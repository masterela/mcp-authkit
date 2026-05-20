"""
CredentialsProvider — MCP elicitation-based credential collection.

Instead of redirecting to an external OAuth provider, the library serves
its own internal HTML page where the user can enter PATs, API keys, or any
other credentials defined by the server developer.

Flow
----
1. Tool is invoked — no credentials cached for this user.
2. Library generates a one-time entry token (bound to the user's sub).
3. URL mode elicitation: client opens
       http://mcp-server/credentials/{name}/entry?t=<entry-token>
4. User fills in the auto-rendered form (with optional how-to markdown above it).
5. POST /credentials/{name}/submit stores the values and calls
   PendingStore.set_result, which unblocks the waiting tool coroutine.
6. Tool proceeds — get_credentials() returns the stored dict.

Storage
-------
Credential persistence and in-flight entry state are delegated to a
(TokenStore, PendingStore) pair.  Use ``lib.store.create_stores()`` to build
the pair from TOKEN_STORAGE_MODE env var (memory | file | redis).  When no
stores are provided, ``create_stores()`` is called automatically.

The entry token is a one-time ``secrets.token_urlsafe(32)`` value stored in
PendingStore with a TTL (default 300 s), preventing replay of stale requests.
"""

from __future__ import annotations

import functools
import logging
import secrets
from collections.abc import Callable
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from mcp.server.fastmcp import Context
from mcp.shared.exceptions import UrlElicitationRequiredError
from mcp.types import ElicitRequestURLParams
from pydantic import BaseModel

from ..store.base import PendingStore, TokenStore

logger = logging.getLogger(__name__)

_jinja = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
    autoescape=select_autoescape(["html"]),
)

# Variable definition schema (one entry per credential field):
#   label    : str  — human-readable label shown above the input
#   type     : str  — "string" | "password" | "url" | "textarea"
#   hint     : str  — placeholder text inside the input
#   required : bool — whether the field is mandatory (default True)
VariableDef = dict[str, Any]


class _CredentialsCompletionForm(BaseModel):
    """Form-mode fallback: user ticks this after submitting via the browser page."""

    submitted: bool


def _load_doc(doc_path: str | None) -> str | None:
    """Return raw markdown content for the how-to guide, or None."""
    if not doc_path:
        return None
    try:
        return Path(doc_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("CredentialsProvider: doc file not found: %s", doc_path)
        return None


def _fields_for_template(variables: dict[str, VariableDef]) -> list[dict]:
    """Convert the variables dict into a flat list suitable for the Jinja2 template."""
    _input_type_map = {"password": "password", "url": "url"}
    result = []
    for var_name, var_def in variables.items():
        type_ = var_def.get("type", "string")
        result.append(
            {
                "name": var_name,
                "label": var_def.get("label", var_name),
                "type": type_,
                "input_type": _input_type_map.get(type_, "text"),
                "hint": var_def.get("hint", ""),
                "required": var_def.get("required", True),
            }
        )
    return result


# ── CredentialsProvider ────────────────────────────────────────────────────────


class CredentialsProvider:
    """
    MCP elicitation-based credential provider for PATs and API keys.

    Serves an internal HTML page (auto-generated from ``variables``) where
    users enter their credentials.  The page optionally renders a Markdown
    how-to guide above the form.

    Unlike ``OAuthProvider``, there is no external redirect: the MCP server
    itself is the destination of the URL mode elicitation.

    Parameters
    ----------
    name
        Short identifier used in route paths and log messages
        (e.g. "confluence", "jira").
    variables
        Ordered dict of credential field definitions::

            {
                "pat": {
                    "label": "Personal Access Token",
                    "type": "password",      # string | password | url | textarea
                    "hint": "e.g. ATBBxyz...",
                    "required": True,
                }
            }
    user_context
        ContextVar[Optional[dict]] set by your auth middleware (same one
        used by OAuthProvider).
    server_base_url
        Full base URL of the MCP server, e.g. "http://localhost:8005".
        Used to build the entry URL sent via elicitation.
    creds_store
        Persistent store for credentials keyed by OIDC sub.  Defaults to
        the store built by ``create_stores()`` from current env vars.
    pending_store
        Ephemeral store for in-flight form sessions.  Defaults to the store
        built by ``create_stores()`` from current env vars.
    doc
        Optional path to a Markdown file rendered above the credential form.
    token_timeout
        Seconds to wait for the user to submit credentials.  Default: 300.
    """

    def __init__(
        self,
        name: str,
        variables: dict[str, VariableDef],
        user_context: ContextVar[dict | None],
        server_base_url: str,
        creds_store: TokenStore | None = None,
        pending_store: PendingStore | None = None,
        doc: str | None = None,
        token_timeout: float = 300.0,
    ) -> None:
        self.name = name
        self.open_paths = [
            f"/credentials/{name}/entry",
            f"/credentials/{name}/submit",
        ]

        self._variables = variables
        self._user_context = user_context
        self._server_base_url = server_base_url.rstrip("/")
        self._token_timeout = token_timeout
        self._doc_md: str | None = _load_doc(doc)

        # Stores — lazy-init from env vars if not injected
        if creds_store is not None and pending_store is not None:
            self._creds_store: TokenStore = creds_store
            self._pending_store: PendingStore = pending_store
        else:
            from ..store.factory import create_stores

            ts, ps = create_stores(namespace=name)
            self._creds_store = creds_store if creds_store is not None else ts
            self._pending_store = pending_store if pending_store is not None else ps

        # In-process only: entry_token → {session, elicitation_id}
        self._sessions: dict[str, dict[str, Any]] = {}

        # Per-request credentials (set by @require_credentials decorator)
        self._current_creds: ContextVar[dict[str, str] | None] = ContextVar(
            f"credentials_{name}", default=None
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_credentials(self) -> dict[str, str] | None:
        """Return the credentials dict for the current tool invocation.
        Only meaningful inside a @require_credentials()-decorated function."""
        return self._current_creds.get()

    async def invalidate_credentials(self, sub: str) -> None:
        """Force re-collection on the user's next tool invocation."""
        await self._creds_store.delete(sub)
        logger.info("%s credentials invalidated for sub='%s'", self.name, sub)

    def require_credentials(self, *, fail_fast: bool = False) -> Callable:
        """
        Decorator factory that gates an async MCP tool behind credential
        collection.

        Apply AFTER @mcp.tool()::

            @mcp.tool(description="...")
            @provider.require_credentials()
            async def my_tool(ctx: Context, ...) -> str:
                creds = provider.get_credentials()
                pat = creds["pat"]
                ...

        Parameters
        ----------
        fail_fast
            False (default): tool call stays open during the credential form flow.
            True: raises UrlElicitationRequiredError; client must retry.
        """

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
                user = self._user_context.get()
                if user is None:
                    return "Error: no authenticated user context."

                sub = user.get("sub", "")
                username = user.get("preferred_username", sub)
                logger.debug(
                    "%s require_credentials: sub=%r fail_fast=%s", self.name, sub, fail_fast
                )

                if fail_fast:
                    creds = await self._ensure_credentials_fail_fast(ctx, sub, username)
                else:
                    creds = await self._ensure_credentials_blocking(ctx, sub, username)

                if creds is None:
                    return (
                        f"{self.name.capitalize()} credentials were not provided "
                        "or the request timed out. Please try again."
                    )

                reset = self._current_creds.set(creds)
                try:
                    return await func(ctx, *args, **kwargs)
                finally:
                    self._current_creds.reset(reset)

            return wrapper

        return decorator

    def register(self, app: FastAPI) -> None:
        """
        Register the credential entry + submit routes on a FastAPI app.

        Call this before mounting the MCP sub-app.  Add ``provider.open_paths``
        to your ``open_paths`` tuple so the auth middleware skips these routes.
        """
        provider = self
        name_cap = provider.name.capitalize()

        @app.get(f"/credentials/{provider.name}/entry", include_in_schema=False)
        async def _entry_page(t: str | None = None):
            if not t:
                return HTMLResponse(
                    _jinja.get_template("credentials_error.html").render(
                        provider_name=name_cap,
                        message="Invalid or missing credential request token.",
                    ),
                    status_code=400,
                )
            meta = await provider._pending_store.get(t)
            if meta is None:
                return HTMLResponse(
                    _jinja.get_template("credentials_error.html").render(
                        provider_name=name_cap,
                        message="Invalid or expired credential request.",
                    ),
                    status_code=400,
                )

            submit_url = f"{provider._server_base_url}/credentials/{provider.name}/submit?t={t}"
            return HTMLResponse(
                _jinja.get_template("credentials_entry.html").render(
                    provider_name=name_cap,
                    fields=_fields_for_template(provider._variables),
                    submit_url=submit_url,
                    doc_md=provider._doc_md,
                )
            )

        @app.post(f"/credentials/{provider.name}/submit", include_in_schema=False)
        async def _submit_credentials(request: Request, t: str | None = None):
            if not t:
                return HTMLResponse(
                    _jinja.get_template("credentials_error.html").render(
                        provider_name=name_cap,
                        message="Invalid or missing credential request token.",
                    ),
                    status_code=400,
                )

            # Pop atomically so a second submit for the same token is rejected
            meta = await provider._pending_store.pop(t)
            if meta is None:
                return HTMLResponse(
                    _jinja.get_template("credentials_error.html").render(
                        provider_name=name_cap,
                        message="Invalid or expired credential request.",
                    ),
                    status_code=400,
                )

            sub: str = meta["sub"]
            local = provider._sessions.pop(t, None)  # {session, elicitation_id} or None

            form_data = await request.form()
            collected: dict[str, str] = {}
            for var_name, var_def in provider._variables.items():
                value = str(form_data.get(var_name, "")).strip()
                if var_def.get("required", True) and not value:
                    return HTMLResponse(
                        _jinja.get_template("credentials_error.html").render(
                            provider_name=name_cap,
                            message=f"'{var_def.get('label', var_name)}' is required.",
                        ),
                        status_code=400,
                    )
                collected[var_name] = value

            await provider._creds_store.set(sub, collected)
            logger.info(
                "%s credentials stored for sub='%s' fields=%s",
                provider.name,
                sub,
                list(collected.keys()),
            )

            elicit_sent = False
            if local:
                try:
                    await local["session"].send_elicit_complete(local["elicitation_id"])
                    elicit_sent = True
                    logger.info(
                        "%s sent elicit_complete (submit) elicitation_id='%s'",
                        provider.name,
                        local["elicitation_id"],
                    )
                except Exception as exc:
                    logger.warning(
                        "%s send_elicit_complete failed for sub='%s': %s",
                        provider.name,
                        sub,
                        exc,
                    )

            await provider._pending_store.set_result(t, {"sub": sub, "_elicit_sent": elicit_sent})

            return HTMLResponse(
                _jinja.get_template("credentials_success.html").render(
                    provider_name=name_cap,
                )
            )

    # ── Internal ───────────────────────────────────────────────────────────────

    def _build_entry_url(self, entry_token: str) -> str:
        return f"{self._server_base_url}/credentials/{self.name}/entry?t={entry_token}"

    async def _new_pending_entry(
        self,
        sub: str,
        elicitation_id: str,
        session: Any,
        entry_token: str | None = None,
    ) -> str:
        """Create a pending entry in the store, return the entry token."""
        token = entry_token or secrets.token_urlsafe(32)
        await self._pending_store.create(
            token,
            {"sub": sub},
            ttl=int(self._token_timeout),
        )
        self._sessions[token] = {"session": session, "elicitation_id": elicitation_id}
        logger.info(
            "%s credentials requested for sub='%s' elicitation_id='%s'",
            self.name,
            sub,
            elicitation_id,
        )
        return token

    async def _ensure_credentials_blocking(
        self, ctx: Context, sub: str, username: str
    ) -> dict[str, str] | None:
        """
        Return cached credentials, or open the entry page via URL mode
        elicitation and wait for the user to submit the form.
        """
        creds = await self._creds_store.get(sub)
        if creds:
            logger.debug("%s _ensure_credentials_blocking sub=%r → cache hit", self.name, sub)
            return creds
        logger.debug(
            "%s _ensure_credentials_blocking sub=%r → cache miss, starting elicitation",
            self.name,
            sub,
        )

        elicitation_id = secrets.token_urlsafe(16)
        entry_token = await self._new_pending_entry(sub, elicitation_id, ctx.session)
        entry_url = self._build_entry_url(entry_token)

        signal: dict | None = None
        try:
            result = await ctx.elicit_url(
                message=(
                    f"{self.name.capitalize()} credentials required for '{username}'.\n"
                    "Open the link and fill in your credentials."
                ),
                url=entry_url,
                elicitation_id=elicitation_id,
            )
            if result.action != "accept":
                self._sessions.pop(entry_token, None)
                await self._pending_store.pop(entry_token)
                logger.info("%s elicitation declined by sub='%s'", self.name, sub)
                return None

            signal = await self._pending_store.wait_for_result(entry_token, self._token_timeout)
            if signal is None:
                self._sessions.pop(entry_token, None)
                await self._pending_store.pop(entry_token)
                logger.warning(
                    "%s timeout waiting for credential submission for sub='%s'",
                    self.name,
                    sub,
                )
                return None

        except Exception as exc:
            logger.info("%s elicit_url not supported (%s) — form fallback", self.name, exc)
            form_result = await ctx.elicit(
                message=(
                    f"{self.name.capitalize()} credentials required for '{username}'.\n"
                    f"Open this URL in your browser:\n{entry_url}\n"
                    "Fill in your credentials, then tick the box below."
                ),
                schema=_CredentialsCompletionForm,
            )
            if form_result.action != "accept" or not form_result.data.submitted:
                self._sessions.pop(entry_token, None)
                await self._pending_store.pop(entry_token)
                logger.info("%s form elicitation declined by sub='%s'", self.name, sub)
                return None

            signal = await self._pending_store.wait_for_result(entry_token, self._token_timeout)
            if signal is None:
                self._sessions.pop(entry_token, None)
                await self._pending_store.pop(entry_token)
                logger.warning(
                    "%s timeout waiting for credential submission for sub='%s'",
                    self.name,
                    sub,
                )
                return None

        # If the submit came from a different instance, send_elicit_complete from here.
        if not signal.get("_elicit_sent"):
            try:
                await ctx.session.send_elicit_complete(elicitation_id)
                logger.info(
                    "%s sent elicit_complete (waiter) elicitation_id='%s'",
                    self.name,
                    elicitation_id,
                )
            except Exception as exc:
                logger.warning("%s send_elicit_complete (waiter) failed: %s", self.name, exc)

        return await self._creds_store.get(sub)

    async def _ensure_credentials_fail_fast(
        self, ctx: Context, sub: str, username: str
    ) -> dict[str, str] | None:
        """
        Return cached credentials, or raise UrlElicitationRequiredError
        immediately.  Client must retry after the user fills in the form.
        """
        creds = await self._creds_store.get(sub)
        if creds:
            logger.debug("%s _ensure_credentials_fail_fast sub=%r → cache hit", self.name, sub)
            return creds
        logger.debug(
            "%s _ensure_credentials_fail_fast sub=%r → cache miss, raising", self.name, sub
        )

        elicitation_id = secrets.token_urlsafe(16)
        entry_token = await self._new_pending_entry(sub, elicitation_id, ctx.session)
        entry_url = self._build_entry_url(entry_token)

        raise UrlElicitationRequiredError(
            elicitations=[
                ElicitRequestURLParams(
                    mode="url",
                    message=(
                        f"{self.name.capitalize()} credentials required for '{username}'.\n"
                        "Open the link and fill in your credentials."
                    ),
                    url=entry_url,
                    elicitationId=elicitation_id,
                )
            ],
            message=f"{self.name.capitalize()} credentials required.",
        )
