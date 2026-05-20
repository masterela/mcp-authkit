"""
OAuthProvider — core implementation of the generic MCP OAuth elicitation pattern.

Spec references (MCP 2025-11-25):
  §3.3  URL mode elicitation  — elicitation/create with mode="url"
  §3.4  Completion notification — notifications/elicitation/complete
  §3.5  URLElicitationRequiredError — JSON-RPC error code -32042
  §6.3  URL mode elicitation for OAuth flows

Storage
-------
Token persistence and in-flight elicitation state are delegated to a
(TokenStore, PendingStore) pair supplied at construction time.  Use
``lib.store.create_stores()`` to build the pair from environment variables
(TOKEN_STORAGE_MODE = memory | file | redis).  When no stores are provided,
``create_stores()`` is called automatically using the current env.

Cross-instance behaviour
------------------------
The two stores decouple the instance that *starts* the OAuth flow from the
instance that *receives* the OAuth callback:

* The initiating instance writes serialisable metadata (sub) to
  PendingStore and keeps the MCP session + elicitation_id in a local dict.
* The callback instance pops the metadata, exchanges the code, stores the
  token, and calls ``set_result`` to signal completion.
* If the callback lands on the *same* instance it also calls
  ``send_elicit_complete`` immediately.  If it lands on a *different*
  instance, ``send_elicit_complete`` is called by the waiter once
  ``wait_for_result`` returns.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import secrets
import ssl
import time
from contextvars import ContextVar
from typing import Any, Callable, Coroutine, Optional, Union
from urllib.parse import urlencode, urlparse

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
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


class _OAuthCompletionForm(BaseModel):
    """Form-mode fallback schema: user ticks this after completing the OAuth flow."""
    completed: bool


# Token store entry shape:
#   access_token : str
#   stored_at    : float   (unix timestamp)
#   refresh_token: str     (optional)
#   expires_at   : float   (optional — stored_at + expires_in)
TokenData = dict[str, Any]

# Return type of exchange_code / refresh_token_fn:
#   str  — bare access token
#   dict — {access_token, refresh_token?, expires_in?}
#   None — failure
ExchangeResult = Optional[str | dict[str, Any]]


def _parse_token_data(result: ExchangeResult, stored_at: float) -> Optional[TokenData]:
    """Normalise an exchange_code / refresh_token_fn result into a TokenData entry."""
    if result is None:
        return None
    if isinstance(result, str):
        return {"access_token": result, "stored_at": stored_at}
    if isinstance(result, dict):
        access = result.get("access_token")
        if not access:
            return None
        entry: TokenData = {"access_token": access, "stored_at": stored_at}
        if rt := result.get("refresh_token"):
            entry["refresh_token"] = rt
        if ei := result.get("expires_in"):
            entry["expires_at"] = stored_at + float(ei)
        return entry
    return None


class OAuthProvider:
    """
    Generic MCP OAuth elicitation provider (MCP spec 2025-11-25).

    Gates MCP tools behind a third-party OAuth flow.  Handles the complete
    token lifecycle: first-time elicitation, expiry checking, silent refresh,
    and reactive invalidation.

    Token lifecycle
    ---------------
    1. First call  — no token → URL mode elicitation → browser OAuth →
                     callback → token stored → tool proceeds.
    2. Next calls  — token valid → tool proceeds immediately.
    3. Expiry known (expires_in provided) — silent refresh via
                     refresh_token_fn if available; else re-elicitation.
    4. Revocation  — tool detects API 401, calls
                     ``await provider.invalidate_token(sub)``
                     and returns an error string → next call triggers re-elicitation.

    Elicitation modes
    -----------------
    require_token(fail_fast=False)  [default]
        Calls ctx.elicit_url(); the tool call stays open and waits for the
        OAuth callback via PendingStore.  After the callback fires,
        send_elicit_complete notifies the client (spec §3.4).

    require_token(fail_fast=True)
        Raises UrlElicitationRequiredError (JSON-RPC -32042, spec §3.5)
        immediately.  The client retries the tool call after the OAuth flow.

    Parameters
    ----------
    name             Human-readable provider name (e.g. "github", "jira").
    build_auth_url   Callable(state, redirect_uri) → authorization URL.
    exchange_code    Async callable(code, state, redirect_uri) → token.
    redirect_uri     Full callback URL registered with the OAuth provider.
    user_context     ContextVar[Optional[dict]] with authenticated user claims.
    token_store      Persistent store for access tokens.  Defaults to the store
                     built by ``create_stores()`` from current env vars.
    pending_store    Ephemeral store for in-flight elicitation state.  Defaults
                     to the store built by ``create_stores()`` from env vars.
    refresh_token_fn Optional async callable(refresh_token, redirect_uri) → token.
    token_timeout    Seconds to wait for the OAuth callback.  Default: 120.
    """

    def __init__(
        self,
        name: str,
        build_auth_url: Callable[[str, str], str],
        exchange_code: Callable[..., Coroutine[Any, Any, ExchangeResult]],
        redirect_uri: str,
        user_context: ContextVar[Optional[dict]],
        token_store: Optional[TokenStore] = None,
        pending_store: Optional[PendingStore] = None,
        refresh_token_fn: Optional[Callable[..., Coroutine[Any, Any, ExchangeResult]]] = None,
        token_timeout: float = 120.0,
    ) -> None:
        self.name = name
        self.callback_path = urlparse(redirect_uri).path

        self._build_auth_url = build_auth_url
        self._exchange_code = exchange_code
        self._redirect_uri = redirect_uri
        self._user_context = user_context
        self._refresh_token_fn = refresh_token_fn
        self._token_timeout = token_timeout

        # Stores — lazy-init from env vars if not injected
        if token_store is not None and pending_store is not None:
            self._token_store: TokenStore = token_store
            self._pending_store: PendingStore = pending_store
        else:
            from ..store.factory import create_stores
            ts, ps = create_stores(namespace=name)
            self._token_store = token_store if token_store is not None else ts
            self._pending_store = pending_store if pending_store is not None else ps

        # In-process only: state → {session, elicitation_id}
        # Never serialised — used to call send_elicit_complete on the right instance.
        self._sessions: dict[str, dict[str, Any]] = {}

        # Per-request token accessor (set by @require_token decorator)
        self._current_token: ContextVar[Optional[str]] = ContextVar(
            f"elicit_oauth_{name}_token", default=None
        )

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def from_standard_oauth2(
        cls,
        *,
        name: str,
        authorization_url: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        redirect_uri: str,
        user_context: ContextVar[Optional[dict]],
        token_store: Optional[TokenStore] = None,
        pending_store: Optional[PendingStore] = None,
        refresh_token_fn: Optional[Callable[..., Coroutine[Any, Any, ExchangeResult]]] = None,
        token_timeout: float = 120.0,
        http_verify: Union[bool, ssl.SSLContext, str] = True,
    ) -> "OAuthProvider":
        """
        Convenience factory for any standard OAuth2 Authorization Code provider
        (GitHub, Google, Jira, Entra, etc.).

        Builds ``build_auth_url`` and ``exchange_code`` internally from standard
        OAuth2 endpoints so the caller only needs to supply configuration::

            github = OAuthProvider.from_standard_oauth2(
                name="github",
                authorization_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                client_id=settings.github_client_id,
                client_secret=settings.github_client_secret,
                scope="read:user repo",
                redirect_uri="http://localhost:8005/github/callback",
                user_context=current_user,
                http_verify=_SSL_CTX,
            )

        Parameters
        ----------
        authorization_url   Full URL of the provider's authorization endpoint.
        token_url           Full URL of the provider's token endpoint.
        client_id           OAuth2 client ID.
        client_secret       OAuth2 client secret.
        scope               Space-separated scope string.
        http_verify         Passed as ``verify=`` to httpx for the token exchange.
        token_store         Optional persistent store override.
        pending_store       Optional pending store override.
        All other params are the same as ``OAuthProvider.__init__``.
        """
        def _build_auth_url(state: str, redir: str) -> str:
            return authorization_url + "?" + urlencode({
                "client_id": client_id,
                "redirect_uri": redir,
                "scope": scope,
                "state": state,
                "response_type": "code",
            })

        async def _exchange_code(code: str, state: str, redir: str) -> ExchangeResult:
            async with httpx.AsyncClient(
                timeout=15, follow_redirects=False, verify=http_verify
            ) as client:
                resp = await client.post(
                    token_url,
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "code": code,
                        "redirect_uri": redir,
                        "grant_type": "authorization_code",
                    },
                    headers={"Accept": "application/json"},
                )
            if resp.status_code != 200:
                logger.error(
                    "%s token exchange failed HTTP %s: %s",
                    name, resp.status_code, resp.text[:300],
                )
                return None
            data = resp.json()
            if not data.get("access_token"):
                logger.error("%s token exchange: no access_token in response: %s", name, data)
                return None
            return data

        return cls(
            name=name,
            build_auth_url=_build_auth_url,
            exchange_code=_exchange_code,
            redirect_uri=redirect_uri,
            user_context=user_context,
            token_store=token_store,
            pending_store=pending_store,
            refresh_token_fn=refresh_token_fn,
            token_timeout=token_timeout,
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_token(self) -> Optional[str]:
        """Return the access token for the current tool invocation.
        Only meaningful inside a @require_token()-decorated function."""
        return self._current_token.get()

    async def invalidate_token(self, sub: str) -> None:
        """
        Remove the cached token for a user, forcing re-elicitation on the
        next tool invocation.

        Call this when the downstream API returns 401::

            token = provider.get_token()
            resp = await _api_get("/path", token)
            if resp.status_code == 401:
                await provider.invalidate_token(current_user.get()["sub"])
                return "Authorization expired — please retry."
        """
        await self._token_store.delete(sub)
        logger.info("%s token invalidated for sub='%s'", self.name, sub)

    def require_token(self, *, fail_fast: bool = False) -> Callable:
        """
        Decorator factory that gates an async MCP tool behind OAuth.

        Apply AFTER @mcp.tool()::

            @mcp.tool(description="...")
            @provider.require_token()
            async def my_tool(ctx: Context, arg: str) -> str:
                token = provider.get_token()   # guaranteed non-None here
                ...

        Parameters
        ----------
        fail_fast
            False (default): tool call stays open during the OAuth flow.
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
                logger.debug("%s require_token: sub=%r fail_fast=%s", self.name, sub, fail_fast)

                if fail_fast:
                    token = await self._ensure_token_fail_fast(ctx, sub, username)
                else:
                    token = await self._ensure_token_blocking(ctx, sub, username)

                if token is None:
                    return (
                        f"{self.name.capitalize()} authorization was cancelled "
                        "or timed out. Please try again."
                    )

                reset = self._current_token.set(token)
                try:
                    return await func(ctx, *args, **kwargs)
                finally:
                    self._current_token.reset(reset)

            return wrapper
        return decorator

    def register(self, app: FastAPI) -> None:
        """
        Register the OAuth callback GET route on a FastAPI app.

        Call this before mounting the MCP sub-app (app.mount("/", ...)).
        The callback path must also be in open_paths so the auth middleware
        does not reject the unauthenticated redirect.  Use
        ``provider.callback_path`` to reference the path dynamically.
        """
        provider = self

        @app.get(provider.callback_path, include_in_schema=False)
        async def _oauth_callback(
            request: Request,
            code: Optional[str] = None,
            state: Optional[str] = None,
            error: Optional[str] = None,
            error_description: Optional[str] = None,
        ):
            name = provider.name.capitalize()

            if error:
                logger.warning("%s callback error: %s — %s", name, error, error_description)
                await provider._fail_pending(state)
                return HTMLResponse(
                    _jinja.get_template("oauth_error.html").render(
                        provider_name=name,
                        error=error,
                        error_description=error_description or "",
                    ),
                    status_code=400,
                )

            if not code or not state:
                return JSONResponse(status_code=400, content={"error": "invalid_request"})

            sub = await provider._handle_callback(code, state)
            if sub is None:
                return HTMLResponse(
                    _jinja.get_template("oauth_error.html").render(
                        provider_name=name,
                        error="Code exchange failed",
                        error_description="Could not exchange the authorization code.",
                    ),
                    status_code=400,
                )

            return HTMLResponse(
                _jinja.get_template("oauth_success.html").render(
                    provider_name=name,
                    sub=sub,
                )
            )

    # ── Internal: token validity & refresh ────────────────────────────────────

    async def _get_valid_token(self, sub: str) -> Optional[str]:
        """Return the stored token if it exists and has not expired (30 s buffer)."""
        entry = await self._token_store.get(sub)
        if not entry:
            logger.debug("%s _get_valid_token sub=%r → no entry", self.name, sub)
            return None
        expires_at = entry.get("expires_at")
        if expires_at is not None and time.time() >= expires_at - 30:
            logger.debug("%s _get_valid_token sub=%r → expired (expires_at=%s)", self.name, sub, expires_at)
            return None  # expired (or about to expire)
        logger.debug("%s _get_valid_token sub=%r → valid", self.name, sub)
        return entry["access_token"]

    async def _try_silent_refresh(self, sub: str) -> Optional[str]:
        """
        Attempt a silent token refresh using a stored refresh_token.
        Returns the new access token on success, None on failure.
        The stale entry is cleared on failure.
        """
        if self._refresh_token_fn is None:
            return None
        entry = await self._token_store.get(sub)
        if not entry or not entry.get("refresh_token"):
            return None

        logger.info("%s silent refresh for sub='%s'", self.name, sub)
        try:
            result = await self._refresh_token_fn(entry["refresh_token"], self._redirect_uri)
        except Exception as exc:
            logger.warning("%s refresh raised for sub='%s': %s", self.name, sub, exc)
            result = None

        new_entry = _parse_token_data(result, time.time())
        if not new_entry:
            await self._token_store.delete(sub)
            logger.warning("%s refresh failed for sub='%s' — token cleared", self.name, sub)
            return None

        # Carry forward refresh_token if the provider did not issue a new one
        if "refresh_token" not in new_entry and entry.get("refresh_token"):
            new_entry["refresh_token"] = entry["refresh_token"]

        await self._token_store.set(sub, new_entry)
        logger.info("%s token refreshed for sub='%s'", self.name, sub)
        return new_entry["access_token"]

    async def _get_or_refresh_token(self, sub: str) -> Optional[str]:
        """Return a valid token, trying silent refresh if expired."""
        token = await self._get_valid_token(sub)
        if token:
            logger.debug("%s _get_or_refresh_token sub=%r → cached token valid", self.name, sub)
            return token
        entry = await self._token_store.get(sub)
        if self._refresh_token_fn and entry and entry.get("refresh_token"):
            logger.debug("%s _get_or_refresh_token sub=%r → attempting silent refresh", self.name, sub)
            return await self._try_silent_refresh(sub)
        logger.debug("%s _get_or_refresh_token sub=%r → no token, elicitation needed", self.name, sub)
        return None

    # ── Internal: elicitation — blocking mode ─────────────────────────────────

    async def _ensure_token_blocking(
        self, ctx: Context, sub: str, username: str
    ) -> Optional[str]:
        """
        Ensure a valid token via ctx.elicit_url() + PendingStore signal.
        The tool call stays open until the OAuth callback fires or timeout.
        Sends notifications/elicitation/complete after the callback (spec §3.4).
        """
        token = await self._get_or_refresh_token(sub)
        if token:
            logger.debug("%s _ensure_token_fail_fast sub=%r → token ready", self.name, sub)
            return token

        state = secrets.token_urlsafe(24)
        elicitation_id = secrets.token_urlsafe(16)
        auth_url = self._build_auth_url(state, self._redirect_uri)

        await self._pending_store.create(
            state, {"sub": sub}, ttl=int(self._token_timeout) + 60
        )
        self._sessions[state] = {"session": ctx.session, "elicitation_id": elicitation_id}
        logger.info(
            "%s OAuth initiated for sub='%s' state='%s' elicitation_id='%s'",
            self.name, sub, state, elicitation_id,
        )

        signal: Optional[dict] = None
        try:
            result = await ctx.elicit_url(
                message=(
                    f"{self.name.capitalize()} authorization required for '{username}'.\n"
                    "Open the link, sign in, and grant access.\n"
                    "Return here when done."
                ),
                url=auth_url,
                elicitation_id=elicitation_id,
            )
            if result.action != "accept":
                self._sessions.pop(state, None)
                await self._pending_store.pop(state)
                logger.info("%s elicitation declined/cancelled by sub='%s'", self.name, sub)
                return None

            signal = await self._pending_store.wait_for_result(state, self._token_timeout)
            if signal is None:
                self._sessions.pop(state, None)
                await self._pending_store.pop(state)
                logger.warning("%s timeout waiting for callback for sub='%s'", self.name, sub)
                return None

        except Exception as exc:
            # Client does not support URL mode — fall back to form mode.
            logger.info("%s elicit_url not supported (%s) — form fallback", self.name, exc)
            form_result = await ctx.elicit(
                message=(
                    f"{self.name.capitalize()} authorization required for '{username}'.\n"
                    f"Open this URL in your browser:\n{auth_url}\n\n"
                    "Complete the sign-in, then tick the box below."
                ),
                schema=_OAuthCompletionForm,
            )
            if form_result.action != "accept" or not form_result.data.completed:
                self._sessions.pop(state, None)
                await self._pending_store.pop(state)
                logger.info("%s form elicitation declined by sub='%s'", self.name, sub)
                return None

            signal = await self._pending_store.wait_for_result(state, self._token_timeout)
            if signal is None:
                self._sessions.pop(state, None)
                await self._pending_store.pop(state)
                logger.warning("%s timeout waiting for callback for sub='%s'", self.name, sub)
                return None

        # If the callback was handled by a *different* instance it could not call
        # send_elicit_complete (no session reference) — call it from here instead.
        if not signal.get("_elicit_sent"):
            try:
                await ctx.session.send_elicit_complete(elicitation_id)
                logger.info(
                    "%s sent elicit_complete (waiter) elicitation_id='%s'",
                    self.name, elicitation_id,
                )
            except Exception as exc:
                logger.warning(
                    "%s send_elicit_complete (waiter) failed: %s", self.name, exc
                )

        return await self._get_valid_token(sub)

    # ── Internal: elicitation — fail-fast mode ────────────────────────────────

    async def _ensure_token_fail_fast(
        self, ctx: Context, sub: str, username: str
    ) -> Optional[str]:
        """
        Ensure a valid token, raising UrlElicitationRequiredError if absent.
        The tool call fails immediately; the client must retry after OAuth.
        """
        token = await self._get_or_refresh_token(sub)
        if token:
            logger.debug("%s _ensure_token_fail_fast sub=%r → token ready", self.name, sub)
            return token

        state = secrets.token_urlsafe(24)
        elicitation_id = secrets.token_urlsafe(16)
        auth_url = self._build_auth_url(state, self._redirect_uri)

        await self._pending_store.create(
            self.name, sub,
        )

        raise UrlElicitationRequiredError(
            elicitations=[
                ElicitRequestURLParams(
                    mode="url",
                    message=(
                        f"{self.name.capitalize()} authorization required for '{username}'.\n"
                        "Open the link, sign in, and grant access."
                    ),
                    url=auth_url,
                    elicitationId=elicitation_id,
                )
            ],
            message=f"{self.name.capitalize()} authorization required.",
        )

    # ── Internal: callback handling ───────────────────────────────────────────

    async def _handle_callback(self, code: str, state: str) -> Optional[str]:
        """
        Exchange the OAuth code, store the token, notify waiter + client.
        Returns the user sub on success, None on failure.

        Cross-instance note: ``_sessions`` is in-process only.  If the
        callback lands on a different instance than the one that started the
        flow, ``_sessions.pop(state)`` returns None and ``send_elicit_complete``
        is not called here — it will be called by the waiting instance once
        ``wait_for_result`` returns.
        """
        meta = await self._pending_store.get(state)
        if meta is None:
            logger.warning("%s callback: unknown or expired state '%s'", self.name, state)
            return None

        sub: str = meta["sub"]
        local = self._sessions.pop(state, None)  # {session, elicitation_id} or None

        try:
            result = await self._exchange_code(code, state, self._redirect_uri)
        except Exception as exc:
            logger.error("%s exchange_code raised for sub='%s': %s", self.name, sub, exc)
            result = None

        entry = _parse_token_data(result, time.time())
        if not entry:
            logger.error("%s code exchange returned no token for sub='%s'", self.name, sub)
            await self._pending_store.set_result(state, {"error": "exchange_failed"})
            await self._pending_store.pop(state)
            return None

        await self._token_store.set(sub, entry)
        logger.info("%s token stored for sub='%s'", self.name, sub)

        elicit_sent = False
        if local:
            try:
                await local["session"].send_elicit_complete(local["elicitation_id"])
                elicit_sent = True
                logger.info(
                    "%s sent elicit_complete (callback) elicitation_id='%s'",
                    self.name, local["elicitation_id"],
                )
            except Exception as exc:
                logger.warning(
                    "%s send_elicit_complete failed for sub='%s': %s", self.name, sub, exc
                )

        # Remove the pending metadata and signal the waiter (same or other instance)
        await self._pending_store.pop(state)
        await self._pending_store.set_result(
            state, {"sub": sub, "_elicit_sent": elicit_sent}
        )
        return sub

    async def _fail_pending(self, state: Optional[str]) -> None:
        """Unblock a waiting tool when the OAuth callback returns an error."""
        if not state:
            return
        self._sessions.pop(state, None)
        await self._pending_store.set_result(state, {"error": "oauth_error"})
        await self._pending_store.pop(state)
