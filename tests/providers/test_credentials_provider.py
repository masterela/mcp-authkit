"""
Tests for CredentialsProvider — credential collection, decorators,
entry/submit HTTP routes, and internal elicitation flow.

Uses MemoryTokenStore + MemoryPendingStore.  Route tests use
httpx.AsyncClient + ASGITransport to share the event loop with fixtures.
"""

from __future__ import annotations

import asyncio
from contextvars import ContextVar
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mcp.shared.exceptions import UrlElicitationRequiredError

from mcpauthkit.providers.credentials_provider import (
    CredentialsProvider,
    _fields_for_template,
    _load_doc,
)
from mcpauthkit.store.memory import MemoryPendingStore, MemoryTokenStore

# ── Mock MCP Context ──────────────────────────────────────────────────────────


class _ElicitResult:
    def __init__(self, action: str = "accept") -> None:
        self.action = action


class _ElicitFormResult:
    def __init__(self, action: str = "accept", submitted: bool = True) -> None:
        self.action = action
        self.data = MagicMock()
        self.data.submitted = submitted


class MockContext:
    def __init__(
        self,
        elicit_url_action: str = "accept",
        elicit_url_raises: Exception | None = None,
        elicit_form_action: str = "accept",
        elicit_form_submitted: bool = True,
    ) -> None:
        self.session = MagicMock()
        self.session.send_elicit_complete = AsyncMock()
        self._elicit_url_action = elicit_url_action
        self._elicit_url_raises = elicit_url_raises
        self._elicit_form_action = elicit_form_action
        self._elicit_form_submitted = elicit_form_submitted

    async def elicit_url(self, **_kw) -> _ElicitResult:
        if self._elicit_url_raises is not None:
            raise self._elicit_url_raises
        return _ElicitResult(self._elicit_url_action)

    async def elicit(self, **_kw) -> _ElicitFormResult:
        return _ElicitFormResult(self._elicit_form_action, self._elicit_form_submitted)


# ── Variables used in tests ───────────────────────────────────────────────────

_VARIABLES = {
    "pat": {
        "label": "Personal Access Token",
        "type": "password",
        "hint": "ATBBxyz",
        "required": True,
    },
    "base_url": {"label": "Base URL", "type": "url", "hint": "https://...", "required": False},
}

# ── Shared fixtures ───────────────────────────────────────────────────────────


@pytest.fixture()
def user_ctx() -> ContextVar:
    return ContextVar("test_user_creds", default=None)


@pytest.fixture()
def stores() -> tuple[MemoryTokenStore, MemoryPendingStore]:
    return MemoryTokenStore(), MemoryPendingStore()


@pytest.fixture()
def provider(user_ctx, stores) -> CredentialsProvider:
    cs, ps = stores
    return CredentialsProvider(
        name="confluence",
        variables=_VARIABLES,
        user_context=user_ctx,
        server_base_url="http://localhost:8005",
        creds_store=cs,
        pending_store=ps,
        token_timeout=5.0,
    )


@pytest.fixture()
def app(provider) -> FastAPI:
    a = FastAPI()
    provider.register(a)
    return a


# ── Utility functions ─────────────────────────────────────────────────────────


def test_load_doc_none_path():
    assert _load_doc(None) is None


def test_load_doc_missing_file():
    assert _load_doc("/nonexistent/file.md") is None


def test_load_doc_existing_file(tmp_path):
    doc = tmp_path / "guide.md"
    doc.write_text("# How to get a PAT", encoding="utf-8")
    assert _load_doc(str(doc)) == "# How to get a PAT"


def test_fields_for_template_maps_types():
    fields = _fields_for_template(_VARIABLES)
    by_name = {f["name"]: f for f in fields}
    assert by_name["pat"]["input_type"] == "password"
    assert by_name["base_url"]["input_type"] == "url"
    assert by_name["pat"]["required"] is True
    assert by_name["base_url"]["required"] is False


def test_fields_for_template_string_type_maps_to_text():
    fields = _fields_for_template({"key": {"type": "string", "required": True}})
    assert fields[0]["input_type"] == "text"


# ── CredentialsProvider construction ─────────────────────────────────────────


def test_provider_open_paths(provider):
    assert "/credentials/confluence/entry" in provider.open_paths
    assert "/credentials/confluence/submit" in provider.open_paths


def test_provider_build_entry_url(provider):
    url = provider._build_entry_url("tok123")
    assert url == "http://localhost:8005/credentials/confluence/entry?t=tok123"


def test_get_credentials_returns_none_outside_decorator(provider):
    assert provider.get_credentials() is None


async def test_invalidate_credentials_removes_stored(provider):
    await provider._creds_store.set("alice", {"pat": "old-pat"})
    await provider.invalidate_credentials("alice")
    assert await provider._creds_store.get("alice") is None


# ── _new_pending_entry ────────────────────────────────────────────────────────


async def test_new_pending_entry_stores_and_returns_token(provider):
    session = MagicMock()
    token = await provider._new_pending_entry("alice", "elicit-1", session)
    assert token is not None
    meta = await provider._pending_store.get(token)
    assert meta == {"sub": "alice"}
    assert provider._sessions[token]["elicitation_id"] == "elicit-1"


async def test_new_pending_entry_uses_provided_token(provider):
    session = MagicMock()
    token = await provider._new_pending_entry("alice", "e1", session, entry_token="fixed-tok")
    assert token == "fixed-tok"


# ── require_credentials decorator ────────────────────────────────────────────


async def test_require_credentials_calls_tool_with_cached_creds(provider, user_ctx):
    sub = "alice"
    user_ctx.set({"sub": sub, "preferred_username": "Alice"})
    await provider._creds_store.set(sub, {"pat": "cached-pat"})

    seen_creds: list = []

    @provider.require_credentials()
    async def my_tool(ctx: MockContext) -> str:
        seen_creds.append(provider.get_credentials())
        return "ok"

    result = await my_tool(MockContext())
    assert result == "ok"
    assert seen_creds == [{"pat": "cached-pat"}]


async def test_require_credentials_no_user_returns_error(provider, user_ctx):
    user_ctx.set(None)

    @provider.require_credentials()
    async def my_tool(ctx: MockContext) -> str:
        return "should not reach"

    result = await my_tool(MockContext())
    assert "Error" in result


async def test_require_credentials_fail_fast_raises_when_no_creds(provider, user_ctx):
    user_ctx.set({"sub": "alice", "preferred_username": "Alice"})

    @provider.require_credentials(fail_fast=True)
    async def my_tool(ctx: MockContext) -> str:
        return "should not reach"

    with pytest.raises(UrlElicitationRequiredError):
        await my_tool(MockContext())


async def test_require_credentials_nil_returns_error(provider, user_ctx):
    user_ctx.set({"sub": "alice", "preferred_username": "Alice"})
    ctx = MockContext(elicit_url_action="cancel")

    @provider.require_credentials()
    async def my_tool(ctx: MockContext) -> str:
        return "should not reach"

    result = await my_tool(ctx)
    assert "timed out" in result or "not provided" in result


# ── _ensure_credentials_fail_fast ────────────────────────────────────────────


async def test_ensure_fail_fast_returns_creds_if_cached(provider):
    await provider._creds_store.set("alice", {"pat": "stored"})
    ctx = MockContext()
    creds = await provider._ensure_credentials_fail_fast(ctx, "alice", "Alice")
    assert creds == {"pat": "stored"}


async def test_ensure_fail_fast_raises_when_no_creds(provider):
    ctx = MockContext()
    with pytest.raises(UrlElicitationRequiredError):
        await provider._ensure_credentials_fail_fast(ctx, "alice", "Alice")


# ── _ensure_credentials_blocking ─────────────────────────────────────────────


async def _fire_creds_signal(provider, sub: str, pending_key_holder: list) -> None:
    """Background helper: wait for pending entry then store creds and signal."""
    while not pending_key_holder:
        await asyncio.sleep(0.01)
    token = pending_key_holder[0]
    await provider._creds_store.set(sub, {"pat": "submitted-pat"})
    await provider._pending_store.set_result(token, {"sub": sub, "_elicit_sent": False})


async def test_ensure_blocking_returns_cached_creds(provider):
    """Cache hit → no elicitation at all."""
    await provider._creds_store.set("alice", {"pat": "existing"})
    ctx = MockContext()
    creds = await provider._ensure_credentials_blocking(ctx, "alice", "Alice")
    assert creds == {"pat": "existing"}


async def test_ensure_blocking_elicits_and_signals(provider):
    sub = "alice"
    captured: list[str] = []

    orig = provider._pending_store.create

    async def capturing(*args, **kwargs):
        captured.append(args[0])
        return await orig(*args, **kwargs)

    provider._pending_store.create = capturing
    ctx = MockContext()

    task = asyncio.create_task(_fire_creds_signal(provider, sub, captured))
    creds = await provider._ensure_credentials_blocking(ctx, sub, "Alice")
    await task

    assert creds == {"pat": "submitted-pat"}
    ctx.session.send_elicit_complete.assert_called_once()


async def test_ensure_blocking_cancelled(provider):
    ctx = MockContext(elicit_url_action="cancel")
    result = await provider._ensure_credentials_blocking(ctx, "alice", "Alice")
    assert result is None


async def test_ensure_blocking_form_fallback_accepts(provider):
    sub = "alice"
    captured: list[str] = []

    orig = provider._pending_store.create

    async def capturing(*args, **kwargs):
        captured.append(args[0])
        return await orig(*args, **kwargs)

    provider._pending_store.create = capturing
    ctx = MockContext(elicit_url_raises=NotImplementedError("unsupported"))

    task = asyncio.create_task(_fire_creds_signal(provider, sub, captured))
    creds = await provider._ensure_credentials_blocking(ctx, sub, "Alice")
    await task

    assert creds == {"pat": "submitted-pat"}


async def test_ensure_blocking_form_fallback_declined(provider):
    ctx = MockContext(
        elicit_url_raises=NotImplementedError("unsupported"),
        elicit_form_submitted=False,
    )
    result = await provider._ensure_credentials_blocking(ctx, "alice", "Alice")
    assert result is None


# ── Entry page route ──────────────────────────────────────────────────────────


async def test_entry_route_missing_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/credentials/confluence/entry")
    assert resp.status_code == 400


async def test_entry_route_invalid_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/credentials/confluence/entry?t=bad-token")
    assert resp.status_code == 400


async def test_entry_route_valid_token(app, provider):
    session = MagicMock()
    token = await provider._new_pending_entry("alice", "e1", session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get(f"/credentials/confluence/entry?t={token}")

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# ── Submit route ──────────────────────────────────────────────────────────────


async def test_submit_route_missing_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.post("/credentials/confluence/submit", data={"pat": "x"})
    assert resp.status_code == 400


async def test_submit_route_invalid_token(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.post("/credentials/confluence/submit?t=bad", data={"pat": "x"})
    assert resp.status_code == 400


async def test_submit_route_missing_required_field(app, provider):
    session = MagicMock()
    token = await provider._new_pending_entry("alice", "e1", session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        # pat is required but omitted
        resp = await c.post(f"/credentials/confluence/submit?t={token}", data={"base_url": "x"})

    assert resp.status_code == 400


async def test_submit_route_success(app, provider):
    sub = "alice"
    session = MagicMock()
    token = await provider._new_pending_entry(sub, "e1", session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.post(
            f"/credentials/confluence/submit?t={token}",
            data={"pat": "my-secret-pat"},
        )

    assert resp.status_code == 200
    stored = await provider._creds_store.get(sub)
    assert stored == {"pat": "my-secret-pat", "base_url": ""}


async def test_submit_route_second_submit_rejected(app, provider):
    """After first successful submit the pending entry is popped; second is rejected."""
    sub = "alice"
    session = MagicMock()
    token = await provider._new_pending_entry(sub, "e1", session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.post(f"/credentials/confluence/submit?t={token}", data={"pat": "tok"})
        resp2 = await c.post(f"/credentials/confluence/submit?t={token}", data={"pat": "tok2"})

    assert resp2.status_code == 400


def test_credentials_provider_lazy_store_init():
    """Provider without explicit stores uses create_stores() internally."""
    uc: ContextVar = ContextVar("lazy_creds_uc", default=None)
    p = CredentialsProvider(
        name="test-lazy",
        variables={},
        user_context=uc,
        server_base_url="http://localhost:8005",
        # No creds_store / pending_store — triggers lazy init
    )
    assert p._creds_store is not None
    assert p._pending_store is not None


async def test_ensure_blocking_url_accepted_but_times_out(provider):
    """elicit_url accepted but form never submitted → timeout → None."""
    provider._token_timeout = 0.1
    ctx = MockContext()
    result = await provider._ensure_credentials_blocking(ctx, "alice", "Alice")
    assert result is None


async def test_ensure_blocking_form_fallback_times_out(provider):
    """Form fallback accepted but never submitted → timeout → None."""
    provider._token_timeout = 0.1
    ctx = MockContext(
        elicit_url_raises=NotImplementedError("unsupported"),
        elicit_form_submitted=True,
    )
    result = await provider._ensure_credentials_blocking(ctx, "alice", "Alice")
    assert result is None


async def test_ensure_blocking_send_elicit_complete_failure_ignored(provider):
    """send_elicit_complete raising does not prevent credentials from being returned."""
    sub = "alice"
    captured: list[str] = []
    orig = provider._pending_store.create

    async def capturing(*args, **kwargs):
        captured.append(args[0])
        return await orig(*args, **kwargs)

    provider._pending_store.create = capturing
    ctx = MockContext()
    ctx.session.send_elicit_complete = AsyncMock(side_effect=RuntimeError("boom"))

    async def fire():
        while not captured:
            await asyncio.sleep(0.01)
        token = captured[0]
        await provider._creds_store.set(sub, {"pat": "t"})
        await provider._pending_store.set_result(token, {"sub": sub, "_elicit_sent": False})

    task = asyncio.create_task(fire())
    creds = await provider._ensure_credentials_blocking(ctx, sub, "Alice")
    await task
    assert creds == {"pat": "t"}


async def test_submit_route_sends_elicit_complete(app, provider):
    """When a session is registered, submit calls send_elicit_complete."""
    sub = "alice"
    mock_session = MagicMock()
    mock_session.send_elicit_complete = AsyncMock()
    token = await provider._new_pending_entry(sub, "elicit-id", mock_session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.post(f"/credentials/confluence/submit?t={token}", data={"pat": "tok"})

    mock_session.send_elicit_complete.assert_called_once_with("elicit-id")
