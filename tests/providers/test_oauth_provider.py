"""
Tests for OAuthProvider — token lifecycle, decorators, callback routes,
and internal state management.

Uses MemoryTokenStore + MemoryPendingStore so no external dependencies are
required.  The MCP Context is mocked to control elicitation responses.
Route tests use httpx.AsyncClient + ASGITransport to share the event loop
with the async fixtures (avoiding asyncio.Event cross-loop issues).
"""

from __future__ import annotations

import asyncio
import time
from contextvars import ContextVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from mcp.shared.exceptions import UrlElicitationRequiredError

from mcpauthkit.providers.oauth_provider import (
    OAuthProvider,
    _parse_token_data,
)
from mcpauthkit.store.memory import MemoryPendingStore, MemoryTokenStore

# ── Mock MCP Context ──────────────────────────────────────────────────────────


class _ElicitResult:
    def __init__(self, action: str = "accept") -> None:
        self.action = action


class _ElicitFormResult:
    def __init__(self, action: str = "accept", completed: bool = True) -> None:
        self.action = action
        self.data = MagicMock()
        self.data.completed = completed


class MockContext:
    def __init__(
        self,
        elicit_url_action: str = "accept",
        elicit_url_raises: Exception | None = None,
        elicit_form_action: str = "accept",
        elicit_form_completed: bool = True,
    ) -> None:
        self.session = MagicMock()
        self.session.send_elicit_complete = AsyncMock()
        self._elicit_url_action = elicit_url_action
        self._elicit_url_raises = elicit_url_raises
        self._elicit_form_action = elicit_form_action
        self._elicit_form_completed = elicit_form_completed

    async def elicit_url(self, **_kw) -> _ElicitResult:
        if self._elicit_url_raises is not None:
            raise self._elicit_url_raises
        return _ElicitResult(self._elicit_url_action)

    async def elicit(self, **_kw) -> _ElicitFormResult:
        return _ElicitFormResult(self._elicit_form_action, self._elicit_form_completed)


# ── Shared fixtures ───────────────────────────────────────────────────────────


@pytest.fixture()
def user_ctx() -> ContextVar:
    return ContextVar("test_user", default=None)


@pytest.fixture()
def stores() -> tuple[MemoryTokenStore, MemoryPendingStore]:
    return MemoryTokenStore(), MemoryPendingStore()


@pytest.fixture()
def provider(user_ctx, stores) -> OAuthProvider:
    ts, ps = stores
    return OAuthProvider(
        name="github",
        build_auth_url=lambda state, redirect: f"https://github.com/oauth/authorize?state={state}",
        exchange_code=AsyncMock(return_value={"access_token": "tok123", "expires_in": 3600}),
        redirect_uri="http://localhost:8005/oauth/github/callback",
        user_context=user_ctx,
        token_store=ts,
        pending_store=ps,
        token_timeout=5.0,
    )


@pytest.fixture()
def app(provider) -> FastAPI:
    a = FastAPI()
    provider.register(a)
    return a


# ── _parse_token_data ─────────────────────────────────────────────────────────


def test_parse_none_returns_none():
    assert _parse_token_data(None, 0) is None


def test_parse_str_returns_entry():
    e = _parse_token_data("bare-token", 1000.0)
    assert e == {"access_token": "bare-token", "stored_at": 1000.0}


def test_parse_dict_with_expiry():
    e = _parse_token_data({"access_token": "t", "expires_in": 60, "refresh_token": "rt"}, 1000.0)
    assert e["access_token"] == "t"
    assert e["expires_at"] == pytest.approx(1060.0)
    assert e["refresh_token"] == "rt"


def test_parse_dict_no_access_token_returns_none():
    assert _parse_token_data({"token_type": "bearer"}, 0) is None


# ── OAuthProvider construction ────────────────────────────────────────────────


def test_provider_name_and_callback_path(provider):
    assert provider.name == "github"
    assert provider.callback_path == "/oauth/github/callback"


def test_get_token_returns_none_outside_decorator(provider):
    assert provider.get_token() is None


async def test_invalidate_token_removes_stored_token(provider):
    await provider._token_store.set("alice", {"access_token": "t", "stored_at": time.time()})
    await provider.invalidate_token("alice")
    assert await provider._token_store.get("alice") is None


# ── _get_valid_token ──────────────────────────────────────────────────────────


async def test_get_valid_token_miss(provider):
    assert await provider._get_valid_token("nobody") is None


async def test_get_valid_token_unexpired(provider):
    await provider._token_store.set(
        "alice",
        {"access_token": "fresh", "stored_at": time.time(), "expires_at": time.time() + 3600},
    )
    assert await provider._get_valid_token("alice") == "fresh"


async def test_get_valid_token_no_expiry_field(provider):
    """No expires_at → token is considered valid indefinitely."""
    await provider._token_store.set("alice", {"access_token": "no-exp", "stored_at": time.time()})
    assert await provider._get_valid_token("alice") == "no-exp"


async def test_get_valid_token_expired(provider):
    await provider._token_store.set(
        "alice",
        {"access_token": "stale", "stored_at": time.time() - 3700, "expires_at": time.time() - 100},
    )
    assert await provider._get_valid_token("alice") is None


# ── _try_silent_refresh ───────────────────────────────────────────────────────


async def test_try_silent_refresh_no_fn(provider):
    """Provider without refresh_token_fn always returns None."""
    await provider._token_store.set("alice", {"access_token": "old", "refresh_token": "rt"})
    assert await provider._try_silent_refresh("alice") is None


async def test_try_silent_refresh_success(provider):
    refresh_fn = AsyncMock(return_value={"access_token": "new-tok", "expires_in": 3600})
    provider._refresh_token_fn = refresh_fn

    await provider._token_store.set(
        "alice",
        {"access_token": "old", "stored_at": time.time(), "refresh_token": "rt-val"},
    )
    result = await provider._try_silent_refresh("alice")
    assert result == "new-tok"
    refresh_fn.assert_called_once_with("rt-val", provider._redirect_uri)


async def test_try_silent_refresh_carries_forward_refresh_token(provider):
    """If the refresh response omits refresh_token, keep the old one."""
    provider._refresh_token_fn = AsyncMock(return_value={"access_token": "new", "expires_in": 60})
    await provider._token_store.set(
        "alice", {"access_token": "old", "stored_at": time.time(), "refresh_token": "kept-rt"}
    )
    await provider._try_silent_refresh("alice")
    entry = await provider._token_store.get("alice")
    assert entry["refresh_token"] == "kept-rt"


async def test_try_silent_refresh_fn_fails_clears_token(provider):
    provider._refresh_token_fn = AsyncMock(side_effect=RuntimeError("network error"))
    await provider._token_store.set(
        "alice", {"access_token": "old", "refresh_token": "rt", "stored_at": time.time()}
    )
    result = await provider._try_silent_refresh("alice")
    assert result is None
    assert await provider._token_store.get("alice") is None


async def test_try_silent_refresh_fn_returns_none_clears_token(provider):
    provider._refresh_token_fn = AsyncMock(return_value=None)
    await provider._token_store.set(
        "alice", {"access_token": "old", "refresh_token": "rt", "stored_at": time.time()}
    )
    result = await provider._try_silent_refresh("alice")
    assert result is None
    assert await provider._token_store.get("alice") is None


async def test_try_silent_refresh_no_entry_returns_none(provider):
    provider._refresh_token_fn = AsyncMock(return_value={"access_token": "new"})
    assert await provider._try_silent_refresh("nobody") is None


# ── _get_or_refresh_token ─────────────────────────────────────────────────────


async def test_get_or_refresh_token_valid_token(provider):
    await provider._token_store.set(
        "alice",
        {"access_token": "valid", "stored_at": time.time(), "expires_at": time.time() + 3600},
    )
    assert await provider._get_or_refresh_token("alice") == "valid"


async def test_get_or_refresh_token_expired_with_refresh(provider):
    provider._refresh_token_fn = AsyncMock(return_value={"access_token": "refreshed"})
    await provider._token_store.set(
        "alice",
        {
            "access_token": "old",
            "stored_at": time.time() - 4000,
            "expires_at": time.time() - 100,
            "refresh_token": "rt",
        },
    )
    result = await provider._get_or_refresh_token("alice")
    assert result == "refreshed"


async def test_get_or_refresh_token_no_token(provider):
    assert await provider._get_or_refresh_token("nobody") is None


# ── require_token decorator ───────────────────────────────────────────────────


async def test_require_token_calls_tool_with_cached_token(provider, user_ctx):
    sub = "alice"
    user_ctx.set({"sub": sub, "preferred_username": "Alice"})
    await provider._token_store.set(sub, {"access_token": "cached-tok", "stored_at": time.time()})

    seen_token: list[str | None] = []

    @provider.require_token()
    async def my_tool(ctx: MockContext, arg: str) -> str:
        seen_token.append(provider.get_token())
        return "ok"

    result = await my_tool(MockContext(), arg="x")
    assert result == "ok"
    assert seen_token == ["cached-tok"]


async def test_require_token_no_user_returns_error(provider, user_ctx):
    user_ctx.set(None)

    @provider.require_token()
    async def my_tool(ctx: MockContext) -> str:
        return "should not reach"

    result = await my_tool(MockContext())
    assert "Error" in result


async def test_require_token_fail_fast_raises_when_no_token(provider, user_ctx):
    user_ctx.set({"sub": "alice", "preferred_username": "Alice"})

    @provider.require_token(fail_fast=True)
    async def my_tool(ctx: MockContext) -> str:
        return "should not reach"

    with pytest.raises(UrlElicitationRequiredError):
        await my_tool(MockContext())


async def test_require_token_nil_token_returns_error(provider, user_ctx):
    """If elicitation is cancelled/timed out, the decorator returns a descriptive error."""
    sub = "alice"
    user_ctx.set({"sub": sub, "preferred_username": "Alice"})

    ctx = MockContext(elicit_url_action="cancel")

    @provider.require_token()
    async def my_tool(ctx: MockContext) -> str:
        return "should not reach"

    result = await my_tool(ctx)
    assert "timed out" in result or "cancelled" in result


# ── _ensure_token_fail_fast ───────────────────────────────────────────────────


async def test_ensure_token_fail_fast_returns_token_if_available(provider):
    await provider._token_store.set("alice", {"access_token": "existing", "stored_at": time.time()})
    ctx = MockContext()
    token = await provider._ensure_token_fail_fast(ctx, "alice", "Alice")
    assert token == "existing"


async def test_ensure_token_fail_fast_raises_when_no_token(provider):
    ctx = MockContext()
    with pytest.raises(UrlElicitationRequiredError):
        await provider._ensure_token_fail_fast(ctx, "alice", "Alice")


# ── _ensure_token_blocking ────────────────────────────────────────────────────


async def _fire_token_signal(provider, sub: str, pending_key_holder: list) -> None:
    """Background helper: wait for pending entry then store token and signal."""
    while not pending_key_holder:
        await asyncio.sleep(0.01)
    state = pending_key_holder[0]
    await provider._token_store.set(sub, {"access_token": "oauth-tok", "stored_at": time.time()})
    await provider._pending_store.set_result(state, {"_elicit_sent": False})


async def test_ensure_token_blocking_accepts_and_signals(provider):
    sub = "alice"
    captured: list[str] = []

    orig = provider._pending_store.create

    async def capturing(*args, **kwargs):
        captured.append(args[0])
        return await orig(*args, **kwargs)

    provider._pending_store.create = capturing
    ctx = MockContext()

    task = asyncio.create_task(_fire_token_signal(provider, sub, captured))
    token = await provider._ensure_token_blocking(ctx, sub, "Alice")
    await task

    assert token == "oauth-tok"
    ctx.session.send_elicit_complete.assert_called_once()


async def test_ensure_token_blocking_cancelled(provider):
    """When elicitation is declined, returns None."""
    ctx = MockContext(elicit_url_action="cancel")
    result = await provider._ensure_token_blocking(ctx, "alice", "Alice")
    assert result is None


async def test_ensure_token_blocking_form_fallback_accepts(provider):
    """elicit_url not supported → falls back to form elicitation → signal fires."""
    sub = "alice"
    captured: list[str] = []

    orig = provider._pending_store.create

    async def capturing(*args, **kwargs):
        captured.append(args[0])
        return await orig(*args, **kwargs)

    provider._pending_store.create = capturing
    # elicit_url raises → form fallback
    ctx = MockContext(elicit_url_raises=NotImplementedError("not supported"))

    task = asyncio.create_task(_fire_token_signal(provider, sub, captured))
    token = await provider._ensure_token_blocking(ctx, sub, "Alice")
    await task

    assert token == "oauth-tok"


async def test_ensure_token_blocking_form_fallback_declined(provider):
    ctx = MockContext(
        elicit_url_raises=NotImplementedError("not supported"),
        elicit_form_completed=False,
    )
    result = await provider._ensure_token_blocking(ctx, "alice", "Alice")
    assert result is None


# ── _handle_callback ──────────────────────────────────────────────────────────


async def test_handle_callback_success(provider):
    state = "cb-state"
    sub = "alice"
    await provider._pending_store.create(state, {"sub": sub}, ttl=60)

    result = await provider._handle_callback("auth-code", state)

    assert result == sub
    stored = await provider._token_store.get(sub)
    assert stored is not None
    assert stored["access_token"] == "tok123"


async def test_handle_callback_unknown_state(provider):
    result = await provider._handle_callback("code", "bad-state")
    assert result is None


async def test_handle_callback_exchange_failure(provider):
    provider._exchange_code = AsyncMock(return_value=None)
    state = "cb-state"
    await provider._pending_store.create(state, {"sub": "alice"}, ttl=60)
    result = await provider._handle_callback("code", state)
    assert result is None


async def test_handle_callback_sends_elicit_complete_when_session_present(provider):
    state = "cb-state"
    sub = "alice"
    mock_session = MagicMock()
    mock_session.send_elicit_complete = AsyncMock()
    await provider._pending_store.create(state, {"sub": sub}, ttl=60)
    provider._sessions[state] = {"session": mock_session, "elicitation_id": "elicit-1"}

    await provider._handle_callback("code", state)

    mock_session.send_elicit_complete.assert_called_once_with("elicit-1")


# ── _fail_pending ─────────────────────────────────────────────────────────────


async def test_fail_pending_none_state_is_noop(provider):
    await provider._fail_pending(None)  # must not raise


async def test_fail_pending_signals_waiter(provider):
    state = "fail-state"
    await provider._pending_store.create(state, {"sub": "alice"}, ttl=60)
    await provider._fail_pending(state)
    result = await provider._pending_store.wait_for_result(state, timeout=1.0)
    assert result is not None
    assert result.get("error") == "oauth_error"


# ── Callback route (via FastAPI) ──────────────────────────────────────────────


async def test_callback_route_missing_code_and_state(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/oauth/github/callback")
    assert resp.status_code == 400


async def test_callback_route_error_param(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/oauth/github/callback?error=access_denied&state=s")
    assert resp.status_code == 400


async def test_callback_route_unknown_state(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get("/oauth/github/callback?code=code&state=unknown")
    assert resp.status_code == 400


async def test_callback_route_success(app, provider):
    state = "test-state"
    sub = "alice"
    await provider._pending_store.create(state, {"sub": sub}, ttl=60)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get(f"/oauth/github/callback?code=authcode&state={state}")

    assert resp.status_code == 200
    assert await provider._token_store.get(sub) is not None


async def test_callback_route_exchange_failure(app, provider):
    provider._exchange_code = AsyncMock(return_value=None)
    state = "test-state"
    await provider._pending_store.create(state, {"sub": "alice"}, ttl=60)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        resp = await c.get(f"/oauth/github/callback?code=code&state={state}")

    assert resp.status_code == 400


# ── from_standard_oauth2 factory ─────────────────────────────────────────────


def test_from_standard_oauth2_creates_provider():
    uc: ContextVar = ContextVar("test_uc", default=None)
    ts, ps = MemoryTokenStore(), MemoryPendingStore()
    p = OAuthProvider.from_standard_oauth2(
        name="myapp",
        authorization_url="https://example.com/authorize",
        token_url="https://example.com/token",
        client_id="cid",
        client_secret="csec",
        scope="read",
        redirect_uri="http://localhost/callback",
        user_context=uc,
        token_store=ts,
        pending_store=ps,
    )
    assert p.name == "myapp"
    assert p.callback_path == "/callback"


async def test_from_standard_oauth2_exchange_code():
    uc: ContextVar = ContextVar("test_uc2", default=None)
    ts, ps = MemoryTokenStore(), MemoryPendingStore()
    p = OAuthProvider.from_standard_oauth2(
        name="myapp2",
        authorization_url="https://example.com/authorize",
        token_url="https://example.com/token",
        client_id="cid",
        client_secret="csec",
        scope="read",
        redirect_uri="http://localhost/callback",
        user_context=uc,
        token_store=ts,
        pending_store=ps,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "exchange-tok", "expires_in": 3600}
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("mcpauthkit.providers.oauth_provider.httpx.AsyncClient", return_value=mock_client):
        result = await p._exchange_code("code123", "state123", "http://localhost/callback")

    assert result == {"access_token": "exchange-tok", "expires_in": 3600}


async def test_from_standard_oauth2_exchange_code_no_access_token():
    """Response body missing access_token returns None."""
    uc: ContextVar = ContextVar("test_uc4", default=None)
    ts, ps = MemoryTokenStore(), MemoryPendingStore()
    p = OAuthProvider.from_standard_oauth2(
        name="myapp4",
        authorization_url="https://example.com/authorize",
        token_url="https://example.com/token",
        client_id="cid",
        client_secret="csec",
        scope="read",
        redirect_uri="http://localhost/callback",
        user_context=uc,
        token_store=ts,
        pending_store=ps,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"token_type": "bearer"}  # no access_token
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("mcpauthkit.providers.oauth_provider.httpx.AsyncClient", return_value=mock_client):
        result = await p._exchange_code("code", "state", "http://localhost/callback")

    assert result is None


def test_parse_token_data_unknown_type_returns_none():
    """Passing a non-typed value (e.g. int) hits the final return None branch."""
    assert _parse_token_data(42, 0) is None  # type: ignore[arg-type]


def test_oauth_provider_lazy_store_init():
    """Provider created without explicit stores uses create_stores() internally."""
    uc: ContextVar = ContextVar("lazy_uc", default=None)
    p = OAuthProvider(
        name="lazy",
        build_auth_url=lambda s, r: s,
        exchange_code=AsyncMock(),
        redirect_uri="http://localhost/callback",
        user_context=uc,
        # No token_store / pending_store — triggers lazy init
    )
    assert p._token_store is not None
    assert p._pending_store is not None


async def test_ensure_blocking_url_elicit_accepted_but_times_out(provider):
    """elicit_url accepted but the OAuth callback never arrives → timeout → None."""
    provider._token_timeout = 0.1
    ctx = MockContext()
    result = await provider._ensure_token_blocking(ctx, "alice", "Alice")
    assert result is None


async def test_ensure_blocking_form_fallback_times_out(provider):
    """Form fallback accepted but the OAuth callback never arrives → timeout → None."""
    provider._token_timeout = 0.1
    ctx = MockContext(
        elicit_url_raises=NotImplementedError("unsupported"),
        elicit_form_completed=True,
    )
    result = await provider._ensure_token_blocking(ctx, "alice", "Alice")
    assert result is None


async def test_ensure_blocking_send_elicit_complete_failure_ignored(provider):
    """send_elicit_complete raising does not prevent token from being returned."""
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
        state = captured[0]
        await provider._token_store.set(sub, {"access_token": "t", "stored_at": time.time()})
        await provider._pending_store.set_result(state, {"_elicit_sent": False})

    task = asyncio.create_task(fire())
    token = await provider._ensure_token_blocking(ctx, sub, "Alice")
    await task
    assert token == "t"


async def test_handle_callback_exchange_raises_returns_none(provider):
    """If exchange_code raises, _handle_callback returns None gracefully."""
    provider._exchange_code = AsyncMock(side_effect=RuntimeError("network error"))
    state = "cb-state"
    await provider._pending_store.create(state, {"sub": "alice"}, ttl=60)
    result = await provider._handle_callback("code", state)
    assert result is None


async def test_handle_callback_send_elicit_complete_failure_ignored(provider):
    """send_elicit_complete failing in the callback handler is logged, not raised."""
    state = "cb-state"
    sub = "alice"
    mock_session = MagicMock()
    mock_session.send_elicit_complete = AsyncMock(side_effect=RuntimeError("boom"))
    await provider._pending_store.create(state, {"sub": sub}, ttl=60)
    provider._sessions[state] = {"session": mock_session, "elicitation_id": "e1"}
    result = await provider._handle_callback("code", state)
    assert result == sub  # token stored, sub returned despite send failure
    uc: ContextVar = ContextVar("test_uc3", default=None)
    ts, ps = MemoryTokenStore(), MemoryPendingStore()
    p = OAuthProvider.from_standard_oauth2(
        name="myapp3",
        authorization_url="https://example.com/authorize",
        token_url="https://example.com/token",
        client_id="cid",
        client_secret="csec",
        scope="read",
        redirect_uri="http://localhost/callback",
        user_context=uc,
        token_store=ts,
        pending_store=ps,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("mcpauthkit.providers.oauth_provider.httpx.AsyncClient", return_value=mock_client):
        result = await p._exchange_code("bad-code", "state", "http://localhost/callback")

    assert result is None
