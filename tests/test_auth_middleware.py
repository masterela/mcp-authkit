"""
Tests for mcpauthkit.auth_middleware — JWT bearer validation and open paths.
"""

from __future__ import annotations

from contextvars import ContextVar
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcpauthkit.auth_middleware import JwtAuthMiddleware
from mcpauthkit.jwt_validator import JwtFailReason

# Shared ContextVar for all tests in this module
current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)

MOCK_CLAIMS = {
    "sub": "user-123",
    "preferred_username": "alice",
    "email": "alice@example.com",
    "name": "Alice",
    "iss": "http://keycloak.local/realms/test",
    "exp": 9_999_999_999,
}


def _build_app(open_paths: tuple[str, ...] = ("/health",)) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        JwtAuthMiddleware,
        issuer_url="http://keycloak.local/realms/test",
        current_user=current_user,
        server_base_url="http://testserver",
        open_paths=open_paths,
    )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/protected")
    async def protected():
        user = current_user.get()
        return {"sub": user["sub"] if user else None}

    return app


@pytest.fixture()
def valid_client(monkeypatch) -> TestClient:
    monkeypatch.setattr(
        "mcpauthkit.auth_middleware.validate_jwt",
        AsyncMock(return_value=(MOCK_CLAIMS, None)),
    )
    return TestClient(_build_app(), raise_server_exceptions=True)


@pytest.fixture()
def invalid_client(monkeypatch) -> TestClient:
    monkeypatch.setattr(
        "mcpauthkit.auth_middleware.validate_jwt",
        AsyncMock(return_value=(None, JwtFailReason.INVALID)),
    )
    return TestClient(_build_app(), raise_server_exceptions=True)


@pytest.fixture()
def expired_client(monkeypatch) -> TestClient:
    monkeypatch.setattr(
        "mcpauthkit.auth_middleware.validate_jwt",
        AsyncMock(return_value=(None, JwtFailReason.EXPIRED)),
    )
    return TestClient(_build_app(), raise_server_exceptions=True)


# ── Open paths ────────────────────────────────────────────────────────────────


def test_open_path_requires_no_auth(invalid_client):
    resp = invalid_client.get("/health")
    assert resp.status_code == 200


# ── Missing / malformed Bearer ────────────────────────────────────────────────


def test_no_authorization_header_returns_401(invalid_client):
    resp = invalid_client.get("/protected")
    assert resp.status_code == 401


def test_non_bearer_scheme_returns_401(invalid_client):
    resp = invalid_client.get("/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401


def test_401_includes_www_authenticate_header(invalid_client):
    resp = invalid_client.get("/protected")
    assert "WWW-Authenticate" in resp.headers
    assert "Bearer" in resp.headers["WWW-Authenticate"]


# ── Invalid token ─────────────────────────────────────────────────────────────


def test_invalid_token_returns_401(invalid_client):
    resp = invalid_client.get("/protected", headers={"Authorization": "Bearer bad-token"})
    assert resp.status_code == 401


# ── Expired token ─────────────────────────────────────────────────────────────


def test_expired_token_returns_401(expired_client):
    resp = expired_client.get("/protected", headers={"Authorization": "Bearer expired-token"})
    assert resp.status_code == 401


def test_expired_token_www_authenticate_contains_invalid_token(expired_client):
    resp = expired_client.get("/protected", headers={"Authorization": "Bearer expired-token"})
    www_auth = resp.headers.get("WWW-Authenticate", "")
    assert "invalid_token" in www_auth


# ── Valid token ───────────────────────────────────────────────────────────────


def test_valid_token_returns_200(valid_client):
    resp = valid_client.get("/protected", headers={"Authorization": "Bearer valid-token"})
    assert resp.status_code == 200


def test_valid_token_populates_current_user(valid_client):
    resp = valid_client.get("/protected", headers={"Authorization": "Bearer valid-token"})
    assert resp.json()["sub"] == "user-123"


# ── OPTIONS passthrough ───────────────────────────────────────────────────────


def test_options_bypasses_auth(invalid_client):
    resp = invalid_client.options("/protected")
    # Must not be a 401 — middleware lets OPTIONS through unconditionally
    assert resp.status_code != 401
