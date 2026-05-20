"""
Tests for mcpauthkit.jwt_validator.

Uses a locally generated RSA-2048 key pair — no real OIDC server required.
httpx.AsyncClient is patched to serve pre-canned OIDC / JWKS responses.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk as jose_jwk
from jose import jwt

import mcpauthkit.jwt_validator as jv
from mcpauthkit.jwt_validator import JwtFailReason, validate_jwt

# ── Test key material (generated once at module import) ───────────────────────

_RSA_KEY = rsa.generate_private_key(65537, 2048, default_backend())
_PRIVATE_PEM = _RSA_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
_PUBLIC_PEM = (
    _RSA_KEY.public_key()
    .public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    .decode()
)

_ISSUER = "http://test-issuer.local/realms/test"
_JWKS_URI = f"{_ISSUER}/.well-known/jwks.json"
_OIDC_DOC: dict = {
    "issuer": _ISSUER,
    "jwks_uri": _JWKS_URI,
    "authorization_endpoint": f"{_ISSUER}/auth",
    "token_endpoint": f"{_ISSUER}/token",
}
_JWK_OBJ = jose_jwk.construct(_PUBLIC_PEM, algorithm="RS256")
_JWKS_DOC: dict = {"keys": [_JWK_OBJ.to_dict()]}


def _sign(sub: str = "alice", iss: str = _ISSUER, exp_offset: int = 300) -> str:
    return jwt.encode(
        {"sub": sub, "iss": iss, "exp": int(time.time()) + exp_offset},
        _PRIVATE_PEM,
        algorithm="RS256",
    )


# ── httpx mock helpers ────────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, data: dict) -> None:
        self._data = data

    def json(self) -> dict:
        return self._data

    def raise_for_status(self) -> None:
        pass


class _FakeClient:
    """Minimal async httpx.AsyncClient stand-in."""

    def __init__(self, urls: dict) -> None:
        self._urls = urls

    async def get(self, url: str, **_kw) -> _FakeResp:
        val = self._urls.get(url)
        if val is None:
            raise ConnectionError(f"no mock configured for {url}")
        if isinstance(val, Exception):
            raise val
        return _FakeResp(val)

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        pass


def _httpx(
    oidc: dict | None = None,
    jwks: dict | None = None,
    oidc_error: Exception | None = None,
):
    """Return a context-manager that patches httpx.AsyncClient in jwt_validator."""
    oidc_url = f"{_ISSUER}/.well-known/openid-configuration"
    urls: dict = {
        oidc_url: oidc_error if oidc_error is not None else (oidc or _OIDC_DOC),
        _JWKS_URI: jwks or _JWKS_DOC,
    }
    return patch(
        "mcpauthkit.jwt_validator.httpx.AsyncClient",
        return_value=_FakeClient(urls),
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_caches():
    """Isolate cache state between tests."""
    jv._oidc_cache.clear()
    jv._jwks_cache.clear()
    yield
    jv._oidc_cache.clear()
    jv._jwks_cache.clear()


# ── Tests: validate_jwt ───────────────────────────────────────────────────────


async def test_valid_jwt_returns_claims():
    token = _sign()
    with _httpx():
        claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is not None
    assert claims["sub"] == "alice"
    assert reason is None


async def test_expired_jwt_returns_expired():
    token = _sign(exp_offset=-60)
    with _httpx():
        claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is None
    assert reason is JwtFailReason.EXPIRED


async def test_wrong_signing_key_returns_invalid():
    other_key = rsa.generate_private_key(65537, 2048, default_backend())
    other_pem = other_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    token = jwt.encode(
        {"sub": "eve", "iss": _ISSUER, "exp": int(time.time()) + 300},
        other_pem,
        algorithm="RS256",
    )
    with _httpx():
        claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is None
    assert reason is JwtFailReason.INVALID


async def test_issuer_mismatch_returns_invalid():
    token = _sign(iss="http://evil.example.com")
    with _httpx():
        claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is None
    assert reason is JwtFailReason.INVALID


async def test_disallowed_algorithm_returns_invalid():
    # HS256 is not in _ALLOWED_ALGORITHMS — rejected before any HTTP call
    token = jwt.encode(
        {"sub": "alice", "iss": _ISSUER, "exp": int(time.time()) + 300},
        "secret",
        algorithm="HS256",
    )
    claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is None
    assert reason is JwtFailReason.INVALID


async def test_network_error_returns_invalid():
    token = _sign()
    with _httpx(oidc_error=ConnectionError("unreachable")):
        claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is None
    assert reason is JwtFailReason.INVALID


# ── Tests: caching ────────────────────────────────────────────────────────────


async def test_oidc_cache_hit_avoids_http():
    """Pre-populated OIDC + JWKS caches → validate_jwt succeeds without HTTP."""
    jv._oidc_cache[_ISSUER] = (time.monotonic(), _OIDC_DOC)
    jv._jwks_cache[_JWKS_URI] = (time.monotonic(), _JWKS_DOC)
    # No httpx patch — a real HTTP attempt to test-issuer.local would raise
    token = _sign()
    claims, reason = await validate_jwt(token, _ISSUER)
    assert claims is not None
    assert reason is None


async def test_get_oidc_config_populates_cache():
    with _httpx():
        result = await jv._get_oidc_config(_ISSUER)
    assert _ISSUER in jv._oidc_cache
    assert result["jwks_uri"] == _JWKS_URI


async def test_get_oidc_config_returns_cached_without_http():
    jv._oidc_cache[_ISSUER] = (time.monotonic(), _OIDC_DOC)
    result = await jv._get_oidc_config(_ISSUER)
    assert result is _OIDC_DOC  # exact same object from cache


async def test_get_jwks_populates_cache():
    with _httpx():
        result = await jv._get_jwks(_JWKS_URI)
    assert _JWKS_URI in jv._jwks_cache
    assert "keys" in result


async def test_get_jwks_returns_cached_without_http():
    jv._jwks_cache[_JWKS_URI] = (time.monotonic(), _JWKS_DOC)
    result = await jv._get_jwks(_JWKS_URI)
    assert result is _JWKS_DOC  # exact same object from cache
