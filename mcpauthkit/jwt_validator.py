"""
JWKS-based JWT validation for any standard OIDC provider
(Keycloak, Okta, Microsoft Entra ID, Duende, Auth0, …).

The issuer URL's /.well-known/openid-configuration is fetched once and
cached; the jwks_uri within it is used to verify token signatures.
No provider-specific code — pure OIDC / RFC 7517.
"""

import logging
import time
from enum import Enum
from typing import Any, cast

import httpx
from jose import ExpiredSignatureError, JWTError, jwt

logger = logging.getLogger(__name__)

_jwks_cache: dict[str, tuple[float, dict]] = {}
_oidc_cache: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 600.0  # 10 minutes


class JwtFailReason(Enum):
    """Why JWT validation failed — used to emit the correct WWW-Authenticate error."""

    EXPIRED = "expired"  # token present but past exp → client should use refresh_token
    INVALID = "invalid"  # token present but malformed / wrong issuer / bad sig


async def _get_oidc_config(issuer_url: str) -> dict:
    now = time.monotonic()
    if issuer_url in _oidc_cache:
        ts, data = _oidc_cache[issuer_url]
        if now - ts < CACHE_TTL:
            return data
    url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
    _oidc_cache[issuer_url] = (now, data)
    return cast(dict[str, Any], data)


async def _get_jwks(jwks_uri: str) -> dict:
    now = time.monotonic()
    if jwks_uri in _jwks_cache:
        ts, data = _jwks_cache[jwks_uri]
        if now - ts < CACHE_TTL:
            return data
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        data = resp.json()
    _jwks_cache[jwks_uri] = (now, data)
    return cast(dict[str, Any], data)


_ALLOWED_ALGORITHMS = {
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
}


async def validate_jwt(token: str, issuer_url: str) -> tuple[dict | None, JwtFailReason | None]:
    """
    Validate a signed JWT via the issuer's JWKS endpoint.

    The issuer's /.well-known/openid-configuration is fetched (and cached)
    to locate the jwks_uri automatically — no need to hard-code a certs URL.

    Returns (claims, None) on success.
    Returns (None, JwtFailReason.EXPIRED) when the token has expired.
    Returns (None, JwtFailReason.INVALID) for any other failure.
    """
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "RS256")
        if alg not in _ALLOWED_ALGORITHMS:
            logger.warning("JWT uses disallowed algorithm: %s", alg)
            return None, JwtFailReason.INVALID

        oidc = await _get_oidc_config(issuer_url)
        jwks = await _get_jwks(oidc["jwks_uri"])

        claims = jwt.decode(
            token,
            jwks,
            algorithms=list(_ALLOWED_ALGORITHMS),
            options={"verify_aud": False},
        )

        # Enforce issuer
        expected_issuer = oidc.get("issuer", "")
        if expected_issuer and claims.get("iss") != expected_issuer:
            logger.warning(
                "JWT issuer mismatch: expected '%s', got '%s'",
                expected_issuer,
                claims.get("iss"),
            )
            return None, JwtFailReason.INVALID

        return claims, None

    except ExpiredSignatureError:
        logger.debug("JWT validation failed: token expired")
        return None, JwtFailReason.EXPIRED
    except JWTError as exc:
        logger.debug("JWT validation failed: %s", exc)
        return None, JwtFailReason.INVALID
    except Exception as exc:
        logger.warning("Unexpected error during JWT validation: %s", exc)
        return None, JwtFailReason.INVALID
