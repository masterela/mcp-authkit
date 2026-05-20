"""
mcpauthkit.auth_middleware — JWT bearer middleware for FastAPI / MCP servers.

Validates every incoming request against an OIDC provider's JWKS endpoint
and populates a ``current_user`` ContextVar so tools can read the caller's
claims.

Usage
-----
    from mcpauthkit.auth_middleware import JwtAuthMiddleware

    app.add_middleware(
        JwtAuthMiddleware,
        issuer_url=settings.keycloak_url,
        current_user=current_user,
        server_base_url="http://localhost:8005",
        open_paths=(
            "/.well-known", "/health", "/register",
            github_oauth.callback_path,
            *confluence_creds.open_paths,
        ),
    )
"""
from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Optional

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .jwt_validator import JwtFailReason, validate_jwt

logger = logging.getLogger(__name__)


class JwtAuthMiddleware(BaseHTTPMiddleware):
    """
    JWT bearer middleware compatible with ``app.add_middleware()``.

    Validates the ``Authorization: Bearer <token>`` header on every
    non-open request using OIDC JWKS discovery.  Works with any standard
    OIDC provider (Keycloak, Okta, Entra ID, Duende, Auth0, …).

    Parameters
    ----------
    issuer_url
        Base URL of the OIDC issuer,
        e.g. ``"http://localhost:8889/realms/mcp-poc5"`` or
        ``"https://login.microsoftonline.com/{tenant}/v2.0"``.
    current_user
        ContextVar populated with the verified JWT claims dict on each
        authenticated request.
    server_base_url
        Used to build the ``WWW-Authenticate`` realm / resource-metadata URIs.
    open_paths
        Tuple of path prefixes that bypass authentication (browser redirects,
        health checks, well-known endpoints, provider callbacks, etc.).
    """

    def __init__(
        self,
        app,
        *,
        issuer_url: str,
        current_user: ContextVar[Optional[dict]],
        server_base_url: str,
        open_paths: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self._issuer_url   = issuer_url
        self._current_user = current_user
        self._base         = server_base_url.rstrip("/")
        self._open_paths   = open_paths

    async def dispatch(self, request: Request, call_next) -> Response:
        logger.debug(
            "→ %s %s  auth=%s  open=%s",
            request.method,
            request.url.path,
            bool(request.headers.get("Authorization")),
            self._is_open(request.url.path),
        )

        if request.method == "OPTIONS" or self._is_open(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.debug("→ no/bad Bearer → 401")
            return self._unauthorized()

        token = auth_header[len("Bearer "):]
        claims, fail_reason = await validate_jwt(token, self._issuer_url)
        if claims is None:
            logger.debug("→ JWT invalid (reason=%s) → 401", fail_reason)
            return (
                self._token_expired()
                if fail_reason is JwtFailReason.EXPIRED
                else self._unauthorized()
            )

        sub = claims.get("sub") or claims.get("preferred_username", "unknown")
        logger.info(
            "Authenticated: sub=%s preferred_username=%s",
            sub, claims.get("preferred_username"),
        )
        self._current_user.set({
            "sub":                sub,
            "preferred_username": claims.get("preferred_username"),
            "email":              claims.get("email"),
            "name":               claims.get("name"),
            "iss":                claims.get("iss"),
            "exp":                claims.get("exp"),
        })
        return await call_next(request)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _is_open(self, path: str) -> bool:
        return any(path.startswith(p) for p in self._open_paths)

    def _unauthorized(self) -> JSONResponse:
        """No token — client must start a fresh PKCE flow (RFC 6750 §3.1)."""
        return JSONResponse(
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer realm="{self._base}/mcp",'
                    f' resource_metadata="{self._base}/.well-known/oauth-protected-resource"'
                )
            },
            content={"error": "unauthorized"},
        )

    def _token_expired(self) -> JSONResponse:
        """Token present but expired — client should refresh (RFC 6750 §3.1)."""
        return JSONResponse(
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer realm="{self._base}/mcp",'
                    f' resource_metadata="{self._base}/.well-known/oauth-protected-resource",'
                    f' error="invalid_token",'
                    f' error_description="The access token has expired"'
                )
            },
            content={
                "error": "invalid_token",
                "error_description": "The access token has expired",
            },
        )
