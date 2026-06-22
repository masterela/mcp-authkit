"""
mcpauthkit.auth_routes — generic MCP OAuth metadata endpoints.

Provides the well-known OAuth protected-resource and authorization-server
discovery documents required by the MCP OAuth spec, plus a Dynamic Client
Registration (DCR) façade that returns a pre-registered public client ID.

Works with any standard OIDC provider (Keycloak, Okta, Entra ID, Duende, …).

Usage
-----
    from mcpauthkit.auth_routes import oauth_meta_router

    app.include_router(oauth_meta_router(
        server_base_url="http://localhost:8005",
        issuer_url="http://localhost:8889/realms/mcp-quickstart",
        client_id="mcp-quickstart-vscode",
    ))

Call ``include_router`` before ``app.mount("/", ...)``.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


def oauth_meta_router(
    *,
    server_base_url: str,
    issuer_url: str,
    client_id: str,
    extra_authorize_params: dict[str, str] | None = None,
) -> APIRouter:
    """
    Return an ``APIRouter`` with well-known OAuth metadata routes and a DCR
    façade.  Mount it on the app with ``app.include_router(...)``.

    Parameters
    ----------
    server_base_url
        Full URL of this MCP server, e.g. ``"http://localhost:8005"``.
    issuer_url
        Base URL of the OIDC issuer,
        e.g. ``"http://localhost:8889/realms/mcp-poc5"`` or
        ``"https://login.microsoftonline.com/{tenant}/v2.0"``.
    client_id
        Pre-registered public client ID returned by the DCR façade.
    extra_authorize_params
        Optional extra query parameters appended to the
        ``authorization_endpoint`` in the
        ``/.well-known/oauth-authorization-server`` response.  MCP clients
        read that URL and use it verbatim when redirecting the user to the
        OIDC provider, so any hint placed here is automatically forwarded.

        Use this for provider-specific routing parameters that fall outside
        the standard OAuth 2.0 / OIDC spec.  For example, Okta's ``idp``
        parameter bypasses the Okta login page and routes users directly to
        a configured external Identity Provider::

            app.include_router(oauth_meta_router(
                server_base_url=settings.server_base_url,
                issuer_url="https://your-org.okta.com/oauth2/default",
                client_id=settings.okta_client_id,
                extra_authorize_params={"idp": "0oaz2r21a8RBmZyOL0h7"},
            ))

        Default: ``None`` (no extra params — fully retro-compatible).
    """
    router = APIRouter()
    base = server_base_url.rstrip("/")
    issuer = issuer_url.rstrip("/")

    @router.get("/.well-known/oauth-protected-resource", include_in_schema=False)
    @router.get("/.well-known/oauth-protected-resource/{path:path}", include_in_schema=False)
    async def _protected_resource_metadata(path: str = ""):
        return JSONResponse(
            {
                "resource": f"{base}/mcp",
                "authorization_servers": [base],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["openid", "profile", "email"],
            }
        )

    @router.get("/.well-known/oauth-authorization-server", include_in_schema=False)
    async def _authorization_server_metadata():
        auth_ep = f"{issuer}/protocol/openid-connect/auth"
        token_ep = f"{issuer}/protocol/openid-connect/token"
        jwks_ep = f"{issuer}/protocol/openid-connect/certs"
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{issuer}/.well-known/openid-configuration")
                if resp.status_code == 200:
                    meta = resp.json()
                    auth_ep = meta.get("authorization_endpoint", auth_ep)
                    token_ep = meta.get("token_endpoint", token_ep)
                    jwks_ep = meta.get("jwks_uri", jwks_ep)
        except Exception as exc:
            logger.warning("Could not fetch OIDC metadata: %s", exc)

        if extra_authorize_params:
            sep = "&" if "?" in auth_ep else "?"
            auth_ep += sep + urlencode(extra_authorize_params)

        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": auth_ep,
                "token_endpoint": token_ep,
                "jwks_uri": jwks_ep,
                "registration_endpoint": f"{base}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
            }
        )

    @router.post("/register", include_in_schema=False)
    async def _dynamic_client_registration(request: Request):
        """DCR façade — always echoes back the pre-registered public client ID."""
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_client_metadata"},
            )
        redirect_uris = body.get("redirect_uris", [])
        logger.info(
            "DCR façade: client_name=%s redirect_uris=%s",
            body.get("client_name"),
            redirect_uris,
        )
        return JSONResponse(
            status_code=201,
            content={
                "client_id": client_id,
                "client_id_issued_at": int(time.time()),
                "redirect_uris": redirect_uris,
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )

    return router
