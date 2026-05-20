"""
Tests for mcpauthkit.auth_routes — well-known OAuth metadata and DCR façade.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcpauthkit.auth_routes import oauth_meta_router

SERVER = "http://testserver"
ISSUER = "http://keycloak.local/realms/test"
CLIENT_ID = "my-mcp-client"


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(
        oauth_meta_router(
            server_base_url=SERVER,
            issuer_url=ISSUER,
            client_id=CLIENT_ID,
        )
    )
    return TestClient(app, raise_server_exceptions=False)


# ── Protected resource metadata (RFC 9728) ────────────────────────────────────


def test_protected_resource_returns_200(client):
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200


def test_protected_resource_content(client):
    data = client.get("/.well-known/oauth-protected-resource").json()
    assert data["resource"] == f"{SERVER}/mcp"
    assert SERVER in data["authorization_servers"]
    assert "header" in data["bearer_methods_supported"]


def test_protected_resource_with_path_suffix(client):
    resp = client.get("/.well-known/oauth-protected-resource/some/sub/path")
    assert resp.status_code == 200


# ── Authorization server metadata (RFC 8414) ─────────────────────────────────


def test_authorization_server_returns_200(client):
    # OIDC server unreachable → falls back to constructed defaults, still 200
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200


def test_authorization_server_issuer_is_server_base(client):
    data = client.get("/.well-known/oauth-authorization-server").json()
    assert data["issuer"] == SERVER


def test_authorization_server_registration_endpoint(client):
    data = client.get("/.well-known/oauth-authorization-server").json()
    assert data["registration_endpoint"] == f"{SERVER}/register"


def test_authorization_server_required_fields(client):
    data = client.get("/.well-known/oauth-authorization-server").json()
    for field in (
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "grant_types_supported",
        "code_challenge_methods_supported",
    ):
        assert field in data, f"missing field: {field}"


def test_authorization_server_pkce_supported(client):
    data = client.get("/.well-known/oauth-authorization-server").json()
    assert "S256" in data["code_challenge_methods_supported"]


def test_authorization_server_uses_oidc_config(client):
    """When OIDC discovery returns 200, its endpoints override the defaults."""
    from unittest.mock import AsyncMock, MagicMock, patch

    oidc_doc = {
        "authorization_endpoint": "http://kc.test/auth",
        "token_endpoint": "http://kc.test/token",
        "jwks_uri": "http://kc.test/certs",
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = oidc_doc

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("mcpauthkit.auth_routes.httpx.AsyncClient", return_value=mock_client):
        data = client.get("/.well-known/oauth-authorization-server").json()

    assert data["authorization_endpoint"] == "http://kc.test/auth"
    assert data["token_endpoint"] == "http://kc.test/token"
    assert data["jwks_uri"] == "http://kc.test/certs"


# ── DCR façade ────────────────────────────────────────────────────────────────


def test_dcr_returns_201(client):
    resp = client.post(
        "/register",
        json={
            "client_name": "my-app",
            "redirect_uris": ["http://localhost/callback"],
            "grant_types": ["authorization_code"],
        },
    )
    assert resp.status_code == 201


def test_dcr_echoes_client_id(client):
    data = client.post("/register", json={"redirect_uris": ["http://x/cb"]}).json()
    assert data["client_id"] == CLIENT_ID


def test_dcr_echoes_redirect_uris(client):
    uris = ["http://localhost/callback", "vscode://callback"]
    data = client.post("/register", json={"redirect_uris": uris}).json()
    assert data["redirect_uris"] == uris


def test_dcr_bad_json_returns_400(client):
    resp = client.post(
        "/register",
        content=b"not-json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
