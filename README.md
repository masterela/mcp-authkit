# mcp-authkit

[![CI](https://github.com/masterela/mcp-authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/masterela/mcp-authkit/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/masterela/mcp-authkit/branch/main/graph/badge.svg)](https://codecov.io/gh/masterela/mcp-authkit)
[![PyPI version](https://img.shields.io/pypi/v/mcp-authkit)](https://pypi.org/project/mcp-authkit/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-authkit)](https://pypi.org/project/mcp-authkit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Pluggable authentication library for [FastMCP](https://github.com/modelcontextprotocol/python-sdk) servers built on FastAPI / Starlette.

Supports two independent auth legs:

1. **Primary leg** — every MCP session is gated behind a standard OIDC provider (Keycloak, Okta, Entra ID, Duende, Auth0, …) using JWT bearer tokens. The MCP client (e.g. VS Code Copilot) handles the PKCE flow automatically.
2. **Secondary leg** — individual MCP tools can additionally require a third-party OAuth token or a PAT / API key, collected on demand via MCP elicitation.

---

## Installation

```bash
pip install mcp-authkit

# Optional Redis storage backend
pip install "mcp-authkit[redis]"
```

---

## Package layout

```
mcpauthkit/
├── __init__.py                 # Public exports: OAuthProvider, CredentialsProvider, …
├── auth_middleware.py          # JwtAuthMiddleware (BaseHTTPMiddleware)
├── auth_routes.py              # oauth_meta_router() — well-known + DCR façade
├── jwt_validator.py            # OIDC JWKS-based JWT validation (provider-agnostic)
├── providers/
│   ├── oauth_provider.py       # OAuthProvider — third-party OAuth 2.0 leg
│   ├── credentials_provider.py # CredentialsProvider — PAT / API-key form
│   └── templates/              # Jinja2 HTML templates (no external CDN)
└── store/
    ├── base.py                 # Abstract store interfaces
    ├── memory.py               # In-process store (dev / testing)
    ├── file_store.py           # Fernet-encrypted file store
    ├── redis_store.py          # Async Redis store (requires redis extra)
    ├── encryption.py           # Fernet key derivation helpers
    └── factory.py              # create_stores() — env-driven backend selection
```

The repository also contains `server.py` (a complete example server using GitHub OAuth and Confluence credentials) and a `docker-compose.yml` / `keycloak-realm.json` for running a local Keycloak instance. See the [quickstart repo](https://github.com/masterela/mcp-authkit-quickstart) for a guided walkthrough.

---

## Primary auth leg — OIDC JWT validation

Every request to the MCP server must carry a valid `Authorization: Bearer <token>` issued by the configured OIDC provider. The middleware performs JWKS discovery automatically and caches keys for 10 minutes.

```python
from mcpauthkit.auth_middleware import JwtAuthMiddleware
from mcpauthkit.auth_routes import oauth_meta_router

ISSUER_URL    = "https://sso.example.com/realms/my-realm"
SERVER_URL    = "https://my-mcp-server.example.com"
CLIENT_ID     = "my-mcp-public-client"   # pre-registered public client

# Publish RFC 8414 / MCP-spec well-known endpoints + DCR façade
app.include_router(oauth_meta_router(
    server_base_url=SERVER_URL,
    issuer_url=ISSUER_URL,
    client_id=CLIENT_ID,
))

# Validate JWT on every request; populate current_user ContextVar
app.add_middleware(
    JwtAuthMiddleware,
    issuer_url=ISSUER_URL,
    current_user=current_user,
    server_base_url=SERVER_URL,
    open_paths=(
        "/.well-known", "/health", "/register",
        github_oauth.callback_path,
        *confluence_creds.open_paths,
    ),
)
```

### `oauth_meta_router`

Returns a FastAPI `APIRouter` with:

| Route | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET /.well-known/oauth-protected-resource/{path}` | Wildcard variant (some clients append the resource path) |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata (proxied from the real OIDC provider) |
| `POST /register` | Dynamic Client Registration façade — always returns the pre-registered public client ID |

### `JwtAuthMiddleware`

`BaseHTTPMiddleware` subclass. Parameters passed via `app.add_middleware(...)`:

| Parameter | Type | Description |
|---|---|---|
| `issuer_url` | `str` | OIDC issuer base URL (e.g. Keycloak realm URL) |
| `current_user` | `ContextVar` | Populated with verified claims on each authenticated request |
| `server_base_url` | `str` | Used in `WWW-Authenticate` realm / resource-metadata URIs |
| `open_paths` | `tuple[str, ...]` | Path prefixes that bypass authentication |

Returns `401` with a standards-compliant `WWW-Authenticate: Bearer …` header when authentication fails, triggering the PKCE flow in the MCP client automatically.

### `jwt_validator`

Provider-agnostic OIDC JWT validation. Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA. Discovers `jwks_uri` automatically via `{issuer_url}/.well-known/openid-configuration`. OIDC config and JWKS are cached for 10 minutes.

---

## Secondary auth leg — tool-level credential acquisition

Individual tools can be gated behind additional credentials collected on demand via [MCP elicitation](https://spec.modelcontextprotocol.io/specification/2025-11-25/client/elicitation/).

### `OAuthProvider` — third-party OAuth 2.0

Gates a tool behind a full Authorization Code + PKCE flow with a third-party provider. The MCP client opens the provider's login page; the tool call suspends until the callback fires.

```python
from mcpauthkit import OAuthProvider

github_oauth = OAuthProvider.from_standard_oauth2(
    name="github",
    authorization_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    client_id=os.environ["GITHUB_CLIENT_ID"],
    client_secret=os.environ["GITHUB_CLIENT_SECRET"],
    scope="read:user repo",
    redirect_uri=f"{SERVER_URL}/github/callback",
    user_context=current_user,
)
github_oauth.register(app)   # registers GET /github/callback on the FastAPI app

@mcp.tool(description="List open PRs")
@github_oauth.require_token()
async def list_prs(ctx: Context, repo: str) -> str:
    token = github_oauth.get_token()    # guaranteed non-None inside the decorator
    ...
```

Key methods:

| Method | Description |
|---|---|
| `from_standard_oauth2(...)` | Factory for any standard OAuth 2.0 provider |
| `register(app)` | Register the callback route on the FastAPI app |
| `require_token(*, fail_fast=False)` | Decorator — elicits token if not cached, or raises immediately |
| `get_token()` | Return the cached access token for the current user (or `None`) |
| `invalidate_token(sub)` | Evict a user's cached token |
| `.callback_path` | The redirect URI path (add to `open_paths`) |

### `CredentialsProvider` — PAT / API key form

Serves a self-hosted HTML form where the user enters credentials (PATs, API keys, etc.). Values are stored server-side, keyed by the primary OIDC `sub`. The form optionally renders a Markdown how-to guide (client-side via [marked.js](https://marked.js.org/)).

```python
from mcpauthkit import CredentialsProvider

confluence_creds = CredentialsProvider(
    name="confluence",
    variables={
        "pat": {
            "label": "Personal Access Token",
            "type": "password",
            "placeholder": "Your Confluence PAT",
        },
    },
    user_context=current_user,
    server_base_url=SERVER_URL,
    doc="docs/confluence_token_how.md",   # optional — rendered above the form
)
confluence_creds.register(app)

@mcp.tool(description="List Confluence pages")
@confluence_creds.require_credentials()
async def list_pages(ctx: Context, space: str) -> str:
    creds = confluence_creds.get_credentials()   # {"pat": "..."}
    ...
```

Key methods / properties:

| Member | Description |
|---|---|
| `register(app)` | Register entry + submit routes on the FastAPI app |
| `require_credentials(*, fail_fast=False)` | Decorator — elicits credentials if not cached |
| `get_credentials()` | Return the cached credentials dict for the current user |
| `invalidate_credentials(sub)` | Evict a user's cached credentials |
| `.open_paths` | Tuple of paths to add to `JwtAuthMiddleware` `open_paths` |

---

## MCP mount

The FastMCP sub-app must be mounted at `/` **after** all routes are registered. Its internal Starlette router exposes the MCP endpoint at `/mcp`:

```python
# All routes (include_router, register, @app.get) must come before this line
app.mount("/", app=mcp.streamable_http_app())
```

The MCP client connects to `http://<host>:<port>/mcp`.

---

## HTML templates

All browser-facing pages use Jinja2 templates in `mcpauthkit/providers/templates/`. Every page extends `base.html` which provides:

- A blue "MCP Authentication 🔒" top bar
- A centered card layout
- Minimal inline CSS (no external CDN dependencies except `marked.js` on the credentials entry page)

---

## Getting started

A full working example (Docker Compose with Redis + Keycloak, a GitHub OAuth tool, and a Confluence credentials tool) lives in the companion repo:

**[mcp-authkit-quickstart](https://github.com/masterela/mcp-authkit-quickstart)**

---

## Storage backends

| Mode | Class | Notes |
|---|---|---|
| `memory` (default) | `MemoryTokenStore` / `MemoryPendingStore` | In-process. Tokens lost on restart. Suitable for development. |
| `file` | `FileTokenStore` / `FilePendingStore` | Fernet-encrypted JSON files. Good for single-instance deployments. |
| `redis` | `RedisTokenStore` / `RedisPendingStore` | Async Redis. Requires `pip install "mcp-authkit[redis]"`. Use for multi-replica deployments. |

Select a backend via the `TOKEN_STORAGE_MODE` environment variable (`memory` / `file` / `redis`), or call `create_stores()` directly.

---

## Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | HTTP framework |
| `mcp>=1.6` | MCP server SDK (FastMCP) |
| `starlette` | ASGI primitives, `BaseHTTPMiddleware` |
| `python-jose[cryptography]` | JWT decoding and JWKS validation |
| `httpx` | Async HTTP client (token exchange, OIDC discovery) |
| `jinja2` | HTML template rendering |
| `cryptography` | Fernet encryption for file and Redis stores |

---

## Contributing

```bash
# Install dev dependencies
uv sync --group dev

# Lint + type-check
uv run ruff check mcpauthkit/ tests/
uv run mypy mcpauthkit/

# Tests with coverage
uv run pytest --cov=mcpauthkit --cov-report=term-missing -q
```

See [CHANGELOG.md](CHANGELOG.md) for release history.
