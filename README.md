# MCP Auth Library

A reusable authentication library for [FastMCP](https://github.com/modelcontextprotocol/python-sdk) servers built on FastAPI / Starlette. Extracted from PoC 5 of an internal MCP authentication research project.

Supports two independent auth legs:

1. **Primary leg** — every MCP session is gated behind a standard OIDC provider (Keycloak, Okta, Entra ID, Duende, Auth0, …) using JWT bearer tokens. The MCP client (e.g. VS Code Copilot) handles the PKCE flow automatically.
2. **Secondary leg** — individual MCP tools can additionally require a third-party OAuth token or a PAT / API key, collected on demand via MCP elicitation.

---

## Repository layout

```
auth-lib/
├── server.py                   # Example FastMCP server (GitHub + Confluence tools)
├── config.py                   # Pydantic settings (loaded from .env)
├── .env.example                # Template for required environment variables
├── docker-compose.yml          # Keycloak dev instance
├── keycloak-realm.json         # Pre-configured realm (import into Keycloak)
├── docs/
│   └── confluence_token_how.md # Markdown guide rendered in the credentials form
└── lib/                        # ← the reusable library
    ├── __init__.py             # Exports OAuthProvider, CredentialsProvider
    ├── auth_middleware.py      # JwtAuthMiddleware (BaseHTTPMiddleware)
    ├── auth_routes.py          # oauth_meta_router() — well-known + DCR façade
    ├── jwt_validator.py        # OIDC JWKS-based JWT validation (provider-agnostic)
    └── providers/
        ├── oauth_provider.py       # OAuthProvider — third-party OAuth 2.0 leg
        ├── credentials_provider.py # CredentialsProvider — PAT / API-key form
        └── templates/              # Jinja2 HTML templates (Tailwind-free, CDN-free)
            ├── base.html
            ├── oauth_success.html
            ├── oauth_error.html
            ├── credentials_entry.html
            ├── credentials_success.html
            └── credentials_error.html
```

---

## Primary auth leg — OIDC JWT validation

Every request to the MCP server must carry a valid `Authorization: Bearer <token>` issued by the configured OIDC provider. The middleware performs JWKS discovery automatically and caches keys for 10 minutes.

```python
from mcpauthkit.auth_middleware import JwtAuthMiddleware
from mcpauthkit.auth_routes import oauth_meta_router

# Publish RFC 8414 / MCP-spec well-known endpoints + DCR façade
app.include_router(oauth_meta_router(
    server_base_url="http://localhost:8005",
    issuer_url="http://localhost:8889/realms/mcp-poc5",
    client_id="mcp-poc5-vscode",          # pre-registered public client
))

# Validate JWT on every request; populate current_user ContextVar
app.add_middleware(
    JwtAuthMiddleware,
    issuer_url="http://localhost:8889/realms/mcp-poc5",
    current_user=current_user,
    server_base_url="http://localhost:8005",
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
    client_id=settings.github_client_id,
    client_secret=settings.github_client_secret,
    scope="read:user repo",
    redirect_uri="http://localhost:8005/github/callback",
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
    server_base_url="http://localhost:8005",
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

All browser-facing pages use Jinja2 templates in `lib/providers/templates/`. Every page extends `base.html` which provides:

- A blue "MCP Authentication 🔒" top bar
- A centered card layout
- Minimal inline CSS (no external CDN dependencies except `marked.js` on the credentials entry page)

---

## Quick start

```bash
# 1. Start Keycloak (Docker required)
docker compose up -d
# Import keycloak-realm.json via the Keycloak admin console or:
# http://localhost:8889  admin / admin  → import realm

# 2. Copy and fill environment
cp .env.example .env

# 3. Install dependencies
uv sync   # or: pip install -e .

# 4. Run
uv run uvicorn server:app --reload --port 8005
```

Test users: `alice / alice123`, `bob / bob123`.  
Connect VS Code GitHub Copilot to `http://localhost:8005/mcp`.

---

## Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | HTTP framework |
| `fastmcp` / `mcp>=1.6` | MCP server SDK |
| `starlette` | ASGI primitives, `BaseHTTPMiddleware` |
| `pydantic-settings` | Typed configuration from `.env` |
| `python-jose` | JWT decoding and JWKS validation |
| `httpx` | Async HTTP client (token exchange, OIDC discovery) |
| `jinja2` | HTML template rendering |
| `uvicorn` | ASGI server |
