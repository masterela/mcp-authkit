# MCP Authentication Kit - mcp-authkit

[![CI](https://github.com/masterela/mcp-authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/masterela/mcp-authkit/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/masterela/mcp-authkit/branch/main/graph/badge.svg)](https://codecov.io/gh/masterela/mcp-authkit)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://masterela.github.io/mcp-authkit/)
[![PyPI version](https://img.shields.io/pypi/v/mcp-authkit)](https://pypi.org/project/mcp-authkit/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-authkit)](https://pypi.org/project/mcp-authkit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Pluggable authentication library for [FastMCP](https://github.com/modelcontextprotocol/python-sdk) servers built on FastAPI / Starlette.

It handles two independent authentication legs:

- **Leg 1 — session auth** — every MCP session is gated behind a standard OIDC provider (Keycloak, Okta, Entra ID, Auth0, …) using JWT bearer tokens. `JwtAuthMiddleware` validates tokens and publishes the RFC 8414 / MCP-spec well-known endpoints so the MCP client drives the PKCE flow automatically.
- **Leg 2 — tool-level credentials** — individual tools can additionally require a third-party OAuth token (`OAuthProvider`) or a PAT / API key (`CredentialsProvider`), collected on demand via [MCP elicitation](https://spec.modelcontextprotocol.io/specification/2025-11-25/client/elicitation/).

---

## Installation

```bash
pip install mcp-authkit

# Optional Redis storage backend
pip install "mcp-authkit[redis]"
```

---

<!-- --8<-- [start:quickstart] -->
## Quick start

### Step 1 — Declare `current_user`

The library is wired together through a single [`ContextVar`](https://docs.python.org/3/library/contextvars.html) that **you** create and own. Declare it once at module level in your server file and pass it to everything:

```python
from contextvars import ContextVar

# You create this. The middleware writes it; providers read it.
current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)
```

Python scopes `ContextVar` per async task automatically, so concurrent requests never interfere.

### Step 2 — Add the JWT middleware (Leg 1)

```python
from mcpauthkit.auth_middleware import JwtAuthMiddleware
from mcpauthkit.auth_routes import oauth_meta_router

app.include_router(oauth_meta_router(
    server_base_url=SERVER_URL,
    issuer_url=ISSUER_URL,
    client_id=CLIENT_ID,
))

app.add_middleware(
    JwtAuthMiddleware,
    issuer_url=ISSUER_URL,
    current_user=current_user,
    server_base_url=SERVER_URL,
    open_paths=("/.well-known", "/health", "/register"),
)
```

### Step 3 — Gate a tool behind a third-party OAuth token (Leg 2a)

```python
from mcpauthkit import OAuthProvider

provider = OAuthProvider.from_standard_oauth2(
    name="github",
    authorization_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    client_id=os.environ["GITHUB_CLIENT_ID"],
    client_secret=os.environ["GITHUB_CLIENT_SECRET"],
    scope="read:user repo",
    redirect_uri=f"{SERVER_URL}/github/callback",
    user_context=current_user,
)
provider.register(app)

@mcp.tool()
@provider.require_token()
async def list_prs(ctx: Context, repo: str) -> str:
    token = provider.get_token()
    ...
```

### Step 4 — Gate a tool behind a PAT / API key form (Leg 2b)

```python
from mcpauthkit import CredentialsProvider

creds = CredentialsProvider(
    name="confluence",
    variables={"pat": {"label": "Personal Access Token", "type": "password"}},
    user_context=current_user,
    server_base_url=SERVER_URL,
)
creds.register(app)

@mcp.tool()
@creds.require_credentials()
async def list_pages(ctx: Context, space: str) -> str:
    pat = creds.get_credentials()["pat"]
    ...
```
<!-- --8<-- [end:quickstart] -->

---

## Storage backends

| Mode | Notes |
|---|---|
| `memory` (default) | In-process. Tokens lost on restart. Good for development. |
| `file` | Fernet-encrypted JSON files. Single-instance deployments. |
| `redis` | Async Redis. Requires `mcp-authkit[redis]`. Multi-replica deployments. |

Select via the `TOKEN_STORAGE_MODE` env var (`memory` / `file` / `redis`).

---

## Documentation

Full API reference, architecture diagrams, and configuration details:
**[https://masterela.github.io/mcp-authkit/](https://masterela.github.io/mcp-authkit/)**

A complete working example (Docker Compose + Keycloak + Redis, GitHub OAuth tool, Confluence credentials tool):
**[mcp-authkit-quickstart](https://github.com/masterela/mcp-authkit-quickstart)**

---

## Contributing

```bash
uv sync --group dev
uv run ruff check mcpauthkit/ tests/
uv run mypy mcpauthkit/
uv run pytest --cov=mcpauthkit --cov-report=term-missing -q
```
