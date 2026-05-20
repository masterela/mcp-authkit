# mcp-authkit

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

## Quick start

### Leg 1 — OIDC JWT middleware

`current_user` is a standard Python [`ContextVar`](https://docs.python.org/3/library/contextvars.html) you declare once at module level. The middleware writes the validated JWT claims into it on every request; the Leg 2 providers read the `sub` claim from it to key cached tokens per user.

```python
from contextvars import ContextVar
from mcpauthkit.auth_middleware import JwtAuthMiddleware
from mcpauthkit.auth_routes import oauth_meta_router

# Declare once at module level — shared by middleware + all providers
current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)

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

### Leg 2a — third-party OAuth token

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

### Leg 2b — PAT / API key form

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
