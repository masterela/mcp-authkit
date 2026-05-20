# mcp-authkit

Pluggable authentication library for [FastMCP](https://github.com/modelcontextprotocol/python-sdk) servers built on FastAPI / Starlette.

## Two auth legs

1. **Primary leg** — every MCP session is gated behind a standard OIDC provider (Keycloak, Okta, Entra ID, Duende, Auth0, …) using JWT bearer tokens. The MCP client (e.g. VS Code Copilot) handles the PKCE flow automatically.
2. **Secondary leg** — individual MCP tools can additionally require a third-party OAuth token or a PAT / API key, collected on demand via MCP elicitation.

## Installation

```bash
pip install mcp-authkit

# Optional Redis storage backend
pip install "mcp-authkit[redis]"
```

## Setup

### 1 — Declare the shared `ContextVar`

Before wiring up anything, declare a single `ContextVar` at module level in your server file. This is the object that connects the middleware to the providers: the middleware **writes** the validated JWT claims into it on every request; the Leg 2 providers **read** the `sub` claim from it to key cached tokens per user.

```python
from contextvars import ContextVar

current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)
```

Python's `ContextVar` is automatically scoped per async task, so each concurrent request gets its own isolated value — no threading issues.

### 2 — Add the middleware (Leg 1)

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
    current_user=current_user,   # ← same object declared above
    server_base_url=SERVER_URL,
    open_paths=("/.well-known", "/health", "/register"),
)
```

### 3 — Add Leg 2 providers (optional)

Pass the same `current_user` to any provider so they can look up the right user's cached credential:

```python
from mcpauthkit import OAuthProvider, CredentialsProvider

provider = OAuthProvider.from_standard_oauth2(
    name="github", ..., user_context=current_user
)
provider.register(app)

creds = CredentialsProvider(
    name="confluence", ..., user_context=current_user
)
creds.register(app)
```

See the [Architecture](architecture.md) page for the full flow diagrams, and the [quickstart repo](https://github.com/masterela/mcp-authkit-quickstart) for a complete working example.

## API reference

- [JwtAuthMiddleware](api/middleware.md) — primary OIDC JWT validation
- [oauth_meta_router](api/routes.md) — RFC 8414 / RFC 9728 well-known endpoints
- [OAuthProvider](api/oauth.md) — tool-level OAuth 2.0 Authorization Code flow
- [CredentialsProvider](api/credentials.md) — tool-level PAT / API key form
- [Storage backends](api/store.md) — memory, file, Redis

See the [GitHub repository](https://github.com/masterela/mcp-authkit) for the source and the [CHANGELOG](https://github.com/masterela/mcp-authkit/blob/main/CHANGELOG.md) for release history.
