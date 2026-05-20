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

## Quick links

- [JwtAuthMiddleware](api/middleware.md) — primary OIDC JWT validation
- [oauth_meta_router](api/routes.md) — RFC 8414 / RFC 9728 well-known endpoints
- [OAuthProvider](api/oauth.md) — tool-level OAuth 2.0 Authorization Code flow
- [CredentialsProvider](api/credentials.md) — tool-level PAT / API key form
- [Storage backends](api/store.md) — memory, file, Redis

See the [GitHub repository](https://github.com/masterela/mcp-authkit) for the source and the [CHANGELOG](https://github.com/masterela/mcp-authkit/blob/main/CHANGELOG.md) for release history.
