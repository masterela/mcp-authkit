"""
mcpauthkit — MCP authentication elicitation library
=====================================================

Provides two providers for gating MCP tools behind credential acquisition:

OAuthProvider
    Gates tools behind a third-party OAuth 2.0 Authorization Code flow
    (GitHub, Google, Jira, Entra, etc.).  Uses URL mode elicitation so
    the client opens the provider's login page; the tool call stays open
    until the callback fires (or raises immediately in fail-fast mode).

    Quick start::

        from mcpauthkit import OAuthProvider

        github = OAuthProvider.from_standard_oauth2(
            name="github",
            authorization_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            client_id=..., client_secret=..., scope="read:user repo",
            redirect_uri="http://localhost:8005/github/callback",
            user_context=current_user,
        )
        github.register(app)                 # register callback route
        _OPEN_PATHS = (..., github.callback_path)

        @mcp.tool(description="...")
        @github.require_token()
        async def my_tool(ctx: Context, ...) -> str:
            token = github.get_token()       # guaranteed non-None here

CredentialsProvider
    Gates tools behind a PAT / API-key form served by the MCP server
    itself.  The client opens an internal URL where the user fills in
    credentials; values are stored server-side and never passed through
    the AI assistant.

    Quick start::

        from mcpauthkit import CredentialsProvider

        creds = CredentialsProvider(
            name="confluence",
            variables={"pat": {"label": "PAT", "type": "password", ...}},
            user_context=current_user,
            server_base_url="http://localhost:8005",
            doc="/path/to/how-to.md",        # optional Markdown guide
        )
        creds.register(app)
        _OPEN_PATHS = (..., *creds.open_paths)

        @mcp.tool(description="...")
        @creds.require_credentials()
        async def my_tool(ctx: Context, ...) -> str:
            c = creds.get_credentials()      # {"pat": "...", ...}

auth_routes
    Generic well-known OAuth metadata endpoints and a DCR façade::

        from mcpauthkit.auth_routes import register_oauth_meta_routes
        register_oauth_meta_routes(app, server_base_url=..., keycloak_url=..., ...)

store
    Pluggable encrypted storage backends::

        from mcpauthkit.store import create_stores
        token_store, pending_store = create_stores()   # reads TOKEN_STORAGE_MODE env var
        # pass token_store / pending_store into OAuthProvider / CredentialsProvider
"""
from .providers import OAuthProvider, CredentialsProvider
from .store import TokenStore, PendingStore, create_stores

__all__ = [
    "OAuthProvider",
    "CredentialsProvider",
    "TokenStore",
    "PendingStore",
    "create_stores",
]
