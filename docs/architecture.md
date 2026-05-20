# Architecture

mcp-authkit answers two distinct authentication questions for every MCP tool invocation:

1. **Who is calling?** — every MCP session must carry a valid JWT from a trusted OIDC provider.
2. **Can this tool proceed?** — some tools require a *secondary* credential (an OAuth token from a third-party service, or a PAT/API key) that the primary identity system does not supply.

These are two independent, composable authentication legs that coexist inside the same FastAPI/FastMCP process.

---

## High-level overview

```mermaid
flowchart TB
    Client["MCP Client\n(VS Code, Claude Desktop, …)"]

    subgraph Server["MCP Server (FastAPI + FastMCP)"]
        direction TB
        Meta["oauth_meta_router\n/.well-known/* · /register"]
        MW["JwtAuthMiddleware\nJWKS validation · current_user ContextVar"]
        Tools["FastMCP tools"]
        OAuth["OAuthProvider\nAuthorization Code + PKCE\ntoken store"]
        Creds["CredentialsProvider\nHTML form\ncredential store"]
        MW --- Tools
        Tools -->|"@require_token()"| OAuth
        Tools -->|"@require_credentials()"| Creds
    end

    IdP["Primary OIDC Provider\n/.well-known/openid-configuration\nJWKS endpoint\nAuthorization + Token endpoints"]
    ThirdParty["Third-party OAuth Provider\nAuthorization + Token endpoints"]
    Browser["User's Browser\n(opened by MCP client via elicitation)"]

    Client -->|"1 — PKCE flow\n(handled by client)"| IdP
    Client -->|"2 — Bearer JWT on every request"| MW
    MW -->|"JWKS discovery + validation"| IdP
    Client -->|"3 — tool call"| Tools
    Tools -->|"4 — elicit URL"| Client
    Client -->|"5 — open in browser"| Browser
    Browser -->|"6 — OAuth callback / form submit"| Server
    Browser -->|"7 — redirect to third-party"| ThirdParty
    ThirdParty -->|"8 — auth code callback"| Server
```

---

## Leg 1 — Session-level OIDC JWT authentication

Every HTTP request must include `Authorization: Bearer <token>`. The token is a JWT issued by the configured OIDC provider and validated locally using the provider's public JWKS.

### MCP client registration

Before the MCP client can authenticate users, it needs to know:

- **Where to send users to log in** — the authorization endpoint
- **Which client to use** — a `client_id` it can use for PKCE

The server exposes the endpoints required by the MCP specification so that clients can discover this information automatically.

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP Client
    participant Server as MCP Server
    participant IdP as OIDC Provider

    Client->>Server: GET /mcp (no token)
    Server-->>Client: 401 Unauthorized<br/>WWW-Authenticate: Bearer realm=…<br/>resource_metadata=/.well-known/oauth-protected-resource

    Client->>Server: GET /.well-known/oauth-protected-resource
    Server-->>Client: { authorization_servers: [server_base_url] }

    Client->>Server: GET /.well-known/oauth-authorization-server
    Note over Server: Fetch from IdP, re-publish under server_base_url
    Server-->>Client: { issuer, authorization_endpoint,<br/>token_endpoint, jwks_uri,<br/>registration_endpoint: /register }

    Client->>Server: POST /register {}
    Note over Server: DCR façade — returns pre-registered client
    Server-->>Client: { client_id }
```

**Why a DCR façade?**
The MCP client expects to register dynamically (RFC 7591). In practice, OIDC providers often use a fixed set of pre-registered public clients. The `/register` façade always returns the pre-registered `client_id`, satisfying the protocol without requiring dynamic registration support from the IdP.

**Why proxy the authorization server metadata?**
The MCP spec requires the authorization server metadata to be served at `{server_base_url}/.well-known/oauth-authorization-server`. The real endpoints live at the IdP. The server fetches the IdP's discovery document and re-publishes the real endpoints under its own well-known URL, with `registration_endpoint` pointing to the local façade.

### PKCE authorization flow

Once the client has a `client_id`, it performs a standard PKCE flow directly with the IdP. The server is not involved — it only validates the resulting JWT on subsequent requests.

```mermaid
sequenceDiagram
    autonumber
    participant User as User
    participant Client as MCP Client
    participant IdP as OIDC Provider
    participant Server as MCP Server

    Client->>Client: Generate code_verifier + code_challenge
    Client->>User: Open browser → authorization_endpoint<br/>?client_id=…&code_challenge=…&response_type=code
    User->>IdP: Log in + consent
    IdP-->>Client: Redirect with authorization code
    Client->>IdP: POST token_endpoint<br/>{ code, code_verifier }
    IdP-->>Client: { access_token (JWT), refresh_token, … }

    loop Every MCP request
        Client->>Server: Authorization: Bearer <JWT>
        Server->>Server: Validate signature via JWKS<br/>Extract sub, email, name → current_user ContextVar
        Server-->>Client: 200 OK
    end
```

### JWT validation

The middleware discovers the `jwks_uri` from `{issuer_url}/.well-known/openid-configuration` (cached 10 minutes) and validates signatures against the JWKS (also cached 10 minutes). Supported algorithms: RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.

The validated claims (`sub`, `preferred_username`, `email`, `name`, `iss`, `exp`) are written into a `ContextVar[dict | None]` that you declare once at module level and pass to both the middleware and the providers:

```python
from contextvars import ContextVar
current_user: ContextVar[dict | None] = ContextVar("current_user", default=None)
```

The middleware **writes** it; the Leg 2 providers **read** the `sub` field from it to key per-user token storage. Python's `ContextVar` is scoped per async task automatically, so concurrent requests never interfere. Any tool can also call `current_user.get()` directly — no FastAPI dependency injection needed.

**The server never sees or stores the primary access token** — it only validates signatures.

---

## Leg 2 — Tool-level credential elicitation

Individual tools that need a secondary credential apply a decorator. On first invocation for a given user the decorator checks the credential store; if nothing is cached it triggers the MCP elicitation flow to collect the credential interactively.

### OAuthProvider — Authorization Code + PKCE flow

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP Client
    participant Server as MCP Server
    participant Store as Token Store
    participant Browser as User's Browser
    participant Provider as OAuth Provider

    Client->>Server: Tool call (e.g. list_repos)
    Server->>Store: get_token(sub)
    Store-->>Server: None (not cached)

    Server->>Server: Generate state token<br/>Store pending entry with asyncio.Event
    Server-->>Client: elicit_url(authorization_url?state=…)
    Client->>Browser: Open URL

    Browser->>Provider: GET /authorize?client_id=…&code_challenge=…
    Provider-->>Browser: Login page
    Browser->>Provider: User logs in
    Provider-->>Browser: Redirect to /callback?code=…&state=…

    Browser->>Server: GET /callback?code=…&state=…
    Server->>Provider: POST /token { code, code_verifier }
    Provider-->>Server: { access_token, … }
    Server->>Store: save_token(sub, access_token)
    Server->>Server: Set asyncio.Event (unblock tool)
    Server-->>Browser: Success page

    Note over Server: Tool resumes
    Server->>Store: get_token(sub)
    Store-->>Server: access_token
    Server-->>Client: Tool result
```

On subsequent invocations the store lookup returns immediately — no browser interaction.

### CredentialsProvider — PAT / API key form

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP Client
    participant Server as MCP Server
    participant Store as Credential Store
    participant Browser as User's Browser

    Client->>Server: Tool call (e.g. list_pages)
    Server->>Store: get_credentials(sub)
    Store-->>Server: None (not cached)

    Server->>Server: Generate entry token (secrets.token_urlsafe)<br/>Store pending entry with asyncio.Event + expiry
    Server-->>Client: elicit_url(/credentials/{name}/entry?token=…)
    Client->>Browser: Open URL

    Browser->>Server: GET /credentials/{name}/entry?token=…
    Server-->>Browser: HTML form (+ optional Markdown guide)
    Browser->>Server: POST /credentials/{name}/submit { token, field1, field2, … }
    Server->>Server: Validate entry token (single-use, expiry check)
    Server->>Store: save_credentials(sub, { field1, field2 })
    Server->>Server: Set asyncio.Event (unblock tool)
    Server-->>Browser: Success page

    Note over Server: Tool resumes
    Server->>Store: get_credentials(sub)
    Store-->>Server: { field1, field2, … }
    Server-->>Client: Tool result
```

The entry token is consumed on submit (single-use) and checked against an expiry timestamp, preventing replay attacks.

---

## Request lifecycle

```mermaid
flowchart TD
    req[Incoming HTTP Request]
    cors[CORSMiddleware]
    open{Path in open_paths?}
    bearer{Bearer header present?}
    valid{JWT valid?}
    user[Set current_user ContextVar]
    router[Route to handler]

    req --> cors --> open
    open -- yes --> router
    open -- no --> bearer
    bearer -- no --> E1[401 Unauthorized\nWWW-Authenticate: Bearer ...]
    bearer -- yes --> valid
    valid -- expired --> E2[401 invalid_token]
    valid -- bad signature/claims --> E1
    valid -- ok --> user --> router

    router --> R1[GET /.well-known/*\nPOST /register]
    router --> R2[GET /{name}/callback\nOAuthProvider callback]
    router --> R3[GET /credentials/{name}/entry\nPOST /credentials/{name}/submit]
    router --> R4[GET /health]
    router --> R5[Mount / → FastMCP\nPOST /mcp → MCP protocol]
```

---

## Token & credential store

All token and credential state flows through a common interface (`TokenStore` / `PendingStore`). Three backends are available, selected via the `TOKEN_STORAGE_MODE` environment variable.

### Backend overview

```mermaid
classDiagram
    class TokenStore {
        <<interface>>
        +get(sub) TokenData
        +save(sub, data)
        +delete(sub)
    }
    class PendingStore {
        <<interface>>
        +create(key) entry
        +get(key) entry
        +delete(key)
    }

    class MemoryTokenStore
    class MemoryPendingStore
    class FileTokenStore
    class FilePendingStore
    class RedisTokenStore
    class RedisPendingStore

    TokenStore <|.. MemoryTokenStore
    TokenStore <|.. FileTokenStore
    TokenStore <|.. RedisTokenStore
    PendingStore <|.. MemoryPendingStore
    PendingStore <|.. FilePendingStore
    PendingStore <|.. RedisPendingStore
```

### Variant comparison

| | Memory | File | Redis |
|---|---|---|---|
| **Persistence** | ✗ Lost on restart | ✓ Survives restart | ✓ Survives restart |
| **Multi-worker** | ✗ Per-process dict | ✓ Shared filesystem | ✓ Native |
| **Distributed** | ✗ | ✓ NFS / EFS | ✓ |
| **Encryption** | — | Fernet (AES-128-CBC + HMAC) | Fernet (AES-128-CBC + HMAC) |
| **Best for** | Development / tests | Single-host deployments | Cloud / multi-replica |

### Selecting a backend

Set `TOKEN_STORAGE_MODE` in the environment:

```
TOKEN_STORAGE_MODE=memory   # default — no other config needed
TOKEN_STORAGE_MODE=file     # requires FILE_STORAGE_PATH
TOKEN_STORAGE_MODE=redis    # requires REDIS_URL; pip install mcp-authkit[redis]
```

### Namespace isolation

Every provider passes its `name` as a namespace when creating stores, preventing two providers that happen to share the same user `sub` from colliding.

```mermaid
flowchart LR
    subgraph Providers
        P1["OAuthProvider\nname='service-a'"]
        P2["OAuthProvider\nname='service-b'"]
        P3["CredentialsProvider\nname='service-c'"]
    end

    subgraph Store["Storage backend (file / Redis / memory)"]
        N1["namespace: service-a\ntokens/{sha256(sub)}.enc"]
        N2["namespace: service-b\ntokens/{sha256(sub)}.enc"]
        N3["namespace: service-c\ncredentials/{sha256(sub)}.enc"]
    end

    P1 --> N1
    P2 --> N2
    P3 --> N3
```

### Encryption at rest (file + Redis backends)

Every value is encrypted with [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256) before writing. The key is resolved at startup:

1. `STORAGE_ENCRYPTION_KEY` env var — base64-encoded Fernet key
2. `STORAGE_ENCRYPTION_KEY_PATH` env var — path to a file containing the key (Docker secrets, Vault agent, AWS Secrets Manager sidecar, …)

If neither is set the server raises `RuntimeError` at startup rather than silently using an ephemeral key.

### Subject hashing

Neither the file store nor the Redis store writes the raw OIDC `sub` to disk or to Redis. Both compute `sha256(sub)` and use the hex digest as the storage key, so a compromised storage layer reveals only opaque hashes and encrypted blobs — no user identifiers.

---

## Component map

```mermaid
flowchart TB
    subgraph mcpauthkit
        MW["auth_middleware.py\nJwtAuthMiddleware"]
        AR["auth_routes.py\noauth_meta_router()"]
        JV["jwt_validator.py\n_get_oidc_config · _get_jwks"]
        OP["providers/oauth_provider.py\nOAuthProvider"]
        CP["providers/credentials_provider.py\nCredentialsProvider"]
        ST["store/\nbase · memory · file · redis · encryption · factory"]
    end

    MW --> JV
    OP --> ST
    CP --> ST
    AR -.->|"proxies OIDC discovery"| JV
```

- **`auth_middleware.py`** — `BaseHTTPMiddleware` subclass; validates JWT on every non-open path; writes claims into `current_user` ContextVar
- **`auth_routes.py`** — `APIRouter` with `/.well-known/*` and `/register`; must be included *before* the FastMCP mount
- **`jwt_validator.py`** — stateless OIDC/JWKS helpers with 10-minute in-process cache
- **`providers/oauth_provider.py`** — full Authorization Code + PKCE flow; `asyncio.Event`-based callback synchronisation
- **`providers/credentials_provider.py`** — HTML form flow; single-use entry token with expiry
- **`store/`** — pluggable storage with Fernet encryption and `sha256` subject hashing
