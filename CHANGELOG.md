# Changelog

All notable changes to **mcp-authkit** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.1.0] — 2026-05-20

### Added
- `JwtAuthMiddleware` — OIDC JWT validation middleware for FastAPI / Starlette apps.  
  Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.  
  Automatic JWKS discovery and 10-minute caching.
- `oauth_meta_router` — RFC 8414 / RFC 9728 well-known endpoints and Dynamic Client Registration façade.
- `OAuthProvider` — tool-level OAuth 2.0 Authorization Code flow via MCP elicitation.  
  `from_standard_oauth2()` factory works with any standards-compliant provider (GitHub, Google, Okta, …).
- `CredentialsProvider` — tool-level PAT / API-key collection via a self-hosted HTML form.  
  Supports optional Markdown how-to guides rendered client-side.
- Three pluggable storage backends: `memory`, `file` (Fernet-encrypted), `redis` (async, Fernet-encrypted).
- Storage factory (`create_stores`) driven by `TOKEN_STORAGE_MODE` env var.
- Jinja2 HTML templates for all browser-facing pages (no external CDN dependencies).
- Full test suite — 191 tests, 99 % line coverage.
- GitHub Actions CI — ruff, mypy, pytest on Python 3.11 and 3.12.

[Unreleased]: https://github.com/masterela/mcp-authkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/masterela/mcp-authkit/releases/tag/v0.1.0
