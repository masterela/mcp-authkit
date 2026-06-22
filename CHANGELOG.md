# Changelog

All notable changes to **mcp-authkit** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [0.2.2] — 2026-06-22

### Added
- **`OAuthProvider.from_standard_oauth2`** — new `extra_authorize_params` keyword
  argument (`dict[str, str] | None`, default `None`).  Extra parameters are merged
  into every authorization URL before the standard ones, so standard params
  (`client_id`, `redirect_uri`, `scope`, `state`, `response_type`) always take
  precedence and cannot be overridden.  Useful for provider-specific routing hints
  that are outside the OAuth 2.0 spec — for example Okta's `idp` parameter, which
  bypasses the Okta login page and routes users directly to a configured external
  Identity Provider::

      okta = OAuthProvider.from_standard_oauth2(
          ...
          extra_authorize_params={"idp": "0oaz2r21a8RBmZyOL0h7"},
      )

## [0.2.1] — 2026-05-20

### Fixed
- **`auth_routes`** — `/.well-known/oauth-protected-resource` now correctly lists
  the MCP server's own base URL in `authorization_servers` (reverts the regression
  introduced in 0.2.0).  The field must point to the resource server's own
  authorization server entry, not the OIDC issuer; using the issuer caused clients
  such as MCP Inspector to redirect users to the OIDC discovery endpoint rather
  than the MCP server's `/.well-known/oauth-authorization-server`.

## [0.2.0] — 2026-05-20

### Fixed
- **`auth_routes`** — `/.well-known/oauth-protected-resource` listed the OIDC
  issuer URL in `authorization_servers` instead of the MCP server's own base URL.
  ⚠️ This introduced a regression (fixed in 0.2.1): clients were directed to the
  OIDC provider's discovery document instead of the MCP server's
  `/.well-known/oauth-authorization-server`, breaking inspector-based flows.

## [0.1.3] — 2026-05-20

### Added
- **Storage / encryption** — startup warning now includes the one-liner to generate a stable Fernet key and the exact env var to export.
- **Storage / encryption** — on decrypt failure (e.g. after key rotation) the stale entry is deleted automatically and an actionable warning is logged; the user is re-prompted once on their next tool call — no exception, no 500 error.
- **docs/api/store.md** — new Key management section: key generation command, env var setup, key rotation behaviour.

### Changed
- **README** — simplified to library-README style: concise description, 4-step quick start (with `ContextVar` declaration as explicit Step 1), storage table, links to full docs.
- **docs/index.md** — new Setup section (Steps 1–3) so the docs home page serves as a proper getting-started guide.
- **docs/architecture.md** — inline callout explains `ContextVar` declaration and write/read split next to the JWT validation section.
- **docs/quickstart.md** (new) — Quick start page in MkDocs, single-sourced from README via `pymdownx.snippets`; editing the README updates the docs automatically on next deploy.
- **mkdocs.yml** — added `pymdownx.snippets` extension, Mermaid diagram support (`pymdownx.superfences`), and Quick start nav entry.

## [0.1.2] — 2026-05-20

### Changed
- Release workflow (`release.yml`): `workflow_dispatch` now auto-resolves the version tag from `pyproject.toml` when no tag input is provided.
- CI (`ci.yml`): `auto-tag` job reads version via `tomllib` and pushes tag on every merge to `main`.

## [0.1.1] — 2026-05-20

### Added
- `pyproject.toml`: Python version classifiers (`Programming Language :: Python :: 3.11 / 3.12`) so PyPI badge shows correctly.

### Fixed
- Release workflow: `tag_name` now correctly uses the resolved tag value for GitHub Release creation.
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

[Unreleased]: https://github.com/masterela/mcp-authkit/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/masterela/mcp-authkit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/masterela/mcp-authkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/masterela/mcp-authkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/masterela/mcp-authkit/releases/tag/v0.1.0
