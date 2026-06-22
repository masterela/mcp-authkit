# OAuthProvider

Tool-level OAuth 2.0 Authorization Code flow via MCP elicitation.

::: mcpauthkit.providers.oauth_provider.OAuthProvider

---

## Provider-specific routing hints

Some providers require extra query parameters on the authorization URL that are
not part of the standard OAuth 2.0 spec.  Pass them via `extra_authorize_params`
— they are merged into every authorization URL built by the factory.

### Okta — routing to an external Identity Provider

Okta supports an `idp` parameter that bypasses its own login page and routes
users directly to a configured external Identity Provider (e.g. Microsoft Entra,
Google Workspace, a SAML IdP).  The value is the **IdP ID** visible in the Okta
Admin Console under **Security → Identity Providers**.

```python
okta = OAuthProvider.from_standard_oauth2(
    name="okta",
    authorization_url="https://your-org.okta.com/oauth2/default/v1/authorize",
    token_url="https://your-org.okta.com/oauth2/default/v1/token",
    client_id=settings.okta_client_id,
    client_secret=settings.okta_client_secret,
    scope="openid profile email",
    redirect_uri=f"{settings.server_base_url}/okta/callback",
    user_context=current_user,
    extra_authorize_params={"idp": "0oaz2r21a8RBmZyOL0h7"},
)
```

The resulting authorization URL will include `&idp=0oaz2r21a8RBmZyOL0h7` in
addition to the standard parameters.  Standard parameters (`client_id`,
`redirect_uri`, `scope`, `state`, `response_type`) always take precedence and
cannot be overridden via `extra_authorize_params`.

---

## Helper types

::: mcpauthkit.providers.oauth_provider._parse_token_data
