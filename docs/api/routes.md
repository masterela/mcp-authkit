# Routes & well-known endpoints

RFC 8414 / RFC 9728 metadata endpoints and Dynamic Client Registration façade.

::: mcpauthkit.auth_routes

---

## Provider-specific routing hints

Some OIDC providers accept extra query parameters on the authorization endpoint
that route users to a specific Identity Provider without showing the provider's
own login page.  Pass them via `extra_authorize_params` — they are appended to
the `authorization_endpoint` URL returned in
`/.well-known/oauth-authorization-server`, which MCP clients use verbatim.

### Okta — routing to an external Identity Provider

Okta's `idp` parameter bypasses the Okta login page and sends users directly to
a configured external IdP (Microsoft Entra, Google Workspace, a SAML IdP, …).
The value is the **IdP ID** shown in the Okta Admin Console under
**Security → Identity Providers**.

```python
app.include_router(oauth_meta_router(
    server_base_url=settings.server_base_url,
    issuer_url="https://your-org.okta.com/oauth2/default",
    client_id=settings.okta_client_id,
    extra_authorize_params={"idp": "0oaz2r21a8RBmZyOL0h7"},
))
```

The resulting `authorization_endpoint` in the well-known document will be:

```
https://your-org.okta.com/oauth2/default/v1/authorize?idp=0oaz2r21a8RBmZyOL0h7
```

MCP clients (VS Code Copilot, MCP Inspector, …) read this URL and include the
`idp` hint when redirecting the user, so they are sent straight to the external
IdP without ever seeing the Okta login screen.
