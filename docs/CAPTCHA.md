# CAPTCHA Integration

How CAPTCHA challenges work in the bouncer. For configuration options see the [Configuration Reference](CONFIGURATION.md#captcha).

## Table of Contents

- [Overview](#overview)
- [Challenge Flow](#challenge-flow)
- [Session Management](#session-management)
- [Providers](#providers)
- [Exposing CAPTCHA Endpoints](#exposing-captcha-endpoints)
- [Testing](#testing)

## Overview

When a CrowdSec decision or WAF response carries a `captcha` action, the bouncer redirects the user to a challenge page instead of returning a ban. Successfully completing the challenge grants access for the duration of the session.

When CAPTCHA is enabled, the bouncer runs two servers:
- **gRPC (default 8080)** — handles Envoy ext_authz requests
- **HTTP (default 8081)** — serves the challenge page and verification endpoint

## Challenge Flow

1. CrowdSec or WAF returns a `captcha` action for the request
2. Bouncer creates a signed challenge token containing the client IP and original URL, then redirects to `/captcha/challenge?challengeToken=<token>`
3. User completes the CAPTCHA widget and submits the form
4. Form POSTs to `/captcha/verify` with the session token and CAPTCHA response
5. Bouncer verifies the CAPTCHA response with the provider API
6. On success, a signed verification token is issued as an HTTP-only cookie and the user is redirected to their original URL
7. Subsequent requests carry the cookie — the bouncer validates it and allows the request without re-challenging

## Session Management

Two token types are used, both signed with `signingKey`:

- **Challenge token** — contains the client IP and original URL. Expires after `challengeDuration` (default 5m). Passed as a query parameter.
- **Verification token** — issued after successful CAPTCHA completion. Expires after `sessionDuration` (default 15m). Stored in an HTTP-only cookie scoped to `cookieDomain`.

Tokens are bound to the client IP extracted from trusted proxy headers. Setting `cookieDomain` to a parent domain (e.g. `.example.com`) allows the verification cookie to be recognized across subdomains.

When `secureCookie` is true, cookies use `Secure` and `SameSite=None`. When false, `SameSite=Lax` is used.

## Providers

| Provider | `provider` value |
|----------|-----------------|
| Google reCAPTCHA v2 | `recaptcha` |
| Cloudflare Turnstile | `turnstile` |

- [reCAPTCHA setup](https://developers.google.com/recaptcha/intro)
- [Turnstile setup](https://developers.cloudflare.com/turnstile/)

## Exposing CAPTCHA Endpoints

The CAPTCHA HTTP server must be publicly reachable for the challenge flow to work. Create an HTTPRoute pointing to the bouncer's HTTP port:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: bouncer-captcha
  namespace: envoy-gateway-system
spec:
  hostnames:
    - auth.example.com
  parentRefs:
    - name: my-gateway
      namespace: envoy-gateway-system
  rules:
    - matches:
      - path:
          type: PathPrefix
          value: /captcha/
      backendRefs:
        - name: envoy-proxy-bouncer
          port: 8081
```

Do not apply a SecurityPolicy to this HTTPRoute.

`callbackURL` must be set to the public-facing base URL where the bouncer is reachable. The bouncer appends `/captcha/challenge` and `/captcha/verify` to construct endpoint URLs.

## See Also

- [Configuration Reference](CONFIGURATION.md)
- [Custom Templates](CUSTOM_TEMPLATES.md)
- [CrowdSec Integration](CROWDSEC.md)
- [Signing Key Generation](SIGNING_KEYS.md)
