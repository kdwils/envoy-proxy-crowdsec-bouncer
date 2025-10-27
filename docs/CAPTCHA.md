# CAPTCHA Configuration Guide

This guide covers CAPTCHA challenge configuration for the Envoy Proxy CrowdSec Bouncer.

## Overview

CAPTCHA challenges provide an alternative to immediately blocking suspicious IPs. When enabled, users can complete a challenge to prove they're human before accessing protected resources.

## How It Works

When CAPTCHA is enabled, the bouncer serves on 2 ports:

1. gRPC Server (default port 8080): Handles Envoy ext_authz requests
2. HTTP Server (default port 8081): Serves CAPTCHA challenge and verification endpoints

### CAPTCHA Flow

1. CrowdSec or WAF returns "captcha" action for a suspicious request
2. Bouncer creates a session and redirects to `/captcha/challenge?session=<id>`
3. User completes the CAPTCHA widget and submits the form
4. Form posts to `/captcha/verify` with session ID and CAPTCHA response
5. Bouncer verifies CAPTCHA with provider
6. On success, IP is cached and user is redirected to original URL
7. Subsequent requests from the same IP are allowed (until session expires)

### Session Management

CAPTCHA Sessions are managed using JWTs.

The flow uses two types of tokens:
- Challenge tokens contain the IP and original URL. They expire after `challengeDuration` (default 5m).
- Verification tokens are issued after successful CAPTCHA completion. They're stored in a cookie and expire after `sessionDuration` (default 15m).

Both tokens are signed using the `signingKey`. Tokens are bound to IP addresses extracted from trusted headers. The verification token cookie uses the configured `cookieDomain` to work across subdomains.

## Supported Providers

| Provider | Configuration Value | Documentation |
|----------|-------------------|----------------|---------------|
| Google reCAPTCHA v2 | `recaptcha` | [reCAPTCHA Documentation](https://developers.google.com/recaptcha) |
| Cloudflare Turnstile | `turnstile` | [Turnstile Documentation](https://developers.cloudflare.com/turnstile/) |

## Configuration

### Basic Setup

```yaml
captcha:
  enabled: true
  provider: "recaptcha"  # or "turnstile"
  siteKey: "<your-site-key>"
  secretKey: "<your-secret-key>"
  signingKey: "<your-jwt-signing-key>"  # Required - key used to sign jwts
  callbackURL: "https://yourdomain.com"
  cookieDomain: ".yourdomain.com"  # Required - parent domain for cookie sharing
  secureCookie: true  # true for HTTPS, false for local dev
  sessionDuration: "15m"
  challengeDuration: "5m"
  timeout: "10s"
```

### Configuration Options

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable CAPTCHA challenges |
| `provider` | string | `""` | Yes | CAPTCHA provider: `recaptcha` or `turnstile` |
| `siteKey` | string | `""` | Yes | Public site key from CAPTCHA provider |
| `secretKey` | string | `""` | Yes | Secret key from CAPTCHA provider |
| `signingKey` | string | `""` | Yes | JWT signing key (minimum 32 bytes). Generate with `openssl rand -base64 32` |
| `callbackURL` | string | `""` | Yes | Base URL for CAPTCHA callbacks (public-facing hostname) |
| `cookieDomain` | string | `""` | Yes | Parent domain for cookies (e.g., `.example.com`) to share across subdomains |
| `secureCookie` | bool | `true` | No | Use Secure flag and SameSite=None (true for HTTPS, false for local dev) |
| `timeout` | duration | `"10s"` | No | Timeout for CAPTCHA provider verification requests |
| `sessionDuration` | duration | `"15m"` | No | How long CAPTCHA verification remains valid |
| `challengeDuration` | duration | `"5m"` | No | How long a challenge token remains valid |

### Environment Variables

```bash
export ENVOY_BOUNCER_CAPTCHA_ENABLED=true
export ENVOY_BOUNCER_CAPTCHA_PROVIDER=recaptcha
export ENVOY_BOUNCER_CAPTCHA_SITEKEY=your-site-key
export ENVOY_BOUNCER_CAPTCHA_SECRETKEY=your-secret-key
export ENVOY_BOUNCER_CAPTCHA_SIGNINGKEY=your-jwt-signing-key
export ENVOY_BOUNCER_CAPTCHA_CALLBACKURL=https://yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_COOKIEDOMAIN=.yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_SECURECOOKIE=true
export ENVOY_BOUNCER_CAPTCHA_SESSIONDURATION=15m
export ENVOY_BOUNCER_CAPTCHA_CHALLENGEDURATION=5m
export ENVOY_BOUNCER_CAPTCHA_TIMEOUT=10s
```

### Callback URL

The `callbackURL` is the **public-facing base URL** where the bouncer is accessible. It's used to construct CAPTCHA endpoint URLs.

**Examples:**

- If bouncer is hosted at `https://auth.example.com`, set `callbackURL: "https://auth.example.com"`
- If bouncer is behind a proxy at `https://example.com/auth`, set `callbackURL: "https://example.com/auth"`

The bouncer will append `/captcha/challenge` and `/captcha/verify` to this URL.

## Provider Setup

### Google reCAPTCHA v2

See 
- https://developers.google.com/recaptcha/intro

Configuration:

```yaml
captcha:
  enabled: true
  provider: "recaptcha"
  siteKey: "0x4AAAAAAABAAAAAAAAAA"        # Example
  secretKey: "0x4AAAAAAABBBBBBBBB"        # Example
  callbackURL: "https://bouncer-host.com" # where the bouncer is publicly accessible
```

### Cloudflare Turnstile

See 
- https://developers.cloudflare.com/turnstile/
- https://www.cloudflare.com/application-services/products/turnstile/

Configuration:

```yaml
captcha:
  enabled: true
  provider: "turnstile"
  siteKey: "0x4AAAAAAABAAAAAAAAAA"        # Example
  secretKey: "0x4AAAAAAABBBBBBBBB"        # Example
  callbackURL: "https://bouncer-host.com" # where the bouncer is publicly accessible
```

### Exposing CAPTCHA Endpoints

Create an HTTPRoute for CAPTCHA endpoints:

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

**Important**: Do NOT apply a SecurityPolicy to the CAPTCHA HTTPRoute, as this would create an infinite redirect loop.

## Custom Templates

You can customize the CAPTCHA challenge page. See [CUSTOM_TEMPLATES.md](CUSTOM_TEMPLATES.md) for details.

### Required Template Elements

Your custom CAPTCHA template **must** include:

1. Form posting to `{{.CallbackURL}}/verify`
2. Hidden session field: `<input type="hidden" name="session" value="{{.SessionID}}" />`
3. CAPTCHA widget rendering with `{{.SiteKey}}`
4. Provider-specific JavaScript library

Example:

```html
<form method="POST" action="{{.CallbackURL}}/verify">
    <div id="captcha-container"></div>
    <input type="hidden" name="session" value="{{.SessionID}}" />
    <button type="submit">Verify</button>
</form>

{{if eq .Provider "recaptcha"}}
<script src="https://www.google.com/recaptcha/api.js" defer></script>
<script>
    grecaptcha.render('captcha-container', {
        'sitekey': '{{.SiteKey}}'
    });
</script>
{{else if eq .Provider "turnstile"}}
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
<script>
    turnstile.render('#captcha-container', {
        sitekey: '{{.SiteKey}}'
    });
</script>
{{end}}
```

## Security Considerations

### Session Security

The `signingKey` must be at least 32 bytes. Generate one with `openssl rand -base64 32`.

Verification tokens are stored in HTTP-only cookies. When `secureCookie` is true, cookies use the Secure flag and SameSite=None (required for cross-site access over HTTPS). When false, SameSite=Lax is used (for local development).

### IP Binding

Sessions are tied to the client's IP address to prevent session hijacking. Configure `trustedProxies` correctly to ensure accurate IP extraction:

```yaml
trustedProxies:
  - 10.0.0.0/8
  - 172.16.0.0/12
```

## Testing

### Local Testing

1. Configure the bouncer with CAPTCHA enabled
2. Add a test decision to CrowdSec:
   ```bash
   cscli decisions add -i <your-ip> -t captcha -d 1h
   ```
3. Access a protected resource
4. Verify redirect to CAPTCHA challenge page
5. Complete the CAPTCHA
6. Verify redirect back to original resource

## See Also

- [Configuration Guide](CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Custom Templates](CUSTOM_TEMPLATES.md)
- [reCAPTCHA Documentation](https://developers.google.com/recaptcha)
- [Cloudflare Turnstile Documentation](https://developers.cloudflare.com/turnstile/)
