# CAPTCHA Configuration Guide

This guide covers CAPTCHA challenge configuration for the Envoy Proxy CrowdSec Bouncer.

## Overview

CAPTCHA challenges provide an alternative to immediately blocking suspicious IPs. When enabled, users can complete a challenge to prove they're human before accessing protected resources.

## How It Works

When CAPTCHA is enabled, the bouncer runs dual servers:

1. **gRPC Server** (default port 8080): Handles Envoy ext_authz requests
2. **HTTP Server** (default port 8081): Serves CAPTCHA challenge and verification endpoints

### CAPTCHA Flow

1. CrowdSec or WAF returns "captcha" action for a suspicious request
2. Bouncer creates a session and redirects to `/captcha/challenge?session=<id>`
3. User completes the CAPTCHA widget and submits the form
4. Form posts to `/captcha/verify` with session ID and CAPTCHA response
5. Bouncer verifies CAPTCHA with provider
6. On success, IP is cached and user is redirected to original URL
7. Subsequent requests from the same IP are allowed (until session expires)

### Session Management

- Sessions are stored in-memory with a configurable duration
- IPs that complete CAPTCHA are cached and allowed through
- Sessions are bound to IP addresses to prevent session hijacking
- CSRF tokens protect against cross-site request forgery
- Expired sessions are automatically cleaned up

## Supported Providers

| Provider | Configuration Value | Site Key Format | Documentation |
|----------|-------------------|----------------|---------------|
| Google reCAPTCHA v2 | `recaptcha` | `6LeIxA...` | [reCAPTCHA Documentation](https://developers.google.com/recaptcha) |
| Cloudflare Turnstile | `turnstile` | `0x4AAA...` | [Turnstile Documentation](https://developers.cloudflare.com/turnstile/) |

## Configuration

### Basic Setup

```yaml
captcha:
  enabled: true
  provider: "recaptcha"  # or "turnstile"
  siteKey: "<your-site-key>"
  secretKey: "<your-secret-key>"
  callbackURL: "https://yourdomain.com"
  sessionDuration: "15m"
  timeout: "10s"
```

### Configuration Options

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable CAPTCHA challenges |
| `provider` | string | `""` | Yes | CAPTCHA provider: `recaptcha` or `turnstile` |
| `siteKey` | string | `""` | Yes | Public site key from CAPTCHA provider |
| `secretKey` | string | `""` | Yes | Secret key from CAPTCHA provider |
| `callbackURL` | string | `""` | Yes | Base URL for CAPTCHA callbacks (public-facing hostname) |
| `timeout` | duration | `"10s"` | No | Timeout for CAPTCHA provider verification requests |
| `sessionDuration` | duration | `"15m"` | No | How long CAPTCHA verification remains valid |
| `cacheCleanupInterval` | duration | `"5m"` | No | How often to clean up expired sessions |

### Environment Variables

```bash
export ENVOY_BOUNCER_CAPTCHA_ENABLED=true
export ENVOY_BOUNCER_CAPTCHA_PROVIDER=recaptcha
export ENVOY_BOUNCER_CAPTCHA_SITEKEY=your-site-key
export ENVOY_BOUNCER_CAPTCHA_SECRETKEY=your-secret-key
export ENVOY_BOUNCER_CAPTCHA_CALLBACKURL=https://yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_SESSIONDURATION=15m
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

1. Visit [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
2. Click "Create" to register a new site
3. Choose **reCAPTCHA v2** → **"I'm not a robot" checkbox**
4. Add your domain(s)
5. Copy the **Site Key** and **Secret Key**

Configuration:

```yaml
captcha:
  enabled: true
  provider: "recaptcha"
  siteKey: "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"  # Example test key
  secretKey: "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"  # Example test key
  callbackURL: "https://yourdomain.com"
```

**Test Keys** (always pass):
- Site Key: `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`
- Secret Key: `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe`

### Cloudflare Turnstile

1. Visit [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Navigate to **Turnstile**
3. Click **Add Site**
4. Choose **Managed** challenge mode
5. Add your domain(s)
6. Copy the **Site Key** and **Secret Key**

Configuration:

```yaml
captcha:
  enabled: true
  provider: "turnstile"
  siteKey: "0x4AAAAAAABjdT4JkT4kXPZL"  # Example
  secretKey: "0x4AAAAAAABjdT4JkT4kXPZL"  # Example
  callbackURL: "https://yourdomain.com"
```

**Test Keys** (always pass):
- Site Key: `1x00000000000000000000AA`
- Secret Key: `1x0000000000000000000000000000000AA`

**Test Keys** (always fail):
- Site Key: `2x00000000000000000000AB`
- Secret Key: `2x0000000000000000000000000000000AA`

## Kubernetes/Helm Deployment

### Helm Configuration

```yaml
# values.yaml
config:
  captcha:
    enabled: true
    provider: "turnstile"
    siteKey: "0x4AAAAAAABjdT4JkT4kXPZL"
    secretKeySecretRef:
      name: captcha-secrets
      key: secret-key
    callbackURL: "https://auth.example.com"
    sessionDuration: "15m"
    timeout: "10s"
```

Create secret:

```bash
kubectl create secret generic captcha-secrets \
  --from-literal=secret-key='your-secret-key' \
  -n envoy-gateway-system
```

Install:

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  -f values.yaml
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

## CrowdSec Integration

### Scenarios with CAPTCHA Remediation

Configure CrowdSec scenarios to use `captcha` instead of `ban`:

```yaml
# /etc/crowdsec/profiles.yaml
name: captcha_profile
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
  - type: captcha
    duration: 4h
on_success: break
```

### AppSec CAPTCHA Actions

Configure AppSec to return `captcha` for suspicious patterns:

```yaml
# /etc/crowdsec/appsec-configs/your-config.yaml
name: my-appsec-config
default_remediation: captcha
rules:
  - name: suspicious-user-agent
    match: req.Headers["User-Agent"] matches "(?i)(bot|crawler|spider)"
    action: captcha
```

## Custom Templates

You can customize the CAPTCHA challenge page. See [CUSTOM_TEMPLATES.md](CUSTOM_TEMPLATES.md) for details.

### Required Template Elements

Your custom CAPTCHA template **must** include:

1. Form posting to `{{.CallbackURL}}/verify`
2. Hidden session field: `<input type="hidden" name="session" value="{{.SessionID}}" />`
3. Hidden CSRF token: `<input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />`
4. CAPTCHA widget rendering with `{{.SiteKey}}`
5. Provider-specific JavaScript library

Example:

```html
<form method="POST" action="{{.CallbackURL}}/verify">
    <div id="captcha-container"></div>
    <input type="hidden" name="session" value="{{.SessionID}}" />
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />
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

- Sessions are bound to IP addresses (extracted from trusted headers)
- CSRF tokens prevent cross-site form submission
- Sessions expire after configurable duration
- Session IDs are cryptographically random

### IP Binding

Sessions are tied to the client's IP address to prevent session hijacking. Configure `trustedProxies` correctly to ensure accurate IP extraction:

```yaml
trustedProxies:
  - 10.0.0.0/8
  - 172.16.0.0/12
```

### Rate Limiting

Consider implementing rate limiting for CAPTCHA endpoints to prevent abuse:

```yaml
# RateLimitPolicy for CAPTCHA endpoints
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: RateLimitPolicy
metadata:
  name: captcha-rate-limit
  namespace: envoy-gateway-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: bouncer-captcha
  rateLimits:
    - clientSelectors:
      - sourceCIDR:
          value: 0.0.0.0/0
      limit:
        requests: 10
        unit: Minute
```

### HTTPS

Always use HTTPS for CAPTCHA endpoints in production to protect:
- Session IDs
- CAPTCHA responses
- User privacy

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

### Using Test Keys

Use provider test keys for development:

**reCAPTCHA:**
```yaml
captcha:
  provider: "recaptcha"
  siteKey: "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
  secretKey: "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
```

**Turnstile:**
```yaml
captcha:
  provider: "turnstile"
  siteKey: "1x00000000000000000000AA"
  secretKey: "1x0000000000000000000000000000000AA"
```

## Troubleshooting

### CAPTCHA Page Not Loading

**Check HTTP server is running:**
```bash
kubectl logs -n envoy-gateway-system deployment/envoy-proxy-bouncer | grep "HTTP server"
```

**Verify HTTPRoute exists:**
```bash
kubectl get httproute -n envoy-gateway-system
```

**Check endpoint is accessible:**
```bash
curl https://yourdomain.com/captcha/challenge?session=test
```

### Infinite Redirect Loop

**Cause**: SecurityPolicy applied to CAPTCHA HTTPRoute

**Solution**: Remove SecurityPolicy from CAPTCHA HTTPRoute, or exclude CAPTCHA paths

### CAPTCHA Verification Fails

**Check provider credentials:**
- Verify site key and secret key are correct
- Ensure domain is registered with provider
- Check provider dashboard for errors

**Check logs:**
```bash
kubectl logs -n envoy-gateway-system deployment/envoy-proxy-bouncer | grep -i captcha
```

**Common issues:**
- Wrong provider selected (`recaptcha` vs `turnstile`)
- Domain mismatch between configuration and provider registration
- Secret key vs site key swapped
- Network connectivity to provider API

### Session Expired

**Symptoms**: User completes CAPTCHA but gets redirected back to challenge

**Solutions:**
- Increase `sessionDuration`
- Check server time synchronization
- Verify IP address consistency (check `trustedProxies` configuration)

### CSRF Token Validation Failed

**Cause**: Missing or invalid CSRF token in custom template

**Solution**: Ensure custom template includes:
```html
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />
```

## Metrics

When metrics are enabled, CAPTCHA-related metrics are reported:

- Total CAPTCHA challenges issued
- Successful CAPTCHA verifications
- Failed CAPTCHA verifications

View metrics:
```bash
cscli metrics
```

## Performance Tuning

### Session Cache Size

The session cache is in-memory and grows with the number of active sessions. Monitor memory usage and adjust pod resources if needed:

```yaml
resources:
  limits:
    memory: 512Mi  # Increase if handling many concurrent sessions
```

### Session Duration

Balance security vs user experience:

- **Shorter duration** (5-10m): More secure, but users may need to re-verify frequently
- **Longer duration** (30m-1h): Better UX, but verified IPs remain cached longer

```yaml
captcha:
  sessionDuration: "15m"  # Good balance for most use cases
```

### Cleanup Interval

Adjust based on session duration and memory constraints:

```yaml
captcha:
  cacheCleanupInterval: "5m"  # Clean up expired sessions every 5 minutes
```

## See Also

- [Configuration Guide](CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Custom Templates](CUSTOM_TEMPLATES.md)
- [reCAPTCHA Documentation](https://developers.google.com/recaptcha)
- [Cloudflare Turnstile Documentation](https://developers.cloudflare.com/turnstile/)
