# Migration Guide: v0.3.1 to v4.0.0

## What Changed

CAPTCHA sessions moved from in-memory cache to stateless JWTs. If you use CAPTCHA, you need to update your config.

### In-memory to JWT

v0.3.1 stored sessions in memory with random session IDs. v4.0.0 uses JWTs instead. There's no more session cache.

The new flow:
1. User hits CAPTCHA → gets a challenge token (JWT)
2. User completes CAPTCHA → gets a verification token (JWT)
3. Verification token stored in a cookie

### New Required Fields

If CAPTCHA is enabled, add these to your config:

**signingKey** - Signs the JWTs. Must be at least 32 bytes.

```bash
openssl rand -base64 32
```

**cookieDomain** - Where the cookie works. Use a parent domain like `.example.com` so the cookie works across `auth.example.com` and `app.example.com`.

**secureCookie** - Defaults to true. Set to false for local dev without HTTPS.

### Removed Field

`cacheCleanupInterval` is gone. No cache means no cleanup needed.

## How to Migrate

Generate a signing key:

```bash
openssl rand -base64 32
```

Update your config. Here's what changed:

```yaml
captcha:
  enabled: true
  provider: "recaptcha"
  siteKey: "your-site-key"
  secretKey: "your-secret-key"
  signingKey: "your-generated-signing-key"  # NEW
  callbackURL: "https://auth.example.com"
  cookieDomain: ".example.com"  # NEW - must start with dot
  secureCookie: true  # NEW - false for local dev
  sessionDuration: "15m"
  challengeDuration: "5m"
```

For Kubernetes, update your secret:

```bash
kubectl create secret generic captcha-secrets \
  --from-literal=secret-key='your-secret-key' \
  --from-literal=signing-key="$(openssl rand -base64 32)" \
  -n envoy-gateway-system
```

Update your Helm values:

```yaml
config:
  captcha:
    enabled: true
    provider: "recaptcha"
    siteKey: "6LeIxA..."
    secretKeySecretRef:
      name: captcha-secrets
      key: secret-key
    signingKeySecretRef:  # NEW
      name: captcha-secrets
      key: signing-key
    callbackURL: "https://auth.example.com"
    cookieDomain: ".example.com"  # NEW
    secureCookie: true  # NEW
```

Add environment variables:

```bash
export ENVOY_BOUNCER_CAPTCHA_SIGNINGKEY=your-signing-key
export ENVOY_BOUNCER_CAPTCHA_COOKIEDOMAIN=.example.com
export ENVOY_BOUNCER_CAPTCHA_SECURECOOKIE=true
```

Deploy and check logs:

```bash
kubectl logs -n envoy-gateway-system deployment/envoy-proxy-bouncer
```

If you see errors about missing `signingKey` or `cookieDomain`, your config is incomplete.

## Cookie Domain Setup

The `cookieDomain` needs a leading dot to work across subdomains.

If your bouncer is at `auth.example.com` and your app is at `app.example.com`, use `.example.com`. The cookie set by the bouncer will be readable by your app.
