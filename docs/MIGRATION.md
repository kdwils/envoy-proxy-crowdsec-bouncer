# Migration Guide: v0.3.1 to v4.0.0

## What Changed

CAPTCHA sessions moved from in-memory cache to stateless JWTs. This change was made to support multiple replicas of the bouncer in addition to not losing state if a pod restarts. Because we are using cookies, this requires additional configuration of the bouncer. 

If you use CAPTCHA, you must to update your config. 

If you are using the bouncer to protect multiple domains, you must use a bouncer per domain to set the cookie.

### In-memory to JWT

v0.3.1 stored sessions in memory with random session IDs. v4.0.0 uses JWTs instead.

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

**cookieDomain** - The parent domain for the cookie 

- For example, `.example.com` cookies would work for `auth.example.com` and `app.example.com`.

**secureCookie** - Defaults to true

### Removed Field

`cacheCleanupInterval` is no long used

## How to Migrate

Generate a signing key:

```bash
openssl rand -base64 32
```

Update config with new fields. Here's what changed:

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

Update Helm values:

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

## Cookie Domain Setup

The `cookieDomain` needs a leading dot to work across subdomains.

If your bouncer is at `auth.example.com` and your app is at `app.example.com`, use `.example.com`. The cookie set by the bouncer will be readable by your app.
