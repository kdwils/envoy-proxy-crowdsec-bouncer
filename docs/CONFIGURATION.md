# Configuration Reference

Configuration methods with the following precedence (last wins):

1. Default values
2. Configuration file (YAML or JSON)
3. Environment variables

```bash
envoy-proxy-bouncer serve --config config.yaml
```

See [example.yaml](./examples/config/example.yaml) for a complete configuration example.

## Server

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `grpcPort` | int | `8080` | Port for gRPC ext_authz server (Envoy integration) |
| `httpPort` | int | `8081` | Port for HTTP server (CAPTCHA endpoints) |
| `logLevel` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error` |

```yaml
server:
  grpcPort: 8080
  httpPort: 8081
  logLevel: "info"
```

```bash
export ENVOY_BOUNCER_SERVER_GRPCPORT=8080
export ENVOY_BOUNCER_SERVER_HTTPPORT=8081
export ENVOY_BOUNCER_SERVER_LOGLEVEL=info
```

## Bouncer

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `true` | No | Enable CrowdSec bouncer functionality |
| `apiKey` | string | `""` | Yes (unless using TLS) | CrowdSec LAPI bouncer API key |
| `lapiURL` | string | `""` | Yes (when enabled) | CrowdSec LAPI URL |
| `metrics` | bool | `false` | No | Enable metrics reporting to CrowdSec |
| `tickerInterval` | duration | `"10s"` | No | Interval to fetch decisions from LAPI |
| `metricsInterval` | duration | `"10m"` | No | Interval to report metrics to LAPI |
| `banStatusCode` | int | `403` | No | HTTP status code for ban responses |
| `tls.enabled` | bool | `false` | No | Enable mTLS authentication with LAPI (mutually exclusive with `apiKey`) |
| `tls.certPath` | string | `""` | Yes (when TLS enabled) | Path to client certificate file |
| `tls.keyPath` | string | `""` | Yes (when TLS enabled) | Path to client private key file |
| `tls.caPath` | string | `""` | No | Path to CA certificate file |
| `tls.insecureSkipVerify` | bool | `false` | No | Skip TLS certificate verification |

```yaml
bouncer:
  enabled: true
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"
  metrics: false
  tickerInterval: "10s"
  metricsInterval: "10m"
  banStatusCode: 403
  tls:
    enabled: false
    certPath: "/path/to/client.crt"
    keyPath: "/path/to/client.key"
    caPath: "/path/to/ca.crt"
    insecureSkipVerify: false
```

```bash
export ENVOY_BOUNCER_BOUNCER_ENABLED=true
export ENVOY_BOUNCER_BOUNCER_APIKEY=your-lapi-bouncer-api-key
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
export ENVOY_BOUNCER_BOUNCER_TICKERINTERVAL=10s
export ENVOY_BOUNCER_BOUNCER_METRICSINTERVAL=10m
export ENVOY_BOUNCER_BOUNCER_METRICS=false
export ENVOY_BOUNCER_BOUNCER_BANSTATUSCODE=403
export ENVOY_BOUNCER_BOUNCER_TLS_ENABLED=false
export ENVOY_BOUNCER_BOUNCER_TLS_CERTPATH=/path/to/client.crt
export ENVOY_BOUNCER_BOUNCER_TLS_KEYPATH=/path/to/client.key
export ENVOY_BOUNCER_BOUNCER_TLS_CAPATH=/path/to/ca.crt
export ENVOY_BOUNCER_BOUNCER_TLS_INSECURESKIPVERIFY=false
```

## WAF

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable WAF request inspection |
| `apiKey` | string | `""` | Yes (when enabled) | CrowdSec AppSec API key |
| `appSecURL` | string | `""` | Yes (when enabled) | CrowdSec AppSec service URL |

```yaml
waf:
  enabled: true
  apiKey: "<lapi-key>"
  appSecURL: "http://appsec:7422"
```

```bash
export ENVOY_BOUNCER_WAF_ENABLED=true
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:7422
export ENVOY_BOUNCER_WAF_APIKEY=your-appsec-api-key
```

## Network

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `trustedProxies` | []string | `[]` | List of trusted proxy IPs/CIDRs |
| `trustedIPHeader` | string | `""` | Header name to read the real client IP from directly, bypassing `X-Forwarded-For`/`trustedProxies` entirely. See below. |
| `exemptIPs` | []string | `[]` | IPs or CIDR ranges to bypass all CrowdSec evaluation (decision cache, WAF, captcha). See below. |

```yaml
trustedProxies:
  - 192.168.0.1
  - 10.0.0.0/8
```

```bash
export ENVOY_BOUNCER_TRUSTEDPROXIES=192.168.0.1,10.0.0.0/8
```

### `trustedIPHeader`

If your edge proxy already resolves the real client IP itself and stamps it into a single, dedicated header - for example Envoy with `numTrustedProxies`/`use_remote_address` configured, which sets `X-Envoy-External-Address` - point `trustedIPHeader` at that header instead of listing every possible upstream proxy's IP ranges in `trustedProxies`. This avoids re-deriving an answer your edge proxy has already computed, and avoids having to track and update a separate CIDR allowlist for every reverse proxy (e.g. Cloudflare) that might sit in front of it.

When set, this header is checked first: if present with a valid IP, that value is used directly, with no `X-Forwarded-For` parsing or `trustedProxies` matching involved. If the header is unset, absent from the request, or does not contain a valid IP, the bouncer falls back to the existing `X-Forwarded-For` / `X-Real-IP` / `trustedProxies` logic - fully backward compatible with existing deployments.

```yaml
trustedIPHeader: "X-Envoy-External-Address"
```

```bash
export ENVOY_BOUNCER_TRUSTEDIPHEADER=X-Envoy-External-Address
```

### `exemptIPs`

A list of IP addresses or CIDR ranges that bypass all CrowdSec evaluation entirely — decision cache lookups, WAF inspection, and captcha challenges are skipped for matching requests.

```yaml
exemptIPs:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
```

```bash
export ENVOY_BOUNCER_EXEMPTIPS=10.0.0.0/8,172.16.0.0/12
```

## CAPTCHA

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable CAPTCHA challenges |
| `provider` | string | `""` | Yes | CAPTCHA provider: `recaptcha` or `turnstile` |
| `siteKey` | string | `""` | Yes | Public site key from CAPTCHA provider |
| `secretKey` | string | `""` | Yes | Secret key from CAPTCHA provider |
| `signingKey` | string | `""` | Yes | JWT signing key (minimum 32 bytes). See [Signing Key Generation](SIGNING_KEYS.md) |
| `callbackURL` | string | `""` | Yes | Base URL for CAPTCHA callbacks (public-facing hostname) |
| `cookieDomain` | string | `""` | Yes | Parent domain for cookies (e.g., `.example.com`) to share across subdomains |
| `secureCookie` | bool | `true` | No | Use Secure flag and SameSite=None (true for HTTPS, false for local dev) |
| `cookieName` | string | `"session"` | No | Name of the session cookie used for CAPTCHA verification |
| `timeout` | duration | `"10s"` | No | Timeout for CAPTCHA provider verification requests |
| `sessionDuration` | duration | `"15m"` | No | How long CAPTCHA verification remains valid |
| `challengeDuration` | duration | `"5m"` | No | How long a challenge token remains valid |
| `disableChallengeReplayProtection` | bool | `false` | No | Disable single-use enforcement for challenge tokens. By default, each token is consumed on first use. Disable only in multi-pod environments where in-memory state is not shared — set a short `challengeDuration` when disabled |

```yaml
captcha:
  enabled: true
  provider: "recaptcha"
  siteKey: "<your-site-key>"
  secretKey: "<your-secret-key>"
  signingKey: "<your-jwt-signing-key>"
  callbackURL: "https://yourdomain.com"
  cookieDomain: ".yourdomain.com"
  secureCookie: true
  cookieName: "session"
  timeout: "10s"
  challengeDuration: "5m"
  sessionDuration: "15m"
  disableChallengeReplayProtection: false
```

```bash
export ENVOY_BOUNCER_CAPTCHA_ENABLED=true
export ENVOY_BOUNCER_CAPTCHA_PROVIDER=recaptcha
export ENVOY_BOUNCER_CAPTCHA_SITEKEY=your-site-key
export ENVOY_BOUNCER_CAPTCHA_SECRETKEY=your-secret-key
export ENVOY_BOUNCER_CAPTCHA_SIGNINGKEY=your-jwt-signing-key
export ENVOY_BOUNCER_CAPTCHA_CALLBACKURL=https://yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_COOKIEDOMAIN=.yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_SECURECOOKIE=true
export ENVOY_BOUNCER_CAPTCHA_COOKIENAME=session
export ENVOY_BOUNCER_CAPTCHA_SESSIONDURATION=15m
export ENVOY_BOUNCER_CAPTCHA_CHALLENGEDURATION=5m
export ENVOY_BOUNCER_CAPTCHA_TIMEOUT=10s
export ENVOY_BOUNCER_CAPTCHA_DISABLECHALLENGEREPLAYPROTECTION=false
```

## Prometheus

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the Prometheus metrics endpoint |
| `port` | int | `9090` | Port for the `/metrics` HTTP endpoint |

```yaml
prometheus:
  enabled: true
  port: 9090
```

```bash
export ENVOY_BOUNCER_PROMETHEUS_ENABLED=true
export ENVOY_BOUNCER_PROMETHEUS_PORT=9090
```

## Webhooks

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `subscriptions[].url` | string | - | Yes | HTTP endpoint to receive webhook events |
| `subscriptions[].events` | []string | - | Yes | List of events to subscribe to |
| `signingKey` | string | `""` | No | HMAC-SHA256 signing key for payload verification. See [Signing Key Generation](SIGNING_KEYS.md) |
| `timeout` | duration | `"5s"` | No | HTTP timeout for webhook delivery |
| `bufferSize` | int | `100` | No | Event channel buffer size |

Subscriptions must be configured via YAML file — they cannot be represented as environment variables.

```yaml
webhook:
  subscriptions:
    - url: "https://example.com/security-events"
      events:
        - request_blocked
        - captcha_required
    - url: "https://siem.example.com/ingest"
      events:
        - request_blocked
  signingKey: "your-hmac-secret"
  timeout: "5s"
  bufferSize: 100
```

```bash
export ENVOY_BOUNCER_WEBHOOK_SIGNINGKEY=your-hmac-signing-key
export ENVOY_BOUNCER_WEBHOOK_TIMEOUT=5s
export ENVOY_BOUNCER_WEBHOOK_BUFFERSIZE=100
```

## Templates

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `deniedTemplatePath` | string | `""` | Path to custom ban page template |
| `deniedTemplateHeaders` | string | `"text/html; charset=utf-8"` | Content-Type header for ban page |
| `showDeniedPage` | bool | `true` | Render the denied page template on ban. When false, an empty body is returned |
| `captchaTemplatePath` | string | `""` | Path to custom CAPTCHA page template |
| `captchaTemplateHeaders` | string | `"text/html; charset=utf-8"` | Content-Type header for CAPTCHA page |

```yaml
templates:
  deniedTemplatePath: "/path/to/custom-ban.html"
  deniedTemplateHeaders: "text/html; charset=utf-8"
  showDeniedPage: true
  captchaTemplatePath: "/path/to/custom-captcha.html"
  captchaTemplateHeaders: "text/html; charset=utf-8"
```

```bash
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH=/path/to/ban.html
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEHEADERS="text/html; charset=utf-8"
export ENVOY_BOUNCER_TEMPLATES_SHOWDENIEDPAGE=true
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH=/path/to/captcha.html
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEHEADERS="text/html; charset=utf-8"
```

## See Also

- [example.yaml](./examples/config/example.yaml) - Complete configuration example
- [Deployment Guide](DEPLOYMENT.md) - Deployment instructions
- [CrowdSec Guide](CROWDSEC.md) - CrowdSec bouncer and WAF setup
- [CAPTCHA Guide](CAPTCHA.md) - CAPTCHA challenge setup
- [Webhook Guide](WEBHOOKS.md) - Webhook event notifications
- [Custom Templates](CUSTOM_TEMPLATES.md) - Template customization
- [Metrics](METRICS.md) - Prometheus metrics reference
