# Configuration Guide

This guide covers all configuration options for the Envoy Proxy CrowdSec Bouncer.

## Configuration Methods

The bouncer supports multiple configuration methods with the following precedence (last wins):

1. Default values
2. Configuration file (YAML or JSON)
3. Environment variables

## Configuration File

Create a configuration file (e.g., `config.yaml`):

```yaml
server:
  grpcPort: 8080 # Port for gRPC (Envoy ext_authz)
  httpPort: 8081 # Port for HTTP (CAPTCHA endpoints)
  logLevel: "info"

trustedProxies: []  # No default trusted proxies - configure as needed
  # - 192.168.0.1
  # - 2001:db8::1
  # - 10.0.0.0/8
  # - 100.64.0.0/10

bouncer:
  enabled: true                             # CrowdSec integration (enabled by default)
  metrics: false
  tickerInterval: "10s"                     # How often to fetch decisions from LAPI
  metricsInterval: "10m"                    # How often to report metrics to LAPI
  banStatusCode: 403                        # HTTP status code for ban responses
  lapiUrl: "http://crowdsec:8080"
  apiKey: "<lapi-key>"

waf:
  enabled: false                            # Set to true to enable WAF inspection
  appSecURL: "http://appsec:7422"
  apiKey: "<lapi-key>"

captcha:
  enabled: false
  provider: "recaptcha" # Options: recaptcha, turnstile
  siteKey: "<your-captcha-site-key>"
  secretKey: "<your-captcha-secret-key>"
  timeout: "10s"                            # Request timeout for CAPTCHA provider verification
  callbackURL: "https://yourdomain.com"     # Base URL for captcha callbacks
  challengeDuration: "5m"                   # How long before a CAPTCHA challenge expires
  sessionDuration: "15m"                    # How long captcha verification is valid

templates:
  deniedTemplatePath: ""                    # Path to custom ban page template
  deniedTemplateHeaders: ""                 # Content-Type header for ban page
  captchaTemplatePath: ""                   # Path to custom CAPTCHA page template
  captchaTemplateHeaders: ""                # Content-Type header for CAPTCHA page
```

Start with config file:

```bash
envoy-proxy-bouncer serve --config config.yaml
```

## Environment Variables

All configuration options can be set via environment variables using the prefix `ENVOY_BOUNCER_` and replacing dots with underscores:

```bash
# Server configuration
export ENVOY_BOUNCER_SERVER_GRPCPORT=8080
export ENVOY_BOUNCER_SERVER_HTTPPORT=8081
export ENVOY_BOUNCER_SERVER_LOGLEVEL=debug

# Bouncer configuration (enabled by default)
export ENVOY_BOUNCER_BOUNCER_ENABLED=true
export ENVOY_BOUNCER_BOUNCER_APIKEY=your-lapi-bouncer-api-key
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
export ENVOY_BOUNCER_BOUNCER_TICKERINTERVAL=10s
export ENVOY_BOUNCER_BOUNCER_METRICSINTERVAL=10m
export ENVOY_BOUNCER_BOUNCER_METRICS=false
export ENVOY_BOUNCER_BOUNCER_BANSTATUSCODE=403

# Trusted proxies (comma-separated) - no defaults
export ENVOY_BOUNCER_TRUSTEDPROXIES=192.168.0.1,10.0.0.0/8

# WAF configuration (disabled by default)
export ENVOY_BOUNCER_WAF_ENABLED=true
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:7422
export ENVOY_BOUNCER_WAF_APIKEY=your-appsec-api-key

# CAPTCHA configuration (disabled by default)
export ENVOY_BOUNCER_CAPTCHA_ENABLED=true
export ENVOY_BOUNCER_CAPTCHA_PROVIDER=recaptcha
export ENVOY_BOUNCER_CAPTCHA_SITEKEY=your-captcha-site-key
export ENVOY_BOUNCER_CAPTCHA_SECRETKEY=your-captcha-secret-key
export ENVOY_BOUNCER_CAPTCHA_TIMEOUT=10s
export ENVOY_BOUNCER_CAPTCHA_CALLBACKURL=https://yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_CHALLENGEDURATION=5m
export ENVOY_BOUNCER_CAPTCHA_SESSIONDURATION=15m

# Template configuration
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH=/path/to/ban.html
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEHEADERS="text/html; charset=utf-8"
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH=/path/to/captcha.html
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEHEADERS="text/html; charset=utf-8"
```

## Configuration Sections

### Server

Controls the bouncer server settings.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `grpcPort` | int | `8080` | Port for gRPC ext_authz server (Envoy integration) |
| `httpPort` | int | `8081` | Port for HTTP server (CAPTCHA endpoints) |
| `logLevel` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error` |

### Trusted Proxies

List of trusted proxy IPs or CIDR ranges. Used to extract the real client IP from forwarded headers.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `trustedProxies` | []string | `[]` | List of trusted proxy IPs/CIDRs |

**Important**: Configure this carefully to prevent IP spoofing. Only list proxies you control.

Example:
```yaml
trustedProxies:
  - 192.168.0.1
  - 10.0.0.0/8
  - 2001:db8::1
```

### Bouncer

Controls CrowdSec bouncer integration.

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `true` | No | Enable CrowdSec bouncer functionality |
| `apiKey` | string | `""` | Yes (when enabled) | CrowdSec LAPI bouncer API key |
| `lapiURL` | string | `""` | Yes (when enabled) | CrowdSec LAPI URL |
| `metrics` | bool | `false` | No | Enable metrics reporting to CrowdSec |
| `tickerInterval` | duration | `"10s"` | No | Interval to fetch decisions from LAPI |
| `metricsInterval` | duration | `"10m"` | No | Interval to report metrics to LAPI |
| `banStatusCode` | int | `403` | No | HTTP status code for ban responses |

**Note**: Generate API key with `cscli bouncers add <name>` on your CrowdSec instance.

#### Metrics Reporting

Enable metrics reporting to track bouncer effectiveness:

```yaml
bouncer:
  metrics: true
  metricsInterval: "10m"
```

Metrics can be viewed using `cscli metrics` on your CrowdSec instance.

#### Custom Ban Status Codes

By default, the bouncer returns HTTP 403 (Forbidden) for banned IPs. You can customize this to avoid feedback loops when CrowdSec processes Envoy logs:

```yaml
bouncer:
  banStatusCode: 418  # Use 418 "I'm a teapot" to distinguish from legitimate 403s
```

This is useful when CrowdSec analyzes Envoy access logs, as it can ignore ban responses (418) while still processing genuine errors (403).

**Common alternatives**:
- `418` - "I'm a teapot" (RFC 2324)
- `429` - "Too Many Requests" 
- `444` - Nginx-style "Connection closed without response"

### WAF

Controls CrowdSec AppSec (WAF) integration.

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable WAF request inspection |
| `apiKey` | string | `""` | Yes (when enabled) | CrowdSec AppSec API key |
| `appSecURL` | string | `""` | Yes (when enabled) | CrowdSec AppSec service URL |

**Note**: You can use the same API key as the bouncer.

### CAPTCHA

Controls CAPTCHA challenge functionality.

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable CAPTCHA challenges |
| `provider` | string | `""` | Yes (when enabled) | CAPTCHA provider: `recaptcha` or `turnstile` |
| `siteKey` | string | `""` | Yes (when enabled) | CAPTCHA site key |
| `secretKey` | string | `""` | Yes (when enabled) | CAPTCHA secret key |
| `callbackURL` | string | `""` | Yes (when enabled) | Base URL for CAPTCHA callbacks |
| `timeout` | duration | `"10s"` | No | Timeout for CAPTCHA provider verification |
| `challengeDuration` | duration | `"5m"` | No | How long before a CAPTCHA challenge expires |
| `sessionDuration` | duration | `"15m"` | No | How long CAPTCHA verification is valid |

See [CAPTCHA.md](CAPTCHA.md) for detailed CAPTCHA configuration.

### Templates

Controls custom HTML template configuration.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `deniedTemplatePath` | string | `""` | Path to custom ban page template |
| `deniedTemplateHeaders` | string | `"text/html; charset=utf-8"` | Content-Type header for ban page |
| `captchaTemplatePath` | string | `""` | Path to custom CAPTCHA page template |
| `captchaTemplateHeaders` | string | `"text/html; charset=utf-8"` | Content-Type header for CAPTCHA page |

See [CUSTOM_TEMPLATES.md](CUSTOM_TEMPLATES.md) for detailed template customization.

## Required Configuration

### Minimal Setup (Bouncer Only)

The bouncer component is **enabled by default**. A minimal configuration requires:

```yaml
bouncer:
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"
```

Or via environment variables:

```bash
export ENVOY_BOUNCER_BOUNCER_APIKEY=your-api-key
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
```

### With WAF

```yaml
bouncer:
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"

waf:
  enabled: true
  apiKey: "<lapi-key>"
  appSecURL: "http://appsec:7422"
```

### With CAPTCHA

```yaml
bouncer:
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"

captcha:
  enabled: true
  provider: "recaptcha"
  siteKey: "<site-key>"
  secretKey: "<secret-key>"
  callbackURL: "https://yourdomain.com"
```

## Default Values

```yaml
server:
  grpcPort: 8080
  httpPort: 8081
  logLevel: "info"

trustedProxies: []

bouncer:
  enabled: true
  metrics: false
  tickerInterval: "10s"
  metricsInterval: "10m"

waf:
  enabled: false

captcha:
  enabled: false
  timeout: "10s"
  challengeDuration: "5m"
  sessionDuration: "15m"

templates:
  deniedTemplateHeaders: "text/html; charset=utf-8"
  captchaTemplateHeaders: "text/html; charset=utf-8"
```

## See Also

- [Deployment Guide](DEPLOYMENT.md)
- [CAPTCHA Configuration](CAPTCHA.md)
- [Custom Templates](CUSTOM_TEMPLATES.md)
