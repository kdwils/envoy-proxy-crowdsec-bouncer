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
  sessionDuration: "15m"                    # How long captcha verification is valid
  cacheCleanupInterval: "5m"                # How often to clean up expired IP verification cache entries

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

**Note**: Generate API key with `cscli bouncers add <name>` on your CrowdSec instance.

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
| `sessionDuration` | duration | `"15m"` | No | How long CAPTCHA verification is valid |
| `cacheCleanupInterval` | duration | `"5m"` | No | Interval to clean up expired sessions |

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
  sessionDuration: "15m"
  cacheCleanupInterval: "5m"

templates:
  deniedTemplateHeaders: "text/html; charset=utf-8"
  captchaTemplateHeaders: "text/html; charset=utf-8"
```

## Validation

The bouncer will validate configuration on startup and fail if:

- Required fields are missing when a component is enabled
- Invalid duration formats are provided
- Invalid URLs are provided
- Template files cannot be read or parsed

Check logs for detailed error messages if the bouncer fails to start.

## Examples

### Production Configuration

```yaml
server:
  grpcPort: 8080
  httpPort: 8081
  logLevel: "info"

trustedProxies:
  - 10.0.0.0/8
  - 172.16.0.0/12

bouncer:
  enabled: true
  metrics: true
  lapiURL: "http://crowdsec.monitoring.svc:8080"
  apiKey: "your-api-key"
  tickerInterval: "10s"
  metricsInterval: "10m"

waf:
  enabled: true
  appSecURL: "http://crowdsec-appsec.monitoring.svc:7422"
  apiKey: "your-api-key"

captcha:
  enabled: true
  provider: "turnstile"
  siteKey: "0x4AAAAAAAA..."
  secretKey: "0x4AAAAAAAA..."
  callbackURL: "https://auth.example.com"
  sessionDuration: "15m"
```

### Development Configuration

```yaml
server:
  grpcPort: 8080
  httpPort: 8081
  logLevel: "debug"

bouncer:
  enabled: true
  metrics: false
  lapiURL: "http://localhost:8080"
  apiKey: "dev-api-key"

waf:
  enabled: false

captcha:
  enabled: false
```

## See Also

- [Deployment Guide](DEPLOYMENT.md)
- [CAPTCHA Configuration](CAPTCHA.md)
- [Custom Templates](CUSTOM_TEMPLATES.md)
