# CrowdSec Configuration

All CrowdSec-related configuration for the Envoy Proxy CrowdSec Bouncer.

## Overview

The bouncer integrates with CrowdSec for IP-based blocking (bouncer) and request inspection (WAF/AppSec). Both features use the CrowdSec LAPI (Local API) for decision streaming and metrics reporting.

## Table of Contents

- [Bouncer Configuration](#bouncer-configuration)
- [WAF Configuration](#waf-configuration)
- [Trusted Proxies](#trusted-proxies)
- [Metrics Reporting](#metrics-reporting)
- [Environment Variables](#environment-variables)
- [Examples](#examples)

## Bouncer Configuration

Controls CrowdSec bouncer integration for IP-based blocking.

### Configuration Options

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `true` | No | Enable CrowdSec bouncer functionality |
| `apiKey` | string | `""` | Yes (when enabled) | CrowdSec LAPI bouncer API key |
| `lapiURL` | string | `""` | Yes (when enabled) | CrowdSec LAPI URL |
| `metrics` | bool | `false` | No | Enable metrics reporting to CrowdSec |
| `tickerInterval` | duration | `"10s"` | No | Interval to fetch decisions from LAPI |
| `metricsInterval` | duration | `"10m"` | No | Interval to report metrics to LAPI |
| `banStatusCode` | int | `403` | No | HTTP status code for ban responses |

### YAML Configuration

```yaml
bouncer:
  enabled: true
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"
  metrics: false
  tickerInterval: "10s"
  metricsInterval: "10m"
  banStatusCode: 403
```

### Generating API Key

Generate a bouncer API key on your CrowdSec instance:

```bash
cscli bouncers add envoy-proxy-bouncer
```

The output will include an API key. Use this value for `apiKey` in your configuration.

### Custom Ban Status Codes

By default, the bouncer returns HTTP 403 (Forbidden) for banned IPs. You can customize this to avoid feedback loops when CrowdSec processes Envoy logs:

```yaml
bouncer:
  banStatusCode: 418  # Use 418 "I'm a teapot" to distinguish from legitimate 403s
```

This is useful when CrowdSec analyzes Envoy access logs, as it can ignore ban responses (418) while still processing genuine errors (403).

**Common alternatives:**
- `418` - "I'm a teapot" (RFC 2324)
- `429` - "Too Many Requests"
- `444` - Nginx-style "Connection closed without response"

## WAF Configuration

Controls CrowdSec AppSec (WAF) integration for request inspection.

### Configuration Options

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `enabled` | bool | `false` | No | Enable WAF request inspection |
| `apiKey` | string | `""` | Yes (when enabled) | CrowdSec AppSec API key |
| `appSecURL` | string | `""` | Yes (when enabled) | CrowdSec AppSec service URL |

### YAML Configuration

```yaml
waf:
  enabled: true
  apiKey: "<lapi-key>"
  appSecURL: "http://appsec:7422"
```

You can use the same API key as the bouncer, or generate a separate one.

## Trusted Proxies

List of trusted proxy IPs or CIDR ranges. Used to extract the real client IP from forwarded headers for CrowdSec decision lookups.

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `trustedProxies` | []string | `[]` | List of trusted proxy IPs/CIDRs |

### YAML Configuration

```yaml
trustedProxies:
  - 192.168.0.1
  - 10.0.0.0/8
  - 2001:db8::1
  - 100.64.0.0/10
```

**Important:** Configure this carefully to prevent IP spoofing. Only list proxies you control.

### IP Extraction Logic

The bouncer extracts the real client IP from headers and trusted proxies:
1. Checks `X-Forwarded-For` header (case-insensitive)
2. Falls back to `X-Real-IP` header
3. Respects trusted proxy configuration
4. Validates IP format before use

## Metrics Reporting

Enable metrics reporting to track bouncer effectiveness and view statistics in CrowdSec.

### Enabling Metrics

```yaml
bouncer:
  metrics: true
  metricsInterval: "10m"
```

### Viewing Metrics

Metrics can be viewed using `cscli metrics` on your CrowdSec instance:

```bash
cscli metrics
```

This shows:
- Total requests processed
- Requests bounced
- Requests allowed
- Per-scenario statistics

## Environment Variables

All CrowdSec configuration options can be set via environment variables using the prefix `ENVOY_BOUNCER_`:

### Bouncer

```bash
export ENVOY_BOUNCER_BOUNCER_ENABLED=true
export ENVOY_BOUNCER_BOUNCER_APIKEY=your-lapi-bouncer-api-key
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
export ENVOY_BOUNCER_BOUNCER_TICKERINTERVAL=10s
export ENVOY_BOUNCER_BOUNCER_METRICSINTERVAL=10m
export ENVOY_BOUNCER_BOUNCER_METRICS=false
export ENVOY_BOUNCER_BOUNCER_BANSTATUSCODE=403
```

### WAF

```bash
export ENVOY_BOUNCER_WAF_ENABLED=true
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:7422
export ENVOY_BOUNCER_WAF_APIKEY=your-appsec-api-key
```

### Trusted Proxies

```bash
export ENVOY_BOUNCER_TRUSTEDPROXIES=192.168.0.1,10.0.0.0/8
```

## Examples

### Minimal Setup (Bouncer Only)

The bouncer component is enabled by default. A minimal configuration requires only the API key and LAPI URL:

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

### Bouncer with Metrics

```yaml
bouncer:
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"
  metrics: true
  metricsInterval: "10m"
```

### Bouncer with WAF

```yaml
bouncer:
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"

waf:
  enabled: true
  apiKey: "<lapi-key>"
  appSecURL: "http://appsec:7422"
```

### Full CrowdSec Configuration

```yaml
trustedProxies:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

bouncer:
  enabled: true
  apiKey: "<lapi-key>"
  lapiURL: "http://crowdsec:8080"
  metrics: true
  tickerInterval: "10s"
  metricsInterval: "10m"
  banStatusCode: 418

waf:
  enabled: true
  apiKey: "<lapi-key>"
  appSecURL: "http://appsec:7422"
```

### Kubernetes/Helm

For Helm-specific configuration, see the [Helm Chart README](../charts/envoy-proxy-bouncer/README.md).

## See Also

- [Configuration Guide](CONFIGURATION.md) - General configuration overview
- [CAPTCHA Configuration](CAPTCHA.md) - CAPTCHA challenge setup
- [Webhook Configuration](WEBHOOKS.md) - Webhook event notifications
- [Deployment Guide](DEPLOYMENT.md) - Deployment instructions
- [CrowdSec Documentation](https://docs.crowdsec.net/) - Official CrowdSec docs
