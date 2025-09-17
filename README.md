![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)
![Build](https://img.shields.io/github/actions/workflow/status/kdwils/envoy-proxy-crowdsec-bouncer/ci.yaml?branch=main)
![License](https://img.shields.io/github/license/kdwils/envoy-proxy-crowdsec-bouncer)

# CrowdSec Envoy Proxy Bouncer
A lightweight [CrowdSec](https://www.crowdsec.net/) bouncer for [Envoy Proxy](https://www.envoyproxy.io/) using the ext_authz filter.

## Features

- Block malicious IPs streamed via CrowdSec decisions
- Bouncer metrics reporting
- Request inspection via CrowdSec AppSec
- CAPTCHA challenges for suspicious IPs with support for:
  - Google reCAPTCHA v2
  - Cloudflare Turnstile

## How It Works

The remediation component subscribes to decisions from CrowdSec via the Stream API, and on each request:

1. Determines the real client IP from the forwarded request.
2. When the Bouncer is enabled, the IP of the request is checked against cached banned decisions, and if the IP banned, returns a 403.
3. When WAF is enabled, the request is forwarded to a CrowdSec AppSec instance and the returned decision is applied.
4. When CAPTCHA is enabled, suspicious IPs are redirected to a CAPTCHA challenge page instead of being immediately blocked when a captcha decision is returned by the WAF component.

## Configuration
The bouncer can be configured using:
1. Configuration file (YAML or JSON)
2. Environment variables

### Configuration File

Create a `config.yaml` file:

```yaml
server:
  grpcPort: 8080          # Port for gRPC (Envoy ext_authz)
  httpPort: 8081          # Port for HTTP (CAPTCHA endpoints)
  logLevel: "info"

trustedProxies:
  - 192.168.0.1
  - 2001:db8::1
  - 10.0.0.0/8
  - 100.64.0.0/10

bouncer:
  enabled: true
  metrics: false
  lapiURL: "http://crowdsec:8080"
  apiKey: "<lapi-key>"

waf:
  enabled: true 
  appSecURL: "http://appsec:7422"
  apiKey: "<lapi-key>"

captcha:
  enabled: true
  provider: "recaptcha"                    # Options: recaptcha, turnstile
  siteKey: "<your-captcha-site-key>"
  secretKey: "<your-captcha-secret-key>"
  url: "https://yourdomain.com"            # Base URL for captcha callbacks
  cacheDuration: "15m"                     # How long to cache sessions
```

Run with config file:
```bash
envoy-proxy-bouncer serve --config config.yaml
```

### Environment Variables

All configuration options can be set via environment variables using the prefix `ENVOY_BOUNCER_` and replacing dots with underscores:

```bash
# Server configuration
export ENVOY_BOUNCER_SERVER_GRPCPORT=8080
export ENVOY_BOUNCER_SERVER_HTTPPORT=8081
export ENVOY_BOUNCER_SERVER_LOGLEVEL=debug
# Deprecated - use GRPCPORT instead
export ENVOY_BOUNCER_SERVER_PORT=8080

# Bouncer configuration
export ENVOY_BOUNCER_BOUNCER_ENABLED=true
export ENVOY_BOUNCER_BOUNCER_APIKEY=your-lapi-bouncer-api-key
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
export ENVOY_BOUNCER_BOUNCER_TICKERINTERVAL=5s
export ENVOY_BOUNCER_BOUNCER_METRICS=false

# Trusted proxies (comma-separated)
export ENVOY_BOUNCER_TRUSTEDPROXIES=192.168.0.1,10.0.0.0/8

# WAF configuration
export ENVOY_BOUNCER_WAF_ENABLED=true
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:7422
export ENVOY_BOUNCER_WAF_APIKEY=your-appsec-api-key

# CAPTCHA configuration
export ENVOY_BOUNCER_CAPTCHA_ENABLED=true
export ENVOY_BOUNCER_CAPTCHA_PROVIDER=recaptcha
export ENVOY_BOUNCER_CAPTCHA_SITEKEY=your-captcha-site-key
export ENVOY_BOUNCER_CAPTCHA_SECRETKEY=your-captcha-secret-key
export ENVOY_BOUNCER_CAPTCHA_URL=https://yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_CACHEDURATION=1h
```

### Configuration Precedence

The configuration is loaded in the following order (last wins):
1. Default values
2. Configuration file
3. Environment variables

### Required Configuration

A minimal configuration requires:

When bouncer is enabled:
- `bouncer.apiKey`
- `bouncer.lapiURL`

When WAF is enabled:
- `waf.apiKey`
- `waf.appSecURL`

When CAPTCHA is enabled:
- `captcha.provider`
- `captcha.siteKey`
- `captcha.secretKey`
- `captcha.url`

Note on API keys:
- A key must be generated on your CrowdSec LAPI (with `cscli bouncers add <name>`). You can use this key for both `bouncer.apiKey` and `waf.apiKey`.
### Default Values

```yaml
server:
  grpcPort: 8080  # ext_authz grpc port
  httpPort: 8081  # Only used when captcha is enabled
  logLevel: "info"

bouncer:
  enabled: false
  metrics: false
  tickerInterval: "10s"

waf:
  enabled: false

captcha:
  enabled: false
  cacheDuration: "15m"
```

## CAPTCHA Configuration

The bouncer supports CAPTCHA challenges as an alternative to immediately blocking suspicious IPs. When enabled, the bouncer runs dual servers:
- gRPC server (default port 8080): Handles Envoy ext_authz requests
- HTTP server (default port 8081): Serves CAPTCHA challenge and verification endpoints

### Supported Providers

| Provider | Configuration Value | Documentation |
|----------|-------------------|---------------|
| Google reCAPTCHA v2 | `recaptcha` | [reCAPTCHA Documentation](https://developers.google.com/recaptcha) |
| Cloudflare Turnstile | `turnstile` | [Turnstile Documentation](https://developers.cloudflare.com/turnstile/) |

### CAPTCHA Flow

1. Detection: CrowdSec identifies a suspicious IP that should be challenged rather than blocked
2. Redirect: The bouncer redirects the request to `/captcha/challenge?session=<session-id>`
3. Challenge: User is presented with a CAPTCHA challenge page
4. Verification: User completes CAPTCHA and submits to `/captcha/verify`
5. Access: Upon successful verification, user is redirected to original URL

### CAPTCHA Endpoints

When CAPTCHA is enabled, the HTTP server exposes these endpoints:

- `GET` `/captcha/challenge?session=<id>`: Displays the CAPTCHA challenge page
- `POST` `/captcha/verify`: Verifies CAPTCHA response and redirects user

### Setup Instructions

1. Register with CAPTCHA provider and obtain site key and secret key
2. Configure the bouncer with your CAPTCHA credentials
3. Update Envoy configuration to allow access to the HTTP server endpoints
4. Set up CrowdSec scenarios to use `captcha` remediation instead of `ban`

## Usage

### Install the binary
```shell
go install github.com/kdwils/envoy-proxy-bouncer@latest
```

```shell
Usage:
  envoy-proxy-bouncer [command]

Available Commands:
  bounce      Test if an IP should be bounced or not
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  serve       serve the envoy gateway bouncer
  version     envoy-proxy-bouncer version

Flags:
      --config string   config file (json or yaml)
  -h, --help            help for envoy-proxy-bouncer
  -t, --toggle          Help message for toggle

Use "envoy-proxy-bouncer [command] --help" for more information about a command.
```

### Start the Bouncer

```bash
envoy-proxy-bouncer serve
```

### Check an IP address against LAPI
```bash
envoy-proxy-bouncer bounce -i 192.168.1.1,10.0.0.1
```

## Metrics
The bouncer can report metrics to CrowdSec's dashboard including:
- Total requests processed
- Number of requests bounced

These are opt-in and can be enabled by setting `metrics: true` in the bouncer config.

Metrics can be viewed using [cscli](https://docs.crowdsec.net/u/getting_started/post_installation/metrics/)
```bash
cscli metrics
```

## Deploying

This project is tested in Kubernetes clusters with Envoy Gateway. For other environments, please open an issue if you encounter problems.

### Kubernetes

The bouncer can be deployed in a Kubernetes cluster alongside Envoy Gateway. See [examples/deploy/README.md](examples/deploy/README.md) for a flat YAML example.

There is also a manifest that can be referenced in my [homelab](https://github.com/kdwils/homelab/blob/main/monitoring/envoy-proxy-bouncer/bouncer.yaml) repo.

### Helm

Add the Helm repository:
```bash
helm repo add envoy-proxy-bouncer https://kdwils.github.io/envoy-proxy-crowdsec-bouncer
helm repo update
```

Install the chart:
```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --set crowdsec.bouncer.enabled=true \
  --set crowdsec.bouncer.apiKey=<lapi-key> \
  --set crowdsec.bouncer.lapiURL=<your-crowdsec-host>:<port> \
  --set crowdsec.trustedProxies=<your-trusted-proxies>
```

Acknowledgements:
* Helm schema generated with [helm-values-schema-json](https://github.com/losisin/helm-values-schema-json)
* Helm docs generated with [helm-docs](https://github.com/norwoodj/helm-docs)