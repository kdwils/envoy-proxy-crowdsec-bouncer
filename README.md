![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)
![Build](https://img.shields.io/github/actions/workflow/status/kdwils/envoy-proxy-crowdsec-bouncer/ci.yaml?branch=main)
![License](https://img.shields.io/github/license/kdwils/envoy-proxy-crowdsec-bouncer)

# CrowdSec Envoy Proxy Bouncer
A lightweight [CrowdSec](https://www.crowdsec.net/) bouncer for [Envoy Proxy](https://www.envoyproxy.io/) using the ext_authz (external authorization) filter.

## Features

- Blocks malicious IPs via streamed CrowdSec decisions
- WAF inspection via CrowdSec AppSec
- Fast, lightweight, and easy to deploy
- Bouncer metrics reporting

## Quickstart

Run locally (requires Go 1.21+):

```bash
go install github.com/kdwils/envoy-proxy-bouncer@latest
export ENVOY_BOUNCER_BOUNCER_ENABLED=true
export ENVOY_BOUNCER_BOUNCER_APIKEY=<lapi-key>
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
export ENVOY_BOUNCER_WAF_ENABLED=true
export ENVOY_BOUNCER_WAF_APIKEY=<lapi-key>
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:7422
envoy-proxy-bouncer serve
```

## How It Works

This bouncer:
1. Subscribes to ban decisions from CrowdSec's LAPI via live stream.
2. Extracts the client IP from incoming requests (supports X-Forwarded-For with trusted proxies).
3. With bouncer enabled - checks cached decisions via Crowdsec Local API stream, and if an IP is banned, denies the request with 403.
4. With WAF enabled - forwards the request to CrowdSec AppSec and applies the decision returned if it has not already been bounced.

## Configuration
The bouncer can be configured using:
1. Configuration file (YAML or JSON)
2. Environment variables
3. Command line flags

### Configuration File

Create a `config.yaml` file:

```yaml
server:
  port: 8080
  logLevel: "info"

trustedProxies:
  - 192.168.0.1
  - 2001:db8::1
  - 10.0.0.0/8
  - 100.64.0.0/10

bouncer:
  enabled: true
  metrics: false
  lapiURL: "http://crowdsec:8080" # required when enabled
  apiKey: "<lapi-key>".           # required when enabled
  tickerInterval: "5m"

waf:
  enabled: true 
  appSecURL: "http://appsec:7422" # required when enabled
  apiKey: "<lapi-key>"            # required when enabled
```

Run with config file:
```bash
envoy-proxy-bouncer serve --config config.yaml
```

### Environment Variables

All configuration options can be set via environment variables using the prefix `ENVOY_BOUNCER_` and replacing dots with underscores:

```bash
# Server configuration
export ENVOY_BOUNCER_SERVER_PORT=8080
export ENVOY_BOUNCER_SERVER_LOGLEVEL=debug

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
```

### Configuration Precedence

The configuration is loaded in the following order (last wins):
1. Default values
2. Configuration file
3. Environment variables
4. Command line flags

### Required Configuration

When bouncer is enabled:
- `bouncer.apiKey`
- `bouncer.lapiURL`

When WAF is enabled:
- `waf.apiKey`
- `waf.appSecURL`

Note on API keys:
- An key must be generated on your CrowdSec LAPI (with `cscli bouncers add <name>`). You can use this key for both `bouncer.apiKey` and `waf.apiKey`.

### Default Values

```yaml
server:
  port: 8080
  logLevel: "info"

bouncer:
  enabled: false
  metrics: false
  tickerInterval: "10s"

waf:
  enabled: false
```

## Usage

### Starting the Bouncer

```bash
envoy-proxy-bouncer serve
```

### Testing IP Decisions

```bash
# Test if an IP is banned (multiple IPs can be specified)
envoy-proxy-bouncer bounce -i 192.168.1.1,10.0.0.1

## Docker
Build and run with Docker:

```bash
# Build
docker build -t envoy-proxy-bouncer .

# Run
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  envoy-proxy-bouncer
```

## Real IP Determination

The bouncer determines the client IP in this order:
1. `X-Forwarded-For` - uses the rightmost non-trusted IP
2. `X-Real-Ip`
3. Socket address

Configure `trustedProxies` to ensure correct client IP extraction.

## Response Codes

- 200 OK: Request allowed
- 403 Forbidden: Request blocked by CrowdSec decision or WAF
- 500 Internal Server Error: Configuration or runtime error

## Metrics

The bouncer can report metrics to CrowdSec's dashboard including:
- Total requests processed
- Number of requests bounced

These are opt-in and can be enabled by setting `metrics: true` in the bouncer config.

### Viewing Metrics
From `cscli`
```bash
cscli metrics
```

## Deploying

This project is tested in Kubernetes clusters with Envoy Gateway. For other environments, please open an issue if you encounter problems.

### Kubernetes

The bouncer can be deployed in a Kubernetes cluster alongside Envoy Gateway. See [examples/deploy/README.md](examples/deploy/README.md) for a flat YAML example.

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
  --set crowdsec.bouncer.lapiURL=<your-crowdsec-host>:<port>
  --set crowdsec.trustedProxies=<your-trusted-proxies>
```

Acknowledgements:
* Helm schema generated with [helm-values-schema-json](https://github.com/losisin/helm-values-schema-json)