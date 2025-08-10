![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Build](https://img.shields.io/github/actions/workflow/status/kdwils/envoy-proxy-crowdsec-bouncer/ci.yml?branch=main)
![License](https://img.shields.io/github/license/kdwils/envoy-proxy-crowdsec-bouncer)

# CrowdSec Envoy Proxy Bouncer
A lightweight [CrowdSec](https://www.crowdsec.net/) bouncer for [Envoy Proxy](https://www.envoyproxy.io/) using the ext_authz (external authorization) filter.

## Features

- Blocks malicious IPs at the edge using CrowdSec ban decisions
- Optional WAF inspection via CrowdSec AppSec
- Fast, lightweight, and easy to deploy (binary, Docker, Kubernetes, Helm)
- Flexible configuration (file, env, CLI)
- Metrics reporting (optional)

## Quickstart

Run locally (requires Go 1.21+):

```bash
go install github.com/kdwils/envoy-proxy-bouncer@latest
export ENVOY_BOUNCER_BOUNCER_APIKEY=<your-lapi-bouncer-api-key>
export ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080
# optional WAF
export ENVOY_BOUNCER_WAF_ENABLED=true
export ENVOY_BOUNCER_WAF_APIKEY=<your-appsec-api-key>
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:4241
envoy-proxy-bouncer serve
```

Or with Docker:

```bash
docker run -p 8080:8080 \
  -e ENVOY_BOUNCER_BOUNCER_APIKEY=<your-lapi-bouncer-api-key> \
  -e ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080 \
  -e ENVOY_BOUNCER_WAF_ENABLED=true \
  -e ENVOY_BOUNCER_WAF_APIKEY=<your-appsec-api-key> \
  -e ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:4241 \
  kdwils/envoy-proxy-bouncer
```

This project provides a seamless way to integrate CrowdSec with Envoy to block malicious IP addresses before they reach your internal services. The bouncer uses CrowdSec's Local API (LAPI) to receive ban decisions and (optionally) forwards requests to CrowdSec AppSec (WAF) for inspection.

---

## How It Works

This bouncer:
1. Subscribes to ban decisions from CrowdSec's LAPI via live stream.
2. Extracts the client IP from incoming requests (supports X-Forwarded-For with trusted proxies).
3. If bouncer is enabled, denies banned IPs with 403.
4. If WAF is enabled, forwards the request to CrowdSec AppSec and applies its decision.

WAF forwarding uses the request method (GET if no body, POST if body present), filters out HTTP/2 pseudo headers, and sets the required AppSec headers.

## Configuration
The bouncer can be configured using:
1. Configuration file (YAML or JSON)
2. Environment variables
3. Command line flags

### Configuration File

Create a `config.yaml` file:

```yaml
server:
  port: 8080                # optional (defaults to 8080)
  logLevel: "info"          # optional (defaults to info)

trustedProxies:             # optional (defaults to 127.0.0.1, ::1)
  - 192.168.0.1             # IPv4
  - 2001:db8::1             # IPv6
  - 10.0.0.0/8              # CIDR range
  - 100.64.0.0/10           # CIDR range

bouncer:
  enabled: true             # optional (defaults to false)
  metrics: false            # optional (defaults to false)
  lapiURL: "http://crowdsec:8080"  # required (LAPI base URL)
  apiKey: "<lapi-bouncer-api-key>" # required
  tickerInterval: "10s"     # optional (defaults to 10s)

waf:
  enabled: true             # optional (defaults to false)
  timeout: "5s"             # optional (defaults to 1s)
  appSecURL: "http://appsec:4241" # required when enabled
  apiKey: "<appsec-api-key>"      # required when enabled
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
export ENVOY_BOUNCER_WAF_TIMEOUT=5s
export ENVOY_BOUNCER_WAF_APPSECURL=http://appsec:4241
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
  timeout: "1s"
```

## WAF Details

When enabled, the bouncer forwards the request to CrowdSec AppSec at `waf.appSecURL` with headers:
- `X-Crowdsec-Appsec-Ip`: real client IP
- `X-Crowdsec-Appsec-Uri`: request path
- `X-Crowdsec-Appsec-Host`: request host
- `X-Crowdsec-Appsec-Verb`: request method
- `X-Crowdsec-Appsec-Api-Key`: AppSec API key
- `X-Crowdsec-Appsec-User-Agent`: original User-Agent
- `X-Crowdsec-Appsec-Http-Version`: HTTP protocol version

Notes:
- HTTP/2 pseudo headers (e.g., `:scheme`, `:authority`, `:path`, `:method`) are not forwarded as HTTP headers.
- Method is GET when the body is empty, POST when a body is present.

## Usage

### Starting the Bouncer

```bash
envoy-proxy-bouncer serve
```

### Testing IP Decisions

```bash
# Test if an IP is banned (multiple IPs can be specified)
envoy-proxy-bouncer bounce -i 192.168.1.1,10.0.0.1

# Manual gRPC request test
grpcurl -plaintext -d @ localhost:8080 envoy.service.auth.v3.Authorization/Check < request.json
```

An example request would look like:
```json
{
  "attributes": {
    "source": {
      "address": {
        "socketAddress": {
          "address": "192.168.1.100",
          "portValue": 50555
        }
      }
    },
    "request": {
      "http": {
        "headers": {
          "x-forwarded-for": "192.168.1.100, 10.0.0.1"
        }
      }
    }
  }
}
```

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

## Headers

The bouncer determines the client IP in this order:
1. `X-Forwarded-For` (uses the rightmost non-trusted IP)
2. `X-Real-Ip`
3. Socket address

Configure `trustedProxies` to ensure correct client IP extraction.

## Response Codes

- 200 OK: Request allowed
- 403 Forbidden: Request blocked by CrowdSec decision or WAF
- 500 Internal Server Error: Configuration or runtime error

## Development

```bash
# Run tests
go test ./...

# Build from source
go build -o envoy-proxy-bouncer
```

### nix

starting a shell with the project dependencies:
```bash
nix develop .
```

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
  --set crowdsec.bouncer.apiKey=<your-api-key> \
  --set crowdsec.bouncer.lapiURL=<your-crowdsec-host>:<port>
  --set crowdsec.trustedProxies=<your-trusted-proxies>
```

Acknowledgements:
* Helm schema generated with [helm-values-schema-json](https://github.com/losisin/helm-values-schema-json)