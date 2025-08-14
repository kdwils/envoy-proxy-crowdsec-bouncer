![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)
![Build](https://img.shields.io/github/actions/workflow/status/kdwils/envoy-proxy-crowdsec-bouncer/ci.yaml?branch=main)
![License](https://img.shields.io/github/license/kdwils/envoy-proxy-crowdsec-bouncer)

# CrowdSec Envoy Proxy Bouncer
A lightweight [CrowdSec](https://www.crowdsec.net/) bouncer for [Envoy Proxy](https://www.envoyproxy.io/) using the ext_authz filter.

## Features

- Bouncer Bblocks malicious IPs streamed via CrowdSec decisions
- WAF inspection via CrowdSec AppSec

## How It Works

The remediation component subscribes to decisions from Crowdsec via stream api, and on each request:

1. Determines the real client ip from the forwarded request
2. With bouncer enabled - check is the IP of the request is banned against cached decisions, and if so, denies the request with 403
3. With WAF enabled - forwards the request to CrowdSec AppSec and applies the decision returned

## Configuration
The bouncer can be configured using:
1. Configuration file (YAML or JSON)
2. Environment variables

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
  lapiURL: "http://crowdsec:8080"
  apiKey: "<lapi-key>"
  tickerInterval: "5m"

waf:
  enabled: true 
  appSecURL: "http://appsec:7422"
  apiKey: "<lapi-key>"
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

### Install the binary
```shell
go install github.com/kdwils/envoy-proxy-bouncer@latest
```

The binary ships with a few commands
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

### Test IP Decisions
Test if an ip is currented banned
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

There is also manifest that can be referenced in my [homelab](https://github.com/kdwils/homelab/blob/main/monitoring/envoy-proxy-bouncer/bouncer.yaml) repo.

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
* Helm docs generated with [helm-docs](https://github.com/norwoodj/helm-docs)