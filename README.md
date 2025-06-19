# CrowdSec Envoy Proxy Bouncer

A lightweight [CrowdSec](https://www.crowdsec.net/) bouncer for [Envoy Proxy](https://www.envoyproxy.io/) using the ext_authz (external authorization) filter.

This project provides a seamless way to integrate CrowdSec with Envoy to block malicious IP addresses before they reach your internal services. The bouncer uses CrowdSec's Local API (LAPI) to receive ban decisions and respond to Envoy's external authorization calls.

---

## How It Works

This bouncer:
1. Subscribes to ban decisions from CrowdSec's LAPI via live stream.
2. Extracts the client IP from incoming requests.
3. Validates the IP against the cached ban list.
4. Returns a `403 Forbidden` to Envoy for banned IPs, or `200 OK` if the IP is clean.

```mermaid
sequenceDiagram
    participant Client
    participant Envoy as Envoy Proxy
    participant Bouncer as Envoy Bouncer

    Client->>Envoy: HTTP Request
    Envoy->>Bouncer: ext_authz Check
    Note over Bouncer: Extract client IP

    alt IP is banned
        Bouncer->>Envoy: 403 Forbidden
        Envoy->>Client: Blocked
    else IP is clean
        Bouncer->>Envoy: 200 OK
        Envoy->>Client: Allow Request
    end
```

## Installation

```bash
go install github.com/kdwils/envoy-proxy-bouncer@latest
```

## Configuration

The bouncer can be configured using:
1. Configuration file (YAML or JSON)
2. Environment variables
3. Command line flags

### Configuration File

Create a `config.yaml` file:

```yaml
server:
  port: 8080                               # optional (defaults to 8080)
  logLevel: "info"                         # optional (defaults to info)

bouncer:
  apiKey: "your-crowdsec-bouncer-api-key"  # required
  apiURL: "http://crowdsec:8080"           # required

  metrics: true                            # optional (defaults to false) - report metrics to the LAPI instance
  
  trustedProxies:                          # optional (defaults to 127.0.0.1, ::1)
    - 192.168.0.1                          # IPv4
    - 2001:db8::1                          # IPv6
    - 10.0.0.0/8                           # CIDR range
    - 100.64.0.0/10                        # CIDR range
  
  tickerInterval: "10s"                    # optional (defaults to 10s) - how often to check for ban decisions from the LAPI stream
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
export ENVOY_BOUNCER_BOUNCER_APIKEY=your-api-key
export ENVOY_BOUNCER_BOUNCER_APIURL=http://crowdsec:8080
export ENVOY_BOUNCER_BOUNCER_TRUSTEDPROXIES=192.168.0.1,10.0.0.0/8
export ENVOY_BOUNCER_BOUNCER_TICKERINTERVAL=5s
```

### Configuration Precedence

The configuration is loaded in the following order (last wins):
1. Default values
2. Configuration file
3. Environment variables
4. Command line flags

### Required Configuration

The following configuration options are required:
- `bouncer.apiKey`: CrowdSec bouncer API key
- `bouncer.apiURL`: CrowdSec API URL

### Default Values

```yaml
server:
  port: 8080
  logLevel: "info"

bouncer:
  metrics: false
  trustedProxies:
    - "127.0.0.1"
    - "::1"
  tickerInterval: "10s"
```

### Simple bouncer configuration
1. Generate an API key from your LAPI instance:
```bash
sudo cscli bouncers add envoy-bouncer
```

2. Set the key as an environment variable with your LAPI host:
```bash
export ENVOY_BOUNCER_BOUNCER_APIKEY=<your-api-key>
export ENVOY_BOUNCER_BOUNCER_APIURL=<your-lapi-host>
```

## Usage

### Starting the Bouncer

```bash
envoy-proxy-bouncer serve
```

### Testing ip Decisions

```bash
# Test if an ip is banned (multiple IPs can be specified)
envoy-proxy-bouncer bounce -i 192.168.1.1,10.0.0.1

# Manual gRPC request test
grpcurl -plaintext -d @ localhost:8080 envoy.service.auth.v3.Authorization/Check < request.json
```

An examle request would look like:
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

The bouncer checks for ip addresses in the following order:
1. Configured headers (in order specified in config)
2. Request's RemoteAddr

For X-Forwarded-For headers with multiple IPs the bouncer uses the first (rightmost) non-trusted ip. For this reason, it is recommended to configure the bouncer with trusted proxies.

## Response Codes

- 200 OK: Request allowed
- 403 Forbidden: Request blocked by CrowdSec decision
- 500 Internal Server Error: Bouncer configuration or runtime error

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

The bouncer reports metrics to CrowdSec's dashboard including:
- Total requests processed
- Number of requests bounced

These are opt-in and can be enabled by setting `metrics: true` in the bouncer config.

### Viewing Metrics
From `cscli`
```bash
cscli metrics
```

## Deploying

I have personally only tested this in a kubernetes cluster with Envoy Gateway installed. If there are other environments that aren't working, feel free to open an issue and i'll try to help.

### Kubernetes

The bouncer can be deployed in a Kubernetes cluster alongside Envoy Gateway:
An flat yaml example lives [here](examples/deploy/README.md).

## Helm Installation

Add the Helm repository:
```bash
helm repo add envoy-proxy-bouncer https://kdwils.github.io/envoy-proxy-bouncer
helm repo update
```

Install the chart:
```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --set crowdsec.apiKey=<your-api-key> \
  --set crowdsec.apiURL=<your-crowsdsec-host>:<port>
```

Acknowledgements:
* Helms schema generated with [helm-values-schema-json](https://github.com/losisin/helm-values-schema-json)