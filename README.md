# Envoy Gateway Bouncer

A CrowdSec bouncer implementation for Envoy Gateway's external authorization (ext_authz) system. This bouncer validates incoming requests against CrowdSec decisions and blocks malicious traffic.

## Installation

```bash
go install github.com/kdwils/envoy-gateway-bouncer@latest
```

## Configuration

The bouncer requires a configuration file (`config.yaml`):

```yaml
server:
  port: 8080                               # optional (defaults to 8080)

bouncer:
  apiKey: "your-crowdsec-bouncer-api-key"  # required
  apiURL: "http://crowdsec:8080"           # required
  headers:                                 # optional (defaults to X-Forwarded-For, X-Real-IP, X-Client-IP, True-Client-IP)
    - "X-Forwarded-For"
    - "X-Real-IP"
    - "True-Client-IP"
```

### Getting a Bouncer API Key

1. Generate an API key from your CrowdSec instance:
```bash
sudo cscli bouncers add envoy-bouncer
```

2. Save the generated API key in your config.yaml

## Usage

### Starting the Bouncer

```bash
envoy-gateway-bouncer serve
```

### Testing IP Decisions

```bash
# Test if an IP is banned
envoy-gateway-bouncer bounce -i 192.168.1.1

# Manual HTTP request test
curl -v -H "X-Forwarded-For: 192.168.1.1" http://localhost:8080/check
```

## Docker

Build and run with Docker:

```bash
# Build
docker build -t envoy-gateway-bouncer .

# Run
docker run -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  envoy-gateway-bouncer
```

## Headers

The bouncer checks for IP addresses in the following order:
1. Configured headers (in order specified in config)
2. Request's RemoteAddr

For X-Forwarded-For headers with multiple IPs, the bouncer uses the first (leftmost) IP.

## Response Codes

- 200 OK: Request allowed
- 403 Forbidden: Request blocked by CrowdSec decision
- 500 Internal Server Error: Bouncer configuration or runtime error

## Development

```bash
# Run tests
go test ./...

# Build from source
go build -o envoy-gateway-bouncer
```

### nix

starting a shell with the project dependencies:
```bash
nix develop .
```

## Envoy Gateway Configuration

Configure Envoy Gateway to use the bouncer for external authorization:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: example
spec:
  gatewayClassName: envoy-gateway
  listeners:
  - name: http
    port: 80
    protocol: HTTP
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: ext-authz
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: example
  extAuth:
    extensionRef:
      name: envoy-bouncer
      namespace: default
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: ExtensionService
metadata:
  name: envoy-bouncer
spec:
  services:
  - name: envoy-bouncer
    port: 8080
```
