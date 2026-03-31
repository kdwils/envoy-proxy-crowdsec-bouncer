# Deployment Guide

## Table of Contents

- [Binary Installation](#binary-installation)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Helm](#helm)
- [Envoy Gateway Integration](#envoy-gateway-integration)

## Binary Installation

### Install from Go

```bash
go install github.com/kdwils/envoy-proxy-bouncer@v0.4.0
```

### Download Pre-built Binary

Check the [releases page](https://github.com/kdwils/envoy-proxy-crowdsec-bouncer/releases) for pre-built binaries.

### Running the Binary

```bash
# Start the bouncer
envoy-proxy-bouncer serve --config config.yaml

# Check if an IP should be bounced
envoy-proxy-bouncer bounce -i 192.168.1.1,10.0.0.1

# Show version
envoy-proxy-bouncer version
```

## Docker

### Docker Run

```bash
docker run -d \
  --name envoy-proxy-bouncer \
  -p 8080:8080 \
  -p 8081:8081 \
  -e ENVOY_BOUNCER_BOUNCER_APIKEY=your-api-key \
  -e ENVOY_BOUNCER_BOUNCER_LAPIURL=http://crowdsec:8080 \
  ghcr.io/kdwils/envoy-proxy-bouncer:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  envoy-proxy-bouncer:
    image: ghcr.io/kdwils/envoy-proxy-bouncer:latest
    container_name: envoy-proxy-bouncer
    ports:
      - "8080:8080"  # gRPC port
      - "8081:8081"  # HTTP port (CAPTCHA)
    environment:
      ENVOY_BOUNCER_BOUNCER_APIKEY: your-api-key
      ENVOY_BOUNCER_BOUNCER_LAPIURL: http://crowdsec:8080
      ENVOY_BOUNCER_SERVER_LOGLEVEL: info
    restart: unless-stopped
    networks:
      - crowdsec

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      COLLECTIONS: "crowdsecurity/linux crowdsecurity/nginx"
    volumes:
      - ./crowdsec/config:/etc/crowdsec
      - ./crowdsec/data:/var/lib/crowdsec/data
    networks:
      - crowdsec

networks:
  crowdsec:
```

## Kubernetes

### Manifest File

See [examples/deploy/README.md](examples/deploy/README.md) for a flat YAML deployment example.

You can also reference this [homelab manifest](https://github.com/kdwils/homelab/blob/main/monitoring/envoy-proxy-bouncer/bouncer.yaml) for a complete example.

## Helm

The chart is available via OCI at `oci://ghcr.io/kdwils/charts/envoy-proxy-bouncer`.

### Basic Installation

```bash
helm install bouncer oci://ghcr.io/kdwils/charts/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  --create-namespace \
  --set config.bouncer.apiKey=<lapi-key> \
  --set config.bouncer.lapiURL=http://crowdsec.monitoring:8080
```

### Installation with Values File

For complete chart configuration options and values, see the [Helm Chart README](../charts/envoy-proxy-bouncer/README.md).

Install with values:

```bash
helm install bouncer oci://ghcr.io/kdwils/charts/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  --create-namespace \
  -f values.yaml
```

### Upgrade

```bash
helm upgrade bouncer oci://ghcr.io/kdwils/charts/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  -f values.yaml
```

### Uninstall

```bash
helm uninstall bouncer --namespace envoy-gateway-system
```

## Envoy Gateway Integration

The bouncer integrates with Envoy Gateway using SecurityPolicies that reference the ext_authz filter. SecurityPolicies must be created at the HTTPRoute level, not at the Gateway level, and in the same namespace as your HTTPRoutes:

### SecurityPolicy Configuration

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: media-security
  namespace: media
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: plex
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: overseerr
  extAuth:
    grpc:
      backendRefs:
        - group: ""
          kind: Service
          name: envoy-proxy-bouncer
          port: 8080
          namespace: envoy-gateway-system
```

### ReferenceGrant Configuration

When SecurityPolicies reference services in different namespaces, a ReferenceGrant is required.

#### Using Helm

The Helm chart can automatically create ReferenceGrants. For configuration details, see the [Helm Chart README](../charts/envoy-proxy-bouncer/README.md).

#### Manual ReferenceGrant

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: bouncer-access
  namespace: envoy-gateway-system
spec:
  from:
  - group: gateway.envoyproxy.io
    kind: SecurityPolicy
    namespace: media
  - group: gateway.envoyproxy.io
    kind: SecurityPolicy
    namespace: blog
  - group: gateway.envoyproxy.io
    kind: SecurityPolicy
    namespace: argocd
  to:
  - group: ""
    kind: Service
    name: envoy-proxy-bouncer
```

## Health Checks

The bouncer does not currently expose health check endpoints. Monitor the service using:

### Kubernetes Readiness

Check pod status:

```bash
kubectl get pods -n envoy-gateway-system -l app=envoy-proxy-bouncer
```

Check logs:

```bash
kubectl logs -n envoy-gateway-system -l app=envoy-proxy-bouncer -f
```

### gRPC Health Check

Use `grpcurl` to test the ext_authz endpoint:

```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Test connection
grpcurl -plaintext localhost:8080 list
```

## See Also

- [Configuration Reference](CONFIGURATION.md)
- [CrowdSec Configuration](CROWDSEC.md) - CrowdSec bouncer and WAF setup
- [CAPTCHA Configuration](CAPTCHA.md) - CAPTCHA challenge setup
- [Webhook Configuration](WEBHOOKS.md) - Webhook event notifications
- [Custom Templates](CUSTOM_TEMPLATES.md) - Template customization
- [Envoy Gateway Documentation](https://gateway.envoyproxy.io/)
- [CrowdSec Documentation](https://docs.crowdsec.net/)
