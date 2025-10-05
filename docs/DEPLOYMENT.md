# Deployment Guide

This guide covers deployment options for the Envoy Proxy CrowdSec Bouncer.

## Overview

The bouncer is primarily tested in Kubernetes environments with Envoy Gateway. For other environments, please open an issue if you encounter problems.

## Table of Contents

- [Binary Installation](#binary-installation)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Helm](#helm)
- [Envoy Gateway Integration](#envoy-gateway-integration)

## Binary Installation

### Install from Go

```bash
go install github.com/kdwils/envoy-proxy-bouncer@latest
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

### Using Flat YAML

See [examples/deploy/README.md](../examples/deploy/README.md) for a flat YAML deployment example.

You can also reference this [homelab manifest](https://github.com/kdwils/homelab/blob/main/monitoring/envoy-proxy-bouncer/bouncer.yaml) for a complete example.

### Manual Deployment

Create a deployment manifest:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: envoy-gateway-system
---
apiVersion: v1
kind: Secret
metadata:
  name: bouncer-secrets
  namespace: envoy-gateway-system
type: Opaque
stringData:
  api-key: "your-crowdsec-api-key"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envoy-proxy-bouncer
  namespace: envoy-gateway-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: envoy-proxy-bouncer
  template:
    metadata:
      labels:
        app: envoy-proxy-bouncer
    spec:
      containers:
      - name: bouncer
        image: ghcr.io/kdwils/envoy-proxy-bouncer:latest
        ports:
        - containerPort: 8080
          name: grpc
          protocol: TCP
        - containerPort: 8081
          name: http
          protocol: TCP
        env:
        - name: ENVOY_BOUNCER_BOUNCER_APIKEY
          valueFrom:
            secretKeyRef:
              name: bouncer-secrets
              key: api-key
        - name: ENVOY_BOUNCER_BOUNCER_LAPIURL
          value: "http://crowdsec.monitoring:8080"
        - name: ENVOY_BOUNCER_SERVER_LOGLEVEL
          value: "info"
---
apiVersion: v1
kind: Service
metadata:
  name: envoy-proxy-bouncer
  namespace: envoy-gateway-system
spec:
  selector:
    app: envoy-proxy-bouncer
  ports:
  - name: grpc
    port: 8080
    targetPort: 8080
    protocol: TCP
  - name: http
    port: 8081
    targetPort: 8081
    protocol: TCP
```

Apply the manifest:

```bash
kubectl apply -f bouncer.yaml
```

## Helm

### Add Repository

```bash
helm repo add envoy-proxy-bouncer https://kdwils.github.io/envoy-proxy-crowdsec-bouncer
helm repo update
```

### Basic Installation

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  --create-namespace \
  --set config.bouncer.apiKey=<lapi-key> \
  --set config.bouncer.lapiURL=http://crowdsec.monitoring:8080
```

### Installation with Values File

Create a `values.yaml`:

```yaml
replicaCount: 2

config:
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
    apiKeySecretRef:
      name: crowdsec-secrets
      key: bouncer-key

  waf:
    enabled: true
    appSecURL: "http://crowdsec-appsec.monitoring.svc:7422"
    apiKeySecretRef:
      name: crowdsec-secrets
      key: appsec-key

  captcha:
    enabled: true
    provider: "turnstile"
    siteKey: "0x4AAAAAAAA..."
    secretKeySecretRef:
      name: captcha-secrets
      key: secret-key
    callbackURL: "https://auth.example.com"

resources:
  limits:
    cpu: 200m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
```

Install with values:

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  --create-namespace \
  -f values.yaml
```

### Upgrade

```bash
helm upgrade bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  -f values.yaml
```

### Uninstall

```bash
helm uninstall bouncer --namespace envoy-gateway-system
```

## Envoy Gateway Integration

### Overview

The bouncer integrates with Envoy Gateway using SecurityPolicies that reference the ext_authz filter.

**Important**: SecurityPolicies must be created at the HTTPRoute level, not at the Gateway level, to ensure proper CAPTCHA redirect functionality.

### SecurityPolicy Configuration

#### ⚠️ Breaking Change (v0.2.0+)

Gateway-level SecurityPolicies are no longer supported due to CAPTCHA redirect limitations. Individual HTTPRoutes cannot be excluded from gateway-level policies, which breaks the bouncer's redirect mechanism.

**Migration Required**: If you were using gateway-level SecurityPolicies, you must migrate to HTTPRoute-level policies.

#### Creating HTTPRoute-Level SecurityPolicies

SecurityPolicies should be created in the same namespace as your HTTPRoutes:

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

#### Example: Multiple Namespaces

If you have HTTPRoutes across multiple namespaces, create a SecurityPolicy in each:

**Namespace: media**
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

**Namespace: blog**
```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: blog-security
  namespace: blog
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: blog
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

The Helm chart can automatically create ReferenceGrants:

```yaml
# values.yaml
referenceGrant:
  create: true
  fromNamespaces:
    - media
    - blog
    - argocd
    - vaultwarden
```

Install with ReferenceGrant:

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  --set config.bouncer.apiKey=<lapi-key> \
  --set config.bouncer.lapiURL=http://crowdsec:8080 \
  --set referenceGrant.create=true \
  --set referenceGrant.fromNamespaces="{media,blog,argocd}"
```

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

### CAPTCHA Endpoint Configuration

When CAPTCHA is enabled, ensure the CAPTCHA endpoints are accessible and **not** protected by the bouncer:

The bouncer automatically handles CAPTCHA endpoints (`/captcha/challenge` and `/captcha/verify`), but you must ensure:

1. The HTTP port (8081) is accessible
2. CAPTCHA endpoints are not included in SecurityPolicy target HTTPRoutes
3. The `callbackURL` matches the public-facing hostname

Example HTTPRoute for CAPTCHA access:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: bouncer-captcha
  namespace: envoy-gateway-system
spec:
  hostnames:
    - auth.example.com
  parentRefs:
    - name: my-gateway
      namespace: envoy-gateway-system
  rules:
    - matches:
      - path:
          type: PathPrefix
          value: /captcha/
      backendRefs:
        - name: envoy-proxy-bouncer
          port: 8081
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

## Troubleshooting

### Bouncer Not Starting

**Check logs:**
```bash
kubectl logs -n envoy-gateway-system deployment/envoy-proxy-bouncer
```

**Common issues:**
- Missing required configuration (API key, LAPI URL)
- Invalid configuration format
- Cannot connect to CrowdSec LAPI
- Template files not found or invalid

### Requests Not Being Blocked

**Verify SecurityPolicy is applied:**
```bash
kubectl get securitypolicy -A
kubectl describe securitypolicy <name> -n <namespace>
```

**Check bouncer logs for decision processing:**
```bash
kubectl logs -n envoy-gateway-system deployment/envoy-proxy-bouncer | grep -i decision
```

**Verify CrowdSec has decisions:**
```bash
cscli decisions list
```

### CAPTCHA Not Working

**Check HTTP port is accessible:**
```bash
kubectl port-forward -n envoy-gateway-system svc/envoy-proxy-bouncer 8081:8081
curl http://localhost:8081/captcha/challenge?session=test
```

**Verify CAPTCHA configuration:**
```bash
kubectl get configmap -n envoy-gateway-system
kubectl describe configmap <bouncer-config> -n envoy-gateway-system
```

**Check browser console for errors** when CAPTCHA page loads.

### Cross-Namespace Access Denied

**Verify ReferenceGrant exists:**
```bash
kubectl get referencegrant -n envoy-gateway-system
kubectl describe referencegrant bouncer-access -n envoy-gateway-system
```

**Ensure SecurityPolicy namespace is listed in ReferenceGrant.**

## Performance Tuning

### Horizontal Pod Autoscaling

Enable autoscaling for high-traffic environments:

```yaml
# values.yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### Resource Requests and Limits

Adjust based on your traffic:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

### CrowdSec Connection Tuning

Adjust ticker intervals based on decision update frequency:

```yaml
config:
  bouncer:
    tickerInterval: "5s"  # More frequent updates
    metricsInterval: "5m"  # More frequent metrics reporting
```

## Security Considerations

1. **Store API keys in Secrets**, not ConfigMaps or environment variables directly
2. **Use RBAC** to restrict access to the bouncer namespace
3. **Enable Pod Security Standards** for the bouncer deployment
4. **Configure trusted proxies** carefully to prevent IP spoofing
5. **Use TLS** for CrowdSec LAPI connections in production
6. **Regularly update** the bouncer image to get security patches

## See Also

- [Configuration Guide](CONFIGURATION.md)
- [CAPTCHA Configuration](CAPTCHA.md)
- [Custom Templates](CUSTOM_TEMPLATES.md)
- [Envoy Gateway Documentation](https://gateway.envoyproxy.io/)
- [CrowdSec Documentation](https://docs.crowdsec.net/)
