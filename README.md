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

The bouncer subscribes to decisions from CrowdSec via the Stream API and processes each request through multiple stages:

1. IP Extraction: Determines the real client IP from forwarded headers, respecting trusted proxy configuration.
2. Bouncer Check: Checks CrowdSec decision cache for IP-based decisions (ban, captcha, allow). Updates to cached decisions are real-time from the Stream API.
3. WAF Analysis: If no blocking decision, forwards request to CrowdSec AppSec for analysis.
4. Decision Application: Applies the final decision:
   - Allow: Request proceeds normally
   - Ban/Deny: Returns 403 Forbidden
   - Captcha: Creates session and redirects to challenge page

When a captcha decision is made:

1. CrowdSec or WAF returns "captcha" action for suspicious request
2. Bouncer creates session and redirects to `/captcha/challenge?session=<id>`
3. User completes CAPTCHA and submits to `/captcha/verify`
4. On success, IP is cached (15 minutes by default) and user redirected to original URL

## Configuration

The bouncer can be configured using:

1. Configuration file (YAML or JSON)
2. Environment variables

### Configuration File

Create a `config.yaml` file:

```yaml
server:
  grpcPort: 8080 # Port for gRPC (Envoy ext_authz)
  httpPort: 8081 # Port for HTTP (CAPTCHA endpoints)
  logLevel: "info"

trustedProxies:
  - 192.168.0.1
  - 2001:db8::1
  - 10.0.0.0/8
  - 100.64.0.0/10

bouncer:
  enabled: true
  metrics: false
  tickerInterval: "10s"                     # How often to fetch decisions from LAPI
  metricsInterval: "10m"                    # How often to report metrics to LAPI
  lapiUrl: "http://crowdsec:8080"
  apiKey: "<lapi-key>"

waf:
  enabled: true
  appSecURL: "http://appsec:7422"
  apiKey: "<lapi-key>"

captcha:
  enabled: true
  provider: "recaptcha" # Options: recaptcha, turnstile
  siteKey: "<your-captcha-site-key>"
  secretKey: "<your-captcha-secret-key>"
  timeout: "10s"                            # Request timeout for CAPTCHA provider verification
  callbackURL: "https://yourdomain.com"     # Base URL for captcha callbacks
                                            # If the bouncer is hosted at https://my-domain.com the callbackURL should be https://my-domain.com
  sessionDuration: "15m"                    # How long captcha verification is valid
  cacheCleanupInterval: "5m"                # How often to clean up expired IP verification cache entries
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
export ENVOY_BOUNCER_BOUNCER_TICKERINTERVAL=10s
export ENVOY_BOUNCER_BOUNCER_METRICSINTERVAL=10m
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
export ENVOY_BOUNCER_CAPTCHA_TIMEOUT=10s
export ENVOY_BOUNCER_CAPTCHA_CALLBACKURL=https://yourdomain.com
export ENVOY_BOUNCER_CAPTCHA_SESSIONDURATION=15m
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
- `captcha.callbackURL`

Note on API keys:

- A key must be generated on your CrowdSec LAPI (with `cscli bouncers add <name>`). You can use this key for both `bouncer.apiKey` and `waf.apiKey`.

### Default Values

```yaml
server:
  grpcPort: 8080 # ext_authz grpc port
  httpPort: 8081 # Only used when captcha is enabled
  logLevel: "info"

trustedProxies:
  - 192.168.0.1
  - 2001:db8::1
  - 10.0.0.0/8
  - 100.64.0.0/10

bouncer:
  enabled: false
  metrics: false
  tickerInterval: "10s"
  metricsInterval: "10m"

waf:
  enabled: false

captcha:
  enabled: false
  timeout: "10s"
  sessionDuration: "15m"
```

### Denied Response Templates

The bouncer serves HTML ban pages by default using an embedded template. You can customize the ban page by setting the `server.banTemplatePath` configuration option to point to your custom template file.

```yaml
server:
  banTemplatePath: "/custom/ban.html"
```

If the specified custom template file is not found or cannot be parsed, the bouncer falls back to the embedded template.

Templates are rendered with Go's `html/template` engine, so variables use the `{{ ... }}` syntax. The following data is available inside the template:

- `{{ .IP }}`, `{{ .Action }}`, `{{ .Reason }}`, `{{ .Timestamp }}`
- Request context: `{{ .Request.Method }}`, `{{ .Request.Path }}`, `{{ .Request.Scheme }}`, `{{ .Request.Host }}`, `{{ .Request.Protocol }}`, `{{ .Request.URL }}`, and `{{ index .Request.Headers "x-forwarded-for" }}`
- CrowdSec decision details when present: `{{ .Decision.Scenario }}`, `{{ .Decision.Origin }}`, `{{ .Decision.Scope }}`, `{{ .Decision.Value }}`, `{{ .Decision.Duration }}`, `{{ .Decision.Until }}`

An example custom template is available at [server/templates/ban.html](server/templates/ban.html).

## CAPTCHA Configuration

The bouncer supports CAPTCHA challenges as an alternative to immediately blocking suspicious IPs. When enabled, the bouncer runs dual servers:

- gRPC server (default port 8080): Handles Envoy ext_authz requests
- HTTP server (default port 8081): Serves CAPTCHA challenge and verification endpoints

### Supported Providers

| Provider             | Configuration Value | Documentation                                                           |
| -------------------- | ------------------- | ----------------------------------------------------------------------- |
| Google reCAPTCHA v2  | `recaptcha`         | [reCAPTCHA Documentation](https://developers.google.com/recaptcha)      |
| Cloudflare Turnstile | `turnstile`         | [Turnstile Documentation](https://developers.cloudflare.com/turnstile/) |

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

### ⚠️ Breaking Changes:

#### SecurityPolicy Configuration 09-21-25

Starting from version 0.2.0, SecurityPolicies are no longer created at the Gateway level due to limitations with redirect flows for CAPTCHA functionality. Individual HTTPRoutes cannot be excluded from gateway-level policies, which breaks the bouncer's redirect mechanism.

SecurityPolicies applied at the gateway level for the bouncer will cause infinite redirects.

Migration Required: SecurityPolicies must now be created at the HTTPRoute level per namespace. See the [SecurityPolicy Configuration](#securitypolicy-configuration) section below for examples.

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
  --set config.bouncer.enabled=true \
  --set config.bouncer.apiKey=<lapi-key> \
  --set config.bouncer.lapiURL=<your-crowdsec-host>:<port> \
  --set config.trustedProxies=<your-trusted-proxies>
```

For cross-namespace SecurityPolicy access, enable the ReferenceGrant:

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --set config.bouncer.enabled=true \
  --set config.bouncer.apiKey=<lapi-key> \
  --set config.bouncer.lapiURL=<your-crowdsec-host>:<port> \
  --set referenceGrant.create=true \
  --set referenceGrant.fromNamespaces="{media,argocd,blog}"
```

### SecurityPolicy Configuration

SecurityPolicies must be created at the HTTPRoute level to ensure proper functionality with CAPTCHA redirects. Create a SecurityPolicy for each namespace that contains HTTPRoutes you want to protect.

#### Creating security policies

1. Namespace: Create the SecurityPolicy in the same namespace as your HTTPRoutes
2. Service Name: Update the service name to match your bouncer deployment
3. Service Namespace: Ensure the namespace matches where the bouncer is deployed
4. Port: Use port 8080 for the gRPC ext_authz service
5. Target Multiple Routes: You can target multiple HTTPRoutes in the same SecurityPolicy

If an a set of HTTPRoutes exist like so:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: plex
  namespace: media
spec:
  hostnames:
    - plex.my-domain.com
  parentRefs:
    - name: my-gateway
      namespace: envoy-gateway-system
  rules:
    - backendRefs:
        - name: plex
          port: 32400
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: overseerr
  namespace: media
spec:
  hostnames:
    - overseerr.my-domain.com
  parentRefs:
    - name: my-gateway
      namespace: envoy-gateway-system
  rules:
    - backendRefs:
        - name: overseerr
          port: 80
```

Then the following security policy could then be created to apply to them:

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: media
  namespace: media
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: overseer
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: plex
  extAuth:
    grpc:
      backendRefs:
        - group: ""
          kind: Service
          name: envoy-proxy-bouncer
          port: 8080
          namespace: envoy-gateway-system
```

#### ReferenceGrant Configuration

When SecurityPolicies are created in different namespaces than the bouncer service, a ReferenceGrant is required to allow cross-namespace access. The Helm chart can automatically create this ReferenceGrant.

Example ReferenceGrant configuration in values.yaml:

```yaml
referenceGrant:
  create: true
  fromNamespaces:
    - media
    - argocd
    - blog
    - vaultwarden
```

This creates a ReferenceGrant that allows SecurityPolicies from the specified namespaces to reference the bouncer service.

#### Migration from Gateway-Level Policies

If you were previously using gateway-level SecurityPolicies:

1. Remove any existing gateway-level SecurityPolicies that target the bouncer
2. Create namespace-specific SecurityPolicies targeting individual HTTPRoutes
3. Ensure CAPTCHA endpoints (`/captcha/*`) are accessible and not protected by the bouncer

Acknowledgements:

- Helm schema generated with [helm-values-schema-json](https://github.com/losisin/helm-values-schema-json)
- Helm docs generated with [helm-docs](https://github.com/norwoodj/helm-docs)
