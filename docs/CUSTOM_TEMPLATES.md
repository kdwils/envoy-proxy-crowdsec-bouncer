# Custom Templates Guide

This guide explains how to customize the ban and CAPTCHA pages displayed by the Envoy Proxy CrowdSec Bouncer.

## Overview

The bouncer uses Go templates to render HTML pages for:
- **Ban Page**: Shown when a request is blocked by CrowdSec
- **CAPTCHA Page**: Shown when the WAF triggers a CAPTCHA challenge

You can customize these pages to match your brand, add additional information, or modify the layout.

## Go Template Basics

The bouncer uses Go's [`html/template`](https://pkg.go.dev/html/template) package. Here are the key concepts:

### Variables

Access template data using `{{ .FieldName }}`:

```html
<p>Your IP address is {{ .IP }}</p>
```

### Conditionals

Use `if` to conditionally display content:

```html
{{ if .Decision }}
  <p>Reason: {{ .Decision.Scenario }}</p>
{{ end }}
```

```html
{{ if eq .Provider "recaptcha" }}
  <!-- reCAPTCHA specific code -->
{{ else if eq .Provider "turnstile" }}
  <!-- Turnstile specific code -->
{{ end }}
```

## Ban Template

### Available Data Fields

The ban template receives a `DeniedTemplateData` struct with the following fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `.IP` | string | The client's IP address | `"192.168.1.100"` |
| `.Reason` | string | Reason for blocking (deprecated, use `.Decision.Scenario`) | `"manual ban"` |
| `.Action` | string | The action taken | `"ban"` |
| `.Timestamp` | time.Time | When the decision was made | `2025-10-02 14:30:00` |
| `.Request.Method` | string | HTTP method | `"GET"`, `"POST"` |
| `.Request.Path` | string | Request path | `"/api/users"` |
| `.Request.Host` | string | Request host | `"example.com"` |
| `.Request.Scheme` | string | URL scheme | `"http"`, `"https"` |
| `.Request.Protocol` | string | HTTP protocol | `"HTTP/1.1"` |
| `.Request.URL` | string | Full URL | `"https://example.com/api/users"` |
| `.Decision` | *models.Decision | CrowdSec decision object (may be nil) | See below |

### Decision Object Fields

When `.Decision` is not nil, you can access:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `.Decision.Scenario` | string | CrowdSec scenario that triggered the ban | `"crowdsecurity/ssh-bruteforce"` |
| `.Decision.Scope` | string | Scope of the decision | `"Ip"`, `"Range"` |
| `.Decision.Value` | string | Value that matched the scope | `"192.168.1.100"` |
| `.Decision.Type` | string | Type of decision | `"ban"`, `"captcha"` |
| `.Decision.Duration` | string | Duration of the ban | `"4h"` |
| `.Decision.Until` | string | Timestamp when ban expires | `"2025-10-02T18:30:00Z"` |

## CAPTCHA Template

### Available Data Fields

The CAPTCHA template receives a `CaptchaTemplateData` struct with the following fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `.Provider` | string | CAPTCHA provider name | `"recaptcha"`, `"turnstile"` |
| `.SiteKey` | string | Public site key for the CAPTCHA provider | `"6LdX..."` |
| `.CallbackURL` | string | Base URL for CAPTCHA verification endpoint | `"https://example.com/captcha"` |
| `.RedirectURL` | string | URL to redirect after successful verification | `"https://example.com/original-page"` |
| `.SessionID` | string | Session ID for this CAPTCHA challenge | `"abc123..."` |
| `.CSRFToken` | string | CSRF token for form submission | `"xyz789..."` |

The default CAPTCHA template lives 

## Configuration

### Non-Containerized Deployment

#### Configuration File (YAML/JSON)

Create a configuration file (e.g., `config.yaml`):

```yaml
templates:
  # Path to custom ban page template
  deniedTemplatePath: "/path/to/custom-ban.html"
  # Content-Type header for ban page (optional)
  deniedTemplateHeaders: "text/html; charset=utf-8"

  # Path to custom CAPTCHA page template
  captchaTemplatePath: "/path/to/custom-captcha.html"
  # Content-Type header for CAPTCHA page (optional)
  captchaTemplateHeaders: "text/html; charset=utf-8"
```

Start the bouncer with the config file:

```bash
./envoy-proxy-bouncer serve --config config.yaml
```

#### Environment Variables

Set environment variables directly:

```bash
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH="/path/to/custom-ban.html"
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEHEADERS="text/html; charset=utf-8"
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH="/path/to/custom-captcha.html"
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEHEADERS="text/html; charset=utf-8"

./envoy-proxy-bouncer serve
```

### Containerized Deployment (Docker)

#### Volume Mount

Mount your custom templates into the container:

```bash
docker run -d \
  -v /host/path/to/custom-ban.html:/templates/ban.html:ro \
  -v /host/path/to/custom-captcha.html:/templates/captcha.html:ro \
  -e ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH=/templates/ban.html \
  -e ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH=/templates/captcha.html \
  ghcr.io/kdwils/envoy-proxy-bouncer:latest
```

#### Docker Compose

```yaml
version: '3.8'
services:
  envoy-proxy-bouncer:
    image: ghcr.io/kdwils/envoy-proxy-bouncer:latest
    volumes:
      - ./custom-templates/ban.html:/templates/ban.html:ro
      - ./custom-templates/captcha.html:/templates/captcha.html:ro
    environment:
      ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH: /templates/ban.html
      ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH: /templates/captcha.html
```

### Kubernetes/Helm Deployment

#### Method 1: Inline Templates

The Helm chart can automatically create and mount a ConfigMap from inline template content.

```yaml
config:
  bouncer:
    apiKey: your-api-key
    lapiURL: http://crowdsec:8080

templates:
  denied.html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom ban template -->
    </html>
  captcha.html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom CAPTCHA template -->
    </html>
```

Install with custom templates:

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  --create-namespace \
  -f values.yaml
```

The Helm chart will automatically:
- Create a ConfigMap named `<release-name>-envoy-proxy-bouncer-templates`
- Mount it at `/app/template/html/`
- Configure the bouncer to use the custom templates

#### Method 2: External ConfigMap

If you prefer to manage the ConfigMap separately, create it first:

```yaml
# custom-templates-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bouncer-custom-templates
  namespace: envoy-gateway-system
data:
  denied.html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom ban template -->
    </html>
  captcha.html: |
    <!DOCTYPE html>
    <html>
    <!-- Your custom CAPTCHA template -->
    </html>
```

Apply the ConfigMap:

```bash
kubectl apply -f custom-templates-configmap.yaml
```

Configure Helm to use the external ConfigMap:

```yaml
# values.yaml
config:
  templates:
    deniedTemplatePath: /custom-templates/denied.html
    captchaTemplatePath: /custom-templates/captcha.html

volumes:
  - name: custom-templates
    configMap:
      name: bouncer-custom-templates

volumeMounts:
  - name: custom-templates
    mountPath: /custom-templates
    readOnly: true
```

Deploy with Helm:

```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --namespace envoy-gateway-system \
  -f values.yaml
```

## Customizing HTTP Headers

You can customize the `Content-Type` header sent with template responses:

### Default Headers

- Ban page: `text/html; charset=utf-8`
- CAPTCHA page: `text/html; charset=utf-8`

### Custom Headers

```yaml
templates:
  deniedTemplateHeaders: "text/html; charset=utf-8"
  captchaTemplateHeaders: "text/html; charset=utf-8"
```

Or via environment variables:

```bash
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEHEADERS="text/html; charset=utf-8"
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEHEADERS="text/html; charset=utf-8"
```

## Examples

See the default templates for reference:
- Ban template: [template/html/denied.html](../template/html/denied.html)
- CAPTCHA template: [template/html/captcha.html](../template/html/captcha.html)

## Additional Resources

- [Go html/template documentation](https://pkg.go.dev/html/template)
- [Go text/template documentation](https://pkg.go.dev/text/template)
- [CrowdSec Documentation](https://docs.crowdsec.net/)
- [reCAPTCHA Documentation](https://developers.google.com/recaptcha)
- [Cloudflare Turnstile Documentation](https://developers.cloudflare.com/turnstile/)
