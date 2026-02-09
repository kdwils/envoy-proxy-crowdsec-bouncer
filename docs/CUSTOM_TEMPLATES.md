# Custom Templates

Customize the ban and CAPTCHA pages displayed by the Envoy Proxy CrowdSec Bouncer.

## Template Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `deniedTemplatePath` | string | `""` | Path to custom ban page template |
| `deniedTemplateHeaders` | string | `"text/html; charset=utf-8"` | Content-Type header for ban page |
| `captchaTemplatePath` | string | `""` | Path to custom CAPTCHA page template |
| `captchaTemplateHeaders` | string | `"text/html; charset=utf-8"` | Content-Type header for CAPTCHA page |

```yaml
templates:
  deniedTemplatePath: "/path/to/custom-ban.html"
  deniedTemplateHeaders: "text/html; charset=utf-8"
  captchaTemplatePath: "/path/to/custom-captcha.html"
  captchaTemplateHeaders: "text/html; charset=utf-8"
```

### Environment Variables

```bash
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH=/path/to/ban.html
export ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEHEADERS="text/html; charset=utf-8"
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH=/path/to/captcha.html
export ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEHEADERS="text/html; charset=utf-8"
```

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
| `.ChallengeToken` | string | Challenge token for this CAPTCHA session | `"abc123..."` |

## Deployment Examples

### Docker

Mount your custom templates into the container:

```bash
docker run -d \
  -v /host/path/to/custom-ban.html:/templates/ban.html:ro \
  -v /host/path/to/custom-captcha.html:/templates/captcha.html:ro \
  -e ENVOY_BOUNCER_TEMPLATES_DENIEDTEMPLATEPATH=/templates/ban.html \
  -e ENVOY_BOUNCER_TEMPLATES_CAPTCHATEMPLATEPATH=/templates/captcha.html \
  ghcr.io/kdwils/envoy-proxy-bouncer:latest
```

### Docker Compose

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

### Kubernetes/Helm

For Helm-specific template configuration and deployment instructions, see the [Helm Chart README](../charts/envoy-proxy-bouncer/README.md).

## Default Templates

See the default templates for reference:
- Ban template: [template/html/denied.html](../template/html/denied.html)
- CAPTCHA template: [template/html/captcha.html](../template/html/captcha.html)

## See Also

- [Configuration Guide](CONFIGURATION.md) - General configuration overview
- [Server Configuration](SERVER.md) - Server ports and log levels
- [CrowdSec Configuration](CROWDSEC.md) - CrowdSec bouncer and WAF setup
- [CAPTCHA Configuration](CAPTCHA.md) - CAPTCHA challenge setup
- [Go html/template documentation](https://pkg.go.dev/html/template)
