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

### Loops

Iterate over arrays or slices:

```html
{{ range .Items }}
  <li>{{ . }}</li>
{{ end }}
```

### HTML Safety

Go templates automatically escape HTML to prevent XSS attacks. All user-provided data (like IP addresses) is safe to display.

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

### Example Ban Template

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Access Blocked</title>
  <style>
    body {
      font-family: sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 0;
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
    }
    main {
      max-width: 560px;
      padding: 2rem;
      background: rgba(15, 23, 42, 0.85);
      border-radius: 12px;
      box-shadow: 0 25px 50px -12px rgba(15, 23, 42, 0.75);
    }
    h1 { margin-top: 0; font-size: 2rem; }
    .details {
      margin: 1.5rem 0;
      padding: 1rem;
      background: rgba(15, 23, 42, 0.6);
      border-radius: 8px;
    }
    dt { font-weight: bold; }
    dd { margin: 0 0 0.75rem 0; }
    footer { font-size: 0.85rem; color: #94a3b8; margin-top: 1.5rem; }
  </style>
</head>
<body>
  <main>
    <h1>Access Blocked</h1>
    <p>Your request was stopped by CrowdSec to protect this service.</p>
    <section class="details">
      <dl>
        <dt>IP Address</dt>
        <dd>{{ .IP }}</dd>
        {{ if .Decision }}
        <dt>Reason</dt>
        <dd>{{ .Decision.Scenario }}</dd>
        <dt>Decision Scope</dt>
        <dd>{{ .Decision.Scope }} &mdash; {{ .Decision.Value }}</dd>
        {{ if .Decision.Until }}
        <dt>Decision Expires</dt>
        <dd>{{ .Decision.Until }}</dd>
        {{ end }}
        {{ end }}
        {{ if .Request.Path }}
        <dt>Request Path</dt>
        <dd>{{ .Request.Path }}</dd>
        {{ end }}
      </dl>
    </section>
    <p>If you believe this is a mistake, contact the site administrator and include the timestamp below.</p>
    <footer>Reference: {{ .Timestamp }}</footer>
  </main>
</body>
</html>
```

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

### Important Requirements

Your CAPTCHA template **must** include:

1. **Form submission to verification endpoint**: `{{.CallbackURL}}/verify`
2. **Hidden session field**: `<input type="hidden" name="session" value="{{.SessionID}}" />`
3. **Hidden CSRF token field**: `<input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />`
4. **Provider-specific JavaScript**: Load the correct CAPTCHA provider library
5. **CAPTCHA widget rendering**: Render the CAPTCHA widget with your site key

### Example CAPTCHA Template

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        .submit-btn {
            background-color: #f48120;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 1rem;
            width: 100%;
        }
        .submit-btn:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Verification</h1>
        <p>Please complete the security verification to continue.</p>

        <form method="POST" action="{{.CallbackURL}}/verify">
            <div id="captcha-container"></div>
            <input type="hidden" name="session" value="{{.SessionID}}" />
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />
            <button type="submit" id="submit-btn" class="submit-btn" disabled>Verify</button>
        </form>
    </div>

    {{if eq .Provider "recaptcha"}}
    <script src="https://www.google.com/recaptcha/api.js" defer></script>
    <script>
        function onCaptchaSuccess(token) {
            document.getElementById('submit-btn').disabled = false;
        }
        window.onload = function () {
            grecaptcha.render('captcha-container', {
                'sitekey': '{{.SiteKey}}',
                'callback': onCaptchaSuccess
            });
        };
    </script>
    {{else if eq .Provider "turnstile"}}
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
    <script>
        function onTurnstileSuccess(token) {
            document.getElementById('submit-btn').disabled = false;
        }
        window.onload = function () {
            turnstile.render('#captcha-container', {
                sitekey: '{{.SiteKey}}',
                callback: onTurnstileSuccess
            });
        };
    </script>
    {{end}}
</body>
</html>
```

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

#### Method 1: Inline Templates (Recommended)

The Helm chart can automatically create and mount a ConfigMap from inline template content. This is the simplest method:

```yaml
# values.yaml
config:
  bouncer:
    apiKey: your-api-key
    lapiURL: http://crowdsec:8080

templates:
  deniedTemplateContent: |
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Custom Ban Page</title>
      <style>
        body { font-family: Arial; background: #f5f5f5; }
        .container { max-width: 600px; margin: 50px auto; padding: 2rem; background: white; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Access Blocked</h1>
        <p>Your IP: {{ .IP }}</p>
        {{ if .Decision }}
        <p>Reason: {{ .Decision.Scenario }}</p>
        {{ end }}
        <p>Timestamp: {{ .Timestamp }}</p>
      </div>
    </body>
    </html>

  captchaTemplateContent: |
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Security Verification</title>
    </head>
    <body>
      <h1>Security Verification</h1>
      <form method="POST" action="{{.CallbackURL}}/verify">
        <div id="captcha-container"></div>
        <input type="hidden" name="session" value="{{.SessionID}}" />
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}" />
        <button type="submit">Verify</button>
      </form>
      {{if eq .Provider "recaptcha"}}
      <script src="https://www.google.com/recaptcha/api.js" defer></script>
      <script>
        grecaptcha.render('captcha-container', {'sitekey': '{{.SiteKey}}'});
      </script>
      {{else if eq .Provider "turnstile"}}
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
      <script>
        turnstile.render('#captcha-container', {sitekey: '{{.SiteKey}}'});
      </script>
      {{end}}
    </body>
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

## Testing Your Templates

### Local Testing

1. Create your custom template files
2. Configure the bouncer to use them
3. Start the bouncer locally
4. Trigger a ban or CAPTCHA challenge
5. View the rendered page in your browser

### Template Validation

Ensure your template is valid Go HTML:

```bash
# Install Go if not already installed
go install golang.org/x/tools/cmd/present@latest

# Basic syntax check (create a test file)
cat > test_template.go <<EOF
package main
import "html/template"
func main() {
    template.Must(template.ParseFiles("your-template.html"))
}
EOF

go run test_template.go
```

## Troubleshooting

### Template Not Loading

**Symptoms**: Default template still displays

**Solutions**:
- Verify file path is correct and accessible by the bouncer process
- Check file permissions (readable by the user running the bouncer)
- Check logs for template loading errors
- Ensure environment variables or config file is correctly set

### Template Parse Errors

**Symptoms**: Error logs about template parsing

**Solutions**:
- Validate Go template syntax
- Ensure all `{{` have matching `}}`
- Check for typos in field names (case-sensitive)
- Verify conditionals have proper `{{ end }}` tags

### CAPTCHA Not Working

**Symptoms**: CAPTCHA challenge doesn't display or verify

**Solutions**:
- Ensure form posts to `{{.CallbackURL}}/verify`
- Include hidden `session` field with `{{.SessionID}}`
- Include hidden `csrf_token` field with `{{.CSRFToken}}`
- Load correct provider JavaScript library
- Verify site key matches your CAPTCHA provider configuration
- Check browser console for JavaScript errors

### Missing Data

**Symptoms**: Template fields show as empty

**Solutions**:
- Check if field is available (e.g., `.Decision` may be nil)
- Use conditionals: `{{ if .Decision }}...{{ end }}`
- Review available fields in this documentation
- Check bouncer logs for data population issues

## Best Practices

1. **Keep templates simple**: Complex logic should be in the application, not templates
2. **Use conditionals**: Always check if optional fields exist before using them
3. **Test thoroughly**: Test with various ban scenarios and CAPTCHA providers
4. **Maintain accessibility**: Ensure your custom pages are accessible (WCAG guidelines)
5. **Mobile responsive**: Test on mobile devices and use responsive CSS
6. **Security**: Never include sensitive information in templates
7. **Version control**: Keep your custom templates in version control
8. **Documentation**: Document any custom fields or special requirements

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
