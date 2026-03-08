# Custom Templates

Customize the ban and CAPTCHA pages displayed by the bouncer. For configuration options see the [Configuration Reference](CONFIGURATION.md#templates).

Default templates:
- Ban: [template/html/denied.html](../template/html/denied.html)
- CAPTCHA: [template/html/captcha.html](../template/html/captcha.html)

## Go Template Basics

Templates use Go's [`html/template`](https://pkg.go.dev/html/template) package.

Access data fields with `{{ .FieldName }}`:

```html
<p>Your IP address is {{ .IP }}</p>
```

Conditionals:

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

Available fields (`DeniedTemplateData`):

| Field | Type | Example |
|-------|------|---------|
| `.IP` | string | `"192.168.1.100"` |
| `.Action` | string | `"ban"` |
| `.Reason` | string | `"manual ban"` (deprecated, use `.Decision.Scenario`) |
| `.Timestamp` | time.Time | `2025-10-02 14:30:00` |
| `.Request.Method` | string | `"GET"` |
| `.Request.Path` | string | `"/api/users"` |
| `.Request.Host` | string | `"example.com"` |
| `.Request.Scheme` | string | `"https"` |
| `.Request.Protocol` | string | `"HTTP/1.1"` |
| `.Request.URL` | string | `"https://example.com/api/users"` |
| `.Decision` | *models.Decision | may be nil |

When `.Decision` is not nil:

| Field | Type | Example |
|-------|------|---------|
| `.Decision.Scenario` | string | `"crowdsecurity/ssh-bruteforce"` |
| `.Decision.Scope` | string | `"Ip"` |
| `.Decision.Value` | string | `"192.168.1.100"` |
| `.Decision.Type` | string | `"ban"` |
| `.Decision.Duration` | string | `"4h"` |
| `.Decision.Until` | string | `"2025-10-02T18:30:00Z"` |

## CAPTCHA Template

Available fields (`CaptchaTemplateData`):

| Field | Type | Example |
|-------|------|---------|
| `.Provider` | string | `"recaptcha"` |
| `.SiteKey` | string | `"6LdX..."` |
| `.CallbackURL` | string | `"https://example.com/captcha"` |
| `.RedirectURL` | string | `"https://example.com/original-page"` |
| `.ChallengeToken` | string | `"abc123..."` |

The form must POST to `{{.CallbackURL}}/verify` with a hidden `session` field containing `{{.ChallengeToken}}`.

## See Also

- [Configuration Reference](CONFIGURATION.md)
- [CAPTCHA Integration](CAPTCHA.md)
- [Signing Key Generation](SIGNING_KEYS.md)
