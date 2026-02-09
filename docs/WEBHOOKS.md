# Webhooks

Send HTTP POST requests when security events happen. Delivery is async - won't block request processing.

Configuration requires a YAML file since subscriptions are complex structures that can't be represented as environment variables.

```yaml
webhook:
  subscriptions:
    - url: "https://example.com/security-events"
      events:
        - request_blocked
        - captcha_required
    - url: "https://siem.example.com/ingest"
      events:
        - request_blocked
  signingKey: "your-hmac-secret"
  timeout: "5s"
  bufferSize: 100
```

```bash
envoy-proxy-bouncer serve --config config.yaml
```

## Events

`request_allowed` - request passed all checks

`request_blocked` - CrowdSec ban/deny or WAF blocked it

`captcha_required` - captcha challenge issued

`captcha_verified` - user completed captcha

## Payload

```json
{
  "type": "request_blocked",
  "timestamp": "2024-01-15T10:30:00Z",
  "ip": "203.0.113.42",
  "action": "ban",
  "reason": "crowdsecurity/ssh-bf",
  "request": {
    "method": "GET",
    "url": "https://example.com/admin",
    "host": "example.com",
    "scheme": "https",
    "path": "/admin",
    "user_agent": "curl/7.68.0"
  }
}
```

`request` object is optional, may be null.

## Signing

Set `signingKey` to sign payloads with HMAC-SHA256. Signature goes in `X-Signature-SHA256` header as hex.

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## Delivery

POST with `Content-Type: application/json`. Timeout defaults to 5s. Failures are logged but not retried. Events buffer in a channel (default 100) - if full, new events get dropped.

| Option | Type | Default |
|--------|------|---------|
| `subscriptions[].url` | string | required |
| `subscriptions[].events` | []string | required |
| `signingKey` | string | `""` |
| `timeout` | duration | `"5s"` |
| `bufferSize` | int | `100` |
