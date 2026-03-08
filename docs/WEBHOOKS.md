# Webhook Configuration

Send HTTP POST requests when security events happen. Delivery is async - won't block request processing.

For configuration options see the [Configuration Reference](CONFIGURATION.md#webhooks).

## Events

| Event | Description |
|-------|-------------|
| `request_allowed` | Request passed all checks |
| `request_blocked` | CrowdSec ban/deny or WAF blocked it |
| `captcha_required` | CAPTCHA challenge issued |
| `captcha_verified` | User completed CAPTCHA |

## Payload

```json
{
  "type": "request_blocked",
  "timestamp": "2025-02-08T10:30:00Z",
  "ip": "203.0.113.42",
  "action": "ban",
  "reason": "manual 'ban' from 'localhost'",
  "request": {
    "method": "GET",
    "url": "https://example.com/admin",
    "host": "example.com",
    "scheme": "https",
    "path": "/admin",
    "user_agent": "Mozilla/5.0"
  }
}
```

`request` object is optional, may be null.

## Signing

Set `signingKey` to sign payloads with HMAC-SHA256. Signature goes in `X-Signature-SHA256` header as hex. See [Signing Key Generation](SIGNING_KEYS.md).

## Delivery

POST with `Content-Type: application/json`. Failures are logged but not retried. Events buffer in a channel - if full, new events get dropped.

Subscriptions must be configured via YAML file - they can't be represented as environment variables.

## See Also

- [Configuration Reference](CONFIGURATION.md)
- [CrowdSec Integration](CROWDSEC.md)
- [CAPTCHA Integration](CAPTCHA.md)
- [Deployment Guide](DEPLOYMENT.md)
