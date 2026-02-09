# Webhook Configuration

Send HTTP POST requests when security events happen. Delivery is async - won't block request processing.

## Configuration Options

| Option | Type | Default | Required | Description |
|--------|------|---------|----------|-------------|
| `subscriptions[].url` | string | - | Yes | HTTP endpoint to receive webhook events |
| `subscriptions[].events` | []string | - | Yes | List of events to subscribe to |
| `signingKey` | string | `""` | No | HMAC-SHA256 signing key for payload verification. See [Signing Key Generation](SIGNING_KEYS.md) |
| `timeout` | duration | `"5s"` | No | HTTP timeout for webhook delivery |
| `bufferSize` | int | `100` | No | Event channel buffer size |

## YAML Configuration

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

Set `signingKey` to sign payloads with HMAC-SHA256. Signature goes in `X-Signature-SHA256` header as hex. See [Signing Key Generation](SIGNING_KEYS.md) for key generation instructions.

## Delivery

POST with `Content-Type: application/json`. Timeout defaults to 5s. Failures are logged but not retried. Events buffer in a channel (default 100) - if full, new events get dropped.

## Environment Variables

```bash
export ENVOY_BOUNCER_WEBHOOK_SIGNINGKEY=your-hmac-signing-key
export ENVOY_BOUNCER_WEBHOOK_TIMEOUT=5s
export ENVOY_BOUNCER_WEBHOOK_BUFFERSIZE=100
```

Webhook subscriptions must be configured via YAML file.

## Kubernetes/Helm

For Helm-specific configuration, see the [Helm Chart README](../charts/envoy-proxy-bouncer/README.md).

## See Also

- [Configuration Guide](CONFIGURATION.md)
- [CrowdSec Configuration](CROWDSEC.md)
- [CAPTCHA Configuration](CAPTCHA.md)
- [Deployment Guide](DEPLOYMENT.md)
