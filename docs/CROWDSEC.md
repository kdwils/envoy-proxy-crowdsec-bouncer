# CrowdSec Integration

How the bouncer integrates with CrowdSec. For configuration options see the [Configuration Reference](CONFIGURATION.md).

## Table of Contents

- [Bouncer](#bouncer)
- [WAF / AppSec](#waf--appsec)
- [Trusted Proxies](#trusted-proxies)
- [Metrics](#metrics)
- [Authentication](#authentication)

## Bouncer

The bouncer uses CrowdSec's stream mode. It maintains a local in-memory cache of decisions synced from the local crowdsec instance.
### Generating an API Key

```bash
cscli bouncers add envoy-proxy-bouncer
```

## WAF / AppSec

When WAF is enabled, requests that pass the bouncer IP check are forwarded to the CrowdSec AppSec component for rule-based inspection

- **allow** — request proceeds
- **ban** — request is denied immediately
- **captcha** — a CAPTCHA challenge is issued (requires CAPTCHA to be enabled)

## Trusted Proxies

Before any decision lookup, the bouncer must determine the real client IP. When requests pass through proxies (load balancers, ingress controllers), the source IP seen by the bouncer is the proxy, not the client.

Trusted proxies tell the bouncer which intermediate IPs to skip when walking the `X-Forwarded-For` chain. The first IP in the chain that does not belong to a trusted proxy is used as the client IP. If no `X-Forwarded-For` header is present, `X-Real-IP` is used as a fallback.

## Metrics

When metrics are enabled, the bouncer periodically reports request counts (allowed, blocked, per-scenario) to the LAPI. This feeds CrowdSec's dashboard and `cscli metrics` output.

```bash
cscli metrics
```

Metrics delivery is best-effort — a failed report is logged and skipped, not retried.

## Authentication

### API Key

The standard method. Generate a key with `cscli bouncers add` and set it as `bouncer.apiKey`. The key is sent as a header on every LAPI request.

### mTLS

For environments where secret distribution is undesirable, the bouncer supports mutual TLS authentication with the LAPI. The bouncer presents a client certificate instead of an API key. API key and mTLS are mutually exclusive — enabling TLS disables API key auth.

The CA certificate (`tls.caPath`) is optional. When omitted, the system trust store is used to verify the LAPI's server certificate.

## See Also

- [Configuration Reference](CONFIGURATION.md)
- [CAPTCHA Integration](CAPTCHA.md)
- [Webhook Configuration](WEBHOOKS.md)
- [Deployment Guide](DEPLOYMENT.md)
- [CrowdSec Documentation](https://docs.crowdsec.net/)
