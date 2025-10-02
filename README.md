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
2. Bouncer Check: Checks CrowdSec decision cache for IP-based decisions (ban, captcha, allow). Updates to cached decisions are received in real-time from the Stream API.
3. WAF Analysis: If there is no blocking decision, the request is forwarded to CrowdSec AppSec for analysis.
4. Decision Application: Applies the final decision:
   - Allow: Request proceeds normally
   - Ban/Deny: Returns 403 Forbidden
   - Captcha: Creates session and redirects to challenge page

![Ban Page](docs/images/ban.jpeg)

When a captcha decision is made:

1. CrowdSec or WAF returns "captcha" action for suspicious request
2. Bouncer creates session and redirects to `/captcha/challenge?session=<id>`
3. User completes CAPTCHA and submits to `/captcha/verify`
4. On success, the IP is cached and the user is redirected to the original URL

## Documentation

- **[Configuration Guide](docs/CONFIGURATION.md)** - Configuration options, environment variables, and examples
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Kubernetes, Helm, Docker, and binary deployment instructions
- **[CAPTCHA Setup](docs/CAPTCHA.md)** - CAPTCHA provider configuration and integration
- **[Custom Templates](docs/CUSTOM_TEMPLATES.md)** - Customize ban and CAPTCHA page templates

## Examples

Kubernetes manifest examples can be found below:
- [Kubernetes Deployment](examples/deploy/README.md)
- [Real Example](https://github.com/kdwils/homelab/blob/main/monitoring/envoy-proxy-bouncer/bouncer.yaml)
- [Custom Templates](examples/deploy/custom-templates.yaml)

## Acknowledgments

* Helm schema generated with [helm-values-schema-json](https://github.com/losisin/helm-values-schema-json)
* Helm docs generated with [helm-docs](https://github.com/norwoodj/helm-docs)
