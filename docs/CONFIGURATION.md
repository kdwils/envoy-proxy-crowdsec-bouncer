# Configuration Guide

This guide covers configuration methods for the Envoy Proxy CrowdSec Bouncer.

## Configuration Methods

The bouncer supports multiple configuration methods with the following precedence (last wins):

1. Default values
2. Configuration file (YAML or JSON)
3. Environment variables

## Configuration File

See [config.yaml](../config.yaml) for a complete configuration example.

Start with config file:

```bash
envoy-proxy-bouncer serve --config config.yaml
```

## Component Configuration

For detailed configuration of specific components, see the dedicated documentation:

- **[Server Configuration](SERVER.md)** - Server ports and log levels
- **[CrowdSec Configuration](CROWDSEC.md)** - Bouncer, WAF, metrics, and trusted proxies
- **[CAPTCHA Configuration](CAPTCHA.md)** - CAPTCHA challenge setup and providers
- **[Webhook Configuration](WEBHOOKS.md)** - Webhook event notifications
- **[Custom Templates](CUSTOM_TEMPLATES.md)** - Template customization

## See Also

- [config.yaml](../config.yaml) - Complete configuration example
- [Deployment Guide](DEPLOYMENT.md) - Deployment instructions
