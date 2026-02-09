# Server Configuration

Server settings for the Envoy Proxy CrowdSec Bouncer.

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `grpcPort` | int | `8080` | Port for gRPC ext_authz server (Envoy integration) |
| `httpPort` | int | `8081` | Port for HTTP server (CAPTCHA endpoints) |
| `logLevel` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error` |

## YAML Configuration

```yaml
server:
  grpcPort: 8080
  httpPort: 8081
  logLevel: "info"
```

## Environment Variables

```bash
export ENVOY_BOUNCER_SERVER_GRPCPORT=8080
export ENVOY_BOUNCER_SERVER_HTTPPORT=8081
export ENVOY_BOUNCER_SERVER_LOGLEVEL=debug
```

## Ports

### gRPC Port

Port for the gRPC server that implements Envoy's ext_authz service. This port must be accessible to Envoy Proxy.

Default: `8080`

### HTTP Port

Port for the HTTP server that serves CAPTCHA challenge and verification endpoints. Only needed when CAPTCHA is enabled.

Default: `8081`

## Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Verbose logging for troubleshooting |
| `info` | Standard operational logging |
| `warn` | Warning messages only |
| `error` | Error messages only |

## Kubernetes/Helm

For Helm-specific configuration, see the [Helm Chart README](../charts/envoy-proxy-bouncer/README.md).

## See Also

- [Configuration Guide](CONFIGURATION.md) - General configuration overview
- [CrowdSec Configuration](CROWDSEC.md) - CrowdSec bouncer and WAF setup
- [CAPTCHA Configuration](CAPTCHA.md) - CAPTCHA challenge setup
- [Deployment Guide](DEPLOYMENT.md) - Deployment instructions
