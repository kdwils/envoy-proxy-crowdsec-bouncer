# Metrics

The bouncer exposes a Prometheus-compatible metrics endpoint. The response uses the standard [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/), which is compatible with both Prometheus and VictoriaMetrics scrapers without any additional configuration.

Enable the endpoint in your configuration:

```yaml
prometheus:
  enabled: true
  port: 9090
```

The endpoint is served at `http://<host>:<port>/metrics`.

## Available Metrics

All metrics use the `bouncer_` namespace.

### Requests

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bouncer_requests_total` | Counter | `action` | Total requests processed, labeled by outcome (`allow`, `ban`, `captcha`, `error`) |
| `bouncer_request_duration_seconds` | Histogram | — | End-to-end request processing duration |
| `bouncer_rate_limited_total` | Counter | — | Total requests rejected by the rate limiter |

### LAPI

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bouncer_lapi_stream_connected` | Gauge | — | Whether the LAPI decision stream is connected (`1`) or not (`0`) |
| `bouncer_lapi_last_sync_timestamp_seconds` | Gauge | — | Unix timestamp of the last successful LAPI decision sync |
| `bouncer_lapi_decisions_added_total` | Counter | `origin` | Decisions added to the cache, labeled by origin |
| `bouncer_lapi_decisions_deleted_total` | Counter | `origin` | Decisions removed from the cache, labeled by origin |
| `bouncer_decision_cache_size` | Gauge | `origin` | Current number of decisions in the cache, labeled by origin |

### WAF

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bouncer_waf_requests_total` | Counter | `action` | Requests inspected by the WAF, labeled by outcome |
| `bouncer_waf_errors_total` | Counter | — | WAF inspection errors |

### CAPTCHA

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bouncer_captcha_challenges_total` | Counter | — | CAPTCHA challenge pages served |
| `bouncer_captcha_verifications_total` | Counter | `result` | CAPTCHA verification attempts, labeled by `success`, `failure`, or `error` |
| `bouncer_captcha_pending_challenges` | Gauge | — | Challenge tokens issued and awaiting verification |
| `bouncer_captcha_expired_challenges_total` | Counter | — | Challenge tokens that expired before verification |
| `bouncer_captcha_errors_total` | Counter | — | CAPTCHA service errors |

### Component Latency

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bouncer_component_duration_seconds` | Histogram | `component` | Per-component processing duration (`bouncer`, `waf`, `captcha`) |

## Scrape Configuration

### Prometheus

```yaml
scrape_configs:
  - job_name: envoy-proxy-bouncer
    static_configs:
      - targets:
          - <host>:9090
```

### VictoriaMetrics

VictoriaMetrics uses the same `scrape_configs` syntax as Prometheus:

```yaml
scrape_configs:
  - job_name: envoy-proxy-bouncer
    static_configs:
      - targets:
          - <host>:9090
```

## See Also

- [Configuration Reference](CONFIGURATION.md) - Full configuration options including Prometheus settings
- [Deployment Guide](DEPLOYMENT.md) - Deployment instructions
