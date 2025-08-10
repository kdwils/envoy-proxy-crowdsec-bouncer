# envoy-proxy-bouncer

![Version: 0.0.3](https://img.shields.io/badge/Version-0.0.3-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.0.3](https://img.shields.io/badge/AppVersion-v0.0.3-informational?style=flat-square)

A Helm chart for CrowdSec Envoy Proxy Bouncer

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| autoscaling.enabled | bool | `false` |  |
| autoscaling.maxReplicas | int | `10` |  |
| autoscaling.minReplicas | int | `1` |  |
| autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| autoscaling.targetMemoryUtilizationPercentage | int | `80` |  |
| config.bouncer.apiKey | string | `""` |  |
| config.bouncer.enabled | bool | `true` |  |
| config.bouncer.lapiURL | string | `"http://crowdsec-service:8080"` |  |
| config.bouncer.metrics | bool | `false` |  |
| config.bouncer.tickerInterval | string | `"10s"` |  |
| config.server.logLevel | string | `"info"` |  |
| config.server.port | int | `8080` |  |
| config.trustedProxies | list | `[]` |  |
| config.waf.apiKey | string | `""` |  |
| config.waf.appSecURL | string | `"http://crowdsec-appsec-service:7422"` |  |
| config.waf.enabled | bool | `false` |  |
| config.waf.timeout | string | `"1s"` |  |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/kdwils/envoy-proxy-bouncer"` |  |
| image.tag | string | `""` |  |
| imagePullSecrets | list | `[]` |  |
| nameOverride | string | `""` |  |
| podSecurityContext | object | `{}` |  |
| replicaCount | int | `1` |  |
| resources.limits.cpu | string | `"100m"` |  |
| resources.limits.memory | string | `"128Mi"` |  |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"all"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| securityContext.runAsNonRoot | bool | `true` |  |
| securityContext.runAsUser | int | `1000` |  |
| securityPolicy.create | bool | `false` |  |
| securityPolicy.gatewayName | string | `""` |  |
| securityPolicy.gatewayNamespace | string | `"envoy-gateway-system"` |  |
| service.port | int | `8080` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |

