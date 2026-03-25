# envoy-proxy-bouncer

![Version: 0.5.6](https://img.shields.io/badge/Version-0.5.6-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.5.5](https://img.shields.io/badge/AppVersion-v0.5.5-informational?style=flat-square)

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
| config.bouncer.apiKeySecretRef.key | string | `""` |  |
| config.bouncer.apiKeySecretRef.name | string | `""` |  |
| config.bouncer.enabled | bool | `true` |  |
| config.bouncer.lapiURL | string | `""` |  |
| config.bouncer.metrics | bool | `false` |  |
| config.bouncer.metricsInterval | string | `"10m"` |  |
| config.bouncer.tickerInterval | string | `"10s"` |  |
| config.bouncer.tls.caPath | string | `"/app/tls/ca.crt"` |  |
| config.bouncer.tls.certPath | string | `"/app/tls/tls.crt"` |  |
| config.bouncer.tls.enabled | bool | `false` |  |
| config.bouncer.tls.insecureSkipVerify | bool | `false` |  |
| config.bouncer.tls.keyPath | string | `"/app/tls/tls.key"` |  |
| config.bouncer.tlsSecretRef.caKey | string | `"ca.crt"` |  |
| config.bouncer.tlsSecretRef.certKey | string | `"tls.crt"` |  |
| config.bouncer.tlsSecretRef.keyKey | string | `"tls.key"` |  |
| config.bouncer.tlsSecretRef.name | string | `""` |  |
| config.captcha.callbackURL | string | `""` |  |
| config.captcha.challengeDuration | string | `"5m"` |  |
| config.captcha.cookieDomain | string | `""` |  |
| config.captcha.cookieName | string | `""` |  |
| config.captcha.enabled | bool | `false` |  |
| config.captcha.provider | string | `""` |  |
| config.captcha.secretKey | string | `""` |  |
| config.captcha.secretKeySecretRef.key | string | `""` |  |
| config.captcha.secretKeySecretRef.name | string | `""` |  |
| config.captcha.secureCookie | bool | `true` |  |
| config.captcha.sessionDuration | string | `"15m"` |  |
| config.captcha.signingKey | string | `""` |  |
| config.captcha.signingKeySecretRef.key | string | `""` |  |
| config.captcha.signingKeySecretRef.name | string | `""` |  |
| config.captcha.siteKey | string | `""` |  |
| config.captcha.timeout | string | `"10s"` |  |
| config.prometheus.enabled | bool | `false` |  |
| config.prometheus.port | int | `9090` |  |
| config.server.grpcPort | int | `8080` |  |
| config.server.httpPort | int | `8081` |  |
| config.server.logLevel | string | `"info"` |  |
| config.templates.captchaTemplateHeaders | string | `""` |  |
| config.templates.captchaTemplatePath | string | `""` |  |
| config.templates.deniedTemplateHeaders | string | `""` |  |
| config.templates.deniedTemplatePath | string | `""` |  |
| config.templates.showDeniedPage | bool | `true` |  |
| config.trustedProxies | list | `[]` |  |
| config.waf.apiKey | string | `""` |  |
| config.waf.apiKeySecretRef.key | string | `""` |  |
| config.waf.apiKeySecretRef.name | string | `""` |  |
| config.waf.appSecURL | string | `""` |  |
| config.waf.enabled | bool | `false` |  |
| config.webhook.bufferSize | int | `100` |  |
| config.webhook.signingKey | string | `""` |  |
| config.webhook.signingKeySecretRef.key | string | `""` |  |
| config.webhook.signingKeySecretRef.name | string | `""` |  |
| config.webhook.subscriptions | list | `[]` |  |
| config.webhook.timeout | string | `"5s"` |  |
| fullnameOverride | string | `""` |  |
| httproute.annotations | object | `{}` |  |
| httproute.enabled | bool | `false` |  |
| httproute.hostnames | list | `[]` |  |
| httproute.parentRefs | list | `[]` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"ghcr.io/kdwils/envoy-proxy-bouncer"` |  |
| image.tag | string | `""` |  |
| imagePullSecrets | list | `[]` |  |
| nameOverride | string | `""` |  |
| podSecurityContext | object | `{}` |  |
| probes.liveness.enabled | bool | `true` |  |
| probes.liveness.failureThreshold | int | `3` |  |
| probes.liveness.initialDelaySeconds | int | `5` |  |
| probes.liveness.periodSeconds | int | `5` |  |
| probes.liveness.timeoutSeconds | int | `5` |  |
| probes.readiness.enabled | bool | `true` |  |
| probes.readiness.failureThreshold | int | `3` |  |
| probes.readiness.initialDelaySeconds | int | `5` |  |
| probes.readiness.periodSeconds | int | `5` |  |
| probes.readiness.timeoutSeconds | int | `5` |  |
| referenceGrant.create | bool | `false` |  |
| referenceGrant.fromNamespaces | list | `[]` |  |
| replicaCount | int | `1` |  |
| resources.limits.cpu | string | `"100m"` |  |
| resources.limits.memory | string | `"128Mi"` |  |
| securityContext.allowPrivilegeEscalation | bool | `false` |  |
| securityContext.capabilities.drop[0] | string | `"all"` |  |
| securityContext.readOnlyRootFilesystem | bool | `true` |  |
| securityContext.runAsNonRoot | bool | `true` |  |
| securityContext.runAsUser | int | `1000` |  |
| service.grpcPort | int | `8080` |  |
| service.httpPort | int | `8081` |  |
| service.type | string | `"ClusterIP"` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| templates.captchaTemplateContent | string | `""` |  |
| templates.deniedTemplateContent | string | `""` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
