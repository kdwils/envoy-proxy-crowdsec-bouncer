# Kubernetes Manifest

The bouncer can be deployed in a Kubernetes cluster alongside Envoy Gateway. Example manifests are provided:

- [manifest.yaml](manifest.yaml) - Basic deployment
- [custom-templates.yaml](custom-templates.yaml) - Deployment with custom ban and CAPTCHA templates
- [policy.yaml](policy.yaml) - Example SecurityPolicy configuration

You will need to create a secret with your LAPI API key and configure the bouncer to use it. I did this via env vars, but you can also use a config map or a file.

> [!WARNING]
> Make sure you point the bouncer to your LAPI instance and update the image sha from `envoy-bouncer` to your desired version.

## Deploying
1. Create a secret with your LAPI API key:
```bash
apiVersion: v1
kind: Secret
metadata:
  name: crowdsec-api-key-secret
  namespace: envoy-gateway-system
type: Opaque
data:
  ENVOY_BOUNCER_BOUNCER_APIKEY: <b64-encoded-api-key>
```

To base64 encode your API key:
```bash
echo -n <your-api-key> | base64
```

Apply it to the cluster
```bash
kubectl apply -f secret.yaml
```

2. Deploy the bouncer:
```bash
kubectl apply -f manifest.yaml
```

3. Check the logs:
```bash
kubectl logs -f deployment/envoy-bouncer
```

## Configurating Envoy Gateway

The bouncer can be configured as an external authorization service in Envoy Gateway. An example policy is provided at [policy.yaml](policy.yaml)

# Helm

Add the Helm repository:
```bash
helm repo add envoy-proxy-bouncer https://kdwils.github.io/envoy-proxy-crowdsec-bouncer
helm repo update
```

Install the chart and create a security policy:
```bash
helm install bouncer envoy-proxy-bouncer/envoy-proxy-bouncer \
  --set crowdsec.apiKey=<your-api-key> \
  --set crowdsec.apiURL=<your-host-url> \
  --set securityPolicy.create=true \
  --set securityPolicy.gatewayName=<your-gateway-name>
  --set securityPolicy.gatewayNamespace=<your-gateway-namespace>