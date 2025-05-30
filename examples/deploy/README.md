# Kubernetes

The bouncer can be deployed in a Kubernetes cluster alongside Envoy Gateway. An example manifest is provided at `manifest.yaml`.

You will need to create a secret with your LAPI API key and configure the bouncer to use it. I did this via env vars, but you can also use a config map or a file.

> [!WARNING]
> Make sure you point the bouncer to your LAPI instance and update the image sha from `envoy-bouncer` to your desired version.

## Deploying
1. Create a secret with your LAPI API key:
```bash
apiVersion: v1
kind: Secret
metadata:
  name: envoy-bouncer
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
