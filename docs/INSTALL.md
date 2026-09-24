# Installation

Install a tagged release binary.

> [!IMPORTANT]
> Always install a specific tagged version rather than tracking `main` or the latest release automatically. The project is under active development and behavior may change unexpectedly between releases — pinning a version keeps your deployment stable and upgrades a deliberate choice.

## 1. Choose a version

Check the [releases page](https://github.com/kdwils/envoy-proxy-crowdsec-bouncer/releases) for the latest tag, then set it:

```bash
export VERSION=v0.8.1
```

## 2. Download

```bash
wget https://github.com/kdwils/envoy-proxy-crowdsec-bouncer/releases/download/${VERSION}/envoy-proxy-crowdsec-bouncer_Linux_x86_64.tar.gz
```

> **macOS:** use `Darwin` instead of `Linux` (e.g. `envoy-proxy-crowdsec-bouncer_Darwin_arm64.tar.gz` for Apple Silicon, `envoy-proxy-crowdsec-bouncer_Darwin_x86_64.tar.gz` for Intel). Four assets are published per release — `Linux`/`Darwin` × `x86_64`/`arm64` — pick the one matching your OS and CPU, or browse the release's assets on the [releases page](https://github.com/kdwils/envoy-proxy-crowdsec-bouncer/releases) if unsure.

## 3. Extract

```bash
tar -xf envoy-proxy-crowdsec-bouncer_Linux_x86_64.tar.gz
```

This extracts the `envoy-proxy-bouncer` binary into the current directory.

## 4. Install

```bash
sudo mv envoy-proxy-bouncer /usr/local/bin/
sudo chmod +x /usr/local/bin/envoy-proxy-bouncer
```

`/usr/local/bin` is on `PATH` by default on Linux and macOS and doesn't require editing shell profiles.

## 5. Verify

```bash
envoy-proxy-bouncer version
```

## See Also

- [Deployment Guide](DEPLOYMENT.md) - Docker, Kubernetes, and Helm installation
- [Configuration Reference](CONFIGURATION.md)
