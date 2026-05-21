# Installation

## Docker images

[quay.io/pgrwl/pgrwl](https://quay.io/repository/pgrwl/pgrwl)

```bash
docker pull quay.io/pgrwl/pgrwl:latest
```

## Helm Chart

See [pgrwl helm-chart](https://github.com/pgrwl/charts)

```bash
helm repo add pgrwl https://pgrwl.github.io/charts
helm repo update pgrwl
helm search repo pgrwl
```

To install the chart with the release name `pgrwl`:

```bash
helm upgrade pgrwl pgrwl/pgrwl \
  --install --debug --atomic --wait --timeout=10m \
  --namespace=pgrwl
```

## Manual Installation

1. Download the latest binary for your platform from
   the [Releases page](https://github.com/pgrwl/pgrwl/releases).
2. Place the binary in your system's `PATH` (e.g., `/usr/local/bin`).

## Installation script for Unix-Based OS

_requires: tar, curl, jq_

```bash
(
set -euo pipefail

OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')"
TAG="$(curl -s https://api.github.com/repos/pgrwl/pgrwl/releases/latest | jq -r .tag_name)"

curl -L "https://github.com/pgrwl/pgrwl/releases/download/${TAG}/pgrwl_${TAG}_${OS}_${ARCH}.tar.gz" |
tar -xzf - -C /usr/local/bin && \
chmod +x /usr/local/bin/pgrwl
)
```

## Package-Based installation

### Debian

```bash
sudo apt update -y && sudo apt install -y curl
curl -LO https://github.com/pgrwl/pgrwl/releases/latest/download/pgrwl_linux_amd64.deb
sudo dpkg -i pgrwl_linux_amd64.deb
```

### Alpine Linux

```bash
apk update && apk add --no-cache bash curl
curl -LO https://github.com/pgrwl/pgrwl/releases/latest/download/pgrwl_linux_amd64.apk
apk add pgrwl_linux_amd64.apk --allow-untrusted
```