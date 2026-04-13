+++
title = 'Install'
weight = 20
BookToC = true
+++

# Install

Three methods are available. The install script is recommended for most deployments.

| Method | Best for |
|--------|---------|
| [Install script](#install-script-recommended) | Standard Linux servers, systemd environments |
| [Pre-built binary](#pre-built-binary) | Environments where curl-pipe-to-shell is prohibited |
| [Build from source](#build-from-source) | Development, or architectures not covered by releases |
| [Docker](#docker) | Container-based deployments |

---

## Install Script (Recommended)

The install script downloads the appropriate release binary, creates a dedicated service user, installs a `ca.json` template, and registers a hardened `systemd` service unit.

```sh
curl -fsSL https://raw.githubusercontent.com/esnet/acme-proxy/main/install.sh | sudo sh
```

### Environment variable overrides

All defaults are overridable:

```sh
# Defaults
INSTALL_DIR=/opt/acme-proxy
DB_DIR=/opt/acme-proxy/db
CONFIG_FILE=/opt/acme-proxy/ca.json
SERVICE_USER=acme-proxy
SERVICE_GROUP=acme-proxy
```

Example — custom paths and user:

```sh
curl -fsSL https://raw.githubusercontent.com/esnet/acme-proxy/main/install.sh | \
  sudo INSTALL_DIR=/usr/local/acme-proxy \
       SERVICE_USER=acmeservice \
       sh
```

### What the script installs

| Path | Description |
|------|-------------|
| `$INSTALL_DIR/step-ca` | The server binary |
| `$INSTALL_DIR/ca.json` | Configuration file (template — must be edited) |
| `$DB_DIR/bbolt` | bbolt KV store for ACME account state |
| `/etc/systemd/system/acme-proxy.service` | Systemd service unit |

The service is **enabled but not started**. [Configure `ca.json`](#configuration) before starting.

---

## Pre-built Binary

Download the release binary directly from the [GitHub releases page](https://github.com/esnet/acme-proxy/releases), verify the checksum, and install manually.

```sh
VERSION=1.0.0   # replace with the current release

# Download binary and checksum
curl -fsSLO "https://github.com/esnet/acme-proxy/releases/download/v${VERSION}/step-ca_linux_amd64"
curl -fsSLO "https://github.com/esnet/acme-proxy/releases/download/v${VERSION}/step-ca_linux_amd64.sha256"

# Verify
sha256sum -c step-ca_linux_amd64.sha256

# Install
sudo install -o root -g root -m 0755 step-ca_linux_amd64 /opt/acme-proxy/step-ca
```

> For arm64, substitute `amd64` with `arm64` in the filename.

After placing the binary, create the config directory and set up `ca.json` manually (see [Configuration](#configuration)), then create a systemd service unit:

```sh
sudo mkdir -p /opt/acme-proxy/db

sudo tee /etc/systemd/system/acme-proxy.service <<'EOF'
[Unit]
Description=ACME Proxy Server (step-ca)
Documentation=https://github.com/esnet/acme-proxy
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=acme-proxy
Group=acme-proxy
ExecStart=/opt/acme-proxy/step-ca /opt/acme-proxy/ca.json
WorkingDirectory=/opt/acme-proxy
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ReadWritePaths=/opt/acme-proxy
StandardOutput=journal
StandardError=journal
SyslogIdentifier=acme-proxy

[Install]
WantedBy=multi-user.target
EOF

sudo useradd -r -s /sbin/nologin acme-proxy
sudo chown -R acme-proxy:acme-proxy /opt/acme-proxy
sudo systemctl daemon-reload
sudo systemctl enable acme-proxy
```

---

## Build from Source

**Requirements:** Go >= 1.25, `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (RHEL/Rocky)

```sh
# Install build dependency
sudo apt-get install -y libpcsclite-dev pkg-config   # Debian / Ubuntu
sudo dnf install -y pcsc-lite-devel pkgconfig        # RHEL / Rocky

# Clone and build
git clone https://github.com/esnet/acme-proxy.git
cd acme-proxy
make
```

The build produces a `step-ca` binary in the current directory. Copy it to your install location:

```sh
sudo install -o root -g root -m 0755 step-ca /opt/acme-proxy/step-ca
```

Then follow the [pre-built binary](#pre-built-binary) instructions to create the service unit.

---

## Docker

### Pre-built image

```sh
docker pull ghcr.io/esnet/acme-proxy:latest
```

Run with a bind-mounted config file:

```sh
docker run -d \
  --name acme-proxy \
  -p 443:443 \
  -v ./ca.json:/opt/acme-proxy/ca.json:ro \
  -v acme-proxy-db:/opt/acme-proxy/db \
  ghcr.io/esnet/acme-proxy:latest
```

View logs:

```sh
docker logs -f acme-proxy
```

### Build your own image

```sh
git clone https://github.com/esnet/acme-proxy.git
cd acme-proxy
docker build -t acme-proxy:latest .
```

Run:

```sh
docker run -d \
  --name acme-proxy \
  -p 443:443 \
  -v ./ca.json:/opt/acme-proxy/ca.json:ro \
  -v acme-proxy-db:/opt/acme-proxy/db \
  acme-proxy:latest
```

### Docker Compose

```yaml
services:
  acme-proxy:
    image: ghcr.io/esnet/acme-proxy:latest
    ports:
      - "443:443"
    volumes:
      - ./ca.json:/opt/acme-proxy/ca.json:ro
      - acme-proxy-db:/opt/acme-proxy/db
    restart: unless-stopped

volumes:
  acme-proxy-db:
```

---

## Configuration

All install methods use the same `ca.json` configuration format. The install script creates a template — five fields require customization before the service can start.

### Minimal required configuration

```json
{
  "address": ":443",
  "dnsNames": ["acmeproxy.example.com"],
  "logger": {
    "format": "json"
  },
  "db": {
    "type": "bbolt",
    "dataSource": "/opt/acme-proxy/db/bbolt"
  },
  "authority": {
    "type": "externalcas",
    "config": {
      "ca_url": "https://acme.sectigo.com/v2/InCommonRSAOV",
      "account_email": "certadmin@example.com",
      "eab_kid": "your-eab-key-id",
      "eab_hmac_key": "your-eab-hmac-key",
      "metrics": {
        "enabled": true,
        "port": 9234,
        "dataSource": "/opt/acme-proxy/db/metrics"
      }
    },
    "provisioners": [
      {
        "type": "ACME",
        "name": "acme",
        "claims": {
          "enableSSHCA": false,
          "disableRenewal": false,
          "allowRenewalAfterExpiry": false,
          "disableSmallstepExtensions": true
        }
      }
    ],
    "backdate": "1m0s"
  },
  "tls": {
    "minVersion": 1.2,
    "maxVersion": 1.3,
    "renegotiation": false
  },
  "commonName": "acmeproxy.example.com"
}
```

### Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `address` | Yes | Listen address. `:443` binds all interfaces on port 443. |
| `dnsNames` | Yes | Hostname(s) that this proxy is reachable at. acme-proxy requests a TLS cert for itself using these names on first start. |
| `authority.config.ca_url` | Yes | ACME directory URL of your upstream certificate authority. |
| `authority.config.account_email` | Yes | Email registered with the upstream CA. |
| `authority.config.eab_kid` | Yes | External Account Binding Key ID, obtained from your CA's account portal. |
| `authority.config.eab_hmac_key` | Yes | External Account Binding HMAC key, obtained from your CA's account portal. |
| `authority.config.metrics.enabled` | No | Expose Prometheus metrics. Default: `true`. |
| `authority.config.metrics.port` | No | Metrics port. Default: `9234`. |
| `db.dataSource` | Yes | Path to the bbolt KV store directory. Must be writable by the service user. |
| `commonName` | Yes | Common name for the proxy's own TLS certificate. Should match `dnsNames[0]`. |

### Upstream CA URLs

| CA | ACME URL |
|----|----------|
| Sectigo / InCommon RSA OV | `https://acme.sectigo.com/v2/InCommonRSAOV` |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` |

> LetsEncrypt does not support External Account Binding and cannot be used as an upstream CA with acme-proxy.

---

## Starting the Service

### Systemd

```sh
sudo systemctl start acme-proxy
sudo systemctl status acme-proxy
```

On first start, acme-proxy registers an account with the upstream CA and obtains a TLS certificate for itself. This takes a few seconds. Follow the logs:

```sh
sudo journalctl -u acme-proxy -f
```

Expected startup sequence:

```
Building new tls configuration using step-ca x509 Signer Interface
Initializing ACME client...
[INFO] acme: Registering account for certadmin@example.com
[INFO] [acmeproxy.example.com] acme: Obtaining bundled SAN certificate
[INFO] [acmeproxy.example.com] acme: Validations succeeded; requesting certificates
Successfully obtained certificate from external CA
Serving HTTPS on :443 ...
```

### Running manually (without systemd)

```sh
/opt/acme-proxy/step-ca /opt/acme-proxy/ca.json
```

### Docker

```sh
docker compose up -d
docker logs -f acme-proxy
```

---

## Verify

```sh
curl -s https://acmeproxy.example.com/acme/acme/directory | jq .
```

A JSON object with `newNonce`, `newAccount`, `newOrder` keys confirms the server is running and accepting ACME requests.
