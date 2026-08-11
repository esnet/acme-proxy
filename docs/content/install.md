+++
title = 'Install'
weight = 20
BookToC = true
+++

# Install

There are a few methods for produciton installation. The install script is recommended for most deployments due to it's simplicity. 

| Method | Best for |
|--------|---------|
| [Install script](#install-script-recommended) | Standard Linux servers, systemd environments |
| [Build from source](#build-from-source) | Development, or architectures not covered by releases |
| [Docker](#docker) | Standalone container-based deployments 

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
  sudo INSTALL_DIR=/usr/local/acme-proxy SERVICE_USER=acmeservice sh
```

### What the script installs

| Path | Description |
|------|-------------|
| `$INSTALL_DIR/step-ca` | The server binary |
| `$INSTALL_DIR/ca.json` | Configuration file (template — must be edited) |
| `$DB_DIR/bbolt` | bbolt KV store for ACME account state |
| `/etc/systemd/system/acme-proxy.service` | Systemd service unit |

The service is **enabled but not started**. [Configure](configuration.md) `ca.json` file before starting.

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
# configure `ca.json` file before starting step-ca
./step-ca ca.json
```

Use the [installer script](https://raw.githubusercontent.com/esnet/acme-proxy/main/install.sh) as a reference to complete the setup with systemd service unit, service account user, permissions etc.

---

## Install using Docker

Run the following commands before starting the container on a linux host

```sh
mkdir -p /opt/acme-proxy/db
touch /opt/acme-proxy/ca.json
chown -R 65532:65532 /opt/acme-proxy
```

Make sure you have configured the `ca.json` file

```sh
docker run -d \
  --name acme-proxy \
  -p 443:443 \
  -v "$(pwd)"/ca.json:/opt/acme-proxy/ca.json:ro \
  -v "$(pwd)"/db:/opt/acme-proxy/db \
  --restart unless-stopped \
ghcr.io/esnet/acme-proxy:latest
```

View logs:

```sh
docker logs -f acme-proxy
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
      - ./db:/opt/acme-proxy/db
    restart: unless-stopped
```

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

{
  "newNonce": "https://proxy.example.com/acme/acme/new-nonce",
  "newAccount": "https://proxy.example.com/acme/acme/new-account",
  "newOrder": "https://proxy.example.com/acme/acme/new-order",
  "revokeCert": "https://proxy.example.com/acme/acme/revoke-cert",
  "keyChange": "https://proxy.example.com/acme/acme/key-change"
}
```

A JSON object with `newNonce`, `newAccount`, `newOrder` keys confirms the ACME server is running and accepting requests.
