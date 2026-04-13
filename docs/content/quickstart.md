+++
title = 'Quickstart'
weight = 10
BookToC = true
+++

# Quickstart

This is the fastest path to a running acme-proxy. It uses a one-line installer script that sets up the service with sane defaults, requires only five config fields, and is ready to issue certificates in under five minutes.

For production deployments with custom install paths, build-from-source, or Docker, see [install.md](install.md).

---

## Step 1 — Install

```sh
curl -fsSL https://raw.githubusercontent.com/esnet/acme-proxy/main/install.sh | sudo sh
```

The script:

- Installs the `step-ca` binary to `/opt/acme-proxy/`
- Writes a `ca.json` config template to `/opt/acme-proxy/ca.json`
- Creates a dedicated `acme-proxy` service user
- Registers and enables an `acme-proxy.service` systemd unit

The service is **enabled but not started** — configure `ca.json` first.

Override install paths if needed:

```sh
curl -fsSL https://raw.githubusercontent.com/esnet/acme-proxy/main/install.sh | \
  sudo INSTALL_DIR=/usr/local/acme-proxy SERVICE_USER=acmeservice sh
```

---

## Step 2 — Configure

Open the config file:

```sh
sudo vim /opt/acme-proxy/ca.json
```

Set these five fields — everything else can stay at its default:

| Field | Where to find it |
|-------|-----------------|
| `dnsNames` | Your acme-proxy hostname, e.g. `["acmeproxy.example.com"]` |
| `ca_url` | Your upstream CA's ACME directory URL (see table below) |
| `account_email` | Contact email registered with the upstream CA |
| `eab_kid` | EAB Key ID from your CA's account portal |
| `eab_hmac_key` | EAB HMAC key from your CA's account portal |

**Common upstream CA URLs:**

| CA | URL |
|----|-----|
| Sectigo / InCommon RSA OV | `https://acme.sectigo.com/v2/InCommonRSAOV` |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` |

> LetsEncrypt does not support EAB and cannot be used as an upstream CA with acme-proxy.

**Minimal working config:**

```json
{
  "address": ":443",
  "dnsNames": ["acmeproxy.example.com"],
  "authority": {
    "type": "externalcas",
    "config": {
      "ca_url": "https://acme.sectigo.com/v2/InCommonRSAOV",
      "account_email": "certadmin@example.com",
      "eab_kid": "your-key-id-here",
      "eab_hmac_key": "your-hmac-key-here"
    }
  },
  "commonName": "acmeproxy.example.com"
}
```

---

## Step 3 — Start

```sh
sudo systemctl start acme-proxy
```

On first start, acme-proxy registers an account with the upstream CA and obtains a TLS certificate for itself before accepting connections. Follow the logs:

```sh
sudo journalctl -u acme-proxy -f
```

The service is ready when logs show:

```
2025/07/15 22:12:25 Building new tls configuration using step-ca x509 Signer Interface
2025/07/15 22:12:25 Initializing ACME client...
2025/07/15 22:12:25 [INFO] acme: Registering account for admin@example.com
2025/07/15 22:12:26 ACME client initialized successfully
2025/07/15 22:12:26 Processing certificate request for domains: [proxy.example.com]
2025/07/15 22:12:26 Starting certificate request processing for domains: [proxy.example.com]
2025/07/15 22:12:26 [INFO] [proxy.example.com] acme: Obtaining bundled SAN certificate given a CSR
2025/07/15 22:12:27 [INFO] [proxy.example.com] AuthURL: https://acme.sectigo.com/v2/InCommonRSAOV/authz/sx4qvINAdWw2IjplmyH6kg
2025/07/15 22:12:27 [INFO] [proxy.example.com] acme: authorization already valid; skipping challenge
2025/07/15 22:12:27 [INFO] [proxy.example.com] acme: Validations succeeded; requesting certificates
2025/07/15 22:12:27 [INFO] Wait for certificate [timeout: 30s, interval: 500ms]
2025/07/15 22:12:33 [INFO] [proxy.example.com] Server responded with a certificate.
2025/07/15 22:12:33 Successfully obtained certificate from InCommon for domains: [proxy.example.com]
2025/07/15 22:12:33 Starting Smallstep CA/0000000-dev (linux/amd64)
2025/07/15 22:12:33 Documentation: https://u.step.sm/docs/ca
2025/07/15 22:12:33 Community Discord: https://u.step.sm/discord
2025/07/15 22:12:33 Config file: ca.json
2025/07/15 22:12:33 The primary server URL is https://acmeproxy.example.com:443
2025/07/15 22:12:33 Root certificates are available at https://acmeproxy.example.com:443/roots.pem
2025/07/15 22:12:33 X.509 Root Fingerprint: a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea
2025/07/15 22:12:33 Serving HTTPS on proxy.example.com:443 ...
```

---

## Step 4 — Verify

```sh
curl -s https://acmeproxy.example.com/acme/acme/directory | jq .
```

Expected:

```json
{
  "newNonce": "https://acmeproxy.example.com/acme/acme/new-nonce",
  "newAccount": "https://acmeproxy.example.com/acme/acme/new-account",
  "newOrder": "https://acmeproxy.example.com/acme/acme/new-order",
  "revokeCert": "https://acmeproxy.example.com/acme/acme/revoke-cert",
  "keyChange": "https://acmeproxy.example.com/acme/acme/key-change"
}
```

---

## Step 5 — Issue a Test Certificate

Install acme.sh if not already present:

```sh
sudo apt-get install -y acme.sh              # Debian / Ubuntu
sudo dnf install -y epel-release acme.sh     # RHEL / Rocky
```

Issue a certificate in standalone mode (temporarily binds port 80 for the HTTP-01 challenge):

```sh
acme.sh --issue \
  --server https://acmeproxy.example.com/acme/acme/directory \
  --domain myserver.example.com \
  --standalone
```

Verify it was signed by your upstream CA:

```sh
openssl x509 \
  -in ~/.acme.sh/myserver.example.com_ecc/myserver.example.com.cer \
  -noout -issuer -dates
```

---

## Next Steps

- **Set up ACME clients system-wide with auto-renewal** — [Admin Guide](admin.md)
- **Issue certificates for NGINX, Apache, Docker workloads** — [User Guide](user.md)
- **Alternative install methods** (binary, source, Docker, full config reference) — [Install](install.md)
