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

`acme-proxy` supports two modes to get a certificate signed from an external CA. 

1. External Account Binding (EAB)
2. DNS01-TXT

**Common ACME enabled CA URLs:**

| CA | URL |
|----|-----|
| LetsEncrypt | `https://acme-v02.api.letsencrypt.org/directory` |
| CertiNext | `https://acme-us.certinext.io/v1/directory` |
| Sectigo OV | `https://acme.sectigo.com/v2/OV` |

Depending on your upstream CA, you may need to configure either one or both modes.

```sh
sudo vim /opt/acme-proxy/ca.json
```

Set the following fields first

| Field | Where to find it |
|-------|-----------------|
| `dnsNames` | Your acme-proxy hostname, e.g. `["acme-proxy.example.com"]` |
| `ca_url` | Your upstream CA's ACME directory URL (see table below) |
| `account_email` | Contact email registered with the upstream CA |


### 1. External Account Binding (EAB)

| Field | Where to find it |
|-------|------------------|
| `eab_kid` | EAB Key ID from your CA's account portal |
| `eab_hmac_key` | EAB HMAC key from your CA's account portal |


```json
{
  "address": ":443",
  "dnsNames": ["acme-proxy.example.com"],
  "authority": {
    "type": "externalcas",
    "config": {
      "ca_url": "https://acme.sectigo.com/v2/InCommonRSAOV",
      "account_email": "certadmin@example.com",
      "eab_kid": "your-key-id-here",
      "eab_hmac_key": "your-hmac-key-here"
    }
  },
  "commonName": "acme-proxy.example.com"
}
```

### 2. DNS01-TXT

LetsEncrypt does not support EAB. To get certificates signed from LetsEncrypt you must use the `dns01_txt` 

| Field                   | Description |
|-------|-----------------|
| `dns01_txt.provider`    | [Lego Provider](https://go-acme.github.io/lego/dns/index.html) CLI Flag |
| `dns01_txt.dns_servers` | Use your authoritative DNS server's addresses to avoid caching/TTL problems |
| `dns01_txt.env_vars`    | Environment variables specific to your Lego DNS Provider for authentication |


```json
{ 
  "address": ":443",
  "dnsNames": ["acme-proxy.example.com"],
  "authority": {
    "type": "externalcas",
    "config": {
      "ca_url": "https://acme-v02.api.letsencrypt.org/directory",
      "account_email": "certadmin@example.com",
      "dns01_txt": {
        "provider": "lego-dns-provider-code",
        "dns_servers": ["8.8.8,8", "1.1.1.1", "2606:4700:4700::1111"],
        "env_vars": { 
          "LEGO_PROVIDER_API_KEY": "xxxxxxx", 
        }
      }
    },
  "commonName": "acme-proxy.example.com"
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
2025/07/15 22:12:26 Processing certificate request for domains: [acme-proxy.example.com]
2025/07/15 22:12:26 Starting certificate request processing for domains: [acme-proxy.example.com]
2025/07/15 22:12:26 [INFO] [acme-proxy.example.com] acme: Obtaining bundled SAN certificate given a CSR
2025/07/15 22:12:27 [INFO] [acme-proxy.example.com] AuthURL: https://acme.sectigo.com/v2/InCommonRSAOV/authz/sx4qvINAdWw2IjplmyH6kg
2025/07/15 22:12:27 [INFO] [acme-proxy.example.com] acme: authorization already valid; skipping challenge
2025/07/15 22:12:27 [INFO] [acme-proxy.example.com] acme: Validations succeeded; requesting certificates
2025/07/15 22:12:27 [INFO] Wait for certificate [timeout: 30s, interval: 500ms]
2025/07/15 22:12:33 [INFO] [acme-proxy.example.com] Server responded with a certificate.
2025/07/15 22:12:33 Successfully obtained certificate from InCommon for domains: [acme-proxy.example.com]
2025/07/15 22:12:33 Starting Smallstep CA/0000000-dev (linux/amd64)
2025/07/15 22:12:33 Documentation: https://u.step.sm/docs/ca
2025/07/15 22:12:33 Community Discord: https://u.step.sm/discord
2025/07/15 22:12:33 Config file: ca.json
2025/07/15 22:12:33 The primary server URL is https://acme-proxy.example.com:443
2025/07/15 22:12:33 Root certificates are available at https://acme-proxy.example.com:443/roots.pem
2025/07/15 22:12:33 X.509 Root Fingerprint: a6cf64dbb4c8d5fd19ce48896068db03b533a8d1336c6256a87d00cbb3def3ea
2025/07/15 22:12:33 Serving HTTPS on acme-proxy.example.com:443 ...
```

---

## Step 4 — Verify

```sh
curl -s https://acme-proxy.example.com/acme/acme/directory | jq .
```

Expected:

```json
{
  "newNonce": "https://acme-proxy.example.com/acme/acme/new-nonce",
  "newAccount": "https://acme-proxy.example.com/acme/acme/new-account",
  "newOrder": "https://acme-proxy.example.com/acme/acme/new-order",
  "revokeCert": "https://acme-proxy.example.com/acme/acme/revoke-cert",
  "keyChange": "https://acme-proxy.example.com/acme/acme/key-change"
}
```

Verify [connectivity requirements](index.md/#connectivity-requirements) have been met before proceeding to the next step.

---

## Step 5 — Issue a Test Certificate

On a server running in your network, install `acme.sh` if not already present:

```sh
# Debian / Ubuntu
sudo apt-get install -y acme.sh socat

# RHEL / Rocky / Alma
sudo dnf install -y epel-release acme.sh socat
```

Issue a certificate in standalone mode (temporarily binds port 80 for the HTTP-01 challenge). 

```sh
acme.sh --issue \
  --server https://acme-proxy.example.com/acme/acme/directory \
  --domain myserver.example.com \
  --standalone
```

Verify it was signed by your upstream CA:

```sh
openssl x509 \
  -in ~/.acme.sh/myserver.example.com_ecc/myserver.example.com.cer \
  -noout -issuer -dates
```
