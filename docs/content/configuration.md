+++
title = 'Configure'
weight = 30
BookToC = true
+++

# Required Configuration

Since acme-proxy uses step-ca as the ACME server much of the required configuration options are set by step-ca itself. Only `authority.config.ca_url` is required; everything else is optional. Depending on your upstream CA you may additionally configure External Account Binding (`eab_kid` + `eab_hmac_key`) and/or a DNS provider (`dns01_txt`). `ca.json` supports `#` comments outside of string literals, so you can document the config in place.

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

# Admin web dashboard (optional; enabled when port > 0). See "Admin Dashboard".
  "dashboard": {
    "port": 8443,
    "username": "admin",
    "password": "kambing",
    "tls_max_age_days": 30
  },

# Client allow-list for ACME requests (optional). See "Access Control List".
  "acl": {
    "file": "/opt/acme-proxy/acl.txt"
  },

  "authority": {
    "type": "externalcas",
    "config": {
      "ca_url": "https://acme-v02.api.letsencrypt.org/directory",
      "account_email": "certadmin@example.com",

      "eab_kid": "",
      "eab_hmac_key": "",

      "challenge_type": "auto",
      "http01_bind": "",
      "http01_port": 80,
      "tlsalpn01_bind": "",
      "tlsalpn01_port": 443,
      "max_concurrent_requests": 1,

      "cert_poll_timeout": 30,
      "request_timeout": 120,
      "cert_cache_min_validity": 7,
      "cert_cache_max_age": 30,

      "dns01_txt": {
        "provider": "",
        "dns_servers": [],
        "env_vars": {}
      },
      "metrics": {
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

## Challenge Types

`challenge_type` selects the challenge acme-proxy solves **toward the upstream CA**. It is completely independent of the challenge type a downstream client (certbot, acme.sh, cert-manager) requests from acme-proxy: clients complete their challenge directly with acme-proxy's step-ca ACME provisioner, and acme-proxy then proves domain control to the upstream CA using the configured type. In other words, interception is always in effect: a client may solve `tls-alpn-01` with acme-proxy while acme-proxy answers the upstream CA with `http-01`.

| Value | Behavior |
|-------|----------|
| `auto` (default) | `dns-01` when `dns01_txt` is fully configured (provider **and** env_vars set), otherwise `http-01` |
| `http-01` | Always use HTTP-01. acme-proxy serves `/.well-known/acme-challenge/` on `http01_bind`:`http01_port` (default `:80`); port 80 must be reachable from the upstream CA |
| `tls-alpn-01` | Always use TLS-ALPN-01. acme-proxy serves the challenge over TLS-ALPN on `tlsalpn01_bind`:`tlsalpn01_port` (default `:443`); port 443 must be reachable from the upstream CA; **not supported by ZeroSSL** |
| `dns-01` | Always use DNS-01. Requires `dns01_txt.provider`; `env_vars` is optional in this explicit mode |

The challenge servers are shared "virtual servers": a single listener serves any number of simultaneous challenges, so concurrent requests never collide on the port.

## Listener Addresses and Port Conflicts

acme-proxy has two kinds of listeners:

1. **Client-facing**: the top-level `address` in `ca.json` (default `:443`), owned by step-ca. This is where your internal ACME clients (certbot, acme.sh, cert-manager) connect.
2. **Challenge listeners**: `http01_bind`:`http01_port` and `tlsalpn01_bind`:`tlsalpn01_port`, used only toward the upstream CA.

If both bind the same IP and port the second bind fails (e.g. `address: ":443"` + `tlsalpn01_port: 443` with no bind IPs set). Resolve conflicts by separating on IP or port:

| Approach | Example |
|----------|---------|
| Separate IPs (multiple interfaces on one host) | `address: "10.0.0.1:443"` (clients, internal) + `tlsalpn01_bind: "203.0.113.5"` (challenge, public IP) |
| Separate ports + DNAT/port-forward | `tlsalpn01_port: 8443` with external 443 forwarded to 8443 |
| step-ca on a non-standard port | `address: ":8443"` for clients + challenge listener free to use `:443` |

Empty `http01_bind`/`tlsalpn01_bind` (default) binds all interfaces, which is fine as long as the ports don't collide on any interface. Note the RFC-mandated external ports still apply: http-01 validations arrive on port **80**, tls-alpn-01 validations on port **443** of the domain's public IP, so the bind/port combination must ultimately map back from there (directly or via DNAT/LB).

## External Account Binding (EAB)

| eab_kid / eab_hmac_key | Result |
|------------------------|--------|
| both empty | Anonymous account registration. Use this for Let's Encrypt, which does not support EAB |
| both set | EAB registration. Common/required with ZeroSSL, Sectigo, CertiNext, DigiCert |
| exactly one set | Configuration error: `eab_kid and eab_hmac_key must be set together` |

## Upstream CA Compatibility

| CA | ACME URL | EAB | http-01 | dns-01 | tls-alpn-01 |
|----|----------|-----|---------|--------|-------------|
| Let's Encrypt | `https://acme-v02.api.letsencrypt.org/directory` | not supported (leave empty) | ✅ | ✅ | ✅ |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` | supported | ✅ | ✅ | ❌ |
| Sectigo OV | `https://acme.sectigo.com/v2/OV` | required | ✅ | ✅ | ❌ |
| CertiNext | `https://acme-us.certinext.io/v1/directory` | required | ✅ | ✅ | ❌ |

Always verify supported challenge types with your CA's documentation before selecting `tls-alpn-01`.

## Concurrency

- `max_concurrent_requests` (default `1`) caps simultaneous upstream ACME operations (issuance and revocation); excess requests are queued and observe the 2-minute request timeout while waiting.
- Identical concurrent requests (same DNS names in the CSR) are coalesced into a **single** upstream order; all callers receive the same certificate.
- Successfully issued certificates are cached and re-served while at least `cert_cache_min_validity` days (default `7`) of validity remain **and** they are younger than `cert_cache_max_age` days (default `30`). The max-age bound keeps the renewal cadence predictable even while upstream certificates are long-lived, which matters for CAs with per-name rate limits such as Let's Encrypt's 5 certificates per rolling 7 days.
- The HTTP-01 challenge listener closes automatically once the last challenge completes, so port 80 is only exposed while a challenge is actually being served.

## Field Reference

Fields under `authority.config` are specific to acme-proxy.

| Field | Required | Description |
|-------|----------|-------------|
| `address` | Yes | Listen address. `:443` binds all interfaces on port 443. |
| `dnsNames` | Yes | Hostname(s) that this proxy is reachable at. acme-proxy requests a TLS cert for itself using these names on first start. |
| `db.type` | Yes | Persistent KV data source to store ACME challenge state information |
| `db.dataSource` | Yes | Path to the bbolt KV store directory. Must be writable by the service user. |
| `authority.config.ca_url` | Yes | ACME directory URL of your upstream certificate authority. |
| `authority.config.account_email` | No | Email registered with the upstream CA. |
| `authority.config.eab_kid` | Conditional | External Account Binding Key ID. Set together with `eab_hmac_key` only if your CA requires EAB; leave both empty for Let's Encrypt. |
| `authority.config.eab_hmac_key` | Conditional | External Account Binding HMAC key. Must be set together with `eab_kid`. |
| `authority.config.challenge_type` | No | Challenge solved toward the upstream CA: `auto` (default), `http-01`, `tls-alpn-01`, or `dns-01`. Independent of downstream client challenges. |
| `authority.config.http01_bind` | No | IP address the HTTP-01 challenge server binds to. Default: empty (all interfaces). Use to avoid conflicts with the client-facing `address`. |
| `authority.config.http01_port` | No | Port for the shared HTTP-01 challenge server. Default: `80`. Must be reachable from the upstream CA. |
| `authority.config.tlsalpn01_bind` | No | IP address the TLS-ALPN-01 challenge server binds to. Default: empty (all interfaces). Use to avoid conflicts with the client-facing `address`. |
| `authority.config.tlsalpn01_port` | No | Port for the shared TLS-ALPN-01 challenge server. Default: `443`. Must be reachable from the upstream CA. |
| `authority.config.max_concurrent_requests` | No | Maximum simultaneous upstream ACME operations; excess requests are queued. Default: `1`. |
| `authority.config.certlifetime` | No | Request certificate with a max lifetime period if supported by upstream CA |
| `authority.config.cert_poll_timeout` | No | Seconds to wait for the upstream CA to issue the certificate after challenge validation. Default: `30`. |
| `authority.config.request_timeout` | No | Total seconds for one certificate request toward the upstream CA, including challenge validation and cert polling. Default: `120`. Slow CAs (e.g. ZeroSSL) may need this raised; keep it above `cert_poll_timeout` plus challenge validation time (e.g. `cert_poll_timeout: 300` with `request_timeout: 420`). |
| `authority.config.cert_cache_min_validity` | No | Minimum remaining validity (days) for a cached certificate to be re-served. Default: `7`. |
| `authority.config.cert_cache_max_age` | No | Maximum age (days) of a cached certificate that may still be served; older entries force a fresh issuance. Default: `30`. Bounds renewal cadence so upstream per-name rate limits (e.g. Let's Encrypt 5/week) are never tripped by stale cache reuse. |
| `authority.config.dns01_txt.provider` | Conditional | [Lego Provider](https://go-acme.github.io/lego/dns/index.html) CLI Flag. Required when `challenge_type` is `dns-01`. |
| `authority.config.dns01_txt.dns_servers` | No | Use your authoritative DNS server's addresses to avoid caching/TTL problems |
| `authority.config.dns01_txt.env_vars` | Conditional | Environment variables specific to your Lego DNS Provider for authentication. Required for `auto` mode to select dns-01; optional with explicit `challenge_type: dns-01`. |
| `authority.config.metrics.port` | No | Metrics port. Default: `9234`. |
| `authority.config.metrics.datasource` | No | Prometheus metrics datastore. Default: `/opt/acme-proxy/db/metrics`. |
| `dashboard.port` | No | Admin web dashboard port. Enabled when `> 0`. Default: disabled. |
| `dashboard.bind` | No | IP the dashboard binds to. Default: empty (all interfaces). |
| `dashboard.username` | No | Dashboard login username. Default: `admin`. |
| `dashboard.password` | No | Dashboard login password. Default: `kambing`. |
| `dashboard.tls_cert` / `dashboard.tls_key` | No | Serve these PEM files for dashboard HTTPS instead of sharing the proxy's own certificate. |
| `dashboard.tls_max_age_days` | No | Maximum age (days) of the proxy's own certificate before background renewal. Default: `30`. |
| `dashboard.data_source` | No | Sidecar bbolt store for dashboard history. Default: `metrics.dataSource`. |
| `acl.file` | No | Path to the client allow-list file. Default: disabled (all clients allowed). |
| `commonName` | Yes | Common name for the proxy's own TLS certificate. Should match `dnsNames[0]`. |
| `tlsKeyFile` | No | Path of the file backing the proxy's own TLS private key. Default: `tls_key.pem` next to `ca.json`. The key is persisted and reused across restarts so the proxy's own certificate is served from cache instead of re-ordered from the upstream CA on every boot. |
| `disableChallengeValidation` | No | If `true`, acme-proxy marks client challenges (http-01/dns-01/tls-alpn-01) as valid without resolving or reaching the requesting client's domain; domain control is delegated to the upstream CA validation instead. This removes the split-DNS requirement for every new subdomain. **Security:** with this enabled, any host able to reach the ACME provisioner can obtain certificates for any name the upstream CA will issue, so restrict network access to the ACME endpoint accordingly. Default: `false`. |

# Admin Dashboard

The optional web dashboard (`dashboard` top-level block in `ca.json`) serves a complete operational console for the proxy: overview stats, a domain-grouped certificate view with per-domain request history (client IPs, timestamps, status, failure reasons, validity), failed-request details, revocation history, the certificate cache (with per-domain cache deletion), a live ACME request log, the ACL editor, and a settings editor.

- **Access**: session login at `https://<host>:<dashboard.port>`; credentials default to `admin`/`kambing`; change them via settings or config.
- **TLS**: by default the dashboard **shares the exact certificate served on the client-facing `:443` listener** (same persistent key + `dnsNames` identity resolved through the shared cert cache), so enabling the dashboard never causes an extra upstream issuance. The certificate is kept on disk beside the store, renewed in the background when older than `tls_max_age_days` (default 30) or close to expiry, and swapped in without a restart. Alternatively pin your own pair with `tls_cert` + `tls_key`.
- **Data**: history is read from the sidecar bbolt store (`dashboard.data_source`, defaulting to `metrics.dataSource`). Client IP attribution and failure reasons are recorded for requests handled by this version; records created before the feature existed show em-dashes.
- The dashboard listener is independent of the ACME, challenge, and metrics listeners, so it cannot interfere with certificate issuance.

# Access Control List

The optional `acl` top-level block points at a plain-text allow-list that gates **every ACME API request** by client IP. A ready-to-copy example lives at [acl.txt.example](https://github.com/esnet/acme-proxy/blob/main/acl.txt.example):

```text
# ACME client allow-list: one IP or CIDR subnet per line.
192.168.100.1           # a single host
192.168.100.0/24        # a subnet
192.168.100.16/28       # a smaller range
```

- **Hot reload**: the file is re-read whenever it changes on disk, so edits apply to the next request with no restart needed. It can also be edited from the dashboard (ACL tab), which validates entries before saving.
- **Client IP resolution**: the first `X-Forwarded-For` value is used when present (reverse-proxy deployments), otherwise the socket peer address.
- **Failure mode**: a configured file that cannot be read fails closed (all requests denied) with an error logged. Omitting the `acl` block disables the feature entirely.
- Denied requests receive an ACME `unauthorized` error naming the blocked client address.

# Runtime Settings

The dashboard's **Settings** tab edits a safe subset of `ca.json` through a form (upstream CA identity, challenge type and DNS provider, timeouts, cache bounds, dashboard credentials, ACL path). On save the daemon:

1. validates the merged configuration end-to-end (invalid values are rejected without touching the file),
2. writes a backup to `ca.json.bak-settings` and rewrites `ca.json` (note: `#` comments are replaced by a generated header; the commented original stays in the backup), and
3. **hot-applies everything without a restart**: config swap, ACME account re-registration when the upstream identity changed, challenge provider rebuild (listener ports take effect on the next challenge), live concurrency-limit resize, dashboard credential change, and dashboard listener rebind when port/bind/TLS files changed.

Changes persist in `ca.json`, so a later daemon restart uses the same values.

# Step-CA

step-ca is a swiss army knife of PKI. To see a full set of supported features and configuration options from step-ca please see to their [official documentation](https://smallstep.com/docs/step-ca/configuration/)
