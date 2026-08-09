+++
title = 'Configure'
weight = 30
BookToC = true
+++

# Required Configuration

Since acme-proxy uses step-ca as the ACME server much of the required configuration options are set by step-ca itself. `acme-proxy` supports two modes - **eab** and **dns01_txt**. To get a certificate signed from an upstream CA, you must configure atleast _one of_ `eab` or `dns01_txt` modes. Depending on the upstream CA, you may need to configure both. 

```json {hl_lines=["13-22"]}
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
      "ca_url": "",
      "account_email": "",
      "eab_kid": "",
      "eab_hmac_key": "",
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


## Field Reference

Fields under `authority.config` are specific to acme-proxy.

| Field | Required | Description |
|-------|----------|-------------|
| `address` | Yes | Listen address. `:443` binds all interfaces on port 443. |
| `dnsNames` | Yes | Hostname(s) that this proxy is reachable at. acme-proxy requests a TLS cert for itself using these names on first start. |
| `db.type` | Yes | Persistent KV data source to store ACME challenge state information |
| `db.dataSource` | Yes | Path to the bbolt KV store directory. Must be writable by the service user. |
| `authority.config.ca_url` | Yes | ACME directory URL of your upstream certificate authority. |
| `authority.config.account_email` | Yes | Email registered with the upstream CA. |
| `authority.config.certlifetime` | No | Request certificate with a max lifetime period if supported by upstream CA |
| `authority.config.eab_kid` | Yes | External Account Binding Key ID, obtained from your CA's account portal. |
| `authority.config.eab_hmac_key` | Yes | External Account Binding HMAC key, obtained from your CA's account portal. |
| `authority.config.dns01_txt.provider` | Yes | [Lego Provider](https://go-acme.github.io/lego/dns/index.html) CLI Flag  |
| `authority.config.dns01_txt.dns_servers` | No | Use your authoritative DNS server's addresses to avoid caching/TTL problems |
| `authority.config.dns01_txt.env_vars` | Yes | Environment variables specific to your Lego DNS Provider for authentication |
| `authority.config.metrics.port` | No | Metrics port. Default: `9234`. |
| `authority.config.metrics.datasource` | No | Prometheus metrics datastore. Default: `/opt/acme-proxy/db/metrics`. |
| `commonName` | Yes | Common name for the proxy's own TLS certificate. Should match `dnsNames[0]`. |

### Upstream CA URLs

These are some commonly used certificate authorities which provide an ACME endpoint. 

| CA | ACME URL |
|----|----------|
| CertiNext | https://acme-us.certinext.io/v1/directory
| Sectigo OV | `https://acme.sectigo.com/v2/OV` |
| LetsEncrypt | `https://acme-v02.api.letsencrypt.org/directory` |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` |

# Step-CA 

step-ca is a swiss army knife of PKI. To see a full set of supported features and configuration options from `step-ca` please see to their [official documentation](https://smallstep.com/docs/step-ca/configuration/)
