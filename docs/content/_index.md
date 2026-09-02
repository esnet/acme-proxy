+++
title = 'acme-proxy'
+++

## What is acme-proxy?

`acme-proxy` allows users to get certificates from any certificate authority that supports ACME protocol (such as LetsEncrypt, Sectigo, Digicert etc.) without opening http/80 to the internet _or_ distributing api keys for your DNS server! This is a standalone ACME server built on [step-ca](https://github.com/smallstep/certificates) that operates in [registration authority (RA)](https://smallstep.com/docs/registration-authorities/) mode. It accepts certificate orders and validates certificate requests using the ACME protocol (RFC 8555), but does **NOT** sign certificates or store private keys.

## Certificate Issuance Flow

`acme-proxy` runs as an ACME server inside your trusted network, acting as an intermediary between your internal infrastructure and an upstream certificate authority which signs the certificate. 

1. Your internal server (behind a firewall perimeter) requests a certificate from `acme-proxy` using a standard ACME client such as certbot, acme.sh or cert-manager.io if you're using Kubernetes.
2. `acme-proxy` presents cryptographic challenges to verify domain ownership.
3. Once validation succeeds, `acme-proxy` forwards the certificate signing request to an external certificate authority for signing.
4. `acme-proxy` retrieves the signed certificate bundle and returns it to your server.

{{< image src="/assets/sequence.png" alt="sequence" >}}

<br>To get signed certificates from an external CA `acme-proxy` supports two modes of operations:

### 1. External Account Binding (EAB)

Some commercial certificate authorities allow their customers to do a one time validation for their apex domain (example.com) and issue a key associated with their account called as external account binding key (EAB). Using this key customers may be able to get certs for *.example.com without having to perform validation for every domain or subdomain (say foo.example.com) individually. 

{{< image src="/assets/highlevel-flow.png" alt="sequence" >}}

**Note:** LetsEncrypt does not support EAB. However, commercial CAs such as Sectigo, ZeroSSL, DigiCert do.

### 2. DNS01-TXT

`acme-proxy` carries [Lego](https://go-acme.github.io/lego/) as a Go dependency which is a well known ACME client that supports over 200 DNS providers to solve ACME challenges. Using one of the Lego providers, acme-proxy authenticates with your DNS server and temporarily places a TXT record which the external CA can verify before issuing a signed certificate. The key benefit of using this mode is that your DNS server's API key or TSIG key lives only on acme-proxy and thus circumvents the need for distributing and rotating those credentials across your infrastructure. 

![DNS01-TXT](/assets/dns01-txt.png)

**Note:** Using this mode also allows users to get signed certificates from LetsEncrypt!

## Connectivity Requirements

For the ACME certificate request issuance, renewal flow to work correctly, make sure your any internal firewalls, ACLs, IPtables rules permit the following traffic.

### Client to acme-proxy (HTTPS/443)

Your servers running certbot must be able to connect to acme-proxy over HTTPS.

```
Source          myserver.example.com
Destination     acme-proxy.example.com
Protocol        https (443)
Action          allow
```

### acme-proxy to Client (HTTP/80)

`acme-proxy` validates HTTP-01 challenges by connecting to your servers directly on port 80. Your servers must allow inbound HTTP/80 from acme-proxy's IP, not from the public internet. This is the key security benefit: your servers' HTTP/80 exposure is limited to a trusted internal host rather than the global internet which is the case when using LetsEncrypt.

```
Source          acme-proxy.example.com
Destination     myserver.example.com
Protocol        http (80)
Action          allow
```

### Upstream CA to acme-proxy (HTTP/80, http-01 mode only)

This is the opposite direction of the flow above and applies only when `challenge_type` is `http-01` (or `auto` without a DNS provider): the upstream CA (e.g. Let's Encrypt) connects to acme-proxy's public IP on port 80 to validate the challenge. Two properties keep this safe:

- The listener exists **only while a certificate request is in flight**. It starts when the request begins and closes automatically once the last challenge completes, so nothing listens on port 80 while the proxy is idle.
- While running it serves **only ACME challenge token responses**, with no general-purpose web service or application code behind it.

If your policy forbids exposing port 80 even for these short windows, use `dns-01` or EAB toward the upstream CA instead; neither requires any inbound port 80.

```
Source          upstream CA validation servers
Destination     acme-proxy public IP
Protocol        http (80)
Action          allow (http-01 mode only; not needed for dns-01/EAB)
```
