+++
title = 'ACME Proxy'
+++

# What is ACME Proxy?

`acme-proxy` is a standalone ACME server built on [step-ca](https://github.com/smallstep/certificates) that operates in [registration authority (RA)](https://smallstep.com/docs/registration-authorities/) mode. It accepts certificate orders and validates certificate requests using the ACME protocol (RFC 8555), but does **NOT** sign certificates or store private keys.

It runs as a standalone server inside your enterprise environment, acting as an intermediary between your internal infrastructure and an external certificate authority service (such as Sectigo).

**Certificate Request Flow:**

1. Your internal server (behind a firewall perimeter) requests a certificate from `acme-proxy` using standard ACME clients like certbot, acme.sh or cert-manager.io if you're using Kubernetes.
2. `acme-proxy` presents cryptographic challenges to verify domain ownership
3. Once validation succeeds, `acme-proxy` forwards the certificate signing request to your external CA using External Account Binding (EAB)
4. The external CA signs the certificate
5. `acme-proxy` retrieves the certificate bundle and returns it to your server

{{< image src="../assets/sequence.png" alt="sequence" >}}
