# ACME server as Registration Authority

See [upstream docs](#upstream-docs) section for more background on what registration authority, CAS are and how those concepts fits into step-ca architecture.

## Certificate Authority Service (CAS)

CAS provides a plugin based architecture that allows Step CA to delegate certificate signing to different backends - whether that's Google Cloud, HashiCorp Vault, or in our case, external certificate authorities like Sectigo or ZeroSSL. ACME proxy can be run as a standalone ACME server in Registraiton Authority mode

### ExternalCAS

`Step CA` provides an interface called `CertificateAuthorityService` [CAS](https://github.com/smallstep/certificates/tree/master/cas) to support external certificate authorities as the signing body. Our code in `externalcas` simply implements the `CertificateAuthorityService` interface.

```go
type CertificateAuthorityService interface {
    CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
    RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
    RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
}
```

The go package also defines a special type called `ExternalCAS` for this exact purpose. Which is why our [ca.json](../ca.json) file defines an authority of `type: externalcas`.

```go
const (
    // DefaultCAS is a CertificateAuthorityService using software.
    DefaultCAS = ""
    // SoftCAS is a CertificateAuthorityService using software.
    SoftCAS = "softcas"
    // CloudCAS is a CertificateAuthorityService using Google Cloud CAS.
    CloudCAS = "cloudcas"
    // StepCAS is a CertificateAuthorityService using another step-ca instance.
    StepCAS = "stepcas"
    // VaultCAS is a CertificateAuthorityService using Hasicorp Vault PKI.
    VaultCAS = "vaultcas"
    // ExternalCAS is a CertificateAuthorityService using an external injected CA implementation
    ExternalCAS = "externalcas"
)
```

## Upstream docs

**Step CA github repo**
<https://github.com/smallstep/certificates/tree/master>

**Step CA Registration Authority (RA)**
<https://smallstep.com/docs/step-ca/registration-authority-ra-mode/>

**RA related github discussions**

- <https://github.com/smallstep/certificates/discussions/884>
- <https://github.com/smallstep/certificates/issues/343>

**Step CA full configuration options**
<https://smallstep.com/docs/step-ca/configuration/>

**Certificate issuance policy configuration**
<https://smallstep.com/docs/step-ca/policies/>
