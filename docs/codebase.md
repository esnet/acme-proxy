## How is the codebase organized ?

### External Certificate Authority Service (ExternalCAS)

`Step CA` is written in Go and the package provides an interface called `CertificateAuthorityService` [CAS](https://github.com/smallstep/certificates/tree/master/cas) to support external certificate authorities as the signing body. The code in `incommoncas` and `letsencryptcas` dir implements the `CertificateAuthorityService` interface.

```go
type CertificateAuthorityService interface {
    CreateCertificate(req *CreateCertificateRequest) (*CreateCertificateResponse, error)
    RenewCertificate(req *RenewCertificateRequest) (*RenewCertificateResponse, error)
    RevokeCertificate(req *RevokeCertificateRequest) (*RevokeCertificateResponse, error)
}
```

The go package also defines a special type called `ExternalCAS` for this exact purpose. Which is why our [ca.json](ca.json) file defines an authority of `type: externalcas`.

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
