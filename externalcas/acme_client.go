package externalcas

import (
	"crypto"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
)

// ACMEClient abstracts ACME certificate operations for testability.
// This interface allows injecting mock implementations for testing without
// requiring actual network calls to ACME servers.
type ACMEClient interface {
	// ObtainForCSR obtains a certificate for the given CSR
	ObtainForCSR(req certificate.ObtainForCSRRequest) (*certificate.Resource, error)

	// Revoke revokes a certificate given its PEM-encoded bytes
	Revoke(pemBytes []byte) error
}

// legoClientAdapter adapts the lego certificate client to our ACMEClient interface.
// This adapter wraps the lego client's Certificate service and implements our interface.
type legoClientAdapter struct {
	certClient interface {
		ObtainForCSR(certificate.ObtainForCSRRequest) (*certificate.Resource, error)
		Revoke([]byte) error
	}
}

// ObtainForCSR implements ACMEClient.ObtainForCSR by delegating to the lego client
func (a *legoClientAdapter) ObtainForCSR(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
	return a.certClient.ObtainForCSR(req)
}

// Revoke implements ACMEClient.Revoke by delegating to the lego client
func (a *legoClientAdapter) Revoke(pemBytes []byte) error {
	return a.certClient.Revoke(pemBytes)
}

// User implements the lego registration.User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
