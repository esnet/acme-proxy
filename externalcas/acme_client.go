package externalcas

import (
	"context"
	"crypto"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
)

// ACMEClient abstracts ACME certificate operations for testability.
// This interface allows injecting mock implementations for testing without
// requiring actual network calls to ACME servers.
type ACMEClient interface {
	// ObtainForCSR obtains a certificate for the given CSR
	ObtainForCSR(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error)

	// Revoke revokes a certificate given its PEM-encoded bytes
	Revoke(ctx context.Context, pemBytes []byte) error
}

// legoClientAdapter adapts the lego certificate client to our ACMEClient interface.
// This adapter wraps the lego client's Certificate service and implements our interface.
type legoClientAdapter struct {
	certClient interface {
		ObtainForCSR(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error)
		Revoke(ctx context.Context, pemBytes []byte) error
	}
}

// ObtainForCSR implements ACMEClient.ObtainForCSR by delegating to the lego client
func (a *legoClientAdapter) ObtainForCSR(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
	return a.certClient.ObtainForCSR(ctx, req)
}

// Revoke implements ACMEClient.Revoke by delegating to the lego client
func (a *legoClientAdapter) Revoke(ctx context.Context, pemBytes []byte) error {
	return a.certClient.Revoke(ctx, pemBytes)
}

// User implements the lego registration.User interface
type User struct {
	Email        string
	Registration *acme.ExtendedAccount
	key          crypto.Signer
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.Signer {
	return u.key
}
