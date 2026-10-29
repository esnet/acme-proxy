package externalcas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

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
		ObtainForCSR(context.Context, certificate.ObtainForCSRRequest) (*certificate.Resource, error)
		Revoke(context.Context, []byte) error
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

// loadAccountKey returns the PEM-encoded EC upstream account key stored at path,
// creating the file on first start if it is missing. Persisting the key keeps the
// same account across restarts, which CAs with single-use EAB keys (Google Trust
// Services) require. With no path it generates a key for this process only, so
// every restart registers a new upstream account.
func loadAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		slog.Warn("account_key_file is not set; a new upstream ACME account will be registered on every restart")
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	keyPEM, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createAccountKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("reading account key file: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("account key file %s does not contain a PEM block", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("account key file %s is not a valid EC private key: %w", path, err)
	}
	slog.Info("using upstream ACME account key", "path", path)
	return key, nil
}

// createAccountKey generates a key and writes it to path. O_EXCL guarantees an
// existing key is never overwritten, and a partially written file is removed so
// the next start does not find a corrupt key.
func createAccountKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding account key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating account key file: %w", err)
	}
	_, err = f.Write(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("writing account key file: %w", errors.Join(err, os.Remove(path)))
	}
	slog.Info("created upstream ACME account key", "path", path)
	return key, nil
}

// User implements the lego registration.User interface
type User struct {
	Email        string
	Registration *acme.ExtendedAccount
	key          *ecdsa.PrivateKey
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
