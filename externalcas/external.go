package externalcas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/smallstep/certificates/cas/apiv1"
)

func init() {
	apiv1.Register(apiv1.ExternalCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

func New(ctx context.Context, opts apiv1.Options) (*ExternalCAS, error) {
	return &ExternalCAS{ctx: ctx, config: opts.Config}, nil
}

// AcmeProxyConfig contains the configuration for connecting to an external ACME CA
type AcmeProxyConfig struct {
	// ACME server url of External CA
	CaURL string `json:"ca_url"`

	// External Account Binding
	Email   string `json:"account_email,omitempty"`
	Kid     string `json:"eab_kid"`
	HmacKey string `json:"eab_hmac_key"`

	// Certificate lifetime in days
	CertLifetime int `json:"certlifetime,omitempty"`

	// Prometheus metrics endpoint
	Metrics Metrics `json:"metrics"`
}

// Validate checks if the AcmeProxyConfig contains required fields and valid values
func (c *AcmeProxyConfig) Validate() error {
	if c.CaURL == "" {
		return errors.New("ca_url is required")
	}
	if c.Kid == "" {
		return errors.New("eab_kid is required")
	}
	if c.HmacKey == "" {
		return errors.New("eab_hmac_key is required")
	}
	if c.CertLifetime < 0 {
		return errors.New("certlifetime cannot be negative")
	}
	return nil
}

// HTTPTimeout returns the timeout for HTTP client operations
func (c *AcmeProxyConfig) HTTPTimeout() time.Duration {
	return 90 * time.Second
}

// RequestTimeout returns the timeout for certificate request operations
func (c *AcmeProxyConfig) RequestTimeout() time.Duration {
	return 2 * time.Minute
}

type Metrics struct {
	Enabled bool `json:"enabled,omitempty"`
	Port    int  `json:"port,omitempty"`
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

// validateCreateCertificateRequest validates that a CreateCertificateRequest has required fields
func validateCreateCertificateRequest(req *apiv1.CreateCertificateRequest) error {
	if req.CSR == nil {
		return errors.New("CSR cannot be nil")
	}
	if req.Template == nil {
		return errors.New("template cannot be nil")
	}
	return nil
}

// validateRevokeCertificateRequest validates that a RevokeCertificateRequest has required fields
func validateRevokeCertificateRequest(req *apiv1.RevokeCertificateRequest) error {
	if req == nil || req.Certificate == nil {
		return errors.New("certificate cannot be nil")
	}
	return nil
}

// splitCertificateBundle splits a PEM-encoded certificate bundle into a leaf certificate
// and a chain of intermediate certificates. The first certificate in the bundle is treated
// as the leaf certificate, and all subsequent certificates are treated as intermediates.
func splitCertificateBundle(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := pemBytes

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certificates = append(certificates, cert)
		}

		remaining = rest
	}

	if len(certificates) == 0 {
		return nil, nil, errors.New("no certificates found in bundle")
	}

	leafCert := certificates[0]
	var intermediates []*x509.Certificate
	if len(certificates) > 1 {
		intermediates = certificates[1:]
	}

	return leafCert, intermediates, nil
}

// certificateResult holds the result of an async certificate operation
type certificateResult struct {
	response *apiv1.CreateCertificateResponse
	err      error
}

// ExternalCAS implements the CertificateAuthorityService interface using an external ACME CA
type ExternalCAS struct {
	ctx    context.Context
	config json.RawMessage
}

func (c *ExternalCAS) Type() apiv1.Type {
	return apiv1.ExternalCAS
}

// parseConfig parses and validates the configuration
func (c *ExternalCAS) parseConfig() (*AcmeProxyConfig, error) {
	var cfg AcmeProxyConfig
	if err := json.Unmarshal(c.config, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

// createLegoClient creates a fresh lego ACME client with clean state.
// This ensures no stale nonces or other protocol state from previous requests.
func (c *ExternalCAS) createLegoClient(cfg *AcmeProxyConfig) (ACMEClient, error) {
	// Generate ECDSA P-256 key for ACME account
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	user := &User{
		Email: cfg.Email,
		key:   privateKey,
	}

	// Configure lego client
	config := lego.NewConfig(user)
	config.CADirURL = cfg.CaURL
	config.Certificate.KeyType = certcrypto.EC256
	config.HTTPClient = &http.Client{
		Timeout: cfg.HTTPTimeout(),
	}

	// Create lego client
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Register with External Account Binding
	reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  cfg.Kid,
		HmacEncoded:          cfg.HmacKey,
	})
	if err != nil {
		return nil, fmt.Errorf("EAB registration failed: %w", err)
	}
	user.Registration = reg

	// Wrap in our interface adapter
	return &legoClientAdapter{certClient: client.Certificate}, nil
}

// CreateCertificate requests a certificate from the external ACME CA
func (c *ExternalCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	if err := validateCreateCertificateRequest(req); err != nil {
		return nil, err
	}

	cfg, err := c.parseConfig()
	if err != nil {
		return nil, err
	}

	// Create a fresh ACME client for this request
	// This eliminates any stale nonce or protocol state issues
	slog.Debug("creating fresh ACME client for certificate request")
	acmeClient, err := c.createLegoClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, cfg.RequestTimeout())
	defer cancel()

	slog.Info("processing certificate request", "domains", req.CSR.DNSNames)

	// Build certificate request
	csrRequest := certificate.ObtainForCSRRequest{
		CSR:    req.CSR,
		Bundle: true,
	}
	if cfg.CertLifetime > 0 {
		csrRequest.NotAfter = time.Now().Add(time.Duration(cfg.CertLifetime) * 24 * time.Hour)
		slog.Debug("using configured certificate lifetime", "days", cfg.CertLifetime)
	}

	// Request certificate with context timeout
	resultChan := make(chan *certificateResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("panic in certificate request", "panic", r)
				resultChan <- &certificateResult{
					err: fmt.Errorf("internal error: %v", r),
				}
			}
		}()

		cert, err := acmeClient.ObtainForCSR(csrRequest)
		if err != nil {
			resultChan <- &certificateResult{
				err: fmt.Errorf("failed to obtain certificate: %w", err),
			}
			return
		}

		leaf, intermediates, err := splitCertificateBundle(cert.Certificate)
		if err != nil {
			resultChan <- &certificateResult{
				err: fmt.Errorf("failed to split certificate bundle: %w", err),
			}
			return
		}

		resultChan <- &certificateResult{
			response: &apiv1.CreateCertificateResponse{
				Certificate:      leaf,
				CertificateChain: intermediates,
			},
		}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			return nil, result.err
		}
		slog.Info("obtained certificate from external CA", "domains", req.CSR.DNSNames)
		return result.response, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("certificate request timed out: %w", ctx.Err())
	}
}

// RenewCertificate is not implemented as certificate renewals are handled via CreateCertificate
// with a new CSR containing the same certificate parameters.
func (c *ExternalCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{}
}

// RevokeCertificate revokes a certificate via the external ACME CA
func (c *ExternalCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	if err := validateRevokeCertificateRequest(req); err != nil {
		return nil, err
	}

	cfg, err := c.parseConfig()
	if err != nil {
		return nil, err
	}

	// Create a fresh ACME client for this revocation request
	slog.Debug("creating fresh ACME client for certificate revocation")
	acmeClient, err := c.createLegoClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Convert DER-encoded certificate to PEM (lego expects PEM)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: req.Certificate.Raw,
	})

	slog.Info("revoking certificate",
		"serial", req.Certificate.SerialNumber.String(),
		"subject", req.Certificate.Subject.CommonName,
	)

	if err := acmeClient.Revoke(pemBytes); err != nil {
		slog.Error("failed to revoke certificate",
			"serial", req.Certificate.SerialNumber.String(),
			"error", err,
		)
		return nil, fmt.Errorf("failed to revoke certificate: %w", err)
	}

	slog.Info("certificate revoked successfully",
		"serial", req.Certificate.SerialNumber.String(),
	)

	return &apiv1.RevokeCertificateResponse{
		Certificate: req.Certificate,
	}, nil
}
