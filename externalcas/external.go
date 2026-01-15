package externalcas

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
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

type Metrics struct {
	Enabled bool `json:"enabled,omitempty"`
	Port    int  `json:"port,omitempty"`
}

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

type certificateResult struct {
	response *apiv1.CreateCertificateResponse
	err      error
}

type ExternalCAS struct {
	ctx       context.Context
	client    *lego.Client
	user      *User
	initOnce  sync.Once
	initError error
	config    json.RawMessage
}

func (c *ExternalCAS) Type() apiv1.Type {
	return apiv1.ExternalCAS
}

func (c *ExternalCAS) initClient() error {
	c.initOnce.Do(func() {
		slog.Info("initializing ACME client")

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			c.initError = fmt.Errorf("failed to generate private key: %w", err)
			return
		}

		// Unmarshal EAB config from ca.json
		var eab AcmeProxyConfig
		if err = json.Unmarshal(c.config, &eab); err != nil {
			slog.Error("failed to unmarshal EAB config", "error", err)
			c.initError = fmt.Errorf("failed to unmarshal EAB config: %w", err)
			return
		}

		user := User{
			Email: eab.Email,
			key:   privateKey,
		}
		c.user = &user

		config := lego.NewConfig(&user)
		config.CADirURL = eab.CaURL
		config.Certificate.KeyType = certcrypto.RSA2048

		// Set a timeout-aware HTTP client
		config.HTTPClient = &http.Client{
			Timeout: 90 * time.Second,
		}

		client, err := lego.NewClient(config)
		if err != nil {
			c.initError = fmt.Errorf("failed to create lego client: %w", err)
			return
		}
		c.client = client

		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  eab.Kid,
			HmacEncoded:          eab.HmacKey,
		})
		if err != nil {
			c.initError = fmt.Errorf("EAB registration failed: %w", err)
			return
		}
		c.user.Registration = reg

		slog.Info("ACME client initialized")
	})
	return c.initError
}

func (c *ExternalCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	if req.CSR == nil {
		return nil, errors.New("CSR cannot be nil")
	}
	if req.Template == nil {
		return nil, errors.New("template cannot be nil")
	}

	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()

	if err := c.initClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize ACME client: %w", err)
	}

	slog.Info("processing certificate request", "domains", req.CSR.DNSNames)

	resultChan := make(chan *certificateResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("recovered from panic in processCertificateRequest", "panic", r)
				resultChan <- &certificateResult{
					err: fmt.Errorf("internal error: %v", r),
				}
			}
		}()
		result := c.processCertificateRequest(ctx, req)

		select {
		case resultChan <- result:
		case <-ctx.Done():
			slog.Warn("certificate request timed out or cancelled", "domains", req.CSR.DNSNames)
		}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			return nil, result.err
		}
		return result.response, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("certificate request timed out or cancelled: %w", ctx.Err())
	}
}

func (c *ExternalCAS) processCertificateRequest(ctx context.Context, req *apiv1.CreateCertificateRequest) *certificateResult {
	slog.Debug("starting certificate request processing", "domains", req.CSR.DNSNames)

	select {
	case <-ctx.Done():
		return &certificateResult{
			err: fmt.Errorf("request cancelled before processing: %v", ctx.Err()),
		}
	default:
	}

	var cfg AcmeProxyConfig
	if err := json.Unmarshal(c.config, &cfg); err != nil {
		return &certificateResult{
			err: fmt.Errorf("failed to parse acmeproxy config: %v", err),
		}
	}

	// Build certificate request - only set NotAfter if CertLifetime is configured
	csrRequest := certificate.ObtainForCSRRequest{
		CSR:    req.CSR,
		Bundle: true,
	}
	if cfg.CertLifetime > 0 {
		csrRequest.NotAfter = time.Now().Add(time.Duration(cfg.CertLifetime) * 24 * time.Hour)
		slog.Debug("using configured certificate lifetime", "days", cfg.CertLifetime)
	}

	cert, err := c.client.Certificate.ObtainForCSR(csrRequest)
	if err != nil {
		return &certificateResult{
			err: fmt.Errorf("failed to obtain certificate from InCommon: %v", err),
		}
	}

	slog.Info("obtained certificate from external CA", "domains", req.CSR.DNSNames)

	leaf, intermediates, err := c.splitCertificateBundle(cert.Certificate)
	if err != nil {
		return &certificateResult{
			err: fmt.Errorf("failed to split certificate bundle: %v", err),
		}
	}

	return &certificateResult{
		response: &apiv1.CreateCertificateResponse{
			Certificate:      leaf,
			CertificateChain: intermediates,
		},
	}
}

func (c *ExternalCAS) splitCertificateBundle(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
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
				return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			certificates = append(certificates, cert)
		}

		remaining = rest
	}

	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in chain")
	}

	leafCert := certificates[0]
	var intermediates []*x509.Certificate
	if len(certificates) > 1 {
		intermediates = certificates[1:]
	}

	return leafCert, intermediates, nil
}

// using `certbot renew` simply generates a new CSR with same certificate config options like SubjAltName
// which is already covered by CreateCertificate(). Certificate renewals seem to be working without implementing this function
func (c *ExternalCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{}
}

func (c *ExternalCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	if req == nil || req.Certificate == nil {
		return nil, errors.New("certificate cannot be nil")
	}

	if err := c.initClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize ACME client: %w", err)
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

	if err := c.client.Certificate.Revoke(pemBytes); err != nil {
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
