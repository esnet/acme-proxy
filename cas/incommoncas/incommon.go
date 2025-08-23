package incommoncas

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
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

func New(ctx context.Context, opts apiv1.Options) (*InCommonCAS, error) {
	return &InCommonCAS{ctx: ctx, config: opts.Config}, nil
}

type EabConfig struct {
	CaURL   string `json:"ca_url,omitempty"`
	Email   string `json:"account_email,omitempty"`
	Kid     string `json:"eab_kid,omitempty"`
	HmacKey string `json:"eab_hmac_key,omitempty"`
}

type InCommonCAS struct {
	ctx       context.Context
	client    *lego.Client
	user      *SectigoUser
	initOnce  sync.Once
	initError error
	config    json.RawMessage
}

type certificateResult struct {
	response *apiv1.CreateCertificateResponse
	err      error
}

func (c *InCommonCAS) Type() apiv1.Type {
	return apiv1.ExternalCAS
}

func (c *InCommonCAS) initClient() error {
	c.initOnce.Do(func() {
		log.Println("Initializing ACME client...")

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			c.initError = fmt.Errorf("failed to generate private key: %w", err)
			return
		}

		// Unmarshal EAB config from ca.json
		var eab EabConfig
		if err = json.Unmarshal(c.config, &eab); err != nil {
			log.Fatal("unable to unmarshall EAB config from ca.json", err)
		}

		user := SectigoUser{
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

		log.Println("ACME client initialized successfully")
	})
	return c.initError
}

func (c *InCommonCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	if req.CSR == nil {
		return nil, errors.New("CSR cannot be nil")
	}
	if req.Template == nil {
		return nil, errors.New("template cannot be nil")
	}

	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Minute)
	defer cancel()

	if err := c.initClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize ACME client: %w", err)
	}

	log.Printf("Processing certificate request for domains: %v", req.CSR.DNSNames)

	resultChan := make(chan *certificateResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic in processCertificateRequest: %v", r)
				resultChan <- &certificateResult{
					err: fmt.Errorf("internal error: %v", r),
				}
			}
		}()
		result := c.processCertificateRequest(ctx, req)

		select {
		case resultChan <- result:
		case <-ctx.Done():
			log.Printf("Certificate request timed out or cancelled for domains: %v", req.CSR.DNSNames)
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

func (c *InCommonCAS) processCertificateRequest(ctx context.Context, req *apiv1.CreateCertificateRequest) *certificateResult {
	log.Printf("Starting certificate request processing for domains: %v", req.CSR.DNSNames)

	select {
	case <-ctx.Done():
		return &certificateResult{
			err: fmt.Errorf("request cancelled before processing: %v", ctx.Err()),
		}
	default:
	}

	cert, err := c.client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:    req.CSR,
		Bundle: true,
	})
	if err != nil {
		return &certificateResult{
			err: fmt.Errorf("failed to obtain certificate from InCommon: %v", err),
		}
	}

	log.Printf("Successfully obtained certificate from InCommon for domains: %v", req.CSR.DNSNames)

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

func (c *InCommonCAS) splitCertificateBundle(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
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

// using `certbot renew` basically generates a new CSR with same certificate config options like SubjAltName
// which is already covered by the CreateCertificate function. certificate renewals seem to be working as is right now
// TODO : Investigate if implementing this function is required or not
func (c *InCommonCAS) RenewCertificate(req *apiv1.RenewCertificateRequest) (*apiv1.RenewCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{}
}

// TODO : Implement revocation if it's supported via Sectigo API
func (c *InCommonCAS) RevokeCertificate(req *apiv1.RevokeCertificateRequest) (*apiv1.RevokeCertificateResponse, error) {
	return nil, apiv1.NotImplementedError{}
}
