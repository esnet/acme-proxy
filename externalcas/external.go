package externalcas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/smallstep/certificates/cas/apiv1"
)

func init() {
	apiv1.Register(apiv1.ExternalCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
}

func New(ctx context.Context, opts apiv1.Options) (*ExternalCAS, error) {
	cas := &ExternalCAS{ctx: ctx}
	cfg, err := parseConfig(opts.Config)
	if err != nil {
		return nil, err
	}
	cas.cfg = cfg
	if cfg.useDNS01 {
		for k, v := range cfg.Lego.Env_Vars {
			os.Setenv(k, v)
		}
		provider, err := dns.NewDNSChallengeProviderByName(cfg.Lego.Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS provider %q: %w", cfg.Lego.Provider, err)
		}
		cas.dnsProvider = provider
	}
	if err := StartMetricsServer(cfg.Metrics, cfg.CaURL); err != nil {
		return nil, err
	}
	return cas, nil
}

// validateCreateCertificateRequest validates that a CreateCertificateRequest has required fields
func validateCreateCertificateRequest(req *apiv1.CreateCertificateRequest) error {
	if req.CSR == nil {
		return errors.New("csr cannot be nil")
	}
	if req.Template == nil {
		return errors.New("cert template cannot be nil")
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

// certificateResult holds the result of an async certificate operation
type certificateResult struct {
	response *apiv1.CreateCertificateResponse
	duration time.Duration // time ObtainForCSR took; used for metrics
	err      error
}

// ExternalCAS implements the CertificateAuthorityService interface using an external CA
type ExternalCAS struct {
	ctx         context.Context
	cfg         *acmeProxyConfig
	dnsProvider challenge.Provider
}

func (c *ExternalCAS) Type() apiv1.Type {
	return apiv1.ExternalCAS
}

// createLegoClient creates a fresh lego ACME client with clean state.
// This ensures no stale nonces or other protocol state from previous requests.
func (c *ExternalCAS) createLegoClient(cfg *acmeProxyConfig) (ACMEClient, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	user := &User{
		Email: cfg.Email,
		key:   privateKey,
	}

	// Configure lego client
	clientConfig := lego.NewConfig(user)
	clientConfig.CADirURL = cfg.CaURL
	clientConfig.Certificate.KeyType = certcrypto.EC256 // gitleaks:allow
	clientConfig.Certificate.Timeout = cfg.ObtainTimeout()
	clientConfig.HTTPClient = &http.Client{
		Timeout: cfg.HTTPTimeout(),
	}

	// Create lego client
	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Lego provider configuration when using dns01 challenge
	if cfg.useDNS01 {
		var opts []dns01.ChallengeOption
		if len(cfg.Lego.DnsServersList) > 0 {
			opts = append(opts, dns01.AddRecursiveNameservers(cfg.Lego.DnsServersList))
		}
		if err := client.Challenge.SetDNS01Provider(c.dnsProvider, opts...); err != nil {
			return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
		}
	}

	// Account registration — EAB takes precedence when configured
	if cfg.useEAB {
		regStart := time.Now()
		reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  cfg.Kid,
			HmacEncoded:          cfg.HmacKey,
		})
		if metricsEnabled {
			acmeRoundtripDuration.WithLabelValues("register").Observe(time.Since(regStart).Seconds())
		}
		if err != nil {
			return nil, fmt.Errorf("lego acme client registration failed with CA: %w", err)
		}
		user.Registration = reg
	} else {
		regStart := time.Now()
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if metricsEnabled {
			acmeRoundtripDuration.WithLabelValues("register").Observe(time.Since(regStart).Seconds())
		}
		if err != nil {
			return nil, fmt.Errorf("lego acme client registration failed with CA: %w", err)
		}
		user.Registration = reg
	}

	// Wrap in our interface adapter
	return &legoClientAdapter{certClient: client.Certificate}, nil
}

// CreateCertificate requests a certificate from the external ACME CA
func (c *ExternalCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	if err := validateCreateCertificateRequest(req); err != nil {
		return nil, err
	}

	// Create a fresh ACME client for this request
	// This eliminates any stale nonce or protocol state issues
	slog.Debug("creating fresh ACME client for certificate request")
	acmeClient, err := c.createLegoClient(c.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego ACME client: %w", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, c.cfg.RequestTimeout())
	defer cancel()

	slog.Info("processing certificate request", "domains", req.CSR.DNSNames)

	// Build certificate request
	csrRequest := certificate.ObtainForCSRRequest{
		CSR:    req.CSR,
		Bundle: true,
	}
	if c.cfg.CertLifetime > 0 {
		csrRequest.NotAfter = time.Now().Add(time.Duration(c.cfg.CertLifetime) * 24 * time.Hour)
		slog.Debug("using configured certificate lifetime", "days", c.cfg.CertLifetime)
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

		start := time.Now()
		cert, err := acmeClient.ObtainForCSR(csrRequest)
		duration := time.Since(start)

		if err != nil {
			resultChan <- &certificateResult{
				err:      fmt.Errorf("failed to obtain certificate: %w", err),
				duration: duration,
			}
			return
		}

		leaf, intermediates, err := splitCertificateBundle(cert.Certificate)
		if err != nil {
			resultChan <- &certificateResult{
				err:      fmt.Errorf("failed to split certificate bundle: %w", err),
				duration: duration,
			}
			return
		}

		resultChan <- &certificateResult{
			response: &apiv1.CreateCertificateResponse{
				Certificate:      leaf,
				CertificateChain: intermediates,
			},
			duration: duration,
		}
	}()

	select {
	case result := <-resultChan:
		if result.err != nil {
			if metricsEnabled {
				certificatesIssuedTotal.WithLabelValues("failure").Inc()
				certificateRequestDuration.WithLabelValues("issue").Observe(result.duration.Seconds())
				acmeRoundtripDuration.WithLabelValues("obtain").Observe(result.duration.Seconds())
				if req.CSR != nil {
					if err := globalStore.recordIssued(CertRecord{
						CommonName:      req.CSR.Subject.CommonName,
						SANs:            strings.Join(req.CSR.DNSNames, ","),
						DurationSeconds: result.duration.Seconds(),
						Status:          "failure",
					}); err != nil {
						slog.Error("failed to record cert issuance failure", "error", err)
					}
				}
			}
			return nil, result.err
		}
		slog.Info("obtained certificate from external CA", "domains", req.CSR.DNSNames)
		if metricsEnabled {
			certificatesIssuedTotal.WithLabelValues("success").Inc()
			certificateRequestDuration.WithLabelValues("issue").Observe(result.duration.Seconds())
			acmeRoundtripDuration.WithLabelValues("obtain").Observe(result.duration.Seconds())
			cert := result.response.Certificate
			lifetime := cert.NotAfter.Sub(cert.NotBefore).Seconds()
			certificateExpirationTime.WithLabelValues("issued").Observe(lifetime)
			lastSuccessfulCertificateTimestamp.SetToCurrentTime()
			if err := globalStore.recordIssued(CertRecord{
				Serial:          cert.SerialNumber.Text(16),
				CommonName:      cert.Subject.CommonName,
				Issuer:          cert.Issuer.CommonName,
				SANs:            strings.Join(cert.DNSNames, ","),
				IssuedAt:        cert.NotBefore,
				ExpiresAt:       cert.NotAfter,
				DurationSeconds: result.duration.Seconds(),
				Status:          "success",
			}); err != nil {
				slog.Error("failed to record cert issuance", "error", err)
			}
		}
		return result.response, nil
	case <-ctx.Done():
		if metricsEnabled {
			certificatesIssuedTotal.WithLabelValues("failure").Inc()
			if req.CSR != nil {
				if err := globalStore.recordIssued(CertRecord{
					CommonName: req.CSR.Subject.CommonName,
					SANs:       strings.Join(req.CSR.DNSNames, ","),
					Status:     "failure",
				}); err != nil {
					slog.Error("failed to record cert issuance timeout", "error", err)
				}
			}
		}
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

	// Create a fresh ACME client for this revocation request
	slog.Debug("creating fresh ACME client for certificate revocation")
	acmeClient, err := c.createLegoClient(c.cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Convert DER-encoded certificate to PEM (lego expects PEM)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: req.Certificate.Raw,
	})

	slog.Info(
		"revoking certificate",
		"serial", req.Certificate.SerialNumber.String(),
		"subject", req.Certificate.Subject.CommonName,
	)

	revokeStart := time.Now()
	revokeErr := acmeClient.Revoke(pemBytes)
	revokeDuration := time.Since(revokeStart)

	if revokeErr != nil {
		slog.Error(
			"failed to revoke certificate",
			"serial", req.Certificate.SerialNumber.String(),
			"error", revokeErr,
		)
		if metricsEnabled {
			certificatesRevokedTotal.WithLabelValues("failure").Inc()
			certificateRequestDuration.WithLabelValues("revoke").Observe(revokeDuration.Seconds())
			acmeRoundtripDuration.WithLabelValues("revoke").Observe(revokeDuration.Seconds())
			cert := req.Certificate
			if err := globalStore.recordRevoked(CertRecord{
				Serial:          cert.SerialNumber.Text(16),
				CommonName:      cert.Subject.CommonName,
				Issuer:          cert.Issuer.CommonName,
				SANs:            strings.Join(cert.DNSNames, ","),
				IssuedAt:        cert.NotBefore,
				ExpiresAt:       cert.NotAfter,
				DurationSeconds: revokeDuration.Seconds(),
				Status:          "failure",
			}); err != nil {
				slog.Error("failed to record cert revocation failure", "error", err)
			}
		}
		return nil, fmt.Errorf("failed to revoke certificate: %w", revokeErr)
	}

	slog.Info(
		"certificate revoked successfully",
		"serial", req.Certificate.SerialNumber.String(),
	)
	if metricsEnabled {
		certificatesRevokedTotal.WithLabelValues("success").Inc()
		certificateRequestDuration.WithLabelValues("revoke").Observe(revokeDuration.Seconds())
		acmeRoundtripDuration.WithLabelValues("revoke").Observe(revokeDuration.Seconds())
		cert := req.Certificate
		if err := globalStore.recordRevoked(CertRecord{
			Serial:          cert.SerialNumber.Text(16),
			CommonName:      cert.Subject.CommonName,
			Issuer:          cert.Issuer.CommonName,
			SANs:            strings.Join(cert.DNSNames, ","),
			IssuedAt:        cert.NotBefore,
			ExpiresAt:       cert.NotAfter,
			DurationSeconds: revokeDuration.Seconds(),
			Status:          "success",
		}); err != nil {
			slog.Error("failed to record cert revocation", "error", err)
		}
	}

	return &apiv1.RevokeCertificateResponse{
		Certificate: req.Certificate,
	}, nil
}
