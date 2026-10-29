package externalcas

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
	"github.com/go-acme/lego/v5/registration"
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
	key, err := loadAccountKey(cfg.AccountKeyFile)
	if err != nil {
		return nil, err
	}
	cas.account = &User{Email: cfg.Email, key: key}
	if cfg.useDNS01 {
		for k, v := range cfg.Lego.Env_Vars {
			os.Setenv(k, v)
		}
		provider, err := dns.NewDNSChallengeProviderByName(cfg.Lego.Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to create DNS provider %q: %w", cfg.Lego.Provider, err)
		}
		cas.dnsProvider = provider

		// When DNS servers are configured, use them as the recursive nameservers lego
		// queries to confirm the challenge TXT record has propagated, instead of the
		// host's default resolver.
		if len(cfg.Lego.DnsServersList) > 0 {
			dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{
				RecursiveNameservers: cfg.Lego.DnsServersList,
			}))
		}
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

	// account is the single upstream ACME account shared by every request.
	// accountMu guards its one-time resolution or registration.
	accountMu sync.Mutex
	account   *User
}

func (c *ExternalCAS) Type() apiv1.Type {
	return apiv1.ExternalCAS
}

// createLegoClient creates a fresh lego ACME client with clean state.
// This ensures no stale nonces or other protocol state from previous requests.
// Every client shares the same upstream account, resolved or registered once.
func (c *ExternalCAS) createLegoClient(cfg *acmeProxyConfig) (ACMEClient, error) {
	if err := c.ensureAccount(cfg); err != nil {
		return nil, err
	}
	client, err := c.newLegoClient(cfg)
	if err != nil {
		return nil, err
	}
	return &legoClientAdapter{certClient: client.Certificate}, nil
}

// ensureAccount looks up the upstream account for the account key and registers
// it if the lookup fails. Registering is safe either way: RFC 8555 §7.3 requires
// a CA to return the existing account when the key is already registered, which
// covers CAs that do not support the lookup. It runs once per process; a failed
// attempt is retried on the next request.
func (c *ExternalCAS) ensureAccount(cfg *acmeProxyConfig) error {
	c.accountMu.Lock()
	defer c.accountMu.Unlock()
	if c.account.Registration != nil {
		return nil
	}

	client, err := c.newLegoClient(cfg)
	if err != nil {
		return err
	}

	regStart := time.Now()
	reg, lookupErr := client.Registration.ResolveAccountByKey(c.ctx)
	if lookupErr != nil {
		var problem *acme.ProblemDetails
		if !errors.As(lookupErr, &problem) || problem.Type != acme.AccountDoesNotExistErrorType {
			slog.Warn("upstream account lookup failed; registering instead", "error", lookupErr)
		}
		reg, err = registerAccount(c.ctx, client, cfg)
	}
	if metricsEnabled {
		acmeRoundtripDuration.WithLabelValues("register").Observe(time.Since(regStart).Seconds())
	}
	if err != nil {
		return fmt.Errorf("lego acme client registration failed with CA: %w", errors.Join(err, lookupErr))
	}

	slog.Info("using upstream ACME account", "account", reg.Location)
	c.account.Registration = reg
	return nil
}

// registerAccount creates a new upstream account, binding it to the EAB
// credentials when configured.
func registerAccount(ctx context.Context, client *lego.Client, cfg *acmeProxyConfig) (*acme.ExtendedAccount, error) {
	if cfg.useEAB {
		return client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  cfg.Kid,
			HmacEncoded:          cfg.HmacKey,
		})
	}
	return client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
}

// newLegoClient builds a lego client for the shared upstream account.
func (c *ExternalCAS) newLegoClient(cfg *acmeProxyConfig) (*lego.Client, error) {
	clientConfig := lego.NewConfig(c.account)
	clientConfig.CADirURL = cfg.CaURL
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
		if err := client.Challenge.SetDNS01Provider(c.dnsProvider); err != nil {
			return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
		}
	}
	return client, nil
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
		cert, err := acmeClient.ObtainForCSR(ctx, csrRequest)
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
	revokeErr := acmeClient.Revoke(c.ctx, pemBytes)
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
