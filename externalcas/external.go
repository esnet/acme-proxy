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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
	"github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/cas/apiv1"
	"golang.org/x/sync/singleflight"

	"github.com/esnet/acme-proxy/acl"
	"github.com/esnet/acme-proxy/reqmeta"
)

func init() {
	apiv1.Register(apiv1.ExternalCAS, func(ctx context.Context, opts apiv1.Options) (apiv1.CertificateAuthorityService, error) {
		return New(ctx, opts)
	})
	// Feed client IPs from the fork's ACME API layer into reqmeta so
	// issuance and revocation records can be attributed to a client.
	api.RequestMetaHook = reqmeta.Record
	// Enforce the file-based client allow-list (no-op until configured).
	api.RequestACLHook = acl.AllowedRequest
}

// New creates an ExternalCAS from the given options.
func New(ctx context.Context, opts apiv1.Options) (*ExternalCAS, error) {
	cas := &ExternalCAS{ctx: ctx}
	cfg, err := parseConfig(opts.Config)
	if err != nil {
		return nil, err
	}
	cas.cfg.Store(cfg)
	currentCAS.Store(cas)

	// Top-level ca.json blocks (dashboard, acl) — outside "authority".
	top := loadTopLevelConfig()
	if err := top.Dashboard.validate(cfg.Metrics); err != nil {
		return nil, err
	}
	if top.ACL.File != "" {
		acl.SetFile(top.ACL.File)
		slog.Info("acl enabled", "file", top.ACL.File)
	}

	// Create the shared challenge providers once, based on the resolved
	// challenge type. The settings reload rebuilds them on change.
	if err := cas.setChallengeProviders(cfg); err != nil {
		return nil, err
	}

	cas.sem = newDynamicSem(cfg.MaxConcurrentRequestsOrDefault())
	cas.newACMEClient = cas.createLegoClient

	// Open the shared sidecar cert store when metrics or the dashboard
	// needs it. The store is opened once per process.
	if globalStore == nil {
		ds := cfg.Metrics.DataSource
		if ds == "" {
			ds = top.Dashboard.DataSource
		}
		if ds != "" {
			s, err := newCertStore(ds)
			if err != nil {
				return nil, fmt.Errorf("failed to open cert store: %w", err)
			}
			globalStore = s
		}
	}

	if err := StartMetricsServer(cfg.Metrics, cfg.CaURL); err != nil {
		return nil, err
	}
	if err := startDashboardServer(cas, cfg, top.Dashboard); err != nil {
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
	certPEM  []byte        // raw PEM bundle from lego (leaf + chain)
	duration time.Duration // time ObtainForCSR took; used for metrics
	err      error
}

// ExternalCAS implements the CertificateAuthorityService interface using an external CA
type ExternalCAS struct {
	ctx context.Context
	// cfg is the active authority config; swapped atomically by the
	// dashboard settings reload so in-flight requests keep a stable view.
	cfg atomic.Pointer[acmeProxyConfig]

	// challengeMu guards challengeProvider/dnsProvider so the settings
	// reload can rebuild them when the challenge config changes.
	challengeMu       sync.RWMutex
	dnsProvider       challenge.Provider
	challengeProvider challenge.Provider

	// sem caps the number of simultaneous upstream ACME operations;
	// its capacity is hot-swapped by the settings reload.
	sem *dynamicSem

	// sf coalesces concurrent identical certificate requests so only one
	// upstream order is performed.
	sf singleflight.Group

	// account is the cached ACME account (registered at most once per process).
	acctMu  sync.Mutex
	account *User

	// newACMEClient builds an ACMEClient; overridable in tests.
	newACMEClient func(*acmeProxyConfig) (ACMEClient, error)
}

func (c *ExternalCAS) Type() apiv1.Type {
	return apiv1.ExternalCAS
}

// getOrCreateAccount returns the cached ACME account, registering a new one
// (with a fresh ECDSA key) the first time it is called. Registration happens
// at most once per process; on failure nothing is cached so the next request
// retries.
func (c *ExternalCAS) getOrCreateAccount() (*User, error) {
	c.acctMu.Lock()
	defer c.acctMu.Unlock()

	if c.account != nil {
		return c.account, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	user := &User{
		Email: c.conf().Email,
		key:   privateKey,
	}

	// Configure lego client
	clientConfig := lego.NewConfig(user)
	clientConfig.CADirURL = c.conf().CaURL
	clientConfig.Certificate.Timeout = c.conf().CertPollTimeoutDuration()
	clientConfig.HTTPClient = &http.Client{
		Timeout: c.conf().HTTPTimeout(),
	}

	// Create lego client
	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Account registration — EAB takes precedence when configured
	regStart := time.Now()
	if c.conf().useEAB {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(c.ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  c.conf().Kid,
			HmacEncoded:          c.conf().HmacKey,
		})
		if metricsEnabled {
			acmeRoundtripDuration.WithLabelValues("register").Observe(time.Since(regStart).Seconds())
		}
		if err != nil {
			return nil, fmt.Errorf("lego acme client registration failed with CA: %w", err)
		}
		user.Registration = reg
	} else {
		reg, err := client.Registration.Register(c.ctx, registration.RegisterOptions{
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

	c.account = user
	return user, nil
}

// createLegoClient builds a lego ACME client using the cached account and the
// shared challenge provider. No registration happens here.
func (c *ExternalCAS) createLegoClient(cfg *acmeProxyConfig) (ACMEClient, error) {
	user, err := c.getOrCreateAccount()
	if err != nil {
		return nil, err
	}

	// Configure lego client
	clientConfig := lego.NewConfig(user)
	clientConfig.CADirURL = cfg.CaURL
	clientConfig.Certificate.Timeout = cfg.CertPollTimeoutDuration()
	clientConfig.HTTPClient = &http.Client{
		Timeout: cfg.HTTPTimeout(),
	}

	// Create lego client
	client, err := lego.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Attach the shared challenge provider by resolved challenge type.
	challengeProvider, dnsProvider := c.challengeProviderForClient()
	switch cfg.challengeType {
	case "dns-01":
		// Recursive nameservers are configured on the shared dns01 client
		// (v5 removed AddRecursiveNameservers as a per-client option).
		if len(cfg.Lego.DnsServersList) > 0 {
			dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{
				RecursiveNameservers: cfg.Lego.DnsServersList,
			}))
		}
		if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
			return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
		}
	case "http-01":
		if err := client.Challenge.SetHTTP01Provider(challengeProvider); err != nil {
			return nil, fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	case "tls-alpn-01":
		if err := client.Challenge.SetTLSALPN01Provider(challengeProvider); err != nil {
			return nil, fmt.Errorf("failed to set TLS-ALPN-01 provider: %w", err)
		}
	}

	// Wrap in our interface adapter
	return &legoClientAdapter{certClient: client.Certificate}, nil
}

// recordIssue persists an issuance record to the sidecar store when open.
func recordIssue(r CertRecord) {
	if globalStore == nil {
		return
	}
	if err := globalStore.recordIssued(r); err != nil {
		slog.Error("failed to record issuance", "error", err)
	}
}

// recordRevoke persists a revocation record to the sidecar store when open.
func recordRevoke(r CertRecord) {
	if globalStore == nil {
		return
	}
	if err := globalStore.recordRevoked(r); err != nil {
		slog.Error("failed to record revocation", "error", err)
	}
}

// CreateCertificate requests a certificate from the external ACME CA
func (c *ExternalCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	if err := validateCreateCertificateRequest(req); err != nil {
		return nil, err
	}

	// Attribute this issuance to the ACME client that submitted the CSR.
	// Consumed once, before singleflight, so coalesced requests share it.
	clientIP := reqmeta.LookupFinalize(req.CSR)

	// Check certificate cache before requesting from external CA.
	// The cached leaf must carry the CSR's public key: a certificate is
	// bound to its key, and callers (e.g. step-ca bootstrap) may present
	// a fresh key on every start.
	if globalStore != nil && len(req.CSR.DNSNames) > 0 {
		if cached := globalStore.findCachedCert(req.CSR.DNSNames); cached != nil && cached.matchesCSR(req.CSR) && cacheFreshEnough(cached, c.conf()) {
			remaining := time.Until(cached.ExpiresAt)
			slog.Info("returning cached certificate",
				"domains", req.CSR.DNSNames,
				"serial", cached.Serial,
				"expires", cached.ExpiresAt.Format(time.RFC3339),
				"remaining", remaining.Round(time.Second))
			if metricsEnabled {
				certificatesIssuedTotal.WithLabelValues("cache_hit").Inc()
			}
			return cached.toResponse()
		}
	}

	// Create the context BEFORE singleflight so both the queue-wait and the
	// upstream obtain share the same deadline.
	ctx, cancel := context.WithTimeout(c.ctx, c.conf().RequestTimeoutDuration())
	defer cancel()

	// Coalesce concurrent identical requests: exactly one upstream order is
	// performed and all callers receive the same response/error.
	v, err, _ := c.sf.Do(cacheKey(req.CSR.DNSNames), func() (any, error) {
		// Re-check the cache: a just-finished identical request may have
		// already cached the certificate. Key match is required for the
		// same reason as the outer check.
		if globalStore != nil && len(req.CSR.DNSNames) > 0 {
			if cached := globalStore.findCachedCert(req.CSR.DNSNames); cached != nil && cached.matchesCSR(req.CSR) && cacheFreshEnough(cached, c.conf()) {
				return cached.toResponse()
			}
		}

		// Acquire the concurrency semaphore, respecting the request context.
		semCh, err := c.sem.acquire(ctx)
		if err != nil {
			return nil, err
		}
		defer c.sem.release(semCh)

		// Create a fresh ACME client for this request.
		slog.Debug("creating fresh ACME client for certificate request")
		acmeClient, err := c.newACMEClient(c.conf())
		if err != nil {
			return nil, fmt.Errorf("failed to create lego ACME client: %w", err)
		}

		slog.Info("processing certificate request", "domains", req.CSR.DNSNames)

		// Build certificate request
		csrRequest := certificate.ObtainForCSRRequest{
			CSR:    req.CSR,
			Bundle: true,
		}
		if c.conf().CertLifetime > 0 {
			csrRequest.NotAfter = time.Now().Add(time.Duration(c.conf().CertLifetime) * 24 * time.Hour)
			slog.Debug("using configured certificate lifetime", "days", c.conf().CertLifetime)
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
				certPEM:  cert.Certificate,
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
				}
				recordIssue(CertRecord{
					CommonName:      req.CSR.Subject.CommonName,
					SANs:            strings.Join(req.CSR.DNSNames, ","),
					DurationSeconds: result.duration.Seconds(),
					Status:          "failure",
					ClientIP:        clientIP,
					Error:           result.err.Error(),
				})
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
			}
			recordIssue(CertRecord{
				Serial:          result.response.Certificate.SerialNumber.Text(16),
				CommonName:      result.response.Certificate.Subject.CommonName,
				Issuer:          result.response.Certificate.Issuer.CommonName,
				SANs:            strings.Join(result.response.Certificate.DNSNames, ","),
				IssuedAt:        result.response.Certificate.NotBefore,
				ExpiresAt:       result.response.Certificate.NotAfter,
				DurationSeconds: result.duration.Seconds(),
				Status:          "success",
				ClientIP:        clientIP,
			})
			// Cache the certificate for future requests
			if globalStore != nil && result.response != nil && len(result.certPEM) > 0 {
				cert := result.response.Certificate
				if err := globalStore.cacheCert(CertRecord{
					Serial:          cert.SerialNumber.Text(16),
					CommonName:      cert.Subject.CommonName,
					Issuer:          cert.Issuer.CommonName,
					SANs:            strings.Join(cert.DNSNames, ","),
					IssuedAt:        cert.NotBefore,
					ExpiresAt:       cert.NotAfter,
					DurationSeconds: result.duration.Seconds(),
					Status:          "success",
					CertPEM:         result.certPEM,
				}); err != nil {
					slog.Error("failed to cache certificate", "error", err)
				}
			}
			return result.response, nil
		case <-ctx.Done():
			if metricsEnabled {
				certificatesIssuedTotal.WithLabelValues("failure").Inc()
			}
			recordIssue(CertRecord{
				CommonName: req.CSR.Subject.CommonName,
				SANs:       strings.Join(req.CSR.DNSNames, ","),
				Status:     "failure",
				ClientIP:   clientIP,
				Error:      fmt.Sprintf("certificate request timed out: %v", ctx.Err()),
			})
			return nil, fmt.Errorf("certificate request timed out: %w", ctx.Err())
		}
	})

	if err != nil {
		return nil, err
	}
	resp, ok := v.(*apiv1.CreateCertificateResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected result type from singleflight: %T", v)
	}
	return resp, nil
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

	ctx, cancel := context.WithTimeout(c.ctx, c.conf().RequestTimeoutDuration())
	defer cancel()

	// Acquire the concurrency semaphore, respecting the request context.
	semCh, err := c.sem.acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("certificate revocation timed out: %w", err)
	}
	defer c.sem.release(semCh)

	// Create a fresh ACME client for this revocation request
	slog.Debug("creating fresh ACME client for certificate revocation")
	acmeClient, err := c.newACMEClient(c.conf())
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Attribute this revocation to the ACME client that requested it.
	clientIP := reqmeta.LookupRevoke(req.Certificate.SerialNumber.String())

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
	revokeErr := acmeClient.Revoke(ctx, pemBytes)
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
		}
		recordRevoke(CertRecord{
			Serial:          req.Certificate.SerialNumber.Text(16),
			CommonName:      req.Certificate.Subject.CommonName,
			Issuer:          req.Certificate.Issuer.CommonName,
			SANs:            strings.Join(req.Certificate.DNSNames, ","),
			IssuedAt:        req.Certificate.NotBefore,
			ExpiresAt:       req.Certificate.NotAfter,
			DurationSeconds: revokeDuration.Seconds(),
			Status:          "failure",
			ClientIP:        clientIP,
			Error:           revokeErr.Error(),
		})
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
	}
	recordRevoke(CertRecord{
		Serial:          req.Certificate.SerialNumber.Text(16),
		CommonName:      req.Certificate.Subject.CommonName,
		Issuer:          req.Certificate.Issuer.CommonName,
		SANs:            strings.Join(req.Certificate.DNSNames, ","),
		IssuedAt:        req.Certificate.NotBefore,
		ExpiresAt:       req.Certificate.NotAfter,
		DurationSeconds: revokeDuration.Seconds(),
		Status:          "success",
		ClientIP:        clientIP,
	})

	return &apiv1.RevokeCertificateResponse{
		Certificate: req.Certificate,
	}, nil
}
