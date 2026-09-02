package externalcas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/smallstep/certificates/cas/apiv1"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	opts := apiv1.Options{
		Type: "externalcas",
		Config: mustMarshalConfig(t, &acmeProxyConfig{
			CaURL:   "https://acme.example.com",
			Kid:     "test-kid",
			HmacKey: "test-hmac",
		}),
	}

	cas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	want := "externalcas"
	got := cas.Type().String()

	if got != want {
		t.Fatalf("want: %s; got %s", want, got)
	}
}

func TestNew_ValidatesConfig(t *testing.T) {
	tests := []struct {
		name   string
		config []byte
		errMsg string
	}{
		{
			name:   "empty config bytes",
			config: []byte(""),
			errMsg: "failed to unmarshal config",
		},
		{
			name:   "missing ca_url",
			config: mustMarshalConfig(t, &acmeProxyConfig{Kid: "k", HmacKey: "h"}),
			errMsg: "ca_url is required",
		},
		{
			name: "partial metrics — port only",
			config: mustMarshalConfig(t, &acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "k",
				HmacKey: "h",
				Metrics: metrics{Port: 9234},
			}),
			errMsg: "invalid metrics port or dataSource",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(context.Background(), apiv1.Options{Config: tt.config})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %q, want error containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestNew_DNS01OnlyConfig(t *testing.T) {
	// "manual" is the one Lego provider that requires no env vars and no network calls.
	// It satisfies dns.NewDNSChallengeProviderByName without hitting any external service.
	cfg := mustMarshalConfig(t, &acmeProxyConfig{
		CaURL: "https://acme.example.com",
		Lego: legoConfig{
			Provider: "manual",
			Env_Vars: map[string]string{"DUMMY": "1"},
		},
	})
	cas, err := New(context.Background(), apiv1.Options{Config: cfg})
	if err != nil {
		t.Fatalf("New() with DNS01-only config returned unexpected error: %v", err)
	}
	if cas == nil {
		t.Fatal("New() returned nil ExternalCAS")
	}
	if cas.dnsProvider == nil {
		t.Error("dnsProvider should be set for DNS01-only config")
	}
}

func TestNew_HTTP01FallbackConfig(t *testing.T) {
	cfg := mustMarshalConfig(t, &acmeProxyConfig{
		CaURL: "https://acme.example.com",
	})
	cas, err := New(context.Background(), apiv1.Options{Config: cfg})
	if err != nil {
		t.Fatalf("New() with HTTP01 fallback config returned unexpected error: %v", err)
	}
	if cas == nil {
		t.Fatal("New() returned nil ExternalCAS")
	}
	if cas.dnsProvider != nil {
		t.Error("dnsProvider should be nil for HTTP01 fallback config")
	}
}

func Test_validateCreateCertificateRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *apiv1.CreateCertificateRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: &apiv1.CreateCertificateRequest{
				CSR:      &x509.CertificateRequest{},
				Template: &x509.Certificate{},
			},
			wantErr: false,
		},
		{
			name: "nil CSR",
			req: &apiv1.CreateCertificateRequest{
				CSR:      nil,
				Template: &x509.Certificate{},
			},
			wantErr: true,
			errMsg:  "csr cannot be nil",
		},
		{
			name: "nil Template",
			req: &apiv1.CreateCertificateRequest{
				CSR:      &x509.CertificateRequest{},
				Template: nil,
			},
			wantErr: true,
			errMsg:  "template cannot be nil",
		},
		{
			name: "both nil",
			req: &apiv1.CreateCertificateRequest{
				CSR:      nil,
				Template: nil,
			},
			wantErr: true,
			errMsg:  "csr cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateCertificateRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreateCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateCreateCertificateRequest() error = %q, want error containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func Test_validateRevokeCertificateRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *apiv1.RevokeCertificateRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid request",
			req: &apiv1.RevokeCertificateRequest{
				Certificate: &x509.Certificate{},
			},
			wantErr: false,
		},
		{
			name:    "nil request",
			req:     nil,
			wantErr: true,
			errMsg:  "certificate cannot be nil",
		},
		{
			name: "nil certificate",
			req: &apiv1.RevokeCertificateRequest{
				Certificate: nil,
			},
			wantErr: true,
			errMsg:  "certificate cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRevokeCertificateRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRevokeCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateRevokeCertificateRequest() error = %q, want error containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestCreateCertificate_Validation(t *testing.T) {
	extcas := &ExternalCAS{ctx: context.Background()}

	tests := []struct {
		name    string
		req     *apiv1.CreateCertificateRequest
		wantErr string
	}{
		{
			name:    "nil CSR returns error",
			req:     &apiv1.CreateCertificateRequest{CSR: nil, Template: &x509.Certificate{}},
			wantErr: "csr cannot be nil",
		},
		{
			name:    "nil Template returns error",
			req:     &apiv1.CreateCertificateRequest{CSR: &x509.CertificateRequest{}, Template: nil},
			wantErr: "template cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extcas.CreateCertificate(tt.req)

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestCreateCertificate_WithMock(t *testing.T) {
	// Create a mock ACME client that returns a test certificate
	mockClient := &mockACMEClient{
		obtainFunc: func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			// Return a test certificate bundle (leaf + intermediate)
			chain := createTestCertPEM(t, 1)
			chain = append(chain, createTestCertPEM(t, 2)...)
			return &certificate.Resource{Certificate: chain}, nil
		},
	}

	// Create a mock ExternalCAS that uses our mock client
	cas := newTestCAS(t, &acmeProxyConfig{
		CaURL:        "https://acme.test.com",
		Email:        "test@example.com",
		Kid:          "test-kid",
		HmacKey:      "test-hmac",
		CertLifetime: 30,
	}, mockClient)

	// Create a test CSR
	csr := &x509.CertificateRequest{
		DNSNames: []string{"test.example.com"},
	}
	req := &apiv1.CreateCertificateRequest{
		CSR:      csr,
		Template: &x509.Certificate{},
	}

	// Process the request
	resp, err := cas.CreateCertificate(req)
	// Verify the result
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Certificate == nil {
		t.Error("expected leaf certificate")
	}
	if len(resp.CertificateChain) != 1 {
		t.Errorf("expected 1 intermediate certificate, got %d", len(resp.CertificateChain))
	}
}

func TestCreateCertificate_WithMock_Error(t *testing.T) {
	// Create a mock ACME client that returns an error
	mockClient := &mockACMEClient{
		obtainFunc: func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			return nil, errors.New("ACME server error")
		},
	}

	cas := newTestCAS(t, &acmeProxyConfig{
		CaURL:   "https://acme.test.com",
		Email:   "test@example.com",
		Kid:     "test-kid",
		HmacKey: "test-hmac",
	}, mockClient)

	csr := &x509.CertificateRequest{
		DNSNames: []string{"test.example.com"},
	}
	req := &apiv1.CreateCertificateRequest{
		CSR:      csr,
		Template: &x509.Certificate{},
	}

	_, err := cas.CreateCertificate(req)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ACME server error") {
		t.Errorf("expected error containing 'ACME server error', got: %v", err)
	}
}

func TestCreateCertificate_Timeout(t *testing.T) {
	// Create a mock client that takes too long
	mockClient := &mockACMEClient{
		obtainFunc: func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			time.Sleep(5 * time.Second)
			return nil, errors.New("should not reach here")
		},
	}

	// Use a short-lived parent context so the real CreateCertificate's
	// internal WithTimeout deadline fires quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cas := &ExternalCAS{
		ctx: ctx,
		sem: newDynamicSem(1),
		newACMEClient: func(*acmeProxyConfig) (ACMEClient, error) {
			return mockClient, nil
		},
	}
	cas.cfg.Store(&acmeProxyConfig{
		CaURL:   "https://acme.test.com",
		Email:   "test@example.com",
		Kid:     "test-kid",
		HmacKey: "test-hmac",
	})

	csr := &x509.CertificateRequest{
		DNSNames: []string{"test.example.com"},
	}
	req := &apiv1.CreateCertificateRequest{
		CSR:      csr,
		Template: &x509.Certificate{},
	}

	_, err := cas.CreateCertificate(req)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func Test_splitCertificateBundle(t *testing.T) {
	tests := []struct {
		name             string
		createBundle     func(t *testing.T) []byte
		wantLeafSerial   int64
		wantIntermediate int
		wantErr          bool
		errMsg           string
	}{
		{
			name: "valid 3-cert bundle",
			createBundle: func(t *testing.T) []byte {
				var chain []byte
				chain = append(chain, createTestCertPEM(t, 1)...)
				chain = append(chain, createTestCertPEM(t, 2)...)
				chain = append(chain, createTestCertPEM(t, 3)...)
				return chain
			},
			wantLeafSerial:   1,
			wantIntermediate: 2,
			wantErr:          false,
		},
		{
			name: "single cert (no intermediates)",
			createBundle: func(t *testing.T) []byte {
				return createTestCertPEM(t, 1)
			},
			wantLeafSerial:   1,
			wantIntermediate: 0,
			wantErr:          false,
		},
		{
			name: "empty bundle",
			createBundle: func(t *testing.T) []byte {
				return []byte("")
			},
			wantErr: true,
			errMsg:  "no certificates found",
		},
		{
			name: "invalid PEM data",
			createBundle: func(t *testing.T) []byte {
				return []byte("not a certificate")
			},
			wantErr: true,
			errMsg:  "no certificates found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := tt.createBundle(t)

			leaf, intermediates, err := splitCertificateBundle(bundle)

			if (err != nil) != tt.wantErr {
				t.Errorf("splitCertificateBundle() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}

			if leaf == nil {
				t.Fatal("expected non-nil leaf certificate")
			}

			if leaf.SerialNumber.Int64() != tt.wantLeafSerial {
				t.Errorf("leaf serial = %d, want %d", leaf.SerialNumber.Int64(), tt.wantLeafSerial)
			}

			if len(intermediates) != tt.wantIntermediate {
				t.Errorf("intermediates count = %d, want %d", len(intermediates), tt.wantIntermediate)
			}
		})
	}
}

func TestRevokeCertificate_Validation(t *testing.T) {
	extcas := &ExternalCAS{ctx: context.Background()}

	tests := []struct {
		name    string
		req     *apiv1.RevokeCertificateRequest
		wantErr string
	}{
		{
			name:    "nil request returns error",
			req:     nil,
			wantErr: "certificate cannot be nil",
		},
		{
			name:    "nil certificate returns error",
			req:     &apiv1.RevokeCertificateRequest{Certificate: nil},
			wantErr: "certificate cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extcas.RevokeCertificate(tt.req)

			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestRenewCertificate_NotImplemented(t *testing.T) {
	cas := &ExternalCAS{ctx: context.Background()}

	_, err := cas.RenewCertificate(&apiv1.RenewCertificateRequest{})
	if err == nil {
		t.Fatal("expected NotImplementedError, got nil")
	}

	var notImplErr apiv1.NotImplementedError
	if !errors.As(err, &notImplErr) {
		t.Errorf("expected NotImplementedError, got %T: %v", err, err)
	}
}

// mockACMEClient is a mock implementation of ACMEClient for testing
type mockACMEClient struct {
	obtainFunc func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error)
	revokeFunc func([]byte) error
}

func (m *mockACMEClient) ObtainForCSR(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
	if m.obtainFunc != nil {
		return m.obtainFunc(ctx, req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockACMEClient) Revoke(ctx context.Context, pemBytes []byte) error {
	if m.revokeFunc != nil {
		return m.revokeFunc(pemBytes)
	}
	return errors.New("not implemented")
}

// newTestCAS builds an ExternalCAS that uses the provided mock ACME client via
// the newACMEClient override, exercising the real CreateCertificate and
// RevokeCertificate methods.
func newTestCAS(t *testing.T, cfg *acmeProxyConfig, mock ACMEClient) *ExternalCAS {
	t.Helper()
	cas := &ExternalCAS{
		ctx: context.Background(),
		sem: newDynamicSem(cfg.MaxConcurrentRequestsOrDefault()),
		newACMEClient: func(*acmeProxyConfig) (ACMEClient, error) {
			return mock, nil
		},
	}
	cas.cfg.Store(cfg)
	return cas
}

// Helper function that generates a self-signed test certificate in PEM format.
func createTestCertPEM(t *testing.T, serial int64) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating ecdsa key for test cert: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "Test Cert",
			Country:      []string{"US"},
			Organization: []string{"example.com"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"testcert.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("error creating test certificate: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	return pem.EncodeToMemory(pemBlock)
}

// mustMarshalConfig marshals a config or fails the test
func mustMarshalConfig(t *testing.T, cfg *acmeProxyConfig) []byte {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	return data
}

func TestUser_InterfaceMethods(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	reg := &acme.ExtendedAccount{Location: "https://acme.example.com/account/1"}

	u := &User{
		Email:        "test@example.com",
		Registration: reg,
		key:          key,
	}

	if got := u.GetEmail(); got != "test@example.com" {
		t.Errorf("GetEmail() = %q, want %q", got, "test@example.com")
	}

	if got := u.GetRegistration(); got != reg {
		t.Errorf("GetRegistration() = %v, want %v", got, reg)
	}

	if got := u.GetPrivateKey(); got != key {
		t.Errorf("GetPrivateKey() did not return the expected key")
	}
}

func TestUser_GetRegistration_Nil(t *testing.T) {
	u := &User{}
	if got := u.GetRegistration(); got != nil {
		t.Errorf("GetRegistration() = %v, want nil", got)
	}
}

// --- splitCertificateBundle(): mixed PEM block types (gap 14) ---

func Test_splitCertificateBundle_MixedPEMTypes(t *testing.T) {
	certPEM := createTestCertPEM(t, 1)

	// Interleave a PRIVATE KEY block before and after the certificate
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-real-key")})
	bundle := append(keyBlock, certPEM...)
	bundle = append(bundle, keyBlock...)

	leaf, intermediates, err := splitCertificateBundle(bundle)
	if err != nil {
		t.Fatalf("splitCertificateBundle() unexpected error: %v", err)
	}
	if leaf == nil {
		t.Fatal("expected non-nil leaf certificate")
	}
	if leaf.SerialNumber.Int64() != 1 {
		t.Errorf("leaf serial = %d, want 1", leaf.SerialNumber.Int64())
	}
	if len(intermediates) != 0 {
		t.Errorf("expected 0 intermediates, got %d", len(intermediates))
	}
}

// --- RevokeCertificate: success and error paths (gaps 15–16) ---

func TestRevokeCertificate_WithMock_Success(t *testing.T) {
	var revokedPEM []byte
	mockClient := &mockACMEClient{
		revokeFunc: func(pemBytes []byte) error {
			revokedPEM = pemBytes
			return nil
		},
	}

	cas := newTestCAS(t, &acmeProxyConfig{
		CaURL:   "https://acme.test.com",
		Kid:     "test-kid",
		HmacKey: "test-hmac",
	}, mockClient)

	cert := createTestCert(t, 42)
	req := &apiv1.RevokeCertificateRequest{Certificate: cert}

	resp, err := cas.RevokeCertificate(req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp == nil || resp.Certificate != cert {
		t.Error("expected response to contain the revoked certificate")
	}
	if len(revokedPEM) == 0 {
		t.Error("expected revokeFunc to be called with PEM bytes")
	}
}

func TestRevokeCertificate_WithMock_Error(t *testing.T) {
	mockClient := &mockACMEClient{
		revokeFunc: func(pemBytes []byte) error {
			return errors.New("ACME revocation refused")
		},
	}

	cas := newTestCAS(t, &acmeProxyConfig{
		CaURL:   "https://acme.test.com",
		Kid:     "test-kid",
		HmacKey: "test-hmac",
	}, mockClient)

	cert := createTestCert(t, 99)
	req := &apiv1.RevokeCertificateRequest{Certificate: cert}

	_, err := cas.RevokeCertificate(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "ACME revocation refused") {
		t.Errorf("expected error containing 'ACME revocation refused', got: %v", err)
	}
}

func TestCreateCertificate_Coalescing(t *testing.T) {
	var mu sync.Mutex
	callCount := 0

	// Pre-generate the chain outside the goroutines to avoid using t inside them.
	chain := createTestCertPEM(t, 1)
	chain = append(chain, createTestCertPEM(t, 2)...)

	mockClient := &mockACMEClient{
		obtainFunc: func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			mu.Lock()
			callCount++
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			return &certificate.Resource{Certificate: chain}, nil
		},
	}

	cfg := &acmeProxyConfig{
		CaURL:                 "https://acme.test.com",
		Email:                 "test@example.com",
		Kid:                   "test-kid",
		HmacKey:               "test-hmac",
		CertLifetime:          30,
		MaxConcurrentRequests: 4,
	}
	cas := newTestCAS(t, cfg, mockClient)

	csr := &x509.CertificateRequest{DNSNames: []string{"test.example.com"}}
	req := &apiv1.CreateCertificateRequest{CSR: csr, Template: &x509.Certificate{}}

	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = cas.CreateCertificate(req)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d error: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Errorf("ObtainForCSR called %d times, want 1 (coalescing)", callCount)
	}
}

func TestCreateCertificate_Serialization(t *testing.T) {
	var mu sync.Mutex
	var active, maxActive int

	chain := createTestCertPEM(t, 1)
	chain = append(chain, createTestCertPEM(t, 2)...)

	mockClient := &mockACMEClient{
		obtainFunc: func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			mu.Lock()
			active++
			if active > maxActive {
				maxActive = active
			}
			mu.Unlock()

			time.Sleep(50 * time.Millisecond)

			mu.Lock()
			active--
			mu.Unlock()

			return &certificate.Resource{Certificate: chain}, nil
		},
	}

	cfg := &acmeProxyConfig{
		CaURL:                 "https://acme.test.com",
		Email:                 "test@example.com",
		Kid:                   "test-kid",
		HmacKey:               "test-hmac",
		MaxConcurrentRequests: 1,
	}
	cas := newTestCAS(t, cfg, mockClient)

	// Two different-domain CSRs so singleflight does not coalesce them.
	reqs := []*apiv1.CreateCertificateRequest{
		{CSR: &x509.CertificateRequest{DNSNames: []string{"a.example.com"}}, Template: &x509.Certificate{}},
		{CSR: &x509.CertificateRequest{DNSNames: []string{"b.example.com"}}, Template: &x509.Certificate{}},
	}

	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Add(1)
		go func(r *apiv1.CreateCertificateRequest) {
			defer wg.Done()
			if _, err := cas.CreateCertificate(r); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}(r)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if maxActive > 1 {
		t.Errorf("max concurrent ObtainForCSR = %d, want 1 (serialized)", maxActive)
	}
}

// createTestCert returns a parsed *x509.Certificate (not just PEM bytes).
func createTestCert(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	pemBytes := createTestCertPEM(t, serial)
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}
	return cert
}
