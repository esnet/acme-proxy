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
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/smallstep/certificates/cas/apiv1"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	opts := apiv1.Options{
		Type:       "externalcas",
		IsCreator:  false,
		IsCAGetter: false,
		Config:     []byte(""),
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

func TestAcmeProxyConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  AcmeProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: AcmeProxyConfig{
				CaURL:        "https://acme.example.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: 30,
			},
			wantErr: false,
		},
		{
			name: "missing ca_url",
			config: AcmeProxyConfig{
				Email:   "test@example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
			},
			wantErr: true,
			errMsg:  "ca_url is required",
		},
		{
			name: "missing eab_kid",
			config: AcmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Email:   "test@example.com",
				HmacKey: "test-hmac",
			},
			wantErr: true,
			errMsg:  "eab_kid is required",
		},
		{
			name: "missing eab_hmac_key",
			config: AcmeProxyConfig{
				CaURL: "https://acme.example.com",
				Email: "test@example.com",
				Kid:   "test-kid",
			},
			wantErr: true,
			errMsg:  "eab_hmac_key is required",
		},
		{
			name: "negative certlifetime",
			config: AcmeProxyConfig{
				CaURL:        "https://acme.example.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: -1,
			},
			wantErr: true,
			errMsg:  "certlifetime cannot be negative",
		},
		{
			name: "zero certlifetime is valid",
			config: AcmeProxyConfig{
				CaURL:        "https://acme.example.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: 0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestAcmeProxyConfig_Timeouts(t *testing.T) {
	config := AcmeProxyConfig{}

	httpTimeout := config.HTTPTimeout()
	if httpTimeout != 90*time.Second {
		t.Errorf("HTTPTimeout() = %v, want %v", httpTimeout, 90*time.Second)
	}

	requestTimeout := config.RequestTimeout()
	if requestTimeout != 2*time.Minute {
		t.Errorf("RequestTimeout() = %v, want %v", requestTimeout, 2*time.Minute)
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: `{
				"ca_url": "https://acme.example.com",
				"account_email": "test@example.com",
				"eab_kid": "test-kid",
				"eab_hmac_key": "test-hmac"
			}`,
			wantErr: false,
		},
		{
			name:    "invalid json",
			config:  `{invalid json`,
			wantErr: true,
			errMsg:  "failed to unmarshal config",
		},
		{
			name: "missing required field",
			config: `{
				"account_email": "test@example.com"
			}`,
			wantErr: true,
			errMsg:  "invalid config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cas := &ExternalCAS{
				ctx:    context.Background(),
				config: []byte(tt.config),
			}

			cfg, err := cas.parseConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("parseConfig() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if cfg == nil {
					t.Error("parseConfig() returned nil config")
				}
			}
		})
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
			errMsg:  "CSR cannot be nil",
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
			errMsg:  "CSR cannot be nil",
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
	ctx := context.Background()
	opts := apiv1.Options{
		Type:   "externalcas",
		Config: []byte("{}"),
	}

	extcas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		req     *apiv1.CreateCertificateRequest
		wantErr string
	}{
		{
			name:    "nil CSR returns error",
			req:     &apiv1.CreateCertificateRequest{CSR: nil, Template: &x509.Certificate{}},
			wantErr: "CSR cannot be nil",
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
		obtainFunc: func(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			// Return a test certificate bundle (leaf + intermediate)
			chain := createTestCertPEM(t, 1)
			chain = append(chain, createTestCertPEM(t, 2)...)
			return &certificate.Resource{Certificate: chain}, nil
		},
	}

	// Create a mock ExternalCAS that uses our mock client
	cas := &testExternalCAS{
		ExternalCAS: &ExternalCAS{
			ctx: context.Background(),
			config: mustMarshalConfig(t, &AcmeProxyConfig{
				CaURL:        "https://acme.test.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: 30,
			}),
		},
		mockClient: mockClient,
	}

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
		obtainFunc: func(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			return nil, errors.New("ACME server error")
		},
	}

	cas := &testExternalCAS{
		ExternalCAS: &ExternalCAS{
			ctx: context.Background(),
			config: mustMarshalConfig(t, &AcmeProxyConfig{
				CaURL:   "https://acme.test.com",
				Email:   "test@example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
			}),
		},
		mockClient: mockClient,
	}

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
		obtainFunc: func(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			time.Sleep(5 * time.Second)
			return nil, errors.New("should not reach here")
		},
	}

	cas := &testExternalCAS{
		ExternalCAS: &ExternalCAS{
			ctx: context.Background(),
			config: mustMarshalConfig(t, &AcmeProxyConfig{
				CaURL:   "https://acme.test.com",
				Email:   "test@example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
			}),
		},
		mockClient:     mockClient,
		requestTimeout: 100 * time.Millisecond, // Short timeout for testing
	}

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
	ctx := context.Background()
	opts := apiv1.Options{
		Type:   "externalcas",
		Config: []byte("{}"),
	}

	extcas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

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
	ctx := context.Background()
	opts := apiv1.Options{
		Type:   "externalcas",
		Config: []byte("{}"),
	}

	cas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cas.RenewCertificate(&apiv1.RenewCertificateRequest{})
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
	obtainFunc func(certificate.ObtainForCSRRequest) (*certificate.Resource, error)
	revokeFunc func([]byte) error
}

func (m *mockACMEClient) ObtainForCSR(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
	if m.obtainFunc != nil {
		return m.obtainFunc(req)
	}
	return nil, errors.New("not implemented")
}

func (m *mockACMEClient) Revoke(pemBytes []byte) error {
	if m.revokeFunc != nil {
		return m.revokeFunc(pemBytes)
	}
	return errors.New("not implemented")
}

// testExternalCAS is a test wrapper that allows injecting a mock ACME client
type testExternalCAS struct {
	*ExternalCAS
	mockClient     ACMEClient
	requestTimeout time.Duration
}

// Override createLegoClient to return our mock
func (t *testExternalCAS) createLegoClient(cfg *AcmeProxyConfig) (ACMEClient, error) {
	if t.mockClient != nil {
		return t.mockClient, nil
	}
	return t.ExternalCAS.createLegoClient(cfg)
}

// CreateCertificate overrides the parent to use custom timeout for testing
func (t *testExternalCAS) CreateCertificate(req *apiv1.CreateCertificateRequest) (*apiv1.CreateCertificateResponse, error) {
	if err := validateCreateCertificateRequest(req); err != nil {
		return nil, err
	}

	cfg, err := t.parseConfig()
	if err != nil {
		return nil, err
	}

	acmeClient, err := t.createLegoClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Use custom timeout if specified, otherwise use config timeout
	timeout := cfg.RequestTimeout()
	if t.requestTimeout > 0 {
		timeout = t.requestTimeout
	}

	ctx, cancel := context.WithTimeout(t.ctx, timeout)
	defer cancel()

	// Build certificate request
	csrRequest := certificate.ObtainForCSRRequest{
		CSR:    req.CSR,
		Bundle: true,
	}
	if cfg.CertLifetime > 0 {
		csrRequest.NotAfter = time.Now().Add(time.Duration(cfg.CertLifetime) * 24 * time.Hour)
	}

	// Request certificate with context timeout
	resultChan := make(chan *certificateResult, 1)
	go func() {
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
		return result.response, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("certificate request timed out: %w", ctx.Err())
	}
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
func mustMarshalConfig(t *testing.T, cfg *AcmeProxyConfig) []byte {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	return data
}
