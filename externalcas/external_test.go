package externalcas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

func TestInitClient(t *testing.T) {
}

func TestValidateCreateCertificateRequest(t *testing.T) {
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
			err := ValidateCreateCertificateRequest(tt.req)
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

func TestValidateRevokeCertificateRequest(t *testing.T) {
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
			err := ValidateRevokeCertificateRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRevokeCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateRevokeCertificateRequest() error = %q, want error containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestCreateCertificate(t *testing.T) {
	ctx := context.Background()
	opts := apiv1.Options{
		Type:   "externalcas",
		Config: []byte("{}"),
	}

	extcas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Table-driven tests for validation logic
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

			// We expect an error
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}

			// Check the error message contains expected text
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
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

func TestProcessCertificateRequest(t *testing.T) {
}

func TestProcessCertificateRequest_WithMock(t *testing.T) {
	// Create a mock ACME client that returns a test certificate
	mockClient := &mockACMEClient{
		obtainFunc: func(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			// Return a test certificate bundle (leaf + intermediate)
			chain := createTestCertPEM(t, 1)
			chain = append(chain, createTestCertPEM(t, 2)...)
			return &certificate.Resource{Certificate: chain}, nil
		},
	}

	// Create ExternalCAS with mock client and parsed config
	cas := &ExternalCAS{
		ctx:        context.Background(),
		acmeClient: mockClient,
		parsedConfig: &AcmeProxyConfig{
			CaURL:        "https://acme.test.com",
			Email:        "test@example.com",
			Kid:          "test-kid",
			HmacKey:      "test-hmac",
			CertLifetime: 30,
		},
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
	result := cas.processCertificateRequest(context.Background(), req)

	// Verify the result
	if result.err != nil {
		t.Fatalf("expected no error, got: %v", result.err)
	}
	if result.response == nil {
		t.Fatal("expected response")
	}
	if result.response.Certificate == nil {
		t.Error("expected leaf certificate")
	}
	if len(result.response.CertificateChain) != 1 {
		t.Errorf("expected 1 intermediate certificate, got %d", len(result.response.CertificateChain))
	}
}

func TestProcessCertificateRequest_WithMock_Error(t *testing.T) {
	// Create a mock ACME client that returns an error
	mockClient := &mockACMEClient{
		obtainFunc: func(req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			return nil, errors.New("ACME server error")
		},
	}

	cas := &ExternalCAS{
		ctx:        context.Background(),
		acmeClient: mockClient,
		parsedConfig: &AcmeProxyConfig{
			CaURL:   "https://acme.test.com",
			Email:   "test@example.com",
			Kid:     "test-kid",
			HmacKey: "test-hmac",
		},
	}

	csr := &x509.CertificateRequest{
		DNSNames: []string{"test.example.com"},
	}
	req := &apiv1.CreateCertificateRequest{
		CSR:      csr,
		Template: &x509.Certificate{},
	}

	result := cas.processCertificateRequest(context.Background(), req)

	if result.err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(result.err.Error(), "ACME server error") {
		t.Errorf("expected error containing 'ACME server error', got: %v", result.err)
	}
}

func TestSplitCertificateBundle(t *testing.T) {
	// Build a chain: leaf + intermediate + root
	var chain []byte
	chain = append(chain, createTestCertPEM(t, 1)...)
	chain = append(chain, createTestCertPEM(t, 2)...)
	chain = append(chain, createTestCertPEM(t, 3)...)

	leaf, intermediates, err := SplitCertificateBundle(chain)
	if err != nil {
		t.Fatalf("SplitCertificateBundle failed: %v", err)
	}

	// Verify we got a leaf certificate
	if leaf == nil {
		t.Fatal("expected non-nil leaf certificate")
	}

	// Verify we got 2 intermediates (intermediate + root)
	if len(intermediates) != 2 {
		t.Fatalf("expected 2 intermediates, got %d", len(intermediates))
	}

	// Verify serial numbers are correct (leaf=1, intermediates=2,3)
	if leaf.SerialNumber.Int64() != 1 {
		t.Errorf("leaf serial: want 1, got %d", leaf.SerialNumber.Int64())
	}
	if intermediates[0].SerialNumber.Int64() != 2 {
		t.Errorf("first intermediate serial: want 2, got %d", intermediates[0].SerialNumber.Int64())
	}
	if intermediates[1].SerialNumber.Int64() != 3 {
		t.Errorf("second intermediate serial: want 3, got %d", intermediates[1].SerialNumber.Int64())
	}
}

func TestRenewCertificate(t *testing.T) {
}

func TestRevokeCertificate(t *testing.T) {
	ctx := context.Background()
	opts := apiv1.Options{
		Type:   "externalcas",
		Config: []byte("{}"),
	}

	extcas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Table-driven tests for validation logic (no network calls)
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

// Helper function that generates a self-signed test certificate in PEM format.
func createTestCertPEM(t *testing.T, serial int64) []byte {
	t.Helper() // marks this as a test helper (better error line numbers)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating ecdsa key for test cert: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), // use the serial parameter
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

	// return self signed cert in PEM format
	return pem.EncodeToMemory(pemBlock)
}
