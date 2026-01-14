package externalcas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

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

func TestInitClient(t *testing.T) {
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

func TestProcessCertificateRequest(t *testing.T) {
}

func TestSplitCertificateBundle(t *testing.T) {
	ctx := context.Background()
	opts := apiv1.Options{
		Type:       "externalcas",
		IsCreator:  false,
		IsCAGetter: false,
		Config:     []byte(""),
	}

	extcas, err := New(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Build a chain: leaf + intermediate + root
	var chain []byte
	chain = append(chain, createTestCertPEM(t, 1)...)
	chain = append(chain, createTestCertPEM(t, 2)...)
	chain = append(chain, createTestCertPEM(t, 3)...)

	leaf, intermediates, err := extcas.splitCertificateBundle(chain)
	if err != nil {
		t.Fatalf("splitCertificateBundle failed: %v", err)
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
