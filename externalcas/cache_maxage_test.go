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
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certificate"
	"github.com/smallstep/certificates/cas/apiv1"
)

// cacheFixture builds a store with one cached cert whose public key matches
// the returned CSR, issued `issuedAgo` ago and expiring `expiresIn` from now.
func cacheFixture(t *testing.T, issuedAgo, expiresIn time.Duration) (*ExternalCAS, *x509.CertificateRequest, *int) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "aged.example.com"},
		DNSNames:     []string{"aged.example.com"},
		NotBefore:    time.Now().Add(-issuedAgo),
		NotAfter:     time.Now().Add(expiresIn),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{DNSNames: []string{"aged.example.com"}}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	// swap in a temp store holding the cached record
	old := globalStore
	s, err := newCertStore(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	globalStore = s
	t.Cleanup(func() {
		globalStore = old
		_ = s.close()
	})
	if err := s.cacheCert(CertRecord{
		Serial: "ff", CommonName: "aged.example.com", SANs: "aged.example.com",
		IssuedAt: time.Now().Add(-issuedAgo), ExpiresAt: time.Now().Add(expiresIn),
		Status: "success", CertPEM: pemOf(t, der),
	}); err != nil {
		t.Fatalf("cacheCert: %v", err)
	}

	obtains := 0
	mock := &mockACMEClient{
		obtainFunc: func(ctx context.Context, req certificate.ObtainForCSRRequest) (*certificate.Resource, error) {
			obtains++
			return &certificate.Resource{Certificate: pemOf(t, der)}, nil
		},
	}
	cas := newTestCAS(t, &acmeProxyConfig{CaURL: "https://ca"}, mock)
	return cas, csr, &obtains
}

func pemOf(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCreateCertificate_CacheMaxAgeForcesRenewal(t *testing.T) {
	// Cert issued 40 days ago, valid for 60 more days: remaining validity is
	// fine, but the default 30-day max cache age must force a re-issue.
	cas, csr, obtains := cacheFixture(t, 40*24*time.Hour, 60*24*time.Hour)
	if _, err := cas.CreateCertificate(&apiv1.CreateCertificateRequest{
		CSR: csr, Template: &x509.Certificate{},
	}); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if *obtains != 1 {
		t.Errorf("upstream obtains = %d, want 1 (stale cache age must re-issue)", *obtains)
	}
}

func TestCreateCertificate_CacheFreshWithinMaxAge(t *testing.T) {
	// Cert issued 1 day ago, 60 days remaining: must be served from cache.
	cas, csr, obtains := cacheFixture(t, 24*time.Hour, 60*24*time.Hour)
	if _, err := cas.CreateCertificate(&apiv1.CreateCertificateRequest{
		CSR: csr, Template: &x509.Certificate{},
	}); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if *obtains != 0 {
		t.Errorf("upstream obtains = %d, want 0 (fresh cache must be served)", *obtains)
	}
}

func TestCertCacheMaxAgeDefaultsAndConfig(t *testing.T) {
	if d := (&acmeProxyConfig{}).CertCacheMaxAgeDuration(); d != 30*24*time.Hour {
		t.Errorf("default max age = %v, want 30d", d)
	}
	if d := (&acmeProxyConfig{CertCacheMaxAge: 10}).CertCacheMaxAgeDuration(); d != 10*24*time.Hour {
		t.Errorf("configured max age = %v, want 10d", d)
	}
}

func TestDashboardTLSMaxAgeDefault(t *testing.T) {
	if d := (dashboard{}).tlsMaxAge(); d != 30*24*time.Hour {
		t.Errorf("default tls max age = %v, want 30d", d)
	}
	if d := (dashboard{TLSMaxAgeDays: 7}).tlsMaxAge(); d != 7*24*time.Hour {
		t.Errorf("configured tls max age = %v, want 7d", d)
	}
}
