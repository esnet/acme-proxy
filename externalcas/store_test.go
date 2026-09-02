package externalcas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewCertStore(t *testing.T) {
	s := newTestStore(t)
	if len(s.allIssued()) != 0 {
		t.Error("expected empty issued store on creation")
	}
	if len(s.allRevoked()) != 0 {
		t.Error("expected empty revoked store on creation")
	}
}

func TestNewCertStore_InvalidPath(t *testing.T) {
	_, err := newCertStore("/nonexistent/path/test.db")
	if err == nil {
		t.Fatal("expected error opening store at invalid path, got nil")
	}
}

func TestCertStore_RecordIssued_Success(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	r := CertRecord{
		Serial:          "abc123",
		CommonName:      "example.com",
		Issuer:          "Test CA",
		SANs:            "example.com,www.example.com",
		IssuedAt:        now,
		ExpiresAt:       now.Add(90 * 24 * time.Hour),
		DurationSeconds: 1.5,
		Status:          "success",
	}
	if err := s.recordIssued(r); err != nil {
		t.Fatalf("recordIssued() error = %v", err)
	}

	issued := s.allIssued()
	if len(issued) != 1 {
		t.Fatalf("allIssued() count = %d, want 1", len(issued))
	}
	got := issued[0]
	if got.Serial != r.Serial {
		t.Errorf("Serial = %q, want %q", got.Serial, r.Serial)
	}
	if got.CommonName != r.CommonName {
		t.Errorf("CommonName = %q, want %q", got.CommonName, r.CommonName)
	}
	if got.Issuer != r.Issuer {
		t.Errorf("Issuer = %q, want %q", got.Issuer, r.Issuer)
	}
	if got.SANs != r.SANs {
		t.Errorf("SANs = %q, want %q", got.SANs, r.SANs)
	}
	if !got.IssuedAt.Equal(r.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, r.IssuedAt)
	}
	if got.DurationSeconds != r.DurationSeconds {
		t.Errorf("DurationSeconds = %v, want %v", got.DurationSeconds, r.DurationSeconds)
	}
	if got.Status != r.Status {
		t.Errorf("Status = %q, want %q", got.Status, r.Status)
	}
}

func TestCertStore_RecordIssued_FailuresAreDistinct(t *testing.T) {
	// Failed issuances have no serial; each attempt must be stored as a separate entry.
	s := newTestStore(t)
	r := CertRecord{CommonName: "example.com", SANs: "example.com", Status: "failure"}

	if err := s.recordIssued(r); err != nil {
		t.Fatal(err)
	}
	if err := s.recordIssued(r); err != nil {
		t.Fatal(err)
	}

	if got := len(s.allIssued()); got != 2 {
		t.Errorf("allIssued() count = %d, want 2 — each failure attempt must be stored separately", got)
	}
}

func TestCertStore_RecordRevoked(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	r := CertRecord{
		Serial:          "def456",
		CommonName:      "example.com",
		Issuer:          "Test CA",
		SANs:            "example.com",
		IssuedAt:        now,
		ExpiresAt:       now.Add(90 * 24 * time.Hour),
		DurationSeconds: 0.8,
		Status:          "success",
	}
	if err := s.recordRevoked(r); err != nil {
		t.Fatalf("recordRevoked() error = %v", err)
	}

	revoked := s.allRevoked()
	if len(revoked) != 1 {
		t.Fatalf("allRevoked() count = %d, want 1", len(revoked))
	}
	if revoked[0].Serial != r.Serial {
		t.Errorf("Serial = %q, want %q", revoked[0].Serial, r.Serial)
	}
}

func TestCertStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	// Write records in the first store instance.
	s1, err := newCertStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.recordIssued(CertRecord{Serial: "abc", CommonName: "example.com", Status: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := s1.recordRevoked(CertRecord{Serial: "def", CommonName: "other.com", Status: "success"}); err != nil {
		t.Fatal(err)
	}
	s1.close()

	// Reopen and verify all records survive the restart.
	s2, err := newCertStore(path)
	if err != nil {
		t.Fatalf("failed to reopen store: %v", err)
	}
	defer s2.close()

	if got := len(s2.allIssued()); got != 1 {
		t.Errorf("allIssued() after reopen = %d, want 1", got)
	}
	if got := len(s2.allRevoked()); got != 1 {
		t.Errorf("allRevoked() after reopen = %d, want 1", got)
	}
	if s2.allIssued()[0].Serial != "abc" {
		t.Errorf("issued serial after reopen = %q, want %q", s2.allIssued()[0].Serial, "abc")
	}
}

func TestStoreKey(t *testing.T) {
	t.Run("success record uses serial as key", func(t *testing.T) {
		key := storeKey(CertRecord{Serial: "abc123", Status: "success"})
		if string(key) != "abc123" {
			t.Errorf("storeKey() = %q, want %q", key, "abc123")
		}
	})

	t.Run("failure record uses failure: prefix", func(t *testing.T) {
		key := storeKey(CertRecord{CommonName: "example.com", Status: "failure"})
		if !strings.HasPrefix(string(key), "failure:example.com:") {
			t.Errorf("storeKey() = %q, want prefix %q", key, "failure:example.com:")
		}
	})
}

func TestCertStore_AllIssued_ReturnsCopy(t *testing.T) {
	s := newTestStore(t)
	if err := s.recordIssued(CertRecord{Serial: "abc", Status: "success"}); err != nil {
		t.Fatal(err)
	}

	issued := s.allIssued()
	issued[0].Serial = "mutated"

	if s.allIssued()[0].Serial != "abc" {
		t.Error("allIssued() must return a copy — mutating the result must not affect internal state")
	}
}

func TestCertStore_CacheCert(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	r := CertRecord{
		Serial:          "cache001",
		CommonName:      "cached.example.com",
		Issuer:          "Test CA",
		SANs:            "cached.example.com,www.cached.example.com",
		IssuedAt:        now,
		ExpiresAt:       now.Add(90 * 24 * time.Hour),
		DurationSeconds: 2.0,
		Status:          "success",
		CertPEM:         []byte("fake-pem-data"),
	}
	if err := s.cacheCert(r); err != nil {
		t.Fatalf("cacheCert() error = %v", err)
	}

	domains := []string{"cached.example.com", "www.cached.example.com"}
	cached := s.findCachedCert(domains)
	if cached == nil {
		t.Fatal("findCachedCert() returned nil for cached domains")
	}
	if cached.Serial != r.Serial {
		t.Errorf("Serial = %q, want %q", cached.Serial, r.Serial)
	}
}

func TestCertStore_CacheCert_IgnoresFailure(t *testing.T) {
	s := newTestStore(t)
	r := CertRecord{
		CommonName: "fail.example.com",
		SANs:       "fail.example.com",
		Status:     "failure",
	}
	if err := s.cacheCert(r); err != nil {
		t.Fatalf("cacheCert() error = %v", err)
	}
	if cached := s.findCachedCert([]string{"fail.example.com"}); cached != nil {
		t.Error("findCachedCert() should return nil for failed cert")
	}
}

func TestCertStore_CacheCert_IgnoresEmptyPEM(t *testing.T) {
	s := newTestStore(t)
	r := CertRecord{
		CommonName: "noPEM.example.com",
		SANs:       "noPEM.example.com",
		Status:     "success",
		CertPEM:    nil,
	}
	if err := s.cacheCert(r); err != nil {
		t.Fatalf("cacheCert() error = %v", err)
	}
	if cached := s.findCachedCert([]string{"noPEM.example.com"}); cached != nil {
		t.Error("findCachedCert() should return nil when CertPEM is empty")
	}
}

func TestCertStore_CacheCert_DomainOrderIndependent(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	r := CertRecord{
		Serial:     "cache002",
		CommonName: "a.example.com",
		SANs:       "a.example.com,b.example.com",
		IssuedAt:   now,
		ExpiresAt:  now.Add(90 * 24 * time.Hour),
		Status:     "success",
		CertPEM:    []byte("fake-pem"),
	}
	if err := s.cacheCert(r); err != nil {
		t.Fatal(err)
	}

	// Lookup with reversed order should still match
	cached := s.findCachedCert([]string{"b.example.com", "a.example.com"})
	if cached == nil {
		t.Fatal("findCachedCert() should match regardless of domain order")
	}
	if cached.Serial != "cache002" {
		t.Errorf("Serial = %q, want %q", cached.Serial, "cache002")
	}
}

func TestCertStore_CacheCert_OverwritesOldEntry(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	r1 := CertRecord{
		Serial:     "old001",
		CommonName: "dup.example.com",
		SANs:       "dup.example.com",
		IssuedAt:   now,
		ExpiresAt:  now.Add(90 * 24 * time.Hour),
		Status:     "success",
		CertPEM:    []byte("old-pem"),
	}
	r2 := CertRecord{
		Serial:     "new001",
		CommonName: "dup.example.com",
		SANs:       "dup.example.com",
		IssuedAt:   now,
		ExpiresAt:  now.Add(90 * 24 * time.Hour),
		Status:     "success",
		CertPEM:    []byte("new-pem"),
	}
	if err := s.cacheCert(r1); err != nil {
		t.Fatal(err)
	}
	if err := s.cacheCert(r2); err != nil {
		t.Fatal(err)
	}

	cached := s.findCachedCert([]string{"dup.example.com"})
	if cached == nil {
		t.Fatal("findCachedCert() returned nil")
	}
	if cached.Serial != "new001" {
		t.Errorf("Serial = %q, want %q (should be latest)", cached.Serial, "new001")
	}
}

func TestCertStore_CacheCert_Miss(t *testing.T) {
	s := newTestStore(t)
	cached := s.findCachedCert([]string{"nonexistent.example.com"})
	if cached != nil {
		t.Error("findCachedCert() should return nil for non-cached domains")
	}
}

func TestCertStore_CachePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")
	now := time.Now().Truncate(time.Second)

	r := CertRecord{
		Serial:     "persist001",
		CommonName: "persist.example.com",
		SANs:       "persist.example.com",
		IssuedAt:   now,
		ExpiresAt:  now.Add(90 * 24 * time.Hour),
		Status:     "success",
		CertPEM:    []byte("persist-pem"),
	}

	s1, err := newCertStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.cacheCert(r); err != nil {
		t.Fatal(err)
	}
	s1.close()

	s2, err := newCertStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.close()

	cached := s2.findCachedCert([]string{"persist.example.com"})
	if cached == nil {
		t.Fatal("findCachedCert() after reopen returned nil — cache not persisted")
	}
	if cached.Serial != "persist001" {
		t.Errorf("Serial = %q, want %q", cached.Serial, "persist001")
	}
}

func TestCacheKey(t *testing.T) {
	key1 := cacheKey([]string{"b.com", "a.com"})
	key2 := cacheKey([]string{"a.com", "b.com"})
	if key1 != key2 {
		t.Errorf("cacheKey() not deterministic: %q != %q", key1, key2)
	}
	if key1 != "a.com,b.com" {
		t.Errorf("cacheKey() = %q, want %q", key1, "a.com,b.com")
	}
}

// newTestStore creates a certStore backed by a temp db that is closed automatically
// when the test ends.
func newTestStore(t *testing.T) *certStore {
	t.Helper()
	s, err := newCertStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("newCertStore() error = %v", err)
	}
	t.Cleanup(func() { s.close() })
	return s
}

// genKey is a test helper generating a fresh ECDSA P-256 key.
func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

// selfSignedCertPEM issues a minimal self-signed certificate for the given key
// and returns its PEM encoding.
func selfSignedCertPEM(t *testing.T, key *ecdsa.PrivateKey, dnsName string) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// csrFor builds a certificate request signed by the given key.
func csrFor(t *testing.T, key *ecdsa.PrivateKey, dnsName string) *x509.CertificateRequest {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{DNSNames: []string{dnsName}}, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	return parsed
}

// Regression: a cached certificate may only be served for a CSR carrying the
// same public key. step-ca bootstraps with a fresh in-memory key on every
// start; serving the previous boot's cached cert for the new key produced
// "tls: private key does not match public key" and crashed the service.
func TestCertRecord_MatchesCSR(t *testing.T) {
	keyA := genKey(t)
	keyB := genKey(t)

	rec := CertRecord{
		Serial:  "match001",
		SANs:    "proxy.example.com",
		Status:  "success",
		CertPEM: selfSignedCertPEM(t, keyA, "proxy.example.com"),
	}

	// Same key -> match.
	if !rec.matchesCSR(csrFor(t, keyA, "proxy.example.com")) {
		t.Error("matchesCSR() = false for the certificate's own key, want true")
	}

	// Different key (fresh bootstrap key) -> no match.
	if rec.matchesCSR(csrFor(t, keyB, "proxy.example.com")) {
		t.Error("matchesCSR() = true for a different public key, want false")
	}

	// Degenerate inputs never match.
	if rec.matchesCSR(nil) {
		t.Error("matchesCSR(nil) = true, want false")
	}
	if (CertRecord{SANs: "x", Status: "success"}).matchesCSR(csrFor(t, keyA, "proxy.example.com")) {
		t.Error("matchesCSR() = true with empty CertPEM, want false")
	}
	if (CertRecord{SANs: "x", Status: "success", CertPEM: []byte("not-pem")}).matchesCSR(csrFor(t, keyA, "proxy.example.com")) {
		t.Error("matchesCSR() = true with invalid PEM, want false")
	}
}
