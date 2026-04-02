package externalcas

import (
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
