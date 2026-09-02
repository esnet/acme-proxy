package reqmeta

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"
)

func TestRemoteIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/finalize", nil)
	r.RemoteAddr = "192.0.2.10:44321"
	if ip := RemoteIP(r); ip != "192.0.2.10" {
		t.Errorf("RemoteIP = %q, want 192.0.2.10", ip)
	}
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if ip := RemoteIP(r); ip != "198.51.100.7" {
		t.Errorf("RemoteIP with XFF = %q, want 198.51.100.7", ip)
	}
}

func genCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return parsed
}

func TestFinalizeRoundTrip(t *testing.T) {
	csr := genCSR(t)
	r := httptest.NewRequest("POST", "/finalize", nil)
	r.RemoteAddr = "192.0.2.10:44321"
	Record(r, "finalize", "order-1", csr, "")

	if ip := LookupFinalize(csr); ip != "192.0.2.10" {
		t.Errorf("LookupFinalize = %q, want 192.0.2.10", ip)
	}
	// Consumed on first lookup.
	if ip := LookupFinalize(csr); ip != "" {
		t.Errorf("second LookupFinalize = %q, want empty", ip)
	}
}

func TestRevokeRoundTrip(t *testing.T) {
	r := httptest.NewRequest("POST", "/revoke", nil)
	r.RemoteAddr = "192.0.2.11:44321"
	Record(r, "revoke", "example.com (1234)", nil, "1234")

	if ip := LookupRevoke("1234"); ip != "192.0.2.11" {
		t.Errorf("LookupRevoke = %q, want 192.0.2.11", ip)
	}
	if ip := LookupRevoke("1234"); ip != "" {
		t.Errorf("second LookupRevoke = %q, want empty", ip)
	}
}

func TestEventsNewestFirst(t *testing.T) {
	r := httptest.NewRequest("POST", "/new-order", nil)
	r.RemoteAddr = "192.0.2.12:44321"
	Record(r, "new-order", "a.example.com", nil, "")
	Record(r, "new-order", "b.example.com", nil, "")

	events := Events()
	if len(events) < 2 {
		t.Fatalf("Events len = %d, want >= 2", len(events))
	}
	if events[0].Detail != "b.example.com" || events[0].At.Before(events[1].At) {
		t.Errorf("events not newest-first: %+v", events[:2])
	}
}
