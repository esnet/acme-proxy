package externalcas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/challenge/tlsalpn01"
)

// TestSharedHTTP01Provider_MultipleChallenges verifies that a single provider
// serves multiple simultaneous http-01 challenges on one listener, that Host
// matching works, and that CleanUp removes a token.
func TestSharedHTTP01Provider_MultipleChallenges(t *testing.T) {
	provider := newSharedHTTP01Provider("127.0.0.1:0")

	// Present two different tokens.
	if err := provider.Present(context.Background(), "example.com", "token-a", "keyauth-a"); err != nil {
		t.Fatalf("Present(token-a) error: %v", err)
	}
	if err := provider.Present(context.Background(), "other.org", "token-b", "keyauth-b"); err != nil {
		t.Fatalf("Present(token-b) error: %v", err)
	}

	provider.mu.RLock()
	addr := provider.listener.Addr().String()
	provider.mu.RUnlock()

	baseURL := "http://" + addr

	// GET token-a with matching Host.
	body := getChallenge(t, baseURL+"/.well-known/acme-challenge/token-a", "example.com")
	if body != "keyauth-a" {
		t.Errorf("token-a body = %q, want %q", body, "keyauth-a")
	}

	// GET token-b with matching Host (host:port form).
	body = getChallenge(t, baseURL+"/.well-known/acme-challenge/token-b", "other.org:1234")
	if body != "keyauth-b" {
		t.Errorf("token-b body = %q, want %q", body, "keyauth-b")
	}

	// Wrong Host -> 404.
	if status := getChallengeStatus(t, baseURL+"/.well-known/acme-challenge/token-a", "wrong.example.com"); status != http.StatusNotFound {
		t.Errorf("wrong host status = %d, want 404", status)
	}

	// CleanUp removes token-a -> 404 after.
	if err := provider.CleanUp(context.Background(), "example.com", "token-a", "keyauth-a"); err != nil {
		t.Fatalf("CleanUp error: %v", err)
	}
	if status := getChallengeStatus(t, baseURL+"/.well-known/acme-challenge/token-a", "example.com"); status != http.StatusNotFound {
		t.Errorf("after cleanup status = %d, want 404", status)
	}

	// token-b still served after token-a cleanup.
	if body := getChallenge(t, baseURL+"/.well-known/acme-challenge/token-b", "other.org"); body != "keyauth-b" {
		t.Errorf("token-b after cleanup body = %q, want %q", body, "keyauth-b")
	}
}

// TestSharedHTTP01Provider_ClosesWhenIdle verifies the listener is closed once
// the last challenge is cleaned up, and lazily reopened on the next Present.
func TestSharedHTTP01Provider_ClosesWhenIdle(t *testing.T) {
	provider := newSharedHTTP01Provider("127.0.0.1:0")

	if err := provider.Present(context.Background(), "example.com", "token-a", "keyauth-a"); err != nil {
		t.Fatalf("Present(token-a) error: %v", err)
	}

	// Closing the last challenge closes the listener.
	if err := provider.CleanUp(context.Background(), "example.com", "token-a", "keyauth-a"); err != nil {
		t.Fatalf("CleanUp error: %v", err)
	}
	provider.mu.RLock()
	closed := provider.listener == nil
	provider.mu.RUnlock()
	if !closed {
		t.Fatal("listener still open after last challenge cleaned up, want closed")
	}

	// It reopens lazily on the next Present.
	if err := provider.Present(context.Background(), "example.com", "token-b", "keyauth-b"); err != nil {
		t.Fatalf("Present(token-b) error: %v", err)
	}
	provider.mu.RLock()
	addr := provider.listener.Addr().String()
	provider.mu.RUnlock()
	if body := getChallenge(t, "http://"+addr+"/.well-known/acme-challenge/token-b", "example.com"); body != "keyauth-b" {
		t.Errorf("token-b body = %q, want %q", body, "keyauth-b")
	}
}

func getChallenge(t *testing.T, url, host string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s error: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body error: %v", err)
	}
	return string(b)
}

func getChallengeStatus(t *testing.T, url, host string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s error: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestSharedTLSALPN01Provider_GetCertificate verifies per-SNI certificate
// lookup, missing-SNI behavior, and CleanUp.
func TestSharedTLSALPN01Provider_GetCertificate(t *testing.T) {
	provider := newSharedTLSALPN01Provider("127.0.0.1:0")

	if err := provider.Present(context.Background(), "Example.COM", "tok", "keyauth-a"); err != nil {
		t.Fatalf("Present(Example.COM) error: %v", err)
	}
	if err := provider.Present(context.Background(), "other.org", "tok2", "keyauth-b"); err != nil {
		t.Fatalf("Present(other.org) error: %v", err)
	}

	// Lookup by lowercased SNI returns the correct cert.
	certA, err := provider.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate(example.com) error: %v", err)
	}
	if certA == nil {
		t.Fatal("GetCertificate(example.com) returned nil")
	}
	if !certContainsDomain(t, certA, "Example.COM") {
		t.Error("cert for example.com does not contain Example.COM SAN")
	}

	certB, err := provider.GetCertificate(&tls.ClientHelloInfo{ServerName: "OTHER.ORG"})
	if err != nil {
		t.Fatalf("GetCertificate(OTHER.ORG) error: %v", err)
	}
	if certB == nil {
		t.Fatal("GetCertificate(OTHER.ORG) returned nil")
	}
	if !certContainsDomain(t, certB, "other.org") {
		t.Error("cert for OTHER.ORG does not contain other.org SAN")
	}

	// Missing SNI -> nil.
	missing, err := provider.GetCertificate(&tls.ClientHelloInfo{ServerName: "nope.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate(missing) error: %v", err)
	}
	if missing != nil {
		t.Error("GetCertificate(missing) = non-nil, want nil")
	}

	// CleanUp removes the domain.
	if err := provider.CleanUp(context.Background(), "example.com", "tok", "keyauth-a"); err != nil {
		t.Fatalf("CleanUp error: %v", err)
	}
	after, err := provider.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("GetCertificate after cleanup error: %v", err)
	}
	if after != nil {
		t.Error("GetCertificate after cleanup = non-nil, want nil")
	}
}

func certContainsDomain(t *testing.T, cert *tls.Certificate, domain string) bool {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse challenge cert: %v", err)
	}
	for _, d := range leaf.DNSNames {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// TestSharedTLSALPN01Provider_Handshake performs a real TLS handshake over a
// listener bound to 127.0.0.1:0 with ALPN "acme-tls/1".
func TestSharedTLSALPN01Provider_Handshake(t *testing.T) {
	provider := newSharedTLSALPN01Provider("127.0.0.1:0")

	if err := provider.Present(context.Background(), "handshake.example.com", "tok", "keyauth-hs"); err != nil {
		t.Fatalf("Present error: %v", err)
	}

	provider.mu.RLock()
	addr := provider.listener.Addr().String()
	provider.mu.RUnlock()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "handshake.example.com",
		NextProtos:         []string{tlsalpn01.ACMETLS1Protocol},
		InsecureSkipVerify: true, //nolint:gosec // challenge cert is self-signed by design
	})
	if err != nil {
		t.Fatalf("tls.Dial error: %v", err)
	}
	defer conn.Close()

	if got := conn.ConnectionState().NegotiatedProtocol; got != tlsalpn01.ACMETLS1Protocol {
		t.Errorf("negotiated protocol = %q, want %q", got, tlsalpn01.ACMETLS1Protocol)
	}

	// A handshake for an unknown SNI should fail.
	if _, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "unknown.example.com",
		NextProtos:         []string{tlsalpn01.ACMETLS1Protocol},
		InsecureSkipVerify: true, //nolint:gosec
	}); err == nil {
		t.Error("expected handshake failure for unknown SNI, got success")
	}
}

// TestHostMatches verifies the Host header matching helper.
func TestHostMatches(t *testing.T) {
	tests := []struct {
		host   string
		domain string
		want   bool
	}{
		{"example.com", "example.com", true},
		{"example.com:80", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},
		{"example.com:443", "example.com", true},
		{"wrong.example.com", "example.com", false},
		{"example.com", "other.org", false},
	}
	for _, tt := range tests {
		if got := hostMatches(tt.host, tt.domain); got != tt.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
		}
	}
}
