package externalcas

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newDashTestStore swaps in a temp cert store and restores the previous one.
func newDashTestStore(t *testing.T) {
	t.Helper()
	old := globalStore
	s, err := newCertStore(filepath.Join(t.TempDir(), "dash.db"))
	if err != nil {
		t.Fatalf("newCertStore: %v", err)
	}
	globalStore = s
	t.Cleanup(func() {
		globalStore = old
		_ = s.close()
	})
}

func dashTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	setDashCreds(dashboard{Username: "admin", Password: "kambing"})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", dashLoginChecker())
	mux.HandleFunc("POST /api/logout", dashLogout)
	mux.Handle("GET /api/certs", dashAuth(dashList(globalStoreAllIssued)))
	mux.Handle("GET /api/failed", dashAuth(dashFailed))
	mux.Handle("GET /api/overview", dashAuth(dashOverview))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func login(t *testing.T, srv *httptest.Server, user, pass string) *http.Response {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	return resp
}

func TestDashboard_Login(t *testing.T) {
	srv := dashTestServer(t)

	if resp := login(t, srv, "admin", "kambing"); resp.StatusCode != http.StatusNoContent {
		t.Errorf("valid login status = %d, want 204", resp.StatusCode)
	}
	if resp := login(t, srv, "admin", "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad password status = %d, want 401", resp.StatusCode)
	}
	if resp := login(t, srv, "root", "kambing"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad user status = %d, want 401", resp.StatusCode)
	}
}

func TestDashboard_UnauthorizedWithoutSession(t *testing.T) {
	srv := dashTestServer(t)
	resp, err := srv.Client().Get(srv.URL + "/api/certs")
	if err != nil {
		t.Fatalf("get certs: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-session status = %d, want 401", resp.StatusCode)
	}
}

func TestDashboard_APIWithSession(t *testing.T) {
	newDashTestStore(t)
	srv := dashTestServer(t)

	// Seed records: one success, one failure.
	if err := globalStore.recordIssued(CertRecord{
		Serial: "abc123", CommonName: "ok.example.com", SANs: "ok.example.com",
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(89 * 24 * time.Hour),
		Status: "success", ClientIP: "192.0.2.10",
	}); err != nil {
		t.Fatalf("recordIssued: %v", err)
	}
	if err := globalStore.recordIssued(CertRecord{
		CommonName: "bad.example.com", SANs: "bad.example.com",
		Status: "failure", ClientIP: "192.0.2.99", Error: "upstream said no",
	}); err != nil {
		t.Fatalf("recordIssued failure: %v", err)
	}

	// Login and keep the session cookie.
	client := srv.Client()
	client.Jar = nil // use default transport cookie handling via login below
	resp, err := client.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"kambing"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()

	// The httptest client does not persist cookies across calls without a Jar;
	// extract the cookie manually.
	loginResp, _ := client.Post(srv.URL+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"kambing"}`))
	var session string
	for _, c := range loginResp.Cookies() {
		if c.Name == "acmeproxy_session" {
			session = c.Value
		}
	}
	loginResp.Body.Close()
	if session == "" {
		t.Fatal("login did not set a session cookie")
	}

	get := func(path string) (int, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: "acmeproxy_session", Value: session})
		r, err := client.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b
	}

	// /api/certs returns both records newest-first.
	code, body := get("/api/certs")
	if code != http.StatusOK {
		t.Fatalf("certs status = %d, want 200", code)
	}
	var certs []dashView
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("unmarshal certs: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("certs len = %d, want 2", len(certs))
	}
	if certs[0].CommonName != "bad.example.com" || certs[0].ClientIP != "192.0.2.99" || certs[0].Error != "upstream said no" {
		t.Errorf("newest record = %+v, want bad.example.com failure with IP and error", certs[0])
	}

	// /api/failed returns only the failure.
	code, body = get("/api/failed")
	if code != http.StatusOK {
		t.Fatalf("failed status = %d, want 200", code)
	}
	var failed []dashView
	if err := json.Unmarshal(body, &failed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(failed) != 1 || failed[0].CommonName != "bad.example.com" {
		t.Errorf("failed = %+v, want one bad.example.com record", failed)
	}

	// /api/overview counts match.
	code, body = get("/api/overview")
	if code != http.StatusOK {
		t.Fatalf("overview status = %d, want 200", code)
	}
	var ov struct {
		IssuedTotal  int `json:"issued_total"`
		FailedTotal  int `json:"failed_total"`
		RevokedTotal int `json:"revoked_total"`
	}
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatalf("unmarshal overview: %v", err)
	}
	if ov.IssuedTotal != 1 || ov.FailedTotal != 1 || ov.RevokedTotal != 0 {
		t.Errorf("overview counts = %+v, want issued=1 failed=1 revoked=0", ov)
	}
}

func TestDashboard_LoadOrCreateKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "dash.pem")
	k1, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateKey: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	k2, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second loadOrCreateKey: %v", err)
	}
	e1, ok1 := k1.(*ecdsa.PrivateKey)
	e2, ok2 := k2.(*ecdsa.PrivateKey)
	if !ok1 || !ok2 || !e1.Equal(e2) {
		t.Error("reloaded key differs from generated key")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestDashboard_ConfigValidation(t *testing.T) {
	// Dashboard config lives at the top level of ca.json now; validate()
	// is driven directly with the struct (loadTopLevelConfig feeds it).
	cases := []struct {
		name    string
		d       dashboard
		m       metrics
		wantErr bool
	}{
		{"disabled by default", dashboard{}, metrics{}, false},
		{"enabled with data_source", dashboard{Port: 8080, DataSource: "/tmp/x.db"}, metrics{}, false},
		{"enabled without data_source", dashboard{Port: 8080}, metrics{}, true},
		{"inherits metrics dataSource", dashboard{Port: 8080}, metrics{Port: 9234, DataSource: "/tmp/m.db"}, false},
		{"tls half set", dashboard{Port: 8080, DataSource: "/tmp/x.db", TLSCert: "c.pem"}, metrics{}, true},
		{"tls_domain deprecated", dashboard{Port: 8080, DataSource: "/tmp/x.db", TLSDomain: "dash.example.com"}, metrics{}, true},
		{"tls_cert ok", dashboard{Port: 8080, DataSource: "/tmp/x.db", TLSCert: "c.pem", TLSKey: "k.pem"}, metrics{}, false},
		{"bad bind", dashboard{Port: 8080, DataSource: "/tmp/x.db", Bind: "not-an-ip"}, metrics{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.d.validate(tc.m)
			if (err != nil) != tc.wantErr {
				t.Errorf("validate err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
