package externalcas

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// newDomainTestServer wires the new domain endpoints against the current
// globalStore (call newDashTestStore first) with a session cookie helper.
func newDomainTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("GET /api/certs/domains", dashAuth(dashCertDomains))
	mux.Handle("GET /api/certs/domains/{domain}", dashAuth(dashCertDomainDetail))
	mux.Handle("DELETE /api/cached/{key}", dashAuth(dashCacheDelete))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// ACL-free auth: mint a session directly.
	sid := "test-session-token"
	dashSessionsMu.Lock()
	dashSessions[sid] = time.Now().Add(time.Hour)
	dashSessionsMu.Unlock()
	t.Cleanup(func() {
		dashSessionsMu.Lock()
		delete(dashSessions, sid)
		dashSessionsMu.Unlock()
	})
	return srv, sid
}

func doDomainReq(t *testing.T, srv *httptest.Server, sid, method, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: "acmeproxy_session", Value: sid})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, b
}

func seedDomainRecords(t *testing.T) {
	t.Helper()
	base := time.Now().Add(-2 * time.Hour)
	for i, ip := range []string{"192.0.2.10", "192.0.2.11"} {
		if err := globalStore.recordIssued(CertRecord{
			Serial: "aa" + string(rune('a'+i)), CommonName: "web.example.com",
			SANs:     "web.example.com,alt.example.com",
			IssuedAt: base.Add(time.Duration(i) * time.Hour), ExpiresAt: base.Add(89 * 24 * time.Hour),
			Status: "success", ClientIP: ip, RecordedAt: base.Add(time.Duration(i) * time.Hour),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := globalStore.recordIssued(CertRecord{
		CommonName: "web.example.com", SANs: "web.example.com",
		Status: "failure", ClientIP: "192.0.2.99", Error: "boom",
		RecordedAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed failure: %v", err)
	}
	if err := globalStore.cacheCert(CertRecord{
		Serial: "aa0", CommonName: "web.example.com", SANs: "alt.example.com,web.example.com",
		IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(89 * 24 * time.Hour),
		Status: "success", CertPEM: []byte("x"),
	}); err != nil {
		t.Fatalf("cacheCert: %v", err)
	}
}

func TestDashCertDomains_GroupingAndPaging(t *testing.T) {
	newDashTestStore(t)
	seedDomainRecords(t)
	srv, sid := newDomainTestServer(t)

	code, body := doDomainReq(t, srv, sid, "GET", "/api/certs/domains?page=1&per_page=1")
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	var res struct {
		Total      int `json:"total"`
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Domains    []struct {
			Domain       string `json:"domain"`
			RequestCount int    `json:"request_count"`
			SuccessCount int    `json:"success_count"`
			FailureCount int    `json:"failure_count"`
			UniqueIPs    int    `json:"unique_ips"`
			Cached       bool   `json:"cached"`
			LastStatus   string `json:"last_status"`
			LastError    string `json:"last_error"`
			Serial       string `json:"serial"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, body)
	}
	// unique domains: web.example.com, alt.example.com
	if res.Total != 2 || res.TotalPages != 2 || len(res.Domains) != 1 {
		t.Fatalf("paging meta wrong: total=%d pages=%d len=%d", res.Total, res.TotalPages, len(res.Domains))
	}
	byDomain := map[string]json.RawMessage{}
	// fetch all pages to inspect both domains
	for p := 1; p <= res.TotalPages; p++ {
		_, b := doDomainReq(t, srv, sid, "GET", "/api/certs/domains?page="+itoa(p)+"&per_page=1")
		var r struct {
			Domains []struct {
				Domain       string `json:"domain"`
				RequestCount int    `json:"request_count"`
				SuccessCount int    `json:"success_count"`
				FailureCount int    `json:"failure_count"`
				UniqueIPs    int    `json:"unique_ips"`
				Cached       bool   `json:"cached"`
				LastStatus   string `json:"last_status"`
				LastError    string `json:"last_error"`
				Serial       string `json:"serial"`
			} `json:"domains"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("unmarshal page %d: %v", p, err)
		}
		for _, d := range r.Domains {
			byDomain[d.Domain] = nil
			switch d.Domain {
			case "web.example.com":
				if d.RequestCount != 3 || d.SuccessCount != 2 || d.FailureCount != 1 {
					t.Errorf("web.example.com counts wrong: %+v", d)
				}
				if d.UniqueIPs != 3 {
					t.Errorf("web.example.com unique IPs = %d, want 3", d.UniqueIPs)
				}
				if d.LastStatus != "failure" || d.LastError != "boom" {
					t.Errorf("last status/error wrong: %+v", d)
				}
				if !d.Cached {
					t.Error("web.example.com should be flagged cached")
				}
				if d.Serial == "" {
					t.Error("web.example.com should expose latest serial")
				}
			case "alt.example.com":
				if d.RequestCount != 2 || d.SuccessCount != 2 {
					t.Errorf("alt.example.com counts wrong: %+v", d)
				}
			default:
				t.Errorf("unexpected domain %q", d.Domain)
			}
		}
	}
	if len(byDomain) != 2 {
		t.Fatalf("expected 2 unique domains, got %d", len(byDomain))
	}

	// search filter
	_, b := doDomainReq(t, srv, sid, "GET", "/api/certs/domains?q=alt")
	var sr struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(b, &sr); err != nil || sr.Total != 1 {
		t.Errorf("search total = %d err=%v, want 1", sr.Total, err)
	}
}

func itoa(i int) string {
	return string(rune('0' + i))
}

func TestDashCertDomainDetail(t *testing.T) {
	newDashTestStore(t)
	seedDomainRecords(t)
	srv, sid := newDomainTestServer(t)

	code, body := doDomainReq(t, srv, sid, "GET", "/api/certs/domains/"+url.PathEscape("web.example.com"))
	if code != 200 {
		t.Fatalf("status = %d", code)
	}
	var res struct {
		Domain   string `json:"domain"`
		Total    int    `json:"total"`
		Requests []struct {
			CommonName string `json:"common_name"`
			ClientIP   string `json:"client_ip"`
			Status     string `json:"status"`
			Error      string `json:"error"`
		} `json:"requests"`
		CachedCert map[string]string `json:"cached_cert"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Domain != "web.example.com" || res.Total != 3 || len(res.Requests) != 3 {
		t.Fatalf("detail meta wrong: %+v", res)
	}
	// newest first: the failure record (1 min ago) must be first
	if res.Requests[0].Status != "failure" || res.Requests[0].ClientIP != "192.0.2.99" || res.Requests[0].Error != "boom" {
		t.Errorf("newest-first ordering wrong: %+v", res.Requests[0])
	}
	if res.CachedCert == nil || res.CachedCert["sans"] == "" {
		t.Error("cached_cert missing for web.example.com")
	}
}

func TestDashCacheDelete(t *testing.T) {
	newDashTestStore(t)
	seedDomainRecords(t)
	srv, sid := newDomainTestServer(t)

	key := "alt.example.com,web.example.com"
	code, _ := doDomainReq(t, srv, sid, "DELETE", "/api/cached/"+key)
	if code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", code)
	}
	if globalStore.findCachedCert([]string{"web.example.com", "alt.example.com"}) != nil {
		t.Error("cache entry still served after delete")
	}
	// a second delete reports 404
	code, _ = doDomainReq(t, srv, sid, "DELETE", "/api/cached/"+key)
	if code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", code)
	}
}
