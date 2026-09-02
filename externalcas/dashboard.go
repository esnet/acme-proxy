package externalcas

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esnet/acme-proxy/acl"
	"github.com/esnet/acme-proxy/reqmeta"
	stepconfig "github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/cas/apiv1"
)

//go:embed web/index.html
var webFS embed.FS

const (
	dashboardSessionTTL = 12 * time.Hour
	defaultDashUser     = "admin"
	defaultDashPass     = "kambing"
)

var (
	dashOnce       sync.Once
	dashSessions   = map[string]time.Time{} // token -> expiry
	dashSessionsMu sync.Mutex

	// dashCreds holds the active login credentials; hot-swapped by the
	// settings reload without restarting the listener.
	dashUser atomic.Pointer[string]
	dashPass atomic.Pointer[string]

	// dashCfg holds the active dashboard config (tls_max_age_days etc.) for
	// the renewal loop; hot-swapped by the settings reload.
	dashCfgPtr atomic.Pointer[dashboard]
)

// setDashCreds swaps the active dashboard credentials (empty fields keep the
// current value).
func setDashCreds(d dashboard) {
	if d.Username != "" {
		u := d.Username
		dashUser.Store(&u)
	}
	if d.Password != "" {
		p := d.Password
		dashPass.Store(&p)
	}
}

func currentDashUser() string {
	if v := dashUser.Load(); v != nil {
		return *v
	}
	return defaultDashUser
}

func currentDashPass() string {
	if v := dashPass.Load(); v != nil {
		return *v
	}
	return defaultDashPass
}

func setDashConfig(d dashboard) {
	dashCfgPtr.Store(&d)
}

func getDashConfig() dashboard {
	if v := dashCfgPtr.Load(); v != nil {
		return *v
	}
	return dashboard{}
}

// startDashboardServer starts the admin web dashboard once when configured.
// It is a separate listener from the ACME client-facing server, the challenge
// listeners, and the metrics server, so it cannot interfere with them.
func startDashboardServer(cas *ExternalCAS, cfg *acmeProxyConfig, d dashboard) error {
	if !d.enabled {
		return nil
	}
	if globalStore == nil {
		slog.Warn("dashboard enabled without a cert store; history will be empty")
	}
	setDashConfig(d)
	setDashCreds(d)

	var startErr error
	dashOnce.Do(func() {
		mux := http.NewServeMux()
		index, err := webFS.ReadFile("web/index.html")
		if err != nil {
			startErr = err
			return
		}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(index) //nolint:noctx
		})
		mux.HandleFunc("POST /api/login", dashLoginChecker())
		mux.HandleFunc("POST /api/logout", dashLogout)
		mux.Handle("GET /api/overview", dashAuth(dashOverview))
		mux.Handle("GET /api/certs", dashAuth(dashList(globalStoreAllIssued)))
		mux.Handle("GET /api/revoked", dashAuth(dashList(globalStoreAllRevoked)))
		mux.Handle("GET /api/failed", dashAuth(dashFailed))
		mux.Handle("GET /api/cached", dashAuth(dashList(globalStoreAllCached)))
		mux.Handle("GET /api/requests", dashAuth(dashRequests))
		mux.Handle("GET /api/certs/domains", dashAuth(dashCertDomains))
		mux.Handle("GET /api/certs/domains/{domain}", dashAuth(dashCertDomainDetail))
		mux.Handle("DELETE /api/cached/{key}", dashAuth(dashCacheDelete))
		mux.Handle("GET /api/acl", dashAuth(dashACLGet))
		mux.Handle("PUT /api/acl", dashAuth(dashACLPut))
		mux.Handle("GET /api/settings", dashAuth(dashSettingsGet))
		mux.Handle("PUT /api/settings", dashAuth(dashSettingsPut))
		dashMux = mux

		tlsConf, err := dashTLSConfig(cas, cfg, d)
		if err != nil {
			// Never take the CA down because the dashboard's TLS setup
			// failed; serve plain HTTP and keep the proxy running.
			slog.Error("dashboard TLS setup failed, serving plain HTTP instead", "error", err)
		}
		if tlsConf != nil {
			dashTLSCfg.Store(tlsConf)
		}
	})

	if startErr == nil {
		startErr = restartDashboardListener(d)
	}
	return startErr
}

var (
	dashMux    *http.ServeMux
	dashSrvMu  sync.Mutex
	dashSrv    *http.Server
	dashTLSCfg atomic.Pointer[tls.Config]
)

// restartDashboardListener binds a dashboard listener for d's address using
// the active TLS config and drains the previous one. Called at startup and by
// the settings reload when port/bind/TLS files change. A bind failure leaves
// the previous listener serving.
func restartDashboardListener(d dashboard) error {
	dashSrvMu.Lock()
	defer dashSrvMu.Unlock()

	addr := net.JoinHostPort(d.Bind, strconv.Itoa(d.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot bind dashboard listener %s: %w", addr, err)
	}
	if dashSrv != nil {
		old := dashSrv
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = old.Shutdown(ctx)
		}()
	}
	tlsConf := dashTLSCfg.Load()
	srv := &http.Server{
		Handler:           dashMux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConf,
	}
	dashSrv = srv
	go func() {
		var err error
		if tlsConf != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("dashboard server stopped", "error", err)
		}
	}()
	scheme := "http"
	if tlsConf != nil {
		scheme = "https"
	}
	slog.Info("dashboard listening", "addr", scheme+"://"+addr)
	if scheme == "http" {
		slog.Warn("dashboard running without TLS; restrict network access or configure tls_cert/tls_key")
	}
	return nil
}

// reloadManualDashTLS rebuilds the dashboard TLS config from d's tls_cert/
// tls_key files (manual mode). On success the new config is swapped in;
// on failure the previous config keeps serving.
func reloadManualDashTLS(d dashboard) error {
	if d.TLSCert == "" || d.TLSKey == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(d.TLSCert, d.TLSKey)
	if err != nil {
		return fmt.Errorf("dashboard tls_cert/tls_key: %w", err)
	}
	dashTLSCfg.Store(&tls.Config{Certificates: []tls.Certificate{cert}})
	return nil
}

// dashTLSConfig resolves the dashboard TLS mode:
//   - tls_cert + tls_key: serve those PEM files.
//   - default: SHARE the client-facing :443 certificate. The CSR is built
//     from the same persistent key (tls_key.pem next to ca.json) and the
//     same CN/dnsNames, so CreateCertificate is a cache hit on the very
//     certificate :443 serves — the dashboard never issues its own
//     certificate, keeping the upstream rate budget untouched. A copy is
//     kept next to the sidecar store so restarts work even if the shared
//     cache entry is overwritten by a client order.
//   - no ca.json identity available: plain HTTP.
func dashTLSConfig(cas *ExternalCAS, cfg *acmeProxyConfig, d dashboard) (*tls.Config, error) {
	if d.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(d.TLSCert, d.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("dashboard tls_cert/tls_key: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	// Same key material as the :443 listener (see authority tlsKeyPath).
	if stepconfig.LoadedFilepath == "" {
		return nil, nil
	}
	top := loadTopLevelConfig()
	cn := top.CommonName
	if cn == "" && len(top.DNSNames) > 0 {
		cn = top.DNSNames[0]
	}
	if cn == "" || len(top.DNSNames) == 0 {
		slog.Warn("dashboard TLS disabled: ca.json dnsNames/commonName missing")
		return nil, nil
	}
	keyPath := filepath.Join(filepath.Dir(stepconfig.LoadedFilepath), "tls_key.pem")
	certPath := filepath.Join(filepath.Dir(d.DataSource), "dashboard-tls-cert.pem")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}

	maxAge := func() time.Duration { return getDashConfig().tlsMaxAge() }
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		// No local copy yet: this resolves via the shared cache (same key
		// + names as :443), so normally no upstream issuance happens.
		cert, err = obtainDashboardCert(cas, cn, top.DNSNames, key)
		if err != nil {
			return nil, fmt.Errorf("dashboard TLS (sharing %q): %w", cn, err)
		}
		if err := writeCertPEM(certPath, cert.Certificate); err != nil {
			return nil, fmt.Errorf("dashboard TLS: saving certificate copy: %w", err)
		}
	}
	var current atomic.Pointer[tls.Certificate]
	current.Store(&cert)

	// Background renewal: when the certificate's cache age is exhausted
	// (tls_max_age_days) or it is close to expiry, obtain a fresh one,
	// persist it, and swap it in atomically — the dashboard switches to
	// the new certificate immediately, without a restart. The :443
	// listener renews through the same shared cache, so both listeners
	// stay on one issuance cadence. A failed renewal keeps serving the
	// previous certificate.
	renew := func() {
		leaf, err := x509.ParseCertificate(current.Load().Certificate[0])
		if err != nil {
			return
		}
		age := time.Since(leaf.NotBefore)
		remaining := time.Until(leaf.NotAfter)
		if age < maxAge() && remaining >= 14*24*time.Hour {
			return
		}
		slog.Info("dashboard certificate past its cache age (or expiring), renewing",
			"cn", cn, "age", age.Round(time.Hour), "remaining", remaining.Round(time.Hour))
		newCert, err := obtainDashboardCert(cas, cn, top.DNSNames, key)
		if err != nil {
			slog.Error("dashboard cert renewal failed; keep serving previous certificate",
				"cn", cn, "error", err)
			return
		}
		if err := writeCertPEM(certPath, newCert.Certificate); err != nil {
			slog.Error("dashboard cert renewal: saving certificate failed", "error", err)
			return
		}
		current.Store(&newCert)
		slog.Info("dashboard certificate renewed and activated", "cn", cn)
	}
	go func() {
		renew() // check immediately at startup, without blocking the listener
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			renew()
		}
	}()

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return current.Load(), nil
		},
	}, nil
}

// loadOrCreateKey loads the persistent TLS private key shared with the
// client-facing listener, creating it on first use when missing. Accepts
// EC SEC1 and PKCS#8 (EC/RSA/Ed25519) PEM forms.
func loadOrCreateKey(path string) (crypto.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("TLS key %s is not valid PEM", path)
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if any, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if s, ok := any.(crypto.Signer); ok {
				return s, nil
			}
			return nil, fmt.Errorf("TLS key %s is not a signing key", path)
		}
		return nil, fmt.Errorf("TLS key %s could not be parsed", path)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// tlsMaxAge returns the maximum age of the proxy's own certificate before
// background renewal kicks in. Defaults to 30 days.
func (d dashboard) tlsMaxAge() time.Duration {
	if d.TLSMaxAgeDays > 0 {
		return time.Duration(d.TLSMaxAgeDays) * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
}

// writeCertPEM persists a DER chain as PEM certificates.
func writeCertPEM(path string, chain [][]byte) error {
	var buf bytes.Buffer
	for _, der := range chain {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return err
		}
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// obtainDashboardCert resolves the certificate for cn/sans via the proxy's
// upstream flow. With the shared :443 key and identical names this is a
// cache hit on the certificate the client-facing listener already serves.
func obtainDashboardCert(cas *ExternalCAS, cn string, sans []string, key crypto.Signer) (tls.Certificate, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	resp, err := cas.CreateCertificate(&apiv1.CreateCertificateRequest{
		CSR:      csr,
		Template: &x509.Certificate{},
	})
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := make([][]byte, 0, 1+len(resp.CertificateChain))
	chain = append(chain, resp.Certificate.Raw)
	for _, c := range resp.CertificateChain {
		chain = append(chain, c.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: key}, nil
}

// dashLoginChecker returns a handler that validates credentials against the
// ACTIVE values (hot-swappable via settings) and sets a session cookie.
func dashLoginChecker() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password := currentDashUser(), currentDashPass()
		userHash := sha256.Sum256([]byte(username))
		passHash := sha256.Sum256([]byte(password))
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		inUser := sha256.Sum256([]byte(body.Username))
		inPass := sha256.Sum256([]byte(body.Password))
		ok := subtle.ConstantTimeCompare(inUser[:], userHash[:]) ==
			subtle.ConstantTimeCompare(inPass[:], passHash[:])
		if !ok {
			// Slow down brute-force attempts.
			time.Sleep(500 * time.Millisecond)
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sid := hex.EncodeToString(token)
		dashSessionsMu.Lock()
		dashSessions[sid] = time.Now().Add(dashboardSessionTTL)
		dashSessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "acmeproxy_session",
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(dashboardSessionTTL.Seconds()),
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func dashLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("acmeproxy_session"); err == nil {
		dashSessionsMu.Lock()
		delete(dashSessions, c.Value)
		dashSessionsMu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

// dashAuth wraps a handler with session-cookie authentication.
func dashAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("acmeproxy_session")
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		dashSessionsMu.Lock()
		exp, ok := dashSessions[c.Value]
		if ok && time.Now().After(exp) {
			delete(dashSessions, c.Value)
			ok = false
		}
		dashSessionsMu.Unlock()
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode dashboard response", "error", err)
	}
}

func globalStoreAllIssued() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allIssued()
}

func globalStoreAllRevoked() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allRevoked()
}

func globalStoreAllCached() []CertRecord {
	if globalStore == nil {
		return nil
	}
	return globalStore.allCached()
}

// dashView is the JSON shape served to the dashboard.
type dashView struct {
	Serial          string  `json:"serial"`
	CommonName      string  `json:"common_name"`
	Issuer          string  `json:"issuer,omitempty"`
	SANs            string  `json:"sans"`
	IssuedAt        string  `json:"issued_at,omitempty"`
	ExpiresAt       string  `json:"expires_at,omitempty"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	Status          string  `json:"status"`
	ClientIP        string  `json:"client_ip,omitempty"`
	Error           string  `json:"error,omitempty"`
	RecordedAt      string  `json:"recorded_at"`

	at time.Time `json:"-"` // full-precision RecordedAt for sorting
}

func toView(r CertRecord) dashView {
	v := dashView{
		Serial:          r.Serial,
		CommonName:      r.CommonName,
		Issuer:          r.Issuer,
		SANs:            r.SANs,
		DurationSeconds: r.DurationSeconds,
		Status:          r.Status,
		ClientIP:        r.ClientIP,
		Error:           r.Error,
		at:              r.RecordedAt,
	}
	if !r.IssuedAt.IsZero() {
		v.IssuedAt = r.IssuedAt.UTC().Format(time.RFC3339)
	}
	if !r.ExpiresAt.IsZero() {
		v.ExpiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if !r.RecordedAt.IsZero() {
		v.RecordedAt = r.RecordedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// dashList serves a record list newest-first.
func dashList(src func() []CertRecord) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		records := src()
		out := make([]dashView, len(records))
		for i, rec := range records {
			out[i] = toView(rec)
		}
		sortViewsNewestFirst(out)
		writeJSON(w, out)
	}
}

func sortViewsNewestFirst(v []dashView) {
	// insertion sort is fine for dashboard-sized data
	// ponytail: O(n²); switch to sort.Slice if history grows past ~10k records
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].at.After(v[j-1].at); j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// dashFailed serves only failed issuance records.
func dashFailed(w http.ResponseWriter, r *http.Request) {
	var out []dashView
	for _, rec := range globalStoreAllIssued() {
		if rec.Status == "failure" {
			out = append(out, toView(rec))
		}
	}
	if out == nil {
		out = []dashView{}
	}
	sortViewsNewestFirst(out)
	writeJSON(w, out)
}

func dashRequests(w http.ResponseWriter, r *http.Request) {
	events := reqmeta.Events()
	if len(events) > 200 {
		events = events[:200]
	}
	if events == nil {
		events = []reqmeta.Event{}
	}
	writeJSON(w, events)
}

// domainSummary aggregates every issuance record (success and failure) that
// mentions one domain, for the domain-grouped certificate list.
type domainSummary struct {
	Domain          string   `json:"domain"`
	RequestCount    int      `json:"request_count"`
	SuccessCount    int      `json:"success_count"`
	FailureCount    int      `json:"failure_count"`
	LastRequestedAt string   `json:"last_requested_at"`
	LastStatus      string   `json:"last_status"`
	LastError       string   `json:"last_error,omitempty"`
	UniqueIPs       int      `json:"unique_ips"`
	UniqueIPList    []string `json:"unique_ip_list"`
	Serial          string   `json:"serial,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	Expired         bool     `json:"expired"`
	Cached          bool     `json:"cached"`
}

// recordDomains returns every domain a record mentions (SANs + CommonName),
// de-duplicated.
func recordDomains(r CertRecord) []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	add(r.CommonName)
	for _, d := range r.domains() {
		add(d)
	}
	return out
}

func recordMentionsDomain(r CertRecord, domain string) bool {
	for _, d := range recordDomains(r) {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// pageParams reads page/per_page with sane bounds (page >= 1, per_page 1..200,
// default 25).
func pageParams(r *http.Request) (page, perPage int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ = strconv.Atoi(r.URL.Query().Get("per_page"))
	if page < 1 {
		page = 1
	}
	switch {
	case perPage < 1:
		perPage = 25
	case perPage > 200:
		perPage = 200
	}
	return page, perPage
}

func paginate[T any](items []T, page, perPage int) []T {
	start := (page - 1) * perPage
	if start >= len(items) {
		return nil
	}
	end := start + perPage
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// aggregateDomains groups issuance records per domain name.
func aggregateDomains(records []CertRecord, cachedSans map[string]bool) map[string]*domainSummary {
	aggs := map[string]*domainSummary{}
	ips := map[string]map[string]bool{}
	for _, rec := range records {
		for _, domain := range recordDomains(rec) {
			agg, ok := aggs[domain]
			if !ok {
				agg = &domainSummary{Domain: domain}
				aggs[domain] = agg
				ips[domain] = map[string]bool{}
			}
			agg.RequestCount++
			if rec.Status == "success" {
				agg.SuccessCount++
				// Records arrive in chronological order, so the latest
				// successful cert keeps overwriting serial/expiry.
				if rec.Serial != "" {
					agg.Serial = rec.Serial
					agg.ExpiresAt = rfc3339(rec.ExpiresAt)
					agg.Expired = !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt)
				}
			} else {
				agg.FailureCount++
			}
			if rec.ClientIP != "" {
				ips[domain][rec.ClientIP] = true
			}
			// newest record wins for last_* fields (records are appended in
			// chronological order by the store)
			if rec.RecordedAt.After(time.Time{}) {
				agg.LastRequestedAt = rfc3339(rec.RecordedAt)
				agg.LastStatus = rec.Status
				agg.LastError = rec.Error
			}
		}
	}
	for domain, agg := range aggs {
		for ip := range ips[domain] {
			agg.UniqueIPList = append(agg.UniqueIPList, ip)
		}
		sortStrings(agg.UniqueIPList)
		agg.UniqueIPs = len(agg.UniqueIPList)
		for sans := range cachedSans {
			for _, d := range strings.Split(sans, ",") {
				if strings.EqualFold(strings.TrimSpace(d), domain) {
					agg.Cached = true
				}
			}
		}
	}
	return aggs
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func sortStrings(s []string) {
	sort.Strings(s) //nolint
}

// dashCertDomains serves the domain-grouped certificate list with
// server-side pagination and search.
func dashCertDomains(w http.ResponseWriter, r *http.Request) {
	page, perPage := pageParams(r)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	cachedSans := map[string]bool{}
	for _, c := range globalStoreAllCached() {
		cachedSans[c.SANs] = true
	}
	aggs := aggregateDomains(globalStoreAllIssued(), cachedSans)

	list := make([]*domainSummary, 0, len(aggs))
	for _, agg := range aggs {
		if q != "" && !strings.Contains(strings.ToLower(agg.Domain), q) {
			continue
		}
		list = append(list, agg)
	}
	// most recently active first
	sort.Slice(list, func(i, j int) bool { return list[i].LastRequestedAt > list[j].LastRequestedAt })

	total := len(list)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	writeJSON(w, map[string]any{
		"domains":     paginate(list, page, perPage),
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
	})
}

// dashCertDomainDetail serves every request record mentioning one domain,
// newest first, with pagination and the domain's cached certificate.
func dashCertDomainDetail(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}
	page, perPage := pageParams(r)

	var views []dashView
	for _, rec := range globalStoreAllIssued() {
		if recordMentionsDomain(rec, domain) {
			views = append(views, toView(rec))
		}
	}
	// newest first by full-precision timestamp; records without one (legacy)
	// sink to the bottom in a stable order.
	sort.SliceStable(views, func(i, j int) bool { return views[i].at.After(views[j].at) })

	var cachedCert map[string]string
	for _, c := range globalStoreAllCached() {
		for _, d := range strings.Split(c.SANs, ",") {
			if strings.EqualFold(strings.TrimSpace(d), domain) {
				cachedCert = map[string]string{
					"sans":       c.SANs,
					"serial":     c.Serial,
					"expires_at": rfc3339(c.ExpiresAt),
				}
			}
		}
	}

	total := len(views)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	resp := map[string]any{
		"domain":      domain,
		"total":       total,
		"page":        page,
		"per_page":    perPage,
		"total_pages": totalPages,
		"requests":    views,
	}
	if cachedCert != nil {
		resp["cached_cert"] = cachedCert
	}
	writeJSON(w, resp)
}

// dashCacheDelete drops one cached domain set so the next request for it
// must obtain a fresh certificate upstream.
func dashCacheDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" || globalStore == nil {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	if !globalStore.dropCached(key) {
		http.Error(w, "not cached", http.StatusNotFound)
		return
	}
	slog.Info("certificate cache entry deleted from dashboard", "domains", key)
	w.WriteHeader(http.StatusNoContent)
}

// dashSettingsGet returns the editable ca.json settings with their values.
func dashSettingsGet(w http.ResponseWriter, r *http.Request) {
	settings, err := currentSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, settings)
}

// dashSettingsPut validates, persists, and hot-applies ca.json changes.
func dashSettingsPut(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	applied, restart, err := saveSettings(body)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{
		"applied":          applied,
		"restart_required": restart,
	})
}

// dashACLGet returns the raw ACL file content for in-browser editing.
func dashACLGet(w http.ResponseWriter, r *http.Request) {
	content, err := acl.Content()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]string{
		"file":    acl.Path(),
		"content": content,
	})
}

// dashACLPut validates and saves new ACL content. Edits take effect on the
// next request — no daemon restart required.
func dashACLPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if bad := acl.Validate(body.Content); len(bad) > 0 {
		writeJSON(w, map[string]any{
			"error":   "invalid entries (nothing saved)",
			"invalid": bad,
		})
		return
	}
	if err := acl.Save(body.Content); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func dashOverview(w http.ResponseWriter, r *http.Request) {
	var issued, failed, revoked, last24 int
	type expiringT struct {
		Serial     string `json:"serial"`
		CommonName string `json:"common_name"`
		SANs       string `json:"sans"`
		ExpiresAt  string `json:"expires_at"`
	}
	var expiring []expiringT
	now := time.Now()
	for _, rec := range globalStoreAllIssued() {
		switch {
		case rec.Status != "success":
			failed++
		default:
			issued++
		}
		if !rec.RecordedAt.IsZero() && now.Sub(rec.RecordedAt) < 24*time.Hour {
			last24++
		}
		if rec.Status == "success" && rec.ExpiresAt.After(now) && rec.ExpiresAt.Sub(now) < 7*24*time.Hour {
			expiring = append(expiring, expiringT{
				Serial:     rec.Serial,
				CommonName: rec.CommonName,
				SANs:       rec.SANs,
				ExpiresAt:  rec.ExpiresAt.UTC().Format(time.RFC3339),
			})
		}
	}
	for range globalStoreAllRevoked() {
		revoked++
	}
	events := reqmeta.Events()
	if len(events) > 20 {
		events = events[:20]
	}
	if events == nil {
		events = []reqmeta.Event{}
	}
	if expiring == nil {
		expiring = []expiringT{}
	}
	writeJSON(w, map[string]any{
		"issued_total":       issued,
		"failed_total":       failed,
		"revoked_total":      revoked,
		"cached_total":       len(globalStoreAllCached()),
		"issued_last_24h":    last24,
		"expiring_within_7d": expiring,
		"recent":             events,
	})
}
