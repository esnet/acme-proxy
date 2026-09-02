// Package reqmeta records per-request metadata (client IP) at the ACME API
// layer and serves it to the externalcas plugin, which sits behind an
// interface that cannot carry a client IP.
//
// The API layer correlates a finalize request to its CSR public key; the CAS
// later looks the IP up by the same key. New-order and revoke events are kept
// in a small ring buffer as a request log for the dashboard.
package reqmeta

import (
	"crypto/sha256"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event is one ACME API request log entry.
type Event struct {
	At     time.Time `json:"at"`
	IP     string    `json:"ip"`
	Kind   string    `json:"kind"` // "new-order", "finalize", "revoke"
	Detail string    `json:"detail"`
}

const logSize = 1000

var (
	mu       sync.RWMutex
	log      []Event
	finalize = map[[32]byte]string{} // CSR public key hash -> client IP
	revoke   = map[string]string{}   // cert serial (decimal) -> client IP
)

// Record is the entry point wired into the fork's ACME API hook. It logs the
// event and, when a CSR or serial is present, remembers the client IP so the
// CAS layer can attribute the issuance/revocation to this client.
func Record(r *http.Request, kind, detail string, csr *x509.CertificateRequest, serial string) {
	ip := RemoteIP(r)
	RecordEvent(ip, kind, detail)
	if csr != nil {
		RecordFinalize(csr, ip)
	}
	if serial != "" {
		RecordRevoke(serial, ip)
	}
}

// RemoteIP returns the client IP for r. It prefers the first X-Forwarded-For
// value so deployments behind a reverse proxy log the real client.
// ponytail: trusts XFF blindly; add a trusted-proxy list if exposed directly.
func RemoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// RecordEvent appends an ACME API event to the request log.
func RecordEvent(ip, kind, detail string) {
	mu.Lock()
	defer mu.Unlock()
	log = append(log, Event{At: time.Now().UTC(), IP: ip, Kind: kind, Detail: detail})
	if len(log) > logSize {
		log = log[len(log)-logSize:]
	}
}

// RecordFinalize associates a CSR with the client that submitted the finalize
// request, so the issuance record can be attributed to that client IP.
func RecordFinalize(csr *x509.CertificateRequest, ip string) {
	if csr == nil {
		return
	}
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	finalize[sha256.Sum256(pub)] = ip
}

// LookupFinalize returns (and forgets) the client IP recorded for this CSR.
func LookupFinalize(csr *x509.CertificateRequest) string {
	if csr == nil {
		return ""
	}
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return ""
	}
	key := sha256.Sum256(pub)
	mu.Lock()
	defer mu.Unlock()
	ip := finalize[key]
	delete(finalize, key)
	return ip
}

// RecordRevoke associates a certificate serial (decimal) with the client that
// requested revocation.
func RecordRevoke(serial, ip string) {
	if serial == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	revoke[serial] = ip
}

// LookupRevoke returns (and forgets) the client IP recorded for this serial.
func LookupRevoke(serial string) string {
	mu.Lock()
	defer mu.Unlock()
	ip := revoke[serial]
	delete(revoke, serial)
	return ip
}

// Events returns a copy of the request log, newest first.
func Events() []Event {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Event, len(log))
	copy(out, log)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
