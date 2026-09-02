package externalcas

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/challenge/tlsalpn01"
)

// httpChallengeEntry holds the state for a single http-01 challenge.
type httpChallengeEntry struct {
	domain  string
	keyAuth string
}

// sharedHTTP01Provider implements challenge.Provider and serves many
// simultaneous http-01 challenges on a single listener ("virtual server").
// The listener is bound lazily on the first Present call and stays open for
// the process lifetime; CleanUp only removes the token from the map.
type sharedHTTP01Provider struct {
	addr string

	mu       sync.RWMutex
	entries  map[string]httpChallengeEntry // keyed by token
	listener net.Listener
}

// newSharedHTTP01Provider creates a provider bound to addr (e.g. ":80").
// Binding happens lazily on the first Present so construction never fails.
func newSharedHTTP01Provider(addr string) *sharedHTTP01Provider {
	return &sharedHTTP01Provider{
		addr:    addr,
		entries: make(map[string]httpChallengeEntry),
	}
}

// Present stores the token and lazily starts the shared HTTP server.
func (p *sharedHTTP01Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.entries[token] = httpChallengeEntry{domain: domain, keyAuth: keyAuth}

	if p.listener == nil {
		ln, err := net.Listen("tcp", p.addr)
		if err != nil {
			// Do not cache the failure: the next Present retries the bind
			// (e.g. the port may have been freed in the meantime) and gets
			// a clear error instead of a silently unserved challenge.
			return fmt.Errorf("could not start HTTP server for challenge: %w", err)
		}
		p.listener = ln
		go p.serve(ln)
	}
	return nil
}

// serve runs the shared HTTP server until the listener is closed.
func (p *sharedHTTP01Provider) serve(ln net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", p.handleChallenge)
	srv := &http.Server{Handler: mux}
	// Disable keep-alives so challenge connections do not linger.
	srv.SetKeepAlivesEnabled(false)
	if err := srv.Serve(ln); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		slog.Error("shared http-01 challenge server stopped", "error", err)
	}
}

// handleChallenge serves the key authorization for a token when the Host
// header matches the challenge domain; otherwise it returns 404.
func (p *sharedHTTP01Provider) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, http01.ChallengePath(""))
	if token == "" {
		http.NotFound(w, r)
		return
	}

	p.mu.RLock()
	entry, ok := p.entries[token]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	if !hostMatches(r.Host, entry.domain) {
		slog.Warn("received http-01 challenge request with non-matching host",
			"host", r.Host, "domain", entry.domain)
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(entry.keyAuth)); err != nil {
		slog.Error("failed to write http-01 key authorization", "error", err)
	}
}

// CleanUp removes the token from the map. When the last challenge is done
// (the map is empty) the shared listener is closed, so port 80 is not left
// exposed; the next Present lazily reopens it.
func (p *sharedHTTP01Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, token)
	if len(p.entries) == 0 && p.listener != nil {
		p.listener.Close()
		p.listener = nil
	}
	return nil
}

// hostMatches reports whether the request Host header matches the challenge
// domain, ignoring an optional numeric port and case.
func hostMatches(host, domain string) bool {
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i]
		}
	}
	return strings.EqualFold(h, domain)
}

// sharedTLSALPN01Provider implements challenge.Provider and serves many
// simultaneous tls-alpn-01 challenges on a single TLS listener. Certificates
// are keyed by lowercased domain and selected per SNI via GetCertificate.
type sharedTLSALPN01Provider struct {
	addr string

	mu       sync.RWMutex
	certs    map[string]*tls.Certificate // keyed by strings.ToLower(domain)
	listener net.Listener
}

// newSharedTLSALPN01Provider creates a provider bound to addr (e.g. ":443").
// Binding happens lazily on the first Present so construction never fails.
func newSharedTLSALPN01Provider(addr string) *sharedTLSALPN01Provider {
	return &sharedTLSALPN01Provider{
		addr:  addr,
		certs: make(map[string]*tls.Certificate),
	}
}

// Present generates the challenge certificate and lazily starts the shared
// TLS listener.
func (p *sharedTLSALPN01Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.certs[strings.ToLower(domain)] = cert

	if p.listener == nil {
		tlsConf := &tls.Config{
			NextProtos:     []string{tlsalpn01.ACMETLS1Protocol},
			GetCertificate: p.GetCertificate,
		}
		ln, err := tls.Listen("tcp", p.addr, tlsConf)
		if err != nil {
			// Do not cache the failure: the next Present retries the bind.
			return fmt.Errorf("could not start TLS-ALPN server for challenge: %w", err)
		}
		p.listener = ln
		go func() {
			if err := http.Serve(ln, nil); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("shared tls-alpn-01 challenge server stopped", "error", err)
			}
		}()
	}
	return nil
}

// GetCertificate returns the challenge certificate for the SNI server name,
// or nil (causing the TLS handshake to fail) when no challenge is pending.
func (p *sharedTLSALPN01Provider) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cert, ok := p.certs[strings.ToLower(chi.ServerName)]
	if !ok {
		return nil, nil
	}
	return cert, nil
}

// CleanUp removes the domain's challenge certificate.
func (p *sharedTLSALPN01Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.certs, strings.ToLower(domain))
	return nil
}
