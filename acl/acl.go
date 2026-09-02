// Package acl enforces an allow-list of client IPs/subnets for ACME
// requests. The list lives in a plain text file that is re-read whenever it
// changes, so edits take effect without restarting the daemon.
//
// File format: one entry per line — an IP (192.168.100.1), a CIDR subnet
// (192.168.100.0/24), or a '#' comment. Blank lines are ignored.
package acl

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/esnet/acme-proxy/reqmeta"
)

type state struct {
	entries []netip.Prefix // single IPs become /32 or /128 prefixes
	modTime time.Time
	size    int64
	invalid []string // unparsable lines (still shown, never matched)
}

var (
	path atomic.Pointer[string]
	cur  atomic.Pointer[state]
	mu   sync.Mutex // serializes reloads and writes
)

// SetFile enables the ACL at path. Until called (or with an empty path) all
// requests are allowed. A configured file that cannot be read leaves the ACL
// in deny-all mode (see Allowed) with an error logged.
func SetFile(p string) {
	if p == "" {
		return
	}
	path.Store(&p)
	if err := reload(); err != nil {
		slog.Error("acl file could not be loaded; denying all clients until fixed",
			"file", p, "error", err)
	}
}

// Path returns the configured ACL file path ("" when disabled).
func Path() string {
	if p := path.Load(); p != nil {
		return *p
	}
	return ""
}

func reload() error {
	p := Path()
	if p == "" {
		return nil
	}
	st, err := load(p)
	if err != nil {
		return err
	}
	cur.Store(st)
	return nil
}

func load(p string) (*state, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	st := &state{modTime: fi.ModTime(), size: fi.Size()}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if prefix, err := netip.ParsePrefix(line); err == nil {
			st.entries = append(st.entries, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(line); err == nil {
			st.entries = append(st.entries, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		st.invalid = append(st.invalid, line)
	}
	return st, nil
}

// maybeReload re-reads the file only when its mtime or size changed.
// ponytail: mtime granularity may miss same-second edits of identical size;
// force via dashboard save or restart if that ever bites.
func maybeReload() {
	p := Path()
	if p == "" {
		return
	}
	st := cur.Load()
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	if st == nil || !fi.ModTime().Equal(st.modTime) || fi.Size() != st.size {
		mu.Lock()
		defer mu.Unlock()
		if err := reload(); err != nil {
			// keep serving the previous list on a failed reload
			return
		}
	}
}

// Allowed reports whether the client IP is permitted by the ACL. With no
// file configured the ACL is disabled (allow all). With a configured file
// that cannot be read at startup, fail closed.
func Allowed(ip string) bool {
	maybeReload()
	st := cur.Load()
	if st == nil {
		return Path() == ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range st.entries {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// AllowedRequest applies Allowed to the request's client IP (X-Forwarded-For
// aware, same resolution as request logging).
func AllowedRequest(r *http.Request) bool {
	return Allowed(reqmeta.RemoteIP(r))
}

// Content returns the raw ACL file for editing.
func Content() (string, error) {
	p := Path()
	if p == "" {
		return "", fmt.Errorf("acl file not configured")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Validate parses content and returns the unparsable lines (empty when valid).
func Validate(content string) (invalid []string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := netip.ParsePrefix(line); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(line); err == nil {
			continue
		}
		invalid = append(invalid, line)
	}
	return invalid
}

// Save validates and writes content to the ACL file, then reloads it.
func Save(content string) error {
	p := Path()
	if p == "" {
		return fmt.Errorf("acl file not configured")
	}
	if bad := Validate(content); len(bad) > 0 {
		return fmt.Errorf("invalid ACL entries: %s", strings.Join(bad, ", "))
	}
	mu.Lock()
	defer mu.Unlock()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		return err
	}
	return reload()
}
