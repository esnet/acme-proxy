package externalcas

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns"

	"github.com/esnet/acme-proxy/acl"
	stepconfig "github.com/smallstep/certificates/authority/config"
)

// currentCAS is the active ExternalCAS instance, set once in New(). The
// settings reload applies new configuration to it in place.
var currentCAS atomic.Pointer[ExternalCAS]

// dynamicSem is a counting semaphore whose capacity can be swapped at
// runtime. A release always drains the channel the acquire used, so resizing
// never corrupts slot accounting for in-flight requests.
type dynamicSem struct {
	mu sync.RWMutex
	ch chan struct{}
}

func newDynamicSem(n int) *dynamicSem {
	s := &dynamicSem{}
	s.resize(n)
	return s
}

func (s *dynamicSem) resize(n int) {
	if n < 1 {
		n = 1
	}
	s.mu.Lock()
	s.ch = make(chan struct{}, n)
	s.mu.Unlock()
}

func (s *dynamicSem) capacity() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cap(s.ch)
}

func (s *dynamicSem) acquire(ctx context.Context) (chan struct{}, error) {
	s.mu.RLock()
	ch := s.ch
	s.mu.RUnlock()
	select {
	case ch <- struct{}{}:
		return ch, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *dynamicSem) release(ch chan struct{}) {
	<-ch
}

// conf returns the active authority config (hot-swapped on settings reload).
func (c *ExternalCAS) conf() *acmeProxyConfig {
	return c.cfg.Load()
}

// setChallengeProviders (re)builds the shared challenge providers for cfg.
// Called at startup and by the settings reload when challenge/DNS settings
// change.
func (c *ExternalCAS) setChallengeProviders(cfg *acmeProxyConfig) error {
	switch cfg.challengeType {
	case "dns-01":
		for k, v := range cfg.Lego.Env_Vars {
			os.Setenv(k, v)
		}
		provider, err := dns.NewDNSChallengeProviderByName(cfg.Lego.Provider)
		if err != nil {
			return fmt.Errorf("failed to create DNS provider %q: %w", cfg.Lego.Provider, err)
		}
		c.challengeMu.Lock()
		c.dnsProvider = provider
		c.challengeProvider = provider
		c.challengeMu.Unlock()
	case "http-01":
		c.challengeMu.Lock()
		c.challengeProvider = newSharedHTTP01Provider(cfg.HTTP01BindAddr())
		c.challengeMu.Unlock()
	case "tls-alpn-01":
		c.challengeMu.Lock()
		c.challengeProvider = newSharedTLSALPN01Provider(cfg.TLSALPN01BindAddr())
		c.challengeMu.Unlock()
	}
	return nil
}

// challengeProviderForClient hands createLegoClient a consistent provider pair.
func (c *ExternalCAS) challengeProviderForClient() (challenge.Provider, challenge.Provider) {
	c.challengeMu.RLock()
	defer c.challengeMu.RUnlock()
	return c.challengeProvider, c.dnsProvider
}

// settingsEditable is the schema of ca.json keys the settings UI may change.
// Everything else in ca.json is left untouched on save.
type settingsSchema struct {
	Authority struct {
		Config map[string]any `json:"config"`
	} `json:"authority"`
	Dashboard map[string]any `json:"dashboard"`
	ACL       map[string]any `json:"acl"`
}

// authorityConfigKeys are the hot/known keys allowed under authority.config.
var authorityConfigKeys = map[string]bool{
	"ca_url": true, "account_email": true,
	"eab_kid": true, "eab_hmac_key": true,
	"challenge_type":    true,
	"dns01_txt":         true,
	"cert_poll_timeout": true, "request_timeout": true,
	"cert_cache_min_validity": true, "cert_cache_max_age": true,
	"certlifetime": true,
	"http01_bind":  true, "http01_port": true,
	"tlsalpn01_bind": true, "tlsalpn01_port": true,
	"max_concurrent_requests": true,
}

var dashboardKeys = map[string]bool{
	"port": true, "bind": true,
	"username": true, "password": true,
	"tls_cert": true, "tls_key": true,
	"tls_max_age_days": true,
}

// readRawConfig reads ca.json as a generic map (comments stripped).
func readRawConfig() (map[string]any, error) {
	raw, err := os.ReadFile(stepconfig.LoadedFilepath)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(stepconfig.StripJSONComments(raw), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// applySettingsInMemory swaps the validated config into the running process:
// authority config (invalidating the cached ACME account when the upstream
// identity changed), rebuilt challenge providers, dashboard credentials and
// TLS max age, and the ACL file.
func applySettingsInMemory(newCfg *acmeProxyConfig, newDash dashboard, newACLFile string, old *ExternalCAS) error {
	oldCfg := old.conf()

	// Upstream identity change requires a fresh account registration.
	if oldCfg.CaURL != newCfg.CaURL || oldCfg.Email != newCfg.Email ||
		oldCfg.Kid != newCfg.Kid || oldCfg.HmacKey != newCfg.HmacKey {
		old.acctMu.Lock()
		old.account = nil
		old.acctMu.Unlock()
		slog.Info("settings reload: upstream CA identity changed, cached ACME account cleared")
	}

	// Challenge-related change requires rebuilt providers.
	if oldCfg.challengeType != newCfg.challengeType ||
		oldCfg.Lego.Provider != newCfg.Lego.Provider ||
		oldCfg.HTTP01BindAddr() != newCfg.HTTP01BindAddr() ||
		oldCfg.TLSALPN01BindAddr() != newCfg.TLSALPN01BindAddr() {
		if err := old.setChallengeProviders(newCfg); err != nil {
			return err
		}
	}

	old.cfg.Store(newCfg)

	if newDash.Username != "" || newDash.Password != "" {
		setDashCreds(newDash)
	}
	oldDash := getDashConfig()
	setDashConfig(newDash)

	// Manual TLS files changed: swap the certificate material first.
	if newDash.TLSCert != "" && (newDash.TLSCert != oldDash.TLSCert || newDash.TLSKey != oldDash.TLSKey) {
		if err := reloadManualDashTLS(newDash); err != nil {
			slog.Error("settings reload: dashboard tls_cert/tls_key rejected, keeping previous", "error", err)
		}
	}

	// Listener address (or TLS mode) changed: rebind without a restart.
	if newDash.enabled && (newDash.Port != oldDash.Port || newDash.Bind != oldDash.Bind ||
		newDash.TLSCert != oldDash.TLSCert || newDash.TLSKey != oldDash.TLSKey) {
		if err := restartDashboardListener(newDash); err != nil {
			slog.Error("settings reload: dashboard rebind failed, previous listener keeps serving", "error", err)
		}
	}

	// Concurrency limit changed: resize the live semaphore.
	if old.sem != nil && newCfg.MaxConcurrentRequests != oldCfg.MaxConcurrentRequests {
		old.sem.resize(newCfg.MaxConcurrentRequestsOrDefault())
		slog.Info("settings reload: concurrency limit updated", "max", newCfg.MaxConcurrentRequestsOrDefault())
	}

	if newACLFile != "" {
		acl.SetFile(newACLFile)
		slog.Info("settings reload: acl file set", "file", newACLFile)
	}
	return nil
}

// saveSettings validates the desired partial ca.json, merges it into the
// live file (with a backup), and hot-applies it. Unknown keys are rejected.
func saveSettings(desired []byte) (applied []string, restart []string, err error) {
	old := currentCAS.Load()
	if old == nil || stepconfig.LoadedFilepath == "" {
		return nil, nil, fmt.Errorf("settings are unavailable (daemon not fully started)")
	}

	var want settingsSchema
	if err := json.Unmarshal(desired, &want); err != nil {
		return nil, nil, fmt.Errorf("invalid settings payload: %w", err)
	}
	for k := range want.Authority.Config {
		if !authorityConfigKeys[k] {
			return nil, nil, fmt.Errorf("unknown authority.config key %q", k)
		}
	}
	for k := range want.Dashboard {
		if !dashboardKeys[k] {
			return nil, nil, fmt.Errorf("unknown dashboard key %q", k)
		}
	}
	for k := range want.ACL {
		if k != "file" {
			return nil, nil, fmt.Errorf("unknown acl key %q", k)
		}
	}

	// Read current file, merge, and re-serialize.
	doc, err := readRawConfig()
	if err != nil {
		return nil, nil, err
	}
	mergeMap(doc, "authority", map[string]any{"config": want.Authority.Config})
	mergeMap(doc, "dashboard", want.Dashboard)
	mergeMap(doc, "acl", want.ACL)

	merged, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, err
	}

	// Validate the merged document end-to-end BEFORE touching disk.
	var full struct {
		Authority struct {
			Config json.RawMessage `json:"config"`
		} `json:"authority"`
		Dashboard dashboard     `json:"dashboard"`
		ACL       aclFileConfig `json:"acl"`
		Metrics   metrics       `json:"-"`
	}
	if err := json.Unmarshal(merged, &full); err != nil {
		return nil, nil, fmt.Errorf("merged config invalid: %w", err)
	}
	newCfg, err := parseConfig(full.Authority.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("merged authority config invalid: %w", err)
	}
	// dashboard data_source defaults to authority.config.metrics.dataSource
	var m struct {
		Authority struct {
			Config struct {
				Metrics metrics `json:"metrics"`
			} `json:"config"`
		} `json:"authority"`
	}
	_ = json.Unmarshal(merged, &m)
	if err := full.Dashboard.validate(m.Authority.Config.Metrics); err != nil {
		return nil, nil, fmt.Errorf("merged dashboard config invalid: %w", err)
	}

	// Backup, then write the normalized file (comments are dropped; the
	// backup preserves them).
	backup := stepconfig.LoadedFilepath + ".bak-settings"
	if raw, err := os.ReadFile(stepconfig.LoadedFilepath); err == nil {
		if err := os.WriteFile(backup, raw, 0o600); err != nil {
			return nil, nil, fmt.Errorf("could not write backup %s: %w", backup, err)
		}
	}
	header := "# Generated by the dashboard settings UI — '#'-comments from the previous file are preserved in ca.json.bak-settings\n"
	if err := os.WriteFile(stepconfig.LoadedFilepath, append([]byte(header), merged...), 0o600); err != nil {
		return nil, nil, fmt.Errorf("could not write ca.json: %w", err)
	}

	// Hot-apply.
	if err := applySettingsInMemory(newCfg, full.Dashboard, full.ACL.File, old); err != nil {
		return nil, nil, fmt.Errorf("saved to ca.json but hot-apply failed (restart to pick up): %w", err)
	}

	slog.Info("settings saved and applied", "file", stepconfig.LoadedFilepath)

	for k := range want.Authority.Config {
		applied = append(applied, "authority.config."+k)
	}
	for k := range want.Dashboard {
		applied = append(applied, "dashboard."+k)
	}
	for k := range want.ACL {
		applied = append(applied, "acl."+k)
	}
	return applied, restart, nil
}

// mergeMap merges src's non-nil entries into doc[path]; nested one level for
// authority.config.
func mergeMap(doc map[string]any, path string, src map[string]any) {
	if len(src) == 0 {
		return
	}
	dst, _ := doc[path].(map[string]any)
	if dst == nil {
		dst = map[string]any{}
		doc[path] = dst
	}
	for k, v := range src {
		if k == "config" {
			sub, _ := v.(map[string]any)
			if len(sub) == 0 {
				continue
			}
			dstCfg, _ := dst["config"].(map[string]any)
			if dstCfg == nil {
				dstCfg = map[string]any{}
				dst["config"] = dstCfg
			}
			for k2, v2 := range sub {
				dstCfg[k2] = v2
			}
			continue
		}
		dst[k] = v
	}
}

// currentSettings builds the GET /api/settings payload from the live config.
func currentSettings() (map[string]any, error) {
	old := currentCAS.Load()
	if old == nil || stepconfig.LoadedFilepath == "" {
		return nil, fmt.Errorf("settings are unavailable")
	}
	c := old.conf()
	d := getDashConfig()
	settings := map[string]any{
		"file": stepconfig.LoadedFilepath,
		"authority": map[string]any{"config": map[string]any{
			"ca_url":                  c.CaURL,
			"account_email":           c.Email,
			"eab_kid":                 c.Kid,
			"eab_hmac_key":            c.HmacKey,
			"challenge_type":          c.ChallengeType,
			"dns01_txt":               c.Lego,
			"cert_poll_timeout":       c.CertPollTimeout,
			"request_timeout":         c.RequestTimeout,
			"cert_cache_min_validity": c.CertCacheMinValidity,
			"cert_cache_max_age":      c.CertCacheMaxAge,
			"http01_bind":             c.HTTP01Bind,
			"http01_port":             c.HTTP01Port,
			"tlsalpn01_bind":          c.TLSALPN01Bind,
			"tlsalpn01_port":          c.TLSALPN01Port,
			"max_concurrent_requests": c.MaxConcurrentRequests,
		}},
		"dashboard": map[string]any{
			"port":             d.Port,
			"bind":             d.Bind,
			"username":         d.Username,
			"password":         d.Password,
			"tls_max_age_days": d.TLSMaxAgeDays,
		},
		"acl": map[string]any{"file": acl.Path()},
	}
	return settings, nil
}
