package externalcas

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	stepconfig "github.com/smallstep/certificates/authority/config"
)

// Configuration bits for a DNS provider as per Lego docs
type legoConfig struct {
	Provider       string            `json:"provider"`
	DnsServersList []string          `json:"dns_servers"`
	Env_Vars       map[string]string `json:"env_vars"`
}

type metrics struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Port       int    `json:"port,omitempty"`
	DataSource string `json:"dataSource,omitempty"`
}

type dashboard struct {
	// Listen port. Dashboard is enabled when port > 0. Must not conflict
	// with the client-facing listener or the challenge listeners.
	Port int `json:"port,omitempty"`

	// Bind IP; empty binds all interfaces.
	Bind string `json:"bind,omitempty"`

	// Credentials; default to admin/kambing when empty.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Optional TLS. When both tls_cert and tls_key are set the dashboard
	// serves those PEM files. When tls_domain is set instead, the proxy
	// obtains a publicly-valid certificate for that domain from the
	// upstream CA (http-01/dns-01 as configured) and renews it
	// automatically; the private key is generated once and kept next to
	// the sidecar store.
	TLSCert   string `json:"tls_cert,omitempty"`
	TLSKey    string `json:"tls_key,omitempty"`
	TLSDomain string `json:"tls_domain,omitempty"`

	// TLSMaxAgeDays is the maximum age in days of the proxy's own
	// certificate before it is renewed in the background (optional,
	// default 30). The certificate on disk is always served — renewal
	// swaps it atomically once the new one arrives — so restarts and
	// rate-limit failures never take the dashboard down or issue
	// needless certificates.
	TLSMaxAgeDays int `json:"tls_max_age_days,omitempty"`

	// Path to the sidecar bbolt store. Defaults to metrics.dataSource.
	DataSource string `json:"data_source,omitempty"`

	enabled bool // derived during Validate()
}

// AcmeProxyConfig contains the configuration for connecting to an external ACME CA
type acmeProxyConfig struct {
	// ACME directory url of External CA (required)
	CaURL string `json:"ca_url"`

	// External Account Binding
	Email string `json:"account_email,omitempty"`

	Kid     string `json:"eab_kid"`
	HmacKey string `json:"eab_hmac_key"`

	// Certificate lifetime in days (optional)
	CertLifetime int `json:"certlifetime,omitempty"`

	// Certificate polling timeout in seconds (optional, default 30)
	CertPollTimeout int `json:"cert_poll_timeout,omitempty"`

	// Total timeout in seconds for one certificate request towards the
	// external CA, including challenge validation and cert polling
	// (optional, default 120). Slow CAs (e.g. ZeroSSL) may need this raised
	// well above cert_poll_timeout.
	RequestTimeout int `json:"request_timeout,omitempty"`

	// Minimum remaining certificate validity in days to serve from cache (optional, default 7)
	CertCacheMinValidity int `json:"cert_cache_min_validity,omitempty"`

	// Maximum age in days of a cached certificate that may still be served
	// (optional, default 30). Older cache entries force a fresh issuance so
	// renewal cadence stays bounded even when upstream certificates are
	// long-lived (e.g. 90-day certs ahead of shorter-lived defaults).
	CertCacheMaxAge int `json:"cert_cache_max_age,omitempty"`

	// Lego provider connection variables for dns01 TXT challenge
	Lego legoConfig `json:"dns01_txt"`

	// ChallengeType selects the ACME challenge type used to solve the upstream
	// challenge. Allowed values: "auto" (default/empty), "http-01",
	// "tls-alpn-01", "dns-01".
	ChallengeType string `json:"challenge_type,omitempty"`

	// HTTP01Port is the port the shared HTTP-01 challenge server binds to.
	// Defaults to 80 when 0.
	HTTP01Port int `json:"http01_port,omitempty"`

	// HTTP01Bind is the IP address the shared HTTP-01 challenge server binds
	// to. Empty (default) binds all interfaces. Set this to avoid conflicts
	// with the client-facing listener (top-level "address" in ca.json).
	HTTP01Bind string `json:"http01_bind,omitempty"`

	// TLSALPN01Port is the port the shared TLS-ALPN-01 challenge server binds to.
	// Defaults to 443 when 0.
	TLSALPN01Port int `json:"tlsalpn01_port,omitempty"`

	// TLSALPN01Bind is the IP address the shared TLS-ALPN-01 challenge server
	// binds to. Empty (default) binds all interfaces. Set this to avoid
	// conflicts with the client-facing listener (top-level "address" in ca.json).
	TLSALPN01Bind string `json:"tlsalpn01_bind,omitempty"`

	// MaxConcurrentRequests caps the number of simultaneous upstream ACME
	// operations (certificate issuance/revocation). Defaults to 1 when 0.
	MaxConcurrentRequests int `json:"max_concurrent_requests,omitempty"`

	// Prometheus metrics endpoint (optional)
	Metrics metrics `json:"metrics"`

	// derived during Validate(); not marshaled
	useEAB        bool
	challengeType string // normalized: "http-01", "tls-alpn-01", or "dns-01"
}

// Validate checks if the values provided in ca.json file contain required fields
// and valid values after they are unmarshalled into `acmeProxyConfig`
func (c *acmeProxyConfig) Validate() error {
	if c.CaURL == "" {
		return errors.New("ca_url is required")
	}

	// External Account Binding: both or neither of Kid/HmacKey must be set.
	switch {
	case c.Kid != "" && c.HmacKey != "":
		c.useEAB = true
	case c.Kid != "" || c.HmacKey != "":
		return errors.New("eab_kid and eab_hmac_key must be set together")
	}

	// Resolve the challenge type. "auto" (or empty) preserves the historical
	// behavior: dns-01 only when the DNS provider is fully configured
	// (provider != "" AND env_vars non-empty), otherwise http-01.
	switch c.ChallengeType {
	case "", "auto":
		if c.Lego.Provider != "" && len(c.Lego.Env_Vars) != 0 {
			c.challengeType = "dns-01"
		} else {
			c.challengeType = "http-01"
		}
	case "http-01":
		c.challengeType = "http-01"
	case "tls-alpn-01":
		c.challengeType = "tls-alpn-01"
	case "dns-01":
		if c.Lego.Provider == "" {
			return errors.New("challenge_type dns-01 requires dns01_txt.provider to be set")
		}
		c.challengeType = "dns-01"
	default:
		return fmt.Errorf("invalid challenge_type %q: must be one of \"auto\", \"http-01\", \"tls-alpn-01\", \"dns-01\"", c.ChallengeType)
	}

	// Port validation: 0 means "use the default"; otherwise must be in range.
	if c.HTTP01Port < 0 || c.HTTP01Port > 65535 {
		return errors.New("http01_port must be between 1 and 65535")
	}
	if c.TLSALPN01Port < 0 || c.TLSALPN01Port > 65535 {
		return errors.New("tlsalpn01_port must be between 1 and 65535")
	}

	// Bind validation: empty binds all interfaces; otherwise a literal IP.
	if c.HTTP01Bind != "" && net.ParseIP(c.HTTP01Bind) == nil {
		return fmt.Errorf("http01_bind %q is not a valid IP address", c.HTTP01Bind)
	}
	if c.TLSALPN01Bind != "" && net.ParseIP(c.TLSALPN01Bind) == nil {
		return fmt.Errorf("tlsalpn01_bind %q is not a valid IP address", c.TLSALPN01Bind)
	}

	if c.MaxConcurrentRequests < 0 {
		return errors.New("max_concurrent_requests cannot be negative")
	}

	if c.CertLifetime < 0 {
		return errors.New("certlifetime cannot be negative")
	}
	if c.CertPollTimeout < 0 {
		return errors.New("cert_poll_timeout cannot be negative")
	}
	if c.RequestTimeout < 0 {
		return errors.New("request_timeout cannot be negative")
	}
	if c.CertCacheMinValidity < 0 {
		return errors.New("cert_cache_min_validity cannot be negative")
	}
	if c.CertCacheMaxAge < 0 {
		return errors.New("cert_cache_max_age cannot be negative")
	}

	// Consider Metrics enabled only when port & datasource both are defined
	if c.Metrics.Port > 0 && c.Metrics.DataSource != "" {
		c.Metrics.Enabled = true
	}

	if (c.Metrics.Port > 0 && c.Metrics.DataSource == "") || (c.Metrics.Port == 0 && c.Metrics.DataSource != "") {
		return errors.New("invalid metrics port or dataSource.\nRefer docs https://software.es.net/acme-proxy/configuration")
	}
	return nil
}

// topLevelConfig mirrors the top-level ca.json blocks the plugin owns.
// The dashboard and ACL live outside "authority" because they configure
// sidecar services of the enclosing binary, not the CA authority itself.
type topLevelConfig struct {
	Dashboard  dashboard     `json:"dashboard"`
	ACL        aclFileConfig `json:"acl"`
	DNSNames   []string      `json:"dnsNames"`
	CommonName string        `json:"commonName"`
}

type aclFileConfig struct {
	// File is the path to the client allow-list (IPs/subnets, '#' comments).
	File string `json:"file"`
}

// validateDashboard checks the derived dashboard settings. The data source
// defaults to metrics.dataSource.
func (d *dashboard) validate(m metrics) error {
	if d.Port < 0 || d.Port > 65535 {
		return errors.New("dashboard port must be between 1 and 65535")
	}
	if d.Port > 0 {
		d.enabled = true
	}
	if d.Bind != "" && net.ParseIP(d.Bind) == nil {
		return fmt.Errorf("dashboard bind %q is not a valid IP address", d.Bind)
	}
	if (d.TLSCert == "") != (d.TLSKey == "") {
		return errors.New("dashboard tls_cert and tls_key must be set together")
	}
	if d.TLSDomain != "" && d.TLSCert != "" {
		return errors.New("dashboard tls_domain and tls_cert are mutually exclusive")
	}
	if d.TLSMaxAgeDays < 0 {
		return errors.New("dashboard tls_max_age_days cannot be negative")
	}
	if d.TLSDomain != "" {
		return errors.New("dashboard tls_domain is no longer supported: the dashboard now always shares the certificate and key used by the client-facing :443 listener (remove tls_domain)")
	}
	if d.enabled {
		if d.DataSource == "" {
			d.DataSource = m.DataSource
		}
		if d.DataSource == "" {
			return errors.New("dashboard requires data_source (or metrics.dataSource)")
		}
	}
	return nil
}

// loadTopLevelConfig reads the dashboard and acl blocks from the ca.json the
// fork loaded (path + comment stripping come from the fork's config package,
// so '#' comments in ca.json are supported here too). Missing file or parse
// errors disable both features with a warning.
func loadTopLevelConfig() topLevelConfig {
	var top topLevelConfig
	if stepconfig.LoadedFilepath == "" {
		return top
	}
	raw, err := os.ReadFile(stepconfig.LoadedFilepath)
	if err != nil {
		slog.Warn("could not re-read ca.json for dashboard/acl config", "path", stepconfig.LoadedFilepath, "error", err)
		return top
	}
	if err := json.Unmarshal(stepconfig.StripJSONComments(raw), &top); err != nil {
		slog.Warn("could not parse top-level ca.json blocks", "error", err)
	}
	return top
}

// MaxConcurrentRequestsOrDefault returns the configured maximum number of
// concurrent upstream ACME operations, defaulting to 1 when unset.
func (c *acmeProxyConfig) MaxConcurrentRequestsOrDefault() int {
	if c.MaxConcurrentRequests > 0 {
		return c.MaxConcurrentRequests
	}
	return 1
}

// HTTP01PortOrDefault returns the configured HTTP-01 challenge port,
// defaulting to 80 when unset.
func (c *acmeProxyConfig) HTTP01PortOrDefault() int {
	if c.HTTP01Port > 0 {
		return c.HTTP01Port
	}
	return 80
}

// TLSALPN01PortOrDefault returns the configured TLS-ALPN-01 challenge port,
// defaulting to 443 when unset.
func (c *acmeProxyConfig) TLSALPN01PortOrDefault() int {
	if c.TLSALPN01Port > 0 {
		return c.TLSALPN01Port
	}
	return 443
}

// HTTP01BindAddr returns the listen address (host:port) for the shared
// HTTP-01 challenge server. With no bind IP configured it binds all
// interfaces (":80" by default).
func (c *acmeProxyConfig) HTTP01BindAddr() string {
	return net.JoinHostPort(c.HTTP01Bind, strconv.Itoa(c.HTTP01PortOrDefault()))
}

// TLSALPN01BindAddr returns the listen address (host:port) for the shared
// TLS-ALPN-01 challenge server. With no bind IP configured it binds all
// interfaces (":443" by default).
func (c *acmeProxyConfig) TLSALPN01BindAddr() string {
	return net.JoinHostPort(c.TLSALPN01Bind, strconv.Itoa(c.TLSALPN01PortOrDefault()))
}

// HTTPTimeout returns the timeout for HTTP client operations
func (c *acmeProxyConfig) HTTPTimeout() time.Duration {
	return 90 * time.Second
}

// RequestTimeoutDuration returns the total timeout for one certificate
// request towards the external CA (challenge validation + cert polling).
// Defaults to 120 seconds if not configured. For slow CAs, keep this above
// cert_poll_timeout plus the time challenges need to validate.
func (c *acmeProxyConfig) RequestTimeoutDuration() time.Duration {
	if c.RequestTimeout > 0 {
		return time.Duration(c.RequestTimeout) * time.Second
	}
	return 120 * time.Second
}

// CertPollTimeoutDuration returns the timeout for polling the ACME server
// for the issued certificate after challenge validation.
// Defaults to 30 seconds if not configured.
func (c *acmeProxyConfig) CertPollTimeoutDuration() time.Duration {
	if c.CertPollTimeout > 0 {
		return time.Duration(c.CertPollTimeout) * time.Second
	}
	return 30 * time.Second
}

// CertCacheMinValidityDuration returns the minimum remaining validity
// for a cached certificate to be considered usable.
// Defaults to 7 days if not configured.
func (c *acmeProxyConfig) CertCacheMinValidityDuration() time.Duration {
	if c.CertCacheMinValidity > 0 {
		return time.Duration(c.CertCacheMinValidity) * 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// CertCacheMaxAgeDuration returns the maximum age of a cached certificate
// that may still be served; older entries force a fresh issuance.
// Defaults to 30 days if not configured.
func (c *acmeProxyConfig) CertCacheMaxAgeDuration() time.Duration {
	if c.CertCacheMaxAge > 0 {
		return time.Duration(c.CertCacheMaxAge) * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
}

// parseConfig is a helper function which reads ca.json file as rawjson and validates
// acme-proxy specific configuration bits under the `authority` section of the config
func parseConfig(raw json.RawMessage) (*acmeProxyConfig, error) {
	var cfg acmeProxyConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
