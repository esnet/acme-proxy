package externalcas

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
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

	// Seconds to wait for the external CA to issue the certificate after the order
	// is finalized (optional, default 30 — lego's default). Some CAs run
	// post-finalization checks that take longer than that; must stay below
	// request_timeout so the outer context still bounds the whole request.
	CertObtainTimeout int `json:"cert_obtain_timeout,omitempty"`

	// Seconds the whole certificate request may take end to end — account
	// registration, authorizations, finalization and the wait above (optional,
	// default 120). Raise it together with cert_obtain_timeout.
	RequestTimeoutSec int `json:"request_timeout,omitempty"`

	// Lego provider connection variables for dns01 TXT challenge
	Lego legoConfig `json:"dns01_txt"`

	// Prometheus metrics endpoint (optional)
	Metrics metrics `json:"metrics"`

	// derived during Validate(); not marshaled
	useEAB   bool
	useDNS01 bool
}

// Validate checks if the values provided in ca.json file contain required fields
// and valid values after they are unmarshalled into `acmeProxyConfig`
func (c *acmeProxyConfig) Validate() error {
	if c.CaURL == "" {
		return errors.New("ca_url is required")
	}
	if c.Kid != "" && c.HmacKey != "" {
		c.useEAB = true
	}
	if c.Lego.Provider != "" && len(c.Lego.Env_Vars) != 0 {
		c.useDNS01 = true
	}

	if !c.useEAB && !c.useDNS01 {
		return errors.New("missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration")
	}
	if c.CertLifetime < 0 {
		return errors.New("certlifetime cannot be negative")
	}
	if c.CertObtainTimeout < 0 {
		return errors.New("cert_obtain_timeout cannot be negative")
	}
	if c.RequestTimeoutSec < 0 {
		return errors.New("request_timeout cannot be negative")
	}
	if c.ObtainTimeout() >= c.RequestTimeout() {
		return fmt.Errorf("cert_obtain_timeout (%s) must be less than request_timeout (%s)", c.ObtainTimeout(), c.RequestTimeout())
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

// HTTPTimeout returns the timeout for HTTP client operations
func (c *acmeProxyConfig) HTTPTimeout() time.Duration {
	return 90 * time.Second
}

// RequestTimeout returns the timeout for certificate request operations
func (c *acmeProxyConfig) RequestTimeout() time.Duration {
	if c.RequestTimeoutSec <= 0 {
		return 2 * time.Minute
	}
	return time.Duration(c.RequestTimeoutSec) * time.Second
}

// ObtainTimeout returns how long lego waits for the external CA to issue the
// certificate after finalization
func (c *acmeProxyConfig) ObtainTimeout() time.Duration {
	if c.CertObtainTimeout <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.CertObtainTimeout) * time.Second
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
