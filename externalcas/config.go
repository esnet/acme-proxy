package externalcas

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

	// TimeoutSeconds is the total upstream issuance budget in seconds (default 300).
	// Directory discovery, account registration, validation, finalization, and certificate retrieval share it.
	// For DNS-01 TXT challenges, consider a higher timeout to give Lego time to create
	// the TXT records, wait for propagation, and clean them up. Timing varies by DNS provider.
	TimeoutSeconds int64 `json:"timeout,omitzero"`

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
	if c.TimeoutSeconds < 0 {
		return errors.New("timeout cannot be negative")
	}
	if c.TimeoutSeconds > math.MaxInt64/int64(time.Second) {
		return errors.New("timeout is too large")
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

func (c *acmeProxyConfig) timeout() time.Duration {
	if c.TimeoutSeconds == 0 {
		return 300 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// parseConfig is a helper function which reads ca.json file as rawjson and validates
// acme-proxy specific configuration bits under the `authority` section of the ca.json file
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
