package externalcas

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Configuration bits for a DNS provider as per Lego docs
type LegoConfig struct {
	Provider       string            `json:"provider"`
	DnsServersList []string          `json:"dns_servers"`
	Env_Vars       map[string]string `json:"env_vars"`
}

type Metrics struct {
	Enabled    bool   `json:"enabled,omitempty"`
	Port       int    `json:"port,omitempty"`
	DataSource string `json:"datasource,omitempty"`
}

// AcmeProxyConfig contains the configuration for connecting to an external ACME CA
type AcmeProxyConfig struct {
	// ACME directory url of External CA (required)
	CaURL string `json:"ca_url"`

	// External Account Binding
	Email   string `json:"account_email,omitempty"`
	Kid     string `json:"eab_kid"`
	HmacKey string `json:"eab_hmac_key"`

	// Certificate lifetime in days (optional)
	CertLifetime int `json:"certlifetime,omitempty"`

	// Lego provider connection variables for DNS01
	Lego LegoConfig `json:"dns01"`

	// Prometheus metrics endpoint (optional)
	Metrics Metrics `json:"metrics"`

	// derived during Validate(); not marshaled
	useEAB   bool
	useDNS01 bool
}

// Validate checks if the AcmeProxyConfig contains required fields and valid values
func (c *AcmeProxyConfig) Validate() error {
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
		return errors.New("Missing eab or dns01 config. Must configure one.\nRefer docs https://software.es.net/acme-proxy/install/#configuration")
	}
	if c.CertLifetime < 0 {
		return errors.New("certlifetime cannot be negative")
	}
	if c.Metrics.Enabled && c.Metrics.DataSource == "" {
		return errors.New("metrics.datasource is required when metrics is enabled")
	}
	return nil
}

// HTTPTimeout returns the timeout for HTTP client operations
func (c *AcmeProxyConfig) HTTPTimeout() time.Duration {
	return 90 * time.Second
}

// RequestTimeout returns the timeout for certificate request operations
func (c *AcmeProxyConfig) RequestTimeout() time.Duration {
	return 2 * time.Minute
}

func parseConfig(raw json.RawMessage) (*AcmeProxyConfig, error) {
	var cfg AcmeProxyConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
