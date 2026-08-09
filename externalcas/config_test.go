package externalcas

import (
	"strings"
	"testing"
	"time"
)

func TestAcmeProxyConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  acmeProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: acmeProxyConfig{
				CaURL:        "https://acme.example.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: 30,
			},
			wantErr: false,
		},
		{
			name: "missing ca_url",
			config: acmeProxyConfig{
				Email:   "test@example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
			},
			wantErr: true,
			errMsg:  "ca_url is required",
		},
		{
			name: "negative certlifetime",
			config: acmeProxyConfig{
				CaURL:        "https://acme.example.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: -1,
			},
			wantErr: true,
			errMsg:  "certlifetime cannot be negative",
		},
		{
			name: "zero certlifetime is valid",
			config: acmeProxyConfig{
				CaURL:        "https://acme.example.com",
				Email:        "test@example.com",
				Kid:          "test-kid",
				HmacKey:      "test-hmac",
				CertLifetime: 0,
			},
			wantErr: false,
		},
		{
			name: "metrics enabled without valid datasource",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
				Metrics: metrics{Port: 9123, DataSource: ""},
			},
			wantErr: true,
			errMsg:  "Invalid metrics port or datasource.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "metrics enabled without valid port",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
				Metrics: metrics{DataSource: "/tmp/test.db"},
			},
			wantErr: true,
			errMsg:  "Invalid metrics port or datasource.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "metrics enabled with valid port and datasource",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
				Metrics: metrics{Port: 9200, DataSource: "/tmp/test.db"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestAcmeProxyConfig_Timeouts(t *testing.T) {
	config := acmeProxyConfig{}

	httpTimeout := config.HTTPTimeout()
	if httpTimeout != 90*time.Second {
		t.Errorf("HTTPTimeout() = %v, want %v", httpTimeout, 90*time.Second)
	}

	requestTimeout := config.RequestTimeout()
	if requestTimeout != 2*time.Minute {
		t.Errorf("RequestTimeout() = %v, want %v", requestTimeout, 2*time.Minute)
	}
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: `{
				"ca_url": "https://acme.example.com",
				"account_email": "test@example.com",
				"eab_kid": "test-kid",
				"eab_hmac_key": "test-hmac"
			}`,
			wantErr: false,
		},
		{
			name:    "invalid json",
			config:  `{invalid json`,
			wantErr: true,
			errMsg:  "failed to unmarshal config",
		},
		{
			name: "missing required field",
			config: `{
				"account_email": "test@example.com"
			}`,
			wantErr: true,
			errMsg:  "invalid config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig([]byte(tt.config))
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("parseConfig() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
			} else {
				if cfg == nil {
					t.Error("parseConfig() returned nil config")
				}
			}
		})
	}
}
