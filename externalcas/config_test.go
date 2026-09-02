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
			name: "negative cert_obtain_timeout",
			config: acmeProxyConfig{
				CaURL:             "https://acme.example.com",
				Kid:               "test-kid",
				HmacKey:           "test-hmac",
				CertObtainTimeout: -1,
			},
			wantErr: true,
			errMsg:  "cert_obtain_timeout cannot be negative",
		},
		{
			name: "cert_obtain_timeout at or above request timeout",
			config: acmeProxyConfig{
				CaURL:             "https://acme.example.com",
				Kid:               "test-kid",
				HmacKey:           "test-hmac",
				CertObtainTimeout: 120,
			},
			wantErr: true,
			errMsg:  "cert_obtain_timeout (2m0s) must be less than request_timeout (2m0s)",
		},
		{
			name: "cert_obtain_timeout below request timeout is valid",
			config: acmeProxyConfig{
				CaURL:             "https://acme.example.com",
				Kid:               "test-kid",
				HmacKey:           "test-hmac",
				CertObtainTimeout: 90,
			},
			wantErr: false,
		},
		{
			name: "negative request_timeout",
			config: acmeProxyConfig{
				CaURL:             "https://acme.example.com",
				Kid:               "test-kid",
				HmacKey:           "test-hmac",
				RequestTimeoutSec: -1,
			},
			wantErr: true,
			errMsg:  "request_timeout cannot be negative",
		},
		{
			name: "cert_obtain_timeout above default request timeout is valid when request_timeout is raised",
			config: acmeProxyConfig{
				CaURL:             "https://acme.example.com",
				Kid:               "test-kid",
				HmacKey:           "test-hmac",
				CertObtainTimeout: 300,
				RequestTimeoutSec: 330,
			},
			wantErr: false,
		},
		{
			name: "cert_obtain_timeout at a raised request_timeout is rejected",
			config: acmeProxyConfig{
				CaURL:             "https://acme.example.com",
				Kid:               "test-kid",
				HmacKey:           "test-hmac",
				CertObtainTimeout: 330,
				RequestTimeoutSec: 330,
			},
			wantErr: true,
			errMsg:  "cert_obtain_timeout (5m30s) must be less than request_timeout (5m30s)",
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
			errMsg:  "invalid metrics port or dataSource.\nRefer docs https://software.es.net/acme-proxy/configuration",
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
			errMsg:  "invalid metrics port or dataSource.\nRefer docs https://software.es.net/acme-proxy/configuration",
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
		{
			name: "metrics not configured leaves metricsEnabled false",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
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

func TestAcmeProxyConfig_Validate_MetricsEnabled(t *testing.T) {
	t.Run("Metrics.Enabled set when port and datasource both present", func(t *testing.T) {
		cfg := acmeProxyConfig{
			CaURL:   "https://acme.example.com",
			Kid:     "test-kid",
			HmacKey: "test-hmac",
			Metrics: metrics{Port: 9234, DataSource: "/tmp/metrics.db"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
		if !cfg.Metrics.Enabled {
			t.Error("Metrics.Enabled = false, want true when port and datasource are both set")
		}
	})

	t.Run("Metrics.Enabled false when metrics not configured", func(t *testing.T) {
		cfg := acmeProxyConfig{
			CaURL:   "https://acme.example.com",
			Kid:     "test-kid",
			HmacKey: "test-hmac",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
		if cfg.Metrics.Enabled {
			t.Error("Metrics.Enabled = true, want false when metrics are not configured")
		}
	})

	t.Run("Metrics.Enabled false when only port set (invalid)", func(t *testing.T) {
		cfg := acmeProxyConfig{
			CaURL:   "https://acme.example.com",
			Kid:     "test-kid",
			HmacKey: "test-hmac",
			Metrics: metrics{Port: 9234},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("Validate() expected error for partial metrics config, got nil")
		}
		if cfg.Metrics.Enabled {
			t.Error("Metrics.Enabled must remain false when Validate() returns an error")
		}
	})
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

	obtainTimeout := config.ObtainTimeout()
	if obtainTimeout != 30*time.Second {
		t.Errorf("ObtainTimeout() default = %v, want %v", obtainTimeout, 30*time.Second)
	}

	config.CertObtainTimeout = 90
	obtainTimeout = config.ObtainTimeout()
	if obtainTimeout != 90*time.Second {
		t.Errorf("ObtainTimeout() with cert_obtain_timeout=90 = %v, want %v", obtainTimeout, 90*time.Second)
	}

	config.RequestTimeoutSec = 330
	requestTimeout = config.RequestTimeout()
	if requestTimeout != 330*time.Second {
		t.Errorf("RequestTimeout() with request_timeout=330 = %v, want %v", requestTimeout, 330*time.Second)
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

func TestParseConfig_DNS01TxtFieldValues(t *testing.T) {
	raw := `{
		"ca_url": "https://acme.example.com",
		"dns01_txt": {
			"provider": "route53",
			"dns_servers": ["8.8.8.8", "1.1.1.1"],
			"env_vars": {"AWS_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "AKIA123"}
		}
	}`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() unexpected error: %v", err)
	}
	if cfg.Lego.Provider != "route53" {
		t.Errorf("Lego.Provider = %q, want %q", cfg.Lego.Provider, "route53")
	}
	if len(cfg.Lego.DnsServersList) != 2 {
		t.Errorf("Lego.DnsServersList len = %d, want 2", len(cfg.Lego.DnsServersList))
	} else {
		if cfg.Lego.DnsServersList[0] != "8.8.8.8" {
			t.Errorf("DnsServersList[0] = %q, want %q", cfg.Lego.DnsServersList[0], "8.8.8.8")
		}
		if cfg.Lego.DnsServersList[1] != "1.1.1.1" {
			t.Errorf("DnsServersList[1] = %q, want %q", cfg.Lego.DnsServersList[1], "1.1.1.1")
		}
	}
	if cfg.Lego.Env_Vars["AWS_REGION"] != "us-east-1" {
		t.Errorf("Lego.Env_Vars[AWS_REGION] = %q, want %q", cfg.Lego.Env_Vars["AWS_REGION"], "us-east-1")
	}
	if cfg.Lego.Env_Vars["AWS_ACCESS_KEY_ID"] != "AKIA123" {
		t.Errorf("Lego.Env_Vars[AWS_ACCESS_KEY_ID] = %q, want %q", cfg.Lego.Env_Vars["AWS_ACCESS_KEY_ID"], "AKIA123")
	}
}

func TestParseConfig_MetricsFieldValues(t *testing.T) {
	// Verifies that the "metrics" JSON block unmarshals correctly, including
	// the "dataSource" casing used in ca.json matching the struct tag.
	raw := `{
		"ca_url": "https://acme.example.com",
		"eab_kid": "kid",
		"eab_hmac_key": "hmac",
		"metrics": {
			"port": 9234,
			"dataSource": "/opt/acme-proxy/db/metrics"
		}
	}`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() unexpected error: %v", err)
	}
	if cfg.Metrics.Port != 9234 {
		t.Errorf("Metrics.Port = %d, want 9234", cfg.Metrics.Port)
	}
	if cfg.Metrics.DataSource != "/opt/acme-proxy/db/metrics" {
		t.Errorf("Metrics.DataSource = %q, want %q", cfg.Metrics.DataSource, "/opt/acme-proxy/db/metrics")
	}
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = false, want true after parseConfig with port and dataSource set")
	}
}

func TestAcmeProxyConfig_Validate_ModeFlags(t *testing.T) {
	tests := []struct {
		name         string
		config       acmeProxyConfig
		wantErr      bool
		errMsg       string
		wantUseEAB   bool
		wantUseDNS01 bool
	}{
		{
			name: "neither EAB nor DNS01 configured",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
			},
			wantErr: true,
			errMsg:  "missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "partial EAB - only Kid set",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Kid:   "test-kid",
			},
			wantErr: true,
			errMsg:  "missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "partial EAB - only HmacKey set",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				HmacKey: "test-hmac",
			},
			wantErr: true,
			errMsg:  "missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "DNS01-only valid",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Lego: legoConfig{
					Provider: "route53",
					Env_Vars: map[string]string{"AWS_REGION": "us-east-1"},
				},
			},
			wantErr:      false,
			wantUseEAB:   false,
			wantUseDNS01: true,
		},
		{
			name: "partial DNS01 - only Provider set",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Lego:  legoConfig{Provider: "route53"},
			},
			wantErr: true,
			errMsg:  "missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "partial DNS01 - only Env_Vars set",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Lego:  legoConfig{Env_Vars: map[string]string{"AWS_REGION": "us-east-1"}},
			},
			wantErr: true,
			errMsg:  "missing eab or dns01 config. acme-proxy requires atleast one.\nRefer docs https://software.es.net/acme-proxy/configuration",
		},
		{
			name: "both EAB and DNS01 configured",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
				Lego: legoConfig{
					Provider: "route53",
					Env_Vars: map[string]string{"AWS_REGION": "us-east-1"},
				},
			},
			wantErr:      false,
			wantUseEAB:   true,
			wantUseDNS01: true,
		},
		{
			name: "EAB-only sets useEAB flag",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
			},
			wantErr:      false,
			wantUseEAB:   true,
			wantUseDNS01: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %q, want error containing %q", err.Error(), tt.errMsg)
				}
				return
			}
			if tt.config.useEAB != tt.wantUseEAB {
				t.Errorf("useEAB = %v, want %v", tt.config.useEAB, tt.wantUseEAB)
			}
			if tt.config.useDNS01 != tt.wantUseDNS01 {
				t.Errorf("useDNS01 = %v, want %v", tt.config.useDNS01, tt.wantUseDNS01)
			}
		})
	}
}

func TestParseConfig_DNS01AndBothModes(t *testing.T) {
	tests := []struct {
		name         string
		config       string
		wantUseEAB   bool
		wantUseDNS01 bool
	}{
		{
			name: "DNS01-only valid JSON",
			config: `{
				"ca_url": "https://acme.example.com",
				"dns01_txt": {
					"provider": "route53",
					"env_vars": {"AWS_REGION": "us-east-1"}
				}
			}`,
			wantUseEAB:   false,
			wantUseDNS01: true,
		},
		{
			name: "both EAB and DNS01 in JSON",
			config: `{
				"ca_url": "https://acme.example.com",
				"eab_kid": "test-kid",
				"eab_hmac_key": "test-hmac",
				"dns01_txt": {
					"provider": "route53",
					"env_vars": {"AWS_REGION": "us-east-1"}
				}
			}`,
			wantUseEAB:   true,
			wantUseDNS01: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig([]byte(tt.config))
			if err != nil {
				t.Fatalf("parseConfig() unexpected error: %v", err)
			}
			if cfg.useEAB != tt.wantUseEAB {
				t.Errorf("useEAB = %v, want %v", cfg.useEAB, tt.wantUseEAB)
			}
			if cfg.useDNS01 != tt.wantUseDNS01 {
				t.Errorf("useDNS01 = %v, want %v", cfg.useDNS01, tt.wantUseDNS01)
			}
		})
	}
}
