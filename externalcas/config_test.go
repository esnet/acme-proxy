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
			name: "negative cert_poll_timeout",
			config: acmeProxyConfig{
				CaURL:           "https://acme.example.com",
				Email:           "test@example.com",
				Kid:             "test-kid",
				HmacKey:         "test-hmac",
				CertPollTimeout: -1,
			},
			wantErr: true,
			errMsg:  "cert_poll_timeout cannot be negative",
		},
		{
			name: "negative cert_cache_min_validity",
			config: acmeProxyConfig{
				CaURL:                "https://acme.example.com",
				Email:                "test@example.com",
				Kid:                  "test-kid",
				HmacKey:              "test-hmac",
				CertCacheMinValidity: -1,
			},
			wantErr: true,
			errMsg:  "cert_cache_min_validity cannot be negative",
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

	requestTimeout := config.RequestTimeoutDuration()
	if requestTimeout != 120*time.Second {
		t.Errorf("RequestTimeoutDuration() = %v, want %v", requestTimeout, 120*time.Second)
	}

	certPollTimeout := config.CertPollTimeoutDuration()
	if certPollTimeout != 30*time.Second {
		t.Errorf("CertPollTimeoutDuration() = %v, want %v", certPollTimeout, 30*time.Second)
	}
}

func TestAcmeProxyConfig_CertPollTimeoutDuration(t *testing.T) {
	tests := []struct {
		name     string
		timeout  int
		expected time.Duration
	}{
		{
			name:     "default when zero",
			timeout:  0,
			expected: 30 * time.Second,
		},
		{
			name:     "custom 3 minutes",
			timeout:  180,
			expected: 3 * time.Minute,
		},
		{
			name:     "custom 5 minutes",
			timeout:  300,
			expected: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &acmeProxyConfig{CertPollTimeout: tt.timeout}
			got := cfg.CertPollTimeoutDuration()
			if got != tt.expected {
				t.Errorf("CertPollTimeoutDuration() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAcmeProxyConfig_RequestTimeoutDuration(t *testing.T) {
	tests := []struct {
		name     string
		timeout  int
		expected time.Duration
	}{
		{
			name:     "default when zero",
			timeout:  0,
			expected: 120 * time.Second,
		},
		{
			name:     "custom 5 minutes for slow CA",
			timeout:  300,
			expected: 5 * time.Minute,
		},
		{
			name:     "custom 10 minutes",
			timeout:  600,
			expected: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &acmeProxyConfig{RequestTimeout: tt.timeout}
			got := cfg.RequestTimeoutDuration()
			if got != tt.expected {
				t.Errorf("RequestTimeoutDuration() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAcmeProxyConfig_Validate_RequestTimeout(t *testing.T) {
	cfg := &acmeProxyConfig{CaURL: "https://acme.example.com", RequestTimeout: -1}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "request_timeout cannot be negative") {
		t.Errorf("Validate() with negative request_timeout: err = %v, want request_timeout error", err)
	}

	cfg = &acmeProxyConfig{CaURL: "https://acme.example.com", RequestTimeout: 420}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with request_timeout=420: unexpected error %v", err)
	}
}

func TestAcmeProxyConfig_CertCacheMinValidityDuration(t *testing.T) {
	tests := []struct {
		name     string
		days     int
		expected time.Duration
	}{
		{
			name:     "default when zero",
			days:     0,
			expected: 7 * 24 * time.Hour,
		},
		{
			name:     "custom 3 days",
			days:     3,
			expected: 3 * 24 * time.Hour,
		},
		{
			name:     "custom 30 days",
			days:     30,
			expected: 30 * 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &acmeProxyConfig{CertCacheMinValidity: tt.days}
			got := cfg.CertCacheMinValidityDuration()
			if got != tt.expected {
				t.Errorf("CertCacheMinValidityDuration() = %v, want %v", got, tt.expected)
			}
		})
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
		name              string
		config            acmeProxyConfig
		wantErr           bool
		errMsg            string
		wantUseEAB        bool
		wantChallengeType string
	}{
		{
			name: "neither EAB nor DNS01 configured - falls back to HTTP01",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
			},
			wantErr:           false,
			wantUseEAB:        false,
			wantChallengeType: "http-01",
		},
		{
			name: "partial EAB - only Kid set - error",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Kid:   "test-kid",
			},
			wantErr: true,
			errMsg:  "eab_kid and eab_hmac_key must be set together",
		},
		{
			name: "partial EAB - only HmacKey set - error",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				HmacKey: "test-hmac",
			},
			wantErr: true,
			errMsg:  "eab_kid and eab_hmac_key must be set together",
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
			wantErr:           false,
			wantUseEAB:        false,
			wantChallengeType: "dns-01",
		},
		{
			name: "partial DNS01 - only Provider set - falls back to HTTP01",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Lego:  legoConfig{Provider: "route53"},
			},
			wantErr:           false,
			wantUseEAB:        false,
			wantChallengeType: "http-01",
		},
		{
			name: "partial DNS01 - only Env_Vars set - falls back to HTTP01",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Lego:  legoConfig{Env_Vars: map[string]string{"AWS_REGION": "us-east-1"}},
			},
			wantErr:           false,
			wantUseEAB:        false,
			wantChallengeType: "http-01",
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
			wantErr:           false,
			wantUseEAB:        true,
			wantChallengeType: "dns-01",
		},
		{
			name: "EAB-only sets useEAB flag, falls back to HTTP01",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "test-kid",
				HmacKey: "test-hmac",
			},
			wantErr:           false,
			wantUseEAB:        true,
			wantChallengeType: "http-01",
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
			if tt.config.challengeType != tt.wantChallengeType {
				t.Errorf("challengeType = %q, want %q", tt.config.challengeType, tt.wantChallengeType)
			}
		})
	}
}

func TestParseConfig_DNS01AndBothModes(t *testing.T) {
	tests := []struct {
		name              string
		config            string
		wantUseEAB        bool
		wantChallengeType string
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
			wantUseEAB:        false,
			wantChallengeType: "dns-01",
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
			wantUseEAB:        true,
			wantChallengeType: "dns-01",
		},
		{
			name: "no DNS01 falls back to HTTP01",
			config: `{
				"ca_url": "https://acme.example.com"
			}`,
			wantUseEAB:        false,
			wantChallengeType: "http-01",
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
			if cfg.challengeType != tt.wantChallengeType {
				t.Errorf("challengeType = %q, want %q", cfg.challengeType, tt.wantChallengeType)
			}
		})
	}
}

func TestAcmeProxyConfig_Validate_ChallengeType(t *testing.T) {
	tests := []struct {
		name              string
		config            acmeProxyConfig
		wantErr           bool
		errMsg            string
		wantChallengeType string
	}{
		{
			name: "auto with fully configured dns01 resolves to dns-01",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "auto",
				Lego: legoConfig{
					Provider: "route53",
					Env_Vars: map[string]string{"AWS_REGION": "us-east-1"},
				},
			},
			wantErr:           false,
			wantChallengeType: "dns-01",
		},
		{
			name: "auto without dns01 resolves to http-01",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "auto",
			},
			wantErr:           false,
			wantChallengeType: "http-01",
		},
		{
			name: "empty challenge type resolves to http-01",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
			},
			wantErr:           false,
			wantChallengeType: "http-01",
		},
		{
			name: "explicit http-01 even when dns01 configured",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "http-01",
				Lego: legoConfig{
					Provider: "route53",
					Env_Vars: map[string]string{"AWS_REGION": "us-east-1"},
				},
			},
			wantErr:           false,
			wantChallengeType: "http-01",
		},
		{
			name: "explicit tls-alpn-01",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "tls-alpn-01",
			},
			wantErr:           false,
			wantChallengeType: "tls-alpn-01",
		},
		{
			name: "explicit dns-01 with provider and env_vars",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "dns-01",
				Lego: legoConfig{
					Provider: "route53",
					Env_Vars: map[string]string{"AWS_REGION": "us-east-1"},
				},
			},
			wantErr:           false,
			wantChallengeType: "dns-01",
		},
		{
			name: "explicit dns-01 without env_vars is OK",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "dns-01",
				Lego: legoConfig{
					Provider: "route53",
				},
			},
			wantErr:           false,
			wantChallengeType: "dns-01",
		},
		{
			name: "explicit dns-01 without provider errors",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "dns-01",
			},
			wantErr: true,
			errMsg:  "challenge_type dns-01 requires dns01_txt.provider",
		},
		{
			name: "invalid challenge type errors",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				ChallengeType: "bogus",
			},
			wantErr: true,
			errMsg:  "invalid challenge_type",
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
			if tt.config.challengeType != tt.wantChallengeType {
				t.Errorf("challengeType = %q, want %q", tt.config.challengeType, tt.wantChallengeType)
			}
		})
	}
}

func TestAcmeProxyConfig_Validate_EABPair(t *testing.T) {
	tests := []struct {
		name       string
		config     acmeProxyConfig
		wantErr    bool
		errMsg     string
		wantUseEAB bool
	}{
		{
			name: "both kid and hmac set enables EAB",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				Kid:     "kid",
				HmacKey: "hmac",
			},
			wantErr:    false,
			wantUseEAB: true,
		},
		{
			name: "neither set disables EAB",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
			},
			wantErr:    false,
			wantUseEAB: false,
		},
		{
			name: "kid only errors",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
				Kid:   "kid",
			},
			wantErr: true,
			errMsg:  "eab_kid and eab_hmac_key must be set together",
		},
		{
			name: "hmac only errors",
			config: acmeProxyConfig{
				CaURL:   "https://acme.example.com",
				HmacKey: "hmac",
			},
			wantErr: true,
			errMsg:  "eab_kid and eab_hmac_key must be set together",
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
		})
	}
}

func TestAcmeProxyConfig_Validate_Ports(t *testing.T) {
	tests := []struct {
		name    string
		config  acmeProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "zero ports are valid (defaults)",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
			},
			wantErr: false,
		},
		{
			name: "valid http01 port",
			config: acmeProxyConfig{
				CaURL:      "https://acme.example.com",
				HTTP01Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "negative http01 port errors",
			config: acmeProxyConfig{
				CaURL:      "https://acme.example.com",
				HTTP01Port: -1,
			},
			wantErr: true,
			errMsg:  "http01_port must be between 1 and 65535",
		},
		{
			name: "http01 port too large errors",
			config: acmeProxyConfig{
				CaURL:      "https://acme.example.com",
				HTTP01Port: 70000,
			},
			wantErr: true,
			errMsg:  "http01_port must be between 1 and 65535",
		},
		{
			name: "valid tlsalpn01 port",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				TLSALPN01Port: 8443,
			},
			wantErr: false,
		},
		{
			name: "negative tlsalpn01 port errors",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				TLSALPN01Port: -1,
			},
			wantErr: true,
			errMsg:  "tlsalpn01_port must be between 1 and 65535",
		},
		{
			name: "tlsalpn01 port too large errors",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				TLSALPN01Port: 70000,
			},
			wantErr: true,
			errMsg:  "tlsalpn01_port must be between 1 and 65535",
		},
		{
			name: "valid http01 bind ip",
			config: acmeProxyConfig{
				CaURL:      "https://acme.example.com",
				HTTP01Bind: "192.168.1.10",
				HTTP01Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "valid http01 bind ipv6",
			config: acmeProxyConfig{
				CaURL:      "https://acme.example.com",
				HTTP01Bind: "::1",
			},
			wantErr: false,
		},
		{
			name: "invalid http01 bind errors",
			config: acmeProxyConfig{
				CaURL:      "https://acme.example.com",
				HTTP01Bind: "not-an-ip",
			},
			wantErr: true,
			errMsg:  `http01_bind "not-an-ip" is not a valid IP address`,
		},
		{
			name: "valid tlsalpn01 bind ip",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				TLSALPN01Bind: "10.0.0.5",
				TLSALPN01Port: 8443,
			},
			wantErr: false,
		},
		{
			name: "invalid tlsalpn01 bind errors",
			config: acmeProxyConfig{
				CaURL:         "https://acme.example.com",
				TLSALPN01Bind: "acme.example.com",
			},
			wantErr: true,
			errMsg:  `tlsalpn01_bind "acme.example.com" is not a valid IP address`,
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

func TestAcmeProxyConfig_Validate_MaxConcurrentRequests(t *testing.T) {
	tests := []struct {
		name    string
		config  acmeProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "zero is valid (defaults to 1)",
			config: acmeProxyConfig{
				CaURL: "https://acme.example.com",
			},
			wantErr: false,
		},
		{
			name: "positive value is valid",
			config: acmeProxyConfig{
				CaURL:                 "https://acme.example.com",
				MaxConcurrentRequests: 5,
			},
			wantErr: false,
		},
		{
			name: "negative value errors",
			config: acmeProxyConfig{
				CaURL:                 "https://acme.example.com",
				MaxConcurrentRequests: -1,
			},
			wantErr: true,
			errMsg:  "max_concurrent_requests cannot be negative",
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

func TestAcmeProxyConfig_Defaults(t *testing.T) {
	cfg := &acmeProxyConfig{}
	if got := cfg.MaxConcurrentRequestsOrDefault(); got != 1 {
		t.Errorf("MaxConcurrentRequestsOrDefault() = %d, want 1", got)
	}
	if got := cfg.HTTP01PortOrDefault(); got != 80 {
		t.Errorf("HTTP01PortOrDefault() = %d, want 80", got)
	}
	if got := cfg.TLSALPN01PortOrDefault(); got != 443 {
		t.Errorf("TLSALPN01PortOrDefault() = %d, want 443", got)
	}
	if got := cfg.HTTP01BindAddr(); got != ":80" {
		t.Errorf("HTTP01BindAddr() = %q, want %q", got, ":80")
	}
	if got := cfg.TLSALPN01BindAddr(); got != ":443" {
		t.Errorf("TLSALPN01BindAddr() = %q, want %q", got, ":443")
	}

	cfg = &acmeProxyConfig{MaxConcurrentRequests: 7, HTTP01Port: 8080, TLSALPN01Port: 8443}
	if got := cfg.MaxConcurrentRequestsOrDefault(); got != 7 {
		t.Errorf("MaxConcurrentRequestsOrDefault() = %d, want 7", got)
	}
	if got := cfg.HTTP01PortOrDefault(); got != 8080 {
		t.Errorf("HTTP01PortOrDefault() = %d, want 8080", got)
	}
	if got := cfg.TLSALPN01PortOrDefault(); got != 8443 {
		t.Errorf("TLSALPN01PortOrDefault() = %d, want 8443", got)
	}

	// Bind addresses combine the optional bind IP with the effective port.
	cfg = &acmeProxyConfig{HTTP01Bind: "203.0.113.10", HTTP01Port: 8080, TLSALPN01Bind: "10.0.0.5"}
	if got := cfg.HTTP01BindAddr(); got != "203.0.113.10:8080" {
		t.Errorf("HTTP01BindAddr() = %q, want %q", got, "203.0.113.10:8080")
	}
	if got := cfg.TLSALPN01BindAddr(); got != "10.0.0.5:443" {
		t.Errorf("TLSALPN01BindAddr() = %q, want %q", got, "10.0.0.5:443")
	}
}
