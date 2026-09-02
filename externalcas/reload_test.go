package externalcas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	stepconfig "github.com/smallstep/certificates/authority/config"
)

func setupSettingsEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "ca.json")
	content := `{ # keep me
  "authority": {"type": "externalcas", "config": {"ca_url": "https://old.example", "challenge_type": "http-01"}},
  "dashboard": {"port": 8443, "data_source": "` + filepath.Join(dir, "ds") + `"},
  "acl": {"file": "` + filepath.Join(dir, "acl.txt") + `"}
}`
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write ca.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "acl.txt"), []byte("192.0.2.0/24\n"), 0o644); err != nil {
		t.Fatalf("write acl: %v", err)
	}

	stepconfig.LoadedFilepath = cfgFile
	t.Cleanup(func() { stepconfig.LoadedFilepath = "" })

	old := &ExternalCAS{sem: newDynamicSem(1)}
	oldCfg, err := parseConfig([]byte(`{"ca_url":"https://old.example"}`))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	old.cfg.Store(oldCfg)
	currentCAS.Store(old)
	t.Cleanup(func() { currentCAS.Store(nil) })
	return cfgFile
}

func TestSaveSettings_MergeValidateApply(t *testing.T) {
	cfgFile := setupSettingsEnv(t)

	applied, restart, err := saveSettings([]byte(`{
		"authority": {"config": {"ca_url": "https://new.example", "request_timeout": 200, "http01_port": 81}},
		"dashboard": {"password": "newpass", "tls_max_age_days": 20}
	}`))
	if err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
	joined := strings.Join(applied, ",") + "|" + strings.Join(restart, ",")
	if !strings.Contains(joined, "authority.config.ca_url") ||
		!strings.Contains(joined, "dashboard.password") ||
		!strings.Contains(joined, "authority.config.http01_port") {
		t.Errorf("applied/restart classification wrong: applied=%v restart=%v", applied, restart)
	}

	// hot-applied in memory
	c := currentCAS.Load().conf()
	if c.CaURL != "https://new.example" || c.RequestTimeout != 200 {
		t.Errorf("hot-apply failed: ca_url=%s request_timeout=%d", c.CaURL, c.RequestTimeout)
	}
	if currentDashPass() != "newpass" {
		t.Error("dashboard password not hot-applied")
	}
	if getDashConfig().TLSMaxAgeDays != 20 {
		t.Error("tls_max_age_days not hot-applied")
	}

	// file rewritten as valid JSON (after the one-line header comment)
	raw, _ := os.ReadFile(cfgFile)
	body := raw[strings.Index(string(raw), "{"):]
	if !json.Valid(body) {
		t.Fatalf("rewritten ca.json body is not valid JSON: %s", body)
	}
	bak, _ := os.ReadFile(cfgFile + ".bak-settings")
	if !strings.Contains(string(bak), "keep me") {
		t.Error("backup should preserve the original commented file")
	}

	// unknown key rejected, file untouched
	_, _, err = saveSettings([]byte(`{"authority": {"config": {"nope": 1}}}`))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("unknown key should be rejected, got err=%v", err)
	}
	raw2, _ := os.ReadFile(cfgFile)
	if !strings.Contains(string(raw2), "https://new.example") {
		t.Error("rejected save must not modify the file")
	}

	// invalid value rejected
	_, _, err = saveSettings([]byte(`{"authority": {"config": {"request_timeout": -5}}}`))
	if err == nil {
		t.Error("negative timeout should be rejected")
	}
}
