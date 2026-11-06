package externalcas

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-acme/lego/v5/acme"
)

func TestACMEAccountStore_ReusesPersistedAccount(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "account.key")
	cfg := &acmeProxyConfig{
		CaURL:          "https://acme.example.com",
		Email:          "account@example.com",
		Kid:            "test-kid",
		HmacKey:        "test-hmac",
		AccountKeyPath: keyPath,
		useEAB:         true,
	}

	store, err := newACMEAccountStore(keyPath, cfg)
	if err != nil {
		t.Fatalf("newACMEAccountStore() error = %v", err)
	}
	firstUser, err := store.newUser(cfg)
	if err != nil {
		t.Fatalf("newUser() error = %v", err)
	}
	firstKey, ok := firstUser.GetPrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("account key is not ECDSA")
	}

	registerCalls := 0
	register := func(user *User) error {
		registerCalls++
		user.Registration = &acme.ExtendedAccount{Location: "https://acme.example.com/acct/123"}
		return nil
	}
	if err := store.ensureRegistration(cfg, firstUser, register); err != nil {
		t.Fatalf("ensureRegistration() error = %v", err)
	}
	if err := store.ensureRegistration(cfg, firstUser, register); err != nil {
		t.Fatalf("second ensureRegistration() error = %v", err)
	}
	if registerCalls != 1 {
		t.Fatalf("registration calls = %d, want 1", registerCalls)
	}

	reopened, err := newACMEAccountStore(keyPath, cfg)
	if err != nil {
		t.Fatalf("reopening account store: %v", err)
	}
	reopenedUser, err := reopened.newUser(cfg)
	if err != nil {
		t.Fatalf("newUser() after reopen: %v", err)
	}
	reopenedKey, ok := reopenedUser.GetPrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("reloaded account key is not ECDSA")
	}
	if firstKey.D.Cmp(reopenedKey.D) != 0 {
		t.Fatal("account key changed after reopening the store")
	}
	if reopenedUser.GetRegistration() == nil || reopenedUser.GetRegistration().Location != firstUser.GetRegistration().Location {
		t.Fatal("account registration URL was not reused after reopening the store")
	}

	if err := reopened.ensureRegistration(cfg, reopenedUser, func(*User) error {
		t.Fatal("registration callback ran for a persisted account")
		return nil
	}); err != nil {
		t.Fatalf("ensureRegistration() for persisted account: %v", err)
	}

	if runtime.GOOS != "windows" {
		for _, path := range []string{keyPath, keyPath + ".account.json"} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat persisted account file: %v", err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("permissions for persisted account file = %04o, want 0600", got)
			}
		}
	}
}

func TestACMEAccountStore_RejectsRegistrationForDifferentConfig(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "account.key")
	cfg := &acmeProxyConfig{
		CaURL:          "https://acme.example.com",
		AccountKeyPath: keyPath,
	}
	store, err := newACMEAccountStore(keyPath, cfg)
	if err != nil {
		t.Fatalf("newACMEAccountStore() error = %v", err)
	}
	user, err := store.newUser(cfg)
	if err != nil {
		t.Fatalf("newUser() error = %v", err)
	}
	if err := store.ensureRegistration(cfg, user, func(user *User) error {
		user.Registration = &acme.ExtendedAccount{Location: "https://acme.example.com/acct/123"}
		return nil
	}); err != nil {
		t.Fatalf("ensureRegistration() error = %v", err)
	}

	changedConfig := *cfg
	changedConfig.CaURL = "https://other.example.com"
	if _, err := newACMEAccountStore(keyPath, &changedConfig); err == nil {
		t.Fatal("expected account store to reject mismatched CA configuration")
	}
}

func TestACMEAccountStore_DoesNotRegenerateMissingRegisteredKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "account.key")
	cfg := &acmeProxyConfig{
		CaURL:          "https://acme.example.com",
		AccountKeyPath: keyPath,
	}
	store, err := newACMEAccountStore(keyPath, cfg)
	if err != nil {
		t.Fatalf("newACMEAccountStore() error = %v", err)
	}
	user, err := store.newUser(cfg)
	if err != nil {
		t.Fatalf("newUser() error = %v", err)
	}
	if err := store.ensureRegistration(cfg, user, func(user *User) error {
		user.Registration = &acme.ExtendedAccount{Location: "https://acme.example.com/acct/123"}
		return nil
	}); err != nil {
		t.Fatalf("ensureRegistration() error = %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove account key: %v", err)
	}
	if _, err := newACMEAccountStore(keyPath, cfg); err == nil {
		t.Fatal("expected missing key with persisted registration to fail")
	}
}
