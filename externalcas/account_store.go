package externalcas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-acme/lego/v5/acme"
)

type acmeAccountStore struct {
	keyPath          string
	registrationPath string
	caURL            string
	email            string
	eabKid           string
	key              *ecdsa.PrivateKey
	account          *acme.ExtendedAccount
	mu               sync.Mutex
}

type persistedAccountRegistration struct {
	Version    int    `json:"version"`
	CaURL      string `json:"ca_url"`
	Email      string `json:"email"`
	EABKid     string `json:"eab_kid,omitempty"`
	KeyID      string `json:"key_id"`
	AccountURL string `json:"account_url"`
}

func newACMEAccountStore(path string, cfg *acmeProxyConfig) (*acmeAccountStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("account_key_path cannot be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create ACME account key directory: %w", err)
	}

	store := &acmeAccountStore{
		keyPath:          path,
		registrationPath: path + ".account.json",
		caURL:            cfg.CaURL,
		email:            cfg.Email,
	}
	if cfg.useEAB {
		store.eabKid = cfg.Kid
	}

	registration, registrationExists, err := readAccountRegistration(store.registrationPath)
	if err != nil {
		return nil, err
	}

	key, keyExists, err := readAccountKey(path)
	if err != nil {
		return nil, err
	}
	if !keyExists {
		if registrationExists {
			return nil, errors.New("ACME account registration state exists but its private key is missing")
		}
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ACME account key: %w", err)
		}
		if err := writeAccountKey(path, key); err != nil {
			return nil, err
		}
	}
	store.key = key

	if registrationExists {
		if registration.Version != 1 ||
			registration.CaURL != store.caURL ||
			registration.Email != store.email ||
			registration.EABKid != store.eabKid {
			return nil, errors.New("persisted ACME account registration does not match the current CA configuration")
		}
		if registration.KeyID != accountKeyID(key) {
			return nil, errors.New("persisted ACME account registration does not match the private key")
		}
		if registration.AccountURL == "" {
			return nil, errors.New("persisted ACME account registration has no account URL")
		}
		store.account = &acme.ExtendedAccount{Location: registration.AccountURL}
	}

	return store, nil
}

func readAccountRegistration(path string) (*persistedAccountRegistration, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to read persisted ACME account registration: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("persisted ACME account registration is not a regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, false, fmt.Errorf("failed to secure persisted ACME account registration: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read persisted ACME account registration: %w", err)
	}

	var registration persistedAccountRegistration
	if err := json.Unmarshal(data, &registration); err != nil {
		return nil, false, fmt.Errorf("failed to parse persisted ACME account registration: %w", err)
	}
	return &registration, true, nil
}

func readAccountKey(path string) (*ecdsa.PrivateKey, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to read persisted ACME account key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("persisted ACME account key is not a regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, false, fmt.Errorf("failed to secure persisted ACME account key: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read persisted ACME account key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, false, errors.New("persisted ACME account key is not valid PEM")
	}

	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, false, errors.New("failed to parse persisted ACME account key")
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, false, errors.New("persisted ACME account key is not ECDSA")
		}
	case "EC PRIVATE KEY":
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, false, errors.New("failed to parse persisted ACME account key")
		}
	default:
		return nil, false, errors.New("persisted ACME account key has an unsupported PEM type")
	}
	if key.Curve != elliptic.P256() {
		return nil, false, errors.New("persisted ACME account key must use the P-256 curve")
	}
	return key, true, nil
}

func writeAccountKey(path string, key *ecdsa.PrivateKey) error {
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to encode ACME account key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})
	if err := writePrivateFile(path, pemData); err != nil {
		return fmt.Errorf("failed to persist ACME account key: %w", err)
	}
	return nil
}

func writeAccountRegistration(path string, registration persistedAccountRegistration) error {
	data, err := json.Marshal(registration)
	if err != nil {
		return fmt.Errorf("failed to encode ACME account registration: %w", err)
	}
	if err := writePrivateFile(path, data); err != nil {
		return fmt.Errorf("failed to persist ACME account registration: %w", err)
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".acme-account-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func accountKeyID(key *ecdsa.PrivateKey) string {
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func (s *acmeAccountStore) newUser(cfg *acmeProxyConfig) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateConfig(cfg); err != nil {
		return nil, err
	}
	return &User{
		Email:        s.email,
		Registration: s.account,
		key:          s.key,
	}, nil
}

func (s *acmeAccountStore) ensureRegistration(cfg *acmeProxyConfig, user *User, register func(*User) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validateConfig(cfg); err != nil {
		return err
	}
	if s.account != nil {
		user.Registration = s.account
		return nil
	}
	if err := register(user); err != nil {
		return err
	}
	if user.Registration == nil || user.Registration.Location == "" {
		return errors.New("upstream ACME registration returned no account URL")
	}

	registration := persistedAccountRegistration{
		Version:    1,
		CaURL:      s.caURL,
		Email:      s.email,
		EABKid:     s.eabKid,
		KeyID:      accountKeyID(s.key),
		AccountURL: user.Registration.Location,
	}
	if registration.KeyID == "" {
		return errors.New("failed to identify persisted ACME account key")
	}
	if err := writeAccountRegistration(s.registrationPath, registration); err != nil {
		return err
	}
	s.account = user.Registration
	return nil
}

func (s *acmeAccountStore) validateConfig(cfg *acmeProxyConfig) error {
	eabKid := ""
	if cfg.useEAB {
		eabKid = cfg.Kid
	}
	if cfg.CaURL != s.caURL || cfg.Email != s.email || eabKid != s.eabKid {
		return errors.New("ACME account store configuration does not match the current CA configuration")
	}
	return nil
}
