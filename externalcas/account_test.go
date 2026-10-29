package externalcas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/smallstep/certificates/cas/apiv1"
)

// fakeACME serves just enough of RFC 8555 (directory, nonce, newAccount) to
// exercise account lookup and registration without a real CA.
type fakeACME struct {
	accountExists   bool
	lookupProblem   string // when set, lookups fail with this problem type
	registerProblem string // when set, registrations fail with this problem type
	lookups         int
	registrations   int
}

func newFakeACME(t *testing.T, f *fakeACME) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	// lego only speaks HTTPS and newLegoClient uses the default transport, so trust
	// the test server's certificate there. Safe because this package's tests are serial.
	defaultTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = defaultTransport })

	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, acme.Directory{
			NewNonceURL:   srv.URL + "/nonce",
			NewAccountURL: srv.URL + "/account",
			NewOrderURL:   srv.URL + "/order",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce")
		var jws struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
			t.Fatalf("decoding JWS: %v", err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			t.Fatalf("decoding JWS payload: %v", err)
		}
		var req acme.Account
		if err := json.Unmarshal(payload, &req); err != nil {
			t.Fatalf("decoding account request: %v", err)
		}

		if req.OnlyReturnExisting {
			f.lookups++
			switch {
			case f.lookupProblem != "":
				writeJSON(t, w, http.StatusForbidden, acme.ProblemDetails{Type: f.lookupProblem})
				return
			case !f.accountExists:
				writeJSON(t, w, http.StatusBadRequest, acme.ProblemDetails{Type: acme.AccountDoesNotExistErrorType})
				return
			}
		} else {
			f.registrations++
			if f.registerProblem != "" {
				writeJSON(t, w, http.StatusForbidden, acme.ProblemDetails{Type: f.registerProblem})
				return
			}
			f.accountExists = true
		}
		w.Header().Set("Location", srv.URL+"/acct/1")
		writeJSON(t, w, http.StatusOK, acme.Account{Status: acme.StatusValid})
	})
	return srv
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("writing response: %v", err)
	}
}

// newTestCAS builds an ExternalCAS pointed at the fake CA, with EAB configured.
func newTestCAS(t *testing.T, srv *httptest.Server) *ExternalCAS {
	t.Helper()
	cas, err := New(context.Background(), apiv1.Options{Config: mustMarshalConfig(t, &acmeProxyConfig{
		CaURL:   srv.URL + "/directory",
		Kid:     "test-kid",
		HmacKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), // HS256 needs a 256-bit key
	})})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return cas
}

func TestEnsureAccount_RegistersOnceWhenAccountMissing(t *testing.T) {
	f := &fakeACME{}
	cas := newTestCAS(t, newFakeACME(t, f))

	for range 3 {
		if err := cas.ensureAccount(cas.cfg); err != nil {
			t.Fatalf("ensureAccount() error: %v", err)
		}
	}

	if f.lookups != 1 || f.registrations != 1 {
		t.Errorf("lookups=%d registrations=%d, want 1 and 1", f.lookups, f.registrations)
	}
	if got := cas.account.Registration.Location; got == "" {
		t.Error("account registration has no location")
	}
}

func TestEnsureAccount_ReusesExistingAccount(t *testing.T) {
	f := &fakeACME{accountExists: true}
	cas := newTestCAS(t, newFakeACME(t, f))

	if err := cas.ensureAccount(cas.cfg); err != nil {
		t.Fatalf("ensureAccount() error: %v", err)
	}

	if f.lookups != 1 || f.registrations != 0 {
		t.Errorf("lookups=%d registrations=%d, want 1 and 0", f.lookups, f.registrations)
	}
}

func TestEnsureAccount_RegistersWhenLookupUnsupported(t *testing.T) {
	f := &fakeACME{lookupProblem: "urn:ietf:params:acme:error:malformed"}
	cas := newTestCAS(t, newFakeACME(t, f))

	if err := cas.ensureAccount(cas.cfg); err != nil {
		t.Fatalf("ensureAccount() error: %v", err)
	}
	if f.lookups != 1 || f.registrations != 1 {
		t.Errorf("lookups=%d registrations=%d, want 1 and 1", f.lookups, f.registrations)
	}
}

func TestEnsureAccount_FailureIsReturnedAndRetried(t *testing.T) {
	const unauthorized = "urn:ietf:params:acme:error:unauthorized"
	f := &fakeACME{lookupProblem: unauthorized, registerProblem: unauthorized}
	cas := newTestCAS(t, newFakeACME(t, f))

	if err := cas.ensureAccount(cas.cfg); err == nil {
		t.Fatal("ensureAccount() succeeded, want error")
	}
	if cas.account.Registration != nil {
		t.Fatal("account kept after a failed registration")
	}

	f.lookupProblem, f.registerProblem = "", ""
	if err := cas.ensureAccount(cas.cfg); err != nil {
		t.Fatalf("retry ensureAccount() error: %v", err)
	}
	if f.lookups != 2 || f.registrations != 2 {
		t.Errorf("lookups=%d registrations=%d, want 2 and 2", f.lookups, f.registrations)
	}
}

func TestLoadAccountKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))

	t.Run("no path generates a key", func(t *testing.T) {
		key, err := loadAccountKey("")
		if err != nil || key == nil {
			t.Fatalf("loadAccountKey() = %v, %v; want a key", key, err)
		}
	})

	t.Run("existing file is used and left untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "account.key")
		if err := os.WriteFile(path, []byte(ecPEM), 0o400); err != nil {
			t.Fatal(err)
		}
		key, err := loadAccountKey(path)
		if err != nil {
			t.Fatalf("loadAccountKey() error: %v", err)
		}
		if !key.Equal(ecKey) {
			t.Error("loadAccountKey() returned a different key")
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != ecPEM {
			t.Errorf("key file was modified: %v", err)
		}
	})

	t.Run("missing file is created once and reused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "account.key")
		first, err := loadAccountKey(path)
		if err != nil {
			t.Fatalf("first loadAccountKey() error: %v", err)
		}
		second, err := loadAccountKey(path)
		if err != nil {
			t.Fatalf("second loadAccountKey() error: %v", err)
		}
		if !first.Equal(second) {
			t.Error("second start returned a different key")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		// Windows does not map Unix permission bits, so only check them elsewhere.
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
		}
	})

	t.Run("missing directory fails", func(t *testing.T) {
		if _, err := loadAccountKey(filepath.Join(t.TempDir(), "missing", "account.key")); err == nil {
			t.Fatal("loadAccountKey() succeeded, want error")
		}
	})

	for name, value := range map[string]string{"not PEM": "not a key", "RSA key": rsaPEM} {
		t.Run(name+" fails and is kept", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "account.key")
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAccountKey(path); err == nil {
				t.Fatal("loadAccountKey() succeeded, want error")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != value {
				t.Errorf("invalid key file was modified: %v", err)
			}
		})
	}
}
