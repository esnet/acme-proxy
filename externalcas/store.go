package externalcas

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/smallstep/certificates/cas/apiv1"
	bolt "go.etcd.io/bbolt"
)

var (
	issuedBucket  = []byte("issued_certs")
	revokedBucket = []byte("revoked_certs")
	cachedBucket  = []byte("cached_certs")
)

// CertRecord holds persisted metadata for a single certificate operation.
// Fields are populated from the *x509.Certificate returned by the external CA.
// For failed issuances, Serial/Issuer/IssuedAt/ExpiresAt are left as zero values;
// CommonName and SANs are sourced from the CSR instead.
type CertRecord struct {
	Serial          string    `json:"serial"` // hex-encoded; empty for failed issuances
	CommonName      string    `json:"common_name"`
	Issuer          string    `json:"issuer"`              // cert.Issuer.CommonName; empty for failed issuances
	SANs            string    `json:"sans"`                // comma-separated DNS SANs
	IssuedAt        time.Time `json:"issued_at"`           // cert.NotBefore; zero for failed issuances
	ExpiresAt       time.Time `json:"expires_at"`          // cert.NotAfter;  zero for failed issuances
	DurationSeconds float64   `json:"duration_seconds"`    // seconds the external CA took
	Status          string    `json:"status"`              // "success" or "failure"
	ClientIP        string    `json:"client_ip,omitempty"` // ACME client that requested the cert
	Error           string    `json:"error,omitempty"`     // failure reason; empty on success
	RecordedAt      time.Time `json:"recorded_at"`         // when this record was persisted
	CertPEM         []byte    `json:"cert_pem,omitempty"`  // full PEM bundle (leaf + chain) for caching
}

// certStore manages a plugin-owned sidecar bbolt database and in-memory caches
// for issued and revoked certificate records. step-ca owns db/bbolt.db under an
// exclusive lock; this store uses a separate file so there is no lock contention.
type certStore struct {
	db        *bolt.DB
	mu        sync.RWMutex
	issued    []CertRecord
	revoked   []CertRecord
	certCache map[string]CertRecord // key: sorted comma-joined domains
}

// cacheKey builds a deterministic cache key from a list of domain names.
func cacheKey(domains []string) string {
	sorted := make([]string, len(domains))
	copy(sorted, domains)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// domains returns the list of domain names from the SANs field.
func (r CertRecord) domains() []string {
	if r.SANs == "" {
		return nil
	}
	return strings.Split(r.SANs, ",")
}

// matchesCSR reports whether the cached certificate's leaf public key equals
// the CSR's public key. A cached certificate can only ever be served for a
// CSR carrying the same key: certificates are bound to their public key, and
// e.g. step-ca bootstraps with a fresh in-memory key on every start.
func (r CertRecord) matchesCSR(csr *x509.CertificateRequest) bool {
	if csr == nil || len(r.CertPEM) == 0 {
		return false
	}
	block, _ := pem.Decode(r.CertPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	certPub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return false
	}
	csrPub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(certPub, csrPub)
}

// cacheFreshEnough reports whether a cached record may still be served:
// enough remaining validity AND not older than the configured maximum
// cache age. The age rule bounds the renewal cadence even for long-lived
// upstream certificates. Zero IssuedAt (legacy records) skips the age rule.
func cacheFreshEnough(r *CertRecord, cfg *acmeProxyConfig) bool {
	if time.Until(r.ExpiresAt) < cfg.CertCacheMinValidityDuration() {
		return false
	}
	if !r.IssuedAt.IsZero() && time.Since(r.IssuedAt) >= cfg.CertCacheMaxAgeDuration() {
		return false
	}
	return true
}

// toResponse converts a cached CertRecord into a CreateCertificateResponse.
func (r CertRecord) toResponse() (*apiv1.CreateCertificateResponse, error) {
	var certs []*x509.Certificate
	remaining := r.CertPEM
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cached certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		remaining = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in cached bundle")
	}
	leaf := certs[0]
	var chain []*x509.Certificate
	if len(certs) > 1 {
		chain = certs[1:]
	}
	return &apiv1.CreateCertificateResponse{
		Certificate:      leaf,
		CertificateChain: chain,
	}, nil
}

// newCertStore opens (or creates) the sidecar bbolt database at path, creates
// the required buckets, and loads existing records into the in-memory caches.
func newCertStore(path string) (*certStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open sidecar db at %s: %w", path, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(issuedBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(revokedBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(cachedBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialise buckets: %w", err)
	}

	s := &certStore{db: db, certCache: make(map[string]CertRecord)}
	if err := s.load(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load existing records: %w", err)
	}
	return s, nil
}

// load reads all records from both buckets into the in-memory caches,
// and loads cached certificates into the certCache index.
// Called once at startup so Prometheus scrapes immediately reflect history
// and cached certificates are available for serving.
func (s *certStore) load() error {
	return s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(issuedBucket).ForEach(func(_, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			s.issued = append(s.issued, r)
			return nil
		}); err != nil {
			return err
		}
		if err := tx.Bucket(revokedBucket).ForEach(func(_, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			s.revoked = append(s.revoked, r)
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(cachedBucket).ForEach(func(_, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			if r.Status == "success" && len(r.CertPEM) > 0 {
				key := cacheKey(r.domains())
				s.certCache[key] = r
			}
			return nil
		})
	})
}

// storeKey returns a stable bbolt key for r.
// Successful records use the hex serial (globally unique).
// Failed records have no serial, so a CN + nanosecond timestamp is used so
// each failed attempt is stored as a distinct entry.
func storeKey(r CertRecord) []byte {
	if r.Serial != "" {
		return []byte(r.Serial)
	}
	return []byte("failure:" + r.CommonName + ":" + fmt.Sprint(time.Now().UnixNano()))
}

func (s *certStore) persist(bucket, key []byte, r CertRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put(key, data)
	})
}

// recordIssued persists r to the issued_certs bucket and appends it to the
// in-memory slice so subsequent Prometheus scrapes pick it up immediately.
func (s *certStore) recordIssued(r CertRecord) error {
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	if err := s.persist(issuedBucket, storeKey(r), r); err != nil {
		return err
	}
	s.mu.Lock()
	s.issued = append(s.issued, r)
	s.mu.Unlock()
	return nil
}

// recordRevoked persists r to the revoked_certs bucket and appends it to the
// in-memory slice.
func (s *certStore) recordRevoked(r CertRecord) error {
	if r.RecordedAt.IsZero() {
		r.RecordedAt = time.Now().UTC()
	}
	if err := s.persist(revokedBucket, storeKey(r), r); err != nil {
		return err
	}
	s.mu.Lock()
	s.revoked = append(s.revoked, r)
	s.mu.Unlock()
	return nil
}

// cacheCert stores a successful certificate in the cache bucket and updates
// the in-memory index. If a cert for the same domains already exists, it is
// overwritten (only the latest valid cert is kept per domain set).
func (s *certStore) cacheCert(r CertRecord) error {
	if r.Status != "success" || len(r.CertPEM) == 0 {
		return nil
	}
	key := cacheKey(r.domains())
	if err := s.persist(cachedBucket, []byte(key), r); err != nil {
		return err
	}
	s.mu.Lock()
	s.certCache[key] = r
	s.mu.Unlock()
	return nil
}

// dropCached removes a cached certificate (key = comma-joined domain set)
// from the in-memory index and the bucket. Reports whether it existed.
func (s *certStore) dropCached(key string) bool {
	s.mu.Lock()
	_, ok := s.certCache[key]
	if ok {
		delete(s.certCache, key)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(cachedBucket).Delete([]byte(key))
	}) == nil
}

// findCachedCert looks up a cached certificate covering all requested domains.
// Returns nil if no valid cached certificate is found.
func (s *certStore) findCachedCert(domains []string) *CertRecord {
	key := cacheKey(domains)
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.certCache[key]
	if !ok {
		return nil
	}
	return &r
}

// allIssued returns a snapshot copy of all issued cert records.
func (s *certStore) allIssued() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, len(s.issued))
	copy(out, s.issued)
	return out
}

// allRevoked returns a snapshot copy of all revoked cert records.
func (s *certStore) allRevoked() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, len(s.revoked))
	copy(out, s.revoked)
	return out
}

// allCached returns a snapshot copy of all cached certificate records.
func (s *certStore) allCached() []CertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertRecord, 0, len(s.certCache))
	for _, r := range s.certCache {
		out = append(out, r)
	}
	return out
}

func (s *certStore) close() error {
	return s.db.Close()
}
