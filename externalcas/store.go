package externalcas

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	issuedBucket  = []byte("issued_certs")
	revokedBucket = []byte("revoked_certs")
)

// CertRecord holds persisted metadata for a single certificate operation.
// Fields are populated from the *x509.Certificate returned by the external CA.
// For failed issuances, Serial/Issuer/IssuedAt/ExpiresAt are left as zero values;
// CommonName and SANs are sourced from the CSR instead.
type CertRecord struct {
	Serial          string    `json:"serial"` // hex-encoded; empty for failed issuances
	CommonName      string    `json:"common_name"`
	Issuer          string    `json:"issuer"`           // cert.Issuer.CommonName; empty for failed issuances
	SANs            string    `json:"sans"`             // comma-separated DNS SANs
	IssuedAt        time.Time `json:"issued_at"`        // cert.NotBefore; zero for failed issuances
	ExpiresAt       time.Time `json:"expires_at"`       // cert.NotAfter;  zero for failed issuances
	DurationSeconds float64   `json:"duration_seconds"` // seconds the external CA took
	Status          string    `json:"status"`           // "success" or "failure"
}

// certStore manages a plugin-owned sidecar bbolt database and in-memory caches
// for issued and revoked certificate records. step-ca owns db/bbolt.db under an
// exclusive lock; this store uses a separate file so there is no lock contention.
type certStore struct {
	db      *bolt.DB
	mu      sync.RWMutex
	issued  []CertRecord
	revoked []CertRecord
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
		_, err := tx.CreateBucketIfNotExists(revokedBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialise buckets: %w", err)
	}

	s := &certStore{db: db}
	if err := s.load(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load existing records: %w", err)
	}
	return s, nil
}

// load reads all records from both buckets into the in-memory caches.
// Called once at startup so Prometheus scrapes immediately reflect history.
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
		return tx.Bucket(revokedBucket).ForEach(func(_, v []byte) error {
			var r CertRecord
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			s.revoked = append(s.revoked, r)
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
	if err := s.persist(revokedBucket, storeKey(r), r); err != nil {
		return err
	}
	s.mu.Lock()
	s.revoked = append(s.revoked, r)
	s.mu.Unlock()
	return nil
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

func (s *certStore) close() error {
	return s.db.Close()
}
