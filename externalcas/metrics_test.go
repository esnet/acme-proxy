package externalcas

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCertMetaCollector_Describe(t *testing.T) {
	c := newCertMetaCollector(newTestStore(t))
	ch := make(chan *prometheus.Desc, 10)
	c.Describe(ch)
	close(ch)

	var count int
	for range ch {
		count++
	}
	if count != 6 {
		t.Errorf("Describe() sent %d descriptors, want 6", count)
	}
}

func TestCertMetaCollector_Collect_SuccessRecord(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)
	if err := s.recordIssued(CertRecord{
		Serial: "abc123", CommonName: "example.com", Issuer: "Test CA",
		SANs: "example.com", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour),
		DurationSeconds: 2.5, Status: "success",
	}); err != nil {
		t.Fatal(err)
	}

	c := newCertMetaCollector(s)
	// A successful issuance emits 4 metric families: info, issuedAt, expiresAt, signingDuration.
	for _, name := range []string{
		"externalcas_certificate_info",
		"externalcas_certificate_issued_timestamp_seconds",
		"externalcas_certificate_expiry_timestamp_seconds",
		"externalcas_certificate_signing_duration_seconds",
	} {
		if n := testutil.CollectAndCount(c, name); n != 1 {
			t.Errorf("CollectAndCount(%q) = %d, want 1", name, n)
		}
	}
}

func TestCertMetaCollector_Collect_FailureRecord(t *testing.T) {
	s := newTestStore(t)
	if err := s.recordIssued(CertRecord{
		CommonName: "example.com", SANs: "example.com",
		DurationSeconds: 0.3, Status: "failure",
	}); err != nil {
		t.Fatal(err)
	}

	c := newCertMetaCollector(s)
	// Failures emit info and duration but NOT timestamp metrics — IssuedAt/ExpiresAt are
	// zero values that would appear as 1970-01-01 in dashboards.
	for _, name := range []string{
		"externalcas_certificate_info",
		"externalcas_certificate_signing_duration_seconds",
	} {
		if n := testutil.CollectAndCount(c, name); n != 1 {
			t.Errorf("CollectAndCount(%q) = %d, want 1", name, n)
		}
	}
	for _, name := range []string{
		"externalcas_certificate_issued_timestamp_seconds",
		"externalcas_certificate_expiry_timestamp_seconds",
	} {
		if n := testutil.CollectAndCount(c, name); n != 0 {
			t.Errorf("CollectAndCount(%q) = %d, want 0 (timestamps must not be emitted for failures)", name, n)
		}
	}
}

func TestCertMetaCollector_Collect_RevokedRecord(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)
	if err := s.recordRevoked(CertRecord{
		Serial: "def456", CommonName: "example.com", Issuer: "Test CA",
		SANs: "example.com", IssuedAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour),
		DurationSeconds: 0.5, Status: "success",
	}); err != nil {
		t.Fatal(err)
	}

	c := newCertMetaCollector(s)
	for _, name := range []string{
		"externalcas_certificate_revocation_info",
		"externalcas_certificate_revocation_duration_seconds",
	} {
		if n := testutil.CollectAndCount(c, name); n != 1 {
			t.Errorf("CollectAndCount(%q) = %d, want 1", name, n)
		}
	}
}

func TestCertMetaCollector_Collect_LabelValues(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Truncate(time.Second)
	if err := s.recordIssued(CertRecord{
		Serial: "abc123", CommonName: "example.com", Issuer: "Test CA",
		SANs: "example.com,www.example.com", IssuedAt: now,
		ExpiresAt: now.Add(time.Hour), Status: "success",
	}); err != nil {
		t.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(newCertMetaCollector(s))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() != "externalcas_certificate_info" {
			continue
		}
		if len(mf.GetMetric()) != 1 {
			t.Fatalf("expected 1 metric, got %d", len(mf.GetMetric()))
		}
		labels := make(map[string]string)
		for _, lp := range mf.GetMetric()[0].GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		for wantK, wantV := range map[string]string{
			"serial":      "abc123",
			"common_name": "example.com",
			"issuer":      "Test CA",
			"sans":        "example.com,www.example.com",
			"status":      "success",
		} {
			if labels[wantK] != wantV {
				t.Errorf("label %q = %q, want %q", wantK, labels[wantK], wantV)
			}
		}
		return
	}
	t.Error("externalcas_certificate_info not found in gathered metrics")
}

func TestStartMetricsServer_Disabled(t *testing.T) {
	if err := StartMetricsServer(Metrics{Enabled: false}); err != nil {
		t.Errorf("StartMetricsServer(disabled) = %v, want nil", err)
	}
}
