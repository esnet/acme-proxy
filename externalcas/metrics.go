// Total certs issued, renewed, revoked
// client metadata (hostname, src_ip, acme_client used)
// SAN(s), isssue/renew status (success, failed)
// cert expiraiton date
// external CA acme endpoint status (up/down)
// measure time it takes to get certs signed from external CA

package externalcas

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// certMetaCollector is a custom Prometheus Collector that emits per-certificate
// metadata metrics on each scrape, reading from the in-memory cache in certStore.
type certMetaCollector struct {
	store              *certStore
	issuedInfo         *prometheus.Desc
	issuedAt           *prometheus.Desc
	expiresAt          *prometheus.Desc
	requestDuration    *prometheus.Desc
	revokedInfo        *prometheus.Desc
	revocationDuration *prometheus.Desc
}

func newCertMetaCollector(s *certStore) *certMetaCollector {
	idLabels := []string{"serial", "common_name"}
	allLabels := []string{"serial", "common_name", "issuer", "sans", "status"}
	durationLabels := []string{"serial", "common_name", "status"}
	return &certMetaCollector{
		store: s,
		issuedInfo: prometheus.NewDesc(
			"externalcas_certificate_info",
			"Metadata for each issued certificate (value is always 1)",
			allLabels, nil,
		),
		issuedAt: prometheus.NewDesc(
			"externalcas_certificate_issued_timestamp_seconds",
			"Unix timestamp when the certificate was issued (NotBefore)",
			idLabels, nil,
		),
		expiresAt: prometheus.NewDesc(
			"externalcas_certificate_expiry_timestamp_seconds",
			"Unix timestamp when the certificate expires (NotAfter)",
			idLabels, nil,
		),
		requestDuration: prometheus.NewDesc(
			"externalcas_certificate_signing_duration_seconds",
			"Time in seconds the external CA took to sign this specific certificate",
			durationLabels, nil,
		),
		revokedInfo: prometheus.NewDesc(
			"externalcas_certificate_revocation_info",
			"Metadata for each revoked certificate (value is always 1)",
			allLabels, nil,
		),
		revocationDuration: prometheus.NewDesc(
			"externalcas_certificate_revocation_duration_seconds",
			"Time in seconds the external CA took to revoke the certificate",
			durationLabels, nil,
		),
	}
}

// Describe sends all metric descriptors to Prometheus.
func (c *certMetaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.issuedInfo
	ch <- c.issuedAt
	ch <- c.expiresAt
	ch <- c.requestDuration
	ch <- c.revokedInfo
	ch <- c.revocationDuration
}

// Collect emits per-certificate metrics for every issued and revoked cert in
// the sidecar store. Called by Prometheus on each scrape.
//
// Label order for issued metrics:
//
//	issuedInfo:      serial, common_name, issuer, sans, status
//	issuedAt:        serial, common_name
//	expiresAt:       serial, common_name
//	requestDuration: serial, common_name, status
//
// Label order for revoked metrics:
//
//	revokedInfo:         serial, common_name, issuer, sans, status
//	revocationDuration:  serial, common_name, status
func (c *certMetaCollector) Collect(ch chan<- prometheus.Metric) {
	for _, r := range c.store.allIssued() {
		ch <- prometheus.MustNewConstMetric(c.issuedInfo, prometheus.GaugeValue, 1,
			r.Serial, r.CommonName, r.Issuer, r.SANs, r.Status)
		ch <- prometheus.MustNewConstMetric(c.requestDuration, prometheus.GaugeValue, r.DurationSeconds,
			r.Serial, r.CommonName, r.Status)
		if r.Status == "success" {
			ch <- prometheus.MustNewConstMetric(c.issuedAt, prometheus.GaugeValue, float64(r.IssuedAt.Unix()),
				r.Serial, r.CommonName)
			ch <- prometheus.MustNewConstMetric(c.expiresAt, prometheus.GaugeValue, float64(r.ExpiresAt.Unix()),
				r.Serial, r.CommonName)
		}
	}
	for _, r := range c.store.allRevoked() {
		ch <- prometheus.MustNewConstMetric(c.revokedInfo, prometheus.GaugeValue, 1,
			r.Serial, r.CommonName, r.Issuer, r.SANs, r.Status)
		ch <- prometheus.MustNewConstMetric(c.revocationDuration, prometheus.GaugeValue, r.DurationSeconds,
			r.Serial, r.CommonName, r.Status)
	}
}

// StartMetricsServer starts the Prometheus metrics HTTP server once.
// DataSource is guaranteed non-empty by AcmeProxyConfig.Validate() when enabled.
// Returns an error if the cert store cannot be opened — this fails server startup.
func StartMetricsServer(m Metrics) error {
	if !m.Enabled {
		return nil
	}
	var startErr error
	metricsServerOnce.Do(func() {
		s, err := newCertStore(m.DataSource)
		if err != nil {
			startErr = fmt.Errorf("failed to open cert store: %w", err)
			return
		}
		globalStore = s
		if err := registry.Register(newCertMetaCollector(s)); err != nil {
			startErr = fmt.Errorf("failed to register cert meta collector: %w", err)
			return
		}
		metricsEnabled = true
		port := m.Port
		if port == 0 {
			port = 9123
		}
		addr := ":" + strconv.Itoa(port)
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		go func() {
			slog.Info("starting metrics server", "addr", addr)
			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server stopped", "error", err)
			}
		}()
	})
	return startErr
}

var (
	// metricsServerOnce ensures the metrics HTTP server starts exactly once
	metricsServerOnce sync.Once

	// metricsEnabled is set to true when the metrics server starts successfully
	metricsEnabled bool

	// globalStore is the sidecar cert store; nil when DataSource is not configured
	globalStore *certStore

	// Prometheus registry for all externalcas metrics
	registry *prometheus.Registry

	// Counters - monotonically increasing values
	certificatesIssuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "externalcas_certificates_issued_total",
			Help: "Total number of certificates issued from external CA, labeled by status (success/failure)",
		},
		[]string{"status"},
	)

	certificatesRenewedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "externalcas_certificates_renewed_total",
			Help: "Total number of certificates renewed from external CA, labeled by status (success/failure)",
		},
		[]string{"status"},
	)

	certificatesRevokedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "externalcas_certificates_revoked_total",
			Help: "Total number of certificates revoked at external CA, labeled by status (success/failure)",
		},
		[]string{"status"},
	)

	acmeErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "externalcas_acme_errors_total",
			Help: "Total number of ACME protocol errors encountered, labeled by error type",
		},
		[]string{"error_type"},
	)

	// Histograms - distribution of observed values (request durations)
	certificateRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "externalcas_certificate_request_duration_seconds",
			Help: "Time taken to obtain certificate from external CA (in seconds)",
			// Buckets: 1s, 2.5s, 5s, 10s, 30s, 60s, 120s
			Buckets: []float64{1, 2.5, 5, 10, 30, 60, 120},
		},
		[]string{"operation"}, // operation: issue, revoke
	)

	acmeRoundtripDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "externalcas_acme_roundtrip_duration_seconds",
			Help: "Time taken for individual ACME API calls (in seconds)",
			// Buckets: 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"acme_operation"}, // acme_operation: register, obtain, revoke
	)

	// Gauges - values that can go up or down
	externalCAStatus = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "externalcas_external_ca_up",
			Help: "Status of external CA (1 = up/healthy, 0 = down/unhealthy)",
		},
	)

	lastSuccessfulCertificateTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "externalcas_last_successful_certificate_timestamp_seconds",
			Help: "Unix timestamp of the last successfully issued certificate",
		},
	)

	certificateExpirationTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "externalcas_certificate_expiration_seconds",
			Help: "Distribution of certificate expiration times (lifetime in seconds)",
			// Buckets: 1 day, 7 days, 30 days, 60 days, 90 days, 365 days
			Buckets: []float64{86400, 604800, 2592000, 5184000, 7776000, 31536000},
		},
		[]string{"status"}, // status: issued, renewed
	)
)

func init() {
	// Create a dedicated Prometheus registry for externalcas metrics
	// This allows isolation from other metrics that might exist in the application
	registry = prometheus.NewRegistry()

	// Register all metrics with the custom registry
	registry.MustRegister(certificatesIssuedTotal)
	registry.MustRegister(certificatesRenewedTotal)
	registry.MustRegister(certificatesRevokedTotal)
	registry.MustRegister(acmeErrorsTotal)
	registry.MustRegister(certificateRequestDuration)
	registry.MustRegister(acmeRoundtripDuration)
	registry.MustRegister(externalCAStatus)
	registry.MustRegister(lastSuccessfulCertificateTimestamp)
	registry.MustRegister(certificateExpirationTime)

	// Initialize external CA status to unknown (0)
	// Will be set to 1 on first successful operation
	externalCAStatus.Set(0)
}
