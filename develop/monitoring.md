# Monitoring acme-proxy with Prometheus and Grafana

This guide covers setting up a local Prometheus and Grafana stack that scrapes metrics from an acme-proxy container running on the `acme-proxy-testbridge` Docker network.

## Prerequisites

- `acme-proxy-testbridge` network exists and acme-proxy is running on it (see `test-infra.md`)
- `ca.json` has `metrics.port` and `metrics.dataSource` configured
- A `prometheus.yml` scrape config

## Start Prometheus

```sh
docker run -d --name prometheus \
  --network acme-proxy-testbridge \
  -v "$(pwd)/contrib/develop/prometheus.yml":/etc/prometheus/prometheus.yml:ro \
  -p 9090:9090 \
  prom/prometheus:latest
```

The `-p 9090:9090` publish is optional. It exposes the Prometheus UI on your host at `http://localhost:9090` but is not required for Grafana — Grafana reaches Prometheus over the bridge by container name.

## Start Grafana

```sh
docker run -d --name grafana \
  --network acme-proxy-testbridge \
  -p 3000:3000 \
  grafana/grafana:latest
```

## Add Prometheus as a Grafana data source

1. Open `http://localhost:3000` (default credentials: `admin` / `admin`)
2. Go to **Connections → Data sources → Add data source → Prometheus**
3. Set the URL to `http://prometheus:9090` — use the container name, not `localhost`
4. Click **Save & test**

---

## Metrics reference

acme-proxy exposes three categories of metrics on the `/metrics` endpoint.

### Per-certificate metrics (custom collector)

These are emitted on every Prometheus scrape from the in-memory sidecar store. One time series is emitted per certificate record — they are not rate-based and do not reset on process restart.

| Metric | Labels | Description |
|---|---|---|
| `externalcas_certificate_info` | `serial`, `common_name`, `issuer`, `sans`, `status` | Metadata for each issued certificate. Value is always 1. Status is `success` or `failure`. Failed issuances have empty serial and issuer. |
| `externalcas_certificate_issued_timestamp_seconds` | `serial`, `common_name` | Unix timestamp of cert `NotBefore`. Only emitted for `status="success"`. |
| `externalcas_certificate_expiry_timestamp_seconds` | `serial`, `common_name` | Unix timestamp of cert `NotAfter`. Only emitted for `status="success"`. |
| `externalcas_certificate_signing_duration_seconds` | `serial`, `common_name`, `status` | Time in seconds the external CA took to sign this specific certificate. Emitted for both success and failure. |
| `externalcas_certificate_revocation_info` | `serial`, `common_name`, `issuer`, `sans`, `status` | Metadata for each revoked certificate. Value is always 1. |
| `externalcas_certificate_revocation_duration_seconds` | `serial`, `common_name`, `status` | Time in seconds the external CA took to process the revocation. |

### Aggregate operation metrics (in-process)

These are standard Prometheus counters, histograms, and gauges updated at operation time. They reset to zero if the process restarts.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `externalcas_certificates_issued_total` | counter | `status` (`success`, `failure`) | Total certificate issuances since process start. |
| `externalcas_certificates_revoked_total` | counter | `status` (`success`, `failure`) | Total certificate revocations since process start. |
| `externalcas_certificate_request_duration_seconds` | histogram | `operation` (`issue`, `revoke`) | End-to-end time from receiving the request to getting a response from the external CA. Buckets: 1s, 2.5s, 5s, 10s, 30s, 60s, 120s. |
| `externalcas_acme_roundtrip_duration_seconds` | histogram | `acme_operation` (`register`, `obtain`, `revoke`) | Time for individual ACME protocol calls. Useful for isolating which step is slow. Buckets: 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s. |
| `externalcas_certificate_expiration_seconds` | histogram | `status` (`issued`) | Distribution of certificate lifetimes (NotAfter − NotBefore in seconds). Buckets: 1d, 7d, 30d, 60d, 90d, 365d. |
| `externalcas_external_ca_up` | gauge | — | Reachability of the external CA directory URL. 1 = last probe returned 2xx, 0 = error or non-2xx. Probed every 30 seconds. |
| `externalcas_last_successful_certificate_timestamp_seconds` | gauge | — | Unix timestamp of the most recently successfully issued certificate. |

### Go runtime and process metrics

Collected automatically from the Go runtime and OS process. A subset of the most useful ones:

| Metric | Description |
|---|---|
| `go_goroutines` | Number of goroutines currently running. |
| `go_gc_duration_seconds` | Distribution of GC stop-the-world pause durations. |
| `go_memstats_alloc_bytes` | Bytes of heap objects currently allocated. |
| `go_memstats_heap_inuse_bytes` | Bytes in heap spans currently in use. |
| `go_memstats_sys_bytes` | Total bytes of memory obtained from the OS. |
| `process_resident_memory_bytes` | RSS — bytes of physical memory in use. |
| `process_cpu_seconds_total` | Total CPU time consumed by the process. |
| `process_open_fds` | Number of open file descriptors. |

---

## Grafana dashboard PromQL

The queries below are organized by recommended Grafana panel type. The suggested dashboard layout has five rows.

### Row 1 — Health overview (Stat panels)

These give an at-a-glance summary of system health at the top of the dashboard.

**External CA status**
Use a Stat panel with value mappings: 1 → "UP" (green), 0 → "DOWN" (red).
```promql
externalcas_external_ca_up
```

**Total certificates issued (success)**
```promql
externalcas_certificates_issued_total{status="success"}
```

**Total certificates issued (failure)**
```promql
externalcas_certificates_issued_total{status="failure"}
```

**Total certificates revoked**
```promql
externalcas_certificates_revoked_total{status="success"}
```

**Issuance success rate**
Percentage of issuance attempts that succeeded over the last 5 minutes. Set unit to `percent (0-1)`.
```promql
rate(externalcas_certificates_issued_total{status="success"}[5m])
/
rate(externalcas_certificates_issued_total[5m])
```

**Time since last successful certificate (minutes)**
Useful for alerting if no cert has been issued recently when one was expected.
```promql
(time() - externalcas_last_successful_certificate_timestamp_seconds) / 60
```

---

### Row 2 — Certificate operations (Time series panels)

**Issuance rate by status**
Two series on one panel: successful and failed issuances per second.
```promql
rate(externalcas_certificates_issued_total[5m])
```

**Revocation rate by status**
```promql
rate(externalcas_certificates_revoked_total[5m])
```

**Cumulative issuances over time**
Shows growth rate visually. Use `increase()` over your dashboard time range for a windowed view.
```promql
increase(externalcas_certificates_issued_total{status="success"}[$__range])
```

---

### Row 3 — Latency (Time series and Heatmap panels)

**End-to-end request latency percentiles (Time series)**
Three queries on one panel for P50, P95, P99. Set legend to `{{operation}} p{{quantile}}`.
```promql
histogram_quantile(0.50, rate(externalcas_certificate_request_duration_seconds_bucket[5m]))
```
```promql
histogram_quantile(0.95, rate(externalcas_certificate_request_duration_seconds_bucket[5m]))
```
```promql
histogram_quantile(0.99, rate(externalcas_certificate_request_duration_seconds_bucket[5m]))
```

**ACME roundtrip latency by operation (Time series)**
Shows how long each individual ACME protocol step takes: account registration, certificate obtain, revoke.
```promql
histogram_quantile(0.95, rate(externalcas_acme_roundtrip_duration_seconds_bucket[5m]))
```

**Certificate lifetime distribution (Bar gauge)**
Shows what proportion of issued certs fall into each lifetime bucket (30-day, 90-day, etc.).
```promql
rate(externalcas_certificate_expiration_seconds_bucket[1h])
```

---

### Row 4 — Certificate inventory (Table panels)

**All active certificates with days remaining**
One row per cert, sorted by days remaining ascending. Set column `Days Remaining` with threshold coloring: red < 15, yellow < 30, green otherwise.
```promql
(externalcas_certificate_expiry_timestamp_seconds - time()) / 86400
```

**Certificates expiring within 30 days**
Filters to only certs approaching expiry. Use as the basis for an alert rule.
```promql
(externalcas_certificate_expiry_timestamp_seconds - time()) / 86400 < 30
```

**Days remaining on the current active cert per CN/SAN pair**
When a cert has been renewed, multiple serials exist for the same CN/SAN. `max` selects the newest cert's expiry without needing to know the serial.
```promql
(
  max by (common_name, sans) (externalcas_certificate_expiry_timestamp_seconds)
  - time()
) / 86400
```

**Renewal count per CN/SAN pair**
Any CN/SAN pair with more than one successful issuance has been renewed. Value of 0 = never renewed, 1 = renewed once, etc.
```promql
count by (common_name, sans) (externalcas_certificate_info{status="success"}) - 1
```

**Full certificate inventory (Table)**
Displays all cert metadata. In Grafana, use a Table panel and enable the label columns `serial`, `common_name`, `issuer`, `sans`, `status`.
```promql
externalcas_certificate_info
```

**Revoked certificate inventory (Table)**
```promql
externalcas_certificate_revocation_info
```

---

### Row 5 — Go runtime and process (Time series panels)

**Goroutine count**
Sustained growth here indicates a goroutine leak.
```promql
go_goroutines
```

**Heap memory in use**
```promql
go_memstats_heap_inuse_bytes
```

**GC pause duration (P99)**
```promql
histogram_quantile(0.99, rate(go_gc_duration_seconds_bucket[5m]))
```

**CPU usage (rate)**
```promql
rate(process_cpu_seconds_total[1m])
```

**Open file descriptors**
```promql
process_open_fds
```

---

## Alert rules

The following PromQL expressions evaluate to a non-empty result when the condition is true, which is the standard Prometheus alerting pattern.

**External CA unreachable**
```promql
externalcas_external_ca_up == 0
```

**Certificate expiring within 30 days**
```promql
(externalcas_certificate_expiry_timestamp_seconds - time()) / 86400 < 30
```

**Certificate expiring within 7 days**
```promql
(externalcas_certificate_expiry_timestamp_seconds - time()) / 86400 < 7
```

**Issuance failure rate above 10% over last 5 minutes**
```promql
rate(externalcas_certificates_issued_total{status="failure"}[5m])
/
rate(externalcas_certificates_issued_total[5m])
> 0.1
```

**No successful issuance in the last hour**
Fires only if at least one issuance has ever occurred (gauge is non-zero) but nothing recent has succeeded.
```promql
(
  externalcas_last_successful_certificate_timestamp_seconds > 0
  and
  (time() - externalcas_last_successful_certificate_timestamp_seconds) > 3600
)
```

---

## Notes on renewal detection

acme-proxy does not explicitly distinguish a first issuance from a renewal at the metric level — both go through `CreateCertificate` and increment `externalcas_certificates_issued_total{status="success"}`. Renewal detection is done at query time: when an ACME client renews a cert it receives a new serial number for the same set of SANs. The `externalcas_certificate_info` metric emits one series per serial, so two series sharing the same `common_name` and `sans` labels but with different `serial` labels indicates a renewal occurred.

The `max` aggregation in several queries above exploits the fact that the newer cert always has a later `NotBefore` and `NotAfter`, so it naturally selects the active cert without needing to inspect the serial directly.

---

## Teardown

```sh
docker kill prometheus grafana
docker rm prometheus grafana
```
