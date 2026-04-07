# KubeSentinel Prometheus Metrics

KubeSentinel exposes comprehensive Prometheus metrics for production observability. This guide explains the available metrics and how to integrate them with your monitoring stack.

## Quick Start

Start the monitor with metrics enabled:

```bash
kubesentinel monitor --metrics-port 8080
```

Prometheus metrics will be available at: `http://localhost:8080/metrics`

## Metrics Endpoint

- **URL**: `http://kubesentinel-host:8080/metrics`
- **Format**: Prometheus text format (RFC 1945)
- **Health check**: `http://kubesentinel-host:8080/health`

## Available Metrics

### Counter: `kubesentinel_falco_events_total`

Total number of Falco security events processed.

**Labels**:
- `severity`: Event severity level (critical, warning, notice, info, etc.)

**Example**:
```prometheus
kubesentinel_falco_events_total{severity="critical"} 42
kubesentinel_falco_events_total{severity="warning"} 156
```

### Counter: `kubesentinel_anomalies_detected_total`

Total number of runtime anomalies detected by the ML model.

**Labels**:
- `severity`: Anomaly severity (critical, high, medium, low)
- `type`: Anomaly type (process, network, file_access, privilege_escalation, etc.)

**Example**:
```prometheus
kubesentinel_anomalies_detected_total{severity="critical",type="privilege_escalation"} 3
kubesentinel_anomalies_detected_total{severity="high",type="network"} 12
```

### Histogram: `kubesentinel_event_process_duration_seconds`

Processing time for each security event, from capture to analysis.

**Labels**:
- `event_type`: Type of Falco event being processed

**Buckets**: Default (0.005s, 0.01s, 0.025s, 0.05s, 0.1s, 0.25s, 0.5s, 1s, 2.5s, 5s, 10s)

**Example**:
```prometheus
kubesentinel_event_process_duration_seconds_bucket{event_type="process",le="0.01"} 156
kubesentinel_event_process_duration_seconds_sum{event_type="process"} 12.34
kubesentinel_event_process_duration_seconds_count{event_type="process"} 234
```

### Histogram: `kubesentinel_scan_duration_seconds`

Time taken to scan Kubernetes manifests for misconfigurations.

**Labels**:
- `status`: Scan result (success, failed)

**Buckets**: 0.1s, 0.5s, 1s, 2s, 5s, 10s

**Example**:
```prometheus
kubesentinel_scan_duration_seconds_bucket{status="success",le="0.5"} 45
kubesentinel_scan_duration_seconds_sum{status="success"} 23.45
kubesentinel_scan_duration_seconds_count{status="success"} 89
```

### Gauge: `kubesentinel_active_connections`

Number of active client connections to the metrics server.

**Example**:
```prometheus
kubesentinel_active_connections 3
```

## Prometheus Configuration

Add KubeSentinel to your Prometheus `scrape_configs`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'kubesentinel'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 10s
    scrape_timeout: 5s
```

## Kubernetes Deployment

When deployed on Kubernetes via DaemonSet, Prometheus can auto-discover KubeSentinel instances:

```yaml
scrape_configs:
  - job_name: 'kubesentinel-daemonset'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - kubesentinel
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: kubesentinel
      - source_labels: [__meta_kubernetes_pod_port_name]
        action: keep
        regex: metrics
      - source_labels: [__meta_kubernetes_pod_name]
        target_label: pod
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
```

## Useful PromQL Queries

### Event Processing Rate (events/second)
```promql
rate(kubesentinel_falco_events_total[1m])
```

### Critical Anomalies Rate
```promql
rate(kubesentinel_anomalies_detected_total{severity="critical"}[5m])
```

### P95 Event Processing Duration
```promql
histogram_quantile(0.95, rate(kubesentinel_event_process_duration_seconds_bucket[5m]))
```

### Events by Severity
```promql
sum by (severity) (rate(kubesentinel_falco_events_total[5m]))
```

### Anomalies by Type
```promql
sum by (type) (kubesentinel_anomalies_detected_total)
```

### Total Processed Events
```promql
sum(kubesentinel_falco_events_total)
```

## Grafana Dashboards

Example dashboard variables to monitor KubeSentinel health:

```yaml
# Events per second by severity
title: "Event Processing Rate"
query: |
  sum by (severity) (
    rate(kubesentinel_falco_events_total[1m])
  )

# Anomaly detection status
title: "Anomalies Detected (24h)"
query: |
  sum by (severity) (
    increase(kubesentinel_anomalies_detected_total[24h])
  )

# Processing latency
title: "Event Processing Duration (P99)"
query: |
  histogram_quantile(0.99, 
    rate(kubesentinel_event_process_duration_seconds_bucket[5m])
  )
```

## Alerting Rules

Example Prometheus alert rules:

```yaml
groups:
  - name: kubesentinel
    rules:
      - alert: HighAnomalyDetectionRate
        expr: |
          rate(kubesentinel_anomalies_detected_total{severity="critical"}[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High rate of critical anomalies detected"
          description: "{{ $value }} critical anomalies per second"

      - alert: SlowEventProcessing
        expr: |
          histogram_quantile(0.95, 
            rate(kubesentinel_event_process_duration_seconds_bucket[5m])
          ) > 1
        for: 10m
        annotations:
          summary: "KubeSentinel event processing latency is high"
          description: "P95 latency: {{ $value }}s"

      - alert: NoEventsProcessed
        expr: |
          rate(kubesentinel_falco_events_total[5m]) == 0
        for: 15m
        annotations:
          summary: "KubeSentinel is not processing events"
          description: "No events received in the last 5 minutes"
```

## Metrics Size and Performance

- **Cardinality**: Low-to-medium (< 100 time series for typical deployments)
- **Scrape size**: ~2-5 KB per scrape
- **Collection overhead**: Negligible (< 1% CPU)
- **Memory overhead**: ~10-20 MB for metrics storage

## Disabling Metrics

To run KubeSentinel without metrics:

```bash
kubesentinel monitor --metrics-port ""
```

Or omit the `--metrics-port` flag entirely.

## Integration Examples

### Adding to Docker Compose

```yaml
kubesentinel:
  image: kubesentinel:latest
  command: monitor --metrics-port 8080
  ports:
    - "8080:8080"  # Metrics

prometheus:
  image: prom/prometheus:latest
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
  ports:
    - "9090:9090"
  command:
    - "--config.file=/etc/prometheus/prometheus.yml"
```

### Kubernetes Deployment

The DaemonSet manifest already includes metrics support:

```yaml
containers:
  - name: kubesentinel
    args:
      - "monitor"
      - "--metrics-port=8080"
    ports:
      - name: metrics
        containerPort: 8080
```

## Troubleshooting

### Metrics not appearing

1. Check if the metrics server started:
   ```bash
   curl http://localhost:8080/health
   ```

2. Verify the metrics endpoint:
   ```bash
   curl http://localhost:8080/metrics
   ```

3. Check for port conflicts:
   ```bash
   netstat -tuln | grep 8080
   ```

### High cardinality issues

If you see cardinality warnings in Prometheus:

1. Limit the number of event types being tracked
2. Filter metrics at scrape time using relabel_configs
3. Increase `metric_relabel_configs` in Prometheus

### Performance impact

Metrics collection is lightweight, but if you observe performance issues:

1. Increase scrape interval: `scrape_interval: 30s`
2. Disable unused metrics (would require code changes)
3. Use Prometheus remote storage to reduce local pressure
