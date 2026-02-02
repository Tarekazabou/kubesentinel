# Go-CSPM Architecture Deep Dive

## Overview

Go-CSPM implements a five-layer security architecture that combines static analysis, runtime monitoring, AI-powered detection, forensic storage, and automated reporting.

## Architecture Layers

### 1. Static Policy Engine (Shift-Left Security)

**Purpose**: Catch misconfigurations before deployment

**Implementation**: `internal/static/`

**Key Components**:
- **Scanner** (`scanner.go`): Orchestrates the scanning process
  - Discovers YAML/YML manifest files
  - Parses Kubernetes resources
  - Applies rules and validators
  - Generates violation reports

- **Rules Engine** (`rules.go`): Manages security policies
  - Loads custom rules from YAML files
  - Evaluates path-based conditions
  - Supports multiple operators (equals, exists, contains, etc.)
  - Extensible rule framework

**Built-in Checks**:
- Privileged containers (SEC-001)
- Missing resource limits (SEC-002)
- Non-root user enforcement (SEC-003)
- Read-only root filesystem (SEC-004)
- Security context validation (SEC-005)

**Integration Point**: CI/CD pipeline
- Returns non-zero exit code on violations
- Generates JSON/YAML reports
- Blocks deployments with critical issues

### 2. Live Stream Monitor (Runtime Detection)

**Purpose**: Real-time security event processing

**Implementation**: `internal/runtime/`

**Key Components**:
- **Monitor** (`monitor.go`): Event stream orchestrator
  - Connects to Falco unix socket
  - Filters events by namespace/deployment
  - Manages worker goroutines
  - Collects metrics

- **Event Processor** (`processor.go`): Concurrent event processing
  - Worker pool pattern with goroutines
  - Lock-free metrics using atomic operations
  - Feature extraction pipeline
  - AI integration layer

**Concurrency Model**:
```
┌─────────────┐
│ Falco Events│
└──────┬──────┘
       │
       ▼
┌──────────────┐
│Event Channel │ (Buffered, 10k capacity)
└──────┬───────┘
       │
       ├──────────┐
       ▼          ▼
  [Worker 1] [Worker 2] ... [Worker N]
       │          │
       └────┬─────┘
            ▼
      ┌──────────┐
      │ AI Client│
      └────┬─────┘
           ▼
    ┌─────────────┐
    │Forensic Vault│
    └─────────────┘
```

**Performance Characteristics**:
- Non-blocking event ingestion
- Configurable worker count (default: 4)
- Lock-free metric collection
- ~50k events/second throughput

### 3. AI Behavioral Analyzer

**Purpose**: Detect unknown threats through behavioral analysis

**Implementation**: 
- Go Client: `internal/ai/client.go`
- Python Service: `ai-module/server.py`

**Architecture**:
```
┌─────────────┐
│   Go CLI    │
└──────┬──────┘
       │ HTTP/REST
       ▼
┌─────────────────┐
│ Flask API       │
│ (Python Server) │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Scikit-learn    │
│ Isolation Forest│
└─────────────────┘
```

**Feature Extraction**:
The system extracts these behavioral features:
- Process frequency patterns
- System call distributions
- File access counts
- Network connection patterns
- Sensitive file access
- Temporal features (time of day, day of week)
- Container lifecycle metrics

**Model**: Isolation Forest
- Unsupervised anomaly detection
- Training on "normal" baseline behavior
- Contamination rate: 10%
- 100 decision trees
- Incremental learning capability

**Detection Flow**:
1. Extract features from security events
2. Normalize features using StandardScaler
3. Score sample using Isolation Forest
4. Apply threshold (default: 0.75)
5. Generate explanation and suggestions

### 4. Smart Forensic Vault

**Purpose**: Policy-aware evidence retention

**Implementation**: `internal/forensics/vault.go`

**Design Philosophy**: 
- **Selective Storage**: Only high-value evidence
- **Policy-Driven**: Retention based on severity and risk
- **Structured Format**: JSON for easy parsing
- **Privacy-Aware**: Configurable retention periods

**Retention Policy**:
Always retained:
- Critical/High severity incidents
- Medium severity with risk score > 0.7
- Confirmed security incidents

Auto-deleted:
- Low severity events
- False positives
- Data older than retention period (90 days default)

**Storage Structure**:
```
forensics/
├── 20240215_143022_1234567890.json  # Timestamp_ID.json
├── 20240215_145533_1234567891.json
└── 20240215_151045_1234567892.json
```

**Record Contents**:
- Incident metadata (ID, timestamp, severity, risk score)
- Container context (ID, name, image, namespace)
- Security events (Falco rules triggered)
- System calls (detailed syscall traces)
- Network traces (connection metadata)
- File operations (filesystem activity)

### 5. Automated Investigator

**Purpose**: Human-readable forensic reporting

**Implementation**: `internal/reporting/generator.go`

**Report Formats**:
1. **Markdown**: Human-readable investigation summaries
2. **JSON**: Machine-readable for SIEM integration
3. **HTML**: Web-viewable reports with styling

**Report Structure**:

```markdown
# Security Investigation Report

## Executive Summary
- Overall risk level
- Total incidents by severity
- Affected containers
- Top threats

## Incidents
[Detailed incident analysis]

## Timeline
[Chronological event sequence]

## Recommendations
[Prioritized remediation steps]

## Statistics
[Metrics and analytics]
```

## Data Flow

### Static Analysis Path
```
YAML Files → Scanner → Rules Engine → Violations → CLI Exit Code
                                                 ↓
                                            JSON Report
```

### Runtime Monitoring Path
```
Falco → Unix Socket → Monitor → Event Channel → Workers → Feature Extraction
                                                              ↓
                                                         AI Client (HTTP)
                                                              ↓
                                                         Python Service
                                                              ↓
                                                      Isolation Forest
                                                              ↓
                                                    Anomaly Score + Reason
                                                              ↓
                                          ┌───────────────────┴────────────┐
                                          ▼                                ▼
                                  [Low Risk]                        [High Risk]
                                   Continue                      Store in Vault
                                                                       ↓
                                                              Generate Report
```

## Performance Optimization

### Concurrency
- **Worker Pool**: Configurable number of goroutines
- **Buffered Channels**: Prevent blocking on event ingestion
- **Lock-Free Metrics**: Atomic operations for counters
- **Context Cancellation**: Graceful shutdown

### Memory Management
- **Bounded Buffers**: Prevent unbounded memory growth
- **Event Filtering**: Early filtering reduces processing load
- **Selective Retention**: Only store high-value forensics
- **Periodic Cleanup**: Remove old forensic records

### Network Optimization
- **Connection Pooling**: HTTP client reuse
- **Request Timeout**: Prevent hanging requests (10s)
- **Health Checks**: Verify AI service availability
- **Batch Processing**: Group similar events (future enhancement)

## Extensibility Points

### 1. Custom Rules
Add YAML files to `configs/rules/`:
```yaml
- id: CUSTOM-001
  name: My Custom Rule
  severity: high
  kind: [Deployment]
  checks:
    - path: spec.template.spec.containers[*].ports
      operator: contains
      value: 22
  remediation: Remove SSH port exposure
```

### 2. Custom Validators
Implement `Validator` interface:
```go
type Validator interface {
    Validate(resource K8sResource) []Violation
}
```

### 3. AI Model Swapping
Replace Isolation Forest with other models:
- One-Class SVM
- Autoencoders
- LSTM networks
- Custom ensembles

### 4. Storage Backends
Implement custom storage:
- S3 for forensics
- Elasticsearch for search
- PostgreSQL for structured queries

## Security Considerations

### Static Analysis
- **No Code Execution**: Pure parsing, no eval()
- **Input Validation**: YAML structure validation
- **Path Traversal**: Restricted to configured directories

### Runtime Monitoring
- **Unix Socket**: Local-only Falco communication
- **Permission Model**: Requires read access to Falco socket
- **Resource Limits**: Bounded memory and CPU usage

### AI Service
- **Network Isolation**: localhost by default
- **Input Sanitization**: Feature validation
- **Model Security**: Immutable model files
- **API Authentication**: (Future enhancement)

### Forensic Storage
- **File Permissions**: 0644 (read-only after write)
- **Directory Isolation**: Separate forensics directory
- **PII Handling**: Configurable data retention
- **Encryption at Rest**: (Future enhancement)

## Deployment Patterns

### 1. CI/CD Integration
```yaml
# GitLab CI example
security_scan:
  stage: test
  script:
    - go-cspm scan --path ./k8s --severity high
  allow_failure: false
```

### 2. Sidecar Pattern
```yaml
# Kubernetes deployment
containers:
- name: app
  image: myapp:latest
- name: cspm
  image: go-cspm:latest
  command: ["go-cspm", "monitor"]
  volumeMounts:
  - name: falco-socket
    mountPath: /var/run/falco
```

### 3. DaemonSet Pattern
Deploy on every node for cluster-wide monitoring.

## Future Enhancements

1. **gRPC for AI Communication**: Replace HTTP with gRPC for better performance
2. **Distributed Tracing**: OpenTelemetry integration
3. **Real-time Dashboard**: WebSocket-based UI
4. **Alert Integration**: Slack, PagerDuty, email
5. **Kubernetes Operator**: Custom CRDs for policy management
6. **Multi-cluster Support**: Federated monitoring
7. **Advanced ML**: Deep learning models for zero-day detection
