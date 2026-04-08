# KubeSentinel: Cloud Security Posture Management Framework

A high-performance security orchestration system that bridges static configuration security and dynamic runtime behavior monitoring for Kubernetes environments.

## 🎯 Project Overview

KubeSentinel is a comprehensive security framework that operates across five critical layers:

1. **Static Policy Engine** - Pre-deployment manifest scanning
2. **Live Stream Monitor** - Runtime event processing via Falco
3. **AI Behavioral Analyzer** - ML-based anomaly detection
4. **Smart Forensic Vault** - Policy-aware log retention
5. **Automated Investigator** - Human-readable forensic reporting

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      KubeSentinel CLI                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐         ┌──────────────────────────┐      │
│  │ Static       │         │ Runtime Monitor          │      │
│  │ Analysis     │─────────│ (Falco Integration)      │      │
│  │ Engine       │         │                          │      │
│  └──────────────┘         └──────────┬───────────────┘      │
│                                      │                      │
│                           ┌──────────▼──────────┐           │
│                           │ Feature Extraction  │           │
│                           │ (Goroutines)        │           │
│                           └──────────┬──────────┘           │
│                                      │                      │
│                           ┌──────────▼──────────┐           │
│                           │ AI Anomaly          │           │
│                           │ Detection (gRPC)    │           │
│                           └──────────┬──────────┘           │
│                                      │                      │
│                    ┌─────────────────┴─────────────────┐    │
│                    │                                   │    │
│         ┌──────────▼──────────┐         ┌────────────▼───┐  │
│         │ Forensic Vault      │         │ Report         │  │
│         │ (Selective Storage) │         │ Generator      │  │
│         └─────────────────────┘         └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- Go 1.21+
- Docker & Kubernetes (Minikube/Kind)
- Falco (for runtime monitoring)
- Python 3.9+ (for AI module)
- Make

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/kubesentinel.git
cd kubesentinel

# Install dependencies
make -C scripts deps

# Build the binary
make -C scripts build

# Run static analysis on manifests
./bin/kubesentinel scan --path ./deploy

# Start runtime monitoring
./bin/kubesentinel monitor --namespace production --deployment api

# Generate forensic report
./bin/kubesentinel report --from "2026-03-01" --to "2026-03-31" --format markdown,json
```

## 📁 Project Structure

```
kubesentinel/
├── cmd/
│   └── kubesentinel/     # CLI entry point
│       └── main.go
├── internal/
│   ├── static/           # Static analysis engine
│   │   ├── scanner.go
│   │   ├── rules.go
│   │   └── validators/
│   ├── runtime/          # Runtime monitoring
│   │   ├── falco.go
│   │   ├── events.go
│   │   └── processor.go
│   ├── ai/               # AI integration layer
│   │   ├── client.go
│   │   ├── features.go
│   │   └── grpc/
│   ├── forensics/        # Forensic retention
│   │   ├── vault.go
│   │   ├── storage.go
│   │   └── policies.go
│   └── reporting/        # Report generation
│       ├── generator.go
│       ├── templates.go
│       └── formats/
├── pkg/
│   ├── models/           # Shared data models
│   ├── utils/            # Common utilities
│   └── config/           # Configuration management
├── ai-module/            # Python AI/ML module
│   ├── server.py
│   ├── model.py
│   └── requirements.txt
├── config/               # Configuration files
│   ├── rules/            # Static analysis rules
│   └── config.yaml       # Main configuration file
├── deploy/               # Deployment manifests (e.g. k8s)
├── scripts/              # Build and deployment scripts
│   └── Makefile
└── README.md
```

## 🔧 Configuration

Create a `config.yaml` file:

```yaml
static:
  rules_path: "./config/rules"
  severity_threshold: "medium"
  
runtime:
  falco_socket: "unix:///var/run/falco/falco.sock"
  buffer_size: 10000
  workers: 4

ai:
  endpoint: "http://localhost:5000"
  model_path: "./ai-module/models/baseline.pkl"
  threshold: 0.75

forensics:
  storage_path: "./forensics"
  retention_days: 90
  max_size_mb: 1000
  compression: true

reporting:
  formats: ["json", "markdown", "html"]
  output_path: "./reports"

gemini:
  enabled: false
  classify_runtime: false
  api_key: ""
  model: "gemini-2.5-flash"
  timeout_seconds: 15
```

## 🎮 Usage Examples

### 1. Static Analysis in CI/CD

```bash
# Scan Kubernetes manifests
kubesentinel scan --path ./k8s-manifests --format json

# Scan with custom rules
kubesentinel scan --path ./deployments --rules ./custom-rules.yaml

# Exit code 0: No violations
# Exit code 1: Violations found
```

### 2. Runtime Monitoring

```bash
# Monitor with default settings
kubesentinel monitor

# Monitor with custom config
kubesentinel monitor --config ./my-config.yaml --namespace production

# Monitor specific workload
kubesentinel monitor --deployment my-app

# Monitor Falco stream from stdin pipeline
kubectl logs -n falco -l app=falco -f | kubesentinel monitor-stdin --namespace production
```

### 3. Generate Forensic Report

```bash
# Generate report for specific incident
kubesentinel report --incident-id abc123 --format markdown

# Generate comprehensive timeline
kubesentinel report --from "2026-03-01" --to "2026-03-31" --format markdown,json

# Deterministic report only (disable LLM)
kubesentinel report --from "2026-03-01" --to "2026-03-31" --no-llm
```

## 🔍 Key Features

### Static Analysis Rules

The engine checks for:
- Privileged containers
- Missing resource limits
- Insecure network policies
- Exposed secrets
- Non-root user enforcement
- Read-only root filesystems
- AppArmor/SELinux configurations

### Runtime Detection

Monitors for:
- Suspicious system calls
- Unauthorized file access
- Network anomalies
- Process execution patterns
- Container escape attempts

### AI Anomaly Detection

Uses behavioral analysis to detect:
- Deviation from normal patterns
- Zero-day exploits
- Advanced persistent threats
- Insider threats

### Forensic Vault

- Retains incident records with policy-aware filtering
- Enforces max vault size by pruning oldest low-value records first
- Supports optional compressed storage (`.json.gz`)

### Optional Gemini Enrichment

- Classifies runtime anomalies into incident categories and stores confidence/reason metadata in forensic records
- Adds narrative and findings to generated reports
- Appends AI-assisted remediation recommendations
- Redacts sensitive fields before external API calls
- Falls back to deterministic report generation on API failure

## 🧪 Testing

```bash
# Run all tests
make -C scripts test

# Run with coverage
make -C scripts test-coverage

# Run integration tests
make -C scripts test-integration

# Benchmark performance
make benchmark
```

## 📊 Performance Metrics

- **Static Analysis**: ~1000 manifests/second
- **Runtime Processing**: ~50,000 events/second
- **Memory Footprint**: ~50MB baseline
- **Latency**: <10ms event processing

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📝 License

MIT License - see [LICENSE](LICENSE)

## � Complete Documentation Index

### Getting Started

- [**getting-started.md**](getting-started.md) - Step-by-step installation and first run guide for all platforms
- [**CSPM-QUICK-START.md**](../CSPM-QUICK-START.md) - Quick start for the Python CSPM scanning module
- [**quick-reference.md**](quick-reference.md) - Command reference and common usage patterns

### Core Documentation

- [**PROJECT-GUIDE.md**](PROJECT-GUIDE.md) - Project overview and contribution guidelines
- [**architecture.md**](architecture.md) - System architecture, design patterns, and component interactions
- [**implementation-roadmap.md**](implementation-roadmap.md) - Feature roadmap and planned enhancements
- [**REPOSITORY-STRUCTURE.md**](REPOSITORY-STRUCTURE.md) - Repository organization and file placement guidelines

### Deployment & Operations

- [**KUBERNETES-DEPLOYMENT.md**](../deploy/KUBERNETES-DEPLOYMENT.md) - Complete Kubernetes deployment guide with RBAC
  - DaemonSet configuration
  - Security best practices
  - Troubleshooting guide
  - Production recommendations

- [**PROMETHEUS-METRICS.md**](PROMETHEUS-METRICS.md) - Prometheus metrics and observability
  - Available metrics reference
  - Prometheus configuration examples
  - Grafana dashboard setup
  - Alert rules

### Configuration

- [**config.yaml**](../config/config.yaml) - Main application configuration template
- [**kubesentinel-daemonset.yaml**](../deploy/kubesentinel-daemonset.yaml) - Kubernetes DaemonSet with full RBAC
- [**kubesentinel-secrets-template.yaml**](../deploy/kubesentinel-secrets-template.yaml) - Kubernetes Secrets template

### API & Integration

- **AI Module API** - See `ai-module/server.py` for:
  - `/predict` - Anomaly detection endpoint (Bearer token protected)
  - `/train` - Model training endpoint (Bearer token protected)
  - `/api/incidents` - Forensics data retrieval (Bearer token protected)
  - `/metrics` - Prometheus metrics
  
- **Go Packages** - See `pkg/` and `internal/` for detailed package documentation

### Testing & Quality

- [**TESTING.md**](../TESTING.md) - Testing strategies, unit tests, and integration tests

### Quick Navigation

| Task | Documentation |
|------|-----------------|
| **I want to...** |  |
| Get started quickly | [getting-started.md](getting-started.md) |
| Understand the architecture | [architecture.md](architecture.md) |
| Deploy to Kubernetes | [KUBERNETES-DEPLOYMENT.md](../deploy/KUBERNETES-DEPLOYMENT.md) |
| Setup monitoring/metrics | [PROMETHEUS-METRICS.md](PROMETHEUS-METRICS.md) |
| Find commands | [quick-reference.md](quick-reference.md) |
| Navigate the codebase | [REPOSITORY-STRUCTURE.md](REPOSITORY-STRUCTURE.md) |
| Contribute code | [PROJECT-GUIDE.md](PROJECT-GUIDE.md) |
| Use CSPM module | [CSPM-QUICK-START.md](../CSPM-QUICK-START.md) |
| Run tests | [TESTING.md](../TESTING.md) |
| See the roadmap | [implementation-roadmap.md](implementation-roadmap.md) |

## 🔗 Resources

- [Full Documentation Index](#-complete-documentation-index)
- [Architecture Deep Dive](architecture.md)
- [Kubernetes Deployment Guide](../deploy/KUBERNETES-DEPLOYMENT.md)
- [Prometheus Metrics Guide](PROMETHEUS-METRICS.md)
