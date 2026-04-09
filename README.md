<div align="center">
  <img src="assets/kubesentinel_logo.svg" alt="KubeSentinel Logo" width="180" />
  <h1>KubeSentinel</h1>
  <p>
    Cloud Security Posture Management (CSPM) framework for Kubernetes that combines static manifest analysis, runtime security monitoring, AI-assisted anomaly detection, and forensic reporting.
  </p>
</div>

## Table of Contents

- [About](#about)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Build](#build)
  - [Run](#run)
  - [Test](#test)
- [Usage](#usage)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

## About

KubeSentinel is designed to improve Kubernetes security across the full lifecycle:

- **Shift-left checks** with static policy scanning of manifests
- **Runtime visibility** through Falco event ingestion and monitoring
- **Behavior analytics** with a Python ML service
- **Forensic readiness** via structured evidence retention and reports

## Features

- **Static Policy Engine**: Detects risky Kubernetes configurations before deployment
- **Runtime Monitor**: Streams and processes Falco security events
- **AI Behavioral Analyzer**: Flags anomalous behavior using Isolation Forest
- **Forensic Vault**: Stores incident evidence with retention, max-size pruning, and optional gzip compression
- **Report Generator**: Produces Markdown, JSON, and HTML investigation outputs
- **Gemini Enrichment (Optional)**: Adds runtime incident classification metadata and report narratives with redaction and deterministic fallback

## Tech Stack

- **Go 1.21+** for CLI and core services
- **Python 3.9+** for ML/anomaly detection
- **Kubernetes** (Minikube/Kind supported)
- **Falco** for runtime security events

## 👨‍💻 For Developers

- **[DEVELOPERS.md](DEVELOPERS.md)** - Quick start guide for contributors
- **[docs/REPOSITORY-STRUCTURE.md](docs/REPOSITORY-STRUCTURE.md)** - Repository organization and file placement
- **[docs/PROJECT-GUIDE.md](docs/PROJECT-GUIDE.md)** - Contribution guidelines

## Project Structure

```text
kubesentinel/
├── cmd/
│   └── kubesentinel/
│       └── main.go
├── internal/
├── pkg/
├── ai-module/
│   ├── server.py
│   ├── requirements.txt
│   └── models/
├── config/
├── deploy/
├── docs/
├── reports/
├── scripts/
│   ├── Makefile
│   ├── install.sh
│   └── install.ps1
├── tests/
├── go.mod
├── go.sum
└── requirements.txt
```

## Getting Started

### Prerequisites

- Go `1.21+`
- Python `3.9+`
- Docker
- Kubernetes (`minikube` or `kind`)
- Falco (for runtime monitoring scenarios)

### Installation

```bash
git clone <your-repo-url>
cd kubesentinel
```

Install dependencies:

```bash
make -C scripts deps
```

### Build

```bash
make -C scripts build
```

### Run

Static scan example:

```bash
./bin/kubesentinel scan --path ./deploy
```

Runtime monitor example:

```bash
./bin/kubesentinel monitor --namespace production --deployment api
```

### Test

```bash
make -C scripts test
```

## Usage

Common commands:

```bash
./bin/kubesentinel scan --path ./deploy
./bin/kubesentinel monitor --namespace production --deployment api --workers 4
./bin/kubesentinel report --from "2026-03-01" --to "2026-03-31" --format markdown,json
./bin/kubesentinel report --incident-id <record-id> --format html --no-llm
```

Config highlights:

```yaml
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

Use `GEMINI_API_KEY` as the canonical secret source (environment variable); keep `gemini.api_key` empty in committed config files.

## Documentation

Complete documentation is organized in the [docs/](docs/) directory:

### 🚀 Getting Started
- [Getting Started Guide](docs/getting-started.md) - Installation and first run
- [CSPM Quick Start](CSPM-QUICK-START.md) - Python CSPM module guide
- [Quick Reference](docs/quick-reference.md) - Command reference and examples

### 🏗️ Architecture & Design
- [Architecture](docs/architecture.md) - System design and components
- [Project Guide](docs/PROJECT-GUIDE.md) - Project structure and guidelines
- [Repository Structure](docs/REPOSITORY-STRUCTURE.md) - Directory organization and file placement

### ☸️ Deployment & Operations
- [Kubernetes Deployment](deploy/KUBERNETES-DEPLOYMENT.md) - K8s DaemonSet, RBAC, and production setup
- [Prometheus Metrics](docs/PROMETHEUS-METRICS.md) - Observability, metrics, and alerting
- [Docker Compose Setup](docker-compose.yml) - Local development stack

### 📚 Additional Resources
- [Testing Guide](TESTING.md) - Test strategies and running tests
- [Implementation Roadmap](docs/implementation-roadmap.md) - Planned features
- [Documentation Index](docs/README.md) - Complete documentation index with search table

## Roadmap

- [x] Static analysis engine
- [x] Runtime monitoring pipeline
- [x] Forensic report generation
- [ ] Threat-intelligence enrichment
- [ ] Dashboard and observability enhancements

## Contributing

Contributions are welcome. Open an issue for bugs/feature requests and submit a PR for improvements.

## License

This project is licensed under the [MIT License](LICENSE).
