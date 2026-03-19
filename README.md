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
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Build](#build)
  - [Run](#run)
  - [Test](#test)
- [Usage](#usage)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
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
- **Forensic Vault**: Stores and organizes incident evidence
- **Report Generator**: Produces investigation-friendly outputs

## Tech Stack

- **Go 1.21+** for CLI and core services
- **Python 3.9+** for ML/anomaly detection
- **Kubernetes** (Minikube/Kind supported)
- **Falco** for runtime security events

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
./bin/kubesentinel monitor --cluster minikube
```

### Test

```bash
make -C scripts test
```

## Usage

Common commands:

```bash
./bin/kubesentinel scan --path ./deploy
./bin/kubesentinel monitor --cluster minikube
./bin/kubesentinel report --from "2024-01-01" --to "2024-12-31"
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Project Guide](docs/PROJECT-GUIDE.md)
- [Quick Reference](docs/quick-reference.md)
- [Implementation Roadmap](docs/implementation-roadmap.md)

## Roadmap

- [x] Static analysis engine
- [x] Runtime monitoring pipeline
- [x] Forensic report generation
- [ ] Threat-intelligence enrichment
- [ ] Dashboard and observability enhancements

## Contributing

Contributions are welcome. Open an issue for bugs/feature requests and submit a PR for improvements.

## License

No license file is currently present in this repository. Add one (for example MIT/Apache-2.0) to define reuse terms.
