# KubeSentinel: Cloud Security Posture Management Framework

A high-performance security orchestration system that bridges static configuration security and dynamic runtime behavior monitoring for Kubernetes environments.

## 📂 Project Structure

```
kubesentinel/
├── cmd/                           # Application entry points
│   ├── main.go                   # Go CLI application entry point
│   └── server.py                 # Python server entry point
├── pkg/                          # Reusable Go packages
│   ├── client.go                 # Kubernetes client
│   ├── scanner.go                # YAML manifest scanner
│   ├── rules.go                  # Security rules engine
│   ├── monitor.go                # Runtime monitoring
│   ├── processor.go              # Event processing
│   ├── vault.go                  # Forensic vault storage
│   └── generator.go              # Report generation
├── config/                       # Configuration files
│   ├── config.yaml               # Main configuration
│   └── custom-rules.yaml         # Custom security rules
├── deploy/                       # Kubernetes deployment manifests
│   ├── insecure-pod.yaml        # Example insecure pod
│   └── secure-pod.yaml          # Example secure pod
├── docs/                         # Documentation
│   ├── README.md                # Project overview
│   ├── architecture.md          # System architecture
│   ├── getting-started.md       # Quick start guide
│   ├── implementation-roadmap.md # Development roadmap
│   ├── PROJECT-GUIDE.md         # Project guide
│   └── quick-reference.md       # Quick reference
├── scripts/                      # Build and utility scripts
│   ├── Makefile                 # Build configurations
│   └── requirements.txt         # Python dependencies
├── go.mod                        # Go module dependencies
└── .qodo                         # QoDo configuration (if applicable)
```

## 🎯 Directory Overview

| Directory | Purpose |
|-----------|---------|
| **cmd/** | Entry points for the application (main executables) |
| **pkg/** | Core reusable Go packages and business logic |
| **config/** | Configuration files for the application |
| **deploy/** | Kubernetes YAML manifests for deployment |
| **docs/** | Comprehensive documentation |
| **scripts/** | Build scripts and utilities |

## 🚀 Getting Started

See [docs/getting-started.md](docs/getting-started.md) for detailed setup instructions.

For architecture details, refer to [docs/architecture.md](docs/architecture.md).

## 📋 Key Components

1. **Static Policy Engine** - Pre-deployment manifest scanning
2. **Live Stream Monitor** - Runtime event processing via Falco
3. **AI Behavioral Analyzer** - ML-based anomaly detection
4. **Smart Forensic Vault** - Policy-aware log retention
5. **Automated Investigator** - Human-readable forensic reporting

## 🔧 Building & Running

See [scripts/Makefile](scripts/Makefile) for available build targets.
Python dependencies are listed in [scripts/requirements.txt](scripts/requirements.txt).

## 📚 Documentation

- [Architecture Deep Dive](docs/architecture.md)
- [Getting Started](docs/getting-started.md)
- [Implementation Roadmap](docs/implementation-roadmap.md)
- [Project Guide](docs/PROJECT-GUIDE.md)
- [Quick Reference](docs/quick-reference.md)
