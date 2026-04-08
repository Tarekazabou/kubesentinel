# KubeSentinel Repository Structure

## Overview

This document defines the repository organization and provides guidance for navigating and contributing to KubeSentinel.

## Directory Structure

```
kubesentinel/
├── cmd/                          # Go CLI application entry points
│   └── kubesentinel/            # Main CLI package
│       └── main.go              # Entry point with commands: scan, monitor, report
│
├── internal/                     # Internal Go packages (not importable by external projects)
│   ├── ai/                      # AI/ML client integration
│   ├── forensics/               # Forensic data collection and vault management
│   ├── llm/                     # LLM (Gemini) client integration
│   ├── reporting/               # Report generation and enrichment
│   ├── runtime/                 # Runtime security monitoring (Falco integration)
│   └── rules/                   # Security rules engine
│
├── pkg/                          # Public packages (importable by external projects)
│   ├── rules/                   # Rules parsing and validation
│   ├── scanner/                 # Static manifest scanning engine
│   └── types/                   # Shared type definitions
│
├── ai-module/                    # Python AI/ML Service
│   ├── server.py                # Flask API server with anomaly detection
│   ├── dashboard/               # Web dashboard for AI insights
│   ├── models/                  # Pre-trained ML models
│   ├── tests/                   # Python unit tests
│   └── requirements.txt          # Python dependencies
│
├── cspm/                         # Python CSPM Scanning Module
│   ├── cli.py                   # Command-line interface
│   ├── manifest_scanner.py      # YAML manifest parser
│   ├── report_generator.py      # Report generation
│   └── __init__.py
│
├── deploy/                       # Kubernetes and Docker deployment manifests
│   ├── kubesentinel-daemonset.yaml          # K8s DaemonSet with RBAC
│   ├── kubesentinel-secrets-template.yaml   # K8s Secrets template
│   ├── secure-pod.yaml          # Example secure pod template
│   ├── insecure-pod.yaml        # Example insecure pod (for testing)
│   ├── test/                    # Test deployment manifests
│   ├── KUBERNETES-DEPLOYMENT.md # K8s deployment guide
│   └── docker-compose.yml       # Docker Compose setup
│
├── config/                       # Configuration templates and rules
│   ├── config.yaml              # Main application configuration
│   └── rules/                   # Security scanning rules
│       ├── build-in-rules.yaml  # Default scanning rules
│       └── custom-rules.yaml    # User-defined rules
│
├── docs/                         # Project documentation
│   ├── README.md                # Documentation index
│   ├── architecture.md          # System architecture and design
│   ├── getting-started.md       # Quick start guide
│   ├── implementation-roadmap.md # Feature roadmap
│   ├── quick-reference.md       # Quick command reference
│   ├── PROJECT-GUIDE.md         # Project structure and contribution guide
│   └── PROMETHEUS-METRICS.md    # Prometheus metrics documentation
│
├── scripts/                      # Build, setup, and utility scripts
│   ├── install.sh              # Linux/macOS installation
│   ├── install.ps1             # Windows PowerShell installation
│   ├── install-prereqs.sh       # Install prerequisite tools
│   ├── Makefile                 # Build automation
│   └── kubesentinel.code-workspace # VS Code workspace config
│
├── tests/                        # Go test files and integration tests
│   └── cspm/                    # CSPM-specific tests
│
├── frontend/                     # Web UI (optional, future)
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── forensics/                    # Runtime forensics data storage
│   └── *.json                   # Forensic incident records
│
├── reports/                      # Generated security reports
│   └── report_*.{json,md,html}  # Output reports
│
├── assets/                       # Images and branding
│   └── kubesentinel_logo.svg
│
├── models/                       # Machine learning models storage
│   └── baseline.pkl             # Pre-trained anomaly detection model
│
├── .venv/                        # Python virtual environment (development only)
│
├── .vscode/                      # VS Code workspace settings
│
├── go.mod                        # Go module definition
├── go.sum                        # Go dependency checksums
│
├── requirements.txt              # Python dependencies (root level)
│
├── dockerfile                    # Docker image for Go binary
├── dockerfile.ai                 # Docker image for Python AI module
│
├── docker-compose.yml            # Local development stack
│
├── .gitignore                    # Git ignore rules (includes .env)
├── .dockerignore                 # Docker build ignore rules
│
├── TESTING.md                    # Testing guide and strategies
├── CSPM-QUICK-START.md          # Quick start for CSPM module
│
└── README.md                     # Main project README

```

## Key Directories Explained

### Core Go Application

- **`cmd/`** - Command-line application entry points
  - Defines CLI commands: `scan`, `monitor`, `report`
  - Routes to internal packages
  
- **`internal/`** - Private implementation packages
  - `runtime/` - Integrates with Falco for runtime monitoring
  - `forensics/` - Stores and manages security events
  - `reporting/` - Generates forensic reports with optional LLM enrichment
  - `ai/` - Client for remote ML service
  - `llm/` - Gemini API integration for intelligent analysis

- **`pkg/`** - Reusable, public packages
  - `scanner/` - Core manifest scanning engine
  - `rules/` - Rule parsing and evaluation

### Python Modules

- **`ai-module/`** - Flask-based ML service
  - Runs on port 5000
  - Exposes `/predict` (anomaly detection), `/train` (model update)
  - Protected endpoints via Bearer token authentication
  - Includes Prometheus `/metrics` endpoint

- **`cspm/`** - Static manifest scanning
  - Parses Kubernetes YAML files
  - Evaluates against security rules
  - Generates reports in multiple formats

### Infrastructure & Deployment

- **`deploy/`** - Kubernetes and container orchestration
  - DaemonSet for runtime monitoring on all nodes
  - RBAC manifests (ServiceAccount, ClusterRole, ClusterRoleBinding)
  - Docker Compose for local development
  - K8s deployment guides

- **`config/`** - Configuration and rules
  - `config.yaml` - Main application settings
  - Security scanning rules (built-in and custom)

### Documentation & Scripts

- **`docs/`** - Comprehensive documentation
  - Architecture and design decisions
  - User guides and quick starts
  - Metrics and monitoring setup
  - Roadmap and contribution guidelines

- **`scripts/`** - Build and deployment automation
  - Installation scripts for different platforms
  - Makefile for development tasks
  - VS Code workspace configuration

## File Placement Guidelines

### Adding a New Feature

1. **Go code for scanning**: `pkg/scanner/` or `pkg/rules/`
2. **Go code for runtime**: `internal/runtime/`
3. **Go code for reporting**: `internal/reporting/`
4. **Python AI features**: `ai-module/` (in `server.py` or new module)
5. **Python CSPM features**: `cspm/` (new file or existing module)
6. **Documentation**: `docs/` with appropriate filename
7. **Tests**: `tests/` (Go) or `ai-module/tests/` (Python)
8. **CLI commands**: Extend `cmd/kubesentinel/main.go`

### Adding Configuration

- Default config template: `config/config.yaml`
- Security rules: `config/rules/`
- Secrets template: `deploy/kubesentinel-secrets-template.yaml`
- Environment variables: Root `.env` file (git-ignored)

### Adding Deployment

- Kubernetes manifests: `deploy/kubesentinel-*.yaml`
- Docker configuration: `dockerfile` or `dockerfile.ai`
- Docker Compose: `docker-compose.yml`

## Development Workflow

### Setup

```bash
# Clone and navigate
git clone <repo>
cd kubesentinel

# Install Go dependencies
go mod download

# Install Python dependencies (for AI module)
cd ai-module
pip install -r requirements.txt
cd ..

# Or use docker-compose
docker-compose up
```

### Building

```bash
# Build CLI binary (outputs to ./bin/)
make build

# Build Docker images
docker build -f dockerfile -t kubesentinel:latest .
docker build -f dockerfile.ai -t kubesentinel-ai:latest .

# Or use make target
make docker-build
```

### Testing

```bash
# Run Go tests
go test ./...

# Run Python tests
cd ai-module && python -m pytest tests/
```

### Running

```bash
# Scan manifests
./bin/kubesentinel scan --path ./deploy

# Monitor runtime events
./bin/kubesentinel monitor --ai-endpoint http://localhost:5000

# Generate reports
./bin/kubesentinel report --from "2024-01-01" --to "2024-01-31"
```

## Important Notes

### Git Ignored Files

The following are intentionally ignored:
- `.env` - Local environment variables (copy from template)
- `.venv/` - Python virtual environment
- `forensics/*.json` - Runtime incident data
- `reports/*.{md,html,json}` - Generated reports
- `models/baseline.pkl` - ML model artifacts
- `bin/kubesentinel` - Built binaries

### Configuration Management

- **Development**: Use `config.yaml` in root (template provided)
- **Kubernetes**: Use ConfigMap + Secrets
- **Environment**: Use `.env` file (git-ignored)
- **Secrets**: Never commit API keys; use `kubesentinel-secrets-template.yaml`

### Documentation

All documentation should be in `docs/` and follow:
- `README.md` - Index and overview
- `*-guide.md` - Step-by-step guides
- `*.md` - Feature documentation

Update `docs/README.md` when adding new documentation.

## Contributing

When contributing to KubeSentinel:

1. Follow the directory structure above
2. Add tests for new features
3. Update `docs/` if adding user-facing features
4. Update `README.md` in `docs/` for documentation index
5. Ensure security rules are in `config/rules/`
6. Add CLI commands in `cmd/kubesentinel/main.go`
7. Keep Go code in `internal/` (private) unless it's a public API in `pkg/`

## Future Improvements

- Organized frontend framework setup in `frontend/`
- Centralized logging configuration
- Plugin system for custom rules and analyzers
- Multi-module workspace setup
