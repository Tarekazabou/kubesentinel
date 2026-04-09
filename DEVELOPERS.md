# Developer's Quick Start Guide

Welcome to KubeSentinel! This guide will help you quickly navigate and contribute to the project.

## 📂 Where Do I Find...?

### I Need to...

| Task | Location | Quick Reference |
|------|----------|-----------------|
| **Understand the overall system** | [docs/architecture.md](docs/architecture.md) | System design and component interactions |
| **Get started developing** | [docs/getting-started.md](docs/getting-started.md) | Installation and setup guide |
| **Find a specific command** | [docs/quick-reference.md](docs/quick-reference.md) | Command reference and examples |
| **Understand the repo structure** | [docs/REPOSITORY-STRUCTURE.md](docs/REPOSITORY-STRUCTURE.md) | Directory organization guide |
| **Deploy to Kubernetes** | [deploy/KUBERNETES-DEPLOYMENT.md](deploy/KUBERNETES-DEPLOYMENT.md) | K8s manifests and deployment guide |
| **Setup monitoring** | [docs/PROMETHEUS-METRICS.md](docs/PROMETHEUS-METRICS.md) | Prometheus and Grafana setup |
| **Write tests** | [TESTING.md](TESTING.md) | Test strategies and examples |
| **View the roadmap** | [docs/implementation-roadmap.md](docs/implementation-roadmap.md) | Planned features |
| **Contribute code** | [docs/PROJECT-GUIDE.md](docs/PROJECT-GUIDE.md) | Contribution guidelines |

## 🏗️ Core Modules at a Glance

### Go Application (`cmd/` & `internal/`)

```
cmd/kubesentinel/main.go           → CLI entry point
├── scan command                    → Static manifest scanning
├── monitor command                 → Runtime event monitoring  
└── report command                  → Forensic report generation

internal/
├── runtime/                        → Falco event processing
├── forensics/                      → Evidence vault storage
├── reporting/                      → Report generation & LLM enrichment
├── ai/                             → ML service client
└── llm/                            → Gemini API integration
```

### Python Modules

```
ai-module/
├── server.py                       → Flask API server
├── models/baseline.pkl             → ML model (Isolation Forest)
└── tests/                          → Python unit tests

cspm/
├── cli.py                          → CSPM CLI interface
├── manifest_scanner.py             → YAML parsing
└── report_generator.py             → Report formatting
```

## 🚀 Quick Development Setup

```bash
# Clone and navigate
git clone <repo>
cd kubesentinel

# Install Go dependencies
go mod download

# Install Python dependencies (for AI module)
cd ai-module && pip install -r requirements.txt && cd ..

# Build
make -C scripts build

# Run tests
make -C scripts test

# Start development environment
docker-compose up
```

## 📝 Adding a New Feature

### If It's a Go Command/Feature

1. Add logic to `internal/` (private packages)
2. If it's reusable, add to `pkg/` (public packages)
3. Wire it up in `cmd/kubesentinel/main.go`
4. Add tests to `tests/`
5. Document in `docs/`

Example: Adding a new scanning rule
- Code: `pkg/scanner/rules/` → implementation
- CLI: `cmd/kubesentinel/main.go` → expose the rule
- Docs: `docs/` → explain the function

### If It's a Python Feature

1. Add to `ai-module/server.py` (new endpoint)
2. Or add to `cspm/` (scanning logic)
3. Add tests to `ai-module/tests/`
4. Document in `docs/`

Example: Adding a new ML model
- Code: `ai-module/server.py` → load new model
- Docs: `docs/PROMETHEUS-METRICS.md` → update if metrics change

### If It's Infrastructure/Deployment

1. Add manifests to `deploy/`
2. Update `deploy/KUBERNETES-DEPLOYMENT.md`
3. Test with docker-compose or K8s

## 🔍 Understanding the Codebase

### Key Files to Know

| File | Purpose |
|------|---------|
| `cmd/kubesentinel/main.go` | CLI definition and command routing |
| `internal/runtime/monitor.go` | Falco event listener and processor |
| `internal/forensics/vault.go` | Evidence storage and management |
| `internal/reporting/generator.go` | Report creation and formatting |
| `ai-module/server.py` | ML anomaly detection service |
| `pkg/scanner/scanner.go` | Static manifest scanning engine |
| `config.yaml` | Configuration template |
| `deploy/kubesentinel-daemonset.yaml` | K8s DaemonSet with RBAC |

### Code Navigation Tips

1. **Start with the CLI**: Look at `cmd/kubesentinel/main.go` to understand how commands are structured
2. **Follow the flow**: Trace a command (e.g., `scan`) from CLI through internal packages
3. **Check the types**: Look in `pkg/types/` or individual package files for data structures
4. **Read the tests**: Tests often show usage examples better than docs
5. **Check package main.go**: Look for `func init()` to understand package setup

## 📊 Metrics and Monitoring

KubeSentinel exposes Prometheus metrics on `/metrics` (port 8080 by default):

```bash
# View metrics endpoint while running
curl http://localhost:8080/metrics

# Useful metrics:
# - kubesentinel_falco_events_total: Events processed by severity
# - kubesentinel_anomalies_detected_total: Anomalies by severity/type
# - kubesentinel_event_process_duration_seconds: Latency histogram
```

See [docs/PROMETHEUS-METRICS.md](docs/PROMETHEUS-METRICS.md) for complete reference.

## 🧪 Testing

```bash
# Run all Go tests
go test ./...

# Run specific test
go test ./internal/runtime -v

# Run Python tests
cd ai-module && python -m pytest tests/ -v

# Run with coverage
go test -cover ./...

# Benchmark
go test -bench=. ./...
```

## 🔐 Security Practices

- Never commit secrets (use `.env` files, git-ignored)
- API keys are loaded from environment variables
- Training endpoint (`/train`) requires Bearer token authentication
- Prediction endpoint requires Bearer token authentication

See [deploy/KUBERNETES-DEPLOYMENT.md](deploy/KUBERNETES-DEPLOYMENT.md) for security setup.

## 🛠️ Common Development Tasks

### Build the CLI

```bash
make -C scripts build
# Output: ./bin/kubesentinel
```

### Run the Development Stack

```bash
docker-compose up
# Starts: Go app, Python AI service, Falco (if configured)
```

### Test a Scanning Rule

```bash
./bin/kubesentinel scan --path ./deploy/test --rules ./config/rules
```

### Monitor with Custom Config

```bash
./bin/kubesentinel monitor --config ./my-config.yaml --metrics-port 8080
```

### Generate a Report

```bash
./bin/kubesentinel report --from "2026-03-01" --to "2026-03-31" --format markdown
```

## 📚 Documentation Structure

All documentation lives in `docs/`:

```
docs/
├── README.md                      → Documentation index
├── REPOSITORY-STRUCTURE.md        → Directory guide (READ THIS FIRST!)
├── architecture.md                → System design
├── getting-started.md             → Installation guide
├── quick-reference.md             → Command reference
├── PROJECT-GUIDE.md               → Contribution guidelines
├── implementation-roadmap.md      → Roadmap
└── PROMETHEUS-METRICS.md          → Metrics and monitoring
```

## 🤝 Getting Help

1. Check [docs/README.md](docs/README.md) for documentation index
2. Search the code using your IDE's symbol search
3. Look at tests for usage examples
4. Check [docs/quick-reference.md](docs/quick-reference.md) for common patterns
5. Open an issue if you're stuck

## 🔧 IDE Setup

### VS Code

1. Open `scripts/kubesentinel.code-workspace`
2. Install recommended extensions (Go, Python)
3. Settings are automatically loaded

### GoLand / IntelliJ

1. Open project as Go module
2. Dependencies will auto-download
3. Tests can be run directly from IDE

## 📋 Before Submitting a PR

- [ ] Code follows project conventions
- [ ] Tests pass locally
- [ ] Documentation is updated
- [ ] No secrets in commits (use `.env`)
- [ ] Commit messages are clear
- [ ] Changes are focused (one feature per PR)

## 🐛 Debugging

### Go Application

```bash
# Run with debug logging
KUBESENTINEL_DEBUG=1 ./bin/kubesentinel monitor

# Run with specific log level
KUBESENTINEL_LOG_LEVEL=debug ./bin/kubesentinel scan --path ./deploy
```

### Python Service

```bash
# Run Flask in debug mode
cd ai-module && FLASK_DEBUG=1 python server.py

# Check internal logs
tail -f /tmp/kubesentinel-*.log
```

### Kubernetes

```bash
# View pod logs
kubectl logs -n kubesentinel -l app=kubesentinel -f

# View metrics
kubectl exec -n kubesentinel <pod-name> -- curl localhost:8080/metrics

# Debug pod
kubectl debug pod/<pod-name> -n kubesentinel -it --image=busybox
```

---

**Happy coding!** 🚀

For detailed guides, see the [documentation index](docs/README.md).
