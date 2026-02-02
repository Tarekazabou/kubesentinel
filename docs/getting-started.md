# Getting Started with KubeSentinel

This guide will walk you through setting up and using KubeSentinel for securing your Kubernetes workloads.

## Prerequisites

Before you begin, ensure you have:

- **Go 1.21 or later**: [Download Go](https://golang.org/dl/)
- **Python 3.9+**: [Download Python](https://www.python.org/downloads/)
- **Docker**: [Install Docker](https://docs.docker.com/get-docker/)
- **Kubernetes cluster**: Minikube, Kind, or any K8s cluster
- **Falco**: [Install Falco](https://falco.org/docs/getting-started/installation/)

## Quick Start (5 minutes)

### 1. Clone and Build

```bash
# Clone the repository
git clone https://github.com/yourusername/kubesentinel.git
cd kubesentinel

# Set up development environment
make setup-dev

# Install dependencies
make deps

# Build the binary
make build

# The binary is now available at ./bin/kubesentinel
```

### 2. Run Your First Scan

```bash
# Scan example manifests
./bin/kubesentinel scan --path ./examples/k8s-manifests

# Expected output:
# Scanning manifests at: ./examples/k8s-manifests
# Found violations in example.yaml:
# - [HIGH] Container missing resource limits
# - [MEDIUM] Container may run as root user
# Scan complete: 2 violations found
```

### 3. Start the AI Service

```bash
# In a new terminal
make run-ai

# Expected output:
# Starting AI/ML service on port 5000
# Model loaded from models/baseline.pkl
```

### 4. Start Runtime Monitoring

```bash
# In another terminal (requires Falco)
./bin/kubesentinel monitor --cluster minikube

# Expected output:
# Starting runtime monitor...
# Connected to Falco, consuming events...
# Worker 0 started
# Worker 1 started
# Worker 2 started
# Worker 3 started
```

## Detailed Setup

### Installing Falco

Falco is required for runtime monitoring.

**On Ubuntu/Debian:**
```bash
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update
apt-get install -y falco
```

**On macOS (using Minikube):**
```bash
minikube start --driver=virtualbox
minikube ssh
# Inside minikube VM:
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update
apt-get install -y falco
```

**Verify Falco:**
```bash
# Check if Falco is running
systemctl status falco

# Check socket
ls -la /var/run/falco/falco.sock
```

### Configuring KubeSentinel

Edit `config.yaml` to customize settings:

```yaml
static:
  rules_path: "./configs/rules"
  severity_threshold: "medium"  # low, medium, high, critical

runtime:
  falco_socket: "unix:///var/run/falco/falco.sock"
  buffer_size: 10000
  workers: 4
  namespace: ""       # Monitor specific namespace (empty = all)
  deployment: ""      # Monitor specific deployment (empty = all)

ai:
  endpoint: "http://localhost:5000"
  threshold: 0.75     # Anomaly detection threshold

forensics:
  storage_path: "./forensics"
  retention_days: 90
  max_size_mb: 1000

reporting:
  formats: ["json", "markdown"]
  output_path: "./reports"
```

## Usage Examples

### Static Analysis in CI/CD

**GitLab CI:**
```yaml
stages:
  - security

security_scan:
  stage: security
  image: golang:1.21
  before_script:
    - make deps
    - make build
  script:
    - ./bin/kubesentinel scan --path ./manifests --severity high --format json
  artifacts:
    reports:
      codequality: scan-results.json
  allow_failure: false  # Block pipeline on violations
```

**GitHub Actions:**
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  cspm-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Go
        uses: actions/setup-go@v2
        with:
          go-version: 1.21
      
      - name: Build KubeSentinel
        run: |
          make deps
          make build
      
      - name: Run Security Scan
        run: |
          ./bin/kubesentinel scan --path ./k8s-manifests
```

### Runtime Monitoring

**Monitor Specific Namespace:**
```bash
./bin/kubesentinel monitor --namespace production
```

**Monitor Specific Deployment:**
```bash
./bin/kubesentinel monitor --deployment api-server
```

**Custom Configuration:**
```bash
./bin/kubesentinel monitor --config ./custom-config.yaml
```

### Generating Reports

**Generate Report for Time Range:**
```bash
./bin/kubesentinel report \
  --from "2024-01-01" \
  --to "2024-01-31" \
  --format markdown \
  --output ./reports
```

**Generate Report for Specific Incident:**
```bash
./bin/kubesentinel report \
  --incident-id abc123 \
  --format json
```

## Creating Custom Rules

Create a new file in `configs/rules/custom-rules.yaml`:

```yaml
- id: CUSTOM-001
  name: Detect Exposed SSH Ports
  description: Container exposes SSH port 22 which should be avoided
  severity: high
  kind: [Pod, Deployment]
  checks:
    - path: spec.containers[*].ports[*].containerPort
      operator: equals
      value: 22
  remediation: Remove SSH port exposure or use alternative secure access method

- id: CUSTOM-002
  name: Require Resource Quotas
  description: Deployment should specify resource quotas
  severity: medium
  kind: [Deployment]
  checks:
    - path: spec.template.spec.containers[*].resources.requests
      operator: notExists
      value: null
  remediation: Add resources.requests.cpu and resources.requests.memory

- id: CUSTOM-003
  name: Disallow Latest Tag
  description: Using 'latest' tag is not recommended for production
  severity: medium
  kind: [Pod, Deployment]
  checks:
    - path: spec.containers[*].image
      operator: contains
      value: ":latest"
  remediation: Use specific image tags instead of 'latest'
```

## Understanding Severity Levels

KubeSentinel uses four severity levels:

- **CRITICAL**: Immediate security risk (e.g., privileged containers)
- **HIGH**: Significant security concern (e.g., missing resource limits)
- **MEDIUM**: Security best practice violation (e.g., root user)
- **LOW**: Informational or minor concern (e.g., missing labels)

## Working with AI Anomaly Detection

### Training the Model

The AI model learns from your "normal" behavior. To train:

1. **Collect baseline data** (7-14 days of normal operation)
2. **Extract features** from security events
3. **Train the model**:

```bash
# The model automatically updates during runtime
# or manually train with historical data:
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d @training-data.json
```

### Adjusting Sensitivity

Edit `config.yaml`:

```yaml
ai:
  threshold: 0.75  # Lower = more sensitive (more anomalies detected)
                   # Higher = less sensitive (fewer false positives)
```

Recommended thresholds:
- **Development**: 0.85 (fewer alerts)
- **Staging**: 0.75 (balanced)
- **Production**: 0.65 (maximum security)

## Forensic Investigation

### Viewing Stored Records

```bash
# List all forensic records
ls -lh ./forensics/

# View a specific record
cat ./forensics/20240215_143022_1234567890.json | jq .
```

### Understanding Forensic Data

Each record contains:
- **Incident metadata**: ID, severity, risk score
- **Container context**: Name, image, namespace
- **Security events**: What triggered the alert
- **System calls**: Low-level process activity
- **Network traces**: Connection details
- **File operations**: Filesystem access patterns

### Retention Management

```bash
# Manually cleanup old records
find ./forensics -name "*.json" -mtime +90 -delete

# Or let KubeSentinel handle it automatically
# (configured via retention_days in config.yaml)
```

## Troubleshooting

### Problem: "Failed to connect to Falco socket"

**Solution:**
```bash
# Check if Falco is running
systemctl status falco

# Verify socket exists
ls -la /var/run/falco/falco.sock

# Check permissions
sudo chmod 666 /var/run/falco/falco.sock
```

### Problem: "AI service unhealthy"

**Solution:**
```bash
# Check if AI service is running
curl http://localhost:5000/health

# Restart AI service
cd ai-module
python3 server.py

# Check Python dependencies
pip3 list | grep -E "flask|scikit|numpy"
```

### Problem: "No violations found" but there should be

**Solution:**
```bash
# Check rule files are loaded
./bin/kubesentinel scan --path ./manifests --rules ./configs/rules

# Verify manifest syntax
kubectl apply --dry-run=client -f ./manifests/

# Lower severity threshold
./bin/kubesentinel scan --path ./manifests --severity low
```

### Problem: High memory usage during monitoring

**Solution:**
Edit `config.yaml`:
```yaml
runtime:
  buffer_size: 5000  # Reduce from 10000
  workers: 2         # Reduce from 4
```

## Best Practices

### 1. Start with Static Analysis
Begin by scanning your existing manifests before enabling runtime monitoring.

### 2. Gradual Rollout
- Day 1-7: Static analysis only
- Day 8-14: Enable runtime monitoring in dev/staging
- Day 15+: Enable in production with appropriate thresholds

### 3. Tune False Positives
Review alerts weekly and adjust:
- Custom rules
- AI threshold
- Retention policies

### 4. Integrate with Existing Tools
- Send JSON reports to SIEM
- Create Grafana dashboards from metrics
- Set up Slack/PagerDuty alerts

### 5. Regular Reviews
- Weekly: Review critical/high incidents
- Monthly: Update security rules
- Quarterly: Retrain AI model with new baselines

## Next Steps

1. **Read Architecture Documentation**: `docs/architecture.md`
2. **Explore Example Rules**: `configs/rules/`
3. **Customize for Your Environment**: Edit `config.yaml`
4. **Set Up CI/CD Integration**: Add to your pipeline
5. **Enable Runtime Monitoring**: Deploy in your cluster
6. **Join Community**: (Add your GitHub discussions link)

## Getting Help

- **Documentation**: `docs/`
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: tarek.azabou@supcom.tn

## Contributing

We welcome contributions! See `CONTRIBUTING.md` for guidelines.
