# Go-CSPM Quick Reference

## Project Structure

```
go-cspm/
├── cmd/go-cspm/              # CLI entry point
│   └── main.go              # Command definitions
├── internal/                 # Core implementation
│   ├── static/              # Static analysis
│   │   ├── scanner.go       # Manifest scanner
│   │   └── rules.go         # Rules engine
│   ├── runtime/             # Runtime monitoring
│   │   ├── monitor.go       # Falco integration
│   │   └── processor.go     # Event processing
│   ├── ai/                  # AI integration
│   │   └── client.go        # HTTP client
│   ├── forensics/           # Evidence storage
│   │   └── vault.go         # Forensic vault
│   └── reporting/           # Report generation
│       └── generator.go     # Report generator
├── ai-module/               # Python AI service
│   ├── server.py           # Flask API
│   └── requirements.txt    # Python deps
├── configs/                 # Configuration
│   └── rules/              # Custom rules
├── examples/                # Examples
│   └── k8s-manifests/      # Test manifests
├── docs/                    # Documentation
│   ├── architecture.md     # Architecture
│   ├── getting-started.md  # Getting started
│   └── implementation-roadmap.md  # Roadmap
├── config.yaml             # Main config
├── Makefile                # Build automation
├── go.mod                  # Go dependencies
└── README.md               # Project overview
```

## Quick Commands

### Build & Test
```bash
make deps        # Install dependencies
make build       # Build binary
make test        # Run tests
make clean       # Clean artifacts
```

### Static Analysis
```bash
./bin/go-cspm scan --path ./manifests
./bin/go-cspm scan --severity high
./bin/go-cspm scan --rules ./custom-rules.yaml
```

### Runtime Monitoring
```bash
./bin/go-cspm monitor
./bin/go-cspm monitor --namespace prod
./bin/go-cspm monitor --deployment api
```

### AI Service
```bash
make run-ai                          # Start service
curl http://localhost:5000/health    # Health check
```

### Reporting
```bash
./bin/go-cspm report --incident-id <id>
./bin/go-cspm report --from 2024-01-01 --to 2024-12-31
```

## Key Concepts

### Static Analysis
- Scans YAML before deployment
- Rule-based validation
- Custom rules supported
- CI/CD integration

### Runtime Monitoring
- Real-time Falco events
- Concurrent processing
- Worker pool pattern
- Namespace filtering

### AI Detection
- Behavioral analysis
- Isolation Forest model
- Baseline learning
- Anomaly scoring

### Forensic Vault
- Selective storage
- Retention policies
- JSON format
- Policy-aware

### Reporting
- Multiple formats
- Timeline view
- Recommendations
- Statistics

## Configuration

### Static Analysis
```yaml
static:
  rules_path: "./configs/rules"
  severity_threshold: "medium"
```

### Runtime Monitoring
```yaml
runtime:
  falco_socket: "unix:///var/run/falco/falco.sock"
  workers: 4
  buffer_size: 10000
```

### AI Service
```yaml
ai:
  endpoint: "http://localhost:5000"
  threshold: 0.75
```

### Forensics
```yaml
forensics:
  storage_path: "./forensics"
  retention_days: 90
  max_size_mb: 1000
```

## Custom Rules

### Rule Structure
```yaml
- id: CUSTOM-001
  name: Rule Name
  description: What it checks
  severity: high
  kind: [Pod, Deployment]
  checks:
    - path: spec.containers.image
      operator: contains
      value: ":latest"
  remediation: How to fix
```

### Operators
- `equals`: Exact match
- `notEquals`: Not equal
- `exists`: Field exists
- `notExists`: Field missing
- `contains`: String contains
- `greaterThan`: Numeric >
- `lessThan`: Numeric <

## Severity Levels

- **CRITICAL**: Immediate action required
- **HIGH**: Significant risk
- **MEDIUM**: Best practice violation
- **LOW**: Informational

## Performance Tips

### Static Analysis
- Scan specific directories
- Use severity threshold
- Cache results

### Runtime Monitoring
- Filter by namespace
- Adjust worker count
- Tune buffer size

### AI Service
- Adjust threshold
- Retrain periodically
- Monitor latency

## Troubleshooting

### Falco Connection
```bash
# Check Falco status
systemctl status falco

# Check socket
ls -la /var/run/falco/falco.sock

# Fix permissions
sudo chmod 666 /var/run/falco/falco.sock
```

### AI Service
```bash
# Check health
curl http://localhost:5000/health

# Check logs
cd ai-module && python3 server.py

# Verify dependencies
pip3 list | grep -E "flask|scikit|numpy"
```

### Memory Issues
```yaml
# Reduce in config.yaml
runtime:
  buffer_size: 5000
  workers: 2
```

## Common Use Cases

### CI/CD Integration
```yaml
# .gitlab-ci.yml
security_scan:
  script:
    - go-cspm scan --path ./k8s --severity high
  allow_failure: false
```

### Production Monitoring
```bash
# Monitor critical namespace
go-cspm monitor --namespace production --workers 8
```

### Incident Investigation
```bash
# Generate report
go-cspm report --incident-id abc123 --format markdown
```

## File Locations

### Input
- Manifests: User-specified path
- Rules: `./configs/rules/*.yaml`
- Config: `./config.yaml`

### Output
- Forensics: `./forensics/*.json`
- Reports: `./reports/*.{md,json,html}`
- Binary: `./bin/go-cspm`

## Development

### Adding New Rule
1. Create YAML in `configs/rules/`
2. Define checks
3. Test with `go-cspm scan`

### Modifying Detection
1. Edit `internal/runtime/processor.go`
2. Update feature extraction
3. Test with live events

### Custom AI Model
1. Modify `ai-module/server.py`
2. Replace Isolation Forest
3. Retrain with data

## Resources

- **Docs**: `docs/`
- **Examples**: `examples/`
- **Tests**: `*_test.go`
- **Config**: `config.yaml`

## Support

- GitHub Issues: Bug reports
- GitHub Discussions: Questions
- Documentation: `docs/`
- Examples: `examples/`
