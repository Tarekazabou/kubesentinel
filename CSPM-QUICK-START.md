# KubeSentinel CSPM — Quick Start Guide

## ✅ What's Been Implemented

The **Cloud Security Posture Management (CSPM) module** is now fully functional and ready to use!

### Module Structure
```
cspm/
├── __init__.py           # Package initialization
├── manifest_scanner.py   # Core security scanning logic
├── report_generator.py   # JSON/HTML report generation
└── cli.py               # Command-line interface
```

### Features
- ✅ **Manifest Scanning** — Analyzes Kubernetes YAML files for security misconfigurations
- ✅ **Multi-format Reporting** — Generates JSON, HTML, and text reports
- ✅ **Security Checks** Including:
  - Privileged containers (CRITICAL)
  - Missing resource limits (HIGH)
  - Running as root (HIGH)
  - Writable filesystems (MEDIUM)
  - Dangerous capabilities (HIGH)
  - hostPath volume mounts (HIGH)
  - Overly permissive RBAC rules (HIGH/CRITICAL)
  
- ✅ **Unit Tests** — 6 comprehensive tests, all passing

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install pyyaml
```

### 2. Scan Your Manifests

**Scan a single file:**
```bash
python -m cspm.cli --manifest deploy/secure-pod.yaml --format json
```

**Scan an entire directory:**
```bash
python -m cspm.cli --manifest deploy/ --format html --output reports/scan.html
```

**Print summary to console:**
```bash
python -m cspm.cli --manifest deploy/ --format json --summary
```

### 3. View Output Formats

**JSON Report** — Machine-readable findings
```bash
python -m cspm.cli --manifest deploy/ --format json --output report.json
```

**HTML Report** — Visual dashboard with severity colors and statistics
```bash
python -m cspm.cli --manifest deploy/ --format html --output report.html
```

**Text Report** — Plain text summary
```bash
python -m cspm.cli --manifest deploy/ --format text --output report.txt
```

---

## 📊 Example Output

### JSON Report Structure
```json
{
  "timestamp": "2026-03-10T21:24:15.723410",
  "summary": {
    "total": 4,
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "rule": "privileged_container",
      "message": "Container nginx in insecure-pod is running as privileged",
      "remediation": "Set securityContext.privileged to false",
      "file": "deploy/insecure-pod.yaml"
    }
  ]
}
```

---

## 🧪 Running Tests

Run all CSPM tests:
```bash
python -m pytest tests/cspm/ -v
```

Run a specific test:
```bash
python -m pytest tests/cspm/test_scanner.py::test_detect_privileged_container -v
```

---

## 📝 How It Works

1. **Manifest Loading** — Reads YAML files and parses them using PyYAML
2. **Security Analysis** — Checks pod specs and RBAC configurations against security best practices
3. **Finding Classification** — Categorizes issues by severity (CRITICAL, HIGH, MEDIUM, LOW)
4. **Report Generation** — Creates reports in your chosen format with remediation guidance

---

## 🔍 Security Checks in Detail

### Pod Specification Checks
| Check | Severity | What It Detects |
|-------|----------|-----------------|
| Privileged Container | CRITICAL | Containers running with `privileged: true` |
| Missing Resource Limits | HIGH | Containers without CPU/memory limits |
| Runs as Root | HIGH | Containers without `runAsUser` or running as UID 0 |
| Writable Filesystem | MEDIUM | Containers with writable root filesystem |
| Dangerous Capabilities | HIGH | Added capabilities like NET_ADMIN, SYS_ADMIN |
| hostPath Mounts | HIGH | Direct host filesystem mounts |

### RBAC Checks
| Check | Severity | What It Detects |
|-------|----------|-----------------|
| Overly Permissive RBAC | HIGH/CRITICAL | Wildcards in verbs, resources, or API groups |
| Dangerous Permissions | CRITICAL | Allows dangerous verbs on all resources |

---

## 💡 Example: Scanning Your Test Pods

Your workspace includes two test pods:
- **`deploy/insecure-pod.yaml`** — Contains multiple security issues (used for testing)
- **`deploy/secure-pod.yaml`** — Follows security best practices (good example to follow)

Compare them:
```bash
# Scan insecure pod
python -m cspm.cli --manifest deploy/insecure-pod.yaml --format json

# Scan secure pod  
python -m cspm.cli --manifest deploy/secure-pod.yaml --format json
```

---

## 🎯 Next Steps

1. ✅ **Phase 1.4 COMPLETE** — CSPM Module working
2. 📋 **Phase 1.5 NEXT** — Integrate with main CLI (update `cmd/main.go`)
3. 📊 **Phase 1.6** — Add integration tests
4. 🔧 **Phase 2** — Runtime monitoring with Falco

---

## 📚 Files Generated

After scanning, you'll have:
- **`reports/cspm-findings.json`** — Detailed findings in JSON format
- **`reports/cspm-report.html`** — Visual HTML report with dashboard and statistics
- **`tests/cspm/test_scanner.py`** — Comprehensive unit tests (all passing ✅)

---

## 🐛 Troubleshooting

**YAML parsing errors?**
```bash
# Make sure your manifests are valid YAML
python -c "import yaml; yaml.safe_load(open('file.yaml'))"
```

**Unicode encoding errors?**
- The CLI uses UTF-8 encoding by default (fixed for Windows compatibility)

**File not found errors?**
- Use absolute paths or ensure working directory is correct
- The scanner recursively searches directories for `*.yaml` files

---

## 📖 Learn More

- See the full [DETAILED-IMPLEMENTATION-PLAN.md](../DETAILED-IMPLEMENTATION-PLAN.md) for Phase 1-4 roadmap
- Review [secure-pod.yaml](../deploy/secure-pod.yaml) for security best practices
- Check test cases in [test_scanner.py](../tests/cspm/test_scanner.py) for examples

---

## Summary of Phase 1.4 Completion

| Item | Status |
|------|--------|
| Manifest scanner module | ✅ Complete |
| Security checks (7 types) | ✅ Complete |
| JSON report generation | ✅ Complete |
| HTML report generation | ✅ Complete |
| CLI interface | ✅ Complete |
| Unit tests (6 tests) | ✅ All passing |
| Real manifests scanning | ✅ Works on deploy/ |

You're ready to move to **Phase 1.5** (CLI integration) or start **Phase 2** (Falco runtime monitoring)!

