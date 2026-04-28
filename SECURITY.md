# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ Active support |
| Older releases | ❌ No support |

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security vulnerabilities.**

Report security issues via one of these channels:

1. **GitHub Private Advisory** (preferred): Use [GitHub's private security advisory feature](https://github.com/Tarekazabou/kubesentinel/security/advisories/new) to report a vulnerability confidentially.
2. **Email**: Open a GitHub issue first and request a private contact channel.

### What to Include

Please include as much of the following information as possible to help us understand the nature and scope of the issue:

- Type of issue (e.g., remote code execution, privilege escalation, credential exposure)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial acknowledgement | Within 48 hours |
| Triage and severity assessment | Within 5 business days |
| Patch or mitigation | Within 30 days for Critical/High |
| Public disclosure | Coordinated with reporter |

## Scope

### In Scope
- KubeSentinel Go CLI (`cmd/`, `internal/`, `pkg/`)
- KubeSentinel AI/ML service (`ai-module/`)
- Kubernetes deployment manifests (`deploy/`)
- Docker images built from `Dockerfile` and `Dockerfile.ai`
- Python CSPM module (`cspm/`)

### Out of Scope
- Falco itself (report to the [Falco project](https://github.com/falcosecurity/falco/security))
- Gemini / Google AI APIs (report to [Google's VRP](https://bughunters.google.com/))
- Third-party dependencies (report to their respective maintainers)

## Security Best Practices for Deployers

- **Secrets**: Never commit API keys or tokens to source control. Use Kubernetes Secrets or an External Secrets Operator.
- **Network**: Apply the `NetworkPolicy` in `deploy/network-policy.yaml` to restrict traffic between KubeSentinel components.
- **RBAC**: The provided ClusterRole is read-only. Do not grant write permissions.
- **Container security**: Enable Pod Security Admission with `restricted` or `baseline` profile in the `kubesentinel` namespace.
- **Token**: Set `TRAINING_API_TOKEN` to protect the `/train` endpoint on the AI service. Leaving it unset disables authentication (demo mode only).
