# Contributing to KubeSentinel

Thank you for your interest in contributing! KubeSentinel is a Kubernetes Cloud Security Posture Management (CSPM) platform and we welcome contributions of all kinds.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Branching Strategy](#branching-strategy)
- [Making a Contribution](#making-a-contribution)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Security Contributions](#security-contributions)

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/) Code of Conduct. By participating you agree to uphold this standard. Unacceptable behaviour can be reported by opening a GitHub issue tagged `conduct`.

---

## Getting Started

1. **Fork** the repository and clone your fork.
2. Read [`DEVELOPERS.md`](DEVELOPERS.md) for the quick-start development guide.
3. Read [`docs/architecture.md`](docs/architecture.md) to understand the system design.
4. Look for issues tagged **`good first issue`** or **`help wanted`**.

---

## Development Setup

### Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Go | 1.21 |
| Python | 3.12 |
| Docker | 24 |
| kubectl | 1.28 |
| Falco (optional) | 0.37 |

### Install dependencies

```bash
make -C scripts deps
```

### Build

```bash
make -C scripts build
```

### Run tests

```bash
make -C scripts test
```

### Run the full CI pipeline locally

```bash
make -C scripts ci
```

---

## Branching Strategy

| Branch type | Convention | Example |
|-------------|------------|---------|
| Feature | `feat/<short-description>` | `feat/add-cis-benchmark-rules` |
| Bug fix | `fix/<short-description>` | `fix/vault-file-permissions` |
| Documentation | `docs/<short-description>` | `docs/update-architecture` |
| Chore / tooling | `chore/<short-description>` | `chore/upgrade-python-3.12` |

All PRs target the `main` branch.

---

## Making a Contribution

1. **Create an issue** first for significant changes, so we can discuss the approach before you invest time.
2. Fork and create a branch from `main`.
3. Make your changes following the [Coding Standards](#coding-standards) below.
4. Add or update tests to cover your changes.
5. Run `make -C scripts test` and ensure all tests pass.
6. Submit a pull request using the provided PR template.

---

## Coding Standards

### Go

- Follow the [Effective Go](https://go.dev/doc/effective_go) style guide.
- Run `golangci-lint run ./...` before pushing (CI will enforce this).
- Use `log/slog` for structured logging — avoid `fmt.Println` in non-test code.
- All exported types and functions must have a doc comment.
- Prefer table-driven tests (`t.Run`).
- Context (`context.Context`) must be the first argument of any function that performs I/O.

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/). Run `flake8` before pushing.
- Type hints are required for all public functions.
- Use `logging` for all output — avoid `print()` in production code.
- Tests go in `ai-module/tests/` and use `pytest`.

### Kubernetes / YAML

- All manifests must pass `kubectl apply --dry-run=server -f <file>`.
- New security rules must include a CIS Benchmark reference where applicable.
- Custom rules require: `id`, `name`, `description`, `severity`, `kind`, `checks`, and `remediation`.

---

## Testing

| Layer | How to run |
|-------|-----------|
| Go unit tests | `go test -v -race ./...` |
| Go integration tests | `go test -tags=integration ./tests/integration/...` |
| Python unit tests | `cd ai-module && python -m pytest tests/ -v` |
| CSPM scanner tests | `python -m pytest tests/cspm/ -v` |
| Static analysis (SAST) | `golangci-lint run ./...` + `flake8 ai-module/` |

Test coverage expectations:
- New Go packages: minimum 70% statement coverage.
- New Python modules: minimum 70% line coverage.

---

## Security Contributions

If you discover a security vulnerability, **do not open a public GitHub issue**. Please follow the [Security Policy](SECURITY.md) for responsible disclosure.

---

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `perf`, `ci`, `security`

**Examples:**
```
feat(scanner): add CIS Kubernetes Benchmark v1.8 rules
fix(vault): restrict forensic record file permissions to 0600
security(gemini): move API key from URL query param to header
```

---

## Pull Request Checklist

Before marking your PR as ready for review:

- [ ] Tests added/updated and all passing
- [ ] Linter passes with no new warnings
- [ ] Documentation updated (README, docs/, inline comments)
- [ ] No hardcoded secrets, tokens, or credentials
- [ ] Security-sensitive changes noted in PR description
- [ ] `CHANGELOG.md` entry added (if applicable)
