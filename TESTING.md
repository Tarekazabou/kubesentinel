# KubeSentinel Testing Guide

This document describes how to run and test the KubeSentinel project.

## Prerequisites

- **Go 1.21+** (`go version go1.25.5` installed)
- **Python 3.9+** (`python 3.13.3` installed)
- **Make** (optional, for convenience—direct Go commands work too)

## Running Tests

### Go Tests

The project includes unit tests and integration tests for the Go components.

#### Run All Go Tests

```bash
go test -v ./...
```

#### Run Specific Test Package

```bash
go test -v ./internal/runtime
go test -v ./internal/forensics
go test -v ./internal/reporting
go test -v ./pkg/...
```

#### Test Coverage

Generate a coverage report:

```bash
go test -v -coverprofile=coverage.out -covermode=atomic ./...
go tool cover -html=coverage.out -o coverage.html
```

### Python Tests

The AI module includes Python tests using pytest.

#### Install Test Dependencies

```bash
pip install pytest scikit-learn numpy flask
```

#### Run Python Tests

From the project root:

```bash
python -m pytest ai-module/tests/ -v
```

Or from the `ai-module` directory:

```bash
cd ai-module
python -m pytest tests/ -v
```

## Integration Testing

Some tests require external services to be running.

### AI Service Tests

The `TestAIIntegration` test requires the Python AI service to be running on `localhost:5000`.

#### Start the AI Service

In a separate terminal:

```bash
cd ai-module
python server.py
```

Then run tests:

```bash
go test -v ./internal/runtime
```

### Static Analysis Tests

Test the static scanner directly:

```bash
./bin/kubesentinel scan --path ./deploy
```

Expected output: Analysis of the test YAML manifests in `deploy/` directory.

## Build and Run

### Build the Binary

```bash
go build -o ./bin/kubesentinel ./cmd/kubesentinel
```

### Run Static Analysis

```bash
./bin/kubesentinel scan --path ./deploy
```

### Start Runtime Monitor

```bash
./bin/kubesentinel monitor --namespace production --deployment api
```

### Generate Forensic Reports

```bash
./bin/kubesentinel report --from "2026-03-01" --to "2026-03-31" --format markdown,json
./bin/kubesentinel report --incident-id <record-id> --format html --no-llm
```

## Known Issues and Fixes

### Issue: Nil Pointer in Concurrency Tests (FIXED ✅)

**Problem**: Tests were crashing with `panic: runtime error: invalid memory address or nil pointer dereference`

**Root Cause**: The `ai.Client` was created without initializing the `HTTPClient` field.

**Solution**: Updated test initialization to properly create the HTTP client:
```go
mockClient := &ai.Client{
    Endpoint:   "http://localhost:5000",
    HTTPClient: &http.Client{Timeout: 5 * time.Second},
    Threshold:  0.75,
}
```

**Status**: ✅ FIXED - `TestProcessorConcurrency` now passes

### Issue: AI Integration Tests Require Service

**Problem**: `TestAIIntegration` fails when the Python AI service is not running.

**Solution**: Start the AI service in a separate terminal before running integration tests.

**Expected Behavior**: This is normal—the tests verify that the AI service communication works when available.

## Test Results Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Go Unit Tests | ✅ Pass | Concurrency and processor tests working |
| Forensics Tests | ✅ Pass | Compression and max-size pruning verified |
| Reporting Tests | ✅ Pass | Assembler and JSON/HTML output generation verified |
| Python Tests | ✅ Setup Ready | Dependencies installable, test framework available |
| Integration Tests | ⚠️ Requires AI Service | Run `python ai-module/server.py` first |
| Static Analysis | ✅ Ready | `./bin/kubesentinel scan --path ./deploy` works |

## CI/CD Integration

For GitHub Actions or similar CI systems, use:

```bash
go test -v -coverprofile=coverage.out ./...
python -m pytest ai-module/tests/ -v --tb=short
```

## Troubleshooting

### Test: "AI service not reachable"

**Solution**: Start the AI service in a separate terminal:
```bash
cd ai-module
python server.py
```

### Test: "No test files found"

**Solution**: Some packages don't have tests yet (e.g., `pkg/rules`, `pkg/scanner`). This is expected.

### Python Dependencies Not Found

**Solution**: Install Python dependencies:
```bash
pip install -r requirements.txt
pip install -r ai-module/requirements.txt
```

## Contributing Tests

When adding new code, include tests in the same package:

- Go: Use `*_test.go` files in the same directory
- Python: Add tests to `ai-module/tests/` directory

Example:
```go
// file: internal/runtime/processor_test.go
package runtime

import "testing"

func TestNewProcessor(t *testing.T) {
    // Test implementation
}
```

## Resources

- [Go Testing Package](https://golang.org/pkg/testing/)
- [Python pytest Documentation](https://docs.pytest.org/)
- [KubeSentinel Project Guide](docs/PROJECT-GUIDE.md)
