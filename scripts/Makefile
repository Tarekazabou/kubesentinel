.PHONY: all build clean test run-static run-monitor run-ai deps docker-build help

# Variables
BINARY_NAME=go-cspm
BUILD_DIR=./bin
MAIN_PATH=./cmd/go-cspm
GO=go
PYTHON=python3
PIP=pip3

# Build information
VERSION?=0.1.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}"

all: deps build ## Build everything

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Install dependencies
	@echo "Installing Go dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "Installing Python dependencies..."
	$(PIP) install -r ai-module/requirements.txt --break-system-packages

build: ## Build the Go binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux: ## Build for Linux
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux $(MAIN_PATH)

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -rf ./forensics/*
	@rm -rf ./reports/*
	@find . -name "*.pyc" -delete
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete"

test: ## Run tests
	@echo "Running Go tests..."
	$(GO) test -v -race -cover ./...
	@echo "Running Python tests..."
	cd ai-module && $(PYTHON) -m pytest tests/ -v || echo "No Python tests found"

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

lint: ## Run linters
	@echo "Running golangci-lint..."
	golangci-lint run ./... || echo "Install golangci-lint: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
	@echo "Running Python linters..."
	cd ai-module && $(PYTHON) -m flake8 . || echo "Install flake8: pip install flake8"

run-static: build ## Run static analysis on example manifests
	@echo "Running static analysis..."
	$(BUILD_DIR)/$(BINARY_NAME) scan --path ./examples/k8s-manifests

run-monitor: build ## Start runtime monitoring
	@echo "Starting runtime monitor..."
	$(BUILD_DIR)/$(BINARY_NAME) monitor --cluster minikube

run-ai: ## Start AI/ML service
	@echo "Starting AI service..."
	cd ai-module && $(PYTHON) server.py

run-report: build ## Generate a sample report
	@echo "Generating report..."
	$(BUILD_DIR)/$(BINARY_NAME) report --from "2024-01-01" --to "2024-12-31"

install: build ## Install binary to /usr/local/bin
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installed successfully"

uninstall: ## Uninstall binary from /usr/local/bin
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstalled successfully"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t go-cspm:$(VERSION) .
	docker tag go-cspm:$(VERSION) go-cspm:latest

docker-run: ## Run in Docker
	@echo "Running in Docker..."
	docker run -v /var/run/falco:/var/run/falco -v $(PWD)/config.yaml:/app/config.yaml go-cspm:latest monitor

setup-dev: ## Setup development environment
	@echo "Setting up development environment..."
	@mkdir -p examples/k8s-manifests
	@mkdir -p configs/rules
	@mkdir -p forensics
	@mkdir -p reports
	@mkdir -p ai-module/models
	@echo "Creating example manifest..."
	@echo "apiVersion: v1\nkind: Pod\nmetadata:\n  name: example-pod\nspec:\n  containers:\n  - name: nginx\n    image: nginx:latest" > examples/k8s-manifests/example.yaml
	@echo "Development environment ready"

integration-test: ## Run integration tests
	@echo "Running integration tests..."
	@echo "Starting AI service in background..."
	@cd ai-module && $(PYTHON) server.py &
	@sleep 3
	@echo "Running integration tests..."
	$(GO) test -v -tags=integration ./tests/integration/...
	@pkill -f "server.py" || true

ci: deps lint test ## Run CI pipeline
	@echo "CI pipeline complete"

# Example rules
example-rules: ## Create example security rules
	@mkdir -p configs/rules
	@cat > configs/rules/container-security.yaml <<EOF
	- id: CUSTOM-001
	  name: Detect Missing Security Context
	  description: Container missing security context configuration
	  severity: medium
	  kind: [Pod, Deployment]
	  checks:
	    - path: spec.containers[*].securityContext
	      operator: notExists
	      value: null
	  remediation: Add securityContext with appropriate settings
	EOF
	@echo "Example rules created in configs/rules/"

.DEFAULT_GOAL := help
