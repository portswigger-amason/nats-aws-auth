# Variables
BINARY_NAME := nats-aws-auth
OUT_DIR := out
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: test test-unit test-helm test-all coverage lint clean
.PHONY: build build-all build-amd64 build-arm64 docker-build docker-push version help

# Default target
all: build-all

# Run unit tests (default test target)
test: test-unit

# Run unit tests only
test-unit: ## Run unit tests
	@echo "Running unit tests..."
	go test -race ./...

# Run Helm unit tests (requires helm-unittest plugin)
test-helm: ## Run Helm unit tests
	@echo "Running Helm unit tests..."
	@command -v helm >/dev/null 2>&1 || { echo "Error: helm is not installed"; exit 1; }
	@helm plugin list | grep -q unittest || { echo "Error: helm-unittest plugin not installed. Run: helm plugin install https://github.com/helm-unittest/helm-unittest"; exit 1; }
	helm unittest --strict helm/nats-aws-auth

# Run all tests (unit + helm)
test-all: test-unit test-helm ## Run all tests

# Run tests with coverage
coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -race -cover ./...

# Run linter (requires golangci-lint)
lint: ## Run linter
	@echo "Running golangci-lint..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Error: golangci-lint is not installed. Install: https://golangci-lint.run/usage/install/"; exit 1; }
	golangci-lint run --timeout=5m

# Build targets
# ============================================================

# Build for current architecture
build: ## Build for current platform
	@echo "Building for current architecture..."
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY_NAME) ./cmd/server/

# Build for all architectures
build-all: build-amd64 build-arm64 ## Build for all platforms
	@echo "All binaries built successfully in $(OUT_DIR)/"

# Build for amd64
build-amd64: ## Build for linux/amd64
	@echo "Building for linux/amd64..."
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-ldflags="$(LDFLAGS)" \
		-o $(OUT_DIR)/$(BINARY_NAME)-linux-amd64 \
		./cmd/server/

# Build for arm64
build-arm64: ## Build for linux/arm64
	@echo "Building for linux/arm64..."
	@mkdir -p $(OUT_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
		-ldflags="$(LDFLAGS)" \
		-o $(OUT_DIR)/$(BINARY_NAME)-linux-arm64 \
		./cmd/server/

# Docker targets
# ============================================================

# Build Docker image for local testing (amd64 only for --load compatibility)
docker-build: build-all ## Build Docker image locally
	@echo "Building Docker image for linux/amd64..."
	docker buildx build \
		--platform linux/amd64 \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest \
		--load \
		.

# Build and push multi-arch Docker image
docker-push: build-all ## Build and push Docker image
	@echo "Building and pushing multi-arch Docker image..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(BINARY_NAME):$(VERSION) \
		-t $(BINARY_NAME):latest \
		--push \
		.

# Utility targets
# ============================================================

# Display version information
version: ## Show version info
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Help message
help: ## Show this help
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Clean test cache and build artifacts
clean: ## Clean build artifacts
	@echo "Cleaning test cache and build artifacts..."
	go clean -testcache
	rm -rf $(OUT_DIR) coverage.out
