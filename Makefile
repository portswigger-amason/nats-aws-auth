BINARY_NAME := nats-kms-auth
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w \
    -X main.version=$(VERSION) \
    -X main.commit=$(COMMIT) \
    -X main.buildDate=$(BUILD_DATE)

.PHONY: build build-all build-amd64 build-arm64 test lint docker-build clean help

build: ## Build for current platform
	go build -ldflags "$(LDFLAGS)" -o out/$(BINARY_NAME) ./cmd/server/

build-all: build-amd64 build-arm64 ## Build for all platforms

build-amd64: ## Build for linux/amd64
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o out/$(BINARY_NAME)-linux-amd64 ./cmd/server/

build-arm64: ## Build for linux/arm64
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o out/$(BINARY_NAME)-linux-arm64 ./cmd/server/

test: ## Run unit tests
	go test -race -v ./...

test-coverage: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint: ## Run linter
	golangci-lint run ./...

docker-build: build-all ## Build Docker image locally
	docker buildx build --platform linux/amd64,linux/arm64 -t $(BINARY_NAME):$(VERSION) .

clean: ## Clean build artifacts
	rm -rf out/ coverage.out

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
