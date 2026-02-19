# nats-aws-auth

## Project Overview

Go application implementing NATS authentication with AWS KMS-backed key management. Three operational modes:
1. **Config generation** (`--generate`): Creates `nats-server.conf` with KMS-signed JWTs
2. **Credential generation** (`--generate-credentials`): Creates NACK JetStream controller credentials signed by an APP account KMS key
3. **Auth service** (default): Runs an auth callout handler for dynamic NATS authorization with pluggable backends

## Build & Run

```bash
go build -o nats-aws-auth ./cmd/server/
./nats-aws-auth --generate                          # Generate nats-server.conf (requires AWS KMS access)
./nats-aws-auth --generate-credentials \
  --app-account-key-alias nats-app-account           # Generate NACK credentials (requires AWS KMS access)
nats-server --config nats-server.conf                # Start server
./nats-aws-auth                                      # Run auth service (allow-all backend)
./nats-aws-auth --auth-backend k8s-oidc              # Run auth service (K8s OIDC backend)
./nats-aws-auth --debug                              # Run with debug-level logging
```

### Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--generate` | `false` | Generate nats-server.conf and exit |
| `--generate-credentials` | `false` | Generate NACK credentials file and exit |
| `--app-account-key-alias` | `""` | KMS key alias for APP account (required for `--generate-credentials`, optional for auth service) |
| `--auth-backend` | `allow-all` | Auth backend: `k8s-oidc` or `allow-all` |
| `--url` | `localhost:4222` | NATS server URL |
| `--debug` | `false` | Enable debug-level logging |
| `--region` | `""` | AWS region (uses AWS config/environment if not specified) |

## Project Structure

- `cmd/server/main.go` - Entry point, CLI flag parsing, logger initialization
- `cmd/server/authservice.go` - Auth service mode: NATS connection setup, account configuration, auth callout handler lifecycle
- `cmd/server/callout.go` - Auth callout request handling (decode, authorize, respond)
- `cmd/server/generate.go` - Config generation mode: KMS key setup, JWT creation, nats-server.conf output
- `cmd/server/credentials.go` - Credential generation mode: NACK user JWT creation signed by APP account KMS key
- `cmd/server/keys.go` - AWS KMS integration, key management, nkey encoding, local key generation
- `cmd/server/metrics.go` - Prometheus metrics definitions (auth callout requests, duration, service health)
- `internal/jwt/` - JWT validator with JWKS support for K8s OIDC
- `internal/k8s/` - ServiceAccount cache with informer + permission builder
- `internal/auth/` - Pluggable Authorizer interface (K8sOIDCAuthorizer, AllowAllAuthorizer)
- `testdata/` - JWKS + token test fixtures

## Key Dependencies

- `github.com/aws/aws-sdk-go-v2/service/kms` - AWS KMS for Ed25519 key management
- `github.com/nats-io/jwt/v2` - NATS JWT creation/validation
- `github.com/nats-io/nkeys` - NATS NKey encoding
- `github.com/nats-io/nats.go` - NATS client
- `github.com/MicahParks/keyfunc/v2` - JWKS key function for JWT validation
- `github.com/golang-jwt/jwt/v5` - JWT parsing and validation
- `github.com/prometheus/client_golang` - Prometheus metrics for auth callout SLO tracking
- `go.uber.org/zap` - Structured logging
- `k8s.io/client-go` - Kubernetes client for SA informer
- `github.com/spf13/pflag` - GNU-style CLI flags

## Conventions

- Go 1.25, standard Go project layout
- 19 tests across cmd/server, internal/jwt, internal/k8s, internal/auth
- Structured logging via zap (`--debug` for verbose output, info level by default)
- Generated files (`.conf`, `.creds`, `.nk`, `.jwt`) are gitignored
- Private keys for Operator/SYS never stored locally - only in KMS
- Prometheus metrics exposed on `:8080/metrics`, health check on `:8080/health`
