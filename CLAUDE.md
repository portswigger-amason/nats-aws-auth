# nats-kms-auth

## Project Overview

Go application implementing NATS authentication with AWS KMS-backed key management. Two operational modes:
1. **Config generation** (`--generate`): Creates `nats-server.conf` with KMS-signed JWTs
2. **Auth service**: Runs an auth callout handler for dynamic NATS authorization with pluggable backends

## Build & Run

```bash
go build -o nats-kms-auth ./cmd/server/
./nats-kms-auth --generate          # Generate config (requires AWS KMS access)
nats-server --config nats-server.conf  # Start server
./nats-kms-auth                     # Run auth service
```

## Project Structure

- `cmd/server/main.go` - Entry point, config generation, auth callout handler
- `cmd/server/keys.go` - AWS KMS integration, key management, nkey encoding
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
- `k8s.io/client-go` - Kubernetes client for SA informer
- `github.com/spf13/pflag` - GNU-style CLI flags

## Conventions

- Go 1.25, standard Go project layout
- 27 tests across internal/jwt, internal/k8s, internal/auth
- Generated files (`.conf`, `.creds`, `.nk`, `.jwt`) are gitignored
- Private keys for Operator/SYS never stored locally - only in KMS
