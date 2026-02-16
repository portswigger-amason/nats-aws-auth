# nats-aws-auth

A NATS authentication service that uses AWS KMS for cryptographic key management. Operator and system account private keys never leave KMS — only public keys are stored locally.

## What it does

This tool has two modes:

1. **Config generation** (`--generate`) — Creates a complete `nats-server.conf` with KMS-signed JWTs for the operator, system account, and auth account. Everything needed to boot a NATS server with JWT-based auth.

2. **Auth service** (default) — Connects to a running NATS server, configures an AUTH account with external authorization (auth callout), creates an APP account with JetStream, and listens for incoming connection requests. When a client connects through the sentinel user, the auth callout handler evaluates credentials and issues a user JWT for the APP account.

### Auth callout flow

```
Client (with sentinel creds)
    │
    ▼
NATS Server ──► Auth Callout ($SYS.REQ.USER.AUTH)
                    │
                    ▼
              Auth Service evaluates via pluggable backend:
              - K8s OIDC (validates K8s SA JWT, looks up permissions)
              - Allow-all (development/testing)
                    │
                    ▼
              Issues user JWT for APP account
                    │
                    ▼
              Client connected to APP account
```

## Prerequisites

- **Go 1.25+**
- **AWS credentials** with KMS permissions (`kms:CreateKey`, `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey`, `kms:CreateAlias`)
- **nats-server** v2.10+ (for auth callout support)
- **nats CLI** (optional, for testing)

## Quick start

```bash
# Build
go build -o nats-aws-auth ./cmd/server/

# Generate server config (creates/reuses KMS keys)
./nats-aws-auth --generate

# Start the NATS server
nats-server --config nats-server.conf

# In another terminal, start the auth service
./nats-aws-auth

# In another terminal, test publishing through auth callout
nats pub test.hello "Hello World" --creds sentinel.creds
```

## CLI flags

### Common

| Flag | Default | Description |
|------|---------|-------------|
| `--generate` | `false` | Generate config and exit |
| `--region` | *(from AWS config)* | AWS region override |

### Config generation mode

| Flag | Default | Description |
|------|---------|-------------|
| `--operator-name` | `KMS-Operator` | Operator name in generated config |
| `--sys-account` | `SYS` | System account name |
| `--output` | `.` | Output directory for generated files |
| `--alias-prefix` | `nats` | Prefix for KMS key aliases (e.g. `nats-operator`, `nats-sys-account`) |

### Auth service mode

| Flag | Default | Description |
|------|---------|-------------|
| `--auth-account-name` | `AUTH` | Name of the AUTH account |
| `--app-account-name` | `APP` | Name of the APP account for authorized users |
| `--url` | `localhost:4222` | NATS server URL |
| `--auth-backend` | `allow-all` | Auth backend (`k8s-oidc` or `allow-all`) |
| `--jwks-url` | | JWKS URL for JWT validation (k8s-oidc backend) |
| `--jwt-issuer` | | Expected JWT issuer (k8s-oidc backend) |
| `--jwt-audience` | `nats` | Expected JWT audience (k8s-oidc backend) |

## How it works

### Config generation (`--generate`)

1. Creates or reuses two Ed25519 keys in AWS KMS (operator + SYS account)
2. Generates local keypairs for AUTH account and sentinel user
3. Signs operator JWT (self-signed via KMS)
4. Signs SYS and AUTH account JWTs (signed by operator via KMS)
5. Creates a bearer-token sentinel user JWT (signed by AUTH account locally)
6. Writes `nats-server.conf` with embedded JWTs, full resolver, and JetStream config

### Auth service (default mode)

1. Looks up operator and SYS account keys from KMS by alias
2. Connects to NATS as a SYS account user (JWT signed via KMS)
3. Fetches all existing account JWTs via `$SYS.REQ.CLAIMS.PACK`
4. Creates APP account (if new) with JetStream enabled
5. Updates AUTH account with a signing key and external authorization config
6. Writes `sentinel.creds` for testing auth callout
7. Subscribes to `$SYS.REQ.USER.AUTH` and handles auth callout requests

### KMS key management

Keys are identified by alias:
- `alias/nats-operator` — Operator signing key
- `alias/nats-sys-account` — SYS account signing key

On first run with `--generate`, keys are created in KMS. On subsequent runs, existing keys are discovered by alias and reused. The `--alias-prefix` flag controls the prefix (default: `nats`).

## Project structure

```
nats-aws-auth/
├── cmd/server/
│   ├── main.go        # Entry point, config generation, auth callout handler
│   └── keys.go        # AWS KMS integration, key types, nkey encoding
├── internal/
│   ├── jwt/           # JWT validator with JWKS support
│   ├── k8s/           # K8s ServiceAccount cache with informer
│   └── auth/          # Pluggable auth backends (K8s OIDC, allow-all)
├── testdata/          # Test fixtures (JWKS, tokens)
├── go.mod
├── go.sum
└── .gitignore
```

## Generated files

| File | Description | Gitignored |
|------|-------------|------------|
| `nats-server.conf` | NATS server configuration with embedded JWTs | Yes |
| `sentinel.creds` | Sentinel user credentials for auth callout testing | Yes |
| `jwt/` | NATS JWT resolver directory (runtime) | Yes |
| `jetstream/` | JetStream storage directory (runtime) | Yes |

## Security notes

- Operator and SYS account private keys are stored exclusively in AWS KMS — no private key material is ever written to disk or held in memory
- The AUTH account and sentinel user keys are generated locally per session (ephemeral)
- The signing key used by the auth callout handler is generated in-memory and not persisted
- Sentinel credentials (`sentinel.creds`) are for testing only — the sentinel user has all pub/sub permissions denied, and only serves to trigger the auth callout
- K8s OIDC backend validates JWT signatures via JWKS, enforces issuer/audience/expiry claims
