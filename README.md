# nats-aws-auth

A NATS authentication service that uses AWS KMS for cryptographic key management. Operator and system account private keys never leave KMS — only public keys are stored locally.

## What it does

This tool has three modes:

1. **Config generation** (`--generate`) — Creates a complete `nats-server.conf` with KMS-signed JWTs for the operator, system account, and auth account. Everything needed to boot a NATS server with JWT-based auth.

2. **Credential generation** (`--generate-credentials`) — Creates pre-signed NACK credentials (`nack.creds`) for the JetStream controller. The user JWT is signed by the APP account's KMS key. Run once, store as a K8s secret.

3. **Auth service** (default) — Connects to a running NATS server, configures an AUTH account with external authorization (auth callout), creates an APP account with JetStream, and listens for incoming connection requests.

### Authentication paths

There are two distinct ways clients authenticate:

**Path A: Applications (auth callout)** — No KMS calls on this path.

```
App ──(K8s SA token)──► NATS Server ──(auth callout)──► nats-aws-auth
                                                              │
                                                    1. Validate K8s OIDC token
                                                    2. Look up SA permissions
                                                    3. Issue user JWT (ephemeral key)
                                                              │
App ◄──(authorized into APP account)──── NATS Server ◄────────┘
```

**Path B: NACK JetStream controller (pre-signed)** — No auth callout involved.

```
NACK ──(nack.creds)──► NATS Server ──► JWT validated against APP account signing keys
                                              │
NACK ◄──(authorized, full $JS.API.> access)───┘
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

# Generate NACK credentials (creates APP account KMS key on first run)
./nats-aws-auth --generate-credentials --app-account-key-alias nats-app-account

# Start the NATS server
nats-server --config nats-server.conf

# In another terminal, start the auth service (with stable APP account key)
./nats-aws-auth --app-account-key-alias nats-app-account

# In another terminal, test publishing through auth callout
nats pub test.hello "Hello World" --creds sentinel.creds
```

## CLI flags

### Common

| Flag | Default | Description |
|------|---------|-------------|
| `--generate` | `false` | Generate server config and exit |
| `--generate-credentials` | `false` | Generate NACK credentials and exit |
| `--region` | *(from AWS config)* | AWS region override |
| `--app-account-key-alias` | | KMS key alias for APP account (e.g. `nats-app-account`). When set, uses a stable KMS-backed key for the APP account identity |

### Config generation mode (`--generate`)

| Flag | Default | Description |
|------|---------|-------------|
| `--operator-name` | `KMS-Operator` | Operator name in generated config |
| `--sys-account` | `SYS` | System account name |
| `--output` | `.` | Output directory for generated files |
| `--alias-prefix` | `nats` | Prefix for KMS key aliases (e.g. `nats-operator`, `nats-sys-account`) |

### Credential generation mode (`--generate-credentials`)

| Flag | Default | Description |
|------|---------|-------------|
| `--app-account-key-alias` | *(required)* | KMS key alias for the APP account |
| `--output` | `.` | Output directory for `nack.creds` |

### Auth service mode

| Flag | Default | Description |
|------|---------|-------------|
| `--auth-account-name` | `AUTH` | Name of the AUTH account |
| `--app-account-name` | `APP` | Name of the APP account for authorized users |
| `--app-account-key-alias` | | KMS key alias for stable APP account identity (optional, falls back to ephemeral keys) |
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

### Credential generation (`--generate-credentials`)

1. Gets or creates APP account key in KMS (`alias/<app-account-key-alias>`)
2. Generates a NACK user keypair (local, in-memory)
3. Creates a NACK user JWT signed by the APP account key via KMS, with `$JS.API.>` permissions
4. Writes `nack.creds` (JWT + nkey seed)

### Auth service (default mode)

1. Looks up operator, SYS, and APP account keys from KMS by alias
2. Connects to NATS as a SYS account user (JWT signed via KMS)
3. Fetches all existing account JWTs via `$SYS.REQ.CLAIMS.PACK`
4. Creates APP account (if new) with KMS-backed identity and JetStream enabled
5. Registers the KMS key and an ephemeral signing key on the APP account
6. Updates AUTH account with a signing key and external authorization config
7. Subscribes to `$SYS.REQ.USER.AUTH` and handles auth callout requests

### KMS key management

Keys are identified by alias:
- `alias/nats-operator` — Operator signing key
- `alias/nats-sys-account` — SYS account signing key
- `alias/<app-account-key-alias>` — APP account identity key (optional, for stable pre-signed credentials)

On first run with `--generate`, operator and SYS keys are created in KMS. On first run with `--generate-credentials`, the APP account key is created. On subsequent runs, existing keys are discovered by alias and reused.

## Project structure

```
nats-aws-auth/
├── cmd/server/
│   ├── main.go           # Entry point, CLI flag parsing
│   ├── generate.go       # Config generation (--generate)
│   ├── credentials.go    # NACK credential generation (--generate-credentials)
│   ├── authservice.go    # Auth service, auth callout handler
│   └── keys.go           # AWS KMS integration, key types, nkey encoding
├── internal/
│   ├── jwt/              # JWT validator with JWKS support
│   ├── k8s/              # K8s ServiceAccount cache with informer
│   └── auth/             # Pluggable auth backends (K8s OIDC, allow-all)
├── helm/nats-aws-auth/   # Helm chart for Kubernetes deployment
├── testdata/             # Test fixtures (JWKS, tokens)
├── go.mod
├── go.sum
└── .gitignore
```

## Generated files

| File | Description | Gitignored |
|------|-------------|------------|
| `nats-server.conf` | NATS server configuration with embedded JWTs | Yes |
| `nack.creds` | NACK JetStream controller credentials | Yes |
| `sentinel.creds` | Sentinel user credentials for auth callout testing | Yes |
| `jwt/` | NATS JWT resolver directory (runtime) | Yes |
| `jetstream/` | JetStream storage directory (runtime) | Yes |

## Security notes

- Operator, SYS, and APP account private keys are stored exclusively in AWS KMS — no private key material is ever written to disk or held in memory
- The AUTH account and sentinel user keys are generated locally per session (ephemeral)
- The signing key used by the auth callout handler is generated in-memory and not persisted
- KMS is only called at startup, never on the authentication hot path
- NACK credentials (`nack.creds`) contain a user nkey seed — treat as a secret (store as a K8s Secret)
- Sentinel credentials (`sentinel.creds`) are for testing only — the sentinel user has all pub/sub permissions denied, and only serves to trigger the auth callout
- K8s OIDC backend validates JWT signatures via JWKS, enforces issuer/audience/expiry claims
