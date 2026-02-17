# NACK Authentication Design

## Problem

NACK needs to connect to the NATS server to manage JetStream resources (Streams, Consumers) via CRDs. The server uses operator/account JWT auth with an auth callout. NACK needs credentials that work within this setup.

## Approach

Extend the `--generate` workflow with a new `--generate-credentials` command that produces a pre-signed NACK credentials file. NACK authenticates directly with the NATS server using the pre-signed JWT — it bypasses the auth callout entirely.

### Key Design Decision: Stable APP Account Key in KMS

Today the APP account identity key is generated ephemerally by the auth service at each startup. This means we can't pre-sign user JWTs at generate time because the account identity isn't known yet.

We promote the APP account key to KMS (same pattern as Operator and SYS), making it stable across restarts. This allows `--generate-credentials` to sign NACK user JWTs against a known, long-lived account identity.

The auth service's ephemeral signing key (used for auth callout) is unchanged — no KMS calls on the hot path.

## NACK Permissions

NACK needs full JetStream API access within the APP account:

```
Pub allow:  $JS.API.>
Sub allow:  $JS.API.>, _INBOX.>
```

## Authentication Paths

| Client | Auth mechanism | KMS involved at runtime? |
|--------|---------------|--------------------------|
| Applications | Auth callout, ephemeral in-memory key | No |
| NACK | Pre-signed JWT from `--generate-credentials` | No |

KMS is only used at startup (auth service fetching APP account public key) and at generate time.

## New CLI Command: `--generate-credentials`

Separate from `--generate` because `--generate` produces public config (`nats-server.conf`) while credentials contain private nkey seeds.

Steps:
1. Fetch/create APP account key from KMS (`alias/nats-app-account`)
2. Generate NACK user keypair (local, in-memory)
3. Create NACK user JWT signed by APP account key, with JetStream permissions
4. Write `nack.creds` (JWT + nkey seed)

The APP account KMS key is created on first use (get-or-create pattern, same as Operator/SYS).

### New flag

`--app-account-key-alias` (default: `alias/nats-app-account`)

## Auth Service Startup Changes

The auth service uses the KMS-backed APP account key instead of generating an ephemeral one for the account identity.

### Startup flow

1. Fetch APP account key from KMS (`--app-account-key-alias`)
2. Derive public key — this is the APP account's stable identity
3. Generate ephemeral signing keypair (local, in-memory) for auth callout
4. Check if APP account JWT already exists in the resolver
5. If exists: fetch it, add ephemeral signing key to `SigningKeys`, re-publish
6. If not: create new APP account JWT using the KMS public key as identity, add ephemeral signing key, publish

If `--app-account-key-alias` is not provided, the auth service falls back to the current ephemeral behaviour for backwards compatibility.

### Two signing authorities in the APP account

- **Stable KMS key**: Signs pre-provisioned user JWTs (NACK). Valid indefinitely.
- **Ephemeral key**: Signs per-request user JWTs via auth callout. Rotated on restart, capped at 5.

## Files to Change

| File | Change |
|------|--------|
| `cmd/server/keys.go` | Add `getOrCreateAppAccountKey()` using KMS alias pattern |
| `cmd/server/main.go` | Add `--generate-credentials` command and `--app-account-key-alias` flag |
| `cmd/server/generate.go` | (or new file) Implement `--generate-credentials`: fetch APP key, create NACK user JWT, write `.creds` |
| `cmd/server/authservice.go` | Change APP account setup to use KMS-backed key for account identity |

## Deployment

1. Run `--generate` to produce `nats-server.conf` (existing)
2. Run `--generate-credentials` to produce `nack.creds` (new)
3. Create K8s Secret from `nack.creds`
4. NACK Account CRD references the secret:

```yaml
apiVersion: jetstream.nats.io/v1beta2
kind: Account
metadata:
  name: nack-account
spec:
  servers:
    - nats://nats.messaging:4222
  creds:
    secret:
      name: nack-nats-credentials
      key: creds
```

## CLI Usage

### Generate NACK credentials

```bash
./nats-aws-auth --generate-credentials --app-account-key-alias nats-app-account --output .
```

This creates `nack.creds` in the output directory. The APP account KMS key is created on first run.

### Run auth service with stable APP account key

```bash
./nats-aws-auth --app-account-key-alias nats-app-account
```

When `--app-account-key-alias` is provided, the auth service uses the KMS-backed key for the APP account identity. When omitted, it falls back to ephemeral keys (original behaviour).

## Future Extension

The same `--generate-credentials` command can be extended to produce credentials for other pre-provisioned users (e.g., NATS Box) by adding flags.
