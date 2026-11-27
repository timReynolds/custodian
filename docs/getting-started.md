# Getting Started & Configuration

This guide explains how to build Custodian, what external services you need to run the full stack, and how to configure each service.

> **Just want to try the CLI and policy engine offline?** See the [Quick Start in README.md](../README.md#quick-start-try-it-locally).

## Prerequisites

- **Go 1.25+** (`go 1.26.0` declared in [go.mod](../go.mod))
- **Git CLI** (`git`)
- **PostgreSQL 16+** (tested on PostgreSQL 17)
- **OIDC Identity Provider** (issues JWTs verified via OIDC discovery / JWKS)
- **Two separate GitHub Apps**:
  - A **read-only GitHub App** used by `custodian-api`, `custodian-worker`, and `custodian-git-gateway` to resolve refs and read repositories.
  - A **write-only GitHub App** used exclusively by `custodian-publisher` (and `custodian-git-gateway` when forwarding pushes) so workspace/scanning processes never hold write credentials.
- **Optional Stage A Scanners**: `gitleaks`, `scancode`, `semgrep`, and `trivy` on `PATH` (or configured via environment variables).
- **Optional Snapshot Storage**: Local disk (`CUSTODIAN_SNAPSHOT_STORE=local`) or Google Cloud Storage (`CUSTODIAN_SNAPSHOT_STORE=gcs`).

## Building from Source

Build all 6 binaries into `./bin/`:

```sh
make build
```

This produces:

- `bin/custodian`
- `bin/custodian-api`
- `bin/custodian-worker`
- `bin/custodian-publisher`
- `bin/custodian-git-gateway`
- `bin/custodian-policy`

## Database Migrations

Embedded PostgreSQL migrations run automatically when `custodian-api` or `custodian-git-gateway` starts. Point all services at the same PostgreSQL database via `CUSTODIAN_DATABASE_URL`.

## Operational Endpoints

`custodian-api` exposes unauthenticated operational endpoints on `CUSTODIAN_LISTEN_ADDR`:

- `GET /healthz` — Liveness check
- `GET /readyz` — Readiness check (verifies PostgreSQL connectivity)
- `GET /metrics` — Prometheus metrics

## Service Configuration

### `custodian-api`

The REST API server (`/v1`, defined in [api/openapi.yaml](../api/openapi.yaml)).

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `CUSTODIAN_DATABASE_URL` | Yes | — | PostgreSQL connection DSN |
| `CUSTODIAN_OIDC_ISSUER` | Yes | — | OIDC issuer URL |
| `CUSTODIAN_OIDC_AUDIENCE` | Yes | — | Expected JWT audience |
| `CUSTODIAN_OIDC_JWKS_URL` | No | From discovery | Explicit JWKS URL override |
| `CUSTODIAN_CAPABILITY_HMAC_SECRET` | Yes | — | HMAC-SHA256 secret (minimum 32 bytes) for upload capability URLs |
| `CUSTODIAN_GITHUB_READ_APP_ID` | Yes | — | Read-only GitHub App ID |
| `CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM` | Yes* | — | Read-only GitHub App RSA private key PEM (*or use `_FILE`) |
| `CUSTODIAN_GITHUB_READ_PRIVATE_KEY_FILE` | Yes* | — | Path to read-only GitHub App PEM file |
| `CUSTODIAN_SNAPSHOT_STORE` | No | `local` | Snapshot backend: `local` or `gcs` |
| `CUSTODIAN_SNAPSHOT_ROOT` | If `local` | — | Local directory for snapshot artifacts (alias: `CUSTODIAN_SNAPSHOT_DIR`) |
| `CUSTODIAN_SNAPSHOT_BUCKET` | If `gcs` | — | GCS bucket name (alias: `CUSTODIAN_GCS_BUCKET`) |
| `CUSTODIAN_SNAPSHOT_PREFIX` | No | `""` | Optional GCS object prefix (alias: `CUSTODIAN_GCS_PREFIX`) |
| `CUSTODIAN_LISTEN_ADDR` | No | `127.0.0.1:8080` | HTTP listen address |
| `CUSTODIAN_API_PUBLIC_URL` | No | — | Public base URL used in generated capability URLs (alias: `CUSTODIAN_BASE_URL`) |
| `CUSTODIAN_POLICY_DIR` | No | — | Directory of YAML `PolicyBundle` files to seed on startup |
| `CUSTODIAN_GITHUB_API_URL` | No | `https://api.github.com/` | GitHub API base URL (for GitHub Enterprise or mock servers) |
| `CUSTODIAN_MAX_UPLOAD_BYTES` | No | `67108864` (64 MiB) | Maximum workspace snapshot upload size |
| `CUSTODIAN_CAPABILITY_TTL` | No | `5m` | Expiration duration for signed upload capability URLs |
| `CUSTODIAN_ARTIFACT_RETENTION` | No | `720h` | Retention TTL for transient artifacts |
| `CUSTODIAN_REPO_CONCURRENCY_LIMIT` | No | `0` (unlimited) | Default per-repository active operation cap |
| `CUSTODIAN_GLOBAL_SCAN_BUDGET` | No | `0` (unlimited) | Global concurrent scan budget |
| `CUSTODIAN_GLOBAL_MODEL_BUDGET` | No | `0` (unlimited) | Global concurrent model assessment budget |
| `CUSTODIAN_LOG_FORMAT` | No | `json` | `json` or `text` |
| `CUSTODIAN_LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, or `error` |
| `CUSTODIAN_OTEL_MODE` | No | `noop` | OpenTelemetry trace mode: `noop`, `stdout`, or `otlp_http` |

### `custodian-worker`

Runs repository checkouts, snapshot reconstruction, automated scanners, optional AI review, and policy evaluation.

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `CUSTODIAN_DATABASE_URL` | Yes | — | PostgreSQL connection DSN |
| `CUSTODIAN_SNAPSHOT_STORE` | No | `local` | `local` or `gcs` |
| `CUSTODIAN_SNAPSHOT_DIR` | If `local` | — | Local snapshot directory |
| `CUSTODIAN_SNAPSHOT_BUCKET` | If `gcs` | — | GCS bucket name |
| `CUSTODIAN_GITHUB_READ_APP_ID` | Yes* | — | Read-only GitHub App ID (*unless `CUSTODIAN_LOCAL_BARE_GIT_DIR` is set) |
| `CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM` / `_FILE` | Yes* | — | Read-only GitHub App RSA private key |
| `CUSTODIAN_LOCAL_BARE_GIT_DIR` | No | — | Local bare Git repositories directory for offline development |
| `CUSTODIAN_POLICY_DIR` | No | `policies/defaults` | Policy bundle directory |
| `CUSTODIAN_MODEL_GATEWAY_URL` | No | — | Optional AI review model gateway URL |
| `CUSTODIAN_ROUTE_POLICY_JSON` | No | Built-in defaults | JSON constraints mapping data classifications to allowed model routes |
| `CUSTODIAN_GITLEAKS_BIN` | No | `gitleaks` | Path to `gitleaks` binary |
| `CUSTODIAN_SCANCODE_BIN` | No | `scancode` | Path to `scancode` binary |
| `CUSTODIAN_SEMGREP_BIN` | No | `semgrep` | Path to `semgrep` binary |
| `CUSTODIAN_TRIVY_BIN` | No | `trivy` | Path to `trivy` binary |
| `CUSTODIAN_SCANNER_TIMEOUT` | No | `60s` | Per-scanner execution timeout |
| `CUSTODIAN_WORKER_CONCURRENCY` | No | `1` | Number of concurrent leased jobs |

### `custodian-publisher`

Isolated binary that pushes approved changes to `custodian/<proposal-id>` and opens pull requests. Keep this service separated from `custodian-worker`: it never receives scanner binaries, model gateway URLs, or OIDC capability secrets.

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `CUSTODIAN_DATABASE_URL` | Yes | — | PostgreSQL connection DSN |
| `CUSTODIAN_SNAPSHOT_STORE` | No | `local` | `local` or `gcs` |
| `CUSTODIAN_SNAPSHOT_DIR` | If `local` | — | Local snapshot directory |
| `CUSTODIAN_SNAPSHOT_BUCKET` | If `gcs` | — | GCS bucket name |
| `CUSTODIAN_GITHUB_WRITE_APP_ID` | Yes | — | Write-only GitHub App ID |
| `CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM` / `_FILE` | Yes | — | Write-only GitHub App RSA private key |
| `CUSTODIAN_GITHUB_API_URL` | No | `https://api.github.com/` | GitHub API base URL |
| `CUSTODIAN_PUBLISHER_COMMITTER_NAME` | No | `Custodian` | Git committer name for published commits |
| `CUSTODIAN_PUBLISHER_COMMITTER_EMAIL` | No | `custodian@custodian.local` | Git committer email for published commits |
| `CUSTODIAN_PUBLISHER_CONCURRENCY` | No | `1` | Number of concurrent publish jobs |

### `custodian-git-gateway`

HTTPS and SSH Git push proxy. See [Git Push Gateway](push-gateway.md) for usage details.

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `CUSTODIAN_DATABASE_URL` | Yes | — | PostgreSQL connection DSN |
| `CUSTODIAN_SNAPSHOT_STORE` | No | `local` | `local` or `gcs` |
| `CUSTODIAN_SNAPSHOT_DIR` | If `local` | — | Local snapshot directory (alias: `CUSTODIAN_SNAPSHOT_ROOT`) |
| `CUSTODIAN_OIDC_ISSUER` | Yes | — | OIDC issuer URL |
| `CUSTODIAN_OIDC_AUDIENCE` | Yes | — | Expected JWT audience |
| `CUSTODIAN_GIT_GATEWAY_HTTP_ADDR` | No | `127.0.0.1:8443` | HTTPS smart-HTTP listen address |
| `CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE` | Yes | — | TLS server certificate PEM file |
| `CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE` | Yes | — | TLS server private key PEM file |
| `CUSTODIAN_GIT_GATEWAY_SSH_ADDR` | No | `127.0.0.1:2222` | SSH listen address (set to `off` or `disabled` to disable SSH) |
| `CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE` | If SSH enabled | — | SSH host private key file |
| `CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE` | If SSH enabled | — | OpenSSH User CA public key file |
| `CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL` | No | `https://github.com` | Upstream Git remote base URL |
| `CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE` | No | `ENFORCE_BLOCK` | Default mode: `ENFORCE_BLOCK`, `PASSIVE_AUDIT`, or `ENFORCE_PR` |
| `CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY` | No | `ASYNC` | Passive audit warning delivery: `ASYNC` or `INLINE_WARN` |
| `CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES` | No | `67108864` (64 MiB) | Max incoming Git pack size |
| `CUSTODIAN_GIT_GATEWAY_MAX_OBJECTS` | No | `10000` | Max Git objects per push |
| `CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES` | No | `33554432` (32 MiB) | Max inflated object size |
| `CUSTODIAN_GIT_GATEWAY_MAX_REF_UPDATES` | No | `100` | Max ref updates per push |
| `CUSTODIAN_GITHUB_READ_APP_ID` / `WRITE_APP_ID` | Optional | — | GitHub App credentials for upstream reads and push forwarding |

## Next Steps

- Walk through creating a workspace and publishing a PR in [Workspace & Pull Request Workflow](usage.md).
- Set up push protection in [Git Push Gateway](push-gateway.md).
- Customize rules in [Writing & Testing Policies](policies.md).
