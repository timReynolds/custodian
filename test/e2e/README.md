# End-to-End Test Suite (`test/e2e/`)

The `test/e2e/` suite verifies Custodian as a complete **opaque-box** system, interacting with all 6 binaries only through their CLI commands, REST API, and Git HTTPS/SSH interfaces:

- **Tier 1 (`TestT1_*`)**: Core functional coverage across workspaces, proposals, inspection, policies, approvals, publication, and the Push Gateway.
- **Tier 2 (`TestT2_*`)**: Boundary cases, negative tests, and security/isolation checks.
- **Tier 3 (`TestT3_*`)**: Cross-feature pairwise combination tests.
- **Tier 4 (`TestT4_*`)**: Full end-to-end real-world workflow scenarios.

## Layout

- `test/e2e/harness/` — Pure Go stdlib test harness (`Env`, ephemeral `postgres:17-alpine` Docker runner, mock OIDC/JWKS server, bare Git + mock GitHub servers, local snapshot store, mock AI gateway, stub scanner controller, API client, and process supervisor) plus harness self-tests in `harness_test.go`.
- `test/e2e/fixtures/` — Policy bundles, golden diffs/manifests, evaluation datasets, and synthetic test payloads.
- `test/e2e/run_e2e.sh` — E2E test runner script.
- `test/e2e/tier*_test.go` — E2E test suites.

## Prerequisites

1. **Go 1.25+** (`go 1.26.0` in root [go.mod](../../go.mod)), resolved via `$CUSTODIAN_GO_BIN` or `PATH`.
2. **Docker** (Docker Desktop / OrbStack) with `postgres:17-alpine` available locally (or set `CUSTODIAN_TEST_DSN` to an external PostgreSQL 16+ database).
3. **Git CLI** (`git`).
4. **100% Offline**: No cloud credentials, internet access, or preinstalled `gitleaks`, `scancode`, `semgrep`, or `trivy` binaries are required.

## Isolation Rules

- **Zero `internal/*` imports**: Neither `test/e2e` nor `test/e2e/harness` ever imports `github.com/timreynolds/custodian/internal/*`.
- **Go stdlib only in `test/e2e/harness/`**: Zero third-party Go dependencies.
- **Single root `go.mod`**: `test/e2e` compiles against the repository root `go.mod`.
- **Credential separation**: The test harness mirrors production isolation—`custodian-api` and `custodian-worker` never receive the write GitHub App private key, and `custodian-publisher` never receives the model gateway URL or scanner binaries.

## Ephemeral Ports

To avoid colliding with local services (such as PostgreSQL on `5432` or a local server on `8080`):
- PostgreSQL Docker containers bind `-p 127.0.0.1::5432` and discover the dynamic port via `docker port`.
- `custodian-api`, mock OIDC, mock GitHub, and mock model gateway bind `127.0.0.1:0`.

## Configuration Overrides

- `CUSTODIAN_E2E_BIN_DIR` — Directory of prebuilt binaries (skips `go build` when binaries are present)
- `CUSTODIAN_E2E_ROOT` — Explicit repository root override
- `CUSTODIAN_E2E_ALLOW_DOCKER_SKIP=1` — Skip Docker-backed PostgreSQL tests if Docker is unavailable
- `test/e2e/contracts.json` (or `$CUSTODIAN_E2E_CONTRACTS`) — Override default paths/flags defined in `test/e2e/harness/contracts.go`

## Running Tests

```sh
# Run harness self-tests only
./test/e2e/run_e2e.sh --harness-only

# Vet and compile-check all E2E suites without running them
./test/e2e/run_e2e.sh --compile-only --tier=all

# Run Push Gateway E2E tests
./test/e2e/run_e2e.sh --push-gateway

# Run specific tiers or the full suite
./test/e2e/run_e2e.sh --tier=1
./test/e2e/run_e2e.sh --tier=2
./test/e2e/run_e2e.sh --tier=3
./test/e2e/run_e2e.sh --tier=4
./test/e2e/run_e2e.sh --tier=all
```
