# Custodian Opaque-Box End-to-End Test Suite (`test/e2e/`)

## Architecture & Opaque-Box Philosophy

The `test/e2e/` suite verifies Custodian (`F-01`–`F-20`, Release Gates `RG-01`–`RG-10`, and Adversarial Scenarios `ADV-01`–`ADV-12`) strictly as an **opaque-box** system through external interfaces only:

- **Tier 1 (`TestT1_*`)**: Category-Partition functional tests (`F-01`..`F-20`, 100 tests).
- **Tier 2 (`TestT2_*`)**: Boundary Value Analysis & Negative/Adversarial tests (`F-01`..`F-20`, 100 tests).
- **Tier 3 (`TestT3_*`)**: Pairwise cross-feature combination tests (26 tests; 236 E2E tests total across Tiers 1–4).
- **Tier 4 (`TestT4_*`)**: End-to-end real-world application workflows (10 scenarios).

### Layout
- `test/e2e/harness/` — Pure Go stdlib test harness (`Env`, `PGDocker`, `MockOIDC`, `BareGitHelper`, `MockGitHub`, `SnapshotStoreHelper`, `MockGateway`, `StubScannerController`, `APIClient`, `Contracts`, `binaries.go` (`BuildOrLocateBinaries`, `RunBinary`, `ResolveGoBin`), archive builders, UUIDv7/audit/secret validators, and 12 self-tests in `harness_test.go`).
- `test/e2e/fixtures/` — Static `PolicyBundle` YAML bundles (`policies/`), golden snapshot/diff/manifest fixtures (`golden/`), labelled Stage B evaluation datasets (`eval/`), and synthetic secret/license/prompt-injection payloads (`payloads/`).
- `test/e2e/run_e2e.sh` — Canonical E2E runner script.
- `test/e2e/tier*_test.go` — Opaque-box E2E test suites.

---

## Prerequisites

1. **Go 1.25+** (`go 1.26.0` in root `go.mod`): Resolved via `$CUSTODIAN_GO_BIN` or `PATH` (`command -v go`).
2. **Docker** (Docker Desktop / OrbStack) with `postgres:17-alpine` available locally (or set `CUSTODIAN_TEST_DSN` to an external PostgreSQL 16+ database).
3. **Git CLI** (`git`).
4. **Offline-only**: No cloud credentials, no internet access, and no preinstalled `gitleaks`, `scancode`, `semgrep`, or `trivy` binaries are required (`StubScannerController` provides deterministic offline wrappers).

---

## Isolation Rules

- **Zero `internal/*` imports**: Neither `test/e2e` nor `test/e2e/harness` ever imports `github.com/timreynolds/custodian/internal/*`.
- **Go stdlib ONLY in `test/e2e/harness/`**: Zero third-party Go dependencies.
- **Single root `go.mod`**: `test/e2e/go.mod` must NEVER exist; tests compile and run against the repository root `go.mod`.
- **Credential separation**: `Env` mirrors production workload isolation — `custodian-api` and `custodian-worker` never receive the write GitHub App private key, and `custodian-publisher` never receives the Model Gateway URL or scanner `PATH`.

---

## Ephemeral Port Allocation

To avoid collisions with pre-existing host services (such as PostgreSQL on `5432` or control-plane HTTP servers on `8080`):
- `PGDocker` binds `-p 127.0.0.1::5432` and discovers the dynamic host port via `docker port` (explicitly rejecting `5432`).
- `custodian-api`, `MockOIDC`, `MockGitHub`, and `MockGateway` bind `127.0.0.1:0` (ephemeral loopback ports, never `8080`).

---

## Wire Alignment via `contracts.go`

Implementation-defined REST/CLI wire details (health/ready/metrics paths, upload capability method/header, status enum strings, `GET /v1/audit/events` query parameter names, and CLI flags/env var keys) are centralized in `test/e2e/harness/contracts.go`.

Defaults can be overridden without editing E2E test logic via:
1. `test/e2e/contracts.json` (or `$CUSTODIAN_E2E_CONTRACTS`)
2. Environment variables (`CUSTODIAN_E2E_HEALTH_PATH`, `CUSTODIAN_E2E_READY_PATH`, `CUSTODIAN_E2E_METRICS_PATH`, `CUSTODIAN_E2E_GATEWAY_FORMAT`, `CUSTODIAN_E2E_UPLOAD_METHOD`, `CUSTODIAN_E2E_UPLOAD_HEADER`)
3. Execution overrides:
   - `CUSTODIAN_E2E_BIN_DIR` — directory of prebuilt binaries (`BuildOrLocateBinaries` skips `go build` when all 5 binaries are present)
   - `CUSTODIAN_E2E_ROOT` — explicit repository root override used by `Env` and fixture loaders
   - `CUSTODIAN_E2E_ALLOW_DOCKER_SKIP=1` — skips `PGDocker` tests when the Docker daemon is unavailable

---

## Running Tests

```bash
# Run harness self-tests only
./test/e2e/run_e2e.sh --harness-only

# Compile-check and vet all E2E suites without running
./test/e2e/run_e2e.sh --compile-only --tier=all

# Run specific tiers or full suite
./test/e2e/run_e2e.sh --tier=1
./test/e2e/run_e2e.sh --tier=2
./test/e2e/run_e2e.sh --tier=3
./test/e2e/run_e2e.sh --tier=4
./test/e2e/run_e2e.sh --tier=all
```
