# Contributing to Custodian

Thanks for your interest in contributing to Custodian!

## Prerequisites

- **Go 1.25+** (`go 1.26.0` in [go.mod](go.mod))
- **Git CLI** (`git`)
- **Docker** (required only for PostgreSQL integration and end-to-end tests, which spin up an ephemeral `postgres:17-alpine` container automatically)

## Local Development Workflow

Run the standard checks locally before opening a pull request:

```sh
# Format and static analysis
gofmt -l .
make vet

# Build all 6 binaries into ./bin/
make build

# Run short unit tests with the race detector
make test-unit

# Validate the OpenAPI 3.1 contract offline
make openapi-validate

# Validate and run policy test suites
./bin/custodian-policy test policies/tests
```

If you have Docker running, you can also run the full integration, adversarial, and end-to-end suites (everything runs 100% offline):

```sh
go test -race ./test/integration/... ./test/adversarial/...
./test/e2e/run_e2e.sh --tier=all
```

See [test/e2e/README.md](test/e2e/README.md) for options to run individual E2E tiers.

## Architecture Boundaries to Preserve

CI checks three strict package boundaries to maintain Custodian's security guarantees:

1. **Pure Domain Layer**: `internal/domain` may only import the Go standard library and `github.com/google/uuid`.
2. **Publisher Isolation**: `cmd/custodian-publisher`, `internal/publication`, and `internal/git/publish` must never import packages under `internal/inspection`, `internal/decisions`, `internal/policy`, `internal/snapshots`, `internal/gitgateway`, or sandbox-related packages.
3. **Opaque-Box E2E Tests**: Packages under `test/e2e` must never import `internal/*`, and `test/e2e/harness` may only use the Go standard library.

## Pull Request Checklist

- Code is formatted with `gofmt` and passes `make vet` and `make test-unit`.
- `go mod tidy` produces no unexpected changes.
- Any API changes are reflected in [api/openapi.yaml](api/openapi.yaml) and pass `make openapi-validate`.
- Any policy schema or CLI flag changes include updated tests and documentation.
- New features or behavior changes are documented clearly in plain English.
