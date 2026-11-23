# Custodian

**Custodian** is a policy-governed Git ingress and egress broker in Go for humans and coding agents. It provides verifiable Git custody, three-stage inspection (deterministic evidence scanners, server-constructed decision model, CEL policy enforcement), digest-bound human approvals, and isolated PR publication.

## Core Invariants

1. **Credentialless Workspaces**: No GitHub credential is ever exposed to an untrusted workspace or sandbox.
2. **Accountable Human Ownership**: Each workspace and Change Proposal has exactly one accountable human owner established at workspace creation from the verified identity directory (never caller/agent-asserted), with separate agent provenance (`agent_id`, `agent_session_id`, `agent_assisted`).
3. **Commit Attribution & Trailers**: Published commits set the verified human as Author and Custodian as Committer, carrying `Custodian-Proposal`, `Custodian-Workspace`, and `Agent-Assisted` trailers.
4. **Immutable Artifact Approval Binding**: Content is inspected, evaluated, approved, and published against exact immutable artifact digests (`publication_manifest_digest`).
5. **Model Non-Override**: Decision model assessments cannot override mandatory security, secret, or IP policy denials.
6. **Branch-Scoped Publication**: Publication creates or updates only the Custodian-owned PR branch `custodian/<proposal-id>`, publishing one canonical commit and one PR per proposal in v1.
7. **Hardened Publisher Environment**: No user-controlled Git configuration, hook, filter, or executable runs inside the credential-bearing publisher.
8. **End-to-End Traceability**: Every decision links to scanner evidence, model version, policy bundle digest, and human approval, recorded in a hash-chained `audit_events` log.

## Binaries

- `cmd/custodian` — CLI operator and workspace client
- `cmd/custodian-api` — REST API server (`/v1`, OpenAPI 3.1)
- `cmd/custodian-worker` — Asynchronous workflow worker (`FOR UPDATE SKIP LOCKED` leases, outbox, scanners, reconstruction, decision model)
- `cmd/custodian-publisher` — Credential-bearing PR publisher (strictly isolated from inspection/decisions/sandbox packages)
- `cmd/custodian-policy` — Offline CEL `PolicyBundle` compiler, validator, and simulator

## 6-Layer Architecture & Publisher Isolation

Custodian enforces a strict bottom-up package DAG:

- **Layer 0 — Domain & Observability**: `internal/domain` (stdlib + `google/uuid` only: entities, UUIDv7, canonical SHA-256 digests, HTTP-mapped errors, port interfaces) and `internal/observability` (OpenTelemetry tracing, isolated Prometheus metrics registry, ID/digest-only structured logger).
- **Layer 1 — Persistence, Auth & Storage**: `internal/persistence` (`pgx/v5`, `golang-migrate` embedded migrations, `sqlc`, leases, transactional outbox, hash-chained audit events), `internal/auth`, `internal/identity`, `internal/snapshots` (GCS + local FS), `internal/artifacts`.
- **Layer 2 — Custody & Archive**: `internal/archive`, `internal/git/checkout`, `internal/git/reconstruct`, `internal/git/publish`, `internal/github`, `internal/github/write`.
- **Layer 3 — Inspection & Enforcement**: `internal/inspection` (Stage A), `internal/decisions` & `internal/decisions/schemas` (Stage B), `internal/policy` (Stage C CEL).
- **Layer 4 — Workflow, Isolated Publisher & API**: `internal/repositories`, `internal/workspaces`, `internal/proposals`, `internal/approvals`, `internal/operations`, `internal/audit`, `internal/workflow`, `internal/publication`, `internal/api`.
- **Layer 5 — Binaries & Offline Harnesses**: `cmd/*`, `internal/harness`.

**Publisher Isolation Boundary**: `cmd/custodian-publisher`, `internal/publication`, and `internal/git/publish` NEVER import directly or transitively any package under `internal/inspection/*`, `internal/decisions/*`, `internal/snapshots`, or sandbox/runtime integration packages.

## Repository Layout

```
├── api/                    # OpenAPI 3.1 contract (openapi.yaml, schemas/*.yaml, embed.go)
├── cmd/                    # 5 service/CLI binaries
├── internal/
│   ├── domain/             # Layer 0 pure domain contracts, UUIDv7, digests, errors, ports
│   ├── observability/      # Layer 0 tracing, Prometheus metrics, ID/digest-only slog handler
│   ├── api/openapi/        # Embedded OpenAPI 3.1 loader & validator
│   └── ...                 # Layers 1-5 (persistence, auth, custody, inspection, workflow, harnesses)
├── policies/               # Versioned YAML CEL PolicyBundles and policy test suites
├── prompts/                # Server-only Stage B decision model prompt templates
└── test/
    ├── fixtures/           # Shared integration/adversarial helpers and fixtures
    ├── integration/        # §16 release gate integration tests (RG-01..RG-10)
    ├── adversarial/        # Tier 5 adversarial security & race suites (ADV-01..ADV-12)
    └── e2e/                # Opaque-box E2E suites (Tiers 1–4) and pure-stdlib harness
```

## Development & Build Commands

Requires **Go 1.25+** (`go 1.26.0` declared in `go.mod`). Pass `GO=/path/to/go` to `make` if `go` is not on `PATH`.

```sh
make vet               # Run go vet across all packages
make build             # Build all packages and cmd/* binaries
make test-unit         # Run short unit tests with race detector
make openapi-validate  # Validate api/openapi.yaml & api/schemas/*.yaml offline
make test              # Run full test suite with race detector
make tidy              # Verify go.mod / go.sum tidiness

# Policy bundle tests, §16 release gates, adversarial suites, and opaque-box E2E
./bin/custodian-policy test policies/tests
go test -race ./test/integration/... ./test/adversarial/...
./test/e2e/run_e2e.sh --tier=all
```

See [test/e2e/README.md](test/e2e/README.md) for E2E harness configuration and prerequisites.

## Offline Test Harnesses

All M1–M5 unit, integration, adversarial, and E2E tests execute 100% offline without live cloud or GitHub credentials using:
- Ephemeral `postgres:17-alpine` Docker container (`127.0.0.1::5432`, never colliding with host port `5432`)
- Ephemeral HTTP servers bound to `:0`
- Local bare Git repositories + PR registry harness
- Local filesystem `SnapshotStore`
- Mock OIDC/JWKS server and mock decision model gateway
- Deterministic local/stub scanner runners alongside real CLI adapters
