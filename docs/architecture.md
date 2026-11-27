# Architecture & Security Model

Custodian is designed around one core rule: **untrusted code and coding agents never get access to Git credentials, and credential-bearing code never runs untrusted tools**.

## Core Security Guarantees

### 1. Credentialless Workspaces & Verified Human Ownership

- Workspaces receive clean source archives with no GitHub tokens, SSH keys, or credential helpers.
- Every workspace and Change Proposal is bound to a single accountable human owner resolved from your OIDC identity provider—never from caller-supplied fields.
- If a coding agent assists, agent metadata (`agent_id`, `agent_session_id`, `model_route`) is tracked separately alongside human ownership.
- Published commits set the verified human owner as Git `Author`, `Custodian` as `Committer`, and attach `Custodian-Proposal`, `Custodian-Workspace`, and `Agent-Assisted` trailers.

### 2. Strict Publisher Isolation

`custodian-publisher` is the only brokered-workflow binary that holds write-only GitHub App credentials:

- It is a separate binary and deployment boundary from `custodian-api` and `custodian-worker`.
- CI enforces at compile time that `cmd/custodian-publisher`, `internal/publication`, and `internal/git/publish` never import inspection, AI decision-model, snapshot, or gateway packages.
- It executes Git in a hardened environment (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, hooks/filters disabled) and only creates or updates the Custodian-owned branch `custodian/<proposal-id>`.

### 3. Immutable Digest Binding

Every proposal and push is bound to canonical SHA-256 digests (`publication_manifest_digest` and `push_manifest_digest`):

- Scanners, policies, human approvals, and publication all operate on the exact same immutable digest.
- Any modification after inspection or approval invalidates the digest and blocks publication or push forwarding.

### 4. Fail-Closed Inspection & Model Non-Override

- If a mandatory scanner fails, times out, or skips coverage, `findings.scan_complete` becomes `false` and the default policies quarantine the change.
- If the optional Stage B AI review model is used, Custodian builds the prompt server-side from redacted evidence and validates responses against a strict JSON schema.
- The AI model can block or flag suspicious changes, but can never override a mandatory scanner or CEL policy denial.

### 5. Tamper-Evident Audit Log & Redacted Logging

- All lifecycle events are stored in a hash-chained `audit_events` table in PostgreSQL.
- Structured logs emit only resource IDs, statuses, and digests—secrets, tokens, DSNs, private keys, and raw source code are scrubbed automatically.

## Package & Directory Overview

```text
api/            OpenAPI 3.1 contract (openapi.yaml and schemas/*.yaml)
cmd/            The 6 binaries (custodian, custodian-api, custodian-worker,
                custodian-publisher, custodian-git-gateway, custodian-policy)
docs/           User, operator, policy, and architecture documentation
internal/
  domain/       Pure domain types, UUIDv7 IDs, SHA-256 digests, and errors
  observability/ OpenTelemetry tracing, Prometheus metrics, and redacted logging
  persistence/  PostgreSQL store, embedded migrations, leases, and outbox
  auth/, identity/  OIDC JWT verification, identity directory, upload capabilities
  archive/, git/    Safe archive handling, clean checkouts, diff reconstruction, publishing
  inspection/   Stage A scanners, concealment detection, and IP fingerprinting
  decisions/    Stage B server-side prompts, route policy, and schema validation
  policy/       Stage C CEL compiler, evaluator, org/repo composer, and test runner
  gitgateway/   HTTPS/SSH push proxy, packfile quarantine, LFS, and approval releases
  api/          REST handlers, middleware, and embedded OpenAPI validation
policies/       Default and example YAML/CEL PolicyBundles and policy test suites
prompts/        Server-only prompt templates for optional AI risk assessment
test/           Integration, adversarial security, and opaque-box E2E test suites
```
