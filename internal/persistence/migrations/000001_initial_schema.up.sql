-- Custodian Layer 1 Initial PostgreSQL 16+ Schema (Spec §10 + M1-M5 Reconciliations)

-- 1. principals
CREATE TABLE principals (
    id             UUID PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('HUMAN', 'AGENT', 'SERVICE')),
    issuer         TEXT,
    subject        TEXT,
    display_name   TEXT,
    verified_email TEXT,
    groups         TEXT[] NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject),
    CHECK ((issuer IS NULL AND subject IS NULL) OR (issuer IS NOT NULL AND subject IS NOT NULL))
);

-- 2. repositories
CREATE TABLE repositories (
    id                        UUID PRIMARY KEY,
    github_repository_id      BIGINT NOT NULL UNIQUE CHECK (github_repository_id > 0),
    github_installation_id    BIGINT NOT NULL CHECK (github_installation_id > 0),
    full_name                 TEXT NOT NULL CHECK (full_name ~ '^[^/\s]+/[^/\s]+$'),
    classification            TEXT NOT NULL CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    enabled                   BOOLEAN NOT NULL DEFAULT true,
    allowed_model_routes      TEXT[] NOT NULL DEFAULT '{}',
    max_concurrent_operations INTEGER NOT NULL DEFAULT 10 CHECK (max_concurrent_operations > 0),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. artifacts
CREATE TABLE artifacts (
    id                   UUID PRIMARY KEY,
    kind                 TEXT NOT NULL CHECK (kind IN (
        'WORKSPACE_SOURCE',
        'SOURCE_MANIFEST',
        'EGRESS_SNAPSHOT',
        'CANONICAL_TREE',
        'CANONICAL_DIFF',
        'PUBLICATION_MANIFEST',
        'SCAN_EVIDENCE',
        'MODEL_EVIDENCE'
    )),
    sha256               CHAR(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    storage_key          TEXT NOT NULL CHECK (storage_key <> ''),
    storage_generation   TEXT NOT NULL CHECK (storage_generation <> ''),
    size_bytes           BIGINT NOT NULL CHECK (size_bytes >= 0),
    format               TEXT NOT NULL DEFAULT 'application/octet-stream' CHECK (format <> ''),
    workspace_id         UUID,
    workspace_generation BIGINT CHECK (workspace_generation IS NULL OR workspace_generation >= 1),
    uploaded_by          UUID REFERENCES principals(id),
    expires_at           TIMESTAMPTZ,
    deleted_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (storage_key, storage_generation)
);

CREATE INDEX idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX idx_artifacts_expires ON artifacts(expires_at) WHERE expires_at IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_artifacts_workspace ON artifacts(workspace_id) WHERE workspace_id IS NOT NULL;

-- 4. workspaces
CREATE TABLE workspaces (
    id                   UUID PRIMARY KEY,
    repository_id        UUID NOT NULL REFERENCES repositories(id),
    owner_id             UUID NOT NULL REFERENCES principals(id),
    agent_id             UUID REFERENCES principals(id),
    agent_type           TEXT,
    agent_session_id     TEXT,
    model_route          TEXT,
    base_commit          CHAR(40) NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
    target_ref           TEXT NOT NULL CHECK (target_ref <> ''),
    source_artifact_id   UUID,
    include_git_metadata BOOLEAN NOT NULL DEFAULT false,
    include_history      BOOLEAN NOT NULL DEFAULT false,
    generation           BIGINT NOT NULL DEFAULT 1 CHECK (generation >= 1),
    status               TEXT NOT NULL CHECK (status IN ('PENDING', 'PREPARING', 'READY', 'FAILED', 'CLOSED')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE workspaces
    ADD CONSTRAINT fk_workspace_source
    FOREIGN KEY (source_artifact_id) REFERENCES artifacts(id);

ALTER TABLE artifacts
    ADD CONSTRAINT fk_artifact_workspace
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id);

CREATE INDEX idx_workspaces_repository ON workspaces(repository_id, created_at DESC);
CREATE INDEX idx_workspaces_owner ON workspaces(owner_id, created_at DESC);
CREATE INDEX idx_workspaces_status ON workspaces(status);

-- 5. proposals
CREATE TABLE proposals (
    id                           UUID PRIMARY KEY,
    workspace_id                 UUID NOT NULL REFERENCES workspaces(id),
    owner_id                     UUID NOT NULL REFERENCES principals(id),
    snapshot_artifact_id         UUID NOT NULL REFERENCES artifacts(id),
    canonical_artifact_id        UUID REFERENCES artifacts(id),
    diff_artifact_id             UUID REFERENCES artifacts(id),
    manifest_artifact_id         UUID REFERENCES artifacts(id),
    base_commit                  CHAR(40) NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
    target_ref                   TEXT NOT NULL CHECK (target_ref <> ''),
    title                        TEXT NOT NULL DEFAULT '',
    description                  TEXT,
    provenance_type              TEXT NOT NULL DEFAULT 'agent_assisted' CHECK (provenance_type IN ('agent_assisted', 'human_authored')),
    capture_method               TEXT NOT NULL DEFAULT 'frozen_filesystem' CHECK (capture_method IN ('frozen_filesystem', 'patch_upload')),
    tree_digest                  TEXT,
    diff_digest                  CHAR(64) CHECK (diff_digest IS NULL OR diff_digest ~ '^[0-9a-f]{64}$'),
    manifest_digest              CHAR(64) CHECK (manifest_digest IS NULL OR manifest_digest ~ '^[0-9a-f]{64}$'),
    latest_policy_evaluation_id  UUID,
    latest_policy_effect         TEXT CHECK (latest_policy_effect IS NULL OR latest_policy_effect IN ('DENY', 'QUARANTINE', 'REQUIRE_REMEDIATION', 'REQUIRE_APPROVAL', 'ALLOW')),
    status                       TEXT NOT NULL CHECK (status IN (
        'CAPTURED',
        'RECONSTRUCTING',
        'RECONSTRUCTED',
        'EVALUATING',
        'PENDING_APPROVAL',
        'DENIED',
        'QUARANTINED',
        'REMEDIATION_REQUIRED',
        'REJECTED',
        'APPROVED',
        'PUBLISHING',
        'PUBLISHED',
        'FAILED'
    )),
    version                      BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_proposals_workspace ON proposals(workspace_id, created_at DESC);
CREATE INDEX idx_proposals_owner ON proposals(owner_id, created_at DESC);

-- 6. scan_runs
CREATE TABLE scan_runs (
    id              UUID PRIMARY KEY,
    proposal_id     UUID NOT NULL REFERENCES proposals(id),
    artifact_id     UUID NOT NULL REFERENCES artifacts(id),
    scanner         TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT', 'INCOMPLETE')),
    coverage        JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_scan_runs_proposal ON scan_runs(proposal_id, started_at DESC);

-- 7. findings
CREATE TABLE findings (
    id                   UUID PRIMARY KEY,
    scan_run_id          UUID NOT NULL REFERENCES scan_runs(id),
    evidence_id          TEXT,
    scanner              TEXT,
    category             TEXT NOT NULL,
    severity             TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    rule_id              TEXT NOT NULL,
    path                 TEXT,
    start_line           INTEGER CHECK (start_line IS NULL OR start_line >= 0),
    end_line             INTEGER CHECK (end_line IS NULL OR end_line >= 0),
    fingerprint          TEXT NOT NULL,
    evidence_artifact_id UUID REFERENCES artifacts(id),
    evidence_ref         TEXT,
    baseline             TEXT,
    confidence           DOUBLE PRECISION CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    message              TEXT,
    redacted             BOOLEAN NOT NULL DEFAULT true,
    metadata             JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_findings_scan ON findings(scan_run_id);

-- 8. model_assessments
CREATE TABLE model_assessments (
    id              UUID PRIMARY KEY,
    proposal_id     UUID NOT NULL REFERENCES proposals(id),
    artifact_id     UUID NOT NULL REFERENCES artifacts(id),
    model_route     TEXT NOT NULL,
    model_version   TEXT NOT NULL,
    prompt_version  TEXT NOT NULL,
    assessment_type TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETE', 'INDETERMINATE', 'FAILED')),
    risk            TEXT CHECK (risk IS NULL OR risk IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    disposition     TEXT CHECK (disposition IS NULL OR disposition IN ('CLEAR', 'REVIEW', 'ESCALATE', 'BLOCK', 'INDETERMINATE')),
    result          JSONB NOT NULL,
    evidence_ids    JSONB NOT NULL DEFAULT '[]'::jsonb,
    input_digest    CHAR(64) NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    output_digest   CHAR(64) NOT NULL CHECK (output_digest ~ '^[0-9a-f]{64}$'),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_model_assessments_proposal ON model_assessments(proposal_id, created_at DESC);

-- 9. policy_bundles
CREATE TABLE policy_bundles (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    scope         TEXT NOT NULL CHECK (scope IN ('ORG', 'REPO')),
    repository_id UUID REFERENCES repositories(id),
    digest        CHAR(64) NOT NULL UNIQUE CHECK (digest ~ '^[0-9a-f]{64}$'),
    definition    JSONB NOT NULL,
    activated_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_bundles_scope_repo ON policy_bundles(scope, repository_id);

-- 10. policy_decisions
CREATE TABLE policy_decisions (
    id               UUID PRIMARY KEY,
    proposal_id      UUID NOT NULL REFERENCES proposals(id),
    policy_bundle_id UUID NOT NULL REFERENCES policy_bundles(id),
    org_bundle_id    UUID REFERENCES policy_bundles(id),
    repo_bundle_id   UUID REFERENCES policy_bundles(id),
    stage            TEXT NOT NULL DEFAULT 'EGRESS' CHECK (stage IN ('INGRESS', 'EGRESS')),
    input_digest     CHAR(64) NOT NULL CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    effect           TEXT NOT NULL CHECK (effect IN ('DENY', 'QUARANTINE', 'REQUIRE_REMEDIATION', 'REQUIRE_APPROVAL', 'ALLOW')),
    reasons          JSONB NOT NULL,
    obligations      JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_decisions_proposal ON policy_decisions(proposal_id, created_at DESC);

ALTER TABLE proposals
    ADD CONSTRAINT fk_proposals_latest_policy_eval
    FOREIGN KEY (latest_policy_evaluation_id) REFERENCES policy_decisions(id);

-- 11. approvals
CREATE TABLE approvals (
    id                 UUID PRIMARY KEY,
    proposal_id        UUID NOT NULL REFERENCES proposals(id),
    reviewer_id        UUID NOT NULL REFERENCES principals(id),
    policy_decision_id UUID NOT NULL REFERENCES policy_decisions(id),
    manifest_digest    CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    decision           TEXT NOT NULL CHECK (decision IN ('APPROVE', 'REJECT')),
    comment            TEXT,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_approvals_proposal ON approvals(proposal_id, created_at DESC);

-- 12. publications
CREATE TABLE publications (
    id                  UUID PRIMARY KEY,
    proposal_id         UUID NOT NULL UNIQUE REFERENCES proposals(id),
    branch_ref          TEXT NOT NULL CHECK (branch_ref = 'custodian/' || proposal_id::text OR branch_ref = 'refs/heads/custodian/' || proposal_id::text),
    commit_sha          CHAR(40) CHECK (commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{40}$'),
    pull_request_number BIGINT,
    pull_request_url    TEXT,
    status              TEXT NOT NULL CHECK (status IN ('PENDING', 'PUBLISHING', 'PUBLISHED', 'FAILED')),
    attempt_count       INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 13. operations
CREATE TABLE operations (
    id             UUID PRIMARY KEY,
    operation_type TEXT NOT NULL CHECK (operation_type IN ('WORKSPACE_INGRESS', 'PROPOSAL_RECONSTRUCT', 'PROPOSAL_EVALUATE', 'PROPOSAL_PUBLISH')),
    resource_type  TEXT,
    resource_id    UUID NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts   INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts >= 1),
    available_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until    TIMESTAMPTZ,
    leased_by      TEXT,
    last_error     TEXT,
    result         JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at   TIMESTAMPTZ
);

CREATE INDEX idx_operations_ready ON operations(available_at) WHERE status = 'PENDING';
CREATE INDEX idx_operations_running_lease ON operations(lease_until) WHERE status = 'RUNNING';
CREATE INDEX idx_operations_resource ON operations(resource_id, created_at DESC);

-- 14. audit_events
CREATE TABLE audit_events (
    id            UUID PRIMARY KEY,
    chain_seq     BIGINT NOT NULL UNIQUE CHECK (chain_seq >= 1),
    event_type    TEXT NOT NULL CHECK (event_type <> ''),
    actor_id      UUID REFERENCES principals(id),
    resource_type TEXT NOT NULL CHECK (resource_type <> ''),
    resource_id   UUID NOT NULL,
    payload       JSONB NOT NULL,
    previous_hash CHAR(64) CHECK (previous_hash IS NULL OR previous_hash ~ '^[0-9a-f]{64}$'),
    event_hash    CHAR(64) NOT NULL UNIQUE CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id, created_at);
CREATE INDEX idx_audit_created_id ON audit_events(created_at, id);
CREATE INDEX idx_audit_actor ON audit_events(actor_id, created_at) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_event_type ON audit_events(event_type, created_at);

-- 15. outbox_events
CREATE TABLE outbox_events (
    id           UUID PRIMARY KEY,
    event_type   TEXT NOT NULL CHECK (event_type <> ''),
    aggregate_id UUID NOT NULL,
    payload      JSONB NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until  TIMESTAMPTZ,
    leased_by    TEXT,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX idx_outbox_pending ON outbox_events(available_at, created_at) WHERE delivered_at IS NULL;

-- 16. idempotency_keys
CREATE TABLE idempotency_keys (
    principal_id     UUID NOT NULL REFERENCES principals(id),
    method           TEXT NOT NULL CHECK (method <> ''),
    route            TEXT NOT NULL CHECK (route <> ''),
    idempotency_key  TEXT NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_hash     CHAR(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    status           TEXT NOT NULL CHECK (status IN ('IN_PROGRESS', 'COMPLETED')),
    response_status  INTEGER,
    response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_body    JSONB,
    locked_until     TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at     TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal_id, method, route, idempotency_key)
);

CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);

-- 17. approval_requirements
CREATE TABLE approval_requirements (
    id                 UUID PRIMARY KEY,
    proposal_id        UUID NOT NULL REFERENCES proposals(id),
    policy_decision_id UUID NOT NULL REFERENCES policy_decisions(id),
    requirement_type   TEXT NOT NULL,
    reviewer_group     TEXT NOT NULL,
    minimum_approvals  INTEGER NOT NULL CHECK (minimum_approvals >= 1),
    satisfied_count    INTEGER NOT NULL DEFAULT 0 CHECK (satisfied_count >= 0),
    satisfied_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_decision_id, requirement_type, reviewer_group)
);

CREATE INDEX idx_approval_reqs_proposal ON approval_requirements(proposal_id);

-- 18. publication_attempts
CREATE TABLE publication_attempts (
    id              UUID PRIMARY KEY,
    publication_id  UUID NOT NULL REFERENCES publications(id),
    attempt_number  INTEGER NOT NULL CHECK (attempt_number >= 1),
    manifest_digest CHAR(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    status          TEXT NOT NULL CHECK (status IN ('STARTED', 'SUCCEEDED', 'FAILED')),
    commit_sha      CHAR(40) CHECK (commit_sha IS NULL OR commit_sha ~ '^[0-9a-f]{40}$'),
    error_code      TEXT,
    error_message   TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    UNIQUE (publication_id, attempt_number)
);

-- 19. audit_chain_head
CREATE TABLE audit_chain_head (
    chain_id        TEXT PRIMARY KEY,
    last_event_id   UUID REFERENCES audit_events(id),
    last_event_hash CHAR(64) CHECK (last_event_hash IS NULL OR last_event_hash ~ '^[0-9a-f]{64}$'),
    event_count     BIGINT NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO audit_chain_head (chain_id, last_event_id, last_event_hash, event_count)
VALUES ('default', NULL, NULL, 0)
ON CONFLICT (chain_id) DO NOTHING;
