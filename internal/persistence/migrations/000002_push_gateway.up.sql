-- Custodian Push Gateway & IP Leakage Prevention Schema Extension (Additive to 000001)

-- 1. artifacts: add GIT_PUSH_BUNDLE kind
ALTER TABLE artifacts
    DROP CONSTRAINT artifacts_kind_check,
    ADD CONSTRAINT artifacts_kind_check CHECK (kind IN (
        'WORKSPACE_SOURCE',
        'SOURCE_MANIFEST',
        'EGRESS_SNAPSHOT',
        'CANONICAL_TREE',
        'CANONICAL_DIFF',
        'PUBLICATION_MANIFEST',
        'SCAN_EVIDENCE',
        'MODEL_EVIDENCE',
        'GIT_PUSH_BUNDLE'
    ));

-- 2. repositories: add egress mode & destination registry columns
ALTER TABLE repositories
    ADD COLUMN egress_mode            TEXT NOT NULL DEFAULT 'PASSIVE_AUDIT'
        CHECK (egress_mode IN ('PASSIVE_AUDIT', 'ENFORCE_BLOCK', 'ENFORCE_PR')),
    ADD COLUMN passive_audit_delivery TEXT NOT NULL DEFAULT 'ASYNC'
        CHECK (passive_audit_delivery IN ('ASYNC', 'INLINE_WARN')),
    ADD COLUMN git_remote_url         TEXT,
    ADD COLUMN remote_host            TEXT NOT NULL DEFAULT 'github.com'
        CHECK (remote_host <> ''),
    ADD COLUMN registered_destination BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN external               BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX idx_repositories_full_name ON repositories(full_name);
CREATE INDEX idx_repositories_git_remote_url ON repositories(git_remote_url)
    WHERE git_remote_url IS NOT NULL;

-- 3. push_sessions (Table 20): strictly attributed to authenticated principal_id
CREATE TABLE push_sessions (
    id                        UUID PRIMARY KEY,
    principal_id              UUID NOT NULL REFERENCES principals(id),
    repository_id             UUID REFERENCES repositories(id),
    destination               TEXT NOT NULL CHECK (destination <> ''),
    destination_host          TEXT NOT NULL DEFAULT '',
    destination_registered    BOOLEAN NOT NULL DEFAULT false,
    destination_external      BOOLEAN NOT NULL DEFAULT false,
    transport                 TEXT NOT NULL DEFAULT 'HTTPS' CHECK (transport IN ('HTTPS', 'SSH')),
    ref_updates               JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(ref_updates) = 'array'),
    has_lfs                   BOOLEAN NOT NULL DEFAULT false,
    lfs_objects               JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(lfs_objects) = 'array'),
    lfs_object_count          BIGINT NOT NULL DEFAULT 0 CHECK (lfs_object_count >= 0),
    lfs_total_bytes           BIGINT NOT NULL DEFAULT 0 CHECK (lfs_total_bytes >= 0),
    push_manifest_digest      CHAR(64) CHECK (push_manifest_digest IS NULL OR push_manifest_digest ~ '^[0-9a-f]{64}$'),
    bundle_artifact_id        UUID REFERENCES artifacts(id),
    egress_mode               TEXT NOT NULL CHECK (egress_mode IN ('PASSIVE_AUDIT', 'ENFORCE_BLOCK', 'ENFORCE_PR')),
    passive_audit_delivery    TEXT NOT NULL DEFAULT 'ASYNC' CHECK (passive_audit_delivery IN ('ASYNC', 'INLINE_WARN')),
    enforced                  BOOLEAN NOT NULL DEFAULT true,
    status                    TEXT NOT NULL CHECK (status IN (
        'RECEIVED',
        'UNPACKING',
        'QUARANTINED',
        'INSPECTING',
        'EVALUATING',
        'ALLOWED',
        'BLOCKED',
        'APPROVAL_REQUIRED',
        'FORWARDING',
        'COMPLETED',
        'OBSERVED_WOULD_BLOCK',
        'FAILED'
    )),
    verdict                   TEXT CHECK (verdict IS NULL OR verdict IN (
        'DENY',
        'QUARANTINE',
        'REQUIRE_REMEDIATION',
        'REQUIRE_APPROVAL',
        'ALLOW'
    )),
    latest_policy_decision_id UUID,
    approval_release_id       UUID,
    error_code                TEXT,
    error_message             TEXT,
    upstream_forwarded        BOOLEAN NOT NULL DEFAULT false,
    upstream_bytes_sent       BIGINT NOT NULL DEFAULT 0 CHECK (upstream_bytes_sent >= 0),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at              TIMESTAMPTZ
);

CREATE INDEX idx_push_sessions_principal ON push_sessions(principal_id, created_at DESC);
CREATE INDEX idx_push_sessions_repository ON push_sessions(repository_id, created_at DESC)
    WHERE repository_id IS NOT NULL;
CREATE INDEX idx_push_sessions_manifest_digest ON push_sessions(push_manifest_digest)
    WHERE push_manifest_digest IS NOT NULL;
CREATE INDEX idx_push_sessions_status ON push_sessions(status, created_at DESC);

-- 4. scan_runs: allow proposal_id OR push_session_id (mutually exclusive)
ALTER TABLE scan_runs
    ALTER COLUMN proposal_id DROP NOT NULL,
    ADD COLUMN push_session_id UUID REFERENCES push_sessions(id),
    ADD CONSTRAINT chk_scan_runs_owner_xor CHECK ((proposal_id IS NOT NULL) <> (push_session_id IS NOT NULL));

CREATE INDEX idx_scan_runs_push_session ON scan_runs(push_session_id, started_at DESC)
    WHERE push_session_id IS NOT NULL;

-- 5. model_assessments: allow proposal_id OR push_session_id, and NOT_REQUIRED status/disposition
ALTER TABLE model_assessments
    ALTER COLUMN proposal_id DROP NOT NULL,
    ADD COLUMN push_session_id UUID REFERENCES push_sessions(id),
    ADD CONSTRAINT chk_model_assessments_owner_xor CHECK ((proposal_id IS NOT NULL) <> (push_session_id IS NOT NULL)),
    DROP CONSTRAINT model_assessments_status_check,
    ADD CONSTRAINT model_assessments_status_check CHECK (status IN (
        'PENDING', 'COMPLETE', 'INDETERMINATE', 'FAILED', 'NOT_REQUIRED'
    )),
    DROP CONSTRAINT model_assessments_disposition_check,
    ADD CONSTRAINT model_assessments_disposition_check CHECK (
        disposition IS NULL OR disposition IN (
            'CLEAR', 'REVIEW', 'ESCALATE', 'BLOCK', 'INDETERMINATE', 'NOT_REQUIRED'
        )
    );

CREATE INDEX idx_model_assessments_push_session ON model_assessments(push_session_id, created_at DESC)
    WHERE push_session_id IS NOT NULL;

-- 6. policy_decisions: allow proposal_id OR push_session_id, add enforced, add PUSH_EGRESS stage
ALTER TABLE policy_decisions
    ALTER COLUMN proposal_id DROP NOT NULL,
    ADD COLUMN push_session_id UUID REFERENCES push_sessions(id),
    ADD COLUMN enforced BOOLEAN NOT NULL DEFAULT true,
    ADD CONSTRAINT chk_policy_decisions_owner_xor CHECK ((proposal_id IS NOT NULL) <> (push_session_id IS NOT NULL)),
    DROP CONSTRAINT policy_decisions_stage_check,
    ADD CONSTRAINT policy_decisions_stage_check CHECK (stage IN ('INGRESS', 'EGRESS', 'PUSH_EGRESS'));

CREATE INDEX idx_policy_decisions_push_session ON policy_decisions(push_session_id, created_at DESC)
    WHERE push_session_id IS NOT NULL;

ALTER TABLE push_sessions
    ADD CONSTRAINT fk_push_sessions_latest_policy_decision
    FOREIGN KEY (latest_policy_decision_id) REFERENCES policy_decisions(id);

-- 7. push_approval_releases (Table 21): single-use expiring release bound to (principal_id, destination, push_manifest_digest)
CREATE TABLE push_approval_releases (
    id                          UUID PRIMARY KEY,
    principal_id                UUID NOT NULL REFERENCES principals(id),
    destination                 TEXT NOT NULL CHECK (destination <> ''),
    push_manifest_digest        CHAR(64) NOT NULL CHECK (push_manifest_digest ~ '^[0-9a-f]{64}$'),
    push_session_id             UUID NOT NULL REFERENCES push_sessions(id),
    consumed_by_push_session_id UUID REFERENCES push_sessions(id),
    policy_decision_id          UUID NOT NULL REFERENCES policy_decisions(id),
    approved_by                 UUID NOT NULL REFERENCES principals(id),
    reason                      TEXT,
    expires_at                  TIMESTAMPTZ NOT NULL,
    consumed_at                 TIMESTAMPTZ,
    revoked_at                  TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (approved_by <> principal_id),
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX idx_push_approval_releases_active_binding
    ON push_approval_releases(principal_id, destination, push_manifest_digest)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX idx_push_approval_releases_session ON push_approval_releases(push_session_id);
CREATE INDEX idx_push_approval_releases_expires ON push_approval_releases(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

ALTER TABLE push_sessions
    ADD CONSTRAINT fk_push_sessions_approval_release
    FOREIGN KEY (approval_release_id) REFERENCES push_approval_releases(id);

-- 8. ip_fingerprint_corpora (Table 22)
CREATE TABLE ip_fingerprint_corpora (
    id                  UUID PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE CHECK (name <> ''),
    description         TEXT,
    classification      TEXT NOT NULL CHECK (classification IN ('CONFIDENTIAL', 'RESTRICTED')),
    repository_id       UUID REFERENCES repositories(id),
    source_ref          TEXT NOT NULL DEFAULT '',
    winnow_k            INTEGER NOT NULL DEFAULT 25 CHECK (winnow_k >= 1),
    winnow_w            INTEGER NOT NULL DEFAULT 15 CHECK (winnow_w >= 1),
    chunk_size_bytes    INTEGER NOT NULL DEFAULT 4096 CHECK (chunk_size_bytes >= 1),
    enabled             BOOLEAN NOT NULL DEFAULT true,
    status              TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'INDEXING', 'READY', 'FAILED')),
    fingerprint_count   BIGINT NOT NULL DEFAULT 0 CHECK (fingerprint_count >= 0),
    last_indexed_digest CHAR(64) CHECK (last_indexed_digest IS NULL OR last_indexed_digest ~ '^[0-9a-f]{64}$'),
    last_indexed_at     TIMESTAMPTZ,
    last_error          TEXT,
    created_by          UUID REFERENCES principals(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ip_fingerprint_corpora_enabled ON ip_fingerprint_corpora(enabled, classification)
    WHERE enabled = true;
CREATE INDEX idx_ip_fingerprint_corpora_repo ON ip_fingerprint_corpora(repository_id)
    WHERE repository_id IS NOT NULL;

-- 9. ip_fingerprints (Table 23): one-way hashes/Winnowing fingerprints + non-raw metadata ONLY
CREATE TABLE ip_fingerprints (
    id               UUID PRIMARY KEY,
    corpus_id        UUID NOT NULL REFERENCES ip_fingerprint_corpora(id) ON DELETE CASCADE,
    layer            TEXT NOT NULL CHECK (layer IN ('L1_EXACT_CHUNK', 'L2_WINNOW_KGRAM', 'L3_HEADER_MARKER')),
    fingerprint_hash TEXT NOT NULL CHECK (fingerprint_hash ~ '^[0-9a-f]{16,64}$'),
    file_path_hash   CHAR(64) CHECK (file_path_hash IS NULL OR file_path_hash ~ '^[0-9a-f]{64}$'),
    language         TEXT,
    chunk_index      INTEGER CHECK (chunk_index IS NULL OR chunk_index >= 0),
    line_start       INTEGER CHECK (line_start IS NULL OR line_start >= 0),
    line_end         INTEGER CHECK (line_end IS NULL OR line_end >= 0),
    token_count      INTEGER CHECK (token_count IS NULL OR token_count >= 0),
    metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (corpus_id, layer, fingerprint_hash, file_path_hash, chunk_index)
);

CREATE INDEX idx_ip_fingerprints_lookup ON ip_fingerprints(layer, fingerprint_hash);
CREATE INDEX idx_ip_fingerprints_corpus ON ip_fingerprints(corpus_id, layer);
