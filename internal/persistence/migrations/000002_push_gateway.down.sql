-- Rollback Push Gateway schema extension in reverse dependency order

DROP TABLE IF EXISTS ip_fingerprints;
DROP TABLE IF EXISTS ip_fingerprint_corpora;

ALTER TABLE IF EXISTS push_sessions
    DROP CONSTRAINT IF EXISTS fk_push_sessions_approval_release,
    DROP CONSTRAINT IF EXISTS fk_push_sessions_latest_policy_decision;

DROP TABLE IF EXISTS push_approval_releases;

-- Remove push-only rows before restoring NOT NULL and v1.0 CHECK constraints
DELETE FROM policy_decisions WHERE push_session_id IS NOT NULL OR stage = 'PUSH_EGRESS';
DROP INDEX IF EXISTS idx_policy_decisions_push_session;
ALTER TABLE policy_decisions
    DROP CONSTRAINT IF EXISTS policy_decisions_stage_check,
    ADD CONSTRAINT policy_decisions_stage_check CHECK (stage IN ('INGRESS', 'EGRESS')),
    DROP CONSTRAINT IF EXISTS chk_policy_decisions_owner_xor,
    DROP COLUMN IF EXISTS enforced,
    DROP COLUMN IF EXISTS push_session_id,
    ALTER COLUMN proposal_id SET NOT NULL;

DELETE FROM model_assessments WHERE push_session_id IS NOT NULL OR status = 'NOT_REQUIRED' OR disposition = 'NOT_REQUIRED';
DROP INDEX IF EXISTS idx_model_assessments_push_session;
ALTER TABLE model_assessments
    DROP CONSTRAINT IF EXISTS model_assessments_disposition_check,
    ADD CONSTRAINT model_assessments_disposition_check CHECK (
        disposition IS NULL OR disposition IN ('CLEAR', 'REVIEW', 'ESCALATE', 'BLOCK', 'INDETERMINATE')
    ),
    DROP CONSTRAINT IF EXISTS model_assessments_status_check,
    ADD CONSTRAINT model_assessments_status_check CHECK (status IN ('PENDING', 'COMPLETE', 'INDETERMINATE', 'FAILED')),
    DROP CONSTRAINT IF EXISTS chk_model_assessments_owner_xor,
    DROP COLUMN IF EXISTS push_session_id,
    ALTER COLUMN proposal_id SET NOT NULL;

DELETE FROM findings WHERE scan_run_id IN (SELECT id FROM scan_runs WHERE push_session_id IS NOT NULL);
DELETE FROM scan_runs WHERE push_session_id IS NOT NULL;
DROP INDEX IF EXISTS idx_scan_runs_push_session;
ALTER TABLE scan_runs
    DROP CONSTRAINT IF EXISTS chk_scan_runs_owner_xor,
    DROP COLUMN IF EXISTS push_session_id,
    ALTER COLUMN proposal_id SET NOT NULL;

DROP TABLE IF EXISTS push_sessions;

DROP INDEX IF EXISTS idx_repositories_git_remote_url;
DROP INDEX IF EXISTS idx_repositories_full_name;
ALTER TABLE repositories
    DROP COLUMN IF EXISTS external,
    DROP COLUMN IF EXISTS registered_destination,
    DROP COLUMN IF EXISTS remote_host,
    DROP COLUMN IF EXISTS git_remote_url,
    DROP COLUMN IF EXISTS passive_audit_delivery,
    DROP COLUMN IF EXISTS egress_mode;

DELETE FROM artifacts WHERE kind = 'GIT_PUSH_BUNDLE';
ALTER TABLE artifacts
    DROP CONSTRAINT IF EXISTS artifacts_kind_check,
    ADD CONSTRAINT artifacts_kind_check CHECK (kind IN (
        'WORKSPACE_SOURCE',
        'SOURCE_MANIFEST',
        'EGRESS_SNAPSHOT',
        'CANONICAL_TREE',
        'CANONICAL_DIFF',
        'PUBLICATION_MANIFEST',
        'SCAN_EVIDENCE',
        'MODEL_EVIDENCE'
    ));
