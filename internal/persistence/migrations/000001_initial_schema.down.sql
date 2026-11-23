-- Rollback initial schema in reverse dependency order

ALTER TABLE IF EXISTS proposals DROP CONSTRAINT IF EXISTS fk_proposals_latest_policy_eval;
ALTER TABLE IF EXISTS artifacts DROP CONSTRAINT IF EXISTS fk_artifact_workspace;
ALTER TABLE IF EXISTS workspaces DROP CONSTRAINT IF EXISTS fk_workspace_source;

DROP TABLE IF EXISTS audit_chain_head;
DROP TABLE IF EXISTS publication_attempts;
DROP TABLE IF EXISTS approval_requirements;
DROP TABLE IF EXISTS idempotency_keys;
DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS operations;
DROP TABLE IF EXISTS publications;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS policy_decisions;
DROP TABLE IF EXISTS policy_bundles;
DROP TABLE IF EXISTS model_assessments;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_runs;
DROP TABLE IF EXISTS proposals;
DROP TABLE IF EXISTS workspaces;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS repositories;
DROP TABLE IF EXISTS principals;
