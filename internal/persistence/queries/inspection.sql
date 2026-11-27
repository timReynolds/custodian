-- name: CreateScanRun :one
INSERT INTO scan_runs (
    id, proposal_id, push_session_id, artifact_id, scanner, scanner_version,
    status, coverage, started_at, completed_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10
)
RETURNING id, proposal_id, push_session_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at;

-- name: GetScanRunByID :one
SELECT id, proposal_id, push_session_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
FROM scan_runs
WHERE id = $1;

-- name: ListScanRunsByProposal :many
SELECT id, proposal_id, push_session_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
FROM scan_runs
WHERE proposal_id = $1
ORDER BY started_at DESC, id DESC;

-- name: ListScanRunsByPushSession :many
SELECT id, proposal_id, push_session_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
FROM scan_runs
WHERE push_session_id = $1
ORDER BY started_at DESC, id DESC;

-- name: CompleteScanRun :one
UPDATE scan_runs
SET status          = $2,
    coverage        = $3,
    completed_at    = $4,
    scanner_version = COALESCE(NULLIF(sqlc.arg(scanner_version)::text, ''), scanner_version)
WHERE id = $1
  AND status IN ('PENDING', 'RUNNING')
RETURNING id, proposal_id, push_session_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at;

-- name: CreateFinding :one
INSERT INTO findings (
    id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18
)
RETURNING id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata;

-- name: GetFindingByID :one
SELECT id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
FROM findings
WHERE id = $1;

-- name: ListFindingsByScanRun :many
SELECT id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
FROM findings
WHERE scan_run_id = $1
ORDER BY id ASC;

-- name: ListFindingsByProposal :many
SELECT f.id, f.scan_run_id, f.evidence_id, f.scanner, f.category, f.severity, f.rule_id,
    f.path, f.start_line, f.end_line, f.fingerprint, f.evidence_artifact_id, f.evidence_ref,
    f.baseline, f.confidence, f.message, f.redacted, f.metadata
FROM findings f
JOIN scan_runs sr ON sr.id = f.scan_run_id
WHERE sr.proposal_id = sqlc.arg(proposal_id)::uuid
  AND (sqlc.narg(scanner)::text IS NULL OR f.scanner = sqlc.narg(scanner)::text)
  AND (sqlc.narg(severity)::text IS NULL OR f.severity = sqlc.narg(severity)::text)
  AND (sqlc.narg(cursor_id)::uuid IS NULL OR f.id > sqlc.narg(cursor_id)::uuid)
ORDER BY f.id ASC
LIMIT sqlc.arg(page_limit);

-- name: ListFindingsByPushSession :many
SELECT f.id, f.scan_run_id, f.evidence_id, f.scanner, f.category, f.severity, f.rule_id,
    f.path, f.start_line, f.end_line, f.fingerprint, f.evidence_artifact_id, f.evidence_ref,
    f.baseline, f.confidence, f.message, f.redacted, f.metadata
FROM findings f
JOIN scan_runs sr ON sr.id = f.scan_run_id
WHERE sr.push_session_id = sqlc.arg(push_session_id)::uuid
  AND (sqlc.narg(scanner)::text IS NULL OR f.scanner = sqlc.narg(scanner)::text)
  AND (sqlc.narg(severity)::text IS NULL OR f.severity = sqlc.narg(severity)::text)
  AND (sqlc.narg(cursor_id)::uuid IS NULL OR f.id > sqlc.narg(cursor_id)::uuid)
ORDER BY f.id ASC
LIMIT sqlc.arg(page_limit);

-- name: CreateModelAssessment :one
INSERT INTO model_assessments (
    id, proposal_id, push_session_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16
)
RETURNING id, proposal_id, push_session_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at;

-- name: GetModelAssessmentByID :one
SELECT id, proposal_id, push_session_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
FROM model_assessments
WHERE id = $1;

-- name: ListModelAssessmentsByProposal :many
SELECT id, proposal_id, push_session_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
FROM model_assessments
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC;

-- name: ListModelAssessmentsByPushSession :many
SELECT id, proposal_id, push_session_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
FROM model_assessments
WHERE push_session_id = $1
ORDER BY created_at DESC, id DESC;

-- name: UpdateModelAssessmentResult :one
UPDATE model_assessments
SET status         = $2,
    risk           = $3,
    disposition    = $4,
    result         = $5,
    evidence_ids   = $6,
    output_digest  = $7,
    model_route    = COALESCE(NULLIF(sqlc.arg(model_route)::text, ''), model_route),
    model_version  = COALESCE(NULLIF(sqlc.arg(model_version)::text, ''), model_version),
    prompt_version = COALESCE(NULLIF(sqlc.arg(prompt_version)::text, ''), prompt_version),
    input_digest   = COALESCE(NULLIF(sqlc.arg(input_digest)::text, ''), input_digest)
WHERE id = $1
  AND status = 'PENDING'
RETURNING id, proposal_id, push_session_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at;

-- name: CountActiveScanRuns :one
SELECT COUNT(*)::bigint
FROM scan_runs
WHERE status IN ('PENDING', 'RUNNING');

-- name: CountActiveModelAssessments :one
SELECT COUNT(*)::bigint
FROM model_assessments
WHERE status = 'PENDING';
