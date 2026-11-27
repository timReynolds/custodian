-- name: CreateProposal :one
INSERT INTO proposals (
    id, workspace_id, owner_id, snapshot_artifact_id,
    base_commit, target_ref, title, description,
    provenance_type, capture_method, status, version,
    created_at, updated_at
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, $8,
    $9, $10, $11, $12,
    $13, $14
)
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at;

-- name: GetProposalByID :one
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE id = $1;

-- name: GetProposalByIDForUpdate :one
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE id = $1
FOR UPDATE;

-- name: GetProposalDetailsByID :one
SELECT
    p.id, p.workspace_id, p.owner_id, p.snapshot_artifact_id, p.canonical_artifact_id,
    p.diff_artifact_id, p.manifest_artifact_id, p.base_commit, p.target_ref, p.title, p.description,
    p.provenance_type, p.capture_method, p.tree_digest, p.diff_digest, p.manifest_digest,
    p.latest_policy_evaluation_id, p.latest_policy_effect, p.status, p.version, p.created_at, p.updated_at,
    r.id AS repository_id, r.github_repository_id, r.full_name AS repository_full_name, r.classification AS repository_classification,
    w.agent_id AS workspace_agent_id, w.agent_session_id AS workspace_agent_session_id,
    w.model_route AS workspace_model_route, w.generation AS workspace_generation,
    pr.kind AS owner_kind, pr.issuer AS owner_issuer, pr.subject AS owner_subject, pr.display_name AS owner_display_name
FROM proposals p
JOIN workspaces w ON w.id = p.workspace_id
JOIN repositories r ON r.id = w.repository_id
JOIN principals pr ON pr.id = p.owner_id
WHERE p.id = $1;

-- name: ListProposalsByWorkspace :many
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE workspace_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: ListProposalDetailsByWorkspace :many
SELECT
    p.id, p.workspace_id, p.owner_id, p.snapshot_artifact_id, p.canonical_artifact_id,
    p.diff_artifact_id, p.manifest_artifact_id, p.base_commit, p.target_ref, p.title, p.description,
    p.provenance_type, p.capture_method, p.tree_digest, p.diff_digest, p.manifest_digest,
    p.latest_policy_evaluation_id, p.latest_policy_effect, p.status, p.version, p.created_at, p.updated_at,
    r.id AS repository_id, r.github_repository_id, r.full_name AS repository_full_name, r.classification AS repository_classification,
    w.agent_id AS workspace_agent_id, w.agent_session_id AS workspace_agent_session_id,
    w.model_route AS workspace_model_route, w.generation AS workspace_generation,
    pr.kind AS owner_kind, pr.issuer AS owner_issuer, pr.subject AS owner_subject, pr.display_name AS owner_display_name
FROM proposals p
JOIN workspaces w ON w.id = p.workspace_id
JOIN repositories r ON r.id = w.repository_id
JOIN principals pr ON pr.id = p.owner_id
WHERE p.workspace_id = $1
ORDER BY p.created_at DESC, p.id DESC
LIMIT $2;

-- name: ListProposalsByOwner :many
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE owner_id = sqlc.arg(owner_id)::uuid
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListProposalDetailsByOwner :many
SELECT
    p.id, p.workspace_id, p.owner_id, p.snapshot_artifact_id, p.canonical_artifact_id,
    p.diff_artifact_id, p.manifest_artifact_id, p.base_commit, p.target_ref, p.title, p.description,
    p.provenance_type, p.capture_method, p.tree_digest, p.diff_digest, p.manifest_digest,
    p.latest_policy_evaluation_id, p.latest_policy_effect, p.status, p.version, p.created_at, p.updated_at,
    r.id AS repository_id, r.github_repository_id, r.full_name AS repository_full_name, r.classification AS repository_classification,
    w.agent_id AS workspace_agent_id, w.agent_session_id AS workspace_agent_session_id,
    w.model_route AS workspace_model_route, w.generation AS workspace_generation,
    pr.kind AS owner_kind, pr.issuer AS owner_issuer, pr.subject AS owner_subject, pr.display_name AS owner_display_name
FROM proposals p
JOIN workspaces w ON w.id = p.workspace_id
JOIN repositories r ON r.id = w.repository_id
JOIN principals pr ON pr.id = p.owner_id
WHERE p.owner_id = sqlc.arg(owner_id)::uuid
  AND (sqlc.narg(status)::text IS NULL OR p.status = sqlc.narg(status)::text)
ORDER BY p.created_at DESC, p.id DESC
LIMIT sqlc.arg(page_limit);

-- name: TransitionProposalStatus :one
UPDATE proposals
SET status     = sqlc.arg(to_status)::text,
    version    = version + 1,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = sqlc.arg(id)::uuid
  AND version = sqlc.arg(expected_version)::bigint
  AND (sqlc.narg(from_status)::text IS NULL OR status = sqlc.narg(from_status)::text)
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at;

-- name: SetProposalReconstruction :one
UPDATE proposals
SET canonical_artifact_id = $2,
    diff_artifact_id      = $3,
    manifest_artifact_id  = $4,
    tree_digest           = $5,
    diff_digest           = $6,
    manifest_digest       = $7,
    status                = $8,
    version               = version + 1,
    updated_at            = $9
WHERE id = $1
  AND version = $10
  AND status IN ('CAPTURED', 'RECONSTRUCTING')
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at;

-- name: ApplyProposalPolicyDecision :one
UPDATE proposals
SET latest_policy_evaluation_id = $2,
    latest_policy_effect        = $3,
    status                      = $4,
    version                     = version + 1,
    updated_at                  = $5
WHERE id = $1
  AND version = $6
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at;
