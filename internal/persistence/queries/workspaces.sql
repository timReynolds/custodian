-- name: CreateWorkspace :one
INSERT INTO workspaces (
    id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12,
    $13, $14, $15, $16
)
RETURNING id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at;

-- name: GetWorkspaceByID :one
SELECT id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
FROM workspaces
WHERE id = $1;

-- name: GetWorkspaceDetailsByID :one
SELECT
    w.id, w.repository_id, w.owner_id, w.agent_id, w.agent_type, w.agent_session_id, w.model_route,
    w.base_commit, w.target_ref, w.source_artifact_id, w.include_git_metadata, w.include_history,
    w.generation, w.status, w.created_at, w.updated_at,
    r.github_repository_id, r.full_name AS repository_full_name,
    p.issuer AS owner_issuer, p.subject AS owner_subject, p.display_name AS owner_display_name
FROM workspaces w
JOIN repositories r ON r.id = w.repository_id
JOIN principals p ON p.id = w.owner_id
WHERE w.id = $1;

-- name: TransitionWorkspaceStatus :one
UPDATE workspaces
SET status = $2,
    updated_at = $3
WHERE id = $1 AND status = $4
RETURNING id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at;

-- name: AttachWorkspaceSourceArtifact :one
UPDATE workspaces
SET source_artifact_id = $2,
    status = $3,
    updated_at = $4
WHERE id = $1
  AND source_artifact_id IS NULL
  AND status IN ('PENDING', 'PREPARING')
RETURNING id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at;
