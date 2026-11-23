-- name: RegisterArtifact :one
INSERT INTO artifacts (
    id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12
)
RETURNING id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at;

-- name: GetArtifactByID :one
SELECT id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
FROM artifacts
WHERE id = $1;

-- name: GetArtifactByStorageObject :one
SELECT id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
FROM artifacts
WHERE storage_key = $1 AND storage_generation = $2;

-- name: ListExpiredArtifacts :many
SELECT id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
FROM artifacts
WHERE expires_at IS NOT NULL
  AND expires_at <= $1
  AND deleted_at IS NULL
ORDER BY expires_at ASC, id ASC
LIMIT $2;

-- name: MarkArtifactDeleted :one
UPDATE artifacts
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at;
