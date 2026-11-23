-- name: GetRepositoryByID :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
WHERE id = $1;

-- name: GetRepositoryByGitHubID :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
WHERE github_repository_id = $1;

-- name: CreateRepository :one
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at;

-- name: UpsertRepository :one
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (github_repository_id) DO UPDATE SET
    github_installation_id    = EXCLUDED.github_installation_id,
    full_name                 = EXCLUDED.full_name,
    classification            = EXCLUDED.classification,
    enabled                   = EXCLUDED.enabled,
    allowed_model_routes      = EXCLUDED.allowed_model_routes,
    max_concurrent_operations = EXCLUDED.max_concurrent_operations
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at;

-- name: GetRepositoryByFullName :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
WHERE full_name = $1
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: ListRepositories :many
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
ORDER BY created_at DESC, id DESC
LIMIT $1;
