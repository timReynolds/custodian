-- name: GetRepositoryByID :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE id = $1;

-- name: GetRepositoryByGitHubID :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE github_repository_id = $1;

-- name: CreateRepository :one
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations,
    egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15
)
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at;

-- name: UpsertRepository :one
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations,
    egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15
)
ON CONFLICT (github_repository_id) DO UPDATE SET
    github_installation_id    = EXCLUDED.github_installation_id,
    full_name                 = EXCLUDED.full_name,
    classification            = EXCLUDED.classification,
    enabled                   = EXCLUDED.enabled,
    allowed_model_routes      = EXCLUDED.allowed_model_routes,
    max_concurrent_operations = EXCLUDED.max_concurrent_operations,
    egress_mode               = CASE WHEN sqlc.arg(set_egress_mode)::boolean THEN EXCLUDED.egress_mode ELSE repositories.egress_mode END,
    passive_audit_delivery    = CASE WHEN sqlc.arg(set_delivery)::boolean THEN EXCLUDED.passive_audit_delivery ELSE repositories.passive_audit_delivery END,
    git_remote_url            = COALESCE(EXCLUDED.git_remote_url, repositories.git_remote_url),
    remote_host               = CASE WHEN sqlc.arg(set_remote_host)::boolean THEN EXCLUDED.remote_host ELSE repositories.remote_host END,
    registered_destination    = CASE WHEN sqlc.arg(set_registered)::boolean THEN EXCLUDED.registered_destination ELSE repositories.registered_destination END,
    external                  = CASE WHEN sqlc.arg(set_external)::boolean THEN EXCLUDED.external ELSE repositories.external END
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at;

-- name: GetRepositoryByFullName :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE full_name = $1
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: GetRepositoryByGitRemoteURL :one
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE git_remote_url = $1
ORDER BY created_at DESC, id DESC
LIMIT 1;

-- name: ListRepositories :many
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
ORDER BY created_at DESC, id DESC
LIMIT $1;

-- name: UpdateRepositoryEgressMode :one
UPDATE repositories
SET egress_mode            = $2,
    passive_audit_delivery = $3
WHERE id = $1
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at;
