-- name: CreatePolicyBundle :one
INSERT INTO policy_bundles (
    id, name, version, scope, repository_id, digest, definition, activated_at, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING id, name, version, scope, repository_id, digest, definition, activated_at, created_at;

-- name: GetPolicyBundleByID :one
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE id = $1;

-- name: GetPolicyBundleByDigest :one
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE digest = $1;

-- name: GetActivePolicyBundle :one
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE scope = sqlc.arg(scope)::text
  AND activated_at IS NOT NULL
  AND (
      (sqlc.narg(repository_id)::uuid IS NULL AND repository_id IS NULL)
      OR repository_id = sqlc.narg(repository_id)::uuid
  )
ORDER BY activated_at DESC, created_at DESC, id DESC
LIMIT 1;

-- name: ActivatePolicyBundle :one
UPDATE policy_bundles
SET activated_at = $2
WHERE id = $1
RETURNING id, name, version, scope, repository_id, digest, definition, activated_at, created_at;

-- name: UpsertPolicyBundleByDigest :one
INSERT INTO policy_bundles (
    id, name, version, scope, repository_id, digest, definition, activated_at, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (digest) DO UPDATE SET
    name          = EXCLUDED.name,
    version       = EXCLUDED.version,
    scope         = EXCLUDED.scope,
    repository_id = EXCLUDED.repository_id,
    definition    = EXCLUDED.definition,
    activated_at  = COALESCE(EXCLUDED.activated_at, policy_bundles.activated_at)
RETURNING id, name, version, scope, repository_id, digest, definition, activated_at, created_at;

-- name: ListActivePolicyBundles :many
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE activated_at IS NOT NULL
ORDER BY scope ASC, activated_at DESC, created_at DESC, id DESC;

-- name: ListActivePolicyBundlesByScope :many
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE scope = sqlc.arg(scope)::text
  AND activated_at IS NOT NULL
  AND (
      (sqlc.narg(repository_id)::uuid IS NULL AND repository_id IS NULL)
      OR repository_id = sqlc.narg(repository_id)::uuid
  )
ORDER BY activated_at DESC, created_at DESC, id DESC;

-- name: CreatePolicyDecision :one
INSERT INTO policy_decisions (
    id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10, $11
)
RETURNING id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at;

-- name: GetPolicyDecisionByID :one
SELECT id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
FROM policy_decisions
WHERE id = $1;

-- name: ListPolicyDecisionsByProposal :many
SELECT id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
FROM policy_decisions
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC;

-- name: GetLatestPolicyDecisionForProposal :one
SELECT id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
FROM policy_decisions
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC
LIMIT 1;
