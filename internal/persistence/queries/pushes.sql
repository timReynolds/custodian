-- name: CreatePushSession :one
INSERT INTO push_sessions (
    id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18,
    $19, $20, $21, $22,
    $23, $24, $25, $26,
    $27, $28, $29
)
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at;

-- name: GetPushSessionByID :one
SELECT id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
FROM push_sessions
WHERE id = $1;

-- name: GetPushSessionByIDForUpdate :one
SELECT id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
FROM push_sessions
WHERE id = $1
FOR UPDATE;

-- name: ListPushSessions :many
SELECT id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
FROM push_sessions
WHERE (sqlc.narg(principal_id)::uuid IS NULL OR principal_id = sqlc.narg(principal_id)::uuid)
  AND (sqlc.narg(repository_id)::uuid IS NULL OR repository_id = sqlc.narg(repository_id)::uuid)
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(cursor_id)::uuid IS NULL OR id < sqlc.narg(cursor_id)::uuid)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: UpdatePushSessionUnpack :one
UPDATE push_sessions
SET push_manifest_digest = $2,
    bundle_artifact_id   = $3,
    ref_updates          = $4,
    status               = $5,
    updated_at           = $6
WHERE id = $1
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at;

-- name: ApplyPushSessionPolicyDecision :one
UPDATE push_sessions
SET latest_policy_decision_id = $2,
    approval_release_id       = COALESCE($3, approval_release_id),
    verdict                   = $4,
    status                    = $5,
    updated_at                = $6
WHERE id = $1
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at;

-- name: CompletePushSession :one
UPDATE push_sessions
SET status              = $2,
    upstream_forwarded  = $3,
    upstream_bytes_sent = $4,
    error_code          = $5,
    error_message       = $6,
    updated_at          = $7,
    completed_at        = $8
WHERE id = $1
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at;

-- name: CreatePushApprovalRelease :one
INSERT INTO push_approval_releases (
    id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12, $13
)
RETURNING id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at;

-- name: GetPushApprovalReleaseByID :one
SELECT id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
FROM push_approval_releases
WHERE id = $1;

-- name: GetActivePushApprovalRelease :one
SELECT id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
FROM push_approval_releases
WHERE principal_id = $1
  AND destination = $2
  AND push_manifest_digest = $3
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > $4
LIMIT 1;

-- name: ConsumePushApprovalRelease :one
UPDATE push_approval_releases
SET consumed_at                 = $4,
    consumed_by_push_session_id = $5
WHERE principal_id = $1
  AND destination = $2
  AND push_manifest_digest = $3
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > $4
  AND approved_by <> principal_id
RETURNING id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at;

-- name: RevokePushApprovalRelease :one
UPDATE push_approval_releases
SET revoked_at = $2
WHERE id = $1
  AND consumed_at IS NULL
  AND revoked_at IS NULL
RETURNING id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at;

-- name: ListPushApprovalReleasesBySession :many
SELECT id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
FROM push_approval_releases
WHERE push_session_id = $1 OR consumed_by_push_session_id = $1
ORDER BY created_at DESC, id DESC;
