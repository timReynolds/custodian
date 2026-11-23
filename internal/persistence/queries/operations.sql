-- name: EnqueueOperation :one
INSERT INTO operations (
    id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, 'PENDING', 0, $5,
    $6, $7, $7
)
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: GetOperationByID :one
SELECT id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
FROM operations
WHERE id = $1;

-- name: ClaimOperations :many
WITH candidate AS (
    SELECT id, status AS prev_status
    FROM operations
    WHERE (
        (status = 'PENDING' AND available_at <= sqlc.arg(now)::timestamptz)
        OR (status = 'RUNNING' AND lease_until IS NOT NULL AND lease_until <= sqlc.arg(now)::timestamptz)
    )
      AND attempts < max_attempts
      AND (sqlc.narg(operation_type)::text IS NULL OR operation_type = sqlc.narg(operation_type)::text)
    ORDER BY available_at ASC, created_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT sqlc.arg(batch_limit)
)
UPDATE operations o
SET status      = 'RUNNING',
    attempts    = o.attempts + 1,
    lease_until = sqlc.arg(lease_until)::timestamptz,
    leased_by   = sqlc.arg(worker_id)::text,
    updated_at  = sqlc.arg(now)::timestamptz
FROM candidate c
WHERE o.id = c.id
RETURNING o.id, o.operation_type, o.resource_type, o.resource_id, o.status, o.attempts, o.max_attempts,
    o.available_at, o.lease_until, o.leased_by, o.last_error, o.result, o.created_at, o.updated_at, o.completed_at,
    (c.prev_status = 'RUNNING') AS reclaimed;

-- name: RenewOperationLease :one
UPDATE operations
SET lease_until = $3,
    updated_at  = $1
WHERE id = $2
  AND status = 'RUNNING'
  AND leased_by = $4
  AND lease_until > $1
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: CompleteOperation :one
UPDATE operations
SET status       = 'SUCCEEDED',
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = NULL,
    result       = $3,
    completed_at = $1,
    updated_at   = $1
WHERE id = $2
  AND status = 'RUNNING'
  AND leased_by = $4
  AND (lease_until IS NULL OR lease_until > $1)
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: RetryOperation :one
UPDATE operations
SET status       = 'PENDING',
    available_at = $3,
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = $4,
    updated_at   = $1
WHERE id = $2
  AND status = 'RUNNING'
  AND leased_by = $5
  AND (lease_until IS NULL OR lease_until > $1)
  AND attempts < max_attempts
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: FailOperationTerminal :one
UPDATE operations
SET status       = 'FAILED',
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = $3,
    completed_at = $1,
    updated_at   = $1
WHERE id = $2
  AND status = 'RUNNING'
  AND leased_by = $4
  AND (lease_until IS NULL OR lease_until > $1)
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: ReapExpiredOperations :many
UPDATE operations
SET status       = 'FAILED',
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = COALESCE(NULLIF(last_error, ''), 'lease expired after max attempts'),
    completed_at = $1,
    updated_at   = $1
WHERE status = 'RUNNING'
  AND lease_until IS NOT NULL
  AND lease_until <= $1
  AND attempts >= max_attempts
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: ReapExpiredOperationsByType :many
UPDATE operations
SET status       = 'FAILED',
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = COALESCE(NULLIF(last_error, ''), 'lease expired after max attempts'),
    completed_at = $1,
    updated_at   = $1
WHERE status = 'RUNNING'
  AND lease_until IS NOT NULL
  AND lease_until <= $1
  AND attempts >= max_attempts
  AND operation_type = $2
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at;

-- name: CountActiveOperationsByRepository :one
SELECT COUNT(DISTINCT o.id)::bigint
FROM operations o
LEFT JOIN workspaces w
  ON w.id = o.resource_id
 AND (o.resource_type IS NULL OR LOWER(o.resource_type) = 'workspace')
LEFT JOIN proposals p
  ON p.id = o.resource_id
 AND (o.resource_type IS NULL OR LOWER(o.resource_type) = 'proposal')
LEFT JOIN workspaces pw
  ON pw.id = p.workspace_id
LEFT JOIN publications pub
  ON pub.id = o.resource_id
 AND (o.resource_type IS NULL OR LOWER(o.resource_type) = 'publication')
LEFT JOIN proposals pubp
  ON pubp.id = pub.proposal_id
LEFT JOIN workspaces pubw
  ON pubw.id = pubp.workspace_id
WHERE o.status IN ('PENDING', 'RUNNING')
  AND (
      w.repository_id = $1
      OR pw.repository_id = $1
      OR pubw.repository_id = $1
  );

-- name: CountActiveOperationsByType :one
SELECT COUNT(*)::bigint
FROM operations
WHERE operation_type = $1
  AND status IN ('PENDING', 'RUNNING');

-- name: GetLatestOperationByResource :one
SELECT id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
FROM operations
WHERE resource_id = $1
  AND operation_type = $2
ORDER BY created_at DESC, id DESC
LIMIT 1;
