-- name: TryInsertIdempotencyKey :execrows
INSERT INTO idempotency_keys (
    principal_id, method, route, idempotency_key, request_hash, status, locked_until, created_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, 'IN_PROGRESS', $6, $7, $8
)
ON CONFLICT (principal_id, method, route, idempotency_key) DO NOTHING;

-- name: GetIdempotencyKeyForUpdate :one
SELECT principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
FROM idempotency_keys
WHERE principal_id = $1 AND method = $2 AND route = $3 AND idempotency_key = $4
FOR UPDATE;

-- name: GetIdempotencyKey :one
SELECT principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
FROM idempotency_keys
WHERE principal_id = $1 AND method = $2 AND route = $3 AND idempotency_key = $4;

-- name: TakeoverStaleIdempotencyKey :one
UPDATE idempotency_keys
SET locked_until = $5,
    expires_at   = $6
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND status = 'IN_PROGRESS'
  AND locked_until <= $7
RETURNING principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at;

-- name: ResetExpiredIdempotencyKey :one
UPDATE idempotency_keys
SET request_hash     = $5,
    status           = 'IN_PROGRESS',
    response_status  = NULL,
    response_headers = '{}'::jsonb,
    response_body    = NULL,
    locked_until     = $6,
    created_at       = $7,
    completed_at     = NULL,
    expires_at       = $8
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND expires_at <= $7
RETURNING principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at;

-- name: FinalizeIdempotencyKey :one
UPDATE idempotency_keys
SET status           = 'COMPLETED',
    response_status  = $5,
    response_headers = $6,
    response_body    = $7,
    completed_at     = $8,
    expires_at       = $9
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND status = 'IN_PROGRESS'
  AND (sqlc.narg(expected_locked_until)::timestamptz IS NULL OR locked_until = sqlc.narg(expected_locked_until)::timestamptz)
RETURNING principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at;

-- name: DeleteExpiredIdempotencyKeys :execrows
DELETE FROM idempotency_keys
WHERE expires_at <= $1;
