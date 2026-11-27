-- name: AcquireAuditChainLock :exec
SELECT pg_advisory_xact_lock($1);

-- name: LockAuditChainHead :one
SELECT chain_id, last_event_id, last_event_hash, event_count, updated_at
FROM audit_chain_head
WHERE chain_id = 'default'
FOR UPDATE;

-- name: NormalizeJSONB :one
SELECT $1::jsonb;

-- name: GetAuditChainHead :one
SELECT chain_id, last_event_id, last_event_hash, event_count, updated_at
FROM audit_chain_head
WHERE chain_id = 'default';

-- name: UpdateAuditChainHead :exec
UPDATE audit_chain_head
SET last_event_id   = $1,
    last_event_hash = $2,
    event_count     = $3,
    updated_at      = $4
WHERE chain_id = 'default';

-- name: InsertAuditEvent :one
INSERT INTO audit_events (
    id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at;

-- name: ListAuditEvents :many
SELECT id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
FROM audit_events
WHERE (sqlc.narg(resource_type)::text IS NULL OR resource_type = sqlc.narg(resource_type)::text)
  AND (sqlc.narg(resource_id)::uuid IS NULL OR resource_id = sqlc.narg(resource_id)::uuid)
  AND (sqlc.narg(event_type)::text IS NULL OR event_type = sqlc.narg(event_type)::text)
  AND (sqlc.narg(actor_id)::uuid IS NULL OR actor_id = sqlc.narg(actor_id)::uuid)
  AND (sqlc.narg(since)::timestamptz IS NULL OR created_at >= sqlc.narg(since)::timestamptz)
  AND (sqlc.narg(until)::timestamptz IS NULL OR created_at <= sqlc.narg(until)::timestamptz)
  AND (
      sqlc.narg(cursor_seq)::bigint IS NULL
      OR chain_seq > sqlc.narg(cursor_seq)::bigint
  )
ORDER BY chain_seq ASC
LIMIT sqlc.arg(page_limit);

-- name: ListAllAuditEventsOrdered :many
SELECT id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
FROM audit_events
ORDER BY chain_seq ASC;
