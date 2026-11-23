-- name: EnqueueOutboxEvent :one
INSERT INTO outbox_events (
    id, event_type, aggregate_id, payload, attempts, available_at, created_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $6
)
RETURNING id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at;

-- name: ClaimOutboxEvents :many
WITH candidate AS (
    SELECT id
    FROM outbox_events
    WHERE delivered_at IS NULL
      AND available_at <= sqlc.arg(now)::timestamptz
      AND (lease_until IS NULL OR lease_until <= sqlc.arg(now)::timestamptz)
    ORDER BY available_at ASC, created_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT sqlc.arg(batch_limit)
)
UPDATE outbox_events o
SET lease_until = sqlc.arg(lease_until)::timestamptz,
    leased_by   = sqlc.arg(worker_id)::text
FROM candidate c
WHERE o.id = c.id
RETURNING o.id, o.event_type, o.aggregate_id, o.payload, o.attempts, o.available_at,
    o.lease_until, o.leased_by, o.last_error, o.created_at, o.delivered_at;

-- name: GetOutboxEventByID :one
SELECT id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at
FROM outbox_events
WHERE id = $1;

-- name: MarkOutboxEventDelivered :one
UPDATE outbox_events
SET delivered_at = $1,
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = NULL
WHERE id = $2
  AND delivered_at IS NULL
  AND leased_by = $3
RETURNING id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at;

-- name: FailOutboxEvent :one
UPDATE outbox_events
SET attempts     = attempts + 1,
    available_at = $2,
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = $3
WHERE id = $1
  AND delivered_at IS NULL
  AND leased_by = $4
RETURNING id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at;
