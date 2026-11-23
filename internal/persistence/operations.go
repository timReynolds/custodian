package persistence

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

type EnqueueOperationParams struct {
	ID            uuid.UUID
	OperationType domain.OperationType
	ResourceType  string
	ResourceID    uuid.UUID
	MaxAttempts   int
	AvailableAt   time.Time
	CreatedAt     time.Time
}

const enqueueOperationSQL = `
INSERT INTO operations (
    id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, 'PENDING', 0, $5,
    $6, $7, $7
)
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func isValidOperationType(t domain.OperationType) bool {
	switch t {
	case domain.OperationTypeWorkspaceIngress,
		domain.OperationTypeProposalReconstruct,
		domain.OperationTypeProposalEvaluate,
		domain.OperationTypeProposalPublish:
		return true
	default:
		return false
	}
}

func (q *Queries) EnqueueOperation(ctx context.Context, arg EnqueueOperationParams) (OperationRow, error) {
	if !isValidOperationType(arg.OperationType) {
		return OperationRow{}, domain.BadRequest("INVALID_OPERATION_TYPE", "invalid operation_type")
	}
	if arg.ResourceID == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_RESOURCE_ID", "resource_id must not be nil")
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return OperationRow{}, err
		}
	}
	maxAttempts := arg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	now := arg.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	availableAt := arg.AvailableAt
	if availableAt.IsZero() {
		availableAt = now
	} else {
		availableAt = availableAt.UTC().Truncate(time.Microsecond)
	}

	var row OperationRow
	err := scanOperationRow(q.db.QueryRow(ctx, enqueueOperationSQL,
		id,
		string(arg.OperationType),
		nilIfEmpty(arg.ResourceType),
		arg.ResourceID,
		maxAttempts,
		availableAt,
		now,
	), &row)
	if err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

const getOperationByIDSQL = `
SELECT id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
FROM operations
WHERE id = $1
`

func (q *Queries) GetOperationByID(ctx context.Context, id uuid.UUID) (OperationRow, error) {
	if id == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_ID", "operation id must not be nil")
	}
	var row OperationRow
	err := scanOperationRow(q.db.QueryRow(ctx, getOperationByIDSQL, id), &row)
	if err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

type ClaimOperationsParams struct {
	Now           time.Time
	LeaseUntil    time.Time
	WorkerID      string
	OperationType *domain.OperationType
	Limit         int
}

const claimOperationsSQL = `
WITH candidate AS (
    SELECT id, status AS prev_status
    FROM operations
    WHERE (
        (status = 'PENDING' AND available_at <= $1)
        OR (status = 'RUNNING' AND lease_until IS NOT NULL AND lease_until <= $1)
    )
      AND attempts < max_attempts
      AND ($4::text IS NULL OR operation_type = $4::text)
    ORDER BY available_at ASC, created_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT $5
)
UPDATE operations o
SET status      = 'RUNNING',
    attempts    = o.attempts + 1,
    lease_until = $2,
    leased_by   = $3,
    updated_at  = $1
FROM candidate c
WHERE o.id = c.id
RETURNING o.id, o.operation_type, o.resource_type, o.resource_id, o.status, o.attempts, o.max_attempts,
    o.available_at, o.lease_until, o.leased_by, o.last_error, o.result, o.created_at, o.updated_at, o.completed_at,
    (c.prev_status = 'RUNNING') AS reclaimed
`

func (q *Queries) ClaimOperations(ctx context.Context, arg ClaimOperationsParams) ([]OperationRow, error) {
	if arg.WorkerID == "" {
		return nil, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	now := arg.Now
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	leaseUntil := arg.LeaseUntil
	if leaseUntil.IsZero() {
		leaseUntil = now.Add(30 * time.Second)
	} else {
		leaseUntil = leaseUntil.UTC().Truncate(time.Microsecond)
	}
	if !leaseUntil.After(now) {
		return nil, domain.BadRequest("INVALID_LEASE", "lease_until must be after now")
	}
	limit := arg.Limit
	if limit <= 0 {
		limit = 1
	}
	var opType *string
	if arg.OperationType != nil {
		if !isValidOperationType(*arg.OperationType) {
			return nil, domain.BadRequest("INVALID_OPERATION_TYPE", "invalid operation_type")
		}
		s := string(*arg.OperationType)
		opType = &s
	}

	rows, err := q.db.Query(ctx, claimOperationsSQL, now, leaseUntil, arg.WorkerID, opType, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]OperationRow, 0)
	for rows.Next() {
		var row OperationRow
		if err := scanClaimedOperationRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const renewOperationLeaseSQL = `
UPDATE operations
SET lease_until = $3,
    updated_at  = $1
WHERE id = $2
  AND status = 'RUNNING'
  AND leased_by = $4
  AND lease_until > $1
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func (q *Queries) RenewOperationLease(ctx context.Context, id uuid.UUID, workerID string, now, newLeaseUntil time.Time) (OperationRow, error) {
	if id == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_ID", "operation id must not be nil")
	}
	if workerID == "" {
		return OperationRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	newLeaseUntil = newLeaseUntil.UTC().Truncate(time.Microsecond)
	if !newLeaseUntil.After(now) {
		return OperationRow{}, domain.BadRequest("INVALID_LEASE", "new lease_until must be after now")
	}

	var row OperationRow
	err := scanOperationRow(q.db.QueryRow(ctx, renewOperationLeaseSQL, now, id, newLeaseUntil, workerID), &row)
	if err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

const completeOperationSQL = `
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
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func (q *Queries) CompleteOperation(ctx context.Context, id uuid.UUID, workerID string, result json.RawMessage, now time.Time) (OperationRow, error) {
	if id == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_ID", "operation id must not be nil")
	}
	if workerID == "" {
		return OperationRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	var resArg any
	if len(result) > 0 {
		canonical, err := domain.CanonicalJSONBytes(result)
		if err != nil {
			return OperationRow{}, err
		}
		resArg = json.RawMessage(canonical)
	}

	var row OperationRow
	err := scanOperationRow(q.db.QueryRow(ctx, completeOperationSQL, now, id, resArg, workerID), &row)
	if err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

const retryOperationSQL = `
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
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func (q *Queries) RetryOperation(ctx context.Context, id uuid.UUID, workerID string, now, nextAvailableAt time.Time, lastError string) (OperationRow, error) {
	if id == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_ID", "operation id must not be nil")
	}
	if workerID == "" {
		return OperationRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	nextAvailableAt = nextAvailableAt.UTC().Truncate(time.Microsecond)

	var row OperationRow
	err := scanOperationRow(q.db.QueryRow(ctx, retryOperationSQL, now, id, nextAvailableAt, nilIfEmpty(lastError), workerID), &row)
	if err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

const failOperationTerminalSQL = `
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
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func (q *Queries) FailOperationTerminal(ctx context.Context, id uuid.UUID, workerID string, now time.Time, lastError string) (OperationRow, error) {
	if id == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_ID", "operation id must not be nil")
	}
	if workerID == "" {
		return OperationRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	var row OperationRow
	err := scanOperationRow(q.db.QueryRow(ctx, failOperationTerminalSQL, now, id, nilIfEmpty(lastError), workerID), &row)
	if err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

const reapExpiredOperationsSQL = `
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
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func (q *Queries) ReapExpiredOperations(ctx context.Context, now time.Time) ([]OperationRow, error) {
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	rows, err := q.db.Query(ctx, reapExpiredOperationsSQL, now)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]OperationRow, 0)
	for rows.Next() {
		var row OperationRow
		if err := scanOperationRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const reapExpiredOperationsByTypeSQL = `
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
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

func (q *Queries) ReapExpiredOperationsByType(ctx context.Context, now time.Time, opType domain.OperationType) ([]OperationRow, error) {
	if !isValidOperationType(opType) {
		return nil, domain.BadRequest("INVALID_OPERATION_TYPE", "invalid operation_type")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	rows, err := q.db.Query(ctx, reapExpiredOperationsByTypeSQL, now, string(opType))
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]OperationRow, 0)
	for rows.Next() {
		var row OperationRow
		if err := scanOperationRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type EnqueueOutboxParams struct {
	ID          uuid.UUID
	EventType   string
	AggregateID uuid.UUID
	Payload     json.RawMessage
	AvailableAt time.Time
	CreatedAt   time.Time
}

const enqueueOutboxEventSQL = `
INSERT INTO outbox_events (
    id, event_type, aggregate_id, payload, attempts, available_at, created_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $6
)
RETURNING id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at
`

func (q *Queries) EnqueueOutboxEvent(ctx context.Context, arg EnqueueOutboxParams) (OutboxEventRow, error) {
	if arg.EventType == "" || arg.AggregateID == uuid.Nil {
		return OutboxEventRow{}, domain.BadRequest("INVALID_OUTBOX_EVENT", "event_type and aggregate_id are required")
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return OutboxEventRow{}, err
		}
	}
	payload := arg.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	canonical, err := domain.CanonicalJSONBytes(payload)
	if err != nil {
		return OutboxEventRow{}, err
	}
	now := arg.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	availableAt := arg.AvailableAt
	if availableAt.IsZero() {
		availableAt = now
	} else {
		availableAt = availableAt.UTC().Truncate(time.Microsecond)
	}

	var row OutboxEventRow
	err = scanOutboxRow(q.db.QueryRow(ctx, enqueueOutboxEventSQL,
		id,
		arg.EventType,
		arg.AggregateID,
		json.RawMessage(canonical),
		availableAt,
		now,
	), &row)
	if err != nil {
		return OutboxEventRow{}, MapError(err)
	}
	return row, nil
}

const claimOutboxEventsSQL = `
WITH candidate AS (
    SELECT id
    FROM outbox_events
    WHERE delivered_at IS NULL
      AND available_at <= $1
      AND (lease_until IS NULL OR lease_until <= $1)
    ORDER BY available_at ASC, created_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT $4
)
UPDATE outbox_events o
SET lease_until = $2,
    leased_by   = $3
FROM candidate c
WHERE o.id = c.id
RETURNING o.id, o.event_type, o.aggregate_id, o.payload, o.attempts, o.available_at,
    o.lease_until, o.leased_by, o.last_error, o.created_at, o.delivered_at
`

func (q *Queries) ClaimOutboxEvents(ctx context.Context, workerID string, now, leaseUntil time.Time, limit int) ([]OutboxEventRow, error) {
	if workerID == "" {
		return nil, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	if leaseUntil.IsZero() {
		leaseUntil = now.Add(30 * time.Second)
	} else {
		leaseUntil = leaseUntil.UTC().Truncate(time.Microsecond)
	}
	if limit <= 0 {
		limit = 10
	}

	rows, err := q.db.Query(ctx, claimOutboxEventsSQL, now, leaseUntil, workerID, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]OutboxEventRow, 0)
	for rows.Next() {
		var row OutboxEventRow
		if err := scanOutboxRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const getOutboxEventByIDSQL = `
SELECT id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at
FROM outbox_events
WHERE id = $1
`

func (q *Queries) GetOutboxEventByID(ctx context.Context, id uuid.UUID) (OutboxEventRow, error) {
	if id == uuid.Nil {
		return OutboxEventRow{}, domain.BadRequest("INVALID_ID", "outbox event id must not be nil")
	}
	var row OutboxEventRow
	err := scanOutboxRow(q.db.QueryRow(ctx, getOutboxEventByIDSQL, id), &row)
	if err != nil {
		return OutboxEventRow{}, MapError(err)
	}
	return row, nil
}

const markOutboxEventDeliveredSQL = `
UPDATE outbox_events
SET delivered_at = $1,
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = NULL
WHERE id = $2
  AND delivered_at IS NULL
  AND leased_by = $3
RETURNING id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at
`

func (q *Queries) MarkOutboxEventDelivered(ctx context.Context, id uuid.UUID, workerID string, deliveredAt time.Time) (OutboxEventRow, error) {
	if id == uuid.Nil {
		return OutboxEventRow{}, domain.BadRequest("INVALID_ID", "outbox event id must not be nil")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return OutboxEventRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if deliveredAt.IsZero() {
		deliveredAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		deliveredAt = deliveredAt.UTC().Truncate(time.Microsecond)
	}

	var row OutboxEventRow
	err := scanOutboxRow(q.db.QueryRow(ctx, markOutboxEventDeliveredSQL, deliveredAt, id, workerID), &row)
	if err != nil {
		return OutboxEventRow{}, MapError(err)
	}
	return row, nil
}

const failOutboxEventSQL = `
UPDATE outbox_events
SET attempts     = attempts + 1,
    available_at = $2,
    lease_until  = NULL,
    leased_by    = NULL,
    last_error   = $3
WHERE id = $1
  AND delivered_at IS NULL
  AND leased_by = $4
RETURNING id, event_type, aggregate_id, payload, attempts, available_at, lease_until, leased_by, last_error, created_at, delivered_at
`

func (q *Queries) FailOutboxEvent(ctx context.Context, id uuid.UUID, workerID string, nextAvailableAt time.Time, lastError string) (OutboxEventRow, error) {
	if id == uuid.Nil {
		return OutboxEventRow{}, domain.BadRequest("INVALID_ID", "outbox event id must not be nil")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return OutboxEventRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if nextAvailableAt.IsZero() {
		nextAvailableAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		nextAvailableAt = nextAvailableAt.UTC().Truncate(time.Microsecond)
	}

	var row OutboxEventRow
	err := scanOutboxRow(q.db.QueryRow(ctx, failOutboxEventSQL, id, nextAvailableAt, nilIfEmpty(lastError), workerID), &row)
	if err != nil {
		return OutboxEventRow{}, MapError(err)
	}
	return row, nil
}

const countActiveOperationsByRepositorySQL = `
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
  )
`

func (q *Queries) CountActiveOperationsByRepository(ctx context.Context, repositoryID uuid.UUID) (int64, error) {
	if repositoryID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "repository_id must not be nil")
	}
	var count int64
	if err := q.db.QueryRow(ctx, countActiveOperationsByRepositorySQL, repositoryID).Scan(&count); err != nil {
		return 0, MapError(err)
	}
	return count, nil
}

const countActiveOperationsByTypeSQL = `
SELECT COUNT(*)::bigint
FROM operations
WHERE operation_type = $1
  AND status IN ('PENDING', 'RUNNING')
`

func (q *Queries) CountActiveOperationsByType(ctx context.Context, opType domain.OperationType) (int64, error) {
	if !isValidOperationType(opType) {
		return 0, domain.BadRequest("INVALID_OPERATION_TYPE", "invalid operation_type")
	}
	var count int64
	if err := q.db.QueryRow(ctx, countActiveOperationsByTypeSQL, string(opType)).Scan(&count); err != nil {
		return 0, MapError(err)
	}
	return count, nil
}

const getLatestOperationByResourceSQL = `
SELECT id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
FROM operations
WHERE resource_id = $1
  AND operation_type = $2
ORDER BY created_at DESC, id DESC
LIMIT 1
`

func (q *Queries) GetLatestOperationByResource(ctx context.Context, resourceID uuid.UUID, opType domain.OperationType) (OperationRow, error) {
	if resourceID == uuid.Nil {
		return OperationRow{}, domain.BadRequest("INVALID_RESOURCE_ID", "resource_id must not be nil")
	}
	if !isValidOperationType(opType) {
		return OperationRow{}, domain.BadRequest("INVALID_OPERATION_TYPE", "invalid operation_type")
	}
	var row OperationRow
	if err := scanOperationRow(q.db.QueryRow(ctx, getLatestOperationByResourceSQL, resourceID, string(opType)), &row); err != nil {
		return OperationRow{}, MapError(err)
	}
	return row, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOperationRow(s rowScanner, row *OperationRow) error {
	var opType, status string
	if err := s.Scan(
		&row.ID,
		&opType,
		&row.ResourceType,
		&row.ResourceID,
		&status,
		&row.Attempts,
		&row.MaxAttempts,
		&row.AvailableAt,
		&row.LeaseUntil,
		&row.LeasedBy,
		&row.LastError,
		&row.Result,
		&row.CreatedAt,
		&row.UpdatedAt,
		&row.CompletedAt,
	); err != nil {
		return err
	}
	row.OperationType = domain.OperationType(opType)
	row.Status = domain.OperationStatus(status)
	return nil
}

func scanClaimedOperationRow(s rowScanner, row *OperationRow) error {
	var opType, status string
	if err := s.Scan(
		&row.ID,
		&opType,
		&row.ResourceType,
		&row.ResourceID,
		&status,
		&row.Attempts,
		&row.MaxAttempts,
		&row.AvailableAt,
		&row.LeaseUntil,
		&row.LeasedBy,
		&row.LastError,
		&row.Result,
		&row.CreatedAt,
		&row.UpdatedAt,
		&row.CompletedAt,
		&row.Reclaimed,
	); err != nil {
		return err
	}
	row.OperationType = domain.OperationType(opType)
	row.Status = domain.OperationStatus(status)
	return nil
}

func scanOutboxRow(s rowScanner, row *OutboxEventRow) error {
	return s.Scan(
		&row.ID,
		&row.EventType,
		&row.AggregateID,
		&row.Payload,
		&row.Attempts,
		&row.AvailableAt,
		&row.LeaseUntil,
		&row.LeasedBy,
		&row.LastError,
		&row.CreatedAt,
		&row.DeliveredAt,
	)
}
