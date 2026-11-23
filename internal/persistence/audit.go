package persistence

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const auditChainAdvisoryLockKey int64 = 7291046281

const acquireAuditChainLockSQL = `
SELECT pg_advisory_xact_lock($1)
`

const lockAuditChainHeadSQL = `
SELECT chain_id, last_event_id, last_event_hash, event_count, updated_at
FROM audit_chain_head
WHERE chain_id = 'default'
FOR UPDATE
`

// LockAuditChainHead acquires a transaction-scoped advisory lock and FOR UPDATE row lock
// on audit_chain_head ('default') to strictly serialize audit_events hash chaining.
func (q *Queries) LockAuditChainHead(ctx context.Context) (AuditChainHeadRow, error) {
	if _, err := q.db.Exec(ctx, acquireAuditChainLockSQL, auditChainAdvisoryLockKey); err != nil {
		return AuditChainHeadRow{}, MapError(err)
	}
	var head AuditChainHeadRow
	err := q.db.QueryRow(ctx, lockAuditChainHeadSQL).Scan(
		&head.ChainID,
		&head.LastEventID,
		&head.LastEventHash,
		&head.EventCount,
		&head.UpdatedAt,
	)
	if err != nil {
		return AuditChainHeadRow{}, MapError(err)
	}
	return head, nil
}

const normalizeJSONBSQL = `
SELECT $1::jsonb
`

// NormalizeJSONB validates payload as canonical JSON and round-trips it through PostgreSQL JSONB
// so numeric tokens (e.g., 1e5 -> 100000, -0.0 -> 0.0) match persisted JSONB bytes.
func (q *Queries) NormalizeJSONB(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	canonical, err := domain.CanonicalJSONBytes(payload)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	if err := q.db.QueryRow(ctx, normalizeJSONBSQL, json.RawMessage(canonical)).Scan(&out); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const getAuditChainHeadSQL = `
SELECT chain_id, last_event_id, last_event_hash, event_count, updated_at
FROM audit_chain_head
WHERE chain_id = 'default'
`

func (q *Queries) GetAuditChainHead(ctx context.Context) (AuditChainHeadRow, error) {
	var head AuditChainHeadRow
	err := q.db.QueryRow(ctx, getAuditChainHeadSQL).Scan(
		&head.ChainID,
		&head.LastEventID,
		&head.LastEventHash,
		&head.EventCount,
		&head.UpdatedAt,
	)
	if err != nil {
		return AuditChainHeadRow{}, MapError(err)
	}
	return head, nil
}

const updateAuditChainHeadSQL = `
UPDATE audit_chain_head
SET last_event_id   = $1,
    last_event_hash = $2,
    event_count     = $3,
    updated_at      = $4
WHERE chain_id = 'default'
`

func (q *Queries) UpdateAuditChainHead(ctx context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error {
	if eventID == uuid.Nil {
		return domain.BadRequest("INVALID_ID", "eventID must not be nil")
	}
	hash, err := domain.ParseSHA256Digest(eventHash)
	if err != nil {
		return err
	}
	_, err = q.db.Exec(ctx, updateAuditChainHeadSQL, eventID, hash, eventCount, updatedAt.UTC().Truncate(time.Microsecond))
	return MapError(err)
}

type InsertAuditEventParams struct {
	ID           uuid.UUID
	ChainSeq     int64
	EventType    string
	ActorID      *uuid.UUID
	ResourceType string
	ResourceID   uuid.UUID
	Payload      json.RawMessage
	PreviousHash string
	EventHash    string
	CreatedAt    time.Time
}

const insertAuditEventSQL = `
INSERT INTO audit_events (
    id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
`

func (q *Queries) InsertAuditEvent(ctx context.Context, arg InsertAuditEventParams) (AuditEventRow, error) {
	if arg.ChainSeq < 1 {
		return AuditEventRow{}, domain.BadRequest("INVALID_CHAIN_SEQ", "chain_seq must be >= 1")
	}
	if arg.ID == uuid.Nil || arg.EventType == "" || arg.ResourceType == "" || arg.ResourceID == uuid.Nil {
		return AuditEventRow{}, domain.BadRequest("INVALID_AUDIT_EVENT", "id, event_type, resource_type, and resource_id are required")
	}
	if !domain.IsUUIDv7(arg.ID) {
		return AuditEventRow{}, domain.BadRequest("INVALID_ID", "audit event id must be UUIDv7")
	}
	eventHash, err := domain.ParseSHA256Digest(arg.EventHash)
	if err != nil {
		return AuditEventRow{}, err
	}
	var prevHash *string
	if arg.PreviousHash != "" {
		parsedPrev, err := domain.ParseSHA256Digest(arg.PreviousHash)
		if err != nil {
			return AuditEventRow{}, err
		}
		prevHash = &parsedPrev
	}
	payload := arg.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	canonicalPayload, err := domain.CanonicalJSONBytes(payload)
	if err != nil {
		return AuditEventRow{}, err
	}
	createdAt := arg.CreatedAt.UTC().Truncate(time.Microsecond)

	var row AuditEventRow
	err = q.db.QueryRow(ctx, insertAuditEventSQL,
		arg.ID,
		arg.ChainSeq,
		arg.EventType,
		arg.ActorID,
		arg.ResourceType,
		arg.ResourceID,
		json.RawMessage(canonicalPayload),
		prevHash,
		eventHash,
		createdAt,
	).Scan(
		&row.ID,
		&row.ChainSeq,
		&row.EventType,
		&row.ActorID,
		&row.ResourceType,
		&row.ResourceID,
		&row.Payload,
		&row.PreviousHash,
		&row.EventHash,
		&row.CreatedAt,
	)
	if err != nil {
		return AuditEventRow{}, MapError(err)
	}
	return row, nil
}

type ListAuditEventsParams struct {
	ResourceType *string
	ResourceID   *uuid.UUID
	EventType    *string
	ActorID      *uuid.UUID
	Since        *time.Time
	Until        *time.Time
	CursorSeq    *int64
	Limit        int
}

const listAuditEventsSQL = `
SELECT id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
FROM audit_events
WHERE ($1::text IS NULL OR resource_type = $1::text)
  AND ($2::uuid IS NULL OR resource_id = $2::uuid)
  AND ($3::text IS NULL OR event_type = $3::text)
  AND ($4::uuid IS NULL OR actor_id = $4::uuid)
  AND ($5::timestamptz IS NULL OR created_at >= $5::timestamptz)
  AND ($6::timestamptz IS NULL OR created_at <= $6::timestamptz)
  AND ($7::bigint IS NULL OR chain_seq > $7::bigint)
ORDER BY chain_seq ASC
LIMIT $8
`

func (q *Queries) ListAuditEvents(ctx context.Context, arg ListAuditEventsParams) ([]AuditEventRow, error) {
	limit := arg.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 501 {
		limit = 501
	}

	var since, until *time.Time
	if arg.Since != nil {
		t := arg.Since.UTC()
		since = &t
	}
	if arg.Until != nil {
		t := arg.Until.UTC()
		until = &t
	}

	rows, err := q.db.Query(ctx, listAuditEventsSQL,
		arg.ResourceType,
		arg.ResourceID,
		arg.EventType,
		arg.ActorID,
		since,
		until,
		arg.CursorSeq,
		limit,
	)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]AuditEventRow, 0)
	for rows.Next() {
		var row AuditEventRow
		if err := rows.Scan(
			&row.ID,
			&row.ChainSeq,
			&row.EventType,
			&row.ActorID,
			&row.ResourceType,
			&row.ResourceID,
			&row.Payload,
			&row.PreviousHash,
			&row.EventHash,
			&row.CreatedAt,
		); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const listAllAuditEventsOrderedSQL = `
SELECT id, chain_seq, event_type, actor_id, resource_type, resource_id, payload, previous_hash, event_hash, created_at
FROM audit_events
ORDER BY chain_seq ASC
`

func (q *Queries) ListAllAuditEventsOrdered(ctx context.Context) ([]AuditEventRow, error) {
	rows, err := q.db.Query(ctx, listAllAuditEventsOrderedSQL)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]AuditEventRow, 0)
	for rows.Next() {
		var row AuditEventRow
		if err := rows.Scan(
			&row.ID,
			&row.ChainSeq,
			&row.EventType,
			&row.ActorID,
			&row.ResourceType,
			&row.ResourceID,
			&row.Payload,
			&row.PreviousHash,
			&row.EventHash,
			&row.CreatedAt,
		); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}
