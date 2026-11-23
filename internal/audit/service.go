package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultListLimit = 50
	maxListLimit     = 500
)

// ChainStore is the transactional persistence subset needed to append hash-chained audit events.
type ChainStore interface {
	LockAuditChainHead(ctx context.Context) (persistence.AuditChainHeadRow, error)
	NormalizeJSONB(ctx context.Context, payload json.RawMessage) (json.RawMessage, error)
	UpdateAuditChainHead(ctx context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error
	InsertAuditEvent(ctx context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error)
}

// ReadStore is the read/verify persistence subset for audit queries and chain verification.
type ReadStore interface {
	GetAuditChainHead(ctx context.Context) (persistence.AuditChainHeadRow, error)
	ListAuditEvents(ctx context.Context, arg persistence.ListAuditEventsParams) ([]persistence.AuditEventRow, error)
	ListAllAuditEventsOrdered(ctx context.Context) ([]persistence.AuditEventRow, error)
}

// Store provides transactional and read operations for the audit service.
type Store interface {
	ChainStore
	ReadStore
	RunInTx(ctx context.Context, fn func(tx ChainStore) error) error
	RunReadSnapshot(ctx context.Context, fn func(rs ReadStore) error) error
}

type persistenceStoreAdapter struct {
	store *persistence.Store
}

// NewStoreAdapter wraps *persistence.Store to satisfy audit.Store.
func NewStoreAdapter(store *persistence.Store) Store {
	return &persistenceStoreAdapter{store: store}
}

func (a *persistenceStoreAdapter) LockAuditChainHead(ctx context.Context) (persistence.AuditChainHeadRow, error) {
	return a.store.LockAuditChainHead(ctx)
}

func (a *persistenceStoreAdapter) NormalizeJSONB(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	return a.store.NormalizeJSONB(ctx, payload)
}

func (a *persistenceStoreAdapter) UpdateAuditChainHead(ctx context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error {
	return a.store.UpdateAuditChainHead(ctx, eventID, eventHash, eventCount, updatedAt)
}

func (a *persistenceStoreAdapter) InsertAuditEvent(ctx context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	return a.store.InsertAuditEvent(ctx, arg)
}

func (a *persistenceStoreAdapter) GetAuditChainHead(ctx context.Context) (persistence.AuditChainHeadRow, error) {
	return a.store.GetAuditChainHead(ctx)
}

func (a *persistenceStoreAdapter) ListAuditEvents(ctx context.Context, arg persistence.ListAuditEventsParams) ([]persistence.AuditEventRow, error) {
	return a.store.ListAuditEvents(ctx, arg)
}

func (a *persistenceStoreAdapter) ListAllAuditEventsOrdered(ctx context.Context) ([]persistence.AuditEventRow, error) {
	return a.store.ListAllAuditEventsOrdered(ctx)
}

func (a *persistenceStoreAdapter) RunInTx(ctx context.Context, fn func(tx ChainStore) error) error {
	return a.store.WithTx(ctx, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}

func (a *persistenceStoreAdapter) RunReadSnapshot(ctx context.Context, fn func(rs ReadStore) error) error {
	return a.store.WithTxOptions(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	}, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}

// AppendInput defines a new audit event to append to the hash chain.
type AppendInput struct {
	ID           uuid.UUID
	EventType    string
	ActorID      *uuid.UUID
	ResourceType string
	ResourceID   uuid.UUID
	Payload      json.RawMessage
	CreatedAt    time.Time
}

// ListFilter filters and paginates audit event queries.
type ListFilter struct {
	ResourceType string
	ResourceID   *uuid.UUID
	EventType    string
	ActorID      *uuid.UUID
	Since        *time.Time
	Until        *time.Time
	Cursor       string
	Limit        int
}

// ListResult returns paginated audit events and cursor state.
type ListResult struct {
	Events     []domain.AuditEvent `json:"events"`
	NextCursor string              `json:"next_cursor,omitempty"`
	HasMore    bool                `json:"has_more"`
}

// VerifyResult summarizes hash-chain integrity verification.
type VerifyResult struct {
	EventCount int64  `json:"event_count"`
	HeadHash   string `json:"head_hash,omitempty"`
}

// Service manages serialized hash-chained audit logging, filtered queries, and verification.
type Service struct {
	store  Store
	logger *slog.Logger
}

// NewService constructs an audit Service backed by *persistence.Store.
func NewService(store *persistence.Store, logger *slog.Logger) *Service {
	var adapter Store
	if store != nil {
		adapter = NewStoreAdapter(store)
	}
	return &Service{
		store:  adapter,
		logger: logger,
	}
}

// NewServiceWithStore constructs an audit Service with a custom Store implementation.
func NewServiceWithStore(store Store, logger *slog.Logger) *Service {
	return &Service{
		store:  store,
		logger: logger,
	}
}

// Append opens a transaction, locks the audit chain head, computes the hash, and appends the event.
func (s *Service) Append(ctx context.Context, input AppendInput) (domain.AuditEvent, error) {
	if s.store == nil {
		return domain.AuditEvent{}, domain.Unavailable("AUDIT_UNAVAILABLE", "audit store is not configured")
	}
	var out domain.AuditEvent
	err := s.store.RunInTx(ctx, func(tx ChainStore) error {
		var err error
		out, err = AppendTx(ctx, tx, input, s.logger)
		return err
	})
	return out, err
}

// AppendTx appends a hash-chained audit event within an existing transaction.
func (s *Service) AppendTx(ctx context.Context, tx ChainStore, input AppendInput) (domain.AuditEvent, error) {
	return AppendTx(ctx, tx, input, s.logger)
}

// AppendTx serializes on audit_chain_head, truncates CreatedAt to UTC microseconds before hashing,
// computes domain.ComputeAuditEventHash, inserts into audit_events, and advances audit_chain_head.
func AppendTx(ctx context.Context, tx ChainStore, input AppendInput, logger *slog.Logger) (domain.AuditEvent, error) {
	if tx == nil {
		return domain.AuditEvent{}, domain.Unavailable("AUDIT_UNAVAILABLE", "audit transaction store must not be nil")
	}
	eventType := strings.TrimSpace(input.EventType)
	resourceType := strings.TrimSpace(input.ResourceType)
	if eventType == "" || resourceType == "" || input.ResourceID == uuid.Nil {
		return domain.AuditEvent{}, domain.BadRequest("INVALID_AUDIT_EVENT", "event_type, resource_type, and resource_id are required")
	}

	id := input.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return domain.AuditEvent{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return domain.AuditEvent{}, domain.BadRequest("INVALID_ID", "audit event id must be UUIDv7")
	}

	payload := input.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	canonicalPayload, err := domain.CanonicalJSONBytes(payload)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	pgNormalized, err := tx.NormalizeJSONB(ctx, json.RawMessage(canonicalPayload))
	if err != nil {
		return domain.AuditEvent{}, err
	}
	canonicalNormalized, err := domain.CanonicalJSONBytes(pgNormalized)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	head, err := tx.LockAuditChainHead(ctx)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	// Critical: PostgreSQL TIMESTAMPTZ stores microsecond precision.
	// Truncate to time.Microsecond UTC BEFORE hashing so DB readbacks match ComputeAuditEventHash.
	createdAt := input.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		createdAt = createdAt.UTC().Truncate(time.Microsecond)
	}

	prevHash := ""
	if head.LastEventHash != nil {
		prevHash = *head.LastEventHash
	}

	ev := domain.AuditEvent{
		ID:           id,
		EventType:    eventType,
		ActorID:      input.ActorID,
		ResourceType: resourceType,
		ResourceID:   input.ResourceID,
		Payload:      json.RawMessage(canonicalNormalized),
		PreviousHash: prevHash,
		CreatedAt:    createdAt,
	}
	eventHash, err := domain.ComputeAuditEventHash(prevHash, ev)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	ev.EventHash = eventHash

	nextSeq := head.EventCount + 1
	inserted, err := tx.InsertAuditEvent(ctx, persistence.InsertAuditEventParams{
		ID:           ev.ID,
		ChainSeq:     nextSeq,
		EventType:    ev.EventType,
		ActorID:      ev.ActorID,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Payload:      ev.Payload,
		PreviousHash: prevHash,
		EventHash:    ev.EventHash,
		CreatedAt:    ev.CreatedAt,
	})
	if err != nil {
		return domain.AuditEvent{}, err
	}

	if err := tx.UpdateAuditChainHead(ctx, inserted.ID, inserted.EventHash, nextSeq, ev.CreatedAt); err != nil {
		return domain.AuditEvent{}, err
	}

	if logger != nil {
		l := observability.LoggerWithTrace(ctx, logger)
		l.InfoContext(ctx, "audit event appended",
			"audit_event_id", inserted.ID.String(),
			"event_type", inserted.EventType,
			"resource_type", inserted.ResourceType,
			"resource_id", inserted.ResourceID.String(),
			"event_hash", inserted.EventHash,
		)
	}

	return inserted.ToDomain(), nil
}

// List queries audit events with optional filters and keyset cursor pagination.
func (s *Service) List(ctx context.Context, filter ListFilter) (ListResult, error) {
	if s.store == nil {
		return ListResult{}, domain.Unavailable("AUDIT_UNAVAILABLE", "audit store is not configured")
	}

	limit := filter.Limit
	if limit == 0 {
		limit = defaultListLimit
	}
	if limit < 1 || limit > maxListLimit {
		return ListResult{}, domain.BadRequest("INVALID_LIMIT", fmt.Sprintf("limit must be between 1 and %d", maxListLimit))
	}

	var cursorSeq *int64
	if filter.Cursor != "" {
		seq, err := decodeCursor(filter.Cursor)
		if err != nil {
			return ListResult{}, err
		}
		cursorSeq = &seq
	}

	var resourceType, eventType *string
	if rt := strings.TrimSpace(filter.ResourceType); rt != "" {
		resourceType = &rt
	}
	if et := strings.TrimSpace(filter.EventType); et != "" {
		eventType = &et
	}

	rows, err := s.store.ListAuditEvents(ctx, persistence.ListAuditEventsParams{
		ResourceType: resourceType,
		ResourceID:   filter.ResourceID,
		EventType:    eventType,
		ActorID:      filter.ActorID,
		Since:        filter.Since,
		Until:        filter.Until,
		CursorSeq:    cursorSeq,
		Limit:        limit + 1,
	})
	if err != nil {
		return ListResult{}, err
	}

	hasMore := false
	nextCursor := ""
	if len(rows) > limit {
		hasMore = true
		rows = rows[:limit]
		nextCursor = encodeCursor(rows[len(rows)-1].ChainSeq)
	}

	events := make([]domain.AuditEvent, 0, len(rows))
	for _, r := range rows {
		events = append(events, r.ToDomain())
	}

	return ListResult{
		Events:     events,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// VerifyChain streams all audit_events in chain_seq order and verifies contiguous sequencing,
// genesis and link hashes, recomputed SHA-256 chain hashes, and audit_chain_head consistency.
func (s *Service) VerifyChain(ctx context.Context) (VerifyResult, error) {
	if s.store == nil {
		return VerifyResult{}, domain.Unavailable("AUDIT_UNAVAILABLE", "audit store is not configured")
	}

	var result VerifyResult
	err := s.store.RunReadSnapshot(ctx, func(rs ReadStore) error {
		head, err := rs.GetAuditChainHead(ctx)
		if err != nil {
			return err
		}
		rows, err := rs.ListAllAuditEventsOrdered(ctx)
		if err != nil {
			return err
		}

		if int64(len(rows)) != head.EventCount {
			return domain.Internal("AUDIT_CHAIN_CORRUPT", fmt.Sprintf("audit event count %d does not match chain head count %d", len(rows), head.EventCount))
		}
		if len(rows) == 0 {
			if head.LastEventID != nil || head.LastEventHash != nil {
				return domain.Internal("AUDIT_CHAIN_CORRUPT", "empty audit log has non-nil chain head")
			}
			result = VerifyResult{EventCount: 0}
			return nil
		}

		expectedPrev := ""
		for i, row := range rows {
			expectedSeq := int64(i + 1)
			if row.ChainSeq != expectedSeq {
				return domain.Internal("AUDIT_CHAIN_CORRUPT", fmt.Sprintf("chain_seq gap at index %d: expected %d, got %d", i, expectedSeq, row.ChainSeq))
			}

			ev := row.ToDomain()
			if ev.PreviousHash != expectedPrev {
				return domain.Internal("AUDIT_CHAIN_CORRUPT", fmt.Sprintf("previous_hash mismatch at chain_seq %d", row.ChainSeq))
			}

			recomputed, err := domain.ComputeAuditEventHash(expectedPrev, ev)
			if err != nil {
				return domain.WrapError(domain.ErrInternal, "AUDIT_CHAIN_CORRUPT", fmt.Sprintf("failed to compute hash at chain_seq %d", row.ChainSeq), err)
			}
			if recomputed != ev.EventHash {
				return domain.Internal("AUDIT_CHAIN_CORRUPT", fmt.Sprintf("event_hash mismatch at chain_seq %d", row.ChainSeq))
			}
			expectedPrev = ev.EventHash
		}

		last := rows[len(rows)-1]
		if head.LastEventID == nil || *head.LastEventID != last.ID {
			return domain.Internal("AUDIT_CHAIN_CORRUPT", "audit_chain_head.last_event_id mismatch")
		}
		if head.LastEventHash == nil || *head.LastEventHash != last.EventHash {
			return domain.Internal("AUDIT_CHAIN_CORRUPT", "audit_chain_head.last_event_hash mismatch")
		}

		result = VerifyResult{
			EventCount: head.EventCount,
			HeadHash:   last.EventHash,
		}
		return nil
	})
	return result, err
}

func encodeCursor(chainSeq int64) string {
	raw := "seq:" + strconv.FormatInt(chainSeq, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(cursor string) (int64, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, domain.BadRequest("INVALID_CURSOR", "malformed audit pagination cursor")
	}
	s := string(decoded)
	if !strings.HasPrefix(s, "seq:") {
		return 0, domain.BadRequest("INVALID_CURSOR", "invalid audit pagination cursor")
	}
	seq, err := strconv.ParseInt(strings.TrimPrefix(s, "seq:"), 10, 64)
	if err != nil || seq < 1 {
		return 0, domain.BadRequest("INVALID_CURSOR", "invalid audit pagination cursor sequence")
	}
	return seq, nil
}
