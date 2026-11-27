package operations

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultMaxAttempts    = 5
	defaultLeaseDuration  = 30 * time.Second
	defaultBaseRetryDelay = 1 * time.Second
	defaultMaxRetryDelay  = 5 * time.Minute
)

// TxStore defines transactional enqueue methods usable inside another service's transaction.
type TxStore interface {
	EnqueueOperation(ctx context.Context, arg persistence.EnqueueOperationParams) (persistence.OperationRow, error)
	EnqueueOutboxEvent(ctx context.Context, arg persistence.EnqueueOutboxParams) (persistence.OutboxEventRow, error)
}

// Store defines all operation and outbox persistence operations.
type Store interface {
	TxStore
	GetOperationByID(ctx context.Context, id uuid.UUID) (persistence.OperationRow, error)
	ClaimOperations(ctx context.Context, arg persistence.ClaimOperationsParams) ([]persistence.OperationRow, error)
	RenewOperationLease(ctx context.Context, id uuid.UUID, workerID string, now, newLeaseUntil time.Time) (persistence.OperationRow, error)
	CompleteOperation(ctx context.Context, id uuid.UUID, workerID string, result json.RawMessage, now time.Time) (persistence.OperationRow, error)
	RetryOperation(ctx context.Context, id uuid.UUID, workerID string, now, nextAvailableAt time.Time, lastError string) (persistence.OperationRow, error)
	FailOperationTerminal(ctx context.Context, id uuid.UUID, workerID string, now time.Time, lastError string) (persistence.OperationRow, error)
	ReapExpiredOperations(ctx context.Context, now time.Time) ([]persistence.OperationRow, error)
	ClaimOutboxEvents(ctx context.Context, workerID string, now, leaseUntil time.Time, limit int) ([]persistence.OutboxEventRow, error)
	GetOutboxEventByID(ctx context.Context, id uuid.UUID) (persistence.OutboxEventRow, error)
	MarkOutboxEventDelivered(ctx context.Context, id uuid.UUID, workerID string, deliveredAt time.Time) (persistence.OutboxEventRow, error)
	FailOutboxEvent(ctx context.Context, id uuid.UUID, workerID string, nextAvailableAt time.Time, lastError string) (persistence.OutboxEventRow, error)
}

// ScopedReapStore is an optional extension to Store allowing ReapExpiredByType
// to filter expired operations by operation_type inside the persistence update.
type ScopedReapStore interface {
	ReapExpiredOperationsByType(ctx context.Context, now time.Time, opType domain.OperationType) ([]persistence.OperationRow, error)
}

// Config configures retry backoff and lease defaults.
type Config struct {
	DefaultLeaseDuration time.Duration
	BaseRetryDelay       time.Duration
	MaxRetryDelay        time.Duration
	Clock                func() time.Time
}

// OperationDetails enriches domain.Operation with OpenAPI and worker lease metadata.
type OperationDetails struct {
	domain.Operation
	ResourceType string          `json:"resource_type,omitempty"`
	MaxAttempts  int             `json:"max_attempts"`
	LeasedBy     string          `json:"leased_by,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
}

// EnqueueInput specifies a new operation to enqueue.
type EnqueueInput struct {
	ID            uuid.UUID
	OperationType domain.OperationType
	ResourceType  string
	ResourceID    uuid.UUID
	MaxAttempts   int
	AvailableAt   time.Time
}

// ClaimInput specifies worker lease claim parameters.
type ClaimInput struct {
	WorkerID      string
	OperationType *domain.OperationType
	Limit         int
	LeaseDuration time.Duration
	Now           time.Time
}

// EnqueueOutboxInput specifies a new outbox event.
type EnqueueOutboxInput struct {
	ID          uuid.UUID
	EventType   string
	AggregateID uuid.UUID
	Payload     json.RawMessage
	AvailableAt time.Time
}

// Service manages leased operations and the transactional outbox.
type Service struct {
	store   Store
	metrics *observability.Metrics
	logger  *slog.Logger
	cfg     Config
}

// NewService constructs an operations Service.
func NewService(store Store, metrics *observability.Metrics, logger *slog.Logger, cfg ...Config) *Service {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}
	if c.DefaultLeaseDuration <= 0 {
		c.DefaultLeaseDuration = defaultLeaseDuration
	}
	if c.BaseRetryDelay <= 0 {
		c.BaseRetryDelay = defaultBaseRetryDelay
	}
	if c.MaxRetryDelay <= 0 {
		c.MaxRetryDelay = defaultMaxRetryDelay
	}
	if c.Clock == nil {
		c.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		store:   store,
		metrics: metrics,
		logger:  logger,
		cfg:     c,
	}
}

func (s *Service) now() time.Time {
	return s.cfg.Clock().UTC().Truncate(time.Microsecond)
}

// Enqueue inserts a new PENDING operation.
func (s *Service) Enqueue(ctx context.Context, input EnqueueInput) (OperationDetails, error) {
	if s == nil || s.store == nil {
		return OperationDetails{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	return EnqueueTx(ctx, s.store, input, s.metrics, s.logger)
}

// EnqueueTx inserts a new PENDING operation using the provided TxStore.
func (s *Service) EnqueueTx(ctx context.Context, tx TxStore, input EnqueueInput) (OperationDetails, error) {
	if s == nil {
		return EnqueueTx(ctx, tx, input, nil, nil)
	}
	return EnqueueTx(ctx, tx, input, s.metrics, s.logger)
}

// EnqueueTx inserts a new PENDING operation inside a caller-managed transaction.
func EnqueueTx(ctx context.Context, tx TxStore, input EnqueueInput, metrics *observability.Metrics, logger *slog.Logger) (OperationDetails, error) {
	if tx == nil {
		return OperationDetails{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	maxAttempts := input.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultMaxAttempts
	}
	row, err := tx.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		ID:            input.ID,
		OperationType: input.OperationType,
		ResourceType:  input.ResourceType,
		ResourceID:    input.ResourceID,
		MaxAttempts:   maxAttempts,
		AvailableAt:   input.AvailableAt,
	})
	if err != nil {
		return OperationDetails{}, err
	}
	details := detailsFromRow(row)
	if metrics != nil {
		metrics.IncOperation(string(details.OperationType), string(details.Status))
	}
	if logger != nil {
		l := observability.LoggerWithTrace(ctx, logger)
		l.InfoContext(ctx, "operation enqueued",
			"operation_id", details.ID.String(),
			"operation_type", string(details.OperationType),
			"resource_id", details.ResourceID.String(),
			"status", string(details.Status),
		)
	}
	return details, nil
}

// GetByID retrieves the domain.Operation by ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (domain.Operation, error) {
	if s == nil || s.store == nil {
		return domain.Operation{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	row, err := s.store.GetOperationByID(ctx, id)
	if err != nil {
		return domain.Operation{}, err
	}
	return row.ToDomain(), nil
}

// GetDetails retrieves the full OperationDetails by ID.
func (s *Service) GetDetails(ctx context.Context, id uuid.UUID) (OperationDetails, error) {
	if s == nil || s.store == nil {
		return OperationDetails{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	row, err := s.store.GetOperationByID(ctx, id)
	if err != nil {
		return OperationDetails{}, err
	}
	return detailsFromRow(row), nil
}

// Claim leases up to Limit ready or expired-lease operations using FOR UPDATE SKIP LOCKED.
func (s *Service) Claim(ctx context.Context, input ClaimInput) ([]OperationDetails, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID := strings.TrimSpace(input.WorkerID)
	if workerID == "" {
		return nil, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	now := input.Now
	if now.IsZero() {
		now = s.now()
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	leaseDur := input.LeaseDuration
	if leaseDur <= 0 {
		leaseDur = s.cfg.DefaultLeaseDuration
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 1
	}

	rows, err := s.store.ClaimOperations(ctx, persistence.ClaimOperationsParams{
		Now:           now,
		LeaseUntil:    now.Add(leaseDur),
		WorkerID:      workerID,
		OperationType: input.OperationType,
		Limit:         limit,
	})
	if err != nil {
		return nil, err
	}

	out := make([]OperationDetails, 0, len(rows))
	for _, r := range rows {
		d := detailsFromRow(r)
		if s.metrics != nil && !r.Reclaimed {
			s.metrics.IncActiveOperation(string(d.OperationType))
		}
		if s.logger != nil {
			l := observability.LoggerWithTrace(ctx, s.logger)
			l.InfoContext(ctx, "operation claimed",
				"operation_id", d.ID.String(),
				"operation_type", string(d.OperationType),
				"attempts", d.Attempts,
				"status", string(d.Status),
			)
		}
		out = append(out, d)
	}
	return out, nil
}

// Renew extends the lease for an active RUNNING operation fenced by workerID and unexpired lease_until.
func (s *Service) Renew(ctx context.Context, id uuid.UUID, workerID string, leaseDuration time.Duration) (OperationDetails, error) {
	if s == nil || s.store == nil {
		return OperationDetails{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return OperationDetails{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if leaseDuration <= 0 {
		leaseDuration = s.cfg.DefaultLeaseDuration
	}
	now := s.now()
	row, err := s.store.RenewOperationLease(ctx, id, workerID, now, now.Add(leaseDuration))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if _, lookupErr := s.store.GetOperationByID(ctx, id); lookupErr == nil {
				return OperationDetails{}, domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
			}
		}
		return OperationDetails{}, err
	}
	return detailsFromRow(row), nil
}

// Complete marks a leased RUNNING operation as SUCCEEDED, fenced by workerID and unexpired lease_until.
func (s *Service) Complete(ctx context.Context, id uuid.UUID, workerID string, result json.RawMessage) (OperationDetails, error) {
	if s == nil || s.store == nil {
		return OperationDetails{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return OperationDetails{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	now := s.now()
	row, err := s.store.CompleteOperation(ctx, id, workerID, result, now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if _, lookupErr := s.store.GetOperationByID(ctx, id); lookupErr == nil {
				return OperationDetails{}, domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
			}
		}
		return OperationDetails{}, err
	}
	d := detailsFromRow(row)
	if s.metrics != nil {
		s.metrics.DecActiveOperation(string(d.OperationType))
		s.metrics.IncOperation(string(d.OperationType), string(d.Status))
	}
	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.InfoContext(ctx, "operation completed",
			"operation_id", d.ID.String(),
			"operation_type", string(d.OperationType),
			"status", string(d.Status),
		)
	}
	return d, nil
}

// Fail records an operation failure fenced by workerID and unexpired lease_until, scheduling exponential
// backoff if retryable and attempts < max_attempts, or transitioning to terminal FAILED otherwise.
func (s *Service) Fail(ctx context.Context, id uuid.UUID, workerID, lastError string, retryable bool) (OperationDetails, error) {
	if s == nil || s.store == nil {
		return OperationDetails{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return OperationDetails{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	current, err := s.store.GetOperationByID(ctx, id)
	if err != nil {
		return OperationDetails{}, err
	}
	now := s.now()
	if current.Status != domain.OperationStatusRunning || current.LeasedBy == nil || *current.LeasedBy != workerID || (current.LeaseUntil != nil && !current.LeaseUntil.After(now)) {
		return OperationDetails{}, domain.Conflict("LEASE_LOST", "operation lease is not held by worker")
	}

	var row persistence.OperationRow
	if retryable && current.Attempts < current.MaxAttempts {
		delay := ComputeBackoff(current.Attempts, s.cfg.BaseRetryDelay, s.cfg.MaxRetryDelay)
		row, err = s.store.RetryOperation(ctx, id, workerID, now, now.Add(delay), lastError)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return OperationDetails{}, domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
			}
			return OperationDetails{}, err
		}
		d := detailsFromRow(row)
		if s.metrics != nil {
			s.metrics.DecActiveOperation(string(d.OperationType))
			s.metrics.IncOperation(string(d.OperationType), "RETRY")
		}
		if s.logger != nil {
			l := observability.LoggerWithTrace(ctx, s.logger)
			l.WarnContext(ctx, "operation scheduled for retry",
				"operation_id", d.ID.String(),
				"operation_type", string(d.OperationType),
				"attempts", d.Attempts,
				"status", string(d.Status),
			)
		}
		return d, nil
	}

	row, err = s.store.FailOperationTerminal(ctx, id, workerID, now, lastError)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return OperationDetails{}, domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
		}
		return OperationDetails{}, err
	}
	d := detailsFromRow(row)
	if s.metrics != nil {
		s.metrics.DecActiveOperation(string(d.OperationType))
		s.metrics.IncOperation(string(d.OperationType), string(d.Status))
	}
	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.ErrorContext(ctx, "operation failed permanently",
			"operation_id", d.ID.String(),
			"operation_type", string(d.OperationType),
			"attempts", d.Attempts,
			"status", string(d.Status),
		)
	}
	return d, nil
}

// ReapExpired marks expired RUNNING operations whose attempts >= max_attempts as terminal FAILED.
func (s *Service) ReapExpired(ctx context.Context, now time.Time) ([]OperationDetails, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	if now.IsZero() {
		now = s.now()
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	rows, err := s.store.ReapExpiredOperations(ctx, now)
	if err != nil {
		return nil, err
	}
	return s.recordReapedOperations(ctx, rows), nil
}

// ReapExpiredByType marks expired RUNNING operations of opType whose attempts >= max_attempts
// as terminal FAILED, without touching or recording metrics for other operation types.
func (s *Service) ReapExpiredByType(ctx context.Context, opType domain.OperationType, now time.Time) ([]OperationDetails, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	if !isValidOperationType(opType) {
		return nil, domain.BadRequest("INVALID_OPERATION_TYPE", "invalid operation_type")
	}
	scoped, ok := s.store.(ScopedReapStore)
	if !ok {
		return nil, domain.Unavailable("SCOPED_REAP_UNSUPPORTED", "operations store does not support type-scoped reaping")
	}
	if now.IsZero() {
		now = s.now()
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	rows, err := scoped.ReapExpiredOperationsByType(ctx, now, opType)
	if err != nil {
		return nil, err
	}
	return s.recordReapedOperations(ctx, rows), nil
}

func (s *Service) recordReapedOperations(ctx context.Context, rows []persistence.OperationRow) []OperationDetails {
	out := make([]OperationDetails, 0, len(rows))
	for _, r := range rows {
		d := detailsFromRow(r)
		if s.metrics != nil {
			s.metrics.DecActiveOperation(string(d.OperationType))
			s.metrics.IncOperation(string(d.OperationType), string(d.Status))
		}
		if s.logger != nil {
			l := observability.LoggerWithTrace(ctx, s.logger)
			l.WarnContext(ctx, "operation reaped after max attempts",
				"operation_id", d.ID.String(),
				"operation_type", string(d.OperationType),
				"attempts", d.Attempts,
				"status", string(d.Status),
			)
		}
		out = append(out, d)
	}
	return out
}

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

// EnqueueOutboxTx inserts an outbox event within the caller's database transaction.
func (s *Service) EnqueueOutboxTx(ctx context.Context, tx TxStore, input EnqueueOutboxInput) (persistence.OutboxEventRow, error) {
	return EnqueueOutboxTx(ctx, tx, input)
}

// EnqueueOutboxTx inserts an outbox event within the caller's database transaction.
func EnqueueOutboxTx(ctx context.Context, tx TxStore, input EnqueueOutboxInput) (persistence.OutboxEventRow, error) {
	if tx == nil {
		return persistence.OutboxEventRow{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "outbox store is not configured")
	}
	return tx.EnqueueOutboxEvent(ctx, persistence.EnqueueOutboxParams{
		ID:          input.ID,
		EventType:   input.EventType,
		AggregateID: input.AggregateID,
		Payload:     input.Payload,
		AvailableAt: input.AvailableAt,
	})
}

// ClaimOutbox leases undelivered outbox events ready for dispatch using FOR UPDATE SKIP LOCKED.
func (s *Service) ClaimOutbox(ctx context.Context, workerID string, leaseDuration time.Duration, limit int) ([]persistence.OutboxEventRow, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return nil, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if leaseDuration <= 0 {
		leaseDuration = s.cfg.DefaultLeaseDuration
	}
	now := s.now()
	return s.store.ClaimOutboxEvents(ctx, workerID, now, now.Add(leaseDuration), limit)
}

// MarkOutboxDelivered marks an outbox event as delivered, strictly fenced by workerID.
func (s *Service) MarkOutboxDelivered(ctx context.Context, id uuid.UUID, workerID string) (persistence.OutboxEventRow, error) {
	if s == nil || s.store == nil {
		return persistence.OutboxEventRow{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return persistence.OutboxEventRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	row, err := s.store.MarkOutboxEventDelivered(ctx, id, workerID, s.now())
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if _, lookupErr := s.store.GetOutboxEventByID(ctx, id); lookupErr == nil {
				return persistence.OutboxEventRow{}, domain.Conflict("LEASE_LOST", "outbox event lease is no longer held by worker")
			}
		}
		return persistence.OutboxEventRow{}, err
	}
	return row, nil
}

// FailOutbox records an outbox delivery failure fenced by workerID and schedules the next retry attempt.
func (s *Service) FailOutbox(ctx context.Context, id uuid.UUID, workerID string, retryDelay time.Duration, lastError string) (persistence.OutboxEventRow, error) {
	if s == nil || s.store == nil {
		return persistence.OutboxEventRow{}, domain.Unavailable("OPERATIONS_UNAVAILABLE", "operations store is not configured")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return persistence.OutboxEventRow{}, domain.BadRequest("INVALID_WORKER_ID", "worker_id must not be empty")
	}
	if retryDelay < 0 {
		retryDelay = 0
	}
	nextAt := s.now().Add(retryDelay)
	row, err := s.store.FailOutboxEvent(ctx, id, workerID, nextAt, lastError)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			if _, lookupErr := s.store.GetOutboxEventByID(ctx, id); lookupErr == nil {
				return persistence.OutboxEventRow{}, domain.Conflict("LEASE_LOST", "outbox event lease is no longer held by worker")
			}
		}
		return persistence.OutboxEventRow{}, err
	}
	return row, nil
}

// ComputeBackoff calculates capped exponential backoff: base * 2^(attempt-1), clamped to maxDelay.
func ComputeBackoff(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	if baseDelay <= 0 {
		baseDelay = defaultBaseRetryDelay
	}
	if maxDelay <= 0 {
		maxDelay = defaultMaxRetryDelay
	}
	if attempt <= 1 {
		if baseDelay > maxDelay {
			return maxDelay
		}
		return baseDelay
	}
	delay := baseDelay
	for i := 1; i < attempt; i++ {
		if delay >= maxDelay || delay > maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func detailsFromRow(row persistence.OperationRow) OperationDetails {
	var completedAt *time.Time
	if row.CompletedAt != nil {
		t := row.CompletedAt.UTC()
		completedAt = &t
	}
	return OperationDetails{
		Operation:    row.ToDomain(),
		ResourceType: derefStr(row.ResourceType),
		MaxAttempts:  row.MaxAttempts,
		LeasedBy:     derefStr(row.LeasedBy),
		Result:       row.Result,
		UpdatedAt:    row.UpdatedAt.UTC(),
		CompletedAt:  completedAt,
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
