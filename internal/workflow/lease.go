package workflow

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/workspaces"
)

type operationLeaseKey struct{}

type operationLease struct {
	opID     uuid.UUID
	workerID string
	attempt  int
}

func withOperationLease(ctx context.Context, lease operationLease) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, operationLeaseKey{}, lease)
}

func withoutOperationLease(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, operationLeaseKey{}, operationLease{})
}

func operationLeaseFromContext(ctx context.Context) (operationLease, bool) {
	if ctx == nil {
		return operationLease{}, false
	}
	lease, ok := ctx.Value(operationLeaseKey{}).(operationLease)
	if !ok || lease.opID == uuid.Nil || strings.TrimSpace(lease.workerID) == "" {
		return operationLease{}, false
	}
	return lease, true
}

func operationLeaseForOp(op operations.OperationDetails, fallbackWorkerID string) (operationLease, bool) {
	if op.ID == uuid.Nil || op.Status != domain.OperationStatusRunning {
		return operationLease{}, false
	}
	workerID := strings.TrimSpace(op.LeasedBy)
	if workerID == "" {
		workerID = strings.TrimSpace(fallbackWorkerID)
	}
	if workerID == "" {
		return operationLease{}, false
	}
	return operationLease{
		opID:     op.ID,
		workerID: workerID,
		attempt:  op.Attempts,
	}, true
}

func (s *Service) ensureOperationLeaseContext(ctx context.Context, op operations.OperationDetails) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := operationLeaseFromContext(ctx); ok {
		return ctx
	}
	if lease, ok := operationLeaseForOp(op, ""); ok {
		return withOperationLease(ctx, lease)
	}
	return ctx
}

func isLeaseLostError(err error) bool {
	var domErr *domain.DomainError
	return errors.As(err, &domErr) && domErr.Code() == "LEASE_LOST"
}

const selectOperationLeaseForUpdateSQL = `
SELECT status, leased_by, lease_until, attempts
FROM operations
WHERE id = $1
FOR UPDATE
`

const selectOperationLeaseSQL = `
SELECT status, leased_by, lease_until, attempts
FROM operations
WHERE id = $1
`

func verifyOperationLeaseTx(ctx context.Context, tx *persistence.Tx, lease operationLease, now time.Time) error {
	if tx == nil || tx.Tx() == nil {
		return nil
	}
	var (
		status     string
		leasedBy   *string
		leaseUntil *time.Time
		attempts   int
	)
	err := tx.Tx().QueryRow(ctx, selectOperationLeaseForUpdateSQL, lease.opID).Scan(&status, &leasedBy, &leaseUntil, &attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
		}
		return persistence.MapError(err)
	}
	if !isLeaseHeld(status, leasedBy, leaseUntil, attempts, lease, now) {
		return domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
	}
	return nil
}

func (s *Service) verifyOperationLease(ctx context.Context) error {
	if s == nil || s.store == nil || s.store.Pool() == nil {
		return nil
	}
	lease, ok := operationLeaseFromContext(ctx)
	if !ok {
		return nil
	}
	var (
		status     string
		leasedBy   *string
		leaseUntil *time.Time
		attempts   int
	)
	err := s.store.Pool().QueryRow(ctx, selectOperationLeaseSQL, lease.opID).Scan(&status, &leasedBy, &leaseUntil, &attempts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
		}
		return persistence.MapError(err)
	}
	if !isLeaseHeld(status, leasedBy, leaseUntil, attempts, lease, s.now()) {
		return domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
	}
	return nil
}

func isLeaseHeld(status string, leasedBy *string, leaseUntil *time.Time, attempts int, lease operationLease, now time.Time) bool {
	if domain.OperationStatus(status) != domain.OperationStatusRunning {
		return false
	}
	if leasedBy == nil || *leasedBy != lease.workerID {
		return false
	}
	if lease.attempt > 0 && attempts != lease.attempt {
		return false
	}
	if leaseUntil != nil && !leaseUntil.After(now) {
		return false
	}
	return true
}

type leaseFencedWorkspaceStore struct {
	workspaces.Store
	store *persistence.Store
	now   func() time.Time
}

func (l *leaseFencedWorkspaceStore) RunInTx(ctx context.Context, fn func(tx workspaces.TxStore) error) error {
	if lease, ok := operationLeaseFromContext(ctx); ok && l.store != nil && l.store.Pool() != nil {
		return l.store.WithTx(ctx, func(tx *persistence.Tx) error {
			if err := verifyOperationLeaseTx(ctx, tx, lease, l.now()); err != nil {
				return err
			}
			return fn(tx)
		})
	}
	return l.Store.RunInTx(ctx, fn)
}

type leaseFencedProposalStore struct {
	proposals.Store
	store *persistence.Store
	now   func() time.Time
}

func (l *leaseFencedProposalStore) RunInTx(ctx context.Context, fn func(tx proposals.TxStore) error) error {
	if lease, ok := operationLeaseFromContext(ctx); ok && l.store != nil && l.store.Pool() != nil {
		return l.store.WithTx(ctx, func(tx *persistence.Tx) error {
			if err := verifyOperationLeaseTx(ctx, tx, lease, l.now()); err != nil {
				return err
			}
			return fn(tx)
		})
	}
	return l.Store.RunInTx(ctx, fn)
}
