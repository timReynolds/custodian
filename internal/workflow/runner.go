package workflow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

var workerOperationTypes = []domain.OperationType{
	domain.OperationTypeWorkspaceIngress,
	domain.OperationTypeProposalReconstruct,
	domain.OperationTypeProposalEvaluate,
}

// RunnerConfig configures the workflow operation, outbox, lease-reaper, and retention-reaper runner.
type RunnerConfig struct {
	Service *Service
	Config  Config
}

// Runner executes leased worker operations (WORKSPACE_INGRESS, PROPOSAL_RECONSTRUCT,
// PROPOSAL_EVALUATE), transactional outbox delivery, expired lease reaping, and
// artifact retention reaping. It NEVER claims PROPOSAL_PUBLISH.
type Runner struct {
	service *Service
	cfg     Config
	nextIdx atomic.Uint64
}

// NewRunner validates RunnerConfig and constructs a workflow Runner.
func NewRunner(rc RunnerConfig) (*Runner, error) {
	if rc.Service == nil {
		return nil, domain.BadRequest("INVALID_RUNNER_CONFIG", "workflow service is required")
	}
	cfg := rc.Service.cfg
	if rc.Config.WorkerID != "" {
		cfg.WorkerID = rc.Config.WorkerID
	}
	if rc.Config.LeaseDuration > 0 {
		cfg.LeaseDuration = rc.Config.LeaseDuration
	}
	if rc.Config.RenewInterval > 0 {
		cfg.RenewInterval = rc.Config.RenewInterval
	}
	if rc.Config.PollInterval > 0 {
		cfg.PollInterval = rc.Config.PollInterval
	}
	if rc.Config.ReapInterval > 0 {
		cfg.ReapInterval = rc.Config.ReapInterval
	}
	if rc.Config.OutboxPollInterval > 0 {
		cfg.OutboxPollInterval = rc.Config.OutboxPollInterval
	}
	if rc.Config.OutboxLeaseDuration > 0 {
		cfg.OutboxLeaseDuration = rc.Config.OutboxLeaseDuration
	}
	if rc.Config.OutboxRetryDelay > 0 {
		cfg.OutboxRetryDelay = rc.Config.OutboxRetryDelay
	}
	if rc.Config.OutboxBatchSize > 0 {
		cfg.OutboxBatchSize = rc.Config.OutboxBatchSize
	}
	if rc.Config.RetentionInterval > 0 {
		cfg.RetentionInterval = rc.Config.RetentionInterval
	}
	if rc.Config.BatchSize > 0 {
		cfg.BatchSize = rc.Config.BatchSize
	}
	if rc.Config.Clock != nil {
		cfg.Clock = rc.Config.Clock
	}
	cfg = cfg.withDefaults()

	return &Runner{
		service: rc.Service,
		cfg:     cfg,
	}, nil
}

// WorkerID returns the runner's lease holder identifier.
func (r *Runner) WorkerID() string {
	return r.cfg.WorkerID
}

// Run runs operation polling, outbox dispatch, expired lease reaping, and artifact
// retention reaping until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Outbox dispatcher loop.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(r.cfg.OutboxPollInterval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := r.DispatchOutboxOnce(ctx)
			if err != nil && ctx.Err() == nil && r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(err)
				observability.LoggerWithTrace(ctx, r.service.logger).Warn("outbox dispatch iteration failed",
					"error_code", code,
					"reason", msg,
				)
			}
			if ctx.Err() != nil {
				return
			}
			if n > 0 {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// Expired lease reaper loop.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(r.cfg.ReapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := r.ReapExpired(ctx); err != nil && ctx.Err() == nil && r.service.logger != nil {
					code, msg := SafeErrorCodeMessage(err)
					observability.LoggerWithTrace(ctx, r.service.logger).Warn("lease reap iteration failed",
						"error_code", code,
						"reason", msg,
					)
				}
			}
		}
	}()

	// Artifact retention reaper loop.
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(r.cfg.RetentionInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := r.ReapExpiredArtifacts(ctx); err != nil && ctx.Err() == nil && r.service.logger != nil {
					code, msg := SafeErrorCodeMessage(err)
					observability.LoggerWithTrace(ctx, r.service.logger).Warn("artifact retention iteration failed",
						"error_code", code,
						"reason", msg,
					)
				}
			}
		}
	}()

	pollTicker := time.NewTicker(r.cfg.PollInterval)
	defer pollTicker.Stop()

	for {
		if ctx.Err() != nil {
			wg.Wait()
			return nil
		}

		claimed, err := r.ProcessOnce(ctx)
		if err != nil && ctx.Err() == nil && r.service.logger != nil {
			code, msg := SafeErrorCodeMessage(err)
			observability.LoggerWithTrace(ctx, r.service.logger).Error("workflow poll iteration failed",
				"error_code", code,
				"reason", msg,
			)
		}
		if ctx.Err() != nil {
			wg.Wait()
			return nil
		}
		if claimed > 0 {
			continue
		}

		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-pollTicker.C:
		}
	}
}

// ProcessOnce claims up to BatchSize worker operations across WORKSPACE_INGRESS,
// PROPOSAL_RECONSTRUCT, and PROPOSAL_EVALUATE (never claiming PROPOSAL_PUBLISH) and processes them.
func (r *Runner) ProcessOnce(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}

	start := int(r.nextIdx.Add(1)-1) % len(workerOperationTypes)
	var claimed []operations.OperationDetails

	for offset := 0; offset < len(workerOperationTypes); offset++ {
		opType := workerOperationTypes[(start+offset)%len(workerOperationTypes)]
		remaining := r.cfg.BatchSize - len(claimed)
		if remaining <= 0 {
			break
		}
		batch, err := r.service.ops.Claim(ctx, operations.ClaimInput{
			WorkerID:      r.cfg.WorkerID,
			OperationType: &opType,
			Limit:         remaining,
			LeaseDuration: r.cfg.LeaseDuration,
			Now:           r.cfg.Clock().UTC(),
		})
		if err != nil {
			if len(claimed) > 0 {
				break
			}
			return 0, err
		}
		claimed = append(claimed, batch...)
		if len(claimed) >= r.cfg.BatchSize {
			break
		}
	}

	if len(claimed) == 0 {
		return 0, nil
	}

	if len(claimed) == 1 {
		r.processOperation(ctx, claimed[0])
		return 1, nil
	}

	var wg sync.WaitGroup
	for _, op := range claimed {
		opCopy := op
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.processOperation(ctx, opCopy)
		}()
	}
	wg.Wait()
	return len(claimed), nil
}

func (r *Runner) processOperation(parentCtx context.Context, op operations.OperationDetails) {
	if op.OperationType == domain.OperationTypeProposalPublish {
		if r.service.logger != nil {
			observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("ignoring PROPOSAL_PUBLISH operation in worker",
				"operation_id", op.ID.String(),
				"operation_type", string(op.OperationType),
			)
		}
		return
	}

	attemptCtx, cancelAttempt := context.WithCancel(parentCtx)
	defer cancelAttempt()
	if lease, ok := operationLeaseForOp(op, r.cfg.WorkerID); ok {
		attemptCtx = withOperationLease(attemptCtx, lease)
	}

	var leaseLost atomic.Bool
	stopRenew := make(chan struct{})
	var renewWG sync.WaitGroup
	renewWG.Add(1)
	go func() {
		defer renewWG.Done()
		ticker := time.NewTicker(r.cfg.RenewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenew:
				return
			case <-attemptCtx.Done():
				return
			case <-ticker.C:
				_, err := r.service.ops.Renew(attemptCtx, op.ID, r.cfg.WorkerID, r.cfg.LeaseDuration)
				if err != nil {
					if errors.Is(err, domain.ErrConflict) {
						leaseLost.Store(true)
						if r.service.logger != nil {
							observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("operation lease lost; cancelling attempt",
								"operation_id", op.ID.String(),
								"operation_type", string(op.OperationType),
								"resource_id", op.ResourceID.String(),
								"error_code", "LEASE_LOST",
							)
						}
						cancelAttempt()
						return
					}
					if attemptCtx.Err() == nil && r.service.logger != nil {
						code, msg := SafeErrorCodeMessage(err)
						observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("failed renewing operation lease",
							"operation_id", op.ID.String(),
							"operation_type", string(op.OperationType),
							"error_code", code,
							"reason", msg,
						)
					}
				}
			}
		}
	}()

	var (
		res     any
		execErr error
	)
	switch op.OperationType {
	case domain.OperationTypeWorkspaceIngress:
		res, execErr = r.service.executeIngress(attemptCtx, op)
	case domain.OperationTypeProposalReconstruct:
		res, execErr = r.service.ExecuteReconstruct(attemptCtx, op)
	case domain.OperationTypeProposalEvaluate:
		res, execErr = r.service.ExecuteEvaluate(attemptCtx, op)
	default:
		execErr = domain.BadRequest("UNSUPPORTED_OPERATION_TYPE", "unsupported worker operation type")
	}

	close(stopRenew)
	renewWG.Wait()

	if leaseLost.Load() {
		return
	}

	if parentCtx.Err() != nil && execErr != nil {
		if r.service.logger != nil {
			observability.LoggerWithTrace(parentCtx, r.service.logger).Info("operation interrupted by shutdown; leaving lease for recovery",
				"operation_id", op.ID.String(),
				"operation_type", string(op.OperationType),
				"resource_id", op.ResourceID.String(),
			)
		}
		return
	}

	if execErr != nil && isLeaseLostError(execErr) {
		if r.service.logger != nil {
			observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("operation lease lost during execution",
				"operation_id", op.ID.String(),
				"operation_type", string(op.OperationType),
				"resource_id", op.ResourceID.String(),
				"error_code", "LEASE_LOST",
			)
		}
		return
	}

	if execErr == nil {
		resultBytes, marshalErr := domain.CanonicalJSONBytes(res)
		if marshalErr != nil {
			resultBytes = nil
		}
		compCtx, compCancel := detachTimeout(parentCtx, defaultTxCleanupTimeout)
		_, err := r.service.ops.Complete(compCtx, op.ID, r.cfg.WorkerID, resultBytes)
		compCancel()
		if err != nil {
			if errors.Is(err, domain.ErrConflict) {
				if r.service.logger != nil {
					observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("lease lost before completing operation",
						"operation_id", op.ID.String(),
						"error_code", "LEASE_LOST",
					)
				}
				return
			}
			if r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(err)
				observability.LoggerWithTrace(parentCtx, r.service.logger).Error("failed completing operation",
					"operation_id", op.ID.String(),
					"error_code", code,
					"reason", msg,
				)
			}
		}
		return
	}

	retryable := IsRetryableError(execErr)
	isFinal := !retryable || (op.MaxAttempts > 0 && op.Attempts >= op.MaxAttempts)

	if isFinal {
		termCtx, termCancel := detachTimeout(attemptCtx, defaultTxCleanupTimeout)
		handleErr := r.service.handleTerminalFailure(termCtx, op, execErr)
		termCancel()
		if handleErr != nil {
			if isLeaseLostError(handleErr) {
				if r.service.logger != nil {
					observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("lease lost before handling terminal operation failure",
						"operation_id", op.ID.String(),
						"operation_type", string(op.OperationType),
						"resource_id", op.ResourceID.String(),
						"error_code", "LEASE_LOST",
					)
				}
				return
			}
			if r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(handleErr)
				observability.LoggerWithTrace(parentCtx, r.service.logger).Error("failed handling terminal operation failure",
					"operation_id", op.ID.String(),
					"operation_type", string(op.OperationType),
					"resource_id", op.ResourceID.String(),
					"error_code", code,
					"reason", msg,
				)
			}
		}
	}

	safeLastErr := formatSafeLastError(execErr)
	failCtx, failCancel := detachTimeout(parentCtx, defaultTxCleanupTimeout)
	_, failErr := r.service.ops.Fail(failCtx, op.ID, r.cfg.WorkerID, safeLastErr, retryable)
	failCancel()
	if failErr != nil {
		if errors.Is(failErr, domain.ErrConflict) {
			if r.service.logger != nil {
				observability.LoggerWithTrace(parentCtx, r.service.logger).Warn("lease lost before failing operation",
					"operation_id", op.ID.String(),
					"error_code", "LEASE_LOST",
				)
			}
			return
		}
		if r.service.logger != nil {
			code, msg := SafeErrorCodeMessage(failErr)
			observability.LoggerWithTrace(parentCtx, r.service.logger).Error("failed recording operation failure",
				"operation_id", op.ID.String(),
				"error_code", code,
				"reason", msg,
			)
		}
		return
	}
}

func (s *Service) handleTerminalFailure(ctx context.Context, op operations.OperationDetails, cause error) error {
	if op.Status != domain.OperationStatusRunning {
		ctx = withoutOperationLease(ctx)
	} else {
		ctx = s.ensureOperationLeaseContext(ctx, op)
	}
	code, _ := SafeErrorCodeMessage(cause)
	if code == "" {
		code = "OPERATION_FAILED"
	}
	switch op.OperationType {
	case domain.OperationTypeWorkspaceIngress:
		var blocked *ingressBlockedError
		if errors.As(cause, &blocked) {
			return s.recordIngressBlocked(ctx, blocked.workspaceID, blocked.effect, blocked.bundleDigest, blocked.matchedRuleIDs)
		}
		return s.failWorkspaceTerminal(ctx, op.ResourceID, code)
	case domain.OperationTypeProposalReconstruct:
		if s.proposals == nil || op.ResourceID == uuid.Nil {
			return nil
		}
		prop, err := s.proposals.Get(ctx, op.ResourceID)
		if err != nil {
			return err
		}
		if prop.Status != domain.ProposalStatusCaptured && prop.Status != domain.ProposalStatusReconstructing {
			return nil
		}
		_, err = s.proposals.MarkFailed(ctx, prop.ID, prop.Version, code)
		return err
	case domain.OperationTypeProposalEvaluate:
		if s.proposals == nil || op.ResourceID == uuid.Nil {
			return nil
		}
		prop, err := s.proposals.Get(ctx, op.ResourceID)
		if err != nil {
			return err
		}
		if prop.Status != domain.ProposalStatusReconstructed && prop.Status != domain.ProposalStatusEvaluating {
			return nil
		}
		_, err = s.proposals.MarkFailed(ctx, prop.ID, prop.Version, code)
		return err
	default:
		return nil
	}
}

const reapExpiredWorkerOperationsSQL = `
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
  AND operation_type IN ('WORKSPACE_INGRESS', 'PROPOSAL_RECONSTRUCT', 'PROPOSAL_EVALUATE')
RETURNING id, operation_type, resource_type, resource_id, status, attempts, max_attempts,
    available_at, lease_until, leased_by, last_error, result, created_at, updated_at, completed_at
`

const listStuckWorkspacesWithFailedOpSQL = `
SELECT w.id
FROM workspaces w
WHERE w.status IN ('PENDING', 'PREPARING')
  AND EXISTS (
      SELECT 1
      FROM operations o
      WHERE o.resource_id = w.id
        AND o.operation_type = 'WORKSPACE_INGRESS'
        AND o.status = 'FAILED'
  )
ORDER BY w.updated_at ASC, w.id ASC
LIMIT 100
`

const listStuckProposalsWithFailedOpSQL = `
SELECT p.id, p.status
FROM proposals p
WHERE (
    p.status IN ('CAPTURED', 'RECONSTRUCTING')
    AND EXISTS (
        SELECT 1
        FROM operations o
        WHERE o.resource_id = p.id
          AND o.operation_type = 'PROPOSAL_RECONSTRUCT'
          AND o.status = 'FAILED'
    )
) OR (
    p.status = 'EVALUATING'
    AND EXISTS (
        SELECT 1
        FROM operations o
        WHERE o.resource_id = p.id
          AND o.operation_type = 'PROPOSAL_EVALUATE'
          AND o.status = 'FAILED'
    )
)
ORDER BY p.updated_at ASC, p.id ASC
LIMIT 100
`

// ReapExpired reaps expired RUNNING worker operations (WORKSPACE_INGRESS, PROPOSAL_RECONSTRUCT,
// PROPOSAL_EVALUATE) whose attempts >= max_attempts without touching PROPOSAL_PUBLISH rows,
// transitions failed worker resources to FAILED with "OPERATION_LEASE_EXPIRED", and
// reconciles any non-terminal worker resources whose latest operation is already FAILED.
func (r *Runner) ReapExpired(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	now := r.cfg.Clock().UTC().Truncate(time.Microsecond)
	reaped, err := r.reapWorkerOperations(ctx, now)
	if err != nil {
		return 0, err
	}
	count := 0
	cause := domain.Unavailable("OPERATION_LEASE_EXPIRED", "operation lease expired after max attempts")
	for _, op := range reaped {
		count++
		if handleErr := r.service.handleTerminalFailure(ctx, op, cause); handleErr != nil && !errors.Is(handleErr, domain.ErrConflict) && r.service.logger != nil {
			code, msg := SafeErrorCodeMessage(handleErr)
			observability.LoggerWithTrace(ctx, r.service.logger).Error("failed handling reaped worker operation",
				"operation_id", op.ID.String(),
				"operation_type", string(op.OperationType),
				"resource_id", op.ResourceID.String(),
				"error_code", code,
				"reason", msg,
			)
		}
	}

	reconciled, recErr := r.reconcileStuckWorkerResources(ctx, cause)
	if recErr != nil {
		return count + reconciled, recErr
	}
	return count + reconciled, nil
}

func (r *Runner) reapWorkerOperations(ctx context.Context, now time.Time) ([]operations.OperationDetails, error) {
	pool := r.service.store.Pool()
	if pool == nil {
		return nil, domain.Unavailable("DATABASE_UNAVAILABLE", "database pool is not initialized")
	}
	rows, err := pool.Query(ctx, reapExpiredWorkerOperationsSQL, now)
	if err != nil {
		return nil, persistence.MapError(err)
	}
	defer rows.Close()

	out := make([]operations.OperationDetails, 0)
	for rows.Next() {
		var row persistence.OperationRow
		var opType, status string
		if err := rows.Scan(
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
			return nil, persistence.MapError(err)
		}
		row.OperationType = domain.OperationType(opType)
		row.Status = domain.OperationStatus(status)
		d := operationDetailsFromRow(row)
		if r.service.metrics != nil {
			r.service.metrics.DecActiveOperation(string(d.OperationType))
			r.service.metrics.IncOperation(string(d.OperationType), string(d.Status))
		}
		if r.service.logger != nil {
			observability.LoggerWithTrace(ctx, r.service.logger).WarnContext(ctx, "worker operation reaped after max attempts",
				"operation_id", d.ID.String(),
				"operation_type", string(d.OperationType),
				"attempts", d.Attempts,
				"status", string(d.Status),
			)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, persistence.MapError(err)
	}
	return out, nil
}

func (r *Runner) reconcileStuckWorkerResources(ctx context.Context, cause error) (int, error) {
	pool := r.service.store.Pool()
	if pool == nil {
		return 0, nil
	}

	reconciled := 0

	// 1. Reconcile stuck workspaces (PENDING/PREPARING) whose latest WORKSPACE_INGRESS op is already FAILED.
	wsRows, err := pool.Query(ctx, listStuckWorkspacesWithFailedOpSQL)
	if err != nil {
		return reconciled, persistence.MapError(err)
	}
	var stuckWS []uuid.UUID
	for wsRows.Next() {
		var wsID uuid.UUID
		if scanErr := wsRows.Scan(&wsID); scanErr != nil {
			wsRows.Close()
			return reconciled, persistence.MapError(scanErr)
		}
		stuckWS = append(stuckWS, wsID)
	}
	if rowsErr := wsRows.Err(); rowsErr != nil {
		wsRows.Close()
		return reconciled, persistence.MapError(rowsErr)
	}
	wsRows.Close()

	for _, wsID := range stuckWS {
		latestOp, opErr := r.service.store.GetLatestOperationByResource(ctx, wsID, domain.OperationTypeWorkspaceIngress)
		if opErr != nil || latestOp.Status != domain.OperationStatusFailed {
			continue
		}
		if handleErr := r.service.handleTerminalFailure(ctx, operationDetailsFromRow(latestOp), cause); handleErr != nil {
			if !errors.Is(handleErr, domain.ErrConflict) && r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(handleErr)
				observability.LoggerWithTrace(ctx, r.service.logger).Error("failed reconciling stuck workspace",
					"workspace_id", wsID.String(),
					"operation_id", latestOp.ID.String(),
					"error_code", code,
					"reason", msg,
				)
			}
			continue
		}
		reconciled++
	}

	// 2. Reconcile stuck proposals (CAPTURED/RECONSTRUCTING/EVALUATING) whose latest worker op is already FAILED.
	propRows, err := pool.Query(ctx, listStuckProposalsWithFailedOpSQL)
	if err != nil {
		return reconciled, persistence.MapError(err)
	}
	type stuckProp struct {
		id     uuid.UUID
		status string
	}
	var stuckProps []stuckProp
	for propRows.Next() {
		var sp stuckProp
		if scanErr := propRows.Scan(&sp.id, &sp.status); scanErr != nil {
			propRows.Close()
			return reconciled, persistence.MapError(scanErr)
		}
		stuckProps = append(stuckProps, sp)
	}
	if rowsErr := propRows.Err(); rowsErr != nil {
		propRows.Close()
		return reconciled, persistence.MapError(rowsErr)
	}
	propRows.Close()

	for _, sp := range stuckProps {
		opType := domain.OperationTypeProposalReconstruct
		if sp.status == string(domain.ProposalStatusEvaluating) {
			opType = domain.OperationTypeProposalEvaluate
		}
		latestOp, opErr := r.service.store.GetLatestOperationByResource(ctx, sp.id, opType)
		if opErr != nil || latestOp.Status != domain.OperationStatusFailed {
			continue
		}
		if handleErr := r.service.handleTerminalFailure(ctx, operationDetailsFromRow(latestOp), cause); handleErr != nil {
			if !errors.Is(handleErr, domain.ErrConflict) && r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(handleErr)
				observability.LoggerWithTrace(ctx, r.service.logger).Error("failed reconciling stuck proposal",
					"proposal_id", sp.id.String(),
					"operation_id", latestOp.ID.String(),
					"error_code", code,
					"reason", msg,
				)
			}
			continue
		}
		reconciled++
	}

	// 3. Reap orphaned RUNNING/PENDING scan_runs & PENDING model_assessments whose proposal no longer
	// has an active PROPOSAL_EVALUATE operation (e.g. worker crash/SIGKILL or reaped operation).
	now := r.cfg.Clock().UTC().Truncate(time.Microsecond)
	_, _ = pool.Exec(ctx, cleanupOrphanedScanRunsSQL, now)
	_, _ = pool.Exec(ctx, cleanupOrphanedModelAssessmentsSQL)

	return reconciled, nil
}

const cleanupOrphanedScanRunsSQL = `
UPDATE scan_runs sr
SET status       = 'FAILED',
    completed_at = COALESCE(sr.completed_at, $1)
WHERE sr.status IN ('PENDING', 'RUNNING')
  AND NOT EXISTS (
      SELECT 1
      FROM operations o
      WHERE o.resource_id = sr.proposal_id
        AND o.operation_type = 'PROPOSAL_EVALUATE'
        AND o.status IN ('PENDING', 'RUNNING')
  )
`

const cleanupOrphanedModelAssessmentsSQL = `
UPDATE model_assessments ma
SET status      = 'FAILED',
    risk        = COALESCE(ma.risk, 'NONE'),
    disposition = COALESCE(ma.disposition, 'INDETERMINATE')
WHERE ma.status = 'PENDING'
  AND NOT EXISTS (
      SELECT 1
      FROM operations o
      WHERE o.resource_id = ma.proposal_id
        AND o.operation_type = 'PROPOSAL_EVALUATE'
        AND o.status IN ('PENDING', 'RUNNING')
  )
`

func operationDetailsFromRow(row persistence.OperationRow) operations.OperationDetails {
	var completedAt *time.Time
	if row.CompletedAt != nil {
		t := row.CompletedAt.UTC()
		completedAt = &t
	}
	var resourceType, leasedBy string
	if row.ResourceType != nil {
		resourceType = *row.ResourceType
	}
	if row.LeasedBy != nil {
		leasedBy = *row.LeasedBy
	}
	return operations.OperationDetails{
		Operation:    row.ToDomain(),
		ResourceType: resourceType,
		MaxAttempts:  row.MaxAttempts,
		LeasedBy:     leasedBy,
		Result:       row.Result,
		UpdatedAt:    row.UpdatedAt.UTC(),
		CompletedAt:  completedAt,
	}
}

// DispatchOutboxOnce claims pending outbox events and marks them delivered (or schedules
// retry via FailOutbox on dispatcher errors).
func (r *Runner) DispatchOutboxOnce(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	events, err := r.service.ops.ClaimOutbox(ctx, r.cfg.WorkerID, r.cfg.OutboxLeaseDuration, r.cfg.OutboxBatchSize)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}

	processed := 0
	for _, ev := range events {
		if ctx.Err() != nil {
			break
		}
		var dispatchErr error
		if r.service.outboxDispatch != nil {
			dispatchErr = r.service.outboxDispatch.Dispatch(ctx, ev)
		} else if r.service.logger != nil {
			observability.LoggerWithTrace(ctx, r.service.logger).InfoContext(ctx, "outbox event dispatched",
				"outbox_event_id", ev.ID.String(),
				"event_type", ev.EventType,
				"aggregate_id", ev.AggregateID.String(),
			)
		}

		if dispatchErr != nil {
			if ctx.Err() != nil {
				break
			}
			safeErr := formatSafeLastError(dispatchErr)
			if r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(dispatchErr)
				observability.LoggerWithTrace(ctx, r.service.logger).Warn("outbox event dispatch failed",
					"outbox_event_id", ev.ID.String(),
					"event_type", ev.EventType,
					"attempts", ev.Attempts,
					"error_code", code,
					"reason", msg,
				)
			}
			retryDelay := operations.ComputeBackoff(ev.Attempts+1, r.cfg.OutboxRetryDelay, defaultMaxOutboxRetryDelay)
			if _, failErr := r.service.ops.FailOutbox(ctx, ev.ID, r.cfg.WorkerID, retryDelay, safeErr); failErr != nil && !errors.Is(failErr, domain.ErrConflict) && r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(failErr)
				observability.LoggerWithTrace(ctx, r.service.logger).Warn("failed scheduling outbox event retry",
					"outbox_event_id", ev.ID.String(),
					"error_code", code,
					"reason", msg,
				)
			}
			continue
		}
		if _, err := r.service.ops.MarkOutboxDelivered(ctx, ev.ID, r.cfg.WorkerID); err != nil {
			if !errors.Is(err, domain.ErrConflict) && r.service.logger != nil {
				code, msg := SafeErrorCodeMessage(err)
				observability.LoggerWithTrace(ctx, r.service.logger).Warn("failed marking outbox event delivered",
					"outbox_event_id", ev.ID.String(),
					"error_code", code,
					"reason", msg,
				)
			}
			continue
		}
		processed++
	}
	return processed, nil
}

// ReapExpiredArtifacts deletes expired artifact blobs from SnapshotStore (ignoring ErrNotFound)
// and marks the artifact metadata deleted_at without mutating proposals or audit_events.
func (r *Runner) ReapExpiredArtifacts(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if r.service.artifacts == nil || r.service.snapshotStore == nil {
		return 0, nil
	}

	total := 0
	for {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		now := r.cfg.Clock().UTC().Truncate(time.Microsecond)
		expired, err := r.service.artifacts.ListExpired(ctx, now, r.cfg.RetentionBatchSize)
		if err != nil {
			return total, err
		}
		if len(expired) == 0 {
			return total, nil
		}

		batchMarked := 0
		for _, art := range expired {
			if ctx.Err() != nil {
				return total, ctx.Err()
			}
			if err := r.service.snapshotStore.Delete(ctx, art.Artifact); err != nil && !errors.Is(err, domain.ErrNotFound) {
				if r.service.logger != nil {
					code, msg := SafeErrorCodeMessage(err)
					observability.LoggerWithTrace(ctx, r.service.logger).Warn("failed deleting expired artifact blob",
						"artifact_id", art.ID.String(),
						"error_code", code,
						"reason", msg,
					)
				}
				continue
			}
			if _, err := r.service.artifacts.MarkDeleted(ctx, art.ID, now); err != nil && !errors.Is(err, domain.ErrConflict) && !errors.Is(err, domain.ErrNotFound) {
				if r.service.logger != nil {
					code, msg := SafeErrorCodeMessage(err)
					observability.LoggerWithTrace(ctx, r.service.logger).Warn("failed marking expired artifact deleted",
						"artifact_id", art.ID.String(),
						"error_code", code,
						"reason", msg,
					)
				}
				continue
			}
			batchMarked++
			total++
			if r.service.logger != nil {
				observability.LoggerWithTrace(ctx, r.service.logger).InfoContext(ctx, "expired artifact reaped",
					"artifact_id", art.ID.String(),
					"sha256", art.SHA256,
				)
			}
		}

		if batchMarked == 0 || len(expired) < r.cfg.RetentionBatchSize {
			return total, nil
		}
	}
}
