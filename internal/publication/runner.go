package publication

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
)

const (
	defaultLeaseDuration = 15 * time.Second
	defaultRenewInterval = 5 * time.Second
	defaultPollInterval  = 150 * time.Millisecond
	defaultReapInterval  = 5 * time.Second
	defaultBatchSize     = 1
)

// RunnerConfig configures the leased PROPOSAL_PUBLISH operation runner.
type RunnerConfig struct {
	Ops           *operations.Service
	Service       *Service
	WorkerID      string
	LeaseDuration time.Duration
	RenewInterval time.Duration
	PollInterval  time.Duration
	ReapInterval  time.Duration
	BatchSize     int
	Logger        *slog.Logger
	Metrics       *observability.Metrics
	Clock         func() time.Time
}

// Runner polls for leased PROPOSAL_PUBLISH operations, renews leases during Git/GitHub I/O,
// delegates execution to Service, classifies retryable vs terminal failures, and reaps
// expired PROPOSAL_PUBLISH operations.
type Runner struct {
	ops           *operations.Service
	service       *Service
	workerID      string
	leaseDuration time.Duration
	renewInterval time.Duration
	pollInterval  time.Duration
	reapInterval  time.Duration
	batchSize     int
	logger        *slog.Logger
	metrics       *observability.Metrics
	clock         func() time.Time
}

// NewRunner constructs a leased publication Runner.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Ops == nil {
		return nil, domain.BadRequest("INVALID_RUNNER_CONFIG", "operations service is required")
	}
	if cfg.Service == nil {
		return nil, domain.BadRequest("INVALID_RUNNER_CONFIG", "publication service is required")
	}

	workerID := cfg.WorkerID
	if workerID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "localhost"
		}
		workerID = fmt.Sprintf("publisher-%s-%d-%s", host, os.Getpid(), uuid.NewString()[:8])
	}

	leaseDur := cfg.LeaseDuration
	if leaseDur <= 0 {
		leaseDur = defaultLeaseDuration
	}
	renewInt := cfg.RenewInterval
	if renewInt <= 0 {
		if leaseDur >= 3*time.Second {
			renewInt = leaseDur / 3
		} else {
			renewInt = defaultRenewInterval
		}
	}
	pollInt := cfg.PollInterval
	if pollInt <= 0 {
		pollInt = defaultPollInterval
	}
	reapInt := cfg.ReapInterval
	if reapInt <= 0 {
		reapInt = defaultReapInterval
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}

	return &Runner{
		ops:           cfg.Ops,
		service:       cfg.Service,
		workerID:      workerID,
		leaseDuration: leaseDur,
		renewInterval: renewInt,
		pollInterval:  pollInt,
		reapInterval:  reapInt,
		batchSize:     batchSize,
		logger:        cfg.Logger,
		metrics:       cfg.Metrics,
		clock:         clock,
	}, nil
}

// WorkerID returns the runner's lease holder identifier.
func (r *Runner) WorkerID() string {
	return r.workerID
}

// Run continuously polls for PROPOSAL_PUBLISH operations and reaps expired leases until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	pollTicker := time.NewTicker(r.pollInterval)
	defer pollTicker.Stop()

	reapTicker := time.NewTicker(r.reapInterval)
	defer reapTicker.Stop()

	for {
		if ctx.Err() != nil {
			return nil
		}

		claimed, err := r.ProcessOnce(ctx)
		if err != nil && ctx.Err() == nil && r.logger != nil {
			_, msg := safeErrorCodeMessage(err)
			observability.LoggerWithTrace(ctx, r.logger).Error("publication poll iteration failed",
				"error_code", "PUBLICATION_POLL_ERROR",
				"reason", msg,
			)
		}

		if ctx.Err() != nil {
			return nil
		}
		if claimed > 0 {
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-reapTicker.C:
			if _, reapErr := r.ReapExpired(ctx); reapErr != nil && ctx.Err() == nil && r.logger != nil {
				_, msg := safeErrorCodeMessage(reapErr)
				observability.LoggerWithTrace(ctx, r.logger).Error("publication reap iteration failed",
					"error_code", "PUBLICATION_REAP_ERROR",
					"reason", msg,
				)
			}
		case <-pollTicker.C:
		}
	}
}

// ProcessOnce claims up to batchSize PROPOSAL_PUBLISH operations and processes them concurrently.
func (r *Runner) ProcessOnce(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}

	opType := domain.OperationTypeProposalPublish
	claimed, err := r.ops.Claim(ctx, operations.ClaimInput{
		WorkerID:      r.workerID,
		OperationType: &opType,
		Limit:         r.batchSize,
		LeaseDuration: r.leaseDuration,
		Now:           r.clock().UTC(),
	})
	if err != nil {
		return 0, err
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
	if op.OperationType != domain.OperationTypeProposalPublish {
		if r.logger != nil {
			observability.LoggerWithTrace(parentCtx, r.logger).Warn("ignoring non-publication operation",
				"operation_id", op.ID.String(),
				"operation_type", string(op.OperationType),
			)
		}
		return
	}

	attemptCtx, cancelAttempt := context.WithCancel(parentCtx)
	defer cancelAttempt()

	var leaseLost atomic.Bool
	stopRenew := make(chan struct{})
	var renewWG sync.WaitGroup
	renewWG.Add(1)
	go func() {
		defer renewWG.Done()
		ticker := time.NewTicker(r.renewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenew:
				return
			case <-attemptCtx.Done():
				return
			case <-ticker.C:
				_, err := r.ops.Renew(attemptCtx, op.ID, r.workerID, r.leaseDuration)
				if err != nil {
					if errors.Is(err, domain.ErrConflict) {
						leaseLost.Store(true)
						if r.logger != nil {
							observability.LoggerWithTrace(parentCtx, r.logger).Warn("publication operation lease lost; cancelling attempt",
								"operation_id", op.ID.String(),
								"resource_id", op.ResourceID.String(),
								"error_code", "LEASE_LOST",
							)
						}
						cancelAttempt()
						return
					}
					if attemptCtx.Err() == nil && r.logger != nil {
						code, msg := safeErrorCodeMessage(err)
						observability.LoggerWithTrace(parentCtx, r.logger).Warn("failed renewing publication operation lease",
							"operation_id", op.ID.String(),
							"error_code", code,
							"reason", msg,
						)
					}
				}
			}
		}
	}()

	res, execErr := r.service.PublishOperation(withRunnerFenced(attemptCtx), op, nil)
	close(stopRenew)
	renewWG.Wait()

	if leaseLost.Load() {
		return
	}

	if parentCtx.Err() != nil && execErr != nil {
		// Graceful shutdown interruption: do NOT permanently fail the operation or proposal.
		if r.logger != nil {
			observability.LoggerWithTrace(parentCtx, r.logger).Info("publication interrupted by shutdown; leaving operation for lease recovery",
				"operation_id", op.ID.String(),
				"resource_id", op.ResourceID.String(),
			)
		}
		return
	}

	if execErr == nil {
		resultBytes, marshalErr := domain.CanonicalJSONBytes(res)
		if marshalErr != nil {
			resultBytes = nil
		}
		if _, err := r.ops.Complete(parentCtx, op.ID, r.workerID, resultBytes); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				if r.logger != nil {
					observability.LoggerWithTrace(parentCtx, r.logger).Warn("lease lost before completing publication operation",
						"operation_id", op.ID.String(),
						"error_code", "LEASE_LOST",
					)
				}
				return
			}
			if r.logger != nil {
				code, msg := safeErrorCodeMessage(err)
				observability.LoggerWithTrace(parentCtx, r.logger).Error("failed completing publication operation",
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

	errCode, errMsg := safeErrorCodeMessage(execErr)
	safeLastErr := errCode
	if errMsg != "" && errMsg != errCode {
		safeLastErr = errCode + ": " + errMsg
	}

	if _, failErr := r.ops.Fail(parentCtx, op.ID, r.workerID, safeLastErr, retryable); failErr != nil {
		if errors.Is(failErr, domain.ErrConflict) {
			if r.logger != nil {
				observability.LoggerWithTrace(parentCtx, r.logger).Warn("lease lost before failing publication operation",
					"operation_id", op.ID.String(),
					"error_code", "LEASE_LOST",
				)
			}
			return
		}
		if r.logger != nil {
			code, msg := safeErrorCodeMessage(failErr)
			observability.LoggerWithTrace(parentCtx, r.logger).Error("failed recording operation failure",
				"operation_id", op.ID.String(),
				"error_code", code,
				"reason", msg,
			)
		}
		return
	}

	if isFinal && !isPostPublishCommitError(execErr) && !isPublicationInProgressError(execErr) {
		termCtx, termCancel := detachTimeout(parentCtx, defaultTxCleanupTimeout)
		_ = r.service.HandleOperationTerminalFailure(termCtx, op, execErr)
		termCancel()
	}
}

// ReapExpired reaps expired RUNNING PROPOSAL_PUBLISH operations and processes them
// through HandleOperationTerminalFailure without touching worker operations.
func (r *Runner) ReapExpired(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	reaped, err := r.ops.ReapExpiredByType(ctx, domain.OperationTypeProposalPublish, r.clock().UTC())
	if err != nil {
		return 0, err
	}
	count := 0
	for _, op := range reaped {
		if op.OperationType != domain.OperationTypeProposalPublish {
			continue
		}
		count++
		cause := domain.Unavailable("OPERATION_LEASE_EXPIRED", "publication operation lease expired after max attempts")
		if handleErr := r.service.HandleOperationTerminalFailure(ctx, op, cause); handleErr != nil && r.logger != nil {
			code, msg := safeErrorCodeMessage(handleErr)
			observability.LoggerWithTrace(ctx, r.logger).Error("failed handling reaped publication operation",
				"operation_id", op.ID.String(),
				"resource_id", op.ResourceID.String(),
				"error_code", code,
				"reason", msg,
			)
		}
	}
	return count, nil
}
