package operations_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestComputeBackoffUnit(t *testing.T) {
	t.Parallel()

	base := 1 * time.Second
	maxDelay := 10 * time.Second

	if got := operations.ComputeBackoff(1, base, maxDelay); got != 1*time.Second {
		t.Fatalf("attempt 1 = %s, want 1s", got)
	}
	if got := operations.ComputeBackoff(2, base, maxDelay); got != 2*time.Second {
		t.Fatalf("attempt 2 = %s, want 2s", got)
	}
	if got := operations.ComputeBackoff(3, base, maxDelay); got != 4*time.Second {
		t.Fatalf("attempt 3 = %s, want 4s", got)
	}
	if got := operations.ComputeBackoff(4, base, maxDelay); got != 8*time.Second {
		t.Fatalf("attempt 4 = %s, want 8s", got)
	}
	if got := operations.ComputeBackoff(5, base, maxDelay); got != 10*time.Second {
		t.Fatalf("attempt 5 = %s, want 10s (capped)", got)
	}
	if got := operations.ComputeBackoff(100, base, maxDelay); got != 10*time.Second {
		t.Fatalf("attempt 100 = %s, want 10s (overflow-safe cap)", got)
	}
}

func TestOperationsNilStoreUnit(t *testing.T) {
	t.Parallel()

	svc := operations.NewService(nil, nil, nil)
	ctx := context.Background()
	id := domain.MustNewID()

	if _, err := svc.Enqueue(ctx, operations.EnqueueInput{OperationType: domain.OperationTypeWorkspaceIngress, ResourceID: id}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Enqueue nil store: got %v", err)
	}
	if _, err := svc.GetByID(ctx, id); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("GetByID nil store: got %v", err)
	}
	if _, err := svc.GetDetails(ctx, id); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("GetDetails nil store: got %v", err)
	}
	if _, err := svc.Claim(ctx, operations.ClaimInput{WorkerID: "w1"}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Claim nil store: got %v", err)
	}
	if _, err := svc.Renew(ctx, id, "w1", time.Second); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Renew nil store: got %v", err)
	}
	if _, err := svc.Complete(ctx, id, "w1", nil); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Complete nil store: got %v", err)
	}
	if _, err := svc.Fail(ctx, id, "w1", "err", false); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Fail nil store: got %v", err)
	}
	if _, err := svc.ReapExpired(ctx, time.Now()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("ReapExpired nil store: got %v", err)
	}
	if _, err := svc.ClaimOutbox(ctx, "w1", time.Second, 1); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("ClaimOutbox nil store: got %v", err)
	}
	if _, err := svc.MarkOutboxDelivered(ctx, id, "w1"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("MarkOutboxDelivered nil store: got %v", err)
	}
	if _, err := svc.FailOutbox(ctx, id, "w1", time.Second, "err"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("FailOutbox nil store: got %v", err)
	}
}

func TestOperationsSkipLockedFencingBackoffReapAndOutboxPG17(t *testing.T) {
	pg := harness.StartPostgres(t)
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	metrics, err := observability.NewMetrics(observability.MetricsConfig{})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	svc := operations.NewService(store, metrics, observability.NewLogger(observability.LoggerConfig{}), operations.Config{
		DefaultLeaseDuration: 15 * time.Second,
		BaseRetryDelay:       100 * time.Millisecond,
		MaxRetryDelay:        1 * time.Second,
	})
	ctx := context.Background()

	// 1. Concurrent FOR UPDATE SKIP LOCKED claim contention: 12 ops, 6 concurrent workers -> 0 double-claims.
	const totalOps = 12
	for i := 0; i < totalOps; i++ {
		_, err := svc.Enqueue(ctx, operations.EnqueueInput{
			OperationType: domain.OperationTypeWorkspaceIngress,
			ResourceType:  "workspace",
			ResourceID:    domain.MustNewID(),
			MaxAttempts:   3,
		})
		if err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
	}

	var mu sync.Mutex
	claimedIDs := make(map[uuid.UUID]string)
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		workerName := "worker-" + string(rune('a'+w))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				ops, err := svc.Claim(ctx, operations.ClaimInput{
					WorkerID:      workerName,
					Limit:         1,
					LeaseDuration: 30 * time.Second,
				})
				if err != nil {
					t.Errorf("Claim(%s): %v", workerName, err)
					return
				}
				if len(ops) == 0 {
					return
				}
				mu.Lock()
				for _, op := range ops {
					if prev, dup := claimedIDs[op.ID]; dup {
						t.Errorf("double claim on %s by %s and %s", op.ID, prev, workerName)
					}
					claimedIDs[op.ID] = workerName
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claimedIDs) != totalOps {
		t.Fatalf("expected %d unique claimed ops, got %d", totalOps, len(claimedIDs))
	}

	// 2. Worker fencing on Renew / Complete / Fail + successful Complete with JSON result.
	var sampleID uuid.UUID
	var ownerWorker string
	for id, w := range claimedIDs {
		sampleID = id
		ownerWorker = w
		break
	}
	wrongWorker := "rogue-worker"

	if _, err := svc.Renew(ctx, sampleID, wrongWorker, 30*time.Second); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on wrong worker Renew, got %v", err)
	}
	if _, err := svc.Complete(ctx, sampleID, wrongWorker, nil); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on wrong worker Complete, got %v", err)
	}
	if _, err := svc.Fail(ctx, sampleID, wrongWorker, "boom", true); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on wrong worker Fail, got %v", err)
	}
	if _, err := svc.Renew(ctx, sampleID, ownerWorker, 45*time.Second); err != nil {
		t.Fatalf("owner Renew: %v", err)
	}
	completed, err := svc.Complete(ctx, sampleID, ownerWorker, json.RawMessage(`{"artifact_id":"ok"}`))
	if err != nil {
		t.Fatalf("owner Complete: %v", err)
	}
	if completed.Status != domain.OperationStatusSucceeded || completed.CompletedAt == nil {
		t.Fatalf("expected SUCCEEDED with CompletedAt, got %+v", completed)
	}

	// Reset DB for isolated retry/reclaim/outbox checks.
	if err := pg.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	// 3. Expired-lease reclaim + retry backoff + max-attempt ReapExpired.
	baseNow := time.Now().UTC().Truncate(time.Microsecond)
	opRetry, err := svc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalEvaluate,
		ResourceType:  "proposal",
		ResourceID:    domain.MustNewID(),
		MaxAttempts:   2,
		AvailableAt:   baseNow.Add(-1 * time.Second),
	})
	if err != nil {
		t.Fatalf("Enqueue opRetry: %v", err)
	}

	// Claim attempt 1 with valid 5s lease.
	claimed1, err := svc.Claim(ctx, operations.ClaimInput{
		WorkerID:      "worker-1",
		Limit:         1,
		LeaseDuration: 5 * time.Second,
		Now:           baseNow,
	})
	if err != nil || len(claimed1) != 1 || claimed1[0].Attempts != 1 {
		t.Fatalf("expected attempt 1 claim, got (%+v, %v)", claimed1, err)
	}

	// Fail retryable -> goes back to PENDING with backoff (100ms).
	retried, err := svc.Fail(ctx, opRetry.ID, "worker-1", "transient error", true)
	if err != nil || retried.Status != domain.OperationStatusPending {
		t.Fatalf("expected PENDING after retryable Fail, got (%+v, %v)", retried, err)
	}

	// Claim attempt 2 after backoff has elapsed.
	tClaim2 := retried.AvailableAt.Add(10 * time.Millisecond)
	claimed2, err := svc.Claim(ctx, operations.ClaimInput{
		WorkerID:      "worker-2",
		Limit:         1,
		LeaseDuration: 50 * time.Millisecond,
		Now:           tClaim2,
	})
	if err != nil || len(claimed2) != 1 || claimed2[0].Attempts != 2 {
		t.Fatalf("expected attempt 2 claim, got (%+v, %v)", claimed2, err)
	}

	// Lease expires at tClaim2 + 50ms. Because attempts == max_attempts (2), Claim skips it and ReapExpired dead-letters it.
	afterExpiry := tClaim2.Add(200 * time.Millisecond)
	claimed3, err := svc.Claim(ctx, operations.ClaimInput{
		WorkerID:      "worker-3",
		Limit:         1,
		LeaseDuration: 10 * time.Second,
		Now:           afterExpiry,
	})
	if err != nil || len(claimed3) != 0 {
		t.Fatalf("expected 0 claims when attempts >= max_attempts, got (%+v, %v)", claimed3, err)
	}

	reaped, err := svc.ReapExpired(ctx, afterExpiry)
	if err != nil || len(reaped) != 1 || reaped[0].ID != opRetry.ID || reaped[0].Status != domain.OperationStatusFailed {
		t.Fatalf("expected opRetry reaped as FAILED, got (%+v, %v)", reaped, err)
	}

	// 3b. Complete/Fail after lease expiry returns 409 Conflict; expired-lease reclaim does not double-increment ActiveOperations gauge.
	curNow := time.Now().UTC().Truncate(time.Microsecond)
	clockSvc := operations.NewService(store, metrics, observability.NewLogger(observability.LoggerConfig{}), operations.Config{
		DefaultLeaseDuration: 10 * time.Second,
		Clock:                func() time.Time { return curNow },
	})
	opExpire, err := clockSvc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    domain.MustNewID(),
		MaxAttempts:   3,
		AvailableAt:   curNow,
	})
	if err != nil {
		t.Fatalf("Enqueue opExpire: %v", err)
	}
	if _, err := clockSvc.Claim(ctx, operations.ClaimInput{WorkerID: "w-exp-1", Limit: 1, LeaseDuration: 5 * time.Second, Now: curNow}); err != nil {
		t.Fatalf("Claim opExpire: %v", err)
	}
	// Advance clock past lease expiry BEFORE reclaim.
	curNow = curNow.Add(10 * time.Second)
	if _, err := clockSvc.Complete(ctx, opExpire.ID, "w-exp-1", nil); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict for Complete after lease expiry, got %v", err)
	}
	if _, err := clockSvc.Fail(ctx, opExpire.ID, "w-exp-1", "late", true); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict for Fail after lease expiry, got %v", err)
	}
	// Reclaim expired RUNNING op -> active gauge should remain 1 (not 2!), then Complete -> 0.
	reclaimedOps, err := clockSvc.Claim(ctx, operations.ClaimInput{WorkerID: "w-exp-2", Limit: 1, LeaseDuration: 10 * time.Second, Now: curNow})
	if err != nil || len(reclaimedOps) != 1 || reclaimedOps[0].ID != opExpire.ID {
		t.Fatalf("expected reclaim of opExpire, got (%+v, %v)", reclaimedOps, err)
	}
	if _, err := clockSvc.Complete(ctx, opExpire.ID, "w-exp-2", nil); err != nil {
		t.Fatalf("Complete reclaimed opExpire: %v", err)
	}
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "custodian_active_operations" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "operation_type" && lp.GetValue() == string(domain.OperationTypeProposalPublish) {
						if got := m.GetGauge().GetValue(); got != 0 {
							t.Fatalf("expected PROPOSAL_PUBLISH active_operations gauge == 0 after reclaim+complete, got %v", got)
						}
					}
				}
			}
		}
	}

	// 4. Transactional outbox rollback atomicity + claim / fail / deliver.
	rollbackSentinel := errors.New("force rollback")
	err = store.WithTx(ctx, func(tx *persistence.Tx) error {
		_, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "workspace.rolled_back",
			AggregateID: domain.MustNewID(),
			Payload:     json.RawMessage(`{"should_not_persist":true}`),
		})
		if err != nil {
			return err
		}
		return rollbackSentinel
	})
	if !errors.Is(err, rollbackSentinel) {
		t.Fatalf("expected rollbackSentinel, got %v", err)
	}
	var outboxCount int
	if err := pg.Pool().QueryRow(ctx, `SELECT count(*) FROM outbox_events`).Scan(&outboxCount); err != nil {
		t.Fatalf("count outbox_events: %v", err)
	}
	if outboxCount != 0 {
		t.Fatalf("expected 0 outbox_events after rolled-back tx, got %d", outboxCount)
	}

	// Committed outbox event -> ClaimOutbox -> FailOutbox -> ClaimOutbox -> MarkOutboxDelivered.
	aggID := domain.MustNewID()
	var obID uuid.UUID
	if err := store.WithTx(ctx, func(tx *persistence.Tx) error {
		row, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "workspace.created",
			AggregateID: aggID,
			Payload:     json.RawMessage(`{"ok":true}`),
		})
		obID = row.ID
		return err
	}); err != nil {
		t.Fatalf("commit outbox tx: %v", err)
	}

	// Unleased outbox event cannot be marked delivered or failed (empty workerID -> 400; valid workerID without lease -> 409).
	if _, err := svc.MarkOutboxDelivered(ctx, obID, ""); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected 400 BadRequest for empty workerID on MarkOutboxDelivered, got %v", err)
	}
	if _, err := svc.FailOutbox(ctx, obID, "   ", 0, "err"); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected 400 BadRequest for empty workerID on FailOutbox, got %v", err)
	}
	if _, err := svc.MarkOutboxDelivered(ctx, obID, "unleased-worker"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict for unleased MarkOutboxDelivered, got %v", err)
	}
	if _, err := svc.FailOutbox(ctx, obID, "unleased-worker", 0, "err"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict for unleased FailOutbox, got %v", err)
	}

	obClaimed, err := svc.ClaimOutbox(ctx, "outbox-w1", 10*time.Second, 5)
	if err != nil || len(obClaimed) != 1 || obClaimed[0].ID != obID {
		t.Fatalf("ClaimOutbox: (%+v, %v)", obClaimed, err)
	}
	// Wrong worker gets 409 Conflict (LEASE_LOST), while missing ID gets 404 NotFound.
	if _, err := svc.MarkOutboxDelivered(ctx, obID, "wrong-worker"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict for wrong-worker MarkOutboxDelivered, got %v", err)
	}
	if _, err := svc.FailOutbox(ctx, obID, "wrong-worker", 0, "err"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict for wrong-worker FailOutbox, got %v", err)
	}
	if _, err := svc.MarkOutboxDelivered(ctx, domain.MustNewID(), "wrong-worker"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected 404 NotFound for missing outbox ID, got %v", err)
	}

	obFailed, err := svc.FailOutbox(ctx, obID, "outbox-w1", 0, "temporary network error")
	if err != nil || obFailed.Attempts != 1 {
		t.Fatalf("FailOutbox: (%+v, %v)", obFailed, err)
	}
	obClaimed2, err := svc.ClaimOutbox(ctx, "outbox-w2", 10*time.Second, 5)
	if err != nil || len(obClaimed2) != 1 || obClaimed2[0].ID != obID {
		t.Fatalf("second ClaimOutbox: (%+v, %v)", obClaimed2, err)
	}
	obDelivered, err := svc.MarkOutboxDelivered(ctx, obID, "outbox-w2")
	if err != nil || obDelivered.DeliveredAt == nil {
		t.Fatalf("MarkOutboxDelivered: (%+v, %v)", obDelivered, err)
	}
	// Already delivered outbox event returns 409 Conflict.
	if _, err := svc.MarkOutboxDelivered(ctx, obID, "outbox-w2"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 Conflict on already-delivered outbox event, got %v", err)
	}
}
