package workflow

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// BudgetLimiter enforces bounded in-process concurrency caps for global Stage A scans,
// global Stage B model assessments, and per-repository operations without ever blocking a
// single active operation when limit >= 1 (and treating limit <= 0 as unlimited).
type BudgetLimiter struct {
	scanSem   chan struct{}
	modelSem  chan struct{}
	repoLimit int

	mu       sync.Mutex
	repoSems map[uuid.UUID]chan struct{}
}

// NewBudgetLimiter constructs a BudgetLimiter from configured caps.
func NewBudgetLimiter(globalScanBudget, globalModelBudget, repoConcurrencyLimit int) *BudgetLimiter {
	var scanSem, modelSem chan struct{}
	if globalScanBudget > 0 {
		scanSem = make(chan struct{}, globalScanBudget)
	}
	if globalModelBudget > 0 {
		modelSem = make(chan struct{}, globalModelBudget)
	}
	return &BudgetLimiter{
		scanSem:   scanSem,
		modelSem:  modelSem,
		repoLimit: repoConcurrencyLimit,
		repoSems:  make(map[uuid.UUID]chan struct{}),
	}
}

// AcquireRepo acquires a per-repository concurrency slot until release() is called.
func (b *BudgetLimiter) AcquireRepo(ctx context.Context, repoID uuid.UUID) (func(), error) {
	if b == nil || b.repoLimit <= 0 || repoID == uuid.Nil {
		return func() {}, nil
	}
	b.mu.Lock()
	sem, ok := b.repoSems[repoID]
	if !ok {
		sem = make(chan struct{}, b.repoLimit)
		b.repoSems[repoID] = sem
	}
	b.mu.Unlock()
	return acquireSem(ctx, sem)
}

// AcquireScan acquires a global Stage A scan slot until release() is called.
func (b *BudgetLimiter) AcquireScan(ctx context.Context) (func(), error) {
	if b == nil || b.scanSem == nil {
		return func() {}, nil
	}
	return acquireSem(ctx, b.scanSem)
}

// AcquireModel acquires a global Stage B model assessment slot until release() is called.
func (b *BudgetLimiter) AcquireModel(ctx context.Context) (func(), error) {
	if b == nil || b.modelSem == nil {
		return func() {}, nil
	}
	return acquireSem(ctx, b.modelSem)
}

func acquireSem(ctx context.Context, sem chan struct{}) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case sem <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-sem })
		}, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}
