package api

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func advisoryLockKey(namespace, id string) int64 {
	sum := sha256.Sum256([]byte(namespace + ":" + id))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func (s *server) repoLockSem(repoID uuid.UUID) chan struct{} {
	s.repoLocksMu.Lock()
	defer s.repoLocksMu.Unlock()
	if s.repoLocks == nil {
		s.repoLocks = make(map[uuid.UUID]chan struct{})
	}
	sem, ok := s.repoLocks[repoID]
	if !ok {
		sem = make(chan struct{}, 1)
		s.repoLocks[repoID] = sem
	}
	return sem
}

func (s *server) withRepoLock(ctx context.Context, repoID uuid.UUID, fn func() error) error {
	return s.withAdvisoryLock(ctx, s.repoLockSem(repoID), advisoryLockKey("custodian:repo_concurrency", repoID.String()), fn)
}

func (s *server) withEvalBudgetLock(ctx context.Context, fn func() error) error {
	if s.evalBudgetLock == nil {
		s.repoLocksMu.Lock()
		if s.evalBudgetLock == nil {
			s.evalBudgetLock = make(chan struct{}, 1)
		}
		s.repoLocksMu.Unlock()
	}
	return s.withAdvisoryLock(ctx, s.evalBudgetLock, advisoryLockKey("custodian:global_eval_budget", "global"), fn)
}

type advisoryLockConn interface {
	Exec(ctx context.Context, sql string, args ...any) error
	Release()
	Close(ctx context.Context) error
}

type advisoryLockPool interface {
	Acquire(ctx context.Context) (advisoryLockConn, error)
}

type pgxAdvisoryLockPool struct {
	pool *pgxpool.Pool
}

func (p pgxAdvisoryLockPool) Acquire(ctx context.Context) (advisoryLockConn, error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return pgxAdvisoryLockConn{conn: conn}, nil
}

type pgxAdvisoryLockConn struct {
	conn *pgxpool.Conn
}

func (c pgxAdvisoryLockConn) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := c.conn.Exec(ctx, sql, args...)
	return err
}

func (c pgxAdvisoryLockConn) Release() {
	c.conn.Release()
}

func (c pgxAdvisoryLockConn) Close(ctx context.Context) error {
	return c.conn.Conn().Close(ctx)
}

func (s *server) advisoryPool() advisoryLockPool {
	if s.lockPool != nil {
		return s.lockPool
	}
	if s.deps.Store != nil {
		if pool := s.deps.Store.Pool(); pool != nil {
			return pgxAdvisoryLockPool{pool: pool}
		}
	}
	return nil
}

func (s *server) withAdvisoryLock(ctx context.Context, localSem chan struct{}, lockKey int64, fn func() error) error {
	lockCtx, cancel := s.withDBTimeout(ctx)
	if err := lockCtx.Err(); err != nil {
		mapped := mapDBTimeoutError(lockCtx, persistence.MapError(err))
		cancel()
		return mapped
	}

	select {
	case localSem <- struct{}{}:
	case <-lockCtx.Done():
		mapped := mapDBTimeoutError(lockCtx, persistence.MapError(lockCtx.Err()))
		cancel()
		return mapped
	}
	defer func() { <-localSem }()

	pool := s.advisoryPool()
	if pool == nil {
		cancel()
		return fn()
	}

	conn, err := pool.Acquire(lockCtx)
	if err != nil {
		mapped := mapDBTimeoutError(lockCtx, persistence.MapError(err))
		cancel()
		return mapped
	}
	defer conn.Release()

	if err := conn.Exec(lockCtx, `SELECT pg_advisory_lock($1::bigint)`, lockKey); err != nil {
		mapped := mapDBTimeoutError(lockCtx, persistence.MapError(err))
		cancel()
		return mapped
	}
	cancel()

	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer unlockCancel()
		if uErr := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1::bigint)`, lockKey); uErr != nil {
			_ = conn.Close(unlockCtx)
		}
	}()

	return fn()
}

func (s *server) withRepoConcurrencyLimit(ctx context.Context, repoID uuid.UUID, repoMaxConcurrent int, fn func(dbCtx context.Context) error) error {
	limit := effectiveRepoConcurrencyLimit(s.deps.RepoConcurrencyLimit, repoMaxConcurrent)
	if limit > 0 && s.deps.Store != nil && repoID != uuid.Nil {
		return s.withRepoLock(ctx, repoID, func() error {
			dbCtx, dbCancel := s.withDBTimeout(ctx)
			defer dbCancel()
			active, err := s.deps.Store.CountActiveOperationsByRepository(dbCtx, repoID)
			if err != nil {
				return mapDBTimeoutError(dbCtx, err)
			}
			if active >= int64(limit) {
				return domain.RateLimited("REPO_CONCURRENCY_LIMIT_EXCEEDED", "repository active operations limit exceeded")
			}
			return fn(dbCtx)
		})
	}
	dbCtx, dbCancel := s.withDBTimeout(ctx)
	defer dbCancel()
	return fn(dbCtx)
}

func (s *server) checkGlobalScanBudget(dbCtx context.Context) error {
	if s.deps.GlobalScanBudget <= 0 || s.deps.Store == nil {
		return nil
	}
	activeIngress, err := s.deps.Store.CountActiveOperationsByType(dbCtx, domain.OperationTypeWorkspaceIngress)
	if err != nil {
		return mapDBTimeoutError(dbCtx, err)
	}
	activeEvalOps, err := s.deps.Store.CountActiveOperationsByType(dbCtx, domain.OperationTypeProposalEvaluate)
	if err != nil {
		return mapDBTimeoutError(dbCtx, err)
	}
	activeScans, err := s.deps.Store.CountActiveScanRuns(dbCtx)
	if err != nil {
		return mapDBTimeoutError(dbCtx, err)
	}
	egressScans := activeEvalOps
	if activeScans > egressScans {
		egressScans = activeScans
	}
	if activeIngress+egressScans >= int64(s.deps.GlobalScanBudget) {
		return domain.RateLimited("GLOBAL_SCAN_BUDGET_EXCEEDED", "global scanning concurrency budget exceeded")
	}
	return nil
}

func (s *server) checkGlobalModelBudget(dbCtx context.Context) error {
	if s.deps.GlobalModelBudget <= 0 || s.deps.Store == nil {
		return nil
	}
	activeEvalOps, err := s.deps.Store.CountActiveOperationsByType(dbCtx, domain.OperationTypeProposalEvaluate)
	if err != nil {
		return mapDBTimeoutError(dbCtx, err)
	}
	activeModels, err := s.deps.Store.CountActiveModelAssessments(dbCtx)
	if err != nil {
		return mapDBTimeoutError(dbCtx, err)
	}
	active := activeEvalOps
	if activeModels > active {
		active = activeModels
	}
	if active >= int64(s.deps.GlobalModelBudget) {
		return domain.RateLimited("GLOBAL_MODEL_BUDGET_EXCEEDED", "global decision model concurrency budget exceeded")
	}
	return nil
}
