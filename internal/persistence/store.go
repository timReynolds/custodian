package persistence

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/timreynolds/custodian/internal/domain"
)

// Compile-time checks that *Store and *Tx satisfy domain.PrincipalStore.
var (
	_ domain.PrincipalStore = (*Store)(nil)
	_ domain.PrincipalStore = (*Tx)(nil)
)

// PoolConfig configures PostgreSQL connection pooling.
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}

// DefaultPoolConfig returns conservative defaults for Custodian persistence pools.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:          16,
		MinConns:          1,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
		ConnectTimeout:    10 * time.Second,
	}
}

// NewPool creates and verifies a *pgxpool.Pool from a PostgreSQL DSN.
func NewPool(ctx context.Context, dsn string, cfg PoolConfig) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, domain.BadRequest("INVALID_DSN", "PostgreSQL DSN must not be empty")
	}
	pgxCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_DSN", "failed to parse PostgreSQL DSN", err)
	}
	if cfg.MaxConns > 0 {
		pgxCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pgxCfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		pgxCfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		pgxCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod > 0 {
		pgxCfg.HealthCheckPeriod = cfg.HealthCheckPeriod
	}
	if cfg.ConnectTimeout > 0 {
		pgxCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxCfg)
	if err != nil {
		return nil, MapError(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, MapError(err)
	}
	return pool, nil
}

// Store is the Layer 1 PostgreSQL persistence store backed by *pgxpool.Pool.
type Store struct {
	pool *pgxpool.Pool
	*Queries
}

// Tx represents an active database transaction bound to *Queries.
type Tx struct {
	tx pgx.Tx
	*Queries
}

// NewStore wraps an existing *pgxpool.Pool in a Store.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, domain.BadRequest("INVALID_POOL", "pgxpool.Pool must not be nil")
	}
	return &Store{
		pool:    pool,
		Queries: New(pool),
	}, nil
}

// Pool returns the underlying *pgxpool.Pool.
func (s *Store) Pool() *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.pool
}

// Ping verifies database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return domain.Unavailable("DATABASE_UNAVAILABLE", "database store is not initialized")
	}
	if err := s.pool.Ping(ctx); err != nil {
		return MapError(err)
	}
	return nil
}

// Close closes the underlying connection pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// Tx returns the underlying pgx.Tx.
func (t *Tx) Tx() pgx.Tx {
	return t.tx
}

// WithTx executes fn within a database transaction, rolling back on any error or panic.
func (s *Store) WithTx(ctx context.Context, fn func(*Tx) error) error {
	return s.WithTxOptions(ctx, pgx.TxOptions{}, fn)
}

// WithTxOptions executes fn within a database transaction with explicit pgx.TxOptions.
func (s *Store) WithTxOptions(ctx context.Context, opts pgx.TxOptions, fn func(*Tx) error) error {
	if s == nil || s.pool == nil {
		return domain.Unavailable("DATABASE_UNAVAILABLE", "database store is not initialized")
	}
	if fn == nil {
		return domain.BadRequest("INVALID_TX_FN", "transaction callback must not be nil")
	}

	pgxTx, err := s.pool.BeginTx(ctx, opts)
	if err != nil {
		return MapError(err)
	}

	rolledBack := false
	defer func() {
		if r := recover(); r != nil {
			if !rolledBack {
				_ = pgxTx.Rollback(context.Background())
			}
			panic(r)
		}
	}()

	tx := &Tx{
		tx:      pgxTx,
		Queries: s.Queries.WithTx(pgxTx),
	}

	if err := fn(tx); err != nil {
		rolledBack = true
		if rbErr := pgxTx.Rollback(context.Background()); rbErr != nil {
			return fmt.Errorf("%w (rollback error: %v)", err, rbErr)
		}
		return err
	}

	if err := pgxTx.Commit(ctx); err != nil {
		rolledBack = true
		return MapError(err)
	}
	return nil
}

// ReserveIdempotencyKey atomically reserves or replays an idempotency key inside a transaction.
func (s *Store) ReserveIdempotencyKey(ctx context.Context, input IdempotencyReserveInput) (IdempotencyReservation, error) {
	var res IdempotencyReservation
	err := s.WithTx(ctx, func(tx *Tx) error {
		var err error
		res, err = tx.ReserveIdempotencyKeyInTx(ctx, input)
		return err
	})
	return res, err
}

// GetByID implements domain.PrincipalStore.
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (domain.Principal, error) {
	row, err := s.GetPrincipalByID(ctx, id)
	if err != nil {
		return domain.Principal{}, err
	}
	return row.ToDomain(), nil
}

// GetByIssuerSubject implements domain.PrincipalStore.
func (s *Store) GetByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Principal, error) {
	row, err := s.GetPrincipalByIssuerSubject(ctx, issuer, subject)
	if err != nil {
		return domain.Principal{}, err
	}
	return row.ToDomain(), nil
}

// Upsert implements domain.PrincipalStore.
func (s *Store) Upsert(ctx context.Context, principal domain.Principal) (domain.Principal, error) {
	row, err := s.UpsertPrincipal(ctx, UpsertPrincipalParams{
		ID:            principal.ID,
		Kind:          principal.Kind,
		Issuer:        principal.Issuer,
		Subject:       principal.Subject,
		DisplayName:   principal.DisplayName,
		VerifiedEmail: principal.VerifiedEmail,
		CreatedAt:     principal.CreatedAt,
	})
	if err != nil {
		return domain.Principal{}, err
	}
	return row.ToDomain(), nil
}

// GetByID implements domain.PrincipalStore on *Tx.
func (t *Tx) GetByID(ctx context.Context, id uuid.UUID) (domain.Principal, error) {
	row, err := t.GetPrincipalByID(ctx, id)
	if err != nil {
		return domain.Principal{}, err
	}
	return row.ToDomain(), nil
}

// GetByIssuerSubject implements domain.PrincipalStore on *Tx.
func (t *Tx) GetByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Principal, error) {
	row, err := t.GetPrincipalByIssuerSubject(ctx, issuer, subject)
	if err != nil {
		return domain.Principal{}, err
	}
	return row.ToDomain(), nil
}

// Upsert implements domain.PrincipalStore on *Tx.
func (t *Tx) Upsert(ctx context.Context, principal domain.Principal) (domain.Principal, error) {
	row, err := t.UpsertPrincipal(ctx, UpsertPrincipalParams{
		ID:            principal.ID,
		Kind:          principal.Kind,
		Issuer:        principal.Issuer,
		Subject:       principal.Subject,
		DisplayName:   principal.DisplayName,
		VerifiedEmail: principal.VerifiedEmail,
		CreatedAt:     principal.CreatedAt,
	})
	if err != nil {
		return domain.Principal{}, err
	}
	return row.ToDomain(), nil
}
