package persistence

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/golang-migrate/migrate/v4"
	pgxv5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence/migrations"
)

// MigrateUp applies all pending embedded up-migrations against the given PostgreSQL DSN.
func MigrateUp(ctx context.Context, dsn string) error {
	return runMigrateDSN(ctx, dsn, true)
}

// MigrateDown rolls back all applied embedded migrations against the given PostgreSQL DSN.
func MigrateDown(ctx context.Context, dsn string) error {
	return runMigrateDSN(ctx, dsn, false)
}

// MigrateUpPool applies all pending embedded up-migrations using an existing pgxpool.Pool.
func MigrateUpPool(ctx context.Context, pool *pgxpool.Pool) error {
	return runMigratePool(ctx, pool, true)
}

// MigrateDownPool rolls back all applied embedded migrations using an existing pgxpool.Pool.
func MigrateDownPool(ctx context.Context, pool *pgxpool.Pool) error {
	return runMigratePool(ctx, pool, false)
}

func runMigrateDSN(ctx context.Context, dsn string, up bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pgx5URL, err := toPGX5URL(dsn)
	if err != nil {
		return domain.WrapError(domain.ErrBadRequest, "INVALID_DSN", "invalid PostgreSQL DSN", err)
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, pgx5URL)
	if err != nil {
		_ = src.Close()
		return MapError(fmt.Errorf("initialize migrator: %w", err))
	}
	defer func() {
		_, _ = m.Close()
	}()

	return executeMigrate(m, up)
}

func runMigratePool(ctx context.Context, pool *pgxpool.Pool, up bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pool == nil {
		return domain.BadRequest("INVALID_POOL", "pgxpool.Pool must not be nil")
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}

	sqlDB := stdlib.OpenDBFromPool(pool)
	drv, err := pgxv5.WithInstance(sqlDB, &pgxv5.Config{})
	if err != nil {
		_ = src.Close()
		_ = sqlDB.Close()
		return MapError(fmt.Errorf("initialize pgx5 migrate driver: %w", err))
	}

	m, err := migrate.NewWithInstance("iofs", src, "pgx5", drv)
	if err != nil {
		_ = src.Close()
		_ = drv.Close()
		return MapError(fmt.Errorf("initialize migrator from pool: %w", err))
	}
	defer func() {
		_, _ = m.Close()
	}()

	return executeMigrate(m, up)
}

func executeMigrate(m *migrate.Migrate, up bool) error {
	var err error
	if up {
		err = m.Up()
	} else {
		err = m.Down()
	}
	if err == nil || errors.Is(err, migrate.ErrNoChange) {
		return nil
	}
	return fmt.Errorf("run migration (up=%t): %w", up, err)
}

func toPGX5URL(dsn string) (string, error) {
	if dsn == "" {
		return "", errors.New("dsn must not be empty")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "postgres", "postgresql", "pgx", "pgx5":
		u.Scheme = "pgx5"
	case "":
		return "", errors.New("dsn scheme must be postgres, postgresql, or pgx5")
	default:
		return "", fmt.Errorf("unsupported dsn scheme %q", u.Scheme)
	}
	return u.String(), nil
}
