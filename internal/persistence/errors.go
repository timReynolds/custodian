package persistence

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/timreynolds/custodian/internal/domain"
)

// MapError translates PostgreSQL and pgx errors into typed *domain.DomainError values.
// Internal database details remain in DomainError.Cause (json:"-").
func MapError(err error) error {
	if err == nil {
		return nil
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.WrapError(domain.ErrNotFound, "NOT_FOUND", "resource not found", err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return domain.WrapError(domain.ErrConflict, "CONFLICT", "resource already exists or conflicts", err)
		case "23503": // foreign_key_violation
			return domain.WrapError(domain.ErrBadRequest, "INVALID_REFERENCE", "referenced resource does not exist", err)
		case "23514", "23502", "22P02": // check_violation, not_null_violation, invalid_text_representation
			return domain.WrapError(domain.ErrBadRequest, "CONSTRAINT_VIOLATION", "invalid input value", err)
		case "40001", "40P01": // serialization_failure, deadlock_detected
			return domain.WrapError(domain.ErrConflict, "TX_CONFLICT", "transaction conflict, please retry", err)
		case "57P01", "57P02", "57P03": // admin_shutdown, crash_shutdown, cannot_connect_now
			return domain.WrapError(domain.ErrUnavailable, "DATABASE_UNAVAILABLE", "database is unavailable", err)
		}
		if strings.HasPrefix(pgErr.Code, "08") {
			return domain.WrapError(domain.ErrUnavailable, "DATABASE_UNAVAILABLE", "database connection error", err)
		}
		return domain.WrapError(domain.ErrInternal, "PERSISTENCE_ERROR", "database operation failed", err)
	}

	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) {
		return domain.WrapError(domain.ErrUnavailable, "DATABASE_UNAVAILABLE", "database connection failed", err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return domain.WrapError(domain.ErrUnavailable, "DATABASE_UNAVAILABLE", "database network error", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.WrapError(domain.ErrUnavailable, "DATABASE_TIMEOUT", "database operation timed out", err)
	}
	if strings.Contains(err.Error(), "closed pool") {
		return domain.WrapError(domain.ErrUnavailable, "DATABASE_UNAVAILABLE", "database pool is closed", err)
	}

	return domain.WrapError(domain.ErrInternal, "PERSISTENCE_ERROR", "database operation failed", err)
}
