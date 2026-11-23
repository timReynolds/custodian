package persistence

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence/migrations"
)

func TestMapError(t *testing.T) {
	t.Parallel()

	if err := MapError(nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	existing := domain.Forbidden("CUSTOM", "denied")
	if got := MapError(existing); got != existing {
		t.Fatalf("expected existing DomainError returned as-is, got %v", got)
	}

	cases := []struct {
		name     string
		err      error
		sentinel error
		status   int
	}{
		{
			name:     "no rows",
			err:      pgx.ErrNoRows,
			sentinel: domain.ErrNotFound,
			status:   404,
		},
		{
			name:     "unique violation 23505",
			err:      &pgconn.PgError{Code: "23505"},
			sentinel: domain.ErrConflict,
			status:   409,
		},
		{
			name:     "foreign key violation 23503",
			err:      &pgconn.PgError{Code: "23503"},
			sentinel: domain.ErrBadRequest,
			status:   400,
		},
		{
			name:     "check violation 23514",
			err:      &pgconn.PgError{Code: "23514"},
			sentinel: domain.ErrBadRequest,
			status:   400,
		},
		{
			name:     "serialization failure 40001",
			err:      &pgconn.PgError{Code: "40001"},
			sentinel: domain.ErrConflict,
			status:   409,
		},
		{
			name:     "deadlock 40P01",
			err:      &pgconn.PgError{Code: "40P01"},
			sentinel: domain.ErrConflict,
			status:   409,
		},
		{
			name:     "connection exception 08006",
			err:      &pgconn.PgError{Code: "08006"},
			sentinel: domain.ErrUnavailable,
			status:   503,
		},
		{
			name:     "net OpError",
			err:      &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
			sentinel: domain.ErrUnavailable,
			status:   503,
		},
		{
			name:     "deadline exceeded",
			err:      context.DeadlineExceeded,
			sentinel: domain.ErrUnavailable,
			status:   503,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapped := MapError(tc.err)
			if !errors.Is(mapped, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", mapped, tc.sentinel)
			}
			if got := domain.HTTPStatusFromError(mapped); got != tc.status {
				t.Fatalf("HTTPStatusFromError = %d, want %d", got, tc.status)
			}
		})
	}
}

func TestToPGX5URL(t *testing.T) {
	t.Parallel()

	got, err := toPGX5URL("postgres://custodian:pw@127.0.0.1:54321/custodian?sslmode=disable")
	if err != nil {
		t.Fatalf("toPGX5URL: %v", err)
	}
	if !strings.HasPrefix(got, "pgx5://") {
		t.Fatalf("expected pgx5:// prefix, got %q", got)
	}

	if _, err := toPGX5URL(""); err == nil {
		t.Fatalf("expected error for empty DSN")
	}
	if _, err := toPGX5URL("mysql://user@host/db"); err == nil {
		t.Fatalf("expected error for unsupported DSN scheme")
	}
}

func TestEmbeddedMigrationsContainRequiredTablesAndIndexes(t *testing.T) {
	t.Parallel()

	upBytes, err := fs.ReadFile(migrations.FS, "000001_initial_schema.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downBytes, err := fs.ReadFile(migrations.FS, "000001_initial_schema.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	upSQL := string(upBytes)
	downSQL := string(downBytes)

	requiredTables := []string{
		"principals", "repositories", "workspaces", "artifacts", "proposals",
		"scan_runs", "findings", "model_assessments", "policy_bundles", "policy_decisions",
		"approvals", "publications", "operations", "audit_events", "outbox_events",
		"idempotency_keys", "approval_requirements", "publication_attempts", "audit_chain_head",
	}
	for _, tbl := range requiredTables {
		if !strings.Contains(upSQL, "CREATE TABLE "+tbl) {
			t.Fatalf("up migration missing CREATE TABLE %s", tbl)
		}
		if !strings.Contains(downSQL, "DROP TABLE IF EXISTS "+tbl) {
			t.Fatalf("down migration missing DROP TABLE IF EXISTS %s", tbl)
		}
	}

	requiredIndexes := []string{
		"idx_proposals_workspace",
		"idx_findings_scan",
		"idx_operations_ready",
		"idx_audit_resource",
	}
	for _, idx := range requiredIndexes {
		if !strings.Contains(upSQL, idx) {
			t.Fatalf("up migration missing Spec §10 index %s", idx)
		}
	}
}
