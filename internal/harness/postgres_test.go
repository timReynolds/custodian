package harness_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestPostgresHarnessLifecycleAndReset(t *testing.T) {
	pg := harness.StartPostgres(t)

	if pg.HostPort() == "" || pg.HostPort() == "5432" {
		t.Fatalf("expected ephemeral host port != 5432, got %q", pg.HostPort())
	}
	if pg.DSN() == "" || pg.MigrateURL() == "" {
		t.Fatalf("expected non-empty DSN and MigrateURL")
	}

	ctx := context.Background()
	var version string
	if err := pg.Pool().QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		t.Fatalf("SELECT version(): %v", err)
	}
	if version == "" {
		t.Fatalf("expected non-empty PostgreSQL version")
	}

	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	id := domain.MustNewID()
	_, err = store.Upsert(ctx, domain.Principal{
		ID:            id,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://issuer.example",
		Subject:       "sub-harness-1",
		DisplayName:   "Alice",
		VerifiedEmail: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Upsert principal: %v", err)
	}

	if err := pg.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	_, err = store.GetByID(ctx, id)
	if err == nil {
		t.Fatalf("expected principal to be deleted after Reset")
	}
	var headCount int64
	if err := pg.Pool().QueryRow(ctx, "SELECT event_count FROM audit_chain_head WHERE chain_id = 'default'").Scan(&headCount); err != nil {
		t.Fatalf("query audit_chain_head after Reset: %v", err)
	}
	if headCount != 0 {
		t.Fatalf("expected audit_chain_head.event_count == 0, got %d", headCount)
	}

	// Ensure idempotent Close works when called manually prior to t.Cleanup.
	_ = uuid.Nil
	if err := pg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := pg.Close(); err != nil {
		t.Fatalf("second Close should be idempotent: %v", err)
	}
}

func TestPostgresHarnessCredentialEscapingPG17(t *testing.T) {
	pg := harness.StartPostgres(t,
		harness.WithPGUser("custodian_user"),
		harness.WithPGPassword("p@ss/w:ord%1#?"),
		harness.WithPGDatabase("custodian_db"),
	)

	var one int
	if err := pg.Pool().QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("SELECT 1 with escaped credentials failed: (%d, %v)", one, err)
	}
	if pg.DSN() == "" || pg.MigrateURL() == "" {
		t.Fatalf("expected non-empty DSN and MigrateURL")
	}
}
