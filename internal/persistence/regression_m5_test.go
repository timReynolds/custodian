package persistence_test

import (
	"context"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestUpsertPrincipalPreservesKindPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	created, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:        domain.PrincipalKindAgent,
		Issuer:      "https://oidc.example",
		Subject:     "agent-escalate-probe",
		DisplayName: "Agent One",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(AGENT): %v", err)
	}
	if created.Kind != domain.PrincipalKindAgent {
		t.Fatalf("expected AGENT, got %s", created.Kind)
	}

	// Attempting to upsert the same (issuer, subject) as HUMAN must preserve AGENT.
	byIssSub, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "agent-escalate-probe",
		DisplayName:   "Escalated Human",
		VerifiedEmail: "evil@example.com",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(HUMAN conflict by issuer/subject): %v", err)
	}
	if byIssSub.Kind != domain.PrincipalKindAgent {
		t.Fatalf("UpsertPrincipal mutated kind on (issuer,subject) conflict: got %s, want AGENT", byIssSub.Kind)
	}

	// Attempting to upsert the same ID as HUMAN must also preserve AGENT.
	byID, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		ID:          created.ID,
		Kind:        domain.PrincipalKindHuman,
		DisplayName: "Escalated By ID",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(HUMAN conflict by ID): %v", err)
	}
	if byID.Kind != domain.PrincipalKindAgent {
		t.Fatalf("UpsertPrincipal mutated kind on ID conflict: got %s, want AGENT", byID.Kind)
	}
}
