package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestM5_FinalizeIdempotencyKeySurvivesCancelledRequestContext(t *testing.T) {
	pg := harness.StartPostgres(t, harness.WithPGAllowDockerSkip(true))
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)

	ctx := context.Background()
	p, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.test",
		Subject:       "idem-disconnect-user",
		DisplayName:   "Disconnect User",
		VerifiedEmail: "disc@acme.test",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal: %v", err)
	}

	s := newServer(Deps{
		Store:     store,
		DBTimeout: 2 * time.Second,
	})
	caller := identity.CallerContext{
		Principal: p.ToDomain(),
		Claims:    auth.VerifiedClaims{Subject: "idem-disconnect-user", Kind: domain.PrincipalKindHuman},
	}

	reqCtx, cancelReq := context.WithCancel(context.Background())
	req1 := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(`{"x":1}`)).WithContext(reqCtx)
	rec1 := httptest.NewRecorder()

	calls := 0
	s.runIdempotent(rec1, req1, caller, "disconnect-idem-key-1", []byte(`{"x":1}`), func() (int, any, error) {
		calls++
		// Simulate client disconnect right after handler commits its DB transaction.
		cancelReq()
		return http.StatusAccepted, map[string]any{"workspace_id": "ws-ok"}, nil
	})
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("initial call expected 202, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Immediate replay must return cached 202 (NOT 409 IDEMPOTENCY_IN_PROGRESS or re-execute fn).
	req2 := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(`{"x":1}`))
	rec2 := httptest.NewRecorder()
	s.runIdempotent(rec2, req2, caller, "disconnect-idem-key-1", []byte(`{"x":1}`), func() (int, any, error) {
		calls++
		return http.StatusAccepted, map[string]any{"workspace_id": "ws-dup"}, nil
	})
	if rec2.Code != http.StatusAccepted || !strings.Contains(rec2.Body.String(), `"ws-ok"`) {
		t.Fatalf("replay expected cached 202 with ws-ok, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected fn executed exactly once, got %d", calls)
	}
}
