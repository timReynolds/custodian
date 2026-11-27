package identity

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

func TestDirectoryResolveOwnerAndCallerInvariants(t *testing.T) {
	t.Parallel()
	store := NewMemoryPrincipalStore()
	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "identity-test",
	})

	dir, err := NewDirectory(store, DirectoryConfig{
		AutoProvisionHumans:    true,
		AutoProvisionWorkloads: true,
		RequireVerifiedEmail:   true,
		Logger:                 logger,
	})
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	ctx := context.Background()
	humanClaims := auth.VerifiedClaims{
		Issuer:        "https://oidc.example",
		Subject:       "human-alice",
		Kind:          domain.PrincipalKindHuman,
		TokenKind:     auth.TokenKindAuditor,
		Email:         "alice@example.com",
		EmailVerified: true,
		DisplayName:   "Alice Example",
		Roles:         []string{"auditor"},
		Groups:        []string{"security"},
	}

	owner, err := dir.ResolveOwner(ctx, humanClaims)
	if err != nil {
		t.Fatalf("ResolveOwner(human): %v", err)
	}
	if owner.Kind != domain.PrincipalKindHuman || owner.VerifiedEmail != "alice@example.com" {
		t.Fatalf("unexpected owner: %+v", owner)
	}
	name, email, err := owner.GitAuthor()
	if err != nil || name != "Alice Example" || email != "alice@example.com" {
		t.Fatalf("GitAuthor failed: name=%q email=%q err=%v", name, email, err)
	}

	// Second call resolves same Principal ID deterministically.
	owner2, err := dir.ResolveOwner(ctx, humanClaims)
	if err != nil {
		t.Fatalf("ResolveOwner second call: %v", err)
	}
	if owner2.ID != owner.ID {
		t.Fatalf("expected stable principal ID, got %s vs %s", owner2.ID, owner.ID)
	}

	// CallerContext role/group predicates.
	caller, err := dir.ResolveCaller(ctx, humanClaims)
	if err != nil {
		t.Fatalf("ResolveCaller(human): %v", err)
	}
	if !caller.IsHuman() || !caller.IsAuditor() || caller.IsPolicyAdmin() || caller.IsController() || !caller.InGroup("SECURITY") {
		t.Fatalf("unexpected CallerContext predicates: %+v", caller)
	}

	// Agent, Service, Controller cannot be resolved as human owner (403).
	for _, tc := range []struct {
		name   string
		claims auth.VerifiedClaims
	}{
		{
			name: "agent",
			claims: auth.VerifiedClaims{
				Issuer: "https://oidc.example", Subject: "agent-1",
				Kind: domain.PrincipalKindAgent, TokenKind: auth.TokenKindAgent,
			},
		},
		{
			name: "service",
			claims: auth.VerifiedClaims{
				Issuer: "https://oidc.example", Subject: "svc-1",
				Kind: domain.PrincipalKindService, TokenKind: auth.TokenKindService,
			},
		},
		{
			name: "controller",
			claims: auth.VerifiedClaims{
				Issuer: "https://oidc.example", Subject: "spiffe://custodian/ctrl/1",
				Kind: domain.PrincipalKindService, TokenKind: auth.TokenKindController,
				Roles: []string{"controller"},
			},
		},
		{
			name: "unverified_human",
			claims: auth.VerifiedClaims{
				Issuer: "https://oidc.example", Subject: "human-unverified",
				Kind: domain.PrincipalKindHuman, TokenKind: auth.TokenKindHuman,
				Email: "", EmailVerified: false,
			},
		},
	} {
		t.Run("reject_owner_"+tc.name, func(t *testing.T) {
			if _, err := dir.ResolveOwner(ctx, tc.claims); !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("expected ErrForbidden for %s, got %v", tc.name, err)
			}
		})
	}

	// Kind escalation on existing (issuer, subject) must be rejected (403).
	if _, err := dir.ResolveCaller(ctx, auth.VerifiedClaims{
		Issuer: "https://oidc.example", Subject: "agent-1",
		Kind: domain.PrincipalKindHuman, TokenKind: auth.TokenKindHuman,
		Email: "escalated@example.com", EmailVerified: true,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for kind escalation, got %v", err)
	}

	// Separate agent principal provenance cannot pass GitAuthor().
	agentPrincipal, err := dir.ResolveAgentPrincipal(ctx, "Pi")
	if err != nil {
		t.Fatalf("ResolveAgentPrincipal: %v", err)
	}
	if agentPrincipal.Kind != domain.PrincipalKindAgent || agentPrincipal.Subject != "pi" {
		t.Fatalf("unexpected agent principal: %+v", agentPrincipal)
	}
	if _, _, err := agentPrincipal.GitAuthor(); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected agent GitAuthor() to fail with ErrForbidden, got %v", err)
	}

	// GetByID checks
	fetched, err := dir.GetByID(ctx, owner.ID)
	if err != nil || fetched.ID != owner.ID {
		t.Fatalf("GetByID failed: %+v err=%v", fetched, err)
	}
	if _, err := dir.GetByID(ctx, uuid.Nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for nil UUID, got %v", err)
	}

	// Logs must never contain emails.
	if strings.Contains(logBuf.String(), "alice@example.com") {
		t.Fatalf("logs leaked email address: %s", logBuf.String())
	}
}

func TestDirectoryDisabledAutoProvisioningAndConcurrency(t *testing.T) {
	t.Parallel()
	store := NewMemoryPrincipalStore()
	dir, err := NewDirectory(store, DirectoryConfig{
		AutoProvisionHumans:    false,
		AutoProvisionWorkloads: false,
	})
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	if _, err := dir.ResolveCaller(context.Background(), auth.VerifiedClaims{
		Issuer: "https://oidc.example", Subject: "unknown",
		Kind: domain.PrincipalKindHuman, TokenKind: auth.TokenKindHuman,
		Email: "u@example.com", EmailVerified: true,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden when auto-provision disabled, got %v", err)
	}

	// Concurrent Upsert/ResolveCaller on same (issuer, subject) keeps single stable ID.
	concDir, err := NewDirectory(NewMemoryPrincipalStore(), DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	claims := auth.VerifiedClaims{
		Issuer: "https://oidc.example", Subject: "concurrent-human",
		Kind: domain.PrincipalKindHuman, TokenKind: auth.TokenKindHuman,
		Email: "conc@example.com", EmailVerified: true,
	}
	var wg sync.WaitGroup
	ids := make(chan uuid.UUID, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := concDir.ResolveOwner(context.Background(), claims)
			if err != nil {
				t.Errorf("concurrent ResolveOwner: %v", err)
				return
			}
			ids <- p.ID
		}()
	}
	wg.Wait()
	close(ids)
	var first uuid.UUID
	for id := range ids {
		if first == uuid.Nil {
			first = id
		} else if id != first {
			t.Fatalf("concurrent ResolveOwner produced multiple IDs: %s vs %s", first, id)
		}
	}
	_ = time.Second
}

func TestDirectoryRejectsControlCharsAndHonorsRequireVerifiedEmail(t *testing.T) {
	t.Parallel()
	store := NewMemoryPrincipalStore()
	dir, err := NewDirectory(store, DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}
	ctx := context.Background()

	// Reject CR, LF, and NUL in DisplayName and VerifiedEmail on ResolveOwner & ResolveCaller.
	for _, tc := range []struct {
		name        string
		displayName string
		email       string
	}{
		{"lf_in_display_name", "Alice\nCo-authored-by: evil", "alice@example.com"},
		{"trailing_lf_in_display_name", "Alice\n", "alice@example.com"},
		{"cr_in_display_name", "Alice\rEvil", "alice@example.com"},
		{"nul_in_display_name", "Alice\x00Evil", "alice@example.com"},
		{"nel_in_display_name", "Alice\u0085Evil", "alice@example.com"},
		{"ls_in_display_name", "Alice\u2028Evil", "alice@example.com"},
		{"ps_in_display_name", "Alice\u2029Evil", "alice@example.com"},
		{"lf_in_email", "Alice", "alice@example.com\nX: y"},
		{"nel_in_email", "Alice", "alice@example.com\u0085"},
		{"ls_in_email", "Alice", "alice@example.com\u2028"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := auth.VerifiedClaims{
				Issuer:        "https://oidc.example",
				Subject:       "subj-" + tc.name,
				Kind:          domain.PrincipalKindHuman,
				TokenKind:     auth.TokenKindHuman,
				Email:         tc.email,
				EmailVerified: true,
				DisplayName:   tc.displayName,
			}
			if _, err := dir.ResolveCaller(ctx, claims); !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("ResolveCaller expected ErrUnprocessable for %s, got %v", tc.name, err)
			}
			if _, err := dir.ResolveOwner(ctx, claims); !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("ResolveOwner expected ErrUnprocessable for %s, got %v", tc.name, err)
			}
		})
	}

	// Pre-populated store record with LF in DisplayName must also be rejected by ResolveCaller/ResolveOwner.
	badID := domain.MustNewID()
	if _, err := store.Upsert(ctx, domain.Principal{
		ID:            badID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "prepop-bad-name",
		DisplayName:   "Bob\nCo-authored-by: evil",
		VerifiedEmail: "bob@example.com",
	}); err != nil {
		t.Fatalf("Upsert prepop: %v", err)
	}
	prepopClaims := auth.VerifiedClaims{
		Issuer:        "https://oidc.example",
		Subject:       "prepop-bad-name",
		Kind:          domain.PrincipalKindHuman,
		TokenKind:     auth.TokenKindHuman,
		Email:         "bob@example.com",
		EmailVerified: true,
	}
	if _, err := dir.ResolveOwner(ctx, prepopClaims); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("ResolveOwner on prepopulated CR/LF record expected ErrUnprocessable, got %v", err)
	}

	// When RequireVerifiedEmail is false, ResolveCaller permits non-owner human without verified email,
	// while ResolveOwner remains unconditionally fail-closed.
	laxDir, err := NewDirectory(NewMemoryPrincipalStore(), DirectoryConfig{
		AutoProvisionHumans:  true,
		RequireVerifiedEmail: false,
	})
	if err != nil {
		t.Fatalf("NewDirectory lax: %v", err)
	}
	unverifiedClaims := auth.VerifiedClaims{
		Issuer:        "https://oidc.example",
		Subject:       "human-no-email",
		Kind:          domain.PrincipalKindHuman,
		TokenKind:     auth.TokenKindHuman,
		EmailVerified: false,
	}
	if caller, err := laxDir.ResolveCaller(ctx, unverifiedClaims); err != nil || caller.Principal.VerifiedEmail != "" {
		t.Fatalf("ResolveCaller with RequireVerifiedEmail=false failed: caller=%+v err=%v", caller, err)
	}
	if _, err := dir.ResolveOwner(ctx, unverifiedClaims); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("ResolveOwner must reject unverified human even when RequireVerifiedEmail=false, got %v", err)
	}
	if _, err := laxDir.ResolveOwner(ctx, unverifiedClaims); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("ResolveOwner must reject unverified human even when RequireVerifiedEmail=false, got %v", err)
	}

	// ResolveAgentPrincipal must reject trailing/embedded control chars and Unicode separators before trimming.
	for _, badAgent := range []string{"pi\n", "\npi", "pi\u0085", "pi\u2028", "pi\u2029"} {
		if _, err := dir.ResolveAgentPrincipal(ctx, badAgent); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("ResolveAgentPrincipal(%q) expected ErrBadRequest, got %v", badAgent, err)
		}
	}
}
