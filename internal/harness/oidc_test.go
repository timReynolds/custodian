package harness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
)

func TestMockOIDCIntegrationWithAuthAndIdentity(t *testing.T) {
	t.Parallel()
	oidcSrv := StartMockOIDC(t, "custodian-api")

	verifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:     oidcSrv.Issuer(),
		Audience:   oidcSrv.Audience(),
		HTTPClient: oidcSrv.HTTPClient(),
		ClockSkew:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}

	dir, err := identity.NewDirectory(identity.NewMemoryPrincipalStore(), identity.DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	ctx := context.Background()

	// Human token -> verified owner with GitAuthor()
	humanJWT := oidcSrv.MintHumanToken("human-1", "dev@example.com", "Dev User", "platform")
	humanClaims, err := verifier.Verify(ctx, humanJWT)
	if err != nil {
		t.Fatalf("Verify human: %v", err)
	}
	owner, err := dir.ResolveOwner(ctx, humanClaims)
	if err != nil {
		t.Fatalf("ResolveOwner: %v", err)
	}
	if _, _, err := owner.GitAuthor(); err != nil {
		t.Fatalf("owner GitAuthor: %v", err)
	}

	// Controller token -> SERVICE/controller, rejected as human owner
	ctrlJWT := oidcSrv.MintControllerToken("spiffe://custodian/controller/1", "controller")
	ctrlClaims, err := verifier.Verify(ctx, ctrlJWT)
	if err != nil {
		t.Fatalf("Verify controller: %v", err)
	}
	caller, err := dir.ResolveCaller(ctx, ctrlClaims)
	if err != nil || !caller.IsController() {
		t.Fatalf("expected controller caller, got %+v err=%v", caller, err)
	}
	if _, err := dir.ResolveOwner(ctx, ctrlClaims); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for controller ResolveOwner, got %v", err)
	}

	// Agent token -> AGENT, rejected as human owner
	agentJWT := oidcSrv.MintAgentToken("agent-pi")
	agentClaims, err := verifier.Verify(ctx, agentJWT)
	if err != nil {
		t.Fatalf("Verify agent: %v", err)
	}
	if _, err := dir.ResolveOwner(ctx, agentClaims); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for agent ResolveOwner, got %v", err)
	}

	// Key rotation + outage simulation
	oidcSrv.RotateKey()
	rotatedJWT := oidcSrv.MintHumanToken("human-2", "dev2@example.com", "Dev Two")
	oidcSrv.SetOutage(true)
	if _, err := verifier.Verify(ctx, rotatedJWT); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable during JWKS outage, got %v", err)
	}
	oidcSrv.SetOutage(false)
	if _, err := verifier.Verify(ctx, rotatedJWT); err != nil {
		t.Fatalf("expected rotated key verify after recovery, got %v", err)
	}

	// Adversarial tokens minted by MockOIDC
	futureNBF := time.Now().UTC().Add(2 * time.Minute)
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"wrong_key", oidcSrv.MintToken(OIDCTokenClaims{Subject: "u", Kind: "HUMAN", Email: "a@b.com", SignWithWrongKey: true})},
		{"tampered_sig", oidcSrv.MintToken(OIDCTokenClaims{Subject: "u", Kind: "HUMAN", Email: "a@b.com", TamperSignature: true})},
		{"tampered_payload", oidcSrv.MintToken(OIDCTokenClaims{Subject: "u", Kind: "HUMAN", Email: "a@b.com", TamperPayload: true})},
		{"alg_none", oidcSrv.MintToken(OIDCTokenClaims{Subject: "u", Kind: "HUMAN", Email: "a@b.com", Algorithm: "none"})},
		{"alg_hs256", oidcSrv.MintToken(OIDCTokenClaims{Subject: "u", Kind: "HUMAN", Email: "a@b.com", Algorithm: "HS256"})},
		{"omit_sub", oidcSrv.MintToken(OIDCTokenClaims{Kind: "HUMAN", Email: "a@b.com", OmitSubject: true})},
		{"future_nbf_2m", oidcSrv.MintToken(OIDCTokenClaims{Subject: "u", Kind: "HUMAN", Email: "a@b.com", NotBefore: &futureNBF})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.Verify(ctx, tc.token); !errors.Is(err, domain.ErrUnauthorized) {
				t.Fatalf("expected ErrUnauthorized for %s, got %v", tc.name, err)
			}
		})
	}
}
