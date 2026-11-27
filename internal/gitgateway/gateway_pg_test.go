package gitgateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestPG17OIDCGroupsPersistenceAndSSHPrincipalNoAutoProvision(t *testing.T) {
	pg := harness.StartPostgres(t)
	oidc := harness.StartMockOIDC(t, "custodian-api")
	ctx := context.Background()

	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	verifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   oidc.Issuer(),
		JWKSURL:  oidc.JWKSURL(),
		Audience: oidc.Audience(),
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	dir, err := identity.NewDirectory(store, identity.DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostSSHPub, _ := ssh.NewPublicKey(hostPub)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caSSHPub := caSigner.PublicKey()

	authenticator, err := NewAuthenticator(AuthenticatorConfig{
		OIDC:       verifier,
		Directory:  dir,
		Store:      store,
		SSHHostKey: hostSigner,
		SSHUserCA:  caSSHPub,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// 1. HTTPS OIDC request resolves caller and persists groups into PG principals.groups.
	jwt := oidc.MintHumanToken("alice-human-001", "alice@example.com", "Alice Dev", "security", "platform")
	req := httptest.NewRequest(http.MethodGet, "/acme/service.git/info/refs", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Custodian-Upstream-Token", "ghp_pg_delegated_123")

	caller, err := authenticator.AuthenticateHTTPRequest(ctx, req)
	if err != nil {
		t.Fatalf("AuthenticateHTTPRequest: %v", err)
	}
	if caller.DelegatedUpstreamToken != "ghp_pg_delegated_123" || !slices.Contains(caller.Groups, "platform") {
		t.Fatalf("unexpected OIDC caller: %+v", caller)
	}

	row, err := store.GetPrincipalByID(ctx, caller.Principal.ID)
	if err != nil {
		t.Fatalf("GetPrincipalByID: %v", err)
	}
	if !slices.Contains(row.Groups, "security") || !slices.Contains(row.Groups, "platform") {
		t.Fatalf("expected OIDC groups persisted in PG principals table, got %v", row.Groups)
	}

	// 2. SSH CertChecker resolves seeded principal by subject or verified_email, and rejects unknown without auto-provision.
	sshCfg, reg, err := authenticator.BuildSSHServerConfig()
	if err != nil {
		t.Fatalf("BuildSSHServerConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc, chans, reqs, err := ssh.NewServerConn(c, sshCfg)
				if err != nil {
					_ = c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for range chans {
				}
				_ = sc.Close()
			}(conn)
		}
	}()

	now := time.Now()
	// Match by subject ("alice-human-001").
	subjSigner, _ := mintSSHUserCert(t, caSigner, []string{"alice-human-001"}, "pg-key-sub", 2001, now.Add(-time.Minute), now.Add(time.Hour))
	sc1, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(subjSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSSHPub),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH dial by subject failed: %v", err)
	}
	gotP1, ok := reg.Get(sc1.SessionID())
	_ = sc1.Close()
	if !ok || gotP1.Principal.ID != caller.Principal.ID || !slices.Contains(gotP1.Groups, "security") {
		t.Fatalf("unexpected SSH principal by subject: ok=%v principal=%+v", ok, gotP1)
	}

	// Match by verified_email ("alice@example.com").
	emailSigner, _ := mintSSHUserCert(t, caSigner, []string{"alice@example.com"}, "pg-key-email", 2002, now.Add(-time.Minute), now.Add(time.Hour))
	sc2, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(emailSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSSHPub),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("SSH dial by verified_email failed: %v", err)
	}
	_ = sc2.Close()

	// Unknown principal MUST be rejected and NOT auto-provisioned in PG.
	var countBefore int
	if err := pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM principals`).Scan(&countBefore); err != nil {
		t.Fatalf("count principals before: %v", err)
	}
	unknownSigner, _ := mintSSHUserCert(t, caSigner, []string{"unknown-principal-xyz"}, "pg-key-unknown", 2003, now.Add(-time.Minute), now.Add(time.Hour))
	if cBad, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(unknownSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSSHPub),
		Timeout:         3 * time.Second,
	}); err == nil {
		_ = cBad.Close()
		t.Fatal("expected unknown SSH principal to be rejected")
	}
	var countAfter int
	if err := pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM principals`).Scan(&countAfter); err != nil {
		t.Fatalf("count principals after: %v", err)
	}
	if countAfter != countBefore {
		t.Fatalf("unknown SSH principal was auto-provisioned! before=%d after=%d", countBefore, countAfter)
	}
}

func TestPG17TargetResolverRepositories(t *testing.T) {
	pg := harness.StartPostgres(t)
	ctx := context.Background()
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	regFlag := true
	extFlag := false
	if _, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:    1001,
		GitHubInstallationID:  2001,
		FullName:              "acme/pg-service",
		Classification:        domain.ClassificationConfidential,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		GitRemoteURL:          "http://127.0.0.1:18080/acme/pg-service.git",
		RemoteHost:            "github.com",
		RegisteredDestination: &regFlag,
		External:              &extFlag,
	}); err != nil {
		t.Fatalf("UpsertRepository(enabled): %v", err)
	}
	if _, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   1002,
		GitHubInstallationID: 2001,
		FullName:             "acme/pg-disabled",
		Classification:       domain.ClassificationInternal,
		Enabled:              false,
		EgressMode:           domain.EgressModeEnforceBlock,
	}); err != nil {
		t.Fatalf("UpsertRepository(disabled): %v", err)
	}

	resolver, err := NewTargetResolver(TargetResolverConfig{
		Store:                store,
		UpstreamBaseURL:      "http://127.0.0.1:18080",
		DefaultEgressMode:    domain.EgressModeEnforceBlock,
		DefaultAuditDelivery: domain.PassiveAuditDeliveryAsync,
	})
	if err != nil {
		t.Fatalf("NewTargetResolver: %v", err)
	}

	got, err := resolver.Resolve(ctx, "acme/pg-service", "gateway.local")
	if err != nil {
		t.Fatalf("Resolve(enabled): %v", err)
	}
	if !got.Registered || got.External || got.CanonicalDestination != "github.com/acme/pg-service" || got.Repository == nil {
		t.Fatalf("unexpected resolved repo: %+v", got)
	}

	_, err = resolver.Resolve(ctx, "acme/pg-disabled", "gateway.local")
	var de *domain.DomainError
	if !errors.As(err, &de) || de.Code() != "REPOSITORY_DISABLED" {
		t.Fatalf("expected REPOSITORY_DISABLED, got %v", err)
	}

	unreg, err := resolver.Resolve(ctx, "external/pg-missing", "gateway.local")
	if err != nil {
		t.Fatalf("Resolve(unregistered): %v", err)
	}
	if unreg.Registered || !unreg.External || unreg.EgressMode != domain.EgressModeEnforceBlock {
		t.Fatalf("unexpected unregistered target: %+v", unreg)
	}
}
