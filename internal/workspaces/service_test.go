package workspaces_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func TestWorkspacesUnitValidation(t *testing.T) {
	t.Parallel()

	svc := workspaces.NewServiceWithStore(nil, nil, nil)
	ctx := context.Background()

	// Nil store returns Unavailable.
	_, err := svc.Get(ctx, domain.MustNewID())
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on nil store, got %v", err)
	}

	// Bad base commit returns BadRequest.
	svcWithFake := workspaces.NewServiceWithStore(workspaces.NewStoreAdapter(&persistence.Store{}), nil, nil)
	_, err = svcWithFake.Create(ctx, workspaces.CreateInput{
		RepositoryID: domain.MustNewID(),
		OwnerID:      domain.MustNewID(),
		BaseCommit:   "not-a-sha",
		TargetRef:    "refs/heads/main",
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on invalid base_commit, got %v", err)
	}

	// Invalid status enum in TransitionStatus returns 400 BadRequest (not 409 Conflict).
	_, err = svcWithFake.TransitionStatus(ctx, domain.MustNewID(), domain.WorkspaceStatus("BOGUS"), domain.WorkspaceStatusReady)
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on invalid fromStatus, got %v", err)
	}
	_, err = svcWithFake.TransitionStatus(ctx, domain.MustNewID(), domain.WorkspaceStatusPending, domain.WorkspaceStatus("BOGUS"))
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on invalid toStatus, got %v", err)
	}
}

func TestWorkspacesAtomicCreationAndLifecyclePG17(t *testing.T) {
	pg := harness.StartPostgres(t)
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	metrics, err := observability.NewMetrics(observability.MetricsConfig{})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	logger := observability.NewLogger(observability.LoggerConfig{})

	repoSvc := repositories.NewService(store, logger)
	wsSvc := workspaces.NewService(store, metrics, logger)
	artSvc := artifacts.NewService(store, logger)
	auditSvc := audit.NewService(store, logger)
	ctx := context.Background()

	humanOwner, err := store.Upsert(ctx, domain.Principal{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "human-owner-1",
		DisplayName:   "Bob",
		VerifiedEmail: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("Upsert humanOwner: %v", err)
	}
	agentPrincipal, err := store.Upsert(ctx, domain.Principal{
		Kind:        domain.PrincipalKindAgent,
		DisplayName: "Coding Agent",
	})
	if err != nil {
		t.Fatalf("Upsert agentPrincipal: %v", err)
	}

	enabledRepo, err := repoSvc.Create(ctx, repositories.UpsertInput{
		GitHubRepositoryID:   1001,
		GitHubInstallationID: 5001,
		FullName:             "acme/custodian-demo",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
		AllowedModelRoutes:   []string{"internal-claude"},
	})
	if err != nil {
		t.Fatalf("Create enabledRepo: %v", err)
	}
	disabledRepo, err := repoSvc.Create(ctx, repositories.UpsertInput{
		GitHubRepositoryID:   1002,
		GitHubInstallationID: 5001,
		FullName:             "acme/disabled-repo",
		Classification:       domain.ClassificationPublic,
		Enabled:              false,
	})
	if err != nil {
		t.Fatalf("Create disabledRepo: %v", err)
	}

	baseCommit := strings.Repeat("a", 40)

	// Rejects disabled repo, disallowed model route, and non-HUMAN owner without leaving partial rows.
	_, err = wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: disabledRepo.ID,
		OwnerID:      humanOwner.ID,
		BaseCommit:   baseCommit,
		TargetRef:    "refs/heads/main",
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo, got %v", err)
	}
	_, err = wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: enabledRepo.ID,
		OwnerID:      humanOwner.ID,
		ModelRoute:   "disallowed-route",
		BaseCommit:   baseCommit,
		TargetRef:    "refs/heads/main",
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disallowed model route, got %v", err)
	}
	_, err = wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: enabledRepo.ID,
		OwnerID:      agentPrincipal.ID,
		BaseCommit:   baseCommit,
		TargetRef:    "refs/heads/main",
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for non-HUMAN owner, got %v", err)
	}

	var wsCount, opCount, outboxCount, auditCount int
	_ = pg.Pool().QueryRow(ctx, "SELECT count(*) FROM workspaces").Scan(&wsCount)
	_ = pg.Pool().QueryRow(ctx, "SELECT count(*) FROM operations").Scan(&opCount)
	_ = pg.Pool().QueryRow(ctx, "SELECT count(*) FROM outbox_events").Scan(&outboxCount)
	_ = pg.Pool().QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&auditCount)
	if wsCount != 0 || opCount != 0 || outboxCount != 0 || auditCount != 0 {
		t.Fatalf("expected 0 rows after rejected Create calls, got ws=%d op=%d ob=%d audit=%d", wsCount, opCount, outboxCount, auditCount)
	}

	// Happy path atomic Create: workspace + operation + outbox + hash-chained audit.
	created, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID:   enabledRepo.ID,
		OwnerID:        humanOwner.ID,
		AgentID:        &agentPrincipal.ID,
		AgentType:      "claude-code",
		AgentSessionID: "sess-1",
		ModelRoute:     "internal-claude",
		BaseCommit:     baseCommit,
		TargetRef:      "refs/heads/main",
		SourceOptions: domain.SourceOptions{
			IncludeGitMetadata: true,
			IncludeHistory:     false,
		},
	})
	if err != nil {
		t.Fatalf("Create workspace: %v", err)
	}
	if created.Workspace.Generation != 1 || created.Workspace.Status != domain.WorkspaceStatusPending {
		t.Fatalf("unexpected workspace state: %+v", created.Workspace)
	}
	if created.Operation.OperationType != domain.OperationTypeWorkspaceIngress || created.Operation.ResourceID != created.Workspace.ID {
		t.Fatalf("unexpected operation: %+v", created.Operation)
	}
	if !created.SourceOptions.IncludeGitMetadata || created.SourceOptions.IncludeHistory || created.AgentType != "claude-code" {
		t.Fatalf("unexpected source options / agent type: %+v", created)
	}

	// Verify GetDetails joins repo and owner info.
	details, err := wsSvc.GetDetails(ctx, created.Workspace.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	if details.GitHubRepositoryID != 1001 || details.RepositoryFullName != "acme/custodian-demo" {
		t.Fatalf("unexpected repo details: %+v", details)
	}
	if details.Owner.PrincipalID != humanOwner.ID || details.Owner.IdentityProvider != "https://oidc.example" {
		t.Fatalf("unexpected owner details: %+v", details.Owner)
	}

	// Transition PENDING -> PREPARING.
	preparing, err := wsSvc.TransitionStatus(ctx, created.Workspace.ID, domain.WorkspaceStatusPending, domain.WorkspaceStatusPreparing)
	if err != nil || preparing.Status != domain.WorkspaceStatusPreparing {
		t.Fatalf("TransitionStatus PENDING->PREPARING: (%+v, %v)", preparing, err)
	}
	// Stale transition PENDING -> READY returns Conflict.
	_, err = wsSvc.TransitionStatus(ctx, created.Workspace.ID, domain.WorkspaceStatusPending, domain.WorkspaceStatusReady)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on stale transition, got %v", err)
	}

	// Invalid enum in TransitionStatus returns 400 BadRequest.
	if _, err := wsSvc.TransitionStatus(ctx, created.Workspace.ID, domain.WorkspaceStatus("BOGUS"), domain.WorkspaceStatusReady); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on invalid fromStatus, got %v", err)
	}

	// Attach WORKSPACE_SOURCE artifact -> READY.
	srcArt, err := artSvc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            domain.SHA256Hex([]byte("source-archive")),
		StorageKey:        "workspaces/" + created.Workspace.ID.String() + "/source.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         512,
		Format:            "tar+gzip",
		WorkspaceID:       &created.Workspace.ID,
	})
	if err != nil {
		t.Fatalf("Register source artifact: %v", err)
	}
	// Rejects non-READY status argument (400 BadRequest).
	if _, err := wsSvc.AttachSourceArtifact(ctx, created.Workspace.ID, srcArt.ID, domain.WorkspaceStatusPending); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for AttachSourceArtifact with PENDING status, got %v", err)
	}
	// Rejects artifact bound to a different workspace (409 Conflict).
	otherWS, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: enabledRepo.ID,
		OwnerID:      humanOwner.ID,
		BaseCommit:   baseCommit,
		TargetRef:    "refs/heads/other",
	})
	if err != nil {
		t.Fatalf("Create otherWS: %v", err)
	}
	otherArt, err := artSvc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            domain.SHA256Hex([]byte("other-ws-archive")),
		StorageKey:        "workspaces/" + otherWS.Workspace.ID.String() + "/source.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         256,
		Format:            "tar+gzip",
		WorkspaceID:       &otherWS.Workspace.ID,
	})
	if err != nil {
		t.Fatalf("Register otherArt: %v", err)
	}
	if _, err := wsSvc.AttachSourceArtifact(ctx, created.Workspace.ID, otherArt.ID, domain.WorkspaceStatusReady); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict for artifact belonging to different workspace, got %v", err)
	}

	readyWS, err := wsSvc.AttachSourceArtifact(ctx, created.Workspace.ID, srcArt.ID, domain.WorkspaceStatusReady)
	if err != nil || readyWS.Status != domain.WorkspaceStatusReady || readyWS.SourceArtifactID == nil || *readyWS.SourceArtifactID != srcArt.ID {
		t.Fatalf("AttachSourceArtifact: (%+v, %v)", readyWS, err)
	}
	// Rejects overwriting source_artifact_id on already-READY workspace (409 Conflict) and preserves original source_artifact_id.
	secondArt, err := artSvc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            domain.SHA256Hex([]byte("second-archive")),
		StorageKey:        "workspaces/" + created.Workspace.ID.String() + "/source2.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         128,
		Format:            "tar+gzip",
		WorkspaceID:       &created.Workspace.ID,
	})
	if err != nil {
		t.Fatalf("Register secondArt: %v", err)
	}
	if _, err := wsSvc.AttachSourceArtifact(ctx, created.Workspace.ID, secondArt.ID, domain.WorkspaceStatusReady); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict overwriting source artifact on READY workspace, got %v", err)
	}
	recheckWS, err := wsSvc.Get(ctx, created.Workspace.ID)
	if err != nil || recheckWS.SourceArtifactID == nil || *recheckWS.SourceArtifactID != srcArt.ID {
		t.Fatalf("expected original source_artifact_id preserved, got (%+v, %v)", recheckWS, err)
	}

	// Transition READY -> CLOSED, then reject further transitions out of terminal CLOSED.
	closedWS, err := wsSvc.TransitionStatus(ctx, created.Workspace.ID, domain.WorkspaceStatusReady, domain.WorkspaceStatusClosed)
	if err != nil || closedWS.Status != domain.WorkspaceStatusClosed {
		t.Fatalf("TransitionStatus READY->CLOSED: (%+v, %v)", closedWS, err)
	}
	_, err = wsSvc.TransitionStatus(ctx, created.Workspace.ID, domain.WorkspaceStatusClosed, domain.WorkspaceStatusReady)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict transitioning out of terminal state, got %v", err)
	}

	// Verify audit chain covers workspace.created (x2), status_transitioned, source_attached, status_transitioned (5 events).
	verifyRes, err := auditSvc.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if verifyRes.EventCount != 5 {
		t.Fatalf("expected 5 audit events, got %d", verifyRes.EventCount)
	}
	_ = uuid.Nil
}
