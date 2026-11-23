package publication_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/publication"
)

var pubPGSeq atomic.Uint64

func startPG17ForPublicationTest(t *testing.T) (string, *persistence.Store) {
	t.Helper()
	if testing.Short() && os.Getenv("CUSTODIAN_TEST_FORCE_DOCKER") != "1" {
		t.Skip("skipping PG17 integration test under -short")
	}

	var dsn string
	var pool *pgxpool.Pool
	if envDSN := strings.TrimSpace(os.Getenv("CUSTODIAN_TEST_DSN")); envDSN != "" {
		p, err := persistence.NewPool(context.Background(), envDSN, persistence.DefaultPoolConfig())
		if err != nil {
			t.Fatalf("connect CUSTODIAN_TEST_DSN: %v", err)
		}
		t.Cleanup(p.Close)
		dsn = envDSN
		pool = p
	} else {
		if err := exec.Command("docker", "info").Run(); err != nil {
			if os.Getenv("CUSTODIAN_TEST_ALLOW_DOCKER_SKIP") == "1" {
				t.Skipf("docker unavailable: %v", err)
			}
			t.Fatalf("docker unavailable: %v", err)
		}

		name := fmt.Sprintf("custodian-m4b-pub-%d-%d", os.Getpid(), pubPGSeq.Add(1))
		runCmd := exec.Command("docker", "run", "-d", "--rm",
			"--name", name,
			"-e", "POSTGRES_USER=custodian",
			"-e", "POSTGRES_PASSWORD=custodian",
			"-e", "POSTGRES_DB=custodian",
			"-p", "127.0.0.1::5432",
			"postgres:17-alpine",
			"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off", "-c", "max_connections=200",
		)
		var out, stderr bytes.Buffer
		runCmd.Stdout = &out
		runCmd.Stderr = &stderr
		if err := runCmd.Run(); err != nil {
			t.Fatalf("docker run: %v (%s)", err, stderr.String())
		}
		cid := strings.TrimSpace(out.String())
		t.Cleanup(func() {
			_ = exec.Command("docker", "rm", "-f", "-v", cid).Run()
		})

		portOut, err := exec.Command("docker", "port", cid, "5432/tcp").CombinedOutput()
		if err != nil {
			t.Fatalf("docker port: %v (%s)", err, string(portOut))
		}
		line := strings.TrimSpace(strings.Split(strings.TrimSpace(string(portOut)), "\n")[0])
		_, portStr, err := net.SplitHostPort(line)
		if err != nil {
			t.Fatalf("split host port %q: %v", line, err)
		}
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum <= 0 || portNum == 5432 {
			t.Fatalf("invalid ephemeral port %q", portStr)
		}

		dsn = fmt.Sprintf("postgres://custodian:custodian@127.0.0.1:%s/custodian?sslmode=disable", portStr)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			p, err := persistence.NewPool(ctx, dsn, persistence.DefaultPoolConfig())
			cancel()
			if err == nil {
				t.Cleanup(p.Close)
				pool = p
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if pool == nil {
			t.Fatalf("timed out waiting for postgres container %s", cid)
		}
	}

	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return dsn, store
}

func seedApprovedProposalPG17(t *testing.T, store *persistence.Store, fix bareRepoFixture) seededIDs {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	ownerRow, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://idp.example.com",
		Subject:       "alice-" + uuid.NewString(),
		DisplayName:   "Alice Example",
		VerifiedEmail: "alice@example.com",
		Groups:        []string{"developers"},
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal owner: %v", err)
	}
	reviewerRow, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://idp.example.com",
		Subject:       "bob-" + uuid.NewString(),
		DisplayName:   "Bob Reviewer",
		VerifiedEmail: "bob@example.com",
		Groups:        []string{"security-reviewers"},
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal reviewer: %v", err)
	}
	repoRow, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		ID:                      fix.repo.ID,
		GitHubRepositoryID:      fix.repo.GitHubRepositoryID,
		GitHubInstallationID:    fix.repo.GitHubInstallationID,
		FullName:                fix.repo.FullName,
		Classification:          fix.repo.Classification,
		Enabled:                 true,
		AllowedModelRoutes:      []string{"default"},
		MaxConcurrentOperations: 4,
	})
	if err != nil {
		t.Fatalf("UpsertRepository: %v", err)
	}
	wsRow, err := store.CreateWorkspace(ctx, persistence.CreateWorkspaceParams{
		RepositoryID: repoRow.ID,
		OwnerID:      ownerRow.ID,
		BaseCommit:   fix.baseCommit,
		TargetRef:    "main",
		Generation:   1,
		Status:       domain.WorkspaceStatusReady,
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	snapArt, err := store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind:              domain.ArtifactKindEgressSnapshot,
		SHA256:            strings.Repeat("e", 64),
		StorageKey:        "egress/snap-" + uuid.NewString() + ".tar.gz",
		StorageGeneration: "1",
		SizeBytes:         64,
		Format:            "tar.gz",
		WorkspaceID:       &wsRow.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact snap: %v", err)
	}
	canonKey := "canonical/tree-" + uuid.NewString() + ".tar.gz"
	srcBytes, readErr := os.ReadFile(filepath.Join(fix.snapRoot, filepath.FromSlash(fix.archiveKey)))
	if readErr != nil {
		t.Fatalf("read canon archive: %v", readErr)
	}
	dstCanonPath := filepath.Join(fix.snapRoot, filepath.FromSlash(canonKey))
	if mkErr := os.MkdirAll(filepath.Dir(dstCanonPath), 0o755); mkErr != nil {
		t.Fatalf("mkdir canon: %v", mkErr)
	}
	if wrErr := os.WriteFile(dstCanonPath, srcBytes, 0o600); wrErr != nil {
		t.Fatalf("write canon: %v", wrErr)
	}
	canonArt, err := store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind:              domain.ArtifactKindCanonicalTree,
		SHA256:            fix.archiveSHA,
		StorageKey:        canonKey,
		StorageGeneration: "1",
		SizeBytes:         fix.archiveSize,
		Format:            "tar.gz",
		WorkspaceID:       &wsRow.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact canon: %v", err)
	}
	writeLocalMetaForPGTest(t, fix.snapRoot, canonKey, fix.archiveSHA, fix.archiveSize, 1)

	propID, _ := domain.NewID()
	manifestDigest := sha256Hex([]byte("manifest:" + propID.String() + ":" + fix.treeDigest))
	manifestArt, err := store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind:              domain.ArtifactKindPublicationManifest,
		SHA256:            manifestDigest,
		StorageKey:        "canonical/manifest-" + propID.String() + ".json",
		StorageGeneration: "1",
		SizeBytes:         128,
		Format:            "json",
		WorkspaceID:       &wsRow.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact manifest: %v", err)
	}

	propRow, err := store.CreateProposal(ctx, persistence.CreateProposalParams{
		ID:                 propID,
		WorkspaceID:        wsRow.ID,
		OwnerID:            ownerRow.ID,
		SnapshotArtifactID: snapArt.ID,
		BaseCommit:         fix.baseCommit,
		TargetRef:          "main",
		Title:              "PG17 integration feature",
		Description:        "Verified end-to-end PG17 publication",
		ProvenanceType:     "agent_assisted",
		CaptureMethod:      "frozen_filesystem",
		Status:             domain.ProposalStatusCaptured,
		Version:            1,
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	propRow, err = store.SetProposalReconstruction(ctx, persistence.SetProposalReconstructionParams{
		ID:                  propRow.ID,
		CanonicalArtifactID: canonArt.ID,
		ManifestArtifactID:  manifestArt.ID,
		TreeDigest:          fix.treeDigest,
		DiffDigest:          strings.Repeat("d", 64),
		ManifestDigest:      manifestDigest,
		Status:              domain.ProposalStatusReconstructed,
		ExpectedVersion:     propRow.Version,
		UpdatedAt:           now,
	})
	if err != nil {
		t.Fatalf("SetProposalReconstruction: %v", err)
	}

	bundleRow, err := store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:       "org-default",
		Version:    "1.0.0",
		Scope:      domain.PolicyScopeOrg,
		Digest:     sha256Hex([]byte("bundle-" + propID.String())),
		Definition: json.RawMessage(`{"rules":[]}`),
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle: %v", err)
	}
	decRow, err := store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID:     propRow.ID,
		PolicyBundleID: bundleRow.ID,
		Stage:          "EGRESS",
		InputDigest:    strings.Repeat("1", 64),
		Effect:         domain.PolicyEffectRequireApproval,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision: %v", err)
	}
	propRow, err = store.ApplyProposalPolicyDecision(ctx, persistence.ApplyProposalPolicyDecisionParams{
		ID:                 propRow.ID,
		PolicyEvaluationID: decRow.ID,
		PolicyEffect:       domain.PolicyEffectRequireApproval,
		Status:             domain.ProposalStatusPendingApproval,
		ExpectedVersion:    propRow.Version,
		UpdatedAt:          now,
	})
	if err != nil {
		t.Fatalf("ApplyProposalPolicyDecision: %v", err)
	}

	reqRow, err := store.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
		ProposalID:       propRow.ID,
		PolicyDecisionID: decRow.ID,
		RequirementType:  "GROUP_APPROVAL",
		ReviewerGroup:    "security-reviewers",
		MinimumApprovals: 1,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequirement: %v", err)
	}
	if _, err := store.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       propRow.ID,
		ReviewerID:       reviewerRow.ID,
		PolicyDecisionID: decRow.ID,
		ManifestDigest:   manifestDigest,
		Decision:         domain.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	if _, err := store.IncrementApprovalRequirementSatisfaction(ctx, reqRow.ID, now); err != nil {
		t.Fatalf("IncrementApprovalRequirementSatisfaction: %v", err)
	}
	fromPending := domain.ProposalStatusPendingApproval
	propRow, err = store.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
		ID:              propRow.ID,
		FromStatus:      &fromPending,
		ToStatus:        domain.ProposalStatusApproved,
		ExpectedVersion: propRow.Version,
		UpdatedAt:       now,
	})
	if err != nil {
		t.Fatalf("TransitionProposalStatus APPROVED: %v", err)
	}

	return seededIDs{
		repoID:         repoRow.ID,
		ownerID:        ownerRow.ID,
		reviewerID:     reviewerRow.ID,
		workspaceID:    wsRow.ID,
		proposalID:     propRow.ID,
		decisionID:     decRow.ID,
		manifestDigest: manifestDigest,
	}
}

func TestPublicationRunnerAndAuditChainPG17(t *testing.T) {
	_, store := startPG17ForPublicationTest(t)
	ctx := context.Background()

	fix := setupBareRepoFixture(t, map[string]string{"pg17.txt": "verified\n"})
	ids := seedApprovedProposalPG17(t, store, fix)

	opener, err := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}
	logger := observability.NewLogger(observability.LoggerConfig{Format: observability.LogFormatJSON})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian_pg17"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	pubSvc, err := publication.NewServiceWithConfig(publication.Config{
		Store:          publication.NewStoreAdapter(store),
		WriteClient:    fix.bareClient,
		ArtifactOpener: opener,
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}

	reqRes, err := pubSvc.RequestPublication(ctx, ids.proposalID, ids.manifestDigest, &ids.ownerID)
	if err != nil {
		t.Fatalf("RequestPublication: %v", err)
	}

	opsSvc := operations.NewService(store, metrics, logger)
	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:           opsSvc,
		Service:       pubSvc,
		LeaseDuration: 15 * time.Second,
		RenewInterval: 5 * time.Second,
		PollInterval:  50 * time.Millisecond,
		ReapInterval:  2 * time.Second,
		Logger:        logger,
		Metrics:       metrics,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	claimed, err := runner.ProcessOnce(ctx)
	if err != nil || claimed != 1 {
		t.Fatalf("ProcessOnce: claimed=%d err=%v", claimed, err)
	}

	opRow, err := store.GetOperationByID(ctx, reqRes.Operation.ID)
	if err != nil || opRow.Status != domain.OperationStatusSucceeded {
		lastErr := ""
		if opRow.LastError != nil {
			lastErr = *opRow.LastError
		}
		t.Fatalf("expected SUCCEEDED operation, err=%v status=%s last_error=%q", err, opRow.Status, lastErr)
	}
	propRow, err := store.GetProposalByID(ctx, ids.proposalID)
	if err != nil || propRow.Status != domain.ProposalStatusPublished {
		t.Fatalf("expected PUBLISHED proposal, err=%v status=%s", err, propRow.Status)
	}
	pubRow, err := store.GetPublicationByProposalID(ctx, ids.proposalID)
	if err != nil || pubRow.Status != domain.PublicationStatusPublished || pubRow.CommitSHA == nil {
		t.Fatalf("expected PUBLISHED publication, err=%v row=%+v", err, pubRow)
	}
	attempts, err := store.ListPublicationAttemptsByPublication(ctx, pubRow.ID)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "SUCCEEDED" {
		t.Fatalf("expected 1 SUCCEEDED attempt, err=%v attempts=%+v", err, attempts)
	}

	// Verify serialized hash-chained audit log passes full cryptographic chain check.
	auditSvc := audit.NewService(store, logger)
	verifyRes, err := auditSvc.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("audit VerifyChain: %v", err)
	}
	if verifyRes.EventCount < 3 {
		t.Fatalf("expected at least 3 audit events, got %d", verifyRes.EventCount)
	}

	// Verify outbox event recorded.
	outboxEvents, err := opsSvc.ClaimOutbox(ctx, "outbox-test", time.Minute, 10)
	if err != nil {
		t.Fatalf("ClaimOutbox: %v", err)
	}
	var foundPublishedOutbox bool
	for _, ev := range outboxEvents {
		if ev.EventType == "proposal.published" && ev.AggregateID == ids.proposalID {
			foundPublishedOutbox = true
		}
	}
	if !foundPublishedOutbox {
		t.Fatalf("expected proposal.published outbox event, got %+v", outboxEvents)
	}

	// Verify PR & branch in bare Git repo.
	if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 1 {
		t.Fatalf("expected 1 PR, got %d", len(prs))
	}
	_ = filepath.Base(fix.bareDir)
}

func TestPublicationOutageRetryAndReaperFilteringPG17(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 outage simulation skipped when running as root")
	}
	_, store := startPG17ForPublicationTest(t)
	ctx := context.Background()

	fix := setupBareRepoFixture(t, map[string]string{"outage.txt": "recovered\n"})
	ids := seedApprovedProposalPG17(t, store, fix)

	opener, err := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}
	logger := observability.NewLogger(observability.LoggerConfig{Format: observability.LogFormatJSON})
	metrics, _ := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian_pg17_retry"})
	pubSvc, err := publication.NewServiceWithConfig(publication.Config{
		Store:          publication.NewStoreAdapter(store),
		WriteClient:    fix.bareClient,
		ArtifactOpener: opener,
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}

	opsSvc := operations.NewService(store, metrics, logger, operations.Config{
		BaseRetryDelay: 50 * time.Millisecond,
	})
	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:     opsSvc,
		Service: pubSvc,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	op, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   3,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Simulate snapshot storage outage via chmod 0000 -> STORAGE_UNAVAILABLE -> retryable.
	if err := os.Chmod(fix.snapRoot, 0o000); err != nil {
		t.Fatalf("chmod 0000: %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		_ = os.Chmod(fix.snapRoot, 0o755)
		t.Fatalf("ProcessOnce outage: n=%d err=%v", n, err)
	}
	if err := os.Chmod(fix.snapRoot, 0o755); err != nil {
		t.Fatalf("restore chmod: %v", err)
	}

	propRow, _ := store.GetProposalByID(ctx, ids.proposalID)
	pubRow, _ := store.GetPublicationByProposalID(ctx, ids.proposalID)
	opRow, _ := store.GetOperationByID(ctx, op.ID)
	if propRow.Status != domain.ProposalStatusPublishing || pubRow.Status != domain.PublicationStatusPublishing {
		t.Fatalf("expected PUBLISHING during outage retry, got prop=%s pub=%s", propRow.Status, pubRow.Status)
	}
	if opRow.Status != domain.OperationStatusPending {
		t.Fatalf("expected PENDING retry operation, got %s", opRow.Status)
	}

	// Wait past backoff and verify recovery succeeds.
	time.Sleep(80 * time.Millisecond)
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce recovery: n=%d err=%v", n, err)
	}
	propRow, _ = store.GetProposalByID(ctx, ids.proposalID)
	if propRow.Status != domain.ProposalStatusPublished {
		t.Fatalf("expected PUBLISHED after outage recovery, got %s", propRow.Status)
	}

	// Now test ReapExpired filtering strictly to PROPOSAL_PUBLISH on PG17.
	fix2 := setupBareRepoFixture(t, map[string]string{"reap.txt": "r\n"})
	fix2.repo.GitHubRepositoryID = 1002
	fix2.repo.FullName = "octo/custodian-demo-2"
	_ = fix2.bareClient.RegisterRepo(fix2.repo.GitHubRepositoryID, fix2.repo.FullName, fix2.bareDir)
	ids2 := seedApprovedProposalPG17(t, store, fix2)
	wsOp2, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    ids2.workspaceID,
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue ws op: %v", err)
	}
	pubOp2, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids2.proposalID,
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue pub op2: %v", err)
	}
	// Claim both and expire their leases in SQL.
	expiredLease := time.Now().UTC().Add(-time.Minute)
	if _, err := store.Pool().Exec(ctx, `UPDATE operations SET status = 'RUNNING', attempts = max_attempts, leased_by = 'dead-worker', lease_until = $1 WHERE id IN ($2, $3)`, expiredLease, wsOp2.ID, pubOp2.ID); err != nil {
		t.Fatalf("expire leases: %v", err)
	}
	reaped, err := runner.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("expected ReapExpired to process 1 PROPOSAL_PUBLISH operation, got %d", reaped)
	}
	prop2, _ := store.GetProposalByID(ctx, ids2.proposalID)
	if prop2.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected reaped proposal FAILED, got %s", prop2.Status)
	}
	op2After, _ := store.GetOperationByID(ctx, pubOp2.ID)
	if op2After.Status != domain.OperationStatusFailed {
		t.Fatalf("expected reaped operation FAILED, got %s", op2After.Status)
	}
	wsOp2After, _ := store.GetOperationByID(ctx, wsOp2.ID)
	if wsOp2After.Status != domain.OperationStatusRunning {
		t.Fatalf("expected expired WORKSPACE_INGRESS operation to remain RUNNING untouched, got %s", wsOp2After.Status)
	}
}

func TestPublicationReapExpiredScopesStrictlyToProposalPublishPG17(t *testing.T) {
	_, store := startPG17ForPublicationTest(t)
	ctx := context.Background()

	fix := setupBareRepoFixture(t, map[string]string{"reap-scope.txt": "ok\n"})
	ids := seedApprovedProposalPG17(t, store, fix)

	opener, err := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}
	logger := observability.NewLogger(observability.LoggerConfig{Format: observability.LogFormatJSON})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian_pg17_reap_scope"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	pubSvc, err := publication.NewServiceWithConfig(publication.Config{
		Store:          publication.NewStoreAdapter(store),
		WriteClient:    fix.bareClient,
		ArtifactOpener: opener,
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}

	opsSvc := operations.NewService(store, metrics, logger)
	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:     opsSvc,
		Service: pubSvc,
		Logger:  logger,
		Metrics: metrics,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	// Enqueue one of each worker operation type + one PROPOSAL_PUBLISH operation.
	wsOp, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    ids.workspaceID,
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue wsOp: %v", err)
	}
	reconOp, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalReconstruct,
		ResourceType:  "proposal",
		ResourceID:    domain.MustNewID(),
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue reconOp: %v", err)
	}
	evalOp, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalEvaluate,
		ResourceType:  "proposal",
		ResourceID:    domain.MustNewID(),
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue evalOp: %v", err)
	}
	pubOp, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue pubOp: %v", err)
	}

	// Seed active_operations gauge for all 4 types in publisher's metrics registry and expire all 4 leases in SQL.
	for _, ot := range []domain.OperationType{
		domain.OperationTypeWorkspaceIngress,
		domain.OperationTypeProposalReconstruct,
		domain.OperationTypeProposalEvaluate,
		domain.OperationTypeProposalPublish,
	} {
		metrics.IncActiveOperation(string(ot))
	}
	expiredLease := time.Now().UTC().Add(-time.Minute)
	if _, err := store.Pool().Exec(ctx,
		`UPDATE operations SET status = 'RUNNING', attempts = max_attempts, leased_by = 'dead-worker', lease_until = $1 WHERE id IN ($2, $3, $4, $5)`,
		expiredLease, wsOp.ID, reconOp.ID, evalOp.ID, pubOp.ID,
	); err != nil {
		t.Fatalf("expire leases: %v", err)
	}

	reaped, err := runner.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("expected ReapExpired to reap exactly 1 PROPOSAL_PUBLISH operation, got %d", reaped)
	}

	// Worker operations MUST remain RUNNING and untouched.
	for _, tc := range []struct {
		name string
		id   uuid.UUID
	}{
		{"WORKSPACE_INGRESS", wsOp.ID},
		{"PROPOSAL_RECONSTRUCT", reconOp.ID},
		{"PROPOSAL_EVALUATE", evalOp.ID},
	} {
		row, err := store.GetOperationByID(ctx, tc.id)
		if err != nil {
			t.Fatalf("GetOperationByID(%s): %v", tc.name, err)
		}
		if row.Status != domain.OperationStatusRunning {
			t.Fatalf("expected expired %s operation to remain RUNNING, got %s", tc.name, row.Status)
		}
	}

	// PROPOSAL_PUBLISH operation and its proposal MUST be FAILED.
	pubAfter, err := store.GetOperationByID(ctx, pubOp.ID)
	if err != nil || pubAfter.Status != domain.OperationStatusFailed {
		t.Fatalf("expected PROPOSAL_PUBLISH operation FAILED, err=%v status=%s", err, pubAfter.Status)
	}
	propAfter, err := store.GetProposalByID(ctx, ids.proposalID)
	if err != nil || propAfter.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected proposal FAILED, err=%v status=%s", err, propAfter.Status)
	}

	// Verify publisher metrics: worker active gauges MUST remain 1 (never decremented); PROPOSAL_PUBLISH decremented to 0.
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather metrics: %v", err)
	}
	activeByType := make(map[string]float64)
	failedByType := make(map[string]float64)
	for _, mf := range mfs {
		switch mf.GetName() {
		case "custodian_pg17_reap_scope_active_operations":
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "operation_type" {
						activeByType[lp.GetValue()] = m.GetGauge().GetValue()
					}
				}
			}
		case "custodian_pg17_reap_scope_operations_total":
			for _, m := range mf.GetMetric() {
				var opType, status string
				for _, lp := range m.GetLabel() {
					switch lp.GetName() {
					case "operation_type":
						opType = lp.GetValue()
					case "status":
						status = lp.GetValue()
					}
				}
				if status == string(domain.OperationStatusFailed) {
					failedByType[opType] = m.GetCounter().GetValue()
				}
			}
		}
	}
	for _, wt := range []domain.OperationType{
		domain.OperationTypeWorkspaceIngress,
		domain.OperationTypeProposalReconstruct,
		domain.OperationTypeProposalEvaluate,
	} {
		if got := activeByType[string(wt)]; got != 1 {
			t.Fatalf("expected publisher active_operations gauge for %s to remain 1, got %v", wt, got)
		}
		if got := failedByType[string(wt)]; got != 0 {
			t.Fatalf("expected publisher failed counter for %s to remain 0, got %v", wt, got)
		}
	}
	if got := activeByType[string(domain.OperationTypeProposalPublish)]; got != 0 {
		t.Fatalf("expected publisher active_operations gauge for PROPOSAL_PUBLISH to decrement to 0, got %v", got)
	}
	if got := failedByType[string(domain.OperationTypeProposalPublish)]; got != 1 {
		t.Fatalf("expected publisher failed counter for PROPOSAL_PUBLISH == 1, got %v", got)
	}
}

func TestConcurrentRequestAndExecutePublicationPG17(t *testing.T) {
	_, store := startPG17ForPublicationTest(t)
	ctx := context.Background()

	fix := setupBareRepoFixture(t, map[string]string{"pg17-race.txt": "concurrent\n"})
	ids := seedApprovedProposalPG17(t, store, fix)

	opener, err := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}
	logger := observability.NewLogger(observability.LoggerConfig{Format: observability.LogFormatJSON})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian_pg17_race"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	pubSvc, err := publication.NewServiceWithConfig(publication.Config{
		Store:          publication.NewStoreAdapter(store),
		WriteClient:    fix.bareClient,
		ArtifactOpener: opener,
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}

	// 1. Concurrent RequestPublication must enqueue exactly 1 PROPOSAL_PUBLISH operation.
	const reqWorkers = 6
	reqResults := make([]publication.RequestResult, reqWorkers)
	reqErrs := make([]error, reqWorkers)
	reqGate := make(chan struct{})
	var reqWG sync.WaitGroup
	for i := range reqWorkers {
		reqWG.Add(1)
		go func(idx int) {
			defer reqWG.Done()
			<-reqGate
			reqResults[idx], reqErrs[idx] = pubSvc.RequestPublication(ctx, ids.proposalID, ids.manifestDigest, &ids.ownerID)
		}(i)
	}
	close(reqGate)
	reqWG.Wait()

	nonIdemp := 0
	for i := range reqWorkers {
		if reqErrs[i] != nil {
			t.Fatalf("RequestPublication worker %d failed: %v", i, reqErrs[i])
		}
		if !reqResults[i].Idempotent {
			nonIdemp++
		}
	}
	if nonIdemp != 1 {
		t.Fatalf("expected exactly 1 non-idempotent RequestPublication result, got %d", nonIdemp)
	}
	var opCount int64
	if err := store.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM operations WHERE resource_id = $1 AND operation_type = 'PROPOSAL_PUBLISH'`, ids.proposalID).Scan(&opCount); err != nil {
		t.Fatalf("count operations: %v", err)
	}
	if opCount != 1 {
		t.Fatalf("expected exactly 1 PROPOSAL_PUBLISH operation in PG17, got %d", opCount)
	}

	// 2. Concurrent Publish calls must serialize via FOR UPDATE, produce 1 PR/commit, and never mark FAILED.
	const pubWorkers = 4
	pubErrs := make([]error, pubWorkers)
	pubGate := make(chan struct{})
	var pubWG sync.WaitGroup
	for i := range pubWorkers {
		pubWG.Add(1)
		go func(idx int) {
			defer pubWG.Done()
			<-pubGate
			_, pubErrs[idx] = pubSvc.Publish(ctx, domain.ApprovedPublication{
				ProposalID:     ids.proposalID,
				ManifestDigest: ids.manifestDigest,
			})
		}(i)
	}
	close(pubGate)
	pubWG.Wait()

	succeeded := 0
	for i, e := range pubErrs {
		if e == nil {
			succeeded++
		} else if !errors.Is(e, domain.ErrConflict) {
			t.Fatalf("Publish worker %d unexpected error: %v", i, e)
		}
	}
	if succeeded < 1 {
		t.Fatalf("expected at least 1 Publish worker to succeed, got errors: %v", pubErrs)
	}

	propRow, _ := store.GetProposalByID(ctx, ids.proposalID)
	pubRow, _ := store.GetPublicationByProposalID(ctx, ids.proposalID)
	if propRow.Status != domain.ProposalStatusPublished || pubRow.Status != domain.PublicationStatusPublished {
		t.Fatalf("expected PUBLISHED in PG17, got prop=%s pub=%s", propRow.Status, pubRow.Status)
	}
	attempts, err := store.ListPublicationAttemptsByPublication(ctx, pubRow.ID)
	if err != nil || len(attempts) != 1 || attempts[0].Status != "SUCCEEDED" {
		t.Fatalf("expected 1 SUCCEEDED attempt in PG17, err=%v attempts=%+v", err, attempts)
	}
	if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 1 {
		t.Fatalf("expected 1 PR in bare repo, got %d", len(prs))
	}
	auditSvc := audit.NewService(store, logger)
	if _, err := auditSvc.VerifyChain(ctx); err != nil {
		t.Fatalf("audit VerifyChain: %v", err)
	}
}

func canonicalFoldPGTest(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		minR := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < minR {
				minR = f
			}
		}
		b.WriteRune(minR)
	}
	return b.String()
}

func writeLocalMetaForPGTest(t *testing.T, rootDir, key, shaHex string, sizeBytes, gen int64) {
	t.Helper()
	metaDir := filepath.Join(rootDir, ".custodian-meta", "meta")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatalf("mkdir metaDir: %v", err)
	}
	sum := sha256.Sum256([]byte(canonicalFoldPGTest(key)))
	metaPath := filepath.Join(metaDir, hex.EncodeToString(sum[:])+".json")
	payload, err := json.Marshal(map[string]any{
		"sha256":      shaHex,
		"storage_key": key,
		"generation":  gen,
		"size_bytes":  sizeBytes,
	})
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(metaPath, payload, 0o600); err != nil {
		t.Fatalf("write meta: %v", err)
	}
}
