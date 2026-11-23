package persistence_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestActiveOperationCountsAndLatestLookupPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fx := seedPG17Fixture(t, ctx, store)

	// Seed a second repository and workspace for isolation checks.
	repoB, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:      42002,
		GitHubInstallationID:    99002,
		FullName:                "custodian-org/other",
		Classification:          domain.ClassificationInternal,
		Enabled:                 true,
		AllowedModelRoutes:      []string{"anthropic/claude"},
		MaxConcurrentOperations: 2,
	})
	if err != nil {
		t.Fatalf("CreateRepository repoB: %v", err)
	}
	wsB, err := store.CreateWorkspace(ctx, persistence.CreateWorkspaceParams{
		RepositoryID: repoB.ID,
		OwnerID:      fx.owner.ID,
		BaseCommit:   "0123456789abcdef0123456789abcdef01234567",
		TargetRef:    "refs/heads/main",
		Status:       domain.WorkspaceStatusPending,
	})
	if err != nil {
		t.Fatalf("CreateWorkspace wsB: %v", err)
	}

	propA, err := store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        fx.workspace.ID,
		OwnerID:            fx.owner.ID,
		SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit:         fx.workspace.BaseCommit,
		TargetRef:          fx.workspace.TargetRef,
		Title:              "Op Count Proposal",
	})
	if err != nil {
		t.Fatalf("CreateProposal propA: %v", err)
	}
	pubA, err := store.EnsurePublication(ctx, persistence.CreatePublicationParams{
		ProposalID: propA.ID,
		BranchRef:  domain.ExpectedBranchName(propA.ID),
		Status:     domain.PublicationStatusPending,
	})
	if err != nil {
		t.Fatalf("EnsurePublication pubA: %v", err)
	}

	// Enqueue 4 active operations for repoA across all 3 resource branches (and NULL resource_type),
	// 1 completed operation for repoA (must be excluded), and 1 active operation for repoB.
	if _, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    fx.workspace.ID,
	}); err != nil {
		t.Fatalf("enqueue wsA: %v", err)
	}
	opReconstruct, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalReconstruct,
		ResourceType:  "proposal",
		ResourceID:    propA.ID,
	})
	if err != nil {
		t.Fatalf("enqueue propA reconstruct: %v", err)
	}
	opEval, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalEvaluate,
		ResourceType:  "", // stored as NULL
		ResourceID:    propA.ID,
	})
	if err != nil {
		t.Fatalf("enqueue propA evaluate: %v", err)
	}
	opPub, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "publication",
		ResourceID:    pubA.ID,
	})
	if err != nil {
		t.Fatalf("enqueue pubA: %v", err)
	}
	opDone, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    fx.workspace.ID,
	})
	if err != nil {
		t.Fatalf("enqueue done op: %v", err)
	}
	if _, err := store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    wsB.ID,
	}); err != nil {
		t.Fatalf("enqueue wsB: %v", err)
	}

	// Claim and complete opDone, plus claim opReconstruct to keep it RUNNING.
	now := time.Now().UTC().Truncate(time.Microsecond)
	reconstructType := domain.OperationTypeProposalReconstruct
	claimedRec, err := store.ClaimOperations(ctx, persistence.ClaimOperationsParams{
		Now:           now,
		LeaseUntil:    now.Add(30 * time.Second),
		WorkerID:      "worker-1",
		OperationType: &reconstructType,
		Limit:         1,
	})
	if err != nil || len(claimedRec) != 1 || claimedRec[0].ID != opReconstruct.ID {
		t.Fatalf("claim reconstruct: (%+v, %v)", claimedRec, err)
	}

	// Mark opDone SUCCEEDED by claiming all PENDING WORKSPACE_INGRESS and completing opDone.
	ingressType := domain.OperationTypeWorkspaceIngress
	claimedIng, err := store.ClaimOperations(ctx, persistence.ClaimOperationsParams{
		Now:           now,
		LeaseUntil:    now.Add(30 * time.Second),
		WorkerID:      "worker-1",
		OperationType: &ingressType,
		Limit:         5,
	})
	if err != nil || len(claimedIng) != 3 {
		t.Fatalf("claim ingress ops: (%d, %v)", len(claimedIng), err)
	}
	if _, err := store.CompleteOperation(ctx, opDone.ID, "worker-1", json.RawMessage(`{"ok":true}`), now.Add(time.Second)); err != nil {
		t.Fatalf("CompleteOperation opDone: %v", err)
	}

	countA, err := store.CountActiveOperationsByRepository(ctx, fx.repo.ID)
	if err != nil {
		t.Fatalf("CountActiveOperationsByRepository(repoA): %v", err)
	}
	if countA != 4 {
		t.Fatalf("CountActiveOperationsByRepository(repoA) = %d, want 4", countA)
	}

	countB, err := store.CountActiveOperationsByRepository(ctx, repoB.ID)
	if err != nil {
		t.Fatalf("CountActiveOperationsByRepository(repoB): %v", err)
	}
	if countB != 1 {
		t.Fatalf("CountActiveOperationsByRepository(repoB) = %d, want 1", countB)
	}

	evalCount, err := store.CountActiveOperationsByType(ctx, domain.OperationTypeProposalEvaluate)
	if err != nil || evalCount != 1 {
		t.Fatalf("CountActiveOperationsByType(EVALUATE) = (%d, %v), want 1", evalCount, err)
	}
	ingressCount, err := store.CountActiveOperationsByType(ctx, domain.OperationTypeWorkspaceIngress)
	if err != nil || ingressCount != 2 {
		t.Fatalf("CountActiveOperationsByType(INGRESS) = (%d, %v), want 2", ingressCount, err)
	}
	recCount, err := store.CountActiveOperationsByType(ctx, domain.OperationTypeProposalReconstruct)
	if err != nil || recCount != 1 {
		t.Fatalf("CountActiveOperationsByType(RECONSTRUCT) = (%d, %v), want 1", recCount, err)
	}
	pubCount, err := store.CountActiveOperationsByType(ctx, domain.OperationTypeProposalPublish)
	if err != nil || pubCount != 1 {
		t.Fatalf("CountActiveOperationsByType(PUBLISH) = (%d, %v), want 1", pubCount, err)
	}

	// Claim & complete opEval -> count drops to 0.
	evalType := domain.OperationTypeProposalEvaluate
	claimedEval, err := store.ClaimOperations(ctx, persistence.ClaimOperationsParams{
		Now:           now,
		LeaseUntil:    now.Add(30 * time.Second),
		WorkerID:      "worker-1",
		OperationType: &evalType,
		Limit:         1,
	})
	if err != nil || len(claimedEval) != 1 || claimedEval[0].ID != opEval.ID {
		t.Fatalf("claim eval: (%+v, %v)", claimedEval, err)
	}
	if _, err := store.CompleteOperation(ctx, opEval.ID, "worker-1", nil, now.Add(2*time.Second)); err != nil {
		t.Fatalf("CompleteOperation opEval: %v", err)
	}
	evalCountAfter, err := store.CountActiveOperationsByType(ctx, domain.OperationTypeProposalEvaluate)
	if err != nil || evalCountAfter != 0 {
		t.Fatalf("CountActiveOperationsByType(EVALUATE) after completion = (%d, %v), want 0", evalCountAfter, err)
	}

	// GetLatestOperationByResource returns newest op for (pubA.ID, PROPOSAL_PUBLISH), and ErrNotFound when absent.
	latestPubOp, err := store.GetLatestOperationByResource(ctx, pubA.ID, domain.OperationTypeProposalPublish)
	if err != nil || latestPubOp.ID != opPub.ID {
		t.Fatalf("GetLatestOperationByResource(pubA): (%+v, %v), want %s", latestPubOp, err, opPub.ID)
	}
	if _, err := store.GetLatestOperationByResource(ctx, wsB.ID, domain.OperationTypeProposalPublish); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetLatestOperationByResource(missing): expected ErrNotFound, got %v", err)
	}

	// Verify CountActiveScanRuns & CountActiveModelAssessments.
	scanRun, err := store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID:     propA.ID,
		ArtifactID:     fx.canonArt.ID,
		Scanner:        "gitleaks",
		ScannerVersion: "8.18.0",
		Status:         domain.ScanStatusRunning,
	})
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	ma, err := store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ProposalID:     propA.ID,
		ArtifactID:     fx.canonArt.ID,
		ModelRoute:     "anthropic/claude",
		ModelVersion:   "v1",
		PromptVersion:  "p1",
		AssessmentType: "SECURITY_REVIEW",
		Status:         domain.AssessmentStatusPending,
		InputDigest:    domain.SHA256Hex([]byte("in")),
		OutputDigest:   domain.SHA256Hex([]byte("out")),
	})
	if err != nil {
		t.Fatalf("CreateModelAssessment: %v", err)
	}
	if activeScans, err := store.CountActiveScanRuns(ctx); err != nil || activeScans != 1 {
		t.Fatalf("CountActiveScanRuns = (%d, %v), want 1", activeScans, err)
	}
	if activeMA, err := store.CountActiveModelAssessments(ctx); err != nil || activeMA != 1 {
		t.Fatalf("CountActiveModelAssessments = (%d, %v), want 1", activeMA, err)
	}
	if _, err := store.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
		ID:          scanRun.ID,
		Status:      domain.ScanStatusCompleted,
		Coverage:    domain.ScanCoverage{FilesExamined: 1, Complete: true},
		CompletedAt: now.Add(3 * time.Second),
	}); err != nil {
		t.Fatalf("CompleteScanRun: %v", err)
	}
	if _, err := store.UpdateModelAssessmentResult(ctx, persistence.UpdateModelAssessmentResultParams{
		ID:           ma.ID,
		Status:       domain.AssessmentStatusComplete,
		Risk:         domain.RiskLevelNone,
		Disposition:  domain.DispositionClear,
		OutputDigest: domain.SHA256Hex([]byte("out2")),
	}); err != nil {
		t.Fatalf("UpdateModelAssessmentResult: %v", err)
	}
	if activeScans, err := store.CountActiveScanRuns(ctx); err != nil || activeScans != 0 {
		t.Fatalf("CountActiveScanRuns after complete = (%d, %v), want 0", activeScans, err)
	}
	if activeMA, err := store.CountActiveModelAssessments(ctx); err != nil || activeMA != 0 {
		t.Fatalf("CountActiveModelAssessments after complete = (%d, %v), want 0", activeMA, err)
	}
}

func TestRepositoryLookupsAndListPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	t0 := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	r1, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   101,
		GitHubInstallationID: 201,
		FullName:             "org/alpha",
		Classification:       domain.ClassificationPublic,
		Enabled:              true,
		CreatedAt:            t0,
	})
	if err != nil {
		t.Fatalf("create r1: %v", err)
	}
	r2, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   102,
		GitHubInstallationID: 201,
		FullName:             "org/beta",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
		AllowedModelRoutes:   []string{"route-a"},
		CreatedAt:            t0.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("create r2: %v", err)
	}
	r3, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   103,
		GitHubInstallationID: 201,
		FullName:             "org/gamma",
		Classification:       domain.ClassificationConfidential,
		Enabled:              false,
		CreatedAt:            t0.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("create r3: %v", err)
	}

	got, err := store.GetRepositoryByFullName(ctx, "  org/beta ")
	if err != nil || got.ID != r2.ID {
		t.Fatalf("GetRepositoryByFullName(org/beta): (%+v, %v)", got, err)
	}
	if _, err := store.GetRepositoryByFullName(ctx, "org/missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetRepositoryByFullName(missing): expected ErrNotFound, got %v", err)
	}

	limited, err := store.ListRepositories(ctx, 2)
	if err != nil || len(limited) != 2 || limited[0].ID != r3.ID || limited[1].ID != r2.ID {
		t.Fatalf("ListRepositories(2): (%+v, %v)", limited, err)
	}
	all, err := store.ListRepositories(ctx, 0)
	if err != nil || len(all) != 3 || all[2].ID != r1.ID {
		t.Fatalf("ListRepositories(0): (%+v, %v)", all, err)
	}
	for _, r := range all {
		if r.AllowedModelRoutes == nil {
			t.Fatalf("expected non-nil AllowedModelRoutes on %s", r.FullName)
		}
	}
}

func TestPolicyBundleUpsertAndActiveListsPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	fx := seedPG17Fixture(t, ctx, store)

	digestOrg := domain.SHA256Hex([]byte("org-policy-v1"))
	t1 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	first, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name:        "org-default",
		Version:     "1.0.0",
		Scope:       domain.PolicyScopeOrg,
		Digest:      digestOrg,
		Definition:  json.RawMessage(`{"rules":[{"id":"r1"}]}`),
		ActivatedAt: nil,
	})
	if err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest first: %v", err)
	}
	if first.ActivatedAt != nil {
		t.Fatalf("expected nil ActivatedAt on first upsert, got %v", first.ActivatedAt)
	}

	// Second upsert with same digest (and new UUID) preserves original row ID and sets activated_at.
	second, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		ID:          domain.MustNewID(),
		Name:        "org-default",
		Version:     "1.0.1",
		Scope:       domain.PolicyScopeOrg,
		Digest:      digestOrg,
		Definition:  json.RawMessage(`{"rules":[{"id":"r1"}]}`),
		ActivatedAt: &t1,
	})
	if err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest second: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected FK-stable ID %s, got %s", first.ID, second.ID)
	}
	if second.ActivatedAt == nil || !second.ActivatedAt.Equal(t1) || second.Version != "1.0.1" {
		t.Fatalf("expected activated bundle v1.0.1 at %v, got %+v", t1, second)
	}

	// Third upsert with nil ActivatedAt must NOT deactivate the already-active bundle.
	third, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name:        "org-default",
		Version:     "1.0.1",
		Scope:       domain.PolicyScopeOrg,
		Digest:      digestOrg,
		Definition:  json.RawMessage(`{"rules":[{"id":"r1"}]}`),
		ActivatedAt: nil,
	})
	if err != nil || third.ActivatedAt == nil || !third.ActivatedAt.Equal(t1) {
		t.Fatalf("expected ActivatedAt preserved when nil passed on conflict, got (%+v, %v)", third, err)
	}

	// Seed an unactivated ORG bundle (must be excluded) and an active REPO bundle.
	if _, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name:       "org-draft",
		Version:    "2.0.0",
		Scope:      domain.PolicyScopeOrg,
		Digest:     domain.SHA256Hex([]byte("org-draft")),
		Definition: json.RawMessage(`{"rules":[]}`),
	}); err != nil {
		t.Fatalf("seed inactive org bundle: %v", err)
	}
	repoBundle, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name:         "repo-override",
		Version:      "1.0.0",
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: &fx.repo.ID,
		Digest:       domain.SHA256Hex([]byte("repo-override")),
		Definition:   json.RawMessage(`{"rules":[{"id":"r2"}]}`),
		ActivatedAt:  &t1,
	})
	if err != nil {
		t.Fatalf("seed active repo bundle: %v", err)
	}

	activeAll, err := store.ListActivePolicyBundles(ctx)
	if err != nil {
		t.Fatalf("ListActivePolicyBundles: %v", err)
	}
	if len(activeAll) != 2 || activeAll[0].ID != first.ID || activeAll[1].ID != repoBundle.ID {
		t.Fatalf("ListActivePolicyBundles expected [ORG, REPO], got %+v", activeAll)
	}

	activeRepo, err := store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeRepo, &fx.repo.ID)
	if err != nil || len(activeRepo) != 1 || activeRepo[0].ID != repoBundle.ID {
		t.Fatalf("ListActivePolicyBundlesByScope(REPO): (%+v, %v)", activeRepo, err)
	}
	activeOrg, err := store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
	if err != nil || len(activeOrg) != 1 || activeOrg[0].ID != first.ID {
		t.Fatalf("ListActivePolicyBundlesByScope(ORG): (%+v, %v)", activeOrg, err)
	}
}

func TestProposalForUpdateDetailsListAndApprovalReqPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	fx := seedPG17Fixture(t, ctx, store)

	prop, err := store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        fx.workspace.ID,
		OwnerID:            fx.owner.ID,
		SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit:         fx.workspace.BaseCommit,
		TargetRef:          fx.workspace.TargetRef,
		Title:              "Lock & Details Test",
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}

	// Verify GetProposalByIDForUpdate blocks a concurrent tx until first tx commits.
	lockedCh := make(chan struct{})
	releaseCh := make(chan struct{})
	tx1Done := make(chan error, 1)
	go func() {
		tx1Done <- store.WithTx(ctx, func(tx *persistence.Tx) error {
			if _, err := tx.GetProposalByIDForUpdate(ctx, prop.ID); err != nil {
				return err
			}
			close(lockedCh)
			<-releaseCh
			_, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
				ID:              prop.ID,
				ToStatus:        domain.ProposalStatusReconstructing,
				ExpectedVersion: 1,
			})
			return err
		})
	}()

	<-lockedCh
	tx2Started := make(chan struct{})
	tx2Done := make(chan persistence.ProposalRow, 1)
	tx2Err := make(chan error, 1)
	go func() {
		close(tx2Started)
		err := store.WithTx(ctx, func(tx *persistence.Tx) error {
			row, err := tx.GetProposalByIDForUpdate(ctx, prop.ID)
			if err != nil {
				return err
			}
			tx2Done <- row
			return nil
		})
		tx2Err <- err
	}()
	<-tx2Started

	select {
	case row := <-tx2Done:
		t.Fatalf("expected tx2 GetProposalByIDForUpdate to block while tx1 holds FOR UPDATE lock, got %+v", row)
	case <-time.After(150 * time.Millisecond):
		// Expected blocking behavior confirmed.
	}

	close(releaseCh)
	if err := <-tx1Done; err != nil {
		t.Fatalf("tx1: %v", err)
	}
	if err := <-tx2Err; err != nil {
		t.Fatalf("tx2: %v", err)
	}
	gotLocked := <-tx2Done
	if gotLocked.Status != domain.ProposalStatusReconstructing || gotLocked.Version != 2 {
		t.Fatalf("expected tx2 to observe committed v2 RECONSTRUCTING after lock release, got %+v", gotLocked)
	}

	// Verify ListProposalDetailsByWorkspace and ListProposalDetailsByOwner.
	wsDetails, err := store.ListProposalDetailsByWorkspace(ctx, fx.workspace.ID, 10)
	if err != nil || len(wsDetails) != 1 {
		t.Fatalf("ListProposalDetailsByWorkspace: (%+v, %v)", wsDetails, err)
	}
	if wsDetails[0].RepositoryFullName != fx.repo.FullName || wsDetails[0].WorkspaceGeneration != fx.workspace.Generation || wsDetails[0].OwnerDisplayName == nil {
		t.Fatalf("unexpected details hydration: %+v", wsDetails[0])
	}

	recStatus := domain.ProposalStatusReconstructing
	ownerDetails, err := store.ListProposalDetailsByOwner(ctx, persistence.ListProposalsByOwnerParams{
		OwnerID: fx.owner.ID,
		Status:  &recStatus,
		Limit:   10,
	})
	if err != nil || len(ownerDetails) != 1 || ownerDetails[0].Proposal.ID != prop.ID {
		t.Fatalf("ListProposalDetailsByOwner(RECONSTRUCTING): (%+v, %v)", ownerDetails, err)
	}

	// Verify GetApprovalRequirementByID.
	bundle, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name:       "default",
		Version:    "1.0.0",
		Scope:      domain.PolicyScopeOrg,
		Digest:     domain.SHA256Hex([]byte("req-test-bundle")),
		Definition: json.RawMessage(`{"rules":[]}`),
	})
	if err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest: %v", err)
	}
	pd, err := store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID:     prop.ID,
		PolicyBundleID: bundle.ID,
		InputDigest:    domain.SHA256Hex([]byte("input")),
		Effect:         domain.PolicyEffectRequireApproval,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision: %v", err)
	}
	req, err := store.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
		ProposalID:       prop.ID,
		PolicyDecisionID: pd.ID,
		RequirementType:  "HUMAN_REVIEW",
		ReviewerGroup:    "security",
		MinimumApprovals: 2,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequirement: %v", err)
	}
	gotReq, err := store.GetApprovalRequirementByID(ctx, req.ID)
	if err != nil || gotReq.ID != req.ID || gotReq.ReviewerGroup != "security" || gotReq.MinimumApprovals != 2 {
		t.Fatalf("GetApprovalRequirementByID: (%+v, %v)", gotReq, err)
	}
	if _, err := store.GetApprovalRequirementByID(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetApprovalRequirementByID(missing): expected ErrNotFound, got %v", err)
	}
}
