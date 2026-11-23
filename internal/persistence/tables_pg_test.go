package persistence_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

type pg17Fixture struct {
	owner     persistence.PrincipalRow
	reviewer1 persistence.PrincipalRow
	reviewer2 persistence.PrincipalRow
	agent     persistence.PrincipalRow
	repo      persistence.RepositoryRow
	srcArt    persistence.ArtifactRow
	snapArt   persistence.ArtifactRow
	canonArt  persistence.ArtifactRow
	diffArt   persistence.ArtifactRow
	manArt    persistence.ArtifactRow
	workspace persistence.WorkspaceRow
}

func seedPG17Fixture(t *testing.T, ctx context.Context, store *persistence.Store) pg17Fixture {
	t.Helper()

	owner, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "owner-1",
		DisplayName:   "Owner One",
		VerifiedEmail: "owner@example.com",
		Groups:        []string{"engineering"},
	})
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	reviewer1, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:        domain.PrincipalKindHuman,
		Issuer:      "https://oidc.example",
		Subject:     "reviewer-1",
		DisplayName: "Reviewer One",
		Groups:      []string{"security"},
	})
	if err != nil {
		t.Fatalf("seed reviewer1: %v", err)
	}
	reviewer2, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:        domain.PrincipalKindHuman,
		Issuer:      "https://oidc.example",
		Subject:     "reviewer-2",
		DisplayName: "Reviewer Two",
		Groups:      []string{"security"},
	})
	if err != nil {
		t.Fatalf("seed reviewer2: %v", err)
	}
	agent, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:        domain.PrincipalKindAgent,
		Issuer:      "https://oidc.example",
		Subject:     "agent-1",
		DisplayName: "Agent Runner",
	})
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	repo, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:      42001,
		GitHubInstallationID:    99001,
		FullName:                "custodian-org/widget",
		Classification:          domain.ClassificationConfidential,
		Enabled:                 true,
		AllowedModelRoutes:      []string{"anthropic/claude"},
		MaxConcurrentOperations: 5,
	})
	if err != nil {
		t.Fatalf("seed repo: %v", err)
	}

	regArtifact := func(kind domain.ArtifactKind, key string) persistence.ArtifactRow {
		art, err := store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
			Kind:              kind,
			SHA256:            domain.SHA256Hex([]byte(key)),
			StorageKey:        key,
			StorageGeneration: "gen-1",
			SizeBytes:         1024,
			UploadedBy:        &owner.ID,
		})
		if err != nil {
			t.Fatalf("seed artifact %s: %v", key, err)
		}
		return art
	}

	srcArt := regArtifact(domain.ArtifactKindWorkspaceSource, "ws/src.tar.gz")
	snapArt := regArtifact(domain.ArtifactKindEgressSnapshot, "ws/snap.tar.gz")
	canonArt := regArtifact(domain.ArtifactKindCanonicalTree, "prop/tree.tar.gz")
	diffArt := regArtifact(domain.ArtifactKindCanonicalDiff, "prop/diff.patch")
	manArt := regArtifact(domain.ArtifactKindPublicationManifest, "prop/manifest.json")

	baseCommit := "abcdef0123456789abcdef0123456789abcdef01"
	ws, err := store.CreateWorkspace(ctx, persistence.CreateWorkspaceParams{
		RepositoryID:     repo.ID,
		OwnerID:          owner.ID,
		AgentID:          &agent.ID,
		AgentType:        "claude-code",
		AgentSessionID:   "sess-42",
		ModelRoute:       "anthropic/claude",
		BaseCommit:       baseCommit,
		TargetRef:        "refs/heads/main",
		SourceArtifactID: &srcArt.ID,
		Status:           domain.WorkspaceStatusReady,
	})
	if err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	return pg17Fixture{
		owner:     owner,
		reviewer1: reviewer1,
		reviewer2: reviewer2,
		agent:     agent,
		repo:      repo,
		srcArt:    srcArt,
		snapArt:   snapArt,
		canonArt:  canonArt,
		diffArt:   diffArt,
		manArt:    manArt,
		workspace: ws,
	}
}

func TestProposalsLifecycleAndOptimisticConcurrencyPG17(t *testing.T) {
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

	// FK violation -> ErrBadRequest
	_, err = store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        domain.MustNewID(),
		OwnerID:            fx.owner.ID,
		SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit:         fx.workspace.BaseCommit,
		TargetRef:          "refs/heads/main",
		Title:              "Invalid FK",
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for missing workspace FK, got %v", err)
	}

	createdAt := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
	prop, err := store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        fx.workspace.ID,
		OwnerID:            fx.owner.ID,
		SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit:         fx.workspace.BaseCommit,
		TargetRef:          "refs/heads/main",
		Title:              "Add rate limiter",
		Description:        "Protects /v1/proposals",
		ProvenanceType:     "agent_assisted",
		CaptureMethod:      "frozen_filesystem",
		CreatedAt:          createdAt,
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	if !domain.IsUUIDv7(prop.ID) || prop.Status != domain.ProposalStatusCaptured || prop.Version != 1 {
		t.Fatalf("unexpected created proposal: %+v", prop)
	}

	// GetProposalByID & ToDomain round-trip
	got, err := store.GetProposalByID(ctx, prop.ID)
	if err != nil {
		t.Fatalf("GetProposalByID: %v", err)
	}
	domProp := got.ToDomain()
	if domProp.ID != prop.ID || domProp.Title != "Add rate limiter" || domProp.Description != "Protects /v1/proposals" || !domProp.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected GetProposalByID.ToDomain: %+v", domProp)
	}

	// GetProposalDetailsByID joins workspaces + repositories + principals
	details, err := store.GetProposalDetailsByID(ctx, prop.ID)
	if err != nil {
		t.Fatalf("GetProposalDetailsByID: %v", err)
	}
	if details.RepositoryID != fx.repo.ID || details.GitHubRepositoryID != fx.repo.GitHubRepositoryID ||
		details.RepositoryFullName != fx.repo.FullName || details.RepositoryClassification != fx.repo.Classification ||
		details.WorkspaceAgentID == nil || *details.WorkspaceAgentID != fx.agent.ID ||
		details.OwnerKind != domain.PrincipalKindHuman || *details.OwnerDisplayName != "Owner One" {
		t.Fatalf("unexpected GetProposalDetailsByID: %+v", details)
	}

	// ListProposalsByWorkspace & ListProposalsByOwner (filtered + unfiltered)
	byWS, err := store.ListProposalsByWorkspace(ctx, fx.workspace.ID, 10)
	if err != nil || len(byWS) != 1 || byWS[0].ID != prop.ID {
		t.Fatalf("ListProposalsByWorkspace: got (%d, %v)", len(byWS), err)
	}
	capturedStatus := domain.ProposalStatusCaptured
	byOwner, err := store.ListProposalsByOwner(ctx, persistence.ListProposalsByOwnerParams{
		OwnerID: fx.owner.ID,
		Status:  &capturedStatus,
		Limit:   10,
	})
	if err != nil || len(byOwner) != 1 || byOwner[0].ID != prop.ID {
		t.Fatalf("ListProposalsByOwner filtered: got (%d, %v)", len(byOwner), err)
	}

	// Optimistic CAS transition CAPTURED -> RECONSTRUCTING
	t1, err := store.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
		ID:              prop.ID,
		FromStatus:      &capturedStatus,
		ToStatus:        domain.ProposalStatusReconstructing,
		ExpectedVersion: 1,
	})
	if err != nil || t1.Status != domain.ProposalStatusReconstructing || t1.Version != 2 {
		t.Fatalf("TransitionProposalStatus: got (%+v, %v)", t1, err)
	}

	// Stale ExpectedVersion=1 -> ErrConflict (409)
	_, err = store.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
		ID:              prop.ID,
		ToStatus:        domain.ProposalStatusEvaluating,
		ExpectedVersion: 1,
	})
	if !errors.Is(err, domain.ErrConflict) || domain.HTTPStatusFromError(err) != 409 {
		t.Fatalf("expected 409 Conflict on stale version, got %v", err)
	}

	// Missing proposal -> ErrNotFound (404)
	_, err = store.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
		ID:              domain.MustNewID(),
		ToStatus:        domain.ProposalStatusEvaluating,
		ExpectedVersion: 1,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing proposal, got %v", err)
	}

	// SetProposalReconstruction
	treeDigest := "1111111111111111111111111111111111111111"
	diffDigest := domain.SHA256Hex([]byte("diff"))
	manifestDigest := domain.SHA256Hex([]byte("manifest"))
	recon, err := store.SetProposalReconstruction(ctx, persistence.SetProposalReconstructionParams{
		ID:                  prop.ID,
		CanonicalArtifactID: fx.canonArt.ID,
		DiffArtifactID:      &fx.diffArt.ID,
		ManifestArtifactID:  fx.manArt.ID,
		TreeDigest:          treeDigest,
		DiffDigest:          diffDigest,
		ManifestDigest:      manifestDigest,
		ExpectedVersion:     2,
	})
	if err != nil || recon.Status != domain.ProposalStatusReconstructed || recon.Version != 3 ||
		*recon.CanonicalArtifactID != fx.canonArt.ID || *recon.DiffArtifactID != fx.diffArt.ID ||
		*recon.ManifestDigest != manifestDigest {
		t.Fatalf("SetProposalReconstruction: got (%+v, %v)", recon, err)
	}

	// ApplyProposalPolicyDecision
	bundle, err := store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:       "org",
		Version:    "1.0.0",
		Scope:      domain.PolicyScopeOrg,
		Digest:     domain.SHA256Hex([]byte("org-bundle")),
		Definition: json.RawMessage(`{"rules":[]}`),
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle: %v", err)
	}
	decision, err := store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID:     prop.ID,
		PolicyBundleID: bundle.ID,
		Stage:          "EGRESS",
		InputDigest:    domain.SHA256Hex([]byte("policy-in")),
		Effect:         domain.PolicyEffectRequireApproval,
		Reasons:        []domain.PolicyReason{{RuleID: "r1", Effect: domain.PolicyEffectRequireApproval}},
		Obligations:    []domain.Obligation{{Type: "HUMAN_REVIEW", ReviewerGroup: "security", Minimum: 1}},
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision: %v", err)
	}

	applied, err := store.ApplyProposalPolicyDecision(ctx, persistence.ApplyProposalPolicyDecisionParams{
		ID:                 prop.ID,
		PolicyEvaluationID: decision.ID,
		PolicyEffect:       domain.PolicyEffectRequireApproval,
		Status:             domain.ProposalStatusPendingApproval,
		ExpectedVersion:    3,
	})
	if err != nil || applied.Version != 4 || applied.Status != domain.ProposalStatusPendingApproval ||
		applied.LatestPolicyEvaluationID == nil || *applied.LatestPolicyEvaluationID != decision.ID ||
		applied.LatestPolicyEffect == nil || *applied.LatestPolicyEffect != domain.PolicyEffectRequireApproval {
		t.Fatalf("ApplyProposalPolicyDecision: got (%+v, %v)", applied, err)
	}

	// Owner list with PENDING_APPROVAL filter returns it; CAPTURED filter returns empty.
	pendingAppStatus := domain.ProposalStatusPendingApproval
	byOwnerPending, err := store.ListProposalsByOwner(ctx, persistence.ListProposalsByOwnerParams{
		OwnerID: fx.owner.ID,
		Status:  &pendingAppStatus,
	})
	if err != nil || len(byOwnerPending) != 1 {
		t.Fatalf("ListProposalsByOwner PENDING_APPROVAL: got (%d, %v)", len(byOwnerPending), err)
	}
	byOwnerCap, err := store.ListProposalsByOwner(ctx, persistence.ListProposalsByOwnerParams{
		OwnerID: fx.owner.ID,
		Status:  &capturedStatus,
	})
	if err != nil || len(byOwnerCap) != 0 {
		t.Fatalf("ListProposalsByOwner CAPTURED: expected 0, got (%d, %v)", len(byOwnerCap), err)
	}
}

func TestInspectionScanRunsFindingsAndAssessmentsPG17(t *testing.T) {
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
		TargetRef:          "refs/heads/main",
		Title:              "Inspection test",
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}

	// 1. scan_runs
	run1, err := store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID:     prop.ID,
		ArtifactID:     fx.canonArt.ID,
		Scanner:        "gitleaks",
		ScannerVersion: "8.18.0",
		Status:         domain.ScanStatusRunning,
	})
	if err != nil {
		t.Fatalf("CreateScanRun run1: %v", err)
	}
	run2, err := store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID:     prop.ID,
		ArtifactID:     fx.canonArt.ID,
		Scanner:        "scancode",
		ScannerVersion: "32.0.0",
		Status:         domain.ScanStatusPending,
		StartedAt:      run1.StartedAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("CreateScanRun run2: %v", err)
	}

	comp1, err := store.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
		ID:     run1.ID,
		Status: domain.ScanStatusCompleted,
		Coverage: domain.ScanCoverage{
			FilesExamined:  42,
			FilesSkipped:   0,
			BytesExamined:  8192,
			SkippedReasons: []string{},
			Complete:       true,
		},
	})
	if err != nil || !comp1.ToDomain().IsCleanComplete() {
		t.Fatalf("CompleteScanRun run1: got (%+v, %v)", comp1, err)
	}

	// Second completion -> ErrConflict
	_, err = store.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
		ID:     run1.ID,
		Status: domain.ScanStatusFailed,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on double CompleteScanRun, got %v", err)
	}

	comp2, err := store.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
		ID:     run2.ID,
		Status: domain.ScanStatusIncomplete,
		Coverage: domain.ScanCoverage{
			FilesExamined:  10,
			FilesSkipped:   2,
			SkippedReasons: []string{"oversized", "binary"},
			Complete:       false,
		},
	})
	if err != nil || comp2.ToDomain().IsCleanComplete() || len(comp2.ToDomain().Coverage.SkippedReasons) != 2 {
		t.Fatalf("CompleteScanRun run2: got (%+v, %v)", comp2, err)
	}

	runs, err := store.ListScanRunsByProposal(ctx, prop.ID)
	if err != nil || len(runs) != 2 || runs[0].ID != run2.ID || runs[1].ID != run1.ID {
		t.Fatalf("ListScanRunsByProposal order mismatch: got (%+v, %v)", runs, err)
	}

	// 2. findings: ValidateRedacted rejects unredacted secret before DB insert
	_, err = store.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID:   run1.ID,
		Category:    "SECRET",
		Severity:    domain.SeverityCritical,
		RuleID:      "aws-access-key",
		Fingerprint: "fp-bad",
		Redacted:    false,
	})
	if !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for unredacted SECRET, got %v", err)
	}

	// Create 5 findings across run1 (gitleaks) and run2 (scancode) for filter + cursor pagination tests.
	start0, end0 := 0, 0
	conf := 0.88
	var createdIDs []uuid.UUID
	specs := []persistence.CreateFindingParams{
		{ScanRunID: run1.ID, EvidenceID: "ev-1", Scanner: "gitleaks", Category: "SECRET", Severity: domain.SeverityCritical, RuleID: "r1", Path: "a.go", StartLine: &start0, EndLine: &end0, Fingerprint: "fp1", Confidence: &conf, Redacted: true, Metadata: map[string]any{"entropy": 4.9}},
		{ScanRunID: run2.ID, EvidenceID: "ev-2", Scanner: "scancode", Category: "LICENSE", Severity: domain.SeverityHigh, RuleID: "gpl3", Path: "b.go", Fingerprint: "fp2", Redacted: true},
		{ScanRunID: run2.ID, EvidenceID: "ev-3", Scanner: "scancode", Category: "LICENSE", Severity: domain.SeverityMedium, RuleID: "apache2", Path: "c.go", Fingerprint: "fp3", Redacted: true},
		{ScanRunID: run2.ID, EvidenceID: "ev-4", Scanner: "scancode", Category: "LICENSE", Severity: domain.SeverityHigh, RuleID: "agpl3", Path: "d.go", Fingerprint: "fp4", Redacted: true},
		{ScanRunID: run1.ID, EvidenceID: "ev-5", Scanner: "gitleaks", Category: "SECRET", Severity: domain.SeverityLow, RuleID: "r5", Path: "e.go", Fingerprint: "fp5", Redacted: true},
	}
	for i, sp := range specs {
		f, err := store.CreateFinding(ctx, sp)
		if err != nil {
			t.Fatalf("CreateFinding[%d]: %v", i, err)
		}
		createdIDs = append(createdIDs, f.ID)
	}

	byRun1, err := store.ListFindingsByScanRun(ctx, run1.ID)
	if err != nil || len(byRun1) != 2 {
		t.Fatalf("ListFindingsByScanRun: expected 2, got (%d, %v)", len(byRun1), err)
	}
	if gotDom := byRun1[0].ToDomain(); gotDom.StartLine != 0 || gotDom.Confidence != 0.88 || gotDom.Metadata["entropy"] != 4.9 {
		t.Fatalf("FindingRow.ToDomain mismatch: %+v", gotDom)
	}

	// Filter by scanner=scancode & severity=HIGH
	scancodeFilter := "scancode"
	highSev := domain.SeverityHigh
	filtered, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: prop.ID,
		Scanner:    &scancodeFilter,
		Severity:   &highSev,
		Limit:      10,
	})
	if err != nil || len(filtered) != 2 {
		t.Fatalf("ListFindingsByProposal filtered: expected 2, got (%d, %v)", len(filtered), err)
	}

	// Keyset cursor pagination across all 5 findings (page size 2)
	page1, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: prop.ID,
		Limit:      2,
	})
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: got (%d, %v)", len(page1), err)
	}
	page2, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: prop.ID,
		CursorID:   &page1[1].ID,
		Limit:      2,
	})
	if err != nil || len(page2) != 2 {
		t.Fatalf("page2: got (%d, %v)", len(page2), err)
	}
	page3, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: prop.ID,
		CursorID:   &page2[1].ID,
		Limit:      2,
	})
	if err != nil || len(page3) != 1 {
		t.Fatalf("page3: got (%d, %v)", len(page3), err)
	}
	var pagedIDs []uuid.UUID
	for _, r := range append(append(page1, page2...), page3...) {
		pagedIDs = append(pagedIDs, r.ID)
	}
	if !reflect.DeepEqual(pagedIDs, createdIDs) {
		t.Fatalf("cursor pagination IDs mismatch: got %v, want %v", pagedIDs, createdIDs)
	}

	// ListFindingsByProposal Limit <= 0 (default 100) & Limit > 1001 (clamp 1001) + CursorID == uuid.Nil
	nilCursor := uuid.Nil
	if _, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: prop.ID,
		CursorID:   &nilCursor,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for CursorID == uuid.Nil, got %v", err)
	}
	propClamp, err := store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        fx.workspace.ID,
		OwnerID:            fx.owner.ID,
		SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit:         fx.workspace.BaseCommit,
		TargetRef:          "refs/heads/main",
		Title:              "Findings clamp test",
	})
	if err != nil {
		t.Fatalf("CreateProposal propClamp: %v", err)
	}
	runClamp, err := store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID:     propClamp.ID,
		ArtifactID:     fx.canonArt.ID,
		Scanner:        "semgrep",
		ScannerVersion: "1.0.0",
		Status:         domain.ScanStatusCompleted,
	})
	if err != nil {
		t.Fatalf("CreateScanRun runClamp: %v", err)
	}
	if err := store.WithTx(ctx, func(tx *persistence.Tx) error {
		for i := 0; i < 1002; i++ {
			if _, err := tx.CreateFinding(ctx, persistence.CreateFindingParams{
				ScanRunID:   runClamp.ID,
				Scanner:     "semgrep",
				Category:    "SAST",
				Severity:    domain.SeverityLow,
				RuleID:      "clamp.rule",
				Fingerprint: fmt.Sprintf("fp-clamp-%d", i),
				Redacted:    true,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed 1002 findings for clamp test: %v", err)
	}
	defaultLimZero, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: propClamp.ID,
		Limit:      0,
	})
	if err != nil || len(defaultLimZero) != 100 {
		t.Fatalf("ListFindingsByProposal Limit=0: expected 100 rows, got (%d, %v)", len(defaultLimZero), err)
	}
	defaultLimNeg, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: propClamp.ID,
		Limit:      -10,
	})
	if err != nil || len(defaultLimNeg) != 100 {
		t.Fatalf("ListFindingsByProposal Limit=-10: expected 100 rows, got (%d, %v)", len(defaultLimNeg), err)
	}
	clampedLim, err := store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: propClamp.ID,
		Limit:      2500,
	})
	if err != nil || len(clampedLim) != 1001 {
		t.Fatalf("ListFindingsByProposal Limit=2500: expected 1001 rows, got (%d, %v)", len(clampedLim), err)
	}

	// 3. model_assessments (verify JSONB evidence_ids + nullable risk/disposition)
	inDigest := domain.SHA256Hex([]byte("model-in"))
	outDigest0 := domain.SHA256Hex([]byte("pending-out"))
	ma, err := store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ProposalID:     prop.ID,
		ArtifactID:     fx.canonArt.ID,
		ModelRoute:     "anthropic/claude",
		ModelVersion:   "claude-sonnet-4",
		PromptVersion:  "sec-v1",
		AssessmentType: "SECURITY_REVIEW",
		Status:         domain.AssessmentStatusPending,
		InputDigest:    inDigest,
		OutputDigest:   outDigest0,
	})
	if err != nil {
		t.Fatalf("CreateModelAssessment pending: %v", err)
	}
	if ma.Risk != nil || ma.Disposition != nil {
		t.Fatalf("expected nil Risk/Disposition on pending assessment, got (%v, %v)", ma.Risk, ma.Disposition)
	}
	if !ma.ToDomain().BlocksPublication() {
		t.Fatalf("pending assessment must block publication")
	}

	outDigest1 := domain.SHA256Hex([]byte("complete-out"))
	updatedMA, err := store.UpdateModelAssessmentResult(ctx, persistence.UpdateModelAssessmentResultParams{
		ID:          ma.ID,
		Status:      domain.AssessmentStatusComplete,
		Risk:        domain.RiskLevelLow,
		Disposition: domain.DispositionReview,
		Result: domain.AssessmentResult{
			SchemaVersion:  "1.0",
			AssessmentType: "SECURITY_REVIEW",
			Risk:           domain.RiskLevelLow,
			Disposition:    domain.DispositionReview,
			Confidence:     0.91,
			Summary:        "Reviewed license findings",
			Findings: []domain.AssessmentFinding{{
				Category:          "LICENSE",
				EvidenceIDs:       []string{"ev-2"},
				Reason:            "GPLv3 detected",
				RecommendedAction: "Confirm legal approval",
			}},
			Limitations: []string{"none"},
		},
		EvidenceIDs:  []string{"ev-2"},
		OutputDigest: outDigest1,
	})
	if err != nil {
		t.Fatalf("UpdateModelAssessmentResult: %v", err)
	}
	domMA := updatedMA.ToDomain()
	if domMA.BlocksPublication() || domMA.Risk != domain.RiskLevelLow || len(domMA.EvidenceIDs) != 1 || domMA.EvidenceIDs[0] != "ev-2" {
		t.Fatalf("unexpected completed ModelAssessment: %+v", domMA)
	}

	// Second UpdateModelAssessmentResult -> ErrConflict
	_, err = store.UpdateModelAssessmentResult(ctx, persistence.UpdateModelAssessmentResultParams{
		ID:           ma.ID,
		Status:       domain.AssessmentStatusFailed,
		OutputDigest: outDigest1,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on second UpdateModelAssessmentResult, got %v", err)
	}

	listedMAs, err := store.ListModelAssessmentsByProposal(ctx, prop.ID)
	if err != nil || len(listedMAs) != 1 || listedMAs[0].ID != ma.ID {
		t.Fatalf("ListModelAssessmentsByProposal: got (%d, %v)", len(listedMAs), err)
	}
}

func TestPoliciesApprovalsAndRequirementsPG17(t *testing.T) {
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
		TargetRef:          "refs/heads/main",
		Title:              "Policy & Approval test",
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}

	// 1. policy_bundles
	t0 := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Microsecond)
	orgDigest := domain.SHA256Hex([]byte("org-v1"))
	orgBundle, err := store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:        "org-baseline",
		Version:     "1.0.0",
		Scope:       domain.PolicyScopeOrg,
		Digest:      orgDigest,
		Definition:  json.RawMessage(`{"rules":[{"id":"org-1"}]}`),
		ActivatedAt: &t0,
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle org: %v", err)
	}

	// Duplicate digest -> ErrConflict
	_, err = store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:       "org-dup",
		Version:    "1.0.1",
		Scope:      domain.PolicyScopeOrg,
		Digest:     orgDigest,
		Definition: json.RawMessage(`{}`),
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate bundle digest, got %v", err)
	}

	gotByDigest, err := store.GetPolicyBundleByDigest(ctx, "SHA256:"+orgDigest)
	if err != nil || gotByDigest.ID != orgBundle.ID {
		t.Fatalf("GetPolicyBundleByDigest: got (%+v, %v)", gotByDigest, err)
	}

	// Unactivated REPO bundle is not returned by GetActivePolicyBundle until ActivatePolicyBundle
	repoBundle, err := store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:         "repo-rules",
		Version:      "1.0.0",
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: &fx.repo.ID,
		Digest:       domain.SHA256Hex([]byte("repo-v1")),
		Definition:   json.RawMessage(`{"rules":[{"id":"repo-1"}]}`),
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle repo: %v", err)
	}
	_, err = store.GetActivePolicyBundle(ctx, domain.PolicyScopeRepo, &fx.repo.ID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound before repo bundle activation, got %v", err)
	}
	if _, err := store.ActivatePolicyBundle(ctx, repoBundle.ID, t0.Add(time.Minute)); err != nil {
		t.Fatalf("ActivatePolicyBundle: %v", err)
	}
	activeRepo, err := store.GetActivePolicyBundle(ctx, domain.PolicyScopeRepo, &fx.repo.ID)
	if err != nil || activeRepo.ID != repoBundle.ID {
		t.Fatalf("GetActivePolicyBundle repo: got (%+v, %v)", activeRepo, err)
	}
	activeOrg, err := store.GetActivePolicyBundle(ctx, domain.PolicyScopeOrg, nil)
	if err != nil || activeOrg.ID != orgBundle.ID {
		t.Fatalf("GetActivePolicyBundle org: got (%+v, %v)", activeOrg, err)
	}

	// 2. policy_decisions
	dec1, err := store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID:     prop.ID,
		PolicyBundleID: repoBundle.ID,
		OrgBundleID:    &orgBundle.ID,
		RepoBundleID:   &repoBundle.ID,
		Stage:          "EGRESS",
		InputDigest:    domain.SHA256Hex([]byte("in-1")),
		Effect:         domain.PolicyEffectRequireApproval,
		Reasons:        []domain.PolicyReason{{RuleID: "org-1", Effect: domain.PolicyEffectRequireApproval, Stage: "EGRESS"}},
		Obligations:    []domain.Obligation{{Type: "HUMAN_REVIEW", ReviewerGroup: "security", Minimum: 2}},
		CreatedAt:      t0,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision dec1: %v", err)
	}
	latestDec, err := store.GetLatestPolicyDecisionForProposal(ctx, prop.ID)
	if err != nil || latestDec.ID != dec1.ID {
		t.Fatalf("GetLatestPolicyDecisionForProposal: got (%+v, %v)", latestDec, err)
	}

	// 3. approval_requirements
	req, err := store.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
		ProposalID:       prop.ID,
		PolicyDecisionID: dec1.ID,
		RequirementType:  "HUMAN_REVIEW",
		ReviewerGroup:    "security",
		MinimumApprovals: 2,
	})
	if err != nil {
		t.Fatalf("CreateApprovalRequirement: %v", err)
	}
	if ob := req.ToObligation(); ob.Minimum != 2 || ob.ReviewerGroup != "security" {
		t.Fatalf("unexpected ToObligation: %+v", ob)
	}
	// Duplicate (policy_decision_id, requirement_type, reviewer_group) -> ErrConflict
	_, err = store.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
		ProposalID:       prop.ID,
		PolicyDecisionID: dec1.ID,
		RequirementType:  "HUMAN_REVIEW",
		ReviewerGroup:    "security",
		MinimumApprovals: 1,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate approval_requirement, got %v", err)
	}

	// Increment 1 -> satisfied_count=1, satisfied_at=nil
	inc1, err := store.IncrementApprovalRequirementSatisfaction(ctx, req.ID, t0.Add(2*time.Minute))
	if err != nil || inc1.SatisfiedCount != 1 || inc1.SatisfiedAt != nil {
		t.Fatalf("Increment 1: got (%+v, %v)", inc1, err)
	}
	// Increment 2 -> satisfied_count=2, satisfied_at!=nil
	inc2, err := store.IncrementApprovalRequirementSatisfaction(ctx, req.ID, t0.Add(3*time.Minute))
	if err != nil || inc2.SatisfiedCount != 2 || inc2.SatisfiedAt == nil {
		t.Fatalf("Increment 2: got (%+v, %v)", inc2, err)
	}
	// Increment 3 -> satisfied_count=3, satisfied_at remains unchanged (idempotency of AND satisfied_at IS NULL)
	inc3, err := store.IncrementApprovalRequirementSatisfaction(ctx, req.ID, t0.Add(3*time.Minute+30*time.Second))
	if err != nil || inc3.SatisfiedCount != 3 || inc3.SatisfiedAt == nil || !inc3.SatisfiedAt.Equal(*inc2.SatisfiedAt) {
		t.Fatalf("Increment 3: got (%+v, %v), want SatisfiedAt=%v", inc3, err, inc2.SatisfiedAt)
	}

	// 4. approvals
	manifestDigest := domain.SHA256Hex([]byte("manifest-v1"))
	app1, err := store.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       prop.ID,
		ReviewerID:       fx.reviewer1.ID,
		PolicyDecisionID: dec1.ID,
		ManifestDigest:   manifestDigest,
		Decision:         domain.ApprovalDecisionApprove,
		Comment:          "Approved 1/2",
	})
	if err != nil || !app1.ToDomain().IsActiveForManifest(manifestDigest) {
		t.Fatalf("CreateApproval app1: got (%+v, %v)", app1, err)
	}
	app2, err := store.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       prop.ID,
		ReviewerID:       fx.reviewer2.ID,
		PolicyDecisionID: dec1.ID,
		ManifestDigest:   manifestDigest,
		Decision:         domain.ApprovalDecisionApprove,
	})
	if err != nil {
		t.Fatalf("CreateApproval app2: %v", err)
	}

	activeList, err := store.ListActiveApprovalsForDecision(ctx, prop.ID, dec1.ID, manifestDigest)
	if err != nil || len(activeList) != 2 || activeList[0].ID != app1.ID || activeList[1].ID != app2.ID {
		t.Fatalf("ListActiveApprovalsForDecision: got (%+v, %v)", activeList, err)
	}
	hasR1, err := store.HasActiveApprovalByReviewer(ctx, prop.ID, dec1.ID, fx.reviewer1.ID, manifestDigest)
	if err != nil || !hasR1 {
		t.Fatalf("HasActiveApprovalByReviewer reviewer1: got (%v, %v)", hasR1, err)
	}
	hasOwner, err := store.HasActiveApprovalByReviewer(ctx, prop.ID, dec1.ID, fx.owner.ID, manifestDigest)
	if err != nil || hasOwner {
		t.Fatalf("HasActiveApprovalByReviewer owner: expected false, got (%v, %v)", hasOwner, err)
	}

	// Revoke & reset
	revokedCount, err := store.RevokeApprovalsForProposal(ctx, prop.ID, t0.Add(4*time.Minute))
	if err != nil || revokedCount != 2 {
		t.Fatalf("RevokeApprovalsForProposal: expected 2, got (%d, %v)", revokedCount, err)
	}
	resetCount, err := store.ResetApprovalRequirementsForPolicyDecision(ctx, dec1.ID)
	if err != nil || resetCount != 1 {
		t.Fatalf("ResetApprovalRequirementsForPolicyDecision: expected 1, got (%d, %v)", resetCount, err)
	}
	afterRevoke, err := store.ListActiveApprovalsForDecision(ctx, prop.ID, dec1.ID, manifestDigest)
	if err != nil || len(afterRevoke) != 0 {
		t.Fatalf("expected 0 active approvals after revoke, got (%d, %v)", len(afterRevoke), err)
	}
	hasR1After, err := store.HasActiveApprovalByReviewer(ctx, prop.ID, dec1.ID, fx.reviewer1.ID, manifestDigest)
	if err != nil || hasR1After {
		t.Fatalf("expected HasActiveApprovalByReviewer false after revoke, got (%v, %v)", hasR1After, err)
	}
	reqsAfterReset, err := store.ListApprovalRequirementsByPolicyDecision(ctx, dec1.ID)
	if err != nil || len(reqsAfterReset) != 1 || reqsAfterReset[0].SatisfiedCount != 0 || reqsAfterReset[0].SatisfiedAt != nil {
		t.Fatalf("unexpected requirements after reset: %+v (%v)", reqsAfterReset, err)
	}

	// Regression: ListActiveApprovalsForDecision must exclude unrevoked REJECT rows while ListApprovalsByProposal returns both.
	prop2, err := store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        fx.workspace.ID,
		OwnerID:            fx.owner.ID,
		SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit:         fx.workspace.BaseCommit,
		TargetRef:          "refs/heads/main",
		Title:              "Approval vs Rejection regression",
	})
	if err != nil {
		t.Fatalf("CreateProposal prop2: %v", err)
	}
	dec2, err := store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID:     prop2.ID,
		PolicyBundleID: repoBundle.ID,
		OrgBundleID:    &orgBundle.ID,
		RepoBundleID:   &repoBundle.ID,
		Stage:          "EGRESS",
		InputDigest:    domain.SHA256Hex([]byte("in-2")),
		Effect:         domain.PolicyEffectRequireApproval,
		Reasons:        []domain.PolicyReason{{RuleID: "org-1", Effect: domain.PolicyEffectRequireApproval, Stage: "EGRESS"}},
		Obligations:    []domain.Obligation{{Type: "HUMAN_REVIEW", ReviewerGroup: "security", Minimum: 1}},
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision dec2: %v", err)
	}
	approveRow, err := store.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       prop2.ID,
		ReviewerID:       fx.reviewer1.ID,
		PolicyDecisionID: dec2.ID,
		ManifestDigest:   manifestDigest,
		Decision:         domain.ApprovalDecisionApprove,
		Comment:          "Approved",
	})
	if err != nil {
		t.Fatalf("CreateApproval APPROVE: %v", err)
	}
	rejectRow, err := store.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       prop2.ID,
		ReviewerID:       fx.reviewer2.ID,
		PolicyDecisionID: dec2.ID,
		ManifestDigest:   manifestDigest,
		Decision:         domain.ApprovalDecisionReject,
		Comment:          "Needs changes",
	})
	if err != nil {
		t.Fatalf("CreateApproval REJECT: %v", err)
	}
	activeDec2, err := store.ListActiveApprovalsForDecision(ctx, prop2.ID, dec2.ID, manifestDigest)
	if err != nil || len(activeDec2) != 1 || activeDec2[0].ID != approveRow.ID || activeDec2[0].Decision != domain.ApprovalDecisionApprove {
		t.Fatalf("ListActiveApprovalsForDecision must return only APPROVE row, got (%+v, %v)", activeDec2, err)
	}
	allProp2Approvals, err := store.ListApprovalsByProposal(ctx, prop2.ID)
	if err != nil || len(allProp2Approvals) != 2 {
		t.Fatalf("ListApprovalsByProposal must return both APPROVE and REJECT rows, got (%+v, %v)", allProp2Approvals, err)
	}
	seen := map[uuid.UUID]domain.ApprovalDecision{}
	for _, a := range allProp2Approvals {
		seen[a.ID] = a.Decision
	}
	if seen[approveRow.ID] != domain.ApprovalDecisionApprove || seen[rejectRow.ID] != domain.ApprovalDecisionReject {
		t.Fatalf("ListApprovalsByProposal missing expected rows: %+v", seen)
	}
}

func TestPublicationsAndAttemptsPG17(t *testing.T) {
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
		TargetRef:          "refs/heads/main",
		Title:              "Publication test",
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}

	// Single publication per proposal + idempotent EnsurePublication
	pub, err := store.CreatePublication(ctx, persistence.CreatePublicationParams{
		ProposalID: prop.ID,
		BranchRef:  domain.ExpectedBranchName(prop.ID),
	})
	if err != nil || pub.Status != domain.PublicationStatusPending || pub.AttemptCount != 0 {
		t.Fatalf("CreatePublication: got (%+v, %v)", pub, err)
	}
	_, err = store.CreatePublication(ctx, persistence.CreatePublicationParams{
		ProposalID: prop.ID,
		BranchRef:  domain.ExpectedBranchName(prop.ID),
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate publication for proposal, got %v", err)
	}

	ensured, err := store.EnsurePublication(ctx, persistence.CreatePublicationParams{
		ProposalID: prop.ID,
	})
	if err != nil || ensured.ID != pub.ID {
		t.Fatalf("EnsurePublication: got (%+v, %v)", ensured, err)
	}

	manifestDigest := domain.SHA256Hex([]byte("pub-manifest"))
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Attempt 1 fails
	var att1 persistence.PublicationAttemptRow
	err = store.WithTx(ctx, func(tx *persistence.Tx) error {
		var txErr error
		pub, att1, txErr = tx.BeginPublicationAttempt(ctx, persistence.BeginPublicationAttemptParams{
			PublicationID:  pub.ID,
			ManifestDigest: manifestDigest,
			Now:            now,
		})
		return txErr
	})
	if err != nil || pub.Status != domain.PublicationStatusPublishing || pub.AttemptCount != 1 || att1.AttemptNumber != 1 || att1.Status != "STARTED" {
		t.Fatalf("BeginPublicationAttempt 1: got (%+v, %+v, %v)", pub, att1, err)
	}

	// Duplicate attempt number -> ErrConflict
	_, err = store.CreatePublicationAttempt(ctx, persistence.CreatePublicationAttemptParams{
		PublicationID:  pub.ID,
		AttemptNumber:  1,
		ManifestDigest: manifestDigest,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate attempt_number, got %v", err)
	}

	failedAtt, err := store.CompletePublicationAttemptFailed(ctx, att1.ID, "GITHUB_502", "upstream gateway error", now.Add(time.Second))
	if err != nil || failedAtt.Status != "FAILED" || *failedAtt.ErrorCode != "GITHUB_502" {
		t.Fatalf("CompletePublicationAttemptFailed: got (%+v, %v)", failedAtt, err)
	}
	failedPub, err := store.MarkPublicationFailed(ctx, pub.ID, now.Add(time.Second))
	if err != nil || failedPub.Status != domain.PublicationStatusFailed {
		t.Fatalf("MarkPublicationFailed: got (%+v, %v)", failedPub, err)
	}

	// Attempt 2 succeeds
	var att2 persistence.PublicationAttemptRow
	err = store.WithTx(ctx, func(tx *persistence.Tx) error {
		var txErr error
		pub, att2, txErr = tx.BeginPublicationAttempt(ctx, persistence.BeginPublicationAttemptParams{
			PublicationID:  pub.ID,
			ManifestDigest: manifestDigest,
			Now:            now.Add(5 * time.Second),
		})
		return txErr
	})
	if err != nil || pub.AttemptCount != 2 || att2.AttemptNumber != 2 {
		t.Fatalf("BeginPublicationAttempt 2: got (%+v, %+v, %v)", pub, att2, err)
	}

	commitSHA := "fedcba9876543210fedcba9876543210fedcba98"
	prNum := int64(101)
	prURL := "https://github.com/custodian-org/widget/pull/101"
	succAtt, err := store.CompletePublicationAttemptSucceeded(ctx, att2.ID, commitSHA, now.Add(6*time.Second))
	if err != nil || succAtt.Status != "SUCCEEDED" || *succAtt.CommitSHA != commitSHA {
		t.Fatalf("CompletePublicationAttemptSucceeded: got (%+v, %v)", succAtt, err)
	}
	published, err := store.MarkPublicationPublished(ctx, persistence.MarkPublicationPublishedParams{
		ID:                pub.ID,
		CommitSHA:         commitSHA,
		PullRequestNumber: &prNum,
		PullRequestURL:    prURL,
		UpdatedAt:         now.Add(6 * time.Second),
	})
	if err != nil || published.Status != domain.PublicationStatusPublished || *published.CommitSHA != commitSHA || *published.PullRequestNumber != 101 {
		t.Fatalf("MarkPublicationPublished: got (%+v, %v)", published, err)
	}

	// Cannot transition PUBLISHED back to PUBLISHING -> ErrConflict
	_, err = store.TransitionPublicationToPublishing(ctx, pub.ID, now.Add(7*time.Second))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict transitioning PUBLISHED -> PUBLISHING, got %v", err)
	}

	attempts, err := store.ListPublicationAttemptsByPublication(ctx, pub.ID)
	if err != nil || len(attempts) != 2 || attempts[0].AttemptNumber != 1 || attempts[1].AttemptNumber != 2 {
		t.Fatalf("ListPublicationAttemptsByPublication: got (%+v, %v)", attempts, err)
	}
}
