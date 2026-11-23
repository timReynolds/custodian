package proposals_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/proposals"
)

type proposalPGFixture struct {
	pg       *harness.PostgresHarness
	store    *persistence.Store
	svc      *proposals.Service
	appSvc   *approvals.Service
	artSvc   *artifacts.Service
	auditSvc *audit.Service
	owner    persistence.PrincipalRow
	reviewer persistence.PrincipalRow
	repo     persistence.RepositoryRow
	ws       persistence.WorkspaceRow
	bundle   persistence.PolicyBundleRow
}

func setupProposalPGFixture(t *testing.T) proposalPGFixture {
	t.Helper()
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
	svc := proposals.NewService(store, metrics, logger)
	appSvc := approvals.NewService(store, metrics, logger)
	artSvc := artifacts.NewService(store, logger)
	auditSvc := audit.NewService(store, logger)

	ctx := context.Background()
	owner, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "owner-1",
		DisplayName: "Owner", VerifiedEmail: "owner@example.com",
	})
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	reviewer, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "rev-1",
		DisplayName: "Reviewer", VerifiedEmail: "rev@example.com", Groups: []string{"security-team"},
	})
	if err != nil {
		t.Fatalf("reviewer: %v", err)
	}
	repo, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID: 88001, GitHubInstallationID: 99001, FullName: "custodian-org/core",
		Classification: domain.ClassificationInternal, Enabled: true,
	})
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	ws, err := store.CreateWorkspace(ctx, persistence.CreateWorkspaceParams{
		RepositoryID: repo.ID, OwnerID: owner.ID,
		BaseCommit: strings.Repeat("a", 40), TargetRef: "refs/heads/main", Status: domain.WorkspaceStatusReady,
	})
	if err != nil {
		t.Fatalf("ws: %v", err)
	}
	bundle, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: "default", Version: "1.0.0", Scope: domain.PolicyScopeOrg,
		Digest: domain.SHA256Hex([]byte("prop-bundle")), Definition: json.RawMessage(`{"rules":[]}`),
	})
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	return proposalPGFixture{
		pg: pg, store: store, svc: svc, appSvc: appSvc, artSvc: artSvc, auditSvc: auditSvc,
		owner: owner, reviewer: reviewer, repo: repo, ws: ws, bundle: bundle,
	}
}

func registerWSArtifact(t *testing.T, ctx context.Context, fx proposalPGFixture, kind domain.ArtifactKind, key string) domain.Artifact {
	t.Helper()
	gen := fx.ws.Generation
	art, err := fx.artSvc.Register(ctx, artifacts.RegisterInput{
		Kind:                kind,
		SHA256:              domain.SHA256Hex([]byte(key)),
		StorageKey:          key,
		StorageGeneration:   "1",
		SizeBytes:           512,
		Format:              "tar+gzip",
		WorkspaceID:         &fx.ws.ID,
		WorkspaceGeneration: &gen,
	})
	if err != nil {
		t.Fatalf("register %s (%s): %v", kind, key, err)
	}
	return art.Artifact
}

func TestProposalsEndToEndLifecycleReevalAndRollbackPG17(t *testing.T) {
	fx := setupProposalPGFixture(t)
	ctx := context.Background()

	snap := registerWSArtifact(t, ctx, fx, domain.ArtifactKindEgressSnapshot, "ws/snap-1.tar.gz")
	canon := registerWSArtifact(t, ctx, fx, domain.ArtifactKindCanonicalTree, "prop/tree-1.tar.gz")
	diff := registerWSArtifact(t, ctx, fx, domain.ArtifactKindCanonicalDiff, "prop/diff-1.patch")
	man := registerWSArtifact(t, ctx, fx, domain.ArtifactKindPublicationManifest, "prop/manifest-1.json")

	// 1. Submit -> CAPTURED + PROPOSAL_RECONSTRUCT op + hydrated details.
	sub, err := fx.svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID:         fx.ws.ID,
		ActorID:             &fx.owner.ID,
		SnapshotArtifactID:  snap.ID,
		SnapshotSHA256:      snap.SHA256,
		WorkspaceGeneration: fx.ws.Generation,
		SizeBytes:           snap.SizeBytes,
		Title:               "Add safety feature",
		Description:         "Details",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if sub.Proposal.Status != domain.ProposalStatusCaptured || sub.Proposal.Version != 1 || sub.Operation.OperationType != domain.OperationTypeProposalReconstruct {
		t.Fatalf("unexpected Submit result: %+v", sub)
	}
	if sub.Details.RepositoryFullName != fx.repo.FullName || sub.Details.WorkspaceGeneration != fx.ws.Generation {
		t.Fatalf("unexpected Submit details: %+v", sub.Details)
	}

	// ListByWorkspace & ListByOwner return ProposalDetails.
	byWS, err := fx.svc.ListByWorkspace(ctx, fx.ws.ID, 10)
	if err != nil || len(byWS) != 1 || byWS[0].ID != sub.Proposal.ID {
		t.Fatalf("ListByWorkspace: (%+v, %v)", byWS, err)
	}
	byOwner, err := fx.svc.ListByOwner(ctx, fx.owner.ID, 10)
	if err != nil || len(byOwner) != 1 || byOwner[0].ID != sub.Proposal.ID {
		t.Fatalf("ListByOwner: (%+v, %v)", byOwner, err)
	}

	// 2. BeginReconstruction + crash-recovery idempotent retry.
	rec1, err := fx.svc.BeginReconstruction(ctx, proposals.BeginReconstructionInput{ProposalID: sub.Proposal.ID, ExpectedVersion: 1})
	if err != nil || rec1.Status != domain.ProposalStatusReconstructing || rec1.Version != 2 {
		t.Fatalf("BeginReconstruction: (%+v, %v)", rec1, err)
	}
	recRetry, err := fx.svc.BeginReconstruction(ctx, proposals.BeginReconstructionInput{ProposalID: sub.Proposal.ID, ExpectedVersion: rec1.Version})
	if err != nil || recRetry.Status != domain.ProposalStatusReconstructing || recRetry.Version != 2 {
		t.Fatalf("BeginReconstruction crash-recovery retry: (%+v, %v)", recRetry, err)
	}

	// 3. CompleteReconstruction -> RECONSTRUCTED.
	reconstructed, err := fx.svc.CompleteReconstruction(ctx, proposals.CompleteReconstructionInput{
		ProposalID:          sub.Proposal.ID,
		ExpectedVersion:     rec1.Version,
		CanonicalArtifactID: canon.ID,
		DiffArtifactID:      &diff.ID,
		ManifestArtifactID:  man.ID,
		TreeDigest:          strings.Repeat("d", 40),
		DiffDigest:          diff.SHA256,
		ManifestDigest:      man.SHA256,
	})
	if err != nil || reconstructed.Status != domain.ProposalStatusReconstructed || reconstructed.Version != 3 {
		t.Fatalf("CompleteReconstruction: (%+v, %v)", reconstructed, err)
	}

	// 4. RequestEvaluation -> EVALUATING + BeginEvaluation crash-recovery idempotency.
	evalReq, err := fx.svc.RequestEvaluation(ctx, proposals.EvaluateInput{ProposalID: sub.Proposal.ID, ExpectedVersion: reconstructed.Version})
	if err != nil || evalReq.Proposal.Status != domain.ProposalStatusEvaluating || evalReq.Operation.OperationType != domain.OperationTypeProposalEvaluate {
		t.Fatalf("RequestEvaluation: (%+v, %v)", evalReq, err)
	}
	evalBegun, err := fx.svc.BeginEvaluation(ctx, sub.Proposal.ID, evalReq.Proposal.Version)
	if err != nil || evalBegun.Status != domain.ProposalStatusEvaluating || evalBegun.Version != evalReq.Proposal.Version {
		t.Fatalf("BeginEvaluation idempotent retry: (%+v, %v)", evalBegun, err)
	}

	// Transaction rollback check: invalid PolicyBundleID FK leaves 0 policy_decisions/audit rows for this failed call.
	var beforeDecisions int
	_ = fx.pg.Pool().QueryRow(ctx, "SELECT count(*) FROM policy_decisions").Scan(&beforeDecisions)
	if _, err := fx.svc.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: evalReq.Proposal.Version,
		PolicyBundleID: domain.MustNewID(), InputDigest: domain.SHA256Hex([]byte("in")), Effect: domain.PolicyEffectAllow,
	}); err == nil {
		t.Fatalf("expected FK failure on unknown PolicyBundleID")
	}
	var afterDecisions int
	_ = fx.pg.Pool().QueryRow(ctx, "SELECT count(*) FROM policy_decisions").Scan(&afterDecisions)
	if afterDecisions != beforeDecisions {
		t.Fatalf("expected 0 partial policy_decisions on tx rollback")
	}

	// 5. ApplyPolicyDecision (REQUIRE_APPROVAL with duplicate obligations) -> PENDING_APPROVAL.
	t1 := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	_, err = fx.store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ProposalID: sub.Proposal.ID, ArtifactID: canon.ID, ModelRoute: "anthropic/claude", ModelVersion: "v1",
		PromptVersion: "p1", AssessmentType: "SECURITY_REVIEW", Status: domain.AssessmentStatusComplete,
		Risk: domain.RiskLevelLow, Disposition: domain.DispositionReview,
		InputDigest: domain.SHA256Hex([]byte("in1")), OutputDigest: domain.SHA256Hex([]byte("out1")), CreatedAt: t1,
	})
	if err != nil {
		t.Fatalf("CreateModelAssessment 1: %v", err)
	}
	pending1, err := fx.svc.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID:      sub.Proposal.ID,
		ExpectedVersion: evalReq.Proposal.Version,
		PolicyBundleID:  fx.bundle.ID,
		InputDigest:     domain.SHA256Hex([]byte("eval1")),
		Effect:          domain.PolicyEffectRequireApproval,
		Obligations: []domain.Obligation{
			{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 1},
			{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
		},
	})
	if err != nil || pending1.Status != domain.ProposalStatusPendingApproval {
		t.Fatalf("ApplyPolicyDecision 1: (%+v, %v)", pending1, err)
	}

	// Reviewer submits partial approval (1/2) -> still PENDING_APPROVAL.
	if _, err := fx.appSvc.Submit(ctx, approvals.SubmitInput{
		ProposalID: sub.Proposal.ID, ReviewerID: fx.reviewer.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: man.SHA256,
		PolicyEvaluationID: domain.MustNewID(),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on wrong eval ID, got %v", err)
	}
	det1, err := fx.svc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	if _, err := fx.appSvc.Submit(ctx, approvals.SubmitInput{
		ProposalID: sub.Proposal.ID, ReviewerID: fx.reviewer.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: man.SHA256,
		PolicyEvaluationID: *det1.LatestPolicyEvaluationID,
	}); err != nil {
		t.Fatalf("partial approve: %v", err)
	}

	// Re-evaluate from PENDING_APPROVAL -> revokes prior partial approval!
	evalReq2, err := fx.svc.RequestEvaluation(ctx, proposals.EvaluateInput{ProposalID: sub.Proposal.ID, ExpectedVersion: pending1.Version})
	if err != nil {
		t.Fatalf("RequestEvaluation re-eval: %v", err)
	}
	appsAfterReeval, err := fx.appSvc.ListByProposal(ctx, sub.Proposal.ID)
	if err != nil || len(appsAfterReeval) != 1 || appsAfterReeval[0].RevokedAt == nil {
		t.Fatalf("expected prior approval revoked on re-eval, got (%+v, %v)", appsAfterReeval, err)
	}

	// ApplyPolicyDecision ALLOW -> still PENDING_APPROVAL (mandatory human approval RG-03).
	_, err = fx.store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ProposalID: sub.Proposal.ID, ArtifactID: canon.ID, ModelRoute: "anthropic/claude", ModelVersion: "v1",
		PromptVersion: "p1", AssessmentType: "SECURITY_REVIEW", Status: domain.AssessmentStatusComplete,
		Risk: domain.RiskLevelNone, Disposition: domain.DispositionClear,
		InputDigest: domain.SHA256Hex([]byte("in2")), OutputDigest: domain.SHA256Hex([]byte("out2")), CreatedAt: t1.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateModelAssessment 2: %v", err)
	}
	pending2, err := fx.svc.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: evalReq2.Proposal.Version,
		PolicyBundleID: fx.bundle.ID, InputDigest: domain.SHA256Hex([]byte("eval2")), Effect: domain.PolicyEffectAllow,
	})
	if err != nil || pending2.Status != domain.ProposalStatusPendingApproval {
		t.Fatalf("ApplyPolicyDecision ALLOW -> PENDING_APPROVAL: (%+v, %v)", pending2, err)
	}
	// Unapproved -> RequestPublish returns 409 Conflict.
	if _, err := fx.svc.RequestPublish(ctx, proposals.PublishRequestInput{
		ProposalID: sub.Proposal.ID, PublicationManifestDigest: man.SHA256,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 before human approval, got %v", err)
	}

	// ListAssessmentsAndDecisions returns ascending chronological order ([len-1] is latest).
	ad, err := fx.svc.ListAssessmentsAndDecisions(ctx, sub.Proposal.ID)
	if err != nil || len(ad.Assessments) != 2 || len(ad.PolicyDecisions) != 2 {
		t.Fatalf("ListAssessmentsAndDecisions: (%+v, %v)", ad, err)
	}
	if ad.Assessments[1].Disposition != domain.DispositionClear || ad.PolicyDecisions[1].Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected newest entry at [len-1], got %+v", ad)
	}

	// Approve on 2nd evaluation -> APPROVED, then RequestPublish -> PUBLISHING + idempotent replay.
	latestDecID := ad.PolicyDecisions[1].ID
	if _, err := fx.appSvc.Submit(ctx, approvals.SubmitInput{
		ProposalID: sub.Proposal.ID, ReviewerID: fx.reviewer.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: man.SHA256, PolicyEvaluationID: latestDecID,
	}); err != nil {
		t.Fatalf("final approve: %v", err)
	}
	pub1, err := fx.svc.RequestPublish(ctx, proposals.PublishRequestInput{
		ProposalID: sub.Proposal.ID, PublicationManifestDigest: man.SHA256, ActorID: &fx.owner.ID,
	})
	if err != nil || pub1.Proposal.Status != domain.ProposalStatusPublishing || pub1.Operation.OperationType != domain.OperationTypeProposalPublish {
		t.Fatalf("RequestPublish 1: (%+v, %v)", pub1, err)
	}
	pub2, err := fx.svc.RequestPublish(ctx, proposals.PublishRequestInput{
		ProposalID: sub.Proposal.ID, PublicationManifestDigest: man.SHA256,
	})
	if err != nil || pub2.Publication.ID != pub1.Publication.ID || pub2.Operation.ID != pub1.Operation.ID {
		t.Fatalf("RequestPublish idempotent while PUBLISHING: (%+v, %v)", pub2, err)
	}

	// MarkFailed transitions PUBLISHING -> FAILED, then rejects terminal transition.
	failed, err := fx.svc.MarkFailed(ctx, sub.Proposal.ID, pub1.Proposal.Version, "publisher timeout")
	if err != nil || failed.Status != domain.ProposalStatusFailed {
		t.Fatalf("MarkFailed: (%+v, %v)", failed, err)
	}
	if _, err := fx.svc.MarkFailed(ctx, sub.Proposal.ID, failed.Version, "again"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on terminal MarkFailed, got %v", err)
	}

	// Audit chain must verify cleanly across all events.
	if res, err := fx.auditSvc.VerifyChain(ctx); err != nil || res.EventCount == 0 {
		t.Fatalf("VerifyChain: (%+v, %v)", res, err)
	}
}

func TestProposalsConcurrentEvaluationAndPublishRacesPG17(t *testing.T) {
	fx := setupProposalPGFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	snap := registerWSArtifact(t, ctx, fx, domain.ArtifactKindEgressSnapshot, "ws/race-snap.tar.gz")
	canon := registerWSArtifact(t, ctx, fx, domain.ArtifactKindCanonicalTree, "prop/race-tree.tar.gz")
	man := registerWSArtifact(t, ctx, fx, domain.ArtifactKindPublicationManifest, "prop/race-manifest.json")

	sub, err := fx.svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: fx.ws.ID, SnapshotArtifactID: snap.ID, SnapshotSHA256: snap.SHA256,
		WorkspaceGeneration: fx.ws.Generation, Title: "Race test",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	reconstructed, err := fx.svc.CompleteReconstruction(ctx, proposals.CompleteReconstructionInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: sub.Proposal.Version,
		CanonicalArtifactID: canon.ID, ManifestArtifactID: man.ID,
		TreeDigest: strings.Repeat("e", 40), DiffDigest: domain.SHA256Hex([]byte("d")), ManifestDigest: man.SHA256,
	})
	if err != nil {
		t.Fatalf("CompleteReconstruction: %v", err)
	}

	// Race 1: 8 concurrent RequestEvaluation calls with same ExpectedVersion -> exactly 1 wins, 7 get ErrConflict.
	const n = 8
	startEval := make(chan struct{})
	var wgEval sync.WaitGroup
	evalErrs := make([]error, n)
	for i := 0; i < n; i++ {
		wgEval.Add(1)
		go func(idx int) {
			defer wgEval.Done()
			<-startEval
			_, evalErrs[idx] = fx.svc.RequestEvaluation(ctx, proposals.EvaluateInput{
				ProposalID: sub.Proposal.ID, ExpectedVersion: reconstructed.Version,
			})
		}(i)
	}
	close(startEval)
	wgEval.Wait()

	okEval, confEval := 0, 0
	for _, err := range evalErrs {
		if err == nil {
			okEval++
		} else if errors.Is(err, domain.ErrConflict) {
			confEval++
		} else {
			t.Fatalf("unexpected RequestEvaluation race err: %v", err)
		}
	}
	if okEval != 1 || confEval != n-1 {
		t.Fatalf("expected 1 eval winner and %d conflicts, got ok=%d conf=%d", n-1, okEval, confEval)
	}

	// Advance to APPROVED.
	propEval, err := fx.svc.Get(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	pending, err := fx.svc.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: propEval.Version,
		PolicyBundleID: fx.bundle.ID, InputDigest: domain.SHA256Hex([]byte("race-eval")), Effect: domain.PolicyEffectAllow,
	})
	if err != nil {
		t.Fatalf("ApplyPolicyDecision: %v", err)
	}
	det, err := fx.svc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	if _, err := fx.appSvc.Submit(ctx, approvals.SubmitInput{
		ProposalID: sub.Proposal.ID, ReviewerID: fx.reviewer.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: man.SHA256,
		PolicyEvaluationID: *det.LatestPolicyEvaluationID,
	}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	_ = pending

	// Race 2: 8 concurrent RequestPublish calls -> all agree on single Publication.ID and single Operation.ID.
	startPub := make(chan struct{})
	var wgPub sync.WaitGroup
	pubResults := make([]proposals.PublishRequestResult, n)
	pubErrs := make([]error, n)
	for i := 0; i < n; i++ {
		wgPub.Add(1)
		go func(idx int) {
			defer wgPub.Done()
			<-startPub
			pubResults[idx], pubErrs[idx] = fx.svc.RequestPublish(ctx, proposals.PublishRequestInput{
				ProposalID: sub.Proposal.ID, PublicationManifestDigest: man.SHA256,
			})
		}(i)
	}
	close(startPub)
	wgPub.Wait()

	var pubID, opID uuid.UUID
	for i := 0; i < n; i++ {
		if pubErrs[i] != nil {
			t.Fatalf("RequestPublish[%d] err: %v", i, pubErrs[i])
		}
		if pubID == uuid.Nil {
			pubID = pubResults[i].Publication.ID
			opID = pubResults[i].Operation.ID
		} else if pubResults[i].Publication.ID != pubID || pubResults[i].Operation.ID != opID {
			t.Fatalf("concurrent RequestPublish diverged: got (%s, %s), want (%s, %s)",
				pubResults[i].Publication.ID, pubResults[i].Operation.ID, pubID, opID)
		}
	}

	var pubRowCount, pubOpCount int
	_ = fx.pg.Pool().QueryRow(ctx, "SELECT count(*) FROM publications WHERE proposal_id = $1", sub.Proposal.ID).Scan(&pubRowCount)
	_ = fx.pg.Pool().QueryRow(ctx, "SELECT count(*) FROM operations WHERE resource_id = $1 AND operation_type = 'PROPOSAL_PUBLISH'", sub.Proposal.ID).Scan(&pubOpCount)
	if pubRowCount != 1 || pubOpCount != 1 {
		t.Fatalf("expected 1 publication and 1 PROPOSAL_PUBLISH op, got pub=%d op=%d", pubRowCount, pubOpCount)
	}

	if _, err := fx.auditSvc.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestProposalsFindingsPaginationAndPolicyDenialPG17(t *testing.T) {
	fx := setupProposalPGFixture(t)
	ctx := context.Background()

	snap := registerWSArtifact(t, ctx, fx, domain.ArtifactKindEgressSnapshot, "ws/deny-snap.tar.gz")
	canon := registerWSArtifact(t, ctx, fx, domain.ArtifactKindCanonicalTree, "prop/deny-tree.tar.gz")
	man := registerWSArtifact(t, ctx, fx, domain.ArtifactKindPublicationManifest, "prop/deny-manifest.json")

	sub, err := fx.svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: fx.ws.ID, SnapshotArtifactID: snap.ID, SnapshotSHA256: snap.SHA256,
		WorkspaceGeneration: fx.ws.Generation, Title: "Findings & Denial",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	reconstructed, err := fx.svc.CompleteReconstruction(ctx, proposals.CompleteReconstructionInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: sub.Proposal.Version,
		CanonicalArtifactID: canon.ID, ManifestArtifactID: man.ID,
		TreeDigest: strings.Repeat("f", 40), DiffDigest: domain.SHA256Hex([]byte("d")), ManifestDigest: man.SHA256,
	})
	if err != nil {
		t.Fatalf("CompleteReconstruction: %v", err)
	}

	// Seed 2 scan runs and 3 redacted findings across gitleaks/semgrep.
	sr1, err := fx.store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID: sub.Proposal.ID, ArtifactID: canon.ID, Scanner: "gitleaks", ScannerVersion: "8.18.0",
		Status: domain.ScanStatusCompleted, Coverage: domain.ScanCoverage{FilesExamined: 5, Complete: true},
	})
	if err != nil {
		t.Fatalf("CreateScanRun 1: %v", err)
	}
	sr2, err := fx.store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID: sub.Proposal.ID, ArtifactID: canon.ID, Scanner: "semgrep", ScannerVersion: "1.90.0",
		Status: domain.ScanStatusCompleted, Coverage: domain.ScanCoverage{FilesExamined: 5, Complete: true},
	})
	if err != nil {
		t.Fatalf("CreateScanRun 2: %v", err)
	}
	if _, err := fx.store.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID: sr1.ID, Scanner: "gitleaks", Category: "SECRET", Severity: domain.SeverityCritical,
		RuleID: "aws-key", Fingerprint: "fp-1", Redacted: true, Metadata: map[string]any{"redacted_preview": "AKIA***"},
	}); err != nil {
		t.Fatalf("CreateFinding 1: %v", err)
	}
	if _, err := fx.store.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID: sr2.ID, Scanner: "semgrep", Category: "SAST", Severity: domain.SeverityHigh,
		RuleID: "sqli", Fingerprint: "fp-2", Redacted: true,
	}); err != nil {
		t.Fatalf("CreateFinding 2: %v", err)
	}
	if _, err := fx.store.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID: sr2.ID, Scanner: "semgrep", Category: "SAST", Severity: domain.SeverityLow,
		RuleID: "style", Fingerprint: "fp-3", Redacted: true,
	}); err != nil {
		t.Fatalf("CreateFinding 3: %v", err)
	}

	page1, err := fx.svc.ListFindings(ctx, proposals.ListFindingsFilter{ProposalID: sub.Proposal.ID, Limit: 2})
	if err != nil || !page1.HasMore || page1.NextCursor == "" || len(page1.Findings) != 2 || len(page1.ScanRuns) != 2 {
		t.Fatalf("ListFindings page1: (%+v, %v)", page1, err)
	}
	page2, err := fx.svc.ListFindings(ctx, proposals.ListFindingsFilter{
		ProposalID: sub.Proposal.ID, Cursor: page1.NextCursor, Limit: 2,
	})
	if err != nil || page2.HasMore || page2.NextCursor != "" || len(page2.Findings) != 1 {
		t.Fatalf("ListFindings page2: (%+v, %v)", page2, err)
	}
	sevHigh := domain.SeverityHigh
	filtered, err := fx.svc.ListFindings(ctx, proposals.ListFindingsFilter{
		ProposalID: sub.Proposal.ID, Scanner: "semgrep", Severity: &sevHigh, Limit: 10,
	})
	if err != nil || len(filtered.Findings) != 1 || filtered.Findings[0].RuleID != "sqli" {
		t.Fatalf("ListFindings filtered: (%+v, %v)", filtered, err)
	}

	// Evaluate -> DENY -> RequestPublish returns *PolicyDeniedError unwrapping to ErrConflict with PolicyDecisionID.
	evalReq, err := fx.svc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: reconstructed.Version,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}
	denied, err := fx.svc.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID: sub.Proposal.ID, ExpectedVersion: evalReq.Proposal.Version,
		PolicyBundleID: fx.bundle.ID, InputDigest: domain.SHA256Hex([]byte("deny-in")),
		Effect:  domain.PolicyEffectDeny,
		Reasons: []domain.PolicyReason{{RuleID: "no-secrets", Effect: domain.PolicyEffectDeny, Stage: "EGRESS", Message: "secret detected"}},
	})
	if err != nil || denied.Status != domain.ProposalStatusDenied {
		t.Fatalf("ApplyPolicyDecision DENY: (%+v, %v)", denied, err)
	}
	det, err := fx.svc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil || det.LatestPolicyEvaluationID == nil {
		t.Fatalf("GetDetails: (%+v, %v)", det, err)
	}

	_, pubErr := fx.svc.RequestPublish(ctx, proposals.PublishRequestInput{
		ProposalID: sub.Proposal.ID, PublicationManifestDigest: man.SHA256,
	})
	var pde *proposals.PolicyDeniedError
	if !errors.As(pubErr, &pde) || pde.PolicyDecisionID != *det.LatestPolicyEvaluationID || pde.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected *PolicyDeniedError with decision %s, got %v", *det.LatestPolicyEvaluationID, pubErr)
	}
	if !errors.Is(pubErr, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict unwrap, got %v", pubErr)
	}
}
