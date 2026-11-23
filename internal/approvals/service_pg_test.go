package approvals_test

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
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

type approvalPGFixture struct {
	store      *persistence.Store
	svc        *approvals.Service
	auditSvc   *audit.Service
	owner      persistence.PrincipalRow
	reviewer1  persistence.PrincipalRow
	reviewer2  persistence.PrincipalRow
	ipReviewer persistence.PrincipalRow
	outsider   persistence.PrincipalRow
	agent      persistence.PrincipalRow
	bundle     persistence.PolicyBundleRow
	ws         persistence.WorkspaceRow
	snapArt    persistence.ArtifactRow
	manifest   string
}

func setupApprovalPGFixture(t *testing.T) approvalPGFixture {
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
	svc := approvals.NewService(store, metrics, logger)
	auditSvc := audit.NewService(store, logger)

	ctx := context.Background()
	owner, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "owner",
		DisplayName: "Owner", VerifiedEmail: "owner@example.com", Groups: []string{"security-team", "ip-review"},
	})
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	reviewer1, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "rev1",
		DisplayName: "Rev One", VerifiedEmail: "rev1@example.com", Groups: []string{"security-team"},
	})
	if err != nil {
		t.Fatalf("reviewer1: %v", err)
	}
	reviewer2, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "rev2",
		DisplayName: "Rev Two", VerifiedEmail: "rev2@example.com", Groups: []string{"security-team"},
	})
	if err != nil {
		t.Fatalf("reviewer2: %v", err)
	}
	ipReviewer, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "iprev",
		DisplayName: "IP Rev", VerifiedEmail: "ip@example.com", Groups: []string{"ip-review"},
	})
	if err != nil {
		t.Fatalf("ipReviewer: %v", err)
	}
	outsider, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindHuman, Issuer: "https://oidc.example", Subject: "outsider",
		DisplayName: "Outsider", VerifiedEmail: "outsider@example.com", Groups: []string{"engineering"},
	})
	if err != nil {
		t.Fatalf("outsider: %v", err)
	}
	agent, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind: domain.PrincipalKindAgent, Issuer: "https://oidc.example", Subject: "agent",
		DisplayName: "Agent",
	})
	if err != nil {
		t.Fatalf("agent: %v", err)
	}

	repo, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID: 77001, GitHubInstallationID: 88001, FullName: "custodian-org/app",
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
	snapArt, err := store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind: domain.ArtifactKindEgressSnapshot, SHA256: domain.SHA256Hex([]byte("snap")),
		StorageKey: "ws/snap.tar.gz", StorageGeneration: "1", SizeBytes: 128,
	})
	if err != nil {
		t.Fatalf("snapArt: %v", err)
	}
	bundle, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: "default", Version: "1.0.0", Scope: domain.PolicyScopeOrg,
		Digest: domain.SHA256Hex([]byte("bundle-v1")), Definition: json.RawMessage(`{"rules":[]}`),
	})
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}

	return approvalPGFixture{
		store: store, svc: svc, auditSvc: auditSvc,
		owner: owner, reviewer1: reviewer1, reviewer2: reviewer2, ipReviewer: ipReviewer,
		outsider: outsider, agent: agent, bundle: bundle, ws: ws, snapArt: snapArt,
		manifest: domain.SHA256Hex([]byte("manifest-v1")),
	}
}

func seedPendingApprovalProposal(t *testing.T, fx approvalPGFixture, effect domain.PolicyEffect, obligations []domain.Obligation) (persistence.ProposalRow, persistence.PolicyDecisionRow) {
	t.Helper()
	ctx := context.Background()
	prop, err := fx.store.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID: fx.ws.ID, OwnerID: fx.owner.ID, SnapshotArtifactID: fx.snapArt.ID,
		BaseCommit: fx.ws.BaseCommit, TargetRef: fx.ws.TargetRef, Title: "Approval test",
	})
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	canonArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind: domain.ArtifactKindCanonicalTree, SHA256: domain.SHA256Hex([]byte("tree-" + prop.ID.String())),
		StorageKey: "prop/" + prop.ID.String() + "/tree", StorageGeneration: "1", SizeBytes: 100,
	})
	if err != nil {
		t.Fatalf("canonArt: %v", err)
	}
	manArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind: domain.ArtifactKindPublicationManifest, SHA256: fx.manifest,
		StorageKey: "prop/" + prop.ID.String() + "/manifest", StorageGeneration: "1", SizeBytes: 100,
	})
	if err != nil {
		t.Fatalf("manArt: %v", err)
	}
	prop, err = fx.store.SetProposalReconstruction(ctx, persistence.SetProposalReconstructionParams{
		ID: prop.ID, CanonicalArtifactID: canonArt.ID, ManifestArtifactID: manArt.ID,
		TreeDigest: strings.Repeat("c", 40), DiffDigest: domain.SHA256Hex([]byte("diff")),
		ManifestDigest: fx.manifest, Status: domain.ProposalStatusReconstructed, ExpectedVersion: prop.Version,
	})
	if err != nil {
		t.Fatalf("SetProposalReconstruction: %v", err)
	}
	pd, err := fx.store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID: prop.ID, PolicyBundleID: fx.bundle.ID,
		InputDigest: domain.SHA256Hex([]byte("input")), Effect: effect, Obligations: obligations,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision: %v", err)
	}
	for _, ob := range obligations {
		if _, err := fx.store.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
			ProposalID: prop.ID, PolicyDecisionID: pd.ID,
			RequirementType: ob.Type, ReviewerGroup: ob.ReviewerGroup, MinimumApprovals: ob.Minimum,
		}); err != nil {
			t.Fatalf("CreateApprovalRequirement: %v", err)
		}
	}
	prop, err = fx.store.ApplyProposalPolicyDecision(ctx, persistence.ApplyProposalPolicyDecisionParams{
		ID: prop.ID, PolicyEvaluationID: pd.ID, PolicyEffect: effect,
		Status: domain.ProposalStatusPendingApproval, ExpectedVersion: prop.Version,
	})
	if err != nil {
		t.Fatalf("ApplyProposalPolicyDecision: %v", err)
	}
	return prop, pd
}

func TestApprovalsLifecycleObligationsRejectAndStalenessPG17(t *testing.T) {
	fx := setupApprovalPGFixture(t)
	ctx := context.Background()

	// 1. ALLOW policy (0 requirements): blocked until non-owner human approves, then APPROVED + audit chain verified.
	propAllow, pdAllow := seedPendingApprovalProposal(t, fx, domain.PolicyEffectAllow, nil)
	if err := approvals.VerifyReadyForPublishTx(ctx, fx.store, propAllow); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected VerifyReadyForPublishTx to fail before human approval, got %v", err)
	}
	// SoD check & agent check
	if _, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propAllow.ID, ReviewerID: fx.owner.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdAllow.ID,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected SoD 403, got %v", err)
	}
	if _, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propAllow.ID, ReviewerID: fx.agent.ID,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdAllow.ID,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected agent 403, got %v", err)
	}

	resAllow, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propAllow.ID, ReviewerID: fx.outsider.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: "sha256:" + strings.ToUpper(fx.manifest),
		PolicyEvaluationID: pdAllow.ID, Comment: "LGTM",
	})
	if err != nil {
		t.Fatalf("approve ALLOW proposal: %v", err)
	}
	if resAllow.ProposalStatus != domain.ProposalStatusApproved || len(resAllow.RemainingObligations) != 0 {
		t.Fatalf("unexpected ALLOW approve result: %+v", resAllow)
	}
	updatedAllow, err := fx.store.GetProposalByID(ctx, propAllow.ID)
	if err != nil {
		t.Fatalf("GetProposalByID: %v", err)
	}
	if err := approvals.VerifyReadyForPublishTx(ctx, fx.store, updatedAllow); err != nil {
		t.Fatalf("VerifyReadyForPublishTx after approval: %v", err)
	}

	// 2. Multi-group obligations (security-team: 2, ip-review: 1):
	propMulti, pdMulti := seedPendingApprovalProposal(t, fx, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
		{Type: "IP_REVIEW", ReviewerGroup: "ip-review", Minimum: 1},
	})
	// Wrong group -> 403 Forbidden and 0 rows created.
	if _, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propMulti.ID, ReviewerID: fx.outsider.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdMulti.ID,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected 403 for wrong group, got %v", err)
	}
	if list, err := fx.svc.ListByProposal(ctx, propMulti.ID); err != nil || len(list) != 0 {
		t.Fatalf("expected 0 approvals after 403, got (%+v, %v)", list, err)
	}

	// 1st security-team approval -> PENDING_APPROVAL, remaining=[security-team:1, ip-review:1]
	r1, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propMulti.ID, ReviewerID: fx.reviewer1.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdMulti.ID,
	})
	if err != nil {
		t.Fatalf("1st security approval: %v", err)
	}
	if r1.ProposalStatus != domain.ProposalStatusPendingApproval || len(r1.RemainingObligations) != 2 {
		t.Fatalf("expected PENDING_APPROVAL + 2 obligations, got %+v", r1)
	}
	// Same reviewer duplicate APPROVE -> 409 Conflict
	if _, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propMulti.ID, ReviewerID: fx.reviewer1.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdMulti.ID,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected 409 duplicate approve, got %v", err)
	}
	// ip-review approval -> PENDING_APPROVAL, remaining=[security-team:1]
	r2, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propMulti.ID, ReviewerID: fx.ipReviewer.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdMulti.ID,
	})
	if err != nil {
		t.Fatalf("ip-review approval: %v", err)
	}
	if r2.ProposalStatus != domain.ProposalStatusPendingApproval || len(r2.RemainingObligations) != 1 || r2.RemainingObligations[0].Minimum != 1 {
		t.Fatalf("expected [security-team:1], got %+v", r2)
	}
	// 2nd security-team approval -> APPROVED, remaining=[]
	r3, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propMulti.ID, ReviewerID: fx.reviewer2.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdMulti.ID,
	})
	if err != nil {
		t.Fatalf("2nd security approval: %v", err)
	}
	if r3.ProposalStatus != domain.ProposalStatusApproved || len(r3.RemainingObligations) != 0 {
		t.Fatalf("expected APPROVED, got %+v", r3)
	}

	// 3. REJECT revokes prior active approvals, resets requirements, and keeps new REJECT unrevoked.
	propRej, pdRej := seedPendingApprovalProposal(t, fx, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
	})
	if _, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propRej.ID, ReviewerID: fx.reviewer1.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdRej.ID,
	}); err != nil {
		t.Fatalf("pre-reject approve: %v", err)
	}
	rejRes, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propRej.ID, ReviewerID: fx.reviewer2.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionReject, ManifestDigest: fx.manifest, PolicyEvaluationID: pdRej.ID, Comment: "Unsafe change",
	})
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejRes.ProposalStatus != domain.ProposalStatusRejected || len(rejRes.RemainingObligations) != 0 {
		t.Fatalf("unexpected reject result: %+v", rejRes)
	}
	rejApprovals, err := fx.svc.ListByProposal(ctx, propRej.ID)
	if err != nil || len(rejApprovals) != 2 {
		t.Fatalf("ListByProposal(propRej): (%+v, %v)", rejApprovals, err)
	}
	for _, a := range rejApprovals {
		if a.Decision == domain.ApprovalDecisionApprove && a.RevokedAt == nil {
			t.Fatalf("expected prior APPROVE to be revoked on REJECT")
		}
		if a.Decision == domain.ApprovalDecisionReject && a.RevokedAt != nil {
			t.Fatalf("expected new REJECT row to remain unrevoked")
		}
	}
	reqsRej, err := fx.svc.ListRequirements(ctx, propRej.ID)
	if err != nil || len(reqsRej) != 1 || reqsRej[0].SatisfiedCount != 0 || reqsRej[0].SatisfiedAt != nil {
		t.Fatalf("expected reset requirements after REJECT, got (%+v, %v)", reqsRej, err)
	}

	// 4. RevokeStaleApprovals revokes active approvals and resets requirements.
	propStale, pdStale := seedPendingApprovalProposal(t, fx, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
	})
	if _, err := fx.svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propStale.ID, ReviewerID: fx.reviewer1.ID, ReviewerKind: domain.PrincipalKindHuman,
		Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdStale.ID,
	}); err != nil {
		t.Fatalf("approve before stale revoke: %v", err)
	}
	revoked, err := fx.svc.RevokeStaleApprovals(ctx, propStale.ID, &pdStale.ID, "re-evaluation")
	if err != nil || revoked != 1 {
		t.Fatalf("RevokeStaleApprovals: (%d, %v), want 1", revoked, err)
	}
	reqsStale, err := fx.svc.ListRequirements(ctx, propStale.ID)
	if err != nil || len(reqsStale) != 1 || reqsStale[0].SatisfiedCount != 0 {
		t.Fatalf("expected reset requirement after RevokeStaleApprovals, got (%+v, %v)", reqsStale, err)
	}

	// Verify audit chain and payload fields (manifest_digest & policy_decision_id).
	verifyRes, err := fx.auditSvc.VerifyChain(ctx)
	if err != nil || verifyRes.EventCount == 0 {
		t.Fatalf("VerifyChain: (%+v, %v)", verifyRes, err)
	}
	events, err := fx.auditSvc.List(ctx, audit.ListFilter{ResourceType: "proposal", ResourceID: &propAllow.ID, Limit: 10})
	if err != nil || len(events.Events) != 1 {
		t.Fatalf("List audit events for propAllow: (%+v, %v)", events, err)
	}
	ev := events.Events[0]
	if !strings.Contains(ev.EventType, "approv") || !strings.Contains(string(ev.Payload), fx.manifest) || !strings.Contains(string(ev.Payload), pdAllow.ID.String()) {
		t.Fatalf("audit event missing expected approval binding: %+v", ev)
	}
}

func TestApprovalsConcurrentRacesPG17(t *testing.T) {
	fx := setupApprovalPGFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Race A: Two distinct reviewers concurrently APPROVE minimum=2 -> BOTH succeed, proposal becomes APPROVED.
	prop2, pd2 := seedPendingApprovalProposal(t, fx, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
	})
	startA := make(chan struct{})
	var wgA sync.WaitGroup
	errsA := make([]error, 2)
	reviewers := []uuid.UUID{fx.reviewer1.ID, fx.reviewer2.ID}
	for i := 0; i < 2; i++ {
		wgA.Add(1)
		go func(idx int) {
			defer wgA.Done()
			<-startA
			_, errsA[idx] = fx.svc.Submit(ctx, approvals.SubmitInput{
				ProposalID: prop2.ID, ReviewerID: reviewers[idx], ReviewerKind: domain.PrincipalKindHuman,
				Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pd2.ID,
			})
		}(i)
	}
	close(startA)
	wgA.Wait()
	for i, err := range errsA {
		if err != nil {
			t.Fatalf("concurrent distinct reviewer[%d] failed: %v", i, err)
		}
	}
	final2, err := fx.store.GetProposalByID(ctx, prop2.ID)
	if err != nil || final2.Status != domain.ProposalStatusApproved {
		t.Fatalf("expected prop2 APPROVED after concurrent approvals, got (%+v, %v)", final2, err)
	}
	reqs2, err := fx.svc.ListRequirements(ctx, prop2.ID)
	if err != nil || len(reqs2) != 1 || reqs2[0].SatisfiedCount != 2 || reqs2[0].SatisfiedAt == nil {
		t.Fatalf("expected satisfied_count == 2, got (%+v, %v)", reqs2, err)
	}

	// Race B: Same reviewer concurrently submits 2 APPROVEs -> exactly 1 succeeds, 1 returns 409 Conflict.
	propDup, pdDup := seedPendingApprovalProposal(t, fx, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
	})
	startB := make(chan struct{})
	var wgB sync.WaitGroup
	errsB := make([]error, 2)
	for i := 0; i < 2; i++ {
		wgB.Add(1)
		go func(idx int) {
			defer wgB.Done()
			<-startB
			_, errsB[idx] = fx.svc.Submit(ctx, approvals.SubmitInput{
				ProposalID: propDup.ID, ReviewerID: fx.reviewer1.ID, ReviewerKind: domain.PrincipalKindHuman,
				Decision: domain.ApprovalDecisionApprove, ManifestDigest: fx.manifest, PolicyEvaluationID: pdDup.ID,
			})
		}(i)
	}
	close(startB)
	wgB.Wait()
	okB, conflictB := 0, 0
	for _, err := range errsB {
		if err == nil {
			okB++
		} else if errors.Is(err, domain.ErrConflict) {
			conflictB++
		} else {
			t.Fatalf("unexpected error in same-reviewer race: %v", err)
		}
	}
	if okB != 1 || conflictB != 1 {
		t.Fatalf("expected 1 ok and 1 conflict in duplicate race, got ok=%d conflict=%d", okB, conflictB)
	}

	// Race C: APPROVE (minimum=1) vs REJECT -> 1 wins (APPROVED or REJECTED), loser returns 409 Conflict.
	propRace, pdRace := seedPendingApprovalProposal(t, fx, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 1},
	})
	startC := make(chan struct{})
	var wgC sync.WaitGroup
	errsC := make([]error, 2)
	decisionsC := []domain.ApprovalDecision{domain.ApprovalDecisionApprove, domain.ApprovalDecisionReject}
	for i := 0; i < 2; i++ {
		wgC.Add(1)
		go func(idx int) {
			defer wgC.Done()
			<-startC
			_, errsC[idx] = fx.svc.Submit(ctx, approvals.SubmitInput{
				ProposalID: propRace.ID, ReviewerID: reviewers[idx], ReviewerKind: domain.PrincipalKindHuman,
				Decision: decisionsC[idx], ManifestDigest: fx.manifest, PolicyEvaluationID: pdRace.ID,
			})
		}(i)
	}
	close(startC)
	wgC.Wait()
	okC, conflictC := 0, 0
	for _, err := range errsC {
		if err == nil {
			okC++
		} else if errors.Is(err, domain.ErrConflict) {
			conflictC++
		} else {
			t.Fatalf("unexpected error in APPROVE vs REJECT race: %v", err)
		}
	}
	if okC != 1 || conflictC != 1 {
		t.Fatalf("expected 1 ok and 1 conflict in APPROVE vs REJECT race, got ok=%d conflict=%d", okC, conflictC)
	}

	if _, err := fx.auditSvc.VerifyChain(ctx); err != nil {
		t.Fatalf("VerifyChain after concurrent races: %v", err)
	}
}
