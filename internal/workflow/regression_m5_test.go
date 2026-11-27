package workflow_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/workflow"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func TestM5_EvaluateCrashRecoveryPreservesApprovedAndCanonicalTTL(t *testing.T) {
	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gwState := &mockGatewayState{}
	gwSrv := startMockGateway(t, gwState)
	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	decSvc, err := decisions.NewService(gwClient)
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}

	svc, runner := newTestWorkflowRunner(t, fx, nil, &stubInspector{}, decSvc, workflow.Config{
		WorkerID:             "worker-1",
		ArtifactRetentionTTL: 24 * time.Hour,
		LeaseDuration:        2 * time.Second,
	})

	wsSvc := workspaces.NewService(fx.store, nil, nil)
	wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID,
		OwnerID:      fx.owner.ID,
		BaseCommit:   fx.bareRepo.HeadSHA,
		TargetRef:    "main",
	})
	if err != nil {
		t.Fatalf("wsSvc.Create: %v", err)
	}
	if processed, err := runner.ProcessOnce(ctx); err != nil || processed != 1 {
		t.Fatalf("ProcessOnce ingress: (%d, %v)", processed, err)
	}

	snapBytes := buildTarGzBytes(t, map[string]string{"README.md": "# Updated\n", "main.go": "package main\nfunc main() {}\n"})
	snapSHA := domain.SHA256Hex(snapBytes)
	putSnap, err := fx.snaps.Store().Put(ctx, domain.PutRequest{
		Kind:        domain.ArtifactKindEgressSnapshot,
		ObjectKey:   "workspaces/" + wsRes.Workspace.ID.String() + "/snap.tar.gz",
		MaxBytes:    int64(len(snapBytes) + 1024),
		WorkspaceID: &wsRes.Workspace.ID,
		ContentType: "application/gzip",
	}, bytes.NewReader(snapBytes), int64(len(snapBytes)))
	if err != nil {
		t.Fatalf("SnapshotStore.Put: %v", err)
	}
	artSvc := artifacts.NewService(fx.store, nil)
	gen1 := int64(1)
	snapArt, err := artSvc.Register(ctx, artifacts.RegisterInput{
		ID:                  putSnap.ID,
		Kind:                domain.ArtifactKindEgressSnapshot,
		SHA256:              snapSHA,
		StorageKey:          putSnap.StorageKey,
		StorageGeneration:   putSnap.StorageGeneration,
		SizeBytes:           putSnap.SizeBytes,
		Format:              "application/gzip",
		WorkspaceID:         &wsRes.Workspace.ID,
		WorkspaceGeneration: &gen1,
	})
	if err != nil {
		t.Fatalf("artifacts.Register: %v", err)
	}

	propSvc := proposals.NewService(fx.store, nil, nil)
	subRes, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID:         wsRes.Workspace.ID,
		SnapshotArtifactID:  snapArt.ID,
		SnapshotSHA256:      snapSHA,
		WorkspaceGeneration: 1,
		SizeBytes:           putSnap.SizeBytes,
		Title:               "M5 crash recovery",
	})
	if err != nil {
		t.Fatalf("propSvc.Submit: %v", err)
	}
	if processed, err := runner.ProcessOnce(ctx); err != nil || processed != 1 {
		t.Fatalf("ProcessOnce reconstruct: (%d, %v)", processed, err)
	}

	// Verify P1-GAP-34d: canonical artifacts have non-nil ExpiresAt matching ArtifactRetentionTTL.
	reconstructed, err := propSvc.GetDetails(ctx, subRes.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	for _, artID := range []*uuid.UUID{reconstructed.CanonicalArtifactID, reconstructed.ManifestArtifactID, reconstructed.DiffArtifactID} {
		if artID == nil {
			continue
		}
		art, err := fx.store.GetArtifactByID(ctx, *artID)
		if err != nil {
			t.Fatalf("GetArtifactByID(%s): %v", *artID, err)
		}
		if art.ExpiresAt == nil {
			t.Fatalf("expected non-nil ExpiresAt on reconstructed artifact %s (kind=%s)", art.ID, art.Kind)
		}
	}

	evalReq, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID:      subRes.Proposal.ID,
		ExpectedVersion: reconstructed.Version,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}

	opsSvc := operations.NewService(fx.store, nil, nil, operations.Config{})
	opType := domain.OperationTypeProposalEvaluate
	claimed, err := opsSvc.Claim(ctx, operations.ClaimInput{
		WorkerID:      "crashed-worker",
		OperationType: &opType,
		Limit:         1,
		LeaseDuration: 2 * time.Second,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("Claim PROPOSAL_EVALUATE: (%d, %v)", len(claimed), err)
	}

	// Simulate worker-1 committing ExecuteEvaluate (PENDING_APPROVAL) then crashing BEFORE ops.Complete.
	if _, err := svc.ExecuteEvaluate(ctx, claimed[0]); err != nil {
		t.Fatalf("ExecuteEvaluate: %v", err)
	}
	gwCallsBefore := len(gwState.requests)

	// Human approves proposal while operation lease is still uncompleted.
	pd, err := fx.store.GetLatestPolicyDecisionForProposal(ctx, subRes.Proposal.ID)
	if err != nil {
		t.Fatalf("GetLatestPolicyDecisionForProposal: %v", err)
	}
	reviewer, err := fx.store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://issuer.test",
		Subject:       "reviewer-1",
		DisplayName:   "Bob Reviewer",
		VerifiedEmail: "bob@example.com",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal reviewer: %v", err)
	}
	pendingProp, err := propSvc.GetDetails(ctx, subRes.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails pending: %v", err)
	}
	if _, err := fx.store.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       pendingProp.ID,
		ReviewerID:       reviewer.ID,
		PolicyDecisionID: pd.ID,
		ManifestDigest:   pendingProp.ManifestDigest,
		Decision:         domain.ApprovalDecisionApprove,
	}); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	fromPending := domain.ProposalStatusPendingApproval
	if _, err := fx.store.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
		ID:              pendingProp.ID,
		FromStatus:      &fromPending,
		ToStatus:        domain.ProposalStatusApproved,
		ExpectedVersion: pendingProp.Version,
		UpdatedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("TransitionProposalStatus(APPROVED): %v", err)
	}

	// Expire op lease and run worker-2 ProcessOnce!
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET lease_until = now() - interval '5 seconds' WHERE id = $1`, evalReq.Operation.ID); err != nil {
		t.Fatalf("expire op lease: %v", err)
	}
	_, runner2 := newTestWorkflowRunner(t, fx, nil, &stubInspector{}, decSvc, workflow.Config{
		WorkerID: "worker-2",
	})
	if _, err := runner2.ProcessOnce(ctx); err != nil {
		t.Fatalf("worker-2 ProcessOnce: %v", err)
	}

	afterProp, err := propSvc.GetDetails(ctx, subRes.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails after retry: %v", err)
	}
	if afterProp.Status != domain.ProposalStatusApproved {
		t.Fatalf("P1-BUG-01 regression: expected APPROVED preserved after stale retry, got %s", afterProp.Status)
	}
	if len(gwState.requests) != gwCallsBefore {
		t.Fatalf("expected 0 extra gateway calls on stale retry, got %d", len(gwState.requests)-gwCallsBefore)
	}
	afterOp, err := opsSvc.GetDetails(ctx, evalReq.Operation.ID)
	if err != nil || afterOp.Status != domain.OperationStatusSucceeded {
		t.Fatalf("expected stale operation marked SUCCEEDED cleanly, got (%+v, %v)", afterOp.Status, err)
	}
}

func TestM5_InFlightScanAndModelCountsAndRouteResolutionAndStrictTrivy(t *testing.T) {
	fx := setupPGFixture(t, domain.ClassificationRestricted, []string{"restricted-ip-review"})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Replace default ORG bundle with org_baseline.yaml + attach restricted_ip_repo.yaml as REPO bundle.
	if _, err := fx.pg.Pool().Exec(ctx, `DELETE FROM policy_bundles`); err != nil {
		t.Fatalf("clear policy_bundles: %v", err)
	}
	pe, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	repoRoot := findRepoRoot(t)
	orgYAML, err := os.ReadFile(filepath.Join(repoRoot, "policies", "examples", "org_baseline.yaml"))
	if err != nil {
		t.Fatalf("read org_baseline.yaml: %v", err)
	}
	repoYAML, err := os.ReadFile(filepath.Join(repoRoot, "policies", "examples", "restricted_ip_repo.yaml"))
	if err != nil {
		t.Fatalf("read restricted_ip_repo.yaml: %v", err)
	}
	orgComp, errs := pe.Compile(orgYAML)
	if len(errs) > 0 {
		t.Fatalf("compile org_baseline: %+v", errs)
	}
	repoComp, errs := pe.Compile(repoYAML)
	if len(errs) > 0 {
		t.Fatalf("compile restricted_ip_repo: %+v", errs)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: orgComp.Bundle.Metadata.Name, Version: orgComp.Bundle.Metadata.Version, Scope: domain.PolicyScopeOrg,
		Digest: orgComp.Digest, Definition: orgComp.Definition, ActivatedAt: &now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("upsert org bundle: %v", err)
	}
	if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: repoComp.Bundle.Metadata.Name, Version: repoComp.Bundle.Metadata.Version, Scope: domain.PolicyScopeRepo,
		RepositoryID: &fx.repo.ID, Digest: repoComp.Digest, Definition: repoComp.Definition, ActivatedAt: &now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("upsert repo bundle: %v", err)
	}

	var activeScanDuringStageA atomic.Int64
	var activeModelDuringStageB atomic.Int64
	insp := &stubInspector{
		fn: func(c context.Context, req inspection.Request) (inspection.Report, error) {
			if req.Stage == inspection.StageEgress {
				cnt, err := fx.store.CountActiveScanRuns(c)
				if err != nil {
					return inspection.Report{}, err
				}
				activeScanDuringStageA.Store(cnt)
			}
			return defaultStubReport(req), nil
		},
	}

	gwState := &mockGatewayState{}
	gwSrv := startMockGateway(t, gwState)
	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	decSvc, err := decisions.NewService(gwClient)
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}
	assessor := &hookDecisionAssessor{
		inner: decSvc,
		fn: func(c context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error) {
			cnt, err := fx.store.CountActiveModelAssessments(c)
			if err != nil {
				return domain.ModelAssessment{}, err
			}
			activeModelDuringStageB.Store(cnt)
			return decSvc.Assess(c, req)
		},
	}

	_, runner := newTestWorkflowRunner(t, fx, nil, insp, assessor, workflow.Config{WorkerID: "m5-inflight-worker"})

	// Create workspace with empty ModelRoute (human workspace) -> P2-GAP-02 must select restricted-ip-review!
	wsSvc := workspaces.NewService(fx.store, nil, nil)
	wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID,
		OwnerID:      fx.owner.ID,
		BaseCommit:   fx.bareRepo.HeadSHA,
		TargetRef:    "main",
	})
	if err != nil {
		t.Fatalf("wsSvc.Create: %v", err)
	}
	if _, err := runner.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce ingress: %v", err)
	}

	snapBytes := buildTarGzBytes(t, map[string]string{"README.md": "# Restricted\n", "main.go": "package main\nfunc main() {}\n"})
	snapSHA := domain.SHA256Hex(snapBytes)
	putSnap, err := fx.snaps.Store().Put(ctx, domain.PutRequest{
		Kind:        domain.ArtifactKindEgressSnapshot,
		ObjectKey:   "workspaces/" + wsRes.Workspace.ID.String() + "/snap-r.tar.gz",
		MaxBytes:    int64(len(snapBytes) + 1024),
		WorkspaceID: &wsRes.Workspace.ID,
		ContentType: "application/gzip",
	}, bytes.NewReader(snapBytes), int64(len(snapBytes)))
	if err != nil {
		t.Fatalf("SnapshotStore.Put: %v", err)
	}
	artSvc := artifacts.NewService(fx.store, nil)
	gen1 := int64(1)
	snapArt, err := artSvc.Register(ctx, artifacts.RegisterInput{
		ID: putSnap.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: snapSHA,
		StorageKey: putSnap.StorageKey, StorageGeneration: putSnap.StorageGeneration, SizeBytes: putSnap.SizeBytes,
		Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen1,
	})
	if err != nil {
		t.Fatalf("artifacts.Register: %v", err)
	}

	propSvc := proposals.NewService(fx.store, nil, nil)
	subRes, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsRes.Workspace.ID, SnapshotArtifactID: snapArt.ID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, SizeBytes: putSnap.SizeBytes, Title: "M5 restricted route",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, err := runner.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce reconstruct: %v", err)
	}
	reconstructed, _ := propSvc.GetDetails(ctx, subRes.Proposal.ID)
	if _, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: reconstructed.ID, ExpectedVersion: reconstructed.Version,
	}); err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}
	if _, err := runner.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce evaluate: %v", err)
	}

	if activeScanDuringStageA.Load() != 1 {
		t.Fatalf("P1-GAP-34b: expected CountActiveScanRuns == 1 during Stage A, got %d", activeScanDuringStageA.Load())
	}
	if activeModelDuringStageB.Load() != 1 {
		t.Fatalf("P1-GAP-34b: expected CountActiveModelAssessments == 1 during Stage B, got %d", activeModelDuringStageB.Load())
	}
	if afterScans, _ := fx.store.CountActiveScanRuns(ctx); afterScans != 0 {
		t.Fatalf("expected 0 active scan_runs after evaluation, got %d", afterScans)
	}
	if afterModels, _ := fx.store.CountActiveModelAssessments(ctx); afterModels != 0 {
		t.Fatalf("expected 0 active model_assessments after evaluation, got %d", afterModels)
	}

	finalProp, err := propSvc.GetDetails(ctx, subRes.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails final: %v", err)
	}
	if finalProp.Status != domain.ProposalStatusPendingApproval {
		t.Fatalf("P2-GAP-02: expected PENDING_APPROVAL via restricted-ip-review route, got %s (effect=%v)", finalProp.Status, finalProp.LatestPolicyEffect)
	}
	if len(gwState.requests) != 1 || gwState.requests[0].ModelRoute != "restricted-ip-review" {
		t.Fatalf("expected gateway invoked with restricted-ip-review, got %+v", gwState.requests)
	}
}

func defaultStubReport(req inspection.Request) inspection.Report {
	now := time.Now().UTC().Truncate(time.Microsecond)
	scanners := req.MandatoryScanners
	if len(scanners) == 0 {
		for _, m := range inspection.MandatoryScanners {
			scanners = append(scanners, string(m))
		}
	}
	runs := make([]domain.ScanRun, 0, len(scanners))
	for _, s := range scanners {
		runs = append(runs, domain.ScanRun{
			ID:             domain.MustNewID(),
			ProposalID:     req.ProposalID,
			ArtifactID:     req.ArtifactID,
			Scanner:        s,
			ScannerVersion: "1.0.0",
			Status:         domain.ScanStatusCompleted,
			Coverage:       domain.ScanCoverage{FilesExamined: 2, Complete: true},
			StartedAt:      now,
			CompletedAt:    &now,
		})
	}
	return inspection.Report{
		ProposalID: req.ProposalID,
		ArtifactID: req.ArtifactID,
		ScanRuns:   runs,
		Findings:   []domain.Finding{},
		Summary: inspection.InspectionSummary{
			MandatoryScannersComplete: true,
			ScanComplete:              true,
			CountsByCategory:          map[string]int{},
			CountsBySeverity:          map[string]int{},
			CountsByScanner:           map[string]int{},
			EvidenceIDs:               []string{},
			FailedScanners:            []string{},
			IncompleteScanners:        []string{},
		},
	}
}

func TestM5_StrictSecurityRepoWithoutManifestsRunsTrivyAndDoesNotQuarantine(t *testing.T) {
	stubDir := t.TempDir()
	gitleaksBin := filepath.Join(stubDir, "gitleaks")
	scancodeBin := filepath.Join(stubDir, "scancode")
	semgrepBin := filepath.Join(stubDir, "semgrep")
	trivyBin := filepath.Join(stubDir, "trivy")

	writeStub := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", path, err)
		}
	}
	writeStub(gitleaksBin, "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"version\" ] && echo v8.18.4 && exit 0; done\nwhile [ $# -gt 0 ]; do case \"$1\" in --report-path) echo '[]' > \"$2\"; exit 0;; *) shift;; esac; done\n")
	writeStub(scancodeBin, "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"--version\" ] && echo 32.1.0 && exit 0; done\nwhile [ $# -gt 0 ]; do case \"$1\" in --json-pp) echo '{\"headers\":[{\"tool_name\":\"scancode-toolkit\",\"tool_version\":\"32.1.0\",\"errors\":[],\"extra_data\":{\"files_count\":1}}],\"files\":[]}' > \"$2\"; exit 0;; *) shift;; esac; done\n")
	writeStub(semgrepBin, "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"--version\" ] && echo 1.90.0 && exit 0; done\nwhile [ $# -gt 0 ]; do case \"$1\" in --output) echo '{\"version\":\"1.90.0\",\"results\":[],\"errors\":[],\"paths\":{\"scanned\":[\"main.go\"],\"skipped\":[]}}' > \"$2\"; exit 0;; *) shift;; esac; done\n")
	writeStub(trivyBin, "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = \"--version\" ] && echo 'Version: 0.58.0' && exit 0; done\nwhile [ $# -gt 0 ]; do case \"$1\" in --output) echo '{\"SchemaVersion\":2,\"ArtifactName\":\".\",\"ArtifactType\":\"filesystem\",\"Results\":[]}' > \"$2\"; exit 0;; *) shift;; esac; done\n")

	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	runner := inspection.NewRunner(inspection.Config{
		GitleaksBin: gitleaksBin,
		ScanCodeBin: scancodeBin,
		SemgrepBin:  semgrepBin,
		TrivyBin:    trivyBin,
	})
	rep, err := runner.Inspect(context.Background(), inspection.Request{
		ProposalID:        domain.MustNewID(),
		ArtifactID:        domain.MustNewID(),
		TargetDir:         targetDir,
		Classification:    domain.ClassificationInternal,
		Stage:             inspection.StageEgress,
		MandatoryScanners: []string{"gitleaks", "scancode", "semgrep", "trivy"},
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !rep.Summary.ScanComplete {
		t.Fatalf("expected ScanComplete=true on manifest-less repo with MandatoryScanners=trivy, got incomplete=%v failed=%v", rep.Summary.IncompleteScanners, rep.Summary.FailedScanners)
	}
	seenTrivy := false
	for _, sr := range rep.ScanRuns {
		if sr.Scanner == "trivy" && sr.IsCleanComplete() {
			seenTrivy = true
		}
	}
	if !seenTrivy {
		t.Fatalf("expected clean completed trivy ScanRun when trivy is in MandatoryScanners, got %+v", rep.ScanRuns)
	}
}
