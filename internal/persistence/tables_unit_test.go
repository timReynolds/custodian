package persistence_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestRowToDomainAndObligationUnit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 19, 10, 0, 0, 123000, time.FixedZone("EST", -5*3600))
	id := domain.MustNewID()
	wsID := domain.MustNewID()
	ownerID := domain.MustNewID()
	snapID := domain.MustNewID()
	canonID := domain.MustNewID()
	manifestID := domain.MustNewID()
	repoID := domain.MustNewID()
	bundleID := domain.MustNewID()
	decisionID := domain.MustNewID()
	reviewerID := domain.MustNewID()
	pubID := domain.MustNewID()
	scanRunID := domain.MustNewID()
	artifactID := domain.MustNewID()

	digest := domain.SHA256Hex([]byte("digest"))
	commitSHA := "0123456789abcdef0123456789abcdef01234567"
	desc := "A change proposal"

	propRow := persistence.ProposalRow{
		ID:                  id,
		WorkspaceID:         wsID,
		OwnerID:             ownerID,
		SnapshotArtifactID:  snapID,
		CanonicalArtifactID: &canonID,
		ManifestArtifactID:  &manifestID,
		BaseCommit:          commitSHA,
		TargetRef:           "refs/heads/main",
		Title:               "Fix issue",
		Description:         &desc,
		ProvenanceType:      "agent_assisted",
		CaptureMethod:       "frozen_filesystem",
		ManifestDigest:      &digest,
		Status:              domain.ProposalStatusPendingApproval,
		Version:             3,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	prop := propRow.ToDomain()
	if prop.ID != id || prop.ManifestDigest != digest || prop.Description != desc || prop.Status != domain.ProposalStatusPendingApproval || prop.Version != 3 {
		t.Fatalf("unexpected ProposalRow.ToDomain: %+v", prop)
	}
	if prop.CreatedAt.Location() != time.UTC {
		t.Fatalf("expected UTC CreatedAt, got %v", prop.CreatedAt.Location())
	}

	completedAt := now.Add(5 * time.Second)
	scanRow := persistence.ScanRunRow{
		ID:             scanRunID,
		ProposalID:     id,
		ArtifactID:     artifactID,
		Scanner:        "gitleaks",
		ScannerVersion: "8.18.0",
		Status:         domain.ScanStatusCompleted,
		Coverage:       json.RawMessage(`{"files_examined":12,"files_skipped":0,"bytes_examined":4096,"complete":true}`),
		StartedAt:      now,
		CompletedAt:    &completedAt,
	}
	scanDom := scanRow.ToDomain()
	if !scanDom.IsCleanComplete() || scanDom.Coverage.FilesExamined != 12 || scanDom.Coverage.SkippedReasons == nil {
		t.Fatalf("unexpected ScanRunRow.ToDomain: %+v", scanDom)
	}
	if scanDom.StartedAt.Location() != time.UTC || scanDom.CompletedAt == nil || scanDom.CompletedAt.Location() != time.UTC {
		t.Fatalf("expected UTC timestamps on ScanRun, got %+v", scanDom)
	}

	startLine, endLine := 10, 12
	conf := 0.92
	path := "pkg/main.go"
	findingRow := persistence.FindingRow{
		ID:          domain.MustNewID(),
		ScanRunID:   scanRunID,
		Category:    "SAST",
		Severity:    domain.SeverityHigh,
		RuleID:      "go.sql.injection",
		Path:        &path,
		StartLine:   &startLine,
		EndLine:     &endLine,
		Fingerprint: "fp-123",
		Confidence:  &conf,
		Redacted:    true,
		Metadata:    json.RawMessage(`{"cwe":"CWE-89"}`),
	}
	findingDom := findingRow.ToDomain()
	if findingDom.StartLine != 10 || findingDom.EndLine != 12 || findingDom.Confidence != 0.92 || findingDom.Metadata["cwe"] != "CWE-89" {
		t.Fatalf("unexpected FindingRow.ToDomain: %+v", findingDom)
	}

	findingNilRow := persistence.FindingRow{
		ID:          domain.MustNewID(),
		ScanRunID:   scanRunID,
		Category:    "LICENSE",
		Severity:    domain.SeverityLow,
		RuleID:      "mit",
		Fingerprint: "fp-nil",
		Redacted:    true,
	}
	findingNilDom := findingNilRow.ToDomain()
	if findingNilDom.StartLine != 0 || findingNilDom.Confidence != 0 || findingNilDom.Metadata == nil {
		t.Fatalf("expected normalized zero/non-nil defaults on FindingRow.ToDomain: %+v", findingNilDom)
	}

	risk := domain.RiskLevelLow
	disp := domain.DispositionReview
	maRow := persistence.ModelAssessmentRow{
		ID:             domain.MustNewID(),
		ProposalID:     id,
		ArtifactID:     artifactID,
		ModelRoute:     "anthropic/claude",
		ModelVersion:   "v1",
		PromptVersion:  "p1",
		AssessmentType: "SECURITY_REVIEW",
		Status:         domain.AssessmentStatusComplete,
		Risk:           &risk,
		Disposition:    &disp,
		Result:         json.RawMessage(`{"schema_version":"1.0","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"REVIEW","confidence":0.8,"summary":"ok"}`),
		EvidenceIDs:    json.RawMessage(`["ev-1","ev-2"]`),
		InputDigest:    digest,
		OutputDigest:   digest,
		CreatedAt:      now,
	}
	maDom := maRow.ToDomain()
	if maDom.Risk != domain.RiskLevelLow || maDom.Disposition != domain.DispositionReview || len(maDom.EvidenceIDs) != 2 || maDom.Result.Findings == nil || maDom.Result.Limitations == nil {
		t.Fatalf("unexpected ModelAssessmentRow.ToDomain: %+v", maDom)
	}

	bundleRow := persistence.PolicyBundleRow{
		ID:           bundleID,
		Name:         "org-default",
		Version:      "1.0.0",
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: &repoID,
		Digest:       digest,
		Definition:   json.RawMessage(`{"rules":[]}`),
		ActivatedAt:  &now,
		CreatedAt:    now,
	}
	bundleDom := bundleRow.ToDomain()
	if bundleDom.Scope != domain.PolicyScopeRepo || bundleDom.ActivatedAt == nil || bundleDom.ActivatedAt.Location() != time.UTC {
		t.Fatalf("unexpected PolicyBundleRow.ToDomain: %+v", bundleDom)
	}
	for _, emptyDef := range []json.RawMessage{nil, {}, json.RawMessage("   \t\n ")} {
		emptyBundle := persistence.PolicyBundleRow{
			ID:         bundleID,
			Name:       "empty-def",
			Version:    "1.0.0",
			Scope:      domain.PolicyScopeOrg,
			Digest:     digest,
			Definition: emptyDef,
		}.ToDomain()
		encoded, err := json.Marshal(emptyBundle)
		if err != nil {
			t.Fatalf("expected PolicyBundleRow.ToDomain with empty Definition (%q) to marshal cleanly, got %v", string(emptyDef), err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		if _, ok := decoded["definition"].(map[string]any); !ok {
			t.Fatalf("expected definition to marshal as JSON object {}, got %s", string(encoded))
		}
	}

	decRow := persistence.PolicyDecisionRow{
		ID:             decisionID,
		ProposalID:     id,
		PolicyBundleID: bundleID,
		Stage:          "EGRESS",
		InputDigest:    digest,
		Effect:         domain.PolicyEffectRequireApproval,
		Reasons:        json.RawMessage(`[{"rule_id":"r1","effect":"REQUIRE_APPROVAL","message":"needs review"}]`),
		Obligations:    json.RawMessage(`[{"type":"HUMAN_REVIEW","reviewer_group":"security","minimum":1}]`),
		CreatedAt:      now,
	}
	decDom := decRow.ToDomain()
	if decDom.Effect != domain.PolicyEffectRequireApproval || len(decDom.Reasons) != 1 || len(decDom.Obligations) != 1 {
		t.Fatalf("unexpected PolicyDecisionRow.ToDomain: %+v", decDom)
	}

	comment := "LGTM"
	appRow := persistence.ApprovalRow{
		ID:               domain.MustNewID(),
		ProposalID:       id,
		ReviewerID:       reviewerID,
		PolicyDecisionID: decisionID,
		ManifestDigest:   digest,
		Decision:         domain.ApprovalDecisionApprove,
		Comment:          &comment,
		CreatedAt:        now,
	}
	appDom := appRow.ToDomain()
	if !appDom.IsActiveForManifest(digest) || appDom.Comment != comment || appDom.CreatedAt.Location() != time.UTC {
		t.Fatalf("unexpected ApprovalRow.ToDomain: %+v", appDom)
	}

	reqRow := persistence.ApprovalRequirementRow{
		ID:               domain.MustNewID(),
		ProposalID:       id,
		PolicyDecisionID: decisionID,
		RequirementType:  "HUMAN_REVIEW",
		ReviewerGroup:    "security",
		MinimumApprovals: 2,
		SatisfiedCount:   1,
		CreatedAt:        now,
	}
	ob := reqRow.ToObligation()
	if ob.Type != "HUMAN_REVIEW" || ob.ReviewerGroup != "security" || ob.Minimum != 2 {
		t.Fatalf("unexpected ApprovalRequirementRow.ToObligation: %+v", ob)
	}

	prNum := int64(42)
	prURL := "https://github.com/org/repo/pull/42"
	pubRow := persistence.PublicationRow{
		ID:                pubID,
		ProposalID:        id,
		BranchRef:         domain.ExpectedBranchName(id),
		CommitSHA:         &commitSHA,
		PullRequestNumber: &prNum,
		PullRequestURL:    &prURL,
		Status:            domain.PublicationStatusPublished,
		AttemptCount:      1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	pubDom := pubRow.ToDomain()
	if pubDom.CommitSHA != commitSHA || *pubDom.PullRequestNumber != 42 || pubDom.PullRequestURL != prURL || pubDom.CreatedAt.Location() != time.UTC {
		t.Fatalf("unexpected PublicationRow.ToDomain: %+v", pubDom)
	}
}

func TestProposalsValidationUnit(t *testing.T) {
	t.Parallel()

	q := persistence.New(nil)
	ctx := context.Background()
	validID := domain.MustNewID()
	validSHA := "0123456789abcdef0123456789abcdef01234567"
	validDigest := domain.SHA256Hex([]byte("ok"))

	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         validSHA,
		TargetRef:          "refs/heads/main",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for nil workspace_id, got %v", err)
	}
	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        validID,
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         "not-a-sha",
		TargetRef:          "refs/heads/main",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for bad base_commit, got %v", err)
	}
	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        validID,
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         validSHA,
		TargetRef:          "",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for empty target_ref, got %v", err)
	}
	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        validID,
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         validSHA,
		TargetRef:          "refs/heads/main",
		ProvenanceType:     "unknown",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid provenance_type, got %v", err)
	}
	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        validID,
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         validSHA,
		TargetRef:          "refs/heads/main",
		CaptureMethod:      "scp",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid capture_method, got %v", err)
	}
	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		WorkspaceID:        validID,
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         validSHA,
		TargetRef:          "refs/heads/main",
		Status:             domain.ProposalStatus("BOGUS"),
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid status, got %v", err)
	}
	if _, err := q.CreateProposal(ctx, persistence.CreateProposalParams{
		ID:                 uuid.New(), // v4, not v7
		WorkspaceID:        validID,
		OwnerID:            validID,
		SnapshotArtifactID: validID,
		BaseCommit:         validSHA,
		TargetRef:          "refs/heads/main",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for non-UUIDv7 id, got %v", err)
	}

	if _, err := q.GetProposalByID(ctx, uuid.Nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for nil proposal id, got %v", err)
	}
	if _, err := q.GetProposalDetailsByID(ctx, uuid.Nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for nil proposal details id, got %v", err)
	}
	if _, err := q.ListProposalsByWorkspace(ctx, uuid.Nil, 10); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for nil workspace id, got %v", err)
	}
	badStatus := domain.ProposalStatus("INVALID")
	if _, err := q.ListProposalsByOwner(ctx, persistence.ListProposalsByOwnerParams{
		OwnerID: validID,
		Status:  &badStatus,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid owner list status, got %v", err)
	}
	if _, err := q.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
		ID:              validID,
		ToStatus:        domain.ProposalStatusEvaluating,
		ExpectedVersion: 0,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for version < 1, got %v", err)
	}
	if _, err := q.SetProposalReconstruction(ctx, persistence.SetProposalReconstructionParams{
		ID:                  validID,
		CanonicalArtifactID: validID,
		ManifestArtifactID:  validID,
		TreeDigest:          "short",
		DiffDigest:          validDigest,
		ManifestDigest:      validDigest,
		ExpectedVersion:     1,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for short tree_digest, got %v", err)
	}
	if _, err := q.ApplyProposalPolicyDecision(ctx, persistence.ApplyProposalPolicyDecisionParams{
		ID:                 validID,
		PolicyEvaluationID: validID,
		PolicyEffect:       domain.PolicyEffect("BOGUS"),
		Status:             domain.ProposalStatusDenied,
		ExpectedVersion:    1,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid policy effect, got %v", err)
	}
}

func TestInspectionValidationUnit(t *testing.T) {
	t.Parallel()

	q := persistence.New(nil)
	ctx := context.Background()
	validID := domain.MustNewID()
	validDigest := domain.SHA256Hex([]byte("x"))

	// scan_runs
	if _, err := q.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ProposalID:     validID,
		ArtifactID:     validID,
		Scanner:        "",
		ScannerVersion: "1.0",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for empty scanner, got %v", err)
	}
	if _, err := q.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
		ID:     validID,
		Status: domain.ScanStatusRunning,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for non-terminal scan completion status, got %v", err)
	}

	// findings: ValidateRedacted must return ErrUnprocessable (422)
	if _, err := q.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID:   validID,
		Category:    "SECRET",
		Severity:    domain.SeverityCritical,
		RuleID:      "aws-key",
		Fingerprint: "fp-1",
		Redacted:    false,
	}); !errors.Is(err, domain.ErrUnprocessable) || domain.HTTPStatusFromError(err) != 422 {
		t.Fatalf("expected 422 ErrUnprocessable for unredacted SECRET finding, got %v", err)
	}
	if _, err := q.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID:   validID,
		Category:    "SECRET",
		Severity:    domain.SeverityCritical,
		RuleID:      "aws-key",
		Fingerprint: "fp-2",
		Redacted:    true,
		Metadata:    map[string]any{"nested": map[string]any{"raw_secret": "AKIA..."}},
	}); !errors.Is(err, domain.ErrUnprocessable) || domain.HTTPStatusFromError(err) != 422 {
		t.Fatalf("expected 422 ErrUnprocessable for forbidden raw_secret metadata, got %v", err)
	}

	negLine := -1
	if _, err := q.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID:   validID,
		Category:    "SAST",
		Severity:    domain.SeverityHigh,
		RuleID:      "r1",
		StartLine:   &negLine,
		Fingerprint: "fp-3",
		Redacted:    true,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for negative start_line, got %v", err)
	}

	badConf := math.NaN()
	if _, err := q.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID:   validID,
		Category:    "SAST",
		Severity:    domain.SeverityHigh,
		RuleID:      "r1",
		Confidence:  &badConf,
		Fingerprint: "fp-4",
		Redacted:    true,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for NaN confidence, got %v", err)
	}

	badSev := domain.Severity("BOGUS")
	if _, err := q.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: validID,
		Severity:   &badSev,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid severity filter, got %v", err)
	}
	nilCursor := uuid.Nil
	if _, err := q.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: validID,
		CursorID:   &nilCursor,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for uuid.Nil cursor_id, got %v", err)
	}

	// model_assessments
	if _, err := q.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ProposalID:     validID,
		ArtifactID:     validID,
		ModelRoute:     "r",
		ModelVersion:   "v1",
		PromptVersion:  "p1",
		AssessmentType: "SECURITY_REVIEW",
		Status:         domain.AssessmentStatusComplete,
		Risk:           domain.RiskLevel("INVALID"),
		InputDigest:    validDigest,
		OutputDigest:   validDigest,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid risk level, got %v", err)
	}
	if _, err := q.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ProposalID:     validID,
		ArtifactID:     validID,
		ModelRoute:     "r",
		ModelVersion:   "v1",
		PromptVersion:  "p1",
		AssessmentType: "SECURITY_REVIEW",
		Status:         domain.AssessmentStatusComplete,
		InputDigest:    "not-sha256",
		OutputDigest:   validDigest,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid input_digest, got %v", err)
	}
}

func TestPoliciesApprovalsAndPublicationsValidationUnit(t *testing.T) {
	t.Parallel()

	q := persistence.New(nil)
	ctx := context.Background()
	validID := domain.MustNewID()
	validDigest := domain.SHA256Hex([]byte("policy"))

	// policy_bundles
	if _, err := q.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:         "org",
		Version:      "1.0",
		Scope:        domain.PolicyScopeOrg,
		RepositoryID: &validID,
		Digest:       validDigest,
		Definition:   json.RawMessage(`{"rules":[]}`),
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for ORG bundle with repository_id, got %v", err)
	}
	if _, err := q.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:         "repo",
		Version:      "1.0",
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: nil,
		Digest:       validDigest,
		Definition:   json.RawMessage(`{"rules":[]}`),
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for REPO bundle without repository_id, got %v", err)
	}
	for _, badDef := range []json.RawMessage{
		nil,
		{},
		json.RawMessage("   \t\n "),
		json.RawMessage("null"),
		json.RawMessage("  null  "),
		json.RawMessage(`{bad json`),
	} {
		if _, err := q.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
			Name:       "org",
			Version:    "1.0",
			Scope:      domain.PolicyScopeOrg,
			Digest:     validDigest,
			Definition: badDef,
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest for invalid definition %q, got %v", string(badDef), err)
		}
	}
	if _, err := q.GetActivePolicyBundle(ctx, domain.PolicyScopeRepo, nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for GetActivePolicyBundle(REPO, nil), got %v", err)
	}
	if _, err := q.GetActivePolicyBundle(ctx, domain.PolicyScopeOrg, &validID); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for GetActivePolicyBundle(ORG, &validID), got %v", err)
	}

	// policy_decisions
	if _, err := q.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID:     validID,
		PolicyBundleID: validID,
		Stage:          "DEPLOY",
		InputDigest:    validDigest,
		Effect:         domain.PolicyEffectAllow,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid policy stage, got %v", err)
	}

	// approvals & approval_requirements
	if _, err := q.CreateApproval(ctx, persistence.CreateApprovalParams{
		ProposalID:       validID,
		ReviewerID:       validID,
		PolicyDecisionID: validID,
		ManifestDigest:   validDigest,
		Decision:         domain.ApprovalDecision("MAYBE"),
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid approval decision, got %v", err)
	}
	if _, err := q.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
		ProposalID:       validID,
		PolicyDecisionID: validID,
		RequirementType:  "HUMAN_REVIEW",
		ReviewerGroup:    "security",
		MinimumApprovals: 0,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for minimum_approvals < 1, got %v", err)
	}

	// publications & publication_attempts
	if _, err := q.CreatePublication(ctx, persistence.CreatePublicationParams{
		ProposalID: validID,
		BranchRef:  "refs/heads/main",
	}); !errors.Is(err, domain.ErrForbidden) || domain.HTTPStatusFromError(err) != 403 {
		t.Fatalf("expected 403 ErrForbidden for non-custodian branch_ref, got %v", err)
	}
	if _, err := q.EnsurePublication(ctx, persistence.CreatePublicationParams{
		ProposalID: validID,
		BranchRef:  "custodian/" + domain.MustNewID().String(),
	}); !errors.Is(err, domain.ErrForbidden) || domain.HTTPStatusFromError(err) != 403 {
		t.Fatalf("expected 403 ErrForbidden for mismatched proposal branch_ref, got %v", err)
	}
	if _, err := q.MarkPublicationPublished(ctx, persistence.MarkPublicationPublishedParams{
		ID:        validID,
		CommitSHA: "short-sha",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid commit_sha, got %v", err)
	}
	if _, err := q.CreatePublicationAttempt(ctx, persistence.CreatePublicationAttemptParams{
		PublicationID:  validID,
		AttemptNumber:  0,
		ManifestDigest: validDigest,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for attempt_number < 1, got %v", err)
	}
	if _, _, err := q.BeginPublicationAttempt(ctx, persistence.BeginPublicationAttemptParams{
		PublicationID:  validID,
		AttemptID:      uuid.New(), // v4, not v7
		ManifestDigest: validDigest,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for non-UUIDv7 AttemptID in BeginPublicationAttempt, got %v", err)
	}
}
