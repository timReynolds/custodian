package proposals_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/proposals"
)

type fakeProposalStore struct {
	workspace         persistence.WorkspaceRow
	workspaceErr      error
	artifacts         map[uuid.UUID]persistence.ArtifactRow
	proposal          persistence.ProposalRow
	proposalErr       error
	details           persistence.ProposalDetailsRow
	detailsList       []persistence.ProposalDetailsRow
	scanRuns          []persistence.ScanRunRow
	findings          []persistence.FindingRow
	assessments       []persistence.ModelAssessmentRow
	decisions         []persistence.PolicyDecisionRow
	requirements      []persistence.ApprovalRequirementRow
	activeApprovals   []persistence.ApprovalRow
	publication       persistence.PublicationRow
	latestOp          persistence.OperationRow
	latestOpErr       error
	createdReqs       []persistence.CreateApprovalRequirementParams
	revokedCount      int
	resetReqCount     int
	enqueuedOps       []persistence.EnqueueOperationParams
	outboxEvents      []persistence.EnqueueOutboxParams
	auditEvents       []persistence.InsertAuditEventParams
	auditSeq          int64
	lastHash          string
	applyDecisionArgs []persistence.ApplyProposalPolicyDecisionParams
}

func (f *fakeProposalStore) GetWorkspaceByID(_ context.Context, _ uuid.UUID) (persistence.WorkspaceRow, error) {
	if f.workspaceErr != nil {
		return persistence.WorkspaceRow{}, f.workspaceErr
	}
	return f.workspace, nil
}

func (f *fakeProposalStore) GetWorkspaceDetailsByID(_ context.Context, _ uuid.UUID) (persistence.WorkspaceDetailsRow, error) {
	return persistence.WorkspaceDetailsRow{Workspace: f.workspace}, nil
}

func (f *fakeProposalStore) GetArtifactByID(_ context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
	a, ok := f.artifacts[id]
	if !ok {
		return persistence.ArtifactRow{}, domain.NotFound("ARTIFACT_NOT_FOUND", "artifact not found")
	}
	return a, nil
}

func (f *fakeProposalStore) CreateProposal(_ context.Context, arg persistence.CreateProposalParams) (persistence.ProposalRow, error) {
	id := arg.ID
	if id == uuid.Nil {
		id = domain.MustNewID()
	}
	var desc *string
	if arg.Description != "" {
		d := arg.Description
		desc = &d
	}
	f.proposal = persistence.ProposalRow{
		ID:                 id,
		WorkspaceID:        arg.WorkspaceID,
		OwnerID:            arg.OwnerID,
		SnapshotArtifactID: arg.SnapshotArtifactID,
		BaseCommit:         arg.BaseCommit,
		TargetRef:          arg.TargetRef,
		Title:              arg.Title,
		Description:        desc,
		ProvenanceType:     arg.ProvenanceType,
		CaptureMethod:      arg.CaptureMethod,
		Status:             arg.Status,
		Version:            arg.Version,
		CreatedAt:          arg.CreatedAt,
		UpdatedAt:          arg.CreatedAt,
	}
	f.details.Proposal = f.proposal
	return f.proposal, nil
}

func (f *fakeProposalStore) GetProposalByID(_ context.Context, _ uuid.UUID) (persistence.ProposalRow, error) {
	if f.proposalErr != nil {
		return persistence.ProposalRow{}, f.proposalErr
	}
	return f.proposal, nil
}

func (f *fakeProposalStore) GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	return f.GetProposalByID(ctx, id)
}

func (f *fakeProposalStore) GetProposalDetailsByID(_ context.Context, _ uuid.UUID) (persistence.ProposalDetailsRow, error) {
	if f.proposalErr != nil {
		return persistence.ProposalDetailsRow{}, f.proposalErr
	}
	d := f.details
	d.Proposal = f.proposal
	return d, nil
}

func (f *fakeProposalStore) ListProposalDetailsByWorkspace(_ context.Context, _ uuid.UUID, _ int32) ([]persistence.ProposalDetailsRow, error) {
	return append([]persistence.ProposalDetailsRow(nil), f.detailsList...), nil
}

func (f *fakeProposalStore) ListProposalDetailsByOwner(_ context.Context, _ persistence.ListProposalsByOwnerParams) ([]persistence.ProposalDetailsRow, error) {
	return append([]persistence.ProposalDetailsRow(nil), f.detailsList...), nil
}

func (f *fakeProposalStore) TransitionProposalStatus(_ context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error) {
	if f.proposal.Version != arg.ExpectedVersion || (arg.FromStatus != nil && f.proposal.Status != *arg.FromStatus) {
		return persistence.ProposalRow{}, domain.Conflict("PROPOSAL_VERSION_CONFLICT", "conflict")
	}
	f.proposal.Status = arg.ToStatus
	f.proposal.Version++
	f.proposal.UpdatedAt = arg.UpdatedAt
	return f.proposal, nil
}

func (f *fakeProposalStore) SetProposalReconstruction(_ context.Context, arg persistence.SetProposalReconstructionParams) (persistence.ProposalRow, error) {
	f.proposal.CanonicalArtifactID = &arg.CanonicalArtifactID
	f.proposal.DiffArtifactID = arg.DiffArtifactID
	f.proposal.ManifestArtifactID = &arg.ManifestArtifactID
	f.proposal.TreeDigest = &arg.TreeDigest
	f.proposal.DiffDigest = &arg.DiffDigest
	f.proposal.ManifestDigest = &arg.ManifestDigest
	f.proposal.Status = arg.Status
	f.proposal.Version++
	f.proposal.UpdatedAt = arg.UpdatedAt
	return f.proposal, nil
}

func (f *fakeProposalStore) ApplyProposalPolicyDecision(_ context.Context, arg persistence.ApplyProposalPolicyDecisionParams) (persistence.ProposalRow, error) {
	f.applyDecisionArgs = append(f.applyDecisionArgs, arg)
	f.proposal.LatestPolicyEvaluationID = &arg.PolicyEvaluationID
	e := arg.PolicyEffect
	f.proposal.LatestPolicyEffect = &e
	f.proposal.Status = arg.Status
	f.proposal.Version++
	f.proposal.UpdatedAt = arg.UpdatedAt
	return f.proposal, nil
}

func (f *fakeProposalStore) CreatePolicyDecision(_ context.Context, arg persistence.CreatePolicyDecisionParams) (persistence.PolicyDecisionRow, error) {
	id := arg.ID
	if id == uuid.Nil {
		id = domain.MustNewID()
	}
	reasons, _ := json.Marshal(arg.Reasons)
	obs, _ := json.Marshal(arg.Obligations)
	row := persistence.PolicyDecisionRow{
		ID:             id,
		ProposalID:     arg.ProposalID,
		PolicyBundleID: arg.PolicyBundleID,
		OrgBundleID:    arg.OrgBundleID,
		RepoBundleID:   arg.RepoBundleID,
		Stage:          arg.Stage,
		InputDigest:    arg.InputDigest,
		Effect:         arg.Effect,
		Reasons:        reasons,
		Obligations:    obs,
		CreatedAt:      arg.CreatedAt,
	}
	f.decisions = append(f.decisions, row)
	return row, nil
}

func (f *fakeProposalStore) CreateApprovalRequirement(_ context.Context, arg persistence.CreateApprovalRequirementParams) (persistence.ApprovalRequirementRow, error) {
	f.createdReqs = append(f.createdReqs, arg)
	row := persistence.ApprovalRequirementRow{
		ID:               domain.MustNewID(),
		ProposalID:       arg.ProposalID,
		PolicyDecisionID: arg.PolicyDecisionID,
		RequirementType:  arg.RequirementType,
		ReviewerGroup:    arg.ReviewerGroup,
		MinimumApprovals: arg.MinimumApprovals,
		CreatedAt:        arg.CreatedAt,
	}
	f.requirements = append(f.requirements, row)
	return row, nil
}

func (f *fakeProposalStore) ListApprovalRequirementsByPolicyDecision(_ context.Context, _ uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	return append([]persistence.ApprovalRequirementRow(nil), f.requirements...), nil
}

func (f *fakeProposalStore) ListActiveApprovalsForDecision(_ context.Context, _, _ uuid.UUID, _ string) ([]persistence.ApprovalRow, error) {
	return append([]persistence.ApprovalRow(nil), f.activeApprovals...), nil
}

func (f *fakeProposalStore) RevokeApprovalsForProposal(_ context.Context, _ uuid.UUID, _ time.Time) (int64, error) {
	f.revokedCount++
	f.activeApprovals = nil
	return 1, nil
}

func (f *fakeProposalStore) ResetApprovalRequirementsForPolicyDecision(_ context.Context, _ uuid.UUID) (int64, error) {
	f.resetReqCount++
	return 1, nil
}

func (f *fakeProposalStore) EnsurePublication(_ context.Context, arg persistence.CreatePublicationParams) (persistence.PublicationRow, error) {
	if f.publication.ID == uuid.Nil {
		f.publication = persistence.PublicationRow{
			ID:         domain.MustNewID(),
			ProposalID: arg.ProposalID,
			BranchRef:  arg.BranchRef,
			Status:     arg.Status,
			CreatedAt:  arg.CreatedAt,
			UpdatedAt:  arg.CreatedAt,
		}
	}
	return f.publication, nil
}

func (f *fakeProposalStore) GetLatestOperationByResource(_ context.Context, _ uuid.UUID, _ domain.OperationType) (persistence.OperationRow, error) {
	if f.latestOpErr != nil {
		return persistence.OperationRow{}, f.latestOpErr
	}
	return f.latestOp, nil
}

func (f *fakeProposalStore) EnqueueOperation(_ context.Context, arg persistence.EnqueueOperationParams) (persistence.OperationRow, error) {
	f.enqueuedOps = append(f.enqueuedOps, arg)
	rt := arg.ResourceType
	op := persistence.OperationRow{
		ID:            domain.MustNewID(),
		OperationType: arg.OperationType,
		ResourceType:  &rt,
		ResourceID:    arg.ResourceID,
		Status:        domain.OperationStatusPending,
		MaxAttempts:   5,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	f.latestOp = op
	f.latestOpErr = nil
	return op, nil
}

func (f *fakeProposalStore) EnqueueOutboxEvent(_ context.Context, arg persistence.EnqueueOutboxParams) (persistence.OutboxEventRow, error) {
	f.outboxEvents = append(f.outboxEvents, arg)
	return persistence.OutboxEventRow{ID: domain.MustNewID(), EventType: arg.EventType, AggregateID: arg.AggregateID}, nil
}

func (f *fakeProposalStore) LockAuditChainHead(_ context.Context) (persistence.AuditChainHeadRow, error) {
	var h *string
	if f.lastHash != "" {
		s := f.lastHash
		h = &s
	}
	return persistence.AuditChainHeadRow{ChainID: "main", EventCount: f.auditSeq, LastEventHash: h}, nil
}

func (f *fakeProposalStore) NormalizeJSONB(_ context.Context, payload json.RawMessage) (json.RawMessage, error) {
	return payload, nil
}

func (f *fakeProposalStore) UpdateAuditChainHead(_ context.Context, _ uuid.UUID, eventHash string, eventCount int64, _ time.Time) error {
	f.auditSeq = eventCount
	f.lastHash = eventHash
	return nil
}

func (f *fakeProposalStore) InsertAuditEvent(_ context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	f.auditEvents = append(f.auditEvents, arg)
	return persistence.AuditEventRow{ID: arg.ID, ChainSeq: arg.ChainSeq, EventType: arg.EventType, EventHash: arg.EventHash, CreatedAt: arg.CreatedAt}, nil
}

func (f *fakeProposalStore) ListScanRunsByProposal(_ context.Context, _ uuid.UUID) ([]persistence.ScanRunRow, error) {
	return append([]persistence.ScanRunRow(nil), f.scanRuns...), nil
}

func (f *fakeProposalStore) ListFindingsByProposal(_ context.Context, arg persistence.ListFindingsByProposalParams) ([]persistence.FindingRow, error) {
	if arg.Limit < len(f.findings) {
		return append([]persistence.FindingRow(nil), f.findings[:arg.Limit]...), nil
	}
	return append([]persistence.FindingRow(nil), f.findings...), nil
}

func (f *fakeProposalStore) ListModelAssessmentsByProposal(_ context.Context, _ uuid.UUID) ([]persistence.ModelAssessmentRow, error) {
	return append([]persistence.ModelAssessmentRow(nil), f.assessments...), nil
}

func (f *fakeProposalStore) ListPolicyDecisionsByProposal(_ context.Context, _ uuid.UUID) ([]persistence.PolicyDecisionRow, error) {
	return append([]persistence.PolicyDecisionRow(nil), f.decisions...), nil
}

func (f *fakeProposalStore) RunInTx(_ context.Context, fn func(tx proposals.TxStore) error) error {
	return fn(f)
}

func newBaseProposalFake() *fakeProposalStore {
	wsID := domain.MustNewID()
	repoID := domain.MustNewID()
	ownerID := domain.MustNewID()
	snapID := domain.MustNewID()
	snapSHA := domain.SHA256Hex([]byte("snapshot"))
	gen := int64(1)
	ws := persistence.WorkspaceRow{
		ID:           wsID,
		RepositoryID: repoID,
		OwnerID:      ownerID,
		BaseCommit:   strings.Repeat("a", 40),
		TargetRef:    "refs/heads/main",
		Generation:   1,
		Status:       domain.WorkspaceStatusReady,
	}
	art := persistence.ArtifactRow{
		ID:                  snapID,
		Kind:                domain.ArtifactKindEgressSnapshot,
		SHA256:              snapSHA,
		StorageKey:          "ws/snap.tar.gz",
		StorageGeneration:   "1",
		SizeBytes:           2048,
		WorkspaceID:         &wsID,
		WorkspaceGeneration: &gen,
	}
	return &fakeProposalStore{
		workspace: ws,
		artifacts: map[uuid.UUID]persistence.ArtifactRow{snapID: art},
		details: persistence.ProposalDetailsRow{
			RepositoryID:             repoID,
			GitHubRepositoryID:       12345,
			RepositoryFullName:       "org/repo",
			RepositoryClassification: domain.ClassificationInternal,
			WorkspaceGeneration:      1,
			OwnerKind:                domain.PrincipalKindHuman,
		},
	}
}

func TestProposalsNilStoreAndSubmitValidationUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	nilSvc := proposals.NewService(nil, nil, nil)
	if _, err := nilSvc.Submit(ctx, proposals.SubmitInput{}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store Submit: %v", err)
	}
	if _, err := nilSvc.Get(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store Get: %v", err)
	}
	if _, err := nilSvc.GetDetails(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store GetDetails: %v", err)
	}
	if _, err := nilSvc.ListByWorkspace(ctx, domain.MustNewID(), 10); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store ListByWorkspace: %v", err)
	}
	if _, err := nilSvc.ListByOwner(ctx, domain.MustNewID(), 10); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store ListByOwner: %v", err)
	}
	if _, err := nilSvc.RequestEvaluation(ctx, proposals.EvaluateInput{}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store RequestEvaluation: %v", err)
	}
	if _, err := nilSvc.RequestPublish(ctx, proposals.PublishRequestInput{}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store RequestPublish: %v", err)
	}
	if _, err := nilSvc.ListFindings(ctx, proposals.ListFindingsFilter{}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store ListFindings: %v", err)
	}
	if _, err := nilSvc.ListAssessmentsAndDecisions(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store ListAssessmentsAndDecisions: %v", err)
	}

	// Submit validation & invariants
	base := newBaseProposalFake()
	var snapID uuid.UUID
	var snapSHA string
	for id, a := range base.artifacts {
		snapID = id
		snapSHA = a.SHA256
	}
	svc := proposals.NewServiceWithStore(base, nil, nil)

	// Bad inputs -> 400
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: "bad",
		WorkspaceGeneration: 1, Title: "t",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on invalid sha256, got %v", err)
	}
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, Title: "   ",
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on blank title, got %v", err)
	}

	// Workspace not READY -> 409
	notReady := newBaseProposalFake()
	notReady.workspace.Status = domain.WorkspaceStatusPending
	for id, a := range notReady.artifacts {
		if _, err := proposals.NewServiceWithStore(notReady, nil, nil).Submit(ctx, proposals.SubmitInput{
			WorkspaceID: notReady.workspace.ID, SnapshotArtifactID: id, SnapshotSHA256: a.SHA256,
			WorkspaceGeneration: 1, Title: "valid",
		}); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("expected ErrConflict for non-READY workspace, got %v", err)
		}
	}

	// Generation mismatch -> 409
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 2, Title: "valid",
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict for generation mismatch, got %v", err)
	}

	// Missing artifact -> 404
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: domain.MustNewID(), SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, Title: "valid",
	}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing artifact, got %v", err)
	}

	// Wrong artifact kind -> 422
	wrongKind := newBaseProposalFake()
	for id, a := range wrongKind.artifacts {
		a.Kind = domain.ArtifactKindWorkspaceSource
		wrongKind.artifacts[id] = a
		if _, err := proposals.NewServiceWithStore(wrongKind, nil, nil).Submit(ctx, proposals.SubmitInput{
			WorkspaceID: wrongKind.workspace.ID, SnapshotArtifactID: id, SnapshotSHA256: a.SHA256,
			WorkspaceGeneration: 1, Title: "valid",
		}); !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("expected ErrUnprocessable for wrong artifact kind, got %v", err)
		}
	}

	// Digest mismatch -> 422
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: strings.Repeat("b", 64),
		WorkspaceGeneration: 1, Title: "valid",
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for digest mismatch, got %v", err)
	}

	// Size mismatch -> 422
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, SizeBytes: 9999, Title: "valid",
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for size mismatch, got %v", err)
	}

	// Artifact belonging to another workspace -> 409
	otherWS := newBaseProposalFake()
	otherID := domain.MustNewID()
	for id, a := range otherWS.artifacts {
		a.WorkspaceID = &otherID
		otherWS.artifacts[id] = a
		if _, err := proposals.NewServiceWithStore(otherWS, nil, nil).Submit(ctx, proposals.SubmitInput{
			WorkspaceID: otherWS.workspace.ID, SnapshotArtifactID: id, SnapshotSHA256: a.SHA256,
			WorkspaceGeneration: 1, Title: "valid",
		}); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("expected ErrConflict for other workspace artifact, got %v", err)
		}
	}

	// Successful Submit sets OwnerID = workspace.OwnerID and Status = CAPTURED.
	res, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: "sha256:" + strings.ToUpper(snapSHA),
		WorkspaceGeneration: 1, Title: "Valid change",
	})
	if err != nil {
		t.Fatalf("Submit valid: %v", err)
	}
	if res.Proposal.OwnerID != base.workspace.OwnerID || res.Proposal.Status != domain.ProposalStatusCaptured {
		t.Fatalf("unexpected submitted proposal: %+v", res.Proposal)
	}

	// Multi-byte UTF-8 rune boundaries: 256*'é' title and 8192*'é' description pass; +1 rune fails.
	exactTitle := strings.Repeat("é", 256)
	exactDesc := strings.Repeat("é", 8192)
	utf8Res, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, Title: exactTitle, Description: exactDesc,
	})
	if err != nil {
		t.Fatalf("Submit exact 256/8192 multi-byte UTF-8 runes: %v", err)
	}
	if utf8Res.Proposal.Title != exactTitle || utf8Res.Proposal.Description != exactDesc {
		t.Fatalf("persisted UTF-8 title/description mismatch")
	}

	overTitle := strings.Repeat("é", 257)
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, Title: overTitle,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for 257-rune UTF-8 title, got %v", err)
	}

	overDesc := strings.Repeat("é", 8193)
	if _, err := svc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: base.workspace.ID, SnapshotArtifactID: snapID, SnapshotSHA256: snapSHA,
		WorkspaceGeneration: 1, Title: "Valid", Description: overDesc,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for 8193-rune UTF-8 description, got %v", err)
	}
}

func TestProposalsPolicyEffectMappingDedupAndDeniedErrorUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Effect mapping & obligation deduplication.
	for _, tc := range []struct {
		effect     domain.PolicyEffect
		wantStatus domain.ProposalStatus
	}{
		{domain.PolicyEffectDeny, domain.ProposalStatusDenied},
		{domain.PolicyEffectQuarantine, domain.ProposalStatusQuarantined},
		{domain.PolicyEffectRequireRemediation, domain.ProposalStatusRemediationRequired},
		{domain.PolicyEffectRequireApproval, domain.ProposalStatusPendingApproval},
		{domain.PolicyEffectAllow, domain.ProposalStatusPendingApproval}, // RG-03 mandatory human approval
	} {
		fake := newBaseProposalFake()
		fake.proposal = persistence.ProposalRow{
			ID: domain.MustNewID(), WorkspaceID: fake.workspace.ID, OwnerID: fake.workspace.OwnerID,
			Status: domain.ProposalStatusEvaluating, Version: 3,
		}
		svc := proposals.NewServiceWithStore(fake, nil, nil)
		out, err := svc.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
			ProposalID: fake.proposal.ID, ExpectedVersion: 3, PolicyBundleID: domain.MustNewID(),
			InputDigest: domain.SHA256Hex([]byte("in")), Effect: tc.effect,
			Obligations: []domain.Obligation{
				{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 1},
				{Type: "SECURITY_REVIEW", ReviewerGroup: "security-team", Minimum: 2},
				{Type: "", ReviewerGroup: "platform-owners", Minimum: 1},
			},
		})
		if err != nil {
			t.Fatalf("ApplyPolicyDecision(%s): %v", tc.effect, err)
		}
		if out.Status != tc.wantStatus {
			t.Fatalf("effect %s -> status %s, want %s", tc.effect, out.Status, tc.wantStatus)
		}
		if tc.wantStatus == domain.ProposalStatusPendingApproval {
			if len(fake.createdReqs) != 2 || fake.createdReqs[0].MinimumApprovals != 2 || fake.createdReqs[1].RequirementType != "HUMAN_REVIEW" {
				t.Fatalf("expected 2 deduplicated approval requirements with max minimum, got %+v", fake.createdReqs)
			}
		} else if len(fake.createdReqs) != 0 {
			t.Fatalf("expected 0 approval requirements for blocking effect %s", tc.effect)
		}
	}

	// *PolicyDeniedError contract on DENIED/QUARANTINED/REMEDIATION_REQUIRED
	manifest := domain.SHA256Hex([]byte("manifest"))
	for _, tc := range []struct {
		status domain.ProposalStatus
		effect domain.PolicyEffect
	}{
		{domain.ProposalStatusDenied, domain.PolicyEffectDeny},
		{domain.ProposalStatusQuarantined, domain.PolicyEffectQuarantine},
		{domain.ProposalStatusRemediationRequired, domain.PolicyEffectRequireRemediation},
	} {
		fake := newBaseProposalFake()
		decID := domain.MustNewID()
		eff := tc.effect
		fake.proposal = persistence.ProposalRow{
			ID: domain.MustNewID(), WorkspaceID: fake.workspace.ID, OwnerID: fake.workspace.OwnerID,
			ManifestDigest: &manifest, LatestPolicyEvaluationID: &decID, LatestPolicyEffect: &eff,
			Status: tc.status, Version: 4,
		}
		_, err := proposals.NewServiceWithStore(fake, nil, nil).RequestPublish(ctx, proposals.PublishRequestInput{
			ProposalID: fake.proposal.ID, PublicationManifestDigest: manifest,
		})
		var pde *proposals.PolicyDeniedError
		if !errors.As(err, &pde) {
			t.Fatalf("expected *PolicyDeniedError for %s, got %T (%v)", tc.status, err, err)
		}
		if pde.PolicyDecisionID != decID || pde.Effect != tc.effect {
			t.Fatalf("PolicyDeniedError fields mismatch: %+v", pde)
		}
		if !errors.Is(err, domain.ErrConflict) || domain.HTTPStatusFromError(err) != http.StatusConflict {
			t.Fatalf("expected PolicyDeniedError to unwrap to ErrConflict (409), got status=%d err=%v", domain.HTTPStatusFromError(err), err)
		}
	}

	// Stale manifest digest on APPROVED -> 409 Conflict
	fakeApproved := newBaseProposalFake()
	decID := domain.MustNewID()
	effAllow := domain.PolicyEffectAllow
	fakeApproved.proposal = persistence.ProposalRow{
		ID: domain.MustNewID(), WorkspaceID: fakeApproved.workspace.ID, OwnerID: fakeApproved.workspace.OwnerID,
		ManifestDigest: &manifest, LatestPolicyEvaluationID: &decID, LatestPolicyEffect: &effAllow,
		Status: domain.ProposalStatusApproved, Version: 5,
	}
	if _, err := proposals.NewServiceWithStore(fakeApproved, nil, nil).RequestPublish(ctx, proposals.PublishRequestInput{
		ProposalID: fakeApproved.proposal.ID, PublicationManifestDigest: strings.Repeat("b", 64),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on stale manifest digest, got %v", err)
	}

	// Idempotent PUBLISHING / PUBLISHED returns existing publication & operation.
	fakePub := newBaseProposalFake()
	revID := domain.MustNewID()
	fakePub.proposal = persistence.ProposalRow{
		ID: domain.MustNewID(), WorkspaceID: fakePub.workspace.ID, OwnerID: fakePub.workspace.OwnerID,
		ManifestDigest: &manifest, LatestPolicyEvaluationID: &decID, LatestPolicyEffect: &effAllow,
		Status: domain.ProposalStatusPublishing, Version: 6,
	}
	fakePub.activeApprovals = []persistence.ApprovalRow{{
		ID: domain.MustNewID(), ProposalID: fakePub.proposal.ID, ReviewerID: revID,
		PolicyDecisionID: decID, ManifestDigest: manifest, Decision: domain.ApprovalDecisionApprove,
	}}
	existingOpID := domain.MustNewID()
	fakePub.latestOp = persistence.OperationRow{
		ID: existingOpID, OperationType: domain.OperationTypeProposalPublish, ResourceID: fakePub.proposal.ID,
		Status: domain.OperationStatusPending, MaxAttempts: 5,
	}
	pubRes, err := proposals.NewServiceWithStore(fakePub, nil, nil).RequestPublish(ctx, proposals.PublishRequestInput{
		ProposalID: fakePub.proposal.ID, PublicationManifestDigest: manifest,
	})
	if err != nil || pubRes.Operation.ID != existingOpID || len(fakePub.enqueuedOps) != 0 {
		t.Fatalf("expected idempotent RequestPublish on PUBLISHING, got (%+v, %v)", pubRes, err)
	}
}

func TestProposalsOrderingAndFindingsRedactionUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newBaseProposalFake()
	propID := domain.MustNewID()
	fake.proposal = persistence.ProposalRow{ID: propID, Status: domain.ProposalStatusPendingApproval, Version: 4}

	t1 := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	id1, id2 := domain.MustNewID(), domain.MustNewID()
	// Persistence returns DESC order (newest first).
	fake.assessments = []persistence.ModelAssessmentRow{
		{ID: id2, ProposalID: propID, CreatedAt: t2},
		{ID: id1, ProposalID: propID, CreatedAt: t1},
	}
	fake.decisions = []persistence.PolicyDecisionRow{
		{ID: id2, ProposalID: propID, Effect: domain.PolicyEffectAllow, CreatedAt: t2},
		{ID: id1, ProposalID: propID, Effect: domain.PolicyEffectRequireRemediation, CreatedAt: t1},
	}

	svc := proposals.NewServiceWithStore(fake, nil, nil)
	ad, err := svc.ListAssessmentsAndDecisions(ctx, propID)
	if err != nil {
		t.Fatalf("ListAssessmentsAndDecisions: %v", err)
	}
	if len(ad.Assessments) != 2 || ad.Assessments[0].ID != id1 || ad.Assessments[1].ID != id2 {
		t.Fatalf("expected ascending chronological Assessments [id1, id2], got %+v", ad.Assessments)
	}
	if len(ad.PolicyDecisions) != 2 || ad.PolicyDecisions[0].ID != id1 || ad.PolicyDecisions[1].ID != id2 {
		t.Fatalf("expected ascending chronological PolicyDecisions [id1, id2], got %+v", ad.PolicyDecisions)
	}

	// Findings cursor pagination (limit=1 over 2 rows -> HasMore=true, NextCursor!="")
	f1, f2 := domain.MustNewID(), domain.MustNewID()
	fake.findings = []persistence.FindingRow{
		{ID: f1, Category: "SAST", Severity: domain.SeverityLow, RuleID: "r1", Fingerprint: "fp1", Redacted: true},
		{ID: f2, Category: "SAST", Severity: domain.SeverityLow, RuleID: "r2", Fingerprint: "fp2", Redacted: true},
	}
	fr, err := svc.ListFindings(ctx, proposals.ListFindingsFilter{ProposalID: propID, Limit: 1})
	if err != nil || !fr.HasMore || fr.NextCursor == "" || len(fr.Findings) != 1 || fr.Findings[0].ID != f1 {
		t.Fatalf("unexpected ListFindings page: (%+v, %v)", fr, err)
	}

	// Unredacted secret finding fails closed with 422 Unprocessable.
	fake.findings = []persistence.FindingRow{
		{ID: f1, Category: "SECRET", Severity: domain.SeverityCritical, RuleID: "gitleaks", Fingerprint: "fp", Redacted: false},
	}
	if _, err := svc.ListFindings(ctx, proposals.ListFindingsFilter{ProposalID: propID, Limit: 10}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for unredacted SECRET finding, got %v", err)
	}
}

func TestRequestEvaluationAndApplyPolicyDecisionEmitApprovalsRevokedEvents(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newBaseProposalFake()
	decID := domain.MustNewID()
	fake.proposal = persistence.ProposalRow{
		ID:                       domain.MustNewID(),
		WorkspaceID:              fake.workspace.ID,
		OwnerID:                  fake.workspace.OwnerID,
		Status:                   domain.ProposalStatusPendingApproval,
		LatestPolicyEvaluationID: &decID,
		Version:                  2,
	}
	svc := proposals.NewServiceWithStore(fake, nil, nil)

	res, err := svc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID:      fake.proposal.ID,
		ExpectedVersion: 2,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}
	if res.Proposal.Status != domain.ProposalStatusEvaluating {
		t.Fatalf("expected EVALUATING, got %s", res.Proposal.Status)
	}
	if fake.revokedCount != 1 || fake.resetReqCount != 1 {
		t.Fatalf("expected revokedCount=1 resetReqCount=1, got %d/%d", fake.revokedCount, fake.resetReqCount)
	}

	foundOutbox := false
	for _, ev := range fake.outboxEvents {
		if ev.EventType == "proposal.approvals_revoked" {
			foundOutbox = true
			break
		}
	}
	if !foundOutbox {
		t.Fatalf("expected proposal.approvals_revoked outbox event, got %+v", fake.outboxEvents)
	}

	foundAudit := false
	for _, ev := range fake.auditEvents {
		if ev.EventType == "proposal.approvals_revoked" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("expected proposal.approvals_revoked audit event, got %+v", fake.auditEvents)
	}
}
