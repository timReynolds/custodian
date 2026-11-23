package approvals_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

type fakeApprovalStore struct {
	proposal        persistence.ProposalRow
	getProposalErr  error
	principals      map[uuid.UUID]persistence.PrincipalRow
	requirements    []persistence.ApprovalRequirementRow
	activeApprovals []persistence.ApprovalRow
	hasActive       bool
	created         []persistence.ApprovalRow
	revokedCount    int64
	resetCount      int64
	transitionedTo  *domain.ProposalStatus
	auditSeq        int64
	lastHash        string
}

func (f *fakeApprovalStore) GetProposalByIDForUpdate(_ context.Context, _ uuid.UUID) (persistence.ProposalRow, error) {
	if f.getProposalErr != nil {
		return persistence.ProposalRow{}, f.getProposalErr
	}
	return f.proposal, nil
}

func (f *fakeApprovalStore) GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	return f.GetProposalByIDForUpdate(ctx, id)
}

func (f *fakeApprovalStore) GetPrincipalByID(_ context.Context, id uuid.UUID) (persistence.PrincipalRow, error) {
	p, ok := f.principals[id]
	if !ok {
		return persistence.PrincipalRow{}, domain.NotFound("PRINCIPAL_NOT_FOUND", "principal not found")
	}
	return p, nil
}

func (f *fakeApprovalStore) CreateApproval(_ context.Context, arg persistence.CreateApprovalParams) (persistence.ApprovalRow, error) {
	id := arg.ID
	if id == uuid.Nil {
		id = domain.MustNewID()
	}
	var comment *string
	if arg.Comment != "" {
		c := arg.Comment
		comment = &c
	}
	row := persistence.ApprovalRow{
		ID:               id,
		ProposalID:       arg.ProposalID,
		ReviewerID:       arg.ReviewerID,
		PolicyDecisionID: arg.PolicyDecisionID,
		ManifestDigest:   arg.ManifestDigest,
		Decision:         arg.Decision,
		Comment:          comment,
		CreatedAt:        arg.CreatedAt,
	}
	f.created = append(f.created, row)
	if arg.Decision == domain.ApprovalDecisionApprove {
		f.activeApprovals = append(f.activeApprovals, row)
	}
	return row, nil
}

func (f *fakeApprovalStore) ListApprovalsByProposal(_ context.Context, _ uuid.UUID) ([]persistence.ApprovalRow, error) {
	return append([]persistence.ApprovalRow(nil), f.created...), nil
}

func (f *fakeApprovalStore) ListActiveApprovalsForDecision(_ context.Context, _, _ uuid.UUID, _ string) ([]persistence.ApprovalRow, error) {
	return append([]persistence.ApprovalRow(nil), f.activeApprovals...), nil
}

func (f *fakeApprovalStore) HasActiveApprovalByReviewer(_ context.Context, _, _, _ uuid.UUID, _ string) (bool, error) {
	return f.hasActive, nil
}

func (f *fakeApprovalStore) RevokeApprovalsForProposal(_ context.Context, _ uuid.UUID, _ time.Time) (int64, error) {
	f.revokedCount++
	f.activeApprovals = nil
	return 1, nil
}

func (f *fakeApprovalStore) ListApprovalRequirementsByProposal(_ context.Context, _ uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	return append([]persistence.ApprovalRequirementRow(nil), f.requirements...), nil
}

func (f *fakeApprovalStore) ListApprovalRequirementsByPolicyDecision(_ context.Context, _ uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	return append([]persistence.ApprovalRequirementRow(nil), f.requirements...), nil
}

func (f *fakeApprovalStore) IncrementApprovalRequirementSatisfaction(_ context.Context, id uuid.UUID, now time.Time) (persistence.ApprovalRequirementRow, error) {
	for i := range f.requirements {
		if f.requirements[i].ID == id {
			f.requirements[i].SatisfiedCount++
			if f.requirements[i].SatisfiedCount >= f.requirements[i].MinimumApprovals && f.requirements[i].SatisfiedAt == nil {
				ts := now
				f.requirements[i].SatisfiedAt = &ts
			}
			return f.requirements[i], nil
		}
	}
	return persistence.ApprovalRequirementRow{}, domain.NotFound("REQ_NOT_FOUND", "not found")
}

func (f *fakeApprovalStore) ResetApprovalRequirementsForPolicyDecision(_ context.Context, _ uuid.UUID) (int64, error) {
	f.resetCount++
	for i := range f.requirements {
		f.requirements[i].SatisfiedCount = 0
		f.requirements[i].SatisfiedAt = nil
	}
	return int64(len(f.requirements)), nil
}

func (f *fakeApprovalStore) TransitionProposalStatus(_ context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error) {
	to := arg.ToStatus
	f.transitionedTo = &to
	f.proposal.Status = to
	f.proposal.Version++
	f.proposal.UpdatedAt = arg.UpdatedAt
	return f.proposal, nil
}

func (f *fakeApprovalStore) EnqueueOperation(_ context.Context, _ persistence.EnqueueOperationParams) (persistence.OperationRow, error) {
	return persistence.OperationRow{}, nil
}

func (f *fakeApprovalStore) EnqueueOutboxEvent(_ context.Context, arg persistence.EnqueueOutboxParams) (persistence.OutboxEventRow, error) {
	return persistence.OutboxEventRow{
		ID:          domain.MustNewID(),
		EventType:   arg.EventType,
		AggregateID: arg.AggregateID,
		Payload:     arg.Payload,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func (f *fakeApprovalStore) LockAuditChainHead(_ context.Context) (persistence.AuditChainHeadRow, error) {
	var lastHash *string
	if f.lastHash != "" {
		h := f.lastHash
		lastHash = &h
	}
	return persistence.AuditChainHeadRow{
		ChainID:       "main",
		EventCount:    f.auditSeq,
		LastEventHash: lastHash,
	}, nil
}

func (f *fakeApprovalStore) NormalizeJSONB(_ context.Context, payload json.RawMessage) (json.RawMessage, error) {
	return payload, nil
}

func (f *fakeApprovalStore) UpdateAuditChainHead(_ context.Context, _ uuid.UUID, eventHash string, eventCount int64, _ time.Time) error {
	f.auditSeq = eventCount
	f.lastHash = eventHash
	return nil
}

func (f *fakeApprovalStore) InsertAuditEvent(_ context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	return persistence.AuditEventRow{
		ID:           arg.ID,
		ChainSeq:     arg.ChainSeq,
		EventType:    arg.EventType,
		ActorID:      arg.ActorID,
		ResourceType: arg.ResourceType,
		ResourceID:   arg.ResourceID,
		Payload:      arg.Payload,
		EventHash:    arg.EventHash,
		CreatedAt:    arg.CreatedAt,
	}, nil
}

func (f *fakeApprovalStore) RunInTx(_ context.Context, fn func(tx approvals.TxStore) error) error {
	return fn(f)
}

func TestApprovalsValidationAndErrorMappingUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Nil store -> 503 Unavailable.
	nilSvc := approvals.NewService(nil, nil, nil)
	if _, err := nilSvc.Submit(ctx, approvals.SubmitInput{}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store Submit: expected ErrUnavailable, got %v", err)
	}
	if _, err := nilSvc.ListByProposal(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store ListByProposal: expected ErrUnavailable, got %v", err)
	}
	if _, err := nilSvc.ListRequirements(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store ListRequirements: expected ErrUnavailable, got %v", err)
	}
	if _, err := nilSvc.RevokeStaleApprovals(ctx, domain.MustNewID(), nil, "stale"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil store RevokeStaleApprovals: expected ErrUnavailable, got %v", err)
	}

	ownerID := domain.MustNewID()
	reviewerID := domain.MustNewID()
	agentID := domain.MustNewID()
	propID := domain.MustNewID()
	decisionID := domain.MustNewID()
	digest := domain.SHA256Hex([]byte("manifest"))
	effectAllow := domain.PolicyEffectAllow

	baseFake := func() *fakeApprovalStore {
		return &fakeApprovalStore{
			proposal: persistence.ProposalRow{
				ID:                       propID,
				OwnerID:                  ownerID,
				ManifestDigest:           &digest,
				LatestPolicyEvaluationID: &decisionID,
				LatestPolicyEffect:       &effectAllow,
				Status:                   domain.ProposalStatusPendingApproval,
				Version:                  2,
			},
			principals: map[uuid.UUID]persistence.PrincipalRow{
				ownerID:    {ID: ownerID, Kind: domain.PrincipalKindHuman, Groups: []string{"security-team"}},
				reviewerID: {ID: reviewerID, Kind: domain.PrincipalKindHuman, Groups: []string{"engineering"}},
				agentID:    {ID: agentID, Kind: domain.PrincipalKindAgent},
			},
		}
	}

	svc := approvals.NewServiceWithStore(baseFake(), nil, nil)

	// Input validation (400 BadRequest).
	badInputs := []approvals.SubmitInput{
		{ReviewerID: reviewerID, PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest},
		{ProposalID: propID, PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest},
		{ProposalID: propID, ReviewerID: reviewerID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest},
		{ProposalID: propID, ReviewerID: reviewerID, PolicyEvaluationID: decisionID, Decision: "MAYBE", ManifestDigest: digest},
		{ProposalID: propID, ReviewerID: reviewerID, PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: "bad"},
		{ProposalID: propID, ReviewerID: reviewerID, PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest, Comment: strings.Repeat("x", 4097)},
		{ProposalID: propID, ReviewerID: reviewerID, PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest, Comment: strings.Repeat("é", 4097)},
		{ID: uuid.MustParse("00000000-0000-4000-8000-000000000001"), ProposalID: propID, ReviewerID: reviewerID, PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest},
	}
	for i, in := range badInputs {
		if _, err := svc.Submit(ctx, in); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("badInput[%d]: expected ErrBadRequest, got %v", i, err)
		}
	}

	// Non-HUMAN ReviewerKind -> 403 Forbidden.
	for _, k := range []domain.PrincipalKind{domain.PrincipalKindAgent, domain.PrincipalKindService} {
		if _, err := svc.Submit(ctx, approvals.SubmitInput{
			ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: k,
			PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
		}); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("non-human kind %s: expected ErrForbidden, got %v", k, err)
		}
	}

	// DB principal is AGENT even when ReviewerKind is empty -> 403 Forbidden.
	if _, err := svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: agentID,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("DB agent principal: expected ErrForbidden, got %v", err)
	}

	// SoD self-approval -> 403 Forbidden.
	if _, err := svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: ownerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-approval: expected ErrForbidden, got %v", err)
	}

	// Non-PENDING_APPROVAL -> 409 Conflict.
	fakeNotPending := baseFake()
	fakeNotPending.proposal.Status = domain.ProposalStatusReconstructed
	if _, err := approvals.NewServiceWithStore(fakeNotPending, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("non-PENDING_APPROVAL: expected ErrConflict, got %v", err)
	}

	// Blocking policy effect -> 409 Conflict.
	fakeBlocked := baseFake()
	effDeny := domain.PolicyEffectDeny
	fakeBlocked.proposal.LatestPolicyEffect = &effDeny
	if _, err := approvals.NewServiceWithStore(fakeBlocked, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("blocking effect: expected ErrConflict, got %v", err)
	}

	// Wrong PolicyEvaluationID -> 409 Conflict.
	if _, err := svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: domain.MustNewID(), Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("wrong eval ID: expected ErrConflict, got %v", err)
	}

	// Wrong ManifestDigest -> 409 Conflict.
	if _, err := svc.Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: strings.Repeat("b", 64),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("wrong digest: expected ErrConflict, got %v", err)
	}

	// Duplicate active approval -> 409 Conflict.
	fakeDup := baseFake()
	fakeDup.hasActive = true
	if _, err := approvals.NewServiceWithStore(fakeDup, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate approval: expected ErrConflict, got %v", err)
	}

	// Wrong reviewer group when obligations exist -> 403 Forbidden.
	fakeGroup := baseFake()
	fakeGroup.requirements = []persistence.ApprovalRequirementRow{{
		ID: domain.MustNewID(), ProposalID: propID, PolicyDecisionID: decisionID,
		RequirementType: "HUMAN_REVIEW", ReviewerGroup: "platform-owners", MinimumApprovals: 1,
	}}
	if _, err := approvals.NewServiceWithStore(fakeGroup, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("wrong reviewer group: expected ErrForbidden, got %v", err)
	}

	// sha256: prefixed uppercase digest normalizes cleanly; RemainingObligations is non-nil [] and decrements properly.
	fakePartial := baseFake()
	fakePartial.requirements = []persistence.ApprovalRequirementRow{{
		ID: domain.MustNewID(), ProposalID: propID, PolicyDecisionID: decisionID,
		RequirementType: "SECURITY_REVIEW", ReviewerGroup: "security-team", MinimumApprovals: 2,
	}}
	res, err := approvals.NewServiceWithStore(fakePartial, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		ReviewerGroups:     []string{"Security-Team"},
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove,
		ManifestDigest: "sha256:" + strings.ToUpper(digest),
	})
	if err != nil {
		t.Fatalf("partial approve: %v", err)
	}
	if res.Approval.ManifestDigest != digest || res.ProposalStatus != domain.ProposalStatusPendingApproval {
		t.Fatalf("unexpected partial approve result: %+v", res)
	}
	if len(res.RemainingObligations) != 1 || res.RemainingObligations[0].Minimum != 1 || res.RemainingObligations[0].ReviewerGroup != "security-team" {
		t.Fatalf("unexpected remaining obligations: %+v", res.RemainingObligations)
	}

	// VerifyReadyForPublishTx fails closed when status != APPROVED, obligations unsatisfied, or active approvals missing.
	if err := approvals.VerifyReadyForPublishTx(ctx, fakePartial, fakePartial.proposal); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("VerifyReadyForPublishTx(PENDING_APPROVAL): expected ErrConflict, got %v", err)
	}
	fakePartial.proposal.Status = domain.ProposalStatusApproved
	if err := approvals.VerifyReadyForPublishTx(ctx, fakePartial, fakePartial.proposal); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("VerifyReadyForPublishTx(unsatisfied req): expected ErrConflict, got %v", err)
	}

	// ALLOW with 0 obligations -> RemainingObligations is non-nil empty slice [], status APPROVED.
	fakeAllow := baseFake()
	allowRes, err := approvals.NewServiceWithStore(fakeAllow, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove, ManifestDigest: digest,
	})
	if err != nil {
		t.Fatalf("allow approve: %v", err)
	}
	if allowRes.RemainingObligations == nil || len(allowRes.RemainingObligations) != 0 || allowRes.ProposalStatus != domain.ProposalStatusApproved {
		t.Fatalf("unexpected allow approve result: %+v", allowRes)
	}
	rawRem, _ := json.Marshal(allowRes.RemainingObligations)
	if string(rawRem) != "[]" {
		t.Fatalf("expected JSON [], got %s", string(rawRem))
	}
	if err := approvals.VerifyReadyForPublishTx(ctx, fakeAllow, fakeAllow.proposal); err != nil {
		t.Fatalf("VerifyReadyForPublishTx(valid APPROVED): %v", err)
	}

	// Exact 4096 multi-byte UTF-8 rune comment (8192 bytes) must be accepted.
	fakeUTF8 := baseFake()
	exactUTF8Comment := strings.Repeat("é", 4096)
	utf8Res, err := approvals.NewServiceWithStore(fakeUTF8, nil, nil).Submit(ctx, approvals.SubmitInput{
		ProposalID: propID, ReviewerID: reviewerID, ReviewerKind: domain.PrincipalKindHuman,
		PolicyEvaluationID: decisionID, Decision: domain.ApprovalDecisionApprove,
		ManifestDigest: digest, Comment: exactUTF8Comment,
	})
	if err != nil {
		t.Fatalf("exact 4096 multi-byte UTF-8 comment: %v", err)
	}
	if utf8Res.Approval.Comment != exactUTF8Comment || utf8Res.ProposalStatus != domain.ProposalStatusApproved {
		t.Fatalf("unexpected UTF-8 boundary approval result: status=%s comment_len=%d", utf8Res.ProposalStatus, len(utf8Res.Approval.Comment))
	}
}
