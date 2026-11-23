package approvals

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

const maxCommentRunes = 4096

// Service manages digest-bound human approvals, separation of duties, group obligations, and revocation.
type Service struct {
	store   Store
	metrics *observability.Metrics
	logger  *slog.Logger
}

// NewService constructs an approvals Service backed by *persistence.Store.
func NewService(store *persistence.Store, metrics *observability.Metrics, logger *slog.Logger) *Service {
	var adapter Store
	if store != nil {
		adapter = NewStoreAdapter(store)
	}
	return NewServiceWithStore(adapter, metrics, logger)
}

// NewServiceWithStore constructs an approvals Service with a custom Store implementation.
func NewServiceWithStore(store Store, metrics *observability.Metrics, logger *slog.Logger) *Service {
	return &Service{
		store:   store,
		metrics: metrics,
		logger:  logger,
	}
}

// Submit atomically validates and records a human APPROVE or REJECT decision bound to
// the proposal's current manifest_digest and latest_policy_evaluation_id.
func (s *Service) Submit(ctx context.Context, input SubmitInput) (SubmitResult, error) {
	if s == nil || s.store == nil {
		return SubmitResult{}, domain.Unavailable("APPROVALS_UNAVAILABLE", "approvals store is not configured")
	}
	start := time.Now()
	if input.ProposalID == uuid.Nil {
		return SubmitResult{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	if input.ReviewerID == uuid.Nil {
		return SubmitResult{}, domain.BadRequest("INVALID_REVIEWER_ID", "reviewer_id must not be nil")
	}
	if input.PolicyEvaluationID == uuid.Nil {
		return SubmitResult{}, domain.BadRequest("INVALID_POLICY_EVALUATION_ID", "policy_evaluation_id must not be nil")
	}
	if input.ID != uuid.Nil && !domain.IsUUIDv7(input.ID) {
		return SubmitResult{}, domain.BadRequest("INVALID_ID", "approval id must be UUIDv7")
	}
	if !input.Decision.IsValid() {
		return SubmitResult{}, domain.BadRequest("INVALID_APPROVAL_DECISION", "decision must be APPROVE or REJECT")
	}
	if utf8.RuneCountInString(input.Comment) > maxCommentRunes {
		return SubmitResult{}, domain.BadRequest("COMMENT_TOO_LONG", "comment must not exceed 4096 characters")
	}
	manifestDigest, err := domain.ParseSHA256Digest(input.ManifestDigest)
	if err != nil {
		return SubmitResult{}, err
	}
	if input.ReviewerKind != "" && input.ReviewerKind != domain.PrincipalKindHuman {
		return SubmitResult{}, domain.Forbidden("NON_HUMAN_REVIEWER", "only HUMAN principals may approve or reject proposals")
	}

	var result SubmitResult
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		propRow, err := tx.GetProposalByIDForUpdate(ctx, input.ProposalID)
		if err != nil {
			return err
		}

		reviewerRow, err := tx.GetPrincipalByID(ctx, input.ReviewerID)
		if err != nil {
			return err
		}
		if reviewerRow.Kind != domain.PrincipalKindHuman {
			return domain.Forbidden("NON_HUMAN_REVIEWER", "only HUMAN principals may approve or reject proposals")
		}
		if input.ReviewerKind != "" && input.ReviewerKind != reviewerRow.Kind {
			return domain.Forbidden("NON_HUMAN_REVIEWER", "reviewer principal kind mismatch")
		}
		if input.ReviewerID == propRow.OwnerID {
			return domain.Forbidden("SOD_SELF_APPROVAL_FORBIDDEN", "proposal owner cannot approve or reject their own proposal")
		}

		if !propRow.Status.CanApprove() {
			return domain.Conflict("PROPOSAL_NOT_PENDING_APPROVAL", "proposal is not in PENDING_APPROVAL status")
		}
		if propRow.LatestPolicyEffect != nil && propRow.LatestPolicyEffect.BlocksPublication() {
			return domain.Conflict("POLICY_BLOCKED", "proposal is blocked by policy effect")
		}
		if propRow.LatestPolicyEvaluationID == nil || *propRow.LatestPolicyEvaluationID != input.PolicyEvaluationID {
			return domain.Conflict("POLICY_EVALUATION_MISMATCH", "policy_evaluation_id does not match proposal's latest policy evaluation")
		}
		if propRow.ManifestDigest == nil || *propRow.ManifestDigest == "" || !strings.EqualFold(manifestDigest, *propRow.ManifestDigest) {
			return domain.Conflict("MANIFEST_DIGEST_MISMATCH", "publication_manifest_digest does not match proposal's current manifest digest")
		}

		decisionID := *propRow.LatestPolicyEvaluationID
		now := time.Now().UTC().Truncate(time.Microsecond)

		if input.Decision == domain.ApprovalDecisionReject {
			// Revoke prior active approvals BEFORE inserting the new REJECT record because
			// RevokeApprovalsForProposal revokes all unrevoked rows for proposal_id.
			if _, err := tx.RevokeApprovalsForProposal(ctx, propRow.ID, now); err != nil {
				return err
			}
			if _, err := tx.ResetApprovalRequirementsForPolicyDecision(ctx, decisionID); err != nil {
				return err
			}

			appRow, err := tx.CreateApproval(ctx, persistence.CreateApprovalParams{
				ID:               input.ID,
				ProposalID:       propRow.ID,
				ReviewerID:       input.ReviewerID,
				PolicyDecisionID: decisionID,
				ManifestDigest:   manifestDigest,
				Decision:         domain.ApprovalDecisionReject,
				Comment:          input.Comment,
				CreatedAt:        now,
			})
			if err != nil {
				return err
			}

			fromStatus := domain.ProposalStatusPendingApproval
			updatedProp, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
				ID:              propRow.ID,
				FromStatus:      &fromStatus,
				ToStatus:        domain.ProposalStatusRejected,
				ExpectedVersion: propRow.Version,
				UpdatedAt:       now,
			})
			if err != nil {
				return err
			}

			payload, err := marshalApprovalEventPayload(appRow, updatedProp.Status, updatedProp.Version, 0)
			if err != nil {
				return err
			}
			if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
				EventType:   "proposal.rejected",
				AggregateID: propRow.ID,
				Payload:     payload,
			}); err != nil {
				return err
			}
			if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
				EventType:    "proposal.rejected",
				ActorID:      &input.ReviewerID,
				ResourceType: "proposal",
				ResourceID:   propRow.ID,
				Payload:      payload,
				CreatedAt:    now,
			}, s.logger); err != nil {
				return err
			}

			result = SubmitResult{
				Approval:             appRow.ToDomain(),
				ProposalStatus:       updatedProp.Status,
				ProposalVersion:      updatedProp.Version,
				RemainingObligations: []domain.Obligation{},
				CreatedAt:            appRow.CreatedAt.UTC(),
			}
			return nil
		}

		// APPROVE path
		exists, err := tx.HasActiveApprovalByReviewer(ctx, propRow.ID, decisionID, input.ReviewerID, manifestDigest)
		if err != nil {
			return err
		}
		if exists {
			return domain.Conflict("DUPLICATE_APPROVAL", "reviewer already has an active approval for this policy evaluation and manifest digest")
		}

		reqs, err := tx.ListApprovalRequirementsByPolicyDecision(ctx, decisionID)
		if err != nil {
			return err
		}

		reviewerGroups := normalizeGroupSet(input.ReviewerGroups, reviewerRow.Groups)
		unsatisfiedCount := 0
		matchedIndices := make([]int, 0, len(reqs))
		for i, req := range reqs {
			if isRequirementSatisfied(req) {
				continue
			}
			unsatisfiedCount++
			if hasGroup(reviewerGroups, req.ReviewerGroup) {
				matchedIndices = append(matchedIndices, i)
			}
		}

		if unsatisfiedCount > 0 && len(matchedIndices) == 0 {
			return domain.Forbidden("REVIEWER_GROUP_MISMATCH", "reviewer is not a member of any unsatisfied required reviewer group")
		}

		for _, idx := range matchedIndices {
			updatedReq, err := tx.IncrementApprovalRequirementSatisfaction(ctx, reqs[idx].ID, now)
			if err != nil {
				return err
			}
			reqs[idx] = updatedReq
		}

		appRow, err := tx.CreateApproval(ctx, persistence.CreateApprovalParams{
			ID:               input.ID,
			ProposalID:       propRow.ID,
			ReviewerID:       input.ReviewerID,
			PolicyDecisionID: decisionID,
			ManifestDigest:   manifestDigest,
			Decision:         domain.ApprovalDecisionApprove,
			Comment:          input.Comment,
			CreatedAt:        now,
		})
		if err != nil {
			return err
		}

		remaining := remainingObligations(reqs)
		finalStatus := propRow.Status
		finalVersion := propRow.Version

		if len(remaining) == 0 {
			activeApprovals, err := tx.ListActiveApprovalsForDecision(ctx, propRow.ID, decisionID, manifestDigest)
			if err != nil {
				return err
			}
			if hasValidHumanApproval(activeApprovals, propRow.OwnerID, manifestDigest) {
				fromStatus := domain.ProposalStatusPendingApproval
				updatedProp, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
					ID:              propRow.ID,
					FromStatus:      &fromStatus,
					ToStatus:        domain.ProposalStatusApproved,
					ExpectedVersion: propRow.Version,
					UpdatedAt:       now,
				})
				if err != nil {
					return err
				}
				finalStatus = updatedProp.Status
				finalVersion = updatedProp.Version
			}
		}

		eventType := "proposal.approval_recorded"
		if finalStatus == domain.ProposalStatusApproved {
			eventType = "proposal.approved"
		}
		payload, err := marshalApprovalEventPayload(appRow, finalStatus, finalVersion, len(remaining))
		if err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   eventType,
			AggregateID: propRow.ID,
			Payload:     payload,
		}); err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    eventType,
			ActorID:      &input.ReviewerID,
			ResourceType: "proposal",
			ResourceID:   propRow.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		result = SubmitResult{
			Approval:             appRow.ToDomain(),
			ProposalStatus:       finalStatus,
			ProposalVersion:      finalVersion,
			RemainingObligations: remaining,
			CreatedAt:            appRow.CreatedAt.UTC(),
		}
		return nil
	})
	if err != nil {
		if s.metrics != nil {
			s.metrics.ObserveWorkflow("approval", "submit", "error", time.Since(start))
		}
		return SubmitResult{}, err
	}

	if s.metrics != nil {
		s.metrics.ObserveWorkflow("approval", "submit", string(result.ProposalStatus), time.Since(start))
	}
	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.InfoContext(ctx, "approval recorded",
			"approval_id", result.Approval.ID.String(),
			"proposal_id", result.Approval.ProposalID.String(),
			"reviewer_id", result.Approval.ReviewerID.String(),
			"policy_decision_id", result.Approval.PolicyDecisionID.String(),
			"manifest_digest", result.Approval.ManifestDigest,
			"decision", string(result.Approval.Decision),
			"proposal_status", string(result.ProposalStatus),
		)
	}
	return result, nil
}

// ListByProposal returns all approvals (including revoked/rejected) for a proposal.
func (s *Service) ListByProposal(ctx context.Context, proposalID uuid.UUID) ([]domain.Approval, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("APPROVALS_UNAVAILABLE", "approvals store is not configured")
	}
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if _, err := s.store.GetProposalByID(ctx, proposalID); err != nil {
		return nil, err
	}
	rows, err := s.store.ListApprovalsByProposal(ctx, proposalID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Approval, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ToDomain())
	}
	return out, nil
}

// ListRequirements returns approval requirements for the proposal's active policy evaluation
// (or all proposal requirements if no policy evaluation is set yet).
func (s *Service) ListRequirements(ctx context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("APPROVALS_UNAVAILABLE", "approvals store is not configured")
	}
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	prop, err := s.store.GetProposalByID(ctx, proposalID)
	if err != nil {
		return nil, err
	}
	if prop.LatestPolicyEvaluationID != nil {
		return s.store.ListApprovalRequirementsByPolicyDecision(ctx, *prop.LatestPolicyEvaluationID)
	}
	return s.store.ListApprovalRequirementsByProposal(ctx, proposalID)
}

// RevokeStaleApprovals revokes active approvals and optionally resets requirement counters
// inside a new transaction, emitting audit and outbox events if any approvals were revoked.
func (s *Service) RevokeStaleApprovals(ctx context.Context, proposalID uuid.UUID, policyDecisionID *uuid.UUID, reason string) (int64, error) {
	if s == nil || s.store == nil {
		return 0, domain.Unavailable("APPROVALS_UNAVAILABLE", "approvals store is not configured")
	}
	if proposalID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	var count int64
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		if _, err := tx.GetProposalByIDForUpdate(ctx, proposalID); err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		var err error
		count, err = RevokeStaleApprovalsTx(ctx, tx, proposalID, policyDecisionID, reason, now, s.logger)
		return err
	})
	return count, err
}

// RevokeStaleApprovalsTx revokes unrevoked approvals for proposalID (and resets requirement counters
// when policyDecisionID is provided) inside an existing transaction.
func RevokeStaleApprovalsTx(
	ctx context.Context,
	tx RevokeStore,
	proposalID uuid.UUID,
	policyDecisionID *uuid.UUID,
	reason string,
	now time.Time,
	logger *slog.Logger,
) (int64, error) {
	if tx == nil {
		return 0, domain.Unavailable("APPROVALS_UNAVAILABLE", "approvals transaction store must not be nil")
	}
	if proposalID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if policyDecisionID != nil && *policyDecisionID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "policy_decision_id must not be nil when provided")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	revokedCount, err := tx.RevokeApprovalsForProposal(ctx, proposalID, now)
	if err != nil {
		return 0, err
	}
	if policyDecisionID != nil {
		if _, err := tx.ResetApprovalRequirementsForPolicyDecision(ctx, *policyDecisionID); err != nil {
			return 0, err
		}
	}
	if revokedCount > 0 {
		payloadMap := map[string]any{
			"proposal_id":   proposalID.String(),
			"revoked_count": revokedCount,
			"reason":        strings.TrimSpace(reason),
		}
		if policyDecisionID != nil {
			payloadMap["policy_decision_id"] = policyDecisionID.String()
		}
		rawPayload, err := domain.CanonicalJSONBytes(payloadMap)
		if err != nil {
			return 0, err
		}
		payload := json.RawMessage(rawPayload)
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.approvals_revoked",
			AggregateID: proposalID,
			Payload:     payload,
		}); err != nil {
			return 0, err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.approvals_revoked",
			ResourceType: "proposal",
			ResourceID:   proposalID,
			Payload:      payload,
			CreatedAt:    now,
		}, logger); err != nil {
			return 0, err
		}
	}
	return revokedCount, nil
}

// VerifyReadyForPublishTx fails closed unless proposal is APPROVED and bound to satisfied
// approval requirements and at least one active non-owner human approval matching its manifest digest.
func VerifyReadyForPublishTx(ctx context.Context, tx PublishVerifyStore, proposal persistence.ProposalRow) error {
	if !proposal.Status.CanPublish() {
		return domain.Conflict("PROPOSAL_NOT_APPROVED", "proposal must be in APPROVED status to publish")
	}
	return VerifyApprovalBindingTx(ctx, tx, proposal)
}

// VerifyApprovalBindingTx verifies fail-closed approval and obligation satisfaction for a proposal
// regardless of whether it is in APPROVED, PUBLISHING, or PUBLISHED status.
func VerifyApprovalBindingTx(ctx context.Context, tx PublishVerifyStore, proposal persistence.ProposalRow) error {
	if tx == nil {
		return domain.Unavailable("APPROVALS_UNAVAILABLE", "approvals store must not be nil")
	}
	if proposal.ManifestDigest == nil || *proposal.ManifestDigest == "" {
		return domain.Conflict("MISSING_MANIFEST_DIGEST", "proposal lacks a manifest_digest")
	}
	manifestDigest, err := domain.ParseSHA256Digest(*proposal.ManifestDigest)
	if err != nil {
		return domain.Conflict("INVALID_MANIFEST_DIGEST", "proposal manifest_digest is invalid")
	}
	if proposal.LatestPolicyEvaluationID == nil || *proposal.LatestPolicyEvaluationID == uuid.Nil {
		return domain.Conflict("MISSING_POLICY_EVALUATION", "proposal lacks a policy evaluation")
	}
	if proposal.LatestPolicyEffect == nil || proposal.LatestPolicyEffect.BlocksPublication() {
		return domain.Conflict("POLICY_BLOCKED", "proposal is blocked by policy effect")
	}

	decisionID := *proposal.LatestPolicyEvaluationID
	reqs, err := tx.ListApprovalRequirementsByPolicyDecision(ctx, decisionID)
	if err != nil {
		return err
	}
	for _, req := range reqs {
		if !isRequirementSatisfied(req) {
			return domain.Conflict("UNSATISFIED_APPROVAL_OBLIGATIONS", "proposal has unsatisfied approval requirements")
		}
	}

	activeApprovals, err := tx.ListActiveApprovalsForDecision(ctx, proposal.ID, decisionID, manifestDigest)
	if err != nil {
		return err
	}
	if !hasValidHumanApproval(activeApprovals, proposal.OwnerID, manifestDigest) {
		return domain.Conflict("MISSING_HUMAN_APPROVAL", "proposal lacks an active non-owner human approval for current manifest digest")
	}
	return nil
}

func isRequirementSatisfied(req persistence.ApprovalRequirementRow) bool {
	return req.SatisfiedCount >= req.MinimumApprovals && req.SatisfiedAt != nil
}

func remainingObligations(reqs []persistence.ApprovalRequirementRow) []domain.Obligation {
	out := make([]domain.Obligation, 0)
	for _, req := range reqs {
		rem := req.MinimumApprovals - req.SatisfiedCount
		if rem > 0 {
			out = append(out, domain.Obligation{
				Type:          req.RequirementType,
				ReviewerGroup: req.ReviewerGroup,
				Minimum:       rem,
			})
		}
	}
	return out
}

func hasValidHumanApproval(rows []persistence.ApprovalRow, ownerID uuid.UUID, manifestDigest string) bool {
	for _, row := range rows {
		if row.ReviewerID == ownerID {
			continue
		}
		if row.ToDomain().IsActiveForManifest(manifestDigest) {
			return true
		}
	}
	return false
}

func normalizeGroupSet(groups ...[]string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, list := range groups {
		for _, g := range list {
			trimmed := strings.ToLower(strings.TrimSpace(g))
			if trimmed != "" {
				out[trimmed] = struct{}{}
			}
		}
	}
	return out
}

func hasGroup(set map[string]struct{}, group string) bool {
	_, ok := set[strings.ToLower(strings.TrimSpace(group))]
	return ok
}

func marshalApprovalEventPayload(app persistence.ApprovalRow, proposalStatus domain.ProposalStatus, proposalVersion int64, remainingCount int) (json.RawMessage, error) {
	canonical, err := domain.CanonicalJSONBytes(map[string]any{
		"approval_id":                 app.ID.String(),
		"proposal_id":                 app.ProposalID.String(),
		"reviewer_id":                 app.ReviewerID.String(),
		"policy_decision_id":          app.PolicyDecisionID.String(),
		"manifest_digest":             app.ManifestDigest,
		"decision":                    string(app.Decision),
		"proposal_status":             string(proposalStatus),
		"proposal_version":            proposalVersion,
		"remaining_obligations_count": remainingCount,
	})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}
