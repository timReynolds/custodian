package persistence

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// --- approvals ---

type CreateApprovalParams struct {
	ID               uuid.UUID
	ProposalID       uuid.UUID
	ReviewerID       uuid.UUID
	PolicyDecisionID uuid.UUID
	ManifestDigest   string
	Decision         domain.ApprovalDecision
	Comment          string
	CreatedAt        time.Time
}

const createApprovalSQL = `
INSERT INTO approvals (
    id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
`

func (q *Queries) CreateApproval(ctx context.Context, arg CreateApprovalParams) (ApprovalRow, error) {
	if arg.ProposalID == uuid.Nil || arg.ReviewerID == uuid.Nil || arg.PolicyDecisionID == uuid.Nil {
		return ApprovalRow{}, domain.BadRequest("INVALID_APPROVAL", "proposal_id, reviewer_id, and policy_decision_id are required")
	}
	manifestDigest, err := domain.ParseSHA256Digest(arg.ManifestDigest)
	if err != nil {
		return ApprovalRow{}, err
	}
	if !arg.Decision.IsValid() {
		return ApprovalRow{}, domain.BadRequest("INVALID_APPROVAL_DECISION", "invalid approval decision")
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return ApprovalRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return ApprovalRow{}, domain.BadRequest("INVALID_ID", "approval id must be UUIDv7")
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)

	var row ApprovalRow
	err = scanApprovalRow(q.db.QueryRow(ctx, createApprovalSQL,
		id,
		arg.ProposalID,
		arg.ReviewerID,
		arg.PolicyDecisionID,
		manifestDigest,
		string(arg.Decision),
		nilIfEmpty(arg.Comment),
		createdAt,
	), &row)
	if err != nil {
		return ApprovalRow{}, MapError(err)
	}
	return row, nil
}

const getApprovalByIDSQL = `
SELECT id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
FROM approvals
WHERE id = $1
`

func (q *Queries) GetApprovalByID(ctx context.Context, id uuid.UUID) (ApprovalRow, error) {
	if id == uuid.Nil {
		return ApprovalRow{}, domain.BadRequest("INVALID_ID", "approval id must not be nil")
	}
	var row ApprovalRow
	err := scanApprovalRow(q.db.QueryRow(ctx, getApprovalByIDSQL, id), &row)
	if err != nil {
		return ApprovalRow{}, MapError(err)
	}
	return row, nil
}

const listApprovalsByProposalSQL = `
SELECT id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
FROM approvals
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC
`

func (q *Queries) ListApprovalsByProposal(ctx context.Context, proposalID uuid.UUID) ([]ApprovalRow, error) {
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listApprovalsByProposalSQL, proposalID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ApprovalRow, 0)
	for rows.Next() {
		var row ApprovalRow
		if err := scanApprovalRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const listActiveApprovalsForDecisionSQL = `
SELECT id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
FROM approvals
WHERE proposal_id = $1
  AND policy_decision_id = $2
  AND manifest_digest = $3
  AND decision = 'APPROVE'
  AND revoked_at IS NULL
ORDER BY created_at ASC, id ASC
`

func (q *Queries) ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]ApprovalRow, error) {
	if proposalID == uuid.Nil || policyDecisionID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id and policy_decision_id must not be nil")
	}
	digest, err := domain.ParseSHA256Digest(manifestDigest)
	if err != nil {
		return nil, err
	}
	rows, err := q.db.Query(ctx, listActiveApprovalsForDecisionSQL, proposalID, policyDecisionID, digest)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ApprovalRow, 0)
	for rows.Next() {
		var row ApprovalRow
		if err := scanApprovalRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const hasActiveApprovalByReviewerSQL = `
SELECT EXISTS (
    SELECT 1
    FROM approvals
    WHERE proposal_id = $1
      AND policy_decision_id = $2
      AND reviewer_id = $3
      AND manifest_digest = $4
      AND decision = 'APPROVE'
      AND revoked_at IS NULL
)
`

func (q *Queries) HasActiveApprovalByReviewer(ctx context.Context, proposalID, policyDecisionID, reviewerID uuid.UUID, manifestDigest string) (bool, error) {
	if proposalID == uuid.Nil || policyDecisionID == uuid.Nil || reviewerID == uuid.Nil {
		return false, domain.BadRequest("INVALID_ID", "proposal_id, policy_decision_id, and reviewer_id must not be nil")
	}
	digest, err := domain.ParseSHA256Digest(manifestDigest)
	if err != nil {
		return false, err
	}
	var exists bool
	if err := q.db.QueryRow(ctx, hasActiveApprovalByReviewerSQL, proposalID, policyDecisionID, reviewerID, digest).Scan(&exists); err != nil {
		return false, MapError(err)
	}
	return exists, nil
}

const revokeApprovalsForProposalSQL = `
UPDATE approvals
SET revoked_at = $2
WHERE proposal_id = $1
  AND revoked_at IS NULL
`

func (q *Queries) RevokeApprovalsForProposal(ctx context.Context, proposalID uuid.UUID, revokedAt time.Time) (int64, error) {
	if proposalID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	ts := normalizeTimestamp(revokedAt)
	tag, err := q.db.Exec(ctx, revokeApprovalsForProposalSQL, proposalID, ts)
	if err != nil {
		return 0, MapError(err)
	}
	return tag.RowsAffected(), nil
}

// --- approval_requirements ---

type CreateApprovalRequirementParams struct {
	ID               uuid.UUID
	ProposalID       uuid.UUID
	PolicyDecisionID uuid.UUID
	RequirementType  string
	ReviewerGroup    string
	MinimumApprovals int
	CreatedAt        time.Time
}

const createApprovalRequirementSQL = `
INSERT INTO approval_requirements (
    id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, 0, $7
)
RETURNING id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
`

func (q *Queries) CreateApprovalRequirement(ctx context.Context, arg CreateApprovalRequirementParams) (ApprovalRequirementRow, error) {
	if arg.ProposalID == uuid.Nil || arg.PolicyDecisionID == uuid.Nil {
		return ApprovalRequirementRow{}, domain.BadRequest("INVALID_APPROVAL_REQUIREMENT", "proposal_id and policy_decision_id are required")
	}
	if arg.RequirementType == "" || arg.ReviewerGroup == "" {
		return ApprovalRequirementRow{}, domain.BadRequest("INVALID_APPROVAL_REQUIREMENT", "requirement_type and reviewer_group must not be empty")
	}
	if arg.MinimumApprovals < 1 {
		return ApprovalRequirementRow{}, domain.BadRequest("INVALID_MINIMUM_APPROVALS", "minimum_approvals must be >= 1")
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return ApprovalRequirementRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return ApprovalRequirementRow{}, domain.BadRequest("INVALID_ID", "approval_requirement id must be UUIDv7")
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)

	var row ApprovalRequirementRow
	err := scanApprovalRequirementRow(q.db.QueryRow(ctx, createApprovalRequirementSQL,
		id,
		arg.ProposalID,
		arg.PolicyDecisionID,
		arg.RequirementType,
		arg.ReviewerGroup,
		arg.MinimumApprovals,
		createdAt,
	), &row)
	if err != nil {
		return ApprovalRequirementRow{}, MapError(err)
	}
	return row, nil
}

const getApprovalRequirementByIDSQL = `
SELECT id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
FROM approval_requirements
WHERE id = $1
`

func (q *Queries) GetApprovalRequirementByID(ctx context.Context, id uuid.UUID) (ApprovalRequirementRow, error) {
	if id == uuid.Nil {
		return ApprovalRequirementRow{}, domain.BadRequest("INVALID_ID", "approval_requirement id must not be nil")
	}
	var row ApprovalRequirementRow
	if err := scanApprovalRequirementRow(q.db.QueryRow(ctx, getApprovalRequirementByIDSQL, id), &row); err != nil {
		return ApprovalRequirementRow{}, MapError(err)
	}
	return row, nil
}

const listApprovalRequirementsByProposalSQL = `
SELECT id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
FROM approval_requirements
WHERE proposal_id = $1
ORDER BY created_at ASC, id ASC
`

func (q *Queries) ListApprovalRequirementsByProposal(ctx context.Context, proposalID uuid.UUID) ([]ApprovalRequirementRow, error) {
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listApprovalRequirementsByProposalSQL, proposalID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ApprovalRequirementRow, 0)
	for rows.Next() {
		var row ApprovalRequirementRow
		if err := scanApprovalRequirementRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const listApprovalRequirementsByPolicyDecisionSQL = `
SELECT id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
FROM approval_requirements
WHERE policy_decision_id = $1
ORDER BY created_at ASC, id ASC
`

func (q *Queries) ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]ApprovalRequirementRow, error) {
	if policyDecisionID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "policy_decision_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listApprovalRequirementsByPolicyDecisionSQL, policyDecisionID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ApprovalRequirementRow, 0)
	for rows.Next() {
		var row ApprovalRequirementRow
		if err := scanApprovalRequirementRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const incrementApprovalRequirementSatisfactionSQL = `
UPDATE approval_requirements
SET satisfied_count = satisfied_count + 1,
    satisfied_at    = CASE
        WHEN satisfied_count + 1 >= minimum_approvals AND satisfied_at IS NULL THEN $2
        ELSE satisfied_at
    END
WHERE id = $1
RETURNING id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
`

func (q *Queries) IncrementApprovalRequirementSatisfaction(ctx context.Context, id uuid.UUID, now time.Time) (ApprovalRequirementRow, error) {
	if id == uuid.Nil {
		return ApprovalRequirementRow{}, domain.BadRequest("INVALID_ID", "approval_requirement id must not be nil")
	}
	ts := normalizeTimestamp(now)
	var row ApprovalRequirementRow
	err := scanApprovalRequirementRow(q.db.QueryRow(ctx, incrementApprovalRequirementSatisfactionSQL, id, ts), &row)
	if err != nil {
		return ApprovalRequirementRow{}, MapError(err)
	}
	return row, nil
}

const resetApprovalRequirementsForPolicyDecisionSQL = `
UPDATE approval_requirements
SET satisfied_count = 0,
    satisfied_at    = NULL
WHERE policy_decision_id = $1
`

func (q *Queries) ResetApprovalRequirementsForPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) (int64, error) {
	if policyDecisionID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "policy_decision_id must not be nil")
	}
	tag, err := q.db.Exec(ctx, resetApprovalRequirementsForPolicyDecisionSQL, policyDecisionID)
	if err != nil {
		return 0, MapError(err)
	}
	return tag.RowsAffected(), nil
}

// --- scan helpers ---

func scanApprovalRow(s rowScanner, row *ApprovalRow) error {
	var decision string
	if err := s.Scan(
		&row.ID,
		&row.ProposalID,
		&row.ReviewerID,
		&row.PolicyDecisionID,
		&row.ManifestDigest,
		&decision,
		&row.Comment,
		&row.RevokedAt,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Decision = domain.ApprovalDecision(decision)
	return nil
}

func scanApprovalRequirementRow(s rowScanner, row *ApprovalRequirementRow) error {
	return s.Scan(
		&row.ID,
		&row.ProposalID,
		&row.PolicyDecisionID,
		&row.RequirementType,
		&row.ReviewerGroup,
		&row.MinimumApprovals,
		&row.SatisfiedCount,
		&row.SatisfiedAt,
		&row.CreatedAt,
	)
}
