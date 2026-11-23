package approvals

import (
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// SubmitInput specifies parameters for recording a human APPROVE or REJECT decision.
type SubmitInput struct {
	ID                 uuid.UUID
	ProposalID         uuid.UUID
	ReviewerID         uuid.UUID
	ReviewerKind       domain.PrincipalKind
	ReviewerGroups     []string
	Decision           domain.ApprovalDecision
	ManifestDigest     string
	PolicyEvaluationID uuid.UUID
	Comment            string
}

// SubmitResult returns the persisted approval, updated proposal state, and remaining obligations.
type SubmitResult struct {
	Approval             domain.Approval       `json:"approval"`
	ProposalStatus       domain.ProposalStatus `json:"proposal_status"`
	ProposalVersion      int64                 `json:"proposal_version"`
	RemainingObligations []domain.Obligation   `json:"remaining_obligations"`
	CreatedAt            time.Time             `json:"created_at"`
}
