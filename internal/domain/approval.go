package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type ApprovalDecision string

const (
	ApprovalDecisionApprove ApprovalDecision = "APPROVE"
	ApprovalDecisionReject  ApprovalDecision = "REJECT"
)

func (d ApprovalDecision) IsValid() bool {
	switch d {
	case ApprovalDecisionApprove, ApprovalDecisionReject:
		return true
	default:
		return false
	}
}

type Approval struct {
	ID               uuid.UUID        `json:"id"`
	ProposalID       uuid.UUID        `json:"proposal_id"`
	ReviewerID       uuid.UUID        `json:"reviewer_id"`
	PolicyDecisionID uuid.UUID        `json:"policy_decision_id"`
	ManifestDigest   string           `json:"manifest_digest"`
	Decision         ApprovalDecision `json:"decision"`
	Comment          string           `json:"comment,omitempty"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
}

// IsActiveForManifest reports whether the approval is unrevoked, APPROVE, and bound to manifestDigest.
func (a Approval) IsActiveForManifest(manifestDigest string) bool {
	if a.RevokedAt != nil || a.Decision != ApprovalDecisionApprove {
		return false
	}
	expected, err := ParseSHA256Digest(manifestDigest)
	if err != nil {
		return false
	}
	actual, err := ParseSHA256Digest(a.ManifestDigest)
	if err != nil {
		return false
	}
	return strings.EqualFold(actual, expected)
}
