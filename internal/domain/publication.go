package domain

import (
	"time"

	"github.com/google/uuid"
)

type PublicationStatus string

const (
	PublicationStatusPending    PublicationStatus = "PENDING"
	PublicationStatusPublishing PublicationStatus = "PUBLISHING"
	PublicationStatusPublished  PublicationStatus = "PUBLISHED"
	PublicationStatusFailed     PublicationStatus = "FAILED"
)

func (s PublicationStatus) IsValid() bool {
	switch s {
	case PublicationStatusPending, PublicationStatusPublishing, PublicationStatusPublished, PublicationStatusFailed:
		return true
	default:
		return false
	}
}

type Publication struct {
	ID                uuid.UUID         `json:"id"`
	ProposalID        uuid.UUID         `json:"proposal_id"`
	BranchRef         string            `json:"branch_ref"`
	CommitSHA         string            `json:"commit_sha,omitempty"`
	PullRequestNumber *int64            `json:"pull_request_number,omitempty"`
	PullRequestURL    string            `json:"pull_request_url,omitempty"`
	Status            PublicationStatus `json:"status"`
	AttemptCount      int               `json:"attempt_count"`
	CreatedAt         time.Time         `json:"created_at"`
}

// ExpectedBranchName returns the broker-owned branch name custodian/<proposal-id>.
func ExpectedBranchName(proposalID uuid.UUID) string {
	return "custodian/" + proposalID.String()
}

// ExpectedBranchRef returns the full Git ref refs/heads/custodian/<proposal-id>.
func ExpectedBranchRef(proposalID uuid.UUID) string {
	return "refs/heads/" + ExpectedBranchName(proposalID)
}

// ValidateBranchRef rejects any branch outside custodian/<proposal-id> or refs/heads/custodian/<proposal-id>.
func ValidateBranchRef(proposalID uuid.UUID, branchRef string) error {
	if proposalID == uuid.Nil {
		return BadRequest("INVALID_PROPOSAL_ID", "proposal ID must not be nil")
	}
	if branchRef == ExpectedBranchName(proposalID) || branchRef == ExpectedBranchRef(proposalID) {
		return nil
	}
	return Forbidden("INVALID_PUBLICATION_BRANCH", "publication is restricted to custodian/<proposal-id>")
}
