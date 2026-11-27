package domain

import (
	"time"

	"github.com/google/uuid"
)

type ProposalStatus string

const (
	ProposalStatusCaptured            ProposalStatus = "CAPTURED"
	ProposalStatusReconstructing      ProposalStatus = "RECONSTRUCTING"
	ProposalStatusReconstructed       ProposalStatus = "RECONSTRUCTED"
	ProposalStatusEvaluating          ProposalStatus = "EVALUATING"
	ProposalStatusPendingApproval     ProposalStatus = "PENDING_APPROVAL"
	ProposalStatusDenied              ProposalStatus = "DENIED"
	ProposalStatusQuarantined         ProposalStatus = "QUARANTINED"
	ProposalStatusRemediationRequired ProposalStatus = "REMEDIATION_REQUIRED"
	ProposalStatusRejected            ProposalStatus = "REJECTED"
	ProposalStatusApproved            ProposalStatus = "APPROVED"
	ProposalStatusPublishing          ProposalStatus = "PUBLISHING"
	ProposalStatusPublished           ProposalStatus = "PUBLISHED"
	ProposalStatusFailed              ProposalStatus = "FAILED"
)

func (s ProposalStatus) IsValid() bool {
	switch s {
	case ProposalStatusCaptured,
		ProposalStatusReconstructing,
		ProposalStatusReconstructed,
		ProposalStatusEvaluating,
		ProposalStatusPendingApproval,
		ProposalStatusDenied,
		ProposalStatusQuarantined,
		ProposalStatusRemediationRequired,
		ProposalStatusRejected,
		ProposalStatusApproved,
		ProposalStatusPublishing,
		ProposalStatusPublished,
		ProposalStatusFailed:
		return true
	default:
		return false
	}
}

func (s ProposalStatus) IsTerminal() bool {
	switch s {
	case ProposalStatusDenied,
		ProposalStatusQuarantined,
		ProposalStatusRejected,
		ProposalStatusPublished,
		ProposalStatusFailed:
		return true
	default:
		return false
	}
}

func (s ProposalStatus) CanApprove() bool {
	return s == ProposalStatusPendingApproval
}

func (s ProposalStatus) CanPublish() bool {
	return s == ProposalStatusApproved
}

type Proposal struct {
	ID                  uuid.UUID      `json:"id"`
	WorkspaceID         uuid.UUID      `json:"workspace_id"`
	OwnerID             uuid.UUID      `json:"owner_id"`
	SnapshotArtifactID  uuid.UUID      `json:"snapshot_artifact_id"`
	CanonicalArtifactID *uuid.UUID     `json:"canonical_artifact_id,omitempty"`
	ManifestArtifactID  *uuid.UUID     `json:"manifest_artifact_id,omitempty"`
	ManifestDigest      string         `json:"manifest_digest,omitempty"`
	BaseCommit          string         `json:"base_commit"`
	TargetRef           string         `json:"target_ref"`
	Title               string         `json:"title,omitempty"`
	Description         string         `json:"description,omitempty"`
	Status              ProposalStatus `json:"status"`
	Version             int64          `json:"version"`
	CreatedAt           time.Time      `json:"created_at"`
}
