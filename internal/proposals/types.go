package proposals

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
)

// OwnerRef identifies the accountable human owner of a proposal.
type OwnerRef struct {
	PrincipalID      uuid.UUID            `json:"principal_id"`
	Kind             domain.PrincipalKind `json:"kind"`
	IdentityProvider string               `json:"identity_provider"`
	Subject          string               `json:"subject,omitempty"`
	DisplayName      string               `json:"display_name,omitempty"`
}

// ProposalDetails enriches domain.Proposal with repository, workspace origin, provenance, and policy metadata.
type ProposalDetails struct {
	domain.Proposal
	RepositoryID             uuid.UUID             `json:"repository_id"`
	GitHubRepositoryID       int64                 `json:"github_repository_id"`
	RepositoryFullName       string                `json:"repository_full_name"`
	RepositoryClassification domain.Classification `json:"repository_classification"`
	WorkspaceAgentID         *uuid.UUID            `json:"workspace_agent_id,omitempty"`
	WorkspaceAgentSessionID  string                `json:"workspace_agent_session_id,omitempty"`
	WorkspaceModelRoute      string                `json:"workspace_model_route,omitempty"`
	WorkspaceGeneration      int64                 `json:"workspace_generation"`
	Owner                    OwnerRef              `json:"owner"`
	DiffArtifactID           *uuid.UUID            `json:"diff_artifact_id,omitempty"`
	ProvenanceType           string                `json:"provenance_type"`
	CaptureMethod            string                `json:"capture_method"`
	TreeDigest               string                `json:"tree_digest,omitempty"`
	DiffDigest               string                `json:"diff_digest,omitempty"`
	LatestPolicyEvaluationID *uuid.UUID            `json:"latest_policy_evaluation_id,omitempty"`
	LatestPolicyEffect       *domain.PolicyEffect  `json:"latest_policy_effect,omitempty"`
	UpdatedAt                time.Time             `json:"updated_at"`
}

// SubmitInput defines parameters for submitting a captured egress snapshot as a Change Proposal.
type SubmitInput struct {
	ID                  uuid.UUID
	WorkspaceID         uuid.UUID
	ActorID             *uuid.UUID
	SnapshotArtifactID  uuid.UUID
	SnapshotSHA256      string
	WorkspaceGeneration int64
	SizeBytes           int64
	CapturedAt          *time.Time
	Title               string
	Description         string
	ProvenanceType      string
	CaptureMethod       string
}

// SubmitResult returns the newly created proposal, hydrated details, and PROPOSAL_RECONSTRUCT operation.
type SubmitResult struct {
	Proposal  domain.Proposal             `json:"proposal"`
	Details   ProposalDetails             `json:"details"`
	Operation operations.OperationDetails `json:"operation"`
}

// EvaluateInput specifies parameters for requesting 3-stage policy evaluation of a proposal.
type EvaluateInput struct {
	ProposalID      uuid.UUID
	ExpectedVersion int64
	ActorID         *uuid.UUID
}

// EvaluateResult returns the updated proposal and enqueued PROPOSAL_EVALUATE operation.
type EvaluateResult struct {
	Proposal  domain.Proposal             `json:"proposal"`
	Operation operations.OperationDetails `json:"operation"`
}

// PublishRequestInput specifies parameters for requesting publication of an approved proposal.
type PublishRequestInput struct {
	ProposalID                uuid.UUID
	PublicationManifestDigest string
	ActorID                   *uuid.UUID
}

// PublishRequestResult returns the proposal, publication record, and PROPOSAL_PUBLISH operation.
type PublishRequestResult struct {
	Proposal    domain.Proposal             `json:"proposal"`
	Publication domain.Publication          `json:"publication"`
	Operation   operations.OperationDetails `json:"operation"`
}

// BeginReconstructionInput specifies parameters for transitioning a proposal into RECONSTRUCTING.
type BeginReconstructionInput struct {
	ProposalID      uuid.UUID
	ExpectedVersion int64
	ActorID         *uuid.UUID
}

// CompleteReconstructionInput specifies canonical artifacts and digests produced by Stage 0 reconstruction.
type CompleteReconstructionInput struct {
	ProposalID          uuid.UUID
	ExpectedVersion     int64
	CanonicalArtifactID uuid.UUID
	DiffArtifactID      *uuid.UUID
	ManifestArtifactID  uuid.UUID
	TreeDigest          string
	DiffDigest          string
	ManifestDigest      string
	ActorID             *uuid.UUID
}

// ApplyPolicyDecisionInput specifies the Stage C policy decision and obligations to persist atomically.
type ApplyPolicyDecisionInput struct {
	ProposalID      uuid.UUID
	ExpectedVersion int64
	PolicyBundleID  uuid.UUID
	OrgBundleID     *uuid.UUID
	RepoBundleID    *uuid.UUID
	Stage           string
	InputDigest     string
	Effect          domain.PolicyEffect
	Reasons         []domain.PolicyReason
	Obligations     []domain.Obligation
	ActorID         *uuid.UUID
}

// ListFindingsFilter specifies filters and keyset cursor pagination for proposal findings.
type ListFindingsFilter struct {
	ProposalID uuid.UUID
	Scanner    string
	Severity   *domain.Severity
	Cursor     string
	Limit      int
}

// ListFindingsResult returns scan runs and redacted findings for a proposal.
type ListFindingsResult struct {
	ProposalID uuid.UUID        `json:"proposal_id"`
	ScanRuns   []domain.ScanRun `json:"scan_runs"`
	Findings   []domain.Finding `json:"findings"`
	NextCursor string           `json:"next_cursor,omitempty"`
	HasMore    bool             `json:"has_more"`
}

// AssessmentsAndDecisions returns model assessments and policy decisions in ascending chronological order.
type AssessmentsAndDecisions struct {
	ProposalID      uuid.UUID                `json:"proposal_id"`
	Assessments     []domain.ModelAssessment `json:"assessments"`
	PolicyDecisions []domain.PolicyDecision  `json:"policy_decisions"`
}

// PolicyDeniedError is returned by RequestPublish when a proposal is blocked by a persisted
// policy decision (DENIED, QUARANTINED, REMEDIATION_REQUIRED).
// Unwrap returns a *domain.DomainError with ErrConflict (HTTP 409) so HTTPStatusFromError
// resolves to 409 Conflict while callers can inspect PolicyDecisionID and Effect via errors.As.
type PolicyDeniedError struct {
	PolicyDecisionID uuid.UUID
	Effect           domain.PolicyEffect
	ProposalStatus   domain.ProposalStatus
	Err              *domain.DomainError
}

func (e *PolicyDeniedError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("%s (policy_decision_id=%s effect=%s)", e.Err.Error(), e.PolicyDecisionID, e.Effect)
	}
	return fmt.Sprintf("proposal blocked by policy decision %s (%s)", e.PolicyDecisionID, e.Effect)
}

func (e *PolicyDeniedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *PolicyDeniedError) Is(target error) bool {
	if e == nil || e.Err == nil {
		return false
	}
	return errors.Is(e.Err, target)
}
