package persistence

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// PrincipalRow represents a row in principals.
type PrincipalRow struct {
	ID            uuid.UUID            `json:"id"`
	Kind          domain.PrincipalKind `json:"kind"`
	Issuer        *string              `json:"issuer,omitempty"`
	Subject       *string              `json:"subject,omitempty"`
	DisplayName   *string              `json:"display_name,omitempty"`
	VerifiedEmail *string              `json:"verified_email,omitempty"`
	Groups        []string             `json:"groups"`
	CreatedAt     time.Time            `json:"created_at"`
}

// ToDomain converts PrincipalRow to domain.Principal.
func (r PrincipalRow) ToDomain() domain.Principal {
	return domain.Principal{
		ID:            r.ID,
		Kind:          r.Kind,
		Issuer:        derefString(r.Issuer),
		Subject:       derefString(r.Subject),
		DisplayName:   derefString(r.DisplayName),
		VerifiedEmail: derefString(r.VerifiedEmail),
		CreatedAt:     r.CreatedAt.UTC(),
	}
}

// RepositoryRow represents a row in repositories.
type RepositoryRow struct {
	ID                      uuid.UUID                   `json:"id"`
	GitHubRepositoryID      int64                       `json:"github_repository_id"`
	GitHubInstallationID    int64                       `json:"github_installation_id"`
	FullName                string                      `json:"full_name"`
	Classification          domain.Classification       `json:"classification"`
	Enabled                 bool                        `json:"enabled"`
	AllowedModelRoutes      []string                    `json:"allowed_model_routes"`
	MaxConcurrentOperations int                         `json:"max_concurrent_operations"`
	EgressMode              domain.EgressMode           `json:"egress_mode"`
	PassiveAuditDelivery    domain.PassiveAuditDelivery `json:"passive_audit_delivery"`
	GitRemoteURL            *string                     `json:"git_remote_url,omitempty"`
	RemoteHost              string                      `json:"remote_host"`
	RegisteredDestination   bool                        `json:"registered_destination"`
	External                bool                        `json:"external"`
	CreatedAt               time.Time                   `json:"created_at"`
}

// ToDomain converts RepositoryRow to domain.Repository.
func (r RepositoryRow) ToDomain() domain.Repository {
	return domain.Repository{
		ID:                    r.ID,
		GitHubRepositoryID:    r.GitHubRepositoryID,
		GitHubInstallationID:  r.GitHubInstallationID,
		FullName:              r.FullName,
		Classification:        r.Classification,
		Enabled:               r.Enabled,
		EgressMode:            r.EgressMode,
		PassiveAuditDelivery:  r.PassiveAuditDelivery,
		GitRemoteURL:          derefString(r.GitRemoteURL),
		RemoteHost:            r.RemoteHost,
		RegisteredDestination: r.RegisteredDestination,
		External:              r.External,
	}
}

// WorkspaceRow represents a row in workspaces.
type WorkspaceRow struct {
	ID                 uuid.UUID              `json:"id"`
	RepositoryID       uuid.UUID              `json:"repository_id"`
	OwnerID            uuid.UUID              `json:"owner_id"`
	AgentID            *uuid.UUID             `json:"agent_id,omitempty"`
	AgentType          *string                `json:"agent_type,omitempty"`
	AgentSessionID     *string                `json:"agent_session_id,omitempty"`
	ModelRoute         *string                `json:"model_route,omitempty"`
	BaseCommit         string                 `json:"base_commit"`
	TargetRef          string                 `json:"target_ref"`
	SourceArtifactID   *uuid.UUID             `json:"source_artifact_id,omitempty"`
	IncludeGitMetadata bool                   `json:"include_git_metadata"`
	IncludeHistory     bool                   `json:"include_history"`
	Generation         int64                  `json:"generation"`
	Status             domain.WorkspaceStatus `json:"status"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// ToDomain converts WorkspaceRow to domain.Workspace.
func (r WorkspaceRow) ToDomain() domain.Workspace {
	return domain.Workspace{
		ID:               r.ID,
		RepositoryID:     r.RepositoryID,
		OwnerID:          r.OwnerID,
		AgentID:          r.AgentID,
		AgentSessionID:   derefString(r.AgentSessionID),
		ModelRoute:       derefString(r.ModelRoute),
		BaseCommit:       r.BaseCommit,
		TargetRef:        r.TargetRef,
		SourceArtifactID: r.SourceArtifactID,
		Generation:       r.Generation,
		Status:           r.Status,
		CreatedAt:        r.CreatedAt.UTC(),
	}
}

// WorkspaceDetailsRow joins workspace metadata with repository and owner principal info.
type WorkspaceDetailsRow struct {
	Workspace          WorkspaceRow `json:"workspace"`
	GitHubRepositoryID int64        `json:"github_repository_id"`
	RepositoryFullName string       `json:"repository_full_name"`
	OwnerIssuer        *string      `json:"owner_issuer,omitempty"`
	OwnerSubject       *string      `json:"owner_subject,omitempty"`
	OwnerDisplayName   *string      `json:"owner_display_name,omitempty"`
}

// ArtifactRow represents a row in artifacts.
type ArtifactRow struct {
	ID                  uuid.UUID           `json:"id"`
	Kind                domain.ArtifactKind `json:"kind"`
	SHA256              string              `json:"sha256"`
	StorageKey          string              `json:"storage_key"`
	StorageGeneration   string              `json:"storage_generation"`
	SizeBytes           int64               `json:"size_bytes"`
	Format              string              `json:"format"`
	WorkspaceID         *uuid.UUID          `json:"workspace_id,omitempty"`
	WorkspaceGeneration *int64              `json:"workspace_generation,omitempty"`
	UploadedBy          *uuid.UUID          `json:"uploaded_by,omitempty"`
	ExpiresAt           *time.Time          `json:"expires_at,omitempty"`
	DeletedAt           *time.Time          `json:"deleted_at,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
}

// ToDomain converts ArtifactRow to domain.Artifact.
func (r ArtifactRow) ToDomain() domain.Artifact {
	return domain.Artifact{
		ID:                r.ID,
		Kind:              r.Kind,
		SHA256:            r.SHA256,
		StorageKey:        r.StorageKey,
		StorageGeneration: r.StorageGeneration,
		SizeBytes:         r.SizeBytes,
		CreatedAt:         r.CreatedAt.UTC(),
	}
}

// OperationRow represents a row in operations.
type OperationRow struct {
	ID            uuid.UUID              `json:"id"`
	OperationType domain.OperationType   `json:"operation_type"`
	ResourceType  *string                `json:"resource_type,omitempty"`
	ResourceID    uuid.UUID              `json:"resource_id"`
	Status        domain.OperationStatus `json:"status"`
	Attempts      int                    `json:"attempts"`
	MaxAttempts   int                    `json:"max_attempts"`
	AvailableAt   time.Time              `json:"available_at"`
	LeaseUntil    *time.Time             `json:"lease_until,omitempty"`
	LeasedBy      *string                `json:"leased_by,omitempty"`
	LastError     *string                `json:"last_error,omitempty"`
	Result        json.RawMessage        `json:"result,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
	Reclaimed     bool                   `json:"-"`
}

// ToDomain converts OperationRow to domain.Operation.
func (r OperationRow) ToDomain() domain.Operation {
	return domain.Operation{
		ID:            r.ID,
		OperationType: r.OperationType,
		ResourceID:    r.ResourceID,
		Status:        r.Status,
		Attempts:      r.Attempts,
		AvailableAt:   r.AvailableAt.UTC(),
		LeaseUntil:    utcPtr(r.LeaseUntil),
		LastError:     derefString(r.LastError),
		CreatedAt:     r.CreatedAt.UTC(),
	}
}

// OutboxEventRow represents a row in outbox_events.
type OutboxEventRow struct {
	ID          uuid.UUID       `json:"id"`
	EventType   string          `json:"event_type"`
	AggregateID uuid.UUID       `json:"aggregate_id"`
	Payload     json.RawMessage `json:"payload"`
	Attempts    int             `json:"attempts"`
	AvailableAt time.Time       `json:"available_at"`
	LeaseUntil  *time.Time      `json:"lease_until,omitempty"`
	LeasedBy    *string         `json:"leased_by,omitempty"`
	LastError   *string         `json:"last_error,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
}

// ToDomain converts OutboxEventRow to domain.OutboxEvent.
func (r OutboxEventRow) ToDomain() domain.OutboxEvent {
	return domain.OutboxEvent{
		ID:          r.ID,
		EventType:   r.EventType,
		AggregateID: r.AggregateID,
		Payload:     r.Payload,
		CreatedAt:   r.CreatedAt.UTC(),
		DeliveredAt: utcPtr(r.DeliveredAt),
	}
}

// AuditChainHeadRow represents a row in audit_chain_head.
type AuditChainHeadRow struct {
	ChainID       string     `json:"chain_id"`
	LastEventID   *uuid.UUID `json:"last_event_id,omitempty"`
	LastEventHash *string    `json:"last_event_hash,omitempty"`
	EventCount    int64      `json:"event_count"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// AuditEventRow represents a row in audit_events.
type AuditEventRow struct {
	ID           uuid.UUID       `json:"id"`
	ChainSeq     int64           `json:"chain_seq"`
	EventType    string          `json:"event_type"`
	ActorID      *uuid.UUID      `json:"actor_id,omitempty"`
	ResourceType string          `json:"resource_type"`
	ResourceID   uuid.UUID       `json:"resource_id"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash *string         `json:"previous_hash,omitempty"`
	EventHash    string          `json:"event_hash"`
	CreatedAt    time.Time       `json:"created_at"`
}

// ToDomain converts AuditEventRow to domain.AuditEvent.
func (r AuditEventRow) ToDomain() domain.AuditEvent {
	return domain.AuditEvent{
		ID:           r.ID,
		EventType:    r.EventType,
		ActorID:      r.ActorID,
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		Payload:      r.Payload,
		PreviousHash: derefString(r.PreviousHash),
		EventHash:    r.EventHash,
		CreatedAt:    r.CreatedAt.UTC(),
	}
}

// IdempotencyKeyRow represents a row in idempotency_keys.
type IdempotencyKeyRow struct {
	PrincipalID     uuid.UUID       `json:"principal_id"`
	Method          string          `json:"method"`
	Route           string          `json:"route"`
	IdempotencyKey  string          `json:"idempotency_key"`
	RequestHash     string          `json:"request_hash"`
	Status          string          `json:"status"`
	ResponseStatus  *int            `json:"response_status,omitempty"`
	ResponseHeaders json.RawMessage `json:"response_headers"`
	ResponseBody    json.RawMessage `json:"response_body,omitempty"`
	LockedUntil     time.Time       `json:"locked_until"`
	CreatedAt       time.Time       `json:"created_at"`
	CompletedAt     *time.Time      `json:"completed_at,omitempty"`
	ExpiresAt       time.Time       `json:"expires_at"`
}

// ProposalRow represents a row in proposals.
type ProposalRow struct {
	ID                       uuid.UUID             `json:"id"`
	WorkspaceID              uuid.UUID             `json:"workspace_id"`
	OwnerID                  uuid.UUID             `json:"owner_id"`
	SnapshotArtifactID       uuid.UUID             `json:"snapshot_artifact_id"`
	CanonicalArtifactID      *uuid.UUID            `json:"canonical_artifact_id,omitempty"`
	DiffArtifactID           *uuid.UUID            `json:"diff_artifact_id,omitempty"`
	ManifestArtifactID       *uuid.UUID            `json:"manifest_artifact_id,omitempty"`
	BaseCommit               string                `json:"base_commit"`
	TargetRef                string                `json:"target_ref"`
	Title                    string                `json:"title"`
	Description              *string               `json:"description,omitempty"`
	ProvenanceType           string                `json:"provenance_type"`
	CaptureMethod            string                `json:"capture_method"`
	TreeDigest               *string               `json:"tree_digest,omitempty"`
	DiffDigest               *string               `json:"diff_digest,omitempty"`
	ManifestDigest           *string               `json:"manifest_digest,omitempty"`
	LatestPolicyEvaluationID *uuid.UUID            `json:"latest_policy_evaluation_id,omitempty"`
	LatestPolicyEffect       *domain.PolicyEffect  `json:"latest_policy_effect,omitempty"`
	Status                   domain.ProposalStatus `json:"status"`
	Version                  int64                 `json:"version"`
	CreatedAt                time.Time             `json:"created_at"`
	UpdatedAt                time.Time             `json:"updated_at"`
}

// ToDomain converts ProposalRow to domain.Proposal.
func (r ProposalRow) ToDomain() domain.Proposal {
	return domain.Proposal{
		ID:                  r.ID,
		WorkspaceID:         r.WorkspaceID,
		OwnerID:             r.OwnerID,
		SnapshotArtifactID:  r.SnapshotArtifactID,
		CanonicalArtifactID: r.CanonicalArtifactID,
		ManifestArtifactID:  r.ManifestArtifactID,
		ManifestDigest:      derefString(r.ManifestDigest),
		BaseCommit:          r.BaseCommit,
		TargetRef:           r.TargetRef,
		Title:               r.Title,
		Description:         derefString(r.Description),
		Status:              r.Status,
		Version:             r.Version,
		CreatedAt:           r.CreatedAt.UTC(),
	}
}

// ProposalDetailsRow joins proposal metadata with workspace, repository, and owner principal info.
type ProposalDetailsRow struct {
	Proposal                 ProposalRow           `json:"proposal"`
	RepositoryID             uuid.UUID             `json:"repository_id"`
	GitHubRepositoryID       int64                 `json:"github_repository_id"`
	RepositoryFullName       string                `json:"repository_full_name"`
	RepositoryClassification domain.Classification `json:"repository_classification"`
	WorkspaceAgentID         *uuid.UUID            `json:"workspace_agent_id,omitempty"`
	WorkspaceAgentSessionID  *string               `json:"workspace_agent_session_id,omitempty"`
	WorkspaceModelRoute      *string               `json:"workspace_model_route,omitempty"`
	WorkspaceGeneration      int64                 `json:"workspace_generation"`
	OwnerKind                domain.PrincipalKind  `json:"owner_kind"`
	OwnerIssuer              *string               `json:"owner_issuer,omitempty"`
	OwnerSubject             *string               `json:"owner_subject,omitempty"`
	OwnerDisplayName         *string               `json:"owner_display_name,omitempty"`
}

// ScanRunRow represents a row in scan_runs.
type ScanRunRow struct {
	ID             uuid.UUID         `json:"id"`
	ProposalID     uuid.UUID         `json:"proposal_id"`
	PushSessionID  *uuid.UUID        `json:"push_session_id,omitempty"`
	ArtifactID     uuid.UUID         `json:"artifact_id"`
	Scanner        string            `json:"scanner"`
	ScannerVersion string            `json:"scanner_version"`
	Status         domain.ScanStatus `json:"status"`
	Coverage       json.RawMessage   `json:"coverage"`
	StartedAt      time.Time         `json:"started_at"`
	CompletedAt    *time.Time        `json:"completed_at,omitempty"`
}

// ToDomain converts ScanRunRow to domain.ScanRun.
func (r ScanRunRow) ToDomain() domain.ScanRun {
	var coverage domain.ScanCoverage
	if len(r.Coverage) > 0 {
		_ = json.Unmarshal(r.Coverage, &coverage)
	}
	if coverage.SkippedReasons == nil {
		coverage.SkippedReasons = []string{}
	}
	return domain.ScanRun{
		ID:             r.ID,
		ProposalID:     r.ProposalID,
		PushSessionID:  r.PushSessionID,
		ArtifactID:     r.ArtifactID,
		Scanner:        r.Scanner,
		ScannerVersion: r.ScannerVersion,
		Status:         r.Status,
		Coverage:       coverage,
		StartedAt:      r.StartedAt.UTC(),
		CompletedAt:    utcPtr(r.CompletedAt),
	}
}

// FindingRow represents a row in findings.
type FindingRow struct {
	ID                 uuid.UUID       `json:"id"`
	ScanRunID          uuid.UUID       `json:"scan_run_id"`
	EvidenceID         *string         `json:"evidence_id,omitempty"`
	Scanner            *string         `json:"scanner,omitempty"`
	Category           string          `json:"category"`
	Severity           domain.Severity `json:"severity"`
	RuleID             string          `json:"rule_id"`
	Path               *string         `json:"path,omitempty"`
	StartLine          *int            `json:"start_line,omitempty"`
	EndLine            *int            `json:"end_line,omitempty"`
	Fingerprint        string          `json:"fingerprint"`
	EvidenceArtifactID *uuid.UUID      `json:"evidence_artifact_id,omitempty"`
	EvidenceRef        *string         `json:"evidence_ref,omitempty"`
	Baseline           *string         `json:"baseline,omitempty"`
	Confidence         *float64        `json:"confidence,omitempty"`
	Message            *string         `json:"message,omitempty"`
	Redacted           bool            `json:"redacted"`
	Metadata           json.RawMessage `json:"metadata"`
}

// ToDomain converts FindingRow to domain.Finding.
func (r FindingRow) ToDomain() domain.Finding {
	metadata := make(map[string]any)
	if len(r.Metadata) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(r.Metadata, &parsed); err == nil && parsed != nil {
			metadata = parsed
		}
	}
	return domain.Finding{
		ID:                 r.ID,
		ScanRunID:          r.ScanRunID,
		EvidenceID:         derefString(r.EvidenceID),
		Scanner:            derefString(r.Scanner),
		Category:           r.Category,
		Severity:           r.Severity,
		RuleID:             r.RuleID,
		Path:               derefString(r.Path),
		StartLine:          derefInt(r.StartLine),
		EndLine:            derefInt(r.EndLine),
		Fingerprint:        r.Fingerprint,
		EvidenceArtifactID: r.EvidenceArtifactID,
		EvidenceRef:        derefString(r.EvidenceRef),
		Baseline:           derefString(r.Baseline),
		Confidence:         derefFloat64(r.Confidence),
		Message:            derefString(r.Message),
		Redacted:           r.Redacted,
		Metadata:           metadata,
	}
}

// ModelAssessmentRow represents a row in model_assessments.
type ModelAssessmentRow struct {
	ID             uuid.UUID               `json:"id"`
	ProposalID     uuid.UUID               `json:"proposal_id"`
	PushSessionID  *uuid.UUID              `json:"push_session_id,omitempty"`
	ArtifactID     uuid.UUID               `json:"artifact_id"`
	ModelRoute     string                  `json:"model_route"`
	ModelVersion   string                  `json:"model_version"`
	PromptVersion  string                  `json:"prompt_version"`
	AssessmentType string                  `json:"assessment_type"`
	Status         domain.AssessmentStatus `json:"status"`
	Risk           *domain.RiskLevel       `json:"risk,omitempty"`
	Disposition    *domain.Disposition     `json:"disposition,omitempty"`
	Result         json.RawMessage         `json:"result"`
	EvidenceIDs    json.RawMessage         `json:"evidence_ids"`
	InputDigest    string                  `json:"input_digest"`
	OutputDigest   string                  `json:"output_digest"`
	CreatedAt      time.Time               `json:"created_at"`
}

// ToDomain converts ModelAssessmentRow to domain.ModelAssessment.
func (r ModelAssessmentRow) ToDomain() domain.ModelAssessment {
	var res domain.AssessmentResult
	if len(r.Result) > 0 {
		_ = json.Unmarshal(r.Result, &res)
	}
	if res.Findings == nil {
		res.Findings = []domain.AssessmentFinding{}
	}
	for i := range res.Findings {
		if res.Findings[i].EvidenceIDs == nil {
			res.Findings[i].EvidenceIDs = []string{}
		}
	}
	if res.Limitations == nil {
		res.Limitations = []string{}
	}

	evidenceIDs := []string{}
	if len(r.EvidenceIDs) > 0 {
		var parsed []string
		if err := json.Unmarshal(r.EvidenceIDs, &parsed); err == nil && parsed != nil {
			evidenceIDs = parsed
		}
	}

	var risk domain.RiskLevel
	if r.Risk != nil {
		risk = *r.Risk
	}
	var disp domain.Disposition
	if r.Disposition != nil {
		disp = *r.Disposition
	}

	return domain.ModelAssessment{
		ID:             r.ID,
		ProposalID:     r.ProposalID,
		PushSessionID:  r.PushSessionID,
		ArtifactID:     r.ArtifactID,
		ModelRoute:     r.ModelRoute,
		ModelVersion:   r.ModelVersion,
		PromptVersion:  r.PromptVersion,
		AssessmentType: r.AssessmentType,
		Status:         r.Status,
		Risk:           risk,
		Disposition:    disp,
		Result:         res,
		EvidenceIDs:    evidenceIDs,
		InputDigest:    r.InputDigest,
		OutputDigest:   r.OutputDigest,
		CreatedAt:      r.CreatedAt.UTC(),
	}
}

// PolicyBundleRow represents a row in policy_bundles.
type PolicyBundleRow struct {
	ID           uuid.UUID          `json:"id"`
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	Scope        domain.PolicyScope `json:"scope"`
	RepositoryID *uuid.UUID         `json:"repository_id,omitempty"`
	Digest       string             `json:"digest"`
	Definition   json.RawMessage    `json:"definition"`
	ActivatedAt  *time.Time         `json:"activated_at,omitempty"`
	CreatedAt    time.Time          `json:"created_at"`
}

// ToDomain converts PolicyBundleRow to domain.PolicyBundle.
func (r PolicyBundleRow) ToDomain() domain.PolicyBundle {
	def := r.Definition
	if len(bytes.TrimSpace(def)) == 0 {
		def = json.RawMessage("{}")
	}
	return domain.PolicyBundle{
		ID:          r.ID,
		Name:        r.Name,
		Version:     r.Version,
		Scope:       r.Scope,
		Digest:      r.Digest,
		Definition:  def,
		ActivatedAt: utcPtr(r.ActivatedAt),
	}
}

// PolicyDecisionRow represents a row in policy_decisions.
type PolicyDecisionRow struct {
	ID             uuid.UUID           `json:"id"`
	ProposalID     uuid.UUID           `json:"proposal_id"`
	PushSessionID  *uuid.UUID          `json:"push_session_id,omitempty"`
	PolicyBundleID uuid.UUID           `json:"policy_bundle_id"`
	OrgBundleID    *uuid.UUID          `json:"org_bundle_id,omitempty"`
	RepoBundleID   *uuid.UUID          `json:"repo_bundle_id,omitempty"`
	Stage          string              `json:"stage"`
	Enforced       bool                `json:"enforced"`
	InputDigest    string              `json:"input_digest"`
	Effect         domain.PolicyEffect `json:"effect"`
	Reasons        json.RawMessage     `json:"reasons"`
	Obligations    json.RawMessage     `json:"obligations"`
	CreatedAt      time.Time           `json:"created_at"`
}

// ToDomain converts PolicyDecisionRow to domain.PolicyDecision.
func (r PolicyDecisionRow) ToDomain() domain.PolicyDecision {
	reasons := []domain.PolicyReason{}
	if len(r.Reasons) > 0 {
		var parsed []domain.PolicyReason
		if err := json.Unmarshal(r.Reasons, &parsed); err == nil && parsed != nil {
			reasons = parsed
		}
	}
	obligations := []domain.Obligation{}
	if len(r.Obligations) > 0 {
		var parsed []domain.Obligation
		if err := json.Unmarshal(r.Obligations, &parsed); err == nil && parsed != nil {
			obligations = parsed
		}
	}
	return domain.PolicyDecision{
		ID:             r.ID,
		ProposalID:     r.ProposalID,
		PushSessionID:  r.PushSessionID,
		PolicyBundleID: r.PolicyBundleID,
		Stage:          domain.PolicyStage(r.Stage),
		Enforced:       r.Enforced,
		InputDigest:    r.InputDigest,
		Effect:         r.Effect,
		Reasons:        reasons,
		Obligations:    obligations,
		CreatedAt:      r.CreatedAt.UTC(),
	}
}

// ApprovalRow represents a row in approvals.
type ApprovalRow struct {
	ID               uuid.UUID               `json:"id"`
	ProposalID       uuid.UUID               `json:"proposal_id"`
	ReviewerID       uuid.UUID               `json:"reviewer_id"`
	PolicyDecisionID uuid.UUID               `json:"policy_decision_id"`
	ManifestDigest   string                  `json:"manifest_digest"`
	Decision         domain.ApprovalDecision `json:"decision"`
	Comment          *string                 `json:"comment,omitempty"`
	RevokedAt        *time.Time              `json:"revoked_at,omitempty"`
	CreatedAt        time.Time               `json:"created_at"`
}

// ToDomain converts ApprovalRow to domain.Approval.
func (r ApprovalRow) ToDomain() domain.Approval {
	return domain.Approval{
		ID:               r.ID,
		ProposalID:       r.ProposalID,
		ReviewerID:       r.ReviewerID,
		PolicyDecisionID: r.PolicyDecisionID,
		ManifestDigest:   r.ManifestDigest,
		Decision:         r.Decision,
		Comment:          derefString(r.Comment),
		RevokedAt:        utcPtr(r.RevokedAt),
		CreatedAt:        r.CreatedAt.UTC(),
	}
}

// ApprovalRequirementRow represents a row in approval_requirements.
type ApprovalRequirementRow struct {
	ID               uuid.UUID  `json:"id"`
	ProposalID       uuid.UUID  `json:"proposal_id"`
	PolicyDecisionID uuid.UUID  `json:"policy_decision_id"`
	RequirementType  string     `json:"requirement_type"`
	ReviewerGroup    string     `json:"reviewer_group"`
	MinimumApprovals int        `json:"minimum_approvals"`
	SatisfiedCount   int        `json:"satisfied_count"`
	SatisfiedAt      *time.Time `json:"satisfied_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ToObligation converts ApprovalRequirementRow to domain.Obligation.
func (r ApprovalRequirementRow) ToObligation() domain.Obligation {
	return domain.Obligation{
		Type:          r.RequirementType,
		ReviewerGroup: r.ReviewerGroup,
		Minimum:       r.MinimumApprovals,
	}
}

// PublicationRow represents a row in publications.
type PublicationRow struct {
	ID                uuid.UUID                `json:"id"`
	ProposalID        uuid.UUID                `json:"proposal_id"`
	BranchRef         string                   `json:"branch_ref"`
	CommitSHA         *string                  `json:"commit_sha,omitempty"`
	PullRequestNumber *int64                   `json:"pull_request_number,omitempty"`
	PullRequestURL    *string                  `json:"pull_request_url,omitempty"`
	Status            domain.PublicationStatus `json:"status"`
	AttemptCount      int                      `json:"attempt_count"`
	CreatedAt         time.Time                `json:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
}

// ToDomain converts PublicationRow to domain.Publication.
func (r PublicationRow) ToDomain() domain.Publication {
	return domain.Publication{
		ID:                r.ID,
		ProposalID:        r.ProposalID,
		BranchRef:         r.BranchRef,
		CommitSHA:         derefString(r.CommitSHA),
		PullRequestNumber: r.PullRequestNumber,
		PullRequestURL:    derefString(r.PullRequestURL),
		Status:            r.Status,
		AttemptCount:      r.AttemptCount,
		CreatedAt:         r.CreatedAt.UTC(),
	}
}

// PublicationAttemptRow represents a row in publication_attempts.
type PublicationAttemptRow struct {
	ID             uuid.UUID  `json:"id"`
	PublicationID  uuid.UUID  `json:"publication_id"`
	AttemptNumber  int        `json:"attempt_number"`
	ManifestDigest string     `json:"manifest_digest"`
	Status         string     `json:"status"`
	CommitSHA      *string    `json:"commit_sha,omitempty"`
	ErrorCode      *string    `json:"error_code,omitempty"`
	ErrorMessage   *string    `json:"error_message,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// PushSessionRow represents a row in push_sessions.
type PushSessionRow struct {
	ID                     uuid.UUID                   `json:"id"`
	PrincipalID            uuid.UUID                   `json:"principal_id"`
	RepositoryID           *uuid.UUID                  `json:"repository_id,omitempty"`
	Destination            string                      `json:"destination"`
	DestinationHost        string                      `json:"destination_host"`
	DestinationRegistered  bool                        `json:"destination_registered"`
	DestinationExternal    bool                        `json:"destination_external"`
	Transport              domain.PushTransport        `json:"transport"`
	RefUpdates             json.RawMessage             `json:"ref_updates"`
	HasLFS                 bool                        `json:"has_lfs"`
	LFSObjects             json.RawMessage             `json:"lfs_objects"`
	LFSObjectCount         int64                       `json:"lfs_object_count"`
	LFSTotalBytes          int64                       `json:"lfs_total_bytes"`
	PushManifestDigest     *string                     `json:"push_manifest_digest,omitempty"`
	BundleArtifactID       *uuid.UUID                  `json:"bundle_artifact_id,omitempty"`
	EgressMode             domain.EgressMode           `json:"egress_mode"`
	PassiveAuditDelivery   domain.PassiveAuditDelivery `json:"passive_audit_delivery"`
	Enforced               bool                        `json:"enforced"`
	Status                 domain.PushSessionStatus    `json:"status"`
	Verdict                *domain.PolicyEffect        `json:"verdict,omitempty"`
	LatestPolicyDecisionID *uuid.UUID                  `json:"latest_policy_decision_id,omitempty"`
	ApprovalReleaseID      *uuid.UUID                  `json:"approval_release_id,omitempty"`
	ErrorCode              *string                     `json:"error_code,omitempty"`
	ErrorMessage           *string                     `json:"error_message,omitempty"`
	UpstreamForwarded      bool                        `json:"upstream_forwarded"`
	UpstreamBytesSent      int64                       `json:"upstream_bytes_sent"`
	CreatedAt              time.Time                   `json:"created_at"`
	UpdatedAt              time.Time                   `json:"updated_at"`
	CompletedAt            *time.Time                  `json:"completed_at,omitempty"`
}

// ToDomain converts PushSessionRow to domain.PushSession.
func (r PushSessionRow) ToDomain() domain.PushSession {
	refs := []domain.PushRefUpdate{}
	if len(r.RefUpdates) > 0 {
		var parsed []domain.PushRefUpdate
		if err := json.Unmarshal(r.RefUpdates, &parsed); err == nil && parsed != nil {
			refs = parsed
		}
	}
	lfs := []domain.PushLFSObject{}
	if len(r.LFSObjects) > 0 {
		var parsed []domain.PushLFSObject
		if err := json.Unmarshal(r.LFSObjects, &parsed); err == nil && parsed != nil {
			lfs = parsed
		}
	}
	return domain.PushSession{
		ID:                     r.ID,
		PrincipalID:            r.PrincipalID,
		RepositoryID:           r.RepositoryID,
		Destination:            r.Destination,
		DestinationHost:        r.DestinationHost,
		DestinationRegistered:  r.DestinationRegistered,
		DestinationExternal:    r.DestinationExternal,
		Transport:              r.Transport,
		RefUpdates:             refs,
		HasLFS:                 r.HasLFS,
		LFSObjects:             lfs,
		LFSObjectCount:         r.LFSObjectCount,
		LFSTotalBytes:          r.LFSTotalBytes,
		PushManifestDigest:     derefString(r.PushManifestDigest),
		BundleArtifactID:       r.BundleArtifactID,
		EgressMode:             r.EgressMode,
		PassiveAuditDelivery:   r.PassiveAuditDelivery,
		Enforced:               r.Enforced,
		Status:                 r.Status,
		Verdict:                r.Verdict,
		LatestPolicyDecisionID: r.LatestPolicyDecisionID,
		ApprovalReleaseID:      r.ApprovalReleaseID,
		ErrorCode:              derefString(r.ErrorCode),
		ErrorMessage:           derefString(r.ErrorMessage),
		UpstreamForwarded:      r.UpstreamForwarded,
		UpstreamBytesSent:      r.UpstreamBytesSent,
		CreatedAt:              r.CreatedAt.UTC(),
		UpdatedAt:              r.UpdatedAt.UTC(),
		CompletedAt:            utcPtr(r.CompletedAt),
	}
}

// PushApprovalReleaseRow represents a row in push_approval_releases.
type PushApprovalReleaseRow struct {
	ID                      uuid.UUID  `json:"id"`
	PrincipalID             uuid.UUID  `json:"principal_id"`
	Destination             string     `json:"destination"`
	PushManifestDigest      string     `json:"push_manifest_digest"`
	PushSessionID           uuid.UUID  `json:"push_session_id"`
	ConsumedByPushSessionID *uuid.UUID `json:"consumed_by_push_session_id,omitempty"`
	PolicyDecisionID        uuid.UUID  `json:"policy_decision_id"`
	ApprovedBy              uuid.UUID  `json:"approved_by"`
	Reason                  *string    `json:"reason,omitempty"`
	ExpiresAt               time.Time  `json:"expires_at"`
	ConsumedAt              *time.Time `json:"consumed_at,omitempty"`
	RevokedAt               *time.Time `json:"revoked_at,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
}

// ToDomain converts PushApprovalReleaseRow to domain.PushApprovalRelease.
func (r PushApprovalReleaseRow) ToDomain() domain.PushApprovalRelease {
	return domain.PushApprovalRelease{
		ID:                      r.ID,
		PrincipalID:             r.PrincipalID,
		Destination:             r.Destination,
		PushManifestDigest:      r.PushManifestDigest,
		PushSessionID:           r.PushSessionID,
		ConsumedByPushSessionID: r.ConsumedByPushSessionID,
		PolicyDecisionID:        r.PolicyDecisionID,
		ApprovedBy:              r.ApprovedBy,
		Reason:                  derefString(r.Reason),
		ExpiresAt:               r.ExpiresAt.UTC(),
		ConsumedAt:              utcPtr(r.ConsumedAt),
		RevokedAt:               utcPtr(r.RevokedAt),
		CreatedAt:               r.CreatedAt.UTC(),
	}
}

// IPFingerprintCorpusRow represents a row in ip_fingerprint_corpora.
type IPFingerprintCorpusRow struct {
	ID                uuid.UUID             `json:"id"`
	Name              string                `json:"name"`
	Description       *string               `json:"description,omitempty"`
	Classification    domain.Classification `json:"classification"`
	RepositoryID      *uuid.UUID            `json:"repository_id,omitempty"`
	SourceRef         string                `json:"source_ref"`
	WinnowK           int                   `json:"winnow_k"`
	WinnowW           int                   `json:"winnow_w"`
	ChunkSizeBytes    int                   `json:"chunk_size_bytes"`
	Enabled           bool                  `json:"enabled"`
	Status            domain.IPCorpusStatus `json:"status"`
	FingerprintCount  int64                 `json:"fingerprint_count"`
	LastIndexedDigest *string               `json:"last_indexed_digest,omitempty"`
	LastIndexedAt     *time.Time            `json:"last_indexed_at,omitempty"`
	LastError         *string               `json:"last_error,omitempty"`
	CreatedBy         *uuid.UUID            `json:"created_by,omitempty"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
}

// ToDomain converts IPFingerprintCorpusRow to domain.IPFingerprintCorpus.
func (r IPFingerprintCorpusRow) ToDomain() domain.IPFingerprintCorpus {
	return domain.IPFingerprintCorpus{
		ID:                r.ID,
		Name:              r.Name,
		Description:       derefString(r.Description),
		Classification:    r.Classification,
		RepositoryID:      r.RepositoryID,
		SourceRef:         r.SourceRef,
		WinnowK:           r.WinnowK,
		WinnowW:           r.WinnowW,
		ChunkSizeBytes:    r.ChunkSizeBytes,
		Enabled:           r.Enabled,
		Status:            r.Status,
		FingerprintCount:  r.FingerprintCount,
		LastIndexedDigest: derefString(r.LastIndexedDigest),
		LastIndexedAt:     utcPtr(r.LastIndexedAt),
		LastError:         derefString(r.LastError),
		CreatedBy:         r.CreatedBy,
		CreatedAt:         r.CreatedAt.UTC(),
		UpdatedAt:         r.UpdatedAt.UTC(),
	}
}

// IPFingerprintRow represents a row in ip_fingerprints.
type IPFingerprintRow struct {
	ID              uuid.UUID               `json:"id"`
	CorpusID        uuid.UUID               `json:"corpus_id"`
	Layer           domain.FingerprintLayer `json:"layer"`
	FingerprintHash string                  `json:"fingerprint_hash"`
	FilePathHash    *string                 `json:"file_path_hash,omitempty"`
	Language        *string                 `json:"language,omitempty"`
	ChunkIndex      *int                    `json:"chunk_index,omitempty"`
	LineStart       *int                    `json:"line_start,omitempty"`
	LineEnd         *int                    `json:"line_end,omitempty"`
	TokenCount      *int                    `json:"token_count,omitempty"`
	Metadata        json.RawMessage         `json:"metadata"`
	CreatedAt       time.Time               `json:"created_at"`
}

// ToDomain converts IPFingerprintRow to domain.IPFingerprint.
func (r IPFingerprintRow) ToDomain() domain.IPFingerprint {
	metadata := make(map[string]any)
	if len(r.Metadata) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(r.Metadata, &parsed); err == nil && parsed != nil {
			metadata = parsed
		}
	}
	return domain.IPFingerprint{
		ID:              r.ID,
		CorpusID:        r.CorpusID,
		Layer:           r.Layer,
		FingerprintHash: r.FingerprintHash,
		FilePathHash:    derefString(r.FilePathHash),
		Language:        derefString(r.Language),
		ChunkIndex:      r.ChunkIndex,
		LineStart:       r.LineStart,
		LineEnd:         r.LineEnd,
		TokenCount:      r.TokenCount,
		Metadata:        metadata,
		CreatedAt:       r.CreatedAt.UTC(),
	}
}

// IPFingerprintLookupRow joins an IPFingerprintRow with its parent corpus metadata.
type IPFingerprintLookupRow struct {
	IPFingerprintRow
	CorpusName     string                `json:"corpus_name"`
	Classification domain.Classification `json:"classification"`
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func derefFloat64(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

func normalizeTimestamp(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC().Truncate(time.Microsecond)
	}
	return t.UTC().Truncate(time.Microsecond)
}
