package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/workspaces"
)

// --- Error Envelope ---

type ErrorDetail struct {
	Code             string         `json:"code"`
	Message          string         `json:"message"`
	TraceID          *string        `json:"trace_id,omitempty"`
	PolicyDecisionID *string        `json:"policy_decision_id,omitempty"`
	Details          map[string]any `json:"details,omitempty"`
}

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// --- Common DTOs ---

type PrincipalRefDTO struct {
	PrincipalID      string `json:"principal_id"`
	IdentityProvider string `json:"identity_provider"`
}

type ArtifactRefDTO struct {
	ArtifactID        string  `json:"artifact_id"`
	Kind              string  `json:"kind"`
	SHA256            string  `json:"sha256"`
	SizeBytes         int64   `json:"size_bytes"`
	Format            string  `json:"format"`
	StorageKey        string  `json:"storage_key"`
	StorageGeneration string  `json:"storage_generation"`
	ExpiresAt         *string `json:"expires_at,omitempty"`
}

type ProvenanceDTO struct {
	Type          string `json:"type"`
	CaptureMethod string `json:"capture_method"`
}

type RepositoryRefDTO struct {
	ProviderID int64   `json:"provider_id"`
	FullName   *string `json:"full_name,omitempty"`
	BaseCommit string  `json:"base_commit"`
	TargetRef  string  `json:"target_ref"`
}

// --- Workspace DTOs ---

type SourceOptionsDTO struct {
	IncludeGitMetadata bool `json:"include_git_metadata"`
	IncludeHistory     bool `json:"include_history"`
}

type WorkspaceRepositoryInputDTO struct {
	Provider     string `json:"provider"`
	RepositoryID int64  `json:"repository_id"`
	Ref          string `json:"ref"`
}

type WorkspaceAgentInputDTO struct {
	Type       string `json:"type"`
	SessionID  string `json:"session_id"`
	ModelRoute string `json:"model_route"`
}

type CreateWorkspaceRequest struct {
	Repository    *WorkspaceRepositoryInputDTO `json:"repository"`
	Agent         *WorkspaceAgentInputDTO      `json:"agent,omitempty"`
	SourceOptions *SourceOptionsDTO            `json:"source_options,omitempty"`
}

type CreateWorkspaceResponse struct {
	WorkspaceID  string `json:"workspace_id"`
	RepositoryID string `json:"repository_id"`
	OwnerID      string `json:"owner_id"`
	BaseCommit   string `json:"base_commit"`
	TargetRef    string `json:"target_ref"`
	Status       string `json:"status"`
	Generation   int64  `json:"generation"`
	OperationID  string `json:"operation_id"`
	CreatedAt    string `json:"created_at"`
}

type WorkspaceAgentInfoDTO struct {
	AgentID    string  `json:"agent_id"`
	Type       *string `json:"type,omitempty"`
	SessionID  string  `json:"session_id"`
	ModelRoute string  `json:"model_route"`
}

type WorkspaceDTO struct {
	ID                 string                 `json:"id"`
	RepositoryID       string                 `json:"repository_id"`
	GitHubRepositoryID int64                  `json:"github_repository_id"`
	RepositoryFullName *string                `json:"repository_full_name,omitempty"`
	Owner              PrincipalRefDTO        `json:"owner"`
	Agent              *WorkspaceAgentInfoDTO `json:"agent,omitempty"`
	BaseCommit         string                 `json:"base_commit"`
	TargetRef          string                 `json:"target_ref"`
	SourceArtifactID   *string                `json:"source_artifact_id,omitempty"`
	Generation         int64                  `json:"generation"`
	Status             string                 `json:"status"`
	SourceOptions      SourceOptionsDTO       `json:"source_options"`
	CreatedAt          string                 `json:"created_at"`
}

type DownloadDescriptorDTO struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt string            `json:"expires_at"`
}

type UploadCapabilityDTO struct {
	Token       string `json:"token"`
	WorkspaceID string `json:"workspace_id"`
	Generation  int64  `json:"generation"`
	MaxBytes    int64  `json:"max_bytes"`
	ExpiresAt   string `json:"expires_at"`
	UploadURL   string `json:"upload_url"`
}

type SourceArtifactDescriptorDTO struct {
	WorkspaceID      string                `json:"workspace_id"`
	Generation       int64                 `json:"generation"`
	BaseCommit       string                `json:"base_commit"`
	Artifact         ArtifactRefDTO        `json:"artifact"`
	Download         DownloadDescriptorDTO `json:"download"`
	SourceOptions    SourceOptionsDTO      `json:"source_options"`
	UploadCapability *UploadCapabilityDTO  `json:"upload_capability,omitempty"`
}

type UploadSnapshotResponse struct {
	ArtifactID string `json:"artifact_id"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
}

// --- Proposal DTOs ---

type SnapshotCaptureInputDTO struct {
	ArtifactID          string  `json:"artifact_id"`
	SHA256              string  `json:"sha256"`
	WorkspaceGeneration int64   `json:"workspace_generation"`
	SizeBytes           *int64  `json:"size_bytes,omitempty"`
	CapturedAt          *string `json:"captured_at,omitempty"`
}

type SubmitProposalRequest struct {
	Snapshot    *SnapshotCaptureInputDTO `json:"snapshot"`
	Title       string                   `json:"title"`
	Description *string                  `json:"description,omitempty"`
	Provenance  *ProvenanceDTO           `json:"provenance,omitempty"`
}

type SubmitProposalResponse struct {
	ProposalID  string `json:"proposal_id"`
	WorkspaceID string `json:"workspace_id"`
	OperationID string `json:"operation_id"`
	BaseCommit  string `json:"base_commit"`
	TargetRef   string `json:"target_ref"`
	Status      string `json:"status"`
	Version     int64  `json:"version"`
	CreatedAt   string `json:"created_at"`
}

type ProposalOriginDTO struct {
	WorkspaceID    string  `json:"workspace_id"`
	AgentID        *string `json:"agent_id,omitempty"`
	AgentSessionID *string `json:"agent_session_id,omitempty"`
	ModelRoute     *string `json:"model_route,omitempty"`
}

type ProposalDTO struct {
	ID                        string            `json:"id"`
	WorkspaceID               string            `json:"workspace_id"`
	Title                     string            `json:"title"`
	Description               *string           `json:"description,omitempty"`
	Owner                     PrincipalRefDTO   `json:"owner"`
	Origin                    ProposalOriginDTO `json:"origin"`
	Repository                RepositoryRefDTO  `json:"repository"`
	Provenance                ProvenanceDTO     `json:"provenance"`
	SnapshotArtifactID        string            `json:"snapshot_artifact_id"`
	CanonicalArtifactID       *string           `json:"canonical_artifact_id,omitempty"`
	ManifestArtifactID        *string           `json:"manifest_artifact_id,omitempty"`
	TreeDigest                *string           `json:"tree_digest,omitempty"`
	DiffDigest                *string           `json:"diff_digest,omitempty"`
	PublicationManifestDigest *string           `json:"publication_manifest_digest,omitempty"`
	LatestPolicyEvaluationID  *string           `json:"latest_policy_evaluation_id,omitempty"`
	LatestPolicyEffect        *string           `json:"latest_policy_effect,omitempty"`
	Status                    string            `json:"status"`
	Version                   int64             `json:"version"`
	CreatedAt                 string            `json:"created_at"`
}

type ChangedFileDTO struct {
	Path       string  `json:"path"`
	ChangeType string  `json:"change_type"`
	OldPath    *string `json:"old_path,omitempty"`
	SizeBytes  int64   `json:"size_bytes"`
	SHA256     *string `json:"sha256,omitempty"`
}

type ProposalDiffDTO struct {
	ProposalID                string           `json:"proposal_id"`
	BaseCommit                string           `json:"base_commit"`
	TreeDigest                string           `json:"tree_digest"`
	DiffDigest                string           `json:"diff_digest"`
	PublicationManifestDigest string           `json:"publication_manifest_digest"`
	Paths                     []ChangedFileDTO `json:"paths"`
	UnifiedDiff               string           `json:"unified_diff"`
	Truncated                 bool             `json:"truncated"`
	DiffArtifactID            *string          `json:"diff_artifact_id,omitempty"`
}

type EvaluateProposalRequest struct {
	ExpectedVersion *int64 `json:"expected_version,omitempty"`
}

type EvaluateProposalResponse struct {
	ProposalID     string             `json:"proposal_id"`
	OperationID    string             `json:"operation_id"`
	Status         string             `json:"status"`
	Version        int64              `json:"version"`
	PolicyDecision *PolicyDecisionDTO `json:"policy_decision,omitempty"`
}

type ObligationDTO struct {
	Type          string `json:"type"`
	ReviewerGroup string `json:"reviewer_group"`
	Minimum       int    `json:"minimum"`
}

type CreateApprovalRequest struct {
	Decision                  string  `json:"decision"`
	PublicationManifestDigest string  `json:"publication_manifest_digest"`
	PolicyEvaluationID        string  `json:"policy_evaluation_id"`
	Comment                   *string `json:"comment,omitempty"`
}

type ApprovalResponse struct {
	ID                   string          `json:"id"`
	ProposalID           string          `json:"proposal_id"`
	ReviewerID           string          `json:"reviewer_id"`
	PolicyDecisionID     string          `json:"policy_decision_id"`
	ManifestDigest       string          `json:"manifest_digest"`
	Decision             string          `json:"decision"`
	Comment              *string         `json:"comment,omitempty"`
	ProposalStatus       string          `json:"proposal_status"`
	RemainingObligations []ObligationDTO `json:"remaining_obligations"`
	CreatedAt            string          `json:"created_at"`
}

// --- Inspection DTOs ---

type ScanRunSummaryDTO struct {
	ID             string  `json:"id"`
	ProposalID     string  `json:"proposal_id"`
	ArtifactID     string  `json:"artifact_id"`
	Scanner        string  `json:"scanner"`
	ScannerVersion string  `json:"scanner_version"`
	Status         string  `json:"status"`
	FilesExamined  int     `json:"files_examined"`
	FilesSkipped   int     `json:"files_skipped"`
	Complete       bool    `json:"complete"`
	StartedAt      string  `json:"started_at"`
	CompletedAt    *string `json:"completed_at,omitempty"`
}

type FindingDTO struct {
	ID                 string         `json:"id"`
	ScanRunID          string         `json:"scan_run_id"`
	EvidenceID         *string        `json:"evidence_id,omitempty"`
	Scanner            *string        `json:"scanner,omitempty"`
	Category           string         `json:"category"`
	Severity           string         `json:"severity"`
	RuleID             string         `json:"rule_id"`
	Path               *string        `json:"path,omitempty"`
	StartLine          *int           `json:"start_line,omitempty"`
	EndLine            *int           `json:"end_line,omitempty"`
	Fingerprint        string         `json:"fingerprint"`
	EvidenceArtifactID *string        `json:"evidence_artifact_id,omitempty"`
	EvidenceRef        *string        `json:"evidence_ref,omitempty"`
	Baseline           *string        `json:"baseline,omitempty"`
	Confidence         *float64       `json:"confidence,omitempty"`
	Message            *string        `json:"message,omitempty"`
	Redacted           bool           `json:"redacted"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type ProposalFindingsResponse struct {
	ProposalID string              `json:"proposal_id"`
	ScanRuns   []ScanRunSummaryDTO `json:"scan_runs"`
	Findings   []FindingDTO        `json:"findings"`
	NextCursor *string             `json:"next_cursor,omitempty"`
	HasMore    bool                `json:"has_more"`
}

type ModelFindingDTO struct {
	Category          string   `json:"category"`
	EvidenceIDs       []string `json:"evidence_ids"`
	Reason            string   `json:"reason"`
	RecommendedAction string   `json:"recommended_action"`
}

type ModelAssessmentDTO struct {
	ID             string            `json:"id"`
	ProposalID     string            `json:"proposal_id"`
	ArtifactID     string            `json:"artifact_id"`
	ModelRoute     string            `json:"model_route"`
	ModelVersion   string            `json:"model_version"`
	PromptVersion  string            `json:"prompt_version"`
	AssessmentType string            `json:"assessment_type"`
	Status         string            `json:"status"`
	Risk           *string           `json:"risk,omitempty"`
	Disposition    *string           `json:"disposition,omitempty"`
	Summary        *string           `json:"summary,omitempty"`
	Findings       []ModelFindingDTO `json:"findings"`
	Limitations    []string          `json:"limitations"`
	InputDigest    string            `json:"input_digest"`
	OutputDigest   string            `json:"output_digest"`
	CreatedAt      string            `json:"created_at"`
}

type PolicyReasonDTO struct {
	RuleID  string  `json:"rule_id"`
	Effect  string  `json:"effect"`
	Stage   *string `json:"stage,omitempty"`
	Message *string `json:"message,omitempty"`
}

type PolicyDecisionDTO struct {
	ID             string            `json:"id"`
	ProposalID     string            `json:"proposal_id"`
	PolicyBundleID string            `json:"policy_bundle_id"`
	InputDigest    string            `json:"input_digest"`
	Effect         string            `json:"effect"`
	Reasons        []PolicyReasonDTO `json:"reasons"`
	Obligations    []ObligationDTO   `json:"obligations"`
	CreatedAt      string            `json:"created_at"`
}

type ProposalAssessmentsResponse struct {
	ProposalID      string               `json:"proposal_id"`
	Assessments     []ModelAssessmentDTO `json:"assessments"`
	PolicyDecisions []PolicyDecisionDTO  `json:"policy_decisions"`
}

// --- Publication DTOs ---

type PublishProposalRequest struct {
	PublicationManifestDigest string `json:"publication_manifest_digest"`
}

type PublishProposalResponse struct {
	PublicationID     string  `json:"publication_id"`
	ProposalID        string  `json:"proposal_id"`
	OperationID       string  `json:"operation_id"`
	BranchRef         string  `json:"branch_ref"`
	Status            string  `json:"status"`
	CommitSHA         *string `json:"commit_sha,omitempty"`
	PullRequestNumber *int64  `json:"pull_request_number,omitempty"`
	PullRequestURL    *string `json:"pull_request_url,omitempty"`
	CreatedAt         string  `json:"created_at"`
}

type PublicationDTO struct {
	ID                string  `json:"id"`
	ProposalID        string  `json:"proposal_id"`
	BranchRef         string  `json:"branch_ref"`
	CommitSHA         *string `json:"commit_sha,omitempty"`
	PullRequestNumber *int64  `json:"pull_request_number,omitempty"`
	PullRequestURL    *string `json:"pull_request_url,omitempty"`
	Status            string  `json:"status"`
	AttemptCount      int     `json:"attempt_count"`
	CreatedAt         string  `json:"created_at"`
}

// --- Policy DTOs ---

type ValidatePolicyRequest struct {
	BundleYAML    string  `json:"bundle_yaml"`
	TestCasesYAML *string `json:"test_cases_yaml,omitempty"`
}

type PolicyValidationErrorDTO struct {
	RuleID  *string `json:"rule_id,omitempty"`
	Code    string  `json:"code"`
	Message string  `json:"message"`
}

type ValidatePolicyResponse struct {
	Valid         bool                       `json:"valid"`
	Name          string                     `json:"name"`
	Version       string                     `json:"version"`
	Scope         *string                    `json:"scope,omitempty"`
	Digest        string                     `json:"digest"`
	RulesCompiled int                        `json:"rules_compiled"`
	Errors        []PolicyValidationErrorDTO `json:"errors"`
}

type SimulatePolicyRequest struct {
	BundleYAML    *string        `json:"bundle_yaml,omitempty"`
	OrgBundleYAML *string        `json:"org_bundle_yaml,omitempty"`
	BundleID      *string        `json:"bundle_id,omitempty"`
	Stage         string         `json:"stage"`
	Input         map[string]any `json:"input"`
}

type RuleTraceDTO struct {
	RuleID  string  `json:"rule_id"`
	Matched bool    `json:"matched"`
	Effect  string  `json:"effect"`
	Error   *string `json:"error,omitempty"`
}

type SimulatePolicyResponse struct {
	Effect         string          `json:"effect"`
	BundleDigest   string          `json:"bundle_digest"`
	InputDigest    string          `json:"input_digest"`
	MatchedRuleIDs []string        `json:"matched_rule_ids"`
	Obligations    []ObligationDTO `json:"obligations"`
	RuleTrace      []RuleTraceDTO  `json:"rule_trace"`
}

// --- Operation DTOs ---

type OperationDTO struct {
	ID            string          `json:"id"`
	OperationType string          `json:"operation_type"`
	ResourceType  *string         `json:"resource_type,omitempty"`
	ResourceID    string          `json:"resource_id"`
	Status        string          `json:"status"`
	Attempts      int             `json:"attempts"`
	AvailableAt   string          `json:"available_at"`
	LeaseUntil    *string         `json:"lease_until,omitempty"`
	LastError     *string         `json:"last_error,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
	CreatedAt     string          `json:"created_at"`
}

// --- Audit DTOs ---

type AuditEventDTO struct {
	ID           string          `json:"id"`
	EventType    string          `json:"event_type"`
	ActorID      *string         `json:"actor_id,omitempty"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash *string         `json:"previous_hash,omitempty"`
	EventHash    string          `json:"event_hash"`
	CreatedAt    string          `json:"created_at"`
}

type AuditEventsListResponse struct {
	Events     []AuditEventDTO `json:"events"`
	NextCursor *string         `json:"next_cursor,omitempty"`
	HasMore    bool            `json:"has_more"`
}

// --- Converters ---

func formatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func formatTimestampPtr(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := formatTimestamp(*t)
	return &s
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func optUUIDString(id *uuid.UUID) *string {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	s := id.String()
	return &s
}

func normalizeHex64OrNil(raw string) *string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	hex, err := domain.ParseSHA256Digest(raw)
	if err != nil {
		return nil
	}
	return &hex
}

func normalizeHex64(raw string) string {
	hex, err := domain.ParseSHA256Digest(raw)
	if err != nil {
		return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "sha256:"))
	}
	return hex
}

func toWorkspaceDTO(ws workspaces.WorkspaceDetails) WorkspaceDTO {
	idp := strings.TrimSpace(ws.Owner.IdentityProvider)
	if idp == "" {
		idp = "custodian"
	}
	var fullName *string
	if len(strings.TrimSpace(ws.RepositoryFullName)) >= 3 {
		fn := ws.RepositoryFullName
		fullName = &fn
	}
	var agent *WorkspaceAgentInfoDTO
	if ws.AgentID != nil && *ws.AgentID != uuid.Nil {
		agent = &WorkspaceAgentInfoDTO{
			AgentID:    ws.AgentID.String(),
			Type:       optString(ws.AgentType),
			SessionID:  ws.AgentSessionID,
			ModelRoute: ws.ModelRoute,
		}
	}
	return WorkspaceDTO{
		ID:                 ws.ID.String(),
		RepositoryID:       ws.RepositoryID.String(),
		GitHubRepositoryID: ws.GitHubRepositoryID,
		RepositoryFullName: fullName,
		Owner: PrincipalRefDTO{
			PrincipalID:      ws.Owner.PrincipalID.String(),
			IdentityProvider: idp,
		},
		Agent:            agent,
		BaseCommit:       strings.ToLower(ws.BaseCommit),
		TargetRef:        ws.TargetRef,
		SourceArtifactID: optUUIDString(ws.SourceArtifactID),
		Generation:       ws.Generation,
		Status:           string(ws.Status),
		SourceOptions: SourceOptionsDTO{
			IncludeGitMetadata: ws.SourceOptions.IncludeGitMetadata,
			IncludeHistory:     ws.SourceOptions.IncludeHistory,
		},
		CreatedAt: formatTimestamp(ws.CreatedAt),
	}
}

func toArtifactRefDTO(rec artifacts.Record) ArtifactRefDTO {
	return ArtifactRefDTO{
		ArtifactID:        rec.ID.String(),
		Kind:              string(rec.Kind),
		SHA256:            normalizeHex64(rec.SHA256),
		SizeBytes:         rec.SizeBytes,
		Format:            rec.Format,
		StorageKey:        rec.StorageKey,
		StorageGeneration: rec.StorageGeneration,
		ExpiresAt:         formatTimestampPtr(rec.ExpiresAt),
	}
}

func toProposalDTO(d proposals.ProposalDetails) ProposalDTO {
	idp := strings.TrimSpace(d.Owner.IdentityProvider)
	if idp == "" {
		idp = "custodian"
	}
	var fullName *string
	if len(strings.TrimSpace(d.RepositoryFullName)) >= 3 {
		fn := d.RepositoryFullName
		fullName = &fn
	}
	var treeDigest *string
	if len(strings.TrimSpace(d.TreeDigest)) >= 40 && len(strings.TrimSpace(d.TreeDigest)) <= 64 {
		td := strings.ToLower(strings.TrimSpace(d.TreeDigest))
		treeDigest = &td
	}
	var latestEffect *string
	if d.LatestPolicyEffect != nil && d.LatestPolicyEffect.IsValid() {
		eff := string(*d.LatestPolicyEffect)
		latestEffect = &eff
	}
	provType := d.ProvenanceType
	if provType == "" {
		provType = "agent_assisted"
	}
	capMethod := d.CaptureMethod
	if capMethod == "" {
		capMethod = "frozen_filesystem"
	}
	return ProposalDTO{
		ID:          d.ID.String(),
		WorkspaceID: d.WorkspaceID.String(),
		Title:       d.Title,
		Description: optString(d.Description),
		Owner: PrincipalRefDTO{
			PrincipalID:      d.Owner.PrincipalID.String(),
			IdentityProvider: idp,
		},
		Origin: ProposalOriginDTO{
			WorkspaceID:    d.WorkspaceID.String(),
			AgentID:        optUUIDString(d.WorkspaceAgentID),
			AgentSessionID: optString(d.WorkspaceAgentSessionID),
			ModelRoute:     optString(d.WorkspaceModelRoute),
		},
		Repository: RepositoryRefDTO{
			ProviderID: d.GitHubRepositoryID,
			FullName:   fullName,
			BaseCommit: strings.ToLower(d.BaseCommit),
			TargetRef:  d.TargetRef,
		},
		Provenance: ProvenanceDTO{
			Type:          provType,
			CaptureMethod: capMethod,
		},
		SnapshotArtifactID:        d.SnapshotArtifactID.String(),
		CanonicalArtifactID:       optUUIDString(d.CanonicalArtifactID),
		ManifestArtifactID:        optUUIDString(d.ManifestArtifactID),
		TreeDigest:                treeDigest,
		DiffDigest:                normalizeHex64OrNil(d.DiffDigest),
		PublicationManifestDigest: normalizeHex64OrNil(d.ManifestDigest),
		LatestPolicyEvaluationID:  optUUIDString(d.LatestPolicyEvaluationID),
		LatestPolicyEffect:        latestEffect,
		Status:                    string(d.Status),
		Version:                   d.Version,
		CreatedAt:                 formatTimestamp(d.CreatedAt),
	}
}

func toChangedFileDTOs(changes []reconstruct.ChangedFile) []ChangedFileDTO {
	out := make([]ChangedFileDTO, 0, len(changes))
	for _, c := range changes {
		out = append(out, ChangedFileDTO{
			Path:       c.Path,
			ChangeType: c.ChangeType,
			OldPath:    optString(c.OldPath),
			SizeBytes:  c.SizeBytes,
			SHA256:     normalizeHex64OrNil(c.SHA256),
		})
	}
	return out
}

func toObligationDTOs(obls []domain.Obligation) []ObligationDTO {
	out := make([]ObligationDTO, 0, len(obls))
	for _, o := range obls {
		typ := strings.TrimSpace(o.Type)
		if typ == "" {
			typ = "HUMAN_REVIEW"
		}
		min := o.Minimum
		if min < 1 {
			min = 1
		}
		out = append(out, ObligationDTO{
			Type:          typ,
			ReviewerGroup: o.ReviewerGroup,
			Minimum:       min,
		})
	}
	return out
}

func toApprovalResponse(res approvals.SubmitResult) ApprovalResponse {
	return ApprovalResponse{
		ID:                   res.Approval.ID.String(),
		ProposalID:           res.Approval.ProposalID.String(),
		ReviewerID:           res.Approval.ReviewerID.String(),
		PolicyDecisionID:     res.Approval.PolicyDecisionID.String(),
		ManifestDigest:       normalizeHex64(res.Approval.ManifestDigest),
		Decision:             string(res.Approval.Decision),
		Comment:              optString(res.Approval.Comment),
		ProposalStatus:       string(res.ProposalStatus),
		RemainingObligations: toObligationDTOs(res.RemainingObligations),
		CreatedAt:            formatTimestamp(res.CreatedAt),
	}
}

func toScanRunSummaryDTO(sr domain.ScanRun) ScanRunSummaryDTO {
	return ScanRunSummaryDTO{
		ID:             sr.ID.String(),
		ProposalID:     sr.ProposalID.String(),
		ArtifactID:     sr.ArtifactID.String(),
		Scanner:        sr.Scanner,
		ScannerVersion: sr.ScannerVersion,
		Status:         string(sr.Status),
		FilesExamined:  sr.Coverage.FilesExamined,
		FilesSkipped:   sr.Coverage.FilesSkipped,
		Complete:       sr.Coverage.Complete,
		StartedAt:      formatTimestamp(sr.StartedAt),
		CompletedAt:    formatTimestampPtr(sr.CompletedAt),
	}
}

func toFindingDTO(f domain.Finding) FindingDTO {
	var startLine, endLine *int
	if f.StartLine > 0 {
		v := f.StartLine
		startLine = &v
	}
	if f.EndLine > 0 {
		v := f.EndLine
		endLine = &v
	}
	var conf *float64
	if f.Confidence > 0 {
		v := f.Confidence
		conf = &v
	}
	var meta map[string]any
	if len(f.Metadata) > 0 {
		meta = f.Metadata
	}
	return FindingDTO{
		ID:                 f.ID.String(),
		ScanRunID:          f.ScanRunID.String(),
		EvidenceID:         optString(f.EvidenceID),
		Scanner:            optString(f.Scanner),
		Category:           f.Category,
		Severity:           string(f.Severity),
		RuleID:             f.RuleID,
		Path:               optString(f.Path),
		StartLine:          startLine,
		EndLine:            endLine,
		Fingerprint:        f.Fingerprint,
		EvidenceArtifactID: optUUIDString(f.EvidenceArtifactID),
		EvidenceRef:        optString(f.EvidenceRef),
		Baseline:           optString(f.Baseline),
		Confidence:         conf,
		Message:            optString(f.Message),
		Redacted:           f.Redacted,
		Metadata:           meta,
	}
}

func toModelAssessmentDTO(a domain.ModelAssessment) ModelAssessmentDTO {
	var risk *string
	if a.Risk.IsValid() {
		s := string(a.Risk)
		risk = &s
	}
	var disp *string
	if a.Disposition.IsValid() {
		s := string(a.Disposition)
		disp = &s
	}
	findings := make([]ModelFindingDTO, 0, len(a.Result.Findings))
	for _, f := range a.Result.Findings {
		evIDs := f.EvidenceIDs
		if evIDs == nil {
			evIDs = []string{}
		}
		findings = append(findings, ModelFindingDTO{
			Category:          f.Category,
			EvidenceIDs:       evIDs,
			Reason:            f.Reason,
			RecommendedAction: f.RecommendedAction,
		})
	}
	lims := a.Result.Limitations
	if lims == nil {
		lims = []string{}
	}
	return ModelAssessmentDTO{
		ID:             a.ID.String(),
		ProposalID:     a.ProposalID.String(),
		ArtifactID:     a.ArtifactID.String(),
		ModelRoute:     a.ModelRoute,
		ModelVersion:   a.ModelVersion,
		PromptVersion:  a.PromptVersion,
		AssessmentType: a.AssessmentType,
		Status:         string(a.Status),
		Risk:           risk,
		Disposition:    disp,
		Summary:        optString(a.Result.Summary),
		Findings:       findings,
		Limitations:    lims,
		InputDigest:    normalizeHex64(a.InputDigest),
		OutputDigest:   normalizeHex64(a.OutputDigest),
		CreatedAt:      formatTimestamp(a.CreatedAt),
	}
}

func toPolicyDecisionDTO(pd domain.PolicyDecision) PolicyDecisionDTO {
	reasons := make([]PolicyReasonDTO, 0, len(pd.Reasons))
	for _, r := range pd.Reasons {
		reasons = append(reasons, PolicyReasonDTO{
			RuleID:  r.RuleID,
			Effect:  string(r.Effect),
			Stage:   optString(r.Stage),
			Message: optString(r.Message),
		})
	}
	return PolicyDecisionDTO{
		ID:             pd.ID.String(),
		ProposalID:     pd.ProposalID.String(),
		PolicyBundleID: pd.PolicyBundleID.String(),
		InputDigest:    normalizeHex64(pd.InputDigest),
		Effect:         string(pd.Effect),
		Reasons:        reasons,
		Obligations:    toObligationDTOs(pd.Obligations),
		CreatedAt:      formatTimestamp(pd.CreatedAt),
	}
}

func toPublicationDTO(row persistence.PublicationRow) PublicationDTO {
	var commitSHA *string
	if row.CommitSHA != nil && domain.IsValidGitSHA(strings.ToLower(*row.CommitSHA)) {
		s := strings.ToLower(*row.CommitSHA)
		commitSHA = &s
	}
	var prURL *string
	if row.PullRequestURL != nil && strings.TrimSpace(*row.PullRequestURL) != "" {
		s := strings.TrimSpace(*row.PullRequestURL)
		prURL = &s
	}
	return PublicationDTO{
		ID:                row.ID.String(),
		ProposalID:        row.ProposalID.String(),
		BranchRef:         domain.ExpectedBranchName(row.ProposalID),
		CommitSHA:         commitSHA,
		PullRequestNumber: row.PullRequestNumber,
		PullRequestURL:    prURL,
		Status:            string(row.Status),
		AttemptCount:      row.AttemptCount,
		CreatedAt:         formatTimestamp(row.CreatedAt),
	}
}

func toValidatePolicyResponse(res policy.ValidationResult) ValidatePolicyResponse {
	var scope *string
	if res.Scope != nil && res.Scope.IsValid() {
		s := string(*res.Scope)
		scope = &s
	}
	errs := make([]PolicyValidationErrorDTO, 0, len(res.Errors))
	for _, e := range res.Errors {
		errs = append(errs, PolicyValidationErrorDTO{
			RuleID:  optString(e.RuleID),
			Code:    e.Code,
			Message: e.Message,
		})
	}
	digest := normalizeHex64(res.Digest)
	if !domain.IsValidSHA256Hex(digest) {
		digest = domain.SHA256Hex([]byte(res.Name + ":" + res.Version))
	}
	return ValidatePolicyResponse{
		Valid:         res.Valid,
		Name:          res.Name,
		Version:       res.Version,
		Scope:         scope,
		Digest:        digest,
		RulesCompiled: res.RulesCompiled,
		Errors:        errs,
	}
}

func toSimulatePolicyResponse(res policy.EvalResult) SimulatePolicyResponse {
	matched := res.MatchedRuleIDs
	if matched == nil {
		matched = []string{}
	}
	trace := make([]RuleTraceDTO, 0, len(res.RuleTrace))
	for _, rt := range res.RuleTrace {
		trace = append(trace, RuleTraceDTO{
			RuleID:  rt.RuleID,
			Matched: rt.Matched,
			Effect:  string(rt.Effect),
			Error:   optString(rt.Error),
		})
	}
	return SimulatePolicyResponse{
		Effect:         string(res.Effect),
		BundleDigest:   normalizeHex64(res.BundleDigest),
		InputDigest:    normalizeHex64(res.InputDigest),
		MatchedRuleIDs: matched,
		Obligations:    toObligationDTOs(res.Obligations),
		RuleTrace:      trace,
	}
}

func toOperationDTO(op operations.OperationDetails) OperationDTO {
	var resRaw json.RawMessage
	trimmed := bytes.TrimSpace(op.Result)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		resRaw = json.RawMessage(trimmed)
	}
	return OperationDTO{
		ID:            op.ID.String(),
		OperationType: string(op.OperationType),
		ResourceType:  optString(op.ResourceType),
		ResourceID:    op.ResourceID.String(),
		Status:        string(op.Status),
		Attempts:      op.Attempts,
		AvailableAt:   formatTimestamp(op.AvailableAt),
		LeaseUntil:    formatTimestampPtr(op.LeaseUntil),
		LastError:     optString(op.LastError),
		Result:        resRaw,
		CreatedAt:     formatTimestamp(op.CreatedAt),
	}
}

func toAuditEventDTO(ev domain.AuditEvent) AuditEventDTO {
	payload := bytes.TrimSpace(ev.Payload)
	if len(payload) == 0 || bytes.Equal(payload, []byte("null")) {
		payload = []byte("{}")
	}
	return AuditEventDTO{
		ID:           ev.ID.String(),
		EventType:    ev.EventType,
		ActorID:      optUUIDString(ev.ActorID),
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID.String(),
		Payload:      json.RawMessage(payload),
		PreviousHash: normalizeHex64OrNil(ev.PreviousHash),
		EventHash:    normalizeHex64(ev.EventHash),
		CreatedAt:    formatTimestamp(ev.CreatedAt),
	}
}
