package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	// APIVersionV1 is the supported YAML/JSON schema version for PolicyBundle and PolicyTestSuite.
	APIVersionV1 = "custodian.dev/v1"

	// KindPolicyBundle identifies a Custodian CEL policy bundle document.
	KindPolicyBundle = "PolicyBundle"

	// KindPolicyTestSuite identifies a Custodian YAML policy test suite document.
	KindPolicyTestSuite = "PolicyTestSuite"

	// StageIngress evaluates policies on repository ingress before source delivery.
	StageIngress = "INGRESS"

	// StageEgress evaluates policies on proposal egress before human approval and publication.
	StageEgress = "EGRESS"

	// StagePushEgress evaluates policies on git push egress before upstream forwarding.
	StagePushEgress = "PUSH_EGRESS"

	// DefaultObligationType is applied when a YAML rule obligation omits `type`.
	DefaultObligationType = "HUMAN_REVIEW"

	// DefaultCostLimit bounds CEL runtime evaluation steps to prevent resource exhaustion.
	DefaultCostLimit uint64 = 100_000
)

// IsValidStage reports whether stage is a supported Custodian evaluation stage.
func IsValidStage(stage string) bool {
	return stage == StageIngress || stage == StageEgress || stage == StagePushEgress
}

// Bundle represents the parsed YAML/JSON PolicyBundle definition.
type Bundle struct {
	APIVersion string            `yaml:"apiVersion" json:"apiVersion"`
	Kind       string            `yaml:"kind" json:"kind"`
	Metadata   BundleMetadata    `yaml:"metadata" json:"metadata"`
	Defaults   BundleDefaults    `yaml:"defaults" json:"defaults"`
	Inspection *InspectionConfig `yaml:"inspection,omitempty" json:"inspection,omitempty"`
	Rules      []Rule            `yaml:"rules" json:"rules"`
}

// BundleMetadata identifies a policy bundle's name, semantic version, and optional scope.
type BundleMetadata struct {
	Name    string             `yaml:"name" json:"name"`
	Version string             `yaml:"version" json:"version"`
	Scope   domain.PolicyScope `yaml:"scope,omitempty" json:"scope,omitempty"`
}

// BundleDefaults specifies fallback behavior when zero rules match or evaluation fails.
type BundleDefaults struct {
	Effect  domain.PolicyEffect `yaml:"effect" json:"effect"`
	OnError domain.PolicyEffect `yaml:"onError" json:"onError"`
}

// InspectionConfig declares mandatory Stage A scanners and Stage B decision-model triggers.
type InspectionConfig struct {
	Mandatory     []string             `yaml:"mandatory,omitempty" json:"mandatory,omitempty"`
	DecisionModel *DecisionModelConfig `yaml:"decisionModel,omitempty" json:"decisionModel,omitempty"`
}

// DecisionModelConfig configures the Stage B contextual model route and trigger conditions.
type DecisionModelConfig struct {
	Route   string   `yaml:"route,omitempty" json:"route,omitempty"`
	Trigger []string `yaml:"trigger,omitempty" json:"trigger,omitempty"`
}

// Rule declares a single CEL policy rule within a PolicyBundle.
type Rule struct {
	ID          string              `yaml:"id" json:"id"`
	Description string              `yaml:"description,omitempty" json:"description,omitempty"`
	Stages      []string            `yaml:"stages" json:"stages"`
	When        string              `yaml:"when" json:"when"`
	Effect      domain.PolicyEffect `yaml:"effect" json:"effect"`
	Overridable *bool               `yaml:"overridable,omitempty" json:"overridable,omitempty"`
	Message     string              `yaml:"message,omitempty" json:"message,omitempty"`
	Obligations []RuleObligation    `yaml:"obligations,omitempty" json:"obligations,omitempty"`
}

// AppliesToStage reports whether the rule is active for the given stage.
func (r Rule) AppliesToStage(stage string) bool {
	return slices.Contains(r.Stages, stage)
}

// IsOverridable returns whether an org-scoped rule permits override by a repo rule.
// Omitted `overridable` defaults to false for ORG scope (fail-closed) and true for REPO scope.
func (r Rule) IsOverridable(scope domain.PolicyScope) bool {
	if r.Overridable != nil {
		return *r.Overridable
	}
	return scope == domain.PolicyScopeRepo
}

// RuleObligation declares a human approval requirement attached to a REQUIRE_APPROVAL rule.
type RuleObligation struct {
	Type          string `yaml:"type,omitempty" json:"type,omitempty"`
	ReviewerGroup string `yaml:"reviewer_group" json:"reviewer_group"`
	Minimum       *int   `yaml:"minimum,omitempty" json:"minimum,omitempty"`
}

// FindingsInput projects Stage A InspectionSummary facts into the CEL `findings` variable.
// Field tags match internal/inspection/types.go InspectionSummary.PolicyFacts() 1:1.
type FindingsInput struct {
	MandatoryScannersComplete bool             `cel:"mandatory_scanners_complete" json:"mandatory_scanners_complete"`
	ScanComplete              bool             `cel:"scan_complete" json:"scan_complete"`
	CriticalSecrets           int64            `cel:"critical_secrets" json:"critical_secrets"`
	ProhibitedLicenses        int64            `cel:"prohibited_licenses" json:"prohibited_licenses"`
	HighVulnerabilities       int64            `cel:"high_vulnerabilities" json:"high_vulnerabilities"`
	HighSASTFindings          int64            `cel:"high_sast_findings" json:"high_sast_findings"`
	TotalFindings             int64            `cel:"total_findings" json:"total_findings"`
	IPExactMatches            int64            `cel:"ip_exact_matches" json:"ip_exact_matches"`
	IPWinnowMatches           int64            `cel:"ip_winnow_matches" json:"ip_winnow_matches"`
	IPHeaderStripMatches      int64            `cel:"ip_header_strip_matches" json:"ip_header_strip_matches"`
	ConcealmentFindings       int64            `cel:"concealment_findings" json:"concealment_findings"`
	RestrictedIPMatches       int64            `cel:"restricted_ip_matches" json:"restricted_ip_matches"`
	ConfidentialIPMatches     int64            `cel:"confidential_ip_matches" json:"confidential_ip_matches"`
	CountsByCategory          map[string]int64 `cel:"counts_by_category" json:"counts_by_category"`
	CountsBySeverity          map[string]int64 `cel:"counts_by_severity" json:"counts_by_severity"`
	CountsByScanner           map[string]int64 `cel:"counts_by_scanner" json:"counts_by_scanner"`
	EvidenceIDs               []string         `cel:"evidence_ids" json:"evidence_ids"`
	FailedScanners            []string         `cel:"failed_scanners" json:"failed_scanners"`
	IncompleteScanners        []string         `cel:"incomplete_scanners" json:"incomplete_scanners"`
}

// AssessmentInput projects Stage B PolicyAssessmentFact into the CEL `assessment` variable.
// Field tags match internal/decisions/policy_input.go PolicyAssessmentFact.ToMap() 1:1.
type AssessmentInput struct {
	Status         string `cel:"status" json:"status"`
	IPRisk         string `cel:"ip_risk" json:"ip_risk"`
	Risk           string `cel:"risk" json:"risk"`
	Disposition    string `cel:"disposition" json:"disposition"`
	ModelRoute     string `cel:"model_route" json:"model_route"`
	ModelVersion   string `cel:"model_version" json:"model_version"`
	PromptVersion  string `cel:"prompt_version" json:"prompt_version"`
	AssessmentType string `cel:"assessment_type" json:"assessment_type"`
}

// ChangeInput projects canonical diff/tree metadata into the CEL `change` variable.
type ChangeInput struct {
	Paths          []string `cel:"paths" json:"paths"`
	FileCount      int64    `cel:"file_count" json:"file_count"`
	TotalBytes     int64    `cel:"total_bytes" json:"total_bytes"`
	TreeDigest     string   `cel:"tree_digest" json:"tree_digest"`
	DiffDigest     string   `cel:"diff_digest" json:"diff_digest"`
	ManifestDigest string   `cel:"manifest_digest" json:"manifest_digest"`
	BaseCommit     string   `cel:"base_commit" json:"base_commit"`
	TargetRef      string   `cel:"target_ref" json:"target_ref"`
}

// RepositoryInput projects repository metadata into the CEL `repository` variable.
type RepositoryInput struct {
	ID                   string   `cel:"id" json:"id"`
	FullName             string   `cel:"full_name" json:"full_name"`
	Classification       string   `cel:"classification" json:"classification"`
	Enabled              bool     `cel:"enabled" json:"enabled"`
	AllowedModelRoutes   []string `cel:"allowed_model_routes" json:"allowed_model_routes"`
	GitHubRepositoryID   int64    `cel:"github_repository_id" json:"github_repository_id"`
	GitHubInstallationID int64    `cel:"github_installation_id" json:"github_installation_id"`
}

// WorkspaceInput projects workspace metadata into the CEL `workspace` variable.
type WorkspaceInput struct {
	ID                 string `cel:"id" json:"id"`
	Generation         int64  `cel:"generation" json:"generation"`
	AgentAssisted      bool   `cel:"agent_assisted" json:"agent_assisted"`
	ModelRoute         string `cel:"model_route" json:"model_route"`
	IncludeGitMetadata bool   `cel:"include_git_metadata" json:"include_git_metadata"`
	IncludeHistory     bool   `cel:"include_history" json:"include_history"`
	BaseCommit         string `cel:"base_commit" json:"base_commit"`
	TargetRef          string `cel:"target_ref" json:"target_ref"`
}

// ProposalInput projects proposal metadata into the CEL `proposal` variable.
type ProposalInput struct {
	ID             string `cel:"id" json:"id"`
	Version        int64  `cel:"version" json:"version"`
	OwnerID        string `cel:"owner_id" json:"owner_id"`
	BaseCommit     string `cel:"base_commit" json:"base_commit"`
	TargetRef      string `cel:"target_ref" json:"target_ref"`
	ProvenanceType string `cel:"provenance_type" json:"provenance_type"`
	CaptureMethod  string `cel:"capture_method" json:"capture_method"`
}

// PrincipalInput projects owner/actor metadata into the CEL `principal` variable.
type PrincipalInput struct {
	ID            string   `cel:"id" json:"id"`
	Kind          string   `cel:"kind" json:"kind"`
	Subject       string   `cel:"subject" json:"subject"`
	DisplayName   string   `cel:"display_name" json:"display_name"`
	VerifiedEmail string   `cel:"verified_email" json:"verified_email"`
	Groups        []string `cel:"groups" json:"groups"`
	Roles         []string `cel:"roles" json:"roles"`
}

// ProvenanceInput projects capture provenance metadata into the CEL `provenance` variable.
type ProvenanceInput struct {
	Type          string `cel:"type" json:"type"`
	CaptureMethod string `cel:"capture_method" json:"capture_method"`
}

// DestinationInput projects Git push remote/destination metadata into the CEL `destination` variable.
type DestinationInput struct {
	ID             string `cel:"id" json:"id"`
	Name           string `cel:"name" json:"name"`
	Host           string `cel:"host" json:"host"`
	Registered     bool   `cel:"registered" json:"registered"`
	External       bool   `cel:"external" json:"external"`
	Classification string `cel:"classification" json:"classification"`
	Org            string `cel:"org" json:"org"`
	Owner          string `cel:"owner" json:"owner"`
}

// PushInput projects Git push transaction and LFS metadata into the CEL `push` variable.
type PushInput struct {
	HasLFS                 bool     `cel:"has_lfs" json:"has_lfs"`
	LFSObjectCount         int64    `cel:"lfs_object_count" json:"lfs_object_count"`
	LFSTotalBytes          int64    `cel:"lfs_total_bytes" json:"lfs_total_bytes"`
	RefNames               []string `cel:"ref_names" json:"ref_names"`
	CommitCount            int64    `cel:"commit_count" json:"commit_count"`
	EgressMode             string   `cel:"egress_mode" json:"egress_mode"`
	ApprovalReleasePresent bool     `cel:"approval_release_present" json:"approval_release_present"`
	PushManifestDigest     string   `cel:"push_manifest_digest" json:"push_manifest_digest"`
}

// PolicyInput is the complete verified fact structure bound into the CEL evaluation environment.
type PolicyInput struct {
	Stage       string           `json:"stage,omitempty"`
	Findings    FindingsInput    `json:"findings"`
	Assessment  AssessmentInput  `json:"assessment"`
	Change      ChangeInput      `json:"change"`
	Repository  RepositoryInput  `json:"repository"`
	Workspace   WorkspaceInput   `json:"workspace"`
	Proposal    ProposalInput    `json:"proposal"`
	Principal   PrincipalInput   `json:"principal"`
	Provenance  ProvenanceInput  `json:"provenance"`
	Destination DestinationInput `json:"destination"`
	Push        PushInput        `json:"push"`
	Flags       map[string]bool  `json:"flags,omitempty"`
}

// ValidationError describes a schema, syntax, type, or test-suite failure during bundle validation.
type ValidationError struct {
	RuleID  string `json:"rule_id,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ValidationResult summarizes bundle validation and compilation for CLI and API responses.
type ValidationResult struct {
	Valid         bool                `json:"valid"`
	Name          string              `json:"name"`
	Version       string              `json:"version"`
	Scope         *domain.PolicyScope `json:"scope,omitempty"`
	Digest        string              `json:"digest"`
	RulesCompiled int                 `json:"rules_compiled"`
	Errors        []ValidationError   `json:"errors"`
}

// CompiledRule holds a validated rule along with its compiled CEL program and normalized obligations.
type CompiledRule struct {
	Spec        Rule
	Program     cel.Program
	Obligations []domain.Obligation
}

// CompiledBundle holds a validated, compiled policy bundle ready for evaluation.
type CompiledBundle struct {
	Bundle     Bundle
	Scope      domain.PolicyScope
	Digest     string
	Definition json.RawMessage
	Rules      []CompiledRule
}

// RuleTrace records the evaluation outcome of an individual stage-applicable rule.
type RuleTrace struct {
	RuleID  string              `json:"rule_id"`
	Matched bool                `json:"matched"`
	Effect  domain.PolicyEffect `json:"effect"`
	Error   string              `json:"error,omitempty"`
}

// EvalResult captures the full outcome of evaluating one or composed policy bundles.
type EvalResult struct {
	Effect         domain.PolicyEffect   `json:"effect"`
	BundleDigest   string                `json:"bundle_digest"`
	InputDigest    string                `json:"input_digest"`
	MatchedRuleIDs []string              `json:"matched_rule_ids"`
	Reasons        []domain.PolicyReason `json:"reasons"`
	Obligations    []domain.Obligation   `json:"obligations"`
	RuleTrace      []RuleTrace           `json:"rule_trace"`
	HadError       bool                  `json:"had_error"`
}

// ToDomainDecision converts an evaluation result into a persistence-ready domain.PolicyDecision.
func (r EvalResult) ToDomainDecision(id, proposalID, primaryBundleID uuid.UUID, createdAt time.Time) domain.PolicyDecision {
	reasons := make([]domain.PolicyReason, len(r.Reasons))
	copy(reasons, r.Reasons)
	obligations := make([]domain.Obligation, len(r.Obligations))
	copy(obligations, r.Obligations)
	if !r.Effect.IsValid() {
		r.Effect = domain.PolicyEffectDeny
	}
	if r.Effect.BlocksPublication() {
		obligations = []domain.Obligation{}
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	return domain.PolicyDecision{
		ID:             id,
		ProposalID:     proposalID,
		PolicyBundleID: primaryBundleID,
		InputDigest:    strings.ToLower(strings.TrimSpace(r.InputDigest)),
		Effect:         r.Effect,
		Reasons:        reasons,
		Obligations:    obligations,
		CreatedAt:      createdAt.UTC().Truncate(time.Microsecond),
	}
}
