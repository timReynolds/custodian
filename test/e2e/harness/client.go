package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// APIError captures standard Custodian JSON error fields (supporting both OpenAPI ErrorResponse and flat payloads).
type APIError struct {
	Error            string         `json:"error"`
	Code             string         `json:"code"`
	Message          string         `json:"message"`
	TraceID          string         `json:"trace_id,omitempty"`
	PolicyDecisionID string         `json:"policy_decision_id,omitempty"`
	Details          map[string]any `json:"details,omitempty"`
}

// RawResponse wraps an HTTP response without failing on 4xx/5xx status codes.
type RawResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Error      *APIError
}

// RequireStatus fails t if StatusCode != want.
func (r *RawResponse) RequireStatus(t testing.TB, want int) {
	t.Helper()
	if r == nil {
		t.Fatalf("nil RawResponse (want status %d)", want)
	}
	if r.StatusCode != want {
		t.Fatalf("unexpected HTTP status %d (want %d): body=%s", r.StatusCode, want, string(r.Body))
	}
}

// RequireAnyStatus fails t if StatusCode is not in wants.
func (r *RawResponse) RequireAnyStatus(t testing.TB, wants ...int) {
	t.Helper()
	if r == nil {
		t.Fatalf("nil RawResponse (want one of %v)", wants)
	}
	for _, w := range wants {
		if r.StatusCode == w {
			return
		}
	}
	t.Fatalf("unexpected HTTP status %d (want one of %v): body=%s", r.StatusCode, wants, string(r.Body))
}

// APIClient is a pure-stdlib REST client for all 16 Custodian /v1 endpoints and operational routes.
type APIClient struct {
	baseURL         string
	token           string
	httpClient      *http.Client
	contracts       *Contracts
	autoIdempotency bool
	seq             atomic.Uint64
}

// NewAPIClient constructs an APIClient targeting baseURL with Bearer token.
func NewAPIClient(baseURL, token string, contracts *Contracts) *APIClient {
	if contracts == nil {
		contracts = DefaultContracts()
	}
	return &APIClient{
		baseURL:         strings.TrimRight(baseURL, "/"),
		token:           token,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		contracts:       contracts,
		autoIdempotency: true,
	}
}

type requestOpts struct {
	idempotencyKey     *string
	disableIdempotency bool
	headers            map[string]string
	tokenOverride      *string
	withoutAuth        bool
	query              map[string]string
	contentType        string
}

// RequestOption customizes an individual APIClient request.
type RequestOption func(*requestOpts)

func WithIdempotencyKey(key string) RequestOption {
	return func(o *requestOpts) { o.idempotencyKey = &key }
}

func WithoutIdempotency() RequestOption {
	return func(o *requestOpts) { o.disableIdempotency = true }
}

func WithHeader(k, v string) RequestOption {
	return func(o *requestOpts) {
		if o.headers == nil {
			o.headers = make(map[string]string)
		}
		o.headers[k] = v
	}
}

func WithTokenOverride(tok string) RequestOption {
	return func(o *requestOpts) { o.tokenOverride = &tok }
}

func WithoutAuth() RequestOption {
	return func(o *requestOpts) { o.withoutAuth = true }
}

func WithQuery(params map[string]string) RequestOption {
	return func(o *requestOpts) {
		if o.query == nil {
			o.query = make(map[string]string)
		}
		for k, v := range params {
			o.query[k] = v
		}
	}
}

func WithContentType(ct string) RequestOption {
	return func(o *requestOpts) { o.contentType = ct }
}

// --- Request & Response DTOs aligned with api/openapi.yaml and api/schemas/*.yaml ---

type PrincipalRef struct {
	PrincipalID      string `json:"principal_id"`
	IdentityProvider string `json:"identity_provider"`
}

type ArtifactRef struct {
	ArtifactID        string `json:"artifact_id"`
	Kind              string `json:"kind"`
	SHA256            string `json:"sha256"`
	SizeBytes         int64  `json:"size_bytes"`
	Format            string `json:"format"`
	StorageKey        string `json:"storage_key"`
	StorageGeneration string `json:"storage_generation"`
	ExpiresAt         string `json:"expires_at,omitempty"`
}

type Provenance struct {
	Type          string `json:"type"`           // "agent_assisted" | "human_authored"
	CaptureMethod string `json:"capture_method"` // "frozen_filesystem" | "patch_upload"
}

type RepositoryRef struct {
	ProviderID int64  `json:"provider_id"`
	FullName   string `json:"full_name,omitempty"`
	BaseCommit string `json:"base_commit"`
	TargetRef  string `json:"target_ref"`
}

type WorkspaceRepoRef struct {
	Provider     string `json:"provider,omitempty"`
	RepositoryID int64  `json:"repository_id"`
	Ref          string `json:"ref"`
}

type WorkspaceAgentInfo struct {
	AgentID    string `json:"agent_id,omitempty"`
	Type       string `json:"type,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	ModelRoute string `json:"model_route,omitempty"`
}

type WorkspaceSourceOptions struct {
	IncludeGitMetadata bool `json:"include_git_metadata"`
	IncludeHistory     bool `json:"include_history"`
}

type CreateWorkspaceReq struct {
	Repository    WorkspaceRepoRef        `json:"repository"`
	Agent         *WorkspaceAgentInfo     `json:"agent,omitempty"`
	SourceOptions *WorkspaceSourceOptions `json:"source_options,omitempty"`
	OwnerID       string                  `json:"owner_id,omitempty"` // negative anti-impersonation tests
}

type WorkspaceCreateResp struct {
	WorkspaceID  string `json:"workspace_id"`
	ID           string `json:"id,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	OwnerID      string `json:"owner_id,omitempty"`
	BaseCommit   string `json:"base_commit"`
	TargetRef    string `json:"target_ref,omitempty"`
	Status       string `json:"status"`
	Generation   int64  `json:"generation,omitempty"`
	OperationID  string `json:"operation_id"`
	CreatedAt    string `json:"created_at,omitempty"`
}

type WorkspaceResp struct {
	ID                 string                  `json:"id"`
	WorkspaceID        string                  `json:"workspace_id,omitempty"`
	RepositoryID       string                  `json:"repository_id"`
	GitHubRepositoryID int64                   `json:"github_repository_id,omitempty"`
	RepositoryFullName string                  `json:"repository_full_name,omitempty"`
	Owner              *PrincipalRef           `json:"owner,omitempty"`
	OwnerID            string                  `json:"owner_id,omitempty"`
	Agent              *WorkspaceAgentInfo     `json:"agent,omitempty"`
	BaseCommit         string                  `json:"base_commit"`
	TargetRef          string                  `json:"target_ref"`
	SourceArtifactID   string                  `json:"source_artifact_id,omitempty"`
	Generation         int64                   `json:"generation"`
	Status             string                  `json:"status"`
	SourceOptions      *WorkspaceSourceOptions `json:"source_options,omitempty"`
	CreatedAt          string                  `json:"created_at,omitempty"`
	UploadURL          string                  `json:"upload_url,omitempty"`
	UploadToken        string                  `json:"upload_token,omitempty"`
}

type DownloadDescriptor struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	ExpiresAt string            `json:"expires_at"`
}

type UploadCapabilityReq struct {
	Generation int64  `json:"generation,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	ObjectKey  string `json:"object_key,omitempty"`
}

type UploadCapabilityResp struct {
	Token           string    `json:"token"`
	CapabilityToken string    `json:"capability_token,omitempty"`
	WorkspaceID     string    `json:"workspace_id"`
	Generation      int64     `json:"generation"`
	MaxBytes        int64     `json:"max_bytes"`
	ExpiresAt       time.Time `json:"expires_at"`
	UploadURL       string    `json:"upload_url"`
	ObjectKey       string    `json:"object_key,omitempty"`
}

type SourceDescriptorResp struct {
	WorkspaceID      string                 `json:"workspace_id"`
	Generation       int64                  `json:"generation"`
	BaseCommit       string                 `json:"base_commit"`
	Artifact         ArtifactRef            `json:"artifact"`
	Download         DownloadDescriptor     `json:"download"`
	SourceOptions    WorkspaceSourceOptions `json:"source_options"`
	UploadCapability *UploadCapabilityResp  `json:"upload_capability,omitempty"`
	ArtifactID       string                 `json:"artifact_id,omitempty"`
	SHA256           string                 `json:"sha256,omitempty"`
	SizeBytes        int64                  `json:"size_bytes,omitempty"`
	DownloadURL      string                 `json:"download_url,omitempty"`
	URL              string                 `json:"url,omitempty"`
	UploadURL        string                 `json:"upload_url,omitempty"`
	UploadToken      string                 `json:"upload_token,omitempty"`
}

type SnapshotSubmitRef struct {
	ArtifactID          string `json:"artifact_id"`
	SHA256              string `json:"sha256"`
	WorkspaceGeneration int64  `json:"workspace_generation"`
	SizeBytes           int64  `json:"size_bytes,omitempty"`
	CapturedAt          string `json:"captured_at,omitempty"`
}

type SubmitProposalReq struct {
	Snapshot    SnapshotSubmitRef `json:"snapshot"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Provenance  *Provenance       `json:"provenance,omitempty"`
	AuthorEmail string            `json:"author_email,omitempty"` // negative forged-author tests
	AuthorName  string            `json:"author_name,omitempty"`
}

type ProposalOrigin struct {
	WorkspaceID    string `json:"workspace_id"`
	AgentID        string `json:"agent_id,omitempty"`
	AgentSessionID string `json:"agent_session_id,omitempty"`
	ModelRoute     string `json:"model_route,omitempty"`
}

type ProposalResp struct {
	ID                        string          `json:"id"`
	ProposalID                string          `json:"proposal_id,omitempty"`
	WorkspaceID               string          `json:"workspace_id"`
	Title                     string          `json:"title,omitempty"`
	Description               string          `json:"description,omitempty"`
	Owner                     *PrincipalRef   `json:"owner,omitempty"`
	OwnerID                   string          `json:"owner_id,omitempty"`
	Origin                    *ProposalOrigin `json:"origin,omitempty"`
	Repository                *RepositoryRef  `json:"repository,omitempty"`
	Provenance                *Provenance     `json:"provenance,omitempty"`
	SnapshotArtifactID        string          `json:"snapshot_artifact_id,omitempty"`
	CanonicalArtifactID       string          `json:"canonical_artifact_id,omitempty"`
	ManifestArtifactID        string          `json:"manifest_artifact_id,omitempty"`
	BaseCommit                string          `json:"base_commit,omitempty"`
	TargetRef                 string          `json:"target_ref,omitempty"`
	TreeDigest                string          `json:"tree_digest,omitempty"`
	DiffDigest                string          `json:"diff_digest,omitempty"`
	PublicationManifestDigest string          `json:"publication_manifest_digest,omitempty"`
	LatestPolicyEvaluationID  string          `json:"latest_policy_evaluation_id,omitempty"`
	LatestPolicyEffect        string          `json:"latest_policy_effect,omitempty"`
	Status                    string          `json:"status"`
	Version                   int64           `json:"version"`
	OperationID               string          `json:"operation_id,omitempty"`
	CreatedAt                 string          `json:"created_at,omitempty"`
}

type ChangedFile struct {
	Path       string `json:"path"`
	ChangeType string `json:"change_type"` // "ADDED" | "MODIFIED" | "DELETED" | "RENAMED"
	OldPath    string `json:"old_path,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256,omitempty"`
}

type ProposalDiffResp struct {
	ProposalID                string        `json:"proposal_id"`
	BaseCommit                string        `json:"base_commit"`
	TreeDigest                string        `json:"tree_digest"`
	DiffDigest                string        `json:"diff_digest"`
	PublicationManifestDigest string        `json:"publication_manifest_digest"`
	Paths                     []ChangedFile `json:"paths"`
	UnifiedDiff               string        `json:"unified_diff"`
	Truncated                 bool          `json:"truncated,omitempty"`
	DiffArtifactID            string        `json:"diff_artifact_id,omitempty"`
}

type ScanRunDTO struct {
	ID            string `json:"id"`
	ProposalID    string `json:"proposal_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
	Scanner       string `json:"scanner"`
	Version       string `json:"scanner_version"`
	Status        string `json:"status"`
	FilesExamined int    `json:"files_examined"`
	FilesSkipped  int    `json:"files_skipped"`
	Complete      bool   `json:"complete"`
	StartedAt     string `json:"started_at,omitempty"`
	CompletedAt   string `json:"completed_at,omitempty"`
}

type FindingDTO struct {
	ID                 string         `json:"id"`
	ScanRunID          string         `json:"scan_run_id,omitempty"`
	EvidenceID         string         `json:"evidence_id,omitempty"`
	Scanner            string         `json:"scanner,omitempty"`
	Category           string         `json:"category"`
	Severity           string         `json:"severity"`
	RuleID             string         `json:"rule_id"`
	Path               string         `json:"path,omitempty"`
	StartLine          int            `json:"start_line,omitempty"`
	EndLine            int            `json:"end_line,omitempty"`
	Fingerprint        string         `json:"fingerprint"`
	EvidenceArtifactID string         `json:"evidence_artifact_id,omitempty"`
	EvidenceRef        string         `json:"evidence_ref,omitempty"`
	Baseline           string         `json:"baseline,omitempty"`
	Confidence         float64        `json:"confidence,omitempty"`
	Message            string         `json:"message,omitempty"`
	Redacted           bool           `json:"redacted"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type FindingsResp struct {
	ProposalID string       `json:"proposal_id"`
	ScanRuns   []ScanRunDTO `json:"scan_runs"`
	Findings   []FindingDTO `json:"findings"`
	NextCursor string       `json:"next_cursor,omitempty"`
	HasMore    bool         `json:"has_more"`
}

type AssessmentDTO struct {
	ID             string          `json:"id"`
	ProposalID     string          `json:"proposal_id,omitempty"`
	ArtifactID     string          `json:"artifact_id,omitempty"`
	ModelRoute     string          `json:"model_route"`
	ModelVersion   string          `json:"model_version"`
	PromptVersion  string          `json:"prompt_version"`
	AssessmentType string          `json:"assessment_type,omitempty"`
	Status         string          `json:"status"`
	Risk           string          `json:"risk,omitempty"`
	Disposition    string          `json:"disposition,omitempty"`
	Summary        string          `json:"summary,omitempty"`
	Findings       []StageBFinding `json:"findings,omitempty"`
	Limitations    []string        `json:"limitations,omitempty"`
	InputDigest    string          `json:"input_digest"`
	OutputDigest   string          `json:"output_digest"`
	CreatedAt      string          `json:"created_at,omitempty"`
}

type PolicyReasonDTO struct {
	RuleID  string `json:"rule_id"`
	Effect  string `json:"effect"`
	Stage   string `json:"stage,omitempty"`
	Message string `json:"message,omitempty"`
}

type ObligationDTO struct {
	Type          string `json:"type"`
	ReviewerGroup string `json:"reviewer_group"`
	Minimum       int    `json:"minimum"`
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

type AssessmentsResp struct {
	ProposalID      string              `json:"proposal_id"`
	Assessments     []AssessmentDTO     `json:"assessments"`
	PolicyDecisions []PolicyDecisionDTO `json:"policy_decisions"`
}

type EvaluateReq struct {
	ExpectedVersion int64 `json:"expected_version,omitempty"`
}

type EvaluateResp struct {
	ProposalID     string             `json:"proposal_id"`
	OperationID    string             `json:"operation_id"`
	Status         string             `json:"status"`
	Version        int64              `json:"version"`
	PolicyDecision *PolicyDecisionDTO `json:"policy_decision,omitempty"`
}

type ApproveReq struct {
	Decision                  string `json:"decision"` // "APPROVE" | "REJECT"
	PublicationManifestDigest string `json:"publication_manifest_digest"`
	PolicyEvaluationID        string `json:"policy_evaluation_id"`
	Comment                   string `json:"comment,omitempty"`
}

type ApprovalResp struct {
	ID                   string          `json:"id"`
	ProposalID           string          `json:"proposal_id"`
	ReviewerID           string          `json:"reviewer_id"`
	PolicyDecisionID     string          `json:"policy_decision_id"`
	ManifestDigest       string          `json:"manifest_digest"`
	Decision             string          `json:"decision"`
	Comment              string          `json:"comment,omitempty"`
	ProposalStatus       string          `json:"proposal_status"`
	RemainingObligations []ObligationDTO `json:"remaining_obligations"`
	CreatedAt            string          `json:"created_at"`
}

type PublishReq struct {
	PublicationManifestDigest string `json:"publication_manifest_digest"`
	TargetBranch              string `json:"target_branch,omitempty"` // negative branch-override tests
	TargetRemote              string `json:"target_remote,omitempty"`
}

type PublicationResp struct {
	ID                string `json:"id,omitempty"`
	PublicationID     string `json:"publication_id,omitempty"`
	ProposalID        string `json:"proposal_id"`
	OperationID       string `json:"operation_id,omitempty"`
	BranchRef         string `json:"branch_ref"`
	Status            string `json:"status"`
	CommitSHA         string `json:"commit_sha,omitempty"`
	PullRequestNumber int64  `json:"pull_request_number,omitempty"`
	PullRequestURL    string `json:"pull_request_url,omitempty"`
	AttemptCount      int    `json:"attempt_count,omitempty"`
	CreatedAt         string `json:"created_at,omitempty"`
}

type PolicyBundleReq struct {
	BundleYAML    string `json:"bundle_yaml"`
	TestCasesYAML string `json:"test_cases_yaml,omitempty"`
}

type PolicyValidationError struct {
	RuleID  string `json:"rule_id,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type PolicyValidateResp struct {
	Valid         bool                    `json:"valid"`
	Name          string                  `json:"name"`
	Version       string                  `json:"version"`
	Scope         string                  `json:"scope,omitempty"`
	Digest        string                  `json:"digest"`
	RulesCompiled int                     `json:"rules_compiled"`
	Errors        []PolicyValidationError `json:"errors"`
}

type PolicyEvaluateReq struct {
	BundleYAML    string         `json:"bundle_yaml,omitempty"`
	OrgBundleYAML string         `json:"org_bundle_yaml,omitempty"`
	BundleID      string         `json:"bundle_id,omitempty"`
	Stage         string         `json:"stage"` // "INGRESS" | "EGRESS"
	Input         map[string]any `json:"input"`
}

type RuleTraceDTO struct {
	RuleID  string `json:"rule_id"`
	Matched bool   `json:"matched"`
	Effect  string `json:"effect"`
	Error   string `json:"error,omitempty"`
}

type PolicyDecisionResp struct {
	Effect         string          `json:"effect"`
	BundleDigest   string          `json:"bundle_digest"`
	InputDigest    string          `json:"input_digest"`
	MatchedRuleIDs []string        `json:"matched_rule_ids"`
	Obligations    []ObligationDTO `json:"obligations"`
	RuleTrace      []RuleTraceDTO  `json:"rule_trace"`
}

type OperationResp struct {
	ID            string         `json:"id"`
	OperationType string         `json:"operation_type"`
	ResourceType  string         `json:"resource_type,omitempty"`
	ResourceID    string         `json:"resource_id"`
	Status        string         `json:"status"`
	Attempts      int            `json:"attempts"`
	AvailableAt   string         `json:"available_at,omitempty"`
	LeaseUntil    string         `json:"lease_until,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
	Result        map[string]any `json:"result,omitempty"`
	CreatedAt     string         `json:"created_at,omitempty"`
}

type AuditEventsResp struct {
	Events     []AuditEvent `json:"events"`
	NextCursor string       `json:"next_cursor,omitempty"`
	HasMore    bool         `json:"has_more"`
}

type AuditFilter struct {
	ResourceType string
	ResourceID   string
	EventType    string
	ActorID      string
	Since        string
	Until        string
	Limit        int
	Cursor       string
}

func (c *APIClient) resolveURL(pathOrURL string, query map[string]string) (string, error) {
	full := pathOrURL
	if !strings.HasPrefix(pathOrURL, "http://") && !strings.HasPrefix(pathOrURL, "https://") {
		if !strings.HasPrefix(pathOrURL, "/") {
			pathOrURL = "/" + pathOrURL
		}
		full = c.baseURL + pathOrURL
	}
	if len(query) == 0 {
		return full, nil
	}
	u, err := url.Parse(full)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *APIClient) v1Path(suffix string) string {
	base := strings.TrimRight(c.contracts.APIBasePath, "/")
	if base == "" {
		base = "/v1"
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return base + suffix
}

// DoRaw sends a raw HTTP request with automatic auth/idempotency headers (unless overridden).
func (c *APIClient) DoRaw(ctx context.Context, method, pathOrURL string, body []byte, opts ...RequestOption) (*RawResponse, error) {
	var o requestOpts
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	targetURL, err := c.resolveURL(pathOrURL, o.query)
	if err != nil {
		return nil, fmt.Errorf("resolve url %q: %w", pathOrURL, err)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, targetURL, err)
	}

	if o.contentType != "" {
		req.Header.Set("Content-Type", o.contentType)
	} else if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if !o.withoutAuth {
		tok := c.token
		if o.tokenOverride != nil {
			tok = *o.tokenOverride
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}

	isMutating := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
	if isMutating && !o.disableIdempotency {
		if o.idempotencyKey != nil {
			req.Header.Set("Idempotency-Key", *o.idempotencyKey)
		} else if c.autoIdempotency {
			c.seq.Add(1)
			req.Header.Set("Idempotency-Key", NewTestUUIDv7())
		}
	}

	for k, v := range o.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	raw := &RawResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       respBytes,
	}
	if resp.StatusCode >= 400 && len(bytes.TrimSpace(respBytes)) > 0 {
		var env struct {
			Error struct {
				Code             string         `json:"code"`
				Message          string         `json:"message"`
				TraceID          string         `json:"trace_id"`
				PolicyDecisionID string         `json:"policy_decision_id"`
				Details          map[string]any `json:"details"`
			} `json:"error"`
		}
		if json.Unmarshal(respBytes, &env) == nil && (env.Error.Code != "" || env.Error.Message != "") {
			raw.Error = &APIError{
				Error:            env.Error.Code,
				Code:             env.Error.Code,
				Message:          env.Error.Message,
				TraceID:          env.Error.TraceID,
				PolicyDecisionID: env.Error.PolicyDecisionID,
				Details:          env.Error.Details,
			}
		} else {
			var apiErr APIError
			if json.Unmarshal(respBytes, &apiErr) == nil && (apiErr.Error != "" || apiErr.Message != "" || apiErr.Code != "") {
				raw.Error = &apiErr
			}
		}
	}
	return raw, nil
}

func doJSON[Resp any](ctx context.Context, c *APIClient, method, pathOrURL string, reqBody any, opts ...RequestOption) (Resp, *RawResponse, error) {
	var zero Resp
	var bodyBytes []byte
	if reqBody != nil {
		var err error
		bodyBytes, err = json.Marshal(reqBody)
		if err != nil {
			return zero, nil, fmt.Errorf("marshal request: %w", err)
		}
	}
	raw, err := c.DoRaw(ctx, method, pathOrURL, bodyBytes, opts...)
	if err != nil {
		return zero, raw, err
	}
	if raw.StatusCode >= 200 && raw.StatusCode < 300 && len(bytes.TrimSpace(raw.Body)) > 0 {
		if err := json.Unmarshal(raw.Body, &zero); err != nil {
			return zero, raw, fmt.Errorf("decode %s %s response: %w", method, pathOrURL, err)
		}
	}
	return zero, raw, nil
}

func (c *APIClient) CreateWorkspace(ctx context.Context, req CreateWorkspaceReq, opts ...RequestOption) (WorkspaceCreateResp, *RawResponse, error) {
	return doJSON[WorkspaceCreateResp](ctx, c, http.MethodPost, c.v1Path("/workspaces"), req, opts...)
}

func (c *APIClient) GetWorkspace(ctx context.Context, workspaceID string, opts ...RequestOption) (WorkspaceResp, *RawResponse, error) {
	return doJSON[WorkspaceResp](ctx, c, http.MethodGet, c.v1Path("/workspaces/"+url.PathEscape(workspaceID)), nil, opts...)
}

func (c *APIClient) GetWorkspaceSource(ctx context.Context, workspaceID string, opts ...RequestOption) (SourceDescriptorResp, *RawResponse, error) {
	return doJSON[SourceDescriptorResp](ctx, c, http.MethodGet, c.v1Path("/workspaces/"+url.PathEscape(workspaceID)+"/source"), nil, opts...)
}

// DownloadWorkspaceSource handles both direct binary tar.gz responses and descriptor-then-GET flows.
func (c *APIClient) DownloadWorkspaceSource(ctx context.Context, workspaceID string, opts ...RequestOption) ([]byte, *RawResponse, error) {
	raw, err := c.DoRaw(ctx, http.MethodGet, c.v1Path("/workspaces/"+url.PathEscape(workspaceID)+"/source"), nil, opts...)
	if err != nil || raw.StatusCode < 200 || raw.StatusCode >= 300 {
		return nil, raw, err
	}

	ct := strings.ToLower(raw.Headers.Get("Content-Type"))
	if strings.Contains(ct, "gzip") || strings.Contains(ct, "octet-stream") || (len(raw.Body) >= 2 && raw.Body[0] == 0x1f && raw.Body[1] == 0x8b) {
		return raw.Body, raw, nil
	}

	var desc SourceDescriptorResp
	if err := json.Unmarshal(raw.Body, &desc); err != nil {
		return nil, raw, fmt.Errorf("decode source descriptor: %w", err)
	}
	dlURL := desc.Download.URL
	if dlURL == "" {
		dlURL = desc.DownloadURL
	}
	if dlURL == "" {
		dlURL = desc.URL
	}
	if dlURL == "" {
		return nil, raw, errors.New("source descriptor did not include download.url or binary payload")
	}
	dlMethod := desc.Download.Method
	if dlMethod == "" {
		dlMethod = http.MethodGet
	}
	dlOpts := make([]RequestOption, 0, len(desc.Download.Headers)+len(opts))
	for k, v := range desc.Download.Headers {
		dlOpts = append(dlOpts, WithHeader(k, v))
	}
	dlOpts = append(dlOpts, opts...)
	binResp, err := c.DoRaw(ctx, dlMethod, dlURL, nil, dlOpts...)
	if err != nil {
		return nil, binResp, err
	}
	return binResp.Body, binResp, nil
}

func (c *APIClient) RequestUploadCapability(ctx context.Context, workspaceID string, req UploadCapabilityReq, opts ...RequestOption) (UploadCapabilityResp, *RawResponse, error) {
	if c.contracts.UploadCapabilityEndpoint != "" {
		ep := strings.ReplaceAll(c.contracts.UploadCapabilityEndpoint, "{id}", url.PathEscape(workspaceID))
		return doJSON[UploadCapabilityResp](ctx, c, http.MethodPost, ep, req, opts...)
	}
	desc, raw, err := c.GetWorkspaceSource(ctx, workspaceID, opts...)
	if err != nil {
		return UploadCapabilityResp{}, raw, err
	}
	if raw != nil && (raw.StatusCode < 200 || raw.StatusCode >= 300) {
		return UploadCapabilityResp{}, raw, nil
	}
	if desc.UploadCapability == nil {
		return UploadCapabilityResp{}, raw, errors.New("workspace source descriptor did not include upload_capability")
	}
	return *desc.UploadCapability, raw, nil
}

// UploadSnapshot uploads gzBytes to uploadURL using the configured capability method and header.
func (c *APIClient) UploadSnapshot(ctx context.Context, uploadURL, capToken string, gzBytes []byte, opts ...RequestOption) (*RawResponse, error) {
	method := c.contracts.UploadCapabilityMethod
	if method == "" {
		method = http.MethodPut
	}
	hdrName := c.contracts.UploadCapabilityHeader
	if hdrName == "" {
		hdrName = "Authorization"
	}
	hdrVal := capToken
	if c.contracts.UploadCapabilityBearer && capToken != "" && !strings.HasPrefix(capToken, "Bearer ") {
		hdrVal = "Bearer " + capToken
	}

	merged := make([]RequestOption, 0, len(opts)+4)
	merged = append(merged,
		WithoutAuth(),
		WithoutIdempotency(),
		WithContentType("application/gzip"),
	)
	if hdrVal != "" {
		merged = append(merged, WithHeader(hdrName, hdrVal))
	}
	merged = append(merged, opts...)
	return c.DoRaw(ctx, method, uploadURL, gzBytes, merged...)
}

func (c *APIClient) SubmitProposal(ctx context.Context, workspaceID string, req SubmitProposalReq, opts ...RequestOption) (ProposalResp, *RawResponse, error) {
	return doJSON[ProposalResp](ctx, c, http.MethodPost, c.v1Path("/workspaces/"+url.PathEscape(workspaceID)+"/proposals"), req, opts...)
}

func (c *APIClient) GetProposal(ctx context.Context, proposalID string, opts ...RequestOption) (ProposalResp, *RawResponse, error) {
	return doJSON[ProposalResp](ctx, c, http.MethodGet, c.v1Path("/proposals/"+url.PathEscape(proposalID)), nil, opts...)
}

func (c *APIClient) GetProposalDiff(ctx context.Context, proposalID string, opts ...RequestOption) (ProposalDiffResp, *RawResponse, error) {
	return doJSON[ProposalDiffResp](ctx, c, http.MethodGet, c.v1Path("/proposals/"+url.PathEscape(proposalID)+"/diff"), nil, opts...)
}

func (c *APIClient) ListProposalFindings(ctx context.Context, proposalID string, opts ...RequestOption) (FindingsResp, *RawResponse, error) {
	return doJSON[FindingsResp](ctx, c, http.MethodGet, c.v1Path("/proposals/"+url.PathEscape(proposalID)+"/findings"), nil, opts...)
}

func (c *APIClient) ListProposalAssessments(ctx context.Context, proposalID string, opts ...RequestOption) (AssessmentsResp, *RawResponse, error) {
	return doJSON[AssessmentsResp](ctx, c, http.MethodGet, c.v1Path("/proposals/"+url.PathEscape(proposalID)+"/assessments"), nil, opts...)
}

func (c *APIClient) EvaluateProposal(ctx context.Context, proposalID string, req EvaluateReq, opts ...RequestOption) (EvaluateResp, *RawResponse, error) {
	return doJSON[EvaluateResp](ctx, c, http.MethodPost, c.v1Path("/proposals/"+url.PathEscape(proposalID)+"/evaluate"), req, opts...)
}

func (c *APIClient) ApproveProposal(ctx context.Context, proposalID string, req ApproveReq, opts ...RequestOption) (ApprovalResp, *RawResponse, error) {
	return doJSON[ApprovalResp](ctx, c, http.MethodPost, c.v1Path("/proposals/"+url.PathEscape(proposalID)+"/approvals"), req, opts...)
}

func (c *APIClient) PublishProposal(ctx context.Context, proposalID string, req PublishReq, opts ...RequestOption) (PublicationResp, *RawResponse, error) {
	return doJSON[PublicationResp](ctx, c, http.MethodPost, c.v1Path("/proposals/"+url.PathEscape(proposalID)+"/publish"), req, opts...)
}

func (c *APIClient) GetPublication(ctx context.Context, publicationID string, opts ...RequestOption) (PublicationResp, *RawResponse, error) {
	return doJSON[PublicationResp](ctx, c, http.MethodGet, c.v1Path("/publications/"+url.PathEscape(publicationID)), nil, opts...)
}

func (c *APIClient) ValidatePolicy(ctx context.Context, req PolicyBundleReq, opts ...RequestOption) (PolicyValidateResp, *RawResponse, error) {
	return doJSON[PolicyValidateResp](ctx, c, http.MethodPost, c.v1Path("/policies/validate"), req, opts...)
}

func (c *APIClient) EvaluatePolicy(ctx context.Context, req PolicyEvaluateReq, opts ...RequestOption) (PolicyDecisionResp, *RawResponse, error) {
	return doJSON[PolicyDecisionResp](ctx, c, http.MethodPost, c.v1Path("/policies/evaluate"), req, opts...)
}

func (c *APIClient) GetOperation(ctx context.Context, operationID string, opts ...RequestOption) (OperationResp, *RawResponse, error) {
	return doJSON[OperationResp](ctx, c, http.MethodGet, c.v1Path("/operations/"+url.PathEscape(operationID)), nil, opts...)
}

func (c *APIClient) ListAuditEvents(ctx context.Context, filter AuditFilter, opts ...RequestOption) (AuditEventsResp, *RawResponse, error) {
	q := make(map[string]string)
	aq := c.contracts.AuditQueryParams
	if filter.ResourceType != "" && aq.ResourceTypeParam != "" {
		q[aq.ResourceTypeParam] = filter.ResourceType
	}
	if filter.ResourceID != "" && aq.ResourceIDParam != "" {
		q[aq.ResourceIDParam] = filter.ResourceID
	}
	if filter.EventType != "" && aq.EventTypeParam != "" {
		q[aq.EventTypeParam] = filter.EventType
	}
	if filter.ActorID != "" && aq.ActorIDParam != "" {
		q[aq.ActorIDParam] = filter.ActorID
	}
	if filter.Since != "" && aq.SinceParam != "" {
		q[aq.SinceParam] = filter.Since
	}
	if filter.Until != "" && aq.UntilParam != "" {
		q[aq.UntilParam] = filter.Until
	}
	if filter.Limit > 0 && aq.LimitParam != "" {
		q[aq.LimitParam] = fmt.Sprintf("%d", filter.Limit)
	}
	if filter.Cursor != "" && aq.CursorParam != "" {
		q[aq.CursorParam] = filter.Cursor
	}
	if len(q) > 0 {
		opts = append([]RequestOption{WithQuery(q)}, opts...)
	}
	return doJSON[AuditEventsResp](ctx, c, http.MethodGet, c.v1Path("/audit/events"), nil, opts...)
}

func (c *APIClient) GetMetrics(ctx context.Context) (string, *RawResponse, error) {
	path := c.contracts.MetricsPath
	if path == "" {
		path = "/metrics"
	}
	raw, err := c.DoRaw(ctx, http.MethodGet, path, nil, WithoutAuth())
	if err != nil {
		return "", raw, err
	}
	return string(raw.Body), raw, nil
}

func (c *APIClient) GetHealth(ctx context.Context) (*RawResponse, error) {
	path := c.contracts.HealthPath
	if path == "" {
		path = "/healthz"
	}
	return c.DoRaw(ctx, http.MethodGet, path, nil, WithoutAuth())
}

func (c *APIClient) GetReady(ctx context.Context) (*RawResponse, error) {
	path := c.contracts.ReadyPath
	if path == "" {
		path = "/readyz"
	}
	return c.DoRaw(ctx, http.MethodGet, path, nil, WithoutAuth())
}

// WaitForOperation polls GET /v1/operations/{id} every 50ms until it reaches a terminal status.
func (c *APIClient) WaitForOperation(ctx context.Context, opID string, timeout time.Duration) (OperationResp, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		op, raw, err := c.GetOperation(ctx, opID)
		if err != nil {
			return op, err
		}
		if raw.StatusCode == http.StatusOK {
			if ContainsStatus(c.contracts.OperationStatuses.TerminalSuccess, op.Status) ||
				ContainsStatus(c.contracts.OperationStatuses.TerminalFailure, op.Status) {
				return op, nil
			}
		}
		select {
		case <-ctx.Done():
			return op, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return OperationResp{}, fmt.Errorf("operation %q did not reach terminal status within %s", opID, timeout)
}
