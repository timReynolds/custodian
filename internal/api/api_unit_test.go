package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func TestDecodeStrictJSONBytes(t *testing.T) {
	t.Run("rejects unknown fields", func(t *testing.T) {
		var req CreateWorkspaceRequest
		body := []byte(`{"repository":{"provider":"github","repository_id":1,"ref":"main"},"owner_id":"bad"}`)
		err := decodeStrictJSONBytes(body, &req, false)
		if err == nil {
			t.Fatal("expected error for unknown field owner_id, got nil")
		}
		if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
			t.Fatalf("expected 400 BadRequest, got %d (%v)", domain.HTTPStatusFromError(err), err)
		}
	})

	t.Run("rejects trailing JSON tokens", func(t *testing.T) {
		var req EvaluateProposalRequest
		err := decodeStrictJSONBytes([]byte(`{"expected_version":1} {"extra":2}`), &req, true)
		if err == nil {
			t.Fatal("expected error for trailing JSON tokens, got nil")
		}
		if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
			t.Fatalf("expected 400 BadRequest, got %d", domain.HTTPStatusFromError(err))
		}
	})

	t.Run("rejects null JSON literal", func(t *testing.T) {
		var req EvaluateProposalRequest
		err := decodeStrictJSONBytes([]byte(`null`), &req, true)
		if err == nil {
			t.Fatal("expected error for null JSON body, got nil")
		}
	})

	t.Run("allows empty body only when allowEmpty is true", func(t *testing.T) {
		var req EvaluateProposalRequest
		if err := decodeStrictJSONBytes([]byte("   "), &req, true); err != nil {
			t.Fatalf("expected empty body allowed when allowEmpty=true, got %v", err)
		}
		if err := decodeStrictJSONBytes([]byte("   "), &req, false); err == nil {
			t.Fatal("expected error when empty body and allowEmpty=false")
		}
	})

	t.Run("rejects explicit null on non-nullable optional request fields", func(t *testing.T) {
		cases := []struct {
			name string
			body string
			dst  any
			skip []string
		}{
			{
				name: "CreateWorkspaceRequest agent:null",
				body: `{"repository":{"provider":"github","repository_id":1,"ref":"main"},"agent":null}`,
				dst:  &CreateWorkspaceRequest{},
			},
			{
				name: "CreateWorkspaceRequest source_options:null",
				body: `{"repository":{"provider":"github","repository_id":1,"ref":"main"},"source_options":null}`,
				dst:  &CreateWorkspaceRequest{},
			},
			{
				name: "CreateWorkspaceRequest source_options.include_history:null",
				body: `{"repository":{"provider":"github","repository_id":1,"ref":"main"},"source_options":{"include_history":null}}`,
				dst:  &CreateWorkspaceRequest{},
			},
			{
				name: "EvaluateProposalRequest expected_version:null",
				body: `{"expected_version":null}`,
				dst:  &EvaluateProposalRequest{},
			},
			{
				name: "SubmitProposalRequest description:null",
				body: `{"snapshot":{"artifact_id":"` + domain.MustNewID().String() + `","sha256":"` + strings.Repeat("a", 64) + `","workspace_generation":1},"title":"t","description":null}`,
				dst:  &SubmitProposalRequest{},
			},
			{
				name: "SubmitProposalRequest snapshot.size_bytes:null",
				body: `{"snapshot":{"artifact_id":"` + domain.MustNewID().String() + `","sha256":"` + strings.Repeat("a", 64) + `","workspace_generation":1,"size_bytes":null},"title":"t"}`,
				dst:  &SubmitProposalRequest{},
			},
			{
				name: "SubmitProposalRequest snapshot.captured_at:null",
				body: `{"snapshot":{"artifact_id":"` + domain.MustNewID().String() + `","sha256":"` + strings.Repeat("a", 64) + `","workspace_generation":1,"captured_at":null},"title":"t"}`,
				dst:  &SubmitProposalRequest{},
			},
			{
				name: "SubmitProposalRequest provenance:null",
				body: `{"snapshot":{"artifact_id":"` + domain.MustNewID().String() + `","sha256":"` + strings.Repeat("a", 64) + `","workspace_generation":1},"title":"t","provenance":null}`,
				dst:  &SubmitProposalRequest{},
			},
			{
				name: "CreateApprovalRequest comment:null",
				body: `{"decision":"APPROVE","publication_manifest_digest":"` + strings.Repeat("a", 64) + `","policy_evaluation_id":"` + domain.MustNewID().String() + `","comment":null}`,
				dst:  &CreateApprovalRequest{},
			},
			{
				name: "ValidatePolicyRequest test_cases_yaml:null",
				body: `{"bundle_yaml":"kind: PolicyBundle","test_cases_yaml":null}`,
				dst:  &ValidatePolicyRequest{},
			},
			{
				name: "SimulatePolicyRequest bundle_yaml:null",
				body: `{"bundle_yaml":null,"stage":"EGRESS","input":{}}`,
				dst:  &SimulatePolicyRequest{},
				skip: []string{"input"},
			},
			{
				name: "SimulatePolicyRequest org_bundle_yaml:null",
				body: `{"org_bundle_yaml":null,"bundle_id":"` + domain.MustNewID().String() + `","stage":"EGRESS","input":{}}`,
				dst:  &SimulatePolicyRequest{},
				skip: []string{"input"},
			},
			{
				name: "SimulatePolicyRequest bundle_id:null",
				body: `{"bundle_yaml":"kind: PolicyBundle","bundle_id":null,"stage":"EGRESS","input":{}}`,
				dst:  &SimulatePolicyRequest{},
				skip: []string{"input"},
			},
			{
				name: "SimulatePolicyRequest input:null",
				body: `{"bundle_yaml":"kind: PolicyBundle","stage":"EGRESS","input":null}`,
				dst:  &SimulatePolicyRequest{},
				skip: []string{"input"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := decodeStrictJSONBytes([]byte(tc.body), tc.dst, false, tc.skip...)
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
				if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
					t.Fatalf("expected 400 BadRequest for %s, got %d (%v)", tc.name, domain.HTTPStatusFromError(err), err)
				}
			})
		}

		// SimulatePolicyRequest allows null inside input map (PolicySimulationInput has additionalProperties: true).
		var simReq SimulatePolicyRequest
		if err := decodeStrictJSONBytes([]byte(`{"bundle_yaml":"kind: PolicyBundle","stage":"EGRESS","input":{"extra":null}}`), &simReq, false, "input"); err != nil {
			t.Fatalf("expected SimulatePolicyRequest input child null to be allowed, got %v", err)
		}
	})

	t.Run("validateSubmitProposalRequest rejects empty or whitespace captured_at", func(t *testing.T) {
		for _, bad := range []string{"", "   "} {
			v := bad
			req := SubmitProposalRequest{
				Title: "Fix",
				Snapshot: &SnapshotCaptureInputDTO{
					ArtifactID:          domain.MustNewID().String(),
					SHA256:              strings.Repeat("a", 64),
					WorkspaceGeneration: 1,
					CapturedAt:          &v,
				},
			}
			if _, _, _, _, _, _, err := validateSubmitProposalRequest(req); err == nil {
				t.Fatalf("expected error for captured_at=%q, got nil", bad)
			} else if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
				t.Fatalf("expected 400 BadRequest for captured_at=%q, got %d", bad, domain.HTTPStatusFromError(err))
			}
		}
	})
}

func TestParseUUIDv7(t *testing.T) {
	v7 := domain.MustNewID()
	parsed, err := parseUUIDv7(v7.String())
	if err != nil || parsed != v7 {
		t.Fatalf("expected valid UUIDv7 %s, got parsed=%s err=%v", v7, parsed, err)
	}

	v4 := uuid.New()
	if _, err := parseUUIDv7(v4.String()); err == nil {
		t.Fatalf("expected UUIDv4 %s to be rejected", v4)
	} else if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
		t.Fatalf("expected 400 for UUIDv4, got %d", domain.HTTPStatusFromError(err))
	}

	if _, err := parseUUIDv7(uuid.Nil.String()); err == nil {
		t.Fatal("expected nil UUID to be rejected")
	}

	if _, err := parseUUIDv7("not-a-uuid"); err == nil {
		t.Fatal("expected malformed UUID to be rejected")
	}
}

func TestParseIfMatchHeader(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    *int64
		wantErr bool
	}{
		{name: "empty", raw: "", want: nil},
		{name: "plain int", raw: "3", want: int64Ptr(3)},
		{name: "quoted ETag", raw: `"7"`, want: int64Ptr(7)},
		{name: "weak ETag", raw: `W/"12"`, want: int64Ptr(12)},
		{name: "zero rejected", raw: "0", wantErr: true},
		{name: "negative rejected", raw: `"-2"`, wantErr: true},
		{name: "non-numeric rejected", raw: `"abc"`, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIfMatchHeader(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.raw, err)
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %d", *got)
				}
				return
			}
			if got == nil || *got != *tc.want {
				t.Fatalf("expected %d, got %v", *tc.want, got)
			}
		})
	}
}

func TestParseIdempotencyKeyHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", nil)
	if _, err := parseIdempotencyKeyHeader(req, true); err == nil {
		t.Fatal("expected error for missing required Idempotency-Key")
	}
	if key, err := parseIdempotencyKeyHeader(req, false); err != nil || key != "" {
		t.Fatalf("expected empty optional Idempotency-Key without error, got %q err=%v", key, err)
	}

	req.Header.Set("Idempotency-Key", "bad key with spaces!")
	if _, err := parseIdempotencyKeyHeader(req, false); err == nil {
		t.Fatal("expected error for invalid Idempotency-Key characters")
	}

	req.Header.Set("Idempotency-Key", "req_123.abc-XYZ")
	key, err := parseIdempotencyKeyHeader(req, true)
	if err != nil || key != "req_123.abc-XYZ" {
		t.Fatalf("expected valid key, got %q err=%v", key, err)
	}
}

func TestDTOFormattingAndNullability(t *testing.T) {
	propID := domain.MustNewID()
	pubID := domain.MustNewID()
	emptyCommit := ""
	emptyURL := "   "
	pubDTO := toPublicationDTO(persistence.PublicationRow{
		ID:             pubID,
		ProposalID:     propID,
		BranchRef:      "refs/heads/custodian/" + propID.String(),
		CommitSHA:      &emptyCommit,
		PullRequestURL: &emptyURL,
		Status:         domain.PublicationStatusPending,
		AttemptCount:   0,
		CreatedAt:      time.Now().UTC(),
	})
	if pubDTO.BranchRef != "custodian/"+propID.String() {
		t.Fatalf("expected branch_ref custodian/%s, got %q", propID, pubDTO.BranchRef)
	}
	if strings.HasPrefix(pubDTO.BranchRef, "refs/heads/") {
		t.Fatalf("branch_ref must not have refs/heads/ prefix: %q", pubDTO.BranchRef)
	}
	if pubDTO.CommitSHA != nil {
		t.Fatalf("expected nil CommitSHA when empty, got %q", *pubDTO.CommitSHA)
	}
	if pubDTO.PullRequestURL != nil {
		t.Fatalf("expected nil PullRequestURL when blank, got %q", *pubDTO.PullRequestURL)
	}

	rawHex := strings.Repeat("AB", 32)
	if got := normalizeHex64("sha256:" + rawHex); got != strings.ToLower(rawHex) {
		t.Fatalf("expected 64-char lowercase hex without sha256: prefix, got %q", got)
	}
	if got := normalizeHex64OrNil("   "); got != nil {
		t.Fatalf("expected nil for empty hex, got %q", *got)
	}

	simDTO := toSimulatePolicyResponse(policy.EvalResult{
		Effect:       domain.PolicyEffectAllow,
		BundleDigest: "sha256:" + strings.Repeat("c", 64),
		InputDigest:  "sha256:" + strings.Repeat("d", 64),
	})
	if simDTO.MatchedRuleIDs == nil || simDTO.Obligations == nil || simDTO.RuleTrace == nil {
		t.Fatalf("expected non-nil empty slices in SimulatePolicyResponse: %+v", simDTO)
	}
	if strings.HasPrefix(simDTO.BundleDigest, "sha256:") || len(simDTO.BundleDigest) != 64 {
		t.Fatalf("unexpected bundle_digest format: %q", simDTO.BundleDigest)
	}

	auditDTO := toAuditEventDTO(domain.AuditEvent{
		ID:           domain.MustNewID(),
		EventType:    "TEST_EVENT",
		ResourceType: "WORKSPACE",
		ResourceID:   domain.MustNewID(),
		Payload:      nil,
		PreviousHash: "",
		EventHash:    "sha256:" + strings.Repeat("e", 64),
		CreatedAt:    time.Now().UTC(),
	})
	if string(auditDTO.Payload) != "{}" {
		t.Fatalf("expected empty AuditEvent payload to serialize as {}, got %s", string(auditDTO.Payload))
	}
	if auditDTO.PreviousHash != nil {
		t.Fatalf("expected nil PreviousHash for genesis event, got %q", *auditDTO.PreviousHash)
	}
	rawJSON, err := json.Marshal(auditDTO)
	if err != nil {
		t.Fatalf("marshal AuditEventDTO: %v", err)
	}
	if !strings.Contains(string(rawJSON), `"payload":{}`) {
		t.Fatalf("expected serialized payload:{}, got %s", string(rawJSON))
	}
}

func TestBuildErrorResponsePolicyDeniedAndRateLimit(t *testing.T) {
	decID := domain.MustNewID()
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals/id/publish", nil)

	status, resp := buildErrorResponse(req, &proposals.PolicyDeniedError{
		PolicyDecisionID: decID,
		Effect:           domain.PolicyEffectDeny,
		Err:              domain.Conflict("POLICY_DENIED", "blocked by policy"),
	})
	if status != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for PolicyDeniedError, got %d", status)
	}
	if resp.Error.PolicyDecisionID == nil || *resp.Error.PolicyDecisionID != decID.String() {
		t.Fatalf("expected policy_decision_id %s, got %v", decID, resp.Error.PolicyDecisionID)
	}

	rlStatus, rlResp := buildErrorResponse(req, domain.RateLimited("REPO_CONCURRENCY_EXCEEDED", "too many concurrent runs"))
	if rlStatus != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rlStatus)
	}
	if rlResp.Error.Code != "REPO_CONCURRENCY_EXCEEDED" {
		t.Fatalf("unexpected error code: %s", rlResp.Error.Code)
	}
}

func TestRBACAndConcurrencyHelpers(t *testing.T) {
	ownerID := domain.MustNewID()
	human := identity.CallerContext{
		Principal: domain.Principal{ID: ownerID, Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindHuman, Roles: []string{"developer"}, Scopes: []string{"repo:history"}},
	}
	auditor := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindAuditor, Roles: []string{"auditor"}},
	}
	policyAdmin := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindPolicyAdmin, Roles: []string{"policy_admin"}},
	}
	reviewer := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindHuman, Roles: []string{"reviewer"}},
	}
	controller := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindService},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindController, Roles: []string{"controller"}},
	}

	if !isRegularHuman(human) || isRegularHuman(auditor) || isRegularHuman(policyAdmin) || isRegularHuman(controller) {
		t.Fatalf("isRegularHuman mismatch")
	}
	if !hasHistoryAuthorization(human) || hasHistoryAuthorization(reviewer) {
		t.Fatalf("hasHistoryAuthorization mismatch")
	}
	if !canReadProposalByOwnerID(human, ownerID) || canReadProposalByOwnerID(reviewer, ownerID) == false {
		t.Fatalf("expected owner and reviewer to read proposal")
	}
	if canReadProposalByOwnerID(auditor, ownerID) {
		t.Fatalf("auditor without controller/reviewer/owner role should not read proposal")
	}
	if !canReadProposalByOwnerID(controller, ownerID) {
		t.Fatalf("controller should read proposal")
	}

	if got := effectiveRepoConcurrencyLimit(3, 5); got != 3 {
		t.Fatalf("expected min(3,5)=3, got %d", got)
	}
	if got := effectiveRepoConcurrencyLimit(0, 4); got != 4 {
		t.Fatalf("expected 4, got %d", got)
	}
	if got := effectiveRepoConcurrencyLimit(2, 0); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}
	if got := effectiveRepoConcurrencyLimit(0, 0); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func int64Ptr(v int64) *int64 { return &v }

func TestMaxLengthUntrimmedValidation(t *testing.T) {
	validSnap := &SnapshotCaptureInputDTO{
		ArtifactID:          domain.MustNewID().String(),
		SHA256:              strings.Repeat("a", 64),
		WorkspaceGeneration: 1,
	}

	t.Run("SubmitProposalRequest rejects untrimmed title > 256 even when trimmed <= 256", func(t *testing.T) {
		badTitles := []struct {
			name  string
			title string
		}{
			{name: "leading spaces 257", title: "  " + strings.Repeat("a", 255)},
			{name: "trailing spaces 257", title: strings.Repeat("a", 255) + "  "},
			{name: "blank spaces", title: "   "},
			{name: "empty", title: ""},
			{name: "unicode 257 runes", title: strings.Repeat("é", 257)},
		}
		for _, tc := range badTitles {
			t.Run(tc.name, func(t *testing.T) {
				req := SubmitProposalRequest{Snapshot: validSnap, Title: tc.title}
				_, _, _, _, _, _, err := validateSubmitProposalRequest(req)
				if err == nil {
					t.Fatalf("expected error for title len=%d, got nil", len(tc.title))
				}
				if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
					t.Fatalf("expected 400 BadRequest, got %d (%v)", domain.HTTPStatusFromError(err), err)
				}
			})
		}

		// Exactly 256 characters (with spaces) must pass validation.
		okReq := SubmitProposalRequest{Snapshot: validSnap, Title: "  " + strings.Repeat("a", 254)}
		if _, _, _, _, _, _, err := validateSubmitProposalRequest(okReq); err != nil {
			t.Fatalf("expected 256-char title with leading spaces to pass, got %v", err)
		}
	})

	t.Run("SubmitProposalRequest rejects untrimmed description > 8192 runes", func(t *testing.T) {
		tooLong := "  " + strings.Repeat("a", 8191)
		req := SubmitProposalRequest{Snapshot: validSnap, Title: "Valid", Description: &tooLong}
		if _, _, _, _, _, _, err := validateSubmitProposalRequest(req); err == nil {
			t.Fatal("expected error for 8193-char description, got nil")
		} else if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
			t.Fatalf("expected 400 BadRequest, got %d", domain.HTTPStatusFromError(err))
		}

		exactRunes := strings.Repeat("é", 8192)
		okReq := SubmitProposalRequest{Snapshot: validSnap, Title: "Valid", Description: &exactRunes}
		if _, _, _, _, _, _, err := validateSubmitProposalRequest(okReq); err != nil {
			t.Fatalf("expected 8192-rune UTF-8 description to pass, got %v", err)
		}
	})

	t.Run("CreateWorkspaceRequest rejects untrimmed ref and agent fields > maxLength", func(t *testing.T) {
		baseRepo := func(ref string) *WorkspaceRepositoryInputDTO {
			return &WorkspaceRepositoryInputDTO{
				Provider:     "github",
				RepositoryID: 1001,
				Ref:          ref,
			}
		}

		cases := []struct {
			name string
			req  CreateWorkspaceRequest
		}{
			{
				name: "ref 257 with leading spaces",
				req:  CreateWorkspaceRequest{Repository: baseRepo("  " + strings.Repeat("a", 255))},
			},
			{
				name: "ref blank spaces",
				req:  CreateWorkspaceRequest{Repository: baseRepo("   ")},
			},
			{
				name: "agent.type 129 with spaces",
				req: CreateWorkspaceRequest{
					Repository: baseRepo("main"),
					Agent:      &WorkspaceAgentInputDTO{Type: "  " + strings.Repeat("a", 127), SessionID: "s1", ModelRoute: "openai/gpt-5"},
				},
			},
			{
				name: "agent.session_id 257 with spaces",
				req: CreateWorkspaceRequest{
					Repository: baseRepo("main"),
					Agent:      &WorkspaceAgentInputDTO{Type: "codex", SessionID: "  " + strings.Repeat("a", 255), ModelRoute: "openai/gpt-5"},
				},
			},
			{
				name: "agent.model_route 129 with spaces",
				req: CreateWorkspaceRequest{
					Repository: baseRepo("main"),
					Agent:      &WorkspaceAgentInputDTO{Type: "codex", SessionID: "s1", ModelRoute: "  " + strings.Repeat("a", 127)},
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := validateCreateWorkspaceRequest(tc.req)
				if err == nil {
					t.Fatalf("expected 400 error for %s, got nil", tc.name)
				}
				if domain.HTTPStatusFromError(err) != http.StatusBadRequest {
					t.Fatalf("expected 400 BadRequest for %s, got %d (%v)", tc.name, domain.HTTPStatusFromError(err), err)
				}
			})
		}

		// Boundary exact maxLength values with spaces pass.
		okReq := CreateWorkspaceRequest{
			Repository: baseRepo(" " + strings.Repeat("a", 255)),
			Agent: &WorkspaceAgentInputDTO{
				Type:       " " + strings.Repeat("a", 127),
				SessionID:  " " + strings.Repeat("a", 255),
				ModelRoute: " " + strings.Repeat("a", 127),
			},
		}
		if err := validateCreateWorkspaceRequest(okReq); err != nil {
			t.Fatalf("expected exact maxLength fields with leading space to pass, got %v", err)
		}
	})
}

type stubTokenVerifier struct {
	claims auth.VerifiedClaims
}

func (v stubTokenVerifier) Verify(_ context.Context, _ string) (auth.VerifiedClaims, error) {
	return v.claims, nil
}

type stubPrincipalStore struct {
	getByIssuerSubjectFn func(ctx context.Context, issuer, subject string) (domain.Principal, error)
}

func (s stubPrincipalStore) GetByID(_ context.Context, _ uuid.UUID) (domain.Principal, error) {
	return domain.Principal{}, domain.NotFound("NOT_FOUND", "not found")
}

func (s stubPrincipalStore) GetByIssuerSubject(ctx context.Context, issuer, subject string) (domain.Principal, error) {
	if s.getByIssuerSubjectFn != nil {
		return s.getByIssuerSubjectFn(ctx, issuer, subject)
	}
	return domain.Principal{}, domain.NotFound("NOT_FOUND", "not found")
}

func (s stubPrincipalStore) Upsert(_ context.Context, p domain.Principal) (domain.Principal, error) {
	return p, nil
}

type stubWorkspaceStore struct {
	workspaces.Store
	getByIDFn        func(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error)
	getDetailsByIDFn func(ctx context.Context, id uuid.UUID) (persistence.WorkspaceDetailsRow, error)
}

func (s stubWorkspaceStore) GetWorkspaceByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error) {
	if s.getByIDFn != nil {
		return s.getByIDFn(ctx, id)
	}
	return persistence.WorkspaceRow{}, domain.NotFound("NOT_FOUND", "not found")
}

func (s stubWorkspaceStore) GetWorkspaceDetailsByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceDetailsRow, error) {
	if s.getDetailsByIDFn != nil {
		return s.getDetailsByIDFn(ctx, id)
	}
	return persistence.WorkspaceDetailsRow{}, domain.NotFound("NOT_FOUND", "not found")
}

type stubArtifactStore struct {
	artifacts.Store
	getByIDFn func(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error)
}

func (s stubArtifactStore) GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
	if s.getByIDFn != nil {
		return s.getByIDFn(ctx, id)
	}
	return persistence.ArtifactRow{}, domain.NotFound("NOT_FOUND", "not found")
}

type slowSnapshotStore struct {
	domain.SnapshotStore
	delay   time.Duration
	payload []byte
}

func (s slowSnapshotStore) Open(ctx context.Context, _ domain.Artifact) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &delayedReader{ctx: ctx, delay: s.delay, reader: bytes.NewReader(s.payload)}, nil
}

type delayedReader struct {
	ctx    context.Context
	delay  time.Duration
	waited bool
	reader *bytes.Reader
}

func (d *delayedReader) Read(p []byte) (int, error) {
	if !d.waited {
		d.waited = true
		select {
		case <-d.ctx.Done():
			return 0, d.ctx.Err()
		case <-time.After(d.delay):
		}
	}
	return d.reader.Read(p)
}

func (d *delayedReader) Close() error { return nil }

func TestDBTimeoutMapsTo503AndLeavesStreamingUnbounded(t *testing.T) {
	ownerID := domain.MustNewID()
	wsID := domain.MustNewID()
	artID := domain.MustNewID()

	humanClaims := auth.VerifiedClaims{
		Issuer:        "https://issuer.example",
		Subject:       "alice",
		Kind:          domain.PrincipalKindHuman,
		TokenKind:     auth.TokenKindHuman,
		Email:         "alice@example.com",
		EmailVerified: true,
	}
	controllerClaims := auth.VerifiedClaims{
		Issuer:    "https://issuer.example",
		Subject:   "controller-1",
		Kind:      domain.PrincipalKindService,
		TokenKind: auth.TokenKindController,
		Roles:     []string{"controller"},
	}

	t.Run("ResolveCaller timeout in OIDC middleware returns 503 DATABASE_TIMEOUT", func(t *testing.T) {
		dir, err := identity.NewDirectory(stubPrincipalStore{
			getByIssuerSubjectFn: func(ctx context.Context, _, _ string) (domain.Principal, error) {
				<-ctx.Done()
				return domain.Principal{}, persistence.MapError(ctx.Err())
			},
		}, identity.DefaultDirectoryConfig())
		if err != nil {
			t.Fatalf("NewDirectory: %v", err)
		}

		router := NewRouter(Deps{
			OIDC:       stubTokenVerifier{claims: humanClaims},
			Directory:  dir,
			Workspaces: workspaces.NewServiceWithStore(stubWorkspaceStore{}, nil, nil),
			DBTimeout:  30 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+wsID.String(), nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer dummy")
		rec := httptest.NewRecorder()

		start := time.Now()
		router.ServeHTTP(rec, req)
		elapsed := time.Since(start)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d (%s)", rec.Code, rec.Body.String())
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("expected fast server-side DB timeout (<500ms), took %v", elapsed)
		}
		var errResp ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("unmarshal error response: %v", err)
		}
		if errResp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected DATABASE_TIMEOUT, got %q", errResp.Error.Code)
		}
	})

	t.Run("handleGetWorkspace DB timeout returns 503 DATABASE_TIMEOUT", func(t *testing.T) {
		dir, err := identity.NewDirectory(stubPrincipalStore{
			getByIssuerSubjectFn: func(_ context.Context, issuer, subject string) (domain.Principal, error) {
				return domain.Principal{
					ID: ownerID, Kind: domain.PrincipalKindHuman, Issuer: issuer, Subject: subject,
					VerifiedEmail: "alice@example.com",
				}, nil
			},
		}, identity.DefaultDirectoryConfig())
		if err != nil {
			t.Fatalf("NewDirectory: %v", err)
		}

		wsSvc := workspaces.NewServiceWithStore(stubWorkspaceStore{
			getDetailsByIDFn: func(ctx context.Context, _ uuid.UUID) (persistence.WorkspaceDetailsRow, error) {
				<-ctx.Done()
				return persistence.WorkspaceDetailsRow{}, ctx.Err()
			},
		}, nil, nil)

		router := NewRouter(Deps{
			OIDC:       stubTokenVerifier{claims: humanClaims},
			Directory:  dir,
			Workspaces: wsSvc,
			DBTimeout:  30 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+wsID.String(), nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer dummy")
		rec := httptest.NewRecorder()

		start := time.Now()
		router.ServeHTTP(rec, req)
		elapsed := time.Since(start)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d (%s)", rec.Code, rec.Body.String())
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("expected fast server-side DB timeout (<500ms), took %v", elapsed)
		}
		var errResp ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("unmarshal error response: %v", err)
		}
		if errResp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected DATABASE_TIMEOUT, got %q", errResp.Error.Code)
		}
	})

	t.Run("handleDownloadWorkspaceSourceArtifact does not truncate io.Copy with DBTimeout", func(t *testing.T) {
		dir, err := identity.NewDirectory(stubPrincipalStore{
			getByIssuerSubjectFn: func(_ context.Context, issuer, subject string) (domain.Principal, error) {
				return domain.Principal{
					ID: ownerID, Kind: domain.PrincipalKindService, Issuer: issuer, Subject: subject,
				}, nil
			},
		}, identity.DefaultDirectoryConfig())
		if err != nil {
			t.Fatalf("NewDirectory: %v", err)
		}

		payload := []byte("streaming-tar-gz-payload")
		sha := domain.SHA256Hex(payload)
		wsSvc := workspaces.NewServiceWithStore(stubWorkspaceStore{
			getByIDFn: func(_ context.Context, id uuid.UUID) (persistence.WorkspaceRow, error) {
				return persistence.WorkspaceRow{
					ID: id, OwnerID: ownerID, Status: domain.WorkspaceStatusReady,
					SourceArtifactID: &artID, BaseCommit: strings.Repeat("a", 40),
				}, nil
			},
		}, nil, nil)
		artSvc := artifacts.NewService(stubArtifactStore{
			getByIDFn: func(_ context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
				return persistence.ArtifactRow{
					ID: id, Kind: domain.ArtifactKindWorkspaceSource, SHA256: sha,
					SizeBytes: int64(len(payload)), StorageKey: "k", StorageGeneration: "1",
				}, nil
			},
		}, nil)

		router := NewRouter(Deps{
			OIDC:       stubTokenVerifier{claims: controllerClaims},
			Directory:  dir,
			Workspaces: wsSvc,
			Artifacts:  artSvc,
			Snapshots:  slowSnapshotStore{delay: 80 * time.Millisecond, payload: payload},
			DBTimeout:  20 * time.Millisecond,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+wsID.String()+"/source/artifact", nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer dummy")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for slow stream longer than DBTimeout, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !bytes.Equal(rec.Body.Bytes(), payload) {
			t.Fatalf("streamed payload mismatch: got %q, want %q", rec.Body.Bytes(), payload)
		}
	})
}

type stubAdvisoryLockPool struct {
	acquireFn func(ctx context.Context) (advisoryLockConn, error)
}

func (p stubAdvisoryLockPool) Acquire(ctx context.Context) (advisoryLockConn, error) {
	return p.acquireFn(ctx)
}

type stubAdvisoryLockConn struct {
	execFn    func(ctx context.Context, sql string, args ...any) error
	releaseFn func()
	closeFn   func(ctx context.Context) error
}

func (c stubAdvisoryLockConn) Exec(ctx context.Context, sql string, args ...any) error {
	if c.execFn != nil {
		return c.execFn(ctx, sql, args...)
	}
	return nil
}

func (c stubAdvisoryLockConn) Release() {
	if c.releaseFn != nil {
		c.releaseFn()
	}
}

func (c stubAdvisoryLockConn) Close(ctx context.Context) error {
	if c.closeFn != nil {
		return c.closeFn(ctx)
	}
	return nil
}

func TestWithAdvisoryLockDBTimeoutAndParentDeadline(t *testing.T) {
	t.Run("pool.Acquire stall returns 503 DATABASE_TIMEOUT within DBTimeout", func(t *testing.T) {
		s := newServer(Deps{DBTimeout: 30 * time.Millisecond})
		s.lockPool = stubAdvisoryLockPool{
			acquireFn: func(ctx context.Context) (advisoryLockConn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		start := time.Now()
		err := s.withRepoLock(ctx, domain.MustNewID(), func() error {
			t.Fatal("callback must not execute when Acquire times out")
			return nil
		})
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected error when Acquire stalls")
		}
		if elapsed > 300*time.Millisecond {
			t.Fatalf("expected timeout near DBTimeout (30ms), took %v", elapsed)
		}
		status, resp := buildErrorResponse(nil, err)
		if status != http.StatusServiceUnavailable || resp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected 503 DATABASE_TIMEOUT, got status=%d code=%q err=%v", status, resp.Error.Code, err)
		}
	})

	t.Run("pg_advisory_lock Exec stall returns 503 DATABASE_TIMEOUT within DBTimeout and releases conn", func(t *testing.T) {
		var mu sync.Mutex
		released := false
		unlocked := false

		s := newServer(Deps{DBTimeout: 30 * time.Millisecond})
		s.lockPool = stubAdvisoryLockPool{
			acquireFn: func(_ context.Context) (advisoryLockConn, error) {
				return stubAdvisoryLockConn{
					execFn: func(ctx context.Context, sql string, _ ...any) error {
						if strings.Contains(sql, "pg_advisory_unlock") {
							mu.Lock()
							unlocked = true
							mu.Unlock()
							return nil
						}
						<-ctx.Done()
						return ctx.Err()
					},
					releaseFn: func() {
						mu.Lock()
						released = true
						mu.Unlock()
					},
				}, nil
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		start := time.Now()
		err := s.withEvalBudgetLock(ctx, func() error {
			t.Fatal("callback must not execute when pg_advisory_lock times out")
			return nil
		})
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected error when pg_advisory_lock stalls")
		}
		if elapsed > 300*time.Millisecond {
			t.Fatalf("expected timeout near DBTimeout (30ms), took %v", elapsed)
		}
		status, resp := buildErrorResponse(nil, err)
		if status != http.StatusServiceUnavailable || resp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected 503 DATABASE_TIMEOUT, got status=%d code=%q err=%v", status, resp.Error.Code, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if !released {
			t.Fatal("expected conn.Release() to be called when pg_advisory_lock fails")
		}
		if unlocked {
			t.Fatal("pg_advisory_unlock must not be called when pg_advisory_lock failed")
		}
	})

	t.Run("localSem contention times out at DBTimeout while holder runs longer with un-canceled ctx", func(t *testing.T) {
		var mu sync.Mutex
		unlockCalls := 0
		s := newServer(Deps{DBTimeout: 35 * time.Millisecond})
		s.lockPool = stubAdvisoryLockPool{
			acquireFn: func(_ context.Context) (advisoryLockConn, error) {
				return stubAdvisoryLockConn{
					execFn: func(_ context.Context, sql string, _ ...any) error {
						if strings.Contains(sql, "pg_advisory_unlock") {
							mu.Lock()
							unlockCalls++
							mu.Unlock()
						}
						return nil
					},
				}, nil
			},
		}

		repoID := domain.MustNewID()
		entered := make(chan struct{})
		releaseHolder := make(chan struct{})
		holderDone := make(chan error, 1)

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			holderDone <- s.withRepoLock(ctx, repoID, func() error {
				close(entered)
				<-releaseHolder
				// Running longer than DBTimeout must NOT cancel parent ctx!
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return nil
			})
		}()

		<-entered
		// Waiter must fail on localSem at ~DBTimeout (35ms), not block on holder.
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer waitCancel()
		start := time.Now()
		waitErr := s.withRepoLock(waitCtx, repoID, func() error {
			t.Fatal("waiter callback must not run while holder holds localSem")
			return nil
		})
		elapsed := time.Since(start)

		status, resp := buildErrorResponse(nil, waitErr)
		if status != http.StatusServiceUnavailable || resp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected waiter to fail with 503 DATABASE_TIMEOUT, got status=%d code=%q err=%v", status, resp.Error.Code, waitErr)
		}
		if elapsed > 300*time.Millisecond {
			t.Fatalf("expected waiter to fail near DBTimeout (35ms), took %v", elapsed)
		}

		// Let holder run slightly past DBTimeout and succeed.
		time.Sleep(50 * time.Millisecond)
		close(releaseHolder)
		if err := <-holderDone; err != nil {
			t.Fatalf("expected holder to complete cleanly after DBTimeout elapsed, got %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if unlockCalls != 1 {
			t.Fatalf("expected 1 pg_advisory_unlock call, got %d", unlockCalls)
		}
	})

	t.Run("parent deadline shorter than DBTimeout during lock acquisition is NOT mapped to 503 DATABASE_TIMEOUT", func(t *testing.T) {
		s := newServer(Deps{DBTimeout: 500 * time.Millisecond})
		s.lockPool = stubAdvisoryLockPool{
			acquireFn: func(ctx context.Context) (advisoryLockConn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}

		parentCtx, parentCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer parentCancel()

		err := s.withRepoLock(parentCtx, domain.MustNewID(), func() error {
			return nil
		})
		if err == nil {
			t.Fatal("expected error when parent deadline expires")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded cause, got %v", err)
		}
		status, resp := buildErrorResponse(nil, err)
		if status == http.StatusServiceUnavailable || resp.Error.Code == "DATABASE_TIMEOUT" {
			t.Fatalf("parent deadline must NOT be misclassified as 503 DATABASE_TIMEOUT, got status=%d code=%q", status, resp.Error.Code)
		}
	})
}

func TestMapDBTimeoutErrorParentDeadlineNotMisclassifiedAs503(t *testing.T) {
	t.Run("direct mapDBTimeoutError distinguishes DBTimeout vs parent deadline", func(t *testing.T) {
		// 1. Genuine DBTimeout expiration -> 503 DATABASE_TIMEOUT (both raw and persistence.MapError).
		parentLong, cancelLong := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelLong()
		dbCtx1, cancelDB1 := withDBTimeoutCause(parentLong, 15*time.Millisecond)
		defer cancelDB1()
		<-dbCtx1.Done()

		for _, rawErr := range []error{dbCtx1.Err(), persistence.MapError(dbCtx1.Err())} {
			mapped := mapDBTimeoutError(dbCtx1, rawErr)
			status, resp := buildErrorResponse(nil, mapped)
			if status != http.StatusServiceUnavailable || resp.Error.Code != "DATABASE_TIMEOUT" {
				t.Fatalf("expected 503 DATABASE_TIMEOUT for genuine DBTimeout, got status=%d code=%q (%v)", status, resp.Error.Code, mapped)
			}
		}

		// 2. Parent deadline shorter than DBTimeout -> must NOT map to 503 DATABASE_TIMEOUT
		// (both raw context.DeadlineExceeded and persistence.MapError-wrapped).
		parentShort, cancelShort := context.WithTimeout(context.Background(), 15*time.Millisecond)
		defer cancelShort()
		dbCtx2, cancelDB2 := withDBTimeoutCause(parentShort, 500*time.Millisecond)
		defer cancelDB2()
		<-dbCtx2.Done()

		for _, rawErr := range []error{dbCtx2.Err(), persistence.MapError(dbCtx2.Err())} {
			mapped := mapDBTimeoutError(dbCtx2, rawErr)
			status, resp := buildErrorResponse(nil, mapped)
			if status == http.StatusServiceUnavailable || resp.Error.Code == "DATABASE_TIMEOUT" {
				t.Fatalf("parent deadline must NOT map to 503 DATABASE_TIMEOUT, got status=%d code=%q (%v)", status, resp.Error.Code, mapped)
			}
			if !errors.Is(mapped, context.DeadlineExceeded) {
				t.Fatalf("expected mapped error to preserve context.DeadlineExceeded, got %v", mapped)
			}
		}
	})

	ownerID := domain.MustNewID()
	wsID := domain.MustNewID()
	humanClaims := auth.VerifiedClaims{
		Issuer:        "https://issuer.example",
		Subject:       "alice",
		Kind:          domain.PrincipalKindHuman,
		TokenKind:     auth.TokenKindHuman,
		Email:         "alice@example.com",
		EmailVerified: true,
	}

	t.Run("OIDC ResolveCaller with parent deadline < DBTimeout does NOT return 503 DATABASE_TIMEOUT", func(t *testing.T) {
		dir, err := identity.NewDirectory(stubPrincipalStore{
			getByIssuerSubjectFn: func(ctx context.Context, _, _ string) (domain.Principal, error) {
				<-ctx.Done()
				return domain.Principal{}, persistence.MapError(ctx.Err())
			},
		}, identity.DefaultDirectoryConfig())
		if err != nil {
			t.Fatalf("NewDirectory: %v", err)
		}

		router := NewRouter(Deps{
			OIDC:       stubTokenVerifier{claims: humanClaims},
			Directory:  dir,
			Workspaces: workspaces.NewServiceWithStore(stubWorkspaceStore{}, nil, nil),
			DBTimeout:  500 * time.Millisecond,
		})

		parentCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+wsID.String(), nil).WithContext(parentCtx)
		req.Header.Set("Authorization", "Bearer dummy")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		var errResp ErrorResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		if rec.Code == http.StatusServiceUnavailable || errResp.Error.Code == "DATABASE_TIMEOUT" {
			t.Fatalf("parent deadline expiration in OIDC middleware must NOT return 503 DATABASE_TIMEOUT, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("handleGetWorkspace with parent deadline < DBTimeout does NOT return 503 DATABASE_TIMEOUT", func(t *testing.T) {
		dir, err := identity.NewDirectory(stubPrincipalStore{
			getByIssuerSubjectFn: func(_ context.Context, issuer, subject string) (domain.Principal, error) {
				return domain.Principal{
					ID: ownerID, Kind: domain.PrincipalKindHuman, Issuer: issuer, Subject: subject,
					VerifiedEmail: "alice@example.com",
				}, nil
			},
		}, identity.DefaultDirectoryConfig())
		if err != nil {
			t.Fatalf("NewDirectory: %v", err)
		}

		for _, tc := range []struct {
			name   string
			mapErr bool
		}{
			{name: "raw ctx.Err()", mapErr: false},
			{name: "persistence.MapError(ctx.Err())", mapErr: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wsSvc := workspaces.NewServiceWithStore(stubWorkspaceStore{
					getDetailsByIDFn: func(ctx context.Context, _ uuid.UUID) (persistence.WorkspaceDetailsRow, error) {
						<-ctx.Done()
						if tc.mapErr {
							return persistence.WorkspaceDetailsRow{}, persistence.MapError(ctx.Err())
						}
						return persistence.WorkspaceDetailsRow{}, ctx.Err()
					},
				}, nil, nil)

				router := NewRouter(Deps{
					OIDC:       stubTokenVerifier{claims: humanClaims},
					Directory:  dir,
					Workspaces: wsSvc,
					DBTimeout:  500 * time.Millisecond,
				})

				parentCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
				defer cancel()
				req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/"+wsID.String(), nil).WithContext(parentCtx)
				req.Header.Set("Authorization", "Bearer dummy")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				var errResp ErrorResponse
				_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
				if rec.Code == http.StatusServiceUnavailable || errResp.Error.Code == "DATABASE_TIMEOUT" {
					t.Fatalf("parent deadline expiration must NOT return 503 DATABASE_TIMEOUT, got %d (%s)", rec.Code, rec.Body.String())
				}
			})
		}
	})
}
