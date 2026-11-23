package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/api/openapi"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func TestOpenAPIParityAll16Routes(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, nil)

	val, err := openapi.NewHTTPValidator()
	if err != nil {
		t.Fatalf("NewHTTPValidator: %v", err)
	}
	defer val.Release()

	humanA := env.mintHuman("human-a", "alice@acme.test", []string{"sec-reviewers"}, []string{"developer"}, "openid profile email")
	humanB := env.mintHuman("human-b", "bob@acme.test", []string{"security-reviewers"}, []string{"reviewer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-1")
	auditorToken := env.mintAuditor("auditor-1")
	policyAdminToken := env.mintPolicyAdmin("poladmin-1")

	ctrlCaller, err := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))
	if err != nil {
		t.Fatalf("ResolveCaller ctrl: %v", err)
	}
	humanACaller, err := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	if err != nil {
		t.Fatalf("ResolveCaller humanA: %v", err)
	}

	// 1. POST /v1/workspaces (201) + 403 unauthorized include_history
	createWSBody := map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
		"source_options": map[string]any{
			"include_git_metadata": true,
			"include_history":      false,
		},
	}
	rec := env.do(http.MethodPost, "/v1/workspaces", humanA, "ws-create-1", createWSBody, nil, val)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/workspaces expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var createWSResp api.CreateWorkspaceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &createWSResp); err != nil {
		t.Fatalf("unmarshal createWSResp: %v", err)
	}

	// Forbidden include_history: true validated against OpenAPI ErrorResponse
	forbidWSBody := map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
		"source_options": map[string]any{
			"include_git_metadata": true,
			"include_history":      true,
		},
	}
	rec = env.do(http.MethodPost, "/v1/workspaces", humanA, "ws-create-history-denied", forbidWSBody, nil, val)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /v1/workspaces include_history expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. GET /v1/workspaces/{id} (200) + 404
	rec = env.do(http.MethodGet, "/v1/workspaces/"+createWSResp.WorkspaceID, humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/workspaces/{id} expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = env.do(http.MethodGet, "/v1/workspaces/"+domain.MustNewID().String(), humanA, "", nil, nil, val)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /v1/workspaces/missing expected 404, got %d", rec.Code)
	}

	// 13. GET /v1/operations/{id} (200)
	rec = env.do(http.MethodGet, "/v1/operations/"+createWSResp.OperationID, humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/operations/{id} expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. GET /v1/workspaces/{id}/source -> 409 before READY, 200 after READY
	rec = env.do(http.MethodGet, "/v1/workspaces/"+createWSResp.WorkspaceID+"/source", ctrlToken, "", nil, nil, val)
	if rec.Code != http.StatusConflict {
		t.Fatalf("GET /v1/workspaces/{id}/source before READY expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	wsID, propSeedID, snapID, snapSHA := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	rec = env.do(http.MethodGet, "/v1/workspaces/"+wsID.String()+"/source", ctrlToken, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/workspaces/{id}/source expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = env.do(http.MethodGet, "/v1/workspaces/"+wsID.String()+"/source", humanA, "", nil, nil, val)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /v1/workspaces/{id}/source human expected 403, got %d", rec.Code)
	}

	// 4. POST /v1/workspaces/{id}/proposals (201)
	ws2Res, err := env.workspaces.Create(ctx, workspaces.CreateInput{
		RepositoryID: env.repo.ID,
		OwnerID:      humanACaller.Principal.ID,
		BaseCommit:   strings.Repeat("a", 40),
		TargetRef:    "main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create ws2: %v", err)
	}
	if _, err := env.workspaces.TransitionStatus(ctx, ws2Res.Workspace.ID, domain.WorkspaceStatusPending, domain.WorkspaceStatusReady); err != nil {
		t.Fatalf("TransitionStatus ws2: %v", err)
	}
	_, _ = env.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = NOW(), updated_at = NOW() WHERE id = $1`, ws2Res.Operation.ID)
	submitBody := map[string]any{
		"title":       "Parity test proposal",
		"description": "Checks OpenAPI 3.1 contract",
		"snapshot": map[string]any{
			"artifact_id":          snapID.String(),
			"sha256":               snapSHA,
			"workspace_generation": 1,
			"size_bytes":           21,
			"captured_at":          time.Now().UTC().Format(time.RFC3339),
		},
		"provenance": map[string]any{
			"type":           "human_authored",
			"capture_method": "frozen_filesystem",
		},
	}
	rec = env.do(http.MethodPost, "/v1/workspaces/"+ws2Res.Workspace.ID.String()+"/proposals", ctrlToken, "prop-submit-1", submitBody, nil, val)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/workspaces/{id}/proposals expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var submitResp api.SubmitProposalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &submitResp); err != nil {
		t.Fatalf("unmarshal submitResp: %v", err)
	}

	// 5. GET /v1/proposals/{id} (200)
	rec = env.do(http.MethodGet, "/v1/proposals/"+submitResp.ProposalID, humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/proposals/{id} expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 6. GET /v1/proposals/{id}/diff -> 409 before reconstruction, 200 after reconstruction
	rec = env.do(http.MethodGet, "/v1/proposals/"+submitResp.ProposalID+"/diff", humanA, "", nil, nil, val)
	if rec.Code != http.StatusConflict {
		t.Fatalf("GET /v1/proposals/{id}/diff before reconstruction expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// 9. POST /v1/proposals/{id}/evaluate (202) after reconstruction completes
	evalPropUUID, err := uuid.Parse(submitResp.ProposalID)
	if err != nil {
		t.Fatalf("parse submitResp.ProposalID: %v", err)
	}
	_, _, evalProp := env.seedReconstructed(ctx, evalPropUUID, ctrlCaller.Principal.ID)
	rec = env.do(http.MethodPost, "/v1/proposals/"+submitResp.ProposalID+"/evaluate", ctrlToken, "eval-1", map[string]any{"expected_version": evalProp.Version}, nil, val)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/proposals/{id}/evaluate expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	// Use propSeedID to test reconstructed + evaluated + findings + assessments + approval + publish!
	manifestDigest, _ := env.seedReconstructedAndEvaluated(ctx, propSeedID, ctrlCaller.Principal.ID, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "REQUIRE_APPROVAL", ReviewerGroup: "security-reviewers", Minimum: 1},
	})

	// 6b. GET /v1/proposals/{id}/diff (200)
	rec = env.do(http.MethodGet, "/v1/proposals/"+propSeedID.String()+"/diff", humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/proposals/{id}/diff expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 7. GET /v1/proposals/{id}/findings (200)
	rec = env.do(http.MethodGet, "/v1/proposals/"+propSeedID.String()+"/findings?limit=10", humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/proposals/{id}/findings expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 8. GET /v1/proposals/{id}/assessments (200)
	rec = env.do(http.MethodGet, "/v1/proposals/"+propSeedID.String()+"/assessments", humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/proposals/{id}/assessments expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var assessResp api.ProposalAssessmentsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &assessResp); err != nil {
		t.Fatalf("unmarshal assessments: %v", err)
	}
	if len(assessResp.PolicyDecisions) == 0 {
		t.Fatal("expected at least 1 policy decision")
	}
	decisionID := assessResp.PolicyDecisions[0].ID

	// 11a. POST /v1/proposals/{id}/publish before approval -> 409 Conflict!
	rec = env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/publish", ctrlToken, "pub-unapproved-1", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil, val)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /v1/proposals/{id}/publish before approval expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal 409 error: %v", err)
	}
	if errResp.Error.Code != "INVALID_PROPOSAL_STATE" {
		t.Fatalf("expected INVALID_PROPOSAL_STATE for unapproved proposal, got %s", rec.Body.String())
	}

	// 11a-denied. POST /v1/proposals/{id}/publish on DENIED proposal -> 409 with policy_decision_id validated against OpenAPI!
	_, deniedPropID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	deniedManifest, deniedDecID := env.seedReconstructedAndEvaluated(ctx, deniedPropID, ctrlCaller.Principal.ID, domain.PolicyEffectDeny, nil)
	rec = env.do(http.MethodPost, "/v1/proposals/"+deniedPropID.String()+"/publish", ctrlToken, "pub-denied-1", map[string]any{
		"publication_manifest_digest": deniedManifest,
	}, nil, val)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /v1/proposals/{id}/publish on DENIED proposal expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var deniedErrResp api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &deniedErrResp); err != nil {
		t.Fatalf("unmarshal denied 409 error: %v", err)
	}
	if deniedErrResp.Error.PolicyDecisionID == nil || *deniedErrResp.Error.PolicyDecisionID != deniedDecID.String() {
		t.Fatalf("expected policy_decision_id=%s in publish 409 error envelope, got %s", deniedDecID, rec.Body.String())
	}

	// 10. POST /v1/proposals/{id}/approvals (201) by HumanB (security-reviewers)
	approveBody := map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        decisionID,
		"comment":                     "LGTM",
	}
	rec = env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/approvals", humanB, "approve-1", approveBody, nil, val)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /v1/proposals/{id}/approvals expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// 11b. POST /v1/proposals/{id}/publish after approval (202)
	rec = env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/publish", ctrlToken, "pub-ok-1", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil, val)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/proposals/{id}/publish expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var pubResp api.PublishProposalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pubResp); err != nil {
		t.Fatalf("unmarshal pubResp: %v", err)
	}

	// 12. GET /v1/publications/{id} (200)
	rec = env.do(http.MethodGet, "/v1/publications/"+pubResp.PublicationID, humanA, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/publications/{id} expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 14. GET /v1/audit/events (200)
	rec = env.do(http.MethodGet, "/v1/audit/events?limit=25", auditorToken, "", nil, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit/events expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 15. POST /v1/policies/validate (200 valid + 200 invalid)
	defaultYAML, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "default.yaml"))
	if err != nil {
		t.Fatalf("read default.yaml: %v", err)
	}
	rec = env.do(http.MethodPost, "/v1/policies/validate", policyAdminToken, "", map[string]any{
		"bundle_yaml": string(defaultYAML),
	}, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/policies/validate expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 16. POST /v1/policies/evaluate (200)
	rec = env.do(http.MethodPost, "/v1/policies/evaluate", policyAdminToken, "", map[string]any{
		"bundle_yaml": string(defaultYAML),
		"stage":       "EGRESS",
		"input": map[string]any{
			"repository": map[string]any{
				"full_name":      "acme/custodian-demo",
				"classification": "INTERNAL",
			},
			"proposal": map[string]any{
				"target_ref": "main",
			},
			"findings": map[string]any{
				"mandatory_scanners_complete": true,
				"scan_complete":               true,
			},
		},
	}, nil, val)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/policies/evaluate expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Negative OpenAPI parity checks: explicit JSON null on non-nullable fields, empty captured_at,
	// and untrimmed OpenAPI maxLength overflows with leading/trailing whitespace
	// must be rejected by both libopenapi-validator and the API handlers with 400 Bad Request.
	negCases := []struct {
		name                   string
		path                   string
		token                  string
		idemKey                string
		body                   string
		expectOpenAPIReqReject bool
		wantErrCode            string
	}{
		{
			name:                   "CreateWorkspace agent:null",
			path:                   "/v1/workspaces",
			token:                  humanA,
			idemKey:                "neg-ws-agent-null",
			body:                   `{"repository":{"provider":"github","repository_id":1001,"ref":"main"},"agent":null}`,
			expectOpenAPIReqReject: true,
		},
		{
			name:                   "EvaluateProposal expected_version:null",
			path:                   "/v1/proposals/" + propSeedID.String() + "/evaluate",
			token:                  ctrlToken,
			idemKey:                "neg-eval-ver-null",
			body:                   `{"expected_version":null}`,
			expectOpenAPIReqReject: true,
		},
		{
			name:                   "SubmitProposal captured_at:empty",
			path:                   "/v1/workspaces/" + ws2Res.Workspace.ID.String() + "/proposals",
			token:                  ctrlToken,
			idemKey:                "neg-prop-empty-captured",
			body:                   `{"title":"Bad ts","snapshot":{"artifact_id":"` + snapID.String() + `","sha256":"` + snapSHA + `","workspace_generation":1,"captured_at":""}}`,
			expectOpenAPIReqReject: false,
		},
		{
			name:                   "SubmitProposal title 257 with leading spaces",
			path:                   "/v1/workspaces/" + ws2Res.Workspace.ID.String() + "/proposals",
			token:                  ctrlToken,
			idemKey:                "neg-prop-title-257-spaces",
			body:                   `{"title":"  ` + strings.Repeat("a", 255) + `","snapshot":{"artifact_id":"` + snapID.String() + `","sha256":"` + snapSHA + `","workspace_generation":1}}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "INVALID_TITLE",
		},
		{
			name:                   "SubmitProposal description 8193 with leading spaces",
			path:                   "/v1/workspaces/" + ws2Res.Workspace.ID.String() + "/proposals",
			token:                  ctrlToken,
			idemKey:                "neg-prop-desc-8193-spaces",
			body:                   `{"title":"Valid","description":"  ` + strings.Repeat("a", 8191) + `","snapshot":{"artifact_id":"` + snapID.String() + `","sha256":"` + snapSHA + `","workspace_generation":1}}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "INVALID_DESCRIPTION",
		},
		{
			name:                   "CreateWorkspace ref 257 with leading spaces",
			path:                   "/v1/workspaces",
			token:                  humanA,
			idemKey:                "neg-ws-ref-257-spaces",
			body:                   `{"repository":{"provider":"github","repository_id":1001,"ref":"  ` + strings.Repeat("a", 255) + `"}}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "INVALID_REF",
		},
		{
			name:                   "CreateWorkspace agent.type 129 with spaces",
			path:                   "/v1/workspaces",
			token:                  humanA,
			idemKey:                "neg-ws-agent-type-129-spaces",
			body:                   `{"repository":{"provider":"github","repository_id":1001,"ref":"main"},"agent":{"type":"  ` + strings.Repeat("a", 127) + `","session_id":"s1","model_route":"openai/gpt-5"}}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "INVALID_AGENT",
		},
		{
			name:                   "CreateWorkspace agent.session_id 257 with spaces",
			path:                   "/v1/workspaces",
			token:                  humanA,
			idemKey:                "neg-ws-agent-sid-257-spaces",
			body:                   `{"repository":{"provider":"github","repository_id":1001,"ref":"main"},"agent":{"type":"codex","session_id":"  ` + strings.Repeat("a", 255) + `","model_route":"openai/gpt-5"}}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "INVALID_AGENT",
		},
		{
			name:                   "CreateWorkspace agent.model_route 129 with spaces",
			path:                   "/v1/workspaces",
			token:                  humanA,
			idemKey:                "neg-ws-agent-route-129-spaces",
			body:                   `{"repository":{"provider":"github","repository_id":1001,"ref":"main"},"agent":{"type":"codex","session_id":"s1","model_route":"  ` + strings.Repeat("a", 127) + `"}}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "INVALID_AGENT",
		},
		{
			name:                   "CreateApproval comment 4097 with spaces",
			path:                   "/v1/proposals/" + propSeedID.String() + "/approvals",
			token:                  humanB,
			idemKey:                "neg-app-comment-4097-spaces",
			body:                   `{"decision":"APPROVE","publication_manifest_digest":"` + manifestDigest + `","policy_evaluation_id":"` + decisionID + `","comment":"  ` + strings.Repeat("a", 4095) + `"}`,
			expectOpenAPIReqReject: true,
			wantErrCode:            "COMMENT_TOO_LONG",
		},
	}
	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			httpReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080"+tc.path, bytes.NewReader([]byte(tc.body)))
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("Authorization", "Bearer "+tc.token)
			httpReq.Header.Set("Idempotency-Key", tc.idemKey)
			if tc.expectOpenAPIReqReject {
				if valid, _ := val.ValidateHttpRequestSync(httpReq); valid {
					t.Fatalf("expected OpenAPI validator to reject %s", tc.name)
				}
			}

			rec := env.do(http.MethodPost, tc.path, tc.token, tc.idemKey, tc.body, nil, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 BadRequest for %s, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
			if tc.wantErrCode != "" {
				var errEnv api.ErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &errEnv); err != nil {
					t.Fatalf("unmarshal error response for %s: %v", tc.name, err)
				}
				if errEnv.Error.Code != tc.wantErrCode {
					t.Fatalf("expected error code %q for %s, got %q (%s)", tc.wantErrCode, tc.name, errEnv.Error.Code, rec.Body.String())
				}
			}
			resp := rec.Result()
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(bytes.NewReader(respBody))
			httpReq.Body = io.NopCloser(bytes.NewReader([]byte(tc.body)))
			if valid, errs := val.ValidateHttpResponse(httpReq, resp); !valid {
				t.Fatalf("400 ErrorResponse failed OpenAPI validation for %s: %+v", tc.name, errs)
			}
		})
	}
}
