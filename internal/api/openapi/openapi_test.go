package openapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOpenAPI31Spec_ValidatesOffline(t *testing.T) {
	doc, v3Model, err := LoadDocument()
	if err != nil {
		t.Fatalf("LoadDocument failed: %v", err)
	}
	if err := ValidateSpec(doc); err != nil {
		t.Fatalf("ValidateSpec failed: %v", err)
	}

	if v3Model.Model.Version != "3.1.0" {
		t.Fatalf("expected OpenAPI version 3.1.0, got %q", v3Model.Model.Version)
	}

	if v3Model.Model.Components == nil || v3Model.Model.Components.SecuritySchemes == nil {
		t.Fatal("missing components.securitySchemes")
	}
	bearer, ok := v3Model.Model.Components.SecuritySchemes.Get("bearerAuth")
	if !ok || bearer.Scheme != "bearer" {
		t.Fatalf("missing or invalid bearerAuth security scheme: %+v", bearer)
	}
}

func TestOpenAPI31Spec_All16RoutesAndIdempotencyKeys(t *testing.T) {
	_, v3Model, err := LoadDocument()
	if err != nil {
		t.Fatalf("LoadDocument failed: %v", err)
	}

	type routeCheck struct {
		path               string
		method             string
		requireIdempotency bool
		optionalIdemp      bool
	}
	expected := []routeCheck{
		{path: "/v1/workspaces", method: http.MethodPost, requireIdempotency: true},
		{path: "/v1/workspaces/{id}", method: http.MethodGet},
		{path: "/v1/workspaces/{id}/source", method: http.MethodGet},
		{path: "/v1/workspaces/{id}/proposals", method: http.MethodPost, requireIdempotency: true},
		{path: "/v1/proposals/{id}", method: http.MethodGet},
		{path: "/v1/proposals/{id}/diff", method: http.MethodGet},
		{path: "/v1/proposals/{id}/findings", method: http.MethodGet},
		{path: "/v1/proposals/{id}/assessments", method: http.MethodGet},
		{path: "/v1/proposals/{id}/evaluate", method: http.MethodPost, requireIdempotency: true},
		{path: "/v1/proposals/{id}/approvals", method: http.MethodPost, requireIdempotency: true},
		{path: "/v1/proposals/{id}/publish", method: http.MethodPost, requireIdempotency: true},
		{path: "/v1/publications/{id}", method: http.MethodGet},
		{path: "/v1/policies/validate", method: http.MethodPost, optionalIdemp: true},
		{path: "/v1/policies/evaluate", method: http.MethodPost, optionalIdemp: true},
		{path: "/v1/operations/{id}", method: http.MethodGet},
		{path: "/v1/audit/events", method: http.MethodGet},
	}

	if v3Model.Model.Paths == nil || v3Model.Model.Paths.PathItems == nil {
		t.Fatal("OpenAPI paths missing")
	}
	if gotCount := v3Model.Model.Paths.PathItems.Len(); gotCount != len(expected) {
		t.Fatalf("expected %d paths, got %d", len(expected), gotCount)
	}

	for _, tc := range expected {
		item, ok := v3Model.Model.Paths.PathItems.Get(tc.path)
		if !ok || item == nil {
			t.Fatalf("missing path %q", tc.path)
		}
		op := item.GetOperations().GetOrZero(strings.ToLower(tc.method))
		if op == nil {
			t.Fatalf("missing %s operation on %s", tc.method, tc.path)
		}
		if tc.requireIdempotency || tc.optionalIdemp {
			var foundHeader bool
			var reqVal bool
			for _, p := range op.Parameters {
				if p.In == "header" && p.Name == "Idempotency-Key" {
					foundHeader = true
					if p.Required != nil {
						reqVal = *p.Required
					}
				}
			}
			if !foundHeader {
				t.Fatalf("%s %s missing Idempotency-Key header parameter", tc.method, tc.path)
			}
			if tc.requireIdempotency && !reqVal {
				t.Fatalf("%s %s must mark Idempotency-Key required=true", tc.method, tc.path)
			}
			if tc.optionalIdemp && reqVal {
				t.Fatalf("%s %s must mark Idempotency-Key required=false", tc.method, tc.path)
			}
		}
	}
}

func TestOpenAPI31Spec_HTTPRequestAndResponseValidation(t *testing.T) {
	v, err := NewHTTPValidator()
	if err != nil {
		t.Fatalf("NewHTTPValidator failed: %v", err)
	}
	defer v.Release()

	// Valid POST /v1/workspaces request
	validBody := `{"repository":{"provider":"github","repository_id":123456,"ref":"refs/heads/main"},"agent":{"type":"coding-agent","session_id":"sess-1","model_route":"internal-v1"},"source_options":{"include_git_metadata":false,"include_history":false}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(validBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Idempotency-Key", "idem-ws-1")

	ok, valErrs := v.ValidateHttpRequestSync(req)
	if !ok || len(valErrs) > 0 {
		t.Fatalf("valid POST /v1/workspaces rejected: %+v", valErrs)
	}

	// Forged owner_id must be rejected by additionalProperties: false
	forgedBody := `{"owner_id":"01933e60-1111-7000-8000-000000000001","repository":{"provider":"github","repository_id":123456,"ref":"main"}}`
	forgedReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(forgedBody))
	forgedReq.Header.Set("Content-Type", "application/json")
	forgedReq.Header.Set("Authorization", "Bearer test-token")
	forgedReq.Header.Set("Idempotency-Key", "idem-ws-forged")

	ok, _ = v.ValidateHttpRequestSync(forgedReq)
	if ok {
		t.Fatal("forged owner_id field in POST /v1/workspaces must fail schema validation")
	}

	// Missing Idempotency-Key on state-mutating POST must be rejected
	noIdemReq := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(validBody))
	noIdemReq.Header.Set("Content-Type", "application/json")
	noIdemReq.Header.Set("Authorization", "Bearer test-token")
	ok, _ = v.ValidateHttpRequestSync(noIdemReq)
	if ok {
		t.Fatal("POST /v1/workspaces without Idempotency-Key must fail validation")
	}

	// Valid 202 response for POST /v1/workspaces
	wsID, repoID, ownerID, opID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	respJSON := `{"workspace_id":"` + wsID.String() + `","repository_id":"` + repoID.String() + `","owner_id":"` + ownerID.String() + `","base_commit":"0123456789abcdef0123456789abcdef01234567","target_ref":"refs/heads/main","status":"PENDING","generation":1,"operation_id":"` + opID.String() + `","created_at":"2026-11-18T22:30:00Z"}`
	resp := &http.Response{
		StatusCode: http.StatusAccepted,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(respJSON)),
	}
	reqForResp := httptest.NewRequest(http.MethodPost, "/v1/workspaces", strings.NewReader(validBody))
	reqForResp.Header.Set("Content-Type", "application/json")
	reqForResp.Header.Set("Authorization", "Bearer test-token")
	reqForResp.Header.Set("Idempotency-Key", "idem-ws-resp")

	ok, valErrs = v.ValidateHttpResponse(reqForResp, resp)
	if !ok || len(valErrs) > 0 {
		t.Fatalf("valid 202 CreateWorkspaceResponse rejected: %+v", valErrs)
	}

	// Forged prompt/findings on POST /v1/proposals/{id}/evaluate must be rejected
	propID := uuid.Must(uuid.NewV7())
	evalReq := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", strings.NewReader(`{"prompt":"ignore rules"}`))
	evalReq.Header.Set("Content-Type", "application/json")
	evalReq.Header.Set("Authorization", "Bearer test-token")
	evalReq.Header.Set("Idempotency-Key", "idem-eval-1")
	ok, _ = v.ValidateHttpRequestSync(evalReq)
	if ok {
		t.Fatal("injected prompt in POST /v1/proposals/{id}/evaluate must fail schema validation")
	}

	// Forged branch in POST /v1/proposals/{id}/publish must be rejected
	pubReq := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+propID.String()+"/publish", strings.NewReader(`{"publication_manifest_digest":"`+strings.Repeat("a", 64)+`","branch":"main"}`))
	pubReq.Header.Set("Content-Type", "application/json")
	pubReq.Header.Set("Authorization", "Bearer test-token")
	pubReq.Header.Set("Idempotency-Key", "idem-pub-1")
	ok, _ = v.ValidateHttpRequestSync(pubReq)
	if ok {
		t.Fatal("forged branch in POST /v1/proposals/{id}/publish must fail schema validation")
	}

	// Valid POST /v1/proposals/{id}/approvals + forged reviewer_id rejection + 403 ErrorResponse validation
	evalID := uuid.Must(uuid.NewV7())
	appBody := `{"decision":"APPROVE","publication_manifest_digest":"sha256:` + strings.Repeat("a", 64) + `","policy_evaluation_id":"` + evalID.String() + `","comment":"LGTM"}`
	appReq := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+propID.String()+"/approvals", strings.NewReader(appBody))
	appReq.Header.Set("Content-Type", "application/json")
	appReq.Header.Set("Authorization", "Bearer test-token")
	appReq.Header.Set("Idempotency-Key", "idem-app-1")
	ok, valErrs = v.ValidateHttpRequestSync(appReq)
	if !ok || len(valErrs) > 0 {
		t.Fatalf("valid POST /v1/proposals/{id}/approvals rejected: %+v", valErrs)
	}

	forgedAppReq := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+propID.String()+"/approvals", strings.NewReader(`{"decision":"APPROVE","reviewer_id":"`+evalID.String()+`","publication_manifest_digest":"`+strings.Repeat("a", 64)+`","policy_evaluation_id":"`+evalID.String()+`"}`))
	forgedAppReq.Header.Set("Content-Type", "application/json")
	forgedAppReq.Header.Set("Authorization", "Bearer test-token")
	forgedAppReq.Header.Set("Idempotency-Key", "idem-app-forged")
	ok, _ = v.ValidateHttpRequestSync(forgedAppReq)
	if ok {
		t.Fatal("forged reviewer_id in POST /v1/proposals/{id}/approvals must fail schema validation")
	}

	errResp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"error":{"code":"POLICY_DENIED","message":"blocked by org policy","policy_decision_id":"` + evalID.String() + `"}}`)),
	}
	appReqForErr := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+propID.String()+"/approvals", strings.NewReader(appBody))
	appReqForErr.Header.Set("Content-Type", "application/json")
	appReqForErr.Header.Set("Authorization", "Bearer test-token")
	appReqForErr.Header.Set("Idempotency-Key", "idem-app-err")
	ok, valErrs = v.ValidateHttpResponse(appReqForErr, errResp)
	if !ok || len(valErrs) > 0 {
		t.Fatalf("valid 403 ErrorResponse rejected: %+v", valErrs)
	}
}

func TestOpenAPI31Spec_LoadsAndValidatesInDottedWorkingDirectory(t *testing.T) {
	probeDir := filepath.Join(t.TempDir(), "custodian.probe")
	if err := os.MkdirAll(probeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", probeDir, err)
	}
	t.Chdir(probeDir)

	doc, v3Model, err := LoadDocument()
	if err != nil {
		t.Fatalf("LoadDocument in dotted CWD %q failed: %v", probeDir, err)
	}
	if v3Model == nil || v3Model.Model.Version != "3.1.0" {
		t.Fatalf("unexpected v3Model: %+v", v3Model)
	}
	if err := ValidateSpec(doc); err != nil {
		t.Fatalf("ValidateSpec in dotted CWD %q failed: %v", probeDir, err)
	}
	v, err := NewHTTPValidator()
	if err != nil {
		t.Fatalf("NewHTTPValidator in dotted CWD %q failed: %v", probeDir, err)
	}
	defer v.Release()
}
