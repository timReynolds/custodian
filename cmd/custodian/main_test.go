package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type capturedReq struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Idem   string
	Body   map[string]any
}

func TestCustodianCLIHelpAndEndpoints(t *testing.T) {
	ctx := context.Background()

	// --help exits 0.
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"--help"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("custodian --help expected 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "CUSTODIAN_API_URL") {
		t.Fatalf("expected CUSTODIAN_API_URL in usage, got: %s", stdout.String())
	}

	var got []capturedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var bodyMap map[string]any
		if len(bytes.TrimSpace(raw)) > 0 {
			_ = json.Unmarshal(raw, &bodyMap)
		}
		got = append(got, capturedReq{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Auth:   r.Header.Get("Authorization"),
			Idem:   r.Header.Get("Idempotency-Key"),
			Body:   bodyMap,
		})
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/readyz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ready"}`))
		case "/v1/workspaces":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"workspace_id":"ws-1","status":"PENDING"}`))
		case "/v1/audit/events":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"events":[],"has_more":false}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	env := func(k string) string {
		switch k {
		case "CUSTODIAN_API_URL":
			return srv.URL
		case "CUSTODIAN_TOKEN":
			return "test-oidc-jwt"
		default:
			return ""
		}
	}

	// health & ready
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"health"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("health expected 0, got %d: %s", code, stderr.String())
	}
	if code := run(ctx, []string{"ready"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("ready expected 0, got %d: %s", code, stderr.String())
	}

	// workspaces create honors CUSTODIAN_API_URL, Authorization, and auto/explicit Idempotency-Key
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"workspaces", "create", "--repo-id", "42", "--ref", "main", "--idempotency-key", "cli-idem-1"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("workspaces create expected 0, got %d: %s", code, stderr.String())
	}

	// proposals approve
	if code := run(ctx, []string{"proposals", "approve", "01950000-0000-7000-8000-000000000001", "--manifest-digest", strings.Repeat("a", 64), "--policy-evaluation-id", "01950000-0000-7000-8000-000000000002", "--idempotency-key", "cli-app-1"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("proposals approve expected 0, got %d: %s", code, stderr.String())
	}

	// audit list
	if code := run(ctx, []string{"audit", "list", "--event-type", "WORKSPACE_CREATED", "--limit", "10"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("audit list expected 0, got %d: %s", code, stderr.String())
	}

	if len(got) != 5 {
		t.Fatalf("expected 5 API requests, got %d", len(got))
	}
	if got[2].Method != http.MethodPost || got[2].Path != "/v1/workspaces" || got[2].Auth != "Bearer test-oidc-jwt" || got[2].Idem != "cli-idem-1" {
		t.Fatalf("unexpected workspaces create request: %+v", got[2])
	}
	if got[3].Method != http.MethodPost || !strings.HasSuffix(got[3].Path, "/approvals") {
		t.Fatalf("unexpected proposals approve request: %+v", got[3])
	}
	if got[4].Method != http.MethodGet || got[4].Path != "/v1/audit/events" || !strings.Contains(got[4].Query, "event_type=WORKSPACE_CREATED") {
		t.Fatalf("unexpected audit list request: %+v", got[4])
	}
}

func TestCustodianCLI_HelpAllSubcommandsAndPartialAgentValidation(t *testing.T) {
	ctx := context.Background()
	httpCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := func(k string) string {
		if k == "CUSTODIAN_API_URL" {
			return srv.URL
		}
		return ""
	}

	helpCases := [][]string{
		{"workspaces", "get", "--help"},
		{"workspaces", "get", "id1", "--help"},
		{"workspaces", "get", "id1", "-h"},
		{"workspaces", "get", "id1", "help"},
		{"workspaces", "source", "--help"},
		{"workspaces", "source", "id1", "--help"},
		{"workspaces", "source", "id1", "-h"},
		{"proposals", "get", "--help"},
		{"proposals", "get", "id1", "--help"},
		{"proposals", "get", "id1", "-h"},
		{"proposals", "diff", "--help"},
		{"proposals", "diff", "id1", "--help"},
		{"proposals", "diff", "id1", "-h"},
		{"proposals", "assessments", "--help"},
		{"proposals", "assessments", "id1", "--help"},
		{"proposals", "assessments", "id1", "help"},
		{"proposals", "findings", "id1", "--help"},
		{"proposals", "findings", "--help"},
		{"proposals", "evaluate", "id1", "--help"},
		{"proposals", "evaluate", "--help"},
		{"proposals", "approve", "id1", "--help"},
		{"proposals", "approve", "--help"},
		{"proposals", "publish", "id1", "--help"},
		{"proposals", "publish", "--help"},
		{"proposals", "submit", "ws1", "--help"},
		{"proposals", "submit", "--help"},
		{"policies", "validate", "--help"},
		{"policies", "evaluate", "--help"},
		{"publications", "get", "--help"},
		{"publications", "get", "id1", "--help"},
		{"publications", "get", "id1", "-h"},
		{"operations", "get", "--help"},
		{"operations", "get", "id1", "--help"},
		{"operations", "get", "id1", "help"},
	}

	for _, args := range helpCases {
		var stdout, stderr bytes.Buffer
		rc := run(ctx, args, env, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("args %v: expected exit 0, got %d (stderr=%q)", args, rc, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("args %v: expected Usage in stdout, got %q", args, stdout.String())
		}
	}
	if httpCalls != 0 {
		t.Fatalf("expected 0 HTTP calls during --help invocations, got %d", httpCalls)
	}

	var stdout, stderr bytes.Buffer
	rc := run(ctx, []string{"workspaces", "create", "--repo-id", "1", "--ref", "main", "--agent-type", "claude"}, env, &stdout, &stderr)
	if rc != 2 {
		t.Fatalf("partial --agent-type expected exit 2, got %d (stderr=%q)", rc, stderr.String())
	}
	if httpCalls != 0 {
		t.Fatalf("expected 0 HTTP calls on client-side partial agent rejection, got %d", httpCalls)
	}
}
