package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("CUSTODIAN_TEST_MAIN_CLI") == "1" {
		os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

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

func TestCustodianCLI_CredentialHelper(t *testing.T) {
	ctx := context.Background()

	const validToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sigvalue123"
	const badToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiYWQifQ.tamperedsig"

	var verifyCalls int
	var lastAuth string
	var lastPathQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyCalls++
		lastAuth = r.Header.Get("Authorization")
		lastPathQuery = r.URL.RequestURI()
		if lastAuth != "Bearer "+validToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"invalid token ` + badToken + `"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pushes":[],"has_more":false}`))
	}))
	defer srv.Close()

	baseEnv := func(k string) string {
		switch k {
		case "CUSTODIAN_API_URL":
			return srv.URL
		case "CUSTODIAN_TOKEN":
			return validToken
		default:
			return ""
		}
	}

	t.Run("help exits 0 with 0 HTTP calls", func(t *testing.T) {
		before := verifyCalls
		for _, args := range [][]string{
			{"credential-helper", "--help"},
			{"credential-helper", "-h"},
			{"credential-helper", "help"},
		} {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, args, baseEnv, strings.NewReader(""), &stdout, &stderr)
			if rc != 0 || !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("args %v: expected exit 0 and Usage, got rc=%d stdout=%q stderr=%q", args, rc, stdout.String(), stderr.String())
			}
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls on help, got %d", verifyCalls-before)
		}
	})

	t.Run("bogus flag and bogus op exit 2 with empty stdout", func(t *testing.T) {
		before := verifyCalls
		for _, args := range [][]string{
			{"credential-helper", "--bogus-flag"},
			{"credential-helper"},
			{"credential-helper", "bogus-op"},
			{"credential-helper", "get", "extra"},
		} {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, args, baseEnv, strings.NewReader("protocol=https\nhost=127.0.0.1\n\n"), &stdout, &stderr)
			if rc != 2 || stdout.Len() != 0 {
				t.Fatalf("args %v: expected exit 2 and empty stdout, got rc=%d stdout=%q stderr=%q", args, rc, stdout.String(), stderr.String())
			}
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls on flag/op errors, got %d", verifyCalls-before)
		}
	})

	t.Run("store and erase exit 0 with empty stdout and 0 HTTP calls", func(t *testing.T) {
		before := verifyCalls
		for _, op := range []string{"store", "erase"} {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, []string{"credential-helper", op}, baseEnv, strings.NewReader("protocol=https\nhost=127.0.0.1\nusername=x\npassword=y\n\n"), &stdout, &stderr)
			if rc != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("%s: expected exit 0 empty io, got rc=%d stdout=%q stderr=%q", op, rc, stdout.String(), stderr.String())
			}
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls on store/erase, got %d", verifyCalls-before)
		}
	})

	t.Run("get happy path via CUSTODIAN_TOKEN and --token-file", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		stdin := strings.NewReader("protocol=https\nhost=127.0.0.1\npath=acme/service.git\n\n")
		rc := runWithIO(ctx, []string{"credential-helper", "get"}, baseEnv, stdin, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("get expected 0, got %d (stderr=%q)", rc, stderr.String())
		}
		if lastPathQuery != "/v1/pushes?limit=1" || lastAuth != "Bearer "+validToken {
			t.Fatalf("unexpected verification request: uri=%q auth=%q", lastPathQuery, lastAuth)
		}
		wantOut := "protocol=https\nhost=127.0.0.1\nusername=x-access-token\npassword=" + validToken + "\n"
		if stdout.String() != wantOut {
			t.Fatalf("unexpected stdout:\ngot:  %q\nwant: %q", stdout.String(), wantOut)
		}
		if strings.Contains(stderr.String(), validToken) {
			t.Fatalf("stderr leaked token: %q", stderr.String())
		}

		// Via --token-file with empty CUSTODIAN_TOKEN
		tokFile := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(tokFile, []byte("  "+validToken+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		envNoTok := func(k string) string {
			if k == "CUSTODIAN_API_URL" {
				return srv.URL
			}
			return ""
		}
		stdout.Reset()
		stderr.Reset()
		rc = runWithIO(ctx, []string{"credential-helper", "--token-file", tokFile, "get"}, envNoTok, strings.NewReader("protocol=http\nhost=127.0.0.1:8080\n\n"), &stdout, &stderr)
		if rc != 0 || !strings.Contains(stdout.String(), "password="+validToken) {
			t.Fatalf("get via --token-file failed: rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
		}
	})

	t.Run("missing CUSTODIAN_API_URL fails closed with empty stdout", func(t *testing.T) {
		before := verifyCalls
		envNoURL := func(k string) string {
			if k == "CUSTODIAN_TOKEN" {
				return validToken
			}
			return ""
		}
		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"credential-helper", "get"}, envNoURL, strings.NewReader("protocol=https\nhost=127.0.0.1\n\n"), &stdout, &stderr)
		if rc != 1 || stdout.Len() != 0 {
			t.Fatalf("expected exit 1 and empty stdout when CUSTODIAN_API_URL empty, got rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls when API URL missing, got %d", verifyCalls-before)
		}
	})

	t.Run("rejected or invalid token fails closed and redacts token from stderr", func(t *testing.T) {
		envBadTok := func(k string) string {
			switch k {
			case "CUSTODIAN_API_URL":
				return srv.URL
			case "CUSTODIAN_TOKEN":
				return badToken
			default:
				return ""
			}
		}
		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"credential-helper", "get"}, envBadTok, strings.NewReader("protocol=https\nhost=127.0.0.1\n\n"), &stdout, &stderr)
		if rc != 1 || stdout.Len() != 0 {
			t.Fatalf("expected exit 1 and empty stdout, got rc=%d stdout=%q", rc, stdout.String())
		}
		if strings.Contains(stderr.String(), badToken) {
			t.Fatalf("stderr leaked rejected token: %q", stderr.String())
		}

		// Empty token, whitespace in token, missing token-file -> 0 HTTP calls
		before := verifyCalls
		for _, tok := range []string{"", "tok with space", "tok\nnewline"} {
			stdout.Reset()
			stderr.Reset()
			envT := func(k string) string {
				if k == "CUSTODIAN_API_URL" {
					return srv.URL
				}
				if k == "CUSTODIAN_TOKEN" {
					return tok
				}
				return ""
			}
			rc = runWithIO(ctx, []string{"credential-helper", "get"}, envT, strings.NewReader("protocol=https\nhost=127.0.0.1\n\n"), &stdout, &stderr)
			if rc != 1 || stdout.Len() != 0 {
				t.Fatalf("token %q: expected exit 1 empty stdout, got rc=%d stdout=%q", tok, rc, stdout.String())
			}
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls for malformed/empty tokens, got %d", verifyCalls-before)
		}
	})

	t.Run("malformed and injection stdin rejected cleanly", func(t *testing.T) {
		before := verifyCalls
		badInputs := []struct {
			name  string
			stdin string
		}{
			{"empty_stdin", ""},
			{"binary_nul", "protocol=https\x00host=127.0.0.1\n\n"},
			{"crlf_injection", "protocol=https\r\nhost=127.0.0.1\r\n\r\n"},
			{"missing_host", "protocol=https\n\n"},
			{"unsupported_protocol_ftp", "protocol=ftp\nhost=127.0.0.1\n\n"},
			{"non_loopback_http", "protocol=http\nhost=github.com\n\n"},
			{"host_with_at", "protocol=https\nhost=user@github.com\n\n"},
			{"host_with_slash", "protocol=https\nhost=github.com/acme\n\n"},
			{"missing_equals", "protocolhttps\nhost=127.0.0.1\n\n"},
		}
		for _, tc := range badInputs {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, []string{"credential-helper", "get"}, baseEnv, strings.NewReader(tc.stdin), &stdout, &stderr)
			if rc != 1 || stdout.Len() != 0 {
				t.Fatalf("%s: expected exit 1 and empty stdout, got rc=%d stdout=%q stderr=%q", tc.name, rc, stdout.String(), stderr.String())
			}
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls for malformed stdin, got %d", verifyCalls-before)
		}
	})

	t.Run("host allowlist filters mismatched host without emitting credentials", func(t *testing.T) {
		before := verifyCalls
		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"credential-helper", "--host", "git.internal.corp", "get"}, baseEnv, strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
		if rc != 0 || stdout.Len() != 0 {
			t.Fatalf("mismatched host expected exit 0 empty stdout, got rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
		}
		if verifyCalls != before {
			t.Fatalf("expected 0 HTTP calls when host filtered out, got %d", verifyCalls-before)
		}
	})
}

func TestCustodianCLI_PushStatus(t *testing.T) {
	ctx := context.Background()
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"
	const pushID = "01950000-0000-7000-8000-000000000101"
	const missingID = "01950000-0000-7000-8000-000000000999"

	var lastURI string
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		lastURI = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/pushes/" + pushID:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"` + pushID + `","status":"APPROVAL_REQUIRED","policy_effect":"REQUIRE_APPROVAL","egress_mode":"ENFORCE_BLOCK","enforced":true,"destination":"github.com/acme/repo","push_manifest_digest":"` + strings.Repeat("a", 64) + `","upstream_forwarded":false,"upstream_bytes_sent":0}`))
		case "/v1/pushes/" + missingID:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"push session not found"}}`))
		case "/v1/pushes/bad-id":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":"INVALID_ID","message":"id must be a valid UUIDv7"}}`))
		case "/v1/pushes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"pushes":[{"id":"` + pushID + `","status":"COMPLETED","policy_effect":"ALLOW","egress_mode":"ENFORCE_BLOCK","enforced":true,"destination":"github.com/acme/repo","push_manifest_digest":"` + strings.Repeat("a", 64) + `","upstream_forwarded":true,"upstream_bytes_sent":128}],"has_more":false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	env := func(k string) string {
		switch k {
		case "CUSTODIAN_API_URL":
			return srv.URL
		case "CUSTODIAN_TOKEN":
			return tok
		default:
			return ""
		}
	}

	t.Run("help exits 0 with 0 HTTP calls", func(t *testing.T) {
		before := callCount
		for _, args := range [][]string{
			{"push", "--help"},
			{"push", "status", "--help"},
			{"push", "status", "-h"},
			{"push", "status", "help"},
		} {
			var stdout, stderr bytes.Buffer
			if rc := runWithIO(ctx, args, env, nil, &stdout, &stderr); rc != 0 || !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("args %v: expected exit 0 and Usage, got rc=%d stdout=%q", args, rc, stdout.String())
			}
		}
		if callCount != before {
			t.Fatalf("expected 0 HTTP calls for help, got %d", callCount-before)
		}
	})

	t.Run("positional, --id, and --push-id single lookup in json and text formats", func(t *testing.T) {
		for _, args := range [][]string{
			{"push", "status", pushID},
			{"push", "status", "--id", pushID},
			{"push", "status", "--push-id", pushID},
		} {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, args, env, nil, &stdout, &stderr)
			if rc != 0 {
				t.Fatalf("args %v: expected exit 0, got %d (stderr=%q)", args, rc, stderr.String())
			}
			var parsed map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
				t.Fatalf("args %v: expected valid JSON stdout, got %v (%q)", args, err, stdout.String())
			}
			if parsed["id"] != pushID || parsed["status"] != "APPROVAL_REQUIRED" {
				t.Fatalf("unexpected JSON: %+v", parsed)
			}
		}

		// --format text renders status, verdict, digest, destination, and next steps
		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"push", "status", pushID, "--format", "text"}, env, nil, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("text format expected exit 0, got %d (stderr=%q)", rc, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{pushID, "APPROVAL_REQUIRED", "REQUIRE_APPROVAL", strings.Repeat("a", 64), "github.com/acme/repo", "POST /v1/pushes/"} {
			if !strings.Contains(out, want) {
				t.Fatalf("text output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("list mode with filters in json and text formats", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"push", "status", "--status", "COMPLETED", "--egress-mode", "ENFORCE_BLOCK", "--limit", "10", "--format", "text"}, env, nil, &stdout, &stderr)
		if rc != 0 {
			t.Fatalf("list mode expected exit 0, got %d (stderr=%q)", rc, stderr.String())
		}
		if !strings.Contains(lastURI, "status=COMPLETED") || !strings.Contains(lastURI, "egress_mode=ENFORCE_BLOCK") || !strings.Contains(lastURI, "limit=10") {
			t.Fatalf("unexpected list URI: %q", lastURI)
		}
		if !strings.Contains(stdout.String(), pushID) || !strings.Contains(stdout.String(), "COMPLETED") {
			t.Fatalf("unexpected list text output: %q", stdout.String())
		}
	})

	t.Run("400 and 404 exit 1 with server status on stderr", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if rc := runWithIO(ctx, []string{"push", "status", "bad-id"}, env, nil, &stdout, &stderr); rc != 1 || !strings.Contains(stderr.String(), "400") {
			t.Fatalf("bad-id expected exit 1 with 400 on stderr, got rc=%d stderr=%q", rc, stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		if rc := runWithIO(ctx, []string{"push", "status", missingID}, env, nil, &stdout, &stderr); rc != 1 || !strings.Contains(stderr.String(), "404") {
			t.Fatalf("missingID expected exit 1 with 404 on stderr, got rc=%d stderr=%q", rc, stderr.String())
		}
	})

	t.Run("client-side flag conflicts exit 2 with 0 HTTP calls", func(t *testing.T) {
		before := callCount
		for _, args := range [][]string{
			{"push", "status", "--format", "yaml"},
			{"push", "status", "--id", pushID, "--push-id", missingID},
			{"push", "status", pushID, "--id", missingID},
			{"push", "status", pushID, "--status", "COMPLETED"},
			{"push", "bogus"},
		} {
			var stdout, stderr bytes.Buffer
			if rc := runWithIO(ctx, args, env, nil, &stdout, &stderr); rc != 2 {
				t.Fatalf("args %v: expected exit 2, got %d (stderr=%q)", args, rc, stderr.String())
			}
		}
		if callCount != before {
			t.Fatalf("expected 0 HTTP calls on validation errors, got %d", callCount-before)
		}
	})
}

func TestCustodianCLI_RegressionIter1Findings(t *testing.T) {
	ctx := context.Background()
	const tokA = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0b2stYSJ9.sigA"
	const tokB = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0b2stYiJ9.sigB"
	const pushID = "01950000-0000-7000-8000-000000000777"

	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/pushes":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"pushes":[],"has_more":false}`))
		case "/v1/pushes/" + pushID:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"` + pushID + `","status":"OBSERVED_WOULD_BLOCK","verdict":"DENY","policy_effect":"DENY","egress_mode":"PASSIVE_AUDIT","enforced":false,"destination":"github.com/acme/repo","upstream_forwarded":true,"upstream_bytes_sent":512}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	env := func(k string) string {
		switch k {
		case "CUSTODIAN_API_URL":
			return srv.URL
		case "CUSTODIAN_TOKEN":
			return tokA
		default:
			return ""
		}
	}

	t.Run("renderPushStatusText prioritizes Status over Verdict for OBSERVED_WOULD_BLOCK and FAILED", func(t *testing.T) {
		for _, verdict := range []string{"DENY", "QUARANTINE", "REQUIRE_APPROVAL"} {
			var stdout, stderr bytes.Buffer
			payload := `{"id":"` + pushID + `","status":"OBSERVED_WOULD_BLOCK","verdict":"` + verdict + `","policy_effect":"` + verdict + `","egress_mode":"PASSIVE_AUDIT","enforced":false,"destination":"github.com/acme/repo","upstream_forwarded":true,"upstream_bytes_sent":512}`
			rc := renderPushStatusText([]byte(payload), &stdout, &stderr)
			if rc != 0 {
				t.Fatalf("renderPushStatusText(%s) rc=%d stderr=%q", verdict, rc, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, "PASSIVE_AUDIT observed policy violations") {
				t.Fatalf("OBSERVED_WOULD_BLOCK + %s missing PASSIVE_AUDIT guidance:\n%s", verdict, out)
			}
			if strings.Contains(out, "zero bytes were sent upstream") || strings.Contains(out, "POST /v1/pushes/") {
				t.Fatalf("OBSERVED_WOULD_BLOCK + %s emitted contradictory guidance:\n%s", verdict, out)
			}
		}

		var stdout, stderr bytes.Buffer
		failedPayload := `{"id":"` + pushID + `","status":"FAILED","policy_effect":"ALLOW","egress_mode":"ENFORCE_BLOCK","enforced":true,"destination":"github.com/acme/repo","upstream_forwarded":false,"upstream_bytes_sent":0,"error_code":"UPSTREAM_ERR"}`
		if rc := renderPushStatusText([]byte(failedPayload), &stdout, &stderr); rc != 0 {
			t.Fatalf("renderPushStatusText(FAILED) rc=%d", rc)
		}
		if strings.Contains(stdout.String(), "Push allowed and completed") {
			t.Fatalf("FAILED + ALLOW emitted completion message:\n%s", stdout.String())
		}
	})

	t.Run("parseGitCredentialInput rejects Unicode controls/spaces, invalid UTF-8, and URI delimiters in host", func(t *testing.T) {
		badInputs := []string{
			"protocol=https\nhost=github.com\xff\n\n",
			"protocol=https\nhost=github.com\u0085evil\n\n",
			"protocol=https\nhost=github.com\u2028evil\n\n",
			"protocol=https\nhost=github.com\u2029evil\n\n",
			"protocol=https\nhost=github.com\u00a0evil\n\n",
			"protocol=https\nhost=github.com\tevil\n\n",
			"protocol=https\nhost=github.com\npath=org/repo\u0085evil\n\n",
			"protocol=https\nhost=github.com?evil=1\n\n",
			"protocol=https\nhost=github.com#frag\n\n",
			"protocol=https\nhost=github.com=evil\n\n",
		}
		for _, in := range badInputs {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, []string{"credential-helper", "get"}, env, strings.NewReader(in), &stdout, &stderr)
			if rc != 1 || stdout.Len() != 0 {
				t.Fatalf("input %q expected exit 1 empty stdout, got rc=%d stdout=%q stderr=%q", in, rc, stdout.String(), stderr.String())
			}
		}
	})

	t.Run("hostInAllowlist normalizes IPv6 brackets", func(t *testing.T) {
		for _, tc := range []struct {
			host string
			flag string
			want bool
		}{
			{"[::1]", "::1", true},
			{"[::1]:8443", "[::1]", true},
			{"[::1]:8443", "::1", true},
			{"::1", "[::1]", true},
			{"[::1]:8443", "[::1]:8443", true},
			{"[::1]:9443", "[::1]:8443", false},
		} {
			if got := hostInAllowlist(tc.host, []string{tc.flag}); got != tc.want {
				t.Fatalf("hostInAllowlist(%q, [%q]) = %v, want %v", tc.host, tc.flag, got, tc.want)
			}
		}

		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"credential-helper", "--host", "::1", "get"}, env, strings.NewReader("protocol=http\nhost=[::1]\n\n"), &stdout, &stderr)
		if rc != 0 || !strings.Contains(stdout.String(), "host=[::1]\n") {
			t.Fatalf("IPv6 allowlist match failed: rc=%d stdout=%q stderr=%q", rc, stdout.String(), stderr.String())
		}
	})

	t.Run("explicit --token-file overrides CUSTODIAN_TOKEN while explicit --token wins", func(t *testing.T) {
		tokFile := filepath.Join(t.TempDir(), "tokb")
		if err := os.WriteFile(tokFile, []byte(tokB+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		rc := runWithIO(ctx, []string{"credential-helper", "--token-file", tokFile, "get"}, env, strings.NewReader("protocol=https\nhost=127.0.0.1\n\n"), &stdout, &stderr)
		if rc != 0 || !strings.Contains(stdout.String(), "password="+tokB+"\n") || lastAuth != "Bearer "+tokB {
			t.Fatalf("expected --token-file to override CUSTODIAN_TOKEN: rc=%d auth=%q stdout=%q stderr=%q", rc, lastAuth, stdout.String(), stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		rc = runWithIO(ctx, []string{"credential-helper", "--token-file", tokFile, "--token", tokA, "get"}, env, strings.NewReader("protocol=https\nhost=127.0.0.1\n\n"), &stdout, &stderr)
		if rc != 0 || !strings.Contains(stdout.String(), "password="+tokA+"\n") || lastAuth != "Bearer "+tokA {
			t.Fatalf("expected explicit --token to win over --token-file: rc=%d auth=%q stdout=%q stderr=%q", rc, lastAuth, stdout.String(), stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		rc = runWithIO(ctx, []string{"push", "status", "--token-file", tokFile, "--format", "text", pushID}, env, nil, &stdout, &stderr)
		if rc != 0 || lastAuth != "Bearer "+tokB {
			t.Fatalf("push status --token-file override (flags-before-id) failed: rc=%d auth=%q stderr=%q", rc, lastAuth, stderr.String())
		}

		lastAuth = ""
		stdout.Reset()
		stderr.Reset()
		rc = runWithIO(ctx, []string{"push", "status", pushID, "--token-file", tokFile, "--format", "text"}, env, nil, &stdout, &stderr)
		if rc != 0 || lastAuth != "Bearer "+tokB {
			t.Fatalf("push status --token-file override (id-before-flags) failed: rc=%d auth=%q stderr=%q", rc, lastAuth, stderr.String())
		}
	})
}

func TestCustodianCLI_RegressionIter3Findings(t *testing.T) {
	ctx := context.Background()
	const validToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLWl0ZXIzIn0.sigIter3"

	var verifyCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+validToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pushes":[],"has_more":false}`))
	}))
	defer srv.Close()

	env := func(k string) string {
		switch k {
		case "CUSTODIAN_API_URL":
			return srv.URL
		case "CUSTODIAN_TOKEN":
			return validToken
		default:
			return ""
		}
	}

	t.Run("accepts ASCII 0x20 space in wwwauth[], path, username, and url path", func(t *testing.T) {
		validInputs := []struct {
			name      string
			stdin     string
			wantProto string
			wantHost  string
		}{
			{
				name:      "git_2_54_smart_http_401_challenge",
				stdin:     "capability[]=authtype\ncapability[]=state\nprotocol=http\nhost=127.0.0.1:54306\npath=org/my-repo.git\nwwwauth[]=Basic realm=\"Custodian\"\n\n",
				wantProto: "http",
				wantHost:  "127.0.0.1:54306",
			},
			{
				name:      "multiple_wwwauth_lines_with_spaces_and_equals",
				stdin:     "protocol=https\nhost=github.com\nwwwauth[]=Bearer realm=\"https://auth.example.com/token\", scope=\"repo\"\nwwwauth[]=Basic realm=\"Custodian\"\n\n",
				wantProto: "https",
				wantHost:  "github.com",
			},
			{
				name:      "spaces_in_path_and_username",
				stdin:     "protocol=https\nhost=github.com\npath=org/my repo.git\nusername=Alice Developer\n\n",
				wantProto: "https",
				wantHost:  "github.com",
			},
			{
				name:      "spaces_in_url_path",
				stdin:     "url=https://github.com/org/my repo.git\n\n",
				wantProto: "https",
				wantHost:  "github.com",
			},
		}
		for _, tc := range validInputs {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, []string{"credential-helper", "get"}, env, strings.NewReader(tc.stdin), &stdout, &stderr)
			if rc != 0 {
				t.Fatalf("%s: expected exit 0, got rc=%d stdout=%q stderr=%q", tc.name, rc, stdout.String(), stderr.String())
			}
			wantOut := "protocol=" + tc.wantProto + "\nhost=" + tc.wantHost + "\nusername=x-access-token\npassword=" + validToken + "\n"
			if stdout.String() != wantOut {
				t.Fatalf("%s: unexpected stdout:\ngot:  %q\nwant: %q", tc.name, stdout.String(), wantOut)
			}
		}
	})

	t.Run("rejects spaces in host/protocol/url-host/keys, duplicates, and controls/non-ASCII spaces", func(t *testing.T) {
		before := verifyCalls.Load()
		badInputs := []struct {
			name  string
			stdin string
		}{
			{"host_internal_space", "protocol=https\nhost=github.com evil\n\n"},
			{"host_leading_space", "protocol=https\nhost= github.com\n\n"},
			{"host_trailing_space", "protocol=https\nhost=github.com \n\n"},
			{"host_spaces_only_with_url_fallback", "protocol=https\nhost=   \nurl=https://github.com/org/repo.git\n\n"},
			{"protocol_leading_space", "protocol= https\nhost=github.com\n\n"},
			{"protocol_trailing_space", "protocol=https \nhost=github.com\n\n"},
			{"protocol_internal_space", "protocol=ht tps\nhost=github.com\n\n"},
			{"protocol_spaces_only_with_url_fallback", "protocol=   \nurl=https://github.com/org/repo.git\n\n"},
			{"url_leading_space", "url= https://github.com/org/repo.git\n\n"},
			{"url_host_space", "url=https://evil host.com/org/repo.git\n\n"},
			{"url_trailing_space_on_host", "url=https://github.com \n\n"},
			{"key_leading_space", " host=github.com\nprotocol=https\n\n"},
			{"key_trailing_space", "protocol=https\nhost =github.com\n\n"},
			{"duplicate_host_smuggling", "protocol=https\nhost=evil.com?x=1\nhost=github.com\n\n"},
			{"duplicate_protocol_smuggling", "protocol=ftp\nprotocol=https\nhost=github.com\n\n"},
			{"duplicate_url_smuggling", "url=https://evil.com/a\nurl=https://github.com/b\n\n"},
			{"wwwauth_tab", "protocol=https\nhost=github.com\nwwwauth[]=Basic\trealm\n\n"},
			{"wwwauth_cr", "protocol=https\nhost=github.com\nwwwauth[]=Basic\rrealm\n\n"},
			{"wwwauth_nul", "protocol=https\nhost=github.com\nwwwauth[]=Basic\x00realm\n\n"},
			{"wwwauth_del", "protocol=https\nhost=github.com\nwwwauth[]=Basic\x7frealm\n\n"},
			{"wwwauth_nel", "protocol=https\nhost=github.com\nwwwauth[]=Basic\u0085realm\n\n"},
			{"wwwauth_ls", "protocol=https\nhost=github.com\nwwwauth[]=Basic\u2028realm\n\n"},
			{"wwwauth_ps", "protocol=https\nhost=github.com\nwwwauth[]=Basic\u2029realm\n\n"},
			{"wwwauth_nbsp", "protocol=https\nhost=github.com\nwwwauth[]=Basic\u00a0realm\n\n"},
			{"path_nbsp", "protocol=https\nhost=github.com\npath=org/my\u00a0repo.git\n\n"},
			{"host_nbsp", "protocol=https\nhost=github.com\u00a0evil\n\n"},
			{"host_query", "protocol=https\nhost=github.com?evil=1\n\n"},
			{"host_fragment", "protocol=https\nhost=github.com#frag\n\n"},
			{"host_equals", "protocol=https\nhost=github.com=evil\n\n"},
		}
		for _, tc := range badInputs {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, []string{"credential-helper", "get"}, env, strings.NewReader(tc.stdin), &stdout, &stderr)
			if rc != 1 || stdout.Len() != 0 {
				t.Fatalf("%s: expected exit 1 and empty stdout, got rc=%d stdout=%q stderr=%q", tc.name, rc, stdout.String(), stderr.String())
			}
		}
		if verifyCalls.Load() != before {
			t.Fatalf("expected 0 HTTP calls for rejected inputs, got %d", verifyCalls.Load()-before)
		}
	})

	t.Run("captive portal or non-PushListResponse 200 OK fails closed without leaking token", func(t *testing.T) {
		cases := []struct {
			name        string
			contentType string
			body        string
		}{
			{"html_captive_portal", "text/html; charset=utf-8", "<html><body>Sign in " + validToken + "</body></html>"},
			{"json_empty_object", "application/json", "{}"},
			{"json_missing_pushes", "application/json", `{"ok":true}`},
			{"json_null_pushes", "application/json", `{"pushes":null}`},
			{"empty_200_body", "application/json", ""},
		}
		for _, tc := range cases {
			portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			portalEnv := func(k string) string {
				switch k {
				case "CUSTODIAN_API_URL":
					return portalSrv.URL
				case "CUSTODIAN_TOKEN":
					return validToken
				default:
					return ""
				}
			}
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, []string{"credential-helper", "get"}, portalEnv, strings.NewReader("protocol=https\nhost=github.com\n\n"), &stdout, &stderr)
			portalSrv.Close()
			if rc != 1 || stdout.Len() != 0 {
				t.Fatalf("%s: expected exit 1 and empty stdout, got rc=%d stdout=%q stderr=%q", tc.name, rc, stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), validToken) {
				t.Fatalf("%s: stderr leaked token: %q", tc.name, stderr.String())
			}
		}
	})

	t.Run("push status rejects negative --limit with exit 2 and 0 HTTP calls", func(t *testing.T) {
		before := verifyCalls.Load()
		for _, args := range [][]string{
			{"push", "status", "--limit", "-1"},
			{"push", "status", "01950000-0000-7000-8000-000000000777", "--limit", "-5"},
		} {
			var stdout, stderr bytes.Buffer
			rc := runWithIO(ctx, args, env, nil, &stdout, &stderr)
			if rc != 2 || stdout.Len() != 0 {
				t.Fatalf("%v: expected exit 2 and empty stdout, got rc=%d stdout=%q stderr=%q", args, rc, stdout.String(), stderr.String())
			}
		}
		if verifyCalls.Load() != before {
			t.Fatalf("expected 0 HTTP calls on negative --limit, got %d", verifyCalls.Load()-before)
		}
	})
}

func TestCustodianCLI_RealGitCredentialChallenge(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("LookPath(git): %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	const validToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJnaXQtcmVhbCJ9.sigRealGit"
	const commitSHA = "0123456789abcdef0123456789abcdef01234567"

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/v1/pushes?limit=1" || r.Header.Get("Authorization") != "Bearer "+validToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pushes":[],"has_more":false}`))
	}))
	defer apiSrv.Close()

	var challenges atomic.Int32
	var authed atomic.Int32
	gitSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/org/my-repo.git/info/refs" && r.URL.Path != "/org/my repo.git/info/refs") ||
			r.URL.Query().Get("service") != "git-upload-pack" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "x-access-token" || pass != validToken {
			challenges.Add(1)
			w.Header().Set("WWW-Authenticate", `Basic realm="Custodian"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authed.Add(1)
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		w.WriteHeader(http.StatusOK)
		pkt := func(s string) string {
			return fmt.Sprintf("%04x%s", len(s)+4, s)
		}
		_, _ = io.WriteString(w, pkt("# service=git-upload-pack\n")+"0000"+pkt(commitSHA+" refs/heads/main\n")+"0000")
	}))
	defer gitSrv.Close()

	for _, repoPath := range []string{"/org/my-repo.git", "/org/my%20repo.git"} {
		challenges.Store(0)
		authed.Store(0)
		cmd := exec.Command(
			"git",
			"-c", "credential.helper=",
			"-c", "credential.useHttpPath=true",
			"-c", `credential.helper=!env CUSTODIAN_TEST_MAIN_CLI=1 "$CUSTODIAN_TEST_BIN" credential-helper --api-url "$CUSTODIAN_TEST_API"`,
			"ls-remote", gitSrv.URL+repoPath,
		)
		cmd.Env = append(os.Environ(),
			"GIT_TERMINAL_PROMPT=0",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"CUSTODIAN_TOKEN="+validToken,
			"CUSTODIAN_TEST_BIN="+exe,
			"CUSTODIAN_TEST_API="+apiSrv.URL,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git ls-remote %s failed: %v\noutput:\n%s", repoPath, err, string(out))
		}
		if challenges.Load() < 1 || authed.Load() != 1 {
			t.Fatalf("git ls-remote %s unexpected counts: challenges=%d authed=%d\noutput:\n%s", repoPath, challenges.Load(), authed.Load(), string(out))
		}
		if !strings.Contains(string(out), commitSHA+"\trefs/heads/main") {
			t.Fatalf("git ls-remote %s missing refs/heads/main in output:\n%s", repoPath, string(out))
		}
	}
}
