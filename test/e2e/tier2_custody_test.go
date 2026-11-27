package e2e_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

func m2CraftCustomJWT(t testing.TB, alg string, claims map[string]any, hsSecret []byte) string {
	t.Helper()
	hdrBytes, err := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal jwt header: %v", err)
	}
	payBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payBytes)
	if strings.EqualFold(alg, "none") {
		return signingInput + "."
	}
	mac := hmac.New(sha256.New, hsSecret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func m2ReserveEphemeralLoopback(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 127.0.0.1:0: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// --- F-01: Go module & 5 binaries (Tier 2: 5 tests) ---

func TestT2_F01_ForbiddenArchitectureDependenciesAbsent(t *testing.T) {
	root := m2FindRepoRoot(t)
	modOut, modErr, modCode := m2RunGoCommand(t, root, "list", "-m", "all")
	if modCode != 0 {
		t.Fatalf("go list -m all failed (exit %d):\n%s\n%s", modCode, modOut, modErr)
	}
	depsOut, depsErr, depsCode := m2RunGoCommand(t, root, "list", "-deps", "./cmd/...")
	if depsCode != 0 {
		t.Fatalf("go list -deps ./cmd/... failed (exit %d):\n%s\n%s", depsCode, depsOut, depsErr)
	}

	combined := modOut + "\n" + depsOut
	forbidden := []string{
		"go.temporal.io",
		"confluentinc/confluent-kafka-go",
		"IBM/sarama",
		"Shopify/sarama",
		"twmb/franz-go",
		"segmentio/kafka-go",
		"open-policy-agent/opa",
	}
	for _, f := range forbidden {
		if strings.Contains(combined, f) {
			t.Fatalf("forbidden architecture dependency %q found in module/deps", f)
		}
	}
}

func TestT2_F01_APIFailsStartupCleanlyOnUnreachableDB(t *testing.T) {
	root := m2FindRepoRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ct := harness.DefaultContracts()
	bins, err := harness.BuildOrLocateBinaries(ctx, "", root, t.TempDir(), "", ct.Binaries)
	if err != nil {
		t.Fatalf("BuildOrLocateBinaries: %v", err)
	}
	apiBin := bins[ct.Binaries.API]

	runCtx, runCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer runCancel()
	badSecret := "secretpass"
	res := harness.RunBinary(runCtx, apiBin, t.TempDir(), nil, map[string]string{
		ct.EnvListenAddr:  m2ReserveEphemeralLoopback(t),
		ct.EnvDatabaseDSN: fmt.Sprintf("postgres://bad:%s@127.0.0.1:1/none?sslmode=disable&connect_timeout=1", badSecret),
	})
	combined := res.Stdout + "\n" + res.Stderr
	if res.ExitCode == 0 {
		t.Fatalf("expected custodian-api to exit non-zero on unreachable DB, got 0:\n%s", combined)
	}
	if strings.Contains(combined, "panic:") {
		t.Fatalf("custodian-api panicked on unreachable DB:\n%s", combined)
	}
	harness.AssertNoSecretLeak(t, combined, badSecret)
}

func TestT2_F01_WorkerExitsNonZeroOnMissingRequiredDSN(t *testing.T) {
	root := m2FindRepoRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ct := harness.DefaultContracts()
	bins, err := harness.BuildOrLocateBinaries(ctx, "", root, t.TempDir(), "", ct.Binaries)
	if err != nil {
		t.Fatalf("BuildOrLocateBinaries: %v", err)
	}
	workerBin := bins[ct.Binaries.Worker]

	runCtx, runCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer runCancel()
	res := harness.RunBinary(runCtx, workerBin, t.TempDir(), nil, map[string]string{
		ct.EnvDatabaseDSN: "",
	})
	combined := res.Stdout + "\n" + res.Stderr
	if res.ExitCode == 0 {
		t.Fatalf("expected custodian-worker to exit non-zero when DSN is empty:\n%s", combined)
	}
	if strings.Contains(combined, "panic:") {
		t.Fatalf("custodian-worker panicked on missing DSN:\n%s", combined)
	}
}

func TestT2_F01_PolicyCLIRejectsInvalidCELBundleNonZero(t *testing.T) {
	root := m2FindRepoRoot(t)
	env := harness.NewEnv(t,
		harness.WithRepoRoot(root),
		harness.WithSkipPostgres(),
		harness.WithSkipServices(),
	)
	ct := env.Contracts()
	badBundle := filepath.Join(root, "test", "e2e", "fixtures", "policies", "invalid_cel_syntax.yaml")

	args := append([]string(nil), ct.CLI.PolicyValidateSubcommand...)
	args = append(args, ct.CLI.PolicyBundleFlag, badBundle)
	res := env.RunCLI(ct.Binaries.Policy, args, nil)
	combined := res.Stdout + "\n" + res.Stderr
	if res.ExitCode == 0 {
		t.Fatalf("expected %s %v to fail on invalid CEL syntax, got exit 0:\n%s", ct.Binaries.Policy, args, combined)
	}
	if strings.Contains(combined, "panic:") {
		t.Fatalf("%s panicked on invalid CEL bundle:\n%s", ct.Binaries.Policy, combined)
	}
}

func TestT2_F01_NoNestedE2EGoModAndNoHardcoded5432Or8080(t *testing.T) {
	root := m2FindRepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "test", "e2e", "go.mod")); !os.IsNotExist(err) {
		t.Fatalf("test/e2e/go.mod must not exist (err=%v)", err)
	}
	env := m2NewEnv(t)
	if env.DB().HostPort() == "" || env.DB().HostPort() == "5432" {
		t.Fatalf("ephemeral DB host port must be non-empty and never 5432, got %q", env.DB().HostPort())
	}
	u, err := url.Parse(env.APIBaseURL())
	if err != nil {
		t.Fatalf("parse APIBaseURL: %v", err)
	}
	if u.Port() == "" || u.Port() == "8080" {
		t.Fatalf("ephemeral API port must be non-empty and never 8080, got %q", u.Port())
	}
}

// --- F-02: Core contracts & publisher isolation (Tier 2: 5 tests) ---

func TestT2_F02_PublisherZeroForbiddenTransitiveImports(t *testing.T) {
	root := m2FindRepoRoot(t)
	stdout, stderr, code := m2RunGoCommand(t, root,
		"list", "-f", `{{range .Deps}}{{.}}{{"\n"}}{{end}}`,
		"./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish",
	)
	if code != 0 {
		t.Fatalf("go list transitive deps failed (exit %d):\n%s\n%s", code, stdout, stderr)
	}
	forbidden := []string{
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/git/reconstruct",
		"github.com/timreynolds/custodian/internal/git/checkout",
		"github.com/google/cel-go",
	}
	for _, line := range strings.Split(stdout, "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		for _, f := range forbidden {
			if pkg == f || strings.HasPrefix(pkg, f+"/") {
				t.Fatalf("publisher transitive import violation: %q matches forbidden %q", pkg, f)
			}
		}
	}
}

func TestT2_F02_APIStrictSchemaRejectsUnknownFields400(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	payload := fmt.Sprintf(`{
  "repository": {"provider": "github", "repository_id": %d, "ref": "refs/heads/main"},
  "rogue_field": "bypass"
}`, repo.GitHubRepoID)

	raw, err := env.Client(humanTok).DoRaw(ctx, http.MethodPost, "/v1/workspaces", []byte(payload))
	if err != nil {
		t.Fatalf("DoRaw: %v", err)
	}
	raw.RequireStatus(t, http.StatusBadRequest)
	if raw.Error == nil || raw.Error.Code == "" || raw.Error.Message == "" {
		t.Fatalf("expected OpenAPI ErrorResponse for unknown field, got: %s", string(raw.Body))
	}

	rows, err := env.DB().QueryRows(`SELECT count(*) FROM workspaces`)
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("expected 0 workspaces created after schema rejection, got rows=%v err=%v", rows, err)
	}
}

func TestT2_F02_ReadOnlyGitHubAppDeniedWriteTokenMinting(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	readJWT, err := harness.SignAppJWT(env.GitHub().ReadAppID(), env.GitHub().ReadAppPrivateKeyPEM(), time.Now().UTC())
	if err != nil {
		t.Fatalf("SignAppJWT(read): %v", err)
	}

	tokenURL := fmt.Sprintf("%sapp/installations/%d/access_tokens", env.GitHub().BaseAPIURL(), repo.InstallationID)
	reqBody := []byte(`{"permissions":{"contents":"write","pull_requests":"write"}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+readJWT)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("Do POST access_tokens: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for read app requesting write permissions, got %d", resp.StatusCode)
	}

	// Mint a valid read-only token and confirm MockGitHub blocks pull creation with it.
	readReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader([]byte(`{"permissions":{"contents":"read"}}`)))
	if err != nil {
		t.Fatalf("NewRequest read: %v", err)
	}
	readReq.Header.Set("Content-Type", "application/json")
	readReq.Header.Set("Authorization", "Bearer "+readJWT)
	readResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(readReq)
	if err != nil {
		t.Fatalf("Do read token: %v", err)
	}
	var tokPayload struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(readResp.Body).Decode(&tokPayload)
	_ = readResp.Body.Close()
	if readResp.StatusCode != http.StatusCreated || !strings.HasPrefix(tokPayload.Token, "ghs_read_") {
		t.Fatalf("expected 201 ghs_read_* token, got status=%d tok=%q", readResp.StatusCode, tokPayload.Token)
	}

	prURL := fmt.Sprintf("%srepos/%s/pulls", env.GitHub().BaseAPIURL(), repo.FullName)
	prReq, err := http.NewRequestWithContext(ctx, http.MethodPost, prURL, bytes.NewReader([]byte(`{"title":"x","head":"custodian/1","base":"main"}`)))
	if err != nil {
		t.Fatalf("NewRequest PR: %v", err)
	}
	prReq.Header.Set("Authorization", "Bearer "+tokPayload.Token)
	prResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(prReq)
	if err != nil {
		t.Fatalf("Do PR with read token: %v", err)
	}
	_ = prResp.Body.Close()
	if prResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when creating PR with read token, got %d", prResp.StatusCode)
	}

	// Exercise Custodian's live ingress runtime and confirm only read-only GitHub access occurred.
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	if ws.BaseCommit != repo.HeadSHA {
		t.Fatalf("workspace base_commit = %q (want %q)", ws.BaseCommit, repo.HeadSHA)
	}
	if pushes := env.GitHub().PushAttempts(); len(pushes) != 0 {
		t.Fatalf("expected 0 push attempts during read-only ingress, got %+v", pushes)
	}
	if prs := env.GitHub().PRCount(repo.FullName); prs != 0 {
		t.Fatalf("expected 0 PRs created during read-only ingress, got %d", prs)
	}
	env.AssertNoSecretLeakInLogs()
}

func TestT2_F02_E2ESuiteHasZeroInternalAndThirdPartyImports(t *testing.T) {
	root := m2FindRepoRoot(t)
	e2eOut, e2eErr, e2eCode := m2RunGoCommand(t, root,
		"list", "-f", "{{.ImportPath}} -> {{.Imports}} {{.TestImports}} {{.XTestImports}}", "./test/e2e/...",
	)
	if e2eCode != 0 {
		t.Fatalf("go list ./test/e2e/... failed (exit %d):\n%s\n%s", e2eCode, e2eOut, e2eErr)
	}
	if strings.Contains(e2eOut, "github.com/timreynolds/custodian/internal/") {
		t.Fatalf("test/e2e/... illegally imports internal/*:\n%s", e2eOut)
	}

	hOut, hErr, hCode := m2RunGoCommand(t, root,
		"list", "-f", `{{range .Imports}}{{.}}{{"\n"}}{{end}}`, "./test/e2e/harness/...",
	)
	if hCode != 0 {
		t.Fatalf("go list ./test/e2e/harness/... failed (exit %d):\n%s\n%s", hCode, hOut, hErr)
	}
	for _, line := range strings.Split(hOut, "\n") {
		imp := strings.TrimSpace(line)
		if imp == "" {
			continue
		}
		if strings.Contains(imp, ".") && imp != "github.com/timreynolds/custodian/test/e2e/harness" {
			t.Fatalf("test/e2e/harness illegally imports non-stdlib package %q", imp)
		}
	}
}

func TestT2_F02_PublisherRejectsUnapprovedProposalPublish(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# unapproved\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "unapproved-publish", nil)
	propID := m2ResolveProposalID(prop)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, raw, err := env.Client(ctrlTok).PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	raw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
	if prCount := env.GitHub().PRCount(repo.FullName); prCount != 0 {
		t.Fatalf("expected 0 PRs for unapproved proposal, got %d", prCount)
	}
	if pushes := env.GitHub().PushAttempts(); len(pushes) != 0 {
		t.Fatalf("expected 0 push attempts for unapproved proposal, got %+v", pushes)
	}
}

// --- F-03: PostgreSQL 16+ schema, migrations & UUIDv7 IDs (Tier 2: 5 tests) ---

func TestT2_F03_MalformedUUIDPathParamsReturn400(t *testing.T) {
	env, _ := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := env.Client(humanTok)

	for _, path := range []string{
		"/v1/workspaces/not-a-uuid",
		"/v1/proposals/abc",
		"/v1/operations/000",
		"/v1/publications/bad",
	} {
		raw, err := c.DoRaw(ctx, http.MethodGet, path, nil)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		raw.RequireStatus(t, http.StatusBadRequest)
		if raw.Error == nil || raw.Error.Code == "" {
			t.Fatalf("GET %s missing ErrorResponse: %s", path, string(raw.Body))
		}
	}
}

func TestT2_F03_UnknownValidUUIDv7Returns404(t *testing.T) {
	env, _ := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := env.Client(humanTok)
	ghost := harness.NewTestUUIDv7()

	_, r1, err := c.GetWorkspace(ctx, ghost)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	r1.RequireStatus(t, http.StatusNotFound)

	_, r2, err := c.GetProposal(ctx, ghost)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	r2.RequireStatus(t, http.StatusNotFound)

	_, r3, err := c.GetOperation(ctx, ghost)
	if err != nil {
		t.Fatalf("GetOperation: %v", err)
	}
	r3.RequireStatus(t, http.StatusNotFound)

	_, r4, err := c.GetPublication(ctx, ghost)
	if err != nil {
		t.Fatalf("GetPublication: %v", err)
	}
	r4.RequireStatus(t, http.StatusNotFound)
}

func TestT2_F03_PostgresCheckConstraintsEnforceDomainInvariants(t *testing.T) {
	env := m2NewEnv(t)

	badStatements := []struct {
		name string
		sql  string
	}{
		{
			name: "invalid_principal_kind",
			sql:  fmt.Sprintf(`INSERT INTO principals (id, kind, issuer, subject) VALUES (%s::uuid, 'ROOT', 'https://idp.test', 'root-1');`, m2SQLLiteral(harness.NewTestUUIDv7())),
		},
		{
			name: "invalid_repo_classification",
			sql:  fmt.Sprintf(`INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification) VALUES (%s::uuid, 99991, 99992, 'acme/bad', 'SECRET');`, m2SQLLiteral(harness.NewTestUUIDv7())),
		},
		{
			name: "invalid_artifact_sha256",
			sql:  fmt.Sprintf(`INSERT INTO artifacts (id, kind, sha256, storage_key, storage_generation, size_bytes) VALUES (%s::uuid, 'EGRESS_SNAPSHOT', 'bad', 'k', '1', 10);`, m2SQLLiteral(harness.NewTestUUIDv7())),
		},
		{
			name: "invalid_workspace_base_commit",
			sql:  fmt.Sprintf(`INSERT INTO workspaces (id, repository_id, owner_id, base_commit, target_ref, status) VALUES (%s::uuid, %s::uuid, %s::uuid, '123', 'refs/heads/main', 'PENDING');`, m2SQLLiteral(harness.NewTestUUIDv7()), m2SQLLiteral(harness.NewTestUUIDv7()), m2SQLLiteral(harness.NewTestUUIDv7())),
		},
	}

	for _, tc := range badStatements {
		if _, err := env.DB().ExecSQL(tc.sql); err == nil {
			t.Fatalf("expected CHECK/FK constraint error for %s, but SQL succeeded", tc.name)
		}
	}
}

func TestT2_F03_NonVersion7UUIDRejectedAtAPI(t *testing.T) {
	env, _ := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Valid UUIDv4 format (version digit = 4, not 7).
	uuidV4 := "01933e5a-1234-4abc-8def-0123456789ab"
	_, raw, err := env.Client(humanTok).GetWorkspace(ctx, uuidV4)
	if err != nil {
		t.Fatalf("GetWorkspace(v4): %v", err)
	}
	raw.RequireStatus(t, http.StatusBadRequest)
}

func TestT2_F03_TransientPostgresPauseReturns503ThenRecovers(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	if err := env.DB().Pause(); err != nil {
		t.Fatalf("DB().Pause: %v", err)
	}
	paused := true
	defer func() {
		if paused {
			_ = env.DB().Unpause()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := env.Client(humanTok)

	_, raw503, err := client.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace during DB pause: %v", err)
	}
	raw503.RequireAnyStatus(t, http.StatusServiceUnavailable, http.StatusInternalServerError)
	if raw503.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable during DB pause, got %d (%s)", raw503.StatusCode, string(raw503.Body))
	}

	readyRaw, err := client.GetReady(ctx)
	if err != nil {
		t.Fatalf("GetReady during DB pause: %v", err)
	}
	if readyRaw.StatusCode == http.StatusOK {
		t.Fatalf("expected /readyz to fail while Postgres is paused, got 200 OK")
	}

	if err := env.DB().Unpause(); err != nil {
		t.Fatalf("DB().Unpause: %v", err)
	}
	paused = false

	deadline := time.Now().Add(15 * time.Second)
	var recovered bool
	for time.Now().Before(deadline) {
		r, err := client.GetReady(ctx)
		if err == nil && r.StatusCode == http.StatusOK {
			recovered = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !recovered {
		t.Fatalf("/readyz did not recover to 200 after PG unpause")
	}

	wsAfter, okRaw, err := client.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace after unpause: %v", err)
	}
	okRaw.RequireStatus(t, http.StatusOK)
	if wsAfter.BaseCommit != ws.BaseCommit || wsAfter.Status != "READY" {
		t.Fatalf("workspace data corrupted after DB recovery: %+v", wsAfter)
	}
}

// --- F-04: Transactional outbox & leased operations (Tier 2: 5 tests) ---

func TestT2_F04_WorkerCrashMidLeaseReclaimedAndRecovered(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(humanTok)
	cResp, raw, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)

	// Simulate an expired worker lease left behind by a crashed worker process.
	_, err = env.DB().ExecSQL(fmt.Sprintf(
		`UPDATE operations SET status = 'RUNNING', lease_until = now() - interval '10 seconds', leased_by = 'dead-worker', attempts = 1 WHERE id = %s::uuid;`,
		m2SQLLiteral(cResp.OperationID),
	))
	if err != nil {
		t.Fatalf("inject expired RUNNING lease: %v", err)
	}

	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}

	op, err := client.WaitForOperation(ctx, cResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("expected reclaimed operation SUCCEEDED, got %q (%s)", op.Status, op.LastError)
	}
	if op.Attempts < 2 {
		t.Fatalf("expected reclaimed operation attempts >= 2, got %d", op.Attempts)
	}

	ws, wsRaw, err := client.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusOK)
	if ws.Status != "READY" {
		t.Fatalf("expected workspace READY after lease recovery, got %q", ws.Status)
	}
}

func TestT2_F04_TransientGitHubCloneOutageRetriesAndSucceeds(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	env.GitHub().SetOutage("POST", "/git-upload-pack", http.StatusServiceUnavailable, 2)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(humanTok)
	cResp, raw, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)

	op, err := client.WaitForOperation(ctx, cResp.OperationID, 35*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("expected operation SUCCEEDED after transient clone outage, got %q (%s)", op.Status, op.LastError)
	}
	if op.Attempts < 2 {
		t.Fatalf("expected retry attempts >= 2 after transient clone outage, got %d", op.Attempts)
	}

	ws, wsRaw, err := client.GetWorkspace(ctx, m2ResolveCreatedWorkspaceID(cResp))
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusOK)
	if ws.Status != "READY" {
		t.Fatalf("expected workspace READY, got %q", ws.Status)
	}
}

func TestT2_F04_OperationExhaustingMaxAttemptsTerminatesFailed(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(humanTok)
	cResp, raw, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)

	if _, err := env.DB().ExecSQL(fmt.Sprintf(`UPDATE operations SET max_attempts = 2 WHERE id = %s::uuid;`, m2SQLLiteral(cResp.OperationID))); err != nil {
		t.Fatalf("set max_attempts=2: %v", err)
	}
	env.GitHub().SetOutage("POST", "/git-upload-pack", http.StatusServiceUnavailable, 0)

	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}

	op, err := client.WaitForOperation(ctx, cResp.OperationID, 35*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "FAILED" {
		t.Fatalf("expected FAILED after max_attempts exhausted, got %q", op.Status)
	}
	if op.Attempts != 2 {
		t.Fatalf("expected Attempts == 2, got %d", op.Attempts)
	}
	if strings.TrimSpace(op.LastError) == "" {
		t.Fatalf("expected non-empty LastError on failed operation")
	}

	ws, wsRaw, err := client.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusOK)
	if ws.Status != "FAILED" {
		t.Fatalf("expected workspace status FAILED, got %q", ws.Status)
	}
}

func TestT2_F04_CrossOwnerAndUnauthenticatedOperationPollingDenied(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	tokA := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "owner-a", Email: "a@example.com"})
	tokB := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "owner-b", Email: "b@example.com"})

	cResp, _ := m2CreateReadyWorkspace(t, env, tokA, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, raw401, err := env.Client("").GetOperation(ctx, cResp.OperationID)
	if err != nil {
		t.Fatalf("unauth GetOperation: %v", err)
	}
	raw401.RequireStatus(t, http.StatusUnauthorized)

	_, raw403, err := env.Client(tokB).GetOperation(ctx, cResp.OperationID)
	if err != nil {
		t.Fatalf("cross-owner GetOperation: %v", err)
	}
	raw403.RequireStatus(t, http.StatusForbidden)
}

func TestT2_F04_OutboxSurvivesTransientSnapshotOutageAndDelivers(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(humanTok)
	cResp, raw, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)

	if err := env.Snapshots().SimulateOutage(true); err != nil {
		t.Fatalf("SimulateOutage(true): %v", err)
	}
	outageActive := true
	defer func() {
		if outageActive {
			_ = env.Snapshots().SimulateOutage(false)
		}
	}()

	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	time.Sleep(800 * time.Millisecond)

	if err := env.Snapshots().SimulateOutage(false); err != nil {
		t.Fatalf("SimulateOutage(false): %v", err)
	}
	outageActive = false

	op, err := client.WaitForOperation(ctx, cResp.OperationID, 35*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("expected operation SUCCEEDED after snapshot store recovery, got %q (%s)", op.Status, op.LastError)
	}

	outboxRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT count(*) FROM outbox_events WHERE aggregate_id = %s::uuid AND delivered_at IS NOT NULL`,
		m2SQLLiteral(wsID),
	))
	if err != nil || len(outboxRows) != 1 || outboxRows[0][0] == "0" {
		t.Fatalf("expected delivered outbox_events row for %s, got rows=%v err=%v", wsID, outboxRows, err)
	}
	wsCountRows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT count(*) FROM workspaces WHERE id = %s::uuid`, m2SQLLiteral(wsID)))
	if err != nil || len(wsCountRows) != 1 || wsCountRows[0][0] != "1" {
		t.Fatalf("expected 1 workspace row (no duplicates), got rows=%v err=%v", wsCountRows, err)
	}
}

// --- F-05: Hash-chained audit_events & query API (Tier 2: 5 tests) ---

func TestT2_F05_NonAuditorPrincipalsDeniedAuditEndpoint(t *testing.T) {
	env, _ := m2NewEnvWithSeededRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, raw401, err := env.Client("").ListAuditEvents(ctx, harness.AuditFilter{})
	if err != nil {
		t.Fatalf("unauth ListAuditEvents: %v", err)
	}
	raw401.RequireStatus(t, http.StatusUnauthorized)

	for _, kind := range []string{"HUMAN", "CONTROLLER", "AGENT", "POLICY_ADMIN"} {
		tok := env.MintToken(harness.TokenClaims{Kind: kind})
		_, raw, err := env.Client(tok).ListAuditEvents(ctx, harness.AuditFilter{})
		if err != nil {
			t.Fatalf("%s ListAuditEvents: %v", kind, err)
		}
		raw.RequireStatus(t, http.StatusForbidden)
	}
}

func TestT2_F05_ConcurrentMutationsProduceSingleSerializedHashChain(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			c := env.Client(humanTok)
			resp, raw, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
				Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
			})
			if err != nil {
				errs[idx] = err
				return
			}
			if raw.StatusCode != http.StatusAccepted {
				errs[idx] = fmt.Errorf("status %d: %s", raw.StatusCode, string(raw.Body))
				return
			}
			op, err := c.WaitForOperation(ctx, resp.OperationID, 30*time.Second)
			if err != nil {
				errs[idx] = err
				return
			}
			if op.Status != "SUCCEEDED" {
				errs[idx] = fmt.Errorf("op %s status=%s", op.ID, op.Status)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent mutation %d failed: %v", i, err)
		}
	}

	seqRows, err := env.DB().QueryRows(`SELECT chain_seq FROM audit_events ORDER BY chain_seq ASC`)
	if err != nil || len(seqRows) < n {
		t.Fatalf("query audit_events chain_seq failed: rows=%d err=%v", len(seqRows), err)
	}
	for i, r := range seqRows {
		if r[0] != fmt.Sprintf("%d", i+1) {
			t.Fatalf("chain_seq gap/fork at index %d: got %q, want %d", i, r[0], i+1)
		}
	}

	events := m2SortAuditEventsAscending(m2FetchAllAuditEvents(t, env.Client(audTok)))
	harness.VerifyFullAuditHashChainFromGenesis(t, events)
}

func TestT2_F05_AuditEventsImmutableAndTamperDetectable(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# tamper test\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "tamper-detect", nil)

	events := m2SortAuditEventsAscending(m2FetchAllAuditEvents(t, env.Client(audTok)))
	if len(events) < 3 {
		t.Fatalf("expected >= 3 audit events, got %d", len(events))
	}
	harness.VerifyFullAuditHashChainFromGenesis(t, events)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	audClient := env.Client(audTok)
	delRaw, err := audClient.DoRaw(ctx, http.MethodDelete, "/v1/audit/events/"+events[0].ID, nil)
	if err != nil {
		t.Fatalf("DELETE audit event: %v", err)
	}
	delRaw.RequireAnyStatus(t, http.StatusNotFound, http.StatusMethodNotAllowed)

	patchRaw, err := audClient.DoRaw(ctx, http.MethodPatch, "/v1/audit/events/"+events[0].ID, []byte(`{"event_type":"tampered"}`))
	if err != nil {
		t.Fatalf("PATCH audit event: %v", err)
	}
	patchRaw.RequireAnyStatus(t, http.StatusNotFound, http.StatusMethodNotAllowed)

	tampered := make([]harness.AuditEvent, len(events))
	copy(tampered, events)
	tampered[1].PreviousHash = strings.Repeat("f", 64)
	if err := harness.ValidateAuditHashChain(tampered); err == nil {
		t.Fatalf("expected ValidateAuditHashChain to detect broken PreviousHash linkage")
	}
}

func TestT2_F05_InvalidAuditQueryFiltersReturn400(t *testing.T) {
	env, _ := m2NewEnvWithSeededRepo(t)
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	audClient := env.Client(audTok)

	invalidFilters := []struct {
		name   string
		params map[string]string
	}{
		{name: "bad_resource_id", params: map[string]string{"resource_id": "bad"}},
		{name: "bad_actor_id", params: map[string]string{"actor_id": "bad"}},
		{name: "limit_zero", params: map[string]string{"limit": "0"}},
		{name: "limit_too_large", params: map[string]string{"limit": "501"}},
		{name: "bad_since", params: map[string]string{"since": "not-a-date"}},
	}
	for _, tc := range invalidFilters {
		raw, err := audClient.DoRaw(ctx, http.MethodGet, "/v1/audit/events", nil, harness.WithQuery(tc.params))
		if err != nil {
			t.Fatalf("%s DoRaw: %v", tc.name, err)
		}
		raw.RequireStatus(t, http.StatusBadRequest)
		if raw.Error == nil || raw.Error.Code == "" {
			t.Fatalf("%s missing ErrorResponse: %s", tc.name, string(raw.Body))
		}
	}
}

func TestT2_F05_DeniedSecurityActionsPersistAuditTrail(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "denied-hist-user", Email: "dhu@example.com"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, raw, err := env.Client(humanTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		SourceOptions: &harness.WorkspaceSourceOptions{
			IncludeGitMetadata: true,
			IncludeHistory:     true,
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(include_history): %v", err)
	}
	raw.RequireStatus(t, http.StatusForbidden)

	events := m2SortAuditEventsAscending(m2FetchAllAuditEvents(t, env.Client(audTok)))
	if len(events) == 0 {
		t.Fatalf("expected audit event persisted for denied include_history request")
	}
	foundDenial := false
	for _, ev := range events {
		lowerType := strings.ToLower(ev.EventType)
		if strings.Contains(lowerType, "denied") || strings.Contains(lowerType, "forbidden") ||
			strings.Contains(lowerType, "rejected") || strings.Contains(lowerType, "auth") {
			foundDenial = true
			break
		}
	}
	if !foundDenial {
		t.Fatalf("expected denial audit event recorded, got events=%+v", events)
	}
	harness.VerifyFullAuditHashChainFromGenesis(t, events)
}

// --- F-06: OIDC / workload identity & human owner resolution (Tier 2: 5 tests) ---

func TestT2_F06_RejectsMissingMalformedExpiredAndRogueJWTs(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	algNone := m2CraftCustomJWT(t, "none", map[string]any{
		"iss":            env.OIDC().Issuer(),
		"sub":            "alg-none-attacker",
		"aud":            env.OIDC().Audience(),
		"email":          "attacker@example.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	}, nil)
	algHS256 := m2CraftCustomJWT(t, "HS256", map[string]any{
		"iss":            env.OIDC().Issuer(),
		"sub":            "hs256-attacker",
		"aud":            env.OIDC().Audience(),
		"email":          "attacker@example.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	}, []byte("confused-key"))

	cases := []struct {
		name string
		opts []harness.RequestOption
	}{
		{name: "missing_auth", opts: []harness.RequestOption{harness.WithoutAuth()}},
		{name: "malformed_jwt", opts: []harness.RequestOption{harness.WithTokenOverride("not.a.jwt")}},
		{name: "expired_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(env.MintToken(harness.TokenClaims{Kind: "HUMAN", ExpiresAt: time.Now().Add(-10 * time.Minute)}))}},
		{name: "rogue_key_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(env.MintToken(harness.TokenClaims{Kind: "HUMAN", SignWithWrongKey: true}))}},
		{name: "tampered_sig_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(env.MintToken(harness.TokenClaims{Kind: "HUMAN", TamperSignature: true}))}},
		{name: "wrong_issuer_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(env.MintToken(harness.TokenClaims{Kind: "HUMAN", Issuer: "https://evil-idp.example.com"}))}},
		{name: "wrong_audience_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(env.MintToken(harness.TokenClaims{Kind: "HUMAN", Audience: []string{"wrong-aud"}}))}},
		{name: "alg_none_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(algNone)}},
		{name: "alg_hs256_jwt", opts: []harness.RequestOption{harness.WithTokenOverride(algHS256)}},
	}

	req := harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	}
	baseClient := env.Client("")
	for _, tc := range cases {
		_, raw, err := baseClient.CreateWorkspace(ctx, req, tc.opts...)
		if err != nil {
			t.Fatalf("%s CreateWorkspace: %v", tc.name, err)
		}
		raw.RequireStatus(t, http.StatusUnauthorized)
	}
}

func TestT2_F06_AntiImpersonationBlocksSpoofedOwnerAndAgentSelfCreate(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "real-human"})
	agentTok := env.MintToken(harness.TokenClaims{Kind: "AGENT", Subject: "rogue-agent"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// (a) Human attempts to spoof owner_id in CreateWorkspaceRequest.
	_, spoofRaw, err := env.Client(humanTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		OwnerID:    harness.NewTestUUIDv7(),
	})
	if err != nil {
		t.Fatalf("spoofed OwnerID CreateWorkspace: %v", err)
	}
	spoofRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusForbidden)

	// (b) Agent workload attempts to create workspace directly.
	_, agentRaw, err := env.Client(agentTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("agent CreateWorkspace: %v", err)
	}
	agentRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)

	rows, err := env.DB().QueryRows(`SELECT count(*) FROM workspaces`)
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("expected 0 workspaces created, got rows=%v err=%v", rows, err)
	}
}

func TestT2_F06_ForgedAuthorMetadataCannotOverrideWorkspaceOwner(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "human-a-real", Email: "humana@example.com"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, sha := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# forged author test\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: ".git/config", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("[user]\n\tname = Spoof\n\temail = spoof@evil.com\n")},
	})
	artifactID, gotSHA := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)
	if gotSHA != sha {
		t.Fatalf("sha mismatch: %s vs %s", gotSHA, sha)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	// (a) Negative SubmitProposal with explicit AuthorEmail/AuthorName must be rejected by strict schema.
	_, forgedRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title:       "forged-fields",
		AuthorEmail: "spoof@evil.com",
		AuthorName:  "Spoof",
	})
	if err != nil {
		t.Fatalf("SubmitProposal with forged author fields: %v", err)
	}
	forgedRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity)

	// (b) Valid submission with .git/config [user] + Author trailer in description preserves Human A as Owner.
	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title:       "forged-git-config-author",
		Description: "Author: spoof@evil.com\nSigned-off-by: Spoof <spoof@evil.com>",
	})
	if err != nil {
		t.Fatalf("SubmitProposal valid: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	propID := m2ResolveProposalID(subResp)
	op, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED, got %q (%s)", op.Status, op.LastError)
	}

	prop, propRaw, err := ctrlClient.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	propRaw.RequireStatus(t, http.StatusOK)
	if prop.Owner == nil || ws.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("proposal owner %+v was overridden; want %+v", prop.Owner, ws.Owner)
	}
}

func TestT2_F06_CrossOwnerCannotReadWorkspaceOrProposal(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	tokA := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-x", Email: "alicex@example.com"})
	tokB := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "bob-x", Email: "bobx@example.com"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, tokA, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# private\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "cross-owner", nil)
	propID := m2ResolveProposalID(prop)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	bob := env.Client(tokB)

	_, r1, err := bob.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("bob GetWorkspace: %v", err)
	}
	r1.RequireStatus(t, http.StatusForbidden)

	_, r2, err := bob.GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("bob GetWorkspaceSource: %v", err)
	}
	r2.RequireStatus(t, http.StatusForbidden)

	_, r3, err := bob.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("bob GetProposal: %v", err)
	}
	r3.RequireStatus(t, http.StatusForbidden)

	_, r4, err := bob.GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("bob GetProposalDiff: %v", err)
	}
	r4.RequireStatus(t, http.StatusForbidden)
}

func TestT2_F06_UnverifiedOrEmptyEmailHumanTokenRejected(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	unverifiedTok := env.MintToken(harness.TokenClaims{
		Kind:          "HUMAN",
		Subject:       "unverified-user",
		Email:         "unverified@example.com",
		EmailVerified: m2PtrBool(false),
	})
	emptyEmailTok := env.MintToken(harness.TokenClaims{
		Kind:          "HUMAN",
		Subject:       "empty-email-user",
		EmailVerified: m2PtrBool(true),
		Extra:         map[string]any{"email": ""},
	})

	req := harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	}
	_, raw1, err := env.Client(unverifiedTok).CreateWorkspace(ctx, req)
	if err != nil {
		t.Fatalf("unverified CreateWorkspace: %v", err)
	}
	raw1.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)

	_, raw2, err := env.Client(emptyEmailTok).CreateWorkspace(ctx, req)
	if err != nil {
		t.Fatalf("empty email CreateWorkspace: %v", err)
	}
	raw2.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)
}
