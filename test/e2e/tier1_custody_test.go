package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

const (
	m2DefaultRepoOwner  = "acme"
	m2DefaultRepoName   = "service"
	m2DefaultRepoFull   = "acme/service"
	m2DefaultModelRoute = "approved-code-review"
)

func m2FindRepoRoot(t testing.TB) string {
	t.Helper()
	if envRoot := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_ROOT")); envRoot != "" {
		return envRoot
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	cur := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			if _, err2 := os.Stat(filepath.Join(cur, "test", "e2e", "run_e2e.sh")); err2 == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	t.Fatalf("unable to locate repository root from %q", wd)
	return ""
}

func m2PolicyDirWithDefault(t testing.TB) string {
	t.Helper()
	root := m2FindRepoRoot(t)
	src := filepath.Join(root, "test", "e2e", "fixtures", "policies", "valid_default.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read default policy fixture %q: %v", src, err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "valid_default.yaml")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write temp default policy %q: %v", dst, err)
	}
	return dir
}

func m2NewEnv(t *testing.T, opts ...harness.EnvOption) *harness.Env {
	t.Helper()
	merged := []harness.EnvOption{
		harness.WithRepoRoot(m2FindRepoRoot(t)),
		harness.WithPolicyBundleDir(m2PolicyDirWithDefault(t)),
	}
	merged = append(merged, opts...)
	return harness.NewEnv(t, merged...)
}

func m2SQLLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func m2SQLTextArray(items []string) string {
	if len(items) == 0 {
		return "'{}'::text[]"
	}
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = m2SQLLiteral(item)
	}
	return "ARRAY[" + strings.Join(quoted, ",") + "]::text[]"
}

func m2SeedRepoDB(t testing.TB, env *harness.Env, repo harness.SeededRepo, classification string, enabled bool, allowedRoutes []string, maxConcurrent int) string {
	t.Helper()
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	repoUUID := harness.NewTestUUIDv7()
	q := fmt.Sprintf(
		`INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations)
		 VALUES (%s::uuid, %d, %d, %s, %s, %t, %s, %d);`,
		m2SQLLiteral(repoUUID),
		repo.GitHubRepoID,
		repo.InstallationID,
		m2SQLLiteral(repo.FullName),
		m2SQLLiteral(classification),
		enabled,
		m2SQLTextArray(allowedRoutes),
		maxConcurrent,
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("m2SeedRepoDB(%s): %v", repo.FullName, err)
	}
	return repoUUID
}

func m2DefaultRepoSeedSpec() harness.RepoSeedSpec {
	return harness.RepoSeedSpec{
		Owner:         m2DefaultRepoOwner,
		Name:          m2DefaultRepoName,
		DefaultBranch: "main",
		Files: map[string]string{
			"README.md": "# acme/service\n",
			"main.go":   "package main\n\nfunc main() {}\n",
		},
	}
}

func m2NewEnvWithSeededRepo(t *testing.T, opts ...harness.EnvOption) (*harness.Env, harness.SeededRepo) {
	t.Helper()
	allOpts := make([]harness.EnvOption, 0, len(opts)+1)
	allOpts = append(allOpts, harness.WithSeedRepos(m2DefaultRepoSeedSpec()))
	allOpts = append(allOpts, opts...)

	env := m2NewEnv(t, allOpts...)
	repo, ok := env.Git().Repo(m2DefaultRepoFull)
	if !ok {
		t.Fatalf("seeded repo %q missing from BareGitHelper", m2DefaultRepoFull)
	}
	m2SeedRepoDB(t, env, repo, "INTERNAL", true, []string{m2DefaultModelRoute}, 10)
	return env, repo
}

func m2ResolveCreatedWorkspaceID(resp harness.WorkspaceCreateResp) string {
	if resp.WorkspaceID != "" {
		return resp.WorkspaceID
	}
	return resp.ID
}

func m2ResolveWorkspaceID(resp harness.WorkspaceResp) string {
	if resp.ID != "" {
		return resp.ID
	}
	return resp.WorkspaceID
}

func m2ResolveProposalID(resp harness.ProposalResp) string {
	if resp.ID != "" {
		return resp.ID
	}
	return resp.ProposalID
}

func m2ResolvePublicationID(resp harness.PublicationResp) string {
	if resp.ID != "" {
		return resp.ID
	}
	return resp.PublicationID
}

func m2CreateReadyWorkspace(t testing.TB, env *harness.Env, humanToken string, req harness.CreateWorkspaceReq) (harness.WorkspaceCreateResp, harness.WorkspaceResp) {
	t.Helper()
	if req.Repository.Provider == "" {
		req.Repository.Provider = "github"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(humanToken)
	createResp, raw, err := client.CreateWorkspace(ctx, req)
	if err != nil {
		t.Fatalf("CreateWorkspace error: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)

	wsID := m2ResolveCreatedWorkspaceID(createResp)
	harness.AssertUUIDv7(t, wsID)
	harness.AssertUUIDv7(t, createResp.OperationID)

	op, err := client.WaitForOperation(ctx, createResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation(%s): %v", createResp.OperationID, err)
	}
	if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
		t.Fatalf("workspace ingress op %s failed: status=%s err=%s", op.ID, op.Status, op.LastError)
	}

	ws, getRaw, err := client.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace(%s): %v", wsID, err)
	}
	getRaw.RequireStatus(t, http.StatusOK)
	if ws.Status != "READY" {
		t.Fatalf("workspace %s status = %q (want READY)", wsID, ws.Status)
	}
	return createResp, ws
}

func m2UploadSnapshotBytes(t testing.TB, env *harness.Env, ctrlToken, wsID string, gzBytes []byte) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := env.Client(ctrlToken)
	capResp, capRaw, err := client.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability(%s): %v", wsID, err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	if capResp.Token == "" || capResp.UploadURL == "" {
		t.Fatalf("incomplete upload capability: %+v", capResp)
	}

	upRaw, err := client.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, gzBytes)
	if err != nil {
		t.Fatalf("UploadSnapshot(%s): %v", capResp.UploadURL, err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)

	var body struct {
		ArtifactID string `json:"artifact_id"`
		ID         string `json:"id"`
		SHA256     string `json:"sha256"`
	}
	if len(bytes.TrimSpace(upRaw.Body)) > 0 {
		if err := json.Unmarshal(upRaw.Body, &body); err != nil {
			t.Fatalf("decode upload response JSON %q: %v", string(upRaw.Body), err)
		}
	}
	artifactID := body.ArtifactID
	if artifactID == "" {
		artifactID = body.ID
	}
	harness.AssertUUIDv7(t, artifactID)

	sha := body.SHA256
	if sha == "" {
		sha = harness.SHA256Hex(gzBytes)
	}
	return artifactID, sha
}

func m2UploadAndSubmitProposal(t testing.TB, env *harness.Env, ctrlToken, wsID string, gen int64, gzBytes []byte, title string, prov *harness.Provenance) (harness.ProposalResp, harness.OperationResp) {
	t.Helper()
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlToken, wsID, gzBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(ctrlToken)
	req := harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: gen,
			SizeBytes:           int64(len(gzBytes)),
		},
		Title:      title,
		Provenance: prov,
	}
	subResp, subRaw, err := client.SubmitProposal(ctx, wsID, req)
	if err != nil {
		t.Fatalf("SubmitProposal(%s): %v", wsID, err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)

	propID := m2ResolveProposalID(subResp)
	harness.AssertUUIDv7(t, propID)
	harness.AssertUUIDv7(t, subResp.OperationID)

	op, err := client.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation(%s): %v", subResp.OperationID, err)
	}
	if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
		t.Fatalf("proposal reconstruct op %s failed: status=%s err=%s", op.ID, op.Status, op.LastError)
	}

	prop, getRaw, err := client.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal(%s): %v", propID, err)
	}
	getRaw.RequireStatus(t, http.StatusOK)
	if prop.Status != "RECONSTRUCTED" {
		t.Fatalf("proposal %s status = %q (want RECONSTRUCTED)", propID, prop.Status)
	}
	return prop, op
}

func m2SubmitAndExpectArchiveRejected(t testing.TB, env *harness.Env, ctrlToken, wsID string, gen int64, gzBytes []byte, label string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := env.Client(ctrlToken)
	capResp, capRaw, err := client.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("[%s] RequestUploadCapability: %v", label, err)
	}
	capRaw.RequireStatus(t, http.StatusOK)

	upRaw, err := client.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, gzBytes)
	if err != nil {
		t.Fatalf("[%s] UploadSnapshot: %v", label, err)
	}
	if upRaw.StatusCode == http.StatusBadRequest || upRaw.StatusCode == http.StatusRequestEntityTooLarge || upRaw.StatusCode == http.StatusUnprocessableEntity {
		return
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)

	var upBody struct {
		ArtifactID string `json:"artifact_id"`
		ID         string `json:"id"`
		SHA256     string `json:"sha256"`
	}
	if err := json.Unmarshal(upRaw.Body, &upBody); err != nil {
		t.Fatalf("[%s] decode upload response %q: %v", label, string(upRaw.Body), err)
	}
	artifactID := upBody.ArtifactID
	if artifactID == "" {
		artifactID = upBody.ID
	}
	harness.AssertUUIDv7(t, artifactID)
	sha := upBody.SHA256
	if sha == "" {
		sha = harness.SHA256Hex(gzBytes)
	}

	subResp, subRaw, err := client.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: gen,
			SizeBytes:           int64(len(gzBytes)),
		},
		Title: "adversarial-" + label,
	})
	if err != nil {
		t.Fatalf("[%s] SubmitProposal: %v", label, err)
	}
	if subRaw.StatusCode == http.StatusBadRequest || subRaw.StatusCode == http.StatusUnprocessableEntity {
		return
	}
	subRaw.RequireStatus(t, http.StatusAccepted)

	propID := m2ResolveProposalID(subResp)
	harness.AssertUUIDv7(t, propID)

	op, err := client.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("[%s] WaitForOperation(%s): %v", label, subResp.OperationID, err)
	}
	if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
		t.Fatalf("[%s] expected terminal failure operation for adversarial archive, got %q", label, op.Status)
	}

	prop, propRaw, err := client.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("[%s] GetProposal(%s): %v", label, propID, err)
	}
	propRaw.RequireStatus(t, http.StatusOK)
	if prop.Status != "FAILED" {
		t.Fatalf("[%s] expected proposal status FAILED, got %q", label, prop.Status)
	}
	if prop.CanonicalArtifactID != "" {
		t.Fatalf("[%s] failed adversarial proposal must not produce canonical_artifact_id %q", label, prop.CanonicalArtifactID)
	}
	if prop.PublicationManifestDigest != "" {
		t.Fatalf("[%s] failed adversarial proposal must not produce publication_manifest_digest %q", label, prop.PublicationManifestDigest)
	}
}

func m2FetchAllAuditEvents(t testing.TB, auditorClient *harness.APIClient) []harness.AuditEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var all []harness.AuditEvent
	cursor := ""
	for page := 0; page < 200; page++ {
		resp, raw, err := auditorClient.ListAuditEvents(ctx, harness.AuditFilter{
			Limit:  100,
			Cursor: cursor,
		})
		if err != nil {
			t.Fatalf("ListAuditEvents(cursor=%q): %v", cursor, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		all = append(all, resp.Events...)
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}
	return all
}

func m2SortAuditEventsAscending(events []harness.AuditEvent) []harness.AuditEvent {
	cp := make([]harness.AuditEvent, len(events))
	copy(cp, events)
	sort.SliceStable(cp, func(i, j int) bool {
		if !cp[i].CreatedAt.Equal(cp[j].CreatedAt) {
			return cp[i].CreatedAt.Before(cp[j].CreatedAt)
		}
		return cp[i].ID < cp[j].ID
	})
	return cp
}

func m2IsLowerHexLen(s string, wantLen int) bool {
	if len(s) != wantLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func m2PtrBool(v bool) *bool {
	return &v
}

func m2RunGoCommand(t testing.TB, repoRoot string, args ...string) (string, string, int) {
	t.Helper()
	goBin, err := harness.ResolveGoBin()
	if err != nil {
		t.Fatalf("ResolveGoBin: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return stdout.String(), stderr.String(), code
}

// --- F-01: Go module & 5 binaries (Tier 1: 5 tests) ---

func TestT1_F01_GoModuleAndAllFiveBinariesBuild(t *testing.T) {
	root := m2FindRepoRoot(t)
	modBytes, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	modText := string(modBytes)
	if !strings.Contains(modText, "module github.com/timreynolds/custodian") {
		t.Fatalf("go.mod missing canonical module path: %s", modText)
	}
	if !strings.Contains(modText, "go 1.25") && !strings.Contains(modText, "go 1.26") && !strings.Contains(modText, "go 1.27") {
		t.Fatalf("go.mod expected Go >= 1.25 directive: %s", modText)
	}

	goBin, err := harness.ResolveGoBin()
	if err != nil {
		t.Fatalf("ResolveGoBin: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	outDir := t.TempDir()
	bins, err := harness.BuildOrLocateBinaries(ctx, goBin, root, outDir, "", harness.DefaultContracts().Binaries)
	if err != nil {
		t.Fatalf("BuildOrLocateBinaries: %v", err)
	}

	for _, name := range harness.AllBinaryNames {
		p, ok := bins[name]
		if !ok {
			t.Fatalf("binary %q missing from build result", name)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat built binary %q (%s): %v", name, p, err)
		}
		if info.Size() == 0 {
			t.Fatalf("built binary %q (%s) is empty", name, p)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("built binary %q (%s) is not executable: mode=%v", name, p, info.Mode())
		}
	}
}

func TestT1_F01_CLIBinariesHelpAndUsage(t *testing.T) {
	root := m2FindRepoRoot(t)
	env := harness.NewEnv(t,
		harness.WithRepoRoot(root),
		harness.WithSkipPostgres(),
		harness.WithSkipServices(),
	)

	for _, bin := range harness.AllBinaryNames {
		res := env.RunCLI(bin, []string{"--help"}, nil)
		combined := res.Stdout + "\n" + res.Stderr
		if res.ExitCode != 0 {
			t.Fatalf("%s --help exited %d: %s", bin, res.ExitCode, combined)
		}
		if strings.TrimSpace(combined) == "" {
			t.Fatalf("%s --help produced empty usage output", bin)
		}
		if strings.Contains(combined, "panic:") {
			t.Fatalf("%s --help panicked: %s", bin, combined)
		}
	}
}

func TestT1_F01_APIServerHealthReadinessAndMetrics(t *testing.T) {
	env := m2NewEnv(t)
	u, err := url.Parse(env.APIBaseURL())
	if err != nil {
		t.Fatalf("parse APIBaseURL %q: %v", env.APIBaseURL(), err)
	}
	if u.Port() == "8080" || u.Port() == "" {
		t.Fatalf("API port must be ephemeral and never 8080, got %q", u.Port())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := env.Client("")
	hRaw, err := client.GetHealth(ctx)
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	hRaw.RequireStatus(t, http.StatusOK)

	rRaw, err := client.GetReady(ctx)
	if err != nil {
		t.Fatalf("GetReady: %v", err)
	}
	rRaw.RequireStatus(t, http.StatusOK)

	metricsBody, mRaw, err := client.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	mRaw.RequireStatus(t, http.StatusOK)
	if !strings.Contains(metricsBody, "# TYPE ") && !strings.Contains(metricsBody, "# HELP ") {
		t.Fatalf("unexpected /metrics payload (missing Prometheus headers): %q", metricsBody)
	}
}

func TestT1_F01_PolicyCLIValidateValidBundle(t *testing.T) {
	root := m2FindRepoRoot(t)
	env := harness.NewEnv(t,
		harness.WithRepoRoot(root),
		harness.WithSkipPostgres(),
		harness.WithSkipServices(),
	)
	ct := env.Contracts()
	bundlePath := filepath.Join(root, "test", "e2e", "fixtures", "policies", "valid_default.yaml")

	args := append([]string(nil), ct.CLI.PolicyValidateSubcommand...)
	args = append(args, ct.CLI.PolicyBundleFlag, bundlePath)
	res := env.RunCLI(ct.Binaries.Policy, args, nil)
	combined := res.Stdout + "\n" + res.Stderr
	if res.ExitCode != 0 {
		t.Fatalf("%s %v exited %d: %s", ct.Binaries.Policy, args, res.ExitCode, combined)
	}
	if strings.Contains(combined, "panic:") {
		t.Fatalf("%s panicked: %s", ct.Binaries.Policy, combined)
	}
}

func TestT1_F01_OperatorCLICleanEnvAndPolicyEvaluate(t *testing.T) {
	root := m2FindRepoRoot(t)
	env, repo := m2NewEnvWithSeededRepo(t)
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

	ct := env.Contracts()
	helpRes := env.RunCLI(ct.Binaries.Custodian, []string{"--help"}, map[string]string{
		"CUSTODIAN_API_URL": env.APIBaseURL(),
	})
	helpOut := helpRes.Stdout + "\n" + helpRes.Stderr
	if helpRes.ExitCode != 0 {
		t.Fatalf("%s --help exited %d: %s", ct.Binaries.Custodian, helpRes.ExitCode, helpOut)
	}
	if strings.TrimSpace(helpOut) == "" || strings.Contains(helpOut, "panic:") {
		t.Fatalf("invalid %s --help output: %s", ct.Binaries.Custodian, helpOut)
	}

	// Verify custodian-policy evaluate using the Contracts-defined subcommand & flags.
	inputJSONPath := filepath.Join(t.TempDir(), "policy_input.json")
	inputPayload := `{
  "stage": "EGRESS",
  "findings": {
    "scan_complete": true,
    "critical_secrets": 0,
    "prohibited_licenses": 0
  },
  "assessment": {
    "status": "COMPLETE",
    "ip_risk": "NONE"
  },
  "change": {
    "paths": ["pkg/hello/hello.go"]
  }
}`
	if err := os.WriteFile(inputJSONPath, []byte(inputPayload), 0o644); err != nil {
		t.Fatalf("write policy input JSON: %v", err)
	}
	bundlePath := filepath.Join(root, "test", "e2e", "fixtures", "policies", "valid_default.yaml")
	evalArgs := append([]string(nil), ct.CLI.PolicyEvaluateSubcommand...)
	evalArgs = append(evalArgs, ct.CLI.PolicyBundleFlag, bundlePath, ct.CLI.PolicyInputFlag, inputJSONPath)
	evalRes := env.RunCLI(ct.Binaries.Policy, evalArgs, nil)
	evalOut := evalRes.Stdout + "\n" + evalRes.Stderr
	if evalRes.ExitCode != 0 {
		t.Fatalf("%s %v exited %d: %s", ct.Binaries.Policy, evalArgs, evalRes.ExitCode, evalOut)
	}
	if !strings.Contains(evalOut, "ALLOW") && !strings.Contains(evalOut, "REQUIRE_APPROVAL") {
		t.Fatalf("expected decision effect in %s evaluate output, got: %s", ct.Binaries.Policy, evalOut)
	}
}

// --- F-02: Core contracts & publisher isolation (Tier 1: 5 tests) ---

func TestT1_F02_PublisherIsolationImportBoundary(t *testing.T) {
	root := m2FindRepoRoot(t)
	stdout, stderr, code := m2RunGoCommand(t, root,
		"list", "-f", "{{.ImportPath}} -> {{.Deps}}",
		"./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish",
	)
	if code != 0 {
		t.Fatalf("go list -deps on publisher packages failed (exit %d):\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}
	forbidden := []string{
		"internal/inspection",
		"internal/decisions",
		"internal/snapshots",
		"internal/git/reconstruct",
		"internal/git/checkout",
		"internal/policy",
	}
	for _, f := range forbidden {
		if strings.Contains(stdout, f) {
			t.Fatalf("publisher isolation boundary violated: found forbidden dependency %q in:\n%s", f, stdout)
		}
	}
}

func TestT1_F02_OpenAPI31SpecificationValidatesOffline(t *testing.T) {
	root := m2FindRepoRoot(t)
	stdout, stderr, code := m2RunGoCommand(t, root, "test", "-v", "-count=1", "./internal/api/openapi/...")
	if code != 0 {
		t.Fatalf("openapi validation failed (exit %d):\nstdout:%s\nstderr:%s", code, stdout, stderr)
	}

	specBytes, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read api/openapi.yaml: %v", err)
	}
	spec := string(specBytes)
	if !strings.Contains(spec, "openapi: 3.1") && !strings.Contains(spec, `openapi: "3.1`) {
		t.Fatalf("api/openapi.yaml does not declare OpenAPI 3.1")
	}
	requiredPaths := []string{
		"/v1/workspaces:",
		"/v1/workspaces/{id}:",
		"/v1/workspaces/{id}/source:",
		"/v1/workspaces/{id}/proposals:",
		"/v1/proposals/{id}:",
		"/v1/proposals/{id}/diff:",
		"/v1/proposals/{id}/findings:",
		"/v1/proposals/{id}/assessments:",
		"/v1/proposals/{id}/evaluate:",
		"/v1/proposals/{id}/approvals:",
		"/v1/proposals/{id}/publish:",
		"/v1/publications/{id}:",
		"/v1/policies/validate:",
		"/v1/policies/evaluate:",
		"/v1/operations/{id}:",
		"/v1/audit/events:",
	}
	for _, p := range requiredPaths {
		if !strings.Contains(spec, p) {
			t.Fatalf("api/openapi.yaml missing required path %q", p)
		}
	}
}

func TestT1_F02_PublisherRunsWithoutModelOrScannerEnv(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() { println(\"ok\") }\n")},
	})
	m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "publisher-env-isolation", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rRaw, err := env.Client("").GetReady(ctx)
	if err != nil {
		t.Fatalf("GetReady: %v", err)
	}
	rRaw.RequireStatus(t, http.StatusOK)

	pubLogs := env.Logs("publisher")
	if strings.Contains(pubLogs, "panic:") {
		t.Fatalf("publisher panicked:\n%s", pubLogs)
	}
	env.AssertNoSecretLeakInLogs()
}

func m2AssertOpenAPIErrorEnvelope(t testing.TB, raw *harness.RawResponse, label string) {
	t.Helper()
	var envelope struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		t.Fatalf("%s response invalid JSON ErrorResponse (%v): body=%s", label, err, string(raw.Body))
	}
	if envelope.Error == nil || envelope.Error.Code == "" || envelope.Error.Message == "" {
		t.Fatalf("%s response missing OpenAPI ErrorResponse {\"error\":{\"code\":...,\"message\":...}}: body=%s", label, string(raw.Body))
	}
}

func TestT1_F02_DomainErrorResponsesFollowOpenAPISchema(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// (a) 401 Unauthenticated
	_, raw401, err := env.Client("").CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "main"},
	})
	if err != nil {
		t.Fatalf("unauth CreateWorkspace: %v", err)
	}
	raw401.RequireStatus(t, http.StatusUnauthorized)
	m2AssertOpenAPIErrorEnvelope(t, raw401, "401")

	// (b) 400 Missing Idempotency-Key
	_, raw400, err := env.Client(humanTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "main"},
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("no-idem CreateWorkspace: %v", err)
	}
	raw400.RequireStatus(t, http.StatusBadRequest)
	m2AssertOpenAPIErrorEnvelope(t, raw400, "400")

	// (c) 404 Not Found
	_, raw404, err := env.Client(humanTok).GetWorkspace(ctx, harness.NewTestUUIDv7())
	if err != nil {
		t.Fatalf("missing GetWorkspace: %v", err)
	}
	raw404.RequireStatus(t, http.StatusNotFound)
	m2AssertOpenAPIErrorEnvelope(t, raw404, "404")
}

func TestT1_F02_CredentialSeparationAcrossAPIWorkerPublisher(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})

	if pushes := env.GitHub().PushAttempts(); len(pushes) != 0 {
		t.Fatalf("expected 0 push attempts during workspace ingress, got %+v", pushes)
	}
	apiAndWorkerLogs := env.Logs("api") + "\n" + env.Logs("worker")
	harness.AssertNoSecretOrEncodedLeak(t, apiAndWorkerLogs, env.GitHub().WriteAppPrivateKeyPEM(), env.GitHub().ReadAppPrivateKeyPEM())
	env.AssertNoSecretLeakInLogs()
}

// --- F-03: PostgreSQL 16+ schema, migrations & UUIDv7 IDs (Tier 1: 5 tests) ---

func TestT1_F03_AllCoreAndReconciledTablesMigrated(t *testing.T) {
	env := m2NewEnv(t)
	rows, err := env.DB().QueryRows(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
	if err != nil {
		t.Fatalf("QueryRows pg_tables: %v", err)
	}
	present := make(map[string]bool, len(rows))
	for _, row := range rows {
		if len(row) > 0 {
			present[row[0]] = true
		}
	}

	expectedTables := []string{
		"principals",
		"repositories",
		"workspaces",
		"artifacts",
		"proposals",
		"scan_runs",
		"findings",
		"model_assessments",
		"policy_bundles",
		"policy_decisions",
		"approvals",
		"publications",
		"operations",
		"audit_events",
		"outbox_events",
		"idempotency_keys",
		"approval_requirements",
		"publication_attempts",
		"audit_chain_head",
	}
	for _, tbl := range expectedTables {
		if !present[tbl] {
			t.Fatalf("expected migrated table %q not found in public schema (present=%v)", tbl, present)
		}
	}
}

func TestT1_F03_PostgreSQL17CleanMigrationAndUniqueConstraints(t *testing.T) {
	env := m2NewEnv(t)
	verRows, err := env.DB().QueryRows(`SELECT current_setting('server_version_num')::int`)
	if err != nil {
		t.Fatalf("query server_version_num: %v", err)
	}
	if len(verRows) != 1 || len(verRows[0]) != 1 {
		t.Fatalf("unexpected server_version_num rows: %v", verRows)
	}
	var verNum int
	if _, err := fmt.Sscanf(verRows[0][0], "%d", &verNum); err != nil || verNum < 160000 {
		t.Fatalf("expected PostgreSQL >= 160000, got %q (err=%v)", verRows[0][0], err)
	}

	migRows, err := env.DB().QueryRows(`SELECT version, dirty FROM schema_migrations ORDER BY version DESC LIMIT 1`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if len(migRows) == 0 || migRows[0][1] != "f" {
		t.Fatalf("expected clean non-dirty migration, got %v", migRows)
	}

	constraintQuery := `
		SELECT c.relname, con.contype, array_to_string(array_agg(a.attname ORDER BY u.ord), ',')
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = u.attnum
		WHERE n.nspname = 'public' AND con.contype = 'u'
		  AND c.relname IN ('publications', 'policy_bundles', 'audit_events')
		GROUP BY c.relname, con.conname, con.contype
		ORDER BY c.relname`
	conRows, err := env.DB().QueryRows(constraintQuery)
	if err != nil {
		t.Fatalf("query pg_constraint: %v", err)
	}
	found := make(map[string]bool)
	for _, r := range conRows {
		if len(r) == 3 {
			found[r[0]+":"+r[2]] = true
		}
	}
	for _, want := range []string{
		"publications:proposal_id",
		"policy_bundles:digest",
		"audit_events:chain_seq",
		"audit_events:event_hash",
	} {
		if !found[want] {
			t.Fatalf("missing expected unique constraint %q (found=%v)", want, found)
		}
	}
}

func TestT1_F03_UUIDv7FormatAndMonotonicOrdering(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	wsIDs := make([]string, 0, 3)
	opIDs := make([]string, 0, 3)
	var firstWS harness.WorkspaceResp
	for i := 0; i < 3; i++ {
		cResp, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
			Repository: harness.WorkspaceRepoRef{
				Provider:     "github",
				RepositoryID: repo.GitHubRepoID,
				Ref:          "refs/heads/main",
			},
		})
		wsIDs = append(wsIDs, m2ResolveWorkspaceID(ws))
		opIDs = append(opIDs, cResp.OperationID)
		if i == 0 {
			firstWS = ws
		}
		time.Sleep(5 * time.Millisecond)
	}
	harness.AssertUUIDv7Monotonic(t, wsIDs)
	harness.AssertUUIDv7Monotonic(t, opIDs)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() { _ = 1 }\n")},
	})
	prop, propOp := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(firstWS), firstWS.Generation, gz, "uuidv7-order", nil)
	harness.AssertUUIDv7(t, m2ResolveProposalID(prop))
	harness.AssertUUIDv7(t, propOp.ID)
}

func TestT1_F03_PersistedStateSurvivesAPIRestart(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# updated\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "survive-restart", nil)
	propID := m2ResolveProposalID(prop)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	beforeDiff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposalDiff before restart: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	if err := env.StopAPI(); err != nil {
		t.Fatalf("StopAPI: %v", err)
	}
	if err := env.RestartAPI(); err != nil {
		t.Fatalf("RestartAPI: %v", err)
	}

	wsAfter, wsRaw, err := env.Client(humanTok).GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace after restart: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusOK)
	if wsAfter.BaseCommit != ws.BaseCommit || wsAfter.Status != "READY" {
		t.Fatalf("workspace mismatch after restart: got %+v, want BaseCommit=%s READY", wsAfter, ws.BaseCommit)
	}

	propAfter, propRaw, err := env.Client(humanTok).GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal after restart: %v", err)
	}
	propRaw.RequireStatus(t, http.StatusOK)
	if propAfter.Version != prop.Version || propAfter.PublicationManifestDigest != prop.PublicationManifestDigest {
		t.Fatalf("proposal mismatch after restart: got %+v, want %+v", propAfter, prop)
	}

	afterDiff, diffRaw, err := env.Client(humanTok).GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposalDiff after restart: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	if afterDiff.TreeDigest != beforeDiff.TreeDigest || afterDiff.DiffDigest != beforeDiff.DiffDigest ||
		afterDiff.PublicationManifestDigest != beforeDiff.PublicationManifestDigest {
		t.Fatalf("diff mismatch after restart: got %+v, want %+v", afterDiff, beforeDiff)
	}
}

func TestT1_F03_ArtifactDigestAndStorageMetadataPersisted(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	desc, raw, err := env.Client(ctrlTok).GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	harness.AssertUUIDv7(t, desc.Artifact.ArtifactID)
	if !m2IsLowerHexLen(desc.Artifact.SHA256, 64) {
		t.Fatalf("invalid artifact sha256 %q", desc.Artifact.SHA256)
	}

	obj, err := env.Snapshots().FindBySHA256(desc.Artifact.SHA256)
	if err != nil {
		t.Fatalf("FindBySHA256(%s): %v", desc.Artifact.SHA256, err)
	}
	objBytes, err := env.Snapshots().ReadBytes(*obj)
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if got := harness.SHA256Hex(objBytes); got != desc.Artifact.SHA256 {
		t.Fatalf("stored file sha256 = %s, want %s", got, desc.Artifact.SHA256)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT id::text, sha256, storage_key, storage_generation, size_bytes::text
		 FROM artifacts WHERE id = %s::uuid`,
		m2SQLLiteral(desc.Artifact.ArtifactID),
	))
	if err != nil {
		t.Fatalf("query artifacts row: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 artifacts row for %s, got %d", desc.Artifact.ArtifactID, len(rows))
	}
	if rows[0][1] != desc.Artifact.SHA256 {
		t.Fatalf("DB sha256=%q != API %q", rows[0][1], desc.Artifact.SHA256)
	}
	if desc.Artifact.StorageKey != "" && rows[0][2] != desc.Artifact.StorageKey {
		t.Fatalf("DB storage_key=%q != API %q", rows[0][2], desc.Artifact.StorageKey)
	}
	if desc.Artifact.StorageGeneration != "" && rows[0][3] != desc.Artifact.StorageGeneration {
		t.Fatalf("DB storage_generation=%q != API %q", rows[0][3], desc.Artifact.StorageGeneration)
	}
}

// --- F-04: Transactional outbox & leased operations (Tier 1: 5 tests) ---

func TestT1_F04_WorkspaceCreateReturns202AndCompletesOperation(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	client := env.Client(humanTok)
	cResp, raw, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)
	harness.AssertUUIDv7(t, wsID)
	harness.AssertUUIDv7(t, cResp.OperationID)

	op, err := client.WaitForOperation(ctx, cResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("operation status = %q (want SUCCEEDED), err=%s", op.Status, op.LastError)
	}
	if op.OperationType != "WORKSPACE_INGRESS" {
		t.Fatalf("operation_type = %q (want WORKSPACE_INGRESS)", op.OperationType)
	}
	if op.ResourceID != wsID {
		t.Fatalf("operation resource_id = %q (want %q)", op.ResourceID, wsID)
	}
	if op.Attempts < 1 {
		t.Fatalf("expected operation attempts >= 1, got %d", op.Attempts)
	}
}

func TestT1_F04_ProposalSubmitEnqueuesReconstructOperation(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	wsID := m2ResolveWorkspaceID(ws)
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "feature.txt", Body: []byte("new feature\n")},
	})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "reconstruct-op-test",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	propID := m2ResolveProposalID(subResp)
	harness.AssertUUIDv7(t, propID)
	harness.AssertUUIDv7(t, subResp.OperationID)

	op, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("op status = %q (want SUCCEEDED), last_error=%s", op.Status, op.LastError)
	}
	if op.OperationType != "PROPOSAL_RECONSTRUCT" {
		t.Fatalf("operation_type = %q (want PROPOSAL_RECONSTRUCT)", op.OperationType)
	}
	if op.ResourceID != propID {
		t.Fatalf("operation resource_id = %q (want %q)", op.ResourceID, propID)
	}
}

func TestT1_F04_TransactionalOutboxAtomicWithWorkspaceCreate(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	client := env.Client(humanTok)
	cResp, raw, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)

	wsRows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT id::text, status FROM workspaces WHERE id = %s::uuid`, m2SQLLiteral(wsID)))
	if err != nil || len(wsRows) != 1 {
		t.Fatalf("expected atomic workspace row for %s, got rows=%v err=%v", wsID, wsRows, err)
	}
	opRows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT id::text, status FROM operations WHERE id = %s::uuid`, m2SQLLiteral(cResp.OperationID)))
	if err != nil || len(opRows) != 1 || opRows[0][1] != "PENDING" {
		t.Fatalf("expected atomic PENDING operation row for %s, got rows=%v err=%v", cResp.OperationID, opRows, err)
	}
	outboxRows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT id::text, delivered_at IS NOT NULL FROM outbox_events WHERE aggregate_id = %s::uuid`, m2SQLLiteral(wsID)))
	if err != nil || len(outboxRows) == 0 {
		t.Fatalf("expected atomic outbox_events row for workspace %s, got rows=%v err=%v", wsID, outboxRows, err)
	}

	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	op, err := client.WaitForOperation(ctx, cResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation after RestartWorker: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED after worker restart, got %q", op.Status)
	}
	deliveredRows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT count(*) FROM outbox_events WHERE aggregate_id = %s::uuid AND delivered_at IS NOT NULL`, m2SQLLiteral(wsID)))
	if err != nil || len(deliveredRows) != 1 || deliveredRows[0][0] == "0" {
		t.Fatalf("expected outbox_events.delivered_at populated after worker completion, got %v err=%v", deliveredRows, err)
	}
}

func TestT1_F04_OperationReadableByOwnerAndController(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	cResp, _ := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ownerOp, ownerRaw, err := env.Client(humanTok).GetOperation(ctx, cResp.OperationID)
	if err != nil {
		t.Fatalf("owner GetOperation: %v", err)
	}
	ownerRaw.RequireStatus(t, http.StatusOK)

	ctrlOp, ctrlRaw, err := env.Client(ctrlTok).GetOperation(ctx, cResp.OperationID)
	if err != nil {
		t.Fatalf("controller GetOperation: %v", err)
	}
	ctrlRaw.RequireStatus(t, http.StatusOK)

	if ownerOp.ID != ctrlOp.ID || ownerOp.OperationType != ctrlOp.OperationType || ownerOp.ResourceID != ctrlOp.ResourceID {
		t.Fatalf("operation mismatch between owner (%+v) and controller (%+v)", ownerOp, ctrlOp)
	}
}

func TestT1_F04_ConcurrentOperationsProcessedWithoutDuplicates(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})

	const n = 5
	type createResult struct {
		wsID string
		opID string
		err  error
	}
	results := make([]createResult, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			c := env.Client(humanTok)
			resp, raw, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
				Repository: harness.WorkspaceRepoRef{
					Provider:     "github",
					RepositoryID: repo.GitHubRepoID,
					Ref:          "refs/heads/main",
				},
			})
			if err != nil {
				results[idx] = createResult{err: err}
				return
			}
			if raw.StatusCode != http.StatusAccepted {
				results[idx] = createResult{err: fmt.Errorf("status %d: %s", raw.StatusCode, string(raw.Body))}
				return
			}
			op, err := c.WaitForOperation(ctx, resp.OperationID, 30*time.Second)
			if err != nil {
				results[idx] = createResult{err: err}
				return
			}
			if op.Status != "SUCCEEDED" {
				results[idx] = createResult{err: fmt.Errorf("op %s status %s", op.ID, op.Status)}
				return
			}
			results[idx] = createResult{wsID: m2ResolveCreatedWorkspaceID(resp), opID: resp.OperationID}
		}(i)
	}
	wg.Wait()

	seenWS := make(map[string]bool, n)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := env.Client(humanTok)
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("goroutine %d failed: %v", i, r.err)
		}
		if seenWS[r.wsID] {
			t.Fatalf("duplicate workspace ID %s returned", r.wsID)
		}
		seenWS[r.wsID] = true
		ws, raw, err := client.GetWorkspace(ctx, r.wsID)
		if err != nil {
			t.Fatalf("GetWorkspace(%s): %v", r.wsID, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		if ws.Status != "READY" {
			t.Fatalf("workspace %s status=%s (want READY)", r.wsID, ws.Status)
		}
	}
}

// --- F-05: Hash-chained audit_events & query API (Tier 1: 5 tests) ---

func TestT1_F05_AuditEventsFormValidGenesisHashChain(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() { _ = 2 }\n")},
	})
	m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "audit-genesis", nil)

	events := m2SortAuditEventsAscending(m2FetchAllAuditEvents(t, env.Client(audTok)))
	if len(events) < 2 {
		t.Fatalf("expected >= 2 audit events, got %d", len(events))
	}
	harness.VerifyFullAuditHashChainFromGenesis(t, events)
	for _, ev := range events {
		harness.AssertUUIDv7(t, ev.ID)
	}
}

func TestT1_F05_AuditFilterByResourceTypeAndResourceID(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	_, ws1 := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	ws1ID := m2ResolveWorkspaceID(ws1)
	m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop1, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, ws1ID, ws1.Generation, gz, "filter-resource", nil)
	prop1ID := m2ResolveProposalID(prop1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	audClient := env.Client(audTok)

	wsEvents, raw1, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{
		ResourceType: "workspace",
		ResourceID:   ws1ID,
		Limit:        100,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(workspace): %v", err)
	}
	raw1.RequireStatus(t, http.StatusOK)
	if len(wsEvents.Events) == 0 {
		t.Fatalf("expected >= 1 audit event for workspace %s", ws1ID)
	}
	for _, ev := range wsEvents.Events {
		if ev.ResourceType != "workspace" || ev.ResourceID != ws1ID {
			t.Fatalf("filtered workspace audit event mismatch: %+v", ev)
		}
		if !m2IsLowerHexLen(ev.EventHash, 64) {
			t.Fatalf("invalid event_hash %q", ev.EventHash)
		}
	}

	propEvents, raw2, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{
		ResourceType: "proposal",
		ResourceID:   prop1ID,
		Limit:        100,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(proposal): %v", err)
	}
	raw2.RequireStatus(t, http.StatusOK)
	if len(propEvents.Events) == 0 {
		t.Fatalf("expected >= 1 audit event for proposal %s", prop1ID)
	}
	for _, ev := range propEvents.Events {
		if ev.ResourceType != "proposal" || ev.ResourceID != prop1ID {
			t.Fatalf("filtered proposal audit event mismatch: %+v", ev)
		}
		if !m2IsLowerHexLen(ev.EventHash, 64) {
			t.Fatalf("invalid event_hash %q", ev.EventHash)
		}
	}
}

func TestT1_F05_AuditFilterByEventTypeActorAndTimeWindow(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	tokA := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "actor-a", Email: "a@example.com", Name: "Actor A"})
	tokB := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "actor-b", Email: "b@example.com", Name: "Actor B"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	m2CreateReadyWorkspace(t, env, tokA, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	_, wsBPre := m2CreateReadyWorkspace(t, env, tokB, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsBPreID := m2ResolveWorkspaceID(wsBPre)

	time.Sleep(50 * time.Millisecond)

	_, wsBPost := m2CreateReadyWorkspace(t, env, tokB, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsBPostID := m2ResolveWorkspaceID(wsBPost)
	actorBID := wsBPost.Owner.PrincipalID
	harness.AssertUUIDv7(t, actorBID)
	if wsBPre.Owner.PrincipalID != actorBID {
		t.Fatalf("expected same principal_id for actor-b across workspaces: pre=%q post=%q", wsBPre.Owner.PrincipalID, actorBID)
	}

	audClient := env.Client(audTok)
	all := m2SortAuditEventsAscending(m2FetchAllAuditEvents(t, audClient))
	harness.VerifyFullAuditHashChainFromGenesis(t, all)

	preByType := make(map[string]harness.AuditEvent)
	for _, ev := range all {
		if ev.ActorID == actorBID && ev.ResourceID == wsBPreID {
			if _, exists := preByType[ev.EventType]; !exists {
				preByType[ev.EventType] = ev
			}
		}
	}

	var targetEventType string
	var evPre, evPost harness.AuditEvent
	for _, ev := range all {
		if ev.ActorID == actorBID && ev.ResourceID == wsBPostID {
			if pre, ok := preByType[ev.EventType]; ok {
				targetEventType = ev.EventType
				evPre = pre
				evPost = ev
				break
			}
		}
	}
	if targetEventType == "" {
		t.Fatalf("no shared audit event type recorded for actor B %s across pre=%s and post=%s", actorBID, wsBPreID, wsBPostID)
	}
	if !evPre.CreatedAt.Before(evPost.CreatedAt) {
		t.Fatalf("expected pre event (%s) created_at < post event (%s)", evPre.CreatedAt, evPost.CreatedAt)
	}
	tMid := evPre.CreatedAt.Add(evPost.CreatedAt.Sub(evPre.CreatedAt) / 2)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Verify Since=tMid returns wsBPost's event and excludes wsBPre's event.
	sinceResp, sinceRaw, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{
		ActorID:   actorBID,
		EventType: targetEventType,
		Since:     tMid.Format(time.RFC3339Nano),
		Limit:     100,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(since): %v", err)
	}
	sinceRaw.RequireStatus(t, http.StatusOK)
	if len(sinceResp.Events) == 0 {
		t.Fatalf("expected >= 1 event after since=%s for actor=%s event_type=%s", tMid, actorBID, targetEventType)
	}
	sawPost := false
	for _, ev := range sinceResp.Events {
		if ev.ActorID != actorBID {
			t.Fatalf("since filter actor_id = %q (want %q)", ev.ActorID, actorBID)
		}
		if ev.EventType != targetEventType {
			t.Fatalf("since filter event_type = %q (want %q)", ev.EventType, targetEventType)
		}
		if ev.CreatedAt.Before(tMid) {
			t.Fatalf("since filter returned event created_at %s before since %s", ev.CreatedAt, tMid)
		}
		if ev.ResourceID == wsBPreID {
			t.Fatalf("since=%s unexpectedly included pre-cutoff workspace %s event %s", tMid, wsBPreID, ev.ID)
		}
		if ev.ResourceID == wsBPostID {
			sawPost = true
		}
	}
	if !sawPost {
		t.Fatalf("since=%s missing post-cutoff workspace %s event", tMid, wsBPostID)
	}

	// Verify Until=tMid returns wsBPre's event and excludes wsBPost's event.
	untilResp, untilRaw, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{
		ActorID:   actorBID,
		EventType: targetEventType,
		Until:     tMid.Format(time.RFC3339Nano),
		Limit:     100,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(until): %v", err)
	}
	untilRaw.RequireStatus(t, http.StatusOK)
	if len(untilResp.Events) == 0 {
		t.Fatalf("expected >= 1 event before until=%s for actor=%s event_type=%s", tMid, actorBID, targetEventType)
	}
	sawPre := false
	for _, ev := range untilResp.Events {
		if ev.ActorID != actorBID {
			t.Fatalf("until filter actor_id = %q (want %q)", ev.ActorID, actorBID)
		}
		if ev.EventType != targetEventType {
			t.Fatalf("until filter event_type = %q (want %q)", ev.EventType, targetEventType)
		}
		if ev.CreatedAt.After(tMid) {
			t.Fatalf("until filter returned event created_at %s after until %s", ev.CreatedAt, tMid)
		}
		if ev.ResourceID == wsBPostID {
			t.Fatalf("until=%s unexpectedly included post-cutoff workspace %s event %s", tMid, wsBPostID, ev.ID)
		}
		if ev.ResourceID == wsBPreID {
			sawPre = true
		}
	}
	if !sawPre {
		t.Fatalf("until=%s missing pre-cutoff workspace %s event", tMid, wsBPreID)
	}
}

func TestT1_F05_AuditCursorPaginationCompleteAndDisjoint(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})

	for i := 0; i < 3; i++ {
		_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
			Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		})
		gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
			{Name: "README.md", Body: []byte(fmt.Sprintf("# edit %d\n", i))},
			{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		})
		m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, fmt.Sprintf("page-%d", i), nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	audClient := env.Client(audTok)

	fullPage, fullRaw, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatalf("ListAuditEvents(limit=500): %v", err)
	}
	fullRaw.RequireStatus(t, http.StatusOK)
	if len(fullPage.Events) < 6 {
		t.Fatalf("expected >= 6 audit events, got %d", len(fullPage.Events))
	}

	var paged []harness.AuditEvent
	seen := make(map[string]bool)
	cursor := ""
	for i := 0; i < 200; i++ {
		resp, raw, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListAuditEvents(limit=2, cursor=%q): %v", cursor, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		for _, ev := range resp.Events {
			if seen[ev.ID] {
				t.Fatalf("duplicate event ID %s across cursor pagination", ev.ID)
			}
			seen[ev.ID] = true
			paged = append(paged, ev)
		}
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}

	if len(paged) != len(fullPage.Events) {
		t.Fatalf("paginated count %d != full count %d", len(paged), len(fullPage.Events))
	}
	for _, ev := range fullPage.Events {
		if !seen[ev.ID] {
			t.Fatalf("event %s missing from paginated output", ev.ID)
		}
	}
	harness.VerifyFullAuditHashChainFromGenesis(t, m2SortAuditEventsAscending(paged))
}

func TestT1_F05_AuditPayloadsContainIDsAndDigestsNoSecrets(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})
	env.RegisterSecret(humanTok)
	env.RegisterSecret(ctrlTok)
	env.RegisterSecret(audTok)

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# clean\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "no-secret-audit", nil)

	events := m2FetchAllAuditEvents(t, env.Client(audTok))
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	harness.AssertNoSecretOrEncodedLeak(t, string(encoded),
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
		humanTok,
		ctrlTok,
		audTok,
	)
	env.AssertNoSecretLeakInLogs(humanTok, ctrlTok, audTok)
}

// --- F-06: OIDC / workload identity & human owner resolution (Tier 1: 5 tests) ---

func TestT1_F06_HumanOIDCBindsAccountableOwnerAtCreation(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	aliceTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "alice-1",
		Email:   "alice@example.com",
		Name:    "Alice Dev",
	})

	_, ws := m2CreateReadyWorkspace(t, env, aliceTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if ws.Owner == nil {
		t.Fatalf("expected non-nil Workspace.Owner")
	}
	harness.AssertUUIDv7(t, ws.Owner.PrincipalID)
	if ws.Owner.IdentityProvider != env.OIDC().Issuer() {
		t.Fatalf("owner.identity_provider = %q (want %q)", ws.Owner.IdentityProvider, env.OIDC().Issuer())
	}
	if ws.Agent != nil {
		t.Fatalf("expected nil Workspace.Agent when not supplied, got %+v", ws.Agent)
	}
}

func TestT1_F06_AgentProvenanceRecordedSeparatelyFromOwner(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "owner-agent-test", Email: "owner@example.com"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		Agent: &harness.WorkspaceAgentInfo{
			Type:       "coding-agent",
			SessionID:  "sess-abc",
			ModelRoute: m2DefaultModelRoute,
		},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# agent assisted\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "agent-provenance", &harness.Provenance{
		Type:          "agent_assisted",
		CaptureMethod: "frozen_filesystem",
	})

	if prop.Owner == nil || ws.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("proposal owner (%+v) != workspace owner (%+v)", prop.Owner, ws.Owner)
	}
	if prop.Origin == nil {
		t.Fatalf("expected Proposal.Origin populated")
	}
	if prop.Origin.AgentID == "" || prop.Origin.AgentID == prop.Owner.PrincipalID {
		t.Fatalf("expected distinct non-empty Origin.AgentID, got %q (owner=%q)", prop.Origin.AgentID, prop.Owner.PrincipalID)
	}
	if prop.Origin.AgentSessionID != "sess-abc" {
		t.Fatalf("Origin.AgentSessionID = %q (want sess-abc)", prop.Origin.AgentSessionID)
	}
	if prop.Origin.ModelRoute != m2DefaultModelRoute {
		t.Fatalf("Origin.ModelRoute = %q (want %q)", prop.Origin.ModelRoute, m2DefaultModelRoute)
	}
	if prop.Provenance == nil || prop.Provenance.Type != "agent_assisted" {
		t.Fatalf("expected Provenance.Type = agent_assisted, got %+v", prop.Provenance)
	}
}

func TestT1_F06_HumanAuthoredProvenanceWithoutAgent(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "human-author-1", Email: "ha1@example.com"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# human authored\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "human-authored", &harness.Provenance{
		Type:          "human_authored",
		CaptureMethod: "frozen_filesystem",
	})

	if prop.Provenance == nil || prop.Provenance.Type != "human_authored" {
		t.Fatalf("expected human_authored provenance, got %+v", prop.Provenance)
	}
	if prop.Origin != nil && prop.Origin.AgentID != "" {
		t.Fatalf("expected empty AgentID for human-authored workspace, got %q", prop.Origin.AgentID)
	}
	if prop.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("expected proposal owner %+v to match workspace owner %+v", prop.Owner, ws.Owner)
	}
}

func TestT1_F06_ControllerWorkloadTokenAuthorizedForCaptureOnly(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "human-owner-99", Email: "h99@example.com"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	srcDesc, srcRaw, err := ctrlClient.GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource: %v", err)
	}
	srcRaw.RequireStatus(t, http.StatusOK)
	if srcDesc.WorkspaceID != wsID {
		t.Fatalf("SourceDescriptor.WorkspaceID = %q (want %q)", srcDesc.WorkspaceID, wsID)
	}

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# ctrl capture\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "ctrl-capture", nil)

	if prop.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("expected proposal owner %+v to remain human creator %+v", prop.Owner, ws.Owner)
	}
}

func TestT1_F06_RepeatedOIDCLoginsResolveSamePrincipalUUID(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	tok1 := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-stable", Email: "alice-stable@example.com", Name: "Alice"})
	tok2 := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-stable", Email: "alice-stable@example.com", Name: "Alice"})

	c1, _ := m2CreateReadyWorkspace(t, env, tok1, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	c2, _ := m2CreateReadyWorkspace(t, env, tok2, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if c1.OwnerID == "" || c1.OwnerID != c2.OwnerID {
		t.Fatalf("expected identical principal UUID across repeated OIDC logins: %q vs %q", c1.OwnerID, c2.OwnerID)
	}
}
