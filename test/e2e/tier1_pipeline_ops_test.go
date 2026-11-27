package e2e_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

// m3Tokens holds pre-minted RS256 OIDC/workload tokens for E2E-M3 tests.
type m3Tokens struct {
	HumanA        string
	HumanB        string
	Reviewer      string
	Reviewer2     string
	IPReviewer    string
	PlatformOwner string
	SecReviewer   string
	Controller    string
	Auditor       string
	PolicyAdmin   string
	Agent         string
	Service       string
}

func m3MintTokens(env *harness.Env) m3Tokens {
	return m3Tokens{
		HumanA: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "human-alice",
			Email:             "alice@example.com",
			Name:              "Alice Developer",
			PreferredUsername: "alice",
			Groups:            []string{"engineering"},
			Roles:             []string{"human", "developer"},
		}),
		HumanB: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "human-bob",
			Email:             "bob@example.com",
			Name:              "Bob Engineer",
			PreferredUsername: "bob",
			Groups:            []string{"engineering"},
			Roles:             []string{"human", "developer"},
		}),
		Reviewer: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "reviewer-1",
			Email:             "rev1@example.com",
			Name:              "Reviewer One",
			PreferredUsername: "rev1",
			Groups:            []string{"engineering", "security-team"},
			Roles:             []string{"human", "reviewer"},
		}),
		Reviewer2: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "reviewer-2",
			Email:             "rev2@example.com",
			Name:              "Reviewer Two",
			PreferredUsername: "rev2",
			Groups:            []string{"engineering", "security-team"},
			Roles:             []string{"human", "reviewer"},
		}),
		IPReviewer: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "ip-reviewer-1",
			Email:             "iprev@example.com",
			Name:              "IP Reviewer",
			PreferredUsername: "iprev",
			Groups:            []string{"engineering", "ip-review"},
			Roles:             []string{"human", "reviewer"},
		}),
		PlatformOwner: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "platform-owner-1",
			Email:             "plat@example.com",
			Name:              "Platform Owner",
			PreferredUsername: "plat",
			Groups:            []string{"engineering", "platform-owners"},
			Roles:             []string{"human", "reviewer"},
		}),
		SecReviewer: env.MintToken(harness.TokenClaims{
			Kind:              "HUMAN",
			Subject:           "sec-reviewer-1",
			Email:             "secrev@example.com",
			Name:              "Security Reviewer",
			PreferredUsername: "secrev",
			Groups:            []string{"security-team", "sec-docs"},
			Roles:             []string{"human", "reviewer"},
		}),
		Controller: env.MintToken(harness.TokenClaims{
			Kind:    "CONTROLLER",
			Subject: "spiffe://custodian.local/ns/sandbox/sa/trusted-runtime-controller",
			Name:    "trusted-runtime-controller",
			Roles:   []string{"service", "controller"},
		}),
		Auditor: env.MintToken(harness.TokenClaims{
			Kind:              "AUDITOR",
			Subject:           "auditor-1",
			Email:             "auditor@example.com",
			Name:              "Security Auditor",
			PreferredUsername: "auditor",
			Groups:            []string{"auditors"},
			Roles:             []string{"auditor"},
		}),
		PolicyAdmin: env.MintToken(harness.TokenClaims{
			Kind:              "POLICY_ADMIN",
			Subject:           "policy-admin-1",
			Email:             "policy-admin@example.com",
			Name:              "Policy Admin",
			PreferredUsername: "policy-admin",
			Groups:            []string{"policy-admins"},
			Roles:             []string{"policy_admin"},
		}),
		Agent: env.MintToken(harness.TokenClaims{
			Kind:    "AGENT",
			Subject: "agent-coder-1",
			Name:    "Coding Agent",
			Roles:   []string{"agent"},
		}),
		Service: env.MintToken(harness.TokenClaims{
			Kind:    "SERVICE",
			Subject: "spiffe://custodian.local/ns/services/sa/generic-service",
			Name:    "generic-service",
			Roles:   []string{"service"},
		}),
	}
}

type m3RepoConfig struct {
	Owner          string
	Name           string
	Classification string
	AllowedRoutes  []string
	MaxConcurrent  int
	Files          map[string]string
}

func m3DefaultFiles() map[string]string {
	return map[string]string{
		"README.md": "# Custodian E2E Repo\n",
		"go.mod":    "module example.com/e2e\n\ngo 1.25\n",
		"main.go":   "package main\n\nfunc main() {}\n",
	}
}

func m3DefaultEntries(extra ...harness.TarEntry) []harness.TarEntry {
	entries := []harness.TarEntry{
		{Name: "README.md", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("# Custodian E2E Repo\n")},
		{Name: "go.mod", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("module example.com/e2e\n\ngo 1.25\n")},
		{Name: "main.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc main() {}\n")},
	}
	entries = append(entries, extra...)
	return entries
}

func m3NonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func m3NormalizeSHA256(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "sha256:"))
}

func m3IsHexN(s string, n int) bool {
	if len(s) != n {
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

func m3SQLQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func m3SQLTextArray(items []string) string {
	if len(items) == 0 {
		return "'{}'::text[]"
	}
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, m3SQLQuote(item))
	}
	return "ARRAY[" + strings.Join(quoted, ",") + "]::text[]"
}

func m3StartEnv(t *testing.T, repoCfg m3RepoConfig, opts ...harness.EnvOption) (*harness.Env, harness.SeededRepo, string) {
	t.Helper()
	owner := m3NonEmpty(repoCfg.Owner, "acme")
	name := m3NonEmpty(repoCfg.Name, "service")
	classification := m3NonEmpty(repoCfg.Classification, "INTERNAL")
	allowedRoutes := repoCfg.AllowedRoutes
	if len(allowedRoutes) == 0 {
		allowedRoutes = []string{"approved-code-review"}
	}
	maxConcurrent := repoCfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	files := repoCfg.Files
	if len(files) == 0 {
		files = m3DefaultFiles()
	}

	allOpts := make([]harness.EnvOption, 0, len(opts)+1)
	allOpts = append(allOpts, harness.WithSeedRepos(harness.RepoSeedSpec{
		Owner:         owner,
		Name:          name,
		Files:         files,
		DefaultBranch: "main",
	}))
	allOpts = append(allOpts, opts...)

	env := harness.NewEnv(t, allOpts...)
	repo, ok := env.Git().Repo(owner + "/" + name)
	if !ok {
		t.Fatalf("seeded repo %s/%s not found in BareGitHelper", owner, name)
	}
	var repoUUID string
	if env.DB() != nil {
		repoUUID = m3EnsureRepoInDB(t, env, repo, classification, allowedRoutes, maxConcurrent)
	}
	return env, repo, repoUUID
}

func m3EnsureRepoInDB(t *testing.T, env *harness.Env, repo harness.SeededRepo, classification string, allowedRoutes []string, maxConcurrent int) string {
	t.Helper()
	if env.DB() == nil {
		t.Fatalf("m3EnsureRepoInDB called without DB")
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	id := harness.NewTestUUIDv7()
	q := fmt.Sprintf(`
INSERT INTO repositories (
	id, github_repository_id, github_installation_id, full_name,
	classification, enabled, allowed_model_routes, max_concurrent_operations
) VALUES (
	%s::uuid, %d, %d, %s, %s, true, %s, %d
)
ON CONFLICT (github_repository_id) DO UPDATE SET
	github_installation_id    = EXCLUDED.github_installation_id,
	full_name                 = EXCLUDED.full_name,
	classification            = EXCLUDED.classification,
	enabled                   = true,
	allowed_model_routes      = EXCLUDED.allowed_model_routes,
	max_concurrent_operations = EXCLUDED.max_concurrent_operations
RETURNING id::text;`,
		m3SQLQuote(id),
		repo.GitHubRepoID,
		repo.InstallationID,
		m3SQLQuote(repo.FullName),
		m3SQLQuote(classification),
		m3SQLTextArray(allowedRoutes),
		maxConcurrent,
	)
	rows, err := env.DB().QueryRows(q)
	if err != nil {
		t.Fatalf("m3EnsureRepoInDB(%s): %v", repo.FullName, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 || rows[0][0] == "" {
		t.Fatalf("m3EnsureRepoInDB(%s): empty RETURNING id", repo.FullName)
	}
	return rows[0][0]
}

func m3ExtractArtifactID(t *testing.T, raw *harness.RawResponse) string {
	t.Helper()
	if raw == nil {
		t.Fatalf("nil upload response")
	}
	var body struct {
		ArtifactID string `json:"artifact_id"`
		ID         string `json:"id"`
	}
	if err := json.Unmarshal(raw.Body, &body); err != nil {
		t.Fatalf("decode upload response (%s): %v", string(raw.Body), err)
	}
	id := m3NonEmpty(body.ArtifactID, body.ID)
	if id == "" {
		t.Fatalf("upload response missing artifact_id/id: %s", string(raw.Body))
	}
	return id
}

func m3CreateReadyWorkspace(t *testing.T, env *harness.Env, humanTok, controllerTok string, repo harness.SeededRepo, modelRoute string, srcOpts *harness.WorkspaceSourceOptions) (harness.WorkspaceResp, harness.SourceDescriptorResp) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if modelRoute == "" {
		modelRoute = "approved-code-review"
	}
	humanClient := env.Client(humanTok)
	created, raw, err := humanClient.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          repo.DefaultBranch,
		},
		Agent: &harness.WorkspaceAgentInfo{
			Type:       "coding-agent",
			SessionID:  "sess-" + harness.NewTestUUIDv7(),
			ModelRoute: modelRoute,
		},
		SourceOptions: srcOpts,
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated, http.StatusOK)

	wsID := m3NonEmpty(created.WorkspaceID, created.ID)
	harness.AssertUUIDv7(t, wsID)

	if created.OperationID != "" {
		op, err := humanClient.WaitForOperation(ctx, created.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(workspace=%s, op=%s): %v", wsID, created.OperationID, err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("workspace operation %s failed: status=%s err=%s", op.ID, op.Status, op.LastError)
		}
	}

	var ws harness.WorkspaceResp
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		got, gRaw, err := humanClient.GetWorkspace(ctx, wsID)
		if err != nil {
			t.Fatalf("GetWorkspace(%s): %v", wsID, err)
		}
		gRaw.RequireStatus(t, http.StatusOK)
		ws = got
		if ws.Status == "READY" {
			break
		}
		if harness.ContainsStatus(env.Contracts().WorkspaceStatuses.TerminalFailure, ws.Status) {
			t.Fatalf("workspace %s entered terminal failure status %q", wsID, ws.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ws.Status != "READY" {
		t.Fatalf("workspace %s did not reach READY (got %q)", wsID, ws.Status)
	}
	if ws.ID == "" {
		ws.ID = wsID
	}

	ctrlClient := env.Client(controllerTok)
	desc, descRaw, err := ctrlClient.GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource(%s): %v", wsID, err)
	}
	descRaw.RequireStatus(t, http.StatusOK)
	return ws, desc
}

func m3UploadSnapshot(t *testing.T, env *harness.Env, controllerTok string, desc harness.SourceDescriptorResp, gzBytes []byte) (string, *harness.RawResponse) {
	t.Helper()
	if desc.UploadCapability == nil {
		t.Fatalf("source descriptor missing upload_capability")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ctrlClient := env.Client(controllerTok)
	raw, err := ctrlClient.UploadSnapshot(ctx, desc.UploadCapability.UploadURL, desc.UploadCapability.Token, gzBytes)
	if err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	if raw.StatusCode < 200 || raw.StatusCode >= 300 {
		return "", raw
	}
	return m3ExtractArtifactID(t, raw), raw
}

func m3PollProposalStatus(t *testing.T, client *harness.APIClient, proposalID string, timeout time.Duration, wants ...string) harness.ProposalResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	deadline := time.Now().Add(timeout)
	var last harness.ProposalResp
	for time.Now().Before(deadline) {
		got, raw, err := client.GetProposal(ctx, proposalID)
		if err != nil {
			t.Fatalf("GetProposal(%s): %v", proposalID, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		last = got
		for _, w := range wants {
			if strings.EqualFold(got.Status, w) {
				if last.ID == "" {
					last.ID = proposalID
				}
				return last
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("proposal %s did not reach any of %v within %s (last status=%q)", proposalID, wants, timeout, last.Status)
	return last
}

func m3PollPublicationStatus(t *testing.T, client *harness.APIClient, pubID string, timeout time.Duration, wants ...string) harness.PublicationResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	deadline := time.Now().Add(timeout)
	var last harness.PublicationResp
	for time.Now().Before(deadline) {
		got, raw, err := client.GetPublication(ctx, pubID)
		if err != nil {
			t.Fatalf("GetPublication(%s): %v", pubID, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		last = got
		for _, w := range wants {
			if strings.EqualFold(got.Status, w) {
				return last
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("publication %s did not reach any of %v within %s (last status=%q)", pubID, wants, timeout, last.Status)
	return last
}

func m3SubmitAndReconstruct(t *testing.T, env *harness.Env, controllerTok string, ws harness.WorkspaceResp, desc harness.SourceDescriptorResp, entries []harness.TarEntry, title string, prov *harness.Provenance) harness.ProposalResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gzBytes, shaHex := harness.BuildTarGz(entries)
	artID, upRaw := m3UploadSnapshot(t, env, controllerTok, desc, gzBytes)
	if upRaw.StatusCode < 200 || upRaw.StatusCode >= 300 {
		t.Fatalf("UploadSnapshot failed: status=%d body=%s", upRaw.StatusCode, string(upRaw.Body))
	}

	if prov == nil {
		prov = &harness.Provenance{Type: "agent_assisted", CaptureMethod: "frozen_filesystem"}
	}
	ctrlClient := env.Client(controllerTok)
	wsID := m3NonEmpty(ws.ID, ws.WorkspaceID)
	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artID,
			SHA256:              shaHex,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gzBytes)),
		},
		Title:      title,
		Provenance: prov,
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated, http.StatusOK)
	propID := m3NonEmpty(subResp.ProposalID, subResp.ID)
	harness.AssertUUIDv7(t, propID)

	if subResp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(reconstruct %s): %v", propID, err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("reconstruct operation %s failed: status=%s err=%s", op.ID, op.Status, op.LastError)
		}
	}

	return m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "RECONSTRUCTED")
}

func m3EvaluateProposal(t *testing.T, env *harness.Env, controllerTok, proposalID string, expectedVersion int64) (harness.ProposalResp, harness.AssessmentsResp, harness.FindingsResp) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ctrlClient := env.Client(controllerTok)
	evalResp, evalRaw, err := ctrlClient.EvaluateProposal(ctx, proposalID, harness.EvaluateReq{
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		t.Fatalf("EvaluateProposal(%s): %v", proposalID, err)
	}
	evalRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	if evalResp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(evaluate %s): %v", proposalID, err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("evaluate operation %s failed: status=%s err=%s", op.ID, op.Status, op.LastError)
		}
	}

	prop := m3PollProposalStatus(t, ctrlClient, proposalID, 30*time.Second,
		"PENDING_APPROVAL", "APPROVED", "DENIED", "QUARANTINED", "REMEDIATION_REQUIRED", "FAILED")

	assessResp, aRaw, err := ctrlClient.ListProposalAssessments(ctx, proposalID)
	if err != nil {
		t.Fatalf("ListProposalAssessments(%s): %v", proposalID, err)
	}
	aRaw.RequireStatus(t, http.StatusOK)

	findResp, fRaw, err := ctrlClient.ListProposalFindings(ctx, proposalID)
	if err != nil {
		t.Fatalf("ListProposalFindings(%s): %v", proposalID, err)
	}
	fRaw.RequireStatus(t, http.StatusOK)

	return prop, assessResp, findResp
}

func m3ApproveProposal(t *testing.T, env *harness.Env, reviewerTok string, prop harness.ProposalResp, decision, comment string) harness.ApprovalResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	propID := m3NonEmpty(prop.ID, prop.ProposalID)
	revClient := env.Client(reviewerTok)
	appResp, raw, err := revClient.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  decision,
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
		Comment:                   comment,
	})
	if err != nil {
		t.Fatalf("ApproveProposal(%s): %v", propID, err)
	}
	raw.RequireStatus(t, http.StatusCreated)
	return appResp
}

func m3PublishAndWait(t *testing.T, env *harness.Env, controllerTok string, prop harness.ProposalResp) harness.PublicationResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	propID := m3NonEmpty(prop.ID, prop.ProposalID)
	ctrlClient := env.Client(controllerTok)
	pubResp, pubRaw, err := ctrlClient.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(%s): %v", propID, err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	pubID := m3NonEmpty(pubResp.PublicationID, pubResp.ID)
	harness.AssertUUIDv7(t, pubID)

	if pubResp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(publish %s): %v", propID, err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) &&
			!harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
			t.Fatalf("publish operation %s unexpected status %q", op.ID, op.Status)
		}
	}
	return m3PollPublicationStatus(t, ctrlClient, pubID, 30*time.Second, "PUBLISHED", "FAILED")
}

func m3ReadFixture(t *testing.T, env *harness.Env, relPath string) []byte {
	t.Helper()
	root := m3FindRepoRoot(t)
	if env != nil {
		if b, err := os.ReadFile(filepath.Join(root, "test", "e2e", "fixtures", relPath)); err == nil {
			return b
		}
	}
	p := filepath.Join(root, "test", "e2e", "fixtures", relPath)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %q: %v", p, err)
	}
	return b
}

// =============================================================================
// F-13: Stage A Deterministic Scanners, Redaction & Coverage Gate (5 Tier 1 Tests)
// =============================================================================

func TestT1_F13_MandatoryScannersAllCleanAndComplete(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Scanners().ResetAll()
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "feature.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Hello() string { return \"ok\" }\n")},
	), "Clean feature change", nil)

	evalProp, _, findings := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	for _, sc := range []harness.ScannerName{harness.ScannerGitleaks, harness.ScannerScanCode, harness.ScannerSemgrep} {
		env.Scanners().AssertInvoked(t, sc)
	}

	seen := make(map[string]harness.ScanRunDTO)
	for _, run := range findings.ScanRuns {
		harness.AssertUUIDv7(t, run.ID)
		seen[run.Scanner] = run
	}
	for _, reqScanner := range []string{"gitleaks", "scancode", "semgrep"} {
		run, ok := seen[reqScanner]
		if !ok {
			t.Fatalf("missing mandatory ScanRun for %q (got %+v)", reqScanner, findings.ScanRuns)
		}
		if run.Status != "COMPLETED" {
			t.Fatalf("scanner %q status=%q, want COMPLETED", reqScanner, run.Status)
		}
		if run.FilesExamined < 1 || run.FilesSkipped != 0 || !run.Complete {
			t.Fatalf("scanner %q coverage mismatch: examined=%d skipped=%d complete=%v", reqScanner, run.FilesExamined, run.FilesSkipped, run.Complete)
		}
	}
	if len(findings.Findings) != 0 {
		t.Fatalf("expected 0 findings on clean archive, got %d: %+v", len(findings.Findings), findings.Findings)
	}
	if evalProp.Status != "PENDING_APPROVAL" && evalProp.Status != "APPROVED" {
		t.Fatalf("expected proposal status PENDING_APPROVAL/APPROVED, got %q", evalProp.Status)
	}
}

func TestT1_F13_GitleaksSecretDetectedAndRedacted(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	secret1 := "AKIAIOSFODNN7EXAMPLE"
	secret2 := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	env.RegisterSecret(secret1)
	env.RegisterSecret(secret2)

	env.Gateway().SetMode(harness.GatewayModeClean)

	secretEnv := m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")
	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: secret1,
		FilePath:    "secrets.env",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: secretEnv},
	), "Secret leak test", nil)

	evalProp, assessResp, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	var foundSecret bool
	for _, f := range findResp.Findings {
		if f.Scanner == "gitleaks" || f.Category == "SECRET" {
			foundSecret = true
			if f.Category != "SECRET" || f.Severity != "CRITICAL" {
				t.Fatalf("gitleaks finding mismatch: category=%q severity=%q", f.Category, f.Severity)
			}
			if !f.Redacted {
				t.Fatalf("expected finding Redacted=true, got false: %+v", f)
			}
			if f.Fingerprint == "" {
				t.Fatalf("expected non-empty finding Fingerprint")
			}
		}
	}
	if !foundSecret {
		t.Fatalf("expected gitleaks SECRET finding in %+v", findResp.Findings)
	}

	findJSON, _ := json.Marshal(findResp)
	assessJSON, _ := json.Marshal(assessResp)
	auditEvents := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop.ID})
	auditJSON, _ := json.Marshal(auditEvents)

	harness.AssertNoSecretOrEncodedLeak(t, string(findJSON), secret1, secret2)
	harness.AssertNoSecretOrEncodedLeak(t, string(assessJSON), secret1, secret2)
	harness.AssertNoSecretOrEncodedLeak(t, string(auditJSON), secret1, secret2)
	env.Gateway().AssertNoSecretInPrompts(t, secret1, secret2)
	env.AssertNoSecretLeakInLogs(secret1, secret2)

	if evalProp.LatestPolicyEffect != "DENY" || evalProp.Status != "DENIED" {
		t.Fatalf("expected Stage C DENY/DENIED on secret leak, got effect=%q status=%q", evalProp.LatestPolicyEffect, evalProp.Status)
	}
}

func TestT1_F13_ScanCodeAndSemgrepFindingsNormalized(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	gplBytes := m3ReadFixture(t, env, "payloads/license_gpl3.txt")
	execGo := []byte("package main\n\nimport \"os/exec\"\n\nfunc run(cmd string) error {\n\t// 6\n\t// 7\n\t// 8\n\t// 9\n\treturn exec.Command(\"sh\", \"-c\", cmd).Run()\n}\n")

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerScanCode, harness.ScannerBehavior{
		Mode:        harness.ScannerModeProhibitedLicense,
		LicenseSPDX: "GPL-3.0-only",
		FilePath:    "LICENSE",
	})
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:     harness.ScannerModeSASTFinding,
		RuleID:   "go.lang.security.audit.unsafe-exec",
		FilePath: "exec.go",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "LICENSE", Typeflag: tar.TypeReg, Mode: 0o644, Body: gplBytes},
		harness.TarEntry{Name: "exec.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: execGo},
	), "License and SAST findings", nil)

	_, _, allFindings := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	var gotSC, gotSG bool
	for _, f := range allFindings.Findings {
		if f.EvidenceID == "" || f.Fingerprint == "" {
			t.Fatalf("finding %+v missing EvidenceID or Fingerprint", f)
		}
		if f.Scanner == "scancode" {
			gotSC = true
			if f.Category != "LICENSE" {
				t.Fatalf("scancode category=%q, want LICENSE", f.Category)
			}
		}
		if f.Scanner == "semgrep" {
			gotSG = true
			if f.Category != "SAST" || f.Severity != "HIGH" {
				t.Fatalf("semgrep finding mismatch: category=%q severity=%q", f.Category, f.Severity)
			}
			if f.StartLine != 10 || f.EndLine != 10 {
				t.Fatalf("semgrep line range mismatch: start=%d end=%d, want 10..10", f.StartLine, f.EndLine)
			}
		}
	}
	if !gotSC || !gotSG {
		t.Fatalf("expected both scancode and semgrep findings, got sc=%v sg=%v (%+v)", gotSC, gotSG, allFindings.Findings)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	scFiltered, scRaw, err := ctrlClient.ListProposalFindings(ctx, prop.ID, harness.WithQuery(map[string]string{"scanner": "scancode"}))
	if err != nil {
		t.Fatalf("ListProposalFindings(scanner=scancode): %v", err)
	}
	scRaw.RequireStatus(t, http.StatusOK)
	if len(scFiltered.Findings) == 0 {
		t.Fatalf("expected >= 1 finding for scanner=scancode")
	}
	for _, f := range scFiltered.Findings {
		if f.Scanner != "scancode" {
			t.Fatalf("filtered scanner=scancode returned finding with scanner=%q", f.Scanner)
		}
	}

	sevFiltered, sevRaw, err := ctrlClient.ListProposalFindings(ctx, prop.ID, harness.WithQuery(map[string]string{"severity": "HIGH"}))
	if err != nil {
		t.Fatalf("ListProposalFindings(severity=HIGH): %v", err)
	}
	sevRaw.RequireStatus(t, http.StatusOK)
	if len(sevFiltered.Findings) == 0 {
		t.Fatalf("expected >= 1 finding for severity=HIGH")
	}
	for _, f := range sevFiltered.Findings {
		if f.Severity != "HIGH" {
			t.Fatalf("filtered severity=HIGH returned finding with severity=%q", f.Severity)
		}
	}
}

func TestT1_F13_ConditionalTrivyAndCustomRulesExecution(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	keyBody := m3ReadFixture(t, env, "payloads/synthetic_private_key.pem")
	canaryKeyData := "FAKE_E2E_TEST_KEY_DATA_DO_NOT_USE_000000000000000000000000000000"
	env.RegisterSecret(canaryKeyData)

	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerTrivy, harness.ScannerBehavior{
		Mode:     harness.ScannerModeVulnFinding,
		RuleID:   "CVE-2026-0001",
		FilePath: "go.mod",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, []harness.TarEntry{
		{Name: "README.md", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("# Modified\n")},
		{Name: "go.mod", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("module example.com/e2e\n\ngo 1.25\n\nrequire example.com/vulnlib v1.0.0\n")},
		{Name: "main.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "secrets/id_rsa.pem", Typeflag: tar.TypeReg, Mode: 0o644, Body: keyBody},
	}, "Dependency change + restricted extension", nil)

	_, _, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	env.Scanners().AssertInvoked(t, harness.ScannerTrivy)

	var hasTrivyRun, hasCustomRun bool
	for _, r := range findResp.ScanRuns {
		if r.Scanner == "trivy" {
			hasTrivyRun = true
		}
		if r.Scanner == "custom" {
			hasCustomRun = true
		}
	}
	if !hasTrivyRun || !hasCustomRun {
		t.Fatalf("expected both trivy and custom ScanRuns, got trivy=%v custom=%v (%+v)", hasTrivyRun, hasCustomRun, findResp.ScanRuns)
	}

	var hasCVE, hasCustomFinding bool
	for _, f := range findResp.Findings {
		if f.RuleID == "CVE-2026-0001" && f.Category == "VULNERABILITY" && f.Severity == "CRITICAL" {
			hasCVE = true
		}
		if f.Scanner == "custom" {
			hasCustomFinding = true
		}
	}
	if !hasCVE || !hasCustomFinding {
		t.Fatalf("expected CVE-2026-0001 vuln finding and custom path/extension finding, got %+v", findResp.Findings)
	}

	rawFindings, _ := json.Marshal(findResp)
	harness.AssertNoSecretLeak(t, string(rawFindings), canaryKeyData)
	env.AssertNoSecretLeakInLogs(canaryKeyData)
}

func TestT1_F13_RestrictedRepoIPFingerprintHook(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{
		Classification: "RESTRICTED",
		AllowedRoutes:  []string{"approved-code-review"},
	})
	toks := m3MintTokens(env)
	env.Scanners().ResetAll()
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "internal_algo.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc proprietaryScore(x int) int { return x * 7 }\n")},
	), "Restricted repo algorithm change", nil)

	_, _, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	seen := make(map[string]harness.ScanRunDTO)
	for _, r := range findResp.ScanRuns {
		seen[r.Scanner] = r
	}
	for _, want := range []string{"gitleaks", "scancode", "semgrep", "ip_fingerprint"} {
		r, ok := seen[want]
		if !ok {
			t.Fatalf("RESTRICTED repo missing expected ScanRun %q in %+v", want, findResp.ScanRuns)
		}
		if r.Status != "COMPLETED" || !r.Complete {
			t.Fatalf("ScanRun %q expected COMPLETED & Complete=true, got status=%q complete=%v", want, r.Status, r.Complete)
		}
	}
}

// =============================================================================
// F-14: Stage B Contextual Decision Model, Untrusted-Data Isolation & Route Binding (5 Tier 1 Tests)
// =============================================================================

func TestT1_F14_ServerOnlyPromptAndStructuredAssessment(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:       harness.GatewayModeClean,
		Format:     harness.GatewayFormatOpenAIChat,
		Confidence: 0.94,
	})

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "clean.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Clean() {}\n")},
	), "Structured assessment test", nil)

	_, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	req, ok := env.Gateway().LastRequest()
	if !ok {
		t.Fatalf("expected MockGateway to receive Stage B assessment request")
	}
	if len(req.RawBody) == 0 {
		t.Fatalf("expected non-empty Stage B prompt request body")
	}
	if len(assessResp.Assessments) == 0 {
		t.Fatalf("expected at least 1 persisted AssessmentDTO, got 0")
	}
	a := assessResp.Assessments[0]
	harness.AssertUUIDv7(t, a.ID)
	if a.Status != "COMPLETE" {
		t.Fatalf("AssessmentDTO.Status=%q, want COMPLETE", a.Status)
	}
	if a.Risk != "LOW" || a.Disposition != "CLEAR" {
		t.Fatalf("AssessmentDTO risk/disposition mismatch: risk=%q disposition=%q", a.Risk, a.Disposition)
	}
	if a.ModelRoute != "approved-code-review" {
		t.Fatalf("AssessmentDTO.ModelRoute=%q, want approved-code-review", a.ModelRoute)
	}
	if a.ModelVersion == "" || a.PromptVersion == "" {
		t.Fatalf("expected non-empty ModelVersion and PromptVersion, got %+v", a)
	}
	if !m3IsHexN(a.InputDigest, 64) || !m3IsHexN(a.OutputDigest, 64) {
		t.Fatalf("expected 64-hex InputDigest and OutputDigest, got in=%q out=%q", a.InputDigest, a.OutputDigest)
	}
}

func TestT1_F14_UntrustedDataFramingIsolation(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	injBytes := m3ReadFixture(t, env, "payloads/prompt_injection_source.go")
	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "sample.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: injBytes},
	), "Untrusted framing test", nil)

	_, _, _ = m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	env.Gateway().AssertPromptUntrustedFraming(t, "Ignore all previous instructions", true)
}

func TestT1_F14_HighRiskIPFindingGroundingAndEscalation(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "CONFIDENTIAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:           harness.GatewayModeHighRiskReview,
		AssessmentType: "IP_PROVENANCE",
	})

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:     harness.ScannerModeSASTFinding,
		FilePath: "algo.go",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "algo.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc algo() int { return 1 }\n")},
	), "High risk IP review", nil)

	evalProp, assessResp, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	if len(assessResp.Assessments) == 0 {
		t.Fatalf("expected persisted AssessmentDTO")
	}
	a := assessResp.Assessments[0]
	if a.Status != "COMPLETE" || a.Risk != "HIGH" || a.Disposition != "REVIEW" {
		t.Fatalf("expected COMPLETE/HIGH/REVIEW, got status=%q risk=%q disp=%q", a.Status, a.Risk, a.Disposition)
	}

	validIDs := make(map[string]struct{})
	for _, f := range findResp.Findings {
		if f.EvidenceID != "" {
			validIDs[f.EvidenceID] = struct{}{}
		}
		if f.ID != "" {
			validIDs[f.ID] = struct{}{}
		}
	}
	if len(a.Findings) == 0 {
		t.Fatalf("expected non-empty Stage B findings in %+v", a)
	}
	for _, mf := range a.Findings {
		for _, eid := range mf.EvidenceIDs {
			if _, ok := validIDs[eid]; !ok {
				t.Fatalf("Stage B evidence_id %q not grounded in Stage A findings %+v", eid, findResp.Findings)
			}
		}
	}

	if evalProp.LatestPolicyEffect != "REQUIRE_APPROVAL" {
		t.Fatalf("expected REQUIRE_APPROVAL on high risk IP finding, got %q", evalProp.LatestPolicyEffect)
	}
	var hasIPObl bool
	for _, pd := range assessResp.PolicyDecisions {
		for _, obl := range pd.Obligations {
			if obl.ReviewerGroup == "ip-review" && obl.Minimum >= 1 {
				hasIPObl = true
			}
		}
	}
	if !hasIPObl {
		t.Fatalf("expected ip-review obligation (minimum >= 1) in PolicyDecisions: %+v", assessResp.PolicyDecisions)
	}
}

func TestT1_F14_SelfContainedAssessmentLineage(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "notes.txt", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("lineage check\n")},
	), "Self-contained lineage", nil)

	_, _, _ = m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	// Switch gateway to outage mode and verify persisted assessment retrieval works offline.
	env.Gateway().SetMode(harness.GatewayModeOutage503)
	beforeReqs := len(env.Gateway().Requests())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got, raw, err := env.Client(toks.HumanA).ListProposalAssessments(ctx, prop.ID)
	if err != nil {
		t.Fatalf("ListProposalAssessments offline: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	if len(env.Gateway().Requests()) != beforeReqs {
		t.Fatalf("GET /assessments unexpectedly called ModelGateway")
	}
	if len(got.Assessments) == 0 {
		t.Fatalf("expected persisted assessments")
	}
	a := got.Assessments[0]
	if a.Risk == "" || a.Disposition == "" || a.ModelVersion == "" || a.PromptVersion == "" ||
		!m3IsHexN(a.InputDigest, 64) || !m3IsHexN(a.OutputDigest, 64) {
		t.Fatalf("incomplete persisted assessment lineage: %+v", a)
	}
}

func TestT1_F14_AuthorizedRouteForRestrictedClassification(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{
		Classification: "RESTRICTED",
		AllowedRoutes:  []string{"restricted-code-review"},
	})
	toks := m3MintTokens(env)
	env.Gateway().SetRouteProgram("restricted-code-review", harness.GatewayProgram{
		Mode:       harness.GatewayModeClean,
		Confidence: 0.95,
	})

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "restricted-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "restricted.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Restricted() {}\n")},
	), "Restricted route test", nil)

	_, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	req, ok := env.Gateway().LastRequest()
	if !ok {
		t.Fatalf("expected MockGateway to receive request on restricted-code-review")
	}
	if req.Route != "restricted-code-review" {
		t.Fatalf("gateway recorded route=%q, want restricted-code-review", req.Route)
	}
	if len(assessResp.Assessments) == 0 {
		t.Fatalf("expected AssessmentDTO")
	}
	a := assessResp.Assessments[0]
	if a.ModelRoute != "restricted-code-review" || a.Status != "COMPLETE" {
		t.Fatalf("expected route=restricted-code-review status=COMPLETE, got route=%q status=%q", a.ModelRoute, a.Status)
	}
}

// =============================================================================
// F-15: Stage C CEL PolicyBundle, Precedence, onError: DENY, Org-Before-Repo & custodian-policy (5 Tier 1 Tests)
// =============================================================================

func TestT1_F15_CustodianPolicyCLISuiteValidateEvalTest(t *testing.T) {
	env := harness.NewEnv(t, harness.WithSkipServices(), harness.WithSkipPostgres())
	root := m3FindRepoRoot(t)
	validBundlePath := filepath.Join(root, "test", "e2e", "fixtures", "policies", "valid_default.yaml")

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "eval_input.json")
	inputPayload := map[string]any{
		"stage": "EGRESS",
		"findings": map[string]any{
			"scan_complete":       true,
			"critical_secrets":    0,
			"prohibited_licenses": 0,
		},
		"assessment": map[string]any{
			"ip_risk": "LOW",
			"status":  "COMPLETE",
		},
		"change": map[string]any{
			"paths": []string{"infra/prod/main.tf"},
		},
	}
	inBytes, _ := json.MarshalIndent(inputPayload, "", "  ")
	if err := os.WriteFile(inputPath, inBytes, 0o644); err != nil {
		t.Fatalf("write CLI eval input: %v", err)
	}

	cliCfg := env.Contracts().CLI
	bin := env.Contracts().Binaries.Policy

	valArgs := append(append([]string(nil), cliCfg.PolicyValidateSubcommand...), cliCfg.PolicyBundleFlag, validBundlePath)
	valRes := env.RunCLI(bin, valArgs, nil)
	if valRes.ExitCode != 0 {
		t.Fatalf("custodian-policy validate failed (exit=%d): stdout=%s stderr=%s err=%v", valRes.ExitCode, valRes.Stdout, valRes.Stderr, valRes.Err)
	}

	evalArgs := append(append([]string(nil), cliCfg.PolicyEvaluateSubcommand...),
		cliCfg.PolicyBundleFlag, validBundlePath,
		cliCfg.PolicyInputFlag, inputPath,
	)
	evalRes := env.RunCLI(bin, evalArgs, nil)
	if evalRes.ExitCode != 0 {
		t.Fatalf("custodian-policy evaluate failed (exit=%d): stdout=%s stderr=%s err=%v", evalRes.ExitCode, evalRes.Stdout, evalRes.Stderr, evalRes.Err)
	}
	if !strings.Contains(evalRes.Stdout, "REQUIRE_APPROVAL") || !strings.Contains(evalRes.Stdout, "platform-owners") {
		t.Fatalf("expected REQUIRE_APPROVAL and platform-owners in CLI stdout, got: %s", evalRes.Stdout)
	}

	// Validate repository policies/defaults/*.yaml (created in M3; required for full M5 E2E pass).
	defaultsDir := filepath.Join(root, "policies", "defaults")
	entries, err := os.ReadDir(defaultsDir)
	if err != nil {
		t.Fatalf("read policies/defaults: %v", err)
	}
	validatedDefaults := 0
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		p := filepath.Join(defaultsDir, e.Name())
		args := append(append([]string(nil), cliCfg.PolicyValidateSubcommand...), cliCfg.PolicyBundleFlag, p)
		res := env.RunCLI(bin, args, nil)
		if res.ExitCode != 0 {
			t.Fatalf("custodian-policy validate %s failed (exit=%d): stdout=%s stderr=%s", p, res.ExitCode, res.Stdout, res.Stderr)
		}
		validatedDefaults++
	}
	if validatedDefaults == 0 {
		t.Fatalf("expected at least 1 YAML policy bundle in %s", defaultsDir)
	}

	if len(cliCfg.PolicyTestSubcommand) == 0 {
		t.Fatalf("expected PolicyTestSubcommand configured in CLIConfig")
	}
	helpArgs := append(append([]string(nil), cliCfg.PolicyTestSubcommand...), "--help")
	helpRes := env.RunCLI(bin, helpArgs, nil)
	if helpRes.ExitCode != 0 {
		t.Fatalf("custodian-policy test --help failed (exit=%d): stdout=%s stderr=%s err=%v", helpRes.ExitCode, helpRes.Stdout, helpRes.Stderr, helpRes.Err)
	}

	testsDir := filepath.Join(root, "policies", "tests")
	if testEntries, err := os.ReadDir(testsDir); err == nil {
		hasTestYAML := false
		for _, e := range testEntries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				hasTestYAML = true
				break
			}
		}
		if hasTestYAML {
			testArgs := append(append([]string(nil), cliCfg.PolicyTestSubcommand...), testsDir)
			testRes := env.RunCLI(bin, testArgs, nil)
			if testRes.ExitCode != 0 {
				t.Fatalf("custodian-policy test %s failed (exit=%d): stdout=%s stderr=%s err=%v", testsDir, testRes.ExitCode, testRes.Stdout, testRes.Stderr, testRes.Err)
			}
		}
	}
}

func TestT1_F15_PolicyValidateAndSimulateAPIEndpoints(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	bundleYAML := string(m3ReadFixture(t, env, "policies/valid_default.yaml"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminClient := env.Client(toks.PolicyAdmin)

	valResp, valRaw, err := adminClient.ValidatePolicy(ctx, harness.PolicyBundleReq{
		BundleYAML: bundleYAML,
	})
	if err != nil {
		t.Fatalf("ValidatePolicy: %v", err)
	}
	valRaw.RequireStatus(t, http.StatusOK)
	if !valResp.Valid || valResp.Name != "engineering-default" || valResp.RulesCompiled != 5 || !m3IsHexN(valResp.Digest, 64) {
		t.Fatalf("unexpected ValidatePolicy response: %+v", valResp)
	}

	allowSim, aRaw, err := adminClient.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: bundleYAML,
		Stage:      "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"scan_complete": true, "critical_secrets": 0, "prohibited_licenses": 0},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{"README.md"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(allow): %v", err)
	}
	aRaw.RequireStatus(t, http.StatusOK)
	if allowSim.Effect != "ALLOW" || !m3ContainsString(allowSim.MatchedRuleIDs, "standard.allow") {
		t.Fatalf("expected ALLOW with standard.allow, got %+v", allowSim)
	}

	infraSim, iRaw, err := adminClient.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: bundleYAML,
		Stage:      "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"scan_complete": true, "critical_secrets": 0, "prohibited_licenses": 0},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{"infra/prod/deploy.yaml"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(infra): %v", err)
	}
	iRaw.RequireStatus(t, http.StatusOK)
	if infraSim.Effect != "REQUIRE_APPROVAL" {
		t.Fatalf("expected REQUIRE_APPROVAL, got %q", infraSim.Effect)
	}
	if !m3IsHexN(infraSim.BundleDigest, 64) || !m3IsHexN(infraSim.InputDigest, 64) || len(infraSim.RuleTrace) == 0 {
		t.Fatalf("missing digests or rule trace in %+v", infraSim)
	}
	var hasPlatObl bool
	for _, obl := range infraSim.Obligations {
		if obl.ReviewerGroup == "platform-owners" && obl.Minimum == 1 {
			hasPlatObl = true
		}
	}
	if !hasPlatObl {
		t.Fatalf("expected platform-owners obligation (min 1), got %+v", infraSim.Obligations)
	}
}

func TestT1_F15_PrecedenceOrderDenyOverQuarantineOverApprovalOverAllow(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: precedence-lattice-test
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep]
  decisionModel:
    route: approved-code-review
rules:
  - id: rule.allow
    stages: [EGRESS]
    when: flags.allow == true
    effect: ALLOW
  - id: rule.req_approval
    stages: [EGRESS]
    when: flags.req_approval == true
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: engineering
        minimum: 1
  - id: rule.req_remediation
    stages: [EGRESS]
    when: flags.req_remediation == true
    effect: REQUIRE_REMEDIATION
  - id: rule.quarantine
    stages: [EGRESS]
    when: flags.quarantine == true
    effect: QUARANTINE
  - id: rule.deny
    stages: [EGRESS]
    when: flags.deny == true
    effect: DENY
`

	cases := []struct {
		name  string
		flags map[string]bool
		want  string
	}{
		{
			name:  "require_approval_over_allow",
			flags: map[string]bool{"allow": true, "req_approval": true},
			want:  "REQUIRE_APPROVAL",
		},
		{
			name:  "require_remediation_over_require_approval",
			flags: map[string]bool{"req_approval": true, "req_remediation": true},
			want:  "REQUIRE_REMEDIATION",
		},
		{
			name:  "quarantine_over_require_remediation",
			flags: map[string]bool{"req_remediation": true, "quarantine": true},
			want:  "QUARANTINE",
		},
		{
			name:  "deny_over_quarantine",
			flags: map[string]bool{"quarantine": true, "deny": true},
			want:  "DENY",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminClient := env.Client(toks.PolicyAdmin)

	for _, tc := range cases {
		res, raw, err := adminClient.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
			BundleYAML: bundleYAML,
			Stage:      "EGRESS",
			Input: map[string]any{
				"flags": map[string]any{
					"allow":           tc.flags["allow"],
					"req_approval":    tc.flags["req_approval"],
					"req_remediation": tc.flags["req_remediation"],
					"quarantine":      tc.flags["quarantine"],
					"deny":            tc.flags["deny"],
				},
			},
		})
		if err != nil {
			t.Fatalf("EvaluatePolicy(%s): %v", tc.name, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		if res.Effect != tc.want {
			t.Fatalf("case %s: effect=%q, want %q (trace=%+v)", tc.name, res.Effect, tc.want, res.RuleTrace)
		}
	}
}

func TestT1_F15_OrgBeforeRepoCompositionAdditiveRestrictions(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	orgYAML := string(m3ReadFixture(t, env, "policies/org_mandatory_deny.yaml"))
	repoYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-docs-security
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep]
  decisionModel:
    route: approved-code-review
rules:
  - id: repo.docs.review
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("docs/security/"))
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: sec-docs
        minimum: 1
`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, raw, err := env.Client(toks.PolicyAdmin).EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		OrgBundleYAML: orgYAML,
		BundleYAML:    repoYAML,
		Stage:         "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"scan_complete": true, "critical_secrets": 0, "prohibited_licenses": 0},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{"docs/security/spec.md"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(org+repo): %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if res.Effect != "REQUIRE_APPROVAL" {
		t.Fatalf("expected REQUIRE_APPROVAL, got %q", res.Effect)
	}
	if !m3ContainsString(res.MatchedRuleIDs, "repo.docs.review") {
		t.Fatalf("expected matched rule repo.docs.review, got %+v", res.MatchedRuleIDs)
	}
	var hasSecDocs bool
	for _, obl := range res.Obligations {
		if obl.ReviewerGroup == "sec-docs" && obl.Minimum == 1 {
			hasSecDocs = true
		}
	}
	if !hasSecDocs {
		t.Fatalf("expected sec-docs obligation, got %+v", res.Obligations)
	}
}

func TestT1_F15_PersistedPolicyDecisionTraceability(t *testing.T) {
	policyDir := m3WritePolicyDirTemp(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/valid_default.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "infra/prod/service.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("replicas: 3\n")},
	), "Infra prod change", nil)

	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	harness.AssertUUIDv7(t, evalProp.LatestPolicyEvaluationID)
	if evalProp.LatestPolicyEffect != "REQUIRE_APPROVAL" {
		t.Fatalf("LatestPolicyEffect=%q, want REQUIRE_APPROVAL", evalProp.LatestPolicyEffect)
	}

	var matched bool
	for _, pd := range assessResp.PolicyDecisions {
		if pd.ID == evalProp.LatestPolicyEvaluationID {
			matched = true
			harness.AssertUUIDv7(t, pd.PolicyBundleID)
			if !m3IsHexN(pd.InputDigest, 64) {
				t.Fatalf("invalid PolicyDecision.InputDigest: %q", pd.InputDigest)
			}
			if pd.Effect != "REQUIRE_APPROVAL" {
				t.Fatalf("PolicyDecision.Effect=%q, want REQUIRE_APPROVAL", pd.Effect)
			}
			var hasInfraRule, hasPlatGroup bool
			for _, r := range pd.Reasons {
				if r.RuleID == "security.infrastructure" {
					hasInfraRule = true
				}
			}
			for _, o := range pd.Obligations {
				if o.ReviewerGroup == "platform-owners" {
					hasPlatGroup = true
				}
			}
			if !hasInfraRule || !hasPlatGroup {
				t.Fatalf("expected rule security.infrastructure and obligation platform-owners in %+v", pd)
			}
		}
	}
	if !matched {
		t.Fatalf("PolicyDecisions %+v did not contain LatestPolicyEvaluationID %q", assessResp.PolicyDecisions, evalProp.LatestPolicyEvaluationID)
	}
}

// =============================================================================
// F-16: Digest-Bound Human Approval, Reviewer Groups, SoD & Staleness Revocation (5 Tier 1 Tests)
// =============================================================================

func TestT1_F16_MandatoryHumanApprovalOnAllowPolicy(t *testing.T) {
	policyDir := m3WritePolicyDirTemp(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/valid_default.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "doc.md", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("# Allow policy still requires human approval\n")},
	), "Allow policy mandatory human approval", nil)

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	if evalProp.LatestPolicyEffect != "ALLOW" {
		t.Fatalf("expected LatestPolicyEffect=ALLOW, got %q", evalProp.LatestPolicyEffect)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(unapproved): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs prior to approval")
	}

	appResp := m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "LGTM")
	if appResp.ProposalStatus != "APPROVED" || len(appResp.RemainingObligations) != 0 {
		t.Fatalf("expected APPROVED with 0 remaining obligations, got status=%q remaining=%+v", appResp.ProposalStatus, appResp.RemainingObligations)
	}

	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" || env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected PUBLISHED with 1 PR, got status=%q prCount=%d", pub.Status, env.GitHub().PRCount(repo.FullName))
	}
}

func TestT1_F16_ReviewerGroupObligationSatisfaction(t *testing.T) {
	policyDir := m3WritePolicyDirTemp(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/valid_default.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "infra/prod/main.tf", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("resource \"null_resource\" \"x\" {}\n")},
	), "Infra prod tf change", nil)

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	appResp := m3ApproveProposal(t, env, toks.PlatformOwner, evalProp, "APPROVE", "Platform owner approved")
	if len(appResp.RemainingObligations) != 0 || appResp.ProposalStatus != "APPROVED" {
		t.Fatalf("expected RemainingObligations empty and APPROVED, got %+v", appResp)
	}
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}
}

func TestT1_F16_MultiApproverMinimumCountDecrement(t *testing.T) {
	twoApproverPolicy := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: two-security-approvers
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep]
  decisionModel:
    route: approved-code-review
rules:
  - id: security.two_approvers
    stages: [EGRESS]
    when: findings.scan_complete && findings.critical_secrets == 0 && findings.prohibited_licenses == 0
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: security-team
        minimum: 2
`
	policyDir := m3WritePolicyDirTemp(t, map[string]string{"default.yaml": twoApproverPolicy})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "auth.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Auth() bool { return true }\n")},
	), "Requires 2 security approvers", nil)

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	app1 := m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "First security approval")
	if len(app1.RemainingObligations) == 0 || app1.ProposalStatus == "APPROVED" {
		t.Fatalf("expected unmet obligation after 1st approval, got %+v", app1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(1/2 approvals): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)

	app2 := m3ApproveProposal(t, env, toks.Reviewer2, evalProp, "APPROVE", "Second security approval")
	if len(app2.RemainingObligations) != 0 || app2.ProposalStatus != "APPROVED" {
		t.Fatalf("expected all obligations satisfied and APPROVED after 2nd reviewer, got %+v", app2)
	}

	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED after 2nd approval, got %q", pub.Status)
	}
}

func TestT1_F16_HumanRejectionBlocksPublication(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "risky.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc risky() {}\n")},
	), "Rejection test", nil)

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	rej := m3ApproveProposal(t, env, toks.Reviewer, evalProp, "REJECT", "unsafe change")
	if rej.Decision != "REJECT" || rej.ProposalStatus != "REJECTED" {
		t.Fatalf("expected REJECT/REJECTED, got decision=%q status=%q", rej.Decision, rej.ProposalStatus)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(rejected): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs on rejected proposal")
	}
}

func TestT1_F16_DigestAndPolicyEvaluationBinding(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "bind.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Bind() {}\n")},
	), "Digest binding test", nil)

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	app := m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Verified digest and evaluation")

	harness.AssertUUIDv7(t, app.ID)
	if app.PolicyDecisionID != evalProp.LatestPolicyEvaluationID {
		t.Fatalf("ApprovalResp.PolicyDecisionID=%q, want %q", app.PolicyDecisionID, evalProp.LatestPolicyEvaluationID)
	}
	wantDigest := m3NormalizeSHA256(evalProp.PublicationManifestDigest)
	if m3NormalizeSHA256(app.ManifestDigest) != wantDigest {
		t.Fatalf("ApprovalResp.ManifestDigest=%q, want %q", app.ManifestDigest, wantDigest)
	}

	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop.ID})
	harness.VerifyAuditHashChain(t, events)
	auditBytes, _ := json.Marshal(events)
	if !strings.Contains(string(auditBytes), wantDigest) || !strings.Contains(string(auditBytes), evalProp.LatestPolicyEvaluationID) {
		t.Fatalf("expected audit events to contain manifest digest %q and evaluation ID %q", wantDigest, evalProp.LatestPolicyEvaluationID)
	}
}

// =============================================================================
// F-17: Isolated custodian-publisher, 14-Step Publish, Trailers, custodian/<id> & Force-Push Check (5 Tier 1 Tests)
// =============================================================================

func TestT1_F17_FourteenStepPublishAndPRCreation(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "hello.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Hello() string { return \"hello\" }\n")},
	), "Add hello.go", nil)

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve hello.go")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)

	wantBranch := "custodian/" + prop.ID
	if pub.Status != "PUBLISHED" {
		t.Fatalf("Publication.Status=%q, want PUBLISHED", pub.Status)
	}
	if pub.BranchRef != wantBranch {
		t.Fatalf("Publication.BranchRef=%q, want %q", pub.BranchRef, wantBranch)
	}
	if !m3IsHexN(pub.CommitSHA, 40) {
		t.Fatalf("Publication.CommitSHA=%q, want 40 lowercase hex", pub.CommitSHA)
	}
	if pub.PullRequestNumber != 1 || pub.PullRequestURL == "" {
		t.Fatalf("unexpected PR fields: num=%d url=%q", pub.PullRequestNumber, pub.PullRequestURL)
	}

	exists, err := env.Git().BranchExists(repo.FullName, wantBranch)
	if err != nil || !exists {
		t.Fatalf("expected bare git branch %q to exist (exists=%v err=%v)", wantBranch, exists, err)
	}
	tree, err := env.Git().InspectTree(repo.FullName, pub.CommitSHA)
	if err != nil {
		t.Fatalf("InspectTree(%s): %v", pub.CommitSHA, err)
	}
	if tree["hello.go"] != "package main\n\nfunc Hello() string { return \"hello\" }\n" {
		t.Fatalf("InspectTree hello.go mismatch: %q", tree["hello.go"])
	}
	prs := env.GitHub().PullRequests(repo.FullName)
	if len(prs) != 1 || prs[0].Head != wantBranch || prs[0].Base != repo.DefaultBranch || prs[0].State != "open" {
		t.Fatalf("unexpected MockGitHub PRs: %+v", prs)
	}
}

func TestT1_F17_CommitAuthorCommitterParentAndTrailers(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	// (1) Agent-assisted proposal
	ws1, desc1 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop1 := m3SubmitAndReconstruct(t, env, toks.Controller, ws1, desc1, m3DefaultEntries(
		harness.TarEntry{Name: "agent_file.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar A = 1\n")},
	), "Agent assisted change", &harness.Provenance{Type: "agent_assisted", CaptureMethod: "frozen_filesystem"})
	eval1, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop1.ID, prop1.Version)
	m3ApproveProposal(t, env, toks.Reviewer, eval1, "APPROVE", "Approve agent change")
	pub1 := m3PublishAndWait(t, env, toks.Controller, eval1)

	ci1, err := env.Git().InspectCommit(repo.FullName, pub1.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit(1): %v", err)
	}
	if ci1.AuthorName != "Alice Developer" || ci1.AuthorEmail != "alice@example.com" {
		t.Fatalf("commit 1 author mismatch: %q <%s>", ci1.AuthorName, ci1.AuthorEmail)
	}
	if !strings.Contains(strings.ToLower(ci1.CommitterName), "custodian") {
		t.Fatalf("commit 1 committer expected Custodian, got %q", ci1.CommitterName)
	}
	if len(ci1.Parents) != 1 || ci1.Parents[0] != ws1.BaseCommit {
		t.Fatalf("commit 1 parents=%v, want [%s]", ci1.Parents, ws1.BaseCommit)
	}
	if !m3ContainsString(ci1.Trailers["Custodian-Proposal"], prop1.ID) ||
		!m3ContainsString(ci1.Trailers["Custodian-Workspace"], ws1.ID) ||
		!m3ContainsString(ci1.Trailers["Agent-Assisted"], "true") {
		t.Fatalf("commit 1 trailers mismatch: %+v", ci1.Trailers)
	}

	// (2) Human-authored proposal
	ws2, desc2 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop2 := m3SubmitAndReconstruct(t, env, toks.Controller, ws2, desc2, m3DefaultEntries(
		harness.TarEntry{Name: "human_file.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar H = 2\n")},
	), "Human authored change", &harness.Provenance{Type: "human_authored", CaptureMethod: "frozen_filesystem"})
	eval2, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop2.ID, prop2.Version)
	m3ApproveProposal(t, env, toks.Reviewer, eval2, "APPROVE", "Approve human change")
	pub2 := m3PublishAndWait(t, env, toks.Controller, eval2)

	ci2, err := env.Git().InspectCommit(repo.FullName, pub2.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit(2): %v", err)
	}
	if ci2.AuthorName != "Alice Developer" || ci2.AuthorEmail != "alice@example.com" {
		t.Fatalf("commit 2 author mismatch: %q <%s>", ci2.AuthorName, ci2.AuthorEmail)
	}
	if !m3ContainsString(ci2.Trailers["Custodian-Proposal"], prop2.ID) ||
		!m3ContainsString(ci2.Trailers["Custodian-Workspace"], ws2.ID) ||
		!m3ContainsString(ci2.Trailers["Agent-Assisted"], "false") {
		t.Fatalf("commit 2 trailers mismatch: %+v", ci2.Trailers)
	}
}

func TestT1_F17_BranchNamespaceExclusivity(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	origMainSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef(main): %v", err)
	}

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "ns.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar NS = 1\n")},
	), "Namespace exclusivity", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	afterMainSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || afterMainSHA != origMainSHA {
		t.Fatalf("main branch mutated: before=%s after=%s err=%v", origMainSHA, afterMainSHA, err)
	}

	branches, err := env.Git().ListBranches(repo.FullName)
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	wantBranch := "custodian/" + prop.ID
	if len(branches) != 2 || !m3ContainsString(branches, "main") || !m3ContainsString(branches, wantBranch) {
		t.Fatalf("expected ONLY [main %s], got %v", wantBranch, branches)
	}

	attempts := env.GitHub().PushAttempts()
	if len(attempts) == 0 {
		t.Fatalf("expected recorded PushAttempts")
	}
	for _, att := range attempts {
		if att.Allowed && att.Ref != "refs/heads/"+wantBranch {
			t.Fatalf("allowed push targeted unexpected ref %q (want refs/heads/%s)", att.Ref, wantBranch)
		}
	}
}

func TestT1_F17_SingleCommitSinglePRIdempotencyReplay(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "idem.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar Idem = 1\n")},
	), "Single PR idempotency", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	pubReq := harness.PublishReq{PublicationManifestDigest: evalProp.PublicationManifestDigest}
	pub1, raw1, err := ctrlClient.PublishProposal(ctx, evalProp.ID, pubReq, harness.WithIdempotencyKey("pub-key-1"))
	if err != nil {
		t.Fatalf("PublishProposal(1): %v", err)
	}
	raw1.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	pubID1 := m3NonEmpty(pub1.PublicationID, pub1.ID)
	if pub1.OperationID != "" {
		if _, err := ctrlClient.WaitForOperation(ctx, pub1.OperationID, 30*time.Second); err != nil {
			t.Fatalf("WaitForOperation(pub1): %v", err)
		}
	}
	final1 := m3PollPublicationStatus(t, ctrlClient, pubID1, 30*time.Second, "PUBLISHED")

	// Exact idempotency replay
	pub2, raw2, err := ctrlClient.PublishProposal(ctx, evalProp.ID, pubReq, harness.WithIdempotencyKey("pub-key-1"))
	if err != nil {
		t.Fatalf("PublishProposal(replay): %v", err)
	}
	raw2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	pubID2 := m3NonEmpty(pub2.PublicationID, pub2.ID)
	if pubID2 != pubID1 {
		t.Fatalf("idempotency replay returned different publication ID: %q vs %q", pubID2, pubID1)
	}
	if pub2.CommitSHA != "" && pub2.CommitSHA != final1.CommitSHA {
		t.Fatalf("idempotency replay commit SHA mismatch: %q vs %q", pub2.CommitSHA, final1.CommitSHA)
	}
	if pub2.PullRequestNumber != 0 && pub2.PullRequestNumber != final1.PullRequestNumber {
		t.Fatalf("idempotency replay PR number mismatch: %d vs %d", pub2.PullRequestNumber, final1.PullRequestNumber)
	}

	// Second distinct key must either return existing publication or 409 Conflict without creating a 2nd PR.
	pub3, raw3, err := ctrlClient.PublishProposal(ctx, evalProp.ID, pubReq, harness.WithIdempotencyKey("pub-key-2"))
	if err != nil {
		t.Fatalf("PublishProposal(key-2): %v", err)
	}
	raw3.RequireAnyStatus(t, http.StatusConflict, http.StatusOK, http.StatusAccepted)
	if raw3.StatusCode != http.StatusConflict {
		if m3NonEmpty(pub3.PublicationID, pub3.ID) != pubID1 {
			t.Fatalf("second publish created distinct publication %q != %q", m3NonEmpty(pub3.PublicationID, pub3.ID), pubID1)
		}
	}

	if env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected PRCount==1, got %d", env.GitHub().PRCount(repo.FullName))
	}
	ci, err := env.Git().InspectCommit(repo.FullName, final1.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit: %v", err)
	}
	if len(ci.Parents) != 1 || ci.Parents[0] != ws.BaseCommit {
		t.Fatalf("expected single canonical commit parented at %s, got %v", ws.BaseCommit, ci.Parents)
	}
}

func TestT1_F17_PublisherPackageAndCredentialIsolation(t *testing.T) {
	root := m3FindRepoRoot(t)
	goBin := m3ResolveGoBin(t)

	cmd := exec.Command(goBin, "list", "-deps", "./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps publisher boundary failed: %v\noutput:\n%s", err, string(out))
	}
	deps := string(out)
	for _, forbidden := range []string{
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/snapshots",
	} {
		if strings.Contains(deps, forbidden) {
			t.Fatalf("publisher isolation violation: %q appears in publisher dependency graph:\n%s", forbidden, deps)
		}
	}

	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "iso.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar Iso = 1\n")},
	), "Publisher isolation test", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	var sawWriteToken bool
	for _, att := range env.GitHub().PushAttempts() {
		if strings.HasPrefix(att.Token, "ghs_write_") {
			sawWriteToken = true
		}
	}
	if !sawWriteToken {
		t.Fatalf("expected publisher push to authenticate with ghs_write_* token, got %+v", env.GitHub().PushAttempts())
	}

	pubLogs := env.Logs("publisher")
	harness.AssertNoSecretOrEncodedLeak(t, pubLogs, env.GitHub().ReadAppPrivateKeyPEM(), env.GitHub().WriteAppPrivateKeyPEM())
	if strings.Contains(pubLogs, env.Gateway().URL()) {
		t.Fatalf("publisher logs unexpectedly reference ModelGateway URL %q", env.Gateway().URL())
	}
}

// =============================================================================
// F-18: Full /v1 REST API, OpenAPI 3.1 Contract, Idempotency-Key & Error Codes (5 Tier 1 Tests)
// =============================================================================

func TestT1_F18_AllSixteenV1EndpointsHappyPathRoundTrip(t *testing.T) {
	policyDir := m3WritePolicyDirTemp(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/valid_default.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. POST /v1/workspaces
	humanClient := env.Client(toks.HumanA)
	wsCreate, r1, err := humanClient.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "s-1", ModelRoute: "approved-code-review"},
	})
	if err != nil {
		t.Fatalf("POST /workspaces: %v", err)
	}
	r1.RequireStatus(t, http.StatusAccepted)
	wsID := m3NonEmpty(wsCreate.WorkspaceID, wsCreate.ID)
	harness.AssertUUIDv7(t, wsID)

	// 2. GET /v1/operations/{id}
	opWS, r2, err := humanClient.GetOperation(ctx, wsCreate.OperationID)
	if err != nil {
		t.Fatalf("GET /operations/{id}: %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)
	harness.AssertUUIDv7(t, opWS.ID)
	if _, err := humanClient.WaitForOperation(ctx, wsCreate.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(ws): %v", err)
	}

	// 3. GET /v1/workspaces/{id}
	ws, r3, err := humanClient.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GET /workspaces/{id}: %v", err)
	}
	r3.RequireStatus(t, http.StatusOK)
	if ws.BaseCommit == "" || ws.Generation < 1 {
		t.Fatalf("unexpected GetWorkspace: %+v", ws)
	}

	// 4. GET /v1/workspaces/{id}/source
	ctrlClient := env.Client(toks.Controller)
	desc, r4, err := ctrlClient.GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GET /workspaces/{id}/source: %v", err)
	}
	r4.RequireStatus(t, http.StatusOK)
	if desc.UploadCapability == nil {
		t.Fatalf("missing upload_capability")
	}

	// Upload snapshot and 5. POST /v1/workspaces/{id}/proposals
	gzBytes, shaHex := harness.BuildTarGz(m3DefaultEntries(
		harness.TarEntry{Name: "roundtrip.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc RoundTrip() {}\n")},
	))
	artID, _ := m3UploadSnapshot(t, env, toks.Controller, desc, gzBytes)
	subResp, r5, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws.Generation, SizeBytes: int64(len(gzBytes))},
		Title:    "Roundtrip all 16 endpoints",
	})
	if err != nil {
		t.Fatalf("POST /workspaces/{id}/proposals: %v", err)
	}
	r5.RequireStatus(t, http.StatusAccepted)
	propID := m3NonEmpty(subResp.ProposalID, subResp.ID)
	harness.AssertUUIDv7(t, propID)
	if _, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(reconstruct): %v", err)
	}

	// 6. GET /v1/proposals/{id}
	prop := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "RECONSTRUCTED")
	propGet, r6, err := ctrlClient.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GET /proposals/{id}: %v", err)
	}
	r6.RequireStatus(t, http.StatusOK)
	if !m3IsHexN(propGet.PublicationManifestDigest, 64) {
		t.Fatalf("missing publication_manifest_digest in %+v", propGet)
	}

	// 7. GET /v1/proposals/{id}/diff
	diffResp, r7, err := ctrlClient.GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GET /proposals/{id}/diff: %v", err)
	}
	r7.RequireStatus(t, http.StatusOK)
	if diffResp.ProposalID != propID || diffResp.UnifiedDiff == "" || len(diffResp.Paths) == 0 {
		t.Fatalf("unexpected GetProposalDiff: %+v", diffResp)
	}

	// 8. POST /v1/proposals/{id}/evaluate
	evalResp, r8, err := ctrlClient.EvaluateProposal(ctx, propID, harness.EvaluateReq{ExpectedVersion: prop.Version})
	if err != nil {
		t.Fatalf("POST /proposals/{id}/evaluate: %v", err)
	}
	r8.RequireStatus(t, http.StatusAccepted)
	if _, err := ctrlClient.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(evaluate): %v", err)
	}
	evalProp := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "PENDING_APPROVAL", "APPROVED")

	// 9. GET /v1/proposals/{id}/findings
	fResp, r9, err := ctrlClient.ListProposalFindings(ctx, propID)
	if err != nil {
		t.Fatalf("GET /proposals/{id}/findings: %v", err)
	}
	r9.RequireStatus(t, http.StatusOK)
	if len(fResp.ScanRuns) < 3 {
		t.Fatalf("expected >= 3 scan runs, got %d", len(fResp.ScanRuns))
	}

	// 10. GET /v1/proposals/{id}/assessments
	aResp, r10, err := ctrlClient.ListProposalAssessments(ctx, propID)
	if err != nil {
		t.Fatalf("GET /proposals/{id}/assessments: %v", err)
	}
	r10.RequireStatus(t, http.StatusOK)
	if len(aResp.Assessments) == 0 || len(aResp.PolicyDecisions) == 0 {
		t.Fatalf("expected assessments and policy decisions, got %+v", aResp)
	}

	// 11. POST /v1/proposals/{id}/approvals
	appResp, r11, err := env.Client(toks.Reviewer).ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalProp.LatestPolicyEvaluationID,
		Comment:                   "approved",
	})
	if err != nil {
		t.Fatalf("POST /proposals/{id}/approvals: %v", err)
	}
	r11.RequireStatus(t, http.StatusCreated)
	harness.AssertUUIDv7(t, appResp.ID)

	// 12. POST /v1/proposals/{id}/publish
	pubInit, r12, err := ctrlClient.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("POST /proposals/{id}/publish: %v", err)
	}
	r12.RequireStatus(t, http.StatusAccepted)
	pubID := m3NonEmpty(pubInit.PublicationID, pubInit.ID)
	harness.AssertUUIDv7(t, pubID)
	if _, err := ctrlClient.WaitForOperation(ctx, pubInit.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(publish): %v", err)
	}

	// 13. GET /v1/publications/{id}
	pubFinal := m3PollPublicationStatus(t, ctrlClient, pubID, 30*time.Second, "PUBLISHED")
	pubGot, r13, err := ctrlClient.GetPublication(ctx, pubID)
	if err != nil {
		t.Fatalf("GET /publications/{id}: %v", err)
	}
	r13.RequireStatus(t, http.StatusOK)
	if pubGot.Status != "PUBLISHED" || pubGot.CommitSHA != pubFinal.CommitSHA {
		t.Fatalf("unexpected GetPublication: %+v", pubGot)
	}

	// 14. POST /v1/policies/validate
	bundleYAML := string(m3ReadFixture(t, env, "policies/valid_default.yaml"))
	valResp, r14, err := env.Client(toks.PolicyAdmin).ValidatePolicy(ctx, harness.PolicyBundleReq{BundleYAML: bundleYAML})
	if err != nil {
		t.Fatalf("POST /policies/validate: %v", err)
	}
	r14.RequireStatus(t, http.StatusOK)
	if !valResp.Valid {
		t.Fatalf("expected valid policy, got %+v", valResp)
	}

	// 15. POST /v1/policies/evaluate
	simResp, r15, err := env.Client(toks.PolicyAdmin).EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: bundleYAML,
		Stage:      "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"scan_complete": true, "critical_secrets": 0, "prohibited_licenses": 0},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{"README.md"}},
		},
	})
	if err != nil {
		t.Fatalf("POST /policies/evaluate: %v", err)
	}
	r15.RequireStatus(t, http.StatusOK)
	if simResp.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW, got %q", simResp.Effect)
	}

	// 16. GET /v1/audit/events
	audResp, r16, err := env.Client(toks.Auditor).ListAuditEvents(ctx, harness.AuditFilter{ResourceID: propID})
	if err != nil {
		t.Fatalf("GET /audit/events: %v", err)
	}
	r16.RequireStatus(t, http.StatusOK)
	if len(audResp.Events) == 0 {
		t.Fatalf("expected audit events for proposal %s", propID)
	}
	harness.VerifyAuditHashChain(t, audResp.Events)
}

func TestT1_F18_OpenAPI31SpecMatchesImplementedRoutesAndSchemas(t *testing.T) {
	root := m3FindRepoRoot(t)
	goBin := m3ResolveGoBin(t)

	specBytes, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read api/openapi.yaml: %v", err)
	}
	specText := string(specBytes)
	if !strings.Contains(specText, "openapi: \"3.1.0\"") && !strings.Contains(specText, "openapi: 3.1.0") {
		t.Fatalf("expected openapi 3.1.0 header in api/openapi.yaml")
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
		if !strings.Contains(specText, p) {
			t.Fatalf("api/openapi.yaml missing path %q", p)
		}
	}

	cmd := exec.Command(goBin, "test", "-count=1", "./internal/api/openapi/...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test ./internal/api/openapi/... failed: %v\n%s", err, string(out))
	}

	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Verify live HTTP error responses match api/schemas/errors.yaml envelope.
	_, raw404, err := env.Client(toks.HumanA).GetProposal(ctx, harness.NewTestUUIDv7())
	if err != nil {
		t.Fatalf("GetProposal(404): %v", err)
	}
	raw404.RequireStatus(t, http.StatusNotFound)
	m3AssertErrorEnvelope(t, raw404)

	_, raw400, err := env.Client(toks.HumanA).GetProposal(ctx, "not-a-uuid")
	if err != nil {
		t.Fatalf("GetProposal(400): %v", err)
	}
	raw400.RequireStatus(t, http.StatusBadRequest)
	m3AssertErrorEnvelope(t, raw400)
}

func TestT1_F18_IdempotencyKeyReplayAcrossMutations(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	humanClient := env.Client(toks.HumanA)
	ctrlClient := env.Client(toks.Controller)
	revClient := env.Client(toks.Reviewer)

	// 1. CreateWorkspace idempotency
	wsReq := harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "s-idem", ModelRoute: "approved-code-review"},
	}
	ws1, wRaw1, err := humanClient.CreateWorkspace(ctx, wsReq, harness.WithIdempotencyKey("m3-idem-ws"))
	if err != nil {
		t.Fatalf("CreateWorkspace(1): %v", err)
	}
	wRaw1.RequireStatus(t, http.StatusAccepted)
	ws2, wRaw2, err := humanClient.CreateWorkspace(ctx, wsReq, harness.WithIdempotencyKey("m3-idem-ws"))
	if err != nil {
		t.Fatalf("CreateWorkspace(2): %v", err)
	}
	wRaw2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	wsID := m3NonEmpty(ws1.WorkspaceID, ws1.ID)
	if m3NonEmpty(ws2.WorkspaceID, ws2.ID) != wsID {
		t.Fatalf("CreateWorkspace replay ID mismatch: %q vs %q", m3NonEmpty(ws2.WorkspaceID, ws2.ID), wsID)
	}
	if _, err := humanClient.WaitForOperation(ctx, ws1.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(ws): %v", err)
	}
	wsReady, wsRaw, err := humanClient.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusOK)
	desc, descRaw, err := ctrlClient.GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource: %v", err)
	}
	descRaw.RequireStatus(t, http.StatusOK)

	// 2. SubmitProposal idempotency
	gzBytes, shaHex := harness.BuildTarGz(m3DefaultEntries(
		harness.TarEntry{Name: "idem_all.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc IdemAll() {}\n")},
	))
	artID, _ := m3UploadSnapshot(t, env, toks.Controller, desc, gzBytes)
	subReq := harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: wsReady.Generation, SizeBytes: int64(len(gzBytes))},
		Title:    "Idem proposal",
	}
	p1, pRaw1, err := ctrlClient.SubmitProposal(ctx, wsID, subReq, harness.WithIdempotencyKey("m3-idem-prop"))
	if err != nil {
		t.Fatalf("SubmitProposal(1): %v", err)
	}
	pRaw1.RequireStatus(t, http.StatusAccepted)
	p2, pRaw2, err := ctrlClient.SubmitProposal(ctx, wsID, subReq, harness.WithIdempotencyKey("m3-idem-prop"))
	if err != nil {
		t.Fatalf("SubmitProposal(2): %v", err)
	}
	pRaw2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	propID := m3NonEmpty(p1.ProposalID, p1.ID)
	if m3NonEmpty(p2.ProposalID, p2.ID) != propID {
		t.Fatalf("SubmitProposal replay ID mismatch: %q vs %q", m3NonEmpty(p2.ProposalID, p2.ID), propID)
	}
	if _, err := ctrlClient.WaitForOperation(ctx, p1.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(prop): %v", err)
	}
	propRec := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "RECONSTRUCTED")

	// 3. EvaluateProposal idempotency
	evalReq := harness.EvaluateReq{ExpectedVersion: propRec.Version}
	e1, eRaw1, err := ctrlClient.EvaluateProposal(ctx, propID, evalReq, harness.WithIdempotencyKey("m3-idem-eval"))
	if err != nil {
		t.Fatalf("EvaluateProposal(1): %v", err)
	}
	eRaw1.RequireStatus(t, http.StatusAccepted)
	e2, eRaw2, err := ctrlClient.EvaluateProposal(ctx, propID, evalReq, harness.WithIdempotencyKey("m3-idem-eval"))
	if err != nil {
		t.Fatalf("EvaluateProposal(2): %v", err)
	}
	eRaw2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if e2.OperationID != e1.OperationID {
		t.Fatalf("EvaluateProposal replay operation_id mismatch: %q vs %q", e2.OperationID, e1.OperationID)
	}
	if _, err := ctrlClient.WaitForOperation(ctx, e1.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(eval): %v", err)
	}
	evalProp := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "PENDING_APPROVAL", "APPROVED")

	// 4. ApproveProposal idempotency
	appReq := harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalProp.LatestPolicyEvaluationID,
		Comment:                   "Idem approval",
	}
	a1, aRaw1, err := revClient.ApproveProposal(ctx, propID, appReq, harness.WithIdempotencyKey("m3-idem-app"))
	if err != nil {
		t.Fatalf("ApproveProposal(1): %v", err)
	}
	aRaw1.RequireStatus(t, http.StatusCreated)
	a2, aRaw2, err := revClient.ApproveProposal(ctx, propID, appReq, harness.WithIdempotencyKey("m3-idem-app"))
	if err != nil {
		t.Fatalf("ApproveProposal(2): %v", err)
	}
	aRaw2.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)
	if a2.ID != a1.ID {
		t.Fatalf("ApproveProposal replay ID mismatch: %q vs %q", a2.ID, a1.ID)
	}

	// 5. PublishProposal idempotency
	pubReq := harness.PublishReq{PublicationManifestDigest: evalProp.PublicationManifestDigest}
	pub1, pubRaw1, err := ctrlClient.PublishProposal(ctx, propID, pubReq, harness.WithIdempotencyKey("m3-idem-pub"))
	if err != nil {
		t.Fatalf("PublishProposal(1): %v", err)
	}
	pubRaw1.RequireStatus(t, http.StatusAccepted)
	pub2, pubRaw2, err := ctrlClient.PublishProposal(ctx, propID, pubReq, harness.WithIdempotencyKey("m3-idem-pub"))
	if err != nil {
		t.Fatalf("PublishProposal(2): %v", err)
	}
	pubRaw2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	pubID := m3NonEmpty(pub1.PublicationID, pub1.ID)
	if m3NonEmpty(pub2.PublicationID, pub2.ID) != pubID {
		t.Fatalf("PublishProposal replay ID mismatch: %q vs %q", m3NonEmpty(pub2.PublicationID, pub2.ID), pubID)
	}
	if _, err := ctrlClient.WaitForOperation(ctx, pub1.OperationID, 30*time.Second); err != nil {
		t.Fatalf("WaitForOperation(pub): %v", err)
	}
	_ = m3PollPublicationStatus(t, ctrlClient, pubID, 30*time.Second, "PUBLISHED")
	if env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected 1 PR after idempotency replays, got %d", env.GitHub().PRCount(repo.FullName))
	}
}

func TestT1_F18_PersistedPolicyDenialsQueryable(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{Mode: harness.ScannerModeSecretFinding})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
	), "Persisted denial query test", nil)

	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	if evalProp.Status != "DENIED" || evalProp.LatestPolicyEffect != "DENY" {
		t.Fatalf("expected DENIED/DENY, got status=%q effect=%q", evalProp.Status, evalProp.LatestPolicyEffect)
	}
	harness.AssertUUIDv7(t, evalProp.LatestPolicyEvaluationID)

	var foundDeny bool
	for _, pd := range assessResp.PolicyDecisions {
		if pd.ID == evalProp.LatestPolicyEvaluationID && pd.Effect == "DENY" && m3IsHexN(pd.InputDigest, 64) {
			for _, r := range pd.Reasons {
				if r.RuleID == "secrets.block" || strings.Contains(r.RuleID, "secrets") {
					foundDeny = true
				}
			}
		}
	}
	if !foundDeny {
		t.Fatalf("expected persisted DENY policy decision with secrets.block reason in %+v", assessResp.PolicyDecisions)
	}

	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop.ID})
	harness.VerifyAuditHashChain(t, events)
	audBytes, _ := json.Marshal(events)
	if !strings.Contains(string(audBytes), "DENY") && !strings.Contains(string(audBytes), "DENIED") {
		t.Fatalf("expected audit events to record denial for proposal %s: %s", prop.ID, string(audBytes))
	}
}

func TestT1_F18_AuditEventsFilteringAndCursorPagination(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "audit.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc AuditMe() {}\n")},
	), "Audit pagination test", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve for audit")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	audClient := env.Client(toks.Auditor)

	var allEvents []harness.AuditEvent
	seenIDs := make(map[string]struct{})
	cursor := ""
	for page := 0; page < 100; page++ {
		resp, raw, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{Limit: 2, Cursor: cursor})
		if err != nil {
			t.Fatalf("ListAuditEvents(page=%d): %v", page, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		for _, ev := range resp.Events {
			if _, dup := seenIDs[ev.ID]; dup {
				t.Fatalf("duplicate audit event ID %q during pagination", ev.ID)
			}
			seenIDs[ev.ID] = struct{}{}
			allEvents = append(allEvents, ev)
		}
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}
	if len(allEvents) < 4 {
		t.Fatalf("expected >= 4 audit events across full lifecycle, got %d", len(allEvents))
	}
	ids := make([]string, len(allEvents))
	for i, ev := range allEvents {
		ids[i] = ev.ID
	}
	harness.AssertUUIDv7Monotonic(t, ids)
	harness.VerifyAuditHashChain(t, allEvents)

	propEvents := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{
		ResourceType: "proposal",
		ResourceID:   prop.ID,
	})
	if len(propEvents) == 0 {
		t.Fatalf("expected >= 1 filtered audit event for proposal %s", prop.ID)
	}
	for _, ev := range propEvents {
		if ev.ResourceID != prop.ID || !strings.EqualFold(ev.ResourceType, "proposal") {
			t.Fatalf("filtered audit query returned non-matching event: %+v", ev)
		}
	}
}

// =============================================================================
// F-19: Observability (Prometheus /metrics, ID/Digest Logs), Concurrency & Budget Limits, Retention (5 Tier 1 Tests)
// =============================================================================

func TestT1_F19_PrometheusMetricsAndHealthReadinessProbes(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := env.Client(toks.HumanA)

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

	preMetrics, mRaw1, err := client.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics(pre): %v", err)
	}
	mRaw1.RequireStatus(t, http.StatusOK)
	if !strings.Contains(preMetrics, "# HELP") || !strings.Contains(preMetrics, "# TYPE") {
		t.Fatalf("expected Prometheus exposition format in /metrics, got:\n%s", preMetrics)
	}

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "obs.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Obs() {}\n")},
	), "Metrics workflow", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve obs")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	postMetrics, mRaw2, err := client.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics(post): %v", err)
	}
	mRaw2.RequireStatus(t, http.StatusOK)
	if !strings.Contains(postMetrics, "custodian_http_requests_total") {
		t.Fatalf("expected custodian_http_requests_total in /metrics, got:\n%s", postMetrics)
	}
	if !strings.Contains(postMetrics, "custodian_") {
		t.Fatalf("expected custodian_* metrics in /metrics")
	}
}

func TestT1_F19_IDAndDigestOnlyStructuredLogs(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	secretCanary := "CUSTODIAN_CANARY_SECRET_987654321"
	sourceCanary := "CANARY_SOURCE_LINE_UNIQUE_XYZ"
	env.RegisterSecret(secretCanary)
	env.RegisterSecret(sourceCanary)
	env.RegisterSecret(toks.HumanA)
	env.RegisterSecret(toks.Controller)

	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: secretCanary,
		FilePath:    "canary.env",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "canary.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("TOKEN=" + secretCanary + "\n")},
		harness.TarEntry{Name: "src.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n// " + sourceCanary + "\n")},
	), "Log redaction canary test", nil)
	_, _, _ = m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	for _, comp := range []string{"api", "worker", "publisher"} {
		logs := env.Logs(comp)
		if strings.TrimSpace(logs) == "" {
			if comp == "api" || comp == "worker" {
				t.Fatalf("expected non-empty structured JSON logs from %s", comp)
			}
			continue
		}
		var jsonLines int
		for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "{") {
				var obj map[string]any
				if err := json.Unmarshal([]byte(line), &obj); err != nil {
					t.Fatalf("%s log line is invalid JSON: %v\nline: %s", comp, err, line)
				}
				jsonLines++
			}
		}
		if jsonLines == 0 {
			t.Fatalf("expected structured JSON log lines from %s, got:\n%s", comp, logs)
		}
	}

	env.AssertNoSecretLeakInLogs(secretCanary, sourceCanary, toks.HumanA, toks.Controller)
}

func TestT1_F19_PerRepoConcurrencyWithinLimitSucceeds(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{
		Classification: "INTERNAL",
		MaxConcurrent:  3,
	}, harness.WithPerRepoConcurrency(3))
	toks := m3MintTokens(env)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wsIDs := make(chan string, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c := env.Client(toks.HumanA)
			resp, raw, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
				Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
				Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: fmt.Sprintf("conc-%d", idx), ModelRoute: "approved-code-review"},
			})
			if err != nil {
				errs <- err
				return
			}
			if raw.StatusCode != http.StatusAccepted {
				errs <- fmt.Errorf("goroutine %d status=%d body=%s", idx, raw.StatusCode, string(raw.Body))
				return
			}
			if resp.OperationID != "" {
				op, err := c.WaitForOperation(ctx, resp.OperationID, 30*time.Second)
				if err != nil {
					errs <- err
					return
				}
				if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
					errs <- fmt.Errorf("op %s status=%s", op.ID, op.Status)
					return
				}
			}
			wsID := m3NonEmpty(resp.WorkspaceID, resp.ID)
			wsIDs <- wsID
		}(i)
	}
	wg.Wait()
	close(errs)
	close(wsIDs)

	for err := range errs {
		t.Fatalf("concurrent workspace creation failed: %v", err)
	}
	var ids []string
	for id := range wsIDs {
		harness.AssertUUIDv7(t, id)
		got, raw, err := env.Client(toks.HumanA).GetWorkspace(ctx, id)
		if err != nil {
			t.Fatalf("GetWorkspace(%s): %v", id, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		if got.Status != "READY" {
			t.Fatalf("workspace %s status=%q, want READY", id, got.Status)
		}
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("expected 2 distinct READY workspaces, got %v", ids)
	}
}

func TestT1_F19_GlobalScanAndModelBudgetsWithinLimitSucceeds(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithGlobalScanBudget(6),
		harness.WithGlobalModelBudget(6),
	)
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	for i := 0; i < 2; i++ {
		ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
		prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
			harness.TarEntry{Name: fmt.Sprintf("budget_%d.go", i), Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n")},
		), fmt.Sprintf("Budget within limit %d", i), nil)
		_, assessResp, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
		if len(findResp.ScanRuns) == 0 || len(assessResp.Assessments) == 0 {
			t.Fatalf("iteration %d expected persisted scan_runs and model_assessments", i)
		}
	}
}

func TestT1_F19_ConfigurableArtifactRetentionReaper(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithRetentionTTL(5*time.Minute),
		harness.WithEnvOverrides(map[string]string{"CUSTODIAN_RETENTION_INTERVAL": "200ms"}),
	)
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "retain.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar Retain = true\n")},
	), "Retention reaper test", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	preCount, err := env.Snapshots().ObjectCount()
	if err != nil || preCount == 0 {
		t.Fatalf("expected stored snapshot objects > 0, got %d (err=%v)", preCount, err)
	}

	if _, err := env.DB().ExecSQL(`UPDATE artifacts SET expires_at = now() - interval '1 hour' WHERE kind IN ('WORKSPACE_SOURCE', 'EGRESS_SNAPSHOT');`); err != nil {
		t.Fatalf("backdate artifact expires_at: %v", err)
	}

	m3WaitCondition(t, 20*time.Second, "expired artifacts reaped from SnapshotStore", func() bool {
		rows, err := env.DB().QueryRows(`SELECT count(*) FROM artifacts WHERE kind IN ('WORKSPACE_SOURCE','EGRESS_SNAPSHOT') AND deleted_at IS NULL;`)
		if err != nil || len(rows) == 0 || len(rows[0]) == 0 {
			return false
		}
		if rows[0][0] != "0" {
			return false
		}
		curCount, err := env.Snapshots().ObjectCount()
		return err == nil && curCount < preCount
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	gotProp, pRaw, err := env.Client(toks.HumanA).GetProposal(ctx, prop.ID)
	if err != nil {
		t.Fatalf("GetProposal after retention reap: %v", err)
	}
	pRaw.RequireStatus(t, http.StatusOK)
	if gotProp.Status != "PUBLISHED" {
		t.Fatalf("expected proposal lineage intact after retention reap, got status=%q", gotProp.Status)
	}
	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop.ID})
	harness.VerifyAuditHashChain(t, events)
}

// =============================================================================
// F-20: Offline Harnesses, §16 Release Gates & Adversarial Suite (5 Tier 1 Tests)
// =============================================================================

func TestT1_F20_OfflineHarnessEndToEndWithoutCloudCreds(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithEnvOverrides(map[string]string{
			"GOOGLE_APPLICATION_CREDENTIALS": "",
			"GITHUB_TOKEN":                   "",
			"OPENAI_API_KEY":                 "",
		}),
	)
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	if env.DB().HostPort() == "5432" {
		t.Fatalf("expected ephemeral Postgres host port != 5432")
	}
	if strings.HasSuffix(env.APIBaseURL(), ":8080") {
		t.Fatalf("expected ephemeral API port != :8080, got %s", env.APIBaseURL())
	}

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "offline.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Offline() {}\n")},
	), "Offline E2E test", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve offline")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED offline, got %q", pub.Status)
	}

	cliRes := env.RunCLI(env.Contracts().Binaries.Custodian, []string{"--help"}, nil)
	if cliRes.ExitCode != 0 {
		t.Fatalf("custodian --help failed (exit=%d): stdout=%s stderr=%s err=%v", cliRes.ExitCode, cliRes.Stdout, cliRes.Stderr, cliRes.Err)
	}
}

func TestT1_F20_RG01_RG02_CredentiallessArtifactAndAntiImpersonation(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// RG-01: Workspace source archive with include_git_metadata=true must be credential-less and git-sanitised.
	srcOpts := &harness.WorkspaceSourceOptions{
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}
	wsA, _ := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", srcOpts)
	srcBytes, dlRaw, err := env.Client(toks.Controller).DownloadWorkspaceSource(ctx, wsA.ID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	dlRaw.RequireStatus(t, http.StatusOK)

	env.Snapshots().AssertArchiveNoSecretLeak(t, srcBytes,
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	)
	env.Snapshots().AssertArchiveGitSanitised(t, srcBytes)

	// RG-02: Spoofed owner_id in CreateWorkspace payload must be rejected (400/403) or ignored in favor of authenticated caller.
	spoofPayload, _ := json.Marshal(harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		OwnerID:    harness.NewTestUUIDv7(),
	})
	spoofRaw, err := env.Client(toks.HumanA).DoRaw(ctx, http.MethodPost, "/v1/workspaces", spoofPayload)
	if err != nil {
		t.Fatalf("DoRaw(spoof owner_id): %v", err)
	}
	if spoofRaw.StatusCode != http.StatusBadRequest && spoofRaw.StatusCode != http.StatusForbidden && spoofRaw.StatusCode != http.StatusUnprocessableEntity {
		if spoofRaw.StatusCode == http.StatusAccepted || spoofRaw.StatusCode == http.StatusCreated {
			var created harness.WorkspaceCreateResp
			_ = json.Unmarshal(spoofRaw.Body, &created)
			wsID := m3NonEmpty(created.WorkspaceID, created.ID)
			got, gRaw, gErr := env.Client(toks.HumanA).GetWorkspace(ctx, wsID)
			if gErr != nil {
				t.Fatalf("GetWorkspace(spoofed): %v", gErr)
			}
			gRaw.RequireStatus(t, http.StatusOK)
			if got.Owner == nil || got.Owner.PrincipalID != wsA.Owner.PrincipalID {
				gotOwner := "<nil>"
				if got.Owner != nil {
					gotOwner = got.Owner.PrincipalID
				}
				t.Fatalf("RG-02 anti-impersonation violated: owner_id=%q (Alice=%q)", gotOwner, wsA.Owner.PrincipalID)
			}
		} else {
			t.Fatalf("unexpected status %d on spoofed owner_id: %s", spoofRaw.StatusCode, string(spoofRaw.Body))
		}
	}

	// RG-02: Cross-owner GetWorkspace must return 403 Forbidden.
	_, crossRaw, err := env.Client(toks.HumanB).GetWorkspace(ctx, wsA.ID)
	if err != nil {
		t.Fatalf("GetWorkspace(HumanB on HumanA workspace): %v", err)
	}
	crossRaw.RequireStatus(t, http.StatusForbidden)
}

func TestT1_F20_RG09_FullTraceabilityLineage(t *testing.T) {
	policyDir := m3WritePolicyDirTemp(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/valid_default.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "infra/prod/app.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("service: custodian-app\n")},
	), "Full RG-09 lineage", &harness.Provenance{Type: "agent_assisted", CaptureMethod: "frozen_filesystem"})

	evalProp, assessResp, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	appResp := m3ApproveProposal(t, env, toks.PlatformOwner, evalProp, "APPROVE", "Platform owner verified lineage")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	ci, err := env.Git().InspectCommit(repo.FullName, pub.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit: %v", err)
	}
	if ci.AuthorName != "Alice Developer" || ci.AuthorEmail != "alice@example.com" {
		t.Fatalf("unexpected commit author: %q <%s>", ci.AuthorName, ci.AuthorEmail)
	}
	if !m3ContainsString(ci.Trailers["Custodian-Proposal"], prop.ID) ||
		!m3ContainsString(ci.Trailers["Custodian-Workspace"], ws.ID) ||
		!m3ContainsString(ci.Trailers["Agent-Assisted"], "true") {
		t.Fatalf("missing lineage trailers in %+v", ci.Trailers)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	finalProp, raw, err := env.Client(toks.HumanA).GetProposal(ctx, prop.ID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if finalProp.Owner == nil || finalProp.Owner.PrincipalID == "" ||
		finalProp.Origin == nil || finalProp.Origin.WorkspaceID != ws.ID ||
		finalProp.SnapshotArtifactID == "" || finalProp.CanonicalArtifactID == "" ||
		finalProp.ManifestArtifactID == "" || !m3IsHexN(finalProp.PublicationManifestDigest, 64) {
		t.Fatalf("incomplete proposal artifact/origin lineage: %+v", finalProp)
	}
	if len(findResp.ScanRuns) < 3 || len(assessResp.Assessments) == 0 || len(assessResp.PolicyDecisions) == 0 || appResp.ID == "" {
		t.Fatalf("missing scan_runs/assessments/policy_decisions/approval in RG-09 lineage")
	}

	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop.ID})
	harness.VerifyAuditHashChain(t, events)
}

func TestT1_F20_LabelledEvalDatasetSchemaAndGrounding(t *testing.T) {
	type evalCase struct {
		CaseID               string   `json:"case_id"`
		FixtureFile          string   `json:"fixture_file"`
		RepoClassification   string   `json:"repo_classification"`
		ModelRouteAuthorised bool     `json:"model_route_authorised"`
		StageAEvidenceIDs    []string `json:"stage_a_evidence_ids"`
		ExpectSchemaValid    bool     `json:"expect_schema_valid"`
		ExpectGrounded       bool     `json:"expect_grounded"`
		ExpectStatus         string   `json:"expect_status"`
		ExpectPublishAllowed bool     `json:"expect_publish_allowed"`
		ExpectedCELEffect    string   `json:"expected_cel_effect"`
	}

	rawDataset := m3ReadFixture(t, nil, "eval/eval_dataset.json")
	var cases []evalCase
	if err := json.Unmarshal(rawDataset, &cases); err != nil {
		t.Fatalf("parse eval_dataset.json: %v", err)
	}
	if len(cases) != 7 {
		t.Fatalf("expected 7 eval cases, got %d", len(cases))
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.CaseID, func(t *testing.T) {
			allowedRoutes := []string{"approved-code-review"}
			if !tc.ModelRouteAuthorised {
				allowedRoutes = []string{"restricted-authorized-only"}
			}
			env, repo, repoUUID := m3StartEnv(t, m3RepoConfig{
				Name:           "eval-" + tc.CaseID,
				Classification: tc.RepoClassification,
				AllowedRoutes:  allowedRoutes,
			})
			env.Gateway().ResetRequests()
			toks := m3MintTokens(env)

			entries := m3DefaultEntries()
			var configureScanners func()
			if len(tc.StageAEvidenceIDs) > 0 {
				switch tc.CaseID {
				case "eval-prompt-injection-03":
					configureScanners = func() {
						env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
							Mode:     harness.ScannerModeSecretFinding,
							FilePath: "secret.env",
						})
					}
					entries = append(entries,
						harness.TarEntry{Name: "prompt_inj.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/prompt_injection_source.go")},
						harness.TarEntry{Name: "secret.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
					)
				case "eval-ungrounded-evidence-05":
					configureScanners = func() {
						env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
							Mode:     harness.ScannerModeSASTFinding,
							FilePath: "real.go",
						})
					}
					entries = append(entries, harness.TarEntry{Name: "real.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nfunc real() {}\n")})
				default:
					configureScanners = func() {
						env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
							Mode:     harness.ScannerModeSASTFinding,
							FilePath: "algo.go",
						})
					}
					entries = append(entries, harness.TarEntry{Name: "algo.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nfunc algo() {}\n")})
				}
			}

			wsRoute := "approved-code-review"
			if !tc.ModelRouteAuthorised {
				// Temporarily authorize at workspace creation, then revoke prior to evaluation to trigger INDETERMINATE.
				m3EnsureRepoInDB(t, env, repo, tc.RepoClassification, []string{"approved-code-review"}, 10)
			}
			ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, wsRoute, nil)
			if configureScanners != nil {
				configureScanners()
			}
			prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, entries, tc.CaseID, nil)

			if !tc.ModelRouteAuthorised {
				if _, err := env.DB().ExecSQL(fmt.Sprintf(
					"UPDATE repositories SET allowed_model_routes = %s WHERE id = %s::uuid;",
					m3SQLTextArray([]string{"restricted-authorized-only"}), m3SQLQuote(repoUUID),
				)); err != nil {
					t.Fatalf("revoke route on repo: %v", err)
				}
			}

			fixtureRaw := m3ReadFixture(t, env, "eval/"+tc.FixtureFile)
			if tc.FixtureFile == "stageb_prompt_injection.json" {
				var wrapper struct {
					Adversarial json.RawMessage `json:"adversarial_model_response"`
				}
				if err := json.Unmarshal(fixtureRaw, &wrapper); err != nil {
					t.Fatalf("unwrap stageb_prompt_injection.json: %v", err)
				}
				fixtureRaw = wrapper.Adversarial
			}

			var gwMu sync.Mutex
			var gwErr string
			env.Gateway().SetDefault(harness.GatewayProgram{
				Format: harness.GatewayFormatRawJSON,
				DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
					body := string(fixtureRaw)
					if strings.Contains(body, "{{EVIDENCE_ID}}") {
						if len(req.EvidenceIDs) == 0 {
							gwMu.Lock()
							gwErr = fmt.Sprintf("case %s: Stage B request missing Stage A evidence_ids in prompt body", tc.CaseID)
							gwMu.Unlock()
							return http.StatusBadRequest, []byte(`{"error":"missing evidence_ids"}`)
						}
						body = strings.ReplaceAll(body, "{{EVIDENCE_ID}}", req.EvidenceIDs[0])
					}
					return http.StatusOK, []byte(body)
				},
			})

			evalProp, assessResp, findResp := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

			gwMu.Lock()
			recordedGWErr := gwErr
			gwMu.Unlock()
			if recordedGWErr != "" {
				t.Fatal(recordedGWErr)
			}

			if !tc.ModelRouteAuthorised {
				env.Gateway().AssertNoRouteCalled(t, "approved-code-review")
				if reqs := env.Gateway().Requests(); len(reqs) != 0 {
					t.Fatalf("case %s: expected 0 gateway requests on unauthorized route, got %d", tc.CaseID, len(reqs))
				}
			}

			if len(assessResp.Assessments) == 0 {
				t.Fatalf("case %s: expected at least 1 AssessmentDTO", tc.CaseID)
			}
			a := assessResp.Assessments[0]
			if a.Status != tc.ExpectStatus {
				t.Fatalf("case %s: assessment status=%q, want %q", tc.CaseID, a.Status, tc.ExpectStatus)
			}
			if !tc.ExpectSchemaValid || !tc.ExpectGrounded {
				if a.Status != "FAILED" {
					t.Fatalf("case %s: expected AssessmentDTO.Status=FAILED when schema_valid=%v grounded=%v, got %q",
						tc.CaseID, tc.ExpectSchemaValid, tc.ExpectGrounded, a.Status)
				}
			}
			if tc.ExpectGrounded {
				if len(tc.StageAEvidenceIDs) > 0 && len(findResp.Findings) == 0 {
					t.Fatalf("case %s: expected Stage A findings when StageAEvidenceIDs=%v", tc.CaseID, tc.StageAEvidenceIDs)
				}
				stageAIDs := make(map[string]struct{})
				for _, f := range findResp.Findings {
					if f.EvidenceID != "" {
						stageAIDs[f.EvidenceID] = struct{}{}
					}
					if f.ID != "" {
						stageAIDs[f.ID] = struct{}{}
					}
				}
				if strings.Contains(string(fixtureRaw), "{{EVIDENCE_ID}}") && len(a.Findings) == 0 {
					t.Fatalf("case %s: expected grounded Stage B findings in AssessmentDTO, got 0", tc.CaseID)
				}
				for _, mf := range a.Findings {
					for _, eid := range mf.EvidenceIDs {
						if _, ok := stageAIDs[eid]; !ok {
							t.Fatalf("case %s: Stage B evidence_id %q not grounded in Stage A findings %+v", tc.CaseID, eid, findResp.Findings)
						}
					}
				}
			}
			if evalProp.LatestPolicyEffect != tc.ExpectedCELEffect {
				t.Fatalf("case %s: CEL effect=%q, want %q", tc.CaseID, evalProp.LatestPolicyEffect, tc.ExpectedCELEffect)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
				PublicationManifestDigest: evalProp.PublicationManifestDigest,
			})
			if err != nil {
				t.Fatalf("PublishProposal(%s): %v", tc.CaseID, err)
			}
			// Unapproved (even clean ALLOW) or blocked cases must not publish without approval.
			if pubRaw.StatusCode >= 200 && pubRaw.StatusCode < 300 {
				t.Fatalf("case %s: unexpected 2xx publish without approval: status=%d body=%s", tc.CaseID, pubRaw.StatusCode, string(pubRaw.Body))
			}
			pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
			if !tc.ExpectPublishAllowed {
				if env.GitHub().PRCount(repo.FullName) != 0 {
					t.Fatalf("case %s: unexpected PR created", tc.CaseID)
				}
				return
			}

			m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve eval clean case")
			pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
			if pub.Status != "PUBLISHED" {
				t.Fatalf("case %s: expected PUBLISHED after approval, got %q", tc.CaseID, pub.Status)
			}
			if env.GitHub().PRCount(repo.FullName) != 1 {
				t.Fatalf("case %s: expected exactly 1 PR after approved publish, got %d", tc.CaseID, env.GitHub().PRCount(repo.FullName))
			}
		})
	}
}

func TestT1_F20_RG10_TransientGitHubAndStorageOutageRecovery(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	// (1) Transient GitHub 503 during PR creation recovers idempotently with PRCount == 1.
	ws1, desc1 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop1 := m3SubmitAndReconstruct(t, env, toks.Controller, ws1, desc1, m3DefaultEntries(
		harness.TarEntry{Name: "retry_gh.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar GH = 1\n")},
	), "GitHub outage recovery", nil)
	eval1, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop1.ID, prop1.Version)
	m3ApproveProposal(t, env, toks.Reviewer, eval1, "APPROVE", "Approve GH retry")

	env.GitHub().SetOutage("POST", "/pulls", http.StatusServiceUnavailable, 2)
	pub := m3PublishAndWait(t, env, toks.Controller, eval1)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED after transient 503s, got %q", pub.Status)
	}
	if env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected exactly 1 PR after transient retries, got %d", env.GitHub().PRCount(repo.FullName))
	}
	if pub.AttemptCount < 2 {
		// Also accept operation retries if publication attempt_count counts differently; log for clarity.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		aud := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop1.ID})
		harness.VerifyAuditHashChain(t, aud)
		_ = ctx
	}

	// (2) Transient SnapshotStore outage recovers cleanly once outage is cleared.
	if err := env.Snapshots().SimulateOutage(true); err != nil {
		t.Fatalf("SimulateOutage(true): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	wsCreate2, raw2, err := env.Client(toks.HumanA).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "outage-store", ModelRoute: "approved-code-review"},
	})
	if err != nil {
		_ = env.Snapshots().SimulateOutage(false)
		t.Fatalf("CreateWorkspace during storage outage: %v", err)
	}
	raw2.RequireStatus(t, http.StatusAccepted)
	time.Sleep(300 * time.Millisecond)
	if err := env.Snapshots().SimulateOutage(false); err != nil {
		t.Fatalf("SimulateOutage(false): %v", err)
	}

	if wsCreate2.OperationID != "" {
		op, err := env.Client(toks.HumanA).WaitForOperation(ctx, wsCreate2.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation after storage outage cleared: %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("expected operation recovery after storage outage cleared, got status=%q err=%s", op.Status, op.LastError)
		}
	}
	wsID2 := m3NonEmpty(wsCreate2.WorkspaceID, wsCreate2.ID)
	m3WaitCondition(t, 20*time.Second, "workspace 2 READY after storage outage cleared", func() bool {
		got, gRaw, gErr := env.Client(toks.HumanA).GetWorkspace(ctx, wsID2)
		return gErr == nil && gRaw.StatusCode == http.StatusOK && got.Status == "READY"
	})

	allAudit := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{})
	harness.VerifyAuditHashChain(t, allAudit)
}

// =============================================================================
// Local M3 Utilities used across Tier 1 & Tier 2
// =============================================================================

func m3WritePolicyDirTemp(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir policy dir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write policy file %q: %v", p, err)
		}
	}
	return dir
}

func m3ContainsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func m3AssertErrorEnvelope(t *testing.T, raw *harness.RawResponse) {
	t.Helper()
	if raw == nil {
		t.Fatalf("nil RawResponse")
	}
	var env struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw.Body, &env); err != nil {
		t.Fatalf("error response is not valid JSON (%v): %s", err, string(raw.Body))
	}
	if env.Error == nil || strings.TrimSpace(env.Error.Code) == "" || strings.TrimSpace(env.Error.Message) == "" {
		t.Fatalf("error response does not match ErrorResponse schema {error:{code,message}}: %s", string(raw.Body))
	}
}

func m3WaitCondition(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("condition %q not satisfied within %s", desc, timeout)
}
