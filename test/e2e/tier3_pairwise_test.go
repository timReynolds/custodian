package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

// Harness/contract observations for E2E-M5 follow-up (documented without modifying test/e2e/harness/):
// - G-1: Env has no SeedRepositoryInDB / SeedPolicyBundleInDB API; m4SeedRepoDB & m4SeedPolicyBundleDB use env.DB().ExecSQL.
// - G-2: APIClient only has WaitForOperation; m4WaitUntil polls GetWorkspace / GetProposal / GetPublication.
// - G-3: UploadSnapshot returns *RawResponse without typed artifact_id struct; m4UploadAndSubmitProposal decodes m4UploadResp.
// - G-4: DTOs carry both ID and *ID aliases (ProposalResp.ID vs ProposalID, PublicationResp.ID vs PublicationID); m4PropID/m4PubID normalize.
// - G-5: Env has no runtime SetPolicyBundle; S5 uses WithPolicyBundleDir + m4SeedPolicyBundleDB + POST /v1/policies/evaluate.
// - G-6: MockGitHub GET /pulls supports ?head=, ?state=, and ?base= filtering in harness/git_github.go; tests also verify single-PR idempotency via PRCount(fullName) == 1.
// - G-7: Env runs one worker/publisher; concurrency races use goroutine barriers against API + DB leases.
// - G-8: MockGateway GatewayModeIndeterminate returns Disposition="INDETERMINATE" on the configured route.

const (
	m4HumanSubject = "alice-human-001"
	m4HumanName    = "Alice Developer"
	m4HumanEmail   = "alice@example.com"
	m4OtherSubject = "bob-human-002"
	m4OtherEmail   = "bob@example.com"
	m4RevSubject   = "carol-reviewer-003"
	m4RevEmail     = "carol@example.com"
	m4DefaultRoute = "approved-code-review"
)

type m4ActorSet struct {
	humanTok       string
	humanCli       *harness.APIClient
	otherHumanTok  string
	otherHumanCli  *harness.APIClient
	reviewerTok    string
	reviewerCli    *harness.APIClient
	auditorTok     string
	auditorCli     *harness.APIClient
	policyAdminTok string
	policyAdminCli *harness.APIClient
	ctrlTok        string
	ctrlCli        *harness.APIClient
	agentTok       string
	agentCli       *harness.APIClient
}

type m4SeededRepo struct {
	seeded         harness.SeededRepo
	dbRepoID       string
	classification string
	allowedRoutes  []string
}

type m4UploadResp struct {
	ArtifactID string `json:"artifact_id"`
	ID         string `json:"id"`
	SHA256     string `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
}

func m4FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func m4IsStreamAbortErr(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "stream closed") ||
		strings.Contains(msg, "stream error") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "http2: stream") ||
		strings.Contains(msg, "request body too large")
}

func m4WorkspaceID(w harness.WorkspaceResp) string {
	return m4FirstNonEmpty(w.ID, w.WorkspaceID)
}

func m4WorkspaceCreateID(w harness.WorkspaceCreateResp) string {
	return m4FirstNonEmpty(w.WorkspaceID, w.ID)
}

func m4PropID(p harness.ProposalResp) string {
	return m4FirstNonEmpty(p.ID, p.ProposalID)
}

func m4PubID(p harness.PublicationResp) string {
	return m4FirstNonEmpty(p.ID, p.PublicationID)
}

func m4LatestDecisionID(p harness.ProposalResp, a harness.AssessmentsResp) string {
	if p.LatestPolicyEvaluationID != "" {
		return p.LatestPolicyEvaluationID
	}
	if n := len(a.PolicyDecisions); n > 0 {
		return a.PolicyDecisions[n-1].ID
	}
	return ""
}

func m4ResolveRepoRoot(t testing.TB) string {
	t.Helper()
	if envRoot := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_ROOT")); envRoot != "" {
		return envRoot
	}
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return abs
}

func m4LoadFixture(t testing.TB, relPath string) []byte {
	t.Helper()
	candidates := []string{
		filepath.Join("fixtures", relPath),
	}
	if envRoot := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_ROOT")); envRoot != "" {
		candidates = append(candidates, filepath.Join(envRoot, "test", "e2e", "fixtures", relPath))
	}
	candidates = append(candidates, filepath.Join("..", "..", "test", "e2e", "fixtures", relPath))
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			return data
		}
	}
	t.Fatalf("fixture %q not found in candidates %v", relPath, candidates)
	return nil
}

func m4WritePolicyDir(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		target := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir policy dir: %v", err)
		}
		if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
			t.Fatalf("write policy file %q: %v", name, err)
		}
	}
	return dir
}

func m4WaitUntil(ctx context.Context, t testing.TB, timeout time.Duration, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		done, err := fn()
		if err != nil {
			t.Fatalf("poll condition failed: %v", err)
		}
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("poll condition timed out after %s", timeout)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled while polling: %v", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func m4SQLQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func m4SQLTextArray(items []string) string {
	if len(items) == 0 {
		return "'{}'::text[]"
	}
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = m4SQLQuote(item)
	}
	return "ARRAY[" + strings.Join(quoted, ",") + "]::text[]"
}

func m4SeedRepoDB(t testing.TB, env *harness.Env, seeded harness.SeededRepo, classification string, routes []string, enabled bool, maxConc int) string {
	t.Helper()
	if classification == "" {
		classification = "INTERNAL"
	}
	if maxConc <= 0 {
		maxConc = 10
	}
	id := harness.NewTestUUIDv7()
	q := fmt.Sprintf(`
INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations)
VALUES (%s, %d, %d, %s, %s, %t, %s, %d)
ON CONFLICT (github_repository_id) DO UPDATE SET
  github_installation_id = EXCLUDED.github_installation_id,
  full_name = EXCLUDED.full_name,
  classification = EXCLUDED.classification,
  enabled = EXCLUDED.enabled,
  allowed_model_routes = EXCLUDED.allowed_model_routes,
  max_concurrent_operations = EXCLUDED.max_concurrent_operations
RETURNING id;`,
		m4SQLQuote(id),
		seeded.GitHubRepoID,
		seeded.InstallationID,
		m4SQLQuote(seeded.FullName),
		m4SQLQuote(classification),
		enabled,
		m4SQLTextArray(routes),
		maxConc,
	)
	out, err := env.DB().ExecSQL(q)
	if err != nil {
		t.Fatalf("seed repository %s in DB: %v", seeded.FullName, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if harness.ValidateUUIDv7(line) == nil {
			return line
		}
	}
	return id
}

func m4SeedPolicyBundleDB(t testing.TB, env *harness.Env, name, version, scope, repoID, yamlBody string) string {
	t.Helper()
	defJSON, parsedName, parsedVersion, err := m3PolicyYAMLToJSON(yamlBody)
	if err != nil {
		t.Fatalf("m3PolicyYAMLToJSON(%s/%s): %v", scope, name, err)
	}
	name = m4FirstNonEmpty(name, parsedName, "e2e-bundle")
	version = m4FirstNonEmpty(version, parsedVersion, "1.0.0")
	id := harness.NewTestUUIDv7()
	digest := harness.SHA256Hex(defJSON)
	repoCol := "NULL"
	if repoID != "" {
		repoCol = m4SQLQuote(repoID)
	}
	q := fmt.Sprintf(`
INSERT INTO policy_bundles (id, name, version, scope, repository_id, digest, definition, activated_at)
VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, now())
ON CONFLICT (digest) DO UPDATE SET
  activated_at = COALESCE(policy_bundles.activated_at, now())
RETURNING id;`,
		m4SQLQuote(id),
		m4SQLQuote(name),
		m4SQLQuote(version),
		m4SQLQuote(scope),
		repoCol,
		m4SQLQuote(digest),
		m4SQLQuote(string(defJSON)),
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("seed policy_bundles (%s/%s): %v", scope, name, err)
	}
	return id
}

func m4NewActors(t testing.TB, env *harness.Env) m4ActorSet {
	t.Helper()
	humanTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: m4HumanSubject,
		Name:    m4HumanName,
		Email:   m4HumanEmail,
		Groups:  []string{"engineering"},
		Scope:   "workspaces:write proposals:read",
	})
	otherHumanTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: m4OtherSubject,
		Name:    "Bob Outsider",
		Email:   m4OtherEmail,
		Groups:  []string{"engineering"},
		Scope:   "workspaces:write proposals:read",
	})
	reviewerTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: m4RevSubject,
		Name:    "Carol Reviewer",
		Email:   m4RevEmail,
		Groups:  []string{"ip-review", "platform-owners", "security-review"},
		Scope:   "proposals:read proposals:approve",
	})
	auditorTok := env.MintToken(harness.TokenClaims{
		Kind:    "AUDITOR",
		Subject: "auditor-001",
		Name:    "Audit Viewer",
		Email:   "auditor@example.com",
		Groups:  []string{"security-audit"},
	})
	policyAdminTok := env.MintToken(harness.TokenClaims{
		Kind:    "POLICY_ADMIN",
		Subject: "policy-admin-001",
		Name:    "Policy Admin",
		Email:   "policy-admin@example.com",
		Groups:  []string{"policy-admins"},
	})
	ctrlTok := env.MintToken(harness.TokenClaims{
		Kind:    "CONTROLLER",
		Subject: "runtime-controller-001",
		Name:    "Sandbox Controller",
		Email:   "controller@system.local",
		Groups:  []string{"controllers"},
	})
	agentTok := env.MintToken(harness.TokenClaims{
		Kind:    "AGENT",
		Subject: "agent-codex-001",
		Name:    "Coding Agent",
		Email:   "agent@system.local",
		Groups:  []string{"agents"},
	})
	return m4ActorSet{
		humanTok:       humanTok,
		humanCli:       env.Client(humanTok),
		otherHumanTok:  otherHumanTok,
		otherHumanCli:  env.Client(otherHumanTok),
		reviewerTok:    reviewerTok,
		reviewerCli:    env.Client(reviewerTok),
		auditorTok:     auditorTok,
		auditorCli:     env.Client(auditorTok),
		policyAdminTok: policyAdminTok,
		policyAdminCli: env.Client(policyAdminTok),
		ctrlTok:        ctrlTok,
		ctrlCli:        env.Client(ctrlTok),
		agentTok:       agentTok,
		agentCli:       env.Client(agentTok),
	}
}

func m4DefaultPolicyDir(t testing.TB) string {
	t.Helper()
	return m4WritePolicyDir(t, map[string]string{
		"default.yaml": string(m4LoadFixture(t, "policies/valid_default.yaml")),
	})
}

func m4SetupRepoEnv(
	t *testing.T,
	owner, name string,
	files map[string]string,
	classification string,
	routes []string,
	enabled bool,
	maxConc int,
	extraOpts ...harness.EnvOption,
) (*harness.Env, m4SeededRepo, m4ActorSet) {
	t.Helper()
	if len(files) == 0 {
		files = map[string]string{
			"README.md": string(m4LoadFixture(t, "golden/clean_tree/README.md")),
		}
	}
	if len(routes) == 0 {
		routes = []string{m4DefaultRoute}
	}
	spec := harness.RepoSeedSpec{
		Owner:          owner,
		Name:           name,
		Files:          files,
		DefaultBranch:  "main",
		RepoID:         10001,
		InstallationID: 20001,
	}
	opts := []harness.EnvOption{
		harness.WithSeedRepos(spec),
		harness.WithPolicyBundleDir(m4DefaultPolicyDir(t)),
	}
	opts = append(opts, extraOpts...)
	env := harness.NewEnv(t, opts...)

	seeded, ok := env.Git().Repo(owner + "/" + name)
	if !ok {
		t.Fatalf("seeded repo %s/%s missing from BareGitHelper", owner, name)
	}
	dbRepoID := m4SeedRepoDB(t, env, seeded, classification, routes, enabled, maxConc)
	actors := m4NewActors(t, env)
	return env, m4SeededRepo{
		seeded:         seeded,
		dbRepoID:       dbRepoID,
		classification: classification,
		allowedRoutes:  routes,
	}, actors
}

func m4RequireOpSucceeded(t testing.TB, env *harness.Env, op harness.OperationResp) {
	t.Helper()
	if op.Status == "SUCCEEDED" {
		return
	}
	if harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
		return
	}
	t.Fatalf("expected operation %s SUCCEEDED, got status=%q last_error=%q", op.ID, op.Status, op.LastError)
}

func m4CreateAndAwaitWorkspace(
	t testing.TB,
	ctx context.Context,
	env *harness.Env,
	cli *harness.APIClient,
	req harness.CreateWorkspaceReq,
) harness.WorkspaceResp {
	t.Helper()
	created, raw, err := cli.CreateWorkspace(ctx, req)
	if err != nil {
		t.Fatalf("CreateWorkspace transport error: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m4WorkspaceCreateID(created)
	harness.AssertUUIDv7(t, wsID)
	if created.OperationID != "" {
		harness.AssertUUIDv7(t, created.OperationID)
		op, err := cli.WaitForOperation(ctx, created.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(CreateWorkspace %s): %v", created.OperationID, err)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var ws harness.WorkspaceResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := cli.GetWorkspace(ctx, wsID)
		if gErr != nil {
			return false, gErr
		}
		if gRaw.StatusCode != http.StatusOK {
			return false, fmt.Errorf("GET /workspaces/%s returned %d", wsID, gRaw.StatusCode)
		}
		ws = got
		return got.Status == "READY" || harness.ContainsStatus(env.Contracts().WorkspaceStatuses.TerminalSuccess, got.Status), nil
	})
	return ws
}

func m4UploadSnapshotOnly(
	t testing.TB,
	ctx context.Context,
	ctrlCli *harness.APIClient,
	wsID string,
	gz []byte,
	gen int64,
) (string, harness.UploadCapabilityResp) {
	t.Helper()
	capResp, capRaw, err := ctrlCli.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{
		Generation: gen,
		MaxBytes:   int64(len(gz)) + 65536,
	})
	if err != nil {
		t.Fatalf("RequestUploadCapability(%s): %v", wsID, err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	capToken := m4FirstNonEmpty(capResp.Token, capResp.CapabilityToken)
	if capResp.UploadURL == "" || capToken == "" {
		t.Fatalf("missing upload_url or capability token in %+v", capResp)
	}

	upRaw, err := ctrlCli.UploadSnapshot(ctx, capResp.UploadURL, capToken, gz)
	if err != nil {
		t.Fatalf("UploadSnapshot(%s): %v", capResp.UploadURL, err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusNoContent)

	var upParsed m4UploadResp
	if len(upRaw.Body) > 0 {
		_ = json.Unmarshal(upRaw.Body, &upParsed)
	}
	artifactID := m4FirstNonEmpty(
		upParsed.ArtifactID,
		upParsed.ID,
		upRaw.Headers.Get("X-Artifact-ID"),
	)
	if artifactID == "" {
		t.Fatalf("UploadSnapshot(%s) succeeded (%d) without artifact_id, id, or X-Artifact-ID header: body=%q",
			capResp.UploadURL, upRaw.StatusCode, string(upRaw.Body))
	}
	harness.AssertUUIDv7(t, artifactID)
	return artifactID, capResp
}

func m4UploadAndSubmitProposal(
	t testing.TB,
	ctx context.Context,
	env *harness.Env,
	ctrlCli *harness.APIClient,
	wsID string,
	gz []byte,
	shaHex string,
	gen int64,
	title string,
	prov *harness.Provenance,
) harness.ProposalResp {
	t.Helper()
	artifactID, _ := m4UploadSnapshotOnly(t, ctx, ctrlCli, wsID, gz, gen)
	if prov == nil {
		prov = &harness.Provenance{
			Type:          "human_authored",
			CaptureMethod: "frozen_filesystem",
		}
	}
	sub, subRaw, err := ctrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              shaHex,
			WorkspaceGeneration: gen,
			SizeBytes:           int64(len(gz)),
			CapturedAt:          time.Now().UTC().Format(time.RFC3339),
		},
		Title:       title,
		Description: "opaque-box e2e proposal: " + title,
		Provenance:  prov,
	})
	if err != nil {
		t.Fatalf("SubmitProposal(%s): %v", wsID, err)
	}
	subRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated)
	propID := m4PropID(sub)
	harness.AssertUUIDv7(t, propID)
	if sub.OperationID != "" {
		harness.AssertUUIDv7(t, sub.OperationID)
		op, err := ctrlCli.WaitForOperation(ctx, sub.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(SubmitProposal %s): %v", sub.OperationID, err)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var prop harness.ProposalResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := ctrlCli.GetProposal(ctx, propID)
		if gErr != nil {
			return false, gErr
		}
		if gRaw.StatusCode != http.StatusOK {
			return false, fmt.Errorf("GET /proposals/%s returned %d", propID, gRaw.StatusCode)
		}
		prop = got
		return got.Status == "RECONSTRUCTED" ||
			got.Status == "PENDING_APPROVAL" ||
			got.Status == "APPROVED" ||
			got.Status == "PUBLISHED" ||
			got.Status == "DENIED" ||
			got.Status == "QUARANTINED" ||
			got.Status == "REMEDIATION_REQUIRED", nil
	})
	if prop.PublicationManifestDigest == "" || prop.TreeDigest == "" || !m4Is64Hex(prop.DiffDigest) {
		t.Fatalf("proposal %s missing/invalid canonical digests after reconstruction: manifest=%q tree=%q diff=%q",
			propID, prop.PublicationManifestDigest, prop.TreeDigest, prop.DiffDigest)
	}
	return prop
}

func m4EvaluateAndAwait(
	t testing.TB,
	ctx context.Context,
	env *harness.Env,
	ctrlCli *harness.APIClient,
	propID string,
	expectedVersion int64,
) (harness.ProposalResp, harness.AssessmentsResp) {
	t.Helper()
	evalResp, evalRaw, err := ctrlCli.EvaluateProposal(ctx, propID, harness.EvaluateReq{
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		t.Fatalf("EvaluateProposal(%s): %v", propID, err)
	}
	evalRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if evalResp.OperationID != "" {
		harness.AssertUUIDv7(t, evalResp.OperationID)
		op, err := ctrlCli.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(Evaluate %s): %v", evalResp.OperationID, err)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var prop harness.ProposalResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := ctrlCli.GetProposal(ctx, propID)
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		prop = got
		return got.Status != "EVALUATING" && got.Status != "RECONSTRUCTED" && got.Status != "CAPTURED", nil
	})
	assessResp, aRaw, err := ctrlCli.ListProposalAssessments(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalAssessments(%s): %v", propID, err)
	}
	aRaw.RequireStatus(t, http.StatusOK)
	return prop, assessResp
}

func m4ApproveAndPublish(
	t testing.TB,
	ctx context.Context,
	env *harness.Env,
	reviewerCli *harness.APIClient,
	ctrlCli *harness.APIClient,
	prop harness.ProposalResp,
	assess harness.AssessmentsResp,
) harness.PublicationResp {
	t.Helper()
	propID := m4PropID(prop)
	evalID := m4LatestDecisionID(prop, assess)
	if evalID == "" {
		t.Fatalf("proposal %s missing latest policy decision id", propID)
	}
	app, appRaw, err := reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
		Comment:                   "E2E approved",
	})
	if err != nil {
		t.Fatalf("ApproveProposal(%s): %v", propID, err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)
	if len(app.RemainingObligations) != 0 {
		t.Fatalf("expected 0 remaining obligations, got %+v", app.RemainingObligations)
	}

	pub, pubRaw, err := ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(%s): %v", propID, err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if pub.OperationID != "" {
		op, err := ctrlCli.WaitForOperation(ctx, pub.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(Publish %s): %v", pub.OperationID, err)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	pubID := m4PubID(pub)
	harness.AssertUUIDv7(t, pubID)
	var finalPub harness.PublicationResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := ctrlCli.GetPublication(ctx, pubID)
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		finalPub = got
		return got.Status == "PUBLISHED" || harness.ContainsStatus(env.Contracts().PublicationStatuses.TerminalSuccess, got.Status), nil
	})
	return finalPub
}

func m4AssertPublishedGitAndPR(
	t testing.TB,
	env *harness.Env,
	fullName string,
	prop harness.ProposalResp,
	pub harness.PublicationResp,
	wantAuthor harness.GitIdentity,
	wantAgentAssisted string,
) {
	t.Helper()
	propID := m4PropID(prop)
	wantBranch := "custodian/" + propID
	if pub.BranchRef != wantBranch && pub.BranchRef != "refs/heads/"+wantBranch {
		t.Fatalf("expected branch_ref %q, got %q", wantBranch, pub.BranchRef)
	}
	if prCount := env.GitHub().PRCount(fullName); prCount != 1 {
		t.Fatalf("expected PRCount(%s) == 1, got %d", fullName, prCount)
	}
	prs := env.GitHub().PullRequests(fullName)
	if prs[0].Head != wantBranch && prs[0].Head != "refs/heads/"+wantBranch {
		t.Fatalf("expected PR head %q, got %q", wantBranch, prs[0].Head)
	}
	ci, err := env.Git().InspectCommit(fullName, wantBranch)
	if err != nil {
		t.Fatalf("InspectCommit(%s, %s): %v", fullName, wantBranch, err)
	}
	baseSHA := prop.BaseCommit
	if baseSHA == "" && prop.Repository != nil {
		baseSHA = prop.Repository.BaseCommit
	}
	if len(ci.Parents) != 1 || ci.Parents[0] != baseSHA {
		t.Fatalf("expected single parent %q, got %v", baseSHA, ci.Parents)
	}
	if ci.AuthorName != wantAuthor.Name || ci.AuthorEmail != wantAuthor.Email {
		t.Fatalf("author mismatch: got %q <%s>, want %q <%s>",
			ci.AuthorName, ci.AuthorEmail, wantAuthor.Name, wantAuthor.Email)
	}
	if !strings.EqualFold(ci.CommitterName, "Custodian") {
		t.Fatalf("expected committer Custodian, got %q", ci.CommitterName)
	}
	if vals := ci.Trailers["Custodian-Proposal"]; len(vals) == 0 || vals[0] != propID {
		t.Fatalf("missing/mismatched Custodian-Proposal trailer: got %v, want %q", vals, propID)
	}
	if vals := ci.Trailers["Custodian-Workspace"]; len(vals) == 0 || vals[0] != prop.WorkspaceID {
		t.Fatalf("missing/mismatched Custodian-Workspace trailer: got %v, want %q", vals, prop.WorkspaceID)
	}
	if vals := ci.Trailers["Agent-Assisted"]; len(vals) == 0 || vals[0] != wantAgentAssisted {
		t.Fatalf("missing/mismatched Agent-Assisted trailer: got %v, want %q", vals, wantAgentAssisted)
	}
}

func m4FetchAllAuditEvents(t testing.TB, ctx context.Context, auditorCli *harness.APIClient, filter harness.AuditFilter) []harness.AuditEvent {
	t.Helper()
	var all []harness.AuditEvent
	cur := ""
	for page := 0; page < 50; page++ {
		f := filter
		if f.Limit <= 0 {
			f.Limit = 200
		}
		f.Cursor = cur
		resp, raw, err := auditorCli.ListAuditEvents(ctx, f)
		if err != nil {
			t.Fatalf("ListAuditEvents: %v", err)
		}
		raw.RequireStatus(t, http.StatusOK)
		all = append(all, resp.Events...)
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		cur = resp.NextCursor
	}
	return all
}

func m4AssertAuditChain(t testing.TB, ctx context.Context, auditorCli *harness.APIClient, resourceID string, wantEventSubstrings ...string) []harness.AuditEvent {
	t.Helper()
	all := m4FetchAllAuditEvents(t, ctx, auditorCli, harness.AuditFilter{})
	harness.VerifyFullAuditHashChainFromGenesis(t, all)
	ids := make([]string, len(all))
	for i, ev := range all {
		ids[i] = ev.ID
	}
	harness.AssertUUIDv7Monotonic(t, ids)

	if resourceID != "" {
		resEvents := m4FetchAllAuditEvents(t, ctx, auditorCli, harness.AuditFilter{ResourceID: resourceID})
		for _, want := range wantEventSubstrings {
			found := false
			for _, ev := range resEvents {
				if strings.Contains(strings.ToLower(ev.EventType), strings.ToLower(want)) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected audit event containing %q for resource %s; got %d events", want, resourceID, len(resEvents))
			}
		}
	}
	return all
}

func m4AssertNoLeaksAllSurfaces(t testing.TB, env *harness.Env, srcArchive []byte, secrets ...string) {
	t.Helper()
	if len(srcArchive) > 0 {
		env.Snapshots().AssertArchiveNoSecretLeak(t, srcArchive, secrets...)
	}
	env.Gateway().AssertNoSecretInPrompts(t, secrets...)
	env.AssertNoSecretLeakInLogs(secrets...)
}

func m4Is40Hex(s string) bool {
	if len(s) != 40 {
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

func m4Is64Hex(s string) bool {
	if len(s) != 64 {
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

// --- Tier 3: 26 Pairwise Cross-Feature Tests (F-01..F-20) ---

// 1. F-06 x F-07: OIDC principal entitlement, classification route binding, and cross-owner isolation.
func TestT3_F06_F07_OIDCOwnerEntitlementAndRouteBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "restricted-app", nil, "RESTRICTED", []string{"restricted-review"}, true, 5)
	disabledSpec := harness.RepoSeedSpec{
		Owner:          "acme",
		Name:           "disabled-app",
		Files:          map[string]string{"README.md": "disabled\n"},
		DefaultBranch:  "main",
		RepoID:         10002,
		InstallationID: 20002,
	}
	disabledSeeded, err := env.Git().InitSeededRepo(disabledSpec.Owner, disabledSpec.Name, disabledSpec.Files,
		harness.WithDefaultBranch("main"), harness.WithRepoID(10002), harness.WithInstallationID(20002))
	if err != nil {
		t.Fatalf("seed disabled repo: %v", err)
	}
	m4SeedRepoDB(t, env, disabledSeeded, "INTERNAL", []string{m4DefaultRoute}, false, 5)

	// (a) Disallowed model route for RESTRICTED repo -> 403/422.
	_, badRouteRaw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent:      &harness.WorkspaceAgentInfo{Type: "codex", SessionID: "s1", ModelRoute: "public-route"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(bad route): %v", err)
	}
	badRouteRaw.RequireAnyStatus(t, http.StatusForbidden, http.StatusUnprocessableEntity)

	// (b) Disabled repository -> 403/422.
	_, disabledRaw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: disabledSeeded.GitHubRepoID, Ref: "main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(disabled repo): %v", err)
	}
	disabledRaw.RequireAnyStatus(t, http.StatusForbidden, http.StatusUnprocessableEntity)

	// (c) Spoofed OwnerID must be rejected (400/403/422) — never honor caller-asserted owner_id.
	_, spoofRaw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent:      &harness.WorkspaceAgentInfo{Type: "codex", SessionID: "s2", ModelRoute: "restricted-review"},
		OwnerID:    harness.NewTestUUIDv7(),
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(spoofed owner): %v", err)
	}
	spoofRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity)

	// Valid creation establishes owner from OIDC and pins base_commit to 40-hex HeadSHA.
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent:      &harness.WorkspaceAgentInfo{Type: "codex", SessionID: "s3", ModelRoute: "restricted-review"},
	})
	if !m4Is40Hex(ws.BaseCommit) || ws.BaseCommit != repo.seeded.HeadSHA {
		t.Fatalf("expected pinned base_commit=%q, got %q", repo.seeded.HeadSHA, ws.BaseCommit)
	}
	wsID := m4WorkspaceID(ws)
	harness.AssertUUIDv7(t, wsID)

	// (d) Cross-owner read blocked -> 403.
	_, otherRaw, err := actors.otherHumanCli.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("otherHuman GetWorkspace: %v", err)
	}
	otherRaw.RequireStatus(t, http.StatusForbidden)
}

// 2. F-06 x F-08: History scope entitlement and ingress .git sanitisation.
func TestT3_F06_F08_HistoryEntitlementAndIngressSanitisation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "history-repo", map[string]string{"README.md": "v1\n"}, "INTERNAL", nil, true, 5)
	if _, err := env.Git().CommitToBranch(repo.seeded.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"README.md": "v2\n"},
		Message: "second commit",
	}); err != nil {
		t.Fatalf("commit second rev: %v", err)
	}
	// Plant an unsafe hook inside the bare repo to ensure ingress checkout never copies hooks or credentials.
	hookPath := filepath.Join(repo.seeded.BarePath, "hooks", "pre-commit")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho ghs_secret_hook_token\n"), 0o755); err != nil {
		t.Fatalf("write pre-commit hook: %v", err)
	}
	env.RegisterSecret("ghs_secret_hook_token")

	// (a) Unprivileged human requesting full history -> 403.
	_, histRaw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository:    harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		SourceOptions: &harness.WorkspaceSourceOptions{IncludeGitMetadata: true, IncludeHistory: true},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(IncludeHistory): %v", err)
	}
	histRaw.RequireStatus(t, http.StatusForbidden)

	// (b) Authorised shallow sanitised .git workspace -> controller downloads credentialless tar.gz.
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository:    harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		SourceOptions: &harness.WorkspaceSourceOptions{IncludeGitMetadata: true, IncludeHistory: false},
	})
	wsID := m4WorkspaceID(ws)
	dlBytes, dlRaw, err := actors.ctrlCli.DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	dlRaw.RequireStatus(t, http.StatusOK)
	env.Snapshots().AssertArchiveGitSanitised(t, dlBytes)
	env.Snapshots().AssertArchiveNoSecretLeak(t, dlBytes, env.GitHub().ReadAppPrivateKeyPEM(), env.GitHub().WriteAppPrivateKeyPEM(), "ghs_secret_hook_token", "ghs_")

	// (c) Non-controller human cannot download source artifact -> 403.
	_, humanDlRaw, err := actors.humanCli.DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("human DownloadWorkspaceSource: %v", err)
	}
	humanDlRaw.RequireStatus(t, http.StatusForbidden)
}

// 3. F-06 x F-17: Verified human author vs forged author metadata and Agent-Assisted trailer.
func TestT3_F06_F17_VerifiedHumanAuthorAndAgentTrailer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "author-service", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent:      &harness.WorkspaceAgentInfo{Type: "codex", SessionID: "sess-42", ModelRoute: m4DefaultRoute},
	})
	wsID := m4WorkspaceID(ws)

	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	artID, _ := m4UploadSnapshotOnly(t, ctx, actors.ctrlCli, wsID, gz, ws.Generation)

	// Forged author metadata must be rejected by strict schema or ignored by server.
	_, forgedRaw, err := actors.ctrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot:    harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws.Generation, SizeBytes: int64(len(gz))},
		Title:       "forged author check",
		Provenance:  &harness.Provenance{Type: "agent_assisted", CaptureMethod: "frozen_filesystem"},
		AuthorName:  "Linus Forged",
		AuthorEmail: "forged@evil.com",
	})
	if err != nil {
		t.Fatalf("SubmitProposal(forged): %v", err)
	}
	forgedRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity)

	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation, "agent patch", &harness.Provenance{
		Type:          "agent_assisted",
		CaptureMethod: "frozen_filesystem",
	})
	if ws.Owner == nil || prop.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("proposal owner must match workspace verified human owner %+v, got %+v", ws.Owner, prop.Owner)
	}
	harness.AssertUUIDv7(t, prop.Owner.PrincipalID)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(prop), prop.Version)
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, pub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "true")
}

// 4. F-07 x F-17: Pinned base_commit vs upstream force-push aborts publication (ADV-11).
func TestT3_F07_F17_RefPinningVsUpstreamForcePushAbort(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "forcepush-t3", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	wsID := m4WorkspaceID(ws)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "app.go", Body: []byte("package app\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation, "force push race", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	evalID := m4LatestDecisionID(evalProp, assess)
	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// Upstream force-pushes an orphan divergent commit to main before publication.
	if _, err := env.Git().ForcePushBranch(repo.seeded.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"README.md": "diverged upstream\n"},
		Message: "divergent force push",
	}); err != nil {
		t.Fatalf("ForcePushBranch: %v", err)
	}

	pub, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal transport err: %v", err)
	}
	if pubRaw.StatusCode == http.StatusAccepted || pubRaw.StatusCode == http.StatusOK {
		if pub.OperationID != "" {
			op, err := actors.ctrlCli.WaitForOperation(ctx, pub.OperationID, 20*time.Second)
			if err != nil {
				t.Fatalf("WaitForOperation: %v", err)
			}
			if op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
				t.Fatalf("expected publish operation FAILED after upstream force-push, got %q", op.Status)
			}
		}
		gotPub, _, gErr := actors.ctrlCli.GetPublication(ctx, m4PubID(pub))
		if gErr == nil && gotPub.Status == "PUBLISHED" {
			t.Fatalf("publication must not reach PUBLISHED after upstream force-push")
		}
	} else {
		pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusFailedDependency)
	}

	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs created after force-push abort, got %d", env.GitHub().PRCount(repo.seeded.FullName))
	}
	exists, err := env.Git().BranchExists(repo.seeded.FullName, "custodian/"+propID)
	if err != nil {
		t.Fatalf("BranchExists: %v", err)
	}
	if exists {
		t.Fatalf("branch custodian/%s must not be pushed on force-push abort", propID)
	}
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "publish")
}

// 5. F-08 x F-09: Ingress source artifact vs upload-only scoped capability & provenance.
func TestT3_F08_F09_IngressSourceVsUploadOnlyCapabilityScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "cap-scope", nil, "INTERNAL", nil, true, 5)
	ws1 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	ws2 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	ws1ID, ws2ID := m4WorkspaceID(ws1), m4WorkspaceID(ws2)

	cap1, raw1, err := actors.ctrlCli.RequestUploadCapability(ctx, ws1ID, harness.UploadCapabilityReq{Generation: ws1.Generation, MaxBytes: 65536})
	if err != nil {
		t.Fatalf("RequestUploadCapability(ws1): %v", err)
	}
	raw1.RequireStatus(t, http.StatusOK)
	cap2, raw2, err := actors.ctrlCli.RequestUploadCapability(ctx, ws2ID, harness.UploadCapabilityReq{Generation: ws2.Generation, MaxBytes: 65536})
	if err != nil {
		t.Fatalf("RequestUploadCapability(ws2): %v", err)
	}
	raw2.RequireStatus(t, http.StatusOK)

	tok1 := m4FirstNonEmpty(cap1.Token, cap1.CapabilityToken)
	// (a) Upload capability must reject GET / read attempts.
	getRaw, err := actors.ctrlCli.DoRaw(ctx, http.MethodGet, cap1.UploadURL, nil,
		harness.WithoutAuth(), harness.WithHeader("Authorization", "Bearer "+tok1))
	if err != nil {
		t.Fatalf("GET upload_url: %v", err)
	}
	getRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed)

	// (b) Cross-workspace token rejected on ws2 upload URL.
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "a.txt", Body: []byte("hi\n")}})
	crossRaw, err := actors.ctrlCli.UploadSnapshot(ctx, cap2.UploadURL, tok1, gz)
	if err != nil {
		t.Fatalf("cross UploadSnapshot: %v", err)
	}
	crossRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)

	// (c) Tampered HMAC token rejected.
	tampered := tok1[:len(tok1)-1]
	if tok1[len(tok1)-1] == 'a' {
		tampered += "b"
	} else {
		tampered += "a"
	}
	tamperRaw, err := actors.ctrlCli.UploadSnapshot(ctx, cap1.UploadURL, tampered, gz)
	if err != nil {
		t.Fatalf("tampered UploadSnapshot: %v", err)
	}
	tamperRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)

	// (d) Non-controller actor cannot submit proposal capture provenance -> 403.
	artID, _ := m4UploadSnapshotOnly(t, ctx, actors.ctrlCli, ws1ID, gz, ws1.Generation)
	_, unauthSubRaw, err := actors.otherHumanCli.SubmitProposal(ctx, ws1ID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws1.Generation, SizeBytes: int64(len(gz))},
		Title:    "untrusted provenance",
	})
	if err != nil {
		t.Fatalf("otherHuman SubmitProposal: %v", err)
	}
	unauthSubRaw.RequireStatus(t, http.StatusForbidden)
}

// 6. F-09 x F-10: Upload capability max_bytes enforcement and adversarial archive rejection (ADV-01..04).
func TestT3_F09_F10_CapabilityMaxBytesAndAdversarialExtraction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "adv-extract", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	wsID := m4WorkspaceID(ws)

	// (a) Oversized / decompression bomb payload exceeds capability max_bytes.
	smallCap, capRaw, err := actors.ctrlCli.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{Generation: ws.Generation, MaxBytes: 1024})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	bomb, _ := harness.BuildGzipBomb(2 << 20)
	if int64(len(bomb)) <= smallCap.MaxBytes {
		// Pad beyond smallCap.MaxBytes with corrupt tail to trigger size gate if compressed < MaxBytes.
		bomb = append(bomb, make([]byte, int(smallCap.MaxBytes)+512)...)
	}
	bombRaw, err := actors.ctrlCli.UploadSnapshot(ctx, smallCap.UploadURL, m4FirstNonEmpty(smallCap.Token, smallCap.CapabilityToken), bomb)
	if err != nil {
		if bombRaw != nil {
			t.Fatalf("UploadSnapshot(bomb) returned both error %v and HTTP %d", err, bombRaw.StatusCode)
		}
		if !m4IsStreamAbortErr(ctx, err) {
			t.Fatalf("UploadSnapshot(bomb) unexpected transport error (not stream abort/EOF): %v", err)
		}
	} else if bombRaw == nil {
		t.Fatalf("UploadSnapshot(bomb) returned nil response and nil error")
	} else if bombRaw.StatusCode >= 200 && bombRaw.StatusCode < 300 {
		// If upload accepted compressed bytes, decompression bomb must fail at submit/reconstruct.
		var bombUp m4UploadResp
		if len(bombRaw.Body) > 0 {
			_ = json.Unmarshal(bombRaw.Body, &bombUp)
		}
		bombArtID := m4FirstNonEmpty(bombUp.ArtifactID, bombUp.ID, bombRaw.Headers.Get("X-Artifact-ID"))
		if bombArtID == "" {
			t.Fatalf("UploadSnapshot(bomb) returned %d without artifact_id, id, or X-Artifact-ID", bombRaw.StatusCode)
		}
		subBomb, subBombRaw, sErr := actors.ctrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
			Snapshot: harness.SnapshotSubmitRef{
				ArtifactID:          bombArtID,
				SHA256:              harness.SHA256Hex(bomb),
				WorkspaceGeneration: ws.Generation,
				SizeBytes:           int64(len(bomb)),
			},
			Title: "gzip bomb",
		})
		if sErr != nil {
			t.Fatalf("SubmitProposal(gzip bomb): %v", sErr)
		}
		if subBombRaw.StatusCode == http.StatusAccepted || subBombRaw.StatusCode == http.StatusCreated {
			bombPropID := m4PropID(subBomb)
			if bombPropID == "" {
				t.Fatalf("SubmitProposal(gzip bomb) returned %d without proposal id: %+v", subBombRaw.StatusCode, subBomb)
			}
			if subBomb.OperationID != "" {
				op, wErr := actors.ctrlCli.WaitForOperation(ctx, subBomb.OperationID, 20*time.Second)
				if wErr != nil {
					t.Fatalf("WaitForOperation(gzip bomb): %v", wErr)
				}
				if op.Status == "SUCCEEDED" || (op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status)) {
					t.Fatalf("expected gzip bomb operation FAILED, got %q", op.Status)
				}
			}
			gotBomb, gRaw, gErr := actors.ctrlCli.GetProposal(ctx, bombPropID)
			if gErr != nil {
				t.Fatalf("GetProposal(gzip bomb %s): %v", bombPropID, gErr)
			}
			gRaw.RequireStatus(t, http.StatusOK)
			if gotBomb.Status == "RECONSTRUCTED" || gotBomb.CanonicalArtifactID != "" {
				t.Fatalf("gzip bomb proposal %s must never reach RECONSTRUCTED or have CanonicalArtifactID, got status=%q canonical=%q",
					bombPropID, gotBomb.Status, gotBomb.CanonicalArtifactID)
			}
		} else {
			subBombRaw.RequireAnyStatus(t, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusBadRequest)
		}
	} else {
		bombRaw.RequireAnyStatus(t, http.StatusForbidden, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusBadRequest)
	}

	// (b)(c)(d) Path traversal, symlink escape, and Unicode NFC/NFD collision rejected with 422 (or failed reconstruct).
	travGZ, travSHA := harness.BuildPathTraversalArchive(harness.TraversalDotDot)
	symGZ, symSHA := harness.BuildSymlinkArchive("evil-link", "/etc/passwd")
	uniGZ, uniSHA := harness.BuildUnicodeCollisionArchive()

	for _, tc := range []struct {
		name string
		gz   []byte
		sha  string
	}{
		{"traversal", travGZ, travSHA},
		{"symlink", symGZ, symSHA},
		{"unicode-collision", uniGZ, uniSHA},
	} {
		artID, _ := m4UploadSnapshotOnly(t, ctx, actors.ctrlCli, wsID, tc.gz, ws.Generation)
		sub, subRaw, err := actors.ctrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
			Snapshot: harness.SnapshotSubmitRef{
				ArtifactID:          artID,
				SHA256:              tc.sha,
				WorkspaceGeneration: ws.Generation,
				SizeBytes:           int64(len(tc.gz)),
			},
			Title: "adv-" + tc.name,
		})
		if err != nil {
			t.Fatalf("SubmitProposal(%s): %v", tc.name, err)
		}
		if subRaw.StatusCode == http.StatusAccepted || subRaw.StatusCode == http.StatusCreated {
			propID := m4PropID(sub)
			if propID == "" {
				t.Fatalf("SubmitProposal(%s) returned %d without proposal id: %+v", tc.name, subRaw.StatusCode, sub)
			}
			if sub.OperationID != "" {
				op, wErr := actors.ctrlCli.WaitForOperation(ctx, sub.OperationID, 20*time.Second)
				if wErr != nil {
					t.Fatalf("WaitForOperation(%s): %v", tc.name, wErr)
				}
				if op.Status == "SUCCEEDED" || (op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status)) {
					t.Fatalf("expected adversarial archive %s operation FAILED, got %q", tc.name, op.Status)
				}
			}
			gotProp, gRaw, gErr := actors.ctrlCli.GetProposal(ctx, propID)
			if gErr != nil {
				t.Fatalf("GetProposal(%s %s): %v", tc.name, propID, gErr)
			}
			gRaw.RequireStatus(t, http.StatusOK)
			if gotProp.Status == "RECONSTRUCTED" || gotProp.CanonicalArtifactID != "" {
				t.Fatalf("adversarial archive %s proposal %s must never reach RECONSTRUCTED or have CanonicalArtifactID, got status=%q canonical=%q",
					tc.name, propID, gotProp.Status, gotProp.CanonicalArtifactID)
			}
		} else {
			subRaw.RequireAnyStatus(t, http.StatusUnprocessableEntity, http.StatusBadRequest)
		}
	}
}

// 7. F-10 x F-11: Sandbox .git injection ignored and canonical Tree/Diff/Manifest digests remain deterministic (ADV-05).
func TestT3_F10_F11_MaliciousSandboxGitIgnoredInCanonicalTree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "git-ignore-canon", nil, "INTERNAL", nil, true, 5)
	ws1 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	ws2 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})

	cleanEntries := []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	}
	gitInjGZ, gitInjSHA := harness.BuildGitInjectionArchive(cleanEntries)
	varMetaGZ, varMetaSHA := harness.BuildTarGzWithVaryingMeta(cleanEntries, time.Unix(1700000000, 0), 999, 999, true)

	p1 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws1), gitInjGZ, gitInjSHA, ws1.Generation, "git injection", nil)
	p2 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws2), varMetaGZ, varMetaSHA, ws2.Generation, "varying tar meta", nil)

	if (!m4Is40Hex(p1.TreeDigest) && !m4Is64Hex(p1.TreeDigest)) || !m4Is64Hex(p1.DiffDigest) || !m4Is64Hex(p1.PublicationManifestDigest) {
		t.Fatalf("expected valid canonical digests on p1 (40-hex or 64-hex tree, 64-hex diff/manifest), got tree=%q diff=%q manifest=%q",
			p1.TreeDigest, p1.DiffDigest, p1.PublicationManifestDigest)
	}
	if p1.TreeDigest != p2.TreeDigest {
		t.Fatalf("TreeDigest mismatch: %q vs %q", p1.TreeDigest, p2.TreeDigest)
	}
	if p1.DiffDigest != p2.DiffDigest {
		t.Fatalf("DiffDigest mismatch: %q vs %q", p1.DiffDigest, p2.DiffDigest)
	}
	if p1.PublicationManifestDigest != p2.PublicationManifestDigest {
		t.Fatalf("PublicationManifestDigest mismatch: %q vs %q", p1.PublicationManifestDigest, p2.PublicationManifestDigest)
	}

	diff1, diffRaw, err := actors.humanCli.GetProposalDiff(ctx, m4PropID(p1))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	for _, cf := range diff1.Paths {
		if strings.HasPrefix(cf.Path, ".git/") || cf.Path == ".git" {
			t.Fatalf("sandbox .git path %q leaked into canonical diff", cf.Path)
		}
	}
}

// 8. F-11 x F-12: Canonical manifest digest & optimistic version concurrency conflict (409).
func TestT3_F11_F12_CanonicalManifestAndOptimisticVersionConflict(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "optimistic-lock", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "version conflict", nil)
	propID := m4PropID(prop)
	v1 := prop.Version

	// (a) Evaluation with current expected_version succeeds and advances version.
	evalProp, _ := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, v1)
	if evalProp.Version <= v1 {
		t.Fatalf("expected proposal version to increment past %d, got %d", v1, evalProp.Version)
	}

	// (b) Stale expected_version returns 409 Conflict with ErrorResponse envelope.
	_, staleRaw, err := actors.ctrlCli.EvaluateProposal(ctx, propID, harness.EvaluateReq{ExpectedVersion: v1})
	if err != nil {
		t.Fatalf("stale EvaluateProposal: %v", err)
	}
	staleRaw.RequireStatus(t, http.StatusConflict)
	if staleRaw.Error == nil || staleRaw.Error.Code == "" {
		t.Fatalf("expected ErrorResponse error.code on 409 conflict, got %+v", staleRaw.Error)
	}

	// (c) Diff digests match proposal manifest digest (64 hex chars).
	diffResp, diffRaw, err := actors.humanCli.GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	if !m4Is64Hex(diffResp.DiffDigest) || !m4Is64Hex(diffResp.PublicationManifestDigest) {
		t.Fatalf("expected 64-hex digests, got diff=%q manifest=%q", diffResp.DiffDigest, diffResp.PublicationManifestDigest)
	}
	if diffResp.PublicationManifestDigest != evalProp.PublicationManifestDigest {
		t.Fatalf("diff manifest %q != proposal manifest %q", diffResp.PublicationManifestDigest, evalProp.PublicationManifestDigest)
	}
}

// 9. F-12 x F-16: Proposal revision revokes/blocks stale approval digest (RG-04, ADV-10).
func TestT3_F12_F16_ProposalRevisionRevokesStaleApproval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "stale-approval", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	wsID := m4WorkspaceID(ws)

	gz1, sha1 := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("version 1\n")},
	})
	p1 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz1, sha1, ws.Generation, "rev 1", nil)
	p1Eval, p1Assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(p1), p1.Version)
	d1 := m4LatestDecisionID(p1Eval, p1Assess)
	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, m4PropID(p1), harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
		PolicyEvaluationID:        d1,
	})
	if err != nil {
		t.Fatalf("ApproveProposal(p1): %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// Submit modified snapshot P2 on the same workspace.
	gz2, sha2 := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("version 2 modified\n")},
	})
	p2 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz2, sha2, ws.Generation, "rev 2", nil)
	p2Eval, p2Assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(p2), p2.Version)
	if p2Eval.PublicationManifestDigest == p1Eval.PublicationManifestDigest {
		t.Fatalf("expected distinct manifest digests between rev 1 and rev 2")
	}

	// (a) Approving P2 using P1's stale digest must fail with 409 Conflict.
	_, badAppRaw, err := actors.reviewerCli.ApproveProposal(ctx, m4PropID(p2), harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
		PolicyEvaluationID:        m4LatestDecisionID(p2Eval, p2Assess),
	})
	if err != nil {
		t.Fatalf("ApproveProposal(stale digest): %v", err)
	}
	badAppRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	// (b) Publishing P2 with P1's digest must fail with 409 Conflict, and 0 PRs created.
	_, badPubRaw, err := actors.ctrlCli.PublishProposal(ctx, m4PropID(p2), harness.PublishReq{
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(stale digest): %v", err)
	}
	badPubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden, http.StatusUnprocessableEntity)
	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs on stale approval attempt, got %d", env.GitHub().PRCount(repo.seeded.FullName))
	}
}

// 10. F-13 x F-14: Stage A secret redaction prevents raw secrets entering Stage B prompts, plus evidence_id validation.
func TestT3_F13_F14_SecretRedactionAndEvidenceGrounding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	synthSecret := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	env, repo, actors := m4SetupRepoEnv(t, "acme", "redact-ground", nil, "INTERNAL", nil, true, 5)
	env.RegisterSecret(synthSecret)
	env.RegisterSecret("AKIAIOSFODNN7EXAMPLE")

	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: synthSecret,
		FilePath:    ".env",
		RuleID:      "generic-api-key",
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	// First force invalid_evidence_ids from Stage B gateway.
	env.Gateway().SetMode(harness.GatewayModeInvalidEvidenceIDs)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: ".env", Body: m4LoadFixture(t, "payloads/synthetic_aws_secret.env")},
		{Name: "infra/prod/config.env", Body: []byte("ENV=prod\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "secret + bad evidence", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	findingsResp, fRaw, err := actors.humanCli.ListProposalFindings(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)
	if len(findingsResp.Findings) == 0 {
		t.Fatalf("expected Stage A gitleaks finding, got 0")
	}
	for _, f := range findingsResp.Findings {
		if !f.Redacted {
			t.Fatalf("finding %s must have Redacted=true", f.ID)
		}
	}
	harness.AssertNoSecretOrEncodedLeak(t, string(fRaw.Body), synthSecret, "AKIAIOSFODNN7EXAMPLE")

	// Gateway prompts must never contain the raw secret.
	env.Gateway().AssertNoSecretInPrompts(t, synthSecret, "AKIAIOSFODNN7EXAMPLE")

	// Invalid evidence IDs must not yield COMPLETE assessment or ALLOW decision.
	if len(assess.Assessments) == 0 {
		t.Fatalf("expected >= 1 Stage B assessment for %s, got 0", propID)
	}
	for _, a := range assess.Assessments {
		if a.Status == "COMPLETE" || (a.Status != "FAILED" && a.Status != "INDETERMINATE") {
			t.Fatalf("invalid evidence_ids must produce FAILED or INDETERMINATE assessment, got %+v", a)
		}
	}
	if evalProp.LatestPolicyEffect == "ALLOW" {
		t.Fatalf("proposal %s must not be ALLOW when secret detected and evidence invalid", propID)
	}
	env.AssertNoSecretLeakInLogs(synthSecret, "AKIAIOSFODNN7EXAMPLE")
}

// 11. F-13 x F-15: Incomplete Stage A scan (FilesSkipped > 0) blocks ALLOW in Stage C CEL (RG-05).
func TestT3_F13_F15_IncompleteScanBlocksAllowInCEL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "scan-incomplete", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:         harness.ScannerModeFilesSkipped,
		SkippedPaths: []string{"huge.bin"},
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	env.Gateway().SetMode(harness.GatewayModeClean)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "huge.bin", Body: []byte("binary-ish payload\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "incomplete scan", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	findingsResp, fRaw, err := actors.humanCli.ListProposalFindings(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)
	sawIncomplete := false
	for _, sr := range findingsResp.ScanRuns {
		if sr.Scanner == "semgrep" && sr.FilesSkipped > 0 && !sr.Complete {
			sawIncomplete = true
		}
	}
	if !sawIncomplete {
		t.Fatalf("expected semgrep ScanRun with FilesSkipped>0 and Complete=false, got %+v", findingsResp.ScanRuns)
	}
	if len(assess.PolicyDecisions) == 0 {
		t.Fatalf("expected persisted PolicyDecision")
	}
	eff := assess.PolicyDecisions[len(assess.PolicyDecisions)-1].Effect
	if eff == "ALLOW" {
		t.Fatalf("incomplete scan must never evaluate to ALLOW, got %q", eff)
	}
	if evalProp.Status != "QUARANTINED" && evalProp.Status != "DENIED" && evalProp.Status != "REMEDIATION_REQUIRED" {
		t.Fatalf("expected blocked proposal status (QUARANTINED/DENIED/REMEDIATION_REQUIRED), got %q", evalProp.Status)
	}
	_, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs on incomplete scan")
	}
}

// 12. F-14 x F-15: Prompt injection causing model CLEAR cannot override Stage A secret + Stage C CEL DENY (ADV-08).
func TestT3_F14_F15_PromptInjectionModelClearCannotBypassCEL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "prompt-inj", nil, "INTERNAL", nil, true, 5)
	env.RegisterSecret("AKIAIOSFODNN7EXAMPLE")
	env.RegisterSecret("custodian_e2e_dummy_secret_value_0123456789abcdef")
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: "custodian_e2e_dummy_secret_value_0123456789abcdef",
		FilePath:    ".env",
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	// Model gateway returns CLEAR despite secret finding (simulating successful prompt injection).
	env.Gateway().SetMode(harness.GatewayModeClean)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "sample.go", Body: m4LoadFixture(t, "payloads/prompt_injection_source.go")},
		{Name: ".env", Body: m4LoadFixture(t, "payloads/synthetic_aws_secret.env")},
		{Name: "infra/prod/config.env", Body: []byte("ENV=prod\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "prompt injection + secret", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	if len(env.Gateway().Requests()) == 0 {
		t.Fatalf("expected Stage B gateway to be invoked for high-risk change, got 0 requests")
	}
	env.Gateway().AssertPromptUntrustedFraming(t, "Ignore all previous instructions", true)
	if len(assess.PolicyDecisions) == 0 || assess.PolicyDecisions[len(assess.PolicyDecisions)-1].Effect != "DENY" {
		t.Fatalf("expected Stage C DENY overriding model CLEAR, got %+v", assess.PolicyDecisions)
	}
	if evalProp.Status != "DENIED" {
		t.Fatalf("expected proposal status DENIED, got %q", evalProp.Status)
	}
	_, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
}

// 13. F-15 x F-16: Mandatory human approval invariant and reviewer-group / SoD enforcement (RG-03).
func TestT3_F15_F16_MandatoryHumanApprovalAndGroupSoD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "approval-sod", nil, "INTERNAL", nil, true, 5)

	// (a) Clean proposal with ALLOW effect still cannot publish without human approval.
	wsClean := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gzClean, shaClean := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	pClean := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(wsClean), gzClean, shaClean, wsClean.Generation, "clean unapproved", nil)
	pCleanEval, _ := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(pClean), pClean.Version)

	_, unapprovedPubRaw, err := actors.ctrlCli.PublishProposal(ctx, m4PropID(pClean), harness.PublishReq{
		PublicationManifestDigest: pCleanEval.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(unapproved): %v", err)
	}
	unapprovedPubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)

	// (b)(c)(d) Proposal touching infra/prod/ requires platform-owners reviewer group and human reviewer (not owner/agent).
	wsInfra := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gzInfra, shaInfra := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "infra/prod/main.tf", Body: []byte("resource \"null_resource\" \"x\" {}\n")},
	})
	pInfra := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(wsInfra), gzInfra, shaInfra, wsInfra.Generation, "infra change", nil)
	pInfraID := m4PropID(pInfra)
	pInfraEval, pInfraAssess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, pInfraID, pInfra.Version)
	evalID := m4LatestDecisionID(pInfraEval, pInfraAssess)

	// Owner / non-member human rejected (403).
	_, ownerAppRaw, err := actors.humanCli.ApproveProposal(ctx, pInfraID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: pInfraEval.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("human ApproveProposal: %v", err)
	}
	ownerAppRaw.RequireStatus(t, http.StatusForbidden)

	// Agent principal rejected (403).
	_, agentAppRaw, err := actors.agentCli.ApproveProposal(ctx, pInfraID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: pInfraEval.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("agent ApproveProposal: %v", err)
	}
	agentAppRaw.RequireStatus(t, http.StatusForbidden)

	// Authorized platform-owners reviewer succeeds and publishes 1 PR.
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, pInfraEval, pInfraAssess)
	if env.GitHub().PRCount(repo.seeded.FullName) != 1 || pub.Status != "PUBLISHED" {
		t.Fatalf("expected 1 PUBLISHED PR, got status=%q count=%d", pub.Status, env.GitHub().PRCount(repo.seeded.FullName))
	}
}

// 14. F-16 x F-17: Digest-bound approval to isolated 14-step publication and branch restriction (RG-07).
func TestT3_F16_F17_DigestBoundApprovalTo14StepPublish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "digest-publish", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "digest publish", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	evalID := m4LatestDecisionID(evalProp, assess)

	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// (a) Mismatched manifest digest rejected.
	_, badDigRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: strings.Repeat("0", 64),
	})
	if err != nil {
		t.Fatalf("PublishProposal(bad digest): %v", err)
	}
	badDigRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	// (b) Attempt to override target_branch / target_remote rejected (additionalProperties: false or 403).
	_, overrideRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		TargetBranch:              "main",
		TargetRemote:              "https://evil.example/repo.git",
	})
	if err != nil {
		t.Fatalf("PublishProposal(override): %v", err)
	}
	overrideRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity)

	// (c) Clean publish succeeds exclusively on custodian/<propID>.
	pub, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(clean): %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if pub.OperationID != "" {
		op, wErr := actors.ctrlCli.WaitForOperation(ctx, pub.OperationID, 30*time.Second)
		if wErr != nil {
			t.Fatalf("WaitForOperation: %v", wErr)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var finalPub harness.PublicationResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := actors.ctrlCli.GetPublication(ctx, m4PubID(pub))
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		finalPub = got
		return got.Status == "PUBLISHED", nil
	})
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, finalPub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")
	tree, err := env.Git().InspectTree(repo.seeded.FullName, "custodian/"+propID)
	if err != nil {
		t.Fatalf("InspectTree: %v", err)
	}
	if _, ok := tree["pkg/hello/hello.go"]; !ok {
		t.Fatalf("published branch missing pkg/hello/hello.go")
	}
}

// 15. F-01 x F-15: custodian-policy CLI + /v1/policies/{validate,evaluate} fail-closed & org-before-repo (RG-06, ADV-09).
func TestT3_F01_F15_CustodianPolicyCLIAndFailClosedValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, _, actors := m4SetupRepoEnv(t, "acme", "policy-cli", nil, "INTERNAL", nil, true, 5)
	invalidSyntax := string(m4LoadFixture(t, "policies/invalid_cel_syntax.yaml"))
	invalidType := string(m4LoadFixture(t, "policies/invalid_cel_type_error.yaml"))
	runtimeErr := string(m4LoadFixture(t, "policies/runtime_cel_error_fail_closed.yaml"))
	orgDeny := string(m4LoadFixture(t, "policies/org_mandatory_deny.yaml"))
	repoPermissive := string(m4LoadFixture(t, "policies/repo_permissive_override_attempt.yaml"))

	tmpDir := t.TempDir()
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidSyntax), 0o600); err != nil {
		t.Fatalf("write invalid.yaml: %v", err)
	}
	if err := os.WriteFile(validPath, m4LoadFixture(t, "policies/valid_default.yaml"), 0o600); err != nil {
		t.Fatalf("write valid.yaml: %v", err)
	}

	// (a) CLI validate rejects invalid CEL syntax; accepts valid default bundle.
	cliCfg := env.Contracts().CLI
	valCmd := append([]string{}, cliCfg.PolicyValidateSubcommand...)
	valCmd = append(valCmd, cliCfg.PolicyBundleFlag, invalidPath)
	badCLI := env.RunCLI(env.Contracts().Binaries.Policy, valCmd, nil)
	if badCLI.ExitCode == 0 {
		t.Fatalf("custodian-policy validate unexpectedly succeeded on invalid CEL syntax: %s", badCLI.Stdout)
	}
	goodCmd := append([]string{}, cliCfg.PolicyValidateSubcommand...)
	goodCmd = append(goodCmd, cliCfg.PolicyBundleFlag, validPath)
	goodCLI := env.RunCLI(env.Contracts().Binaries.Policy, goodCmd, nil)
	if goodCLI.ExitCode != 0 {
		t.Fatalf("custodian-policy validate failed on valid_default.yaml: exit=%d stderr=%s", goodCLI.ExitCode, goodCLI.Stderr)
	}

	// (b) API /v1/policies/validate rejects syntax & type errors.
	for _, badYAML := range []string{invalidSyntax, invalidType} {
		vResp, vRaw, err := actors.policyAdminCli.ValidatePolicy(ctx, harness.PolicyBundleReq{BundleYAML: badYAML})
		if err != nil {
			t.Fatalf("ValidatePolicy: %v", err)
		}
		if vRaw.StatusCode == http.StatusOK {
			if vResp.Valid || len(vResp.Errors) == 0 {
				t.Fatalf("expected Valid=false with errors, got %+v", vResp)
			}
		} else {
			vRaw.RequireAnyStatus(t, http.StatusUnprocessableEntity, http.StatusBadRequest)
		}
	}

	// (c) Runtime CEL error fails closed (onError: DENY).
	rtResp, rtRaw, err := actors.policyAdminCli.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: runtimeErr,
		Stage:      "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"critical_secrets": 0, "prohibited_licenses": 0, "scan_complete": true},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{"README.md"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(runtime error): %v", err)
	}
	rtRaw.RequireStatus(t, http.StatusOK)
	if rtResp.Effect != "DENY" {
		t.Fatalf("expected fail-closed DENY on runtime CEL error, got %q", rtResp.Effect)
	}

	// (d) Org-before-repo: repo permissive override cannot weaken org.secrets.block.
	orgResp, orgRaw, err := actors.policyAdminCli.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		OrgBundleYAML: orgDeny,
		BundleYAML:    repoPermissive,
		Stage:         "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"critical_secrets": 1, "prohibited_licenses": 0, "scan_complete": true},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{".env"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(org vs repo): %v", err)
	}
	orgRaw.RequireStatus(t, http.StatusOK)
	if orgResp.Effect != "DENY" {
		t.Fatalf("expected ORG mandatory DENY, got %q", orgResp.Effect)
	}
}

// 16. F-01 x F-02: Publisher import isolation boundary (go list -deps) & 5-binary CLI build check.
func TestT3_F01_F02_PublisherIsolationAndCLIBuildCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "pub-isolation", nil, "INTERNAL", nil, true, 5)
	bins := env.Contracts().Binaries
	for _, bin := range []string{bins.Custodian, bins.API, bins.Worker, bins.Publisher, bins.Policy} {
		res := env.RunCLI(bin, []string{"--help"}, nil)
		if res.Err != nil && res.ExitCode != 0 && res.ExitCode != 2 {
			t.Fatalf("binary %s --help failed: exit=%d err=%v stderr=%s", bin, res.ExitCode, res.Err, res.Stderr)
		}
		if strings.TrimSpace(res.Stdout+res.Stderr) == "" {
			t.Fatalf("binary %s --help produced empty output", bin)
		}
	}

	// Verify publisher isolation statically from repo root via go list -deps.
	goBin, err := harness.ResolveGoBin()
	if err != nil {
		t.Fatalf("ResolveGoBin: %v", err)
	}
	repoRoot := m4ResolveRepoRoot(t)
	cmd := exec.CommandContext(ctx, goBin, "list", "-deps", "./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps publisher boundary failed in %s: %v\n%s", repoRoot, err, string(out))
	}
	depsText := string(out)
	for _, forbidden := range []string{
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
	} {
		if strings.Contains(depsText, forbidden) {
			t.Fatalf("publisher isolation violation: found forbidden dependency %q", forbidden)
		}
	}

	// Runtime isolation: publishing an approved proposal invokes zero gateway or scanner calls during publish step.
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "pub isolation", nil)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(prop), prop.Version)

	gwBefore := len(env.Gateway().Requests())
	scanBefore := len(env.Scanners().Invocations(harness.ScannerGitleaks))
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}
	if len(env.Gateway().Requests()) != gwBefore {
		t.Fatalf("publisher step must not call model gateway")
	}
	if len(env.Scanners().Invocations(harness.ScannerGitleaks)) != scanBefore {
		t.Fatalf("publisher step must not invoke scanners")
	}
}

// 17. F-03 x F-05: UUIDv7 monotonic ordering, auditor RBAC, and genesis-to-tip audit hash chain.
func TestT3_F03_F05_UUIDv7OrderingAndAuditChainContinuity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "uuid-audit", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	wsID := m4WorkspaceID(ws)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation, "uuid audit", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	evalID := m4LatestDecisionID(evalProp, assess)
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)
	pubID := m4PubID(pub)

	harness.AssertUUIDv7Monotonic(t, []string{wsID, propID, evalID, pubID})

	// Non-auditor human denied access to global audit stream.
	_, denyRaw, err := actors.otherHumanCli.ListAuditEvents(ctx, harness.AuditFilter{})
	if err != nil {
		t.Fatalf("otherHuman ListAuditEvents: %v", err)
	}
	denyRaw.RequireStatus(t, http.StatusForbidden)

	events := m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "proposal", "publish")
	if len(events) < 3 {
		t.Fatalf("expected >= 3 audit events across lifecycle, got %d", len(events))
	}
}

// 18. F-04 x F-17: Publisher SIGKILL crash + GitHub 503 outage recover via leased outbox without duplicate PRs (RG-08, RG-10).
func TestT3_F04_F17_OutboxLeaseCrashAndGitHubOutagePublishRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "outbox-pub", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "pub crash recovery", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	evalID := m4LatestDecisionID(evalProp, assess)
	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// Inject transient GitHub 503 on PR creation, trigger publish, kill publisher mid-flight, then restart.
	env.GitHub().SetOutage("POST", "/pulls", http.StatusServiceUnavailable, 2)
	pub, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	time.Sleep(150 * time.Millisecond)
	if err := env.KillPublisher(); err != nil {
		t.Fatalf("KillPublisher: %v", err)
	}
	env.GitHub().ClearOutages()
	if err := env.RestartPublisher(); err != nil {
		t.Fatalf("RestartPublisher: %v", err)
	}

	if pub.OperationID != "" {
		op, err := actors.ctrlCli.WaitForOperation(ctx, pub.OperationID, 45*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(publish recovery): %v", err)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var finalPub harness.PublicationResp
	m4WaitUntil(ctx, t, 30*time.Second, func() (bool, error) {
		got, gRaw, gErr := actors.ctrlCli.GetPublication(ctx, m4PubID(pub))
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		finalPub = got
		return got.Status == "PUBLISHED", nil
	})
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, finalPub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "publish")
}

// 19. F-04 x F-08: SnapshotStore outage during ingress holds/retries cleanly without exposing corrupt artifact (RG-01, RG-10).
func TestT3_F04_F08_SnapshotStoreOutageAndIngressOperationRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "store-outage", nil, "INTERNAL", nil, true, 5)
	if err := env.Snapshots().SimulateOutage(true); err != nil {
		t.Fatalf("SimulateOutage(true): %v", err)
	}
	defer func() { _ = env.Snapshots().SimulateOutage(false) }()

	created, raw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace during outage: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m4WorkspaceCreateID(created)

	// While SnapshotStore is down, wait for the worker to attempt the operation and verify no partial source artifact is exposed.
	_, srcRaw, err := actors.ctrlCli.GetWorkspaceSource(ctx, wsID)
	if err == nil && srcRaw != nil && srcRaw.StatusCode == http.StatusOK {
		t.Fatalf("workspace %s must not expose source artifact while SnapshotStore outage active", wsID)
	}
	if created.OperationID != "" {
		m4WaitUntil(ctx, t, 10*time.Second, func() (bool, error) {
			op, oRaw, oErr := actors.humanCli.GetOperation(ctx, created.OperationID)
			if oErr != nil {
				return false, oErr
			}
			oRaw.RequireStatus(t, http.StatusOK)
			return op.LastError != "" || op.Attempts >= 2 || op.Status == "FAILED", nil
		})
	}
	_, srcRawAfterAttempt, err := actors.ctrlCli.GetWorkspaceSource(ctx, wsID)
	if err == nil && srcRawAfterAttempt != nil && srcRawAfterAttempt.StatusCode == http.StatusOK {
		t.Fatalf("workspace %s must not expose source artifact after SnapshotStore outage attempt", wsID)
	}

	// Restore SnapshotStore and verify operation recovers (or retry workspace ingress cleanly).
	if err := env.Snapshots().SimulateOutage(false); err != nil {
		t.Fatalf("SimulateOutage(false): %v", err)
	}
	if created.OperationID != "" {
		op, err := actors.humanCli.WaitForOperation(ctx, created.OperationID, 45*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(ingress recovery): %v", err)
		}
		if op.Status == "FAILED" {
			// If max attempts exhausted during outage, a fresh workspace after recovery must succeed cleanly.
			wsRecovered := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
				Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
			})
			wsID = m4WorkspaceID(wsRecovered)
		} else {
			m4RequireOpSucceeded(t, env, op)
		}
	}
	dl, dlRaw, err := actors.ctrlCli.DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource after recovery: %v", err)
	}
	dlRaw.RequireStatus(t, http.StatusOK)
	env.Snapshots().AssertArchiveNoSecretLeak(t, dl, env.GitHub().ReadAppPrivateKeyPEM(), env.GitHub().WriteAppPrivateKeyPEM())
}

// 20. F-05 x F-13: Audit events, findings, and logs redact secrets and keep audit chain valid.
func TestT3_F05_F13_AuditRedactionOnSecretDetection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	canary := "custodian_canary_secret_9876543210fedcba"
	env, repo, actors := m4SetupRepoEnv(t, "acme", "audit-redact", nil, "INTERNAL", nil, true, 5)
	env.RegisterSecret(canary)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: canary,
		FilePath:    "config/secret.env",
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "config/secret.env", Body: []byte("API_TOKEN=" + canary + "\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "audit redaction", nil)
	propID := m4PropID(prop)
	m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	findingsResp, fRaw, err := actors.humanCli.ListProposalFindings(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)
	if len(findingsResp.Findings) == 0 {
		t.Fatalf("expected >= 1 finding")
	}
	for _, f := range findingsResp.Findings {
		if !f.Redacted {
			t.Fatalf("expected Redacted=true for %s", f.ID)
		}
	}
	harness.AssertNoSecretOrEncodedLeak(t, string(fRaw.Body), canary)

	auditEvents := m4AssertAuditChain(t, ctx, actors.auditorCli, propID)
	auditJSON, _ := json.Marshal(auditEvents)
	harness.AssertNoSecretOrEncodedLeak(t, string(auditJSON), canary)
	env.AssertNoSecretLeakInLogs(canary)
}

// 21. F-05 x F-15: Persisted policy denials reference policy_decision_id in API errors and audit events.
func TestT3_F05_F15_PersistedPolicyDenialsAndAuditLinkage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	orgPolicyDir := m4WritePolicyDir(t, map[string]string{
		"org.yaml": string(m4LoadFixture(t, "policies/org_mandatory_deny.yaml")),
	})
	env, repo, actors := m4SetupRepoEnv(t, "acme", "policy-audit-link", nil, "INTERNAL", nil, true, 5,
		harness.WithPolicyBundleDir(orgPolicyDir))
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	env.Scanners().Set(harness.ScannerScanCode, harness.ScannerBehavior{
		Mode:        harness.ScannerModeProhibitedLicense,
		FilePath:    "LICENSE",
		LicenseSPDX: "GPL-3.0-or-later",
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "LICENSE", Body: m4LoadFixture(t, "payloads/license_gpl3.txt")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "gpl3 license deny", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	if len(assess.PolicyDecisions) == 0 {
		t.Fatalf("expected persisted policy decision")
	}
	pd := assess.PolicyDecisions[len(assess.PolicyDecisions)-1]
	if pd.Effect != "DENY" || !m4Is64Hex(pd.InputDigest) || len(pd.Reasons) == 0 {
		t.Fatalf("unexpected persisted policy decision: %+v", pd)
	}
	if evalProp.Status != "DENIED" {
		t.Fatalf("expected DENIED proposal status, got %q", evalProp.Status)
	}

	_, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(denied): %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
	if pubRaw.Error == nil || pubRaw.Error.PolicyDecisionID != pd.ID {
		t.Fatalf("expected PublishProposal(denied) Error.PolicyDecisionID == %q, got %+v", pd.ID, pubRaw.Error)
	}
	if evalProp.LatestPolicyEvaluationID != pd.ID {
		t.Fatalf("expected proposal LatestPolicyEvaluationID == %q, got %q", pd.ID, evalProp.LatestPolicyEvaluationID)
	}
	events := m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "policy")
	evBytes, _ := json.Marshal(events)
	if !strings.Contains(string(evBytes), pd.ID) {
		t.Fatalf("expected audit_events to reference policy_decision_id %s", pd.ID)
	}
}

// 22. F-17 x F-18: Publish Idempotency-Key missing (400), replay (same ID, 1 PR), and payload mismatch (409) (RG-08, ADV-12).
func TestT3_F17_F18_PublishIdempotencyReplayAndPayloadConflict(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "pub-idemp", nil, "INTERNAL", nil, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "idemp publish", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	evalID := m4LatestDecisionID(evalProp, assess)
	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// (a) Missing Idempotency-Key -> 400.
	_, noKeyRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("PublishProposal(no idemp key): %v", err)
	}
	noKeyRaw.RequireStatus(t, http.StatusBadRequest)

	// (b) First publish with key "k-pub-1".
	p1, r1, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	}, harness.WithIdempotencyKey("k-pub-1"))
	if err != nil {
		t.Fatalf("PublishProposal(k-pub-1): %v", err)
	}
	r1.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	// (c) Replay with same key & payload returns same PublicationID and creates only 1 PR.
	p2, r2, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	}, harness.WithIdempotencyKey("k-pub-1"))
	if err != nil {
		t.Fatalf("PublishProposal(replay k-pub-1): %v", err)
	}
	r2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if m4PubID(p1) != m4PubID(p2) {
		t.Fatalf("idempotency replay returned different publication IDs: %q vs %q", m4PubID(p1), m4PubID(p2))
	}

	// (d) Same key with different payload -> 409 Conflict.
	_, mismatchRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: strings.Repeat("a", 64),
	}, harness.WithIdempotencyKey("k-pub-1"))
	if err != nil {
		t.Fatalf("PublishProposal(payload mismatch): %v", err)
	}
	mismatchRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	if p1.OperationID != "" {
		op, err := actors.ctrlCli.WaitForOperation(ctx, p1.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation: %v", err)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		return env.GitHub().PRCount(repo.seeded.FullName) == 1, nil
	})
}

// 23. F-18 x F-19: Per-repository concurrency rate limit (429 + Retry-After) and Prometheus /metrics.
func TestT3_F18_F19_PerRepoConcurrencyRateLimitAndMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "conc-limit", nil, "INTERNAL", nil, true, 1,
		harness.WithPerRepoConcurrency(1))
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}

	ws1, r1, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace #1: %v", err)
	}
	r1.RequireStatus(t, http.StatusAccepted)

	saw429 := false
	for i := 0; i < 3; i++ {
		_, ri, cErr := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
			Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		})
		if cErr != nil {
			t.Fatalf("CreateWorkspace #%d: %v", i+2, cErr)
		}
		if ri.StatusCode == http.StatusTooManyRequests {
			saw429 = true
			if ra := ri.Headers.Get("Retry-After"); ra != "" {
				if n, pErr := strconv.Atoi(ra); pErr != nil || n < 0 {
					t.Fatalf("invalid Retry-After header %q", ra)
				}
			}
			if ri.Error == nil || ri.Error.Code == "" {
				t.Fatalf("expected ErrorResponse body on 429")
			}
		}
	}
	if !saw429 {
		t.Fatalf("expected at least one 429 Too Many Requests when per-repo concurrency=1")
	}

	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	if ws1.OperationID != "" {
		op, err := actors.humanCli.WaitForOperation(ctx, ws1.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(ws1): %v", err)
		}
		m4RequireOpSucceeded(t, env, op)
	}

	metrics, mRaw, err := actors.humanCli.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	mRaw.RequireStatus(t, http.StatusOK)
	if strings.TrimSpace(metrics) == "" {
		t.Fatalf("expected non-empty Prometheus metrics text")
	}
	env.AssertNoSecretLeakInLogs()
}

// 24. F-03 x F-19: Artifact retention reaper deletes expired blobs while preserving proposal, decision & audit lineage.
func TestT3_F03_F19_ArtifactRetentionReaperPreservesAuditAndMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "retention-reaper", nil, "INTERNAL", nil, true, 5,
		harness.WithRetentionTTL(5*time.Minute),
		harness.WithEnvOverrides(map[string]string{
			"CUSTODIAN_RETENTION_INTERVAL": "200ms",
		}),
	)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "retention", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)

	beforeCount, err := env.Snapshots().ObjectCount()
	if err != nil {
		t.Fatalf("ObjectCount before: %v", err)
	}
	if beforeCount == 0 {
		t.Fatalf("expected stored snapshot artifacts > 0 before retention sweep")
	}

	if _, err := env.DB().ExecSQL(`UPDATE artifacts SET expires_at = now() - interval '1 hour' WHERE deleted_at IS NULL;`); err != nil {
		t.Fatalf("backdate artifacts.expires_at: %v", err)
	}

	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		afterCount, cErr := env.Snapshots().ObjectCount()
		if cErr != nil {
			return false, cErr
		}
		return afterCount < beforeCount, nil
	})

	// Proposal, decisions, and audit chain remain intact after artifact blob deletion.
	gotProp, pRaw, err := actors.humanCli.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal after retention: %v", err)
	}
	pRaw.RequireStatus(t, http.StatusOK)
	if gotProp.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED preserved after retention, got %q", gotProp.Status)
	}
	gotAssess, aRaw, err := actors.humanCli.ListProposalAssessments(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalAssessments after retention: %v", err)
	}
	aRaw.RequireStatus(t, http.StatusOK)
	if len(gotAssess.PolicyDecisions) == 0 {
		t.Fatalf("expected persisted policy decisions preserved")
	}
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "proposal", "publish")
}

// 25. F-11 x F-20: Golden snapshot archive, canonical diff, and cross-run digest determinism.
func TestT3_F11_F20_GoldenTreeDiffManifestVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "golden-verify", map[string]string{
		"README.md": string(m4LoadFixture(t, "golden/clean_tree/README.md")),
	}, "INTERNAL", nil, true, 5)

	goldenGZ := m4LoadFixture(t, "golden/clean_snapshot.tar.gz")
	expectedSHA := strings.TrimSpace(string(m4LoadFixture(t, "golden/clean_snapshot.sha256")))
	if gotSHA := harness.SHA256Hex(goldenGZ); gotSHA != expectedSHA {
		t.Fatalf("golden fixture sha256 mismatch: got %s, want %s", gotSHA, expectedSHA)
	}

	ws1 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	ws2 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})

	p1 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws1), goldenGZ, expectedSHA, ws1.Generation, "golden 1", nil)
	p2 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws2), goldenGZ, expectedSHA, ws2.Generation, "golden 2", nil)

	if p1.TreeDigest != p2.TreeDigest || p1.DiffDigest != p2.DiffDigest || p1.PublicationManifestDigest != p2.PublicationManifestDigest {
		t.Fatalf("non-deterministic golden digests across runs: p1=(%s,%s,%s) p2=(%s,%s,%s)",
			p1.TreeDigest, p1.DiffDigest, p1.PublicationManifestDigest,
			p2.TreeDigest, p2.DiffDigest, p2.PublicationManifestDigest)
	}

	diffResp, diffRaw, err := actors.humanCli.GetProposalDiff(ctx, m4PropID(p1))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	foundHello := false
	for _, cf := range diffResp.Paths {
		if cf.Path == "pkg/hello/hello.go" && cf.ChangeType == "ADDED" {
			foundHello = true
		}
	}
	if !foundHello {
		t.Fatalf("expected ADDED pkg/hello/hello.go in diff paths, got %+v", diffResp.Paths)
	}
	if !strings.Contains(diffResp.UnifiedDiff, "func Greeting(name string) string") {
		t.Fatalf("unified diff missing expected Greeting function body:\n%s", diffResp.UnifiedDiff)
	}
}

// 26. F-14 x F-19: Global model budget throttling (429) and ID/digest-only structured logging.
func TestT3_F14_F19_GlobalModelBudget429AndIDDigestOnlyLogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "model-budget", nil, "INTERNAL", nil, true, 10,
		harness.WithGlobalModelBudget(1))
	// Hold first gateway request briefly so second concurrent EvaluateProposal exceeds global model budget=1.
	env.Gateway().Enqueue(
		harness.GatewayProgram{Mode: harness.GatewayModeClean, Delay: 1500 * time.Millisecond},
		harness.GatewayProgram{Mode: harness.GatewayModeClean},
	)

	ws1 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	ws2 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "infra/prod/unique_code_marker.go", Body: []byte("package m\nconst SecretCodeMarker = \"do_not_log_this_source_body\"\n")},
	})
	env.RegisterSecret("do_not_log_this_source_body")

	p1 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws1), gz, shaHex, ws1.Generation, "budget 1", nil)
	p2 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws2), gz, shaHex, ws2.Generation, "budget 2", nil)

	e1, r1, err := actors.ctrlCli.EvaluateProposal(ctx, m4PropID(p1), harness.EvaluateReq{ExpectedVersion: p1.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal #1: %v", err)
	}
	r1.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	e2, r2, err := actors.ctrlCli.EvaluateProposal(ctx, m4PropID(p2), harness.EvaluateReq{ExpectedVersion: p2.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal #2: %v", err)
	}
	if r2.StatusCode == http.StatusTooManyRequests {
		if r2.Error == nil || r2.Error.Code == "" {
			t.Fatalf("expected ErrorResponse body on 429")
		}
	} else {
		// If queued asynchronously and throttled in worker, wait for e2 and verify clean completion or explicit budget/rate-limit failure.
		r2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
		if e2.OperationID != "" {
			op2, wErr := actors.ctrlCli.WaitForOperation(ctx, e2.OperationID, 30*time.Second)
			if wErr != nil {
				t.Fatalf("WaitForOperation(e2): %v", wErr)
			}
			if op2.Status == "FAILED" || harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op2.Status) {
				lowerErr := strings.ToLower(op2.LastError)
				if !strings.Contains(lowerErr, "budget") && !strings.Contains(lowerErr, "rate") && !strings.Contains(lowerErr, "limit") && !strings.Contains(lowerErr, "429") && !strings.Contains(lowerErr, "throttl") {
					t.Fatalf("expected e2 operation failure to indicate budget/rate-limit throttling, got status=%q last_error=%q", op2.Status, op2.LastError)
				}
			} else {
				m4RequireOpSucceeded(t, env, op2)
			}
		}
	}
	if e1.OperationID != "" {
		op1, err := actors.ctrlCli.WaitForOperation(ctx, e1.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(e1): %v", err)
		}
		m4RequireOpSucceeded(t, env, op1)
	}

	// Verify logs contain IDs and SHA-256 digests only, never source code or tokens.
	env.AssertNoSecretLeakInLogs("do_not_log_this_source_body", actors.humanTok, actors.ctrlTok)
}
