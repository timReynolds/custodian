package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

type t1pgPolicyValidateOut struct {
	Valid         bool   `json:"valid"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Scope         string `json:"scope"`
	Digest        string `json:"digest"`
	RulesCompiled int    `json:"rules_compiled"`
}

type t1pgPolicyEvalOut struct {
	Effect         string                    `json:"effect"`
	BundleDigest   string                    `json:"bundle_digest"`
	InputDigest    string                    `json:"input_digest"`
	MatchedRuleIDs []string                  `json:"matched_rule_ids"`
	Reasons        []harness.PolicyReasonDTO `json:"reasons"`
	Obligations    []harness.ObligationDTO   `json:"obligations"`
	RuleTrace      []harness.RuleTraceDTO    `json:"rule_trace"`
	HadError       bool                      `json:"had_error"`
}

func t1pgPolicyDirWithRepoPushDefault(t testing.TB, extra map[string]string) string {
	t.Helper()
	root := pgFindRepoRoot(t)
	dir := t.TempDir()

	files := []struct {
		src string
		dst string
	}{
		{
			src: filepath.Join(root, "test", "e2e", "fixtures", "policies", "valid_default.yaml"),
			dst: "valid_default.yaml",
		},
		{
			src: filepath.Join(root, "policies", "defaults", "push-ip-protection.yaml"),
			dst: "push-ip-protection.yaml",
		},
	}
	for _, f := range files {
		data, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatalf("read policy %q: %v", f.src, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.dst), data, 0o644); err != nil {
			t.Fatalf("write temp policy %q: %v", f.dst, err)
		}
	}
	for name, content := range extra {
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", dst, err)
		}
		if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
			t.Fatalf("write extra policy %q: %v", name, err)
		}
	}
	return dir
}

func t1pgRunPolicyValidate(t testing.TB, env *harness.Env, bundlePath string) t1pgPolicyValidateOut {
	t.Helper()
	ct := env.Contracts()
	args := append([]string(nil), ct.CLI.PolicyValidateSubcommand...)
	if len(args) == 0 {
		args = []string{"validate"}
	}
	bundleFlag := ct.CLI.PolicyBundleFlag
	if bundleFlag == "" {
		bundleFlag = "--bundle"
	}
	args = append(args, bundleFlag, bundlePath, "--format", "json")
	res := env.RunCLI(ct.Binaries.Policy, args, nil)
	if res.ExitCode != 0 {
		t.Fatalf("custodian-policy validate %s failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			bundlePath, res.ExitCode, res.Stdout, res.Stderr)
	}
	var out t1pgPolicyValidateOut
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("decode validate JSON %q: %v", res.Stdout, err)
	}
	return out
}

func t1pgRunPolicySuite(t testing.TB, env *harness.Env, testDir string) {
	t.Helper()
	ct := env.Contracts()
	args := append([]string(nil), ct.CLI.PolicyTestSubcommand...)
	if len(args) == 0 {
		args = []string{"test"}
	}
	args = append(args, testDir)
	res := env.RunCLI(ct.Binaries.Policy, args, nil)
	if res.ExitCode != 0 {
		t.Fatalf("custodian-policy test %s failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			testDir, res.ExitCode, res.Stdout, res.Stderr)
	}
}

func t1pgRunPolicyEvaluate(t testing.TB, env *harness.Env, bundlePath, orgBundlePath, stage string, input map[string]any) t1pgPolicyEvalOut {
	t.Helper()
	rawInput, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		t.Fatalf("marshal policy input: %v", err)
	}
	inputPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inputPath, rawInput, 0o644); err != nil {
		t.Fatalf("write input JSON: %v", err)
	}

	ct := env.Contracts()
	args := append([]string(nil), ct.CLI.PolicyEvaluateSubcommand...)
	if len(args) == 0 {
		args = []string{"evaluate"}
	}
	bundleFlag := ct.CLI.PolicyBundleFlag
	if bundleFlag == "" {
		bundleFlag = "--bundle"
	}
	inputFlag := ct.CLI.PolicyInputFlag
	if inputFlag == "" {
		inputFlag = "--input"
	}
	args = append(args, bundleFlag, bundlePath, inputFlag, inputPath, "--format", "json")
	if orgBundlePath != "" {
		args = append(args, "--org-bundle", orgBundlePath)
	}
	if stage != "" {
		args = append(args, "--stage", stage)
	}

	res := env.RunCLI(ct.Binaries.Policy, args, nil)
	if res.ExitCode != 0 {
		t.Fatalf("custodian-policy evaluate failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}
	var out t1pgPolicyEvalOut
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("decode evaluate JSON %q: %v", res.Stdout, err)
	}
	return out
}

func t1pgSeededHTTPSPush(
	t testing.TB,
	env *harness.Env,
	repoFullName string,
	token string,
	branch string,
	files map[string]string,
	commitMsg string,
) (string, string, pgGitResult) {
	t.Helper()
	workDir, cloneRes := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repoFullName), token, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP(%s) failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			repoFullName, cloneRes.ExitCode, cloneRes.Stdout, cloneRes.Stderr)
	}
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name)
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email)
	if branch != "" && branch != "main" {
		if res := pgRunHardenedGit(workDir, nil, "checkout", "-b", branch); res.ExitCode != 0 {
			t.Fatalf("git checkout -b %s: %s", branch, res.Stderr)
		}
	} else {
		branch = "main"
	}
	tipSHA := pgAddCommit(t, workDir, files, nil, commitMsg, author)
	pushRes := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repoFullName), token, "HEAD:refs/heads/"+branch, env.GitGatewayCACertPath())
	return workDir, tipSHA, pushRes
}

func t1pgFindLatestPushForRepo(t testing.TB, env *harness.Env, cli *harness.APIClient, repoID string) harness.PushSessionResp {
	t.Helper()
	return t1pgWaitLatestPush(t, env, cli, repoID, 20*time.Second)
}

func t1pgRunPushStatusCLI(t testing.TB, env *harness.Env, token, pushID string) (harness.CLIResult, harness.PushSessionResp) {
	t.Helper()
	ct := env.Contracts()
	args := append([]string(nil), ct.CLI.PushStatusSubcommand...)
	if len(args) == 0 {
		args = []string{"push", "status"}
	}
	args = append(args, pushID)
	cliEnv := map[string]string{}
	if token != "" {
		cliEnv["CUSTODIAN_TOKEN"] = token
	}
	res := env.RunCLI(ct.Binaries.Custodian, args, cliEnv)
	var parsed harness.PushSessionResp
	if res.ExitCode == 0 && strings.TrimSpace(res.Stdout) != "" {
		if err := json.Unmarshal([]byte(res.Stdout), &parsed); err != nil {
			t.Fatalf("decode custodian push status JSON %q: %v", res.Stdout, err)
		}
	}
	return res, parsed
}

func t1pgExtractMetricSum(metricsText, metricName string, requiredLabels ...string) (float64, bool) {
	var sum float64
	found := false
	for _, line := range strings.Split(metricsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, metricName) {
			continue
		}
		rest := line[len(metricName):]
		if rest == "" || (rest[0] != '{' && rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		labelMatch := true
		for _, lbl := range requiredLabels {
			if !strings.Contains(line, lbl) {
				labelMatch = false
				break
			}
		}
		if !labelMatch {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		sum += val
		found = true
	}
	return sum, found
}

func t1pgAssertSidebandContains(t testing.TB, stderr string, substrings ...string) {
	t.Helper()
	var remoteLines []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "remote:") {
			remoteLines = append(remoteLines, line)
		}
	}
	if len(remoteLines) == 0 {
		t.Fatalf("expected sideband channel-2 'remote:' lines in git stderr, got:\n%s", stderr)
	}
	joined := strings.ToLower(strings.Join(remoteLines, "\n"))
	for _, sub := range substrings {
		if !strings.Contains(joined, strings.ToLower(sub)) {
			t.Fatalf("expected sideband output to contain %q, got:\n%s", sub, strings.Join(remoteLines, "\n"))
		}
	}
}

func t1pgSetRepoClassification(t testing.TB, env *harness.Env, repoID, classification string) {
	t.Helper()
	q := fmt.Sprintf("UPDATE repositories SET classification = %s WHERE id = %s::uuid;",
		t1pgSQLQuote(classification), t1pgSQLQuote(repoID))
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("update repository %s classification=%s: %v", repoID, classification, err)
	}
}

func t1pgScrapeGatewayMetrics(t testing.TB, env *harness.Env) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.GitGatewayMetricsURL(), nil)
	if err != nil {
		t.Fatalf("NewRequest(gateway metrics): %v", err)
	}
	resp, err := env.GitGatewayHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", env.GitGatewayMetricsURL(), err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway /metrics status = %d, body=%s", resp.StatusCode, string(body))
	}
	return string(body)
}

// --- EF11: PUSH_EGRESS Policy & Default Hard-Block (5 tests) ---

func TestT1_PG_EF11_DefaultPushIPProtectionBundleValidatesAndLoads(t *testing.T) {
	pgRequireGatewayBinary(t)
	root := pgFindRepoRoot(t)
	defaultPushBundle := filepath.Join(root, "policies", "defaults", "push-ip-protection.yaml")
	testsDir := filepath.Join(root, "policies", "tests")

	cliEnv := harness.NewEnv(t,
		harness.WithRepoRoot(root),
		harness.WithSkipPostgres(),
		harness.WithSkipServices(),
	)
	valOut := t1pgRunPolicyValidate(t, cliEnv, defaultPushBundle)
	if !valOut.Valid {
		t.Fatalf("expected push-ip-protection.yaml to be valid, got %+v", valOut)
	}
	if valOut.RulesCompiled != 13 {
		t.Fatalf("expected 13 compiled rules in push-ip-protection.yaml, got %d", valOut.RulesCompiled)
	}
	if valOut.Scope != "ORG" {
		t.Fatalf("expected scope=ORG, got %q", valOut.Scope)
	}
	t1pgRunPolicySuite(t, cliEnv, testsDir)

	env, _, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	rows, err := env.DB().QueryRows("SELECT name, digest, activated_at IS NOT NULL FROM policy_bundles WHERE name = 'push-ip-protection' ORDER BY created_at DESC LIMIT 1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("expected push-ip-protection bundle loaded into policy_bundles, rows=%v err=%v", rows, err)
	}
	if rows[0][1] != valOut.Digest {
		t.Fatalf("loaded DB digest %q != CLI validated digest %q", rows[0][1], valOut.Digest)
	}
	if rows[0][2] != "t" && rows[0][2] != "true" {
		t.Fatalf("expected push-ip-protection bundle activated_at IS NOT NULL, got %q", rows[0][2])
	}
}

func TestT1_PG_EF11_RegisteredInternalCleanPushAllowed(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)

	root := pgFindRepoRoot(t)
	defaultPushBundle := filepath.Join(root, "policies", "defaults", "push-ip-protection.yaml")
	evalOut := t1pgRunPolicyEvaluate(t, env, defaultPushBundle, "", "PUSH_EGRESS", map[string]any{
		"stage": "PUSH_EGRESS",
		"destination": map[string]any{
			"id":             repoID,
			"name":           repo.FullName,
			"host":           "github.com",
			"registered":     true,
			"external":       false,
			"classification": "INTERNAL",
		},
		"findings": map[string]any{
			"scan_complete":               true,
			"mandatory_scanners_complete": true,
			"critical_secrets":            0,
			"prohibited_licenses":         0,
			"restricted_ip_matches":       0,
			"ip_header_strip_matches":     0,
			"concealment_findings":        0,
		},
		"assessment": map[string]any{
			"status":      "NOT_REQUIRED",
			"disposition": "NOT_REQUIRED",
			"ip_risk":     "NONE",
			"risk":        "NONE",
		},
		"push": map[string]any{
			"has_lfs":      false,
			"commit_count": 1,
			"egress_mode":  "ENFORCE_BLOCK",
			"ref_names":    []string{"refs/heads/main"},
		},
	})
	if evalOut.Effect != "ALLOW" {
		t.Fatalf("expected ALLOW from push-ip-protection.yaml, got %+v", evalOut)
	}
	if len(evalOut.MatchedRuleIDs) != 1 || evalOut.MatchedRuleIDs[0] != "push.allow" {
		t.Fatalf("expected matched_rule_ids=[push.allow], got %v", evalOut.MatchedRuleIDs)
	}

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"clean.go": cleanSrc,
	}, "feat: clean internal push")
	if res.ExitCode != 0 {
		t.Fatalf("clean push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if push.PolicyEffect != "ALLOW" || !push.DestinationRegistered || push.DestinationExternal || !push.UpstreamForwarded {
		t.Fatalf("unexpected push session state: %+v", push)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF11_UnregisteredRepoDefaultDeny(t *testing.T) {
	env := pgNewEnv(t,
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
		harness.WithGitGateway(harness.WithGitGatewayDefaultEgressMode("ENFORCE_BLOCK")),
	)
	actors := pgMintActors(env)

	root := pgFindRepoRoot(t)
	defaultPushBundle := filepath.Join(root, "policies", "defaults", "push-ip-protection.yaml")
	evalOut := t1pgRunPolicyEvaluate(t, env, defaultPushBundle, "", "PUSH_EGRESS", map[string]any{
		"stage": "PUSH_EGRESS",
		"destination": map[string]any{
			"name":       "unregistered/personal-repo",
			"host":       "github.com",
			"registered": false,
			"external":   true,
		},
		"findings": map[string]any{
			"scan_complete": true,
		},
		"assessment": map[string]any{
			"status":      "NOT_REQUIRED",
			"disposition": "NOT_REQUIRED",
		},
	})
	if evalOut.Effect != "DENY" {
		t.Fatalf("expected DENY for unregistered destination, got %+v", evalOut)
	}
	foundRule := false
	for _, r := range evalOut.MatchedRuleIDs {
		if r == "push.destination.unregistered_or_external" {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Fatalf("expected push.destination.unregistered_or_external in matched_rule_ids, got %v", evalOut.MatchedRuleIDs)
	}

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	workDir := pgCreateGitRepoWithFiles(t, map[string]string{
		"README.md":        "# personal repo\n",
		"clean_feature.go": cleanSrc,
	}, "feat: attempt push to unregistered personal repo", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, "unregistered/personal-repo"), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected push to unregistered/personal-repo to be denied")
	}
	pgAssertZeroUpstreamReceivePack(t, env, "unregistered/personal-repo")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listResp, raw, err := actors.SecAdminCli.ListPushes(ctx, harness.PushFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListPushes: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	var matched *harness.PushSessionResp
	for i := range listResp.Pushes {
		if strings.Contains(listResp.Pushes[i].Destination, "unregistered/personal-repo") {
			matched = &listResp.Pushes[i]
			break
		}
	}
	if matched == nil {
		t.Fatalf("expected recorded push session for unregistered/personal-repo in %+v", listResp.Pushes)
	}
	if matched.PolicyEffect != "DENY" || matched.DestinationRegistered {
		t.Fatalf("expected PolicyEffect=DENY and DestinationRegistered=false, got %+v", *matched)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF11_ExternalDestinationDefaultDenyAndStandaloneOverride(t *testing.T) {
	extSpec := harness.RepoSeedSpec{
		Owner:         "partner",
		Name:          "mirror",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# partner/mirror\n"},
	}
	env := pgNewEnv(t,
		harness.WithSeedRepos(extSpec),
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)

	repo, ok := env.Git().Repo("partner/mirror")
	if !ok {
		t.Fatalf("partner/mirror missing from BareGitHelper")
	}
	repoID := harness.NewTestUUIDv7()
	q := fmt.Sprintf(
		`INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, registered_destination, external)
		 VALUES (%s::uuid, %d, %d, %s, 'INTERNAL', true, ARRAY['approved-code-review']::text[], 10, 'ENFORCE_BLOCK', true, true);`,
		t1pgSQLQuote(repoID), repo.GitHubRepoID, repo.InstallationID, t1pgSQLQuote(repo.FullName),
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("insert external repo row: %v", err)
	}

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	env.GitHub().ResetPacketCounters()
	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"clean_feature.go": cleanSrc,
	}, "feat: push to registered external repo")
	if res.ExitCode == 0 {
		t.Fatalf("expected default policy to DENY registered external destination")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if push.PolicyEffect != "DENY" || !push.DestinationExternal {
		t.Fatalf("expected PolicyEffect=DENY and DestinationExternal=true, got %+v", push)
	}

	root := pgFindRepoRoot(t)
	defaultPushBundle := filepath.Join(root, "policies", "defaults", "push-ip-protection.yaml")
	allowExtFixture := filepath.Join(root, "test", "e2e", "fixtures", "push_gateway", "policies", "push_repo_allow_external.yaml")
	illegalOverrideFixture := filepath.Join(root, "test", "e2e", "fixtures", "push_gateway", "policies", "push_repo_illegal_override.yaml")

	// Standalone REPO policy allows clean external push.
	standaloneOut := t1pgRunPolicyEvaluate(t, env, allowExtFixture, "", "PUSH_EGRESS", map[string]any{
		"stage": "PUSH_EGRESS",
		"destination": map[string]any{
			"name":       "partner/mirror",
			"registered": true,
			"external":   true,
		},
		"findings": map[string]any{
			"scan_complete": true,
		},
		"assessment": map[string]any{
			"status":      "NOT_REQUIRED",
			"disposition": "NOT_REQUIRED",
		},
	})
	if standaloneOut.Effect != "ALLOW" {
		t.Fatalf("expected standalone push_repo_allow_external.yaml to evaluate ALLOW, got %+v", standaloneOut)
	}

	// Composed under ORG bundle, illegal override on overridable=false rule cannot weaken DENY.
	composedOut := t1pgRunPolicyEvaluate(t, env, illegalOverrideFixture, defaultPushBundle, "PUSH_EGRESS", map[string]any{
		"stage": "PUSH_EGRESS",
		"destination": map[string]any{
			"name":       "acme/service",
			"registered": true,
			"external":   false,
		},
		"findings": map[string]any{
			"scan_complete":         true,
			"restricted_ip_matches": 1,
		},
		"assessment": map[string]any{
			"status":      "NOT_REQUIRED",
			"disposition": "NOT_REQUIRED",
		},
	})
	if composedOut.Effect != "DENY" {
		t.Fatalf("expected composed illegal override to stay DENY (overridable=false), got %+v", composedOut)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF11_CELEvaluationOfPushAndFindingsInputs(t *testing.T) {
	pgRequireGatewayBinary(t)
	root := pgFindRepoRoot(t)
	cliEnv := harness.NewEnv(t,
		harness.WithRepoRoot(root),
		harness.WithSkipPostgres(),
		harness.WithSkipServices(),
	)

	defaultPushBundle := filepath.Join(root, "policies", "defaults", "push-ip-protection.yaml")
	lfsGateBundle := filepath.Join(root, "test", "e2e", "fixtures", "push_gateway", "policies", "push_lfs_gate.yaml")

	baseClean := func() map[string]any {
		return map[string]any{
			"stage": "PUSH_EGRESS",
			"destination": map[string]any{
				"name":       "acme/service",
				"registered": true,
				"external":   false,
			},
			"findings": map[string]any{
				"scan_complete": true,
			},
			"assessment": map[string]any{
				"status":      "NOT_REQUIRED",
				"disposition": "NOT_REQUIRED",
			},
		}
	}

	// PushInput cases on push_lfs_gate.yaml.
	inOversizeLFS := baseClean()
	inOversizeLFS["push"] = map[string]any{"has_lfs": true, "lfs_total_bytes": 2097152}
	if out := t1pgRunPolicyEvaluate(t, cliEnv, lfsGateBundle, "", "PUSH_EGRESS", inOversizeLFS); out.Effect != "REQUIRE_APPROVAL" {
		t.Fatalf("oversize LFS expected REQUIRE_APPROVAL, got %+v", out)
	}

	inBoundedLFS := baseClean()
	inBoundedLFS["push"] = map[string]any{"has_lfs": true, "lfs_total_bytes": 512}
	if out := t1pgRunPolicyEvaluate(t, cliEnv, lfsGateBundle, "", "PUSH_EGRESS", inBoundedLFS); out.Effect != "ALLOW" {
		t.Fatalf("bounded LFS expected ALLOW, got %+v", out)
	}

	inUnregLFS := baseClean()
	inUnregLFS["destination"].(map[string]any)["registered"] = false
	inUnregLFS["push"] = map[string]any{"has_lfs": true, "lfs_total_bytes": 512}
	if out := t1pgRunPolicyEvaluate(t, cliEnv, lfsGateBundle, "", "PUSH_EGRESS", inUnregLFS); out.Effect != "DENY" {
		t.Fatalf("unregistered LFS expected DENY, got %+v", out)
	}

	// Additive FindingsInput counters on push-ip-protection.yaml.
	inRestrictedIP := baseClean()
	inRestrictedIP["findings"].(map[string]any)["restricted_ip_matches"] = 1
	if out := t1pgRunPolicyEvaluate(t, cliEnv, defaultPushBundle, "", "PUSH_EGRESS", inRestrictedIP); out.Effect != "DENY" {
		t.Fatalf("restricted_ip_matches=1 expected DENY, got %+v", out)
	}

	inHeaderStrip := baseClean()
	inHeaderStrip["findings"].(map[string]any)["ip_header_strip_matches"] = 1
	if out := t1pgRunPolicyEvaluate(t, cliEnv, defaultPushBundle, "", "PUSH_EGRESS", inHeaderStrip); out.Effect != "DENY" {
		t.Fatalf("ip_header_strip_matches=1 expected DENY, got %+v", out)
	}

	inConcealment := baseClean()
	inConcealment["findings"].(map[string]any)["concealment_findings"] = 1
	if out := t1pgRunPolicyEvaluate(t, cliEnv, defaultPushBundle, "", "PUSH_EGRESS", inConcealment); out.Effect != "QUARANTINE" {
		t.Fatalf("concealment_findings=1 expected QUARANTINE, got %+v", out)
	}

	inConfidential := baseClean()
	inConfidential["findings"].(map[string]any)["confidential_ip_matches"] = 1
	inConfidential["findings"].(map[string]any)["ip_winnow_matches"] = 1
	confOut := t1pgRunPolicyEvaluate(t, cliEnv, defaultPushBundle, "", "PUSH_EGRESS", inConfidential)
	if confOut.Effect != "REQUIRE_APPROVAL" {
		t.Fatalf("confidential_ip_matches=1 expected REQUIRE_APPROVAL, got %+v", confOut)
	}
	hasIPReviewObligation := false
	for _, obl := range confOut.Obligations {
		if obl.ReviewerGroup == "ip-review" && obl.Minimum >= 1 {
			hasIPReviewObligation = true
			break
		}
	}
	if !hasIPReviewObligation {
		t.Fatalf("expected ip-review obligation on confidential IP match, got %+v", confOut.Obligations)
	}
}

// --- EF12: Conditional Stage B Provenance (5 tests) ---

func TestT1_PG_EF12_CleanPushLeavesStageBNotRequiredWithZeroCalls(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)
	env.Gateway().ResetRequests()

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"clean.go": cleanSrc,
	}, "feat: clean push without stage B")
	if res.ExitCode != 0 {
		t.Fatalf("clean push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	if reqs := env.Gateway().Requests(); len(reqs) != 0 {
		t.Fatalf("expected 0 Stage B model gateway requests on untriggered clean push, got %d", len(reqs))
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if push.AssessmentStatus != "NOT_REQUIRED" || push.AssessmentDisposition != "NOT_REQUIRED" {
		t.Fatalf("expected NOT_REQUIRED assessment on push, got status=%q disposition=%q",
			push.AssessmentStatus, push.AssessmentDisposition)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT status, disposition, model_route FROM model_assessments WHERE push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("expected persisted NOT_REQUIRED model_assessments row, rows=%v err=%v", rows, err)
	}
	if rows[0][0] != "NOT_REQUIRED" || rows[0][1] != "NOT_REQUIRED" {
		t.Fatalf("unexpected model_assessments row: %+v", rows[0])
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF12_ConcealmentOrIPTriggerInvokesStageB(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef12-restricted-trigger", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			evIDs := req.EvidenceIDs
			findings := []harness.StageBFinding{}
			if len(evIDs) > 0 {
				findings = append(findings, harness.StageBFinding{
					Category:          "IP_PROVENANCE",
					EvidenceIDs:       evIDs,
					Reason:            "Stage A concealment or restricted IP trigger confirmed",
					RecommendedAction: "IP_REVIEW",
				})
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "HIGH",
				Disposition:    "REVIEW",
				Confidence:     0.93,
				Summary:        "Triggered IP provenance review",
				Findings:       findings,
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})
	env.Gateway().ResetRequests()

	b64Src := t1pgReadQuarantineFixture(t, "payloads", "concealed_base64.txt")
	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"concealed.txt": b64Src,
	}, "feat: trigger Stage B via concealment")
	if res.ExitCode == 0 {
		t.Fatalf("expected concealed push triggering Stage B to be blocked/quarantined")
	}

	reqs := env.Gateway().Requests()
	if len(reqs) < 1 {
		t.Fatalf("expected >= 1 Stage B request to MockGateway on concealment trigger")
	}
	if reqs[0].Route != "approved-code-review" {
		t.Fatalf("expected route approved-code-review, got %q", reqs[0].Route)
	}
	if len(reqs[0].Messages) < 2 {
		t.Fatalf("expected system + user messages in Stage B request, got %+v", reqs[0].Messages)
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	harness.AssertUUIDv7(t, push.AssessmentID)

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF12_StageBClearAndPassingPolicyAllowsPush(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)
	t1pgSetRepoClassification(t, env, repoID, "RESTRICTED")

	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "LOW",
				Disposition:    "CLEAR",
				Confidence:     0.97,
				Summary:        "Clean change on restricted repo cleared by Stage B",
				Findings:       []harness.StageBFinding{},
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})
	env.Gateway().ResetRequests()

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, tipSHA, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"clean_on_restricted.go": cleanSrc,
	}, "feat: clean push on RESTRICTED repo")
	if res.ExitCode != 0 {
		t.Fatalf("expected Stage B CLEAR push on clean file to succeed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	if reqs := env.Gateway().Requests(); len(reqs) != 1 {
		t.Fatalf("expected 1 Stage B request on RESTRICTED repo, got %d", len(reqs))
	}
	gotHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotHead != tipSHA {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotHead, err, tipSHA)
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if push.AssessmentStatus != "COMPLETE" || push.AssessmentDisposition != "CLEAR" || push.PolicyEffect != "ALLOW" || !push.UpstreamForwarded {
		t.Fatalf("unexpected push fields after Stage B CLEAR: %+v", push)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF12_StageBBlockAndEscalatePreventUpstreamForwarding(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)
	t1pgSetRepoClassification(t, env, repoID, "RESTRICTED")

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")

	// Subtest A: Stage B BLOCK -> DENY, 0 upstream bytes.
	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "CRITICAL",
				Disposition:    "BLOCK",
				Confidence:     0.98,
				Summary:        "Stage B blocked exfiltration risk",
				Findings:       []harness.StageBFinding{},
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})
	env.GitHub().ResetPacketCounters()
	_, _, resBlock := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "feat/stageb-block", map[string]string{
		"a.go": cleanSrc,
	}, "feat: stage B block")
	if resBlock.ExitCode == 0 {
		t.Fatalf("expected Stage B BLOCK to fail push")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pBlock := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)[0]
	if pBlock.PolicyEffect != "DENY" || pBlock.UpstreamForwarded {
		t.Fatalf("expected DENY and upstream_forwarded=false on Stage B BLOCK, got %+v", pBlock)
	}

	// Subtest B: Stage B ESCALATE -> REQUIRE_APPROVAL (push.model.review), 0 upstream bytes.
	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "HIGH",
				Disposition:    "ESCALATE",
				Confidence:     0.85,
				Summary:        "Stage B escalated for human security review",
				Findings:       []harness.StageBFinding{},
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})
	env.GitHub().ResetPacketCounters()
	_, _, resEscalate := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "feat/stageb-escalate", map[string]string{
		"b.go": cleanSrc,
	}, "feat: stage B escalate")
	if resEscalate.ExitCode == 0 {
		t.Fatalf("expected Stage B ESCALATE to require approval and fail push")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pEscalate := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)[0]
	if pEscalate.PolicyEffect != "REQUIRE_APPROVAL" || pEscalate.UpstreamForwarded {
		t.Fatalf("expected REQUIRE_APPROVAL and upstream_forwarded=false on Stage B ESCALATE, got %+v", pEscalate)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF12_StageBAssessmentPersistedAndLinkedToPushSession(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)
	t1pgSetRepoClassification(t, env, repoID, "RESTRICTED")

	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			findings := []harness.StageBFinding{}
			if len(req.EvidenceIDs) > 0 {
				findings = append(findings, harness.StageBFinding{
					Category:          "IP_PROVENANCE",
					EvidenceIDs:       req.EvidenceIDs,
					Reason:            "Grounded Stage A evidence check",
					RecommendedAction: "IP_REVIEW",
				})
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "HIGH",
				Disposition:    "REVIEW",
				Confidence:     0.91,
				Summary:        "Persisted IP provenance assessment",
				Findings:       findings,
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"persist_stageb.go": cleanSrc,
	}, "feat: persist Stage B assessment")
	if res.ExitCode == 0 {
		t.Fatalf("expected REVIEW disposition to require approval")
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	harness.AssertUUIDv7(t, push.AssessmentID)

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT id::text, proposal_id IS NULL, push_session_id::text, model_route, status, disposition, input_digest, output_digest
		 FROM model_assessments WHERE push_session_id = %s::uuid`,
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query model_assessments for push %s: rows=%v err=%v", push.ID, rows, err)
	}
	if rows[0][0] != push.AssessmentID {
		t.Fatalf("model_assessments.id %q != push.AssessmentID %q", rows[0][0], push.AssessmentID)
	}
	if rows[0][1] != "t" && rows[0][1] != "true" {
		t.Fatalf("expected proposal_id IS NULL on push model_assessment, got %q", rows[0][1])
	}
	if rows[0][2] != push.ID {
		t.Fatalf("push_session_id %q != %q", rows[0][2], push.ID)
	}
	if rows[0][3] != "approved-code-review" {
		t.Fatalf("model_route = %q, want approved-code-review", rows[0][3])
	}
	if rows[0][4] != "COMPLETE" || rows[0][5] != "REVIEW" {
		t.Fatalf("expected status=COMPLETE disposition=REVIEW, got %s / %s", rows[0][4], rows[0][5])
	}
	if !t1pgIsHex64(rows[0][6]) || !t1pgIsHex64(rows[0][7]) {
		t.Fatalf("expected 64-hex input/output digests, got %q / %q", rows[0][6], rows[0][7])
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

// --- EF13: Sideband Channel-2, Zero-Byte Upstream, Clean Repack & push_approval_releases (5 tests) ---

func TestT1_PG_EF13_SidebandChannel2StreamsProgressAndVerdict(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, allowRes := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"sideband_ok.go": cleanSrc,
	}, "feat: sideband allow")
	if allowRes.ExitCode != 0 {
		t.Fatalf("clean push failed (exit %d): %s", allowRes.ExitCode, allowRes.Stderr)
	}
	t1pgAssertSidebandContains(t, allowRes.Stderr, "ALLOW")

	// Deny push to unregistered destination streams DENY verdict over sideband-2.
	unregDir := pgCreateGitRepoWithFiles(t, map[string]string{
		"unreg.go": cleanSrc,
	}, "feat: sideband deny", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	denyRes := pgGitPushHTTP(t, unregDir, t1pgGatewayRepoURL(env, "unregistered/sideband-deny"), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if denyRes.ExitCode == 0 {
		t.Fatalf("expected push to unregistered repo to fail")
	}
	t1pgAssertSidebandContains(t, denyRes.Stderr, "DENY")

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF13_DenyAndQuarantineSendZeroBytesUpstream(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	// Case 1: DENY via secret finding -> 0 upstream bytes.
	const canary = "AKIAIOSFODNN7EXAMPLE"
	env.RegisterSecret(canary)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: canary,
		FilePath:    "secrets.env",
	})
	env.GitHub().ResetPacketCounters()
	_, _, denyRes := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"secrets.env": "AWS_ACCESS_KEY_ID=" + canary + "\n",
	}, "chore: secret push")
	if denyRes.ExitCode == 0 {
		t.Fatalf("expected secret push to be denied")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pDeny := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)[0]
	if pDeny.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=false on DENY")
	}
	dbRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT upstream_forwarded, upstream_bytes_sent FROM push_sessions WHERE id = %s::uuid",
		t1pgSQLQuote(pDeny.ID),
	))
	if err != nil || len(dbRows) == 0 || dbRows[0][1] != "0" {
		t.Fatalf("expected upstream_bytes_sent=0 in push_sessions, rows=%v err=%v", dbRows, err)
	}

	// Case 2: QUARANTINE via concealment-only payload (no RESTRICTED IP markers) -> 0 upstream bytes.
	env.Scanners().ResetAll()
	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "LOW",
				Disposition:    "CLEAR",
				Confidence:     0.95,
				Summary:        "Stage B cleared non-IP concealment test artifact",
				Findings:       []harness.StageBFinding{},
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})
	disguisedELF := string(append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, []byte("benign notes text disguised as elf binary")...))
	env.GitHub().ResetPacketCounters()
	_, _, quarRes := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"docs/notes.txt": disguisedELF,
	}, "feat: concealed quarantine")
	if quarRes.ExitCode == 0 {
		t.Fatalf("expected concealed push to be quarantined")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pQuar := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)[0]
	if pQuar.Status != "QUARANTINED" || pQuar.PolicyEffect != "QUARANTINE" || pQuar.UpstreamForwarded {
		t.Fatalf("expected QUARANTINED / QUARANTINE and upstream_forwarded=false, got %+v", pQuar)
	}
	if pQuar.AssessmentStatus != "COMPLETE" || pQuar.AssessmentDisposition != "CLEAR" {
		t.Fatalf("expected Stage B COMPLETE/CLEAR so push.concealment.quarantine triggered QUARANTINE, got %+v", pQuar)
	}
	qRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT upstream_forwarded, upstream_bytes_sent FROM push_sessions WHERE id = %s::uuid",
		t1pgSQLQuote(pQuar.ID),
	))
	if err != nil || len(qRows) == 0 || qRows[0][1] != "0" {
		t.Fatalf("expected upstream_bytes_sent=0 for QUARANTINED push, rows=%v err=%v", qRows, err)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, canary)
}

func TestT1_PG_EF13_AllowCleanRepacksAndForwardsUpstream(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	env.GitHub().ResetPacketCounters()

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, tipSHA, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "feat/clean-repack", map[string]string{
		"pkg/repack/clean.go": cleanSrc,
	}, "feat: clean repack forwarding")
	if res.ExitCode != 0 {
		t.Fatalf("clean repack push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	if len(env.GitHub().ReceivePackCalls()) == 0 {
		t.Fatalf("expected >= 1 upstream receive-pack call")
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) <= 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0")
	}
	gotSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/feat/clean-repack")
	if err != nil || gotSHA != tipSHA {
		t.Fatalf("upstream feat/clean-repack = %q (err=%v), want %q", gotSHA, err, tipSHA)
	}
	tree, err := env.Git().InspectTree(repo.FullName, tipSHA)
	if err != nil || tree["pkg/repack/clean.go"] != cleanSrc {
		t.Fatalf("upstream tree mismatch for pkg/repack/clean.go (err=%v)", err)
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if !push.UpstreamForwarded || !t1pgIsHex64(push.PushManifestDigest) {
		t.Fatalf("expected upstream_forwarded=true and 64-hex digest, got %+v", push)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF13_RequireApprovalBlocksThenApprovePushReleasesOnce(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t1pgPolicyDirWithRepoPushDefault(t, nil)),
	)
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef13-confidential", "CONFIDENTIAL", t1pgConfidentialCorpusFiles(t))

	env.Gateway().SetDefault(harness.GatewayProgram{
		DynamicFn: func(req harness.RecordedGatewayRequest) (int, []byte) {
			aType, _ := req.ParsedBody["assessment_type"].(string)
			if aType == "" {
				aType = "IP_PROVENANCE"
			}
			b, _ := json.Marshal(harness.StageBAssessmentPayload{
				SchemaVersion:  "1",
				AssessmentType: aType,
				Risk:           "MEDIUM",
				Disposition:    "REVIEW",
				Confidence:     0.9,
				Summary:        "Confidential IP review required",
				Findings:       []harness.StageBFinding{},
				Limitations:    []string{},
			})
			return http.StatusOK, b
		},
	})

	confSrc := t1pgReadQuarantineFixture(t, "corpora", "confidential", "internal_billing_rules.go")
	workDir, tipSHA, res1 := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "feat/approved", map[string]string{
		"billing/rules.go": confSrc,
	}, "feat: confidential billing rules")
	if res1.ExitCode == 0 {
		t.Fatalf("expected initial confidential push to require approval")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	initialPush := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)[0]
	if initialPush.PolicyEffect != "REQUIRE_APPROVAL" || !t1pgIsHex64(initialPush.PushManifestDigest) {
		t.Fatalf("expected REQUIRE_APPROVAL with 64-hex digest, got %+v", initialPush)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, appRaw, err := actors.SecAdminCli.ApprovePush(ctx, initialPush.ID, harness.ApprovePushReq{
		Decision:           "APPROVE",
		PushManifestDigest: initialPush.PushManifestDigest,
		Destination:        initialPush.Destination,
		TTLSeconds:         300,
		Comment:            "approved confidential billing reuse",
	})
	if err != nil {
		t.Fatalf("ApprovePush(%s): %v", initialPush.ID, err)
	}
	appRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)
	harness.AssertUUIDv7(t, rel.ID)

	// Re-push exact same commit -> released once and forwarded upstream.
	res2 := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/feat/approved", env.GitGatewayCACertPath())
	if res2.ExitCode != 0 {
		t.Fatalf("approved re-push failed (exit %d):\nstdout:\n%s\nstderr:\n%s", res2.ExitCode, res2.Stdout, res2.Stderr)
	}
	gotHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/feat/approved")
	if err != nil || gotHead != tipSHA {
		t.Fatalf("upstream feat/approved = %q (err=%v), want %q", gotHead, err, tipSHA)
	}
	releasedPush := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)[0]
	if !releasedPush.UpstreamForwarded || releasedPush.ApprovalReleaseID != rel.ID {
		t.Fatalf("expected upstream_forwarded=true and approval_release_id=%s, got %+v", rel.ID, releasedPush)
	}

	// Reset upstream refs/heads/feat/approved so replay carries the exact same push_manifest_digest
	// without a new approval -> blocked (single-use release consumed).
	if r := pgRunHardenedGit(repo.BarePath, nil, "update-ref", "-d", "refs/heads/feat/approved"); r.ExitCode != 0 {
		t.Fatalf("delete upstream refs/heads/feat/approved before replay: %s", r.Stderr)
	}
	env.GitHub().ResetPacketCounters()
	res3 := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/feat/approved", env.GitGatewayCACertPath())
	if res3.ExitCode == 0 {
		t.Fatalf("expected replay after single-use approval consumption to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	replayPush := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 3, 20*time.Second)[0]
	if replayPush.Status != "APPROVAL_REQUIRED" || replayPush.PolicyEffect != "REQUIRE_APPROVAL" || replayPush.UpstreamForwarded {
		t.Fatalf("expected replay to be blocked with APPROVAL_REQUIRED / REQUIRE_APPROVAL and 0 upstream forwarding, got %+v", replayPush)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.SecAdminTok)
}

func TestT1_PG_EF13_ApprovalReleaseBindingFieldsPersistedAndVerified(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef13-binding-conf", "CONFIDENTIAL", t1pgConfidentialCorpusFiles(t))

	confSrc := t1pgReadQuarantineFixture(t, "corpora", "confidential", "internal_billing_rules.go")
	workDir, _, res1 := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"billing/ledger.go": confSrc,
	}, "feat: confidential ledger rules")
	if res1.ExitCode == 0 {
		t.Fatalf("expected initial confidential push to require approval")
	}

	initialPush := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)[0]
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, appRaw, err := actors.SecAdminCli.ApprovePush(ctx, initialPush.ID, harness.ApprovePushReq{
		Decision:           "APPROVE",
		PushManifestDigest: initialPush.PushManifestDigest,
		Destination:        initialPush.Destination,
		TTLSeconds:         300,
	})
	if err != nil {
		t.Fatalf("ApprovePush: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)

	res2 := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res2.ExitCode != 0 {
		t.Fatalf("approved re-push failed (exit %d): %s", res2.ExitCode, res2.Stderr)
	}
	secondPush := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)[0]

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT principal_id::text, approved_by::text, destination, push_manifest_digest,
		        consumed_at IS NOT NULL, COALESCE(consumed_by_push_session_id::text,''), expires_at > created_at
		 FROM push_approval_releases WHERE id = %s::uuid`,
		t1pgSQLQuote(rel.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query push_approval_releases %s: rows=%v err=%v", rel.ID, rows, err)
	}
	r := rows[0]
	if r[0] != initialPush.PrincipalID {
		t.Fatalf("release principal_id = %q, want %q", r[0], initialPush.PrincipalID)
	}
	if r[1] == r[0] {
		t.Fatalf("separation of duties violated: approved_by == principal_id (%s)", r[1])
	}
	if r[2] != initialPush.Destination {
		t.Fatalf("release destination = %q, want %q", r[2], initialPush.Destination)
	}
	if r[3] != initialPush.PushManifestDigest || !t1pgIsHex64(r[3]) {
		t.Fatalf("release push_manifest_digest = %q, want %q", r[3], initialPush.PushManifestDigest)
	}
	if r[4] != "t" && r[4] != "true" {
		t.Fatalf("expected consumed_at IS NOT NULL after re-push, got %q", r[4])
	}
	if r[5] != secondPush.ID {
		t.Fatalf("consumed_by_push_session_id = %q, want %q", r[5], secondPush.ID)
	}
	if r[6] != "t" && r[6] != "true" {
		t.Fatalf("expected expires_at > created_at, got %q", r[6])
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.SecAdminTok)
}

// --- EF14: Control-Plane API, CLI push status, Metrics & Zero-Secret Logs (5 tests) ---

func TestT1_PG_EF14_ListPushesFilteringAndPagination(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, resA := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"clean_a.go": cleanSrc,
	}, "feat: clean push by Alice")
	if resA.ExitCode != 0 {
		t.Fatalf("clean push failed: %s", resA.Stderr)
	}

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		FilePath:    "bad.env",
	})
	_, _, resB := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanBTok, "main", map[string]string{
		"bad.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
	}, "chore: blocked push by Bob")
	if resB.ExitCode == 0 {
		t.Fatalf("expected Bob's secret push to be blocked")
	}

	allPushes := t1pgWaitPushCount(t, env, actors.SecAdminCli, repoID, 2, 20*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	blockedList, bRaw, err := actors.SecAdminCli.ListPushes(ctx, harness.PushFilter{
		RepositoryID: repoID,
		Status:       "BLOCKED",
		Limit:        10,
	})
	if err != nil {
		t.Fatalf("ListPushes(Status=BLOCKED): %v", err)
	}
	bRaw.RequireStatus(t, http.StatusOK)
	if len(blockedList.Pushes) != 1 {
		t.Fatalf("expected 1 BLOCKED push, got %d (%+v)", len(blockedList.Pushes), blockedList.Pushes)
	}
	blockedPush := blockedList.Pushes[0]

	byPrincipal, pRaw, err := actors.SecAdminCli.ListPushes(ctx, harness.PushFilter{
		PrincipalID: blockedPush.PrincipalID,
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("ListPushes(PrincipalID): %v", err)
	}
	pRaw.RequireStatus(t, http.StatusOK)
	if len(byPrincipal.Pushes) != 1 || byPrincipal.Pushes[0].ID != blockedPush.ID {
		t.Fatalf("expected Bob's single push %s, got %+v", blockedPush.ID, byPrincipal.Pushes)
	}

	// Pagination with Limit=1.
	page1, p1Raw, err := actors.SecAdminCli.ListPushes(ctx, harness.PushFilter{
		RepositoryID: repoID,
		Limit:        1,
	})
	if err != nil {
		t.Fatalf("ListPushes(page 1): %v", err)
	}
	p1Raw.RequireStatus(t, http.StatusOK)
	if len(page1.Pushes) != 1 || !page1.HasMore || page1.NextCursor == "" {
		t.Fatalf("expected HasMore=true and NextCursor on page 1, got %+v", page1)
	}
	page2, p2Raw, err := actors.SecAdminCli.ListPushes(ctx, harness.PushFilter{
		RepositoryID: repoID,
		Limit:        1,
		Cursor:       page1.NextCursor,
	})
	if err != nil {
		t.Fatalf("ListPushes(page 2): %v", err)
	}
	p2Raw.RequireStatus(t, http.StatusOK)
	if len(page2.Pushes) != 1 || page2.Pushes[0].ID == page1.Pushes[0].ID {
		t.Fatalf("expected disjoint push on page 2 (page1=%s, page2=%+v, total=%d)",
			page1.Pushes[0].ID, page2.Pushes, len(allPushes))
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.HumanBTok, "AKIAIOSFODNN7EXAMPLE")
}

func TestT1_PG_EF14_GetPushDetailAndPersistedFindings(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	const secretVal = "AKIAIOSFODNN7EXAMPLE"
	env.RegisterSecret(secretVal)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: secretVal,
		FilePath:    "config/secret.env",
	})

	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"config/secret.env": "AWS_ACCESS_KEY_ID=" + secretVal + "\n",
	}, "chore: commit secret for detail inspection")
	if res.ExitCode == 0 {
		t.Fatalf("expected secret push to be blocked")
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)
	harness.AssertUUIDv7(t, push.ID)
	harness.AssertUUIDv7(t, push.RepositoryID)
	harness.AssertUUIDv7(t, push.PrincipalID)
	harness.AssertUUIDv7(t, push.PolicyDecisionID)
	harness.AssertUUIDv7(t, push.BundleArtifactID)
	if !t1pgIsHex64(push.PushManifestDigest) {
		t.Fatalf("expected 64-hex PushManifestDigest, got %q", push.PushManifestDigest)
	}
	if push.EgressMode != "ENFORCE_BLOCK" || push.PolicyEffect != "DENY" || push.UpstreamForwarded {
		t.Fatalf("unexpected push detail fields: %+v", push)
	}
	if len(push.RefUpdates) == 0 {
		t.Fatalf("expected non-empty ref_updates in GetPush detail")
	}

	fRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT f.category, f.redacted, COALESCE((sr.coverage->>'files_skipped')::int, -1)
		 FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id
		 WHERE sr.push_session_id = %s::uuid`,
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(fRows) == 0 {
		t.Fatalf("expected persisted findings linked via scan_runs, rows=%v err=%v", fRows, err)
	}
	foundRedactedSecret := false
	for _, r := range fRows {
		if r[0] == "SECRET" && (r[1] == "t" || r[1] == "true") && r[2] == "0" {
			foundRedactedSecret = true
			break
		}
	}
	if !foundRedactedSecret {
		t.Fatalf("expected redacted SECRET finding with 0 files_skipped, got %+v", fRows)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, secretVal)
}

func TestT1_PG_EF14_CustodianPushStatusCLIJSONAndExitCodes(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, res := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"cli_status.go": cleanSrc,
	}, "feat: push for custodian push status CLI")
	if res.ExitCode != 0 {
		t.Fatalf("clean push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgFindLatestPushForRepo(t, env, actors.HumanACli, repoID)

	cliRes, got := t1pgRunPushStatusCLI(t, env, actors.HumanATok, push.ID)
	if cliRes.ExitCode != 0 {
		t.Fatalf("custodian push status %s failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			push.ID, cliRes.ExitCode, cliRes.Stdout, cliRes.Stderr)
	}
	if got.ID != push.ID || got.Status != push.Status || got.PolicyEffect != "ALLOW" || !got.UpstreamForwarded {
		t.Fatalf("CLI push status mismatch: got=%+v want=%+v", got, push)
	}
	if got.PushManifestDigest != push.PushManifestDigest {
		t.Fatalf("CLI digest %q != API digest %q", got.PushManifestDigest, push.PushManifestDigest)
	}

	unknownRes, _ := t1pgRunPushStatusCLI(t, env, actors.HumanATok, harness.NewTestUUIDv7())
	if unknownRes.ExitCode == 0 || strings.Contains(unknownRes.Stderr, "panic:") {
		t.Fatalf("expected non-zero clean error for unknown push ID, got exit=%d stderr=%q", unknownRes.ExitCode, unknownRes.Stderr)
	}

	unauthRes, _ := t1pgRunPushStatusCLI(t, env, "", push.ID)
	if unauthRes.ExitCode == 0 || strings.Contains(unauthRes.Stderr, "panic:") {
		t.Fatalf("expected non-zero clean error without token, got exit=%d stderr=%q", unauthRes.ExitCode, unauthRes.Stderr)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF14_PrometheusPushGatewayMetricsIncremented(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, r1 := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"m1.go": cleanSrc,
	}, "feat: metrics allow push")
	if r1.ExitCode != 0 {
		t.Fatalf("allow push failed: %s", r1.Stderr)
	}

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		FilePath:    "m2.env",
	})
	_, _, r2 := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"m2.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
	}, "chore: metrics deny push")
	if r2.ExitCode == 0 {
		t.Fatalf("expected secret push to fail")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, mRaw, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "INLINE_WARN",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode(PASSIVE_AUDIT): %v", err)
	}
	mRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)

	_, _, r3 := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"m3.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
	}, "chore: metrics passive audit would-block push")
	if r3.ExitCode != 0 {
		t.Fatalf("expected passive audit push to succeed, got %s", r3.Stderr)
	}

	gwMetrics := t1pgScrapeGatewayMetrics(t, env)
	if !strings.Contains(gwMetrics, "# TYPE") || !strings.Contains(gwMetrics, "# HELP") {
		t.Fatalf("expected Prometheus # TYPE / # HELP headers in gateway /metrics")
	}

	for _, name := range []string{
		"custodian_push_sessions_total",
		"custodian_push_gateway_duration_seconds_count",
		"custodian_push_upstream_bytes_total",
		"custodian_push_passive_audit_would_block_total",
		"custodian_policy_decisions_total",
	} {
		sum, ok := t1pgExtractMetricSum(gwMetrics, name)
		if !ok || sum <= 0 {
			apiMetrics, apiRaw, apiErr := env.Client("").GetMetrics(ctx)
			if apiErr == nil && apiRaw != nil && apiRaw.StatusCode == http.StatusOK {
				if apiSum, apiOK := t1pgExtractMetricSum(apiMetrics, name); apiOK && apiSum > 0 {
					continue
				}
			}
			t.Fatalf("expected metric %q > 0 in gateway (or API) /metrics (found=%v sum=%v)", name, ok, sum)
		}
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, "AKIAIOSFODNN7EXAMPLE")
}

func TestT1_PG_EF14_ZeroSecretLogsAcrossAllServicesIncludingExtraSecretsAndSSHKeys(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	const canarySecret = "CANARY_PG_SECRET_TOKEN_XYZ987"
	env.RegisterSecret(canarySecret)
	env.RegisterSecret(actors.HumanATok)
	env.RegisterSecret(actors.SecAdminTok)

	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_, _, resHTTP := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"zero_http.go": cleanSrc,
	}, "feat: zero-secret HTTPS push")
	if resHTTP.ExitCode != 0 {
		t.Fatalf("HTTPS push failed: %s", resHTTP.Stderr)
	}

	cred := env.SSHCA().MintValidCert("alice-zero-secret-ssh", []string{"alice@example.com"})
	sshDir, cloneRes := pgGitCloneSSH(t, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("SSH clone failed: %s", cloneRes.Stderr)
	}
	_ = pgRunHardenedGit(sshDir, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(sshDir, nil, "config", "user.email", "alice@example.com")
	_ = pgAddCommit(t, sshDir, map[string]string{"zero_ssh.go": cleanSrc}, nil, "feat: zero-secret SSH push", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if resSSH := pgGitPushSSH(t, sshDir, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA()); resSSH.ExitCode != 0 {
		t.Fatalf("SSH push failed: %s", resSSH.Stderr)
	}

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: canarySecret,
		FilePath:    "canary.env",
	})
	_, _, resCanary := t1pgSeededHTTPSPush(t, env, repo.FullName, actors.HumanATok, "main", map[string]string{
		"canary.env": "SECRET=" + canarySecret + "\n",
	}, "chore: canary secret push")
	if resCanary.ExitCode == 0 {
		t.Fatalf("expected canary secret push to be blocked")
	}

	_ = t1pgFindLatestPushForRepo(t, env, actors.SecAdminCli, repoID)

	for _, comp := range []string{"git-gateway", "api", "worker"} {
		logs := env.Logs(comp)
		if strings.Contains(logs, "panic:") {
			t.Fatalf("%s logs contained panic:\n%s", comp, logs)
		}
		if strings.TrimSpace(logs) != "" {
			for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if strings.HasPrefix(line, "{") {
					var obj map[string]any
					if err := json.Unmarshal([]byte(line), &obj); err != nil {
						t.Fatalf("%s emitted malformed JSON log line %q: %v", comp, line, err)
					}
				}
			}
		}
	}

	env.AssertNoSecretLeakInLogs(canarySecret, actors.AliceWritePAT, actors.HumanATok, actors.SecAdminTok)
}
