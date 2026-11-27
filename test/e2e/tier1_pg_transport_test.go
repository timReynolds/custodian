package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func t1pgGatewayRepoURL(env *harness.Env, fullName string) string {
	return strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + fullName + ".git"
}

func t1pgGatewaySSHRepoURL(env *harness.Env, fullName string) string {
	return "ssh://git@" + env.GitGatewaySSHAddr() + "/" + fullName + ".git"
}

func t1pgReadTransportFixture(t testing.TB, rel string) string {
	t.Helper()
	p := filepath.Join(pgFindRepoRoot(t), "test", "e2e", "fixtures", "push_gateway", rel)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read push_gateway fixture %q: %v", p, err)
	}
	return string(data)
}

func t1pgAuditorClient(env *harness.Env) *harness.APIClient {
	tok := env.MintToken(harness.TokenClaims{
		Kind:    "AUDITOR",
		Subject: "t1pg-auditor-001",
		Email:   "t1pg-auditor@example.com",
		Groups:  []string{"audit-readers"},
	})
	return env.Client(tok)
}

func t1pgEnsurePrincipalSeeded(t testing.TB, env *harness.Env, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _ = env.Client(token).GetWorkspace(ctx, harness.NewTestUUIDv7())
}

func t1pgIsTerminalPushStatus(env *harness.Env, status string) bool {
	norm := strings.ToUpper(strings.TrimSpace(status))
	if norm == "" || norm == "ALLOWED" || norm == "FORWARDED" {
		return false
	}
	switch norm {
	case "COMPLETED", "BLOCKED", "DENIED", "QUARANTINED", "APPROVAL_REQUIRED", "OBSERVED_WOULD_BLOCK", "FAILED":
		return true
	}
	st := env.Contracts().PushStatuses
	return harness.ContainsStatus(st.TerminalSuccess, status) || harness.ContainsStatus(st.TerminalFailure, status)
}

func t1pgLatestPushForRepo(t testing.TB, env *harness.Env, cli *harness.APIClient, repoID string) harness.PushSessionResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	deadline := time.Now().Add(15 * time.Second)
	var latestID string
	for time.Now().Before(deadline) {
		listResp, raw, err := cli.ListPushes(ctx, harness.PushFilter{
			RepositoryID: repoID,
			Limit:        20,
		})
		if err != nil {
			t.Fatalf("ListPushes(repo=%s): %v", repoID, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		if len(listResp.Pushes) > 0 {
			latestID = listResp.Pushes[0].ID
			if t1pgIsTerminalPushStatus(env, listResp.Pushes[0].Status) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if latestID == "" {
		t.Fatalf("no push sessions recorded for repository %s", repoID)
	}
	harness.AssertUUIDv7(t, latestID)

	detail, gRaw, err := cli.GetPush(ctx, latestID)
	if err != nil {
		t.Fatalf("GetPush(%s): %v", latestID, err)
	}
	gRaw.RequireStatus(t, http.StatusOK)
	return detail
}

// t1pgPolicyYAMLToCanonicalJSON converts Custodian PolicyBundle YAML into canonical JSON
// matching internal/policy.CanonicalBundleJSON + internal/domain.CanonicalJSONBytes using Go stdlib only.
func t1pgPolicyYAMLToCanonicalJSON(yamlText string) ([]byte, string, string, string, error) {
	type t1pgRuleObl struct {
		Type          string `json:"type,omitempty"`
		ReviewerGroup string `json:"reviewer_group"`
		Minimum       *int   `json:"minimum,omitempty"`
	}
	type t1pgRuleDef struct {
		ID          string        `json:"id"`
		Description string        `json:"description,omitempty"`
		Stages      []string      `json:"stages"`
		When        string        `json:"when"`
		Effect      string        `json:"effect"`
		Overridable *bool         `json:"overridable,omitempty"`
		Message     string        `json:"message,omitempty"`
		Obligations []t1pgRuleObl `json:"obligations,omitempty"`
	}
	type t1pgDecisionModelDef struct {
		Route   string   `json:"route,omitempty"`
		Trigger []string `json:"trigger,omitempty"`
	}
	type t1pgInspectionDef struct {
		Mandatory     []string              `json:"mandatory,omitempty"`
		DecisionModel *t1pgDecisionModelDef `json:"decisionModel,omitempty"`
	}
	type t1pgBundleDef struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Scope   string `json:"scope,omitempty"`
		} `json:"metadata"`
		Defaults struct {
			Effect  string `json:"effect"`
			OnError string `json:"onError"`
		} `json:"defaults"`
		Inspection *t1pgInspectionDef `json:"inspection,omitempty"`
		Rules      []t1pgRuleDef      `json:"rules"`
	}

	unquote := func(s string) string {
		s = strings.TrimSpace(s)
		if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
			return s[1 : len(s)-1]
		}
		return s
	}
	parseInlineList := func(s string) []string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
		if strings.TrimSpace(s) == "" {
			return nil
		}
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if v := unquote(p); v != "" {
				out = append(out, v)
			}
		}
		return out
	}

	b := t1pgBundleDef{Rules: make([]t1pgRuleDef, 0)}
	ensureInspection := func() *t1pgInspectionDef {
		if b.Inspection == nil {
			b.Inspection = &t1pgInspectionDef{}
		}
		return b.Inspection
	}
	ensureDecisionModel := func() *t1pgDecisionModelDef {
		ins := ensureInspection()
		if ins.DecisionModel == nil {
			ins.DecisionModel = &t1pgDecisionModelDef{}
		}
		return ins.DecisionModel
	}

	lines := strings.Split(yamlText, "\n")
	section := ""
	subSection := ""
	ruleListIndent := -1
	stagesKeyIndent := -1
	oblKeyIndent := -1
	oblListIndent := -1
	var curRule *t1pgRuleDef
	var curObl *t1pgRuleObl
	inWhenFold := false
	whenIndent := 0
	var whenBuf []string

	flushWhen := func() {
		if inWhenFold && curRule != nil {
			curRule.When = strings.TrimSpace(strings.Join(whenBuf, " "))
		}
		inWhenFold = false
		whenBuf = nil
	}
	flushObl := func() {
		if curObl != nil && curRule != nil {
			if strings.TrimSpace(curObl.Type) == "" {
				curObl.Type = "HUMAN_REVIEW"
			}
			if curObl.Minimum == nil {
				minVal := 1
				curObl.Minimum = &minVal
			}
			curRule.Obligations = append(curRule.Obligations, *curObl)
			curObl = nil
		}
	}
	flushRule := func() {
		flushWhen()
		flushObl()
		if curRule != nil {
			b.Rules = append(b.Rules, *curRule)
			curRule = nil
		}
		subSection = ""
		stagesKeyIndent = -1
		oblKeyIndent = -1
		oblListIndent = -1
	}

	applyOblKV := func(obl *t1pgRuleObl, k, v string) {
		switch strings.TrimSpace(k) {
		case "type":
			obl.Type = unquote(v)
		case "reviewer_group":
			obl.ReviewerGroup = unquote(v)
		case "minimum":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				obl.Minimum = &n
			}
		}
	}

	applyRuleKV := func(k, v string, indent int) {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "id":
			curRule.ID = unquote(v)
		case "description":
			curRule.Description = unquote(v)
		case "message":
			curRule.Message = unquote(v)
		case "stages":
			if strings.HasPrefix(v, "[") {
				curRule.Stages = parseInlineList(v)
				subSection = ""
			} else if v == "" {
				subSection = "stages"
				stagesKeyIndent = indent
			} else {
				curRule.Stages = []string{unquote(v)}
			}
		case "when":
			if v == ">-" || v == ">" || v == "|" || v == "|-" {
				inWhenFold = true
				whenIndent = indent
				whenBuf = nil
			} else {
				curRule.When = unquote(v)
			}
		case "effect":
			curRule.Effect = unquote(v)
		case "overridable":
			val := strings.EqualFold(unquote(v), "true")
			curRule.Overridable = &val
		case "obligations":
			subSection = "obligations"
			oblKeyIndent = indent
			oblListIndent = -1
		}
	}

	for _, rawLine := range lines {
		if strings.TrimSpace(rawLine) == "" || strings.HasPrefix(strings.TrimSpace(rawLine), "#") {
			continue
		}
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " "))
		trimmed := strings.TrimSpace(rawLine)

		if inWhenFold {
			if indent > whenIndent {
				whenBuf = append(whenBuf, trimmed)
				continue
			}
			flushWhen()
		}

		if indent == 0 {
			flushRule()
			subSection = ""
			k, v, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "apiVersion":
				b.APIVersion = unquote(v)
				section = ""
			case "kind":
				b.Kind = unquote(v)
				section = ""
			case "metadata", "defaults", "rules":
				section = k
			case "inspection":
				section = k
				ensureInspection()
			}
			continue
		}

		switch section {
		case "metadata":
			k, v, _ := strings.Cut(trimmed, ":")
			switch strings.TrimSpace(k) {
			case "name":
				b.Metadata.Name = unquote(v)
			case "version":
				b.Metadata.Version = unquote(v)
			case "scope":
				b.Metadata.Scope = unquote(v)
			}
		case "defaults":
			k, v, _ := strings.Cut(trimmed, ":")
			switch strings.TrimSpace(k) {
			case "effect":
				b.Defaults.Effect = unquote(v)
			case "onError":
				b.Defaults.OnError = unquote(v)
			}
		case "inspection":
			if strings.HasPrefix(trimmed, "- ") {
				item := unquote(strings.TrimPrefix(trimmed, "- "))
				if subSection == "mandatory" {
					ins := ensureInspection()
					ins.Mandatory = append(ins.Mandatory, item)
				} else if subSection == "trigger" {
					dm := ensureDecisionModel()
					dm.Trigger = append(dm.Trigger, item)
				}
				continue
			}
			k, v, _ := strings.Cut(trimmed, ":")
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			switch k {
			case "mandatory":
				subSection = "mandatory"
				ins := ensureInspection()
				if strings.HasPrefix(v, "[") {
					ins.Mandatory = append(ins.Mandatory, parseInlineList(v)...)
				}
			case "decisionModel":
				subSection = "decisionModel"
				ensureDecisionModel()
			case "route":
				dm := ensureDecisionModel()
				dm.Route = unquote(v)
			case "trigger":
				subSection = "trigger"
				dm := ensureDecisionModel()
				if strings.HasPrefix(v, "[") {
					dm.Trigger = append(dm.Trigger, parseInlineList(v)...)
				}
			}
		case "rules":
			if strings.HasPrefix(trimmed, "- ") && (ruleListIndent == -1 || indent == ruleListIndent) {
				flushRule()
				if ruleListIndent == -1 {
					ruleListIndent = indent
				}
				curRule = &t1pgRuleDef{}
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				if k, v, ok := strings.Cut(rest, ":"); ok {
					applyRuleKV(k, v, indent)
				}
				continue
			}
			if curRule == nil {
				continue
			}
			if subSection == "stages" {
				if strings.HasPrefix(trimmed, "- ") && (indent > stagesKeyIndent || indent == stagesKeyIndent) {
					curRule.Stages = append(curRule.Stages, unquote(strings.TrimPrefix(trimmed, "- ")))
					continue
				}
				if indent <= stagesKeyIndent {
					subSection = ""
				}
			}
			if subSection == "obligations" {
				if strings.HasPrefix(trimmed, "- ") && (indent > oblKeyIndent || indent == oblKeyIndent) {
					flushObl()
					if oblListIndent == -1 {
						oblListIndent = indent
					}
					curObl = &t1pgRuleObl{Type: "HUMAN_REVIEW"}
					rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
					if k, v, ok := strings.Cut(rest, ":"); ok {
						applyOblKV(curObl, k, v)
					}
					continue
				}
				if curObl != nil && indent > oblListIndent {
					if k, v, ok := strings.Cut(trimmed, ":"); ok {
						applyOblKV(curObl, k, v)
						continue
					}
				}
				flushObl()
				subSection = ""
			}
			k, v, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			applyRuleKV(k, v, indent)
		}
	}
	flushRule()

	if strings.TrimSpace(b.Defaults.Effect) == "" {
		b.Defaults.Effect = "DENY"
	}
	if strings.TrimSpace(b.Defaults.OnError) == "" {
		b.Defaults.OnError = "DENY"
	}

	var rawBuf bytes.Buffer
	rawEnc := json.NewEncoder(&rawBuf)
	rawEnc.SetEscapeHTML(false)
	if err := rawEnc.Encode(b); err != nil {
		return nil, "", "", "", err
	}

	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSuffix(rawBuf.Bytes(), []byte("\n"))))
	dec.UseNumber()
	var normalized any
	if err := dec.Decode(&normalized); err != nil {
		return nil, "", "", "", err
	}

	var canonBuf bytes.Buffer
	canonEnc := json.NewEncoder(&canonBuf)
	canonEnc.SetEscapeHTML(false)
	if err := canonEnc.Encode(normalized); err != nil {
		return nil, "", "", "", err
	}
	canon := bytes.TrimSuffix(canonBuf.Bytes(), []byte("\n"))
	return canon, harness.SHA256Hex(canon), b.Metadata.Name, b.Metadata.Version, nil
}

// t1pgSeedRepoPolicyBundleDB inserts and activates a scope=REPO PolicyBundle bound to repository_id
// in PostgreSQL policy_bundles (because seedPolicyDir and workflow.SyncPolicyDir skip REPO bundles on disk).
func t1pgSeedRepoPolicyBundleDB(t testing.TB, env *harness.Env, repoID, yamlBody string) string {
	t.Helper()
	if strings.TrimSpace(repoID) == "" {
		t.Fatalf("t1pgSeedRepoPolicyBundleDB requires non-empty repoID")
	}
	defJSON, digest, name, version, err := t1pgPolicyYAMLToCanonicalJSON(yamlBody)
	if err != nil {
		t.Fatalf("t1pgPolicyYAMLToCanonicalJSON: %v", err)
	}
	if strings.TrimSpace(name) == "" {
		name = "e2e-repo-bundle"
	}
	if strings.TrimSpace(version) == "" {
		version = "1.0.0"
	}
	id := harness.NewTestUUIDv7()
	q := fmt.Sprintf(`
INSERT INTO policy_bundles (
	id, name, version, scope, repository_id, digest, definition, activated_at
) VALUES (
	%s::uuid, %s, %s, 'REPO', %s::uuid, %s, %s::jsonb, NOW()
)
ON CONFLICT (digest) DO UPDATE SET
	name = EXCLUDED.name,
	version = EXCLUDED.version,
	scope = 'REPO',
	repository_id = EXCLUDED.repository_id,
	definition = EXCLUDED.definition,
	activated_at = NOW()
RETURNING id::text;`,
		t1pgSQLQuote(id),
		t1pgSQLQuote(name),
		t1pgSQLQuote(version),
		t1pgSQLQuote(repoID),
		t1pgSQLQuote(digest),
		t1pgSQLQuote(string(defJSON)),
	)
	rows, err := env.DB().QueryRows(q)
	if err != nil {
		t.Fatalf("t1pgSeedRepoPolicyBundleDB(%s, %s): %v", name, repoID, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		t.Fatalf("t1pgSeedRepoPolicyBundleDB returned no id")
	}
	return rows[0][0]
}

func t1pgCloneAndCommitHTTP(
	t testing.TB,
	env *harness.Env,
	repo harness.SeededRepo,
	token string,
	files map[string]string,
	msg string,
	author harness.GitIdentity,
) (string, string) {
	t.Helper()
	workDir, res := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), token, env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP(%s) failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			repo.FullName, res.ExitCode, res.Stdout, res.Stderr)
	}
	if author.Name == "" {
		author.Name = "Alice Developer"
	}
	if author.Email == "" {
		author.Email = "alice@example.com"
	}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name)
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email)
	tipSHA := pgAddCommit(t, workDir, files, nil, msg, author)
	return workDir, tipSHA
}

func t1pgCloneAndCommitSSH(
	t testing.TB,
	env *harness.Env,
	repo harness.SeededRepo,
	cred harness.SSHUserCredential,
	files map[string]string,
	msg string,
	author harness.GitIdentity,
) (string, string) {
	t.Helper()
	workDir, res := pgGitCloneSSH(t, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if res.ExitCode != 0 {
		t.Fatalf("pgGitCloneSSH(%s) failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			repo.FullName, res.ExitCode, res.Stdout, res.Stderr)
	}
	if author.Name == "" {
		author.Name = "Alice Developer"
	}
	if author.Email == "" {
		author.Email = "alice@example.com"
	}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name)
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email)
	tipSHA := pgAddCommit(t, workDir, files, nil, msg, author)
	return workDir, tipSHA
}

// t1pgRunGitWithLFSHooks runs git with isolated global/system config while allowing local
// .git/hooks (such as git-lfs pre-push) to execute.
func t1pgRunGitWithLFSHooks(dir string, extraEnv map[string]string, args ...string) pgGitResult {
	fullArgs := append([]string{"-c", "core.symlinks=false"}, args...)
	cmd := exec.Command("git", fullArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	envMap := map[string]string{
		"PATH":                os.Getenv("PATH"),
		"HOME":                os.Getenv("HOME"),
		"TMPDIR":              os.Getenv("TMPDIR"),
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_TERMINAL_PROMPT": "0",
	}
	for k, v := range extraEnv {
		envMap[k] = v
	}
	cmdEnv := make([]string, 0, len(envMap))
	for k, v := range envMap {
		cmdEnv = append(cmdEnv, k+"="+v)
	}
	cmd.Env = cmdEnv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return pgGitResult{
		ExitCode: code,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
}

func t1pgInitAndCommitLFSFile(
	t testing.TB,
	workDir string,
	pattern string,
	relPath string,
	data []byte,
	msg string,
	caCertPath string,
) string {
	t.Helper()
	lfsEnv := map[string]string{}
	if caCertPath != "" {
		lfsEnv["GIT_SSL_CAINFO"] = caCertPath
	}
	if res := t1pgRunGitWithLFSHooks(workDir, lfsEnv, "lfs", "install", "--local"); res.ExitCode != 0 {
		t.Fatalf("git lfs install --local failed (exit %d): %s\n%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	if res := t1pgRunGitWithLFSHooks(workDir, lfsEnv, "lfs", "track", pattern); res.ExitCode != 0 {
		t.Fatalf("git lfs track %q failed (exit %d): %s\n%s", pattern, res.ExitCode, res.Stdout, res.Stderr)
	}
	target := filepath.Join(workDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir LFS file dir %q: %v", relPath, err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatalf("write LFS file %q: %v", relPath, err)
	}
	if res := t1pgRunGitWithLFSHooks(workDir, lfsEnv, "add", ".gitattributes", relPath); res.ExitCode != 0 {
		t.Fatalf("git add LFS files failed (exit %d): %s\n%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	authorEnv := map[string]string{
		"GIT_AUTHOR_NAME":     "Alice Developer",
		"GIT_AUTHOR_EMAIL":    "alice@example.com",
		"GIT_COMMITTER_NAME":  "Alice Developer",
		"GIT_COMMITTER_EMAIL": "alice@example.com",
	}
	for k, v := range lfsEnv {
		authorEnv[k] = v
	}
	if res := t1pgRunGitWithLFSHooks(workDir, authorEnv, "commit", "-m", msg); res.ExitCode != 0 {
		t.Fatalf("git commit LFS file failed (exit %d): %s\n%s", res.ExitCode, res.Stdout, res.Stderr)
	}
	shaRes := pgRunHardenedGit(workDir, nil, "rev-parse", "HEAD")
	if shaRes.ExitCode != 0 {
		t.Fatalf("git rev-parse HEAD failed: %s", shaRes.Stderr)
	}
	return strings.TrimSpace(shaRes.Stdout)
}

func t1pgGitPushHTTPSWithLFS(t testing.TB, repoDir, gatewayRepoURL, token, refspec, caCertPath string) pgGitResult {
	t.Helper()
	pushURL, err := pgInjectHTTPAuth(gatewayRepoURL, token)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth(%q): %v", gatewayRepoURL, err)
	}
	if refspec == "" {
		refspec = "HEAD:refs/heads/main"
	}
	extraEnv := map[string]string{}
	if caCertPath != "" {
		extraEnv["GIT_SSL_CAINFO"] = caCertPath
	}
	return t1pgRunGitWithLFSHooks(repoDir, extraEnv, "push", pushURL, refspec)
}

// --- EF1: HTTPS Smart-HTTP Gateway & Read Proxy (5 tests) ---

func TestT1_PG_EF1_HTTPSCloneUploadPackReadProxy(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	env.GitHub().ResetPacketCounters()

	workDir, res := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("HTTPS git clone through gateway failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	headRes := pgRunHardenedGit(workDir, nil, "rev-parse", "HEAD")
	if headRes.ExitCode != 0 {
		t.Fatalf("git rev-parse HEAD: %s", headRes.Stderr)
	}
	if got := strings.TrimSpace(headRes.Stdout); got != repo.HeadSHA {
		t.Fatalf("cloned HEAD = %q, want %q", got, repo.HeadSHA)
	}

	readmeBytes, err := os.ReadFile(filepath.Join(workDir, "README.md"))
	if err != nil {
		t.Fatalf("read cloned README.md: %v", err)
	}
	if string(readmeBytes) != "# acme/service\n" {
		t.Fatalf("cloned README.md = %q, want %q", string(readmeBytes), "# acme/service\n")
	}

	mainBytes, err := os.ReadFile(filepath.Join(workDir, "main.go"))
	if err != nil {
		t.Fatalf("read cloned main.go: %v", err)
	}
	if string(mainBytes) != "package main\n\nfunc main() {}\n" {
		t.Fatalf("cloned main.go = %q", string(mainBytes))
	}

	foundInfoRefs := false
	for _, c := range env.GitHub().InfoRefsCalls() {
		if c.Repo == repo.FullName && c.Service == "git-upload-pack" && c.StatusCode == http.StatusOK {
			foundInfoRefs = true
			break
		}
	}
	if !foundInfoRefs {
		t.Fatalf("expected GET /info/refs?service=git-upload-pack (200) on upstream MockGitHub; got %+v", env.GitHub().InfoRefsCalls())
	}

	foundUploadPack := false
	for _, c := range env.GitHub().UploadPackCalls() {
		if c.Repo == repo.FullName && c.StatusCode == http.StatusOK {
			foundUploadPack = true
			break
		}
	}
	if !foundUploadPack {
		t.Fatalf("expected POST /git-upload-pack (200) proxied to upstream MockGitHub; got %+v", env.GitHub().UploadPackCalls())
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF1_HTTPSCleanPushReceivePackAllowed(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	env.GitHub().ResetPacketCounters()

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, tipSHA := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"pkg/greeting/feature.go": cleanSrc,
	}, "feat: add clean greeting helper", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("HTTPS clean push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	gotSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef(refs/heads/main): %v", err)
	}
	if gotSHA != tipSHA {
		t.Fatalf("upstream refs/heads/main = %q, want %q", gotSHA, tipSHA)
	}

	if calls := env.GitHub().ReceivePackCalls(); len(calls) == 0 {
		t.Fatalf("expected >= 1 upstream POST /git-receive-pack call on ALLOW")
	}
	if n := env.GitHub().ReceivePackBytes(repo.FullName); n <= 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0, got %d", n)
	}

	push := t1pgLatestPushForRepo(t, env, actors.HumanACli, repoID)
	harness.AssertUUIDv7(t, push.ID)
	if !push.DestinationRegistered || push.DestinationExternal {
		t.Fatalf("unexpected destination flags: registered=%v external=%v", push.DestinationRegistered, push.DestinationExternal)
	}
	if !push.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=true, got false (status=%q)", push.Status)
	}
	if len(push.PushManifestDigest) != 64 {
		t.Fatalf("expected 64-hex push_manifest_digest, got %q", push.PushManifestDigest)
	}
	if !harness.ContainsStatus(env.Contracts().PushStatuses.TerminalSuccess, push.Status) {
		t.Fatalf("expected terminal success push status, got %q", push.Status)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF1_HTTPSBranchAndTagCreationPush(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, tipSHA := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"pkg/release/feature.go": cleanSrc,
	}, "feat: prepare release v1.0.0-ef1", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	tagRes := pgRunHardenedGit(workDir, map[string]string{
		"GIT_AUTHOR_NAME":     "Alice Developer",
		"GIT_AUTHOR_EMAIL":    "alice@example.com",
		"GIT_COMMITTER_NAME":  "Alice Developer",
		"GIT_COMMITTER_EMAIL": "alice@example.com",
	}, "tag", "-a", "v1.0.0-ef1", "-m", "release ef1")
	if tagRes.ExitCode != 0 {
		t.Fatalf("git tag failed (exit %d): %s", tagRes.ExitCode, tagRes.Stderr)
	}

	pushURL, err := pgInjectHTTPAuth(t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	pushRes := pgRunHardenedGit(workDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "push", pushURL, "HEAD:refs/heads/feat/ef1-branch", "refs/tags/v1.0.0-ef1:refs/tags/v1.0.0-ef1")
	if pushRes.ExitCode != 0 {
		t.Fatalf("branch+tag HTTPS push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			pushRes.ExitCode, pushRes.Stdout, pushRes.Stderr)
	}

	exists, err := env.Git().BranchExists(repo.FullName, "feat/ef1-branch")
	if err != nil || !exists {
		t.Fatalf("expected branch feat/ef1-branch to exist upstream (exists=%v err=%v)", exists, err)
	}
	branchSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/feat/ef1-branch")
	if err != nil || branchSHA != tipSHA {
		t.Fatalf("refs/heads/feat/ef1-branch = %q (err=%v), want %q", branchSHA, err, tipSHA)
	}
	tagTargetSHA, err := env.Git().ResolveRef(repo.FullName, "refs/tags/v1.0.0-ef1^{commit}")
	if err != nil || tagTargetSHA != tipSHA {
		t.Fatalf("refs/tags/v1.0.0-ef1^{commit} = %q (err=%v), want %q", tagTargetSHA, err, tipSHA)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF1_HTTPSFastForwardMultiCommitPush(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir, res := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP failed: %s", res.Stderr)
	}
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name)
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email)

	c1 := pgAddCommit(t, workDir, map[string]string{"step1.go": "package main\nfunc step1() int { return 1 }\n"}, nil, "commit 1", author)
	c2 := pgAddCommit(t, workDir, map[string]string{"step2.go": "package main\nfunc step2() int { return 2 }\n"}, nil, "commit 2", author)
	c3 := pgAddCommit(t, workDir, map[string]string{"step3.go": "package main\nfunc step3() int { return 3 }\n"}, nil, "commit 3", author)

	pushRes := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if pushRes.ExitCode != 0 {
		t.Fatalf("multi-commit HTTPS push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			pushRes.ExitCode, pushRes.Stdout, pushRes.Stderr)
	}

	gotHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotHead != c3 {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotHead, err, c3)
	}
	info3, err := env.Git().InspectCommit(repo.FullName, c3)
	if err != nil || len(info3.Parents) != 1 || info3.Parents[0] != c2 {
		t.Fatalf("commit c3 parents = %+v (err=%v), want [%s]", info3.Parents, err, c2)
	}
	info2, err := env.Git().InspectCommit(repo.FullName, c2)
	if err != nil || len(info2.Parents) != 1 || info2.Parents[0] != c1 {
		t.Fatalf("commit c2 parents = %+v (err=%v), want [%s]", info2.Parents, err, c1)
	}
	info1, err := env.Git().InspectCommit(repo.FullName, c1)
	if err != nil || len(info1.Parents) != 1 || info1.Parents[0] != repo.HeadSHA {
		t.Fatalf("commit c1 parents = %+v (err=%v), want [%s]", info1.Parents, err, repo.HeadSHA)
	}

	tree, err := env.Git().InspectTree(repo.FullName, c3)
	if err != nil {
		t.Fatalf("InspectTree(%s): %v", c3, err)
	}
	for _, f := range []string{"step1.go", "step2.go", "step3.go"} {
		if _, ok := tree[f]; !ok {
			t.Fatalf("expected %q in upstream tree at %s", f, c3)
		}
	}

	push := t1pgLatestPushForRepo(t, env, actors.SecAdminCli, repoID)
	if !push.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=true")
	}
	if push.CommitCount != 0 && push.CommitCount != 3 {
		t.Fatalf("expected commit_count == 3, got %d", push.CommitCount)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF1_HTTPSInfoRefsCapabilitiesAndSidebandProgress(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	client := env.GitGatewayHTTPClient()
	for _, svc := range []string{"git-receive-pack", "git-upload-pack"} {
		reqURL := t1pgGatewayRepoURL(env, repo.FullName) + "/info/refs?service=" + svc
		req, err := http.NewRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s): %v", reqURL, err)
		}
		req.Header.Set("Authorization", "Bearer "+actors.HumanATok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", reqURL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d (want 200), body=%s", reqURL, resp.StatusCode, string(body))
		}
		wantCT := "application/x-" + svc + "-advertisement"
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, wantCT) {
			t.Fatalf("GET %s Content-Type = %q (want %q)", reqURL, ct, wantCT)
		}
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "# service="+svc) {
			t.Fatalf("GET %s missing service pkt-line header %q in %q", reqURL, "# service="+svc, bodyStr)
		}
		if !strings.Contains(bodyStr, repo.HeadSHA) {
			t.Fatalf("GET %s missing seeded HeadSHA %s", reqURL, repo.HeadSHA)
		}
		if svc == "git-receive-pack" {
			if !strings.Contains(bodyStr, "report-status") || !strings.Contains(bodyStr, "side-band-64k") {
				t.Fatalf("GET %s missing report-status/side-band-64k capabilities in %q", reqURL, bodyStr)
			}
		}
	}

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, _ := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"sideband_check.go": cleanSrc,
	}, "feat: test sideband progress", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	pushURL, err := pgInjectHTTPAuth(t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(workDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "push", "--progress", pushURL, "HEAD:refs/heads/main")
	if res.ExitCode != 0 {
		t.Fatalf("git push --progress failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stderr, "remote:") {
		t.Fatalf("expected sideband channel-2 'remote:' progress/verdict output in git stderr, got:\n%s", res.Stderr)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

// --- EF2: SSH User-Certificate Termination & Principal Binding (5 tests) ---

func TestT1_PG_EF2_SSHCloneWithValidUserCert(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	t1pgEnsurePrincipalSeeded(t, env, pgMintActors(env).HumanATok)
	cred := env.SSHCA().MintValidCert("alice-ssh-clone", []string{"alice@example.com"})
	env.GitHub().ResetPacketCounters()

	workDir, res := pgGitCloneSSH(t, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if res.ExitCode != 0 {
		t.Fatalf("SSH git clone failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	headRes := pgRunHardenedGit(workDir, nil, "rev-parse", "HEAD")
	if headRes.ExitCode != 0 || strings.TrimSpace(headRes.Stdout) != repo.HeadSHA {
		t.Fatalf("SSH cloned HEAD = %q (err=%s), want %q", strings.TrimSpace(headRes.Stdout), headRes.Stderr, repo.HeadSHA)
	}
	mainBytes, err := os.ReadFile(filepath.Join(workDir, "main.go"))
	if err != nil || string(mainBytes) != "package main\n\nfunc main() {}\n" {
		t.Fatalf("cloned main.go mismatch (err=%v): %q", err, string(mainBytes))
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	env.AssertNoSecretLeakInLogs()
}

func TestT1_PG_EF2_SSHPushWithValidUserCert(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t1pgEnsurePrincipalSeeded(t, env, actors.HumanATok)
	cred := env.SSHCA().MintValidCert("alice-ssh-push", []string{"alice@example.com"})
	env.GitHub().ResetPacketCounters()

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, tipSHA := t1pgCloneAndCommitSSH(t, env, repo, cred, map[string]string{
		"ssh_feature.go": cleanSrc,
	}, "feat: clean push over SSH cert", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushSSH(t, workDir, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	if res.ExitCode != 0 {
		t.Fatalf("SSH clean push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	gotSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotSHA != tipSHA {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotSHA, err, tipSHA)
	}
	if n := env.GitHub().ReceivePackBytes(repo.FullName); n <= 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0, got %d", n)
	}

	push := t1pgLatestPushForRepo(t, env, actors.SecAdminCli, repoID)
	if !push.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=true")
	}
	if !harness.ContainsStatus(env.Contracts().PushStatuses.TerminalSuccess, push.Status) {
		t.Fatalf("expected terminal success push status, got %q", push.Status)
	}

	env.AssertNoSecretLeakInLogs()
}

func TestT1_PG_EF2_SSHMultiPrincipalCertMatchesUser(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t1pgEnsurePrincipalSeeded(t, env, actors.HumanATok)
	principals := []string{"eng-group", "alice@example.com", "alice-human-001"}
	cred := env.SSHCA().MintValidCert("alice-multi-prin", principals)

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, tipSHA := t1pgCloneAndCommitSSH(t, env, repo, cred, map[string]string{
		"multi_principal.go": cleanSrc,
	}, "feat: multi-principal ssh push", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushSSH(t, workDir, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/feat/ssh-multi", env.SSHCA())
	if res.ExitCode != 0 {
		t.Fatalf("SSH multi-principal push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	exists, err := env.Git().BranchExists(repo.FullName, "feat/ssh-multi")
	if err != nil || !exists {
		t.Fatalf("expected upstream branch feat/ssh-multi (exists=%v, err=%v)", exists, err)
	}
	gotSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/feat/ssh-multi")
	if err != nil || gotSHA != tipSHA {
		t.Fatalf("refs/heads/feat/ssh-multi = %q (err=%v), want %q", gotSHA, err, tipSHA)
	}

	push := t1pgLatestPushForRepo(t, env, actors.SecAdminCli, repoID)
	harness.AssertUUIDv7(t, push.PrincipalID)
	matched := false
	for _, p := range principals {
		if strings.Contains(push.PrincipalSubject, p) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("push.PrincipalSubject %q did not match any cert principal in %v", push.PrincipalSubject, principals)
	}

	env.AssertNoSecretLeakInLogs()
}

func TestT1_PG_EF2_SSHKeyIDAndPrincipalRecordedOnPushSessionAndAuditEvent(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	audCli := t1pgAuditorClient(env)

	const certKeyID = "ssh-key-id-ef2-004"
	const certPrincipal = "alice-cert@example.com"
	emailVerified := true
	certActorTok := env.OIDC().MintToken(harness.TokenClaims{
		Kind:          "HUMAN",
		Subject:       certPrincipal,
		Email:         certPrincipal,
		EmailVerified: &emailVerified,
	})
	t1pgEnsurePrincipalSeeded(t, env, certActorTok)
	cred := env.SSHCA().MintValidCert(certKeyID, []string{certPrincipal})

	forgedAuthor := harness.GitIdentity{Name: "Mallory Forged", Email: "mallory@evil.example"}
	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, _ := t1pgCloneAndCommitSSH(t, env, repo, cred, map[string]string{
		"attributed.go": cleanSrc,
	}, "feat: test ssh cert principal binding", forgedAuthor)

	res := pgGitPushSSH(t, workDir, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	if res.ExitCode != 0 {
		t.Fatalf("SSH push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	push := t1pgLatestPushForRepo(t, env, actors.SecAdminCli, repoID)
	harness.AssertUUIDv7(t, push.PrincipalID)
	if !strings.Contains(push.PrincipalSubject, certPrincipal) {
		t.Fatalf("push.PrincipalSubject = %q, expected to contain SSH cert principal %q", push.PrincipalSubject, certPrincipal)
	}
	if strings.Contains(strings.ToLower(push.PrincipalSubject), "mallory") {
		t.Fatalf("forged Git author leaked into PrincipalSubject: %q", push.PrincipalSubject)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	audResp, raw, err := audCli.ListAuditEvents(ctx, harness.AuditFilter{
		ResourceID: push.ID,
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(resource_id=%s): %v", push.ID, err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if len(audResp.Events) == 0 {
		t.Fatalf("expected >= 1 audit event for push_session %s", push.ID)
	}
	harness.VerifyAuditHashChain(t, audResp.Events)

	foundCertAttribution := false
	for _, ev := range audResp.Events {
		if ev.ActorID == push.PrincipalID {
			payload := string(ev.Payload)
			if strings.Contains(strings.ToLower(payload), "mallory@evil.example") {
				t.Fatalf("audit event %s attributed actor/payload to forged Git author: %s", ev.ID, payload)
			}
			if strings.Contains(payload, certPrincipal) || strings.Contains(payload, certKeyID) {
				foundCertAttribution = true
			}
		}
	}
	if !foundCertAttribution {
		t.Fatalf("expected audit event actor/payload to reference SSH cert principal %q or key_id %q", certPrincipal, certKeyID)
	}

	env.AssertNoSecretLeakInLogs()
}

func TestT1_PG_EF2_SSHNonFastForwardAndBranchDelete(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	t1pgEnsurePrincipalSeeded(t, env, pgMintActors(env).HumanATok)
	cred := env.SSHCA().MintValidCert("alice-ssh-ff-del", []string{"alice@example.com"})

	if _, err := env.Git().CommitToBranch(repo.FullName, "feat/force-target", harness.CommitSpec{
		Files:   map[string]string{"target.txt": "initial branch content\n"},
		Message: "seed feat/force-target",
	}); err != nil {
		t.Fatalf("CommitToBranch(feat/force-target): %v", err)
	}
	if _, err := env.Git().CommitToBranch(repo.FullName, "feat/to-delete", harness.CommitSpec{
		Files:   map[string]string{"temp.txt": "branch to delete\n"},
		Message: "seed feat/to-delete",
	}); err != nil {
		t.Fatalf("CommitToBranch(feat/to-delete): %v", err)
	}

	workDir, cloneRes := pgGitCloneSSH(t, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("pgGitCloneSSH failed (exit %d): %s", cloneRes.ExitCode, cloneRes.Stderr)
	}
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name)
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email)

	// Create divergent orphan history for non-fast-forward force push.
	if res := pgRunHardenedGit(workDir, nil, "checkout", "--orphan", "divergent-branch"); res.ExitCode != 0 {
		t.Fatalf("git checkout --orphan failed: %s", res.Stderr)
	}
	_ = pgRunHardenedGit(workDir, nil, "rm", "-rf", ".")
	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	divergentSHA := pgAddCommit(t, workDir, map[string]string{"rewritten.go": cleanSrc}, nil, "feat: rewritten clean branch", author)

	forceRes := pgGitPushSSH(t, workDir, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), "+HEAD:refs/heads/feat/force-target", env.SSHCA())
	if forceRes.ExitCode != 0 {
		t.Fatalf("SSH non-fast-forward force push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			forceRes.ExitCode, forceRes.Stdout, forceRes.Stderr)
	}
	gotForceSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/feat/force-target")
	if err != nil || gotForceSHA != divergentSHA {
		t.Fatalf("refs/heads/feat/force-target = %q (err=%v), want %q", gotForceSHA, err, divergentSHA)
	}

	// Delete remote branch over SSH.
	delRes := pgGitPushSSH(t, workDir, t1pgGatewaySSHRepoURL(env, repo.FullName), cred, env.GitGatewaySSHAddr(), ":refs/heads/feat/to-delete", env.SSHCA())
	if delRes.ExitCode != 0 {
		t.Fatalf("SSH branch delete push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			delRes.ExitCode, delRes.Stdout, delRes.Stderr)
	}
	exists, err := env.Git().BranchExists(repo.FullName, "feat/to-delete")
	if err != nil {
		t.Fatalf("BranchExists(feat/to-delete): %v", err)
	}
	if exists {
		t.Fatalf("expected feat/to-delete to be deleted upstream")
	}

	env.AssertNoSecretLeakInLogs()
}

// --- EF3: Credential Helper & Upstream Tokens (ExtraSecrets) (5 tests) ---

func TestT1_PG_EF3_CredentialHelperGetWithOIDCToken(t *testing.T) {
	env, _, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	sub := env.Contracts().CLI.CredentialHelperSubcommand
	if len(sub) == 0 {
		sub = []string{"credential-helper"}
	}
	custBin := env.Contracts().Binaries.Custodian
	if custBin == "" {
		custBin = "custodian"
	}

	stdinPayload := "protocol=https\nhost=127.0.0.1\npath=acme/service.git\n\n"
	cliEnv := map[string]string{
		"CUSTODIAN_TOKEN":   actors.HumanATok,
		"CUSTODIAN_API_URL": env.APIBaseURL(),
	}

	getRes := env.RunCLIWithStdin(custBin, append(append([]string(nil), sub...), "get"), cliEnv, stdinPayload)
	if getRes.ExitCode != 0 {
		t.Fatalf("custodian credential-helper get failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			getRes.ExitCode, getRes.Stdout, getRes.Stderr)
	}
	if !strings.Contains(getRes.Stdout, "username=") || !strings.Contains(getRes.Stdout, "password="+actors.HumanATok) {
		t.Fatalf("expected username= and password=<OIDC token> in credential-helper stdout, got:\n%s", getRes.Stdout)
	}
	if strings.Contains(getRes.Stderr, actors.HumanATok) {
		t.Fatalf("OIDC token leaked to credential-helper stderr")
	}

	storeRes := env.RunCLIWithStdin(custBin, append(append([]string(nil), sub...), "store"), cliEnv, stdinPayload+"username=x-access-token\npassword="+actors.HumanATok+"\n\n")
	if storeRes.ExitCode != 0 {
		t.Fatalf("custodian credential-helper store failed (exit %d): %s", storeRes.ExitCode, storeRes.Stderr)
	}

	eraseRes := env.RunCLIWithStdin(custBin, append(append([]string(nil), sub...), "erase"), cliEnv, stdinPayload)
	if eraseRes.ExitCode != 0 {
		t.Fatalf("custodian credential-helper erase failed (exit %d): %s", eraseRes.ExitCode, eraseRes.Stderr)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF3_GitPushUsingCustodianCredentialHelper(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, tipSHA := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"cred_helper_push.go": cleanSrc,
	}, "feat: push via custodian credential-helper", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTPCredentialHelper(t, env, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main")
	if res.ExitCode != 0 {
		t.Fatalf("git push using custodian credential-helper failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	gotSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotSHA != tipSHA {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotSHA, err, tipSHA)
	}

	push := t1pgLatestPushForRepo(t, env, actors.SecAdminCli, repoID)
	if !push.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=true")
	}
	if !strings.Contains(push.PrincipalSubject, "alice-human-001") && !strings.Contains(push.PrincipalSubject, "alice@example.com") {
		t.Fatalf("unexpected PrincipalSubject %q for HumanA", push.PrincipalSubject)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF3_BrokerExchangedScopedUpstreamTokenUsedUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	env.GitHub().ResetPacketCounters()

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, _ := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"brokered_token.go": cleanSrc,
	}, "feat: verify brokered upstream token", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("HTTPS push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	var foundBrokered bool
	var capturedSecrets []string
	capturedSecrets = append(capturedSecrets, actors.HumanATok)
	for _, c := range env.GitHub().ReceivePackCalls() {
		if c.Repo == repo.FullName && c.StatusCode == http.StatusOK {
			if !c.HasToken {
				t.Fatalf("upstream receive-pack call had HasToken=false")
			}
			if c.Token == actors.HumanATok {
				t.Fatalf("gateway leaked caller OIDC token directly to upstream instead of exchanging brokered token")
			}
			if !strings.HasPrefix(c.Token, "ghs_write_") {
				t.Fatalf("expected brokered GitHub App write token ghs_write_*, got %q", c.Token)
			}
			env.RegisterSecret(c.Token)
			capturedSecrets = append(capturedSecrets, c.Token)
			foundBrokered = true
		}
	}
	if !foundBrokered {
		t.Fatalf("expected upstream receive-pack call with brokered ghs_write_* token; got %+v", env.GitHub().ReceivePackCalls())
	}

	env.AssertNoSecretLeakInLogs(capturedSecrets...)
}

func TestT1_PG_EF3_UserDelegatedOAuthPATForwarding(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	env.GitHub().ResetPacketCounters()

	cleanSrc := t1pgReadTransportFixture(t, filepath.Join("payloads", "clean_feature.go"))
	workDir, tipSHA := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"delegated_pat.go": cleanSrc,
	}, "feat: user-delegated PAT forwarding", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	pushURL, err := pgInjectHTTPAuth(t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(workDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "-c", "http.extraHeader=X-Custodian-Upstream-Token: "+actors.AliceWritePAT, "push", pushURL, "HEAD:refs/heads/main")
	if res.ExitCode != 0 {
		t.Fatalf("user-delegated PAT push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	gotSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotSHA != tipSHA {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotSHA, err, tipSHA)
	}

	foundDelegatedPAT := false
	for _, c := range env.GitHub().ReceivePackCalls() {
		if c.Repo == repo.FullName && c.HasToken && c.Token == actors.AliceWritePAT {
			foundDelegatedPAT = true
			break
		}
	}
	if !foundDelegatedPAT {
		t.Fatalf("expected upstream receive-pack call using delegated AliceWritePAT; got %+v", env.GitHub().ReceivePackCalls())
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.AliceWritePAT)
}

func TestT1_PG_EF3_ExtraSecretsRedactionAcrossLogsAndFindings(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	const extraSecret = "gho_extra_secrets_redaction_e2e_token_999"
	env.GitHub().RegisterUserToken(extraSecret, true)
	env.RegisterSecret(extraSecret)

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: extraSecret,
		FilePath:    "config/leaked.env",
		RuleID:      "github-pat-token",
	})

	workDir, _ := t1pgCloneAndCommitHTTP(t, env, repo, actors.HumanATok, map[string]string{
		"config/leaked.env": "UPSTREAM_PAT=" + extraSecret + "\n",
	}, "chore: accidental delegated token commit", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	pushURL, err := pgInjectHTTPAuth(t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(workDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "-c", "http.extraHeader=X-Custodian-Upstream-Token: "+extraSecret, "push", pushURL, "HEAD:refs/heads/main")
	if res.ExitCode == 0 {
		t.Fatalf("expected push with ExtraSecrets / gitleaks secret finding to be blocked")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	push := t1pgLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if push.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=false on blocked push")
	}

	rows, err := env.DB().QueryRows("SELECT COALESCE(message,''), COALESCE(metadata::text,''), COALESCE(evidence_ref,'') FROM findings")
	if err != nil {
		t.Fatalf("query findings table: %v", err)
	}
	var dbDump strings.Builder
	for _, row := range rows {
		dbDump.WriteString(strings.Join(row, " | "))
		dbDump.WriteByte('\n')
	}
	harness.AssertNoSecretOrEncodedLeak(t, dbDump.String(), extraSecret, actors.HumanATok)
	harness.AssertNoSecretOrEncodedLeak(t, res.Stderr, extraSecret, actors.HumanATok)
	env.AssertNoSecretLeakInLogs(actors.HumanATok, extraSecret)
}

// --- EF4: Git LFS Batch Gating (info/lfs/objects/batch & push.has_lfs) (5 tests) ---

func TestT1_PG_EF4_LFSBatchDownloadOp(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	payload := []byte("clean-lfs-download-artifact-payload-0123456789")
	sum := sha256.Sum256(payload)
	oid := hex.EncodeToString(sum[:])

	seedURL := env.GitHub().CloneURL(repo.FullName) + "/info/lfs/objects/" + oid
	seedReq, err := http.NewRequest(http.MethodPut, seedURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest(seed LFS): %v", err)
	}
	seedReq.Header.Set("Authorization", "Bearer "+actors.AliceWritePAT)
	seedResp, err := http.DefaultClient.Do(seedReq)
	if err != nil {
		t.Fatalf("PUT seed LFS object: %v", err)
	}
	_ = seedResp.Body.Close()
	if seedResp.StatusCode != http.StatusOK && seedResp.StatusCode != http.StatusCreated {
		t.Fatalf("seed LFS PUT status = %d", seedResp.StatusCode)
	}

	env.GitHub().ResetPacketCounters()

	batchReqBody, _ := json.Marshal(map[string]any{
		"operation": "download",
		"transfers": []string{"basic"},
		"objects": []map[string]any{
			{"oid": oid, "size": len(payload)},
		},
	})
	gwClient := env.GitGatewayHTTPClient()
	batchURL := t1pgGatewayRepoURL(env, repo.FullName) + "/info/lfs/objects/batch"
	req, err := http.NewRequest(http.MethodPost, batchURL, bytes.NewReader(batchReqBody))
	if err != nil {
		t.Fatalf("NewRequest(LFS batch): %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+actors.HumanATok)
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	req.Header.Set("Accept", "application/vnd.git-lfs+json")

	resp, err := gwClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", batchURL, err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS batch download status = %d, body=%s", resp.StatusCode, string(rawBody))
	}

	var batchResp struct {
		Objects []struct {
			OID     string `json:"oid"`
			Size    int64  `json:"size"`
			Actions map[string]struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(rawBody, &batchResp); err != nil {
		t.Fatalf("decode LFS batch response %q: %v", string(rawBody), err)
	}
	if len(batchResp.Objects) != 1 || batchResp.Objects[0].OID != oid {
		t.Fatalf("unexpected LFS batch objects: %+v", batchResp.Objects)
	}
	dlAction, ok := batchResp.Objects[0].Actions["download"]
	if !ok || dlAction.Href == "" {
		t.Fatalf("expected non-empty actions.download.href in %+v", batchResp.Objects[0])
	}

	dlReq, err := http.NewRequest(http.MethodGet, dlAction.Href, nil)
	if err != nil {
		t.Fatalf("NewRequest(download href): %v", err)
	}
	for k, v := range dlAction.Header {
		dlReq.Header.Set(k, v)
	}
	if dlReq.Header.Get("Authorization") == "" && strings.HasPrefix(dlAction.Href, env.GitGatewayHTTPSURL()) {
		dlReq.Header.Set("Authorization", "Bearer "+actors.HumanATok)
	}
	dlResp, err := gwClient.Do(dlReq)
	if err != nil {
		t.Fatalf("GET %s: %v", dlAction.Href, err)
	}
	gotBytes, _ := io.ReadAll(dlResp.Body)
	_ = dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK || !bytes.Equal(gotBytes, payload) {
		t.Fatalf("LFS download GET status=%d bytes=%q (want %q)", dlResp.StatusCode, string(gotBytes), string(payload))
	}

	foundBatch := false
	for _, c := range env.GitHub().LFSBatchCalls() {
		if c.Repo == repo.FullName && c.Operation == "download" && len(c.ObjectOIDs) == 1 && c.ObjectOIDs[0] == oid {
			foundBatch = true
			break
		}
	}
	if !foundBatch {
		t.Fatalf("expected upstream LFS download batch call for OID %s; got %+v", oid, env.GitHub().LFSBatchCalls())
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF4_LFSBatchUploadOpCleanPointer(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	env.GitHub().ResetPacketCounters()

	payload := bytes.Repeat([]byte("L"), 512)
	sum := sha256.Sum256(payload)
	oid := hex.EncodeToString(sum[:])

	batchReqBody, _ := json.Marshal(map[string]any{
		"operation": "upload",
		"transfers": []string{"basic"},
		"objects": []map[string]any{
			{"oid": oid, "size": len(payload)},
		},
	})
	gwClient := env.GitGatewayHTTPClient()
	batchURL := t1pgGatewayRepoURL(env, repo.FullName) + "/info/lfs/objects/batch"
	req, err := http.NewRequest(http.MethodPost, batchURL, bytes.NewReader(batchReqBody))
	if err != nil {
		t.Fatalf("NewRequest(LFS upload batch): %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+actors.HumanATok)
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	req.Header.Set("Accept", "application/vnd.git-lfs+json")

	resp, err := gwClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", batchURL, err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS batch upload status = %d, body=%s", resp.StatusCode, string(rawBody))
	}

	var batchResp struct {
		Objects []struct {
			OID     string `json:"oid"`
			Size    int64  `json:"size"`
			Actions map[string]struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(rawBody, &batchResp); err != nil {
		t.Fatalf("decode LFS upload batch response %q: %v", string(rawBody), err)
	}
	if len(batchResp.Objects) != 1 || batchResp.Objects[0].OID != oid {
		t.Fatalf("unexpected LFS batch objects: %+v", batchResp.Objects)
	}
	upAction, ok := batchResp.Objects[0].Actions["upload"]
	if !ok || upAction.Href == "" {
		t.Fatalf("expected non-empty actions.upload.href in %+v", batchResp.Objects[0])
	}

	putReq, err := http.NewRequest(http.MethodPut, upAction.Href, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest(PUT upload href): %v", err)
	}
	for k, v := range upAction.Header {
		putReq.Header.Set(k, v)
	}
	if putReq.Header.Get("Authorization") == "" && strings.HasPrefix(upAction.Href, env.GitGatewayHTTPSURL()) {
		putReq.Header.Set("Authorization", "Bearer "+actors.HumanATok)
	}
	putResp, err := gwClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT %s: %v", upAction.Href, err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK && putResp.StatusCode != http.StatusCreated {
		t.Fatalf("LFS object PUT status = %d", putResp.StatusCode)
	}

	foundBatch := false
	for _, c := range env.GitHub().LFSBatchCalls() {
		if c.Repo == repo.FullName && c.Operation == "upload" && len(c.ObjectOIDs) == 1 && c.ObjectOIDs[0] == oid {
			foundBatch = true
			break
		}
	}
	if !foundBatch {
		t.Fatalf("expected upstream LFS upload batch call for OID %s; got %+v", oid, env.GitHub().LFSBatchCalls())
	}
	if gotBytes := env.GitHub().LFSUploadBytes(repo.FullName); gotBytes != 512 {
		t.Fatalf("MockGitHub LFSUploadBytes = %d, want 512", gotBytes)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF4_GitPushWithLFSPointerSetsHasLFS(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir, cloneRes := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP failed: %s", cloneRes.Stderr)
	}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", "alice@example.com")

	data := bytes.Repeat([]byte{0x42}, 2048)
	_ = t1pgInitAndCommitLFSFile(t, workDir, "*.bin", "assets/model.bin", data, "feat: add clean 2KiB LFS binary", env.GitGatewayCACertPath())

	res := t1pgGitPushHTTPSWithLFS(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("git push with LFS pointer failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	push := t1pgLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if !push.HasLFS {
		t.Fatalf("expected push.HasLFS == true")
	}
	if push.LFSObjectCount != 1 {
		t.Fatalf("expected push.LFSObjectCount == 1, got %d", push.LFSObjectCount)
	}
	if push.LFSTotalBytes != 2048 {
		t.Fatalf("expected push.LFSTotalBytes == 2048, got %d", push.LFSTotalBytes)
	}
	if !push.UpstreamForwarded {
		t.Fatalf("expected push.UpstreamForwarded == true")
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF4_PushLFSGatePolicyCELTriggeredByHasLFS(t *testing.T) {
	lfsGateYAML := t1pgReadTransportFixture(t, filepath.Join("policies", "push_lfs_gate.yaml"))

	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	t1pgSeedRepoPolicyBundleDB(t, env, repoID, lfsGateYAML)
	actors := pgMintActors(env)

	// Step 1: Bounded LFS push (4096 bytes <= 1 MiB) -> ALLOW.
	workDir1, cloneRes1 := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes1.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP (step 1) failed: %s", cloneRes1.Stderr)
	}
	_ = pgRunHardenedGit(workDir1, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(workDir1, nil, "config", "user.email", "alice@example.com")
	_ = t1pgInitAndCommitLFSFile(t, workDir1, "*.bin", "assets/bounded.bin", bytes.Repeat([]byte{0x11}, 4096), "feat: bounded 4KiB LFS asset", env.GitGatewayCACertPath())

	res1 := t1pgGitPushHTTPSWithLFS(t, workDir1, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res1.ExitCode != 0 {
		t.Fatalf("bounded LFS push failed (exit %d):\nstdout:\n%s\nstderr:\n%s", res1.ExitCode, res1.Stdout, res1.Stderr)
	}
	push1 := t1pgLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if !push1.HasLFS || push1.LFSTotalBytes != 4096 || !push1.UpstreamForwarded {
		t.Fatalf("unexpected step 1 push record: %+v", push1)
	}

	// Step 2: Oversize LFS push (> 1 MiB) -> REQUIRE_APPROVAL triggered by push.lfs.oversize_approval.
	workDir2, cloneRes2 := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes2.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP (step 2) failed: %s", cloneRes2.Stderr)
	}
	_ = pgRunHardenedGit(workDir2, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(workDir2, nil, "config", "user.email", "alice@example.com")
	oversizeBytes := bytes.Repeat([]byte{0x22}, 1048576+1024)
	_ = t1pgInitAndCommitLFSFile(t, workDir2, "*.bin", "assets/oversize.bin", oversizeBytes, "feat: oversize >1MiB LFS asset", env.GitGatewayCACertPath())

	env.GitHub().ResetPacketCounters()
	res2 := t1pgGitPushHTTPSWithLFS(t, workDir2, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res2.ExitCode == 0 {
		t.Fatalf("expected oversize LFS push (> 1 MiB) to require approval and reject direct receive-pack")
	}
	if calls := env.GitHub().ReceivePackCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 upstream POST /git-receive-pack calls on REQUIRE_APPROVAL, got %+v", calls)
	}
	if n := env.GitHub().ReceivePackBytes(repo.FullName); n != 0 {
		t.Fatalf("expected 0 upstream receive-pack bytes on REQUIRE_APPROVAL, got %d", n)
	}

	push2 := t1pgLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if !push2.HasLFS || push2.LFSTotalBytes != int64(len(oversizeBytes)) {
		t.Fatalf("expected HasLFS=true and LFSTotalBytes=%d, got %+v", len(oversizeBytes), push2)
	}
	if push2.PolicyEffect != "REQUIRE_APPROVAL" && push2.Status != "APPROVAL_REQUIRED" {
		t.Fatalf("expected REQUIRE_APPROVAL / APPROVAL_REQUIRED, got effect=%q status=%q", push2.PolicyEffect, push2.Status)
	}
	if push2.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=false on REQUIRE_APPROVAL")
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF4_LFSObjectUploadCounterVerifiedOnMockGitHub(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir, cloneRes := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP failed: %s", cloneRes.Stderr)
	}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", "alice@example.com")

	lfsEnv := map[string]string{"GIT_SSL_CAINFO": env.GitGatewayCACertPath()}
	if res := t1pgRunGitWithLFSHooks(workDir, lfsEnv, "lfs", "install", "--local"); res.ExitCode != 0 {
		t.Fatalf("git lfs install --local failed: %s", res.Stderr)
	}
	if res := t1pgRunGitWithLFSHooks(workDir, lfsEnv, "lfs", "track", "*.dat"); res.ExitCode != 0 {
		t.Fatalf("git lfs track *.dat failed: %s", res.Stderr)
	}

	dataA := bytes.Repeat([]byte{0x0A}, 4096)
	dataB := bytes.Repeat([]byte{0x0B}, 8192)
	sumA := sha256.Sum256(dataA)
	sumB := sha256.Sum256(dataB)
	oidA := hex.EncodeToString(sumA[:])
	oidB := hex.EncodeToString(sumB[:])

	if err := os.MkdirAll(filepath.Join(workDir, "blobs"), 0o755); err != nil {
		t.Fatalf("mkdir blobs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "blobs", "a.dat"), dataA, 0o644); err != nil {
		t.Fatalf("write a.dat: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "blobs", "b.dat"), dataB, 0o644); err != nil {
		t.Fatalf("write b.dat: %v", err)
	}
	if res := t1pgRunGitWithLFSHooks(workDir, lfsEnv, "add", ".gitattributes", "blobs/a.dat", "blobs/b.dat"); res.ExitCode != 0 {
		t.Fatalf("git add LFS files failed: %s", res.Stderr)
	}
	commitEnv := map[string]string{
		"GIT_SSL_CAINFO":      env.GitGatewayCACertPath(),
		"GIT_AUTHOR_NAME":     "Alice Developer",
		"GIT_AUTHOR_EMAIL":    "alice@example.com",
		"GIT_COMMITTER_NAME":  "Alice Developer",
		"GIT_COMMITTER_EMAIL": "alice@example.com",
	}
	if res := t1pgRunGitWithLFSHooks(workDir, commitEnv, "commit", "-m", "feat: add two clean LFS dat assets"); res.ExitCode != 0 {
		t.Fatalf("git commit failed: %s", res.Stderr)
	}

	env.GitHub().ResetPacketCounters()
	res := t1pgGitPushHTTPSWithLFS(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("LFS multi-object push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	seenOIDs := make(map[string]bool)
	for _, c := range env.GitHub().LFSBatchCalls() {
		if c.Repo == repo.FullName && c.Operation == "upload" {
			for _, id := range c.ObjectOIDs {
				seenOIDs[strings.ToLower(id)] = true
			}
		}
	}
	if !seenOIDs[oidA] || !seenOIDs[oidB] {
		t.Fatalf("expected upload batch calls containing %s and %s; got %+v", oidA, oidB, env.GitHub().LFSBatchCalls())
	}
	if gotBytes := env.GitHub().LFSUploadBytes(repo.FullName); gotBytes != 12288 {
		t.Fatalf("expected MockGitHub LFSUploadBytes == 12288, got %d", gotBytes)
	}

	push := t1pgLatestPushForRepo(t, env, actors.HumanACli, repoID)
	if !push.HasLFS || push.LFSObjectCount != 2 || push.LFSTotalBytes != 12288 || !push.UpstreamForwarded {
		t.Fatalf("unexpected multi-LFS push metadata: %+v", push)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}
