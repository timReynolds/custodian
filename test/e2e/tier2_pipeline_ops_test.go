package e2e_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

// =============================================================================
// Shared M3 Tier 2 Helpers (all m3-prefixed for package e2e_test isolation)
// =============================================================================

func m3WritePolicyDir(t *testing.T, files map[string]string) string {
	return m3WritePolicyDirTemp(t, files)
}

func m3FindRepoRoot(t *testing.T) string {
	t.Helper()
	if envRoot := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_ROOT")); envRoot != "" {
		if _, err := os.Stat(filepath.Join(envRoot, "go.mod")); err == nil {
			return envRoot
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	cur := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur
		}
		if _, err := os.Stat(filepath.Join(cur, "test", "e2e", "run_e2e.sh")); err == nil {
			return cur
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

func m3ResolveGoBin(t *testing.T) string {
	t.Helper()
	goBin, err := harness.ResolveGoBin()
	if err != nil {
		t.Fatalf("ResolveGoBin: %v", err)
	}
	return goBin
}

func m3FetchAllAuditEvents(t *testing.T, env *harness.Env, auditorTok string, filter harness.AuditFilter) []harness.AuditEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := env.Client(auditorTok)
	var all []harness.AuditEvent
	f := filter
	if f.Limit <= 0 {
		f.Limit = 100
	}
	for page := 0; page < 100; page++ {
		resp, raw, err := client.ListAuditEvents(ctx, f)
		if err != nil {
			t.Fatalf("ListAuditEvents(page=%d): %v", page, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		all = append(all, resp.Events...)
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		f.Cursor = resp.NextCursor
	}
	return all
}

func m3PrepareEvaluatedProposal(t *testing.T, env *harness.Env, toks m3Tokens, repo harness.SeededRepo, modelRoute string, entries []harness.TarEntry) (harness.WorkspaceResp, harness.ProposalResp, harness.AssessmentsResp) {
	t.Helper()
	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, modelRoute, nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, entries, "Evaluated proposal", nil)
	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	return ws, evalProp, assessResp
}

func m3PrepareApprovedProposal(t *testing.T, env *harness.Env, toks m3Tokens, repo harness.SeededRepo, entries []harness.TarEntry) (harness.WorkspaceResp, harness.ProposalResp) {
	t.Helper()
	ws, evalProp, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", entries)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approved in helper")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	latest, raw, err := env.Client(toks.Controller).GetProposal(ctx, evalProp.ID)
	if err != nil {
		t.Fatalf("GetProposal after approval: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	return ws, latest
}

// m3PolicyYAMLToJSON converts Custodian PolicyBundle YAML into canonical JSON using Go stdlib only
// (avoiding any third-party YAML import in test/e2e).
func m3PolicyYAMLToJSON(yamlText string) ([]byte, string, string, error) {
	type ruleObl struct {
		Type          string `json:"type,omitempty"`
		ReviewerGroup string `json:"reviewer_group,omitempty"`
		Minimum       int    `json:"minimum"`
	}
	type ruleDef struct {
		ID          string    `json:"id"`
		Stages      []string  `json:"stages,omitempty"`
		When        string    `json:"when"`
		Effect      string    `json:"effect"`
		Overridable *bool     `json:"overridable,omitempty"`
		Obligations []ruleObl `json:"obligations,omitempty"`
	}
	type decisionModelDef struct {
		Route   string   `json:"route,omitempty"`
		Trigger []string `json:"trigger,omitempty"`
	}
	type inspectionDef struct {
		Mandatory     []string          `json:"mandatory,omitempty"`
		DecisionModel *decisionModelDef `json:"decisionModel,omitempty"`
	}
	type bundleDef struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"metadata"`
		Defaults struct {
			Effect  string `json:"effect"`
			OnError string `json:"onError"`
		} `json:"defaults"`
		Inspection *inspectionDef `json:"inspection,omitempty"`
		Rules      []ruleDef      `json:"rules"`
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

	b := bundleDef{
		Rules: make([]ruleDef, 0),
	}
	ensureInspection := func() *inspectionDef {
		if b.Inspection == nil {
			b.Inspection = &inspectionDef{}
		}
		return b.Inspection
	}
	ensureDecisionModel := func() *decisionModelDef {
		ins := ensureInspection()
		if ins.DecisionModel == nil {
			ins.DecisionModel = &decisionModelDef{}
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
	var curRule *ruleDef
	var curObl *ruleObl
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

	applyOblKV := func(obl *ruleObl, k, v string) {
		switch strings.TrimSpace(k) {
		case "type":
			obl.Type = unquote(v)
		case "reviewer_group":
			obl.ReviewerGroup = unquote(v)
		case "minimum":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				obl.Minimum = n
			}
		}
	}

	applyRuleKV := func(k, v string, indent int) {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "id":
			curRule.ID = unquote(v)
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
				curRule = &ruleDef{}
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
					curObl = &ruleObl{Minimum: 1}
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

	out, err := json.Marshal(b)
	if err != nil {
		return nil, "", "", err
	}
	return out, b.Metadata.Name, b.Metadata.Version, nil
}

func m3SeedPolicyBundleDB(t *testing.T, env *harness.Env, scope, repoUUID, name, version, bundleYAML string) string {
	t.Helper()
	if env.DB() == nil {
		t.Fatalf("m3SeedPolicyBundleDB requires DB")
	}
	defJSON, parsedName, parsedVersion, err := m3PolicyYAMLToJSON(bundleYAML)
	if err != nil {
		t.Fatalf("m3PolicyYAMLToJSON: %v", err)
	}
	if name == "" {
		name = m3NonEmpty(parsedName, "e2e-bundle")
	}
	if version == "" {
		version = m3NonEmpty(parsedVersion, "1.0.0")
	}
	digest := harness.SHA256Hex(defJSON)
	id := harness.NewTestUUIDv7()

	repoExpr := "NULL"
	if scope == "REPO" && repoUUID != "" {
		repoExpr = m3SQLQuote(repoUUID) + "::uuid"
	}
	q := fmt.Sprintf(`
INSERT INTO policy_bundles (
	id, name, version, scope, repository_id, digest, definition, activated_at
) VALUES (
	%s::uuid, %s, %s, %s, %s, %s, %s::jsonb, now()
)
ON CONFLICT (digest) DO UPDATE SET
	activated_at = now(),
	repository_id = EXCLUDED.repository_id,
	scope = EXCLUDED.scope
RETURNING id::text;`,
		m3SQLQuote(id),
		m3SQLQuote(name),
		m3SQLQuote(version),
		m3SQLQuote(scope),
		repoExpr,
		m3SQLQuote(digest),
		m3SQLQuote(string(defJSON)),
	)
	rows, err := env.DB().QueryRows(q)
	if err != nil {
		t.Fatalf("m3SeedPolicyBundleDB(%s, %s): %v", scope, name, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		t.Fatalf("m3SeedPolicyBundleDB(%s, %s): empty RETURNING id", scope, name)
	}
	return rows[0][0]
}

// =============================================================================
// F-13: Stage A Boundary & Failure Modes (5 Tier 2 Tests)
// =============================================================================

func TestT2_F13_ScannerFilesSkippedBlocksCleanAndPublish(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:         harness.ScannerModeFilesSkipped,
		SkippedPaths: []string{"huge.bin"},
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "huge.bin", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("binary-blob")},
	), "Evaluated proposal", nil)
	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findResp, fRaw, err := env.Client(toks.Controller).ListProposalFindings(ctx, evalProp.ID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)

	var semgrepIncomplete bool
	for _, run := range findResp.ScanRuns {
		if run.Scanner == "semgrep" && run.FilesSkipped > 0 && !run.Complete {
			semgrepIncomplete = true
		}
	}
	if !semgrepIncomplete {
		t.Fatalf("expected semgrep ScanRun with FilesSkipped > 0 and Complete=false, got %+v", findResp.ScanRuns)
	}
	if evalProp.LatestPolicyEffect == "ALLOW" {
		t.Fatalf("Stage C must not ALLOW when files were skipped (decisions=%+v)", assessResp.PolicyDecisions)
	}

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(skipped): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F13_MandatoryScannerCrashFailsClosed(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:     harness.ScannerModeCrash,
		ExitCode: 2,
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(), "Evaluated proposal", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findResp, fRaw, err := env.Client(toks.Controller).ListProposalFindings(ctx, evalProp.ID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)

	var gitleaksFailed bool
	for _, run := range findResp.ScanRuns {
		if run.Scanner == "gitleaks" && run.Status == "FAILED" && !run.Complete {
			gitleaksFailed = true
		}
	}
	if !gitleaksFailed {
		t.Fatalf("expected gitleaks ScanRun FAILED & Complete=false, got %+v", findResp.ScanRuns)
	}
	if evalProp.LatestPolicyEffect == "ALLOW" {
		t.Fatalf("Stage C must fail closed when mandatory scanner crashes, got effect=%q", evalProp.LatestPolicyEffect)
	}

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(crashed scanner): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F13_MandatoryScannerTimeoutFailsClosed(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithEnvOverrides(map[string]string{
			"CUSTODIAN_SCANNER_TIMEOUT": "1s",
		}),
	)
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:          harness.ScannerModeTimeout,
		SleepDuration: 5 * time.Second,
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(), "Evaluated proposal", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findResp, fRaw, err := env.Client(toks.Controller).ListProposalFindings(ctx, evalProp.ID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)

	var timedOut bool
	for _, run := range findResp.ScanRuns {
		if run.Scanner == "semgrep" && !run.Complete && (run.Status == "TIMED_OUT" || run.Status == "FAILED" || run.Status == "INCOMPLETE") {
			timedOut = true
		}
	}
	if !timedOut {
		t.Fatalf("expected semgrep ScanRun non-complete TIMED_OUT/FAILED/INCOMPLETE, got %+v", findResp.ScanRuns)
	}
	if evalProp.LatestPolicyEffect == "ALLOW" {
		t.Fatalf("Stage C must block ALLOW on scanner timeout, got %q", evalProp.LatestPolicyEffect)
	}

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(timeout): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F13_MultipleConcurrentSecretsInArchiveAllRedacted(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	sec1 := "AKIAIOSFODNN7EXAMPLE"
	sec2 := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	sec3 := "FAKE_E2E_TEST_KEY_DATA_DO_NOT_USE_000000000000000000000000000000"
	env.RegisterSecret(sec1)
	env.RegisterSecret(sec2)
	env.RegisterSecret(sec3)

	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: sec1,
		FilePath:    "secrets.env",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
		harness.TarEntry{Name: "id_rsa.pem", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_private_key.pem")},
	), "Evaluated proposal", nil)
	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	if evalProp.LatestPolicyEffect != "DENY" || evalProp.Status != "DENIED" {
		t.Fatalf("expected DENY/DENIED, got effect=%q status=%q", evalProp.LatestPolicyEffect, evalProp.Status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	findResp, fRaw, err := env.Client(toks.Controller).ListProposalFindings(ctx, evalProp.ID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)

	fJSON, _ := json.Marshal(findResp)
	aJSON, _ := json.Marshal(assessResp)
	audJSON, _ := json.Marshal(m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: evalProp.ID}))

	harness.AssertNoSecretOrEncodedLeak(t, string(fJSON), sec1, sec2, sec3)
	harness.AssertNoSecretOrEncodedLeak(t, string(aJSON), sec1, sec2, sec3)
	harness.AssertNoSecretOrEncodedLeak(t, string(audJSON), sec1, sec2, sec3)
	env.Gateway().AssertNoSecretInPrompts(t, sec1, sec2, sec3)
	harness.AssertNoSecretOrEncodedLeak(t, env.AllLogs(), sec1, sec2, sec3)
}

func TestT2_F13_ProhibitedLicenseAGPL3AndGPL3Blocked(t *testing.T) {
	policyDir := m3WritePolicyDir(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/org_mandatory_deny.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	cases := []struct {
		name        string
		spdx        string
		fixturePath string
		needle      string
	}{
		{"AGPL-3.0-only", "AGPL-3.0-only", "payloads/license_agpl3.txt", "AGPL"},
		{"GPL-3.0-only", "GPL-3.0-only", "payloads/license_gpl3.txt", "GPL"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env.Scanners().ResetAll()
			t.Cleanup(env.Scanners().ResetAll)

			ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
			env.Scanners().Set(harness.ScannerScanCode, harness.ScannerBehavior{
				Mode:        harness.ScannerModeProhibitedLicense,
				LicenseSPDX: tc.spdx,
				FilePath:    "LICENSE",
			})
			prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
				harness.TarEntry{Name: "LICENSE", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, tc.fixturePath)},
			), "Evaluated proposal", nil)
			evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			findResp, fRaw, err := env.Client(toks.Controller).ListProposalFindings(ctx, evalProp.ID)
			if err != nil {
				t.Fatalf("ListProposalFindings: %v", err)
			}
			fRaw.RequireStatus(t, http.StatusOK)

			var hasProhibited bool
			for _, f := range findResp.Findings {
				if f.Scanner == "scancode" && f.Category == "LICENSE" && strings.Contains(strings.ToUpper(f.RuleID+f.Message), tc.needle) {
					hasProhibited = true
				}
			}
			if !hasProhibited {
				t.Fatalf("expected scancode %s license finding in %+v", tc.spdx, findResp.Findings)
			}
			if evalProp.LatestPolicyEffect != "DENY" || evalProp.Status != "DENIED" {
				t.Fatalf("expected Stage C DENY/DENIED on prohibited license %s, got effect=%q status=%q", tc.spdx, evalProp.LatestPolicyEffect, evalProp.Status)
			}

			_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
				PublicationManifestDigest: evalProp.PublicationManifestDigest,
			})
			if err != nil {
				t.Fatalf("PublishProposal(license %s): %v", tc.spdx, err)
			}
			pubRaw.RequireStatus(t, http.StatusConflict)
		})
	}
}

// =============================================================================
// F-14: Stage B Boundary, Prompt Injection & Schema/Route Rejections (5 Tier 2 Tests)
// =============================================================================

func TestT2_F14_PromptInjectionCannotOverrideMandatoryDeny(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:       harness.GatewayModeClean,
		Confidence: 0.99,
	})

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:     harness.ScannerModeSecretFinding,
		FilePath: "secret.env",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "inj.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/prompt_injection_source.go")},
		harness.TarEntry{Name: "secret.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
	), "Evaluated proposal", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	env.Gateway().AssertPromptUntrustedFraming(t, "Ignore all previous instructions", true)
	if evalProp.LatestPolicyEffect != "DENY" || evalProp.Status != "DENIED" {
		t.Fatalf("prompt injection bypassed mandatory secret DENY: effect=%q status=%q", evalProp.LatestPolicyEffect, evalProp.Status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(prompt injection): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F14_UnauthorizedModelRouteForRestrictedRepoYieldsIndeterminate(t *testing.T) {
	env, repo, repoUUID := m3StartEnv(t, m3RepoConfig{
		Classification: "RESTRICTED",
		AllowedRoutes:  []string{"restricted-only-route"},
	})
	toks := m3MintTokens(env)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// (a) Unauthorized route at CreateWorkspace must be rejected with 403 Forbidden.
	_, unauthRaw, err := env.Client(toks.HumanA).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "unauth-route", ModelRoute: "public-cheap-route"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(unauthorized route): %v", err)
	}
	unauthRaw.RequireStatus(t, http.StatusForbidden)

	// (b) Create with authorized route, then revoke route in DB prior to EvaluateProposal.
	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "restricted-only-route", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(), "Route revoked before eval", nil)

	if _, err := env.DB().ExecSQL(fmt.Sprintf(
		"UPDATE repositories SET allowed_model_routes = %s WHERE id = %s::uuid;",
		m3SQLTextArray([]string{"different-restricted-route"}), m3SQLQuote(repoUUID),
	)); err != nil {
		t.Fatalf("revoke model route in DB: %v", err)
	}

	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	env.Gateway().AssertNoRouteCalled(t, "restricted-only-route")

	if len(assessResp.Assessments) == 0 || assessResp.Assessments[0].Status != "INDETERMINATE" {
		t.Fatalf("expected INDETERMINATE assessment, got %+v", assessResp.Assessments)
	}
	if evalProp.LatestPolicyEffect != "QUARANTINE" || evalProp.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINE/QUARANTINED, got effect=%q status=%q", evalProp.LatestPolicyEffect, evalProp.Status)
	}

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(indeterminate): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F14_MalformedModelGatewayJSONRejectedAndBlocksPublish(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeMalformedJSON)

	_, evalProp, assessResp := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries())

	if len(assessResp.Assessments) == 0 || assessResp.Assessments[0].Status != "FAILED" {
		t.Fatalf("expected AssessmentDTO.Status=FAILED on malformed JSON, got %+v", assessResp.Assessments)
	}
	if evalProp.LatestPolicyEffect != "QUARANTINE" && evalProp.LatestPolicyEffect != "DENY" {
		t.Fatalf("expected QUARANTINE/DENY on malformed model JSON, got %q", evalProp.LatestPolicyEffect)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(malformed JSON): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F14_UnknownDispositionAndMissingFieldsRejected(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().Enqueue(
		harness.GatewayProgram{Mode: harness.GatewayModeUnknownDisposition},
		harness.GatewayProgram{Mode: harness.GatewayModeMissingFields},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i, label := range []string{"unknown_disposition", "missing_fields"} {
		_, evalProp, assessResp := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries(
			harness.TarEntry{Name: fmt.Sprintf("case_%d.go", i), Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n")},
		))
		if len(assessResp.Assessments) == 0 || assessResp.Assessments[0].Status != "FAILED" {
			t.Fatalf("%s: expected AssessmentDTO.Status=FAILED, got %+v", label, assessResp.Assessments)
		}
		if evalProp.LatestPolicyEffect == "ALLOW" {
			t.Fatalf("%s: Stage C must block ALLOW, got %q", label, evalProp.LatestPolicyEffect)
		}
		_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
			PublicationManifestDigest: evalProp.PublicationManifestDigest,
		})
		if err != nil {
			t.Fatalf("PublishProposal(%s): %v", label, err)
		}
		pubRaw.RequireStatus(t, http.StatusConflict)
	}
}

func TestT2_F14_UngroundedEvidenceIDsRejected(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeInvalidEvidenceIDs)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:     harness.ScannerModeSASTFinding,
		FilePath: "sast.go",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "sast.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n")},
	), "Evaluated proposal", nil)
	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)

	if len(assessResp.Assessments) == 0 || assessResp.Assessments[0].Status != "FAILED" {
		t.Fatalf("expected AssessmentDTO.Status=FAILED on ungrounded evidence_ids, got %+v", assessResp.Assessments)
	}
	if evalProp.LatestPolicyEffect == "ALLOW" {
		t.Fatalf("Stage C must block ALLOW on ungrounded evidence_ids, got %q", evalProp.LatestPolicyEffect)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(ungrounded evidence): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

// =============================================================================
// F-15: Stage C Boundary, Fail-Closed CEL Errors & Org/Repo Composition (5 Tier 2 Tests)
// =============================================================================

func TestT2_F15_InvalidCELSyntaxAndTypeErrorRejectedBeforeActivation(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	root := m3FindRepoRoot(t)
	cliCfg := env.Contracts().CLI
	bin := env.Contracts().Binaries.Policy

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminClient := env.Client(toks.PolicyAdmin)

	for _, rel := range []string{"policies/invalid_cel_syntax.yaml", "policies/invalid_cel_type_error.yaml"} {
		bundleYAML := string(m3ReadFixture(t, env, rel))
		valResp, valRaw, err := adminClient.ValidatePolicy(ctx, harness.PolicyBundleReq{BundleYAML: bundleYAML})
		if err != nil {
			t.Fatalf("ValidatePolicy(%s): %v", rel, err)
		}
		if valRaw.StatusCode == http.StatusOK {
			if valResp.Valid || len(valResp.Errors) == 0 {
				t.Fatalf("%s: expected Valid=false with non-empty Errors, got %+v", rel, valResp)
			}
		} else {
			valRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusUnprocessableEntity)
		}

		_, simRaw, err := adminClient.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
			BundleYAML: bundleYAML,
			Stage:      "EGRESS",
			Input: map[string]any{
				"findings": map[string]any{"critical_secrets": 0},
			},
		})
		if err != nil {
			t.Fatalf("EvaluatePolicy(%s): %v", rel, err)
		}
		simRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusUnprocessableEntity)

		bundlePath := filepath.Join(root, "test", "e2e", "fixtures", rel)
		args := append(append([]string(nil), cliCfg.PolicyValidateSubcommand...), cliCfg.PolicyBundleFlag, bundlePath)
		cliRes := env.RunCLI(bin, args, nil)
		if cliRes.ExitCode == 0 {
			t.Fatalf("custodian-policy validate %s unexpectedly succeeded (stdout=%s)", rel, cliRes.Stdout)
		}
	}
}

func TestT2_F15_CELRuntimeErrorFailsClosedToDeny(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	root := m3FindRepoRoot(t)
	bundleYAML := string(m3ReadFixture(t, env, "policies/runtime_cel_error_fail_closed.yaml"))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	simResp, simRaw, err := env.Client(toks.PolicyAdmin).EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: bundleYAML,
		Stage:      "EGRESS",
		Input: map[string]any{
			"findings": map[string]any{"critical_secrets": 0, "prohibited_licenses": 0, "scan_complete": true},
			"change":   map[string]any{"paths": []string{"main.go"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(runtime error): %v", err)
	}
	simRaw.RequireStatus(t, http.StatusOK)
	if simResp.Effect != "DENY" {
		t.Fatalf("expected fail-closed DENY on runtime CEL error, got %q", simResp.Effect)
	}
	var hasErrorTrace bool
	for _, rt := range simResp.RuleTrace {
		if rt.Error != "" {
			hasErrorTrace = true
		}
	}
	if !hasErrorTrace {
		t.Fatalf("expected runtime error captured in RuleTrace, got %+v", simResp.RuleTrace)
	}

	inputPath := filepath.Join(t.TempDir(), "runtime_err_input.json")
	inBytes, _ := json.Marshal(map[string]any{
		"stage":    "EGRESS",
		"findings": map[string]any{"critical_secrets": 0, "prohibited_licenses": 0, "scan_complete": true},
		"change":   map[string]any{"paths": []string{"main.go"}},
	})
	if err := os.WriteFile(inputPath, inBytes, 0o644); err != nil {
		t.Fatalf("write input json: %v", err)
	}
	cliCfg := env.Contracts().CLI
	bundlePath := filepath.Join(root, "test", "e2e", "fixtures", "policies", "runtime_cel_error_fail_closed.yaml")
	args := append(append([]string(nil), cliCfg.PolicyEvaluateSubcommand...),
		cliCfg.PolicyBundleFlag, bundlePath,
		cliCfg.PolicyInputFlag, inputPath,
	)
	cliRes := env.RunCLI(env.Contracts().Binaries.Policy, args, nil)
	if !strings.Contains(cliRes.Stdout+cliRes.Stderr, "DENY") {
		t.Fatalf("expected fail-closed DENY from custodian-policy evaluate, got exit=%d stdout=%s stderr=%s", cliRes.ExitCode, cliRes.Stdout, cliRes.Stderr)
	}
}

func TestT2_F15_OrgNonOverridableDenyBlocksRepoPermissiveOverride(t *testing.T) {
	env, repo, repoUUID := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	orgYAML := string(m3ReadFixture(t, env, "policies/org_mandatory_deny.yaml"))
	repoYAML := string(m3ReadFixture(t, env, "policies/repo_permissive_override_attempt.yaml"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// (a) Policy simulation API with org + permissive repo override attempt
	simResp, simRaw, err := env.Client(toks.PolicyAdmin).EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		OrgBundleYAML: orgYAML,
		BundleYAML:    repoYAML,
		Stage:         "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"critical_secrets": 1, "prohibited_licenses": 0, "scan_complete": true},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{"secrets.env"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(org vs repo override): %v", err)
	}
	simRaw.RequireStatus(t, http.StatusOK)
	if simResp.Effect != "DENY" || !m3ContainsString(simResp.MatchedRuleIDs, "org.secrets.block") {
		t.Fatalf("expected DENY with org.secrets.block, got effect=%q matched=%v", simResp.Effect, simResp.MatchedRuleIDs)
	}

	// (b) Live proposal evaluation with ORG and REPO policy_bundles seeded in PostgreSQL
	m3SeedPolicyBundleDB(t, env, "ORG", "", "org-mandatory-baseline", "1.0.0", orgYAML)
	m3SeedPolicyBundleDB(t, env, "REPO", repoUUID, "repo-permissive-override", "1.0.0", repoYAML)

	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:     harness.ScannerModeSecretFinding,
		FilePath: "secrets.env",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
	), "Evaluated proposal", nil)
	evalProp, assessResp, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	if evalProp.LatestPolicyEffect != "DENY" || evalProp.Status != "DENIED" {
		t.Fatalf("live proposal expected DENY/DENIED despite permissive repo bundle, got effect=%q status=%q", evalProp.LatestPolicyEffect, evalProp.Status)
	}
	var sawOrgRule bool
	for _, pd := range assessResp.PolicyDecisions {
		for _, r := range pd.Reasons {
			if r.RuleID == "org.secrets.block" {
				sawOrgRule = true
			}
		}
	}
	if !sawOrgRule {
		t.Fatalf("expected org.secrets.block reason in PolicyDecisions: %+v", assessResp.PolicyDecisions)
	}
}

func TestT2_F15_UnsupportedBundleVersionAndInvalidStageRejected(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	adminClient := env.Client(toks.PolicyAdmin)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Malformed YAML
	malResp, malRaw, err := adminClient.ValidatePolicy(ctx, harness.PolicyBundleReq{
		BundleYAML: "apiVersion: custodian.dev/v1\nrules: [\n  unclosed",
	})
	if err != nil {
		t.Fatalf("ValidatePolicy(malformed): %v", err)
	}
	if malRaw.StatusCode == http.StatusOK {
		if malResp.Valid || len(malResp.Errors) == 0 {
			t.Fatalf("expected Valid=false on malformed YAML, got %+v", malResp)
		}
	} else {
		malRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusUnprocessableEntity)
	}

	// Unsupported apiVersion
	v99 := `apiVersion: custodian.dev/v99
kind: PolicyBundle
metadata:
  name: future-bundle
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: DENY
rules: []
`
	v99Resp, v99Raw, err := adminClient.ValidatePolicy(ctx, harness.PolicyBundleReq{BundleYAML: v99})
	if err != nil {
		t.Fatalf("ValidatePolicy(v99): %v", err)
	}
	if v99Raw.StatusCode == http.StatusOK {
		if v99Resp.Valid || len(v99Resp.Errors) == 0 {
			t.Fatalf("expected Valid=false on apiVersion v99, got %+v", v99Resp)
		}
	} else {
		v99Raw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusUnprocessableEntity)
	}

	// Invalid stage on EvaluatePolicy
	validYAML := string(m3ReadFixture(t, env, "policies/valid_default.yaml"))
	_, stRaw, err := adminClient.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: validYAML,
		Stage:      "INVALID_STAGE",
		Input:      map[string]any{"change": map[string]any{"paths": []string{"README.md"}}},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(INVALID_STAGE): %v", err)
	}
	stRaw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusUnprocessableEntity)
}

func TestT2_F15_DefaultEffectIsDenyWhenNoRuleMatches(t *testing.T) {
	env, _, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: default-deny-unmatched
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep]
  decisionModel:
    route: approved-code-review
rules:
  - id: only.nonexistent
    stages: [EGRESS]
    when: change.paths.exists(p, p == "nonexistent")
    effect: ALLOW
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, raw, err := env.Client(toks.PolicyAdmin).EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: bundleYAML,
		Stage:      "EGRESS",
		Input: map[string]any{
			"change": map[string]any{"paths": []string{"README.md"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(no rule match): %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if res.Effect != "DENY" || len(res.MatchedRuleIDs) != 0 {
		t.Fatalf("expected Effect=DENY and 0 matched rules, got effect=%q matched=%v", res.Effect, res.MatchedRuleIDs)
	}
}

// =============================================================================
// F-16: Approval Boundary, SoD, Non-Human Block & Stale Revocation (5 Tier 2 Tests)
// =============================================================================

func TestT2_F16_NonHumanTokenCannotApprove(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, prop, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name string
		tok  string
	}{
		{"agent", toks.Agent},
		{"controller", toks.Controller},
		{"service", toks.Service},
	} {
		_, raw, err := env.Client(tc.tok).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
			Decision:                  "APPROVE",
			PublicationManifestDigest: prop.PublicationManifestDigest,
			PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
			Comment:                   "non-human approval attempt",
		})
		if err != nil {
			t.Fatalf("ApproveProposal(%s): %v", tc.name, err)
		}
		raw.RequireStatus(t, http.StatusForbidden)
	}

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(after non-human attempts): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F16_SeparationOfDutiesSelfApprovalRejected(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	// Re-mint HumanA token WITH reviewer groups to prove SoD blocks self-approval regardless of groups.
	aliceWithGroups := env.MintToken(harness.TokenClaims{
		Kind:              "HUMAN",
		Subject:           "human-alice",
		Email:             "alice@example.com",
		Name:              "Alice Developer",
		PreferredUsername: "alice",
		Groups:            []string{"engineering", "platform-owners", "security-team"},
		Roles:             []string{"human", "developer", "reviewer"},
	})
	toks.HumanA = aliceWithGroups

	_, prop, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, appRaw, err := env.Client(aliceWithGroups).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
		Comment:                   "Self-approval attempt",
	})
	if err != nil {
		t.Fatalf("ApproveProposal(self): %v", err)
	}
	appRaw.RequireStatus(t, http.StatusForbidden)

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(self-approved): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F16_WrongReviewerGroupCannotSatisfyObligation(t *testing.T) {
	policyDir := m3WritePolicyDir(t, map[string]string{
		"default.yaml": string(m3ReadFixture(t, nil, "policies/valid_default.yaml")),
	})
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"}, harness.WithPolicyBundleDir(policyDir))
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, prop, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries(
		harness.TarEntry{Name: "infra/prod/main.tf", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("resource \"null_resource\" \"prod\" {}\n")},
	))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// HumanB is only in ["engineering"], NOT ["platform-owners"].
	appResp, appRaw, err := env.Client(toks.HumanB).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
		Comment:                   "Wrong group approval",
	})
	if err != nil {
		t.Fatalf("ApproveProposal(wrong group): %v", err)
	}
	if appRaw.StatusCode != http.StatusForbidden {
		appRaw.RequireStatus(t, http.StatusCreated)
		if len(appResp.RemainingObligations) == 0 || appResp.ProposalStatus == "APPROVED" {
			t.Fatalf("wrong reviewer group satisfied platform-owners obligation: %+v", appResp)
		}
	}

	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(wrong group): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs when obligation unsatisfied")
	}
}

func TestT2_F16_StaleManifestDigestAndWrongEvalIDRejected(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, prop, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	badDigest := strings.Repeat("a", 64)
	if badDigest == m3NormalizeSHA256(prop.PublicationManifestDigest) {
		badDigest = strings.Repeat("b", 64)
	}

	// (a) Altered manifest digest on ApproveProposal
	_, rA, err := env.Client(toks.Reviewer).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: badDigest,
		PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal(bad digest): %v", err)
	}
	rA.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	// (b) Wrong PolicyEvaluationID on ApproveProposal
	_, rB, err := env.Client(toks.Reviewer).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        harness.NewTestUUIDv7(),
	})
	if err != nil {
		t.Fatalf("ApproveProposal(wrong eval id): %v", err)
	}
	rB.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	// (c) Valid approval followed by PublishProposal with altered manifest digest
	m3ApproveProposal(t, env, toks.Reviewer, prop, "APPROVE", "Valid approval")
	_, rC, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: badDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(bad digest): %v", err)
	}
	rC.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs on stale digest publish")
	}
}

func TestT2_F16_ContentChangeInvalidatesPriorApproval(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, prop1 := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries(
		harness.TarEntry{Name: "hello.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar V = 1\n")},
	))
	d1 := prop1.PublicationManifestDigest

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	desc, descRaw, err := env.Client(toks.Controller).GetWorkspaceSource(ctx, ws.ID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource: %v", err)
	}
	descRaw.RequireStatus(t, http.StatusOK)

	// Upload modified snapshot S2 in same workspace -> prop2 with manifest digest D2 != D1.
	prop2 := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "hello.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar V = 2\n")},
	), "Modified snapshot S2", nil)
	eval2, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop2.ID, prop2.Version)
	d2 := eval2.PublicationManifestDigest
	if d2 == "" || d2 == d1 {
		t.Fatalf("expected distinct manifest digest D2 != D1, got d1=%q d2=%q", d1, d2)
	}

	// Both (a) unapproved publish with D2 and (b) publish with old digest D1 must fail with 409 Conflict.
	_, pubA, err := env.Client(toks.Controller).PublishProposal(ctx, eval2.ID, harness.PublishReq{PublicationManifestDigest: d2})
	if err != nil {
		t.Fatalf("PublishProposal(S2 unapproved): %v", err)
	}
	pubA.RequireStatus(t, http.StatusConflict)

	_, pubB, err := env.Client(toks.Controller).PublishProposal(ctx, eval2.ID, harness.PublishReq{PublicationManifestDigest: d1})
	if err != nil {
		t.Fatalf("PublishProposal(S2 with D1): %v", err)
	}
	pubB.RequireStatus(t, http.StatusConflict)

	// Fresh human approval bound to D2 and eval2.LatestPolicyEvaluationID permits publish.
	m3ApproveProposal(t, env, toks.Reviewer, eval2, "APPROVE", "Fresh approval for S2")
	pub := m3PublishAndWait(t, env, toks.Controller, eval2)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED after fresh S2 approval, got %q", pub.Status)
	}
}

// =============================================================================
// F-17: Publisher Boundary, Forged Author, Malicious Git, Force-Push & Race (5 Tier 2 Tests)
// =============================================================================

func TestT2_F17_CallerBranchAndRemoteOverrideRejected(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, prop := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries(
		harness.TarEntry{Name: "override.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n")},
	))
	origMainSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef(main): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	payload := []byte(fmt.Sprintf(
		`{"publication_manifest_digest":%q,"target_branch":"main","target_remote":"https://evil.invalid/repo.git"}`,
		prop.PublicationManifestDigest,
	))
	raw, err := env.Client(toks.Controller).DoRaw(ctx, http.MethodPost, "/v1/proposals/"+prop.ID+"/publish", payload)
	if err != nil {
		t.Fatalf("DoRaw(publish override): %v", err)
	}
	raw.RequireAnyStatus(t, http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusForbidden)
	m3AssertErrorEnvelope(t, raw)

	afterMainSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || afterMainSHA != origMainSHA {
		t.Fatalf("main branch mutated after rejected override: before=%s after=%s", origMainSHA, afterMainSHA)
	}
	for _, att := range env.GitHub().PushAttempts() {
		if att.Ref == "refs/heads/main" && att.Allowed {
			t.Fatalf("unexpected allowed push to main: %+v", att)
		}
	}
}

func TestT2_F17_ForgedAuthorMetadataIgnored(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)

	// Snapshot embeds forged .git/config user.name/user.email; SubmitProposal tests forged AuthorName/Email/description.
	entries := m3DefaultEntries(
		harness.TarEntry{Name: "legit.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar Legit = true\n")},
		harness.TarEntry{Name: ".git/config", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("[user]\n\tname = Evil Spoofer\n\temail = ceo@company.com\n")},
	)
	gzBytes, shaHex := harness.BuildTarGz(entries)
	artID, _ := m3UploadSnapshot(t, env, toks.Controller, desc, gzBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	// First verify forged author_email/author_name fields are either rejected (400) or ignored.
	forgedReq := harness.SubmitProposalReq{
		Snapshot:    harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws.Generation, SizeBytes: int64(len(gzBytes))},
		Title:       "Forged author test",
		Description: "Author: CEO <ceo@company.com>",
		AuthorEmail: "ceo@company.com",
		AuthorName:  "Evil Spoofer",
	}
	fResp, fRaw, err := ctrlClient.SubmitProposal(ctx, ws.ID, forgedReq)
	if err != nil {
		t.Fatalf("SubmitProposal(forged): %v", err)
	}
	var propID string
	if fRaw.StatusCode == http.StatusBadRequest || fRaw.StatusCode == http.StatusUnprocessableEntity {
		// Expected strict additionalProperties: false rejection; re-submit valid request with spoofed .git/config & description.
		subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, ws.ID, harness.SubmitProposalReq{
			Snapshot:    harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws.Generation, SizeBytes: int64(len(gzBytes))},
			Title:       "Forged .git/config author test",
			Description: "Author: CEO <ceo@company.com>",
		})
		if err != nil {
			t.Fatalf("SubmitProposal(clean req): %v", err)
		}
		subRaw.RequireStatus(t, http.StatusAccepted)
		propID = m3NonEmpty(subResp.ProposalID, subResp.ID)
		if subResp.OperationID != "" {
			if _, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second); err != nil {
				t.Fatalf("WaitForOperation: %v", err)
			}
		}
	} else {
		fRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated)
		propID = m3NonEmpty(fResp.ProposalID, fResp.ID)
		if fResp.OperationID != "" {
			if _, err := ctrlClient.WaitForOperation(ctx, fResp.OperationID, 30*time.Second); err != nil {
				t.Fatalf("WaitForOperation: %v", err)
			}
		}
	}

	prop := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "RECONSTRUCTED")
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}

	ci, err := env.Git().InspectCommit(repo.FullName, pub.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit: %v", err)
	}
	if ci.AuthorName != "Alice Developer" || ci.AuthorEmail != "alice@example.com" {
		t.Fatalf("author spoofed! got %q <%s>, want Alice Developer <alice@example.com>", ci.AuthorName, ci.AuthorEmail)
	}
}

func TestT2_F17_MaliciousSandboxGitHooksAndConfigNeverExecuted(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	gzBytes, shaHex := harness.BuildGitInjectionArchive(m3DefaultEntries(
		harness.TarEntry{Name: "clean.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc Clean() {}\n")},
	))
	artID, upRaw := m3UploadSnapshot(t, env, toks.Controller, desc, gzBytes)
	if upRaw.StatusCode < 200 || upRaw.StatusCode >= 300 {
		t.Fatalf("UploadSnapshot: status=%d body=%s", upRaw.StatusCode, string(upRaw.Body))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)
	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, ws.ID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws.Generation, SizeBytes: int64(len(gzBytes))},
		Title:    "Sandbox .git injection stripped",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	propID := m3NonEmpty(subResp.ProposalID, subResp.ID)
	if subResp.OperationID != "" {
		if _, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second); err != nil {
			t.Fatalf("WaitForOperation: %v", err)
		}
	}
	prop := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "RECONSTRUCTED")

	diffResp, diffRaw, err := ctrlClient.GetProposalDiff(ctx, prop.ID)
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	var hasCleanGo bool
	for _, cf := range diffResp.Paths {
		if strings.HasPrefix(cf.Path, ".git/") || cf.Path == ".git" {
			t.Fatalf("sandbox .git entry leaked into canonical diff paths: %+v", cf)
		}
		if cf.Path == "clean.go" {
			hasCleanGo = true
		}
	}
	if !hasCleanGo {
		t.Fatalf("expected clean.go in canonical diff paths, got %+v", diffResp.Paths)
	}

	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve")
	pub := m3PublishAndWait(t, env, toks.Controller, evalProp)
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED (hardened git must not execute sandbox hook), got %q", pub.Status)
	}

	tree, err := env.Git().InspectTree(repo.FullName, pub.CommitSHA)
	if err != nil {
		t.Fatalf("InspectTree: %v", err)
	}
	for p := range tree {
		if strings.HasPrefix(p, ".git/") || p == ".git" {
			t.Fatalf(".git entry %q found in published tree", p)
		}
	}
	if _, ok := tree["clean.go"]; !ok {
		t.Fatalf("clean.go missing from published tree")
	}
	env.AssertNoSecretLeakInLogs("ghp_FAKEADMIN999TESTONLY0000000000000000")
}

func TestT2_F17_UpstreamForcePushDetectedAndAborted(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, prop := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries(
		harness.TarEntry{Name: "feature.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar F = 1\n")},
	))

	newMainSHA, err := env.Git().ForcePushBranch(repo.FullName, repo.DefaultBranch, harness.CommitSpec{
		Files:   map[string]string{"rewritten.txt": "divergent\n"},
		Message: "Upstream force push",
		Author:  harness.GitIdentity{Name: "Upstream User", Email: "upstream@example.com"},
	})
	if err != nil {
		t.Fatalf("ForcePushBranch: %v", err)
	}
	resolvedSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/"+repo.DefaultBranch)
	if err != nil || resolvedSHA != newMainSHA {
		t.Fatalf("ResolveRef after ForcePushBranch mismatch: %q vs %q (err=%v)", resolvedSHA, newMainSHA, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)
	pubResp, pubRaw, err := ctrlClient.PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(after force-push): %v", err)
	}
	if pubRaw.StatusCode != http.StatusConflict {
		pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
		pubID := m3NonEmpty(pubResp.PublicationID, pubResp.ID)
		if pubResp.OperationID != "" {
			_, _ = ctrlClient.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		}
		finalPub := m3PollPublicationStatus(t, ctrlClient, pubID, 30*time.Second, "FAILED", "PUBLISHED")
		if finalPub.Status != "FAILED" {
			t.Fatalf("expected publication aborted as FAILED after upstream force-push, got %q", finalPub.Status)
		}
	}

	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected PRCount == 0 after force-push abort, got %d", env.GitHub().PRCount(repo.FullName))
	}
	exists, _ := env.Git().BranchExists(repo.FullName, "custodian/"+prop.ID)
	if exists {
		t.Fatalf("custodian/%s branch must not be created after force-push abort", prop.ID)
	}

	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{ResourceID: prop.ID})
	harness.VerifyAuditHashChain(t, events)
}

func TestT2_F17_ConcurrentPublishRaceProducesAtMostOneCommitAndPR(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, prop := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries(
		harness.TarEntry{Name: "race.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar Race = 1\n")},
	))

	const workers = 8
	keys := []string{"race-k1", "race-k1", "race-k2", "race-k3", "race-k4", "race-k5", "race-k6", "race-k7"}
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	type raceResult struct {
		status int
		pubID  string
		opID   string
		err    error
	}
	results := make([]raceResult, workers)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startCh
			c := env.Client(toks.Controller)
			resp, raw, err := c.PublishProposal(ctx, prop.ID, harness.PublishReq{
				PublicationManifestDigest: prop.PublicationManifestDigest,
			}, harness.WithIdempotencyKey(keys[idx]))
			if err != nil {
				results[idx] = raceResult{err: err}
				return
			}
			results[idx] = raceResult{
				status: raw.StatusCode,
				pubID:  m3NonEmpty(resp.PublicationID, resp.ID),
				opID:   resp.OperationID,
			}
		}(i)
	}
	close(startCh)
	wg.Wait()

	var winnerPubID, winnerOpID string
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("goroutine %d err: %v", i, r.err)
		}
		if r.status >= 500 {
			t.Fatalf("goroutine %d returned 5xx status %d", i, r.status)
		}
		if r.status == http.StatusAccepted || r.status == http.StatusOK {
			if winnerPubID == "" {
				winnerPubID = r.pubID
				winnerOpID = r.opID
			} else if r.pubID != "" && r.pubID != winnerPubID {
				t.Fatalf("concurrent publish produced distinct publication IDs: %q vs %q", r.pubID, winnerPubID)
			}
		} else if r.status != http.StatusConflict {
			t.Fatalf("goroutine %d unexpected status %d", i, r.status)
		}
	}
	if winnerPubID == "" {
		t.Fatalf("expected at least one winning publication ID across concurrent requests")
	}
	ctrlClient := env.Client(toks.Controller)
	if winnerOpID != "" {
		_, _ = ctrlClient.WaitForOperation(ctx, winnerOpID, 30*time.Second)
	}
	finalPub := m3PollPublicationStatus(t, ctrlClient, winnerPubID, 30*time.Second, "PUBLISHED")

	if env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected PRCount == 1 after concurrent race, got %d", env.GitHub().PRCount(repo.FullName))
	}
	ci, err := env.Git().InspectCommit(repo.FullName, finalPub.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit: %v", err)
	}
	if len(ci.Parents) != 1 || ci.Parents[0] != ws.BaseCommit {
		t.Fatalf("expected single canonical commit parented at %s, got %v", ws.BaseCommit, ci.Parents)
	}
}

// =============================================================================
// F-18: /v1 REST API Negative Auth, Validation, Idempotency & State Conflict Tests (5 Tier 2 Tests)
// =============================================================================

func TestT2_F18_UnauthenticatedAndInvalidJWTRejected401(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, prop, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries())

	badTokens := []struct {
		name string
		opt  harness.RequestOption
	}{
		{
			name: "no_auth",
			opt:  harness.WithoutAuth(),
		},
		{
			name: "expired",
			opt: harness.WithTokenOverride(env.MintToken(harness.TokenClaims{
				Kind:      "HUMAN",
				Subject:   "expired-user",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			})),
		},
		{
			name: "wrong_key",
			opt: harness.WithTokenOverride(env.MintToken(harness.TokenClaims{
				Kind:             "HUMAN",
				Subject:          "rogue-user",
				SignWithWrongKey: true,
			})),
		},
		{
			name: "tampered_sig",
			opt: harness.WithTokenOverride(env.MintToken(harness.TokenClaims{
				Kind:            "HUMAN",
				Subject:         "tampered-user",
				TamperSignature: true,
			})),
		},
		{
			name: "wrong_audience",
			opt: harness.WithTokenOverride(env.MintToken(harness.TokenClaims{
				Kind:     "HUMAN",
				Subject:  "wrong-aud-user",
				Audience: []string{"wrong-aud"},
			})),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := env.Client(toks.HumanA)

	for _, bt := range badTokens {
		_, r1, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
			Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		}, bt.opt)
		if err != nil {
			t.Fatalf("%s CreateWorkspace: %v", bt.name, err)
		}
		r1.RequireStatus(t, http.StatusUnauthorized)
		m3AssertErrorEnvelope(t, r1)

		_, r2, err := c.ListAuditEvents(ctx, harness.AuditFilter{}, bt.opt)
		if err != nil {
			t.Fatalf("%s ListAuditEvents: %v", bt.name, err)
		}
		r2.RequireStatus(t, http.StatusUnauthorized)

		_, r3, err := c.ValidatePolicy(ctx, harness.PolicyBundleReq{BundleYAML: "apiVersion: custodian.dev/v1\n"}, bt.opt)
		if err != nil {
			t.Fatalf("%s ValidatePolicy: %v", bt.name, err)
		}
		r3.RequireStatus(t, http.StatusUnauthorized)

		_, r4, err := c.ApproveProposal(ctx, prop.ID, harness.ApproveReq{
			Decision:                  "APPROVE",
			PublicationManifestDigest: prop.PublicationManifestDigest,
			PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
		}, bt.opt)
		if err != nil {
			t.Fatalf("%s ApproveProposal: %v", bt.name, err)
		}
		r4.RequireStatus(t, http.StatusUnauthorized)
	}
}

func TestT2_F18_CrossRoleAuthorizationMatrix403(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, prop := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. HumanB -> HumanA's workspace
	_, r1, err := env.Client(toks.HumanB).GetWorkspace(ctx, ws.ID)
	if err != nil {
		t.Fatalf("GetWorkspace(HumanB): %v", err)
	}
	r1.RequireStatus(t, http.StatusForbidden)
	m3AssertErrorEnvelope(t, r1)

	// 2. HumanA -> GetWorkspaceSource (controller-only)
	_, r2, err := env.Client(toks.HumanA).GetWorkspaceSource(ctx, ws.ID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource(HumanA): %v", err)
	}
	r2.RequireStatus(t, http.StatusForbidden)
	m3AssertErrorEnvelope(t, r2)

	// 3. HumanA -> ValidatePolicy (policy-admin-only)
	_, r3, err := env.Client(toks.HumanA).ValidatePolicy(ctx, harness.PolicyBundleReq{
		BundleYAML: string(m3ReadFixture(t, env, "policies/valid_default.yaml")),
	})
	if err != nil {
		t.Fatalf("ValidatePolicy(HumanA): %v", err)
	}
	r3.RequireStatus(t, http.StatusForbidden)
	m3AssertErrorEnvelope(t, r3)

	// 4. HumanA -> ListAuditEvents (auditor-only)
	_, r4, err := env.Client(toks.HumanA).ListAuditEvents(ctx, harness.AuditFilter{})
	if err != nil {
		t.Fatalf("ListAuditEvents(HumanA): %v", err)
	}
	r4.RequireStatus(t, http.StatusForbidden)
	m3AssertErrorEnvelope(t, r4)

	// 5. HumanA -> PublishProposal (controller-only)
	_, r5, err := env.Client(toks.HumanA).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(HumanA): %v", err)
	}
	r5.RequireStatus(t, http.StatusForbidden)
	m3AssertErrorEnvelope(t, r5)
}

func TestT2_F18_MissingIdempotencyKey400AndPayloadMismatch409(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, prop := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// (a) Missing Idempotency-Key across all 5 mutating POST endpoints -> 400 Bad Request
	_, r1, err := env.Client(toks.HumanA).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("CreateWorkspace(no idem): %v", err)
	}
	r1.RequireStatus(t, http.StatusBadRequest)

	_, r2, err := env.Client(toks.Controller).SubmitProposal(ctx, ws.ID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: harness.NewTestUUIDv7(), SHA256: strings.Repeat("0", 64), WorkspaceGeneration: ws.Generation},
		Title:    "No idem",
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("SubmitProposal(no idem): %v", err)
	}
	r2.RequireStatus(t, http.StatusBadRequest)

	_, r3, err := env.Client(toks.Controller).EvaluateProposal(ctx, prop.ID, harness.EvaluateReq{ExpectedVersion: prop.Version}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("EvaluateProposal(no idem): %v", err)
	}
	r3.RequireStatus(t, http.StatusBadRequest)

	_, r4, err := env.Client(toks.Reviewer2).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("ApproveProposal(no idem): %v", err)
	}
	r4.RequireStatus(t, http.StatusBadRequest)

	_, r5, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("PublishProposal(no idem): %v", err)
	}
	r5.RequireStatus(t, http.StatusBadRequest)

	// (b) Reused Idempotency-Key with different request body -> 409 Conflict
	_, okRaw, err := env.Client(toks.HumanA).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
	}, harness.WithIdempotencyKey("idem-mismatch"))
	if err != nil {
		t.Fatalf("CreateWorkspace(idem-mismatch 1): %v", err)
	}
	okRaw.RequireStatus(t, http.StatusAccepted)

	_, misRaw, err := env.Client(toks.HumanA).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "other"},
	}, harness.WithIdempotencyKey("idem-mismatch"))
	if err != nil {
		t.Fatalf("CreateWorkspace(idem-mismatch 2): %v", err)
	}
	misRaw.RequireStatus(t, http.StatusConflict)
	m3AssertErrorEnvelope(t, misRaw)
}

func TestT2_F18_UnknownFieldsMalformedJSONAndNonUUID400(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := env.Client(toks.HumanA)

	// (a) Malformed JSON
	rA, err := c.DoRaw(ctx, http.MethodPost, "/v1/workspaces", []byte("{bad-json"))
	if err != nil {
		t.Fatalf("DoRaw(bad json): %v", err)
	}
	rA.RequireStatus(t, http.StatusBadRequest)
	m3AssertErrorEnvelope(t, rA)

	// (b) Unknown field violating additionalProperties: false
	rB, err := c.DoRaw(ctx, http.MethodPost, "/v1/workspaces", []byte(fmt.Sprintf(
		`{"repository":{"provider":"github","repository_id":%d,"ref":"main"},"unknown_field":true}`,
		repo.GitHubRepoID,
	)))
	if err != nil {
		t.Fatalf("DoRaw(unknown field): %v", err)
	}
	rB.RequireStatus(t, http.StatusBadRequest)
	m3AssertErrorEnvelope(t, rB)

	// (c) Non-UUID path param
	_, rC, err := c.GetProposal(ctx, "not-a-uuid")
	if err != nil {
		t.Fatalf("GetProposal(not-a-uuid): %v", err)
	}
	rC.RequireStatus(t, http.StatusBadRequest)
	m3AssertErrorEnvelope(t, rC)

	// (d) Non-existent valid UUIDv7
	_, rD, err := c.GetProposal(ctx, harness.NewTestUUIDv7())
	if err != nil {
		t.Fatalf("GetProposal(non-existent): %v", err)
	}
	rD.RequireStatus(t, http.StatusNotFound)
	m3AssertErrorEnvelope(t, rD)
}

func TestT2_F18_InvalidStateTransitionsAndOptimisticVersionConflict409(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(), "State transitions & version", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// (a) Approve before Evaluate -> 409 Conflict
	_, appRaw, err := env.Client(toks.Reviewer).ApproveProposal(ctx, prop.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        harness.NewTestUUIDv7(),
	})
	if err != nil {
		t.Fatalf("ApproveProposal(before eval): %v", err)
	}
	appRaw.RequireStatus(t, http.StatusConflict)

	// (b) Publish before Evaluation/Approval -> 409 Conflict
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, prop.ID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(before eval): %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)

	// (c) Evaluate once (version increments >= 2), then call Evaluate with stale ExpectedVersion == prop.Version
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	if evalProp.Version <= prop.Version {
		t.Fatalf("expected version to increment after evaluation: before=%d after=%d", prop.Version, evalProp.Version)
	}
	_, staleRaw, err := env.Client(toks.Controller).EvaluateProposal(ctx, prop.ID, harness.EvaluateReq{
		ExpectedVersion: prop.Version,
	})
	if err != nil {
		t.Fatalf("EvaluateProposal(stale version): %v", err)
	}
	staleRaw.RequireStatus(t, http.StatusConflict)
	m3AssertErrorEnvelope(t, staleRaw)

	// Verify proposal state and version remained intact.
	afterProp, gRaw, err := env.Client(toks.Controller).GetProposal(ctx, prop.ID)
	if err != nil {
		t.Fatalf("GetProposal(after stale conflict): %v", err)
	}
	gRaw.RequireStatus(t, http.StatusOK)
	if afterProp.Version != evalProp.Version || afterProp.Status != evalProp.Status {
		t.Fatalf("stale conflict mutated proposal: got v=%d status=%q, want v=%d status=%q",
			afterProp.Version, afterProp.Status, evalProp.Version, evalProp.Status)
	}
}

// =============================================================================
// F-19: Rate Limits (429), Budget Exhaustion (429), Log Redaction & Retention Boundary (5 Tier 2 Tests)
// =============================================================================

func TestT2_F19_PerRepoConcurrencyLimitReturns429(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{
		Classification: "INTERNAL",
		MaxConcurrent:  1,
	}, harness.WithPerRepoConcurrency(1))
	toks := m3MintTokens(env)

	// Stop worker so the 1st operation stays PENDING and occupies the 1/1 per-repo slot.
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	c := env.Client(toks.HumanA)

	ws1, r1, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "slot-1", ModelRoute: "approved-code-review"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(1): %v", err)
	}
	r1.RequireStatus(t, http.StatusAccepted)

	_, r2, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "slot-2", ModelRoute: "approved-code-review"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(2): %v", err)
	}
	r2.RequireStatus(t, http.StatusTooManyRequests)
	m3AssertErrorEnvelope(t, r2)

	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	if ws1.OperationID != "" {
		if _, err := c.WaitForOperation(ctx, ws1.OperationID, 30*time.Second); err != nil {
			t.Fatalf("WaitForOperation(ws1): %v", err)
		}
	}
	wsID1 := m3NonEmpty(ws1.WorkspaceID, ws1.ID)
	m3WaitCondition(t, 20*time.Second, "ws1 READY", func() bool {
		got, gRaw, gErr := c.GetWorkspace(ctx, wsID1)
		return gErr == nil && gRaw.StatusCode == http.StatusOK && got.Status == "READY"
	})

	_, r3, err := c.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
		Agent:      &harness.WorkspaceAgentInfo{Type: "agent", SessionID: "slot-3", ModelRoute: "approved-code-review"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(3 after drain): %v", err)
	}
	r3.RequireStatus(t, http.StatusAccepted)
}

func TestT2_F19_GlobalScanBudgetExhaustedReturns429(t *testing.T) {
	// Assumption: CUSTODIAN_GLOBAL_SCAN_BUDGET=1 caps active/windowed evaluation scan budget to 1 proposal evaluation.
	// Keeping p1 in-flight during p2's EvaluateProposal triggers 429 under both active-concurrency and quota-window budget designs.
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithGlobalScanBudget(1),
	)
	toks := m3MintTokens(env)

	ws1, desc1 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	p1 := m3SubmitAndReconstruct(t, env, toks.Controller, ws1, desc1, m3DefaultEntries(
		harness.TarEntry{Name: "p1.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar P1 = 1\n")},
	), "Scan budget P1", nil)

	ws2, desc2 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	p2 := m3SubmitAndReconstruct(t, env, toks.Controller, ws2, desc2, m3DefaultEntries(
		harness.TarEntry{Name: "p2.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar P2 = 2\n")},
	), "Scan budget P2", nil)

	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:          harness.ScannerModeTimeout,
		SleepDuration: 1500 * time.Millisecond,
	})
	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:  harness.GatewayModeClean,
		Delay: 1500 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	// Start P1 evaluation and keep it in-flight while submitting P2 concurrently.
	eval1Resp, eval1Raw, err := ctrlClient.EvaluateProposal(ctx, p1.ID, harness.EvaluateReq{ExpectedVersion: p1.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal(p1): %v", err)
	}
	eval1Raw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	if eval1Resp.OperationID != "" {
		m3WaitCondition(t, 10*time.Second, "p1 eval operation RUNNING", func() bool {
			op, oRaw, oErr := ctrlClient.GetOperation(ctx, eval1Resp.OperationID)
			return oErr == nil && oRaw.StatusCode == http.StatusOK && (op.Status == "RUNNING" || harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status))
		})
	}

	type eval2Result struct {
		raw *harness.RawResponse
		err error
	}
	ch := make(chan eval2Result, 1)
	go func() {
		_, r2, err2 := env.Client(toks.Controller).EvaluateProposal(ctx, p2.ID, harness.EvaluateReq{ExpectedVersion: p2.Version})
		ch <- eval2Result{raw: r2, err: err2}
	}()
	res2 := <-ch
	if res2.err != nil {
		t.Fatalf("EvaluateProposal(p2): %v", res2.err)
	}
	res2.raw.RequireStatus(t, http.StatusTooManyRequests)
	m3AssertErrorEnvelope(t, res2.raw)

	if eval1Resp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, eval1Resp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(p1 eval): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("expected p1 eval to succeed, got %+v", op)
		}
	}
	invCountAfterP1 := len(env.Scanners().Invocations(harness.ScannerGitleaks))
	if invCountAfterP1 == 0 {
		t.Fatalf("expected p1 to invoke gitleaks at least once")
	}
	// Brief settle to verify throttled p2 did not trigger additional scanner invocations.
	time.Sleep(150 * time.Millisecond)
	if len(env.Scanners().Invocations(harness.ScannerGitleaks)) != invCountAfterP1 {
		t.Fatalf("expected no additional scanner invocations for throttled p2")
	}
}

func TestT2_F19_GlobalModelBudgetExhaustedReturns429(t *testing.T) {
	// Assumption: CUSTODIAN_GLOBAL_MODEL_BUDGET=1 caps active/windowed model gateway budget to 1 evaluation.
	// Keeping p1 in-flight inside MockGateway while triggering p2 concurrently enforces 429 under both concurrency and quota-window designs.
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithGlobalModelBudget(1),
		harness.WithGlobalScanBudget(10),
	)
	toks := m3MintTokens(env)
	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:  harness.GatewayModeClean,
		Delay: 1500 * time.Millisecond,
	})

	ws1, desc1 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	p1 := m3SubmitAndReconstruct(t, env, toks.Controller, ws1, desc1, m3DefaultEntries(
		harness.TarEntry{Name: "m1.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar M1 = 1\n")},
	), "Model budget P1", nil)

	ws2, desc2 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	p2 := m3SubmitAndReconstruct(t, env, toks.Controller, ws2, desc2, m3DefaultEntries(
		harness.TarEntry{Name: "m2.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar M2 = 2\n")},
	), "Model budget P2", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	// Start P1 evaluation and wait until P1 is actively in-flight in MockGateway.
	eval1Resp, eval1Raw, err := ctrlClient.EvaluateProposal(ctx, p1.ID, harness.EvaluateReq{ExpectedVersion: p1.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal(p1): %v", err)
	}
	eval1Raw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	if !env.Gateway().WaitForRequests(1, 10*time.Second) {
		t.Fatalf("timed out waiting for p1 to enter MockGateway")
	}

	type eval2Result struct {
		raw *harness.RawResponse
		err error
	}
	ch := make(chan eval2Result, 1)
	go func() {
		_, r2, err2 := env.Client(toks.Controller).EvaluateProposal(ctx, p2.ID, harness.EvaluateReq{ExpectedVersion: p2.Version})
		ch <- eval2Result{raw: r2, err: err2}
	}()
	res2 := <-ch
	if res2.err != nil {
		t.Fatalf("EvaluateProposal(p2 model budget): %v", res2.err)
	}
	res2.raw.RequireStatus(t, http.StatusTooManyRequests)
	m3AssertErrorEnvelope(t, res2.raw)

	if eval1Resp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, eval1Resp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(p1 model eval): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("expected p1 model eval to succeed, got %+v", op)
		}
	}
	gwReqsAfterP1 := len(env.Gateway().Requests())
	time.Sleep(150 * time.Millisecond)
	if len(env.Gateway().Requests()) != gwReqsAfterP1 {
		t.Fatalf("expected no second MockGateway request after model budget exhaustion (before=%d after=%d)",
			gwReqsAfterP1, len(env.Gateway().Requests()))
	}
}

func TestT2_F19_LogsNeverContainRawSecretsTokensOrSourceDiffs(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	diffCanary := "UNIQUE_DIFF_CANARY_STRING_998877"
	sec1 := "AKIAIOSFODNN7EXAMPLE"
	sec2 := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	env.RegisterSecret(diffCanary)
	env.RegisterSecret(sec1)
	env.RegisterSecret(sec2)
	env.RegisterSecret(toks.HumanA)
	env.RegisterSecret(toks.Controller)

	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: sec1,
		FilePath:    "secrets.env",
	})
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
		harness.TarEntry{Name: "diff_canary.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n// " + diffCanary + "\n")},
	), "Evaluated proposal", nil)
	evalProp, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop.ID, prop.Version)
	if evalProp.LatestPolicyEffect != "DENY" {
		t.Fatalf("expected DENY, got %q", evalProp.LatestPolicyEffect)
	}

	env.AssertNoSecretLeakInLogs(diffCanary, sec1, sec2, toks.HumanA, toks.Controller)
}

func TestT2_F19_RetentionReaperPreservesUnexpiredAndAuditLineage(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"},
		harness.WithRetentionTTL(5*time.Minute),
		harness.WithEnvOverrides(map[string]string{"CUSTODIAN_RETENTION_INTERVAL": "200ms"}),
	)
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	wsOld, pOld := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries(
		harness.TarEntry{Name: "old_file.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar Old = 1\n")},
	))
	pubOld := m3PublishAndWait(t, env, toks.Controller, pOld)
	if pubOld.Status != "PUBLISHED" {
		t.Fatalf("expected pOld PUBLISHED, got %q", pubOld.Status)
	}

	wsFresh, pFresh := m3PrepareApprovedProposal(t, env, toks, repo, m3DefaultEntries(
		harness.TarEntry{Name: "fresh_file.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar Fresh = 2\n")},
	))

	// Expire only pOld/wsOld transient artifacts (WORKSPACE_SOURCE/EGRESS_SNAPSHOT); keep pFresh/wsFresh unexpired.
	if _, err := env.DB().ExecSQL(fmt.Sprintf(`
UPDATE artifacts
SET expires_at = now() - interval '1 hour', deleted_at = NULL
WHERE kind IN ('WORKSPACE_SOURCE', 'EGRESS_SNAPSHOT')
  AND (
      workspace_id = %s::uuid
      OR id IN (
          SELECT unnest(ARRAY[snapshot_artifact_id, canonical_artifact_id, manifest_artifact_id, diff_artifact_id])
          FROM proposals WHERE id = %s::uuid
      )
  );
UPDATE artifacts
SET expires_at = now() + interval '1 day', deleted_at = NULL
WHERE workspace_id = %s::uuid
   OR id IN (
       SELECT unnest(ARRAY[snapshot_artifact_id, canonical_artifact_id, manifest_artifact_id, diff_artifact_id])
       FROM proposals WHERE id = %s::uuid
   );`,
		m3SQLQuote(wsOld.ID), m3SQLQuote(pOld.ID),
		m3SQLQuote(wsFresh.ID), m3SQLQuote(pFresh.ID),
	)); err != nil {
		t.Fatalf("update artifact expires_at: %v", err)
	}

	m3WaitCondition(t, 20*time.Second, "pOld WORKSPACE_SOURCE/EGRESS_SNAPSHOT reaped while pFresh retained", func() bool {
		oldRows, err := env.DB().QueryRows(fmt.Sprintf(
			`SELECT count(*) FROM artifacts WHERE workspace_id = %s::uuid AND kind IN ('WORKSPACE_SOURCE', 'EGRESS_SNAPSHOT') AND deleted_at IS NULL;`,
			m3SQLQuote(wsOld.ID),
		))
		if err != nil || len(oldRows) == 0 || oldRows[0][0] != "0" {
			return false
		}
		freshRows, err := env.DB().QueryRows(fmt.Sprintf(
			`SELECT count(*) FROM artifacts WHERE workspace_id = %s::uuid AND kind IN ('WORKSPACE_SOURCE', 'EGRESS_SNAPSHOT') AND deleted_at IS NULL;`,
			m3SQLQuote(wsFresh.ID),
		))
		return err == nil && len(freshRows) > 0 && freshRows[0][0] != "0"
	})

	// Verify unexpired pFresh snapshot object still exists in SnapshotStore.
	freshObjs, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT sha256 FROM artifacts WHERE id = %s::uuid AND deleted_at IS NULL;`,
		m3SQLQuote(pFresh.SnapshotArtifactID),
	))
	if err != nil || len(freshObjs) == 0 {
		t.Fatalf("pFresh snapshot artifact unexpectedly missing from DB: %v", err)
	}
	if _, err := env.Snapshots().FindBySHA256(freshObjs[0][0]); err != nil {
		t.Fatalf("pFresh artifact file missing from SnapshotStore: %v", err)
	}

	// Verify pOld proposal & audit hash chain remain intact.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	gotOld, rawOld, err := env.Client(toks.HumanA).GetProposal(ctx, pOld.ID)
	if err != nil {
		t.Fatalf("GetProposal(pOld): %v", err)
	}
	rawOld.RequireStatus(t, http.StatusOK)
	if gotOld.Status != "PUBLISHED" {
		t.Fatalf("expected pOld status PUBLISHED, got %q", gotOld.Status)
	}
	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{})
	harness.VerifyAuditHashChain(t, events)
}

// =============================================================================
// F-20: §16 Adversarial Containment & Crash Recovery Integration (5 Tier 2 Tests)
// =============================================================================

func TestT2_F20_RG10_WorkerAndPublisherCrashMidLeaseRecovery(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	prop := m3SubmitAndReconstruct(t, env, toks.Controller, ws, desc, m3DefaultEntries(
		harness.TarEntry{Name: "crash_rec.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nvar CrashRec = true\n")},
	), "RG-10 crash recovery", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	// Inject a short MockGateway delay so worker is deterministically mid-lease before SIGKILL.
	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:  harness.GatewayModeClean,
		Delay: 800 * time.Millisecond,
	})
	evalResp, evalRaw, err := ctrlClient.EvaluateProposal(ctx, prop.ID, harness.EvaluateReq{ExpectedVersion: prop.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal: %v", err)
	}
	evalRaw.RequireStatus(t, http.StatusAccepted)
	if evalResp.OperationID != "" {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			rows, qErr := env.DB().QueryRows(fmt.Sprintf(
				`SELECT status FROM operations WHERE id = %s::uuid;`,
				m3SQLQuote(evalResp.OperationID),
			))
			if qErr == nil && len(rows) > 0 && len(rows[0]) > 0 {
				st := rows[0][0]
				if st == "RUNNING" || harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, st) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
		}
	}
	if err := env.KillWorker(); err != nil {
		t.Fatalf("KillWorker: %v", err)
	}
	env.Gateway().SetMode(harness.GatewayModeClean)
	if _, err := env.DB().ExecSQL(`UPDATE operations SET lease_until = now() - interval '1 second' WHERE status = 'RUNNING';`); err != nil {
		t.Fatalf("expire worker lease: %v", err)
	}
	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	if evalResp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(eval recovery): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("eval operation failed after worker restart: %+v", op)
		}
	}
	evalProp := m3PollProposalStatus(t, ctrlClient, prop.ID, 30*time.Second, "PENDING_APPROVAL", "APPROVED")
	m3ApproveProposal(t, env, toks.Reviewer, evalProp, "APPROVE", "Approve after worker recovery")

	// Start publication, briefly poll operations.status = 'RUNNING', then SIGKILL publisher + expire RUNNING lease.
	pubResp, pubRaw, err := ctrlClient.PublishProposal(ctx, evalProp.ID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusAccepted)
	pubID := m3NonEmpty(pubResp.PublicationID, pubResp.ID)

	if pubResp.OperationID != "" {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			rows, qErr := env.DB().QueryRows(fmt.Sprintf(
				`SELECT status FROM operations WHERE id = %s::uuid;`,
				m3SQLQuote(pubResp.OperationID),
			))
			if qErr == nil && len(rows) > 0 && len(rows[0]) > 0 {
				st := rows[0][0]
				if st == "RUNNING" || harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, st) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := env.KillPublisher(); err != nil {
		t.Fatalf("KillPublisher: %v", err)
	}
	if _, err := env.DB().ExecSQL(`UPDATE operations SET lease_until = now() - interval '1 second' WHERE status = 'RUNNING';`); err != nil {
		t.Fatalf("expire publisher lease: %v", err)
	}
	if err := env.RestartPublisher(); err != nil {
		t.Fatalf("RestartPublisher: %v", err)
	}
	if pubResp.OperationID != "" {
		op, err := ctrlClient.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(pub recovery): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("publish operation failed after publisher restart: %+v", op)
		}
	}
	finalPub := m3PollPublicationStatus(t, ctrlClient, pubID, 30*time.Second, "PUBLISHED")
	if finalPub.Status != "PUBLISHED" || env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected PUBLISHED and PRCount==1 after publisher crash recovery, got status=%q prCount=%d",
			finalPub.Status, env.GitHub().PRCount(repo.FullName))
	}

	events := m3FetchAllAuditEvents(t, env, toks.Auditor, harness.AuditFilter{})
	harness.VerifyAuditHashChain(t, events)
}

func TestT2_F20_ADV01_02_03_04_AdversarialArchiveRejectionMatrix(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	corruptRandom := harness.BuildCorruptTarGz(harness.CorruptRandomBytes)
	corruptTrunc := harness.BuildCorruptTarGz(harness.CorruptTruncatedGzip)
	corruptCksum := harness.BuildCorruptTarGz(harness.CorruptTarChecksum)
	bombBytes, _ := harness.BuildGzipBomb(64 << 20)
	travDotDot, _ := harness.BuildPathTraversalArchive(harness.TraversalDotDot)
	travAbs, _ := harness.BuildPathTraversalArchive(harness.TraversalAbsolute)
	travBack, _ := harness.BuildPathTraversalArchive(harness.TraversalBackslash)
	symEsc, _ := harness.BuildSymlinkArchive("escape", "/etc/passwd")
	hardLink, _ := harness.BuildHardlinkArchive("hard", "target.txt")
	fifoEntry, _ := harness.BuildSpecialFileArchive(tar.TypeFifo, "fifo")
	caseCol, _ := harness.BuildCaseCollisionArchive()
	uniCol, _ := harness.BuildUnicodeCollisionArchive()

	matrix := []struct {
		name  string
		bytes []byte
	}{
		{"ADV01_random_bytes", corruptRandom},
		{"ADV01_truncated_gzip", corruptTrunc},
		{"ADV01_tar_checksum", corruptCksum},
		{"ADV01_gzip_bomb", bombBytes},
		{"ADV02_traversal_dotdot", travDotDot},
		{"ADV02_traversal_abs", travAbs},
		{"ADV02_traversal_backslash", travBack},
		{"ADV03_symlink_escape", symEsc},
		{"ADV03_hardlink", hardLink},
		{"ADV03_fifo_special", fifoEntry},
		{"ADV04_case_collision", caseCol},
		{"ADV04_unicode_nfc_nfd", uniCol},
	}

	ctrlClient := env.Client(toks.Controller)

	for _, tc := range matrix {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			// Each adversarial subtest provisions its own workspace & upload capability (unique ObjectKey)
			// so create-once SnapshotStore semantics never collide with 409 OBJECT_ALREADY_EXISTS.
			ws, desc := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)

			shaHex := harness.SHA256Hex(tc.bytes)
			upRaw, err := ctrlClient.UploadSnapshot(ctx, desc.UploadCapability.UploadURL, desc.UploadCapability.Token, tc.bytes)
			if err != nil {
				t.Fatalf("UploadSnapshot(%s): %v", tc.name, err)
			}
			if upRaw.StatusCode == http.StatusUnprocessableEntity || upRaw.StatusCode == http.StatusBadRequest || upRaw.StatusCode == http.StatusRequestEntityTooLarge {
				return
			}
			if upRaw.StatusCode < 200 || upRaw.StatusCode >= 300 {
				t.Fatalf("%s: unexpected upload status %d: %s", tc.name, upRaw.StatusCode, string(upRaw.Body))
			}

			artID := m3ExtractArtifactID(t, upRaw)
			subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, ws.ID, harness.SubmitProposalReq{
				Snapshot: harness.SnapshotSubmitRef{
					ArtifactID:          artID,
					SHA256:              shaHex,
					WorkspaceGeneration: ws.Generation,
					SizeBytes:           int64(len(tc.bytes)),
				},
				Title: "Adversarial " + tc.name,
			})
			if err != nil {
				t.Fatalf("SubmitProposal(%s): %v", tc.name, err)
			}
			if subRaw.StatusCode == http.StatusUnprocessableEntity || subRaw.StatusCode == http.StatusBadRequest {
				return
			}
			subRaw.RequireStatus(t, http.StatusAccepted)
			propID := m3NonEmpty(subResp.ProposalID, subResp.ID)
			if subResp.OperationID != "" {
				_, _ = ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
			}
			finalProp := m3PollProposalStatus(t, ctrlClient, propID, 30*time.Second, "FAILED", "DENIED", "RECONSTRUCTED")
			if finalProp.Status == "RECONSTRUCTED" {
				t.Fatalf("%s: adversarial archive unexpectedly reached RECONSTRUCTED", tc.name)
			}
		})
	}
}

func TestT2_F20_ADV05_06_07_SandboxGitSecretsAndForgedAuthor(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	secret1 := "AKIAIOSFODNN7EXAMPLE"
	env.RegisterSecret(secret1)

	// (1) Snapshot with .git injection + synthetic AWS secret -> DENIED & redacted
	ws1, desc1 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: secret1,
		FilePath:    "secrets.env",
	})
	gz1, sha1 := harness.BuildGitInjectionArchive(m3DefaultEntries(
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
	))
	art1, _ := m3UploadSnapshot(t, env, toks.Controller, desc1, gz1)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)
	sub1, raw1, err := ctrlClient.SubmitProposal(ctx, ws1.ID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: art1, SHA256: sha1, WorkspaceGeneration: ws1.Generation, SizeBytes: int64(len(gz1))},
		Title:    "ADV-05+06 git + secret",
	})
	if err != nil {
		t.Fatalf("SubmitProposal(1): %v", err)
	}
	raw1.RequireStatus(t, http.StatusAccepted)
	propID1 := m3NonEmpty(sub1.ProposalID, sub1.ID)
	if sub1.OperationID != "" {
		_, _ = ctrlClient.WaitForOperation(ctx, sub1.OperationID, 30*time.Second)
	}
	prop1 := m3PollProposalStatus(t, ctrlClient, propID1, 30*time.Second, "RECONSTRUCTED")
	eval1, _, find1 := m3EvaluateProposal(t, env, toks.Controller, prop1.ID, prop1.Version)
	if eval1.LatestPolicyEffect != "DENY" || eval1.Status != "DENIED" {
		t.Fatalf("expected DENY/DENIED for ADV-06, got effect=%q status=%q", eval1.LatestPolicyEffect, eval1.Status)
	}
	fJSON, _ := json.Marshal(find1)
	harness.AssertNoSecretOrEncodedLeak(t, string(fJSON), secret1)

	// (2) Snapshot with .git injection + clean app.go -> .git stripped, hook never runs, author is Alice
	env.Scanners().ResetAll()
	ws2, desc2 := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	gz2, sha2 := harness.BuildGitInjectionArchive(m3DefaultEntries(
		harness.TarEntry{Name: "app.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc App() {}\n")},
	))
	art2, _ := m3UploadSnapshot(t, env, toks.Controller, desc2, gz2)
	sub2, raw2, err := ctrlClient.SubmitProposal(ctx, ws2.ID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{ArtifactID: art2, SHA256: sha2, WorkspaceGeneration: ws2.Generation, SizeBytes: int64(len(gz2))},
		Title:    "ADV-05+07 git + forged author",
	})
	if err != nil {
		t.Fatalf("SubmitProposal(2): %v", err)
	}
	raw2.RequireStatus(t, http.StatusAccepted)
	propID2 := m3NonEmpty(sub2.ProposalID, sub2.ID)
	if sub2.OperationID != "" {
		_, _ = ctrlClient.WaitForOperation(ctx, sub2.OperationID, 30*time.Second)
	}
	prop2 := m3PollProposalStatus(t, ctrlClient, propID2, 30*time.Second, "RECONSTRUCTED")
	eval2, _, _ := m3EvaluateProposal(t, env, toks.Controller, prop2.ID, prop2.Version)
	m3ApproveProposal(t, env, toks.HumanB, eval2, "APPROVE", "Bob approves")
	pub2 := m3PublishAndWait(t, env, toks.Controller, eval2)
	if pub2.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub2.Status)
	}

	tree, err := env.Git().InspectTree(repo.FullName, pub2.CommitSHA)
	if err != nil {
		t.Fatalf("InspectTree: %v", err)
	}
	for p := range tree {
		if strings.HasPrefix(p, ".git/") || p == ".git" {
			t.Fatalf(".git entry %q leaked into published tree", p)
		}
	}
	ci, err := env.Git().InspectCommit(repo.FullName, pub2.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit: %v", err)
	}
	if ci.AuthorName != "Alice Developer" || ci.AuthorEmail != "alice@example.com" {
		t.Fatalf("forged author leaked: %q <%s>", ci.AuthorName, ci.AuthorEmail)
	}
}

func TestT2_F20_ADV08_09_10_PromptInjectionCelFailClosedAndStaleApproval(t *testing.T) {
	env, repo, _ := m3StartEnv(t, m3RepoConfig{Classification: "INTERNAL"})
	toks := m3MintTokens(env)

	// ADV-08: Prompt injection + secret -> DENY despite clean model output
	env.Gateway().SetMode(harness.GatewayModeClean)
	wsInj, descInj := m3CreateReadyWorkspace(t, env, toks.HumanA, toks.Controller, repo, "approved-code-review", nil)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:     harness.ScannerModeSecretFinding,
		FilePath: "secrets.env",
	})
	propInj := m3SubmitAndReconstruct(t, env, toks.Controller, wsInj, descInj, m3DefaultEntries(
		harness.TarEntry{Name: "inj.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/prompt_injection_source.go")},
		harness.TarEntry{Name: "secrets.env", Typeflag: tar.TypeReg, Mode: 0o644, Body: m3ReadFixture(t, env, "payloads/synthetic_aws_secret.env")},
	), "Evaluated proposal", nil)
	pInj, _, _ := m3EvaluateProposal(t, env, toks.Controller, propInj.ID, propInj.Version)
	if pInj.LatestPolicyEffect != "DENY" || pInj.Status != "DENIED" {
		t.Fatalf("ADV-08 expected DENY/DENIED, got effect=%q status=%q", pInj.LatestPolicyEffect, pInj.Status)
	}

	// ADV-09: CEL runtime error fails closed to DENY
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	celErrYAML := string(m3ReadFixture(t, env, "policies/runtime_cel_error_fail_closed.yaml"))
	simRes, simRaw, err := env.Client(toks.PolicyAdmin).EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		BundleYAML: celErrYAML,
		Stage:      "EGRESS",
		Input: map[string]any{
			"findings": map[string]any{"critical_secrets": 0, "prohibited_licenses": 0, "scan_complete": true},
			"change":   map[string]any{"paths": []string{"main.go"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(ADV-09): %v", err)
	}
	simRaw.RequireStatus(t, http.StatusOK)
	if simRes.Effect != "DENY" {
		t.Fatalf("ADV-09 expected fail-closed DENY, got %q", simRes.Effect)
	}

	// ADV-10: Stale manifest digest on ApproveProposal and PublishProposal -> 409 Conflict
	env.Scanners().ResetAll()
	_, pClean, _ := m3PrepareEvaluatedProposal(t, env, toks, repo, "approved-code-review", m3DefaultEntries(
		harness.TarEntry{Name: "stale.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar Stale = 1\n")},
	))
	staleDigest := strings.Repeat("c", 64)
	_, appRaw, err := env.Client(toks.Reviewer).ApproveProposal(ctx, pClean.ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: staleDigest,
		PolicyEvaluationID:        pClean.LatestPolicyEvaluationID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal(ADV-10): %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	m3ApproveProposal(t, env, toks.Reviewer, pClean, "APPROVE", "Valid approval")
	_, pubRaw, err := env.Client(toks.Controller).PublishProposal(ctx, pClean.ID, harness.PublishReq{
		PublicationManifestDigest: staleDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(ADV-10): %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs on stale approval/publish")
	}
}

func TestT2_F20_ADV11_12_RG07_08_ForcePushAndConcurrentPublishGate(t *testing.T) {
	env := harness.NewEnv(t, harness.WithSeedRepos(
		harness.RepoSeedSpec{Owner: "org", Name: "repo-force", Files: m3DefaultFiles(), DefaultBranch: "main"},
		harness.RepoSeedSpec{Owner: "org", Name: "repo-race", Files: m3DefaultFiles(), DefaultBranch: "main"},
	))
	repoForce, ok := env.Git().Repo("org/repo-force")
	if !ok {
		t.Fatalf("org/repo-force not seeded")
	}
	repoRace, ok := env.Git().Repo("org/repo-race")
	if !ok {
		t.Fatalf("org/repo-race not seeded")
	}
	m3EnsureRepoInDB(t, env, repoForce, "INTERNAL", []string{"approved-code-review"}, 10)
	m3EnsureRepoInDB(t, env, repoRace, "INTERNAL", []string{"approved-code-review"}, 10)

	toks := m3MintTokens(env)
	env.Gateway().SetMode(harness.GatewayModeClean)

	_, propForce := m3PrepareApprovedProposal(t, env, toks, repoForce, m3DefaultEntries(
		harness.TarEntry{Name: "force.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar Force = 1\n")},
	))
	wsRace, propRace := m3PrepareApprovedProposal(t, env, toks, repoRace, m3DefaultEntries(
		harness.TarEntry{Name: "race2.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\nvar Race2 = 1\n")},
	))

	// ADV-11: Upstream force-push before publish
	if _, err := env.Git().ForcePushBranch("org/repo-force", "main", harness.CommitSpec{
		Files:   map[string]string{"rewritten.md": "diverged history\n"},
		Message: "Force push main",
		Author:  harness.GitIdentity{Name: "Upstream", Email: "up@example.com"},
	}); err != nil {
		t.Fatalf("ForcePushBranch: %v", err)
	}
	afterForceMainSHA, err := env.Git().ResolveRef("org/repo-force", "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef(repo-force main): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ctrlClient := env.Client(toks.Controller)

	fPub, fRaw, err := ctrlClient.PublishProposal(ctx, propForce.ID, harness.PublishReq{
		PublicationManifestDigest: propForce.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(propForce): %v", err)
	}
	if fRaw.StatusCode != http.StatusConflict {
		fRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
		fPubID := m3NonEmpty(fPub.PublicationID, fPub.ID)
		if fPub.OperationID != "" {
			_, _ = ctrlClient.WaitForOperation(ctx, fPub.OperationID, 30*time.Second)
		}
		finalForce := m3PollPublicationStatus(t, ctrlClient, fPubID, 30*time.Second, "FAILED", "PUBLISHED")
		if finalForce.Status != "FAILED" {
			t.Fatalf("expected FAILED on force-pushed repo, got %q", finalForce.Status)
		}
	}
	if env.GitHub().PRCount("org/repo-force") != 0 {
		t.Fatalf("expected PRCount == 0 for org/repo-force")
	}
	checkMainSHA, _ := env.Git().ResolveRef("org/repo-force", "refs/heads/main")
	if checkMainSHA != afterForceMainSHA {
		t.Fatalf("org/repo-force main modified unexpectedly")
	}

	// ADV-12 + RG-07 + RG-08: 6 concurrent PublishProposal calls on org/repo-race
	origRaceMainSHA, err := env.Git().ResolveRef("org/repo-race", "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef(repo-race main): %v", err)
	}

	const nConc = 6
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	var winMu sync.Mutex
	var winPubID, winOpID string
	errs := make(chan error, nConc)

	for i := 0; i < nConc; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startCh
			c := env.Client(toks.Controller)
			resp, raw, err := c.PublishProposal(ctx, propRace.ID, harness.PublishReq{
				PublicationManifestDigest: propRace.PublicationManifestDigest,
			}, harness.WithIdempotencyKey(fmt.Sprintf("adv12-key-%d", idx)))
			if err != nil {
				errs <- err
				return
			}
			if raw.StatusCode >= 500 {
				errs <- fmt.Errorf("5xx status %d", raw.StatusCode)
				return
			}
			if raw.StatusCode == http.StatusAccepted || raw.StatusCode == http.StatusOK {
				pid := m3NonEmpty(resp.PublicationID, resp.ID)
				winMu.Lock()
				if winPubID == "" {
					winPubID = pid
					winOpID = resp.OperationID
				} else if pid != winPubID {
					errs <- fmt.Errorf("distinct pub IDs %q vs %q", pid, winPubID)
				}
				winMu.Unlock()
			} else if raw.StatusCode != http.StatusConflict {
				errs <- fmt.Errorf("unexpected status %d", raw.StatusCode)
			}
		}(i)
	}
	close(startCh)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent race error: %v", err)
	}
	if winPubID == "" {
		t.Fatalf("expected winning publication ID")
	}
	if winOpID != "" {
		_, _ = ctrlClient.WaitForOperation(ctx, winOpID, 30*time.Second)
	}
	finalRace := m3PollPublicationStatus(t, ctrlClient, winPubID, 30*time.Second, "PUBLISHED")
	if env.GitHub().PRCount("org/repo-race") != 1 {
		t.Fatalf("expected PRCount == 1 for org/repo-race, got %d", env.GitHub().PRCount("org/repo-race"))
	}
	branches, err := env.Git().ListBranches("org/repo-race")
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	wantBranch := "custodian/" + propRace.ID
	if len(branches) != 2 || !m3ContainsString(branches, "main") || !m3ContainsString(branches, wantBranch) {
		t.Fatalf("org/repo-race branches=%v, want [main %s]", branches, wantBranch)
	}
	afterRaceMainSHA, _ := env.Git().ResolveRef("org/repo-race", "refs/heads/main")
	if afterRaceMainSHA != origRaceMainSHA {
		t.Fatalf("org/repo-race main was modified")
	}
	ci, err := env.Git().InspectCommit("org/repo-race", finalRace.CommitSHA)
	if err != nil {
		t.Fatalf("InspectCommit(repo-race): %v", err)
	}
	if len(ci.Parents) != 1 || ci.Parents[0] != wsRace.BaseCommit {
		t.Fatalf("expected single canonical commit parented at %s, got %v", wsRace.BaseCommit, ci.Parents)
	}
}
