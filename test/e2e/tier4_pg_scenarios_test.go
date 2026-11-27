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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

// =============================================================================
// Tier 4 Push Gateway Scenario Helpers (t4pg* prefix; pure stdlib + harness)
// =============================================================================

type t4pgLFSBatchReq struct {
	Operation string              `json:"operation"`
	Transfers []string            `json:"transfers,omitempty"`
	Objects   []t4pgLFSBatchEntry `json:"objects"`
}

type t4pgLFSBatchEntry struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

type t4pgLFSBatchResp struct {
	Transfer string `json:"transfer"`
	Objects  []struct {
		OID     string `json:"oid"`
		Size    int64  `json:"size"`
		Actions map[string]struct {
			Href   string            `json:"href"`
			Header map[string]string `json:"header,omitempty"`
		} `json:"actions,omitempty"`
	} `json:"objects"`
}

type t4pgUploadResp struct {
	ArtifactID string `json:"artifact_id"`
	ID         string `json:"id"`
}

func t4pgFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func t4pgSQLQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func t4pgReadRepoFixture(t testing.TB, parts ...string) []byte {
	t.Helper()
	all := append([]string{pgFindRepoRoot(t)}, parts...)
	p := filepath.Join(all...)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %q: %v", p, err)
	}
	return data
}

func t4pgReadPGFixture(t testing.TB, relParts ...string) []byte {
	t.Helper()
	all := append([]string{"test", "e2e", "fixtures", "push_gateway"}, relParts...)
	return t4pgReadRepoFixture(t, all...)
}

func t4pgPolicyDirWithRepoDefault(t testing.TB, extraFiles map[string]string) string {
	t.Helper()
	root := pgFindRepoRoot(t)
	dir := t.TempDir()
	base := []struct {
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
	for _, f := range base {
		data, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatalf("read policy %q: %v", f.src, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.dst), data, 0o644); err != nil {
			t.Fatalf("write policy %q: %v", f.dst, err)
		}
	}
	for name, content := range extraFiles {
		target := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir policy dir %q: %v", name, err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatalf("write extra policy %q: %v", name, err)
		}
	}
	return dir
}

func t4pgCustomizeOrgBundleForPartner(t testing.TB, partnerFullName string) string {
	t.Helper()
	if strings.ContainsAny(partnerFullName, `"'`+"\n\r\\") {
		t.Fatalf("partnerFullName %q contains unsupported quote, backslash, or newline characters", partnerFullName)
	}
	orig := string(t4pgReadRepoFixture(t, "policies", "defaults", "push-ip-protection.yaml"))
	const (
		origDenyWhen = `when: "!destination.registered || destination.external"`
		origAllowSub = `!destination.external &&`
	)
	if !strings.Contains(orig, origDenyWhen) || !strings.Contains(orig, origAllowSub) {
		t.Fatalf("unexpected push-ip-protection.yaml layout; cannot customize ORG bundle for %q", partnerFullName)
	}
	customDenyWhen := fmt.Sprintf(`when: '!destination.registered || (destination.external && destination.name != %q)'`, partnerFullName)
	customAllowSub := fmt.Sprintf(`(!destination.external || destination.name == "%s") &&`, partnerFullName)

	customized := strings.Replace(orig, origDenyWhen, customDenyWhen, 1)
	customized = strings.Replace(customized, origAllowSub, customAllowSub, 1)
	customized = strings.Replace(customized, "name: push-ip-protection", "name: push-ip-protection-partner-org", 1)

	dir := t.TempDir()
	validDefault := t4pgReadRepoFixture(t, "test", "e2e", "fixtures", "policies", "valid_default.yaml")
	if err := os.WriteFile(filepath.Join(dir, "valid_default.yaml"), validDefault, 0o644); err != nil {
		t.Fatalf("write valid_default.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "push-ip-protection-partner-org.yaml"), []byte(customized), 0o644); err != nil {
		t.Fatalf("write customized ORG bundle in %q: %v", dir, err)
	}
	return dir
}

func t4pgWaitForPushSession(
	t testing.TB,
	ctx context.Context,
	cli *harness.APIClient,
	filter harness.PushFilter,
	minCount int,
	timeout time.Duration,
	match func(harness.PushSessionResp) bool,
) (harness.PushSessionResp, []byte) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastBody []byte
	for {
		list, raw, err := cli.ListPushes(ctx, filter)
		if err == nil && raw != nil && raw.StatusCode == http.StatusOK {
			lastBody = raw.Body
			if len(list.Pushes) >= minCount {
				for _, p := range list.Pushes {
					if match == nil || match(p) {
						return p, lastBody
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for push session (filter=%+v, minCount=%d); lastBody=%s", filter, minCount, string(lastBody))
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for push session: %v", ctx.Err())
		case <-time.After(75 * time.Millisecond):
		}
	}
}

func t4pgWaitUntil(t testing.TB, ctx context.Context, timeout time.Duration, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, err := fn()
		if err != nil {
			t.Fatalf("poll failed: %v", err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("poll timed out after %s", timeout)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("poll context cancelled: %v", ctx.Err())
		case <-time.After(60 * time.Millisecond):
		}
	}
}

func t4pgAssertOneOfStatus(t testing.TB, got string, allowed ...string) {
	t.Helper()
	for _, a := range allowed {
		if got == a {
			return
		}
	}
	t.Fatalf("unexpected status %q, want one of %v", got, allowed)
}

func t4pgEnsurePrincipalSeeded(t testing.TB, env *harness.Env, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _ = env.Client(token).GetWorkspace(ctx, harness.NewTestUUIDv7())
}

type t4pgScanRunSummary struct {
	ID            string `json:"id"`
	Scanner       string `json:"scanner"`
	Status        string `json:"status"`
	FilesExamined int    `json:"files_examined"`
	FilesSkipped  int    `json:"files_skipped"`
	Complete      bool   `json:"complete"`
}

type t4pgPushDetail struct {
	ID                    string               `json:"id"`
	Status                string               `json:"status"`
	Transport             string               `json:"transport,omitempty"`
	ErrorCode             string               `json:"error_code,omitempty"`
	PolicyEffect          string               `json:"policy_effect,omitempty"`
	AssessmentStatus      string               `json:"assessment_status,omitempty"`
	AssessmentDisposition string               `json:"assessment_disposition,omitempty"`
	ScanRuns              []t4pgScanRunSummary `json:"scan_runs,omitempty"`
	Findings              []harness.FindingDTO `json:"findings,omitempty"`
}

func t4pgGetPushDetail(t testing.TB, ctx context.Context, cli *harness.APIClient, pushID string) (harness.PushSessionResp, t4pgPushDetail) {
	t.Helper()
	sess, raw, err := cli.GetPush(ctx, pushID)
	if err != nil {
		t.Fatalf("GetPush(%s): %v", pushID, err)
	}
	raw.RequireStatus(t, http.StatusOK)
	var detail t4pgPushDetail
	if err := json.Unmarshal(raw.Body, &detail); err != nil {
		t.Fatalf("decode GetPush(%s) detail: %v (body=%s)", pushID, err, string(raw.Body))
	}
	return sess, detail
}

func t4pgQueryLatestModelAssessment(t testing.TB, env *harness.Env, pushSessionID string) (assessmentType, status, disposition string) {
	t.Helper()
	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT COALESCE(assessment_type, ''), status, COALESCE(disposition, '') FROM model_assessments WHERE push_session_id = %s::uuid ORDER BY created_at DESC LIMIT 1;`,
		t4pgSQLQuote(pushSessionID),
	))
	if err != nil {
		t.Fatalf("query model_assessments for %s: %v", pushSessionID, err)
	}
	if len(rows) == 0 {
		t.Fatalf("expected >=1 model_assessments row for push_session %s, got 0", pushSessionID)
	}
	return rows[0][0], rows[0][1], rows[0][2]
}

func t4pgAssertNoRawCorpusAcrossSurfaces(
	t testing.TB,
	ctx context.Context,
	env *harness.Env,
	auditorCli *harness.APIClient,
	repoID, pushID, gitStderr string,
	rawSnippets ...string,
) {
	t.Helper()
	pgAssertNoRawCorpusLeak(t, env, rawSnippets...)
	if gitStderr != "" {
		harness.AssertNoSecretOrEncodedLeak(t, gitStderr, rawSnippets...)
	}
	if pushID != "" {
		_, getRaw, err := auditorCli.GetPush(ctx, pushID)
		if err != nil {
			t.Fatalf("GetPush(%s): %v", pushID, err)
		}
		getRaw.RequireStatus(t, http.StatusOK)
		harness.AssertNoSecretOrEncodedLeak(t, string(getRaw.Body), rawSnippets...)
	}
	_, listRaw, err := auditorCli.ListPushes(ctx, harness.PushFilter{RepositoryID: repoID})
	if err != nil {
		t.Fatalf("ListPushes: %v", err)
	}
	listRaw.RequireStatus(t, http.StatusOK)
	harness.AssertNoSecretOrEncodedLeak(t, string(listRaw.Body), rawSnippets...)

	_, corpRaw, err := auditorCli.ListIPCorpora(ctx, harness.IPCorpusFilter{})
	if err != nil {
		t.Fatalf("ListIPCorpora: %v", err)
	}
	corpRaw.RequireStatus(t, http.StatusOK)
	harness.AssertNoSecretOrEncodedLeak(t, string(corpRaw.Body), rawSnippets...)

	rows, err := env.DB().QueryRows(
		`SELECT layer, fingerprint_hash, COALESCE(file_path_hash, ''), COALESCE(language, ''), metadata::text FROM ip_fingerprints;`,
	)
	if err != nil {
		t.Fatalf("query ip_fingerprints: %v", err)
	}
	var sb strings.Builder
	for _, r := range rows {
		sb.WriteString(strings.Join(r, "\t"))
		sb.WriteByte('\n')
	}
	if sb.Len() > 0 {
		harness.AssertNoSecretOrEncodedLeak(t, sb.String(), rawSnippets...)
	}
}

func t4pgScrapeGatewayMetrics(t testing.TB, ctx context.Context, env *harness.Env) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.GitGatewayMetricsURL(), nil)
	if err != nil {
		t.Fatalf("build metrics request: %v", err)
	}
	resp, err := env.GitGatewayHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", env.GitGatewayMetricsURL(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics HTTP %d: %s", resp.StatusCode, string(body))
	}
	return string(body)
}

func t4pgMetricSumForName(metricsBody, metricName string) (found bool, sum float64) {
	for _, line := range strings.Split(metricsBody, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, metricName) {
			continue
		}
		rest := line[len(metricName):]
		if rest != "" && rest[0] != '{' && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		found = true
		sum += v
	}
	return found, sum
}

func t4pgLFSUploadViaGateway(
	t testing.TB,
	ctx context.Context,
	env *harness.Env,
	repoFullName, token string,
	blob []byte,
) (oid string, batchStatus int, putStatus int) {
	t.Helper()
	sum := sha256.Sum256(blob)
	oid = hex.EncodeToString(sum[:])

	payload, err := json.Marshal(t4pgLFSBatchReq{
		Operation: "upload",
		Transfers: []string{"basic"},
		Objects:   []t4pgLFSBatchEntry{{OID: oid, Size: int64(len(blob))}},
	})
	if err != nil {
		t.Fatalf("marshal LFS batch: %v", err)
	}

	batchURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repoFullName + ".git/info/lfs/objects/batch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, batchURL, strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("new LFS batch request: %v", err)
	}
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	req.SetBasicAuth("x-access-token", token)

	cli := env.GitGatewayHTTPClient()
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", batchURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read LFS batch response: %v", err)
	}
	batchStatus = resp.StatusCode
	if batchStatus != http.StatusOK {
		return oid, batchStatus, 0
	}

	var parsed t4pgLFSBatchResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode LFS batch response: %v", err)
	}
	if len(parsed.Objects) != 1 {
		t.Fatalf("expected 1 LFS batch object, got %d", len(parsed.Objects))
	}
	uploadHref := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repoFullName + ".git/info/lfs/objects/" + oid
	var uploadHeaders map[string]string
	if act, ok := parsed.Objects[0].Actions["upload"]; ok && act.Href != "" {
		uploadHref = act.Href
		uploadHeaders = act.Header
	}
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadHref, strings.NewReader(string(blob)))
	if err != nil {
		t.Fatalf("new LFS PUT request: %v", err)
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range uploadHeaders {
		putReq.Header.Set(k, v)
	}
	if putReq.Header.Get("Authorization") == "" {
		putReq.SetBasicAuth("x-access-token", token)
	}
	putResp, err := cli.Do(putReq)
	if err != nil {
		t.Fatalf("PUT %s: %v", uploadHref, err)
	}
	defer putResp.Body.Close()
	_, _ = io.ReadAll(putResp.Body)
	return oid, batchStatus, putResp.StatusCode
}

func t4pgSeedRepositoryRow(
	t testing.TB,
	env *harness.Env,
	repo harness.SeededRepo,
	classification, egressMode string,
	registered, external bool,
	remoteHost string,
) string {
	t.Helper()
	repoID := harness.NewTestUUIDv7()
	q := fmt.Sprintf(`
INSERT INTO repositories (
	id, github_repository_id, github_installation_id, full_name, classification,
	enabled, allowed_model_routes, max_concurrent_operations,
	egress_mode, passive_audit_delivery, remote_host, registered_destination, external
) VALUES (
	%s::uuid, %d, %d, %s, %s,
	true, ARRAY['approved-code-review']::text[], 10,
	%s, 'ASYNC', %s, %t, %t
);`,
		t4pgSQLQuote(repoID),
		repo.GitHubRepoID,
		repo.InstallationID,
		t4pgSQLQuote(repo.FullName),
		t4pgSQLQuote(classification),
		t4pgSQLQuote(egressMode),
		t4pgSQLQuote(remoteHost),
		registered,
		external,
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("seed repository %s: %v", repo.FullName, err)
	}
	return repoID
}

// t4pgPolicyYAMLToJSON converts Custodian PolicyBundle YAML into canonical JSON using Go stdlib only.
func t4pgPolicyYAMLToJSON(yamlText string) ([]byte, string, string, error) {
	type ruleObl struct {
		Type          string `json:"type,omitempty"`
		ReviewerGroup string `json:"reviewer_group"`
		Minimum       *int   `json:"minimum,omitempty"`
	}
	type ruleDef struct {
		ID          string    `json:"id"`
		Description string    `json:"description,omitempty"`
		Stages      []string  `json:"stages"`
		When        string    `json:"when"`
		Effect      string    `json:"effect"`
		Overridable *bool     `json:"overridable,omitempty"`
		Message     string    `json:"message,omitempty"`
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
			Scope   string `json:"scope,omitempty"`
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

	b := bundleDef{Rules: make([]ruleDef, 0)}
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
	whenMode := ""
	whenIndent := 0
	var whenRawLines []string

	flushWhen := func() {
		if inWhenFold && curRule != nil {
			if len(whenRawLines) == 0 {
				curRule.When = ""
			} else {
				baseIndent := len(whenRawLines[0]) - len(strings.TrimLeft(whenRawLines[0], " "))
				if whenMode == "|" || whenMode == "|-" {
					outLines := make([]string, 0, len(whenRawLines))
					for _, line := range whenRawLines {
						lineIndent := len(line) - len(strings.TrimLeft(line, " "))
						cut := baseIndent
						if lineIndent < cut {
							cut = lineIndent
						}
						outLines = append(outLines, line[cut:])
					}
					curRule.When = strings.TrimSpace(strings.Join(outLines, "\n"))
				} else {
					var sb strings.Builder
					prevMore := false
					for i, line := range whenRawLines {
						lineIndent := len(line) - len(strings.TrimLeft(line, " "))
						cut := baseIndent
						if lineIndent < cut {
							cut = lineIndent
						}
						rel := line[cut:]
						curMore := lineIndent > baseIndent
						if i > 0 {
							if prevMore || curMore {
								sb.WriteByte('\n')
							} else {
								sb.WriteByte(' ')
							}
						}
						if curMore {
							sb.WriteString(rel)
						} else {
							sb.WriteString(strings.TrimSpace(rel))
						}
						prevMore = curMore
					}
					curRule.When = strings.TrimSpace(sb.String())
				}
			}
		}
		inWhenFold = false
		whenMode = ""
		whenRawLines = nil
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

	applyOblKV := func(obl *ruleObl, k, v string) {
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
				whenMode = v
				whenIndent = indent
				whenRawLines = nil
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
		rawLine = strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(rawLine) == "" || strings.HasPrefix(strings.TrimSpace(rawLine), "#") {
			continue
		}
		indent := len(rawLine) - len(strings.TrimLeft(rawLine, " "))
		trimmed := strings.TrimSpace(rawLine)

		if inWhenFold {
			if indent > whenIndent {
				whenRawLines = append(whenRawLines, rawLine)
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
					curObl = &ruleObl{Type: "HUMAN_REVIEW"}
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
		return nil, "", "", err
	}

	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSuffix(rawBuf.Bytes(), []byte("\n"))))
	dec.UseNumber()
	var normalized any
	if err := dec.Decode(&normalized); err != nil {
		return nil, "", "", err
	}

	var canonBuf bytes.Buffer
	canonEnc := json.NewEncoder(&canonBuf)
	canonEnc.SetEscapeHTML(false)
	if err := canonEnc.Encode(normalized); err != nil {
		return nil, "", "", err
	}
	canon := bytes.TrimSuffix(canonBuf.Bytes(), []byte("\n"))
	return canon, b.Metadata.Name, b.Metadata.Version, nil
}

// t4pgSeedRepoPolicyBundleDB inserts/activates a scope=REPO PolicyBundle bound to repository_id
// in PostgreSQL policy_bundles (because workflow.SyncPolicyDir only syncs ORG bundles from disk).
func t4pgSeedRepoPolicyBundleDB(t testing.TB, env *harness.Env, repoID, yamlBody string) string {
	t.Helper()
	if repoID == "" {
		t.Fatalf("t4pgSeedRepoPolicyBundleDB requires non-empty repoID")
	}
	defJSON, name, version, err := t4pgPolicyYAMLToJSON(yamlBody)
	if err != nil {
		t.Fatalf("t4pgPolicyYAMLToJSON: %v", err)
	}
	name = t4pgFirstNonEmpty(name, "e2e-repo-bundle")
	version = t4pgFirstNonEmpty(version, "1.0.0")
	id := harness.NewTestUUIDv7()
	digest := harness.SHA256Hex(defJSON)
	q := fmt.Sprintf(`
INSERT INTO policy_bundles (id, name, version, scope, repository_id, digest, definition, activated_at)
VALUES (%s::uuid, %s, %s, 'REPO', %s::uuid, %s, %s::jsonb, now())
ON CONFLICT (digest) DO UPDATE SET
  scope = 'REPO',
  repository_id = EXCLUDED.repository_id,
  activated_at = COALESCE(policy_bundles.activated_at, now())
RETURNING id;`,
		t4pgSQLQuote(id),
		t4pgSQLQuote(name),
		t4pgSQLQuote(version),
		t4pgSQLQuote(repoID),
		t4pgSQLQuote(digest),
		t4pgSQLQuote(string(defJSON)),
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("seed REPO policy_bundles (%s/%s for repo %s): %v", name, version, repoID, err)
	}
	return id
}

// =============================================================================
// Tier 4 Real-World Application Scenarios (7 scenarios matching TEST_INFRA.md)
// =============================================================================

// Scenario 1: Registered internal repo clean feature dev (OIDC credential-helper + HTTPS clone +
// branch push + Stage B NOT_REQUIRED + clean repack + upstream receipt + custodian push status + zero-secret logs).
func TestT4_PG_Scenario1_CleanInternalFeatureDev(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t4pgPolicyDirWithRepoDefault(t, nil)),
	)
	actors := pgMintActors(env)
	env.Gateway().ResetRequests()

	gwHTTPSURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git"
	workDir, cloneRes := pgGitCloneHTTP(t, gwHTTPSURL, actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("HTTPS clone failed: %s", cloneRes.Stderr)
	}
	if len(env.GitHub().UploadPackCalls()) == 0 {
		t.Fatalf("expected transparent git-upload-pack read proxy call during clone")
	}

	if res := pgRunHardenedGit(workDir, nil, "checkout", "-b", "feature/greeting"); res.ExitCode != 0 {
		t.Fatalf("git checkout -b failed: %s", res.Stderr)
	}
	featureSHA := pgAddCommit(t, workDir, map[string]string{
		"pkg/greeting/greeting.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, nil, "Add clean greeting feature", harness.GitIdentity{
		Name: "Alice Developer", Email: "alice@example.com",
	})

	pushRes := pgGitPushHTTPCredentialHelper(t, env, workDir, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/feature/greeting")
	if pushRes.ExitCode != 0 {
		t.Fatalf("credential-helper branch push failed (exit=%d): %s", pushRes.ExitCode, pushRes.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected non-zero upstream receive-pack bytes for clean feature push")
	}

	// Verify Stage B was NOT_REQUIRED (untriggered).
	if reqs := env.Gateway().Requests(); len(reqs) != 0 {
		t.Fatalf("expected 0 Stage B requests for clean internal push, got %d", len(reqs))
	}

	// Verify upstream bare repo received the branch & commit.
	upstreamSHA, err := env.Git().ResolveRef(repo.FullName, "refs/heads/feature/greeting")
	if err != nil || upstreamSHA != featureSHA {
		t.Fatalf("upstream branch feature/greeting mismatch: got %q err=%v want %q", upstreamSHA, err, featureSHA)
	}

	// Verify control-plane push session & clean repack GIT_PUSH_BUNDLE artifact.
	sess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.Status == "COMPLETED"
	})
	detail, getRaw, err := actors.AuditorCli.GetPush(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetPush(%s): %v", sess.ID, err)
	}
	getRaw.RequireStatus(t, http.StatusOK)
	if detail.AssessmentStatus != "NOT_REQUIRED" || detail.AssessmentDisposition != "NOT_REQUIRED" || detail.PolicyEffect != "ALLOW" || !detail.UpstreamForwarded {
		t.Fatalf("unexpected clean push session state: %+v", detail)
	}
	harness.AssertUUIDv7(t, sess.BundleArtifactID)
	artRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT kind, size_bytes FROM artifacts WHERE id = %s::uuid;`, t4pgSQLQuote(sess.BundleArtifactID),
	))
	if err != nil || len(artRows) != 1 || artRows[0][0] != "GIT_PUSH_BUNDLE" {
		t.Fatalf("expected GIT_PUSH_BUNDLE artifact in DB, got rows=%+v err=%v", artRows, err)
	}
	artSize, convErr := strconv.ParseInt(artRows[0][1], 10, 64)
	if convErr != nil || artSize <= 0 {
		t.Fatalf("expected GIT_PUSH_BUNDLE size_bytes > 0, got %q (err=%v)", artRows[0][1], convErr)
	}

	// Verify `custodian push status` CLI output.
	cliArgs := append(append([]string{}, env.Contracts().CLI.PushStatusSubcommand...), "--id", sess.ID)
	cliRes := env.RunCLI(env.Contracts().Binaries.Custodian, cliArgs, map[string]string{
		"CUSTODIAN_TOKEN": actors.HumanATok,
	})
	if cliRes.ExitCode != 0 {
		t.Fatalf("custodian push status failed (exit=%d): %s %s", cliRes.ExitCode, cliRes.Stdout, cliRes.Stderr)
	}
	if !strings.Contains(cliRes.Stdout+cliRes.Stderr, sess.ID) || !strings.Contains(cliRes.Stdout+cliRes.Stderr, "COMPLETED") {
		t.Fatalf("expected session ID and COMPLETED in push status output:\n%s\n%s", cliRes.Stdout, cliRes.Stderr)
	}

	// Zero-secret log assertion.
	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.AliceWritePAT, env.GitHub().ReadAppPrivateKeyPEM(), env.GitHub().WriteAppPrivateKeyPEM())
}

// Scenario 2: Developer SSH cert push blocked by history-smuggled IP, security-admin inspects /v1/pushes/{id},
// issues single-use push_approval_releases (SoD approved_by != principal_id), developer re-pushes once successfully,
// replay and tampered/amended push rejected.
func TestT4_PG_Scenario2_SSHHistorySmuggleAndApprovalRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t4pgPolicyDirWithRepoDefault(t, nil)),
	)
	actors := pgMintActors(env)
	t4pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	confSrc := string(t4pgReadPGFixture(t, "corpora", "confidential", "internal_billing_rules.go"))
	_ = pgSeedCorpusFiles(t, env, actors.SecAdminTok, "t4-s2-confidential", "CONFIDENTIAL", map[string]string{
		"internal_billing_rules.go": confSrc,
	})

	cred := env.SSHCA().MintValidCert("alice-s2-ed25519", []string{"alice-human-001", "alice@example.com"})
	gwHTTPSURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git"
	gwSSHURL := "ssh://git@" + env.GitGatewaySSHAddr() + "/" + repo.FullName + ".git"
	authCloneURL, err := pgInjectHTTPAuth(gwHTTPSURL, actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}

	// Create history-smuggle repo (commit 1 adds confidential billing rules; commit 2 deletes it leaving clean tip).
	workDir, _, _ := pgMakeHistorySmuggleRepo(t, authCloneURL, map[string]string{
		"billing/internal_billing_rules.go": confSrc,
	}, map[string]string{
		"pkg/clean.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, env.GitGatewayCACertPath())

	// 1. Developer SSH cert push is blocked pending IP review approval, with 0 upstream bytes.
	env.GitHub().ResetPacketCounters()
	resBlocked := pgGitPushSSH(t, workDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/feature/smuggle-review", env.SSHCA())
	if resBlocked.ExitCode == 0 {
		t.Fatalf("expected SSH history-smuggled push to be blocked pending approval")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	blockedSess, _ := t4pgWaitForPushSession(t, ctx, actors.SecAdminCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.PolicyEffect == "REQUIRE_APPROVAL"
	})
	t4pgAssertOneOfStatus(t, blockedSess.Status, "APPROVAL_REQUIRED")

	// Security admin inspects /v1/pushes/{id}.
	detail, detailRaw, err := actors.SecAdminCli.GetPush(ctx, blockedSess.ID)
	if err != nil {
		t.Fatalf("GetPush(%s): %v", blockedSess.ID, err)
	}
	detailRaw.RequireStatus(t, http.StatusOK)
	if detail.PushManifestDigest == "" || detail.Destination == "" {
		t.Fatalf("push detail missing manifest digest or destination: %+v", detail)
	}

	// SoD check: developer Alice cannot self-approve her own push even with approver groups.
	aliceApproverTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "alice-human-001",
		Name:    "Alice Developer",
		Email:   "alice@example.com",
		Groups:  []string{"engineering", "ip-review", "security-admins"},
	})
	_, selfRaw, err := env.Client(aliceApproverTok).ApprovePush(ctx, blockedSess.ID, harness.ApprovePushReq{
		Decision:           "APPROVE",
		PushManifestDigest: detail.PushManifestDigest,
		Destination:        detail.Destination,
		TTLSeconds:         300,
	})
	if err != nil {
		t.Fatalf("self ApprovePush error: %v", err)
	}
	selfRaw.RequireAnyStatus(t, http.StatusForbidden, http.StatusConflict)
	if selfRaw.Error == nil || selfRaw.Error.Code != "APPROVAL_RELEASE_SOD_VIOLATION" {
		t.Fatalf("expected APPROVAL_RELEASE_SOD_VIOLATION on self-approval, got error=%+v body=%s", selfRaw.Error, string(selfRaw.Body))
	}

	// 2. Security admin Carol issues single-use approval release bound to (principal_id, destination, push_manifest_digest).
	rel, appRaw, err := actors.SecAdminCli.ApprovePush(ctx, blockedSess.ID, harness.ApprovePushReq{
		Decision:           "APPROVE",
		PushManifestDigest: detail.PushManifestDigest,
		Destination:        detail.Destination,
		TTLSeconds:         300,
		Comment:            "Security admin approved history-smuggle exception",
	})
	if err != nil {
		t.Fatalf("SecAdmin ApprovePush: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)
	harness.AssertUUIDv7(t, rel.ID)

	// Verify DB SoD constraint (approved_by <> principal_id).
	sodRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT approved_by::text, principal_id::text, consumed_at IS NOT NULL FROM push_approval_releases WHERE id = %s::uuid;`,
		t4pgSQLQuote(rel.ID),
	))
	if err != nil || len(sodRows) != 1 || sodRows[0][0] == sodRows[0][1] || sodRows[0][2] != "f" {
		t.Fatalf("unexpected push_approval_releases row before re-push: rows=%+v err=%v", sodRows, err)
	}

	// 3. Negative check: tampered/amended push must be rejected and MUST NOT consume the approval release.
	tamperedDir := filepath.Join(t.TempDir(), "tampered-repo")
	if cpRes := pgRunHardenedGit("", nil, "clone", workDir, tamperedDir); cpRes.ExitCode != 0 {
		t.Fatalf("local clone for tamper test failed: %s", cpRes.Stderr)
	}
	pgAddCommit(t, tamperedDir, map[string]string{
		"pkg/tamper.go": "package payloads\n\nfunc Tampered() bool { return true }\n",
	}, nil, "Tampered extra commit", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	resTamper := pgGitPushSSH(t, tamperedDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/feature/smuggle-review", env.SSHCA())
	if resTamper.ExitCode == 0 {
		t.Fatalf("expected tampered/amended push with different manifest digest to be rejected")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	// 4. Developer re-pushes exact unamended branch once -> succeeds upstream!
	env.GitHub().ResetPacketCounters()
	resApproved := pgGitPushSSH(t, workDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/feature/smuggle-review", env.SSHCA())
	if resApproved.ExitCode != 0 {
		t.Fatalf("expected approved SSH re-push to succeed (exit=%d): %s", resApproved.ExitCode, resApproved.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected non-zero upstream bytes on approved SSH re-push")
	}
	consumedRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT consumed_at IS NOT NULL, consumed_by_push_session_id IS NOT NULL FROM push_approval_releases WHERE id = %s::uuid;`,
		t4pgSQLQuote(rel.ID),
	))
	if err != nil || len(consumedRows) != 1 || consumedRows[0][0] != "t" || consumedRows[0][1] != "t" {
		t.Fatalf("expected consumed approval release after re-push, got rows=%+v err=%v", consumedRows, err)
	}

	preReplayList, preReplayRaw, err := actors.SecAdminCli.ListPushes(ctx, harness.PushFilter{RepositoryID: repoID})
	if err != nil {
		t.Fatalf("ListPushes before replay: %v", err)
	}
	preReplayRaw.RequireStatus(t, http.StatusOK)
	seenBeforeReplay := make(map[string]bool, len(preReplayList.Pushes))
	for _, p := range preReplayList.Pushes {
		seenBeforeReplay[p.ID] = true
	}

	// 5. Replay after single-use consumption must be rejected with 0 upstream bytes.
	delRes := pgRunHardenedGit(repo.BarePath, nil, "update-ref", "-d", "refs/heads/feature/smuggle-review")
	if delRes.ExitCode != 0 {
		t.Fatalf("git update-ref -d failed (exit=%d): %s", delRes.ExitCode, delRes.Stderr)
	}
	env.GitHub().ResetPacketCounters()
	resReplay := pgGitPushSSH(t, workDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/feature/smuggle-review", env.SSHCA())
	if resReplay.ExitCode == 0 {
		t.Fatalf("expected replay of consumed approval release to be rejected")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	replaySess, _ := t4pgWaitForPushSession(t, ctx, actors.SecAdminCli, harness.PushFilter{
		RepositoryID: repoID,
	}, len(preReplayList.Pushes)+1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return !seenBeforeReplay[p.ID] && p.Status == "APPROVAL_REQUIRED"
	})
	if replaySess.PolicyEffect != "REQUIRE_APPROVAL" || replaySess.UpstreamForwarded {
		t.Fatalf("expected replay push session APPROVAL_REQUIRED / REQUIRE_APPROVAL with UpstreamForwarded=false, got %+v", replaySess)
	}
}

// Scenario 3: Concealment evasion (base64 + nested zip + stripped header + Winnowing) detected across L2/L3/L4,
// zero upstream bytes, audit/push_session attributed strictly to OIDC principal despite forged Git Author/Committer.
func TestT4_PG_Scenario3_ConcealmentEvasionAndForgedAuthor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t4pgPolicyDirWithRepoDefault(t, nil)),
	)
	actors := pgMintActors(env)

	restrictedSrc := string(t4pgReadPGFixture(t, "corpora", "restricted", "proprietary_engine.go"))
	_ = pgSeedCorpusFiles(t, env, actors.SecAdminTok, "t4-s3-restricted", "RESTRICTED", map[string]string{
		"proprietary_engine.go": restrictedSrc,
	})

	gwHTTPSURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git"
	workDir, cloneRes := pgGitCloneHTTP(t, gwHTTPSURL, actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}

	concealed := pgBuildConcealmentPayloads(t, []byte(restrictedSrc))
	if err := os.WriteFile(filepath.Join(workDir, "evasion_nested.zip"), t4pgReadPGFixture(t, "payloads", "concealed_nested.zip"), 0o644); err != nil {
		t.Fatalf("write concealed_nested.zip: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "evasion_disguised.png"), concealed["disguised.png"], 0o644); err != nil {
		t.Fatalf("write disguised.png: %v", err)
	}
	pgAddCommit(t, workDir, map[string]string{
		"evasion_b64.txt":     string(t4pgReadPGFixture(t, "payloads", "concealed_base64.txt")),
		"evasion_hex.txt":     string(concealed["concealed_hex.txt"]),
		"evasion_stripped.go": string(t4pgReadPGFixture(t, "payloads", "stripped_header_engine.go")),
	}, nil, "Refactor utility helpers", harness.GitIdentity{
		Name: "Forged Victim", Email: "victim-exec@acme-spoof.invalid",
	})

	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	env.GitHub().ResetPacketCounters()
	pushRes := pgGitPushHTTP(t, workDir, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/concealment-evasion", env.GitGatewayCACertPath())
	if pushRes.ExitCode == 0 {
		t.Fatalf("expected multi-layer concealment evasion push to be blocked/quarantined")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	sess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.Status == "BLOCKED" || p.Status == "QUARANTINED"
	})
	if sess.PolicyEffect != "DENY" && sess.PolicyEffect != "QUARANTINE" {
		t.Fatalf("expected DENY or QUARANTINE effect for L2/L3/L4 evasion, got %q", sess.PolicyEffect)
	}
	t4pgAssertOneOfStatus(t, sess.Status, "BLOCKED", "QUARANTINED")

	_, detail := t4pgGetPushDetail(t, ctx, actors.AuditorCli, sess.ID)
	var (
		hasL2Winnow         bool
		hasL3Strip          bool
		hasL4Conceal        bool
		strippedHasL2Winnow bool
		strippedHasL3Strip  bool
	)
	for _, f := range detail.Findings {
		normPath := filepath.ToSlash(f.Path)
		isStrippedFile := (normPath == "evasion_stripped.go" || strings.HasSuffix(normPath, "/evasion_stripped.go")) &&
			!strings.ContainsAny(normPath, "#!")
		switch {
		case f.Category == "IP_WINNOW" || f.RuleID == "ip.l2.winnow-kgram":
			hasL2Winnow = true
			if isStrippedFile && f.Category == "IP_WINNOW" && f.RuleID == "ip.l2.winnow-kgram" {
				strippedHasL2Winnow = true
			}
		case f.Category == "IP_HEADER_STRIP" || f.RuleID == "ip.l3.header-stripped":
			hasL3Strip = true
			if isStrippedFile && f.Category == "IP_HEADER_STRIP" && f.RuleID == "ip.l3.header-stripped" {
				strippedHasL3Strip = true
			}
		case f.Category == "IP_CONCEALMENT" || strings.HasPrefix(f.RuleID, "ip.l4."):
			hasL4Conceal = true
		}
	}
	if !hasL2Winnow || !hasL3Strip || !hasL4Conceal || !strippedHasL2Winnow || !strippedHasL3Strip {
		t.Fatalf("expected L2 (IP_WINNOW), L3 (IP_HEADER_STRIP), L4 (IP_CONCEALMENT), and evasion_stripped.go L2+L3 findings in GetPush(%s) (L2=%v L3=%v L4=%v strippedL2=%v strippedL3=%v), got %+v",
			sess.ID, hasL2Winnow, hasL3Strip, hasL4Conceal, strippedHasL2Winnow, strippedHasL3Strip, detail.Findings)
	}
	maType, maStatus, maDisp := t4pgQueryLatestModelAssessment(t, env, sess.ID)
	if maType != "IP_PROVENANCE" || maStatus != "COMPLETE" || maDisp != "CLEAR" {
		t.Fatalf("expected model_assessments IP_PROVENANCE COMPLETE/CLEAR, got type=%q status=%q disp=%q", maType, maStatus, maDisp)
	}

	// Verify DB attribution belongs strictly to authenticated OIDC principal alice-human-001, ignoring forged author.
	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT p.subject FROM push_sessions ps JOIN principals p ON p.id = ps.principal_id WHERE ps.id = %s::uuid;`,
		t4pgSQLQuote(sess.ID),
	))
	if err != nil || len(rows) != 1 || rows[0][0] != "alice-human-001" {
		t.Fatalf("expected OIDC principal attribution alice-human-001, got rows=%+v err=%v", rows, err)
	}
	auditResp, aRaw, err := actors.AuditorCli.ListAuditEvents(ctx, harness.AuditFilter{
		ResourceType: "push_session",
		ResourceID:   sess.ID,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	aRaw.RequireStatus(t, http.StatusOK)
	if len(auditResp.Events) == 0 {
		t.Fatalf("expected >=1 push_session audit event for %s, got 0", sess.ID)
	}
	hasAliceAudit := false
	for _, ev := range auditResp.Events {
		if strings.Contains(string(ev.Payload), "victim-exec@acme-spoof.invalid") {
			t.Fatalf("forged Git author leaked into audit attribution: %s", string(ev.Payload))
		}
		if strings.Contains(string(ev.Payload), "alice-human-001") {
			hasAliceAudit = true
		}
	}
	if !hasAliceAudit {
		t.Fatalf("expected alice-human-001 attribution in push_session audit events, got %+v", auditResp.Events)
	}

	t4pgAssertNoRawCorpusAcrossSurfaces(t, ctx, env, actors.AuditorCli, repoID, sess.ID, pushRes.Stderr,
		"ProprietaryMagicHeader", "ErrCalibrationDiverged", "TelemetryCalibrator", restrictedSrc)
}

// Scenario 4: Unregistered personal/external destination blocked by default push-ip-protection.yaml (DENY),
// negative check that REPO override cannot weaken ORG DENY or overridable: false, and ORG-customized policy
// allows clean non-IP code to approved external partner repo while still blocking unapproved external repos
// and restricted IP / secrets (overridable: false).
func TestT4_PG_Scenario4_ExternalDestinationDefaultDenyAndPolicyConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Phase A: Default ORG push-ip-protection.yaml blocks unregistered & external destinations,
	// and REPO override bundles CANNOT weaken ORG DENY or overridable: false rules.
	repoAllowExternalYAML := string(t4pgReadPGFixture(t, "policies", "push_repo_allow_external.yaml"))
	illegalRepoYAML := string(t4pgReadPGFixture(t, "policies", "push_repo_illegal_override.yaml"))
	policyDirA := t4pgPolicyDirWithRepoDefault(t, map[string]string{
		"push_repo_allow_external.yaml":   repoAllowExternalYAML,
		"push_repo_illegal_override.yaml": illegalRepoYAML,
	})
	envA, _, repoAIDA := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(policyDirA),
	)
	actorsA := pgMintActors(envA)

	unregRepoA, err := envA.Git().InitSeededRepo("alice-personal", "exfil-repo", map[string]string{
		"README.md": "# personal repo\n",
	})
	if err != nil {
		t.Fatalf("InitSeededRepo(unreg A): %v", err)
	}
	partnerRepoA, err := envA.Git().InitSeededRepo("partner", "approved-mirror", map[string]string{
		"README.md": "# partner mirror\n",
	})
	if err != nil {
		t.Fatalf("InitSeededRepo(partner A): %v", err)
	}
	partnerRepoAID := t4pgSeedRepositoryRow(t, envA, partnerRepoA, "INTERNAL", "ENFORCE_BLOCK", true, true, "partner.example.com")
	// Seed REPO-scoped bundles directly in policy_bundles bound to repository_id (SyncPolicyDir skips scope=REPO).
	t4pgSeedRepoPolicyBundleDB(t, envA, partnerRepoAID, repoAllowExternalYAML)
	t4pgSeedRepoPolicyBundleDB(t, envA, repoAIDA, illegalRepoYAML)

	// A1: Push clean code to unregistered personal repo -> DENY, 0 upstream bytes.
	gwUnregURL := strings.TrimRight(envA.GitGatewayHTTPSURL(), "/") + "/" + unregRepoA.FullName + ".git"
	unregWork, cloneUnreg := pgGitCloneHTTP(t, gwUnregURL, actorsA.HumanATok, envA.GitGatewayCACertPath())
	if cloneUnreg.ExitCode != 0 {
		t.Fatalf("clone unregRepoA failed: %s", cloneUnreg.Stderr)
	}
	pgAddCommit(t, unregWork, map[string]string{
		"clean.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, nil, "Clean commit to unregistered repo", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if res := pgGitPushHTTP(t, unregWork, gwUnregURL, actorsA.HumanATok, "HEAD:refs/heads/main", envA.GitGatewayCACertPath()); res.ExitCode == 0 {
		t.Fatalf("expected unregistered destination push to be denied")
	}
	pgAssertZeroUpstreamReceivePack(t, envA, unregRepoA.FullName)
	a1Sess, _ := t4pgWaitForPushSession(t, ctx, actorsA.AuditorCli, harness.PushFilter{}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return strings.Contains(p.Destination, unregRepoA.FullName) && p.Status == "BLOCKED"
	})
	if a1Sess.PolicyEffect != "DENY" || a1Sess.DestinationRegistered || !a1Sess.DestinationExternal {
		t.Fatalf("expected A1 BLOCKED/DENY unregistered external push_session, got %+v", a1Sess)
	}

	// A2: Push clean code to registered external partner repo -> DENY under default ORG policy (even with REPO allow bundle present).
	gwPartnerURL := strings.TrimRight(envA.GitGatewayHTTPSURL(), "/") + "/" + partnerRepoA.FullName + ".git"
	partnerWorkA, clonePartnerA := pgGitCloneHTTP(t, gwPartnerURL, actorsA.HumanATok, envA.GitGatewayCACertPath())
	if clonePartnerA.ExitCode != 0 {
		t.Fatalf("clone partnerRepoA failed: %s", clonePartnerA.Stderr)
	}
	pgAddCommit(t, partnerWorkA, map[string]string{
		"clean.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, nil, "Clean commit to external partner under default ORG DENY", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if res := pgGitPushHTTP(t, partnerWorkA, gwPartnerURL, actorsA.HumanATok, "HEAD:refs/heads/main", envA.GitGatewayCACertPath()); res.ExitCode == 0 {
		t.Fatalf("expected external destination push to remain DENY when REPO cannot weaken ORG DENY")
	}
	pgAssertZeroUpstreamReceivePack(t, envA, partnerRepoA.FullName)
	a2Sess, _ := t4pgWaitForPushSession(t, ctx, actorsA.AuditorCli, harness.PushFilter{
		RepositoryID: partnerRepoAID,
	}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.Status == "BLOCKED"
	})
	if a2Sess.PolicyEffect != "DENY" || !a2Sess.DestinationRegistered || !a2Sess.DestinationExternal {
		t.Fatalf("expected A2 BLOCKED/DENY registered external push_session, got %+v", a2Sess)
	}

	// A3: Verify via EvaluatePolicy API that REPO illegal override cannot weaken overridable: false push.ip.restricted.block.
	orgYAML := string(t4pgReadRepoFixture(t, "policies", "defaults", "push-ip-protection.yaml"))
	evalDec, evalRaw, evalErr := actorsA.PolicyAdminCli.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		OrgBundleYAML: orgYAML,
		BundleYAML:    illegalRepoYAML,
		Stage:         "PUSH_EGRESS",
		Input: map[string]any{
			"findings": map[string]any{
				"scan_complete":               true,
				"mandatory_scanners_complete": true,
				"restricted_ip_matches":       1,
			},
			"destination": map[string]any{
				"registered": true,
				"external":   false,
				"name":       "acme/service",
			},
			"assessment": map[string]any{
				"status":      "NOT_REQUIRED",
				"disposition": "NOT_REQUIRED",
			},
		},
	})
	if evalErr != nil {
		t.Fatalf("EvaluatePolicy(PUSH_EGRESS illegal override): %v", evalErr)
	}
	evalRaw.RequireStatus(t, http.StatusOK)
	if evalDec.Effect != "DENY" {
		t.Fatalf("expected REPO override of overridable:false restricted IP rule to remain DENY, got %q", evalDec.Effect)
	}

	// Phase B: ORG-customized policy permitting ONLY partner/approved-mirror while keeping unapproved external DENY
	// and restricted IP / secrets overridable: false DENY.
	partnerOrgDir := t4pgCustomizeOrgBundleForPartner(t, "partner/approved-mirror")
	envB, _, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(partnerOrgDir),
	)
	actorsB := pgMintActors(envB)

	restrictedSrc := string(t4pgReadPGFixture(t, "corpora", "restricted", "proprietary_engine.go"))
	_ = pgSeedCorpusFiles(t, envB, actorsB.SecAdminTok, "t4-s4-restricted", "RESTRICTED", map[string]string{
		"proprietary_engine.go": restrictedSrc,
	})

	partnerRepoB, err := envB.Git().InitSeededRepo("partner", "approved-mirror", map[string]string{
		"README.md": "# approved partner mirror\n",
	})
	if err != nil {
		t.Fatalf("InitSeededRepo(partner B): %v", err)
	}
	partnerRepoBID := t4pgSeedRepositoryRow(t, envB, partnerRepoB, "INTERNAL", "ENFORCE_BLOCK", true, true, "partner.example.com")

	unapprovedExternalB, err := envB.Git().InitSeededRepo("evil", "exfil-repo", map[string]string{
		"README.md": "# unapproved external\n",
	})
	if err != nil {
		t.Fatalf("InitSeededRepo(evil B): %v", err)
	}

	// B1: Clean non-IP push to approved partner/approved-mirror -> ALLOW, forwarded upstream.
	gwPartnerBURL := strings.TrimRight(envB.GitGatewayHTTPSURL(), "/") + "/" + partnerRepoB.FullName + ".git"
	partnerWorkB, clonePartnerB := pgGitCloneHTTP(t, gwPartnerBURL, actorsB.HumanATok, envB.GitGatewayCACertPath())
	if clonePartnerB.ExitCode != 0 {
		t.Fatalf("clone partnerRepoB failed: %s", clonePartnerB.Stderr)
	}
	pgAddCommit(t, partnerWorkB, map[string]string{
		"pkg/clean.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, nil, "Clean code to approved external partner", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if res := pgGitPushHTTP(t, partnerWorkB, gwPartnerBURL, actorsB.HumanATok, "HEAD:refs/heads/partner-clean", envB.GitGatewayCACertPath()); res.ExitCode != 0 {
		t.Fatalf("expected clean push to approved partner mirror to succeed: %s", res.Stderr)
	}
	if envB.GitHub().ReceivePackBytes(partnerRepoB.FullName) == 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0 for approved partner mirror")
	}

	// B2: Clean push to unapproved external repo evil/exfil-repo -> still DENY, 0 upstream bytes.
	gwEvilURL := strings.TrimRight(envB.GitGatewayHTTPSURL(), "/") + "/" + unapprovedExternalB.FullName + ".git"
	evilWork, cloneEvil := pgGitCloneHTTP(t, gwEvilURL, actorsB.HumanATok, envB.GitGatewayCACertPath())
	if cloneEvil.ExitCode != 0 {
		t.Fatalf("clone evil/exfil-repo failed: %s", cloneEvil.Stderr)
	}
	pgAddCommit(t, evilWork, map[string]string{
		"pkg/clean.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, nil, "Exfiltrate to unapproved external repo", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if res := pgGitPushHTTP(t, evilWork, gwEvilURL, actorsB.HumanATok, "HEAD:refs/heads/main", envB.GitGatewayCACertPath()); res.ExitCode == 0 {
		t.Fatalf("expected unapproved external repo push to be denied")
	}
	pgAssertZeroUpstreamReceivePack(t, envB, unapprovedExternalB.FullName)
	b2Sess, _ := t4pgWaitForPushSession(t, ctx, actorsB.AuditorCli, harness.PushFilter{}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return strings.Contains(p.Destination, unapprovedExternalB.FullName) && p.Status == "BLOCKED"
	})
	if b2Sess.PolicyEffect != "DENY" || b2Sess.DestinationRegistered || !b2Sess.DestinationExternal {
		t.Fatalf("expected B2 BLOCKED/DENY unapproved external push_session, got %+v", b2Sess)
	}

	// B3: Restricted IP push to approved partner/approved-mirror -> still DENY (overridable: false), 0 upstream bytes.
	envB.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	envB.GitHub().ResetPacketCounters()
	pgAddCommit(t, partnerWorkB, map[string]string{
		"internal/proprietary_engine.go": restrictedSrc,
	}, nil, "Attempt restricted IP push to approved partner mirror", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if res := pgGitPushHTTP(t, partnerWorkB, gwPartnerBURL, actorsB.HumanATok, "HEAD:refs/heads/partner-ip-leak", envB.GitGatewayCACertPath()); res.ExitCode == 0 {
		t.Fatalf("expected restricted IP push to approved partner mirror to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, envB, partnerRepoB.FullName)
	b3Sess, _ := t4pgWaitForPushSession(t, ctx, actorsB.AuditorCli, harness.PushFilter{
		RepositoryID: partnerRepoBID,
	}, 2, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.Status == "BLOCKED"
	})
	if b3Sess.PolicyEffect != "DENY" || b3Sess.UpstreamForwarded {
		t.Fatalf("expected B3 BLOCKED/DENY with UpstreamForwarded=false, got %+v", b3Sess)
	}
	b3Type, b3Status, b3Disp := t4pgQueryLatestModelAssessment(t, envB, b3Sess.ID)
	if b3Type != "IP_PROVENANCE" || b3Status != "COMPLETE" || b3Disp != "CLEAR" {
		t.Fatalf("expected B3 model_assessments IP_PROVENANCE COMPLETE/CLEAR, got type=%q status=%q disp=%q", b3Type, b3Status, b3Disp)
	}
}

// Scenario 5: PASSIVE_AUDIT (INLINE_WARN & ASYNC) rollout -> OBSERVED_WOULD_BLOCK (enforced=false) ->
// custodian-publisher cannot publish from PUSH_EGRESS/enforced=false -> inspect custodian push status & /metrics ->
// promote repo to ENFORCE_BLOCK via PUT /v1/repositories/{id}/egress-mode -> subsequent push blocked with 0 upstream bytes.
func TestT4_PG_Scenario5_PassiveAuditRolloutAndEnforcePromotion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	env, repo, repoID := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT",
		harness.WithPolicyBundleDir(t4pgPolicyDirWithRepoDefault(t, nil)),
		harness.WithGitGateway(harness.WithGitGatewayPassiveDelivery("INLINE_WARN")),
	)
	actors := pgMintActors(env)
	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")

	// 1. INLINE_WARN rollout push with secret -> forwarded upstream with warning, OBSERVED_WOULD_BLOCK (enforced=false).
	_, modeRaw1, err := actors.PolicyAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "INLINE_WARN",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode(INLINE_WARN): %v", err)
	}
	modeRaw1.RequireAnyStatus(t, http.StatusOK, http.StatusAccepted)

	gwHTTPSURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git"
	workDir, cloneRes := pgGitCloneHTTP(t, gwHTTPSURL, actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}

	secretEnv := string(t4pgReadRepoFixture(t, "test", "e2e", "fixtures", "payloads", "synthetic_aws_secret.env"))
	pgAddCommit(t, workDir, map[string]string{
		"config/warn.env": secretEnv,
	}, nil, "Rollout commit under PASSIVE_AUDIT INLINE_WARN", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	warnPush := pgGitPushHTTP(t, workDir, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/rollout-warn", env.GitGatewayCACertPath())
	if warnPush.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT INLINE_WARN push failed: %s", warnPush.Stderr)
	}
	if !strings.Contains(warnPush.Stderr, "remote:") {
		t.Fatalf("expected sideband channel-2 'remote:' INLINE_WARN warning in git stderr, got:\n%s", warnPush.Stderr)
	}
	warnLower := strings.ToLower(warnPush.Stderr)
	if !strings.Contains(warnLower, "warn") && !strings.Contains(warnLower, "would") && !strings.Contains(warnLower, "passive") && !strings.Contains(warnLower, "custodian") && !strings.Contains(warnLower, "policy") {
		t.Fatalf("expected INLINE_WARN warning indicator in sideband stderr, got:\n%s", warnPush.Stderr)
	}
	harness.AssertNoSecretOrEncodedLeak(t, warnPush.Stderr, "AKIAIOSFODNN7EXAMPLE", "custodian_e2e_dummy_secret_value_0123456789abcdef")

	warnSess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.Status == "OBSERVED_WOULD_BLOCK"
	})
	wType, wStatus, wDisp := t4pgQueryLatestModelAssessment(t, env, warnSess.ID)
	if wType != "IP_PROVENANCE" || wStatus != "COMPLETE" || wDisp != "CLEAR" {
		t.Fatalf("expected warnSess model_assessments IP_PROVENANCE COMPLETE/CLEAR, got type=%q status=%q disp=%q", wType, wStatus, wDisp)
	}

	// 2. Switch delivery to ASYNC and push another policy-triggering commit.
	_, modeRaw2, err := actors.PolicyAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "ASYNC",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode(ASYNC): %v", err)
	}
	modeRaw2.RequireAnyStatus(t, http.StatusOK, http.StatusAccepted)

	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	env.GitHub().ResetPacketCounters()
	pgAddCommit(t, workDir, map[string]string{
		"config/async.pem": string(t4pgReadRepoFixture(t, "test", "e2e", "fixtures", "payloads", "synthetic_private_key.pem")),
	}, nil, "Rollout commit under PASSIVE_AUDIT ASYNC", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	asyncPush := pgGitPushHTTP(t, workDir, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/rollout-async", env.GitGatewayCACertPath())
	if asyncPush.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT ASYNC push failed: %s", asyncPush.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected non-zero upstream ReceivePackBytes under PASSIVE_AUDIT ASYNC")
	}
	if strings.Contains(asyncPush.Stderr, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("did not expect INLINE_WARN warning in ASYNC passive audit stderr, got:\n%s", asyncPush.Stderr)
	}

	asyncSess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 2, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.ID != warnSess.ID && p.Status == "OBSERVED_WOULD_BLOCK"
	})
	aType, aStatus, aDisp := t4pgQueryLatestModelAssessment(t, env, asyncSess.ID)
	if aType != "IP_PROVENANCE" || aStatus != "COMPLETE" || aDisp != "CLEAR" {
		t.Fatalf("expected asyncSess model_assessments IP_PROVENANCE COMPLETE/CLEAR, got type=%q status=%q disp=%q", aType, aStatus, aDisp)
	}

	// Verify DB policy_decisions rows for passive audit have enforced=false and stage='PUSH_EGRESS'.
	decRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT stage, enforced::text FROM policy_decisions WHERE push_session_id IN (%s::uuid, %s::uuid);`,
		t4pgSQLQuote(warnSess.ID), t4pgSQLQuote(asyncSess.ID),
	))
	if err != nil || len(decRows) < 2 {
		t.Fatalf("expected >=2 PUSH_EGRESS policy_decisions rows, got %+v err=%v", decRows, err)
	}
	for _, r := range decRows {
		if r[0] != "PUSH_EGRESS" || r[1] != "false" {
			t.Fatalf("expected stage=PUSH_EGRESS and enforced=false, got %+v", r)
		}
	}

	// Verify custodian-publisher cannot publish when decision is unenforced (enforced=false).
	wsCreated, wsRaw, err := actors.HumanACli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: repo.DefaultBranch},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusAccepted)
	wsID := t4pgFirstNonEmpty(wsCreated.WorkspaceID, wsCreated.ID)
	if wsCreated.OperationID != "" {
		if _, err := actors.HumanACli.WaitForOperation(ctx, wsCreated.OperationID, 30*time.Second); err != nil {
			t.Fatalf("WaitForOperation(ws): %v", err)
		}
	}
	ws, wsGetRaw, err := actors.HumanACli.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace(%s): %v", wsID, err)
	}
	wsGetRaw.RequireStatus(t, http.StatusOK)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "pkg/clean.go", Body: t4pgReadPGFixture(t, "payloads", "clean_feature.go")},
	})
	capResp, capRaw, err := actors.CtrlCli.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{
		Generation: ws.Generation, MaxBytes: int64(len(gz)) + 4096,
	})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	upRaw, err := actors.CtrlCli.UploadSnapshot(ctx, capResp.UploadURL, t4pgFirstNonEmpty(capResp.Token, capResp.CapabilityToken), gz)
	if err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusNoContent)
	var upParsed t4pgUploadResp
	if len(upRaw.Body) > 0 {
		_ = json.Unmarshal(upRaw.Body, &upParsed)
	}
	artID := t4pgFirstNonEmpty(upParsed.ArtifactID, upParsed.ID, upRaw.Headers.Get("X-Artifact-ID"))
	if artID == "" {
		t.Fatalf("UploadSnapshot returned empty artifact ID (body=%s)", string(upRaw.Body))
	}
	sub, subRaw, err := actors.CtrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID: artID, SHA256: shaHex, WorkspaceGeneration: ws.Generation, SizeBytes: int64(len(gz)),
			CapturedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Title: "Publisher unenforced guard check",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated)
	propID := t4pgFirstNonEmpty(sub.ProposalID, sub.ID)
	if propID == "" {
		t.Fatalf("SubmitProposal returned empty proposal ID: %+v", sub)
	}
	if sub.OperationID != "" {
		if _, err := actors.CtrlCli.WaitForOperation(ctx, sub.OperationID, 30*time.Second); err != nil {
			t.Fatalf("WaitForOperation(submit %s): %v", sub.OperationID, err)
		}
	}
	var prop harness.ProposalResp
	t4pgWaitUntil(t, ctx, 20*time.Second, func() (bool, error) {
		p, pRaw, e := actors.CtrlCli.GetProposal(ctx, propID)
		if e != nil {
			return false, e
		}
		if pRaw.StatusCode != http.StatusOK {
			return false, fmt.Errorf("GetProposal(%s) HTTP %d: %s", propID, pRaw.StatusCode, string(pRaw.Body))
		}
		prop = p
		return p.Status == "RECONSTRUCTED", nil
	})
	// Restore MockGateway default SECURITY_REVIEW mode strictly for v1.0 EvaluateProposal.
	env.Gateway().SetMode(harness.GatewayModeClean)
	evalResp, evalRaw, err := actors.CtrlCli.EvaluateProposal(ctx, propID, harness.EvaluateReq{ExpectedVersion: prop.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal: %v", err)
	}
	evalRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if evalResp.OperationID != "" {
		if _, err := actors.CtrlCli.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second); err != nil {
			t.Fatalf("WaitForOperation(eval %s): %v", evalResp.OperationID, err)
		}
	}
	evalProp, evalPropRaw, err := actors.CtrlCli.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal(evaluated %s): %v", propID, err)
	}
	evalPropRaw.RequireStatus(t, http.StatusOK)
	assess, assessRaw, err := actors.CtrlCli.ListProposalAssessments(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalAssessments(%s): %v", propID, err)
	}
	assessRaw.RequireStatus(t, http.StatusOK)
	if len(assess.PolicyDecisions) == 0 {
		t.Fatalf("ListProposalAssessments(%s) returned 0 policy decisions", propID)
	}
	latestPD := assess.PolicyDecisions[len(assess.PolicyDecisions)-1]
	_, appRaw, err := actors.SecAdminCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        latestPD.ID,
		Comment:                   "Approve before unenforced flip",
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)
	if _, err := env.DB().ExecSQL(fmt.Sprintf(`UPDATE policy_decisions SET enforced = false WHERE id = %s::uuid;`, t4pgSQLQuote(latestPD.ID))); err != nil {
		t.Fatalf("set enforced=false: %v", err)
	}
	pubResp, pubRaw, err := actors.CtrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	if pubRaw.StatusCode != http.StatusForbidden && pubRaw.StatusCode != http.StatusConflict {
		pubRaw.RequireStatus(t, http.StatusAccepted)
		if pubResp.OperationID == "" {
			t.Fatalf("expected non-empty OperationID on 202 Accepted PublishProposal response, got %+v", pubResp)
		}
		op, waitErr := actors.CtrlCli.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		if waitErr != nil {
			t.Fatalf("WaitForOperation(%s): %v", pubResp.OperationID, waitErr)
		}
		if op.Status != "FAILED" {
			t.Fatalf("expected async publish operation %s to reach FAILED when policy_decision.enforced=false, got status=%q last_error=%q", pubResp.OperationID, op.Status, op.LastError)
		}
		if !strings.Contains(op.LastError, "UNENFORCED_POLICY_DECISION") {
			t.Fatalf("expected UNENFORCED_POLICY_DECISION in failed operation last_error, got %q", op.LastError)
		}
	}
	pubRows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT count(*) FROM publications WHERE proposal_id = %s::uuid AND status IN ('PUBLISHED', 'SUCCEEDED');`,
		t4pgSQLQuote(propID),
	))
	if err != nil {
		t.Fatalf("query publications: %v", err)
	}
	if len(pubRows) == 0 || pubRows[0][0] != "0" {
		t.Fatalf("expected 0 PUBLISHED/SUCCEEDED publications when policy_decision.enforced=false, got %+v", pubRows)
	}
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs from unenforced decision, got %d", env.GitHub().PRCount(repo.FullName))
	}

	// 3. Inspect via `custodian push status` CLI and Prometheus `/metrics`.
	cliArgs := append(append([]string{}, env.Contracts().CLI.PushStatusSubcommand...), "--id", asyncSess.ID)
	cliRes := env.RunCLI(env.Contracts().Binaries.Custodian, cliArgs, map[string]string{
		"CUSTODIAN_TOKEN": actors.AuditorTok,
	})
	if cliRes.ExitCode != 0 || !strings.Contains(cliRes.Stdout+cliRes.Stderr, "OBSERVED_WOULD_BLOCK") {
		t.Fatalf("custodian push status failed or missing OBSERVED_WOULD_BLOCK: exit=%d out=%s err=%s", cliRes.ExitCode, cliRes.Stdout, cliRes.Stderr)
	}
	metricsText := t4pgScrapeGatewayMetrics(t, ctx, env)
	if ok, sum := t4pgMetricSumForName(metricsText, "custodian_push_passive_audit_would_block_total"); !ok || sum < 2 {
		t.Fatalf("expected custodian_push_passive_audit_would_block_total >= 2, got found=%v sum=%v", ok, sum)
	}

	// 4. Promote repo to ENFORCE_BLOCK via PUT /v1/repositories/{id}/egress-mode and verify subsequent push blocked with 0 bytes.
	promResp, promRaw, err := actors.PolicyAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode: "ENFORCE_BLOCK",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode(ENFORCE_BLOCK): %v", err)
	}
	promRaw.RequireAnyStatus(t, http.StatusOK, http.StatusAccepted)
	if promResp.EgressMode != "ENFORCE_BLOCK" {
		t.Fatalf("expected ENFORCE_BLOCK after promotion, got %q", promResp.EgressMode)
	}

	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	env.GitHub().ResetPacketCounters()
	pgAddCommit(t, workDir, map[string]string{
		"config/blocked.env": secretEnv,
	}, nil, "Commit after ENFORCE_BLOCK promotion", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	enforcedPush := pgGitPushHTTP(t, workDir, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/rollout-enforced", env.GitGatewayCACertPath())
	if enforcedPush.ExitCode == 0 {
		t.Fatalf("expected push after ENFORCE_BLOCK promotion to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	enforcedSess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 3, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.ID != warnSess.ID && p.ID != asyncSess.ID && p.Status == "BLOCKED"
	})
	if enforcedSess.PolicyEffect != "DENY" || enforcedSess.UpstreamForwarded {
		t.Fatalf("expected BLOCKED/DENY push session after ENFORCE_BLOCK promotion, got %+v", enforcedSess)
	}
	eType, eStatus, eDisp := t4pgQueryLatestModelAssessment(t, env, enforcedSess.ID)
	if eType != "IP_PROVENANCE" || eStatus != "COMPLETE" || eDisp != "CLEAR" {
		t.Fatalf("expected enforcedSess model_assessments IP_PROVENANCE COMPLETE/CLEAR, got type=%q status=%q disp=%q", eType, eStatus, eDisp)
	}
	env.AssertNoSecretLeakInLogs(
		actors.HumanATok,
		actors.SecAdminTok,
		actors.AuditorTok,
		actors.PolicyAdminTok,
		actors.AliceWritePAT,
		actors.BobReadPAT,
		"AKIAIOSFODNN7EXAMPLE",
		"custodian_e2e_dummy_secret_value_0123456789abcdef",
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	)
}

// Scenario 6: Git LFS large-asset push over SSH user-cert with push.has_lfs CEL enforcement (push_lfs_gate.yaml),
// brokered scoped token + ExtraSecrets redaction, and zero-secret log/finding/prompt verification.
func TestT4_PG_Scenario6_GitLFSSSHBrokeredTokenAndZeroSecretLogs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	lfsPolicy := string(t4pgReadPGFixture(t, "policies", "push_lfs_gate.yaml"))
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t4pgPolicyDirWithRepoDefault(t, map[string]string{
			"push_lfs_gate.yaml": lfsPolicy,
		})),
	)
	t4pgSeedRepoPolicyBundleDB(t, env, repoID, lfsPolicy)
	actors := pgMintActors(env)
	t4pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	cred := env.SSHCA().MintValidCert("alice-lfs-s6", []string{"alice-human-001", "alice@example.com"})
	gwSSHURL := "ssh://git@" + env.GitGatewaySSHAddr() + "/" + repo.FullName + ".git"

	// 1. Upload bounded LFS asset (<= 1 MiB) via LFS batch + PUT, push LFS pointer over SSH -> ALLOW via brokered token.
	smallData := make([]byte, 4096)
	for i := range smallData {
		smallData[i] = byte('A' + (i % 26))
	}
	smallOID, batchStatus, putStatus := t4pgLFSUploadViaGateway(t, ctx, env, repo.FullName, actors.HumanATok, smallData)
	if batchStatus != http.StatusOK || (putStatus != http.StatusOK && putStatus != http.StatusCreated) {
		t.Fatalf("bounded LFS upload failed: batch=%d put=%d", batchStatus, putStatus)
	}

	workDir, cloneRes := pgGitCloneSSH(t, gwSSHURL, cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("SSH clone failed: %s", cloneRes.Stderr)
	}
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}
	pgAddCommit(t, workDir, map[string]string{
		".gitattributes":    "*.dat filter=lfs diff=lfs merge=lfs -text\n",
		"weights/small.dat": fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", smallOID, len(smallData)),
	}, nil, "Add bounded LFS dataset", author)

	resSmall := pgGitPushSSH(t, workDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/lfs-small", env.SSHCA())
	if resSmall.ExitCode != 0 {
		t.Fatalf("bounded LFS SSH push failed: %s", resSmall.Stderr)
	}

	// Verify brokered upstream token used on MockGitHub (never user OIDC JWT).
	calls := env.GitHub().ReceivePackCalls()
	if len(calls) == 0 {
		t.Fatalf("expected non-zero upstream ReceivePackCalls after bounded LFS SSH push")
	}
	var brokeredTokens []string
	for _, c := range calls {
		if c.Token == "" || c.Token == actors.HumanATok {
			t.Fatalf("expected brokered upstream token, got %q", c.Token)
		}
		brokeredTokens = append(brokeredTokens, c.Token)
	}

	// 2. Large LFS asset (> 1 MiB) triggers push.lfs.oversize_approval -> REQUIRE_APPROVAL, 0 upstream receive-pack.
	env.GitHub().ResetPacketCounters()
	largeSize := int64(2 * 1024 * 1024)
	largeSum := sha256.Sum256([]byte("large-model-checkpoint-v1"))
	largeOID := hex.EncodeToString(largeSum[:])
	pgAddCommit(t, workDir, map[string]string{
		"weights/model.dat": fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", largeOID, largeSize),
	}, nil, "Add large >1MiB LFS model checkpoint", author)

	resLarge := pgGitPushSSH(t, workDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/lfs-large", env.SSHCA())
	if resLarge.ExitCode == 0 {
		t.Fatalf("expected >1MiB LFS push to require approval")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	largeSess, _ := t4pgWaitForPushSession(t, ctx, actors.SecAdminCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 2, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.HasLFS && p.LFSTotalBytes >= largeSize && p.PolicyEffect == "REQUIRE_APPROVAL"
	})

	// Admin approves large LFS push -> re-push succeeds.
	_, appRaw, err := actors.SecAdminCli.ApprovePush(ctx, largeSess.ID, harness.ApprovePushReq{
		Decision:           "APPROVE",
		PushManifestDigest: largeSess.PushManifestDigest,
		Destination:        largeSess.Destination,
		TTLSeconds:         300,
		Comment:            "Approved large LFS dataset",
	})
	if err != nil {
		t.Fatalf("ApprovePush(large LFS): %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)

	env.GitHub().ResetPacketCounters()
	resLargeApproved := pgGitPushSSH(t, workDir, gwSSHURL, cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/lfs-large", env.SSHCA())
	if resLargeApproved.ExitCode != 0 {
		t.Fatalf("expected approved large LFS SSH re-push to succeed: %s", resLargeApproved.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected non-zero upstream bytes after large LFS approval")
	}
	for _, c := range env.GitHub().ReceivePackCalls() {
		if c.Token != "" {
			brokeredTokens = append(brokeredTokens, c.Token)
		}
	}

	// Zero-secret log, prompt, and API response checks (including minted brokered tokens).
	logSecrets := append([]string{
		actors.HumanATok,
		actors.SecAdminTok,
		actors.AliceWritePAT,
		actors.BobReadPAT,
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	}, brokeredTokens...)
	env.AssertNoSecretLeakInLogs(logSecrets...)
	promptSecrets := append([]string{
		actors.HumanATok,
		actors.AliceWritePAT,
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	}, brokeredTokens...)
	env.Gateway().AssertNoSecretInPrompts(t, promptSecrets...)
	_, listRaw, err := actors.AuditorCli.ListPushes(ctx, harness.PushFilter{RepositoryID: repoID})
	if err != nil {
		t.Fatalf("ListPushes: %v", err)
	}
	listRaw.RequireStatus(t, http.StatusOK)
	harness.AssertNoSecretOrEncodedLeak(t, string(listRaw.Body), actors.HumanATok, actors.AliceWritePAT, actors.BobReadPAT)
}

// Scenario 7: Register RESTRICTED IP corpus via /v1/ip-corpora, trigger /v1/ip-corpora/{id}/reindex,
// verify zero raw restricted source exposure across logs/HTTP/stderr/DB (ip_fingerprints), verify Stage B/scanner
// outage fails closed in ENFORCE_BLOCK with zero upstream bytes, and verify recovery after outage clears.
func TestT4_PG_Scenario7_CorpusLifecycleReindexAndOutageResilience(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(t4pgPolicyDirWithRepoDefault(t, nil)),
	)
	actors := pgMintActors(env)

	// 1. Register RESTRICTED corpus (1 file) then trigger non-no-op /v1/ip-corpora/{id}/reindex with 2 files.
	restrictedGo := string(t4pgReadPGFixture(t, "corpora", "restricted", "proprietary_engine.go"))
	restrictedPy := string(t4pgReadPGFixture(t, "corpora", "restricted", "proprietary_header.py"))
	goSum := sha256.Sum256([]byte(restrictedGo))
	pySum := sha256.Sum256([]byte(restrictedPy))
	corpResp, createRaw, err := actors.SecAdminCli.CreateIPCorpus(ctx, harness.CreateIPCorpusReq{
		Name:           "t4-s7-restricted-ip",
		Classification: "RESTRICTED",
		Files: []harness.IPCorpusFileInput{
			{Path: "proprietary_engine.go", Content: restrictedGo, SHA256: hex.EncodeToString(goSum[:])},
		},
	})
	if err != nil {
		t.Fatalf("CreateIPCorpus: %v", err)
	}
	createRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	harness.AssertUUIDv7(t, corpResp.ID)
	if corpResp.FingerprintCount <= 0 {
		t.Fatalf("expected initial CreateIPCorpus FingerprintCount > 0, got %d", corpResp.FingerprintCount)
	}
	corpusID := corpResp.ID

	reindexBody, err := json.Marshal(struct {
		Force bool                        `json:"force"`
		Files []harness.IPCorpusFileInput `json:"files"`
	}{
		Force: true,
		Files: []harness.IPCorpusFileInput{
			{Path: "proprietary_engine.go", Content: restrictedGo, SHA256: hex.EncodeToString(goSum[:])},
			{Path: "proprietary_header.py", Content: restrictedPy, SHA256: hex.EncodeToString(pySum[:])},
		},
	})
	if err != nil {
		t.Fatalf("marshal reindex payload: %v", err)
	}
	reindexRaw, err := actors.SecAdminCli.DoRaw(ctx, http.MethodPost, "/v1/ip-corpora/"+corpusID+"/reindex", reindexBody)
	if err != nil {
		t.Fatalf("POST /v1/ip-corpora/%s/reindex: %v", corpusID, err)
	}
	reindexRaw.RequireAnyStatus(t, http.StatusOK, http.StatusAccepted)
	var reindexResp harness.ReindexIPCorpusResp
	if err := json.Unmarshal(reindexRaw.Body, &reindexResp); err != nil {
		t.Fatalf("decode ReindexIPCorpusResp: %v (body=%s)", err, string(reindexRaw.Body))
	}
	if reindexResp.OperationID != "" {
		op, opErr := actors.SecAdminCli.WaitForOperation(ctx, reindexResp.OperationID, 30*time.Second)
		if opErr != nil {
			t.Fatalf("WaitForOperation(reindex %s): %v", reindexResp.OperationID, opErr)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("reindex operation %s ended in status %q (err=%q)", op.ID, op.Status, op.LastError)
		}
	}
	if reindexResp.FilesProcessed != 2 || reindexResp.FingerprintsIndexed <= corpResp.FingerprintCount {
		t.Fatalf("expected non-no-op reindex with FilesProcessed=2 and FingerprintsIndexed > %d, got %+v", corpResp.FingerprintCount, reindexResp)
	}

	corpora, listCorpRaw, err := actors.AuditorCli.ListIPCorpora(ctx, harness.IPCorpusFilter{Classification: "RESTRICTED"})
	if err != nil {
		t.Fatalf("ListIPCorpora: %v", err)
	}
	listCorpRaw.RequireStatus(t, http.StatusOK)
	var matched bool
	for _, c := range corpora.Corpora {
		if c.ID == corpusID && c.FingerprintCount == reindexResp.FingerprintsIndexed {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected corpus %s with updated FingerprintCount=%d in %+v", corpusID, reindexResp.FingerprintsIndexed, corpora.Corpora)
	}

	gwHTTPSURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git"
	workDir, cloneRes := pgGitCloneHTTP(t, gwHTTPSURL, actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}

	// 2. Push matching RESTRICTED IP -> blocked with 0 upstream bytes & 0 raw source exposure.
	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	pgAddCommit(t, workDir, map[string]string{
		"engine/copy.go": restrictedGo,
	}, nil, "Push restricted corpus code", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	resIP := pgGitPushHTTP(t, workDir, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/s7-restricted", env.GitGatewayCACertPath())
	if resIP.ExitCode == 0 {
		t.Fatalf("expected RESTRICTED IP push to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	ipSess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, 1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return p.PolicyEffect == "DENY"
	})
	ipType, ipStatus, ipDisp := t4pgQueryLatestModelAssessment(t, env, ipSess.ID)
	if ipType != "IP_PROVENANCE" || ipStatus != "COMPLETE" || ipDisp != "CLEAR" {
		t.Fatalf("expected Step 2 model_assessments IP_PROVENANCE COMPLETE/CLEAR, got type=%q status=%q disp=%q", ipType, ipStatus, ipDisp)
	}
	t4pgAssertNoRawCorpusAcrossSurfaces(t, ctx, env, actors.AuditorCli, repoID, ipSess.ID, resIP.Stderr,
		"ProprietaryMagicHeader", "ErrCalibrationDiverged", "TelemetryCalibrator", "ACME_SETTLEMENT_WEIGHTS",
		restrictedGo, restrictedPy)

	// 3. Stage B 503 outage & timeout on clean branch in RESTRICTED repo -> fail-closed with 0 upstream bytes.
	if _, err := env.DB().ExecSQL(fmt.Sprintf(`UPDATE repositories SET classification = 'RESTRICTED' WHERE id = %s::uuid;`, t4pgSQLQuote(repoID))); err != nil {
		t.Fatalf("update repo classification=RESTRICTED: %v", err)
	}
	cleanWork, cloneClean := pgGitCloneHTTP(t, gwHTTPSURL, actors.HumanATok, env.GitGatewayCACertPath())
	if cloneClean.ExitCode != 0 {
		t.Fatalf("clean clone failed: %s", cloneClean.Stderr)
	}
	pgAddCommit(t, cleanWork, map[string]string{
		"pkg/feature.go": string(t4pgReadPGFixture(t, "payloads", "clean_feature.go")),
	}, nil, "Clean commit during outages", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeOutage503, "IP_PROVENANCE")
	env.GitHub().ResetPacketCounters()
	resStageBOutage := pgGitPushHTTP(t, cleanWork, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/s7-stageb-outage", env.GitGatewayCACertPath())
	if resStageBOutage.ExitCode == 0 {
		t.Fatalf("expected Stage B 503 outage in ENFORCE_BLOCK to fail closed")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	env.Gateway().SetDefault(harness.GatewayProgram{
		Mode:           harness.GatewayModeTimeout,
		AssessmentType: "IP_PROVENANCE",
		Delay:          17 * time.Second,
	})
	env.GitHub().ResetPacketCounters()
	resStageBTimeout := pgGitPushHTTP(t, cleanWork, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/s7-stageb-timeout", env.GitGatewayCACertPath())
	if resStageBTimeout.ExitCode == 0 {
		t.Fatalf("expected Stage B timeout outage in ENFORCE_BLOCK to fail closed")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	// 4. Scanner crash outage -> fail-closed strictly from incomplete scan (zero ASSESSMENT_TYPE_MISMATCH confounding).
	preScanList, preScanRaw, err := actors.AuditorCli.ListPushes(ctx, harness.PushFilter{RepositoryID: repoID})
	if err != nil {
		t.Fatalf("ListPushes before scanner outage: %v", err)
	}
	preScanRaw.RequireStatus(t, http.StatusOK)
	seenBeforeScanOutage := make(map[string]bool, len(preScanList.Pushes))
	for _, p := range preScanList.Pushes {
		seenBeforeScanOutage[p.ID] = true
	}

	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{Mode: harness.ScannerModeCrash, ExitCode: 2})
	env.GitHub().ResetPacketCounters()
	resScannerOutage := pgGitPushHTTP(t, cleanWork, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/s7-scanner-outage", env.GitGatewayCACertPath())
	if resScannerOutage.ExitCode == 0 {
		t.Fatalf("expected scanner crash outage in ENFORCE_BLOCK to fail closed")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	scanOutageSess, _ := t4pgWaitForPushSession(t, ctx, actors.AuditorCli, harness.PushFilter{
		RepositoryID: repoID,
	}, len(preScanList.Pushes)+1, 20*time.Second, func(p harness.PushSessionResp) bool {
		return !seenBeforeScanOutage[p.ID] && (p.Status == "QUARANTINED" || p.Status == "BLOCKED")
	})
	s4Type, s4Status, s4Disp := t4pgQueryLatestModelAssessment(t, env, scanOutageSess.ID)
	if s4Type != "IP_PROVENANCE" || s4Status != "COMPLETE" || s4Disp != "CLEAR" {
		t.Fatalf("expected Step 4 model_assessments IP_PROVENANCE COMPLETE/CLEAR (no ASSESSMENT_TYPE_MISMATCH), got type=%q status=%q disp=%q", s4Type, s4Status, s4Disp)
	}
	_, s4Detail := t4pgGetPushDetail(t, ctx, actors.AuditorCli, scanOutageSess.ID)
	hasFailedGitleaks := false
	for _, sr := range s4Detail.ScanRuns {
		if sr.Scanner == "gitleaks" && (!sr.Complete || sr.Status != "COMPLETED") {
			hasFailedGitleaks = true
		}
	}
	if !hasFailedGitleaks {
		t.Fatalf("expected incomplete/failed gitleaks scan_run in Step 4 GetPush(%s), got %+v", scanOutageSess.ID, s4Detail.ScanRuns)
	}

	// 5. Clear outages -> subsequent clean push recovers and succeeds upstream.
	env.Scanners().ResetAll()
	env.Gateway().SetModeWithAssessmentType(harness.GatewayModeClean, "IP_PROVENANCE")
	if _, err := env.DB().ExecSQL(fmt.Sprintf(`UPDATE repositories SET classification = 'INTERNAL' WHERE id = %s::uuid;`, t4pgSQLQuote(repoID))); err != nil {
		t.Fatalf("restore repo classification=INTERNAL: %v", err)
	}
	env.GitHub().ResetPacketCounters()
	resRecovered := pgGitPushHTTP(t, cleanWork, gwHTTPSURL, actors.HumanATok, "HEAD:refs/heads/s7-recovered", env.GitGatewayCACertPath())
	if resRecovered.ExitCode != 0 {
		t.Fatalf("expected push to succeed after outages cleared: %s", resRecovered.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0 after recovery")
	}
}
