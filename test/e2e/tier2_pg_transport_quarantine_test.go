package e2e_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

// =============================================================================
// Shared Tier 2 Push Gateway Helpers (t2pg-prefixed for package e2e_test isolation)
// =============================================================================

func t2pgSQLLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func t2pgReadFixture(t testing.TB, rel string) []byte {
	t.Helper()
	p := filepath.Join(pgFindRepoRoot(t), "test", "e2e", "fixtures", rel)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %q: %v", p, err)
	}
	return b
}

func t2pgGatewayRepoURL(env *harness.Env, fullName string) string {
	return strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + strings.TrimPrefix(fullName, "/") + ".git"
}

func t2pgGatewaySSHURL(env *harness.Env, user, fullName string) string {
	if user == "" {
		user = "git"
	}
	return fmt.Sprintf("ssh://%s@%s/%s.git", user, env.GitGatewaySSHAddr(), strings.TrimPrefix(fullName, "/"))
}

func t2pgAssertErrorEnvelope(t testing.TB, raw *harness.RawResponse) {
	t.Helper()
	if raw == nil {
		t.Fatalf("expected non-nil RawResponse")
	}
	if raw.Error == nil || strings.TrimSpace(raw.Error.Code) == "" || strings.TrimSpace(raw.Error.Message) == "" {
		t.Fatalf("expected structured ErrorResponse envelope (status=%d), got body=%s", raw.StatusCode, string(raw.Body))
	}
}

func t2pgAssertPushRejectedZeroUpstream(t testing.TB, res pgGitResult, env *harness.Env, repoFull string) {
	t.Helper()
	if res.ExitCode == 0 {
		t.Fatalf("expected git push to fail, succeeded: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
	pgAssertZeroUpstreamReceivePack(t, env, repoFull)
}

func t2pgAssertRawPackRejected(t testing.TB, status int, respBody []byte, refName, label string) {
	t.Helper()
	rejected := status >= 400 ||
		(bytes.Contains(respBody, []byte("unpack ")) && !bytes.Contains(respBody, []byte("unpack ok"))) ||
		bytes.Contains(respBody, []byte("ng "))
	if !rejected || (status >= 200 && status < 300 && bytes.Contains(respBody, []byte("ok "+refName))) {
		t.Fatalf("%s: expected explicit raw pack rejection, got HTTP %d body=%q", label, status, string(respBody))
	}
}

func t2pgLatestPushForRepo(t testing.TB, cli *harness.APIClient, repoID string) harness.PushSessionResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	list, raw, err := cli.ListPushes(ctx, harness.PushFilter{
		RepositoryID: repoID,
		Limit:        20,
	})
	if err != nil {
		t.Fatalf("ListPushes(repo=%s): %v", repoID, err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if len(list.Pushes) == 0 {
		t.Fatalf("expected >=1 push session for repository %q, got 0", repoID)
	}
	p := list.Pushes[0]
	if p.ID != "" {
		harness.AssertUUIDv7(t, p.ID)
	}
	return p
}

func t2pgEnsurePrincipalSeeded(t testing.TB, env *harness.Env, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, _ = env.Client(token).GetWorkspace(ctx, harness.NewTestUUIDv7())
}

func t2pgSeedUnregisteredRepo(t testing.TB, env *harness.Env, owner, name string) harness.SeededRepo {
	t.Helper()
	repo, err := env.Git().InitSeededRepo(owner, name, map[string]string{
		"README.md": "# " + owner + "/" + name + "\n",
		"main.go":   "package main\n\nfunc main() {}\n",
	}, harness.WithDefaultBranch("main"))
	if err != nil {
		t.Fatalf("InitSeededRepo(%s/%s): %v", owner, name, err)
	}
	return repo
}

func t2pgResolveRef(t testing.TB, env *harness.Env, fullName, ref string) string {
	t.Helper()
	sha, err := env.Git().ResolveRef(fullName, ref)
	if err != nil {
		t.Fatalf("ResolveRef(%s, %s): %v", fullName, ref, err)
	}
	return sha
}

func t2pgNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func t2pgPolicyYAMLToJSON(yamlText string) ([]byte, string, string, error) {
	type t2pgRuleObl struct {
		Type          string `json:"type,omitempty"`
		ReviewerGroup string `json:"reviewer_group"`
		Minimum       *int   `json:"minimum,omitempty"`
	}
	type t2pgRuleDef struct {
		ID          string        `json:"id"`
		Description string        `json:"description,omitempty"`
		Stages      []string      `json:"stages"`
		When        string        `json:"when"`
		Effect      string        `json:"effect"`
		Overridable *bool         `json:"overridable,omitempty"`
		Message     string        `json:"message,omitempty"`
		Obligations []t2pgRuleObl `json:"obligations,omitempty"`
	}
	type t2pgDMDef struct {
		Route   string   `json:"route,omitempty"`
		Trigger []string `json:"trigger,omitempty"`
	}
	type t2pgInspectDef struct {
		Mandatory     []string   `json:"mandatory,omitempty"`
		DecisionModel *t2pgDMDef `json:"decisionModel,omitempty"`
	}
	type t2pgBundleDef struct {
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
		Inspection *t2pgInspectDef `json:"inspection,omitempty"`
		Rules      []t2pgRuleDef   `json:"rules"`
	}

	unquote := func(s string) string {
		s = strings.TrimSpace(s)
		if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
			return s[1 : len(s)-1]
		}
		return s
	}
	parseInlineList := func(v string) []string {
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "[")
		v = strings.TrimSuffix(v, "]")
		if strings.TrimSpace(v) == "" {
			return nil
		}
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			item := unquote(p)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	}

	b := t2pgBundleDef{Rules: make([]t2pgRuleDef, 0)}
	ensureInspection := func() *t2pgInspectDef {
		if b.Inspection == nil {
			b.Inspection = &t2pgInspectDef{}
		}
		return b.Inspection
	}
	ensureDecisionModel := func() *t2pgDMDef {
		ins := ensureInspection()
		if ins.DecisionModel == nil {
			ins.DecisionModel = &t2pgDMDef{}
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
	var curRule *t2pgRuleDef
	var curObl *t2pgRuleObl
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
	applyOblKV := func(obl *t2pgRuleObl, k, v string) {
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
		case "message":
			curRule.Message = unquote(v)
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
				curRule = &t2pgRuleDef{}
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
					curObl = &t2pgRuleObl{Type: "HUMAN_REVIEW"}
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

func t2pgSeedPolicyBundleDB(t testing.TB, env *harness.Env, scope, repoUUID, name, version, bundleYAML string) string {
	t.Helper()
	defJSON, parsedName, parsedVersion, err := t2pgPolicyYAMLToJSON(bundleYAML)
	if err != nil {
		t.Fatalf("t2pgPolicyYAMLToJSON: %v", err)
	}
	if name == "" {
		name = t2pgNonEmpty(parsedName, "e2e-push-bundle")
	}
	if version == "" {
		version = t2pgNonEmpty(parsedVersion, "1.0.0")
	}
	digest := harness.SHA256Hex(defJSON)
	id := harness.NewTestUUIDv7()
	repoExpr := "NULL"
	if scope == "REPO" && repoUUID != "" {
		repoExpr = t2pgSQLLiteral(repoUUID) + "::uuid"
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
		t2pgSQLLiteral(id),
		t2pgSQLLiteral(name),
		t2pgSQLLiteral(version),
		t2pgSQLLiteral(scope),
		repoExpr,
		t2pgSQLLiteral(digest),
		t2pgSQLLiteral(string(defJSON)),
	)
	rows, err := env.DB().QueryRows(q)
	if err != nil {
		t.Fatalf("t2pgSeedPolicyBundleDB(%s, %s): %v", scope, name, err)
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		t.Fatalf("t2pgSeedPolicyBundleDB returned no id")
	}
	return rows[0][0]
}

// =============================================================================
// Raw Smart-HTTP, TLS, Packfile v2, and Git Attack Builders (t2pg*)
// =============================================================================

func t2pgPktLine(payload []byte) []byte {
	hdr := fmt.Sprintf("%04x", 4+len(payload))
	out := make([]byte, 0, 4+len(payload))
	out = append(out, hdr...)
	out = append(out, payload...)
	return out
}

func t2pgReceivePackBody(cmds []string, packBytes []byte) []byte {
	var buf bytes.Buffer
	for i, c := range cmds {
		line := c
		if i == 0 && !strings.Contains(line, "\x00") {
			line += "\x00report-status side-band-64k"
		}
		if !strings.HasSuffix(line, "\n") {
			line += "\n"
		}
		buf.Write(t2pgPktLine([]byte(line)))
	}
	buf.WriteString("0000")
	buf.Write(packBytes)
	return buf.Bytes()
}

func t2pgRawTLSHTTPRequest(t testing.TB, httpsURL, caCertPath, rawReq string) (int, string) {
	t.Helper()
	addr := strings.TrimPrefix(httpsURL, "https://")
	if idx := strings.IndexByte(addr, '/'); idx >= 0 {
		addr = addr[:idx]
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCertPath != "" {
		pemBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			t.Fatalf("read caCertPath %q: %v", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			t.Fatalf("append CA cert %q failed", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		t.Fatalf("tls.Dial(%s): %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, rawReq); err != nil {
		t.Fatalf("write raw HTTP request: %v", err)
	}
	respBytes, _ := io.ReadAll(conn)
	respStr := string(respBytes)
	firstLine, _, _ := strings.Cut(respStr, "\r\n")
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) < 2 {
		return 0, respStr
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, respStr
	}
	return code, respStr
}

type t2pgPackEntry struct {
	Type    int
	Data    []byte
	BaseOID [20]byte // used only when Type == 7 (OBJ_REF_DELTA)
}

func t2pgGitObjectID(objType string, payload []byte) [20]byte {
	hdr := fmt.Sprintf("%s %d\x00", objType, len(payload))
	h := sha1.New()
	_, _ = h.Write([]byte(hdr))
	_, _ = h.Write(payload)
	var oid [20]byte
	copy(oid[:], h.Sum(nil))
	return oid
}

func t2pgEncodePackEntryHeader(objType int, size int64) []byte {
	var out []byte
	first := byte((objType & 0x07) << 4)
	first |= byte(size & 0x0f)
	size >>= 4
	if size > 0 {
		first |= 0x80
	}
	out = append(out, first)
	for size > 0 {
		b := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

func t2pgBuildPack(t testing.TB, entries []t2pgPackEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("PACK")
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], 2)
	buf.Write(u32[:])
	binary.BigEndian.PutUint32(u32[:], uint32(len(entries)))
	buf.Write(u32[:])

	for _, e := range entries {
		buf.Write(t2pgEncodePackEntryHeader(e.Type, int64(len(e.Data))))
		if e.Type == 7 {
			buf.Write(e.BaseOID[:])
		}
		var zbuf bytes.Buffer
		zw := zlib.NewWriter(&zbuf)
		if _, err := zw.Write(e.Data); err != nil {
			t.Fatalf("zlib write pack entry: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("zlib close pack entry: %v", err)
		}
		buf.Write(zbuf.Bytes())
	}

	sum := sha1.Sum(buf.Bytes())
	buf.Write(sum[:])
	return buf.Bytes()
}

func t2pgEncodeLEB128(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

func t2pgBuildRawCommit(treeOID [20]byte, parentHex, msg string) ([]byte, [20]byte) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "tree %s\n", hex.EncodeToString(treeOID[:]))
	if parentHex != "" {
		fmt.Fprintf(&buf, "parent %s\n", parentHex)
	}
	buf.WriteString("author Alice Developer <alice@example.com> 1795420000 +0000\n")
	buf.WriteString("committer Alice Developer <alice@example.com> 1795420000 +0000\n\n")
	buf.WriteString(msg)
	if !strings.HasSuffix(msg, "\n") {
		buf.WriteByte('\n')
	}
	data := buf.Bytes()
	return data, t2pgGitObjectID("commit", data)
}

func t2pgBuildDeltaBombPack(t testing.TB, parentHex string, targetSize int) ([]byte, string) {
	t.Helper()
	const baseLen = 4096
	baseBlob := bytes.Repeat([]byte{'A'}, baseLen)
	baseOID := t2pgGitObjectID("blob", baseBlob)

	var delta bytes.Buffer
	delta.Write(t2pgEncodeLEB128(baseLen))
	delta.Write(t2pgEncodeLEB128(uint64(targetSize)))
	copies := targetSize / baseLen
	if copies == 0 {
		copies = 1
	}
	for i := 0; i < copies; i++ {
		// Copy from offset 0, size 4096 (0x1000 -> size1=0x00, size2=0x10).
		delta.WriteByte(0x80 | 0x10 | 0x20)
		delta.WriteByte(0x00)
		delta.WriteByte(0x10)
	}

	// Compute inflated target blob OID by repeating baseLen bytes so tree+commit reference it cleanly.
	inflatedBlob := bytes.Repeat(baseBlob, copies)
	targetOID := t2pgGitObjectID("blob", inflatedBlob)

	var tree bytes.Buffer
	tree.WriteString("100644 bomb.bin\x00")
	tree.Write(targetOID[:])
	treeOID := t2pgGitObjectID("tree", tree.Bytes())

	commitData, commitOID := t2pgBuildRawCommit(treeOID, parentHex, "delta bomb commit")

	pack := t2pgBuildPack(t, []t2pgPackEntry{
		{Type: 3, Data: baseBlob},
		{Type: 7, Data: delta.Bytes(), BaseOID: baseOID},
		{Type: 2, Data: tree.Bytes()},
		{Type: 1, Data: commitData},
	})
	return pack, hex.EncodeToString(commitOID[:])
}

func t2pgBuildTraversalTreePack(t testing.TB, parentHex, entryName string) ([]byte, string) {
	t.Helper()
	blob := []byte("owned\n")
	blobOID := t2pgGitObjectID("blob", blob)

	var tree bytes.Buffer
	tree.WriteString("100644 " + entryName + "\x00")
	tree.Write(blobOID[:])
	treeOID := t2pgGitObjectID("tree", tree.Bytes())

	commitData, commitOID := t2pgBuildRawCommit(treeOID, parentHex, "traversal attempt")
	pack := t2pgBuildPack(t, []t2pgPackEntry{
		{Type: 3, Data: blob},
		{Type: 2, Data: tree.Bytes()},
		{Type: 1, Data: commitData},
	})
	return pack, hex.EncodeToString(commitOID[:])
}

func t2pgBuildValidCommitPack(t testing.TB, workDir, refspec string) (packBytes []byte, oldOID, newOID string) {
	t.Helper()
	oldRes := pgRunHardenedGit(workDir, nil, "rev-parse", "HEAD~1")
	if oldRes.ExitCode != 0 {
		oldOID = strings.Repeat("0", 40)
	} else {
		oldOID = strings.TrimSpace(oldRes.Stdout)
	}
	newRes := pgRunHardenedGit(workDir, nil, "rev-parse", "HEAD")
	if newRes.ExitCode != 0 {
		t.Fatalf("rev-parse HEAD: %s", newRes.Stderr)
	}
	newOID = strings.TrimSpace(newRes.Stdout)

	cmd := exec.Command("git", "pack-objects", "--stdout", "--revs")
	cmd.Dir = workDir
	cmd.Stdin = strings.NewReader(newOID + "\n^" + oldOID + "\n")
	if strings.HasPrefix(oldOID, "0000") {
		cmd.Stdin = strings.NewReader(newOID + "\n")
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("git pack-objects failed: %v (%s)", err, errBuf.String())
	}
	_ = refspec
	return out.Bytes(), oldOID, newOID
}

func t2pgPrepareApprovedV1Proposal(t testing.TB, env *harness.Env, actors pgActorSet, repo harness.SeededRepo) (string, harness.ProposalResp) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Ensure HumanA & SecAdmin exist in principals and create workspace.
	wsResp, wsRaw, err := actors.HumanACli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	wsRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusAccepted)
	wsID := t2pgNonEmpty(wsResp.WorkspaceID, wsResp.ID)
	if wsResp.OperationID != "" {
		op, err := actors.HumanACli.WaitForOperation(ctx, wsResp.OperationID, 30*time.Second)
		if err != nil || !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("WaitForOperation(ws): err=%v op=%+v", err, op)
		}
	}
	ws, gRaw, err := actors.HumanACli.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	gRaw.RequireStatus(t, http.StatusOK)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# clean pr\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})

	capResp, capRaw, err := actors.CtrlCli.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	upRaw, err := actors.CtrlCli.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, gz)
	if err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)
	var upBody struct {
		ArtifactID string `json:"artifact_id"`
		ID         string `json:"id"`
		SHA256     string `json:"sha256"`
	}
	if err := json.Unmarshal(upRaw.Body, &upBody); err != nil {
		t.Fatalf("unmarshal upload body: %v", err)
	}
	artID := t2pgNonEmpty(upBody.ArtifactID, upBody.ID)
	sha := t2pgNonEmpty(upBody.SHA256, harness.SHA256Hex(gz))

	subResp, subRaw, err := actors.CtrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "t2pg-isolation-check",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	propID := t2pgNonEmpty(subResp.ID, subResp.ProposalID)
	if subResp.OperationID != "" {
		op, err := actors.CtrlCli.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
		if err != nil || !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("WaitForOperation(reconstruct): err=%v op=%+v", err, op)
		}
	}

	prop, pRaw, err := actors.CtrlCli.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	pRaw.RequireStatus(t, http.StatusOK)

	evalResp, evalRaw, err := actors.CtrlCli.EvaluateProposal(ctx, propID, harness.EvaluateReq{
		ExpectedVersion: prop.Version,
	})
	if err != nil {
		t.Fatalf("EvaluateProposal: %v", err)
	}
	evalRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if evalResp.OperationID != "" {
		op, err := actors.CtrlCli.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second)
		if err != nil || !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("WaitForOperation(evaluate): err=%v op=%+v", err, op)
		}
	}

	// Poll until proposal reaches PENDING_APPROVAL or APPROVED.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		prop, pRaw, err = actors.CtrlCli.GetProposal(ctx, propID)
		if err == nil && pRaw.StatusCode == http.StatusOK && (prop.Status == "PENDING_APPROVAL" || prop.Status == "APPROVED") {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if prop.Status == "PENDING_APPROVAL" {
		_, appRaw, err := actors.SecAdminCli.ApproveProposal(ctx, propID, harness.ApproveReq{
			Decision:                  "APPROVE",
			PublicationManifestDigest: prop.PublicationManifestDigest,
			PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
			Comment:                   "approved for publisher isolation check",
		})
		if err != nil {
			t.Fatalf("ApproveProposal: %v", err)
		}
		appRaw.RequireStatus(t, http.StatusCreated)
		prop, _, err = actors.CtrlCli.GetProposal(ctx, propID)
		if err != nil {
			t.Fatalf("GetProposal(after approve): %v", err)
		}
	}
	if prop.Status != "APPROVED" {
		t.Fatalf("expected proposal %s APPROVED, got %q", propID, prop.Status)
	}
	return propID, prop
}

func t2pgBuildLFSPointer(oidHex string, size int64) string {
	return fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oidHex, size)
}

func t2pgUploadLFSObjectViaGateway(t testing.TB, env *harness.Env, token, repoFull string, payload []byte) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	oid := hex.EncodeToString(sum[:])

	batchReqBody, _ := json.Marshal(map[string]any{
		"operation": "upload",
		"transfers": []string{"basic"},
		"objects": []map[string]any{
			{"oid": oid, "size": len(payload)},
		},
	})
	batchURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repoFull + ".git/info/lfs/objects/batch"
	req, err := http.NewRequest(http.MethodPost, batchURL, bytes.NewReader(batchReqBody))
	if err != nil {
		t.Fatalf("new LFS batch req: %v", err)
	}
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	req.SetBasicAuth("x-access-token", token)

	client := env.GitGatewayHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("LFS batch POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LFS batch POST status=%d body=%s", resp.StatusCode, string(body))
	}

	var parsed struct {
		Objects []struct {
			OID     string `json:"oid"`
			Actions map[string]struct {
				Href   string            `json:"href"`
				Header map[string]string `json:"header"`
			} `json:"actions"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode LFS batch response: %v (%s)", err, string(body))
	}
	if len(parsed.Objects) == 0 {
		t.Fatalf("LFS batch returned 0 objects: %s", string(body))
	}
	uploadAction, ok := parsed.Objects[0].Actions["upload"]
	if !ok || uploadAction.Href == "" {
		t.Fatalf("LFS batch missing upload action for oid %s: %s", oid, string(body))
	}
	putReq, err := http.NewRequest(http.MethodPut, uploadAction.Href, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new LFS upload PUT: %v", err)
	}
	for k, v := range uploadAction.Header {
		putReq.Header.Set(k, v)
	}
	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("LFS upload PUT: %v", err)
	}
	_ = putResp.Body.Close()
	if putResp.StatusCode < 200 || putResp.StatusCode >= 300 {
		t.Fatalf("LFS upload PUT status=%d", putResp.StatusCode)
	}
	return oid
}

// =============================================================================
// EF1: HTTPS Smart-HTTP Gateway & Read Proxy Boundaries (6 tests)
// =============================================================================

func TestT2_PG_EF01_UnauthenticatedGitPushRejected401ZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	gwURL := t2pgGatewayRepoURL(env, repo.FullName)

	workDir := pgCreateGitRepoWithFiles(t, map[string]string{
		"README.md": "# unauth push\n",
	}, "unauth commit", harness.GitIdentity{Name: "Anon", Email: "anon@example.com"})

	// 1. Real git push with empty token must be rejected.
	res := pgGitPushHTTP(t, workDir, gwURL, "", "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected unauthenticated git push to fail, got exit 0")
	}

	// 2. Direct unauthenticated POST /git-receive-pack must return 401.
	packBytes, oldOID, newOID := t2pgBuildValidCommitPack(t, workDir, "HEAD:refs/heads/main")
	rawBody := t2pgReceivePackBody([]string{oldOID + " " + newOID + " refs/heads/main"}, packBytes)
	status, _ := pgGitPushRawPack(t, gwURL+"/git-receive-pack", "", env.GitGatewayCACertPath(), rawBody)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 on unauthenticated POST /git-receive-pack, got %d", status)
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF01_InvalidHTTPMethodRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	client := env.GitGatewayHTTPClient()
	baseRepoURL := t2pgGatewayRepoURL(env, repo.FullName)

	cases := []struct {
		method string
		url    string
	}{
		{http.MethodPut, baseRepoURL + "/git-receive-pack"},
		{http.MethodDelete, baseRepoURL + "/git-receive-pack"},
		{http.MethodPost, baseRepoURL + "/info/refs?service=git-receive-pack"},
	}
	for _, tc := range cases {
		req, err := http.NewRequest(tc.method, tc.url, strings.NewReader("garbage"))
		if err != nil {
			t.Fatalf("build request %s %s: %v", tc.method, tc.url, err)
		}
		req.Header.Set("Authorization", "Bearer "+actors.HumanATok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", tc.method, tc.url, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s expected 405/400/404, got %d", tc.method, tc.url, resp.StatusCode)
		}
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF01_MalformedPktLineRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	receivePackURL := t2pgGatewayRepoURL(env, repo.FullName) + "/git-receive-pack"

	badBodies := []struct {
		name string
		body []byte
	}{
		{"invalid_hex_len", []byte("zzzz0000")},
		{"truncated_pkt", []byte("0040short")},
		{"length_below_4", []byte("0003")},
	}
	for _, tc := range badBodies {
		status, _ := pgGitPushRawPack(t, receivePackURL, actors.HumanATok, env.GitGatewayCACertPath(), tc.body)
		if status >= 200 && status < 300 {
			t.Fatalf("%s: expected non-2xx rejection for malformed pkt-line, got %d", tc.name, status)
		}
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF01_OversizedContentLengthRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayMaxPackBytes(4096)),
	)
	actors := pgMintActors(env)

	// 1. Raw TLS request declaring 4 MiB Content-Length (> MaxPackBytes 4096 + 2 MiB command area) without streaming 4 MiB must be rejected early.
	rawReq := fmt.Sprintf(
		"POST /%s.git/git-receive-pack HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 4194304\r\nConnection: close\r\n\r\n0000",
		repo.FullName, actors.HumanATok,
	)
	status, rawResp := t2pgRawTLSHTTPRequest(t, env.GitGatewayHTTPSURL(), env.GitGatewayCACertPath(), rawReq)
	if status != http.StatusRequestEntityTooLarge && status != http.StatusBadRequest && status != http.StatusForbidden {
		t.Fatalf("expected 413/400/403 on oversized Content-Length, got %d (resp=%q)", status, rawResp)
	}

	// 2. Real git push with incompressible 16 KiB file exceeding 4096 max_pack_bytes.
	incompressible := make([]byte, 16384)
	if _, err := rand.Read(incompressible); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"blob.bin": string(incompressible),
	}, nil, "oversized pack", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	pushRes := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, pushRes, env, repo.FullName)
}

func TestT2_PG_EF01_InvalidRepoPathAndTraversalRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	rawPaths := []string{
		"/acme/../../etc/passwd.git/info/refs?service=git-receive-pack",
		"/%2e%2e/acme/service.git/git-receive-pack",
		"/invalid-no-dot-git/info/refs?service=git-receive-pack",
	}
	for _, p := range rawPaths {
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", p, actors.HumanATok)
		status, _ := t2pgRawTLSHTTPRequest(t, env.GitGatewayHTTPSURL(), env.GitGatewayCACertPath(), req)
		if status < 400 || status >= 500 {
			t.Fatalf("path %q: expected 4xx rejection, got %d", p, status)
		}
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF01_NonExistentAndDisabledRepoRejectedZeroUpstream(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	// 1. Push to nonexistent repo.
	workDir := pgCreateGitRepoWithFiles(t, map[string]string{
		"clean.go": "package main\n",
	}, "clean commit", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	resNonExistent := pgGitPushHTTP(t, workDir, t2pgGatewayRepoURL(env, "acme/nonexistent"), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, resNonExistent, env, "acme/nonexistent")

	// 2. Disable seeded repo in DB and verify push is rejected.
	if _, err := env.DB().ExecSQL(fmt.Sprintf("UPDATE repositories SET enabled = false WHERE id = %s::uuid;", t2pgSQLLiteral(repoID))); err != nil {
		t.Fatalf("disable repository: %v", err)
	}
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode == 0 {
		_ = pgAddCommit(t, cloneDir, map[string]string{"note.txt": "disabled"}, nil, "disabled push", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
		resDisabled := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
		t2pgAssertPushRejectedZeroUpstream(t, resDisabled, env, repo.FullName)
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

// =============================================================================
// EF2: SSH User-Certificate Termination & Principal Binding Boundaries (5 tests)
// =============================================================================

func TestT2_PG_EF02_ExpiredSSHUserCertRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t2pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"a.txt": "expired cert"}, nil, "expired ssh cert", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	expiredCred := env.SSHCA().MintExpiredCert("alice-expired", []string{"alice-human-001"})
	res := pgGitPushSSH(t, cloneDir, t2pgGatewaySSHURL(env, "alice-human-001", repo.FullName), expiredCred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF02_RogueCASSHUserCertRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t2pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"b.txt": "rogue ca"}, nil, "rogue ca cert", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	rogueCred := env.SSHCA().MintWrongCACert("alice-rogue", []string{"alice-human-001"})
	res := pgGitPushSSH(t, cloneDir, t2pgGatewaySSHURL(env, "alice-human-001", repo.FullName), rogueCred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF02_WrongPrincipalSSHUserCertRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t2pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"c.txt": "wrong principal"}, nil, "wrong principal", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	// 1. Cert carries bob-human-002 while connecting as ssh://alice-human-001@...
	wrongCred := env.SSHCA().MintWrongPrincipalCert("alice-wrong-p", []string{"bob-human-002"})
	res1 := pgGitPushSSH(t, cloneDir, t2pgGatewaySSHURL(env, "alice-human-001", repo.FullName), wrongCred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	t2pgAssertPushRejectedZeroUpstream(t, res1, env, repo.FullName)

	// 2. Cert carries an unregistered/unknown principal.
	unknownCred := env.SSHCA().MintWrongPrincipalCert("unknown-p", []string{"unregistered-principal-xyz"})
	res2 := pgGitPushSSH(t, cloneDir, t2pgGatewaySSHURL(env, "git", repo.FullName), unknownCred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	t2pgAssertPushRejectedZeroUpstream(t, res2, env, repo.FullName)
}

func TestT2_PG_EF02_EmptyValidPrincipalsSSHUserCertRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t2pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"d.txt": "empty principals"}, nil, "empty principals", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	emptyPrincipalsCred := env.SSHCA().MintUserCert(harness.SSHUserCertSpec{
		KeyID:      "empty-principals",
		Principals: nil,
	})
	if len(emptyPrincipalsCred.Principals) != 0 {
		t.Fatalf("expected 0 principals in minted cert, got %v", emptyPrincipalsCred.Principals)
	}

	res := pgGitPushSSH(t, cloneDir, t2pgGatewaySSHURL(env, "git", repo.FullName), emptyPrincipalsCred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF02_ForgedGitAuthorIgnoredAttributedToSSHCertPrincipal(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t2pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	cred := env.SSHCA().MintValidCert("alice-key-1", []string{"alice-human-001"})
	cloneDir, cloneRes := pgGitCloneSSH(t, t2pgGatewaySSHURL(env, "alice-human-001", repo.FullName), cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("SSH clone failed: %s", cloneRes.Stderr)
	}

	forgedAuthor := harness.GitIdentity{Name: "Mallory Spoof", Email: "mallory@evil.example"}
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"clean.go": string(t2pgReadFixture(t, "push_gateway/payloads/clean_feature.go")),
	}, nil, "clean commit with forged author", forgedAuthor)

	pushRes := pgGitPushSSH(t, cloneDir, t2pgGatewaySSHURL(env, "alice-human-001", repo.FullName), cred, env.GitGatewaySSHAddr(), "HEAD:refs/heads/main", env.SSHCA())
	if pushRes.ExitCode != 0 {
		t.Fatalf("expected clean SSH push by authenticated Alice to succeed, got exit %d: %s", pushRes.ExitCode, pushRes.Stderr)
	}

	session := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if session.PrincipalSubject != "" && session.PrincipalSubject != "alice-human-001" {
		t.Fatalf("expected push attribution to alice-human-001, got %q", session.PrincipalSubject)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT p.subject, coalesce(p.verified_email, '')
		 FROM push_sessions ps
		 JOIN principals p ON p.id = ps.principal_id
		 WHERE ps.id = %s::uuid;`,
		t2pgSQLLiteral(session.ID),
	))
	if err != nil {
		t.Fatalf("query push_sessions principal: %v", err)
	}
	if len(rows) == 0 || rows[0][0] != "alice-human-001" {
		t.Fatalf("expected DB principal subject alice-human-001, got %+v", rows)
	}
	if strings.Contains(rows[0][1], "mallory") {
		t.Fatalf("forged author leaked into principal verified_email: %q", rows[0][1])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	audits, raw, err := actors.AuditorCli.ListAuditEvents(ctx, harness.AuditFilter{ResourceID: session.ID})
	if err != nil {
		t.Fatalf("ListAuditEvents(resource_id=%s): %v", session.ID, err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if len(audits.Events) == 0 {
		t.Fatalf("expected >=1 audit event for push session %s, got 0", session.ID)
	}
	for _, ev := range audits.Events {
		if strings.Contains(strings.ToLower(ev.ActorID), "mallory") {
			t.Fatalf("audit event attributed to forged author: %+v", ev)
		}
	}
}

// =============================================================================
// EF3: Credential Helper & Upstream Token Boundaries (5 tests)
// =============================================================================

func TestT2_PG_EF03_CredentialHelperInvalidActionFlagsMissingURLAndExpiredToken(t *testing.T) {
	env := pgNewEnv(t)
	ct := env.Contracts()
	bin := ct.Binaries.Custodian
	validTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-human-001", Email: "alice@example.com"})
	expiredTok := env.MintToken(harness.TokenClaims{
		Kind:      "HUMAN",
		Subject:   "alice-human-001",
		Email:     "alice@example.com",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	// 1. Unknown flag -> exit 2.
	resFlag := env.RunCLIWithStdin(bin, []string{"credential-helper", "--bogus-flag"}, map[string]string{
		"CUSTODIAN_API_URL": env.APIBaseURL(),
		"CUSTODIAN_TOKEN":   validTok,
	}, "protocol=https\nhost=127.0.0.1\n\n")
	if resFlag.ExitCode != 2 {
		t.Fatalf("unknown flag expected exit 2, got %d (stderr=%q)", resFlag.ExitCode, resFlag.Stderr)
	}

	// 2. Invalid action -> non-zero exit (1 or 2), empty stdout.
	resOp := env.RunCLIWithStdin(bin, []string{"credential-helper", "bogus-op"}, map[string]string{
		"CUSTODIAN_API_URL": env.APIBaseURL(),
		"CUSTODIAN_TOKEN":   validTok,
	}, "protocol=https\nhost=127.0.0.1\n\n")
	if resOp.ExitCode == 0 || strings.TrimSpace(resOp.Stdout) != "" {
		t.Fatalf("bogus action expected non-zero & empty stdout, got code=%d stdout=%q", resOp.ExitCode, resOp.Stdout)
	}

	// 3. Missing API URL -> non-zero exit, empty stdout.
	resNoURL := env.RunCLIWithStdin(bin, []string{"credential-helper", "get"}, map[string]string{
		"CUSTODIAN_API_URL": "",
		"CUSTODIAN_TOKEN":   validTok,
	}, "protocol=https\nhost=127.0.0.1\n\n")
	if resNoURL.ExitCode == 0 || strings.TrimSpace(resNoURL.Stdout) != "" {
		t.Fatalf("missing API URL expected non-zero & empty stdout, got code=%d stdout=%q", resNoURL.ExitCode, resNoURL.Stdout)
	}

	// 4. Expired OIDC token -> non-zero exit, empty stdout, zero secret leak.
	resExp := env.RunCLIWithStdin(bin, []string{"credential-helper", "get"}, map[string]string{
		"CUSTODIAN_API_URL": env.APIBaseURL(),
		"CUSTODIAN_TOKEN":   expiredTok,
	}, "protocol=https\nhost=127.0.0.1\n\n")
	if resExp.ExitCode == 0 || strings.TrimSpace(resExp.Stdout) != "" {
		t.Fatalf("expired token expected non-zero & empty stdout, got code=%d stdout=%q", resExp.ExitCode, resExp.Stdout)
	}
	harness.AssertNoSecretOrEncodedLeak(t, resExp.Stdout+"\n"+resExp.Stderr, expiredTok)
}

func TestT2_PG_EF03_InsufficientScopePATRejectedWithoutTokenLeak(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	origMainSHA := t2pgResolveRef(t, env, repo.FullName, "refs/heads/main")

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanBTok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"bob.txt": "read only pat"}, nil, "bob pat push", harness.GitIdentity{Name: "Bob", Email: "bob@example.com"})

	env.GitHub().ResetPacketCounters()
	pushURL, err := pgInjectHTTPAuth(t2pgGatewayRepoURL(env, repo.FullName), actors.HumanBTok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(cloneDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "-c", "http.extraHeader=X-Custodian-Upstream-Token: "+actors.BobReadPAT, "push", pushURL, "HEAD:refs/heads/main")
	if res.ExitCode == 0 {
		t.Fatalf("expected push with read-only delegated PAT to fail, got exit 0")
	}
	if n := env.GitHub().ReceivePackBytes(repo.FullName); n != 0 {
		t.Fatalf("expected 0 upstream receive-pack bytes for insufficient-scope PAT, got %d", n)
	}
	for _, p := range env.GitHub().PushAttempts() {
		if p.Repo == repo.FullName && p.Allowed {
			t.Fatalf("expected upstream push attempt with read-only PAT to be denied, got %+v", p)
		}
	}
	if gotSHA := t2pgResolveRef(t, env, repo.FullName, "refs/heads/main"); gotSHA != origMainSHA {
		t.Fatalf("expected upstream main to remain %q, got %q", origMainSHA, gotSHA)
	}
	harness.AssertNoSecretOrEncodedLeak(t, res.Stdout+"\n"+res.Stderr, actors.BobReadPAT, actors.HumanBTok)
	env.AssertNoSecretLeakInLogs(actors.BobReadPAT, actors.HumanBTok)
}

func TestT2_PG_EF03_URLEncodedAndBase64PATVariantsRedactedExtraSecrets(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	specialPAT := "gho_e2e+test/slash=eq12345"
	env.GitHub().RegisterUserToken(specialPAT, true)
	env.RegisterSecret(specialPAT)
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: specialPAT,
		FilePath:    "leak_check.txt",
		RuleID:      "github-pat-token",
	})

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone with OIDC token failed: %s", cloneRes.Stderr)
	}
	// Push commit whose content contains the forwarded PAT (caught by scanner and redacted via ExtraSecrets + SafeHandler).
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"leak_check.txt": "token=" + specialPAT + "\n",
	}, nil, "check ExtraSecrets redaction", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	pushURL, err := pgInjectHTTPAuth(t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(cloneDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "-c", "http.extraHeader=X-Custodian-Upstream-Token: "+specialPAT, "push", pushURL, "HEAD:refs/heads/main")
	if res.ExitCode == 0 {
		t.Fatalf("expected push containing forwarded PAT to be blocked by ExtraSecrets inspection")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)

	rows, err := env.DB().QueryRows("SELECT COALESCE(message,''), COALESCE(metadata::text,''), COALESCE(evidence_ref,'') FROM findings;")
	if err != nil {
		t.Fatalf("query findings table: %v", err)
	}
	var dbDump strings.Builder
	for _, row := range rows {
		dbDump.WriteString(strings.Join(row, " | "))
		dbDump.WriteByte('\n')
	}
	harness.AssertNoSecretOrEncodedLeak(t, dbDump.String(), specialPAT, actors.HumanATok)

	push := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, getPushRaw, err := actors.AuditorCli.GetPush(ctx, push.ID)
	if err != nil {
		t.Fatalf("GetPush(%s): %v", push.ID, err)
	}
	getPushRaw.RequireStatus(t, http.StatusOK)
	harness.AssertNoSecretOrEncodedLeak(t, string(getPushRaw.Body), specialPAT, actors.HumanATok)

	harness.AssertNoSecretOrEncodedLeak(t, res.Stdout+"\n"+res.Stderr, specialPAT, actors.HumanATok)
	env.AssertNoSecretLeakInLogs(specialPAT, actors.HumanATok)
}

func TestT2_PG_EF03_CredentialHelperMalformedStdinRejectedCleanly(t *testing.T) {
	env := pgNewEnv(t)
	bin := env.Contracts().Binaries.Custodian
	tok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-human-001", Email: "alice@example.com"})

	malformedInputs := []struct {
		name  string
		stdin string
	}{
		{"empty_stdin", ""},
		{"binary_nul", "protocol=https\x00host=127.0.0.1\n\n"},
		{"missing_host", "protocol=https\n\n"},
		{"unsupported_protocol", "protocol=ftp\nhost=127.0.0.1\n\n"},
	}
	for _, tc := range malformedInputs {
		res := env.RunCLIWithStdin(bin, []string{"credential-helper", "get"}, map[string]string{
			"CUSTODIAN_API_URL": env.APIBaseURL(),
			"CUSTODIAN_TOKEN":   tok,
		}, tc.stdin)
		if res.ExitCode == 0 {
			t.Fatalf("%s: expected non-zero exit code, got 0 (stdout=%q)", tc.name, res.Stdout)
		}
		if strings.Contains(res.Stderr, "panic:") {
			t.Fatalf("%s: credential-helper panicked: %s", tc.name, res.Stderr)
		}
		if strings.TrimSpace(res.Stdout) != "" {
			t.Fatalf("%s: expected empty stdout on error, got %q", tc.name, res.Stdout)
		}
	}
}

func TestT2_PG_EF03_CredentialHelperUnauthenticatedAndRogueJWTFailsClosed(t *testing.T) {
	env := pgNewEnv(t)
	bin := env.Contracts().Binaries.Custodian
	wrongKeyTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-human-001", SignWithWrongKey: true})
	tamperedTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "alice-human-001", TamperSignature: true})

	for _, tc := range []struct {
		name string
		tok  string
	}{
		{"empty_token", ""},
		{"wrong_key_jwt", wrongKeyTok},
		{"tampered_jwt", tamperedTok},
	} {
		res := env.RunCLIWithStdin(bin, []string{"credential-helper", "get"}, map[string]string{
			"CUSTODIAN_API_URL": env.APIBaseURL(),
			"CUSTODIAN_TOKEN":   tc.tok,
		}, "protocol=https\nhost=127.0.0.1\n\n")
		if res.ExitCode == 0 {
			t.Fatalf("%s: expected non-zero exit, got 0", tc.name)
		}
		if strings.TrimSpace(res.Stdout) != "" {
			t.Fatalf("%s: expected empty stdout, got %q", tc.name, res.Stdout)
		}
		if tc.tok != "" {
			harness.AssertNoSecretOrEncodedLeak(t, res.Stdout+"\n"+res.Stderr, tc.tok)
		}
	}
}

// =============================================================================
// EF4: Git LFS Batch Gating Boundaries (5 tests)
// =============================================================================

func TestT2_PG_EF04_LFSBatchInvalidOIDRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	batchURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git/info/lfs/objects/batch"
	client := env.GitGatewayHTTPClient()

	badOIDs := []string{"not-a-sha256", ".", "../etc/passwd"}
	for _, oid := range badOIDs {
		body, _ := json.Marshal(map[string]any{
			"operation": "upload",
			"transfers": []string{"basic"},
			"objects":   []map[string]any{{"oid": oid, "size": 128}},
		})
		req, _ := http.NewRequest(http.MethodPost, batchURL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
		req.SetBasicAuth("x-access-token", actors.HumanATok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("LFS batch (%q): %v", oid, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("LFS batch (%q): expected 400/422, got %d", oid, resp.StatusCode)
		}
	}
	if calls := env.GitHub().LFSBatchCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 upstream LFSBatchCalls on invalid OID, got %+v", calls)
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF04_LFSBatchOversizedOrUnsupportedOpRejectedZeroUpstream(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	batchURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + repo.FullName + ".git/info/lfs/objects/batch"
	client := env.GitGatewayHTTPClient()
	validOID := strings.Repeat("a", 64)

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			"unsupported_op",
			map[string]any{"operation": "delete", "objects": []map[string]any{{"oid": validOID, "size": 128}}},
		},
		{
			"negative_size",
			map[string]any{"operation": "upload", "objects": []map[string]any{{"oid": validOID, "size": -1}}},
		},
		{
			"oversized_100gib",
			map[string]any{"operation": "upload", "objects": []map[string]any{{"oid": validOID, "size": int64(100) << 30}}},
		},
	}
	for _, tc := range cases {
		raw, _ := json.Marshal(tc.body)
		req, _ := http.NewRequest(http.MethodPost, batchURL, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
		req.SetBasicAuth("x-access-token", actors.HumanATok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Fatalf("%s: expected 4xx rejection, got %d", tc.name, resp.StatusCode)
		}
	}
	if calls := env.GitHub().LFSBatchCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 upstream LFSBatchCalls, got %+v", calls)
	}
	if n := env.GitHub().LFSUploadBytes(repo.FullName); n != 0 {
		t.Fatalf("expected 0 upstream LFSUploadBytes, got %d", n)
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF04_LFSPointerMissingObjectOrHashMismatchBlocked(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	// 1. Push LFS pointer referencing an object never uploaded.
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	missingOID := strings.Repeat("b", 64)
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"assets/model.bin": t2pgBuildLFSPointer(missingOID, 1024),
	}, nil, "missing lfs object", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	res1 := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res1, env, repo.FullName)

	// 2. Upload 128-byte object, but commit pointer claiming size 9999.
	cloneDir2, cloneRes2 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes2.ExitCode != 0 {
		t.Fatalf("clone2 failed: %s", cloneRes2.Stderr)
	}
	payload := bytes.Repeat([]byte("Z"), 128)
	uploadedOID := t2pgUploadLFSObjectViaGateway(t, env, actors.HumanATok, repo.FullName, payload)
	env.GitHub().ResetPacketCounters()
	_ = pgAddCommit(t, cloneDir2, map[string]string{
		"assets/mismatch.bin": t2pgBuildLFSPointer(uploadedOID, 9999),
	}, nil, "mismatched lfs size", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	res2 := pgGitPushHTTP(t, cloneDir2, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res2, env, repo.FullName)
}

func TestT2_PG_EF04_LFSBatchDenySendsZeroUpstreamLFSBytes(t *testing.T) {
	env, _, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	unreg := t2pgSeedUnregisteredRepo(t, env, "external", "unreg-lfs")

	payload := bytes.Repeat([]byte("L"), 512)
	sum := sha256.Sum256(payload)
	oid := hex.EncodeToString(sum[:])

	batchURL := strings.TrimRight(env.GitGatewayHTTPSURL(), "/") + "/" + unreg.FullName + ".git/info/lfs/objects/batch"
	body, _ := json.Marshal(map[string]any{
		"operation": "upload",
		"transfers": []string{"basic"},
		"objects":   []map[string]any{{"oid": oid, "size": len(payload)}},
	})
	req, _ := http.NewRequest(http.MethodPost, batchURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	req.SetBasicAuth("x-access-token", actors.HumanATok)

	resp, err := env.GitGatewayHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("LFS batch unregistered: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 403/404/422 for unregistered LFS batch, got %d", resp.StatusCode)
	}
	if calls := env.GitHub().LFSBatchCalls(); len(calls) != 0 {
		t.Fatalf("expected 0 upstream LFSBatchCalls on denied batch, got %+v", calls)
	}
	if bytesSent := env.GitHub().LFSUploadBytes(""); bytesSent != 0 {
		t.Fatalf("expected 0 upstream LFSUploadBytes, got %d", bytesSent)
	}
	pgAssertZeroUpstreamReceivePack(t, env, unreg.FullName)
}

func TestT2_PG_EF04_LFSOverEnforceBlockPolicyDenyOnPushHasLFS(t *testing.T) {
	lfsDenyYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: push-repo-deny-lfs
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: push.lfs.deny_all
    stages: [PUSH_EGRESS]
    when: push.has_lfs
    effect: DENY
    overridable: false
    message: Git LFS uploads are disabled for this repository.
`
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithPolicyBundleDir(pgPolicyDirWithDefaults(t, map[string]string{
			"push_repo_deny_lfs.yaml": lfsDenyYAML,
		})),
	)
	actors := pgMintActors(env)
	t2pgSeedPolicyBundleDB(t, env, "REPO", repoID, "push-repo-deny-lfs", "1.0.0", lfsDenyYAML)

	payload := bytes.Repeat([]byte("M"), 2048)
	oid := t2pgUploadLFSObjectViaGateway(t, env, actors.HumanATok, repo.FullName, payload)
	env.GitHub().ResetPacketCounters()

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"assets/large.bin": t2pgBuildLFSPointer(oid, int64(len(payload))),
	}, nil, "commit with LFS pointer", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	pushRes := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, pushRes, env, repo.FullName)

	session := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if !session.HasLFS {
		t.Fatalf("expected PushSessionResp.HasLFS=true, got false (%+v)", session)
	}
}

// =============================================================================
// EF5: Egress Operating Mode Boundaries (5 tests)
// =============================================================================

func TestT2_PG_EF05_InvalidEgressModeRejected400(t *testing.T) {
	env, _, repoID := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT")
	actors := pgMintActors(env)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for _, badMode := range []string{"INVALID_MODE", "", "enforce_block"} {
		_, raw, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
			EgressMode: badMode,
		})
		if err != nil {
			t.Fatalf("SetRepoEgressMode(%q): %v", badMode, err)
		}
		raw.RequireStatus(t, http.StatusBadRequest)
		t2pgAssertErrorEnvelope(t, raw)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf("SELECT egress_mode FROM repositories WHERE id = %s::uuid;", t2pgSQLLiteral(repoID)))
	if err != nil {
		t.Fatalf("query repositories.egress_mode: %v", err)
	}
	if len(rows) == 0 || rows[0][0] != "PASSIVE_AUDIT" {
		t.Fatalf("expected egress_mode to remain PASSIVE_AUDIT, got %+v", rows)
	}
}

func TestT2_PG_EF05_PassiveAuditInvalidDeliveryRejected400(t *testing.T) {
	env, _, repoID := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT")
	actors := pgMintActors(env)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for _, badDelivery := range []string{"WEBHOOK", "SYNC", "inline_warn"} {
		_, raw, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
			EgressMode:           "PASSIVE_AUDIT",
			PassiveAuditDelivery: badDelivery,
		})
		if err != nil {
			t.Fatalf("SetRepoEgressMode(delivery=%q): %v", badDelivery, err)
		}
		raw.RequireStatus(t, http.StatusBadRequest)
		t2pgAssertErrorEnvelope(t, raw)
	}
	_ = env
}

func TestT2_PG_EF05_EnforceBlockScannerOutageFailsClosedZeroUpstream(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayExtraEnv(map[string]string{
			"CUSTODIAN_SCANNER_TIMEOUT": "2s",
		})),
	)
	actors := pgMintActors(env)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"clean.go": string(t2pgReadFixture(t, "push_gateway/payloads/clean_feature.go")),
	}, nil, "scanner outage push", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:      harness.ScannerModeCrash,
		ExitCode:  2,
		StderrMsg: "simulated gitleaks crash",
	})
	resCrash := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, resCrash, env, repo.FullName)

	session := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if !harness.ContainsStatus([]string{"QUARANTINED", "BLOCKED", "FAILED", "DENIED"}, session.Status) {
		t.Fatalf("expected fail-closed status on scanner crash, got %q", session.Status)
	}

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{Mode: harness.ScannerModeClean})
	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:          harness.ScannerModeTimeout,
		SleepDuration: 6 * time.Second,
	})
	resTimeout := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/timeout-branch", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, resTimeout, env, repo.FullName)
}

func TestT2_PG_EF05_EnforceBlockStageBOutageFailsClosedZeroUpstream(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	// Mark repo RESTRICTED so Stage B trigger (restricted_repository) fires even on clean diff.
	if _, err := env.DB().ExecSQL(fmt.Sprintf("UPDATE repositories SET classification = 'RESTRICTED' WHERE id = %s::uuid;", t2pgSQLLiteral(repoID))); err != nil {
		t.Fatalf("update repo classification: %v", err)
	}

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"clean.go": string(t2pgReadFixture(t, "push_gateway/payloads/clean_feature.go")),
	}, nil, "stage B outage push", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	env.Gateway().SetMode(harness.GatewayModeOutage503)
	res503 := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res503, env, repo.FullName)

	session := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if !harness.ContainsStatus([]string{"QUARANTINED", "BLOCKED", "FAILED"}, session.Status) {
		t.Fatalf("expected fail-closed status on Stage B 503, got %q", session.Status)
	}

	env.Gateway().SetMode(harness.GatewayModeTimeout)
	resTO := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/to-branch", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, resTO, env, repo.FullName)
}

func TestT2_PG_EF05_PassiveAuditScannerAndStageBOutageRecordsWithoutBlocking(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT")
	actors := pgMintActors(env)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// Configure INLINE_WARN and RESTRICTED classification so Stage B runs.
	_, rawMode, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "INLINE_WARN",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode: %v", err)
	}
	rawMode.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	if _, err := env.DB().ExecSQL(fmt.Sprintf("UPDATE repositories SET classification = 'RESTRICTED' WHERE id = %s::uuid;", t2pgSQLLiteral(repoID))); err != nil {
		t.Fatalf("update repo classification: %v", err)
	}

	// Subcase A: scanner secret finding in PASSIVE_AUDIT -> upstream receives bytes, session records OBSERVED_WOULD_BLOCK + enforced=false.
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		FilePath:    "creds.env",
	})
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{
		"creds.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
	}, nil, "passive audit finding", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	resA := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if resA.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT must not block push on finding: exit=%d stderr=%s", resA.ExitCode, resA.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0 in PASSIVE_AUDIT")
	}

	// Poll briefly if async passive audit finalizes asynchronously.
	var sessA harness.PushSessionResp
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		sessA = t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
		if sessA.Status == "OBSERVED_WOULD_BLOCK" || sessA.Status == "COMPLETED" || sessA.Status == "FAILED" {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if sessA.Status != "OBSERVED_WOULD_BLOCK" {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK in PASSIVE_AUDIT with secret finding, got %q", sessA.Status)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT enforced::text FROM policy_decisions WHERE push_session_id = %s::uuid ORDER BY created_at DESC LIMIT 1;",
		t2pgSQLLiteral(sessA.ID),
	))
	if err != nil {
		t.Fatalf("query policy_decisions.enforced: %v", err)
	}
	if len(rows) == 0 || rows[0][0] != "false" {
		t.Fatalf("expected policy_decisions.enforced=false in PASSIVE_AUDIT, got %+v", rows)
	}

	// Subcase B: scanner crash + Stage B 503 outage in ASYNC PASSIVE_AUDIT -> still forwards without blocking.
	_, rawAsync, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "ASYNC",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode(ASYNC): %v", err)
	}
	rawAsync.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	env.GitHub().ResetPacketCounters()
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{Mode: harness.ScannerModeCrash, ExitCode: 2})
	env.Gateway().SetMode(harness.GatewayModeOutage503)

	_ = pgAddCommit(t, cloneDir, map[string]string{"note.txt": "outage in passive"}, nil, "passive outage", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	resB := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if resB.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT must not block push during scanner/Stage B outage: exit=%d stderr=%s", resB.ExitCode, resB.Stderr)
	}
	if env.GitHub().ReceivePackBytes(repo.FullName) == 0 {
		t.Fatalf("expected upstream receive-pack bytes > 0 in PASSIVE_AUDIT during outage")
	}
}

// =============================================================================
// EF6: Publisher Isolation Boundaries (5 tests)
// =============================================================================

func TestT2_PG_EF06_PassiveAuditUnenforcedDecisionRejectedByPublisher(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT")
	actors := pgMintActors(env)
	propID, prop := t2pgPrepareApprovedV1Proposal(t, env, actors, repo)

	// Mutate latest policy_decision for this proposal to enforced=false (simulating PASSIVE_AUDIT decision).
	if _, err := env.DB().ExecSQL(fmt.Sprintf(
		"UPDATE policy_decisions SET enforced = false WHERE proposal_id = %s::uuid;",
		t2pgSQLLiteral(propID),
	)); err != nil {
		t.Fatalf("update policy_decisions enforced=false: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pubResp, raw, err := actors.CtrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	if raw.StatusCode == http.StatusForbidden || raw.StatusCode == http.StatusConflict {
		t2pgAssertErrorEnvelope(t, raw)
	} else {
		raw.RequireStatus(t, http.StatusAccepted)
		if pubResp.OperationID == "" {
			t.Fatalf("expected OperationID on 202 Accepted PublishProposal response, got %+v", pubResp)
		}
		op, waitErr := actors.CtrlCli.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		if waitErr == nil && op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
			t.Fatalf("expected async publish operation %s to fail when policy_decision.enforced=false, got status=%q last_error=%q", pubResp.OperationID, op.Status, op.LastError)
		}
	}

	pubRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT count(*) FROM publications WHERE proposal_id = %s::uuid AND status IN ('PUBLISHED', 'SUCCEEDED');",
		t2pgSQLLiteral(propID),
	))
	if err != nil {
		t.Fatalf("query publications: %v", err)
	}
	if len(pubRows) == 0 || pubRows[0][0] != "0" {
		t.Fatalf("expected 0 PUBLISHED/SUCCEEDED publications when policy_decision.enforced=false, got %+v", pubRows)
	}
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs when policy_decision.enforced=false")
	}
}

func TestT2_PG_EF06_PushEgressAllowDecisionRejectedByPublisher(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	propID, prop := t2pgPrepareApprovedV1Proposal(t, env, actors, repo)

	// Mutate policy_decision stage to PUSH_EGRESS (even with enforced=true, effect=ALLOW) and align
	// proposals.latest_policy_effect so custodian-publisher reaches INVALID_POLICY_STAGE rather than STALE_POLICY_DECISION.
	if _, err := env.DB().ExecSQL(fmt.Sprintf(
		"UPDATE policy_decisions SET stage = 'PUSH_EGRESS', effect = 'ALLOW', enforced = true WHERE proposal_id = %s::uuid;",
		t2pgSQLLiteral(propID),
	)); err != nil {
		t.Fatalf("update policy_decisions stage=PUSH_EGRESS: %v", err)
	}
	if _, err := env.DB().ExecSQL(fmt.Sprintf(
		"UPDATE proposals SET latest_policy_effect = 'ALLOW' WHERE id = %s::uuid;",
		t2pgSQLLiteral(propID),
	)); err != nil {
		t.Fatalf("update proposals.latest_policy_effect=ALLOW: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	pubResp, raw, err := actors.CtrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	if raw.StatusCode == http.StatusForbidden || raw.StatusCode == http.StatusConflict {
		t2pgAssertErrorEnvelope(t, raw)
	} else {
		raw.RequireStatus(t, http.StatusAccepted)
		if pubResp.OperationID == "" {
			t.Fatalf("expected OperationID on 202 Accepted PublishProposal response, got %+v", pubResp)
		}
		op, waitErr := actors.CtrlCli.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		if waitErr == nil && op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
			t.Fatalf("expected async publish operation %s to fail when policy_decision.stage=PUSH_EGRESS, got status=%q last_error=%q", pubResp.OperationID, op.Status, op.LastError)
		}
	}

	pubRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT count(*) FROM publications WHERE proposal_id = %s::uuid AND status IN ('PUBLISHED', 'SUCCEEDED');",
		t2pgSQLLiteral(propID),
	))
	if err != nil {
		t.Fatalf("query publications: %v", err)
	}
	if len(pubRows) == 0 || pubRows[0][0] != "0" {
		t.Fatalf("expected 0 PUBLISHED/SUCCEEDED publications when policy_decision.stage=PUSH_EGRESS, got %+v", pubRows)
	}
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs when policy_decision.stage=PUSH_EGRESS")
	}
}

func TestT2_PG_EF06_PublisherBinaryZeroForbiddenDependencies(t *testing.T) {
	pgRequireGatewayBinary(t)
	root := pgFindRepoRoot(t)
	goBin := strings.TrimSpace(os.Getenv("CUSTODIAN_GO_BIN"))
	if goBin == "" {
		if p, err := exec.LookPath("go"); err == nil {
			goBin = p
		} else {
			goBin = "/Users/tim/Code/github.com/timreynolds/forge/data/kind/tools/go/bin/go"
		}
	}

	cmd := exec.Command(goBin, "list", "-f", `{{range .Deps}}{{.}}{{"\n"}}{{end}}`, "./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish")
	cmd.Dir = root
	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps publisher packages failed: %v\n%s", err, string(outBytes))
	}
	deps := strings.Split(string(outBytes), "\n")
	forbiddenPrefixes := []string{
		"github.com/timreynolds/custodian/internal/gitgateway",
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/git/checkout",
		"github.com/timreynolds/custodian/internal/git/reconstruct",
		"github.com/google/cel-go",
		"golang.org/x/crypto/ssh",
	}
	const forbiddenExact = "github.com/timreynolds/custodian/internal/github"

	for _, d := range deps {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if d == forbiddenExact {
			t.Fatalf("publisher packages illegally depend on %q", d)
		}
		for _, p := range forbiddenPrefixes {
			if d == p || strings.HasPrefix(d, p+"/") {
				t.Fatalf("publisher packages illegally depend on forbidden prefix %q (dep=%q)", p, d)
			}
		}
	}
}

func TestT2_PG_EF06_GatewayReadPathNeverUsesOrLeaksWriteKeys(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	t2pgEnsurePrincipalSeeded(t, env, actors.HumanATok)

	// 1. HTTPS read clone through gateway.
	_, httpCloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if httpCloneRes.ExitCode != 0 {
		t.Fatalf("HTTP clone failed: %s", httpCloneRes.Stderr)
	}

	// 2. SSH read clone through gateway.
	cred := env.SSHCA().MintValidCert("alice-read", []string{"alice-human-001"})
	_, sshCloneRes := pgGitCloneSSH(t, t2pgGatewaySSHURL(env, "alice-human-001", repo.FullName), cred, env.GitGatewaySSHAddr(), env.SSHCA())
	if sshCloneRes.ExitCode != 0 {
		t.Fatalf("SSH clone failed: %s", sshCloneRes.Stderr)
	}

	env.AssertNoSecretLeakInLogs(env.GitHub().WriteAppPrivateKeyPEM(), env.GitHub().ReadAppPrivateKeyPEM())
	if len(env.GitHub().ReceivePackCalls()) != 0 || len(env.GitHub().PushAttempts()) != 0 {
		t.Fatalf("read clones must trigger 0 receive-pack/push attempts")
	}

	rows, err := env.DB().QueryRows("SELECT count(*) FROM publications;")
	if err != nil {
		t.Fatalf("query publications: %v", err)
	}
	if len(rows) == 0 || rows[0][0] != "0" {
		t.Fatalf("expected 0 publications from read path, got %+v", rows)
	}
}

func TestT2_PG_EF06_PassiveAuditFindingsNeverAutoPublish(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT")
	actors := pgMintActors(env)

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		FilePath:    "secret.env",
	})
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"secret.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"}, nil, "passive finding", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	pushRes := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if pushRes.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT push failed: %s", pushRes.Stderr)
	}

	_ = t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs created from PASSIVE_AUDIT push")
	}
	rows, err := env.DB().QueryRows("SELECT count(*) FROM publications;")
	if err != nil {
		t.Fatalf("query publications: %v", err)
	}
	if len(rows) == 0 || rows[0][0] != "0" {
		t.Fatalf("expected 0 publications rows from PASSIVE_AUDIT, got %+v", rows)
	}
}

// =============================================================================
// EF7: Hardened Quarantine, Streaming Bounds & Protocol Attacks (9 tests)
// =============================================================================

func TestT2_PG_EF07_MaxPackBytesExceededFailsClosed(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayMaxPackBytes(4096)),
	)
	actors := pgMintActors(env)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	noise := make([]byte, 8192)
	if _, err := rand.Read(noise); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"noise.bin": string(noise)}, nil, "exceed max_pack_bytes", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF07_MaxObjectsExceededFailsClosed(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayMaxObjects(5)),
	)
	actors := pgMintActors(env)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	files := make(map[string]string, 10)
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("dir_%d/f_%d.txt", i, i)] = fmt.Sprintf("distinct object payload %d\n", i)
	}
	_ = pgAddCommit(t, cloneDir, files, nil, "exceed max_objects", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF07_MaxRefUpdatesExceededFailsClosed(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayMaxRefUpdates(2)),
	)
	actors := pgMintActors(env)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"multi.txt": "three refs"}, nil, "3 ref updates", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	pushURL, err := pgInjectHTTPAuth(t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(cloneDir, map[string]string{"GIT_SSL_CAINFO": env.GitGatewayCACertPath()},
		"push", pushURL, "HEAD:refs/heads/b1", "HEAD:refs/heads/b2", "HEAD:refs/heads/b3",
	)
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF07_DeltaInflationExceededFailsClosed(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayMaxInflatedBytes(32768)),
	)
	actors := pgMintActors(env)
	headSHA := t2pgResolveRef(t, env, repo.FullName, "refs/heads/main")
	packBytes, commitHex := t2pgBuildDeltaBombPack(t, headSHA, 65536)

	rawBody := t2pgReceivePackBody([]string{headSHA + " " + commitHex + " refs/heads/main"}, packBytes)
	status, respBody := pgGitPushRawPack(t, t2pgGatewayRepoURL(env, repo.FullName)+"/git-receive-pack", actors.HumanATok, env.GitGatewayCACertPath(), rawBody)
	t2pgAssertRawPackRejected(t, status, respBody, "refs/heads/main", "delta bomb pack")
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF07_UnreferencedObjectsPackRejected(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	headSHA := t2pgResolveRef(t, env, repo.FullName, "refs/heads/main")

	cleanBlob := []byte("package main\nfunc helper() {}\n")
	cleanBlobOID := t2pgGitObjectID("blob", cleanBlob)
	orphanBlob := []byte("unreferenced orphan payload smuggling attempt\n")

	var tree bytes.Buffer
	tree.WriteString("100644 helper.go\x00")
	tree.Write(cleanBlobOID[:])
	treeOID := t2pgGitObjectID("tree", tree.Bytes())
	commitData, commitOID := t2pgBuildRawCommit(treeOID, headSHA, "commit with orphan blob")

	pack := t2pgBuildPack(t, []t2pgPackEntry{
		{Type: 3, Data: cleanBlob},
		{Type: 3, Data: orphanBlob},
		{Type: 2, Data: tree.Bytes()},
		{Type: 1, Data: commitData},
	})
	rawBody := t2pgReceivePackBody([]string{headSHA + " " + hex.EncodeToString(commitOID[:]) + " refs/heads/main"}, pack)
	status, respBody := pgGitPushRawPack(t, t2pgGatewayRepoURL(env, repo.FullName)+"/git-receive-pack", actors.HumanATok, env.GitGatewayCACertPath(), rawBody)
	t2pgAssertRawPackRejected(t, status, respBody, "refs/heads/main", "unreferenced object pack")
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF07_MalformedPackChecksumRejected(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"good.txt": "corrupt trailer"}, nil, "corrupt pack", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	packBytes, oldOID, newOID := t2pgBuildValidCommitPack(t, cloneDir, "HEAD:refs/heads/main")
	if len(packBytes) < 32 {
		t.Fatalf("unexpected short pack: %d", len(packBytes))
	}
	packBytes[len(packBytes)-1] ^= 0xff

	rawBody := t2pgReceivePackBody([]string{oldOID + " " + newOID + " refs/heads/main"}, packBytes)
	status, respBody := pgGitPushRawPack(t, t2pgGatewayRepoURL(env, repo.FullName)+"/git-receive-pack", actors.HumanATok, env.GitGatewayCACertPath(), rawBody)
	t2pgAssertRawPackRejected(t, status, respBody, "refs/heads/main", "corrupt checksum pack")
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF07_DisallowedRefsReplaceAndPathTraversalRejected(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	headSHA := t2pgResolveRef(t, env, repo.FullName, "refs/heads/main")

	// 1. Disallowed refs/replace/* update via real git push.
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	newSHA := pgAddCommit(t, cloneDir, map[string]string{"rep.txt": "replace ref"}, nil, "replace commit", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	if res := pgRunHardenedGit(cloneDir, nil, "update-ref", "refs/replace/"+headSHA, newSHA); res.ExitCode != 0 {
		t.Fatalf("git update-ref failed: %s", res.Stderr)
	}
	pushRes := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "refs/replace/"+headSHA+":refs/replace/"+headSHA, env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, pushRes, env, repo.FullName)

	// 2. Path traversal entry "../escape.txt" and ".git/hooks/post-receive" inside raw Git tree.
	for _, badPath := range []string{"../escape.txt", ".git/hooks/post-receive"} {
		pack, commitHex := t2pgBuildTraversalTreePack(t, headSHA, badPath)
		rawBody := t2pgReceivePackBody([]string{headSHA + " " + commitHex + " refs/heads/main"}, pack)
		status, respBody := pgGitPushRawPack(t, t2pgGatewayRepoURL(env, repo.FullName)+"/git-receive-pack", actors.HumanATok, env.GitGatewayCACertPath(), rawBody)
		t2pgAssertRawPackRejected(t, status, respBody, "refs/heads/main", "path traversal "+badPath)
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
}

func TestT2_PG_EF07_SymlinkEscapeAndSubmoduleGitmodulesRejected(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	headSHA := t2pgResolveRef(t, env, repo.FullName, "refs/heads/main")

	// 1. Symlink escape (mode 120000 pointing to /etc/passwd).
	clone1, res1 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res1.ExitCode != 0 {
		t.Fatalf("clone1 failed: %s", res1.Stderr)
	}
	_ = pgRunHardenedGit(clone1, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(clone1, nil, "config", "user.email", "alice@example.com")
	hashCmd := exec.Command("git", "hash-object", "-w", "--stdin")
	hashCmd.Dir = clone1
	hashCmd.Stdin = strings.NewReader("/etc/passwd")
	blobOut, err := hashCmd.Output()
	if err != nil {
		t.Fatalf("git hash-object symlink target: %v", err)
	}
	symlinkBlob := strings.TrimSpace(string(blobOut))
	if r := pgRunHardenedGit(clone1, nil, "update-index", "--add", "--cacheinfo", "120000,"+symlinkBlob+",escape-link"); r.ExitCode != 0 {
		t.Fatalf("git update-index symlink: %s", r.Stderr)
	}
	if r := pgRunHardenedGit(clone1, nil, "commit", "-m", "symlink escape"); r.ExitCode != 0 {
		t.Fatalf("git commit symlink: %s", r.Stderr)
	}
	push1 := pgGitPushHTTP(t, clone1, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, push1, env, repo.FullName)

	// 2. Submodule gitlink (mode 160000) + .gitmodules.
	clone2, res2 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res2.ExitCode != 0 {
		t.Fatalf("clone2 failed: %s", res2.Stderr)
	}
	_ = pgRunHardenedGit(clone2, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(clone2, nil, "config", "user.email", "alice@example.com")
	if err := os.WriteFile(filepath.Join(clone2, ".gitmodules"), []byte("[submodule \"sub\"]\n\tpath = sub\n\turl = ext::sh -c id\n"), 0o644); err != nil {
		t.Fatalf("write .gitmodules: %v", err)
	}
	if r := pgRunHardenedGit(clone2, nil, "add", ".gitmodules"); r.ExitCode != 0 {
		t.Fatalf("git add .gitmodules: %s", r.Stderr)
	}
	if r := pgRunHardenedGit(clone2, nil, "update-index", "--add", "--cacheinfo", "160000,"+headSHA+",sub"); r.ExitCode != 0 {
		t.Fatalf("git update-index submodule: %s", r.Stderr)
	}
	if r := pgRunHardenedGit(clone2, nil, "commit", "-m", "submodule attack"); r.ExitCode != 0 {
		t.Fatalf("git commit submodule: %s", r.Stderr)
	}
	push2 := pgGitPushHTTP(t, clone2, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/sub-branch", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, push2, env, repo.FullName)
}

func TestT2_PG_EF07_ScannerFilesSkippedFailsClosed(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	env.Scanners().Set(harness.ScannerSemgrep, harness.ScannerBehavior{
		Mode:         harness.ScannerModeFilesSkipped,
		SkippedPaths: []string{"huge.bin"},
	})
	cloneDir, cloneRes := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if cloneRes.ExitCode != 0 {
		t.Fatalf("clone failed: %s", cloneRes.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"huge.bin": "data"}, nil, "files skipped", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})

	pushRes := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, pushRes, env, repo.FullName)

	session := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if !harness.ContainsStatus([]string{"QUARANTINED", "BLOCKED"}, session.Status) {
		t.Fatalf("expected QUARANTINED/BLOCKED when FilesSkipped > 0, got %q", session.Status)
	}
}

// =============================================================================
// EF8: History Extraction, GIT_PUSH_BUNDLE & Manifest Digest Boundaries (5 tests)
// =============================================================================

func TestT2_PG_EF08_HistorySmugglingSecretDeletedBeforeTipBlocked(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cloneURL, err := pgInjectHTTPAuth(t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	workDir, _, _ := pgMakeHistorySmuggleRepo(
		t,
		cloneURL,
		map[string]string{"secrets.env": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"},
		map[string]string{"clean.go": string(t2pgReadFixture(t, "push_gateway/payloads/clean_feature.go"))},
		env.GitGatewayCACertPath(),
	)
	res := pgGitPushHTTP(t, workDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF08_HistorySmugglingRestrictedIPDeletedBeforeTipBlocked(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	restricted := string(t2pgReadFixture(t, "push_gateway/corpora/restricted/proprietary_engine.go"))
	_ = pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef08-restricted", "RESTRICTED", map[string]string{
		"proprietary_engine.go": restricted,
	})

	cloneURL, err := pgInjectHTTPAuth(t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	workDir, _, _ := pgMakeHistorySmuggleRepo(
		t,
		cloneURL,
		map[string]string{"engine/proprietary_engine.go": restricted},
		map[string]string{"clean.go": string(t2pgReadFixture(t, "push_gateway/payloads/clean_feature.go"))},
		env.GitGatewayCACertPath(),
	)
	res := pgGitPushHTTP(t, workDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, res, env, repo.FullName)
}

func TestT2_PG_EF08_SecretAndIPInCommitMessageOnlyBlocked(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	restricted := string(t2pgReadFixture(t, "push_gateway/corpora/restricted/proprietary_engine.go"))
	_ = pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef08-msg-ip", "RESTRICTED", map[string]string{
		"proprietary_engine.go": restricted,
	})

	// 1. Secret embedded in commit message only while tree is completely clean.
	clone1, res1 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res1.ExitCode != 0 {
		t.Fatalf("clone1 failed: %s", res1.Stderr)
	}
	_ = pgAddCommit(t, clone1, map[string]string{
		"clean.go": string(t2pgReadFixture(t, "push_gateway/payloads/clean_feature.go")),
	}, nil, "feat: clean file with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	push1 := pgGitPushHTTP(t, clone1, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, push1, env, repo.FullName)

	// 2. Restricted IP snippet embedded in commit message only.
	clone2, res2 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res2.ExitCode != 0 {
		t.Fatalf("clone2 failed: %s", res2.Stderr)
	}
	_ = pgAddCommit(t, clone2, map[string]string{
		"clean2.go": "package main\n",
	}, nil, "docs:\n\n"+restricted, harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	push2 := pgGitPushHTTP(t, clone2, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/ip-msg", env.GitGatewayCACertPath())
	t2pgAssertPushRejectedZeroUpstream(t, push2, env, repo.FullName)
}

func TestT2_PG_EF08_OneByteBlobEditMutatesPushManifestDigest(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	clone1, res1 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res1.ExitCode != 0 {
		t.Fatalf("clone1 failed: %s", res1.Stderr)
	}
	_ = pgAddCommit(t, clone1, map[string]string{"val.go": "package main\nfunc Val() int { return 1 }\n"}, nil, "v1", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	if r := pgGitPushHTTP(t, clone1, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/digest-check", env.GitGatewayCACertPath()); r.ExitCode != 0 {
		t.Fatalf("push A failed: %s", r.Stderr)
	}
	sessA := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if len(sessA.PushManifestDigest) != 64 {
		t.Fatalf("expected 64-hex PushManifestDigest for push A, got %q", sessA.PushManifestDigest)
	}

	// Delete the branch in the upstream bare repo so push B uses the exact same ref_name and old_oid (0000...).
	if r := pgRunHardenedGit(repo.BarePath, nil, "update-ref", "-d", "refs/heads/digest-check"); r.ExitCode != 0 {
		t.Fatalf("delete upstream refs/heads/digest-check: %s", r.Stderr)
	}

	clone2, res2 := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res2.ExitCode != 0 {
		t.Fatalf("clone2 failed: %s", res2.Stderr)
	}
	_ = pgAddCommit(t, clone2, map[string]string{"val.go": "package main\nfunc Val() int { return 2 }\n"}, nil, "v1", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	if r := pgGitPushHTTP(t, clone2, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/digest-check", env.GitGatewayCACertPath()); r.ExitCode != 0 {
		t.Fatalf("push B failed: %s", r.Stderr)
	}
	sessB := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)
	if len(sessB.PushManifestDigest) != 64 {
		t.Fatalf("expected 64-hex PushManifestDigest for push B, got %q", sessB.PushManifestDigest)
	}
	if sessA.ID == sessB.ID {
		t.Fatalf("expected distinct push sessions for push A and push B, got %q", sessA.ID)
	}
	if sessA.PushManifestDigest == sessB.PushManifestDigest {
		t.Fatalf("expected 1-byte blob edit to mutate push_manifest_digest, both were %q", sessA.PushManifestDigest)
	}
}

func TestT2_PG_EF08_CommitAmendMutatesPushManifestDigest(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	cloneDir, res := pgGitCloneHTTP(t, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("clone failed: %s", res.Stderr)
	}
	_ = pgAddCommit(t, cloneDir, map[string]string{"feature.go": "package main\nfunc Feature() {}\n"}, nil, "initial feature", harness.GitIdentity{Name: "Alice", Email: "alice@example.com"})
	if r := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/digest-check", env.GitGatewayCACertPath()); r.ExitCode != 0 {
		t.Fatalf("push A failed: %s", r.Stderr)
	}
	sessA := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)

	// Delete the branch in the upstream bare repo so push B uses the exact same ref_name and old_oid (0000...).
	if r := pgRunHardenedGit(repo.BarePath, nil, "update-ref", "-d", "refs/heads/digest-check"); r.ExitCode != 0 {
		t.Fatalf("delete upstream refs/heads/digest-check: %s", r.Stderr)
	}

	if r := pgRunHardenedGit(cloneDir, map[string]string{
		"GIT_AUTHOR_NAME":     "Alice Developer",
		"GIT_AUTHOR_EMAIL":    "alice@example.com",
		"GIT_COMMITTER_NAME":  "Alice Developer",
		"GIT_COMMITTER_EMAIL": "alice@example.com",
	}, "commit", "--amend", "-m", "amended feature message"); r.ExitCode != 0 {
		t.Fatalf("git commit --amend failed: %s", r.Stderr)
	}
	if r := pgGitPushHTTP(t, cloneDir, t2pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/digest-check", env.GitGatewayCACertPath()); r.ExitCode != 0 {
		t.Fatalf("push B failed: %s", r.Stderr)
	}
	sessB := t2pgLatestPushForRepo(t, actors.AuditorCli, repoID)

	if len(sessA.PushManifestDigest) != 64 || len(sessB.PushManifestDigest) != 64 {
		t.Fatalf("expected 64-hex digests, got A=%q B=%q", sessA.PushManifestDigest, sessB.PushManifestDigest)
	}
	if sessA.ID == sessB.ID {
		t.Fatalf("expected distinct push sessions for push A and push B, got %q", sessA.ID)
	}
	if sessA.PushManifestDigest == sessB.PushManifestDigest {
		t.Fatalf("expected commit --amend to mutate push_manifest_digest, both were %q", sessA.PushManifestDigest)
	}
}
