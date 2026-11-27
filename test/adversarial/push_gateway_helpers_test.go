package adversarial_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/snapshots"
	"github.com/timreynolds/custodian/internal/workflow"
	"github.com/timreynolds/custodian/internal/workspaces"
	"github.com/timreynolds/custodian/test/fixtures"
)

type advLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *advLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *advLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type advReceivePackCall struct {
	OwnerRepo string
	Token     string
	Bytes     int64
	SHA256    string
}

type advUpstreamGitServer struct {
	mu                  sync.Mutex
	server              *httptest.Server
	repos               map[string]string
	lfsObjects          map[string]map[string][]byte
	requireWriteTok     string
	infoRefsCalls       int
	uploadPackCalls     int
	receivePackCalls    []advReceivePackCall
	receivePackBytes    int64
	lfsBatchCalls       int
	lfsUploadBytes      int64
	seenAuthTokens      []string
	receivePackOverride func(ownerRepo string, body []byte) (status int, respBody []byte, handled bool)
	uploadPackOverride  func(ownerRepo string, body []byte) (status int, respBody []byte, handled bool)
}

func newAdvUpstreamGitServer(t *testing.T, writeTok string) *advUpstreamGitServer {
	t.Helper()
	m := &advUpstreamGitServer{
		repos:           make(map[string]string),
		lfsObjects:      make(map[string]map[string][]byte),
		requireWriteTok: writeTok,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

func (m *advUpstreamGitServer) setReceivePackOverride(fn func(ownerRepo string, body []byte) (int, []byte, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.receivePackOverride = fn
}

func (m *advUpstreamGitServer) setUploadPackOverride(fn func(ownerRepo string, body []byte) (int, []byte, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploadPackOverride = fn
}

func (m *advUpstreamGitServer) resetCounters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infoRefsCalls = 0
	m.uploadPackCalls = 0
	m.receivePackCalls = nil
	m.receivePackBytes = 0
	m.lfsBatchCalls = 0
	m.lfsUploadBytes = 0
}

func (m *advUpstreamGitServer) stats() (recvCalls int, recvBytes int64, infoRefs int, uploadCalls int, lfsBatch int, lfsBytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.receivePackCalls), m.receivePackBytes, m.infoRefsCalls, m.uploadPackCalls, m.lfsBatchCalls, m.lfsUploadBytes
}

func (m *advUpstreamGitServer) receiveCallsFor(ownerRepo string) []advReceivePackCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []advReceivePackCall
	for _, c := range m.receivePackCalls {
		if c.OwnerRepo == ownerRepo {
			out = append(out, c)
		}
	}
	return out
}

func (m *advUpstreamGitServer) seenTokens() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.seenAuthTokens...)
}

func (m *advUpstreamGitServer) barePath(ownerRepo string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repos[ownerRepo]
}

func (m *advUpstreamGitServer) bareObjectCount(t *testing.T, ownerRepo string) int {
	t.Helper()
	bp := m.barePath(ownerRepo)
	if bp == "" {
		return 0
	}
	out, code := runAdvGit(t, bp, nil, "rev-list", "--all", "--objects")
	if code != 0 {
		t.Fatalf("rev-list --all --objects failed: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return 0
	}
	return len(lines)
}

func (m *advUpstreamGitServer) bareRefSHA(t *testing.T, ownerRepo, refName string) string {
	t.Helper()
	bp := m.barePath(ownerRepo)
	if bp == "" {
		return ""
	}
	out, code := runAdvGit(t, bp, nil, "rev-parse", "--verify", refName)
	if code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func (m *advUpstreamGitServer) seedBareRepo(t *testing.T, fullName string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	bareDir := filepath.Join(root, "bare.git")
	workDir := filepath.Join(root, "work")

	mustAdvGit(t, "", nil, "init", "--bare", "--initial-branch=main", bareDir)
	mustAdvGit(t, "", nil, "init", "--initial-branch=main", workDir)
	mustAdvGit(t, workDir, nil, "config", "user.name", "Upstream Seed")
	mustAdvGit(t, workDir, nil, "config", "user.email", "seed@example.com")
	for rel, content := range files {
		full := filepath.Join(workDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	mustAdvGit(t, workDir, nil, "add", ".")
	mustAdvGit(t, workDir, nil, "commit", "-m", "initial upstream commit")
	mustAdvGit(t, workDir, nil, "push", bareDir, "HEAD:refs/heads/main")
	headSHA := strings.TrimSpace(mustAdvGit(t, bareDir, nil, "rev-parse", "refs/heads/main"))

	m.mu.Lock()
	m.repos[fullName] = bareDir
	m.mu.Unlock()
	return headSHA
}

func (m *advUpstreamGitServer) addCommitToRepo(t *testing.T, fullName, relPath, content string) string {
	t.Helper()
	bareDir := m.barePath(fullName)
	if bareDir == "" {
		t.Fatalf("addCommitToRepo: repo %s not seeded", fullName)
	}
	workDir := filepath.Join(t.TempDir(), "work")
	mustAdvGit(t, "", nil, "clone", bareDir, workDir)
	mustAdvGit(t, workDir, nil, "config", "user.name", "Upstream Advance")
	mustAdvGit(t, workDir, nil, "config", "user.email", "advance@example.com")
	full := filepath.Join(workDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	mustAdvGit(t, workDir, nil, "add", relPath)
	mustAdvGit(t, workDir, nil, "commit", "-m", "advance "+relPath)
	mustAdvGit(t, workDir, nil, "push", bareDir, "HEAD:refs/heads/main")
	return strings.TrimSpace(mustAdvGit(t, bareDir, nil, "rev-parse", "refs/heads/main"))
}

func (m *advUpstreamGitServer) putLFSObject(fullName, oid string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lfsObjects[fullName] == nil {
		m.lfsObjects[fullName] = make(map[string][]byte)
	}
	m.lfsObjects[fullName][oid] = append([]byte(nil), data...)
}

func (m *advUpstreamGitServer) lfsObject(fullName, oid string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.lfsObjects[fullName][oid]
	return b, ok
}

func (m *advUpstreamGitServer) serve(w http.ResponseWriter, r *http.Request) {
	idx := strings.Index(r.URL.Path, ".git/")
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	fullName := strings.TrimPrefix(r.URL.Path[:idx], "/")
	suffix := r.URL.Path[idx+len(".git"):]
	m.mu.Lock()
	bareDir, ok := m.repos[fullName]
	override := m.receivePackOverride
	upOverride := m.uploadPackOverride
	reqWriteTok := m.requireWriteTok
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	tok := ""
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		tok = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
	}
	if tok != "" {
		m.mu.Lock()
		m.seenAuthTokens = append(m.seenAuthTokens, tok)
		m.mu.Unlock()
	}

	switch {
	case suffix == "/info/refs":
		svc := r.URL.Query().Get("service")
		m.mu.Lock()
		m.infoRefsCalls++
		m.mu.Unlock()
		if svc == "git-receive-pack" && reqWriteTok != "" && tok != reqWriteTok {
			http.Error(w, "write token required", http.StatusForbidden)
			return
		}
		cmdName := strings.TrimPrefix(svc, "git-")
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", "--advertise-refs", bareDir)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-"+svc+"-advertisement")
		pkt := fmt.Sprintf("# service=%s\n", svc)
		_, _ = fmt.Fprintf(w, "%04x%s0000", len(pkt)+4, pkt)
		_, _ = w.Write(out)

	case suffix == "/git-upload-pack":
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.uploadPackCalls++
		m.mu.Unlock()
		if upOverride != nil {
			if st, respBody, handled := upOverride(fullName, body); handled {
				w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
				w.WriteHeader(st)
				_, _ = w.Write(respBody)
				return
			}
		}
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "upload-pack", "--stateless-rpc", bareDir)
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_, _ = w.Write(out)

	case suffix == "/git-receive-pack":
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		m.mu.Lock()
		m.receivePackCalls = append(m.receivePackCalls, advReceivePackCall{
			OwnerRepo: fullName,
			Token:     tok,
			Bytes:     int64(len(body)),
			SHA256:    hex.EncodeToString(sum[:]),
		})
		m.receivePackBytes += int64(len(body))
		m.mu.Unlock()
		if override != nil {
			if st, respBody, handled := override(fullName, body); handled {
				w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
				w.WriteHeader(st)
				_, _ = w.Write(respBody)
				return
			}
		}
		if reqWriteTok != "" && tok != reqWriteTok {
			http.Error(w, "write token required", http.StatusForbidden)
			return
		}
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "receive-pack", "--stateless-rpc", bareDir)
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_, _ = w.Write(out)

	case suffix == "/info/lfs/objects/batch":
		m.mu.Lock()
		m.lfsBatchCalls++
		m.mu.Unlock()
		var req gitgateway.LFSBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Operation == "upload" && reqWriteTok != "" && tok != reqWriteTok {
			http.Error(w, "write token required", http.StatusForbidden)
			return
		}
		resp := gitgateway.LFSBatchResponse{Transfer: "basic", Objects: make([]gitgateway.LFSBatchObjectResponse, 0, len(req.Objects))}
		m.mu.Lock()
		objs := m.lfsObjects[fullName]
		for _, o := range req.Objects {
			item := gitgateway.LFSBatchObjectResponse{OID: o.OID, Size: o.Size, Authenticated: true}
			href := fmt.Sprintf("%s/%s.git/info/lfs/objects/%s", m.server.URL, fullName, o.OID)
			hdr := map[string]string{"Authorization": "Bearer " + tok}
			if req.Operation == "upload" {
				item.Actions = map[string]gitgateway.LFSAction{"upload": {Href: href, Header: hdr}}
			} else if _, exists := objs[o.OID]; exists {
				item.Actions = map[string]gitgateway.LFSAction{"download": {Href: href, Header: hdr}}
			} else {
				item.Error = &gitgateway.LFSError{Code: 404, Message: "not found"}
			}
			resp.Objects = append(resp.Objects, item)
		}
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_ = json.NewEncoder(w).Encode(resp)

	case strings.HasPrefix(suffix, "/info/lfs/objects/"):
		oid := strings.TrimPrefix(suffix, "/info/lfs/objects/")
		if r.Method == http.MethodPut {
			if reqWriteTok != "" && tok != reqWriteTok {
				http.Error(w, "write token required", http.StatusForbidden)
				return
			}
			data, _ := io.ReadAll(r.Body)
			m.mu.Lock()
			if m.lfsObjects[fullName] == nil {
				m.lfsObjects[fullName] = make(map[string][]byte)
			}
			m.lfsObjects[fullName][oid] = data
			m.lfsUploadBytes += int64(len(data))
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		m.mu.Lock()
		data, exists := m.lfsObjects[fullName][oid]
		m.mu.Unlock()
		if !exists {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)

	default:
		http.NotFound(w, r)
	}
}

type advStageBGateway struct {
	mu       sync.Mutex
	server   *httptest.Server
	requests []decisions.GatewayRequest
	fn       func(req decisions.GatewayRequest) (int, []byte)
}

func startAdvStageBGateway(t *testing.T) *advStageBGateway {
	t.Helper()
	m := &advStageBGateway{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req decisions.GatewayRequest
		_ = json.Unmarshal(body, &req)
		m.mu.Lock()
		m.requests = append(m.requests, req)
		fn := m.fn
		m.mu.Unlock()
		if fn != nil {
			st, resp := fn(req)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(st)
			_, _ = w.Write(resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mustAdvStageBResponse("IP_PROVENANCE", "CLEAR", "LOW", nil))
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *advStageBGateway) setHandler(fn func(req decisions.GatewayRequest) (int, []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fn = fn
}

func (m *advStageBGateway) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}

func (m *advStageBGateway) allRequests() []decisions.GatewayRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]decisions.GatewayRequest(nil), m.requests...)
}

func mustAdvStageBResponse(assessmentType, disposition, risk string, evidenceIDs []string) []byte {
	findings := []domain.AssessmentFinding{}
	if len(evidenceIDs) > 0 {
		findings = append(findings, domain.AssessmentFinding{
			Category:          "IP_PROVENANCE",
			EvidenceIDs:       evidenceIDs,
			Reason:            "Grounded Stage A evidence",
			RecommendedAction: "REVIEW",
		})
	}
	payload := map[string]any{
		"schema_version":  "1",
		"assessment_type": assessmentType,
		"risk":            risk,
		"disposition":     disposition,
		"confidence":      0.95,
		"summary":         "Adversarial test Stage B response",
		"findings":        findings,
		"limitations":     []string{},
	}
	inner, _ := json.Marshal(payload)
	outer, _ := json.Marshal(map[string]any{
		"model_version": "approved-code-review-v1",
		"cost_usd":      0.001,
		"choices": []map[string]any{
			{"message": map[string]any{"content": string(inner)}},
		},
	})
	return outer
}

type advScannerController struct {
	mu          sync.Mutex
	dir         string
	gitleaksBin string
	scancodeBin string
	semgrepBin  string
	trivyBin    string
	Config      inspection.Config
}

func newAdvScannerController(t *testing.T) *advScannerController {
	t.Helper()
	dir := t.TempDir()
	c := &advScannerController{dir: dir}
	c.setGitleaksMode("clean")
	c.setSemgrepMode("clean")

	writeBin := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatalf("write scanner stub %s: %v", name, err)
		}
		return p
	}

	c.gitleaksBin = writeBin("gitleaks", fmt.Sprintf(`#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "version" ] || [ "$a" = "--version" ] && echo "v8.18.4" && exit 0; done
SRC_DIR=""
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SRC_DIR="$2"; shift 2 ;;
    --report-path) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
MODE=$(cat %q 2>/dev/null || echo clean)
case "$MODE" in
  crash)
    echo "gitleaks crash" >&2
    exit 2
    ;;
  secret:*)
    SEC=${MODE#secret:}
    printf '[{"Description":"Secret","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":40,"Match":"TOK=%%s","Secret":"%%s","File":".env","RuleID":"generic-api-key","Fingerprint":"fp-sec-1"}]\n' "$SEC" "$SEC" > "$OUT_FILE"
    ;;
  *)
    if [ -n "$SRC_DIR" ] && grep -rq "AKIAIOSFODNN7EXAMPLE" "$SRC_DIR" 2>/dev/null; then
      MATCH_FILE=$(grep -rl "AKIAIOSFODNN7EXAMPLE" "$SRC_DIR" 2>/dev/null | head -n 1)
      REL_FILE=${MATCH_FILE#"$SRC_DIR"/}
      printf '[{"Description":"AWS Access Key","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":40,"Match":"AKIAIOSFODNN7EXAMPLE","Secret":"AKIAIOSFODNN7EXAMPLE","File":"%%s","RuleID":"aws-access-token","Fingerprint":"fp-aws-1"}]\n' "$REL_FILE" > "$OUT_FILE"
    else
      printf '[]\n' > "$OUT_FILE"
    fi
    ;;
esac
`, filepath.Join(dir, "gitleaks.mode")))

	c.scancodeBin = writeBin("scancode", `#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "--version" ] && echo "32.1.0" && exit 0; done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json-pp) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}\n' > "$OUT_FILE"
`)

	c.semgrepBin = writeBin("semgrep", fmt.Sprintf(`#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "--version" ] && echo "1.90.0" && exit 0; done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
MODE=$(cat %q 2>/dev/null || echo clean)
case "$MODE" in
  crash)
    echo "semgrep fatal crash" >&2
    exit 2
    ;;
  timeout)
    sleep 4
    printf '{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["README.md"],"skipped":[]}}\n' > "$OUT_FILE"
    ;;
  skipped)
    printf '{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["README.md"],"skipped":["big.min.js"]}}\n' > "$OUT_FILE"
    ;;
  *)
    printf '{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["README.md"],"skipped":[]}}\n' > "$OUT_FILE"
    ;;
esac
`, filepath.Join(dir, "semgrep.mode")))

	c.trivyBin = writeBin("trivy", `#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "--version" ] && echo "Version: 0.58.0" && exit 0; done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}\n' > "$OUT_FILE"
`)

	c.Config = inspection.DefaultConfig()
	c.Config.GitleaksBin = c.gitleaksBin
	c.Config.ScanCodeBin = c.scancodeBin
	c.Config.SemgrepBin = c.semgrepBin
	c.Config.TrivyBin = c.trivyBin
	c.Config.ScannerTimeout = 10 * time.Second
	return c
}

func (c *advScannerController) setGitleaksMode(mode string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.WriteFile(filepath.Join(c.dir, "gitleaks.mode"), []byte(mode), 0o644)
}

func (c *advScannerController) setSemgrepMode(mode string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.WriteFile(filepath.Join(c.dir, "semgrep.mode"), []byte(mode), 0o644)
}

type advRefResolver struct {
	upstream *advUpstreamGitServer
}

func (r advRefResolver) ResolveRef(_ context.Context, repo domain.Repository, ref string) (string, error) {
	if bp := r.upstream.barePath(repo.FullName); bp != "" {
		cmd := exec.Command("git", "rev-parse", "--verify", ref)
		cmd.Dir = bp
		if out, err := cmd.Output(); err == nil {
			if sha := strings.TrimSpace(string(out)); sha != "" {
				return sha, nil
			}
		}
	}
	return strings.Repeat("a", 40), nil
}

type advIPCorpusReindexer struct {
	indexer *fingerprints.CorpusIndexer
}

func (a *advIPCorpusReindexer) Reindex(ctx context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	dir := strings.TrimSpace(input.SourcePath)
	files := make([]fingerprints.CorpusFile, 0, len(input.Files))
	for _, f := range input.Files {
		files = append(files, fingerprints.CorpusFile{
			Path:    f.Path,
			Content: []byte(f.Content),
			SHA256:  f.SHA256,
		})
	}
	if dir == "" && len(files) == 0 && input.Corpus.Status == domain.IPCorpusStatusReady && input.Corpus.FingerprintCount > 0 {
		return api.IPCorpusReindexResult{
			Status:              domain.IPCorpusStatusReady,
			FingerprintsIndexed: input.Corpus.FingerprintCount,
			FilesProcessed:      0,
			LastIndexedDigest:   input.Corpus.LastIndexedDigest,
			CompletedAt:         input.Corpus.LastIndexedAt,
		}, nil
	}
	res, err := a.indexer.Index(ctx, fingerprints.IndexRequest{
		CorpusID: input.Corpus.ID,
		Dir:      dir,
		Files:    files,
		Force:    input.Force,
	})
	if err != nil {
		return api.IPCorpusReindexResult{}, err
	}
	return api.IPCorpusReindexResult{
		Status:              res.Corpus.Status,
		FingerprintsIndexed: res.FingerprintCount,
		FilesProcessed:      int64(res.FilesIndexed),
		LastIndexedDigest:   res.Corpus.LastIndexedDigest,
		CompletedAt:         res.Corpus.LastIndexedAt,
	}, nil
}

type pgAdvOptions struct {
	limits              quarantine.Limits
	scannerTimeout      time.Duration
	modelGatewayTimeout time.Duration
	inspectionRunner    inspection.Runner
	snapshotStore       domain.SnapshotStore
	corpusReindexer     func(base api.IPCorpusReindexer) api.IPCorpusReindexer
}

type pgAdvStack struct {
	t            *testing.T
	repoRoot     string
	pg           *harness.PostgresHarness
	store        *persistence.Store
	snapStore    *snapshots.LocalStore
	oidc         *harness.MockOIDC
	upstream     *advUpstreamGitServer
	gwServer     *gitgateway.Server
	gwHTTP       *httptest.Server
	apiServer    *httptest.Server
	caFile       string
	sshAddr      string
	sshHostPub   ssh.PublicKey
	sshHostLine  string
	caPrivPath   string
	caSigner     ssh.Signer
	rogueCAPath  string
	rogueSigner  ssh.Signer
	scanners     *advScannerController
	stageBGW     *advStageBGateway
	auditSvc     *audit.Service
	reposSvc     *repositories.Service
	metrics      *observability.Metrics
	policyEngine *policy.Engine
	indexer      *fingerprints.CorpusIndexer
	alice        persistence.PrincipalRow
	bob          persistence.PrincipalRow
	admin        persistence.PrincipalRow
	auditor      persistence.PrincipalRow
	aliceJWT     string
	bobJWT       string
	adminJWT     string
	auditorJWT   string
	repo         persistence.RepositoryRow
	writeTok     string
	readTok      string
	logBuf       *advLogBuffer
	secrets      []string
	ghPEM        []byte
	capSecret    []byte
}

func newPGAdvStack(t *testing.T, optFns ...func(*pgAdvOptions)) *pgAdvStack {
	t.Helper()
	// CRITICAL: StartPostgres with WithPGAllowDockerSkip(true) MUST run first so
	// `make test-unit` (`go test -race -short ./...`) skips cleanly without Docker!
	pg := harness.StartPostgres(t, harness.WithPGAllowDockerSkip(true))

	opts := pgAdvOptions{
		scannerTimeout:      10 * time.Second,
		modelGatewayTimeout: 5 * time.Second,
	}
	for _, fn := range optFns {
		if fn != nil {
			fn(&opts)
		}
	}

	ctx := context.Background()
	repoRoot := fixtures.FindRepoRoot(t)

	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)

	logBuf := &advLogBuffer{}
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    logBuf,
		Format:    observability.LogFormatJSON,
		Level:     slog.LevelDebug,
		Component: "custodian-adv-pg",
	})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	oidc := harness.StartMockOIDC(t, "custodian-api")
	verifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   oidc.Issuer(),
		JWKSURL:  oidc.JWKSURL(),
		Audience: oidc.Audience(),
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	capSvc, err := auth.NewCapabilityService(auth.CapabilityConfig{
		Secret:     []byte("adv-api-capability-secret-32-bytes!!"),
		DefaultTTL: 5 * time.Minute,
		MaxTTL:     15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewCapabilityService: %v", err)
	}
	dir, err := identity.NewDirectory(store, identity.DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	snapH := harness.NewSnapshotHarness(t)
	writeTok := "ghs_write_adv_secret_token_987654"
	readTok := "ghs_read_adv_secret_token_123456"
	upstream := newAdvUpstreamGitServer(t, writeTok)
	upstream.seedBareRepo(t, "acme/service", map[string]string{
		"README.md": "# acme/service\n",
		"main.go":   "package main\n\nfunc main() {}\n",
	})

	scanners := newAdvScannerController(t)
	if opts.scannerTimeout > 0 {
		scanners.Config.ScannerTimeout = opts.scannerTimeout
	}
	scanners.Config.IPFingerprinter = fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:        store,
		RequireStore: true,
	})
	scanners.Config.Metrics = metrics
	scanners.Config.Logger = logger

	stageBGW := startAdvStageBGateway(t)
	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{
		BaseURL:          stageBGW.server.URL,
		Timeout:          opts.modelGatewayTimeout,
		MaxResponseBytes: decisions.DefaultMaxResponseBytes,
	})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	decSvc, err := decisions.NewService(gwClient, decisions.WithMetrics(metrics), decisions.WithLogger(logger))
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}

	policyEngine, err := policy.NewEngine(policy.WithMetrics(metrics), policy.WithLogger(logger))
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	if _, err := workflow.SyncPolicyDir(ctx, store, policyEngine, filepath.Join(repoRoot, "policies", "defaults"), time.Now().UTC()); err != nil {
		t.Fatalf("SyncPolicyDir: %v", err)
	}

	_, ghPEM := generateAdvRSAPrivateKeyAndPEM(t)
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens"):
			tok := writeTok
			if strings.Contains(r.URL.Path, "/installations/2001/") {
				// Distinguish read vs write via JWT issuer if needed, or return writeTok/readTok.
				tok = writeTok
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      tok,
				"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/installation"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": int64(2001)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ghAPI.Close)

	broker, err := gitgateway.NewTokenBroker(gitgateway.TokenBrokerConfig{
		APIBaseURL:         ghAPI.URL,
		ReadAppID:          101,
		ReadPrivateKeyPEM:  ghPEM,
		WriteAppID:         102,
		WritePrivateKeyPEM: ghPEM,
		Logger:             logger,
	})
	if err != nil {
		t.Fatalf("NewTokenBroker: %v", err)
	}
	upClient, err := gitgateway.NewHTTPUpstreamClient(gitgateway.HTTPUpstreamConfig{
		BaseURL:           upstream.server.URL,
		AllowInsecureHTTP: true,
		Logger:            logger,
	})
	if err != nil {
		t.Fatalf("NewHTTPUpstreamClient: %v", err)
	}

	aliceID, _ := domain.NewID()
	alice, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		ID:            aliceID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "alice-human-001",
		DisplayName:   "Alice Developer",
		VerifiedEmail: "alice@example.com",
		Groups:        []string{"engineering"},
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(alice): %v", err)
	}
	bobID, _ := domain.NewID()
	bob, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		ID:            bobID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "bob-human-002",
		DisplayName:   "Bob Security",
		VerifiedEmail: "bob@example.com",
		Groups:        []string{"security-admins", "ip-review"},
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(bob): %v", err)
	}
	adminID, _ := domain.NewID()
	admin, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		ID:            adminID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "admin-human-003",
		DisplayName:   "Admin Ops",
		VerifiedEmail: "admin@example.com",
		Groups:        []string{"security-admins", "policy-admins", "ip-review"},
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(admin): %v", err)
	}
	auditorID, _ := domain.NewID()
	auditor, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		ID:            auditorID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "auditor-004",
		DisplayName:   "Auditor",
		VerifiedEmail: "auditor@example.com",
		Groups:        []string{"auditors"},
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(auditor): %v", err)
	}

	regTrue, extFalse := true, false
	repoRow, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:    1001,
		GitHubInstallationID:  2001,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		AllowedModelRoutes:    []string{"approved-code-review"},
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		GitRemoteURL:          upstream.server.URL + "/acme/service.git",
		RemoteHost:            "github.com",
		RegisteredDestination: &regTrue,
		External:              &extFalse,
	})
	if err != nil {
		t.Fatalf("UpsertRepository: %v", err)
	}

	// Generate SSH Host Key, Trusted User CA, and Rogue CA.
	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostSSHPub, _ := ssh.NewPublicKey(hostPub)

	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caSSHPub := caSigner.PublicKey()
	caBlock, _ := ssh.MarshalPrivateKey(caPriv, "")
	caPrivPath := filepath.Join(t.TempDir(), "user_ca")
	if err := os.WriteFile(caPrivPath, pem.EncodeToMemory(caBlock), 0o600); err != nil {
		t.Fatalf("WriteFile(user_ca): %v", err)
	}
	if err := os.WriteFile(caPrivPath+".pub", ssh.MarshalAuthorizedKey(caSSHPub), 0o644); err != nil {
		t.Fatalf("WriteFile(user_ca.pub): %v", err)
	}

	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	rogueSigner, _ := ssh.NewSignerFromKey(roguePriv)
	rogueBlock, _ := ssh.MarshalPrivateKey(roguePriv, "")
	rogueCAPath := filepath.Join(t.TempDir(), "rogue_ca")
	if err := os.WriteFile(rogueCAPath, pem.EncodeToMemory(rogueBlock), 0o600); err != nil {
		t.Fatalf("WriteFile(rogue_ca): %v", err)
	}
	if err := os.WriteFile(rogueCAPath+".pub", ssh.MarshalAuthorizedKey(rogueSigner.PublicKey()), 0o644); err != nil {
		t.Fatalf("WriteFile(rogue_ca.pub): %v", err)
	}

	authenticator, err := gitgateway.NewAuthenticator(gitgateway.AuthenticatorConfig{
		OIDC:       verifier,
		Directory:  dir,
		Store:      store,
		SSHHostKey: hostSigner,
		SSHUserCA:  caSSHPub,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	resolver, err := gitgateway.NewTargetResolver(gitgateway.TargetResolverConfig{
		Store:                store,
		UpstreamBaseURL:      upstream.server.URL,
		DefaultEgressMode:    domain.EgressModeEnforceBlock,
		DefaultAuditDelivery: domain.PassiveAuditDeliveryAsync,
	})
	if err != nil {
		t.Fatalf("NewTargetResolver: %v", err)
	}

	unpacker, err := quarantine.NewQuarantineUnpacker(quarantine.UnpackerConfig{
		DefaultLimits: opts.limits,
		SnapshotStore: nil,
		Metrics:       metrics,
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	auditSvc := audit.NewService(store, logger)
	snapStoreForPipeline := domain.SnapshotStore(snapH.Store())
	if opts.snapshotStore != nil {
		snapStoreForPipeline = opts.snapshotStore
	}
	pCfg := gitgateway.PipelineConfig{
		Store:              store,
		SnapshotStore:      snapStoreForPipeline,
		QuarantineUnpacker: unpacker,
		PolicyEngine:       policyEngine,
		PolicyDir:          filepath.Join(repoRoot, "policies", "defaults"),
		InspectionConfig:   scanners.Config,
		InspectionRunner:   opts.inspectionRunner,
		DecisionsService:   decSvc,
		TokenBroker:        broker,
		Upstream:           upClient,
		AuditService:       auditSvc,
		Limits:             opts.limits,
		Metrics:            metrics,
		Logger:             logger,
	}
	handler, err := gitgateway.NewPipelineReceivePackHandler(pCfg)
	if err != nil {
		t.Fatalf("NewPipelineReceivePackHandler: %v", err)
	}

	capSecret := []byte("adv-lfs-capability-secret-32bytes!!")
	gwSrv, err := gitgateway.NewServer(gitgateway.ServerConfig{
		Store:               store,
		Authenticator:       authenticator,
		TargetResolver:      resolver,
		TokenBroker:         broker,
		Upstream:            upClient,
		ReceivePackHandler:  handler,
		Limits:              opts.limits,
		LFSCapabilitySecret: capSecret,
		Metrics:             metrics,
		Logger:              logger,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	certPair, _, caFile := generateAdvLocalhostTLSCert(t)
	gwHTTP := httptest.NewUnstartedServer(gwSrv.HTTPHandler())
	gwHTTP.TLS = &tls.Config{Certificates: []tls.Certificate{certPair}, MinVersion: tls.VersionTLS12}
	gwHTTP.StartTLS()
	t.Cleanup(gwHTTP.Close)

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(ssh): %v", err)
	}
	sshErrCh := make(chan error, 1)
	go func() {
		sshErrCh <- gwSrv.SSHServer().Serve(sshLn)
	}()
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = gwSrv.SSHServer().Shutdown(shutCtx)
		<-sshErrCh
	})

	_, sshPort, _ := net.SplitHostPort(sshLn.Addr().String())
	sshHostLine := fmt.Sprintf("[127.0.0.1]:%s %s", sshPort, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSSHPub))))

	// Control-Plane API router with IPCorpusReindexer explicitly wired.
	indexer := fingerprints.NewCorpusIndexer(store, fingerprints.NewPersistenceTxRunner(store))
	var reindexer api.IPCorpusReindexer = &advIPCorpusReindexer{indexer: indexer}
	if opts.corpusReindexer != nil {
		reindexer = opts.corpusReindexer(reindexer)
	}
	reposSvc := repositories.NewService(store, logger)
	wsSvc := workspaces.NewService(store, metrics, logger)
	opsSvc := operations.NewService(store, metrics, logger, operations.Config{DefaultLeaseDuration: 15 * time.Second})
	artSvc := artifacts.NewService(store, logger)
	propSvc := proposals.NewService(store, metrics, logger)
	appSvc := approvals.NewService(store, metrics, logger)

	apiRouter := api.NewRouter(api.Deps{
		Store:                store,
		OIDC:                 verifier,
		Capabilities:         capSvc,
		Directory:            dir,
		Snapshots:            snapStoreForPipeline,
		GitHubRead:           advRefResolver{upstream: upstream},
		Repositories:         reposSvc,
		Workspaces:           wsSvc,
		Operations:           opsSvc,
		Audit:                auditSvc,
		Artifacts:            artSvc,
		Proposals:            propSvc,
		Approvals:            appSvc,
		PolicyEngine:         policyEngine,
		IPCorpusReindexer:    reindexer,
		Metrics:              metrics,
		Logger:               logger,
		RepoConcurrencyLimit: 5,
		GlobalScanBudget:     10,
		GlobalModelBudget:    10,
		MaxUploadBytes:       16 << 20,
		CapabilityTTL:        5 * time.Minute,
		ArtifactRetentionTTL: 720 * time.Hour,
		MaxDiffBytes:         4 << 20,
	})
	apiServer := httptest.NewServer(apiRouter)
	t.Cleanup(apiServer.Close)

	ev := true
	aliceJWT := oidc.MintToken(harness.OIDCTokenClaims{
		Subject: "alice-human-001", Kind: "HUMAN", Email: "alice@example.com", EmailVerified: &ev,
		DisplayName: "Alice Developer", Groups: []string{"engineering"}, Roles: []string{"developer"},
	})
	bobJWT := oidc.MintToken(harness.OIDCTokenClaims{
		Subject: "bob-human-002", Kind: "HUMAN", Email: "bob@example.com", EmailVerified: &ev,
		DisplayName: "Bob Security", Groups: []string{"security-admins", "ip-review"}, Roles: []string{"reviewer"},
	})
	adminJWT := oidc.MintToken(harness.OIDCTokenClaims{
		Subject: "admin-human-003", Kind: "HUMAN", Email: "admin@example.com", EmailVerified: &ev,
		DisplayName: "Admin Ops", Groups: []string{"security-admins", "policy-admins", "ip-review"}, Roles: []string{"admin", "security-admin", "policy-admin", "reviewer"},
	})
	auditorJWT := oidc.MintToken(harness.OIDCTokenClaims{
		Subject: "auditor-004", Kind: "HUMAN", Email: "auditor@example.com", EmailVerified: &ev,
		DisplayName: "Auditor", Groups: []string{"auditors"}, Roles: []string{"auditor"},
	})

	return &pgAdvStack{
		t:            t,
		repoRoot:     repoRoot,
		pg:           pg,
		store:        store,
		snapStore:    snapH.Store(),
		oidc:         oidc,
		upstream:     upstream,
		gwServer:     gwSrv,
		gwHTTP:       gwHTTP,
		apiServer:    apiServer,
		caFile:       caFile,
		sshAddr:      sshLn.Addr().String(),
		sshHostPub:   hostSSHPub,
		sshHostLine:  sshHostLine,
		caPrivPath:   caPrivPath,
		caSigner:     caSigner,
		rogueCAPath:  rogueCAPath,
		rogueSigner:  rogueSigner,
		scanners:     scanners,
		stageBGW:     stageBGW,
		auditSvc:     auditSvc,
		reposSvc:     reposSvc,
		metrics:      metrics,
		policyEngine: policyEngine,
		indexer:      indexer,
		alice:        alice,
		bob:          bob,
		admin:        admin,
		auditor:      auditor,
		aliceJWT:     aliceJWT,
		bobJWT:       bobJWT,
		adminJWT:     adminJWT,
		auditorJWT:   auditorJWT,
		repo:         repoRow,
		writeTok:     writeTok,
		readTok:      readTok,
		logBuf:       logBuf,
		secrets:      []string{writeTok, readTok, aliceJWT, bobJWT, adminJWT, auditorJWT, string(ghPEM)},
		ghPEM:        ghPEM,
		capSecret:    capSecret,
	}
}

func (s *pgAdvStack) gitHTTPURL(ownerRepo, jwt string) string {
	if jwt == "" {
		return s.gwHTTP.URL + "/" + ownerRepo + ".git"
	}
	return strings.Replace(s.gwHTTP.URL, "https://", "https://x-access-token:"+jwt+"@", 1) + "/" + ownerRepo + ".git"
}

func (s *pgAdvStack) gitSSHURL(user, ownerRepo string) string {
	if user == "" {
		user = "git"
	}
	return fmt.Sprintf("ssh://%s@%s/%s.git", user, s.sshAddr, ownerRepo)
}

func (s *pgAdvStack) registerRepo(t *testing.T, ghRepoID int64, fullName string, cls domain.Classification, mode domain.EgressMode, registered, external bool) persistence.RepositoryRow {
	t.Helper()
	row, err := s.store.UpsertRepository(context.Background(), persistence.UpsertRepositoryParams{
		GitHubRepositoryID:    ghRepoID,
		GitHubInstallationID:  2001,
		FullName:              fullName,
		Classification:        cls,
		Enabled:               true,
		AllowedModelRoutes:    []string{"approved-code-review"},
		EgressMode:            mode,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		GitRemoteURL:          s.upstream.server.URL + "/" + fullName + ".git",
		RemoteHost:            "github.com",
		RegisteredDestination: &registered,
		External:              &external,
	})
	if err != nil {
		t.Fatalf("UpsertRepository(%s): %v", fullName, err)
	}
	return row
}

func (s *pgAdvStack) indexCorpus(t *testing.T, name string, cls domain.Classification, files []fingerprints.CorpusFile) persistence.IPFingerprintCorpusRow {
	t.Helper()
	ctx := context.Background()
	row, err := s.store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           name,
		Classification: cls,
		CreatedBy:      &s.admin.ID,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus(%s): %v", name, err)
	}
	if _, err := s.indexer.Index(ctx, fingerprints.IndexRequest{
		CorpusID: row.ID,
		Files:    files,
	}); err != nil {
		t.Fatalf("Index(%s): %v", name, err)
	}
	return row
}

func (s *pgAdvStack) latestPushSession(t *testing.T, repoID *uuid.UUID) persistence.PushSessionRow {
	t.Helper()
	rows, err := s.store.ListPushSessions(context.Background(), persistence.ListPushSessionsParams{
		RepositoryID: repoID,
		Limit:        1,
	})
	if err != nil || len(rows) == 0 {
		t.Fatalf("ListPushSessions: rows=%d err=%v", len(rows), err)
	}
	return rows[0]
}

func (s *pgAdvStack) pushSessionCount(t *testing.T) int {
	t.Helper()
	var cnt int
	if err := s.pg.Pool().QueryRow(context.Background(), `SELECT COUNT(*) FROM push_sessions`).Scan(&cnt); err != nil {
		t.Fatalf("count push_sessions: %v", err)
	}
	return cnt
}

func (s *pgAdvStack) doAPIJSON(t *testing.T, method, path, token, idemKey string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.apiServer.URL+path, rdr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := s.apiServer.Client().Do(req)
	if err != nil {
		t.Fatalf("API %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func (s *pgAdvStack) assertZeroSecretsInLogs(t *testing.T, extra ...string) {
	t.Helper()
	logs := s.logBuf.String()
	all := append(append([]string(nil), s.secrets...), extra...)
	for _, sec := range all {
		if sec != "" && strings.Contains(logs, sec) {
			t.Fatalf("secret leaked in logs!")
		}
	}
}

func (s *pgAdvStack) cloneAndCommitHTTP(t *testing.T, ownerRepo, jwt, authorName, authorEmail, commitMsg string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "work")
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}
	out, code := runAdvGit(t, "", httpEnv, "clone", s.gitHTTPURL(ownerRepo, jwt), dir)
	if code != 0 {
		t.Fatalf("clone %s failed (%d):\n%s", ownerRepo, code, out)
	}
	mustAdvGit(t, dir, nil, "config", "user.name", authorName)
	mustAdvGit(t, dir, nil, "config", "user.email", authorEmail)
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	mustAdvGit(t, dir, nil, "add", ".")
	mustAdvGit(t, dir, nil, "commit", "-m", commitMsg)
	return dir
}

func (s *pgAdvStack) initLocalAndCommit(t *testing.T, authorName, authorEmail, commitMsg string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "local")
	mustAdvGit(t, "", nil, "init", "--initial-branch=main", dir)
	mustAdvGit(t, dir, nil, "config", "user.name", authorName)
	mustAdvGit(t, dir, nil, "config", "user.email", authorEmail)
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	mustAdvGit(t, dir, nil, "add", ".")
	mustAdvGit(t, dir, nil, "commit", "-m", commitMsg)
	return dir
}

type advSSHCred struct {
	keyPath        string
	certPath       string
	knownHostsPath string
}

func (s *pgAdvStack) mintSSHCertWithKeygen(t *testing.T, caPrivPath string, principals []string, keyID string, serial uint64, validity string, options []string) advSSHCred {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	cmdGen := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath)
	if out, err := cmdGen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen keygen failed: %v\n%s", err, string(out))
	}
	args := []string{
		"-s", caPrivPath,
		"-I", keyID,
		"-z", fmt.Sprintf("%d", serial),
	}
	if len(principals) > 0 {
		args = append(args, "-n", strings.Join(principals, ","))
	}
	if validity != "" {
		args = append(args, "-V", validity)
	}
	for _, opt := range options {
		args = append(args, "-O", opt)
	}
	args = append(args, keyPath+".pub")
	cmdSign := exec.Command("ssh-keygen", args...)
	if out, err := cmdSign.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen sign failed: %v\n%s", err, string(out))
	}
	khPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(khPath, []byte(s.sshHostLine+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(known_hosts): %v", err)
	}
	return advSSHCred{
		keyPath:        keyPath,
		certPath:       keyPath + "-cert.pub",
		knownHostsPath: khPath,
	}
}

func (c advSSHCred) gitEnv(useCert bool) []string {
	if useCert {
		return []string{fmt.Sprintf(
			"GIT_SSH_COMMAND=ssh -i %s -o CertificateFile=%s -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -o BatchMode=yes",
			c.keyPath, c.certPath, c.knownHostsPath,
		)}
	}
	return []string{fmt.Sprintf(
		"GIT_SSH_COMMAND=ssh -i %s -o CertificateFile=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -o BatchMode=yes",
		c.keyPath, c.knownHostsPath,
	)}
}

var (
	advCustodianBinOnce sync.Once
	advCustodianBinPath string
	advCustodianBinErr  error
)

func buildAdvCustodianCLI(t *testing.T) string {
	t.Helper()
	// Note: Tests must call StartPostgres before this so -short skips cleanly.
	advCustodianBinOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "custodian-adv-cli-*")
		if err != nil {
			advCustodianBinErr = err
			return
		}
		binPath := filepath.Join(tmpDir, "custodian")
		cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/custodian")
		out, err := cmd.CombinedOutput()
		if err != nil {
			advCustodianBinErr = fmt.Errorf("go build ../../cmd/custodian: %w\n%s", err, string(out))
			return
		}
		advCustodianBinPath = binPath
	})
	if advCustodianBinErr != nil {
		t.Fatalf("buildAdvCustodianCLI: %v", advCustodianBinErr)
	}
	return advCustodianBinPath
}

func runAdvGit(t *testing.T, dir string, extraEnv []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	}, extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = 1
		}
	}
	return string(out), code
}

func mustAdvGit(t *testing.T, dir string, extraEnv []string, args ...string) string {
	t.Helper()
	out, code := runAdvGit(t, dir, extraEnv, args...)
	if code != 0 {
		t.Fatalf("git %v (dir=%s) failed (%d):\n%s", args, dir, code, out)
	}
	return out
}

// runAdvGitAllowHooks runs git without core.hooksPath=/dev/null so local git-lfs hooks fire.
func runAdvGitAllowHooks(t *testing.T, dir string, extraEnv []string, args ...string) (string, int) {
	t.Helper()
	return runAdvGit(t, dir, extraEnv, args...)
}

func generateAdvRSAPrivateKeyAndPEM(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(RSA): %v", err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}

func generateAdvLocalhostTLSCert(t *testing.T) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(ca.crt): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pair, pool, caFile
}

// --- Archive, Raw Smart-HTTP, and Raw Packfile Builders ---

func buildAdvZipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip.Create(%s): %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("zip.Write(%s): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close: %v", err)
	}
	return buf.Bytes()
}

func buildAdvTarGzBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(content)),
			ModTime:  time.Unix(1700000000, 0).UTC(),
		}); err != nil {
			t.Fatalf("tar.WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tar.Write(%s): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}
	return buf.Bytes()
}

func writeAdvPktLine(w io.Writer, data []byte) {
	_, _ = fmt.Fprintf(w, "%04x", len(data)+4)
	_, _ = w.Write(data)
}

func (s *pgAdvStack) postRawReceivePack(t *testing.T, ownerRepo, jwt string, refs []quarantine.RefUpdate, pack []byte) (int, string) {
	t.Helper()
	var body bytes.Buffer
	for i, ru := range refs {
		if i == 0 {
			writeAdvPktLine(&body, []byte(fmt.Sprintf("%s %s %s\x00report-status side-band-64k\n", ru.OldOID, ru.NewOID, ru.RefName)))
		} else {
			writeAdvPktLine(&body, []byte(fmt.Sprintf("%s %s %s\n", ru.OldOID, ru.NewOID, ru.RefName)))
		}
	}
	_, _ = body.WriteString("0000")
	_, _ = body.Write(pack)

	req, err := http.NewRequest(http.MethodPost, s.gwHTTP.URL+"/"+ownerRepo+".git/git-receive-pack", &body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	resp, err := s.gwHTTP.Client().Do(req)
	if err != nil {
		t.Fatalf("POST raw receive-pack: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

const (
	advPackObjCommit   = 1
	advPackObjTree     = 2
	advPackObjBlob     = 3
	advPackObjOfsDelta = 6
	advPackObjRefDelta = 7
)

type advRawPackEntry struct {
	objType              int
	rawPayload           []byte
	declaredSizeOverride int64
	ofsDeltaNeg          uint64
	refDeltaBase         [20]byte
}

func encodeAdvPackEntryHeader(objType int, size uint64) []byte {
	var out []byte
	b := byte((objType&0x07)<<4) | byte(size&0x0f)
	size >>= 4
	if size > 0 {
		b |= 0x80
	}
	out = append(out, b)
	for size > 0 {
		nb := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			nb |= 0x80
		}
		out = append(out, nb)
	}
	return out
}

func encodeAdvOfsDeltaOffset(neg uint64) []byte {
	var rev []byte
	rev = append(rev, byte(neg&0x7f))
	neg >>= 7
	for neg > 0 {
		neg--
		rev = append(rev, byte(0x80|(neg&0x7f)))
		neg >>= 7
	}
	out := make([]byte, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

func encodeAdvLEB128(v uint64) []byte {
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

func compressAdvZlib(data []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func buildAdvRawPack(entries []advRawPackEntry) []byte {
	var body bytes.Buffer
	body.WriteString("PACK")
	_ = binary.Write(&body, binary.BigEndian, uint32(2))
	_ = binary.Write(&body, binary.BigEndian, uint32(len(entries)))
	for _, e := range entries {
		sz := uint64(len(e.rawPayload))
		if e.declaredSizeOverride >= 0 {
			sz = uint64(e.declaredSizeOverride)
		}
		body.Write(encodeAdvPackEntryHeader(e.objType, sz))
		switch e.objType {
		case advPackObjOfsDelta:
			body.Write(encodeAdvOfsDeltaOffset(e.ofsDeltaNeg))
		case advPackObjRefDelta:
			body.Write(e.refDeltaBase[:])
		}
		body.Write(compressAdvZlib(e.rawPayload))
	}
	sum := sha1.Sum(body.Bytes())
	body.Write(sum[:])
	return body.Bytes()
}

func hashAdvGitObjectRaw(objType string, payload []byte) ([20]byte, string) {
	hdr := fmt.Sprintf("%s %d\x00", objType, len(payload))
	h := sha1.New()
	_, _ = h.Write([]byte(hdr))
	_, _ = h.Write(payload)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out, hex.EncodeToString(out[:])
}

func buildAdvRawTreePayload(entries []struct {
	mode string
	name string
	oid  [20]byte
}) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.mode)
		buf.WriteByte(' ')
		buf.WriteString(e.name)
		buf.WriteByte(0)
		buf.Write(e.oid[:])
	}
	return buf.Bytes()
}

func buildAdvPackFromRevs(t *testing.T, repoDir string, revs []string) []byte {
	t.Helper()
	var stdin bytes.Buffer
	for _, r := range revs {
		stdin.WriteString(r)
		stdin.WriteByte('\n')
	}
	cmd := exec.Command("git", "pack-objects", "--revs", "--stdout", "-q")
	cmd.Dir = repoDir
	cmd.Stdin = &stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git pack-objects failed: %v\n%s", err, stderr.String())
	}
	return stdout.Bytes()
}
