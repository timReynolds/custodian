package fixtures

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/inspection"
)

// FindRepoRoot walks up from the current working directory until go.mod is found.
func FindRepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod from %s", dir)
		}
		dir = parent
	}
}

// TarEntrySpec describes an archive entry for deterministic or adversarial tar.gz construction.
type TarEntrySpec struct {
	Name     string
	Typeflag byte
	Mode     int64
	Body     []byte
	Linkname string
	Size     int64
	HasSize  bool
}

// BuildTarGz encodes entries into a gzip-compressed tar archive.
func BuildTarGz(t testing.TB, entries []TarEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		tf := e.Typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := e.Mode
		if mode == 0 {
			if tf == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o644
			}
		}
		size := int64(len(e.Body))
		if e.HasSize {
			size = e.Size
		}
		hdr := &tar.Header{
			Name:     e.Name,
			Typeflag: tf,
			Mode:     mode,
			Size:     size,
			Linkname: e.Linkname,
			ModTime:  time.Unix(1700000000, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", e.Name, err)
		}
		if tf == tar.TypeReg && len(e.Body) > 0 {
			if _, err := tw.Write(e.Body); err != nil {
				t.Fatalf("Write(%q): %v", e.Name, err)
			}
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

// BuildConcatenatedTarGz joins two valid gzip-compressed tar streams into a single multi-member stream.
func BuildConcatenatedTarGz(t testing.TB, first, second []TarEntrySpec) []byte {
	t.Helper()
	a := BuildTarGz(t, first)
	b := BuildTarGz(t, second)
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	return out
}

// StubScannerController configures POSIX /bin/sh scanner stubs for Stage A testing.
type StubScannerController struct {
	mu           sync.Mutex
	dir          string
	gitleaksMode string
	secretValue  string
	semgrepMode  string
	trivyMode    string
	skippedFile  string
	Config       inspection.Config
}

// NewStubScanners creates isolated POSIX /bin/sh stub binaries for gitleaks, scancode, semgrep, and trivy.
func NewStubScanners(t testing.TB) *StubScannerController {
	t.Helper()
	dir := t.TempDir()
	ctrl := &StubScannerController{dir: dir}

	write := func(name, script string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
		return p
	}

	modeFile := func(name string) string {
		return filepath.Join(dir, name+".mode")
	}
	ctrl.SetClean()

	gitPath := write("gitleaks", fmt.Sprintf(`#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "version" ] || [ "$a" = "--version" ] && echo "v8.18.4" && exit 0; done
OUT=""
while [ $# -gt 0 ]; do case "$1" in --report-path) OUT="$2"; shift 2;; *) shift;; esac; done
MODE=$(cat %q 2>/dev/null || echo clean)
case "$MODE" in
  secret:*)
    SEC=${MODE#secret:}
    printf '[{"Description":"Secret","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":10,"Match":"TOK=%%s","Secret":"%%s","File":".env","RuleID":"generic-api-key","Fingerprint":"fp-sec-1"}]\n' "$SEC" "$SEC" > "$OUT"
    ;;
  crash)
    echo "gitleaks fatal error" >&2
    exit 2
    ;;
  *)
    printf '[]\n' > "$OUT"
    ;;
esac
`, modeFile("gitleaks")))

	scPath := write("scancode", `#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "--version" ] && echo "32.1.0" && exit 0; done
OUT=""
while [ $# -gt 0 ]; do case "$1" in --json-pp) OUT="$2"; shift 2;; *) shift;; esac; done
printf '{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}\n' > "$OUT"
`)

	sgPath := write("semgrep", fmt.Sprintf(`#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "--version" ] && echo "1.90.0" && exit 0; done
OUT=""
while [ $# -gt 0 ]; do case "$1" in --output) OUT="$2"; shift 2;; *) shift;; esac; done
MODE=$(cat %q 2>/dev/null || echo clean)
case "$MODE" in
  skipped)
    printf '{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["README.md"],"skipped":["big.min.js"]}}\n' > "$OUT"
    ;;
  crash)
    echo "semgrep failed" >&2
    exit 2
    ;;
  *)
    printf '{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["README.md"],"skipped":[]}}\n' > "$OUT"
    ;;
esac
`, modeFile("semgrep")))

	tvPath := write("trivy", `#!/bin/sh
set -eu
for a in "$@"; do [ "$a" = "--version" ] && echo "Version: 0.58.0" && exit 0; done
OUT=""
while [ $# -gt 0 ]; do case "$1" in --output) OUT="$2"; shift 2;; *) shift;; esac; done
printf '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}\n' > "$OUT"
`)

	ctrl.Config = inspection.Config{
		GitleaksBin:    gitPath,
		ScanCodeBin:    scPath,
		SemgrepBin:     sgPath,
		TrivyBin:       tvPath,
		ScannerTimeout: 10 * time.Second,
	}
	return ctrl
}

func (c *StubScannerController) SetClean() {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.WriteFile(filepath.Join(c.dir, "gitleaks.mode"), []byte("clean"), 0o644)
	_ = os.WriteFile(filepath.Join(c.dir, "semgrep.mode"), []byte("clean"), 0o644)
}

func (c *StubScannerController) SetGitleaksSecret(secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.WriteFile(filepath.Join(c.dir, "gitleaks.mode"), []byte("secret:"+secret), 0o644)
}

func (c *StubScannerController) SetGitleaksCrash() {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.WriteFile(filepath.Join(c.dir, "gitleaks.mode"), []byte("crash"), 0o644)
}

func (c *StubScannerController) SetSemgrepFilesSkipped() {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.WriteFile(filepath.Join(c.dir, "semgrep.mode"), []byte("skipped"), 0o644)
}

// MockGateway records Stage B requests and serves configurable responses.
type MockGateway struct {
	mu          sync.Mutex
	Server      *httptest.Server
	Requests    []decisions.GatewayRequest
	StatusCode  int
	Disposition string
	Risk        string
}

// StartMockGateway starts an offline Stage B model gateway server.
func StartMockGateway(t testing.TB) *MockGateway {
	t.Helper()
	mg := &MockGateway{
		StatusCode:  http.StatusOK,
		Disposition: "CLEAR",
		Risk:        "LOW",
	}
	mg.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req decisions.GatewayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		mg.mu.Lock()
		mg.Requests = append(mg.Requests, req)
		code := mg.StatusCode
		disp := mg.Disposition
		risk := mg.Risk
		mg.mu.Unlock()

		if code >= 400 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"gateway unavailable"}`))
			return
		}
		at := req.AssessmentType
		if at == "" {
			at = "SECURITY_REVIEW"
		}
		payload, _ := json.Marshal(map[string]any{
			"schema_version":  "1",
			"assessment_type": at,
			"risk":            risk,
			"disposition":     disp,
			"confidence":      0.96,
			"summary":         "mock gateway assessment",
			"findings":        []any{},
			"limitations":     []string{},
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "chatcmpl-fixture",
			"object": "chat.completion",
			"model":  "mock-model-1.0",
			"choices": []map[string]any{
				{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": string(payload)},
					"finish_reason": "stop",
				},
			},
		})
	}))
	t.Cleanup(mg.Server.Close)
	return mg
}

func (g *MockGateway) SetStatus(code int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.StatusCode = code
}

func (g *MockGateway) CallCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.Requests)
}

// GenerateTestRSAPEM creates an ephemeral RSA private key PEM string for credential-redaction tests.
func GenerateTestRSAPEM(t testing.TB) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}
