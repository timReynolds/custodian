package inspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

type stubSpec struct {
	VersionOut    string
	FailOnVersion bool
	ExitCode      int
	HasFindings   bool
	SleepSec      string
	StderrMsg     string
	JSONPayload   string
}

type stubHarness struct {
	t       *testing.T
	binDir  string
	ctrlDir string
}

func newStubHarness(t *testing.T) *stubHarness {
	t.Helper()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	ctrlDir := filepath.Join(root, "ctrl")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatalf("mkdir ctrlDir: %v", err)
	}
	h := &stubHarness{t: t, binDir: binDir, ctrlDir: ctrlDir}
	for _, name := range []string{"gitleaks", "scancode", "semgrep", "trivy"} {
		h.writeWrapper(name)
	}
	h.setCleanDefaults()
	return h
}

func (h *stubHarness) setCleanDefaults() {
	h.set("gitleaks", stubSpec{VersionOut: "v8.18.4", JSONPayload: "[]\n"})
	h.set("scancode", stubSpec{VersionOut: "32.1.0", JSONPayload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}`})
	h.set("semgrep", stubSpec{VersionOut: "1.90.0", JSONPayload: `{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`})
	h.set("trivy", stubSpec{VersionOut: "0.58.0", JSONPayload: `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}`})
}

func (h *stubHarness) writeWrapper(name string) {
	h.t.Helper()
	ctrlFile := filepath.Join(h.ctrlDir, name+".ctrl")
	jsonFile := filepath.Join(h.ctrlDir, name+".json")
	invFile := filepath.Join(h.ctrlDir, name+".invocations.txt")
	envLeakFile := filepath.Join(h.ctrlDir, name+".env.txt")
	scriptPath := filepath.Join(h.binDir, name)

	script := fmt.Sprintf(`#!/bin/sh
set -eu
CTRL_FILE=%s
JSON_FILE=%s
INV_FILE=%s
ENV_LEAK_FILE=%s
SCANNER_NAME=%s

if [ -f "$CTRL_FILE" ]; then
  . "$CTRL_FILE"
fi

for arg in "$@"; do
  if [ "$arg" = "--version" ] || [ "$arg" = "version" ] || [ "$arg" = "-V" ]; then
    if [ "${FAIL_ON_VERSION:-0}" = "1" ]; then
      printf 'version probe failed\n' >&2
      exit 2
    fi
    printf '%%s\n' "${VERSION_OUT:-1.0.0}"
    exit 0
  fi
done

printf '%%s\n' "$*" >> "$INV_FILE"
env | sort > "$ENV_LEAK_FILE"

OUT_FILE=""
REQ_EXIT_CODE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report-path=*|--json-pp=*|--output=*)
      OUT_FILE="${1#*=}"
      shift
      ;;
    --report-path|--json-pp|--output|-o)
      OUT_FILE="$2"
      shift 2
      ;;
    --exit-code=*)
      REQ_EXIT_CODE="${1#*=}"
      shift
      ;;
    --exit-code)
      REQ_EXIT_CODE="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ "${SLEEP_SEC:-0}" != "0" ] && [ -n "${SLEEP_SEC:-}" ]; then
  /bin/sleep "$SLEEP_SEC"
fi

if [ -n "${STDERR_MSG:-}" ]; then
  printf '%%s\n' "$STDERR_MSG" >&2
fi

if [ "${EXIT_CODE:-0}" -ge 2 ]; then
  exit "$EXIT_CODE"
fi

if [ -n "$OUT_FILE" ] && [ "$OUT_FILE" != "-" ]; then
  mkdir -p "$(dirname "$OUT_FILE")"
  cp "$JSON_FILE" "$OUT_FILE"
else
  cat "$JSON_FILE"
fi

FINAL_CODE="${EXIT_CODE:-0}"
if [ "${HAS_FINDINGS:-0}" = "1" ] && [ -n "$REQ_EXIT_CODE" ]; then
  FINAL_CODE="$REQ_EXIT_CODE"
fi
exit "$FINAL_CODE"
`, shQuote(ctrlFile), shQuote(jsonFile), shQuote(invFile), shQuote(envLeakFile), shQuote(name))

	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		h.t.Fatalf("write wrapper %s: %v", name, err)
	}
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func (h *stubHarness) set(name string, spec stubSpec) {
	h.t.Helper()
	if spec.VersionOut == "" {
		spec.VersionOut = "1.0.0"
	}
	if err := os.WriteFile(filepath.Join(h.ctrlDir, name+".json"), []byte(spec.JSONPayload), 0o644); err != nil {
		h.t.Fatalf("write json %s: %v", name, err)
	}
	failVer := "0"
	if spec.FailOnVersion {
		failVer = "1"
	}
	hasFindings := "0"
	if spec.HasFindings {
		hasFindings = "1"
	}
	ctrl := fmt.Sprintf("EXIT_CODE=%d\nHAS_FINDINGS=%s\nSLEEP_SEC=%s\nSTDERR_MSG=%s\nFAIL_ON_VERSION=%s\nVERSION_OUT=%s\n",
		spec.ExitCode, hasFindings, shQuote(spec.SleepSec), shQuote(spec.StderrMsg), failVer, shQuote(spec.VersionOut))
	if err := os.WriteFile(filepath.Join(h.ctrlDir, name+".ctrl"), []byte(ctrl), 0o644); err != nil {
		h.t.Fatalf("write ctrl %s: %v", name, err)
	}
}

func (h *stubHarness) binPath(name string) string {
	return filepath.Join(h.binDir, name)
}

func (h *stubHarness) invocations(name string) []string {
	data, err := os.ReadFile(filepath.Join(h.ctrlDir, name+".invocations.txt"))
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func (h *stubHarness) capturedEnv(name string) string {
	data, err := os.ReadFile(filepath.Join(h.ctrlDir, name+".env.txt"))
	if err != nil {
		return ""
	}
	return string(data)
}

func (h *stubHarness) config(t *testing.T, logBuf *bytes.Buffer) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.GitleaksBin = h.binPath("gitleaks")
	cfg.ScanCodeBin = h.binPath("scancode")
	cfg.SemgrepBin = h.binPath("semgrep")
	cfg.TrivyBin = h.binPath("trivy")
	cfg.ScannerTimeout = 5 * time.Second
	if logBuf != nil {
		cfg.Logger = observability.NewLogger(observability.LoggerConfig{
			Writer:    logBuf,
			Level:     slog.LevelDebug,
			Format:    observability.LogFormatJSON,
			Component: "inspection-test",
		})
	}
	return cfg
}

func TestIntegration_StubCLIs_CleanCompleteAndEnvIsolation(t *testing.T) {
	h := newStubHarness(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Inject sensitive broker env vars; scanner subprocesses must never see them.
	t.Setenv("CUSTODIAN_CAPABILITY_HMAC_SECRET", "super-secret-hmac")
	t.Setenv("GITHUB_TOKEN", "ghp_broker_secret_12345678")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-broker-secret")

	var logBuf bytes.Buffer
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	tr, err := observability.NewTracerProvider(context.Background(), observability.TracerConfig{
		ServiceName: "custodian-test",
		Mode:        observability.TraceModeInMemory,
	})
	if err != nil {
		t.Fatalf("NewTracerProvider: %v", err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	cfg := h.config(t, &logBuf)
	cfg.Metrics = metrics
	cfg.Tracer = tr

	runner := NewRunner(cfg)
	rep, err := runner.Inspect(context.Background(), Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      target,
		Classification: domain.ClassificationInternal,
		Stage:          StageEgress,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !rep.AllCleanComplete() || !rep.Summary.ScanComplete || !rep.Summary.MandatoryScannersComplete {
		t.Fatalf("expected clean complete report, got summary=%+v", rep.Summary)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("expected 0 findings on clean repo, got %d", len(rep.Findings))
	}
	if len(rep.ScanRuns) != 4 {
		t.Fatalf("expected exactly 4 mandatory ScanRuns (gitleaks, scancode, semgrep, custom), got %d", len(rep.ScanRuns))
	}
	for _, run := range rep.ScanRuns {
		if run.Coverage.FilesExamined < 1 || run.Coverage.FilesSkipped != 0 || !run.IsCleanComplete() {
			t.Fatalf("unexpected ScanRun coverage for %s: %+v", run.Scanner, run.Coverage)
		}
	}

	// Verify exact CLI flags used against stubs.
	if inv := h.invocations("gitleaks"); len(inv) != 1 || !strings.Contains(inv[0], "--report-path") {
		t.Fatalf("expected gitleaks --report-path invocation, got %v", inv)
	}
	if inv := h.invocations("scancode"); len(inv) != 1 || !strings.Contains(inv[0], "--json-pp") {
		t.Fatalf("expected scancode --json-pp invocation, got %v", inv)
	}
	if inv := h.invocations("semgrep"); len(inv) != 1 || !strings.Contains(inv[0], "--json --output") {
		t.Fatalf("expected semgrep --json --output invocation, got %v", inv)
	}
	if inv := h.invocations("trivy"); len(inv) != 0 {
		t.Fatalf("expected trivy NOT invoked without manifests, got %v", inv)
	}

	// Verify secret env vars stripped from child subprocesses.
	for _, tool := range []string{"gitleaks", "scancode", "semgrep"} {
		captured := h.capturedEnv(tool)
		for _, forbidden := range []string{"CUSTODIAN_CAPABILITY_HMAC_SECRET", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "super-secret-hmac"} {
			if strings.Contains(captured, forbidden) {
				t.Fatalf("scanner %s inherited sensitive env var %q:\n%s", tool, forbidden, captured)
			}
		}
	}

	// Verify OTel spans and Prometheus metrics were recorded.
	spans := tr.InMemory.GetSpans()
	if len(spans) < 5 {
		t.Fatalf("expected root + 4 scanner spans, got %d", len(spans))
	}
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var sawScannerRuns bool
	for _, mf := range mfs {
		if mf.GetName() == "custodian_scanner_runs_total" && len(mf.GetMetric()) >= 4 {
			sawScannerRuns = true
		}
	}
	if !sawScannerRuns {
		t.Fatalf("expected custodian_scanner_runs_total metrics recorded")
	}
	if !strings.Contains(logBuf.String(), "stage_a_scanner_completed") {
		t.Fatalf("expected structured stage_a_scanner_completed logs, got: %s", logBuf.String())
	}
}

func TestIntegration_StubCLIs_ConditionalTrivyAndRestrictedIP(t *testing.T) {
	h := newStubHarness(t)
	h.set("trivy", stubSpec{
		VersionOut:  "0.58.0",
		HasFindings: true,
		JSONPayload: `{
			"SchemaVersion": 2,
			"ArtifactName": ".",
			"ArtifactType": "filesystem",
			"Results": [{
				"Target": "go.mod",
				"Class": "lang-pkgs",
				"Type": "gomod",
				"Vulnerabilities": [{
					"VulnerabilityID": "CVE-2026-0001",
					"PkgName": "example.com/vulnlib",
					"InstalledVersion": "v1.0.0",
					"FixedVersion": "v1.0.1",
					"Severity": "CRITICAL",
					"Title": "Critical dependency vulnerability"
				}],
				"Misconfigurations": []
			}]
		}`,
	})

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := NewRunner(h.config(t, nil))
	rep, err := runner.Inspect(context.Background(), Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      target,
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !rep.AllCleanComplete() {
		t.Fatalf("expected AllCleanComplete=true, summary=%+v", rep.Summary)
	}
	if len(rep.ScanRuns) != 6 {
		t.Fatalf("expected 6 ScanRuns (4 mandatory + trivy + ip_fingerprint), got %d", len(rep.ScanRuns))
	}

	var seenScanners []string
	for _, run := range rep.ScanRuns {
		seenScanners = append(seenScanners, run.Scanner)
	}
	for _, expected := range []string{"gitleaks", "scancode", "semgrep", "custom", "trivy", "ip_fingerprint"} {
		if !slices.Contains(seenScanners, expected) {
			t.Fatalf("missing expected scanner %q in %v", expected, seenScanners)
		}
	}
	if inv := h.invocations("trivy"); len(inv) != 1 || !strings.Contains(inv[0], "--format json --output") {
		t.Fatalf("expected trivy --format json --output invocation, got %v", inv)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].RuleID != "CVE-2026-0001" || rep.Summary.HighVulnerabilities != 1 {
		t.Fatalf("expected Trivy CVE-2026-0001 finding, got %+v summary=%+v", rep.Findings, rep.Summary)
	}
}

func TestIntegration_ADV06_MultipleSecretsRedactedAcrossAllSurfaces(t *testing.T) {
	h := newStubHarness(t)
	awsSecret := "AKIAIOSFODNN7EXAMPLE"
	dummySecret := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	pemCanary := "FAKE_E2E_TEST_KEY_DATA_DO_NOT_USE_000000000000000000000000000000"
	envSecret := "super_secret_env_token_99887766"

	h.set("gitleaks", stubSpec{
		VersionOut:  "v8.18.4",
		ExitCode:    1,
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`[
			{
				"Description": "AWS key %s and %s",
				"StartLine": 2,
				"EndLine": 2,
				"Match": "AWS_ACCESS_KEY_ID=%s",
				"Secret": "%s",
				"File": "config.go",
				"RuleID": "aws-access-token",
				"Fingerprint": "config.go:aws-access-token:2"
			},
			{
				"Description": "Dummy token %s",
				"StartLine": 5,
				"EndLine": 5,
				"Match": "TOKEN=%s",
				"Secret": "%s",
				"File": "config.go",
				"RuleID": "generic-api-key",
				"Fingerprint": "config.go:generic-api-key:5"
			}
		]`, awsSecret, base64.StdEncoding.EncodeToString([]byte(dummySecret)), awsSecret, awsSecret, url.QueryEscape(awsSecret), dummySecret, dummySecret),
	})

	// Cross-scanner generic fallback emitting a SECRET via Semgrep.
	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`{
			"scanner": "semgrep",
			"category": "SECRET",
			"severity": "CRITICAL",
			"rule_id": "semgrep-secret-fallback",
			"path": "config.go",
			"message": "Detected secret %s"
		}`, dummySecret),
	})

	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "secrets", "id_rsa.pem"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\n"+pemCanary+"\n-----END RSA PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, ".env"), []byte("APP_SECRET="+envSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "config.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	runner := NewRunner(h.config(t, &logBuf))
	rep, err := runner.Inspect(context.Background(), Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      target,
		Classification: domain.ClassificationInternal,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if len(rep.Findings) < 4 {
		t.Fatalf("expected >= 4 findings across gitleaks, semgrep fallback, and custom, got %d", len(rep.Findings))
	}
	if rep.Summary.CriticalSecrets < 4 {
		t.Fatalf("expected CriticalSecrets >= 4, got %d", rep.Summary.CriticalSecrets)
	}

	for i, f := range rep.Findings {
		if !f.Redacted {
			t.Fatalf("finding %d (%s) has Redacted=false", i, f.Scanner)
		}
		if err := f.ValidateRedacted(); err != nil {
			t.Fatalf("finding %d ValidateRedacted failed: %v", i, err)
		}
		if !strings.HasPrefix(f.EvidenceID, "finding_") {
			t.Fatalf("finding %d invalid EvidenceID %q", i, f.EvidenceID)
		}
	}

	reportJSON, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	surfaces := []string{string(reportJSON), logBuf.String()}
	for _, secret := range []string{awsSecret, dummySecret, pemCanary, envSecret} {
		variants := []string{
			secret,
			base64.StdEncoding.EncodeToString([]byte(secret)),
			base64.RawURLEncoding.EncodeToString([]byte(secret)),
			url.QueryEscape(secret),
		}
		for _, surf := range surfaces {
			for _, v := range variants {
				if strings.Contains(surf, v) {
					t.Fatalf("ADV-06 leak detected for variant %q in surface:\n%s", v, surf)
				}
			}
		}
	}
}

func TestIntegration_RG05_FilesSkippedFailClosed(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*stubHarness)
	}{
		{
			name: "semgrep_paths_skipped",
			setup: func(h *stubHarness) {
				h.set("semgrep", stubSpec{
					VersionOut:  "1.90.0",
					StderrMsg:   "semgrep skipped 1 file(s): huge.bin",
					JSONPayload: `{"version":"1.90.0","results":[],"errors":[{"level":"warn","message":"skipped file due to size/parse limit"}],"paths":{"scanned":["main.go"],"skipped":["huge.bin"]}}`,
				})
			},
		},
		{
			name: "scancode_extra_data_files_skipped",
			setup: func(h *stubHarness) {
				h.set("scancode", stubSpec{
					VersionOut:  "32.1.0",
					StderrMsg:   "scancode skipped 1 file(s): huge.bin",
					JSONPayload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":["skipped 1 file(s)"],"extra_data":{"files_count":1,"files_skipped":1}}],"files":[{"path":"huge.bin","type":"file","scan_errors":["error scanning binary/oversize file"]}]}`,
				})
			},
		},
		{
			name: "gitleaks_stderr_skipped",
			setup: func(h *stubHarness) {
				h.set("gitleaks", stubSpec{
					VersionOut:  "v8.18.4",
					StderrMsg:   "gitleaks skipped 1 file(s): huge.bin",
					JSONPayload: "[]\n",
				})
			},
		},
		{
			name: "trivy_stderr_skipped",
			setup: func(h *stubHarness) {
				h.set("trivy", stubSpec{
					VersionOut:  "0.58.0",
					StderrMsg:   "trivy skipped 1 file(s): huge.bin",
					JSONPayload: `{"SchemaVersion":2,"Results":[]}`,
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			tc.setup(h)

			target := t.TempDir()
			if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			metrics, _ := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
			cfg := h.config(t, nil)
			cfg.Metrics = metrics

			rep, err := NewRunner(cfg).Inspect(context.Background(), Request{
				ProposalID: domain.MustNewID(),
				ArtifactID: domain.MustNewID(),
				TargetDir:  target,
			})
			if err != nil {
				t.Fatalf("Inspect returned error: %v", err)
			}
			if rep.AllCleanComplete() || rep.Summary.ScanComplete {
				t.Fatalf("expected fail-closed incomplete report, got summary=%+v", rep.Summary)
			}
			if rep.Summary.PolicyFacts()["scan_complete"] != false {
				t.Fatalf("expected PolicyFacts[scan_complete]=false")
			}
			if len(rep.Summary.IncompleteScanners) == 0 {
				t.Fatalf("expected IncompleteScanners populated, got %+v", rep.Summary)
			}
			var foundIncomplete bool
			for _, run := range rep.ScanRuns {
				if run.Status == domain.ScanStatusIncomplete {
					foundIncomplete = true
					if run.IsCleanComplete() || run.Coverage.Complete || run.Coverage.FilesSkipped == 0 {
						t.Fatalf("expected incomplete ScanRun with FilesSkipped>0, got %+v", run)
					}
				}
			}
			if !foundIncomplete {
				t.Fatalf("expected at least one INCOMPLETE ScanRun, got %+v", rep.ScanRuns)
			}
		})
	}
}

func TestIntegration_RG05_CrashAndMissingBinaryFailClosed(t *testing.T) {
	h := newStubHarness(t)
	h.set("gitleaks", stubSpec{
		VersionOut: "v8.18.4",
		ExitCode:   2,
		StderrMsg:  "gitleaks fatal error: simulated crash",
	})

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(t, nil)
	cfg.SemgrepBin = filepath.Join(t.TempDir(), "missing-semgrep-binary")

	rep, err := NewRunner(cfg).Inspect(context.Background(), Request{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		TargetDir:  target,
	})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}

	if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.MandatoryScannersComplete {
		t.Fatalf("expected fail-closed summary on crash/missing binary, got %+v", rep.Summary)
	}
	if len(rep.ScanRuns) != 4 {
		t.Fatalf("expected all 4 mandatory ScanRuns reported even when 2 fail, got %d", len(rep.ScanRuns))
	}

	statusByScanner := map[string]domain.ScanRun{}
	for _, r := range rep.ScanRuns {
		statusByScanner[r.Scanner] = r
	}
	if statusByScanner["gitleaks"].Status != domain.ScanStatusFailed || statusByScanner["gitleaks"].IsCleanComplete() {
		t.Fatalf("expected gitleaks FAILED, got %+v", statusByScanner["gitleaks"])
	}
	if statusByScanner["semgrep"].Status != domain.ScanStatusFailed || statusByScanner["semgrep"].IsCleanComplete() {
		t.Fatalf("expected semgrep FAILED, got %+v", statusByScanner["semgrep"])
	}
	if !statusByScanner["scancode"].IsCleanComplete() || !statusByScanner["custom"].IsCleanComplete() {
		t.Fatalf("expected remaining scanners to complete cleanly, got scancode=%+v custom=%+v", statusByScanner["scancode"], statusByScanner["custom"])
	}
	if !slices.Contains(rep.Summary.FailedScanners, "gitleaks") || !slices.Contains(rep.Summary.FailedScanners, "semgrep") {
		t.Fatalf("expected FailedScanners to include gitleaks and semgrep, got %v", rep.Summary.FailedScanners)
	}
}

func TestIntegration_RG05_TimeoutKillsProcessGroupAndFailsClosed(t *testing.T) {
	h := newStubHarness(t)
	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		SleepSec:    "10",
		JSONPayload: `{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`,
	})

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvScannerTimeout, "150ms")
	loaded, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}
	loaded.GitleaksBin = h.binPath("gitleaks")
	loaded.ScanCodeBin = h.binPath("scancode")
	loaded.SemgrepBin = h.binPath("semgrep")
	loaded.TrivyBin = h.binPath("trivy")

	start := time.Now()
	rep, err := NewRunner(loaded).Inspect(context.Background(), Request{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		TargetDir:  target,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("timeout took too long (%v); child process group may not have been killed promptly", elapsed)
	}
	if rep.AllCleanComplete() || rep.Summary.ScanComplete {
		t.Fatalf("expected fail-closed summary on timeout, got %+v", rep.Summary)
	}

	var sawTimedOut bool
	for _, run := range rep.ScanRuns {
		if run.Scanner == "semgrep" {
			sawTimedOut = true
			if run.Status != domain.ScanStatusTimedOut || run.IsCleanComplete() || run.Coverage.Complete {
				t.Fatalf("expected semgrep TIMED_OUT with Complete=false, got %+v", run)
			}
		}
	}
	if !sawTimedOut {
		t.Fatalf("missing semgrep ScanRun")
	}
}

func TestIntegration_FailOnVersionStillRunsScan(t *testing.T) {
	h := newStubHarness(t)
	h.set("scancode", stubSpec{
		FailOnVersion: true,
		JSONPayload:   `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}`,
	})

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := NewRunner(h.config(t, nil)).Inspect(context.Background(), Request{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		TargetDir:  target,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if !rep.AllCleanComplete() {
		t.Fatalf("expected AllCleanComplete=true even when version probe failed, got %+v", rep.Summary)
	}
	for _, r := range rep.ScanRuns {
		if r.Scanner == "scancode" && r.ScannerVersion != "32.1.0" {
			t.Fatalf("expected scancode fallback version from report JSON '32.1.0', got %q", r.ScannerVersion)
		}
	}
}
