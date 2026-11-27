package harness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ScannerName identifies one of the 4 CLI scanners supported by Custodian.
type ScannerName string

const (
	ScannerGitleaks ScannerName = "gitleaks"
	ScannerScanCode ScannerName = "scancode"
	ScannerSemgrep  ScannerName = "semgrep"
	ScannerTrivy    ScannerName = "trivy"
)

// ScannerMode selects the deterministic behavior of a stub scanner wrapper.
type ScannerMode string

const (
	ScannerModeClean             ScannerMode = "clean"
	ScannerModeSecretFinding     ScannerMode = "secret_finding"
	ScannerModeProhibitedLicense ScannerMode = "prohibited_license"
	ScannerModeSASTFinding       ScannerMode = "sast_finding"
	ScannerModeVulnFinding       ScannerMode = "vuln_finding"
	ScannerModeFilesSkipped      ScannerMode = "files_skipped"
	ScannerModeCrash             ScannerMode = "crash"
	ScannerModeTimeout           ScannerMode = "timeout"
)

// ScannerBehavior configures a stub scanner's output, exit code, and timing.
type ScannerBehavior struct {
	Mode          ScannerMode
	SecretValue   string
	FilePath      string
	RuleID        string
	LicenseSPDX   string
	SkippedPaths  []string
	ExitCode      int
	SleepDuration time.Duration
	FailOnVersion bool
	StderrMsg     string
	RawJSON       []byte
}

// ScannerInvocation captures a single execution of a stub scanner binary.
type ScannerInvocation struct {
	Timestamp time.Time `json:"timestamp"`
	Scanner   string    `json:"scanner"`
	Args      []string  `json:"args"`
}

// StubScannerController manages per-test POSIX /bin/sh wrapper binaries for
// gitleaks, scancode, semgrep, and trivy inside an isolated t.TempDir().
type StubScannerController struct {
	t       testing.TB
	rootDir string
	binDir  string
	ctrlDir string

	mu        sync.Mutex
	behaviors map[ScannerName]ScannerBehavior
}

var allScannerNames = []ScannerName{
	ScannerGitleaks,
	ScannerScanCode,
	ScannerSemgrep,
	ScannerTrivy,
}

var defaultScannerVersions = map[ScannerName]string{
	ScannerGitleaks: "v8.18.4",
	ScannerScanCode: "32.1.0",
	ScannerSemgrep:  "1.90.0",
	ScannerTrivy:    "0.58.0",
}

// NewStubScannerController creates an isolated stub scanner directory and writes all 4 executable wrappers.
func NewStubScannerController(t testing.TB) *StubScannerController {
	t.Helper()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	ctrlDir := filepath.Join(root, "ctrl")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir stub scanner bin: %v", err)
	}
	if err := os.MkdirAll(ctrlDir, 0o755); err != nil {
		t.Fatalf("mkdir stub scanner ctrl: %v", err)
	}

	c := &StubScannerController{
		t:         t,
		rootDir:   root,
		binDir:    binDir,
		ctrlDir:   ctrlDir,
		behaviors: make(map[ScannerName]ScannerBehavior),
	}

	for _, name := range allScannerNames {
		if err := c.writeWrapperScript(name); err != nil {
			t.Fatalf("write stub wrapper %s: %v", name, err)
		}
	}
	c.ResetAll()
	return c
}

func (c *StubScannerController) writeWrapperScript(name ScannerName) error {
	ctrlFile := filepath.Join(c.ctrlDir, string(name)+".ctrl")
	jsonFile := filepath.Join(c.ctrlDir, string(name)+".json")
	invFile := filepath.Join(c.ctrlDir, string(name)+".invocations.jsonl")
	scriptPath := filepath.Join(c.binDir, string(name))

	// POSIX /bin/sh wrapper with zero external dependencies beyond standard shell + cat/sleep/printf.
	script := fmt.Sprintf(`#!/bin/sh
set -eu

CTRL_FILE=%s
JSON_FILE=%s
INV_FILE=%s
SCANNER_NAME=%s

if [ -f "$CTRL_FILE" ]; then
  . "$CTRL_FILE"
fi

# Handle version probes cleanly so startup healthchecks succeed even in crash mode.
for arg in "$@"; do
  if [ "$arg" = "--version" ] || [ "$arg" = "version" ] || [ "$arg" = "-V" ]; then
    if [ "${FAIL_ON_VERSION:-0}" = "1" ]; then
      printf 'version check failed\n' >&2
      exit 2
    fi
    printf '%%s\n' "${VERSION_OUT:-1.0.0}"
    exit 0
  fi
done

# Append invocation record (JSONL).
esc_args=""
sep=""
for arg in "$@"; do
  cleaned=$(printf '%%s' "$arg" | sed 's/\\/\\\\/g; s/"/\\"/g')
  esc_args="${esc_args}${sep}\"${cleaned}\""
  sep=","
done
ts=$(date -u +"%%Y-%%m-%%dT%%H:%%M:%%SZ")
printf '{"timestamp":"%%s","scanner":"%s","args":[%%s]}\n' "$ts" "$esc_args" >> "$INV_FILE"

OUT_FILE=""
REQ_EXIT_CODE=""
HAS_ERROR_FLAG=0

while [ $# -gt 0 ]; do
  case "$1" in
    --report-path=*|--json-pp=*|--output=*)
      OUT_FILE="${1#*=}"
      shift
      ;;
    --report-path|--json-pp|--output|-o)
      if [ $# -ge 2 ]; then
        OUT_FILE="$2"
        shift 2
      else
        shift
      fi
      ;;
    --json=*)
      OUT_FILE="${1#*=}"
      shift
      ;;
    --json)
      if [ "$SCANNER_NAME" = "scancode" ] && [ $# -ge 2 ]; then
        case "$2" in
          -*)
            shift
            ;;
          *)
            if [ ! -d "$2" ]; then
              OUT_FILE="$2"
              shift 2
            else
              shift
            fi
            ;;
        esac
      else
        shift
      fi
      ;;
    --exit-code=*)
      REQ_EXIT_CODE="${1#*=}"
      shift
      ;;
    --exit-code)
      if [ $# -ge 2 ]; then
        REQ_EXIT_CODE="$2"
        shift 2
      else
        shift
      fi
      ;;
    --error)
      HAS_ERROR_FLAG=1
      shift
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
if [ "${HAS_FINDINGS:-0}" = "1" ]; then
  if [ -n "$REQ_EXIT_CODE" ]; then
    FINAL_CODE="$REQ_EXIT_CODE"
  elif [ "$HAS_ERROR_FLAG" = "1" ]; then
    FINAL_CODE=1
  fi
fi
exit "$FINAL_CODE"
`, shellQuote(ctrlFile), shellQuote(jsonFile), shellQuote(invFile), shellQuote(string(name)), string(name))

	return os.WriteFile(scriptPath, []byte(script), 0o755)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// BinDir returns the directory containing the 4 executable scanner wrapper scripts.
func (c *StubScannerController) BinDir() string {
	return c.binDir
}

// BinaryPath returns the executable wrapper path for scanner.
func (c *StubScannerController) BinaryPath(scanner ScannerName) string {
	return filepath.Join(c.binDir, string(scanner))
}

// EnvVars returns a copy of baseEnv with BinDir prepended to PATH and contract scanner bin vars set.
func (c *StubScannerController) EnvVars(baseEnv []string, contracts *Contracts) []string {
	envMap := make(map[string]string)
	for _, entry := range baseEnv {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			envMap[k] = v
		}
	}
	for k, v := range c.EnvMap(contracts) {
		if k == "PATH" {
			if cur := envMap["PATH"]; cur != "" {
				envMap["PATH"] = c.binDir + string(os.PathListSeparator) + cur
			} else {
				envMap["PATH"] = c.binDir
			}
		} else {
			envMap[k] = v
		}
	}
	out := make([]string, 0, len(envMap))
	for k, v := range envMap {
		out = append(out, k+"="+v)
	}
	return out
}

// EnvMap returns environment variables injecting BinDir into PATH and setting contract binary env vars.
func (c *StubScannerController) EnvMap(contracts *Contracts) map[string]string {
	curPath := os.Getenv("PATH")
	newPath := c.binDir
	if curPath != "" {
		newPath = c.binDir + string(os.PathListSeparator) + curPath
	}
	m := map[string]string{
		"PATH": newPath,
	}
	if contracts != nil {
		for scanner, envKey := range contracts.CLI.ScannerBinEnvVars {
			if envKey != "" {
				m[envKey] = filepath.Join(c.binDir, scanner)
			}
		}
	}
	return m
}

// ResetAll resets all 4 scanners to ScannerModeClean.
func (c *StubScannerController) ResetAll() {
	for _, name := range allScannerNames {
		c.Set(name, ScannerBehavior{Mode: ScannerModeClean})
	}
}

// Set programs the output and exit behavior for scanner.
func (c *StubScannerController) Set(scanner ScannerName, behavior ScannerBehavior) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.behaviors[scanner] = behavior

	jsonBytes, exitCode, hasFindings, sleepSec, stderrMsg := c.renderScannerArtifacts(scanner, behavior)
	if len(behavior.RawJSON) > 0 {
		jsonBytes = behavior.RawJSON
	}

	jsonPath := filepath.Join(c.ctrlDir, string(scanner)+".json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
		c.t.Fatalf("write stub json %s: %v", jsonPath, err)
	}

	failVer := "0"
	if behavior.FailOnVersion {
		failVer = "1"
	}
	findingsFlag := "0"
	if hasFindings {
		findingsFlag = "1"
	}
	verOut := defaultScannerVersions[scanner]
	if verOut == "" {
		verOut = "1.0.0"
	}

	ctrlContent := fmt.Sprintf(
		"EXIT_CODE=%d\nHAS_FINDINGS=%s\nSLEEP_SEC=%s\nSTDERR_MSG=%s\nFAIL_ON_VERSION=%s\nVERSION_OUT=%s\n",
		exitCode,
		findingsFlag,
		shellQuote(sleepSec),
		shellQuote(stderrMsg),
		failVer,
		shellQuote(verOut),
	)
	ctrlPath := filepath.Join(c.ctrlDir, string(scanner)+".ctrl")
	if err := os.WriteFile(ctrlPath, []byte(ctrlContent), 0o644); err != nil {
		c.t.Fatalf("write stub ctrl %s: %v", ctrlPath, err)
	}
}

func (c *StubScannerController) renderScannerArtifacts(scanner ScannerName, b ScannerBehavior) (jsonBytes []byte, exitCode int, hasFindings bool, sleepSec string, stderrMsg string) {
	sleepSec = "0"
	stderrMsg = b.StderrMsg
	filePath := b.FilePath
	if filePath == "" {
		if scanner == ScannerTrivy {
			filePath = "go.mod"
		} else {
			filePath = "main.go"
		}
	}

	switch b.Mode {
	case ScannerModeCrash:
		code := b.ExitCode
		if code < 2 {
			code = 2
		}
		if stderrMsg == "" {
			stderrMsg = fmt.Sprintf("%s fatal error: simulated scanner crash", scanner)
		}
		return []byte("{}"), code, false, "0", stderrMsg

	case ScannerModeTimeout:
		dur := b.SleepDuration
		if dur <= 0 {
			dur = 5 * time.Second
		}
		sleepSec = strconv.FormatFloat(dur.Seconds(), 'f', 3, 64)
		// Still emit clean JSON if caller didn't cancel before sleep completes.
		return c.renderCleanJSON(scanner), 0, false, sleepSec, stderrMsg

	case ScannerModeSecretFinding:
		secret := b.SecretValue
		if secret == "" {
			secret = "AKIAIOSFODNN7EXAMPLE"
		}
		rule := nonEmpty(b.RuleID, "aws-access-token")
		if scanner == ScannerGitleaks {
			payload := []map[string]any{
				{
					"Description": "Hardcoded AWS Access Key",
					"StartLine":   2,
					"EndLine":     2,
					"StartColumn": 1,
					"EndColumn":   30,
					"Match":       "AWS_ACCESS_KEY_ID=" + secret,
					"Secret":      secret,
					"File":        filePath,
					"RuleID":      rule,
					"Fingerprint": fmt.Sprintf("%s:%s:2", filePath, rule),
				},
			}
			raw, _ := json.MarshalIndent(payload, "", "  ")
			return raw, 1, true, "0", stderrMsg
		}
		return c.renderGenericFindingJSON(scanner, filePath, rule, "SECRET", "CRITICAL", "Detected secret "+secret), 0, true, "0", stderrMsg

	case ScannerModeProhibitedLicense:
		spdx := nonEmpty(b.LicenseSPDX, "GPL-3.0-only")
		rule := nonEmpty(b.RuleID, "prohibited-license-"+strings.ToLower(spdx))
		if scanner == ScannerScanCode {
			payload := map[string]any{
				"headers": []map[string]any{
					{
						"tool_name":    "scancode-toolkit",
						"tool_version": defaultScannerVersions[ScannerScanCode],
						"errors":       []string{},
						"extra_data":   map[string]any{"files_count": 1},
					},
				},
				"files": []map[string]any{
					{
						"path":                             filePath,
						"type":                             "file",
						"detected_license_expression_spdx": spdx,
						"license_detections": []map[string]any{
							{
								"license_expression_spdx": spdx,
								"rule_identifier":         rule,
							},
						},
						"scan_errors": []string{},
					},
				},
			}
			raw, _ := json.MarshalIndent(payload, "", "  ")
			return raw, 0, true, "0", stderrMsg
		}
		return c.renderGenericFindingJSON(scanner, filePath, rule, "LICENSE", "HIGH", "Prohibited license "+spdx), 0, true, "0", stderrMsg

	case ScannerModeSASTFinding:
		rule := nonEmpty(b.RuleID, "go.lang.security.audit.unsafe-exec")
		if scanner == ScannerSemgrep {
			payload := map[string]any{
				"version": defaultScannerVersions[ScannerSemgrep],
				"results": []map[string]any{
					{
						"check_id": rule,
						"path":     filePath,
						"start":    map[string]int{"line": 10, "col": 2},
						"end":      map[string]int{"line": 10, "col": 24},
						"extra": map[string]any{
							"message":     "Potential command injection",
							"severity":    "ERROR",
							"fingerprint": "semgrep-fp-1",
							"metadata":    map[string]any{"category": "security"},
						},
					},
				},
				"errors": []any{},
				"paths": map[string]any{
					"scanned": []string{filePath},
					"skipped": []string{},
				},
			}
			raw, _ := json.MarshalIndent(payload, "", "  ")
			return raw, 0, true, "0", stderrMsg
		}
		return c.renderGenericFindingJSON(scanner, filePath, rule, "SAST", "HIGH", "Potential command injection"), 0, true, "0", stderrMsg

	case ScannerModeVulnFinding:
		rule := nonEmpty(b.RuleID, "CVE-2026-0001")
		if scanner == ScannerTrivy {
			payload := map[string]any{
				"SchemaVersion": 2,
				"ArtifactName":  ".",
				"ArtifactType":  "filesystem",
				"Results": []map[string]any{
					{
						"Target": filePath,
						"Class":  "lang-pkgs",
						"Type":   "gomod",
						"Vulnerabilities": []map[string]any{
							{
								"VulnerabilityID":  rule,
								"PkgName":          "example.com/vulnlib",
								"InstalledVersion": "v1.0.0",
								"FixedVersion":     "v1.0.1",
								"Severity":         "CRITICAL",
								"Title":            "Critical dependency vulnerability",
							},
						},
						"Misconfigurations": []any{},
					},
				},
			}
			raw, _ := json.MarshalIndent(payload, "", "  ")
			return raw, 0, true, "0", stderrMsg
		}
		return c.renderGenericFindingJSON(scanner, filePath, rule, "VULNERABILITY", "CRITICAL", "Critical dependency vulnerability"), 0, true, "0", stderrMsg

	case ScannerModeFilesSkipped:
		skipped := b.SkippedPaths
		if len(skipped) == 0 {
			skipped = []string{"skipped_unreadable.bin"}
		}
		if stderrMsg == "" {
			stderrMsg = fmt.Sprintf("%s skipped %d file(s): %s", scanner, len(skipped), strings.Join(skipped, ","))
		}
		switch scanner {
		case ScannerScanCode:
			payload := map[string]any{
				"headers": []map[string]any{
					{
						"tool_name":    "scancode-toolkit",
						"tool_version": defaultScannerVersions[ScannerScanCode],
						"errors":       []string{fmt.Sprintf("skipped %d file(s)", len(skipped))},
						"extra_data":   map[string]any{"files_count": 1, "files_skipped": len(skipped)},
					},
				},
				"files": []map[string]any{
					{
						"path":                             skipped[0],
						"type":                             "file",
						"detected_license_expression_spdx": "",
						"license_detections":               []any{},
						"scan_errors":                      []string{"error scanning binary/oversize file"},
					},
				},
			}
			raw, _ := json.MarshalIndent(payload, "", "  ")
			return raw, 0, false, "0", stderrMsg
		case ScannerSemgrep:
			payload := map[string]any{
				"version": defaultScannerVersions[ScannerSemgrep],
				"results": []any{},
				"errors": []map[string]any{
					{"level": "warn", "message": "skipped file due to size/parse limit"},
				},
				"paths": map[string]any{
					"scanned": []string{filePath},
					"skipped": skipped,
				},
			}
			raw, _ := json.MarshalIndent(payload, "", "  ")
			return raw, 0, false, "0", stderrMsg
		default:
			// Gitleaks / Trivy do not have a standard native skipped array; signal via stderr + optional non-zero code if configured.
			code := b.ExitCode
			return c.renderCleanJSON(scanner), code, false, "0", stderrMsg
		}

	default:
		return c.renderCleanJSON(scanner), 0, false, "0", stderrMsg
	}
}

func (c *StubScannerController) renderCleanJSON(scanner ScannerName) []byte {
	switch scanner {
	case ScannerGitleaks:
		return []byte("[]\n")
	case ScannerScanCode:
		raw, _ := json.MarshalIndent(map[string]any{
			"headers": []map[string]any{
				{
					"tool_name":    "scancode-toolkit",
					"tool_version": defaultScannerVersions[ScannerScanCode],
					"errors":       []string{},
					"extra_data":   map[string]any{"files_count": 1},
				},
			},
			"files": []any{},
		}, "", "  ")
		return raw
	case ScannerSemgrep:
		raw, _ := json.MarshalIndent(map[string]any{
			"version": defaultScannerVersions[ScannerSemgrep],
			"results": []any{},
			"errors":  []any{},
			"paths": map[string]any{
				"scanned": []string{"main.go"},
				"skipped": []string{},
			},
		}, "", "  ")
		return raw
	case ScannerTrivy:
		raw, _ := json.MarshalIndent(map[string]any{
			"SchemaVersion": 2,
			"ArtifactName":  ".",
			"ArtifactType":  "filesystem",
			"Results":       []any{},
		}, "", "  ")
		return raw
	default:
		return []byte("{}\n")
	}
}

func (c *StubScannerController) renderGenericFindingJSON(scanner ScannerName, filePath, rule, category, severity, message string) []byte {
	raw, _ := json.MarshalIndent(map[string]any{
		"scanner":  scanner,
		"category": category,
		"severity": severity,
		"rule_id":  rule,
		"path":     filePath,
		"message":  message,
	}, "", "  ")
	return raw
}

// Invocations returns all recorded invocations for scanner.
func (c *StubScannerController) Invocations(scanner ScannerName) []ScannerInvocation {
	invPath := filepath.Join(c.ctrlDir, string(scanner)+".invocations.jsonl")
	data, err := os.ReadFile(invPath)
	if err != nil {
		return nil
	}
	var out []ScannerInvocation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var inv ScannerInvocation
		if err := json.Unmarshal([]byte(line), &inv); err == nil {
			out = append(out, inv)
		}
	}
	return out
}

// AssertInvoked fails t if scanner was not invoked at least once.
func (c *StubScannerController) AssertInvoked(t testing.TB, scanner ScannerName) {
	t.Helper()
	if len(c.Invocations(scanner)) == 0 {
		t.Fatalf("expected stub scanner %q to be invoked at least once", scanner)
	}
}
