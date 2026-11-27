package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

var genericQuotedKVRe = regexp.MustCompile(`[^\s=:]+\s*[:=]\s*(?:"([^"]+)"|'([^']+)')`)

type gitleaksRawFinding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
}

type genericScannerFinding struct {
	Scanner  string `json:"scanner"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Path     string `json:"path"`
	Message  string `json:"message"`
	Error    string `json:"error"`
}

type gitleaksScanner struct {
	cfg Config
}

func newGitleaksScanner(cfg Config) *gitleaksScanner {
	return &gitleaksScanner{cfg: cfg}
}

func (s *gitleaksScanner) Name() string {
	return string(ScannerGitleaks)
}

func (s *gitleaksScanner) Version(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "custodian-gitleaks-ver-*")
	if err != nil {
		return "unknown", err
	}
	defer os.RemoveAll(tmpDir)
	ver, missing, err := probeVersion(ctx, s.cfg.GitleaksBin, []string{"version"}, s.cfg.VersionProbeTimeout, tmpDir, nil)
	if missing {
		return "unknown", err
	}
	return ver, nil
}

func (s *gitleaksScanner) Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error) {
	startedAt := time.Now().UTC().Truncate(time.Microsecond)
	runID, err := domain.NewID()
	if err != nil {
		return ScannerOutcome{}, err
	}

	run := domain.ScanRun{
		ID:             runID,
		ProposalID:     req.ProposalID,
		ArtifactID:     req.ArtifactID,
		Scanner:        s.Name(),
		ScannerVersion: "unknown",
		Status:         domain.ScanStatusRunning,
		StartedAt:      startedAt,
	}

	tmpDir, err := os.MkdirTemp("", "custodian-gitleaks-*")
	if err != nil {
		return ScannerOutcome{}, err
	}
	defer os.RemoveAll(tmpDir)

	redactor := NewRedactor(req.ExtraSecrets...)
	ver, missing, verErr := probeVersion(ctx, s.cfg.GitleaksBin, []string{"version"}, s.cfg.VersionProbeTimeout, tmpDir, redactor)
	run.ScannerVersion = ver
	if missing {
		completedAt := time.Now().UTC().Truncate(time.Microsecond)
		run.CompletedAt = &completedAt
		finalizeScanRunCoverage(&run, inv, 0, 0, []string{"binary_missing"}, true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "binary_missing",
		}, verErr
	}

	reportPath := filepath.Join(tmpDir, "gitleaks.json")
	args := []string{
		"detect",
		"--no-git",
		"--source", req.TargetDir,
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "0",
	}

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.ScannerTimeout)
	defer cancel()

	res := runCommand(runCtx, s.cfg.GitleaksBin, args, req.TargetDir, tmpDir, defaultMaxStdioBytes)
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	run.CompletedAt = &completedAt

	stderrSkipped, stderrReasons := parseStderrSkipped(string(res.Stderr), redactor)

	if res.TimedOut || res.Canceled {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "scanner_timeout"), false, true, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "timeout",
		}, res.Err
	}

	if res.BinaryMissing || res.ExitCode >= 2 || (res.ExitCode != 0 && res.ExitCode != 1) {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, fmt.Sprintf("exit_code_%d", res.ExitCode)), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "crash",
		}, res.Err
	}

	raw, readErr := readReportOrStdout(reportPath, res.Stdout, res.StdoutTruncated, s.cfg.MaxOutputBytes)
	if readErr != nil {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "missing_or_oversized_report"), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "parse_error",
		}, readErr
	}

	findings, rawSecrets, parseErr := parseGitleaksReport(raw, req.TargetDir, redactor)
	if parseErr != nil {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "invalid_json_report"), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "parse_error",
		}, parseErr
	}

	if res.ExitCode == 1 && len(findings) == 0 {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "exit_code_1_without_findings"), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "crash",
		}, fmt.Errorf("gitleaks exited with code 1 without findings")
	}

	redactor.AddSecrets(rawSecrets...)
	for i := range findings {
		if err := redactor.FinalizeFinding(&findings[i], run.ID); err != nil {
			finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "redaction_validation_failed"), true, false, redactor)
			return ScannerOutcome{
				ScanRun:       run,
				FailureReason: "redaction_error",
			}, err
		}
	}

	var examined int
	if inv != nil {
		examined = inv.FilesExamined
	}
	finalizeScanRunCoverage(&run, inv, examined, stderrSkipped, stderrReasons, false, false, redactor)
	failureReason := ""
	if !run.IsCleanComplete() {
		failureReason = "files_skipped"
	}
	return ScannerOutcome{
		ScanRun:       run,
		Findings:      findings,
		FailureReason: failureReason,
		rawSecrets:    rawSecrets,
	}, nil
}

func parseGitleaksReport(raw []byte, targetDir string, redactor *Redactor) ([]domain.Finding, []string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil, fmt.Errorf("empty gitleaks report")
	}

	if trimmed[0] == '[' {
		var items []*gitleaksRawFinding
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, nil, fmt.Errorf("decode gitleaks array: %w", err)
		}
		findings := make([]domain.Finding, 0, len(items))
		var secrets []string
		for idx, item := range items {
			if item == nil {
				return nil, nil, fmt.Errorf("gitleaks report element %d is null", idx)
			}
			if strings.TrimSpace(item.RuleID) == "" &&
				strings.TrimSpace(item.Secret) == "" &&
				strings.TrimSpace(item.Match) == "" &&
				strings.TrimSpace(item.File) == "" &&
				strings.TrimSpace(item.Description) == "" {
				return nil, nil, fmt.Errorf("gitleaks report element %d is empty", idx)
			}
			if item.Secret != "" {
				secrets = append(secrets, item.Secret)
			}
			if item.Match != "" {
				secrets = append(secrets, item.Match)
			}
			redactor.AddSecrets(item.Secret, item.Match)

			ruleID := strings.TrimSpace(item.RuleID)
			if ruleID == "" {
				ruleID = "gitleaks-secret"
			}
			relPath := normalizeRelPath(targetDir, item.File)
			material := item.Secret + "\x00" + item.Match + "\x00" + item.Fingerprint
			fp := ComputeFingerprint(string(ScannerGitleaks), ruleID, relPath, item.StartLine, item.EndLine, material)

			msg := fmt.Sprintf("Redacted secret detected by rule %s", ruleID)
			if desc := strings.TrimSpace(item.Description); desc != "" {
				msg = fmt.Sprintf("%s (%s)", msg, redactor.ScrubString(desc))
			}

			findings = append(findings, domain.Finding{
				Scanner:     string(ScannerGitleaks),
				Category:    "SECRET",
				Severity:    domain.SeverityCritical,
				RuleID:      ruleID,
				Path:        relPath,
				StartLine:   max(0, item.StartLine),
				EndLine:     max(0, item.EndLine),
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     msg,
				Redacted:    true,
				Metadata: map[string]any{
					"tool":    string(ScannerGitleaks),
					"rule_id": ruleID,
				},
			})
		}
		return findings, secrets, nil
	}

	if trimmed[0] == '{' {
		return parseGenericFindingObject(trimmed, string(ScannerGitleaks), targetDir, redactor)
	}

	return nil, nil, fmt.Errorf("unexpected gitleaks JSON payload")
}

func readReportOrStdout(reportPath string, stdout []byte, stdoutTruncated bool, maxBytes int64) ([]byte, error) {
	if _, err := os.Stat(reportPath); err == nil {
		return readBoundedFile(reportPath, maxBytes)
	}
	if stdoutTruncated {
		return nil, fmt.Errorf("scanner stdout output truncated at buffer limit")
	}
	if len(bytes.TrimSpace(stdout)) > 0 {
		if maxBytes <= 0 {
			maxBytes = defaultMaxOutputBytes
		}
		if int64(len(stdout)) > maxBytes {
			return nil, fmt.Errorf("scanner stdout exceeds %d bytes", maxBytes)
		}
		return stdout, nil
	}
	return nil, fmt.Errorf("scanner report file %s not created and stdout empty", reportPath)
}

func parseGenericFindingObject(raw []byte, defaultScanner, targetDir string, redactor *Redactor) ([]domain.Finding, []string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return nil, nil, fmt.Errorf("invalid %s generic finding JSON payload", defaultScanner)
	}
	var gen genericScannerFinding
	if err := json.Unmarshal(trimmed, &gen); err != nil {
		return nil, nil, fmt.Errorf("decode generic finding JSON: %w", err)
	}
	if strings.TrimSpace(gen.Error) != "" {
		return nil, nil, fmt.Errorf("%s reported error payload", defaultScanner)
	}
	if strings.TrimSpace(gen.RuleID) == "" && strings.TrimSpace(gen.Category) == "" && strings.TrimSpace(gen.Message) == "" {
		return nil, nil, fmt.Errorf("empty or unrecognized %s generic finding object", defaultScanner)
	}

	category := strings.ToUpper(strings.TrimSpace(gen.Category))
	if category == "" {
		category = "POLICY"
	}
	ruleID := strings.TrimSpace(gen.RuleID)
	if ruleID == "" {
		ruleID = defaultScanner + "-finding"
	}
	relPath := normalizeRelPath(targetDir, gen.Path)
	fp := ComputeFingerprint(defaultScanner, ruleID, relPath, 0, 0, gen.Message)

	msg := strings.TrimSpace(gen.Message)
	var secrets []string
	addSecretToken := func(tok string) {
		tok = strings.Trim(strings.TrimSpace(tok), `"'`)
		if len(tok) < 4 {
			return
		}
		secrets = append(secrets, tok)
		redactor.AddSecrets(tok)
		if idx := strings.IndexAny(tok, "=:"); idx > 0 && idx+1 < len(tok) {
			rhs := strings.Trim(strings.TrimSpace(tok[idx+1:]), `"'`)
			if len(rhs) >= 4 {
				secrets = append(secrets, rhs)
				redactor.AddSecrets(rhs)
			}
		}
	}
	extractQuotedKVs := func(s string) {
		for _, m := range genericQuotedKVRe.FindAllStringSubmatch(s, -1) {
			val := m[1]
			if val == "" {
				val = m[2]
			}
			addSecretToken(val)
		}
	}
	if category == "SECRET" {
		if strings.HasPrefix(strings.ToLower(msg), "detected secret ") {
			candidate := strings.TrimSpace(msg[len("detected secret "):])
			extractQuotedKVs(candidate)
			addSecretToken(candidate)
			for _, tok := range strings.Fields(candidate) {
				if len(strings.Trim(tok, `"'`)) >= 4 {
					addSecretToken(tok)
				}
			}
		} else {
			extractQuotedKVs(msg)
			addSecretToken(msg)
			for _, tok := range strings.Fields(msg) {
				if len(strings.Trim(tok, `"'`)) >= 4 {
					addSecretToken(tok)
				}
			}
		}
		msg = fmt.Sprintf("Redacted secret detected by rule %s", ruleID)
	} else {
		msg = redactor.ScrubString(msg)
	}

	f := domain.Finding{
		Scanner:     defaultScanner,
		Category:    category,
		Severity:    normalizeSeverity(gen.Severity),
		RuleID:      ruleID,
		Path:        relPath,
		Fingerprint: fp,
		Confidence:  1.0,
		Message:     msg,
		Redacted:    true,
		Metadata: map[string]any{
			"tool":           defaultScanner,
			"generic_format": true,
		},
	}
	return []domain.Finding{f}, secrets, nil
}
