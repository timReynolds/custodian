package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

type semgrepReport struct {
	Version string           `json:"version"`
	Results []*semgrepResult `json:"results"`
	Errors  []semgrepError   `json:"errors"`
	Paths   semgrepPaths     `json:"paths"`
}

type semgrepResult struct {
	CheckID string          `json:"check_id"`
	Path    string          `json:"path"`
	Start   semgrepPosition `json:"start"`
	End     semgrepPosition `json:"end"`
	Extra   semgrepExtra    `json:"extra"`
}

type semgrepPosition struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message     string         `json:"message"`
	Severity    string         `json:"severity"`
	Fingerprint string         `json:"fingerprint"`
	Metadata    map[string]any `json:"metadata"`
}

type semgrepError struct {
	Level   string `json:"level"`
	Type    string `json:"type"`
	Message string `json:"message"`
	Path    string `json:"path"`
}

type semgrepPaths struct {
	Scanned []string `json:"scanned"`
	Skipped []string `json:"skipped"`
}

type semgrepScanner struct {
	cfg Config
}

func newSemgrepScanner(cfg Config) *semgrepScanner {
	return &semgrepScanner{cfg: cfg}
}

func (s *semgrepScanner) Name() string {
	return string(ScannerSemgrep)
}

func (s *semgrepScanner) Version(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "custodian-semgrep-ver-*")
	if err != nil {
		return "unknown", err
	}
	defer os.RemoveAll(tmpDir)
	ver, missing, err := probeVersion(ctx, s.cfg.SemgrepBin, []string{"--version"}, s.cfg.VersionProbeTimeout, tmpDir, nil)
	if missing {
		return "unknown", err
	}
	return ver, nil
}

func (s *semgrepScanner) Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error) {
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

	tmpDir, err := os.MkdirTemp("", "custodian-semgrep-*")
	if err != nil {
		return ScannerOutcome{}, err
	}
	defer os.RemoveAll(tmpDir)

	redactor := NewRedactor(req.ExtraSecrets...)
	ver, missing, verErr := probeVersion(ctx, s.cfg.SemgrepBin, []string{"--version"}, s.cfg.VersionProbeTimeout, tmpDir, redactor)
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

	reportPath := filepath.Join(tmpDir, "semgrep.json")
	args := []string{
		"scan",
		"--json",
		"--output", reportPath,
		req.TargetDir,
	}

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.ScannerTimeout)
	defer cancel()

	res := runCommand(runCtx, s.cfg.SemgrepBin, args, req.TargetDir, tmpDir, defaultMaxStdioBytes)
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

	if res.BinaryMissing || res.ExitCode != 0 {
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

	parsed, parseErr := parseSemgrepReport(raw, req.TargetDir, redactor)
	if parseErr != nil {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "invalid_json_report"), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "parse_error",
		}, parseErr
	}

	if parsed.version != "" && run.ScannerVersion == "unknown" {
		scrubbedVer := strings.TrimSpace(redactor.ScrubString(parsed.version))
		if scrubbedVer != "" {
			run.ScannerVersion = scrubbedVer
		}
	}

	for i := range parsed.findings {
		if err := redactor.FinalizeFinding(&parsed.findings[i], run.ID); err != nil {
			finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "redaction_validation_failed"), true, false, redactor)
			return ScannerOutcome{
				ScanRun:       run,
				FailureReason: "redaction_error",
			}, err
		}
	}

	skippedTotal := max(parsed.filesSkipped, stderrSkipped)
	allReasons := append(parsed.skippedReasons, stderrReasons...)
	finalizeScanRunCoverage(&run, inv, parsed.filesExamined, skippedTotal, allReasons, false, false, redactor)

	failureReason := ""
	if !run.IsCleanComplete() {
		failureReason = "files_skipped"
	}
	return ScannerOutcome{
		ScanRun:       run,
		Findings:      parsed.findings,
		FailureReason: failureReason,
		rawSecrets:    parsed.rawSecrets,
	}, nil
}

type semgrepParsed struct {
	version        string
	findings       []domain.Finding
	filesExamined  int
	filesSkipped   int
	skippedReasons []string
	rawSecrets     []string
}

func parseSemgrepReport(raw []byte, targetDir string, redactor *Redactor) (semgrepParsed, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return semgrepParsed{}, fmt.Errorf("empty semgrep report")
	}
	if bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return semgrepParsed{}, fmt.Errorf("unexpected semgrep JSON payload")
	}

	var rep semgrepReport
	if err := json.Unmarshal(trimmed, &rep); err != nil {
		return semgrepParsed{}, fmt.Errorf("decode semgrep JSON: %w", err)
	}

	hasMetadata := strings.TrimSpace(rep.Version) != "" ||
		rep.Paths.Scanned != nil ||
		rep.Paths.Skipped != nil
	if rep.Results == nil || !hasMetadata {
		hasNativeHint := rep.Results != nil ||
			strings.TrimSpace(rep.Version) != "" ||
			len(rep.Errors) > 0 ||
			rep.Paths.Scanned != nil ||
			rep.Paths.Skipped != nil
		if !hasNativeHint {
			findings, secrets, genErr := parseGenericFindingObject(trimmed, string(ScannerSemgrep), targetDir, redactor)
			if genErr == nil && len(findings) > 0 {
				return semgrepParsed{
					findings:      findings,
					filesExamined: len(findings),
					rawSecrets:    secrets,
				}, nil
			}
			if genErr != nil {
				return semgrepParsed{}, fmt.Errorf("semgrep report missing required results/metadata: %w", genErr)
			}
		}
		return semgrepParsed{}, fmt.Errorf("semgrep report missing required results/metadata")
	}

	out := semgrepParsed{
		version:       redactor.ScrubString(strings.TrimSpace(rep.Version)),
		findings:      make([]domain.Finding, 0, len(rep.Results)),
		filesExamined: len(rep.Paths.Scanned),
		filesSkipped:  len(rep.Paths.Skipped),
	}

	for _, sp := range rep.Paths.Skipped {
		rel := normalizeRelPath(targetDir, sp)
		if rel != "" {
			out.skippedReasons = append(out.skippedReasons, "skipped:"+rel)
		}
	}

	for _, e := range rep.Errors {
		errType := strings.TrimSpace(e.Type)
		msg := strings.TrimSpace(e.Message)
		relErrPath := normalizeRelPath(targetDir, e.Path)

		var parts []string
		if errType != "" {
			parts = append(parts, errType)
		}
		if relErrPath != "" {
			parts = append(parts, relErrPath)
		}
		if msg != "" {
			parts = append(parts, msg)
		}
		reason := "semgrep_error"
		if len(parts) > 0 {
			reason = strings.Join(parts, ": ")
		}
		if redactor != nil {
			reason = redactor.ScrubString(reason)
		}
		out.skippedReasons = append(out.skippedReasons, reason)
		if out.filesSkipped == 0 {
			out.filesSkipped = 1
		}
	}

	for idx, res := range rep.Results {
		if res == nil {
			return semgrepParsed{}, fmt.Errorf("semgrep result element %d is null", idx)
		}
		if strings.TrimSpace(res.CheckID) == "" &&
			strings.TrimSpace(res.Path) == "" &&
			strings.TrimSpace(res.Extra.Message) == "" {
			return semgrepParsed{}, fmt.Errorf("semgrep result element %d is empty", idx)
		}
		ruleID := strings.TrimSpace(res.CheckID)
		if ruleID == "" {
			ruleID = "semgrep-rule"
		}
		relPath := normalizeRelPath(targetDir, res.Path)
		startLine := max(0, res.Start.Line)
		endLine := max(0, res.End.Line)
		sev := mapSemgrepSeverity(res.Extra.Severity)
		fp := ComputeFingerprint(string(ScannerSemgrep), ruleID, relPath, startLine, endLine, res.Extra.Fingerprint)

		msg := redactor.ScrubString(strings.TrimSpace(res.Extra.Message))
		if msg == "" {
			msg = fmt.Sprintf("SAST finding %s", ruleID)
		}

		meta := redactor.SanitizeMetadata(res.Extra.Metadata)
		meta["tool"] = string(ScannerSemgrep)

		out.findings = append(out.findings, domain.Finding{
			Scanner:     string(ScannerSemgrep),
			Category:    "SAST",
			Severity:    sev,
			RuleID:      ruleID,
			Path:        relPath,
			StartLine:   startLine,
			EndLine:     endLine,
			Fingerprint: fp,
			Confidence:  1.0,
			Message:     msg,
			Redacted:    true,
			Metadata:    meta,
		})
	}

	return out, nil
}

func mapSemgrepSeverity(raw string) domain.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "ERROR", "HIGH":
		return domain.SeverityHigh
	case "WARNING", "WARN", "MEDIUM":
		return domain.SeverityMedium
	case "INFO":
		return domain.SeverityInfo
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityMedium
	}
}
