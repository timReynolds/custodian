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

type scancodeReport struct {
	Headers []scancodeHeader `json:"headers"`
	Files   []*scancodeFile  `json:"files"`
}

type scancodeHeader struct {
	ToolName    string            `json:"tool_name"`
	ToolVersion string            `json:"tool_version"`
	Errors      []string          `json:"errors"`
	ExtraData   scancodeExtraData `json:"extra_data"`
}

type scancodeExtraData struct {
	FilesCount   int `json:"files_count"`
	FilesSkipped int `json:"files_skipped"`
}

type scancodeFile struct {
	Path                          string                     `json:"path"`
	Type                          string                     `json:"type"`
	DetectedLicenseExpressionSPDX string                     `json:"detected_license_expression_spdx"`
	LicenseDetections             []scancodeLicenseDetection `json:"license_detections"`
	ScanErrors                    []string                   `json:"scan_errors"`
}

type scancodeLicenseDetection struct {
	LicenseExpressionSPDX string `json:"license_expression_spdx"`
	RuleIdentifier        string `json:"rule_identifier"`
}

type scancodeScanner struct {
	cfg Config
}

func newScanCodeScanner(cfg Config) *scancodeScanner {
	return &scancodeScanner{cfg: cfg}
}

func (s *scancodeScanner) Name() string {
	return string(ScannerScanCode)
}

func (s *scancodeScanner) Version(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "custodian-scancode-ver-*")
	if err != nil {
		return "unknown", err
	}
	defer os.RemoveAll(tmpDir)
	ver, missing, err := probeVersion(ctx, s.cfg.ScanCodeBin, []string{"--version"}, s.cfg.VersionProbeTimeout, tmpDir, nil)
	if missing {
		return "unknown", err
	}
	return ver, nil
}

func (s *scancodeScanner) Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error) {
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

	tmpDir, err := os.MkdirTemp("", "custodian-scancode-*")
	if err != nil {
		return ScannerOutcome{}, err
	}
	defer os.RemoveAll(tmpDir)

	redactor := NewRedactor(req.ExtraSecrets...)
	ver, missing, verErr := probeVersion(ctx, s.cfg.ScanCodeBin, []string{"--version"}, s.cfg.VersionProbeTimeout, tmpDir, redactor)
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

	reportPath := filepath.Join(tmpDir, "scancode.json")
	// Always use --json-pp (never bare --json) to avoid ambiguity with directory positional args.
	args := []string{
		"--license",
		"--json-pp", reportPath,
		req.TargetDir,
	}

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.ScannerTimeout)
	defer cancel()

	res := runCommand(runCtx, s.cfg.ScanCodeBin, args, req.TargetDir, tmpDir, defaultMaxStdioBytes)
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

	parsed, parseErr := parseScanCodeReport(raw, req.TargetDir, s.cfg.ProhibitedLicenses, redactor)
	if parseErr != nil {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "invalid_json_report"), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "parse_error",
		}, parseErr
	}

	if parsed.toolVersion != "" && run.ScannerVersion == "unknown" {
		scrubbedVer := strings.TrimSpace(redactor.ScrubString(parsed.toolVersion))
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

type scancodeParsed struct {
	toolVersion    string
	findings       []domain.Finding
	filesExamined  int
	filesSkipped   int
	skippedReasons []string
	rawSecrets     []string
}

func parseScanCodeReport(raw []byte, targetDir string, prohibited []string, redactor *Redactor) (scancodeParsed, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return scancodeParsed{}, fmt.Errorf("empty scancode report")
	}
	if bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return scancodeParsed{}, fmt.Errorf("unexpected scancode JSON payload")
	}

	var rep scancodeReport
	if err := json.Unmarshal(trimmed, &rep); err != nil {
		return scancodeParsed{}, fmt.Errorf("decode scancode JSON: %w", err)
	}

	// Support generic cross-scanner fallback payload if ScanCode fields are absent; fail closed otherwise.
	hasValidHeader := false
	for _, hdr := range rep.Headers {
		if strings.TrimSpace(hdr.ToolName) != "" || strings.TrimSpace(hdr.ToolVersion) != "" {
			hasValidHeader = true
			break
		}
	}
	if !hasValidHeader || rep.Files == nil {
		hasNativeHint := len(rep.Headers) > 0 || rep.Files != nil
		if !hasNativeHint {
			findings, secrets, genErr := parseGenericFindingObject(trimmed, string(ScannerScanCode), targetDir, redactor)
			if genErr == nil && len(findings) > 0 {
				for i := range findings {
					if isProhibitedLicense(findings[i].RuleID+" "+findings[i].Message, prohibited) {
						if findings[i].Metadata == nil {
							findings[i].Metadata = map[string]any{}
						}
						findings[i].Metadata["prohibited"] = true
					}
				}
				return scancodeParsed{
					findings:      findings,
					filesExamined: len(findings),
					rawSecrets:    secrets,
				}, nil
			}
			if genErr != nil {
				return scancodeParsed{}, fmt.Errorf("scancode report missing valid headers/files: %w", genErr)
			}
		}
		return scancodeParsed{}, fmt.Errorf("scancode report missing valid headers/files")
	}

	out := scancodeParsed{
		findings: make([]domain.Finding, 0),
	}

	for _, hdr := range rep.Headers {
		if out.toolVersion == "" && strings.TrimSpace(hdr.ToolVersion) != "" {
			ver := strings.TrimSpace(hdr.ToolVersion)
			if redactor != nil {
				ver = strings.TrimSpace(redactor.ScrubString(ver))
			}
			out.toolVersion = ver
		}
		if hdr.ExtraData.FilesCount > out.filesExamined {
			out.filesExamined = hdr.ExtraData.FilesCount
		}
		if hdr.ExtraData.FilesSkipped > out.filesSkipped {
			out.filesSkipped = hdr.ExtraData.FilesSkipped
		}
		for _, e := range hdr.Errors {
			reason := strings.TrimSpace(e)
			if reason == "" {
				reason = "scancode_error"
			} else if redactor != nil {
				reason = redactor.ScrubString(reason)
			}
			out.skippedReasons = append(out.skippedReasons, reason)
			if out.filesSkipped == 0 {
				out.filesSkipped = 1
			}
		}
	}

	if len(rep.Files) > out.filesExamined {
		out.filesExamined = len(rep.Files)
	}

	scanErrFiles := 0
	for idx, f := range rep.Files {
		if f == nil {
			return scancodeParsed{}, fmt.Errorf("scancode file element %d is null", idx)
		}
		if strings.TrimSpace(f.Path) == "" {
			return scancodeParsed{}, fmt.Errorf("scancode file element %d missing path", idx)
		}
		relPath := normalizeRelPath(targetDir, f.Path)
		if relPath == "" {
			return scancodeParsed{}, fmt.Errorf("scancode file element %d has empty normalized path", idx)
		}
		if len(f.ScanErrors) > 0 {
			scanErrFiles++
			for _, se := range f.ScanErrors {
				errMsg := strings.TrimSpace(se)
				if errMsg == "" {
					errMsg = "scancode_scan_error"
				} else if redactor != nil {
					errMsg = redactor.ScrubString(errMsg)
				}
				out.skippedReasons = append(out.skippedReasons, fmt.Sprintf("%s: %s", relPath, errMsg))
			}
		}

		detections := f.LicenseDetections
		if len(detections) == 0 && strings.TrimSpace(f.DetectedLicenseExpressionSPDX) != "" {
			detections = []scancodeLicenseDetection{{
				LicenseExpressionSPDX: strings.TrimSpace(f.DetectedLicenseExpressionSPDX),
			}}
		}

		for _, det := range detections {
			spdx := strings.TrimSpace(det.LicenseExpressionSPDX)
			if spdx == "" {
				spdx = strings.TrimSpace(f.DetectedLicenseExpressionSPDX)
			}
			if spdx == "" {
				continue
			}

			isProhib := isProhibitedLicense(spdx, prohibited)
			ruleID := strings.TrimSpace(det.RuleIdentifier)
			if ruleID == "" {
				ruleID = spdx
			}

			sev := domain.SeverityInfo
			msg := fmt.Sprintf("Detected SPDX license %s", spdx)
			if isProhib {
				sev = domain.SeverityHigh
				msg = fmt.Sprintf("Prohibited SPDX license %s detected", spdx)
			}

			fp := ComputeFingerprint(string(ScannerScanCode), ruleID, relPath, 0, 0, spdx)
			out.findings = append(out.findings, domain.Finding{
				Scanner:     string(ScannerScanCode),
				Category:    "LICENSE",
				Severity:    sev,
				RuleID:      ruleID,
				Path:        relPath,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     msg,
				Redacted:    true,
				Metadata: map[string]any{
					"tool":       string(ScannerScanCode),
					"spdx":       spdx,
					"prohibited": isProhib,
				},
			})
		}
	}

	if scanErrFiles > out.filesSkipped {
		out.filesSkipped = scanErrFiles
	}
	if len(out.skippedReasons) > 0 && out.filesSkipped == 0 {
		out.filesSkipped = len(out.skippedReasons)
	}
	return out, nil
}

func isProhibitedLicense(spdx string, prohibited []string) bool {
	upper := strings.ToUpper(strings.TrimSpace(spdx))
	if upper == "" {
		return false
	}
	// Tokenize composite SPDX expressions like "MIT OR GPL-3.0-only" or "Apache-2.0 WITH ..."
	tokens := strings.FieldsFunc(upper, func(r rune) bool {
		return r == ' ' || r == '(' || r == ')' || r == ',' || r == ';'
	})
	checkList := prohibited
	if len(checkList) == 0 {
		checkList = DefaultProhibitedLicenses
	}
	for _, tok := range tokens {
		if tok == "AND" || tok == "OR" || tok == "WITH" {
			continue
		}
		for _, rule := range checkList {
			rUpper := strings.ToUpper(strings.TrimSpace(rule))
			if rUpper == "" {
				continue
			}
			if strings.HasSuffix(rUpper, "-") {
				if strings.HasPrefix(tok, rUpper) || tok == strings.TrimSuffix(rUpper, "-") {
					return true
				}
			} else if tok == rUpper || strings.HasPrefix(tok, rUpper+"-") {
				return true
			}
		}
	}
	return false
}
