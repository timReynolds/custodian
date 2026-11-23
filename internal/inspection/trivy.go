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

type trivyReport struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName"`
	ArtifactType  string         `json:"ArtifactType"`
	Results       []*trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string                `json:"Target"`
	Class             string                `json:"Class"`
	Type              string                `json:"Type"`
	Vulnerabilities   []*trivyVulnerability `json:"Vulnerabilities"`
	Misconfigurations []*trivyMisconfig     `json:"Misconfigurations"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

type trivyMisconfig struct {
	ID       string `json:"ID"`
	Title    string `json:"Title"`
	Message  string `json:"Message"`
	Severity string `json:"Severity"`
}

type trivyScanner struct {
	cfg Config
}

func newTrivyScanner(cfg Config) *trivyScanner {
	return &trivyScanner{cfg: cfg}
}

func (s *trivyScanner) Name() string {
	return string(ScannerTrivy)
}

func (s *trivyScanner) Version(ctx context.Context) (string, error) {
	tmpDir, err := os.MkdirTemp("", "custodian-trivy-ver-*")
	if err != nil {
		return "unknown", err
	}
	defer os.RemoveAll(tmpDir)
	ver, missing, err := probeVersion(ctx, s.cfg.TrivyBin, []string{"--version"}, s.cfg.VersionProbeTimeout, tmpDir, nil)
	if missing {
		return "unknown", err
	}
	return ver, nil
}

func (s *trivyScanner) Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error) {
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

	tmpDir, err := os.MkdirTemp("", "custodian-trivy-*")
	if err != nil {
		return ScannerOutcome{}, err
	}
	defer os.RemoveAll(tmpDir)

	redactor := NewRedactor(req.ExtraSecrets...)
	ver, missing, verErr := probeVersion(ctx, s.cfg.TrivyBin, []string{"--version"}, s.cfg.VersionProbeTimeout, tmpDir, redactor)
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

	reportPath := filepath.Join(tmpDir, "trivy.json")
	args := []string{
		"fs",
		"--format", "json",
		"--output", reportPath,
		req.TargetDir,
	}

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.ScannerTimeout)
	defer cancel()

	res := runCommand(runCtx, s.cfg.TrivyBin, args, req.TargetDir, tmpDir, defaultMaxStdioBytes)
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

	findings, rawSecrets, resultCount, parseErr := parseTrivyReport(raw, req.TargetDir, redactor)
	if parseErr != nil {
		finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "invalid_json_report"), true, false, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: "parse_error",
		}, parseErr
	}

	for i := range findings {
		if err := redactor.FinalizeFinding(&findings[i], run.ID); err != nil {
			finalizeScanRunCoverage(&run, inv, 0, stderrSkipped, append(stderrReasons, "redaction_validation_failed"), true, false, redactor)
			return ScannerOutcome{
				ScanRun:       run,
				FailureReason: "redaction_error",
			}, err
		}
	}

	examined := resultCount
	if inv != nil && inv.FilesExamined > examined {
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

func parseTrivyReport(raw []byte, targetDir string, redactor *Redactor) ([]domain.Finding, []string, int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil, 0, fmt.Errorf("empty trivy report")
	}
	if bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return nil, nil, 0, fmt.Errorf("unexpected trivy JSON payload")
	}

	var rep trivyReport
	if err := json.Unmarshal(trimmed, &rep); err != nil {
		return nil, nil, 0, fmt.Errorf("decode trivy JSON: %w", err)
	}

	if rep.SchemaVersion <= 0 || rep.Results == nil {
		hasNativeHint := rep.SchemaVersion > 0 || rep.Results != nil
		if !hasNativeHint {
			findings, secrets, genErr := parseGenericFindingObject(trimmed, string(ScannerTrivy), targetDir, redactor)
			if genErr == nil && len(findings) > 0 {
				return findings, secrets, len(findings), nil
			}
			if genErr != nil {
				return nil, nil, 0, fmt.Errorf("trivy report missing SchemaVersion/Results: %w", genErr)
			}
		}
		return nil, nil, 0, fmt.Errorf("trivy report missing SchemaVersion/Results")
	}

	findings := make([]domain.Finding, 0)
	for rIdx, res := range rep.Results {
		if res == nil {
			return nil, nil, 0, fmt.Errorf("trivy result element %d is null", rIdx)
		}
		if strings.TrimSpace(res.Target) == "" && len(res.Vulnerabilities) == 0 && len(res.Misconfigurations) == 0 {
			return nil, nil, 0, fmt.Errorf("trivy result element %d is empty", rIdx)
		}
		relPath := normalizeRelPath(targetDir, res.Target)
		for vIdx, v := range res.Vulnerabilities {
			if v == nil {
				return nil, nil, 0, fmt.Errorf("trivy vulnerability element %d.%d is null", rIdx, vIdx)
			}
			if strings.TrimSpace(v.VulnerabilityID) == "" &&
				strings.TrimSpace(v.PkgName) == "" &&
				strings.TrimSpace(v.Title) == "" {
				return nil, nil, 0, fmt.Errorf("trivy vulnerability element %d.%d is empty", rIdx, vIdx)
			}
			ruleID := strings.TrimSpace(v.VulnerabilityID)
			if ruleID == "" {
				ruleID = "trivy-vulnerability"
			}
			title := strings.TrimSpace(v.Title)
			if title == "" {
				title = ruleID
			}
			msg := fmt.Sprintf("%s (%s %s -> %s)", title, strings.TrimSpace(v.PkgName), strings.TrimSpace(v.InstalledVersion), strings.TrimSpace(v.FixedVersion))
			msg = redactor.ScrubString(strings.TrimSpace(msg))
			fp := ComputeFingerprint(string(ScannerTrivy), ruleID, relPath, 0, 0, v.PkgName+"@"+v.InstalledVersion)

			findings = append(findings, domain.Finding{
				Scanner:     string(ScannerTrivy),
				Category:    "VULNERABILITY",
				Severity:    normalizeSeverity(v.Severity),
				RuleID:      ruleID,
				Path:        relPath,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     msg,
				Redacted:    true,
				Metadata: map[string]any{
					"tool":              string(ScannerTrivy),
					"pkg_name":          v.PkgName,
					"installed_version": v.InstalledVersion,
					"fixed_version":     v.FixedVersion,
					"target_type":       res.Type,
					"target_class":      res.Class,
				},
			})
		}

		for mIdx, m := range res.Misconfigurations {
			if m == nil {
				return nil, nil, 0, fmt.Errorf("trivy misconfiguration element %d.%d is null", rIdx, mIdx)
			}
			if strings.TrimSpace(m.ID) == "" &&
				strings.TrimSpace(m.Title) == "" &&
				strings.TrimSpace(m.Message) == "" {
				return nil, nil, 0, fmt.Errorf("trivy misconfiguration element %d.%d is empty", rIdx, mIdx)
			}
			ruleID := strings.TrimSpace(m.ID)
			if ruleID == "" {
				ruleID = "trivy-misconfiguration"
			}
			msg := strings.TrimSpace(m.Title)
			if m.Message != "" {
				msg = strings.TrimSpace(m.Message)
			}
			if msg == "" {
				msg = ruleID
			}
			fp := ComputeFingerprint(string(ScannerTrivy), ruleID, relPath, 0, 0, msg)
			findings = append(findings, domain.Finding{
				Scanner:     string(ScannerTrivy),
				Category:    "MISCONFIGURATION",
				Severity:    normalizeSeverity(m.Severity),
				RuleID:      ruleID,
				Path:        relPath,
				Fingerprint: fp,
				Confidence:  1.0,
				Message:     redactor.ScrubString(msg),
				Redacted:    true,
				Metadata: map[string]any{
					"tool":         string(ScannerTrivy),
					"target_type":  res.Type,
					"target_class": res.Class,
				},
			})
		}
	}

	return findings, nil, len(rep.Results), nil
}
