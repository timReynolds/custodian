package inspection

import (
	"context"

	"github.com/google/uuid"
	"github.com/timreynolds/custodian/internal/domain"
)

// ScannerKind identifies a Stage A scanner.
type ScannerKind string

const (
	ScannerGitleaks      ScannerKind = "gitleaks"
	ScannerScanCode      ScannerKind = "scancode"
	ScannerSemgrep       ScannerKind = "semgrep"
	ScannerTrivy         ScannerKind = "trivy"
	ScannerCustom        ScannerKind = "custom"
	ScannerIPFingerprint ScannerKind = "ip_fingerprint"
)

// Stage identifies the Custodian workflow stage triggering inspection.
const (
	StageIngress = "INGRESS"
	StageEgress  = "EGRESS"
)

// MandatoryScanners lists scanners required on every Stage A inspection run.
var MandatoryScanners = []ScannerKind{
	ScannerGitleaks,
	ScannerScanCode,
	ScannerSemgrep,
	ScannerCustom,
}

// Request describes the verified workspace/tree target for Stage A inspection.
type Request struct {
	ProposalID        uuid.UUID             `json:"proposal_id"`
	ArtifactID        uuid.UUID             `json:"artifact_id"`
	TargetDir         string                `json:"target_dir"`
	Classification    domain.Classification `json:"classification"`
	Stage             string                `json:"stage,omitempty"`
	ChangedPaths      []string              `json:"changed_paths,omitempty"`
	MandatoryScanners []string              `json:"mandatory_scanners,omitempty"`
	ExtraSecrets      []string              `json:"-"`
}

// ScannerOutcome is the normalized output from a single Stage A scanner execution.
type ScannerOutcome struct {
	ScanRun       domain.ScanRun
	Findings      []domain.Finding
	FailureReason string
	rawSecrets    []string
}

// Scanner executes deterministic Stage A analysis for a single tool or rule engine.
type Scanner interface {
	Name() string
	Version(ctx context.Context) (string, error)
	Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error)
}

// IPFingerprinter is the Stage A extension hook for RESTRICTED repositories.
type IPFingerprinter interface {
	Name() string
	Version() string
	Analyze(ctx context.Context, req Request, inv *Inventory) ([]domain.Finding, domain.ScanCoverage, error)
}

// Runner executes the full Stage A deterministic inspection pipeline.
type Runner interface {
	Inspect(ctx context.Context, req Request) (Report, error)
}

// InspectionSummary aggregates normalized Stage A evidence and coverage facts.
type InspectionSummary struct {
	MandatoryScannersComplete bool           `json:"mandatory_scanners_complete"`
	ScanComplete              bool           `json:"scan_complete"`
	CriticalSecrets           int            `json:"critical_secrets"`
	ProhibitedLicenses        int            `json:"prohibited_licenses"`
	HighVulnerabilities       int            `json:"high_vulnerabilities"`
	HighSASTFindings          int            `json:"high_sast_findings"`
	TotalFindings             int            `json:"total_findings"`
	CountsByCategory          map[string]int `json:"counts_by_category"`
	CountsBySeverity          map[string]int `json:"counts_by_severity"`
	CountsByScanner           map[string]int `json:"counts_by_scanner"`
	EvidenceIDs               []string       `json:"evidence_ids"`
	FailedScanners            []string       `json:"failed_scanners"`
	IncompleteScanners        []string       `json:"incomplete_scanners"`
}

// PolicyFacts exposes the Stage A summary map consumed by Stage C CEL rules under "findings".
func (s InspectionSummary) PolicyFacts() map[string]any {
	return map[string]any{
		"mandatory_scanners_complete": s.MandatoryScannersComplete,
		"scan_complete":               s.ScanComplete,
		"critical_secrets":            s.CriticalSecrets,
		"prohibited_licenses":         s.ProhibitedLicenses,
		"high_vulnerabilities":        s.HighVulnerabilities,
		"high_sast_findings":          s.HighSASTFindings,
		"total_findings":              s.TotalFindings,
		"counts_by_category":          cloneIntMap(s.CountsByCategory),
		"counts_by_severity":          cloneIntMap(s.CountsBySeverity),
		"counts_by_scanner":           cloneIntMap(s.CountsByScanner),
		"evidence_ids":                cloneStringSlice(s.EvidenceIDs),
		"failed_scanners":             cloneStringSlice(s.FailedScanners),
		"incomplete_scanners":         cloneStringSlice(s.IncompleteScanners),
	}
}

// Report contains all persisted-ready Stage A scan runs, redacted findings, and summary facts.
type Report struct {
	ProposalID uuid.UUID         `json:"proposal_id"`
	ArtifactID uuid.UUID         `json:"artifact_id"`
	ScanRuns   []domain.ScanRun  `json:"scan_runs"`
	Findings   []domain.Finding  `json:"findings"`
	Summary    InspectionSummary `json:"summary"`
	redactor   *Redactor
}

// ScrubText redacts all secrets harvested during Stage A inspection (plus encoded
// variants and built-in credential patterns) from untrusted text before downstream
// consumption (e.g., Stage B canonical diffs).
func (r Report) ScrubText(s string) string {
	if s == "" {
		return ""
	}
	if r.redactor != nil {
		return r.redactor.ScrubString(s)
	}
	return NewRedactor().ScrubString(s)
}

// AllCleanComplete reports whether every mandatory and invoked scanner finished cleanly with zero skipped files.
func (r Report) AllCleanComplete() bool {
	if len(r.ScanRuns) == 0 {
		return false
	}
	seenMandatory := make(map[ScannerKind]bool, len(MandatoryScanners))
	for _, run := range r.ScanRuns {
		if !run.IsCleanComplete() {
			return false
		}
		k := ScannerKind(run.Scanner)
		for _, m := range MandatoryScanners {
			if k == m {
				seenMandatory[m] = true
			}
		}
	}
	for _, m := range MandatoryScanners {
		if !seenMandatory[m] {
			return false
		}
	}
	return true
}

func cloneIntMap(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
