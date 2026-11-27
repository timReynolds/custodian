package inspection

import (
	"context"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const defaultIPFingerprintVersion = "1.0.0"

// DefaultIPFingerprinter provides the baseline Stage A IP fingerprinting hook for RESTRICTED repositories.
// External or future M6 similarity engines can implement IPFingerprinter and inject via Config.IPFingerprinter.
type DefaultIPFingerprinter struct{}

// NewDefaultIPFingerprinter creates the default Stage A IPFingerprinter implementation.
func NewDefaultIPFingerprinter() *DefaultIPFingerprinter {
	return &DefaultIPFingerprinter{}
}

func (d *DefaultIPFingerprinter) Name() string {
	return string(ScannerIPFingerprint)
}

func (d *DefaultIPFingerprinter) Version() string {
	return defaultIPFingerprintVersion
}

func (d *DefaultIPFingerprinter) Analyze(ctx context.Context, req Request, inv *Inventory) ([]domain.Finding, domain.ScanCoverage, error) {
	if ctx.Err() != nil {
		return nil, domain.ScanCoverage{Complete: false}, ctx.Err()
	}
	var examined int
	var bytesExamined int64
	if inv != nil {
		examined = inv.FilesExamined
		bytesExamined = inv.BytesExamined
	}
	if req.Stage == StagePushEgress {
		return nil, domain.ScanCoverage{
			FilesExamined:  examined,
			FilesSkipped:   0,
			BytesExamined:  bytesExamined,
			SkippedReasons: []string{"ip_fingerprinter_unconfigured"},
			Complete:       false,
		}, domain.Unavailable("IP_FINGERPRINTER_UNCONFIGURED", "fingerprints.Engine must be configured for PUSH_EGRESS")
	}
	if inv == nil {
		return nil, domain.ScanCoverage{
			FilesExamined:  0,
			FilesSkipped:   0,
			SkippedReasons: []string{},
			Complete:       true,
		}, nil
	}
	// finalizeScanRunCoverage adds inv.FilesSkipped and inv.SkippedReasons; report 0 newly skipped here.
	return nil, domain.ScanCoverage{
		FilesExamined:  inv.FilesExamined,
		FilesSkipped:   0,
		BytesExamined:  inv.BytesExamined,
		SkippedReasons: []string{},
		Complete:       inv.FilesSkipped == 0 && len(inv.SkippedReasons) == 0,
	}, nil
}

type ipFingerprintScanner struct {
	hook IPFingerprinter
}

func newIPFingerprintScanner(hook IPFingerprinter) *ipFingerprintScanner {
	if hook == nil {
		hook = NewDefaultIPFingerprinter()
	}
	return &ipFingerprintScanner{hook: hook}
}

func (s *ipFingerprintScanner) Name() string {
	name := s.hook.Name()
	if name == "" {
		return string(ScannerIPFingerprint)
	}
	return name
}

func (s *ipFingerprintScanner) Version(context.Context) (string, error) {
	ver := s.hook.Version()
	if ver == "" {
		return defaultIPFingerprintVersion, nil
	}
	return ver, nil
}

func (s *ipFingerprintScanner) Scan(ctx context.Context, req Request, inv *Inventory) (ScannerOutcome, error) {
	startedAt := time.Now().UTC().Truncate(time.Microsecond)
	runID, err := domain.NewID()
	if err != nil {
		return ScannerOutcome{}, err
	}

	ver, _ := s.Version(ctx)
	run := domain.ScanRun{
		ID:             runID,
		ProposalID:     req.ProposalID,
		PushSessionID:  cloneUUIDPtr(req.PushSessionID),
		ArtifactID:     req.ArtifactID,
		Scanner:        s.Name(),
		ScannerVersion: ver,
		Status:         domain.ScanStatusRunning,
		StartedAt:      startedAt,
	}

	redactor := NewRedactor(req.ExtraSecrets...)
	findings, cov, analyzeErr := s.hook.Analyze(ctx, req, inv)
	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	run.CompletedAt = &completedAt

	if analyzeErr != nil {
		timedOut := ctx.Err() != nil
		reason := "hook_error"
		if timedOut {
			reason = "timeout"
		}
		finalizeScanRunCoverage(&run, inv, cov.FilesExamined, cov.FilesSkipped, append(cov.SkippedReasons, reason), !timedOut, timedOut, redactor)
		return ScannerOutcome{
			ScanRun:       run,
			FailureReason: reason,
		}, analyzeErr
	}

	for i := range findings {
		if findings[i].Scanner == "" {
			findings[i].Scanner = s.Name()
		}
		if err := redactor.FinalizeFinding(&findings[i], run.ID); err != nil {
			finalizeScanRunCoverage(&run, inv, cov.FilesExamined, cov.FilesSkipped, append(cov.SkippedReasons, "redaction_validation_failed"), true, false, redactor)
			return ScannerOutcome{
				ScanRun:       run,
				FailureReason: "redaction_error",
			}, err
		}
	}

	reasons := cloneStringSlice(cov.SkippedReasons)
	if !cov.Complete && cov.FilesSkipped == 0 && len(reasons) == 0 {
		reasons = append(reasons, "ip_fingerprint_incomplete")
	}
	finalizeScanRunCoverage(&run, inv, cov.FilesExamined, cov.FilesSkipped, reasons, false, false, redactor)
	if !cov.Complete {
		run.Coverage.Complete = false
		if run.Status == domain.ScanStatusCompleted {
			run.Status = domain.ScanStatusIncomplete
		}
	}
	failureReason := ""
	if !run.IsCleanComplete() {
		failureReason = "files_skipped"
	}
	return ScannerOutcome{
		ScanRun:       run,
		Findings:      findings,
		FailureReason: failureReason,
	}, nil
}
