package inspection

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// DefaultRunner orchestrates Stage A deterministic scanners, secret redaction,
// coverage tracking, and observability emission.
type DefaultRunner struct {
	cfg Config
}

// NewRunner constructs a Stage A inspection Runner with defaults applied to zero-value fields.
func NewRunner(cfg Config) *DefaultRunner {
	return &DefaultRunner{
		cfg: cfg.withDefaults(),
	}
}

type scannerExecResult struct {
	outcome    ScannerOutcome
	spanCtx    context.Context
	span       trace.Span
	duration   time.Duration
	durationMs int64
	hasErr     bool
}

// Inspect executes all mandatory and triggered conditional Stage A scanners against req.TargetDir.
func (r *DefaultRunner) Inspect(ctx context.Context, req Request) (Report, error) {
	if req.PushSessionID != nil && *req.PushSessionID == uuid.Nil {
		return Report{}, domain.BadRequest("INVALID_PUSH_SESSION_ID", "push_session_id must not be nil when provided")
	}
	hasProposal := req.ProposalID != uuid.Nil
	hasPush := req.PushSessionID != nil && *req.PushSessionID != uuid.Nil
	if !hasProposal && !hasPush {
		return Report{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id or push_session_id is required")
	}
	if hasProposal && hasPush {
		return Report{}, domain.BadRequest("INVALID_INSPECTION_OWNER", "proposal_id and push_session_id are mutually exclusive")
	}
	if req.ArtifactID == uuid.Nil {
		return Report{}, domain.BadRequest("INVALID_ARTIFACT_ID", "artifact_id is required")
	}
	if strings.TrimSpace(req.TargetDir) == "" {
		return Report{}, domain.BadRequest("INVALID_TARGET_DIR", "target_dir is required")
	}
	if req.Stage == "" {
		req.Stage = StageEgress
	}
	req.TargetDir = filepath.Clean(req.TargetDir)

	spanAttrs := []attribute.KeyValue{
		attribute.String("artifact_id", req.ArtifactID.String()),
		attribute.String("classification", string(req.Classification)),
		attribute.String("stage", req.Stage),
	}
	if hasProposal {
		spanAttrs = append(spanAttrs, attribute.String("proposal_id", req.ProposalID.String()))
	}
	if hasPush {
		spanAttrs = append(spanAttrs, attribute.String("push_session_id", req.PushSessionID.String()))
	}

	tracer := r.tracer()
	rootCtx, rootSpan := tracer.Start(ctx, "inspection.stage_a", trace.WithAttributes(spanAttrs...))
	defer rootSpan.End()

	inv, err := WalkWorkspace(req.TargetDir)
	if err != nil {
		rootSpan.RecordError(err)
		rootSpan.SetStatus(codes.Error, "workspace walk failed")
		return Report{}, err
	}

	scanners := r.scheduleScanners(req, inv)
	results := make([]scannerExecResult, len(scanners))
	defer func() {
		for i := range results {
			if results[i].span != nil {
				results[i].span.End()
				results[i].span = nil
			}
		}
	}()

	var wg sync.WaitGroup
	for i, sc := range scanners {
		wg.Add(1)
		go func(idx int, scanner Scanner) {
			defer wg.Done()
			results[idx] = r.runSingleScanner(rootCtx, tracer, scanner, req, inv)
		}(i, sc)
	}
	wg.Wait()

	// Aggregate all discovered secrets across every scanner so cross-scanner leaks are scrubbed everywhere.
	redactor := NewRedactor(req.ExtraSecrets...)
	for _, res := range results {
		redactor.AddSecrets(res.outcome.rawSecrets...)
	}

	runs := make([]domain.ScanRun, 0, len(results))
	findings := make([]domain.Finding, 0)
	for i, res := range results {
		out := res.outcome
		if len(out.ScanRun.Coverage.SkippedReasons) > 0 {
			scrubbedReasons := make([]string, len(out.ScanRun.Coverage.SkippedReasons))
			for j, reason := range out.ScanRun.Coverage.SkippedReasons {
				scrubbedReasons[j] = redactor.ScrubString(reason)
			}
			out.ScanRun.Coverage.SkippedReasons = scrubbedReasons
		}
		out.ScanRun.ScannerVersion = strings.TrimSpace(redactor.ScrubString(out.ScanRun.ScannerVersion))
		if len(out.ScanRun.ScannerVersion) > 64 {
			out.ScanRun.ScannerVersion = out.ScanRun.ScannerVersion[:64]
		}
		if out.ScanRun.ScannerVersion == "" {
			out.ScanRun.ScannerVersion = "unknown"
		}
		if out.FailureReason != "" {
			out.FailureReason = redactor.ScrubString(out.FailureReason)
		}

		r.cfg.Metrics.IncScannerRun(out.ScanRun.Scanner, string(out.ScanRun.Status))
		if out.ScanRun.Scanner == string(ScannerIPFingerprint) {
			r.cfg.Metrics.ObservePushIPFingerprint(safeMetricClassificationLabel(string(req.Classification)), res.duration)
		}
		if !out.ScanRun.IsCleanComplete() {
			reason := out.FailureReason
			if reason == "" {
				reason = strings.ToLower(string(out.ScanRun.Status))
			}
			r.cfg.Metrics.IncScannerFailure(out.ScanRun.Scanner, reason)
			if res.span != nil {
				res.span.SetStatus(codes.Error, reason)
			}
		}
		if res.span != nil {
			res.span.End()
			results[i].span = nil
		}

		r.logScannerOutcome(res.spanCtx, out, res.durationMs, res.hasErr)

		runs = append(runs, out.ScanRun)
		for j := range out.Findings {
			if err := redactor.FinalizeFinding(&out.Findings[j], out.ScanRun.ID); err != nil {
				rootSpan.RecordError(err)
				rootSpan.SetStatus(codes.Error, "finding redaction validation failed")
				r.cfg.Metrics.IncScannerFailure(out.ScanRun.Scanner, "redaction_error")
				return Report{}, err
			}
			if layerLabel, clsLabel, ok := ipFindingMetricLabels(out.Findings[j]); ok {
				r.cfg.Metrics.IncPushIPMatch(layerLabel, clsLabel)
			}
			findings = append(findings, out.Findings[j])
		}
	}

	sortFindingsDeterministically(findings)
	summary := buildSummary(runs, findings, r.cfg.ProhibitedLicenses)

	rootSpan.SetAttributes(
		attribute.Bool("scan_complete", summary.ScanComplete),
		attribute.Int("total_findings", summary.TotalFindings),
		attribute.Int("critical_secrets", summary.CriticalSecrets),
	)

	return Report{
		ProposalID:    req.ProposalID,
		PushSessionID: cloneUUIDPtr(req.PushSessionID),
		ArtifactID:    req.ArtifactID,
		ScanRuns:      runs,
		Findings:      findings,
		Summary:       summary,
		redactor:      redactor,
	}, nil
}

func (r *DefaultRunner) scheduleScanners(req Request, inv *Inventory) []Scanner {
	scanners := []Scanner{
		newGitleaksScanner(r.cfg),
		newScanCodeScanner(r.cfg),
		newSemgrepScanner(r.cfg),
		newCustomScanner(r.cfg),
	}
	if (inv != nil && inv.HasManifests) || slices.Contains(req.MandatoryScanners, string(ScannerTrivy)) {
		scanners = append(scanners, newTrivyScanner(r.cfg))
	}
	if req.Stage == StagePushEgress ||
		req.Classification == domain.ClassificationRestricted ||
		slices.Contains(req.MandatoryScanners, string(ScannerIPFingerprint)) {
		scanners = append(scanners, newIPFingerprintScanner(r.cfg.IPFingerprinter))
	}
	for _, extra := range r.cfg.ExtraScanners {
		if extra != nil {
			scanners = append(scanners, extra)
		}
	}
	return scanners
}

func (r *DefaultRunner) runSingleScanner(ctx context.Context, tracer trace.Tracer, sc Scanner, req Request, inv *Inventory) scannerExecResult {
	scannerName := sc.Name()
	start := time.Now()
	spanAttrs := []attribute.KeyValue{
		attribute.String("artifact_id", req.ArtifactID.String()),
		attribute.String("scanner", scannerName),
	}
	if req.ProposalID != uuid.Nil {
		spanAttrs = append(spanAttrs, attribute.String("proposal_id", req.ProposalID.String()))
	}
	if req.PushSessionID != nil && *req.PushSessionID != uuid.Nil {
		spanAttrs = append(spanAttrs, attribute.String("push_session_id", req.PushSessionID.String()))
	}
	spanCtx, span := tracer.Start(ctx, "inspection.scanner."+scannerName, trace.WithAttributes(spanAttrs...))

	out, err := sc.Scan(spanCtx, req, inv)
	if out.ScanRun.ID == uuid.Nil || !domain.IsUUIDv7(out.ScanRun.ID) {
		if out.ScanRun.ID == uuid.Nil {
			now := time.Now().UTC().Truncate(time.Microsecond)
			out.ScanRun = domain.ScanRun{
				ID:             domain.MustNewID(),
				ProposalID:     req.ProposalID,
				PushSessionID:  cloneUUIDPtr(req.PushSessionID),
				ArtifactID:     req.ArtifactID,
				Scanner:        scannerName,
				ScannerVersion: "unknown",
				Status:         domain.ScanStatusFailed,
				Coverage: domain.ScanCoverage{
					FilesExamined:  0,
					FilesSkipped:   0,
					SkippedReasons: []string{"scanner_internal_error"},
					Complete:       false,
				},
				StartedAt:   start.UTC().Truncate(time.Microsecond),
				CompletedAt: &now,
			}
			if out.FailureReason == "" {
				out.FailureReason = "internal_error"
			}
		} else {
			out.ScanRun.ID = domain.MustNewID()
		}
	}
	if err != nil && out.ScanRun.Status != domain.ScanStatusTimedOut {
		out.ScanRun.Status = domain.ScanStatusFailed
		out.ScanRun.Coverage.Complete = false
		if out.ScanRun.CompletedAt == nil {
			now := time.Now().UTC().Truncate(time.Microsecond)
			out.ScanRun.CompletedAt = &now
		}
		if len(out.ScanRun.Coverage.SkippedReasons) == 0 {
			out.ScanRun.Coverage.SkippedReasons = []string{"scanner_error"}
		}
		if out.FailureReason == "" {
			out.FailureReason = "scanner_error"
		}
	}
	if out.ScanRun.ProposalID == uuid.Nil && req.ProposalID != uuid.Nil {
		out.ScanRun.ProposalID = req.ProposalID
	}
	if out.ScanRun.PushSessionID == nil && req.PushSessionID != nil {
		out.ScanRun.PushSessionID = cloneUUIDPtr(req.PushSessionID)
	}
	if out.ScanRun.ArtifactID == uuid.Nil {
		out.ScanRun.ArtifactID = req.ArtifactID
	}
	if out.ScanRun.Scanner == "" {
		out.ScanRun.Scanner = scannerName
	}
	if strings.TrimSpace(out.ScanRun.ScannerVersion) == "" {
		out.ScanRun.ScannerVersion = "unknown"
	}
	if out.ScanRun.Coverage.SkippedReasons == nil {
		out.ScanRun.Coverage.SkippedReasons = []string{}
	}

	duration := time.Since(start)
	durationMs := duration.Milliseconds()

	span.SetAttributes(
		attribute.String("scan_run_id", out.ScanRun.ID.String()),
		attribute.String("status", string(out.ScanRun.Status)),
		attribute.Int("files_examined", out.ScanRun.Coverage.FilesExamined),
		attribute.Int("files_skipped", out.ScanRun.Coverage.FilesSkipped),
		attribute.Bool("complete", out.ScanRun.Coverage.Complete),
	)

	return scannerExecResult{
		outcome:    out,
		spanCtx:    spanCtx,
		span:       span,
		duration:   duration,
		durationMs: durationMs,
		hasErr:     err != nil,
	}
}

func (r *DefaultRunner) logScannerOutcome(ctx context.Context, out ScannerOutcome, durationMs int64, hasErr bool) {
	if r.cfg.Logger == nil {
		return
	}
	logger := observability.LoggerWithTrace(ctx, r.cfg.Logger)
	attrs := []any{
		slog.String("proposal_id", out.ScanRun.ProposalID.String()),
		slog.String("artifact_id", out.ScanRun.ArtifactID.String()),
		slog.String("scan_run_id", out.ScanRun.ID.String()),
		slog.String("scanner", out.ScanRun.Scanner),
		slog.String("scanner_version", out.ScanRun.ScannerVersion),
		slog.String("status", string(out.ScanRun.Status)),
		slog.Int("files_examined", out.ScanRun.Coverage.FilesExamined),
		slog.Int("files_skipped", out.ScanRun.Coverage.FilesSkipped),
		slog.Bool("complete", out.ScanRun.Coverage.Complete),
		slog.Int64("duration_ms", durationMs),
	}
	if out.ScanRun.PushSessionID != nil {
		attrs = append(attrs, slog.String("push_session_id", out.ScanRun.PushSessionID.String()))
	}
	if out.FailureReason != "" {
		attrs = append(attrs, slog.String("error_code", out.FailureReason))
	}
	if !out.ScanRun.IsCleanComplete() || hasErr {
		logger.Warn("stage_a_scanner_incomplete_or_failed", attrs...)
		return
	}
	logger.Info("stage_a_scanner_completed", attrs...)
}

func (r *DefaultRunner) tracer() trace.Tracer {
	return r.cfg.Tracer.Tracer("custodian/inspection")
}

func sortFindingsDeterministically(findings []domain.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Scanner != findings[j].Scanner {
			return findings[i].Scanner < findings[j].Scanner
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		if findings[i].StartLine != findings[j].StartLine {
			return findings[i].StartLine < findings[j].StartLine
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}

func buildSummary(runs []domain.ScanRun, findings []domain.Finding, prohibitedLicenses []string) InspectionSummary {
	summary := InspectionSummary{
		CountsByCategory:   make(map[string]int),
		CountsBySeverity:   make(map[string]int),
		CountsByScanner:    make(map[string]int),
		EvidenceIDs:        make([]string, 0, len(findings)),
		FailedScanners:     make([]string, 0),
		IncompleteScanners: make([]string, 0),
	}

	mandatorySeen := make(map[ScannerKind]bool, len(MandatoryScanners))
	mandatoryClean := true
	allClean := len(runs) > 0

	for _, run := range runs {
		if run.IsCleanComplete() {
			for _, m := range MandatoryScanners {
				if ScannerKind(run.Scanner) == m {
					mandatorySeen[m] = true
				}
			}
			continue
		}
		allClean = false
		for _, m := range MandatoryScanners {
			if ScannerKind(run.Scanner) == m {
				mandatoryClean = false
			}
		}
		if run.Status == domain.ScanStatusFailed || run.Status == domain.ScanStatusTimedOut {
			summary.FailedScanners = append(summary.FailedScanners, run.Scanner)
		} else {
			summary.IncompleteScanners = append(summary.IncompleteScanners, run.Scanner)
		}
	}

	for _, m := range MandatoryScanners {
		if !mandatorySeen[m] {
			mandatoryClean = false
			allClean = false
		}
	}

	summary.MandatoryScannersComplete = mandatoryClean
	summary.ScanComplete = mandatoryClean && allClean

	seenEvidence := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		summary.TotalFindings++
		summary.CountsByCategory[f.Category]++
		summary.CountsBySeverity[string(f.Severity)]++
		if f.Scanner != "" {
			summary.CountsByScanner[f.Scanner]++
		}

		if f.EvidenceID != "" {
			if _, seen := seenEvidence[f.EvidenceID]; !seen {
				seenEvidence[f.EvidenceID] = struct{}{}
				summary.EvidenceIDs = append(summary.EvidenceIDs, f.EvidenceID)
			}
		}

		if f.Category == "SECRET" && (f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh) {
			summary.CriticalSecrets++
		}
		if f.Category == "LICENSE" && isFindingProhibitedLicense(f, prohibitedLicenses) {
			summary.ProhibitedLicenses++
		}
		if f.Category == "VULNERABILITY" && (f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh) {
			summary.HighVulnerabilities++
		}
		if f.Category == "SAST" && (f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh) {
			summary.HighSASTFindings++
		}

		cat := strings.ToUpper(strings.TrimSpace(f.Category))
		layer := findingMetadataString(f, "layer")
		if isIPConcealmentFinding(cat, layer, f.RuleID) {
			summary.ConcealmentFindings++
		}
		if isIPL1ExactFinding(cat, layer, f.RuleID) {
			summary.IPExactMatches++
		}
		if isIPL2WinnowFinding(cat, layer, f.RuleID) {
			summary.IPWinnowMatches++
		}
		if isIPL3HeaderStripFinding(f, cat) {
			summary.IPHeaderStripMatches++
		}
		if isIPCorpusOrMarkerMatch(cat, layer, f.RuleID) {
			switch findingIPClassification(f) {
			case string(domain.ClassificationRestricted):
				summary.RestrictedIPMatches++
			case string(domain.ClassificationConfidential):
				summary.ConfidentialIPMatches++
			}
		}
	}

	summary.FailedScanners = dedupeNonEmptyStrings(summary.FailedScanners)
	summary.IncompleteScanners = dedupeNonEmptyStrings(summary.IncompleteScanners)
	return summary
}

func cloneUUIDPtr(in *uuid.UUID) *uuid.UUID {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func findingMetadataString(f domain.Finding, key string) string {
	if f.Metadata == nil {
		return ""
	}
	if v, ok := f.Metadata[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func findingMetadataBool(f domain.Finding, key string) bool {
	if f.Metadata == nil {
		return false
	}
	v, ok := f.Metadata[key].(bool)
	return ok && v
}

func findingIPClassification(f domain.Finding) string {
	if cls := strings.ToUpper(findingMetadataString(f, "corpus_classification")); cls != "" {
		return cls
	}
	return strings.ToUpper(findingMetadataString(f, "classification"))
}

func isIPConcealmentFinding(cat, layer, ruleID string) bool {
	return cat == "CONCEALMENT" || cat == "IP_CONCEALMENT" ||
		strings.EqualFold(layer, "L4_CONCEALMENT") ||
		strings.HasPrefix(ruleID, "ip.l4.")
}

func isIPL1ExactFinding(cat, layer, ruleID string) bool {
	return cat == "IP_EXACT" ||
		strings.EqualFold(layer, string(domain.FingerprintLayerL1ExactChunk)) ||
		strings.HasPrefix(ruleID, "ip.l1.")
}

func isIPL2WinnowFinding(cat, layer, ruleID string) bool {
	return cat == "IP_WINNOW" ||
		strings.EqualFold(layer, string(domain.FingerprintLayerL2WinnowKGram)) ||
		strings.HasPrefix(ruleID, "ip.l2.")
}

func isIPL3HeaderStripFinding(f domain.Finding, cat string) bool {
	return cat == "IP_HEADER_STRIP" ||
		findingMetadataBool(f, "header_stripped") ||
		f.RuleID == "ip.l3.header-stripped" ||
		f.RuleID == "ip.l3.header-strip"
}

func isIPCorpusOrMarkerMatch(cat, layer, ruleID string) bool {
	if isIPConcealmentFinding(cat, layer, ruleID) {
		return false
	}
	return cat == "IP_EXACT" ||
		cat == "IP_WINNOW" ||
		cat == "IP_HEADER_MARKER" ||
		cat == "IP_HEADER_STRIP" ||
		cat == "IP_FINGERPRINT" ||
		cat == "IP_SIMILARITY" ||
		strings.HasPrefix(cat, "IP_") ||
		strings.HasPrefix(ruleID, "ip.l1.") ||
		strings.HasPrefix(ruleID, "ip.l2.") ||
		strings.HasPrefix(ruleID, "ip.l3.")
}

func safeMetricClassificationLabel(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(domain.ClassificationPublic):
		return string(domain.ClassificationPublic)
	case string(domain.ClassificationInternal):
		return string(domain.ClassificationInternal)
	case string(domain.ClassificationConfidential):
		return string(domain.ClassificationConfidential)
	case string(domain.ClassificationRestricted):
		return string(domain.ClassificationRestricted)
	default:
		return "UNKNOWN"
	}
}

func ipFindingMetricLabels(f domain.Finding) (layer string, classification string, ok bool) {
	cat := strings.ToUpper(strings.TrimSpace(f.Category))
	metaLayer := strings.ToUpper(findingMetadataString(f, "layer"))
	switch {
	case isIPConcealmentFinding(cat, metaLayer, f.RuleID):
		return "L4_CONCEALMENT", "CONCEALMENT", true
	case isIPL1ExactFinding(cat, metaLayer, f.RuleID):
		return string(domain.FingerprintLayerL1ExactChunk), safeMetricClassificationLabel(findingIPClassification(f)), true
	case isIPL2WinnowFinding(cat, metaLayer, f.RuleID):
		return string(domain.FingerprintLayerL2WinnowKGram), safeMetricClassificationLabel(findingIPClassification(f)), true
	case cat == "IP_HEADER_MARKER" || cat == "IP_HEADER_STRIP" || strings.EqualFold(metaLayer, string(domain.FingerprintLayerL3HeaderMarker)) || strings.HasPrefix(f.RuleID, "ip.l3."):
		return string(domain.FingerprintLayerL3HeaderMarker), safeMetricClassificationLabel(findingIPClassification(f)), true
	case isIPCorpusOrMarkerMatch(cat, metaLayer, f.RuleID):
		return "IP_OTHER", safeMetricClassificationLabel(findingIPClassification(f)), true
	default:
		return "", "", false
	}
}

func isFindingProhibitedLicense(f domain.Finding, prohibited []string) bool {
	if f.Metadata != nil {
		if p, ok := f.Metadata["prohibited"].(bool); ok {
			return p
		}
		if spdx, ok := f.Metadata["spdx"].(string); ok && spdx != "" {
			return isProhibitedLicense(spdx, prohibited)
		}
	}
	return isProhibitedLicense(f.RuleID+" "+f.Message, prohibited)
}
