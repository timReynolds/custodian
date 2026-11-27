package inspection

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

func TestDefaultIPFingerprinterPushEgressFailClosedAndNoDoubleCount(t *testing.T) {
	def := NewDefaultIPFingerprinter()

	// 1. PUSH_EGRESS must fail closed when DefaultIPFingerprinter stub is active.
	_, cov, err := def.Analyze(context.Background(), Request{
		Stage: StagePushEgress,
	}, &Inventory{FilesExamined: 2})
	if err == nil || cov.Complete {
		t.Fatalf("expected DefaultIPFingerprinter to fail closed on PUSH_EGRESS, cov=%+v err=%v", cov, err)
	}

	// 2. Non-PUSH_EGRESS must not double-count inv.FilesSkipped.
	_, cov2, err := def.Analyze(context.Background(), Request{
		Stage: StageEgress,
	}, &Inventory{FilesExamined: 2, FilesSkipped: 1, SkippedReasons: []string{"symlink_skipped:x"}})
	if err != nil {
		t.Fatalf("unexpected error on StageEgress: %v", err)
	}
	if cov2.FilesSkipped != 0 || cov2.Complete {
		t.Fatalf("expected FilesSkipped=0 (avoiding double-count) and Complete=false, got %+v", cov2)
	}
}

type staticIPHook struct {
	findings []domain.Finding
	complete bool
}

func (h staticIPHook) Name() string    { return string(ScannerIPFingerprint) }
func (h staticIPHook) Version() string { return "1.0.0-test" }
func (h staticIPHook) Analyze(_ context.Context, _ Request, inv *Inventory) ([]domain.Finding, domain.ScanCoverage, error) {
	examined := 0
	var bytesExamined int64
	if inv != nil {
		examined = inv.FilesExamined
		bytesExamined = inv.BytesExamined
	}
	return h.findings, domain.ScanCoverage{
		FilesExamined:  examined,
		FilesSkipped:   0,
		BytesExamined:  bytesExamined,
		SkippedReasons: []string{},
		Complete:       h.complete,
	}, nil
}

func TestRunnerPushEgressScheduleSummaryMetricsAndXORValidation(t *testing.T) {
	ctx := context.Background()
	h := newStubHarness(t)

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatal(err)
	}

	propID := domain.MustNewID()
	pushID := domain.MustNewID()
	artID := domain.MustNewID()

	// 1. XOR owner validation.
	cfgBase := h.config(t, nil)
	runnerBase := NewRunner(cfgBase)
	if _, err := runnerBase.Inspect(ctx, Request{ArtifactID: artID, TargetDir: target}); err == nil {
		t.Fatalf("expected error when both ProposalID and PushSessionID are nil")
	}
	if _, err := runnerBase.Inspect(ctx, Request{ProposalID: propID, PushSessionID: &pushID, ArtifactID: artID, TargetDir: target}); err == nil {
		t.Fatalf("expected error when both ProposalID and PushSessionID are set")
	}
	zeroID := uuid.Nil
	if _, err := runnerBase.Inspect(ctx, Request{PushSessionID: &zeroID, ArtifactID: artID, TargetDir: target}); err == nil {
		t.Fatalf("expected error when PushSessionID points to uuid.Nil")
	}

	// 2. StageEgress + ClassificationInternal preserves 4 ScanRuns (v1.0 compatibility).
	repEgress, err := runnerBase.Inspect(ctx, Request{
		ProposalID:     propID,
		ArtifactID:     artID,
		TargetDir:      target,
		Classification: domain.ClassificationInternal,
		Stage:          StageEgress,
	})
	if err != nil {
		t.Fatalf("StageEgress Inspect failed: %v", err)
	}
	if len(repEgress.ScanRuns) != 4 {
		t.Fatalf("expected 4 ScanRuns on StageEgress INTERNAL, got %d", len(repEgress.ScanRuns))
	}

	// 3. StagePushEgress with DefaultIPFingerprinter fails closed.
	repUnconfigured, err := runnerBase.Inspect(ctx, Request{
		PushSessionID:  &pushID,
		ArtifactID:     artID,
		TargetDir:      target,
		Classification: domain.ClassificationInternal,
		Stage:          StagePushEgress,
	})
	if err != nil {
		t.Fatalf("StagePushEgress Inspect returned error: %v", err)
	}
	if repUnconfigured.Summary.ScanComplete || repUnconfigured.AllCleanComplete() {
		t.Fatalf("expected fail-closed ScanComplete=false when DefaultIPFingerprinter runs on PUSH_EGRESS")
	}

	// 4. StagePushEgress + ClassificationInternal + custom IP hook + Metrics -> 5 ScanRuns, PushSessionID propagated, 6 counters + PolicyFacts + Metrics populated.
	cfgPush := h.config(t, nil)
	cfgPush.Metrics = metrics
	cfgPush.IPFingerprinter = staticIPHook{
		complete: true,
		findings: []domain.Finding{
			{
				Category:    "IP_EXACT",
				Severity:    domain.SeverityCritical,
				RuleID:      "ip.l1.exact-chunk",
				Path:        "a.go",
				StartLine:   1,
				EndLine:     10,
				Fingerprint: domain.SHA256Hex([]byte("l1")),
				Message:     "Exact IP match",
				Redacted:    true,
				Metadata:    map[string]any{"layer": "L1_EXACT_CHUNK", "corpus_classification": "RESTRICTED"},
			},
			{
				Category:    "IP_WINNOW",
				Severity:    domain.SeverityHigh,
				RuleID:      "ip.l2.winnow-kgram",
				Path:        "b.go",
				StartLine:   1,
				EndLine:     20,
				Fingerprint: domain.SHA256Hex([]byte("l2")),
				Message:     "Winnow IP match",
				Redacted:    true,
				Metadata:    map[string]any{"layer": "L2_WINNOW_KGRAM", "corpus_classification": "CONFIDENTIAL"},
			},
			{
				Category:    "IP_HEADER_STRIP",
				Severity:    domain.SeverityCritical,
				RuleID:      "ip.l3.header-stripped",
				Path:        "b.go",
				StartLine:   1,
				EndLine:     1,
				Fingerprint: domain.SHA256Hex([]byte("l3strip")),
				Message:     "Header stripped",
				Redacted:    true,
				Metadata:    map[string]any{"layer": "L3_HEADER_MARKER", "header_stripped": true, "corpus_classification": "RESTRICTED"},
			},
			{
				Category:    "IP_CONCEALMENT",
				Severity:    domain.SeverityHigh,
				RuleID:      "ip.l4.high-entropy",
				Path:        "blob.bin",
				StartLine:   1,
				EndLine:     1,
				Fingerprint: domain.SHA256Hex([]byte("l4")),
				Message:     "High entropy",
				Redacted:    true,
				Metadata:    map[string]any{"layer": "L4_CONCEALMENT"},
			},
		},
	}

	repPush, err := NewRunner(cfgPush).Inspect(ctx, Request{
		PushSessionID:  &pushID,
		ArtifactID:     artID,
		TargetDir:      target,
		Classification: domain.ClassificationInternal,
		Stage:          StagePushEgress,
	})
	if err != nil {
		t.Fatalf("StagePushEgress Inspect failed: %v", err)
	}
	if repPush.PushSessionID == nil || *repPush.PushSessionID != pushID {
		t.Fatalf("expected Report.PushSessionID=%s, got %v", pushID, repPush.PushSessionID)
	}
	if len(repPush.ScanRuns) != 5 {
		t.Fatalf("expected 5 ScanRuns (4 mandatory + ip_fingerprint) on PUSH_EGRESS INTERNAL, got %d", len(repPush.ScanRuns))
	}
	for _, run := range repPush.ScanRuns {
		if run.ProposalID != uuid.Nil || run.PushSessionID == nil || *run.PushSessionID != pushID {
			t.Fatalf("expected PushSessionID=%s and ProposalID=Nil on ScanRun %s, got %+v", pushID, run.Scanner, run)
		}
	}

	s := repPush.Summary
	if s.IPExactMatches != 1 || s.IPWinnowMatches != 1 || s.IPHeaderStripMatches != 1 ||
		s.ConcealmentFindings != 1 || s.RestrictedIPMatches != 2 || s.ConfidentialIPMatches != 1 {
		t.Fatalf("unexpected Summary IP counters: %+v", s)
	}
	facts := s.PolicyFacts()
	for _, k := range []string{"ip_exact_matches", "ip_winnow_matches", "ip_header_strip_matches", "concealment_findings", "restricted_ip_matches", "confidential_ip_matches"} {
		if _, ok := facts[k]; !ok {
			t.Fatalf("missing PolicyFacts key %q", k)
		}
	}
	if facts["restricted_ip_matches"] != 2 || facts["concealment_findings"] != 1 {
		t.Fatalf("unexpected PolicyFacts values: %+v", facts)
	}

	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var metricNames []string
	for _, mf := range mfs {
		metricNames = append(metricNames, mf.GetName())
	}
	for _, expected := range []string{"custodian_push_ip_fingerprint_duration_seconds", "custodian_push_ip_fingerprint_matches_total"} {
		if !slices.Contains(metricNames, expected) {
			t.Fatalf("expected metric %q to be recorded, got %v", expected, metricNames)
		}
	}
}
