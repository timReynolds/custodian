package inspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"go.opentelemetry.io/otel/codes"
)

func TestRegression_R4_ADV06_TrailingContextQuotedTokensAndShortDetectedSecret(t *testing.T) {
	dir := t.TempDir()

	t.Run("generic_secret_trailing_context_and_short_tokens", func(t *testing.T) {
		cases := []struct {
			name   string
			msg    string
			secret string
		}{
			{
				name:   "quoted_colon_with_trailing_context",
				msg:    `found secret: "quoted_trailing_ctx_secret_12345" in config.yaml`,
				secret: "quoted_trailing_ctx_secret_12345",
			},
			{
				name:   "single_quoted_equals_with_trailing_context",
				msg:    `found token = 'single_trailing_ctx_secret_98765' in env`,
				secret: "single_trailing_ctx_secret_98765",
			},
			{
				name:   "short_4char_detected_secret",
				msg:    `detected secret token abcd`,
				secret: "abcd",
			},
			{
				name:   "short_4char_quoted_detected_secret",
				msg:    `detected secret "wxyz" in cfg`,
				secret: "wxyz",
			},
			{
				name:   "quoted_secret_with_internal_spaces",
				msg:    `found secret: "my spaced secret 123" in config.yaml`,
				secret: "my spaced secret 123",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				redactor := NewRedactor()
				payload := fmt.Sprintf(`{"scanner":"gitleaks","category":"SECRET","severity":"CRITICAL","rule_id":"r1","path":"a.go","message":%q}`, tc.msg)
				findings, _, err := parseGenericFindingObject([]byte(payload), "gitleaks", dir, redactor)
				if err != nil || len(findings) != 1 {
					t.Fatalf("parseGenericFindingObject failed: len=%d err=%v", len(findings), err)
				}

				if got := redactor.ScrubString("raw=" + tc.secret); got != "raw="+redactedMarker {
					t.Fatalf("raw secret %q not scrubbed: got %q", tc.secret, got)
				}
				b64 := base64.StdEncoding.EncodeToString([]byte(tc.secret))
				if got := redactor.ScrubString(b64); got != redactedMarker {
					t.Fatalf("base64(%q)=%q not scrubbed: got %q", tc.secret, b64, got)
				}
			})
		}
	})

	t.Run("redactor_multi_kv_and_trailing_context", func(t *testing.T) {
		cases := []struct {
			name        string
			input       string
			secret      string
			benignCheck string
		}{
			{
				name:        "trailing_context_quoted_colon",
				input:       `found secret: "quoted_trailing_redactor_54321" in config.yaml`,
				secret:      "quoted_trailing_redactor_54321",
				benignCheck: "in config.yaml",
			},
			{
				name:        "multi_kv_with_quoted_colon",
				input:       `FOO=bar secret: "second_colon_secret_77889"`,
				secret:      "second_colon_secret_77889",
				benignCheck: "unrelated",
			},
			{
				name:        "multi_kv_with_unquoted_colon_token",
				input:       `FOO=bar secret:colon_nospace_4455`,
				secret:      "colon_nospace_4455",
				benignCheck: "unrelated",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				r := NewRedactor(tc.input)
				if got := r.ScrubString("raw=" + tc.secret); got != "raw="+redactedMarker {
					t.Fatalf("raw secret %q leaked in Redactor: %q", tc.secret, got)
				}
				b64 := base64.StdEncoding.EncodeToString([]byte(tc.secret))
				if got := r.ScrubString(b64); got != redactedMarker {
					t.Fatalf("base64(%q)=%q leaked in Redactor: %q", tc.secret, b64, got)
				}
				if got := r.ScrubString(tc.benignCheck); got != tc.benignCheck {
					t.Fatalf("benign text %q was over-redacted to %q", tc.benignCheck, got)
				}
			})
		}
	})
}

func TestRegression_R4_ADV06_ExtraScannerFailureReasonRedactedInMetricsAndSpans(t *testing.T) {
	h := newStubHarness(t)
	envSecret := "extra_scanner_fail_reason_secret_5566"

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, ".env"), []byte("FAIL_SEC="+envSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	tr, err := observability.NewTracerProvider(context.Background(), observability.TracerConfig{
		ServiceName: "custodian-r4-test",
		Mode:        observability.TraceModeInMemory,
	})
	if err != nil {
		t.Fatalf("NewTracerProvider: %v", err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	var logBuf bytes.Buffer
	cfg := h.config(t, &logBuf)
	cfg.Metrics = metrics
	cfg.Tracer = tr
	cfg.ExtraScanners = []Scanner{
		fakeExtraScanner{
			name: "extra-fail-secret",
			out: ScannerOutcome{
				ScanRun: domain.ScanRun{
					ID:     domain.MustNewID(),
					Status: domain.ScanStatusFailed,
					Coverage: domain.ScanCoverage{
						FilesExamined: 1,
						Complete:      false,
					},
				},
				FailureReason: "failed_with_" + envSecret,
			},
		},
	}

	rep, err := NewRunner(cfg).Inspect(context.Background(), Request{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		TargetDir:  target,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if rep.AllCleanComplete() || rep.Summary.ScanComplete {
		t.Fatalf("expected ScanComplete=false when extra scanner fails, got %+v", rep.Summary)
	}

	// Check Prometheus metrics for leaked secret in reason label.
	mfs, err := metrics.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather metrics: %v", err)
	}
	var sawFailureMetric bool
	for _, mf := range mfs {
		if mf.GetName() != "custodian_scanner_failures_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var scannerLabel, reasonLabel string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "scanner" {
					scannerLabel = lp.GetValue()
				}
				if lp.GetName() == "reason" {
					reasonLabel = lp.GetValue()
				}
			}
			if strings.Contains(reasonLabel, envSecret) {
				t.Fatalf("Prometheus scanner_failures_total leaked secret in reason label: %q", reasonLabel)
			}
			if scannerLabel == "extra-fail-secret" {
				sawFailureMetric = true
				if reasonLabel != "failed_with_[REDACTED]" {
					t.Fatalf("expected scrubbed Prometheus reason label %q, got %q", "failed_with_[REDACTED]", reasonLabel)
				}
			}
		}
	}
	if !sawFailureMetric {
		t.Fatalf("expected custodian_scanner_failures_total metric for extra-fail-secret")
	}

	// Check OTel spans for leaked secret and scrubbed error status.
	var sawExtraSpan bool
	for _, sp := range tr.InMemory.GetSpans() {
		if sp.Name == "inspection.scanner.extra-fail-secret" {
			sawExtraSpan = true
			if sp.Status.Code != codes.Error {
				t.Fatalf("expected OTel span error status, got %v", sp.Status.Code)
			}
			if strings.Contains(sp.Status.Description, envSecret) {
				t.Fatalf("OTel span status description leaked secret: %q", sp.Status.Description)
			}
			if sp.Status.Description != "failed_with_[REDACTED]" {
				t.Fatalf("expected scrubbed OTel span status %q, got %q", "failed_with_[REDACTED]", sp.Status.Description)
			}
		}
	}
	if !sawExtraSpan {
		t.Fatalf("missing OTel span for extra-fail-secret")
	}

	if strings.Contains(logBuf.String(), envSecret) {
		t.Fatalf("slog output leaked secret: %s", logBuf.String())
	}
}

func TestRegression_R4_ADV06_InlinePEMFollowedByMultilinePEMOnSameLine(t *testing.T) {
	h := newStubHarness(t)
	inlinePEM := "-----BEGIN RSA PRIVATE KEY-----MIIEOne111-----END RSA PRIVATE KEY-----"
	multilineBody := "MIIETwo222MultilineAfterInline"
	multilinePEM := "-----BEGIN RSA PRIVATE KEY-----\n" + multilineBody + "\n-----END RSA PRIVATE KEY-----"
	restrictedCommentBody := "# MIIERestrictedCommentLookingBody"
	restrictedAfterPEM := "restricted_after_pem_999"
	safeVar := "safe_var_after_combined_line"
	safeComment := "benign_normal_comment"

	echoMsg := strings.Join([]string{
		"pub=" + safeVar,
		"comment=" + safeComment,
		"inline_b64=" + base64.StdEncoding.EncodeToString([]byte(inlinePEM)),
		"mbody=" + multilineBody,
		"multi_b64=" + base64.StdEncoding.EncodeToString([]byte(multilinePEM)),
		"rbody=" + restrictedCommentBody,
		"rafter=" + restrictedAfterPEM,
	}, " ")

	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`{
			"version":"1.90.0",
			"results":[{
				"check_id":"go.lang.audit.pem",
				"path":"main.go",
				"start":{"line":1,"col":1},
				"end":{"line":4,"col":10},
				"extra":{"message":%q,"severity":"WARNING","fingerprint":"fp-inline-multi"}
			}],
			"errors":[],
			"paths":{"scanned":["main.go"],"skipped":[]}
		}`, echoMsg),
	})

	target := t.TempDir()
	mainSrc := strings.Join([]string{
		"package main",
		fmt.Sprintf(`const x = "%s" + "-----BEGIN RSA PRIVATE KEY-----`, inlinePEM),
		multilineBody,
		`-----END RSA PRIVATE KEY-----"`,
		fmt.Sprintf(`const ok = %q`, safeVar),
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte(mainSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	envSrc := strings.Join([]string{
		inlinePEM + " -----BEGIN RSA PRIVATE KEY-----",
		restrictedCommentBody,
		"-----END RSA PRIVATE KEY-----",
		"# " + safeComment,
		"API_KEY=" + restrictedAfterPEM,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(target, ".env"), []byte(envSrc), 0o600); err != nil {
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

	var semgrepMsg string
	for _, f := range rep.Findings {
		if f.Scanner == string(ScannerSemgrep) {
			semgrepMsg = f.Message
		}
	}
	if !strings.Contains(semgrepMsg, safeVar) || !strings.Contains(semgrepMsg, safeComment) {
		t.Fatalf("benign tokens over-redacted in semgrep finding: %q", semgrepMsg)
	}

	reportBytes, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	reportJSON := string(reportBytes)
	for _, needle := range []string{
		"MIIEOne111",
		base64.StdEncoding.EncodeToString([]byte(inlinePEM)),
		multilineBody,
		base64.StdEncoding.EncodeToString([]byte(multilinePEM)),
		restrictedCommentBody,
		restrictedAfterPEM,
	} {
		if strings.Contains(reportJSON, needle) {
			t.Fatalf("leaked PEM/restricted secret %q in report JSON: %s", needle, reportJSON)
		}
	}
}

func TestRegression_R4_RG05_ScanCodeHeaderlessFilesAndBlankNullErrors(t *testing.T) {
	failClosedCases := []struct {
		name    string
		payload string
	}{
		{name: "files_empty_obj_no_headers", payload: `{"files":[{}]}`},
		{name: "files_null_elem_no_headers", payload: `{"files":[null]}`},
		{name: "files_path_only_no_headers", payload: `{"files":[{"path":"main.go"}]}`},
		{name: "valid_header_files_empty_obj", payload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0"}],"files":[{}]}`},
		{name: "valid_header_files_null_elem", payload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0"}],"files":[null]}`},
		{name: "null_header_empty_files", payload: `{"headers":[null],"files":[]}`},
	}

	for _, tc := range failClosedCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			h.set("scancode", stubSpec{VersionOut: "32.1.0", ExitCode: 0, JSONPayload: tc.payload})

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
			if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.MandatoryScannersComplete {
				t.Fatalf("expected fail-closed for %s, got summary=%+v", tc.name, rep.Summary)
			}
			if rep.Summary.PolicyFacts()["scan_complete"] != false {
				t.Fatalf("expected PolicyFacts[scan_complete]=false for %s", tc.name)
			}
			for _, run := range rep.ScanRuns {
				if run.Scanner == string(ScannerScanCode) && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
					t.Fatalf("expected scancode FAILED with Complete=false for %s, got %+v", tc.name, run)
				}
			}
		})
	}

	incompleteCases := []struct {
		name    string
		payload string
	}{
		{
			name:    "header_errors_blank_str",
			payload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[""]}],"files":[]}`,
		},
		{
			name:    "header_errors_null_elem",
			payload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[null]}],"files":[]}`,
		},
	}

	for _, tc := range incompleteCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			h.set("scancode", stubSpec{VersionOut: "32.1.0", ExitCode: 0, JSONPayload: tc.payload})

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
			if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.PolicyFacts()["scan_complete"] != false {
				t.Fatalf("expected fail-closed incomplete for %s, got summary=%+v", tc.name, rep.Summary)
			}
			for _, run := range rep.ScanRuns {
				if run.Scanner == string(ScannerScanCode) {
					if run.Status != domain.ScanStatusIncomplete || run.Coverage.Complete || run.Coverage.FilesSkipped < 1 {
						t.Fatalf("expected scancode INCOMPLETE with FilesSkipped>=1 for %s, got %+v", tc.name, run)
					}
					if !slices.Contains(run.Coverage.SkippedReasons, "scancode_error") {
						t.Fatalf("expected SkippedReasons to contain scancode_error for %s, got %v", tc.name, run.Coverage.SkippedReasons)
					}
				}
			}
		})
	}
}

func TestRegression_R4_RG05_SemgrepEmptyNullResultsAndBareResultsArrayFailClosed(t *testing.T) {
	failCases := []struct {
		name    string
		payload string
	}{
		{name: "results_empty_obj", payload: `{"version":"1.90.0","results":[{}]}`},
		{name: "results_null_elem", payload: `{"version":"1.90.0","results":[null]}`},
		{name: "results_start_line_only", payload: `{"version":"1.90.0","results":[{"start":{"line":1}}]}`},
		{name: "results_empty_array_without_version_or_paths", payload: `{"results":[]}`},
	}

	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			h.set("semgrep", stubSpec{VersionOut: "1.90.0", ExitCode: 0, JSONPayload: tc.payload})

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
			if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.MandatoryScannersComplete {
				t.Fatalf("expected fail-closed for %s, got summary=%+v", tc.name, rep.Summary)
			}
			if rep.Summary.TotalFindings != 0 {
				t.Fatalf("expected 0 fabricated findings for %s, got %d (%+v)", tc.name, rep.Summary.TotalFindings, rep.Findings)
			}
			for _, run := range rep.ScanRuns {
				if run.Scanner == string(ScannerSemgrep) && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
					t.Fatalf("expected semgrep FAILED with Complete=false for %s, got %+v", tc.name, run)
				}
			}
		})
	}

	// Paths without version should still pass cleanly.
	t.Run("results_empty_with_paths_succeeds", func(t *testing.T) {
		h := newStubHarness(t)
		h.set("semgrep", stubSpec{
			VersionOut:  "1.90.0",
			ExitCode:    0,
			JSONPayload: `{"results":[],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`,
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
		if !rep.AllCleanComplete() || !rep.Summary.ScanComplete {
			t.Fatalf("expected clean complete when paths are present, got summary=%+v", rep.Summary)
		}
	})
}

func TestRegression_R4_RG05_TrivyEmptyAndNullElementsFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "results_empty_obj", payload: `{"SchemaVersion":2,"Results":[{}]}`},
		{name: "results_null_elem", payload: `{"SchemaVersion":2,"Results":[null]}`},
		{name: "vuln_empty_obj", payload: `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Vulnerabilities":[{}]}]}`},
		{name: "vuln_null_elem", payload: `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Vulnerabilities":[null]}]}`},
		{name: "misconfig_empty_obj", payload: `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Misconfigurations":[{}]}]}`},
		{name: "misconfig_null_elem", payload: `{"SchemaVersion":2,"Results":[{"Target":"go.mod","Misconfigurations":[null]}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			h.set("trivy", stubSpec{VersionOut: "0.58.0", ExitCode: 0, JSONPayload: tc.payload})

			target := t.TempDir()
			if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
				t.Fatal(err)
			}
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
			if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.PolicyFacts()["scan_complete"] != false {
				t.Fatalf("expected fail-closed for %s, got summary=%+v", tc.name, rep.Summary)
			}
			if rep.Summary.TotalFindings != 0 {
				t.Fatalf("expected 0 fabricated findings for %s, got %d (%+v)", tc.name, rep.Summary.TotalFindings, rep.Findings)
			}
			for _, run := range rep.ScanRuns {
				if run.Scanner == string(ScannerTrivy) && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
					t.Fatalf("expected trivy FAILED with Complete=false for %s, got %+v", tc.name, run)
				}
			}
		})
	}
}

func TestRegression_R4_RG05_GenericFindingObjectWithErrorAndRuleIDFailsClosed(t *testing.T) {
	payload := `{"scanner":"gitleaks","rule_id":"r1","message":"err","error":"internal error"}`

	if _, _, err := parseGenericFindingObject([]byte(payload), "gitleaks", t.TempDir(), NewRedactor()); err == nil {
		t.Fatalf("expected parseGenericFindingObject to reject payload with non-empty error field")
	}

	h := newStubHarness(t)
	h.set("gitleaks", stubSpec{VersionOut: "v8.18.4", ExitCode: 0, JSONPayload: payload})

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
	if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.MandatoryScannersComplete {
		t.Fatalf("expected fail-closed when generic finding object includes error, got %+v", rep.Summary)
	}
	if rep.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 findings on error payload, got %d", rep.Summary.TotalFindings)
	}
	for _, run := range rep.ScanRuns {
		if run.Scanner == string(ScannerGitleaks) && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
			t.Fatalf("expected gitleaks FAILED with Complete=false, got %+v", run)
		}
	}
}
