package inspection

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestRegression_R3_ADV06_ScannerVersionLoggingAndDeferredClamp(t *testing.T) {
	t.Run("slog_receives_only_cross_scanner_redacted_version", func(t *testing.T) {
		h := newStubHarness(t)
		envSecret := "env_ver_secret_abc12345"

		h.set("gitleaks", stubSpec{VersionOut: "v8.18.4-" + envSecret, JSONPayload: "[]\n"})
		h.set("scancode", stubSpec{
			VersionOut:  "32.1.0-" + envSecret,
			JSONPayload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}`,
		})
		h.set("semgrep", stubSpec{
			VersionOut:  "1.90.0-" + envSecret,
			JSONPayload: `{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`,
		})
		h.set("trivy", stubSpec{
			VersionOut:  "0.58.0-" + envSecret,
			JSONPayload: `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}`,
		})

		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, ".env"), []byte("VSEC="+envSecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		var logBuf bytes.Buffer
		rep, err := NewRunner(h.config(t, &logBuf)).Inspect(context.Background(), Request{
			ProposalID: domain.MustNewID(),
			ArtifactID: domain.MustNewID(),
			TargetDir:  target,
		})
		if err != nil {
			t.Fatalf("Inspect failed: %v", err)
		}

		if strings.Contains(logBuf.String(), envSecret) {
			t.Fatalf("slog output leaked unredacted ScannerVersion secret:\n%s", logBuf.String())
		}
		if !strings.Contains(logBuf.String(), "stage_a_scanner_completed") {
			t.Fatalf("expected stage_a_scanner_completed log entries, got:\n%s", logBuf.String())
		}
		for _, run := range rep.ScanRuns {
			if strings.Contains(run.ScannerVersion, envSecret) {
				t.Fatalf("ScanRun %s ScannerVersion leaked secret: %q", run.Scanner, run.ScannerVersion)
			}
			if run.Scanner != string(ScannerCustom) && !strings.Contains(run.ScannerVersion, redactedMarker) {
				t.Fatalf("expected scrubbed ScannerVersion containing %s for %s, got %q", redactedMarker, run.Scanner, run.ScannerVersion)
			}
		}
	})

	t.Run("long_secret_in_version_scrubbed_before_64_byte_clamp", func(t *testing.T) {
		h := newStubHarness(t)
		longSecret := "long_secret_prefix_0123456789_abcdefghijklmnopqrstuvwxyz_9876543210_end"
		longBenign := strings.Repeat("b", 90)

		h.set("gitleaks", stubSpec{
			VersionOut:  "v8.18.4-" + longSecret,
			JSONPayload: "[]\n",
		})
		h.set("semgrep", stubSpec{
			VersionOut:  longBenign,
			JSONPayload: `{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`,
		})

		target := t.TempDir()
		if err := os.WriteFile(filepath.Join(target, ".env"), []byte("LONG_SEC="+longSecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		var logBuf bytes.Buffer
		rep, err := NewRunner(h.config(t, &logBuf)).Inspect(context.Background(), Request{
			ProposalID: domain.MustNewID(),
			ArtifactID: domain.MustNewID(),
			TargetDir:  target,
		})
		if err != nil {
			t.Fatalf("Inspect failed: %v", err)
		}

		reportBytes, err := json.Marshal(rep)
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if strings.Contains(string(reportBytes), "long_secret_prefix") || strings.Contains(logBuf.String(), "long_secret_prefix") {
			t.Fatalf("long secret prefix leaked in report or logs: report=%s logs=%s", string(reportBytes), logBuf.String())
		}
		for _, run := range rep.ScanRuns {
			if run.Scanner == string(ScannerGitleaks) && run.ScannerVersion != "v8.18.4-[REDACTED]" {
				t.Fatalf("expected gitleaks ScannerVersion 'v8.18.4-[REDACTED]', got %q", run.ScannerVersion)
			}
			if run.Scanner == string(ScannerSemgrep) && len(run.ScannerVersion) > 64 {
				t.Fatalf("expected semgrep benign ScannerVersion clamped to <=64 bytes after scrub, got len=%d (%q)", len(run.ScannerVersion), run.ScannerVersion)
			}
		}
	})
}

func TestRegression_R3_ADV06_SingleLinePEMAndClosingPrefix(t *testing.T) {
	h := newStubHarness(t)
	inlinePEM := "-----BEGIN RSA PRIVATE KEY-----MIIEOneLineBody12345-----END RSA PRIVATE KEY-----"
	multiPEMBody := "MIIEMultiLineBody1234567890"
	multiPEMClean := "-----BEGIN RSA PRIVATE KEY-----\n" + multiPEMBody + "\n-----END RSA PRIVATE KEY-----"
	publicVar1 := "public_unquoted_var_12345"
	publicVar2 := "another_public_var_67890"

	echoMsg := fmt.Sprintf("pub1=%s pub2=%s inline_b64=%s multi_b64=%s multi_body=%s",
		publicVar1,
		publicVar2,
		base64.StdEncoding.EncodeToString([]byte(inlinePEM)),
		base64.StdEncoding.EncodeToString([]byte(multiPEMClean)),
		multiPEMBody,
	)
	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`{
			"version":"1.90.0",
			"results":[{
				"check_id":"go.lang.audit.check",
				"path":"main.go",
				"start":{"line":3,"col":1},
				"end":{"line":3,"col":20},
				"extra":{"message":%q,"severity":"WARNING","fingerprint":"fp-inline-pem"}
			}],
			"errors":[],
			"paths":{"scanned":["main.go"],"skipped":[]}
		}`, echoMsg),
	})

	target := t.TempDir()
	mainSrc := strings.Join([]string{
		"package main",
		fmt.Sprintf(`const singleLinePEM = %q`, inlinePEM),
		fmt.Sprintf(`const x = %s`, publicVar1),
		"const multiPEM = `",
		"-----BEGIN RSA PRIVATE KEY-----",
		multiPEMBody,
		"prefix-----END RSA PRIVATE KEY-----`",
		fmt.Sprintf(`const y = %s`, publicVar2),
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte(mainSrc), 0o644); err != nil {
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
	if !strings.Contains(semgrepMsg, publicVar1) || !strings.Contains(semgrepMsg, publicVar2) {
		t.Fatalf("subsequent benign code lines were over-redacted after single-line/multi-line PEM: %q", semgrepMsg)
	}
	if strings.Contains(semgrepMsg, base64.StdEncoding.EncodeToString([]byte(inlinePEM))) {
		t.Fatalf("single-line PEM base64 leaked in semgrep finding: %q", semgrepMsg)
	}
	if strings.Contains(semgrepMsg, multiPEMBody) {
		t.Fatalf("multi-line PEM body leaked in semgrep finding: %q", semgrepMsg)
	}
	if strings.Contains(semgrepMsg, base64.StdEncoding.EncodeToString([]byte(multiPEMClean))) {
		t.Fatalf("multi-line PEM base64 (closing line with prefix) leaked in semgrep finding: %q", semgrepMsg)
	}
}

func TestRegression_R3_ADV06_QuotedColonSecretTrimOrder(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name   string
		msg    string
		secret string
	}{
		{
			name:   "double_quoted_colon",
			msg:    `secret: "quoted_colon_secret_98765"`,
			secret: "quoted_colon_secret_98765",
		},
		{
			name:   "single_quoted_equals",
			msg:    `token = 'quoted_single_secret_54321'`,
			secret: "quoted_single_secret_54321",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			redactor := NewRedactor()
			payload := fmt.Sprintf(`{"scanner":"gitleaks","category":"SECRET","severity":"CRITICAL","rule_id":"r1","path":"a.go","message":%q}`, tc.msg)
			findings, _, err := parseGenericFindingObject([]byte(payload), "gitleaks", dir, redactor)
			if err != nil || len(findings) != 1 {
				t.Fatalf("parseGenericFindingObject failed: len=%d err=%v", len(findings), err)
			}
			b64 := base64.StdEncoding.EncodeToString([]byte(tc.secret))
			if got := redactor.ScrubString(b64); got != redactedMarker {
				t.Fatalf("expected base64(%q)=%q scrubbed to [REDACTED], got %q", tc.secret, b64, got)
			}

			directRedactor := NewRedactor(tc.msg)
			if got := directRedactor.ScrubString(b64); got != redactedMarker {
				t.Fatalf("expected direct Redactor.AddSecrets(%q) to scrub base64(%q) to [REDACTED], got %q", tc.msg, b64, got)
			}
		})
	}
}

func TestRegression_R3_ADV06_URLUserinfoPercentDecodedPasswordScrubbed(t *testing.T) {
	h := newStubHarness(t)
	rawEncPass := "p%40ss%2Fword_probe_7766"
	decodedPass := "p@ss/word_probe_7766"
	rawPlusPass := "my%2Bpass%20word_8899"
	decodedPlusPass := "my+pass word_8899"

	echoMsg := strings.Join([]string{
		"enc=" + rawEncPass,
		"dec=" + decodedPass,
		"dec_b64=" + base64.StdEncoding.EncodeToString([]byte(decodedPass)),
		"plus_dec=" + decodedPlusPass,
	}, " ")

	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`{
			"version":"1.90.0",
			"results":[{
				"check_id":"go.lang.audit.url",
				"path":"main.go",
				"start":{"line":2,"col":1},
				"end":{"line":2,"col":40},
				"extra":{"message":%q,"severity":"ERROR","fingerprint":"fp-url-dec"}
			}],
			"errors":[],
			"paths":{"scanned":["main.go"],"skipped":[]}
		}`, echoMsg),
	})

	target := t.TempDir()
	mainSrc := fmt.Sprintf(
		"package main\nconst dsn1 = \"postgres://admin:%s@db.internal:5432/prod\"\nconst dsn2 = \"https://u:%s@api.internal/v1\"\n",
		rawEncPass, rawPlusPass,
	)
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte(mainSrc), 0o644); err != nil {
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

	reportBytes, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	reportJSON := string(reportBytes)
	for _, needle := range []string{
		rawEncPass,
		decodedPass,
		base64.StdEncoding.EncodeToString([]byte(decodedPass)),
		rawPlusPass,
		decodedPlusPass,
	} {
		if strings.Contains(reportJSON, needle) {
			t.Fatalf("leaked URL userinfo password variant %q in report JSON: %s", needle, reportJSON)
		}
	}
}

func TestRegression_R3_RG05_SemgrepMissingResultsAndAnyErrorFailClosed(t *testing.T) {
	t.Run("missing_or_null_results_fails_closed", func(t *testing.T) {
		payloads := []struct {
			name string
			body string
		}{
			{
				name: "version_with_results_null",
				body: `{"version":"1.90.0","results":null,"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`,
			},
			{
				name: "version_only",
				body: `{"version":"1.90.0"}`,
			},
			{
				name: "errors_only",
				body: `{"errors":[{}]}`,
			},
			{
				name: "results_null_with_errors",
				body: `{"version":"1.90.0","results":null,"errors":[{"level":"error","message":"fatal"}]}`,
			},
		}

		for _, tc := range payloads {
			t.Run(tc.name, func(t *testing.T) {
				h := newStubHarness(t)
				h.set("semgrep", stubSpec{VersionOut: "1.90.0", ExitCode: 0, JSONPayload: tc.body})

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
					t.Fatalf("expected fail-closed summary for %s, got %+v", tc.name, rep.Summary)
				}
				if rep.Summary.PolicyFacts()["scan_complete"] != false {
					t.Fatalf("expected PolicyFacts[scan_complete]=false for %s", tc.name)
				}
				for _, run := range rep.ScanRuns {
					if run.Scanner == string(ScannerSemgrep) && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
						t.Fatalf("expected semgrep FAILED with Complete=false for %s, got %+v", tc.name, run)
					}
				}
			})
		}
	})

	t.Run("any_error_entry_forces_incomplete", func(t *testing.T) {
		payloads := []struct {
			name           string
			body           string
			expectedReason string
		}{
			{
				name:           "warn_type_partial_parsing_no_path",
				body:           `{"version":"1.90.0","results":[],"errors":[{"level":"warn","type":"PartialParsing","message":"could not analyze file"}],"paths":{"scanned":["main.go"],"skipped":[]}}`,
				expectedReason: "PartialParsing: could not analyze file",
			},
			{
				name:           "warn_type_fatal_error_only",
				body:           `{"version":"1.90.0","results":[],"errors":[{"level":"warn","type":"FatalError"}],"paths":{"scanned":["main.go"],"skipped":[]}}`,
				expectedReason: "FatalError",
			},
			{
				name:           "empty_error_object",
				body:           `{"version":"1.90.0","results":[],"errors":[{}],"paths":{"scanned":["main.go"],"skipped":[]}}`,
				expectedReason: "semgrep_error",
			},
		}

		for _, tc := range payloads {
			t.Run(tc.name, func(t *testing.T) {
				h := newStubHarness(t)
				h.set("semgrep", stubSpec{VersionOut: "1.90.0", ExitCode: 0, JSONPayload: tc.body})

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
					t.Fatalf("expected fail-closed incomplete summary for %s, got %+v", tc.name, rep.Summary)
				}
				for _, run := range rep.ScanRuns {
					if run.Scanner == string(ScannerSemgrep) {
						if run.Status != domain.ScanStatusIncomplete || run.Coverage.Complete || run.Coverage.FilesSkipped < 1 {
							t.Fatalf("expected semgrep INCOMPLETE with FilesSkipped>=1 for %s, got %+v", tc.name, run)
						}
						if !slices.Contains(run.Coverage.SkippedReasons, tc.expectedReason) {
							t.Fatalf("expected SkippedReasons to contain %q for %s, got %v", tc.expectedReason, tc.name, run.Coverage.SkippedReasons)
						}
					}
				}
			})
		}
	})
}

func TestRegression_R3_RG05_ScanCodeAndTrivySchemaHardening(t *testing.T) {
	cases := []struct {
		name    string
		scanner string
		payload string
	}{
		{
			name:    "scancode_empty_header_obj",
			scanner: "scancode",
			payload: `{"headers":[{}]}`,
		},
		{
			name:    "scancode_headers_with_null_files",
			scanner: "scancode",
			payload: `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":null}`,
		},
		{
			name:    "scancode_empty_headers_and_empty_files",
			scanner: "scancode",
			payload: `{"headers":[],"files":[]}`,
		},
		{
			name:    "trivy_null_results",
			scanner: "trivy",
			payload: `{"SchemaVersion":2,"Results":null}`,
		},
		{
			name:    "trivy_missing_results",
			scanner: "trivy",
			payload: `{"SchemaVersion":2}`,
		},
		{
			name:    "trivy_missing_schema_version",
			scanner: "trivy",
			payload: `{"Results":[]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			h.set(tc.scanner, stubSpec{VersionOut: "1.0.0", ExitCode: 0, JSONPayload: tc.payload})

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
			for _, run := range rep.ScanRuns {
				if run.Scanner == tc.scanner && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
					t.Fatalf("expected %s FAILED with Complete=false for %s, got %+v", tc.scanner, tc.name, run)
				}
			}
		})
	}
}

func TestRegression_R3_RG05_GitleaksEmptyAndNullArrayElementsFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "array_empty_object", payload: `[{}]`},
		{name: "array_null_element", payload: `[null]`},
		{name: "array_only_start_line", payload: `[{"StartLine": 1}]`},
		{name: "array_mixed_empty_and_valid", payload: `[{}, {"Description":"x","RuleID":"r1","Secret":"secret_12345","File":"main.go"}]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newStubHarness(t)
			h.set("gitleaks", stubSpec{VersionOut: "v8.18.4", ExitCode: 0, JSONPayload: tc.payload})

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
				if run.Scanner == string(ScannerGitleaks) {
					if run.Status != domain.ScanStatusFailed || run.Coverage.Complete {
						t.Fatalf("expected gitleaks FAILED with Complete=false for %s, got %+v", tc.name, run)
					}
				}
			}
		})
	}
}

// Compile-time check that url.QueryEscape is exercised if needed in future subtests.
var _ = url.QueryEscape
