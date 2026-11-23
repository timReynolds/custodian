package inspection

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestRegression_ADV06_EnvMultiTokenInlineCommentAndURLBearerBasic(t *testing.T) {
	h := newStubHarness(t)
	tokAlpha := "tok_alpha_probe_12345"
	tokBeta := "tok_beta_probe_67890"
	tokGamma := "tok_gamma_probe_11223"
	tokQuoted := "tok_quoted_44556"
	urlPass := "url_pass_probe_998877"
	bearerTok := "bearer_tok_probe_998877"
	basicTok := "dXNlcjpwYXNzX2Jhc2ljX3Rva2Vu"

	echoAll := strings.Join([]string{
		tokAlpha,
		base64.StdEncoding.EncodeToString([]byte(tokAlpha)),
		tokBeta,
		base64.RawURLEncoding.EncodeToString([]byte(tokBeta)),
		tokGamma,
		url.QueryEscape(tokGamma),
		tokQuoted,
		urlPass,
		base64.StdEncoding.EncodeToString([]byte(urlPass)),
		bearerTok,
		base64.StdEncoding.EncodeToString([]byte(bearerTok)),
		basicTok,
		base64.StdEncoding.EncodeToString([]byte(basicTok)),
	}, " ")

	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`{
			"version": "1.90.0",
			"results": [{
				"check_id": "go.lang.audit.echo",
				"path": "main.go",
				"start": {"line": 1, "col": 1},
				"end": {"line": 1, "col": 10},
				"extra": {
					"message": %q,
					"severity": "ERROR",
					"fingerprint": "fp-adv06-1",
					"metadata": {"echo": %q, "note": "trailing comment"}
				}
			}],
			"errors": [],
			"paths": {"scanned": ["main.go"], "skipped": []}
		}`, echoAll, echoAll),
	})

	target := t.TempDir()
	envBody := fmt.Sprintf(
		"FOO=%s BAR=%s\nBAZ=%s # inline comment\nQUOTED=%q # trailing comment\n",
		tokAlpha, tokBeta, tokGamma, tokQuoted+" # inside",
	)
	if err := os.WriteFile(filepath.Join(target, ".env"), []byte(envBody), 0o600); err != nil {
		t.Fatal(err)
	}
	mainBody := fmt.Sprintf(
		"package main\nconst u = \"https://user:%s@db.internal/app\"\nconst h1 = \"Bearer %s\"\nconst h2 = \"Basic %s\"\n",
		urlPass, bearerTok, basicTok,
	)
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte(mainBody), 0o644); err != nil {
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

	for _, secret := range []string{tokAlpha, tokBeta, tokGamma, tokQuoted, urlPass, bearerTok, basicTok} {
		for _, variant := range []string{
			secret,
			base64.StdEncoding.EncodeToString([]byte(secret)),
			base64.RawStdEncoding.EncodeToString([]byte(secret)),
			base64.RawURLEncoding.EncodeToString([]byte(secret)),
			url.QueryEscape(secret),
		} {
			if strings.Contains(reportJSON, variant) {
				t.Fatalf("leaked secret variant %q in report JSON: %s", variant, reportJSON)
			}
		}
	}
	if !strings.Contains(reportJSON, `"trailing comment"`) {
		t.Fatalf("inline comment text should not have been treated as a secret: %s", reportJSON)
	}
}

func TestRegression_ADV06_PGPBlockAndCRLFNonRestrictedPEM(t *testing.T) {
	h := newStubHarness(t)

	pgpBody := "lQOYBGPTestPGPBodyLine0123456789abcdef0123456789"
	pgpBlock := "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + pgpBody + "\n-----END PGP PRIVATE KEY BLOCK-----"

	rsaRestrictedBody := "MIIEowIBAAKCAQEAProbeRSABody0123456789abcdef0123456789"
	rsaRestrictedLF := "-----BEGIN RSA PRIVATE KEY-----\n" + rsaRestrictedBody + "\n-----END RSA PRIVATE KEY-----"
	rsaRestrictedCRLF := strings.ReplaceAll(rsaRestrictedLF, "\n", "\r\n") + "\r\n"

	rsaNonResBody := "MIIEowIBAAKCAQEANonRestrictedRSABody0123456789abcdef"
	rsaNonResLF := "-----BEGIN RSA PRIVATE KEY-----\n" + rsaNonResBody + "\n-----END RSA PRIVATE KEY-----"

	echoMsg := strings.Join([]string{
		"rsa_lf_b64=" + base64.StdEncoding.EncodeToString([]byte(rsaRestrictedLF)),
		"nonres_b64=" + base64.StdEncoding.EncodeToString([]byte(rsaNonResLF)),
		"pgp_body=" + pgpBody,
		"pgp_b64=" + base64.StdEncoding.EncodeToString([]byte(pgpBlock)),
	}, " ")

	h.set("semgrep", stubSpec{
		VersionOut:  "1.90.0",
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`{
			"version": "1.90.0",
			"results": [{
				"check_id": "go.lang.audit.pem",
				"path": "main.go",
				"start": {"line": 1, "col": 1},
				"end": {"line": 1, "col": 10},
				"extra": {
					"message": %q,
					"severity": "ERROR",
					"fingerprint": "fp-adv06-pem",
					"metadata": {"raw_pgp": %q}
				}
			}],
			"errors": [],
			"paths": {"scanned": ["main.go"], "skipped": []}
		}`, echoMsg, pgpBlock),
	})

	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "secrets", "id_rsa.pem"), []byte(rsaRestrictedCRLF), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "pgp.asc"), []byte(pgpBlock+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\nconst key = `\n"+rsaNonResLF+"\n`\n"), 0o644); err != nil {
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
		pgpBody,
		pgpBlock,
		base64.StdEncoding.EncodeToString([]byte(pgpBlock)),
		rsaRestrictedBody,
		base64.StdEncoding.EncodeToString([]byte(rsaRestrictedLF)),
		rsaNonResBody,
		base64.StdEncoding.EncodeToString([]byte(rsaNonResLF)),
	} {
		if strings.Contains(reportJSON, needle) {
			t.Fatalf("leaked PEM/PGP material %q in report JSON: %s", needle, reportJSON)
		}
	}
}

type customSecretStr string

type ptrJSONMarshaler struct {
	Secret string
	Note   string
}

func (p *ptrJSONMarshaler) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"raw_secret": p.Secret,
		"note":       p.Note,
	})
}

type cycleNode struct {
	Label string     `json:"label"`
	Next  *cycleNode `json:"next,omitempty"`
}

func TestRegression_ADV06_SanitizeMetadataNamedStringPtrMarshalerAndCycles(t *testing.T) {
	secret := "super_secret_probe_token_12345"
	r := NewRedactor(secret)

	namedVal := customSecretStr("prefix_" + secret)
	namedPtr := &namedVal

	cyclicMap := map[string]any{"msg": "leak=" + secret}
	cyclicMap["self"] = cyclicMap

	cyclicSlice := make([]any, 2)
	cyclicSlice[0] = "slice=" + secret
	cyclicSlice[1] = cyclicSlice

	cyclicStruct := &cycleNode{Label: "node=" + secret}
	cyclicStruct.Next = cyclicStruct

	f := domain.Finding{
		Scanner:     "custom",
		Category:    "SECRET",
		Severity:    domain.SeverityCritical,
		RuleID:      "r1",
		Path:        "a.go",
		Fingerprint: domain.SHA256Hex([]byte("meta-test")),
		Metadata: map[string]any{
			"named_str":       namedVal,
			"named_str_ptr":   namedPtr,
			"named_str_slice": []customSecretStr{namedVal},
			"named_str_map":   map[string]customSecretStr{"k": namedVal},
			"ptr_marshaler":   &ptrJSONMarshaler{Secret: secret, Note: "note=" + secret},
			"cyclic_map":      cyclicMap,
			"cyclic_slice":    cyclicSlice,
			"cyclic_struct":   cyclicStruct,
		},
	}

	if err := r.FinalizeFinding(&f, domain.MustNewID()); err != nil {
		t.Fatalf("FinalizeFinding failed: %v", err)
	}
	if err := f.ValidateRedacted(); err != nil {
		t.Fatalf("ValidateRedacted failed: %v", err)
	}

	serialized, err := json.Marshal(f.Metadata)
	if err != nil {
		t.Fatalf("marshal sanitized metadata: %v", err)
	}
	payload := string(serialized)
	if strings.Contains(payload, secret) {
		t.Fatalf("metadata leaked raw secret: %s", payload)
	}
	if strings.Contains(payload, `"raw_secret"`) {
		t.Fatalf("ptrJSONMarshaler leaked forbidden raw_secret key: %s", payload)
	}
	if !strings.Contains(payload, `"note":"note=[REDACTED]"`) {
		t.Fatalf("expected ptrJSONMarshaler note to be scrubbed, got: %s", payload)
	}
}

func TestRegression_ADV06_ScannerVersionScrubbed(t *testing.T) {
	h := newStubHarness(t)
	secret1 := "AKIAIOSFODNN7EXAMPLE"
	secret2 := "super_secret_env_token_99887766"

	h.set("semgrep", stubSpec{
		FailOnVersion: true,
		JSONPayload:   fmt.Sprintf(`{"version":"1.90.0-%s","results":[],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`, secret1),
	})
	h.set("scancode", stubSpec{
		FailOnVersion: true,
		JSONPayload:   fmt.Sprintf(`{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0-%s","errors":[],"extra_data":{"files_count":1}}],"files":[]}`, secret2),
	})
	h.set("gitleaks", stubSpec{
		VersionOut:  "v8.18.4",
		ExitCode:    1,
		HasFindings: true,
		JSONPayload: fmt.Sprintf(`[{"Description":"AWS","StartLine":1,"EndLine":1,"Match":"KEY=%s","Secret":%q,"File":"main.go","RuleID":"aws","Fingerprint":"fp1"}]`, secret1, secret1),
	})

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, ".env"), []byte("APP_SECRET="+secret2+"\n"), 0o600); err != nil {
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

	for _, run := range rep.ScanRuns {
		if strings.Contains(run.ScannerVersion, secret1) || strings.Contains(run.ScannerVersion, secret2) {
			t.Fatalf("ScannerVersion leaked secret for %s: %q", run.Scanner, run.ScannerVersion)
		}
	}
}

func TestRegression_ADV06_GenericFindingSpaceFreeSecret(t *testing.T) {
	dir := t.TempDir()
	for _, msg := range []string{
		"secret=custom_noslack_secret_98765",
		"token:custom_colon_secret_98765",
	} {
		redactor := NewRedactor()
		payload := fmt.Sprintf(`{"scanner":"gitleaks","category":"SECRET","severity":"CRITICAL","rule_id":"r1","path":"a.go","message":%q}`, msg)
		findings, secrets, err := parseGenericFindingObject([]byte(payload), "gitleaks", dir, redactor)
		if err != nil {
			t.Fatalf("parseGenericFindingObject failed for %q: %v", msg, err)
		}
		if len(findings) != 1 || len(secrets) == 0 {
			t.Fatalf("expected 1 finding and harvested secrets for %q, got findings=%d secrets=%v", msg, len(findings), secrets)
		}
		rhs := strings.SplitN(strings.ReplaceAll(msg, ":", "="), "=", 2)[1]
		b64 := base64.StdEncoding.EncodeToString([]byte(rhs))
		if scrubbed := redactor.ScrubString(b64); scrubbed != redactedMarker {
			t.Fatalf("expected base64(%q) to scrub to [REDACTED], got %q", rhs, scrubbed)
		}
	}
}

func TestRegression_RG05_ExitZeroEmptyNullErrorPayloadsFailClosed(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"{}", "null", `{"error":"internal crash"}`} {
		if _, _, err := parseGenericFindingObject([]byte(bad), "gitleaks", dir, NewRedactor()); err == nil {
			t.Fatalf("parseGenericFindingObject should error on %s", bad)
		}
	}

	scanners := []string{"gitleaks", "scancode", "semgrep", "trivy"}
	payloads := []struct {
		name string
		body string
	}{
		{name: "empty_object", body: "{}"},
		{name: "null", body: "null"},
		{name: "error_object", body: `{"error":"internal crash"}`},
	}

	for _, sc := range scanners {
		for _, pl := range payloads {
			t.Run(sc+"_"+pl.name, func(t *testing.T) {
				h := newStubHarness(t)
				h.set(sc, stubSpec{
					VersionOut:  "1.0.0",
					ExitCode:    0,
					JSONPayload: pl.body,
				})

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
				if rep.AllCleanComplete() || rep.Summary.ScanComplete {
					t.Fatalf("expected fail-closed on %s %s, got summary=%+v", sc, pl.name, rep.Summary)
				}
				if rep.Summary.PolicyFacts()["scan_complete"] != false {
					t.Fatalf("expected PolicyFacts[scan_complete]=false for %s %s", sc, pl.name)
				}
				var sawFailed bool
				for _, run := range rep.ScanRuns {
					if run.Scanner == sc {
						sawFailed = true
						if run.Status != domain.ScanStatusFailed || run.Coverage.Complete {
							t.Fatalf("expected %s FAILED with Complete=false on %s, got %+v", sc, pl.name, run)
						}
					}
				}
				if !sawFailed {
					t.Fatalf("missing ScanRun for %s", sc)
				}
			})
		}
	}
}

func TestRegression_RG05_CustomOversizedFileTrackedAsSkipped(t *testing.T) {
	dir := t.TempDir()
	bigContent := "package main\nconst tok = \"ghp_1234567890abcdef123456\"\n" + strings.Repeat("A", 1024)
	if err := os.WriteFile(filepath.Join(dir, "big.go"), []byte(bigContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET="+strings.Repeat("B", 300)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.MaxFileInspectBytes = 256
	sc := newCustomScanner(cfg)
	inv, err := WalkWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sc.Scan(context.Background(), Request{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		TargetDir:  dir,
	}, inv)
	if err != nil {
		t.Fatalf("custom scan returned error: %v", err)
	}
	if out.ScanRun.IsCleanComplete() || out.ScanRun.Status != domain.ScanStatusIncomplete || out.ScanRun.Coverage.Complete {
		t.Fatalf("expected INCOMPLETE ScanRun on oversized files, got %+v", out.ScanRun)
	}
	if out.ScanRun.Coverage.FilesSkipped != 2 {
		t.Fatalf("expected FilesSkipped=2 (big.go and .env), got %d (%v)", out.ScanRun.Coverage.FilesSkipped, out.ScanRun.Coverage.SkippedReasons)
	}
	if !slices.Contains(out.ScanRun.Coverage.SkippedReasons, "oversized_skipped:big.go") ||
		!slices.Contains(out.ScanRun.Coverage.SkippedReasons, "oversized_skipped:.env") {
		t.Fatalf("expected oversized_skipped reasons, got %v", out.ScanRun.Coverage.SkippedReasons)
	}
}

func TestRegression_RG05_GitleaksExitOneEmptyArrayFailsClosed(t *testing.T) {
	h := newStubHarness(t)
	h.set("gitleaks", stubSpec{
		VersionOut:  "v8.18.4",
		ExitCode:    1,
		HasFindings: false,
		JSONPayload: "[]\n",
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
	if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.MandatoryScannersComplete {
		t.Fatalf("expected fail-closed when gitleaks exits 1 with [], got summary=%+v", rep.Summary)
	}
	for _, run := range rep.ScanRuns {
		if run.Scanner == "gitleaks" && (run.Status != domain.ScanStatusFailed || run.Coverage.Complete) {
			t.Fatalf("expected gitleaks FAILED with Complete=false, got %+v", run)
		}
	}
}

func TestRegression_RG05_SemgrepWarnErrorsFailClosed(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		payload string
	}{
		{
			name:    "warn_with_path_and_syntax",
			payload: `{"version":"1.90.0","results":[],"errors":[{"level":"warn","message":"syntax error in broken.py","path":"broken.py"}],"paths":{"scanned":["main.go"],"skipped":[]}}`,
		},
		{
			name:    "warn_parse_without_path",
			payload: `{"version":"1.90.0","results":[],"errors":[{"level":"warn","message":"parse failure on file"}],"paths":{"scanned":["main.go"],"skipped":[]}}`,
		},
		{
			name:    "warn_fail_without_path",
			payload: `{"version":"1.90.0","results":[],"errors":[{"level":"warn","message":"rule execution failed"}],"paths":{"scanned":["main.go"],"skipped":[]}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseSemgrepReport([]byte(tc.payload), dir, NewRedactor())
			if err != nil {
				t.Fatalf("parseSemgrepReport failed: %v", err)
			}
			if parsed.filesSkipped < 1 || len(parsed.skippedReasons) == 0 {
				t.Fatalf("expected filesSkipped>=1 for %s, got %+v", tc.name, parsed)
			}
		})
	}
}

type incompleteIPHook struct{}

func (incompleteIPHook) Name() string    { return string(ScannerIPFingerprint) }
func (incompleteIPHook) Version() string { return "1.0.0-test" }
func (incompleteIPHook) Analyze(_ context.Context, _ Request, inv *Inventory) ([]domain.Finding, domain.ScanCoverage, error) {
	n := 0
	if inv != nil {
		n = inv.FilesExamined
	}
	return nil, domain.ScanCoverage{
		FilesExamined: n,
		FilesSkipped:  0,
		Complete:      false,
	}, nil
}

func TestRegression_RG05_IPFingerprinterIncompletePreserved(t *testing.T) {
	h := newStubHarness(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(t, nil)
	cfg.IPFingerprinter = incompleteIPHook{}

	rep, err := NewRunner(cfg).Inspect(context.Background(), Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      target,
		Classification: domain.ClassificationRestricted,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.PolicyFacts()["scan_complete"] != false {
		t.Fatalf("expected fail-closed when ip_fingerprint reports Complete=false, got summary=%+v", rep.Summary)
	}
	var found bool
	for _, run := range rep.ScanRuns {
		if run.Scanner == string(ScannerIPFingerprint) {
			found = true
			if run.Status != domain.ScanStatusIncomplete || run.Coverage.Complete || run.IsCleanComplete() {
				t.Fatalf("expected ip_fingerprint INCOMPLETE with Complete=false, got %+v", run)
			}
		}
	}
	if !found {
		t.Fatalf("missing ip_fingerprint ScanRun")
	}
}

func TestRegression_StderrSkippedZeroIgnored(t *testing.T) {
	n, reasons := parseStderrSkipped("gitleaks skipped 0 file(s)\nscancode skipped 0 files", NewRedactor())
	if n != 0 || len(reasons) != 0 {
		t.Fatalf("expected 0 skipped and empty reasons for 'skipped 0 file(s)', got n=%d reasons=%v", n, reasons)
	}

	h := newStubHarness(t)
	h.set("gitleaks", stubSpec{
		VersionOut:  "v8.18.4",
		StderrMsg:   "skipped 0 file(s)",
		JSONPayload: "[]\n",
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
		t.Fatalf("expected clean complete when stderr reports skipped 0 file(s), got summary=%+v", rep.Summary)
	}
}

type fakeExtraScanner struct {
	name string
	out  ScannerOutcome
	err  error
}

func (f fakeExtraScanner) Name() string                            { return f.name }
func (f fakeExtraScanner) Version(context.Context) (string, error) { return "", nil }
func (f fakeExtraScanner) Scan(context.Context, Request, *Inventory) (ScannerOutcome, error) {
	return f.out, f.err
}

func TestRegression_ExtraScannerErrorAndEmptyVersionHardening(t *testing.T) {
	h := newStubHarness(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("error_forces_failed", func(t *testing.T) {
		cfg := h.config(t, nil)
		cfg.ExtraScanners = []Scanner{
			fakeExtraScanner{
				name: "extra-err",
				out: ScannerOutcome{
					ScanRun: domain.ScanRun{
						ID:       domain.MustNewID(),
						Status:   domain.ScanStatusCompleted,
						Coverage: domain.ScanCoverage{FilesExamined: 1, Complete: true},
					},
				},
				err: errors.New("external failure"),
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
			t.Fatalf("expected fail-closed when ExtraScanner returns err, got %+v", rep.Summary)
		}
		for _, run := range rep.ScanRuns {
			if run.Scanner == "extra-err" {
				if run.Status != domain.ScanStatusFailed || run.Coverage.Complete || run.ScannerVersion != "unknown" {
					t.Fatalf("unexpected ScanRun for extra-err: %+v", run)
				}
			}
		}
	})

	t.Run("empty_version_backfilled", func(t *testing.T) {
		cfg := h.config(t, nil)
		cfg.ExtraScanners = []Scanner{
			fakeExtraScanner{
				name: "extra-ok",
				out: ScannerOutcome{
					ScanRun: domain.ScanRun{
						ID:       domain.MustNewID(),
						Status:   domain.ScanStatusCompleted,
						Coverage: domain.ScanCoverage{FilesExamined: 1, Complete: true},
					},
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
		if !rep.AllCleanComplete() {
			t.Fatalf("expected AllCleanComplete=true, got %+v", rep.Summary)
		}
		for _, run := range rep.ScanRuns {
			if run.Scanner == "extra-ok" && run.ScannerVersion != "unknown" {
				t.Fatalf("expected ScannerVersion backfilled to 'unknown', got %q", run.ScannerVersion)
			}
		}
	})
}

func TestRegression_FinalizeFindingValidatesEvidenceIDPattern(t *testing.T) {
	evPattern := regexp.MustCompile(`^finding_[A-Za-z0-9_-]+$`)
	r := NewRedactor()
	runID := domain.MustNewID()

	for _, bad := range []string{"", "finding_", "finding_bad space", "finding_bad:char", "other_prefix_123"} {
		f := domain.Finding{
			Scanner:     "semgrep",
			Category:    "SAST",
			Severity:    domain.SeverityHigh,
			RuleID:      "rule.1",
			Path:        "main.go",
			EvidenceID:  bad,
			Fingerprint: domain.SHA256Hex([]byte("ev-test")),
		}
		if err := r.FinalizeFinding(&f, runID); err != nil {
			t.Fatalf("FinalizeFinding failed: %v", err)
		}
		if !evPattern.MatchString(f.EvidenceID) {
			t.Fatalf("expected recomputed EvidenceID matching %s for input %q, got %q", evPattern.String(), bad, f.EvidenceID)
		}
	}

	valid := "finding_custom_abc-123_XYZ"
	f := domain.Finding{
		Scanner:     "custom",
		Category:    "POLICY",
		Severity:    domain.SeverityMedium,
		RuleID:      "rule.2",
		Path:        "main.go",
		EvidenceID:  valid,
		Fingerprint: domain.SHA256Hex([]byte("ev-valid")),
	}
	if err := r.FinalizeFinding(&f, runID); err != nil {
		t.Fatalf("FinalizeFinding failed: %v", err)
	}
	if f.EvidenceID != valid {
		t.Fatalf("expected valid EvidenceID %q preserved, got %q", valid, f.EvidenceID)
	}
}

func TestRegression_MaxOutputBytesTruncationFailsClosed(t *testing.T) {
	// Unit check on readBoundedFile.
	tmpFile := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(tmpFile, []byte(strings.Repeat("x", 600)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(tmpFile, 512); err == nil {
		t.Fatalf("expected readBoundedFile error when file exceeds maxBytes")
	}

	// Integration check: scanner emits a valid JSON report exceeding cfg.MaxOutputBytes.
	h := newStubHarness(t)
	oversizedMsg := strings.Repeat("a", 800)
	h.set("semgrep", stubSpec{
		VersionOut: "1.90.0",
		JSONPayload: fmt.Sprintf(
			`{"version":"1.90.0","results":[{"check_id":"r1","path":"main.go","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":%q,"severity":"WARNING"}}],"errors":[],"paths":{"scanned":["main.go"],"skipped":[]}}`,
			oversizedMsg,
		),
	})

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := h.config(t, nil)
	cfg.MaxOutputBytes = 512

	rep, err := NewRunner(cfg).Inspect(context.Background(), Request{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		TargetDir:  target,
	})
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if rep.AllCleanComplete() || rep.Summary.ScanComplete || rep.Summary.PolicyFacts()["scan_complete"] != false {
		t.Fatalf("expected fail-closed on MaxOutputBytes truncation, got summary=%+v", rep.Summary)
	}
	var sawSemgrepFailed bool
	for _, run := range rep.ScanRuns {
		if run.Scanner == "semgrep" {
			sawSemgrepFailed = true
			if run.Status != domain.ScanStatusFailed || run.Coverage.Complete {
				t.Fatalf("expected semgrep FAILED with Complete=false on oversized report, got %+v", run)
			}
			if !slices.Contains(run.Coverage.SkippedReasons, "missing_or_oversized_report") {
				t.Fatalf("expected missing_or_oversized_report reason, got %v", run.Coverage.SkippedReasons)
			}
		}
	}
	if !sawSemgrepFailed {
		t.Fatalf("missing semgrep ScanRun")
	}

	// Also verify stdout fallback > MaxOutputBytes fails closed.
	if _, err := readReportOrStdout(filepath.Join(t.TempDir(), "nonexistent.json"), []byte(strings.Repeat("y", 600)), false, 512); err == nil {
		t.Fatalf("expected error when stdout fallback exceeds MaxOutputBytes")
	}
	if _, err := readReportOrStdout(filepath.Join(t.TempDir(), "nonexistent.json"), []byte("[]"), true, 512); err == nil {
		t.Fatalf("expected error when stdout was truncated at stdio buffer limit")
	}
}
