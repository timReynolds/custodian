package inspection

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestGitleaksParserNormalization(t *testing.T) {
	dir := t.TempDir()
	redactor := NewRedactor()
	secret := "AKIAIOSFODNN7EXAMPLE"
	raw := []byte(`[
		{
			"Description": "Hardcoded AWS Access Key (` + secret + `)",
			"StartLine": 2,
			"EndLine": 2,
			"Match": "AWS_ACCESS_KEY_ID=` + secret + `",
			"Secret": "` + secret + `",
			"File": "` + filepath.Join(dir, "main.go") + `",
			"RuleID": "aws-access-token",
			"Fingerprint": "main.go:aws-access-token:2"
		}
	]`)

	findings, secrets, err := parseGitleaksReport(raw, dir, redactor)
	if err != nil {
		t.Fatalf("parseGitleaksReport failed: %v", err)
	}
	if len(findings) != 1 || len(secrets) < 2 {
		t.Fatalf("expected 1 finding and >=2 harvested secrets, got %d findings, %d secrets", len(findings), len(secrets))
	}
	runID := domain.MustNewID()
	if err := redactor.FinalizeFinding(&findings[0], runID); err != nil {
		t.Fatalf("FinalizeFinding failed: %v", err)
	}
	f := findings[0]
	if f.Category != "SECRET" || f.Severity != domain.SeverityCritical || !f.Redacted {
		t.Fatalf("unexpected finding classification: %+v", f)
	}
	if f.Path != "main.go" || f.StartLine != 2 || f.EndLine != 2 {
		t.Fatalf("unexpected location normalization: path=%q %d..%d", f.Path, f.StartLine, f.EndLine)
	}
	if strings.Contains(f.Message, secret) || strings.Contains(f.Fingerprint, secret) {
		t.Fatalf("secret leaked in normalized finding: %+v", f)
	}

	// Clean report []
	clean, _, err := parseGitleaksReport([]byte("[]\n"), dir, NewRedactor())
	if err != nil || len(clean) != 0 {
		t.Fatalf("expected clean empty array, got len=%d err=%v", len(clean), err)
	}

	// Malformed JSON must error
	if _, _, err := parseGitleaksReport([]byte("[{bad json"), dir, NewRedactor()); err == nil {
		t.Fatalf("expected error on malformed gitleaks JSON")
	}

	// Generic fallback object with SECRET category
	genRaw := []byte(`{
		"scanner": "gitleaks",
		"category": "SECRET",
		"severity": "CRITICAL",
		"rule_id": "custom-token",
		"path": "cfg.go",
		"message": "Detected secret custodian_e2e_dummy_secret_value_0123456789abcdef"
	}`)
	genFindings, genSecrets, err := parseGitleaksReport(genRaw, dir, NewRedactor())
	if err != nil || len(genFindings) != 1 || len(genSecrets) == 0 {
		t.Fatalf("generic fallback failed: len=%d secrets=%d err=%v", len(genFindings), len(genSecrets), err)
	}
	if strings.Contains(genFindings[0].Message, "custodian_e2e_dummy_secret_value") {
		t.Fatalf("generic fallback leaked secret in Message: %q", genFindings[0].Message)
	}
}

func TestScanCodeParserAndProhibitedLicenses(t *testing.T) {
	dir := t.TempDir()
	prohibRaw := []byte(`{
		"headers": [{
			"tool_name": "scancode-toolkit",
			"tool_version": "32.1.0",
			"errors": [],
			"extra_data": {"files_count": 2, "files_skipped": 0}
		}],
		"files": [
			{
				"path": "COPYING",
				"type": "file",
				"detected_license_expression_spdx": "AGPL-3.0-only",
				"license_detections": [{"license_expression_spdx": "AGPL-3.0-only", "rule_identifier": "prohibited-license-agpl-3.0-only"}],
				"scan_errors": []
			},
			{
				"path": "LICENSE",
				"type": "file",
				"detected_license_expression_spdx": "MIT",
				"license_detections": [{"license_expression_spdx": "MIT", "rule_identifier": "mit"}],
				"scan_errors": []
			}
		]
	}`)

	parsed, err := parseScanCodeReport(prohibRaw, dir, DefaultProhibitedLicenses, NewRedactor())
	if err != nil {
		t.Fatalf("parseScanCodeReport failed: %v", err)
	}
	if parsed.toolVersion != "32.1.0" || parsed.filesExamined != 2 || parsed.filesSkipped != 0 {
		t.Fatalf("unexpected scancode coverage: %+v", parsed)
	}
	if len(parsed.findings) != 2 {
		t.Fatalf("expected 2 license findings, got %d", len(parsed.findings))
	}
	if !isFindingProhibitedLicense(parsed.findings[0], DefaultProhibitedLicenses) {
		t.Fatalf("expected AGPL-3.0-only to be marked prohibited")
	}
	if isFindingProhibitedLicense(parsed.findings[1], DefaultProhibitedLicenses) {
		t.Fatalf("expected MIT not to be prohibited")
	}
	if !strings.Contains(strings.ToUpper(parsed.findings[0].RuleID+parsed.findings[0].Message), "AGPL") {
		t.Fatalf("expected RuleID+Message to retain AGPL SPDX identifier")
	}

	// Test composite SPDX expressions
	if !isProhibitedLicense("MIT OR GPL-3.0-or-later", DefaultProhibitedLicenses) {
		t.Fatalf("expected composite MIT OR GPL-3.0-or-later to be prohibited")
	}
	if isProhibitedLicense("LGPL-2.1-only", DefaultProhibitedLicenses) {
		t.Fatalf("expected LGPL-2.1-only not to match GPL- prefix")
	}

	// FilesSkipped + scan_errors
	skippedRaw := []byte(`{
		"headers": [{
			"tool_name": "scancode-toolkit",
			"tool_version": "32.1.0",
			"errors": ["skipped 1 file(s)"],
			"extra_data": {"files_count": 1, "files_skipped": 1}
		}],
		"files": [{
			"path": "huge.bin",
			"type": "file",
			"scan_errors": ["error scanning binary/oversize file"]
		}]
	}`)
	skippedParsed, err := parseScanCodeReport(skippedRaw, dir, DefaultProhibitedLicenses, NewRedactor())
	if err != nil {
		t.Fatalf("parseScanCodeReport skipped failed: %v", err)
	}
	if skippedParsed.filesSkipped < 1 || len(skippedParsed.skippedReasons) == 0 {
		t.Fatalf("expected filesSkipped >= 1 and non-empty reasons, got %+v", skippedParsed)
	}
}

func TestSemgrepParserAndSeverityMapping(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{
		"version": "1.90.0",
		"results": [
			{
				"check_id": "go.lang.security.audit.unsafe-exec",
				"path": "main.go",
				"start": {"line": 10, "col": 2},
				"end": {"line": 10, "col": 24},
				"extra": {
					"message": "Potential command injection",
					"severity": "ERROR",
					"fingerprint": "semgrep-fp-1",
					"metadata": {"category": "security"}
				}
			},
			{
				"check_id": "go.lang.best-practice.warn",
				"path": "util.go",
				"start": {"line": 5, "col": 1},
				"end": {"line": 5, "col": 10},
				"extra": {"message": "Warn issue", "severity": "WARNING", "fingerprint": "fp-2"}
			}
		],
		"errors": [],
		"paths": {"scanned": ["main.go", "util.go"], "skipped": []}
	}`)

	parsed, err := parseSemgrepReport(raw, dir, NewRedactor())
	if err != nil {
		t.Fatalf("parseSemgrepReport failed: %v", err)
	}
	if parsed.version != "1.90.0" || parsed.filesExamined != 2 || parsed.filesSkipped != 0 {
		t.Fatalf("unexpected semgrep parsed metadata: %+v", parsed)
	}
	if len(parsed.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(parsed.findings))
	}
	if parsed.findings[0].Category != "SAST" || parsed.findings[0].Severity != domain.SeverityHigh {
		t.Fatalf("expected SAST/HIGH for ERROR, got %s/%s", parsed.findings[0].Category, parsed.findings[0].Severity)
	}
	if parsed.findings[0].StartLine != 10 || parsed.findings[0].EndLine != 10 {
		t.Fatalf("expected lines 10..10, got %d..%d", parsed.findings[0].StartLine, parsed.findings[0].EndLine)
	}
	if parsed.findings[1].Severity != domain.SeverityMedium {
		t.Fatalf("expected MEDIUM for WARNING, got %s", parsed.findings[1].Severity)
	}

	// Skipped paths -> incomplete
	skippedRaw := []byte(`{
		"version": "1.90.0",
		"results": [],
		"errors": [{"level": "warn", "message": "skipped file due to size/parse limit"}],
		"paths": {"scanned": ["main.go"], "skipped": ["huge.bin"]}
	}`)
	skippedParsed, err := parseSemgrepReport(skippedRaw, dir, NewRedactor())
	if err != nil {
		t.Fatalf("parseSemgrepReport skipped failed: %v", err)
	}
	if skippedParsed.filesSkipped < 1 || len(skippedParsed.skippedReasons) == 0 {
		t.Fatalf("expected skipped files detected, got %+v", skippedParsed)
	}
}

func TestTrivyConditionalManifestAndParser(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{
		"SchemaVersion": 2,
		"ArtifactName": ".",
		"ArtifactType": "filesystem",
		"Results": [{
			"Target": "go.mod",
			"Class": "lang-pkgs",
			"Type": "gomod",
			"Vulnerabilities": [{
				"VulnerabilityID": "CVE-2026-0001",
				"PkgName": "example.com/vulnlib",
				"InstalledVersion": "v1.0.0",
				"FixedVersion": "v1.0.1",
				"Severity": "CRITICAL",
				"Title": "Critical dependency vulnerability"
			}],
			"Misconfigurations": [{
				"ID": "DS002",
				"Title": "Image user should not be root",
				"Severity": "HIGH"
			}]
		}]
	}`)

	findings, _, resultCount, err := parseTrivyReport(raw, dir, NewRedactor())
	if err != nil {
		t.Fatalf("parseTrivyReport failed: %v", err)
	}
	if resultCount != 1 || len(findings) != 2 {
		t.Fatalf("expected 1 result and 2 findings, got resultCount=%d findings=%d", resultCount, len(findings))
	}
	if findings[0].Category != "VULNERABILITY" || findings[0].RuleID != "CVE-2026-0001" || findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("unexpected vulnerability finding: %+v", findings[0])
	}
	if findings[1].Category != "MISCONFIGURATION" || findings[1].RuleID != "DS002" || findings[1].Severity != domain.SeverityHigh {
		t.Fatalf("unexpected misconfiguration finding: %+v", findings[1])
	}
}

func TestCustomScannerRulesAndCleanRepo(t *testing.T) {
	cleanDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cleanDir, "README.md"), []byte("# Clean Repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cleanDir, "go.mod"), []byte("module example.com/clean\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cleanDir, ".env.example"), []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cleanDir, "id_rsa.pub"), []byte("ssh-rsa AAAAB3NzaC1yc2E\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := newCustomScanner(DefaultConfig())
	invClean, err := WalkWorkspace(cleanDir)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{ProposalID: domain.MustNewID(), ArtifactID: domain.MustNewID(), TargetDir: cleanDir}
	outClean, err := sc.Scan(context.Background(), req, invClean)
	if err != nil {
		t.Fatalf("custom clean scan failed: %v", err)
	}
	if !outClean.ScanRun.IsCleanComplete() || len(outClean.Findings) != 0 || outClean.ScanRun.Coverage.FilesExamined != 4 {
		t.Fatalf("expected clean complete with 0 findings and 4 files examined, got run=%+v findings=%d", outClean.ScanRun, len(outClean.Findings))
	}

	// Now create restricted secrets, PEM, credential lines, and ELF binary.
	dirtyDir := t.TempDir()
	canaryKeyBody := "FAKE_E2E_TEST_KEY_DATA_DO_NOT_USE_000000000000000000000000000000"
	pemContent := "-----BEGIN RSA PRIVATE KEY-----\n" + canaryKeyBody + "\n-----END RSA PRIVATE KEY-----\n"
	if err := os.MkdirAll(filepath.Join(dirtyDir, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirtyDir, "secrets", "id_rsa.pem"), []byte(pemContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirtyDir, ".env"), []byte("API_SECRET=super_secret_env_value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirtyDir, "main.go"), []byte("package main\nconst tok = \"ghp_1234567890abcdef123456\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ELF header
	if err := os.WriteFile(filepath.Join(dirtyDir, "payload.bin"), []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, 0o644); err != nil {
		t.Fatal(err)
	}

	invDirty, err := WalkWorkspace(dirtyDir)
	if err != nil {
		t.Fatal(err)
	}
	outDirty, err := sc.Scan(context.Background(), Request{ProposalID: domain.MustNewID(), ArtifactID: domain.MustNewID(), TargetDir: dirtyDir}, invDirty)
	if err != nil {
		t.Fatalf("custom dirty scan failed: %v", err)
	}
	if len(outDirty.Findings) != 4 {
		t.Fatalf("expected 4 custom findings (.env, main.go, payload.bin, secrets/id_rsa.pem), got %d: %+v", len(outDirty.Findings), outDirty.Findings)
	}

	redactor := NewRedactor()
	redactor.AddSecrets(outDirty.rawSecrets...)
	for i := range outDirty.Findings {
		if err := redactor.FinalizeFinding(&outDirty.Findings[i], outDirty.ScanRun.ID); err != nil {
			t.Fatalf("FinalizeFinding failed: %v", err)
		}
		if !outDirty.Findings[i].Redacted {
			t.Fatalf("expected finding %d to have Redacted=true", i)
		}
		if strings.Contains(outDirty.Findings[i].Message, canaryKeyBody) ||
			strings.Contains(outDirty.Findings[i].Message, "super_secret_env_value") ||
			strings.Contains(outDirty.Findings[i].Message, "ghp_1234567890abcdef123456") {
			t.Fatalf("secret leaked in custom finding message: %+v", outDirty.Findings[i])
		}
	}
	// Ensure base64 of the canary PEM body is also registered in rawSecrets/Redactor.
	scrubbedB64 := redactor.ScrubString(base64.StdEncoding.EncodeToString([]byte(canaryKeyBody)))
	if strings.Contains(scrubbedB64, base64.StdEncoding.EncodeToString([]byte(canaryKeyBody))) {
		t.Fatalf("expected canaryKeyBody base64 to be scrubbed by harvested secrets")
	}
}

type mockIPHook struct {
	findings []domain.Finding
	err      error
}

func (m mockIPHook) Name() string    { return string(ScannerIPFingerprint) }
func (m mockIPHook) Version() string { return "2.1.0-custom" }
func (m mockIPHook) Analyze(_ context.Context, _ Request, inv *Inventory) ([]domain.Finding, domain.ScanCoverage, error) {
	if m.err != nil {
		return nil, domain.ScanCoverage{Complete: false}, m.err
	}
	n := 0
	if inv != nil {
		n = inv.FilesExamined
	}
	return m.findings, domain.ScanCoverage{FilesExamined: n, Complete: true}, nil
}

func TestIPFingerprintHook(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := WalkWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}

	sc := newIPFingerprintScanner(nil)
	out, err := sc.Scan(context.Background(), Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      dir,
		Classification: domain.ClassificationRestricted,
	}, inv)
	if err != nil {
		t.Fatalf("default ip_fingerprint scan failed: %v", err)
	}
	if out.ScanRun.Scanner != "ip_fingerprint" || !out.ScanRun.IsCleanComplete() || out.ScanRun.Coverage.FilesExamined != 1 {
		t.Fatalf("unexpected ip_fingerprint ScanRun: %+v", out.ScanRun)
	}

	// Custom hook returning finding with safe metadata
	customHook := mockIPHook{
		findings: []domain.Finding{{
			Category: "IP_SIMILARITY",
			Severity: domain.SeverityHigh,
			RuleID:   "ip.similarity.high",
			Path:     "main.go",
			Message:  "High similarity to proprietary corpus",
			Metadata: map[string]any{"score": 0.92},
		}},
	}
	scCustom := newIPFingerprintScanner(customHook)
	outCustom, err := scCustom.Scan(context.Background(), Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      dir,
		Classification: domain.ClassificationRestricted,
	}, inv)
	if err != nil {
		t.Fatalf("custom ip_fingerprint scan failed: %v", err)
	}
	if outCustom.ScanRun.ScannerVersion != "2.1.0-custom" || len(outCustom.Findings) != 1 || !outCustom.Findings[0].Redacted {
		t.Fatalf("unexpected custom hook output: run=%+v findings=%+v", outCustom.ScanRun, outCustom.Findings)
	}
}
