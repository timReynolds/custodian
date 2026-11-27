package inspection

import (
	"encoding/base64"
	"encoding/json"
	"go/parser"
	"go/token"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/timreynolds/custodian/internal/domain"
)

func TestInspectionImportsLayer0Only(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("readdir %s: %v", wd, err)
	}

	forbiddenPrefixes := []string{
		"github.com/timreynolds/custodian/internal/persistence",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/artifacts",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/git",
		"github.com/timreynolds/custodian/internal/github",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/workflow",
		"github.com/timreynolds/custodian/internal/publication",
		"github.com/timreynolds/custodian/internal/api",
		"github.com/timreynolds/custodian/test/e2e",
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fileAST, parseErr := parser.ParseFile(fset, filepath.Join(wd, name), nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		for _, imp := range fileAST.Imports {
			pathVal, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", name, err)
			}
			for _, bad := range forbiddenPrefixes {
				if strings.HasPrefix(pathVal, bad) {
					t.Fatalf("forbidden import %q in %s (must remain Layer 0 + stdlib only)", pathVal, name)
				}
			}
			if strings.Contains(pathVal, ".") {
				allowedThirdParty := pathVal == "github.com/google/uuid" ||
					pathVal == "github.com/timreynolds/custodian/internal/domain" ||
					pathVal == "github.com/timreynolds/custodian/internal/observability" ||
					strings.HasPrefix(pathVal, "go.opentelemetry.io/otel/")
				if !allowedThirdParty {
					t.Fatalf("unexpected non-stdlib import %q in %s", pathVal, name)
				}
			}
		}
	}
}

func TestLoadConfigFromEnvAndDefaults(t *testing.T) {
	t.Setenv(EnvGitleaksBin, "/custom/bin/gitleaks")
	t.Setenv(EnvScanCodeBin, "/custom/bin/scancode")
	t.Setenv(EnvSemgrepBin, "/custom/bin/semgrep")
	t.Setenv(EnvTrivyBin, "/custom/bin/trivy")
	t.Setenv(EnvScannerTimeout, "2500ms")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv failed: %v", err)
	}
	if cfg.GitleaksBin != "/custom/bin/gitleaks" ||
		cfg.ScanCodeBin != "/custom/bin/scancode" ||
		cfg.SemgrepBin != "/custom/bin/semgrep" ||
		cfg.TrivyBin != "/custom/bin/trivy" {
		t.Fatalf("unexpected bin overrides: %+v", cfg)
	}
	if cfg.ScannerTimeout.Milliseconds() != 2500 {
		t.Fatalf("expected 2500ms timeout, got %v", cfg.ScannerTimeout)
	}

	t.Setenv(EnvScannerTimeout, "not-a-duration")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error on invalid %s", EnvScannerTimeout)
	}

	t.Setenv(EnvScannerTimeout, "-5s")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error on negative %s", EnvScannerTimeout)
	}
}

func TestDeterministicFingerprintAndEvidenceID(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	fp1 := ComputeFingerprint("gitleaks", "aws-access-token", "main.go", 2, 2, secret)
	fp2 := ComputeFingerprint("gitleaks", "aws-access-token", "main.go", 2, 2, secret)
	fpDiffLine := ComputeFingerprint("gitleaks", "aws-access-token", "main.go", 3, 3, secret)

	if fp1 != fp2 {
		t.Fatalf("expected deterministic fingerprint, got %q vs %q", fp1, fp2)
	}
	if !domain.IsValidSHA256Hex(fp1) {
		t.Fatalf("expected valid 64-hex SHA-256 fingerprint, got %q", fp1)
	}
	if fp1 == fpDiffLine {
		t.Fatalf("expected different line numbers to produce different fingerprints")
	}
	if strings.Contains(fp1, secret) {
		t.Fatalf("fingerprint leaked raw secret")
	}

	ev1 := ComputeEvidenceID("gitleaks", "SECRET", "aws-access-token", "main.go", 2, 2, fp1)
	ev2 := ComputeEvidenceID("gitleaks", "SECRET", "aws-access-token", "main.go", 2, 2, fp2)
	if ev1 != ev2 {
		t.Fatalf("expected deterministic evidence ID, got %q vs %q", ev1, ev2)
	}
	evPattern := regexp.MustCompile(`^finding_[A-Za-z0-9_-]+$`)
	if !evPattern.MatchString(ev1) {
		t.Fatalf("evidence ID %q does not match ^finding_[A-Za-z0-9_-]+$", ev1)
	}
	if strings.Contains(ev1, secret) {
		t.Fatalf("evidence ID leaked raw secret")
	}
}

func TestRedactorVerbatimAndEncodedScrubbing(t *testing.T) {
	secret1 := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	secret2 := "FAKE_E2E_TEST_KEY_DATA_DO_NOT_USE_000000000000000000000000000000"
	pemBlock := "-----BEGIN RSA PRIVATE KEY-----\n" + secret2 + "\n-----END RSA PRIVATE KEY-----"

	r := NewRedactor("AWS_ACCESS_KEY_ID=" + secret1)
	r.AddSecrets(pemBlock)

	type nestedStruct struct {
		SafeField string `json:"safe_field"`
		Secret    string `json:"secret"`
	}

	ptrSecret := secret1
	f := domain.Finding{
		ID:          uuid.New(), // UUIDv4 intentionally: FinalizeFinding must replace with UUIDv7.
		Scanner:     "gitleaks",
		Category:    "secret",
		Severity:    domain.SeverityCritical,
		RuleID:      "aws-access-token",
		Path:        "config.go",
		StartLine:   -3,
		EndLine:     -1,
		Confidence:  math.NaN(),
		Fingerprint: "raw-secret-" + secret1,
		Message: strings.Join([]string{
			"verbatim=" + secret1,
			"b64=" + base64.StdEncoding.EncodeToString([]byte(secret1)),
			"b64url=" + base64.RawURLEncoding.EncodeToString([]byte(secret1)),
			"urlq=" + url.QueryEscape(secret1),
			"pem=" + base64.StdEncoding.EncodeToString([]byte(secret2)),
		}, " "),
		EvidenceRef: "ref/" + url.QueryEscape(secret1),
		Baseline:    base64.StdEncoding.EncodeToString([]byte(secret2)),
		Redacted:    false,
		Metadata: map[string]any{
			"raw_secret":  secret1,
			"SECRET":      secret1,
			"token":       secret1,
			"private_key": secret2,
			"password":    secret1,
			"credential":  secret1,
			"match_raw":   secret1,
			"safe_ptr":    &ptrSecret,
			"safe_nested": nestedStruct{SafeField: base64.RawURLEncoding.EncodeToString([]byte(secret1)), Secret: secret1},
			"safe_raw":    json.RawMessage(`{"note":"` + base64.StdEncoding.EncodeToString([]byte(secret1)) + `","token":"bad"}`),
		},
	}

	runID := domain.MustNewID()
	if err := r.FinalizeFinding(&f, runID); err != nil {
		t.Fatalf("FinalizeFinding failed: %v", err)
	}

	if !domain.IsUUIDv7(f.ID) {
		t.Fatalf("expected FinalizeFinding to assign UUIDv7 ID, got %s", f.ID)
	}
	if f.ScanRunID != runID {
		t.Fatalf("expected ScanRunID %s, got %s", runID, f.ScanRunID)
	}
	if !f.Redacted {
		t.Fatalf("expected Redacted=true")
	}
	if f.StartLine != 0 || f.EndLine != 0 {
		t.Fatalf("expected clamped non-negative line numbers, got %d..%d", f.StartLine, f.EndLine)
	}
	if f.Confidence != 0 {
		t.Fatalf("expected NaN confidence clamped to 0, got %v", f.Confidence)
	}
	if !domain.IsValidSHA256Hex(f.Fingerprint) {
		t.Fatalf("expected SHA-256 fingerprint, got %q", f.Fingerprint)
	}
	if !strings.HasPrefix(f.EvidenceID, "finding_gitleaks_") {
		t.Fatalf("unexpected evidence ID %q", f.EvidenceID)
	}
	if err := f.ValidateRedacted(); err != nil {
		t.Fatalf("ValidateRedacted failed after FinalizeFinding: %v", err)
	}

	serialized, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	payload := string(serialized)
	for _, needle := range []string{
		secret1,
		secret2,
		base64.StdEncoding.EncodeToString([]byte(secret1)),
		base64.RawURLEncoding.EncodeToString([]byte(secret1)),
		url.QueryEscape(secret1),
		base64.StdEncoding.EncodeToString([]byte(secret2)),
		base64.RawURLEncoding.EncodeToString([]byte(secret2)),
		url.QueryEscape(secret2),
		`"raw_secret"`,
		`"private_key"`,
		`"match_raw"`,
	} {
		if strings.Contains(payload, needle) {
			t.Fatalf("leaked sensitive or forbidden token %q in finding JSON: %s", needle, payload)
		}
	}

	// Verify domain.Finding.ValidateRedacted itself rejects unredacted SECRET findings or forbidden keys.
	unredacted := domain.Finding{Category: "SECRET", Redacted: false}
	if err := unredacted.ValidateRedacted(); err == nil {
		t.Fatalf("expected ValidateRedacted error for unredacted SECRET finding")
	}
	withForbidden := domain.Finding{
		Category: "SECRET",
		Redacted: true,
		Metadata: map[string]any{"raw_secret": "leak"},
	}
	if err := withForbidden.ValidateRedacted(); err == nil {
		t.Fatalf("expected ValidateRedacted error for raw_secret metadata key")
	}
}

func TestInventoryWalkWorkspaceAndManifests(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write .git/HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "Dockerfile.prod"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile.prod: %v", err)
	}

	inv, err := WalkWorkspace(dir)
	if err != nil {
		t.Fatalf("WalkWorkspace failed: %v", err)
	}
	if inv.FilesExamined != 3 {
		t.Fatalf("expected 3 regular files (excluding .git), got %d", inv.FilesExamined)
	}
	if inv.FilesSkipped != 0 {
		t.Fatalf("expected 0 skipped files, got %d (%v)", inv.FilesSkipped, inv.SkippedReasons)
	}
	if !inv.HasManifests || len(inv.ManifestPaths) != 2 {
		t.Fatalf("expected 2 manifests (go.mod, sub/Dockerfile.prod), got %v", inv.ManifestPaths)
	}

	// Adding a symlink must increment FilesSkipped and record reason.
	if err := os.Symlink(filepath.Join(dir, "main.go"), filepath.Join(dir, "link.go")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	invSym, err := WalkWorkspace(dir)
	if err != nil {
		t.Fatalf("WalkWorkspace with symlink failed: %v", err)
	}
	if invSym.FilesSkipped != 1 || len(invSym.SkippedReasons) != 1 {
		t.Fatalf("expected 1 skipped symlink, got count=%d reasons=%v", invSym.FilesSkipped, invSym.SkippedReasons)
	}
}

func TestReportAllCleanCompleteAndSummaryPolicyFacts(t *testing.T) {
	propID := domain.MustNewID()
	artID := domain.MustNewID()

	makeRun := func(scanner string, status domain.ScanStatus, complete bool, skipped int) domain.ScanRun {
		return domain.ScanRun{
			ID:             domain.MustNewID(),
			ProposalID:     propID,
			ArtifactID:     artID,
			Scanner:        scanner,
			ScannerVersion: "1.0.0",
			Status:         status,
			Coverage: domain.ScanCoverage{
				FilesExamined: 3,
				FilesSkipped:  skipped,
				Complete:      complete,
			},
		}
	}

	cleanRuns := []domain.ScanRun{
		makeRun("gitleaks", domain.ScanStatusCompleted, true, 0),
		makeRun("scancode", domain.ScanStatusCompleted, true, 0),
		makeRun("semgrep", domain.ScanStatusCompleted, true, 0),
		makeRun("custom", domain.ScanStatusCompleted, true, 0),
	}
	repClean := Report{ProposalID: propID, ArtifactID: artID, ScanRuns: cleanRuns}
	if !repClean.AllCleanComplete() {
		t.Fatalf("expected AllCleanComplete=true when all mandatory scanners complete cleanly")
	}

	// Missing one mandatory scanner -> false.
	repMissing := Report{ProposalID: propID, ArtifactID: artID, ScanRuns: cleanRuns[:3]}
	if repMissing.AllCleanComplete() {
		t.Fatalf("expected AllCleanComplete=false when custom scanner is missing")
	}

	// Conditional trivy skipped files -> false even when mandatory scanners succeeded.
	withSkippedTrivy := append(append([]domain.ScanRun(nil), cleanRuns...), makeRun("trivy", domain.ScanStatusIncomplete, false, 1))
	repSkipped := Report{ProposalID: propID, ArtifactID: artID, ScanRuns: withSkippedTrivy}
	if repSkipped.AllCleanComplete() {
		t.Fatalf("expected AllCleanComplete=false when trivy has skipped files")
	}

	findings := []domain.Finding{
		{
			ID:          domain.MustNewID(),
			ScanRunID:   cleanRuns[0].ID,
			EvidenceID:  "finding_gitleaks_1111",
			Scanner:     "gitleaks",
			Category:    "SECRET",
			Severity:    domain.SeverityCritical,
			RuleID:      "aws-access-token",
			Fingerprint: domain.SHA256Hex([]byte("1")),
			Redacted:    true,
		},
		{
			ID:          domain.MustNewID(),
			ScanRunID:   cleanRuns[1].ID,
			EvidenceID:  "finding_scancode_2222",
			Scanner:     "scancode",
			Category:    "LICENSE",
			Severity:    domain.SeverityHigh,
			RuleID:      "prohibited-license-gpl-3.0-only",
			Fingerprint: domain.SHA256Hex([]byte("2")),
			Redacted:    true,
			Metadata:    map[string]any{"spdx": "GPL-3.0-only", "prohibited": true},
		},
	}

	summary := buildSummary(withSkippedTrivy, findings, DefaultProhibitedLicenses)
	if summary.ScanComplete {
		t.Fatalf("expected ScanComplete=false")
	}
	if !summary.MandatoryScannersComplete {
		t.Fatalf("expected MandatoryScannersComplete=true")
	}
	if summary.CriticalSecrets != 1 || summary.ProhibitedLicenses != 1 || summary.TotalFindings != 2 {
		t.Fatalf("unexpected summary counts: %+v", summary)
	}

	facts := summary.PolicyFacts()
	if facts["scan_complete"] != false {
		t.Fatalf("expected facts[scan_complete]=false, got %v", facts["scan_complete"])
	}
	if facts["critical_secrets"] != 1 || facts["prohibited_licenses"] != 1 {
		t.Fatalf("unexpected PolicyFacts counts: %+v", facts)
	}
}

func TestReportScrubTextRedactsHarvestedAndPatternSecrets(t *testing.T) {
	sec1 := "AKIAIOSFODNN7EXAMPLE"
	sec2 := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	red := NewRedactor(sec2)
	rep := Report{redactor: red}

	diff := "+++ b/secrets.env\n+AWS_ACCESS_KEY_ID=" + sec1 + "\n+CUSTODIAN_SYNTHETIC_TOKEN=" + sec2 + "\n+NORMAL=ok\n"
	scrubbed := rep.ScrubText(diff)
	if strings.Contains(scrubbed, sec1) || strings.Contains(scrubbed, sec2) {
		t.Fatalf("expected all secrets scrubbed from diff, got: %s", scrubbed)
	}
	if !strings.Contains(scrubbed, "+NORMAL=ok") {
		t.Fatalf("expected non-secret diff lines preserved, got: %s", scrubbed)
	}

	// Zero-value redactor still scrubs built-in credential patterns.
	zeroRep := Report{}
	if got := zeroRep.ScrubText("key=" + sec1); strings.Contains(got, sec1) {
		t.Fatalf("expected built-in pattern scrubbed even with nil redactor, got: %s", got)
	}
}
