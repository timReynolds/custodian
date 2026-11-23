package policy_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/policy"
)

func TestSuite_RunPoliciesTestsDirectory(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	testsDir := filepath.Join("..", "..", "policies", "tests")
	report, err := engine.RunTestDir(context.Background(), testsDir)
	if err != nil {
		t.Fatalf("RunTestDir(%s): %v", testsDir, err)
	}
	if !report.AllPassed() {
		t.Fatalf("policy test directory failed:\n%s", report.FormatText())
	}
	if len(report.Suites) < 3 || report.Passed < 14 {
		t.Fatalf("expected >= 3 suites and >= 14 passed cases, got suites=%d passed=%d", len(report.Suites), report.Passed)
	}

	textOut := report.FormatText()
	if !strings.Contains(textOut, "TOTAL:") {
		t.Fatalf("expected TOTAL summary in FormatText, got %q", textOut)
	}
	jsonOut, err := report.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	var decoded policy.TestDirReport
	if err := json.Unmarshal(jsonOut, &decoded); err != nil {
		t.Fatalf("unmarshal FormatJSON: %v", err)
	}
	if decoded.Passed != report.Passed || decoded.Failed != 0 {
		t.Fatalf("unexpected decoded JSON report: %+v", decoded)
	}
}

func TestSuite_ValidateWithInlineTestCases(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	passingSuite := `apiVersion: custodian.dev/v1
kind: PolicyTestSuite
metadata:
  name: inline-suite
cases:
  - name: allow_clean_egress
    stage: EGRESS
    input:
      findings:
        scan_complete: true
        critical_secrets: 0
        prohibited_licenses: 0
      change:
        paths: ["pkg/app.go"]
    expect:
      effect: ALLOW
      matched_rules: [rule.allow]
      absent_rules: [rule.approval]
`
	res, rep := engine.ValidateWithTests(context.Background(), []byte(minimalValidBundleYAML), []byte(passingSuite))
	if !res.Valid || rep == nil || !rep.AllPassed() {
		t.Fatalf("expected valid bundle and passing inline suite, got res=%+v rep=%+v", res, rep)
	}

	failingSuite := `apiVersion: custodian.dev/v1
kind: PolicyTestSuite
metadata:
  name: failing-inline-suite
cases:
  - name: wrong_expectation
    stage: EGRESS
    input:
      findings:
        scan_complete: true
        critical_secrets: 0
      change:
        paths: ["pkg/app.go"]
    expect:
      effect: DENY
`
	failRes, failRep := engine.ValidateWithTests(context.Background(), []byte(minimalValidBundleYAML), []byte(failingSuite))
	if failRes.Valid || failRep == nil || failRep.AllPassed() {
		t.Fatalf("expected ValidateWithTests to fail on mismatched test expectation, got res=%+v rep=%+v", failRes, failRep)
	}
	if len(failRes.Errors) == 0 || failRes.Errors[0].Code != "POLICY_TEST_FAILED" {
		t.Fatalf("expected POLICY_TEST_FAILED error, got %+v", failRes.Errors)
	}
}
