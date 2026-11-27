package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustodianPolicyHelpAndSubcommands(t *testing.T) {
	ctx := context.Background()

	// --help exits 0.
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--help expected 0, got %d (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "custodian-policy") {
		t.Fatalf("unexpected --help output: %s", stdout.String())
	}

	// test --help exits 0.
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"test", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("test --help expected 0, got %d (stderr=%s)", code, stderr.String())
	}

	// validate default bundle exits 0.
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"validate", "--bundle", "../../policies/defaults/default.yaml", "--format", "json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("validate default.yaml expected 0, got %d\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}
	var valOut map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &valOut); err != nil {
		t.Fatalf("unmarshal validate JSON: %v (%s)", err, stdout.String())
	}
	if valid, _ := valOut["valid"].(bool); !valid {
		t.Fatalf("expected valid=true, got %+v", valOut)
	}

	// validate invalid bundle exits non-zero.
	badPath := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(badPath, []byte("name: bad\nrules:\n  - id: r1\n    when: invalid(((cel\n"), 0o600); err != nil {
		t.Fatalf("WriteFile bad.yaml: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"validate", "--bundle", badPath}, &stdout, &stderr); code == 0 {
		t.Fatalf("validate invalid bundle expected non-zero exit, got 0")
	}

	// evaluate valid input prints decision effect & obligations JSON cleanly.
	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := `{
  "repository": {"full_name": "acme/demo", "classification": "INTERNAL"},
  "proposal": {"target_ref": "main"},
  "findings": {"mandatory_scanners_complete": true, "scan_complete": true}
}`
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("WriteFile input.json: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"evaluate", "--bundle", "../../policies/defaults/default.yaml", "--input", inputPath, "--stage", "EGRESS"}, &stdout, &stderr); code != 0 {
		t.Fatalf("evaluate default.yaml expected 0, got %d\nstderr=%s", code, stderr.String())
	}
	var evalOut map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &evalOut); err != nil {
		t.Fatalf("unmarshal evaluate output: %v (%s)", err, stdout.String())
	}
	if _, ok := evalOut["effect"].(string); !ok {
		t.Fatalf("expected effect in evaluate output: %+v", evalOut)
	}
	if _, ok := evalOut["obligations"]; !ok {
		t.Fatalf("expected obligations in evaluate output: %+v", evalOut)
	}

	// evaluate with CEL runtime error and onError: DENY returns DENY effect cleanly!
	denyErrBundle := filepath.Join(t.TempDir(), "on_error_deny.yaml")
	denyYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: on-error-deny-test
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: div-zero-deny
    stages:
      - EGRESS
    when: "1 / 0 == 1"
    effect: ALLOW
    message: "runtime error triggers deny"
`
	if err := os.WriteFile(denyErrBundle, []byte(denyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile on_error_deny.yaml: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"evaluate", "--bundle", denyErrBundle, "--input", inputPath, "--stage", "EGRESS"}, &stdout, &stderr); code != 0 {
		t.Fatalf("evaluate onError:DENY expected 0, got %d\nstderr=%s", code, stderr.String())
	}
	evalOut = nil
	if err := json.Unmarshal(stdout.Bytes(), &evalOut); err != nil {
		t.Fatalf("unmarshal onError evaluate output: %v (%s)", err, stdout.String())
	}
	if evalOut["effect"] != "DENY" {
		t.Fatalf("expected effect=DENY for onError:DENY runtime error, got %v", evalOut["effect"])
	}

	// test ../../policies/tests runs all suites and exits 0.
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"test", "../../policies/tests"}, &stdout, &stderr); code != 0 {
		t.Fatalf("custodian-policy test ../../policies/tests expected 0, got %d\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}

	// validate --bundle push-ip-protection.yaml --tests push_ip_protection_test.yaml exits 0.
	stdout.Reset()
	stderr.Reset()
	if code := run(ctx, []string{"validate", "--bundle", "../../policies/defaults/push-ip-protection.yaml", "--tests", "../../policies/tests/push_ip_protection_test.yaml", "--format", "json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("validate push-ip-protection with tests expected 0, got %d\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}
	var pushValOut map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &pushValOut); err != nil {
		t.Fatalf("unmarshal push validate JSON: %v (%s)", err, stdout.String())
	}
	if valid, _ := pushValOut["valid"].(bool); !valid {
		t.Fatalf("expected push-ip-protection valid=true, got %+v", pushValOut)
	}
}
