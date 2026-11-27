package policy_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/policy"
)

func TestCompiler_RepoPoliciesAndE2EFixtures(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// 1. Validate all bundles in policies/defaults and policies/examples.
	for _, sub := range []string{"defaults", "examples"} {
		dir := filepath.Join("..", "..", "policies", sub)
		bundles, err := engine.LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir(%s): %v", dir, err)
		}
		if len(bundles) == 0 {
			t.Fatalf("expected at least 1 bundle in %s", dir)
		}
	}

	// 2. Validate valid E2E fixtures.
	validFixtures := []struct {
		file      string
		wantName  string
		wantRules int
	}{
		{"valid_default.yaml", "engineering-default", 5},
		{"org_mandatory_deny.yaml", "org-mandatory-baseline", 3},
		{"repo_permissive_override_attempt.yaml", "repo-permissive-override", 2},
		{"runtime_cel_error_fail_closed.yaml", "runtime-cel-error-fail-closed", 2},
	}
	for _, fx := range validFixtures {
		path := filepath.Join("..", "..", "test", "e2e", "fixtures", "policies", fx.file)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		res := engine.Validate(raw)
		if !res.Valid {
			t.Fatalf("fixture %s failed validation: %+v", fx.file, res.Errors)
		}
		if res.Name != fx.wantName || res.RulesCompiled != fx.wantRules {
			t.Fatalf("fixture %s got name=%q rules=%d, want name=%q rules=%d", fx.file, res.Name, res.RulesCompiled, fx.wantName, fx.wantRules)
		}
	}

	// 3. Reject invalid E2E fixtures at compile time.
	invalidFixtures := []struct {
		file     string
		wantCode string
	}{
		{"invalid_cel_syntax.yaml", "CEL_SYNTAX_ERROR"},
		{"invalid_cel_type_error.yaml", "CEL_TYPE_ERROR"},
	}
	for _, fx := range invalidFixtures {
		path := filepath.Join("..", "..", "test", "e2e", "fixtures", "policies", fx.file)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		res := engine.Validate(raw)
		if res.Valid || len(res.Errors) == 0 {
			t.Fatalf("expected fixture %s to fail validation, got %+v", fx.file, res)
		}
		if res.Errors[0].Code != fx.wantCode {
			t.Fatalf("fixture %s error code=%q, want %q (%+v)", fx.file, res.Errors[0].Code, fx.wantCode, res.Errors)
		}
		if compiled, errs := engine.Compile(raw); compiled != nil || len(errs) == 0 {
			t.Fatalf("Compile(%s) must fail", fx.file)
		}
	}
}

func TestCompiler_RejectsUnknownFieldsAndNonBooleanReturns(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name     string
		when     string
		wantCode string
	}{
		{
			name:     "unknown_struct_field",
			when:     "findings.nonexistent_counter > 0",
			wantCode: "CEL_TYPE_ERROR",
		},
		{
			name:     "non_boolean_int_return",
			when:     "findings.critical_secrets + 1",
			wantCode: "CEL_NON_BOOLEAN_RETURN",
		},
		{
			name:     "non_boolean_string_return",
			when:     `assessment.status`,
			wantCode: "CEL_NON_BOOLEAN_RETURN",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: bad-cel
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: bad.rule
    stages: [EGRESS]
    when: ` + tc.when + `
    effect: ALLOW
`
			res := engine.Validate([]byte(raw))
			if res.Valid || len(res.Errors) == 0 {
				t.Fatalf("expected invalid result for %q, got %+v", tc.when, res)
			}
			if res.Errors[0].Code != tc.wantCode {
				t.Fatalf("code=%q, want %q (errors=%+v)", res.Errors[0].Code, tc.wantCode, res.Errors)
			}
		})
	}
}

func TestLayer3ImportIsolation(t *testing.T) {
	forbiddenPrefixes := []string{
		"github.com/timreynolds/custodian/internal/persistence",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/artifacts",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/git",
		"github.com/timreynolds/custodian/internal/github",
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/repositories",
		"github.com/timreynolds/custodian/internal/workspaces",
		"github.com/timreynolds/custodian/internal/proposals",
		"github.com/timreynolds/custodian/internal/approvals",
		"github.com/timreynolds/custodian/internal/operations",
		"github.com/timreynolds/custodian/internal/audit",
		"github.com/timreynolds/custodian/internal/workflow",
		"github.com/timreynolds/custodian/internal/publication",
		"github.com/timreynolds/custodian/internal/api",
		"github.com/timreynolds/custodian/internal/harness",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", e.Name(), err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenPrefixes {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Fatalf("layer boundary violation: %s imports forbidden package %s", e.Name(), path)
				}
			}
		}
	}
}
