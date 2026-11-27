package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/policy"
)

const minimalValidBundleYAML = `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: test-bundle
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep]
  decisionModel:
    route: approved-code-review
rules:
  - id: rule.approval
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("infra/"))
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: platform-owners
  - id: rule.allow
    stages: [EGRESS]
    when: findings.scan_complete && findings.critical_secrets == 0
    effect: ALLOW
`

func TestParseBundle_DefaultsAndCanonicalDigest(t *testing.T) {
	b, errs := policy.ParseBundle([]byte(minimalValidBundleYAML))
	if len(errs) != 0 {
		t.Fatalf("unexpected parse errors: %+v", errs)
	}
	if b.Rules[0].Obligations[0].Type != policy.DefaultObligationType {
		t.Fatalf("obligation type=%q, want %q", b.Rules[0].Obligations[0].Type, policy.DefaultObligationType)
	}
	if b.Rules[0].Obligations[0].Minimum == nil || *b.Rules[0].Obligations[0].Minimum != 1 {
		t.Fatalf("obligation minimum=%v, want 1", b.Rules[0].Obligations[0].Minimum)
	}

	canonBytes, digest1, err := policy.CanonicalBundleJSON(b)
	if err != nil {
		t.Fatalf("CanonicalBundleJSON: %v", err)
	}
	if !domain.IsValidSHA256Hex(digest1) {
		t.Fatalf("invalid SHA256 digest: %q", digest1)
	}

	// Re-parsing from JSON (simulating DB policy_bundles.definition) must yield the exact same digest.
	dbBundle := domain.PolicyBundle{
		ID:         uuid.New(),
		Name:       b.Metadata.Name,
		Version:    b.Metadata.Version,
		Scope:      domain.PolicyScopeOrg,
		Digest:     digest1,
		Definition: json.RawMessage(canonBytes),
	}
	bFromDB, dbErrs := policy.ParseDomainBundle(dbBundle)
	if len(dbErrs) != 0 {
		t.Fatalf("ParseDomainBundle errors: %+v", dbErrs)
	}
	_, digest2, err := policy.CanonicalBundleJSON(bFromDB)
	if err != nil {
		t.Fatalf("CanonicalBundleJSON(db): %v", err)
	}
	if digest1 != digest2 {
		t.Fatalf("digest mismatch between YAML (%s) and DB JSON (%s)", digest1, digest2)
	}
}

func TestParseBundle_StrictValidationErrors(t *testing.T) {
	cases := []struct {
		name     string
		yaml     string
		wantCode string
	}{
		{
			name:     "empty_input",
			yaml:     "   \n",
			wantCode: "INVALID_YAML",
		},
		{
			name:     "unknown_field",
			yaml:     minimalValidBundleYAML + "unexpected_top_key: true\n",
			wantCode: "INVALID_YAML",
		},
		{
			name:     "multi_document_yaml",
			yaml:     minimalValidBundleYAML + "\n---\n" + minimalValidBundleYAML,
			wantCode: "MULTI_DOCUMENT_YAML",
		},
		{
			name: "unsupported_api_version",
			yaml: `apiVersion: custodian.dev/v99
kind: PolicyBundle
metadata:
  name: v99
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
`,
			wantCode: "UNSUPPORTED_API_VERSION",
		},
		{
			name: "invalid_kind",
			yaml: `apiVersion: custodian.dev/v1
kind: SomethingElse
metadata:
  name: bad-kind
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
`,
			wantCode: "INVALID_KIND",
		},
		{
			name: "empty_metadata",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: ""
  version: ""
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
`,
			wantCode: "INVALID_METADATA",
		},
		{
			name: "invalid_scope",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: bad-scope
  version: "1.0.0"
  scope: TEAM
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
`,
			wantCode: "INVALID_SCOPE",
		},
		{
			name: "invalid_on_error_allow",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: fail-open
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: ALLOW
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
`,
			wantCode: "INVALID_ON_ERROR",
		},
		{
			name: "empty_rules",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: no-rules
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules: []
`,
			wantCode: "EMPTY_RULES",
		},
		{
			name: "duplicate_rule_id",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: dup-id
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: dup.rule
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
  - id: dup.rule
    stages: [EGRESS]
    when: "false"
    effect: DENY
`,
			wantCode: "DUPLICATE_RULE_ID",
		},
		{
			name: "invalid_stage",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: bad-stage
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [PUBLISH]
    when: "true"
    effect: ALLOW
`,
			wantCode: "INVALID_RULE_STAGES",
		},
		{
			name: "invalid_effect",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: bad-effect
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: BYPASS
`,
			wantCode: "INVALID_RULE_EFFECT",
		},
		{
			name: "obligation_on_allow_rejected",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: bad-obl
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
    obligations:
      - reviewer_group: sec
        minimum: 1
`,
			wantCode: "INVALID_OBLIGATION",
		},
		{
			name: "obligation_minimum_zero_rejected",
			yaml: `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: bad-min
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r1
    stages: [EGRESS]
    when: "true"
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: sec
        minimum: 0
`,
			wantCode: "INVALID_OBLIGATION",
		},
	}

	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := engine.Validate([]byte(tc.yaml))
			if res.Valid {
				t.Fatalf("expected invalid validation result, got valid=true")
			}
			if !domain.IsValidSHA256Hex(res.Digest) {
				t.Fatalf("expected valid 64-hex digest even on invalid bundle, got %q", res.Digest)
			}
			var found bool
			for _, e := range res.Errors {
				if e.Code == tc.wantCode {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error code %q, got %+v", tc.wantCode, res.Errors)
			}
		})
	}
}

func TestLoader_LoadDirAndPartitionByScope(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	emptyDir := t.TempDir()
	if _, err := engine.LoadDir(emptyDir); err == nil {
		t.Fatalf("expected error loading empty policy directory")
	}

	badDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(badDir, "bad.yaml"), []byte("not: valid"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := engine.LoadDir(badDir); err == nil {
		t.Fatalf("expected error when directory contains invalid bundle")
	}

	examples, err := engine.LoadDir(filepath.Join("..", "..", "policies", "examples"))
	if err != nil {
		t.Fatalf("LoadDir(examples): %v", err)
	}
	orgB, repoB := policy.PartitionByScope(examples)
	if len(orgB) != 1 || len(repoB) != 2 {
		t.Fatalf("PartitionByScope got org=%d repo=%d, want org=1 repo=2", len(orgB), len(repoB))
	}
}
