package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/policy"
)

func loadFixtureBundle(t *testing.T, engine *policy.Engine, name string) *policy.CompiledBundle {
	t.Helper()
	path := filepath.Join("..", "..", "test", "e2e", "fixtures", "policies", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	cb, errs := engine.Compile(raw)
	if len(errs) > 0 {
		t.Fatalf("compile fixture %s: %+v", name, errs)
	}
	return cb
}

func TestComposition_OrgNonOverridableDenyBlocksPermissiveRepo(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	org := loadFixtureBundle(t, engine, "org_mandatory_deny.yaml")
	repo := loadFixtureBundle(t, engine, "repo_permissive_override_attempt.yaml")

	res, err := engine.ComposeAndEvaluate(context.Background(), org, repo, policy.StageEgress, map[string]any{
		"findings": map[string]any{
			"critical_secrets":    1,
			"prohibited_licenses": 0,
			"scan_complete":       true,
		},
		"assessment": map[string]any{
			"status":  "COMPLETE",
			"ip_risk": "LOW",
		},
		"change": map[string]any{
			"paths": []string{"secrets.env"},
		},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate: %v", err)
	}
	if res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("effect=%s, want DENY", res.Effect)
	}
	if !slices.Contains(res.MatchedRuleIDs, "org.secrets.block") {
		t.Fatalf("expected org.secrets.block in matched rules, got %v", res.MatchedRuleIDs)
	}
}

func TestComposition_AdditiveRepoRestrictionsWhenOrgMatchesZeroRules(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	org := loadFixtureBundle(t, engine, "org_mandatory_deny.yaml")

	repoYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-docs-security
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep, trivy]
  decisionModel:
    route: restricted-review
    trigger: [docs_security_change]
rules:
  - id: repo.docs.review
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("docs/security/"))
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: sec-docs
        minimum: 1
`
	repo, errs := engine.Compile([]byte(repoYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(repo): %+v", errs)
	}

	res, err := engine.ComposeAndEvaluate(context.Background(), org, repo, policy.StageEgress, map[string]any{
		"findings":   map[string]any{"scan_complete": true, "critical_secrets": 0, "prohibited_licenses": 0},
		"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
		"change":     map[string]any{"paths": []string{"docs/security/spec.md"}},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate: %v", err)
	}
	if res.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("effect=%s, want REQUIRE_APPROVAL", res.Effect)
	}
	if !slices.Contains(res.MatchedRuleIDs, "repo.docs.review") {
		t.Fatalf("expected repo.docs.review matched, got %v", res.MatchedRuleIDs)
	}
	if len(res.Obligations) != 1 || res.Obligations[0].ReviewerGroup != "sec-docs" || res.Obligations[0].Minimum != 1 {
		t.Fatalf("unexpected obligations: %+v", res.Obligations)
	}

	// Verify inspection config merges org + repo cleanly, preferring org route.
	ins := policy.ComposeInspectionConfig(org, repo)
	if !slices.Contains(ins.Mandatory, "trivy") || !slices.Contains(ins.Mandatory, "gitleaks") {
		t.Fatalf("expected merged mandatory scanners, got %v", ins.Mandatory)
	}
	if ins.DecisionModel == nil || ins.DecisionModel.Route != "approved-code-review" {
		t.Fatalf("expected org route preferred, got %+v", ins.DecisionModel)
	}
	if !slices.Contains(ins.DecisionModel.Trigger, "docs_security_change") {
		t.Fatalf("expected repo trigger merged, got %v", ins.DecisionModel.Trigger)
	}
}

func TestComposition_ZeroMatchesAcrossBothUsesMoreRestrictiveDefault(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	org := loadFixtureBundle(t, engine, "org_mandatory_deny.yaml") // defaults.effect = DENY
	permissiveRepoYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-permissive-default
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: repo.unmatched
    stages: [EGRESS]
    when: change.paths.exists(p, p == "never-matches")
    effect: ALLOW
`
	repo, errs := engine.Compile([]byte(permissiveRepoYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	res, err := engine.ComposeAndEvaluate(context.Background(), org, repo, policy.StageEgress, map[string]any{
		"findings": map[string]any{"scan_complete": true, "critical_secrets": 0, "prohibited_licenses": 0},
		"change":   map[string]any{"paths": []string{"README.md"}},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate: %v", err)
	}
	if res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("effect=%s, want DENY (repo default ALLOW must not weaken org default DENY)", res.Effect)
	}
}

func TestComposition_OverridableOrgRuleCanBeTightenedNotWeakened(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	orgYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: org-overridable-and-implicit
  version: "1.0.0"
  scope: ORG
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: org.implicit.nonoverridable
    stages: [EGRESS]
    when: findings.prohibited_licenses > 0
    effect: DENY
  - id: org.review.overridable
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("api/"))
    effect: REQUIRE_APPROVAL
    overridable: true
    obligations:
      - reviewer_group: api-owners
        minimum: 1
`
	repoWeakenYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-weaken
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: org.implicit.nonoverridable
    stages: [EGRESS]
    when: findings.prohibited_licenses > 0
    effect: ALLOW
  - id: org.review.overridable
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("api/"))
    effect: ALLOW
`
	repoTightenYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-tighten
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: org.review.overridable
    stages: [EGRESS]
    when: change.paths.exists(p, p.startsWith("api/"))
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: api-security-board
        minimum: 2
`

	org, errs := engine.Compile([]byte(orgYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(org): %+v", errs)
	}
	repoWeaken, errs := engine.Compile([]byte(repoWeakenYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(repoWeaken): %+v", errs)
	}
	repoTighten, errs := engine.Compile([]byte(repoTightenYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(repoTighten): %+v", errs)
	}

	// 1. Omitted `overridable` in ORG defaults to false -> cannot be weakened.
	res1, err := engine.ComposeAndEvaluate(context.Background(), org, repoWeaken, policy.StageEgress, map[string]any{
		"findings": map[string]any{"prohibited_licenses": 1},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(1): %v", err)
	}
	if res1.Effect != domain.PolicyEffectDeny {
		t.Fatalf("effect=%s, want DENY", res1.Effect)
	}

	// 2. Even overridable: true ORG rule cannot be weakened to ALLOW.
	res2, err := engine.ComposeAndEvaluate(context.Background(), org, repoWeaken, policy.StageEgress, map[string]any{
		"change": map[string]any{"paths": []string{"api/openapi.yaml"}},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(2): %v", err)
	}
	if res2.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("effect=%s, want REQUIRE_APPROVAL (repo cannot weaken overridable org rule)", res2.Effect)
	}

	// 3. Overridable: true ORG rule CAN be replaced/tightened with >= rank.
	res3, err := engine.ComposeAndEvaluate(context.Background(), org, repoTighten, policy.StageEgress, map[string]any{
		"change": map[string]any{"paths": []string{"api/openapi.yaml"}},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(3): %v", err)
	}
	if res3.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("effect=%s, want REQUIRE_APPROVAL", res3.Effect)
	}
	if len(res3.Obligations) != 1 || res3.Obligations[0].ReviewerGroup != "api-security-board" || res3.Obligations[0].Minimum != 2 {
		t.Fatalf("expected tightened repo obligation to replace overridable org rule, got %+v", res3.Obligations)
	}
}
