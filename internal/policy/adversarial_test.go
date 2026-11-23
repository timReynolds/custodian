package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/policy"
)

// ADV-08 & RG-05: A clean/CLEAR Stage B model assessment must never override Stage A deterministic denials.
func TestAdversarial_ADV08_ModelClearCannotOverrideStageADenials(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defaultBundle, err := engine.LoadBundleFile("../../policies/defaults/default.yaml")
	if err != nil {
		t.Fatalf("LoadBundleFile(default.yaml): %v", err)
	}

	cases := []struct {
		name       string
		findings   map[string]any
		wantEffect domain.PolicyEffect
		wantRule   string
	}{
		{
			name: "secret_overrides_clear_model",
			findings: map[string]any{
				"scan_complete":       true,
				"critical_secrets":    1,
				"prohibited_licenses": 0,
			},
			wantEffect: domain.PolicyEffectDeny,
			wantRule:   "secrets.block",
		},
		{
			name: "prohibited_license_overrides_clear_model",
			findings: map[string]any{
				"scan_complete":       true,
				"critical_secrets":    0,
				"prohibited_licenses": 1,
			},
			wantEffect: domain.PolicyEffectDeny,
			wantRule:   "licenses.block",
		},
		{
			name: "incomplete_scan_overrides_clear_model",
			findings: map[string]any{
				"scan_complete":       false,
				"critical_secrets":    0,
				"prohibited_licenses": 0,
			},
			wantEffect: domain.PolicyEffectQuarantine,
			wantRule:   "scan.incomplete",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := engine.Evaluate(context.Background(), defaultBundle, policy.StageEgress, map[string]any{
				"findings": tc.findings,
				"assessment": map[string]any{
					"status":      "COMPLETE",
					"disposition": "CLEAR",
					"risk":        "NONE",
					"ip_risk":     "NONE",
				},
				"change": map[string]any{
					"paths": []string{"main.go"},
				},
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if res.Effect != tc.wantEffect {
				t.Fatalf("effect=%s, want %s", res.Effect, tc.wantEffect)
			}
			if !res.Effect.BlocksPublication() {
				t.Fatalf("expected blocking effect")
			}
			if policy.RequiresHumanApproval(res) {
				t.Fatalf("blocked evaluation must not be approvable")
			}
			var found bool
			for _, id := range res.MatchedRuleIDs {
				if id == tc.wantRule {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q in %v", tc.wantRule, res.MatchedRuleIDs)
			}
		})
	}
}

// ADV-09 & RG-05: Every CEL runtime evaluation error (OOB, div-by-zero, missing map key,
// cost limit exceeded, canceled context) must fail closed to DENY even with defaults.effect: ALLOW.
func TestAdversarial_ADV09_CELRuntimeErrorsFailClosedToDeny(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// 1. E2E fixture: OOB index + division by zero.
	rtBundle := loadFixtureBundle(t, engine, "runtime_cel_error_fail_closed.yaml")
	res, err := engine.Evaluate(context.Background(), rtBundle, policy.StageEgress, map[string]any{
		"findings": map[string]any{
			"critical_secrets":    0,
			"prohibited_licenses": 0,
			"scan_complete":       true,
		},
		"change": map[string]any{
			"paths": []string{"main.go"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate(runtime fixture): %v", err)
	}
	if res.Effect != domain.PolicyEffectDeny || !res.HadError {
		t.Fatalf("expected fail-closed DENY with HadError=true, got %+v", res)
	}
	var traceErrors int
	for _, rt := range res.RuleTrace {
		if rt.Error != "" {
			traceErrors++
		}
	}
	if traceErrors != 2 {
		t.Fatalf("expected 2 trace errors (oob + divzero), got %d (%+v)", traceErrors, res.RuleTrace)
	}

	// 2. Missing map key fails closed even when a sibling ALLOW rule matches.
	missingKeyYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: missing-key-fail-closed
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: sibling.allow
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
  - id: missing.map.key
    stages: [EGRESS]
    when: findings.counts_by_category["nonexistent"] > 0
    effect: ALLOW
`
	mkBundle, errs := engine.Compile([]byte(missingKeyYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(missingKey): %+v", errs)
	}
	mkRes, err := engine.Evaluate(context.Background(), mkBundle, policy.StageEgress, map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate(missingKey): %v", err)
	}
	if mkRes.Effect != domain.PolicyEffectDeny || !mkRes.HadError {
		t.Fatalf("missing map key must fail closed to DENY, got %+v", mkRes)
	}

	// 2b. Missing unknown flag key fails closed even when other flags are provided.
	unknownFlagYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: unknown-flag-fail-closed
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: unknown.flag
    stages: [EGRESS]
    when: flags.unknown_flag == true
    effect: ALLOW
`
	ufBundle, errs := engine.Compile([]byte(unknownFlagYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(unknownFlag): %+v", errs)
	}
	ufRes, err := engine.Evaluate(context.Background(), ufBundle, policy.StageEgress, map[string]any{
		"flags": map[string]bool{"allow": true},
	})
	if err != nil {
		t.Fatalf("Evaluate(unknownFlag): %v", err)
	}
	if ufRes.Effect != domain.PolicyEffectDeny || !ufRes.HadError {
		t.Fatalf("unknown flag key must fail closed to DENY, got %+v", ufRes)
	}

	// 3. Cost limit exceeded fails closed to DENY.
	tightEngine, err := policy.NewEngine(policy.WithCostLimit(5))
	if err != nil {
		t.Fatalf("NewEngine(costLimit=5): %v", err)
	}
	expensiveYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: cost-limit-test
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: expensive.comprehension
    stages: [EGRESS]
    when: '[1,2,3,4,5,6,7,8,9,10].all(x, [1,2,3,4,5,6,7,8,9,10].all(y, x + y > 0))'
    effect: ALLOW
`
	expBundle, errs := tightEngine.Compile([]byte(expensiveYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(expensive): %+v", errs)
	}
	costRes, err := tightEngine.Evaluate(context.Background(), expBundle, policy.StageEgress, map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate(cost): %v", err)
	}
	if costRes.Effect != domain.PolicyEffectDeny || !costRes.HadError {
		t.Fatalf("cost limit exceeded must fail closed to DENY, got %+v", costRes)
	}

	// 4. Canceled context fails closed to DENY.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelRes, err := engine.Evaluate(canceledCtx, mkBundle, policy.StageEgress, map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate(canceled): %v", err)
	}
	if cancelRes.Effect != domain.PolicyEffectDeny || !cancelRes.HadError {
		t.Fatalf("canceled context must fail closed to DENY, got %+v", cancelRes)
	}

	// 5. Nil bundle fails closed to DENY.
	nilRes, err := engine.Evaluate(context.Background(), nil, policy.StageEgress, map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate(nil): %v", err)
	}
	if nilRes.Effect != domain.PolicyEffectDeny || !nilRes.HadError {
		t.Fatalf("nil bundle must fail closed to DENY, got %+v", nilRes)
	}
}

func TestAdversarial_WrongInputTypesRejected(t *testing.T) {
	_, err := policy.PolicyInputFromMap(policy.StageEgress, map[string]any{
		"findings": map[string]any{
			"critical_secrets": "zero",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "INVALID_POLICY_INPUT") {
		t.Fatalf("expected INVALID_POLICY_INPUT on wrong type, got %v", err)
	}
}

// RG-05: Stage B blocking dispositions (BLOCK, INDETERMINATE) must fail closed on EGRESS
// across default, org_baseline, restricted_ip_repo, and composed org+repo bundles,
// even when Stage A deterministic scans are clean and permissive repo ALLOW rules match.
func TestAdversarial_RG05_StageBBlockingDispositionsCannotFailOpen(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	defaultBundle, err := engine.LoadBundleFile("../../policies/defaults/default.yaml")
	if err != nil {
		t.Fatalf("LoadBundleFile(default.yaml): %v", err)
	}
	orgBaseline, err := engine.LoadBundleFile("../../policies/examples/org_baseline.yaml")
	if err != nil {
		t.Fatalf("LoadBundleFile(org_baseline.yaml): %v", err)
	}
	restrictedIP, err := engine.LoadBundleFile("../../policies/examples/restricted_ip_repo.yaml")
	if err != nil {
		t.Fatalf("LoadBundleFile(restricted_ip_repo.yaml): %v", err)
	}
	repoStrict, err := engine.LoadBundleFile("../../policies/examples/repo_strict_security.yaml")
	if err != nil {
		t.Fatalf("LoadBundleFile(repo_strict_security.yaml): %v", err)
	}

	permissiveRepoYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: adversarial-permissive-repo
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: org.model.block
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
    overridable: true
  - id: org.model.indeterminate
    stages: [EGRESS]
    when: "true"
    effect: ALLOW
    overridable: true
  - id: repo.allow.all
    stages: [INGRESS, EGRESS]
    when: "true"
    effect: ALLOW
`
	permissiveRepo, errs := engine.Compile([]byte(permissiveRepoYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(permissiveRepo): %+v", errs)
	}

	type target struct {
		name     string
		evalFn   func(input any) (policy.EvalResult, error)
		blockID  string
		indetID  string
		allowIng bool
	}
	targets := []target{
		{
			name: "policies/defaults/default.yaml",
			evalFn: func(input any) (policy.EvalResult, error) {
				return engine.Evaluate(context.Background(), defaultBundle, policy.StageEgress, input)
			},
			blockID:  "model.block",
			indetID:  "model.indeterminate",
			allowIng: true,
		},
		{
			name: "policies/examples/org_baseline.yaml",
			evalFn: func(input any) (policy.EvalResult, error) {
				return engine.Evaluate(context.Background(), orgBaseline, policy.StageEgress, input)
			},
			blockID: "org.model.block",
			indetID: "org.model.indeterminate",
		},
		{
			name: "policies/examples/restricted_ip_repo.yaml",
			evalFn: func(input any) (policy.EvalResult, error) {
				return engine.Evaluate(context.Background(), restrictedIP, policy.StageEgress, input)
			},
			blockID:  "restricted.model.block",
			indetID:  "restricted.model.indeterminate",
			allowIng: true,
		},
		{
			name: "ComposeAndEvaluate(org_baseline, repo_strict_security)",
			evalFn: func(input any) (policy.EvalResult, error) {
				return engine.ComposeAndEvaluate(context.Background(), orgBaseline, repoStrict, policy.StageEgress, input)
			},
			blockID: "org.model.block",
			indetID: "org.model.indeterminate",
		},
		{
			name: "ComposeAndEvaluate(org_baseline, adversarial_permissive_repo)",
			evalFn: func(input any) (policy.EvalResult, error) {
				return engine.ComposeAndEvaluate(context.Background(), orgBaseline, permissiveRepo, policy.StageEgress, input)
			},
			blockID: "org.model.block",
			indetID: "org.model.indeterminate",
		},
	}

	scenarios := []struct {
		name       string
		assessment map[string]any
		wantEffect domain.PolicyEffect
		wantRuleFn func(target) string
	}{
		{
			name: "complete_block_code_review_ip_risk_none",
			assessment: map[string]any{
				"status":          "COMPLETE",
				"disposition":     "BLOCK",
				"risk":            "CRITICAL",
				"ip_risk":         "NONE",
				"assessment_type": "CODE_REVIEW",
			},
			wantEffect: domain.PolicyEffectDeny,
			wantRuleFn: func(tg target) string { return tg.blockID },
		},
		{
			name: "complete_block_ip_provenance_ip_risk_critical",
			assessment: map[string]any{
				"status":          "COMPLETE",
				"disposition":     "BLOCK",
				"risk":            "CRITICAL",
				"ip_risk":         "CRITICAL",
				"assessment_type": "IP_PROVENANCE",
			},
			wantEffect: domain.PolicyEffectDeny,
			wantRuleFn: func(tg target) string { return tg.blockID },
		},
		{
			name: "complete_indeterminate_disposition",
			assessment: map[string]any{
				"status":      "COMPLETE",
				"disposition": "INDETERMINATE",
				"risk":        "NONE",
				"ip_risk":     "NONE",
			},
			wantEffect: domain.PolicyEffectQuarantine,
			wantRuleFn: func(tg target) string { return tg.indetID },
		},
	}

	for _, tg := range targets {
		for _, sc := range scenarios {
			t.Run(tg.name+"/"+sc.name, func(t *testing.T) {
				res, err := tg.evalFn(map[string]any{
					"findings": map[string]any{
						"scan_complete":       true,
						"critical_secrets":    0,
						"prohibited_licenses": 0,
					},
					"assessment": sc.assessment,
					"change": map[string]any{
						"paths": []string{"auth/handler.go"},
					},
				})
				if err != nil {
					t.Fatalf("Evaluate: %v", err)
				}
				if res.Effect != sc.wantEffect {
					t.Fatalf("effect=%s, want %s (matched=%v)", res.Effect, sc.wantEffect, res.MatchedRuleIDs)
				}
				if !res.Effect.BlocksPublication() {
					t.Fatalf("expected BlocksPublication() == true for effect %s", res.Effect)
				}
				if policy.RequiresHumanApproval(res) {
					t.Fatalf("blocked evaluation must not be approvable")
				}
				if len(res.Obligations) != 0 {
					t.Fatalf("blocked evaluation must clear obligations, got %+v", res.Obligations)
				}
				wantRule := sc.wantRuleFn(tg)
				var matched bool
				for _, id := range res.MatchedRuleIDs {
					if id == wantRule {
						matched = true
						break
					}
				}
				if !matched {
					t.Fatalf("expected rule %q in %v", wantRule, res.MatchedRuleIDs)
				}
			})
		}
	}

	// Verify clean INGRESS with empty assessment is unaffected for default and restricted_ip_repo.
	cleanIngressInput := map[string]any{
		"findings": map[string]any{
			"scan_complete":       true,
			"critical_secrets":    0,
			"prohibited_licenses": 0,
		},
	}
	for _, b := range []*policy.CompiledBundle{defaultBundle, restrictedIP} {
		res, err := engine.Evaluate(context.Background(), b, policy.StageIngress, cleanIngressInput)
		if err != nil {
			t.Fatalf("Evaluate(INGRESS, %s): %v", b.Bundle.Metadata.Name, err)
		}
		if res.Effect != domain.PolicyEffectAllow {
			t.Fatalf("clean INGRESS for %s got %s, want ALLOW", b.Bundle.Metadata.Name, res.Effect)
		}
	}
}
