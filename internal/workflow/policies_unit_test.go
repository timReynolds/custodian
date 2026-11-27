package workflow

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
)

func compileTestBundleEntry(t *testing.T, engine *policy.Engine, yamlBytes []byte, id uuid.UUID, scope domain.PolicyScope) persistedCompiledBundle {
	t.Helper()
	compiled, errs := engine.Compile(yamlBytes)
	if len(errs) > 0 {
		t.Fatalf("Compile bundle: %+v", errs)
	}
	return persistedCompiledBundle{
		row: persistence.PolicyBundleRow{
			ID:      id,
			Name:    compiled.Bundle.Metadata.Name,
			Version: compiled.Bundle.Metadata.Version,
			Scope:   scope,
			Digest:  compiled.Digest,
		},
		compiled: compiled,
	}
}

func loadDefaultsForUnitTest(t *testing.T, engine *policy.Engine) (defaultEntry, pushEntry persistedCompiledBundle) {
	t.Helper()
	defaultBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "default.yaml"))
	if err != nil {
		t.Fatalf("read default.yaml: %v", err)
	}
	pushBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	return compileTestBundleEntry(t, engine, defaultBytes, domain.MustNewID(), domain.PolicyScopeOrg),
		compileTestBundleEntry(t, engine, pushBytes, domain.MustNewID(), domain.PolicyScopeOrg)
}

func TestStageFiltering_ComposeInspectionConfigExcludesPushOnlyBundles(t *testing.T) {
	t.Parallel()

	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defaultEntry, pushEntry := loadDefaultsForUnitTest(t, engine)

	pushCustomYAML := []byte(`apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: push-custom-org
  version: "1.0.0"
  scope: ORG
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory:
    - push_only_scanner
  decisionModel:
    route: push-only-route
    trigger:
      - push_only_trigger
rules:
  - id: push.custom.deny
    stages: [PUSH_EGRESS]
    when: findings.critical_secrets > 0
    effect: DENY
`)
	pushCustomEntry := compileTestBundleEntry(t, engine, pushCustomYAML, domain.MustNewID(), domain.PolicyScopeOrg)

	// Place PUSH_EGRESS-only bundles BEFORE engineering-default (matching ListActivePolicyBundlesByScope order).
	orgBundles := []persistedCompiledBundle{pushCustomEntry, pushEntry, defaultEntry}

	for _, stage := range []string{policy.StageIngress, policy.StageEgress} {
		cfg := composeInspectionConfigForStage(stage, orgBundles, nil)
		if slices.Contains(cfg.Mandatory, "push_only_scanner") {
			t.Fatalf("%s inspection mandatory leaked push_only_scanner: %v", stage, cfg.Mandatory)
		}
		if cfg.DecisionModel == nil {
			t.Fatalf("%s expected DecisionModel from engineering-default", stage)
		}
		if cfg.DecisionModel.Route != "approved-code-review" {
			t.Fatalf("%s expected route approved-code-review, got %q", stage, cfg.DecisionModel.Route)
		}
		if slices.Contains(cfg.DecisionModel.Trigger, "concealment_finding") || slices.Contains(cfg.DecisionModel.Trigger, "push_only_trigger") {
			t.Fatalf("%s decisionModel triggers leaked PUSH_EGRESS triggers: %v", stage, cfg.DecisionModel.Trigger)
		}
	}

	pushCfg := composeInspectionConfigForStage(policy.StagePushEgress, orgBundles, nil)
	if !slices.Contains(pushCfg.Mandatory, "push_only_scanner") {
		t.Fatalf("PUSH_EGRESS should retain push_only_scanner, got %v", pushCfg.Mandatory)
	}
	if pushCfg.DecisionModel == nil || !slices.Contains(pushCfg.DecisionModel.Trigger, "concealment_finding") {
		t.Fatalf("PUSH_EGRESS should include concealment_finding trigger, got %+v", pushCfg.DecisionModel)
	}
}

func TestStageFiltering_ResolveEvaluationModelRouteIgnoresPushOnlyOrgBundle(t *testing.T) {
	t.Parallel()

	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defaultEntry, _ := loadDefaultsForUnitTest(t, engine)

	pushOnlyOrgYAML := []byte(`apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: push-only-route-org
  version: "1.0.0"
  scope: ORG
defaults:
  effect: DENY
  onError: DENY
inspection:
  decisionModel:
    route: push-only-route
rules:
  - id: push.only.rule
    stages: [PUSH_EGRESS]
    when: findings.critical_secrets > 0
    effect: DENY
`)
	pushOnlyEntry := compileTestBundleEntry(t, engine, pushOnlyOrgYAML, domain.MustNewID(), domain.PolicyScopeOrg)

	// PUSH_EGRESS-only ORG bundle sits at orgBundles[0] ahead of engineering-default.
	orgBundles := []persistedCompiledBundle{pushOnlyEntry, defaultEntry}
	inspCfg := composeInspectionConfigForStage(policy.StageEgress, orgBundles, nil)

	route := resolveEvaluationModelRoute("", []string{"approved-code-review", "push-only-route"}, orgBundles, nil, inspCfg)
	if route != "approved-code-review" {
		t.Fatalf("expected approved-code-review (ignoring PUSH_EGRESS-only ORG bundle), got %q", route)
	}
}

func TestStageFiltering_EvaluateComposedBundlesIsolationAndFallback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	svc := &Service{policyEngine: engine}
	defaultEntry, pushEntry := loadDefaultsForUnitTest(t, engine)

	// 1. With push-ip-protection at orgBundles[0] and engineering-default at orgBundles[1],
	// INGRESS/EGRESS must evaluate only engineering-default (preserving Digest & BundleID).
	orgBundles := []persistedCompiledBundle{pushEntry, defaultEntry}

	ingressOut, err := svc.evaluateComposedBundles(ctx, orgBundles, nil, policy.StageIngress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
	})
	if err != nil {
		t.Fatalf("evaluateComposedBundles(INGRESS): %v", err)
	}
	if ingressOut.result.Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected ALLOW on clean INGRESS, got %s", ingressOut.result.Effect)
	}
	if ingressOut.primaryBundleID != defaultEntry.row.ID {
		t.Fatalf("expected primaryBundleID=%s (engineering-default), got %s", defaultEntry.row.ID, ingressOut.primaryBundleID)
	}
	if ingressOut.orgBundleID == nil || *ingressOut.orgBundleID != defaultEntry.row.ID {
		t.Fatalf("expected orgBundleID=%s, got %v", defaultEntry.row.ID, ingressOut.orgBundleID)
	}
	if ingressOut.result.BundleDigest != defaultEntry.compiled.Digest {
		t.Fatalf("expected unpolluted BundleDigest=%s, got %s", defaultEntry.compiled.Digest, ingressOut.result.BundleDigest)
	}

	egressOut, err := svc.evaluateComposedBundles(ctx, orgBundles, nil, policy.StageEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: "COMPLETE", Disposition: "CLEAR", IPRisk: "NONE"},
	})
	if err != nil {
		t.Fatalf("evaluateComposedBundles(EGRESS): %v", err)
	}
	if egressOut.result.Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected ALLOW on clean EGRESS, got %s", egressOut.result.Effect)
	}
	if egressOut.primaryBundleID != defaultEntry.row.ID {
		t.Fatalf("expected EGRESS primaryBundleID=%s, got %s", defaultEntry.row.ID, egressOut.primaryBundleID)
	}

	// 2. A custom EGRESS ORG bundle with defaults.effect: ALLOW and non-matching rules must not
	// be polluted by push-ip-protection's defaults.effect: DENY.
	allowDefaultEgressYAML := []byte(`apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: egress-allow-default
  version: "1.0.0"
  scope: ORG
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: egress.secrets.block
    stages: [EGRESS]
    when: findings.critical_secrets > 0
    effect: DENY
`)
	allowDefaultEntry := compileTestBundleEntry(t, engine, allowDefaultEgressYAML, domain.MustNewID(), domain.PolicyScopeOrg)
	allowOut, err := svc.evaluateComposedBundles(ctx, []persistedCompiledBundle{pushEntry, allowDefaultEntry}, nil, policy.StageEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
	})
	if err != nil {
		t.Fatalf("evaluateComposedBundles(ALLOW default): %v", err)
	}
	if allowOut.result.Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected ALLOW when only stage-applicable bundle defaults to ALLOW, got %s", allowOut.result.Effect)
	}

	// 3. When ZERO bundles apply to the requested stage, preserve fail-closed fallback with non-nil primaryBundleID.
	fallbackOut, err := svc.evaluateComposedBundles(ctx, []persistedCompiledBundle{pushEntry}, nil, policy.StageEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
	})
	if err != nil {
		t.Fatalf("evaluateComposedBundles(fallback): %v", err)
	}
	if fallbackOut.result.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected fail-closed DENY fallback when zero bundles apply to EGRESS, got %s", fallbackOut.result.Effect)
	}
	if fallbackOut.primaryBundleID != pushEntry.row.ID {
		t.Fatalf("expected non-nil fallback primaryBundleID=%s, got %s", pushEntry.row.ID, fallbackOut.primaryBundleID)
	}
}
