package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/policy"
)

func TestPushEgressStageAndInputCompatibility(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if !policy.IsValidStage(policy.StagePushEgress) {
		t.Fatal("expected StagePushEgress to be valid")
	}
	if policy.IsValidStage("BOGUS") {
		t.Fatal("expected BOGUS stage to be invalid")
	}

	// Verify v1.0 default.yaml still evaluates INGRESS/EGRESS identically when destination/push are omitted.
	defaultBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "default.yaml"))
	if err != nil {
		t.Fatalf("read default.yaml: %v", err)
	}
	defaultBundle, errs := engine.Compile(defaultBytes)
	if len(errs) > 0 {
		t.Fatalf("Compile(default.yaml): %+v", errs)
	}

	in, err := policy.PolicyInputFromMap(policy.StageEgress, map[string]any{
		"findings": map[string]any{"scan_complete": true},
		"assessment": map[string]any{
			"status":      "COMPLETE",
			"disposition": "CLEAR",
			"ip_risk":     "NONE",
		},
	})
	if err != nil {
		t.Fatalf("PolicyInputFromMap: %v", err)
	}
	if in.Push.RefNames == nil {
		t.Fatal("expected in.Push.RefNames to be initialized non-nil")
	}

	egressRes, err := engine.Evaluate(ctx, defaultBundle, policy.StageEgress, map[string]any{
		"findings":   map[string]any{"scan_complete": true},
		"assessment": map[string]any{"status": "COMPLETE", "ip_risk": "NONE"},
	})
	if err != nil {
		t.Fatalf("Evaluate(EGRESS): %v", err)
	}
	if egressRes.Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected ALLOW for clean EGRESS, got %s", egressRes.Effect)
	}

	ingressRes, err := engine.Evaluate(ctx, defaultBundle, policy.StageIngress, map[string]any{
		"findings": map[string]any{"scan_complete": true},
	})
	if err != nil {
		t.Fatalf("Evaluate(INGRESS): %v", err)
	}
	if ingressRes.Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected ALLOW for clean INGRESS, got %s", ingressRes.Effect)
	}
}

func TestPushLFSAndOverridableEnforcement(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pushBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	orgBundle, errs := engine.Compile(pushBytes)
	if len(errs) > 0 {
		t.Fatalf("Compile(push-ip-protection.yaml): %+v", errs)
	}
	if orgBundle.Bundle.Inspection == nil {
		t.Fatal("expected inspection config on push-ip-protection.yaml")
	}
	for _, m := range orgBundle.Bundle.Inspection.Mandatory {
		if m == "ip_fingerprint" {
			t.Fatal("push-ip-protection.yaml must NOT include ip_fingerprint in inspection.mandatory")
		}
	}

	// Custom REPO bundle exercising push.has_lfs and attempting to weaken non-overridable restricted IP rule.
	repoYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-push-lfs
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: push.lfs.review
    stages: [PUSH_EGRESS]
    when: push.has_lfs && push.lfs_total_bytes > 0
    effect: REQUIRE_APPROVAL
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: lfs-review
        minimum: 1
  - id: push.ip.restricted.block
    stages: [PUSH_EGRESS]
    when: findings.restricted_ip_matches > 0
    effect: ALLOW
`
	repoBundle, repoErrs := engine.Compile([]byte(repoYAML))
	if len(repoErrs) > 0 {
		t.Fatalf("Compile(repo-push-lfs): %+v", repoErrs)
	}

	// 1. Clean internal push with LFS triggers REQUIRE_APPROVAL via push.has_lfs.
	lfsRes, err := engine.ComposeAndEvaluate(ctx, orgBundle, repoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: "NOT_REQUIRED", Disposition: "NOT_REQUIRED"},
		Destination: policy.DestinationInput{
			Host:       "github.com",
			Name:       "acme/assets",
			Registered: true,
			External:   false,
		},
		Push: policy.PushInput{
			HasLFS:         true,
			LFSObjectCount: 1,
			LFSTotalBytes:  1024,
			RefNames:       []string{"refs/heads/main"},
			CommitCount:    1,
			EgressMode:     "ENFORCE_BLOCK",
		},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(LFS): %v", err)
	}
	if lfsRes.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL for push.has_lfs, got %s", lfsRes.Effect)
	}

	// 2. Non-overridable restricted IP match cannot be weakened to ALLOW by REPO rule.
	restrictedRes, err := engine.ComposeAndEvaluate(ctx, orgBundle, repoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true, RestrictedIPMatches: 1},
		Assessment: policy.AssessmentInput{Status: "NOT_REQUIRED", Disposition: "NOT_REQUIRED"},
		Destination: policy.DestinationInput{
			Host:       "github.com",
			Name:       "acme/assets",
			Registered: true,
			External:   false,
		},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(restricted): %v", err)
	}
	if restrictedRes.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected non-overridable DENY for restricted IP, got %s", restrictedRes.Effect)
	}

	// 3. Empty/missing Stage B assessment fails closed to QUARANTINE.
	emptyAssessRes, err := engine.Evaluate(ctx, orgBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
		Destination: policy.DestinationInput{
			Registered: true,
			External:   false,
		},
	})
	if err != nil {
		t.Fatalf("Evaluate(empty assessment): %v", err)
	}
	if emptyAssessRes.Effect != domain.PolicyEffectQuarantine {
		t.Fatalf("expected QUARANTINE on empty assessment status, got %s", emptyAssessRes.Effect)
	}
}

func TestPushIPProtection_StageBReviewEscalateAndOverridable(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pushBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	orgBundle, errs := engine.Compile(pushBytes)
	if len(errs) > 0 {
		t.Fatalf("Compile(push-ip-protection.yaml): %+v", errs)
	}

	if len(orgBundle.Bundle.Rules) != 13 {
		t.Fatalf("expected 13 rules in push-ip-protection.yaml, got %d", len(orgBundle.Bundle.Rules))
	}

	seenRules := make(map[string]policy.Rule, len(orgBundle.Bundle.Rules))
	for _, r := range orgBundle.Bundle.Rules {
		seenRules[r.ID] = r
		switch r.ID {
		case "push.destination.unregistered_or_external":
			if r.Overridable == nil || !*r.Overridable {
				t.Fatalf("expected %s overridable=true, got %v", r.ID, r.Overridable)
			}
			if r.Effect != domain.PolicyEffectDeny {
				t.Fatalf("expected %s effect=DENY, got %s", r.ID, r.Effect)
			}
		case "push.allow":
			if r.Effect != domain.PolicyEffectAllow {
				t.Fatalf("expected push.allow effect=ALLOW, got %s", r.Effect)
			}
		default:
			if r.Overridable == nil || *r.Overridable {
				t.Fatalf("expected blocking/review rule %s overridable=false, got %v", r.ID, r.Overridable)
			}
		}
	}
	for _, requiredID := range []string{"push.ip.review", "push.model.review"} {
		if _, ok := seenRules[requiredID]; !ok {
			t.Fatalf("missing expected rule %q", requiredID)
		}
	}

	maliciousRepoYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-override-attempt
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: push.ip.review
    stages: [PUSH_EGRESS]
    when: "true"
    effect: ALLOW
  - id: push.model.review
    stages: [PUSH_EGRESS]
    when: "true"
    effect: ALLOW
  - id: push.model.indeterminate
    stages: [PUSH_EGRESS]
    when: "true"
    effect: ALLOW
  - id: push.destination.unregistered_or_external
    stages: [PUSH_EGRESS]
    when: "true"
    effect: REQUIRE_APPROVAL
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: repo-admins
        minimum: 1
  - id: repo.blanket.allow
    stages: [PUSH_EGRESS]
    when: "true"
    effect: ALLOW
`
	maliciousRepoBundle, repoErrs := engine.Compile([]byte(maliciousRepoYAML))
	if len(repoErrs) > 0 {
		t.Fatalf("Compile(maliciousRepoYAML): %+v", repoErrs)
	}

	internalDest := policy.DestinationInput{
		Host:       "github.com",
		Name:       "acme/app",
		Registered: true,
		External:   false,
	}

	hasGroup := func(obs []domain.Obligation, group string) bool {
		for _, o := range obs {
			if o.ReviewerGroup == group {
				return true
			}
		}
		return false
	}

	// 1. IP_PROVENANCE + COMPLETE + REVIEW (MEDIUM) -> REQUIRE_APPROVAL (ip-review & security-team).
	res, err := engine.ComposeAndEvaluate(ctx, orgBundle, maliciousRepoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{
			Status:         "COMPLETE",
			Disposition:    "REVIEW",
			Risk:           "MEDIUM",
			IPRisk:         "MEDIUM",
			AssessmentType: "IP_PROVENANCE",
		},
		Destination: internalDest,
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(IP_PROVENANCE REVIEW MEDIUM): %v", err)
	}
	if res.Effect != domain.PolicyEffectRequireApproval || !hasGroup(res.Obligations, "ip-review") || !hasGroup(res.Obligations, "security-team") {
		t.Fatalf("unexpected outcome for IP_PROVENANCE REVIEW MEDIUM: effect=%s obs=%+v", res.Effect, res.Obligations)
	}

	// 2. IP_PROVENANCE + COMPLETE + REVIEW (LOW) -> REQUIRE_APPROVAL.
	res, err = engine.ComposeAndEvaluate(ctx, orgBundle, maliciousRepoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{
			Status:         "COMPLETE",
			Disposition:    "REVIEW",
			Risk:           "LOW",
			IPRisk:         "LOW",
			AssessmentType: "IP_PROVENANCE",
		},
		Destination: internalDest,
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(IP_PROVENANCE REVIEW LOW): %v", err)
	}
	if res.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL for IP_PROVENANCE REVIEW LOW, got %s", res.Effect)
	}

	// 3. SECURITY_REVIEW + COMPLETE + ESCALATE (HIGH) -> REQUIRE_APPROVAL (security-team).
	res, err = engine.ComposeAndEvaluate(ctx, orgBundle, maliciousRepoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{
			Status:         "COMPLETE",
			Disposition:    "ESCALATE",
			Risk:           "HIGH",
			IPRisk:         "NONE",
			AssessmentType: "SECURITY_REVIEW",
		},
		Destination: internalDest,
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(SECURITY_REVIEW ESCALATE HIGH): %v", err)
	}
	if res.Effect != domain.PolicyEffectRequireApproval || !hasGroup(res.Obligations, "security-team") {
		t.Fatalf("unexpected outcome for SECURITY_REVIEW ESCALATE HIGH: effect=%s obs=%+v", res.Effect, res.Obligations)
	}

	// 4. SECURITY_REVIEW + COMPLETE + ESCALATE (CRITICAL) -> REQUIRE_APPROVAL.
	res, err = engine.ComposeAndEvaluate(ctx, orgBundle, maliciousRepoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{
			Status:         "COMPLETE",
			Disposition:    "ESCALATE",
			Risk:           "CRITICAL",
			IPRisk:         "NONE",
			AssessmentType: "SECURITY_REVIEW",
		},
		Destination: internalDest,
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(SECURITY_REVIEW ESCALATE CRITICAL): %v", err)
	}
	if res.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("expected REQUIRE_APPROVAL for SECURITY_REVIEW ESCALATE CRITICAL, got %s", res.Effect)
	}

	// 5. COMPLETE + NOT_REQUIRED -> QUARANTINE (REPO ALLOW ignored; obligations empty).
	res, err = engine.ComposeAndEvaluate(ctx, orgBundle, maliciousRepoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{
			Status:      "COMPLETE",
			Disposition: "NOT_REQUIRED",
			IPRisk:      "NONE",
		},
		Destination: internalDest,
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(COMPLETE NOT_REQUIRED): %v", err)
	}
	if res.Effect != domain.PolicyEffectQuarantine || len(res.Obligations) != 0 {
		t.Fatalf("expected QUARANTINE with empty obligations, got effect=%s obs=%+v", res.Effect, res.Obligations)
	}

	// 6. destination.external: true -> DENY (REPO cannot weaken DENY Rank 5).
	res, err = engine.ComposeAndEvaluate(ctx, orgBundle, maliciousRepoBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: "NOT_REQUIRED", Disposition: "NOT_REQUIRED"},
		Destination: policy.DestinationInput{
			Host:       "git.partner.example",
			Name:       "partner/mirror",
			Registered: true,
			External:   true,
		},
	})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(external dest): %v", err)
	}
	if res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected DENY for external destination even with REPO override attempt, got %s", res.Effect)
	}

	// 7. Verify ORG-level CEL customization works as documented.
	customOrgYAML := string(pushBytes)
	customOrgYAML = strings.Replace(customOrgYAML,
		`when: "!destination.registered || destination.external"`,
		`when: "!destination.registered || (destination.external && destination.host != \"git.partner.example\")"`,
		1)
	customOrgYAML = strings.Replace(customOrgYAML,
		"!destination.external &&",
		`(!destination.external || destination.host == "git.partner.example") &&`,
		1)
	customOrgBundle, customErrs := engine.Compile([]byte(customOrgYAML))
	if len(customErrs) > 0 {
		t.Fatalf("Compile(customOrgYAML): %+v", customErrs)
	}

	// Registered partner mirror allowed when clean.
	res, err = engine.Evaluate(ctx, customOrgBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: "NOT_REQUIRED", Disposition: "NOT_REQUIRED"},
		Destination: policy.DestinationInput{
			Host:       "git.partner.example",
			Name:       "partner/mirror",
			Registered: true,
			External:   true,
		},
	})
	if err != nil || res.Effect != domain.PolicyEffectAllow {
		t.Fatalf("expected ALLOW for ORG-exempted partner mirror, got (%s, %v)", res.Effect, err)
	}

	// Unapproved external host still denied.
	res, err = engine.Evaluate(ctx, customOrgBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: "NOT_REQUIRED", Disposition: "NOT_REQUIRED"},
		Destination: policy.DestinationInput{
			Host:       "evil.example",
			Name:       "evil/repo",
			Registered: true,
			External:   true,
		},
	})
	if err != nil || res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected DENY for unapproved external host, got (%s, %v)", res.Effect, err)
	}

	// Restricted IP still denied even to exempted partner mirror.
	res, err = engine.Evaluate(ctx, customOrgBundle, policy.StagePushEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true, RestrictedIPMatches: 1},
		Assessment: policy.AssessmentInput{Status: "NOT_REQUIRED", Disposition: "NOT_REQUIRED"},
		Destination: policy.DestinationInput{
			Host:       "git.partner.example",
			Name:       "partner/mirror",
			Registered: true,
			External:   true,
		},
	})
	if err != nil || res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected DENY for restricted IP to exempted partner mirror, got (%s, %v)", res.Effect, err)
	}
}

func TestPushIPProtection_ExhaustiveAssessmentMatrixAlignedWithDomain(t *testing.T) {
	ctx := context.Background()
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	pushBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	orgBundle, errs := engine.Compile(pushBytes)
	if len(errs) > 0 {
		t.Fatalf("Compile(push-ip-protection.yaml): %+v", errs)
	}

	statuses := []domain.AssessmentStatus{
		domain.AssessmentStatusPending,
		domain.AssessmentStatusComplete,
		domain.AssessmentStatusIndeterminate,
		domain.AssessmentStatusFailed,
		domain.AssessmentStatusNotRequired,
		"",
		"BOGUS",
	}
	dispositions := []domain.Disposition{
		domain.DispositionClear,
		domain.DispositionReview,
		domain.DispositionEscalate,
		domain.DispositionBlock,
		domain.DispositionIndeterminate,
		domain.DispositionNotRequired,
		"",
		"BOGUS",
	}

	for _, s := range statuses {
		for _, d := range dispositions {
			res, evalErr := engine.Evaluate(ctx, orgBundle, policy.StagePushEgress, policy.PolicyInput{
				Findings:    policy.FindingsInput{ScanComplete: true},
				Destination: policy.DestinationInput{Registered: true, External: false},
				Assessment: policy.AssessmentInput{
					Status:      string(s),
					Disposition: string(d),
					Risk:        "NONE",
					IPRisk:      "NONE",
				},
			})
			if evalErr != nil {
				t.Fatalf("Evaluate(%q, %q): %v", s, d, evalErr)
			}

			allows := (domain.ModelAssessment{Status: s, Disposition: d}).AllowsPushEgress()
			if !allows {
				want := domain.PolicyEffectQuarantine
				if d == domain.DispositionBlock {
					want = domain.PolicyEffectDeny
				}
				if res.Effect != want {
					t.Fatalf("status=%q disposition=%q AllowsPushEgress=false: want %s, got %s (matched=%v)", s, d, want, res.Effect, res.MatchedRuleIDs)
				}
				if !res.Effect.BlocksPublication() {
					t.Fatalf("status=%q disposition=%q expected BlocksPublication=true for %s", s, d, res.Effect)
				}
				if slices.Contains(res.MatchedRuleIDs, "push.allow") {
					t.Fatalf("status=%q disposition=%q unexpectedly matched push.allow", s, d)
				}
				continue
			}

			if s == domain.AssessmentStatusComplete && (d == domain.DispositionReview || d == domain.DispositionEscalate) {
				if res.Effect != domain.PolicyEffectRequireApproval {
					t.Fatalf("status=%q disposition=%q want REQUIRE_APPROVAL, got %s", s, d, res.Effect)
				}
				if slices.Contains(res.MatchedRuleIDs, "push.allow") {
					t.Fatalf("status=%q disposition=%q unexpectedly matched push.allow", s, d)
				}
				if len(res.Obligations) == 0 {
					t.Fatalf("status=%q disposition=%q expected non-empty obligations", s, d)
				}
			} else if res.Effect != domain.PolicyEffectAllow {
				t.Fatalf("status=%q disposition=%q AllowsPushEgress=true: want ALLOW, got %s (matched=%v)", s, d, res.Effect, res.MatchedRuleIDs)
			}
		}
	}
}
