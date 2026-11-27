package workflow

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/policy"
)

func TestSummaryToFindingsInputAndPushPolicyIntegration(t *testing.T) {
	t.Parallel()

	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	yamlBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "push-ip-protection.yaml"))
	if err != nil {
		t.Fatalf("read push-ip-protection.yaml: %v", err)
	}
	compiled, errs := engine.Compile(yamlBytes)
	if len(errs) > 0 {
		t.Fatalf("compile push-ip-protection.yaml: %+v", errs)
	}

	baseInput := func(summary inspection.InspectionSummary) policy.PolicyInput {
		return policy.PolicyInput{
			Stage:    policy.StagePushEgress,
			Findings: SummaryToFindingsInput(summary),
			Assessment: policy.AssessmentInput{
				Status:      "NOT_REQUIRED",
				IPRisk:      "NONE",
				Risk:        "NONE",
				Disposition: "NOT_REQUIRED",
			},
			Destination: policy.DestinationInput{
				ID:             "repo-1",
				Name:           "acme/app",
				Host:           "github.com",
				Registered:     true,
				External:       false,
				Classification: "INTERNAL",
			},
			Push: policy.PushInput{
				RefNames:   []string{"refs/heads/main"},
				EgressMode: "ENFORCE_BLOCK",
			},
		}
	}

	// 1. Clean internal push -> ALLOW.
	resClean, err := engine.Evaluate(context.Background(), compiled, policy.StagePushEgress, baseInput(inspection.InspectionSummary{
		MandatoryScannersComplete: true,
		ScanComplete:              true,
	}))
	if err != nil || resClean.Effect != domain.PolicyEffectAllow {
		t.Fatalf("clean push expected ALLOW, got effect=%s err=%v", resClean.Effect, err)
	}

	// 2. Restricted IP match -> DENY.
	resRest, err := engine.Evaluate(context.Background(), compiled, policy.StagePushEgress, baseInput(inspection.InspectionSummary{
		MandatoryScannersComplete: true,
		ScanComplete:              true,
		IPExactMatches:            1,
		RestrictedIPMatches:       1,
	}))
	if err != nil || resRest.Effect != domain.PolicyEffectDeny {
		t.Fatalf("restricted IP expected DENY, got effect=%s err=%v", resRest.Effect, err)
	}

	// 3. Stripped header -> DENY.
	resStrip, err := engine.Evaluate(context.Background(), compiled, policy.StagePushEgress, baseInput(inspection.InspectionSummary{
		MandatoryScannersComplete: true,
		ScanComplete:              true,
		IPWinnowMatches:           1,
		IPHeaderStripMatches:      1,
	}))
	if err != nil || resStrip.Effect != domain.PolicyEffectDeny {
		t.Fatalf("header strip expected DENY, got effect=%s err=%v", resStrip.Effect, err)
	}

	// 4. Concealment finding -> QUARANTINE.
	resConc, err := engine.Evaluate(context.Background(), compiled, policy.StagePushEgress, baseInput(inspection.InspectionSummary{
		MandatoryScannersComplete: true,
		ScanComplete:              true,
		ConcealmentFindings:       1,
	}))
	if err != nil || resConc.Effect != domain.PolicyEffectQuarantine {
		t.Fatalf("concealment expected QUARANTINE, got effect=%s err=%v", resConc.Effect, err)
	}

	// 5. Confidential IP match -> REQUIRE_APPROVAL (ip-review).
	resConf, err := engine.Evaluate(context.Background(), compiled, policy.StagePushEgress, baseInput(inspection.InspectionSummary{
		MandatoryScannersComplete: true,
		ScanComplete:              true,
		IPWinnowMatches:           1,
		ConfidentialIPMatches:     1,
	}))
	if err != nil || resConf.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("confidential IP expected REQUIRE_APPROVAL, got effect=%s err=%v", resConf.Effect, err)
	}
}
