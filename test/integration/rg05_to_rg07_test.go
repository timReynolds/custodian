package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/test/fixtures"
)

func TestRG05_FailClosedInspectionPipeline(t *testing.T) {
	ctx := context.Background()
	root := fixtures.FindRepoRoot(t)
	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	defaultYAML := fixtures.VerifyRepoBundleLoaded(t, "policies/defaults/default.yaml")
	compiledDefault, errs := polEngine.Compile(defaultYAML)
	if len(errs) > 0 {
		t.Fatalf("compile default.yaml: %+v", errs)
	}

	// 1. Stage A: scanner crash OR FilesSkipped > 0 -> ScanComplete=false -> CEL QUARANTINE.
	sc := fixtures.NewStubScanners(t)
	targetDir := t.TempDir()
	sc.SetSemgrepFilesSkipped()
	runner := inspection.NewRunner(sc.Config)
	repSkipped, err := runner.Inspect(ctx, inspection.Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      targetDir,
		Classification: domain.ClassificationInternal,
		Stage:          inspection.StageEgress,
	})
	if err != nil {
		t.Fatalf("Inspect(skipped): %v", err)
	}
	if repSkipped.Summary.ScanComplete {
		t.Fatalf("expected ScanComplete=false when semgrep skipped files")
	}

	resSkipped, err := polEngine.Evaluate(ctx, compiledDefault, policy.StageEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: repSkipped.Summary.ScanComplete},
		Assessment: policy.AssessmentInput{Status: "COMPLETE", Disposition: "CLEAR"},
	})
	if err != nil || !resSkipped.Effect.BlocksPublication() {
		t.Fatalf("RG-05 violation: expected blocking effect on skipped files, got (%s, %v)", resSkipped.Effect, err)
	}

	sc.SetGitleaksCrash()
	repCrash, err := runner.Inspect(ctx, inspection.Request{
		ProposalID:     domain.MustNewID(),
		ArtifactID:     domain.MustNewID(),
		TargetDir:      targetDir,
		Classification: domain.ClassificationInternal,
		Stage:          inspection.StageEgress,
	})
	if err != nil || repCrash.Summary.ScanComplete {
		t.Fatalf("expected ScanComplete=false on gitleaks crash, got (%v, %v)", repCrash.Summary.ScanComplete, err)
	}

	// 2. Stage B: RoutePolicy blocks openai/gpt-5 on CONFIDENTIAL with 0 gateway calls -> INDETERMINATE -> QUARANTINE.
	var gwCalls atomic.Int32
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gwCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer gwSrv.Close()
	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	decSvc, err := decisions.NewService(gwClient, decisions.WithRoutePolicy(&decisions.RoutePolicy{
		RouteMaxClassification: map[string]domain.Classification{
			"openai/gpt-5": domain.ClassificationInternal,
		},
	}))
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}
	ma, err := decSvc.Assess(ctx, decisions.AssessRequest{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		Repository: domain.Repository{
			ID:             domain.MustNewID(),
			FullName:       "acme/conf-repo",
			Classification: domain.ClassificationConfidential,
			Enabled:        true,
		},
		AllowedModelRoutes: []string{"openai/gpt-5", "approved-code-review"},
		ModelRoute:         "openai/gpt-5",
		AssessmentType:     "IP_PROVENANCE",
		ChangedPaths:       []string{"main.go"},
		CanonicalDiff:      "+func x() {}",
	})
	if err != nil || gwCalls.Load() != 0 || ma.Status != domain.AssessmentStatusIndeterminate {
		t.Fatalf("expected 0 gateway calls and INDETERMINATE, got calls=%d status=%s err=%v", gwCalls.Load(), ma.Status, err)
	}

	// 3. Stage B: Gateway 503 / malformed JSON / ungrounded evidence_ids -> FAILED -> QUARANTINE.
	badGw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"x","findings":[{"title":"f","severity":"LOW","summary":"s","evidence_ids":["nonexistent-ev"]}],"limitations":[]}`))
	}))
	defer badGw.Close()
	badClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: badGw.URL})
	badSvc, _ := decisions.NewService(badClient)
	maUngrounded, _ := badSvc.Assess(ctx, decisions.AssessRequest{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		Repository: domain.Repository{
			ID:             domain.MustNewID(),
			FullName:       "acme/internal-repo",
			Classification: domain.ClassificationInternal,
			Enabled:        true,
		},
		AllowedModelRoutes: []string{"approved-code-review"},
		ModelRoute:         "approved-code-review",
		AssessmentType:     "SECURITY_REVIEW",
		ChangedPaths:       []string{"main.go"},
		CanonicalDiff:      "+func x() {}",
	})
	if maUngrounded.Status != domain.AssessmentStatusFailed {
		t.Fatalf("expected FAILED assessment for ungrounded evidence_ids, got %s", maUngrounded.Status)
	}
	fact := decisions.ToPolicyAssessmentFact(maUngrounded)
	resUngrounded, err := polEngine.Evaluate(ctx, compiledDefault, policy.StageEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: fact.Status, Risk: fact.Risk, Disposition: fact.Disposition},
	})
	if err != nil || !resUngrounded.Effect.BlocksPublication() {
		t.Fatalf("expected blocking CEL effect on FAILED Stage B, got (%s, %v)", resUngrounded.Effect, err)
	}

	// 4. Stage C: runtime CEL error fails closed to DENY.
	errBundle, compileErrs := polEngine.Compile([]byte(`
apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: err-bundle
  version: "1.0.0"
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: divzero
    stages: [EGRESS]
    when: (10 / findings.critical_secrets) > 0
    effect: ALLOW
`))
	if len(compileErrs) > 0 {
		t.Fatalf("compile errBundle: %+v", compileErrs)
	}
	resCEL, err := polEngine.Evaluate(ctx, errBundle, policy.StageEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true, CriticalSecrets: 0},
	})
	if err != nil || resCEL.Effect != domain.PolicyEffectDeny || !resCEL.HadError {
		t.Fatalf("expected fail-closed DENY with HadError=true, got (%+v, %v)", resCEL, err)
	}
	_ = root
	_ = filepath.Separator
	_ = json.Marshal
}

func TestRG06_OrgBeforeRepoComposition(t *testing.T) {
	ctx := context.Background()
	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	orgComp, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "policies/examples/org_baseline.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile org_baseline: %+v", errs)
	}
	permissiveRepo, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "test/e2e/fixtures/policies/repo_permissive_override_attempt.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile permissive repo: %+v", errs)
	}

	// Non-overridable ORG secret block beats permissive REPO allow on BOTH INGRESS and EGRESS.
	for _, stage := range []string{policy.StageIngress, policy.StageEgress} {
		res, err := polEngine.ComposeAndEvaluate(ctx, orgComp, permissiveRepo, stage, policy.PolicyInput{
			Findings:   policy.FindingsInput{ScanComplete: true, CriticalSecrets: 1},
			Assessment: policy.AssessmentInput{Status: "COMPLETE", Disposition: "CLEAR"},
		})
		if err != nil {
			t.Fatalf("ComposeAndEvaluate(%s): %v", stage, err)
		}
		if res.Effect != domain.PolicyEffectDeny {
			t.Fatalf("RG-06 violation (%s): expected DENY, got %s (matched=%v)", stage, res.Effect, res.MatchedRuleIDs)
		}
	}

	// Additive obligations: org_baseline + repo_strict_security combines obligations cleanly.
	strictComp, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "policies/examples/repo_strict_security.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile repo_strict_security: %+v", errs)
	}
	resAdd, err := polEngine.ComposeAndEvaluate(ctx, orgComp, strictComp, policy.StageEgress, policy.PolicyInput{
		Findings:   policy.FindingsInput{ScanComplete: true},
		Assessment: policy.AssessmentInput{Status: "COMPLETE", Disposition: "CLEAR"},
		Change:     policy.ChangeInput{Paths: []string{"auth/oidc.go", "migrations/0001_init.sql"}},
	})
	if err != nil || resAdd.Effect != domain.PolicyEffectRequireApproval || len(resAdd.Obligations) < 2 {
		t.Fatalf("expected additive REQUIRE_APPROVAL with >=2 obligations, got (%+v, %v)", resAdd, err)
	}
}

func TestRG07_PublisherIsolationAndBranchExclusivity(t *testing.T) {
	root := fixtures.FindRepoRoot(t)
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "list", "-deps", "./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, string(out))
	}
	deps := string(out)
	forbidden := []string{
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/git/reconstruct",
		"github.com/timreynolds/custodian/internal/git/checkout",
		"github.com/google/cel-go",
	}
	for _, prefix := range forbidden {
		if strings.Contains(deps, prefix) {
			t.Fatalf("RG-07 isolation violation: publisher depends on forbidden package %q", prefix)
		}
	}

	// Branch exclusivity check.
	propID := domain.MustNewID()
	if err := domain.ValidateBranchRef(propID, "main"); err == nil {
		t.Fatalf("RG-07 violation: ValidateBranchRef allowed pushing to main")
	}
	if err := domain.ValidateBranchRef(propID, "custodian/"+domain.MustNewID().String()); err == nil {
		t.Fatalf("RG-07 violation: ValidateBranchRef allowed pushing to another proposal's branch")
	}
	if err := domain.ValidateBranchRef(propID, "custodian/"+propID.String()); err != nil {
		t.Fatalf("ValidateBranchRef rejected canonical branch: %v", err)
	}
}
