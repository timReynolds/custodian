package policy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/policy"
)

func TestEvaluator_PrecedenceLatticeForwardAndReverse(t *testing.T) {
	forwardYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: precedence-forward
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r.allow
    stages: [EGRESS]
    when: flags.allow == true
    effect: ALLOW
  - id: r.approval
    stages: [EGRESS]
    when: flags.req_approval == true
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: engineering
        minimum: 1
  - id: r.remediation
    stages: [EGRESS]
    when: flags.req_remediation == true
    effect: REQUIRE_REMEDIATION
  - id: r.quarantine
    stages: [EGRESS]
    when: flags.quarantine == true
    effect: QUARANTINE
  - id: r.deny
    stages: [EGRESS]
    when: flags.deny == true
    effect: DENY
`
	reverseYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: precedence-reverse
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r.deny
    stages: [EGRESS]
    when: flags.deny == true
    effect: DENY
  - id: r.quarantine
    stages: [EGRESS]
    when: flags.quarantine == true
    effect: QUARANTINE
  - id: r.remediation
    stages: [EGRESS]
    when: flags.req_remediation == true
    effect: REQUIRE_REMEDIATION
  - id: r.approval
    stages: [EGRESS]
    when: flags.req_approval == true
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: engineering
        minimum: 1
  - id: r.allow
    stages: [EGRESS]
    when: flags.allow == true
    effect: ALLOW
`

	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	fwdBundle, errs := engine.Compile([]byte(forwardYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(forward): %+v", errs)
	}
	revBundle, errs := engine.Compile([]byte(reverseYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile(reverse): %+v", errs)
	}

	cases := []struct {
		name  string
		flags map[string]bool
		want  domain.PolicyEffect
	}{
		{"allow_only", map[string]bool{"allow": true}, domain.PolicyEffectAllow},
		{"approval_over_allow", map[string]bool{"allow": true, "req_approval": true}, domain.PolicyEffectRequireApproval},
		{"remediation_over_approval", map[string]bool{"allow": true, "req_approval": true, "req_remediation": true}, domain.PolicyEffectRequireRemediation},
		{"quarantine_over_remediation", map[string]bool{"req_remediation": true, "quarantine": true}, domain.PolicyEffectQuarantine},
		{"deny_over_all", map[string]bool{"allow": true, "req_approval": true, "req_remediation": true, "quarantine": true, "deny": true}, domain.PolicyEffectDeny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{"flags": tc.flags}
			resFwd, err := engine.Evaluate(context.Background(), fwdBundle, policy.StageEgress, input)
			if err != nil {
				t.Fatalf("Evaluate(fwd): %v", err)
			}
			resRev, err := engine.Evaluate(context.Background(), revBundle, policy.StageEgress, input)
			if err != nil {
				t.Fatalf("Evaluate(rev): %v", err)
			}
			if resFwd.Effect != tc.want || resRev.Effect != tc.want {
				t.Fatalf("precedence mismatch: fwd=%s rev=%s want=%s", resFwd.Effect, resRev.Effect, tc.want)
			}
			if tc.want.BlocksPublication() && len(resFwd.Obligations) != 0 {
				t.Fatalf("blocking effect %s must clear obligations, got %+v", tc.want, resFwd.Obligations)
			}
		})
	}
}

func TestEvaluator_ZeroMatchedRulesFallsBackToDefaultDeny(t *testing.T) {
	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: default-deny-unmatched
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: only.nonexistent
    stages: [EGRESS]
    when: change.paths.exists(p, p == "nonexistent")
    effect: ALLOW
`
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bundle, errs := engine.Compile([]byte(bundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	res, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, map[string]any{
		"change": map[string]any{"paths": []string{"README.md"}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("effect=%s, want DENY", res.Effect)
	}
	if len(res.MatchedRuleIDs) != 0 {
		t.Fatalf("expected 0 matched rules, got %v", res.MatchedRuleIDs)
	}
}

func TestEvaluator_StageFilteringAndInvalidStage(t *testing.T) {
	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: stage-filter
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: ingress.allow
    stages: [INGRESS]
    when: findings.critical_secrets == 0
    effect: ALLOW
  - id: egress.approval
    stages: [EGRESS]
    when: "true"
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: owners
        minimum: 1
`
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bundle, errs := engine.Compile([]byte(bundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	inRes, err := engine.Evaluate(context.Background(), bundle, policy.StageIngress, map[string]any{
		"findings": map[string]any{"critical_secrets": 0},
	})
	if err != nil {
		t.Fatalf("Evaluate(INGRESS): %v", err)
	}
	if inRes.Effect != domain.PolicyEffectAllow || !slices.Equal(inRes.MatchedRuleIDs, []string{"ingress.allow"}) {
		t.Fatalf("unexpected INGRESS result: %+v", inRes)
	}
	if len(inRes.RuleTrace) != 1 || inRes.RuleTrace[0].RuleID != "ingress.allow" {
		t.Fatalf("unexpected INGRESS trace: %+v", inRes.RuleTrace)
	}

	if _, err := engine.Evaluate(context.Background(), bundle, "INVALID_STAGE", map[string]any{}); err == nil {
		t.Fatalf("expected error on INVALID_STAGE")
	}
}

func TestEvaluator_ObligationDeduplicationAndDomainDecision(t *testing.T) {
	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: dedup-obligations
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: obl.sec.one
    stages: [EGRESS]
    when: "true"
    effect: REQUIRE_APPROVAL
    obligations:
      - reviewer_group: security-team
        minimum: 1
  - id: obl.sec.two
    stages: [EGRESS]
    when: "true"
    effect: REQUIRE_APPROVAL
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: security-team
        minimum: 3
      - reviewer_group: platform-owners
        minimum: 2
`
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bundle, errs := engine.Compile([]byte(bundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	res, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, policy.PolicyInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Effect != domain.PolicyEffectRequireApproval {
		t.Fatalf("effect=%s, want REQUIRE_APPROVAL", res.Effect)
	}
	if len(res.Obligations) != 2 {
		t.Fatalf("expected 2 deduplicated obligations, got %+v", res.Obligations)
	}
	if res.Obligations[0].ReviewerGroup != "security-team" || res.Obligations[0].Minimum != 3 {
		t.Fatalf("expected max minimum 3 for security-team, got %+v", res.Obligations[0])
	}
	if !policy.RequiresHumanApproval(res) {
		t.Fatalf("expected RequiresHumanApproval=true for REQUIRE_APPROVAL")
	}

	dec := res.ToDomainDecision(uuid.New(), uuid.New(), uuid.New(), time.Now())
	if dec.Effect != domain.PolicyEffectRequireApproval || len(dec.Obligations) != 2 || !domain.IsValidSHA256Hex(dec.InputDigest) {
		t.Fatalf("unexpected domain decision: %+v", dec)
	}
}

func TestEvaluator_ObservabilityMetricsAndSafeLogs(t *testing.T) {
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Level:     slog.LevelInfo,
		Component: "policy-test",
	})

	engine, err := policy.NewEngine(
		policy.WithMetrics(metrics),
		policy.WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	bundle, errs := engine.Compile([]byte(minimalValidBundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	// Trigger DENY via zero matched rules on INGRESS.
	res, err := engine.Evaluate(context.Background(), bundle, policy.StageIngress, map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Effect != domain.PolicyEffectDeny {
		t.Fatalf("effect=%s, want DENY", res.Effect)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics handler status=%d, want 200", rec.Code)
	}
	metricsBody := rec.Body.String()
	if !strings.Contains(metricsBody, `custodian_policy_decisions_total{effect="DENY",stage="INGRESS"} 1`) {
		t.Fatalf("expected custodian_policy_decisions_total DENY=1 in metrics output:\n%s", metricsBody)
	}
	if !strings.Contains(metricsBody, `custodian_policy_denials_total{scope="DEFAULT",stage="INGRESS"} 1`) {
		t.Fatalf("expected custodian_policy_denials_total DEFAULT=1 in metrics output:\n%s", metricsBody)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, res.BundleDigest) || !strings.Contains(logged, res.InputDigest) {
		t.Fatalf("expected allowlisted digests in log output, got %s", logged)
	}
}

func TestEvaluator_PolicyInputFromJSON_Int64PrecisionOver2Pow53(t *testing.T) {
	const (
		wantRepoID         int64 = 9007199254740993 // 2^53 + 1
		wantInstallationID int64 = 9007199254740995 // 2^53 + 3
		wantTotalBytes     int64 = 9007199254740997 // 2^53 + 5
	)

	rawJSON := []byte(`{"repository":{"github_repository_id":9007199254740993,"github_installation_id":9007199254740995},"change":{"total_bytes":9007199254740997}}`)

	parsed, err := policy.PolicyInputFromJSON(policy.StageEgress, rawJSON)
	if err != nil {
		t.Fatalf("PolicyInputFromJSON: %v", err)
	}
	if parsed.Repository.GitHubRepositoryID != wantRepoID {
		t.Fatalf("github_repository_id=%d, want %d", parsed.Repository.GitHubRepositoryID, wantRepoID)
	}
	if parsed.Repository.GitHubInstallationID != wantInstallationID {
		t.Fatalf("github_installation_id=%d, want %d", parsed.Repository.GitHubInstallationID, wantInstallationID)
	}
	if parsed.Change.TotalBytes != wantTotalBytes {
		t.Fatalf("total_bytes=%d, want %d", parsed.Change.TotalBytes, wantTotalBytes)
	}

	// Verify PolicyInputFromMap also preserves json.Number precision cleanly.
	fromMap, err := policy.PolicyInputFromMap(policy.StageEgress, map[string]any{
		"repository": map[string]any{
			"github_repository_id":   json.Number("9007199254740993"),
			"github_installation_id": json.Number("9007199254740995"),
		},
		"change": map[string]any{
			"total_bytes": json.Number("9007199254740997"),
		},
	})
	if err != nil {
		t.Fatalf("PolicyInputFromMap: %v", err)
	}
	if fromMap.Repository.GitHubRepositoryID != wantRepoID ||
		fromMap.Repository.GitHubInstallationID != wantInstallationID ||
		fromMap.Change.TotalBytes != wantTotalBytes {
		t.Fatalf("PolicyInputFromMap precision mismatch: %+v", fromMap)
	}

	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: int64-precision-test
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: repo.exact.id
    stages: [EGRESS]
    when: repository.github_repository_id == 9007199254740993 && repository.github_installation_id == 9007199254740995 && change.total_bytes == 9007199254740997
    effect: ALLOW
`
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bundle, errs := engine.Compile([]byte(bundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	typedInput := policy.PolicyInput{
		Repository: policy.RepositoryInput{
			GitHubRepositoryID:   wantRepoID,
			GitHubInstallationID: wantInstallationID,
		},
		Change: policy.ChangeInput{
			TotalBytes: wantTotalBytes,
		},
	}

	resTyped, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, typedInput)
	if err != nil {
		t.Fatalf("Evaluate(typed): %v", err)
	}
	resRawMsg, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, json.RawMessage(rawJSON))
	if err != nil {
		t.Fatalf("Evaluate(json.RawMessage): %v", err)
	}
	resBytes, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, rawJSON)
	if err != nil {
		t.Fatalf("Evaluate([]byte): %v", err)
	}

	if resTyped.Effect != domain.PolicyEffectAllow {
		t.Fatalf("typed Effect=%s, want ALLOW", resTyped.Effect)
	}
	if resRawMsg.Effect != domain.PolicyEffectAllow {
		t.Fatalf("json.RawMessage Effect=%s, want ALLOW (precision lost?)", resRawMsg.Effect)
	}
	if resBytes.Effect != domain.PolicyEffectAllow {
		t.Fatalf("[]byte Effect=%s, want ALLOW (precision lost?)", resBytes.Effect)
	}
	if resRawMsg.InputDigest != resBytes.InputDigest {
		t.Fatalf("json.RawMessage InputDigest %s != []byte InputDigest %s", resRawMsg.InputDigest, resBytes.InputDigest)
	}
}

func TestEvaluator_EmptyInputDigestParityAndNilFallback(t *testing.T) {
	bundleYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: empty-digest-parity
  version: "1.0.0"
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: r.deny
    stages: [EGRESS]
    when: "false"
    effect: ALLOW
`
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bundle, errs := engine.Compile([]byte(bundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}

	wantEmptyObjDigest := domain.SHA256Hex([]byte("{}"))

	resMapEmpty, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, map[string]any{})
	if err != nil {
		t.Fatalf("Evaluate(map{}): %v", err)
	}
	resRawMsgEmpty, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("Evaluate(json.RawMessage(\"{}\")): %v", err)
	}
	resBytesEmpty, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, []byte("{}"))
	if err != nil {
		t.Fatalf("Evaluate([]byte(\"{}\")): %v", err)
	}
	resWhitespaceEmpty, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, json.RawMessage(" { } \n"))
	if err != nil {
		t.Fatalf("Evaluate(json.RawMessage(\" { } \")): %v", err)
	}

	for name, digest := range map[string]string{
		"map[string]any{}":        resMapEmpty.InputDigest,
		"json.RawMessage(\"{}\")": resRawMsgEmpty.InputDigest,
		"[]byte(\"{}\")":          resBytesEmpty.InputDigest,
		"whitespace {}":           resWhitespaceEmpty.InputDigest,
	} {
		if digest != wantEmptyObjDigest {
			t.Fatalf("%s InputDigest=%s, want %s", name, digest, wantEmptyObjDigest)
		}
	}

	// Nil inputs must consistently fall back to canonicalized initialized PolicyInput digest.
	var typedNilMap map[string]any
	var typedNilStruct *policy.PolicyInput
	resUntypedNil, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, nil)
	if err != nil {
		t.Fatalf("Evaluate(nil): %v", err)
	}
	resNilMap, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, typedNilMap)
	if err != nil {
		t.Fatalf("Evaluate(map[string]any(nil)): %v", err)
	}
	resNilStruct, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, typedNilStruct)
	if err != nil {
		t.Fatalf("Evaluate((*PolicyInput)(nil)): %v", err)
	}
	if resNilMap.InputDigest != resUntypedNil.InputDigest || resNilStruct.InputDigest != resUntypedNil.InputDigest {
		t.Fatalf("nil fallback InputDigest mismatch: nil=%s nilMap=%s nilStruct=%s",
			resUntypedNil.InputDigest, resNilMap.InputDigest, resNilStruct.InputDigest)
	}
	if resMapEmpty.InputDigest == resUntypedNil.InputDigest {
		t.Fatalf("non-nil empty map{} must not collapse to nil fallback digest %s", resUntypedNil.InputDigest)
	}

	// Verify ComposeAndEvaluate preserves the same parity.
	composedEmpty, err := engine.ComposeAndEvaluate(context.Background(), bundle, bundle, policy.StageEgress, map[string]any{})
	if err != nil {
		t.Fatalf("ComposeAndEvaluate(map{}): %v", err)
	}
	if composedEmpty.InputDigest != wantEmptyObjDigest {
		t.Fatalf("ComposeAndEvaluate(map{}) InputDigest=%s, want %s", composedEmpty.InputDigest, wantEmptyObjDigest)
	}
}

func TestEvaluator_PolicyInputFromJSON_RejectsTrailingTokensAndInvalidPayloads(t *testing.T) {
	invalidCases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: []byte("")},
		{name: "whitespace_only", raw: []byte("   \n\t")},
		{name: "trailing_garbage", raw: []byte(`{"findings":{"critical_secrets":0}} garbage`)},
		{name: "trailing_second_object", raw: []byte(`{"findings":{"critical_secrets":0}} {"extra":1}`)},
		{name: "trailing_number", raw: []byte(`{} 123`)},
		{name: "trailing_null", raw: []byte(`{} null`)},
		{name: "json_array", raw: []byte(`[1, 2, 3]`)},
		{name: "json_literal_null", raw: []byte(`null`)},
		{name: "json_literal_null_whitespace", raw: []byte(" \n null \t ")},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.PolicyInputFromJSON(policy.StageEgress, tc.raw)
			if err == nil || !strings.Contains(err.Error(), "INVALID_POLICY_INPUT") {
				t.Fatalf("expected INVALID_POLICY_INPUT for %s (%q), got %v", tc.name, string(tc.raw), err)
			}
		})
	}

	// Evaluate and ComposeAndEvaluate must also reject json.RawMessage("null") and []byte("null")
	// while continuing to accept {} and nil inputs.
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	bundle, errs := engine.Compile([]byte(minimalValidBundleYAML))
	if len(errs) > 0 {
		t.Fatalf("Compile: %+v", errs)
	}
	for _, rawNull := range []any{json.RawMessage("null"), []byte("null"), json.RawMessage(" \n null \t ")} {
		if _, err := engine.Evaluate(context.Background(), bundle, policy.StageEgress, rawNull); err == nil || !strings.Contains(err.Error(), "INVALID_POLICY_INPUT") {
			t.Fatalf("Evaluate(%T(%q)) expected INVALID_POLICY_INPUT, got %v", rawNull, rawNull, err)
		}
		if _, err := engine.ComposeAndEvaluate(context.Background(), bundle, bundle, policy.StageEgress, rawNull); err == nil || !strings.Contains(err.Error(), "INVALID_POLICY_INPUT") {
			t.Fatalf("ComposeAndEvaluate(%T(%q)) expected INVALID_POLICY_INPUT, got %v", rawNull, rawNull, err)
		}
	}
	if _, err := policy.PolicyInputFromJSON(policy.StageEgress, []byte("{}")); err != nil {
		t.Fatalf("expected PolicyInputFromJSON(\"{}\") to succeed, got %v", err)
	}

	// Trailing whitespace after a valid JSON object must succeed.
	valid, err := policy.PolicyInputFromJSON(policy.StageEgress, []byte("{\"findings\":{\"critical_secrets\":2}}  \n\t "))
	if err != nil {
		t.Fatalf("expected valid JSON with trailing whitespace to succeed, got %v", err)
	}
	if valid.Findings.CriticalSecrets != 2 {
		t.Fatalf("critical_secrets=%d, want 2", valid.Findings.CriticalSecrets)
	}
}
