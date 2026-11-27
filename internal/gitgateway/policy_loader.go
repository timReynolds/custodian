package gitgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
)

const fallbackDefaultPushIPProtectionYAML = `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: push-ip-protection
  version: "1.0.0"
  scope: ORG
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory:
    - gitleaks
    - scancode
    - semgrep
  decisionModel:
    route: approved-code-review
    trigger:
      - restricted_ip_finding
      - concealment_finding
      - high_risk_change
      - restricted_repository
rules:
  - id: push.secrets.block
    description: Block any critical secret finding on push egress.
    stages: [PUSH_EGRESS]
    when: findings.critical_secrets > 0
    effect: DENY
    overridable: false
    message: Critical secret detected by deterministic inspection.
  - id: push.licenses.block
    description: Block prohibited license findings on push egress.
    stages: [PUSH_EGRESS]
    when: findings.prohibited_licenses > 0
    effect: DENY
    overridable: false
    message: Prohibited software license detected by deterministic inspection.
  - id: push.ip.restricted.block
    description: Block restricted proprietary IP fingerprint matches on push egress.
    stages: [PUSH_EGRESS]
    when: findings.restricted_ip_matches > 0
    effect: DENY
    overridable: false
    message: Restricted proprietary IP fingerprint match detected.
  - id: push.ip.header_strip.block
    description: Block pushes where proprietary copyright or confidentiality headers were stripped.
    stages: [PUSH_EGRESS]
    when: findings.ip_header_strip_matches > 0
    effect: DENY
    overridable: false
    message: Proprietary copyright or confidentiality header stripping detected.
  - id: push.concealment.quarantine
    description: Quarantine pushes containing concealed, obfuscated, or nested-archive payloads.
    stages: [PUSH_EGRESS]
    when: findings.concealment_findings > 0
    effect: QUARANTINE
    overridable: false
    message: Concealment or smuggling indicator detected during inspection.
  - id: push.scan.incomplete
    description: Quarantine pushes when mandatory scanners did not complete with full coverage.
    stages: [PUSH_EGRESS]
    when: "!findings.scan_complete"
    effect: QUARANTINE
    overridable: false
    message: Mandatory deterministic inspection did not complete with full coverage.
  - id: push.destination.unregistered_or_external
    description: Deny pushes to unregistered or external Git destinations by default (customizable via ORG-bundle CEL).
    stages: [PUSH_EGRESS]
    when: "!destination.registered || destination.external"
    effect: DENY
    overridable: true
    message: Destination repository is unregistered or external.
  - id: push.model.block
    description: Deny pushes when Stage B contextual assessment disposition is BLOCK.
    stages: [PUSH_EGRESS]
    when: assessment.disposition == "BLOCK"
    effect: DENY
    overridable: false
    message: Contextual decision model blocked push egress.
  - id: push.model.indeterminate
    description: Quarantine pushes when Stage B contextual assessment status/disposition is missing, failed, indeterminate, or mismatched.
    stages: [PUSH_EGRESS]
    when: >-
      !(
        (assessment.status == "COMPLETE" && assessment.disposition in ["CLEAR", "REVIEW", "ESCALATE", "BLOCK"]) ||
        (assessment.status == "NOT_REQUIRED" && assessment.disposition in ["NOT_REQUIRED", "", "CLEAR"])
      )
    effect: QUARANTINE
    overridable: false
    message: Contextual decision model assessment is incomplete, indeterminate, or has an invalid status/disposition pair.
  - id: push.ip.confidential.review
    description: Require dedicated IP review when confidential IP or fingerprint matches are detected.
    stages: [PUSH_EGRESS]
    when: findings.confidential_ip_matches > 0 || findings.ip_exact_matches > 0 || findings.ip_winnow_matches > 0
    effect: REQUIRE_APPROVAL
    overridable: false
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: ip-review
        minimum: 1
    message: Confidential IP fingerprint match requires IP reviewer approval.
  - id: push.ip.review
    description: Require dedicated IP review when contextual IP risk is HIGH or CRITICAL, or IP provenance requests review/escalation.
    stages: [PUSH_EGRESS]
    when: >-
      assessment.ip_risk in ["HIGH", "CRITICAL"] ||
      (assessment.assessment_type == "IP_PROVENANCE" && assessment.status == "COMPLETE" && assessment.disposition in ["REVIEW", "ESCALATE"])
    effect: REQUIRE_APPROVAL
    overridable: false
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: ip-review
        minimum: 1
    message: High/critical IP provenance risk or IP provenance review disposition requires IP reviewer approval.
  - id: push.model.review
    description: Require human security review when Stage B contextual assessment is COMPLETE with disposition REVIEW or ESCALATE, or reports HIGH/CRITICAL risk.
    stages: [PUSH_EGRESS]
    when: >-
      (assessment.status == "COMPLETE" && assessment.disposition in ["REVIEW", "ESCALATE"]) ||
      assessment.risk in ["HIGH", "CRITICAL"]
    effect: REQUIRE_APPROVAL
    overridable: false
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: security-team
        minimum: 1
    message: Contextual decision model requires human review before push egress.
  - id: push.allow
    description: Allow clean push egress to registered internal destinations when Stage B is COMPLETE+CLEAR or validly NOT_REQUIRED.
    stages: [PUSH_EGRESS]
    when: >-
      findings.scan_complete &&
      findings.critical_secrets == 0 &&
      findings.prohibited_licenses == 0 &&
      findings.restricted_ip_matches == 0 &&
      findings.ip_header_strip_matches == 0 &&
      findings.concealment_findings == 0 &&
      destination.registered &&
      !destination.external &&
      (
        (assessment.status == "COMPLETE" && assessment.disposition == "CLEAR") ||
        (assessment.status == "NOT_REQUIRED" && assessment.disposition in ["NOT_REQUIRED", "", "CLEAR"])
      ) &&
      !(assessment.ip_risk in ["HIGH", "CRITICAL"]) &&
      !(assessment.risk in ["HIGH", "CRITICAL"])
    effect: ALLOW
`

type persistedCompiledBundle struct {
	row      persistence.PolicyBundleRow
	compiled *policy.CompiledBundle
}

type composedPushEvalOutcome struct {
	result          policy.EvalResult
	primaryBundleID uuid.UUID
	orgBundleID     *uuid.UUID
	repoBundleID    *uuid.UUID
}

func resolveActivePushPolicyBundles(
	ctx context.Context,
	store *persistence.Store,
	engine *policy.Engine,
	policyDir string,
	repositoryID *uuid.UUID,
	now time.Time,
) ([]persistedCompiledBundle, []persistedCompiledBundle, error) {
	if store == nil {
		return nil, nil, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is unavailable")
	}
	if engine == nil {
		return nil, nil, domain.Unavailable("POLICY_ENGINE_UNAVAILABLE", "policy engine is unavailable")
	}

	orgRows, err := store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
	if err != nil {
		return nil, nil, err
	}

	var repoRows []persistence.PolicyBundleRow
	if repositoryID != nil && *repositoryID != uuid.Nil {
		repoRows, err = store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeRepo, repositoryID)
		if err != nil {
			return nil, nil, err
		}
	}

	repoDigests := make(map[string]struct{}, len(repoRows))
	repoBundles := make([]persistedCompiledBundle, 0, len(repoRows))
	for _, r := range repoRows {
		domBundle := r.ToDomain()
		if !bundleAppliesToPushStageRaw(domBundle, policy.StagePushEgress) {
			continue
		}
		compiled, errs := engine.CompileDomainBundle(domBundle)
		if len(errs) > 0 {
			return nil, nil, domain.Unprocessable("INVALID_POLICY_BUNDLE", errs[0].Message)
		}
		if !bundleAppliesToPushStage(compiled, policy.StagePushEgress) {
			continue
		}
		repoDigests[r.Digest] = struct{}{}
		repoBundles = append(repoBundles, persistedCompiledBundle{row: r, compiled: compiled})
	}

	compileOrgRows := func(rows []persistence.PolicyBundleRow) ([]persistedCompiledBundle, error) {
		out := make([]persistedCompiledBundle, 0, len(rows))
		for _, r := range rows {
			domBundle := r.ToDomain()
			if !bundleAppliesToPushStageRaw(domBundle, policy.StagePushEgress) {
				continue
			}
			compiled, errs := engine.CompileDomainBundle(domBundle)
			if len(errs) > 0 {
				return nil, domain.Unprocessable("INVALID_POLICY_BUNDLE", errs[0].Message)
			}
			if !bundleAppliesToPushStage(compiled, policy.StagePushEgress) {
				continue
			}
			if compiled.Bundle.Metadata.Scope == "" {
				if _, sameDigestAsRepo := repoDigests[r.Digest]; sameDigestAsRepo {
					continue
				}
			}
			out = append(out, persistedCompiledBundle{row: r, compiled: compiled})
		}
		return out, nil
	}

	orgBundles, err := compileOrgRows(orgRows)
	if err != nil {
		return nil, nil, err
	}

	if len(orgBundles) == 0 {
		if err := seedDefaultPushEgressORGPolicy(ctx, store, engine, policyDir, now); err != nil {
			return nil, nil, err
		}
		orgRows, err = store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
		if err != nil {
			return nil, nil, err
		}
		orgBundles, err = compileOrgRows(orgRows)
		if err != nil {
			return nil, nil, err
		}
	}

	return orgBundles, repoBundles, nil
}

func seedDefaultPushEgressORGPolicy(
	ctx context.Context,
	store *persistence.Store,
	engine *policy.Engine,
	policyDir string,
	now time.Time,
) error {
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	var toSeed []*policy.CompiledBundle
	if trimmedDir := strings.TrimSpace(policyDir); trimmedDir != "" {
		bundles, err := engine.LoadDir(trimmedDir)
		if err == nil {
			orgB, _ := policy.PartitionByScope(bundles)
			for _, b := range orgB {
				if bundleAppliesToPushStage(b, policy.StagePushEgress) {
					toSeed = append(toSeed, b)
				}
			}
		}
	}

	if len(toSeed) == 0 {
		for _, candidate := range []string{
			filepath.Join("policies", "defaults", "push-ip-protection.yaml"),
			filepath.Join("..", "..", "policies", "defaults", "push-ip-protection.yaml"),
		} {
			if raw, err := os.ReadFile(candidate); err == nil {
				if compiled, errs := engine.Compile(raw); err == nil && len(errs) == 0 {
					toSeed = append(toSeed, compiled)
					break
				}
			}
		}
	}

	if len(toSeed) == 0 {
		compiled, errs := engine.Compile([]byte(fallbackDefaultPushIPProtectionYAML))
		if len(errs) > 0 || compiled == nil {
			return domain.Internal("POLICY_SEED_FAILED", "failed compiling fallback push-ip-protection policy")
		}
		toSeed = append(toSeed, compiled)
	}

	for _, b := range toSeed {
		scope := b.Scope
		if !scope.IsValid() {
			scope = domain.PolicyScopeOrg
		}
		if _, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name:        b.Bundle.Metadata.Name,
			Version:     b.Bundle.Metadata.Version,
			Scope:       scope,
			Digest:      b.Digest,
			Definition:  b.Definition,
			ActivatedAt: &now,
			CreatedAt:   now,
		}); err != nil {
			return err
		}
	}
	return nil
}

func bundleAppliesToPushStage(b *policy.CompiledBundle, stage string) bool {
	if b == nil {
		return false
	}
	for _, r := range b.Rules {
		if r.Spec.AppliesToStage(stage) {
			return true
		}
	}
	return false
}

// bundleAppliesToPushStageRaw checks whether a raw persisted PolicyBundle targets stage
// before full CEL/structural compilation, so invalid bundles belonging exclusively to other
// stages (e.g. INGRESS/EGRESS) do not fail PUSH_EGRESS bundle resolution. Unparseable or
// stage-less bundles conservatively return true so corrupt bundles still fail closed in ENFORCE_BLOCK.
func bundleAppliesToPushStageRaw(db domain.PolicyBundle, stage string) bool {
	b, _ := policy.ParseDomainBundle(db)
	if len(b.Rules) > 0 {
		for _, r := range b.Rules {
			if len(r.Stages) == 0 {
				return true
			}
			for _, st := range r.Stages {
				if strings.EqualFold(strings.TrimSpace(st), stage) {
					return true
				}
			}
		}
		return false
	}
	var probe struct {
		Rules []struct {
			Stages []string `json:"stages"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(db.Definition, &probe); err != nil || len(probe.Rules) == 0 {
		return true
	}
	for _, r := range probe.Rules {
		if len(r.Stages) == 0 {
			return true
		}
		for _, st := range r.Stages {
			if strings.EqualFold(strings.TrimSpace(st), stage) {
				return true
			}
		}
	}
	return false
}

func composePushInspectionConfig(orgBundles, repoBundles []persistedCompiledBundle) policy.InspectionConfig {
	out := policy.InspectionConfig{
		Mandatory: []string{},
	}
	seenMandatory := make(map[string]struct{})
	seenTriggers := make(map[string]struct{})
	var route string
	var triggers []string

	ordered := make([]persistedCompiledBundle, 0, len(orgBundles)+len(repoBundles))
	ordered = append(ordered, orgBundles...)
	ordered = append(ordered, repoBundles...)

	for _, entry := range ordered {
		b := entry.compiled
		if b == nil || b.Bundle.Inspection == nil {
			continue
		}
		for _, m := range b.Bundle.Inspection.Mandatory {
			if m == "" {
				continue
			}
			if _, ok := seenMandatory[m]; !ok {
				seenMandatory[m] = struct{}{}
				out.Mandatory = append(out.Mandatory, m)
			}
		}
		if dm := b.Bundle.Inspection.DecisionModel; dm != nil {
			if route == "" && dm.Route != "" {
				route = dm.Route
			}
			for _, tr := range dm.Trigger {
				if tr == "" {
					continue
				}
				if _, ok := seenTriggers[tr]; !ok {
					seenTriggers[tr] = struct{}{}
					triggers = append(triggers, tr)
				}
			}
		}
	}

	if route != "" || len(triggers) > 0 {
		if triggers == nil {
			triggers = []string{}
		}
		out.DecisionModel = &policy.DecisionModelConfig{
			Route:   route,
			Trigger: triggers,
		}
	}
	return out
}

func resolvePushModelRoute(allowedRepoRoutes []string, orgBundles, repoBundles []persistedCompiledBundle, inspCfg policy.InspectionConfig) string {
	orgRoute := firstConfiguredPushModelRoute(orgBundles)
	repoRoute := firstAuthorizedPushModelRoute(repoBundles, allowedRepoRoutes)
	if orgRoute != "" {
		if len(allowedRepoRoutes) == 0 || slices.Contains(allowedRepoRoutes, orgRoute) {
			return orgRoute
		}
		if repoRoute != "" {
			return repoRoute
		}
		return orgRoute
	}
	if repoRoute != "" {
		return repoRoute
	}
	if inspCfg.DecisionModel != nil {
		if r := strings.TrimSpace(inspCfg.DecisionModel.Route); r != "" {
			return r
		}
	}
	return "approved-code-review"
}

func firstConfiguredPushModelRoute(bundles []persistedCompiledBundle) string {
	for _, entry := range bundles {
		b := entry.compiled
		if b == nil || b.Bundle.Inspection == nil || b.Bundle.Inspection.DecisionModel == nil {
			continue
		}
		if r := strings.TrimSpace(b.Bundle.Inspection.DecisionModel.Route); r != "" {
			return r
		}
	}
	return ""
}

func firstAuthorizedPushModelRoute(bundles []persistedCompiledBundle, allowed []string) string {
	for _, entry := range bundles {
		b := entry.compiled
		if b == nil || b.Bundle.Inspection == nil || b.Bundle.Inspection.DecisionModel == nil {
			continue
		}
		r := strings.TrimSpace(b.Bundle.Inspection.DecisionModel.Route)
		if r != "" && slices.Contains(allowed, r) {
			return r
		}
	}
	return ""
}

func evaluateComposedPushBundles(
	ctx context.Context,
	engine *policy.Engine,
	orgBundles, repoBundles []persistedCompiledBundle,
	stage string,
	input policy.PolicyInput,
) (composedPushEvalOutcome, error) {
	if len(orgBundles) == 0 && len(repoBundles) == 0 {
		res, err := engine.Evaluate(ctx, nil, stage, input)
		return composedPushEvalOutcome{result: res}, err
	}

	if len(orgBundles) == 1 && len(repoBundles) <= 1 {
		var orgC, repoC *policy.CompiledBundle
		var orgID, repoID *uuid.UUID
		primaryID := orgBundles[0].row.ID
		orgC = orgBundles[0].compiled
		orgIDVal := orgBundles[0].row.ID
		orgID = &orgIDVal
		if len(repoBundles) == 1 {
			repoC = repoBundles[0].compiled
			repoIDVal := repoBundles[0].row.ID
			repoID = &repoIDVal
		}
		res, err := engine.ComposeAndEvaluate(ctx, orgC, repoC, stage, input)
		return composedPushEvalOutcome{
			result:          res,
			primaryBundleID: primaryID,
			orgBundleID:     orgID,
			repoBundleID:    repoID,
		}, err
	}

	if len(orgBundles) == 0 && len(repoBundles) == 1 {
		res, err := engine.Evaluate(ctx, repoBundles[0].compiled, stage, input)
		repoIDVal := repoBundles[0].row.ID
		return composedPushEvalOutcome{
			result:          res,
			primaryBundleID: repoIDVal,
			repoBundleID:    &repoIDVal,
		}, err
	}

	var primaryID uuid.UUID
	var orgBundleID *uuid.UUID
	var repoBundleID *uuid.UUID
	if len(orgBundles) > 0 {
		id := orgBundles[0].row.ID
		orgBundleID = &id
		primaryID = id
	}
	if len(repoBundles) > 0 {
		id := repoBundles[0].row.ID
		repoBundleID = &id
		if primaryID == uuid.Nil {
			primaryID = id
		}
	}

	type bundlePair struct {
		org  *persistedCompiledBundle
		repo *persistedCompiledBundle
	}
	var pairs []bundlePair
	switch {
	case len(orgBundles) > 0 && len(repoBundles) > 0:
		for i := range orgBundles {
			for j := range repoBundles {
				pairs = append(pairs, bundlePair{org: &orgBundles[i], repo: &repoBundles[j]})
			}
		}
	case len(orgBundles) > 0:
		for i := range orgBundles {
			pairs = append(pairs, bundlePair{org: &orgBundles[i]})
		}
	default:
		for j := range repoBundles {
			pairs = append(pairs, bundlePair{repo: &repoBundles[j]})
		}
	}

	var (
		hasAnyExplicitRule bool
		hadAnyError        bool
		combinedEffect     = domain.PolicyEffectAllow
		defaultEffect      = domain.PolicyEffectAllow
		inputDigest        string
		bundleDigests      = make([]string, 0, len(pairs))
		matchedIDs         = make([]string, 0)
		seenMatchedID      = make(map[string]struct{})
		reasons            = make([]domain.PolicyReason, 0)
		seenReasonKey      = make(map[string]struct{})
		obligations        = make([]domain.Obligation, 0)
		traces             = make([]policy.RuleTrace, 0)
		errorReasons       = make([]domain.PolicyReason, 0)
		winningOrgID       uuid.UUID
		winningOrgRank     int
		winningRepoID      uuid.UUID
		winningRepoRank    int
	)

	for _, p := range pairs {
		var orgC, repoC *policy.CompiledBundle
		if p.org != nil {
			orgC = p.org.compiled
		}
		if p.repo != nil {
			repoC = p.repo.compiled
		}
		res, err := engine.ComposeAndEvaluate(ctx, orgC, repoC, stage, input)
		if err != nil {
			return composedPushEvalOutcome{}, err
		}
		if inputDigest == "" {
			inputDigest = res.InputDigest
		}
		if res.BundleDigest != "" {
			bundleDigests = append(bundleDigests, res.BundleDigest)
		}
		traces = append(traces, res.RuleTrace...)

		if res.HadError {
			hadAnyError = true
			for _, r := range res.Reasons {
				if r.Effect == domain.PolicyEffectDeny {
					errorReasons = append(errorReasons, r)
				}
			}
		}

		orgTraceCount := 0
		if p.org != nil {
			orgTraceCount = countPushRulesForStage(p.org.compiled, stage)
		}
		if orgTraceCount > len(res.RuleTrace) {
			orgTraceCount = len(res.RuleTrace)
		}
		if p.org != nil {
			if orgMatched, orgRank := traceEffectivePushRank(res.RuleTrace[:orgTraceCount]); orgMatched && orgRank > winningOrgRank {
				winningOrgRank = orgRank
				winningOrgID = p.org.row.ID
			}
		}
		if p.repo != nil {
			if repoMatched, repoRank := traceEffectivePushRank(res.RuleTrace[orgTraceCount:]); repoMatched && repoRank > winningRepoRank {
				winningRepoRank = repoRank
				winningRepoID = p.repo.row.ID
			}
		}

		if len(res.MatchedRuleIDs) == 0 {
			defaultEffect = defaultEffect.MoreRestrictive(res.Effect)
			continue
		}

		hasAnyExplicitRule = true
		combinedEffect = combinedEffect.MoreRestrictive(res.Effect)

		for _, id := range res.MatchedRuleIDs {
			if _, ok := seenMatchedID[id]; !ok {
				seenMatchedID[id] = struct{}{}
				matchedIDs = append(matchedIDs, id)
			}
		}
		for _, r := range res.Reasons {
			key := fmt.Sprintf("%s|%s|%s|%s", r.RuleID, r.Effect, r.Stage, r.Message)
			if _, ok := seenReasonKey[key]; !ok {
				seenReasonKey[key] = struct{}{}
				reasons = append(reasons, r)
			}
		}
		obligations = append(obligations, res.Obligations...)
	}

	if hadAnyError {
		combinedEffect = domain.PolicyEffectDeny
		reasons = append(reasons, errorReasons...)
		obligations = []domain.Obligation{}
	} else if !hasAnyExplicitRule {
		combinedEffect = defaultEffect
		if !combinedEffect.IsValid() {
			combinedEffect = domain.PolicyEffectDeny
		}
		reasons = []domain.PolicyReason{{
			RuleID:  "defaults.effect",
			Effect:  combinedEffect,
			Stage:   stage,
			Message: "no policy rules matched across active policy bundles",
		}}
		obligations = []domain.Obligation{}
	} else if combinedEffect.BlocksPublication() {
		obligations = []domain.Obligation{}
	}

	if winningOrgID != uuid.Nil {
		orgBundleID = &winningOrgID
		primaryID = winningOrgID
	}
	if winningRepoID != uuid.Nil {
		repoBundleID = &winningRepoID
		if primaryID == uuid.Nil {
			primaryID = winningRepoID
		}
	}

	composedDigest, err := domain.CanonicalJSONDigest(bundleDigests)
	if err != nil {
		composedDigest = domain.SHA256Hex([]byte(strings.Join(bundleDigests, ":")))
	}

	return composedPushEvalOutcome{
		result: policy.EvalResult{
			Effect:         combinedEffect,
			BundleDigest:   composedDigest,
			InputDigest:    inputDigest,
			MatchedRuleIDs: matchedIDs,
			Reasons:        reasons,
			Obligations:    obligations,
			RuleTrace:      traces,
			HadError:       hadAnyError,
		},
		primaryBundleID: primaryID,
		orgBundleID:     orgBundleID,
		repoBundleID:    repoBundleID,
	}, nil
}

func countPushRulesForStage(b *policy.CompiledBundle, stage string) int {
	if b == nil {
		return 0
	}
	count := 0
	for _, r := range b.Rules {
		if r.Spec.AppliesToStage(stage) {
			count++
		}
	}
	return count
}

func traceEffectivePushRank(traces []policy.RuleTrace) (bool, int) {
	matchedAny := false
	maxRank := 0
	for _, tr := range traces {
		if tr.Error != "" {
			matchedAny = true
			if r := domain.PolicyEffectDeny.Rank(); r > maxRank {
				maxRank = r
			}
			continue
		}
		if tr.Matched {
			matchedAny = true
			if r := tr.Effect.Rank(); r > maxRank {
				maxRank = r
			}
		}
	}
	return matchedAny, maxRank
}

func enforcePushMandatoryScanners(summary inspection.InspectionSummary, scanRuns []domain.ScanRun, required []string) inspection.InspectionSummary {
	if len(required) == 0 {
		return summary
	}
	byScanner := make(map[string]domain.ScanRun, len(scanRuns))
	for _, run := range scanRuns {
		byScanner[run.Scanner] = run
	}

	out := summary
	out.IncompleteScanners = slices.Clone(summary.IncompleteScanners)
	if out.IncompleteScanners == nil {
		out.IncompleteScanners = []string{}
	}

	for _, name := range required {
		if name == "" {
			continue
		}
		run, ok := byScanner[name]
		if !ok || !run.IsCleanComplete() {
			out.MandatoryScannersComplete = false
			out.ScanComplete = false
			if !slices.Contains(out.IncompleteScanners, name) {
				out.IncompleteScanners = append(out.IncompleteScanners, name)
			}
		}
	}
	return out
}

func pushSummaryToFindingsInput(s inspection.InspectionSummary) policy.FindingsInput {
	cat := make(map[string]int64, len(s.CountsByCategory))
	for k, v := range s.CountsByCategory {
		cat[k] = int64(v)
	}
	sev := make(map[string]int64, len(s.CountsBySeverity))
	for k, v := range s.CountsBySeverity {
		sev[k] = int64(v)
	}
	sc := make(map[string]int64, len(s.CountsByScanner))
	for k, v := range s.CountsByScanner {
		sc[k] = int64(v)
	}
	evIDs := slices.Clone(s.EvidenceIDs)
	if evIDs == nil {
		evIDs = []string{}
	}
	failed := slices.Clone(s.FailedScanners)
	if failed == nil {
		failed = []string{}
	}
	incomplete := slices.Clone(s.IncompleteScanners)
	if incomplete == nil {
		incomplete = []string{}
	}
	return policy.FindingsInput{
		MandatoryScannersComplete: s.MandatoryScannersComplete,
		ScanComplete:              s.ScanComplete,
		CriticalSecrets:           int64(s.CriticalSecrets),
		ProhibitedLicenses:        int64(s.ProhibitedLicenses),
		HighVulnerabilities:       int64(s.HighVulnerabilities),
		HighSASTFindings:          int64(s.HighSASTFindings),
		TotalFindings:             int64(s.TotalFindings),
		IPExactMatches:            int64(s.IPExactMatches),
		IPWinnowMatches:           int64(s.IPWinnowMatches),
		IPHeaderStripMatches:      int64(s.IPHeaderStripMatches),
		ConcealmentFindings:       int64(s.ConcealmentFindings),
		RestrictedIPMatches:       int64(s.RestrictedIPMatches),
		ConfidentialIPMatches:     int64(s.ConfidentialIPMatches),
		CountsByCategory:          cat,
		CountsBySeverity:          sev,
		CountsByScanner:           sc,
		EvidenceIDs:               evIDs,
		FailedScanners:            failed,
		IncompleteScanners:        incomplete,
	}
}
