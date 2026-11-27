package workflow

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
)

type persistedCompiledBundle struct {
	row      persistence.PolicyBundleRow
	compiled *policy.CompiledBundle
}

// SyncPolicyDir loads and compiles all YAML policy bundles from policyDir and upserts
// ORG-scoped bundles into PostgreSQL policy_bundles with ActivatedAt set so Stage C
// policy_decisions FK references resolve deterministically.
func SyncPolicyDir(ctx context.Context, store *persistence.Store, engine *policy.Engine, policyDir string, now time.Time) (int, error) {
	policyDir = strings.TrimSpace(policyDir)
	if policyDir == "" {
		return 0, nil
	}
	if store == nil {
		return 0, domain.BadRequest("INVALID_WORKFLOW_CONFIG", "persistence store is required to sync policy directory")
	}
	if engine == nil {
		var err error
		engine, err = policy.NewEngine()
		if err != nil {
			return 0, err
		}
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	bundles, err := engine.LoadDir(policyDir)
	if err != nil {
		return 0, err
	}
	orgBundles, _ := policy.PartitionByScope(bundles)

	upserted := 0
	for _, b := range orgBundles {
		if b == nil {
			continue
		}
		_, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name:        b.Bundle.Metadata.Name,
			Version:     b.Bundle.Metadata.Version,
			Scope:       domain.PolicyScopeOrg,
			Digest:      b.Digest,
			Definition:  b.Definition,
			ActivatedAt: &now,
			CreatedAt:   now,
		})
		if err != nil {
			return upserted, err
		}
		upserted++
	}
	return upserted, nil
}

func (s *Service) resolveActivePolicyBundles(ctx context.Context, repositoryID uuid.UUID) ([]persistedCompiledBundle, []persistedCompiledBundle, error) {
	orgRows, err := s.store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(orgRows) == 0 && strings.TrimSpace(s.cfg.PolicyDir) != "" {
		if _, syncErr := SyncPolicyDir(ctx, s.store, s.policyEngine, s.cfg.PolicyDir, s.now()); syncErr != nil {
			return nil, nil, syncErr
		}
		orgRows, err = s.store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
		if err != nil {
			return nil, nil, err
		}
	}

	var repoRows []persistence.PolicyBundleRow
	if repositoryID != uuid.Nil {
		repoRows, err = s.store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeRepo, &repositoryID)
		if err != nil {
			return nil, nil, err
		}
	}

	// Track active REPO bundle digests so an unscoped PolicyDir copy of an explicit
	// DB REPO bundle is not double-evaluated as ORG. Never suppress by Name@Version,
	// and never suppress explicit Scope == ORG bundles (RG-06).
	repoDigests := make(map[string]struct{}, len(repoRows))
	repoBundles := make([]persistedCompiledBundle, 0, len(repoRows))
	for _, r := range repoRows {
		compiled, errs := s.policyEngine.CompileDomainBundle(r.ToDomain())
		if len(errs) > 0 {
			return nil, nil, domain.Unprocessable("INVALID_POLICY_BUNDLE", errs[0].Message)
		}
		repoDigests[r.Digest] = struct{}{}
		repoBundles = append(repoBundles, persistedCompiledBundle{row: r, compiled: compiled})
	}

	orgBundles := make([]persistedCompiledBundle, 0, len(orgRows))
	for _, r := range orgRows {
		compiled, errs := s.policyEngine.CompileDomainBundle(r.ToDomain())
		if len(errs) > 0 {
			return nil, nil, domain.Unprocessable("INVALID_POLICY_BUNDLE", errs[0].Message)
		}
		if compiled.Bundle.Metadata.Scope == "" {
			if _, sameDigestAsRepo := repoDigests[r.Digest]; sameDigestAsRepo {
				continue
			}
		}
		orgBundles = append(orgBundles, persistedCompiledBundle{row: r, compiled: compiled})
	}

	return orgBundles, repoBundles, nil
}

func bundleAppliesToStage(b *policy.CompiledBundle, stage string) bool {
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

func filterBundlesForStage(bundles []persistedCompiledBundle, stage string) []persistedCompiledBundle {
	out := make([]persistedCompiledBundle, 0, len(bundles))
	for _, b := range bundles {
		if bundleAppliesToStage(b.compiled, stage) {
			out = append(out, b)
		}
	}
	return out
}

func composeInspectionConfigForStage(stage string, orgBundles, repoBundles []persistedCompiledBundle) policy.InspectionConfig {
	out := policy.InspectionConfig{
		Mandatory: []string{},
	}
	seenMandatory := make(map[string]struct{})
	seenTriggers := make(map[string]struct{})
	var route string
	var triggers []string

	stageOrg := filterBundlesForStage(orgBundles, stage)
	stageRepo := filterBundlesForStage(repoBundles, stage)

	ordered := make([]persistedCompiledBundle, 0, len(stageOrg)+len(stageRepo))
	ordered = append(ordered, stageOrg...)
	ordered = append(ordered, stageRepo...)

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

// resolveEvaluationModelRoute chooses the Stage B model route for an evaluation.
// Explicit workspace model routes always take precedence. Otherwise, if an ORG
// default route is absent or not in repo.AllowedModelRoutes while a REPO bundle
// specifies a route that is in repo.AllowedModelRoutes, the REPO route is used
// instead of letting an ORG default shadow the repository's authorized route.
func resolveEvaluationModelRoute(
	workspaceRoute string,
	allowedRepoRoutes []string,
	orgBundles, repoBundles []persistedCompiledBundle,
	inspCfg policy.InspectionConfig,
) string {
	if explicit := strings.TrimSpace(workspaceRoute); explicit != "" {
		return explicit
	}
	stageOrg := filterBundlesForStage(orgBundles, policy.StageEgress)
	stageRepo := filterBundlesForStage(repoBundles, policy.StageEgress)
	if len(stageOrg) == 0 && len(stageRepo) == 0 {
		stageOrg = orgBundles
		stageRepo = repoBundles
	}
	orgRoute := firstConfiguredModelRoute(stageOrg)
	repoRoute := firstAuthorizedModelRoute(stageRepo, allowedRepoRoutes)
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
		return strings.TrimSpace(inspCfg.DecisionModel.Route)
	}
	return ""
}

func firstConfiguredModelRoute(bundles []persistedCompiledBundle) string {
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

func firstAuthorizedModelRoute(bundles []persistedCompiledBundle, allowed []string) string {
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

type composedEvalOutcome struct {
	result          policy.EvalResult
	primaryBundleID uuid.UUID
	orgBundleID     *uuid.UUID
	repoBundleID    *uuid.UUID
}

// evaluateComposedBundles evaluates all active ORG bundles and repo-specific REPO bundles
// preserving org-before-repo precedence (DENY > QUARANTINE > REQUIRE_REMEDIATION > REQUIRE_APPROVAL > ALLOW)
// and ensuring non-overridable ORG rules cannot be weakened by any REPO bundle.
func (s *Service) evaluateComposedBundles(
	ctx context.Context,
	orgBundles, repoBundles []persistedCompiledBundle,
	stage string,
	input policy.PolicyInput,
) (composedEvalOutcome, error) {
	if len(orgBundles) == 0 && len(repoBundles) == 0 {
		res, err := s.policyEngine.Evaluate(ctx, nil, stage, input)
		return composedEvalOutcome{result: res}, err
	}

	stageOrg := filterBundlesForStage(orgBundles, stage)
	stageRepo := filterBundlesForStage(repoBundles, stage)
	if len(stageOrg) > 0 || len(stageRepo) > 0 {
		orgBundles = stageOrg
		repoBundles = stageRepo
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
		res, err := s.policyEngine.ComposeAndEvaluate(ctx, orgC, repoC, stage, input)
		return composedEvalOutcome{
			result:          res,
			primaryBundleID: primaryID,
			orgBundleID:     orgID,
			repoBundleID:    repoID,
		}, err
	}

	if len(orgBundles) == 0 && len(repoBundles) == 1 {
		res, err := s.policyEngine.Evaluate(ctx, repoBundles[0].compiled, stage, input)
		repoIDVal := repoBundles[0].row.ID
		return composedEvalOutcome{
			result:          res,
			primaryBundleID: repoIDVal,
			repoBundleID:    &repoIDVal,
		}, err
	}

	// Multiple ORG and/or REPO bundles: evaluate every ORG bundle paired with every REPO bundle
	// (or standalone if one side is empty), aggregate matched rules & obligations, and take the
	// most restrictive effect so no ORG rule can be shadowed by another bundle.
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

	var pairs []struct {
		org  *persistedCompiledBundle
		repo *persistedCompiledBundle
	}
	switch {
	case len(orgBundles) > 0 && len(repoBundles) > 0:
		for i := range orgBundles {
			for j := range repoBundles {
				pairs = append(pairs, struct {
					org  *persistedCompiledBundle
					repo *persistedCompiledBundle
				}{org: &orgBundles[i], repo: &repoBundles[j]})
			}
		}
	case len(orgBundles) > 0:
		for i := range orgBundles {
			pairs = append(pairs, struct {
				org  *persistedCompiledBundle
				repo *persistedCompiledBundle
			}{org: &orgBundles[i]})
		}
	default:
		for j := range repoBundles {
			pairs = append(pairs, struct {
				org  *persistedCompiledBundle
				repo *persistedCompiledBundle
			}{repo: &repoBundles[j]})
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
		res, err := s.policyEngine.ComposeAndEvaluate(ctx, orgC, repoC, stage, input)
		if err != nil {
			return composedEvalOutcome{}, err
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
			orgTraceCount = countRulesForStage(p.org.compiled, stage)
		}
		if orgTraceCount > len(res.RuleTrace) {
			orgTraceCount = len(res.RuleTrace)
		}
		if p.org != nil {
			if orgMatched, orgRank := traceEffectiveRank(res.RuleTrace[:orgTraceCount]); orgMatched && orgRank > winningOrgRank {
				winningOrgRank = orgRank
				winningOrgID = p.org.row.ID
			}
		}
		if p.repo != nil {
			if repoMatched, repoRank := traceEffectiveRank(res.RuleTrace[orgTraceCount:]); repoMatched && repoRank > winningRepoRank {
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

	return composedEvalOutcome{
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

func countRulesForStage(b *policy.CompiledBundle, stage string) int {
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

func traceEffectiveRank(traces []policy.RuleTrace) (bool, int) {
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

func hasIngressAllowRule(bundles ...[]persistedCompiledBundle) bool {
	for _, group := range bundles {
		for _, entry := range group {
			if entry.compiled == nil {
				continue
			}
			for _, rule := range entry.compiled.Rules {
				if rule.Spec.Effect != domain.PolicyEffectAllow {
					continue
				}
				for _, st := range rule.Spec.Stages {
					if strings.EqualFold(st, policy.StageIngress) {
						return true
					}
				}
			}
		}
	}
	return false
}
