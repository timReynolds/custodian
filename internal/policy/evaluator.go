package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

var standardPrecedenceFlags = []string{
	"allow",
	"req_approval",
	"req_remediation",
	"quarantine",
	"deny",
}

// PolicyInputFromMap validates stage and decodes an untyped JSON/map simulation input
// into a typed, non-nil PolicyInput.
func PolicyInputFromMap(stage string, raw map[string]any) (PolicyInput, error) {
	if stage == "" && raw != nil {
		if s, ok := raw["stage"].(string); ok {
			stage = strings.TrimSpace(s)
		}
	}
	if !IsValidStage(stage) {
		return PolicyInput{}, domain.BadRequest("INVALID_POLICY_STAGE", fmt.Sprintf("stage must be INGRESS, EGRESS, or PUSH_EGRESS, got %q", stage))
	}

	var in PolicyInput
	if len(raw) > 0 {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return PolicyInput{}, domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_INPUT", "failed to encode policy input", err)
		}
		if err := json.Unmarshal(encoded, &in); err != nil {
			return PolicyInput{}, domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_INPUT", "policy input does not match expected schema types", err)
		}
	}

	in.Stage = stage
	initNonNilPolicyInput(&in)
	return in, nil
}

// PolicyInputFromJSON validates stage and decodes raw JSON bytes into a typed PolicyInput.
func PolicyInputFromJSON(stage string, rawJSON []byte) (PolicyInput, error) {
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return PolicyInput{}, domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_INPUT", "failed to decode policy input JSON", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return PolicyInput{}, domain.BadRequest("INVALID_POLICY_INPUT", "policy input JSON contains trailing data")
	}
	if m == nil {
		return PolicyInput{}, domain.BadRequest("INVALID_POLICY_INPUT", "policy input JSON must be a JSON object, got null")
	}
	return PolicyInputFromMap(stage, m)
}

// NormalizePolicyInput ensures stage validity and initializes nil slices/maps on a PolicyInput.
func NormalizePolicyInput(stage string, in PolicyInput) (PolicyInput, error) {
	if stage == "" {
		stage = strings.TrimSpace(in.Stage)
	}
	if !IsValidStage(stage) {
		return PolicyInput{}, domain.BadRequest("INVALID_POLICY_STAGE", fmt.Sprintf("stage must be INGRESS, EGRESS, or PUSH_EGRESS, got %q", stage))
	}
	in.Stage = stage
	initNonNilPolicyInput(&in)
	return in, nil
}

func initNonNilPolicyInput(in *PolicyInput) {
	if in.Findings.CountsByCategory == nil {
		in.Findings.CountsByCategory = map[string]int64{}
	}
	if in.Findings.CountsBySeverity == nil {
		in.Findings.CountsBySeverity = map[string]int64{}
	}
	if in.Findings.CountsByScanner == nil {
		in.Findings.CountsByScanner = map[string]int64{}
	}
	if in.Findings.EvidenceIDs == nil {
		in.Findings.EvidenceIDs = []string{}
	}
	if in.Findings.FailedScanners == nil {
		in.Findings.FailedScanners = []string{}
	}
	if in.Findings.IncompleteScanners == nil {
		in.Findings.IncompleteScanners = []string{}
	}
	if in.Change.Paths == nil {
		in.Change.Paths = []string{}
	}
	if in.Repository.AllowedModelRoutes == nil {
		in.Repository.AllowedModelRoutes = []string{}
	}
	if in.Principal.Groups == nil {
		in.Principal.Groups = []string{}
	}
	if in.Principal.Roles == nil {
		in.Principal.Roles = []string{}
	}
	if in.Push.RefNames == nil {
		in.Push.RefNames = []string{}
	}
	if in.Flags == nil {
		in.Flags = map[string]bool{}
	}
}

func normalizeRawInput(stage string, rawInput any) (PolicyInput, string, error) {
	switch v := rawInput.(type) {
	case nil:
		in, err := PolicyInputFromMap(stage, nil)
		if err != nil {
			return PolicyInput{}, "", err
		}
		digest, err := domain.CanonicalJSONDigest(in)
		return in, digest, err
	case PolicyInput:
		in, err := NormalizePolicyInput(stage, v)
		if err != nil {
			return PolicyInput{}, "", err
		}
		digest, err := domain.CanonicalJSONDigest(in)
		return in, digest, err
	case *PolicyInput:
		if v == nil {
			return normalizeRawInput(stage, nil)
		}
		return normalizeRawInput(stage, *v)
	case map[string]any:
		in, err := PolicyInputFromMap(stage, v)
		if err != nil {
			return PolicyInput{}, "", err
		}
		digestTarget := any(v)
		if v == nil {
			digestTarget = in
		}
		digest, err := domain.CanonicalJSONDigest(digestTarget)
		return in, digest, err
	case json.RawMessage:
		in, err := PolicyInputFromJSON(stage, v)
		if err != nil {
			return PolicyInput{}, "", err
		}
		digest, err := domain.CanonicalJSONDigest(v)
		return in, digest, err
	case []byte:
		in, err := PolicyInputFromJSON(stage, v)
		if err != nil {
			return PolicyInput{}, "", err
		}
		digest, err := domain.CanonicalJSONDigest(v)
		return in, digest, err
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return PolicyInput{}, "", domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_INPUT", "unsupported policy input type", err)
		}
		return normalizeRawInput(stage, encoded)
	}
}

func buildActivationVars(in PolicyInput) map[string]any {
	flagsCopy := make(map[string]bool, len(in.Flags)+len(standardPrecedenceFlags))
	maps.Copy(flagsCopy, in.Flags)
	// When callers pass a partial subset of standard simulation flags, default omitted
	// precedence keys to false so `flags.deny == true` does not fail on missing key lookup,
	// while non-standard keys (e.g. `flags.unknown`) still fail closed at runtime.
	if len(in.Flags) > 0 {
		for _, k := range standardPrecedenceFlags {
			if _, ok := flagsCopy[k]; !ok {
				flagsCopy[k] = false
			}
		}
	}

	return map[string]any{
		"stage":       in.Stage,
		"findings":    in.Findings,
		"assessment":  in.Assessment,
		"change":      in.Change,
		"repository":  in.Repository,
		"workspace":   in.Workspace,
		"proposal":    in.Proposal,
		"principal":   in.Principal,
		"provenance":  in.Provenance,
		"destination": in.Destination,
		"push":        in.Push,
		"flags":       flagsCopy,
	}
}

// Evaluate runs all stage-applicable rules in a single CompiledBundle and resolves the final
// policy effect using the precedence lattice DENY > QUARANTINE > REQUIRE_REMEDIATION > REQUIRE_APPROVAL > ALLOW.
// Any CEL runtime evaluation error fails closed to DENY.
func (e *Engine) Evaluate(ctx context.Context, bundle *CompiledBundle, stage string, rawInput any) (EvalResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !IsValidStage(stage) {
		return EvalResult{}, domain.BadRequest("INVALID_POLICY_STAGE", fmt.Sprintf("stage must be INGRESS, EGRESS, or PUSH_EGRESS, got %q", stage))
	}

	in, inputDigest, err := normalizeRawInput(stage, rawInput)
	if err != nil {
		return EvalResult{}, err
	}

	ctx, span := e.tracer.Start(ctx, "policy.Evaluate", trace.WithAttributes(
		attribute.String("stage", stage),
		attribute.String("input_digest", inputDigest),
	))
	defer span.End()

	if bundle == nil {
		res := EvalResult{
			Effect:         domain.PolicyEffectDeny,
			InputDigest:    inputDigest,
			MatchedRuleIDs: []string{},
			Reasons: []domain.PolicyReason{{
				RuleID:  "bundle.missing",
				Effect:  domain.PolicyEffectDeny,
				Stage:   stage,
				Message: "no compiled policy bundle available (fail-closed)",
			}},
			Obligations: []domain.Obligation{},
			RuleTrace:   []RuleTrace{},
			HadError:    true,
		}
		e.recordObservability(ctx, stage, "", res)
		return res, nil
	}

	vars := buildActivationVars(in)
	evalRes := e.evalBundleRules(ctx, bundle, stage, vars)

	var finalEffect domain.PolicyEffect
	matchedIDs := make([]string, 0, len(evalRes.matched))
	reasons := make([]domain.PolicyReason, 0, len(evalRes.matched)+1)
	rawObls := make([]domain.Obligation, 0)

	if evalRes.hadError {
		finalEffect = domain.PolicyEffectDeny
		for _, m := range evalRes.matched {
			matchedIDs = append(matchedIDs, m.rule.Spec.ID)
			reasons = append(reasons, m.reason)
		}
		reasons = append(reasons, evalRes.errorReasons...)
	} else if len(evalRes.matched) == 0 {
		finalEffect = bundle.Bundle.Defaults.Effect
		if !finalEffect.IsValid() {
			finalEffect = domain.PolicyEffectDeny
		}
		reasons = append(reasons, domain.PolicyReason{
			RuleID:  "defaults.effect",
			Effect:  finalEffect,
			Stage:   stage,
			Message: "no policy rules matched",
		})
	} else {
		finalEffect = domain.PolicyEffectAllow
		for _, m := range evalRes.matched {
			matchedIDs = append(matchedIDs, m.rule.Spec.ID)
			reasons = append(reasons, m.reason)
			finalEffect = finalEffect.MoreRestrictive(m.rule.Spec.Effect)
			rawObls = append(rawObls, m.rule.Obligations...)
		}
	}

	obligations := finalizeObligations(finalEffect, rawObls)
	res := EvalResult{
		Effect:         finalEffect,
		BundleDigest:   bundle.Digest,
		InputDigest:    inputDigest,
		MatchedRuleIDs: matchedIDs,
		Reasons:        reasons,
		Obligations:    obligations,
		RuleTrace:      evalRes.traces,
		HadError:       evalRes.hadError,
	}

	scope := string(bundle.Scope)
	if scope == "" {
		scope = string(bundle.Bundle.Metadata.Scope)
	}
	e.recordObservability(ctx, stage, scope, res)
	return res, nil
}

// ComposeAndEvaluate enforces org-before-repo policy composition:
//  1. Both ORG and REPO stage-applicable rules are evaluated.
//  2. ORG rules with overridable=false (the default for ORG rules when omitted) cannot be
//     overridden or weakened by any REPO rule or REPO defaults.effect.
//  3. Even overridable=true ORG rules cannot be weakened by a less-restrictive REPO rule.
//  4. Additive REPO restrictions (e.g., REQUIRE_APPROVAL when 0 ORG rules match) apply.
//  5. When 0 rules match across BOTH bundles, defaults resolve to org.Defaults.MoreRestrictive(repo.Defaults).
func (e *Engine) ComposeAndEvaluate(ctx context.Context, orgBundle, repoBundle *CompiledBundle, stage string, rawInput any) (EvalResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !IsValidStage(stage) {
		return EvalResult{}, domain.BadRequest("INVALID_POLICY_STAGE", fmt.Sprintf("stage must be INGRESS, EGRESS, or PUSH_EGRESS, got %q", stage))
	}
	if orgBundle == nil && repoBundle == nil {
		return e.Evaluate(ctx, nil, stage, rawInput)
	}
	if orgBundle == nil {
		return e.Evaluate(ctx, repoBundle, stage, rawInput)
	}
	if repoBundle == nil {
		return e.Evaluate(ctx, orgBundle, stage, rawInput)
	}

	in, inputDigest, err := normalizeRawInput(stage, rawInput)
	if err != nil {
		return EvalResult{}, err
	}

	composedDigest, err := domain.CanonicalJSONDigest(struct {
		OrgDigest  string `json:"org_digest"`
		RepoDigest string `json:"repo_digest"`
	}{
		OrgDigest:  orgBundle.Digest,
		RepoDigest: repoBundle.Digest,
	})
	if err != nil {
		composedDigest = domain.SHA256Hex([]byte(orgBundle.Digest + ":" + repoBundle.Digest))
	}

	ctx, span := e.tracer.Start(ctx, "policy.ComposeAndEvaluate", trace.WithAttributes(
		attribute.String("stage", stage),
		attribute.String("bundle_digest", composedDigest),
		attribute.String("input_digest", inputDigest),
	))
	defer span.End()

	vars := buildActivationVars(in)
	orgEval := e.evalBundleRules(ctx, orgBundle, stage, vars)
	repoEval := e.evalBundleRules(ctx, repoBundle, stage, vars)

	traces := make([]RuleTrace, 0, len(orgEval.traces)+len(repoEval.traces))
	traces = append(traces, orgEval.traces...)
	traces = append(traces, repoEval.traces...)

	hadError := orgEval.hadError || repoEval.hadError

	// Index matched repo rules by ID to evaluate override attempts against matched org rules.
	repoByID := make(map[string]matchedRule, len(repoEval.matched))
	for _, rm := range repoEval.matched {
		repoByID[rm.rule.Spec.ID] = rm
	}

	activeMatches := make([]matchedRule, 0, len(orgEval.matched)+len(repoEval.matched))
	suppressedRepoIDs := make(map[string]struct{})

	for _, om := range orgEval.matched {
		overridable := om.rule.Spec.IsOverridable(domain.PolicyScopeOrg)
		if rm, hasRepoSameID := repoByID[om.rule.Spec.ID]; hasRepoSameID {
			if overridable && rm.rule.Spec.Effect.Rank() >= om.rule.Spec.Effect.Rank() {
				// Repo rule is permitted to replace this overridable org rule without weakening it.
				continue
			}
			// Org rule is non-overridable or repo attempted to weaken it: org rule stands, repo override ignored.
			suppressedRepoIDs[rm.rule.Spec.ID] = struct{}{}
		}
		activeMatches = append(activeMatches, om)
	}

	for _, rm := range repoEval.matched {
		if _, suppressed := suppressedRepoIDs[rm.rule.Spec.ID]; suppressed {
			continue
		}
		activeMatches = append(activeMatches, rm)
	}

	var finalEffect domain.PolicyEffect
	matchedIDs := make([]string, 0, len(activeMatches))
	reasons := make([]domain.PolicyReason, 0, len(activeMatches)+2)
	rawObls := make([]domain.Obligation, 0)

	if hadError {
		finalEffect = domain.PolicyEffectDeny
		for _, m := range activeMatches {
			matchedIDs = append(matchedIDs, m.rule.Spec.ID)
			reasons = append(reasons, m.reason)
		}
		reasons = append(reasons, orgEval.errorReasons...)
		reasons = append(reasons, repoEval.errorReasons...)
	} else if len(activeMatches) == 0 {
		finalEffect = orgBundle.Bundle.Defaults.Effect.MoreRestrictive(repoBundle.Bundle.Defaults.Effect)
		if !finalEffect.IsValid() {
			finalEffect = domain.PolicyEffectDeny
		}
		reasons = append(reasons, domain.PolicyReason{
			RuleID:  "defaults.effect",
			Effect:  finalEffect,
			Stage:   stage,
			Message: "no policy rules matched across organization or repository bundles",
		})
	} else {
		finalEffect = domain.PolicyEffectAllow
		for _, m := range activeMatches {
			matchedIDs = append(matchedIDs, m.rule.Spec.ID)
			reasons = append(reasons, m.reason)
			finalEffect = finalEffect.MoreRestrictive(m.rule.Spec.Effect)
			rawObls = append(rawObls, m.rule.Obligations...)
		}
	}

	obligations := finalizeObligations(finalEffect, rawObls)
	res := EvalResult{
		Effect:         finalEffect,
		BundleDigest:   composedDigest,
		InputDigest:    inputDigest,
		MatchedRuleIDs: matchedIDs,
		Reasons:        reasons,
		Obligations:    obligations,
		RuleTrace:      traces,
		HadError:       hadError,
	}

	e.recordObservability(ctx, stage, "COMPOSED", res)
	return res, nil
}

// ComposeInspectionConfig merges Stage A mandatory scanners and Stage B decision-model
// triggers with organization-first precedence.
func ComposeInspectionConfig(orgBundle, repoBundle *CompiledBundle) InspectionConfig {
	out := InspectionConfig{
		Mandatory: []string{},
	}
	seenMandatory := make(map[string]struct{})
	seenTriggers := make(map[string]struct{})
	var route string
	var triggers []string

	for _, b := range []*CompiledBundle{orgBundle, repoBundle} {
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
		out.DecisionModel = &DecisionModelConfig{
			Route:   route,
			Trigger: triggers,
		}
	}
	return out
}

type matchedRule struct {
	rule   CompiledRule
	reason domain.PolicyReason
}

type bundleRuleEval struct {
	matched      []matchedRule
	traces       []RuleTrace
	errorReasons []domain.PolicyReason
	hadError     bool
}

func (e *Engine) evalBundleRules(ctx context.Context, bundle *CompiledBundle, stage string, vars map[string]any) bundleRuleEval {
	out := bundleRuleEval{
		traces: make([]RuleTrace, 0, len(bundle.Rules)),
	}
	for _, r := range bundle.Rules {
		if !r.Spec.AppliesToStage(stage) {
			continue
		}
		matched, evalErr := evalSingleRule(ctx, r, vars)
		if evalErr != nil {
			out.hadError = true
			out.traces = append(out.traces, RuleTrace{
				RuleID:  r.Spec.ID,
				Matched: false,
				Effect:  domain.PolicyEffectDeny,
				Error:   evalErr.Error(),
			})
			out.errorReasons = append(out.errorReasons, domain.PolicyReason{
				RuleID:  r.Spec.ID,
				Effect:  domain.PolicyEffectDeny,
				Stage:   stage,
				Message: "cel evaluation error (fail-closed)",
			})
			continue
		}

		out.traces = append(out.traces, RuleTrace{
			RuleID:  r.Spec.ID,
			Matched: matched,
			Effect:  r.Spec.Effect,
		})
		if matched {
			msg := r.Spec.Message
			if msg == "" {
				msg = r.Spec.Description
			}
			out.matched = append(out.matched, matchedRule{
				rule: r,
				reason: domain.PolicyReason{
					RuleID:  r.Spec.ID,
					Effect:  r.Spec.Effect,
					Stage:   stage,
					Message: msg,
				},
			})
		}
	}
	return out
}

func evalSingleRule(ctx context.Context, r CompiledRule, vars map[string]any) (matched bool, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			matched = false
			err = fmt.Errorf("cel panic: %v", rec)
		}
	}()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}

	val, _, evalErr := r.Program.ContextEval(ctx, vars)
	if evalErr != nil {
		return false, evalErr
	}
	if val == nil {
		return false, fmt.Errorf("cel evaluation returned nil value")
	}
	b, ok := val.Value().(bool)
	if !ok {
		return false, fmt.Errorf("cel expression returned non-boolean value %T", val.Value())
	}
	return b, nil
}

func finalizeObligations(finalEffect domain.PolicyEffect, raw []domain.Obligation) []domain.Obligation {
	if finalEffect.BlocksPublication() || len(raw) == 0 {
		return []domain.Obligation{}
	}

	type oblKey struct {
		typ   string
		group string
	}
	order := make([]oblKey, 0, len(raw))
	byKey := make(map[oblKey]domain.Obligation, len(raw))

	for _, obl := range raw {
		typ := strings.TrimSpace(obl.Type)
		if typ == "" {
			typ = DefaultObligationType
		}
		grp := strings.TrimSpace(obl.ReviewerGroup)
		if grp == "" {
			continue
		}
		minVal := obl.Minimum
		if minVal < 1 {
			minVal = 1
		}

		k := oblKey{typ: typ, group: grp}
		if existing, exists := byKey[k]; exists {
			if minVal > existing.Minimum {
				existing.Minimum = minVal
				byKey[k] = existing
			}
			continue
		}
		order = append(order, k)
		byKey[k] = domain.Obligation{
			Type:          typ,
			ReviewerGroup: grp,
			Minimum:       minVal,
		}
	}

	out := make([]domain.Obligation, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out
}

func (e *Engine) recordObservability(ctx context.Context, stage, scope string, res EvalResult) {
	if e.metrics != nil {
		e.metrics.IncPolicyDecision(stage, string(res.Effect))
		if res.Effect.BlocksPublication() {
			s := scope
			if s == "" {
				s = "DEFAULT"
			}
			e.metrics.IncPolicyDenial(stage, s)
		}
	}
	if e.logger != nil {
		l := observability.LoggerWithTrace(ctx, e.logger)
		l.Info("policy evaluation completed",
			slog.String("stage", stage),
			slog.String("effect", string(res.Effect)),
			slog.String("bundle_digest", res.BundleDigest),
			slog.String("input_digest", res.InputDigest),
			slog.String("status", evalStatusLabel(res)),
		)
	}
}

func evalStatusLabel(res EvalResult) string {
	if res.HadError {
		return "ERROR_FAIL_CLOSED"
	}
	if res.Effect.BlocksPublication() {
		return "BLOCKED"
	}
	return "PASSED"
}

// RequiresHumanApproval enforces the Custodian system invariant that every non-blocked
// publication still requires explicit human approval bound to the publication manifest digest.
func RequiresHumanApproval(res EvalResult) bool {
	return !res.Effect.BlocksPublication()
}

// SortedRuleIDs returns a deterministic copy of matched rule IDs without mutating EvalResult.
func SortedRuleIDs(res EvalResult) []string {
	out := slices.Clone(res.MatchedRuleIDs)
	slices.Sort(out)
	return out
}
