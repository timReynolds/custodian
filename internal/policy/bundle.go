package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/timreynolds/custodian/internal/domain"
)

// ParseBundle strictly decodes a single-document YAML or JSON PolicyBundle,
// normalizes defaults/obligations, and validates structural invariants.
func ParseBundle(raw []byte) (Bundle, []ValidationError) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Bundle{}, []ValidationError{{
			Code:    "INVALID_YAML",
			Message: "policy bundle must not be empty",
		}}
	}

	var b Bundle
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, []ValidationError{{
			Code:    "INVALID_YAML",
			Message: fmt.Sprintf("failed to parse policy bundle YAML: %v", err),
		}}
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		msg := "multi-document YAML is not permitted for policy bundles"
		if err != nil {
			msg = fmt.Sprintf("trailing YAML content is invalid: %v", err)
		}
		return Bundle{}, []ValidationError{{
			Code:    "MULTI_DOCUMENT_YAML",
			Message: msg,
		}}
	}

	normalizeBundle(&b)
	errs := validateBundleStructure(&b)
	return b, errs
}

// ParseDomainBundle decodes a persisted domain.PolicyBundle's JSON definition.
func ParseDomainBundle(db domain.PolicyBundle) (Bundle, []ValidationError) {
	b, errs := ParseBundle(db.Definition)
	if len(errs) > 0 {
		return b, errs
	}
	if db.Scope != "" && !db.Scope.IsValid() {
		errs = append(errs, ValidationError{
			Code:    "INVALID_SCOPE",
			Message: fmt.Sprintf("unsupported bundle scope %q", db.Scope),
		})
	}
	return b, errs
}

// CanonicalBundleJSON returns deterministic canonical JSON bytes and the 64-char hex SHA-256 digest.
func CanonicalBundleJSON(b Bundle) (json.RawMessage, string, error) {
	canonical, err := domain.CanonicalJSONBytes(b)
	if err != nil {
		return nil, "", err
	}
	return json.RawMessage(canonical), domain.SHA256Hex(canonical), nil
}

func normalizeBundle(b *Bundle) {
	b.APIVersion = strings.TrimSpace(b.APIVersion)
	b.Kind = strings.TrimSpace(b.Kind)
	b.Metadata.Name = strings.TrimSpace(b.Metadata.Name)
	b.Metadata.Version = strings.TrimSpace(b.Metadata.Version)
	b.Metadata.Scope = domain.PolicyScope(strings.TrimSpace(string(b.Metadata.Scope)))

	b.Defaults.Effect = domain.PolicyEffect(strings.TrimSpace(string(b.Defaults.Effect)))
	if b.Defaults.Effect == "" {
		b.Defaults.Effect = domain.PolicyEffectDeny
	}
	b.Defaults.OnError = domain.PolicyEffect(strings.TrimSpace(string(b.Defaults.OnError)))
	if b.Defaults.OnError == "" {
		b.Defaults.OnError = domain.PolicyEffectDeny
	}

	if b.Inspection != nil {
		for i := range b.Inspection.Mandatory {
			b.Inspection.Mandatory[i] = strings.TrimSpace(b.Inspection.Mandatory[i])
		}
		if b.Inspection.DecisionModel != nil {
			b.Inspection.DecisionModel.Route = strings.TrimSpace(b.Inspection.DecisionModel.Route)
			for i := range b.Inspection.DecisionModel.Trigger {
				b.Inspection.DecisionModel.Trigger[i] = strings.TrimSpace(b.Inspection.DecisionModel.Trigger[i])
			}
		}
	}

	for i := range b.Rules {
		r := &b.Rules[i]
		r.ID = strings.TrimSpace(r.ID)
		r.When = strings.TrimSpace(r.When)
		r.Effect = domain.PolicyEffect(strings.TrimSpace(string(r.Effect)))
		for j := range r.Stages {
			r.Stages[j] = strings.TrimSpace(r.Stages[j])
		}
		for j := range r.Obligations {
			obl := &r.Obligations[j]
			obl.Type = strings.TrimSpace(obl.Type)
			if obl.Type == "" {
				obl.Type = DefaultObligationType
			}
			obl.ReviewerGroup = strings.TrimSpace(obl.ReviewerGroup)
			if obl.Minimum == nil {
				minVal := 1
				obl.Minimum = &minVal
			}
		}
	}
}

func validateBundleStructure(b *Bundle) []ValidationError {
	var errs []ValidationError

	if b.APIVersion != APIVersionV1 {
		errs = append(errs, ValidationError{
			Code:    "UNSUPPORTED_API_VERSION",
			Message: fmt.Sprintf("apiVersion must be %q, got %q", APIVersionV1, b.APIVersion),
		})
	}
	if b.Kind != KindPolicyBundle {
		errs = append(errs, ValidationError{
			Code:    "INVALID_KIND",
			Message: fmt.Sprintf("kind must be %q, got %q", KindPolicyBundle, b.Kind),
		})
	}
	if b.Metadata.Name == "" || b.Metadata.Version == "" {
		errs = append(errs, ValidationError{
			Code:    "INVALID_METADATA",
			Message: "metadata.name and metadata.version must not be empty",
		})
	}
	if b.Metadata.Scope != "" && !b.Metadata.Scope.IsValid() {
		errs = append(errs, ValidationError{
			Code:    "INVALID_SCOPE",
			Message: fmt.Sprintf("metadata.scope must be ORG or REPO, got %q", b.Metadata.Scope),
		})
	}
	if !b.Defaults.Effect.IsValid() {
		errs = append(errs, ValidationError{
			Code:    "INVALID_DEFAULT_EFFECT",
			Message: fmt.Sprintf("defaults.effect %q is invalid", b.Defaults.Effect),
		})
	}
	if b.Defaults.OnError != domain.PolicyEffectDeny {
		errs = append(errs, ValidationError{
			Code:    "INVALID_ON_ERROR",
			Message: fmt.Sprintf("defaults.onError must be %q for fail-closed enforcement, got %q", domain.PolicyEffectDeny, b.Defaults.OnError),
		})
	}
	if len(b.Rules) == 0 {
		errs = append(errs, ValidationError{
			Code:    "EMPTY_RULES",
			Message: "policy bundle must define at least one rule",
		})
		return errs
	}

	seenIDs := make(map[string]struct{}, len(b.Rules))
	for i, r := range b.Rules {
		if r.ID == "" {
			errs = append(errs, ValidationError{
				Code:    "INVALID_RULE_ID",
				Message: fmt.Sprintf("rules[%d].id must not be empty", i),
			})
		} else if _, dup := seenIDs[r.ID]; dup {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    "DUPLICATE_RULE_ID",
				Message: fmt.Sprintf("duplicate rule id %q", r.ID),
			})
		} else {
			seenIDs[r.ID] = struct{}{}
		}

		if len(r.Stages) == 0 {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    "INVALID_RULE_STAGES",
				Message: "rule must specify at least one stage (INGRESS or EGRESS)",
			})
		} else {
			seenStages := make(map[string]struct{}, len(r.Stages))
			for _, st := range r.Stages {
				if !IsValidStage(st) {
					errs = append(errs, ValidationError{
						RuleID:  r.ID,
						Code:    "INVALID_RULE_STAGES",
						Message: fmt.Sprintf("unsupported rule stage %q (must be INGRESS or EGRESS)", st),
					})
				} else if _, dup := seenStages[st]; dup {
					errs = append(errs, ValidationError{
						RuleID:  r.ID,
						Code:    "INVALID_RULE_STAGES",
						Message: fmt.Sprintf("duplicate stage %q in rule", st),
					})
				} else {
					seenStages[st] = struct{}{}
				}
			}
		}

		if r.When == "" {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    "EMPTY_RULE_CONDITION",
				Message: "rule `when` CEL expression must not be empty",
			})
		}
		if !r.Effect.IsValid() {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    "INVALID_RULE_EFFECT",
				Message: fmt.Sprintf("invalid rule effect %q", r.Effect),
			})
		}

		if len(r.Obligations) > 0 {
			if r.Effect != domain.PolicyEffectRequireApproval {
				errs = append(errs, ValidationError{
					RuleID:  r.ID,
					Code:    "INVALID_OBLIGATION",
					Message: fmt.Sprintf("obligations are only allowed on %s rules, got %s", domain.PolicyEffectRequireApproval, r.Effect),
				})
			}
			for j, obl := range r.Obligations {
				if obl.Type == "" {
					errs = append(errs, ValidationError{
						RuleID:  r.ID,
						Code:    "INVALID_OBLIGATION",
						Message: fmt.Sprintf("obligations[%d].type must not be empty", j),
					})
				}
				if obl.ReviewerGroup == "" {
					errs = append(errs, ValidationError{
						RuleID:  r.ID,
						Code:    "INVALID_OBLIGATION",
						Message: fmt.Sprintf("obligations[%d].reviewer_group must not be empty", j),
					})
				}
				if obl.Minimum == nil || *obl.Minimum < 1 {
					errs = append(errs, ValidationError{
						RuleID:  r.ID,
						Code:    "INVALID_OBLIGATION",
						Message: fmt.Sprintf("obligations[%d].minimum must be >= 1", j),
					})
				}
			}
		}
	}

	return errs
}
