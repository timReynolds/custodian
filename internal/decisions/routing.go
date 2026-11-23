package decisions

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	modelVersionRouteUnauthorized = "route-unauthorized"
	modelRouteMissingPlaceholder  = "route-missing"
)

// AuthorizeModelRoute enforces repository enablement, valid classification,
// requested route presence in allowedRoutes, and optional classification policy
// constraints BEFORE any gateway HTTP call is made.
func AuthorizeModelRoute(repo domain.Repository, allowedRoutes []string, requestedRoute string, policy *RoutePolicy) error {
	if !repo.Enabled {
		return domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled for model assessment")
	}
	if !repo.Classification.IsValid() {
		return domain.Forbidden("INVALID_CLASSIFICATION", "repository classification is invalid")
	}

	route := strings.TrimSpace(requestedRoute)
	if route == "" {
		return domain.Forbidden("MODEL_ROUTE_MISSING", "model_route is required for assessment")
	}

	if !containsNormalizedRoute(allowedRoutes, route) {
		return domain.Forbidden(
			"MODEL_ROUTE_UNAUTHORIZED",
			fmt.Sprintf("model_route %q is not in repository allowed_model_routes", route),
		)
	}

	if policy != nil {
		if len(policy.ClassificationRoutes) > 0 || policy.RequireClassificationRule {
			classRoutes, ok := policy.ClassificationRoutes[repo.Classification]
			if !ok {
				if policy.RequireClassificationRule {
					return domain.Forbidden(
						"MODEL_ROUTE_CLASSIFICATION_MISMATCH",
						fmt.Sprintf("no route policy defined for classification %q", repo.Classification),
					)
				}
			} else if !containsNormalizedRoute(classRoutes, route) {
				return domain.Forbidden(
					"MODEL_ROUTE_CLASSIFICATION_MISMATCH",
					fmt.Sprintf("model_route %q is not permitted for classification %q", route, repo.Classification),
				)
			}
		}

		if maxClass, ok := policy.RouteMaxClassification[route]; ok {
			if !maxClass.IsValid() || classificationRank(repo.Classification) > classificationRank(maxClass) {
				return domain.Forbidden(
					"MODEL_ROUTE_CLASSIFICATION_MISMATCH",
					fmt.Sprintf("model_route %q exceeds maximum allowed classification for %q", route, repo.Classification),
				)
			}
		}
	}

	return nil
}

func containsNormalizedRoute(routes []string, target string) bool {
	for _, r := range routes {
		if strings.TrimSpace(r) == target && target != "" {
			return true
		}
	}
	return false
}

func classificationRank(c domain.Classification) int {
	switch c {
	case domain.ClassificationPublic:
		return 1
	case domain.ClassificationInternal:
		return 2
	case domain.ClassificationConfidential:
		return 3
	case domain.ClassificationRestricted:
		return 4
	default:
		return 99
	}
}

func buildUnauthorizedAssessment(
	req AssessRequest,
	assessmentType string,
	promptVersion string,
	inputDigest string,
	reason string,
	now time.Time,
) (domain.ModelAssessment, error) {
	route := strings.TrimSpace(req.ModelRoute)
	if route == "" {
		route = modelRouteMissingPlaceholder
	}

	limitation := strings.TrimSpace(reason)
	if limitation == "" {
		limitation = "model route unauthorized for repository classification"
	}

	result := domain.AssessmentResult{
		SchemaVersion:  "1",
		AssessmentType: assessmentType,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionIndeterminate,
		Confidence:     0.0,
		Summary:        "Assessment indeterminate: model route is not authorized for repository classification",
		Findings:       []domain.AssessmentFinding{},
		Limitations:    []string{limitation},
	}

	outputDigest, err := domain.CanonicalJSONDigest(result)
	if err != nil {
		return domain.ModelAssessment{}, domain.WrapError(
			domain.ErrInternal,
			"ASSESSMENT_DIGEST_ERROR",
			"failed to compute output digest for unauthorized route assessment",
			err,
		)
	}

	id, err := domain.NewID()
	if err != nil {
		return domain.ModelAssessment{}, err
	}

	return domain.ModelAssessment{
		ID:             id,
		ProposalID:     req.ProposalID,
		ArtifactID:     req.ArtifactID,
		ModelRoute:     route,
		ModelVersion:   modelVersionRouteUnauthorized,
		PromptVersion:  promptVersion,
		AssessmentType: assessmentType,
		Status:         domain.AssessmentStatusIndeterminate,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionIndeterminate,
		Result:         result,
		EvidenceIDs:    []string{},
		InputDigest:    inputDigest,
		OutputDigest:   outputDigest,
		CreatedAt:      now.UTC(),
	}, nil
}

// cloneSortedStrings returns a non-nil sorted copy of input strings.
func cloneSortedStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	slices.Sort(out)
	return out
}
