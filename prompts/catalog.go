package prompts

import (
	"fmt"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	AssessmentTypeSecurityReview = "SECURITY_REVIEW"
	AssessmentTypeIPProvenance   = "IP_PROVENANCE"

	baseVersionSecurityReviewV1 = "stageb-security-review-v1"
	baseVersionIPProvenanceV1   = "stageb-ip-provenance-v1"
)

type templateSpec struct {
	fileName    string
	baseVersion string
}

var catalog = map[string]templateSpec{
	AssessmentTypeSecurityReview: {
		fileName:    "stageb_security_review_v1.txt",
		baseVersion: baseVersionSecurityReviewV1,
	},
	AssessmentTypeIPProvenance: {
		fileName:    "stageb_ip_provenance_v1.txt",
		baseVersion: baseVersionIPProvenanceV1,
	},
}

// AllowedAssessmentTypes returns the canonical Stage B assessment types in deterministic order.
func AllowedAssessmentTypes() []string {
	return []string{
		AssessmentTypeSecurityReview,
		AssessmentTypeIPProvenance,
	}
}

// IsAllowedAssessmentType reports whether assessmentType is a supported Stage B assessment type.
func IsAllowedAssessmentType(assessmentType string) bool {
	_, ok := catalog[strings.TrimSpace(assessmentType)]
	return ok
}

// TemplateFor returns the static server-side system prompt and deterministic promptVersion
// for assessmentType. Unknown assessment types are rejected with domain.ErrBadRequest.
func TemplateFor(assessmentType string) (systemPrompt string, promptVersion string, err error) {
	norm := strings.TrimSpace(assessmentType)
	spec, ok := catalog[norm]
	if !ok {
		return "", "", domain.BadRequest(
			"INVALID_ASSESSMENT_TYPE",
			fmt.Sprintf("unsupported Stage B assessment_type %q", assessmentType),
		)
	}

	raw, readErr := PromptFS.ReadFile(spec.fileName)
	if readErr != nil {
		return "", "", domain.WrapError(
			domain.ErrInternal,
			"PROMPT_TEMPLATE_LOAD_FAILED",
			"failed to load embedded Stage B prompt template",
			readErr,
		)
	}

	promptText := strings.TrimSpace(string(raw))
	if promptText == "" {
		return "", "", domain.Internal(
			"PROMPT_TEMPLATE_EMPTY",
			"embedded Stage B prompt template is empty",
		)
	}

	digest := domain.SHA256Hex(raw)
	version := fmt.Sprintf("%s+%s", spec.baseVersion, digest[:12])
	return promptText, version, nil
}
