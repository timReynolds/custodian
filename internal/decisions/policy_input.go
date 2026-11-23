package decisions

import (
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/prompts"
)

// PolicyAssessmentFact projects a domain.ModelAssessment into the verified
// Stage C CEL PolicyInput.assessment structure.
type PolicyAssessmentFact struct {
	Status         string `json:"status"`
	IPRisk         string `json:"ip_risk"`
	Risk           string `json:"risk"`
	Disposition    string `json:"disposition"`
	ModelRoute     string `json:"model_route"`
	ModelVersion   string `json:"model_version"`
	PromptVersion  string `json:"prompt_version"`
	AssessmentType string `json:"assessment_type"`
}

// ToMap returns a map representation compatible with Stage C CEL PolicyInput evaluation.
func (f PolicyAssessmentFact) ToMap() map[string]any {
	return map[string]any{
		"status":          f.Status,
		"ip_risk":         f.IPRisk,
		"risk":            f.Risk,
		"disposition":     f.Disposition,
		"model_route":     f.ModelRoute,
		"model_version":   f.ModelVersion,
		"prompt_version":  f.PromptVersion,
		"assessment_type": f.AssessmentType,
	}
}

// ToPolicyAssessmentFact maps a Stage B ModelAssessment into Stage C PolicyInput.assessment.
// Incomplete, failed, or indeterminate assessments always project ip_risk="NONE" and
// preserve non-COMPLETE status so Stage C fail-closed CEL rules (assessment.status != "COMPLETE")
// trigger QUARANTINE.
func ToPolicyAssessmentFact(a domain.ModelAssessment) PolicyAssessmentFact {
	risk := string(domain.RiskLevelNone)
	if a.Risk.IsValid() {
		risk = string(a.Risk)
	}

	ipRisk := string(domain.RiskLevelNone)
	if a.Status == domain.AssessmentStatusComplete && a.Risk.IsValid() && isIPAssessment(a) {
		ipRisk = string(a.Risk)
	}

	return PolicyAssessmentFact{
		Status:         string(a.Status),
		IPRisk:         ipRisk,
		Risk:           risk,
		Disposition:    string(a.Disposition),
		ModelRoute:     a.ModelRoute,
		ModelVersion:   a.ModelVersion,
		PromptVersion:  a.PromptVersion,
		AssessmentType: a.AssessmentType,
	}
}

func isIPAssessment(a domain.ModelAssessment) bool {
	if strings.EqualFold(strings.TrimSpace(a.AssessmentType), prompts.AssessmentTypeIPProvenance) {
		return true
	}
	for _, f := range a.Result.Findings {
		cat := strings.ToUpper(strings.TrimSpace(f.Category))
		if cat == "SOURCE_SIMILARITY" || cat == "IP_PROVENANCE" || strings.HasPrefix(cat, "IP_") || strings.Contains(cat, "LICENSE") {
			return true
		}
	}
	return false
}
