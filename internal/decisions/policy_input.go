package decisions

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/prompts"
)

// NotRequiredAssessmentInput defines parameters for constructing a deterministic,
// persistence-ready NOT_REQUIRED ModelAssessment without invoking any model gateway.
type NotRequiredAssessmentInput struct {
	ID             uuid.UUID
	ProposalID     uuid.UUID
	PushSessionID  *uuid.UUID
	ArtifactID     uuid.UUID
	AssessmentType string
	InputDigest    string
	Reason         string
	CreatedAt      time.Time
}

// BuildNotRequiredAssessment constructs a persistence-ready NOT_REQUIRED ModelAssessment
// when Stage B triggers were not activated. It never invokes a model gateway.
func BuildNotRequiredAssessment(in NotRequiredAssessmentInput) (domain.ModelAssessment, error) {
	if in.PushSessionID != nil && *in.PushSessionID == uuid.Nil {
		return domain.ModelAssessment{}, domain.BadRequest("INVALID_ID", "push_session_id must not be nil when provided")
	}
	hasProposal := in.ProposalID != uuid.Nil
	hasPush := in.PushSessionID != nil && *in.PushSessionID != uuid.Nil
	if hasProposal == hasPush {
		return domain.ModelAssessment{}, domain.BadRequest("INVALID_MODEL_ASSESSMENT", "exactly one of proposal_id or push_session_id is required")
	}
	if in.ArtifactID == uuid.Nil {
		return domain.ModelAssessment{}, domain.BadRequest("INVALID_MODEL_ASSESSMENT", "artifact_id is required")
	}

	assessmentType := strings.TrimSpace(in.AssessmentType)
	if assessmentType == "" {
		assessmentType = prompts.AssessmentTypeIPProvenance
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		reason = "Stage B contextual assessment not required"
	}

	var inputDigest string
	if strings.TrimSpace(in.InputDigest) != "" {
		parsed, err := domain.ParseSHA256Digest(in.InputDigest)
		if err != nil {
			return domain.ModelAssessment{}, err
		}
		inputDigest = parsed
	} else {
		var ownerID string
		if hasProposal {
			ownerID = in.ProposalID.String()
		} else {
			ownerID = in.PushSessionID.String()
		}
		dig, err := domain.CanonicalJSONDigest(struct {
			OwnerID        string `json:"owner_id"`
			ArtifactID     string `json:"artifact_id"`
			AssessmentType string `json:"assessment_type"`
			Status         string `json:"status"`
		}{
			OwnerID:        ownerID,
			ArtifactID:     in.ArtifactID.String(),
			AssessmentType: assessmentType,
			Status:         string(domain.AssessmentStatusNotRequired),
		})
		if err != nil {
			return domain.ModelAssessment{}, err
		}
		inputDigest = dig
	}

	result := domain.AssessmentResult{
		SchemaVersion:  "1",
		AssessmentType: assessmentType,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionNotRequired,
		Confidence:     1.0,
		Summary:        reason,
		Findings:       []domain.AssessmentFinding{},
		Limitations:    []string{},
	}
	outputDigest, err := domain.CanonicalJSONDigest(result)
	if err != nil {
		return domain.ModelAssessment{}, err
	}

	id := in.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return domain.ModelAssessment{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return domain.ModelAssessment{}, domain.BadRequest("INVALID_ID", "model_assessment id must be UUIDv7")
	}

	createdAt := in.CreatedAt.UTC().Truncate(time.Microsecond)
	if in.CreatedAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Microsecond)
	}

	return domain.ModelAssessment{
		ID:             id,
		ProposalID:     in.ProposalID,
		PushSessionID:  in.PushSessionID,
		ArtifactID:     in.ArtifactID,
		ModelRoute:     "not-required",
		ModelVersion:   "not-required",
		PromptVersion:  "not-required",
		AssessmentType: assessmentType,
		Status:         domain.AssessmentStatusNotRequired,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionNotRequired,
		Result:         result,
		EvidenceIDs:    []string{},
		InputDigest:    inputDigest,
		OutputDigest:   outputDigest,
		CreatedAt:      createdAt,
	}, nil
}

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
// Incomplete, failed, indeterminate, or NOT_REQUIRED assessments always project ip_risk="NONE" and
// preserve status so Stage C fail-closed CEL rules behave accurately per stage.
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
