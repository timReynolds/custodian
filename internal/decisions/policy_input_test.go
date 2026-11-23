package decisions

import (
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/prompts"
)

func TestToPolicyAssessmentFact(t *testing.T) {
	t.Parallel()

	t.Run("complete IP_PROVENANCE propagates ip_risk", func(t *testing.T) {
		t.Parallel()
		fact := ToPolicyAssessmentFact(domain.ModelAssessment{
			Status:         domain.AssessmentStatusComplete,
			AssessmentType: prompts.AssessmentTypeIPProvenance,
			Risk:           domain.RiskLevelHigh,
			Disposition:    domain.DispositionReview,
			ModelRoute:     "approved-code-review",
			ModelVersion:   "v1",
			PromptVersion:  "p1",
		})
		if fact.Status != "COMPLETE" || fact.IPRisk != "HIGH" || fact.Risk != "HIGH" || fact.Disposition != "REVIEW" {
			t.Fatalf("unexpected fact: %+v", fact)
		}
		m := fact.ToMap()
		if m["ip_risk"] != "HIGH" || m["status"] != "COMPLETE" {
			t.Fatalf("unexpected map: %+v", m)
		}
	})

	t.Run("incomplete or failed assessment projects ip_risk NONE", func(t *testing.T) {
		t.Parallel()
		for _, status := range []domain.AssessmentStatus{domain.AssessmentStatusIndeterminate, domain.AssessmentStatusFailed} {
			fact := ToPolicyAssessmentFact(domain.ModelAssessment{
				Status:         status,
				AssessmentType: prompts.AssessmentTypeIPProvenance,
				Risk:           domain.RiskLevelHigh,
			})
			if fact.IPRisk != "NONE" || fact.Status != string(status) {
				t.Fatalf("status=%s: unexpected fact %+v", status, fact)
			}
		}
	})
}
