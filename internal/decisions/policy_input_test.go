package decisions

import (
	"errors"
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
		for _, status := range []domain.AssessmentStatus{domain.AssessmentStatusIndeterminate, domain.AssessmentStatusFailed, domain.AssessmentStatusNotRequired} {
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

func TestBuildNotRequiredAssessment(t *testing.T) {
	t.Parallel()

	pushID := domain.MustNewID()
	artID := domain.MustNewID()

	ma, err := BuildNotRequiredAssessment(NotRequiredAssessmentInput{
		PushSessionID: &pushID,
		ArtifactID:    artID,
	})
	if err != nil {
		t.Fatalf("BuildNotRequiredAssessment: %v", err)
	}
	if !domain.IsUUIDv7(ma.ID) {
		t.Fatalf("expected UUIDv7 ID, got %s", ma.ID)
	}
	if ma.Status != domain.AssessmentStatusNotRequired || ma.Disposition != domain.DispositionNotRequired || ma.Risk != domain.RiskLevelNone {
		t.Fatalf("unexpected NOT_REQUIRED assessment fields: %+v", ma)
	}
	if !domain.IsValidSHA256Hex(ma.InputDigest) || !domain.IsValidSHA256Hex(ma.OutputDigest) {
		t.Fatalf("expected valid 64-hex digests, got in=%q out=%q", ma.InputDigest, ma.OutputDigest)
	}
	if !ma.AllowsPushEgress() {
		t.Fatal("expected AllowsPushEgress() == true")
	}
	if !ma.BlocksPublication() {
		t.Fatal("expected v1.0 BlocksPublication() == true")
	}
	fact := ToPolicyAssessmentFact(ma)
	if fact.Status != "NOT_REQUIRED" || fact.Disposition != "NOT_REQUIRED" || fact.IPRisk != "NONE" {
		t.Fatalf("unexpected ToPolicyAssessmentFact: %+v", fact)
	}

	// Missing owner or both owners fails closed.
	if _, err := BuildNotRequiredAssessment(NotRequiredAssessmentInput{ArtifactID: artID}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("missing owner expected ErrBadRequest, got %v", err)
	}
	if _, err := BuildNotRequiredAssessment(NotRequiredAssessmentInput{ProposalID: pushID, PushSessionID: &pushID, ArtifactID: artID}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("both owners expected ErrBadRequest, got %v", err)
	}
}
