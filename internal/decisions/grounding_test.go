package decisions

import (
	"errors"
	"slices"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestValidateGrounding(t *testing.T) {
	t.Parallel()

	f1ID := domain.MustNewID()
	f2ID := domain.MustNewID()
	stageA := []domain.Finding{
		{
			ID:         f1ID,
			EvidenceID: "finding_ip_001",
		},
		{
			ID:         f2ID,
			EvidenceID: "",
		},
	}

	t.Run("accepts EvidenceID and UUID ID", func(t *testing.T) {
		t.Parallel()
		res := domain.AssessmentResult{
			Findings: []domain.AssessmentFinding{
				{
					Category:          "SOURCE_SIMILARITY",
					EvidenceIDs:       []string{f2ID.String(), "finding_ip_001", "finding_ip_001"},
					Reason:            "match",
					RecommendedAction: "IP_REVIEW",
				},
			},
		}
		got, err := ValidateGrounding(res, stageA)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{f2ID.String(), "finding_ip_001"}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("rejects ungrounded evidence_id", func(t *testing.T) {
		t.Parallel()
		res := domain.AssessmentResult{
			Findings: []domain.AssessmentFinding{
				{
					Category:          "SOURCE_SIMILARITY",
					EvidenceIDs:       []string{"nonexistent_finding_999"},
					Reason:            "fabricated",
					RecommendedAction: "IP_REVIEW",
				},
			},
		}
		_, err := ValidateGrounding(res, stageA)
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("expected ErrUnprocessable, got %v", err)
		}
	})

	t.Run("empty findings returns non-nil empty slice", func(t *testing.T) {
		t.Parallel()
		res := domain.AssessmentResult{Findings: []domain.AssessmentFinding{}}
		got, err := ValidateGrounding(res, stageA)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("expected non-nil empty slice, got %#v", got)
		}
	})
}
