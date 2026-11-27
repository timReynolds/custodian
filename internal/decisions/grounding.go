package decisions

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// ValidateGrounding verifies that every evidence_id cited in res.Findings exists
// in the Stage A findings' non-empty EvidenceID or ID.String() set.
// It returns a deterministically sorted, deduplicated non-nil slice of grounded IDs.
func ValidateGrounding(res domain.AssessmentResult, stageAFindings []domain.Finding) ([]string, error) {
	allowed := make(map[string]struct{}, len(stageAFindings)*2)
	for _, f := range stageAFindings {
		if evID := strings.TrimSpace(f.EvidenceID); evID != "" {
			allowed[evID] = struct{}{}
		}
		if f.ID != uuid.Nil {
			allowed[f.ID.String()] = struct{}{}
		}
	}

	seen := make(map[string]struct{})
	grounded := make([]string, 0)

	for _, mf := range res.Findings {
		for _, rawID := range mf.EvidenceIDs {
			eid := strings.TrimSpace(rawID)
			if eid == "" {
				return nil, domain.Unprocessable(
					"UNGROUNDED_EVIDENCE_ID",
					"assessment finding contains empty evidence_id",
				)
			}
			if _, ok := allowed[eid]; !ok {
				return nil, domain.Unprocessable(
					"UNGROUNDED_EVIDENCE_ID",
					fmt.Sprintf("assessment finding cites ungrounded evidence_id %q", eid),
				)
			}
			if _, dup := seen[eid]; !dup {
				seen[eid] = struct{}{}
				grounded = append(grounded, eid)
			}
		}
	}

	slices.Sort(grounded)
	return grounded, nil
}
