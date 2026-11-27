package prompts

import (
	"errors"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestTemplateFor_SupportedTypes(t *testing.T) {
	t.Parallel()

	for _, assessmentType := range AllowedAssessmentTypes() {
		t.Run(assessmentType, func(t *testing.T) {
			t.Parallel()

			sysPrompt, version, err := TemplateFor(assessmentType)
			if err != nil {
				t.Fatalf("TemplateFor(%q) unexpected error: %v", assessmentType, err)
			}
			if strings.TrimSpace(sysPrompt) == "" {
				t.Fatalf("TemplateFor(%q) returned empty system prompt", assessmentType)
			}
			if strings.TrimSpace(version) == "" {
				t.Fatalf("TemplateFor(%q) returned empty prompt version", assessmentType)
			}

			// Verify determinism across calls.
			sysPrompt2, version2, err := TemplateFor(assessmentType)
			if err != nil {
				t.Fatalf("TemplateFor(%q) second call unexpected error: %v", assessmentType, err)
			}
			if sysPrompt != sysPrompt2 || version != version2 {
				t.Fatalf("TemplateFor(%q) not deterministic: got (%q, %q) vs (%q, %q)", assessmentType, version, sysPrompt, version2, sysPrompt2)
			}

			// System prompt must be static (no template interpolation delimiters).
			if strings.Contains(sysPrompt, "{{") || strings.Contains(sysPrompt, "}}") {
				t.Fatalf("TemplateFor(%q) contains template interpolation placeholders", assessmentType)
			}

			// Verify required static instructions: untrusted framing, evidence grounding, strict JSON keys.
			for _, required := range []string{
				"UNTRUSTED DATA",
				"evidence_ids",
				"schema_version",
				"assessment_type",
				"risk",
				"disposition",
				"confidence",
				"summary",
				"findings",
				"limitations",
				assessmentType,
			} {
				if !strings.Contains(sysPrompt, required) {
					t.Fatalf("TemplateFor(%q) system prompt missing required directive/field %q", assessmentType, required)
				}
			}
		})
	}
}

func TestTemplateFor_RejectsUnknownTypes(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "   ", "UNKNOWN", "CUSTOM_REVIEW", "security_review"} {
		_, _, err := TemplateFor(bad)
		if err == nil {
			t.Fatalf("TemplateFor(%q) expected error, got nil", bad)
		}
		if !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("TemplateFor(%q) expected ErrBadRequest, got %v", bad, err)
		}
		var domErr *domain.DomainError
		if !errors.As(err, &domErr) || domErr.Code() != "INVALID_ASSESSMENT_TYPE" {
			t.Fatalf("TemplateFor(%q) expected INVALID_ASSESSMENT_TYPE, got %v", bad, err)
		}
	}
}

func TestIsAllowedAssessmentType(t *testing.T) {
	t.Parallel()

	if !IsAllowedAssessmentType(AssessmentTypeSecurityReview) {
		t.Fatalf("expected %q to be allowed", AssessmentTypeSecurityReview)
	}
	if !IsAllowedAssessmentType(AssessmentTypeIPProvenance) {
		t.Fatalf("expected %q to be allowed", AssessmentTypeIPProvenance)
	}
	if IsAllowedAssessmentType("ARBITRARY") || IsAllowedAssessmentType("") {
		t.Fatalf("expected invalid types to be rejected")
	}
}
