package schemas

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func evalFixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "test", "e2e", "fixtures", "eval", name)
}

func TestAssessmentResultSchemaBytes(t *testing.T) {
	t.Parallel()

	raw, err := AssessmentResultSchemaBytes()
	if err != nil {
		t.Fatalf("AssessmentResultSchemaBytes() error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("embedded schema is invalid JSON: %v", err)
	}
	if parsed["additionalProperties"] != false {
		t.Fatalf("expected additionalProperties=false in embedded schema")
	}
}

func TestValidateAssessmentResult_EvalFixtures(t *testing.T) {
	t.Parallel()

	t.Run("stageb_clean.json", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_clean.json"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ValidateAssessmentResult(raw)
		if err != nil {
			t.Fatalf("expected valid result, got %v", err)
		}
		if res.Risk != domain.RiskLevelLow || res.Disposition != domain.DispositionClear {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res.Findings == nil || len(res.Findings) != 0 {
			t.Fatalf("expected non-nil empty findings slice, got %#v", res.Findings)
		}
		if res.Limitations == nil || len(res.Limitations) != 1 {
			t.Fatalf("expected 1 limitation, got %#v", res.Limitations)
		}
	})

	t.Run("stageb_high_risk_ip_security.json", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_high_risk_ip_security.json"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ValidateAssessmentResult(raw)
		if err != nil {
			t.Fatalf("expected valid result, got %v", err)
		}
		if res.AssessmentType != "IP_PROVENANCE" || res.Risk != domain.RiskLevelHigh || res.Disposition != domain.DispositionReview {
			t.Fatalf("unexpected result: %+v", res)
		}
		if len(res.Findings) != 1 || len(res.Findings[0].EvidenceIDs) != 1 {
			t.Fatalf("unexpected findings: %+v", res.Findings)
		}
	})

	t.Run("stageb_prompt_injection.json adversarial_model_response", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_prompt_injection.json"))
		if err != nil {
			t.Fatal(err)
		}
		var wrapper struct {
			Adversarial json.RawMessage `json:"adversarial_model_response"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			t.Fatal(err)
		}
		res, err := ValidateAssessmentResult(wrapper.Adversarial)
		if err != nil {
			t.Fatalf("expected valid adversarial result schema, got %v", err)
		}
		if res.Findings == nil || res.Limitations == nil {
			t.Fatalf("expected non-nil Findings and Limitations slices")
		}
	})

	t.Run("stageb_indeterminate.json", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_indeterminate.json"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ValidateAssessmentResult(raw)
		if err != nil {
			t.Fatalf("expected valid indeterminate schema, got %v", err)
		}
		if res.Disposition != domain.DispositionIndeterminate || res.Risk != domain.RiskLevelNone {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("stageb_ungrounded_evidence.json is schema valid", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_ungrounded_evidence.json"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ValidateAssessmentResult(raw)
		if err != nil {
			t.Fatalf("expected schema-valid result, got %v", err)
		}
		if res.Findings[0].EvidenceIDs[0] != "nonexistent_finding_999" {
			t.Fatalf("unexpected evidence id: %+v", res.Findings)
		}
	})

	t.Run("stageb_unknown_disposition.json rejected", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_unknown_disposition.json"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = ValidateAssessmentResult(raw)
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("expected ErrUnprocessable, got %v", err)
		}
	})

	t.Run("stageb_malformed.txt rejected", func(t *testing.T) {
		raw, err := os.ReadFile(evalFixturePath(t, "stageb_malformed.txt"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = ValidateAssessmentResult(raw)
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("expected ErrUnprocessable, got %v", err)
		}
	})
}

func TestValidateAssessmentResult_StrictRejections(t *testing.T) {
	t.Parallel()

	validBase := `{
		"schema_version": "1",
		"assessment_type": "SECURITY_REVIEW",
		"risk": "LOW",
		"disposition": "CLEAR",
		"confidence": 0.9,
		"summary": "All good",
		"findings": [],
		"limitations": []
	}`

	if res, err := ValidateAssessmentResult([]byte(validBase)); err != nil {
		t.Fatalf("expected validBase to pass: %v", err)
	} else if res.Findings == nil || res.Limitations == nil {
		t.Fatalf("expected non-nil slices on empty arrays")
	}

	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"whitespace", "   \n\t  "},
		{"null", "null"},
		{"array", "[]"},
		{"string", `"hello"`},
		{"number", "42"},
		{"empty_object", "{}"},
		{"trailing_object", validBase + `{"extra":1}`},
		{"trailing_garbage", validBase + ` trailing`},
		{"unknown_root_property", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[],"extra":"nope"}`},
		{"missing_limitations", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[]}`},
		{"wrong_schema_version", `{"schema_version":"2","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`},
		{"unknown_assessment_type", `{"schema_version":"1","assessment_type":"OTHER","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`},
		{"invalid_risk", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"EXTREME","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`},
		{"invalid_disposition", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"SHIP_IT_YOLO","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`},
		{"confidence_negative", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":-0.01,"summary":"ok","findings":[],"limitations":[]}`},
		{"confidence_above_one", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":1.01,"summary":"ok","findings":[],"limitations":[]}`},
		{"confidence_string", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":"0.9","summary":"ok","findings":[],"limitations":[]}`},
		{"empty_summary", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"   ","findings":[],"limitations":[]}`},
		{"null_findings", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":null,"limitations":[]}`},
		{"null_limitations", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":null}`},
		{"non_string_limitation", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[123]}`},
		{"finding_unknown_key", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[{"category":"A","evidence_ids":["e1"],"reason":"r","recommended_action":"a","extra":1}],"limitations":[]}`},
		{"finding_missing_key", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[{"category":"A","evidence_ids":["e1"],"reason":"r"}],"limitations":[]}`},
		{"finding_null_evidence_ids", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[{"category":"A","evidence_ids":null,"reason":"r","recommended_action":"a"}],"limitations":[]}`},
		{"finding_empty_evidence_id", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[{"category":"A","evidence_ids":["  "],"reason":"r","recommended_action":"a"}],"limitations":[]}`},
		{"finding_empty_category", `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[{"category":"","evidence_ids":["e1"],"reason":"r","recommended_action":"a"}],"limitations":[]}`},
		{"whitespace_padded_assessment_type_leading_trailing", `{"schema_version":"1","assessment_type":" SECURITY_REVIEW ","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`},
		{"whitespace_padded_assessment_type_newline", `{"schema_version":"1","assessment_type":"IP_PROVENANCE\n","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ValidateAssessmentResult([]byte(tc.raw)); err == nil {
				t.Fatalf("case %s: expected error, got nil", tc.name)
			} else if !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("case %s: expected ErrUnprocessable, got %v", tc.name, err)
			}
		})
	}
}

func TestValidateAssessmentResult_DuplicateJSONKeysRejected(t *testing.T) {
	t.Parallel()

	dupCases := []struct {
		name string
		raw  string
	}{
		{
			name: "duplicate_root_risk",
			raw:  `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"CRITICAL","risk":"NONE","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`,
		},
		{
			name: "duplicate_root_disposition",
			raw:  `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"CRITICAL","disposition":"BLOCK","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`,
		},
		{
			name: "duplicate_root_escaped_key",
			raw:  `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","\u0072isk":"CRITICAL","risk":"NONE","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`,
		},
		{
			name: "duplicate_finding_key",
			raw:  `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"HIGH","disposition":"REVIEW","confidence":0.9,"summary":"ok","findings":[{"category":"A","category":"B","evidence_ids":["e1"],"reason":"r","recommended_action":"a"}],"limitations":[]}`,
		},
	}

	for _, tc := range dupCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateAssessmentResult([]byte(tc.raw))
			if err == nil {
				t.Fatalf("case %s: expected error for duplicate key, got nil", tc.name)
			}
			if !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("case %s: expected ErrUnprocessable, got %v", tc.name, err)
			}
			var domErr *domain.DomainError
			if !errors.As(err, &domErr) || domErr.Code() != "DUPLICATE_JSON_KEY" {
				t.Fatalf("case %s: expected DUPLICATE_JSON_KEY error code, got %v", tc.name, err)
			}
		})
	}

	// Multiple distinct finding objects sharing the same property names must remain valid.
	multiFinding := `{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"HIGH","disposition":"REVIEW","confidence":0.8,"summary":"two findings","findings":[{"category":"A","evidence_ids":["e1"],"reason":"r1","recommended_action":"a1"},{"category":"B","evidence_ids":["e2"],"reason":"r2","recommended_action":"a2"}],"limitations":[]}`
	res, err := ValidateAssessmentResult([]byte(multiFinding))
	if err != nil {
		t.Fatalf("expected valid multi-finding payload to pass, got %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(res.Findings))
	}

	// Gateway LLM responses must never be permitted to emit disposition=NOT_REQUIRED.
	spoofedNotReq := `{"schema_version":"1","assessment_type":"IP_PROVENANCE","risk":"NONE","disposition":"NOT_REQUIRED","confidence":1.0,"summary":"bypassed","findings":[],"limitations":[]}`
	if _, err := ValidateAssessmentResult([]byte(spoofedNotReq)); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for disposition=NOT_REQUIRED from gateway, got %v", err)
	}
}
