package schemas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/prompts"
)

const expectedSchemaVersion = "1"

var requiredRootKeys = map[string]struct{}{
	"schema_version":  {},
	"assessment_type": {},
	"risk":            {},
	"disposition":     {},
	"confidence":      {},
	"summary":         {},
	"findings":        {},
	"limitations":     {},
}

var requiredFindingKeys = map[string]struct{}{
	"category":           {},
	"evidence_ids":       {},
	"reason":             {},
	"recommended_action": {},
}

// ValidateAssessmentResult validates raw JSON bytes strictly against the Stage B
// AssessmentResult schema (unique JSON keys per object, exact required keys,
// additionalProperties: false, enum bounds, finite [0, 1] confidence, non-null
// slices, and single-JSON-value EOF).
func ValidateAssessmentResult(raw []byte) (domain.AssessmentResult, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return domain.AssessmentResult{}, domain.Unprocessable("MALFORMED_ASSESSMENT_JSON", "assessment output is empty")
	}

	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return domain.AssessmentResult{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var root any
	if err := dec.Decode(&root); err != nil {
		return domain.AssessmentResult{}, domain.WrapError(
			domain.ErrUnprocessable,
			"MALFORMED_ASSESSMENT_JSON",
			"assessment output is not valid JSON",
			err,
		)
	}

	// Reject trailing tokens after the first JSON value.
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"MALFORMED_ASSESSMENT_JSON",
			"assessment output contains trailing data after JSON object",
		)
	}

	obj, ok := root.(map[string]any)
	if !ok || obj == nil {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"assessment output must be a JSON object",
		)
	}

	for key := range obj {
		if _, allowed := requiredRootKeys[key]; !allowed {
			return domain.AssessmentResult{}, domain.Unprocessable(
				"INVALID_ASSESSMENT_SCHEMA",
				fmt.Sprintf("assessment output contains unexpected property %q", key),
			)
		}
	}
	for reqKey := range requiredRootKeys {
		if _, present := obj[reqKey]; !present {
			return domain.AssessmentResult{}, domain.Unprocessable(
				"INVALID_ASSESSMENT_SCHEMA",
				fmt.Sprintf("assessment output missing required property %q", reqKey),
			)
		}
	}

	schemaVersion, ok := obj["schema_version"].(string)
	if !ok || schemaVersion != expectedSchemaVersion {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			fmt.Sprintf("schema_version must be %q", expectedSchemaVersion),
		)
	}

	assessmentType, ok := obj["assessment_type"].(string)
	if !ok || !slices.Contains(prompts.AllowedAssessmentTypes(), assessmentType) {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"assessment_type must be a supported non-empty assessment type",
		)
	}

	riskStr, ok := obj["risk"].(string)
	if !ok || !domain.RiskLevel(riskStr).IsValid() {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"risk must be a valid RiskLevel",
		)
	}
	risk := domain.RiskLevel(riskStr)

	dispStr, ok := obj["disposition"].(string)
	if !ok || !domain.Disposition(dispStr).IsValid() {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"disposition must be a valid Disposition",
		)
	}
	disposition := domain.Disposition(dispStr)

	confNum, ok := obj["confidence"].(json.Number)
	if !ok {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"confidence must be a JSON number",
		)
	}
	confidence, err := strconv.ParseFloat(confNum.String(), 64)
	if err != nil || math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0.0 || confidence > 1.0 {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"confidence must be a finite number in [0.0, 1.0]",
		)
	}

	summary, ok := obj["summary"].(string)
	if !ok || strings.TrimSpace(summary) == "" {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"summary must be a non-empty string",
		)
	}

	rawFindings, ok := obj["findings"].([]any)
	if !ok || rawFindings == nil {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"findings must be a non-null JSON array",
		)
	}

	findings := make([]domain.AssessmentFinding, 0, len(rawFindings))
	for i, item := range rawFindings {
		f, err := validateFinding(item, i)
		if err != nil {
			return domain.AssessmentResult{}, err
		}
		findings = append(findings, f)
	}

	rawLimitations, ok := obj["limitations"].([]any)
	if !ok || rawLimitations == nil {
		return domain.AssessmentResult{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			"limitations must be a non-null JSON array",
		)
	}

	limitations := make([]string, 0, len(rawLimitations))
	for i, item := range rawLimitations {
		lim, ok := item.(string)
		if !ok {
			return domain.AssessmentResult{}, domain.Unprocessable(
				"INVALID_ASSESSMENT_SCHEMA",
				fmt.Sprintf("limitations[%d] must be a string", i),
			)
		}
		limitations = append(limitations, lim)
	}

	return domain.AssessmentResult{
		SchemaVersion:  schemaVersion,
		AssessmentType: assessmentType,
		Risk:           risk,
		Disposition:    disposition,
		Confidence:     confidence,
		Summary:        summary,
		Findings:       findings,
		Limitations:    limitations,
	}, nil
}

type jsonFrame struct {
	delim     byte
	seen      map[string]struct{}
	expectKey bool
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var stack []jsonFrame
	markValueComplete := func() {
		if n := len(stack); n > 0 && stack[n-1].delim == '{' {
			stack[n-1].expectKey = true
		}
	}

	tok, err := dec.Token()
	if err != nil {
		return domain.WrapError(
			domain.ErrUnprocessable,
			"MALFORMED_ASSESSMENT_JSON",
			"assessment output is not valid JSON",
			err,
		)
	}

	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{':
			stack = append(stack, jsonFrame{delim: '{', seen: make(map[string]struct{}), expectKey: true})
		case '[':
			stack = append(stack, jsonFrame{delim: '['})
		default:
			return domain.Unprocessable("MALFORMED_ASSESSMENT_JSON", "assessment output is not valid JSON")
		}
	}

	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return domain.WrapError(
				domain.ErrUnprocessable,
				"MALFORMED_ASSESSMENT_JSON",
				"assessment output is not valid JSON",
				err,
			)
		}

		top := &stack[len(stack)-1]
		if top.delim == '{' {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				markValueComplete()
				continue
			}
			if top.expectKey {
				key, ok := tok.(string)
				if !ok {
					return domain.Unprocessable("MALFORMED_ASSESSMENT_JSON", "assessment output object key must be a string")
				}
				if _, dup := top.seen[key]; dup {
					return domain.Unprocessable(
						"DUPLICATE_JSON_KEY",
						fmt.Sprintf("assessment output contains duplicate JSON key %q", key),
					)
				}
				top.seen[key] = struct{}{}
				top.expectKey = false
				continue
			}
			if d, ok := tok.(json.Delim); ok {
				switch d {
				case '{':
					stack = append(stack, jsonFrame{delim: '{', seen: make(map[string]struct{}), expectKey: true})
				case '[':
					stack = append(stack, jsonFrame{delim: '['})
				default:
					return domain.Unprocessable("MALFORMED_ASSESSMENT_JSON", "assessment output is not valid JSON")
				}
				continue
			}
			markValueComplete()
			continue
		}

		if d, ok := tok.(json.Delim); ok {
			switch d {
			case ']':
				stack = stack[:len(stack)-1]
				markValueComplete()
			case '{':
				stack = append(stack, jsonFrame{delim: '{', seen: make(map[string]struct{}), expectKey: true})
			case '[':
				stack = append(stack, jsonFrame{delim: '['})
			default:
				return domain.Unprocessable("MALFORMED_ASSESSMENT_JSON", "assessment output is not valid JSON")
			}
		}
	}

	if _, err := dec.Token(); err != io.EOF {
		return domain.Unprocessable(
			"MALFORMED_ASSESSMENT_JSON",
			"assessment output contains trailing data after JSON object",
		)
	}
	return nil
}

func validateFinding(raw any, idx int) (domain.AssessmentFinding, error) {
	fObj, ok := raw.(map[string]any)
	if !ok || fObj == nil {
		return domain.AssessmentFinding{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			fmt.Sprintf("findings[%d] must be a JSON object", idx),
		)
	}

	for key := range fObj {
		if _, allowed := requiredFindingKeys[key]; !allowed {
			return domain.AssessmentFinding{}, domain.Unprocessable(
				"INVALID_ASSESSMENT_SCHEMA",
				fmt.Sprintf("findings[%d] contains unexpected property %q", idx, key),
			)
		}
	}
	for reqKey := range requiredFindingKeys {
		if _, present := fObj[reqKey]; !present {
			return domain.AssessmentFinding{}, domain.Unprocessable(
				"INVALID_ASSESSMENT_SCHEMA",
				fmt.Sprintf("findings[%d] missing required property %q", idx, reqKey),
			)
		}
	}

	category, ok := fObj["category"].(string)
	if !ok || strings.TrimSpace(category) == "" {
		return domain.AssessmentFinding{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			fmt.Sprintf("findings[%d].category must be a non-empty string", idx),
		)
	}

	reason, ok := fObj["reason"].(string)
	if !ok || strings.TrimSpace(reason) == "" {
		return domain.AssessmentFinding{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			fmt.Sprintf("findings[%d].reason must be a non-empty string", idx),
		)
	}

	recommendedAction, ok := fObj["recommended_action"].(string)
	if !ok || strings.TrimSpace(recommendedAction) == "" {
		return domain.AssessmentFinding{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			fmt.Sprintf("findings[%d].recommended_action must be a non-empty string", idx),
		)
	}

	rawEvIDs, ok := fObj["evidence_ids"].([]any)
	if !ok || rawEvIDs == nil {
		return domain.AssessmentFinding{}, domain.Unprocessable(
			"INVALID_ASSESSMENT_SCHEMA",
			fmt.Sprintf("findings[%d].evidence_ids must be a non-null JSON array", idx),
		)
	}

	evIDs := make([]string, 0, len(rawEvIDs))
	for j, elem := range rawEvIDs {
		eid, ok := elem.(string)
		if !ok || strings.TrimSpace(eid) == "" {
			return domain.AssessmentFinding{}, domain.Unprocessable(
				"INVALID_ASSESSMENT_SCHEMA",
				fmt.Sprintf("findings[%d].evidence_ids[%d] must be a non-empty string", idx, j),
			)
		}
		evIDs = append(evIDs, eid)
	}

	return domain.AssessmentFinding{
		Category:          category,
		EvidenceIDs:       evIDs,
		Reason:            reason,
		RecommendedAction: recommendedAction,
	}, nil
}
