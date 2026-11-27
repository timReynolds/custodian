package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

type ScanStatus string

const (
	ScanStatusPending    ScanStatus = "PENDING"
	ScanStatusRunning    ScanStatus = "RUNNING"
	ScanStatusCompleted  ScanStatus = "COMPLETED"
	ScanStatusFailed     ScanStatus = "FAILED"
	ScanStatusTimedOut   ScanStatus = "TIMED_OUT"
	ScanStatusIncomplete ScanStatus = "INCOMPLETE"
)

func (s ScanStatus) IsValid() bool {
	switch s {
	case ScanStatusPending, ScanStatusRunning, ScanStatusCompleted, ScanStatusFailed, ScanStatusTimedOut, ScanStatusIncomplete:
		return true
	default:
		return false
	}
}

type ScanCoverage struct {
	FilesExamined  int      `json:"files_examined"`
	FilesSkipped   int      `json:"files_skipped"`
	BytesExamined  int64    `json:"bytes_examined,omitempty"`
	SkippedReasons []string `json:"skipped_reasons,omitempty"`
	Complete       bool     `json:"complete"`
}

type ScanRun struct {
	ID             uuid.UUID    `json:"id"`
	ProposalID     uuid.UUID    `json:"proposal_id"`
	PushSessionID  *uuid.UUID   `json:"push_session_id,omitempty"`
	ArtifactID     uuid.UUID    `json:"artifact_id"`
	Scanner        string       `json:"scanner"`
	ScannerVersion string       `json:"scanner_version"`
	Status         ScanStatus   `json:"status"`
	Coverage       ScanCoverage `json:"coverage"`
	StartedAt      time.Time    `json:"started_at"`
	CompletedAt    *time.Time   `json:"completed_at,omitempty"`
}

// IsCleanComplete reports whether the scan completed with zero skipped files.
func (s ScanRun) IsCleanComplete() bool {
	return s.Status == ScanStatusCompleted && s.Coverage.Complete && s.Coverage.FilesSkipped == 0
}

type Finding struct {
	ID                 uuid.UUID      `json:"id"`
	ScanRunID          uuid.UUID      `json:"scan_run_id"`
	EvidenceID         string         `json:"evidence_id,omitempty"`
	Scanner            string         `json:"scanner,omitempty"`
	Category           string         `json:"category"`
	Severity           Severity       `json:"severity"`
	RuleID             string         `json:"rule_id"`
	Path               string         `json:"path,omitempty"`
	StartLine          int            `json:"start_line,omitempty"`
	EndLine            int            `json:"end_line,omitempty"`
	Fingerprint        string         `json:"fingerprint"`
	EvidenceArtifactID *uuid.UUID     `json:"evidence_artifact_id,omitempty"`
	EvidenceRef        string         `json:"evidence_ref,omitempty"`
	Baseline           string         `json:"baseline,omitempty"`
	Confidence         float64        `json:"confidence,omitempty"`
	Message            string         `json:"message,omitempty"`
	Redacted           bool           `json:"redacted"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

var forbiddenMetadataKeys = map[string]struct{}{
	"rawsecret":  {},
	"secret":     {},
	"token":      {},
	"privatekey": {},
	"password":   {},
	"credential": {},
	"matchraw":   {},
}

// ValidateRedacted ensures secret findings are redacted and Metadata never carries raw secret keys.
func (f Finding) ValidateRedacted() error {
	if strings.EqualFold(strings.TrimSpace(f.Category), "SECRET") && !f.Redacted {
		return Unprocessable("UNREDACTED_SECRET_FINDING", "secret findings must be redacted")
	}
	if err := checkMetadataKeys(f.Metadata); err != nil {
		return err
	}
	return nil
}

type metadataVisitKey struct {
	kind reflect.Kind
	ptr  uintptr
	len  int
	typ  reflect.Type
}

func checkMetadataKeys(m map[string]any) error {
	return checkMetadataKeysWith(m, isForbiddenMetadataKeyName, "FORBIDDEN_SECRET_METADATA", "finding metadata contains forbidden raw-secret key")
}

func checkMetadataKeysWith(m map[string]any, isForbidden func(string) bool, errCode, errMsg string) error {
	return checkMetadataValueWith(m, isForbidden, errCode, errMsg)
}

func checkMetadataValueWith(v any, isForbidden func(string) bool, errCode, errMsg string) error {
	if v == nil {
		return nil
	}
	return checkMetadataReflect(reflect.ValueOf(v), nil, isForbidden, errCode, errMsg)
}

var (
	jsonMarshalerType  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	jsonRawMessageType = reflect.TypeOf(json.RawMessage(nil))
	timeType           = reflect.TypeOf(time.Time{})
	timePtrType        = reflect.TypeOf((*time.Time)(nil))
)

func checkMetadataReflect(rv reflect.Value, visiting map[metadataVisitKey]bool, isForbidden func(string) bool, errCode, errMsg string) error {
	if !rv.IsValid() {
		return nil
	}
	if rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		return checkMetadataReflect(rv.Elem(), visiting, isForbidden, errCode, errMsg)
	}
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil
	}
	if rv.Type() == jsonRawMessageType && rv.IsNil() {
		return nil
	}
	if rv.Type() != timeType && rv.Type() != timePtrType {
		var marshaler json.Marshaler
		switch {
		case rv.CanInterface() && rv.Type().Implements(jsonMarshalerType):
			marshaler = rv.Interface().(json.Marshaler)
		case rv.Kind() != reflect.Pointer && rv.CanAddr() && rv.Addr().CanInterface() && rv.Addr().Type().Implements(jsonMarshalerType):
			marshaler = rv.Addr().Interface().(json.Marshaler)
		}
		if marshaler != nil {
			return checkJSONMarshaler(marshaler, visiting, isForbidden, errCode, errMsg)
		}
	}
	switch rv.Kind() {
	case reflect.Pointer:
		key := metadataVisitKey{
			kind: reflect.Pointer,
			ptr:  rv.Pointer(),
			typ:  rv.Type(),
		}
		if visiting[key] {
			return nil
		}
		if visiting == nil {
			visiting = make(map[metadataVisitKey]bool)
		}
		visiting[key] = true
		defer delete(visiting, key)
		return checkMetadataReflect(rv.Elem(), visiting, isForbidden, errCode, errMsg)
	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		key := metadataVisitKey{
			kind: reflect.Map,
			ptr:  rv.Pointer(),
			typ:  rv.Type(),
		}
		if visiting[key] {
			return nil
		}
		if visiting == nil {
			visiting = make(map[metadataVisitKey]bool)
		}
		visiting[key] = true
		defer delete(visiting, key)
		iter := rv.MapRange()
		for iter.Next() {
			if isForbiddenMetadataKeyValueWith(iter.Key(), isForbidden) {
				return Unprocessable(errCode, errMsg)
			}
			if err := checkMetadataReflect(iter.Value(), visiting, isForbidden, errCode, errMsg); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		if !rv.IsNil() && rv.Len() > 0 {
			key := metadataVisitKey{
				kind: reflect.Slice,
				ptr:  rv.Pointer(),
				len:  rv.Len(),
				typ:  rv.Type(),
			}
			if visiting[key] {
				return nil
			}
			if visiting == nil {
				visiting = make(map[metadataVisitKey]bool)
			}
			visiting[key] = true
			defer delete(visiting, key)
		}
		for i := 0; i < rv.Len(); i++ {
			if err := checkMetadataReflect(rv.Index(i), visiting, isForbidden, errCode, errMsg); err != nil {
				return err
			}
		}
		return nil
	case reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := checkMetadataReflect(rv.Index(i), visiting, isForbidden, errCode, errMsg); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		rt := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			sf := rt.Field(i)
			f := rv.Field(i)
			if !sf.IsExported() {
				// encoding/json promotes exported fields of unexported embedded structs (and pointers to structs)
				// unless explicitly omitted with json:"-".
				if sf.Anonymous && sf.Tag.Get("json") != "-" &&
					(f.Kind() == reflect.Struct || (f.Kind() == reflect.Pointer && !f.IsNil() && f.Type().Elem().Kind() == reflect.Struct)) {
					if err := checkMetadataReflect(f, visiting, isForbidden, errCode, errMsg); err != nil {
						return err
					}
				}
				continue
			}
			if isForbidden(sf.Name) {
				return Unprocessable(errCode, errMsg)
			}
			if tag := sf.Tag.Get("json"); tag != "" {
				tagName := strings.Split(tag, ",")[0]
				if tagName != "" && tagName != "-" && isForbidden(tagName) {
					return Unprocessable(errCode, errMsg)
				}
			}
			if err := checkMetadataReflect(f, visiting, isForbidden, errCode, errMsg); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func checkJSONMarshaler(marshaler json.Marshaler, visiting map[metadataVisitKey]bool, isForbidden func(string) bool, errCode, errMsg string) error {
	raw, err := marshaler.MarshalJSON()
	if err != nil {
		return Unprocessable(errCode, "metadata failed JSON marshaling")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Unprocessable(errCode, "metadata contains empty JSON marshaler output")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return Unprocessable(errCode, "metadata contains invalid JSON marshaler output")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Unprocessable(errCode, "metadata contains trailing JSON marshaler output")
	}
	return checkMetadataReflect(reflect.ValueOf(decoded), visiting, isForbidden, errCode, errMsg)
}

func isForbiddenMetadataKeyValueWith(k reflect.Value, isForbidden func(string) bool) bool {
	if !k.IsValid() {
		return false
	}
	for k.Kind() == reflect.Interface || k.Kind() == reflect.Pointer {
		if k.IsNil() {
			return false
		}
		k = k.Elem()
	}
	var keyStr string
	switch {
	case k.Kind() == reflect.String:
		keyStr = k.String()
	case k.CanInterface():
		keyStr = fmt.Sprint(k.Interface())
	default:
		return false
	}
	return isForbidden(keyStr)
}

func normalizeMetadataKeyName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isForbiddenMetadataKeyName(name string) bool {
	norm := normalizeMetadataKeyName(name)
	_, forbidden := forbiddenMetadataKeys[norm]
	return forbidden
}

type AssessmentStatus string

const (
	AssessmentStatusPending       AssessmentStatus = "PENDING"
	AssessmentStatusComplete      AssessmentStatus = "COMPLETE"
	AssessmentStatusIndeterminate AssessmentStatus = "INDETERMINATE"
	AssessmentStatusFailed        AssessmentStatus = "FAILED"
	AssessmentStatusNotRequired   AssessmentStatus = "NOT_REQUIRED"
)

func (s AssessmentStatus) IsValid() bool {
	switch s {
	case AssessmentStatusPending, AssessmentStatusComplete, AssessmentStatusIndeterminate, AssessmentStatusFailed, AssessmentStatusNotRequired:
		return true
	default:
		return false
	}
}

type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelNone     RiskLevel = "NONE"
)

func (r RiskLevel) IsValid() bool {
	switch r {
	case RiskLevelCritical, RiskLevelHigh, RiskLevelMedium, RiskLevelLow, RiskLevelNone:
		return true
	default:
		return false
	}
}

type Disposition string

const (
	DispositionClear         Disposition = "CLEAR"
	DispositionReview        Disposition = "REVIEW"
	DispositionEscalate      Disposition = "ESCALATE"
	DispositionBlock         Disposition = "BLOCK"
	DispositionIndeterminate Disposition = "INDETERMINATE"
	DispositionNotRequired   Disposition = "NOT_REQUIRED"
)

func (d Disposition) IsValid() bool {
	switch d {
	case DispositionClear, DispositionReview, DispositionEscalate, DispositionBlock, DispositionIndeterminate, DispositionNotRequired:
		return true
	default:
		return false
	}
}

func (d Disposition) BlocksPublication() bool {
	return d == DispositionBlock || d == DispositionIndeterminate || d == DispositionNotRequired || !d.IsValid()
}

type AssessmentFinding struct {
	Category          string   `json:"category"`
	EvidenceIDs       []string `json:"evidence_ids"`
	Reason            string   `json:"reason"`
	RecommendedAction string   `json:"recommended_action"`
}

type AssessmentResult struct {
	SchemaVersion  string              `json:"schema_version"`
	AssessmentType string              `json:"assessment_type"`
	Risk           RiskLevel           `json:"risk"`
	Disposition    Disposition         `json:"disposition"`
	Confidence     float64             `json:"confidence"`
	Summary        string              `json:"summary"`
	Findings       []AssessmentFinding `json:"findings"`
	Limitations    []string            `json:"limitations"`
}

type ModelAssessment struct {
	ID             uuid.UUID        `json:"id"`
	ProposalID     uuid.UUID        `json:"proposal_id"`
	PushSessionID  *uuid.UUID       `json:"push_session_id,omitempty"`
	ArtifactID     uuid.UUID        `json:"artifact_id"`
	ModelRoute     string           `json:"model_route"`
	ModelVersion   string           `json:"model_version"`
	PromptVersion  string           `json:"prompt_version"`
	AssessmentType string           `json:"assessment_type"`
	Status         AssessmentStatus `json:"status"`
	Risk           RiskLevel        `json:"risk,omitempty"`
	Disposition    Disposition      `json:"disposition,omitempty"`
	Result         AssessmentResult `json:"result"`
	EvidenceIDs    []string         `json:"evidence_ids,omitempty"`
	InputDigest    string           `json:"input_digest"`
	OutputDigest   string           `json:"output_digest"`
	CreatedAt      time.Time        `json:"created_at"`
}

// BlocksPublication fails closed whenever an assessment is incomplete, indeterminate, failed, or blocking.
func (a ModelAssessment) BlocksPublication() bool {
	return a.Status != AssessmentStatusComplete || a.Disposition.BlocksPublication()
}

// AllowsPushEgress reports whether the assessment permits PUSH_EGRESS evaluation without
// blocking. Unlike BlocksPublication() (which stays strictly fail-closed for v1.0 PR EGRESS),
// PUSH_EGRESS permits NOT_REQUIRED when Stage B was intentionally bypassed.
func (a ModelAssessment) AllowsPushEgress() bool {
	if a.Status == AssessmentStatusNotRequired {
		return a.Disposition == DispositionNotRequired || a.Disposition == "" || a.Disposition == DispositionClear
	}
	return !a.BlocksPublication()
}

// BlocksStage applies stage-appropriate fail-closed semantics for ModelAssessment.
func (a ModelAssessment) BlocksStage(stage PolicyStage) bool {
	if stage == PolicyStagePushEgress {
		return !a.AllowsPushEgress()
	}
	return a.BlocksPublication()
}
