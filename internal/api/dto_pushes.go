package api

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

// --- Push Control-Plane DTOs ---

type PushRefUpdateDTO struct {
	RefName string `json:"ref_name"`
	OldOID  string `json:"old_oid"`
	NewOID  string `json:"new_oid"`
}

type PushLFSObjectDTO struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

type PushScanRunSummaryDTO struct {
	ID             string  `json:"id"`
	ProposalID     *string `json:"proposal_id,omitempty"`
	PushSessionID  string  `json:"push_session_id"`
	ArtifactID     string  `json:"artifact_id"`
	Scanner        string  `json:"scanner"`
	ScannerVersion string  `json:"scanner_version"`
	Status         string  `json:"status"`
	FilesExamined  int     `json:"files_examined"`
	FilesSkipped   int     `json:"files_skipped"`
	Complete       bool    `json:"complete"`
	StartedAt      string  `json:"started_at"`
	CompletedAt    *string `json:"completed_at,omitempty"`
}

type PushModelAssessmentDTO struct {
	ID             string            `json:"id"`
	ProposalID     *string           `json:"proposal_id,omitempty"`
	PushSessionID  string            `json:"push_session_id"`
	ArtifactID     string            `json:"artifact_id"`
	ModelRoute     string            `json:"model_route"`
	ModelVersion   string            `json:"model_version"`
	PromptVersion  string            `json:"prompt_version"`
	AssessmentType string            `json:"assessment_type"`
	Status         string            `json:"status"`
	Risk           *string           `json:"risk,omitempty"`
	Disposition    *string           `json:"disposition,omitempty"`
	Summary        *string           `json:"summary,omitempty"`
	Findings       []ModelFindingDTO `json:"findings"`
	Limitations    []string          `json:"limitations"`
	InputDigest    string            `json:"input_digest"`
	OutputDigest   string            `json:"output_digest"`
	CreatedAt      string            `json:"created_at"`
}

type PushPolicyDecisionDTO struct {
	ID             string            `json:"id"`
	ProposalID     *string           `json:"proposal_id,omitempty"`
	PushSessionID  string            `json:"push_session_id"`
	PolicyBundleID string            `json:"policy_bundle_id"`
	Stage          string            `json:"stage"`
	Enforced       bool              `json:"enforced"`
	InputDigest    string            `json:"input_digest"`
	Effect         string            `json:"effect"`
	Reasons        []PolicyReasonDTO `json:"reasons"`
	Obligations    []ObligationDTO   `json:"obligations"`
	CreatedAt      string            `json:"created_at"`
}

type PushApprovalReleaseResponseDTO struct {
	ID                      string  `json:"id"`
	PushSessionID           string  `json:"push_session_id"`
	PrincipalID             string  `json:"principal_id"`
	ApprovedBy              string  `json:"approved_by"`
	ConsumedByPushSessionID *string `json:"consumed_by_push_session_id,omitempty"`
	PolicyDecisionID        *string `json:"policy_decision_id,omitempty"`
	Destination             string  `json:"destination"`
	PushManifestDigest      string  `json:"push_manifest_digest"`
	Decision                string  `json:"decision"`
	SingleUse               bool    `json:"single_use"`
	Consumed                bool    `json:"consumed"`
	Reason                  *string `json:"reason,omitempty"`
	Comment                 *string `json:"comment,omitempty"`
	ExpiresAt               *string `json:"expires_at,omitempty"`
	ConsumedAt              *string `json:"consumed_at,omitempty"`
	RevokedAt               *string `json:"revoked_at,omitempty"`
	CreatedAt               string  `json:"created_at"`
}

type PushSessionDTO struct {
	ID                     string                           `json:"id"`
	PushSessionID          *string                          `json:"push_session_id,omitempty"`
	PrincipalID            string                           `json:"principal_id"`
	PrincipalSubject       *string                          `json:"principal_subject,omitempty"`
	RepositoryID           *string                          `json:"repository_id,omitempty"`
	Destination            string                           `json:"destination"`
	DestinationHost        *string                          `json:"destination_host,omitempty"`
	DestinationRegistered  bool                             `json:"destination_registered"`
	DestinationExternal    bool                             `json:"destination_external"`
	Transport              *string                          `json:"transport,omitempty"`
	RefUpdates             []PushRefUpdateDTO               `json:"ref_updates"`
	HasLFS                 bool                             `json:"has_lfs"`
	LFSObjects             []PushLFSObjectDTO               `json:"lfs_objects"`
	LFSObjectCount         int64                            `json:"lfs_object_count"`
	LFSTotalBytes          int64                            `json:"lfs_total_bytes"`
	CommitCount            int64                            `json:"commit_count,omitempty"`
	PushManifestDigest     *string                          `json:"push_manifest_digest,omitempty"`
	BundleArtifactID       *string                          `json:"bundle_artifact_id,omitempty"`
	EgressMode             string                           `json:"egress_mode"`
	PassiveAuditDelivery   *string                          `json:"passive_audit_delivery,omitempty"`
	Enforced               bool                             `json:"enforced"`
	Status                 string                           `json:"status"`
	Verdict                *string                          `json:"verdict,omitempty"`
	PolicyEffect           *string                          `json:"policy_effect,omitempty"`
	LatestPolicyDecisionID *string                          `json:"latest_policy_decision_id,omitempty"`
	PolicyDecisionID       *string                          `json:"policy_decision_id,omitempty"`
	AssessmentID           *string                          `json:"assessment_id,omitempty"`
	AssessmentStatus       *string                          `json:"assessment_status,omitempty"`
	AssessmentDisposition  *string                          `json:"assessment_disposition,omitempty"`
	ApprovalReleaseID      *string                          `json:"approval_release_id,omitempty"`
	ErrorCode              *string                          `json:"error_code,omitempty"`
	ErrorMessage           *string                          `json:"error_message,omitempty"`
	UpstreamForwarded      bool                             `json:"upstream_forwarded"`
	UpstreamBytesSent      int64                            `json:"upstream_bytes_sent"`
	CreatedAt              string                           `json:"created_at"`
	UpdatedAt              *string                          `json:"updated_at,omitempty"`
	CompletedAt            *string                          `json:"completed_at,omitempty"`
	ScanRuns               []PushScanRunSummaryDTO          `json:"scan_runs,omitempty"`
	Findings               []FindingDTO                     `json:"findings,omitempty"`
	Assessments            []PushModelAssessmentDTO         `json:"assessments,omitempty"`
	PolicyDecisions        []PushPolicyDecisionDTO          `json:"policy_decisions,omitempty"`
	ApprovalReleases       []PushApprovalReleaseResponseDTO `json:"approval_releases,omitempty"`
}

type PushListResponse struct {
	Pushes     []PushSessionDTO `json:"pushes"`
	NextCursor *string          `json:"next_cursor,omitempty"`
	HasMore    bool             `json:"has_more"`
}

type ApprovePushRequest struct {
	Decision           string  `json:"decision"`
	PushManifestDigest string  `json:"push_manifest_digest"`
	PolicyEvaluationID *string `json:"policy_evaluation_id,omitempty"`
	Destination        *string `json:"destination,omitempty"`
	TTLSeconds         *int64  `json:"ttl_seconds,omitempty"`
	ExpiresAt          *string `json:"expires_at,omitempty"`
	Comment            *string `json:"comment,omitempty"`
	Reason             *string `json:"reason,omitempty"`
}

// --- Repository Egress Mode DTOs ---

type SetRepositoryEgressModeRequest struct {
	EgressMode            string  `json:"egress_mode"`
	PassiveAuditDelivery  *string `json:"passive_audit_delivery,omitempty"`
	GitRemoteURL          *string `json:"git_remote_url,omitempty"`
	RemoteHost            *string `json:"remote_host,omitempty"`
	RegisteredDestination *bool   `json:"registered_destination,omitempty"`
	External              *bool   `json:"external,omitempty"`
}

type RepositoryEgressModeResponseDTO struct {
	RepositoryID          string  `json:"repository_id"`
	FullName              *string `json:"full_name,omitempty"`
	EgressMode            string  `json:"egress_mode"`
	PassiveAuditDelivery  string  `json:"passive_audit_delivery"`
	GitRemoteURL          *string `json:"git_remote_url,omitempty"`
	RemoteHost            *string `json:"remote_host,omitempty"`
	RegisteredDestination bool    `json:"registered_destination"`
	External              bool    `json:"external"`
	UpdatedAt             *string `json:"updated_at,omitempty"`
}

// --- IP Corpus DTOs ---

type IPCorpusFileInputDTO struct {
	Path    string  `json:"path"`
	Content *string `json:"content,omitempty"`
	SHA256  *string `json:"sha256,omitempty"`
}

type CreateIPCorpusRequest struct {
	Name           string                 `json:"name"`
	Classification string                 `json:"classification"`
	Description    *string                `json:"description,omitempty"`
	RepositoryID   *string                `json:"repository_id,omitempty"`
	SourceRef      *string                `json:"source_ref,omitempty"`
	SourcePath     *string                `json:"source_path,omitempty"`
	Files          []IPCorpusFileInputDTO `json:"files,omitempty"`
	WinnowK        *int                   `json:"winnow_k,omitempty"`
	WinnowW        *int                   `json:"winnow_w,omitempty"`
	ChunkSizeBytes *int                   `json:"chunk_size_bytes,omitempty"`
	Enabled        *bool                  `json:"enabled,omitempty"`
}

type IPCorpusDTO struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	Description       *string `json:"description,omitempty"`
	Classification    string  `json:"classification"`
	RepositoryID      *string `json:"repository_id,omitempty"`
	SourceRef         *string `json:"source_ref,omitempty"`
	WinnowK           int     `json:"winnow_k"`
	WinnowW           int     `json:"winnow_w"`
	ChunkSizeBytes    int     `json:"chunk_size_bytes"`
	Enabled           bool    `json:"enabled"`
	Status            string  `json:"status"`
	FingerprintCount  int64   `json:"fingerprint_count"`
	LastIndexedDigest *string `json:"last_indexed_digest,omitempty"`
	LastIndexedAt     *string `json:"last_indexed_at,omitempty"`
	LastError         *string `json:"last_error,omitempty"`
	CreatedBy         *string `json:"created_by,omitempty"`
	CreatedAt         string  `json:"created_at"`
	UpdatedAt         string  `json:"updated_at"`
}

type IPCorporaListResponse struct {
	Corpora    []IPCorpusDTO `json:"corpora"`
	NextCursor *string       `json:"next_cursor,omitempty"`
	HasMore    bool          `json:"has_more"`
}

type ReindexIPCorpusRequest struct {
	Force      bool                   `json:"force,omitempty"`
	SourceRef  *string                `json:"source_ref,omitempty"`
	SourcePath *string                `json:"source_path,omitempty"`
	Files      []IPCorpusFileInputDTO `json:"files,omitempty"`
}

type ReindexIPCorpusResponseDTO struct {
	CorpusID            string  `json:"corpus_id"`
	OperationID         *string `json:"operation_id,omitempty"`
	Status              string  `json:"status"`
	FingerprintsIndexed int64   `json:"fingerprints_indexed"`
	FilesProcessed      int64   `json:"files_processed,omitempty"`
	LastIndexedDigest   *string `json:"last_indexed_digest,omitempty"`
	CompletedAt         *string `json:"completed_at,omitempty"`
}

// --- Secret / Restricted-Source Sanitization Helpers ---

var (
	apiSecretValuePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
		regexp.MustCompile(`(?i)\b(x-access-token|oauth2):[^\s@]+`),
		regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|glpat|github_pat)_[A-Za-z0-9_]{8,}\b`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	}

	apiForbiddenMetaKeys = map[string]struct{}{
		"rawsecret":           {},
		"secret":              {},
		"token":               {},
		"privatekey":          {},
		"password":            {},
		"credential":          {},
		"credentials":         {},
		"matchraw":            {},
		"rawsource":           {},
		"rawcode":             {},
		"sourcetext":          {},
		"content":             {},
		"snippet":             {},
		"contentsnippet":      {},
		"codesnippet":         {},
		"matchedtext":         {},
		"sourcesnippet":       {},
		"matchtext":           {},
		"rawline":             {},
		"sshkey":              {},
		"apikey":              {},
		"clientsecret":        {},
		"bearertoken":         {},
		"rawmatch":            {},
		"secretvalue":         {},
		"accesstoken":         {},
		"oidctoken":           {},
		"oauthtoken":          {},
		"pat":                 {},
		"authorization":       {},
		"xaccesstoken":        {},
		"extrasecrets":        {},
		"privatetoken":        {},
		"jobtoken":            {},
		"deploytoken":         {},
		"apitoken":            {},
		"authtoken":           {},
		"refreshtoken":        {},
		"idtoken":             {},
		"sessiontoken":        {},
		"personalaccesstoken": {},
		"passwd":              {},
		"secretkey":           {},
		"accesskey":           {},
		"xamzsecuritytoken":   {},
		"xamzcredential":      {},
		"xamzsignature":       {},
	}

	apiTimeType           = reflect.TypeOf(time.Time{})
	apiTimePtrType        = reflect.TypeOf((*time.Time)(nil))
	apiJSONRawMessageType = reflect.TypeOf(json.RawMessage(nil))
	apiJSONMarshalerType  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	apiTextMarshalerType  = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	apiByteSliceType      = reflect.TypeOf([]byte(nil))
	apiMapStringAnyType   = reflect.TypeOf((map[string]any)(nil))
	apiAnySliceType       = reflect.TypeOf(([]any)(nil))
)

type apiMetaVisitKey struct {
	kind reflect.Kind
	ptr  uintptr
	len  int
	typ  reflect.Type
}

func normalizeAPIMetaKey(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func scrubAPISecretString(s string) string {
	out := s
	for _, re := range apiSecretValuePatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

func sanitizeMetadataValue(v any) any {
	return sanitizeMetadataValueWith(v, nil)
}

func sanitizeMetadataValueWith(v any, visiting map[apiMetaVisitKey]bool) any {
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case string:
		return scrubAPISecretString(tv)
	case map[string]any:
		if sanitized := sanitizeMetadataMapWith(tv, visiting); sanitized != nil {
			return sanitized
		}
		return nil
	case []any:
		if tv == nil {
			return nil
		}
		if len(tv) > 0 {
			key := apiMetaVisitKey{
				kind: reflect.Slice,
				ptr:  reflect.ValueOf(tv).Pointer(),
				len:  len(tv),
				typ:  apiAnySliceType,
			}
			if visiting[key] {
				return nil
			}
			if visiting == nil {
				visiting = make(map[apiMetaVisitKey]bool)
			}
			visiting[key] = true
			defer delete(visiting, key)
		}
		out := make([]any, 0, len(tv))
		for _, elem := range tv {
			out = append(out, sanitizeMetadataValueWith(elem, visiting))
		}
		return out
	case json.RawMessage:
		return sanitizeRawJSON(tv, visiting)
	case *json.RawMessage:
		if tv == nil {
			return nil
		}
		return sanitizeRawJSON(*tv, visiting)
	}
	return sanitizeMetadataReflect(reflect.ValueOf(v), visiting)
}

func sanitizeRawJSON(raw []byte, visiting map[apiMetaVisitKey]bool) any {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		return scrubAPISecretString(string(trimmed))
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return scrubAPISecretString(string(trimmed))
	}
	return sanitizeMetadataValueWith(decoded, visiting)
}

func sanitizeMetadataReflect(rv reflect.Value, visiting map[apiMetaVisitKey]bool) any {
	if !rv.IsValid() {
		return nil
	}
	if rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		return sanitizeMetadataReflect(rv.Elem(), visiting)
	}
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil
	}
	if rv.Type() == apiJSONRawMessageType {
		return sanitizeRawJSON(rv.Bytes(), visiting)
	}
	if rv.Type() == apiTimeType || rv.Type() == apiTimePtrType {
		if rv.CanInterface() {
			return rv.Interface()
		}
		return nil
	}
	var marshaler json.Marshaler
	switch {
	case rv.CanInterface() && rv.Type().Implements(apiJSONMarshalerType):
		marshaler = rv.Interface().(json.Marshaler)
	case rv.Kind() != reflect.Pointer && rv.CanAddr() && rv.Addr().CanInterface() && rv.Addr().Type().Implements(apiJSONMarshalerType):
		marshaler = rv.Addr().Interface().(json.Marshaler)
	}
	if marshaler != nil {
		raw, err := marshaler.MarshalJSON()
		if err != nil {
			return nil
		}
		return sanitizeRawJSON(raw, visiting)
	}
	var textMarshaler encoding.TextMarshaler
	switch {
	case rv.CanInterface() && rv.Type().Implements(apiTextMarshalerType):
		textMarshaler = rv.Interface().(encoding.TextMarshaler)
	case rv.Kind() != reflect.Pointer && rv.CanAddr() && rv.Addr().CanInterface() && rv.Addr().Type().Implements(apiTextMarshalerType):
		textMarshaler = rv.Addr().Interface().(encoding.TextMarshaler)
	}
	if textMarshaler != nil {
		raw, err := textMarshaler.MarshalText()
		if err != nil {
			return nil
		}
		return scrubAPISecretString(string(raw))
	}

	switch rv.Kind() {
	case reflect.Pointer:
		key := apiMetaVisitKey{kind: reflect.Pointer, ptr: rv.Pointer(), typ: rv.Type()}
		if visiting[key] {
			return nil
		}
		if visiting == nil {
			visiting = make(map[apiMetaVisitKey]bool)
		}
		visiting[key] = true
		defer delete(visiting, key)
		return sanitizeMetadataReflect(rv.Elem(), visiting)
	case reflect.String:
		return scrubAPISecretString(rv.String())
	case reflect.Map:
		if rv.IsNil() || rv.Len() == 0 {
			return nil
		}
		key := apiMetaVisitKey{kind: reflect.Map, ptr: rv.Pointer(), typ: rv.Type()}
		if visiting[key] {
			return nil
		}
		if visiting == nil {
			visiting = make(map[apiMetaVisitKey]bool)
		}
		visiting[key] = true
		defer delete(visiting, key)

		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			kStr := metadataMapKeyToString(iter.Key())
			if _, forbidden := apiForbiddenMetaKeys[normalizeAPIMetaKey(kStr)]; forbidden {
				continue
			}
			var elemVal any
			if iter.Value().CanInterface() {
				elemVal = iter.Value().Interface()
			}
			out[kStr] = sanitizeMetadataValueWith(elemVal, visiting)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case reflect.Slice:
		if rv.IsNil() {
			return nil
		}
		elemType := rv.Type().Elem()
		if elemType == apiByteSliceType.Elem() {
			return scrubAPISecretString(string(rv.Bytes()))
		}
		if elemType.Kind() == reflect.Uint8 && !elemType.Implements(apiJSONMarshalerType) && !reflect.PointerTo(elemType).Implements(apiJSONMarshalerType) {
			b := make([]byte, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				b[i] = byte(rv.Index(i).Uint())
			}
			return scrubAPISecretString(string(b))
		}
		if rv.Len() > 0 {
			key := apiMetaVisitKey{kind: reflect.Slice, ptr: rv.Pointer(), len: rv.Len(), typ: rv.Type()}
			if visiting[key] {
				return nil
			}
			if visiting == nil {
				visiting = make(map[apiMetaVisitKey]bool)
			}
			visiting[key] = true
			defer delete(visiting, key)
		}
		out := make([]any, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			var elemVal any
			if idx := rv.Index(i); idx.CanInterface() {
				elemVal = idx.Interface()
			}
			out = append(out, sanitizeMetadataValueWith(elemVal, visiting))
		}
		return out
	case reflect.Array:
		elemType := rv.Type().Elem()
		if elemType.Kind() == reflect.Uint8 && !elemType.Implements(apiJSONMarshalerType) && !reflect.PointerTo(elemType).Implements(apiJSONMarshalerType) {
			b := make([]byte, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				b[i] = byte(rv.Index(i).Uint())
			}
			return scrubAPISecretString(string(b))
		}
		out := make([]any, 0, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			var elemVal any
			if idx := rv.Index(i); idx.CanInterface() {
				elemVal = idx.Interface()
			}
			out = append(out, sanitizeMetadataValueWith(elemVal, visiting))
		}
		return out
	case reflect.Struct:
		out := make(map[string]any)
		sanitizeStructFields(rv, visiting, out)
		if len(out) == 0 {
			return nil
		}
		return out
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		if rv.CanInterface() {
			return rv.Interface()
		}
		return nil
	default:
		return nil
	}
}

func metadataMapKeyToString(k reflect.Value) string {
	for k.Kind() == reflect.Interface || k.Kind() == reflect.Pointer {
		if k.IsNil() {
			return ""
		}
		k = k.Elem()
	}
	if k.Kind() == reflect.String {
		return k.String()
	}
	if k.CanInterface() {
		return fmt.Sprint(k.Interface())
	}
	return ""
}

func sanitizeStructFields(rv reflect.Value, visiting map[apiMetaVisitKey]bool, out map[string]any) {
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		sf := rt.Field(i)
		f := rv.Field(i)
		jsonTag := sf.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}
		tagName := strings.Split(jsonTag, ",")[0]
		if !sf.IsExported() {
			if sf.Anonymous && (f.Kind() == reflect.Struct || (f.Kind() == reflect.Pointer && !f.IsNil() && f.Type().Elem().Kind() == reflect.Struct)) {
				sub := sanitizeMetadataReflect(f, visiting)
				if subMap, ok := sub.(map[string]any); ok {
					for mk, mv := range subMap {
						out[mk] = mv
					}
				}
			}
			continue
		}
		if _, forbidden := apiForbiddenMetaKeys[normalizeAPIMetaKey(sf.Name)]; forbidden {
			continue
		}
		if tagName != "" {
			if _, forbidden := apiForbiddenMetaKeys[normalizeAPIMetaKey(tagName)]; forbidden {
				continue
			}
		}
		outKey := sf.Name
		if tagName != "" {
			outKey = tagName
		}
		var fieldVal any
		if f.CanInterface() {
			fieldVal = f.Interface()
		}
		out[outKey] = sanitizeMetadataValueWith(fieldVal, visiting)
	}
}

func sanitizeMetadataMap(m map[string]any) map[string]any {
	return sanitizeMetadataMapWith(m, nil)
}

func sanitizeMetadataMapWith(m map[string]any, visiting map[apiMetaVisitKey]bool) map[string]any {
	if len(m) == 0 {
		return nil
	}
	key := apiMetaVisitKey{
		kind: reflect.Map,
		ptr:  reflect.ValueOf(m).Pointer(),
		typ:  apiMapStringAnyType,
	}
	if visiting[key] {
		return nil
	}
	if visiting == nil {
		visiting = make(map[apiMetaVisitKey]bool)
	}
	visiting[key] = true
	defer delete(visiting, key)

	out := make(map[string]any, len(m))
	for k, v := range m {
		if _, forbidden := apiForbiddenMetaKeys[normalizeAPIMetaKey(k)]; forbidden {
			continue
		}
		out[k] = sanitizeMetadataValueWith(v, visiting)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isSensitiveDestinationQueryKey(k string) bool {
	norm := normalizeAPIMetaKey(k)
	if _, forbidden := apiForbiddenMetaKeys[norm]; forbidden {
		return true
	}
	switch norm {
	case "auth", "key", "code", "signature", "sig", "pass", "pwd":
		return true
	}
	return false
}

func hasSensitiveRawQuery(rawQuery string) bool {
	if rawQuery == "" {
		return false
	}
	if q, err := url.ParseQuery(rawQuery); err == nil {
		for k := range q {
			if isSensitiveDestinationQueryKey(k) {
				return true
			}
		}
		return false
	}
	for _, part := range strings.FieldsFunc(rawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
		if part == "" {
			continue
		}
		k, _, _ := strings.Cut(part, "=")
		decK, err := url.QueryUnescape(k)
		if err != nil || isSensitiveDestinationQueryKey(decK) || isSensitiveDestinationQueryKey(k) {
			return true
		}
	}
	return false
}

func scrubRawDestinationQueryParams(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.FieldsFunc(rawQuery, func(r rune) bool {
		return r == '&' || r == ';'
	})
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		k, v, hasEq := strings.Cut(part, "=")
		decK, kErr := url.QueryUnescape(k)
		if kErr != nil {
			continue
		}
		if isSensitiveDestinationQueryKey(decK) || isSensitiveDestinationQueryKey(k) {
			continue
		}
		if !hasEq {
			kept = append(kept, part)
			continue
		}
		if decV, vErr := url.QueryUnescape(v); vErr == nil {
			scrubbedDec := scrubAPISecretString(decV)
			if scrubbedDec != decV {
				kept = append(kept, k+"="+url.QueryEscape(scrubbedDec))
				continue
			}
		}
		kept = append(kept, k+"="+scrubAPISecretString(v))
	}
	return strings.Join(kept, "&")
}

func scrubRawDestinationQueryAndFragment(s string) string {
	baseAndQuery, frag, hasFrag := strings.Cut(s, "#")
	base, rawQuery, hasQuery := strings.Cut(baseAndQuery, "?")
	out := base
	if hasQuery {
		if scrubbedQuery := scrubRawDestinationQueryParams(rawQuery); scrubbedQuery != "" {
			out += "?" + scrubbedQuery
		}
	}
	if hasFrag {
		out += "#" + scrubAPISecretString(frag)
	}
	return scrubAPISecretString(out)
}

func sanitizeDestinationForAPI(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
			u.User = nil
			if u.RawQuery != "" {
				if q, qErr := url.ParseQuery(u.RawQuery); qErr == nil {
					for k, vals := range q {
						if isSensitiveDestinationQueryKey(k) {
							q.Del(k)
							continue
						}
						for i, v := range vals {
							vals[i] = scrubAPISecretString(v)
						}
						q[k] = vals
					}
					u.RawQuery = q.Encode()
				} else {
					u.RawQuery = scrubRawDestinationQueryParams(u.RawQuery)
				}
			}
			if u.Fragment != "" {
				u.Fragment = scrubAPISecretString(u.Fragment)
				u.RawFragment = ""
			}
			return scrubAPISecretString(u.String())
		}
	}
	if schemeSep := strings.Index(trimmed, "://"); schemeSep >= 0 {
		scheme := trimmed[:schemeSep]
		afterScheme := trimmed[schemeSep+3:]
		if atIdx := strings.Index(afterScheme, "@"); atIdx >= 0 {
			authEnd := strings.IndexAny(afterScheme, "/?#")
			if authEnd == -1 || atIdx < authEnd {
				userinfo := afterScheme[:atIdx]
				if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") || isCredentialUserinfo(userinfo) {
					return scrubRawDestinationQueryAndFragment(scheme + "://" + afterScheme[atIdx+1:])
				}
			}
		}
		return scrubRawDestinationQueryAndFragment(trimmed)
	}
	if atIdx := strings.Index(trimmed, "@"); atIdx >= 0 {
		authEnd := strings.IndexAny(trimmed, "/?#")
		if authEnd == -1 || atIdx < authEnd {
			userinfo := trimmed[:atIdx]
			afterAt := trimmed[atIdx+1:]
			if isCredentialUserinfo(userinfo) {
				return scrubRawDestinationQueryAndFragment(afterAt)
			}
		}
	}
	return scrubRawDestinationQueryAndFragment(trimmed)
}

func redactErrorMessageForAPI(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	scrubbed := scrubAPISecretString(trimmed)
	for len(scrubbed) > 512 {
		_, size := utf8.DecodeLastRuneInString(scrubbed)
		if size <= 0 {
			break
		}
		scrubbed = scrubbed[:len(scrubbed)-size]
	}
	return scrubbed
}

func sanitizeFindingForAPI(f domain.Finding) FindingDTO {
	dto := toFindingDTO(f)
	if dto.Message != nil {
		scrubbed := scrubAPISecretString(*dto.Message)
		dto.Message = &scrubbed
	}
	if strings.EqualFold(strings.TrimSpace(f.Category), "SECRET") {
		dto.Redacted = true
	}
	dto.Metadata = sanitizeMetadataMap(dto.Metadata)
	return dto
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// canonicalizeDestination normalizes destination to "<lowercase-host>/<path>"
// without embedded credentials or schemes, matching push_approval_releases and
// domain.PushApprovalRelease.IsUsableFor.
func canonicalizeDestination(rawDest, fallbackHost string) (canonDest string, host string, err error) {
	trimmed := strings.TrimSpace(rawDest)
	if trimmed == "" {
		return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must not be empty")
	}
	for _, r := range rawDest {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination contains invalid control characters")
		}
	}

	if schemePart, _, hasSchemeSep := strings.Cut(trimmed, "://"); hasSchemeSep && !strings.ContainsAny(schemePart, "@./[]\\:") {
		u, parseErr := url.Parse(trimmed)
		if parseErr != nil || strings.TrimSpace(u.Host) == "" {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination URL must include host")
		}
		host = strings.ToLower(strings.TrimSpace(u.Host))
		path := strings.TrimLeft(u.Path, "/")
		if path == "" {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
		}
		return host + "/" + path, host, nil
	}

	// Strip userinfo@ if present before the first '/'.
	if atIdx := strings.Index(trimmed, "@"); atIdx >= 0 {
		slashIdx := strings.Index(trimmed, "/")
		if slashIdx == -1 || atIdx < slashIdx {
			trimmed = strings.TrimSpace(trimmed[atIdx+1:])
			if trimmed == "" {
				return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include host and repository")
			}
		}
	}

	// Handle bracketed IPv6 hosts (e.g., [::1]:8443/Org/Repo or [::1]:Org/Repo or [::1]/Org/Repo).
	if strings.HasPrefix(trimmed, "[") {
		closeIdx := strings.Index(trimmed, "]")
		if closeIdx <= 1 || strings.ContainsAny(trimmed[1:closeIdx], "[ \t/?#\\") {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination has invalid bracketed host")
		}
		hostLiteral := strings.ToLower(trimmed[:closeIdx+1])
		rest := trimmed[closeIdx+1:]
		if strings.HasPrefix(rest, ":") {
			afterColon := rest[1:]
			if portPart, restPath, hasSlash := strings.Cut(afterColon, "/"); hasSlash {
				if isASCIIDigits(portPart) {
					path := strings.TrimLeft(restPath, "/")
					if path == "" {
						return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
					}
					h := hostLiteral + ":" + portPart
					return h + "/" + path, h, nil
				}
			} else if isASCIIDigits(afterColon) {
				return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
			}
			path := strings.TrimLeft(afterColon, "/")
			if path == "" {
				return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
			}
			return hostLiteral + "/" + path, hostLiteral, nil
		}
		if strings.HasPrefix(rest, "/") {
			path := strings.TrimLeft(rest, "/")
			if path == "" {
				return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
			}
			return hostLiteral + "/" + path, hostLiteral, nil
		}
		return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
	}

	// Handle SCP-style host:path vs host:port/path before splitting on '/'.
	colonIdx := strings.Index(trimmed, ":")
	slashIdx := strings.Index(trimmed, "/")
	if colonIdx >= 0 && (slashIdx == -1 || colonIdx < slashIdx) {
		beforeColon := strings.ToLower(strings.TrimSpace(trimmed[:colonIdx]))
		afterColon := trimmed[colonIdx+1:]
		if beforeColon == "" {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include host and repository")
		}
		if portPart, restPath, hasSlash := strings.Cut(afterColon, "/"); hasSlash && isASCIIDigits(portPart) {
			path := strings.TrimLeft(restPath, "/")
			if path == "" {
				return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
			}
			h := beforeColon + ":" + portPart
			return h + "/" + path, h, nil
		}
		if !strings.Contains(afterColon, "/") && isASCIIDigits(afterColon) {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
		}
		path := strings.TrimLeft(afterColon, "/")
		if path == "" {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include repository path")
		}
		return beforeColon + "/" + path, beforeColon, nil
	}

	fb := strings.ToLower(strings.TrimSpace(fallbackHost))
	h, path, ok := strings.Cut(trimmed, "/")
	if !ok {
		if fb == "" {
			return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include host and repository")
		}
		return fb + "/" + strings.TrimLeft(trimmed, "/"), fb, nil
	}
	hTrim := strings.TrimSpace(h)
	path = strings.TrimLeft(path, "/")
	if hTrim == "" || path == "" {
		return "", "", domain.BadRequest("INVALID_DESTINATION", "destination must include host and repository")
	}
	if fb != "" && !strings.Contains(hTrim, ".") && !strings.EqualFold(hTrim, "localhost") {
		return fb + "/" + strings.TrimLeft(trimmed, "/"), fb, nil
	}
	host = strings.ToLower(hTrim)
	return host + "/" + path, host, nil
}

// --- DTO Converters ---

func toPushSessionDTO(row persistence.PushSessionRow, principalSubject string) PushSessionDTO {
	d := row.ToDomain()
	idStr := d.ID.String()

	refs := make([]PushRefUpdateDTO, 0, len(d.RefUpdates))
	for _, ru := range d.RefUpdates {
		refs = append(refs, PushRefUpdateDTO{
			RefName: ru.RefName,
			OldOID:  ru.OldOID,
			NewOID:  ru.NewOID,
		})
	}
	lfsObjs := make([]PushLFSObjectDTO, 0, len(d.LFSObjects))
	for _, lo := range d.LFSObjects {
		lfsObjs = append(lfsObjs, PushLFSObjectDTO{
			OID:  normalizeHex64(lo.OID),
			Size: lo.Size,
		})
	}

	var transport *string
	if d.Transport.IsValid() {
		s := string(d.Transport)
		transport = &s
	}
	var delivery *string
	if d.PassiveAuditDelivery.IsValid() {
		s := string(d.PassiveAuditDelivery)
		delivery = &s
	}
	var verdict *string
	if d.Verdict != nil && d.Verdict.IsValid() {
		s := string(*d.Verdict)
		verdict = &s
	}

	latestDecID := optUUIDString(d.LatestPolicyDecisionID)
	updatedAt := formatTimestamp(d.UpdatedAt)

	return PushSessionDTO{
		ID:                     idStr,
		PushSessionID:          &idStr,
		PrincipalID:            d.PrincipalID.String(),
		PrincipalSubject:       optString(principalSubject),
		RepositoryID:           optUUIDString(d.RepositoryID),
		Destination:            sanitizeDestinationForAPI(d.Destination),
		DestinationHost:        optString(strings.ToLower(strings.TrimSpace(d.DestinationHost))),
		DestinationRegistered:  d.DestinationRegistered,
		DestinationExternal:    d.DestinationExternal,
		Transport:              transport,
		RefUpdates:             refs,
		HasLFS:                 d.HasLFS,
		LFSObjects:             lfsObjs,
		LFSObjectCount:         d.LFSObjectCount,
		LFSTotalBytes:          d.LFSTotalBytes,
		PushManifestDigest:     normalizeHex64OrNil(d.PushManifestDigest),
		BundleArtifactID:       optUUIDString(d.BundleArtifactID),
		EgressMode:             string(d.EgressMode),
		PassiveAuditDelivery:   delivery,
		Enforced:               d.Enforced,
		Status:                 string(d.Status),
		Verdict:                verdict,
		PolicyEffect:           verdict,
		LatestPolicyDecisionID: latestDecID,
		PolicyDecisionID:       latestDecID,
		ApprovalReleaseID:      optUUIDString(d.ApprovalReleaseID),
		ErrorCode:              optString(d.ErrorCode),
		ErrorMessage:           optString(redactErrorMessageForAPI(d.ErrorMessage)),
		UpstreamForwarded:      d.UpstreamForwarded,
		UpstreamBytesSent:      d.UpstreamBytesSent,
		CreatedAt:              formatTimestamp(d.CreatedAt),
		UpdatedAt:              &updatedAt,
		CompletedAt:            formatTimestampPtr(d.CompletedAt),
	}
}

func toPushScanRunSummaryDTO(row persistence.ScanRunRow) PushScanRunSummaryDTO {
	sr := row.ToDomain()
	var propID *string
	if sr.ProposalID != uuidNilFallback {
		s := sr.ProposalID.String()
		propID = &s
	}
	pushID := ""
	if sr.PushSessionID != nil {
		pushID = sr.PushSessionID.String()
	}
	return PushScanRunSummaryDTO{
		ID:             sr.ID.String(),
		ProposalID:     propID,
		PushSessionID:  pushID,
		ArtifactID:     sr.ArtifactID.String(),
		Scanner:        sr.Scanner,
		ScannerVersion: sr.ScannerVersion,
		Status:         string(sr.Status),
		FilesExamined:  sr.Coverage.FilesExamined,
		FilesSkipped:   sr.Coverage.FilesSkipped,
		Complete:       sr.Coverage.Complete,
		StartedAt:      formatTimestamp(sr.StartedAt),
		CompletedAt:    formatTimestampPtr(sr.CompletedAt),
	}
}

var uuidNilFallback [16]byte

func toPushModelAssessmentDTO(row persistence.ModelAssessmentRow) PushModelAssessmentDTO {
	a := row.ToDomain()
	var propID *string
	if a.ProposalID != uuidNilFallback {
		s := a.ProposalID.String()
		propID = &s
	}
	pushID := ""
	if a.PushSessionID != nil {
		pushID = a.PushSessionID.String()
	}
	var risk *string
	if a.Risk.IsValid() {
		s := string(a.Risk)
		risk = &s
	}
	var disp *string
	if a.Disposition.IsValid() {
		s := string(a.Disposition)
		disp = &s
	}
	findings := make([]ModelFindingDTO, 0, len(a.Result.Findings))
	for _, f := range a.Result.Findings {
		evIDs := f.EvidenceIDs
		if evIDs == nil {
			evIDs = []string{}
		}
		findings = append(findings, ModelFindingDTO{
			Category:          f.Category,
			EvidenceIDs:       evIDs,
			Reason:            scrubAPISecretString(f.Reason),
			RecommendedAction: f.RecommendedAction,
		})
	}
	lims := a.Result.Limitations
	if lims == nil {
		lims = []string{}
	}
	return PushModelAssessmentDTO{
		ID:             a.ID.String(),
		ProposalID:     propID,
		PushSessionID:  pushID,
		ArtifactID:     a.ArtifactID.String(),
		ModelRoute:     a.ModelRoute,
		ModelVersion:   a.ModelVersion,
		PromptVersion:  a.PromptVersion,
		AssessmentType: a.AssessmentType,
		Status:         string(a.Status),
		Risk:           risk,
		Disposition:    disp,
		Summary:        optString(scrubAPISecretString(a.Result.Summary)),
		Findings:       findings,
		Limitations:    lims,
		InputDigest:    normalizeHex64(a.InputDigest),
		OutputDigest:   normalizeHex64(a.OutputDigest),
		CreatedAt:      formatTimestamp(a.CreatedAt),
	}
}

func toPushPolicyDecisionDTO(row persistence.PolicyDecisionRow) PushPolicyDecisionDTO {
	pd := row.ToDomain()
	var propID *string
	if pd.ProposalID != uuidNilFallback {
		s := pd.ProposalID.String()
		propID = &s
	}
	pushID := ""
	if pd.PushSessionID != nil {
		pushID = pd.PushSessionID.String()
	}
	reasons := make([]PolicyReasonDTO, 0, len(pd.Reasons))
	for _, r := range pd.Reasons {
		reasons = append(reasons, PolicyReasonDTO{
			RuleID:  r.RuleID,
			Effect:  string(r.Effect),
			Stage:   optString(r.Stage),
			Message: optString(r.Message),
		})
	}
	stage := string(pd.Stage)
	if stage == "" {
		stage = string(domain.PolicyStagePushEgress)
	}
	return PushPolicyDecisionDTO{
		ID:             pd.ID.String(),
		ProposalID:     propID,
		PushSessionID:  pushID,
		PolicyBundleID: pd.PolicyBundleID.String(),
		Stage:          stage,
		Enforced:       pd.Enforced,
		InputDigest:    normalizeHex64(pd.InputDigest),
		Effect:         string(pd.Effect),
		Reasons:        reasons,
		Obligations:    toObligationDTOs(pd.Obligations),
		CreatedAt:      formatTimestamp(pd.CreatedAt),
	}
}

func toPushApprovalReleaseResponseDTO(row persistence.PushApprovalReleaseRow, decision, comment string) PushApprovalReleaseResponseDTO {
	d := row.ToDomain()
	if decision == "" {
		decision = "APPROVE"
	}
	decID := d.PolicyDecisionID.String()
	return PushApprovalReleaseResponseDTO{
		ID:                      d.ID.String(),
		PushSessionID:           d.PushSessionID.String(),
		PrincipalID:             d.PrincipalID.String(),
		ApprovedBy:              d.ApprovedBy.String(),
		ConsumedByPushSessionID: optUUIDString(d.ConsumedByPushSessionID),
		PolicyDecisionID:        &decID,
		Destination:             sanitizeDestinationForAPI(d.Destination),
		PushManifestDigest:      normalizeHex64(d.PushManifestDigest),
		Decision:                decision,
		SingleUse:               true,
		Consumed:                d.ConsumedAt != nil || d.ConsumedByPushSessionID != nil,
		Reason:                  optString(d.Reason),
		Comment:                 optString(comment),
		ExpiresAt:               formatTimestampPtr(&d.ExpiresAt),
		ConsumedAt:              formatTimestampPtr(d.ConsumedAt),
		RevokedAt:               formatTimestampPtr(d.RevokedAt),
		CreatedAt:               formatTimestamp(d.CreatedAt),
	}
}

func toIPCorpusDTO(row persistence.IPFingerprintCorpusRow) IPCorpusDTO {
	c := row.ToDomain()
	return IPCorpusDTO{
		ID:                c.ID.String(),
		Name:              c.Name,
		Description:       optString(c.Description),
		Classification:    string(c.Classification),
		RepositoryID:      optUUIDString(c.RepositoryID),
		SourceRef:         optString(c.SourceRef),
		WinnowK:           c.WinnowK,
		WinnowW:           c.WinnowW,
		ChunkSizeBytes:    c.ChunkSizeBytes,
		Enabled:           c.Enabled,
		Status:            string(c.Status),
		FingerprintCount:  c.FingerprintCount,
		LastIndexedDigest: normalizeHex64OrNil(c.LastIndexedDigest),
		LastIndexedAt:     formatTimestampPtr(c.LastIndexedAt),
		LastError:         optString(redactErrorMessageForAPI(c.LastError)),
		CreatedBy:         optUUIDString(c.CreatedBy),
		CreatedAt:         formatTimestamp(c.CreatedAt),
		UpdatedAt:         formatTimestamp(c.UpdatedAt),
	}
}
