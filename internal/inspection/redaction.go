package inspection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/timreynolds/custodian/internal/domain"
)

const redactedMarker = "[REDACTED]"

var (
	evidenceIDPattern    = regexp.MustCompile(`^finding_[A-Za-z0-9_-]+$`)
	urlCredSubTokenRe    = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://([^/\s:@]*):([^/\s@]+)@`)
	authHeaderSubTokenRe = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{6,})`)
	quotedKVSubTokenRe   = regexp.MustCompile(`[^\s=:]+\s*[:=]\s*(?:"([^"]+)"|'([^']+)')`)

	jsonMarshalerType  = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	jsonRawMessageType = reflect.TypeOf(json.RawMessage(nil))
	timeType           = reflect.TypeOf(time.Time{})
	timePtrType        = reflect.TypeOf((*time.Time)(nil))
	byteSliceType      = reflect.TypeOf([]byte(nil))
	stringSliceType    = reflect.TypeOf([]string(nil))
)

var forbiddenFindingMetadataKeys = map[string]struct{}{
	"raw_secret":  {},
	"secret":      {},
	"token":       {},
	"private_key": {},
	"password":    {},
	"credential":  {},
	"match_raw":   {},
}

var secretScrubPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+[A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----`),
	regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`),
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
	regexp.MustCompile(`\bx-access-token:[^\s@'"]+`),
	regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`\bxox[bp]-[A-Za-z0-9-]{8,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`),
	regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]*:[^/\s@]+@`),
}

// Redactor scrubs raw secrets, their encoded variants (base64-std, base64-rawurl, URL-escaped),
// and known credential patterns from findings, metadata, and diagnostic strings.
type Redactor struct {
	mu      sync.RWMutex
	secrets map[string]struct{}
}

// NewRedactor creates a Redactor seeded with optional initial secret values.
func NewRedactor(initialSecrets ...string) *Redactor {
	r := &Redactor{
		secrets: make(map[string]struct{}),
	}
	r.AddSecrets(initialSecrets...)
	return r
}

// AddSecrets registers secret strings whose verbatim and encoded representations must be scrubbed.
func (r *Redactor) AddSecrets(values ...string) {
	if r == nil || len(values) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, raw := range values {
		r.addSingleLocked(raw)
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" && trimmed != raw {
			r.addSingleLocked(trimmed)
		}
	}
}

func (r *Redactor) addSingleLocked(val string) {
	if len(val) < 4 {
		return
	}
	r.secrets[val] = struct{}{}
	r.registerCredentialSubTokensLocked(val)

	// Normalize CRLF -> LF so multi-line blocks (e.g., PEM/PGP) scrub regardless of line endings.
	lf := val
	if strings.Contains(val, "\r\n") {
		lf = strings.ReplaceAll(val, "\r\n", "\n")
		if len(lf) >= 4 {
			r.secrets[lf] = struct{}{}
			r.registerCredentialSubTokensLocked(lf)
		}
	}
	if strings.Contains(lf, "-----BEGIN ") && strings.Contains(lf, "-----END ") {
		trimmedBlock := strings.TrimSpace(lf)
		if len(trimmedBlock) >= 4 {
			r.secrets[trimmedBlock] = struct{}{}
			r.secrets[trimmedBlock+"\n"] = struct{}{}
		}
	}

	// If val spans multiple lines (e.g., PEM/PGP block), also register substantial non-delimiter lines.
	if strings.Contains(lf, "\n") {
		for _, line := range strings.Split(lf, "\n") {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) < 6 {
				continue
			}
			if strings.HasPrefix(trimmed, "-----BEGIN ") || strings.HasPrefix(trimmed, "-----END ") {
				continue
			}
			r.secrets[trimmed] = struct{}{}
			r.registerCredentialSubTokensLocked(trimmed)
		}
	}
}

func (r *Redactor) addURLPasswordLocked(rawPass string) {
	if len(rawPass) >= 4 {
		r.secrets[rawPass] = struct{}{}
	}
	if unescaped, err := url.PathUnescape(rawPass); err == nil && len(unescaped) >= 4 {
		r.secrets[unescaped] = struct{}{}
	}
	if unescaped, err := url.QueryUnescape(rawPass); err == nil && len(unescaped) >= 4 {
		r.secrets[unescaped] = struct{}{}
	}
}

func (r *Redactor) registerCredentialSubTokensLocked(val string) {
	for _, m := range urlCredSubTokenRe.FindAllStringSubmatch(val, -1) {
		if len(m) >= 3 && len(m[2]) >= 4 {
			r.addURLPasswordLocked(m[2])
		}
	}
	for _, m := range authHeaderSubTokenRe.FindAllStringSubmatch(val, -1) {
		if len(m) >= 2 && len(m[1]) >= 4 {
			r.secrets[m[1]] = struct{}{}
		}
	}

	// Handle .env multi-token lines (e.g. FOO=a BAR=b) and unquoted inline # comments.
	cleaned := stripUnquotedInlineComment(val)
	if cleaned != "" && cleaned != val && len(cleaned) >= 4 {
		r.secrets[cleaned] = struct{}{}
	}
	kvVals := extractEnvAssignmentValues(cleaned)
	for _, kv := range kvVals {
		if len(kv) >= 4 {
			r.secrets[kv] = struct{}{}
			for _, m := range urlCredSubTokenRe.FindAllStringSubmatch(kv, -1) {
				if len(m) >= 3 && len(m[2]) >= 4 {
					r.addURLPasswordLocked(m[2])
				}
			}
			for _, m := range authHeaderSubTokenRe.FindAllStringSubmatch(kv, -1) {
				if len(m) >= 2 && len(m[1]) >= 4 {
					r.secrets[m[1]] = struct{}{}
				}
			}
		}
	}

	// Extract quoted key[:=]"..." / '...' values across the entire line regardless of other key=value pairs.
	quotedMatches := quotedKVSubTokenRe.FindAllStringSubmatch(cleaned, -1)
	for _, m := range quotedMatches {
		valMatch := strings.TrimSpace(m[1])
		if valMatch == "" {
			valMatch = strings.TrimSpace(m[2])
		}
		if len(valMatch) >= 4 {
			r.secrets[valMatch] = struct{}{}
			if subCleaned := stripUnquotedInlineComment(valMatch); subCleaned != "" && subCleaned != valMatch && len(subCleaned) >= 4 {
				r.secrets[subCleaned] = struct{}{}
			}
			for _, um := range urlCredSubTokenRe.FindAllStringSubmatch(valMatch, -1) {
				if len(um) >= 3 && len(um[2]) >= 4 {
					r.addURLPasswordLocked(um[2])
				}
			}
			for _, am := range authHeaderSubTokenRe.FindAllStringSubmatch(valMatch, -1) {
				if len(am) >= 2 && len(am[1]) >= 4 {
					r.secrets[am[1]] = struct{}{}
				}
			}
		}
	}

	// Extract quote-trimmed values from key=value / key:value tokens across the line.
	hasTokenKV := false
	for _, tok := range strings.Fields(cleaned) {
		unquoted := strings.Trim(tok, `"'`)
		if idx := strings.IndexAny(unquoted, "=:"); idx > 0 && idx+1 < len(unquoted) {
			lhs := unquoted[:idx]
			rhs := strings.Trim(strings.TrimSpace(unquoted[idx+1:]), `"'`)
			if strings.Contains(lhs, "://") || strings.HasPrefix(rhs, "//") {
				continue
			}
			hasTokenKV = true
			if len(rhs) >= 4 {
				r.secrets[rhs] = struct{}{}
			}
		}
	}

	// Fallback for single key=value or key:value expressions (e.g., "secret: value" or "x-access-token:tok").
	if len(kvVals) == 0 && !hasTokenKV && len(quotedMatches) == 0 && !strings.Contains(cleaned, "\n") {
		if idx := strings.IndexAny(cleaned, "=:"); idx > 0 && idx+1 < len(cleaned) {
			rhs := strings.Trim(strings.TrimSpace(cleaned[idx+1:]), `"'`)
			if len(rhs) >= 4 {
				r.secrets[rhs] = struct{}{}
			}
		}
	}
}

func stripUnquotedInlineComment(line string) string {
	if strings.Contains(line, "\n") {
		return line
	}
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		switch ch {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '#':
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

func extractEnvAssignmentValues(line string) []string {
	if line == "" || strings.Contains(line, "\n") || strings.HasPrefix(strings.TrimSpace(line), "#") {
		return nil
	}
	var tokens []string
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		if line[i] == '#' {
			break
		}
		start := i
		inSingle := false
		inDouble := false
		escaped := false
		for i < len(line) {
			ch := line[i]
			if inDouble {
				if escaped {
					escaped = false
					i++
					continue
				}
				if ch == '\\' {
					escaped = true
					i++
					continue
				}
				if ch == '"' {
					inDouble = false
				}
				i++
				continue
			}
			if inSingle {
				if ch == '\'' {
					inSingle = false
				}
				i++
				continue
			}
			if ch == ' ' || ch == '\t' {
				break
			}
			if ch == '"' {
				inDouble = true
			} else if ch == '\'' {
				inSingle = true
			}
			i++
		}
		tokens = append(tokens, line[start:i])
	}

	var values []string
	for _, tok := range tokens {
		eqIdx := strings.IndexByte(tok, '=')
		if eqIdx <= 0 || eqIdx+1 >= len(tok) {
			continue
		}
		lhs := tok[:eqIdx]
		if strings.Contains(lhs, "://") {
			continue
		}
		rhs := strings.TrimSpace(tok[eqIdx+1:])
		if len(rhs) >= 2 && ((rhs[0] == '"' && rhs[len(rhs)-1] == '"') || (rhs[0] == '\'' && rhs[len(rhs)-1] == '\'')) {
			rhs = rhs[1 : len(rhs)-1]
		}
		if rhs != "" {
			values = append(values, rhs)
		}
	}
	return values
}

func (r *Redactor) expandedTokens() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	base := make([]string, 0, len(r.secrets))
	for s := range r.secrets {
		base = append(base, s)
	}
	r.mu.RUnlock()

	if len(base) == 0 {
		return nil
	}

	variants := make(map[string]struct{}, len(base)*5)
	for _, s := range base {
		for _, cand := range []string{
			s,
			base64.StdEncoding.EncodeToString([]byte(s)),
			base64.RawStdEncoding.EncodeToString([]byte(s)),
			base64.RawURLEncoding.EncodeToString([]byte(s)),
			base64.URLEncoding.EncodeToString([]byte(s)),
			url.QueryEscape(s),
			url.PathEscape(s),
		} {
			if len(cand) >= 4 {
				variants[cand] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(variants))
	for v := range variants {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// ScrubString replaces all registered secrets (verbatim + encoded forms) and known credential patterns.
func (r *Redactor) ScrubString(in string) string {
	if in == "" {
		return ""
	}
	out := in
	for _, tok := range r.expandedTokens() {
		if strings.Contains(out, tok) {
			out = strings.ReplaceAll(out, tok, redactedMarker)
		}
	}
	for _, pat := range secretScrubPatterns {
		out = pat.ReplaceAllString(out, redactedMarker)
	}
	return out
}

type metadataVisitKey struct {
	kind reflect.Kind
	ptr  uintptr
	len  int
	typ  reflect.Type
}

// SanitizeMetadata recursively strips forbidden secret keys and scrubs all string values.
func (r *Redactor) SanitizeMetadata(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return map[string]any{}
	}
	cleaned, ok := r.sanitizeValue(meta, nil).(map[string]any)
	if !ok || cleaned == nil {
		return map[string]any{}
	}
	return cleaned
}

func (r *Redactor) sanitizeValue(v any, visiting map[metadataVisitKey]bool) any {
	if v == nil {
		return nil
	}
	return r.sanitizeReflect(reflect.ValueOf(v), visiting)
}

func (r *Redactor) sanitizeReflect(rv reflect.Value, visiting map[metadataVisitKey]bool) any {
	if !rv.IsValid() {
		return nil
	}
	for rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil
	}
	if rv.Type() == jsonRawMessageType {
		if rv.IsNil() {
			return nil
		}
		raw := rv.Bytes()
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err == nil {
			return r.sanitizeValue(decoded, visiting)
		}
		return r.ScrubString(string(raw))
	}

	// Check json.Marshaler BEFORE dereferencing reflect.Pointer so pointer-receiver MarshalJSON
	// implementations are honored consistently with encoding/json and domain.ValidateRedacted.
	if rv.Type() != timeType && rv.Type() != timePtrType {
		var marshaler json.Marshaler
		switch {
		case rv.CanInterface() && rv.Type().Implements(jsonMarshalerType):
			marshaler = rv.Interface().(json.Marshaler)
		case rv.Kind() != reflect.Pointer && rv.CanAddr() && rv.Addr().CanInterface() && rv.Addr().Type().Implements(jsonMarshalerType):
			marshaler = rv.Addr().Interface().(json.Marshaler)
		}
		if marshaler != nil {
			raw, err := marshaler.MarshalJSON()
			if err != nil {
				return r.ScrubString(fmt.Sprint(rv.Interface()))
			}
			var decoded any
			if err := json.Unmarshal(raw, &decoded); err == nil {
				return r.sanitizeValue(decoded, visiting)
			}
			return r.ScrubString(string(raw))
		}
	}

	switch rv.Kind() {
	case reflect.String:
		return r.ScrubString(rv.String())
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
		return r.sanitizeReflect(rv.Elem(), visiting)
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

		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			mk := iter.Key()
			var kStr string
			if mk.Kind() == reflect.String {
				kStr = mk.String()
			} else if mk.CanInterface() {
				kStr = fmt.Sprint(mk.Interface())
			}
			if isForbiddenMetadataKey(kStr) {
				continue
			}
			out[r.ScrubString(kStr)] = r.sanitizeReflect(iter.Value(), visiting)
		}
		return out
	case reflect.Slice:
		if rv.Type() == byteSliceType {
			return r.ScrubString(string(rv.Bytes()))
		}
		if rv.IsNil() {
			return nil
		}
		if rv.Len() > 0 {
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
		if rv.Type() == stringSliceType {
			out := make([]string, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				out[i] = r.ScrubString(rv.Index(i).String())
			}
			return out
		}
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = r.sanitizeReflect(rv.Index(i), visiting)
		}
		return out
	case reflect.Array:
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = r.sanitizeReflect(rv.Index(i), visiting)
		}
		return out
	case reflect.Struct:
		if rv.Type() == timeType {
			return rv.Interface()
		}
		raw, err := json.Marshal(rv.Interface())
		if err != nil {
			return r.ScrubString(fmt.Sprint(rv.Interface()))
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return r.ScrubString(string(raw))
		}
		return r.sanitizeValue(decoded, visiting)
	default:
		if rv.CanInterface() {
			return rv.Interface()
		}
		return nil
	}
}

func isForbiddenMetadataKey(k string) bool {
	_, bad := forbiddenFindingMetadataKeys[strings.ToLower(strings.TrimSpace(k))]
	return bad
}

// FinalizeFinding normalizes, redacts, computes deterministic Fingerprint & EvidenceID,
// assigns UUIDv7 ID, and enforces ValidateRedacted() as a mandatory fail-closed gate.
func (r *Redactor) FinalizeFinding(f *domain.Finding, scanRunID uuid.UUID) error {
	if f == nil {
		return domain.Internal("NIL_FINDING", "cannot finalize nil finding")
	}
	if f.ID == uuid.Nil || !domain.IsUUIDv7(f.ID) {
		id, err := domain.NewID()
		if err != nil {
			return err
		}
		f.ID = id
	}
	if scanRunID != uuid.Nil {
		f.ScanRunID = scanRunID
	}

	f.Scanner = strings.TrimSpace(f.Scanner)
	f.Category = strings.ToUpper(strings.TrimSpace(f.Category))
	if f.Category == "" {
		f.Category = "POLICY"
	}
	f.Severity = normalizeSeverity(string(f.Severity))
	f.RuleID = r.ScrubString(strings.TrimSpace(f.RuleID))
	if f.RuleID == "" {
		f.RuleID = "unspecified-rule"
	}
	f.Path = r.ScrubString(strings.TrimSpace(f.Path))
	if f.StartLine < 0 {
		f.StartLine = 0
	}
	if f.EndLine < 0 {
		f.EndLine = 0
	}
	if f.EndLine > 0 && f.EndLine < f.StartLine {
		f.EndLine = f.StartLine
	}
	if math.IsNaN(f.Confidence) || f.Confidence < 0 {
		f.Confidence = 0
	}
	if f.Confidence > 1 {
		f.Confidence = 1
	}

	f.Message = r.ScrubString(strings.TrimSpace(f.Message))
	f.EvidenceRef = r.ScrubString(strings.TrimSpace(f.EvidenceRef))
	f.Baseline = r.ScrubString(strings.TrimSpace(f.Baseline))
	f.Metadata = r.SanitizeMetadata(f.Metadata)
	f.Redacted = true

	if !domain.IsValidSHA256Hex(f.Fingerprint) {
		f.Fingerprint = ComputeFingerprint(f.Scanner, f.RuleID, f.Path, f.StartLine, f.EndLine, f.Fingerprint)
	}
	f.EvidenceID = strings.TrimSpace(f.EvidenceID)
	if !evidenceIDPattern.MatchString(f.EvidenceID) || r.ScrubString(f.EvidenceID) != f.EvidenceID {
		f.EvidenceID = ComputeEvidenceID(f.Scanner, f.Category, f.RuleID, f.Path, f.StartLine, f.EndLine, f.Fingerprint)
	}

	if err := f.ValidateRedacted(); err != nil {
		return err
	}
	return nil
}

func normalizeSeverity(raw string) domain.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH", "ERROR":
		return domain.SeverityHigh
	case "MEDIUM", "WARNING", "WARN":
		return domain.SeverityMedium
	case "LOW", "UNKNOWN":
		return domain.SeverityLow
	case "INFO", "NOTE":
		return domain.SeverityInfo
	default:
		return domain.SeverityMedium
	}
}
