package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/proposals"
)

const maxJSONBodyBytes = 4 << 20 // 4 MiB cap for JSON API payloads

func writeJSON(w http.ResponseWriter, status int, body any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"failed to encode response"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeRawJSON(w http.ResponseWriter, status int, headers map[string]string, body []byte) {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		w.Header().Set(k, v)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func writeError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	status, resp := buildErrorResponse(r, err)
	if status == http.StatusTooManyRequests && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	if logger != nil && status >= 500 {
		log := observability.LoggerWithTrace(r.Context(), logger)
		log.Error("api internal or upstream error",
			"http_status", status,
			"error_code", resp.Error.Code,
			"method", r.Method,
			"route", routePattern(r),
		)
	}
	writeJSON(w, status, resp)
}

func buildErrorResponse(r *http.Request, err error) (int, ErrorResponse) {
	status := http.StatusInternalServerError
	code := "INTERNAL_ERROR"
	msg := "an internal error occurred"
	var policyDecisionID *string

	var pde *proposals.PolicyDeniedError
	if errors.As(err, &pde) && pde != nil {
		status = http.StatusConflict
		if pde.PolicyDecisionID != uuid.Nil {
			s := pde.PolicyDecisionID.String()
			policyDecisionID = &s
		}
		if pde.Err != nil {
			code = pde.Err.Code()
			msg = pde.Err.Message
		} else {
			code = "POLICY_DENIED"
			msg = fmt.Sprintf("proposal is blocked by policy effect %s", pde.Effect)
		}
	} else {
		var domErr *domain.DomainError
		if errors.As(err, &domErr) && domErr != nil {
			status = domErr.HTTPStatus()
			code = domErr.Code()
			msg = domErr.Message
		} else if err != nil {
			status = domain.HTTPStatusFromError(err)
			code = defaultCodeForHTTPStatus(status)
			if status < 500 {
				msg = err.Error()
			}
		}
	}

	if code == "" {
		code = defaultCodeForHTTPStatus(status)
	}
	if len(code) > 128 {
		code = code[:128]
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	if len(msg) > 512 {
		msg = msg[:512]
	}

	var traceID *string
	if r != nil {
		sc := trace.SpanContextFromContext(r.Context())
		if sc.IsValid() {
			t := sc.TraceID().String()
			if len(t) > 64 {
				t = t[:64]
			}
			traceID = &t
		}
	}

	return status, ErrorResponse{
		Error: ErrorDetail{
			Code:             code,
			Message:          msg,
			TraceID:          traceID,
			PolicyDecisionID: policyDecisionID,
		},
	}
}

func defaultCodeForHTTPStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusRequestEntityTooLarge:
		return "PAYLOAD_TOO_LARGE"
	case http.StatusUnprocessableEntity:
		return "UNPROCESSABLE_ENTITY"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	default:
		return "INTERNAL_ERROR"
	}
}

func readBoundedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = maxJSONBodyBytes
	}
	if r.Body == nil {
		return nil, nil
	}
	reader := http.MaxBytesReader(w, r.Body, maxBytes)
	data, err := io.ReadAll(reader)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, domain.BadRequest("REQUEST_TOO_LARGE", "request body exceeds maximum allowed size")
		}
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_REQUEST_BODY", "failed reading request body", err)
	}
	return data, nil
}

func decodeStrictJSONBytes(raw []byte, dst any, allowEmpty bool, allowNullChildPaths ...string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if allowEmpty {
			return nil
		}
		return domain.BadRequest("INVALID_JSON", "request body must not be empty")
	}
	if bytes.Equal(trimmed, []byte("null")) {
		return domain.BadRequest("INVALID_JSON", "request body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return domain.WrapError(domain.ErrBadRequest, "INVALID_JSON", fmt.Sprintf("invalid JSON request body: %v", err), err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return domain.BadRequest("INVALID_JSON", "request body contains trailing JSON tokens")
	}
	if err := checkNoNullJSONFields(trimmed, allowNullChildPaths...); err != nil {
		return err
	}
	return nil
}

func checkNoNullJSONFields(trimmed []byte, allowNullChildPaths ...string) error {
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return domain.WrapError(domain.ErrBadRequest, "INVALID_JSON", fmt.Sprintf("invalid JSON request body: %v", err), err)
	}
	allowSet := make(map[string]struct{}, len(allowNullChildPaths))
	for _, p := range allowNullChildPaths {
		allowSet[p] = struct{}{}
	}
	return walkRejectNullJSON("", root, allowSet)
}

func walkRejectNullJSON(path string, v any, allowChildrenOf map[string]struct{}) error {
	switch tv := v.(type) {
	case nil:
		if path == "" {
			return domain.BadRequest("INVALID_JSON", "request body must be a JSON object")
		}
		return domain.BadRequest("INVALID_JSON", fmt.Sprintf("field %q must not be null", path))
	case map[string]any:
		if _, skipChildren := allowChildrenOf[path]; skipChildren {
			return nil
		}
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			if err := walkRejectNullJSON(childPath, tv[k], allowChildrenOf); err != nil {
				return err
			}
		}
	case []any:
		if _, skipChildren := allowChildrenOf[path]; skipChildren {
			return nil
		}
		for i, elem := range tv {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := walkRejectNullJSON(elemPath, elem, allowChildrenOf); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseUUIDv7(raw string) (uuid.UUID, error) {
	id, err := domain.ParseID(raw)
	if err != nil {
		return uuid.Nil, err
	}
	if !domain.IsUUIDv7(id) {
		return uuid.Nil, domain.BadRequest("INVALID_ID", "id must be a valid UUIDv7")
	}
	return id, nil
}

func parseUUIDv7Param(r *http.Request, name string) (uuid.UUID, error) {
	return parseUUIDv7(chi.URLParam(r, name))
}

func parsePositiveInt64(raw string, code, msg string) (int64, error) {
	val, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || val < 1 {
		return 0, domain.BadRequest(code, msg)
	}
	return val, nil
}
