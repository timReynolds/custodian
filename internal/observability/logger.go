package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

type LogFormat string

const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

const (
	redactedPlaceholder = "[REDACTED]"
	maxLogStringLen     = 256
)

type LoggerConfig struct {
	Writer         io.Writer
	Level          slog.Leveler
	Format         LogFormat
	Component      string
	ExtraAllowlist []string
}

var defaultAllowlist = []string{
	// IDs
	"trace_id", "span_id", "request_id", "correlation_id",
	"workspace_id", "proposal_id", "operation_id", "artifact_id",
	"source_artifact_id", "snapshot_artifact_id", "canonical_artifact_id", "manifest_artifact_id",
	"repository_id", "github_repository_id", "github_installation_id",
	"principal_id", "owner_id", "actor_id", "agent_id", "agent_session_id",
	"publication_id", "scan_run_id", "finding_id", "evidence_id",
	"policy_bundle_id", "policy_decision_id", "model_assessment_id", "assessment_id",
	"approval_id", "outbox_event_id", "audit_event_id", "idempotency_key",
	"rule_id", "reviewer_group", "resource_id", "aggregate_id", "pull_request_number",
	// Digests & hashes
	"sha256", "digest", "tree_digest", "diff_digest", "manifest_digest",
	"publication_manifest_digest", "input_digest", "output_digest", "bundle_digest",
	"artifact_sha", "event_hash", "previous_hash", "fingerprint", "commit_sha", "base_commit",
	// Safe operational metadata
	"status", "effect", "disposition", "risk", "severity", "category",
	"error_code", "err_code", "http_status", "method", "path", "route",
	"duration_ms", "operation_type", "event_type", "resource_type",
	"scanner", "scanner_version", "model_route", "model_version", "prompt_version",
	"assessment_type", "classification", "component", "service", "version",
	"stage", "generation", "attempts", "attempt_count", "size_bytes",
	"files_examined", "files_skipped", "complete", "branch_ref", "target_ref", "reason",
}

var defaultAllowedGroups = []string{
	"request", "http", "trace", "workspace", "proposal", "operation",
	"artifact", "repository", "principal", "publication", "scan",
	"assessment", "policy", "approval", "audit", "error", "metadata",
}

var explicitDenylist = map[string]struct{}{
	"source": {}, "diff": {}, "patch": {}, "code": {}, "content": {},
	"prompt": {}, "system_prompt": {}, "token": {}, "access_token": {},
	"refresh_token": {}, "id_token": {}, "secret": {}, "client_secret": {},
	"password": {}, "passwd": {}, "authorization": {}, "auth": {},
	"cookie": {}, "set_cookie": {}, "private_key": {}, "api_key": {},
	"apikey": {}, "body": {}, "payload": {}, "email": {},
	"verified_email": {}, "comment": {}, "stdout": {}, "stderr": {},
	"env": {}, "headers": {}, "raw": {},
}

var secretValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
	regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`),
	regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`\bxox[bp]-[A-Za-z0-9-]{8,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`),
	regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]*:[^/\s@]+@`),
}

// SafeHandler wraps an slog.Handler and enforces an ID/digest-only allowlist plus secret/payload redaction.
type SafeHandler struct {
	inner      slog.Handler
	allow      map[string]struct{}
	groupAllow map[string]struct{}
	groups     []string
}

// NewLogger constructs a structured *slog.Logger backed by SafeHandler.
func NewLogger(cfg LoggerConfig) *slog.Logger {
	w := cfg.Writer
	if w == nil {
		w = os.Stdout
	}
	lvl := cfg.Level
	if lvl == nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}

	var inner slog.Handler
	switch cfg.Format {
	case LogFormatText:
		inner = slog.NewTextHandler(w, opts)
	default:
		inner = slog.NewJSONHandler(w, opts)
	}

	h := NewSafeHandler(inner, cfg.ExtraAllowlist)
	logger := slog.New(h)
	if cfg.Component != "" {
		logger = logger.With("component", cfg.Component)
	}
	return logger
}

// NewSafeHandler wraps inner with strict allowlist/denylist and value sanitization.
func NewSafeHandler(inner slog.Handler, extraAllowlist []string) *SafeHandler {
	allow := make(map[string]struct{}, len(defaultAllowlist)+len(extraAllowlist))
	for _, k := range defaultAllowlist {
		allow[k] = struct{}{}
	}
	for _, k := range extraAllowlist {
		norm := normalizeKey(k)
		if norm == "" {
			continue
		}
		if _, denied := explicitDenylist[norm]; denied {
			continue
		}
		allow[norm] = struct{}{}
	}
	groupAllow := make(map[string]struct{}, len(defaultAllowedGroups))
	for _, g := range defaultAllowedGroups {
		groupAllow[g] = struct{}{}
	}
	return &SafeHandler{
		inner:      inner,
		allow:      allow,
		groupAllow: groupAllow,
	}
}

func (h *SafeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *SafeHandler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, sanitizeString(r.Message), r.PC)

	// If any active WithGroup scope is disallowed, omit all record attributes in that scope.
	if !h.allActiveGroupsAllowed() {
		return h.inner.Handle(ctx, clean)
	}

	r.Attrs(func(a slog.Attr) bool {
		if sanitized, ok := h.sanitizeAttr(a); ok {
			clean.AddAttrs(sanitized)
		}
		return true
	})

	return h.inner.Handle(ctx, clean)
}

func (h *SafeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if !h.allActiveGroupsAllowed() {
		return &SafeHandler{
			inner:      h.inner,
			allow:      h.allow,
			groupAllow: h.groupAllow,
			groups:     append([]string(nil), h.groups...),
		}
	}
	filtered := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if sanitized, ok := h.sanitizeAttr(a); ok {
			filtered = append(filtered, sanitized)
		}
	}
	nextInner := h.inner
	if len(filtered) > 0 {
		nextInner = h.inner.WithAttrs(filtered)
	}
	return &SafeHandler{
		inner:      nextInner,
		allow:      h.allow,
		groupAllow: h.groupAllow,
		groups:     append([]string(nil), h.groups...),
	}
}

func (h *SafeHandler) WithGroup(name string) slog.Handler {
	groups := make([]string, len(h.groups)+1)
	copy(groups, h.groups)
	groups[len(h.groups)] = name

	nextInner := h.inner
	if h.isGroupAllowed(name) && h.allActiveGroupsAllowed() {
		nextInner = h.inner.WithGroup(name)
	}
	return &SafeHandler{
		inner:      nextInner,
		allow:      h.allow,
		groupAllow: h.groupAllow,
		groups:     groups,
	}
}

func (h *SafeHandler) allActiveGroupsAllowed() bool {
	for _, g := range h.groups {
		if !h.isGroupAllowed(g) {
			return false
		}
	}
	return true
}

func (h *SafeHandler) isGroupAllowed(name string) bool {
	norm := normalizeKey(name)
	if _, denied := explicitDenylist[norm]; denied {
		return false
	}
	_, ok := h.groupAllow[norm]
	return ok
}

func (h *SafeHandler) isKeyAllowed(key string) bool {
	norm := normalizeKey(key)
	if _, denied := explicitDenylist[norm]; denied {
		return false
	}
	_, ok := h.allow[norm]
	return ok
}

func (h *SafeHandler) sanitizeAttr(a slog.Attr) (slog.Attr, bool) {
	a.Value = a.Value.Resolve()
	if a.Key == "" {
		return slog.Attr{}, false
	}

	if a.Value.Kind() == slog.KindGroup {
		if !h.isGroupAllowed(a.Key) {
			return slog.Attr{}, false
		}
		children := a.Value.Group()
		filtered := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			if sc, ok := h.sanitizeAttr(child); ok {
				filtered = append(filtered, sc)
			}
		}
		if len(filtered) == 0 {
			return slog.Attr{}, false
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(filtered...)}, true
	}

	if !h.isKeyAllowed(a.Key) {
		return slog.Attr{}, false
	}

	return slog.Attr{Key: a.Key, Value: sanitizeValue(a.Value)}, true
}

func sanitizeValue(v slog.Value) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(sanitizeString(v.String()))
	case slog.KindAny:
		if v.Any() == nil {
			return v
		}
		return slog.StringValue(sanitizeString(fmt.Sprint(v.Any())))
	default:
		return v
	}
}

func sanitizeString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > maxLogStringLen || strings.ContainsAny(s, "\r\n") {
		return redactedPlaceholder
	}
	for _, pat := range secretValuePatterns {
		if pat.MatchString(s) {
			return redactedPlaceholder
		}
	}
	return s
}

func normalizeKey(k string) string {
	return strings.ToLower(strings.TrimSpace(k))
}

// LoggerWithTrace returns a child logger carrying allowlisted trace_id and span_id if ctx holds a valid span context.
func LoggerWithTrace(ctx context.Context, l *slog.Logger) *slog.Logger {
	if l == nil {
		return nil
	}
	if ctx == nil {
		return l
	}
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return l
	}
	return l.With(
		"trace_id", sc.TraceID().String(),
		"span_id", sc.SpanID().String(),
	)
}
