package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type secretValuer struct {
	val any
}

func (s secretValuer) LogValue() slog.Value {
	return slog.AnyValue(s.val)
}

type groupValuer struct{}

func (groupValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("workspace_id", "ws_safe"),
		slog.String("token", "ghp_secretvaluer12345"),
	)
}

func TestSafeHandler_AllowlistAndDenylist(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Writer:         &buf,
		Format:         LogFormatJSON,
		Component:      "custodian-api",
		ExtraAllowlist: []string{"custom_safe_tag", "token", "secret"}, // denylist cannot be overridden
	})

	logger.Info("workspace created",
		"workspace_id", "ws_123",
		"proposal_id", "prop_456",
		"sha256", strings.Repeat("a", 64),
		"status", "READY",
		"custom_safe_tag", "ok",
		"source", "package main\nfunc secret() {}",
		"diff", "+apiKey := 'abc'",
		"prompt", "ignore previous instructions",
		"token", "ghp_supersecret1234567890",
		"secret", "top-secret-value",
		"password", "hunter2",
		"authorization", "Bearer eyJabc.def.ghi",
		"private_key", "-----BEGIN RSA PRIVATE KEY-----",
		"email", "alice@example.com",
		"arbitrary_key", "should-be-dropped",
	)

	out := buf.String()
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON log output: %v\nraw: %s", err, out)
	}

	// Allowlisted fields present
	for _, k := range []string{"component", "workspace_id", "proposal_id", "sha256", "status", "custom_safe_tag"} {
		if _, ok := parsed[k]; !ok {
			t.Fatalf("expected allowlisted key %q in output: %s", k, out)
		}
	}

	// Disallowed keys & values absent
	for _, forbiddenKey := range []string{"source", "diff", "prompt", "token", "secret", "password", "authorization", "private_key", "email", "arbitrary_key"} {
		if _, ok := parsed[forbiddenKey]; ok {
			t.Fatalf("forbidden key %q leaked into log output: %s", forbiddenKey, out)
		}
	}
	for _, forbiddenVal := range []string{"package main", "ignore previous", "ghp_supersecret", "top-secret-value", "hunter2", "alice@example.com", "should-be-dropped"} {
		if strings.Contains(out, forbiddenVal) {
			t.Fatalf("forbidden value %q leaked into log output: %s", forbiddenVal, out)
		}
	}
}

func TestSafeHandler_GroupsWithAttrsAndLogValuer(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Writer: &buf,
		Format: LogFormatJSON,
	})

	// Allowed group with mixed attrs + disallowed group + LogValuer + WithGroup
	derived := logger.With("operation_id", "op_1", "payload", "raw-payload-leak")
	derived.Info("operation checked",
		slog.Group("workspace",
			slog.String("workspace_id", "ws_1"),
			slog.String("diff", "secret-diff-text"),
			slog.Any("nested_valuer", secretValuer{val: "ghp_valuerleak123456"}),
		),
		slog.Group("secret",
			slog.String("workspace_id", "ws_hidden_in_disallowed_group"),
		),
		slog.Any("operation", groupValuer{}),
		slog.Any("err_code", secretValuer{val: "ghp_allowlistedvaluer12345"}),
		slog.String("reason", "https://user:pass@github.com/org/repo.git"),
	)

	out := buf.String()
	if !strings.Contains(out, `"operation_id":"op_1"`) {
		t.Fatalf("missing operation_id: %s", out)
	}
	if !strings.Contains(out, `"workspace_id":"ws_1"`) {
		t.Fatalf("missing workspace.workspace_id: %s", out)
	}
	if !strings.Contains(out, `"err_code":"[REDACTED]"`) {
		t.Fatalf("expected allowlisted secretValuer to be redacted: %s", out)
	}
	if strings.Contains(out, "raw-payload-leak") || strings.Contains(out, "secret-diff-text") || strings.Contains(out, "ghp_valuerleak") || strings.Contains(out, "ghp_secretvaluer") || strings.Contains(out, "ghp_allowlistedvaluer") || strings.Contains(out, "ws_hidden_in_disallowed_group") || strings.Contains(out, "user:pass@") {
		t.Fatalf("sensitive value leaked in grouped/valuer log: %s", out)
	}
	if !strings.Contains(out, `"reason":"[REDACTED]"`) {
		t.Fatalf("expected URL credentials in allowlisted reason to be redacted: %s", out)
	}

	// Test WithGroup disallowed
	buf.Reset()
	disallowedGrp := logger.WithGroup("payload")
	disallowedGrp.Info("ignored group", "workspace_id", "ws_should_drop")
	if strings.Contains(buf.String(), "ws_should_drop") {
		t.Fatalf("WithGroup(disallowed) leaked attr: %s", buf.String())
	}
}

func TestSafeHandler_ValueRedactionAndTraceCorrelation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{Writer: &buf, Format: LogFormatJSON})

	// Test message and allowlisted field redaction for secrets, multiline, and >256-char payloads
	logger.Info("Bearer ghp_1234567890abcdef",
		"reason", "line1\nline2",
		"branch_ref", strings.Repeat("x", 300),
		"err_code", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123",
	)
	out := buf.String()
	if strings.Contains(out, "ghp_1234567890abcdef") || strings.Contains(out, "line1") || strings.Contains(out, strings.Repeat("x", 50)) || strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("secret/multiline/oversized payload leaked: %s", out)
	}

	// Test LoggerWithTrace with real in-memory OTel span
	ctx := context.Background()
	rt, err := NewTracerProvider(ctx, TracerConfig{Mode: TraceModeInMemory})
	if err != nil {
		t.Fatalf("NewTracerProvider: %v", err)
	}
	defer func() { _ = rt.Shutdown(ctx) }()

	ctx, span := rt.Tracer("test").Start(ctx, "TraceLog")
	defer span.End()

	buf.Reset()
	traced := LoggerWithTrace(ctx, logger)
	traced.Info("correlated", "workspace_id", "ws_99")
	tracedOut := buf.String()
	if !strings.Contains(tracedOut, span.SpanContext().TraceID().String()) || !strings.Contains(tracedOut, span.SpanContext().SpanID().String()) {
		t.Fatalf("LoggerWithTrace missing trace_id/span_id: %s", tracedOut)
	}
}

func TestSafeHandler_RedactsNonHTTPCredentialedURLs(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		secret string
	}{
		{
			name:   "postgres",
			url:    "postgres://custodian:my_pg_secret@db.internal:5432/custodian",
			secret: "my_pg_secret",
		},
		{
			name:   "postgresql",
			url:    "postgresql://custodian:my_pg_secret2@db.internal:5432/custodian",
			secret: "my_pg_secret2",
		},
		{
			name:   "ssh",
			url:    "ssh://user:ssh_secret_val@host/repo",
			secret: "ssh_secret_val",
		},
		{
			name:   "git",
			url:    "git://user:git_token_val@host/repo",
			secret: "git_token_val",
		},
		{
			name:   "amqp",
			url:    "amqp://broker:amqp_secret@mq.internal:5672/",
			secret: "amqp_secret",
		},
		{
			name:   "redis",
			url:    "redis://default:redis_secret@cache.internal:6379/0",
			secret: "redis_secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(LoggerConfig{
				Writer:    &buf,
				Format:    LogFormatJSON,
				Component: "probe",
			})
			logger.Error(tc.url,
				"reason", tc.url,
				"err_code", errors.New("wrapped err: "+tc.url),
				"path", tc.url,
				"branch_ref", tc.url,
			)
			out := buf.String()
			if strings.Contains(out, tc.secret) {
				t.Fatalf("%s secret %q leaked in log output: %s", tc.name, tc.secret, out)
			}
			var parsed map[string]any
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				t.Fatalf("invalid JSON log output: %v\nraw: %s", err, out)
			}
			for _, field := range []string{"msg", "reason", "err_code", "path", "branch_ref"} {
				if got, _ := parsed[field].(string); got != "[REDACTED]" {
					t.Fatalf("%s field %q = %q, want [REDACTED] (raw=%s)", tc.name, field, got, out)
				}
			}
		})
	}
}

func TestSafeHandler_RedactsPasswordOnlyURLsAndAllowsCredentialFreeURLs(t *testing.T) {
	secretCases := []struct {
		name   string
		url    string
		secret string
	}{
		{
			name:   "redis_empty_username",
			url:    "redis://:redis_nopassuser_666@cache.internal:6379/0",
			secret: "redis_nopassuser_666",
		},
		{
			name:   "https_empty_username",
			url:    "https://:https_nopassuser_777@github.com/org/repo.git",
			secret: "https_nopassuser_777",
		},
	}

	for _, tc := range secretCases {
		for _, format := range []LogFormat{LogFormatJSON, LogFormatText} {
			t.Run(tc.name+"/"+string(format), func(t *testing.T) {
				var buf bytes.Buffer
				logger := NewLogger(LoggerConfig{
					Writer:    &buf,
					Format:    format,
					Component: "probe",
				})
				logger.Error(tc.url,
					"reason", tc.url,
					"err_code", errors.New("connect failed: "+tc.url),
					"path", tc.url,
					"branch_ref", tc.url,
					"target_ref", secretValuer{val: tc.url},
				)
				out := buf.String()
				if strings.Contains(out, tc.secret) {
					t.Fatalf("%s (%s) secret %q leaked in log output: %s", tc.name, format, tc.secret, out)
				}
				if format == LogFormatJSON {
					var parsed map[string]any
					if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
						t.Fatalf("invalid JSON log output: %v\nraw: %s", err, out)
					}
					for _, field := range []string{"msg", "reason", "err_code", "path", "branch_ref", "target_ref"} {
						if got, _ := parsed[field].(string); got != "[REDACTED]" {
							t.Fatalf("%s field %q = %q, want [REDACTED] (raw=%s)", tc.name, field, got, out)
						}
					}
				} else {
					for _, field := range []string{"msg=[REDACTED]", "reason=[REDACTED]", "err_code=[REDACTED]", "path=[REDACTED]", "branch_ref=[REDACTED]", "target_ref=[REDACTED]"} {
						if !strings.Contains(out, field) {
							t.Fatalf("%s text log missing %q in %s", tc.name, field, out)
						}
					}
				}
			})
		}
	}

	safeURLs := []struct {
		name string
		url  string
	}{
		{name: "ssh_user_only", url: "ssh://git@github.com/org/repo.git"},
		{name: "https_no_userinfo", url: "https://github.com/org/repo.git"},
	}
	for _, tc := range safeURLs {
		for _, format := range []LogFormat{LogFormatJSON, LogFormatText} {
			t.Run(tc.name+"/"+string(format), func(t *testing.T) {
				var buf bytes.Buffer
				logger := NewLogger(LoggerConfig{
					Writer:    &buf,
					Format:    format,
					Component: "probe",
				})
				logger.Info(tc.url,
					"reason", tc.url,
					"path", tc.url,
					"branch_ref", tc.url,
					"target_ref", tc.url,
				)
				out := buf.String()
				if strings.Contains(out, "[REDACTED]") {
					t.Fatalf("%s (%s) falsely redacted safe URL: %s", tc.name, format, out)
				}
				if !strings.Contains(out, tc.url) {
					t.Fatalf("%s (%s) missing expected safe URL %q: %s", tc.name, format, tc.url, out)
				}
			})
		}
	}
}
