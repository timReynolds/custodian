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

func TestSafeHandler_PushGatewayAllowlistDenylistAndPatterns(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LoggerConfig{
		Writer:         &buf,
		Format:         LogFormatJSON,
		Component:      "custodian-git-gateway",
		ExtraAllowlist: []string{"raw_bundle", "packfile", "oidc_token", "oauth_token", "pat", "ssh_cert", "ssh_private_key", "commit_message"},
	})

	logger.Info("push session evaluated",
		"push_session_id", "ps_123",
		"push_manifest_digest", strings.Repeat("a", 64),
		"transport", "SSH",
		"egress_mode", "ENFORCE_BLOCK",
		"has_lfs", true,
		"ssh_cert_serial", "42",
		"raw_bundle", "PACK...",
		"packfile", "raw-pack-bytes",
		"oidc_token", "oidc-secret-val",
		"oauth_token", "oauth-secret-val",
		"pat", "pat-secret-val",
		"ssh_cert", "ssh-cert-blob",
		"ssh_private_key", "private-key-material",
		"commit_message", "secret commit msg",
		slog.Group("push",
			slog.String("push_session_id", "ps_123"),
			slog.String("raw_pack", "pack-leak"),
		),
	)

	out := buf.String()
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON log output: %v\nraw: %s", err, out)
	}
	for _, k := range []string{"push_session_id", "push_manifest_digest", "transport", "egress_mode", "has_lfs", "ssh_cert_serial", "push"} {
		if _, ok := parsed[k]; !ok {
			t.Fatalf("expected allowlisted push key %q in output: %s", k, out)
		}
	}
	for _, forbiddenKey := range []string{"raw_bundle", "packfile", "oidc_token", "oauth_token", "pat", "ssh_cert", "ssh_private_key", "commit_message"} {
		if _, ok := parsed[forbiddenKey]; ok {
			t.Fatalf("denylisted key %q leaked into log output: %s", forbiddenKey, out)
		}
	}
	for _, forbiddenVal := range []string{"PACK...", "raw-pack-bytes", "oidc-secret-val", "oauth-secret-val", "pat-secret-val", "ssh-cert-blob", "private-key-material", "secret commit msg", "pack-leak"} {
		if strings.Contains(out, forbiddenVal) {
			t.Fatalf("denylisted value %q leaked into log output: %s", forbiddenVal, out)
		}
	}

	secretPayloads := []struct {
		name    string
		payload string
		secret  string
	}{
		{"x_access_token", "remote failed for x-access-token:ghs_supersecret12345", "ghs_supersecret12345"},
		{"x_access_token_mixed_case", "auth failed: X-Access-Token:custom_broker_tok_9988", "custom_broker_tok_9988"},
		{"oauth2_prefix", "oauth2:my_oauth_secret_token_99", "my_oauth_secret_token_99"},
		{"access_token_kv", "redirect access_token=tok_secret_value_123&state=ok", "tok_secret_value_123"},
		{"proxy_authorization", "Proxy-Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		{"ssh_ed25519_key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyMaterialBlob12345", "AAAAC3NzaC1lZDI1NTE5"},
		{"ssh_cert_blob", "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t", "AAAAIHNzaC1lZDI1NTE5"},
		{"ssh_dss_cert_blob", "ssh-dss-cert-v01@openssh.com AAAAB3NzaC1kc3NjZXJ0LXYwMUBvcGVuc3NoLmNvbQ==", "AAAAB3NzaC1kc3NjZXJ0"},
		{"ssh_dss_cert_short", "ssh-dss-cert-v01@openssh.com AAAA1234", "AAAA1234"},
		{"ecdsa_cert_blob", "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20=", "AAAAE2VjZHNh"},
		{"sk_ed25519_key", "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t", "AAAAGnNrLXNzaC1lZDI1NTE5"},
		{"sk_ecdsa_key", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20=", "AAAAInNrLWVjZHNh"},
		{"sk_ed25519_cert_short", "sk-ssh-ed25519-cert-v01@openssh.com AAAA1234", "AAAA1234"},
		{"sk_ecdsa_cert_short", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA1234", "AAAA1234"},
	}

	for _, tc := range secretPayloads {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			logger.Error(tc.payload, "reason", tc.payload)
			s := buf.String()
			if strings.Contains(s, tc.secret) {
				t.Fatalf("%s leaked secret %q in %s", tc.name, tc.secret, s)
			}
			var row map[string]any
			if err := json.Unmarshal(buf.Bytes(), &row); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if row["msg"] != "[REDACTED]" || row["reason"] != "[REDACTED]" {
				t.Fatalf("%s expected [REDACTED], got msg=%v reason=%v", tc.name, row["msg"], row["reason"])
			}
		})
	}

	t.Run("denylist_normalized_bypass_attempts", func(t *testing.T) {
		var bypassBuf bytes.Buffer
		bypassLogger := NewLogger(LoggerConfig{
			Writer:    &bypassBuf,
			Format:    LogFormatJSON,
			Component: "custodian-git-gateway",
			ExtraAllowlist: []string{
				"rawBundle", "raw-bundle", "raw bundle",
				"oidcToken", "brokerToken", "sshPrivateKey",
				"xAccessToken", "privateKey", "clientSecret", "commitMessage",
			},
		})
		bypassLogger.Info("bypass check",
			"push_session_id", "ps_ok",
			"rawBundle", "leak-raw-bundle",
			"raw-bundle", "leak-raw-dash",
			"raw bundle", "leak-raw-space",
			"oidcToken", "leak-oidc",
			"brokerToken", "leak-broker",
			"sshPrivateKey", "leak-ssh-priv",
			"xAccessToken", "leak-x-access",
			"privateKey", "leak-priv-key",
			"clientSecret", "leak-client-sec",
			"commitMessage", "leak-commit-msg",
			"raw_bundle", "leak-snake-bundle",
			"oidc_token", "leak-snake-oidc",
			slog.Group("sshPrivateKey", slog.String("workspace_id", "ws_grouped_drop")),
		)
		s := bypassBuf.String()
		var parsed map[string]any
		if err := json.Unmarshal(bypassBuf.Bytes(), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v\nraw: %s", err, s)
		}
		if parsed["push_session_id"] != "ps_ok" {
			t.Fatalf("expected push_session_id=ps_ok, got %v", parsed["push_session_id"])
		}
		for _, k := range []string{
			"rawBundle", "raw-bundle", "raw bundle", "oidcToken", "brokerToken",
			"sshPrivateKey", "xAccessToken", "privateKey", "clientSecret", "commitMessage",
			"raw_bundle", "oidc_token",
		} {
			if _, ok := parsed[k]; ok {
				t.Fatalf("normalized denylist key %q leaked into log output: %s", k, s)
			}
		}
		for _, val := range []string{
			"leak-raw-bundle", "leak-raw-dash", "leak-raw-space", "leak-oidc", "leak-broker",
			"leak-ssh-priv", "leak-x-access", "leak-priv-key", "leak-client-sec", "leak-commit-msg",
			"leak-snake-bundle", "leak-snake-oidc", "ws_grouped_drop",
		} {
			if strings.Contains(s, val) {
				t.Fatalf("normalized denylist value %q leaked into log output: %s", val, s)
			}
		}

		bypassBuf.Reset()
		bypassLogger.WithGroup("sshPrivateKey").Info("msg", "workspace_id", "ws_1")
		if strings.Contains(bypassBuf.String(), "ws_1") || strings.Contains(bypassBuf.String(), "workspace_id") {
			t.Fatalf("WithGroup denylisted camelCase group leaked child attr: %s", bypassBuf.String())
		}
	})

	t.Run("non_redaction_preservation", func(t *testing.T) {
		safeMsgs := []string{
			"ssh://git@github.com/org/repo.git",
			"https://github.com/org/repo.git",
			"ssh-ed25519 authentication failed",
		}
		for _, msg := range safeMsgs {
			buf.Reset()
			logger.Info(msg, "reason", msg)
			s := buf.String()
			if strings.Contains(s, "[REDACTED]") {
				t.Fatalf("safe payload %q was falsely redacted: %s", msg, s)
			}
			if !strings.Contains(s, msg) {
				t.Fatalf("safe payload %q missing from output: %s", msg, s)
			}
		}
	})
}
