package workflow

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const maxSafeErrorLen = 512

var (
	errURLUserInfoPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+)@`)
	errKVPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*=\s*(?:'[^']*'|"[^"]*"|\S+)`)
	errTokenPatterns      = []*regexp.Regexp{
		regexp.MustCompile(`(?s)-----BEGIN\s+[A-Z0-9 ]*-----.*?-----END\s+[A-Z0-9 ]*-----`),
		regexp.MustCompile(`(?s)-----BEGIN\s+[A-Z0-9 ]*-----.*$`),
		regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`x-access-token:[^\s@'"]+`),
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	}
)

// IsRetryableError classifies transient infrastructure/outage errors vs terminal errors.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var blocked *ingressBlockedError
	if errors.As(err, &blocked) {
		return false
	}
	if errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrRateLimited) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		switch domErr.Code() {
		case "TX_CONFLICT":
			return true
		}
	}
	return false
}

// SafeErrorCodeMessage returns a sanitized operational error code and message safe for
// persistence in operations.last_error, proposals/audit events, and structured logs.
func SafeErrorCodeMessage(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		code := strings.TrimSpace(domErr.Code())
		if code == "" {
			code = "WORKFLOW_FAILED"
		}
		msg := SanitizeErrorString(domErr.Message)
		if msg == "" {
			msg = code
		}
		return code, msg
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "OPERATION_TIMEOUT", "operation timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "OPERATION_CANCELLED", "operation cancelled"
	}
	if errors.Is(err, domain.ErrUnavailable) {
		return "SERVICE_UNAVAILABLE", "downstream dependency unavailable"
	}
	if errors.Is(err, domain.ErrRateLimited) {
		return "RATE_LIMITED", "downstream dependency rate limited"
	}
	if errors.Is(err, domain.ErrNotFound) {
		return "NOT_FOUND", "required resource not found"
	}
	if errors.Is(err, domain.ErrForbidden) {
		return "FORBIDDEN", "operation forbidden"
	}
	if errors.Is(err, domain.ErrUnauthorized) {
		return "UNAUTHORIZED", "operation unauthorized"
	}
	if errors.Is(err, domain.ErrUnprocessable) {
		return "UNPROCESSABLE", "unprocessable input"
	}
	if errors.Is(err, domain.ErrConflict) {
		return "CONFLICT", "resource state conflict"
	}
	if errors.Is(err, domain.ErrBadRequest) {
		return "BAD_REQUEST", "invalid operation input"
	}
	msg := SanitizeErrorString(err.Error())
	if msg == "" {
		msg = "operation failed"
	}
	return "WORKFLOW_FAILED", msg
}

// SanitizeErrorString strips URL credentials, DSN passwords, auth tokens, and PEM blocks.
func SanitizeErrorString(raw string) string {
	out := strings.TrimSpace(raw)
	out = errURLUserInfoPattern.ReplaceAllString(out, "${1}[REDACTED]@")
	out = errKVPasswordPattern.ReplaceAllString(out, "password=[REDACTED]")
	for _, pat := range errTokenPatterns {
		out = pat.ReplaceAllString(out, "[REDACTED]")
	}
	if len(out) > maxSafeErrorLen {
		out = out[:maxSafeErrorLen] + "...[truncated]"
	}
	return out
}

func formatSafeLastError(err error) string {
	code, msg := SafeErrorCodeMessage(err)
	if msg == "" || msg == code {
		return code
	}
	combined := code + ": " + msg
	if len(combined) > maxSafeErrorLen {
		return combined[:maxSafeErrorLen] + "...[truncated]"
	}
	return combined
}

func detachTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), d)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

func firstNonNilErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
