package write

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	gogithub "github.com/google/go-github/v75/github"

	"github.com/timreynolds/custodian/internal/domain"
)

// ValidateRefName enforces strict Git ref/SHA input hygiene to prevent flag injection or traversal.
func ValidateRefName(ref string) error {
	if ref == "" || strings.TrimSpace(ref) != ref {
		return domain.BadRequest("INVALID_REF_NAME", "git ref must not be empty or have surrounding whitespace")
	}
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return domain.BadRequest("INVALID_REF_NAME", "git ref has invalid leading or trailing character")
	}
	if strings.HasSuffix(ref, ".lock") || strings.HasSuffix(ref, ".") {
		return domain.BadRequest("INVALID_REF_NAME", "git ref has invalid suffix")
	}
	if strings.ContainsAny(ref, " \t\r\n\x00?*~^:\\") || strings.Contains(ref, "[") {
		return domain.BadRequest("INVALID_REF_NAME", "git ref contains disallowed characters")
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") {
		return domain.BadRequest("INVALID_REF_NAME", "git ref contains disallowed sequence")
	}
	for _, seg := range strings.Split(ref, "/") {
		if seg == "" {
			return domain.BadRequest("INVALID_REF_NAME", "git ref must not contain empty path segments")
		}
		if strings.HasPrefix(seg, ".") {
			return domain.BadRequest("INVALID_REF_NAME", "git ref segment must not start with '.'")
		}
		if strings.HasSuffix(seg, ".lock") {
			return domain.BadRequest("INVALID_REF_NAME", "git ref segment must not end with '.lock'")
		}
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return domain.BadRequest("INVALID_REF_NAME", "git ref contains control characters")
		}
	}
	return nil
}

func mapGitHubError(err error, resp *gogithub.Response, defaultMsg string) error {
	if err == nil {
		return nil
	}
	var rateErr *gogithub.RateLimitError
	if errors.As(err, &rateErr) {
		return domain.WrapError(domain.ErrRateLimited, "GITHUB_RATE_LIMITED", "GitHub API rate limit exceeded", err)
	}
	var abuseErr *gogithub.AbuseRateLimitError
	if errors.As(err, &abuseErr) {
		return domain.WrapError(domain.ErrRateLimited, "GITHUB_RATE_LIMITED", "GitHub API secondary rate limit exceeded", err)
	}

	status := 0
	var ghErr *gogithub.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		status = ghErr.Response.StatusCode
	} else if resp != nil && resp.Response != nil {
		status = resp.StatusCode
	}

	if status != 0 {
		switch status {
		case http.StatusNotFound:
			return domain.WrapError(domain.ErrNotFound, "GITHUB_NOT_FOUND", defaultMsg, err)
		case http.StatusUnauthorized:
			return domain.WrapError(domain.ErrForbidden, "GITHUB_AUTH_FAILED", "GitHub App authentication failed", err)
		case http.StatusForbidden:
			if resp != nil && resp.Response != nil && resp.Header.Get("X-RateLimit-Remaining") == "0" {
				return domain.WrapError(domain.ErrRateLimited, "GITHUB_RATE_LIMITED", "GitHub API rate limit exceeded", err)
			}
			return domain.WrapError(domain.ErrForbidden, "GITHUB_FORBIDDEN", "GitHub access denied", err)
		case http.StatusUnprocessableEntity:
			return domain.WrapError(domain.ErrUnprocessable, "GITHUB_UNPROCESSABLE", defaultMsg, err)
		case http.StatusTooManyRequests:
			return domain.WrapError(domain.ErrRateLimited, "GITHUB_RATE_LIMITED", "GitHub API rate limit exceeded", err)
		case http.StatusBadRequest:
			return domain.WrapError(domain.ErrBadRequest, "GITHUB_BAD_REQUEST", defaultMsg, err)
		default:
			if status >= 500 {
				return domain.WrapError(domain.ErrUnavailable, "GITHUB_UNAVAILABLE", "GitHub API temporarily unavailable", err)
			}
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return domain.WrapError(domain.ErrUnavailable, "GITHUB_UNAVAILABLE", "GitHub API unreachable", err)
	}
	return domain.WrapError(domain.ErrUnavailable, "GITHUB_UNAVAILABLE", defaultMsg, err)
}
