package gitgateway

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/timreynolds/custodian/internal/domain"
)

// CanonicalizeDestination normalizes destination to "<lowercase-host>/<path>"
// without embedded credentials or schemes, matching internal/api/dto_pushes.go
// and domain.PushApprovalRelease.IsUsableFor.
func CanonicalizeDestination(rawDest, fallbackHost string) (canonDest string, host string, err error) {
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

func hasUnsafePathCharsOrTraversal(raw string) bool {
	if raw == "" {
		return true
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return true
		}
	}
	if strings.Contains(raw, "\\") || strings.Contains(raw, "..") || strings.Contains(raw, "//") {
		return true
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return true
	}
	if strings.Contains(raw, "/./") || strings.HasSuffix(raw, "/.") {
		return true
	}
	return false
}

func validateOwnerRepo(ownerRepo string) error {
	if strings.TrimSpace(ownerRepo) != ownerRepo || ownerRepo == "" {
		return domain.BadRequest("INVALID_REPOSITORY_NAME", "repository name must not be empty or padded")
	}
	if strings.HasSuffix(strings.ToLower(ownerRepo), ".git") {
		return domain.BadRequest("INVALID_REPOSITORY_NAME", "repository name must not retain .git suffix")
	}
	owner, repo, err := (domain.Repository{FullName: ownerRepo}).OwnerRepo()
	if err != nil {
		return err
	}
	for _, seg := range []string{owner, repo} {
		if seg == "." || seg == ".." || strings.HasPrefix(seg, ".") || strings.HasSuffix(seg, ".") {
			return domain.BadRequest("INVALID_REPOSITORY_NAME", "invalid repository path segment")
		}
		for _, r := range seg {
			switch {
			case r >= 'a' && r <= 'z',
				r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9',
				r == '-', r == '_', r == '.':
			default:
				return domain.BadRequest("INVALID_REPOSITORY_NAME", "repository name contains disallowed characters")
			}
		}
	}
	return nil
}

// ParseSmartHTTPRepoPath validates rawEscapedPath and decodedPath against path traversal,
// encoded dots, backslashes, NUL/control chars, and extracts ownerRepo ("owner/repo" without ".git")
// along with the route suffix ("/info/refs", "/git-upload-pack", "/git-receive-pack", etc.).
func ParseSmartHTTPRepoPath(rawEscapedPath, decodedPath string) (ownerRepo, suffix string, err error) {
	rawPath := rawEscapedPath
	if qIdx := strings.IndexByte(rawPath, '?'); qIdx >= 0 {
		rawPath = rawPath[:qIdx]
	}
	if rawPath == "" {
		rawPath = decodedPath
	}
	if hasUnsafePathCharsOrTraversal(rawPath) || hasUnsafePathCharsOrTraversal(decodedPath) {
		return "", "", domain.BadRequest("INVALID_REPO_PATH", "invalid or unsafe repository path")
	}
	if !strings.HasPrefix(decodedPath, "/") {
		return "", "", domain.BadRequest("INVALID_REPO_PATH", "repository path must start with '/'")
	}
	if strings.ContainsAny(decodedPath, "?#") || strings.ContainsAny(rawPath, "#") {
		return "", "", domain.BadRequest("INVALID_REPO_PATH", "repository path contains disallowed delimiters")
	}

	idx := strings.Index(decodedPath, ".git/")
	if idx < 0 {
		return "", "", domain.BadRequest("INVALID_REPO_PATH", "repository path must include '.git/'")
	}
	ownerRepo = strings.TrimPrefix(decodedPath[:idx], "/")
	suffix = decodedPath[idx+len(".git"):]
	if err := validateOwnerRepo(ownerRepo); err != nil {
		return "", "", domain.BadRequest("INVALID_REPO_PATH", err.Error())
	}
	if suffix == "" || suffix == "/" {
		return "", "", domain.BadRequest("INVALID_REPO_PATH", "missing git service endpoint")
	}
	return ownerRepo, suffix, nil
}

// ParseSSHRepoPath parses an SSH git-upload-pack / git-receive-pack repository argument,
// stripping optional surrounding quotes, leading '/', and trailing '.git', while rejecting
// traversal, backslashes, encoded dots, or invalid repository names.
func ParseSSHRepoPath(rawArg string) (string, error) {
	trimmed := strings.TrimSpace(rawArg)
	if len(trimmed) >= 2 {
		if (trimmed[0] == '\'' && trimmed[len(trimmed)-1] == '\'') ||
			(trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"') {
			trimmed = trimmed[1 : len(trimmed)-1]
		}
	}
	if trimmed == "" {
		return "", domain.BadRequest("INVALID_REPO_PATH", "repository path is required")
	}
	if strings.ContainsAny(trimmed, "?# \t") || hasUnsafePathCharsOrTraversal(trimmed) {
		return "", domain.BadRequest("INVALID_REPO_PATH", "invalid or unsafe repository path")
	}
	clean := strings.TrimPrefix(trimmed, "/")
	clean = strings.TrimSuffix(clean, ".git")
	if err := validateOwnerRepo(clean); err != nil {
		return "", domain.BadRequest("INVALID_REPO_PATH", err.Error())
	}
	return clean, nil
}

// ValidateLFSOID validates that oid is a strict lowercase 64-character SHA-256 hex digest.
func ValidateLFSOID(oid string) error {
	if len(oid) != 64 {
		return domain.BadRequest("INVALID_LFS_OID", "LFS object oid must be 64 lowercase hex characters")
	}
	for i := 0; i < len(oid); i++ {
		c := oid[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return domain.BadRequest("INVALID_LFS_OID", "LFS object oid must be 64 lowercase hex characters")
		}
	}
	return nil
}

// ValidateRepoInContext validates ownerRepo using domain.Repository rules.
func NormalizeHostFromURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Host))
}
