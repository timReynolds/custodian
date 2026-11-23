package publish

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

var (
	urlUserInfoPattern      = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+)@`)
	urlStripPattern         = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'"<>]+`)
	repoNotFoundPattern     = regexp.MustCompile(`\brepository\s+(?:(?:'[^']*'|"[^"]*"|\[url\])\s+)?not found\b`)
	httpStatus401403Pattern = regexp.MustCompile(`\b(?:returned error:|http(?:/[0-9.]+)?|status(?:\s+code)?)\s*:?\s*(?:401|403)\b`)
	httpStatus404Pattern    = regexp.MustCompile(`\b(?:returned error:|http(?:/[0-9.]+)?|status(?:\s+code)?)\s*:?\s*404\b`)
	httpStatus5xxPattern    = regexp.MustCompile(`\b(?:returned error:|http(?:/[0-9.]+)?|status(?:\s+code)?)\s*:?\s*50[0234]\b`)
	tokenPatterns           = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`x-access-token:[^\s@'"]+`),
	}
)

// hardenedGitFlags returns mandatory -c flags that disable hooks, symlinks, fsmonitor,
// credential helpers, submodule recursion, and unsafe transport protocols.
func hardenedGitFlags(allowLocalBare bool) []string {
	fileAllow := "never"
	if allowLocalBare {
		fileAllow = "always"
	}
	return []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "core.fsmonitor=false",
		"-c", "core.autocrlf=false",
		"-c", "credential.helper=",
		"-c", "submodule.recurse=false",
		"-c", "fetch.fsckObjects=true",
		"-c", "transfer.fsckObjects=true",
		"-c", "receive.fsckObjects=true",
		"-c", "commit.gpgsign=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=" + fileAllow,
	}
}

// cleanGitEnv constructs a minimal isolated environment for native git invocations,
// stripping all inherited GIT_*, SSH_ASKPASS, LD_*, and DYLD_* variables.
func cleanGitEnv(homeDir string, allowLocalBare, allowInsecureHTTP bool, askpassPath, tokenFilePath string, extraEnv ...string) []string {
	allowedKeys := map[string]struct{}{
		"PATH":          {},
		"TMPDIR":        {},
		"LANG":          {},
		"LC_ALL":        {},
		"SSL_CERT_FILE": {},
		"SSL_CERT_DIR":  {},
	}

	env := make([]string, 0, 16+len(extraEnv))
	for _, entry := range os.Environ() {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, keep := allowedKeys[k]; keep {
			env = append(env, entry)
		}
	}

	allowProtocol := "https"
	if allowLocalBare {
		allowProtocol = "file"
	} else if allowInsecureHTTP {
		allowProtocol = "https:http"
	}

	env = append(env,
		"HOME="+homeDir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL="+allowProtocol,
	)

	if askpassPath != "" && tokenFilePath != "" {
		env = append(env,
			"GIT_ASKPASS="+askpassPath,
			"CUSTODIAN_TOKEN_FILE="+tokenFilePath,
		)
	}
	env = append(env, extraEnv...)
	return env
}

// prepareAskpass creates an isolated 0700 directory with a 0600 token file and 0700 askpass helper script.
func prepareAskpass(token string) (askpassPath, tokenFilePath string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "custodian-pub-askpass-*")
	if err != nil {
		return "", "", nil, fmt.Errorf("create askpass dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", nil, fmt.Errorf("chmod askpass dir: %w", err)
	}
	cleanupFn := func() {
		_ = os.RemoveAll(dir)
	}

	tokenFilePath = filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFilePath, []byte(token+"\n"), 0o600); err != nil {
		cleanupFn()
		return "", "", nil, fmt.Errorf("write askpass token file: %w", err)
	}

	askpassPath = filepath.Join(dir, "askpass.sh")
	script := "#!/bin/sh\ncase \"$1\" in\n  *Username*|*username*) printf '%s\\n' 'x-access-token' ;;\n  *) cat \"$CUSTODIAN_TOKEN_FILE\" ;;\nesac\n"
	if err := os.WriteFile(askpassPath, []byte(script), 0o700); err != nil {
		cleanupFn()
		return "", "", nil, fmt.Errorf("write askpass script: %w", err)
	}
	return askpassPath, tokenFilePath, cleanupFn, nil
}

// validateRemoteURL enforces safe transport schemes and rejects flag injection,
// embedded credentials, and disallowed protocols.
func validateRemoteURL(raw string, allowLocalBare, allowInsecureHTTP bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", domain.BadRequest("INVALID_REMOTE_URL", "remote URL must not be empty")
	}
	if strings.HasPrefix(trimmed, "-") {
		return "", domain.BadRequest("INVALID_REMOTE_URL", "remote URL must not start with '-'")
	}
	if strings.ContainsAny(trimmed, " \t\r\n\x00") {
		return "", domain.BadRequest("INVALID_REMOTE_URL", "remote URL contains whitespace or control characters")
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "ext::") || strings.HasPrefix(lower, "fd::") {
		return "", domain.BadRequest("DISALLOWED_GIT_PROTOCOL", "disallowed git transport helper")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", domain.WrapError(domain.ErrBadRequest, "INVALID_REMOTE_URL", "malformed remote URL", err)
	}
	if u.User != nil {
		return "", domain.BadRequest("INVALID_REMOTE_URL", "remote URL must not embed credentials")
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		if u.Host == "" {
			return "", domain.BadRequest("INVALID_REMOTE_URL", "https remote URL requires a host")
		}
		return trimmed, nil
	case "http":
		if !allowInsecureHTTP {
			return "", domain.BadRequest("DISALLOWED_GIT_PROTOCOL", "insecure http remote URL is not allowed")
		}
		if u.Host == "" {
			return "", domain.BadRequest("INVALID_REMOTE_URL", "http remote URL requires a host")
		}
		return trimmed, nil
	case "file":
		if !allowLocalBare {
			return "", domain.BadRequest("DISALLOWED_GIT_PROTOCOL", "file:// remote URL is not allowed")
		}
		if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
			return "", domain.BadRequest("INVALID_REMOTE_URL", "file:// remote URL must be local")
		}
		if u.Path == "" || strings.Contains(u.Path, "..") {
			return "", domain.BadRequest("INVALID_REMOTE_URL", "file:// remote path is invalid")
		}
		info, statErr := os.Stat(u.Path)
		if statErr != nil || !info.IsDir() {
			return "", domain.NotFound("BARE_REPO_NOT_FOUND", "local bare repository directory not found")
		}
		return trimmed, nil
	default:
		return "", domain.BadRequest("DISALLOWED_GIT_PROTOCOL", "unsupported git remote protocol")
	}
}

// validateRefName enforces strict Git ref/SHA input hygiene to prevent flag injection or traversal.
func validateRefName(ref string) error {
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

// sanitizeGitOutput strips credentials, tokens, and URL userinfo from git stderr/stdout before surfacing errors.
func sanitizeGitOutput(raw string, secrets ...string) string {
	out := redactGitSecrets(raw, secrets...)
	if len(out) > 512 {
		out = out[:512] + "...[truncated]"
	}
	return out
}

func redactGitSecrets(raw string, secrets ...string) string {
	out := strings.TrimSpace(raw)
	for _, s := range secrets {
		if s != "" {
			out = strings.ReplaceAll(out, s, "[REDACTED]")
		}
	}
	out = urlUserInfoPattern.ReplaceAllString(out, "${1}[REDACTED]@")
	for _, pat := range tokenPatterns {
		out = pat.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

func classifyGitError(ctx context.Context, stderr string, err error, secrets ...string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
		return domain.WrapError(domain.ErrUnavailable, "GIT_PUBLISH_TIMEOUT", "git publication command timed out or was cancelled", err)
	}
	sanitized := sanitizeGitOutput(stderr, secrets...)
	// Strip URLs before pattern matching so ports (e.g. :40412) or path segments
	// (e.g. /org401/, /org403/, /org404/) never collide with HTTP status classification.
	classifyLower := strings.ToLower(urlStripPattern.ReplaceAllString(redactGitSecrets(stderr, secrets...), "[url]"))

	switch {
	case strings.Contains(classifyLower, "could not resolve host"),
		strings.Contains(classifyLower, "connection refused"),
		strings.Contains(classifyLower, "couldn't connect to server"),
		strings.Contains(classifyLower, "failed to connect to"),
		strings.Contains(classifyLower, "timed out"),
		strings.Contains(classifyLower, "network is unreachable"),
		strings.Contains(classifyLower, "connection reset by peer"):
		return domain.WrapError(domain.ErrUnavailable, "GIT_UPSTREAM_UNAVAILABLE", "git upstream unavailable: "+sanitized, err)
	case httpStatus5xxPattern.MatchString(classifyLower),
		strings.Contains(classifyLower, "internal server error"),
		strings.Contains(classifyLower, "bad gateway"),
		strings.Contains(classifyLower, "service unavailable"),
		strings.Contains(classifyLower, "gateway timeout"):
		return domain.WrapError(domain.ErrUnavailable, "GIT_UPSTREAM_UNAVAILABLE", "git upstream unavailable: "+sanitized, err)
	case strings.Contains(classifyLower, "failed to lock"),
		strings.Contains(classifyLower, "stale info"),
		strings.Contains(classifyLower, "non-fast-forward"),
		strings.Contains(classifyLower, "rejected"):
		return domain.WrapError(domain.ErrConflict, "GIT_PUSH_CONFLICT", "git push rejected: "+sanitized, err)
	case strings.Contains(classifyLower, "authentication failed"),
		httpStatus401403Pattern.MatchString(classifyLower),
		strings.Contains(classifyLower, "permission denied"),
		strings.Contains(classifyLower, "terminal prompts disabled"):
		return domain.WrapError(domain.ErrForbidden, "GIT_AUTH_FAILED", "git authentication failed: "+sanitized, err)
	case strings.Contains(classifyLower, "couldn't find remote ref"),
		repoNotFoundPattern.MatchString(classifyLower),
		strings.Contains(classifyLower, "does not appear to be a git repository"),
		httpStatus404Pattern.MatchString(classifyLower):
		return domain.WrapError(domain.ErrNotFound, "GIT_REF_NOT_FOUND", "git repository or ref not found: "+sanitized, err)
	default:
		return domain.WrapError(domain.ErrUnprocessable, "GIT_PUBLISH_FAILED", "git command failed: "+sanitized, err)
	}
}
