package checkout

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

const minimalSafeGitConfig = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tsymlinks = false\n"

// ValidateRemoteURL enforces safe transport schemes and rejects flag injection,
// embedded credentials, and disallowed protocols.
func ValidateRemoteURL(raw string, allowLocalBare, allowInsecureHTTP bool) (string, error) {
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

// PrepareWorkDir validates an empty target directory or allocates an isolated 0700 temp dir.
func PrepareWorkDir(workDir string) (dir string, created bool, err error) {
	trimmed := strings.TrimSpace(workDir)
	if trimmed == "" {
		tmp, err := os.MkdirTemp("", "custodian-checkout-*")
		if err != nil {
			return "", false, domain.WrapError(domain.ErrInternal, "CHECKOUT_DIR_FAILED", "failed to create checkout directory", err)
		}
		if err := os.Chmod(tmp, 0o700); err != nil {
			_ = os.RemoveAll(tmp)
			return "", false, domain.WrapError(domain.ErrInternal, "CHECKOUT_DIR_FAILED", "failed to secure checkout directory", err)
		}
		return tmp, true, nil
	}

	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return "", false, domain.WrapError(domain.ErrBadRequest, "INVALID_WORK_DIR", "invalid work directory path", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if mkErr := os.MkdirAll(abs, 0o700); mkErr != nil {
				return "", false, domain.WrapError(domain.ErrInternal, "CHECKOUT_DIR_FAILED", "failed to create work directory", mkErr)
			}
			return abs, true, nil
		}
		return "", false, domain.WrapError(domain.ErrBadRequest, "INVALID_WORK_DIR", "failed to stat work directory", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", false, domain.BadRequest("INVALID_WORK_DIR", "work directory must be a non-symlink directory")
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return "", false, domain.WrapError(domain.ErrBadRequest, "INVALID_WORK_DIR", "failed to inspect work directory", err)
	}
	if len(entries) > 0 {
		return "", false, domain.Conflict("WORK_DIR_NOT_EMPTY", "checkout work directory must be empty")
	}
	return abs, false, nil
}

// SanitizeGitMetadata removes hooks, reflogs, remote refs/URLs, FETCH_HEAD/ORIG_HEAD,
// modules, lfs, and rewrites .git/config to a minimal safe core-only block.
func SanitizeGitMetadata(gitDir string) error {
	stripPaths := []string{
		"hooks",
		"logs",
		filepath.Join("refs", "remotes"),
		"FETCH_HEAD",
		"ORIG_HEAD",
		"COMMIT_EDITMSG",
		"MERGE_HEAD",
		"MERGE_MSG",
		"MERGE_MODE",
		"CHERRY_PICK_HEAD",
		"REBASE_HEAD",
		"rebase-merge",
		"rebase-apply",
		"lfs",
		"modules",
		"remotes",
		"branches",
		"description",
	}
	for _, rel := range stripPaths {
		if err := os.RemoveAll(filepath.Join(gitDir, rel)); err != nil {
			return domain.WrapError(domain.ErrInternal, "GIT_SANITIZE_FAILED", "failed stripping unsafe git metadata", err)
		}
	}

	cfgPath := filepath.Join(gitDir, "config")
	if err := os.WriteFile(cfgPath, []byte(minimalSafeGitConfig), 0o644); err != nil {
		return domain.WrapError(domain.ErrInternal, "GIT_SANITIZE_FAILED", "failed rewriting sanitized git config", err)
	}
	return nil
}
