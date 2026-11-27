package quarantine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
)

const (
	maxGitStderrCaptureBytes = 64 * 1024

	indexPackStrictFlag = "--strict=" +
		"hasDot=error," +
		"hasDotdot=error," +
		"hasDotgit=error," +
		"emptyName=error," +
		"fullPathname=error," +
		"largePathname=error," +
		"nulInCommit=error," +
		"nullSha1=error," +
		"zeroPaddedFilemode=error," +
		"gitmodulesSymlink=error," +
		"gitmodulesParse=error," +
		"gitattributesSymlink=error," +
		"gitignoreSymlink=error," +
		"mailmapSymlink=error"
)

var disallowedExactRefs = map[string]struct{}{
	"HEAD":        {},
	"FETCH_HEAD":  {},
	"ORIG_HEAD":   {},
	"MERGE_HEAD":  {},
	"CHERRY_PICK": {},
}

var disallowedRefPrefixes = []string{
	"refs/replace/",
	"refs/notes/",
	"refs/pull/",
	"refs/original/",
	"refs/remotes/",
	"refs/stash",
	"refs/bisect/",
}

func hardenedGitFlags() []string {
	base := checkout.HardenedGitFlags(false)
	out := make([]string, 0, len(base)+14)
	out = append(out, base...)
	out = append(out,
		"-c", "transfer.fsckObjects=true",
		"-c", "receive.fsckObjects=true",
		"-c", "commit.gpgsign=false",
		"-c", "gc.auto=0",
		"-c", "maintenance.auto=false",
		"-c", "core.precomposeUnicode=false",
		"-c", "core.quotePath=false",
	)
	return out
}

func cleanGitEnv(homeDir string) []string {
	base := checkout.CleanGitEnv(homeDir, false, false, "", "")
	out := make([]string, 0, len(base)+3)
	for _, entry := range base {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if k == "GIT_ALLOW_PROTOCOL" || k == "XDG_CONFIG_HOME" || k == "LC_ALL" {
			continue
		}
		out = append(out, entry)
	}
	out = append(out,
		"GIT_ALLOW_PROTOCOL=none",
		"XDG_CONFIG_HOME="+filepath.Join(homeDir, "xdg"),
		"LC_ALL=C",
	)
	return out
}

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	rem := b.limit - b.buf.Len()
	if rem > 0 {
		if len(p) <= rem {
			_, _ = b.buf.Write(p)
		} else {
			_, _ = b.buf.Write(p[:rem])
			b.truncated = true
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}

func runHardenedGit(ctx context.Context, gitBin, homeDir, repoDir string, stdin io.Reader, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, domain.WrapError(domain.ErrUnavailable, "QUARANTINE_ABORTED", "quarantine git operation aborted", err)
	}
	cmdArgs := hardenedGitFlags()
	if repoDir != "" {
		cmdArgs = append(cmdArgs, "-C", repoDir)
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.CommandContext(ctx, gitBin, cmdArgs...)
	cmd.Env = cleanGitEnv(homeDir)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout bytes.Buffer
	stderr := &cappedBuffer{limit: maxGitStderrCaptureBytes}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, domain.WrapError(domain.ErrUnavailable, "QUARANTINE_TIMEOUT", "git command timed out or cancelled", ctxErr)
		}
		sanitized := checkout.SanitizeGitOutput(stderr.String())
		if sanitized == "" {
			sanitized = checkout.SanitizeGitOutput(err.Error())
		}
		return stdout.Bytes(), fmt.Errorf("git failed (%s): %w", sanitized, err)
	}
	return stdout.Bytes(), nil
}

func startHardenedGitPipe(ctx context.Context, gitBin, homeDir, repoDir string, stdin io.Reader, args ...string) (*exec.Cmd, io.ReadCloser, *cappedBuffer, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, domain.WrapError(domain.ErrUnavailable, "QUARANTINE_ABORTED", "quarantine git operation aborted", err)
	}
	cmdArgs := hardenedGitFlags()
	if repoDir != "" {
		cmdArgs = append(cmdArgs, "-C", repoDir)
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.CommandContext(ctx, gitBin, cmdArgs...)
	cmd.Env = cleanGitEnv(homeDir)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("git stdout pipe: %w", err)
	}
	stderr := &cappedBuffer{limit: maxGitStderrCaptureBytes}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("git start: %w", err)
	}
	return cmd, stdout, stderr, nil
}

func validateRefSyntax(ref string) error {
	if ref == "" || strings.TrimSpace(ref) != ref {
		return domain.Unprocessable("INVALID_REF_NAME", "git ref must not be empty or have surrounding whitespace")
	}
	if strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return domain.Unprocessable("INVALID_REF_NAME", "git ref has invalid leading or trailing character")
	}
	if strings.HasSuffix(ref, ".lock") || strings.HasSuffix(ref, ".") {
		return domain.Unprocessable("INVALID_REF_NAME", "git ref has invalid suffix")
	}
	if strings.ContainsAny(ref, " \t\r\n\x00?*~^:\\") || strings.Contains(ref, "[") {
		return domain.Unprocessable("INVALID_REF_NAME", "git ref contains disallowed characters")
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") {
		return domain.Unprocessable("INVALID_REF_NAME", "git ref contains disallowed sequence")
	}
	for _, seg := range strings.Split(ref, "/") {
		if seg == "" {
			return domain.Unprocessable("INVALID_REF_NAME", "git ref must not contain empty path segments")
		}
		if strings.HasPrefix(seg, ".") {
			return domain.Unprocessable("INVALID_REF_NAME", "git ref segment must not start with '.'")
		}
		if strings.HasPrefix(seg, "-") {
			return domain.Unprocessable("INVALID_REF_NAME", "git ref segment must not start with '-'")
		}
		if strings.HasSuffix(seg, ".lock") {
			return domain.Unprocessable("INVALID_REF_NAME", "git ref segment must not end with '.lock'")
		}
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return domain.Unprocessable("INVALID_REF_NAME", "git ref contains control characters")
		}
	}
	return nil
}

func validateAllowedRefNamespace(ref string, allowedPrefixes []string) error {
	upper := strings.ToUpper(ref)
	if _, forbidden := disallowedExactRefs[upper]; forbidden {
		return domain.Unprocessable("DISALLOWED_REF_NAMESPACE", fmt.Sprintf("ref %q is not permitted", ref))
	}
	for _, dis := range disallowedRefPrefixes {
		if strings.HasPrefix(ref, dis) || ref == strings.TrimSuffix(dis, "/") {
			return domain.Unprocessable("DISALLOWED_REF_NAMESPACE", fmt.Sprintf("ref namespace %q is not permitted", ref))
		}
	}
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(ref, prefix) && len(ref) > len(prefix) {
			return nil
		}
	}
	return domain.Unprocessable("DISALLOWED_REF_NAMESPACE", fmt.Sprintf("ref %q is outside allowed namespaces", ref))
}

func stripIgnorableAndTrailing(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimRight(b.String(), ". ")
}

func (u *QuarantineUnpacker) recordRejection(reason string, sessionID uuid.UUID, errCode string) {
	if u.metrics != nil {
		u.metrics.IncPushQuarantineRejection(reason)
	}
	if u.logger != nil {
		u.logger.Warn("quarantine rejected push",
			slog.String("component", "quarantine"),
			slog.String("push_session_id", sessionID.String()),
			slog.String("reason", reason),
			slog.String("error_code", errCode),
		)
	}
}

func errorCodeOf(err error) string {
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		return domErr.Code()
	}
	return "INTERNAL_ERROR"
}
