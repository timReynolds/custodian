package checkout

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const defaultCheckoutTimeout = 2 * time.Minute

// RunnerConfig configures hardened native git checkout execution.
type RunnerConfig struct {
	GitBinary string
	Timeout   time.Duration
	Logger    *slog.Logger
}

// Request describes a pinned commit checkout operation.
type Request struct {
	RemoteURL          string
	CommitSHA          string
	WorkDir            string
	IncludeGitMetadata bool
	IncludeHistory     bool
	Token              string
	AllowLocalBare     bool
	AllowInsecureHTTP  bool
}

// Runner executes ephemeral hardened git init + fetch + checkout sequences.
type Runner struct {
	gitBin  string
	timeout time.Duration
	logger  *slog.Logger
}

// NewRunner constructs a Runner with secure defaults.
func NewRunner(cfg RunnerConfig) *Runner {
	bin := strings.TrimSpace(cfg.GitBinary)
	if bin == "" {
		bin = "git"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultCheckoutTimeout
	}
	return &Runner{
		gitBin:  bin,
		timeout: timeout,
		logger:  cfg.Logger,
	}
}

// Checkout performs a hardened pinned-SHA checkout into an isolated working directory.
func (r *Runner) Checkout(ctx context.Context, req Request) (domain.CheckoutResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sha, err := domain.ParseGitSHA(req.CommitSHA)
	if err != nil {
		return domain.CheckoutResult{}, err
	}
	remoteURL, err := ValidateRemoteURL(req.RemoteURL, req.AllowLocalBare, req.AllowInsecureHTTP)
	if err != nil {
		return domain.CheckoutResult{}, err
	}

	workDir, createdWorkDir, err := PrepareWorkDir(req.WorkDir)
	if err != nil {
		return domain.CheckoutResult{}, err
	}
	cleanupOnErr := true
	defer func() {
		if cleanupOnErr && createdWorkDir {
			_ = os.RemoveAll(workDir)
		}
	}()

	homeDir, err := os.MkdirTemp("", "custodian-githome-*")
	if err != nil {
		return domain.CheckoutResult{}, domain.WrapError(domain.ErrInternal, "CHECKOUT_ENV_FAILED", "failed creating isolated git home", err)
	}
	_ = os.Chmod(homeDir, 0o700)
	defer os.RemoveAll(homeDir)

	var askpassPath, tokenFilePath string
	if req.Token != "" {
		var askCleanup func()
		askpassPath, tokenFilePath, askCleanup, err = PrepareAskpass(req.Token)
		if err != nil {
			return domain.CheckoutResult{}, domain.WrapError(domain.ErrInternal, "CHECKOUT_ENV_FAILED", "failed preparing ephemeral git auth", err)
		}
		defer askCleanup()
	}

	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	env := CleanGitEnv(homeDir, req.AllowLocalBare, req.AllowInsecureHTTP, askpassPath, tokenFilePath)
	baseFlags := HardenedGitFlags(req.AllowLocalBare)

	// 1. Initialize clean repository without any remote configured in .git/config.
	if _, err := r.runGit(runCtx, env, req.Token, baseFlags, "init", "--initial-branch=main", "--", workDir); err != nil {
		return domain.CheckoutResult{}, err
	}

	// 2. Fetch exact pinned SHA directly into FETCH_HEAD (never storing remote URL in .git/config).
	fetchArgs := []string{"-C", workDir, "fetch", "--no-tags"}
	if !req.IncludeHistory {
		fetchArgs = append(fetchArgs, "--depth=1")
	}
	fetchArgs = append(fetchArgs, "--", remoteURL, sha)
	if _, err := r.runGit(runCtx, env, req.Token, baseFlags, fetchArgs...); err != nil {
		return domain.CheckoutResult{}, err
	}

	// 3. Detach HEAD at the pinned commit SHA.
	if _, err := r.runGit(runCtx, env, req.Token, baseFlags, "-C", workDir, "checkout", "--detach", sha); err != nil {
		return domain.CheckoutResult{}, err
	}

	// 4. Verify checked-out HEAD matches pinned SHA exactly.
	headOut, err := r.runGit(runCtx, env, req.Token, baseFlags, "-C", workDir, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return domain.CheckoutResult{}, err
	}
	checkedOutSHA := strings.ToLower(strings.TrimSpace(headOut))
	if checkedOutSHA != sha {
		return domain.CheckoutResult{}, domain.Internal("CHECKOUT_SHA_MISMATCH", "checked-out HEAD does not match requested commit SHA")
	}

	// 5. Verify clean working tree.
	statusOut, err := r.runGit(runCtx, env, req.Token, baseFlags, "-C", workDir, "status", "--porcelain")
	if err != nil {
		return domain.CheckoutResult{}, err
	}
	if strings.TrimSpace(statusOut) != "" {
		return domain.CheckoutResult{}, domain.Internal("CHECKOUT_DIRTY_TREE", "checkout produced an unexpected dirty working tree")
	}

	// 6. Enforce single-commit history invariant when IncludeHistory is false.
	if !req.IncludeHistory {
		countOut, err := r.runGit(runCtx, env, req.Token, baseFlags, "-C", workDir, "rev-list", "--count", "HEAD")
		if err != nil {
			return domain.CheckoutResult{}, err
		}
		if strings.TrimSpace(countOut) != "1" {
			return domain.CheckoutResult{}, domain.Internal("CHECKOUT_HISTORY_VIOLATION", "shallow checkout contains unexpected commit history")
		}
	}

	// 7. Strip or sanitize .git directory.
	gitDir := filepath.Join(workDir, ".git")
	if !req.IncludeGitMetadata {
		if err := os.RemoveAll(gitDir); err != nil {
			return domain.CheckoutResult{}, domain.WrapError(domain.ErrInternal, "GIT_CLEANUP_FAILED", "failed removing .git directory", err)
		}
	} else {
		if err := SanitizeGitMetadata(gitDir); err != nil {
			return domain.CheckoutResult{}, err
		}
	}

	cleanupOnErr = false
	if r.logger != nil {
		r.logger.Info("git checkout completed",
			"commit_sha", checkedOutSHA,
			"status", "ok",
		)
	}
	return domain.CheckoutResult{
		CommitSHA:       checkedOutSHA,
		WorkDir:         workDir,
		HasGitMetadata:  req.IncludeGitMetadata,
		IncludesHistory: req.IncludeHistory,
	}, nil
}

func (r *Runner) runGit(ctx context.Context, env []string, secretToken string, baseFlags []string, args ...string) (string, error) {
	allArgs := make([]string, 0, len(baseFlags)+len(args))
	allArgs = append(allArgs, baseFlags...)
	allArgs = append(allArgs, args...)

	cmd := exec.CommandContext(ctx, r.gitBin, allArgs...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		sanitized := SanitizeGitOutput(stderr.String(), secretToken)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", domain.WrapError(domain.ErrUnavailable, "GIT_TIMEOUT", "git checkout timed out", err)
		}
		lower := strings.ToLower(sanitized)
		switch {
		case strings.Contains(lower, "not our ref"),
			strings.Contains(lower, "couldn't find remote ref"),
			strings.Contains(lower, "does not exist"),
			strings.Contains(lower, "not found"),
			strings.Contains(lower, "returned error: 404"):
			return "", domain.NotFound("GIT_REF_NOT_FOUND", "requested git commit or repository not found")
		case strings.Contains(lower, "authentication failed"),
			strings.Contains(lower, "returned error: 401"),
			strings.Contains(lower, "returned error: 403"):
			return "", domain.Forbidden("GIT_AUTH_FAILED", "git authentication failed")
		case strings.Contains(lower, "could not resolve host"),
			strings.Contains(lower, "connection refused"),
			strings.Contains(lower, "failed to connect"),
			strings.Contains(lower, "returned error: 500"),
			strings.Contains(lower, "returned error: 502"),
			strings.Contains(lower, "returned error: 503"):
			return "", domain.Unavailable("GIT_UPSTREAM_UNAVAILABLE", "git remote temporarily unavailable")
		default:
			return "", domain.WrapError(domain.ErrUnprocessable, "GIT_CHECKOUT_FAILED", "git command failed: "+sanitized, err)
		}
	}
	return stdout.String(), nil
}
