package github

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
	"github.com/timreynolds/custodian/internal/github/write"
)

// LocalBareOption configures LocalBareGitReader.
type LocalBareOption func(*LocalBareGitReader)

// LocalBareGitReader implements domain.GitReader against local bare Git repositories for offline tests.
type LocalBareGitReader struct {
	mu       sync.RWMutex
	rootDir  string
	byRepoID map[int64]string
	byName   map[string]string
	gitBin   string
	checkout *checkout.Runner
	logger   *slog.Logger
	writer   *write.LocalBareClient
}

var _ domain.GitReader = (*LocalBareGitReader)(nil)

func WithBareRootDir(dir string) LocalBareOption {
	return func(r *LocalBareGitReader) {
		r.rootDir = strings.TrimSpace(dir)
	}
}

func WithCheckoutRunner(runner *checkout.Runner) LocalBareOption {
	return func(r *LocalBareGitReader) {
		r.checkout = runner
	}
}

func WithGitBinary(bin string) LocalBareOption {
	return func(r *LocalBareGitReader) {
		if strings.TrimSpace(bin) != "" {
			r.gitBin = strings.TrimSpace(bin)
		}
	}
}

func WithLogger(logger *slog.Logger) LocalBareOption {
	return func(r *LocalBareGitReader) {
		r.logger = logger
	}
}

// NewLocalBareGitReader constructs a LocalBareGitReader.
func NewLocalBareGitReader(opts ...LocalBareOption) *LocalBareGitReader {
	r := &LocalBareGitReader{
		byRepoID: make(map[int64]string),
		byName:   make(map[string]string),
		gitBin:   "git",
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	if r.checkout == nil {
		r.checkout = checkout.NewRunner(checkout.RunnerConfig{
			GitBinary: r.gitBin,
			Logger:    r.logger,
		})
	}
	r.writer = write.NewLocalBareClient(
		write.WithBareRootDir(r.rootDir),
		write.WithGitBinary(r.gitBin),
		write.WithLogger(r.logger),
	)
	return r
}

func validateRepoSegment(seg string) error {
	if seg == "" || seg == "." || seg == ".." {
		return domain.BadRequest("INVALID_REPOSITORY_NAME", "repository owner and name must not be empty or traversal segments")
	}
	if strings.HasPrefix(seg, "-") {
		return domain.BadRequest("INVALID_REPOSITORY_NAME", "repository owner and name must not start with '-'")
	}
	for _, r := range seg {
		if r == '/' || r == '\\' || r == '\x00' || unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return domain.BadRequest("INVALID_REPOSITORY_NAME", "repository owner and name contain illegal characters")
		}
	}
	return nil
}

// RegisterRepo maps a GitHubRepositoryID and/or owner/repo FullName to a local bare repo path.
func (r *LocalBareGitReader) RegisterRepo(repoID int64, fullName, barePath string) error {
	var normalizedName string
	if trimmed := strings.TrimSpace(fullName); trimmed != "" {
		owner, name, err := (domain.Repository{FullName: trimmed}).OwnerRepo()
		if err != nil {
			return err
		}
		if err := validateRepoSegment(owner); err != nil {
			return err
		}
		if err := validateRepoSegment(name); err != nil {
			return err
		}
		normalizedName = strings.ToLower(owner + "/" + name)
	}

	abs, err := filepath.Abs(strings.TrimSpace(barePath))
	if err != nil {
		return domain.WrapError(domain.ErrBadRequest, "INVALID_BARE_PATH", "invalid bare repository path", err)
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return domain.NotFound("BARE_REPO_NOT_FOUND", "bare repository directory does not exist")
	}

	r.mu.Lock()
	if repoID > 0 {
		r.byRepoID[repoID] = abs
	}
	if normalizedName != "" {
		r.byName[normalizedName] = abs
	}
	w := r.writer
	r.mu.Unlock()
	if w != nil {
		return w.RegisterRepo(repoID, fullName, abs)
	}
	return nil
}

func (r *LocalBareGitReader) resolveBarePath(repo domain.Repository) (string, error) {
	owner, name, err := repo.OwnerRepo()
	if err != nil {
		return "", err
	}
	if err := validateRepoSegment(owner); err != nil {
		return "", err
	}
	if err := validateRepoSegment(name); err != nil {
		return "", err
	}

	r.mu.RLock()
	if repo.GitHubRepositoryID > 0 {
		if p, ok := r.byRepoID[repo.GitHubRepositoryID]; ok {
			r.mu.RUnlock()
			return p, nil
		}
	}
	if p, ok := r.byName[strings.ToLower(owner+"/"+name)]; ok {
		r.mu.RUnlock()
		return p, nil
	}
	root := r.rootDir
	r.mu.RUnlock()

	if root != "" {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return "", domain.WrapError(domain.ErrBadRequest, "INVALID_BARE_PATH", "invalid bare root path", err)
		}
		absCandidate, err := filepath.Abs(filepath.Join(absRoot, owner, name+".git"))
		if err != nil {
			return "", domain.BadRequest("INVALID_REPOSITORY_NAME", "invalid repository path")
		}
		rel, relErr := filepath.Rel(absRoot, absCandidate)
		if relErr != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", domain.BadRequest("INVALID_REPOSITORY_NAME", "repository path escapes bare root directory")
		}
		evalRoot, evalRootErr := filepath.EvalSymlinks(absRoot)
		if evalRootErr == nil {
			ownerDir := filepath.Dir(absCandidate)
			if _, lstatErr := os.Lstat(ownerDir); lstatErr == nil {
				evalOwner, err := filepath.EvalSymlinks(ownerDir)
				if err != nil {
					return "", domain.BadRequest("PATH_ESCAPE", "unable to resolve repository owner directory")
				}
				if evalOwner != evalRoot && !strings.HasPrefix(evalOwner, evalRoot+string(filepath.Separator)) {
					return "", domain.BadRequest("PATH_ESCAPE", "repository owner directory escapes bare root")
				}
			}
		}
		if info, statErr := os.Stat(absCandidate); statErr == nil && info.IsDir() {
			if evalRootErr == nil {
				evalCand, err := filepath.EvalSymlinks(absCandidate)
				if err != nil {
					return "", domain.BadRequest("PATH_ESCAPE", "unable to resolve repository directory")
				}
				if evalCand != evalRoot && !strings.HasPrefix(evalCand, evalRoot+string(filepath.Separator)) {
					return "", domain.BadRequest("PATH_ESCAPE", "repository path escapes bare root via symlink")
				}
			}
			return absCandidate, nil
		}
	}
	return "", domain.NotFound("REPOSITORY_NOT_FOUND", "local bare repository not found")
}

func (r *LocalBareGitReader) ResolveRef(ctx context.Context, repo domain.Repository, ref string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return "", domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	if err := ValidateRefName(ref); err != nil {
		return "", err
	}
	barePath, err := r.resolveBarePath(repo)
	if err != nil {
		return "", err
	}

	// Explicit 40-char SHA
	if domain.IsValidGitSHA(strings.ToLower(ref)) {
		sha := strings.ToLower(ref)
		out, err := r.runBareGit(ctx, barePath, "cat-file", "-t", "--", sha+"^{commit}")
		if err == nil && strings.TrimSpace(out) == "commit" {
			return sha, nil
		}
		if objType, typeErr := r.runBareGit(ctx, barePath, "cat-file", "-t", "--", sha); typeErr == nil {
			return "", domain.Unprocessable("NON_COMMIT_REF", fmt.Sprintf("object %s is %q, expected commit", sha, strings.TrimSpace(objType)))
		}
		return "", domain.NotFound("GIT_REF_NOT_FOUND", "commit SHA not found in repository")
	}

	if ref == "HEAD" {
		out, err := r.runBareGit(ctx, barePath, "rev-parse", "--verify", "HEAD^{commit}")
		if err != nil {
			return "", domain.NotFound("GIT_REF_NOT_FOUND", "HEAD ref not found")
		}
		return domain.ParseGitSHA(out)
	}

	if strings.HasPrefix(ref, "refs/heads/") || strings.HasPrefix(ref, "refs/tags/") {
		out, err := r.runBareGit(ctx, barePath, "rev-parse", "--verify", ref+"^{commit}")
		if err == nil {
			return domain.ParseGitSHA(out)
		}
		if _, existsErr := r.runBareGit(ctx, barePath, "rev-parse", "--verify", ref); existsErr == nil {
			return "", domain.Unprocessable("NON_COMMIT_REF", fmt.Sprintf("ref %q does not resolve to a commit", ref))
		}
		return "", domain.NotFound("GIT_REF_NOT_FOUND", "git ref not found")
	}

	if strings.HasPrefix(ref, "refs/") {
		return "", domain.BadRequest("UNSUPPORTED_REF", "ref namespace is not allowed")
	}

	// Short ref: branch first, then tag
	if out, err := r.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/heads/"+ref+"^{commit}"); err == nil {
		return domain.ParseGitSHA(out)
	}
	if _, existsErr := r.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/heads/"+ref); existsErr == nil {
		return "", domain.Unprocessable("NON_COMMIT_REF", fmt.Sprintf("ref %q does not resolve to a commit", ref))
	}
	if out, err := r.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/tags/"+ref+"^{commit}"); err == nil {
		return domain.ParseGitSHA(out)
	}
	if _, existsErr := r.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/tags/"+ref); existsErr == nil {
		return "", domain.Unprocessable("NON_COMMIT_REF", fmt.Sprintf("ref %q does not resolve to a commit", ref))
	}
	return "", domain.NotFound("GIT_REF_NOT_FOUND", "git ref not found")
}

func (r *LocalBareGitReader) Checkout(ctx context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return domain.CheckoutResult{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	sha, err := domain.ParseGitSHA(commitSHA)
	if err != nil {
		return domain.CheckoutResult{}, err
	}
	barePath, err := r.resolveBarePath(repo)
	if err != nil {
		return domain.CheckoutResult{}, err
	}

	return r.checkout.Checkout(ctx, checkout.Request{
		RemoteURL:          "file://" + barePath,
		CommitSHA:          sha,
		WorkDir:            opts.WorkDir,
		IncludeGitMetadata: opts.IncludeGitMetadata,
		IncludeHistory:     opts.IncludeHistory,
		AllowLocalBare:     true,
	})
}

func (r *LocalBareGitReader) runBareGit(ctx context.Context, barePath string, args ...string) (string, error) {
	homeDir, err := os.MkdirTemp("", "custodian-baregit-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(homeDir)

	allArgs := append(checkout.HardenedGitFlags(true), "-C", barePath)
	allArgs = append(allArgs, args...)

	cmd := exec.CommandContext(ctx, r.gitBin, allArgs...)
	cmd.Env = checkout.CleanGitEnv(homeDir, true, false, "", "")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}
