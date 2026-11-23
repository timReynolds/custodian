package write

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/timreynolds/custodian/internal/domain"
)

// LocalBareOption configures LocalBareClient.
type LocalBareOption func(*LocalBareClient)

type localPRRecord struct {
	Number int64
	Title  string
	Body   string
	Head   string
	Base   string
	State  string
}

// LocalBareClient implements Client against local bare Git repositories and an
// in-memory PR registry matching MockGitHub semantics for offline unit tests.
type LocalBareClient struct {
	mu       sync.RWMutex
	rootDir  string
	byRepoID map[int64]string
	byName   map[string]string
	prs      map[string][]localPRRecord
	gitBin   string
	logger   *slog.Logger
}

var _ Client = (*LocalBareClient)(nil)

func WithBareRootDir(dir string) LocalBareOption {
	return func(c *LocalBareClient) {
		c.rootDir = strings.TrimSpace(dir)
	}
}

func WithGitBinary(bin string) LocalBareOption {
	return func(c *LocalBareClient) {
		if strings.TrimSpace(bin) != "" {
			c.gitBin = strings.TrimSpace(bin)
		}
	}
}

func WithLogger(logger *slog.Logger) LocalBareOption {
	return func(c *LocalBareClient) {
		c.logger = logger
	}
}

// NewLocalBareClient constructs a LocalBareClient with zero dependency on internal/git/checkout.
func NewLocalBareClient(opts ...LocalBareOption) *LocalBareClient {
	c := &LocalBareClient{
		byRepoID: make(map[int64]string),
		byName:   make(map[string]string),
		prs:      make(map[string][]localPRRecord),
		gitBin:   "git",
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
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
func (c *LocalBareClient) RegisterRepo(repoID int64, fullName, barePath string) error {
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

	c.mu.Lock()
	defer c.mu.Unlock()
	if repoID > 0 {
		c.byRepoID[repoID] = abs
	}
	if normalizedName != "" {
		c.byName[normalizedName] = abs
	}
	return nil
}

func (c *LocalBareClient) resolveBarePath(repo domain.Repository) (string, error) {
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

	c.mu.RLock()
	if repo.GitHubRepositoryID > 0 {
		if p, ok := c.byRepoID[repo.GitHubRepositoryID]; ok {
			c.mu.RUnlock()
			return p, nil
		}
	}
	if p, ok := c.byName[strings.ToLower(owner+"/"+name)]; ok {
		c.mu.RUnlock()
		return p, nil
	}
	root := c.rootDir
	c.mu.RUnlock()

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

// PreparePushAccess returns file:// push access and default branch for the registered local bare repository.
func (c *LocalBareClient) PreparePushAccess(ctx context.Context, repo domain.Repository) (RepositoryAccess, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return RepositoryAccess{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	barePath, err := c.resolveBarePath(repo)
	if err != nil {
		return RepositoryAccess{}, err
	}
	defaultBranch := ""
	if out, err := c.runBareGit(ctx, barePath, "symbolic-ref", "--short", "HEAD"); err == nil {
		defaultBranch = strings.TrimSpace(out)
	}
	return RepositoryAccess{
		RemoteURL:         "file://" + barePath,
		Token:             "",
		DefaultBranch:     defaultBranch,
		AllowLocalBare:    true,
		AllowInsecureHTTP: false,
	}, nil
}

// ResolveBranchSHA resolves refs/heads/<branch> to its 40-hex commit SHA in the local bare repo.
func (c *LocalBareClient) ResolveBranchSHA(ctx context.Context, repo domain.Repository, branch string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", domain.WrapError(domain.ErrUnavailable, "GIT_REF_LOOKUP_ABORTED", "git branch ref lookup aborted", err)
	}
	if !repo.Enabled {
		return "", domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	shortBranch, err := normalizeBranchName(branch)
	if err != nil {
		return "", err
	}
	barePath, err := c.resolveBarePath(repo)
	if err != nil {
		return "", err
	}
	out, err := c.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/heads/"+shortBranch+"^{commit}")
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", domain.WrapError(domain.ErrUnavailable, "GIT_REF_LOOKUP_ABORTED", "git branch ref lookup aborted", ctxErr)
		}
		if !isGitMissingRefError(err) {
			return "", domain.WrapError(domain.ErrInternal, "GIT_REF_LOOKUP_FAILED", "failed resolving git branch ref", err)
		}
		_, existsErr := c.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/heads/"+shortBranch)
		if existsErr == nil {
			return "", domain.Unprocessable("NON_COMMIT_REF", fmt.Sprintf("ref %q does not resolve to a commit", shortBranch))
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", domain.WrapError(domain.ErrUnavailable, "GIT_REF_LOOKUP_ABORTED", "git branch ref lookup aborted", ctxErr)
		}
		if isGitMissingRefError(existsErr) {
			return "", domain.NotFound("GIT_REF_NOT_FOUND", "git branch ref not found")
		}
		return "", domain.WrapError(domain.ErrInternal, "GIT_REF_LOOKUP_FAILED", "failed resolving git branch ref", existsErr)
	}
	return domain.ParseGitSHA(out)
}

// IsAncestor checks whether baseCommit is an ancestor of targetBranch in the local bare repo.
func (c *LocalBareClient) IsAncestor(ctx context.Context, repo domain.Repository, baseCommit, targetBranch string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, domain.WrapError(domain.ErrUnavailable, "GIT_ANCESTRY_ABORTED", "git ancestry check aborted", err)
	}
	baseSHA, err := domain.ParseGitSHA(baseCommit)
	if err != nil {
		return false, err
	}
	tipSHA, err := c.ResolveBranchSHA(ctx, repo, targetBranch)
	if err != nil {
		return false, err
	}
	barePath, err := c.resolveBarePath(repo)
	if err != nil {
		return false, err
	}
	if _, err := c.runBareGit(ctx, barePath, "cat-file", "-e", baseSHA); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, domain.WrapError(domain.ErrUnavailable, "GIT_ANCESTRY_ABORTED", "git ancestry check aborted", ctxErr)
		}
		if isGitExitStatusOne(err) {
			return false, nil
		}
		return false, domain.WrapError(domain.ErrInternal, "GIT_ANCESTRY_FAILED", "failed checking base commit existence", err)
	}
	objType, err := c.runBareGit(ctx, barePath, "cat-file", "-t", baseSHA)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, domain.WrapError(domain.ErrUnavailable, "GIT_ANCESTRY_ABORTED", "git ancestry check aborted", ctxErr)
		}
		return false, domain.WrapError(domain.ErrInternal, "GIT_ANCESTRY_FAILED", "failed checking base commit object type", err)
	}
	if strings.TrimSpace(objType) != "commit" {
		return false, nil
	}
	if _, err := c.runBareGit(ctx, barePath, "merge-base", "--is-ancestor", baseSHA, tipSHA); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, domain.WrapError(domain.ErrUnavailable, "GIT_ANCESTRY_ABORTED", "git ancestry check aborted", ctxErr)
		}
		if isGitExitStatusOne(err) {
			return false, nil
		}
		return false, domain.WrapError(domain.ErrInternal, "GIT_ANCESTRY_FAILED", "failed checking git commit ancestry", err)
	}
	return true, nil
}

type bareGitError struct {
	err    error
	stderr string
}

func (e *bareGitError) Error() string {
	if s := strings.TrimSpace(e.stderr); s != "" {
		return fmt.Sprintf("%v: %s", e.err, s)
	}
	return e.err.Error()
}

func (e *bareGitError) Unwrap() error {
	return e.err
}

func isGitExitStatusOne(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

func isGitMissingRefError(err error) bool {
	if isGitExitStatusOne(err) {
		return true
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 128 {
		return false
	}
	var bareErr *bareGitError
	if !errors.As(err, &bareErr) {
		return false
	}
	lower := strings.ToLower(bareErr.stderr)
	return strings.Contains(lower, "needed a single revision") ||
		strings.Contains(lower, "unknown revision") ||
		strings.Contains(lower, "not a valid object name") ||
		strings.Contains(lower, "bad revision")
}

// CreateOrUpdatePullRequest creates or updates an in-memory PR for the bare repository,
// enforcing branch existence and single-open-PR-per-(head,base) uniqueness like MockGitHub.
func (c *LocalBareClient) CreateOrUpdatePullRequest(ctx context.Context, params PullRequestParams) (PullRequestResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !params.Repository.Enabled {
		return PullRequestResult{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	owner, name, err := params.Repository.OwnerRepo()
	if err != nil {
		return PullRequestResult{}, err
	}
	headBranch, err := normalizeBranchName(params.HeadBranch)
	if err != nil {
		return PullRequestResult{}, err
	}
	baseBranch, err := normalizeBranchName(params.BaseBranch)
	if err != nil {
		return PullRequestResult{}, err
	}
	title := strings.TrimSpace(params.Title)
	if title == "" {
		return PullRequestResult{}, domain.BadRequest("INVALID_PULL_REQUEST_TITLE", "pull request title must not be empty")
	}

	barePath, err := c.resolveBarePath(params.Repository)
	if err != nil {
		return PullRequestResult{}, err
	}
	if _, err := c.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/heads/"+headBranch+"^{commit}"); err != nil {
		return PullRequestResult{}, domain.Unprocessable("GITHUB_UNPROCESSABLE", "head branch does not exist in bare repository")
	}
	if _, err := c.runBareGit(ctx, barePath, "rev-parse", "--verify", "refs/heads/"+baseBranch+"^{commit}"); err != nil {
		return PullRequestResult{}, domain.Unprocessable("GITHUB_UNPROCESSABLE", "base branch does not exist in bare repository")
	}

	repoKey := strings.ToLower(owner + "/" + name)
	c.mu.Lock()
	defer c.mu.Unlock()

	list := c.prs[repoKey]
	for i := range list {
		if list[i].State == "open" && list[i].Head == headBranch && list[i].Base == baseBranch {
			changed := list[i].Title != title || list[i].Body != params.Body
			list[i].Title = title
			list[i].Body = params.Body
			return localPRToResult(owner, name, list[i], changed), nil
		}
	}

	rec := localPRRecord{
		Number: int64(len(list) + 1),
		Title:  title,
		Body:   params.Body,
		Head:   headBranch,
		Base:   baseBranch,
		State:  "open",
	}
	c.prs[repoKey] = append(list, rec)
	return localPRToResult(owner, name, rec, false), nil
}

// PullRequests returns a snapshot of all PRs recorded for fullName ("owner/repo").
func (c *LocalBareClient) PullRequests(fullName string) []PullRequestResult {
	owner, name, err := (domain.Repository{FullName: fullName}).OwnerRepo()
	if err != nil {
		return nil
	}
	repoKey := strings.ToLower(owner + "/" + name)
	c.mu.RLock()
	defer c.mu.RUnlock()
	src := c.prs[repoKey]
	out := make([]PullRequestResult, len(src))
	for i, rec := range src {
		out[i] = localPRToResult(owner, name, rec, false)
	}
	return out
}

// ClosePullRequest transitions a PR in the in-memory store to closed for test scenarios.
func (c *LocalBareClient) ClosePullRequest(fullName string, number int64) error {
	owner, name, err := (domain.Repository{FullName: fullName}).OwnerRepo()
	if err != nil {
		return err
	}
	repoKey := strings.ToLower(owner + "/" + name)
	c.mu.Lock()
	defer c.mu.Unlock()
	list := c.prs[repoKey]
	for i := range list {
		if list[i].Number == number {
			list[i].State = "closed"
			return nil
		}
	}
	return domain.NotFound("PR_NOT_FOUND", "pull request not found")
}

func localPRToResult(owner, name string, rec localPRRecord, updated bool) PullRequestResult {
	return PullRequestResult{
		Number:  rec.Number,
		Title:   rec.Title,
		Body:    rec.Body,
		URL:     fmt.Sprintf("https://github.com/repos/%s/%s/pulls/%d", owner, name, rec.Number),
		HTMLURL: fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, name, rec.Number),
		Head:    rec.Head,
		Base:    rec.Base,
		State:   rec.State,
		Updated: updated,
	}
}

func (c *LocalBareClient) runBareGit(ctx context.Context, barePath string, args ...string) (string, error) {
	homeDir, err := os.MkdirTemp("", "custodian-barewrite-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(homeDir)

	allArgs := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "core.fsmonitor=false",
		"-c", "core.autocrlf=false",
		"-c", "credential.helper=",
		"-c", "submodule.recurse=false",
		"-c", "fetch.fsckObjects=true",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=always",
		"-C", barePath,
	}
	allArgs = append(allArgs, args...)

	cmd := exec.CommandContext(ctx, c.gitBin, allArgs...)
	cmd.Env = cleanBareEnv(homeDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", &bareGitError{err: err, stderr: stderr.String()}
	}
	return strings.TrimSpace(stdout.String()), nil
}

func cleanBareEnv(homeDir string) []string {
	allowed := map[string]struct{}{
		"PATH":          {},
		"TMPDIR":        {},
		"LANG":          {},
		"LC_ALL":        {},
		"SSL_CERT_FILE": {},
		"SSL_CERT_DIR":  {},
	}
	env := make([]string, 0, 12)
	for _, entry := range os.Environ() {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, keep := allowed[k]; keep {
			env = append(env, entry)
		}
	}
	env = append(env,
		"HOME="+homeDir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=file",
	)
	return env
}
