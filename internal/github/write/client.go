package write

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	gogithub "github.com/google/go-github/v75/github"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

// RepositoryAccess contains ephemeral Git push access details for a repository.
type RepositoryAccess struct {
	RemoteURL         string
	Token             string
	DefaultBranch     string
	AllowLocalBare    bool
	AllowInsecureHTTP bool
}

// PullRequestParams describes an idempotent pull request create/update request.
type PullRequestParams struct {
	Repository domain.Repository
	HeadBranch string
	BaseBranch string
	Title      string
	Body       string
}

// PullRequestResult describes a created or updated pull request.
type PullRequestResult struct {
	Number  int64
	Title   string
	Body    string
	URL     string
	HTMLURL string
	Head    string
	Base    string
	State   string
	Updated bool
}

// Client defines the write-scoped GitHub operations required by the isolated publisher.
type Client interface {
	PreparePushAccess(ctx context.Context, repo domain.Repository) (RepositoryAccess, error)
	ResolveBranchSHA(ctx context.Context, repo domain.Repository, branch string) (string, error)
	CreateOrUpdatePullRequest(ctx context.Context, params PullRequestParams) (PullRequestResult, error)
}

// WriteClient implements Client using a write-scoped GitHub App
// (contents: write, pull_requests: write, metadata: read).
type WriteClient struct {
	auth              *writeTokenSource
	gitBaseURL        string
	allowInsecureHTTP bool
	logger            *slog.Logger
}

var _ Client = (*WriteClient)(nil)

// NewWriteClient constructs a WriteClient from WriteConfig.
func NewWriteClient(cfg WriteConfig) (*WriteClient, error) {
	authSrc, err := newWriteTokenSource(cfg)
	if err != nil {
		return nil, err
	}

	gitBase := strings.TrimRight(strings.TrimSpace(cfg.GitBaseURL), "/")
	if gitBase != "" {
		u, err := url.Parse(gitBase)
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "invalid GitHub git base URL")
		}
	}

	return &WriteClient{
		auth:              authSrc,
		gitBaseURL:        gitBase,
		allowInsecureHTTP: cfg.AllowInsecureHTTP,
		logger:            cfg.Logger,
	}, nil
}

// PreparePushAccess mints a write-scoped installation token and resolves the repository's Git remote URL.
func (c *WriteClient) PreparePushAccess(ctx context.Context, repo domain.Repository) (RepositoryAccess, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return RepositoryAccess{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	owner, name, err := repo.OwnerRepo()
	if err != nil {
		return RepositoryAccess{}, err
	}

	token, err := c.auth.installationToken(ctx, repo.GitHubInstallationID, repo.GitHubRepositoryID, name)
	if err != nil {
		return RepositoryAccess{}, err
	}

	var remoteURL string
	var defaultBranch string
	if c.gitBaseURL != "" {
		remoteURL = fmt.Sprintf("%s/%s/%s.git", c.gitBaseURL, url.PathEscape(owner), url.PathEscape(name))
	} else {
		gh := c.auth.newBaseClient().WithAuthToken(token)
		ghRepo, resp, err := gh.Repositories.Get(ctx, owner, name)
		if err != nil {
			return RepositoryAccess{}, mapGitHubError(err, resp, "failed to fetch GitHub repository metadata")
		}
		if ghRepo != nil {
			defaultBranch = strings.TrimSpace(ghRepo.GetDefaultBranch())
			remoteURL = strings.TrimSpace(ghRepo.GetCloneURL())
		}
		if remoteURL == "" {
			derivedBase := c.deriveGitBaseURL()
			remoteURL = fmt.Sprintf("%s/%s/%s.git", derivedBase, url.PathEscape(owner), url.PathEscape(name))
		}
	}

	return RepositoryAccess{
		RemoteURL:         remoteURL,
		Token:             token,
		DefaultBranch:     defaultBranch,
		AllowLocalBare:    false,
		AllowInsecureHTTP: c.allowInsecureHTTP,
	}, nil
}

// ResolveDefaultBranch queries GET /repos/{owner}/{repo} to obtain the repository's default branch.
func (c *WriteClient) ResolveDefaultBranch(ctx context.Context, repo domain.Repository) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return "", domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	owner, name, err := repo.OwnerRepo()
	if err != nil {
		return "", err
	}
	token, err := c.auth.installationToken(ctx, repo.GitHubInstallationID, repo.GitHubRepositoryID, name)
	if err != nil {
		return "", err
	}
	gh := c.auth.newBaseClient().WithAuthToken(token)
	ghRepo, resp, err := gh.Repositories.Get(ctx, owner, name)
	if err != nil {
		return "", mapGitHubError(err, resp, "failed to fetch GitHub repository metadata")
	}
	branch := strings.TrimSpace(ghRepo.GetDefaultBranch())
	if branch == "" {
		return "", domain.NotFound("DEFAULT_BRANCH_NOT_FOUND", "repository default branch is empty")
	}
	return branch, nil
}

// ResolveBranchSHA resolves a branch name (or refs/heads/<branch>) to a 40-hex commit SHA.
func (c *WriteClient) ResolveBranchSHA(ctx context.Context, repo domain.Repository, branch string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return "", domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	owner, name, err := repo.OwnerRepo()
	if err != nil {
		return "", err
	}
	shortBranch, err := normalizeBranchName(branch)
	if err != nil {
		return "", err
	}

	token, err := c.auth.installationToken(ctx, repo.GitHubInstallationID, repo.GitHubRepositoryID, name)
	if err != nil {
		return "", err
	}
	gh := c.auth.newBaseClient().WithAuthToken(token)

	refObj, resp, err := gh.Git.GetRef(ctx, owner, name, "heads/"+shortBranch)
	if err != nil {
		return "", mapGitHubError(err, resp, "git branch ref not found")
	}
	if refObj == nil || refObj.Object == nil {
		return "", domain.NotFound("GIT_REF_NOT_FOUND", "git branch ref has no target object")
	}
	if objType := refObj.Object.GetType(); objType != "" && objType != "commit" {
		return "", domain.Unprocessable("UNSUPPORTED_GIT_OBJECT", fmt.Sprintf("branch ref resolves to %q, expected commit", objType))
	}
	return domain.ParseGitSHA(refObj.Object.GetSHA())
}

// CreateOrUpdatePullRequest idempotently creates a PR for (HeadBranch, BaseBranch) or updates an existing open PR.
func (c *WriteClient) CreateOrUpdatePullRequest(ctx context.Context, params PullRequestParams) (PullRequestResult, error) {
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

	token, err := c.auth.installationToken(ctx, params.Repository.GitHubInstallationID, params.Repository.GitHubRepositoryID, name)
	if err != nil {
		return PullRequestResult{}, err
	}
	gh := c.auth.newBaseClient().WithAuthToken(token)

	existing, err := c.findOpenPR(ctx, gh, owner, name, headBranch, baseBranch)
	if err != nil {
		return PullRequestResult{}, err
	}
	if existing != nil {
		return c.reconcileExistingPR(ctx, gh, owner, name, existing, title, params.Body, baseBranch)
	}

	created, resp, createErr := gh.PullRequests.Create(ctx, owner, name, &gogithub.NewPullRequest{
		Title: gogithub.Ptr(title),
		Head:  gogithub.Ptr(headBranch),
		Base:  gogithub.Ptr(baseBranch),
		Body:  gogithub.Ptr(params.Body),
	})
	if createErr != nil {
		mapped := mapGitHubError(createErr, resp, "failed to create pull request")
		if errors.Is(mapped, domain.ErrUnprocessable) {
			// Concurrent race fallback: another worker may have created the PR between List and Create.
			if raced, findErr := c.findOpenPR(ctx, gh, owner, name, headBranch, baseBranch); findErr == nil && raced != nil {
				return c.reconcileExistingPR(ctx, gh, owner, name, raced, title, params.Body, baseBranch)
			}
		}
		return PullRequestResult{}, mapped
	}

	res := toPullRequestResult(created, false)
	if c.logger != nil {
		observability.LoggerWithTrace(ctx, c.logger).Info("created github pull request",
			"github_repository_id", params.Repository.GitHubRepositoryID,
			"pull_request_number", res.Number,
			"branch_ref", headBranch,
			"target_ref", baseBranch,
			"status", "created",
		)
	}
	return res, nil
}

func (c *WriteClient) findOpenPR(ctx context.Context, gh *gogithub.Client, owner, name, headBranch, baseBranch string) (*gogithub.PullRequest, error) {
	prs, resp, err := gh.PullRequests.List(ctx, owner, name, &gogithub.PullRequestListOptions{
		State: "open",
		Head:  owner + ":" + headBranch,
		Base:  baseBranch,
	})
	if err != nil {
		return nil, mapGitHubError(err, resp, "failed to list open pull requests")
	}
	if len(prs) == 0 {
		return nil, nil
	}
	return prs[0], nil
}

func (c *WriteClient) reconcileExistingPR(
	ctx context.Context,
	gh *gogithub.Client,
	owner, name string,
	existing *gogithub.PullRequest,
	title, body, baseBranch string,
) (PullRequestResult, error) {
	existingBase := ""
	if existing.Base != nil {
		existingBase = existing.Base.GetRef()
	}
	if existing.GetTitle() == title && existing.GetBody() == body && (existingBase == "" || existingBase == baseBranch) {
		res := toPullRequestResult(existing, false)
		if c.logger != nil {
			observability.LoggerWithTrace(ctx, c.logger).Info("reused existing github pull request",
				"pull_request_number", res.Number,
				"branch_ref", res.Head,
				"target_ref", baseBranch,
				"status", "reused",
			)
		}
		return res, nil
	}

	patch := &gogithub.PullRequest{
		Title: gogithub.Ptr(title),
		Body:  gogithub.Ptr(body),
		Base:  &gogithub.PullRequestBranch{Ref: gogithub.Ptr(baseBranch)},
	}
	updated, resp, err := gh.PullRequests.Edit(ctx, owner, name, existing.GetNumber(), patch)
	if err != nil {
		return PullRequestResult{}, mapGitHubError(err, resp, "failed to update existing pull request")
	}
	res := toPullRequestResult(updated, true)
	if c.logger != nil {
		observability.LoggerWithTrace(ctx, c.logger).Info("updated existing github pull request",
			"pull_request_number", res.Number,
			"branch_ref", res.Head,
			"target_ref", baseBranch,
			"status", "updated",
		)
	}
	return res, nil
}

func (c *WriteClient) deriveGitBaseURL() string {
	u := *c.auth.apiBaseURL
	if strings.EqualFold(u.Host, "api.github.com") {
		return defaultGitHubGitBase
	}
	cleanPath := strings.TrimRight(u.Path, "/")
	cleanPath = strings.TrimSuffix(cleanPath, "/api/v3")
	u.Path = cleanPath
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func normalizeBranchName(branch string) (string, error) {
	if err := ValidateRefName(branch); err != nil {
		return "", err
	}
	if strings.HasPrefix(branch, "refs/heads/") {
		short := strings.TrimPrefix(branch, "refs/heads/")
		if err := ValidateRefName(short); err != nil {
			return "", err
		}
		return short, nil
	}
	if strings.HasPrefix(branch, "refs/") {
		return "", domain.BadRequest("UNSUPPORTED_REF", "ref must be a branch under refs/heads/")
	}
	return branch, nil
}

func toPullRequestResult(pr *gogithub.PullRequest, updated bool) PullRequestResult {
	if pr == nil {
		return PullRequestResult{Updated: updated}
	}
	head := ""
	if pr.Head != nil {
		head = pr.Head.GetRef()
	}
	base := ""
	if pr.Base != nil {
		base = pr.Base.GetRef()
	}
	return PullRequestResult{
		Number:  int64(pr.GetNumber()),
		Title:   pr.GetTitle(),
		Body:    pr.GetBody(),
		URL:     pr.GetURL(),
		HTMLURL: pr.GetHTMLURL(),
		Head:    head,
		Base:    base,
		State:   pr.GetState(),
		Updated: updated,
	}
}
