package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	gogithub "github.com/google/go-github/v75/github"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
)

const maxAnnotatedTagHops = 5

// ReadOnlyClient implements domain.GitReader using a read-only GitHub App
// (contents: read, metadata: read) and delegates cloning to checkout.Runner.
type ReadOnlyClient struct {
	auth              *appTokenSource
	gitBaseURL        string
	allowInsecureHTTP bool
	checkout          *checkout.Runner
	logger            *slog.Logger
}

var _ domain.GitReader = (*ReadOnlyClient)(nil)

// NewReadOnlyClient constructs a ReadOnlyClient from AppConfig.
func NewReadOnlyClient(cfg AppConfig) (*ReadOnlyClient, error) {
	authSrc, err := newAppTokenSource(cfg)
	if err != nil {
		return nil, err
	}

	gitBase := strings.TrimRight(strings.TrimSpace(cfg.GitBaseURL), "/")
	if gitBase == "" {
		gitBase = defaultGitHubGitBase
	}
	u, err := url.Parse(gitBase)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "invalid GitHub git base URL")
	}

	runner := cfg.CheckoutRunner
	if runner == nil {
		runner = checkout.NewRunner(checkout.RunnerConfig{Logger: cfg.Logger})
	}

	return &ReadOnlyClient{
		auth:              authSrc,
		gitBaseURL:        gitBase,
		allowInsecureHTTP: cfg.AllowInsecureHTTP,
		checkout:          runner,
		logger:            cfg.Logger,
	}, nil
}

func (c *ReadOnlyClient) ResolveRef(ctx context.Context, repo domain.Repository, ref string) (string, error) {
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
	if err := ValidateRefName(ref); err != nil {
		return "", err
	}

	token, err := c.auth.installationToken(ctx, repo.GitHubInstallationID, repo.GitHubRepositoryID, name)
	if err != nil {
		return "", err
	}
	gh := c.auth.newBaseClient().WithAuthToken(token)

	// 1. Explicit 40-char hex SHA
	if domain.IsValidGitSHA(strings.ToLower(ref)) {
		sha := strings.ToLower(ref)
		commit, resp, err := gh.Repositories.GetCommit(ctx, owner, name, sha, nil)
		if err != nil {
			return "", mapGitHubError(err, resp, "commit SHA not found")
		}
		resolved := commit.GetSHA()
		if resolved == "" {
			resolved = sha
		}
		return domain.ParseGitSHA(resolved)
	}

	// 2. HEAD
	if ref == "HEAD" {
		sha, resp, err := gh.Repositories.GetCommitSHA1(ctx, owner, name, "HEAD", "")
		if err != nil {
			return "", mapGitHubError(err, resp, "HEAD ref not found")
		}
		return domain.ParseGitSHA(sha)
	}

	// 3. Qualified refs/heads/* or refs/tags/*
	if strings.HasPrefix(ref, "refs/heads/") {
		return c.resolveQualifiedGitRef(ctx, gh, owner, name, strings.TrimPrefix(ref, "refs/"))
	}
	if strings.HasPrefix(ref, "refs/tags/") {
		return c.resolveQualifiedGitRef(ctx, gh, owner, name, strings.TrimPrefix(ref, "refs/"))
	}
	if strings.HasPrefix(ref, "refs/") {
		return "", domain.BadRequest("UNSUPPORTED_REF", "ref namespace is not allowed")
	}

	// 4. Short ref: try branch first, then tag on 404
	sha, err := c.resolveQualifiedGitRef(ctx, gh, owner, name, "heads/"+ref)
	if err == nil {
		return sha, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return "", err
	}
	return c.resolveQualifiedGitRef(ctx, gh, owner, name, "tags/"+ref)
}

func (c *ReadOnlyClient) resolveQualifiedGitRef(ctx context.Context, gh *gogithub.Client, owner, name, gitRef string) (string, error) {
	refObj, resp, err := gh.Git.GetRef(ctx, owner, name, gitRef)
	if err != nil {
		return "", mapGitHubError(err, resp, "git ref not found")
	}
	if refObj == nil || refObj.Object == nil {
		return "", domain.NotFound("GIT_REF_NOT_FOUND", "git ref has no target object")
	}

	objType := refObj.Object.GetType()
	objSHA := refObj.Object.GetSHA()
	for hop := 0; hop < maxAnnotatedTagHops && objType == "tag"; hop++ {
		tagObj, tagResp, err := gh.Git.GetTag(ctx, owner, name, objSHA)
		if err != nil {
			return "", mapGitHubError(err, tagResp, "failed dereferencing annotated tag")
		}
		if tagObj == nil || tagObj.Object == nil {
			return "", domain.Unprocessable("INVALID_GIT_TAG", "annotated tag target is missing")
		}
		objType = tagObj.Object.GetType()
		objSHA = tagObj.Object.GetSHA()
	}

	if objType != "commit" {
		return "", domain.Unprocessable("UNSUPPORTED_GIT_OBJECT", fmt.Sprintf("ref resolves to %q, expected commit", objType))
	}
	return domain.ParseGitSHA(objSHA)
}

func (c *ReadOnlyClient) Checkout(ctx context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !repo.Enabled {
		return domain.CheckoutResult{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	owner, name, err := repo.OwnerRepo()
	if err != nil {
		return domain.CheckoutResult{}, err
	}
	sha, err := domain.ParseGitSHA(commitSHA)
	if err != nil {
		return domain.CheckoutResult{}, err
	}

	token, err := c.auth.installationToken(ctx, repo.GitHubInstallationID, repo.GitHubRepositoryID, name)
	if err != nil {
		return domain.CheckoutResult{}, err
	}

	cloneURL := fmt.Sprintf("%s/%s/%s.git", c.gitBaseURL, url.PathEscape(owner), url.PathEscape(name))
	if c.logger != nil {
		c.logger.Info("starting read-only github checkout",
			"repository_id", repo.ID.String(),
			"github_repository_id", repo.GitHubRepositoryID,
			"commit_sha", sha,
		)
	}

	return c.checkout.Checkout(ctx, checkout.Request{
		RemoteURL:          cloneURL,
		CommitSHA:          sha,
		WorkDir:            opts.WorkDir,
		IncludeGitMetadata: opts.IncludeGitMetadata,
		IncludeHistory:     opts.IncludeHistory,
		Token:              token,
		AllowLocalBare:     false,
		AllowInsecureHTTP:  c.allowInsecureHTTP,
	})
}
