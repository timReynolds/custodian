package github

import (
	"context"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/github/write"
)

var _ write.Client = (*LocalBareGitReader)(nil)

// WriteClient returns the underlying write.LocalBareClient synchronized with this reader.
func (r *LocalBareGitReader) WriteClient() *write.LocalBareClient {
	return r.writer
}

// PreparePushAccess returns file:// push access and default branch for the local bare repository.
func (r *LocalBareGitReader) PreparePushAccess(ctx context.Context, repo domain.Repository) (write.RepositoryAccess, error) {
	return r.writer.PreparePushAccess(ctx, repo)
}

// ResolveBranchSHA resolves refs/heads/<branch> to its 40-hex commit SHA in the local bare repository.
func (r *LocalBareGitReader) ResolveBranchSHA(ctx context.Context, repo domain.Repository, branch string) (string, error) {
	return r.writer.ResolveBranchSHA(ctx, repo, branch)
}

// IsAncestor reports whether baseCommit is an ancestor of targetBranch in the local bare repository.
func (r *LocalBareGitReader) IsAncestor(ctx context.Context, repo domain.Repository, baseCommit, targetBranch string) (bool, error) {
	return r.writer.IsAncestor(ctx, repo, baseCommit, targetBranch)
}

// CreateOrUpdatePullRequest idempotently creates or updates an in-memory pull request for the bare repository.
func (r *LocalBareGitReader) CreateOrUpdatePullRequest(ctx context.Context, params write.PullRequestParams) (write.PullRequestResult, error) {
	return r.writer.CreateOrUpdatePullRequest(ctx, params)
}

// PullRequests returns a snapshot of all recorded pull requests for fullName ("owner/repo").
func (r *LocalBareGitReader) PullRequests(fullName string) []write.PullRequestResult {
	return r.writer.PullRequests(fullName)
}
