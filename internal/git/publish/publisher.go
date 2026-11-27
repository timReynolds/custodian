package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	defaultTimeout        = 2 * time.Minute
	defaultCommitterName  = "Custodian"
	defaultCommitterEmail = "custodian@custodian.local"
)

// InputLoader resolves an ApprovedPublication into a concrete PublishRequest
// for domain.Publisher.Publish.
type InputLoader interface {
	LoadApprovedPublication(ctx context.Context, req domain.ApprovedPublication) (PublishRequest, error)
}

// ArtifactOpener opens persisted CANONICAL_TREE artifacts (satisfied by domain.SnapshotStore).
type ArtifactOpener interface {
	Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error)
}

type defaultBranchResolver interface {
	ResolveDefaultBranch(ctx context.Context, repo domain.Repository) (string, error)
}

// Config configures the isolated Git publisher Service.
type Config struct {
	GitBinary      string
	Timeout        time.Duration
	WriteClient    write.Client
	Loader         InputLoader
	ArtifactOpener ArtifactOpener
	ArchiveLimits  ArchiveLimits
	CommitterName  string
	CommitterEmail string
	Logger         *slog.Logger
	Metrics        *observability.Metrics
}

// PublishRequest describes a fully-resolved, policy-approved canonical publication payload.
type PublishRequest struct {
	ProposalID                  uuid.UUID
	WorkspaceID                 uuid.UUID
	Repository                  domain.Repository
	Owner                       domain.Principal
	BaseCommit                  string
	TargetRef                   string
	Title                       string
	Description                 string
	PRBody                      string
	AgentAssisted               bool
	ManifestDigest              string
	ExpectedTreeDigest          string
	ExpectedCanonicalTreeSHA256 string
	CanonicalTreeArtifact       *domain.Artifact
	CanonicalTreeTarGz          []byte
	OpenCanonicalTree           func(ctx context.Context) (io.ReadCloser, error)
	CommitTime                  time.Time
	BranchOverride              string
}

// Service implements domain.Publisher in a hardened, dependency-isolated Git environment.
type Service struct {
	gitBin         string
	timeout        time.Duration
	writeClient    write.Client
	loader         InputLoader
	artifactOpener ArtifactOpener
	archiveLimits  ArchiveLimits
	committerName  string
	committerEmail string
	logger         *slog.Logger
	metrics        *observability.Metrics
}

var _ domain.Publisher = (*Service)(nil)

// NewService constructs a hardened isolated Git publisher Service.
func NewService(cfg Config) (*Service, error) {
	if cfg.WriteClient == nil {
		return nil, domain.Internal("MISSING_WRITE_CLIENT", "write GitHub client is required")
	}
	gitBin := strings.TrimSpace(cfg.GitBinary)
	if gitBin == "" {
		gitBin = "git"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	committerName := strings.TrimSpace(cfg.CommitterName)
	if committerName == "" {
		committerName = defaultCommitterName
	}
	committerEmail := strings.TrimSpace(cfg.CommitterEmail)
	if committerEmail == "" {
		committerEmail = defaultCommitterEmail
	}
	return &Service{
		gitBin:         gitBin,
		timeout:        timeout,
		writeClient:    cfg.WriteClient,
		loader:         cfg.Loader,
		artifactOpener: cfg.ArtifactOpener,
		archiveLimits:  cfg.ArchiveLimits.withDefaults(),
		committerName:  committerName,
		committerEmail: committerEmail,
		logger:         cfg.Logger,
		metrics:        cfg.Metrics,
	}, nil
}

// Publish implements domain.Publisher by loading the approved publication payload via InputLoader
// and verifying the bound ManifestDigest before delegating to PublishRequest.
func (s *Service) Publish(ctx context.Context, req domain.ApprovedPublication) (domain.PublicationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if req.ProposalID == uuid.Nil {
		return domain.PublicationResult{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	approvedDigest, err := domain.ParseSHA256Digest(req.ManifestDigest)
	if err != nil {
		return domain.PublicationResult{}, err
	}
	if s.loader == nil {
		return domain.PublicationResult{}, domain.Internal("MISSING_INPUT_LOADER", "publication input loader is not configured")
	}

	pubReq, err := s.loader.LoadApprovedPublication(ctx, domain.ApprovedPublication{
		ProposalID:     req.ProposalID,
		ManifestDigest: approvedDigest,
	})
	if err != nil {
		return domain.PublicationResult{}, err
	}
	if pubReq.ProposalID != req.ProposalID {
		return domain.PublicationResult{}, domain.Conflict("PROPOSAL_MISMATCH", "loaded proposal_id does not match approved publication")
	}
	loadedDigest, err := domain.ParseSHA256Digest(pubReq.ManifestDigest)
	if err != nil || loadedDigest != approvedDigest {
		return domain.PublicationResult{}, domain.Conflict("MANIFEST_DIGEST_MISMATCH", "loaded manifest_digest does not match approved publication digest")
	}
	pubReq.ManifestDigest = approvedDigest
	return s.PublishRequest(ctx, pubReq)
}

// PublishRequest executes hardened canonical commit creation, upstream force-push checking,
// exclusive custodian/<proposal-id> branch push, and idempotent PR creation/update.
func (s *Service) PublishRequest(ctx context.Context, req PublishRequest) (domain.PublicationResult, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	recordOutcome := func(status string) {
		if s.metrics != nil {
			s.metrics.IncPublication(status)
			s.metrics.ObserveWorkflow("publish", "publish", status, time.Since(start))
		}
	}

	// 1. Validate request invariants fail-closed before touching Git or GitHub.
	if req.ProposalID == uuid.Nil {
		recordOutcome("error")
		return domain.PublicationResult{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	if req.WorkspaceID == uuid.Nil {
		recordOutcome("error")
		return domain.PublicationResult{}, domain.BadRequest("INVALID_WORKSPACE_ID", "workspace_id must not be nil")
	}
	if !req.Repository.Enabled {
		recordOutcome("error")
		return domain.PublicationResult{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	if _, _, err := req.Repository.OwnerRepo(); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	if req.BranchOverride != "" {
		if err := domain.ValidateBranchRef(req.ProposalID, req.BranchOverride); err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}
	}
	branchName := domain.ExpectedBranchName(req.ProposalID)
	branchRef := domain.ExpectedBranchRef(req.ProposalID)
	if err := domain.ValidateBranchRef(req.ProposalID, branchRef); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	baseSHA, err := domain.ParseGitSHA(req.BaseCommit)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	if err := validateRefName(req.TargetRef); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	var manifestDigest string
	if strings.TrimSpace(req.ManifestDigest) != "" {
		manifestDigest, err = domain.ParseSHA256Digest(req.ManifestDigest)
		if err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}
	}

	var expectedTreeDigest string
	if strings.TrimSpace(req.ExpectedTreeDigest) != "" {
		expectedTreeDigest, err = domain.ParseGitSHA(req.ExpectedTreeDigest)
		if err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}
	}

	// ADV-07: Author comes strictly from accountable verified human principal.
	authorName, authorEmail, err := req.Owner.GitAuthor()
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	expectedArchiveSHA := strings.TrimSpace(req.ExpectedCanonicalTreeSHA256)
	var expectedArchiveSize int64
	if req.CanonicalTreeArtifact != nil {
		if req.CanonicalTreeArtifact.Kind != domain.ArtifactKindCanonicalTree {
			recordOutcome("error")
			return domain.PublicationResult{}, domain.BadRequest("INVALID_ARTIFACT_KIND", "publication artifact must have kind CANONICAL_TREE")
		}
		if expectedArchiveSHA == "" {
			expectedArchiveSHA = req.CanonicalTreeArtifact.SHA256
		}
		if req.CanonicalTreeArtifact.SizeBytes > 0 {
			expectedArchiveSize = req.CanonicalTreeArtifact.SizeBytes
		}
	}
	if expectedArchiveSHA != "" {
		expectedArchiveSHA, err = domain.ParseSHA256Digest(expectedArchiveSHA)
		if err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}
	}

	cleanTitle := sanitizeTitle(req.Title, req.ProposalID)
	commitMsg := FormatCommitMessage(cleanTitle, req.Description, req.ProposalID, req.WorkspaceID, req.AgentAssisted)
	prBody := formatPRBody(req.PRBody, req.Description, req.ProposalID, req.WorkspaceID, baseSHA, manifestDigest, req.AgentAssisted)

	// 2. Acquire write-scoped remote access & resolve target branch.
	access, err := s.writeClient.PreparePushAccess(runCtx, req.Repository)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	remoteURL, err := validateRemoteURL(access.RemoteURL, access.AllowLocalBare, access.AllowInsecureHTTP)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	baseBranch, err := s.resolveTargetBranch(runCtx, req.Repository, req.TargetRef, access.DefaultBranch)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	// 3. Create isolated 0700 HOME, working directory, and ephemeral GIT_ASKPASS.
	homeDir, err := os.MkdirTemp("", "custodian-pub-home-*")
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, domain.WrapError(domain.ErrInternal, "PUBLISH_ENV_FAILED", "failed creating isolated git home directory", err)
	}
	_ = os.Chmod(homeDir, 0o700)
	defer os.RemoveAll(homeDir)

	workDir, err := os.MkdirTemp("", "custodian-pub-work-*")
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, domain.WrapError(domain.ErrInternal, "PUBLISH_ENV_FAILED", "failed creating isolated publish working directory", err)
	}
	_ = os.Chmod(workDir, 0o700)
	defer os.RemoveAll(workDir)

	var askpassPath, tokenFilePath string
	if access.Token != "" {
		var cleanupAskpass func()
		askpassPath, tokenFilePath, cleanupAskpass, err = prepareAskpass(access.Token)
		if err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, domain.WrapError(domain.ErrInternal, "ASKPASS_SETUP_FAILED", "failed preparing ephemeral git askpass", err)
		}
		defer cleanupAskpass()
	}

	baseEnv := cleanGitEnv(homeDir, access.AllowLocalBare, access.AllowInsecureHTTP, askpassPath, tokenFilePath)

	// 4. Initialize isolated repository.
	if _, err := s.runGit(runCtx, "", baseEnv, access.AllowLocalBare, access.Token, "init", "--initial-branch=main", "--", workDir); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	// 5. Upstream Force-Push Check (ADV-11): fetch target branch and verify baseCommit is an ancestor.
	targetFetchRef := "refs/heads/" + baseBranch
	if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "fetch", "--no-tags", "--", remoteURL, targetFetchRef); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			recordOutcome("conflict")
			return domain.PublicationResult{}, domain.Conflict("UPSTREAM_BRANCH_MISSING", fmt.Sprintf("target branch %q does not exist on remote; aborting publication", baseBranch))
		}
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	targetTipOut, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		recordOutcome("conflict")
		return domain.PublicationResult{}, domain.Conflict("UPSTREAM_FORCE_PUSH", "target branch tip commit is invalid; aborting publication")
	}
	targetTipSHA, err := domain.ParseGitSHA(targetTipOut)
	if err != nil {
		recordOutcome("conflict")
		return domain.PublicationResult{}, domain.Conflict("UPSTREAM_FORCE_PUSH", "target branch tip commit SHA is invalid; aborting publication")
	}

	if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "cat-file", "-e", baseSHA+"^{commit}"); err != nil {
		recordOutcome("conflict")
		return domain.PublicationResult{}, domain.Conflict("UPSTREAM_FORCE_PUSH", "base_commit is not reachable from target branch; aborting publication")
	}
	if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "merge-base", "--is-ancestor", baseSHA, targetTipSHA); err != nil {
		recordOutcome("conflict")
		return domain.PublicationResult{}, domain.Conflict("UPSTREAM_FORCE_PUSH", "base_commit is not an ancestor of target branch; aborting publication")
	}

	// 6. Checkout pinned base_commit detached, clear worktree preserving .git, extract CANONICAL_TREE.
	if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "checkout", "--detach", baseSHA); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	if err := clearWorkTreePreservingGit(workDir); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	treeReader, err := s.openCanonicalTree(runCtx, req)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	extractErr := extractCanonicalTree(runCtx, treeReader, expectedArchiveSize, expectedArchiveSHA, workDir, s.archiveLimits)
	_ = treeReader.Close()
	if extractErr != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, extractErr
	}

	// 7. Stage canonical tree deterministically and verify tree digest.
	if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "read-tree", "--empty"); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "-c", "core.precomposeUnicode=false", "-c", "core.filemode=true", "add", "-A", "-f", "--", "."); err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	treeOut, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "write-tree")
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}
	treeSHA, err := domain.ParseGitSHA(treeOut)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, domain.Internal("INVALID_TREE_DIGEST", "git write-tree returned invalid SHA")
	}
	if expectedTreeDigest != "" && treeSHA != expectedTreeDigest {
		recordOutcome("conflict")
		return domain.PublicationResult{}, domain.Conflict("TREE_DIGEST_MISMATCH", "staged canonical tree digest does not match expected tree_digest")
	}

	// 8. Check remote custodian/<proposal-id> for idempotent replay (RG-08).
	remoteBranchSHA, remoteExists, err := s.lsRemoteHead(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, remoteURL, branchRef)
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	var commitSHA string
	if remoteExists {
		matches, matchErr := s.remoteCommitMatches(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, remoteURL, branchRef, remoteBranchSHA, treeSHA, baseSHA, authorName, authorEmail, s.committerName, s.committerEmail, commitMsg)
		if matchErr != nil {
			if errors.Is(matchErr, domain.ErrNotFound) {
				recordOutcome("conflict")
				return domain.PublicationResult{}, domain.Conflict("PUBLICATION_BRANCH_RACE", fmt.Sprintf("proposal branch %q disappeared on remote during idempotency verification; aborting publication", branchName))
			}
			recordOutcome("error")
			return domain.PublicationResult{}, matchErr
		}
		if matches {
			commitSHA = remoteBranchSHA
			if s.metrics != nil {
				s.metrics.IncPublicationRetry()
			}
		}
	}

	// 9. Create single-parent canonical commit and push strictly to refs/heads/custodian/<proposal-id>.
	if commitSHA == "" {
		msgFile := filepath.Join(homeDir, "COMMIT_MSG")
		if err := os.WriteFile(msgFile, []byte(commitMsg), 0o600); err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, domain.WrapError(domain.ErrInternal, "COMMIT_MSG_WRITE_FAILED", "failed writing commit message file", err)
		}

		commitEnv := make([]string, 0, len(baseEnv)+6)
		commitEnv = append(commitEnv, baseEnv...)
		commitEnv = append(commitEnv,
			"GIT_AUTHOR_NAME="+authorName,
			"GIT_AUTHOR_EMAIL="+authorEmail,
			"GIT_COMMITTER_NAME="+s.committerName,
			"GIT_COMMITTER_EMAIL="+s.committerEmail,
		)
		if !req.CommitTime.IsZero() {
			ts := req.CommitTime.UTC().Format(time.RFC3339)
			commitEnv = append(commitEnv, "GIT_AUTHOR_DATE="+ts, "GIT_COMMITTER_DATE="+ts)
		}

		commitOut, err := s.runGit(runCtx, workDir, commitEnv, access.AllowLocalBare, access.Token, "commit-tree", treeSHA, "-p", baseSHA, "-F", msgFile)
		if err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}
		commitSHA, err = domain.ParseGitSHA(commitOut)
		if err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, domain.Internal("INVALID_COMMIT_SHA", "git commit-tree returned invalid SHA")
		}

		if err := s.verifyCommitMetadata(runCtx, workDir, baseEnv, access.AllowLocalBare, commitSHA, treeSHA, baseSHA, authorName, authorEmail, s.committerName, s.committerEmail); err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}

		// Re-enforce branch exclusivity immediately before pushing.
		if err := domain.ValidateBranchRef(req.ProposalID, branchRef); err != nil {
			recordOutcome("error")
			return domain.PublicationResult{}, err
		}

		refspec := commitSHA + ":" + branchRef
		if remoteExists {
			if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "push", "--force-with-lease="+branchRef+":"+remoteBranchSHA, "--", remoteURL, refspec); err != nil {
				recordOutcome("error")
				return domain.PublicationResult{}, err
			}
		} else {
			if _, err := s.runGit(runCtx, workDir, baseEnv, access.AllowLocalBare, access.Token, "push", "--", remoteURL, refspec); err != nil {
				recordOutcome("error")
				return domain.PublicationResult{}, err
			}
		}
	}

	// 10. Idempotently create or update the single pull request.
	pr, err := s.writeClient.CreateOrUpdatePullRequest(runCtx, write.PullRequestParams{
		Repository: req.Repository,
		HeadBranch: branchName,
		BaseBranch: baseBranch,
		Title:      cleanTitle,
		Body:       prBody,
	})
	if err != nil {
		recordOutcome("error")
		return domain.PublicationResult{}, err
	}

	recordOutcome("published")
	if s.logger != nil {
		observability.LoggerWithTrace(runCtx, s.logger).Info("published proposal branch and pull request",
			"proposal_id", req.ProposalID.String(),
			"workspace_id", req.WorkspaceID.String(),
			"repository_id", req.Repository.ID.String(),
			"github_repository_id", req.Repository.GitHubRepositoryID,
			"commit_sha", commitSHA,
			"base_commit", baseSHA,
			"tree_digest", treeSHA,
			"manifest_digest", manifestDigest,
			"branch_ref", branchName,
			"target_ref", baseBranch,
			"pull_request_number", pr.Number,
			"status", "published",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}

	return domain.PublicationResult{
		ProposalID: req.ProposalID,
		CommitSHA:  commitSHA,
		Branch:     branchName,
		PRNumber:   pr.Number,
		PRURL:      pr.HTMLURL,
	}, nil
}

func (s *Service) resolveTargetBranch(ctx context.Context, repo domain.Repository, targetRef, defaultBranch string) (string, error) {
	if targetRef == "HEAD" {
		branch := strings.TrimPrefix(strings.TrimSpace(defaultBranch), "refs/heads/")
		if branch == "" {
			if resolver, ok := s.writeClient.(defaultBranchResolver); ok {
				resolved, err := resolver.ResolveDefaultBranch(ctx, repo)
				if err != nil {
					return "", err
				}
				branch = strings.TrimPrefix(strings.TrimSpace(resolved), "refs/heads/")
			}
		}
		if branch == "" {
			return "", domain.BadRequest("UNKNOWN_TARGET_BRANCH", "unable to resolve default branch for HEAD target_ref")
		}
		if err := validateRefName(branch); err != nil {
			return "", err
		}
		return branch, nil
	}
	if strings.HasPrefix(targetRef, "refs/heads/") {
		branch := strings.TrimPrefix(targetRef, "refs/heads/")
		if branch == "" {
			return "", domain.BadRequest("INVALID_REF_NAME", "target branch name must not be empty")
		}
		if err := validateRefName(branch); err != nil {
			return "", err
		}
		return branch, nil
	}
	if strings.HasPrefix(targetRef, "refs/") {
		return "", domain.BadRequest("UNSUPPORTED_TARGET_REF", "target_ref must be a branch")
	}
	if domain.IsValidGitSHA(strings.ToLower(targetRef)) {
		return "", domain.BadRequest("UNSUPPORTED_TARGET_REF", "target_ref must be a branch name, not a commit SHA")
	}
	return targetRef, nil
}

func (s *Service) openCanonicalTree(ctx context.Context, req PublishRequest) (io.ReadCloser, error) {
	if req.OpenCanonicalTree != nil {
		return req.OpenCanonicalTree(ctx)
	}
	if len(req.CanonicalTreeTarGz) > 0 {
		return io.NopCloser(bytes.NewReader(req.CanonicalTreeTarGz)), nil
	}
	if req.CanonicalTreeArtifact != nil {
		if s.artifactOpener == nil {
			return nil, domain.Internal("MISSING_ARTIFACT_OPENER", "artifact opener is not configured")
		}
		return s.artifactOpener.Open(ctx, *req.CanonicalTreeArtifact)
	}
	return nil, domain.BadRequest("MISSING_CANONICAL_TREE", "canonical tree archive is required")
}

func (s *Service) lsRemoteHead(ctx context.Context, workDir string, env []string, allowLocalBare bool, token, remoteURL, branchRef string) (string, bool, error) {
	out, err := s.runGit(ctx, workDir, env, allowLocalBare, token, "ls-remote", "--heads", "--", remoteURL, branchRef)
	if err != nil {
		return "", false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == branchRef {
			sha, parseErr := domain.ParseGitSHA(fields[0])
			if parseErr != nil {
				return "", false, parseErr
			}
			return sha, true, nil
		}
	}
	return "", false, nil
}

func (s *Service) remoteCommitMatches(
	ctx context.Context,
	workDir string,
	env []string,
	allowLocalBare bool,
	token, remoteURL, branchRef, remoteSHA string,
	wantTree, wantParent, wantAuthorName, wantAuthorEmail, wantCommitterName, wantCommitterEmail, wantMsg string,
) (bool, error) {
	if _, err := s.runGit(ctx, workDir, env, allowLocalBare, token, "fetch", "--no-tags", "--", remoteURL, branchRef); err != nil {
		return false, err
	}
	fetchedOut, err := s.runGit(ctx, workDir, env, allowLocalBare, token, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return false, err
	}
	fetchedSHA, err := domain.ParseGitSHA(fetchedOut)
	if err != nil || fetchedSHA != remoteSHA {
		return false, nil
	}
	const sep = "\x1e"
	format := strings.Join([]string{"%T", "%P", "%an", "%ae", "%cn", "%ce", "%B"}, sep)
	out, err := s.runGit(ctx, workDir, env, allowLocalBare, token, "show", "-s", "--format="+format, remoteSHA)
	if err != nil {
		return false, err
	}
	parts := strings.SplitN(out, sep, 7)
	if len(parts) < 7 {
		return false, nil
	}
	return strings.TrimSpace(parts[0]) == wantTree &&
		strings.TrimSpace(parts[1]) == wantParent &&
		parts[2] == wantAuthorName &&
		parts[3] == wantAuthorEmail &&
		parts[4] == wantCommitterName &&
		parts[5] == wantCommitterEmail &&
		strings.TrimRight(parts[6], "\r\n") == strings.TrimRight(wantMsg, "\r\n"), nil
}

func (s *Service) verifyCommitMetadata(
	ctx context.Context,
	workDir string,
	env []string,
	allowLocalBare bool,
	commitSHA, wantTree, wantParent, wantAuthorName, wantAuthorEmail, wantCommitterName, wantCommitterEmail string,
) error {
	const sep = "\x1e"
	format := strings.Join([]string{"%T", "%P", "%an", "%ae", "%cn", "%ce"}, sep)
	out, err := s.runGit(ctx, workDir, env, allowLocalBare, "", "show", "-s", "--format="+format, commitSHA)
	if err != nil {
		return err
	}
	parts := strings.SplitN(out, sep, 6)
	if len(parts) < 6 {
		return domain.Internal("COMMIT_VERIFICATION_FAILED", "unexpected git show output")
	}
	if strings.TrimSpace(parts[0]) != wantTree {
		return domain.Internal("COMMIT_VERIFICATION_FAILED", "created commit tree does not match canonical tree")
	}
	if strings.TrimSpace(parts[1]) != wantParent {
		return domain.Internal("COMMIT_VERIFICATION_FAILED", "created commit parent does not match base_commit")
	}
	if parts[2] != wantAuthorName || parts[3] != wantAuthorEmail {
		return domain.Internal("COMMIT_VERIFICATION_FAILED", "created commit author does not match verified human owner")
	}
	if parts[4] != wantCommitterName || strings.TrimSpace(parts[5]) != wantCommitterEmail {
		return domain.Internal("COMMIT_VERIFICATION_FAILED", "created commit committer does not match Custodian")
	}
	return nil
}

func (s *Service) runGit(ctx context.Context, workDir string, env []string, allowLocalBare bool, token string, args ...string) (string, error) {
	flags := hardenedGitFlags(allowLocalBare)
	allArgs := make([]string, 0, len(flags)+2+len(args))
	allArgs = append(allArgs, flags...)
	if workDir != "" {
		allArgs = append(allArgs, "-C", workDir)
	}
	allArgs = append(allArgs, args...)

	cmd := exec.CommandContext(ctx, s.gitBin, allArgs...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", classifyGitError(ctx, stderr.String(), err, token)
	}
	return strings.TrimRight(stdout.String(), "\r\n"), nil
}

func clearWorkTreePreservingGit(workDir string) error {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "WORKTREE_CLEAR_FAILED", "failed reading publish worktree", err)
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(workDir, entry.Name())); err != nil {
			return domain.WrapError(domain.ErrInternal, "WORKTREE_CLEAR_FAILED", "failed clearing publish worktree", err)
		}
	}
	return nil
}

func sanitizeTitle(raw string, proposalID uuid.UUID) string {
	clean := strings.ReplaceAll(raw, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.Join(strings.Fields(clean), " ")
	if clean == "" {
		return "Custodian proposal " + proposalID.String()
	}
	return clean
}

// FormatCommitMessage formats the canonical commit message with sanitized body text and
// authoritative Custodian-Proposal, Custodian-Workspace, and Agent-Assisted trailers.
func FormatCommitMessage(title, description string, proposalID, workspaceID uuid.UUID, agentAssisted bool) string {
	cleanTitle := sanitizeTitle(title, proposalID)
	cleanBody := sanitizeDescription(description)

	var b strings.Builder
	b.WriteString(cleanTitle)
	b.WriteString("\n\n")
	if cleanBody != "" {
		b.WriteString(cleanBody)
		b.WriteString("\n\n")
	}
	b.WriteString("Custodian-Proposal: ")
	b.WriteString(proposalID.String())
	b.WriteByte('\n')
	b.WriteString("Custodian-Workspace: ")
	b.WriteString(workspaceID.String())
	b.WriteByte('\n')
	b.WriteString("Agent-Assisted: ")
	b.WriteString(strconv.FormatBool(agentAssisted))
	b.WriteByte('\n')
	return b.String()
}

func sanitizeDescription(raw string) string {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if isReservedTrailerLine(lower) {
			continue
		}
		filtered = append(filtered, strings.TrimRight(line, " \t"))
	}
	return strings.TrimSpace(strings.Join(filtered, "\n"))
}

func isReservedTrailerLine(lowerTrimmed string) bool {
	for _, key := range []string{"custodian-proposal", "custodian-workspace", "agent-assisted"} {
		if strings.HasPrefix(lowerTrimmed, key) {
			rest := strings.TrimSpace(lowerTrimmed[len(key):])
			if strings.HasPrefix(rest, ":") {
				return true
			}
		}
	}
	return false
}

func formatPRBody(prBody, description string, proposalID, workspaceID uuid.UUID, baseSHA, manifestDigest string, agentAssisted bool) string {
	if trimmed := strings.TrimSpace(prBody); trimmed != "" {
		return trimmed
	}
	var b strings.Builder
	if cleanDesc := sanitizeDescription(description); cleanDesc != "" {
		b.WriteString(cleanDesc)
		b.WriteString("\n\n")
	}
	b.WriteString("Custodian-Proposal: ")
	b.WriteString(proposalID.String())
	b.WriteByte('\n')
	b.WriteString("Custodian-Workspace: ")
	b.WriteString(workspaceID.String())
	b.WriteByte('\n')
	b.WriteString("Base-Commit: ")
	b.WriteString(baseSHA)
	b.WriteByte('\n')
	if manifestDigest != "" {
		b.WriteString("Publication-Manifest-Digest: ")
		b.WriteString(manifestDigest)
		b.WriteByte('\n')
	}
	b.WriteString("Agent-Assisted: ")
	b.WriteString(strconv.FormatBool(agentAssisted))
	b.WriteByte('\n')
	return b.String()
}
