package write

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

func runGitBareTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Tester",
		"GIT_AUTHOR_EMAIL=tester@example.com",
		"GIT_COMMITTER_NAME=Tester",
		"GIT_COMMITTER_EMAIL=tester@example.com",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func setupTestBareRepo(t *testing.T, rootDir, owner, name string) (bareDir, sha1, sha2 string) {
	t.Helper()
	bareDir = filepath.Join(rootDir, owner, name+".git")
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", bareDir).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	seed := filepath.Join(t.TempDir(), "seed")
	if out, err := exec.Command("git", "init", "--initial-branch=main", seed).CombinedOutput(); err != nil {
		t.Fatalf("git init seed: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(seed, "README.md"), []byte("v1\n"), 0o644)
	runGitBareTest(t, seed, "add", "README.md")
	runGitBareTest(t, seed, "commit", "-m", "v1")
	sha1 = runGitBareTest(t, seed, "rev-parse", "HEAD")

	_ = os.WriteFile(filepath.Join(seed, "README.md"), []byte("v2\n"), 0o644)
	runGitBareTest(t, seed, "add", "README.md")
	runGitBareTest(t, seed, "commit", "-m", "v2")
	sha2 = runGitBareTest(t, seed, "rev-parse", "HEAD")

	runGitBareTest(t, seed, "push", bareDir, "main")
	return bareDir, sha1, sha2
}

func TestLocalBareClientAccessBranchAndPRLifecycle(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bareDir, sha1, sha2 := setupTestBareRepo(t, root, "acme", "svc")

	client := NewLocalBareClient(WithBareRootDir(root))
	repo := domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   101,
		GitHubInstallationID: 1,
		FullName:             "acme/svc",
		Enabled:              true,
	}
	ctx := context.Background()

	access, err := client.PreparePushAccess(ctx, repo)
	if err != nil {
		t.Fatalf("PreparePushAccess: %v", err)
	}
	if access.RemoteURL != "file://"+bareDir || !access.AllowLocalBare || access.DefaultBranch != "main" {
		t.Fatalf("unexpected RepositoryAccess: %+v", access)
	}

	gotSHA, err := client.ResolveBranchSHA(ctx, repo, "main")
	if err != nil || gotSHA != sha2 {
		t.Fatalf("ResolveBranchSHA(main): got %q err=%v", gotSHA, err)
	}

	ok, err := client.IsAncestor(ctx, repo, sha1, "main")
	if err != nil || !ok {
		t.Fatalf("expected sha1 to be ancestor of main, got ok=%v err=%v", ok, err)
	}

	// Missing head branch must fail with 422 Unprocessable.
	if _, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/missing",
		BaseBranch: "main",
		Title:      "Test PR",
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for missing head branch, got %v", err)
	}

	// Create branch ref in bare repo and test PR create/reuse/update/close lifecycle.
	runGitBareTest(t, bareDir, "update-ref", "refs/heads/custodian/prop-1", sha2)

	pr1, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "PR Title",
		Body:       "PR Body",
	})
	if err != nil {
		t.Fatalf("CreateOrUpdatePullRequest: %v", err)
	}
	if pr1.Number != 1 || pr1.Updated || pr1.State != "open" {
		t.Fatalf("unexpected PR1: %+v", pr1)
	}

	// Identical replay reuses PR #1.
	prReplay, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "PR Title",
		Body:       "PR Body",
	})
	if err != nil || prReplay.Number != 1 || prReplay.Updated {
		t.Fatalf("expected reused PR #1, got %+v err=%v", prReplay, err)
	}

	// Updated body patches PR #1.
	prUpdated, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "PR Title v2",
		Body:       "PR Body v2",
	})
	if err != nil || prUpdated.Number != 1 || !prUpdated.Updated || prUpdated.Title != "PR Title v2" {
		t.Fatalf("expected updated PR #1, got %+v err=%v", prUpdated, err)
	}

	// Close PR #1, next CreateOrUpdate creates PR #2.
	if err := client.ClosePullRequest("acme/svc", 1); err != nil {
		t.Fatalf("ClosePullRequest: %v", err)
	}
	pr2, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "PR Title v3",
		Body:       "PR Body v3",
	})
	if err != nil || pr2.Number != 2 || pr2.Updated {
		t.Fatalf("expected PR #2 after closing #1, got %+v err=%v", pr2, err)
	}
	if len(client.PullRequests("acme/svc")) != 2 {
		t.Fatalf("expected 2 PRs recorded")
	}

	// Simulate orphan force-push on main -> IsAncestor returns false.
	orphanWork := filepath.Join(t.TempDir(), "orphan")
	if out, err := exec.Command("git", "init", "--initial-branch=main", orphanWork).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	_ = os.WriteFile(filepath.Join(orphanWork, "README.md"), []byte("orphan\n"), 0o644)
	runGitBareTest(t, orphanWork, "add", "README.md")
	runGitBareTest(t, orphanWork, "commit", "-m", "orphan")
	runGitBareTest(t, orphanWork, "push", "--force", bareDir, "main")

	anc, err := client.IsAncestor(ctx, repo, sha1, "main")
	if err != nil {
		t.Fatalf("IsAncestor after force-push: %v", err)
	}
	if anc {
		t.Fatalf("expected sha1 NOT to be ancestor after orphan force-push")
	}
}

func TestLocalBareClientPathTraversalAndDisabledRepo(t *testing.T) {
	t.Parallel()
	outer := t.TempDir()
	bareRoot := filepath.Join(outer, "repos")
	_ = os.MkdirAll(bareRoot, 0o755)
	secretBare, _, _ := setupTestBareRepo(t, outer, "outside", "secret")

	_ = os.MkdirAll(filepath.Join(bareRoot, "sym"), 0o755)
	if err := os.Symlink(secretBare, filepath.Join(bareRoot, "sym", "escaped.git")); err != nil {
		t.Fatal(err)
	}

	client := NewLocalBareClient(WithBareRootDir(bareRoot))
	ctx := context.Background()

	for _, bad := range []string{"../secret", "-evil/repo", "owner/-evil", "sym/escaped"} {
		repo := domain.Repository{ID: domain.MustNewID(), FullName: bad, Enabled: true}
		if _, err := client.PreparePushAccess(ctx, repo); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("PreparePushAccess(%q) expected ErrBadRequest, got %v", bad, err)
		}
	}

	disabled := domain.Repository{ID: domain.MustNewID(), FullName: "acme/svc", Enabled: false}
	if _, err := client.PreparePushAccess(ctx, disabled); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo, got %v", err)
	}
}

func TestLocalBareClientIsAncestorErrorPropagation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bareDir, sha1, _ := setupTestBareRepo(t, root, "acme", "svc")
	repo := domain.Repository{
		ID:                 domain.MustNewID(),
		GitHubRepositoryID: 101,
		FullName:           "acme/svc",
		Enabled:            true,
	}

	client := NewLocalBareClient(WithBareRootDir(root))

	// 1. Missing baseSHA returns (false, nil).
	ok, err := client.IsAncestor(context.Background(), repo, strings.Repeat("a", 40), "main")
	if err != nil || ok {
		t.Fatalf("missing baseSHA: expected (false, nil), got (%v, %v)", ok, err)
	}

	// 2. Non-commit object SHA (blob) returns (false, nil).
	blobSHA := runGitBareTest(t, bareDir, "rev-parse", "main:README.md")
	ok, err = client.IsAncestor(context.Background(), repo, blobSHA, "main")
	if err != nil || ok {
		t.Fatalf("blob baseSHA: expected (false, nil), got (%v, %v)", ok, err)
	}

	// 3. Cancelled context propagates context.Canceled / ErrUnavailable.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err = client.IsAncestor(cancelledCtx, repo, sha1, "main")
	if ok || !errors.Is(err, context.Canceled) || !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("cancelled ctx: expected ErrUnavailable wrapping context.Canceled, got ok=%v err=%v", ok, err)
	}

	// 4. Non-exit-1 failure from git (e.g., exit 128 on merge-base) returns an error instead of (false, nil).
	realGit, lookErr := exec.LookPath("git")
	if lookErr != nil {
		t.Fatalf("LookPath(git): %v", lookErr)
	}
	wrapper := filepath.Join(t.TempDir(), "git-fail-merge-base")
	script := "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"merge-base\" ]; then\n    echo \"fatal: simulated corruption\" >&2\n    exit 128\n  fi\ndone\nexec \"" + realGit + "\" \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	failClient := NewLocalBareClient(WithBareRootDir(root), WithGitBinary(wrapper))
	ok, err = failClient.IsAncestor(context.Background(), repo, sha1, "main")
	if ok || err == nil {
		t.Fatalf("non-exit-1 merge-base error: expected (false, err), got (%v, %v)", ok, err)
	}
}

func TestLocalBareClientResolveBranchSHAAndIsAncestorErrorPropagation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, sha1, _ := setupTestBareRepo(t, root, "acme", "svc")
	repo := domain.Repository{
		ID:                 domain.MustNewID(),
		GitHubRepositoryID: 101,
		FullName:           "acme/svc",
		Enabled:            true,
	}

	realGit, lookErr := exec.LookPath("git")
	if lookErr != nil {
		t.Fatalf("LookPath(git): %v", lookErr)
	}

	// 1. Mid-flight context deadline exceeded during rev-parse must return ErrUnavailable (not ErrNotFound).
	slowWrapper := filepath.Join(t.TempDir(), "git-slow-rev-parse")
	slowScript := "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"rev-parse\" ]; then\n    sleep 0.3\n    break\n  fi\ndone\nexec \"" + realGit + "\" \"$@\"\n"
	if err := os.WriteFile(slowWrapper, []byte(slowScript), 0o700); err != nil {
		t.Fatal(err)
	}
	slowClient := NewLocalBareClient(WithBareRootDir(root), WithGitBinary(slowWrapper))

	ctx1, cancel1 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel1()
	if _, err := slowClient.ResolveBranchSHA(ctx1, repo, "main"); !errors.Is(err, domain.ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveBranchSHA mid-flight timeout: expected ErrUnavailable wrapping DeadlineExceeded, got %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if ok, err := slowClient.IsAncestor(ctx2, repo, sha1, "main"); ok || !errors.Is(err, domain.ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("IsAncestor mid-flight timeout: expected (false, ErrUnavailable/DeadlineExceeded), got ok=%v err=%v", ok, err)
	}

	// 2. Unexpected exit 128 corruption error on rev-parse must return ErrInternal (not ErrNotFound).
	corruptWrapper := filepath.Join(t.TempDir(), "git-corrupt-rev-parse")
	corruptScript := "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = \"rev-parse\" ]; then\n    echo \"fatal: simulated repository corruption\" >&2\n    exit 128\n  fi\ndone\nexec \"" + realGit + "\" \"$@\"\n"
	if err := os.WriteFile(corruptWrapper, []byte(corruptScript), 0o700); err != nil {
		t.Fatal(err)
	}
	corruptClient := NewLocalBareClient(WithBareRootDir(root), WithGitBinary(corruptWrapper))
	if _, err := corruptClient.ResolveBranchSHA(context.Background(), repo, "main"); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("corrupt rev-parse: expected ErrInternal, got %v", err)
	}

	// 3. Missing git binary must return ErrInternal (not ErrNotFound).
	missingBinClient := NewLocalBareClient(WithBareRootDir(root), WithGitBinary(filepath.Join(t.TempDir(), "nonexistent-git")))
	if _, err := missingBinClient.ResolveBranchSHA(context.Background(), repo, "main"); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("missing git binary: expected ErrInternal, got %v", err)
	}

	// 4. Genuine missing branch still returns ErrNotFound.
	normalClient := NewLocalBareClient(WithBareRootDir(root))
	if _, err := normalClient.ResolveBranchSHA(context.Background(), repo, "does-not-exist"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing branch: expected ErrNotFound, got %v", err)
	}

	// 5. Invalid branch refs (including refs/heads/-evil, .hidden, foo.lock/bar) fail fast with ErrBadRequest.
	for _, bad := range []string{"refs/heads/-evil", "refs/heads/.hidden", "refs/heads/foo.lock/bar", "foo.lock/bar", ".hidden"} {
		if _, err := normalClient.ResolveBranchSHA(context.Background(), repo, bad); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("ResolveBranchSHA(%q): expected ErrBadRequest, got %v", bad, err)
		}
		if ok, err := normalClient.IsAncestor(context.Background(), repo, sha1, bad); ok || !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("IsAncestor(%q): expected (false, ErrBadRequest), got ok=%v err=%v", bad, ok, err)
		}
		if _, err := normalClient.CreateOrUpdatePullRequest(context.Background(), PullRequestParams{
			Repository: repo,
			HeadBranch: "custodian/prop-1",
			BaseBranch: bad,
			Title:      "Test",
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("CreateOrUpdatePullRequest(BaseBranch=%q): expected ErrBadRequest, got %v", bad, err)
		}
	}
}
