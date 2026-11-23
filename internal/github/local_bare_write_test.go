package github

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestLocalBareGitReaderWriteExtensions(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bareDir := filepath.Join(tmp, "acme", "ext.git")
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", bareDir).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}

	seed := filepath.Join(tmp, "seed")
	if out, err := exec.Command("git", "init", "--initial-branch=main", seed).CombinedOutput(); err != nil {
		t.Fatalf("init seed: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(seed, "app.go"), []byte("package main\n"), 0o644)
	runGitLocalBareTest(t, seed, "add", "app.go")
	runGitLocalBareTest(t, seed, "commit", "-m", "v1")
	sha1 := runGitLocalBareTest(t, seed, "rev-parse", "HEAD")
	runGitLocalBareTest(t, seed, "push", bareDir, "main")
	runGitLocalBareTest(t, bareDir, "update-ref", "refs/heads/custodian/prop-ext", sha1)

	reader := NewLocalBareGitReader(WithBareRootDir(tmp))
	repo := domain.Repository{
		ID:                 domain.MustNewID(),
		GitHubRepositoryID: 888,
		FullName:           "acme/ext",
		Enabled:            true,
	}
	ctx := context.Background()

	access, err := reader.PreparePushAccess(ctx, repo)
	if err != nil || access.RemoteURL != "file://"+bareDir || !access.AllowLocalBare {
		t.Fatalf("PreparePushAccess: %+v err=%v", access, err)
	}
	gotSHA, err := reader.ResolveBranchSHA(ctx, repo, "main")
	if err != nil || gotSHA != sha1 {
		t.Fatalf("ResolveBranchSHA: %q err=%v", gotSHA, err)
	}
	anc, err := reader.IsAncestor(ctx, repo, sha1, "main")
	if err != nil || !anc {
		t.Fatalf("IsAncestor: %v err=%v", anc, err)
	}

	pr, err := reader.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-ext",
		BaseBranch: "main",
		Title:      "Extension PR",
		Body:       "Via LocalBareGitReader",
	})
	if err != nil || pr.Number != 1 {
		t.Fatalf("CreateOrUpdatePullRequest: %+v err=%v", pr, err)
	}
	if len(reader.PullRequests("acme/ext")) != 1 {
		t.Fatalf("expected 1 PR on LocalBareGitReader")
	}
}
