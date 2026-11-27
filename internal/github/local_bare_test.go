package github

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func runGitLocalBareTest(t *testing.T, dir string, args ...string) string {
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

func TestLocalBareGitReaderResolveAndCheckout(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bareDir := filepath.Join(tmp, "acme", "service.git")
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", bareDir).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v\n%s", err, out)
	}
	runGitLocalBareTest(t, bareDir, "config", "uploadpack.allowReachableSHA1InWant", "true")

	seed := filepath.Join(tmp, "seed")
	if out, err := exec.Command("git", "init", "--initial-branch=main", seed).CombinedOutput(); err != nil {
		t.Fatalf("init seed: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(seed, "app.go"), []byte("package main // v1\n"), 0o644)
	runGitLocalBareTest(t, seed, "add", "app.go")
	runGitLocalBareTest(t, seed, "commit", "-m", "v1")
	sha1 := runGitLocalBareTest(t, seed, "rev-parse", "HEAD")

	_ = os.WriteFile(filepath.Join(seed, "app.go"), []byte("package main // v2\n"), 0o644)
	runGitLocalBareTest(t, seed, "add", "app.go")
	runGitLocalBareTest(t, seed, "commit", "-m", "v2")
	sha2 := runGitLocalBareTest(t, seed, "rev-parse", "HEAD")

	runGitLocalBareTest(t, seed, "tag", "v1.0", sha1)
	runGitLocalBareTest(t, seed, "tag", "-a", "v2.0", "-m", "release v2", sha2)
	runGitLocalBareTest(t, seed, "push", bareDir, "main", "refs/tags/v1.0", "refs/tags/v2.0")

	reader := NewLocalBareGitReader(WithBareRootDir(tmp))
	repo := domain.Repository{
		ID:                 domain.MustNewID(),
		GitHubRepositoryID: 101,
		FullName:           "acme/service",
		Classification:     domain.ClassificationInternal,
		Enabled:            true,
	}
	ctx := context.Background()

	if got, err := reader.ResolveRef(ctx, repo, "main"); err != nil || got != sha2 {
		t.Fatalf("ResolveRef(main): got %q err=%v", got, err)
	}
	if got, err := reader.ResolveRef(ctx, repo, "v1.0"); err != nil || got != sha1 {
		t.Fatalf("ResolveRef(v1.0): got %q err=%v", got, err)
	}
	if got, err := reader.ResolveRef(ctx, repo, "refs/tags/v2.0"); err != nil || got != sha2 {
		t.Fatalf("ResolveRef(annotated v2.0): got %q err=%v", got, err)
	}
	if got, err := reader.ResolveRef(ctx, repo, sha1); err != nil || got != sha1 {
		t.Fatalf("ResolveRef(sha1): got %q err=%v", got, err)
	}
	if _, err := reader.ResolveRef(ctx, repo, "nonexistent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for nonexistent ref, got %v", err)
	}

	disabled := repo
	disabled.Enabled = false
	if _, err := reader.ResolveRef(ctx, disabled, "main"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo, got %v", err)
	}

	// Checkout non-tip sha1 cleanly without .git
	res, err := reader.Checkout(ctx, repo, sha1, domain.CheckoutOptions{
		IncludeGitMetadata: false,
		IncludeHistory:     false,
	})
	if err != nil {
		t.Fatalf("Checkout(sha1): %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(res.WorkDir) })
	content, err := os.ReadFile(filepath.Join(res.WorkDir, "app.go"))
	if err != nil || string(content) != "package main // v1\n" {
		t.Fatalf("unexpected checked out content: %q err=%v", content, err)
	}
}

func TestLocalBareGitReaderPathTraversalAndNonCommitRef(t *testing.T) {
	t.Parallel()
	outer := t.TempDir()
	bareRoot := filepath.Join(outer, "repos")
	if err := os.MkdirAll(bareRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a bare repo outside bareRoot at outer/secret.git that "../secret" would reach if unguarded.
	secretBare := filepath.Join(outer, "secret.git")
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", secretBare).CombinedOutput(); err != nil {
		t.Fatalf("init secret bare: %v\n%s", err, out)
	}
	seed := filepath.Join(outer, "seed")
	if out, err := exec.Command("git", "init", "--initial-branch=main", seed).CombinedOutput(); err != nil {
		t.Fatalf("init seed: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(seed, "secret.txt"), []byte("top-secret\n"), 0o644)
	runGitLocalBareTest(t, seed, "add", "secret.txt")
	runGitLocalBareTest(t, seed, "commit", "-m", "secret")
	runGitLocalBareTest(t, seed, "push", secretBare, "main")

	// Also create a valid repo inside bareRoot with a tag pointing to a tree object.
	legitBare := filepath.Join(bareRoot, "acme", "demo.git")
	if err := os.MkdirAll(filepath.Dir(legitBare), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", legitBare).CombinedOutput(); err != nil {
		t.Fatalf("init legit bare: %v\n%s", err, out)
	}
	runGitLocalBareTest(t, seed, "push", legitBare, "main")
	treeSHA := runGitLocalBareTest(t, legitBare, "rev-parse", "main^{tree}")
	runGitLocalBareTest(t, legitBare, "update-ref", "refs/tags/tree-tag", treeSHA)

	// Symlink inside bareRoot pointing to secretBare outside bareRoot.
	if err := os.MkdirAll(filepath.Join(bareRoot, "symowner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretBare, filepath.Join(bareRoot, "symowner", "escaped.git")); err != nil {
		t.Fatal(err)
	}

	reader := NewLocalBareGitReader(WithBareRootDir(bareRoot))
	ctx := context.Background()

	// Path traversal and invalid segments must fail with ErrBadRequest.
	for _, badFullName := range []string{
		"../secret",
		"./repo",
		"owner/..",
		"owner/.",
		"-evil/repo",
		"owner/-evil",
		"owner/bad name",
		"symowner/escaped",
	} {
		repo := domain.Repository{
			ID:       domain.MustNewID(),
			FullName: badFullName,
			Enabled:  true,
		}
		if _, err := reader.ResolveRef(ctx, repo, "main"); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("ResolveRef(%q) expected ErrBadRequest, got %v", badFullName, err)
		}
		if err := reader.RegisterRepo(1, badFullName, legitBare); badFullName != "symowner/escaped" && !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("RegisterRepo(%q) expected ErrBadRequest, got %v", badFullName, err)
		}
	}

	// Non-commit ref (tree tag) must fail with 422 ErrUnprocessable (matching ReadOnlyClient).
	legitRepo := domain.Repository{
		ID:       domain.MustNewID(),
		FullName: "acme/demo",
		Enabled:  true,
	}
	for _, treeRef := range []string{"refs/tags/tree-tag", "tree-tag", treeSHA} {
		if _, err := reader.ResolveRef(ctx, legitRepo, treeRef); !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("ResolveRef(%q) expected ErrUnprocessable for tree object, got %v", treeRef, err)
		}
	}
}
