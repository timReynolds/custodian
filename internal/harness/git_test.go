package harness

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
)

func TestBareGitHarnessAndIngressPipeline(t *testing.T) {
	t.Parallel()
	gh := NewBareGitHarness(t, "")
	repoInfo, err := gh.InitBareRepo("custodian", "demo",
		WithDefaultBranch("main"),
		WithGitHubRepoID(9001),
		WithInstallationID(77),
		WithInitialFiles(map[string]string{
			"README.md":  "# Demo\n",
			"pkg/app.go": "package pkg\n",
		}),
	)
	if err != nil {
		t.Fatalf("InitBareRepo: %v", err)
	}
	if !domain.IsValidGitSHA(repoInfo.HeadSHA) {
		t.Fatalf("invalid initial HeadSHA: %q", repoInfo.HeadSHA)
	}

	sha2, err := gh.CommitFile("custodian/demo", "main", "pkg/app.go", "package pkg // v2\n", "second commit")
	if err != nil {
		t.Fatalf("CommitFile: %v", err)
	}
	if head, err := gh.GetHeadSHA("custodian/demo"); err != nil || head != sha2 {
		t.Fatalf("GetHeadSHA: got %q err=%v", head, err)
	}

	if err := gh.CreateBranch("custodian/demo", "feature", "main"); err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
	if err := gh.CreateTag("custodian/demo", "v1.0.0", repoInfo.HeadSHA); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}
	if err := gh.CreateAnnotatedTag("custodian/demo", "v2.0.0", sha2, "release v2", GitIdentity{Name: "Rel", Email: "rel@custodian.local"}); err != nil {
		t.Fatalf("CreateAnnotatedTag: %v", err)
	}

	domRepo, err := gh.DomainRepo("custodian/demo", domain.ClassificationConfidential)
	if err != nil {
		t.Fatalf("DomainRepo: %v", err)
	}

	reader := gh.LocalReader()
	ctx := context.Background()

	if got, err := reader.ResolveRef(ctx, domRepo, "feature"); err != nil || got != sha2 {
		t.Fatalf("ResolveRef(feature): got %q err=%v", got, err)
	}
	if got, err := reader.ResolveRef(ctx, domRepo, "v1.0.0"); err != nil || got != repoInfo.HeadSHA {
		t.Fatalf("ResolveRef(v1.0.0): got %q err=%v", got, err)
	}
	if got, err := reader.ResolveRef(ctx, domRepo, "refs/tags/v2.0.0"); err != nil || got != sha2 {
		t.Fatalf("ResolveRef(v2.0.0): got %q err=%v", got, err)
	}

	// Checkout + IngressPackager + SnapshotHarness end-to-end
	chk, err := reader.Checkout(ctx, domRepo, sha2, domain.CheckoutOptions{
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	})
	if err != nil {
		t.Fatalf("LocalReader.Checkout: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(chk.WorkDir) })

	if _, err := os.Stat(filepath.Join(chk.WorkDir, "pkg", "app.go")); err != nil {
		t.Fatalf("expected pkg/app.go in checkout: %v", err)
	}

	pkg := archive.NewIngressPackager(nil)
	pkgRes, err := pkg.Package(ctx, archive.IngressPackageRequest{
		SourceDir:          chk.WorkDir,
		RepositoryID:       &domRepo.ID,
		GitHubRepositoryID: domRepo.GitHubRepositoryID,
		RepositoryFullName: domRepo.FullName,
		CommitSHA:          chk.CommitSHA,
		TargetRef:          "refs/tags/v2.0.0",
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	})
	if err != nil {
		t.Fatalf("IngressPackager.Package: %v", err)
	}

	sh := NewSnapshotHarness(t)
	art, err := sh.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "ws/demo/source.tar.gz", pkgRes.ArchiveBytes)
	if err != nil {
		t.Fatalf("SnapshotHarness.PutBytes: %v", err)
	}
	if err := sh.Store().Verify(ctx, art); err != nil {
		t.Fatalf("SnapshotStore.Verify: %v", err)
	}

	// ForcePushBranch creates divergent history
	forcedSHA, err := gh.ForcePushBranch("custodian/demo", "feature", "README.md", "# Rewritten\n", "force rewrite")
	if err != nil {
		t.Fatalf("ForcePushBranch: %v", err)
	}
	if forcedSHA == sha2 {
		t.Fatalf("expected divergent SHA after force push")
	}
	if got, err := gh.GetRefSHA("custodian/demo", "refs/heads/feature"); err != nil || got != forcedSHA {
		t.Fatalf("GetRefSHA after force push: got %q err=%v", got, err)
	}
}
