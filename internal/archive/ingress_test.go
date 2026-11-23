package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

func readTarEntries(t *testing.T, tgz []byte) (gzip.Header, map[string]tar.Header, map[string][]byte) {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	gh := gr.Header

	tr := tar.NewReader(gr)
	headers := make(map[string]tar.Header)
	contents := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		headers[hdr.Name] = *hdr
		if hdr.Typeflag == tar.TypeReg {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read tar entry %s: %v", hdr.Name, err)
			}
			contents[hdr.Name] = b
		}
	}
	return gh, headers, contents
}

func runGitForArchiveTest(t *testing.T, dir string, args ...string) string {
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

func TestIngressPackagerDeterminismAndShallowDefault(t *testing.T) {
	t.Parallel()
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	for _, d := range []string{dir1, dir2} {
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(d, ".git", "hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\necho evil\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "main.go"), []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "sub", "run.sh"), []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Set different mtimes on dir2 files to prove determinism across timestamps.
	future := time.Now().Add(48 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir2, "main.go"), future, future)
	_ = os.Chtimes(filepath.Join(dir2, "sub", "run.sh"), future, future)

	pkg := NewIngressPackager(nil)
	sha := strings.Repeat("a", 40)
	ctx := context.Background()

	res1, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          dir1,
		CommitSHA:          sha,
		RepositoryFullName: "org/repo",
		TargetRef:          "main",
	})
	if err != nil {
		t.Fatalf("Package dir1: %v", err)
	}
	res2, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          dir2,
		CommitSHA:          sha,
		RepositoryFullName: "org/repo",
		TargetRef:          "main",
	})
	if err != nil {
		t.Fatalf("Package dir2: %v", err)
	}

	if res1.ArchiveSHA256 != res2.ArchiveSHA256 || !bytes.Equal(res1.ArchiveBytes, res2.ArchiveBytes) {
		t.Fatalf("archive output is not deterministic: %s vs %s", res1.ArchiveSHA256, res2.ArchiveSHA256)
	}
	if res1.ManifestSHA256 != res2.ManifestSHA256 || !bytes.Equal(res1.ManifestJSON, res2.ManifestJSON) {
		t.Fatalf("manifest output is not deterministic")
	}

	gh, hdrs, _ := readTarEntries(t, res1.ArchiveBytes)
	if (!gh.ModTime.IsZero() && !gh.ModTime.Equal(EpochTime)) || gh.OS != 255 || gh.Name != "" || gh.Comment != "" {
		t.Fatalf("non-deterministic gzip header: %+v", gh)
	}
	for name, h := range hdrs {
		if strings.HasPrefix(name, ".git") {
			t.Fatalf(".git entry leaked into shallow default archive: %s", name)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || !h.ModTime.Equal(EpochTime) {
			t.Fatalf("non-normalized tar header for %s: %+v", name, h)
		}
	}
	if hdrs["main.go"].Mode != 0o644 || hdrs["sub/run.sh"].Mode != 0o755 {
		t.Fatalf("unexpected file modes: main.go=%o run.sh=%o", hdrs["main.go"].Mode, hdrs["sub/run.sh"].Mode)
	}
	if res1.Manifest.FileCount != 2 {
		t.Fatalf("expected 2 files in manifest, got %d", res1.Manifest.FileCount)
	}
}

func TestIngressPackagerSanitizedGitAndHistoryGates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pkg := NewIngressPackager(nil)

	// 1. IncludeHistory: true without HistoryAuthorised -> 403 ErrForbidden
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o644)
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:         dir,
		CommitSHA:         strings.Repeat("b", 40),
		IncludeHistory:    true,
		HistoryAuthorised: false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden when IncludeHistory=true and HistoryAuthorised=false, got %v", err)
	}

	// 2. Multi-commit repo with IncludeGitMetadata=true, IncludeHistory=false -> rejected (403)
	multiRepo := t.TempDir()
	runGitForArchiveTest(t, multiRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(multiRepo, "a.txt"), []byte("1"), 0o644)
	runGitForArchiveTest(t, multiRepo, "add", "a.txt")
	runGitForArchiveTest(t, multiRepo, "commit", "-m", "c1")
	_ = os.WriteFile(filepath.Join(multiRepo, "a.txt"), []byte("2"), 0o644)
	runGitForArchiveTest(t, multiRepo, "add", "a.txt")
	runGitForArchiveTest(t, multiRepo, "commit", "-m", "c2")
	multiSHA := runGitForArchiveTest(t, multiRepo, "rev-parse", "HEAD")

	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          multiRepo,
		CommitSHA:          multiSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for unapproved multi-commit .git, got %v", err)
	}

	// With IncludeHistory: true & HistoryAuthorised: true -> allowed and .git sanitized!
	resHist, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          multiRepo,
		CommitSHA:          multiSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     true,
		HistoryAuthorised:  true,
	})
	if err != nil {
		t.Fatalf("expected authorised history packaging to succeed, got %v", err)
	}
	_, hdrsHist, contentsHist := readTarEntries(t, resHist.ArchiveBytes)
	if _, ok := hdrsHist[".git/config"]; !ok {
		t.Fatalf("expected .git/config in authorised metadata archive")
	}
	cfgStr := string(contentsHist[".git/config"])
	if strings.Contains(cfgStr, "[remote") || strings.Contains(cfgStr, "fsmonitor") || !strings.Contains(cfgStr, "symlinks = false") {
		t.Fatalf("unexpected sanitized .git/config:\n%s", cfgStr)
	}

	// 3. Single-commit shallow repo with injected malicious .git/config, hooks, logs, FETCH_HEAD, refs/remotes -> all stripped/sanitized!
	shallowRepo := t.TempDir()
	runGitForArchiveTest(t, shallowRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(shallowRepo, "app.go"), []byte("package app\n"), 0o644)
	runGitForArchiveTest(t, shallowRepo, "add", "app.go")
	runGitForArchiveTest(t, shallowRepo, "commit", "-m", "initial")
	shallowSHA := runGitForArchiveTest(t, shallowRepo, "rev-parse", "HEAD")

	// Inject hostile git artifacts into shallowRepo/.git
	_ = os.WriteFile(filepath.Join(shallowRepo, ".git", "config"), []byte("[core]\n\tfsmonitor = evil.sh\n[remote \"origin\"]\n\turl = https://x-access-token:ghs_EvilToken123456@github.com/a/b.git\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(shallowRepo, ".git", "hooks"), 0o755)
	_ = os.WriteFile(filepath.Join(shallowRepo, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\nid\n"), 0o755)
	_ = os.MkdirAll(filepath.Join(shallowRepo, ".git", "refs", "remotes", "origin"), 0o755)
	_ = os.WriteFile(filepath.Join(shallowRepo, ".git", "refs", "remotes", "origin", "main"), []byte(shallowSHA+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(shallowRepo, ".git", "FETCH_HEAD"), []byte(shallowSHA+"\thttps://x-access-token:ghs_Evil@github.com/a/b.git\n"), 0o644)

	resSan, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          shallowRepo,
		CommitSHA:          shallowSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
		ForbiddenSecrets:   []string{"ghs_EvilToken123456"},
	})
	if err != nil {
		t.Fatalf("Package sanitized shallow repo: %v", err)
	}
	_, hdrsSan, contentsSan := readTarEntries(t, resSan.ArchiveBytes)
	for name := range hdrsSan {
		if strings.HasPrefix(name, ".git/hooks") || strings.HasPrefix(name, ".git/logs") ||
			strings.HasPrefix(name, ".git/refs/remotes") || name == ".git/FETCH_HEAD" {
			t.Fatalf("hostile .git entry survived sanitization: %s", name)
		}
	}
	if bytes.Contains(resSan.ArchiveBytes, []byte("ghs_EvilToken123456")) || bytes.Contains(contentsSan[".git/config"], []byte("fsmonitor")) {
		t.Fatalf("hostile .git/config or secret survived sanitization")
	}

	// 4. Symlink and credential leak in refs/heads or TargetRef -> rejected
	symRepo := t.TempDir()
	_ = os.WriteFile(filepath.Join(symRepo, "a.txt"), []byte("hi"), 0o644)
	_ = os.Symlink("/etc/passwd", filepath.Join(symRepo, "badlink"))
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir: symRepo,
		CommitSHA: shallowSHA,
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for symlink in SourceDir, got %v", err)
	}

	cleanRepo := t.TempDir()
	_ = os.WriteFile(filepath.Join(cleanRepo, "a.txt"), []byte("hi"), 0o644)
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:        cleanRepo,
		CommitSHA:        shallowSHA,
		TargetRef:        "ghp_LeakedSecretInRef12345",
		ForbiddenSecrets: []string{"ghp_LeakedSecretInRef12345"},
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for credential leak in manifest, got %v", err)
	}
}

func TestIngressPackagerAdversarialBypassAndAllowlistRegressions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pkg := NewIngressPackager(nil)

	// 1. Nested .git (and .GIT) directories excluded under both IncludeGitMetadata=false and true.
	nestedRepo := t.TempDir()
	runGitForArchiveTest(t, nestedRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(nestedRepo, "main.go"), []byte("package main\n"), 0o644)
	runGitForArchiveTest(t, nestedRepo, "add", "main.go")
	runGitForArchiveTest(t, nestedRepo, "commit", "-m", "root")
	nestedSHA := runGitForArchiveTest(t, nestedRepo, "rev-parse", "HEAD")

	_ = os.MkdirAll(filepath.Join(nestedRepo, "sub", ".git", "hooks"), 0o755)
	_ = os.WriteFile(filepath.Join(nestedRepo, "sub", ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\nid\n"), 0o755)
	_ = os.WriteFile(filepath.Join(nestedRepo, "sub", ".git", "config"), []byte("[remote \"origin\"]\n\turl = https://x:ghs_NestedSecret12345@github.com/a/b.git\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(nestedRepo, "deep", "pkg", ".GIT"), 0o755)
	_ = os.WriteFile(filepath.Join(nestedRepo, "deep", "pkg", ".GIT", "HEAD"), []byte("ref: refs/heads/evil\n"), 0o644)

	for _, includeGit := range []bool{false, true} {
		res, err := pkg.Package(ctx, IngressPackageRequest{
			SourceDir:          nestedRepo,
			CommitSHA:          nestedSHA,
			IncludeGitMetadata: includeGit,
			IncludeHistory:     false,
		})
		if err != nil {
			t.Fatalf("Package(includeGit=%v): %v", includeGit, err)
		}
		_, hdrs, _ := readTarEntries(t, res.ArchiveBytes)
		for name := range hdrs {
			if strings.Contains(name, "sub/.git") || strings.Contains(strings.ToLower(name), "deep/pkg/.git") {
				t.Fatalf("nested .git entry leaked (includeGit=%v): %s", includeGit, name)
			}
		}
		if bytes.Contains(res.ArchiveBytes, []byte("ghs_NestedSecret12345")) {
			t.Fatalf("nested .git secret leaked (includeGit=%v)", includeGit)
		}
	}

	// 2a. Multi-commit bypass via 1-commit orphan HEAD + 2-commit CommitSHA branch -> ErrForbidden.
	orphanBypassRepo := t.TempDir()
	runGitForArchiveTest(t, orphanBypassRepo, "init", "--initial-branch=secret-branch")
	_ = os.WriteFile(filepath.Join(orphanBypassRepo, "secret.txt"), []byte("secret-v1\n"), 0o644)
	runGitForArchiveTest(t, orphanBypassRepo, "add", "secret.txt")
	runGitForArchiveTest(t, orphanBypassRepo, "commit", "-m", "c1")
	_ = os.Remove(filepath.Join(orphanBypassRepo, "secret.txt"))
	_ = os.WriteFile(filepath.Join(orphanBypassRepo, "clean.txt"), []byte("clean\n"), 0o644)
	runGitForArchiveTest(t, orphanBypassRepo, "add", "-A")
	runGitForArchiveTest(t, orphanBypassRepo, "commit", "-m", "c2")
	targetC2 := runGitForArchiveTest(t, orphanBypassRepo, "rev-parse", "HEAD")

	runGitForArchiveTest(t, orphanBypassRepo, "checkout", "--orphan", "main")
	runGitForArchiveTest(t, orphanBypassRepo, "rm", "-rf", ".")
	_ = os.WriteFile(filepath.Join(orphanBypassRepo, "clean.txt"), []byte("clean\n"), 0o644)
	runGitForArchiveTest(t, orphanBypassRepo, "add", "clean.txt")
	runGitForArchiveTest(t, orphanBypassRepo, "commit", "-m", "orphan-1")

	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          orphanBypassRepo,
		CommitSHA:          targetC2,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for orphan HEAD + 2-commit CommitSHA bypass, got %v", err)
	}

	// 2b. Multi-commit bypass via stale .git/shallow with ancestor objects still in .git/objects -> ErrForbidden.
	shallowBypassRepo := t.TempDir()
	runGitForArchiveTest(t, shallowBypassRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(shallowBypassRepo, "secret.txt"), []byte("deleted-secret\n"), 0o644)
	runGitForArchiveTest(t, shallowBypassRepo, "add", "secret.txt")
	runGitForArchiveTest(t, shallowBypassRepo, "commit", "-m", "c1")
	_ = os.Remove(filepath.Join(shallowBypassRepo, "secret.txt"))
	_ = os.WriteFile(filepath.Join(shallowBypassRepo, "ok.txt"), []byte("ok\n"), 0o644)
	runGitForArchiveTest(t, shallowBypassRepo, "add", "-A")
	runGitForArchiveTest(t, shallowBypassRepo, "commit", "-m", "c2")
	shallowTip := runGitForArchiveTest(t, shallowBypassRepo, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(shallowBypassRepo, ".git", "shallow"), []byte(shallowTip+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          shallowBypassRepo,
		CommitSHA:          shallowTip,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for stale .git/shallow with ancestor objects, got %v", err)
	}

	// 2c. Dangling amended commit object still in .git/objects -> ErrForbidden.
	amendRepo := t.TempDir()
	runGitForArchiveTest(t, amendRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(amendRepo, "secret.txt"), []byte("amended-away-secret\n"), 0o644)
	runGitForArchiveTest(t, amendRepo, "add", "secret.txt")
	runGitForArchiveTest(t, amendRepo, "commit", "-m", "initial")
	_ = os.Remove(filepath.Join(amendRepo, "secret.txt"))
	_ = os.WriteFile(filepath.Join(amendRepo, "public.txt"), []byte("public\n"), 0o644)
	runGitForArchiveTest(t, amendRepo, "add", "-A")
	runGitForArchiveTest(t, amendRepo, "commit", "--amend", "-m", "amended")
	amendedSHA := runGitForArchiveTest(t, amendRepo, "rev-parse", "HEAD")
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          amendRepo,
		CommitSHA:          amendedSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for dangling amended commit objects, got %v", err)
	}

	// 3. Strict .git allowlist strips AUTO_MERGE, custom_creds, and rejects objects/info/alternates.
	allowRepo := t.TempDir()
	runGitForArchiveTest(t, allowRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(allowRepo, "app.go"), []byte("package app\n"), 0o644)
	runGitForArchiveTest(t, allowRepo, "add", "app.go")
	runGitForArchiveTest(t, allowRepo, "commit", "-m", "clean")
	allowSHA := runGitForArchiveTest(t, allowRepo, "rev-parse", "HEAD")

	_ = os.WriteFile(filepath.Join(allowRepo, ".git", "AUTO_MERGE"), []byte("ghs_UnlistedSecretToken9999\n"), 0o644)
	_ = os.WriteFile(filepath.Join(allowRepo, ".git", "custom_creds"), []byte("https://user:ghp_AnotherSecret9999@github.com/a/b.git\n"), 0o644)

	resAllow, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          allowRepo,
		CommitSHA:          allowSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	})
	if err != nil {
		t.Fatalf("Package allowRepo: %v", err)
	}
	_, hdrsAllow, _ := readTarEntries(t, resAllow.ArchiveBytes)
	for _, banned := range []string{".git/AUTO_MERGE", ".git/custom_creds"} {
		if _, ok := hdrsAllow[banned]; ok {
			t.Fatalf("unlisted .git file %s survived strict allowlist", banned)
		}
	}

	_ = os.MkdirAll(filepath.Join(allowRepo, ".git", "objects", "info"), 0o755)
	_ = os.WriteFile(filepath.Join(allowRepo, ".git", "objects", "info", "alternates"), []byte("/etc/somewhere\n"), 0o644)
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          allowRepo,
		CommitSHA:          allowSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden when .git/objects/info/alternates exists, got %v", err)
	}
	_ = os.Remove(filepath.Join(allowRepo, ".git", "objects", "info", "alternates"))

	// 4. ForbiddenSecrets hidden inside zlib-compressed git blob object -> ErrForbidden.
	blobSecretRepo := t.TempDir()
	runGitForArchiveTest(t, blobSecretRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(blobSecretRepo, "cfg.txt"), []byte("token=custodian_super_secret_blob_12345\n"), 0o644)
	runGitForArchiveTest(t, blobSecretRepo, "add", "cfg.txt")
	runGitForArchiveTest(t, blobSecretRepo, "commit", "-m", "blob")
	blobSHA := runGitForArchiveTest(t, blobSecretRepo, "rev-parse", "HEAD")

	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          blobSecretRepo,
		CommitSHA:          blobSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
		ForbiddenSecrets:   []string{"custodian_super_secret_blob_12345"},
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for ForbiddenSecret inside compressed git blob, got %v", err)
	}

	// 5. Mid-stream MaxArchiveBytes aborts early and does not write past limit.
	bigDir := t.TempDir()
	randomish := bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!@#"), 400)
	_ = os.WriteFile(filepath.Join(bigDir, "data.bin"), randomish, 0o644)
	var outBuf bytes.Buffer
	_, err = pkg.PackageToWriter(ctx, IngressPackageRequest{
		SourceDir:       bigDir,
		CommitSHA:       allowSHA,
		MaxArchiveBytes: 64,
	}, &outBuf)
	if !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on mid-stream MaxArchiveBytes exceed, got %v", err)
	}
	if int64(outBuf.Len()) > 64 {
		t.Fatalf("expected writer to receive <= 64 bytes before abort, got %d", outBuf.Len())
	}

	// 6. Packfile verification & 1-to-1 pairing regressions.
	// 6a. Valid single-commit repacked repo (git repack -ad, paired .pack + .idx) succeeds cleanly.
	packedRepo := t.TempDir()
	runGitForArchiveTest(t, packedRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(packedRepo, "main.go"), []byte("package main\n"), 0o644)
	runGitForArchiveTest(t, packedRepo, "add", "main.go")
	runGitForArchiveTest(t, packedRepo, "commit", "-m", "packed")
	packedSHA := runGitForArchiveTest(t, packedRepo, "rev-parse", "HEAD")
	runGitForArchiveTest(t, packedRepo, "repack", "-ad")

	resPacked, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          packedRepo,
		CommitSHA:          packedSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	})
	if err != nil {
		t.Fatalf("expected valid repacked single-commit repo to succeed, got %v", err)
	}
	_, hdrsPacked, _ := readTarEntries(t, resPacked.ArchiveBytes)
	foundPack, foundIdx := false, false
	for name := range hdrsPacked {
		if strings.HasPrefix(name, ".git/objects/pack/pack-") && strings.HasSuffix(name, ".pack") {
			foundPack = true
		}
		if strings.HasPrefix(name, ".git/objects/pack/pack-") && strings.HasSuffix(name, ".idx") {
			foundIdx = true
		}
		if strings.HasSuffix(name, ".rev") {
			t.Fatalf(".rev file should not be packaged into archive: %s", name)
		}
	}
	if !foundPack || !foundIdx {
		t.Fatalf("expected paired .pack and .idx in archive, got pack=%v idx=%v", foundPack, foundIdx)
	}

	// Create a second repacked repo containing a secret to test unindexed .pack smuggling.
	secretPackedRepo := t.TempDir()
	runGitForArchiveTest(t, secretPackedRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(secretPackedRepo, "secret.txt"), []byte("custodian_smuggled_real_pack_secret_XYZ\n"), 0o644)
	runGitForArchiveTest(t, secretPackedRepo, "add", "secret.txt")
	runGitForArchiveTest(t, secretPackedRepo, "commit", "-m", "secret")
	runGitForArchiveTest(t, secretPackedRepo, "repack", "-ad")

	secretPackFiles, err := filepath.Glob(filepath.Join(secretPackedRepo, ".git", "objects", "pack", "pack-*.pack"))
	if err != nil || len(secretPackFiles) != 1 {
		t.Fatalf("expected 1 secret pack file, got %v err=%v", secretPackFiles, err)
	}
	secretIdxFiles, err := filepath.Glob(filepath.Join(secretPackedRepo, ".git", "objects", "pack", "pack-*.idx"))
	if err != nil || len(secretIdxFiles) != 1 {
		t.Fatalf("expected 1 secret idx file, got %v err=%v", secretIdxFiles, err)
	}

	// 6b. Real valid .pack copied from another repo WITHOUT .idx -> rejected with ErrForbidden.
	unindexedRepo := t.TempDir()
	runGitForArchiveTest(t, unindexedRepo, "init", "--initial-branch=main")
	_ = os.WriteFile(filepath.Join(unindexedRepo, "clean.go"), []byte("package clean\n"), 0o644)
	runGitForArchiveTest(t, unindexedRepo, "add", "clean.go")
	runGitForArchiveTest(t, unindexedRepo, "commit", "-m", "clean")
	unindexedSHA := runGitForArchiveTest(t, unindexedRepo, "rev-parse", "HEAD")

	rawSecretPack, err := os.ReadFile(secretPackFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	smuggledPackDest := filepath.Join(unindexedRepo, ".git", "objects", "pack", filepath.Base(secretPackFiles[0]))
	if err := os.WriteFile(smuggledPackDest, rawSecretPack, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          unindexedRepo,
		CommitSHA:          unindexedSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
		ForbiddenSecrets:   []string{"custodian_smuggled_real_pack_secret_XYZ"},
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for unindexed real .pack without .idx, got %v", err)
	}
	_ = os.Remove(smuggledPackDest)

	// 6c. Orphan .idx WITHOUT .pack -> rejected with ErrForbidden.
	rawSecretIdx, err := os.ReadFile(secretIdxFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	orphanIdxDest := filepath.Join(unindexedRepo, ".git", "objects", "pack", filepath.Base(secretIdxFiles[0]))
	if err := os.WriteFile(orphanIdxDest, rawSecretIdx, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          unindexedRepo,
		CommitSHA:          unindexedSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for orphan .idx without .pack, got %v", err)
	}

	// 6d. Corrupted/fake .pack paired with .idx -> rejected (verify-pack failure).
	fakePackDest := filepath.Join(unindexedRepo, ".git", "objects", "pack", filepath.Base(secretPackFiles[0]))
	if err := os.WriteFile(fakePackDest, []byte("PACK_SMUGGLED_ghs_OrphanPackSecret9999"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          unindexedRepo,
		CommitSHA:          unindexedSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
		ForbiddenSecrets:   []string{"ghs_OrphanPackSecret9999"},
	}); err == nil {
		t.Fatalf("expected error for corrupted/fake .pack paired with .idx, got nil")
	}
	_ = os.Remove(fakePackDest)
	_ = os.Remove(orphanIdxDest)

	// 6e. Unexpected auxiliary file in .git/objects/pack (e.g. .keep / .tmp / .bitmap) -> rejected.
	keepDest := filepath.Join(unindexedRepo, ".git", "objects", "pack", "pack-"+strings.Repeat("a", 40)+".keep")
	if err := os.WriteFile(keepDest, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.Package(ctx, IngressPackageRequest{
		SourceDir:          unindexedRepo,
		CommitSHA:          unindexedSHA,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for unexpected .keep file in .git/objects/pack, got %v", err)
	}
}
