package reconstruct

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/snapshots"
)

type tarSpec struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	mtime    time.Time
	uid      int
	gid      int
}

func buildTarGzFromSpecs(t testing.TB, specs []tarSpec) ([]byte, string) {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, s := range specs {
		tf := s.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := s.mode
		if mode == 0 {
			if tf == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o644
			}
		}
		mtime := s.mtime
		if mtime.IsZero() {
			mtime = archive.EpochTime
		}
		hdr := &tar.Header{
			Name:     s.name,
			Mode:     mode,
			Uid:      s.uid,
			Gid:      s.gid,
			Size:     int64(len(s.body)),
			ModTime:  mtime,
			Typeflag: tf,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", s.name, err)
		}
		if tf == tar.TypeReg && len(s.body) > 0 {
			if _, err := tw.Write(s.body); err != nil {
				t.Fatalf("Write(%q): %v", s.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gw.Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gw.Close: %v", err)
	}
	b := gzBuf.Bytes()
	return b, domain.SHA256Hex(b)
}

type memObject struct {
	artifact domain.Artifact
	data     []byte
}

type memSnapshotStore struct {
	mu           sync.Mutex
	objects      map[string]memObject
	failOnPutNum int // 1-based; 0 disables
	putCalls     int
	deletedKeys  []string
}

func newMemSnapshotStore() *memSnapshotStore {
	return &memSnapshotStore{
		objects: make(map[string]memObject),
	}
}

func (s *memSnapshotStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	if err := ctx.Err(); err != nil {
		return domain.Artifact{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putCalls++
	if s.failOnPutNum > 0 && s.putCalls == s.failOnPutNum {
		return domain.Artifact{}, domain.Unavailable("INJECTED_PUT_FAILURE", "simulated storage error")
	}
	if _, exists := s.objects[req.ObjectKey]; exists && (req.Generation == nil || *req.Generation == 0) {
		return domain.Artifact{}, domain.Conflict("OBJECT_ALREADY_EXISTS", "object already exists")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return domain.Artifact{}, err
	}
	if int64(len(data)) != size {
		return domain.Artifact{}, domain.Unprocessable("SIZE_MISMATCH", "size mismatch")
	}
	sum := domain.SHA256Hex(data)
	if req.ExpectedSHA256 != "" && sum != req.ExpectedSHA256 {
		return domain.Artifact{}, domain.Unprocessable("DIGEST_MISMATCH", "digest mismatch")
	}
	art := domain.Artifact{
		ID:                domain.MustNewID(),
		Kind:              req.Kind,
		SHA256:            sum,
		StorageKey:        req.ObjectKey,
		StorageGeneration: "1",
		SizeBytes:         int64(len(data)),
		CreatedAt:         time.Now().UTC(),
	}
	s.objects[req.ObjectKey] = memObject{artifact: art, data: data}
	return art, nil
}

func (s *memSnapshotStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[artifact.StorageKey]
	if !ok {
		return nil, domain.NotFound("OBJECT_NOT_FOUND", "missing object")
	}
	return io.NopCloser(bytes.NewReader(obj.data)), nil
}

func (s *memSnapshotStore) Verify(ctx context.Context, artifact domain.Artifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[artifact.StorageKey]
	if !ok {
		return domain.NotFound("OBJECT_NOT_FOUND", "missing object")
	}
	if domain.SHA256Hex(obj.data) != artifact.SHA256 {
		return domain.Unprocessable("DIGEST_MISMATCH", "digest mismatch")
	}
	return nil
}

func (s *memSnapshotStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, artifact.StorageKey)
	s.deletedKeys = append(s.deletedKeys, artifact.StorageKey)
	return nil
}

func (s *memSnapshotStore) putSnapshot(t testing.TB, key string, data []byte) domain.Artifact {
	t.Helper()
	sum := domain.SHA256Hex(data)
	art, err := s.Put(context.Background(), domain.PutRequest{
		Kind:           domain.ArtifactKindEgressSnapshot,
		ObjectKey:      key,
		ExpectedSHA256: sum,
		MaxBytes:       int64(len(data)),
	}, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("putSnapshot(%s): %v", key, err)
	}
	return art
}

func (s *memSnapshotStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

func (s *memSnapshotStore) getBytes(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj, ok := s.objects[key]
	if !ok {
		return nil, false
	}
	return slices.Clone(obj.data), true
}

type localBareGitReader struct {
	bareDir string
	runner  *checkout.Runner
}

func newLocalBareGitReader(t testing.TB) (*localBareGitReader, string) {
	t.Helper()
	bareDir := t.TempDir()
	runGitCmd(t, bareDir, "init", "--bare", "--initial-branch=main")
	return &localBareGitReader{
		bareDir: bareDir,
		runner:  checkout.NewRunner(checkout.RunnerConfig{}),
	}, bareDir
}

func (r *localBareGitReader) ResolveRef(ctx context.Context, repo domain.Repository, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", r.bareDir, "rev-parse", "--verify", ref)
	out, err := cmd.Output()
	if err != nil {
		return "", domain.NotFound("GIT_REF_NOT_FOUND", "ref not found")
	}
	return domain.ParseGitSHA(string(out))
}

func (r *localBareGitReader) Checkout(ctx context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error) {
	return r.runner.Checkout(ctx, checkout.Request{
		RemoteURL:          "file://" + r.bareDir,
		CommitSHA:          commitSHA,
		WorkDir:            opts.WorkDir,
		IncludeGitMetadata: opts.IncludeGitMetadata,
		IncludeHistory:     opts.IncludeHistory,
		AllowLocalBare:     true,
	})
}

func runGitCmd(t testing.TB, dir string, args ...string) string {
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

func seedCommit(t testing.TB, bareDir string, files map[string]struct {
	body []byte
	mode os.FileMode
}) string {
	t.Helper()
	work := t.TempDir()
	runGitCmd(t, work, "clone", "file://"+bareDir, ".")
	runGitCmd(t, work, "checkout", "-B", "main")
	for rel, f := range files {
		full := filepath.Join(work, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(full, f.body, mode); err != nil {
			t.Fatal(err)
		}
	}
	runGitCmd(t, work, "add", "-A")
	runGitCmd(t, work, "commit", "-m", "seed commit")
	runGitCmd(t, work, "push", "origin", "main")
	return runGitCmd(t, work, "rev-parse", "HEAD")
}

func testRepo() domain.Repository {
	return domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   1001,
		GitHubInstallationID: 2001,
		FullName:             "org/custodian-demo",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
	}
}

func TestReconstruct_GoldenCleanSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	goldenDir := filepath.Join("..", "..", "..", "test", "e2e", "fixtures", "golden")
	readmeBytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_tree", "README.md"))
	if err != nil {
		t.Fatalf("read golden README.md: %v", err)
	}
	snapBytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_snapshot.tar.gz"))
	if err != nil {
		t.Fatalf("read golden clean_snapshot.tar.gz: %v", err)
	}
	snapSHAFile, err := os.ReadFile(filepath.Join(goldenDir, "clean_snapshot.sha256"))
	if err != nil {
		t.Fatalf("read golden clean_snapshot.sha256: %v", err)
	}
	expectedPatchBytes, err := os.ReadFile(filepath.Join(goldenDir, "expected_diff_hello.patch"))
	if err != nil {
		t.Fatalf("read golden expected_diff_hello.patch: %v", err)
	}

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"README.md": {body: readmeBytes, mode: 0o644},
	})

	store := newMemSnapshotStore()
	snapArt := store.putSnapshot(t, "egress/golden.tar.gz", snapBytes)
	if snapArt.SHA256 != strings.TrimSpace(string(snapSHAFile)) {
		t.Fatalf("golden sha256 mismatch: got %s, file %s", snapArt.SHA256, strings.TrimSpace(string(snapSHAFile)))
	}

	svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	res, err := svc.ReconstructDetailed(ctx, testRepo(), baseSHA, snapArt)
	if err != nil {
		t.Fatalf("ReconstructDetailed(golden): %v", err)
	}

	// Note: expected_diff_hello.patch uses placeholder short blob hash f4f8d2b on its index line,
	// whereas git hash-object on clean_snapshot.tar.gz's pkg/hello/hello.go is 474978b.
	// Verify all diff header, mode, and hunk lines match expected_diff_hello.patch.
	expectedLines := strings.Split(strings.TrimSpace(string(expectedPatchBytes)), "\n")
	gotLines := strings.Split(strings.TrimSpace(res.UnifiedDiff), "\n")
	if len(gotLines) != len(expectedLines) {
		t.Fatalf("golden unified diff line count mismatch: got %d, want %d\nGOT:\n%s", len(gotLines), len(expectedLines), res.UnifiedDiff)
	}
	for i := range expectedLines {
		if i == 2 && strings.HasPrefix(expectedLines[i], "index 0000000..") {
			if !strings.HasPrefix(gotLines[i], "index 0000000..474978b") {
				t.Fatalf("unexpected golden index line: %q", gotLines[i])
			}
			continue
		}
		if gotLines[i] != expectedLines[i] {
			t.Fatalf("golden diff line %d mismatch: got %q, want %q", i, gotLines[i], expectedLines[i])
		}
	}
	if !domain.IsValidGitSHA(res.Change.TreeDigest) {
		t.Fatalf("invalid tree digest: %q", res.Change.TreeDigest)
	}
	if !domain.IsValidSHA256Hex(res.Change.DiffDigest) || !domain.IsValidSHA256Hex(res.Change.ManifestDigest) {
		t.Fatalf("invalid sha256 digests: diff=%q manifest=%q", res.Change.DiffDigest, res.Change.ManifestDigest)
	}
	if len(res.ChangedFiles) != 1 || res.ChangedFiles[0].Path != "pkg/hello/hello.go" || res.ChangedFiles[0].ChangeType != "ADDED" {
		t.Fatalf("unexpected changed files: %+v", res.ChangedFiles)
	}
}

func TestReconstruct_AddedModifiedDeletedRenamedAndExecutable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	renameContent := []byte("package rename\n\nfunc StableValue() string { return \"identical-content-for-rename-detection\" }\n")
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"keep.txt":       {body: []byte("unchanged\n"), mode: 0o644},
		"modify.txt":     {body: []byte("v1\n"), mode: 0o644},
		"delete.txt":     {body: []byte("gone\n"), mode: 0o644},
		"rename_old.txt": {body: renameContent, mode: 0o644},
		".gitignore":     {body: []byte("*.log\n"), mode: 0o644},
	})

	egressBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "keep.txt", mode: 0o644, body: []byte("unchanged\n")},
		{name: "modify.txt", mode: 0o644, body: []byte("v2\n")},
		{name: "rename_new.txt", mode: 0o644, body: renameContent},
		{name: ".gitignore", mode: 0o644, body: []byte("*.log\n")},
		{name: "empty.txt", mode: 0o644, body: nil},
		{name: "scripts/build.sh", mode: 0o755, body: []byte("#!/bin/sh\necho ok\n")},
		{name: "ignored_by_gitignore.log", mode: 0o644, body: []byte("must still be staged\n")},
	})

	store := newMemSnapshotStore()
	snapArt := store.putSnapshot(t, "egress/changes.tar.gz", egressBytes)
	svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.ReconstructDetailed(ctx, testRepo(), baseSHA, snapArt)
	if err != nil {
		t.Fatalf("ReconstructDetailed: %v", err)
	}

	byPath := make(map[string]ChangedFile, len(res.ChangedFiles))
	for _, cf := range res.ChangedFiles {
		byPath[cf.Path] = cf
	}

	if _, ok := byPath["keep.txt"]; ok {
		t.Fatalf("unchanged file keep.txt must not appear in ChangedFiles")
	}
	if cf, ok := byPath["modify.txt"]; !ok || cf.ChangeType != "MODIFIED" || cf.SHA256 != domain.SHA256Hex([]byte("v2\n")) {
		t.Fatalf("unexpected modify.txt entry: %+v", cf)
	}
	if cf, ok := byPath["delete.txt"]; !ok || cf.ChangeType != "DELETED" || cf.SizeBytes != 0 || cf.SHA256 != "" {
		t.Fatalf("unexpected delete.txt entry: %+v", cf)
	}
	if cf, ok := byPath["rename_new.txt"]; !ok || cf.ChangeType != "RENAMED" || cf.OldPath != "rename_old.txt" {
		t.Fatalf("unexpected rename_new.txt entry: %+v", cf)
	}
	if cf, ok := byPath["empty.txt"]; !ok || cf.ChangeType != "ADDED" || cf.SizeBytes != 0 {
		t.Fatalf("unexpected 0-byte empty.txt entry: %+v", cf)
	}
	if cf, ok := byPath["scripts/build.sh"]; !ok || cf.ChangeType != "ADDED" {
		t.Fatalf("expected scripts/build.sh ADDED, got %+v", cf)
	}
	if cf, ok := byPath["ignored_by_gitignore.log"]; !ok || cf.ChangeType != "ADDED" {
		t.Fatalf("expected .gitignore-matched egress file to be staged via -f, got %+v", cf)
	}

	// Verify executable mode 100755 was preserved in the Git diff & CANONICAL_TREE despite core.filemode=false in .git/config.
	if !strings.Contains(res.UnifiedDiff, "new file mode 100755") {
		t.Fatalf("expected unified diff to preserve new file mode 100755, got:\n%s", res.UnifiedDiff)
	}
	treeTarBytes, ok := store.getBytes(res.Change.Artifact.StorageKey)
	if !ok {
		t.Fatalf("missing CANONICAL_TREE in store")
	}
	extRes, err := archive.ValidateEgress(ctx, bytes.NewReader(treeTarBytes), archive.EgressOptions{})
	if err != nil {
		t.Fatalf("ValidateEgress(CANONICAL_TREE): %v", err)
	}
	foundExec := false
	for _, f := range extRes.Files {
		if f.Path == "scripts/build.sh" {
			foundExec = true
			if f.Mode != 0o755 {
				t.Fatalf("expected 0755 in CANONICAL_TREE, got %o", f.Mode)
			}
		}
	}
	if !foundExec {
		t.Fatalf("scripts/build.sh missing from CANONICAL_TREE")
	}
}

func TestReconstruct_InvariantToTarMtimeUIDOrderAndDotGitInjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"README.md": {body: []byte("base\n"), mode: 0o644},
	})

	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "reconstruct-test",
	})

	// Variant 1: clean deterministic order & epoch metadata.
	cleanBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "README.md", mode: 0o644, body: []byte("base\n")},
		{name: "a.go", mode: 0o644, body: []byte("package a\n")},
		{name: "bin/tool", mode: 0o755, body: []byte("#!/bin/sh\necho tool\n")},
	})

	// Variant 2: reversed order, varying mtime, uid, gid.
	future := time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
	variedBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "bin/tool", mode: 0o755, body: []byte("#!/bin/sh\necho tool\n"), mtime: future, uid: 1001, gid: 1001},
		{name: "a.go", mode: 0o644, body: []byte("package a\n"), mtime: future, uid: 500, gid: 500},
		{name: "README.md", mode: 0o644, body: []byte("base\n"), mtime: future, uid: 42, gid: 42},
	})

	// Variant 3: ADV-05 & ADV-07 hostile sandbox .git/* injection (hooks, fsmonitor, sshCommand, token, forged [user]).
	secretToken := "ghp_" + "EvilToken12345678901234567890"
	evilGitBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: ".git/", typeflag: tar.TypeDir, mode: 0o755},
		{name: ".git/hooks/pre-commit", mode: 0o755, body: []byte("#!/bin/sh\necho PWNED\nexit 1\n")},
		{name: ".git/config", mode: 0o644, body: []byte(fmt.Sprintf(
			"[user]\n\tname = Forged Author\n\temail = forged@evil.com\n[core]\n\tfsmonitor = sh -c id\n\tsshCommand = sh -c id\n[credential]\n\thelper = store\n[remote \"origin\"]\n\turl = https://x-access-token:%s@github.com/org/repo.git\n",
			secretToken,
		))},
		{name: ".git/HEAD", mode: 0o644, body: []byte("ref: refs/heads/evil\n")},
		{name: "README.md", mode: 0o644, body: []byte("base\n")},
		{name: "a.go", mode: 0o644, body: []byte("package a\n")},
		{name: "bin/tool", mode: 0o755, body: []byte("#!/bin/sh\necho tool\n")},
	})

	store := newMemSnapshotStore()
	svc, err := NewService(Config{GitReader: reader, SnapshotStore: store, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}

	repo := testRepo()
	resClean, err := svc.ReconstructDetailed(ctx, repo, baseSHA, store.putSnapshot(t, "egress/v1.tar.gz", cleanBytes))
	if err != nil {
		t.Fatalf("clean reconstruct: %v", err)
	}
	resVaried, err := svc.ReconstructDetailed(ctx, repo, baseSHA, store.putSnapshot(t, "egress/v2.tar.gz", variedBytes))
	if err != nil {
		t.Fatalf("varied reconstruct: %v", err)
	}
	resEvil, err := svc.ReconstructDetailed(ctx, repo, baseSHA, store.putSnapshot(t, "egress/v3.tar.gz", evilGitBytes))
	if err != nil {
		t.Fatalf("evil .git reconstruct: %v", err)
	}

	for name, r := range map[string]Result{"varied": resVaried, "evil_git": resEvil} {
		if r.Change.TreeDigest != resClean.Change.TreeDigest {
			t.Fatalf("%s TreeDigest mismatch: %s vs %s", name, r.Change.TreeDigest, resClean.Change.TreeDigest)
		}
		if r.Change.DiffDigest != resClean.Change.DiffDigest {
			t.Fatalf("%s DiffDigest mismatch: %s vs %s", name, r.Change.DiffDigest, resClean.Change.DiffDigest)
		}
		if r.Change.ManifestDigest != resClean.Change.ManifestDigest {
			t.Fatalf("%s ManifestDigest mismatch: %s vs %s", name, r.Change.ManifestDigest, resClean.Change.ManifestDigest)
		}
		if r.Change.Artifact.SHA256 != resClean.Change.Artifact.SHA256 {
			t.Fatalf("%s CANONICAL_TREE SHA256 mismatch: %s vs %s", name, r.Change.Artifact.SHA256, resClean.Change.Artifact.SHA256)
		}
		if r.UnifiedDiff != resClean.UnifiedDiff {
			t.Fatalf("%s UnifiedDiff mismatch", name)
		}
	}

	for _, p := range resEvil.Change.Paths {
		if strings.Contains(strings.ToLower(p), ".git") {
			t.Fatalf(".git path leaked into Paths: %s", p)
		}
	}
	manifestBytes, ok := store.getBytes(resEvil.Change.ManifestArtifact.StorageKey)
	if !ok {
		t.Fatalf("missing manifest artifact")
	}
	if bytes.Contains(manifestBytes, []byte("forged@evil.com")) || bytes.Contains(manifestBytes, []byte(secretToken)) {
		t.Fatalf("forged author or secret leaked into PUBLICATION_MANIFEST")
	}
	if strings.Contains(logBuf.String(), secretToken) || strings.Contains(logBuf.String(), "forged@evil.com") {
		t.Fatalf("secret or forged author leaked into logs: %s", logBuf.String())
	}
}

func TestReconstruct_SingleByteSensitivity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"app.go": {body: []byte("package app\n\nfunc V() int { return 1 }\n"), mode: 0o644},
	})

	snap1, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "app.go", mode: 0o644, body: []byte("package app\n\nfunc V() int { return 2 }\n")},
	})
	snap2, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "app.go", mode: 0o644, body: []byte("package app\n\nfunc V() int { return 3 }\n")},
	})

	store := newMemSnapshotStore()
	svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
	if err != nil {
		t.Fatal(err)
	}
	repo := testRepo()
	r1, err := svc.Reconstruct(ctx, repo, baseSHA, store.putSnapshot(t, "egress/1.tar.gz", snap1))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Reconstruct(ctx, repo, baseSHA, store.putSnapshot(t, "egress/2.tar.gz", snap2))
	if err != nil {
		t.Fatal(err)
	}

	if r1.TreeDigest == r2.TreeDigest {
		t.Fatalf("expected 1-byte change to mutate TreeDigest")
	}
	if r1.DiffDigest == r2.DiffDigest {
		t.Fatalf("expected 1-byte change to mutate DiffDigest")
	}
	if r1.ManifestDigest == r2.ManifestDigest {
		t.Fatalf("expected 1-byte change to mutate ManifestDigest")
	}
}

func TestReconstruct_PinnedBaseCommitNotFloatingHead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	c1 := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"base.txt": {body: []byte("base v1\n"), mode: 0o644},
	})
	_ = seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"base.txt":           {body: []byte("base v1\n"), mode: 0o644},
		"upstream_later.txt": {body: []byte("pushed after workspace creation\n"), mode: 0o644},
	})

	snapBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "base.txt", mode: 0o644, body: []byte("base v1\n")},
		{name: "feature.txt", mode: 0o644, body: []byte("agent work\n")},
	})

	store := newMemSnapshotStore()
	svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.ReconstructDetailed(ctx, testRepo(), c1, store.putSnapshot(t, "egress/pinned.tar.gz", snapBytes))
	if err != nil {
		t.Fatalf("ReconstructDetailed: %v", err)
	}
	if len(res.ChangedFiles) != 1 || res.ChangedFiles[0].Path != "feature.txt" || res.ChangedFiles[0].ChangeType != "ADDED" {
		t.Fatalf("expected ONLY feature.txt ADDED against pinned c1, got %+v", res.ChangedFiles)
	}
}

func TestReconstruct_SnapshotDigestSizeKindAndAdversarialRejections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"README.md": {body: []byte("hi\n"), mode: 0o644},
	})

	validBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "README.md", mode: 0o644, body: []byte("hi\n")},
	})

	cases := []struct {
		name      string
		mutateArt func(a domain.Artifact) domain.Artifact
		payload   []byte
	}{
		{
			name:    "sha256_mismatch",
			payload: validBytes,
			mutateArt: func(a domain.Artifact) domain.Artifact {
				a.SHA256 = strings.Repeat("0", 64)
				return a
			},
		},
		{
			name:    "size_mismatch",
			payload: validBytes,
			mutateArt: func(a domain.Artifact) domain.Artifact {
				a.SizeBytes += 10
				return a
			},
		},
		{
			name:    "wrong_kind",
			payload: validBytes,
			mutateArt: func(a domain.Artifact) domain.Artifact {
				a.Kind = domain.ArtifactKindWorkspaceSource
				return a
			},
		},
		{
			name: "adversarial_traversal",
			payload: func() []byte {
				b, _ := buildTarGzFromSpecs(t, []tarSpec{
					{name: "../../etc/passwd", mode: 0o644, body: []byte("evil")},
				})
				return b
			}(),
		},
		{
			name: "adversarial_case_collision",
			payload: func() []byte {
				b, _ := buildTarGzFromSpecs(t, []tarSpec{
					{name: "Config.yaml", mode: 0o644, body: []byte("a")},
					{name: "config.yaml", mode: 0o644, body: []byte("b")},
				})
				return b
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemSnapshotStore()
			art := store.putSnapshot(t, "egress/bad.tar.gz", tc.payload)
			if tc.mutateArt != nil {
				art = tc.mutateArt(art)
			}
			initialCount := store.count()

			svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
			if err != nil {
				t.Fatal(err)
			}
			_, err = svc.Reconstruct(ctx, testRepo(), baseSHA, art)
			if !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("%s: expected domain.ErrUnprocessable, got %v", tc.name, err)
			}
			if store.count() != initialCount {
				t.Fatalf("%s: expected zero canonical artifacts persisted on rejection, got %d new objects", tc.name, store.count()-initialCount)
			}
		})
	}
}

func TestReconstruct_RetryAndRollbackAndManifestSchema(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"README.md": {body: []byte("base\n"), mode: 0o644},
	})

	snapBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "README.md", mode: 0o644, body: []byte("updated\n")},
	})

	// 1. Retry with identical content must succeed without SnapshotStore conflict.
	store := newMemSnapshotStore()
	snapArt := store.putSnapshot(t, "egress/retry.tar.gz", snapBytes)
	svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
	if err != nil {
		t.Fatal(err)
	}
	repo := testRepo()
	c1, err := svc.Reconstruct(ctx, repo, baseSHA, snapArt)
	if err != nil {
		t.Fatalf("first Reconstruct: %v", err)
	}
	c2, err := svc.Reconstruct(ctx, repo, baseSHA, snapArt)
	if err != nil {
		t.Fatalf("retry Reconstruct: %v", err)
	}
	if c1.TreeDigest != c2.TreeDigest || c1.DiffDigest != c2.DiffDigest || c1.ManifestDigest != c2.ManifestDigest {
		t.Fatalf("retry produced non-deterministic digests")
	}
	if c1.Artifact.StorageKey == c2.Artifact.StorageKey {
		t.Fatalf("expected distinct per-run storage keys on retry")
	}

	// Verify stored PUBLICATION_MANIFEST JSON structure & content-purity.
	manifestRaw, ok := store.getBytes(c1.ManifestArtifact.StorageKey)
	if !ok {
		t.Fatalf("missing PUBLICATION_MANIFEST in store")
	}
	if domain.SHA256Hex(manifestRaw) != c1.ManifestDigest {
		t.Fatalf("manifest SHA-256 mismatch")
	}
	var decoded map[string]any
	if err := json.Unmarshal(manifestRaw, &decoded); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if decoded["tree_digest"] != c1.TreeDigest || decoded["diff_digest"] != c1.DiffDigest || decoded["base_commit"] != baseSHA {
		t.Fatalf("unexpected manifest fields: %+v", decoded)
	}
	for _, forbidden := range []string{"workspace_id", "proposal_id", "created_at", "snapshot_sha256"} {
		if _, exists := decoded[forbidden]; exists {
			t.Fatalf("manifest must not contain volatile field %q", forbidden)
		}
	}

	// 2. Partial Put failure on 3rd artifact (PUBLICATION_MANIFEST) rolls back prior 2 puts via Delete.
	failStore := newMemSnapshotStore()
	failSnap := failStore.putSnapshot(t, "egress/fail.tar.gz", snapBytes)
	failStore.failOnPutNum = 4 // 1st put was putSnapshot; 2=tree, 3=diff, 4=manifest fails!
	failSvc, err := NewService(Config{GitReader: reader, SnapshotStore: failStore})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failSvc.Reconstruct(ctx, repo, baseSHA, failSnap); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on Put failure, got %v", err)
	}
	if failStore.count() != 1 || len(failStore.deletedKeys) != 2 {
		t.Fatalf("expected 2 rolled-back artifacts and only original snapshot remaining, got count=%d deleted=%v", failStore.count(), failStore.deletedKeys)
	}
	_ = uuid.Nil
}

func computeCanonicalTreeGitSHA(t testing.TB, ctx context.Context, treeTarBytes []byte) string {
	t.Helper()
	treeDir := t.TempDir()
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(treeTarBytes), treeDir, archive.EgressOptions{}); err != nil {
		t.Fatalf("ExtractEgress(CANONICAL_TREE): %v", err)
	}
	runGitCmd(t, treeDir, "init", "--initial-branch=main")
	runGitCmd(t, treeDir, "-c", "core.precomposeUnicode=false", "-c", "core.filemode=true", "add", "-A", "-f", "--", ".")
	return runGitCmd(t, treeDir, "write-tree")
}

func TestReconstruct_CaseOnlyAndNFCtoNFDRenames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("case_only_rename", func(t *testing.T) {
		t.Parallel()
		reader, bareDir := newLocalBareGitReader(t)
		content := []byte("# Custodian Case Rename Test\n\nStable body for rename detection.\n")
		baseSHA := seedCommit(t, bareDir, map[string]struct {
			body []byte
			mode os.FileMode
		}{
			"README.md": {body: content, mode: 0o644},
		})

		egressBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
			{name: "readme.md", mode: 0o644, body: content},
		})

		store := newMemSnapshotStore()
		snapArt := store.putSnapshot(t, "egress/case-rename.tar.gz", egressBytes)
		svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
		if err != nil {
			t.Fatal(err)
		}

		res, err := svc.ReconstructDetailed(ctx, testRepo(), baseSHA, snapArt)
		if err != nil {
			t.Fatalf("ReconstructDetailed(case_only_rename): %v", err)
		}

		treeTarBytes, ok := store.getBytes(res.Change.Artifact.StorageKey)
		if !ok {
			t.Fatalf("missing CANONICAL_TREE in store")
		}
		expectedTreeSHA := computeCanonicalTreeGitSHA(t, ctx, treeTarBytes)
		if res.Change.TreeDigest != expectedTreeSHA {
			t.Fatalf("TreeDigest mismatch against CANONICAL_TREE: got %s, want %s (changed=%+v)", res.Change.TreeDigest, expectedTreeSHA, res.ChangedFiles)
		}
		if res.Change.FileCount != 1 {
			t.Fatalf("expected FileCount=1 in CANONICAL_TREE, got %d", res.Change.FileCount)
		}
		for _, cf := range res.ChangedFiles {
			if cf.Path == "README.md" && cf.ChangeType == "MODIFIED" {
				t.Fatalf("ChangedFiles must not contain stale README.md MODIFIED entry: %+v", res.ChangedFiles)
			}
		}
	})

	t.Run("nfc_to_nfd_rename", func(t *testing.T) {
		t.Parallel()
		reader, bareDir := newLocalBareGitReader(t)
		nfcPath := "docs/caf\u00e9.txt"
		nfdPath := "docs/cafe\u0301.txt"
		content := []byte("unicode normalization test content\n")
		baseSHA := seedCommit(t, bareDir, map[string]struct {
			body []byte
			mode os.FileMode
		}{
			nfcPath: {body: content, mode: 0o644},
		})

		egressBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
			{name: nfdPath, mode: 0o644, body: content},
		})

		store := newMemSnapshotStore()
		snapArt := store.putSnapshot(t, "egress/nfc-nfd-rename.tar.gz", egressBytes)
		svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
		if err != nil {
			t.Fatal(err)
		}

		res, err := svc.ReconstructDetailed(ctx, testRepo(), baseSHA, snapArt)
		if err != nil {
			t.Fatalf("ReconstructDetailed(nfc_to_nfd_rename): %v", err)
		}

		treeTarBytes, ok := store.getBytes(res.Change.Artifact.StorageKey)
		if !ok {
			t.Fatalf("missing CANONICAL_TREE in store")
		}
		expectedTreeSHA := computeCanonicalTreeGitSHA(t, ctx, treeTarBytes)
		if res.Change.TreeDigest != expectedTreeSHA {
			t.Fatalf("TreeDigest mismatch against CANONICAL_TREE: got %s, want %s (changed=%+v)", res.Change.TreeDigest, expectedTreeSHA, res.ChangedFiles)
		}
		if res.Change.FileCount != 1 {
			t.Fatalf("expected FileCount=1 in CANONICAL_TREE, got %d", res.Change.FileCount)
		}
		for _, cf := range res.ChangedFiles {
			if cf.Path == nfcPath && cf.ChangeType == "MODIFIED" {
				t.Fatalf("ChangedFiles must not contain stale NFC path %q MODIFIED entry: %+v", nfcPath, res.ChangedFiles)
			}
		}
	})
}

type cancelOnNthPutStore struct {
	inner    domain.SnapshotStore
	cancel   context.CancelFunc
	cancelAt int
	mu       sync.Mutex
	putCount int
}

func (s *cancelOnNthPutStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	s.mu.Lock()
	s.putCount++
	n := s.putCount
	s.mu.Unlock()
	if s.cancelAt > 0 && n == s.cancelAt && s.cancel != nil {
		s.cancel()
	}
	return s.inner.Put(ctx, req, r, size)
}

func (s *cancelOnNthPutStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	return s.inner.Open(ctx, artifact)
}

func (s *cancelOnNthPutStore) Verify(ctx context.Context, artifact domain.Artifact) error {
	return s.inner.Verify(ctx, artifact)
}

func (s *cancelOnNthPutStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	return s.inner.Delete(ctx, artifact)
}

func TestReconstruct_PersistArtifactsCancelledContextRollback(t *testing.T) {
	t.Parallel()

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"README.md": {body: []byte("base\n"), mode: 0o644},
	})
	snapBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "README.md", mode: 0o644, body: []byte("updated\n")},
	})

	storeDir := t.TempDir()
	localStore, err := snapshots.NewLocalStore(snapshots.LocalConfig{RootDir: storeDir})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	snapArt, err := localStore.Put(context.Background(), domain.PutRequest{
		Kind:           domain.ArtifactKindEgressSnapshot,
		ObjectKey:      "egress/rollback.tar.gz",
		ExpectedSHA256: domain.SHA256Hex(snapBytes),
		MaxBytes:       int64(len(snapBytes)),
	}, bytes.NewReader(snapBytes), int64(len(snapBytes)))
	if err != nil {
		t.Fatalf("seed LocalStore snapshot: %v", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wrappedStore := &cancelOnNthPutStore{
		inner:    localStore,
		cancel:   cancel,
		cancelAt: 3, // Cancel ctx on 3rd Put inside persistArtifacts (PUBLICATION_MANIFEST).
	}
	svc, err := NewService(Config{GitReader: reader, SnapshotStore: wrappedStore})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Reconstruct(runCtx, testRepo(), baseSHA, snapArt); err == nil {
		t.Fatalf("expected Reconstruct to fail when ctx cancelled on 3rd Put")
	}

	// Verify zero leaked reconstruct/* artifact files and only the original egress snapshot metadata remain.
	reconstructRoot := filepath.Join(storeDir, "reconstruct")
	if _, statErr := os.Stat(reconstructRoot); statErr == nil {
		var leaked []string
		if walkErr := filepath.WalkDir(reconstructRoot, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				leaked = append(leaked, path)
			}
			return nil
		}); walkErr != nil {
			t.Fatalf("WalkDir(reconstruct): %v", walkErr)
		}
		if len(leaked) > 0 {
			t.Fatalf("rollback leaked %d reconstruct/* artifacts on cancelled ctx: %v", len(leaked), leaked)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stat reconstructRoot: %v", statErr)
	}

	metaDir := filepath.Join(storeDir, ".custodian-meta", "meta")
	var metaFiles []string
	if walkErr := filepath.WalkDir(metaDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			metaFiles = append(metaFiles, path)
		}
		return nil
	}); walkErr != nil {
		t.Fatalf("WalkDir(meta): %v", walkErr)
	}
	if len(metaFiles) != 1 {
		t.Fatalf("expected only 1 metadata file (original egress snapshot), got %d: %v", len(metaFiles), metaFiles)
	}
}

type closeErrReadCloser struct {
	r          io.Reader
	closeErr   error
	closeCalls int
}

func (c *closeErrReadCloser) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *closeErrReadCloser) Close() error {
	c.closeCalls++
	return c.closeErr
}

type closeErrOpenStore struct {
	*memSnapshotStore
	closeErr   error
	lastReader *closeErrReadCloser
}

func (s *closeErrOpenStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	rc, err := s.memSnapshotStore.Open(ctx, artifact)
	if err != nil {
		return nil, err
	}
	s.lastReader = &closeErrReadCloser{r: rc, closeErr: s.closeErr}
	return s.lastReader, nil
}

func TestReconstruct_SnapshotCloseErrorPropagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	reader, bareDir := newLocalBareGitReader(t)
	baseSHA := seedCommit(t, bareDir, map[string]struct {
		body []byte
		mode os.FileMode
	}{
		"README.md": {body: []byte("base\n"), mode: 0o644},
	})
	snapBytes, _ := buildTarGzFromSpecs(t, []tarSpec{
		{name: "README.md", mode: 0o644, body: []byte("updated\n")},
	})

	baseStore := newMemSnapshotStore()
	snapArt := baseStore.putSnapshot(t, "egress/close-err.tar.gz", snapBytes)

	t.Run("normal_read_closes_once", func(t *testing.T) {
		store := &closeErrOpenStore{memSnapshotStore: baseStore}
		svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Reconstruct(ctx, testRepo(), baseSHA, snapArt); err != nil {
			t.Fatalf("unexpected Reconstruct error: %v", err)
		}
		if store.lastReader == nil || store.lastReader.closeCalls != 1 {
			t.Fatalf("expected SnapshotStore ReadCloser.Close() called exactly once, got %v", store.lastReader)
		}
	})

	t.Run("close_error_propagated_and_closed_once", func(t *testing.T) {
		store := &closeErrOpenStore{
			memSnapshotStore: baseStore,
			closeErr:         errors.New("simulated underlying I/O close failure"),
		}
		svc, err := NewService(Config{GitReader: reader, SnapshotStore: store})
		if err != nil {
			t.Fatal(err)
		}

		_, err = svc.Reconstruct(ctx, testRepo(), baseSHA, snapArt)
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("expected ErrUnprocessable on unexpected rc.Close() I/O failure, got %v", err)
		}
		if store.lastReader == nil || store.lastReader.closeCalls != 1 {
			t.Fatalf("expected SnapshotStore ReadCloser.Close() called exactly once, got %v", store.lastReader)
		}
	})
}
