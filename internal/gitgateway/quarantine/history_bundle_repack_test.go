package quarantine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/snapshots"
)

type cleanTestIPFingerprinter struct{}

func (cleanTestIPFingerprinter) Name() string    { return string(inspection.ScannerIPFingerprint) }
func (cleanTestIPFingerprinter) Version() string { return "1.0.0-test" }
func (cleanTestIPFingerprinter) Analyze(_ context.Context, _ inspection.Request, inv *inspection.Inventory) ([]domain.Finding, domain.ScanCoverage, error) {
	examined := 0
	var bytesExamined int64
	if inv != nil {
		examined = inv.FilesExamined
		bytesExamined = inv.BytesExamined
	}
	return nil, domain.ScanCoverage{
		FilesExamined:  examined,
		FilesSkipped:   0,
		BytesExamined:  bytesExamined,
		SkippedReasons: []string{},
		Complete:       inv == nil || (inv.FilesSkipped == 0 && len(inv.SkippedReasons) == 0),
	}, nil
}

func newCleanInspectionRunner(t *testing.T) *inspection.DefaultRunner {
	t.Helper()
	binDir := t.TempDir()
	writeStub := func(name, versionOut, jsonPayload string) string {
		jsonPath := filepath.Join(binDir, name+".json")
		if err := os.WriteFile(jsonPath, []byte(jsonPayload), 0o644); err != nil {
			t.Fatalf("write stub json %s: %v", name, err)
		}
		scriptPath := filepath.Join(binDir, name)
		script := fmt.Sprintf(`#!/bin/sh
set -eu
for arg in "$@"; do
  if [ "$arg" = "--version" ] || [ "$arg" = "version" ] || [ "$arg" = "-V" ]; then
    printf '%%s\n' %q
    exit 0
  fi
done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report-path=*|--json-pp=*|--output=*)
      OUT_FILE="${1#*=}"
      shift
      ;;
    --report-path|--json-pp|--output|-o)
      OUT_FILE="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [ -n "$OUT_FILE" ] && [ "$OUT_FILE" != "-" ]; then
  mkdir -p "$(dirname "$OUT_FILE")"
  cp %q "$OUT_FILE"
else
  cat %q
fi
`, versionOut, jsonPath, jsonPath)
		if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
			t.Fatalf("write stub script %s: %v", name, err)
		}
		return scriptPath
	}

	cfg := inspection.DefaultConfig()
	cfg.GitleaksBin = writeStub("gitleaks", "v8.18.4", "[]\n")
	cfg.ScanCodeBin = writeStub("scancode", "32.1.0", `{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}`)
	cfg.SemgrepBin = writeStub("semgrep", "1.90.0", `{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":[],"skipped":[]}}`)
	cfg.TrivyBin = writeStub("trivy", "0.58.0", `{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}`)
	cfg.IPFingerprinter = cleanTestIPFingerprinter{}
	return inspection.NewRunner(cfg)
}

func TestHistoryExtractionAndWorkspaceMaterialization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	t.Run("multi_commit_fast_forward_with_baseline_excludes_old_commits", func(t *testing.T) {
		work := initTestRepo(t, false)
		c0 := commitFile(t, work, "base.txt", "baseline\n", "base commit")
		bare := initTestRepo(t, true)
		runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")

		c1 := commitFile(t, work, "f1.go", "package f1\n", "commit 1")
		c2 := commitFile(t, work, "f2.go", "package f2\n", "commit 2")
		c3 := commitFile(t, work, "f3.go", "package f3\n", "commit 3")

		pack := buildPackFromRevs(t, work, []string{c3, "^" + c0}, true)
		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(pack),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c0, NewOID: c3}},
			BaselineRepoDir: bare,
			ExistingRefResolver: &testRefResolver{
				refs:         map[string]string{"refs/heads/main": c0},
				baselineOIDs: []string{c0},
			},
		})
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		defer res.Close()

		if len(res.Commits) != 3 {
			t.Fatalf("len(Commits) = %d, want 3 (%+v)", len(res.Commits), res.Commits)
		}
		for _, c := range res.Commits {
			if c.OID == c0 {
				t.Fatalf("baseline commit %s leaked into extracted commits", c0)
			}
		}
		if !res.NeedsPack() {
			t.Fatalf("expected NeedsPack() == true")
		}
		inv := assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
		if inv.FilesExamined < 3 {
			t.Fatalf("FilesExamined = %d, want >= 3", inv.FilesExamined)
		}
		_ = c1
		_ = c2
	})

	t.Run("branch_create_from_zero_with_baseline_excludes_baseline_history", func(t *testing.T) {
		work := initTestRepo(t, false)
		c0 := commitFile(t, work, "base.txt", "baseline\n", "base commit")
		bare := initTestRepo(t, true)
		runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")

		runTestGit(t, work, nil, nil, "checkout", "-b", "feat/new")
		c1 := commitFile(t, work, "feat.txt", "new feature\n", "feature commit")

		pack := buildPackFromRevs(t, work, []string{c1, "^" + c0}, true)
		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(pack),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/feat/new", OldOID: ZeroOID, NewOID: c1}},
			BaselineRepoDir: bare,
		})
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		defer res.Close()

		if len(res.Commits) != 1 || res.Commits[0].OID != c1 {
			t.Fatalf("Commits = %+v, want only %s", res.Commits, c1)
		}
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})

	t.Run("force_push_rewritten_commit", func(t *testing.T) {
		work := initTestRepo(t, false)
		c0 := commitFile(t, work, "base.txt", "base\n", "base")
		cOld := commitFile(t, work, "old.txt", "old branch\n", "old")
		bare := initTestRepo(t, true)
		runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")

		runTestGit(t, work, nil, nil, "reset", "--hard", c0)
		cNew := commitFile(t, work, "new.txt", "force pushed\n", "rewritten")
		pack := buildPackFromRevs(t, work, []string{cNew, "^" + c0}, true)

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID:   uuid.New(),
			PackReader:      bytes.NewReader(pack),
			RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: cOld, NewOID: cNew}},
			BaselineRepoDir: bare,
		})
		if err != nil {
			t.Fatalf("Unpack force-push: %v", err)
		}
		defer res.Close()
		if len(res.Commits) != 1 || res.Commits[0].OID != cNew {
			t.Fatalf("Commits = %+v, want only %s", res.Commits, cNew)
		}
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})

	t.Run("multi_ref_push_with_annotated_tag_and_executable_mode_normalized", func(t *testing.T) {
		work := initTestRepo(t, false)
		scriptPath := filepath.Join(work, "run.sh")
		if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
			t.Fatalf("write script: %v", err)
		}
		runTestGit(t, work, nil, nil, "add", "run.sh")
		runTestGit(t, work, nil, nil, "commit", "-m", "add executable script")
		c1 := strings.TrimSpace(runTestGit(t, work, nil, nil, "rev-parse", "HEAD"))
		c2 := commitFile(t, work, "docs.md", "hello docs\n", "second commit")
		runTestGit(t, work, nil, nil, "tag", "-a", "v1.0.0", "-m", "Release v1.0.0 tag secret=ghp_0123456789abcdef0123456789abcdef", c2)
		tagOID := strings.TrimSpace(runTestGit(t, work, nil, nil, "rev-parse", "v1.0.0"))

		pack := buildPackFromRevs(t, work, []string{c2, tagOID}, false)
		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates: []RefUpdate{
				{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c2},
				{RefName: "refs/heads/release", OldOID: ZeroOID, NewOID: c1},
				{RefName: "refs/tags/v1.0.0", OldOID: ZeroOID, NewOID: tagOID},
			},
		})
		if err != nil {
			t.Fatalf("Unpack multi-ref: %v", err)
		}
		defer res.Close()

		if len(res.Tags) != 1 || res.Tags[0].OID != tagOID {
			t.Fatalf("Tags = %+v, want %s", res.Tags, tagOID)
		}
		tagFile := filepath.Join(res.WorkspaceDir, "history", "tags", tagOID+".txt")
		tagBytes, err := os.ReadFile(tagFile)
		if err != nil {
			t.Fatalf("read tag file: %v", err)
		}
		if !strings.Contains(string(tagBytes), "Release v1.0.0") {
			t.Fatalf("tag file missing message: %q", string(tagBytes))
		}
		// assertWorkspaceSafeForInspection verifies run.sh is 0644 (not 0755).
		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
	})

	t.Run("pure_ref_deletion_empty_and_nil_pack", func(t *testing.T) {
		work := initTestRepo(t, false)
		c0 := commitFile(t, work, "base.txt", "base\n", "base")
		bare := initTestRepo(t, true)
		runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")

		for _, reader := range []io.Reader{bytes.NewReader(nil), nil} {
			res, err := unpacker.Unpack(ctx, UnpackRequest{
				PushSessionID:   uuid.New(),
				PackReader:      reader,
				RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c0, NewOID: ZeroOID}},
				BaselineRepoDir: bare,
			})
			if err != nil {
				t.Fatalf("pure deletion Unpack failed: %v", err)
			}
			if res.NeedsPack() {
				t.Fatalf("pure deletion NeedsPack() = true, want false")
			}
			if len(res.Commits) != 0 || len(res.Blobs) != 0 || len(res.Trees) != 0 {
				t.Fatalf("expected zero objects for pure deletion")
			}
			inv := assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
			if inv.FilesExamined != 0 || inv.FilesSkipped != 0 {
				t.Fatalf("expected 0 examined / 0 skipped, got %d / %d", inv.FilesExamined, inv.FilesSkipped)
			}
			if err := res.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
	})
}

func TestHistorySmugglingAndCommitMessageDetectedByInspection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	fakePAT := "ghp_" + "ABCDEF1234567890abcdef1234567890ABCD"

	t.Run("secret_added_in_commit_1_deleted_before_tip_detected", func(t *testing.T) {
		repo := initTestRepo(t, false)
		c1 := commitFile(t, repo, "secrets/leaked.env", "GITHUB_TOKEN="+fakePAT+"\n", "add secret accidentally")
		runTestGit(t, repo, nil, nil, "rm", "secrets/leaked.env")
		c2 := commitFile(t, repo, "README.md", "# Clean Readme\n", "remove secret before push")

		pack := buildPackFromRevs(t, repo, []string{c2}, false)
		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c2}},
		})
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		defer res.Close()

		_ = assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
		deletedFilePath := filepath.Join(res.WorkspaceDir, "history", "commits", c1, "files", "secrets", "leaked.env")
		if _, err := os.Stat(deletedFilePath); err != nil {
			t.Fatalf("expected deleted historical file at %s: %v", deletedFilePath, err)
		}

		// Run Stage A DefaultRunner (custom scanner + clean stubs) directly over res.WorkspaceDir to verify zero skipped files + real finding!
		pushSessID := uuid.New()
		runner := newCleanInspectionRunner(t)
		report, err := runner.Inspect(ctx, inspection.Request{
			PushSessionID:     &pushSessID,
			ArtifactID:        uuid.New(),
			TargetDir:         res.WorkspaceDir,
			Classification:    domain.ClassificationInternal,
			Stage:             inspection.StagePushEgress,
			MandatoryScanners: []string{"custom"},
		})
		if err != nil {
			t.Fatalf("runner.Inspect: %v", err)
		}
		if !report.Summary.ScanComplete || !report.AllCleanComplete() {
			t.Fatalf("expected clean complete scan run, got summary=%+v runs=%+v", report.Summary, report.ScanRuns)
		}
		if len(report.Findings) == 0 {
			t.Fatalf("expected Stage A custom scanner to detect smuggled historical secret, got 0 findings")
		}
	})

	t.Run("secret_in_commit_message_only_materialized_and_detected", func(t *testing.T) {
		repo := initTestRepo(t, false)
		c1 := commitFile(t, repo, "clean.txt", "completely clean file\n", "debug token="+fakePAT)
		pack := buildPackFromRevs(t, repo, []string{c1}, false)

		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
		})
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		defer res.Close()

		_ = assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
		pushSessID := uuid.New()
		runner := newCleanInspectionRunner(t)
		report, err := runner.Inspect(ctx, inspection.Request{
			PushSessionID:     &pushSessID,
			ArtifactID:        uuid.New(),
			TargetDir:         res.WorkspaceDir,
			Classification:    domain.ClassificationInternal,
			Stage:             inspection.StagePushEgress,
			MandatoryScanners: []string{"custom"},
		})
		if err != nil {
			t.Fatalf("runner.Inspect: %v", err)
		}
		if !report.Summary.ScanComplete || !report.AllCleanComplete() {
			t.Fatalf("expected clean complete scan run, got summary=%+v runs=%+v", report.Summary, report.ScanRuns)
		}
		foundInMsg := false
		for _, f := range report.Findings {
			if strings.HasSuffix(f.Path, "message.txt") {
				foundInMsg = true
				break
			}
		}
		if !foundInMsg {
			t.Fatalf("expected finding in commit message.txt, got %+v", report.Findings)
		}
	})
}

func TestDiffChunkingAndWorkspaceLimits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	repo := initTestRepo(t, false)
	var bigContent strings.Builder
	for i := 0; i < 60; i++ {
		bigContent.WriteString("line content padding 0123456789abcdef\n")
	}
	c1 := commitFile(t, repo, "big.txt", bigContent.String(), "big commit")
	pack := buildPackFromRevs(t, repo, []string{c1}, false)

	t.Run("diff_split_below_max_diff_bytes_per_commit", func(t *testing.T) {
		res, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
			Limits:        Limits{MaxDiffBytesPerCommit: 512},
		})
		if err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		defer res.Close()

		assertWorkspaceSafeForInspection(t, res.WorkspaceDir)
		patches, err := filepath.Glob(filepath.Join(res.WorkspaceDir, "history", "commits", c1, "diff*.patch"))
		if err != nil || len(patches) < 2 {
			t.Fatalf("expected >= 2 split diff patch files, got %v (err=%v)", patches, err)
		}
		for _, p := range patches {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			if info.Size() > 512 {
				t.Fatalf("patch %s size %d exceeds MaxDiffBytesPerCommit=512", p, info.Size())
			}
		}
	})

	t.Run("max_workspace_bytes_exceeded_fails_closed", func(t *testing.T) {
		_, err := unpacker.Unpack(ctx, UnpackRequest{
			PushSessionID: uuid.New(),
			PackReader:    bytes.NewReader(pack),
			RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1}},
			Limits:        Limits{MaxWorkspaceBytes: 256},
		})
		assertDomainErrCode(t, err, "WORKSPACE_LIMIT_EXCEEDED")
	})
}

func TestManifestDigestDeterminismMutationsAndLocalStoreBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store, err := snapshots.NewLocalStore(snapshots.LocalConfig{RootDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{SnapshotStore: store})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	repo := initTestRepo(t, false)
	c1 := commitFile(t, repo, "app.go", "package app\nconst V = 1\n", "initial app")
	runTestGit(t, repo, nil, nil, "tag", "-a", "v1", "-m", "v1", c1)
	t1 := strings.TrimSpace(runTestGit(t, repo, nil, nil, "rev-parse", "v1"))

	pack1 := buildPackFromRevs(t, repo, []string{c1, t1}, false)
	// Repack with different compression level to verify digest is invariant to pack bytes!
	cmd := exec.Command("git", "-c", "pack.compression=0", "pack-objects", "--revs", "--stdout", "-q")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(c1 + "\n" + t1 + "\n")
	pack2, err := cmd.Output()
	if err != nil {
		t.Fatalf("repack compression=0: %v", err)
	}

	lfs := []domain.PushLFSObject{{OID: strings.Repeat("d", 64), Size: 4096}}
	refs := []RefUpdate{
		{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1},
		{RefName: "refs/tags/v1", OldOID: ZeroOID, NewOID: t1},
	}

	res1, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(pack1),
		RefUpdates:    refs,
		LFSObjects:    lfs,
	})
	if err != nil {
		t.Fatalf("Unpack 1: %v", err)
	}
	defer res1.Close()

	// Second identical re-push must produce exact same PushManifestDigest and NOT collide in LocalStore!
	res2, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(pack2),
		RefUpdates:    refs,
		LFSObjects:    lfs,
	})
	if err != nil {
		t.Fatalf("Unpack 2 (identical re-push): %v", err)
	}
	defer res2.Close()

	if !domain.IsValidSHA256Hex(res1.PushManifestDigest) {
		t.Fatalf("invalid PushManifestDigest %q", res1.PushManifestDigest)
	}
	if res1.PushManifestDigest != res2.PushManifestDigest {
		t.Fatalf("re-push digest mismatch: %s vs %s", res1.PushManifestDigest, res2.PushManifestDigest)
	}
	if res1.BundleArtifact == nil || res2.BundleArtifact == nil {
		t.Fatalf("expected non-nil BundleArtifacts")
	}
	if res1.BundleArtifact.Kind != domain.ArtifactKindGitPushBundle {
		t.Fatalf("BundleArtifact.Kind = %s, want GIT_PUSH_BUNDLE", res1.BundleArtifact.Kind)
	}
	if res1.BundleArtifact.StorageKey == res2.BundleArtifact.StorageKey {
		t.Fatalf("re-push reused storage key %s", res1.BundleArtifact.StorageKey)
	}
	if err := store.Verify(ctx, *res1.BundleArtifact); err != nil {
		t.Fatalf("store.Verify(res1): %v", err)
	}
	if err := store.Verify(ctx, *res2.BundleArtifact); err != nil {
		t.Fatalf("store.Verify(res2): %v", err)
	}

	// Verify deterministic .tar.gz structure from LocalStore.Open.
	rc, err := store.Open(ctx, *res1.BundleArtifact)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer rc.Close()
	gz, err := gzip.NewReader(rc)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var tarNames []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		tarNames = append(tarNames, hdr.Name)
		if hdr.Uid != 0 || hdr.Gid != 0 || !hdr.ModTime.Equal(archive.EpochTime) {
			t.Fatalf("non-deterministic tar metadata on %s: uid=%d gid=%d mtime=%v", hdr.Name, hdr.Uid, hdr.Gid, hdr.ModTime)
		}
	}
	wantNames := []string{"push.pack", "push_manifest.json", "push_manifest.sha256"}
	if strings.Join(tarNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("tar entries = %v, want %v", tarNames, wantNames)
	}

	// Mutation tests:
	// 1) Ref name change
	resRefMut, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(pack1),
		RefUpdates: []RefUpdate{
			{RefName: "refs/heads/other", OldOID: ZeroOID, NewOID: c1},
			{RefName: "refs/tags/v1", OldOID: ZeroOID, NewOID: t1},
		},
		LFSObjects: lfs,
	})
	if err != nil {
		t.Fatalf("Unpack ref mutation: %v", err)
	}
	defer resRefMut.Close()
	if resRefMut.PushManifestDigest == res1.PushManifestDigest {
		t.Fatalf("ref name change did not mutate PushManifestDigest")
	}

	// 2) LFS change
	resLFSMut, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(pack1),
		RefUpdates:    refs,
		LFSObjects:    []domain.PushLFSObject{{OID: strings.Repeat("d", 64), Size: 4097}},
	})
	if err != nil {
		t.Fatalf("Unpack LFS mutation: %v", err)
	}
	defer resLFSMut.Close()
	if resLFSMut.PushManifestDigest == res1.PushManifestDigest {
		t.Fatalf("LFS size change did not mutate PushManifestDigest")
	}

	// 3) Commit amend (message change)
	runTestGit(t, repo, nil, nil, "commit", "--amend", "-m", "amended message")
	c1Amend := strings.TrimSpace(runTestGit(t, repo, nil, nil, "rev-parse", "HEAD"))
	packAmend := buildPackFromRevs(t, repo, []string{c1Amend}, false)
	resAmend, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(packAmend),
		RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1Amend}},
		LFSObjects:    lfs,
	})
	if err != nil {
		t.Fatalf("Unpack commit amend: %v", err)
	}
	defer resAmend.Close()
	if resAmend.PushManifestDigest == res1.PushManifestDigest {
		t.Fatalf("commit amend did not mutate PushManifestDigest")
	}

	// 4) 1-byte blob edit
	c1Byte := commitFile(t, repo, "app.go", "package app\nconst V = 2\n", "amended message")
	packByte := buildPackFromRevs(t, repo, []string{c1Byte}, false)
	resByte, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(packByte),
		RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: c1Byte}},
		LFSObjects:    lfs,
	})
	if err != nil {
		t.Fatalf("Unpack 1-byte edit: %v", err)
	}
	defer resByte.Close()
	if resByte.PushManifestDigest == resAmend.PushManifestDigest {
		t.Fatalf("1-byte blob edit did not mutate PushManifestDigest")
	}
}

func TestCleanRepackReceivePackAndCloseLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	// Nil-safe Close
	var nilRes *UnpackResult
	if err := nilRes.Close(); err != nil {
		t.Fatalf("nil UnpackResult.Close(): %v", err)
	}

	work := initTestRepo(t, false)
	c0 := commitFile(t, work, "base.txt", "base\n", "base")
	upstreamBare := initTestRepo(t, true)
	runTestGit(t, work, nil, nil, "push", upstreamBare, "main:refs/heads/main")

	c1 := commitFile(t, work, "new.go", "package main\nfunc ok() {}\n", "feature commit")
	thinPack := buildPackFromRevs(t, work, []string{c1, "^" + c0}, true)

	res, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID:   uuid.New(),
		PackReader:      bytes.NewReader(thinPack),
		RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c0, NewOID: c1}},
		BaselineRepoDir: upstreamBare,
	})
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	// Verify RepackForUpstream + git index-pack --strict on a fresh bare repo with upstream alternates.
	cleanPack, stats, err := RepackForUpstream(ctx, res, CleanPackOptions{UseOfsDelta: true})
	if err != nil {
		t.Fatalf("RepackForUpstream: %v", err)
	}
	if !stats.HasObjects || stats.BytesWritten == 0 || !bytes.HasPrefix(cleanPack, []byte("PACK")) {
		t.Fatalf("unexpected clean pack stats: %+v", stats)
	}

	// Push via real `git receive-pack --stateless-rpc` into upstreamBare!
	cmdLine := strings.Join([]string{c0, c1, "refs/heads/main"}, " ") + "\x00report-status ofs-delta\n"
	var rpcReq bytes.Buffer
	pkt := make([]byte, 4+len(cmdLine))
	copy(pkt[:4], []byte(formatPktLen(4+len(cmdLine))))
	copy(pkt[4:], cmdLine)
	rpcReq.Write(pkt)
	rpcReq.WriteString("0000")
	rpcReq.Write(cleanPack)

	rpcCmd := exec.Command("git", "receive-pack", "--stateless-rpc", upstreamBare)
	rpcCmd.Stdin = &rpcReq
	var rpcOut, rpcErr bytes.Buffer
	rpcCmd.Stdout = &rpcOut
	rpcCmd.Stderr = &rpcErr
	if err := rpcCmd.Run(); err != nil {
		t.Fatalf("git receive-pack --stateless-rpc failed: %v\nstderr=%s\nstdout=%q", err, rpcErr.String(), rpcOut.String())
	}
	if !bytes.Contains(rpcOut.Bytes(), []byte("unpack ok")) {
		t.Fatalf("receive-pack output missing 'unpack ok': %q", rpcOut.String())
	}
	gotHead := strings.TrimSpace(runTestGit(t, upstreamBare, nil, nil, "rev-parse", "refs/heads/main"))
	if gotHead != c1 {
		t.Fatalf("upstream main = %s, want %s", gotHead, c1)
	}

	// Verify index-pack --strict directly on RepackForUpstream output when standalone.
	verifyBare := initTestRepo(t, true)
	_ = os.WriteFile(filepath.Join(verifyBare, "objects", "info", "alternates"), []byte(filepath.Join(upstreamBare, "objects")+"\n"), 0o600)
	_ = binary.BigEndian.Uint32(cleanPack[4:8])
	runTestGit(t, verifyBare, nil, cleanPack, "index-pack", "--strict", "--stdin")

	wsDir := res.WorkspaceDir
	repoDir := res.RepoDir

	// Close must remove quarantine directories and be idempotent.
	if err := res.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	if err := res.Close(); err != nil {
		t.Fatalf("Close 2 (idempotent): %v", err)
	}
	if _, err := os.Stat(wsDir); !os.IsNotExist(err) {
		t.Fatalf("WorkspaceDir still exists after Close: %s", wsDir)
	}
	if _, err := os.Stat(repoDir); !os.IsNotExist(err) {
		t.Fatalf("RepoDir still exists after Close: %s", repoDir)
	}

	// BuildCleanPack after Close must fail closed.
	_, err = BuildCleanPack(ctx, res, io.Discard)
	assertDomainErrCode(t, err, "QUARANTINE_CLOSED")
}

func TestConcurrentUnpackAndCloseStress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store, err := snapshots.NewLocalStore(snapshots.LocalConfig{RootDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	unpacker, err := NewQuarantineUnpacker(UnpackerConfig{SnapshotStore: store})
	if err != nil {
		t.Fatalf("NewQuarantineUnpacker: %v", err)
	}

	// Prepare a shared baseline repo + thin pack, plus a standalone pack.
	work := initTestRepo(t, false)
	c0 := commitFile(t, work, "base.txt", strings.Repeat("base line\n", 20), "base")
	bare := initTestRepo(t, true)
	runTestGit(t, work, nil, nil, "push", bare, "main:refs/heads/main")
	c1 := commitFile(t, work, "feat.txt", strings.Repeat("base line\n", 20)+"feature\n", "feature")
	thinPack := buildPackFromRevs(t, work, []string{c1, "^" + c0}, true)

	soloWork := initTestRepo(t, false)
	cSolo := commitFile(t, soloWork, "solo.go", "package solo\nconst OK = true\n", "solo")
	soloPack := buildPackFromRevs(t, soloWork, []string{cSolo}, false)

	expectedThin, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID:   uuid.New(),
		PackReader:      bytes.NewReader(thinPack),
		RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c0, NewOID: c1}},
		BaselineRepoDir: bare,
	})
	if err != nil {
		t.Fatalf("baseline thin Unpack: %v", err)
	}
	wantThinDigest := expectedThin.PushManifestDigest
	_ = expectedThin.Close()

	expectedSolo, err := unpacker.Unpack(ctx, UnpackRequest{
		PushSessionID: uuid.New(),
		PackReader:    bytes.NewReader(soloPack),
		RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: cSolo}},
	})
	if err != nil {
		t.Fatalf("baseline solo Unpack: %v", err)
	}
	wantSoloDigest := expectedSolo.PushManifestDigest
	_ = expectedSolo.Close()

	const workers = 8
	const iters = 2
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, workers*iters)
	keysCh := make(chan string, workers*iters)

	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startCh
			for iter := 0; iter < iters; iter++ {
				useThin := (workerID+iter)%2 == 0
				var (
					req        UnpackRequest
					wantDigest string
				)
				if useThin {
					req = UnpackRequest{
						PushSessionID:   uuid.New(),
						PackReader:      bytes.NewReader(thinPack),
						RefUpdates:      []RefUpdate{{RefName: "refs/heads/main", OldOID: c0, NewOID: c1}},
						BaselineRepoDir: bare,
					}
					wantDigest = wantThinDigest
				} else {
					req = UnpackRequest{
						PushSessionID: uuid.New(),
						PackReader:    bytes.NewReader(soloPack),
						RefUpdates:    []RefUpdate{{RefName: "refs/heads/main", OldOID: ZeroOID, NewOID: cSolo}},
					}
					wantDigest = wantSoloDigest
				}

				res, uerr := unpacker.Unpack(ctx, req)
				if uerr != nil {
					errCh <- fmt.Errorf("worker %d iter %d Unpack: %w", workerID, iter, uerr)
					return
				}
				if res.PushManifestDigest != wantDigest {
					_ = res.Close()
					errCh <- fmt.Errorf("worker %d iter %d digest = %s, want %s", workerID, iter, res.PushManifestDigest, wantDigest)
					return
				}
				if res.BundleArtifact == nil {
					_ = res.Close()
					errCh <- fmt.Errorf("worker %d iter %d missing BundleArtifact", workerID, iter)
					return
				}
				if verr := store.Verify(ctx, *res.BundleArtifact); verr != nil {
					_ = res.Close()
					errCh <- fmt.Errorf("worker %d iter %d store.Verify: %w", workerID, iter, verr)
					return
				}
				if _, stats, rerr := RepackForUpstream(ctx, res, CleanPackOptions{UseOfsDelta: true}); rerr != nil || !stats.HasObjects {
					_ = res.Close()
					errCh <- fmt.Errorf("worker %d iter %d RepackForUpstream: err=%v stats=%+v", workerID, iter, rerr, stats)
					return
				}
				keysCh <- res.BundleArtifact.StorageKey
				wsDir := res.WorkspaceDir
				repoDir := res.RepoDir
				if cerr := res.Close(); cerr != nil {
					errCh <- fmt.Errorf("worker %d iter %d Close: %w", workerID, iter, cerr)
					return
				}
				if _, serr := os.Stat(wsDir); !os.IsNotExist(serr) {
					errCh <- fmt.Errorf("worker %d iter %d WorkspaceDir not removed: %s", workerID, iter, wsDir)
					return
				}
				if _, serr := os.Stat(repoDir); !os.IsNotExist(serr) {
					errCh <- fmt.Errorf("worker %d iter %d RepoDir not removed: %s", workerID, iter, repoDir)
					return
				}
			}
		}(g)
	}

	close(startCh)
	wg.Wait()
	close(errCh)
	close(keysCh)

	for uerr := range errCh {
		t.Fatal(uerr)
	}

	seenKeys := make(map[string]struct{}, workers*iters)
	for k := range keysCh {
		if _, dup := seenKeys[k]; dup {
			t.Fatalf("duplicate BundleArtifact.StorageKey under concurrent Unpack: %s", k)
		}
		seenKeys[k] = struct{}{}
	}
	if len(seenKeys) != workers*iters {
		t.Fatalf("got %d bundle keys, want %d", len(seenKeys), workers*iters)
	}
}

func formatPktLen(n int) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{
		hexChars[(n>>12)&0xf],
		hexChars[(n>>8)&0xf],
		hexChars[(n>>4)&0xf],
		hexChars[n&0xf],
	})
}
