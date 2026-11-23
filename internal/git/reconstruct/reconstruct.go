package reconstruct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	// ManifestSchemaVersion identifies the deterministic PUBLICATION_MANIFEST schema version.
	ManifestSchemaVersion = "1"
	// DefaultTimeout bounds git reconstruction operations.
	DefaultTimeout = 2 * time.Minute
	// DefaultMaxSnapshotBytes bounds the compressed egress snapshot downloaded from SnapshotStore.
	DefaultMaxSnapshotBytes int64 = 256 << 20
)

// Config configures a clean base reconstruction Service.
type Config struct {
	GitReader        domain.GitReader
	SnapshotStore    domain.SnapshotStore
	GitBinary        string
	Timeout          time.Duration
	MaxSnapshotBytes int64
	EgressOptions    archive.EgressOptions
	Logger           *slog.Logger
}

// ChangedFile describes one canonical working-tree diff entry relative to base_commit.
type ChangedFile struct {
	Path       string `json:"path"`
	ChangeType string `json:"change_type"` // "ADDED" | "MODIFIED" | "DELETED" | "RENAMED"
	OldPath    string `json:"old_path,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256,omitempty"`
}

// PublicationManifest is the content-pure deterministic manifest hashed for human approval.
// It intentionally excludes volatile workspace/proposal/run IDs and timestamps.
type PublicationManifest struct {
	SchemaVersion       string        `json:"schema_version"`
	BaseCommit          string        `json:"base_commit"`
	TreeDigest          string        `json:"tree_digest"`
	CanonicalTreeSHA256 string        `json:"canonical_tree_sha256"`
	DiffDigest          string        `json:"diff_digest"`
	FileCount           int           `json:"file_count"`
	TotalBytes          int64         `json:"total_bytes"`
	Changes             []ChangedFile `json:"changes"`
}

// Result holds the full reconstruction output including canonical artifacts, diff, and manifest.
type Result struct {
	Change       domain.CanonicalChange
	ChangedFiles []ChangedFile
	UnifiedDiff  string
	Manifest     PublicationManifest
}

// Service implements domain.Reconstructor over injected GitReader and SnapshotStore ports.
type Service struct {
	gitReader        domain.GitReader
	snapshotStore    domain.SnapshotStore
	gitBin           string
	timeout          time.Duration
	maxSnapshotBytes int64
	egressOpts       archive.EgressOptions
	logger           *slog.Logger
}

var _ domain.Reconstructor = (*Service)(nil)

// NewService constructs a clean base reconstruction Service.
func NewService(cfg Config) (*Service, error) {
	if cfg.GitReader == nil {
		return nil, domain.Internal("MISSING_GIT_READER", "GitReader dependency is required")
	}
	if cfg.SnapshotStore == nil {
		return nil, domain.Internal("MISSING_SNAPSHOT_STORE", "SnapshotStore dependency is required")
	}
	gitBin := strings.TrimSpace(cfg.GitBinary)
	if gitBin == "" {
		gitBin = "git"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxSnap := cfg.MaxSnapshotBytes
	if maxSnap <= 0 {
		maxSnap = DefaultMaxSnapshotBytes
	}
	return &Service{
		gitReader:        cfg.GitReader,
		snapshotStore:    cfg.SnapshotStore,
		gitBin:           gitBin,
		timeout:          timeout,
		maxSnapshotBytes: maxSnap,
		egressOpts:       cfg.EgressOptions,
		logger:           cfg.Logger,
	}, nil
}

// Reconstruct applies a verified egress snapshot onto a clean checkout of baseCommit.
func (s *Service) Reconstruct(ctx context.Context, repo domain.Repository, baseCommit string, snapshot domain.Artifact) (domain.CanonicalChange, error) {
	res, err := s.ReconstructDetailed(ctx, repo, baseCommit, snapshot)
	if err != nil {
		return domain.CanonicalChange{}, err
	}
	return res.Change, nil
}

// ReconstructDetailed verifies snapshot integrity, overlays validated egress files onto a clean
// pinned base checkout, computes canonical tree/diff/manifest digests, and stores the 3 artifacts.
func (s *Service) ReconstructDetailed(ctx context.Context, repo domain.Repository, baseCommit string, snapshot domain.Artifact) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, domain.WrapError(domain.ErrUnavailable, "RECONSTRUCT_ABORTED", "reconstruction aborted", err)
	}
	if !repo.Enabled {
		return Result{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}

	baseSHA, err := domain.ParseGitSHA(baseCommit)
	if err != nil {
		return Result{}, err
	}

	if snapshot.Kind != domain.ArtifactKindEgressSnapshot {
		return Result{}, domain.Unprocessable("INVALID_SNAPSHOT_KIND", "snapshot artifact must have kind EGRESS_SNAPSHOT")
	}
	if strings.TrimSpace(snapshot.StorageKey) == "" {
		return Result{}, domain.Unprocessable("INVALID_SNAPSHOT_KEY", "snapshot storage_key must not be empty")
	}
	if snapshot.SizeBytes <= 0 {
		return Result{}, domain.Unprocessable("INVALID_SNAPSHOT_SIZE", "snapshot size_bytes must be positive")
	}
	if snapshot.SizeBytes > s.maxSnapshotBytes {
		return Result{}, domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "snapshot exceeds maximum allowed byte size")
	}

	expectedSnapSHA, err := domain.ParseSHA256Digest(snapshot.SHA256)
	if err != nil {
		return Result{}, domain.WrapError(domain.ErrUnprocessable, "INVALID_SNAPSHOT_DIGEST", "snapshot sha256 digest is invalid", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// 1. Download and pre-verify EGRESS_SNAPSHOT SHA-256 and exact byte size BEFORE archive parsing.
	tmpDir, err := os.MkdirTemp("", "custodian-reconstruct-*")
	if err != nil {
		return Result{}, domain.WrapError(domain.ErrInternal, "RECONSTRUCT_TMP_FAILED", "failed creating reconstruction staging directory", err)
	}
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		_ = os.RemoveAll(tmpDir)
		return Result{}, domain.WrapError(domain.ErrInternal, "RECONSTRUCT_TMP_FAILED", "failed securing reconstruction staging directory", err)
	}
	defer os.RemoveAll(tmpDir)

	snapPath := filepath.Join(tmpDir, "egress.tar.gz")
	if err := s.downloadAndVerifySnapshot(runCtx, snapshot, expectedSnapSHA, snapPath); err != nil {
		return Result{}, err
	}

	// 2. Perform clean pinned checkout at baseCommit with sanitized .git metadata.
	chk, err := s.gitReader.Checkout(runCtx, repo, baseSHA, domain.CheckoutOptions{
		IncludeGitMetadata: true,
		IncludeHistory:     false,
	})
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(chk.WorkDir) == "" {
		return Result{}, domain.Internal("CHECKOUT_DIR_MISSING", "checkout did not return a working directory")
	}
	defer os.RemoveAll(chk.WorkDir)

	if !strings.EqualFold(strings.TrimSpace(chk.CommitSHA), baseSHA) {
		return Result{}, domain.Internal("CHECKOUT_SHA_MISMATCH", "checked-out commit SHA does not match pinned base_commit")
	}

	if err := validateCheckoutWorkDir(chk.WorkDir); err != nil {
		return Result{}, err
	}

	// 3. Wipe all non-.git working tree entries while preserving sanitized .git metadata.
	if err := wipeWorkingTreePreservingGit(chk.WorkDir); err != nil {
		return Result{}, err
	}

	// 4. Extract validated egress archive into chk.WorkDir (top-level .git/* ignored).
	snapFile, err := os.Open(snapPath)
	if err != nil {
		return Result{}, domain.WrapError(domain.ErrInternal, "SNAPSHOT_OPEN_FAILED", "failed opening verified egress snapshot", err)
	}
	_, extractErr := archive.ExtractEgress(runCtx, snapFile, chk.WorkDir, s.egressOpts)
	_ = snapFile.Close()
	if extractErr != nil {
		return Result{}, extractErr
	}

	// 5. Stage egress tree (overriding core.filemode=true and -f) and compute canonical tree + diff.
	diffRes, err := stageAndDiff(runCtx, s.gitBin, chk.WorkDir, baseSHA)
	if err != nil {
		return Result{}, err
	}

	// 6. Package canonical working tree (excluding .git) into deterministic .tar.gz.
	packager := archive.NewIngressPackager(s.logger)
	pkgRes, err := packager.Package(runCtx, archive.IngressPackageRequest{
		SourceDir:          chk.WorkDir,
		CommitSHA:          baseSHA,
		IncludeGitMetadata: false,
		IncludeHistory:     false,
	})
	if err != nil {
		return Result{}, err
	}

	// 7. Build content-pure PUBLICATION_MANIFEST JSON and digest.
	manifest := PublicationManifest{
		SchemaVersion:       ManifestSchemaVersion,
		BaseCommit:          baseSHA,
		TreeDigest:          diffRes.TreeDigest,
		CanonicalTreeSHA256: pkgRes.ArchiveSHA256,
		DiffDigest:          diffRes.DiffDigest,
		FileCount:           pkgRes.Manifest.FileCount,
		TotalBytes:          pkgRes.Manifest.TotalBytes,
		Changes:             diffRes.ChangedFiles,
	}
	manifestJSON, err := domain.CanonicalJSONBytes(manifest)
	if err != nil {
		return Result{}, err
	}
	manifestDigest := domain.SHA256Hex(manifestJSON)

	// 8. Persist CANONICAL_TREE, CANONICAL_DIFF, and PUBLICATION_MANIFEST under unique per-run keys.
	treeArt, diffArt, manifestArt, err := s.persistArtifacts(runCtx, pkgRes.ArchiveBytes, pkgRes.ArchiveSHA256, []byte(diffRes.UnifiedDiff), diffRes.DiffDigest, manifestJSON, manifestDigest)
	if err != nil {
		return Result{}, err
	}

	paths := make([]string, len(diffRes.ChangedFiles))
	for i, cf := range diffRes.ChangedFiles {
		paths[i] = cf.Path
	}

	if s.logger != nil {
		log := observability.LoggerWithTrace(runCtx, s.logger)
		log.Info("base reconstruction completed",
			"repository_id", repo.ID.String(),
			"artifact_id", treeArt.ID.String(),
			"commit_sha", baseSHA,
			"tree_digest", diffRes.TreeDigest,
			"diff_digest", diffRes.DiffDigest,
			"manifest_digest", manifestDigest,
			"size_bytes", pkgRes.ArchiveSizeBytes,
			"status", "ok",
		)
	}

	return Result{
		Change: domain.CanonicalChange{
			Artifact:         treeArt,
			DiffArtifact:     &diffArt,
			ManifestArtifact: &manifestArt,
			TreeDigest:       diffRes.TreeDigest,
			DiffDigest:       diffRes.DiffDigest,
			ManifestDigest:   manifestDigest,
			Paths:            paths,
			FileCount:        pkgRes.Manifest.FileCount,
			TotalBytes:       pkgRes.Manifest.TotalBytes,
		},
		ChangedFiles: diffRes.ChangedFiles,
		UnifiedDiff:  diffRes.UnifiedDiff,
		Manifest:     manifest,
	}, nil
}

func (s *Service) downloadAndVerifySnapshot(ctx context.Context, snapshot domain.Artifact, expectedSHA, destPath string) error {
	rc, err := s.snapshotStore.Open(ctx, snapshot)
	if err != nil {
		return err
	}
	rcClosed := false
	defer func() {
		if !rcClosed {
			_ = rc.Close()
		}
	}()

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "RECONSTRUCT_TMP_FAILED", "failed creating snapshot staging file", err)
	}

	hasher := sha256.New()
	limited := io.LimitReader(rc, s.maxSnapshotBytes+1)
	written, copyErr := io.Copy(io.MultiWriter(f, hasher), limited)
	closeFileErr := f.Close()
	rcClosed = true
	closeRCErr := rc.Close()

	if copyErr != nil {
		var domErr *domain.DomainError
		if errors.As(copyErr, &domErr) {
			return domErr
		}
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return domain.WrapError(domain.ErrUnavailable, "SNAPSHOT_DOWNLOAD_ABORTED", "snapshot download aborted", copyErr)
		}
		return domain.WrapError(domain.ErrUnprocessable, "SNAPSHOT_READ_FAILED", "failed reading egress snapshot stream", copyErr)
	}
	if closeFileErr != nil {
		return domain.WrapError(domain.ErrInternal, "RECONSTRUCT_TMP_FAILED", "failed flushing snapshot staging file", closeFileErr)
	}
	if closeRCErr != nil {
		var domErr *domain.DomainError
		if errors.As(closeRCErr, &domErr) {
			return domErr
		}
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
			errors.Is(closeRCErr, context.Canceled) || errors.Is(closeRCErr, context.DeadlineExceeded) {
			return domain.WrapError(domain.ErrUnavailable, "SNAPSHOT_DOWNLOAD_ABORTED", "snapshot download aborted", closeRCErr)
		}
		return domain.WrapError(domain.ErrUnprocessable, "SNAPSHOT_READ_FAILED", "failed closing egress snapshot stream", closeRCErr)
	}

	if written > s.maxSnapshotBytes {
		return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "snapshot stream exceeds maximum allowed size")
	}
	if written != snapshot.SizeBytes {
		return domain.Unprocessable("SIZE_MISMATCH", fmt.Sprintf("snapshot byte size mismatch: got %d, expected %d", written, snapshot.SizeBytes))
	}
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA != expectedSHA {
		return domain.Unprocessable("DIGEST_MISMATCH", "snapshot SHA-256 digest mismatch")
	}
	return nil
}

func validateCheckoutWorkDir(workDir string) error {
	workInfo, err := os.Lstat(workDir)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "CHECKOUT_DIR_INVALID", "failed inspecting checkout directory", err)
	}
	if workInfo.Mode()&os.ModeSymlink != 0 || !workInfo.IsDir() {
		return domain.Internal("CHECKOUT_DIR_INVALID", "checkout working directory must be a non-symlink directory")
	}
	gitInfo, err := os.Lstat(filepath.Join(workDir, ".git"))
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "CHECKOUT_GIT_MISSING", "checkout directory must contain .git metadata", err)
	}
	if gitInfo.Mode()&os.ModeSymlink != 0 || !gitInfo.IsDir() {
		return domain.Internal("CHECKOUT_GIT_INVALID", "checkout .git must be a non-symlink directory")
	}
	return nil
}

func wipeWorkingTreePreservingGit(workDir string) error {
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "WORKTREE_WIPE_FAILED", "failed listing checkout working directory", err)
	}
	for _, entry := range entries {
		if entry.Name() == ".git" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(workDir, entry.Name())); err != nil {
			return domain.WrapError(domain.ErrInternal, "WORKTREE_WIPE_FAILED", "failed clearing base working tree", err)
		}
	}
	return nil
}

func (s *Service) persistArtifacts(
	ctx context.Context,
	treeBytes []byte, treeSHA string,
	diffBytes []byte, diffSHA string,
	manifestBytes []byte, manifestSHA string,
) (treeArt, diffArt, manifestArt domain.Artifact, err error) {
	runID, err := domain.NewID()
	if err != nil {
		return domain.Artifact{}, domain.Artifact{}, domain.Artifact{}, err
	}
	prefix := fmt.Sprintf("reconstruct/%s", runID.String())

	stored := make([]domain.Artifact, 0, 3)
	rollback := func() {
		rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer rbCancel()
		for i := len(stored) - 1; i >= 0; i-- {
			_ = s.snapshotStore.Delete(rbCtx, stored[i])
		}
	}

	treeArt, err = s.snapshotStore.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindCanonicalTree,
		ObjectKey:      prefix + "/canonical_tree.tar.gz",
		ExpectedSHA256: treeSHA,
		MaxBytes:       int64(len(treeBytes)),
		ContentType:    "application/gzip",
	}, bytes.NewReader(treeBytes), int64(len(treeBytes)))
	if err != nil {
		rollback()
		return domain.Artifact{}, domain.Artifact{}, domain.Artifact{}, err
	}
	if treeArt.ID == uuid.Nil {
		treeArt.ID = domain.MustNewID()
	}
	stored = append(stored, treeArt)

	diffArt, err = s.snapshotStore.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindCanonicalDiff,
		ObjectKey:      prefix + "/canonical_diff.patch",
		ExpectedSHA256: diffSHA,
		MaxBytes:       int64(len(diffBytes)),
		ContentType:    "text/plain; charset=utf-8",
	}, bytes.NewReader(diffBytes), int64(len(diffBytes)))
	if err != nil {
		rollback()
		return domain.Artifact{}, domain.Artifact{}, domain.Artifact{}, err
	}
	if diffArt.ID == uuid.Nil {
		diffArt.ID = domain.MustNewID()
	}
	stored = append(stored, diffArt)

	manifestArt, err = s.snapshotStore.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindPublicationManifest,
		ObjectKey:      prefix + "/publication_manifest.json",
		ExpectedSHA256: manifestSHA,
		MaxBytes:       int64(len(manifestBytes)),
		ContentType:    "application/json",
	}, bytes.NewReader(manifestBytes), int64(len(manifestBytes)))
	if err != nil {
		rollback()
		return domain.Artifact{}, domain.Artifact{}, domain.Artifact{}, err
	}
	if manifestArt.ID == uuid.Nil {
		manifestArt.ID = domain.MustNewID()
	}
	stored = append(stored, manifestArt)

	return treeArt, diffArt, manifestArt, nil
}
