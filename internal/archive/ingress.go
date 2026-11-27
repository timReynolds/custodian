package archive

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const sanitizedGitConfig = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tsymlinks = false\n"

// IngressPackageRequest configures deterministic ingress archive packaging.
type IngressPackageRequest struct {
	SourceDir          string
	WorkspaceID        *uuid.UUID
	RepositoryID       *uuid.UUID
	GitHubRepositoryID int64
	RepositoryFullName string
	CommitSHA          string
	TargetRef          string
	IncludeGitMetadata bool
	IncludeHistory     bool
	HistoryAuthorised  bool
	ForbiddenSecrets   []string
	MaxArchiveBytes    int64
}

// IngressPackageResult contains the packaged deterministic archive digest, manifest, and optional bytes.
type IngressPackageResult struct {
	ArchiveBytes     []byte
	ArchiveSHA256    string
	ArchiveSizeBytes int64
	Manifest         SourceManifest
	ManifestJSON     []byte
	ManifestSHA256   string
}

// IngressPackager builds deterministic shallow source archives and canonical manifests.
type IngressPackager struct {
	logger *slog.Logger
}

// NewIngressPackager constructs an IngressPackager.
func NewIngressPackager(logger *slog.Logger) *IngressPackager {
	return &IngressPackager{logger: logger}
}

type archiveEntry struct {
	relPath  string
	mode     int64
	typeflag byte
	size     int64
	srcPath  string // disk path when content == nil
	content  []byte // in-memory sanitized content (for .git/config, .git/HEAD, etc.)
	inGit    bool
}

var errArchiveSizeExceeded = errors.New("archive size limit exceeded")

type countingWriter struct {
	n        int64
	max      int64
	exceeded bool
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.exceeded {
		return 0, errArchiveSizeExceeded
	}
	if c.max > 0 && c.n+int64(len(p)) > c.max {
		c.exceeded = true
		return 0, errArchiveSizeExceeded
	}
	c.n += int64(len(p))
	return len(p), nil
}

// Package produces an in-memory deterministic .tar.gz archive and SourceManifest.
func (p *IngressPackager) Package(ctx context.Context, req IngressPackageRequest) (IngressPackageResult, error) {
	var buf bytes.Buffer
	res, err := p.PackageToWriter(ctx, req, &buf)
	if err != nil {
		return IngressPackageResult{}, err
	}
	res.ArchiveBytes = buf.Bytes()
	return res, nil
}

// PackageToWriter streams a deterministic .tar.gz archive into w and computes its manifest.
func (p *IngressPackager) PackageToWriter(ctx context.Context, req IngressPackageRequest, w io.Writer) (IngressPackageResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return IngressPackageResult{}, domain.WrapError(domain.ErrUnavailable, "PACKAGING_ABORTED", "archive packaging aborted", err)
	}
	if w == nil {
		return IngressPackageResult{}, domain.BadRequest("INVALID_WRITER", "output writer must not be nil")
	}

	// Enforce history entitlement invariant fail-closed.
	if req.IncludeHistory && !req.HistoryAuthorised {
		return IngressPackageResult{}, domain.Forbidden("HISTORY_NOT_AUTHORISED", "full git history is not authorised for this workspace")
	}

	commitSHA, err := domain.ParseGitSHA(req.CommitSHA)
	if err != nil {
		return IngressPackageResult{}, err
	}

	srcDir := strings.TrimSpace(req.SourceDir)
	if srcDir == "" {
		return IngressPackageResult{}, domain.BadRequest("INVALID_SOURCE_DIR", "source directory is required")
	}
	srcLstat, err := os.Lstat(srcDir)
	if err != nil {
		return IngressPackageResult{}, domain.WrapError(domain.ErrBadRequest, "INVALID_SOURCE_DIR", "source directory cannot be inspected", err)
	}
	if srcLstat.Mode()&os.ModeSymlink != 0 || !srcLstat.IsDir() {
		return IngressPackageResult{}, domain.Unprocessable("UNSAFE_SOURCE_DIR", "source directory must be a non-symlink directory")
	}

	entries, err := p.collectEntries(ctx, srcDir, commitSHA, req)
	if err != nil {
		return IngressPackageResult{}, err
	}

	slices.SortFunc(entries, func(a, b archiveEntry) int {
		return strings.Compare(a.relPath, b.relPath)
	})

	archHash := sha256.New()
	archCounter := countingWriter{max: req.MaxArchiveBytes}
	mw := io.MultiWriter(&archCounter, w, archHash)

	gw, err := gzip.NewWriterLevel(mw, gzip.BestCompression)
	if err != nil {
		return IngressPackageResult{}, domain.WrapError(domain.ErrInternal, "GZIP_INIT_FAILED", "failed initializing gzip writer", err)
	}
	gw.Header = gzip.Header{
		ModTime: EpochTime,
		OS:      255,
	}

	tw := tar.NewWriter(gw)
	manifestFiles := make([]ManifestFileEntry, 0, len(entries))
	var totalBytes int64

	sizeExceededErr := func() error {
		return domain.Unprocessable("ARCHIVE_SIZE_EXCEEDED", "packaged archive exceeds maximum allowed size")
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			return IngressPackageResult{}, domain.WrapError(domain.ErrUnavailable, "PACKAGING_ABORTED", "archive packaging aborted", err)
		}
		if !entry.inGit && hasGitSegment(entry.relPath) {
			_ = tw.Close()
			_ = gw.Close()
			return IngressPackageResult{}, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "nested .git path is not permitted in workspace archive")
		}

		hdr := &tar.Header{
			Name:     entry.relPath,
			Mode:     entry.mode,
			Uid:      0,
			Gid:      0,
			Uname:    "",
			Gname:    "",
			Size:     entry.size,
			ModTime:  EpochTime,
			Typeflag: entry.typeflag,
		}
		if entry.typeflag == tar.TypeDir && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			if archCounter.exceeded || errors.Is(err, errArchiveSizeExceeded) {
				return IngressPackageResult{}, sizeExceededErr()
			}
			return IngressPackageResult{}, domain.WrapError(domain.ErrInternal, "TAR_WRITE_FAILED", "failed writing tar header", err)
		}
		if entry.typeflag != tar.TypeReg {
			continue
		}

		fileHash := sha256.New()
		var written int64
		if entry.content != nil {
			written = int64(len(entry.content))
			_, _ = fileHash.Write(entry.content)
			if _, err := tw.Write(entry.content); err != nil {
				_ = tw.Close()
				_ = gw.Close()
				if archCounter.exceeded || errors.Is(err, errArchiveSizeExceeded) {
					return IngressPackageResult{}, sizeExceededErr()
				}
				return IngressPackageResult{}, domain.WrapError(domain.ErrInternal, "TAR_WRITE_FAILED", "failed writing tar entry", err)
			}
		} else {
			f, err := os.Open(entry.srcPath)
			if err != nil {
				_ = tw.Close()
				_ = gw.Close()
				return IngressPackageResult{}, domain.WrapError(domain.ErrUnprocessable, "SOURCE_READ_FAILED", "failed opening source file", err)
			}
			written, copyErr := io.Copy(io.MultiWriter(tw, fileHash), io.LimitReader(f, entry.size+1))
			closeErr := f.Close()
			if copyErr != nil || closeErr != nil {
				_ = tw.Close()
				_ = gw.Close()
				if archCounter.exceeded || errors.Is(copyErr, errArchiveSizeExceeded) {
					return IngressPackageResult{}, sizeExceededErr()
				}
				return IngressPackageResult{}, domain.WrapError(domain.ErrUnprocessable, "SOURCE_READ_FAILED", "failed streaming source file", copyErr)
			}
			if written != entry.size {
				_ = tw.Close()
				_ = gw.Close()
				return IngressPackageResult{}, domain.Unprocessable("SOURCE_MODIFIED", "source file size changed during packaging")
			}
		}

		fileSHA := hex.EncodeToString(fileHash.Sum(nil))
		totalBytes += written
		manifestFiles = append(manifestFiles, ManifestFileEntry{
			Path:      entry.relPath,
			Mode:      fmt.Sprintf("%04o", entry.mode),
			SizeBytes: written,
			SHA256:    fileSHA,
		})
	}

	if err := tw.Close(); err != nil {
		_ = gw.Close()
		if archCounter.exceeded || errors.Is(err, errArchiveSizeExceeded) {
			return IngressPackageResult{}, sizeExceededErr()
		}
		return IngressPackageResult{}, domain.WrapError(domain.ErrInternal, "TAR_CLOSE_FAILED", "failed closing tar archive", err)
	}
	if err := gw.Close(); err != nil {
		if archCounter.exceeded || errors.Is(err, errArchiveSizeExceeded) {
			return IngressPackageResult{}, sizeExceededErr()
		}
		return IngressPackageResult{}, domain.WrapError(domain.ErrInternal, "GZIP_CLOSE_FAILED", "failed closing gzip archive", err)
	}

	if req.MaxArchiveBytes > 0 && (archCounter.exceeded || archCounter.n > req.MaxArchiveBytes) {
		return IngressPackageResult{}, sizeExceededErr()
	}

	archSHA := hex.EncodeToString(archHash.Sum(nil))
	manifest := SourceManifest{
		SchemaVersion:      ManifestSchemaVersion,
		WorkspaceID:        req.WorkspaceID,
		RepositoryID:       req.RepositoryID,
		GitHubRepositoryID: req.GitHubRepositoryID,
		RepositoryFullName: strings.TrimSpace(req.RepositoryFullName),
		CommitSHA:          commitSHA,
		TargetRef:          strings.TrimSpace(req.TargetRef),
		Format:             FormatTarGz,
		IncludeGitMetadata: req.IncludeGitMetadata,
		IncludeHistory:     req.IncludeHistory,
		FileCount:          len(manifestFiles),
		TotalBytes:         totalBytes,
		ArchiveSHA256:      archSHA,
		ArchiveSizeBytes:   archCounter.n,
		Files:              manifestFiles,
	}

	manifestJSON, err := domain.CanonicalJSONBytes(manifest)
	if err != nil {
		return IngressPackageResult{}, err
	}
	if err := ScanForCredentials(manifestJSON, req.ForbiddenSecrets); err != nil {
		return IngressPackageResult{}, err
	}
	manifestSHA := domain.SHA256Hex(manifestJSON)

	if p.logger != nil {
		p.logger.Info("ingress archive packaged",
			"commit_sha", commitSHA,
			"sha256", archSHA,
			"manifest_digest", manifestSHA,
			"size_bytes", archCounter.n,
		)
	}

	return IngressPackageResult{
		ArchiveSHA256:    archSHA,
		ArchiveSizeBytes: archCounter.n,
		Manifest:         manifest,
		ManifestJSON:     manifestJSON,
		ManifestSHA256:   manifestSHA,
	}, nil
}

func hasGitSegment(relPosix string) bool {
	for _, seg := range strings.Split(relPosix, "/") {
		if strings.EqualFold(seg, ".git") {
			return true
		}
	}
	return false
}

func (p *IngressPackager) collectEntries(ctx context.Context, srcDir, commitSHA string, req IngressPackageRequest) ([]archiveEntry, error) {
	var entries []archiveEntry
	hasGitDir := false

	err := filepath.WalkDir(srcDir, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if fullPath == srcDir {
			return nil
		}

		relOS, err := filepath.Rel(srcDir, fullPath)
		if err != nil {
			return domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "failed resolving relative path")
		}
		relPosix, err := ValidateArchiveRelPath(relOS)
		if err != nil {
			return err
		}

		if relPosix == ".git" {
			if !req.IncludeGitMetadata {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				hasGitDir = true
				return fs.SkipDir
			}
			return domain.Unprocessable("UNSAFE_GIT_DIR", ".git must be a directory")
		}

		if hasGitSegment(relPosix) || strings.EqualFold(d.Name(), ".git") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		linfo, err := os.Lstat(fullPath)
		if err != nil {
			return domain.WrapError(domain.ErrUnprocessable, "SOURCE_STAT_FAILED", "failed inspecting source entry", err)
		}
		mode := linfo.Mode()
		if mode&os.ModeSymlink != 0 {
			return domain.Unprocessable("UNSAFE_SYMLINK", "symlinks are not permitted in ingress workspace archives")
		}
		if mode&(os.ModeSocket|os.ModeNamedPipe|os.ModeDevice|os.ModeCharDevice) != 0 {
			return domain.Unprocessable("UNSAFE_FILE_TYPE", "special files are not permitted in ingress workspace archives")
		}

		if linfo.IsDir() {
			entries = append(entries, archiveEntry{
				relPath:  relPosix,
				mode:     0o755,
				typeflag: tar.TypeDir,
			})
			return nil
		}
		if !mode.IsRegular() {
			return domain.Unprocessable("UNSAFE_FILE_TYPE", "unsupported file type in source directory")
		}

		perm := int64(0o644)
		if mode.Perm()&0o111 != 0 {
			perm = 0o755
		}
		entries = append(entries, archiveEntry{
			relPath:  relPosix,
			mode:     perm,
			typeflag: tar.TypeReg,
			size:     linfo.Size(),
			srcPath:  fullPath,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	if req.IncludeGitMetadata && hasGitDir {
		gitEntries, err := collectSanitizedGitEntries(ctx, srcDir, filepath.Join(srcDir, ".git"), commitSHA, req.IncludeHistory, req.ForbiddenSecrets)
		if err != nil {
			return nil, err
		}
		entries = append(entries, gitEntries...)
	}

	return entries, nil
}

var (
	looseGitObjectDirRe  = regexp.MustCompile(`^objects/[0-9a-f]{2}$`)
	looseGitObjectFileRe = regexp.MustCompile(`^objects/[0-9a-f]{2}/[0-9a-f]{38}$`)
	gitPackFileRe        = regexp.MustCompile(`^objects/pack/pack-[0-9a-f]{40}\.(pack|idx)$`)
	gitPackNameRe        = regexp.MustCompile(`^pack-([0-9a-f]{40})\.(pack|idx|rev)$`)
)

func isAllowedGitDir(relPosix string) bool {
	if relPosix == "info" ||
		relPosix == "refs" ||
		relPosix == "refs/heads" || strings.HasPrefix(relPosix, "refs/heads/") ||
		relPosix == "refs/tags" || strings.HasPrefix(relPosix, "refs/tags/") ||
		relPosix == "objects" ||
		relPosix == "objects/pack" ||
		looseGitObjectDirRe.MatchString(relPosix) {
		return true
	}
	return false
}

func collectSanitizedGitEntries(ctx context.Context, srcDir, gitDir, commitSHA string, includeHistory bool, forbiddenSecrets []string) ([]archiveEntry, error) {
	if _, err := os.Lstat(filepath.Join(gitDir, "objects", "info", "alternates")); err == nil {
		return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "git object alternates are not permitted")
	}

	packObjs, err := verifyGitPackFiles(ctx, srcDir, gitDir)
	if err != nil {
		return nil, err
	}

	var objectSet map[string]struct{}
	if !includeHistory {
		var err error
		objectSet, err = verifySingleCommitHistory(ctx, srcDir, gitDir, commitSHA)
		if err != nil {
			return nil, err
		}
		for sha := range packObjs {
			if _, ok := objectSet[sha]; !ok {
				return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "multi-commit or unapproved git objects are not authorised")
			}
		}
	} else if len(forbiddenSecrets) > 0 {
		var err error
		objectSet, err = listAllGitObjects(ctx, srcDir)
		if err != nil {
			return nil, err
		}
		for sha := range packObjs {
			objectSet[sha] = struct{}{}
		}
	}

	if len(forbiddenSecrets) > 0 && len(objectSet) > 0 {
		if err := scanGitObjectsForSecrets(ctx, srcDir, objectSet, forbiddenSecrets); err != nil {
			return nil, err
		}
	}

	var entries []archiveEntry
	entries = append(entries, archiveEntry{
		relPath:  ".git",
		mode:     0o755,
		typeflag: tar.TypeDir,
		inGit:    true,
	})

	// Emit sanitized .git/config and pinned .git/HEAD explicitly.
	cfgBytes := []byte(sanitizedGitConfig)
	if err := ScanForCredentials(cfgBytes, forbiddenSecrets); err != nil {
		return nil, err
	}
	entries = append(entries, archiveEntry{
		relPath:  ".git/config",
		mode:     0o644,
		typeflag: tar.TypeReg,
		size:     int64(len(cfgBytes)),
		content:  cfgBytes,
		inGit:    true,
	})

	headBytes := []byte(commitSHA + "\n")
	entries = append(entries, archiveEntry{
		relPath:  ".git/HEAD",
		mode:     0o644,
		typeflag: tar.TypeReg,
		size:     int64(len(headBytes)),
		content:  headBytes,
		inGit:    true,
	})

	if !includeHistory {
		shallowBytes := []byte(commitSHA + "\n")
		entries = append(entries, archiveEntry{
			relPath:  ".git/shallow",
			mode:     0o644,
			typeflag: tar.TypeReg,
			size:     int64(len(shallowBytes)),
			content:  shallowBytes,
			inGit:    true,
		})
	}

	err = filepath.WalkDir(gitDir, func(fullPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if fullPath == gitDir {
			return nil
		}
		relOS, err := filepath.Rel(gitDir, fullPath)
		if err != nil {
			return domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "invalid .git path")
		}
		relPosix, err := ValidateArchiveRelPath(relOS)
		if err != nil {
			return err
		}

		linfo, err := os.Lstat(fullPath)
		if err != nil {
			return domain.WrapError(domain.ErrUnprocessable, "SOURCE_STAT_FAILED", "failed inspecting .git entry", err)
		}
		mode := linfo.Mode()
		if mode&os.ModeSymlink != 0 || mode&(os.ModeSocket|os.ModeNamedPipe|os.ModeDevice|os.ModeCharDevice) != 0 {
			return domain.Unprocessable("UNSAFE_GIT_ENTRY", "unsafe symlink or special file inside .git")
		}

		if relPosix == "config" || relPosix == "HEAD" || relPosix == "shallow" {
			return nil
		}

		archivePath := ".git/" + relPosix
		if linfo.IsDir() {
			if !isAllowedGitDir(relPosix) {
				return fs.SkipDir
			}
			entries = append(entries, archiveEntry{
				relPath:  archivePath,
				mode:     0o755,
				typeflag: tar.TypeDir,
				inGit:    true,
			})
			return nil
		}
		if !mode.IsRegular() {
			return domain.Unprocessable("UNSAFE_GIT_ENTRY", "non-regular file inside .git")
		}

		switch {
		case relPosix == "index" || relPosix == "info/exclude":
			raw, err := os.ReadFile(fullPath)
			if err != nil {
				return domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed reading git metadata file", err)
			}
			if err := ScanForCredentials(raw, forbiddenSecrets); err != nil {
				return err
			}
			entries = append(entries, archiveEntry{
				relPath:  archivePath,
				mode:     0o644,
				typeflag: tar.TypeReg,
				size:     int64(len(raw)),
				content:  raw,
				inGit:    true,
			})
			return nil

		case relPosix == "packed-refs":
			raw, err := os.ReadFile(fullPath)
			if err != nil {
				return domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed reading packed-refs", err)
			}
			if err := ScanForCredentials(raw, forbiddenSecrets); err != nil {
				return err
			}
			filtered := filterPackedRefs(raw, commitSHA, includeHistory)
			if len(filtered) == 0 {
				return nil
			}
			entries = append(entries, archiveEntry{
				relPath:  archivePath,
				mode:     0o644,
				typeflag: tar.TypeReg,
				size:     int64(len(filtered)),
				content:  filtered,
				inGit:    true,
			})
			return nil

		case strings.HasPrefix(relPosix, "refs/heads/") || strings.HasPrefix(relPosix, "refs/tags/"):
			raw, err := os.ReadFile(fullPath)
			if err != nil {
				return domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed reading git ref file", err)
			}
			if err := ScanForCredentials(raw, forbiddenSecrets); err != nil {
				return err
			}
			if !includeHistory {
				refSHA := strings.ToLower(strings.TrimSpace(string(raw)))
				if refSHA != commitSHA {
					return nil
				}
			}
			entries = append(entries, archiveEntry{
				relPath:  archivePath,
				mode:     0o644,
				typeflag: tar.TypeReg,
				size:     int64(len(raw)),
				content:  raw,
				inGit:    true,
			})
			return nil

		case looseGitObjectFileRe.MatchString(relPosix) || gitPackFileRe.MatchString(relPosix):
			entries = append(entries, archiveEntry{
				relPath:  archivePath,
				mode:     0o644,
				typeflag: tar.TypeReg,
				size:     linfo.Size(),
				srcPath:  fullPath,
				inGit:    true,
			})
			return nil

		default:
			// Strict allowlist: exclude any unlisted .git files (hooks, logs, remotes, alternates, AUTO_MERGE, etc.).
			return nil
		}
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func verifyGitPackFiles(ctx context.Context, srcDir, gitDir string) (map[string]struct{}, error) {
	packDir := filepath.Join(gitDir, "objects", "pack")
	linfo, err := os.Lstat(packDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, domain.WrapError(domain.ErrUnprocessable, "SOURCE_STAT_FAILED", "failed inspecting .git/objects/pack", err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 || !linfo.IsDir() {
		return nil, domain.Unprocessable("UNSAFE_GIT_ENTRY", "unsafe symlink or non-directory .git/objects/pack")
	}

	dirEntries, err := os.ReadDir(packDir)
	if err != nil {
		return nil, domain.WrapError(domain.ErrUnprocessable, "SOURCE_STAT_FAILED", "failed listing .git/objects/pack", err)
	}

	packs := make(map[string]struct{})
	idxs := make(map[string]struct{})
	revs := make(map[string]struct{})
	for _, de := range dirEntries {
		name := de.Name()
		fullPath := filepath.Join(packDir, name)
		info, statErr := os.Lstat(fullPath)
		if statErr != nil {
			return nil, domain.WrapError(domain.ErrUnprocessable, "SOURCE_STAT_FAILED", "failed inspecting git pack entry", statErr)
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			return nil, domain.Unprocessable("UNSAFE_GIT_ENTRY", "unsafe symlink or non-regular entry in .git/objects/pack")
		}
		m := gitPackNameRe.FindStringSubmatch(name)
		if m == nil {
			return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unexpected file in git pack directory is not permitted")
		}
		switch m[2] {
		case "pack":
			packs[m[1]] = struct{}{}
		case "idx":
			idxs[m[1]] = struct{}{}
		case "rev":
			revs[m[1]] = struct{}{}
		}
	}

	for id := range packs {
		if _, ok := idxs[id]; !ok {
			return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unindexed or mismatched git packfile is not permitted")
		}
	}
	for id := range idxs {
		if _, ok := packs[id]; !ok {
			return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unindexed or mismatched git packfile is not permitted")
		}
	}
	for id := range revs {
		if _, ok := packs[id]; !ok {
			return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unindexed or mismatched git packfile is not permitted")
		}
	}

	if len(packs) == 0 {
		return nil, nil
	}

	packIDs := make([]string, 0, len(packs))
	for id := range packs {
		packIDs = append(packIDs, id)
	}
	slices.Sort(packIDs)

	packObjs := make(map[string]struct{})
	for _, id := range packIDs {
		packRel := ".git/objects/pack/pack-" + id + ".pack"
		out, verifyErr := runHardenedGit(ctx, srcDir, nil, "verify-pack", "-v", "--", packRel)
		if verifyErr != nil {
			return nil, domain.Unprocessable("CORRUPT_GIT_PACKFILE", "git packfile failed verification")
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			sha := strings.ToLower(fields[0])
			if domain.IsValidGitSHA(sha) {
				packObjs[sha] = struct{}{}
			}
		}
	}

	return packObjs, nil
}

func runHardenedGit(ctx context.Context, srcDir string, stdin io.Reader, args ...string) ([]byte, error) {
	fullArgs := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "core.fsmonitor=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"-C", srcDir,
	}
	fullArgs = append(fullArgs, args...)
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	}
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %v: %w (%s)", args, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func verifySingleCommitHistory(ctx context.Context, srcDir, gitDir, commitSHA string) (map[string]struct{}, error) {
	// Verify commitSHA is a valid commit object.
	typeOut, err := runHardenedGit(ctx, srcDir, nil, "cat-file", "-t", "--", commitSHA)
	if err != nil || strings.TrimSpace(string(typeOut)) != "commit" {
		return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unable to verify pinned commit object in git metadata")
	}

	// Verify commitSHA has single-commit reachable history (no ancestors).
	countOut, err := runHardenedGit(ctx, srcDir, nil, "rev-list", "--count", commitSHA, "--")
	if err != nil || strings.TrimSpace(string(countOut)) != "1" {
		return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "multi-commit or unapproved git history is not authorised")
	}

	// Compute the exact object closure of ONLY commitSHA (--no-walk ignores parent pointers).
	reachOut, err := runHardenedGit(ctx, srcDir, nil, "rev-list", "--objects", "--no-walk", commitSHA, "--")
	if err != nil {
		return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unable to enumerate pinned commit objects")
	}
	allowedObjs := make(map[string]struct{})
	for _, line := range strings.Split(string(reachOut), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		sha := strings.ToLower(fields[0])
		if domain.IsValidGitSHA(sha) {
			allowedObjs[sha] = struct{}{}
		}
	}
	if _, ok := allowedObjs[commitSHA]; !ok {
		return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "pinned commit missing from reachable object set")
	}

	// Enumerate EVERY object stored in .git/objects (both loose and packed) and reject any extra object.
	allObjs, err := listAllGitObjects(ctx, srcDir)
	if err != nil {
		return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unable to inspect stored git objects")
	}
	for sha := range allObjs {
		if _, ok := allowedObjs[sha]; !ok {
			return nil, domain.Forbidden("UNAPPROVED_GIT_HISTORY", "multi-commit or unapproved git objects are not authorised")
		}
	}
	return allowedObjs, nil
}

func listAllGitObjects(ctx context.Context, srcDir string) (map[string]struct{}, error) {
	out, err := runHardenedGit(ctx, srcDir, nil, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
	if err != nil {
		return nil, err
	}
	objs := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		sha := strings.ToLower(strings.TrimSpace(line))
		if sha == "" {
			continue
		}
		if domain.IsValidGitSHA(sha) {
			objs[sha] = struct{}{}
		}
	}
	return objs, nil
}

func scanGitObjectsForSecrets(ctx context.Context, srcDir string, objSet map[string]struct{}, forbiddenSecrets []string) error {
	var secrets [][]byte
	maxLen := 0
	for _, s := range forbiddenSecrets {
		if s == "" {
			continue
		}
		b := []byte(s)
		secrets = append(secrets, b)
		if len(b) > maxLen {
			maxLen = len(b)
		}
	}
	if len(secrets) == 0 || len(objSet) == 0 {
		return nil
	}

	shas := make([]string, 0, len(objSet))
	for sha := range objSet {
		shas = append(shas, sha)
	}
	slices.Sort(shas)
	var stdinBuf bytes.Buffer
	for _, sha := range shas {
		stdinBuf.WriteString(sha)
		stdinBuf.WriteByte('\n')
	}

	fullArgs := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "core.symlinks=false",
		"-c", "core.fsmonitor=false",
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.file.allow=never",
		"-C", srcDir,
		"cat-file", "--batch",
	}
	cmd := exec.CommandContext(ctx, "git", fullArgs...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	}
	cmd.Stdin = &stdinBuf
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed piping git object scan", err)
	}
	if err := cmd.Start(); err != nil {
		return domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed starting git object scan", err)
	}

	br := bufio.NewReader(stdoutPipe)
	var scanErr error
	const chunkSize = 64 * 1024
	buf := make([]byte, chunkSize)

	for {
		headerLine, err := br.ReadString('\n')
		if err == io.EOF && headerLine == "" {
			break
		}
		if err != nil && err != io.EOF {
			scanErr = domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed reading git object header", err)
			break
		}
		fields := strings.Fields(headerLine)
		if len(fields) != 3 {
			scanErr = domain.Forbidden("UNAPPROVED_GIT_HISTORY", "unexpected git object batch header")
			break
		}
		size, parseErr := strconv.ParseInt(fields[2], 10, 64)
		if parseErr != nil || size < 0 {
			scanErr = domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "invalid git object size", parseErr)
			break
		}

		remaining := size
		var carry []byte
		for remaining > 0 {
			toRead := int64(len(buf))
			if remaining < toRead {
				toRead = remaining
			}
			n, readErr := io.ReadFull(br, buf[:toRead])
			if readErr != nil {
				scanErr = domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed reading git object body", readErr)
				break
			}
			remaining -= int64(n)
			window := append(carry, buf[:n]...)
			for _, sec := range secrets {
				if bytes.Contains(window, sec) {
					scanErr = domain.Forbidden("CREDENTIAL_LEAK_DETECTED", "forbidden credential detected in git object")
					break
				}
			}
			if scanErr != nil {
				break
			}
			if maxLen > 1 && len(window) >= maxLen-1 {
				carry = append([]byte(nil), window[len(window)-(maxLen-1):]...)
			} else {
				carry = append([]byte(nil), window...)
			}
		}
		if scanErr != nil {
			break
		}
		if _, lfErr := br.ReadByte(); lfErr != nil {
			scanErr = domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "failed reading git object delimiter", lfErr)
			break
		}
	}

	if scanErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return scanErr
	}
	if err := cmd.Wait(); err != nil {
		return domain.WrapError(domain.ErrUnprocessable, "GIT_READ_FAILED", "git object scan failed", err)
	}
	return nil
}

func filterPackedRefs(raw []byte, commitSHA string, includeHistory bool) []byte {
	var out bytes.Buffer
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "^") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			continue
		}
		refSHA, refName := strings.ToLower(fields[0]), fields[1]
		if !strings.HasPrefix(refName, "refs/heads/") && !strings.HasPrefix(refName, "refs/tags/") {
			continue
		}
		if !includeHistory && refSHA != commitSHA {
			continue
		}
		out.WriteString(refSHA)
		out.WriteByte(' ')
		out.WriteString(refName)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
