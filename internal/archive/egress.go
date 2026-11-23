package archive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	// DefaultMaxCompressedBytes bounds the compressed .tar.gz stream accepted during egress parsing.
	DefaultMaxCompressedBytes int64 = 64 << 20
	// DefaultMaxUncompressedBytes bounds the total decompressed tar stream bytes during egress parsing.
	DefaultMaxUncompressedBytes int64 = 64 << 20
	// DefaultMaxSingleFileBytes bounds any individual regular file inside an egress archive.
	DefaultMaxSingleFileBytes int64 = 32 << 20
	// DefaultMaxEntries bounds the total number of tar entries processed in a single egress archive.
	DefaultMaxEntries int = 10_000
	// DefaultMaxPathBytes bounds the byte length of any tar entry name.
	DefaultMaxPathBytes int = 4096
	// DefaultMaxPathDepth bounds the directory segment depth of any tar entry path.
	DefaultMaxPathDepth int = 64
)

var (
	errCompressedLimitExceeded   = errors.New("compressed archive size limit exceeded")
	errUncompressedLimitExceeded = errors.New("uncompressed archive size limit exceeded")
)

// EgressOptions configures hardening limits for egress archive validation and extraction.
type EgressOptions struct {
	MaxCompressedBytes   int64
	MaxUncompressedBytes int64
	MaxSingleFileBytes   int64
	MaxEntries           int
	MaxPathBytes         int
	MaxPathDepth         int
}

func (o EgressOptions) withDefaults() EgressOptions {
	if o.MaxCompressedBytes <= 0 {
		o.MaxCompressedBytes = DefaultMaxCompressedBytes
	}
	if o.MaxUncompressedBytes <= 0 {
		o.MaxUncompressedBytes = DefaultMaxUncompressedBytes
	}
	if o.MaxSingleFileBytes <= 0 {
		o.MaxSingleFileBytes = DefaultMaxSingleFileBytes
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	if o.MaxPathBytes <= 0 {
		o.MaxPathBytes = DefaultMaxPathBytes
	}
	if o.MaxPathDepth <= 0 {
		o.MaxPathDepth = DefaultMaxPathDepth
	}
	return o
}

// EgressFileEntry describes one validated and normalized regular file in an egress archive.
type EgressFileEntry struct {
	Path      string `json:"path"`
	Mode      int64  `json:"mode"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// EgressResult summarizes validated (and optionally extracted) egress archive contents.
type EgressResult struct {
	Files             []EgressFileEntry `json:"files"`
	Dirs              []string          `json:"dirs"`
	FileCount         int               `json:"file_count"`
	TotalBytes        int64             `json:"total_bytes"`
	CompressedBytes   int64             `json:"compressed_bytes"`
	UncompressedBytes int64             `json:"uncompressed_bytes"`
	EntryCount        int               `json:"entry_count"`
	IgnoredGitEntries int               `json:"ignored_git_entries"`
}

// ValidateEgress streams and validates an egress .tar.gz archive without writing files to disk.
func ValidateEgress(ctx context.Context, r io.Reader, opts EgressOptions) (EgressResult, error) {
	return processEgress(ctx, r, nil, opts)
}

// ExtractEgress validates and safely extracts an egress .tar.gz archive into destDir,
// confining all filesystem operations inside os.OpenRoot(destDir).
func ExtractEgress(ctx context.Context, r io.Reader, destDir string, opts EgressOptions) (EgressResult, error) {
	trimmed := strings.TrimSpace(destDir)
	if trimmed == "" {
		return EgressResult{}, domain.Unprocessable("UNSAFE_DEST_DIR", "destination directory must not be empty")
	}
	info, err := os.Lstat(trimmed)
	if err != nil {
		return EgressResult{}, domain.WrapError(domain.ErrUnprocessable, "UNSAFE_DEST_DIR", "destination directory cannot be inspected", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return EgressResult{}, domain.Unprocessable("UNSAFE_DEST_DIR", "destination path must be a non-symlink directory")
	}
	root, err := os.OpenRoot(trimmed)
	if err != nil {
		return EgressResult{}, domain.WrapError(domain.ErrUnprocessable, "UNSAFE_DEST_DIR", "failed opening destination root", err)
	}
	defer root.Close()

	return processEgress(ctx, r, root, opts)
}

func processEgress(ctx context.Context, r io.Reader, destRoot *os.Root, opts EgressOptions) (res EgressResult, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return EgressResult{}, domain.WrapError(domain.ErrUnavailable, "ARCHIVE_ABORTED", "archive processing aborted", err)
	}
	if r == nil {
		return EgressResult{}, domain.BadRequest("INVALID_READER", "archive reader must not be nil")
	}

	cfg := opts.withDefaults()

	var createdFiles []string
	var createdDirs []string
	defer func() {
		if err != nil && destRoot != nil {
			for i := len(createdFiles) - 1; i >= 0; i-- {
				_ = destRoot.Remove(createdFiles[i])
			}
			for i := len(createdDirs) - 1; i >= 0; i-- {
				_ = destRoot.Remove(createdDirs[i])
			}
		}
	}()

	compCounter := &ctxLimitedReader{
		ctx:      ctx,
		r:        r,
		max:      cfg.MaxCompressedBytes,
		limitErr: errCompressedLimitExceeded,
	}
	// Wrap compCounter in a bufio.Reader (which implements io.ByteReader / flate.Reader)
	// so gzip.NewReader does not allocate a hidden internal buffer that swallows trailing bytes.
	compBuf := bufio.NewReader(compCounter)

	gzr, gzErr := gzip.NewReader(compBuf)
	if gzErr != nil {
		return EgressResult{}, mapEgressStreamError(gzErr, "CORRUPT_ARCHIVE", "invalid gzip archive header")
	}
	defer gzr.Close()
	gzr.Multistream(false)

	uncompCounter := &ctxLimitedReader{
		ctx:      ctx,
		r:        gzr,
		max:      cfg.MaxUncompressedBytes,
		limitErr: errUncompressedLimitExceeded,
	}

	tr := tar.NewReader(uncompCounter)
	tracker := newCollisionTracker()
	files := make([]EgressFileEntry, 0)
	dirs := make([]string, 0)
	var totalFileBytes int64

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return EgressResult{}, domain.WrapError(domain.ErrUnavailable, "ARCHIVE_ABORTED", "archive processing aborted", ctxErr)
		}

		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return EgressResult{}, mapEgressStreamError(nextErr, "CORRUPT_ARCHIVE", "corrupt or truncated tar archive")
		}

		res.EntryCount++
		if res.EntryCount > cfg.MaxEntries {
			return EgressResult{}, domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", fmt.Sprintf("archive entry count exceeds limit of %d", cfg.MaxEntries))
		}

		isDir, err := validateTarHeaderTypeAndMode(hdr)
		if err != nil {
			return EgressResult{}, err
		}

		cleanPath, isRootDir, err := normalizeEgressTarPath(hdr.Name, hdr.Typeflag, cfg.MaxPathBytes, cfg.MaxPathDepth)
		if err != nil {
			return EgressResult{}, err
		}

		if isRootDir {
			continue
		}

		segs := strings.Split(cleanPath, "/")
		for _, seg := range segs {
			if strings.EqualFold(seg, ".gitmodules") {
				return EgressResult{}, domain.Unprocessable("SUBMODULE_NOT_ALLOWED", ".gitmodules is not permitted in egress archives")
			}
		}

		if strings.EqualFold(segs[0], ".git") {
			if err := validateTarEntrySize(hdr.Size, cfg, uncompCounter.n); err != nil {
				return EgressResult{}, err
			}
			if !isDir && hdr.Size > 0 {
				written, drainErr := io.CopyN(io.Discard, tr, hdr.Size)
				if drainErr != nil {
					return EgressResult{}, mapEgressStreamError(drainErr, "CORRUPT_ARCHIVE", "truncated tar entry inside .git")
				}
				if written != hdr.Size {
					return EgressResult{}, domain.Unprocessable("CORRUPT_ARCHIVE", "truncated tar entry inside .git")
				}
			}
			res.IgnoredGitEntries++
			continue
		}

		for i := 1; i < len(segs); i++ {
			if strings.EqualFold(segs[i], ".git") {
				return EgressResult{}, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "nested .git path is not permitted in egress archives")
			}
		}

		if err := tracker.add(cleanPath, isDir); err != nil {
			return EgressResult{}, err
		}

		if isDir {
			if destRoot != nil {
				if err := mkdirAllEgressNoSymlink(destRoot, cleanPath, &createdDirs); err != nil {
					return EgressResult{}, err
				}
			}
			dirs = append(dirs, cleanPath)
			continue
		}

		if err := validateTarEntrySize(hdr.Size, cfg, uncompCounter.n); err != nil {
			return EgressResult{}, err
		}

		perm := int64(0o644)
		if hdr.Mode&0o111 != 0 {
			perm = 0o755
		}

		fileHash := sha256.New()
		var dst io.Writer = fileHash
		var outFile *os.File

		if destRoot != nil {
			parent := path.Dir(cleanPath)
			if parent != "." {
				if err := mkdirAllEgressNoSymlink(destRoot, parent, &createdDirs); err != nil {
					return EgressResult{}, err
				}
			}
			f, openErr := destRoot.OpenFile(cleanPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(perm))
			if openErr != nil {
				return EgressResult{}, mapDestFSError(openErr, "failed creating extracted archive file")
			}
			createdFiles = append(createdFiles, cleanPath)
			if chmodErr := f.Chmod(fs.FileMode(perm)); chmodErr != nil {
				_ = f.Close()
				return EgressResult{}, mapDestFSError(chmodErr, "failed setting permissions on extracted file")
			}
			outFile = f
			dst = io.MultiWriter(f, fileHash)
		}

		written, copyErr := io.CopyN(dst, tr, hdr.Size)
		if outFile != nil {
			if closeErr := outFile.Close(); closeErr != nil && copyErr == nil {
				copyErr = closeErr
			}
		}
		if copyErr != nil {
			return EgressResult{}, mapEgressStreamError(copyErr, "CORRUPT_ARCHIVE", "corrupt or truncated regular file in tar archive")
		}
		if written != hdr.Size {
			return EgressResult{}, domain.Unprocessable("CORRUPT_ARCHIVE", "tar entry body shorter than declared header size")
		}

		totalFileBytes += written
		files = append(files, EgressFileEntry{
			Path:      cleanPath,
			Mode:      perm,
			SizeBytes: written,
			SHA256:    hex.EncodeToString(fileHash.Sum(nil)),
		})
	}

	// Drain remaining tar EOF zero-padding through the uncompressed limiter so
	// gzip trailer CRC32/ISIZE and uncompressed size caps are always enforced.
	if _, drainErr := io.Copy(io.Discard, uncompCounter); drainErr != nil {
		return EgressResult{}, mapEgressStreamError(drainErr, "CORRUPT_ARCHIVE", "corrupt or truncated gzip stream trailer")
	}
	if closeErr := gzr.Close(); closeErr != nil {
		return EgressResult{}, mapEgressStreamError(closeErr, "CORRUPT_ARCHIVE", "invalid gzip archive trailer")
	}

	// Probe compressed stream via compBuf to verify EOF (triggering SnapshotStore integrity checks)
	// and reject trailing concatenated bytes after the single gzip member.
	if _, trailErr := compBuf.ReadByte(); trailErr == nil {
		return EgressResult{}, domain.Unprocessable("CORRUPT_ARCHIVE", "trailing data after gzip archive is not permitted")
	} else if trailErr != io.EOF {
		return EgressResult{}, mapEgressStreamError(trailErr, "CORRUPT_ARCHIVE", "failed verifying end of archive stream")
	}

	slices.SortFunc(files, func(a, b EgressFileEntry) int {
		return strings.Compare(a.Path, b.Path)
	})
	slices.Sort(dirs)

	res.Files = files
	res.Dirs = dirs
	res.FileCount = len(files)
	res.TotalBytes = totalFileBytes
	res.CompressedBytes = compCounter.n
	res.UncompressedBytes = uncompCounter.n
	return res, nil
}

func validateTarHeaderTypeAndMode(hdr *tar.Header) (isDir bool, err error) {
	if hdr.Size < 0 {
		return false, domain.Unprocessable("CORRUPT_ARCHIVE", "tar entry size must not be negative")
	}
	if hdr.Devmajor != 0 || hdr.Devminor != 0 {
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "device major/minor numbers are not permitted in egress archives")
	}
	if hdr.Linkname != "" {
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "link targets are not permitted in egress archives")
	}

	ifmt := hdr.Mode & 0o170000
	if ifmt == 0o160000 {
		return false, domain.Unprocessable("SUBMODULE_NOT_ALLOWED", "gitlink submodule entries are not permitted in egress archives")
	}

	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		if ifmt != 0 && ifmt != 0o100000 {
			return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "invalid POSIX mode bits on regular file entry")
		}
		return false, nil
	case tar.TypeDir:
		if ifmt != 0 && ifmt != 0o040000 {
			return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "invalid POSIX mode bits on directory entry")
		}
		if hdr.Size != 0 {
			return false, domain.Unprocessable("CORRUPT_ARCHIVE", "directory entry must have zero byte size")
		}
		return true, nil
	case tar.TypeSymlink:
		return false, domain.Unprocessable("UNSAFE_SYMLINK", "symlinks are not permitted in egress archives")
	case tar.TypeLink:
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "hardlinks are not permitted in egress archives")
	case tar.TypeFifo, tar.TypeChar, tar.TypeBlock:
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "special device or FIFO entries are not permitted in egress archives")
	default:
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", fmt.Sprintf("unsupported tar entry type %q", hdr.Typeflag))
	}
}

func validateTarEntrySize(size int64, cfg EgressOptions, currentUncompressed int64) error {
	if size > cfg.MaxSingleFileBytes {
		return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", fmt.Sprintf("tar entry size %d exceeds single-file limit %d", size, cfg.MaxSingleFileBytes))
	}
	if size > cfg.MaxUncompressedBytes || currentUncompressed > cfg.MaxUncompressedBytes || size > cfg.MaxUncompressedBytes-currentUncompressed {
		return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", fmt.Sprintf("archive uncompressed size exceeds limit %d", cfg.MaxUncompressedBytes))
	}
	return nil
}

func normalizeEgressTarPath(rawName string, typeflag byte, maxPathBytes, maxPathDepth int) (cleanPath string, isRootDir bool, err error) {
	if rawName == "" {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must not be empty")
	}
	if len(rawName) > maxPathBytes {
		return "", false, domain.Unprocessable("ARCHIVE_PATH_TOO_LONG", "archive entry path exceeds maximum byte length")
	}
	if !utf8.ValidString(rawName) {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must be valid UTF-8")
	}
	for _, r := range rawName {
		if r < 0x20 || r == 0x7f {
			return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path contains control characters")
		}
	}
	if strings.ContainsRune(rawName, '\x00') || strings.Contains(rawName, "\\") {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path contains illegal characters")
	}
	if strings.HasPrefix(rawName, "/") {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must be relative")
	}
	if hasVolumeOrDrivePrefix(rawName) || hasVolumeOrDrivePrefix(stripLeadingDotSlash(rawName)) {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must not include a volume name")
	}

	if rawName == "." || rawName == "./" {
		if typeflag == tar.TypeDir {
			return "", true, nil
		}
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "non-directory entry cannot use root path '.'")
	}

	name := strings.TrimPrefix(rawName, "./")
	if typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	} else if strings.HasSuffix(name, "/") {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "non-directory entry must not end with '/'")
	}
	if hasVolumeOrDrivePrefix(name) {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must not include a volume name")
	}

	clean, err := ValidateArchiveRelPath(name)
	if err != nil {
		return "", false, err
	}
	if hasVolumeOrDrivePrefix(clean) {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must not include a volume name")
	}
	if len(clean) > maxPathBytes {
		return "", false, domain.Unprocessable("ARCHIVE_PATH_TOO_LONG", "normalized archive path exceeds maximum byte length")
	}
	depth := strings.Count(clean, "/") + 1
	if depth > maxPathDepth {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", fmt.Sprintf("archive path depth %d exceeds limit %d", depth, maxPathDepth))
	}
	return clean, false, nil
}

func hasVolumeOrDrivePrefix(p string) bool {
	return filepath.VolumeName(p) != "" || hasWindowsDrivePrefix(p)
}

func stripLeadingDotSlash(p string) string {
	for strings.HasPrefix(p, "./") {
		p = strings.TrimPrefix(p, "./")
	}
	return p
}

func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

type trackedPathEntry struct {
	rawPath  string
	isDir    bool
	explicit bool
}

type collisionTracker struct {
	caser   cases.Caser
	entries map[string]trackedPathEntry
}

func newCollisionTracker() *collisionTracker {
	return &collisionTracker{
		caser:   cases.Fold(),
		entries: make(map[string]trackedPathEntry),
	}
}

func (ct *collisionTracker) foldSegment(seg string) string {
	return norm.NFC.String(strings.ToLower(ct.caser.String(norm.NFD.String(seg))))
}

func (ct *collisionTracker) add(cleanPath string, isDir bool) error {
	segs := strings.Split(cleanPath, "/")
	foldedSegs := make([]string, len(segs))
	for i, seg := range segs {
		foldedSegs[i] = ct.foldSegment(seg)
	}

	// Validate and register every ancestor directory prefix.
	for i := 0; i < len(segs)-1; i++ {
		rawPrefix := strings.Join(segs[:i+1], "/")
		foldedPrefix := strings.Join(foldedSegs[:i+1], "/")
		if prev, exists := ct.entries[foldedPrefix]; exists {
			if !prev.isDir {
				return domain.Unprocessable("ARCHIVE_PATH_COLLISION", fmt.Sprintf("file vs directory path collision on %q", rawPrefix))
			}
			if prev.rawPath != rawPrefix {
				return domain.Unprocessable("ARCHIVE_PATH_COLLISION", fmt.Sprintf("case or Unicode normalization collision on directory %q", rawPrefix))
			}
			continue
		}
		ct.entries[foldedPrefix] = trackedPathEntry{
			rawPath:  rawPrefix,
			isDir:    true,
			explicit: false,
		}
	}

	foldedFull := strings.Join(foldedSegs, "/")
	if prev, exists := ct.entries[foldedFull]; exists {
		if prev.explicit {
			return domain.Unprocessable("ARCHIVE_PATH_COLLISION", fmt.Sprintf("duplicate or colliding archive entry %q", cleanPath))
		}
		if !isDir {
			return domain.Unprocessable("ARCHIVE_PATH_COLLISION", fmt.Sprintf("file vs directory path collision on %q", cleanPath))
		}
		if prev.rawPath != cleanPath {
			return domain.Unprocessable("ARCHIVE_PATH_COLLISION", fmt.Sprintf("case or Unicode normalization collision on directory %q", cleanPath))
		}
		ct.entries[foldedFull] = trackedPathEntry{
			rawPath:  cleanPath,
			isDir:    true,
			explicit: true,
		}
		return nil
	}

	ct.entries[foldedFull] = trackedPathEntry{
		rawPath:  cleanPath,
		isDir:    isDir,
		explicit: true,
	}
	return nil
}

type ctxLimitedReader struct {
	ctx      context.Context
	r        io.Reader
	max      int64
	n        int64
	exceeded bool
	limitErr error
}

func (c *ctxLimitedReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, domain.WrapError(domain.ErrUnavailable, "ARCHIVE_ABORTED", "archive processing aborted", err)
	}
	if c.exceeded {
		return 0, c.limitErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	rem := c.max - c.n
	if rem <= 0 {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			c.exceeded = true
			return 0, c.limitErr
		}
		return 0, err
	}
	if int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func mapEgressStreamError(err error, defaultCode, defaultMsg string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errCompressedLimitExceeded) || errors.Is(err, errUncompressedLimitExceeded) {
		return domain.WrapError(domain.ErrUnprocessable, "ARCHIVE_LIMIT_EXCEEDED", err.Error(), err)
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		return domErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return domain.WrapError(domain.ErrUnavailable, "ARCHIVE_ABORTED", "archive processing aborted", err)
	}
	return domain.WrapError(domain.ErrUnprocessable, defaultCode, defaultMsg, err)
}

func mapDestFSError(err error, msg string) error {
	if err == nil {
		return nil
	}
	if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
		return domain.WrapError(domain.ErrUnprocessable, "UNSAFE_SYMLINK", "destination path escapes root or traverses symlink", err)
	}
	if errors.Is(err, fs.ErrExist) {
		return domain.WrapError(domain.ErrUnprocessable, "ARCHIVE_PATH_COLLISION", msg, err)
	}
	return domain.WrapError(domain.ErrUnprocessable, "ARCHIVE_EXTRACT_FAILED", msg, err)
}

func mkdirAllEgressNoSymlink(root *os.Root, relSlashDir string, createdDirs *[]string) error {
	if relSlashDir == "" || relSlashDir == "." {
		return nil
	}
	parts := strings.Split(relSlashDir, "/")
	cur := ""
	for _, seg := range parts {
		if cur == "" {
			cur = seg
		} else {
			cur = cur + "/" + seg
		}
		fi, err := root.Lstat(cur)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return domain.Unprocessable("UNSAFE_SYMLINK", "destination directory path contains symlink")
			}
			if !fi.IsDir() {
				return domain.Unprocessable("ARCHIVE_PATH_COLLISION", "intermediate destination path is not a directory")
			}
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return mapDestFSError(err, "failed inspecting destination directory")
		}
		if mkErr := root.Mkdir(cur, 0o755); mkErr != nil {
			if !errors.Is(mkErr, fs.ErrExist) {
				return mapDestFSError(mkErr, "failed creating destination directory")
			}
		} else if createdDirs != nil {
			*createdDirs = append(*createdDirs, cur)
		}
		fi, err = root.Lstat(cur)
		if err != nil {
			return mapDestFSError(err, "failed verifying created destination directory")
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return domain.Unprocessable("UNSAFE_SYMLINK", "destination directory path became a symlink")
		}
		if !fi.IsDir() {
			return domain.Unprocessable("ARCHIVE_PATH_COLLISION", "created destination path is not a directory")
		}
	}
	return nil
}

func isRootEscapeErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "escapes from parent")
}
