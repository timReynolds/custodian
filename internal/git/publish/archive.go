package publish

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
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	defaultMaxCompressedBytes   int64 = 64 << 20
	defaultMaxUncompressedBytes int64 = 64 << 20
	defaultMaxSingleFileBytes   int64 = 32 << 20
	defaultMaxEntries           int   = 10_000
	defaultMaxPathBytes         int   = 4096
	defaultMaxPathDepth         int   = 64
)

var (
	errCompressedLimitExceeded   = errors.New("compressed archive size limit exceeded")
	errUncompressedLimitExceeded = errors.New("uncompressed archive size limit exceeded")
)

// ArchiveLimits configures bounds for extracting CANONICAL_TREE .tar.gz archives.
type ArchiveLimits struct {
	MaxCompressedBytes   int64
	MaxUncompressedBytes int64
	MaxSingleFileBytes   int64
	MaxEntries           int
	MaxPathBytes         int
	MaxPathDepth         int
}

func (l ArchiveLimits) withDefaults() ArchiveLimits {
	if l.MaxCompressedBytes <= 0 {
		l.MaxCompressedBytes = defaultMaxCompressedBytes
	}
	if l.MaxUncompressedBytes <= 0 {
		l.MaxUncompressedBytes = defaultMaxUncompressedBytes
	}
	if l.MaxSingleFileBytes <= 0 {
		l.MaxSingleFileBytes = defaultMaxSingleFileBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = defaultMaxEntries
	}
	if l.MaxPathBytes <= 0 {
		l.MaxPathBytes = defaultMaxPathBytes
	}
	if l.MaxPathDepth <= 0 {
		l.MaxPathDepth = defaultMaxPathDepth
	}
	return l
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
		p = p[:int(rem)]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
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
	return ct.caser.String(norm.NFC.String(seg))
}

func (ct *collisionTracker) add(cleanPath string, isDir bool) error {
	segs := strings.Split(cleanPath, "/")
	foldedSegs := make([]string, len(segs))
	for i, seg := range segs {
		foldedSegs[i] = ct.foldSegment(seg)
	}

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

func extractCanonicalTree(ctx context.Context, r io.Reader, expectedSize int64, expectedSHA256 string, destDir string, limits ArchiveLimits) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return domain.BadRequest("MISSING_CANONICAL_TREE", "canonical tree reader must not be nil")
	}
	cfg := limits.withDefaults()

	var normExpectedSHA string
	if strings.TrimSpace(expectedSHA256) != "" {
		var err error
		normExpectedSHA, err = domain.ParseSHA256Digest(expectedSHA256)
		if err != nil {
			return err
		}
	}

	root, err := os.OpenRoot(destDir)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "PUBLISH_ROOT_FAILED", "failed opening publish working tree root", err)
	}
	defer root.Close()

	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)
	compReader := &ctxLimitedReader{
		ctx:      ctx,
		r:        tee,
		max:      cfg.MaxCompressedBytes,
		limitErr: errCompressedLimitExceeded,
	}
	br := bufio.NewReader(compReader)
	gz, err := gzip.NewReader(br)
	if err != nil {
		if errors.Is(err, errCompressedLimitExceeded) {
			return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree archive exceeds compressed byte limit")
		}
		var domErr *domain.DomainError
		if errors.As(err, &domErr) {
			return domErr
		}
		return domain.WrapError(domain.ErrUnprocessable, "CORRUPT_CANONICAL_TREE", "failed opening gzip canonical tree archive", err)
	}
	gzClosed := false
	defer func() {
		if !gzClosed {
			_ = gz.Close()
		}
	}()

	uncompReader := &ctxLimitedReader{
		ctx:      ctx,
		r:        gz,
		max:      cfg.MaxUncompressedBytes,
		limitErr: errUncompressedLimitExceeded,
	}
	tr := tar.NewReader(uncompReader)
	tracker := newCollisionTracker()
	entryCount := 0

	for {
		if err := ctx.Err(); err != nil {
			return domain.WrapError(domain.ErrUnavailable, "ARCHIVE_ABORTED", "canonical tree extraction aborted", err)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, errUncompressedLimitExceeded) || errors.Is(err, errCompressedLimitExceeded) {
				return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree archive exceeds size limit")
			}
			var domErr *domain.DomainError
			if errors.As(err, &domErr) {
				return err
			}
			return domain.WrapError(domain.ErrUnprocessable, "CORRUPT_CANONICAL_TREE", "failed reading canonical tree tar entry", err)
		}

		entryCount++
		if entryCount > cfg.MaxEntries {
			return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", fmt.Sprintf("canonical tree entry count exceeds limit %d", cfg.MaxEntries))
		}

		isDir, err := validateCanonicalTarHeader(hdr)
		if err != nil {
			return err
		}
		cleanPath, isRootDir, err := normalizeCanonicalTarPath(hdr.Name, hdr.Typeflag, cfg.MaxPathBytes, cfg.MaxPathDepth)
		if err != nil {
			return err
		}
		if isRootDir {
			continue
		}
		if err := tracker.add(cleanPath, isDir); err != nil {
			return err
		}

		if isDir {
			if err := mkdirAllInRoot(root, cleanPath); err != nil {
				return err
			}
			continue
		}

		if hdr.Size > cfg.MaxSingleFileBytes || hdr.Size > cfg.MaxUncompressedBytes || uncompReader.n > cfg.MaxUncompressedBytes-hdr.Size {
			return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree file exceeds uncompressed size limit")
		}

		if parent := path.Dir(cleanPath); parent != "." {
			if err := mkdirAllInRoot(root, parent); err != nil {
				return err
			}
		}

		fileMode := os.FileMode(0o644)
		if hdr.Mode&0o111 != 0 {
			fileMode = 0o755
		}
		f, err := root.OpenFile(cleanPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, fileMode)
		if err != nil {
			return domain.WrapError(domain.ErrUnprocessable, "CANONICAL_TREE_WRITE_FAILED", "failed creating canonical tree file", err)
		}

		copied, copyErr := io.CopyN(f, tr, hdr.Size)
		if copyErr == nil {
			var extra [1]byte
			if n, eofErr := tr.Read(extra[:]); n > 0 || (eofErr != nil && !errors.Is(eofErr, io.EOF)) {
				_ = f.Close()
				return domain.Unprocessable("CORRUPT_CANONICAL_TREE", "tar file payload does not match declared header size")
			}
		}
		chmodErr := f.Chmod(fileMode)
		closeErr := f.Close()
		if copyErr != nil {
			if errors.Is(copyErr, errUncompressedLimitExceeded) || errors.Is(copyErr, errCompressedLimitExceeded) {
				return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree archive exceeds size limit")
			}
			var domErr *domain.DomainError
			if errors.As(copyErr, &domErr) {
				return domErr
			}
			return domain.WrapError(domain.ErrUnprocessable, "CORRUPT_CANONICAL_TREE", "failed extracting canonical tree file", copyErr)
		}
		if copied != hdr.Size {
			return domain.Unprocessable("CORRUPT_CANONICAL_TREE", "truncated canonical tree file entry")
		}
		if chmodErr != nil {
			return domain.WrapError(domain.ErrInternal, "CANONICAL_TREE_WRITE_FAILED", "failed setting canonical file permissions", chmodErr)
		}
		if closeErr != nil {
			return domain.WrapError(domain.ErrInternal, "CANONICAL_TREE_WRITE_FAILED", "failed closing canonical file", closeErr)
		}
	}

	// Drain the uncompressed gzip stream first so gzip CRC32/ISIZE trailers and any
	// trailing gzip members are validated and bounded by MaxUncompressedBytes.
	if _, err := io.Copy(io.Discard, uncompReader); err != nil {
		if errors.Is(err, errUncompressedLimitExceeded) || errors.Is(err, errCompressedLimitExceeded) {
			return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree archive exceeds size limit")
		}
		var domErr *domain.DomainError
		if errors.As(err, &domErr) {
			return err
		}
		return domain.WrapError(domain.ErrUnprocessable, "CORRUPT_CANONICAL_TREE", "failed reading canonical tree gzip stream", err)
	}
	gzClosed = true
	if err := gz.Close(); err != nil {
		if errors.Is(err, errUncompressedLimitExceeded) || errors.Is(err, errCompressedLimitExceeded) {
			return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree archive exceeds size limit")
		}
		var domErr *domain.DomainError
		if errors.As(err, &domErr) {
			return err
		}
		return domain.WrapError(domain.ErrUnprocessable, "CORRUPT_CANONICAL_TREE", "failed closing canonical tree gzip stream", err)
	}

	// Drain any remaining compressed trailer bytes so SHA-256 and byte count cover the full archive.
	if _, err := io.Copy(io.Discard, compReader); err != nil {
		if errors.Is(err, errCompressedLimitExceeded) {
			return domain.Unprocessable("ARCHIVE_LIMIT_EXCEEDED", "canonical tree archive exceeds compressed byte limit")
		}
		var domErr *domain.DomainError
		if errors.As(err, &domErr) {
			return err
		}
		return domain.WrapError(domain.ErrUnprocessable, "CORRUPT_CANONICAL_TREE", "failed draining canonical tree archive stream", err)
	}

	if expectedSize > 0 && compReader.n != expectedSize {
		return domain.Conflict("CANONICAL_TREE_SIZE_MISMATCH", fmt.Sprintf("canonical tree archive size %d does not match expected %d", compReader.n, expectedSize))
	}
	if normExpectedSHA != "" {
		actualSHA := hex.EncodeToString(hasher.Sum(nil))
		if actualSHA != normExpectedSHA {
			return domain.Conflict("CANONICAL_TREE_DIGEST_MISMATCH", "canonical tree archive sha256 does not match expected digest")
		}
	}
	return nil
}

func validateCanonicalTarHeader(hdr *tar.Header) (isDir bool, err error) {
	if hdr == nil {
		return false, domain.Unprocessable("CORRUPT_CANONICAL_TREE", "nil tar header")
	}
	if hdr.Size < 0 {
		return false, domain.Unprocessable("CORRUPT_CANONICAL_TREE", "negative tar entry size")
	}
	if hdr.Devmajor != 0 || hdr.Devminor != 0 {
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "device major/minor numbers are not permitted")
	}
	if hdr.Linkname != "" {
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "link targets are not permitted in canonical tree")
	}
	ifmt := hdr.Mode & 0o170000
	if ifmt == 0o160000 {
		return false, domain.Unprocessable("SUBMODULE_NOT_ALLOWED", "gitlink submodule entries are not permitted")
	}
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeRegA:
		if ifmt != 0 && ifmt != 0o100000 {
			return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "invalid POSIX mode bits on regular file")
		}
		return false, nil
	case tar.TypeDir:
		if ifmt != 0 && ifmt != 0o040000 {
			return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "invalid POSIX mode bits on directory")
		}
		if hdr.Size != 0 {
			return false, domain.Unprocessable("CORRUPT_CANONICAL_TREE", "directory entry must have zero byte size")
		}
		return true, nil
	case tar.TypeSymlink:
		return false, domain.Unprocessable("UNSAFE_SYMLINK", "symlinks are not permitted in canonical tree")
	case tar.TypeLink:
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "hardlinks are not permitted in canonical tree")
	case tar.TypeFifo, tar.TypeChar, tar.TypeBlock:
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", "special device or FIFO entries are not permitted")
	default:
		return false, domain.Unprocessable("UNSAFE_FILE_TYPE", fmt.Sprintf("unsupported tar entry type %q", hdr.Typeflag))
	}
}

func normalizeCanonicalTarPath(rawName string, typeflag byte, maxPathBytes, maxPathDepth int) (cleanPath string, isRootDir bool, err error) {
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
	if name == "" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path contains empty segment")
	}
	if hasVolumeOrDrivePrefix(name) {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must not include a volume name")
	}

	segs := strings.Split(name, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path contains traversal or empty segment")
		}
		if strings.EqualFold(seg, ".git") {
			return "", false, domain.Unprocessable("UNSAFE_GIT_PATH", ".git entries are not permitted in canonical tree")
		}
	}

	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path escapes root")
	}
	if hasVolumeOrDrivePrefix(clean) {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive entry path must not include a volume name")
	}
	if len(clean) > maxPathBytes {
		return "", false, domain.Unprocessable("ARCHIVE_PATH_TOO_LONG", "normalized archive path exceeds maximum byte length")
	}
	if len(segs) > maxPathDepth {
		return "", false, domain.Unprocessable("UNSAFE_ARCHIVE_PATH", fmt.Sprintf("archive path depth %d exceeds limit %d", len(segs), maxPathDepth))
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

func mkdirAllInRoot(root *os.Root, relDir string) error {
	if relDir == "" || relDir == "." {
		return nil
	}
	parts := strings.Split(relDir, "/")
	curr := ""
	for _, p := range parts {
		if curr == "" {
			curr = p
		} else {
			curr = curr + "/" + p
		}
		if err := root.Mkdir(curr, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return domain.WrapError(domain.ErrUnprocessable, "CANONICAL_TREE_WRITE_FAILED", "failed creating canonical directory", err)
		}
	}
	return nil
}
