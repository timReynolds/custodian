package snapshots

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	metaDirName = ".custodian-meta"
	metaSubDir  = ".custodian-meta/meta"
	tmpSubDir   = ".custodian-meta/tmp"
	locksSubDir = ".custodian-meta/locks"
)

// LocalConfig configures a filesystem-backed domain.SnapshotStore.
type LocalConfig struct {
	RootDir string
	Logger  *slog.Logger
}

type keyLockEntry struct {
	mu   sync.Mutex
	refs int
}

// LocalStore implements domain.SnapshotStore on the local filesystem with
// atomic commits, generation preconditions, symlink rejection, and streaming SHA-256 verification.
type LocalStore struct {
	realRoot string
	logger   *slog.Logger

	mu    sync.Mutex
	locks map[string]*keyLockEntry
}

var _ domain.SnapshotStore = (*LocalStore)(nil)

type localObjectMeta struct {
	ID         uuid.UUID           `json:"id"`
	Kind       domain.ArtifactKind `json:"kind"`
	SHA256     string              `json:"sha256"`
	StorageKey string              `json:"storage_key"`
	Generation int64               `json:"generation"`
	SizeBytes  int64               `json:"size_bytes"`
	CreatedAt  time.Time           `json:"created_at"`
}

// NewLocalStore initializes a LocalStore rooted at cfg.RootDir.
func NewLocalStore(cfg LocalConfig) (*LocalStore, error) {
	trimmed := strings.TrimSpace(cfg.RootDir)
	if trimmed == "" {
		return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "local root directory is required")
	}
	absRoot, err := filepath.Abs(trimmed)
	if err != nil {
		return nil, mapLocalError(err)
	}
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		return nil, mapLocalError(err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, mapLocalError(err)
	}
	if !info.IsDir() {
		return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "local root path must be a directory")
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, mapLocalError(err)
	}
	return &LocalStore{
		realRoot: realRoot,
		logger:   cfg.Logger,
		locks:    make(map[string]*keyLockEntry),
	}, nil
}

func (s *LocalStore) lockKey(foldedKey string) func() {
	s.mu.Lock()
	entry, ok := s.locks[foldedKey]
	if !ok {
		entry = &keyLockEntry{}
		s.locks[foldedKey] = entry
	}
	entry.refs++
	s.mu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.locks, foldedKey)
		}
		s.mu.Unlock()
	}
}

func (s *LocalStore) openRoot() (*os.Root, error) {
	info, err := os.Lstat(s.realRoot)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, domain.WrapError(domain.ErrBadRequest, "SYMLINK_ESCAPE", "local snapshot root must not traverse symlinks", err)
		}
		return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot root is unavailable", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, domain.BadRequest("SYMLINK_ESCAPE", "local snapshot root must not be a symlink")
	}
	resolved, err := filepath.EvalSymlinks(s.realRoot)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, domain.WrapError(domain.ErrBadRequest, "SYMLINK_ESCAPE", "local snapshot root must not traverse symlinks", err)
		}
		return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot root is unavailable", err)
	}
	if resolved != s.realRoot {
		return nil, domain.BadRequest("SYMLINK_ESCAPE", "local snapshot root path must not traverse symlinks")
	}
	root, err := os.OpenRoot(s.realRoot)
	if err != nil {
		return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot root is unavailable", err)
	}
	return root, nil
}

func flockExclusive(fd int) error {
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

// acquireKeyFlock acquires an exclusive advisory lock on a per-folded-key lockfile
// under .custodian-meta/locks/ using an unlink-safe inode-verification loop.
// On unlock, the lockfile is removed while still holding LOCK_EX so unused lockfiles
// do not accumulate or alter SnapshotStoreHelper.ObjectCount() deltas.
func acquireKeyFlock(ctx context.Context, root *os.Root, foldedKey string) (func(), error) {
	sum := sha256.Sum256([]byte(foldedKey))
	lockRel := path.Join(locksSubDir, hex.EncodeToString(sum[:])+".lock")
	for {
		if err := ctx.Err(); err != nil {
			return nil, mapContextError(err)
		}
		if err := ensureNoSymlinks(root, lockRel); err != nil {
			return nil, err
		}
		f, err := root.OpenFile(lockRel, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Concurrent Remove(lockRel) + OpenFile(O_CREATE) on BSD/macOS can surface ENOENT
				// if the file is unlinked between kernel lookup and open. Retry while locksSubDir exists.
				if dirInfo, dirErr := root.Lstat(locksSubDir); dirErr == nil && dirInfo.IsDir() {
					continue
				} else if dirErr != nil {
					if isRootEscapeErr(dirErr) || errors.Is(dirErr, syscall.ELOOP) {
						return nil, domain.BadRequest("SYMLINK_NOT_ALLOWED", "lock path must not be a symlink")
					}
					return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot lock directory is unavailable", dirErr)
				}
				return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot lock directory is unavailable", err)
			}
			if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
				return nil, domain.BadRequest("SYMLINK_NOT_ALLOWED", "lock path must not be a symlink")
			}
			return nil, mapLocalError(err)
		}
		if err := flockExclusive(int(f.Fd())); err != nil {
			_ = f.Close()
			return nil, mapLocalError(err)
		}
		fiLock, err := f.Stat()
		if err != nil {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return nil, mapLocalError(err)
		}
		fiPath, err := root.Lstat(lockRel)
		if err == nil {
			if fiPath.Mode()&os.ModeSymlink != 0 {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
				return nil, domain.BadRequest("SYMLINK_NOT_ALLOWED", "lock path must not be a symlink")
			}
			if os.SameFile(fiLock, fiPath) {
				return func() {
					_ = root.Remove(lockRel)
					_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
					_ = f.Close()
				}, nil
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
				return nil, domain.BadRequest("SYMLINK_NOT_ALLOWED", "lock path must not be a symlink")
			}
			return nil, mapLocalError(err)
		}
		// Lockfile was unlinked or replaced before we obtained LOCK_EX; retry on fresh inode.
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

func validateLocalKey(rawKey string) (string, error) {
	cleanKey, err := ValidateObjectKey(rawKey)
	if err != nil {
		return "", err
	}
	for _, seg := range strings.Split(cleanKey, "/") {
		if strings.EqualFold(seg, metaDirName) {
			return "", domain.BadRequest("RESERVED_OBJECT_KEY", "object key must not target reserved metadata prefix")
		}
	}
	return cleanKey, nil
}

// canonicalFold maps s to a deterministic canonical Unicode simple-case-folded form
// such that canonicalFold(a) == canonicalFold(b) iff strings.EqualFold(a, b).
func canonicalFold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		minR := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < minR {
				minR = f
			}
		}
		b.WriteRune(minR)
	}
	return b.String()
}

func metaRelPathFor(foldedKey string) string {
	sum := sha256.Sum256([]byte(foldedKey))
	return path.Join(metaSubDir, hex.EncodeToString(sum[:])+".json")
}

func (s *LocalStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return domain.Artifact{}, mapContextError(err)
	}
	if !req.Kind.IsValid() {
		return domain.Artifact{}, domain.BadRequest("INVALID_ARTIFACT_KIND", "artifact kind is invalid")
	}
	cleanKey, err := validateLocalKey(req.ObjectKey)
	if err != nil {
		return domain.Artifact{}, err
	}
	if r == nil {
		return domain.Artifact{}, domain.BadRequest("INVALID_READER", "put reader must not be nil")
	}
	if size < 0 || req.MaxBytes < 0 {
		return domain.Artifact{}, domain.BadRequest("INVALID_SIZE", "size and max_bytes must be non-negative")
	}
	if req.MaxBytes > 0 && size > req.MaxBytes {
		return domain.Artifact{}, domain.Unprocessable("SIZE_LIMIT_EXCEEDED", "artifact size exceeds maximum allowed bytes")
	}

	var expectedSHA string
	if req.ExpectedSHA256 != "" {
		expectedSHA, err = domain.ParseSHA256Digest(req.ExpectedSHA256)
		if err != nil {
			return domain.Artifact{}, err
		}
	}

	var wantGen int64
	if req.Generation != nil {
		if *req.Generation < 0 {
			return domain.Artifact{}, domain.BadRequest("INVALID_GENERATION", "generation precondition must be non-negative")
		}
		wantGen = *req.Generation
	}

	foldedKey := canonicalFold(cleanKey)
	unlock := s.lockKey(foldedKey)
	defer unlock()

	root, err := s.openRoot()
	if err != nil {
		return domain.Artifact{}, err
	}
	defer root.Close()

	if err := ensureNoSymlinks(root, cleanKey); err != nil {
		return domain.Artifact{}, err
	}
	if err := ensureNoSymlinks(root, tmpSubDir); err != nil {
		return domain.Artifact{}, err
	}
	if err := ensureNoSymlinks(root, metaSubDir); err != nil {
		return domain.Artifact{}, err
	}
	if err := ensureNoSymlinks(root, locksSubDir); err != nil {
		return domain.Artifact{}, err
	}

	if err := mkdirAllNoSymlink(root, locksSubDir); err != nil {
		return domain.Artifact{}, err
	}
	unlockFlock, err := acquireKeyFlock(ctx, root, foldedKey)
	if err != nil {
		return domain.Artifact{}, err
	}
	defer unlockFlock()

	metaRel := metaRelPathFor(foldedKey)
	oldMeta, hasMeta, err := readMeta(root, metaRel)
	if err != nil {
		return domain.Artifact{}, err
	}

	var nextGen int64
	if wantGen == 0 {
		if hasMeta {
			return domain.Artifact{}, domain.Conflict("OBJECT_ALREADY_EXISTS", "snapshot object already exists")
		}
		if _, statErr := root.Lstat(cleanKey); statErr == nil {
			return domain.Artifact{}, domain.Conflict("OBJECT_ALREADY_EXISTS", "snapshot object already exists")
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			if isRootEscapeErr(statErr) || errors.Is(statErr, syscall.ELOOP) {
				return domain.Artifact{}, domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks")
			}
			return domain.Artifact{}, mapLocalError(statErr)
		}
		nextGen = 1
	} else {
		if !hasMeta || oldMeta.Generation != wantGen || (oldMeta.StorageKey != "" && oldMeta.StorageKey != cleanKey) {
			return domain.Artifact{}, domain.Conflict("OBJECT_PRECONDITION_FAILED", "snapshot generation precondition failed")
		}
		nextGen = oldMeta.Generation + 1
	}

	if err := mkdirAllNoSymlink(root, tmpSubDir); err != nil {
		return domain.Artifact{}, err
	}
	if err := mkdirAllNoSymlink(root, metaSubDir); err != nil {
		return domain.Artifact{}, err
	}

	id, err := domain.NewID()
	if err != nil {
		return domain.Artifact{}, domain.WrapError(domain.ErrInternal, "ID_GENERATION_FAILED", "failed to generate artifact ID", err)
	}

	tmpBlobRel := path.Join(tmpSubDir, id.String()+".blob")
	tmpMetaRel := path.Join(tmpSubDir, id.String()+".meta")

	tmpFile, err := root.OpenFile(tmpBlobRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return domain.Artifact{}, mapLocalError(err)
	}
	blobCommitted := false
	defer func() {
		if !blobCommitted {
			_ = root.Remove(tmpBlobRel)
		}
	}()

	hasher := sha256.New()
	cr := &ctxReader{ctx: ctx, r: r}
	limited := io.LimitReader(cr, size)
	tee := io.TeeReader(limited, hasher)
	ew := &writeTracker{w: tmpFile}

	written, copyErr := io.Copy(ew, tee)
	if copyErr != nil {
		_ = tmpFile.Close()
		if ew.err != nil {
			return domain.Artifact{}, mapLocalError(ew.err)
		}
		if ctx.Err() != nil {
			return domain.Artifact{}, mapContextError(ctx.Err())
		}
		return domain.Artifact{}, domain.WrapError(domain.ErrBadRequest, "STREAM_READ_ERROR", "failed reading artifact stream", copyErr)
	}
	if written != size {
		_ = tmpFile.Close()
		return domain.Artifact{}, domain.Unprocessable("SIZE_MISMATCH", "artifact stream ended before declared size")
	}

	const maxEmptyTrailingReads = 100
	var extra [1]byte
	for emptyReads := 0; ; emptyReads++ {
		if err := ctx.Err(); err != nil {
			_ = tmpFile.Close()
			return domain.Artifact{}, mapContextError(err)
		}
		extraN, extraErr := r.Read(extra[:])
		if extraN > 0 {
			_ = tmpFile.Close()
			return domain.Artifact{}, domain.Unprocessable("SIZE_MISMATCH", "artifact stream exceeded declared size")
		}
		if extraErr == io.EOF {
			break
		}
		if extraErr != nil {
			_ = tmpFile.Close()
			if ctx.Err() != nil {
				return domain.Artifact{}, mapContextError(ctx.Err())
			}
			return domain.Artifact{}, domain.WrapError(domain.ErrBadRequest, "STREAM_READ_ERROR", "failed reading artifact stream", extraErr)
		}
		if emptyReads+1 >= maxEmptyTrailingReads {
			_ = tmpFile.Close()
			return domain.Artifact{}, domain.BadRequest("STREAM_READ_ERROR", "artifact stream exceeded consecutive empty reads")
		}
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		_ = tmpFile.Close()
		return domain.Artifact{}, domain.Unprocessable("DIGEST_MISMATCH", "artifact SHA-256 digest does not match expected digest")
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return domain.Artifact{}, mapLocalError(err)
	}
	if err := tmpFile.Close(); err != nil {
		return domain.Artifact{}, mapLocalError(err)
	}

	now := time.Now().UTC()
	meta := localObjectMeta{
		ID:         id,
		Kind:       req.Kind,
		SHA256:     actualSHA,
		StorageKey: cleanKey,
		Generation: nextGen,
		SizeBytes:  written,
		CreatedAt:  now,
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return domain.Artifact{}, domain.WrapError(domain.ErrInternal, "META_ENCODE_FAILED", "failed to encode snapshot metadata", err)
	}

	metaCommitted := false
	defer func() {
		if !metaCommitted {
			_ = root.Remove(tmpMetaRel)
		}
	}()
	if err := writeExclusiveFile(root, tmpMetaRel, metaBytes, 0o600); err != nil {
		return domain.Artifact{}, mapLocalError(err)
	}

	if parent := path.Dir(cleanKey); parent != "." {
		if err := mkdirAllNoSymlink(root, parent); err != nil {
			return domain.Artifact{}, err
		}
	}

	if nextGen == 1 {
		if err := root.Link(tmpMetaRel, metaRel); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return domain.Artifact{}, domain.Conflict("OBJECT_ALREADY_EXISTS", "snapshot object already exists")
			}
			return domain.Artifact{}, mapLocalError(err)
		}
		if err := root.Link(tmpBlobRel, cleanKey); err != nil {
			_ = root.Remove(metaRel)
			if errors.Is(err, fs.ErrExist) {
				return domain.Artifact{}, domain.Conflict("OBJECT_ALREADY_EXISTS", "snapshot object already exists")
			}
			return domain.Artifact{}, mapLocalError(err)
		}
		// Extra temp hardlinks are removed by deferred cleanup when not marked committed.
	} else {
		backupBlobRel := path.Join(tmpSubDir, id.String()+".bak")
		backupCreated := false
		defer func() {
			if backupCreated {
				_ = root.Remove(backupBlobRel)
			}
		}()
		if linkErr := root.Link(cleanKey, backupBlobRel); linkErr == nil {
			backupCreated = true
		} else if !errors.Is(linkErr, fs.ErrNotExist) {
			if isRootEscapeErr(linkErr) || errors.Is(linkErr, syscall.ELOOP) {
				return domain.Artifact{}, domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks")
			}
			return domain.Artifact{}, mapLocalError(linkErr)
		}

		if err := root.Rename(tmpBlobRel, cleanKey); err != nil {
			return domain.Artifact{}, mapLocalError(err)
		}
		blobCommitted = true
		if err := root.Rename(tmpMetaRel, metaRel); err != nil {
			if backupCreated {
				_ = root.Rename(backupBlobRel, cleanKey)
			} else {
				_ = root.Remove(cleanKey)
			}
			return domain.Artifact{}, mapLocalError(err)
		}
		metaCommitted = true
	}

	artifact := domain.Artifact{
		ID:                id,
		Kind:              req.Kind,
		SHA256:            actualSHA,
		StorageKey:        cleanKey,
		StorageGeneration: strconv.FormatInt(nextGen, 10),
		SizeBytes:         written,
		CreatedAt:         now,
	}
	s.logArtifact("snapshot_put", artifact)
	return artifact, nil
}

func (s *LocalStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, mapContextError(err)
	}
	cleanKey, err := validateLocalKey(artifact.StorageKey)
	if err != nil {
		return nil, err
	}

	var expectedSHA string
	if artifact.SHA256 != "" {
		expectedSHA, err = domain.ParseSHA256Digest(artifact.SHA256)
		if err != nil {
			return nil, err
		}
	}

	var wantGen int64
	if artifact.StorageGeneration != "" {
		wantGen, err = parsePositiveGen(artifact.StorageGeneration)
		if err != nil {
			return nil, err
		}
	}

	foldedKey := canonicalFold(cleanKey)
	unlock := s.lockKey(foldedKey)
	defer unlock()

	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()

	if err := ensureNoSymlinks(root, cleanKey); err != nil {
		return nil, err
	}
	if err := ensureNoSymlinks(root, metaSubDir); err != nil {
		return nil, err
	}
	if err := ensureNoSymlinks(root, locksSubDir); err != nil {
		return nil, err
	}

	if err := mkdirAllNoSymlink(root, locksSubDir); err != nil {
		return nil, err
	}
	unlockFlock, err := acquireKeyFlock(ctx, root, foldedKey)
	if err != nil {
		return nil, err
	}
	defer unlockFlock()

	metaRel := metaRelPathFor(foldedKey)
	meta, hasMeta, err := readMeta(root, metaRel)
	if err != nil {
		return nil, err
	}

	if hasMeta && meta.StorageKey != "" && meta.StorageKey != cleanKey {
		return nil, domain.NotFound("OBJECT_NOT_FOUND", "snapshot object not found")
	}

	if hasMeta && wantGen > 0 && meta.Generation != wantGen {
		return nil, domain.Conflict("OBJECT_PRECONDITION_FAILED", "snapshot generation precondition failed")
	}

	f, err := root.OpenFile(cleanKey, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, domain.NotFound("OBJECT_NOT_FOUND", "snapshot object not found")
		}
		if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
			return nil, domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not target a symlink")
		}
		return nil, mapLocalError(err)
	}

	if !hasMeta && wantGen > 0 {
		_ = f.Close()
		return nil, domain.Conflict("OBJECT_PRECONDITION_FAILED", "snapshot generation precondition failed")
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, mapLocalError(err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, domain.BadRequest("INVALID_OBJECT_PATH", "snapshot object is not a regular file")
	}

	if artifact.SizeBytes >= 0 && fi.Size() != artifact.SizeBytes {
		_ = f.Close()
		return nil, domain.Unprocessable("SIZE_MISMATCH", "stored object size does not match artifact size")
	}

	expectedSize := artifact.SizeBytes
	if expectedSize < 0 {
		if hasMeta {
			expectedSize = meta.SizeBytes
		} else {
			expectedSize = -1
		}
	}
	if expectedSHA == "" && hasMeta {
		expectedSHA = meta.SHA256
	}

	return newVerifyingReadCloser(f, expectedSHA, expectedSize), nil
}

func (s *LocalStore) Verify(ctx context.Context, artifact domain.Artifact) error {
	if _, err := validateLocalKey(artifact.StorageKey); err != nil {
		return err
	}
	if artifact.SHA256 == "" && artifact.SizeBytes <= 0 {
		return domain.BadRequest("MISSING_VERIFICATION_EXPECTATION", "verify requires expected sha256 or positive size_bytes")
	}
	rc, err := s.Open(ctx, artifact)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(io.Discard, rc)
	closeErr := rc.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func (s *LocalStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return mapContextError(err)
	}
	cleanKey, err := validateLocalKey(artifact.StorageKey)
	if err != nil {
		return err
	}

	var wantGen int64
	if artifact.StorageGeneration != "" {
		wantGen, err = parsePositiveGen(artifact.StorageGeneration)
		if err != nil {
			return err
		}
	}

	foldedKey := canonicalFold(cleanKey)
	unlock := s.lockKey(foldedKey)
	defer unlock()

	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	if err := ensureNoSymlinks(root, cleanKey); err != nil {
		return err
	}
	if err := ensureNoSymlinks(root, metaSubDir); err != nil {
		return err
	}
	if err := ensureNoSymlinks(root, locksSubDir); err != nil {
		return err
	}

	if err := mkdirAllNoSymlink(root, locksSubDir); err != nil {
		return err
	}
	unlockFlock, err := acquireKeyFlock(ctx, root, foldedKey)
	if err != nil {
		return err
	}
	defer unlockFlock()

	metaRel := metaRelPathFor(foldedKey)
	meta, hasMeta, err := readMeta(root, metaRel)
	if err != nil {
		return err
	}

	if hasMeta && meta.StorageKey != "" && meta.StorageKey != cleanKey {
		return domain.NotFound("OBJECT_NOT_FOUND", "snapshot object not found")
	}

	if !hasMeta {
		fi, statErr := root.Lstat(cleanKey)
		if statErr != nil {
			if errors.Is(statErr, fs.ErrNotExist) {
				return domain.NotFound("OBJECT_NOT_FOUND", "snapshot object not found")
			}
			return mapLocalError(statErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not target a symlink")
		}
		if fi.IsDir() || !fi.Mode().IsRegular() {
			return domain.BadRequest("INVALID_OBJECT_PATH", "snapshot object path must be a regular file")
		}
		if wantGen > 0 {
			return domain.Conflict("OBJECT_PRECONDITION_FAILED", "snapshot generation precondition failed")
		}
		if err := root.Remove(cleanKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return mapLocalError(err)
		}
		s.logArtifact("snapshot_deleted", artifact)
		return nil
	}

	if wantGen > 0 && meta.Generation != wantGen {
		return domain.Conflict("OBJECT_PRECONDITION_FAILED", "snapshot generation precondition failed")
	}

	targetKey := meta.StorageKey
	if targetKey == "" {
		targetKey = cleanKey
	}
	if err := root.Remove(targetKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return mapLocalError(err)
	}
	if cleanKey != targetKey {
		if err := root.Remove(cleanKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return mapLocalError(err)
		}
	}
	if err := root.Remove(metaRel); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return mapLocalError(err)
	}

	s.logArtifact("snapshot_deleted", artifact)
	return nil
}

func (s *LocalStore) logArtifact(msg string, a domain.Artifact) {
	if s.logger == nil {
		return
	}
	s.logger.Info(msg,
		"artifact_id", a.ID.String(),
		"sha256", a.SHA256,
		"generation", a.StorageGeneration,
		"size_bytes", a.SizeBytes,
	)
}

func readMeta(root *os.Root, metaRel string) (localObjectMeta, bool, error) {
	f, err := root.OpenFile(metaRel, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return localObjectMeta{}, false, nil
		}
		if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
			return localObjectMeta{}, false, domain.BadRequest("SYMLINK_NOT_ALLOWED", "metadata path must not be a symlink")
		}
		return localObjectMeta{}, false, mapLocalError(err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return localObjectMeta{}, false, mapLocalError(err)
	}
	var meta localObjectMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return localObjectMeta{}, false, domain.WrapError(domain.ErrUnavailable, "STORAGE_CORRUPT", "failed to decode snapshot metadata", err)
	}
	return meta, true, nil
}

func writeExclusiveFile(root *os.Root, relPath string, data []byte, perm fs.FileMode) error {
	f, err := root.OpenFile(relPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func ensureNoSymlinks(root *os.Root, relSlashPath string) error {
	if relSlashPath == "" || relSlashPath == "." {
		return nil
	}
	parts := strings.Split(relSlashPath, "/")
	cur := ""
	for i, seg := range parts {
		if cur == "" {
			cur = seg
		} else {
			cur = cur + "/" + seg
		}
		fi, err := root.Lstat(cur)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
				return domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks")
			}
			return mapLocalError(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse or target symlinks")
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return domain.BadRequest("INVALID_OBJECT_PATH", "intermediate object path component is not a directory")
		}
	}
	return nil
}

func mkdirAllNoSymlink(root *os.Root, relSlashDir string) error {
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
				return domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks")
			}
			if !fi.IsDir() {
				return domain.BadRequest("INVALID_OBJECT_PATH", "intermediate object path component is not a directory")
			}
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
				return domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks")
			}
			return mapLocalError(err)
		}
		if mkErr := root.Mkdir(cur, 0o755); mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
			return mapLocalError(mkErr)
		}
		fi, err = root.Lstat(cur)
		if err != nil {
			return mapLocalError(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return domain.BadRequest("SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks")
		}
		if !fi.IsDir() {
			return domain.BadRequest("INVALID_OBJECT_PATH", "intermediate object path component is not a directory")
		}
	}
	return nil
}

func isRootEscapeErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "escapes from parent")
}

func mapContextError(err error) error {
	return domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "snapshot operation cancelled or timed out", err)
}

func mapLocalError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return mapContextError(err)
	}
	if isRootEscapeErr(err) || errors.Is(err, syscall.ELOOP) {
		return domain.WrapError(domain.ErrBadRequest, "SYMLINK_NOT_ALLOWED", "object path must not traverse symlinks", err)
	}
	if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EISDIR) {
		return domain.WrapError(domain.ErrBadRequest, "INVALID_OBJECT_PATH", "invalid object path component", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return domain.WrapError(domain.ErrNotFound, "OBJECT_NOT_FOUND", "snapshot object not found", err)
	}
	if errors.Is(err, fs.ErrExist) {
		return domain.WrapError(domain.ErrConflict, "OBJECT_ALREADY_EXISTS", "snapshot object already exists", err)
	}
	if errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EROFS) ||
		errors.Is(err, syscall.EIO) ||
		errors.Is(err, syscall.ENOSPC) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) {
		return domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot storage unavailable", err)
	}
	return domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot storage error", err)
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type writeTracker struct {
	w   io.Writer
	err error
}

func (wt *writeTracker) Write(p []byte) (int, error) {
	n, err := wt.w.Write(p)
	if err != nil {
		wt.err = err
	}
	return n, err
}
