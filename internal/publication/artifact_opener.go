package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/publish"
)

const (
	metaDirName = ".custodian-meta"
	metaSubDir  = ".custodian-meta/meta"
)

// ArtifactOpenerConfig configures the publisher's dedicated read-only ArtifactOpener.
type ArtifactOpenerConfig struct {
	StoreKind    string
	LocalRootDir string
	GCSBucket    string
	GCSPrefix    string
	GCSClient    *storage.Client
	GCSOptions   []option.ClientOption
	Logger       *slog.Logger
}

// NewArtifactOpener constructs a read-only publish.ArtifactOpener for either "local" or "gcs" storage.
// It returns an optional close function to release owned resources (such as a GCS client).
func NewArtifactOpener(ctx context.Context, cfg ArtifactOpenerConfig) (publish.ArtifactOpener, func() error, error) {
	kind := strings.ToLower(strings.TrimSpace(cfg.StoreKind))
	if kind == "" {
		if strings.TrimSpace(cfg.GCSBucket) != "" && strings.TrimSpace(cfg.LocalRootDir) == "" {
			kind = "gcs"
		} else {
			kind = "local"
		}
	}

	switch kind {
	case "local":
		opener, err := NewLocalArtifactOpener(LocalOpenerConfig{
			RootDir: cfg.LocalRootDir,
			Logger:  cfg.Logger,
		})
		if err != nil {
			return nil, nil, err
		}
		return opener, func() error { return nil }, nil
	case "gcs":
		opener, err := NewGCSArtifactOpener(ctx, GCSOpenerConfig{
			Bucket:  cfg.GCSBucket,
			Prefix:  cfg.GCSPrefix,
			Client:  cfg.GCSClient,
			Options: cfg.GCSOptions,
			Logger:  cfg.Logger,
		})
		if err != nil {
			return nil, nil, err
		}
		return opener, opener.Close, nil
	default:
		return nil, nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", fmt.Sprintf("unsupported snapshot store kind %q", kind))
	}
}

// LocalOpenerConfig configures a strictly read-only local filesystem ArtifactOpener.
type LocalOpenerConfig struct {
	RootDir string
	Logger  *slog.Logger
}

type localObjectMeta struct {
	SHA256     string `json:"sha256"`
	StorageKey string `json:"storage_key"`
	Generation int64  `json:"generation"`
	SizeBytes  int64  `json:"size_bytes"`
}

// LocalArtifactOpener implements publish.ArtifactOpener over a local snapshot directory
// in strictly read-only mode without creating lockfiles or importing internal/snapshots.
type LocalArtifactOpener struct {
	realRoot string
	logger   *slog.Logger
}

var _ publish.ArtifactOpener = (*LocalArtifactOpener)(nil)

// NewLocalArtifactOpener initializes a read-only LocalArtifactOpener rooted at cfg.RootDir.
func NewLocalArtifactOpener(cfg LocalOpenerConfig) (*LocalArtifactOpener, error) {
	trimmed := strings.TrimSpace(cfg.RootDir)
	if trimmed == "" {
		return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "local root directory is required")
	}
	absRoot, err := filepath.Abs(trimmed)
	if err != nil {
		return nil, mapLocalError(err)
	}

	realRoot := absRoot
	info, err := os.Lstat(absRoot)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, domain.BadRequest("SYMLINK_ESCAPE", "local snapshot root must not be a symlink")
		}
		if !info.IsDir() {
			return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "local root path must be a directory")
		}
		resolved, evalErr := filepath.EvalSymlinks(absRoot)
		if evalErr != nil {
			if errors.Is(evalErr, syscall.ELOOP) {
				return nil, domain.WrapError(domain.ErrBadRequest, "SYMLINK_ESCAPE", "local snapshot root must not traverse symlinks", evalErr)
			}
			return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "local snapshot root is unavailable", evalErr)
		}
		realRoot = resolved
	} else if errors.Is(err, syscall.ELOOP) {
		return nil, domain.WrapError(domain.ErrBadRequest, "SYMLINK_ESCAPE", "local snapshot root must not traverse symlinks", err)
	} else if errors.Is(err, fs.ErrNotExist) {
		if evalParent, pErr := filepath.EvalSymlinks(filepath.Dir(absRoot)); pErr == nil {
			realRoot = filepath.Join(evalParent, filepath.Base(absRoot))
		}
	}

	return &LocalArtifactOpener{
		realRoot: realRoot,
		logger:   cfg.Logger,
	}, nil
}

func (s *LocalArtifactOpener) openRoot() (*os.Root, error) {
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
	if !info.IsDir() {
		return nil, domain.Unavailable("STORAGE_UNAVAILABLE", "local snapshot root is not a directory")
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

// Open opens and verifies an artifact read-only using os.OpenRoot, O_NOFOLLOW,
// generation metadata checks, size verification, and streaming SHA-256 verification.
func (s *LocalArtifactOpener) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
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

	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()

	if err := ensureNoSymlinks(root, cleanKey, true); err != nil {
		return nil, err
	}
	if err := ensureNoSymlinks(root, metaSubDir, false); err != nil {
		return nil, err
	}

	metaRel := metaRelPathFor(canonicalFold(cleanKey))
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

	f, err := root.OpenFile(cleanKey, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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

// GCSOpenerConfig configures a read-only GCS ArtifactOpener.
type GCSOpenerConfig struct {
	Bucket  string
	Prefix  string
	Client  *storage.Client
	Options []option.ClientOption
	Logger  *slog.Logger
}

// GCSArtifactOpener implements publish.ArtifactOpener against Google Cloud Storage JSON APIs
// in strictly read-only mode.
type GCSArtifactOpener struct {
	client     *storage.Client
	ownsClient bool
	bucket     string
	prefix     string
	logger     *slog.Logger
}

var _ publish.ArtifactOpener = (*GCSArtifactOpener)(nil)

// NewGCSArtifactOpener creates a read-only GCSArtifactOpener for the configured bucket and prefix.
func NewGCSArtifactOpener(ctx context.Context, cfg GCSOpenerConfig) (*GCSArtifactOpener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" {
		return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "GCS bucket is required")
	}
	var cleanPrefix string
	if strings.TrimSpace(cfg.Prefix) != "" {
		p, err := validateObjectKey(strings.Trim(cfg.Prefix, "/"))
		if err != nil {
			return nil, err
		}
		cleanPrefix = p
	}

	client := cfg.Client
	owns := false
	if client == nil {
		opts := make([]option.ClientOption, 0, len(cfg.Options)+1)
		opts = append(opts, cfg.Options...)
		opts = append(opts, storage.WithJSONReads())
		c, err := storage.NewClient(ctx, opts...)
		if err != nil {
			return nil, domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "failed to initialize GCS client", err)
		}
		client = c
		owns = true
	}

	return &GCSArtifactOpener{
		client:     client,
		ownsClient: owns,
		bucket:     bucket,
		prefix:     cleanPrefix,
		logger:     cfg.Logger,
	}, nil
}

// Close releases the underlying GCS client if created by NewGCSArtifactOpener.
func (s *GCSArtifactOpener) Close() error {
	if s != nil && s.ownsClient && s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *GCSArtifactOpener) fullObjectName(cleanKey string) string {
	if s.prefix == "" {
		return cleanKey
	}
	return path.Join(s.prefix, cleanKey)
}

// Open opens and streams an artifact from GCS with GenerationMatch, decompressed-transfer
// rejection, size verification, and streaming SHA-256 verification.
func (s *GCSArtifactOpener) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, mapContextError(err)
	}
	cleanKey, err := validateObjectKey(artifact.StorageKey)
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

	obj := s.client.Bucket(s.bucket).Object(s.fullObjectName(cleanKey))
	if artifact.StorageGeneration != "" {
		gen, err := parsePositiveGen(artifact.StorageGeneration)
		if err != nil {
			return nil, err
		}
		obj = obj.If(storage.Conditions{GenerationMatch: gen})
	}

	rc, err := obj.NewReader(ctx)
	if err != nil {
		return nil, mapGCSError(err)
	}
	if rc.Attrs.Decompressed {
		_ = rc.Close()
		return nil, domain.Unprocessable("UNEXPECTED_TRANSCODED_CONTENT", "stored object was unexpectedly decompressed during transfer")
	}
	if artifact.SizeBytes >= 0 && rc.Attrs.Size >= 0 && rc.Attrs.Size != artifact.SizeBytes {
		_ = rc.Close()
		return nil, domain.Unprocessable("SIZE_MISMATCH", "stored object size does not match artifact size")
	}

	expectedSize := artifact.SizeBytes
	if expectedSize < 0 {
		expectedSize = -1
	}
	return newVerifyingReadCloser(rc, expectedSHA, expectedSize), nil
}

func validateObjectKey(key string) (string, error) {
	if key == "" {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key must not be empty")
	}
	if strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsRune(key, '\x00') {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key contains illegal path characters")
	}
	if filepath.VolumeName(key) != "" {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key must not contain a volume name")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key contains empty or traversal segments")
		}
	}
	clean := path.Clean(key)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key is unsafe")
	}
	return clean, nil
}

func validateLocalKey(rawKey string) (string, error) {
	cleanKey, err := validateObjectKey(rawKey)
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

func readMeta(root *os.Root, metaRel string) (localObjectMeta, bool, error) {
	f, err := root.OpenFile(metaRel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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

	fi, err := f.Stat()
	if err != nil {
		return localObjectMeta{}, false, mapLocalError(err)
	}
	if !fi.Mode().IsRegular() {
		return localObjectMeta{}, false, domain.BadRequest("INVALID_OBJECT_PATH", "metadata object is not a regular file")
	}

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

func ensureNoSymlinks(root *os.Root, relSlashPath string, leafMustBeRegular bool) error {
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
		if i < len(parts)-1 {
			if !fi.IsDir() {
				return domain.BadRequest("INVALID_OBJECT_PATH", "intermediate object path component is not a directory")
			}
			continue
		}
		if leafMustBeRegular {
			if !fi.Mode().IsRegular() {
				return domain.BadRequest("INVALID_OBJECT_PATH", "snapshot object is not a regular file")
			}
		} else if !fi.IsDir() {
			return domain.BadRequest("INVALID_OBJECT_PATH", "metadata path component is not a directory")
		}
	}
	return nil
}

func parsePositiveGen(raw string) (int64, error) {
	gen, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || gen <= 0 {
		return 0, domain.BadRequest("INVALID_GENERATION", "storage generation must be a positive integer")
	}
	return gen, nil
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

func mapGCSError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrObjectNotExist) || errors.Is(err, storage.ErrBucketNotExist) {
		return domain.WrapError(domain.ErrNotFound, "OBJECT_NOT_FOUND", "snapshot object not found", err)
	}
	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		switch gErr.Code {
		case http.StatusPreconditionFailed:
			return domain.WrapError(domain.ErrConflict, "OBJECT_PRECONDITION_FAILED", "snapshot generation precondition failed", err)
		case http.StatusNotFound:
			return domain.WrapError(domain.ErrNotFound, "OBJECT_NOT_FOUND", "snapshot object not found", err)
		case http.StatusUnauthorized, http.StatusForbidden:
			return domain.WrapError(domain.ErrForbidden, "STORAGE_FORBIDDEN", "snapshot storage access denied", err)
		case http.StatusBadRequest:
			return domain.WrapError(domain.ErrBadRequest, "INVALID_STORAGE_REQUEST", "invalid snapshot storage request", err)
		case http.StatusTooManyRequests:
			return domain.WrapError(domain.ErrRateLimited, "STORAGE_RATE_LIMITED", "snapshot storage rate limited", err)
		default:
			if gErr.Code >= 500 {
				return domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "snapshot storage temporarily unavailable", err)
			}
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "snapshot storage unreachable", err)
	}
	return domain.WrapError(domain.ErrUnavailable, "STORAGE_UNAVAILABLE", "snapshot storage error", err)
}

type verifyingReadCloser struct {
	inner  io.ReadCloser
	hasher interface {
		io.Writer
		Sum(b []byte) []byte
	}
	bytesRead    int64
	expectedSHA  string
	expectedSize int64
	verified     bool
	verifyErr    error
}

func newVerifyingReadCloser(inner io.ReadCloser, expectedSHA string, expectedSize int64) *verifyingReadCloser {
	return &verifyingReadCloser{
		inner:        inner,
		hasher:       sha256.New(),
		expectedSHA:  expectedSHA,
		expectedSize: expectedSize,
	}
}

func (v *verifyingReadCloser) Read(p []byte) (int, error) {
	if v.verified && v.verifyErr != nil {
		return 0, v.verifyErr
	}
	n, err := v.inner.Read(p)
	if n > 0 {
		_, _ = v.hasher.Write(p[:n])
		v.bytesRead += int64(n)
	}
	if err == io.EOF {
		if verr := v.verify(); verr != nil {
			return n, verr
		}
		return n, io.EOF
	}
	return n, err
}

func (v *verifyingReadCloser) verify() error {
	if v.verified {
		return v.verifyErr
	}
	v.verified = true
	if v.expectedSize >= 0 && v.bytesRead != v.expectedSize {
		v.verifyErr = domain.Unprocessable("SIZE_MISMATCH", fmt.Sprintf("artifact size mismatch: got %d bytes, expected %d", v.bytesRead, v.expectedSize))
		return v.verifyErr
	}
	if v.expectedSHA != "" {
		actual := hex.EncodeToString(v.hasher.Sum(nil))
		if actual != v.expectedSHA {
			v.verifyErr = domain.Unprocessable("DIGEST_MISMATCH", "artifact SHA-256 digest mismatch")
			return v.verifyErr
		}
	}
	return nil
}

func (v *verifyingReadCloser) Close() error {
	return v.inner.Close()
}
