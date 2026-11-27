package snapshots

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/timreynolds/custodian/internal/domain"
)

// GCSConfig configures a GCS-backed domain.SnapshotStore.
type GCSConfig struct {
	Bucket    string
	Prefix    string
	Client    *storage.Client
	Options   []option.ClientOption
	ChunkSize int
	Logger    *slog.Logger
}

// GCSStore implements domain.SnapshotStore using Google Cloud Storage JSON APIs
// with generation preconditions and streaming SHA-256 verification.
type GCSStore struct {
	client     *storage.Client
	ownsClient bool
	bucket     string
	prefix     string
	chunkSize  int
	logger     *slog.Logger
}

var _ domain.SnapshotStore = (*GCSStore)(nil)

// NewGCSStore creates a GCSStore for the configured bucket and prefix.
func NewGCSStore(ctx context.Context, cfg GCSConfig) (*GCSStore, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" {
		return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "GCS bucket is required")
	}
	var cleanPrefix string
	if strings.TrimSpace(cfg.Prefix) != "" {
		p, err := ValidateObjectKey(strings.Trim(cfg.Prefix, "/"))
		if err != nil {
			return nil, err
		}
		cleanPrefix = p
	}
	if cfg.ChunkSize < 0 {
		return nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "GCS chunk size must be non-negative")
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

	return &GCSStore{
		client:     client,
		ownsClient: owns,
		bucket:     bucket,
		prefix:     cleanPrefix,
		chunkSize:  cfg.ChunkSize,
		logger:     cfg.Logger,
	}, nil
}

// Close releases the underlying GCS client if created by NewGCSStore.
func (s *GCSStore) Close() error {
	if s.ownsClient && s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *GCSStore) fullObjectName(cleanKey string) string {
	if s.prefix == "" {
		return cleanKey
	}
	return path.Join(s.prefix, cleanKey)
}

func (s *GCSStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !req.Kind.IsValid() {
		return domain.Artifact{}, domain.BadRequest("INVALID_ARTIFACT_KIND", "artifact kind is invalid")
	}
	cleanKey, err := ValidateObjectKey(req.ObjectKey)
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

	obj := s.client.Bucket(s.bucket).Object(s.fullObjectName(cleanKey))
	if req.Generation == nil || *req.Generation == 0 {
		obj = obj.If(storage.Conditions{DoesNotExist: true})
	} else if *req.Generation > 0 {
		obj = obj.If(storage.Conditions{GenerationMatch: *req.Generation})
	} else {
		return domain.Artifact{}, domain.BadRequest("INVALID_GENERATION", "generation precondition must be non-negative")
	}

	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	w := obj.NewWriter(uploadCtx)
	contentType := strings.TrimSpace(req.ContentType)
	if contentType == "" {
		if strings.HasSuffix(cleanKey, ".tar.gz") {
			contentType = "application/gzip"
		} else {
			contentType = "application/octet-stream"
		}
	}
	w.ContentType = contentType
	// Never set w.ContentEncoding = "gzip": artifacts must be stored and retrieved byte-for-byte.
	if s.chunkSize > 0 {
		w.ChunkSize = s.chunkSize
	}
	w.Metadata = map[string]string{
		"custodian-kind": string(req.Kind),
	}

	hasher := sha256.New()
	limited := io.LimitReader(r, size)
	tee := io.TeeReader(limited, hasher)

	written, copyErr := io.Copy(w, tee)
	if copyErr != nil {
		cancel()
		return domain.Artifact{}, mapGCSError(copyErr)
	}
	if written != size {
		cancel()
		return domain.Artifact{}, domain.Unprocessable("SIZE_MISMATCH", "artifact stream ended before declared size")
	}

	// Ensure caller stream does not contain trailing bytes beyond declared size.
	var extra [1]byte
	extraN, extraErr := r.Read(extra[:])
	if extraN > 0 {
		cancel()
		return domain.Artifact{}, domain.Unprocessable("SIZE_MISMATCH", "artifact stream exceeded declared size")
	}
	if extraErr != nil && extraErr != io.EOF {
		cancel()
		return domain.Artifact{}, domain.WrapError(domain.ErrBadRequest, "STREAM_READ_ERROR", "failed reading artifact stream", extraErr)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		cancel()
		return domain.Artifact{}, domain.Unprocessable("DIGEST_MISMATCH", "artifact SHA-256 digest does not match expected digest")
	}

	if err := w.Close(); err != nil {
		return domain.Artifact{}, mapGCSError(err)
	}

	attrs := w.Attrs()
	genStr := "1"
	if attrs != nil && attrs.Generation > 0 {
		genStr = strconv.FormatInt(attrs.Generation, 10)
	}

	id, err := domain.NewID()
	if err != nil {
		return domain.Artifact{}, domain.WrapError(domain.ErrInternal, "ID_GENERATION_FAILED", "failed to generate artifact ID", err)
	}

	artifact := domain.Artifact{
		ID:                id,
		Kind:              req.Kind,
		SHA256:            actualSHA,
		StorageKey:        cleanKey,
		StorageGeneration: genStr,
		SizeBytes:         written,
		CreatedAt:         time.Now().UTC(),
	}
	s.logArtifact("snapshot_put", artifact)
	return artifact, nil
}

func (s *GCSStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cleanKey, err := ValidateObjectKey(artifact.StorageKey)
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

func (s *GCSStore) Verify(ctx context.Context, artifact domain.Artifact) error {
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

func (s *GCSStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cleanKey, err := ValidateObjectKey(artifact.StorageKey)
	if err != nil {
		return err
	}

	obj := s.client.Bucket(s.bucket).Object(s.fullObjectName(cleanKey))
	if artifact.StorageGeneration != "" {
		gen, err := parsePositiveGen(artifact.StorageGeneration)
		if err != nil {
			return err
		}
		obj = obj.If(storage.Conditions{GenerationMatch: gen})
	}

	if err := obj.Delete(ctx); err != nil {
		return mapGCSError(err)
	}
	s.logArtifact("snapshot_deleted", artifact)
	return nil
}

func (s *GCSStore) logArtifact(msg string, a domain.Artifact) {
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

func parsePositiveGen(raw string) (int64, error) {
	gen, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || gen <= 0 {
		return 0, domain.BadRequest("INVALID_GENERATION", "storage generation must be a positive integer")
	}
	return gen, nil
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
