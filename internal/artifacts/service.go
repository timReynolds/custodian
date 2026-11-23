package artifacts

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

// Store defines the persistence operations required by the artifacts service.
type Store interface {
	RegisterArtifact(ctx context.Context, arg persistence.RegisterArtifactParams) (persistence.ArtifactRow, error)
	GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error)
	GetArtifactByStorageObject(ctx context.Context, storageKey, storageGeneration string) (persistence.ArtifactRow, error)
	ListExpiredArtifacts(ctx context.Context, asOf time.Time, limit int) ([]persistence.ArtifactRow, error)
	MarkArtifactDeleted(ctx context.Context, id uuid.UUID, deletedAt time.Time) (persistence.ArtifactRow, error)
}

// Record represents a persisted artifact along with format, provenance, and retention metadata.
type Record struct {
	domain.Artifact
	Format              string     `json:"format"`
	WorkspaceID         *uuid.UUID `json:"workspace_id,omitempty"`
	WorkspaceGeneration *int64     `json:"workspace_generation,omitempty"`
	UploadedBy          *uuid.UUID `json:"uploaded_by,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	DeletedAt           *time.Time `json:"deleted_at,omitempty"`
}

// RegisterInput specifies metadata for registering an immutable content-addressed artifact.
type RegisterInput struct {
	ID                  uuid.UUID
	Kind                domain.ArtifactKind
	SHA256              string
	StorageKey          string
	StorageGeneration   string
	SizeBytes           int64
	Format              string
	WorkspaceID         *uuid.UUID
	WorkspaceGeneration *int64
	UploadedBy          *uuid.UUID
	ExpiresAt           *time.Time
}

// Service manages artifact metadata registration and lifecycle queries.
type Service struct {
	store  Store
	logger *slog.Logger
}

// NewService constructs an artifacts Service.
func NewService(store Store, logger *slog.Logger) *Service {
	return &Service{
		store:  store,
		logger: logger,
	}
}

// Register validates and persists immutable artifact metadata.
func (s *Service) Register(ctx context.Context, input RegisterInput) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("ARTIFACTS_UNAVAILABLE", "artifact store is not configured")
	}
	id := input.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return Record{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return Record{}, domain.BadRequest("INVALID_ID", "artifact id must be UUIDv7")
	}

	if !input.Kind.IsValid() {
		return Record{}, domain.BadRequest("INVALID_ARTIFACT_KIND", "invalid artifact kind")
	}

	sha, err := domain.ParseSHA256Digest(input.SHA256)
	if err != nil {
		return Record{}, err
	}

	if input.SizeBytes < 0 {
		return Record{}, domain.BadRequest("INVALID_SIZE", "size_bytes must be non-negative")
	}

	key := strings.TrimSpace(input.StorageKey)
	gen := strings.TrimSpace(input.StorageGeneration)
	if key == "" || gen == "" {
		return Record{}, domain.BadRequest("INVALID_STORAGE_REF", "storage_key and storage_generation must not be empty")
	}

	format := strings.TrimSpace(input.Format)
	if format == "" || len(format) > 64 {
		return Record{}, domain.BadRequest("INVALID_FORMAT", "format must be 1..64 characters")
	}

	if input.WorkspaceGeneration != nil && *input.WorkspaceGeneration < 1 {
		return Record{}, domain.BadRequest("INVALID_GENERATION", "workspace_generation must be >= 1")
	}

	row, err := s.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID:                  id,
		Kind:                input.Kind,
		SHA256:              sha,
		StorageKey:          key,
		StorageGeneration:   gen,
		SizeBytes:           input.SizeBytes,
		Format:              format,
		WorkspaceID:         input.WorkspaceID,
		WorkspaceGeneration: input.WorkspaceGeneration,
		UploadedBy:          input.UploadedBy,
		ExpiresAt:           input.ExpiresAt,
	})
	if err != nil {
		return Record{}, err
	}

	rec := recordFromRow(row)
	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.InfoContext(ctx, "artifact registered",
			"artifact_id", rec.ID.String(),
			"sha256", rec.SHA256,
			"size_bytes", rec.SizeBytes,
		)
	}
	return rec, nil
}

// GetByID retrieves an artifact by its UUID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("ARTIFACTS_UNAVAILABLE", "artifact store is not configured")
	}
	row, err := s.store.GetArtifactByID(ctx, id)
	if err != nil {
		return Record{}, err
	}
	return recordFromRow(row), nil
}

// GetByStorageObject retrieves an artifact by its immutable storage_key and storage_generation.
func (s *Service) GetByStorageObject(ctx context.Context, storageKey, storageGeneration string) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("ARTIFACTS_UNAVAILABLE", "artifact store is not configured")
	}
	row, err := s.store.GetArtifactByStorageObject(ctx, storageKey, storageGeneration)
	if err != nil {
		return Record{}, err
	}
	return recordFromRow(row), nil
}

// ListExpired returns non-deleted artifacts whose expires_at <= asOf.
func (s *Service) ListExpired(ctx context.Context, asOf time.Time, limit int) ([]Record, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("ARTIFACTS_UNAVAILABLE", "artifact store is not configured")
	}
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := s.store.ListExpiredArtifacts(ctx, asOf, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, recordFromRow(r))
	}
	return out, nil
}

// MarkDeleted marks an artifact as deleted at deletedAt.
func (s *Service) MarkDeleted(ctx context.Context, id uuid.UUID, deletedAt time.Time) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("ARTIFACTS_UNAVAILABLE", "artifact store is not configured")
	}
	row, err := s.store.MarkArtifactDeleted(ctx, id, deletedAt)
	if err != nil {
		return Record{}, err
	}
	rec := recordFromRow(row)
	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.InfoContext(ctx, "artifact marked deleted",
			"artifact_id", rec.ID.String(),
			"sha256", rec.SHA256,
		)
	}
	return rec, nil
}

func recordFromRow(row persistence.ArtifactRow) Record {
	var expiresAt, deletedAt *time.Time
	if row.ExpiresAt != nil {
		t := row.ExpiresAt.UTC()
		expiresAt = &t
	}
	if row.DeletedAt != nil {
		t := row.DeletedAt.UTC()
		deletedAt = &t
	}
	return Record{
		Artifact:            row.ToDomain(),
		Format:              row.Format,
		WorkspaceID:         row.WorkspaceID,
		WorkspaceGeneration: row.WorkspaceGeneration,
		UploadedBy:          row.UploadedBy,
		ExpiresAt:           expiresAt,
		DeletedAt:           deletedAt,
	}
}
