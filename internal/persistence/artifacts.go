package persistence

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

type RegisterArtifactParams struct {
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
	CreatedAt           time.Time
}

const registerArtifactSQL = `
INSERT INTO artifacts (
    id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12
)
RETURNING id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
`

func (q *Queries) RegisterArtifact(ctx context.Context, arg RegisterArtifactParams) (ArtifactRow, error) {
	if !arg.Kind.IsValid() {
		return ArtifactRow{}, domain.BadRequest("INVALID_ARTIFACT_KIND", "invalid artifact kind")
	}
	sha, err := domain.ParseSHA256Digest(arg.SHA256)
	if err != nil {
		return ArtifactRow{}, err
	}
	if arg.StorageKey == "" || arg.StorageGeneration == "" {
		return ArtifactRow{}, domain.BadRequest("INVALID_STORAGE_REF", "storage_key and storage_generation must not be empty")
	}
	if arg.SizeBytes < 0 {
		return ArtifactRow{}, domain.BadRequest("INVALID_SIZE", "size_bytes must be non-negative")
	}
	format := arg.Format
	if format == "" {
		format = "application/octet-stream"
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return ArtifactRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return ArtifactRow{}, domain.BadRequest("INVALID_ID", "artifact id must be UUIDv7")
	}
	createdAt := arg.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		createdAt = createdAt.UTC().Truncate(time.Microsecond)
	}
	var expiresAt *time.Time
	if arg.ExpiresAt != nil {
		t := arg.ExpiresAt.UTC().Truncate(time.Microsecond)
		expiresAt = &t
	}

	var row ArtifactRow
	var kind string
	err = q.db.QueryRow(ctx, registerArtifactSQL,
		id,
		string(arg.Kind),
		sha,
		arg.StorageKey,
		arg.StorageGeneration,
		arg.SizeBytes,
		format,
		arg.WorkspaceID,
		arg.WorkspaceGeneration,
		arg.UploadedBy,
		expiresAt,
		createdAt,
	).Scan(
		&row.ID,
		&kind,
		&row.SHA256,
		&row.StorageKey,
		&row.StorageGeneration,
		&row.SizeBytes,
		&row.Format,
		&row.WorkspaceID,
		&row.WorkspaceGeneration,
		&row.UploadedBy,
		&row.ExpiresAt,
		&row.DeletedAt,
		&row.CreatedAt,
	)
	if err != nil {
		return ArtifactRow{}, MapError(err)
	}
	row.Kind = domain.ArtifactKind(kind)
	return row, nil
}

const getArtifactByIDSQL = `
SELECT id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
FROM artifacts
WHERE id = $1
`

func (q *Queries) GetArtifactByID(ctx context.Context, id uuid.UUID) (ArtifactRow, error) {
	if id == uuid.Nil {
		return ArtifactRow{}, domain.BadRequest("INVALID_ID", "artifact id must not be nil")
	}
	var row ArtifactRow
	var kind string
	err := q.db.QueryRow(ctx, getArtifactByIDSQL, id).Scan(
		&row.ID,
		&kind,
		&row.SHA256,
		&row.StorageKey,
		&row.StorageGeneration,
		&row.SizeBytes,
		&row.Format,
		&row.WorkspaceID,
		&row.WorkspaceGeneration,
		&row.UploadedBy,
		&row.ExpiresAt,
		&row.DeletedAt,
		&row.CreatedAt,
	)
	if err != nil {
		return ArtifactRow{}, MapError(err)
	}
	row.Kind = domain.ArtifactKind(kind)
	return row, nil
}

const getArtifactByStorageObjectSQL = `
SELECT id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
FROM artifacts
WHERE storage_key = $1 AND storage_generation = $2
`

func (q *Queries) GetArtifactByStorageObject(ctx context.Context, storageKey, storageGeneration string) (ArtifactRow, error) {
	if storageKey == "" || storageGeneration == "" {
		return ArtifactRow{}, domain.BadRequest("INVALID_STORAGE_REF", "storage_key and storage_generation must not be empty")
	}
	var row ArtifactRow
	var kind string
	err := q.db.QueryRow(ctx, getArtifactByStorageObjectSQL, storageKey, storageGeneration).Scan(
		&row.ID,
		&kind,
		&row.SHA256,
		&row.StorageKey,
		&row.StorageGeneration,
		&row.SizeBytes,
		&row.Format,
		&row.WorkspaceID,
		&row.WorkspaceGeneration,
		&row.UploadedBy,
		&row.ExpiresAt,
		&row.DeletedAt,
		&row.CreatedAt,
	)
	if err != nil {
		return ArtifactRow{}, MapError(err)
	}
	row.Kind = domain.ArtifactKind(kind)
	return row, nil
}

const listExpiredArtifactsSQL = `
SELECT id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
FROM artifacts
WHERE expires_at IS NOT NULL
  AND expires_at <= $1
  AND deleted_at IS NULL
ORDER BY expires_at ASC, id ASC
LIMIT $2
`

func (q *Queries) ListExpiredArtifacts(ctx context.Context, asOf time.Time, limit int) ([]ArtifactRow, error) {
	if asOf.IsZero() {
		asOf = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		asOf = asOf.UTC().Truncate(time.Microsecond)
	}
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := q.db.Query(ctx, listExpiredArtifactsSQL, asOf, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ArtifactRow, 0)
	for rows.Next() {
		var row ArtifactRow
		var kind string
		if err := rows.Scan(
			&row.ID,
			&kind,
			&row.SHA256,
			&row.StorageKey,
			&row.StorageGeneration,
			&row.SizeBytes,
			&row.Format,
			&row.WorkspaceID,
			&row.WorkspaceGeneration,
			&row.UploadedBy,
			&row.ExpiresAt,
			&row.DeletedAt,
			&row.CreatedAt,
		); err != nil {
			return nil, MapError(err)
		}
		row.Kind = domain.ArtifactKind(kind)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const markArtifactDeletedSQL = `
UPDATE artifacts
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, kind, sha256, storage_key, storage_generation, size_bytes, format,
    workspace_id, workspace_generation, uploaded_by, expires_at, deleted_at, created_at
`

func (q *Queries) MarkArtifactDeleted(ctx context.Context, id uuid.UUID, deletedAt time.Time) (ArtifactRow, error) {
	if id == uuid.Nil {
		return ArtifactRow{}, domain.BadRequest("INVALID_ID", "artifact id must not be nil")
	}
	if deletedAt.IsZero() {
		deletedAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		deletedAt = deletedAt.UTC().Truncate(time.Microsecond)
	}
	var row ArtifactRow
	var kind string
	err := q.db.QueryRow(ctx, markArtifactDeletedSQL, id, deletedAt).Scan(
		&row.ID,
		&kind,
		&row.SHA256,
		&row.StorageKey,
		&row.StorageGeneration,
		&row.SizeBytes,
		&row.Format,
		&row.WorkspaceID,
		&row.WorkspaceGeneration,
		&row.UploadedBy,
		&row.ExpiresAt,
		&row.DeletedAt,
		&row.CreatedAt,
	)
	if err != nil {
		return ArtifactRow{}, MapError(err)
	}
	row.Kind = domain.ArtifactKind(kind)
	return row, nil
}
