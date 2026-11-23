package persistence

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const getRepositoryByIDSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
WHERE id = $1
`

func (q *Queries) GetRepositoryByID(ctx context.Context, id uuid.UUID) (RepositoryRow, error) {
	if id == uuid.Nil {
		return RepositoryRow{}, domain.BadRequest("INVALID_ID", "repository id must not be nil")
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByIDSQL, id), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const getRepositoryByGitHubIDSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
WHERE github_repository_id = $1
`

func (q *Queries) GetRepositoryByGitHubID(ctx context.Context, githubRepoID int64) (RepositoryRow, error) {
	if githubRepoID <= 0 {
		return RepositoryRow{}, domain.BadRequest("INVALID_REPOSITORY_ID", "github_repository_id must be positive")
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByGitHubIDSQL, githubRepoID), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const getRepositoryByFullNameSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
WHERE full_name = $1
ORDER BY created_at DESC, id DESC
LIMIT 1
`

func (q *Queries) GetRepositoryByFullName(ctx context.Context, fullName string) (RepositoryRow, error) {
	trimmed := strings.TrimSpace(fullName)
	if _, _, err := (domain.Repository{FullName: trimmed}).OwnerRepo(); err != nil {
		return RepositoryRow{}, err
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByFullNameSQL, trimmed), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const listRepositoriesSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
FROM repositories
ORDER BY created_at DESC, id DESC
LIMIT $1
`

func (q *Queries) ListRepositories(ctx context.Context, limit int32) ([]RepositoryRow, error) {
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := q.db.Query(ctx, listRepositoriesSQL, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]RepositoryRow, 0)
	for rows.Next() {
		var row RepositoryRow
		if err := scanRepositoryRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type UpsertRepositoryParams struct {
	ID                      uuid.UUID
	GitHubRepositoryID      int64
	GitHubInstallationID    int64
	FullName                string
	Classification          domain.Classification
	Enabled                 bool
	AllowedModelRoutes      []string
	MaxConcurrentOperations int
	CreatedAt               time.Time
}

const createRepositorySQL = `
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
`

const upsertRepositorySQL = `
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (github_repository_id) DO UPDATE SET
    github_installation_id    = EXCLUDED.github_installation_id,
    full_name                 = EXCLUDED.full_name,
    classification            = EXCLUDED.classification,
    enabled                   = EXCLUDED.enabled,
    allowed_model_routes      = EXCLUDED.allowed_model_routes,
    max_concurrent_operations = EXCLUDED.max_concurrent_operations
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, created_at
`

func (q *Queries) CreateRepository(ctx context.Context, arg UpsertRepositoryParams) (RepositoryRow, error) {
	return q.execRepositoryWrite(ctx, createRepositorySQL, arg)
}

func (q *Queries) UpsertRepository(ctx context.Context, arg UpsertRepositoryParams) (RepositoryRow, error) {
	return q.execRepositoryWrite(ctx, upsertRepositorySQL, arg)
}

func (q *Queries) execRepositoryWrite(ctx context.Context, stmt string, arg UpsertRepositoryParams) (RepositoryRow, error) {
	if arg.GitHubRepositoryID <= 0 || arg.GitHubInstallationID <= 0 {
		return RepositoryRow{}, domain.BadRequest("INVALID_REPOSITORY", "github repository and installation IDs must be positive")
	}
	if !arg.Classification.IsValid() {
		return RepositoryRow{}, domain.BadRequest("INVALID_CLASSIFICATION", "invalid repository classification")
	}
	repo := domain.Repository{
		FullName: arg.FullName,
	}
	if _, _, err := repo.OwnerRepo(); err != nil {
		return RepositoryRow{}, err
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return RepositoryRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return RepositoryRow{}, domain.BadRequest("INVALID_ID", "repository id must be UUIDv7")
	}
	routes := arg.AllowedModelRoutes
	if routes == nil {
		routes = []string{}
	}
	maxConc := arg.MaxConcurrentOperations
	if maxConc <= 0 {
		maxConc = 10
	}
	createdAt := arg.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		createdAt = createdAt.UTC().Truncate(time.Microsecond)
	}

	var row RepositoryRow
	err := scanRepositoryRow(q.db.QueryRow(ctx, stmt,
		id,
		arg.GitHubRepositoryID,
		arg.GitHubInstallationID,
		arg.FullName,
		string(arg.Classification),
		arg.Enabled,
		routes,
		maxConc,
		createdAt,
	), &row)
	if err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

func scanRepositoryRow(s rowScanner, row *RepositoryRow) error {
	var classification string
	if err := s.Scan(
		&row.ID,
		&row.GitHubRepositoryID,
		&row.GitHubInstallationID,
		&row.FullName,
		&classification,
		&row.Enabled,
		&row.AllowedModelRoutes,
		&row.MaxConcurrentOperations,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Classification = domain.Classification(classification)
	if row.AllowedModelRoutes == nil {
		row.AllowedModelRoutes = []string{}
	}
	return nil
}
