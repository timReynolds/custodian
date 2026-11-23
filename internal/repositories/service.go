package repositories

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

// Store defines the persistence operations required by the repositories service.
type Store interface {
	GetRepositoryByID(ctx context.Context, id uuid.UUID) (persistence.RepositoryRow, error)
	GetRepositoryByGitHubID(ctx context.Context, githubRepoID int64) (persistence.RepositoryRow, error)
	CreateRepository(ctx context.Context, arg persistence.UpsertRepositoryParams) (persistence.RepositoryRow, error)
	UpsertRepository(ctx context.Context, arg persistence.UpsertRepositoryParams) (persistence.RepositoryRow, error)
}

// Record represents a registered repository with policy and concurrency metadata.
type Record struct {
	domain.Repository
	AllowedModelRoutes      []string  `json:"allowed_model_routes"`
	MaxConcurrentOperations int       `json:"max_concurrent_operations"`
	CreatedAt               time.Time `json:"created_at"`
}

// UpsertInput configures creation or update of a repository registration.
type UpsertInput struct {
	ID                      uuid.UUID
	GitHubRepositoryID      int64
	GitHubInstallationID    int64
	FullName                string
	Classification          domain.Classification
	Enabled                 bool
	AllowedModelRoutes      []string
	MaxConcurrentOperations int
}

// Service manages repository registry lookups, persistence, and entitlement authorization.
type Service struct {
	store  Store
	logger *slog.Logger
}

// NewService constructs a repositories Service.
func NewService(store Store, logger *slog.Logger) *Service {
	return &Service{
		store:  store,
		logger: logger,
	}
}

// GetByID retrieves a repository by its Custodian UUID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("REPOSITORIES_UNAVAILABLE", "repository store is not configured")
	}
	row, err := s.store.GetRepositoryByID(ctx, id)
	if err != nil {
		return Record{}, err
	}
	return recordFromRow(row), nil
}

// GetByGitHubID retrieves a repository by its GitHub repository ID.
func (s *Service) GetByGitHubID(ctx context.Context, githubRepoID int64) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("REPOSITORIES_UNAVAILABLE", "repository store is not configured")
	}
	row, err := s.store.GetRepositoryByGitHubID(ctx, githubRepoID)
	if err != nil {
		return Record{}, err
	}
	return recordFromRow(row), nil
}

// Create registers a new repository, failing with Conflict if github_repository_id already exists.
func (s *Service) Create(ctx context.Context, input UpsertInput) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("REPOSITORIES_UNAVAILABLE", "repository store is not configured")
	}
	if input.ID != uuid.Nil && !domain.IsUUIDv7(input.ID) {
		return Record{}, domain.BadRequest("INVALID_ID", "repository id must be UUIDv7")
	}
	row, err := s.store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		ID:                      input.ID,
		GitHubRepositoryID:      input.GitHubRepositoryID,
		GitHubInstallationID:    input.GitHubInstallationID,
		FullName:                input.FullName,
		Classification:          input.Classification,
		Enabled:                 input.Enabled,
		AllowedModelRoutes:      input.AllowedModelRoutes,
		MaxConcurrentOperations: input.MaxConcurrentOperations,
	})
	if err != nil {
		return Record{}, err
	}
	rec := recordFromRow(row)
	s.logEvent(ctx, "repository created", rec)
	return rec, nil
}

// Upsert creates or updates a repository keyed by github_repository_id.
func (s *Service) Upsert(ctx context.Context, input UpsertInput) (Record, error) {
	if s == nil || s.store == nil {
		return Record{}, domain.Unavailable("REPOSITORIES_UNAVAILABLE", "repository store is not configured")
	}
	if input.ID != uuid.Nil && !domain.IsUUIDv7(input.ID) {
		return Record{}, domain.BadRequest("INVALID_ID", "repository id must be UUIDv7")
	}
	row, err := s.store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		ID:                      input.ID,
		GitHubRepositoryID:      input.GitHubRepositoryID,
		GitHubInstallationID:    input.GitHubInstallationID,
		FullName:                input.FullName,
		Classification:          input.Classification,
		Enabled:                 input.Enabled,
		AllowedModelRoutes:      input.AllowedModelRoutes,
		MaxConcurrentOperations: input.MaxConcurrentOperations,
	})
	if err != nil {
		return Record{}, err
	}
	rec := recordFromRow(row)
	s.logEvent(ctx, "repository upserted", rec)
	return rec, nil
}

// RequireEnabled verifies that the repository exists, is enabled, has a valid classification, and valid owner/repo name.
func (s *Service) RequireEnabled(ctx context.Context, repoID uuid.UUID) (Record, error) {
	rec, err := s.GetByID(ctx, repoID)
	if err != nil {
		return Record{}, err
	}
	if err := ValidateRecord(rec, ""); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Authorize verifies repository entitlement and optional model route allowance for a repository ID.
func (s *Service) Authorize(ctx context.Context, repoID uuid.UUID, modelRoute string) (Record, error) {
	rec, err := s.GetByID(ctx, repoID)
	if err != nil {
		return Record{}, err
	}
	if err := ValidateRecord(rec, modelRoute); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// AuthorizeByGitHubID verifies repository entitlement and optional model route allowance by GitHub repository ID.
func (s *Service) AuthorizeByGitHubID(ctx context.Context, githubRepoID int64, modelRoute string) (Record, error) {
	rec, err := s.GetByGitHubID(ctx, githubRepoID)
	if err != nil {
		return Record{}, err
	}
	if err := ValidateRecord(rec, modelRoute); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// ValidateRecord checks enabled state, valid classification, owner/repo syntax, and optional modelRoute allowance.
func ValidateRecord(rec Record, modelRoute string) error {
	if !rec.Enabled {
		return domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	if !rec.Classification.IsValid() {
		return domain.Forbidden("INVALID_CLASSIFICATION", "repository has an invalid classification")
	}
	if _, _, err := rec.OwnerRepo(); err != nil {
		return err
	}
	if modelRoute != "" {
		if len(rec.AllowedModelRoutes) == 0 || !slices.Contains(rec.AllowedModelRoutes, modelRoute) {
			return domain.Forbidden("MODEL_ROUTE_FORBIDDEN", "model route is not authorized for this repository")
		}
	}
	return nil
}

func recordFromRow(row persistence.RepositoryRow) Record {
	routes := slices.Clone(row.AllowedModelRoutes)
	if routes == nil {
		routes = []string{}
	}
	return Record{
		Repository:              row.ToDomain(),
		AllowedModelRoutes:      routes,
		MaxConcurrentOperations: row.MaxConcurrentOperations,
		CreatedAt:               row.CreatedAt.UTC(),
	}
}

func (s *Service) logEvent(ctx context.Context, msg string, rec Record) {
	if s.logger == nil {
		return
	}
	l := observability.LoggerWithTrace(ctx, s.logger)
	l.InfoContext(ctx, msg,
		"repository_id", rec.ID.String(),
		"github_repository_id", rec.GitHubRepositoryID,
		"classification", string(rec.Classification),
	)
}
