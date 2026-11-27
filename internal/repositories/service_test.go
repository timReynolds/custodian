package repositories_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/repositories"
)

type stubRepoStore struct {
	byID map[uuid.UUID]persistence.RepositoryRow
}

func (s *stubRepoStore) GetRepositoryByID(_ context.Context, id uuid.UUID) (persistence.RepositoryRow, error) {
	r, ok := s.byID[id]
	if !ok {
		return persistence.RepositoryRow{}, domain.NotFound("NOT_FOUND", "not found")
	}
	return r, nil
}

func (s *stubRepoStore) GetRepositoryByGitHubID(_ context.Context, ghID int64) (persistence.RepositoryRow, error) {
	for _, r := range s.byID {
		if r.GitHubRepositoryID == ghID {
			return r, nil
		}
	}
	return persistence.RepositoryRow{}, domain.NotFound("NOT_FOUND", "not found")
}

func (s *stubRepoStore) CreateRepository(_ context.Context, arg persistence.UpsertRepositoryParams) (persistence.RepositoryRow, error) {
	r := persistence.RepositoryRow{
		ID:                      arg.ID,
		GitHubRepositoryID:      arg.GitHubRepositoryID,
		GitHubInstallationID:    arg.GitHubInstallationID,
		FullName:                arg.FullName,
		Classification:          arg.Classification,
		Enabled:                 arg.Enabled,
		AllowedModelRoutes:      arg.AllowedModelRoutes,
		MaxConcurrentOperations: arg.MaxConcurrentOperations,
	}
	s.byID[r.ID] = r
	return r, nil
}

func (s *stubRepoStore) UpsertRepository(ctx context.Context, arg persistence.UpsertRepositoryParams) (persistence.RepositoryRow, error) {
	return s.CreateRepository(ctx, arg)
}

func TestRepositoriesUnitAuthorize(t *testing.T) {
	t.Parallel()

	enabledID := domain.MustNewID()
	disabledID := domain.MustNewID()
	restrictedID := domain.MustNewID()

	store := &stubRepoStore{
		byID: map[uuid.UUID]persistence.RepositoryRow{
			enabledID: {
				ID:                   enabledID,
				GitHubRepositoryID:   101,
				GitHubInstallationID: 201,
				FullName:             "acme/app",
				Classification:       domain.ClassificationInternal,
				Enabled:              true,
				AllowedModelRoutes:   []string{"claude-internal", "local-vllm"},
			},
			disabledID: {
				ID:                   disabledID,
				GitHubRepositoryID:   102,
				GitHubInstallationID: 201,
				FullName:             "acme/disabled",
				Classification:       domain.ClassificationPublic,
				Enabled:              false,
			},
			restrictedID: {
				ID:                   restrictedID,
				GitHubRepositoryID:   103,
				GitHubInstallationID: 201,
				FullName:             "acme/secret",
				Classification:       domain.ClassificationRestricted,
				Enabled:              true,
				AllowedModelRoutes:   []string{"local-airgap"},
			},
		},
	}

	svc := repositories.NewService(store, observability.NewLogger(observability.LoggerConfig{}))
	ctx := context.Background()

	if _, err := svc.RequireEnabled(ctx, enabledID); err != nil {
		t.Fatalf("RequireEnabled(enabledID): %v", err)
	}
	if _, err := svc.Authorize(ctx, enabledID, "claude-internal"); err != nil {
		t.Fatalf("Authorize allowed route: %v", err)
	}
	if _, err := svc.Authorize(ctx, disabledID, ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo, got %v", err)
	}
	if _, err := svc.Authorize(ctx, restrictedID, "public-cloud-llm"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disallowed model route, got %v", err)
	}

	// Fail-closed: empty AllowedModelRoutes with non-empty modelRoute must return 403 across ALL classifications,
	// while empty modelRoute == "" continues to pass.
	for _, cls := range []domain.Classification{
		domain.ClassificationPublic,
		domain.ClassificationInternal,
		domain.ClassificationConfidential,
		domain.ClassificationRestricted,
	} {
		repoID := domain.MustNewID()
		store.byID[repoID] = persistence.RepositoryRow{
			ID:                   repoID,
			GitHubRepositoryID:   200 + int64(len(store.byID)),
			GitHubInstallationID: 201,
			FullName:             "acme/empty-routes-" + string(cls),
			Classification:       cls,
			Enabled:              true,
			AllowedModelRoutes:   []string{},
		}
		if _, err := svc.Authorize(ctx, repoID, ""); err != nil {
			t.Fatalf("expected empty modelRoute to succeed for %s with empty AllowedModelRoutes, got %v", cls, err)
		}
		if _, err := svc.Authorize(ctx, repoID, "public-cloud-llm"); !errors.Is(err, domain.ErrForbidden) || domain.HTTPStatusFromError(err) != 403 {
			t.Fatalf("expected 403 Forbidden for %s with empty AllowedModelRoutes and non-empty route, got %v", cls, err)
		}
	}

	// UUIDv4 IDs are rejected with 400 BadRequest.
	if _, err := svc.Create(ctx, repositories.UpsertInput{
		ID:                   uuid.New(), // v4
		GitHubRepositoryID:   999,
		GitHubInstallationID: 201,
		FullName:             "acme/bad-id",
		Classification:       domain.ClassificationPublic,
		Enabled:              true,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for UUIDv4 in Create, got %v", err)
	}
	if _, err := svc.Upsert(ctx, repositories.UpsertInput{
		ID:                   uuid.New(), // v4
		GitHubRepositoryID:   999,
		GitHubInstallationID: 201,
		FullName:             "acme/bad-id",
		Classification:       domain.ClassificationPublic,
		Enabled:              true,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for UUIDv4 in Upsert, got %v", err)
	}

	// Nil store returns 503 Unavailable.
	nilSvc := repositories.NewService(nil, nil)
	if _, err := nilSvc.GetByID(ctx, enabledID); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on nil store, got %v", err)
	}
}

func TestRepositoriesIntegrationPG17(t *testing.T) {
	pg := harness.StartPostgres(t)
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	svc := repositories.NewService(store, nil)
	ctx := context.Background()

	created, err := svc.Create(ctx, repositories.UpsertInput{
		GitHubRepositoryID:      9001,
		GitHubInstallationID:    7001,
		FullName:                "custodian/broker",
		Classification:          domain.ClassificationConfidential,
		Enabled:                 true,
		AllowedModelRoutes:      []string{"private-vpc"},
		MaxConcurrentOperations: 4,
	})
	if err != nil {
		t.Fatalf("Create repository: %v", err)
	}
	if !domain.IsUUIDv7(created.ID) {
		t.Fatalf("expected UUIDv7 repo ID, got %s", created.ID)
	}

	// Duplicate Create fails with 409 Conflict.
	_, err = svc.Create(ctx, repositories.UpsertInput{
		GitHubRepositoryID:   9001,
		GitHubInstallationID: 7001,
		FullName:             "custodian/broker",
		Classification:       domain.ClassificationConfidential,
		Enabled:              true,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate github_repository_id, got %v", err)
	}

	// Upsert updates existing repository by github_repository_id.
	updated, err := svc.Upsert(ctx, repositories.UpsertInput{
		GitHubRepositoryID:      9001,
		GitHubInstallationID:    7002,
		FullName:                "custodian/broker",
		Classification:          domain.ClassificationRestricted,
		Enabled:                 false,
		AllowedModelRoutes:      []string{"airgap"},
		MaxConcurrentOperations: 2,
	})
	if err != nil {
		t.Fatalf("Upsert repository: %v", err)
	}
	if updated.ID != created.ID || updated.Enabled || updated.Classification != domain.ClassificationRestricted {
		t.Fatalf("unexpected upserted repo: %+v", updated)
	}

	if _, err := svc.AuthorizeByGitHubID(ctx, 9001, "airgap"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo via AuthorizeByGitHubID, got %v", err)
	}

	// Empty AllowedModelRoutes ('{}') fails closed when modelRoute != "" in PG17, succeeds when modelRoute == "".
	emptyRoutesRepo, err := svc.Create(ctx, repositories.UpsertInput{
		GitHubRepositoryID:   9002,
		GitHubInstallationID: 7001,
		FullName:             "custodian/empty-routes",
		Classification:       domain.ClassificationRestricted,
		Enabled:              true,
	})
	if err != nil {
		t.Fatalf("Create emptyRoutesRepo: %v", err)
	}
	if _, err := svc.Authorize(ctx, emptyRoutesRepo.ID, ""); err != nil {
		t.Fatalf("Authorize empty route on emptyRoutesRepo: %v", err)
	}
	if _, err := svc.Authorize(ctx, emptyRoutesRepo.ID, "any-model"); !errors.Is(err, domain.ErrForbidden) || domain.HTTPStatusFromError(err) != 403 {
		t.Fatalf("expected 403 Forbidden for non-empty route on empty AllowedModelRoutes, got %v", err)
	}

	// Rejects UUIDv4 IDs in PG17 path.
	if _, err := svc.Create(ctx, repositories.UpsertInput{
		ID:                   uuid.New(),
		GitHubRepositoryID:   9003,
		GitHubInstallationID: 7001,
		FullName:             "custodian/v4-id",
		Classification:       domain.ClassificationPublic,
		Enabled:              true,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for UUIDv4 in PG17 Create, got %v", err)
	}
}
