package artifacts_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/persistence"
)

type stubArtifactStore struct {
	byID      map[uuid.UUID]persistence.ArtifactRow
	lastLimit int
}

func (s *stubArtifactStore) RegisterArtifact(_ context.Context, arg persistence.RegisterArtifactParams) (persistence.ArtifactRow, error) {
	r := persistence.ArtifactRow{
		ID:                  arg.ID,
		Kind:                arg.Kind,
		SHA256:              arg.SHA256,
		StorageKey:          arg.StorageKey,
		StorageGeneration:   arg.StorageGeneration,
		SizeBytes:           arg.SizeBytes,
		Format:              arg.Format,
		WorkspaceID:         arg.WorkspaceID,
		WorkspaceGeneration: arg.WorkspaceGeneration,
		UploadedBy:          arg.UploadedBy,
		ExpiresAt:           arg.ExpiresAt,
		CreatedAt:           time.Now().UTC(),
	}
	s.byID[r.ID] = r
	return r, nil
}

func (s *stubArtifactStore) GetArtifactByID(_ context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
	r, ok := s.byID[id]
	if !ok {
		return persistence.ArtifactRow{}, domain.NotFound("NOT_FOUND", "not found")
	}
	return r, nil
}

func (s *stubArtifactStore) GetArtifactByStorageObject(_ context.Context, key, gen string) (persistence.ArtifactRow, error) {
	for _, r := range s.byID {
		if r.StorageKey == key && r.StorageGeneration == gen {
			return r, nil
		}
	}
	return persistence.ArtifactRow{}, domain.NotFound("NOT_FOUND", "not found")
}

func (s *stubArtifactStore) ListExpiredArtifacts(_ context.Context, _ time.Time, limit int) ([]persistence.ArtifactRow, error) {
	s.lastLimit = limit
	return nil, nil
}

func (s *stubArtifactStore) MarkArtifactDeleted(_ context.Context, id uuid.UUID, deletedAt time.Time) (persistence.ArtifactRow, error) {
	r, ok := s.byID[id]
	if !ok {
		return persistence.ArtifactRow{}, domain.NotFound("NOT_FOUND", "not found")
	}
	r.DeletedAt = &deletedAt
	return r, nil
}

func TestArtifactsUnitValidation(t *testing.T) {
	t.Parallel()

	svc := artifacts.NewService(&stubArtifactStore{byID: make(map[uuid.UUID]persistence.ArtifactRow)}, nil)
	ctx := context.Background()
	validSHA := strings.Repeat("a", 64)

	// Rejects non-v7 UUID.
	_, err := svc.Register(ctx, artifacts.RegisterInput{
		ID:                uuid.New(), // v4
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            validSHA,
		StorageKey:        "ws/1/source.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         128,
		Format:            "tar+gzip",
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for v4 UUID, got %v", err)
	}

	// Rejects invalid ArtifactKind.
	_, err = svc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKind("BOGUS"),
		SHA256:            validSHA,
		StorageKey:        "ws/1/source.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         128,
		Format:            "tar+gzip",
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid kind, got %v", err)
	}

	// Rejects negative size and empty format.
	_, err = svc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            validSHA,
		StorageKey:        "ws/1/source.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         -1,
		Format:            "tar+gzip",
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for negative size, got %v", err)
	}
	_, err = svc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            validSHA,
		StorageKey:        "ws/1/source.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         10,
		Format:            "",
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for empty format, got %v", err)
	}

	// Normalizes sha256: prefix and uppercase hex.
	rec, err := svc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            "sha256:" + strings.Repeat("AB", 32),
		StorageKey:        "ws/1/source.tar.gz",
		StorageGeneration: "gen-1",
		SizeBytes:         256,
		Format:            "tar+gzip",
	})
	if err != nil {
		t.Fatalf("Register valid artifact: %v", err)
	}
	if rec.SHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("expected normalized lowercase sha256, got %q", rec.SHA256)
	}

	// ListExpired clamps limit <= 0 to 100 and > 1000 to 1000.
	store := &stubArtifactStore{byID: make(map[uuid.UUID]persistence.ArtifactRow)}
	clampSvc := artifacts.NewService(store, nil)
	if _, err := clampSvc.ListExpired(ctx, time.Now(), 0); err != nil {
		t.Fatalf("ListExpired(0): %v", err)
	}
	if store.lastLimit != 100 {
		t.Fatalf("expected limit 0 clamped to 100, got %d", store.lastLimit)
	}
	if _, err := clampSvc.ListExpired(ctx, time.Now(), 5000); err != nil {
		t.Fatalf("ListExpired(5000): %v", err)
	}
	if store.lastLimit != 1000 {
		t.Fatalf("expected limit 5000 clamped to 1000, got %d", store.lastLimit)
	}

	// Nil store returns 503 Unavailable.
	nilSvc := artifacts.NewService(nil, nil)
	if _, err := nilSvc.GetByID(ctx, domain.MustNewID()); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on nil store GetByID, got %v", err)
	}
	if _, err := nilSvc.ListExpired(ctx, time.Now(), 10); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on nil store ListExpired, got %v", err)
	}
}

func TestArtifactsIntegrationPG17(t *testing.T) {
	pg := harness.StartPostgres(t)
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	svc := artifacts.NewService(store, nil)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	expiredAt := now.Add(-1 * time.Hour)
	futureAt := now.Add(24 * time.Hour)

	a1, err := svc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            domain.SHA256Hex([]byte("artifact-1")),
		StorageKey:        "sources/a1.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         100,
		Format:            "tar+gzip",
		ExpiresAt:         &expiredAt,
	})
	if err != nil {
		t.Fatalf("Register a1: %v", err)
	}
	_, err = svc.Register(ctx, artifacts.RegisterInput{
		Kind:              domain.ArtifactKindEgressSnapshot,
		SHA256:            domain.SHA256Hex([]byte("artifact-2")),
		StorageKey:        "snapshots/a2.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         200,
		Format:            "tar+gzip",
		ExpiresAt:         &futureAt,
	})
	if err != nil {
		t.Fatalf("Register a2: %v", err)
	}

	gotByID, err := svc.GetByID(ctx, a1.ID)
	if err != nil || gotByID.SHA256 != a1.SHA256 {
		t.Fatalf("GetByID: (%+v, %v)", gotByID, err)
	}

	gotByObj, err := svc.GetByStorageObject(ctx, "sources/a1.tar.gz", "1")
	if err != nil || gotByObj.ID != a1.ID {
		t.Fatalf("GetByStorageObject: (%+v, %v)", gotByObj, err)
	}

	expired, err := svc.ListExpired(ctx, now, 10)
	if err != nil || len(expired) != 1 || expired[0].ID != a1.ID {
		t.Fatalf("ListExpired expected [a1], got (%+v, %v)", expired, err)
	}

	deleted, err := svc.MarkDeleted(ctx, a1.ID, now)
	if err != nil || deleted.DeletedAt == nil {
		t.Fatalf("MarkDeleted: (%+v, %v)", deleted, err)
	}

	expiredAfter, err := svc.ListExpired(ctx, now, 10)
	if err != nil || len(expiredAfter) != 0 {
		t.Fatalf("expected 0 expired after MarkDeleted, got (%+v, %v)", expiredAfter, err)
	}
}
