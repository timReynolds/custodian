package harness

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/snapshots"
)

// SnapshotHarness wraps a local filesystem snapshots.LocalStore for offline tests.
type SnapshotHarness struct {
	t       testing.TB
	rootDir string
	store   *snapshots.LocalStore
}

// NewSnapshotHarness initializes an isolated LocalStore in t.TempDir().
func NewSnapshotHarness(t testing.TB) *SnapshotHarness {
	t.Helper()
	dir := t.TempDir()
	store, err := snapshots.NewLocalStore(snapshots.LocalConfig{RootDir: dir})
	if err != nil {
		t.Fatalf("NewSnapshotHarness: %v", err)
	}
	return &SnapshotHarness{
		t:       t,
		rootDir: dir,
		store:   store,
	}
}

func (h *SnapshotHarness) Store() *snapshots.LocalStore {
	return h.store
}

func (h *SnapshotHarness) RootDir() string {
	return h.rootDir
}

func (h *SnapshotHarness) PutBytes(ctx context.Context, kind domain.ArtifactKind, key string, data []byte) (domain.Artifact, error) {
	return h.store.Put(ctx, domain.PutRequest{
		Kind:           kind,
		ObjectKey:      key,
		ExpectedSHA256: domain.SHA256Hex(data),
	}, bytes.NewReader(data), int64(len(data)))
}

func (h *SnapshotHarness) ReadBytes(ctx context.Context, artifact domain.Artifact) ([]byte, error) {
	rc, err := h.store.Open(ctx, artifact)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// CorruptBlob overwrites the stored object bytes directly on disk to test tamper detection.
func (h *SnapshotHarness) CorruptBlob(objectKey string, newData []byte) error {
	clean, err := snapshots.ValidateObjectKey(objectKey)
	if err != nil {
		return err
	}
	target := filepath.Join(h.rootDir, filepath.FromSlash(clean))
	return os.WriteFile(target, newData, 0o644)
}
