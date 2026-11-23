package harness

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestSnapshotHarnessRoundTripAndTamper(t *testing.T) {
	t.Parallel()
	sh := NewSnapshotHarness(t)
	ctx := context.Background()

	payload := []byte("snapshot-harness-payload")
	art, err := sh.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "ws/1/source.tar.gz", payload)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}

	if err := sh.Store().Verify(ctx, art); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	got, err := sh.ReadBytes(ctx, art)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadBytes mismatch: err=%v got=%q", err, got)
	}

	// Duplicate create-once conflicts
	if _, err := sh.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "ws/1/source.tar.gz", payload); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate PutBytes, got %v", err)
	}

	// Corrupt blob on disk -> Verify and ReadBytes fail with ErrUnprocessable
	corrupted := append([]byte(nil), payload...)
	corrupted[0] ^= 0x55
	if err := sh.CorruptBlob("ws/1/source.tar.gz", corrupted); err != nil {
		t.Fatalf("CorruptBlob: %v", err)
	}
	if err := sh.Store().Verify(ctx, art); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable after CorruptBlob, got %v", err)
	}
	if _, err := sh.ReadBytes(ctx, art); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable from ReadBytes after CorruptBlob, got %v", err)
	}

	// Delete -> ErrNotFound
	if err := sh.Store().Delete(ctx, art); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := sh.Store().Verify(ctx, art); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after Delete, got %v", err)
	}
}
