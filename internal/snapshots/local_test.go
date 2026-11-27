package snapshots

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestLocalStoreLifecycleAndTamperDetection(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}

	ctx := context.Background()
	payload := []byte("custodian-immutable-blob")
	wantSHA := domain.SHA256Hex(payload)

	art, err := store.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      "workspaces/ws-1/source.tar.gz",
		ExpectedSHA256: wantSHA,
		MaxBytes:       1024,
	}, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if art.StorageGeneration != "1" || art.SHA256 != wantSHA || art.SizeBytes != int64(len(payload)) {
		t.Fatalf("unexpected artifact: %+v", art)
	}

	if err := store.Verify(ctx, art); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	rc, err := store.Open(ctx, art)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("Open read mismatch: err=%v got=%q", err, got)
	}

	// Duplicate create-once returns ErrConflict
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "workspaces/ws-1/source.tar.gz",
	}, bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate put, got %v", err)
	}

	// CAS update with wrong generation returns ErrConflict
	wrongGen := int64(42)
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:       domain.ArtifactKindWorkspaceSource,
		ObjectKey:  "workspaces/ws-1/source.tar.gz",
		Generation: &wrongGen,
	}, bytes.NewReader([]byte("x")), 1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on wrong generation, got %v", err)
	}

	// Valid CAS update increments generation
	gen1 := int64(1)
	v2 := []byte("custodian-immutable-blob-v2")
	art2, err := store.Put(ctx, domain.PutRequest{
		Kind:       domain.ArtifactKindWorkspaceSource,
		ObjectKey:  "workspaces/ws-1/source.tar.gz",
		Generation: &gen1,
	}, bytes.NewReader(v2), int64(len(v2)))
	if err != nil {
		t.Fatalf("CAS Put: %v", err)
	}
	if art2.StorageGeneration != "2" {
		t.Fatalf("expected generation 2, got %q", art2.StorageGeneration)
	}

	// On-disk tampering (same length, different bytes) caught by Verify and Open EOF!
	blobPath := filepath.Join(root, "workspaces", "ws-1", "source.tar.gz")
	tampered := append([]byte(nil), v2...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(blobPath, tampered, 0o644); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	if err := store.Verify(ctx, art2); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on tampered Verify, got %v", err)
	}
	rc2, err := store.Open(ctx, art2)
	if err != nil {
		t.Fatalf("Open after same-size tamper: %v", err)
	}
	_, readErr := io.ReadAll(rc2)
	_ = rc2.Close()
	if !errors.Is(readErr, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable at EOF on tampered Open, got %v", readErr)
	}

	// Delete stale generation fails; current generation succeeds
	if err := store.Delete(ctx, art); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on stale generation delete, got %v", err)
	}
	if err := store.Delete(ctx, art2); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Open(ctx, art2); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestLocalStoreTraversalSymlinkAbortsAndOutage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()

	// Unsafe keys rejected
	for _, badKey := range []string{
		"",
		"/etc/passwd",
		"../escape.tar.gz",
		"a/../../escape.tar.gz",
		"a\\b.tar.gz",
		"a//b.tar.gz",
		"a/./b.tar.gz",
		".custodian-meta/evil.json",
		"a\x00b",
	} {
		if _, err := store.Put(ctx, domain.PutRequest{
			Kind:      domain.ArtifactKindWorkspaceSource,
			ObjectKey: badKey,
		}, bytes.NewReader([]byte("x")), 1); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest for key %q, got %v", badKey, err)
		}
	}

	// Symlink directory escape rejected
	symDir := filepath.Join(root, "escape-dir")
	if err := os.Symlink(outside, symDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "escape-dir/pwned.txt",
	}, bytes.NewReader([]byte("evil")), 4); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for symlink escape, got %v", err)
	}

	// Failed Put (digest mismatch) leaves zero leftover files
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      "clean/aborted.bin",
		ExpectedSHA256: strings.Repeat("0", 64),
	}, bytes.NewReader([]byte("abc")), 3); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for digest mismatch, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "clean", "aborted.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("aborted blob should not exist, got %v", err)
	}

	// Concurrent create-once race: exactly 1 succeeds, others get ErrConflict
	var wg sync.WaitGroup
	var okCount, conflictCount int
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Put(ctx, domain.PutRequest{
				Kind:      domain.ArtifactKindWorkspaceSource,
				ObjectKey: "race/obj.bin",
			}, bytes.NewReader([]byte("race-data")), 9)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				okCount++
			} else if errors.Is(err, domain.ErrConflict) {
				conflictCount++
			} else {
				t.Errorf("unexpected error in race put: %v", err)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 || conflictCount != 7 {
		t.Fatalf("expected 1 success and 7 conflicts, got ok=%d conflict=%d", okCount, conflictCount)
	}

	// Outage simulation via chmod 0000 -> ErrUnavailable (skip only if running as root)
	if os.Geteuid() != 0 {
		outageRoot := t.TempDir()
		outageStore, err := NewLocalStore(LocalConfig{RootDir: outageRoot})
		if err != nil {
			t.Fatalf("NewLocalStore outage: %v", err)
		}
		if err := os.Chmod(outageRoot, 0o000); err != nil {
			t.Fatalf("chmod 0000: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(outageRoot, 0o755) })
		if _, err := outageStore.Put(ctx, domain.PutRequest{
			Kind:      domain.ArtifactKindWorkspaceSource,
			ObjectKey: "sub/outage.bin",
		}, bytes.NewReader([]byte("x")), 1); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("expected ErrUnavailable on permission outage, got %v", err)
		}
	}
}

func TestLocalStoreCaseInsensitiveMetaPrefixReservation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()

	payload := []byte("legit-payload")
	art, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "ws/1/source.tar.gz",
	}, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put legit: %v", err)
	}

	for _, metaKey := range []string{
		".CUSTODIAN-META",
		".CUSTODIAN-META/ws/1/source.tar.gz.json",
		".Custodian-Meta/ws/1/source.tar.gz.json",
		".custodian-META/ws/2/forged.bin.json",
		".cu\u017ftodian-meta",
		".cu\u017ftodian-meta/ws/1/source.tar.gz.json",
		".CU\u017fTODIAN-META/ws/1/source.tar.gz.json",
	} {
		if _, err := store.Put(ctx, domain.PutRequest{
			Kind:      domain.ArtifactKindWorkspaceSource,
			ObjectKey: metaKey,
		}, bytes.NewReader([]byte("{}")), 2); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("Put(%q) expected ErrBadRequest, got %v", metaKey, err)
		}
		if _, err := store.Open(ctx, domain.Artifact{
			StorageKey: metaKey,
			SizeBytes:  -1,
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("Open(%q) expected ErrBadRequest, got %v", metaKey, err)
		}
		if err := store.Verify(ctx, domain.Artifact{
			StorageKey: metaKey,
			SizeBytes:  10,
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("Verify(%q) expected ErrBadRequest, got %v", metaKey, err)
		}
		if err := store.Delete(ctx, domain.Artifact{
			StorageKey: metaKey,
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("Delete(%q) expected ErrBadRequest, got %v", metaKey, err)
		}
	}

	// Legitimate artifact and its generation-checked metadata must remain intact.
	if err := store.Verify(ctx, art); err != nil {
		t.Fatalf("Verify legit after rejected meta probes: %v", err)
	}
}

func TestLocalStoreCaseInsensitiveConcurrentCASRace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}

	ctx := context.Background()
	payload := []byte("content")

	// 25 concurrent rounds
	for i := 0; i < 25; i++ {
		keyA_i := fmt.Sprintf("ws/%d/Blob.tar.gz", i)
		keyB_i := fmt.Sprintf("ws/%d/blob.tar.gz", i)

		var wg sync.WaitGroup
		wg.Add(2)
		results := make(chan error, 2)

		runPut := func(key string) {
			defer wg.Done()
			_, err := store.Put(ctx, domain.PutRequest{
				Kind:      domain.ArtifactKindWorkspaceSource,
				ObjectKey: key,
			}, bytes.NewReader(payload), int64(len(payload)))
			results <- err
		}

		go runPut(keyA_i)
		go runPut(keyB_i)
		wg.Wait()
		close(results)

		// Expect one success, one conflict
		successes := 0
		conflicts := 0
		for err := range results {
			if err == nil {
				successes++
			} else if errors.Is(err, domain.ErrConflict) {
				conflicts++
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Errorf("round %d: expected 1 success and 1 conflict, got %d successes and %d conflicts", i, successes, conflicts)
		}
	}
}

type stepRead struct {
	data []byte
	err  error
}

type scriptedReader struct {
	steps []stepRead
	idx   int
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.steps) {
		return 0, io.EOF
	}
	step := r.steps[r.idx]
	r.idx++
	n := copy(p, step.data)
	return n, step.err
}

type endlessZeroAfterPayloadReader struct {
	payload []byte
	sent    bool
}

func (r *endlessZeroAfterPayloadReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		n := copy(p, r.payload)
		return n, nil
	}
	return 0, nil
}

func assertNoLeftoverLockfiles(t *testing.T, root string) {
	t.Helper()
	locksDir := filepath.Join(root, ".custodian-meta", "locks")
	entries, err := os.ReadDir(locksDir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", locksDir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 leftover lockfiles in %q, found %d", locksDir, len(entries))
	}
}

func TestLocalStoreCrossInstanceCASAndDeleteRace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	storeA, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore A: %v", err)
	}
	storeB, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore B: %v", err)
	}

	ctx := context.Background()
	key := "two/cas/shared.bin"
	initPayload := []byte("init-gen-1")
	art, err := storeA.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      key,
		ExpectedSHA256: domain.SHA256Hex(initPayload),
	}, bytes.NewReader(initPayload), int64(len(initPayload)))
	if err != nil {
		t.Fatalf("initial Put: %v", err)
	}

	// Race 4 goroutines (2 on storeA, 2 on storeB) across 25 sequential CAS generations.
	curGen := int64(1)
	for round := 0; round < 25; round++ {
		type outcome struct {
			art domain.Artifact
			err error
			pay []byte
		}
		results := make(chan outcome, 4)
		var wg sync.WaitGroup
		start := make(chan struct{})

		for g := 0; g < 4; g++ {
			st := storeA
			if g >= 2 {
				st = storeB
			}
			payload := []byte(fmt.Sprintf("round-%02d-goroutine-%d-payload", round, g))
			gen := curGen
			wg.Add(1)
			go func(s *LocalStore, data []byte, wantGen int64) {
				defer wg.Done()
				<-start
				a, putErr := s.Put(ctx, domain.PutRequest{
					Kind:           domain.ArtifactKindWorkspaceSource,
					ObjectKey:      key,
					ExpectedSHA256: domain.SHA256Hex(data),
					Generation:     &wantGen,
				}, bytes.NewReader(data), int64(len(data)))
				results <- outcome{art: a, err: putErr, pay: data}
			}(st, payload, gen)
		}

		close(start)
		wg.Wait()
		close(results)

		var winners []outcome
		conflicts := 0
		for res := range results {
			if res.err == nil {
				winners = append(winners, res)
			} else if errors.Is(res.err, domain.ErrConflict) {
				conflicts++
			} else {
				t.Fatalf("round %d: unexpected error: %v (cause: %v)", round, res.err, errors.Unwrap(res.err))
			}
		}
		if len(winners) != 1 || conflicts != 3 {
			t.Fatalf("round %d: expected 1 CAS winner and 3 conflicts, got winners=%d conflicts=%d", round, len(winners), conflicts)
		}
		wantGenStr := fmt.Sprintf("%d", curGen+1)
		if winners[0].art.StorageGeneration != wantGenStr {
			t.Fatalf("round %d: expected generation %q, got %q", round, wantGenStr, winners[0].art.StorageGeneration)
		}
		if err := storeA.Verify(ctx, winners[0].art); err != nil {
			t.Fatalf("round %d: storeA Verify winner: %v", round, err)
		}
		if err := storeB.Verify(ctx, winners[0].art); err != nil {
			t.Fatalf("round %d: storeB Verify winner: %v", round, err)
		}
		rc, err := storeB.Open(ctx, winners[0].art)
		if err != nil {
			t.Fatalf("round %d: storeB Open winner: %v", round, err)
		}
		got, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil || !bytes.Equal(got, winners[0].pay) {
			t.Fatalf("round %d: payload mismatch: err=%v", round, readErr)
		}
		art = winners[0].art
		curGen++
	}
	_ = art

	// Race Delete vs CAS Put across storeA and storeB.
	for round := 0; round < 20; round++ {
		raceKey := fmt.Sprintf("two/del-cas/%d.bin", round)
		basePayload := []byte(fmt.Sprintf("base-%d", round))
		baseArt, err := storeA.Put(ctx, domain.PutRequest{
			Kind:           domain.ArtifactKindWorkspaceSource,
			ObjectKey:      raceKey,
			ExpectedSHA256: domain.SHA256Hex(basePayload),
		}, bytes.NewReader(basePayload), int64(len(basePayload)))
		if err != nil {
			t.Fatalf("del-cas seed %d: %v", round, err)
		}

		nextPayload := []byte(fmt.Sprintf("next-%d", round))
		gen1 := int64(1)
		var delErr, putErr error
		var nextArt domain.Artifact
		var wg sync.WaitGroup
		start := make(chan struct{})

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			delErr = storeA.Delete(ctx, baseArt)
		}()
		go func() {
			defer wg.Done()
			<-start
			nextArt, putErr = storeB.Put(ctx, domain.PutRequest{
				Kind:           domain.ArtifactKindWorkspaceSource,
				ObjectKey:      raceKey,
				ExpectedSHA256: domain.SHA256Hex(nextPayload),
				Generation:     &gen1,
			}, bytes.NewReader(nextPayload), int64(len(nextPayload)))
		}()
		close(start)
		wg.Wait()

		switch {
		case delErr == nil && errors.Is(putErr, domain.ErrConflict):
			if _, err := storeB.Open(ctx, baseArt); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("del-cas %d: expected ErrNotFound after Delete won, got %v", round, err)
			}
		case putErr == nil && errors.Is(delErr, domain.ErrConflict):
			if nextArt.StorageGeneration != "2" {
				t.Fatalf("del-cas %d: expected gen 2, got %q", round, nextArt.StorageGeneration)
			}
			if err := storeA.Verify(ctx, nextArt); err != nil {
				t.Fatalf("del-cas %d: expected Verify after Put won: %v", round, err)
			}
		default:
			t.Fatalf("del-cas %d: inconsistent race outcome delErr=%v putErr=%v", round, delErr, putErr)
		}
	}

	assertNoLeftoverLockfiles(t, root)
}

func TestLocalStoreTrailingZeroNilReaderAndEmptyReadBound(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()

	// Reader emits (N, nil), then (0, nil), then (1, io.EOF) -> must reject as ErrUnprocessable.
	rTrailing := &scriptedReader{
		steps: []stepRead{
			{data: []byte("abcd"), err: nil},
			{data: nil, err: nil},
			{data: []byte("X"), err: io.EOF},
		},
	}
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "stream/trailing-after-zero.bin",
	}, rTrailing, 4); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on trailing byte after (0, nil), got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "stream", "trailing-after-zero.bin")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected rejected blob not to exist, got %v", statErr)
	}

	// Reader emits (N, nil), then (0, nil), then (0, io.EOF) -> valid exact stream.
	rValid := &scriptedReader{
		steps: []stepRead{
			{data: []byte("abcd"), err: nil},
			{data: nil, err: nil},
			{data: nil, err: io.EOF},
		},
	}
	art, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "stream/zero-then-eof.bin",
	}, rValid, 4)
	if err != nil {
		t.Fatalf("expected valid (0, nil) before io.EOF to succeed, got %v", err)
	}
	if err := store.Verify(ctx, art); err != nil {
		t.Fatalf("Verify valid stream: %v", err)
	}

	// Reader emits endless (0, nil) after payload -> bounded loop returns ErrBadRequest.
	rEndless := &endlessZeroAfterPayloadReader{payload: []byte("abcd")}
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "stream/endless-zero.bin",
	}, rEndless, 4); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest on endless (0, nil) trailing reads, got %v", err)
	}

	assertNoLeftoverLockfiles(t, root)
}

func TestLocalStorePostConstructionRootSymlinkSwap(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "snap-root")
	outside := t.TempDir()

	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()

	payload := []byte("before-swap")
	art, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "ok/item.bin",
	}, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("initial Put: %v", err)
	}

	// Swap RootDir with a symlink pointing outside after construction.
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("RemoveAll root: %v", err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatalf("Symlink root -> outside: %v", err)
	}

	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "escape.bin",
	}, bytes.NewReader([]byte("pwn")), 3); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("Put after RootDir symlink swap: expected ErrBadRequest, got %v", err)
	}
	if _, err := store.Open(ctx, art); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("Open after RootDir symlink swap: expected ErrBadRequest, got %v", err)
	}
	if err := store.Verify(ctx, art); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("Verify after RootDir symlink swap: expected ErrBadRequest, got %v", err)
	}
	if err := store.Delete(ctx, art); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("Delete after RootDir symlink swap: expected ErrBadRequest, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "escape.bin")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected nothing written to outside dir, got %v", statErr)
	}
}

func TestLocalStoreDeleteEmptyDirectoryWithoutMetaRejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()

	art, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "dir/sub/file.bin",
	}, bytes.NewReader([]byte("abc")), 3)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, art); err != nil {
		t.Fatalf("Delete file: %v", err)
	}

	// "dir/sub" is now an empty directory with no metadata; Delete must return ErrBadRequest and not remove it.
	if err := store.Delete(ctx, domain.Artifact{StorageKey: "dir/sub"}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest deleting directory key, got %v", err)
	}
	fi, err := os.Stat(filepath.Join(root, "dir", "sub"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("expected empty directory to remain intact, fi=%v err=%v", fi, err)
	}
}

func TestLocalStoreRemovedRootOutageAndFileCountDelta(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "snap-root")
	store, err := NewLocalStore(LocalConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	ctx := context.Background()

	countAllFiles := func(dir string) int {
		count := 0
		_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				count++
			}
			return nil
		})
		return count
	}

	payload := []byte("hello")
	art, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "delta/obj.bin",
	}, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	beforeFailed := countAllFiles(root)

	// Failed Put (oversized, digest mismatch, conflict) must not change total file count in root.
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "delta/fail-size.bin",
		MaxBytes:  2,
	}, bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable, got %v", err)
	}
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      "delta/fail-sha.bin",
		ExpectedSHA256: strings.Repeat("0", 64),
	}, bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable, got %v", err)
	}
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "delta/obj.bin",
	}, bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if afterFailed := countAllFiles(root); afterFailed != beforeFailed {
		t.Fatalf("file count changed after failed Puts: before=%d after=%d", beforeFailed, afterFailed)
	}

	// Delete must strictly reduce total file count in root.
	if err := store.Delete(ctx, art); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if afterDelete := countAllFiles(root); afterDelete >= beforeFailed {
		t.Fatalf("expected file count to decrease after Delete: before=%d after=%d", beforeFailed, afterDelete)
	}

	// Removed RootDir maps all operations to ErrUnavailable (never ErrNotFound).
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "outage/x.bin",
	}, bytes.NewReader([]byte("x")), 1); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Put after RemoveAll: expected ErrUnavailable, got %v", err)
	}
	if _, err := store.Open(ctx, art); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Open after RemoveAll: expected ErrUnavailable, got %v", err)
	}
	if err := store.Verify(ctx, art); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Verify after RemoveAll: expected ErrUnavailable, got %v", err)
	}
	if err := store.Delete(ctx, art); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Delete after RemoveAll: expected ErrUnavailable, got %v", err)
	}
}
