package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/timreynolds/custodian/internal/domain"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeMetaFile(t *testing.T, rootDir, key string, data []byte, gen int64) {
	t.Helper()
	metaDir := filepath.Join(rootDir, ".custodian-meta", "meta")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatalf("mkdir metaDir: %v", err)
	}
	sum := sha256.Sum256([]byte(canonicalFold(key)))
	metaPath := filepath.Join(metaDir, hex.EncodeToString(sum[:])+".json")
	payload, err := json.Marshal(localObjectMeta{
		SHA256:     sha256Hex(data),
		StorageKey: key,
		Generation: gen,
		SizeBytes:  int64(len(data)),
	})
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(metaPath, payload, 0o600); err != nil {
		t.Fatalf("write meta: %v", err)
	}
}

func TestLocalArtifactOpener_ValidAndReadOnly(t *testing.T) {
	root := t.TempDir()
	key := "proposals/p1/canonical-tree.tar.gz"
	content := []byte("canonical-archive-bytes-v1")
	fullPath := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	opener, err := NewLocalArtifactOpener(LocalOpenerConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}

	art := domain.Artifact{
		Kind:       domain.ArtifactKindCanonicalTree,
		StorageKey: key,
		SHA256:     sha256Hex(content),
		SizeBytes:  int64(len(content)),
	}
	rc, err := opener.Open(context.Background(), art)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, readErr := io.ReadAll(rc)
	closeErr := rc.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read/close: read=%v close=%v", readErr, closeErr)
	}
	if string(got) != string(content) {
		t.Fatalf("got %q, want %q", got, content)
	}

	// Strictly read-only: must never create .custodian-meta or locks.
	if _, statErr := os.Stat(filepath.Join(root, ".custodian-meta")); !os.IsNotExist(statErr) {
		t.Fatalf("expected .custodian-meta not to be created by read-only opener, stat err=%v", statErr)
	}
}

func TestLocalArtifactOpener_GenerationAndVerificationErrors(t *testing.T) {
	root := t.TempDir()
	key := "proposals/p2/canonical-tree.tar.gz"
	content := []byte("hello-canonical-tree")
	fullPath := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	writeMetaFile(t, root, key, content, 3)

	opener, err := NewLocalArtifactOpener(LocalOpenerConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}

	// Matching generation succeeds.
	rc, err := opener.Open(context.Background(), domain.Artifact{
		Kind:              domain.ArtifactKindCanonicalTree,
		StorageKey:        key,
		StorageGeneration: "3",
		SHA256:            sha256Hex(content),
		SizeBytes:         int64(len(content)),
	})
	if err != nil {
		t.Fatalf("Open matching generation: %v", err)
	}
	_, _ = io.ReadAll(rc)
	_ = rc.Close()

	// Generation mismatch -> 409 ErrConflict.
	_, err = opener.Open(context.Background(), domain.Artifact{
		Kind:              domain.ArtifactKindCanonicalTree,
		StorageKey:        key,
		StorageGeneration: "2",
		SHA256:            sha256Hex(content),
		SizeBytes:         int64(len(content)),
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on generation mismatch, got %v", err)
	}

	// Size mismatch -> 422 ErrUnprocessable.
	_, err = opener.Open(context.Background(), domain.Artifact{
		Kind:       domain.ArtifactKindCanonicalTree,
		StorageKey: key,
		SHA256:     sha256Hex(content),
		SizeBytes:  int64(len(content) + 1),
	})
	if !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on size mismatch, got %v", err)
	}

	// SHA-256 mismatch -> 422 ErrUnprocessable on Read/EOF.
	rc, err = opener.Open(context.Background(), domain.Artifact{
		Kind:       domain.ArtifactKindCanonicalTree,
		StorageKey: key,
		SHA256:     strings.Repeat("a", 64),
		SizeBytes:  int64(len(content)),
	})
	if err != nil {
		t.Fatalf("Open before streaming digest check: %v", err)
	}
	_, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if !errors.Is(readErr, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on SHA-256 mismatch, got %v", readErr)
	}
}

func TestLocalArtifactOpener_SymlinksAndReservedKeysRejected(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	// Leaf symlink.
	if err := os.Symlink(outsideFile, filepath.Join(root, "leaf-link.tar.gz")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Directory symlink.
	if err := os.Symlink(outsideDir, filepath.Join(root, "dir-link")); err != nil {
		t.Fatalf("dir symlink: %v", err)
	}

	opener, err := NewLocalArtifactOpener(LocalOpenerConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}

	for _, badKey := range []string{
		"leaf-link.tar.gz",
		"dir-link/secret.txt",
		".custodian-meta/meta/abc.json",
		".CUSTODIAN-META/x",
		"../escape.tar.gz",
		"/abs/path.tar.gz",
		"bad\\slash.tar.gz",
		"",
	} {
		_, openErr := opener.Open(context.Background(), domain.Artifact{StorageKey: badKey})
		if !errors.Is(openErr, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest for key %q, got %v", badKey, openErr)
		}
	}
}

func TestLocalArtifactOpener_OutageVsNotFound(t *testing.T) {
	root := t.TempDir()
	opener, err := NewLocalArtifactOpener(LocalOpenerConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}

	// Missing object inside accessible root -> ErrNotFound (404).
	_, err = opener.Open(context.Background(), domain.Artifact{StorageKey: "missing/obj.tar.gz"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing object, got %v", err)
	}

	// Inaccessible / missing root dir -> ErrUnavailable (503 STORAGE_UNAVAILABLE).
	if os.Geteuid() != 0 {
		if err := os.Chmod(root, 0o000); err != nil {
			t.Fatalf("chmod 0000: %v", err)
		}
		defer func() { _ = os.Chmod(root, 0o755) }()

		_, err = opener.Open(context.Background(), domain.Artifact{StorageKey: "missing/obj.tar.gz"})
		if !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("expected ErrUnavailable on chmod 0000 root, got %v", err)
		}
	}

	missingRoot := filepath.Join(t.TempDir(), "does-not-exist")
	missingOpener, err := NewLocalArtifactOpener(LocalOpenerConfig{RootDir: missingRoot})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener(missingRoot): %v", err)
	}
	_, err = missingOpener.Open(context.Background(), domain.Artifact{StorageKey: "obj.tar.gz"})
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for missing root, got %v", err)
	}
}

func TestGCSArtifactOpener_HTTPAndErrorMapping(t *testing.T) {
	content := []byte("gcs-canonical-tree-archive")
	wantSHA := sha256Hex(content)

	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "ok":
			if got := r.URL.Query().Get("ifGenerationMatch"); got != "7" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"error":{"code":412,"message":"missing ifGenerationMatch"}}`))
				return
			}
			if r.URL.Query().Get("alt") != "media" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"kind":        "storage#object",
					"bucket":      "test-bucket",
					"name":        "prefix/p/tree.tar.gz",
					"generation":  "7",
					"size":        strconv.Itoa(len(content)),
					"contentType": "application/octet-stream",
				})
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(content)))
			_, _ = w.Write(content)
		case "size_mismatch":
			if r.URL.Query().Get("alt") != "media" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"kind":       "storage#object",
					"bucket":     "test-bucket",
					"name":       "prefix/p/tree.tar.gz",
					"generation": "7",
					"size":       strconv.Itoa(len(content) + 5),
				})
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(content)+5))
			_, _ = w.Write(append(append([]byte{}, content...), []byte("12345")...))
		case "404":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"message":"not found"}}`))
		case "412":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"error":{"code":412,"message":"precondition failed"}}`))
		case "429":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":429,"message":"rate limited"}}`))
		case "503":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"code":503,"message":"unavailable"}}`))
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	client, err := storage.NewClient(ctx,
		option.WithEndpoint(srv.URL+"/storage/v1/"),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		storage.WithJSONReads(),
	)
	if err != nil {
		t.Fatalf("storage.NewClient: %v", err)
	}
	defer client.Close()
	client.SetRetry(storage.WithMaxAttempts(1))

	opener, closeFn, err := NewArtifactOpener(ctx, ArtifactOpenerConfig{
		StoreKind: "gcs",
		GCSBucket: "test-bucket",
		GCSPrefix: "/prefix/",
		GCSClient: client,
	})
	if err != nil {
		t.Fatalf("NewArtifactOpener(gcs): %v", err)
	}
	defer func() { _ = closeFn() }()

	// Also verify NewArtifactOpener constructing an owned GCS client via GCSOptions.
	ownedOpener, ownedClose, err := NewArtifactOpener(ctx, ArtifactOpenerConfig{
		StoreKind: "gcs",
		GCSBucket: "test-bucket",
		GCSPrefix: "/prefix/",
		GCSOptions: []option.ClientOption{
			option.WithEndpoint(srv.URL + "/storage/v1/"),
			option.WithoutAuthentication(),
			option.WithHTTPClient(srv.Client()),
		},
	})
	if err != nil {
		t.Fatalf("NewArtifactOpener(owned gcs): %v", err)
	}
	defer func() { _ = ownedClose() }()
	mode = "ok"
	if rcOwned, err := ownedOpener.Open(ctx, domain.Artifact{
		Kind:              domain.ArtifactKindCanonicalTree,
		StorageKey:        "p/tree.tar.gz",
		StorageGeneration: "7",
		SHA256:            wantSHA,
		SizeBytes:         int64(len(content)),
	}); err != nil {
		t.Fatalf("owned GCS Open(ok): %v", err)
	} else {
		_, _ = io.ReadAll(rcOwned)
		_ = rcOwned.Close()
	}

	art := domain.Artifact{
		Kind:              domain.ArtifactKindCanonicalTree,
		StorageKey:        "p/tree.tar.gz",
		StorageGeneration: "7",
		SHA256:            wantSHA,
		SizeBytes:         int64(len(content)),
	}

	mode = "ok"
	rc, err := opener.Open(ctx, art)
	if err != nil {
		t.Fatalf("GCS Open(ok): %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || string(got) != string(content) {
		t.Fatalf("GCS read mismatch: err=%v got=%q", err, got)
	}

	// Verify SHA-256 mismatch on GCS stream.
	badSHAArt := art
	badSHAArt.SHA256 = strings.Repeat("b", 64)
	rc, err = opener.Open(ctx, badSHAArt)
	if err != nil {
		t.Fatalf("GCS Open(badSHA): %v", err)
	}
	_, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if !errors.Is(readErr, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on GCS SHA mismatch, got %v", readErr)
	}

	mode = "size_mismatch"
	_, err = opener.Open(ctx, art)
	if !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable on GCS size mismatch, got %v", err)
	}

	cases := []struct {
		m    string
		want error
	}{
		{"404", domain.ErrNotFound},
		{"412", domain.ErrConflict},
		{"429", domain.ErrRateLimited},
		{"503", domain.ErrUnavailable},
	}
	for _, tc := range cases {
		mode = tc.m
		_, err = opener.Open(ctx, art)
		if !errors.Is(err, tc.want) {
			t.Fatalf("GCS mode %s: expected %v, got %v", tc.m, tc.want, err)
		}
	}

	// Direct mapGCSError unit coverage for remaining status codes.
	if !errors.Is(mapGCSError(&googleapi.Error{Code: http.StatusForbidden}), domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for 403")
	}
	if !errors.Is(mapGCSError(&googleapi.Error{Code: http.StatusBadRequest}), domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for 400")
	}
	if !errors.Is(mapGCSError(storage.ErrObjectNotExist), domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for ErrObjectNotExist")
	}
}

func TestLocalArtifactOpener_FIFORejectedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	fifoPath := filepath.Join(root, "pipe.tar.gz")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.Symlink(fifoPath, filepath.Join(root, "link-to-pipe.tar.gz")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	opener, err := NewLocalArtifactOpener(LocalOpenerConfig{RootDir: root})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, openErr := opener.Open(context.Background(), domain.Artifact{StorageKey: "pipe.tar.gz"})
		done <- openErr
	}()

	select {
	case openErr := <-done:
		if !errors.Is(openErr, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest for FIFO, got %v", openErr)
		}
		var domErr *domain.DomainError
		if !errors.As(openErr, &domErr) || domErr.Code() != "INVALID_OBJECT_PATH" {
			t.Fatalf("expected INVALID_OBJECT_PATH, got %v", openErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("LocalArtifactOpener.Open blocked on FIFO")
	}

	_, linkErr := opener.Open(context.Background(), domain.Artifact{StorageKey: "link-to-pipe.tar.gz"})
	var linkDomErr *domain.DomainError
	if !errors.As(linkErr, &linkDomErr) || linkDomErr.Code() != "SYMLINK_NOT_ALLOWED" {
		t.Fatalf("expected SYMLINK_NOT_ALLOWED for symlink to FIFO, got %v", linkErr)
	}
}
