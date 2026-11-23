package snapshots

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/timreynolds/custodian/internal/domain"
)

type mockGCSObject struct {
	data        []byte
	generation  int64
	contentType string
}

type mockGCSServer struct {
	mu          sync.Mutex
	bucket      string
	objects     map[string]mockGCSObject
	forceStatus int
	server      *httptest.Server
}

func newMockGCSServer(t *testing.T, bucket string) *mockGCSServer {
	t.Helper()
	m := &mockGCSServer{
		bucket:  bucket,
		objects: make(map[string]mockGCSObject),
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockGCSServer) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	forced := m.forceStatus
	m.mu.Unlock()
	if forced != 0 {
		writeGCSError(w, forced, "forced test error")
		return
	}

	uploadPrefix := "/upload/storage/v1/b/" + m.bucket + "/o"
	objPrefix := "/storage/v1/b/" + m.bucket + "/o/"

	switch {
	case r.Method == http.MethodPost && r.URL.Path == uploadPrefix:
		m.handleUpload(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, objPrefix):
		key, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, objPrefix))
		if err != nil {
			writeGCSError(w, http.StatusBadRequest, "bad object path")
			return
		}
		m.handleGet(w, r, key)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, objPrefix):
		key, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, objPrefix))
		if err != nil {
			writeGCSError(w, http.StatusBadRequest, "bad object path")
			return
		}
		m.handleDelete(w, r, key)
	default:
		writeGCSError(w, http.StatusNotFound, "unsupported route: "+r.Method+" "+r.URL.Path)
	}
}

func (m *mockGCSServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uploadType := q.Get("uploadType")
	if uploadType != "multipart" {
		writeGCSError(w, http.StatusBadRequest, "unsupported uploadType: "+uploadType)
		return
	}
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		writeGCSError(w, http.StatusBadRequest, "invalid multipart content type")
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])

	// Part 1: JSON metadata
	metaPart, err := mr.NextPart()
	if err != nil {
		writeGCSError(w, http.StatusBadRequest, "missing metadata part")
		return
	}
	var meta struct {
		Name        string `json:"name"`
		ContentType string `json:"contentType"`
	}
	if err := json.NewDecoder(metaPart).Decode(&meta); err != nil {
		writeGCSError(w, http.StatusBadRequest, "invalid metadata JSON")
		return
	}

	// Part 2: Object bytes
	dataPart, err := mr.NextPart()
	if err != nil {
		writeGCSError(w, http.StatusBadRequest, "missing media part")
		return
	}
	payload, err := io.ReadAll(dataPart)
	if err != nil {
		writeGCSError(w, http.StatusBadRequest, "aborted upload stream")
		return
	}
	if meta.Name == "" {
		meta.Name = q.Get("name")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	existing, exists := m.objects[meta.Name]
	if ifGen := q.Get("ifGenerationMatch"); ifGen != "" {
		want, _ := strconv.ParseInt(ifGen, 10, 64)
		if want == 0 && exists {
			writeGCSError(w, http.StatusPreconditionFailed, "object already exists")
			return
		}
		if want > 0 && (!exists || existing.generation != want) {
			writeGCSError(w, http.StatusPreconditionFailed, "generation mismatch")
			return
		}
	}

	nextGen := int64(1)
	if exists {
		nextGen = existing.generation + 1
	}
	m.objects[meta.Name] = mockGCSObject{
		data:        payload,
		generation:  nextGen,
		contentType: meta.ContentType,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind":        "storage#object",
		"bucket":      m.bucket,
		"name":        meta.Name,
		"generation":  strconv.FormatInt(nextGen, 10),
		"size":        strconv.FormatInt(int64(len(payload)), 10),
		"contentType": meta.ContentType,
	})
}

func (m *mockGCSServer) handleGet(w http.ResponseWriter, r *http.Request, key string) {
	q := r.URL.Query()
	m.mu.Lock()
	obj, exists := m.objects[key]
	m.mu.Unlock()
	if !exists {
		writeGCSError(w, http.StatusNotFound, "object not found")
		return
	}
	if ifGen := q.Get("ifGenerationMatch"); ifGen != "" {
		want, _ := strconv.ParseInt(ifGen, 10, 64)
		if obj.generation != want {
			writeGCSError(w, http.StatusPreconditionFailed, "generation mismatch")
			return
		}
	}

	if q.Get("alt") == "media" {
		w.Header().Set("Content-Type", obj.contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(obj.data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(obj.data)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind":        "storage#object",
		"bucket":      m.bucket,
		"name":        key,
		"generation":  strconv.FormatInt(obj.generation, 10),
		"size":        strconv.FormatInt(int64(len(obj.data)), 10),
		"contentType": obj.contentType,
	})
}

func (m *mockGCSServer) handleDelete(w http.ResponseWriter, r *http.Request, key string) {
	q := r.URL.Query()
	m.mu.Lock()
	defer m.mu.Unlock()
	obj, exists := m.objects[key]
	if !exists {
		writeGCSError(w, http.StatusNotFound, "object not found")
		return
	}
	if ifGen := q.Get("ifGenerationMatch"); ifGen != "" {
		want, _ := strconv.ParseInt(ifGen, 10, 64)
		if obj.generation != want {
			writeGCSError(w, http.StatusPreconditionFailed, "generation mismatch")
			return
		}
	}
	delete(m.objects, key)
	w.WriteHeader(http.StatusNoContent)
}

func writeGCSError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
}

func TestGCSStoreLifecycleAndPreconditions(t *testing.T) {
	t.Parallel()
	srv := newMockGCSServer(t, "custodian-test-bucket")

	store, err := NewGCSStore(context.Background(), GCSConfig{
		Bucket: "custodian-test-bucket",
		Prefix: "artifacts",
		Options: []option.ClientOption{
			option.WithHTTPClient(srv.server.Client()),
			option.WithEndpoint(srv.server.URL + "/storage/v1/"),
			storage.WithJSONReads(),
		},
	})
	if err != nil {
		t.Fatalf("NewGCSStore: %v", err)
	}
	defer store.Close()

	// Create valid gzipped payload to verify byte-for-byte preservation (no auto-decompression).
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte("hello custodian gcs"))
	_ = gw.Close()
	payload := gzBuf.Bytes()
	wantSHA := domain.SHA256Hex(payload)

	ctx := context.Background()
	art, err := store.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      "ws/123/source.tar.gz",
		ExpectedSHA256: wantSHA,
		MaxBytes:       int64(len(payload) + 100),
		ContentType:    "application/gzip",
	}, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if art.SHA256 != wantSHA || art.StorageGeneration != "1" || art.SizeBytes != int64(len(payload)) {
		t.Fatalf("unexpected artifact: %+v", art)
	}

	// Verify succeeds
	if err := store.Verify(ctx, art); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Open returns exact gzipped bytes
	rc, err := store.Open(ctx, art)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	gotBytes, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(gotBytes, payload) {
		t.Fatalf("byte mismatch: got %d bytes, want %d", len(gotBytes), len(payload))
	}

	// DoesNotExist precondition (Generation == nil) -> 412 -> ErrConflict
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "ws/123/source.tar.gz",
	}, bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate create, got %v", err)
	}

	// Wrong generation CAS update -> ErrConflict
	wrongGen := int64(99)
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:       domain.ArtifactKindWorkspaceSource,
		ObjectKey:  "ws/123/source.tar.gz",
		Generation: &wrongGen,
	}, bytes.NewReader(payload), int64(len(payload))); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on wrong generation CAS, got %v", err)
	}

	// Valid CAS update (gen 1 -> gen 2)
	gen1 := int64(1)
	newPayload := []byte("updated-v2")
	art2, err := store.Put(ctx, domain.PutRequest{
		Kind:       domain.ArtifactKindWorkspaceSource,
		ObjectKey:  "ws/123/source.tar.gz",
		Generation: &gen1,
	}, bytes.NewReader(newPayload), int64(len(newPayload)))
	if err != nil {
		t.Fatalf("CAS Put: %v", err)
	}
	if art2.StorageGeneration != "2" {
		t.Fatalf("expected generation 2, got %q", art2.StorageGeneration)
	}

	// Digest mismatch aborts upload before Commit (object must NOT appear)
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      "ws/123/aborted.tar.gz",
		ExpectedSHA256: strings.Repeat("a", 64),
	}, bytes.NewReader([]byte("bad")), 3); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for digest mismatch, got %v", err)
	}
	if _, err := store.Open(ctx, domain.Artifact{StorageKey: "ws/123/aborted.tar.gz", SizeBytes: -1}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("aborted object must not exist on GCS, got %v", err)
	}

	// Size mismatch aborts upload
	if _, err := store.Put(ctx, domain.PutRequest{
		Kind:      domain.ArtifactKindWorkspaceSource,
		ObjectKey: "ws/123/aborted-size.tar.gz",
	}, bytes.NewReader([]byte("longer-than-declared")), 4); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("expected ErrUnprocessable for size mismatch, got %v", err)
	}

	// Delete with stale generation -> ErrConflict, valid generation -> succeeds -> Open 404
	if err := store.Delete(ctx, art); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on stale generation delete, got %v", err)
	}
	if err := store.Delete(ctx, art2); err != nil {
		t.Fatalf("Delete gen2: %v", err)
	}
	if err := store.Verify(ctx, art2); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}

	// Outage & forbidden mapping (use bounded ctx so GCS client's 503 retry backoff finishes promptly)
	srv.mu.Lock()
	srv.forceStatus = http.StatusServiceUnavailable
	srv.mu.Unlock()
	outageCtx, cancelOutage := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancelOutage()
	if _, err := store.Open(outageCtx, art2); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on 503, got %v", err)
	}

	srv.mu.Lock()
	srv.forceStatus = http.StatusForbidden
	srv.mu.Unlock()
	if _, err := store.Open(ctx, art2); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden on 403, got %v", err)
	}
	_ = fmt.Sprintf("")
}
