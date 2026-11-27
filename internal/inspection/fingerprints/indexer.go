package fingerprints

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultIndexBatchSize  = 2000
	maxSafeIndexErrorChars = 512
)

// CorpusFile is an explicit in-memory file entry for CorpusIndexer.
type CorpusFile struct {
	Path    string
	Content []byte
	SHA256  string // optional integrity check
}

// IndexRequest configures indexing or reindexing for an IP fingerprint corpus.
type IndexRequest struct {
	CorpusID  uuid.UUID
	Dir       string
	Files     []CorpusFile
	Force     bool
	BatchSize int
}

// IndexResult summarizes the outcome of a CorpusIndexer.Index call.
type IndexResult struct {
	Corpus           domain.IPFingerprintCorpus
	FilesIndexed     int
	FingerprintCount int64
	Skipped          bool
}

// CorpusIndexer deterministically indexes RESTRICTED and CONFIDENTIAL corpora into
// one-way L1/L2/L3 fingerprint rows without persisting any raw source text.
type CorpusIndexer struct {
	store    CorpusStore
	txRunner CorpusTxRunner
	mu       sync.Mutex
	locks    map[uuid.UUID]*sync.Mutex
}

// NewCorpusIndexer creates a CorpusIndexer backed by store and optional txRunner.
// If txRunner is nil and store implements CorpusTxRunner, store is used as the txRunner.
func NewCorpusIndexer(store CorpusStore, txRunner CorpusTxRunner) *CorpusIndexer {
	if txRunner == nil {
		if tr, ok := store.(CorpusTxRunner); ok {
			txRunner = tr
		}
	}
	return &CorpusIndexer{
		store:    store,
		txRunner: txRunner,
		locks:    make(map[uuid.UUID]*sync.Mutex),
	}
}

func (idx *CorpusIndexer) lockFor(corpusID uuid.UUID) *sync.Mutex {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	l, ok := idx.locks[corpusID]
	if !ok {
		l = &sync.Mutex{}
		idx.locks[corpusID] = l
	}
	return l
}

// Index validates, extracts one-way L1-L3 fingerprints, and atomically replaces the corpus's stored fingerprints.
func (idx *CorpusIndexer) Index(ctx context.Context, req IndexRequest) (IndexResult, error) {
	if err := ctx.Err(); err != nil {
		return IndexResult{}, err
	}
	if idx == nil || idx.store == nil {
		return IndexResult{}, domain.Internal("NIL_CORPUS_STORE", "corpus store is required")
	}
	if req.CorpusID == uuid.Nil {
		return IndexResult{}, domain.BadRequest("INVALID_ID", "corpus_id is required")
	}

	corpusMu := idx.lockFor(req.CorpusID)
	corpusMu.Lock()
	defer corpusMu.Unlock()

	corpusRow, err := idx.store.GetIPFingerprintCorpusByID(ctx, req.CorpusID)
	if err != nil {
		return IndexResult{}, err
	}
	corpus := corpusRow.ToDomain()
	if err := corpus.ValidateClassification(); err != nil {
		return IndexResult{}, err
	}
	if corpus.WinnowK <= 0 {
		corpus.WinnowK = defaultWinnowK
	}
	if corpus.WinnowW <= 0 {
		corpus.WinnowW = defaultWinnowW
	}
	if corpus.ChunkSizeBytes <= 0 {
		corpus.ChunkSizeBytes = defaultChunkSizeBytes
	}

	batchSize := req.BatchSize
	if batchSize <= 0 {
		batchSize = defaultIndexBatchSize
	}

	wasReady := corpus.Status == domain.IPCorpusStatusReady

	failCorpus := func(cause error) (IndexResult, error) {
		if wasReady && idx.txRunner != nil {
			// Prior READY corpus and its fingerprints remain intact (no non-TX mutation occurred
			// and any RunCorpusTx failure rolled back cleanly). Preserve READY without disabling matching.
			return IndexResult{}, cause
		}
		curCount := corpus.FingerprintCount
		if c, countErr := idx.store.CountIPFingerprintsByCorpus(context.Background(), corpus.ID); countErr == nil {
			curCount = c
		}
		if wasReady && curCount > 0 {
			return IndexResult{}, cause
		}
		safeErr := sanitizeIndexError(cause)
		_, _ = idx.store.UpdateIPFingerprintCorpusStatus(context.Background(), persistence.UpdateIPFingerprintCorpusStatusParams{
			ID:               corpus.ID,
			Status:           domain.IPCorpusStatusFailed,
			FingerprintCount: curCount,
			LastError:        safeErr,
			UpdatedAt:        time.Now().UTC().Truncate(time.Microsecond),
		})
		return IndexResult{}, cause
	}

	files, err := loadAndValidateCorpusFiles(req)
	if err != nil {
		return failCorpus(err)
	}

	corpusDigest := computeCorpusDigest(corpus.WinnowK, corpus.WinnowW, corpus.ChunkSizeBytes, files)
	if !req.Force &&
		corpus.Status == domain.IPCorpusStatusReady &&
		corpus.LastIndexedDigest == corpusDigest &&
		corpus.FingerprintCount > 0 {
		return IndexResult{
			Corpus:           corpus,
			FilesIndexed:     len(files),
			FingerprintCount: corpus.FingerprintCount,
			Skipped:          true,
		}, nil
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	if !wasReady {
		if _, err := idx.store.UpdateIPFingerprintCorpusStatus(ctx, persistence.UpdateIPFingerprintCorpusStatusParams{
			ID:               corpus.ID,
			Status:           domain.IPCorpusStatusIndexing,
			FingerprintCount: corpus.FingerprintCount,
			LastError:        "",
			UpdatedAt:        now,
		}); err != nil {
			return IndexResult{}, err
		}
	}

	items, err := extractCorpusFingerprints(corpus, files, now)
	if err != nil {
		return failCorpus(err)
	}
	if len(items) == 0 {
		return failCorpus(domain.Unprocessable("EMPTY_CORPUS_FINGERPRINTS", "corpus yielded zero extractable fingerprints"))
	}

	var updatedRow persistence.IPFingerprintCorpusRow
	var finalCount int64
	persistFn := func(tx CorpusTxStore) error {
		if _, err := tx.DeleteIPFingerprintsByCorpus(ctx, corpus.ID); err != nil {
			return err
		}
		for start := 0; start < len(items); start += batchSize {
			end := start + batchSize
			if end > len(items) {
				end = len(items)
			}
			if _, err := tx.UpsertIPFingerprintsBatch(ctx, items[start:end]); err != nil {
				return err
			}
		}
		cnt, err := tx.CountIPFingerprintsByCorpus(ctx, corpus.ID)
		if err != nil {
			return err
		}
		finalCount = cnt
		doneAt := time.Now().UTC().Truncate(time.Microsecond)
		row, err := tx.UpdateIPFingerprintCorpusStatus(ctx, persistence.UpdateIPFingerprintCorpusStatusParams{
			ID:                corpus.ID,
			Status:            domain.IPCorpusStatusReady,
			FingerprintCount:  cnt,
			LastIndexedDigest: corpusDigest,
			LastIndexedAt:     &doneAt,
			LastError:         "",
			UpdatedAt:         doneAt,
		})
		if err != nil {
			return err
		}
		updatedRow = row
		return nil
	}

	if idx.txRunner != nil {
		err = idx.txRunner.RunCorpusTx(ctx, persistFn)
	} else {
		err = persistFn(idx.store)
	}
	if err != nil {
		return failCorpus(err)
	}

	return IndexResult{
		Corpus:           updatedRow.ToDomain(),
		FilesIndexed:     len(files),
		FingerprintCount: finalCount,
		Skipped:          false,
	}, nil
}

func loadAndValidateCorpusFiles(req IndexRequest) ([]CorpusFile, error) {
	var raw []CorpusFile
	if strings.TrimSpace(req.Dir) != "" {
		inv, err := inspection.WalkWorkspace(req.Dir)
		if err != nil {
			return nil, err
		}
		if inv.FilesSkipped > 0 || len(inv.SkippedReasons) > 0 {
			return nil, domain.Unprocessable("INCOMPLETE_CORPUS_WALK", "corpus directory contains unreadable, symlinked, or non-regular files")
		}
		raw = make([]CorpusFile, 0, len(inv.Files))
		for _, entry := range inv.Files {
			content, err := os.ReadFile(entry.AbsPath)
			if err != nil {
				return nil, domain.WrapError(domain.ErrUnprocessable, "CORPUS_FILE_READ_FAILED", "failed reading corpus file", err)
			}
			raw = append(raw, CorpusFile{
				Path:    entry.RelPath,
				Content: content,
			})
		}
	} else {
		raw = make([]CorpusFile, len(req.Files))
		copy(raw, req.Files)
	}

	if len(raw) == 0 {
		return nil, domain.Unprocessable("EMPTY_CORPUS", "corpus contains no files to index")
	}

	out := make([]CorpusFile, 0, len(raw))
	seenPaths := make(map[string]struct{}, len(raw))
	totalNonWhitespace := 0

	for _, f := range raw {
		cleanPath, err := normalizeCorpusRelPath(f.Path)
		if err != nil {
			return nil, err
		}
		if _, dup := seenPaths[cleanPath]; dup {
			return nil, domain.BadRequest("DUPLICATE_CORPUS_PATH", "duplicate file path in corpus")
		}
		seenPaths[cleanPath] = struct{}{}

		if strings.TrimSpace(f.SHA256) != "" {
			expected, err := domain.ParseSHA256Digest(f.SHA256)
			if err != nil {
				return nil, err
			}
			actual := domain.SHA256Hex(f.Content)
			if actual != expected {
				return nil, domain.Unprocessable("CORPUS_FILE_DIGEST_MISMATCH", "corpus file content digest mismatch")
			}
		}

		if !looksBinary(f.Content) {
			totalNonWhitespace += countNonWhitespaceBytes(normalizeText(f.Content))
		}
		out = append(out, CorpusFile{
			Path:    cleanPath,
			Content: f.Content,
		})
	}

	if totalNonWhitespace == 0 {
		return nil, domain.Unprocessable("EMPTY_CORPUS", "corpus contains no non-empty text source files")
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out, nil
}

func normalizeCorpusRelPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsRune(trimmed, '\x00') || strings.ContainsRune(trimmed, '\\') {
		return "", domain.BadRequest("INVALID_CORPUS_PATH", "corpus file path is invalid")
	}
	if strings.HasPrefix(trimmed, "/") || filepath.IsAbs(trimmed) {
		return "", domain.BadRequest("INVALID_CORPUS_PATH", "corpus file path must be relative")
	}
	slash := filepath.ToSlash(filepath.Clean(trimmed))
	slash = strings.TrimPrefix(slash, "./")
	if slash == "" || slash == "." || slash == ".." || strings.HasPrefix(slash, "../") {
		return "", domain.BadRequest("INVALID_CORPUS_PATH", "corpus file path must not traverse outside root")
	}
	return slash, nil
}

func computeCorpusDigest(winnowK, winnowW, chunkSize int, files []CorpusFile) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "k=%d;w=%d;c=%d\n", winnowK, winnowW, chunkSize)
	for _, f := range files {
		pathHash := domain.SHA256Hex([]byte(f.Path))
		contentHash := domain.SHA256Hex(f.Content)
		_, _ = fmt.Fprintf(h, "%s:%s\n", pathHash, contentHash)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func extractCorpusFingerprints(corpus domain.IPFingerprintCorpus, files []CorpusFile, now time.Time) ([]persistence.InsertIPFingerprintParams, error) {
	items := make([]persistence.InsertIPFingerprintParams, 0, len(files)*16)

	for _, f := range files {
		filePathHash := domain.SHA256Hex([]byte(f.Path))
		lang := DetectLanguage(f.Path, f.Content)
		hdr := ExtractHeadersAndBody(f.Content)

		// L1 exact chunks
		chunks := ExtractL1Chunks(f.Path, f.Content, corpus.ChunkSizeBytes)
		for _, ch := range chunks {
			ci := ch.ChunkIndex
			ls := ch.LineStart
			le := ch.LineEnd
			meta := map[string]any{
				"chunk_bytes":       ch.ChunkBytes,
				"corpus_has_header": hdr.HasHeader,
			}
			if err := domain.ValidateIPFingerprintMetadata(meta); err != nil {
				return nil, err
			}
			items = append(items, persistence.InsertIPFingerprintParams{
				CorpusID:        corpus.ID,
				Layer:           domain.FingerprintLayerL1ExactChunk,
				FingerprintHash: ch.HashHex,
				FilePathHash:    filePathHash,
				Language:        lang,
				ChunkIndex:      &ci,
				LineStart:       &ls,
				LineEnd:         &le,
				Metadata:        meta,
				CreatedAt:       now,
			})
		}

		// L2 Winnowing k-grams
		_, winnows := ExtractL2Winnow(f.Path, f.Content, corpus.WinnowK, corpus.WinnowW)
		for _, w := range winnows {
			ls := w.LineStart
			le := w.LineEnd
			tc := w.TokenCount
			meta := map[string]any{
				"winnow_k":          corpus.WinnowK,
				"winnow_w":          corpus.WinnowW,
				"corpus_has_header": hdr.HasHeader,
			}
			if err := domain.ValidateIPFingerprintMetadata(meta); err != nil {
				return nil, err
			}
			items = append(items, persistence.InsertIPFingerprintParams{
				CorpusID:        corpus.ID,
				Layer:           domain.FingerprintLayerL2WinnowKGram,
				FingerprintHash: w.HashHex,
				FilePathHash:    filePathHash,
				Language:        lang,
				LineStart:       &ls,
				LineEnd:         &le,
				TokenCount:      &tc,
				Metadata:        meta,
				CreatedAt:       now,
			})
		}

		// L3 header markers & headerless body hash
		for _, m := range hdr.Markers {
			ls := m.LineStart
			le := m.LineEnd
			meta := map[string]any{
				"marker_kind":       m.MarkerKind,
				"corpus_has_header": true,
			}
			if err := domain.ValidateIPFingerprintMetadata(meta); err != nil {
				return nil, err
			}
			items = append(items, persistence.InsertIPFingerprintParams{
				CorpusID:        corpus.ID,
				Layer:           domain.FingerprintLayerL3HeaderMarker,
				FingerprintHash: m.HashHex,
				FilePathHash:    filePathHash,
				Language:        lang,
				LineStart:       &ls,
				LineEnd:         &le,
				Metadata:        meta,
				CreatedAt:       now,
			})
		}
		if hdr.HasHeader && hdr.HeaderlessBodyHash != "" {
			meta := map[string]any{
				"marker_kind":       "headerless_body",
				"corpus_has_header": true,
			}
			if err := domain.ValidateIPFingerprintMetadata(meta); err != nil {
				return nil, err
			}
			items = append(items, persistence.InsertIPFingerprintParams{
				CorpusID:        corpus.ID,
				Layer:           domain.FingerprintLayerL3HeaderMarker,
				FingerprintHash: hdr.HeaderlessBodyHash,
				FilePathHash:    filePathHash,
				Language:        lang,
				Metadata:        meta,
				CreatedAt:       now,
			})
		}
	}

	return items, nil
}

func sanitizeIndexError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > maxSafeIndexErrorChars {
		msg = msg[:maxSafeIndexErrorChars]
	}
	return msg
}
