package fingerprints

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

// FingerprintLookupStore is the minimal read-only store required by Engine.Analyze.
type FingerprintLookupStore interface {
	LookupIPFingerprintsByHashes(ctx context.Context, layer domain.FingerprintLayer, hashes []string) ([]persistence.IPFingerprintLookupRow, error)
}

// CorpusTxStore represents the transactional persistence operations used during atomic corpus reindexing.
type CorpusTxStore interface {
	DeleteIPFingerprintsByCorpus(ctx context.Context, corpusID uuid.UUID) (int64, error)
	UpsertIPFingerprintsBatch(ctx context.Context, items []persistence.InsertIPFingerprintParams) (int64, error)
	CountIPFingerprintsByCorpus(ctx context.Context, corpusID uuid.UUID) (int64, error)
	UpdateIPFingerprintCorpusStatus(ctx context.Context, arg persistence.UpdateIPFingerprintCorpusStatusParams) (persistence.IPFingerprintCorpusRow, error)
}

// CorpusStore abstracts persistence for both Engine lookups and CorpusIndexer lifecycle/reindex operations.
// *persistence.Store and *persistence.Tx satisfy CorpusStore directly without adapter structs.
type CorpusStore interface {
	FingerprintLookupStore
	CorpusTxStore
	GetIPFingerprintCorpusByID(ctx context.Context, id uuid.UUID) (persistence.IPFingerprintCorpusRow, error)
}

// CorpusTxRunner wraps transactional execution of Delete + Upsert + Count + StatusUpdate.
type CorpusTxRunner interface {
	RunCorpusTx(ctx context.Context, fn func(tx CorpusTxStore) error) error
}

type persistenceTxRunner struct {
	store *persistence.Store
}

// NewPersistenceTxRunner wraps *persistence.Store.WithTx as a CorpusTxRunner for atomic corpus reindexing.
func NewPersistenceTxRunner(store *persistence.Store) CorpusTxRunner {
	if store == nil {
		return nil
	}
	return &persistenceTxRunner{store: store}
}

func (r *persistenceTxRunner) RunCorpusTx(ctx context.Context, fn func(tx CorpusTxStore) error) error {
	if r == nil || r.store == nil {
		return domain.Internal("NIL_PERSISTENCE_STORE", "persistence store is required")
	}
	return r.store.WithTx(ctx, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}

var (
	_ FingerprintLookupStore = (*persistence.Store)(nil)
	_ CorpusStore            = (*persistence.Store)(nil)
	_ CorpusStore            = (*persistence.Tx)(nil)
	_ CorpusStore            = (*MemoryCorpusStore)(nil)
	_ CorpusTxRunner         = (*MemoryCorpusStore)(nil)
)

// MemoryCorpusStore is a thread-safe in-memory CorpusStore and CorpusTxRunner enforcing the
// same validation, UNIQUE NULLS NOT DISTINCT deduplication, and READY+enabled filtering rules
// as PostgreSQL persistence for fast unit testing.
type MemoryCorpusStore struct {
	txMu           sync.Mutex
	mu             sync.RWMutex
	corpora        map[uuid.UUID]persistence.IPFingerprintCorpusRow
	corpusByName   map[string]uuid.UUID
	fingerprints   map[uuid.UUID]map[string]persistence.IPFingerprintRow // corpusID -> dedupKey -> row
	touchedCorpora map[uuid.UUID]struct{}
	touchedFP      map[uuid.UUID]struct{}
}

// NewMemoryCorpusStore constructs an empty in-memory fingerprint store.
func NewMemoryCorpusStore() *MemoryCorpusStore {
	return &MemoryCorpusStore{
		corpora:      make(map[uuid.UUID]persistence.IPFingerprintCorpusRow),
		corpusByName: make(map[string]uuid.UUID),
		fingerprints: make(map[uuid.UUID]map[string]persistence.IPFingerprintRow),
	}
}

// CreateIPFingerprintCorpus creates a corpus in memory matching persistence validation rules.
func (s *MemoryCorpusStore) CreateIPFingerprintCorpus(ctx context.Context, arg persistence.CreateIPFingerprintCorpusParams) (persistence.IPFingerprintCorpusRow, error) {
	if err := ctx.Err(); err != nil {
		return persistence.IPFingerprintCorpusRow{}, err
	}
	name := strings.TrimSpace(arg.Name)
	if name == "" {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "corpus name is required")
	}
	if err := (domain.IPFingerprintCorpus{Classification: arg.Classification}).ValidateClassification(); err != nil {
		return persistence.IPFingerprintCorpusRow{}, err
	}
	if arg.RepositoryID != nil && *arg.RepositoryID == uuid.Nil {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "repository_id must not be nil when provided")
	}
	if arg.CreatedBy != nil && *arg.CreatedBy == uuid.Nil {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "created_by must not be nil when provided")
	}
	winnowK := arg.WinnowK
	if winnowK == 0 {
		winnowK = 25
	}
	if winnowK < 1 {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "winnow_k must be >= 1")
	}
	winnowW := arg.WinnowW
	if winnowW == 0 {
		winnowW = 15
	}
	if winnowW < 1 {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "winnow_w must be >= 1")
	}
	chunkSize := arg.ChunkSizeBytes
	if chunkSize == 0 {
		chunkSize = 4096
	}
	if chunkSize < 1 {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "chunk_size_bytes must be >= 1")
	}
	enabled := true
	if arg.Enabled != nil {
		enabled = *arg.Enabled
	}
	status := arg.Status
	if status == "" {
		status = domain.IPCorpusStatusPending
	}
	if !status.IsValid() {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS_STATUS", "invalid corpus status")
	}
	if arg.FingerprintCount < 0 {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "fingerprint_count must be >= 0")
	}
	var lastDigest *string
	if strings.TrimSpace(arg.LastIndexedDigest) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.LastIndexedDigest)
		if err != nil {
			return persistence.IPFingerprintCorpusRow{}, err
		}
		lastDigest = &parsed
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return persistence.IPFingerprintCorpusRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "corpus id must be UUIDv7")
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	createdAt := now
	if !arg.CreatedAt.IsZero() {
		createdAt = arg.CreatedAt.UTC().Truncate(time.Microsecond)
	}
	updatedAt := createdAt
	if !arg.UpdatedAt.IsZero() {
		updatedAt = arg.UpdatedAt.UTC().Truncate(time.Microsecond)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.corpora[id]; exists {
		return persistence.IPFingerprintCorpusRow{}, domain.Conflict("CONFLICT", "corpus id already exists")
	}
	if _, exists := s.corpusByName[name]; exists {
		return persistence.IPFingerprintCorpusRow{}, domain.Conflict("CONFLICT", "corpus name already exists")
	}

	row := persistence.IPFingerprintCorpusRow{
		ID:                id,
		Name:              name,
		Description:       optStrPtr(arg.Description),
		Classification:    arg.Classification,
		RepositoryID:      copyUUIDPtr(arg.RepositoryID),
		SourceRef:         strings.TrimSpace(arg.SourceRef),
		WinnowK:           winnowK,
		WinnowW:           winnowW,
		ChunkSizeBytes:    chunkSize,
		Enabled:           enabled,
		Status:            status,
		FingerprintCount:  arg.FingerprintCount,
		LastIndexedDigest: lastDigest,
		LastIndexedAt:     copyTimePtr(arg.LastIndexedAt),
		LastError:         optStrPtr(arg.LastError),
		CreatedBy:         copyUUIDPtr(arg.CreatedBy),
		CreatedAt:         createdAt,
		UpdatedAt:         updatedAt,
	}
	s.corpora[id] = row
	s.corpusByName[name] = id
	if s.touchedCorpora != nil {
		s.touchedCorpora[id] = struct{}{}
	}
	return cloneCorpusRow(row), nil
}

// GetIPFingerprintCorpusByID returns a corpus by ID or ErrNotFound.
func (s *MemoryCorpusStore) GetIPFingerprintCorpusByID(ctx context.Context, id uuid.UUID) (persistence.IPFingerprintCorpusRow, error) {
	if err := ctx.Err(); err != nil {
		return persistence.IPFingerprintCorpusRow{}, err
	}
	if id == uuid.Nil {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "corpus id must not be nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	row, ok := s.corpora[id]
	if !ok {
		return persistence.IPFingerprintCorpusRow{}, domain.NotFound("NOT_FOUND", "ip fingerprint corpus not found")
	}
	return cloneCorpusRow(row), nil
}

// UpdateIPFingerprintCorpusStatus updates corpus lifecycle state with COALESCE digest/timestamp semantics.
func (s *MemoryCorpusStore) UpdateIPFingerprintCorpusStatus(ctx context.Context, arg persistence.UpdateIPFingerprintCorpusStatusParams) (persistence.IPFingerprintCorpusRow, error) {
	if err := ctx.Err(); err != nil {
		return persistence.IPFingerprintCorpusRow{}, err
	}
	if arg.ID == uuid.Nil {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "corpus id must not be nil")
	}
	if !arg.Status.IsValid() {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS_STATUS", "invalid corpus status")
	}
	if arg.FingerprintCount < 0 {
		return persistence.IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "fingerprint_count must be >= 0")
	}
	var digestPtr *string
	if strings.TrimSpace(arg.LastIndexedDigest) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.LastIndexedDigest)
		if err != nil {
			return persistence.IPFingerprintCorpusRow{}, err
		}
		digestPtr = &parsed
	}
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	if !arg.UpdatedAt.IsZero() {
		updatedAt = arg.UpdatedAt.UTC().Truncate(time.Microsecond)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.corpora[arg.ID]
	if !ok {
		return persistence.IPFingerprintCorpusRow{}, domain.NotFound("NOT_FOUND", "ip fingerprint corpus not found")
	}
	row.Status = arg.Status
	row.FingerprintCount = arg.FingerprintCount
	if digestPtr != nil {
		row.LastIndexedDigest = digestPtr
	}
	if arg.LastIndexedAt != nil {
		row.LastIndexedAt = copyTimePtr(arg.LastIndexedAt)
	}
	row.LastError = optStrPtr(arg.LastError)
	row.UpdatedAt = updatedAt
	s.corpora[arg.ID] = row
	if s.touchedCorpora != nil {
		s.touchedCorpora[arg.ID] = struct{}{}
	}
	return cloneCorpusRow(row), nil
}

// UpsertIPFingerprintsBatch validates, deduplicates, and upserts fingerprint rows.
func (s *MemoryCorpusStore) UpsertIPFingerprintsBatch(ctx context.Context, items []persistence.InsertIPFingerprintParams) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(items) == 0 {
		return 0, nil
	}

	type prepared struct {
		key string
		row persistence.IPFingerprintRow
	}
	prepped := make([]prepared, 0, len(items))
	seen := make(map[string]int, len(items))

	for _, item := range items {
		row, key, err := prepareMemoryFingerprint(item)
		if err != nil {
			return 0, err
		}
		if idx, ok := seen[key]; ok {
			prepped[idx] = prepared{key: key, row: row}
			continue
		}
		seen[key] = len(prepped)
		prepped = append(prepped, prepared{key: key, row: row})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var affected int64
	for _, p := range prepped {
		if _, ok := s.corpora[p.row.CorpusID]; !ok {
			return 0, domain.NotFound("NOT_FOUND", "corpus not found for fingerprint")
		}
		byCorpus := s.fingerprints[p.row.CorpusID]
		if byCorpus == nil {
			byCorpus = make(map[string]persistence.IPFingerprintRow)
			s.fingerprints[p.row.CorpusID] = byCorpus
		}
		if existing, exists := byCorpus[p.key]; exists {
			merged := p.row
			merged.ID = existing.ID
			merged.CreatedAt = existing.CreatedAt
			if merged.Language == nil {
				merged.Language = copyStrPtr(existing.Language)
			}
			if merged.LineStart == nil {
				merged.LineStart = copyIntPtr(existing.LineStart)
			}
			if merged.LineEnd == nil {
				merged.LineEnd = copyIntPtr(existing.LineEnd)
			}
			if merged.TokenCount == nil {
				merged.TokenCount = copyIntPtr(existing.TokenCount)
			}
			byCorpus[p.key] = merged
		} else {
			byCorpus[p.key] = p.row
		}
		if s.touchedFP != nil {
			s.touchedFP[p.row.CorpusID] = struct{}{}
		}
		affected++
	}
	return affected, nil
}

// DeleteIPFingerprintsByCorpus removes all fingerprints for corpusID and returns the deleted count.
func (s *MemoryCorpusStore) DeleteIPFingerprintsByCorpus(ctx context.Context, corpusID uuid.UUID) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if corpusID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "corpus_id must not be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := s.fingerprints[corpusID]
	n := int64(len(existing))
	delete(s.fingerprints, corpusID)
	if s.touchedFP != nil {
		s.touchedFP[corpusID] = struct{}{}
	}
	return n, nil
}

// CountIPFingerprintsByCorpus counts stored fingerprints for corpusID.
func (s *MemoryCorpusStore) CountIPFingerprintsByCorpus(ctx context.Context, corpusID uuid.UUID) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if corpusID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "corpus_id must not be nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.fingerprints[corpusID])), nil
}

// LookupIPFingerprintsByHashes looks up matching hashes across enabled READY corpora for the given layer.
func (s *MemoryCorpusStore) LookupIPFingerprintsByHashes(ctx context.Context, layer domain.FingerprintLayer, hashes []string) ([]persistence.IPFingerprintLookupRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !layer.IsValid() {
		return nil, domain.BadRequest("INVALID_FINGERPRINT_LAYER", "invalid fingerprint layer")
	}
	if len(hashes) == 0 {
		return []persistence.IPFingerprintLookupRow{}, nil
	}
	wanted := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		norm, err := normalizeFingerprintHash(h)
		if err != nil {
			return nil, err
		}
		wanted[norm] = struct{}{}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]persistence.IPFingerprintLookupRow, 0)
	for corpusID, byKey := range s.fingerprints {
		corpus, ok := s.corpora[corpusID]
		if !ok || !corpus.Enabled || corpus.Status != domain.IPCorpusStatusReady {
			continue
		}
		for _, row := range byKey {
			if row.Layer != layer {
				continue
			}
			if _, match := wanted[row.FingerprintHash]; !match {
				continue
			}
			out = append(out, persistence.IPFingerprintLookupRow{
				IPFingerprintRow: cloneFingerprintRow(row),
				CorpusName:       corpus.Name,
				Classification:   corpus.Classification,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

// RunCorpusTx runs fn against an isolated transactional snapshot, rolling back on error.
func (s *MemoryCorpusStore) RunCorpusTx(ctx context.Context, fn func(tx CorpusTxStore) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()

	s.mu.RLock()
	txStore := &MemoryCorpusStore{
		corpora:        make(map[uuid.UUID]persistence.IPFingerprintCorpusRow, len(s.corpora)),
		corpusByName:   make(map[string]uuid.UUID, len(s.corpusByName)),
		fingerprints:   make(map[uuid.UUID]map[string]persistence.IPFingerprintRow, len(s.fingerprints)),
		touchedCorpora: make(map[uuid.UUID]struct{}),
		touchedFP:      make(map[uuid.UUID]struct{}),
	}
	for k, v := range s.corpora {
		txStore.corpora[k] = cloneCorpusRow(v)
	}
	for k, v := range s.corpusByName {
		txStore.corpusByName[k] = v
	}
	for cid, rows := range s.fingerprints {
		cp := make(map[string]persistence.IPFingerprintRow, len(rows))
		for k, r := range rows {
			cp[k] = cloneFingerprintRow(r)
		}
		txStore.fingerprints[cid] = cp
	}
	s.mu.RUnlock()

	if err := fn(txStore); err != nil {
		return err
	}

	s.mu.Lock()
	for cid := range txStore.touchedCorpora {
		if row, ok := txStore.corpora[cid]; ok {
			s.corpora[cid] = row
			s.corpusByName[row.Name] = cid
		} else {
			delete(s.corpora, cid)
		}
	}
	for cid := range txStore.touchedFP {
		if rows, ok := txStore.fingerprints[cid]; ok {
			s.fingerprints[cid] = rows
		} else {
			delete(s.fingerprints, cid)
		}
	}
	s.mu.Unlock()
	return nil
}

// ListAllFingerprints returns a deterministic snapshot of stored fingerprint rows for corpusID (for tests).
func (s *MemoryCorpusStore) ListAllFingerprints(corpusID uuid.UUID) []persistence.IPFingerprintRow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	byKey := s.fingerprints[corpusID]
	out := make([]persistence.IPFingerprintRow, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, cloneFingerprintRow(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Layer != out[j].Layer {
			return out[i].Layer < out[j].Layer
		}
		return out[i].FingerprintHash < out[j].FingerprintHash
	})
	return out
}

func normalizeFingerprintHash(raw string) (string, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "sha256:")
	if len(trimmed) < 16 || len(trimmed) > 64 || len(trimmed)%2 != 0 {
		return "", domain.BadRequest("INVALID_FINGERPRINT_HASH", "fingerprint_hash must be 16-64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(trimmed); err != nil {
		return "", domain.BadRequest("INVALID_FINGERPRINT_HASH", "fingerprint_hash must be valid hex")
	}
	return trimmed, nil
}

func prepareMemoryFingerprint(arg persistence.InsertIPFingerprintParams) (persistence.IPFingerprintRow, string, error) {
	if arg.CorpusID == uuid.Nil {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_ID", "corpus_id must not be nil")
	}
	if !arg.Layer.IsValid() {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_FINGERPRINT_LAYER", "invalid fingerprint layer")
	}
	fpHash, err := normalizeFingerprintHash(arg.FingerprintHash)
	if err != nil {
		return persistence.IPFingerprintRow{}, "", err
	}
	var filePathHash *string
	if strings.TrimSpace(arg.FilePathHash) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.FilePathHash)
		if err != nil {
			return persistence.IPFingerprintRow{}, "", err
		}
		filePathHash = &parsed
	}
	if arg.ChunkIndex != nil && *arg.ChunkIndex < 0 {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_FINGERPRINT", "chunk_index must be >= 0")
	}
	if arg.LineStart != nil && *arg.LineStart < 0 {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_FINGERPRINT", "line_start must be >= 0")
	}
	if arg.LineEnd != nil && *arg.LineEnd < 0 {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_FINGERPRINT", "line_end must be >= 0")
	}
	if arg.TokenCount != nil && *arg.TokenCount < 0 {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_FINGERPRINT", "token_count must be >= 0")
	}
	if err := domain.ValidateIPFingerprintMetadata(arg.Metadata); err != nil {
		return persistence.IPFingerprintRow{}, "", err
	}
	meta := arg.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	rawMeta, err := json.Marshal(meta)
	if err != nil {
		return persistence.IPFingerprintRow{}, "", domain.WrapError(domain.ErrBadRequest, "INVALID_METADATA", "failed to marshal fingerprint metadata", err)
	}
	canonMeta, err := domain.CanonicalJSONBytes(rawMeta)
	if err != nil {
		return persistence.IPFingerprintRow{}, "", err
	}

	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return persistence.IPFingerprintRow{}, "", err
		}
	} else if !domain.IsUUIDv7(id) {
		return persistence.IPFingerprintRow{}, "", domain.BadRequest("INVALID_ID", "ip_fingerprint id must be UUIDv7")
	}
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	if !arg.CreatedAt.IsZero() {
		createdAt = arg.CreatedAt.UTC().Truncate(time.Microsecond)
	}

	fph := "<nil>"
	if filePathHash != nil {
		fph = *filePathHash
	}
	ci := "<nil>"
	if arg.ChunkIndex != nil {
		ci = fmt.Sprintf("%d", *arg.ChunkIndex)
	}
	dedupKey := fmt.Sprintf("%s|%s|%s|%s|%s", arg.CorpusID, arg.Layer, fpHash, fph, ci)

	row := persistence.IPFingerprintRow{
		ID:              id,
		CorpusID:        arg.CorpusID,
		Layer:           arg.Layer,
		FingerprintHash: fpHash,
		FilePathHash:    filePathHash,
		Language:        optStrPtr(strings.TrimSpace(arg.Language)),
		ChunkIndex:      copyIntPtr(arg.ChunkIndex),
		LineStart:       copyIntPtr(arg.LineStart),
		LineEnd:         copyIntPtr(arg.LineEnd),
		TokenCount:      copyIntPtr(arg.TokenCount),
		Metadata:        json.RawMessage(canonMeta),
		CreatedAt:       createdAt,
	}
	return row, dedupKey, nil
}

func optStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

func copyStrPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyUUIDPtr(p *uuid.UUID) *uuid.UUID {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyTimePtr(p *time.Time) *time.Time {
	if p == nil {
		return nil
	}
	v := p.UTC().Truncate(time.Microsecond)
	return &v
}

func cloneCorpusRow(r persistence.IPFingerprintCorpusRow) persistence.IPFingerprintCorpusRow {
	r.Description = copyStrPtr(r.Description)
	r.RepositoryID = copyUUIDPtr(r.RepositoryID)
	r.LastIndexedDigest = copyStrPtr(r.LastIndexedDigest)
	r.LastIndexedAt = copyTimePtr(r.LastIndexedAt)
	r.LastError = copyStrPtr(r.LastError)
	r.CreatedBy = copyUUIDPtr(r.CreatedBy)
	return r
}

func cloneFingerprintRow(r persistence.IPFingerprintRow) persistence.IPFingerprintRow {
	r.FilePathHash = copyStrPtr(r.FilePathHash)
	r.Language = copyStrPtr(r.Language)
	r.ChunkIndex = copyIntPtr(r.ChunkIndex)
	r.LineStart = copyIntPtr(r.LineStart)
	r.LineEnd = copyIntPtr(r.LineEnd)
	r.TokenCount = copyIntPtr(r.TokenCount)
	if r.Metadata != nil {
		cp := make(json.RawMessage, len(r.Metadata))
		copy(cp, r.Metadata)
		r.Metadata = cp
	}
	return r
}
