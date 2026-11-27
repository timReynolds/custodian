package persistence

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// --- ip_fingerprint_corpora ---

type CreateIPFingerprintCorpusParams struct {
	ID                uuid.UUID
	Name              string
	Description       string
	Classification    domain.Classification
	RepositoryID      *uuid.UUID
	SourceRef         string
	WinnowK           int
	WinnowW           int
	ChunkSizeBytes    int
	Enabled           *bool
	Status            domain.IPCorpusStatus
	FingerprintCount  int64
	LastIndexedDigest string
	LastIndexedAt     *time.Time
	LastError         string
	CreatedBy         *uuid.UUID
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

const createIPFingerprintCorpusSQL = `
INSERT INTO ip_fingerprint_corpora (
    id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11,
    $12, $13, $14, $15,
    $16, $17, $18
)
RETURNING id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
`

func (q *Queries) CreateIPFingerprintCorpus(ctx context.Context, arg CreateIPFingerprintCorpusParams) (IPFingerprintCorpusRow, error) {
	name := strings.TrimSpace(arg.Name)
	if name == "" {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "corpus name is required")
	}
	if err := (domain.IPFingerprintCorpus{Classification: arg.Classification}).ValidateClassification(); err != nil {
		return IPFingerprintCorpusRow{}, err
	}
	if arg.RepositoryID != nil && *arg.RepositoryID == uuid.Nil {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "repository_id must not be nil when provided")
	}
	if arg.CreatedBy != nil && *arg.CreatedBy == uuid.Nil {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "created_by must not be nil when provided")
	}
	winnowK := arg.WinnowK
	if winnowK == 0 {
		winnowK = 25
	}
	if winnowK < 1 {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "winnow_k must be >= 1")
	}
	winnowW := arg.WinnowW
	if winnowW == 0 {
		winnowW = 15
	}
	if winnowW < 1 {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "winnow_w must be >= 1")
	}
	chunkSize := arg.ChunkSizeBytes
	if chunkSize == 0 {
		chunkSize = 4096
	}
	if chunkSize < 1 {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "chunk_size_bytes must be >= 1")
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
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS_STATUS", "invalid corpus status")
	}
	if arg.FingerprintCount < 0 {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "fingerprint_count must be >= 0")
	}
	var lastDigest *string
	if strings.TrimSpace(arg.LastIndexedDigest) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.LastIndexedDigest)
		if err != nil {
			return IPFingerprintCorpusRow{}, err
		}
		lastDigest = &parsed
	}

	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return IPFingerprintCorpusRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "corpus id must be UUIDv7")
	}

	createdAt := normalizeTimestamp(arg.CreatedAt)
	updatedAt := createdAt
	if !arg.UpdatedAt.IsZero() {
		updatedAt = normalizeTimestamp(arg.UpdatedAt)
	}

	var row IPFingerprintCorpusRow
	err := scanIPFingerprintCorpusRow(q.db.QueryRow(ctx, createIPFingerprintCorpusSQL,
		id,
		name,
		nilIfEmpty(arg.Description),
		string(arg.Classification),
		arg.RepositoryID,
		strings.TrimSpace(arg.SourceRef),
		winnowK,
		winnowW,
		chunkSize,
		enabled,
		string(status),
		arg.FingerprintCount,
		lastDigest,
		utcPtr(arg.LastIndexedAt),
		nilIfEmpty(arg.LastError),
		arg.CreatedBy,
		createdAt,
		updatedAt,
	), &row)
	if err != nil {
		return IPFingerprintCorpusRow{}, MapError(err)
	}
	return row, nil
}

const getIPFingerprintCorpusByIDSQL = `
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE id = $1
`

func (q *Queries) GetIPFingerprintCorpusByID(ctx context.Context, id uuid.UUID) (IPFingerprintCorpusRow, error) {
	if id == uuid.Nil {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "corpus id must not be nil")
	}
	var row IPFingerprintCorpusRow
	if err := scanIPFingerprintCorpusRow(q.db.QueryRow(ctx, getIPFingerprintCorpusByIDSQL, id), &row); err != nil {
		return IPFingerprintCorpusRow{}, MapError(err)
	}
	return row, nil
}

const getIPFingerprintCorpusByNameSQL = `
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE name = $1
`

func (q *Queries) GetIPFingerprintCorpusByName(ctx context.Context, name string) (IPFingerprintCorpusRow, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "corpus name must not be empty")
	}
	var row IPFingerprintCorpusRow
	if err := scanIPFingerprintCorpusRow(q.db.QueryRow(ctx, getIPFingerprintCorpusByNameSQL, trimmed), &row); err != nil {
		return IPFingerprintCorpusRow{}, MapError(err)
	}
	return row, nil
}

const getIPFingerprintCorpusByNameForUpdateSQL = getIPFingerprintCorpusByNameSQL + `
FOR UPDATE
`

func (q *Queries) GetIPFingerprintCorpusByNameForUpdate(ctx context.Context, name string) (IPFingerprintCorpusRow, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "corpus name must not be empty")
	}
	var row IPFingerprintCorpusRow
	if err := scanIPFingerprintCorpusRow(q.db.QueryRow(ctx, getIPFingerprintCorpusByNameForUpdateSQL, trimmed), &row); err != nil {
		return IPFingerprintCorpusRow{}, MapError(err)
	}
	return row, nil
}

type ListIPFingerprintCorporaParams struct {
	Enabled        *bool
	Classification *domain.Classification
	Limit          int
}

const listIPFingerprintCorporaSQL = `
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE ($1::boolean IS NULL OR enabled = $1::boolean)
  AND ($2::text IS NULL OR classification = $2::text)
ORDER BY created_at DESC, id DESC
LIMIT $3
`

func (q *Queries) ListIPFingerprintCorpora(ctx context.Context, arg ListIPFingerprintCorporaParams) ([]IPFingerprintCorpusRow, error) {
	var clsArg *string
	if arg.Classification != nil {
		if err := (domain.IPFingerprintCorpus{Classification: *arg.Classification}).ValidateClassification(); err != nil {
			return nil, err
		}
		s := string(*arg.Classification)
		clsArg = &s
	}
	limit := arg.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}

	rows, err := q.db.Query(ctx, listIPFingerprintCorporaSQL, arg.Enabled, clsArg, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]IPFingerprintCorpusRow, 0)
	for rows.Next() {
		var row IPFingerprintCorpusRow
		if err := scanIPFingerprintCorpusRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type UpdateIPFingerprintCorpusStatusParams struct {
	ID                uuid.UUID
	Status            domain.IPCorpusStatus
	FingerprintCount  int64
	LastIndexedDigest string
	LastIndexedAt     *time.Time
	LastError         string
	UpdatedAt         time.Time
}

const updateIPFingerprintCorpusStatusSQL = `
UPDATE ip_fingerprint_corpora
SET status              = $2,
    fingerprint_count   = $3,
    last_indexed_digest = COALESCE($4, last_indexed_digest),
    last_indexed_at     = COALESCE($5, last_indexed_at),
    last_error          = $6,
    updated_at          = $7
WHERE id = $1
RETURNING id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
`

func (q *Queries) UpdateIPFingerprintCorpusStatus(ctx context.Context, arg UpdateIPFingerprintCorpusStatusParams) (IPFingerprintCorpusRow, error) {
	if arg.ID == uuid.Nil {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_ID", "corpus id must not be nil")
	}
	if !arg.Status.IsValid() {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS_STATUS", "invalid corpus status")
	}
	if arg.FingerprintCount < 0 {
		return IPFingerprintCorpusRow{}, domain.BadRequest("INVALID_CORPUS", "fingerprint_count must be >= 0")
	}
	var digestPtr *string
	if strings.TrimSpace(arg.LastIndexedDigest) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.LastIndexedDigest)
		if err != nil {
			return IPFingerprintCorpusRow{}, err
		}
		digestPtr = &parsed
	}
	updatedAt := normalizeTimestamp(arg.UpdatedAt)

	var row IPFingerprintCorpusRow
	err := scanIPFingerprintCorpusRow(q.db.QueryRow(ctx, updateIPFingerprintCorpusStatusSQL,
		arg.ID,
		string(arg.Status),
		arg.FingerprintCount,
		digestPtr,
		utcPtr(arg.LastIndexedAt),
		nilIfEmpty(arg.LastError),
		updatedAt,
	), &row)
	if err != nil {
		return IPFingerprintCorpusRow{}, MapError(err)
	}
	return row, nil
}

// --- ip_fingerprints ---

type InsertIPFingerprintParams struct {
	ID              uuid.UUID
	CorpusID        uuid.UUID
	Layer           domain.FingerprintLayer
	FingerprintHash string
	FilePathHash    string
	Language        string
	ChunkIndex      *int
	LineStart       *int
	LineEnd         *int
	TokenCount      *int
	Metadata        map[string]any
	CreatedAt       time.Time
}

const insertIPFingerprintSQL = `
INSERT INTO ip_fingerprints (
    id, corpus_id, layer, fingerprint_hash, file_path_hash,
    language, chunk_index, line_start, line_end, token_count,
    metadata, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10,
    $11, $12
)
ON CONFLICT (corpus_id, layer, fingerprint_hash, file_path_hash, chunk_index) DO UPDATE SET
    language    = COALESCE(EXCLUDED.language, ip_fingerprints.language),
    line_start  = COALESCE(EXCLUDED.line_start, ip_fingerprints.line_start),
    line_end    = COALESCE(EXCLUDED.line_end, ip_fingerprints.line_end),
    token_count = COALESCE(EXCLUDED.token_count, ip_fingerprints.token_count),
    metadata    = EXCLUDED.metadata
RETURNING id, corpus_id, layer, fingerprint_hash, file_path_hash,
    language, chunk_index, line_start, line_end, token_count,
    metadata, created_at
`

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

type preparedFingerprint struct {
	id           uuid.UUID
	corpusID     uuid.UUID
	layer        string
	fpHash       string
	filePathHash *string
	language     *string
	chunkIndex   *int
	lineStart    *int
	lineEnd      *int
	tokenCount   *int
	metaJSON     json.RawMessage
	createdAt    time.Time
}

func prepareIPFingerprint(arg InsertIPFingerprintParams) (preparedFingerprint, error) {
	if arg.CorpusID == uuid.Nil {
		return preparedFingerprint{}, domain.BadRequest("INVALID_ID", "corpus_id must not be nil")
	}
	if !arg.Layer.IsValid() {
		return preparedFingerprint{}, domain.BadRequest("INVALID_FINGERPRINT_LAYER", "invalid fingerprint layer")
	}
	fpHash, err := normalizeFingerprintHash(arg.FingerprintHash)
	if err != nil {
		return preparedFingerprint{}, err
	}
	var filePathHash *string
	if strings.TrimSpace(arg.FilePathHash) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.FilePathHash)
		if err != nil {
			return preparedFingerprint{}, err
		}
		filePathHash = &parsed
	}
	if arg.ChunkIndex != nil && *arg.ChunkIndex < 0 {
		return preparedFingerprint{}, domain.BadRequest("INVALID_FINGERPRINT", "chunk_index must be >= 0")
	}
	if arg.LineStart != nil && *arg.LineStart < 0 {
		return preparedFingerprint{}, domain.BadRequest("INVALID_FINGERPRINT", "line_start must be >= 0")
	}
	if arg.LineEnd != nil && *arg.LineEnd < 0 {
		return preparedFingerprint{}, domain.BadRequest("INVALID_FINGERPRINT", "line_end must be >= 0")
	}
	if arg.TokenCount != nil && *arg.TokenCount < 0 {
		return preparedFingerprint{}, domain.BadRequest("INVALID_FINGERPRINT", "token_count must be >= 0")
	}
	if err := domain.ValidateIPFingerprintMetadata(arg.Metadata); err != nil {
		return preparedFingerprint{}, err
	}
	meta := arg.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	rawMeta, err := json.Marshal(meta)
	if err != nil {
		return preparedFingerprint{}, domain.WrapError(domain.ErrBadRequest, "INVALID_METADATA", "failed to marshal fingerprint metadata", err)
	}
	canonMeta, err := domain.CanonicalJSONBytes(rawMeta)
	if err != nil {
		return preparedFingerprint{}, err
	}

	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return preparedFingerprint{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return preparedFingerprint{}, domain.BadRequest("INVALID_ID", "ip_fingerprint id must be UUIDv7")
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)

	return preparedFingerprint{
		id:           id,
		corpusID:     arg.CorpusID,
		layer:        string(arg.Layer),
		fpHash:       fpHash,
		filePathHash: filePathHash,
		language:     nilIfEmpty(strings.TrimSpace(arg.Language)),
		chunkIndex:   arg.ChunkIndex,
		lineStart:    arg.LineStart,
		lineEnd:      arg.LineEnd,
		tokenCount:   arg.TokenCount,
		metaJSON:     json.RawMessage(canonMeta),
		createdAt:    createdAt,
	}, nil
}

func (q *Queries) InsertIPFingerprint(ctx context.Context, arg InsertIPFingerprintParams) (IPFingerprintRow, error) {
	prep, err := prepareIPFingerprint(arg)
	if err != nil {
		return IPFingerprintRow{}, err
	}
	var row IPFingerprintRow
	err = scanIPFingerprintRow(q.db.QueryRow(ctx, insertIPFingerprintSQL,
		prep.id,
		prep.corpusID,
		prep.layer,
		prep.fpHash,
		prep.filePathHash,
		prep.language,
		prep.chunkIndex,
		prep.lineStart,
		prep.lineEnd,
		prep.tokenCount,
		prep.metaJSON,
		prep.createdAt,
	), &row)
	if err != nil {
		return IPFingerprintRow{}, MapError(err)
	}
	return row, nil
}

const upsertIPFingerprintBatchSQL = `
INSERT INTO ip_fingerprints (
    id, corpus_id, layer, fingerprint_hash, file_path_hash,
    language, chunk_index, line_start, line_end, token_count,
    metadata, created_at
)
SELECT
    u.id, u.corpus_id, u.layer, u.fingerprint_hash, u.file_path_hash,
    u.language, u.chunk_index, u.line_start, u.line_end, u.token_count,
    u.metadata, u.created_at
FROM UNNEST(
    $1::uuid[], $2::uuid[], $3::text[], $4::text[], $5::char(64)[],
    $6::text[], $7::integer[], $8::integer[], $9::integer[], $10::integer[],
    $11::jsonb[], $12::timestamptz[]
) AS u(
    id, corpus_id, layer, fingerprint_hash, file_path_hash,
    language, chunk_index, line_start, line_end, token_count,
    metadata, created_at
)
ON CONFLICT (corpus_id, layer, fingerprint_hash, file_path_hash, chunk_index) DO UPDATE SET
    language    = COALESCE(EXCLUDED.language, ip_fingerprints.language),
    line_start  = COALESCE(EXCLUDED.line_start, ip_fingerprints.line_start),
    line_end    = COALESCE(EXCLUDED.line_end, ip_fingerprints.line_end),
    token_count = COALESCE(EXCLUDED.token_count, ip_fingerprints.token_count),
    metadata    = EXCLUDED.metadata
`

func (q *Queries) UpsertIPFingerprintsBatch(ctx context.Context, items []InsertIPFingerprintParams) (int64, error) {
	if len(items) == 0 {
		return 0, nil
	}
	prepped := make([]preparedFingerprint, 0, len(items))
	seen := make(map[string]int, len(items))
	for _, item := range items {
		p, err := prepareIPFingerprint(item)
		if err != nil {
			return 0, err
		}
		fph := "<nil>"
		if p.filePathHash != nil {
			fph = *p.filePathHash
		}
		ci := "<nil>"
		if p.chunkIndex != nil {
			ci = fmt.Sprintf("%d", *p.chunkIndex)
		}
		dedupKey := fmt.Sprintf("%s|%s|%s|%s|%s", p.corpusID, p.layer, p.fpHash, fph, ci)
		if idx, ok := seen[dedupKey]; ok {
			prepped[idx] = p
			continue
		}
		seen[dedupKey] = len(prepped)
		prepped = append(prepped, p)
	}

	n := len(prepped)
	ids := make([]uuid.UUID, n)
	corpusIDs := make([]uuid.UUID, n)
	layers := make([]string, n)
	fpHashes := make([]string, n)
	filePathHashes := make([]*string, n)
	languages := make([]*string, n)
	chunkIndices := make([]*int, n)
	lineStarts := make([]*int, n)
	lineEnds := make([]*int, n)
	tokenCounts := make([]*int, n)
	metas := make([]json.RawMessage, n)
	createdAts := make([]time.Time, n)

	for i, p := range prepped {
		ids[i] = p.id
		corpusIDs[i] = p.corpusID
		layers[i] = p.layer
		fpHashes[i] = p.fpHash
		filePathHashes[i] = p.filePathHash
		languages[i] = p.language
		chunkIndices[i] = p.chunkIndex
		lineStarts[i] = p.lineStart
		lineEnds[i] = p.lineEnd
		tokenCounts[i] = p.tokenCount
		metas[i] = p.metaJSON
		createdAts[i] = p.createdAt
	}

	tag, err := q.db.Exec(ctx, upsertIPFingerprintBatchSQL,
		ids, corpusIDs, layers, fpHashes, filePathHashes,
		languages, chunkIndices, lineStarts, lineEnds, tokenCounts,
		metas, createdAts,
	)
	if err != nil {
		return 0, MapError(err)
	}
	return tag.RowsAffected(), nil
}

const deleteIPFingerprintsByCorpusSQL = `
DELETE FROM ip_fingerprints
WHERE corpus_id = $1
`

func (q *Queries) DeleteIPFingerprintsByCorpus(ctx context.Context, corpusID uuid.UUID) (int64, error) {
	if corpusID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "corpus_id must not be nil")
	}
	tag, err := q.db.Exec(ctx, deleteIPFingerprintsByCorpusSQL, corpusID)
	if err != nil {
		return 0, MapError(err)
	}
	return tag.RowsAffected(), nil
}

const lookupIPFingerprintsByHashesSQL = `
SELECT f.id, f.corpus_id, f.layer, f.fingerprint_hash, f.file_path_hash,
    f.language, f.chunk_index, f.line_start, f.line_end, f.token_count,
    f.metadata, f.created_at,
    c.name AS corpus_name, c.classification
FROM ip_fingerprints f
JOIN ip_fingerprint_corpora c ON c.id = f.corpus_id
WHERE f.layer = $1
  AND f.fingerprint_hash = ANY($2::text[])
  AND c.enabled = true
  AND c.status = 'READY'
ORDER BY f.id ASC
`

func (q *Queries) LookupIPFingerprintsByHashes(ctx context.Context, layer domain.FingerprintLayer, hashes []string) ([]IPFingerprintLookupRow, error) {
	if !layer.IsValid() {
		return nil, domain.BadRequest("INVALID_FINGERPRINT_LAYER", "invalid fingerprint layer")
	}
	if len(hashes) == 0 {
		return []IPFingerprintLookupRow{}, nil
	}
	normHashes := make([]string, 0, len(hashes))
	for _, h := range hashes {
		norm, err := normalizeFingerprintHash(h)
		if err != nil {
			return nil, err
		}
		normHashes = append(normHashes, norm)
	}

	rows, err := q.db.Query(ctx, lookupIPFingerprintsByHashesSQL, string(layer), normHashes)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]IPFingerprintLookupRow, 0)
	for rows.Next() {
		var row IPFingerprintLookupRow
		var layerStr, clsStr string
		if err := rows.Scan(
			&row.ID,
			&row.CorpusID,
			&layerStr,
			&row.FingerprintHash,
			&row.FilePathHash,
			&row.Language,
			&row.ChunkIndex,
			&row.LineStart,
			&row.LineEnd,
			&row.TokenCount,
			&row.Metadata,
			&row.CreatedAt,
			&row.CorpusName,
			&clsStr,
		); err != nil {
			return nil, MapError(err)
		}
		row.Layer = domain.FingerprintLayer(layerStr)
		row.Classification = domain.Classification(clsStr)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const countIPFingerprintsByCorpusSQL = `
SELECT COUNT(*)::bigint
FROM ip_fingerprints
WHERE corpus_id = $1
`

func (q *Queries) CountIPFingerprintsByCorpus(ctx context.Context, corpusID uuid.UUID) (int64, error) {
	if corpusID == uuid.Nil {
		return 0, domain.BadRequest("INVALID_ID", "corpus_id must not be nil")
	}
	var count int64
	if err := q.db.QueryRow(ctx, countIPFingerprintsByCorpusSQL, corpusID).Scan(&count); err != nil {
		return 0, MapError(err)
	}
	return count, nil
}

// --- scan helpers ---

func scanIPFingerprintCorpusRow(s rowScanner, row *IPFingerprintCorpusRow) error {
	var cls, status string
	if err := s.Scan(
		&row.ID,
		&row.Name,
		&row.Description,
		&cls,
		&row.RepositoryID,
		&row.SourceRef,
		&row.WinnowK,
		&row.WinnowW,
		&row.ChunkSizeBytes,
		&row.Enabled,
		&status,
		&row.FingerprintCount,
		&row.LastIndexedDigest,
		&row.LastIndexedAt,
		&row.LastError,
		&row.CreatedBy,
		&row.CreatedAt,
		&row.UpdatedAt,
	); err != nil {
		return err
	}
	row.Classification = domain.Classification(cls)
	row.Status = domain.IPCorpusStatus(status)
	return nil
}

func scanIPFingerprintRow(s rowScanner, row *IPFingerprintRow) error {
	var layer string
	if err := s.Scan(
		&row.ID,
		&row.CorpusID,
		&layer,
		&row.FingerprintHash,
		&row.FilePathHash,
		&row.Language,
		&row.ChunkIndex,
		&row.LineStart,
		&row.LineEnd,
		&row.TokenCount,
		&row.Metadata,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Layer = domain.FingerprintLayer(layer)
	return nil
}
