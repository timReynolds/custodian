-- name: CreateIPFingerprintCorpus :one
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
    created_by, created_at, updated_at;

-- name: GetIPFingerprintCorpusByID :one
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE id = $1;

-- name: GetIPFingerprintCorpusByName :one
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE name = $1;

-- name: ListIPFingerprintCorpora :many
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE (sqlc.narg(enabled)::boolean IS NULL OR enabled = sqlc.narg(enabled)::boolean)
  AND (sqlc.narg(classification)::text IS NULL OR classification = sqlc.narg(classification)::text)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: UpdateIPFingerprintCorpusStatus :one
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
    created_by, created_at, updated_at;

-- name: InsertIPFingerprint :one
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
    metadata, created_at;

-- name: DeleteIPFingerprintsByCorpus :execrows
DELETE FROM ip_fingerprints
WHERE corpus_id = $1;

-- name: LookupIPFingerprintsByHashes :many
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
ORDER BY f.id ASC;

-- name: CountIPFingerprintsByCorpus :one
SELECT COUNT(*)::bigint
FROM ip_fingerprints
WHERE corpus_id = $1;

-- name: UpsertIPFingerprintsBatch :execrows
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
    metadata    = EXCLUDED.metadata;
