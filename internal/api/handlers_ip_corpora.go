package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func validateCorpusSourceString(raw, code, field string, maxRunes int) (string, error) {
	if maxRunes > 0 && utf8.RuneCountInString(raw) > maxRunes {
		return "", domain.BadRequest(code, fmt.Sprintf("%s must not exceed %d characters", field, maxRunes))
	}
	for _, r := range raw {
		if r == 0 || r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return "", domain.BadRequest(code, field+" contains invalid control characters")
		}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", domain.BadRequest(code, field+" must not be empty")
	}
	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return "", domain.BadRequest(code, field+" must not contain path traversal")
		}
	}
	return trimmed, nil
}

func validateCorpusSourceRefNoCreds(sourceRef string) error {
	if sourceRef == "" {
		return nil
	}
	if scrubAPISecretString(sourceRef) != sourceRef {
		return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must not contain embedded credentials")
	}
	if strings.Contains(sourceRef, "://") {
		u, err := url.Parse(sourceRef)
		if err != nil {
			return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must be a valid URL")
		}
		if u.User != nil {
			return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must not contain embedded credentials")
		}
		if u.RawQuery != "" {
			q, qErr := url.ParseQuery(u.RawQuery)
			if qErr != nil {
				return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must not contain invalid query parameters")
			}
			for k := range q {
				if isSensitiveDestinationQueryKey(k) {
					return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must not contain embedded credentials")
				}
			}
		}
		return nil
	}
	baseAndQuery, _, _ := strings.Cut(sourceRef, "#")
	if _, rawQuery, hasQuery := strings.Cut(baseAndQuery, "?"); hasQuery && hasSensitiveRawQuery(rawQuery) {
		return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must not contain embedded credentials")
	}
	if userinfo, _, hasAt := strings.Cut(sourceRef, "@"); hasAt && !strings.ContainsAny(userinfo, "/?#") {
		if isCredentialUserinfo(userinfo) {
			return domain.BadRequest("INVALID_CORPUS_SOURCE", "source_ref must not contain embedded credentials")
		}
	}
	return nil
}

func validateAndConvertCorpusFiles(files []IPCorpusFileInputDTO) ([]IPCorpusFileInput, error) {
	out := make([]IPCorpusFileInput, 0, len(files))
	for _, f := range files {
		p, err := validateCorpusSourceString(f.Path, "INVALID_CORPUS_FILE", "files[].path", 1024)
		if err != nil {
			return nil, err
		}
		var content string
		if f.Content != nil {
			content = *f.Content
		}
		var digest string
		if f.SHA256 != nil && strings.TrimSpace(*f.SHA256) != "" {
			parsed, err := domain.ParseSHA256Digest(*f.SHA256)
			if err != nil {
				return nil, err
			}
			digest = parsed
		}
		if strings.TrimSpace(content) == "" && digest == "" {
			return nil, domain.Unprocessable("INVALID_CORPUS_FILE", "each corpus file must provide non-empty content or sha256")
		}
		out = append(out, IPCorpusFileInput{
			Path:    p,
			Content: content,
			SHA256:  digest,
		})
	}
	return out, nil
}

// computeSafeCorpusSourceRef computes a hash-derived source_ref without persisting raw file paths or contents.
func computeSafeCorpusSourceRef(sourceRef, sourcePath string, files []IPCorpusFileInput) string {
	if sourceRef != "" {
		if validateCorpusSourceRefNoCreds(sourceRef) != nil {
			return "ref:sha256:" + domain.SHA256Hex([]byte(sourceRef))
		}
		return sourceRef
	}
	if len(files) > 0 {
		parts := make([]string, 0, len(files))
		for _, f := range files {
			pathHash := domain.SHA256Hex([]byte(f.Path))
			contentHash := f.SHA256
			if contentHash == "" {
				contentHash = domain.SHA256Hex([]byte(f.Content))
			}
			parts = append(parts, pathHash+":"+contentHash)
		}
		sort.Strings(parts)
		return "inline:sha256:" + domain.SHA256Hex([]byte(strings.Join(parts, "\n")))
	}
	return "path:sha256:" + domain.SHA256Hex([]byte(sourcePath))
}

func (s *server) handleListIPCorpora(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isPushAdmin(caller) && !isPushAuditor(caller) && !caller.IsController() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to list IP fingerprint corpora"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	q := r.URL.Query()
	var cls *domain.Classification
	if rawCls := strings.TrimSpace(q.Get("classification")); rawCls != "" {
		c := domain.Classification(strings.ToUpper(rawCls))
		if err := (domain.IPFingerprintCorpus{Classification: c}).ValidateClassification(); err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS_CLASSIFICATION", "classification must be CONFIDENTIAL or RESTRICTED"))
			return
		}
		cls = &c
	}

	var enabled *bool
	if rawEnabled := strings.TrimSpace(q.Get("enabled")); rawEnabled != "" {
		v, err := strconv.ParseBool(rawEnabled)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_ENABLED", "enabled must be true or false"))
			return
		}
		enabled = &v
	}

	var cursorID *uuid.UUID
	if rawCursor := strings.TrimSpace(q.Get("cursor")); rawCursor != "" {
		id, err := parseUUIDv7(rawCursor)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CURSOR", "cursor must be a valid UUIDv7"))
			return
		}
		cursorID = &id
	}

	limit := 50
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		v, err := strconv.Atoi(rawLimit)
		if err != nil || v < 1 || v > 500 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_LIMIT", "limit must be an integer between 1 and 500"))
			return
		}
		limit = v
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()

	var rows []persistence.IPFingerprintCorpusRow
	var err error
	if cursorID == nil {
		rows, err = s.deps.Store.ListIPFingerprintCorpora(dbCtx, persistence.ListIPFingerprintCorporaParams{
			Enabled:        enabled,
			Classification: cls,
			Limit:          limit + 1,
		})
	} else {
		rows, err = s.listIPCorporaWithCursor(dbCtx, enabled, cls, *cursorID, limit+1)
	}
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}

	hasMore := false
	var nextCursor *string
	if len(rows) > limit {
		hasMore = true
		rows = rows[:limit]
		nc := rows[len(rows)-1].ID.String()
		nextCursor = &nc
	}

	corpora := make([]IPCorpusDTO, 0, len(rows))
	for _, row := range rows {
		corpora = append(corpora, toIPCorpusDTO(row))
	}

	writeJSON(w, http.StatusOK, IPCorporaListResponse{
		Corpora:    corpora,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	})
}

const listIPCorporaWithCursorSQL = `
SELECT id, name, description, classification, repository_id, source_ref,
    winnow_k, winnow_w, chunk_size_bytes, enabled, status,
    fingerprint_count, last_indexed_digest, last_indexed_at, last_error,
    created_by, created_at, updated_at
FROM ip_fingerprint_corpora
WHERE ($1::boolean IS NULL OR enabled = $1::boolean)
  AND ($2::text IS NULL OR classification = $2::text)
  AND id < $3::uuid
ORDER BY created_at DESC, id DESC
LIMIT $4
`

func (s *server) listIPCorporaWithCursor(
	ctx context.Context,
	enabled *bool,
	cls *domain.Classification,
	cursorID uuid.UUID,
	limit int,
) ([]persistence.IPFingerprintCorpusRow, error) {
	pool := s.deps.Store.Pool()
	if pool == nil {
		return nil, domain.Unavailable("STORE_UNAVAILABLE", "database pool is not configured")
	}
	var clsArg *string
	if cls != nil {
		v := string(*cls)
		clsArg = &v
	}
	pgRows, err := pool.Query(ctx, listIPCorporaWithCursorSQL, enabled, clsArg, cursorID, limit)
	if err != nil {
		return nil, persistence.MapError(err)
	}
	defer pgRows.Close()

	out := make([]persistence.IPFingerprintCorpusRow, 0)
	for pgRows.Next() {
		var row persistence.IPFingerprintCorpusRow
		var clsStr, statusStr string
		if err := pgRows.Scan(
			&row.ID,
			&row.Name,
			&row.Description,
			&clsStr,
			&row.RepositoryID,
			&row.SourceRef,
			&row.WinnowK,
			&row.WinnowW,
			&row.ChunkSizeBytes,
			&row.Enabled,
			&statusStr,
			&row.FingerprintCount,
			&row.LastIndexedDigest,
			&row.LastIndexedAt,
			&row.LastError,
			&row.CreatedBy,
			&row.CreatedAt,
			&row.UpdatedAt,
		); err != nil {
			return nil, persistence.MapError(err)
		}
		row.Classification = domain.Classification(clsStr)
		row.Status = domain.IPCorpusStatus(statusStr)
		out = append(out, row)
	}
	if err := pgRows.Err(); err != nil {
		return nil, persistence.MapError(err)
	}
	return out, nil
}

func (s *server) handleCreateIPCorpus(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isPushAdmin(caller) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("PUSH_ADMIN_REQUIRED", "only policy/security admins may register IP fingerprint corpora"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	idemKey, err := parseIdempotencyKeyHeader(r, true)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	rawBody, err := readBoundedBody(w, r, maxJSONBodyBytes)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var req CreateIPCorpusRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	if utf8.RuneCountInString(req.Name) > 255 {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS", "name must be between 1 and 255 characters"))
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS", "name must be between 1 and 255 characters"))
		return
	}

	cls := domain.Classification(strings.ToUpper(strings.TrimSpace(req.Classification)))
	if err := (domain.IPFingerprintCorpus{Classification: cls}).ValidateClassification(); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var desc string
	if req.Description != nil {
		if utf8.RuneCountInString(*req.Description) > 4096 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS", "description must not exceed 4096 characters"))
			return
		}
		desc = *req.Description
	}

	var repoID *uuid.UUID
	if req.RepositoryID != nil {
		id, err := parseUUIDv7(*req.RepositoryID)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_REPOSITORY_ID", "repository_id must be a valid UUIDv7"))
			return
		}
		repoID = &id
	}

	var sourceRef, sourcePath string
	if req.SourceRef != nil {
		sourceRef, err = validateCorpusSourceString(*req.SourceRef, "INVALID_CORPUS_SOURCE", "source_ref", 256)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
		if err := validateCorpusSourceRefNoCreds(sourceRef); err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
	}
	if req.SourcePath != nil {
		sourcePath, err = validateCorpusSourceString(*req.SourcePath, "INVALID_CORPUS_SOURCE", "source_path", 1024)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
	}
	if req.Files != nil && len(req.Files) == 0 {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS_FILES", "files must contain at least 1 item"))
		return
	}
	var files []IPCorpusFileInput
	if len(req.Files) > 0 {
		files, err = validateAndConvertCorpusFiles(req.Files)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
	}

	if sourceRef == "" && sourcePath == "" && len(files) == 0 {
		writeError(w, r, s.deps.Logger, domain.Unprocessable("MISSING_CORPUS_SOURCE", "at least one of source_ref, source_path, or non-empty files is required"))
		return
	}

	winnowK := 25
	if req.WinnowK != nil {
		if *req.WinnowK < 1 || *req.WinnowK > 256 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS", "winnow_k must be between 1 and 256"))
			return
		}
		winnowK = *req.WinnowK
	}
	winnowW := 15
	if req.WinnowW != nil {
		if *req.WinnowW < 1 || *req.WinnowW > 256 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS", "winnow_w must be between 1 and 256"))
			return
		}
		winnowW = *req.WinnowW
	}
	chunkSize := 4096
	if req.ChunkSizeBytes != nil {
		if *req.ChunkSizeBytes < 64 || *req.ChunkSizeBytes > 1048576 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS", "chunk_size_bytes must be between 64 and 1048576"))
			return
		}
		chunkSize = *req.ChunkSizeBytes
	}

	safeSourceRef := computeSafeCorpusSourceRef(sourceRef, sourcePath, files)

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		dbCtx1, cancel1 := s.withDBTimeout(r.Context())

		now := time.Now().UTC().Truncate(time.Microsecond)
		var corpusRow persistence.IPFingerprintCorpusRow
		txErr := s.deps.Store.WithTx(dbCtx1, func(tx *persistence.Tx) error {
			existing, getErr := tx.GetIPFingerprintCorpusByNameForUpdate(dbCtx1, name)
			if getErr == nil {
				if !canRetryFailedCorpusCreation(existing, cls, desc, repoID, safeSourceRef, winnowK, winnowW, chunkSize, req.Enabled, caller.Principal.ID) {
					return domain.Conflict("CONFLICT", "resource already exists or conflicts")
				}
				updated, updErr := tx.UpdateIPFingerprintCorpusStatus(dbCtx1, persistence.UpdateIPFingerprintCorpusStatusParams{
					ID:               existing.ID,
					Status:           domain.IPCorpusStatusPending,
					FingerprintCount: 0,
					LastError:        "",
					UpdatedAt:        now,
				})
				if updErr != nil {
					return updErr
				}
				corpusRow = updated
				return nil
			}
			if !errors.Is(getErr, domain.ErrNotFound) {
				return getErr
			}

			var err error
			corpusRow, err = tx.CreateIPFingerprintCorpus(dbCtx1, persistence.CreateIPFingerprintCorpusParams{
				Name:           name,
				Description:    desc,
				Classification: cls,
				RepositoryID:   repoID,
				SourceRef:      safeSourceRef,
				WinnowK:        winnowK,
				WinnowW:        winnowW,
				ChunkSizeBytes: chunkSize,
				Enabled:        req.Enabled,
				Status:         domain.IPCorpusStatusPending,
				CreatedBy:      &caller.Principal.ID,
				CreatedAt:      now,
				UpdatedAt:      now,
			})
			if err != nil {
				return err
			}

			// Metadata-only audit payload: NEVER store raw files, contents, or raw file paths.
			payloadBytes, _ := json.Marshal(map[string]any{
				"corpus_id":        corpusRow.ID.String(),
				"name":             corpusRow.Name,
				"classification":   string(corpusRow.Classification),
				"source_ref":       corpusRow.SourceRef,
				"winnow_k":         corpusRow.WinnowK,
				"winnow_w":         corpusRow.WinnowW,
				"chunk_size_bytes": corpusRow.ChunkSizeBytes,
				"enabled":          corpusRow.Enabled,
				"status":           string(corpusRow.Status),
			})
			if _, err := audit.AppendTx(dbCtx1, tx, audit.AppendInput{
				EventType:    "ip_corpus.created",
				ActorID:      &caller.Principal.ID,
				ResourceType: "ip_corpus",
				ResourceID:   corpusRow.ID,
				Payload:      payloadBytes,
				CreatedAt:    now,
			}, s.deps.Logger); err != nil {
				return err
			}
			return nil
		})
		cancel1()
		if txErr != nil {
			return 0, nil, mapDBTimeoutError(dbCtx1, txErr)
		}

		// If a reindexer is configured and source files/path were supplied at creation time,
		// run deterministic indexing synchronously now (never storing raw source in DB).
		if s.deps.IPCorpusReindexer != nil && (len(files) > 0 || sourcePath != "") {
			res, reErr := s.deps.IPCorpusReindexer.Reindex(r.Context(), IPCorpusReindexInput{
				Corpus:     corpusRow.ToDomain(),
				SourceRef:  safeSourceRef,
				SourcePath: sourcePath,
				Files:      files,
				Force:      true,
				ActorID:    caller.Principal.ID,
			})
			if reErr != nil {
				failCtx, failCancel := s.withDBTimeout(context.WithoutCancel(r.Context()))
				_, _ = s.deps.Store.UpdateIPFingerprintCorpusStatus(failCtx, persistence.UpdateIPFingerprintCorpusStatusParams{
					ID:        corpusRow.ID,
					Status:    domain.IPCorpusStatusFailed,
					LastError: redactErrorMessageForAPI(reErr.Error()),
					UpdatedAt: time.Now().UTC().Truncate(time.Microsecond),
				})
				failCancel()
				return 0, nil, reErr
			}

			dbCtx2, cancel2 := s.withDBTimeout(r.Context())
			defer cancel2()

			refreshed, getErr := s.deps.Store.GetIPFingerprintCorpusByID(dbCtx2, corpusRow.ID)
			if getErr != nil {
				return 0, nil, mapDBTimeoutError(dbCtx2, getErr)
			}
			corpusRow = refreshed

			status := res.Status
			if !status.IsValid() {
				status = domain.IPCorpusStatusReady
			}
			if corpusRow.Status == domain.IPCorpusStatusPending {
				completedAt := res.CompletedAt
				if completedAt == nil && status == domain.IPCorpusStatusReady {
					doneAt := time.Now().UTC().Truncate(time.Microsecond)
					completedAt = &doneAt
				}
				updated, updErr := s.deps.Store.UpdateIPFingerprintCorpusStatus(dbCtx2, persistence.UpdateIPFingerprintCorpusStatusParams{
					ID:                corpusRow.ID,
					Status:            status,
					FingerprintCount:  res.FingerprintsIndexed,
					LastIndexedDigest: res.LastIndexedDigest,
					LastIndexedAt:     completedAt,
					UpdatedAt:         time.Now().UTC().Truncate(time.Microsecond),
				})
				if updErr != nil {
					return 0, nil, mapDBTimeoutError(dbCtx2, updErr)
				}
				corpusRow = updated
			}
		}

		return http.StatusCreated, toIPCorpusDTO(corpusRow), nil
	})
}

func (s *server) handleReindexIPCorpus(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isPushAdmin(caller) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("PUSH_ADMIN_REQUIRED", "only policy/security admins may reindex IP fingerprint corpora"))
		return
	}
	if s.deps.IPCorpusReindexer == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "IP corpus reindexer is not configured"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	corpusID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	idemKey, err := parseIdempotencyKeyHeader(r, true)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	rawBody, err := readBoundedBody(w, r, maxJSONBodyBytes)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var req ReindexIPCorpusRequest
	if err := decodeStrictJSONBytes(rawBody, &req, true); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var reqSourceRef, reqSourcePath string
	if req.SourceRef != nil {
		reqSourceRef, err = validateCorpusSourceString(*req.SourceRef, "INVALID_CORPUS_SOURCE", "source_ref", 256)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
		if err := validateCorpusSourceRefNoCreds(reqSourceRef); err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
	}
	if req.SourcePath != nil {
		reqSourcePath, err = validateCorpusSourceString(*req.SourcePath, "INVALID_CORPUS_SOURCE", "source_path", 1024)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
	}
	if req.Files != nil && len(req.Files) == 0 {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_CORPUS_FILES", "files must contain at least 1 item"))
		return
	}
	var files []IPCorpusFileInput
	if len(req.Files) > 0 {
		files, err = validateAndConvertCorpusFiles(req.Files)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		dbCtx1, cancel1 := s.withDBTimeout(r.Context())
		corpusRow, err := s.deps.Store.GetIPFingerprintCorpusByID(dbCtx1, corpusID)
		cancel1()
		if err != nil {
			return 0, nil, mapDBTimeoutError(dbCtx1, err)
		}

		sourceRef := corpusRow.SourceRef
		if reqSourceRef != "" {
			sourceRef = reqSourceRef
		}

		res, err := s.deps.IPCorpusReindexer.Reindex(r.Context(), IPCorpusReindexInput{
			Corpus:     corpusRow.ToDomain(),
			SourceRef:  sourceRef,
			SourcePath: reqSourcePath,
			Files:      files,
			Force:      req.Force,
			ActorID:    caller.Principal.ID,
		})
		if err != nil {
			return 0, nil, err
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		status := res.Status
		if !status.IsValid() {
			status = domain.IPCorpusStatusReady
		}
		completedAt := res.CompletedAt
		if completedAt == nil && status == domain.IPCorpusStatusReady {
			completedAt = &now
		}

		var digestPtr *string
		if strings.TrimSpace(res.LastIndexedDigest) != "" {
			digestPtr = normalizeHex64OrNil(res.LastIndexedDigest)
		}

		dbCtx2, cancel2 := s.withDBTimeout(r.Context())
		defer cancel2()

		txErr := s.deps.Store.WithTx(dbCtx2, func(tx *persistence.Tx) error {
			current, err := tx.GetIPFingerprintCorpusByID(dbCtx2, corpusID)
			if err != nil {
				return err
			}
			if current.Status == domain.IPCorpusStatusPending || current.FingerprintCount != res.FingerprintsIndexed || current.Status != status {
				digestVal := ""
				if digestPtr != nil {
					digestVal = *digestPtr
				}
				if _, err := tx.UpdateIPFingerprintCorpusStatus(dbCtx2, persistence.UpdateIPFingerprintCorpusStatusParams{
					ID:                corpusID,
					Status:            status,
					FingerprintCount:  res.FingerprintsIndexed,
					LastIndexedDigest: digestVal,
					LastIndexedAt:     completedAt,
					UpdatedAt:         now,
				}); err != nil {
					return err
				}
			}

			payloadBytes, _ := json.Marshal(map[string]any{
				"corpus_id":            corpusID.String(),
				"status":               string(status),
				"fingerprints_indexed": res.FingerprintsIndexed,
				"files_processed":      res.FilesProcessed,
				"force":                req.Force,
			})
			if _, err := audit.AppendTx(dbCtx2, tx, audit.AppendInput{
				EventType:    "ip_corpus.reindexed",
				ActorID:      &caller.Principal.ID,
				ResourceType: "ip_corpus",
				ResourceID:   corpusID,
				Payload:      payloadBytes,
				CreatedAt:    now,
			}, s.deps.Logger); err != nil {
				return err
			}
			return nil
		})
		if txErr != nil {
			return 0, nil, mapDBTimeoutError(dbCtx2, txErr)
		}

		return http.StatusAccepted, ReindexIPCorpusResponseDTO{
			CorpusID:            corpusID.String(),
			OperationID:         optUUIDString(res.OperationID),
			Status:              string(status),
			FingerprintsIndexed: res.FingerprintsIndexed,
			FilesProcessed:      res.FilesProcessed,
			LastIndexedDigest:   digestPtr,
			CompletedAt:         formatTimestampPtr(completedAt),
		}, nil
	})
}

func canRetryFailedCorpusCreation(
	existing persistence.IPFingerprintCorpusRow,
	cls domain.Classification,
	desc string,
	repoID *uuid.UUID,
	safeSourceRef string,
	winnowK, winnowW, chunkSize int,
	reqEnabled *bool,
	actorID uuid.UUID,
) bool {
	if existing.Status != domain.IPCorpusStatusFailed ||
		existing.FingerprintCount != 0 ||
		existing.LastIndexedDigest != nil {
		return false
	}
	if existing.Classification != cls ||
		existing.SourceRef != safeSourceRef ||
		existing.WinnowK != winnowK ||
		existing.WinnowW != winnowW ||
		existing.ChunkSizeBytes != chunkSize {
		return false
	}
	enabledVal := true
	if reqEnabled != nil {
		enabledVal = *reqEnabled
	}
	if existing.Enabled != enabledVal {
		return false
	}
	existingDesc := ""
	if existing.Description != nil {
		existingDesc = *existing.Description
	}
	if existingDesc != desc {
		return false
	}
	if (existing.RepositoryID == nil) != (repoID == nil) {
		return false
	}
	if existing.RepositoryID != nil && *existing.RepositoryID != *repoID {
		return false
	}
	if existing.CreatedBy == nil || *existing.CreatedBy != actorID {
		return false
	}
	return true
}
