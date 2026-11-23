package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/snapshots"
)

func (s *server) handleUploadMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodPut)
	writeError(w, r, s.deps.Logger, &domain.DomainError{
		Status:  http.StatusMethodNotAllowed,
		ErrCode: "METHOD_NOT_ALLOWED",
		Message: "upload capability URLs only accept PUT",
	})
}

func (s *server) handleUploadSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.deps.Capabilities == nil || s.deps.Snapshots == nil || s.deps.Artifacts == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "upload dependencies are not configured"))
		return
	}

	wsID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	gen, err := parsePositiveInt64(chi.URLParam(r, "generation"), "INVALID_GENERATION", "workspace generation must be >= 1")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	objectKey := strings.TrimPrefix(strings.TrimSpace(chi.URLParam(r, "*")), "/")
	cleanKey, err := snapshots.ValidateObjectKey(objectKey)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	token, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	// Verify capability signature, expiry, workspace, generation, object_key, and upload-only operation
	// BEFORE inspecting/storing any payload bytes.
	claims, err := s.deps.Capabilities.VerifyUploadFor(r.Context(), token, auth.UploadScope{
		WorkspaceID:   wsID,
		Generation:    gen,
		ObjectKey:     cleanKey,
		ContentLength: 0,
		Operation:     "upload",
	})
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	if r.ContentLength > claims.MaxBytes {
		writeError(w, r, s.deps.Logger, &domain.DomainError{
			Status:  http.StatusRequestEntityTooLarge,
			ErrCode: "SIZE_LIMIT_EXCEEDED",
			Message: "upload Content-Length exceeds capability max_bytes",
		})
		return
	}

	if r.Body == nil {
		writeError(w, r, s.deps.Logger, domain.BadRequest("EMPTY_UPLOAD", "upload body must not be empty"))
		return
	}

	tmpFile, err := os.CreateTemp("", "custodian-upload-*")
	if err != nil {
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrInternal, "UPLOAD_STAGE_FAILED", "failed creating upload staging file", err))
		return
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	limited := io.LimitReader(r.Body, claims.MaxBytes+1)
	written, copyErr := io.Copy(io.MultiWriter(tmpFile, hasher), limited)
	if copyErr != nil {
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrBadRequest, "UPLOAD_READ_FAILED", "failed reading upload stream", copyErr))
		return
	}
	if written > claims.MaxBytes {
		writeError(w, r, s.deps.Logger, &domain.DomainError{
			Status:  http.StatusRequestEntityTooLarge,
			ErrCode: "SIZE_LIMIT_EXCEEDED",
			Message: "uploaded payload exceeds capability max_bytes",
		})
		return
	}
	if written <= 0 {
		writeError(w, r, s.deps.Logger, domain.BadRequest("EMPTY_UPLOAD", "uploaded snapshot must not be empty"))
		return
	}
	if r.ContentLength >= 0 && written != r.ContentLength {
		writeError(w, r, s.deps.Logger, domain.Unprocessable("SIZE_MISMATCH", "uploaded byte count does not match Content-Length"))
		return
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrInternal, "UPLOAD_STAGE_FAILED", "failed rewinding upload staging file", err))
		return
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	storedArt, err := s.deps.Snapshots.Put(r.Context(), domain.PutRequest{
		Kind:           domain.ArtifactKindEgressSnapshot,
		ObjectKey:      cleanKey,
		ExpectedSHA256: actualSHA,
		MaxBytes:       claims.MaxBytes,
		WorkspaceID:    &wsID,
		ContentType:    "application/gzip",
	}, tmpFile, written)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var expiresAt *time.Time
	if s.deps.ArtifactRetentionTTL > 0 {
		exp := time.Now().UTC().Add(s.deps.ArtifactRetentionTTL).Truncate(time.Microsecond)
		expiresAt = &exp
	}

	uploadedBy := claims.IssuedTo
	regCtx, regCancel := s.withDBTimeout(r.Context())
	rec, err := s.deps.Artifacts.Register(regCtx, artifacts.RegisterInput{
		ID:                  storedArt.ID,
		Kind:                domain.ArtifactKindEgressSnapshot,
		SHA256:              storedArt.SHA256,
		StorageKey:          storedArt.StorageKey,
		StorageGeneration:   storedArt.StorageGeneration,
		SizeBytes:           storedArt.SizeBytes,
		Format:              "tar.gz",
		WorkspaceID:         &wsID,
		WorkspaceGeneration: &gen,
		UploadedBy:          &uploadedBy,
		ExpiresAt:           expiresAt,
	})
	regCancel()
	if err != nil {
		_ = s.deps.Snapshots.Delete(r.Context(), storedArt)
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(regCtx, err))
		return
	}

	writeJSON(w, http.StatusCreated, UploadSnapshotResponse{
		ArtifactID: rec.ID.String(),
		SHA256:     normalizeHex64(rec.SHA256),
		SizeBytes:  rec.SizeBytes,
	})
}
