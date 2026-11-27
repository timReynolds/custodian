package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/proposals"
)

func (s *server) handleSubmitProposal(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsController() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("CONTROLLER_REQUIRED", "only CONTROLLER principals may submit proposals"))
		return
	}
	if s.deps.Proposals == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "proposals service is not configured"))
		return
	}

	wsID, err := parseUUIDv7Param(r, "id")
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

	var req SubmitProposalRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	snapID, snapSHA, sizeBytes, capturedAt, provType, capMethod, err := validateSubmitProposalRequest(req)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var desc string
	if req.Description != nil {
		desc = *req.Description
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		ctx := r.Context()
		actorID := caller.Principal.ID
		submitFn := func(dbCtx context.Context) (proposals.SubmitResult, error) {
			r, err := s.deps.Proposals.Submit(dbCtx, proposals.SubmitInput{
				WorkspaceID:         wsID,
				ActorID:             &actorID,
				SnapshotArtifactID:  snapID,
				SnapshotSHA256:      snapSHA,
				WorkspaceGeneration: req.Snapshot.WorkspaceGeneration,
				SizeBytes:           sizeBytes,
				CapturedAt:          capturedAt,
				Title:               req.Title,
				Description:         desc,
				ProvenanceType:      provType,
				CaptureMethod:       capMethod,
			})
			return r, mapDBTimeoutError(dbCtx, err)
		}

		var res proposals.SubmitResult
		var repoID uuid.UUID
		var repoMaxConc int
		if s.deps.Store != nil {
			lookupCtx, lookupCancel := s.withDBTimeout(ctx)
			ws, wsErr := s.deps.Store.GetWorkspaceByID(lookupCtx, wsID)
			if wsErr == nil && ws.Status == domain.WorkspaceStatusReady {
				if repoRow, repoErr := s.deps.Store.GetRepositoryByID(lookupCtx, ws.RepositoryID); repoErr == nil {
					repoID = repoRow.ID
					repoMaxConc = repoRow.MaxConcurrentOperations
				}
			}
			lookupCancel()
		}

		if repoID != uuid.Nil {
			if err := s.withRepoConcurrencyLimit(ctx, repoID, repoMaxConc, func(dbCtx context.Context) error {
				r, err := submitFn(dbCtx)
				if err != nil {
					return err
				}
				res = r
				return nil
			}); err != nil {
				return 0, nil, err
			}
		} else {
			dbCtx, cancel := s.withDBTimeout(ctx)
			var err error
			res, err = submitFn(dbCtx)
			cancel()
			if err != nil {
				return 0, nil, err
			}
		}

		resp := SubmitProposalResponse{
			ProposalID:  res.Proposal.ID.String(),
			WorkspaceID: res.Proposal.WorkspaceID.String(),
			OperationID: res.Operation.ID.String(),
			BaseCommit:  strings.ToLower(res.Proposal.BaseCommit),
			TargetRef:   res.Proposal.TargetRef,
			Status:      string(res.Proposal.Status),
			Version:     res.Proposal.Version,
			CreatedAt:   formatTimestamp(res.Proposal.CreatedAt),
		}
		return http.StatusAccepted, resp, nil
	})
}

func validateSubmitProposalRequest(req SubmitProposalRequest) (uuid.UUID, string, int64, *time.Time, string, string, error) {
	if req.Snapshot == nil {
		return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_SNAPSHOT", "snapshot is required")
	}
	snapID, err := parseUUIDv7(req.Snapshot.ArtifactID)
	if err != nil {
		return uuid.Nil, "", 0, nil, "", "", err
	}
	snapSHA, err := domain.ParseSHA256Digest(req.Snapshot.SHA256)
	if err != nil {
		return uuid.Nil, "", 0, nil, "", "", err
	}
	if req.Snapshot.WorkspaceGeneration < 1 {
		return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_GENERATION", "snapshot.workspace_generation must be >= 1")
	}
	var sizeBytes int64
	if req.Snapshot.SizeBytes != nil {
		if *req.Snapshot.SizeBytes < 1 {
			return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_SIZE", "snapshot.size_bytes must be >= 1")
		}
		sizeBytes = *req.Snapshot.SizeBytes
	}
	var capturedAt *time.Time
	if req.Snapshot.CapturedAt != nil {
		trimmedCapturedAt := strings.TrimSpace(*req.Snapshot.CapturedAt)
		if trimmedCapturedAt == "" {
			return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_TIMESTAMP", "snapshot.captured_at must not be empty")
		}
		t, err := time.Parse(time.RFC3339Nano, trimmedCapturedAt)
		if err != nil {
			return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_TIMESTAMP", "snapshot.captured_at must be valid RFC3339 date-time")
		}
		utc := t.UTC()
		capturedAt = &utc
	}
	if utf8.RuneCountInString(req.Title) > 256 || len(strings.TrimSpace(req.Title)) < 1 {
		return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_TITLE", "title must be between 1 and 256 characters")
	}
	if req.Description != nil && utf8.RuneCountInString(*req.Description) > 8192 {
		return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_DESCRIPTION", "description must not exceed 8192 characters")
	}
	var provType, capMethod string
	if req.Provenance != nil {
		switch req.Provenance.Type {
		case "agent_assisted", "human_authored":
			provType = req.Provenance.Type
		default:
			return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_PROVENANCE", "provenance.type must be agent_assisted or human_authored")
		}
		switch req.Provenance.CaptureMethod {
		case "frozen_filesystem", "patch_upload":
			capMethod = req.Provenance.CaptureMethod
		default:
			return uuid.Nil, "", 0, nil, "", "", domain.BadRequest("INVALID_PROVENANCE", "provenance.capture_method must be frozen_filesystem or patch_upload")
		}
	}
	return snapID, snapSHA, sizeBytes, capturedAt, provType, capMethod, nil
}

func (s *server) handleGetProposal(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Proposals == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "proposals service is not configured"))
		return
	}

	propID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()
	details, err := s.deps.Proposals.GetDetails(dbCtx, propID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !canReadProposalByOwnerID(caller, details.OwnerID) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view this proposal"))
		return
	}

	writeJSON(w, http.StatusOK, toProposalDTO(details))
}

func (s *server) handleGetProposalDiff(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Proposals == nil || s.deps.Artifacts == nil || s.deps.Snapshots == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "proposal diff dependencies are not configured"))
		return
	}

	propID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	details, err := s.deps.Proposals.GetDetails(dbCtx, propID)
	cancel()
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !canReadProposalByOwnerID(caller, details.OwnerID) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view this proposal diff"))
		return
	}

	if details.ManifestArtifactID == nil || strings.TrimSpace(details.TreeDigest) == "" ||
		strings.TrimSpace(details.DiffDigest) == "" || strings.TrimSpace(details.ManifestDigest) == "" {
		writeError(w, r, s.deps.Logger, domain.Conflict("DIFF_NOT_READY", "proposal has not completed canonical reconstruction"))
		return
	}

	artCtx, artCancel := s.withDBTimeout(r.Context())
	manifestArt, err := s.deps.Artifacts.GetByID(artCtx, *details.ManifestArtifactID)
	artCancel()
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(artCtx, err))
		return
	}
	manifestRC, err := s.deps.Snapshots.Open(r.Context(), manifestArt.Artifact)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	manifestBytes, readErr := io.ReadAll(io.LimitReader(manifestRC, 4<<20))
	closeErr := manifestRC.Close()
	if readErr != nil {
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrUnavailable, "MANIFEST_READ_FAILED", "failed reading publication manifest artifact", readErr))
		return
	}
	if closeErr != nil {
		writeError(w, r, s.deps.Logger, closeErr)
		return
	}

	var manifest reconstruct.PublicationManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrInternal, "INVALID_PUBLICATION_MANIFEST", "failed decoding persisted publication manifest", err))
		return
	}

	unifiedDiff := ""
	truncated := false
	if details.DiffArtifactID != nil {
		diffArtCtx, diffArtCancel := s.withDBTimeout(r.Context())
		diffArt, err := s.deps.Artifacts.GetByID(diffArtCtx, *details.DiffArtifactID)
		diffArtCancel()
		if err != nil {
			writeError(w, r, s.deps.Logger, mapDBTimeoutError(diffArtCtx, err))
			return
		}
		diffRC, err := s.deps.Snapshots.Open(r.Context(), diffArt.Artifact)
		if err != nil {
			writeError(w, r, s.deps.Logger, err)
			return
		}
		maxRead := int64(s.deps.MaxDiffBytes)
		buf, dReadErr := io.ReadAll(io.LimitReader(diffRC, maxRead+1))
		var dDrainErr error
		if dReadErr == nil && int64(len(buf)) > maxRead {
			truncated = true
			buf = buf[:maxRead]
			// Drain remaining bytes so SnapshotStore's verifyingReadCloser reaches io.EOF
			// and verifies full SHA-256 digest and byte size before writing any response.
			_, dDrainErr = io.Copy(io.Discard, diffRC)
		}
		dCloseErr := diffRC.Close()
		for _, rErr := range []error{dReadErr, dDrainErr, dCloseErr} {
			if rErr == nil {
				continue
			}
			var domErr *domain.DomainError
			if errors.As(rErr, &domErr) {
				writeError(w, r, s.deps.Logger, domErr)
				return
			}
			writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrUnavailable, "DIFF_READ_FAILED", "failed reading canonical diff artifact", rErr))
			return
		}
		unifiedDiff = string(buf)
	}

	writeJSON(w, http.StatusOK, ProposalDiffDTO{
		ProposalID:                details.ID.String(),
		BaseCommit:                strings.ToLower(details.BaseCommit),
		TreeDigest:                strings.ToLower(details.TreeDigest),
		DiffDigest:                normalizeHex64(details.DiffDigest),
		PublicationManifestDigest: normalizeHex64(details.ManifestDigest),
		Paths:                     toChangedFileDTOs(manifest.Changes),
		UnifiedDiff:               unifiedDiff,
		Truncated:                 truncated,
		DiffArtifactID:            optUUIDString(details.DiffArtifactID),
	})
}

func (s *server) handleListProposalFindings(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Proposals == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "proposals service is not configured"))
		return
	}

	propID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()
	details, err := s.deps.Proposals.GetDetails(dbCtx, propID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !canReadProposalByOwnerID(caller, details.OwnerID) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view proposal findings"))
		return
	}

	q := r.URL.Query()
	scanner := strings.TrimSpace(q.Get("scanner"))
	cursor := strings.TrimSpace(q.Get("cursor"))

	var severity *domain.Severity
	if rawSev := strings.TrimSpace(q.Get("severity")); rawSev != "" {
		sev := domain.Severity(strings.ToUpper(rawSev))
		if !sev.IsValid() {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_SEVERITY", "severity must be CRITICAL, HIGH, MEDIUM, LOW, or INFO"))
			return
		}
		severity = &sev
	}

	limit := 100
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		v, err := strconv.Atoi(rawLimit)
		if err != nil || v < 1 || v > 500 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_LIMIT", "limit must be an integer between 1 and 500"))
			return
		}
		limit = v
	}

	res, err := s.deps.Proposals.ListFindings(dbCtx, proposals.ListFindingsFilter{
		ProposalID: propID,
		Scanner:    scanner,
		Severity:   severity,
		Cursor:     cursor,
		Limit:      limit,
	})
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}

	scanRuns := make([]ScanRunSummaryDTO, 0, len(res.ScanRuns))
	for _, sr := range res.ScanRuns {
		scanRuns = append(scanRuns, toScanRunSummaryDTO(sr))
	}
	findings := make([]FindingDTO, 0, len(res.Findings))
	for _, f := range res.Findings {
		findings = append(findings, toFindingDTO(f))
	}

	writeJSON(w, http.StatusOK, ProposalFindingsResponse{
		ProposalID: propID.String(),
		ScanRuns:   scanRuns,
		Findings:   findings,
		NextCursor: optString(res.NextCursor),
		HasMore:    res.HasMore,
	})
}

func (s *server) handleListProposalAssessments(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Proposals == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "proposals service is not configured"))
		return
	}

	propID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()
	details, err := s.deps.Proposals.GetDetails(dbCtx, propID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !canReadProposalByOwnerID(caller, details.OwnerID) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view proposal assessments"))
		return
	}

	res, err := s.deps.Proposals.ListAssessmentsAndDecisions(dbCtx, propID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}

	assessments := make([]ModelAssessmentDTO, 0, len(res.Assessments))
	for _, a := range res.Assessments {
		assessments = append(assessments, toModelAssessmentDTO(a))
	}
	decisions := make([]PolicyDecisionDTO, 0, len(res.PolicyDecisions))
	for _, pd := range res.PolicyDecisions {
		decisions = append(decisions, toPolicyDecisionDTO(pd))
	}

	writeJSON(w, http.StatusOK, ProposalAssessmentsResponse{
		ProposalID:      propID.String(),
		Assessments:     assessments,
		PolicyDecisions: decisions,
	})
}

func parseIfMatchHeader(raw string) (*int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	trimmed = strings.TrimPrefix(trimmed, "W/")
	trimmed = strings.Trim(trimmed, `"`)
	v, err := strconv.ParseInt(strings.TrimSpace(trimmed), 10, 64)
	if err != nil || v < 1 {
		return nil, domain.BadRequest("INVALID_IF_MATCH", "If-Match header must be a positive integer version")
	}
	return &v, nil
}

func (s *server) handleEvaluateProposal(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsController() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("CONTROLLER_REQUIRED", "only CONTROLLER principals may trigger proposal evaluation"))
		return
	}
	if s.deps.Proposals == nil || s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "evaluation dependencies are not configured"))
		return
	}

	propID, err := parseUUIDv7Param(r, "id")
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

	var req EvaluateProposalRequest
	if err := decodeStrictJSONBytes(rawBody, &req, true); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	if req.ExpectedVersion != nil && *req.ExpectedVersion < 1 {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1"))
		return
	}

	ifMatchVer, err := parseIfMatchHeader(r.Header.Get("If-Match"))
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	if ifMatchVer != nil && req.ExpectedVersion != nil && *ifMatchVer != *req.ExpectedVersion {
		writeError(w, r, s.deps.Logger, domain.Conflict("VERSION_MISMATCH", "If-Match header disagrees with expected_version"))
		return
	}

	var extraHashParts []string
	if rawIfMatch := strings.TrimSpace(r.Header.Get("If-Match")); rawIfMatch != "" {
		extraHashParts = append(extraHashParts, "If-Match:"+rawIfMatch)
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		ctx := r.Context()

		getCtx, getCancel := s.withDBTimeout(ctx)
		prop, err := s.deps.Proposals.GetDetails(getCtx, propID)
		getCancel()
		if err != nil {
			return 0, nil, mapDBTimeoutError(getCtx, err)
		}

		expectedVersion := prop.Version
		if ifMatchVer != nil {
			expectedVersion = *ifMatchVer
		} else if req.ExpectedVersion != nil {
			expectedVersion = *req.ExpectedVersion
		}

		if prop.Version != expectedVersion {
			return 0, nil, domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}
		if prop.Status != domain.ProposalStatusReconstructed &&
			prop.Status != domain.ProposalStatusRemediationRequired &&
			prop.Status != domain.ProposalStatusPendingApproval &&
			prop.Status != domain.ProposalStatusEvaluating {
			return 0, nil, domain.Conflict("INVALID_PROPOSAL_STATE", "proposal is not eligible for evaluation in its current status")
		}

		var repoMaxConc int
		if s.deps.Store != nil && prop.RepositoryID != uuid.Nil {
			repoCtx, repoCancel := s.withDBTimeout(ctx)
			if repoRow, repoErr := s.deps.Store.GetRepositoryByID(repoCtx, prop.RepositoryID); repoErr == nil {
				repoMaxConc = repoRow.MaxConcurrentOperations
			}
			repoCancel()
		}

		actorID := caller.Principal.ID
		requestEval := func(dbCtx context.Context) (proposals.EvaluateResult, error) {
			res, err := s.deps.Proposals.RequestEvaluation(dbCtx, proposals.EvaluateInput{
				ProposalID:      propID,
				ExpectedVersion: expectedVersion,
				ActorID:         &actorID,
			})
			return res, mapDBTimeoutError(dbCtx, err)
		}

		var res proposals.EvaluateResult
		if err := s.withRepoConcurrencyLimit(ctx, prop.RepositoryID, repoMaxConc, func(repoDBCtx context.Context) error {
			if s.deps.GlobalScanBudget > 0 || s.deps.GlobalModelBudget > 0 {
				return s.withEvalBudgetLock(ctx, func() error {
					dbCtx, dbCancel := s.withDBTimeout(ctx)
					defer dbCancel()
					if err := s.checkGlobalScanBudget(dbCtx); err != nil {
						return err
					}
					if err := s.checkGlobalModelBudget(dbCtx); err != nil {
						return err
					}
					r, err := requestEval(dbCtx)
					if err != nil {
						return err
					}
					res = r
					return nil
				})
			}
			r, err := requestEval(repoDBCtx)
			if err != nil {
				return err
			}
			res = r
			return nil
		}); err != nil {
			return 0, nil, err
		}

		return http.StatusAccepted, EvaluateProposalResponse{
			ProposalID:  res.Proposal.ID.String(),
			OperationID: res.Operation.ID.String(),
			Status:      string(res.Proposal.Status),
			Version:     res.Proposal.Version,
		}, nil
	}, extraHashParts...)
}
