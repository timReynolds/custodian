package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultPushApprovalTTL = 15 * time.Minute
	maxPushApprovalTTL     = 24 * time.Hour
)

func (s *server) handleListPushes(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	q := r.URL.Query()
	var repoID, principalID, cursorID *uuid.UUID
	var status *domain.PushSessionStatus
	var egressMode *domain.EgressMode

	if rawRepo := strings.TrimSpace(q.Get("repository_id")); rawRepo != "" {
		id, err := parseUUIDv7(rawRepo)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_REPOSITORY_ID", "repository_id must be a valid UUIDv7"))
			return
		}
		repoID = &id
	}
	if rawPrin := strings.TrimSpace(q.Get("principal_id")); rawPrin != "" {
		id, err := parseUUIDv7(rawPrin)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_PRINCIPAL_ID", "principal_id must be a valid UUIDv7"))
			return
		}
		principalID = &id
	}
	if !canReadAllPushes(caller) {
		if principalID != nil && *principalID != caller.Principal.ID {
			writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller may only query their own push sessions"))
			return
		}
		pid := caller.Principal.ID
		principalID = &pid
	}

	if rawStatus := strings.TrimSpace(q.Get("status")); rawStatus != "" {
		st := domain.PushSessionStatus(strings.ToUpper(rawStatus))
		if !st.IsValid() {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_PUSH_STATUS", "invalid push session status"))
			return
		}
		status = &st
	}
	if rawMode := strings.TrimSpace(q.Get("egress_mode")); rawMode != "" {
		em := domain.EgressMode(strings.ToUpper(rawMode))
		if !em.IsValid() {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_EGRESS_MODE", "invalid egress_mode"))
			return
		}
		egressMode = &em
	}
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

	var rows []persistence.PushSessionRow
	var err error
	if egressMode == nil {
		rows, err = s.deps.Store.ListPushSessions(dbCtx, persistence.ListPushSessionsParams{
			PrincipalID:  principalID,
			RepositoryID: repoID,
			Status:       status,
			CursorID:     cursorID,
			Limit:        limit + 1,
		})
	} else {
		rows, err = s.listPushSessionsWithEgressMode(dbCtx, principalID, repoID, status, *egressMode, cursorID, limit+1)
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

	subjects := make(map[uuid.UUID]string)
	pushes := make([]PushSessionDTO, 0, len(rows))
	for _, row := range rows {
		subj, ok := subjects[row.PrincipalID]
		if !ok {
			if pr, pErr := s.deps.Store.GetPrincipalByID(dbCtx, row.PrincipalID); pErr == nil && pr.Subject != nil {
				subj = *pr.Subject
			}
			subjects[row.PrincipalID] = subj
		}
		pushes = append(pushes, toPushSessionDTO(row, subj))
	}

	writeJSON(w, http.StatusOK, PushListResponse{
		Pushes:     pushes,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	})
}

const listPushSessionsByEgressModeSQL = `
SELECT id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
FROM push_sessions
WHERE ($1::uuid IS NULL OR principal_id = $1::uuid)
  AND ($2::uuid IS NULL OR repository_id = $2::uuid)
  AND ($3::text IS NULL OR status = $3::text)
  AND egress_mode = $4::text
  AND ($5::uuid IS NULL OR id < $5::uuid)
ORDER BY created_at DESC, id DESC
LIMIT $6
`

func (s *server) listPushSessionsWithEgressMode(
	ctx context.Context,
	principalID, repoID *uuid.UUID,
	status *domain.PushSessionStatus,
	egressMode domain.EgressMode,
	cursorID *uuid.UUID,
	limit int,
) ([]persistence.PushSessionRow, error) {
	pool := s.deps.Store.Pool()
	if pool == nil {
		return nil, domain.Unavailable("STORE_UNAVAILABLE", "database pool is not configured")
	}
	var statusArg *string
	if status != nil {
		v := string(*status)
		statusArg = &v
	}
	pgRows, err := pool.Query(ctx, listPushSessionsByEgressModeSQL, principalID, repoID, statusArg, string(egressMode), cursorID, limit)
	if err != nil {
		return nil, persistence.MapError(err)
	}
	defer pgRows.Close()

	out := make([]persistence.PushSessionRow, 0)
	for pgRows.Next() {
		var row persistence.PushSessionRow
		var transport, modeStr, deliveryStr, statusStr string
		var verdictStr *string
		if err := pgRows.Scan(
			&row.ID,
			&row.PrincipalID,
			&row.RepositoryID,
			&row.Destination,
			&row.DestinationHost,
			&row.DestinationRegistered,
			&row.DestinationExternal,
			&transport,
			&row.RefUpdates,
			&row.HasLFS,
			&row.LFSObjects,
			&row.LFSObjectCount,
			&row.LFSTotalBytes,
			&row.PushManifestDigest,
			&row.BundleArtifactID,
			&modeStr,
			&deliveryStr,
			&row.Enforced,
			&statusStr,
			&verdictStr,
			&row.LatestPolicyDecisionID,
			&row.ApprovalReleaseID,
			&row.ErrorCode,
			&row.ErrorMessage,
			&row.UpstreamForwarded,
			&row.UpstreamBytesSent,
			&row.CreatedAt,
			&row.UpdatedAt,
			&row.CompletedAt,
		); err != nil {
			return nil, persistence.MapError(err)
		}
		row.Transport = domain.PushTransport(transport)
		row.EgressMode = domain.EgressMode(modeStr)
		row.PassiveAuditDelivery = domain.PassiveAuditDelivery(deliveryStr)
		row.Status = domain.PushSessionStatus(statusStr)
		if verdictStr != nil {
			eff := domain.PolicyEffect(*verdictStr)
			row.Verdict = &eff
		}
		out = append(out, row)
	}
	if err := pgRows.Err(); err != nil {
		return nil, persistence.MapError(err)
	}
	return out, nil
}

func (s *server) handleGetPush(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	pushID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()

	pushRow, err := s.deps.Store.GetPushSessionByID(dbCtx, pushID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !canReadAllPushes(caller) && pushRow.PrincipalID != caller.Principal.ID {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view this push session"))
		return
	}

	var subj string
	if pr, pErr := s.deps.Store.GetPrincipalByID(dbCtx, pushRow.PrincipalID); pErr == nil && pr.Subject != nil {
		subj = *pr.Subject
	}
	dto := toPushSessionDTO(pushRow, subj)

	scanRunRows, err := s.deps.Store.ListScanRunsByPushSession(dbCtx, pushID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	scanRuns := make([]PushScanRunSummaryDTO, 0, len(scanRunRows))
	for _, sr := range scanRunRows {
		scanRuns = append(scanRuns, toPushScanRunSummaryDTO(sr))
	}

	findingRows, err := s.deps.Store.ListFindingsByPushSession(dbCtx, persistence.ListFindingsByPushSessionParams{
		PushSessionID: pushID,
		Limit:         500,
	})
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	findings := make([]FindingDTO, 0, len(findingRows))
	for _, f := range findingRows {
		findings = append(findings, sanitizeFindingForAPI(f.ToDomain()))
	}

	assessmentRows, err := s.deps.Store.ListModelAssessmentsByPushSession(dbCtx, pushID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	assessments := make([]PushModelAssessmentDTO, 0, len(assessmentRows))
	for _, ma := range assessmentRows {
		assessments = append(assessments, toPushModelAssessmentDTO(ma))
	}
	if len(assessments) > 0 {
		latest := assessments[0]
		dto.AssessmentID = &latest.ID
		dto.AssessmentStatus = &latest.Status
		dto.AssessmentDisposition = latest.Disposition
	}

	decisionRows, err := s.deps.Store.ListPolicyDecisionsByPushSession(dbCtx, pushID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	decisions := make([]PushPolicyDecisionDTO, 0, len(decisionRows))
	for _, pd := range decisionRows {
		decisions = append(decisions, toPushPolicyDecisionDTO(pd))
	}
	if dto.PolicyEffect == nil && len(decisions) > 0 {
		eff := decisions[0].Effect
		dto.PolicyEffect = &eff
		dto.Verdict = &eff
	}
	if dto.PolicyDecisionID == nil && len(decisions) > 0 {
		id := decisions[0].ID
		dto.PolicyDecisionID = &id
		dto.LatestPolicyDecisionID = &id
	}

	releaseRows, err := s.deps.Store.ListPushApprovalReleasesBySession(dbCtx, pushID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	releases := make([]PushApprovalReleaseResponseDTO, 0, len(releaseRows))
	for _, rel := range releaseRows {
		releases = append(releases, toPushApprovalReleaseResponseDTO(rel, "APPROVE", ""))
	}

	dto.ScanRuns = scanRuns
	dto.Findings = findings
	dto.Assessments = assessments
	dto.PolicyDecisions = decisions
	dto.ApprovalReleases = releases

	writeJSON(w, http.StatusOK, dto)
}

func (s *server) handleApprovePush(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isPushApprover(caller) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("PUSH_APPROVER_REQUIRED", "only authorized human reviewers may approve or reject pushes"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	pushID, err := parseUUIDv7Param(r, "id")
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

	var req ApprovePushRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	decision := strings.ToUpper(strings.TrimSpace(req.Decision))
	if decision != "APPROVE" && decision != "REJECT" {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_APPROVAL_DECISION", "decision must be APPROVE or REJECT"))
		return
	}

	manifestDigest, err := domain.ParseSHA256Digest(req.PushManifestDigest)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	var reqPolicyEvalID *uuid.UUID
	if req.PolicyEvaluationID != nil {
		id, err := parseUUIDv7(*req.PolicyEvaluationID)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_POLICY_EVALUATION_ID", "policy_evaluation_id must be a valid UUIDv7"))
			return
		}
		reqPolicyEvalID = &id
	}

	var comment, reason string
	if req.Comment != nil {
		if utf8.RuneCountInString(*req.Comment) > 4096 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("COMMENT_TOO_LONG", "comment must not exceed 4096 characters"))
			return
		}
		comment = *req.Comment
	}
	if req.Reason != nil {
		if utf8.RuneCountInString(*req.Reason) > 4096 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("REASON_TOO_LONG", "reason must not exceed 4096 characters"))
			return
		}
		reason = *req.Reason
	}
	reasonForDB := reason
	if reasonForDB == "" {
		reasonForDB = comment
	}

	if req.Destination != nil {
		if utf8.RuneCountInString(*req.Destination) > 512 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_DESTINATION", "destination must not exceed 512 characters"))
			return
		}
		if strings.TrimSpace(*req.Destination) == "" {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_DESTINATION", "destination must not be empty"))
			return
		}
	}
	if req.TTLSeconds != nil && req.ExpiresAt != nil {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_EXPIRY", "specify either ttl_seconds or expires_at, not both"))
		return
	}
	if req.TTLSeconds != nil && (*req.TTLSeconds < 1 || *req.TTLSeconds > int64(maxPushApprovalTTL.Seconds())) {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_TTL", "ttl_seconds must be between 1 and 86400"))
		return
	}
	var parsedExpiresAt *time.Time
	if req.ExpiresAt != nil {
		t, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(*req.ExpiresAt))
		if parseErr != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_EXPIRY", "expires_at must be a valid RFC3339 date-time"))
			return
		}
		utc := t.UTC().Truncate(time.Microsecond)
		parsedExpiresAt = &utc
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		var expiresAt time.Time
		if req.TTLSeconds != nil {
			expiresAt = now.Add(time.Duration(*req.TTLSeconds) * time.Second)
		} else if parsedExpiresAt != nil {
			if !parsedExpiresAt.After(now) {
				return 0, nil, domain.BadRequest("INVALID_EXPIRY", "expires_at must be in the future")
			}
			if parsedExpiresAt.After(now.Add(maxPushApprovalTTL)) {
				return 0, nil, domain.BadRequest("INVALID_EXPIRY", "expires_at must not exceed 24 hours from now")
			}
			expiresAt = *parsedExpiresAt
		} else {
			expiresAt = now.Add(defaultPushApprovalTTL)
		}

		dbCtx, cancel := s.withDBTimeout(r.Context())
		defer cancel()

		var resp PushApprovalReleaseResponseDTO
		txErr := s.deps.Store.WithTx(dbCtx, func(tx *persistence.Tx) error {
			pushRow, err := tx.GetPushSessionByIDForUpdate(dbCtx, pushID)
			if err != nil {
				return err
			}
			if caller.Principal.Kind != domain.PrincipalKindHuman || caller.Principal.ID == pushRow.PrincipalID {
				return domain.Forbidden("APPROVAL_RELEASE_SOD_VIOLATION", "reviewer cannot approve or reject their own push")
			}
			if pushRow.PushManifestDigest == nil || strings.TrimSpace(*pushRow.PushManifestDigest) == "" {
				return domain.Conflict("MANIFEST_NOT_READY", "push session has no push_manifest_digest")
			}
			sessionDigest, err := domain.ParseSHA256Digest(*pushRow.PushManifestDigest)
			if err != nil || !strings.EqualFold(sessionDigest, manifestDigest) {
				return domain.Conflict("MANIFEST_DIGEST_MISMATCH", "push_manifest_digest does not match push session")
			}

			if pushRow.Verdict != nil {
				switch *pushRow.Verdict {
				case domain.PolicyEffectDeny, domain.PolicyEffectQuarantine, domain.PolicyEffectRequireRemediation:
					return domain.Conflict("POLICY_BLOCKED", "push session is blocked by policy and cannot be released via approval")
				}
			}
			if pushRow.Status != domain.PushSessionStatusApprovalRequired {
				return domain.Conflict("INVALID_PUSH_STATE", "push session is not awaiting approval")
			}
			if pushRow.LatestPolicyDecisionID == nil || *pushRow.LatestPolicyDecisionID == uuid.Nil {
				return domain.Conflict("MISSING_POLICY_DECISION", "push session has no policy decision")
			}
			if reqPolicyEvalID != nil && *reqPolicyEvalID != *pushRow.LatestPolicyDecisionID {
				return domain.Conflict("POLICY_DECISION_MISMATCH", "policy_evaluation_id does not match latest policy decision")
			}

			canonDest, destHost, err := canonicalizeDestination(pushRow.Destination, pushRow.DestinationHost)
			if err != nil {
				return err
			}
			if req.Destination != nil {
				canonReqDest, _, err := canonicalizeDestination(*req.Destination, destHost)
				if err != nil {
					return err
				}
				if canonReqDest != canonDest {
					return domain.Conflict("DESTINATION_MISMATCH", "destination does not match push session")
				}
			}

			// Lock existing releases for this push session and reject APPROVE or REJECT if any
			// release issued from this push session has already been consumed.
			hasConsumed, err := tx.HasConsumedPushApprovalReleaseForSession(dbCtx, pushRow.ID)
			if err != nil {
				return err
			}
			if hasConsumed {
				return domain.Conflict("APPROVAL_ALREADY_CONSUMED", "push session approval release has already been consumed")
			}

			// Revoke any expired unrevoked releases for the same binding so partial unique index allows replacement.
			if _, err := tx.Tx().Exec(dbCtx, `
				UPDATE push_approval_releases
				SET revoked_at = $4
				WHERE principal_id = $1
				  AND destination IN ($2, $5)
				  AND push_manifest_digest = $3
				  AND consumed_at IS NULL
				  AND revoked_at IS NULL
				  AND expires_at <= $4
			`, pushRow.PrincipalID, canonDest, manifestDigest, now, pushRow.Destination); err != nil {
				return persistence.MapError(err)
			}

			if decision == "REJECT" {
				revokedRows, err := tx.Tx().Query(dbCtx, `
					UPDATE push_approval_releases
					SET revoked_at = $4
					WHERE principal_id = $1
					  AND destination IN ($2, $5)
					  AND push_manifest_digest = $3
					  AND consumed_at IS NULL
					  AND revoked_at IS NULL
					RETURNING id
				`, pushRow.PrincipalID, canonDest, manifestDigest, now, pushRow.Destination)
				if err != nil {
					return persistence.MapError(err)
				}
				var rejectID uuid.UUID
				if revokedRows.Next() {
					if scanErr := revokedRows.Scan(&rejectID); scanErr != nil {
						revokedRows.Close()
						return persistence.MapError(scanErr)
					}
				}
				if rowsErr := revokedRows.Err(); rowsErr != nil {
					revokedRows.Close()
					return persistence.MapError(rowsErr)
				}
				revokedRows.Close()
				if rejectID == uuid.Nil {
					rejectID, err = domain.NewID()
					if err != nil {
						return err
					}
				}
				if _, err := tx.Tx().Exec(dbCtx, `
					UPDATE push_sessions
					SET status = $2,
					    updated_at = $3,
					    completed_at = COALESCE(completed_at, $3)
					WHERE id = $1
				`, pushRow.ID, string(domain.PushSessionStatusBlocked), now); err != nil {
					return persistence.MapError(err)
				}

				payloadBytes, _ := json.Marshal(map[string]any{
					"push_session_id":      pushRow.ID.String(),
					"principal_id":         pushRow.PrincipalID.String(),
					"approved_by":          caller.Principal.ID.String(),
					"destination":          canonDest,
					"push_manifest_digest": manifestDigest,
					"policy_decision_id":   pushRow.LatestPolicyDecisionID.String(),
					"decision":             "REJECT",
				})
				if _, err := audit.AppendTx(dbCtx, tx, audit.AppendInput{
					EventType:    "push.approval_rejected",
					ActorID:      &caller.Principal.ID,
					ResourceType: "push_session",
					ResourceID:   pushRow.ID,
					Payload:      payloadBytes,
					CreatedAt:    now,
				}, s.deps.Logger); err != nil {
					return err
				}
				s.deps.Metrics.IncPushApprovalRelease("rejected")

				nowStr := formatTimestamp(now)
				decIDStr := pushRow.LatestPolicyDecisionID.String()
				resp = PushApprovalReleaseResponseDTO{
					ID:                 rejectID.String(),
					PushSessionID:      pushRow.ID.String(),
					PrincipalID:        pushRow.PrincipalID.String(),
					ApprovedBy:         caller.Principal.ID.String(),
					PolicyDecisionID:   &decIDStr,
					Destination:        canonDest,
					PushManifestDigest: manifestDigest,
					Decision:           "REJECT",
					SingleUse:          true,
					Consumed:           false,
					Reason:             optString(reasonForDB),
					Comment:            optString(comment),
					RevokedAt:          &nowStr,
					CreatedAt:          nowStr,
				}
				return nil
			}

			// decision == "APPROVE"
			_, activeErr := tx.GetActivePushApprovalRelease(dbCtx, pushRow.PrincipalID, canonDest, manifestDigest, now)
			if activeErr == nil {
				return domain.Conflict("DUPLICATE_APPROVAL_RELEASE", "an active unconsumed push approval release already exists for this binding")
			}
			if !errors.Is(activeErr, domain.ErrNotFound) {
				return activeErr
			}

			relRow, err := tx.CreatePushApprovalRelease(dbCtx, persistence.CreatePushApprovalReleaseParams{
				PrincipalID:        pushRow.PrincipalID,
				Destination:        canonDest,
				PushManifestDigest: manifestDigest,
				PushSessionID:      pushRow.ID,
				PolicyDecisionID:   *pushRow.LatestPolicyDecisionID,
				ApprovedBy:         caller.Principal.ID,
				Reason:             reasonForDB,
				ExpiresAt:          expiresAt,
				CreatedAt:          now,
			})
			if err != nil {
				return err
			}

			if _, err := tx.Tx().Exec(dbCtx, `
				UPDATE push_sessions
				SET approval_release_id = $2,
				    updated_at = $3
				WHERE id = $1
			`, pushRow.ID, relRow.ID, now); err != nil {
				return persistence.MapError(err)
			}

			payloadBytes, _ := json.Marshal(map[string]any{
				"release_id":           relRow.ID.String(),
				"push_session_id":      pushRow.ID.String(),
				"principal_id":         pushRow.PrincipalID.String(),
				"approved_by":          caller.Principal.ID.String(),
				"destination":          canonDest,
				"push_manifest_digest": manifestDigest,
				"policy_decision_id":   pushRow.LatestPolicyDecisionID.String(),
				"expires_at":           formatTimestamp(relRow.ExpiresAt),
				"decision":             "APPROVE",
			})
			if _, err := audit.AppendTx(dbCtx, tx, audit.AppendInput{
				EventType:    "push.approval_released",
				ActorID:      &caller.Principal.ID,
				ResourceType: "push_session",
				ResourceID:   pushRow.ID,
				Payload:      payloadBytes,
				CreatedAt:    now,
			}, s.deps.Logger); err != nil {
				return err
			}
			s.deps.Metrics.IncPushApprovalRelease("issued")

			resp = toPushApprovalReleaseResponseDTO(relRow, "APPROVE", comment)
			return nil
		})
		if txErr != nil {
			return 0, nil, mapDBTimeoutError(dbCtx, txErr)
		}
		return http.StatusCreated, resp, nil
	})
}
