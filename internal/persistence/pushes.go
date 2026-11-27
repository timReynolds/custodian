package persistence

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// --- push_sessions ---

type CreatePushSessionParams struct {
	ID                     uuid.UUID
	PrincipalID            uuid.UUID
	RepositoryID           *uuid.UUID
	Destination            string
	DestinationHost        string
	DestinationRegistered  bool
	DestinationExternal    bool
	Transport              domain.PushTransport
	RefUpdates             []domain.PushRefUpdate
	HasLFS                 bool
	LFSObjects             []domain.PushLFSObject
	LFSObjectCount         int64
	LFSTotalBytes          int64
	PushManifestDigest     string
	BundleArtifactID       *uuid.UUID
	EgressMode             domain.EgressMode
	PassiveAuditDelivery   domain.PassiveAuditDelivery
	Enforced               *bool
	Status                 domain.PushSessionStatus
	Verdict                *domain.PolicyEffect
	LatestPolicyDecisionID *uuid.UUID
	ApprovalReleaseID      *uuid.UUID
	ErrorCode              string
	ErrorMessage           string
	UpstreamForwarded      bool
	UpstreamBytesSent      int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
	CompletedAt            *time.Time
}

const createPushSessionSQL = `
INSERT INTO push_sessions (
    id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18,
    $19, $20, $21, $22,
    $23, $24, $25, $26,
    $27, $28, $29
)
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
`

func marshalPushRefUpdates(refs []domain.PushRefUpdate) (json.RawMessage, error) {
	if refs == nil {
		refs = []domain.PushRefUpdate{}
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_REF_UPDATES", "failed to marshal ref_updates", err)
	}
	canon, err := domain.CanonicalJSONBytes(raw)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canon), nil
}

func marshalPushLFSObjects(objs []domain.PushLFSObject) (json.RawMessage, error) {
	if objs == nil {
		objs = []domain.PushLFSObject{}
	}
	raw, err := json.Marshal(objs)
	if err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_LFS_OBJECTS", "failed to marshal lfs_objects", err)
	}
	canon, err := domain.CanonicalJSONBytes(raw)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canon), nil
}

func (q *Queries) CreatePushSession(ctx context.Context, arg CreatePushSessionParams) (PushSessionRow, error) {
	if arg.PrincipalID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_SESSION", "principal_id is required")
	}
	if arg.RepositoryID != nil && *arg.RepositoryID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "repository_id must not be nil when provided")
	}
	dest := strings.TrimSpace(arg.Destination)
	if dest == "" {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_SESSION", "destination is required")
	}
	transport := arg.Transport
	if transport == "" {
		transport = domain.PushTransportHTTPS
	}
	if !transport.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_TRANSPORT", "invalid push transport")
	}
	if !arg.EgressMode.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_EGRESS_MODE", "invalid egress_mode")
	}
	delivery := arg.PassiveAuditDelivery
	if delivery == "" {
		delivery = domain.PassiveAuditDeliveryAsync
	}
	if !delivery.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_PASSIVE_AUDIT_DELIVERY", "invalid passive_audit_delivery")
	}
	status := arg.Status
	if status == "" {
		status = domain.PushSessionStatusReceived
	}
	if !status.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_STATUS", "invalid push session status")
	}
	if arg.Verdict != nil && !arg.Verdict.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_POLICY_EFFECT", "invalid push verdict")
	}
	if arg.LFSObjectCount < 0 || arg.LFSTotalBytes < 0 || arg.UpstreamBytesSent < 0 {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_SESSION", "byte and object counts must be non-negative")
	}
	var manifestDigest *string
	if strings.TrimSpace(arg.PushManifestDigest) != "" {
		parsed, err := domain.ParseSHA256Digest(arg.PushManifestDigest)
		if err != nil {
			return PushSessionRow{}, err
		}
		manifestDigest = &parsed
	}
	if arg.BundleArtifactID != nil && *arg.BundleArtifactID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "bundle_artifact_id must not be nil when provided")
	}
	if arg.LatestPolicyDecisionID != nil && *arg.LatestPolicyDecisionID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "latest_policy_decision_id must not be nil when provided")
	}
	if arg.ApprovalReleaseID != nil && *arg.ApprovalReleaseID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "approval_release_id must not be nil when provided")
	}

	refsJSON, err := marshalPushRefUpdates(arg.RefUpdates)
	if err != nil {
		return PushSessionRow{}, err
	}
	lfsJSON, err := marshalPushLFSObjects(arg.LFSObjects)
	if err != nil {
		return PushSessionRow{}, err
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return PushSessionRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "push_session id must be UUIDv7")
	}

	enforced := arg.EgressMode != domain.EgressModePassiveAudit
	if arg.Enforced != nil {
		enforced = *arg.Enforced
	}
	var verdictStr *string
	if arg.Verdict != nil {
		s := string(*arg.Verdict)
		verdictStr = &s
	}

	createdAt := normalizeTimestamp(arg.CreatedAt)
	updatedAt := createdAt
	if !arg.UpdatedAt.IsZero() {
		updatedAt = normalizeTimestamp(arg.UpdatedAt)
	}
	var completedAt *time.Time
	if arg.CompletedAt != nil {
		t := arg.CompletedAt.UTC().Truncate(time.Microsecond)
		completedAt = &t
	}

	var row PushSessionRow
	err = scanPushSessionRow(q.db.QueryRow(ctx, createPushSessionSQL,
		id,
		arg.PrincipalID,
		arg.RepositoryID,
		dest,
		strings.TrimSpace(arg.DestinationHost),
		arg.DestinationRegistered,
		arg.DestinationExternal,
		string(transport),
		refsJSON,
		arg.HasLFS,
		lfsJSON,
		arg.LFSObjectCount,
		arg.LFSTotalBytes,
		manifestDigest,
		arg.BundleArtifactID,
		string(arg.EgressMode),
		string(delivery),
		enforced,
		string(status),
		verdictStr,
		arg.LatestPolicyDecisionID,
		arg.ApprovalReleaseID,
		nilIfEmpty(arg.ErrorCode),
		nilIfEmpty(arg.ErrorMessage),
		arg.UpstreamForwarded,
		arg.UpstreamBytesSent,
		createdAt,
		updatedAt,
		completedAt,
	), &row)
	if err != nil {
		return PushSessionRow{}, MapError(err)
	}
	return row, nil
}

const getPushSessionByIDSQL = `
SELECT id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
FROM push_sessions
WHERE id = $1
`

func (q *Queries) GetPushSessionByID(ctx context.Context, id uuid.UUID) (PushSessionRow, error) {
	if id == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "push_session id must not be nil")
	}
	var row PushSessionRow
	if err := scanPushSessionRow(q.db.QueryRow(ctx, getPushSessionByIDSQL, id), &row); err != nil {
		return PushSessionRow{}, MapError(err)
	}
	return row, nil
}

const getPushSessionByIDForUpdateSQL = `
SELECT id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
FROM push_sessions
WHERE id = $1
FOR UPDATE
`

func (q *Queries) GetPushSessionByIDForUpdate(ctx context.Context, id uuid.UUID) (PushSessionRow, error) {
	if id == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "push_session id must not be nil")
	}
	var row PushSessionRow
	if err := scanPushSessionRow(q.db.QueryRow(ctx, getPushSessionByIDForUpdateSQL, id), &row); err != nil {
		return PushSessionRow{}, MapError(err)
	}
	return row, nil
}

type ListPushSessionsParams struct {
	PrincipalID  *uuid.UUID
	RepositoryID *uuid.UUID
	Status       *domain.PushSessionStatus
	CursorID     *uuid.UUID
	Limit        int
}

const listPushSessionsSQL = `
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
  AND ($4::uuid IS NULL OR id < $4::uuid)
ORDER BY created_at DESC, id DESC
LIMIT $5
`

func (q *Queries) ListPushSessions(ctx context.Context, arg ListPushSessionsParams) ([]PushSessionRow, error) {
	if arg.PrincipalID != nil && *arg.PrincipalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "principal_id must not be nil")
	}
	if arg.RepositoryID != nil && *arg.RepositoryID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "repository_id must not be nil")
	}
	var statusArg *string
	if arg.Status != nil {
		if !arg.Status.IsValid() {
			return nil, domain.BadRequest("INVALID_PUSH_STATUS", "invalid push session status")
		}
		s := string(*arg.Status)
		statusArg = &s
	}
	if arg.CursorID != nil && *arg.CursorID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_CURSOR", "cursor_id must not be nil")
	}
	limit := arg.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1001 {
		limit = 1001
	}

	rows, err := q.db.Query(ctx, listPushSessionsSQL, arg.PrincipalID, arg.RepositoryID, statusArg, arg.CursorID, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]PushSessionRow, 0)
	for rows.Next() {
		var row PushSessionRow
		if err := scanPushSessionRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type UpdatePushSessionUnpackParams struct {
	ID                 uuid.UUID
	PushManifestDigest string
	BundleArtifactID   *uuid.UUID
	RefUpdates         []domain.PushRefUpdate
	Status             domain.PushSessionStatus
	UpdatedAt          time.Time
}

const updatePushSessionUnpackSQL = `
UPDATE push_sessions
SET push_manifest_digest = $2,
    bundle_artifact_id   = $3,
    ref_updates          = $4,
    status               = $5,
    updated_at           = $6
WHERE id = $1
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
`

func (q *Queries) UpdatePushSessionUnpack(ctx context.Context, arg UpdatePushSessionUnpackParams) (PushSessionRow, error) {
	if arg.ID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "push_session id must not be nil")
	}
	digest, err := domain.ParseSHA256Digest(arg.PushManifestDigest)
	if err != nil {
		return PushSessionRow{}, err
	}
	if arg.BundleArtifactID != nil && *arg.BundleArtifactID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "bundle_artifact_id must not be nil when provided")
	}
	status := arg.Status
	if status == "" {
		status = domain.PushSessionStatusQuarantined
	}
	if !status.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_STATUS", "invalid push session status")
	}
	refsJSON, err := marshalPushRefUpdates(arg.RefUpdates)
	if err != nil {
		return PushSessionRow{}, err
	}
	updatedAt := normalizeTimestamp(arg.UpdatedAt)

	var row PushSessionRow
	err = scanPushSessionRow(q.db.QueryRow(ctx, updatePushSessionUnpackSQL,
		arg.ID,
		digest,
		arg.BundleArtifactID,
		refsJSON,
		string(status),
		updatedAt,
	), &row)
	if err != nil {
		return PushSessionRow{}, MapError(err)
	}
	return row, nil
}

type ApplyPushSessionPolicyDecisionParams struct {
	ID                uuid.UUID
	PolicyDecisionID  uuid.UUID
	ApprovalReleaseID *uuid.UUID
	Verdict           domain.PolicyEffect
	Status            domain.PushSessionStatus
	UpdatedAt         time.Time
}

const applyPushSessionPolicyDecisionSQL = `
UPDATE push_sessions
SET latest_policy_decision_id = $2,
    approval_release_id       = COALESCE($3, approval_release_id),
    verdict                   = $4,
    status                    = $5,
    updated_at                = $6
WHERE id = $1
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
`

func (q *Queries) ApplyPushSessionPolicyDecision(ctx context.Context, arg ApplyPushSessionPolicyDecisionParams) (PushSessionRow, error) {
	if arg.ID == uuid.Nil || arg.PolicyDecisionID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "push_session id and policy_decision_id are required")
	}
	if arg.ApprovalReleaseID != nil && *arg.ApprovalReleaseID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "approval_release_id must not be nil when provided")
	}
	if !arg.Verdict.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_POLICY_EFFECT", "invalid policy verdict")
	}
	if !arg.Status.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_STATUS", "invalid push session status")
	}
	updatedAt := normalizeTimestamp(arg.UpdatedAt)

	var row PushSessionRow
	err := scanPushSessionRow(q.db.QueryRow(ctx, applyPushSessionPolicyDecisionSQL,
		arg.ID,
		arg.PolicyDecisionID,
		arg.ApprovalReleaseID,
		string(arg.Verdict),
		string(arg.Status),
		updatedAt,
	), &row)
	if err != nil {
		return PushSessionRow{}, MapError(err)
	}
	return row, nil
}

type CompletePushSessionParams struct {
	ID                uuid.UUID
	Status            domain.PushSessionStatus
	UpstreamForwarded bool
	UpstreamBytesSent int64
	ErrorCode         string
	ErrorMessage      string
	UpdatedAt         time.Time
	CompletedAt       time.Time
}

const completePushSessionSQL = `
UPDATE push_sessions
SET status              = $2,
    upstream_forwarded  = $3,
    upstream_bytes_sent = $4,
    error_code          = $5,
    error_message       = $6,
    updated_at          = $7,
    completed_at        = $8
WHERE id = $1
RETURNING id, principal_id, repository_id, destination, destination_host, destination_registered, destination_external,
    transport, ref_updates, has_lfs, lfs_objects, lfs_object_count, lfs_total_bytes,
    push_manifest_digest, bundle_artifact_id, egress_mode, passive_audit_delivery, enforced,
    status, verdict, latest_policy_decision_id, approval_release_id,
    error_code, error_message, upstream_forwarded, upstream_bytes_sent,
    created_at, updated_at, completed_at
`

func (q *Queries) CompletePushSession(ctx context.Context, arg CompletePushSessionParams) (PushSessionRow, error) {
	if arg.ID == uuid.Nil {
		return PushSessionRow{}, domain.BadRequest("INVALID_ID", "push_session id must not be nil")
	}
	if !arg.Status.IsValid() {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_STATUS", "invalid push session status")
	}
	if arg.UpstreamBytesSent < 0 {
		return PushSessionRow{}, domain.BadRequest("INVALID_PUSH_SESSION", "upstream_bytes_sent must be non-negative")
	}
	completedAt := normalizeTimestamp(arg.CompletedAt)
	updatedAt := completedAt
	if !arg.UpdatedAt.IsZero() {
		updatedAt = normalizeTimestamp(arg.UpdatedAt)
	}

	var row PushSessionRow
	err := scanPushSessionRow(q.db.QueryRow(ctx, completePushSessionSQL,
		arg.ID,
		string(arg.Status),
		arg.UpstreamForwarded,
		arg.UpstreamBytesSent,
		nilIfEmpty(arg.ErrorCode),
		nilIfEmpty(arg.ErrorMessage),
		updatedAt,
		completedAt,
	), &row)
	if err != nil {
		return PushSessionRow{}, MapError(err)
	}
	return row, nil
}

// --- push_approval_releases ---

type CreatePushApprovalReleaseParams struct {
	ID                 uuid.UUID
	PrincipalID        uuid.UUID
	Destination        string
	PushManifestDigest string
	PushSessionID      uuid.UUID
	PolicyDecisionID   uuid.UUID
	ApprovedBy         uuid.UUID
	Reason             string
	ExpiresAt          time.Time
	CreatedAt          time.Time
}

const createPushApprovalReleaseSQL = `
INSERT INTO push_approval_releases (
    id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    NULL, $6, $7, $8,
    $9, NULL, NULL, $10
)
RETURNING id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
`

func (q *Queries) CreatePushApprovalRelease(ctx context.Context, arg CreatePushApprovalReleaseParams) (PushApprovalReleaseRow, error) {
	if arg.PrincipalID == uuid.Nil || arg.PushSessionID == uuid.Nil || arg.PolicyDecisionID == uuid.Nil || arg.ApprovedBy == uuid.Nil {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_APPROVAL_RELEASE", "principal_id, push_session_id, policy_decision_id, and approved_by are required")
	}
	if arg.ApprovedBy == arg.PrincipalID {
		return PushApprovalReleaseRow{}, domain.Forbidden("APPROVAL_RELEASE_SOD_VIOLATION", "reviewer cannot approve their own push")
	}
	dest := strings.TrimSpace(arg.Destination)
	if dest == "" {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_APPROVAL_RELEASE", "destination is required")
	}
	digest, err := domain.ParseSHA256Digest(arg.PushManifestDigest)
	if err != nil {
		return PushApprovalReleaseRow{}, err
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)
	if arg.ExpiresAt.IsZero() || !arg.ExpiresAt.UTC().After(createdAt) {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_APPROVAL_RELEASE", "expires_at must be after created_at")
	}
	expiresAt := arg.ExpiresAt.UTC().Truncate(time.Microsecond)

	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return PushApprovalReleaseRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_ID", "approval release id must be UUIDv7")
	}

	var row PushApprovalReleaseRow
	err = scanPushApprovalReleaseRow(q.db.QueryRow(ctx, createPushApprovalReleaseSQL,
		id,
		arg.PrincipalID,
		dest,
		digest,
		arg.PushSessionID,
		arg.PolicyDecisionID,
		arg.ApprovedBy,
		nilIfEmpty(arg.Reason),
		expiresAt,
		createdAt,
	), &row)
	if err != nil {
		return PushApprovalReleaseRow{}, MapError(err)
	}
	return row, nil
}

const getPushApprovalReleaseByIDSQL = `
SELECT id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
FROM push_approval_releases
WHERE id = $1
`

func (q *Queries) GetPushApprovalReleaseByID(ctx context.Context, id uuid.UUID) (PushApprovalReleaseRow, error) {
	if id == uuid.Nil {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_ID", "approval release id must not be nil")
	}
	var row PushApprovalReleaseRow
	if err := scanPushApprovalReleaseRow(q.db.QueryRow(ctx, getPushApprovalReleaseByIDSQL, id), &row); err != nil {
		return PushApprovalReleaseRow{}, MapError(err)
	}
	return row, nil
}

const getActivePushApprovalReleaseSQL = `
SELECT id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
FROM push_approval_releases
WHERE principal_id = $1
  AND destination = $2
  AND push_manifest_digest = $3
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > $4
LIMIT 1
`

func (q *Queries) GetActivePushApprovalRelease(ctx context.Context, principalID uuid.UUID, destination, pushManifestDigest string, now time.Time) (PushApprovalReleaseRow, error) {
	if principalID == uuid.Nil {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_ID", "principal_id must not be nil")
	}
	dest := strings.TrimSpace(destination)
	if dest == "" {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_DESTINATION", "destination must not be empty")
	}
	digest, err := domain.ParseSHA256Digest(pushManifestDigest)
	if err != nil {
		return PushApprovalReleaseRow{}, err
	}
	ts := normalizeTimestamp(now)

	var row PushApprovalReleaseRow
	if err := scanPushApprovalReleaseRow(q.db.QueryRow(ctx, getActivePushApprovalReleaseSQL, principalID, dest, digest, ts), &row); err != nil {
		return PushApprovalReleaseRow{}, MapError(err)
	}
	return row, nil
}

type ConsumePushApprovalReleaseParams struct {
	PrincipalID             uuid.UUID
	Destination             string
	PushManifestDigest      string
	ConsumedAt              time.Time
	ConsumedByPushSessionID uuid.UUID
}

const consumePushApprovalReleaseSQL = `
UPDATE push_approval_releases
SET consumed_at                 = $4,
    consumed_by_push_session_id = $5
WHERE principal_id = $1
  AND destination = $2
  AND push_manifest_digest = $3
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > $4
  AND approved_by <> principal_id
RETURNING id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
`

func (q *Queries) ConsumePushApprovalRelease(ctx context.Context, arg ConsumePushApprovalReleaseParams) (PushApprovalReleaseRow, error) {
	if arg.PrincipalID == uuid.Nil || arg.ConsumedByPushSessionID == uuid.Nil {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_APPROVAL_RELEASE", "principal_id and consumed_by_push_session_id are required")
	}
	dest := strings.TrimSpace(arg.Destination)
	if dest == "" {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_DESTINATION", "destination must not be empty")
	}
	digest, err := domain.ParseSHA256Digest(arg.PushManifestDigest)
	if err != nil {
		return PushApprovalReleaseRow{}, err
	}
	consumedAt := normalizeTimestamp(arg.ConsumedAt)

	var row PushApprovalReleaseRow
	if err := scanPushApprovalReleaseRow(q.db.QueryRow(ctx, consumePushApprovalReleaseSQL,
		arg.PrincipalID,
		dest,
		digest,
		consumedAt,
		arg.ConsumedByPushSessionID,
	), &row); err != nil {
		return PushApprovalReleaseRow{}, MapError(err)
	}
	return row, nil
}

const revokePushApprovalReleaseSQL = `
UPDATE push_approval_releases
SET revoked_at = $2
WHERE id = $1
  AND consumed_at IS NULL
  AND revoked_at IS NULL
RETURNING id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
`

func (q *Queries) RevokePushApprovalRelease(ctx context.Context, id uuid.UUID, revokedAt time.Time) (PushApprovalReleaseRow, error) {
	if id == uuid.Nil {
		return PushApprovalReleaseRow{}, domain.BadRequest("INVALID_ID", "approval release id must not be nil")
	}
	ts := normalizeTimestamp(revokedAt)
	var row PushApprovalReleaseRow
	if err := scanPushApprovalReleaseRow(q.db.QueryRow(ctx, revokePushApprovalReleaseSQL, id, ts), &row); err != nil {
		return PushApprovalReleaseRow{}, MapError(err)
	}
	return row, nil
}

const listPushApprovalReleasesBySessionSQL = `
SELECT id, principal_id, destination, push_manifest_digest, push_session_id,
    consumed_by_push_session_id, policy_decision_id, approved_by, reason,
    expires_at, consumed_at, revoked_at, created_at
FROM push_approval_releases
WHERE push_session_id = $1 OR consumed_by_push_session_id = $1
ORDER BY created_at DESC, id DESC
`

func (q *Queries) ListPushApprovalReleasesBySession(ctx context.Context, pushSessionID uuid.UUID) ([]PushApprovalReleaseRow, error) {
	if pushSessionID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "push_session_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listPushApprovalReleasesBySessionSQL, pushSessionID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]PushApprovalReleaseRow, 0)
	for rows.Next() {
		var row PushApprovalReleaseRow
		if err := scanPushApprovalReleaseRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const lockPushApprovalReleasesBySessionForConsumedCheckSQL = `
SELECT consumed_at
FROM push_approval_releases
WHERE push_session_id = $1
FOR UPDATE
`

// HasConsumedPushApprovalReleaseForSession locks any approval releases issued for pushSessionID
// and reports whether any of them has already been consumed.
func (q *Queries) HasConsumedPushApprovalReleaseForSession(ctx context.Context, pushSessionID uuid.UUID) (bool, error) {
	if pushSessionID == uuid.Nil {
		return false, domain.BadRequest("INVALID_ID", "push_session_id must not be nil")
	}
	rows, err := q.db.Query(ctx, lockPushApprovalReleasesBySessionForConsumedCheckSQL, pushSessionID)
	if err != nil {
		return false, MapError(err)
	}
	defer rows.Close()

	for rows.Next() {
		var consumedAt *time.Time
		if err := rows.Scan(&consumedAt); err != nil {
			return false, MapError(err)
		}
		if consumedAt != nil {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, MapError(err)
	}
	return false, nil
}

// --- scan helpers ---

func scanPushSessionRow(s rowScanner, row *PushSessionRow) error {
	var transport, egressMode, delivery, status string
	var verdict *string
	if err := s.Scan(
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
		&egressMode,
		&delivery,
		&row.Enforced,
		&status,
		&verdict,
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
		return err
	}
	row.Transport = domain.PushTransport(transport)
	row.EgressMode = domain.EgressMode(egressMode)
	row.PassiveAuditDelivery = domain.PassiveAuditDelivery(delivery)
	row.Status = domain.PushSessionStatus(status)
	if verdict != nil {
		v := domain.PolicyEffect(*verdict)
		row.Verdict = &v
	} else {
		row.Verdict = nil
	}
	return nil
}

func scanPushApprovalReleaseRow(s rowScanner, row *PushApprovalReleaseRow) error {
	return s.Scan(
		&row.ID,
		&row.PrincipalID,
		&row.Destination,
		&row.PushManifestDigest,
		&row.PushSessionID,
		&row.ConsumedByPushSessionID,
		&row.PolicyDecisionID,
		&row.ApprovedBy,
		&row.Reason,
		&row.ExpiresAt,
		&row.ConsumedAt,
		&row.RevokedAt,
		&row.CreatedAt,
	)
}
