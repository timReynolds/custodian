package persistence

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/timreynolds/custodian/internal/domain"
)

type CreateProposalParams struct {
	ID                 uuid.UUID
	WorkspaceID        uuid.UUID
	OwnerID            uuid.UUID
	SnapshotArtifactID uuid.UUID
	BaseCommit         string
	TargetRef          string
	Title              string
	Description        string
	ProvenanceType     string
	CaptureMethod      string
	Status             domain.ProposalStatus
	Version            int64
	CreatedAt          time.Time
}

const createProposalSQL = `
INSERT INTO proposals (
    id, workspace_id, owner_id, snapshot_artifact_id,
    base_commit, target_ref, title, description,
    provenance_type, capture_method, status, version,
    created_at, updated_at
) VALUES (
    $1, $2, $3, $4,
    $5, $6, $7, $8,
    $9, $10, $11, $12,
    $13, $14
)
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
`

func validateProvenanceType(v string) (string, error) {
	if v == "" {
		return "agent_assisted", nil
	}
	switch v {
	case "agent_assisted", "human_authored":
		return v, nil
	default:
		return "", domain.BadRequest("INVALID_PROVENANCE_TYPE", "provenance_type must be agent_assisted or human_authored")
	}
}

func validateCaptureMethod(v string) (string, error) {
	if v == "" {
		return "frozen_filesystem", nil
	}
	switch v {
	case "frozen_filesystem", "patch_upload":
		return v, nil
	default:
		return "", domain.BadRequest("INVALID_CAPTURE_METHOD", "capture_method must be frozen_filesystem or patch_upload")
	}
}

func (q *Queries) CreateProposal(ctx context.Context, arg CreateProposalParams) (ProposalRow, error) {
	if arg.WorkspaceID == uuid.Nil || arg.OwnerID == uuid.Nil || arg.SnapshotArtifactID == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_PROPOSAL", "workspace_id, owner_id, and snapshot_artifact_id are required")
	}
	baseCommit, err := domain.ParseGitSHA(arg.BaseCommit)
	if err != nil {
		return ProposalRow{}, err
	}
	if arg.TargetRef == "" {
		return ProposalRow{}, domain.BadRequest("INVALID_TARGET_REF", "target_ref must not be empty")
	}
	provenanceType, err := validateProvenanceType(arg.ProvenanceType)
	if err != nil {
		return ProposalRow{}, err
	}
	captureMethod, err := validateCaptureMethod(arg.CaptureMethod)
	if err != nil {
		return ProposalRow{}, err
	}
	status := arg.Status
	if status == "" {
		status = domain.ProposalStatusCaptured
	}
	if !status.IsValid() {
		return ProposalRow{}, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid proposal status")
	}
	version := arg.Version
	if version == 0 {
		version = 1
	}
	if version < 1 {
		return ProposalRow{}, domain.BadRequest("INVALID_VERSION", "proposal version must be >= 1")
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return ProposalRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return ProposalRow{}, domain.BadRequest("INVALID_ID", "proposal id must be UUIDv7")
	}
	now := normalizeTimestamp(arg.CreatedAt)

	var row ProposalRow
	err = scanProposalRow(q.db.QueryRow(ctx, createProposalSQL,
		id,
		arg.WorkspaceID,
		arg.OwnerID,
		arg.SnapshotArtifactID,
		baseCommit,
		arg.TargetRef,
		arg.Title,
		nilIfEmpty(arg.Description),
		provenanceType,
		captureMethod,
		string(status),
		version,
		now,
		now,
	), &row)
	if err != nil {
		return ProposalRow{}, MapError(err)
	}
	return row, nil
}

const getProposalByIDSQL = `
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE id = $1
`

func (q *Queries) GetProposalByID(ctx context.Context, id uuid.UUID) (ProposalRow, error) {
	if id == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_ID", "proposal id must not be nil")
	}
	var row ProposalRow
	err := scanProposalRow(q.db.QueryRow(ctx, getProposalByIDSQL, id), &row)
	if err != nil {
		return ProposalRow{}, MapError(err)
	}
	return row, nil
}

const getProposalByIDForUpdateSQL = `
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE id = $1
FOR UPDATE
`

func (q *Queries) GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (ProposalRow, error) {
	if id == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_ID", "proposal id must not be nil")
	}
	var row ProposalRow
	err := scanProposalRow(q.db.QueryRow(ctx, getProposalByIDForUpdateSQL, id), &row)
	if err != nil {
		return ProposalRow{}, MapError(err)
	}
	return row, nil
}

const getProposalDetailsByIDSQL = `
SELECT
    p.id, p.workspace_id, p.owner_id, p.snapshot_artifact_id, p.canonical_artifact_id,
    p.diff_artifact_id, p.manifest_artifact_id, p.base_commit, p.target_ref, p.title, p.description,
    p.provenance_type, p.capture_method, p.tree_digest, p.diff_digest, p.manifest_digest,
    p.latest_policy_evaluation_id, p.latest_policy_effect, p.status, p.version, p.created_at, p.updated_at,
    r.id AS repository_id, r.github_repository_id, r.full_name AS repository_full_name, r.classification AS repository_classification,
    w.agent_id AS workspace_agent_id, w.agent_session_id AS workspace_agent_session_id,
    w.model_route AS workspace_model_route, w.generation AS workspace_generation,
    pr.kind AS owner_kind, pr.issuer AS owner_issuer, pr.subject AS owner_subject, pr.display_name AS owner_display_name
FROM proposals p
JOIN workspaces w ON w.id = p.workspace_id
JOIN repositories r ON r.id = w.repository_id
JOIN principals pr ON pr.id = p.owner_id
WHERE p.id = $1
`

func (q *Queries) GetProposalDetailsByID(ctx context.Context, id uuid.UUID) (ProposalDetailsRow, error) {
	if id == uuid.Nil {
		return ProposalDetailsRow{}, domain.BadRequest("INVALID_ID", "proposal id must not be nil")
	}
	var details ProposalDetailsRow
	if err := scanProposalDetailsRow(q.db.QueryRow(ctx, getProposalDetailsByIDSQL, id), &details); err != nil {
		return ProposalDetailsRow{}, MapError(err)
	}
	return details, nil
}

const listProposalsByWorkspaceSQL = `
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE workspace_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2
`

func (q *Queries) ListProposalsByWorkspace(ctx context.Context, workspaceID uuid.UUID, limit int) ([]ProposalRow, error) {
	if workspaceID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "workspace_id must not be nil")
	}
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := q.db.Query(ctx, listProposalsByWorkspaceSQL, workspaceID, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ProposalRow, 0)
	for rows.Next() {
		var row ProposalRow
		if err := scanProposalRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type ListProposalsByOwnerParams struct {
	OwnerID uuid.UUID
	Status  *domain.ProposalStatus
	Limit   int
}

const listProposalsByOwnerSQL = `
SELECT id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
FROM proposals
WHERE owner_id = $1
  AND ($2::text IS NULL OR status = $2::text)
ORDER BY created_at DESC, id DESC
LIMIT $3
`

func (q *Queries) ListProposalsByOwner(ctx context.Context, arg ListProposalsByOwnerParams) ([]ProposalRow, error) {
	if arg.OwnerID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "owner_id must not be nil")
	}
	var statusArg *string
	if arg.Status != nil {
		if !arg.Status.IsValid() {
			return nil, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid proposal status")
		}
		s := string(*arg.Status)
		statusArg = &s
	}
	limit := arg.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}

	rows, err := q.db.Query(ctx, listProposalsByOwnerSQL, arg.OwnerID, statusArg, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ProposalRow, 0)
	for rows.Next() {
		var row ProposalRow
		if err := scanProposalRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const listProposalDetailsByWorkspaceSQL = `
SELECT
    p.id, p.workspace_id, p.owner_id, p.snapshot_artifact_id, p.canonical_artifact_id,
    p.diff_artifact_id, p.manifest_artifact_id, p.base_commit, p.target_ref, p.title, p.description,
    p.provenance_type, p.capture_method, p.tree_digest, p.diff_digest, p.manifest_digest,
    p.latest_policy_evaluation_id, p.latest_policy_effect, p.status, p.version, p.created_at, p.updated_at,
    r.id AS repository_id, r.github_repository_id, r.full_name AS repository_full_name, r.classification AS repository_classification,
    w.agent_id AS workspace_agent_id, w.agent_session_id AS workspace_agent_session_id,
    w.model_route AS workspace_model_route, w.generation AS workspace_generation,
    pr.kind AS owner_kind, pr.issuer AS owner_issuer, pr.subject AS owner_subject, pr.display_name AS owner_display_name
FROM proposals p
JOIN workspaces w ON w.id = p.workspace_id
JOIN repositories r ON r.id = w.repository_id
JOIN principals pr ON pr.id = p.owner_id
WHERE p.workspace_id = $1
ORDER BY p.created_at DESC, p.id DESC
LIMIT $2
`

func (q *Queries) ListProposalDetailsByWorkspace(ctx context.Context, workspaceID uuid.UUID, limit int32) ([]ProposalDetailsRow, error) {
	if workspaceID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "workspace_id must not be nil")
	}
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := q.db.Query(ctx, listProposalDetailsByWorkspaceSQL, workspaceID, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ProposalDetailsRow, 0)
	for rows.Next() {
		var row ProposalDetailsRow
		if err := scanProposalDetailsRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const listProposalDetailsByOwnerSQL = `
SELECT
    p.id, p.workspace_id, p.owner_id, p.snapshot_artifact_id, p.canonical_artifact_id,
    p.diff_artifact_id, p.manifest_artifact_id, p.base_commit, p.target_ref, p.title, p.description,
    p.provenance_type, p.capture_method, p.tree_digest, p.diff_digest, p.manifest_digest,
    p.latest_policy_evaluation_id, p.latest_policy_effect, p.status, p.version, p.created_at, p.updated_at,
    r.id AS repository_id, r.github_repository_id, r.full_name AS repository_full_name, r.classification AS repository_classification,
    w.agent_id AS workspace_agent_id, w.agent_session_id AS workspace_agent_session_id,
    w.model_route AS workspace_model_route, w.generation AS workspace_generation,
    pr.kind AS owner_kind, pr.issuer AS owner_issuer, pr.subject AS owner_subject, pr.display_name AS owner_display_name
FROM proposals p
JOIN workspaces w ON w.id = p.workspace_id
JOIN repositories r ON r.id = w.repository_id
JOIN principals pr ON pr.id = p.owner_id
WHERE p.owner_id = $1
  AND ($2::text IS NULL OR p.status = $2::text)
ORDER BY p.created_at DESC, p.id DESC
LIMIT $3
`

func (q *Queries) ListProposalDetailsByOwner(ctx context.Context, arg ListProposalsByOwnerParams) ([]ProposalDetailsRow, error) {
	if arg.OwnerID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "owner_id must not be nil")
	}
	var statusArg *string
	if arg.Status != nil {
		if !arg.Status.IsValid() {
			return nil, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid proposal status")
		}
		s := string(*arg.Status)
		statusArg = &s
	}
	limit := arg.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}

	rows, err := q.db.Query(ctx, listProposalDetailsByOwnerSQL, arg.OwnerID, statusArg, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ProposalDetailsRow, 0)
	for rows.Next() {
		var row ProposalDetailsRow
		if err := scanProposalDetailsRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type TransitionProposalStatusParams struct {
	ID              uuid.UUID
	FromStatus      *domain.ProposalStatus
	ToStatus        domain.ProposalStatus
	ExpectedVersion int64
	UpdatedAt       time.Time
}

const transitionProposalStatusSQL = `
UPDATE proposals
SET status     = $2,
    version    = version + 1,
    updated_at = $3
WHERE id = $1
  AND version = $4
  AND ($5::text IS NULL OR status = $5::text)
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
`

func (q *Queries) TransitionProposalStatus(ctx context.Context, arg TransitionProposalStatusParams) (ProposalRow, error) {
	if arg.ID == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_ID", "proposal id must not be nil")
	}
	if !arg.ToStatus.IsValid() {
		return ProposalRow{}, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid target proposal status")
	}
	if arg.ExpectedVersion < 1 {
		return ProposalRow{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	var fromArg *string
	if arg.FromStatus != nil {
		if !arg.FromStatus.IsValid() {
			return ProposalRow{}, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid source proposal status")
		}
		s := string(*arg.FromStatus)
		fromArg = &s
	}
	now := normalizeTimestamp(arg.UpdatedAt)

	var row ProposalRow
	err := scanProposalRow(q.db.QueryRow(ctx, transitionProposalStatusSQL,
		arg.ID,
		string(arg.ToStatus),
		now,
		arg.ExpectedVersion,
		fromArg,
	), &row)
	if err != nil {
		return ProposalRow{}, q.disambiguateProposalConflict(ctx, arg.ID, err)
	}
	return row, nil
}

type SetProposalReconstructionParams struct {
	ID                  uuid.UUID
	CanonicalArtifactID uuid.UUID
	DiffArtifactID      *uuid.UUID
	ManifestArtifactID  uuid.UUID
	TreeDigest          string
	DiffDigest          string
	ManifestDigest      string
	Status              domain.ProposalStatus
	ExpectedVersion     int64
	UpdatedAt           time.Time
}

const setProposalReconstructionSQL = `
UPDATE proposals
SET canonical_artifact_id = $2,
    diff_artifact_id      = $3,
    manifest_artifact_id  = $4,
    tree_digest           = $5,
    diff_digest           = $6,
    manifest_digest       = $7,
    status                = $8,
    version               = version + 1,
    updated_at            = $9
WHERE id = $1
  AND version = $10
  AND status IN ('CAPTURED', 'RECONSTRUCTING')
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
`

func (q *Queries) SetProposalReconstruction(ctx context.Context, arg SetProposalReconstructionParams) (ProposalRow, error) {
	if arg.ID == uuid.Nil || arg.CanonicalArtifactID == uuid.Nil || arg.ManifestArtifactID == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_RECONSTRUCTION", "proposal, canonical artifact, and manifest artifact IDs are required")
	}
	if arg.DiffArtifactID != nil && *arg.DiffArtifactID == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_ID", "diff_artifact_id must not be nil when provided")
	}
	treeDigest := strings.TrimSpace(arg.TreeDigest)
	if len(treeDigest) < 40 || len(treeDigest) > 64 {
		return ProposalRow{}, domain.BadRequest("INVALID_TREE_DIGEST", "tree_digest must be between 40 and 64 characters")
	}
	diffDigest, err := domain.ParseSHA256Digest(arg.DiffDigest)
	if err != nil {
		return ProposalRow{}, err
	}
	manifestDigest, err := domain.ParseSHA256Digest(arg.ManifestDigest)
	if err != nil {
		return ProposalRow{}, err
	}
	status := arg.Status
	if status == "" {
		status = domain.ProposalStatusReconstructed
	}
	if !status.IsValid() {
		return ProposalRow{}, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid proposal status")
	}
	if arg.ExpectedVersion < 1 {
		return ProposalRow{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	now := normalizeTimestamp(arg.UpdatedAt)

	var row ProposalRow
	err = scanProposalRow(q.db.QueryRow(ctx, setProposalReconstructionSQL,
		arg.ID,
		arg.CanonicalArtifactID,
		arg.DiffArtifactID,
		arg.ManifestArtifactID,
		treeDigest,
		diffDigest,
		manifestDigest,
		string(status),
		now,
		arg.ExpectedVersion,
	), &row)
	if err != nil {
		return ProposalRow{}, q.disambiguateProposalConflict(ctx, arg.ID, err)
	}
	return row, nil
}

type ApplyProposalPolicyDecisionParams struct {
	ID                 uuid.UUID
	PolicyEvaluationID uuid.UUID
	PolicyEffect       domain.PolicyEffect
	Status             domain.ProposalStatus
	ExpectedVersion    int64
	UpdatedAt          time.Time
}

const applyProposalPolicyDecisionSQL = `
UPDATE proposals
SET latest_policy_evaluation_id = $2,
    latest_policy_effect        = $3,
    status                      = $4,
    version                     = version + 1,
    updated_at                  = $5
WHERE id = $1
  AND version = $6
RETURNING id, workspace_id, owner_id, snapshot_artifact_id, canonical_artifact_id,
    diff_artifact_id, manifest_artifact_id, base_commit, target_ref, title, description,
    provenance_type, capture_method, tree_digest, diff_digest, manifest_digest,
    latest_policy_evaluation_id, latest_policy_effect, status, version, created_at, updated_at
`

func (q *Queries) ApplyProposalPolicyDecision(ctx context.Context, arg ApplyProposalPolicyDecisionParams) (ProposalRow, error) {
	if arg.ID == uuid.Nil || arg.PolicyEvaluationID == uuid.Nil {
		return ProposalRow{}, domain.BadRequest("INVALID_POLICY_APPLICATION", "proposal id and policy_evaluation_id are required")
	}
	if !arg.PolicyEffect.IsValid() {
		return ProposalRow{}, domain.BadRequest("INVALID_POLICY_EFFECT", "invalid policy effect")
	}
	if !arg.Status.IsValid() {
		return ProposalRow{}, domain.BadRequest("INVALID_PROPOSAL_STATUS", "invalid proposal status")
	}
	if arg.ExpectedVersion < 1 {
		return ProposalRow{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	now := normalizeTimestamp(arg.UpdatedAt)

	var row ProposalRow
	err := scanProposalRow(q.db.QueryRow(ctx, applyProposalPolicyDecisionSQL,
		arg.ID,
		arg.PolicyEvaluationID,
		string(arg.PolicyEffect),
		string(arg.Status),
		now,
		arg.ExpectedVersion,
	), &row)
	if err != nil {
		return ProposalRow{}, q.disambiguateProposalConflict(ctx, arg.ID, err)
	}
	return row, nil
}

func (q *Queries) disambiguateProposalConflict(ctx context.Context, id uuid.UUID, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		var existing ProposalRow
		lookupErr := scanProposalRow(q.db.QueryRow(ctx, getProposalByIDSQL, id), &existing)
		if lookupErr == nil {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version or status has changed")
		}
		if !errors.Is(lookupErr, pgx.ErrNoRows) {
			return MapError(lookupErr)
		}
	}
	return MapError(err)
}

func scanProposalRow(s rowScanner, row *ProposalRow) error {
	var effect *string
	var status string
	if err := s.Scan(
		&row.ID,
		&row.WorkspaceID,
		&row.OwnerID,
		&row.SnapshotArtifactID,
		&row.CanonicalArtifactID,
		&row.DiffArtifactID,
		&row.ManifestArtifactID,
		&row.BaseCommit,
		&row.TargetRef,
		&row.Title,
		&row.Description,
		&row.ProvenanceType,
		&row.CaptureMethod,
		&row.TreeDigest,
		&row.DiffDigest,
		&row.ManifestDigest,
		&row.LatestPolicyEvaluationID,
		&effect,
		&status,
		&row.Version,
		&row.CreatedAt,
		&row.UpdatedAt,
	); err != nil {
		return err
	}
	if effect != nil {
		e := domain.PolicyEffect(*effect)
		row.LatestPolicyEffect = &e
	} else {
		row.LatestPolicyEffect = nil
	}
	row.Status = domain.ProposalStatus(status)
	return nil
}

func scanProposalDetailsRow(s rowScanner, details *ProposalDetailsRow) error {
	var effect *string
	var status, repoClass, ownerKind string
	if err := s.Scan(
		&details.Proposal.ID,
		&details.Proposal.WorkspaceID,
		&details.Proposal.OwnerID,
		&details.Proposal.SnapshotArtifactID,
		&details.Proposal.CanonicalArtifactID,
		&details.Proposal.DiffArtifactID,
		&details.Proposal.ManifestArtifactID,
		&details.Proposal.BaseCommit,
		&details.Proposal.TargetRef,
		&details.Proposal.Title,
		&details.Proposal.Description,
		&details.Proposal.ProvenanceType,
		&details.Proposal.CaptureMethod,
		&details.Proposal.TreeDigest,
		&details.Proposal.DiffDigest,
		&details.Proposal.ManifestDigest,
		&details.Proposal.LatestPolicyEvaluationID,
		&effect,
		&status,
		&details.Proposal.Version,
		&details.Proposal.CreatedAt,
		&details.Proposal.UpdatedAt,
		&details.RepositoryID,
		&details.GitHubRepositoryID,
		&details.RepositoryFullName,
		&repoClass,
		&details.WorkspaceAgentID,
		&details.WorkspaceAgentSessionID,
		&details.WorkspaceModelRoute,
		&details.WorkspaceGeneration,
		&ownerKind,
		&details.OwnerIssuer,
		&details.OwnerSubject,
		&details.OwnerDisplayName,
	); err != nil {
		return err
	}
	if effect != nil {
		e := domain.PolicyEffect(*effect)
		details.Proposal.LatestPolicyEffect = &e
	} else {
		details.Proposal.LatestPolicyEffect = nil
	}
	details.Proposal.Status = domain.ProposalStatus(status)
	details.RepositoryClassification = domain.Classification(repoClass)
	details.OwnerKind = domain.PrincipalKind(ownerKind)
	return nil
}
