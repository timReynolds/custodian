package persistence

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

type CreateWorkspaceParams struct {
	ID                 uuid.UUID
	RepositoryID       uuid.UUID
	OwnerID            uuid.UUID
	AgentID            *uuid.UUID
	AgentType          string
	AgentSessionID     string
	ModelRoute         string
	BaseCommit         string
	TargetRef          string
	SourceArtifactID   *uuid.UUID
	IncludeGitMetadata bool
	IncludeHistory     bool
	Generation         int64
	Status             domain.WorkspaceStatus
	CreatedAt          time.Time
}

const createWorkspaceSQL = `
INSERT INTO workspaces (
    id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12,
    $13, $14, $15, $16
)
RETURNING id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
`

func (q *Queries) CreateWorkspace(ctx context.Context, arg CreateWorkspaceParams) (WorkspaceRow, error) {
	if arg.RepositoryID == uuid.Nil || arg.OwnerID == uuid.Nil {
		return WorkspaceRow{}, domain.BadRequest("INVALID_WORKSPACE", "repository_id and owner_id are required")
	}
	baseCommit, err := domain.ParseGitSHA(arg.BaseCommit)
	if err != nil {
		return WorkspaceRow{}, err
	}
	if arg.TargetRef == "" {
		return WorkspaceRow{}, domain.BadRequest("INVALID_TARGET_REF", "target_ref must not be empty")
	}
	status := arg.Status
	if status == "" {
		status = domain.WorkspaceStatusPending
	}
	if !status.IsValid() {
		return WorkspaceRow{}, domain.BadRequest("INVALID_WORKSPACE_STATUS", "invalid workspace status")
	}
	gen := arg.Generation
	if gen == 0 {
		gen = 1
	}
	if gen < 1 {
		return WorkspaceRow{}, domain.BadRequest("INVALID_GENERATION", "workspace generation must be >= 1")
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return WorkspaceRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return WorkspaceRow{}, domain.BadRequest("INVALID_ID", "workspace id must be UUIDv7")
	}
	now := arg.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}

	var row WorkspaceRow
	var st string
	err = q.db.QueryRow(ctx, createWorkspaceSQL,
		id,
		arg.RepositoryID,
		arg.OwnerID,
		arg.AgentID,
		nilIfEmpty(arg.AgentType),
		nilIfEmpty(arg.AgentSessionID),
		nilIfEmpty(arg.ModelRoute),
		baseCommit,
		arg.TargetRef,
		arg.SourceArtifactID,
		arg.IncludeGitMetadata,
		arg.IncludeHistory,
		gen,
		string(status),
		now,
		now,
	).Scan(
		&row.ID,
		&row.RepositoryID,
		&row.OwnerID,
		&row.AgentID,
		&row.AgentType,
		&row.AgentSessionID,
		&row.ModelRoute,
		&row.BaseCommit,
		&row.TargetRef,
		&row.SourceArtifactID,
		&row.IncludeGitMetadata,
		&row.IncludeHistory,
		&row.Generation,
		&st,
		&row.CreatedAt,
		&row.UpdatedAt,
	)
	if err != nil {
		return WorkspaceRow{}, MapError(err)
	}
	row.Status = domain.WorkspaceStatus(st)
	return row, nil
}

const getWorkspaceByIDSQL = `
SELECT id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
FROM workspaces
WHERE id = $1
`

func (q *Queries) GetWorkspaceByID(ctx context.Context, id uuid.UUID) (WorkspaceRow, error) {
	if id == uuid.Nil {
		return WorkspaceRow{}, domain.BadRequest("INVALID_ID", "workspace id must not be nil")
	}
	var row WorkspaceRow
	var st string
	err := q.db.QueryRow(ctx, getWorkspaceByIDSQL, id).Scan(
		&row.ID,
		&row.RepositoryID,
		&row.OwnerID,
		&row.AgentID,
		&row.AgentType,
		&row.AgentSessionID,
		&row.ModelRoute,
		&row.BaseCommit,
		&row.TargetRef,
		&row.SourceArtifactID,
		&row.IncludeGitMetadata,
		&row.IncludeHistory,
		&row.Generation,
		&st,
		&row.CreatedAt,
		&row.UpdatedAt,
	)
	if err != nil {
		return WorkspaceRow{}, MapError(err)
	}
	row.Status = domain.WorkspaceStatus(st)
	return row, nil
}

const getWorkspaceDetailsByIDSQL = `
SELECT
    w.id, w.repository_id, w.owner_id, w.agent_id, w.agent_type, w.agent_session_id, w.model_route,
    w.base_commit, w.target_ref, w.source_artifact_id, w.include_git_metadata, w.include_history,
    w.generation, w.status, w.created_at, w.updated_at,
    r.github_repository_id, r.full_name,
    p.issuer, p.subject, p.display_name
FROM workspaces w
JOIN repositories r ON r.id = w.repository_id
JOIN principals p ON p.id = w.owner_id
WHERE w.id = $1
`

func (q *Queries) GetWorkspaceDetailsByID(ctx context.Context, id uuid.UUID) (WorkspaceDetailsRow, error) {
	if id == uuid.Nil {
		return WorkspaceDetailsRow{}, domain.BadRequest("INVALID_ID", "workspace id must not be nil")
	}
	var details WorkspaceDetailsRow
	var st string
	err := q.db.QueryRow(ctx, getWorkspaceDetailsByIDSQL, id).Scan(
		&details.Workspace.ID,
		&details.Workspace.RepositoryID,
		&details.Workspace.OwnerID,
		&details.Workspace.AgentID,
		&details.Workspace.AgentType,
		&details.Workspace.AgentSessionID,
		&details.Workspace.ModelRoute,
		&details.Workspace.BaseCommit,
		&details.Workspace.TargetRef,
		&details.Workspace.SourceArtifactID,
		&details.Workspace.IncludeGitMetadata,
		&details.Workspace.IncludeHistory,
		&details.Workspace.Generation,
		&st,
		&details.Workspace.CreatedAt,
		&details.Workspace.UpdatedAt,
		&details.GitHubRepositoryID,
		&details.RepositoryFullName,
		&details.OwnerIssuer,
		&details.OwnerSubject,
		&details.OwnerDisplayName,
	)
	if err != nil {
		return WorkspaceDetailsRow{}, MapError(err)
	}
	details.Workspace.Status = domain.WorkspaceStatus(st)
	return details, nil
}

const transitionWorkspaceStatusSQL = `
UPDATE workspaces
SET status     = $2,
    updated_at = $3
WHERE id = $1 AND status = $4
RETURNING id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
`

func (q *Queries) TransitionWorkspaceStatus(ctx context.Context, id uuid.UUID, fromStatus, toStatus domain.WorkspaceStatus, now time.Time) (WorkspaceRow, error) {
	if id == uuid.Nil {
		return WorkspaceRow{}, domain.BadRequest("INVALID_ID", "workspace id must not be nil")
	}
	if !fromStatus.IsValid() || !toStatus.IsValid() {
		return WorkspaceRow{}, domain.BadRequest("INVALID_WORKSPACE_STATUS", "invalid workspace status")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	var row WorkspaceRow
	var st string
	err := q.db.QueryRow(ctx, transitionWorkspaceStatusSQL, id, string(toStatus), now, string(fromStatus)).Scan(
		&row.ID,
		&row.RepositoryID,
		&row.OwnerID,
		&row.AgentID,
		&row.AgentType,
		&row.AgentSessionID,
		&row.ModelRoute,
		&row.BaseCommit,
		&row.TargetRef,
		&row.SourceArtifactID,
		&row.IncludeGitMetadata,
		&row.IncludeHistory,
		&row.Generation,
		&st,
		&row.CreatedAt,
		&row.UpdatedAt,
	)
	if err != nil {
		return WorkspaceRow{}, MapError(err)
	}
	row.Status = domain.WorkspaceStatus(st)
	return row, nil
}

const attachWorkspaceSourceArtifactSQL = `
UPDATE workspaces
SET source_artifact_id = $2,
    status             = $3,
    updated_at         = $4
WHERE id = $1
  AND source_artifact_id IS NULL
  AND status IN ('PENDING', 'PREPARING')
RETURNING id, repository_id, owner_id, agent_id, agent_type, agent_session_id, model_route,
    base_commit, target_ref, source_artifact_id, include_git_metadata, include_history,
    generation, status, created_at, updated_at
`

func (q *Queries) AttachWorkspaceSourceArtifact(ctx context.Context, workspaceID, artifactID uuid.UUID, status domain.WorkspaceStatus, now time.Time) (WorkspaceRow, error) {
	if workspaceID == uuid.Nil || artifactID == uuid.Nil {
		return WorkspaceRow{}, domain.BadRequest("INVALID_ID", "workspace_id and artifact_id must not be nil")
	}
	if status == "" {
		status = domain.WorkspaceStatusReady
	}
	if !status.IsValid() || status != domain.WorkspaceStatusReady {
		return WorkspaceRow{}, domain.BadRequest("INVALID_WORKSPACE_STATUS", "attaching source artifact requires READY status")
	}
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	var row WorkspaceRow
	var st string
	err := q.db.QueryRow(ctx, attachWorkspaceSourceArtifactSQL, workspaceID, artifactID, string(status), now).Scan(
		&row.ID,
		&row.RepositoryID,
		&row.OwnerID,
		&row.AgentID,
		&row.AgentType,
		&row.AgentSessionID,
		&row.ModelRoute,
		&row.BaseCommit,
		&row.TargetRef,
		&row.SourceArtifactID,
		&row.IncludeGitMetadata,
		&row.IncludeHistory,
		&row.Generation,
		&st,
		&row.CreatedAt,
		&row.UpdatedAt,
	)
	if err != nil {
		return WorkspaceRow{}, MapError(err)
	}
	row.Status = domain.WorkspaceStatus(st)
	return row, nil
}
