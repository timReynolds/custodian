package domain

import (
	"time"

	"github.com/google/uuid"
)

type WorkspaceStatus string

const (
	WorkspaceStatusPending   WorkspaceStatus = "PENDING"
	WorkspaceStatusPreparing WorkspaceStatus = "PREPARING"
	WorkspaceStatusReady     WorkspaceStatus = "READY"
	WorkspaceStatusFailed    WorkspaceStatus = "FAILED"
	WorkspaceStatusClosed    WorkspaceStatus = "CLOSED"
)

func (s WorkspaceStatus) IsValid() bool {
	switch s {
	case WorkspaceStatusPending, WorkspaceStatusPreparing, WorkspaceStatusReady, WorkspaceStatusFailed, WorkspaceStatusClosed:
		return true
	default:
		return false
	}
}

func (s WorkspaceStatus) IsTerminal() bool {
	return s == WorkspaceStatusFailed || s == WorkspaceStatusClosed
}

type SourceOptions struct {
	IncludeGitMetadata bool `json:"include_git_metadata"`
	IncludeHistory     bool `json:"include_history"`
}

type Workspace struct {
	ID               uuid.UUID       `json:"id"`
	RepositoryID     uuid.UUID       `json:"repository_id"`
	OwnerID          uuid.UUID       `json:"owner_id"`
	AgentID          *uuid.UUID      `json:"agent_id,omitempty"`
	AgentSessionID   string          `json:"agent_session_id,omitempty"`
	ModelRoute       string          `json:"model_route,omitempty"`
	BaseCommit       string          `json:"base_commit"`
	TargetRef        string          `json:"target_ref"`
	SourceArtifactID *uuid.UUID      `json:"source_artifact_id,omitempty"`
	Generation       int64           `json:"generation"`
	Status           WorkspaceStatus `json:"status"`
	CreatedAt        time.Time       `json:"created_at"`
}
