package workspaces

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/repositories"
)

// TxStore defines all persistence methods usable inside a workspace transaction.
type TxStore interface {
	GetRepositoryByID(ctx context.Context, id uuid.UUID) (persistence.RepositoryRow, error)
	GetPrincipalByID(ctx context.Context, id uuid.UUID) (persistence.PrincipalRow, error)
	GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error)
	CreateWorkspace(ctx context.Context, arg persistence.CreateWorkspaceParams) (persistence.WorkspaceRow, error)
	GetWorkspaceByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error)
	TransitionWorkspaceStatus(ctx context.Context, id uuid.UUID, fromStatus, toStatus domain.WorkspaceStatus, now time.Time) (persistence.WorkspaceRow, error)
	AttachWorkspaceSourceArtifact(ctx context.Context, workspaceID, artifactID uuid.UUID, status domain.WorkspaceStatus, now time.Time) (persistence.WorkspaceRow, error)
	operations.TxStore
	audit.ChainStore
}

// Store defines the persistence operations and transaction runner required by the workspaces service.
type Store interface {
	TxStore
	GetWorkspaceDetailsByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceDetailsRow, error)
	RunInTx(ctx context.Context, fn func(tx TxStore) error) error
}

type persistenceStoreAdapter struct {
	*persistence.Store
}

// NewStoreAdapter wraps *persistence.Store to satisfy workspaces.Store.
func NewStoreAdapter(store *persistence.Store) Store {
	return &persistenceStoreAdapter{Store: store}
}

func (a *persistenceStoreAdapter) RunInTx(ctx context.Context, fn func(tx TxStore) error) error {
	return a.Store.WithTx(ctx, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}

// OwnerRef identifies the accountable human owner of a workspace.
type OwnerRef struct {
	PrincipalID      uuid.UUID `json:"principal_id"`
	IdentityProvider string    `json:"identity_provider"`
	DisplayName      string    `json:"display_name,omitempty"`
}

// WorkspaceDetails enriches domain.Workspace with OpenAPI-required source options, agent type, repository, and owner info.
type WorkspaceDetails struct {
	domain.Workspace
	SourceOptions      domain.SourceOptions `json:"source_options"`
	AgentType          string               `json:"agent_type,omitempty"`
	GitHubRepositoryID int64                `json:"github_repository_id"`
	RepositoryFullName string               `json:"repository_full_name"`
	Owner              OwnerRef             `json:"owner"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

// CreateInput defines parameters for atomic workspace creation.
type CreateInput struct {
	ID             uuid.UUID
	RepositoryID   uuid.UUID
	OwnerID        uuid.UUID
	AgentID        *uuid.UUID
	AgentType      string
	AgentSessionID string
	ModelRoute     string
	BaseCommit     string
	TargetRef      string
	SourceOptions  domain.SourceOptions
}

// CreateResult returns the newly created workspace and its initial WORKSPACE_INGRESS operation.
type CreateResult struct {
	Workspace     domain.Workspace            `json:"workspace"`
	Operation     operations.OperationDetails `json:"operation"`
	SourceOptions domain.SourceOptions        `json:"source_options"`
	AgentType     string                      `json:"agent_type,omitempty"`
}

// Service manages workspace creation and lifecycle transitions.
type Service struct {
	store   Store
	metrics *observability.Metrics
	logger  *slog.Logger
}

// NewService constructs a workspaces Service backed by *persistence.Store.
func NewService(store *persistence.Store, metrics *observability.Metrics, logger *slog.Logger) *Service {
	var adapter Store
	if store != nil {
		adapter = NewStoreAdapter(store)
	}
	return &Service{
		store:   adapter,
		metrics: metrics,
		logger:  logger,
	}
}

// NewServiceWithStore constructs a workspaces Service with a custom Store implementation.
func NewServiceWithStore(store Store, metrics *observability.Metrics, logger *slog.Logger) *Service {
	return &Service{
		store:   store,
		metrics: metrics,
		logger:  logger,
	}
}

// Create atomically verifies repository and owner principal, creates a generation-1 workspace,
// enqueues a WORKSPACE_INGRESS operation, emits an outbox event, and appends a hash-chained audit event.
func (s *Service) Create(ctx context.Context, input CreateInput) (CreateResult, error) {
	if s.store == nil {
		return CreateResult{}, domain.Unavailable("WORKSPACES_UNAVAILABLE", "workspace store is not configured")
	}
	if input.RepositoryID == uuid.Nil {
		return CreateResult{}, domain.BadRequest("INVALID_REPOSITORY_ID", "repository_id must not be nil")
	}
	if input.OwnerID == uuid.Nil {
		return CreateResult{}, domain.BadRequest("INVALID_OWNER_ID", "owner_id must not be nil")
	}
	baseCommit, err := domain.ParseGitSHA(input.BaseCommit)
	if err != nil {
		return CreateResult{}, err
	}
	targetRef := strings.TrimSpace(input.TargetRef)
	if targetRef == "" {
		return CreateResult{}, domain.BadRequest("INVALID_TARGET_REF", "target_ref must not be empty")
	}
	if input.AgentID != nil && *input.AgentID == uuid.Nil {
		return CreateResult{}, domain.BadRequest("INVALID_AGENT_ID", "agent_id must not be nil UUID when provided")
	}

	wsID := input.ID
	if wsID == uuid.Nil {
		wsID, err = domain.NewID()
		if err != nil {
			return CreateResult{}, err
		}
	} else if !domain.IsUUIDv7(wsID) {
		return CreateResult{}, domain.BadRequest("INVALID_ID", "workspace id must be UUIDv7")
	}

	var result CreateResult
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		repoRow, err := tx.GetRepositoryByID(ctx, input.RepositoryID)
		if err != nil {
			return err
		}
		repoRec := repositories.Record{
			Repository:              repoRow.ToDomain(),
			AllowedModelRoutes:      repoRow.AllowedModelRoutes,
			MaxConcurrentOperations: repoRow.MaxConcurrentOperations,
			CreatedAt:               repoRow.CreatedAt,
		}
		if err := repositories.ValidateRecord(repoRec, strings.TrimSpace(input.ModelRoute)); err != nil {
			return err
		}

		ownerRow, err := tx.GetPrincipalByID(ctx, input.OwnerID)
		if err != nil {
			return err
		}
		if ownerRow.Kind != domain.PrincipalKindHuman {
			return domain.Forbidden("INVALID_OWNER_PRINCIPAL", "workspace owner must be a HUMAN principal")
		}

		if input.AgentID != nil {
			if _, err := tx.GetPrincipalByID(ctx, *input.AgentID); err != nil {
				return err
			}
		}

		wsRow, err := tx.CreateWorkspace(ctx, persistence.CreateWorkspaceParams{
			ID:                 wsID,
			RepositoryID:       input.RepositoryID,
			OwnerID:            input.OwnerID,
			AgentID:            input.AgentID,
			AgentType:          strings.TrimSpace(input.AgentType),
			AgentSessionID:     strings.TrimSpace(input.AgentSessionID),
			ModelRoute:         strings.TrimSpace(input.ModelRoute),
			BaseCommit:         baseCommit,
			TargetRef:          targetRef,
			IncludeGitMetadata: input.SourceOptions.IncludeGitMetadata,
			IncludeHistory:     input.SourceOptions.IncludeHistory,
			Generation:         1,
			Status:             domain.WorkspaceStatusPending,
		})
		if err != nil {
			return err
		}

		op, err := operations.EnqueueTx(ctx, tx, operations.EnqueueInput{
			OperationType: domain.OperationTypeWorkspaceIngress,
			ResourceType:  "workspace",
			ResourceID:    wsRow.ID,
		}, s.metrics, s.logger)
		if err != nil {
			return err
		}

		eventPayload, err := domain.CanonicalJSONBytes(map[string]any{
			"workspace_id":         wsRow.ID.String(),
			"repository_id":        wsRow.RepositoryID.String(),
			"owner_id":             wsRow.OwnerID.String(),
			"operation_id":         op.ID.String(),
			"base_commit":          wsRow.BaseCommit,
			"target_ref":           wsRow.TargetRef,
			"generation":           wsRow.Generation,
			"include_git_metadata": wsRow.IncludeGitMetadata,
			"include_history":      wsRow.IncludeHistory,
		})
		if err != nil {
			return err
		}

		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "workspace.created",
			AggregateID: wsRow.ID,
			Payload:     json.RawMessage(eventPayload),
		}); err != nil {
			return err
		}

		actorID := input.OwnerID
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "workspace.created",
			ActorID:      &actorID,
			ResourceType: "workspace",
			ResourceID:   wsRow.ID,
			Payload:      json.RawMessage(eventPayload),
		}, s.logger); err != nil {
			return err
		}

		result = CreateResult{
			Workspace: wsRow.ToDomain(),
			Operation: op,
			SourceOptions: domain.SourceOptions{
				IncludeGitMetadata: wsRow.IncludeGitMetadata,
				IncludeHistory:     wsRow.IncludeHistory,
			},
			AgentType: derefString(wsRow.AgentType),
		}
		return nil
	})
	if err != nil {
		return CreateResult{}, err
	}

	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.InfoContext(ctx, "workspace created",
			"workspace_id", result.Workspace.ID.String(),
			"repository_id", result.Workspace.RepositoryID.String(),
			"owner_id", result.Workspace.OwnerID.String(),
			"operation_id", result.Operation.ID.String(),
			"generation", result.Workspace.Generation,
			"status", string(result.Workspace.Status),
		)
	}

	return result, nil
}

// Get retrieves the domain.Workspace by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (domain.Workspace, error) {
	if s.store == nil {
		return domain.Workspace{}, domain.Unavailable("WORKSPACES_UNAVAILABLE", "workspace store is not configured")
	}
	row, err := s.store.GetWorkspaceByID(ctx, id)
	if err != nil {
		return domain.Workspace{}, err
	}
	return row.ToDomain(), nil
}

// GetDetails retrieves workspace details joined with repository and owner principal info.
func (s *Service) GetDetails(ctx context.Context, id uuid.UUID) (WorkspaceDetails, error) {
	if s.store == nil {
		return WorkspaceDetails{}, domain.Unavailable("WORKSPACES_UNAVAILABLE", "workspace store is not configured")
	}
	row, err := s.store.GetWorkspaceDetailsByID(ctx, id)
	if err != nil {
		return WorkspaceDetails{}, err
	}
	return WorkspaceDetails{
		Workspace: row.Workspace.ToDomain(),
		SourceOptions: domain.SourceOptions{
			IncludeGitMetadata: row.Workspace.IncludeGitMetadata,
			IncludeHistory:     row.Workspace.IncludeHistory,
		},
		AgentType:          derefString(row.Workspace.AgentType),
		GitHubRepositoryID: row.GitHubRepositoryID,
		RepositoryFullName: row.RepositoryFullName,
		Owner: OwnerRef{
			PrincipalID:      row.Workspace.OwnerID,
			IdentityProvider: derefString(row.OwnerIssuer),
			DisplayName:      derefString(row.OwnerDisplayName),
		},
		UpdatedAt: row.Workspace.UpdatedAt.UTC(),
	}, nil
}

// TransitionStatus atomically transitions a workspace from fromStatus to toStatus and logs an audit event.
func (s *Service) TransitionStatus(ctx context.Context, id uuid.UUID, fromStatus, toStatus domain.WorkspaceStatus) (domain.Workspace, error) {
	if s == nil || s.store == nil {
		return domain.Workspace{}, domain.Unavailable("WORKSPACES_UNAVAILABLE", "workspace store is not configured")
	}
	if !fromStatus.IsValid() || !toStatus.IsValid() {
		return domain.Workspace{}, domain.BadRequest("INVALID_WORKSPACE_STATUS", "invalid workspace status")
	}
	if !isAllowedWorkspaceTransition(fromStatus, toStatus) {
		return domain.Workspace{}, domain.Conflict("INVALID_STATE_TRANSITION", "workspace status transition is not allowed")
	}

	var updated domain.Workspace
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		now := time.Now().UTC().Truncate(time.Microsecond)
		row, err := tx.TransitionWorkspaceStatus(ctx, id, fromStatus, toStatus, now)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				if _, lookupErr := tx.GetWorkspaceByID(ctx, id); lookupErr == nil {
					return domain.Conflict("WORKSPACE_STATE_CONFLICT", "workspace status changed concurrently")
				}
			}
			return err
		}

		payload, err := domain.CanonicalJSONBytes(map[string]any{
			"workspace_id": id.String(),
			"from_status":  string(fromStatus),
			"to_status":    string(toStatus),
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "workspace.status_transitioned",
			ResourceType: "workspace",
			ResourceID:   id,
			Payload:      json.RawMessage(payload),
		}, s.logger); err != nil {
			return err
		}

		updated = row.ToDomain()
		return nil
	})
	return updated, err
}

// AttachSourceArtifact attaches a WORKSPACE_SOURCE artifact to the workspace and sets its status (default READY).
func (s *Service) AttachSourceArtifact(ctx context.Context, workspaceID, artifactID uuid.UUID, status domain.WorkspaceStatus) (domain.Workspace, error) {
	if s == nil || s.store == nil {
		return domain.Workspace{}, domain.Unavailable("WORKSPACES_UNAVAILABLE", "workspace store is not configured")
	}
	if status == "" {
		status = domain.WorkspaceStatusReady
	}
	if !status.IsValid() {
		return domain.Workspace{}, domain.BadRequest("INVALID_WORKSPACE_STATUS", "invalid workspace status")
	}
	if status != domain.WorkspaceStatusReady {
		return domain.Workspace{}, domain.BadRequest("INVALID_WORKSPACE_STATUS", "attaching source artifact must transition workspace to READY")
	}

	var updated domain.Workspace
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		wsRow, err := tx.GetWorkspaceByID(ctx, workspaceID)
		if err != nil {
			return err
		}
		if wsRow.Status != domain.WorkspaceStatusPending && wsRow.Status != domain.WorkspaceStatusPreparing {
			return domain.Conflict("WORKSPACE_STATE_CONFLICT", "workspace must be PENDING or PREPARING to attach source artifact")
		}
		if wsRow.SourceArtifactID != nil {
			return domain.Conflict("SOURCE_ARTIFACT_ALREADY_ATTACHED", "workspace already has a source artifact attached")
		}
		artRow, err := tx.GetArtifactByID(ctx, artifactID)
		if err != nil {
			return err
		}
		if artRow.Kind != domain.ArtifactKindWorkspaceSource {
			return domain.BadRequest("INVALID_ARTIFACT_KIND", "source artifact must have kind WORKSPACE_SOURCE")
		}
		if artRow.WorkspaceID != nil && *artRow.WorkspaceID != workspaceID {
			return domain.Conflict("ARTIFACT_WORKSPACE_MISMATCH", "source artifact belongs to a different workspace")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		row, err := tx.AttachWorkspaceSourceArtifact(ctx, workspaceID, artifactID, status, now)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				if _, lookupErr := tx.GetWorkspaceByID(ctx, workspaceID); lookupErr == nil {
					return domain.Conflict("WORKSPACE_STATE_CONFLICT", "workspace state changed concurrently")
				}
			}
			return err
		}

		payload, err := domain.CanonicalJSONBytes(map[string]any{
			"workspace_id":       workspaceID.String(),
			"source_artifact_id": artifactID.String(),
			"status":             string(status),
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "workspace.source_attached",
			ResourceType: "workspace",
			ResourceID:   workspaceID,
			Payload:      json.RawMessage(payload),
		}, s.logger); err != nil {
			return err
		}

		updated = row.ToDomain()
		return nil
	})
	return updated, err
}

func isAllowedWorkspaceTransition(from, to domain.WorkspaceStatus) bool {
	if !from.IsValid() || !to.IsValid() || from.IsTerminal() || from == to {
		return false
	}
	switch from {
	case domain.WorkspaceStatusPending:
		return to == domain.WorkspaceStatusPreparing || to == domain.WorkspaceStatusReady || to == domain.WorkspaceStatusFailed || to == domain.WorkspaceStatusClosed
	case domain.WorkspaceStatusPreparing:
		return to == domain.WorkspaceStatusReady || to == domain.WorkspaceStatusFailed || to == domain.WorkspaceStatusClosed
	case domain.WorkspaceStatusReady:
		return to == domain.WorkspaceStatusFailed || to == domain.WorkspaceStatusClosed
	default:
		return false
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
