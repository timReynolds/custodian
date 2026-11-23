package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func hasHistoryAuthorization(c identity.CallerContext) bool {
	if c.HasRole("history_reader") || c.InGroup("history-readers") {
		return true
	}
	for _, s := range c.Claims.Scopes {
		if strings.EqualFold(strings.TrimSpace(s), "repo:history") {
			return true
		}
	}
	return false
}

func effectiveRepoConcurrencyLimit(globalLimit, repoLimit int) int {
	switch {
	case globalLimit > 0 && repoLimit > 0:
		if globalLimit < repoLimit {
			return globalLimit
		}
		return repoLimit
	case globalLimit > 0:
		return globalLimit
	case repoLimit > 0:
		return repoLimit
	default:
		return 0
	}
}

func (s *server) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isRegularHuman(caller) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("HUMAN_CALLER_REQUIRED", "only verified HUMAN principals may create workspaces"))
		return
	}
	if s.deps.Directory == nil || s.deps.Repositories == nil || s.deps.Workspaces == nil || s.deps.GitHubRead == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "workspace dependencies are not configured"))
		return
	}

	ownerCtx, ownerCancel := s.withDBTimeout(r.Context())
	owner, err := s.deps.Directory.ResolveOwner(ownerCtx, caller.Claims)
	ownerCancel()
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(ownerCtx, err))
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

	var req CreateWorkspaceRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	if err := validateCreateWorkspaceRequest(req); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		ctx := r.Context()

		var modelRoute string
		if req.Agent != nil {
			modelRoute = strings.TrimSpace(req.Agent.ModelRoute)
		}
		authCtx, authCancel := s.withDBTimeout(ctx)
		repoRec, err := s.deps.Repositories.AuthorizeByGitHubID(authCtx, req.Repository.RepositoryID, modelRoute)
		authCancel()
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return 0, nil, domain.Forbidden("REPOSITORY_NOT_ENTITLED", "repository is not registered or authorized")
			}
			return 0, nil, mapDBTimeoutError(authCtx, err)
		}

		var srcOpts domain.SourceOptions
		if req.SourceOptions != nil {
			srcOpts = domain.SourceOptions{
				IncludeGitMetadata: req.SourceOptions.IncludeGitMetadata,
				IncludeHistory:     req.SourceOptions.IncludeHistory,
			}
		}

		if srcOpts.IncludeHistory && !hasHistoryAuthorization(caller) {
			auditCtx, auditCancel := s.withDBTimeout(ctx)
			s.appendSecurityDenialAudit(auditCtx, &owner.ID, "repository", repoRec.ID, "workspace.history_denied", map[string]any{
				"github_repository_id": repoRec.GitHubRepositoryID,
				"reason":               "missing repo:history scope, history_reader role, or history-readers group",
			})
			auditCancel()
			return 0, nil, domain.Forbidden("HISTORY_ACCESS_FORBIDDEN", "caller is not authorized to request full git history")
		}

		limit := effectiveRepoConcurrencyLimit(s.deps.RepoConcurrencyLimit, repoRec.MaxConcurrentOperations)
		if (limit > 0 || s.deps.GlobalScanBudget > 0) && s.deps.Store != nil {
			cntCtx, cntCancel := s.withDBTimeout(ctx)
			if limit > 0 {
				active, err := s.deps.Store.CountActiveOperationsByRepository(cntCtx, repoRec.ID)
				if err != nil {
					cntCancel()
					return 0, nil, mapDBTimeoutError(cntCtx, err)
				}
				if active >= int64(limit) {
					cntCancel()
					return 0, nil, domain.RateLimited("REPO_CONCURRENCY_LIMIT_EXCEEDED", "repository active operations limit exceeded")
				}
			}
			if err := s.checkGlobalScanBudget(cntCtx); err != nil {
				cntCancel()
				return 0, nil, err
			}
			cntCancel()
		}

		ref := strings.TrimSpace(req.Repository.Ref)
		baseCommit, err := s.deps.GitHubRead.ResolveRef(ctx, repoRec.Repository, ref)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return 0, nil, domain.WrapError(domain.ErrUnprocessable, "INVALID_GIT_REF", "requested git ref was not found", err)
			}
			return 0, nil, err
		}

		var agentID *uuid.UUID
		var agentType, agentSessionID string
		if req.Agent != nil {
			agentCtx, agentCancel := s.withDBTimeout(ctx)
			agentPrincipal, err := s.deps.Directory.ResolveAgentPrincipal(agentCtx, req.Agent.Type)
			agentCancel()
			if err != nil {
				return 0, nil, mapDBTimeoutError(agentCtx, err)
			}
			idCopy := agentPrincipal.ID
			agentID = &idCopy
			agentType = strings.TrimSpace(req.Agent.Type)
			agentSessionID = strings.TrimSpace(req.Agent.SessionID)
		}

		createWS := func(dbCtx context.Context) (workspaces.CreateResult, error) {
			res, err := s.deps.Workspaces.Create(dbCtx, workspaces.CreateInput{
				RepositoryID:   repoRec.ID,
				OwnerID:        owner.ID,
				AgentID:        agentID,
				AgentType:      agentType,
				AgentSessionID: agentSessionID,
				ModelRoute:     modelRoute,
				BaseCommit:     baseCommit,
				TargetRef:      ref,
				SourceOptions:  srcOpts,
			})
			return res, mapDBTimeoutError(dbCtx, err)
		}

		var created workspaces.CreateResult
		if err := s.withRepoConcurrencyLimit(ctx, repoRec.ID, repoRec.MaxConcurrentOperations, func(repoDBCtx context.Context) error {
			if s.deps.GlobalScanBudget > 0 && s.deps.Store != nil {
				return s.withEvalBudgetLock(ctx, func() error {
					dbCtx, dbCancel := s.withDBTimeout(ctx)
					defer dbCancel()
					if err := s.checkGlobalScanBudget(dbCtx); err != nil {
						return err
					}
					res, err := createWS(dbCtx)
					if err != nil {
						return err
					}
					created = res
					return nil
				})
			}
			res, err := createWS(repoDBCtx)
			if err != nil {
				return err
			}
			created = res
			return nil
		}); err != nil {
			return 0, nil, err
		}

		resp := CreateWorkspaceResponse{
			WorkspaceID:  created.Workspace.ID.String(),
			RepositoryID: created.Workspace.RepositoryID.String(),
			OwnerID:      created.Workspace.OwnerID.String(),
			BaseCommit:   strings.ToLower(created.Workspace.BaseCommit),
			TargetRef:    created.Workspace.TargetRef,
			Status:       string(created.Workspace.Status),
			Generation:   created.Workspace.Generation,
			OperationID:  created.Operation.ID.String(),
			CreatedAt:    formatTimestamp(created.Workspace.CreatedAt),
		}
		return http.StatusAccepted, resp, nil
	})
}

func validateCreateWorkspaceRequest(req CreateWorkspaceRequest) error {
	if req.Repository == nil {
		return domain.BadRequest("INVALID_WORKSPACE_REQUEST", "repository is required")
	}
	if req.Repository.Provider != "github" {
		return domain.BadRequest("UNSUPPORTED_PROVIDER", "repository.provider must be \"github\"")
	}
	if req.Repository.RepositoryID < 1 {
		return domain.BadRequest("INVALID_REPOSITORY_ID", "repository.repository_id must be >= 1")
	}
	if utf8.RuneCountInString(req.Repository.Ref) > 256 || len(strings.TrimSpace(req.Repository.Ref)) < 1 {
		return domain.BadRequest("INVALID_REF", "repository.ref must be between 1 and 256 characters")
	}
	if req.Agent != nil {
		if utf8.RuneCountInString(req.Agent.Type) > 128 || len(strings.TrimSpace(req.Agent.Type)) < 1 {
			return domain.BadRequest("INVALID_AGENT", "agent.type must be between 1 and 128 characters")
		}
		if utf8.RuneCountInString(req.Agent.SessionID) > 256 || len(strings.TrimSpace(req.Agent.SessionID)) < 1 {
			return domain.BadRequest("INVALID_AGENT", "agent.session_id must be between 1 and 256 characters")
		}
		if utf8.RuneCountInString(req.Agent.ModelRoute) > 128 || len(strings.TrimSpace(req.Agent.ModelRoute)) < 1 {
			return domain.BadRequest("INVALID_AGENT", "agent.model_route must be between 1 and 128 characters")
		}
	}
	return nil
}

func (s *server) appendSecurityDenialAudit(ctx context.Context, actorID *uuid.UUID, resourceType string, resourceID uuid.UUID, eventType string, fields map[string]any) {
	if s.deps.Audit == nil || resourceID == uuid.Nil {
		return
	}
	raw, err := domain.CanonicalJSONBytes(fields)
	if err != nil {
		raw = []byte("{}")
	}
	_, _ = s.deps.Audit.Append(ctx, audit.AppendInput{
		EventType:    eventType,
		ActorID:      actorID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Payload:      json.RawMessage(raw),
	})
}

func (s *server) handleGetWorkspace(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Workspaces == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "workspace service is not configured"))
		return
	}
	wsID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()
	details, err := s.deps.Workspaces.GetDetails(dbCtx, wsID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !caller.IsController() && caller.Principal.ID != details.OwnerID {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view this workspace"))
		return
	}

	writeJSON(w, http.StatusOK, toWorkspaceDTO(details))
}

func (s *server) handleGetWorkspaceSource(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsController() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("CONTROLLER_REQUIRED", "only CONTROLLER principals may access workspace source descriptors"))
		return
	}
	if s.deps.Workspaces == nil || s.deps.Artifacts == nil || s.deps.Capabilities == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "source descriptor dependencies are not configured"))
		return
	}

	wsID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()

	ws, err := s.deps.Workspaces.GetDetails(dbCtx, wsID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if ws.Status != domain.WorkspaceStatusReady || ws.SourceArtifactID == nil {
		writeError(w, r, s.deps.Logger, domain.Conflict("WORKSPACE_NOT_READY", "workspace source artifact is not ready"))
		return
	}

	art, err := s.deps.Artifacts.GetByID(dbCtx, *ws.SourceArtifactID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if art.DeletedAt != nil {
		writeError(w, r, s.deps.Logger, domain.Conflict("ARTIFACT_DELETED", "workspace source artifact has been deleted"))
		return
	}

	now := time.Now().UTC()
	capExpiresAt := now.Add(s.deps.CapabilityTTL)
	objID := domain.MustNewID()
	objectKey := fmt.Sprintf("workspaces/%s/gen-%d/egress/%s.tar.gz", ws.ID.String(), ws.Generation, objID.String())

	token, err := s.deps.Capabilities.IssueUpload(r.Context(), domain.SnapshotCapability{
		WorkspaceID: ws.ID,
		Generation:  ws.Generation,
		ObjectKey:   objectKey,
		MaxBytes:    s.deps.MaxUploadBytes,
		UploadOnly:  true,
		IssuedTo:    caller.Principal.ID,
		Provenance:  caller.Claims.Subject,
		IssuedAt:    now,
		ExpiresAt:   capExpiresAt,
	})
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	baseURL := requestBaseURL(r, s.deps.BaseURL)
	downloadURL := fmt.Sprintf("%s/v1/workspaces/%s/source/artifact", baseURL, ws.ID.String())
	uploadURL := fmt.Sprintf("%s/v1/uploads/workspaces/%s/generations/%d/%s", baseURL, ws.ID.String(), ws.Generation, objectKey)

	resp := SourceArtifactDescriptorDTO{
		WorkspaceID: ws.ID.String(),
		Generation:  ws.Generation,
		BaseCommit:  strings.ToLower(ws.BaseCommit),
		Artifact:    toArtifactRefDTO(art),
		Download: DownloadDescriptorDTO{
			Method:    http.MethodGet,
			URL:       downloadURL,
			ExpiresAt: formatTimestamp(capExpiresAt),
		},
		SourceOptions: SourceOptionsDTO{
			IncludeGitMetadata: ws.SourceOptions.IncludeGitMetadata,
			IncludeHistory:     ws.SourceOptions.IncludeHistory,
		},
		UploadCapability: &UploadCapabilityDTO{
			Token:       token,
			WorkspaceID: ws.ID.String(),
			Generation:  ws.Generation,
			MaxBytes:    s.deps.MaxUploadBytes,
			ExpiresAt:   formatTimestamp(capExpiresAt),
			UploadURL:   uploadURL,
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleDownloadWorkspaceSourceArtifact(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsController() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("CONTROLLER_REQUIRED", "only CONTROLLER principals may download workspace source artifacts"))
		return
	}
	if s.deps.Workspaces == nil || s.deps.Artifacts == nil || s.deps.Snapshots == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "snapshot download dependencies are not configured"))
		return
	}

	wsID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	ws, err := s.deps.Workspaces.Get(dbCtx, wsID)
	cancel()
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if ws.Status != domain.WorkspaceStatusReady || ws.SourceArtifactID == nil {
		writeError(w, r, s.deps.Logger, domain.Conflict("WORKSPACE_NOT_READY", "workspace source artifact is not ready"))
		return
	}

	artCtx, artCancel := s.withDBTimeout(r.Context())
	art, err := s.deps.Artifacts.GetByID(artCtx, *ws.SourceArtifactID)
	artCancel()
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(artCtx, err))
		return
	}
	if art.DeletedAt != nil {
		writeError(w, r, s.deps.Logger, domain.Conflict("ARTIFACT_DELETED", "workspace source artifact has been deleted"))
		return
	}

	rc, err := s.deps.Snapshots.Open(r.Context(), art.Artifact)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	defer rc.Close()

	// Buffer/verify before writing 200 headers when small or stream directly?
	// Open verifies SHA-256 on EOF, so streaming with Content-Type/Length works cleanly.
	w.Header().Set("Content-Type", "application/gzip")
	if art.SizeBytes >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(art.SizeBytes, 10))
	}
	w.Header().Set("X-Content-SHA256", normalizeHex64(art.SHA256))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}
