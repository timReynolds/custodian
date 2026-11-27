package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
)

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("DATABASE_UNAVAILABLE", "persistence store is not initialized"))
		return
	}
	ctx, cancel := s.withDBTimeout(r.Context())
	defer cancel()
	if err := s.deps.Store.Ping(ctx); err != nil {
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrUnavailable, "DATABASE_UNAVAILABLE", "database is not ready", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.deps.Metrics == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("METRICS_UNAVAILABLE", "metrics registry is not configured"))
		return
	}
	s.deps.Metrics.Handler().ServeHTTP(w, r)
}

func (s *server) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Operations == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "operations service is not configured"))
		return
	}

	opID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()

	op, err := s.deps.Operations.GetDetails(dbCtx, opID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}

	if !caller.IsController() {
		ownerID, err := s.resolveOperationOwnerID(dbCtx, op.ResourceType, op.ResourceID)
		if err != nil {
			writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
			return
		}
		if caller.Principal.ID != ownerID {
			writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view this operation"))
			return
		}
	}

	writeJSON(w, http.StatusOK, toOperationDTO(op))
}

func (s *server) resolveOperationOwnerID(ctx context.Context, resourceType string, resourceID uuid.UUID) (uuid.UUID, error) {
	rt := strings.ToLower(strings.TrimSpace(resourceType))
	switch rt {
	case "workspace":
		if s.deps.Workspaces == nil {
			return uuid.Nil, domain.Unavailable("SERVICE_UNAVAILABLE", "workspace service is not configured")
		}
		ws, err := s.deps.Workspaces.Get(ctx, resourceID)
		if err != nil {
			return uuid.Nil, err
		}
		return ws.OwnerID, nil
	case "proposal":
		if s.deps.Proposals == nil {
			return uuid.Nil, domain.Unavailable("SERVICE_UNAVAILABLE", "proposals service is not configured")
		}
		prop, err := s.deps.Proposals.Get(ctx, resourceID)
		if err != nil {
			return uuid.Nil, err
		}
		return prop.OwnerID, nil
	case "publication":
		if s.deps.Store == nil || s.deps.Proposals == nil {
			return uuid.Nil, domain.Unavailable("SERVICE_UNAVAILABLE", "publication store is not configured")
		}
		pub, err := s.deps.Store.GetPublicationByID(ctx, resourceID)
		if err != nil {
			return uuid.Nil, err
		}
		prop, err := s.deps.Proposals.Get(ctx, pub.ProposalID)
		if err != nil {
			return uuid.Nil, err
		}
		return prop.OwnerID, nil
	default:
		if s.deps.Workspaces != nil {
			if ws, err := s.deps.Workspaces.Get(ctx, resourceID); err == nil {
				return ws.OwnerID, nil
			} else if !errors.Is(err, domain.ErrNotFound) {
				return uuid.Nil, err
			}
		}
		if s.deps.Proposals != nil {
			if prop, err := s.deps.Proposals.Get(ctx, resourceID); err == nil {
				return prop.OwnerID, nil
			} else if !errors.Is(err, domain.ErrNotFound) {
				return uuid.Nil, err
			}
		}
		if s.deps.Store != nil && s.deps.Proposals != nil {
			if pub, err := s.deps.Store.GetPublicationByID(ctx, resourceID); err == nil {
				prop, err := s.deps.Proposals.Get(ctx, pub.ProposalID)
				if err != nil {
					return uuid.Nil, err
				}
				return prop.OwnerID, nil
			} else if !errors.Is(err, domain.ErrNotFound) {
				return uuid.Nil, err
			}
		}
		return uuid.Nil, domain.NotFound("OPERATION_RESOURCE_NOT_FOUND", "operation resource not found")
	}
}

func (s *server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsAuditor() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("AUDITOR_REQUIRED", "only AUDITOR principals may query audit events"))
		return
	}
	if s.deps.Audit == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "audit service is not configured"))
		return
	}

	q := r.URL.Query()
	filter := audit.ListFilter{
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		EventType:    strings.TrimSpace(q.Get("event_type")),
		Cursor:       strings.TrimSpace(q.Get("cursor")),
		Limit:        50,
	}

	if rawResID := strings.TrimSpace(q.Get("resource_id")); rawResID != "" {
		id, err := parseUUIDv7(rawResID)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_RESOURCE_ID", "resource_id must be a valid UUIDv7"))
			return
		}
		filter.ResourceID = &id
	}

	if rawActorID := strings.TrimSpace(q.Get("actor_id")); rawActorID != "" {
		id, err := parseUUIDv7(rawActorID)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must be a valid UUIDv7"))
			return
		}
		filter.ActorID = &id
	}

	if rawSince := strings.TrimSpace(q.Get("since")); rawSince != "" {
		t, err := time.Parse(time.RFC3339Nano, rawSince)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_SINCE", "since must be valid RFC3339 date-time"))
			return
		}
		utc := t.UTC()
		filter.Since = &utc
	}

	if rawUntil := strings.TrimSpace(q.Get("until")); rawUntil != "" {
		t, err := time.Parse(time.RFC3339Nano, rawUntil)
		if err != nil {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_UNTIL", "until must be valid RFC3339 date-time"))
			return
		}
		utc := t.UTC()
		filter.Until = &utc
	}

	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		v, err := strconv.Atoi(rawLimit)
		if err != nil || v < 1 || v > 500 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_LIMIT", "limit must be an integer between 1 and 500"))
			return
		}
		filter.Limit = v
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()
	res, err := s.deps.Audit.List(dbCtx, filter)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}

	events := make([]AuditEventDTO, 0, len(res.Events))
	for _, ev := range res.Events {
		events = append(events, toAuditEventDTO(ev))
	}

	writeJSON(w, http.StatusOK, AuditEventsListResponse{
		Events:     events,
		NextCursor: optString(res.NextCursor),
		HasMore:    res.HasMore,
	})
}
