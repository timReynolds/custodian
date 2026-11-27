package api

import (
	"context"
	"net/http"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/proposals"
)

func (s *server) handleCreateApproval(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !isRegularHuman(caller) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("NON_HUMAN_REVIEWER", "only HUMAN principals may approve or reject proposals"))
		return
	}
	if s.deps.Approvals == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "approvals service is not configured"))
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

	var req CreateApprovalRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	decision := domain.ApprovalDecision(req.Decision)
	if !decision.IsValid() {
		writeError(w, r, s.deps.Logger, domain.BadRequest("INVALID_APPROVAL_DECISION", "decision must be APPROVE or REJECT"))
		return
	}
	manifestDigest, err := domain.ParseSHA256Digest(req.PublicationManifestDigest)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	policyEvalID, err := parseUUIDv7(req.PolicyEvaluationID)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}
	var comment string
	if req.Comment != nil {
		if utf8.RuneCountInString(*req.Comment) > 4096 {
			writeError(w, r, s.deps.Logger, domain.BadRequest("COMMENT_TOO_LONG", "comment must not exceed 4096 characters"))
			return
		}
		comment = *req.Comment
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		dbCtx, cancel := s.withDBTimeout(r.Context())
		defer cancel()
		res, err := s.deps.Approvals.Submit(dbCtx, approvals.SubmitInput{
			ProposalID:         propID,
			ReviewerID:         caller.Principal.ID,
			ReviewerKind:       caller.Principal.Kind,
			ReviewerGroups:     caller.Claims.Groups,
			Decision:           decision,
			ManifestDigest:     manifestDigest,
			PolicyEvaluationID: policyEvalID,
			Comment:            comment,
		})
		if err != nil {
			return 0, nil, mapDBTimeoutError(dbCtx, err)
		}
		return http.StatusCreated, toApprovalResponse(res), nil
	})
}

func (s *server) handlePublishProposal(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if !caller.IsController() {
		writeError(w, r, s.deps.Logger, domain.Forbidden("CONTROLLER_REQUIRED", "only CONTROLLER principals may trigger proposal publication"))
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

	var req PublishProposalRequest
	if err := decodeStrictJSONBytes(rawBody, &req, false); err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	manifestDigest, err := domain.ParseSHA256Digest(req.PublicationManifestDigest)
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	s.runIdempotent(w, r, caller, idemKey, rawBody, func() (int, any, error) {
		ctx := r.Context()
		actorID := caller.Principal.ID
		publishFn := func(dbCtx context.Context) (proposals.PublishRequestResult, error) {
			r, err := s.deps.Proposals.RequestPublish(dbCtx, proposals.PublishRequestInput{
				ProposalID:                propID,
				PublicationManifestDigest: manifestDigest,
				ActorID:                   &actorID,
			})
			return r, mapDBTimeoutError(dbCtx, err)
		}

		var res proposals.PublishRequestResult
		var repoID uuid.UUID
		var repoMaxConc int
		if s.deps.Store != nil {
			lookupCtx, lookupCancel := s.withDBTimeout(ctx)
			if prop, propErr := s.deps.Proposals.GetDetails(lookupCtx, propID); propErr == nil && prop.Status == domain.ProposalStatusApproved {
				if repoRow, repoErr := s.deps.Store.GetRepositoryByID(lookupCtx, prop.RepositoryID); repoErr == nil {
					repoID = repoRow.ID
					repoMaxConc = repoRow.MaxConcurrentOperations
				}
			}
			lookupCancel()
		}

		if repoID != uuid.Nil {
			if err := s.withRepoConcurrencyLimit(ctx, repoID, repoMaxConc, func(dbCtx context.Context) error {
				r, err := publishFn(dbCtx)
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
			res, err = publishFn(dbCtx)
			cancel()
			if err != nil {
				return 0, nil, err
			}
		}

		var commitSHA *string
		if domain.IsValidGitSHA(res.Publication.CommitSHA) {
			s := res.Publication.CommitSHA
			commitSHA = &s
		}

		return http.StatusAccepted, PublishProposalResponse{
			PublicationID:     res.Publication.ID.String(),
			ProposalID:        res.Proposal.ID.String(),
			OperationID:       res.Operation.ID.String(),
			BranchRef:         domain.ExpectedBranchName(res.Proposal.ID),
			Status:            string(res.Publication.Status),
			CommitSHA:         commitSHA,
			PullRequestNumber: res.Publication.PullRequestNumber,
			PullRequestURL:    optString(res.Publication.PullRequestURL),
			CreatedAt:         formatTimestamp(res.Publication.CreatedAt),
		}, nil
	})
}

func (s *server) handleGetPublication(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, r, s.deps.Logger, domain.Unauthorized("UNAUTHORIZED", "authentication required"))
		return
	}
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("SERVICE_UNAVAILABLE", "persistence store is not configured"))
		return
	}

	pubID, err := parseUUIDv7Param(r, "id")
	if err != nil {
		writeError(w, r, s.deps.Logger, err)
		return
	}

	dbCtx, cancel := s.withDBTimeout(r.Context())
	defer cancel()

	pubRow, err := s.deps.Store.GetPublicationByID(dbCtx, pubID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}

	propRow, err := s.deps.Store.GetProposalByID(dbCtx, pubRow.ProposalID)
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(dbCtx, err))
		return
	}
	if !canReadProposalByOwnerID(caller, propRow.OwnerID) {
		writeError(w, r, s.deps.Logger, domain.Forbidden("FORBIDDEN", "caller is not authorized to view this publication"))
		return
	}

	writeJSON(w, http.StatusOK, toPublicationDTO(pubRow))
}
