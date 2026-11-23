package publication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/publish"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultTxCleanupTimeout = 5 * time.Second
	maxSafeErrorLen         = 512
)

var (
	errURLUserInfoPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+)@`)
	errTokenPatterns      = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}`),
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
		regexp.MustCompile(`x-access-token:[^\s@'"]+`),
		regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`),
	}
)

type (
	runnerFencedKey struct{}

	operationLease struct {
		opID     uuid.UUID
		workerID string
		attempt  int
	}

	postPublishCommitError struct {
		err error
	}
)

func (e *postPublishCommitError) Error() string {
	if e == nil || e.err == nil {
		return "post-publish commit failed"
	}
	return e.err.Error()
}

func (e *postPublishCommitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func withRunnerFenced(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, runnerFencedKey{}, true)
}

func isRunnerFenced(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(runnerFencedKey{}).(bool)
	return v
}

func isPostPublishCommitError(err error) bool {
	var target *postPublishCommitError
	return errors.As(err, &target)
}

func isPublicationInProgressError(err error) bool {
	var domErr *domain.DomainError
	return errors.As(err, &domErr) && domErr.Code() == "PUBLICATION_IN_PROGRESS"
}

func isTxConcurrencyConflict(err error) bool {
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) {
		return false
	}
	switch domErr.Code() {
	case "PROPOSAL_VERSION_CONFLICT",
		"PUBLICATION_STATE_CONFLICT",
		"PUBLICATION_ATTEMPT_STATE_CONFLICT",
		"PUBLICATION_IN_PROGRESS",
		"LEASE_LOST",
		"TX_CONFLICT":
		return true
	default:
		return false
	}
}

func operationDetailsFromRow(row persistence.OperationRow) operations.OperationDetails {
	var completedAt *time.Time
	if row.CompletedAt != nil {
		t := row.CompletedAt.UTC()
		completedAt = &t
	}
	return operations.OperationDetails{
		Operation:    row.ToDomain(),
		ResourceType: derefString(row.ResourceType),
		MaxAttempts:  row.MaxAttempts,
		LeasedBy:     derefString(row.LeasedBy),
		Result:       row.Result,
		UpdatedAt:    row.UpdatedAt.UTC(),
		CompletedAt:  completedAt,
	}
}

// GitPublisher executes the isolated Git commit, force-push check, branch push, and PR creation/update.
type GitPublisher interface {
	PublishRequest(ctx context.Context, req publish.PublishRequest) (domain.PublicationResult, error)
}

// Config configures the isolated publication Service.
type Config struct {
	Store          Store
	GitPublisher   GitPublisher
	WriteClient    write.Client
	ArtifactOpener publish.ArtifactOpener
	CommitterName  string
	CommitterEmail string
	GitBinary      string
	GitTimeout     time.Duration
	Metrics        *observability.Metrics
	Logger         *slog.Logger
	Clock          func() time.Time
}

// OperationPayload carries optional cross-check fields for queued PROPOSAL_PUBLISH operations.
type OperationPayload struct {
	PublicationID             uuid.UUID `json:"publication_id,omitempty"`
	ProposalID                uuid.UUID `json:"proposal_id,omitempty"`
	ManifestDigest            string    `json:"manifest_digest,omitempty"`
	PublicationManifestDigest string    `json:"publication_manifest_digest,omitempty"`
}

// RequestResult is returned by RequestPublication for POST /v1/proposals/{id}/publish.
type RequestResult struct {
	Publication domain.Publication           `json:"publication"`
	Operation   *operations.OperationDetails `json:"operation,omitempty"`
	Idempotent  bool                         `json:"idempotent,omitempty"`
}

// Service implements the 14-step isolated publication orchestrator.
type Service struct {
	store        Store
	gitPublisher GitPublisher
	metrics      *observability.Metrics
	logger       *slog.Logger
	clock        func() time.Time
}

var (
	_ domain.Publisher    = (*Service)(nil)
	_ publish.InputLoader = (*Service)(nil)
)

// NewService constructs a publication Service from a *persistence.Store and *publish.Service.
func NewService(store *persistence.Store, gitPub *publish.Service, metrics *observability.Metrics, logger *slog.Logger) (*Service, error) {
	return NewServiceWithConfig(Config{
		Store:        NewStoreAdapter(store),
		GitPublisher: gitPub,
		Metrics:      metrics,
		Logger:       logger,
	})
}

// NewServiceWithConfig constructs a publication Service from Config.
func NewServiceWithConfig(cfg Config) (*Service, error) {
	gitPub := cfg.GitPublisher
	if gitPub == nil && cfg.WriteClient != nil {
		svc, err := publish.NewService(publish.Config{
			GitBinary:      cfg.GitBinary,
			Timeout:        cfg.GitTimeout,
			WriteClient:    cfg.WriteClient,
			ArtifactOpener: cfg.ArtifactOpener,
			CommitterName:  cfg.CommitterName,
			CommitterEmail: cfg.CommitterEmail,
			Logger:         cfg.Logger,
			Metrics:        cfg.Metrics,
		})
		if err != nil {
			return nil, err
		}
		gitPub = svc
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Service{
		store:        cfg.Store,
		gitPublisher: gitPub,
		metrics:      cfg.Metrics,
		logger:       cfg.Logger,
		clock:        clock,
	}, nil
}

func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

// ParseOperationPayload decodes optional operation/outbox JSON metadata and validates digests.
func ParseOperationPayload(raw json.RawMessage) (OperationPayload, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return OperationPayload{}, nil
	}
	var payload OperationPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return OperationPayload{}, domain.WrapError(domain.ErrBadRequest, "INVALID_OPERATION_PAYLOAD", "invalid publication operation payload", err)
	}
	var normA, normB string
	if strings.TrimSpace(payload.ManifestDigest) != "" {
		d, err := domain.ParseSHA256Digest(payload.ManifestDigest)
		if err != nil {
			return OperationPayload{}, err
		}
		normA = d
		payload.ManifestDigest = d
	}
	if strings.TrimSpace(payload.PublicationManifestDigest) != "" {
		d, err := domain.ParseSHA256Digest(payload.PublicationManifestDigest)
		if err != nil {
			return OperationPayload{}, err
		}
		normB = d
		payload.PublicationManifestDigest = d
	}
	if normA != "" && normB != "" && normA != normB {
		return OperationPayload{}, domain.Conflict("MANIFEST_DIGEST_MISMATCH", "operation payload manifest digests do not match")
	}
	if payload.ManifestDigest == "" && normB != "" {
		payload.ManifestDigest = normB
	}
	return payload, nil
}

// GetPublication loads a publication by ID.
func (s *Service) GetPublication(ctx context.Context, id uuid.UUID) (domain.Publication, error) {
	if s == nil || s.store == nil {
		return domain.Publication{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if id == uuid.Nil {
		return domain.Publication{}, domain.BadRequest("INVALID_ID", "publication id must not be nil")
	}
	row, err := s.store.GetPublicationByID(ctx, id)
	if err != nil {
		return domain.Publication{}, err
	}
	return row.ToDomain(), nil
}

// GetPublicationByProposalID loads a publication by proposal ID.
func (s *Service) GetPublicationByProposalID(ctx context.Context, proposalID uuid.UUID) (domain.Publication, error) {
	if s == nil || s.store == nil {
		return domain.Publication{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if proposalID == uuid.Nil {
		return domain.Publication{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	row, err := s.store.GetPublicationByProposalID(ctx, proposalID)
	if err != nil {
		return domain.Publication{}, err
	}
	return row.ToDomain(), nil
}

// RequestPublication validates approval/policy preconditions and atomically ensures the publication
// row and enqueues a PROPOSAL_PUBLISH operation (or short-circuits idempotently if already PUBLISHED).
func (s *Service) RequestPublication(ctx context.Context, proposalID uuid.UUID, manifestDigest string, actorID *uuid.UUID) (RequestResult, error) {
	if s == nil || s.store == nil {
		return RequestResult{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if proposalID == uuid.Nil {
		return RequestResult{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	wantDigest, err := domain.ParseSHA256Digest(manifestDigest)
	if err != nil {
		return RequestResult{}, err
	}
	if actorID != nil && *actorID == uuid.Nil {
		return RequestResult{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}

	bundle, idempotentRes, err := s.loadAndVerifyPreconditions(ctx, s.store, proposalID, wantDigest)
	if err != nil {
		return RequestResult{}, err
	}
	if idempotentRes != nil {
		pubRow, pubErr := s.store.GetPublicationByProposalID(ctx, proposalID)
		if pubErr != nil {
			return RequestResult{}, pubErr
		}
		return RequestResult{
			Publication: pubRow.ToDomain(),
			Idempotent:  true,
		}, nil
	}

	var res RequestResult
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		now := s.now()
		prop, err := tx.GetProposalByIDForUpdate(ctx, proposalID)
		if err != nil {
			return err
		}
		if prop.ManifestDigest == nil {
			return domain.Conflict("MISSING_MANIFEST_DIGEST", "proposal is missing manifest_digest")
		}
		normManifest, err := domain.ParseSHA256Digest(*prop.ManifestDigest)
		if err != nil {
			return err
		}
		if normManifest != wantDigest {
			return domain.Conflict("MANIFEST_DIGEST_MISMATCH", "proposal manifest_digest does not match requested publication_manifest_digest")
		}

		if prop.Status == domain.ProposalStatusPublished {
			pubRow, err := tx.GetPublicationByProposalID(ctx, prop.ID)
			if err != nil {
				return err
			}
			if pubRow.Status == domain.PublicationStatusPublished && pubRow.CommitSHA != nil && *pubRow.CommitSHA != "" {
				res = RequestResult{
					Publication: pubRow.ToDomain(),
					Idempotent:  true,
				}
				return nil
			}
			return domain.Conflict("PUBLICATION_STATE_CONFLICT", "proposal is published without a completed publication record")
		}
		if prop.Status != domain.ProposalStatusApproved && prop.Status != domain.ProposalStatusPublishing {
			return domain.Conflict("PROPOSAL_NOT_APPROVED", fmt.Sprintf("proposal status %s cannot be published", prop.Status))
		}

		branchName := domain.ExpectedBranchName(prop.ID)
		if err := domain.ValidateBranchRef(prop.ID, branchName); err != nil {
			return err
		}
		pubRow, err := tx.EnsurePublication(ctx, persistence.CreatePublicationParams{
			ProposalID: prop.ID,
			BranchRef:  branchName,
			Status:     domain.PublicationStatusPending,
			CreatedAt:  now,
		})
		if err != nil {
			return err
		}
		if pubRow.Status == domain.PublicationStatusPublished && pubRow.CommitSHA != nil && *pubRow.CommitSHA != "" {
			res = RequestResult{
				Publication: pubRow.ToDomain(),
				Idempotent:  true,
			}
			return nil
		}

		latestOp, opErr := tx.GetLatestOperationByResource(ctx, prop.ID, domain.OperationTypeProposalPublish)
		if opErr == nil {
			if latestOp.Status == domain.OperationStatusPending || latestOp.Status == domain.OperationStatusRunning {
				details := operationDetailsFromRow(latestOp)
				res = RequestResult{
					Publication: pubRow.ToDomain(),
					Operation:   &details,
					Idempotent:  true,
				}
				return nil
			}
		} else if !errors.Is(opErr, domain.ErrNotFound) {
			return opErr
		}

		if prop.Status == domain.ProposalStatusPublishing || pubRow.Status == domain.PublicationStatusPublishing {
			res = RequestResult{
				Publication: pubRow.ToDomain(),
				Idempotent:  true,
			}
			return nil
		}

		op, err := operations.EnqueueTx(ctx, tx, operations.EnqueueInput{
			OperationType: domain.OperationTypeProposalPublish,
			ResourceType:  "proposal",
			ResourceID:    prop.ID,
		}, s.metrics, s.logger)
		if err != nil {
			return err
		}

		payloadBytes, err := domain.CanonicalJSONBytes(map[string]any{
			"proposal_id":     prop.ID.String(),
			"publication_id":  pubRow.ID.String(),
			"operation_id":    op.ID.String(),
			"branch_ref":      pubRow.BranchRef,
			"manifest_digest": bundle.manifestDigest,
		})
		if err != nil {
			return err
		}

		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.publish_requested",
			AggregateID: prop.ID,
			Payload:     json.RawMessage(payloadBytes),
		}); err != nil {
			return err
		}

		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.publish_requested",
			ActorID:      actorID,
			ResourceType: "proposal",
			ResourceID:   prop.ID,
			Payload:      json.RawMessage(payloadBytes),
		}, s.logger); err != nil {
			return err
		}

		res = RequestResult{
			Publication: pubRow.ToDomain(),
			Operation:   &op,
		}
		return nil
	})
	if err != nil {
		return RequestResult{}, err
	}
	return res, nil
}

// Publish implements domain.Publisher.
func (s *Service) Publish(ctx context.Context, req domain.ApprovedPublication) (domain.PublicationResult, error) {
	if s == nil || s.store == nil {
		return domain.PublicationResult{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if req.ProposalID == uuid.Nil {
		return domain.PublicationResult{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	digest, err := domain.ParseSHA256Digest(req.ManifestDigest)
	if err != nil {
		return domain.PublicationResult{}, err
	}
	return s.ExecutePublication(ctx, req.ProposalID, digest, true)
}

// LoadApprovedPublication implements publish.InputLoader.
func (s *Service) LoadApprovedPublication(ctx context.Context, req domain.ApprovedPublication) (publish.PublishRequest, error) {
	if s == nil || s.store == nil {
		return publish.PublishRequest{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if req.ProposalID == uuid.Nil {
		return publish.PublishRequest{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	digest, err := domain.ParseSHA256Digest(req.ManifestDigest)
	if err != nil {
		return publish.PublishRequest{}, err
	}
	bundle, shortCircuit, err := s.loadAndVerifyPreconditions(ctx, s.store, req.ProposalID, digest)
	if err != nil {
		return publish.PublishRequest{}, err
	}
	if shortCircuit != nil || bundle.proposal.Status == domain.ProposalStatusPublished {
		return publish.PublishRequest{}, domain.Conflict("PROPOSAL_ALREADY_PUBLISHED", "proposal is already published")
	}
	return bundle.toPublishRequest(), nil
}

// PublishOperation resolves a claimed PROPOSAL_PUBLISH operation (and optional JSON payload)
// and executes the 14-step publication flow.
func (s *Service) PublishOperation(ctx context.Context, op operations.OperationDetails, rawPayload json.RawMessage) (domain.PublicationResult, error) {
	if s == nil || s.store == nil {
		return domain.PublicationResult{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if op.OperationType != domain.OperationTypeProposalPublish {
		return domain.PublicationResult{}, domain.BadRequest("INVALID_OPERATION_TYPE", "operation must be PROPOSAL_PUBLISH")
	}

	payload, err := ParseOperationPayload(rawPayload)
	if err != nil {
		return domain.PublicationResult{}, err
	}

	proposalID, err := s.resolveOperationProposalID(ctx, op, payload)
	if err != nil {
		return domain.PublicationResult{}, err
	}

	var lease *operationLease
	if op.ID != uuid.Nil && strings.TrimSpace(op.LeasedBy) != "" {
		lease = &operationLease{
			opID:     op.ID,
			workerID: strings.TrimSpace(op.LeasedBy),
			attempt:  op.Attempts,
		}
	}

	isFinal := op.Attempts >= op.MaxAttempts && op.MaxAttempts > 0
	return s.executePublication(ctx, proposalID, payload.ManifestDigest, isFinal, lease)
}

func (s *Service) resolveOperationProposalID(ctx context.Context, op operations.OperationDetails, payload OperationPayload) (uuid.UUID, error) {
	if op.ResourceID == uuid.Nil {
		return uuid.Nil, domain.BadRequest("INVALID_RESOURCE_ID", "operation resource_id must not be nil")
	}

	var proposalID uuid.UUID
	var resolvedPubID uuid.UUID

	switch strings.ToLower(strings.TrimSpace(op.ResourceType)) {
	case "publication":
		pub, err := s.store.GetPublicationByID(ctx, op.ResourceID)
		if err != nil {
			return uuid.Nil, err
		}
		resolvedPubID = pub.ID
		proposalID = pub.ProposalID
	case "proposal":
		proposalID = op.ResourceID
	case "":
		pub, err := s.store.GetPublicationByID(ctx, op.ResourceID)
		if err == nil {
			resolvedPubID = pub.ID
			proposalID = pub.ProposalID
		} else if errors.Is(err, domain.ErrNotFound) {
			proposalID = op.ResourceID
		} else {
			return uuid.Nil, err
		}
	default:
		return uuid.Nil, domain.BadRequest("INVALID_RESOURCE_TYPE", fmt.Sprintf("unsupported operation resource_type %q", op.ResourceType))
	}

	if payload.ProposalID != uuid.Nil && payload.ProposalID != proposalID {
		return uuid.Nil, domain.Conflict("PROPOSAL_MISMATCH", "operation payload proposal_id does not match target proposal")
	}
	if payload.PublicationID != uuid.Nil {
		if resolvedPubID != uuid.Nil && payload.PublicationID != resolvedPubID {
			return uuid.Nil, domain.Conflict("PUBLICATION_MISMATCH", "operation payload publication_id does not match target publication")
		}
		if resolvedPubID == uuid.Nil {
			pub, err := s.store.GetPublicationByID(ctx, payload.PublicationID)
			if err != nil {
				return uuid.Nil, err
			}
			if pub.ProposalID != proposalID {
				return uuid.Nil, domain.Conflict("PUBLICATION_MISMATCH", "operation payload publication does not belong to proposal")
			}
		}
	}
	return proposalID, nil
}

// ExecutePublication runs the full 14-step isolated publication orchestrator using two short
// database transactions (Tx 1 before Git/GitHub I/O; Tx 2 after) so LockAuditChainHead is never
// held across external I/O.
func (s *Service) ExecutePublication(ctx context.Context, proposalID uuid.UUID, expectedManifestDigest string, isFinalAttempt bool) (domain.PublicationResult, error) {
	return s.executePublication(ctx, proposalID, expectedManifestDigest, isFinalAttempt, nil)
}

func (s *Service) executePublication(ctx context.Context, proposalID uuid.UUID, expectedManifestDigest string, isFinalAttempt bool, lease *operationLease) (domain.PublicationResult, error) {
	if s == nil || s.store == nil {
		return domain.PublicationResult{}, domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if proposalID == uuid.Nil {
		return domain.PublicationResult{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}

	var wantDigest string
	if strings.TrimSpace(expectedManifestDigest) != "" {
		var err error
		wantDigest, err = domain.ParseSHA256Digest(expectedManifestDigest)
		if err != nil {
			return domain.PublicationResult{}, err
		}
	}

	// Steps 1–6: Fail-closed precondition & approval/policy/artifact verification.
	bundle, shortCircuit, preErr := s.loadAndVerifyPreconditions(ctx, s.store, proposalID, wantDigest)
	if preErr != nil {
		if s.metrics != nil {
			s.metrics.IncPublication("error")
		}
		if !isRunnerFenced(ctx) && !errors.Is(preErr, context.Canceled) && !errors.Is(ctx.Err(), context.Canceled) && (!IsRetryableError(preErr) || isFinalAttempt) {
			termCtx, termCancel := detachTimeout(ctx, defaultTxCleanupTimeout)
			_ = s.HandleTerminalFailure(termCtx, proposalID, preErr)
			termCancel()
		}
		return domain.PublicationResult{}, preErr
	}
	if shortCircuit != nil {
		return *shortCircuit, nil
	}

	if s.gitPublisher == nil {
		return domain.PublicationResult{}, domain.Internal("MISSING_GIT_PUBLISHER", "git publisher is not configured")
	}

	// Step 7 (Tx 1): Ensure publication, close any interrupted attempts on lease recovery,
	// transition APPROVED->PUBLISHING, begin publication attempt, and append proposal.publish_started audit event.
	var (
		pubRow     persistence.PublicationRow
		attemptRow persistence.PublicationAttemptRow
		tx1Result  *domain.PublicationResult
	)
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		now := s.now()
		prop, err := tx.GetProposalByIDForUpdate(ctx, proposalID)
		if err != nil {
			return err
		}
		if lease != nil {
			opRow, opErr := tx.GetOperationByID(ctx, lease.opID)
			if opErr != nil {
				return opErr
			}
			if opRow.Status != domain.OperationStatusRunning || opRow.LeasedBy == nil || *opRow.LeasedBy != lease.workerID || (lease.attempt > 0 && opRow.Attempts != lease.attempt) {
				return domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
			}
		}
		if prop.ManifestDigest == nil {
			return domain.Conflict("MISSING_MANIFEST_DIGEST", "proposal is missing manifest_digest")
		}
		curDigest, err := domain.ParseSHA256Digest(*prop.ManifestDigest)
		if err != nil {
			return err
		}
		if curDigest != bundle.manifestDigest {
			return domain.Conflict("MANIFEST_DIGEST_MISMATCH", "proposal manifest_digest changed concurrently")
		}

		branchName := domain.ExpectedBranchName(prop.ID)
		if err := domain.ValidateBranchRef(prop.ID, branchName); err != nil {
			return err
		}

		if prop.Status == domain.ProposalStatusPublished {
			existingPub, err := tx.GetPublicationByProposalID(ctx, prop.ID)
			if err != nil {
				return err
			}
			res, err := publicationRowToResult(existingPub)
			if err != nil {
				return err
			}
			tx1Result = &res
			return nil
		}
		if prop.Status != domain.ProposalStatusApproved && prop.Status != domain.ProposalStatusPublishing {
			return domain.Conflict("PROPOSAL_NOT_APPROVED", fmt.Sprintf("proposal status %s cannot be published", prop.Status))
		}

		pubRow, err = tx.EnsurePublication(ctx, persistence.CreatePublicationParams{
			ProposalID: prop.ID,
			BranchRef:  branchName,
			Status:     domain.PublicationStatusPending,
			CreatedAt:  now,
		})
		if err != nil {
			return err
		}
		if err := domain.ValidateBranchRef(prop.ID, pubRow.BranchRef); err != nil {
			return err
		}
		if pubRow.Status == domain.PublicationStatusPublished && pubRow.CommitSHA != nil && *pubRow.CommitSHA != "" {
			if prop.Status != domain.ProposalStatusPublished {
				fromStatus := prop.Status
				if _, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
					ID:              prop.ID,
					FromStatus:      &fromStatus,
					ToStatus:        domain.ProposalStatusPublished,
					ExpectedVersion: prop.Version,
					UpdatedAt:       now,
				}); err != nil {
					return err
				}
			}
			res, err := publicationRowToResult(pubRow)
			if err != nil {
				return err
			}
			tx1Result = &res
			return nil
		}

		// Close dangling STARTED attempts only when legitimately recovering/retrying a reclaimed
		// operation (attempts > 1 under verified lease); otherwise an active concurrent caller
		// owns the STARTED attempt and must not be clobbered.
		priorAttempts, err := tx.ListPublicationAttemptsByPublication(ctx, pubRow.ID)
		if err != nil {
			return err
		}
		for _, prev := range priorAttempts {
			if prev.Status == "STARTED" {
				if lease == nil || lease.attempt <= 1 {
					return domain.Conflict("PUBLICATION_IN_PROGRESS", "publication attempt is already in progress")
				}
				if _, err := tx.CompletePublicationAttemptFailed(ctx, prev.ID, "INTERRUPTED_ATTEMPT", "previous publication attempt did not complete", now); err != nil {
					return err
				}
			}
		}

		if prop.Status == domain.ProposalStatusApproved {
			fromStatus := domain.ProposalStatusApproved
			prop, err = tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
				ID:              prop.ID,
				FromStatus:      &fromStatus,
				ToStatus:        domain.ProposalStatusPublishing,
				ExpectedVersion: prop.Version,
				UpdatedAt:       now,
			})
			if err != nil {
				return err
			}
		}

		pubRow, attemptRow, err = tx.BeginPublicationAttempt(ctx, persistence.BeginPublicationAttemptParams{
			PublicationID:  pubRow.ID,
			ManifestDigest: bundle.manifestDigest,
			Now:            now,
		})
		if err != nil {
			if errors.Is(err, domain.ErrConflict) {
				reloaded, relErr := tx.GetPublicationByProposalID(ctx, prop.ID)
				if relErr == nil && reloaded.Status == domain.PublicationStatusPublished && reloaded.CommitSHA != nil && *reloaded.CommitSHA != "" {
					res, resErr := publicationRowToResult(reloaded)
					if resErr == nil {
						tx1Result = &res
						return nil
					}
				}
			}
			return err
		}

		startPayload, err := domain.CanonicalJSONBytes(map[string]any{
			"proposal_id":     prop.ID.String(),
			"publication_id":  pubRow.ID.String(),
			"attempt_id":      attemptRow.ID.String(),
			"attempt_number":  attemptRow.AttemptNumber,
			"branch_ref":      pubRow.BranchRef,
			"manifest_digest": bundle.manifestDigest,
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.publish_started",
			ResourceType: "proposal",
			ResourceID:   prop.ID,
			Payload:      json.RawMessage(startPayload),
		}, s.logger); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if isTxConcurrencyConflict(err) {
			if existingPub, pubErr := s.store.GetPublicationByProposalID(ctx, proposalID); pubErr == nil &&
				existingPub.Status == domain.PublicationStatusPublished &&
				existingPub.CommitSHA != nil && *existingPub.CommitSHA != "" {
				if res, resErr := publicationRowToResult(existingPub); resErr == nil {
					return res, nil
				}
			}
			return domain.PublicationResult{}, err
		}
		if !isRunnerFenced(ctx) && !errors.Is(err, context.Canceled) && !errors.Is(ctx.Err(), context.Canceled) && (!IsRetryableError(err) || isFinalAttempt) {
			termCtx, termCancel := detachTimeout(ctx, defaultTxCleanupTimeout)
			_ = s.HandleTerminalFailure(termCtx, proposalID, err)
			termCancel()
		}
		return domain.PublicationResult{}, err
	}
	if tx1Result != nil {
		return *tx1Result, nil
	}

	// Step 8 (Outside DB Tx): Perform Git reconstruction/commit/push and GitHub PR create/update.
	pubReq := bundle.toPublishRequest()
	res, pubErr := s.gitPublisher.PublishRequest(ctx, pubReq)

	// Step 9 (Tx 2 Success): Record commit, PR, PUBLISHED status, audit event, and outbox event.
	if pubErr == nil {
		txCtx, cancel := detachTimeout(ctx, defaultTxCleanupTimeout)
		defer cancel()

		txErr := s.store.RunInTx(txCtx, func(tx TxStore) error {
			now := s.now()
			if _, err := tx.CompletePublicationAttemptSucceeded(txCtx, attemptRow.ID, res.CommitSHA, now); err != nil {
				return err
			}
			var prNum *int64
			if res.PRNumber > 0 {
				v := res.PRNumber
				prNum = &v
			}
			if _, err := tx.MarkPublicationPublished(txCtx, persistence.MarkPublicationPublishedParams{
				ID:                pubRow.ID,
				CommitSHA:         res.CommitSHA,
				PullRequestNumber: prNum,
				PullRequestURL:    res.PRURL,
				UpdatedAt:         now,
			}); err != nil {
				return err
			}

			prop, err := tx.GetProposalByIDForUpdate(txCtx, proposalID)
			if err != nil {
				return err
			}
			if prop.Status != domain.ProposalStatusPublished {
				fromStatus := prop.Status
				if _, err := tx.TransitionProposalStatus(txCtx, persistence.TransitionProposalStatusParams{
					ID:              prop.ID,
					FromStatus:      &fromStatus,
					ToStatus:        domain.ProposalStatusPublished,
					ExpectedVersion: prop.Version,
					UpdatedAt:       now,
				}); err != nil {
					return err
				}
			}

			pubPayloadMap := map[string]any{
				"proposal_id":     prop.ID.String(),
				"publication_id":  pubRow.ID.String(),
				"attempt_id":      attemptRow.ID.String(),
				"attempt_number":  attemptRow.AttemptNumber,
				"commit_sha":      res.CommitSHA,
				"branch_ref":      res.Branch,
				"manifest_digest": bundle.manifestDigest,
			}
			if res.PRNumber > 0 {
				pubPayloadMap["pull_request_number"] = res.PRNumber
			}
			if res.PRURL != "" {
				pubPayloadMap["pull_request_url"] = res.PRURL
			}
			pubPayload, err := domain.CanonicalJSONBytes(pubPayloadMap)
			if err != nil {
				return err
			}

			if _, err := audit.AppendTx(txCtx, tx, audit.AppendInput{
				EventType:    "proposal.published",
				ResourceType: "proposal",
				ResourceID:   prop.ID,
				Payload:      json.RawMessage(pubPayload),
			}, s.logger); err != nil {
				return err
			}
			if _, err := operations.EnqueueOutboxTx(txCtx, tx, operations.EnqueueOutboxInput{
				EventType:   "proposal.published",
				AggregateID: prop.ID,
				Payload:     json.RawMessage(pubPayload),
			}); err != nil {
				return err
			}
			return nil
		})
		if txErr != nil {
			if isTxConcurrencyConflict(txErr) {
				if existingPub, pubErr := s.store.GetPublicationByProposalID(txCtx, proposalID); pubErr == nil &&
					existingPub.Status == domain.PublicationStatusPublished &&
					existingPub.CommitSHA != nil && *existingPub.CommitSHA != "" {
					if idempRes, resErr := publicationRowToResult(existingPub); resErr == nil {
						return idempRes, nil
					}
				}
			}
			return domain.PublicationResult{}, &postPublishCommitError{err: txErr}
		}
		return res, nil
	}

	// Step 10 (Tx 2 Failure): On graceful shutdown or LEASE_LOST cancellation, do NOT permanently fail proposal/publication!
	if errors.Is(pubErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		if s.logger != nil {
			observability.LoggerWithTrace(ctx, s.logger).Warn("publication interrupted by context cancellation; preserving PUBLISHING state",
				"proposal_id", proposalID.String(),
				"publication_id", pubRow.ID.String(),
			)
		}
		return domain.PublicationResult{}, pubErr
	}

	retryable := IsRetryableError(pubErr)
	errCode, errMsg := safeErrorCodeMessage(pubErr)
	txCtx, cancel := detachTimeout(ctx, defaultTxCleanupTimeout)
	defer cancel()

	txErr := s.store.RunInTx(txCtx, func(tx TxStore) error {
		now := s.now()
		if lease != nil {
			opRow, opErr := tx.GetOperationByID(txCtx, lease.opID)
			if opErr != nil {
				return opErr
			}
			if opRow.Status != domain.OperationStatusRunning || opRow.LeasedBy == nil || *opRow.LeasedBy != lease.workerID || (lease.attempt > 0 && opRow.Attempts != lease.attempt) {
				return domain.Conflict("LEASE_LOST", "operation lease is no longer held by worker")
			}
		}
		if _, err := tx.CompletePublicationAttemptFailed(txCtx, attemptRow.ID, errCode, errMsg, now); err != nil {
			return err
		}

		if retryable && !isFinalAttempt {
			retryPayload, err := domain.CanonicalJSONBytes(map[string]any{
				"proposal_id":    proposalID.String(),
				"publication_id": pubRow.ID.String(),
				"attempt_id":     attemptRow.ID.String(),
				"attempt_number": attemptRow.AttemptNumber,
				"error_code":     errCode,
				"reason":         errMsg,
			})
			if err != nil {
				return err
			}
			if _, err := audit.AppendTx(txCtx, tx, audit.AppendInput{
				EventType:    "proposal.publish_retry_scheduled",
				ResourceType: "proposal",
				ResourceID:   proposalID,
				Payload:      json.RawMessage(retryPayload),
			}, s.logger); err != nil {
				return err
			}
			return nil
		}

		if isRunnerFenced(ctx) {
			// Runner will fence via ops.Fail before calling HandleOperationTerminalFailure.
			return nil
		}

		curPub, err := tx.GetPublicationByID(txCtx, pubRow.ID)
		if err != nil {
			return err
		}
		if curPub.Status == domain.PublicationStatusPublished {
			return nil
		}
		if curPub.Status == domain.PublicationStatusPending || curPub.Status == domain.PublicationStatusPublishing {
			if _, err := tx.MarkPublicationFailed(txCtx, curPub.ID, now); err != nil {
				return err
			}
		}

		curProp, err := tx.GetProposalByIDForUpdate(txCtx, proposalID)
		if err != nil {
			return err
		}
		if curProp.Status == domain.ProposalStatusApproved || curProp.Status == domain.ProposalStatusPublishing {
			fromStatus := curProp.Status
			if _, err := tx.TransitionProposalStatus(txCtx, persistence.TransitionProposalStatusParams{
				ID:              curProp.ID,
				FromStatus:      &fromStatus,
				ToStatus:        domain.ProposalStatusFailed,
				ExpectedVersion: curProp.Version,
				UpdatedAt:       now,
			}); err != nil {
				return err
			}
		}

		failPayload, err := domain.CanonicalJSONBytes(map[string]any{
			"proposal_id":    proposalID.String(),
			"publication_id": pubRow.ID.String(),
			"attempt_id":     attemptRow.ID.String(),
			"attempt_number": attemptRow.AttemptNumber,
			"error_code":     errCode,
			"reason":         errMsg,
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(txCtx, tx, audit.AppendInput{
			EventType:    "proposal.publish_failed",
			ResourceType: "proposal",
			ResourceID:   proposalID,
			Payload:      json.RawMessage(failPayload),
		}, s.logger); err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(txCtx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.publish_failed",
			AggregateID: proposalID,
			Payload:     json.RawMessage(failPayload),
		}); err != nil {
			return err
		}
		return nil
	})
	if txErr != nil && s.logger != nil {
		observability.LoggerWithTrace(ctx, s.logger).Error("failed recording publication failure state",
			"proposal_id", proposalID.String(),
			"publication_id", pubRow.ID.String(),
			"error_code", "PERSISTENCE_ERROR",
		)
	}
	return domain.PublicationResult{}, pubErr
}

// HandleOperationTerminalFailure resolves proposalID from an operation and records terminal failure.
func (s *Service) HandleOperationTerminalFailure(ctx context.Context, op operations.OperationDetails, cause error) error {
	if s == nil || s.store == nil {
		return domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	proposalID, err := s.resolveOperationProposalID(ctx, op, OperationPayload{})
	if err != nil {
		return err
	}
	return s.HandleTerminalFailure(ctx, proposalID, cause)
}

// HandleTerminalFailure idempotently transitions an APPROVED/PUBLISHING proposal and its
// PENDING/PUBLISHING publication to FAILED, closing any dangling STARTED attempts and emitting
// audit + outbox events. Already-PUBLISHED or already-terminal proposals are never overwritten.
func (s *Service) HandleTerminalFailure(ctx context.Context, proposalID uuid.UUID, cause error) error {
	if s == nil || s.store == nil {
		return domain.Unavailable("PUBLICATION_UNAVAILABLE", "publication store is not configured")
	}
	if proposalID == uuid.Nil {
		return domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	errCode, errMsg := safeErrorCodeMessage(cause)

	return s.store.RunInTx(ctx, func(tx TxStore) error {
		now := s.now()
		prop, err := tx.GetProposalByIDForUpdate(ctx, proposalID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			return err
		}
		if prop.Status == domain.ProposalStatusPublished || prop.Status.IsTerminal() {
			return nil
		}
		if prop.Status != domain.ProposalStatusApproved && prop.Status != domain.ProposalStatusPublishing {
			return nil
		}

		var pubID uuid.UUID
		pub, pubErr := tx.GetPublicationByProposalID(ctx, proposalID)
		if pubErr != nil {
			if !errors.Is(pubErr, domain.ErrNotFound) {
				return pubErr
			}
			pub, err = tx.EnsurePublication(ctx, persistence.CreatePublicationParams{
				ProposalID: proposalID,
				BranchRef:  domain.ExpectedBranchName(proposalID),
				Status:     domain.PublicationStatusPending,
				CreatedAt:  now,
			})
			if err != nil {
				return err
			}
		}
		if pub.Status == domain.PublicationStatusPublished {
			return nil
		}
		pubID = pub.ID

		attempts, err := tx.ListPublicationAttemptsByPublication(ctx, pub.ID)
		if err != nil {
			return err
		}
		for _, a := range attempts {
			if a.Status == "STARTED" {
				if _, err := tx.CompletePublicationAttemptFailed(ctx, a.ID, errCode, errMsg, now); err != nil {
					return err
				}
			}
		}

		if pub.Status == domain.PublicationStatusPending || pub.Status == domain.PublicationStatusPublishing {
			if _, err := tx.MarkPublicationFailed(ctx, pub.ID, now); err != nil {
				return err
			}
		}

		fromStatus := prop.Status
		if _, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
			ID:              prop.ID,
			FromStatus:      &fromStatus,
			ToStatus:        domain.ProposalStatusFailed,
			ExpectedVersion: prop.Version,
			UpdatedAt:       now,
		}); err != nil {
			return err
		}

		failPayload, err := domain.CanonicalJSONBytes(map[string]any{
			"proposal_id":    proposalID.String(),
			"publication_id": pubID.String(),
			"error_code":     errCode,
			"reason":         errMsg,
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.publish_failed",
			ResourceType: "proposal",
			ResourceID:   proposalID,
			Payload:      json.RawMessage(failPayload),
		}, s.logger); err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.publish_failed",
			AggregateID: proposalID,
			Payload:     json.RawMessage(failPayload),
		}); err != nil {
			return err
		}
		return nil
	})
}

type verifiedBundle struct {
	proposal       persistence.ProposalRow
	workspace      persistence.WorkspaceRow
	repository     persistence.RepositoryRow
	owner          persistence.PrincipalRow
	treeArtifact   persistence.ArtifactRow
	manifestDigest string
	treeDigest     string
	agentAssisted  bool
}

func (b verifiedBundle) toPublishRequest() publish.PublishRequest {
	art := b.treeArtifact.ToDomain()
	return publish.PublishRequest{
		ProposalID:                  b.proposal.ID,
		WorkspaceID:                 b.proposal.WorkspaceID,
		Repository:                  b.repository.ToDomain(),
		Owner:                       b.owner.ToDomain(),
		BaseCommit:                  b.proposal.BaseCommit,
		TargetRef:                   b.proposal.TargetRef,
		Title:                       b.proposal.Title,
		Description:                 derefString(b.proposal.Description),
		AgentAssisted:               b.agentAssisted,
		ManifestDigest:              b.manifestDigest,
		ExpectedTreeDigest:          b.treeDigest,
		ExpectedCanonicalTreeSHA256: art.SHA256,
		CanonicalTreeArtifact:       &art,
	}
}

func (s *Service) loadAndVerifyPreconditions(ctx context.Context, store TxStore, proposalID uuid.UUID, wantManifestDigest string) (verifiedBundle, *domain.PublicationResult, error) {
	prop, err := store.GetProposalByID(ctx, proposalID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	if err := domain.ValidateBranchRef(prop.ID, domain.ExpectedBranchName(prop.ID)); err != nil {
		return verifiedBundle{}, nil, err
	}

	ws, err := store.GetWorkspaceByID(ctx, prop.WorkspaceID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	repo, err := store.GetRepositoryByID(ctx, ws.RepositoryID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	owner, err := store.GetPrincipalByID(ctx, prop.OwnerID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}

	// Verify link consistency & owner/repository eligibility.
	if ws.OwnerID != prop.OwnerID {
		return verifiedBundle{}, nil, domain.Conflict("WORKSPACE_OWNER_MISMATCH", "proposal owner does not match workspace owner")
	}
	if prop.BaseCommit != ws.BaseCommit || prop.TargetRef != ws.TargetRef {
		return verifiedBundle{}, nil, domain.Conflict("PROPOSAL_WORKSPACE_MISMATCH", "proposal base_commit/target_ref does not match workspace")
	}
	if !repo.Enabled {
		return verifiedBundle{}, nil, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	if _, _, err := repo.ToDomain().OwnerRepo(); err != nil {
		return verifiedBundle{}, nil, err
	}
	if _, _, err := owner.ToDomain().GitAuthor(); err != nil {
		return verifiedBundle{}, nil, err
	}

	if prop.Status != domain.ProposalStatusApproved &&
		prop.Status != domain.ProposalStatusPublishing &&
		prop.Status != domain.ProposalStatusPublished {
		return verifiedBundle{}, nil, domain.Conflict("PROPOSAL_NOT_APPROVED", fmt.Sprintf("proposal status %s is not eligible for publication", prop.Status))
	}

	// Verify digests & artifacts.
	if prop.ManifestDigest == nil {
		return verifiedBundle{}, nil, domain.Conflict("MISSING_MANIFEST_DIGEST", "proposal is missing manifest_digest")
	}
	manifestDigest, err := domain.ParseSHA256Digest(*prop.ManifestDigest)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	if wantManifestDigest != "" && manifestDigest != wantManifestDigest {
		return verifiedBundle{}, nil, domain.Conflict("MANIFEST_DIGEST_MISMATCH", "proposal manifest_digest does not match approved manifest digest")
	}

	// Idempotent short-circuit if already PUBLISHED (RG-08).
	if prop.Status == domain.ProposalStatusPublished {
		pubRow, pubErr := store.GetPublicationByProposalID(ctx, prop.ID)
		if pubErr != nil {
			return verifiedBundle{}, nil, pubErr
		}
		if err := domain.ValidateBranchRef(prop.ID, pubRow.BranchRef); err != nil {
			return verifiedBundle{}, nil, err
		}
		res, resErr := publicationRowToResult(pubRow)
		if resErr != nil {
			return verifiedBundle{}, nil, resErr
		}
		return verifiedBundle{}, &res, nil
	}

	// Also check if publication row already completed before proposal row updated (crash recovery).
	if pubRow, pubErr := store.GetPublicationByProposalID(ctx, prop.ID); pubErr == nil {
		if err := domain.ValidateBranchRef(prop.ID, pubRow.BranchRef); err != nil {
			return verifiedBundle{}, nil, err
		}
		if pubRow.Status == domain.PublicationStatusPublished && pubRow.CommitSHA != nil && *pubRow.CommitSHA != "" {
			res, resErr := publicationRowToResult(pubRow)
			if resErr == nil {
				// Let Tx 1 reconcile proposal status -> PUBLISHED if needed, or return idempotently after verifying preconditions below.
				_ = res
			}
		}
	} else if !errors.Is(pubErr, domain.ErrNotFound) {
		return verifiedBundle{}, nil, pubErr
	}

	if prop.CanonicalArtifactID == nil || *prop.CanonicalArtifactID == uuid.Nil {
		return verifiedBundle{}, nil, domain.Conflict("MISSING_CANONICAL_ARTIFACT", "proposal is missing canonical_artifact_id")
	}
	if prop.TreeDigest == nil || strings.TrimSpace(*prop.TreeDigest) == "" {
		return verifiedBundle{}, nil, domain.Conflict("MISSING_TREE_DIGEST", "proposal is missing tree_digest")
	}
	treeDigest, err := domain.ParseGitSHA(*prop.TreeDigest)
	if err != nil {
		return verifiedBundle{}, nil, err
	}

	treeArt, err := store.GetArtifactByID(ctx, *prop.CanonicalArtifactID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	if treeArt.DeletedAt != nil {
		return verifiedBundle{}, nil, domain.Conflict("ARTIFACT_DELETED", "canonical tree artifact has been deleted")
	}
	if treeArt.Kind != domain.ArtifactKindCanonicalTree {
		return verifiedBundle{}, nil, domain.BadRequest("INVALID_ARTIFACT_KIND", "canonical artifact must have kind CANONICAL_TREE")
	}
	if treeArt.SizeBytes <= 0 {
		return verifiedBundle{}, nil, domain.Unprocessable("INVALID_ARTIFACT_SIZE", "canonical tree artifact size must be positive")
	}
	if treeArt.WorkspaceID != nil && *treeArt.WorkspaceID != prop.WorkspaceID {
		return verifiedBundle{}, nil, domain.Conflict("ARTIFACT_WORKSPACE_MISMATCH", "canonical tree artifact belongs to a different workspace")
	}

	if prop.ManifestArtifactID != nil && *prop.ManifestArtifactID != uuid.Nil {
		manifestArt, err := store.GetArtifactByID(ctx, *prop.ManifestArtifactID)
		if err != nil {
			return verifiedBundle{}, nil, err
		}
		if manifestArt.DeletedAt != nil {
			return verifiedBundle{}, nil, domain.Conflict("ARTIFACT_DELETED", "publication manifest artifact has been deleted")
		}
		if manifestArt.Kind != domain.ArtifactKindPublicationManifest {
			return verifiedBundle{}, nil, domain.BadRequest("INVALID_ARTIFACT_KIND", "manifest artifact must have kind PUBLICATION_MANIFEST")
		}
		artDigest, err := domain.ParseSHA256Digest(manifestArt.SHA256)
		if err != nil || artDigest != manifestDigest {
			return verifiedBundle{}, nil, domain.Conflict("MANIFEST_DIGEST_MISMATCH", "manifest artifact digest does not match proposal manifest_digest")
		}
	}

	// Verify latest policy decision fail-closed.
	if prop.LatestPolicyEvaluationID == nil || *prop.LatestPolicyEvaluationID == uuid.Nil {
		return verifiedBundle{}, nil, domain.Forbidden("MISSING_POLICY_DECISION", "proposal lacks a policy evaluation decision")
	}
	latestDecision, err := store.GetLatestPolicyDecisionForProposal(ctx, prop.ID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	if latestDecision.ProposalID != prop.ID || latestDecision.ID != *prop.LatestPolicyEvaluationID {
		return verifiedBundle{}, nil, domain.Conflict("STALE_POLICY_DECISION", "proposal latest_policy_evaluation_id does not match latest policy decision")
	}
	if prop.LatestPolicyEffect == nil || *prop.LatestPolicyEffect != latestDecision.Effect {
		return verifiedBundle{}, nil, domain.Conflict("STALE_POLICY_DECISION", "proposal latest_policy_effect does not match latest policy decision")
	}
	if latestDecision.Effect.BlocksPublication() {
		return verifiedBundle{}, nil, domain.Forbidden("POLICY_BLOCKED", fmt.Sprintf("policy decision effect %s blocks publication", latestDecision.Effect))
	}

	// Verify approval requirements & active approvals bound to (decision.ID, manifestDigest) + SoD (RG-03, RG-04).
	reqs, err := store.ListApprovalRequirementsByPolicyDecision(ctx, latestDecision.ID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	for _, r := range reqs {
		if r.ProposalID != prop.ID {
			return verifiedBundle{}, nil, domain.Conflict("APPROVAL_REQUIREMENT_MISMATCH", "approval requirement does not belong to proposal")
		}
		if r.SatisfiedAt == nil || r.SatisfiedCount < r.MinimumApprovals {
			return verifiedBundle{}, nil, domain.Forbidden("MISSING_APPROVAL_REQUIREMENT", fmt.Sprintf("approval requirement for group %q is not satisfied", r.ReviewerGroup))
		}
	}

	allApprovals, err := store.ListApprovalsByProposal(ctx, prop.ID)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	for _, a := range allApprovals {
		if a.RevokedAt != nil || a.Decision != domain.ApprovalDecisionReject {
			continue
		}
		if a.PolicyDecisionID == latestDecision.ID && strings.EqualFold(a.ManifestDigest, manifestDigest) {
			return verifiedBundle{}, nil, domain.Conflict("PROPOSAL_REJECTED", "proposal has an active rejection for the current policy decision and manifest")
		}
	}

	activeApprovals, err := store.ListActiveApprovalsForDecision(ctx, prop.ID, latestDecision.ID, manifestDigest)
	if err != nil {
		return verifiedBundle{}, nil, err
	}
	validCount := 0
	for _, a := range activeApprovals {
		domApp := a.ToDomain()
		if !domApp.IsActiveForManifest(manifestDigest) {
			continue
		}
		if a.ReviewerID == prop.OwnerID {
			return verifiedBundle{}, nil, domain.Forbidden("SOD_VIOLATION", "proposal owner cannot approve their own proposal")
		}
		reviewer, err := store.GetPrincipalByID(ctx, a.ReviewerID)
		if err != nil {
			return verifiedBundle{}, nil, err
		}
		if reviewer.Kind != domain.PrincipalKindHuman {
			return verifiedBundle{}, nil, domain.Forbidden("NON_HUMAN_APPROVER", "only HUMAN principals may satisfy publication approval")
		}
		validCount++
	}
	if validCount < 1 {
		return verifiedBundle{}, nil, domain.Forbidden("UNAPPROVED_PROPOSAL", "proposal lacks an active human approval bound to the current policy decision and manifest digest")
	}

	agentAssisted := prop.ProvenanceType == "agent_assisted" || (prop.ProvenanceType == "" && ws.AgentID != nil)

	return verifiedBundle{
		proposal:       prop,
		workspace:      ws,
		repository:     repo,
		owner:          owner,
		treeArtifact:   treeArt,
		manifestDigest: manifestDigest,
		treeDigest:     treeDigest,
		agentAssisted:  agentAssisted,
	}, nil, nil
}

// IsRetryableError classifies errors into retryable transient failures vs terminal failures.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrRateLimited) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		switch domErr.Code() {
		case "TX_CONFLICT", "PUBLICATION_IN_PROGRESS":
			return true
		case "GIT_PUSH_CONFLICT":
			lower := strings.ToLower(domErr.Message)
			return strings.Contains(lower, "failed to lock") || strings.Contains(lower, "stale info")
		}
	}
	return false
}

func publicationRowToResult(pub persistence.PublicationRow) (domain.PublicationResult, error) {
	if pub.Status != domain.PublicationStatusPublished || pub.CommitSHA == nil || strings.TrimSpace(*pub.CommitSHA) == "" {
		return domain.PublicationResult{}, domain.Conflict("PUBLICATION_INCOMPLETE", "publication is not completed")
	}
	var prNum int64
	if pub.PullRequestNumber != nil {
		prNum = *pub.PullRequestNumber
	}
	return domain.PublicationResult{
		ProposalID: pub.ProposalID,
		CommitSHA:  *pub.CommitSHA,
		Branch:     pub.BranchRef,
		PRNumber:   prNum,
		PRURL:      derefString(pub.PullRequestURL),
	}, nil
}

func safeErrorCodeMessage(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	code := "PUBLISH_FAILED"
	msg := err.Error()
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		code = domErr.Code()
		msg = domErr.Message
		if msg == "" {
			msg = code
		}
	}
	msg = sanitizeErrorString(msg)
	if len(msg) > maxSafeErrorLen {
		msg = msg[:maxSafeErrorLen] + "...[truncated]"
	}
	return code, msg
}

func sanitizeErrorString(raw string) string {
	out := strings.TrimSpace(raw)
	out = errURLUserInfoPattern.ReplaceAllString(out, "${1}[REDACTED]@")
	for _, pat := range errTokenPatterns {
		out = pat.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

func detachTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), d)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
