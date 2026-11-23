package proposals

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultFindingsLimit = 100
	maxFindingsLimit     = 500
	maxTitleLen          = 256
	maxDescriptionLen    = 8192
	maxReasonLen         = 512
)

// Service manages the Change Proposal lifecycle, state transitions, and evidence queries.
type Service struct {
	store   Store
	metrics *observability.Metrics
	logger  *slog.Logger
}

// NewService constructs a proposals Service backed by *persistence.Store.
func NewService(store *persistence.Store, metrics *observability.Metrics, logger *slog.Logger) *Service {
	var adapter Store
	if store != nil {
		adapter = NewStoreAdapter(store)
	}
	return NewServiceWithStore(adapter, metrics, logger)
}

// NewServiceWithStore constructs a proposals Service with a custom Store implementation.
func NewServiceWithStore(store Store, metrics *observability.Metrics, logger *slog.Logger) *Service {
	return &Service{
		store:   store,
		metrics: metrics,
		logger:  logger,
	}
}

// Submit validates an uploaded EGRESS_SNAPSHOT artifact against its workspace and generation,
// creates a CAPTURED proposal bound to the workspace's accountable human owner, and atomically
// enqueues PROPOSAL_RECONSTRUCT, an outbox event, and an audit event.
func (s *Service) Submit(ctx context.Context, input SubmitInput) (SubmitResult, error) {
	if s == nil || s.store == nil {
		return SubmitResult{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if input.WorkspaceID == uuid.Nil {
		return SubmitResult{}, domain.BadRequest("INVALID_WORKSPACE_ID", "workspace_id must not be nil")
	}
	if input.SnapshotArtifactID == uuid.Nil {
		return SubmitResult{}, domain.BadRequest("INVALID_ARTIFACT_ID", "snapshot artifact_id must not be nil")
	}
	if input.ActorID != nil && *input.ActorID == uuid.Nil {
		return SubmitResult{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}
	snapshotSHA, err := domain.ParseSHA256Digest(input.SnapshotSHA256)
	if err != nil {
		return SubmitResult{}, err
	}
	if input.WorkspaceGeneration < 1 {
		return SubmitResult{}, domain.BadRequest("INVALID_GENERATION", "workspace_generation must be >= 1")
	}
	if input.SizeBytes < 0 {
		return SubmitResult{}, domain.BadRequest("INVALID_SIZE", "size_bytes must be non-negative")
	}
	title := strings.TrimSpace(input.Title)
	if utf8.RuneCountInString(title) < 1 || utf8.RuneCountInString(title) > maxTitleLen {
		return SubmitResult{}, domain.BadRequest("INVALID_TITLE", "title must be between 1 and 256 characters")
	}
	if utf8.RuneCountInString(input.Description) > maxDescriptionLen {
		return SubmitResult{}, domain.BadRequest("INVALID_DESCRIPTION", "description must not exceed 8192 characters")
	}
	provenanceType, err := normalizeProvenanceType(input.ProvenanceType)
	if err != nil {
		return SubmitResult{}, err
	}
	captureMethod, err := normalizeCaptureMethod(input.CaptureMethod)
	if err != nil {
		return SubmitResult{}, err
	}
	propID := input.ID
	if propID == uuid.Nil {
		propID, err = domain.NewID()
		if err != nil {
			return SubmitResult{}, err
		}
	} else if !domain.IsUUIDv7(propID) {
		return SubmitResult{}, domain.BadRequest("INVALID_ID", "proposal id must be UUIDv7")
	}

	var result SubmitResult
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		ws, err := tx.GetWorkspaceByID(ctx, input.WorkspaceID)
		if err != nil {
			return err
		}
		if ws.Status != domain.WorkspaceStatusReady {
			return domain.Conflict("WORKSPACE_NOT_READY", "workspace must be READY to submit a proposal")
		}
		if input.WorkspaceGeneration != ws.Generation {
			return domain.Conflict("WORKSPACE_GENERATION_MISMATCH", "workspace_generation does not match current workspace generation")
		}

		art, err := tx.GetArtifactByID(ctx, input.SnapshotArtifactID)
		if err != nil {
			return err
		}
		if art.DeletedAt != nil {
			return domain.Conflict("ARTIFACT_DELETED", "snapshot artifact has been deleted")
		}
		if art.Kind != domain.ArtifactKindEgressSnapshot {
			return domain.Unprocessable("INVALID_ARTIFACT_KIND", "snapshot artifact must have kind EGRESS_SNAPSHOT")
		}
		if art.WorkspaceID != nil && *art.WorkspaceID != ws.ID {
			return domain.Conflict("ARTIFACT_WORKSPACE_MISMATCH", "snapshot artifact belongs to a different workspace")
		}
		if art.WorkspaceGeneration != nil && *art.WorkspaceGeneration != input.WorkspaceGeneration {
			return domain.Conflict("WORKSPACE_GENERATION_MISMATCH", "snapshot artifact workspace_generation mismatch")
		}
		if !strings.EqualFold(art.SHA256, snapshotSHA) {
			return domain.Unprocessable("SNAPSHOT_DIGEST_MISMATCH", "snapshot sha256 does not match registered artifact digest")
		}
		if input.SizeBytes > 0 && art.SizeBytes != input.SizeBytes {
			return domain.Unprocessable("SNAPSHOT_SIZE_MISMATCH", "snapshot size_bytes does not match registered artifact size")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		propRow, err := tx.CreateProposal(ctx, persistence.CreateProposalParams{
			ID:                 propID,
			WorkspaceID:        ws.ID,
			OwnerID:            ws.OwnerID,
			SnapshotArtifactID: art.ID,
			BaseCommit:         ws.BaseCommit,
			TargetRef:          ws.TargetRef,
			Title:              title,
			Description:        input.Description,
			ProvenanceType:     provenanceType,
			CaptureMethod:      captureMethod,
			Status:             domain.ProposalStatusCaptured,
			Version:            1,
			CreatedAt:          now,
		})
		if err != nil {
			return err
		}

		op, err := operations.EnqueueTx(ctx, tx, operations.EnqueueInput{
			OperationType: domain.OperationTypeProposalReconstruct,
			ResourceType:  "proposal",
			ResourceID:    propRow.ID,
		}, s.metrics, s.logger)
		if err != nil {
			return err
		}

		payloadMap := map[string]any{
			"proposal_id":          propRow.ID.String(),
			"workspace_id":         propRow.WorkspaceID.String(),
			"owner_id":             propRow.OwnerID.String(),
			"snapshot_artifact_id": propRow.SnapshotArtifactID.String(),
			"snapshot_sha256":      snapshotSHA,
			"workspace_generation": ws.Generation,
			"operation_id":         op.ID.String(),
			"provenance_type":      provenanceType,
			"capture_method":       captureMethod,
			"status":               string(propRow.Status),
			"version":              propRow.Version,
		}
		if input.CapturedAt != nil && !input.CapturedAt.IsZero() {
			payloadMap["captured_at"] = input.CapturedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		}
		payload, err := marshalCanonicalPayload(payloadMap)
		if err != nil {
			return err
		}

		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.submitted",
			AggregateID: propRow.ID,
			Payload:     payload,
		}); err != nil {
			return err
		}

		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.submitted",
			ActorID:      input.ActorID,
			ResourceType: "proposal",
			ResourceID:   propRow.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		detailsRow, err := tx.GetProposalDetailsByID(ctx, propRow.ID)
		if err != nil {
			return err
		}

		result = SubmitResult{
			Proposal:  propRow.ToDomain(),
			Details:   detailsFromRow(detailsRow),
			Operation: op,
		}
		return nil
	})
	if err != nil {
		return SubmitResult{}, err
	}

	if s.logger != nil {
		l := observability.LoggerWithTrace(ctx, s.logger)
		l.InfoContext(ctx, "proposal submitted",
			"proposal_id", result.Proposal.ID.String(),
			"workspace_id", result.Proposal.WorkspaceID.String(),
			"owner_id", result.Proposal.OwnerID.String(),
			"operation_id", result.Operation.ID.String(),
			"snapshot_sha256", snapshotSHA,
			"status", string(result.Proposal.Status),
		)
	}
	return result, nil
}

// Get retrieves the domain.Proposal by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (domain.Proposal, error) {
	if s == nil || s.store == nil {
		return domain.Proposal{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if id == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "proposal id must not be nil")
	}
	row, err := s.store.GetProposalByID(ctx, id)
	if err != nil {
		return domain.Proposal{}, err
	}
	return row.ToDomain(), nil
}

// GetDetails retrieves enriched ProposalDetails by ID.
func (s *Service) GetDetails(ctx context.Context, id uuid.UUID) (ProposalDetails, error) {
	if s == nil || s.store == nil {
		return ProposalDetails{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if id == uuid.Nil {
		return ProposalDetails{}, domain.BadRequest("INVALID_ID", "proposal id must not be nil")
	}
	row, err := s.store.GetProposalDetailsByID(ctx, id)
	if err != nil {
		return ProposalDetails{}, err
	}
	return detailsFromRow(row), nil
}

// ListByWorkspace lists proposals belonging to workspaceID in newest-first order.
func (s *Service) ListByWorkspace(ctx context.Context, workspaceID uuid.UUID, limit int32) ([]ProposalDetails, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if workspaceID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "workspace_id must not be nil")
	}
	if limit < 0 {
		return nil, domain.BadRequest("INVALID_LIMIT", "limit must be non-negative")
	}
	if limit == 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := s.store.ListProposalDetailsByWorkspace(ctx, workspaceID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]ProposalDetails, 0, len(rows))
	for _, r := range rows {
		out = append(out, detailsFromRow(r))
	}
	return out, nil
}

// ListByOwner lists proposals owned by ownerID in newest-first order.
func (s *Service) ListByOwner(ctx context.Context, ownerID uuid.UUID, limit int32) ([]ProposalDetails, error) {
	if s == nil || s.store == nil {
		return nil, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if ownerID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "owner_id must not be nil")
	}
	if limit < 0 {
		return nil, domain.BadRequest("INVALID_LIMIT", "limit must be non-negative")
	}
	if limit == 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := s.store.ListProposalDetailsByOwner(ctx, persistence.ListProposalsByOwnerParams{
		OwnerID: ownerID,
		Limit:   int(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ProposalDetails, 0, len(rows))
	for _, r := range rows {
		out = append(out, detailsFromRow(r))
	}
	return out, nil
}

// BeginReconstruction transitions CAPTURED -> RECONSTRUCTING with optimistic version checking,
// and is crash-recovery idempotent when the proposal is already RECONSTRUCTING at ExpectedVersion.
func (s *Service) BeginReconstruction(ctx context.Context, input BeginReconstructionInput) (domain.Proposal, error) {
	if s == nil || s.store == nil {
		return domain.Proposal{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if input.ProposalID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if input.ExpectedVersion < 1 {
		return domain.Proposal{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	if input.ActorID != nil && *input.ActorID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}

	var out domain.Proposal
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, input.ProposalID)
		if err != nil {
			return err
		}
		if prop.Version != input.ExpectedVersion {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}
		if prop.Status == domain.ProposalStatusReconstructing {
			// Crash-recovery idempotent retry.
			out = prop.ToDomain()
			return nil
		}
		if prop.Status != domain.ProposalStatusCaptured {
			return domain.Conflict("INVALID_PROPOSAL_STATE", "proposal must be CAPTURED to begin reconstruction")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		fromStatus := domain.ProposalStatusCaptured
		updated, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
			ID:              prop.ID,
			FromStatus:      &fromStatus,
			ToStatus:        domain.ProposalStatusReconstructing,
			ExpectedVersion: input.ExpectedVersion,
			UpdatedAt:       now,
		})
		if err != nil {
			return err
		}

		payload, err := marshalCanonicalPayload(map[string]any{
			"proposal_id": updated.ID.String(),
			"from_status": string(prop.Status),
			"to_status":   string(updated.Status),
			"version":     updated.Version,
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.reconstructing",
			ActorID:      input.ActorID,
			ResourceType: "proposal",
			ResourceID:   updated.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		out = updated.ToDomain()
		return nil
	})
	return out, err
}

// CompleteReconstruction validates canonical reconstruction artifacts and digests, transitions
// CAPTURED|RECONSTRUCTING -> RECONSTRUCTED, and emits outbox and audit events.
func (s *Service) CompleteReconstruction(ctx context.Context, input CompleteReconstructionInput) (domain.Proposal, error) {
	if s == nil || s.store == nil {
		return domain.Proposal{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if input.ProposalID == uuid.Nil || input.CanonicalArtifactID == uuid.Nil || input.ManifestArtifactID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_RECONSTRUCTION", "proposal_id, canonical_artifact_id, and manifest_artifact_id are required")
	}
	if input.DiffArtifactID != nil && *input.DiffArtifactID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "diff_artifact_id must not be nil UUID when provided")
	}
	if input.ActorID != nil && *input.ActorID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}
	if input.ExpectedVersion < 1 {
		return domain.Proposal{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	treeDigest := strings.TrimSpace(input.TreeDigest)
	if len(treeDigest) < 40 || len(treeDigest) > 64 {
		return domain.Proposal{}, domain.BadRequest("INVALID_TREE_DIGEST", "tree_digest must be between 40 and 64 characters")
	}
	diffDigest, err := domain.ParseSHA256Digest(input.DiffDigest)
	if err != nil {
		return domain.Proposal{}, err
	}
	manifestDigest, err := domain.ParseSHA256Digest(input.ManifestDigest)
	if err != nil {
		return domain.Proposal{}, err
	}

	var out domain.Proposal
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, input.ProposalID)
		if err != nil {
			return err
		}
		if prop.Status != domain.ProposalStatusCaptured && prop.Status != domain.ProposalStatusReconstructing {
			return domain.Conflict("INVALID_PROPOSAL_STATE", "proposal must be CAPTURED or RECONSTRUCTING to complete reconstruction")
		}
		if prop.Version != input.ExpectedVersion {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}

		if err := verifyReconstructionArtifact(ctx, tx, input.CanonicalArtifactID, domain.ArtifactKindCanonicalTree, prop.WorkspaceID); err != nil {
			return err
		}
		if err := verifyReconstructionArtifact(ctx, tx, input.ManifestArtifactID, domain.ArtifactKindPublicationManifest, prop.WorkspaceID); err != nil {
			return err
		}
		if input.DiffArtifactID != nil {
			if err := verifyReconstructionArtifact(ctx, tx, *input.DiffArtifactID, domain.ArtifactKindCanonicalDiff, prop.WorkspaceID); err != nil {
				return err
			}
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		updated, err := tx.SetProposalReconstruction(ctx, persistence.SetProposalReconstructionParams{
			ID:                  prop.ID,
			CanonicalArtifactID: input.CanonicalArtifactID,
			DiffArtifactID:      input.DiffArtifactID,
			ManifestArtifactID:  input.ManifestArtifactID,
			TreeDigest:          treeDigest,
			DiffDigest:          diffDigest,
			ManifestDigest:      manifestDigest,
			Status:              domain.ProposalStatusReconstructed,
			ExpectedVersion:     input.ExpectedVersion,
			UpdatedAt:           now,
		})
		if err != nil {
			return err
		}

		payload, err := marshalCanonicalPayload(map[string]any{
			"proposal_id":          updated.ID.String(),
			"canonical_artifact":   input.CanonicalArtifactID.String(),
			"manifest_artifact_id": input.ManifestArtifactID.String(),
			"tree_digest":          treeDigest,
			"diff_digest":          diffDigest,
			"manifest_digest":      manifestDigest,
			"status":               string(updated.Status),
			"version":              updated.Version,
		})
		if err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.reconstructed",
			AggregateID: updated.ID,
			Payload:     payload,
		}); err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.reconstructed",
			ActorID:      input.ActorID,
			ResourceType: "proposal",
			ResourceID:   updated.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		out = updated.ToDomain()
		return nil
	})
	return out, err
}

// RequestEvaluation enforces optimistic concurrency, revokes any stale approvals if re-evaluating
// from PENDING_APPROVAL, transitions to EVALUATING, and enqueues PROPOSAL_EVALUATE.
func (s *Service) RequestEvaluation(ctx context.Context, input EvaluateInput) (EvaluateResult, error) {
	if s == nil || s.store == nil {
		return EvaluateResult{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if input.ProposalID == uuid.Nil {
		return EvaluateResult{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if input.ExpectedVersion < 1 {
		return EvaluateResult{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	if input.ActorID != nil && *input.ActorID == uuid.Nil {
		return EvaluateResult{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}

	var result EvaluateResult
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, input.ProposalID)
		if err != nil {
			return err
		}
		if prop.Version != input.ExpectedVersion {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}
		if !isEvaluationEligible(prop.Status) {
			return domain.Conflict("INVALID_PROPOSAL_STATE", "proposal is not eligible for evaluation in its current status")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		if prop.Status == domain.ProposalStatusPendingApproval {
			if _, err := approvals.RevokeStaleApprovalsTx(ctx, tx, prop.ID, prop.LatestPolicyEvaluationID, "proposal re-evaluation requested", now, s.logger); err != nil {
				return err
			}
		}

		fromStatus := prop.Status
		updated, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
			ID:              prop.ID,
			FromStatus:      &fromStatus,
			ToStatus:        domain.ProposalStatusEvaluating,
			ExpectedVersion: input.ExpectedVersion,
			UpdatedAt:       now,
		})
		if err != nil {
			return err
		}

		op, err := operations.EnqueueTx(ctx, tx, operations.EnqueueInput{
			OperationType: domain.OperationTypeProposalEvaluate,
			ResourceType:  "proposal",
			ResourceID:    updated.ID,
		}, s.metrics, s.logger)
		if err != nil {
			return err
		}

		payload, err := marshalCanonicalPayload(map[string]any{
			"proposal_id":  updated.ID.String(),
			"operation_id": op.ID.String(),
			"from_status":  string(fromStatus),
			"to_status":    string(updated.Status),
			"version":      updated.Version,
		})
		if err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.evaluation_requested",
			AggregateID: updated.ID,
			Payload:     payload,
		}); err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.evaluation_requested",
			ActorID:      input.ActorID,
			ResourceType: "proposal",
			ResourceID:   updated.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		result = EvaluateResult{
			Proposal:  updated.ToDomain(),
			Operation: op,
		}
		return nil
	})
	return result, err
}

// BeginEvaluation transitions an eligible proposal into EVALUATING with optimistic versioning,
// and is crash-recovery idempotent when the proposal is already EVALUATING at expectedVersion.
func (s *Service) BeginEvaluation(ctx context.Context, proposalID uuid.UUID, expectedVersion int64) (domain.Proposal, error) {
	if s == nil || s.store == nil {
		return domain.Proposal{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if proposalID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if expectedVersion < 1 {
		return domain.Proposal{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}

	var out domain.Proposal
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, proposalID)
		if err != nil {
			return err
		}
		if prop.Version != expectedVersion {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}
		if prop.Status == domain.ProposalStatusEvaluating {
			// Crash-recovery idempotent retry.
			out = prop.ToDomain()
			return nil
		}
		if !isEvaluationEligible(prop.Status) {
			return domain.Conflict("INVALID_PROPOSAL_STATE", "proposal is not eligible for evaluation in its current status")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		if prop.Status == domain.ProposalStatusPendingApproval {
			if _, err := approvals.RevokeStaleApprovalsTx(ctx, tx, prop.ID, prop.LatestPolicyEvaluationID, "proposal re-evaluation requested", now, s.logger); err != nil {
				return err
			}
		}

		fromStatus := prop.Status
		updated, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
			ID:              prop.ID,
			FromStatus:      &fromStatus,
			ToStatus:        domain.ProposalStatusEvaluating,
			ExpectedVersion: expectedVersion,
			UpdatedAt:       now,
		})
		if err != nil {
			return err
		}

		payload, err := marshalCanonicalPayload(map[string]any{
			"proposal_id": updated.ID.String(),
			"from_status": string(fromStatus),
			"to_status":   string(updated.Status),
			"version":     updated.Version,
		})
		if err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.evaluating",
			ResourceType: "proposal",
			ResourceID:   updated.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		out = updated.ToDomain()
		return nil
	})
	return out, err
}

// ApplyPolicyDecision persists the Stage C policy decision, revokes any stale approvals,
// deduplicates and stores approval_requirements when entering PENDING_APPROVAL, enforces the
// mandatory human approval invariant (ALLOW -> PENDING_APPROVAL), and emits outbox + audit events.
func (s *Service) ApplyPolicyDecision(ctx context.Context, input ApplyPolicyDecisionInput) (domain.Proposal, error) {
	if s == nil || s.store == nil {
		return domain.Proposal{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if input.ProposalID == uuid.Nil || input.PolicyBundleID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_POLICY_APPLICATION", "proposal_id and policy_bundle_id are required")
	}
	if input.OrgBundleID != nil && *input.OrgBundleID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "org_bundle_id must not be nil UUID when provided")
	}
	if input.RepoBundleID != nil && *input.RepoBundleID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "repo_bundle_id must not be nil UUID when provided")
	}
	if input.ActorID != nil && *input.ActorID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}
	if input.ExpectedVersion < 1 {
		return domain.Proposal{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	if !input.Effect.IsValid() {
		return domain.Proposal{}, domain.BadRequest("INVALID_POLICY_EFFECT", "invalid policy effect")
	}
	stage := strings.ToUpper(strings.TrimSpace(input.Stage))
	if stage == "" {
		stage = "EGRESS"
	}
	if stage != "EGRESS" && stage != "INGRESS" {
		return domain.Proposal{}, domain.BadRequest("INVALID_POLICY_STAGE", "stage must be INGRESS or EGRESS")
	}
	inputDigest, err := domain.ParseSHA256Digest(input.InputDigest)
	if err != nil {
		return domain.Proposal{}, err
	}

	targetStatus, err := statusForPolicyEffect(input.Effect)
	if err != nil {
		return domain.Proposal{}, err
	}
	dedupObligations, err := deduplicateObligations(input.Obligations)
	if err != nil {
		return domain.Proposal{}, err
	}

	var out domain.Proposal
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, input.ProposalID)
		if err != nil {
			return err
		}
		if prop.Status != domain.ProposalStatusEvaluating {
			return domain.Conflict("INVALID_PROPOSAL_STATE", "proposal must be EVALUATING to apply a policy decision")
		}
		if prop.Version != input.ExpectedVersion {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, err := approvals.RevokeStaleApprovalsTx(ctx, tx, prop.ID, prop.LatestPolicyEvaluationID, "new policy decision applied", now, s.logger); err != nil {
			return err
		}

		pd, err := tx.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
			ProposalID:     prop.ID,
			PolicyBundleID: input.PolicyBundleID,
			OrgBundleID:    input.OrgBundleID,
			RepoBundleID:   input.RepoBundleID,
			Stage:          stage,
			InputDigest:    inputDigest,
			Effect:         input.Effect,
			Reasons:        input.Reasons,
			Obligations:    dedupObligations,
			CreatedAt:      now,
		})
		if err != nil {
			return err
		}

		if targetStatus == domain.ProposalStatusPendingApproval {
			for _, ob := range dedupObligations {
				if _, err := tx.CreateApprovalRequirement(ctx, persistence.CreateApprovalRequirementParams{
					ProposalID:       prop.ID,
					PolicyDecisionID: pd.ID,
					RequirementType:  ob.Type,
					ReviewerGroup:    ob.ReviewerGroup,
					MinimumApprovals: ob.Minimum,
					CreatedAt:        now,
				}); err != nil {
					return err
				}
			}
		}

		updated, err := tx.ApplyProposalPolicyDecision(ctx, persistence.ApplyProposalPolicyDecisionParams{
			ID:                 prop.ID,
			PolicyEvaluationID: pd.ID,
			PolicyEffect:       input.Effect,
			Status:             targetStatus,
			ExpectedVersion:    input.ExpectedVersion,
			UpdatedAt:          now,
		})
		if err != nil {
			return err
		}

		payload, err := marshalCanonicalPayload(map[string]any{
			"proposal_id":        updated.ID.String(),
			"policy_decision_id": pd.ID.String(),
			"policy_bundle_id":   input.PolicyBundleID.String(),
			"stage":              stage,
			"input_digest":       inputDigest,
			"effect":             string(input.Effect),
			"status":             string(updated.Status),
			"version":            updated.Version,
		})
		if err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.policy_decided",
			AggregateID: updated.ID,
			Payload:     payload,
		}); err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.policy_decided",
			ActorID:      input.ActorID,
			ResourceType: "proposal",
			ResourceID:   updated.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		out = updated.ToDomain()
		return nil
	})
	if err != nil {
		return domain.Proposal{}, err
	}

	if s.metrics != nil {
		s.metrics.IncPolicyDecision(stage, string(input.Effect))
		if input.Effect.BlocksPublication() {
			scope := "ORG"
			if input.RepoBundleID != nil {
				scope = "REPO"
			}
			s.metrics.IncPolicyDenial(stage, scope)
		}
	}
	return out, nil
}

// MarkFailed transitions a non-terminal proposal to FAILED with optimistic version checking.
func (s *Service) MarkFailed(ctx context.Context, proposalID uuid.UUID, expectedVersion int64, reason string) (domain.Proposal, error) {
	if s == nil || s.store == nil {
		return domain.Proposal{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if proposalID == uuid.Nil {
		return domain.Proposal{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if expectedVersion < 1 {
		return domain.Proposal{}, domain.BadRequest("INVALID_VERSION", "expected_version must be >= 1")
	}
	safeReason := sanitizeReason(reason)

	var out domain.Proposal
	err := s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, proposalID)
		if err != nil {
			return err
		}
		if prop.Status.IsTerminal() {
			return domain.Conflict("INVALID_PROPOSAL_STATE", "cannot mark a terminal proposal as FAILED")
		}
		if prop.Version != expectedVersion {
			return domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version has changed")
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		fromStatus := prop.Status
		updated, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
			ID:              prop.ID,
			FromStatus:      &fromStatus,
			ToStatus:        domain.ProposalStatusFailed,
			ExpectedVersion: expectedVersion,
			UpdatedAt:       now,
		})
		if err != nil {
			return err
		}

		payload, err := marshalCanonicalPayload(map[string]any{
			"proposal_id": updated.ID.String(),
			"from_status": string(fromStatus),
			"to_status":   string(updated.Status),
			"reason":      safeReason,
			"version":     updated.Version,
		})
		if err != nil {
			return err
		}
		if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
			EventType:   "proposal.failed",
			AggregateID: updated.ID,
			Payload:     payload,
		}); err != nil {
			return err
		}
		if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
			EventType:    "proposal.failed",
			ResourceType: "proposal",
			ResourceID:   updated.ID,
			Payload:      payload,
			CreatedAt:    now,
		}, s.logger); err != nil {
			return err
		}

		out = updated.ToDomain()
		return nil
	})
	return out, err
}

// RequestPublish enforces approval, manifest digest, and policy readiness invariants (returning
// *PolicyDeniedError on policy-blocked states), ensures a single publication row, transitions
// APPROVED -> PUBLISHING, and enqueues PROPOSAL_PUBLISH (or idempotently returns existing
// publication/operation when already PUBLISHING or PUBLISHED with matching digest).
func (s *Service) RequestPublish(ctx context.Context, input PublishRequestInput) (PublishRequestResult, error) {
	if s == nil || s.store == nil {
		return PublishRequestResult{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if input.ProposalID == uuid.Nil {
		return PublishRequestResult{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if input.ActorID != nil && *input.ActorID == uuid.Nil {
		return PublishRequestResult{}, domain.BadRequest("INVALID_ACTOR_ID", "actor_id must not be nil UUID when provided")
	}
	manifestDigest, err := domain.ParseSHA256Digest(input.PublicationManifestDigest)
	if err != nil {
		return PublishRequestResult{}, err
	}

	var result PublishRequestResult
	err = s.store.RunInTx(ctx, func(tx TxStore) error {
		prop, err := tx.GetProposalByIDForUpdate(ctx, input.ProposalID)
		if err != nil {
			return err
		}

		if err := checkPolicyBlockedError(prop); err != nil {
			return err
		}

		switch prop.Status {
		case domain.ProposalStatusApproved:
			if prop.ManifestDigest == nil || *prop.ManifestDigest == "" || !strings.EqualFold(*prop.ManifestDigest, manifestDigest) {
				return domain.Conflict("STALE_MANIFEST_DIGEST", "publication_manifest_digest does not match proposal's current manifest digest")
			}
			if err := approvals.VerifyReadyForPublishTx(ctx, tx, prop); err != nil {
				return err
			}

			now := time.Now().UTC().Truncate(time.Microsecond)
			fromStatus := domain.ProposalStatusApproved
			updated, err := tx.TransitionProposalStatus(ctx, persistence.TransitionProposalStatusParams{
				ID:              prop.ID,
				FromStatus:      &fromStatus,
				ToStatus:        domain.ProposalStatusPublishing,
				ExpectedVersion: prop.Version,
				UpdatedAt:       now,
			})
			if err != nil {
				return err
			}

			pubRow, err := tx.EnsurePublication(ctx, persistence.CreatePublicationParams{
				ProposalID: updated.ID,
				BranchRef:  domain.ExpectedBranchName(updated.ID),
				Status:     domain.PublicationStatusPending,
				CreatedAt:  now,
			})
			if err != nil {
				return err
			}

			op, err := operations.EnqueueTx(ctx, tx, operations.EnqueueInput{
				OperationType: domain.OperationTypeProposalPublish,
				ResourceType:  "proposal",
				ResourceID:    updated.ID,
			}, s.metrics, s.logger)
			if err != nil {
				return err
			}

			payload, err := marshalCanonicalPayload(map[string]any{
				"proposal_id":     updated.ID.String(),
				"publication_id":  pubRow.ID.String(),
				"operation_id":    op.ID.String(),
				"manifest_digest": manifestDigest,
				"branch_ref":      pubRow.BranchRef,
				"status":          string(updated.Status),
				"version":         updated.Version,
			})
			if err != nil {
				return err
			}
			if _, err := operations.EnqueueOutboxTx(ctx, tx, operations.EnqueueOutboxInput{
				EventType:   "proposal.publish_requested",
				AggregateID: updated.ID,
				Payload:     payload,
			}); err != nil {
				return err
			}
			if _, err := audit.AppendTx(ctx, tx, audit.AppendInput{
				EventType:    "proposal.publish_requested",
				ActorID:      input.ActorID,
				ResourceType: "proposal",
				ResourceID:   updated.ID,
				Payload:      payload,
				CreatedAt:    now,
			}, s.logger); err != nil {
				return err
			}

			result = PublishRequestResult{
				Proposal:    updated.ToDomain(),
				Publication: pubRow.ToDomain(),
				Operation:   op,
			}
			return nil

		case domain.ProposalStatusPublishing, domain.ProposalStatusPublished:
			if prop.ManifestDigest == nil || *prop.ManifestDigest == "" || !strings.EqualFold(*prop.ManifestDigest, manifestDigest) {
				return domain.Conflict("STALE_MANIFEST_DIGEST", "publication_manifest_digest does not match proposal's current manifest digest")
			}
			if err := approvals.VerifyApprovalBindingTx(ctx, tx, prop); err != nil {
				return err
			}
			pubRow, err := tx.EnsurePublication(ctx, persistence.CreatePublicationParams{
				ProposalID: prop.ID,
				BranchRef:  domain.ExpectedBranchName(prop.ID),
				Status:     domain.PublicationStatusPending,
			})
			if err != nil {
				return err
			}
			opRow, err := tx.GetLatestOperationByResource(ctx, prop.ID, domain.OperationTypeProposalPublish)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					return domain.Conflict("PUBLICATION_IN_PROGRESS", "proposal is already publishing or published")
				}
				return err
			}
			result = PublishRequestResult{
				Proposal:    prop.ToDomain(),
				Publication: pubRow.ToDomain(),
				Operation:   operationDetailsFromRow(opRow),
			}
			return nil

		default:
			return domain.Conflict("INVALID_PROPOSAL_STATE", "proposal must be APPROVED to request publication")
		}
	})
	return result, err
}

// ListFindings lists scan runs and cursor-paginated findings for a proposal, enforcing
// redaction validation before returning any finding.
func (s *Service) ListFindings(ctx context.Context, filter ListFindingsFilter) (ListFindingsResult, error) {
	if s == nil || s.store == nil {
		return ListFindingsResult{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if filter.ProposalID == uuid.Nil {
		return ListFindingsResult{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	limit := filter.Limit
	if limit == 0 {
		limit = defaultFindingsLimit
	}
	if limit < 1 || limit > maxFindingsLimit {
		return ListFindingsResult{}, domain.BadRequest("INVALID_LIMIT", fmt.Sprintf("limit must be between 1 and %d", maxFindingsLimit))
	}
	if filter.Severity != nil && !filter.Severity.IsValid() {
		return ListFindingsResult{}, domain.BadRequest("INVALID_SEVERITY", "invalid finding severity")
	}
	var cursorID *uuid.UUID
	if strings.TrimSpace(filter.Cursor) != "" {
		id, err := decodeFindingCursor(filter.Cursor)
		if err != nil {
			return ListFindingsResult{}, err
		}
		cursorID = &id
	}

	if _, err := s.store.GetProposalByID(ctx, filter.ProposalID); err != nil {
		return ListFindingsResult{}, err
	}

	scanRunRows, err := s.store.ListScanRunsByProposal(ctx, filter.ProposalID)
	if err != nil {
		return ListFindingsResult{}, err
	}
	scanRuns := make([]domain.ScanRun, 0, len(scanRunRows))
	for _, sr := range scanRunRows {
		scanRuns = append(scanRuns, sr.ToDomain())
	}

	var scannerArg *string
	if sc := strings.TrimSpace(filter.Scanner); sc != "" {
		scannerArg = &sc
	}
	findingRows, err := s.store.ListFindingsByProposal(ctx, persistence.ListFindingsByProposalParams{
		ProposalID: filter.ProposalID,
		Scanner:    scannerArg,
		Severity:   filter.Severity,
		CursorID:   cursorID,
		Limit:      limit + 1,
	})
	if err != nil {
		return ListFindingsResult{}, err
	}

	hasMore := false
	nextCursor := ""
	if len(findingRows) > limit {
		hasMore = true
		findingRows = findingRows[:limit]
		nextCursor = encodeFindingCursor(findingRows[len(findingRows)-1].ID)
	}

	findings := make([]domain.Finding, 0, len(findingRows))
	for _, fr := range findingRows {
		f := fr.ToDomain()
		if err := f.ValidateRedacted(); err != nil {
			return ListFindingsResult{}, err
		}
		findings = append(findings, f)
	}

	return ListFindingsResult{
		ProposalID: filter.ProposalID,
		ScanRuns:   scanRuns,
		Findings:   findings,
		NextCursor: nextCursor,
		HasMore:    hasMore,
	}, nil
}

// ListAssessmentsAndDecisions returns model assessments and policy decisions for proposalID
// sorted in ascending chronological order (so [len-1] is always the latest entry).
func (s *Service) ListAssessmentsAndDecisions(ctx context.Context, proposalID uuid.UUID) (AssessmentsAndDecisions, error) {
	if s == nil || s.store == nil {
		return AssessmentsAndDecisions{}, domain.Unavailable("PROPOSALS_UNAVAILABLE", "proposals store is not configured")
	}
	if proposalID == uuid.Nil {
		return AssessmentsAndDecisions{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	if _, err := s.store.GetProposalByID(ctx, proposalID); err != nil {
		return AssessmentsAndDecisions{}, err
	}

	assessmentRows, err := s.store.ListModelAssessmentsByProposal(ctx, proposalID)
	if err != nil {
		return AssessmentsAndDecisions{}, err
	}
	decisionRows, err := s.store.ListPolicyDecisionsByProposal(ctx, proposalID)
	if err != nil {
		return AssessmentsAndDecisions{}, err
	}

	// Persistence returns DESC; reverse into ascending chronological order (CreatedAt ASC, ID ASC).
	assessments := make([]domain.ModelAssessment, 0, len(assessmentRows))
	for i := len(assessmentRows) - 1; i >= 0; i-- {
		assessments = append(assessments, assessmentRows[i].ToDomain())
	}
	decisions := make([]domain.PolicyDecision, 0, len(decisionRows))
	for i := len(decisionRows) - 1; i >= 0; i-- {
		decisions = append(decisions, decisionRows[i].ToDomain())
	}

	return AssessmentsAndDecisions{
		ProposalID:      proposalID,
		Assessments:     assessments,
		PolicyDecisions: decisions,
	}, nil
}

func checkPolicyBlockedError(prop persistence.ProposalRow) error {
	isBlockedStatus := prop.Status == domain.ProposalStatusDenied ||
		prop.Status == domain.ProposalStatusQuarantined ||
		prop.Status == domain.ProposalStatusRemediationRequired
	isBlockedEffect := prop.LatestPolicyEffect != nil && prop.LatestPolicyEffect.BlocksPublication()

	if !isBlockedStatus && !isBlockedEffect {
		return nil
	}

	effect := domain.PolicyEffectDeny
	if prop.LatestPolicyEffect != nil {
		effect = *prop.LatestPolicyEffect
	} else {
		switch prop.Status {
		case domain.ProposalStatusQuarantined:
			effect = domain.PolicyEffectQuarantine
		case domain.ProposalStatusRemediationRequired:
			effect = domain.PolicyEffectRequireRemediation
		}
	}

	code := "POLICY_DENIED"
	switch prop.Status {
	case domain.ProposalStatusQuarantined:
		code = "PROPOSAL_QUARANTINED"
	case domain.ProposalStatusRemediationRequired:
		code = "REMEDIATION_REQUIRED"
	}

	domErr := domain.Conflict(code, fmt.Sprintf("proposal is blocked by policy effect %s", effect))
	if prop.LatestPolicyEvaluationID != nil {
		return &PolicyDeniedError{
			PolicyDecisionID: *prop.LatestPolicyEvaluationID,
			Effect:           effect,
			ProposalStatus:   prop.Status,
			Err:              domErr,
		}
	}
	return domErr
}

func verifyReconstructionArtifact(ctx context.Context, tx TxStore, artifactID uuid.UUID, expectedKind domain.ArtifactKind, workspaceID uuid.UUID) error {
	art, err := tx.GetArtifactByID(ctx, artifactID)
	if err != nil {
		return err
	}
	if art.DeletedAt != nil {
		return domain.Conflict("ARTIFACT_DELETED", fmt.Sprintf("%s artifact has been deleted", expectedKind))
	}
	if art.Kind != expectedKind {
		return domain.Unprocessable("INVALID_ARTIFACT_KIND", fmt.Sprintf("expected artifact kind %s, got %s", expectedKind, art.Kind))
	}
	if art.WorkspaceID != nil && *art.WorkspaceID != workspaceID {
		return domain.Conflict("ARTIFACT_WORKSPACE_MISMATCH", "reconstruction artifact belongs to a different workspace")
	}
	return nil
}

func isEvaluationEligible(status domain.ProposalStatus) bool {
	return status == domain.ProposalStatusReconstructed ||
		status == domain.ProposalStatusRemediationRequired ||
		status == domain.ProposalStatusPendingApproval
}

func statusForPolicyEffect(effect domain.PolicyEffect) (domain.ProposalStatus, error) {
	switch effect {
	case domain.PolicyEffectDeny:
		return domain.ProposalStatusDenied, nil
	case domain.PolicyEffectQuarantine:
		return domain.ProposalStatusQuarantined, nil
	case domain.PolicyEffectRequireRemediation:
		return domain.ProposalStatusRemediationRequired, nil
	case domain.PolicyEffectRequireApproval, domain.PolicyEffectAllow:
		// RG-03: Mandatory human approval invariant — ALLOW still requires human approval.
		return domain.ProposalStatusPendingApproval, nil
	default:
		return "", domain.BadRequest("INVALID_POLICY_EFFECT", "invalid policy effect")
	}
}

func deduplicateObligations(obligations []domain.Obligation) ([]domain.Obligation, error) {
	type key struct {
		reqType string
		group   string
	}
	order := make([]key, 0, len(obligations))
	merged := make(map[key]domain.Obligation, len(obligations))
	for _, ob := range obligations {
		reqType := strings.TrimSpace(ob.Type)
		if reqType == "" {
			reqType = "HUMAN_REVIEW"
		}
		group := strings.TrimSpace(ob.ReviewerGroup)
		if group == "" {
			return nil, domain.BadRequest("INVALID_OBLIGATION", "obligation reviewer_group must not be empty")
		}
		min := ob.Minimum
		if min < 1 {
			min = 1
		}
		k := key{reqType: reqType, group: group}
		if existing, ok := merged[k]; ok {
			if min > existing.Minimum {
				existing.Minimum = min
				merged[k] = existing
			}
			continue
		}
		order = append(order, k)
		merged[k] = domain.Obligation{
			Type:          reqType,
			ReviewerGroup: group,
			Minimum:       min,
		}
	}
	out := make([]domain.Obligation, 0, len(order))
	for _, k := range order {
		out = append(out, merged[k])
	}
	return out, nil
}

func normalizeProvenanceType(v string) (string, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "agent_assisted", nil
	}
	switch trimmed {
	case "agent_assisted", "human_authored":
		return trimmed, nil
	default:
		return "", domain.BadRequest("INVALID_PROVENANCE_TYPE", "provenance_type must be agent_assisted or human_authored")
	}
}

func normalizeCaptureMethod(v string) (string, error) {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return "frozen_filesystem", nil
	}
	switch trimmed {
	case "frozen_filesystem", "patch_upload":
		return trimmed, nil
	default:
		return "", domain.BadRequest("INVALID_CAPTURE_METHOD", "capture_method must be frozen_filesystem or patch_upload")
	}
}

func sanitizeReason(reason string) string {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return "operation failed"
	}
	if len(trimmed) > maxReasonLen {
		return trimmed[:maxReasonLen]
	}
	return trimmed
}

func detailsFromRow(row persistence.ProposalDetailsRow) ProposalDetails {
	return ProposalDetails{
		Proposal:                 row.Proposal.ToDomain(),
		RepositoryID:             row.RepositoryID,
		GitHubRepositoryID:       row.GitHubRepositoryID,
		RepositoryFullName:       row.RepositoryFullName,
		RepositoryClassification: row.RepositoryClassification,
		WorkspaceAgentID:         row.WorkspaceAgentID,
		WorkspaceAgentSessionID:  derefString(row.WorkspaceAgentSessionID),
		WorkspaceModelRoute:      derefString(row.WorkspaceModelRoute),
		WorkspaceGeneration:      row.WorkspaceGeneration,
		Owner: OwnerRef{
			PrincipalID:      row.Proposal.OwnerID,
			Kind:             row.OwnerKind,
			IdentityProvider: derefString(row.OwnerIssuer),
			Subject:          derefString(row.OwnerSubject),
			DisplayName:      derefString(row.OwnerDisplayName),
		},
		DiffArtifactID:           row.Proposal.DiffArtifactID,
		ProvenanceType:           row.Proposal.ProvenanceType,
		CaptureMethod:            row.Proposal.CaptureMethod,
		TreeDigest:               derefString(row.Proposal.TreeDigest),
		DiffDigest:               derefString(row.Proposal.DiffDigest),
		LatestPolicyEvaluationID: row.Proposal.LatestPolicyEvaluationID,
		LatestPolicyEffect:       row.Proposal.LatestPolicyEffect,
		UpdatedAt:                row.Proposal.UpdatedAt.UTC(),
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

func encodeFindingCursor(id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte("id:" + id.String()))
}

func decodeFindingCursor(cursor string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(cursor)
	if id, err := uuid.Parse(trimmed); err == nil {
		if id == uuid.Nil {
			return uuid.Nil, domain.BadRequest("INVALID_CURSOR", "cursor id must not be nil")
		}
		return id, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return uuid.Nil, domain.BadRequest("INVALID_CURSOR", "malformed findings pagination cursor")
	}
	s := string(decoded)
	if !strings.HasPrefix(s, "id:") {
		return uuid.Nil, domain.BadRequest("INVALID_CURSOR", "invalid findings pagination cursor")
	}
	id, err := uuid.Parse(strings.TrimPrefix(s, "id:"))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, domain.BadRequest("INVALID_CURSOR", "invalid findings pagination cursor id")
	}
	return id, nil
}

func marshalCanonicalPayload(v any) (json.RawMessage, error) {
	canonical, err := domain.CanonicalJSONBytes(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
