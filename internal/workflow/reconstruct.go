package workflow

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/proposals"
)

// ReconstructResult records the outcome of a PROPOSAL_RECONSTRUCT operation.
type ReconstructResult struct {
	ProposalID         uuid.UUID `json:"proposal_id"`
	CanonicalArtifact  uuid.UUID `json:"canonical_artifact_id"`
	DiffArtifactID     uuid.UUID `json:"diff_artifact_id,omitempty"`
	ManifestArtifactID uuid.UUID `json:"manifest_artifact_id"`
	TreeDigest         string    `json:"tree_digest"`
	DiffDigest         string    `json:"diff_digest"`
	ManifestDigest     string    `json:"manifest_digest"`
	Status             string    `json:"status"`
	Version            int64     `json:"version"`
	Idempotent         bool      `json:"idempotent,omitempty"`
}

// ExecuteReconstruct runs the PROPOSAL_RECONSTRUCT workflow for the given operation.
func (s *Service) ExecuteReconstruct(ctx context.Context, op operations.OperationDetails) (ReconstructResult, error) {
	ctx = s.ensureOperationLeaseContext(ctx, op)
	if s == nil || s.proposals == nil || s.repositories == nil || s.artifacts == nil {
		return ReconstructResult{}, domain.Unavailable("WORKFLOW_UNAVAILABLE", "workflow service dependencies are not configured")
	}
	if s.reconstructor == nil {
		return ReconstructResult{}, domain.Unavailable("RECONSTRUCTOR_UNAVAILABLE", "reconstructor is not configured")
	}

	details, err := s.proposals.GetDetails(ctx, op.ResourceID)
	if err != nil {
		return ReconstructResult{}, err
	}

	if isAlreadyReconstructed(details) {
		var diffID uuid.UUID
		if details.DiffArtifactID != nil {
			diffID = *details.DiffArtifactID
		}
		return ReconstructResult{
			ProposalID:         details.ID,
			CanonicalArtifact:  *details.CanonicalArtifactID,
			DiffArtifactID:     diffID,
			ManifestArtifactID: *details.ManifestArtifactID,
			TreeDigest:         details.TreeDigest,
			DiffDigest:         details.DiffDigest,
			ManifestDigest:     details.ManifestDigest,
			Status:             string(details.Status),
			Version:            details.Version,
			Idempotent:         true,
		}, nil
	}
	if details.Status.IsTerminal() {
		return ReconstructResult{}, domain.Conflict("PROPOSAL_TERMINAL", "proposal is already in a terminal status")
	}

	releaseRepo, err := s.budgets.AcquireRepo(ctx, details.RepositoryID)
	if err != nil {
		return ReconstructResult{}, err
	}
	defer releaseRepo()

	repoRec, err := s.repositories.RequireEnabled(ctx, details.RepositoryID)
	if err != nil {
		return ReconstructResult{}, err
	}

	prop, err := s.proposals.BeginReconstruction(ctx, proposals.BeginReconstructionInput{
		ProposalID:      details.ID,
		ExpectedVersion: details.Version,
	})
	if err != nil {
		return ReconstructResult{}, err
	}

	snapArt, err := s.artifacts.GetByID(ctx, details.SnapshotArtifactID)
	if err != nil {
		return ReconstructResult{}, err
	}
	if snapArt.DeletedAt != nil {
		return ReconstructResult{}, domain.Conflict("ARTIFACT_DELETED", "egress snapshot artifact has been deleted")
	}

	// ReconstructDetailed writes CANONICAL_TREE, CANONICAL_DIFF, and PUBLICATION_MANIFEST
	// blobs to SnapshotStore; it does NOT register them in PostgreSQL.
	if err := s.verifyOperationLease(ctx); err != nil {
		return ReconstructResult{}, err
	}
	reconRes, err := s.reconstructor.ReconstructDetailed(ctx, repoRec.Repository, details.BaseCommit, snapArt.Artifact)
	if err != nil {
		return ReconstructResult{}, err
	}

	change := reconRes.Change
	if change.ManifestArtifact == nil {
		return ReconstructResult{}, domain.Internal("MISSING_MANIFEST_ARTIFACT", "reconstruction did not produce a publication manifest artifact")
	}

	if err := s.verifyOperationLease(ctx); err != nil {
		return ReconstructResult{}, err
	}
	// Register all 3 reconstructed artifacts in PostgreSQL with configurable retention TTL.
	treeArt, err := s.registerReconstructedArtifact(ctx, change.Artifact, "application/gzip", details)
	if err != nil {
		return ReconstructResult{}, err
	}
	manifestArt, err := s.registerReconstructedArtifact(ctx, *change.ManifestArtifact, "application/json", details)
	if err != nil {
		return ReconstructResult{}, err
	}
	var diffArtifactID *uuid.UUID
	if change.DiffArtifact != nil {
		diffArt, err := s.registerReconstructedArtifact(ctx, *change.DiffArtifact, "text/plain; charset=utf-8", details)
		if err != nil {
			return ReconstructResult{}, err
		}
		diffArtifactID = &diffArt.ID
	}

	completed, err := s.proposals.CompleteReconstruction(ctx, proposals.CompleteReconstructionInput{
		ProposalID:          details.ID,
		ExpectedVersion:     prop.Version,
		CanonicalArtifactID: treeArt.ID,
		DiffArtifactID:      diffArtifactID,
		ManifestArtifactID:  manifestArt.ID,
		TreeDigest:          change.TreeDigest,
		DiffDigest:          change.DiffDigest,
		ManifestDigest:      change.ManifestDigest,
	})
	if err != nil {
		return ReconstructResult{}, err
	}

	var diffID uuid.UUID
	if diffArtifactID != nil {
		diffID = *diffArtifactID
	}

	if s.logger != nil {
		observability.LoggerWithTrace(ctx, s.logger).InfoContext(ctx, "proposal reconstruction completed",
			"proposal_id", completed.ID.String(),
			"canonical_artifact_id", treeArt.ID.String(),
			"manifest_artifact_id", manifestArt.ID.String(),
			"tree_digest", change.TreeDigest,
			"diff_digest", change.DiffDigest,
			"manifest_digest", change.ManifestDigest,
			"status", string(completed.Status),
		)
	}

	return ReconstructResult{
		ProposalID:         completed.ID,
		CanonicalArtifact:  treeArt.ID,
		DiffArtifactID:     diffID,
		ManifestArtifactID: manifestArt.ID,
		TreeDigest:         change.TreeDigest,
		DiffDigest:         change.DiffDigest,
		ManifestDigest:     change.ManifestDigest,
		Status:             string(completed.Status),
		Version:            completed.Version,
	}, nil
}

func (s *Service) registerReconstructedArtifact(ctx context.Context, art domain.Artifact, format string, details proposals.ProposalDetails) (artifacts.Record, error) {
	id := art.ID
	if id == uuid.Nil || !domain.IsUUIDv7(id) {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return artifacts.Record{}, err
		}
	}
	wsID := details.WorkspaceID
	wsGen := details.WorkspaceGeneration
	uploadedBy := details.OwnerID

	var expiresAt *time.Time
	if s.cfg.ArtifactRetentionTTL > 0 {
		t := s.now().Add(s.cfg.ArtifactRetentionTTL).UTC().Truncate(time.Microsecond)
		expiresAt = &t
	}

	reg, err := s.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                  id,
		Kind:                art.Kind,
		SHA256:              art.SHA256,
		StorageKey:          art.StorageKey,
		StorageGeneration:   art.StorageGeneration,
		SizeBytes:           art.SizeBytes,
		Format:              format,
		WorkspaceID:         &wsID,
		WorkspaceGeneration: &wsGen,
		UploadedBy:          &uploadedBy,
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			existing, lookupErr := s.artifacts.GetByStorageObject(ctx, art.StorageKey, art.StorageGeneration)
			if lookupErr == nil {
				return existing, nil
			}
		}
		return artifacts.Record{}, err
	}
	return reg, nil
}

func isAlreadyReconstructed(details proposals.ProposalDetails) bool {
	if details.CanonicalArtifactID == nil || details.ManifestArtifactID == nil {
		return false
	}
	switch details.Status {
	case domain.ProposalStatusReconstructed,
		domain.ProposalStatusEvaluating,
		domain.ProposalStatusPendingApproval,
		domain.ProposalStatusRemediationRequired,
		domain.ProposalStatusApproved,
		domain.ProposalStatusPublishing,
		domain.ProposalStatusPublished,
		domain.ProposalStatusDenied,
		domain.ProposalStatusQuarantined,
		domain.ProposalStatusRejected:
		return true
	default:
		return false
	}
}
