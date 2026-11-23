package proposals

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

// TxStore defines all persistence methods usable inside a proposals transaction.
type TxStore interface {
	GetWorkspaceByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error)
	GetWorkspaceDetailsByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceDetailsRow, error)
	GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error)

	CreateProposal(ctx context.Context, arg persistence.CreateProposalParams) (persistence.ProposalRow, error)
	GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error)
	GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error)
	GetProposalDetailsByID(ctx context.Context, id uuid.UUID) (persistence.ProposalDetailsRow, error)
	TransitionProposalStatus(ctx context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error)
	SetProposalReconstruction(ctx context.Context, arg persistence.SetProposalReconstructionParams) (persistence.ProposalRow, error)
	ApplyProposalPolicyDecision(ctx context.Context, arg persistence.ApplyProposalPolicyDecisionParams) (persistence.ProposalRow, error)

	CreatePolicyDecision(ctx context.Context, arg persistence.CreatePolicyDecisionParams) (persistence.PolicyDecisionRow, error)
	CreateApprovalRequirement(ctx context.Context, arg persistence.CreateApprovalRequirementParams) (persistence.ApprovalRequirementRow, error)
	ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error)
	ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error)
	RevokeApprovalsForProposal(ctx context.Context, proposalID uuid.UUID, revokedAt time.Time) (int64, error)
	ResetApprovalRequirementsForPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) (int64, error)
	EnsurePublication(ctx context.Context, arg persistence.CreatePublicationParams) (persistence.PublicationRow, error)
	GetLatestOperationByResource(ctx context.Context, resourceID uuid.UUID, opType domain.OperationType) (persistence.OperationRow, error)

	operations.TxStore
	audit.ChainStore
}

// Store defines the persistence operations and transaction runner required by the proposals service.
type Store interface {
	TxStore
	ListProposalDetailsByWorkspace(ctx context.Context, workspaceID uuid.UUID, limit int32) ([]persistence.ProposalDetailsRow, error)
	ListProposalDetailsByOwner(ctx context.Context, arg persistence.ListProposalsByOwnerParams) ([]persistence.ProposalDetailsRow, error)
	ListScanRunsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ScanRunRow, error)
	ListFindingsByProposal(ctx context.Context, arg persistence.ListFindingsByProposalParams) ([]persistence.FindingRow, error)
	ListModelAssessmentsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ModelAssessmentRow, error)
	ListPolicyDecisionsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.PolicyDecisionRow, error)
	RunInTx(ctx context.Context, fn func(tx TxStore) error) error
}

type persistenceStoreAdapter struct {
	*persistence.Store
}

// NewStoreAdapter wraps *persistence.Store to satisfy proposals.Store.
func NewStoreAdapter(store *persistence.Store) Store {
	return &persistenceStoreAdapter{Store: store}
}

func (a *persistenceStoreAdapter) RunInTx(ctx context.Context, fn func(tx TxStore) error) error {
	return a.Store.WithTx(ctx, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}
