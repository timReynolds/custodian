package publication

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

// TxStore defines all persistence operations usable inside a publication transaction.
type TxStore interface {
	GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error)
	GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error)
	GetProposalDetailsByID(ctx context.Context, id uuid.UUID) (persistence.ProposalDetailsRow, error)
	TransitionProposalStatus(ctx context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error)
	GetWorkspaceByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error)
	GetRepositoryByID(ctx context.Context, id uuid.UUID) (persistence.RepositoryRow, error)
	GetPrincipalByID(ctx context.Context, id uuid.UUID) (persistence.PrincipalRow, error)
	GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error)
	GetPolicyDecisionByID(ctx context.Context, id uuid.UUID) (persistence.PolicyDecisionRow, error)
	GetLatestPolicyDecisionForProposal(ctx context.Context, proposalID uuid.UUID) (persistence.PolicyDecisionRow, error)
	ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error)
	ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error)
	ListApprovalsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRow, error)
	EnsurePublication(ctx context.Context, arg persistence.CreatePublicationParams) (persistence.PublicationRow, error)
	GetPublicationByID(ctx context.Context, id uuid.UUID) (persistence.PublicationRow, error)
	GetPublicationByProposalID(ctx context.Context, proposalID uuid.UUID) (persistence.PublicationRow, error)
	BeginPublicationAttempt(ctx context.Context, arg persistence.BeginPublicationAttemptParams) (persistence.PublicationRow, persistence.PublicationAttemptRow, error)
	MarkPublicationPublished(ctx context.Context, arg persistence.MarkPublicationPublishedParams) (persistence.PublicationRow, error)
	MarkPublicationFailed(ctx context.Context, id uuid.UUID, updatedAt time.Time) (persistence.PublicationRow, error)
	ListPublicationAttemptsByPublication(ctx context.Context, publicationID uuid.UUID) ([]persistence.PublicationAttemptRow, error)
	CompletePublicationAttemptSucceeded(ctx context.Context, id uuid.UUID, commitSHA string, completedAt time.Time) (persistence.PublicationAttemptRow, error)
	CompletePublicationAttemptFailed(ctx context.Context, id uuid.UUID, errorCode, errorMessage string, completedAt time.Time) (persistence.PublicationAttemptRow, error)
	GetOperationByID(ctx context.Context, id uuid.UUID) (persistence.OperationRow, error)
	GetLatestOperationByResource(ctx context.Context, resourceID uuid.UUID, opType domain.OperationType) (persistence.OperationRow, error)
	operations.TxStore
	audit.ChainStore
}

// Store defines the persistence operations and transaction runner required by the publication service.
type Store interface {
	TxStore
	RunInTx(ctx context.Context, fn func(tx TxStore) error) error
}

type persistenceStoreAdapter struct {
	*persistence.Store
}

// NewStoreAdapter wraps *persistence.Store to satisfy publication.Store.
func NewStoreAdapter(store *persistence.Store) Store {
	if store == nil {
		return nil
	}
	return &persistenceStoreAdapter{Store: store}
}

func (a *persistenceStoreAdapter) RunInTx(ctx context.Context, fn func(tx TxStore) error) error {
	return a.Store.WithTx(ctx, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}
