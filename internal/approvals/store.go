package approvals

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
)

// PublishVerifyStore is the minimal read subset needed to verify approval readiness for publication.
type PublishVerifyStore interface {
	ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error)
	ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error)
}

// RevokeStore is the minimal persistence subset needed to revoke stale approvals and emit audit/outbox events.
type RevokeStore interface {
	RevokeApprovalsForProposal(ctx context.Context, proposalID uuid.UUID, revokedAt time.Time) (int64, error)
	ResetApprovalRequirementsForPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) (int64, error)
	operations.TxStore
	audit.ChainStore
}

// TxStore defines all persistence methods usable inside an approvals transaction.
type TxStore interface {
	GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error)
	GetPrincipalByID(ctx context.Context, id uuid.UUID) (persistence.PrincipalRow, error)
	CreateApproval(ctx context.Context, arg persistence.CreateApprovalParams) (persistence.ApprovalRow, error)
	ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error)
	HasActiveApprovalByReviewer(ctx context.Context, proposalID, policyDecisionID, reviewerID uuid.UUID, manifestDigest string) (bool, error)
	RevokeApprovalsForProposal(ctx context.Context, proposalID uuid.UUID, revokedAt time.Time) (int64, error)
	ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error)
	IncrementApprovalRequirementSatisfaction(ctx context.Context, id uuid.UUID, now time.Time) (persistence.ApprovalRequirementRow, error)
	ResetApprovalRequirementsForPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) (int64, error)
	TransitionProposalStatus(ctx context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error)
	operations.TxStore
	audit.ChainStore
}

// Store defines the persistence operations and transaction runner required by the approvals service.
type Store interface {
	TxStore
	GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error)
	ListApprovalsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRow, error)
	ListApprovalRequirementsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRequirementRow, error)
	RunInTx(ctx context.Context, fn func(tx TxStore) error) error
}

type persistenceStoreAdapter struct {
	*persistence.Store
}

// NewStoreAdapter wraps *persistence.Store to satisfy approvals.Store.
func NewStoreAdapter(store *persistence.Store) Store {
	return &persistenceStoreAdapter{Store: store}
}

func (a *persistenceStoreAdapter) RunInTx(ctx context.Context, fn func(tx TxStore) error) error {
	return a.Store.WithTx(ctx, func(tx *persistence.Tx) error {
		return fn(tx)
	})
}
