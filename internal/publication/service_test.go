package publication_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/publish"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/publication"
)

type memStore struct {
	mu          sync.Mutex
	proposals   map[uuid.UUID]persistence.ProposalRow
	workspaces  map[uuid.UUID]persistence.WorkspaceRow
	repos       map[uuid.UUID]persistence.RepositoryRow
	principals  map[uuid.UUID]persistence.PrincipalRow
	artifacts   map[uuid.UUID]persistence.ArtifactRow
	decisions   map[uuid.UUID]persistence.PolicyDecisionRow
	reqs        map[uuid.UUID][]persistence.ApprovalRequirementRow
	approvals   map[uuid.UUID][]persistence.ApprovalRow
	pubsByID    map[uuid.UUID]persistence.PublicationRow
	pubsByProp  map[uuid.UUID]uuid.UUID
	attempts    map[uuid.UUID][]persistence.PublicationAttemptRow
	ops         map[uuid.UUID]persistence.OperationRow
	outbox      []persistence.OutboxEventRow
	auditEvents []persistence.AuditEventRow
	auditHead   persistence.AuditChainHeadRow
	renewCalls  atomic.Int32
}

func newMemStore() *memStore {
	return &memStore{
		proposals:  make(map[uuid.UUID]persistence.ProposalRow),
		workspaces: make(map[uuid.UUID]persistence.WorkspaceRow),
		repos:      make(map[uuid.UUID]persistence.RepositoryRow),
		principals: make(map[uuid.UUID]persistence.PrincipalRow),
		artifacts:  make(map[uuid.UUID]persistence.ArtifactRow),
		decisions:  make(map[uuid.UUID]persistence.PolicyDecisionRow),
		reqs:       make(map[uuid.UUID][]persistence.ApprovalRequirementRow),
		approvals:  make(map[uuid.UUID][]persistence.ApprovalRow),
		pubsByID:   make(map[uuid.UUID]persistence.PublicationRow),
		pubsByProp: make(map[uuid.UUID]uuid.UUID),
		attempts:   make(map[uuid.UUID][]persistence.PublicationAttemptRow),
		ops:        make(map[uuid.UUID]persistence.OperationRow),
		auditHead:  persistence.AuditChainHeadRow{ChainID: "default"},
	}
}

func (m *memStore) cloneState() *memStore {
	cp := newMemStore()
	for k, v := range m.proposals {
		cp.proposals[k] = v
	}
	for k, v := range m.workspaces {
		cp.workspaces[k] = v
	}
	for k, v := range m.repos {
		cp.repos[k] = v
	}
	for k, v := range m.principals {
		cp.principals[k] = v
	}
	for k, v := range m.artifacts {
		cp.artifacts[k] = v
	}
	for k, v := range m.decisions {
		cp.decisions[k] = v
	}
	for k, v := range m.reqs {
		cp.reqs[k] = slices.Clone(v)
	}
	for k, v := range m.approvals {
		cp.approvals[k] = slices.Clone(v)
	}
	for k, v := range m.pubsByID {
		cp.pubsByID[k] = v
	}
	for k, v := range m.pubsByProp {
		cp.pubsByProp[k] = v
	}
	for k, v := range m.attempts {
		cp.attempts[k] = slices.Clone(v)
	}
	for k, v := range m.ops {
		cp.ops[k] = v
	}
	cp.outbox = slices.Clone(m.outbox)
	cp.auditEvents = slices.Clone(m.auditEvents)
	cp.auditHead = m.auditHead
	return cp
}

func (m *memStore) restoreFrom(cp *memStore) {
	m.proposals = cp.proposals
	m.workspaces = cp.workspaces
	m.repos = cp.repos
	m.principals = cp.principals
	m.artifacts = cp.artifacts
	m.decisions = cp.decisions
	m.reqs = cp.reqs
	m.approvals = cp.approvals
	m.pubsByID = cp.pubsByID
	m.pubsByProp = cp.pubsByProp
	m.attempts = cp.attempts
	m.ops = cp.ops
	m.outbox = cp.outbox
	m.auditEvents = cp.auditEvents
	m.auditHead = cp.auditHead
}

type memTx struct {
	m *memStore
}

func (m *memStore) RunInTx(_ context.Context, fn func(tx publication.TxStore) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := m.cloneState()
	if err := fn(&memTx{m: m}); err != nil {
		m.restoreFrom(snap)
		return err
	}
	return nil
}

func (t *memTx) GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	return t.m.getProposalByIDLocked(ctx, id)
}
func (t *memTx) GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	return t.m.getProposalByIDLocked(ctx, id)
}
func (t *memTx) GetOperationByID(ctx context.Context, id uuid.UUID) (persistence.OperationRow, error) {
	return t.m.getOperationByIDLocked(ctx, id)
}
func (t *memTx) GetLatestOperationByResource(ctx context.Context, resourceID uuid.UUID, opType domain.OperationType) (persistence.OperationRow, error) {
	return t.m.getLatestOperationByResourceLocked(ctx, resourceID, opType)
}
func (t *memTx) GetProposalDetailsByID(ctx context.Context, id uuid.UUID) (persistence.ProposalDetailsRow, error) {
	return t.m.getProposalDetailsByIDLocked(ctx, id)
}
func (t *memTx) TransitionProposalStatus(ctx context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error) {
	return t.m.transitionProposalStatusLocked(ctx, arg)
}
func (t *memTx) GetWorkspaceByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error) {
	return t.m.getWorkspaceByIDLocked(ctx, id)
}
func (t *memTx) GetRepositoryByID(ctx context.Context, id uuid.UUID) (persistence.RepositoryRow, error) {
	return t.m.getRepositoryByIDLocked(ctx, id)
}
func (t *memTx) GetPrincipalByID(ctx context.Context, id uuid.UUID) (persistence.PrincipalRow, error) {
	return t.m.getPrincipalByIDLocked(ctx, id)
}
func (t *memTx) GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
	return t.m.getArtifactByIDLocked(ctx, id)
}
func (t *memTx) GetPolicyDecisionByID(ctx context.Context, id uuid.UUID) (persistence.PolicyDecisionRow, error) {
	return t.m.getPolicyDecisionByIDLocked(ctx, id)
}
func (t *memTx) GetLatestPolicyDecisionForProposal(ctx context.Context, proposalID uuid.UUID) (persistence.PolicyDecisionRow, error) {
	return t.m.getLatestPolicyDecisionForProposalLocked(ctx, proposalID)
}
func (t *memTx) ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	return t.m.listApprovalRequirementsByPolicyDecisionLocked(ctx, policyDecisionID)
}
func (t *memTx) ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error) {
	return t.m.listActiveApprovalsForDecisionLocked(ctx, proposalID, policyDecisionID, manifestDigest)
}
func (t *memTx) ListApprovalsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRow, error) {
	return t.m.listApprovalsByProposalLocked(ctx, proposalID)
}
func (t *memTx) EnsurePublication(ctx context.Context, arg persistence.CreatePublicationParams) (persistence.PublicationRow, error) {
	return t.m.ensurePublicationLocked(ctx, arg)
}
func (t *memTx) GetPublicationByID(ctx context.Context, id uuid.UUID) (persistence.PublicationRow, error) {
	return t.m.getPublicationByIDLocked(ctx, id)
}
func (t *memTx) GetPublicationByProposalID(ctx context.Context, proposalID uuid.UUID) (persistence.PublicationRow, error) {
	return t.m.getPublicationByProposalIDLocked(ctx, proposalID)
}
func (t *memTx) BeginPublicationAttempt(ctx context.Context, arg persistence.BeginPublicationAttemptParams) (persistence.PublicationRow, persistence.PublicationAttemptRow, error) {
	return t.m.beginPublicationAttemptLocked(ctx, arg)
}
func (t *memTx) MarkPublicationPublished(ctx context.Context, arg persistence.MarkPublicationPublishedParams) (persistence.PublicationRow, error) {
	return t.m.markPublicationPublishedLocked(ctx, arg)
}
func (t *memTx) MarkPublicationFailed(ctx context.Context, id uuid.UUID, updatedAt time.Time) (persistence.PublicationRow, error) {
	return t.m.markPublicationFailedLocked(ctx, id, updatedAt)
}
func (t *memTx) ListPublicationAttemptsByPublication(ctx context.Context, publicationID uuid.UUID) ([]persistence.PublicationAttemptRow, error) {
	return t.m.listPublicationAttemptsByPublicationLocked(ctx, publicationID)
}
func (t *memTx) CompletePublicationAttemptSucceeded(ctx context.Context, id uuid.UUID, commitSHA string, completedAt time.Time) (persistence.PublicationAttemptRow, error) {
	return t.m.completePublicationAttemptSucceededLocked(ctx, id, commitSHA, completedAt)
}
func (t *memTx) CompletePublicationAttemptFailed(ctx context.Context, id uuid.UUID, errorCode, errorMessage string, completedAt time.Time) (persistence.PublicationAttemptRow, error) {
	return t.m.completePublicationAttemptFailedLocked(ctx, id, errorCode, errorMessage, completedAt)
}
func (t *memTx) EnqueueOperation(ctx context.Context, arg persistence.EnqueueOperationParams) (persistence.OperationRow, error) {
	return t.m.enqueueOperationLocked(ctx, arg)
}
func (t *memTx) EnqueueOutboxEvent(ctx context.Context, arg persistence.EnqueueOutboxParams) (persistence.OutboxEventRow, error) {
	return t.m.enqueueOutboxEventLocked(ctx, arg)
}
func (t *memTx) LockAuditChainHead(ctx context.Context) (persistence.AuditChainHeadRow, error) {
	return t.m.auditHead, nil
}
func (t *memTx) NormalizeJSONB(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	return t.m.NormalizeJSONB(ctx, payload)
}
func (t *memTx) UpdateAuditChainHead(ctx context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error {
	return t.m.updateAuditChainHeadLocked(ctx, eventID, eventHash, eventCount, updatedAt)
}
func (t *memTx) InsertAuditEvent(ctx context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	return t.m.insertAuditEventLocked(ctx, arg)
}

func (m *memStore) GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getProposalByIDLocked(ctx, id)
}
func (m *memStore) GetProposalByIDForUpdate(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getProposalByIDLocked(ctx, id)
}
func (m *memStore) getProposalByIDLocked(_ context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	row, ok := m.proposals[id]
	if !ok {
		return persistence.ProposalRow{}, domain.NotFound("NOT_FOUND", "proposal not found")
	}
	return row, nil
}

func (m *memStore) GetProposalDetailsByID(ctx context.Context, id uuid.UUID) (persistence.ProposalDetailsRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getProposalDetailsByIDLocked(ctx, id)
}
func (m *memStore) getProposalDetailsByIDLocked(_ context.Context, id uuid.UUID) (persistence.ProposalDetailsRow, error) {
	prop, ok := m.proposals[id]
	if !ok {
		return persistence.ProposalDetailsRow{}, domain.NotFound("NOT_FOUND", "proposal not found")
	}
	ws := m.workspaces[prop.WorkspaceID]
	repo := m.repos[ws.RepositoryID]
	owner := m.principals[prop.OwnerID]
	return persistence.ProposalDetailsRow{
		Proposal:                 prop,
		RepositoryID:             repo.ID,
		GitHubRepositoryID:       repo.GitHubRepositoryID,
		RepositoryFullName:       repo.FullName,
		RepositoryClassification: repo.Classification,
		WorkspaceAgentID:         ws.AgentID,
		WorkspaceAgentSessionID:  ws.AgentSessionID,
		WorkspaceModelRoute:      ws.ModelRoute,
		WorkspaceGeneration:      ws.Generation,
		OwnerKind:                owner.Kind,
		OwnerIssuer:              owner.Issuer,
		OwnerSubject:             owner.Subject,
		OwnerDisplayName:         owner.DisplayName,
	}, nil
}

func (m *memStore) TransitionProposalStatus(ctx context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transitionProposalStatusLocked(ctx, arg)
}
func (m *memStore) transitionProposalStatusLocked(_ context.Context, arg persistence.TransitionProposalStatusParams) (persistence.ProposalRow, error) {
	prop, ok := m.proposals[arg.ID]
	if !ok {
		return persistence.ProposalRow{}, domain.NotFound("NOT_FOUND", "proposal not found")
	}
	if prop.Version != arg.ExpectedVersion || (arg.FromStatus != nil && prop.Status != *arg.FromStatus) {
		return persistence.ProposalRow{}, domain.Conflict("PROPOSAL_VERSION_CONFLICT", "proposal version or status has changed")
	}
	prop.Status = arg.ToStatus
	prop.Version++
	prop.UpdatedAt = arg.UpdatedAt.UTC().Truncate(time.Microsecond)
	m.proposals[arg.ID] = prop
	return prop, nil
}

func (m *memStore) GetWorkspaceByID(ctx context.Context, id uuid.UUID) (persistence.WorkspaceRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getWorkspaceByIDLocked(ctx, id)
}
func (m *memStore) getWorkspaceByIDLocked(_ context.Context, id uuid.UUID) (persistence.WorkspaceRow, error) {
	row, ok := m.workspaces[id]
	if !ok {
		return persistence.WorkspaceRow{}, domain.NotFound("NOT_FOUND", "workspace not found")
	}
	return row, nil
}

func (m *memStore) GetRepositoryByID(ctx context.Context, id uuid.UUID) (persistence.RepositoryRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getRepositoryByIDLocked(ctx, id)
}
func (m *memStore) getRepositoryByIDLocked(_ context.Context, id uuid.UUID) (persistence.RepositoryRow, error) {
	row, ok := m.repos[id]
	if !ok {
		return persistence.RepositoryRow{}, domain.NotFound("NOT_FOUND", "repository not found")
	}
	return row, nil
}

func (m *memStore) GetPrincipalByID(ctx context.Context, id uuid.UUID) (persistence.PrincipalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getPrincipalByIDLocked(ctx, id)
}
func (m *memStore) getPrincipalByIDLocked(_ context.Context, id uuid.UUID) (persistence.PrincipalRow, error) {
	row, ok := m.principals[id]
	if !ok {
		return persistence.PrincipalRow{}, domain.NotFound("NOT_FOUND", "principal not found")
	}
	return row, nil
}

func (m *memStore) GetArtifactByID(ctx context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getArtifactByIDLocked(ctx, id)
}
func (m *memStore) getArtifactByIDLocked(_ context.Context, id uuid.UUID) (persistence.ArtifactRow, error) {
	row, ok := m.artifacts[id]
	if !ok {
		return persistence.ArtifactRow{}, domain.NotFound("NOT_FOUND", "artifact not found")
	}
	return row, nil
}

func (m *memStore) GetPolicyDecisionByID(ctx context.Context, id uuid.UUID) (persistence.PolicyDecisionRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getPolicyDecisionByIDLocked(ctx, id)
}
func (m *memStore) getPolicyDecisionByIDLocked(_ context.Context, id uuid.UUID) (persistence.PolicyDecisionRow, error) {
	row, ok := m.decisions[id]
	if !ok {
		return persistence.PolicyDecisionRow{}, domain.NotFound("NOT_FOUND", "policy decision not found")
	}
	return row, nil
}

func (m *memStore) GetLatestPolicyDecisionForProposal(ctx context.Context, proposalID uuid.UUID) (persistence.PolicyDecisionRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getLatestPolicyDecisionForProposalLocked(ctx, proposalID)
}
func (m *memStore) getLatestPolicyDecisionForProposalLocked(_ context.Context, proposalID uuid.UUID) (persistence.PolicyDecisionRow, error) {
	var latest *persistence.PolicyDecisionRow
	for _, d := range m.decisions {
		if d.ProposalID != proposalID {
			continue
		}
		if latest == nil || d.CreatedAt.After(latest.CreatedAt) || (d.CreatedAt.Equal(latest.CreatedAt) && d.ID.String() > latest.ID.String()) {
			cp := d
			latest = &cp
		}
	}
	if latest == nil {
		return persistence.PolicyDecisionRow{}, domain.NotFound("NOT_FOUND", "policy decision not found")
	}
	return *latest, nil
}

func (m *memStore) ListApprovalRequirementsByPolicyDecision(ctx context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listApprovalRequirementsByPolicyDecisionLocked(ctx, policyDecisionID)
}
func (m *memStore) listApprovalRequirementsByPolicyDecisionLocked(_ context.Context, policyDecisionID uuid.UUID) ([]persistence.ApprovalRequirementRow, error) {
	return slices.Clone(m.reqs[policyDecisionID]), nil
}

func (m *memStore) ListActiveApprovalsForDecision(ctx context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listActiveApprovalsForDecisionLocked(ctx, proposalID, policyDecisionID, manifestDigest)
}
func (m *memStore) listActiveApprovalsForDecisionLocked(_ context.Context, proposalID, policyDecisionID uuid.UUID, manifestDigest string) ([]persistence.ApprovalRow, error) {
	var out []persistence.ApprovalRow
	for _, a := range m.approvals[proposalID] {
		if a.PolicyDecisionID == policyDecisionID && strings.EqualFold(a.ManifestDigest, manifestDigest) && a.Decision == domain.ApprovalDecisionApprove && a.RevokedAt == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memStore) ListApprovalsByProposal(ctx context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listApprovalsByProposalLocked(ctx, proposalID)
}
func (m *memStore) listApprovalsByProposalLocked(_ context.Context, proposalID uuid.UUID) ([]persistence.ApprovalRow, error) {
	return slices.Clone(m.approvals[proposalID]), nil
}

func (m *memStore) EnsurePublication(ctx context.Context, arg persistence.CreatePublicationParams) (persistence.PublicationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensurePublicationLocked(ctx, arg)
}
func (m *memStore) ensurePublicationLocked(_ context.Context, arg persistence.CreatePublicationParams) (persistence.PublicationRow, error) {
	if existingID, ok := m.pubsByProp[arg.ProposalID]; ok {
		return m.pubsByID[existingID], nil
	}
	id := arg.ID
	if id == uuid.Nil {
		id, _ = domain.NewID()
	}
	branchRef := arg.BranchRef
	if branchRef == "" {
		branchRef = domain.ExpectedBranchName(arg.ProposalID)
	}
	if err := domain.ValidateBranchRef(arg.ProposalID, branchRef); err != nil {
		return persistence.PublicationRow{}, err
	}
	status := arg.Status
	if status == "" {
		status = domain.PublicationStatusPending
	}
	now := arg.CreatedAt.UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	}
	row := persistence.PublicationRow{
		ID:         id,
		ProposalID: arg.ProposalID,
		BranchRef:  branchRef,
		Status:     status,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	m.pubsByID[id] = row
	m.pubsByProp[arg.ProposalID] = id
	return row, nil
}

func (m *memStore) GetPublicationByID(ctx context.Context, id uuid.UUID) (persistence.PublicationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getPublicationByIDLocked(ctx, id)
}
func (m *memStore) getPublicationByIDLocked(_ context.Context, id uuid.UUID) (persistence.PublicationRow, error) {
	row, ok := m.pubsByID[id]
	if !ok {
		return persistence.PublicationRow{}, domain.NotFound("NOT_FOUND", "publication not found")
	}
	return row, nil
}

func (m *memStore) GetPublicationByProposalID(ctx context.Context, proposalID uuid.UUID) (persistence.PublicationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getPublicationByProposalIDLocked(ctx, proposalID)
}
func (m *memStore) getPublicationByProposalIDLocked(_ context.Context, proposalID uuid.UUID) (persistence.PublicationRow, error) {
	pubID, ok := m.pubsByProp[proposalID]
	if !ok {
		return persistence.PublicationRow{}, domain.NotFound("NOT_FOUND", "publication not found")
	}
	return m.pubsByID[pubID], nil
}

func (m *memStore) BeginPublicationAttempt(ctx context.Context, arg persistence.BeginPublicationAttemptParams) (persistence.PublicationRow, persistence.PublicationAttemptRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.beginPublicationAttemptLocked(ctx, arg)
}
func (m *memStore) beginPublicationAttemptLocked(_ context.Context, arg persistence.BeginPublicationAttemptParams) (persistence.PublicationRow, persistence.PublicationAttemptRow, error) {
	pub, ok := m.pubsByID[arg.PublicationID]
	if !ok {
		return persistence.PublicationRow{}, persistence.PublicationAttemptRow{}, domain.NotFound("NOT_FOUND", "publication not found")
	}
	if pub.Status == domain.PublicationStatusPublished {
		return persistence.PublicationRow{}, persistence.PublicationAttemptRow{}, domain.Conflict("PUBLICATION_STATE_CONFLICT", "publication is already published")
	}
	now := arg.Now.UTC().Truncate(time.Microsecond)
	pub.Status = domain.PublicationStatusPublishing
	pub.AttemptCount++
	pub.UpdatedAt = now
	m.pubsByID[pub.ID] = pub

	attID := arg.AttemptID
	if attID == uuid.Nil {
		attID, _ = domain.NewID()
	}
	att := persistence.PublicationAttemptRow{
		ID:             attID,
		PublicationID:  pub.ID,
		AttemptNumber:  pub.AttemptCount,
		ManifestDigest: arg.ManifestDigest,
		Status:         "STARTED",
		StartedAt:      now,
	}
	m.attempts[pub.ID] = append(m.attempts[pub.ID], att)
	return pub, att, nil
}

func (m *memStore) MarkPublicationPublished(ctx context.Context, arg persistence.MarkPublicationPublishedParams) (persistence.PublicationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.markPublicationPublishedLocked(ctx, arg)
}
func (m *memStore) markPublicationPublishedLocked(_ context.Context, arg persistence.MarkPublicationPublishedParams) (persistence.PublicationRow, error) {
	pub, ok := m.pubsByID[arg.ID]
	if !ok {
		return persistence.PublicationRow{}, domain.NotFound("NOT_FOUND", "publication not found")
	}
	if pub.Status != domain.PublicationStatusPublishing {
		return persistence.PublicationRow{}, domain.Conflict("PUBLICATION_STATE_CONFLICT", "publication is not in PUBLISHING status")
	}
	if arg.PullRequestNumber != nil && *arg.PullRequestNumber <= 0 {
		return persistence.PublicationRow{}, domain.BadRequest("INVALID_PR_NUMBER", "pull_request_number must be positive")
	}
	sha, err := domain.ParseGitSHA(arg.CommitSHA)
	if err != nil {
		return persistence.PublicationRow{}, err
	}
	pub.Status = domain.PublicationStatusPublished
	pub.CommitSHA = &sha
	pub.PullRequestNumber = arg.PullRequestNumber
	if arg.PullRequestURL != "" {
		u := arg.PullRequestURL
		pub.PullRequestURL = &u
	}
	pub.UpdatedAt = arg.UpdatedAt.UTC().Truncate(time.Microsecond)
	m.pubsByID[pub.ID] = pub
	return pub, nil
}

func (m *memStore) MarkPublicationFailed(ctx context.Context, id uuid.UUID, updatedAt time.Time) (persistence.PublicationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.markPublicationFailedLocked(ctx, id, updatedAt)
}
func (m *memStore) markPublicationFailedLocked(_ context.Context, id uuid.UUID, updatedAt time.Time) (persistence.PublicationRow, error) {
	pub, ok := m.pubsByID[id]
	if !ok {
		return persistence.PublicationRow{}, domain.NotFound("NOT_FOUND", "publication not found")
	}
	if pub.Status != domain.PublicationStatusPending && pub.Status != domain.PublicationStatusPublishing {
		return persistence.PublicationRow{}, domain.Conflict("PUBLICATION_STATE_CONFLICT", "publication cannot transition to FAILED from current status")
	}
	pub.Status = domain.PublicationStatusFailed
	pub.UpdatedAt = updatedAt.UTC().Truncate(time.Microsecond)
	m.pubsByID[pub.ID] = pub
	return pub, nil
}

func (m *memStore) ListPublicationAttemptsByPublication(ctx context.Context, publicationID uuid.UUID) ([]persistence.PublicationAttemptRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listPublicationAttemptsByPublicationLocked(ctx, publicationID)
}
func (m *memStore) listPublicationAttemptsByPublicationLocked(_ context.Context, publicationID uuid.UUID) ([]persistence.PublicationAttemptRow, error) {
	return slices.Clone(m.attempts[publicationID]), nil
}

func (m *memStore) CompletePublicationAttemptSucceeded(ctx context.Context, id uuid.UUID, commitSHA string, completedAt time.Time) (persistence.PublicationAttemptRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.completePublicationAttemptSucceededLocked(ctx, id, commitSHA, completedAt)
}
func (m *memStore) completePublicationAttemptSucceededLocked(_ context.Context, id uuid.UUID, commitSHA string, completedAt time.Time) (persistence.PublicationAttemptRow, error) {
	ts := completedAt.UTC().Truncate(time.Microsecond)
	for pubID, list := range m.attempts {
		for i := range list {
			if list[i].ID == id {
				if list[i].Status != "STARTED" {
					return persistence.PublicationAttemptRow{}, domain.Conflict("PUBLICATION_ATTEMPT_STATE_CONFLICT", "attempt not STARTED")
				}
				list[i].Status = "SUCCEEDED"
				list[i].CommitSHA = &commitSHA
				list[i].CompletedAt = &ts
				m.attempts[pubID] = list
				return list[i], nil
			}
		}
	}
	return persistence.PublicationAttemptRow{}, domain.NotFound("NOT_FOUND", "attempt not found")
}

func (m *memStore) CompletePublicationAttemptFailed(ctx context.Context, id uuid.UUID, errorCode, errorMessage string, completedAt time.Time) (persistence.PublicationAttemptRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.completePublicationAttemptFailedLocked(ctx, id, errorCode, errorMessage, completedAt)
}
func (m *memStore) completePublicationAttemptFailedLocked(_ context.Context, id uuid.UUID, errorCode, errorMessage string, completedAt time.Time) (persistence.PublicationAttemptRow, error) {
	ts := completedAt.UTC().Truncate(time.Microsecond)
	for pubID, list := range m.attempts {
		for i := range list {
			if list[i].ID == id {
				if list[i].Status != "STARTED" {
					return persistence.PublicationAttemptRow{}, domain.Conflict("PUBLICATION_ATTEMPT_STATE_CONFLICT", "attempt not STARTED")
				}
				list[i].Status = "FAILED"
				if errorCode != "" {
					ec := errorCode
					list[i].ErrorCode = &ec
				}
				if errorMessage != "" {
					em := errorMessage
					list[i].ErrorMessage = &em
				}
				list[i].CompletedAt = &ts
				m.attempts[pubID] = list
				return list[i], nil
			}
		}
	}
	return persistence.PublicationAttemptRow{}, domain.NotFound("NOT_FOUND", "attempt not found")
}

// operations.TxStore & operations.Store methods
func (m *memStore) EnqueueOperation(ctx context.Context, arg persistence.EnqueueOperationParams) (persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enqueueOperationLocked(ctx, arg)
}
func (m *memStore) enqueueOperationLocked(_ context.Context, arg persistence.EnqueueOperationParams) (persistence.OperationRow, error) {
	id := arg.ID
	if id == uuid.Nil {
		id, _ = domain.NewID()
	}
	maxAttempts := arg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	avail := arg.AvailableAt
	if avail.IsZero() {
		avail = now
	}
	var rt *string
	if arg.ResourceType != "" {
		s := arg.ResourceType
		rt = &s
	}
	row := persistence.OperationRow{
		ID:            id,
		OperationType: arg.OperationType,
		ResourceType:  rt,
		ResourceID:    arg.ResourceID,
		Status:        domain.OperationStatusPending,
		MaxAttempts:   maxAttempts,
		AvailableAt:   avail,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	m.ops[id] = row
	return row, nil
}

func (m *memStore) GetOperationByID(ctx context.Context, id uuid.UUID) (persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getOperationByIDLocked(ctx, id)
}
func (m *memStore) getOperationByIDLocked(_ context.Context, id uuid.UUID) (persistence.OperationRow, error) {
	row, ok := m.ops[id]
	if !ok {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "operation not found")
	}
	return row, nil
}

func (m *memStore) GetLatestOperationByResource(ctx context.Context, resourceID uuid.UUID, opType domain.OperationType) (persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getLatestOperationByResourceLocked(ctx, resourceID, opType)
}
func (m *memStore) getLatestOperationByResourceLocked(_ context.Context, resourceID uuid.UUID, opType domain.OperationType) (persistence.OperationRow, error) {
	var latest *persistence.OperationRow
	for _, op := range m.ops {
		if op.ResourceID != resourceID || op.OperationType != opType {
			continue
		}
		if latest == nil || op.CreatedAt.After(latest.CreatedAt) || (op.CreatedAt.Equal(latest.CreatedAt) && op.ID.String() > latest.ID.String()) {
			cp := op
			latest = &cp
		}
	}
	if latest == nil {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "operation not found")
	}
	return *latest, nil
}

func (m *memStore) ClaimOperations(_ context.Context, arg persistence.ClaimOperationsParams) ([]persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := arg.Now
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	}
	var out []persistence.OperationRow
	for id, op := range m.ops {
		if len(out) >= arg.Limit {
			break
		}
		if arg.OperationType != nil && op.OperationType != *arg.OperationType {
			continue
		}
		if op.Attempts >= op.MaxAttempts {
			continue
		}
		readyPending := op.Status == domain.OperationStatusPending && !op.AvailableAt.After(now)
		expiredRunning := op.Status == domain.OperationStatusRunning && op.LeaseUntil != nil && !op.LeaseUntil.After(now)
		if !readyPending && !expiredRunning {
			continue
		}
		op.Reclaimed = op.Status == domain.OperationStatusRunning
		op.Status = domain.OperationStatusRunning
		op.Attempts++
		lu := arg.LeaseUntil
		op.LeaseUntil = &lu
		w := arg.WorkerID
		op.LeasedBy = &w
		op.UpdatedAt = now
		m.ops[id] = op
		out = append(out, op)
	}
	return out, nil
}

func (m *memStore) RenewOperationLease(_ context.Context, id uuid.UUID, workerID string, now, newLeaseUntil time.Time) (persistence.OperationRow, error) {
	m.renewCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "operation not found")
	}
	if op.Status != domain.OperationStatusRunning || op.LeasedBy == nil || *op.LeasedBy != workerID || op.LeaseUntil == nil || !op.LeaseUntil.After(now) {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "lease not held")
	}
	lu := newLeaseUntil
	op.LeaseUntil = &lu
	op.UpdatedAt = now
	m.ops[id] = op
	return op, nil
}

func (m *memStore) CompleteOperation(_ context.Context, id uuid.UUID, workerID string, result json.RawMessage, now time.Time) (persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "operation not found")
	}
	if op.Status != domain.OperationStatusRunning || op.LeasedBy == nil || *op.LeasedBy != workerID || (op.LeaseUntil != nil && !op.LeaseUntil.After(now)) {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "lease not held")
	}
	op.Status = domain.OperationStatusSucceeded
	op.LeaseUntil = nil
	op.LeasedBy = nil
	op.LastError = nil
	op.Result = result
	op.CompletedAt = &now
	op.UpdatedAt = now
	m.ops[id] = op
	return op, nil
}

func (m *memStore) RetryOperation(_ context.Context, id uuid.UUID, workerID string, now, nextAvailableAt time.Time, lastError string) (persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "operation not found")
	}
	if op.Status != domain.OperationStatusRunning || op.LeasedBy == nil || *op.LeasedBy != workerID || (op.LeaseUntil != nil && !op.LeaseUntil.After(now)) || op.Attempts >= op.MaxAttempts {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "lease not held")
	}
	op.Status = domain.OperationStatusPending
	op.AvailableAt = nextAvailableAt
	op.LeaseUntil = nil
	op.LeasedBy = nil
	if lastError != "" {
		le := lastError
		op.LastError = &le
	}
	op.UpdatedAt = now
	m.ops[id] = op
	return op, nil
}

func (m *memStore) FailOperationTerminal(_ context.Context, id uuid.UUID, workerID string, now time.Time, lastError string) (persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "operation not found")
	}
	if op.Status != domain.OperationStatusRunning || op.LeasedBy == nil || *op.LeasedBy != workerID || (op.LeaseUntil != nil && !op.LeaseUntil.After(now)) {
		return persistence.OperationRow{}, domain.NotFound("NOT_FOUND", "lease not held")
	}
	op.Status = domain.OperationStatusFailed
	op.LeaseUntil = nil
	op.LeasedBy = nil
	if lastError != "" {
		le := lastError
		op.LastError = &le
	}
	op.CompletedAt = &now
	op.UpdatedAt = now
	m.ops[id] = op
	return op, nil
}

func (m *memStore) ReapExpiredOperations(_ context.Context, now time.Time) ([]persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []persistence.OperationRow
	for id, op := range m.ops {
		if op.Status == domain.OperationStatusRunning && op.LeaseUntil != nil && !op.LeaseUntil.After(now) && op.Attempts >= op.MaxAttempts {
			op.Status = domain.OperationStatusFailed
			op.LeaseUntil = nil
			op.LeasedBy = nil
			if op.LastError == nil || *op.LastError == "" {
				le := "lease expired after max attempts"
				op.LastError = &le
			}
			op.CompletedAt = &now
			op.UpdatedAt = now
			m.ops[id] = op
			out = append(out, op)
		}
	}
	return out, nil
}

func (m *memStore) ReapExpiredOperationsByType(_ context.Context, now time.Time, opType domain.OperationType) ([]persistence.OperationRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []persistence.OperationRow
	for id, op := range m.ops {
		if op.OperationType == opType && op.Status == domain.OperationStatusRunning && op.LeaseUntil != nil && !op.LeaseUntil.After(now) && op.Attempts >= op.MaxAttempts {
			op.Status = domain.OperationStatusFailed
			op.LeaseUntil = nil
			op.LeasedBy = nil
			if op.LastError == nil || *op.LastError == "" {
				le := "lease expired after max attempts"
				op.LastError = &le
			}
			op.CompletedAt = &now
			op.UpdatedAt = now
			m.ops[id] = op
			out = append(out, op)
		}
	}
	return out, nil
}

func (m *memStore) EnqueueOutboxEvent(ctx context.Context, arg persistence.EnqueueOutboxParams) (persistence.OutboxEventRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enqueueOutboxEventLocked(ctx, arg)
}
func (m *memStore) enqueueOutboxEventLocked(_ context.Context, arg persistence.EnqueueOutboxParams) (persistence.OutboxEventRow, error) {
	id := arg.ID
	if id == uuid.Nil {
		id, _ = domain.NewID()
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := persistence.OutboxEventRow{
		ID:          id,
		EventType:   arg.EventType,
		AggregateID: arg.AggregateID,
		Payload:     arg.Payload,
		AvailableAt: now,
		CreatedAt:   now,
	}
	m.outbox = append(m.outbox, row)
	return row, nil
}

func (m *memStore) ClaimOutboxEvents(context.Context, string, time.Time, time.Time, int) ([]persistence.OutboxEventRow, error) {
	return nil, nil
}
func (m *memStore) GetOutboxEventByID(context.Context, uuid.UUID) (persistence.OutboxEventRow, error) {
	return persistence.OutboxEventRow{}, domain.NotFound("NOT_FOUND", "not found")
}
func (m *memStore) MarkOutboxEventDelivered(context.Context, uuid.UUID, string, time.Time) (persistence.OutboxEventRow, error) {
	return persistence.OutboxEventRow{}, nil
}
func (m *memStore) FailOutboxEvent(context.Context, uuid.UUID, string, time.Time, string) (persistence.OutboxEventRow, error) {
	return persistence.OutboxEventRow{}, nil
}

// audit.ChainStore methods
func (m *memStore) LockAuditChainHead(context.Context) (persistence.AuditChainHeadRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.auditHead, nil
}
func (m *memStore) NormalizeJSONB(_ context.Context, payload json.RawMessage) (json.RawMessage, error) {
	canon, err := domain.CanonicalJSONBytes(payload)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canon), nil
}
func (m *memStore) UpdateAuditChainHead(ctx context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updateAuditChainHeadLocked(ctx, eventID, eventHash, eventCount, updatedAt)
}
func (m *memStore) updateAuditChainHeadLocked(_ context.Context, eventID uuid.UUID, eventHash string, eventCount int64, updatedAt time.Time) error {
	m.auditHead.LastEventID = &eventID
	m.auditHead.LastEventHash = &eventHash
	m.auditHead.EventCount = eventCount
	m.auditHead.UpdatedAt = updatedAt
	return nil
}
func (m *memStore) InsertAuditEvent(ctx context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.insertAuditEventLocked(ctx, arg)
}
func (m *memStore) insertAuditEventLocked(_ context.Context, arg persistence.InsertAuditEventParams) (persistence.AuditEventRow, error) {
	var prev *string
	if arg.PreviousHash != "" {
		p := arg.PreviousHash
		prev = &p
	}
	row := persistence.AuditEventRow{
		ID:           arg.ID,
		ChainSeq:     arg.ChainSeq,
		EventType:    arg.EventType,
		ActorID:      arg.ActorID,
		ResourceType: arg.ResourceType,
		ResourceID:   arg.ResourceID,
		Payload:      arg.Payload,
		PreviousHash: prev,
		EventHash:    arg.EventHash,
		CreatedAt:    arg.CreatedAt,
	}
	m.auditEvents = append(m.auditEvents, row)
	return row, nil
}

// --- Test Fixtures ---

type bareRepoFixture struct {
	bareDir     string
	baseCommit  string
	treeDigest  string
	archiveKey  string
	archiveSHA  string
	archiveSize int64
	snapRoot    string
	repo        domain.Repository
	bareClient  *write.LocalBareClient
}

func runGitCLI(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"-c", "user.name=Init", "-c", "user.email=init@example.com"}, args...)
	cmd := exec.Command("git", cmdArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func setupBareRepoFixture(t *testing.T, files map[string]string) bareRepoFixture {
	t.Helper()
	tmp := t.TempDir()
	bareDir := filepath.Join(tmp, "origin.git")
	workDir := filepath.Join(tmp, "work")
	snapRoot := filepath.Join(tmp, "snapshots")
	if err := os.MkdirAll(snapRoot, 0o755); err != nil {
		t.Fatalf("mkdir snapRoot: %v", err)
	}

	runGitCLI(t, "", "init", "--bare", "--initial-branch=main", bareDir)
	runGitCLI(t, "", "clone", bareDir, workDir)
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("initial\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGitCLI(t, workDir, "add", "README.md")
	runGitCLI(t, workDir, "commit", "-m", "initial commit")
	runGitCLI(t, workDir, "push", "origin", "HEAD:refs/heads/main")
	baseCommit := runGitCLI(t, workDir, "rev-parse", "HEAD")

	// Build canonical tree + compute git write-tree digest + package tar.gz.
	canonWork := filepath.Join(tmp, "canon-work")
	runGitCLI(t, "", "clone", bareDir, canonWork)
	runGitCLI(t, canonWork, "checkout", baseCommit)
	for rel, body := range files {
		dst := filepath.Join(canonWork, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir canon file: %v", err)
		}
		if err := os.WriteFile(dst, []byte(body), 0o644); err != nil {
			t.Fatalf("write canon file: %v", err)
		}
	}
	runGitCLI(t, canonWork, "add", "-A")
	treeDigest := runGitCLI(t, canonWork, "write-tree")

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	allFiles := map[string]string{"README.md": "initial\n"}
	for k, v := range files {
		allFiles[k] = v
	}
	var keys []string
	for k := range allFiles {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		data := []byte(allFiles[k])
		hdr := &tar.Header{
			Name: k,
			Mode: 0o644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	archiveBytes := buf.Bytes()
	sum := sha256.Sum256(archiveBytes)
	archiveSHA := hex.EncodeToString(sum[:])
	archiveKey := "canonical/tree.tar.gz"
	archivePath := filepath.Join(snapRoot, filepath.FromSlash(archiveKey))
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	if err := os.WriteFile(archivePath, archiveBytes, 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	repoID, _ := domain.NewID()
	repo := domain.Repository{
		ID:                   repoID,
		GitHubRepositoryID:   1001,
		GitHubInstallationID: 2002,
		FullName:             "octo/custodian-demo",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
	}
	bareClient := write.NewLocalBareClient()
	if err := bareClient.RegisterRepo(repo.GitHubRepositoryID, repo.FullName, bareDir); err != nil {
		t.Fatalf("RegisterRepo: %v", err)
	}

	return bareRepoFixture{
		bareDir:     bareDir,
		baseCommit:  baseCommit,
		treeDigest:  treeDigest,
		archiveKey:  archiveKey,
		archiveSHA:  archiveSHA,
		archiveSize: int64(len(archiveBytes)),
		snapRoot:    snapRoot,
		repo:        repo,
		bareClient:  bareClient,
	}
}

type seededIDs struct {
	repoID         uuid.UUID
	ownerID        uuid.UUID
	reviewerID     uuid.UUID
	workspaceID    uuid.UUID
	proposalID     uuid.UUID
	decisionID     uuid.UUID
	manifestDigest string
}

func seedApprovedProposal(t *testing.T, st *memStore, fix bareRepoFixture) seededIDs {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	ownerID, _ := domain.NewID()
	reviewerID, _ := domain.NewID()
	wsID, _ := domain.NewID()
	snapArtID, _ := domain.NewID()
	canonArtID, _ := domain.NewID()
	manifestArtID, _ := domain.NewID()
	propID, _ := domain.NewID()
	bundleID, _ := domain.NewID()
	decID, _ := domain.NewID()
	appID, _ := domain.NewID()
	reqID, _ := domain.NewID()

	ownerEmail := "alice@example.com"
	ownerName := "Alice Example"
	revEmail := "bob@example.com"
	revName := "Bob Reviewer"

	st.principals[ownerID] = persistence.PrincipalRow{
		ID:            ownerID,
		Kind:          domain.PrincipalKindHuman,
		DisplayName:   &ownerName,
		VerifiedEmail: &ownerEmail,
		CreatedAt:     now,
	}
	st.principals[reviewerID] = persistence.PrincipalRow{
		ID:            reviewerID,
		Kind:          domain.PrincipalKindHuman,
		DisplayName:   &revName,
		VerifiedEmail: &revEmail,
		Groups:        []string{"security-reviewers"},
		CreatedAt:     now,
	}
	st.repos[fix.repo.ID] = persistence.RepositoryRow{
		ID:                      fix.repo.ID,
		GitHubRepositoryID:      fix.repo.GitHubRepositoryID,
		GitHubInstallationID:    fix.repo.GitHubInstallationID,
		FullName:                fix.repo.FullName,
		Classification:          fix.repo.Classification,
		Enabled:                 fix.repo.Enabled,
		AllowedModelRoutes:      []string{"default"},
		MaxConcurrentOperations: 4,
		CreatedAt:               now,
	}
	st.workspaces[wsID] = persistence.WorkspaceRow{
		ID:           wsID,
		RepositoryID: fix.repo.ID,
		OwnerID:      ownerID,
		BaseCommit:   fix.baseCommit,
		TargetRef:    "main",
		Generation:   1,
		Status:       domain.WorkspaceStatusReady,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	st.artifacts[canonArtID] = persistence.ArtifactRow{
		ID:          canonArtID,
		Kind:        domain.ArtifactKindCanonicalTree,
		SHA256:      fix.archiveSHA,
		StorageKey:  fix.archiveKey,
		SizeBytes:   fix.archiveSize,
		Format:      "tar.gz",
		WorkspaceID: &wsID,
		CreatedAt:   now,
	}

	manifestDigest := sha256Hex([]byte("manifest:" + propID.String() + ":" + fix.treeDigest))
	st.artifacts[manifestArtID] = persistence.ArtifactRow{
		ID:          manifestArtID,
		Kind:        domain.ArtifactKindPublicationManifest,
		SHA256:      manifestDigest,
		StorageKey:  "canonical/manifest.json",
		SizeBytes:   128,
		Format:      "json",
		WorkspaceID: &wsID,
		CreatedAt:   now,
	}

	desc := "Add feature file\nCustodian-Proposal: forged\nAgent-Assisted: false"
	treeDig := fix.treeDigest
	effect := domain.PolicyEffectRequireApproval
	st.proposals[propID] = persistence.ProposalRow{
		ID:                       propID,
		WorkspaceID:              wsID,
		OwnerID:                  ownerID,
		SnapshotArtifactID:       snapArtID,
		CanonicalArtifactID:      &canonArtID,
		ManifestArtifactID:       &manifestArtID,
		BaseCommit:               fix.baseCommit,
		TargetRef:                "main",
		Title:                    "Add safe feature",
		Description:              &desc,
		ProvenanceType:           "agent_assisted",
		CaptureMethod:            "frozen_filesystem",
		TreeDigest:               &treeDig,
		ManifestDigest:           &manifestDigest,
		LatestPolicyEvaluationID: &decID,
		LatestPolicyEffect:       &effect,
		Status:                   domain.ProposalStatusApproved,
		Version:                  1,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	st.decisions[decID] = persistence.PolicyDecisionRow{
		ID:             decID,
		ProposalID:     propID,
		PolicyBundleID: bundleID,
		Stage:          "EGRESS",
		InputDigest:    strings.Repeat("1", 64),
		Effect:         domain.PolicyEffectRequireApproval,
		CreatedAt:      now,
	}
	satAt := now
	st.reqs[decID] = []persistence.ApprovalRequirementRow{
		{
			ID:               reqID,
			ProposalID:       propID,
			PolicyDecisionID: decID,
			RequirementType:  "GROUP_APPROVAL",
			ReviewerGroup:    "security-reviewers",
			MinimumApprovals: 1,
			SatisfiedCount:   1,
			SatisfiedAt:      &satAt,
			CreatedAt:        now,
		},
	}
	st.approvals[propID] = []persistence.ApprovalRow{
		{
			ID:               appID,
			ProposalID:       propID,
			ReviewerID:       reviewerID,
			PolicyDecisionID: decID,
			ManifestDigest:   manifestDigest,
			Decision:         domain.ApprovalDecisionApprove,
			CreatedAt:        now,
		},
	}

	return seededIDs{
		repoID:         fix.repo.ID,
		ownerID:        ownerID,
		reviewerID:     reviewerID,
		workspaceID:    wsID,
		proposalID:     propID,
		decisionID:     decID,
		manifestDigest: manifestDigest,
	}
}

func newTestPublicationService(t *testing.T, st *memStore, fix bareRepoFixture, wc write.Client) *publication.Service {
	t.Helper()
	opener, err := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
	if err != nil {
		t.Fatalf("NewLocalArtifactOpener: %v", err)
	}
	logger := observability.NewLogger(observability.LoggerConfig{Format: observability.LogFormatJSON})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian_test"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	svc, err := publication.NewServiceWithConfig(publication.Config{
		Store:          st,
		WriteClient:    wc,
		ArtifactOpener: opener,
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}
	return svc
}

func TestFourteenStepPublishHappyPathAndIdempotentReplay(t *testing.T) {
	fix := setupBareRepoFixture(t, map[string]string{"hello.txt": "world\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)
	svc := newTestPublicationService(t, st, fix, fix.bareClient)

	ctx := context.Background()
	reqRes, err := svc.RequestPublication(ctx, ids.proposalID, ids.manifestDigest, &ids.ownerID)
	if err != nil {
		t.Fatalf("RequestPublication: %v", err)
	}
	if reqRes.Operation == nil || reqRes.Operation.OperationType != domain.OperationTypeProposalPublish {
		t.Fatalf("expected PROPOSAL_PUBLISH operation, got %+v", reqRes.Operation)
	}

	res, err := svc.Publish(ctx, domain.ApprovedPublication{
		ProposalID:     ids.proposalID,
		ManifestDigest: ids.manifestDigest,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if res.Branch != domain.ExpectedBranchName(ids.proposalID) {
		t.Fatalf("unexpected branch: %s", res.Branch)
	}
	if res.PRNumber != 1 {
		t.Fatalf("expected PRNumber 1, got %d", res.PRNumber)
	}

	// Verify Git commit author, committer, parent, trailers, and branch exclusivity.
	showOut := runGitCLI(t, fix.bareDir, "show", "-s", "--format=%P|%an|%ae|%cn|%ce|%B", res.CommitSHA)
	parts := strings.SplitN(showOut, "|", 6)
	if parts[0] != fix.baseCommit {
		t.Fatalf("parent=%s, want %s", parts[0], fix.baseCommit)
	}
	if parts[1] != "Alice Example" || parts[2] != "alice@example.com" {
		t.Fatalf("author=%s <%s>", parts[1], parts[2])
	}
	if parts[3] != "Custodian" || parts[4] != "custodian@custodian.local" {
		t.Fatalf("committer=%s <%s>", parts[3], parts[4])
	}
	if !strings.Contains(parts[5], "Custodian-Proposal: "+ids.proposalID.String()) ||
		!strings.Contains(parts[5], "Custodian-Workspace: "+ids.workspaceID.String()) ||
		!strings.Contains(parts[5], "Agent-Assisted: true") {
		t.Fatalf("missing required trailers in commit message:\n%s", parts[5])
	}

	heads := runGitCLI(t, fix.bareDir, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
	if heads != "custodian/"+ids.proposalID.String()+"\nmain" && heads != "main\ncustodian/"+ids.proposalID.String() {
		t.Fatalf("unexpected branches in bare repo: %q", heads)
	}

	// Verify DB state, audit events, and outbox.
	prop, _ := st.GetProposalByID(ctx, ids.proposalID)
	if prop.Status != domain.ProposalStatusPublished {
		t.Fatalf("proposal status=%s, want PUBLISHED", prop.Status)
	}
	pub, err := svc.GetPublication(ctx, reqRes.Publication.ID)
	if err != nil {
		t.Fatalf("GetPublication: %v", err)
	}
	if pub.Status != domain.PublicationStatusPublished || pub.CommitSHA != res.CommitSHA {
		t.Fatalf("unexpected publication: %+v", pub)
	}
	pubByProp, err := svc.GetPublicationByProposalID(ctx, ids.proposalID)
	if err != nil || pubByProp.ID != pub.ID {
		t.Fatalf("GetPublicationByProposalID: err=%v pub=%+v", err, pubByProp)
	}

	var eventTypes []string
	for _, ev := range st.auditEvents {
		eventTypes = append(eventTypes, ev.EventType)
	}
	if !slices.Contains(eventTypes, "proposal.publish_requested") ||
		!slices.Contains(eventTypes, "proposal.publish_started") ||
		!slices.Contains(eventTypes, "proposal.published") {
		t.Fatalf("missing expected audit events: %v", eventTypes)
	}

	// Idempotent replay (RG-08): zero duplicate commits or PRs.
	replayRes, err := svc.Publish(ctx, domain.ApprovedPublication{
		ProposalID:     ids.proposalID,
		ManifestDigest: ids.manifestDigest,
	})
	if err != nil {
		t.Fatalf("Publish replay: %v", err)
	}
	if replayRes.CommitSHA != res.CommitSHA || replayRes.PRNumber != 1 {
		t.Fatalf("replay mismatch: got %+v, want %+v", replayRes, res)
	}
	if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 1 {
		t.Fatalf("expected 1 PR after replay, got %d", len(prs))
	}
	reqReplay, err := svc.RequestPublication(ctx, ids.proposalID, ids.manifestDigest, &ids.ownerID)
	if err != nil || !reqReplay.Idempotent {
		t.Fatalf("expected idempotent RequestPublication replay, err=%v res=%+v", err, reqReplay)
	}
}

func TestAgentAssistedProvenanceMatrix(t *testing.T) {
	agentID, _ := domain.NewID()
	cases := []struct {
		name           string
		provenanceType string
		workspaceAgent *uuid.UUID
		wantAgent      bool
	}{
		{"explicit_agent_assisted", "agent_assisted", nil, true},
		{"explicit_human_authored_even_with_agent_id", "human_authored", &agentID, false},
		{"empty_with_workspace_agent_id", "", &agentID, true},
		{"empty_without_workspace_agent_id", "", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fix := setupBareRepoFixture(t, map[string]string{"f.txt": "data\n"})
			st := newMemStore()
			ids := seedApprovedProposal(t, st, fix)

			prop := st.proposals[ids.proposalID]
			prop.ProvenanceType = tc.provenanceType
			st.proposals[ids.proposalID] = prop

			ws := st.workspaces[ids.workspaceID]
			ws.AgentID = tc.workspaceAgent
			st.workspaces[ids.workspaceID] = ws

			svc := newTestPublicationService(t, st, fix, fix.bareClient)
			req, err := svc.LoadApprovedPublication(context.Background(), domain.ApprovedPublication{
				ProposalID:     ids.proposalID,
				ManifestDigest: ids.manifestDigest,
			})
			if err != nil {
				t.Fatalf("LoadApprovedPublication: %v", err)
			}
			if req.AgentAssisted != tc.wantAgent {
				t.Fatalf("AgentAssisted=%v, want %v", req.AgentAssisted, tc.wantAgent)
			}
		})
	}
}

func TestUpstreamForcePushAbortIsTerminal(t *testing.T) {
	fix := setupBareRepoFixture(t, map[string]string{"a.txt": "1\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)
	svc := newTestPublicationService(t, st, fix, fix.bareClient)

	// Force-push an orphan commit onto main after proposal approval (ADV-11).
	orphanDir := t.TempDir()
	runGitCLI(t, "", "init", "--initial-branch=main", orphanDir)
	if err := os.WriteFile(filepath.Join(orphanDir, "force.txt"), []byte("rewritten\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	runGitCLI(t, orphanDir, "add", "force.txt")
	runGitCLI(t, orphanDir, "commit", "-m", "force pushed history")
	runGitCLI(t, orphanDir, "push", "--force", fix.bareDir, "HEAD:refs/heads/main")

	// Simulate attempt 1 of 5 via Runner (attempts < max_attempts): must STILL be terminal!
	ctx := context.Background()
	opsSvc := operations.NewService(st, nil, nil)
	op, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   5,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:     opsSvc,
		Service: svc,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	claimed, err := runner.ProcessOnce(ctx)
	if err != nil || claimed != 1 {
		t.Fatalf("ProcessOnce: claimed=%d err=%v", claimed, err)
	}

	gotOp, _ := st.GetOperationByID(ctx, op.ID)
	if gotOp.Status != domain.OperationStatusFailed {
		t.Fatalf("expected terminal FAILED operation on UPSTREAM_FORCE_PUSH, got %s", gotOp.Status)
	}
	prop, _ := st.GetProposalByID(ctx, ids.proposalID)
	if prop.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected FAILED proposal, got %s", prop.Status)
	}
	pub, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
	if pub.Status != domain.PublicationStatusFailed {
		t.Fatalf("expected FAILED publication, got %s", pub.Status)
	}
	if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 0 {
		t.Fatalf("expected 0 PRs after force push abort, got %d", len(prs))
	}
	heads := runGitCLI(t, fix.bareDir, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
	if strings.Contains(heads, "custodian/") {
		t.Fatalf("custodian branch should not exist after force push abort: %s", heads)
	}
}

func TestFailClosedRejectionMatrix(t *testing.T) {
	ctx := context.Background()

	runCase := func(t *testing.T, mutate func(st *memStore, ids seededIDs), wantErr error, wantStatus domain.ProposalStatus) {
		t.Helper()
		fix := setupBareRepoFixture(t, map[string]string{"x.txt": "x\n"})
		st := newMemStore()
		ids := seedApprovedProposal(t, st, fix)
		mutate(st, ids)
		svc := newTestPublicationService(t, st, fix, fix.bareClient)

		_, err := svc.ExecutePublication(ctx, ids.proposalID, ids.manifestDigest, false)
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
		if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 0 {
			t.Fatalf("expected 0 PRs on rejected publication, got %d", len(prs))
		}
		prop, _ := st.GetProposalByID(ctx, ids.proposalID)
		if prop.Status != wantStatus {
			t.Fatalf("proposal status=%s, want %s", prop.Status, wantStatus)
		}
	}

	t.Run("unapproved_pending_approval", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			p := st.proposals[ids.proposalID]
			p.Status = domain.ProposalStatusPendingApproval
			st.proposals[ids.proposalID] = p
		}, domain.ErrConflict, domain.ProposalStatusPendingApproval)
	})

	t.Run("denied_proposal_never_overwritten", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			p := st.proposals[ids.proposalID]
			p.Status = domain.ProposalStatusDenied
			st.proposals[ids.proposalID] = p
		}, domain.ErrConflict, domain.ProposalStatusDenied)
	})

	t.Run("policy_blocked_deny", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			d := st.decisions[ids.decisionID]
			d.Effect = domain.PolicyEffectDeny
			st.decisions[ids.decisionID] = d
			p := st.proposals[ids.proposalID]
			e := domain.PolicyEffectDeny
			p.LatestPolicyEffect = &e
			st.proposals[ids.proposalID] = p
		}, domain.ErrForbidden, domain.ProposalStatusFailed)
	})

	t.Run("stale_policy_decision", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			newerID, _ := domain.NewID()
			st.decisions[newerID] = persistence.PolicyDecisionRow{
				ID:             newerID,
				ProposalID:     ids.proposalID,
				PolicyBundleID: st.decisions[ids.decisionID].PolicyBundleID,
				Stage:          "EGRESS",
				InputDigest:    strings.Repeat("2", 64),
				Effect:         domain.PolicyEffectAllow,
				CreatedAt:      time.Now().UTC().Add(time.Minute),
			}
		}, domain.ErrConflict, domain.ProposalStatusFailed)
	})

	t.Run("manifest_digest_mismatch", func(t *testing.T) {
		fix := setupBareRepoFixture(t, map[string]string{"x.txt": "x\n"})
		st := newMemStore()
		ids := seedApprovedProposal(t, st, fix)
		svc := newTestPublicationService(t, st, fix, fix.bareClient)

		_, err := svc.ExecutePublication(ctx, ids.proposalID, strings.Repeat("9", 64), false)
		if !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("expected ErrConflict, got %v", err)
		}
	})

	t.Run("active_reject_blocks_publication", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			rejID, _ := domain.NewID()
			st.approvals[ids.proposalID] = append(st.approvals[ids.proposalID], persistence.ApprovalRow{
				ID:               rejID,
				ProposalID:       ids.proposalID,
				ReviewerID:       ids.reviewerID,
				PolicyDecisionID: ids.decisionID,
				ManifestDigest:   ids.manifestDigest,
				Decision:         domain.ApprovalDecisionReject,
				CreatedAt:        time.Now().UTC(),
			})
		}, domain.ErrConflict, domain.ProposalStatusFailed)
	})

	t.Run("sod_violation_owner_cannot_approve", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			apps := st.approvals[ids.proposalID]
			apps[0].ReviewerID = ids.ownerID
			st.approvals[ids.proposalID] = apps
		}, domain.ErrForbidden, domain.ProposalStatusFailed)
	})

	t.Run("non_human_approver_rejected", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			rev := st.principals[ids.reviewerID]
			rev.Kind = domain.PrincipalKindAgent
			st.principals[ids.reviewerID] = rev
		}, domain.ErrForbidden, domain.ProposalStatusFailed)
	})

	t.Run("unsatisfied_approval_requirement", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			reqs := st.reqs[ids.decisionID]
			reqs[0].SatisfiedAt = nil
			reqs[0].SatisfiedCount = 0
			st.reqs[ids.decisionID] = reqs
		}, domain.ErrForbidden, domain.ProposalStatusFailed)
	})

	t.Run("owner_missing_verified_email", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			own := st.principals[ids.ownerID]
			own.VerifiedEmail = nil
			st.principals[ids.ownerID] = own
		}, domain.ErrUnprocessable, domain.ProposalStatusFailed)
	})

	t.Run("disabled_repository", func(t *testing.T) {
		runCase(t, func(st *memStore, ids seededIDs) {
			r := st.repos[ids.repoID]
			r.Enabled = false
			st.repos[ids.repoID] = r
		}, domain.ErrForbidden, domain.ProposalStatusFailed)
	})
}

type flakyGitPublisher struct {
	mu       sync.Mutex
	calls    int
	behavior func(call int, ctx context.Context, req publish.PublishRequest) (domain.PublicationResult, error)
}

func (f *flakyGitPublisher) PublishRequest(ctx context.Context, req publish.PublishRequest) (domain.PublicationResult, error) {
	f.mu.Lock()
	f.calls++
	c := f.calls
	f.mu.Unlock()
	return f.behavior(c, ctx, req)
}

func TestTransientFailureRetryAndFinalAttemptFailure(t *testing.T) {
	ctx := context.Background()
	fix := setupBareRepoFixture(t, map[string]string{"retry.txt": "ok\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)

	realGitPub, err := publish.NewService(publish.Config{
		WriteClient: fix.bareClient,
		ArtifactOpener: func() publish.ArtifactOpener {
			o, _ := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
			return o
		}(),
	})
	if err != nil {
		t.Fatalf("publish.NewService: %v", err)
	}

	flaky := &flakyGitPublisher{
		behavior: func(call int, ctx context.Context, req publish.PublishRequest) (domain.PublicationResult, error) {
			if call == 1 {
				return domain.PublicationResult{}, domain.Unavailable("GITHUB_UNAVAILABLE", "503 upstream down")
			}
			if call == 2 {
				return domain.PublicationResult{}, domain.Conflict("GIT_PUSH_CONFLICT", "failed to lock remote ref")
			}
			return realGitPub.PublishRequest(ctx, req)
		},
	}

	svc, err := publication.NewServiceWithConfig(publication.Config{
		Store:        st,
		GitPublisher: flaky,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}

	var nowMu sync.Mutex
	curNow := time.Now().UTC().Truncate(time.Microsecond)
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}

	opsSvc := operations.NewService(st, nil, nil, operations.Config{
		BaseRetryDelay: 100 * time.Millisecond,
		Clock:          clock,
	})
	op, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   4,
		AvailableAt:   curNow,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:     opsSvc,
		Service: svc,
		Clock:   clock,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	// Attempt 1: 503 Unavailable -> retry scheduled, proposal & publication stay PUBLISHING.
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce #1: n=%d err=%v", n, err)
	}
	prop, _ := st.GetProposalByID(ctx, ids.proposalID)
	pub, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
	gotOp, _ := st.GetOperationByID(ctx, op.ID)
	if prop.Status != domain.ProposalStatusPublishing || pub.Status != domain.PublicationStatusPublishing {
		t.Fatalf("expected PUBLISHING on retryable error, got prop=%s pub=%s", prop.Status, pub.Status)
	}
	if gotOp.Status != domain.OperationStatusPending || !gotOp.AvailableAt.After(curNow) {
		t.Fatalf("expected PENDING with backoff, got status=%s available_at=%v", gotOp.Status, gotOp.AvailableAt)
	}

	// Attempt 2: transient GIT_PUSH_CONFLICT ("failed to lock") -> also retryable.
	nowMu.Lock()
	curNow = gotOp.AvailableAt.Add(time.Millisecond)
	nowMu.Unlock()
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce #2: n=%d err=%v", n, err)
	}
	gotOp, _ = st.GetOperationByID(ctx, op.ID)
	if gotOp.Status != domain.OperationStatusPending {
		t.Fatalf("expected PENDING after transient lock conflict, got %s", gotOp.Status)
	}

	// Attempt 3: succeeds.
	nowMu.Lock()
	curNow = gotOp.AvailableAt.Add(time.Millisecond)
	nowMu.Unlock()
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce #3: n=%d err=%v", n, err)
	}
	gotOp, _ = st.GetOperationByID(ctx, op.ID)
	prop, _ = st.GetProposalByID(ctx, ids.proposalID)
	pub, _ = st.GetPublicationByProposalID(ctx, ids.proposalID)
	if gotOp.Status != domain.OperationStatusSucceeded || prop.Status != domain.ProposalStatusPublished || pub.Status != domain.PublicationStatusPublished {
		t.Fatalf("expected SUCCEEDED/PUBLISHED, got op=%s prop=%s pub=%s", gotOp.Status, prop.Status, pub.Status)
	}
	if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 1 {
		t.Fatalf("expected 1 PR, got %d", len(prs))
	}
}

func TestGracefulShutdownDoesNotFailProposal(t *testing.T) {
	fix := setupBareRepoFixture(t, map[string]string{"shutdown.txt": "x\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)

	started := make(chan struct{})
	blockingPub := &flakyGitPublisher{
		behavior: func(_ int, ctx context.Context, _ publish.PublishRequest) (domain.PublicationResult, error) {
			close(started)
			<-ctx.Done()
			return domain.PublicationResult{}, ctx.Err()
		},
	}
	svc, err := publication.NewServiceWithConfig(publication.Config{
		Store:        st,
		GitPublisher: blockingPub,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}
	opsSvc := operations.NewService(st, nil, nil)
	op, _ := opsSvc.Enqueue(context.Background(), operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   1,
	})
	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:     opsSvc,
		Service: svc,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = runner.ProcessOnce(runCtx)
	}()

	<-started
	cancel()
	<-done

	prop, _ := st.GetProposalByID(context.Background(), ids.proposalID)
	pub, _ := st.GetPublicationByProposalID(context.Background(), ids.proposalID)
	gotOp, _ := st.GetOperationByID(context.Background(), op.ID)
	if prop.Status != domain.ProposalStatusPublishing || pub.Status != domain.PublicationStatusPublishing {
		t.Fatalf("graceful shutdown must NOT permanently fail proposal/publication: prop=%s pub=%s", prop.Status, pub.Status)
	}
	if gotOp.Status == domain.OperationStatusFailed {
		t.Fatalf("graceful shutdown must NOT mark operation terminal FAILED")
	}
}

func TestRunnerLeaseRenewalLeaseLostAndReapExpiredFiltering(t *testing.T) {
	ctx := context.Background()
	fix := setupBareRepoFixture(t, map[string]string{"lease.txt": "ok\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)

	// Enqueue an unrelated WORKSPACE_INGRESS operation that Runner must NOT claim or reap-fail.
	wsOpID, _ := domain.NewID()
	opsSvc := operations.NewService(st, nil, nil)
	_, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
		ID:            wsOpID,
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    ids.workspaceID,
		MaxAttempts:   1,
	})
	if err != nil {
		t.Fatalf("Enqueue ws op: %v", err)
	}

	slowPub := &flakyGitPublisher{
		behavior: func(_ int, ctx context.Context, _ publish.PublishRequest) (domain.PublicationResult, error) {
			// Exceed initial 120ms lease so background renewal must extend lease.
			select {
			case <-time.After(180 * time.Millisecond):
				return domain.PublicationResult{
					ProposalID: ids.proposalID,
					CommitSHA:  strings.Repeat("a", 40),
					Branch:     domain.ExpectedBranchName(ids.proposalID),
					PRNumber:   1,
					PRURL:      "https://github.com/octo/demo/pull/1",
				}, nil
			case <-ctx.Done():
				return domain.PublicationResult{}, ctx.Err()
			}
		},
	}

	svc, err := publication.NewServiceWithConfig(publication.Config{
		Store:        st,
		GitPublisher: slowPub,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}
	pubOp, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   2,
	})
	if err != nil {
		t.Fatalf("Enqueue pub op: %v", err)
	}

	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:           opsSvc,
		Service:       svc,
		LeaseDuration: 120 * time.Millisecond,
		RenewInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	n, err := runner.ProcessOnce(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ProcessOnce: n=%d err=%v", n, err)
	}
	if st.renewCalls.Load() < 1 {
		t.Fatalf("expected at least 1 lease renewal during slow publish, got %d", st.renewCalls.Load())
	}
	gotPubOp, _ := st.GetOperationByID(ctx, pubOp.ID)
	gotWSOp, _ := st.GetOperationByID(ctx, wsOpID)
	if gotPubOp.Status != domain.OperationStatusSucceeded {
		t.Fatalf("expected SUCCEEDED pub op, got %s", gotPubOp.Status)
	}
	if gotWSOp.Status != domain.OperationStatusPending {
		t.Fatalf("runner must not claim non-publish op, got %s", gotWSOp.Status)
	}

	// Test LEASE_LOST cancellation + ReapExpired filtering.
	st2 := newMemStore()
	ids2 := seedApprovedProposal(t, st2, fix)
	otherPropID, _ := domain.NewID()

	// Seed an expired WORKSPACE_INGRESS op (attempts==max_attempts) and an expired PROPOSAL_PUBLISH op.
	expiredAt := time.Now().UTC().Add(-time.Minute)
	otherOwner := "dead-worker"
	wsExpiredID, _ := domain.NewID()
	st2.ops[wsExpiredID] = persistence.OperationRow{
		ID:            wsExpiredID,
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceID:    otherPropID,
		Status:        domain.OperationStatusRunning,
		Attempts:      1,
		MaxAttempts:   1,
		LeaseUntil:    &expiredAt,
		LeasedBy:      &otherOwner,
	}
	pubExpiredID, _ := domain.NewID()
	st2.ops[pubExpiredID] = persistence.OperationRow{
		ID:            pubExpiredID,
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  strPtr("proposal"),
		ResourceID:    ids2.proposalID,
		Status:        domain.OperationStatusRunning,
		Attempts:      2,
		MaxAttempts:   2,
		LeaseUntil:    &expiredAt,
		LeasedBy:      &otherOwner,
	}

	m2, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian_unit_reap"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	m2.IncActiveOperation(string(domain.OperationTypeWorkspaceIngress))
	m2.IncActiveOperation(string(domain.OperationTypeProposalPublish))
	opsSvc2 := operations.NewService(st2, m2, nil)
	svc2, _ := publication.NewServiceWithConfig(publication.Config{Store: st2, GitPublisher: slowPub, Metrics: m2})
	runner2, _ := publication.NewRunner(publication.RunnerConfig{Ops: opsSvc2, Service: svc2, Metrics: m2})
	reapedCount, err := runner2.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if reapedCount != 1 {
		t.Fatalf("expected ReapExpired to handle 1 PROPOSAL_PUBLISH op, got %d", reapedCount)
	}
	prop2, _ := st2.GetProposalByID(ctx, ids2.proposalID)
	if prop2.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected reaped proposal FAILED, got %s", prop2.Status)
	}
	wsExpiredAfter, _ := st2.GetOperationByID(ctx, wsExpiredID)
	if wsExpiredAfter.Status != domain.OperationStatusRunning {
		t.Fatalf("expected expired WORKSPACE_INGRESS op to remain RUNNING untouched by publication Runner, got %s", wsExpiredAfter.Status)
	}
	pubExpiredAfter, _ := st2.GetOperationByID(ctx, pubExpiredID)
	if pubExpiredAfter.Status != domain.OperationStatusFailed {
		t.Fatalf("expected expired PROPOSAL_PUBLISH op FAILED, got %s", pubExpiredAfter.Status)
	}
	mfs2, err := m2.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather metrics: %v", err)
	}
	for _, mf := range mfs2 {
		if mf.GetName() == "custodian_unit_reap_active_operations" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "operation_type" {
						switch lp.GetValue() {
						case string(domain.OperationTypeWorkspaceIngress):
							if got := m.GetGauge().GetValue(); got != 1 {
								t.Fatalf("WORKSPACE_INGRESS active_operations gauge must remain 1 (not decremented), got %v", got)
							}
						case string(domain.OperationTypeProposalPublish):
							if got := m.GetGauge().GetValue(); got != 0 {
								t.Fatalf("PROPOSAL_PUBLISH active_operations gauge must be decremented to 0, got %v", got)
							}
						}
					}
				}
			}
		}
	}

	// Test LEASE_LOST cancels attemptCtx without marking proposal FAILED.
	st3 := newMemStore()
	ids3 := seedApprovedProposal(t, st3, fix)
	opsSvc3 := operations.NewService(st3, nil, nil)
	leaseLostStarted := make(chan struct{})
	var cancelledByLease atomic.Bool
	lostPub := &flakyGitPublisher{
		behavior: func(_ int, ctx context.Context, _ publish.PublishRequest) (domain.PublicationResult, error) {
			close(leaseLostStarted)
			<-ctx.Done()
			cancelledByLease.Store(true)
			return domain.PublicationResult{}, ctx.Err()
		},
	}
	svc3, _ := publication.NewServiceWithConfig(publication.Config{Store: st3, GitPublisher: lostPub})
	op3, _ := opsSvc3.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids3.proposalID,
		MaxAttempts:   1,
	})
	runner3, _ := publication.NewRunner(publication.RunnerConfig{
		Ops:           opsSvc3,
		Service:       svc3,
		LeaseDuration: 500 * time.Millisecond,
		RenewInterval: 25 * time.Millisecond,
	})

	done3 := make(chan struct{})
	go func() {
		defer close(done3)
		_, _ = runner3.ProcessOnce(ctx)
	}()
	<-leaseLostStarted
	// Steal lease by changing LeasedBy in st3.
	st3.mu.Lock()
	row3 := st3.ops[op3.ID]
	stolen := "other-worker"
	row3.LeasedBy = &stolen
	st3.ops[op3.ID] = row3
	st3.mu.Unlock()
	<-done3

	if !cancelledByLease.Load() {
		t.Fatalf("expected LEASE_LOST to cancel in-flight attempt context")
	}
	prop3, _ := st3.GetProposalByID(ctx, ids3.proposalID)
	if prop3.Status != domain.ProposalStatusPublishing {
		t.Fatalf("expected proposal to stay PUBLISHING on LEASE_LOST, got %s", prop3.Status)
	}
}

func TestLoadApprovedPublication_PublishedProposalReturnsConflict(t *testing.T) {
	ctx := context.Background()
	fix := setupBareRepoFixture(t, map[string]string{"published.txt": "done\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)
	svc := newTestPublicationService(t, st, fix, fix.bareClient)

	if _, err := svc.Publish(ctx, domain.ApprovedPublication{
		ProposalID:     ids.proposalID,
		ManifestDigest: ids.manifestDigest,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	req, err := svc.LoadApprovedPublication(ctx, domain.ApprovedPublication{
		ProposalID:     ids.proposalID,
		ManifestDigest: ids.manifestDigest,
	})
	if err == nil {
		t.Fatalf("expected conflict error from LoadApprovedPublication on PUBLISHED proposal, got nil (req=%+v)", req)
	}
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) || domErr.Code() != "PROPOSAL_ALREADY_PUBLISHED" {
		t.Fatalf("expected PROPOSAL_ALREADY_PUBLISHED, got %v", err)
	}
	if req.ProposalID != uuid.Nil {
		t.Fatalf("expected zero PublishRequest on error, got %+v", req)
	}
}

func TestConcurrentRequestPublicationAndExecutePublication_NoDuplicateOrFailedClobber(t *testing.T) {
	ctx := context.Background()

	t.Run("concurrent_request_publication_single_operation", func(t *testing.T) {
		fix := setupBareRepoFixture(t, map[string]string{"req.txt": "ok\n"})
		st := newMemStore()
		ids := seedApprovedProposal(t, st, fix)
		svc := newTestPublicationService(t, st, fix, fix.bareClient)

		const workers = 8
		results := make([]publication.RequestResult, workers)
		errs := make([]error, workers)
		startGate := make(chan struct{})
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startGate
				results[idx], errs[idx] = svc.RequestPublication(ctx, ids.proposalID, ids.manifestDigest, &ids.ownerID)
			}(i)
		}
		close(startGate)
		wg.Wait()

		nonIdempotent := 0
		idempotent := 0
		var opID, pubID uuid.UUID
		for i := range workers {
			if errs[i] != nil {
				t.Fatalf("worker %d RequestPublication error: %v", i, errs[i])
			}
			if results[i].Operation == nil {
				t.Fatalf("worker %d returned nil Operation", i)
			}
			if opID == uuid.Nil {
				opID = results[i].Operation.ID
				pubID = results[i].Publication.ID
			} else if results[i].Operation.ID != opID || results[i].Publication.ID != pubID {
				t.Fatalf("worker %d mismatch: got op=%s pub=%s, want op=%s pub=%s", i, results[i].Operation.ID, results[i].Publication.ID, opID, pubID)
			}
			if results[i].Idempotent {
				idempotent++
			} else {
				nonIdempotent++
			}
		}
		if nonIdempotent != 1 || idempotent != workers-1 {
			t.Fatalf("expected 1 non-idempotent + %d idempotent results, got non=%d idemp=%d", workers-1, nonIdempotent, idempotent)
		}
		st.mu.Lock()
		opCount := len(st.ops)
		st.mu.Unlock()
		if opCount != 1 {
			t.Fatalf("expected exactly 1 enqueued operation, got %d", opCount)
		}
	})

	t.Run("concurrent_execute_publication_single_pr_no_failed", func(t *testing.T) {
		fix := setupBareRepoFixture(t, map[string]string{"conc.txt": "single\n"})
		st := newMemStore()
		ids := seedApprovedProposal(t, st, fix)

		realGitPub, err := publish.NewService(publish.Config{
			WriteClient: fix.bareClient,
			ArtifactOpener: func() publish.ArtifactOpener {
				o, _ := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
				return o
			}(),
		})
		if err != nil {
			t.Fatalf("publish.NewService: %v", err)
		}

		firstEntered := make(chan struct{})
		releaseFirst := make(chan struct{})
		var pubCalls atomic.Int32
		gatedPub := &flakyGitPublisher{
			behavior: func(call int, ctx context.Context, req publish.PublishRequest) (domain.PublicationResult, error) {
				pubCalls.Add(1)
				if call == 1 {
					close(firstEntered)
					<-releaseFirst
				}
				return realGitPub.PublishRequest(ctx, req)
			},
		}

		svc, err := publication.NewServiceWithConfig(publication.Config{
			Store:        st,
			GitPublisher: gatedPub,
		})
		if err != nil {
			t.Fatalf("NewServiceWithConfig: %v", err)
		}

		// Launch winner first so it holds PUBLISHING + STARTED attempt during Step 8.
		type execOutcome struct {
			res domain.PublicationResult
			err error
		}
		winnerCh := make(chan execOutcome, 1)
		go func() {
			r, e := svc.Publish(ctx, domain.ApprovedPublication{
				ProposalID:     ids.proposalID,
				ManifestDigest: ids.manifestDigest,
			})
			winnerCh <- execOutcome{res: r, err: e}
		}()

		<-firstEntered

		// While winner is in Step 8, race 3 concurrent ExecutePublication/Publish callers.
		const racers = 3
		var racerWG sync.WaitGroup
		racerErrs := make([]error, racers)
		for i := range racers {
			racerWG.Add(1)
			go func(idx int) {
				defer racerWG.Done()
				_, racerErrs[idx] = svc.Publish(ctx, domain.ApprovedPublication{
					ProposalID:     ids.proposalID,
					ManifestDigest: ids.manifestDigest,
				})
			}(i)
		}
		racerWG.Wait()

		// Winner's proposal & publication must STILL be PUBLISHING (never FAILED!).
		propMid, _ := st.GetProposalByID(ctx, ids.proposalID)
		pubMid, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
		if propMid.Status != domain.ProposalStatusPublishing || pubMid.Status != domain.PublicationStatusPublishing {
			close(releaseFirst)
			<-winnerCh
			t.Fatalf("concurrent callers clobbered in-flight state: prop=%s pub=%s", propMid.Status, pubMid.Status)
		}

		close(releaseFirst)
		winner := <-winnerCh
		if winner.err != nil {
			t.Fatalf("winner Publish failed: %v", winner.err)
		}

		for i, e := range racerErrs {
			if e != nil && !errors.Is(e, domain.ErrConflict) {
				t.Fatalf("racer %d got unexpected error %v", i, e)
			}
		}

		propEnd, _ := st.GetProposalByID(ctx, ids.proposalID)
		pubEnd, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
		if propEnd.Status != domain.ProposalStatusPublished || pubEnd.Status != domain.PublicationStatusPublished {
			t.Fatalf("expected PUBLISHED at end, got prop=%s pub=%s", propEnd.Status, pubEnd.Status)
		}
		if pubCalls.Load() != 1 {
			t.Fatalf("expected exactly 1 GitPublisher call, got %d", pubCalls.Load())
		}
		if prs := fix.bareClient.PullRequests(fix.repo.FullName); len(prs) != 1 {
			t.Fatalf("expected exactly 1 PR, got %d", len(prs))
		}
		attempts, _ := st.ListPublicationAttemptsByPublication(ctx, pubEnd.ID)
		if len(attempts) != 1 || attempts[0].Status != "SUCCEEDED" {
			t.Fatalf("expected 1 SUCCEEDED attempt, got %+v", attempts)
		}
	})
}

func TestExpiredLeaseWorkerDoesNotClobberReclaimedAttempt(t *testing.T) {
	ctx := context.Background()

	runLeaseRace := func(t *testing.T, w1ReturnsErr error) {
		t.Helper()
		fix := setupBareRepoFixture(t, map[string]string{"reclaim.txt": "safe\n"})
		st := newMemStore()
		ids := seedApprovedProposal(t, st, fix)

		realGitPub, err := publish.NewService(publish.Config{
			WriteClient: fix.bareClient,
			ArtifactOpener: func() publish.ArtifactOpener {
				o, _ := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
				return o
			}(),
		})
		if err != nil {
			t.Fatalf("publish.NewService: %v", err)
		}

		w1Started := make(chan struct{})
		w1Release := make(chan struct{})
		w2Started := make(chan struct{})
		w2Release := make(chan struct{})

		pub := &flakyGitPublisher{
			behavior: func(call int, ctx context.Context, req publish.PublishRequest) (domain.PublicationResult, error) {
				if call == 1 {
					close(w1Started)
					<-w1Release
					if w1ReturnsErr != nil {
						return domain.PublicationResult{}, w1ReturnsErr
					}
					return domain.PublicationResult{
						ProposalID: ids.proposalID,
						CommitSHA:  strings.Repeat("b", 40),
						Branch:     domain.ExpectedBranchName(ids.proposalID),
						PRNumber:   1,
						PRURL:      "https://github.com/octo/demo/pull/1",
					}, nil
				}
				close(w2Started)
				<-w2Release
				return realGitPub.PublishRequest(ctx, req)
			},
		}

		var clockMu sync.Mutex
		curNow := time.Now().UTC().Truncate(time.Microsecond)
		clock := func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return curNow
		}

		svc, err := publication.NewServiceWithConfig(publication.Config{
			Store:        st,
			GitPublisher: pub,
			Clock:        clock,
		})
		if err != nil {
			t.Fatalf("NewServiceWithConfig: %v", err)
		}
		opsSvc := operations.NewService(st, nil, nil, operations.Config{Clock: clock})
		op, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
			OperationType: domain.OperationTypeProposalPublish,
			ResourceType:  "proposal",
			ResourceID:    ids.proposalID,
			MaxAttempts:   3,
			AvailableAt:   curNow,
		})
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}

		// Long renew interval so Worker 1's lease expires before any Renew call.
		runner1, _ := publication.NewRunner(publication.RunnerConfig{
			Ops:           opsSvc,
			Service:       svc,
			WorkerID:      "worker-1",
			LeaseDuration: 100 * time.Millisecond,
			RenewInterval: time.Hour,
			Clock:         clock,
		})
		runner2, _ := publication.NewRunner(publication.RunnerConfig{
			Ops:           opsSvc,
			Service:       svc,
			WorkerID:      "worker-2",
			LeaseDuration: 30 * time.Second,
			RenewInterval: 10 * time.Second,
			Clock:         clock,
		})

		w1Done := make(chan struct{})
		go func() {
			defer close(w1Done)
			_, _ = runner1.ProcessOnce(ctx)
		}()
		<-w1Started

		// Advance clock past Worker 1's lease and reclaim via Worker 2.
		clockMu.Lock()
		curNow = curNow.Add(200 * time.Millisecond)
		clockMu.Unlock()

		w2Done := make(chan struct{})
		go func() {
			defer close(w2Done)
			_, _ = runner2.ProcessOnce(ctx)
		}()
		<-w2Started

		// Unblock expired Worker 1 while Worker 2 is in Step 8 (Attempt 2 STARTED).
		close(w1Release)
		<-w1Done

		propMid, _ := st.GetProposalByID(ctx, ids.proposalID)
		pubMid, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
		opMid, _ := st.GetOperationByID(ctx, op.ID)
		if propMid.Status != domain.ProposalStatusPublishing || pubMid.Status != domain.PublicationStatusPublishing {
			close(w2Release)
			<-w2Done
			t.Fatalf("expired Worker 1 clobbered reclaimed state: prop=%s pub=%s", propMid.Status, pubMid.Status)
		}
		if opMid.Status != domain.OperationStatusRunning || opMid.LeasedBy == nil || *opMid.LeasedBy != "worker-2" {
			close(w2Release)
			<-w2Done
			t.Fatalf("expected op still RUNNING by worker-2, got status=%s leased_by=%v", opMid.Status, opMid.LeasedBy)
		}

		// Let Worker 2 finish cleanly.
		close(w2Release)
		<-w2Done

		propEnd, _ := st.GetProposalByID(ctx, ids.proposalID)
		pubEnd, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
		opEnd, _ := st.GetOperationByID(ctx, op.ID)
		if propEnd.Status != domain.ProposalStatusPublished || pubEnd.Status != domain.PublicationStatusPublished || opEnd.Status != domain.OperationStatusSucceeded {
			t.Fatalf("expected PUBLISHED/SUCCEEDED after Worker 2 completed, got prop=%s pub=%s op=%s", propEnd.Status, pubEnd.Status, opEnd.Status)
		}
		attempts, _ := st.ListPublicationAttemptsByPublication(ctx, pubEnd.ID)
		if len(attempts) != 2 || attempts[0].Status != "FAILED" || attempts[1].Status != "SUCCEEDED" {
			t.Fatalf("unexpected attempts: %+v", attempts)
		}
	}

	t.Run("step9_after_attempt2_reclaimed", func(t *testing.T) {
		runLeaseRace(t, nil)
	})

	t.Run("step8_terminal_error_after_attempt2_reclaimed", func(t *testing.T) {
		runLeaseRace(t, domain.Conflict("UPSTREAM_FORCE_PUSH", "non-fast-forward"))
	})

	t.Run("post_github_tx2_outage_on_final_attempt_preserves_publishing", func(t *testing.T) {
		fix := setupBareRepoFixture(t, map[string]string{"tx2fail.txt": "ok\n"})
		st := newMemStore()
		ids := seedApprovedProposal(t, st, fix)

		wrappedStore := &tx2FailStore{memStore: st}
		svc, err := publication.NewServiceWithConfig(publication.Config{
			Store: wrappedStore,
			GitPublisher: &flakyGitPublisher{
				behavior: func(_ int, _ context.Context, _ publish.PublishRequest) (domain.PublicationResult, error) {
					return domain.PublicationResult{
						ProposalID: ids.proposalID,
						CommitSHA:  strings.Repeat("c", 40),
						Branch:     domain.ExpectedBranchName(ids.proposalID),
						PRNumber:   9,
						PRURL:      "https://github.com/octo/demo/pull/9",
					}, nil
				},
			},
		})
		if err != nil {
			t.Fatalf("NewServiceWithConfig: %v", err)
		}
		opsSvc := operations.NewService(st, nil, nil)
		op, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
			OperationType: domain.OperationTypeProposalPublish,
			ResourceType:  "proposal",
			ResourceID:    ids.proposalID,
			MaxAttempts:   1,
		})
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		runner, _ := publication.NewRunner(publication.RunnerConfig{Ops: opsSvc, Service: svc})
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce: n=%d err=%v", n, err)
		}

		gotOp, _ := st.GetOperationByID(ctx, op.ID)
		if gotOp.Status != domain.OperationStatusFailed {
			t.Fatalf("expected FAILED op after final attempt Tx 2 error, got %s", gotOp.Status)
		}
		prop, _ := st.GetProposalByID(ctx, ids.proposalID)
		pub, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
		if prop.Status != domain.ProposalStatusPublishing || pub.Status != domain.PublicationStatusPublishing {
			t.Fatalf("post-GitHub Tx 2 outage must NOT clobber proposal/publication to FAILED: prop=%s pub=%s", prop.Status, pub.Status)
		}
	})
}

type tx2FailStore struct {
	*memStore
}

func (s *tx2FailStore) RunInTx(ctx context.Context, fn func(tx publication.TxStore) error) error {
	return s.memStore.RunInTx(ctx, func(tx publication.TxStore) error {
		return fn(&tx2FailTx{TxStore: tx})
	})
}

type tx2FailTx struct {
	publication.TxStore
}

func (t *tx2FailTx) CompletePublicationAttemptSucceeded(context.Context, uuid.UUID, string, time.Time) (persistence.PublicationAttemptRow, error) {
	return persistence.PublicationAttemptRow{}, domain.Unavailable("DATABASE_UNAVAILABLE", "db outage during Step 9")
}

func TestExhaustedMaxAttemptsTransientFailureMarksFailed(t *testing.T) {
	ctx := context.Background()
	fix := setupBareRepoFixture(t, map[string]string{"exhaust.txt": "x\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)

	alwaysUnavailable := &flakyGitPublisher{
		behavior: func(_ int, _ context.Context, _ publish.PublishRequest) (domain.PublicationResult, error) {
			return domain.PublicationResult{}, domain.Unavailable("GITHUB_UNAVAILABLE", "503 persistent outage")
		},
	}

	var nowMu sync.Mutex
	curNow := time.Now().UTC().Truncate(time.Microsecond)
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}

	svc, err := publication.NewServiceWithConfig(publication.Config{
		Store:        st,
		GitPublisher: alwaysUnavailable,
		Clock:        clock,
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}
	opsSvc := operations.NewService(st, nil, nil, operations.Config{
		BaseRetryDelay: 25 * time.Millisecond,
		Clock:          clock,
	})
	op, err := opsSvc.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    ids.proposalID,
		MaxAttempts:   2,
		AvailableAt:   curNow,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:     opsSvc,
		Service: svc,
		Clock:   clock,
	})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	// Attempt 1 -> PENDING retry, proposal & publication stay PUBLISHING.
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce #1: n=%d err=%v", n, err)
	}
	gotOp, _ := st.GetOperationByID(ctx, op.ID)
	if gotOp.Status != domain.OperationStatusPending || gotOp.Attempts != 1 {
		t.Fatalf("expected PENDING after attempt 1, got status=%s attempts=%d", gotOp.Status, gotOp.Attempts)
	}

	// Attempt 2 (MaxAttempts == 2) -> terminal FAILED across operation, proposal, and publication.
	nowMu.Lock()
	curNow = gotOp.AvailableAt.Add(time.Millisecond)
	nowMu.Unlock()
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce #2: n=%d err=%v", n, err)
	}

	gotOp, _ = st.GetOperationByID(ctx, op.ID)
	prop, _ := st.GetProposalByID(ctx, ids.proposalID)
	pub, _ := st.GetPublicationByProposalID(ctx, ids.proposalID)
	if gotOp.Status != domain.OperationStatusFailed || prop.Status != domain.ProposalStatusFailed || pub.Status != domain.PublicationStatusFailed {
		t.Fatalf("expected FAILED after exhausting MaxAttempts=2, got op=%s prop=%s pub=%s", gotOp.Status, prop.Status, pub.Status)
	}
	var hasFailedAudit bool
	for _, ev := range st.auditEvents {
		if ev.EventType == "proposal.publish_failed" {
			hasFailedAudit = true
			break
		}
	}
	if !hasFailedAudit {
		t.Fatalf("expected proposal.publish_failed audit event")
	}
}

type cancel57014Store struct {
	*memStore
}

func (s *cancel57014Store) GetProposalByID(ctx context.Context, id uuid.UUID) (persistence.ProposalRow, error) {
	if ctx.Err() != nil {
		return persistence.ProposalRow{}, domain.WrapError(domain.ErrInternal, "PERSISTENCE_ERROR", "query canceled", errors.New("SQLSTATE 57014"))
	}
	return s.memStore.GetProposalByID(ctx, id)
}

func TestSteps1To6ContextCanceledDoesNotFailProposal(t *testing.T) {
	fix := setupBareRepoFixture(t, map[string]string{"cancel.txt": "ok\n"})
	st := newMemStore()
	ids := seedApprovedProposal(t, st, fix)

	svc, err := publication.NewServiceWithConfig(publication.Config{
		Store:       &cancel57014Store{memStore: st},
		WriteClient: fix.bareClient,
		ArtifactOpener: func() publish.ArtifactOpener {
			o, _ := publication.NewLocalArtifactOpener(publication.LocalOpenerConfig{RootDir: fix.snapRoot})
			return o
		}(),
	})
	if err != nil {
		t.Fatalf("NewServiceWithConfig: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, execErr := svc.ExecutePublication(ctx, ids.proposalID, ids.manifestDigest, true)
	if !errors.Is(execErr, domain.ErrInternal) {
		t.Fatalf("expected ErrInternal from 57014 simulation, got %v", execErr)
	}
	prop, _ := st.GetProposalByID(context.Background(), ids.proposalID)
	if prop.Status != domain.ProposalStatusApproved {
		t.Fatalf("expected proposal to remain APPROVED when ctx is cancelled, got %s", prop.Status)
	}
}

func strPtr(s string) *string { return &s }

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Verify fmt is used if needed
var _ = fmt.Sprintf
