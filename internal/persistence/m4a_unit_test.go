package persistence_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestM4aAdditiveQueriesValidationUnit(t *testing.T) {
	t.Parallel()

	q := persistence.New(nil)
	ctx := context.Background()

	if _, err := q.CountActiveOperationsByRepository(ctx, uuid.Nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CountActiveOperationsByRepository(nil): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.CountActiveOperationsByType(ctx, domain.OperationType("BOGUS")); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CountActiveOperationsByType(BOGUS): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.GetLatestOperationByResource(ctx, uuid.Nil, domain.OperationTypeProposalPublish); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("GetLatestOperationByResource(nil): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.GetLatestOperationByResource(ctx, domain.MustNewID(), domain.OperationType("BOGUS")); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("GetLatestOperationByResource(BOGUS): expected ErrBadRequest, got %v", err)
	}

	if _, err := q.GetRepositoryByFullName(ctx, ""); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("GetRepositoryByFullName(''): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.GetRepositoryByFullName(ctx, "noslash"); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("GetRepositoryByFullName('noslash'): expected ErrBadRequest, got %v", err)
	}

	repoID := domain.MustNewID()
	nilUUID := uuid.Nil
	validDigest := domain.SHA256Hex([]byte("bundle"))
	for _, tc := range []struct {
		name string
		arg  persistence.CreatePolicyBundleParams
	}{
		{
			name: "org_with_repo_id",
			arg: persistence.CreatePolicyBundleParams{
				Name:         "b",
				Version:      "1.0.0",
				Scope:        domain.PolicyScopeOrg,
				RepositoryID: &repoID,
				Digest:       validDigest,
				Definition:   json.RawMessage(`{"rules":[]}`),
			},
		},
		{
			name: "repo_without_repo_id",
			arg: persistence.CreatePolicyBundleParams{
				Name:       "b",
				Version:    "1.0.0",
				Scope:      domain.PolicyScopeRepo,
				Digest:     validDigest,
				Definition: json.RawMessage(`{"rules":[]}`),
			},
		},
		{
			name: "null_definition",
			arg: persistence.CreatePolicyBundleParams{
				Name:       "b",
				Version:    "1.0.0",
				Scope:      domain.PolicyScopeOrg,
				Digest:     validDigest,
				Definition: json.RawMessage(`null`),
			},
		},
		{
			name: "invalid_digest",
			arg: persistence.CreatePolicyBundleParams{
				Name:       "b",
				Version:    "1.0.0",
				Scope:      domain.PolicyScopeOrg,
				Digest:     "bad",
				Definition: json.RawMessage(`{"rules":[]}`),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := q.UpsertPolicyBundleByDigest(ctx, tc.arg); !errors.Is(err, domain.ErrBadRequest) {
				t.Fatalf("UpsertPolicyBundleByDigest(%s): expected ErrBadRequest, got %v", tc.name, err)
			}
		})
	}

	if _, err := q.ListActivePolicyBundlesByScope(ctx, domain.PolicyScope("BAD"), nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListActivePolicyBundlesByScope(BAD): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, &repoID); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListActivePolicyBundlesByScope(ORG+repo): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeRepo, nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListActivePolicyBundlesByScope(REPO+nil): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeRepo, &nilUUID); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListActivePolicyBundlesByScope(REPO+NilUUID): expected ErrBadRequest, got %v", err)
	}

	if _, err := q.GetProposalByIDForUpdate(ctx, uuid.Nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("GetProposalByIDForUpdate(nil): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.ListProposalDetailsByWorkspace(ctx, uuid.Nil, 10); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListProposalDetailsByWorkspace(nil): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.ListProposalDetailsByOwner(ctx, persistence.ListProposalsByOwnerParams{OwnerID: uuid.Nil}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListProposalDetailsByOwner(nil): expected ErrBadRequest, got %v", err)
	}
	badStatus := domain.ProposalStatus("BOGUS")
	if _, err := q.ListProposalDetailsByOwner(ctx, persistence.ListProposalsByOwnerParams{OwnerID: domain.MustNewID(), Status: &badStatus}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("ListProposalDetailsByOwner(BOGUS): expected ErrBadRequest, got %v", err)
	}
	if _, err := q.GetApprovalRequirementByID(ctx, uuid.Nil); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("GetApprovalRequirementByID(nil): expected ErrBadRequest, got %v", err)
	}
}
