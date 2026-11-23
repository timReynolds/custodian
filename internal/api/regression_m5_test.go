package api_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/api/openapi"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/repositories"
)

func TestM5_RepoConcurrencyLimitsAcrossAllMutationsAndGlobalScanBudgetWithIngress(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.RepoConcurrencyLimit = 1
		d.GlobalScanBudget = 1
		d.GlobalModelBudget = 1
	})

	humanA := env.mintHuman("m5-human-a", "m5a@acme.test", []string{"eng"}, []string{"developer"}, "openid profile email")
	humanB := env.mintHuman("m5-human-b", "m5b@acme.test", []string{"security-reviewers"}, []string{"reviewer"}, "openid profile email")
	ctrlToken := env.mintController("m5-ctrl")

	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))
	_, _ = env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanB))

	// Seed a READY workspace + uploaded snapshot + RECONSTRUCTED proposal + APPROVED proposal.
	wsID, propEvalID, snapID, snapSHA := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	if _, err := env.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = now() WHERE status IN ('PENDING', 'RUNNING')`); err != nil {
		t.Fatalf("clear operations: %v", err)
	}
	_, _, evalProp := env.seedReconstructed(ctx, propEvalID, ctrlCaller.Principal.ID)

	_, propPubID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	manifestDigest, decisionID := env.seedReconstructedAndEvaluated(ctx, propPubID, ctrlCaller.Principal.ID, domain.PolicyEffectAllow, nil)
	recApprove := env.do(http.MethodPost, "/v1/proposals/"+propPubID.String()+"/approvals", humanB, "m5-approve-1", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        decisionID.String(),
	}, nil, nil)
	if recApprove.Code != http.StatusCreated {
		t.Fatalf("approve propPubID expected 201, got %d: %s", recApprove.Code, recApprove.Body.String())
	}

	if _, err := env.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = now() WHERE status IN ('PENDING', 'RUNNING')`); err != nil {
		t.Fatalf("clear operations 2: %v", err)
	}

	// Occupy repo slot & global scan budget with 1 WORKSPACE_INGRESS operation.
	recWS := env.do(http.MethodPost, "/v1/workspaces", humanA, "m5-ws-1", map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}, nil, nil)
	if recWS.Code != http.StatusAccepted {
		t.Fatalf("first CreateWorkspace expected 202, got %d: %s", recWS.Code, recWS.Body.String())
	}

	// 1. Second CreateWorkspace -> 429 REPO_CONCURRENCY_LIMIT_EXCEEDED
	recWS2 := env.do(http.MethodPost, "/v1/workspaces", humanA, "m5-ws-2", map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}, nil, nil)
	if recWS2.Code != http.StatusTooManyRequests {
		t.Fatalf("second CreateWorkspace expected 429, got %d: %s", recWS2.Code, recWS2.Body.String())
	}

	// 2. SubmitProposal on same repo -> 429 REPO_CONCURRENCY_LIMIT_EXCEEDED
	recSub := env.do(http.MethodPost, "/v1/workspaces/"+wsID.String()+"/proposals", ctrlToken, "m5-sub-429", map[string]any{
		"snapshot": map[string]any{
			"artifact_id":          snapID.String(),
			"sha256":               snapSHA,
			"workspace_generation": 1,
		},
		"title": "blocked by repo limit",
	}, nil, nil)
	if recSub.Code != http.StatusTooManyRequests || !strings.Contains(recSub.Body.String(), "REPO_CONCURRENCY_LIMIT_EXCEEDED") {
		t.Fatalf("SubmitProposal expected 429 REPO_CONCURRENCY_LIMIT_EXCEEDED, got %d: %s", recSub.Code, recSub.Body.String())
	}

	// 3. EvaluateProposal on same repo -> 429 REPO_CONCURRENCY_LIMIT_EXCEEDED
	recEval := env.do(http.MethodPost, "/v1/proposals/"+propEvalID.String()+"/evaluate", ctrlToken, "m5-eval-429", map[string]any{
		"expected_version": evalProp.Version,
	}, nil, nil)
	if recEval.Code != http.StatusTooManyRequests || !strings.Contains(recEval.Body.String(), "REPO_CONCURRENCY_LIMIT_EXCEEDED") {
		t.Fatalf("EvaluateProposal expected 429 REPO_CONCURRENCY_LIMIT_EXCEEDED, got %d: %s", recEval.Code, recEval.Body.String())
	}

	// 4. PublishProposal on same repo -> 429 REPO_CONCURRENCY_LIMIT_EXCEEDED
	recPub := env.do(http.MethodPost, "/v1/proposals/"+propPubID.String()+"/publish", ctrlToken, "m5-pub-429", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil, nil)
	if recPub.Code != http.StatusTooManyRequests || !strings.Contains(recPub.Body.String(), "REPO_CONCURRENCY_LIMIT_EXCEEDED") {
		t.Fatalf("PublishProposal expected 429 REPO_CONCURRENCY_LIMIT_EXCEEDED, got %d: %s", recPub.Code, recPub.Body.String())
	}

	// 5. EvaluateProposal on repo1 while a DIFFERENT repo has active WORKSPACE_INGRESS -> 429 GLOBAL_SCAN_BUDGET_EXCEEDED
	if _, err := env.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = now() WHERE status IN ('PENDING', 'RUNNING')`); err != nil {
		t.Fatalf("clear operations 3: %v", err)
	}
	repo2, err := env.repos.Upsert(ctx, repositories.UpsertInput{
		ID:                      domain.MustNewID(),
		GitHubRepositoryID:      env.repo.GitHubRepositoryID + 77,
		GitHubInstallationID:    env.repo.GitHubInstallationID + 77,
		FullName:                "acme/other-repo",
		Classification:          domain.ClassificationInternal,
		Enabled:                 true,
		AllowedModelRoutes:      []string{"approved-code-review"},
		MaxConcurrentOperations: 5,
	})
	if err != nil {
		t.Fatalf("repos.Upsert repo2: %v", err)
	}
	ws2, err := env.store.CreateWorkspace(ctx, persistence.CreateWorkspaceParams{
		RepositoryID: repo2.ID,
		OwnerID:      humanACaller.Principal.ID,
		BaseCommit:   strings.Repeat("a", 40),
		TargetRef:    "main",
		Status:       domain.WorkspaceStatusReady,
	})
	if err != nil {
		t.Fatalf("CreateWorkspace repo2: %v", err)
	}
	if _, err := env.operations.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    ws2.ID,
		MaxAttempts:   3,
	}); err != nil {
		t.Fatalf("Enqueue WORKSPACE_INGRESS on ws2: %v", err)
	}

	recEvalGlobal := env.do(http.MethodPost, "/v1/proposals/"+propEvalID.String()+"/evaluate", ctrlToken, "m5-eval-global-429", map[string]any{
		"expected_version": evalProp.Version,
	}, nil, nil)
	if recEvalGlobal.Code != http.StatusTooManyRequests || !strings.Contains(recEvalGlobal.Body.String(), "GLOBAL_SCAN_BUDGET_EXCEEDED") {
		t.Fatalf("EvaluateProposal expected 429 GLOBAL_SCAN_BUDGET_EXCEEDED, got %d: %s", recEvalGlobal.Code, recEvalGlobal.Body.String())
	}

	// CreateWorkspace on repo1 while repo2 has WORKSPACE_INGRESS -> 429 GLOBAL_SCAN_BUDGET_EXCEEDED
	recWSGlobal := env.do(http.MethodPost, "/v1/workspaces", humanA, "m5-ws-global-429", map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}, nil, nil)
	if recWSGlobal.Code != http.StatusTooManyRequests || !strings.Contains(recWSGlobal.Body.String(), "GLOBAL_SCAN_BUDGET_EXCEEDED") {
		t.Fatalf("CreateWorkspace expected 429 GLOBAL_SCAN_BUDGET_EXCEEDED, got %d: %s", recWSGlobal.Code, recWSGlobal.Body.String())
	}
}

func TestM5_OpenAPIIfMatchAndApprovalsRevokedAudit(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, nil)

	val, err := openapi.NewHTTPValidator()
	if err != nil {
		t.Fatalf("NewHTTPValidator: %v", err)
	}
	defer val.Release()

	humanA := env.mintHuman("m5-idem-a", "m5ia@acme.test", []string{"eng"}, []string{"developer"}, "openid profile email")
	humanB := env.mintHuman("m5-idem-b", "m5ib@acme.test", []string{"security-reviewers"}, []string{"reviewer"}, "openid profile email")
	ctrlToken := env.mintController("m5-idem-ctrl")

	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))
	_, _ = env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanB))

	_, propID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	manifestDigest, decisionID := env.seedReconstructedAndEvaluated(ctx, propID, ctrlCaller.Principal.ID, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "REQUIRE_APPROVAL", ReviewerGroup: "security-reviewers", Minimum: 2},
	})
	recApprove := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/approvals", humanB, "m5-app-rev", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        decisionID.String(),
	}, nil, val)
	if recApprove.Code != http.StatusCreated {
		t.Fatalf("approve expected 201, got %d: %s", recApprove.Code, recApprove.Body.String())
	}

	details, err := env.proposals.GetDetails(ctx, propID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	recEval := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "m5-reeval-ifmatch", map[string]any{}, map[string]string{
		"If-Match": `"` + strconv.FormatInt(details.Version, 10) + `"`,
	}, val)
	if recEval.Code != http.StatusAccepted {
		t.Fatalf("re-evaluate with If-Match expected 202, got %d: %s", recEval.Code, recEval.Body.String())
	}

	var revokedCount int
	if err := env.pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE resource_id = $1 AND event_type = 'proposal.approvals_revoked'`, propID).Scan(&revokedCount); err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	if revokedCount < 1 {
		t.Fatalf("expected >= 1 proposal.approvals_revoked audit event, got %d", revokedCount)
	}
}
