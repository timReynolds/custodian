package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/api/openapi"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/test/fixtures"
)

func TestRG08_IdempotentSingleCommitSinglePRPublication(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	ownerTok := st.MintHuman("rg08-owner", "rg08o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("rg08-rev", "rg08r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("rg08-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# RG08\n")},
		{Name: "feature.go", Body: []byte("package main\nfunc Feature() {}\n")},
	})

	code, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "rg08-eval", map[string]any{
		"expected_version": version,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d", code)
	}
	st.DrainWorker(ctx)

	code, propRaw := st.DoJSON(http.MethodGet, "/v1/proposals/"+propID, ownerTok, "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GetProposal expected 200, got %d", code)
	}
	var propOut struct {
		PolicyEvaluationID string `json:"latest_policy_evaluation_id"`
	}
	_ = json.Unmarshal(propRaw, &propOut)

	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg08-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve expected 201, got %d", code)
	}

	// Publish twice with DIFFERENT idempotency keys -> must converge on 1 publication, 1 branch, 1 PR.
	code1, pubRaw1 := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg08-pub-1", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if code1 != http.StatusAccepted {
		t.Fatalf("Publish #1 expected 202, got %d: %s", code1, string(pubRaw1))
	}
	st.DrainPublisher(ctx)

	code2, pubRaw2 := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg08-pub-2", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if code2 != http.StatusAccepted {
		t.Fatalf("Publish #2 expected 202, got %d: %s", code2, string(pubRaw2))
	}
	st.DrainPublisher(ctx)

	var p1, p2 struct {
		PublicationID     string `json:"publication_id"`
		PullRequestNumber int64  `json:"pull_request_number"`
	}
	_ = json.Unmarshal(pubRaw1, &p1)
	_ = json.Unmarshal(pubRaw2, &p2)
	if p1.PublicationID != p2.PublicationID {
		t.Fatalf("RG-08 violation: duplicate publication created (%s vs %s)", p1.PublicationID, p2.PublicationID)
	}

	// Verify exactly 1 PR and 2 branches (main + custodian/<proposal-id>) in bare git.
	prs := st.WriteClient.PullRequests(st.BareRepo.FullName)
	if len(prs) != 1 {
		t.Fatalf("RG-08 violation: expected 1 PR, got %d (%+v)", len(prs), prs)
	}
	out, err := exec.Command("git", "-C", st.BareRepo.BarePath, "for-each-ref", "--format=%(refname:short)", "refs/heads").CombinedOutput()
	if err != nil {
		t.Fatalf("git for-each-ref: %v (%s)", err, string(out))
	}
	branches := strings.Fields(strings.TrimSpace(string(out)))
	if len(branches) != 2 {
		t.Fatalf("expected 2 branches (main + custodian/%s), got %v", propID, branches)
	}
}

func TestRG09_FullTraceabilityLineageAndAuditChain(t *testing.T) {
	ctx := context.Background()
	twoReviewerPolicy := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: rg09-two-reviewers
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
inspection:
  mandatory: [gitleaks, scancode, semgrep]
rules:
  - id: repo.two.reviewers
    stages: [EGRESS]
    when: "true"
    effect: REQUIRE_APPROVAL
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: security-reviewers
        minimum: 2
  - id: repo.ingress.allow
    stages: [INGRESS]
    when: "findings.scan_complete && findings.critical_secrets == 0 && findings.prohibited_licenses == 0"
    effect: ALLOW
`
	st := fixtures.NewFullStack(t, fixtures.WithRepoPolicy(twoReviewerPolicy))

	val, err := openapi.NewHTTPValidator()
	if err != nil {
		t.Fatalf("NewHTTPValidator: %v", err)
	}
	defer val.Release()

	ownerTok := st.MintHuman("rg09-owner", "rg09o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("rg09-rev", "rg09r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	reviewer2Tok := st.MintHuman("rg09-rev2", "rg09r2@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("rg09-ctrl")
	auditorTok := st.MintAuditor("rg09-aud")

	wsID, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# RG09\n")},
		{Name: "trace.go", Body: []byte("package main\nfunc Trace() {}\n")},
	})

	// Evaluate using OpenAPI-validated If-Match header.
	reqEval, _ := http.NewRequest(http.MethodPost, st.Server.URL+"/v1/proposals/"+propID+"/evaluate", strings.NewReader(`{}`))
	reqEval.Header.Set("Authorization", "Bearer "+ctrlTok)
	reqEval.Header.Set("Content-Type", "application/json")
	reqEval.Header.Set("Idempotency-Key", "rg09-eval-1")
	reqEval.Header.Set("If-Match", `"`+strconv.FormatInt(version, 10)+`"`)
	if ok, valErrs := val.ValidateHttpRequestSync(reqEval); !ok {
		t.Fatalf("OpenAPI If-Match validation failed: %+v", valErrs)
	}
	code, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "rg09-eval-1", map[string]any{}, map[string]string{
		"If-Match": `"` + strconv.FormatInt(version, 10) + `"`,
	})
	if code != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d", code)
	}
	st.DrainWorker(ctx)

	code, propRaw := st.DoJSON(http.MethodGet, "/v1/proposals/"+propID, ownerTok, "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GetProposal expected 200, got %d", code)
	}
	var propOut struct {
		Version            int64  `json:"version"`
		PolicyEvaluationID string `json:"latest_policy_evaluation_id"`
	}
	_ = json.Unmarshal(propRaw, &propOut)

	// Approve, then re-evaluate to verify proposal.approvals_revoked audit & outbox events.
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg09-app-1", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve #1 expected 201, got %d", code)
	}
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "rg09-eval-2", map[string]any{}, map[string]string{
		"If-Match": `"` + strconv.FormatInt(propOut.Version, 10) + `"`,
	})
	if code != http.StatusAccepted {
		t.Fatalf("Re-evaluate expected 202, got %d", code)
	}
	st.DrainWorker(ctx)

	code, propRaw2 := st.DoJSON(http.MethodGet, "/v1/proposals/"+propID, ownerTok, "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GetProposal #2 expected 200, got %d", code)
	}
	_ = json.Unmarshal(propRaw2, &propOut)

	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg09-app-2a", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve #2a expected 201, got %d", code)
	}
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewer2Tok, "rg09-app-2b", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve #2b expected 201, got %d", code)
	}
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg09-pub", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Publish expected 202, got %d", code)
	}
	st.DrainPublisher(ctx)

	// Verify commit trailers & author/committer metadata in bare Git.
	commitMeta, err := exec.Command("git", "-C", st.BareRepo.BarePath, "log", "-1", "--format=%an|%ae|%cn|%ce|%B", "custodian/"+propID).CombinedOutput()
	if err != nil {
		t.Fatalf("git log custodian/%s: %v (%s)", propID, err, string(commitMeta))
	}
	metaStr := string(commitMeta)
	for _, want := range []string{
		"rg09-owner|rg09o@acme.test|Custodian|",
		"Custodian-Proposal: " + propID,
		"Custodian-Workspace: " + wsID,
		"Agent-Assisted: true",
	} {
		if !strings.Contains(metaStr, want) {
			t.Fatalf("RG-09 violation: commit metadata missing %q in:\n%s", want, metaStr)
		}
	}

	// Verify audit chain via auditor endpoint & proposal.approvals_revoked presence.
	code, audRaw := st.DoJSON(http.MethodGet, "/v1/audit/events?limit=200", auditorTok, "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/audit/events expected 200, got %d: %s", code, string(audRaw))
	}
	if !strings.Contains(string(audRaw), `"proposal.approvals_revoked"`) {
		t.Fatalf("expected proposal.approvals_revoked in audit events, got: %s", string(audRaw))
	}
	if verifyRes, err := st.Audit.VerifyChain(ctx); err != nil || verifyRes.EventCount == 0 {
		t.Fatalf("RG-09 violation: audit hash chain verification failed: (%+v, %v)", verifyRes, err)
	}
}

func TestRG10_AdmissionLimitsBudgetsAndOutageRecovery(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t, fixtures.WithLimits(1, 1, 1))

	ownerTok := st.MintHuman("rg10-owner", "rg10o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("rg10-rev", "rg10r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("rg10-ctrl")

	// Seed a READY workspace & reconstructed proposal while limits are temporarily free.
	wsID, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# RG10\n")},
	})

	// Test transient gateway outage recovery via retry!
	st.Gateway.SetStatus(http.StatusServiceUnavailable)
	code, evalRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "rg10-eval-1", map[string]any{
		"expected_version": version,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d: %s", code, string(evalRaw))
	}
	var evalResp struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(evalRaw, &evalResp)

	// While active PROPOSAL_EVALUATE exists -> second Evaluate / CreateWorkspace / SubmitProposal all 429!
	codeWS429, _ := st.DoJSON(http.MethodPost, "/v1/workspaces", ownerTok, "rg10-ws-429", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": st.Repo.GitHubRepositoryID, "ref": "main"},
	}, nil)
	if codeWS429 != http.StatusTooManyRequests {
		t.Fatalf("CreateWorkspace while repo busy expected 429, got %d", codeWS429)
	}

	// Attempt 1 hits 503 -> retryable, operation goes back to PENDING.
	_, err := st.WorkerRunner.ProcessOnce(ctx)
	if err != nil {
		t.Fatalf("ProcessOnce(503): %v", err)
	}
	opAfter503, err := st.Operations.GetDetails(ctx, uuid.MustParse(evalResp.OperationID))
	if err != nil || opAfter503.Status != domain.OperationStatusPending {
		t.Fatalf("expected PENDING retryable op after 503 outage, got (%+v, %v)", opAfter503.Status, err)
	}

	// Restore gateway, make operation immediately available, drain -> PENDING_APPROVAL.
	st.Gateway.SetStatus(http.StatusOK)
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE operations SET available_at = now() - interval '1 second' WHERE id = $1`, uuid.MustParse(evalResp.OperationID)); err != nil {
		t.Fatalf("make op available: %v", err)
	}
	st.DrainWorker(ctx)

	code, propRaw := st.DoJSON(http.MethodGet, "/v1/proposals/"+propID, ownerTok, "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GetProposal expected 200, got %d", code)
	}
	var propOut struct {
		Status             string `json:"status"`
		PolicyEvaluationID string `json:"latest_policy_evaluation_id"`
	}
	_ = json.Unmarshal(propRaw, &propOut)
	if propOut.Status != "PENDING_APPROVAL" {
		t.Fatalf("expected PENDING_APPROVAL after outage recovery, got %q", propOut.Status)
	}

	// Enqueue an active WORKSPACE_INGRESS manually via CreateWorkspace, verify Submit & Publish return 429!
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg10-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve expected 201, got %d", code)
	}

	if _, err := st.Operations.Enqueue(ctx, operations.EnqueueInput{
		OperationType: domain.OperationTypeWorkspaceIngress,
		ResourceType:  "workspace",
		ResourceID:    uuid.MustParse(wsID),
		MaxAttempts:   3,
	}); err != nil {
		t.Fatalf("Enqueue WORKSPACE_INGRESS: %v", err)
	}
	codePub429, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg10-pub-429", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if codePub429 != http.StatusTooManyRequests {
		t.Fatalf("Publish while repo concurrency full expected 429, got %d", codePub429)
	}
}
