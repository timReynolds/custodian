package adversarial_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/test/fixtures"
)

func TestADV10_StaleEvaluateCrashRecoveryAndDigestStaleness(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	ownerTok := st.MintHuman("adv10-owner", "adv10o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("adv10-rev", "adv10r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("adv10-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# ADV10\n")},
	})
	propUUID := uuid.MustParse(propID)

	// Request evaluation, claim PROPOSAL_EVALUATE, run ExecuteEvaluate WITHOUT ops.Complete.
	code, evalRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "adv10-eval", map[string]any{
		"expected_version": version,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d", code)
	}
	var evalOut struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(evalRaw, &evalOut)
	opUUID := uuid.MustParse(evalOut.OperationID)

	opType := domain.OperationTypeProposalEvaluate
	claimed, err := st.Operations.Claim(ctx, operations.ClaimInput{
		WorkerID:      "crashed-worker",
		OperationType: &opType,
		Limit:         1,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("Claim: (%d, %v)", len(claimed), err)
	}
	if _, err := st.WorkflowSvc.ExecuteEvaluate(ctx, claimed[0]); err != nil {
		t.Fatalf("ExecuteEvaluate: %v", err)
	}

	// Human approves while op lease is still uncompleted -> APPROVED.
	propRow, err := st.Store.GetProposalByID(ctx, propUUID)
	if err != nil {
		t.Fatalf("GetProposalByID: %v", err)
	}
	code, appRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "adv10-approve", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propRow.LatestPolicyEvaluationID.String(),
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve expected 201, got %d: %s", code, string(appRaw))
	}

	// Expire op lease and run WorkerRunner.ProcessOnce -> must NOT overwrite APPROVED to FAILED!
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE operations SET lease_until = now() - interval '5 seconds' WHERE id = $1`, opUUID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	gwCallsBefore := st.Gateway.CallCount()
	if _, err := st.WorkerRunner.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce recovery: %v", err)
	}

	after, err := st.Store.GetProposalByID(ctx, propUUID)
	if err != nil {
		t.Fatalf("GetProposalByID after recovery: %v", err)
	}
	if after.Status != domain.ProposalStatusApproved {
		t.Fatalf("ADV-10 / P1-BUG-01 violation: expected APPROVED preserved, got %s", after.Status)
	}
	if st.Gateway.CallCount() != gwCallsBefore {
		t.Fatalf("expected 0 gateway re-calls on stale evaluate retry")
	}

	// Stale digest approval after evaluation also fails (409).
	codeStale, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "adv10-stale-digest", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": strings.Repeat("f", 64),
		"policy_evaluation_id":        propRow.LatestPolicyEvaluationID.String(),
	}, nil)
	if codeStale != http.StatusConflict {
		t.Fatalf("stale digest approval expected 409, got %d", codeStale)
	}
}

func TestADV11_UpstreamForcePushAbort(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	ownerTok := st.MintHuman("adv11-owner", "adv11o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("adv11-rev", "adv11r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("adv11-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# ADV11\n")},
	})

	code, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "adv11-eval", map[string]any{
		"expected_version": version,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d", code)
	}
	st.DrainWorker(ctx)

	propRow, _ := st.Store.GetProposalByID(ctx, uuid.MustParse(propID))
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "adv11-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propRow.LatestPolicyEvaluationID.String(),
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve expected 201, got %d", code)
	}

	// Simulate an orphan upstream force-push on bare repo's main branch before publication executes.
	workDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		out, gErr := cmd.CombinedOutput()
		if gErr != nil {
			t.Fatalf("git %v: %v\n%s", args, gErr, string(out))
		}
	}
	runGit("init", "--initial-branch=main", workDir)
	runGit("-C", workDir, "config", "user.name", "ForcePusher")
	runGit("-C", workDir, "config", "user.email", "fp@acme.test")
	runGit("-C", workDir, "commit", "--allow-empty", "-m", "orphan force push")
	runGit("-C", workDir, "push", "--force", st.BareRepo.BarePath, "HEAD:refs/heads/main")

	code, pubRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "adv11-pub", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Publish expected 202, got %d: %s", code, string(pubRaw))
	}
	var pubOut struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(pubRaw, &pubOut)
	st.DrainPublisher(ctx)

	op, err := st.Operations.GetDetails(ctx, uuid.MustParse(pubOut.OperationID))
	if err != nil || op.Status != domain.OperationStatusFailed || !strings.Contains(op.LastError, "UPSTREAM_FORCE_PUSH") {
		t.Fatalf("ADV-11 violation: expected FAILED op with UPSTREAM_FORCE_PUSH, got status=%s lastErr=%q err=%v", op.Status, op.LastError, err)
	}
	if len(st.WriteClient.PullRequests(st.BareRepo.FullName)) != 0 {
		t.Fatalf("ADV-11 violation: expected 0 PRs after upstream force-push abort")
	}
}

func TestADV12_ConcurrentPublishRaces(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	ownerTok := st.MintHuman("adv12-owner", "adv12o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("adv12-rev", "adv12r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("adv12-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# ADV12\n")},
		{Name: "race.go", Body: []byte("package main\nfunc Race() {}\n")},
	})

	code, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "adv12-eval", map[string]any{
		"expected_version": version,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d", code)
	}
	st.DrainWorker(ctx)

	propRow, _ := st.Store.GetProposalByID(ctx, uuid.MustParse(propID))
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "adv12-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propRow.LatestPolicyEvaluationID.String(),
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("Approve expected 201, got %d", code)
	}

	const racers = 5
	codes := make([]int, racers)
	pubIDs := make([]string, racers)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-gate
			c, raw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "adv12-race-"+string(rune('a'+idx)), map[string]any{
				"publication_manifest_digest": manifestDigest,
			}, nil)
			codes[idx] = c
			var out struct {
				PublicationID string `json:"publication_id"`
			}
			_ = json.Unmarshal(raw, &out)
			pubIDs[idx] = out.PublicationID
		}(i)
	}
	close(gate)
	wg.Wait()

	st.DrainPublisher(ctx)

	var seenID string
	for i, c := range codes {
		if c != http.StatusAccepted && c != http.StatusConflict {
			t.Fatalf("racer %d unexpected status %d", i, c)
		}
		if c == http.StatusAccepted && pubIDs[i] != "" {
			if seenID == "" {
				seenID = pubIDs[i]
			} else if pubIDs[i] != seenID {
				t.Fatalf("ADV-12 violation: concurrent publish created distinct publication IDs (%s vs %s)", seenID, pubIDs[i])
			}
		}
	}
	if seenID == "" {
		t.Fatalf("expected at least one publish request accepted")
	}
	if prs := st.WriteClient.PullRequests(st.BareRepo.FullName); len(prs) != 1 {
		t.Fatalf("ADV-12 violation: expected 1 PR under concurrent publish race, got %d", len(prs))
	}
}
