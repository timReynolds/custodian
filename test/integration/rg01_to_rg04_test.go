package integration_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/test/fixtures"
)

func TestRG01_CredentiallessWorkspaceAndReadOnlyIngress(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	humanTok := st.MintHuman("rg01-owner", "rg01@acme.test", []string{"eng"}, []string{"developer"})
	ctrlTok := st.MintController("rg01-ctrl")

	code, wsRaw := st.DoJSON(http.MethodPost, "/v1/workspaces", humanTok, "rg01-ws-1", map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": st.Repo.GitHubRepositoryID,
			"ref":           "main",
		},
		"source_options": map[string]any{"include_git_metadata": true, "include_history": false},
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("CreateWorkspace expected 202, got %d: %s", code, string(wsRaw))
	}
	var wsOut struct {
		WorkspaceID string `json:"workspace_id"`
	}
	_ = json.Unmarshal(wsRaw, &wsOut)
	st.DrainWorker(ctx)

	// Controller downloads source archive and verifies zero credentials/hooks/remotes exist inside.
	code, descRaw := st.DoJSON(http.MethodGet, "/v1/workspaces/"+wsOut.WorkspaceID+"/source", ctrlTok, "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /source expected 200, got %d: %s", code, string(descRaw))
	}
	var desc struct {
		Download struct {
			URL string `json:"url"`
		} `json:"download"`
	}
	_ = json.Unmarshal(descRaw, &desc)

	dlURL := desc.Download.URL
	if strings.HasPrefix(dlURL, "http://127.0.0.1:8080") {
		dlURL = st.Server.URL + strings.TrimPrefix(dlURL, "http://127.0.0.1:8080")
	}
	dlReq, _ := http.NewRequest(http.MethodGet, dlURL, nil)
	dlReq.Header.Set("Authorization", "Bearer "+ctrlTok)
	dlResp, err := http.DefaultClient.Do(dlReq)
	if err != nil {
		t.Fatalf("download source artifact: %v", err)
	}
	tarGzBytes, _ := io.ReadAll(dlResp.Body)
	dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		t.Fatalf("download source expected 200, got %d", dlResp.StatusCode)
	}

	gr, err := gzip.NewReader(bytes.NewReader(tarGzBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		if strings.Contains(hdr.Name, ".git/hooks/") {
			t.Fatalf("RG-01 violation: .git/hooks leaked in workspace source archive: %s", hdr.Name)
		}
		if hdr.Typeflag == tar.TypeReg {
			body, _ := io.ReadAll(tr)
			text := string(body)
			for _, bad := range []string{"ghp_", "github_pat_", "x-access-token", "BEGIN RSA PRIVATE KEY", "Authorization:"} {
				if strings.Contains(text, bad) {
					t.Fatalf("RG-01 violation: credential marker %q found in %s", bad, hdr.Name)
				}
			}
		}
	}

	// Human cannot access controller-only GET /source (403).
	code, _ = st.DoJSON(http.MethodGet, "/v1/workspaces/"+wsOut.WorkspaceID+"/source", humanTok, "", nil, nil)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for human GET /source, got %d", code)
	}
}

func TestRG02_AntiImpersonationAndOwnerBinding(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	humanTok := st.MintHuman("rg02-alice", "alice@acme.test", []string{"eng"}, []string{"developer"})
	ctrlTok := st.MintController("rg02-ctrl")

	// 1. Controller cannot create a workspace (HUMAN_CALLER_REQUIRED -> 403).
	code, _ := st.DoJSON(http.MethodPost, "/v1/workspaces", ctrlTok, "rg02-ctrl-ws", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": st.Repo.GitHubRepositoryID, "ref": "main"},
	}, nil)
	if code != http.StatusForbidden {
		t.Fatalf("expected 403 for CONTROLLER CreateWorkspace, got %d", code)
	}

	// 2. Caller cannot spoof owner_id in CreateWorkspace (unknown field rejected -> 400).
	code, _ = st.DoJSON(http.MethodPost, "/v1/workspaces", humanTok, "rg02-spoof", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": st.Repo.GitHubRepositoryID, "ref": "main"},
		"owner_id":   domain.MustNewID().String(),
	}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for spoofed owner_id, got %d", code)
	}

	// 3. PG17 UpsertPrincipal rejects kind escalation AGENT -> HUMAN.
	agentRow, err := st.Store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:        domain.PrincipalKindAgent,
		Issuer:      st.OIDC.Issuer(),
		Subject:     "rg02-agent-subj",
		DisplayName: "RG02 Agent",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(AGENT): %v", err)
	}
	escalated, err := st.Store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        st.OIDC.Issuer(),
		Subject:       "rg02-agent-subj",
		DisplayName:   "Spoofed Human",
		VerifiedEmail: "spoof@acme.test",
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal(HUMAN conflict): %v", err)
	}
	if escalated.Kind != domain.PrincipalKindAgent || escalated.ID != agentRow.ID {
		t.Fatalf("RG-02 violation: principal kind mutated from AGENT to %s", escalated.Kind)
	}
}

func TestRG03_MandatoryHumanApprovalAndSoD(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	ownerTok := st.MintHuman("rg03-owner", "owner@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("rg03-reviewer", "rev@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("rg03-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# RG03\n")},
		{Name: "main.go", Body: []byte("package main\nfunc main() { println(\"rg03\") }\n")},
	})

	// Evaluate clean change -> ALLOW maps to PENDING_APPROVAL (never auto-publishes).
	code, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "rg03-eval", map[string]any{
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
		Status             string `json:"status"`
		PolicyEvaluationID string `json:"latest_policy_evaluation_id"`
	}
	_ = json.Unmarshal(propRaw, &propOut)
	if propOut.Status != "PENDING_APPROVAL" {
		t.Fatalf("RG-03 violation: expected PENDING_APPROVAL, got %q", propOut.Status)
	}

	// Unapproved publish must fail (409).
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg03-pub-unapproved", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if code != http.StatusConflict {
		t.Fatalf("unapproved publish expected 409, got %d", code)
	}

	// Owner self-approval rejected (403 SOD_SELF_APPROVAL_FORBIDDEN).
	code, selfRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", ownerTok, "rg03-self-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusForbidden || !strings.Contains(string(selfRaw), "SOD_SELF_APPROVAL_FORBIDDEN") {
		t.Fatalf("owner self-approval expected 403 SOD_SELF_APPROVAL_FORBIDDEN, got %d: %s", code, string(selfRaw))
	}

	// Controller (non-human) approval rejected (403).
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", ctrlTok, "rg03-ctrl-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusForbidden {
		t.Fatalf("controller approval expected 403, got %d", code)
	}

	// Independent human reviewer approval unlocks APPROVED -> PUBLISHED.
	code, appRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg03-rev-app", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("reviewer approval expected 201, got %d: %s", code, string(appRaw))
	}
	code, pubRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg03-pub-ok", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("approved publish expected 202, got %d: %s", code, string(pubRaw))
	}
	st.DrainPublisher(ctx)

	propUUID := uuid.MustParse(propID)
	finalProp, err := st.Store.GetProposalByID(ctx, propUUID)
	if err != nil || finalProp.Status != domain.ProposalStatusPublished {
		t.Fatalf("expected PUBLISHED proposal, got (%s, %v)", finalProp.Status, err)
	}
}

func TestRG04_ArtifactToApprovalDigestIntegrity(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	ownerTok := st.MintHuman("rg04-owner", "rg04o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("rg04-rev", "rg04r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("rg04-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# RG04\n")},
		{Name: "main.go", Body: []byte("package main\nfunc main() {}\n")},
	})

	code, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "rg04-eval", map[string]any{
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

	// Stale/tampered manifest digest in approval must fail with 409 MANIFEST_DIGEST_MISMATCH.
	wrongDigest := strings.Repeat("b", 64)
	code, wrongRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg04-app-wrong", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": wrongDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusConflict || !strings.Contains(string(wrongRaw), "MANIFEST_DIGEST_MISMATCH") {
		t.Fatalf("stale digest approval expected 409 MANIFEST_DIGEST_MISMATCH, got %d: %s", code, string(wrongRaw))
	}

	// Approve valid digest, then publish with wrong digest -> rejected 409.
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "rg04-app-ok", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propOut.PolicyEvaluationID,
	}, nil)
	if code != http.StatusCreated {
		t.Fatalf("valid approval expected 201, got %d", code)
	}
	code, pubWrongRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, "rg04-pub-wrong", map[string]any{
		"publication_manifest_digest": wrongDigest,
	}, nil)
	if code != http.StatusConflict || !strings.Contains(string(pubWrongRaw), "STALE_MANIFEST_DIGEST") {
		t.Fatalf("publish with altered digest expected 409 STALE_MANIFEST_DIGEST, got %d: %s", code, string(pubWrongRaw))
	}
}
