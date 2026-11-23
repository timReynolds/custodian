package e2e_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

// Scenario 1: Clean human-owned feature PR end-to-end happy path (RG-01, RG-02, RG-03, RG-07, RG-08, RG-09).
func TestT4_S01_CleanHumanOwnedFeaturePR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "payments", map[string]string{
		"README.md": string(m4LoadFixture(t, "golden/clean_tree/README.md")),
	}, "INTERNAL", []string{m4DefaultRoute}, true, 5)

	// 1. Human creates workspace (no git metadata, no history).
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository:    harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		SourceOptions: &harness.WorkspaceSourceOptions{IncludeGitMetadata: false, IncludeHistory: false},
	})
	wsID := m4WorkspaceID(ws)
	if ws.BaseCommit != repo.seeded.HeadSHA {
		t.Fatalf("workspace base_commit %q != seeded HEAD %q", ws.BaseCommit, repo.seeded.HeadSHA)
	}

	// 2. Controller downloads ingress archive, asserts credentialless, adds pkg/hello/hello.go.
	srcArchive, dlRaw, err := actors.ctrlCli.DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	dlRaw.RequireStatus(t, http.StatusOK)
	env.Snapshots().AssertArchiveNoSecretLeak(t, srcArchive, env.GitHub().ReadAppPrivateKeyPEM(), env.GitHub().WriteAppPrivateKeyPEM(), "ghs_")

	entries, err := harness.ExtractTarGz(srcArchive)
	if err != nil {
		t.Fatalf("ExtractTarGz(ingress): %v", err)
	}
	entries = append(entries, harness.TarEntry{
		Name: "pkg/hello/hello.go",
		Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go"),
	})
	egressGZ, egressSHA := harness.MustBuildTarGz(t, entries)

	// 3. Upload snapshot & submit proposal -> wait for RECONSTRUCTED -> verify diff.
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, egressGZ, egressSHA, ws.Generation,
		"Add deterministic greeting package",
		&harness.Provenance{Type: "human_authored", CaptureMethod: "frozen_filesystem"})
	propID := m4PropID(prop)

	diffResp, diffRaw, err := actors.humanCli.GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	if len(diffResp.Paths) != 1 || diffResp.Paths[0].Path != "pkg/hello/hello.go" || diffResp.Paths[0].ChangeType != "ADDED" {
		t.Fatalf("unexpected diff paths: %+v", diffResp.Paths)
	}

	// 4. Evaluate Stages A/B/C -> verify clean scan_runs, COMPLETE/CLEAR assessment, ALLOW decision.
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	findingsResp, fRaw, err := actors.humanCli.ListProposalFindings(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)
	if len(findingsResp.ScanRuns) == 0 {
		t.Fatalf("expected >= 1 scan_run")
	}
	for _, sr := range findingsResp.ScanRuns {
		if !sr.Complete || sr.FilesSkipped != 0 {
			t.Fatalf("expected complete scan run with 0 skipped files, got %+v", sr)
		}
	}
	if len(assess.Assessments) == 0 || assess.Assessments[len(assess.Assessments)-1].Status != "COMPLETE" ||
		assess.Assessments[len(assess.Assessments)-1].Disposition != "CLEAR" {
		t.Fatalf("expected COMPLETE/CLEAR model assessment, got %+v", assess.Assessments)
	}
	if len(assess.PolicyDecisions) == 0 || assess.PolicyDecisions[len(assess.PolicyDecisions)-1].Effect != "ALLOW" {
		t.Fatalf("expected ALLOW policy decision, got %+v", assess.PolicyDecisions)
	}

	// 5 & 6. Human reviewer approves bound to exact manifest digest -> controller publishes -> 1 PR & trailers.
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, pub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")

	harness.AssertUUIDv7Monotonic(t, []string{wsID, propID, m4LatestDecisionID(evalProp, assess), m4PubID(pub)})
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "proposal", "publish")
	m4AssertNoLeaksAllSurfaces(t, env, srcArchive, actors.humanTok, actors.reviewerTok, actors.ctrlTok)
}

// Scenario 2: Agent-assisted patch with reviewer group obligation and separation of duties (RG-02, RG-03, RG-09).
func TestT4_S02_AgentAssistedPatchReviewerGroupSoD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "infra", nil, "INTERNAL", []string{m4DefaultRoute}, true, 5)
	env.Gateway().SetMode(harness.GatewayModeHighRiskReview)

	// 1. Create agent-attributed workspace owned by verified human.
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent: &harness.WorkspaceAgentInfo{
			Type:       "claude-code",
			SessionID:  "sess-s02",
			ModelRoute: m4DefaultRoute,
		},
	})
	wsID := m4WorkspaceID(ws)

	// 2. Upload snapshot modifying infra/prod/network.tf.
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "infra/prod/network.tf", Body: []byte("resource \"google_compute_network\" \"prod\" { name = \"prod\" }\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation,
		"Provision prod VPC network",
		&harness.Provenance{Type: "agent_assisted", CaptureMethod: "frozen_filesystem"})
	propID := m4PropID(prop)
	if prop.Origin == nil || prop.Origin.AgentSessionID != "sess-s02" {
		t.Fatalf("expected proposal origin agent_session_id=sess-s02, got %+v", prop.Origin)
	}
	if prop.Provenance == nil || prop.Provenance.Type != "agent_assisted" {
		t.Fatalf("expected provenance.type=agent_assisted, got %+v", prop.Provenance)
	}

	// 3. Evaluate -> REQUIRE_APPROVAL with reviewer group obligation(s).
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	if len(assess.PolicyDecisions) == 0 {
		t.Fatalf("expected persisted policy decisions")
	}
	latestPD := assess.PolicyDecisions[len(assess.PolicyDecisions)-1]
	if latestPD.Effect != "REQUIRE_APPROVAL" || len(latestPD.Obligations) == 0 {
		t.Fatalf("expected REQUIRE_APPROVAL with obligations, got %+v", latestPD)
	}
	evalID := m4LatestDecisionID(evalProp, assess)

	// 4. Negative SoD & group checks: agent rejected (403) and workspace owner lacking group rejected (403).
	_, agentAppRaw, err := actors.agentCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("agent ApproveProposal: %v", err)
	}
	agentAppRaw.RequireStatus(t, http.StatusForbidden)

	_, ownerAppRaw, err := actors.humanCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("owner human ApproveProposal: %v", err)
	}
	ownerAppRaw.RequireStatus(t, http.StatusForbidden)

	// 5 & 6. Authorized reviewer (member of ip-review + platform-owners) approves -> publishes -> Agent-Assisted: true.
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, pub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "true")
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "proposal", "approv", "publish")
}

// Scenario 3: Secret leak + prompt injection blocked across Stages A, B, and C (ADV-06, ADV-08, RG-05).
func TestT4_S03_SecretLeakAndPromptInjectionBlocked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	synthToken := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	env, repo, actors := m4SetupRepoEnv(t, "acme", "sec-inj", nil, "INTERNAL", []string{m4DefaultRoute}, true, 5)
	env.RegisterSecret(synthToken)
	env.RegisterSecret(awsKey)

	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})

	t.Cleanup(func() { env.Scanners().ResetAll() })
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: synthToken,
		FilePath:    ".env",
		RuleID:      "generic-api-key",
	})
	// Worst-case Stage B output: prompt injection attempts to coerce model into returning CLEAR.
	env.Gateway().SetMode(harness.GatewayModeClean)
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "prompt_injection_source.go", Body: m4LoadFixture(t, "payloads/prompt_injection_source.go")},
		{Name: ".env", Body: m4LoadFixture(t, "payloads/synthetic_aws_secret.env")},
		{Name: "infra/prod/config.env", Body: []byte("ENV=prod\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation,
		"prompt injection and secret payload", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	if len(env.Gateway().Requests()) == 0 {
		t.Fatalf("expected Stage B gateway to be invoked for high-risk change, got 0 requests")
	}
	env.Gateway().AssertPromptUntrustedFraming(t, "Ignore all previous instructions", true)

	findingsResp, fRaw, err := actors.humanCli.ListProposalFindings(ctx, propID)
	if err != nil {
		t.Fatalf("ListProposalFindings: %v", err)
	}
	fRaw.RequireStatus(t, http.StatusOK)
	if len(findingsResp.Findings) == 0 {
		t.Fatalf("expected Stage A secret finding")
	}
	for _, f := range findingsResp.Findings {
		if !f.Redacted {
			t.Fatalf("finding %s must be redacted", f.ID)
		}
	}
	harness.AssertNoSecretOrEncodedLeak(t, string(fRaw.Body), synthToken, awsKey)

	// Stage C CEL must DENY even though Stage B returned CLEAR.
	if len(assess.PolicyDecisions) == 0 || assess.PolicyDecisions[len(assess.PolicyDecisions)-1].Effect != "DENY" {
		t.Fatalf("expected Stage C DENY overriding CLEAR model output, got %+v", assess.PolicyDecisions)
	}
	if evalProp.Status != "DENIED" {
		t.Fatalf("expected proposal status DENIED, got %q", evalProp.Status)
	}

	// Neither approval nor publish can proceed on a DENIED proposal.
	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        m4LatestDecisionID(evalProp, assess),
	})
	if err != nil {
		t.Fatalf("ApproveProposal(denied): %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden, http.StatusUnprocessableEntity)

	_, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(denied): %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs on blocked secret/injection proposal")
	}

	events := m4AssertAuditChain(t, ctx, actors.auditorCli, propID)
	evJSON, _ := json.Marshal(events)
	harness.AssertNoSecretOrEncodedLeak(t, string(evJSON), synthToken, awsKey)
	m4AssertNoLeaksAllSurfaces(t, env, nil, synthToken, awsKey)
}

// Scenario 4: Restricted repo + unauthorized route check + INDETERMINATE quarantine and recovery (RG-05).
func TestT4_S04_RestrictedClassificationIndeterminateQuarantineAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	restrictedRoute := "restricted-ip-review"
	unauthRoute := "public-fast"
	env, repo, actors := m4SetupRepoEnv(t, "acme", "core-ip", nil, "RESTRICTED", []string{restrictedRoute}, true, 5)

	// 1. Unauthorized route rejected at workspace creation (403/422) and gateway never invoked for it.
	_, badRouteRaw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent:      &harness.WorkspaceAgentInfo{Type: "codex", SessionID: "s4-bad", ModelRoute: unauthRoute},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(unauth route): %v", err)
	}
	badRouteRaw.RequireAnyStatus(t, http.StatusForbidden, http.StatusUnprocessableEntity)
	env.Gateway().AssertNoRouteCalled(t, unauthRoute)

	// 2. Authorized route configured to return INDETERMINATE on first evaluation.
	env.Gateway().SetRouteProgram(restrictedRoute, harness.GatewayProgram{Mode: harness.GatewayModeIndeterminate})
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
		Agent:      &harness.WorkspaceAgentInfo{Type: "codex", SessionID: "s4-ok", ModelRoute: restrictedRoute},
	})
	wsID := m4WorkspaceID(ws)

	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "core/engine.go", Body: []byte("package core\nfunc Run() int { return 1 }\n")},
	})
	pQuar := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation, "restricted quarantine", nil)
	pQuarID := m4PropID(pQuar)
	pQuarEval, qAssess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, pQuarID, pQuar.Version)

	if len(qAssess.Assessments) == 0 ||
		(qAssess.Assessments[len(qAssess.Assessments)-1].Status != "INDETERMINATE" &&
			qAssess.Assessments[len(qAssess.Assessments)-1].Disposition != "INDETERMINATE") {
		t.Fatalf("expected INDETERMINATE model assessment, got %+v", qAssess.Assessments)
	}
	if len(qAssess.PolicyDecisions) == 0 || qAssess.PolicyDecisions[len(qAssess.PolicyDecisions)-1].Effect != "QUARANTINE" {
		t.Fatalf("expected QUARANTINE policy decision, got %+v", qAssess.PolicyDecisions)
	}
	if pQuarEval.Status != "QUARANTINED" {
		t.Fatalf("expected proposal status QUARANTINED, got %q", pQuarEval.Status)
	}

	// Quarantined proposal cannot be published (0 PRs).
	_, qPubRaw, err := actors.ctrlCli.PublishProposal(ctx, pQuarID, harness.PublishReq{
		PublicationManifestDigest: pQuarEval.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(quarantined): %v", err)
	}
	qPubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs while quarantined")
	}

	// 3. Recovery: restore clean response on restricted route, re-evaluate or submit fresh proposal, approve & publish.
	env.Gateway().SetRouteProgram(restrictedRoute, harness.GatewayProgram{Mode: harness.GatewayModeClean})
	env.Gateway().SetMode(harness.GatewayModeClean)

	pRec := pQuarEval
	var recAssess harness.AssessmentsResp
	reEvalResp, reRaw, err := actors.ctrlCli.EvaluateProposal(ctx, pQuarID, harness.EvaluateReq{ExpectedVersion: pQuarEval.Version})
	if err == nil && (reRaw.StatusCode == http.StatusAccepted || reRaw.StatusCode == http.StatusOK) {
		if reEvalResp.OperationID != "" {
			op, wErr := actors.ctrlCli.WaitForOperation(ctx, reEvalResp.OperationID, 30*time.Second)
			if wErr != nil {
				t.Fatalf("WaitForOperation(recovery eval): %v", wErr)
			}
			m4RequireOpSucceeded(t, env, op)
		}
		gotP, pRaw, pErr := actors.ctrlCli.GetProposal(ctx, pQuarID)
		if pErr != nil {
			t.Fatalf("GetProposal(recovery %s): %v", pQuarID, pErr)
		}
		pRaw.RequireStatus(t, http.StatusOK)
		gotA, aRaw, aErr := actors.ctrlCli.ListProposalAssessments(ctx, pQuarID)
		if aErr != nil {
			t.Fatalf("ListProposalAssessments(recovery %s): %v", pQuarID, aErr)
		}
		aRaw.RequireStatus(t, http.StatusOK)
		pRec, recAssess = gotP, gotA
	} else {
		// If state machine treats QUARANTINED as terminal, submit clean retry proposal on the same workspace.
		pRetry := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation, "restricted recovery", nil)
		pRec, recAssess = m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(pRetry), pRetry.Version)
	}

	if len(recAssess.PolicyDecisions) == 0 || recAssess.PolicyDecisions[len(recAssess.PolicyDecisions)-1].Effect == "QUARANTINE" {
		t.Fatalf("expected recovered proposal out of QUARANTINE, got %+v", recAssess.PolicyDecisions)
	}
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, pRec, recAssess)
	if pub.Status != "PUBLISHED" || env.GitHub().PRCount(repo.seeded.FullName) != 1 {
		t.Fatalf("expected PUBLISHED with 1 PR after recovery, got status=%q count=%d", pub.Status, env.GitHub().PRCount(repo.seeded.FullName))
	}
	env.Gateway().AssertNoRouteCalled(t, unauthRoute)
	m4AssertAuditChain(t, ctx, actors.auditorCli, m4PropID(pRec), "proposal", "publish")
}

// Scenario 5: Organization mandatory DENY vs permissive repository override attempt (RG-06, ADV-09).
func TestT4_S05_OrgMandatoryDenyVsPermissiveRepoOverride(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	orgYAML := string(m4LoadFixture(t, "policies/org_mandatory_deny.yaml"))
	repoYAML := string(m4LoadFixture(t, "policies/repo_permissive_override_attempt.yaml"))
	policyDir := m4WritePolicyDir(t, map[string]string{
		"00-org-mandatory.yaml": orgYAML,
	})

	env, repo, actors := m4SetupRepoEnv(t, "acme", "override-test", nil, "INTERNAL", []string{m4DefaultRoute}, true, 5,
		harness.WithPolicyBundleDir(policyDir))
	m4SeedPolicyBundleDB(t, env, "org-mandatory-baseline", "1.0.0", "ORG", "", orgYAML)
	m4SeedPolicyBundleDB(t, env, "repo-permissive-override", "1.0.0", "REPO", repo.dbRepoID, repoYAML)

	// 1. CLI + /v1/policies/evaluate verify org-before-repo composition blocks permissive override.
	orgPath := filepath.Join(policyDir, "00-org-mandatory.yaml")
	cliCfg := env.Contracts().CLI
	valArgs := append([]string{}, cliCfg.PolicyValidateSubcommand...)
	valArgs = append(valArgs, cliCfg.PolicyBundleFlag, orgPath)
	if res := env.RunCLI(env.Contracts().Binaries.Policy, valArgs, nil); res.ExitCode != 0 {
		t.Fatalf("custodian-policy validate org bundle failed: exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}

	simResp, simRaw, err := actors.policyAdminCli.EvaluatePolicy(ctx, harness.PolicyEvaluateReq{
		OrgBundleYAML: orgYAML,
		BundleYAML:    repoYAML,
		Stage:         "EGRESS",
		Input: map[string]any{
			"findings":   map[string]any{"critical_secrets": 1, "prohibited_licenses": 0, "scan_complete": true},
			"assessment": map[string]any{"ip_risk": "LOW", "status": "COMPLETE"},
			"change":     map[string]any{"paths": []string{".env"}},
		},
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy(org vs repo): %v", err)
	}
	simRaw.RequireStatus(t, http.StatusOK)
	if simResp.Effect != "DENY" {
		t.Fatalf("expected ORG DENY over permissive repo override, got %q", simResp.Effect)
	}
	foundOrgRule := false
	for _, id := range simResp.MatchedRuleIDs {
		if id == "org.secrets.block" {
			foundOrgRule = true
		}
	}
	if !foundOrgRule {
		t.Fatalf("expected org.secrets.block in matched_rule_ids, got %v", simResp.MatchedRuleIDs)
	}

	// 2. Live proposal evaluation with secret finding must DENY and reject publish.
	secretVal := "custodian_e2e_dummy_secret_value_0123456789abcdef"
	env.RegisterSecret(secretVal)

	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: secretVal,
		FilePath:    ".env",
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: ".env", Body: m4LoadFixture(t, "payloads/synthetic_aws_secret.env")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws), gz, shaHex, ws.Generation, "org deny override test", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)

	if len(assess.PolicyDecisions) == 0 {
		t.Fatalf("expected live PolicyDecision, got 0")
	}
	latestPD := assess.PolicyDecisions[len(assess.PolicyDecisions)-1]
	if latestPD.Effect != "DENY" {
		t.Fatalf("expected live PolicyDecision DENY, got %+v", latestPD)
	}
	foundLiveOrgReason := false
	for _, r := range latestPD.Reasons {
		if r.RuleID == "org.secrets.block" {
			foundLiveOrgReason = true
			break
		}
	}
	if !foundLiveOrgReason {
		t.Fatalf("expected org.secrets.block in persisted PolicyDecision.Reasons, got %+v", latestPD.Reasons)
	}
	rows, qErr := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COUNT(*) FROM policy_decisions WHERE proposal_id = %s::uuid AND org_bundle_id IS NOT NULL AND repo_bundle_id IS NOT NULL;",
		m3SQLQuote(propID),
	))
	if qErr != nil {
		t.Fatalf("query policy_decisions org/repo bundle ids: %v", qErr)
	}
	if len(rows) == 0 || len(rows[0]) == 0 || rows[0][0] == "0" {
		t.Fatalf("expected policy_decisions row for %s with both org_bundle_id and repo_bundle_id non-null, got %v", propID, rows)
	}
	if evalProp.Status != "DENIED" {
		t.Fatalf("expected DENIED status, got %q", evalProp.Status)
	}

	_, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(denied): %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)
	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs on org-denied proposal")
	}
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID)
}

// Scenario 6: Modified snapshot after approval revokes/blocks stale manifest digest (RG-04, ADV-10).
func TestT4_S06_ModifiedSnapshotAfterApprovalStaleDigestRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "stale-digest", nil, "INTERNAL", []string{m4DefaultRoute}, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	wsID := m4WorkspaceID(ws)

	// 1. Submit, evaluate, and approve P1 (v1).
	gz1, sha1 := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "main.go", Body: []byte("package main\nfunc Version() int { return 1 }\n")},
	})
	p1 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz1, sha1, ws.Generation, "v1 change", nil)
	p1ID := m4PropID(p1)
	p1Eval, p1Assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, p1ID, p1.Version)
	d1 := m4LatestDecisionID(p1Eval, p1Assess)
	_, app1Raw, err := actors.reviewerCli.ApproveProposal(ctx, p1ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
		PolicyEvaluationID:        d1,
	})
	if err != nil {
		t.Fatalf("ApproveProposal(p1): %v", err)
	}
	app1Raw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// 2. Upload modified snapshot v2 -> P2 with distinct manifest digest.
	gz2, sha2 := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "main.go", Body: []byte("package main\nfunc Version() int { return 2 }\n")},
	})
	p2 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz2, sha2, ws.Generation, "v2 modified", nil)
	p2ID := m4PropID(p2)
	p2Eval, p2Assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, p2ID, p2.Version)
	d2 := m4LatestDecisionID(p2Eval, p2Assess)
	if p2Eval.PublicationManifestDigest == p1Eval.PublicationManifestDigest {
		t.Fatalf("v2 manifest digest must differ from v1")
	}

	// 3. Stale v1 digest cannot approve or publish P2.
	_, staleAppRaw, err := actors.reviewerCli.ApproveProposal(ctx, p2ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
		PolicyEvaluationID:        d2,
	})
	if err != nil {
		t.Fatalf("ApproveProposal(stale v1 digest on p2): %v", err)
	}
	staleAppRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	_, stalePubRaw, err := actors.ctrlCli.PublishProposal(ctx, p2ID, harness.PublishReq{
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(stale v1 digest on p2): %v", err)
	}
	stalePubRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden, http.StatusUnprocessableEntity)
	if env.GitHub().PRCount(repo.seeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs before valid v2 approval")
	}

	// 4. Approve P2 with exact v2 digest -> publish -> verify Git tree matches v2 content only.
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, p2Eval, p2Assess)
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, p2Eval, pub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")

	tree, err := env.Git().InspectTree(repo.seeded.FullName, "custodian/"+p2ID)
	if err != nil {
		t.Fatalf("InspectTree: %v", err)
	}
	if !strings.Contains(tree["main.go"], "return 2") {
		t.Fatalf("expected published main.go to contain v2 content, got %q", tree["main.go"])
	}
	m4AssertAuditChain(t, ctx, actors.auditorCli, p2ID, "proposal", "publish")
}

// Scenario 7: Adversarial sandbox archives rejected (422) followed by clean retry with malicious .git ignored (ADV-01..05).
func TestT4_S07_AdversarialSandboxArchiveAndCleanRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "adv-sandbox", nil, "INTERNAL", []string{m4DefaultRoute}, true, 5)
	ws := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	wsID := m4WorkspaceID(ws)

	symGZ, symSHA := harness.BuildSymlinkArchive("evil-link", "/etc/passwd")
	uniGZ, uniSHA := harness.BuildUnicodeCollisionArchive()
	caseGZ, caseSHA := harness.BuildCaseCollisionArchive()
	travGZ, travSHA := harness.BuildPathTraversalArchive(harness.TraversalDotDot)
	hardGZ, hardSHA := harness.BuildHardlinkArchive("hard.txt", "README.md")
	fifoGZ, fifoSHA := harness.BuildSpecialFileArchive(tar.TypeFifo, "evil.fifo")
	subGZ, subSHA := harness.BuildSubmoduleArchive()
	corruptGZ := harness.BuildCorruptTarGz(harness.CorruptTarChecksum)

	adversarialCases := []struct {
		name string
		gz   []byte
		sha  string
	}{
		{"symlink", symGZ, symSHA},
		{"unicode-collision", uniGZ, uniSHA},
		{"case-collision", caseGZ, caseSHA},
		{"traversal", travGZ, travSHA},
		{"hardlink", hardGZ, hardSHA},
		{"special-fifo", fifoGZ, fifoSHA},
		{"submodule", subGZ, subSHA},
		{"corrupt-checksum", corruptGZ, harness.SHA256Hex(corruptGZ)},
	}

	for _, tc := range adversarialCases {
		capResp, capRaw, err := actors.ctrlCli.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{
			Generation: ws.Generation,
			MaxBytes:   int64(len(tc.gz)) + 65536,
		})
		if err != nil {
			t.Fatalf("RequestUploadCapability(%s): %v", tc.name, err)
		}
		capRaw.RequireStatus(t, http.StatusOK)
		upRaw, err := actors.ctrlCli.UploadSnapshot(ctx, capResp.UploadURL, m4FirstNonEmpty(capResp.Token, capResp.CapabilityToken), tc.gz)
		if err != nil {
			t.Fatalf("UploadSnapshot(%s): %v", tc.name, err)
		}
		if upRaw.StatusCode >= 400 {
			upRaw.RequireAnyStatus(t, http.StatusUnprocessableEntity, http.StatusBadRequest)
			continue
		}
		var upParsed m4UploadResp
		if len(upRaw.Body) > 0 {
			_ = json.Unmarshal(upRaw.Body, &upParsed)
		}
		artID := m4FirstNonEmpty(upParsed.ArtifactID, upParsed.ID, upRaw.Headers.Get("X-Artifact-ID"))
		if artID == "" {
			t.Fatalf("UploadSnapshot(%s) returned %d without artifact_id, id, or X-Artifact-ID", tc.name, upRaw.StatusCode)
		}

		sub, subRaw, err := actors.ctrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
			Snapshot: harness.SnapshotSubmitRef{
				ArtifactID:          artID,
				SHA256:              tc.sha,
				WorkspaceGeneration: ws.Generation,
				SizeBytes:           int64(len(tc.gz)),
			},
			Title: "adv-" + tc.name,
		})
		if err != nil {
			t.Fatalf("SubmitProposal(%s): %v", tc.name, err)
		}
		if subRaw.StatusCode == http.StatusAccepted || subRaw.StatusCode == http.StatusCreated {
			propID := m4PropID(sub)
			if propID == "" {
				t.Fatalf("SubmitProposal(%s) returned %d without proposal id: %+v", tc.name, subRaw.StatusCode, sub)
			}
			if sub.OperationID != "" {
				op, wErr := actors.ctrlCli.WaitForOperation(ctx, sub.OperationID, 20*time.Second)
				if wErr != nil {
					t.Fatalf("WaitForOperation(%s): %v", tc.name, wErr)
				}
				if op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
					t.Fatalf("adversarial %s must fail, got op status=%q", tc.name, op.Status)
				}
			}
			gotProp, gRaw, gErr := actors.ctrlCli.GetProposal(ctx, propID)
			if gErr != nil {
				t.Fatalf("GetProposal(%s %s): %v", tc.name, propID, gErr)
			}
			gRaw.RequireStatus(t, http.StatusOK)
			if gotProp.Status == "RECONSTRUCTED" || gotProp.CanonicalArtifactID != "" {
				t.Fatalf("adversarial %s proposal %s must never reach RECONSTRUCTED or have CanonicalArtifactID, got status=%q canonical=%q",
					tc.name, propID, gotProp.Status, gotProp.CanonicalArtifactID)
			}
		} else {
			subRaw.RequireAnyStatus(t, http.StatusUnprocessableEntity, http.StatusBadRequest)
		}
	}

	// 2 & 3. Retry with clean app.go + malicious sandbox .git/* -> .git ignored during reconstruction and publish succeeds.
	gitInjGZ, gitInjSHA := harness.BuildGitInjectionArchive([]harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "app.go", Body: []byte("package app\nfunc Ok() bool { return true }\n")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gitInjGZ, gitInjSHA, ws.Generation, "clean retry after adv", nil)
	propID := m4PropID(prop)

	diffResp, diffRaw, err := actors.humanCli.GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusOK)
	if len(diffResp.Paths) != 1 || diffResp.Paths[0].Path != "app.go" {
		t.Fatalf("expected ONLY app.go in canonical diff (sandbox .git ignored), got %+v", diffResp.Paths)
	}

	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	pub := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, evalProp, assess)
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, pub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")

	tree, err := env.Git().InspectTree(repo.seeded.FullName, "custodian/"+propID)
	if err != nil {
		t.Fatalf("InspectTree: %v", err)
	}
	for p := range tree {
		if strings.HasPrefix(p, ".git") {
			t.Fatalf("malicious sandbox .git path %q must never be published", p)
		}
	}
	if _, ok := tree["app.go"]; !ok {
		t.Fatalf("published branch missing app.go")
	}
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "proposal", "publish")
}

// Scenario 8: Worker SIGKILL crash mid-operation & transient GitHub/SnapshotStore outage recovery (RG-10, RG-08).
func TestT4_S08_WorkerCrashAndOutageRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "crash-recover", nil, "INTERNAL", []string{m4DefaultRoute}, true, 5)

	// 1. Create workspace and SIGKILL worker mid-lease; restart worker and verify recovery to READY.
	created, cRaw, err := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	cRaw.RequireStatus(t, http.StatusAccepted)
	wsID := m4WorkspaceCreateID(created)

	if err := env.KillWorker(); err != nil {
		t.Fatalf("KillWorker: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}

	if created.OperationID != "" {
		op, wErr := actors.humanCli.WaitForOperation(ctx, created.OperationID, 45*time.Second)
		if wErr != nil {
			t.Fatalf("WaitForOperation(ingress after SIGKILL): %v", wErr)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var ws harness.WorkspaceResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := actors.humanCli.GetWorkspace(ctx, wsID)
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		ws = got
		return got.Status == "READY", nil
	})

	// 2. Upload, evaluate, and approve proposal.
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	prop := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsID, gz, shaHex, ws.Generation, "crash recovery pr", nil)
	propID := m4PropID(prop)
	evalProp, assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, propID, prop.Version)
	evalID := m4LatestDecisionID(evalProp, assess)
	_, appRaw, err := actors.reviewerCli.ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
		PolicyEvaluationID:        evalID,
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	// 3. Inject transient GitHub 503 + SnapshotStore outage + publisher SIGKILL, then restore and verify single-PR recovery.
	env.GitHub().SetOutage("POST", "/git/refs", http.StatusServiceUnavailable, 1)
	env.GitHub().SetOutage("POST", "/pulls", http.StatusServiceUnavailable, 1)
	if err := env.Snapshots().SimulateOutage(true); err != nil {
		t.Fatalf("SimulateOutage(true): %v", err)
	}
	defer func() { _ = env.Snapshots().SimulateOutage(false) }()

	pub, pubRaw, err := actors.ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: evalProp.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	time.Sleep(150 * time.Millisecond)
	if err := env.KillPublisher(); err != nil {
		t.Fatalf("KillPublisher: %v", err)
	}
	env.GitHub().ClearOutages()
	if err := env.Snapshots().SimulateOutage(false); err != nil {
		t.Fatalf("SimulateOutage(false): %v", err)
	}
	if err := env.RestartPublisher(); err != nil {
		t.Fatalf("RestartPublisher: %v", err)
	}

	if pub.OperationID != "" {
		op, wErr := actors.ctrlCli.WaitForOperation(ctx, pub.OperationID, 45*time.Second)
		if wErr != nil {
			t.Fatalf("WaitForOperation(publish after outages): %v", wErr)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	var finalPub harness.PublicationResp
	m4WaitUntil(ctx, t, 30*time.Second, func() (bool, error) {
		got, gRaw, gErr := actors.ctrlCli.GetPublication(ctx, m4PubID(pub))
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		finalPub = got
		return got.Status == "PUBLISHED", nil
	})
	m4AssertPublishedGitAndPR(t, env, repo.seeded.FullName, evalProp, finalPub, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")
	m4AssertAuditChain(t, ctx, actors.auditorCli, propID, "proposal", "publish")
}

// Scenario 9: Concurrent publish race, idempotency payload mismatch, and upstream force-push abort (RG-07, RG-08, ADV-11, ADV-12).
func TestT4_S09_ConcurrentPublishRaceForcePushAndIdempotency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	env, repo, actors := m4SetupRepoEnv(t, "acme", "race-primary", nil, "INTERNAL", []string{m4DefaultRoute}, true, 10)
	fpSeeded, err := env.Git().InitSeededRepo("acme", "forcepush", map[string]string{"README.md": "fp base\n"},
		harness.WithDefaultBranch("main"), harness.WithRepoID(10009), harness.WithInstallationID(20009))
	if err != nil {
		t.Fatalf("seed forcepush repo: %v", err)
	}
	m4SeedRepoDB(t, env, fpSeeded, "INTERNAL", []string{m4DefaultRoute}, true, 10)

	// Part A: Concurrent publish race with shared and distinct Idempotency-Keys -> exactly 1 PR & 1 branch.
	ws1 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.seeded.GitHubRepoID, Ref: "main"},
	})
	gz, shaHex := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	p1 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws1), gz, shaHex, ws1.Generation, "concurrent race", nil)
	p1ID := m4PropID(p1)
	p1Eval, p1Assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, p1ID, p1.Version)
	_, app1Raw, err := actors.reviewerCli.ApproveProposal(ctx, p1ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: p1Eval.PublicationManifestDigest,
		PolicyEvaluationID:        m4LatestDecisionID(p1Eval, p1Assess),
	})
	if err != nil {
		t.Fatalf("ApproveProposal(p1): %v", err)
	}
	app1Raw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	type raceResult struct {
		pub harness.PublicationResp
		raw *harness.RawResponse
		err error
	}
	const workers = 6
	results := make([]raceResult, workers)
	startCh := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "s9-race-same"
			if idx >= 3 {
				key = fmt.Sprintf("s9-race-distinct-%d", idx)
			}
			<-startCh
			pub, raw, pErr := actors.ctrlCli.PublishProposal(ctx, p1ID, harness.PublishReq{
				PublicationManifestDigest: p1Eval.PublicationManifestDigest,
			}, harness.WithIdempotencyKey(key))
			results[idx] = raceResult{pub: pub, raw: raw, err: pErr}
		}(i)
	}
	close(startCh)
	wg.Wait()

	var acceptedPubID string
	for i, res := range results {
		if res.err != nil {
			t.Fatalf("goroutine %d transport error: %v", i, res.err)
		}
		if res.raw.StatusCode == http.StatusAccepted || res.raw.StatusCode == http.StatusOK {
			id := m4PubID(res.pub)
			if acceptedPubID == "" {
				acceptedPubID = id
			} else if id != "" && id != acceptedPubID {
				t.Fatalf("concurrent publish created distinct publication IDs: %q vs %q", acceptedPubID, id)
			}
		} else {
			res.raw.RequireAnyStatus(t, http.StatusConflict, http.StatusTooManyRequests)
		}
	}
	if acceptedPubID == "" {
		t.Fatalf("expected at least one concurrent publish call to succeed")
	}

	// Reusing "s9-race-same" with altered digest must return 409.
	_, mismatchRaw, err := actors.ctrlCli.PublishProposal(ctx, p1ID, harness.PublishReq{
		PublicationManifestDigest: strings.Repeat("b", 64),
	}, harness.WithIdempotencyKey("s9-race-same"))
	if err != nil {
		t.Fatalf("PublishProposal(mismatch): %v", err)
	}
	mismatchRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	m4WaitUntil(ctx, t, 30*time.Second, func() (bool, error) {
		got, gRaw, gErr := actors.ctrlCli.GetPublication(ctx, acceptedPubID)
		if gErr != nil {
			return false, gErr
		}
		if gRaw.StatusCode != http.StatusOK {
			return false, nil
		}
		return got.Status == "PUBLISHED", nil
	})
	if env.GitHub().PRCount(repo.seeded.FullName) != 1 {
		t.Fatalf("expected exactly 1 PR on concurrent publish race, got %d", env.GitHub().PRCount(repo.seeded.FullName))
	}
	branches, err := env.Git().ListBranches(repo.seeded.FullName)
	if err != nil {
		t.Fatalf("ListBranches: %v", err)
	}
	if len(branches) != 2 {
		t.Fatalf("expected exactly 2 branches (main + custodian/%s), got %v", p1ID, branches)
	}

	// Part B: Upstream force-push replaces baseA with orphan baseB -> publish aborts safely with 0 PRs.
	ws2 := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: fpSeeded.GitHubRepoID, Ref: "main"},
	})
	p2 := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(ws2), gz, shaHex, ws2.Generation, "forcepush abort", nil)
	p2ID := m4PropID(p2)
	p2Eval, p2Assess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, p2ID, p2.Version)
	_, app2Raw, err := actors.reviewerCli.ApproveProposal(ctx, p2ID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: p2Eval.PublicationManifestDigest,
		PolicyEvaluationID:        m4LatestDecisionID(p2Eval, p2Assess),
	})
	if err != nil {
		t.Fatalf("ApproveProposal(p2): %v", err)
	}
	app2Raw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)

	if _, err := env.Git().ForcePushBranch(fpSeeded.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"README.md": "orphan rewrite\n"},
		Message: "orphan force push",
	}); err != nil {
		t.Fatalf("ForcePushBranch: %v", err)
	}

	fpPub, fpRaw, err := actors.ctrlCli.PublishProposal(ctx, p2ID, harness.PublishReq{
		PublicationManifestDigest: p2Eval.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(p2): %v", err)
	}
	if fpRaw.StatusCode == http.StatusAccepted || fpRaw.StatusCode == http.StatusOK {
		if fpPub.OperationID != "" {
			op, wErr := actors.ctrlCli.WaitForOperation(ctx, fpPub.OperationID, 20*time.Second)
			if wErr != nil {
				t.Fatalf("WaitForOperation(p2): %v", wErr)
			}
			if op.Status != "FAILED" && !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
				t.Fatalf("expected failed publish operation after force-push, got %q", op.Status)
			}
		}
	} else {
		fpRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)
	}
	if env.GitHub().PRCount(fpSeeded.FullName) != 0 {
		t.Fatalf("expected 0 PRs on forcepush repo, got %d", env.GitHub().PRCount(fpSeeded.FullName))
	}
	m4AssertAuditChain(t, ctx, actors.auditorCli, p1ID, "publish")
}

// Scenario 10: Multi-repo burst rate limiting (429), retention reaper, /metrics, and full audit hash chain.
func TestT4_S10_MultiRepoBurstRateLimitRetentionAndAuditChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	canary := "custodian_s10_canary_secret_abcdef0123456789"
	env, repoA, actors := m4SetupRepoEnv(t, "acme", "repo-alpha", nil, "INTERNAL", []string{m4DefaultRoute}, true, 2,
		harness.WithPerRepoConcurrency(2),
		harness.WithGlobalScanBudget(4),
		harness.WithGlobalModelBudget(4),
		harness.WithRetentionTTL(5*time.Minute),
		harness.WithEnvOverrides(map[string]string{
			"CUSTODIAN_RETENTION_INTERVAL": "200ms",
		}),
	)
	env.RegisterSecret(canary)

	repoBSeeded, err := env.Git().InitSeededRepo("acme", "repo-beta", map[string]string{"README.md": "beta\n"},
		harness.WithDefaultBranch("main"), harness.WithRepoID(10010), harness.WithInstallationID(20010))
	if err != nil {
		t.Fatalf("seed repo-beta: %v", err)
	}
	m4SeedRepoDB(t, env, repoBSeeded, "INTERNAL", []string{m4DefaultRoute}, true, 2)

	// 1 & 2. Pause worker and burst 5 concurrent CreateWorkspace requests on repoA (max_concurrent=2).
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}

	const burst = 5
	type wsAttempt struct {
		resp harness.WorkspaceCreateResp
		raw  *harness.RawResponse
		err  error
	}
	attempts := make([]wsAttempt, burst)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-gate
			c, r, cErr := actors.humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
				Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repoA.seeded.GitHubRepoID, Ref: "main"},
			})
			attempts[idx] = wsAttempt{resp: c, raw: r, err: cErr}
		}(i)
	}
	close(gate)
	wg.Wait()

	admitted := make([]harness.WorkspaceCreateResp, 0, burst)
	rateLimited := 0
	for i, a := range attempts {
		if a.err != nil {
			t.Fatalf("burst CreateWorkspace %d transport error: %v", i, a.err)
		}
		switch a.raw.StatusCode {
		case http.StatusAccepted:
			admitted = append(admitted, a.resp)
		case http.StatusTooManyRequests:
			rateLimited++
			if ra := a.raw.Headers.Get("Retry-After"); ra != "" {
				if n, pErr := strconv.Atoi(ra); pErr != nil || n < 0 {
					t.Fatalf("invalid Retry-After header %q", ra)
				}
			}
		default:
			t.Fatalf("unexpected burst CreateWorkspace status %d", a.raw.StatusCode)
		}
	}
	if len(admitted) == 0 || len(admitted) > 2 || rateLimited == 0 {
		t.Fatalf("expected 1..2 admitted and >= 1 429 on repoA burst, got admitted=%d rateLimited=%d", len(admitted), rateLimited)
	}

	// 3. Restart worker and complete 2 proposals across repoA (clean -> PUBLISHED) and repoB (secret -> DENIED).
	if err := env.RestartWorker(); err != nil {
		t.Fatalf("RestartWorker: %v", err)
	}
	if admitted[0].OperationID != "" {
		op, wErr := actors.humanCli.WaitForOperation(ctx, admitted[0].OperationID, 30*time.Second)
		if wErr != nil {
			t.Fatalf("WaitForOperation(admitted[0]): %v", wErr)
		}
		m4RequireOpSucceeded(t, env, op)
	}
	wsAID := m4WorkspaceCreateID(admitted[0])
	var wsA harness.WorkspaceResp
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		got, gRaw, gErr := actors.humanCli.GetWorkspace(ctx, wsAID)
		if gErr != nil {
			return false, gErr
		}
		gRaw.RequireStatus(t, http.StatusOK)
		wsA = got
		return got.Status == "READY", nil
	})

	cleanGZ, cleanSHA := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: m4LoadFixture(t, "golden/clean_tree/README.md")},
		{Name: "pkg/hello/hello.go", Body: m4LoadFixture(t, "golden/clean_tree/pkg/hello/hello.go")},
	})
	pA := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, wsAID, cleanGZ, cleanSHA, wsA.Generation, "repoA clean", nil)
	pAEval, pAAssess := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(pA), pA.Version)
	pubA := m4ApproveAndPublish(t, ctx, env, actors.reviewerCli, actors.ctrlCli, pAEval, pAAssess)
	m4AssertPublishedGitAndPR(t, env, repoA.seeded.FullName, pAEval, pubA, harness.GitIdentity{
		Name:  m4HumanName,
		Email: m4HumanEmail,
	}, "false")

	// Proposal on repoB triggers secret finding -> DENIED.
	wsB := m4CreateAndAwaitWorkspace(t, ctx, env, actors.humanCli, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repoBSeeded.GitHubRepoID, Ref: "main"},
	})
	t.Cleanup(func() { env.Scanners().ResetAll() })
	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		SecretValue: canary,
		FilePath:    "secret.env",
	})
	secGZ, secSHA := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "secret.env", Body: []byte("TOKEN=" + canary + "\n")},
	})
	pB := m4UploadAndSubmitProposal(t, ctx, env, actors.ctrlCli, m4WorkspaceID(wsB), secGZ, secSHA, wsB.Generation, "repoB secret", nil)
	pBEval, _ := m4EvaluateAndAwait(t, ctx, env, actors.ctrlCli, m4PropID(pB), pB.Version)
	if pBEval.Status != "DENIED" {
		t.Fatalf("expected repoB secret proposal DENIED, got %q", pBEval.Status)
	}

	// 4. Backdate artifact expiry and verify retention deletes blobs without breaking proposals or audit chain.
	beforeObjs, err := env.Snapshots().ObjectCount()
	if err != nil {
		t.Fatalf("ObjectCount before: %v", err)
	}
	if _, err := env.DB().ExecSQL(`UPDATE artifacts SET expires_at = now() - interval '1 hour' WHERE deleted_at IS NULL;`); err != nil {
		t.Fatalf("backdate artifacts.expires_at: %v", err)
	}
	m4WaitUntil(ctx, t, 20*time.Second, func() (bool, error) {
		afterObjs, cErr := env.Snapshots().ObjectCount()
		if cErr != nil {
			return false, cErr
		}
		return afterObjs < beforeObjs, nil
	})

	// 5. Scrape /metrics, verify genesis-to-tip audit chain across multi-repo workload, and check zero secret leaks.
	metrics, mRaw, err := actors.humanCli.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	mRaw.RequireStatus(t, http.StatusOK)
	if strings.TrimSpace(metrics) == "" {
		t.Fatalf("expected non-empty /metrics body")
	}

	allEvents := m4AssertAuditChain(t, ctx, actors.auditorCli, m4PropID(pA), "proposal", "publish")
	evBytes, _ := json.Marshal(allEvents)
	harness.AssertNoSecretOrEncodedLeak(t, string(evBytes), canary)
	env.AssertNoSecretLeakInLogs(canary, actors.humanTok, actors.reviewerTok, actors.ctrlTok)
}
