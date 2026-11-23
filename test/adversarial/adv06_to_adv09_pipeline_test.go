package adversarial_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/prompts"
	"github.com/timreynolds/custodian/test/fixtures"
)

func TestADV06_SecretsRedactionAndIngressEgressBlocking(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	const canarySecret = "ghp_Adv06SuperSecretToken1234567890"
	ownerTok := st.MintHuman("adv06-owner", "adv06@acme.test", []string{"eng"}, []string{"developer"})
	ctrlTok := st.MintController("adv06-ctrl")
	auditorTok := st.MintAuditor("adv06-aud")

	// 1. Ingress blocked when Stage A gitleaks detects a secret on base commit.
	st.Scanners.SetGitleaksSecret(canarySecret)
	code, wsRaw := st.DoJSON(http.MethodPost, "/v1/workspaces", ownerTok, "adv06-ws-blocked", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": st.Repo.GitHubRepositoryID, "ref": "main"},
	}, nil)
	if code != http.StatusAccepted {
		t.Fatalf("CreateWorkspace expected 202, got %d", code)
	}
	var wsBlocked struct {
		WorkspaceID string `json:"workspace_id"`
	}
	_ = json.Unmarshal(wsRaw, &wsBlocked)
	st.DrainWorker(ctx)

	wsRec, err := st.Workspaces.Get(ctx, uuid.MustParse(wsBlocked.WorkspaceID))
	if err != nil || wsRec.Status != domain.WorkspaceStatusFailed {
		t.Fatalf("ADV-06 violation: expected FAILED workspace on ingress secret, got (%s, %v)", wsRec.Status, err)
	}

	// 2. Clean ingress, then secret introduced on egress -> DENIED, secret redacted in findings/audit/logs.
	st.Scanners.SetClean()
	_, propID, _, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: ".env", Body: []byte("TOKEN=" + canarySecret + "\n")},
	})

	st.Scanners.SetGitleaksSecret(canarySecret)
	code, _ = st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "adv06-eval-secret", map[string]any{
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
		Status string `json:"status"`
	}
	_ = json.Unmarshal(propRaw, &propOut)
	if propOut.Status != "DENIED" {
		t.Fatalf("expected DENIED on egress secret, got %q", propOut.Status)
	}

	_, findRaw := st.DoJSON(http.MethodGet, "/v1/proposals/"+propID+"/findings", ownerTok, "", nil, nil)
	_, audRaw := st.DoJSON(http.MethodGet, "/v1/audit/events?limit=200", auditorTok, "", nil, nil)
	for label, blob := range map[string]string{
		"findings":     string(findRaw),
		"audit_events": string(audRaw),
		"logs":         st.Logs.String(),
	} {
		if strings.Contains(blob, canarySecret) {
			t.Fatalf("ADV-06 redaction violation: raw secret leaked in %s", label)
		}
	}
}

func TestADV07_ForgedAuthorAndPrincipalKindEscalation(t *testing.T) {
	ctx := context.Background()
	st := fixtures.NewFullStack(t)

	// Verify PG17 UpsertPrincipal + Directory.ResolveCaller rejects AGENT -> HUMAN escalation.
	if _, err := st.Store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:        domain.PrincipalKindAgent,
		Issuer:      st.OIDC.Issuer(),
		Subject:     "adv07-agent",
		DisplayName: "Agent 07",
	}); err != nil {
		t.Fatalf("UpsertPrincipal(AGENT): %v", err)
	}

	// Mint a HUMAN token sharing (issuer, subject) with the AGENT principal and call API -> 403 PRINCIPAL_KIND_MISMATCH!
	spoofTok := st.MintHuman("adv07-agent", "forged@acme.test", []string{"eng"}, []string{"developer"})
	code, errRaw := st.DoJSON(http.MethodPost, "/v1/workspaces", spoofTok, "adv07-esc-1", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": st.Repo.GitHubRepositoryID, "ref": "main"},
	}, nil)
	if code != http.StatusForbidden || !strings.Contains(string(errRaw), "PRINCIPAL_KIND_MISMATCH") {
		t.Fatalf("expected 403 PRINCIPAL_KIND_MISMATCH on AGENT->HUMAN escalation, got %d: %s", code, string(errRaw))
	}

	// Caller-asserted author metadata in proposal submission is rejected (400 unknown field).
	realHumanTok := st.MintHuman("adv07-real", "real@acme.test", []string{"eng"}, []string{"developer"})
	ctrlTok := st.MintController("adv07-ctrl")
	wsID, _, _, _ := st.CreateReadyWorkspaceAndSubmit(ctx, realHumanTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# clean\n")},
	})
	codeForged, _ := st.DoJSON(http.MethodPost, "/v1/workspaces/"+wsID+"/proposals", ctrlTok, "adv07-forged-prop", map[string]any{
		"snapshot": map[string]any{"artifact_id": domain.MustNewID().String(), "sha256": strings.Repeat("a", 64), "workspace_generation": 1},
		"title":    "forged",
		"author":   map[string]any{"name": "Fake Boss", "email": "boss@acme.test"},
	}, nil)
	if codeForged != http.StatusBadRequest {
		t.Fatalf("expected 400 rejecting forged author field, got %d", codeForged)
	}
}

func TestADV08_PromptInjectionAndEvalDatasetStageC(t *testing.T) {
	ctx := context.Background()
	root := fixtures.FindRepoRoot(t)
	evalDir := filepath.Join(root, "test", "e2e", "fixtures", "eval")
	rawDataset, err := os.ReadFile(filepath.Join(evalDir, "eval_dataset.json"))
	if err != nil {
		t.Fatalf("read eval_dataset.json: %v", err)
	}
	var cases []struct {
		CaseID               string   `json:"case_id"`
		FixtureFile          string   `json:"fixture_file"`
		RepoClassification   string   `json:"repo_classification"`
		ModelRouteAuthorised bool     `json:"model_route_authorised"`
		StageAEvidenceIDs    []string `json:"stage_a_evidence_ids"`
		ExpectStatus         string   `json:"expect_status"`
		ExpectedCELEffect    string   `json:"expected_cel_effect"`
	}
	if err := json.Unmarshal(rawDataset, &cases); err != nil {
		t.Fatalf("unmarshal eval_dataset.json: %v", err)
	}

	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	compiledDefault, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "policies/defaults/default.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile default.yaml: %+v", errs)
	}

	for _, tc := range cases {
		t.Run(tc.CaseID, func(t *testing.T) {
			fixtureRaw, err := os.ReadFile(filepath.Join(evalDir, tc.FixtureFile))
			if err != nil {
				t.Fatalf("read fixture %s: %v", tc.FixtureFile, err)
			}
			diff := "diff --git a/main.go b/main.go\n+func Clean() {}\n"
			if tc.FixtureFile == "stageb_prompt_injection.json" {
				var wrap struct {
					Adversarial json.RawMessage `json:"adversarial_model_response"`
				}
				_ = json.Unmarshal(fixtureRaw, &wrap)
				fixtureRaw = wrap.Adversarial
				inj, _ := os.ReadFile(filepath.Join(root, "test", "e2e", "fixtures", "payloads", "prompt_injection_source.go"))
				diff = string(inj)
			}

			gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := string(fixtureRaw)
				if len(tc.StageAEvidenceIDs) > 0 {
					body = strings.ReplaceAll(body, "{{EVIDENCE_ID}}", tc.StageAEvidenceIDs[0])
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer gwSrv.Close()

			gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
			decSvc, _ := decisions.NewService(gwClient)

			findings := make([]domain.Finding, 0, len(tc.StageAEvidenceIDs))
			var criticalSecrets int64
			scanRunID := domain.MustNewID()
			for _, eid := range tc.StageAEvidenceIDs {
				cat := "SAST"
				if strings.Contains(eid, "secret") {
					cat = "SECRET"
					criticalSecrets++
				}
				findings = append(findings, domain.Finding{
					ID:          domain.MustNewID(),
					ScanRunID:   scanRunID,
					EvidenceID:  eid,
					Scanner:     "semgrep",
					Category:    cat,
					Severity:    domain.SeverityHigh,
					RuleID:      "rule-1",
					Fingerprint: "fp-" + eid,
					Message:     "redacted",
					Redacted:    true,
				})
			}

			allowed := []string{"approved-code-review"}
			if !tc.ModelRouteAuthorised {
				allowed = []string{"restricted-only"}
			}
			at := prompts.AssessmentTypeSecurityReview
			var meta struct {
				AssessmentType string `json:"assessment_type"`
			}
			if json.Unmarshal(fixtureRaw, &meta) == nil && prompts.IsAllowedAssessmentType(meta.AssessmentType) {
				at = meta.AssessmentType
			}

			ma, err := decSvc.Assess(ctx, decisions.AssessRequest{
				ProposalID: domain.MustNewID(),
				ArtifactID: domain.MustNewID(),
				Repository: domain.Repository{
					ID: domain.MustNewID(), FullName: "acme/eval", Classification: domain.Classification(tc.RepoClassification), Enabled: true,
				},
				AllowedModelRoutes: allowed,
				ModelRoute:         "approved-code-review",
				AssessmentType:     at,
				ChangedPaths:       []string{"main.go"},
				CanonicalDiff:      diff,
				Findings:           findings,
			})
			if err != nil {
				t.Fatalf("Assess: %v", err)
			}
			if string(ma.Status) != tc.ExpectStatus {
				t.Fatalf("status=%s, want %s", ma.Status, tc.ExpectStatus)
			}
			fact := decisions.ToPolicyAssessmentFact(ma)
			celRes, err := polEngine.Evaluate(ctx, compiledDefault, policy.StageEgress, policy.PolicyInput{
				Findings: policy.FindingsInput{
					MandatoryScannersComplete: true,
					ScanComplete:              true,
					CriticalSecrets:           criticalSecrets,
					EvidenceIDs:               tc.StageAEvidenceIDs,
				},
				Assessment: policy.AssessmentInput{
					Status: fact.Status, Risk: fact.Risk, Disposition: fact.Disposition, IPRisk: fact.IPRisk, AssessmentType: fact.AssessmentType,
				},
				Change:     policy.ChangeInput{Paths: []string{"main.go"}},
				Repository: policy.RepositoryInput{Classification: tc.RepoClassification},
			})
			if err != nil {
				t.Fatalf("policy.Evaluate: %v", err)
			}
			if string(celRes.Effect) != tc.ExpectedCELEffect {
				t.Fatalf("CEL effect=%s, want %s", celRes.Effect, tc.ExpectedCELEffect)
			}
		})
	}
}

func TestADV09_CELErrorsAndOrgOverrideAttempts(t *testing.T) {
	ctx := context.Background()
	polEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	orgDeny, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "test/e2e/fixtures/policies/org_mandatory_deny.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile org_mandatory_deny: %+v", errs)
	}
	repoPermissive, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "test/e2e/fixtures/policies/repo_permissive_override_attempt.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile repo_permissive_override_attempt: %+v", errs)
	}

	// P2-GAP-01 verification: scan_complete=false must block on BOTH INGRESS and EGRESS despite repo ALLOW override!
	for _, stage := range []string{policy.StageIngress, policy.StageEgress} {
		res, err := polEngine.ComposeAndEvaluate(ctx, orgDeny, repoPermissive, stage, policy.PolicyInput{
			Findings:   policy.FindingsInput{ScanComplete: false, CriticalSecrets: 0, ProhibitedLicenses: 0},
			Assessment: policy.AssessmentInput{Status: "COMPLETE", Disposition: "CLEAR"},
		})
		if err != nil {
			t.Fatalf("ComposeAndEvaluate(%s): %v", stage, err)
		}
		if !res.Effect.BlocksPublication() {
			t.Fatalf("ADV-09 violation (%s): incomplete scan allowed when repo permissive override present (effect=%s)", stage, res.Effect)
		}
	}

	// Verify runtime CEL error bundle fails closed to DENY.
	errBundle, errs := polEngine.Compile(fixtures.VerifyRepoBundleLoaded(t, "test/e2e/fixtures/policies/runtime_cel_error_fail_closed.yaml"))
	if len(errs) > 0 {
		t.Fatalf("compile runtime_cel_error_fail_closed: %+v", errs)
	}
	resErr, err := polEngine.Evaluate(ctx, errBundle, policy.StageEgress, policy.PolicyInput{
		Findings: policy.FindingsInput{ScanComplete: true, CriticalSecrets: 0},
	})
	if err != nil || resErr.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected DENY on runtime CEL error, got (%s, %v)", resErr.Effect, err)
	}
}
