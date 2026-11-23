package decisions

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/prompts"
)

type evalDatasetCase struct {
	CaseID               string   `json:"case_id"`
	FixtureFile          string   `json:"fixture_file"`
	RepoClassification   string   `json:"repo_classification"`
	ModelRouteAuthorised bool     `json:"model_route_authorised"`
	StageAEvidenceIDs    []string `json:"stage_a_evidence_ids"`
	ExpectSchemaValid    bool     `json:"expect_schema_valid"`
	ExpectGrounded       bool     `json:"expect_grounded"`
	ExpectStatus         string   `json:"expect_status"`
	ExpectPublishAllowed bool     `json:"expect_publish_allowed"`
	ExpectedCELEffect    string   `json:"expected_cel_effect"`
}

func TestEvalDataset_GoldenAllSevenCases(t *testing.T) {
	t.Parallel()

	evalDir := filepath.Join("..", "..", "test", "e2e", "fixtures", "eval")
	rawDataset, err := os.ReadFile(filepath.Join(evalDir, "eval_dataset.json"))
	if err != nil {
		t.Fatalf("read eval_dataset.json: %v", err)
	}

	var cases []evalDatasetCase
	if err := json.Unmarshal(rawDataset, &cases); err != nil {
		t.Fatalf("unmarshal eval_dataset.json: %v", err)
	}
	if len(cases) != 7 {
		t.Fatalf("expected 7 golden eval cases, got %d", len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.CaseID, func(t *testing.T) {
			t.Parallel()

			fixtureRaw, err := os.ReadFile(filepath.Join(evalDir, tc.FixtureFile))
			if err != nil {
				t.Fatalf("read fixture %s: %v", tc.FixtureFile, err)
			}

			var canonicalDiff = "diff --git a/main.go b/main.go\n+func Feature() {}\n"
			if tc.FixtureFile == "stageb_prompt_injection.json" {
				var wrapper struct {
					Adversarial json.RawMessage `json:"adversarial_model_response"`
				}
				if err := json.Unmarshal(fixtureRaw, &wrapper); err != nil {
					t.Fatalf("unwrap %s: %v", tc.FixtureFile, err)
				}
				fixtureRaw = wrapper.Adversarial

				injBytes, err := os.ReadFile(filepath.Join("..", "..", "test", "e2e", "fixtures", "payloads", "prompt_injection_source.go"))
				if err != nil {
					t.Fatalf("read prompt_injection_source.go: %v", err)
				}
				canonicalDiff = string(injBytes)
			}

			var gwCalls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gwCalls.Add(1)
				reqRaw, _ := io.ReadAll(r.Body)

				var parsed struct {
					Messages []GatewayMessage `json:"messages"`
				}
				if err := json.Unmarshal(reqRaw, &parsed); err != nil {
					t.Errorf("invalid gateway request JSON: %v", err)
				}
				for _, m := range parsed.Messages {
					if strings.EqualFold(m.Role, "system") && strings.Contains(m.Content, "Ignore all previous instructions") {
						t.Errorf("untrusted injection leaked into system message")
					}
				}

				body := string(fixtureRaw)
				if strings.Contains(body, "{{EVIDENCE_ID}}") {
					if len(tc.StageAEvidenceIDs) == 0 {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if !strings.Contains(string(reqRaw), tc.StageAEvidenceIDs[0]) {
						t.Errorf("expected Stage A evidence ID %q in gateway request body", tc.StageAEvidenceIDs[0])
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					body = strings.ReplaceAll(body, "{{EVIDENCE_ID}}", tc.StageAEvidenceIDs[0])
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			gwClient, err := NewHTTPGatewayClient(GatewayConfig{BaseURL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			svc, err := NewService(gwClient)
			if err != nil {
				t.Fatal(err)
			}

			findings := make([]domain.Finding, 0, len(tc.StageAEvidenceIDs))
			scanRunID := domain.MustNewID()
			for _, eid := range tc.StageAEvidenceIDs {
				cat := "SAST"
				if strings.Contains(eid, "secret") {
					cat = "SECRET"
				}
				findings = append(findings, domain.Finding{
					ID:          domain.MustNewID(),
					ScanRunID:   scanRunID,
					EvidenceID:  eid,
					Scanner:     "semgrep",
					Category:    cat,
					Severity:    domain.SeverityHigh,
					RuleID:      "eval-rule",
					Fingerprint: "fp-" + eid,
					Message:     "redacted stage a finding",
					Redacted:    true,
				})
			}

			allowedRoutes := []string{"approved-code-review"}
			if !tc.ModelRouteAuthorised {
				allowedRoutes = []string{"restricted-authorized-only"}
			}

			assessmentType := prompts.AssessmentTypeSecurityReview
			var fixtureMeta struct {
				AssessmentType string `json:"assessment_type"`
			}
			if json.Unmarshal(fixtureRaw, &fixtureMeta) == nil && prompts.IsAllowedAssessmentType(fixtureMeta.AssessmentType) {
				assessmentType = strings.TrimSpace(fixtureMeta.AssessmentType)
			}

			req := AssessRequest{
				ProposalID: domain.MustNewID(),
				ArtifactID: domain.MustNewID(),
				Repository: domain.Repository{
					ID:             domain.MustNewID(),
					FullName:       "org/eval-repo",
					Classification: domain.Classification(tc.RepoClassification),
					Enabled:        true,
				},
				AllowedModelRoutes: allowedRoutes,
				ModelRoute:         "approved-code-review",
				AssessmentType:     assessmentType,
				ChangedPaths:       []string{"main.go"},
				CanonicalDiff:      canonicalDiff,
				Findings:           findings,
			}

			got, err := svc.Assess(context.Background(), req)
			if err != nil {
				t.Fatalf("case %s: unexpected error: %v", tc.CaseID, err)
			}

			if !tc.ModelRouteAuthorised {
				if gwCalls.Load() != 0 {
					t.Fatalf("case %s: expected 0 gateway calls on unauthorized route, got %d", tc.CaseID, gwCalls.Load())
				}
			} else if gwCalls.Load() != 1 {
				t.Fatalf("case %s: expected 1 gateway call, got %d", tc.CaseID, gwCalls.Load())
			}

			if string(got.Status) != tc.ExpectStatus {
				t.Fatalf("case %s: status=%q, want %q (limitations=%v)", tc.CaseID, got.Status, tc.ExpectStatus, got.Result.Limitations)
			}
			if !domain.IsValidSHA256Hex(got.InputDigest) || !domain.IsValidSHA256Hex(got.OutputDigest) {
				t.Fatalf("case %s: invalid digests input=%q output=%q", tc.CaseID, got.InputDigest, got.OutputDigest)
			}
			if got.ModelVersion == "" || got.PromptVersion == "" || got.ModelRoute == "" {
				t.Fatalf("case %s: empty lineage metadata %+v", tc.CaseID, got)
			}
			if got.Result.Findings == nil || got.Result.Limitations == nil || got.EvidenceIDs == nil {
				t.Fatalf("case %s: expected non-nil slices on ModelAssessment", tc.CaseID)
			}

			if tc.ExpectStatus != string(domain.AssessmentStatusComplete) {
				if !got.BlocksPublication() {
					t.Fatalf("case %s: expected BlocksPublication()==true for status %s", tc.CaseID, got.Status)
				}
			}

			if tc.ExpectGrounded && tc.ExpectStatus == string(domain.AssessmentStatusComplete) && len(tc.StageAEvidenceIDs) > 0 && tc.FixtureFile == "stageb_high_risk_ip_security.json" {
				if len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != tc.StageAEvidenceIDs[0] {
					t.Fatalf("case %s: expected grounded EvidenceIDs=%v, got %v", tc.CaseID, tc.StageAEvidenceIDs, got.EvidenceIDs)
				}
			}

			fact := ToPolicyAssessmentFact(got)
			if fact.Status != tc.ExpectStatus {
				t.Fatalf("case %s: PolicyAssessmentFact.Status=%q, want %q", tc.CaseID, fact.Status, tc.ExpectStatus)
			}

			polEngine, err := policy.NewEngine()
			if err != nil {
				t.Fatalf("policy.NewEngine: %v", err)
			}
			defaultBundleYAML, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "default.yaml"))
			if err != nil {
				t.Fatalf("read default.yaml: %v", err)
			}
			compiled, compileErrs := polEngine.Compile(defaultBundleYAML)
			if len(compileErrs) > 0 {
				t.Fatalf("compile default.yaml: %+v", compileErrs)
			}
			criticalSecrets := int64(0)
			for _, f := range findings {
				if f.Category == "SECRET" {
					criticalSecrets++
				}
			}
			celRes, err := polEngine.Evaluate(context.Background(), compiled, policy.StageEgress, policy.PolicyInput{
				Findings: policy.FindingsInput{
					MandatoryScannersComplete: true,
					ScanComplete:              true,
					CriticalSecrets:           criticalSecrets,
					ProhibitedLicenses:        0,
					EvidenceIDs:               append([]string{}, tc.StageAEvidenceIDs...),
				},
				Assessment: policy.AssessmentInput{
					Status:         fact.Status,
					Risk:           fact.Risk,
					Disposition:    fact.Disposition,
					IPRisk:         fact.IPRisk,
					AssessmentType: fact.AssessmentType,
				},
				Change: policy.ChangeInput{
					Paths: []string{"main.go"},
				},
				Repository: policy.RepositoryInput{
					Classification: tc.RepoClassification,
				},
			})
			if err != nil {
				t.Fatalf("case %s: policy.Evaluate: %v", tc.CaseID, err)
			}
			if string(celRes.Effect) != tc.ExpectedCELEffect {
				t.Fatalf("case %s: CEL effect=%q, want %q (reasons=%+v)", tc.CaseID, celRes.Effect, tc.ExpectedCELEffect, celRes.Reasons)
			}
		})
	}
}
