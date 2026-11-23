package workflow_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/workflow"
	"github.com/timreynolds/custodian/internal/workspaces"
)

// --- Unit Tests ---

func TestErrorClassificationAndSanitization(t *testing.T) {
	retryable := []error{
		domain.Unavailable("GITHUB_UNAVAILABLE", "503"),
		domain.RateLimited("GITHUB_RATE_LIMITED", "429"),
		context.DeadlineExceeded,
		domain.Conflict("TX_CONFLICT", "deadlock detected"),
	}
	for _, err := range retryable {
		if !workflow.IsRetryableError(err) {
			t.Fatalf("expected retryable for %v", err)
		}
	}

	terminal := []error{
		domain.BadRequest("BAD", "bad"),
		domain.Unauthorized("UNAUTH", "unauth"),
		domain.Forbidden("FORB", "forb"),
		domain.NotFound("NF", "nf"),
		domain.Unprocessable("UNPROC", "unproc"),
		domain.Conflict("INVALID_STATE", "conflict"),
		domain.Internal("INT", "internal"),
		context.Canceled,
		nil,
	}
	for _, err := range terminal {
		if workflow.IsRetryableError(err) {
			t.Fatalf("expected terminal (non-retryable) for %v", err)
		}
	}

	dirtyErr := domain.Unavailable("GITHUB_UNAVAILABLE", "clone failed https://x-access-token:ghp_secret1234567890@github.com/acme/repo.git Bearer tok_abc123 password=supersecret AKIAIOSFODNN7EXAMPLE eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig_part-123\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbody\n-----END RSA PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\nunclosedbody")
	code, msg := workflow.SafeErrorCodeMessage(dirtyErr)
	if code != "GITHUB_UNAVAILABLE" {
		t.Fatalf("unexpected code %q", code)
	}
	for _, leak := range []string{
		"ghp_secret1234567890",
		"tok_abc123",
		"supersecret",
		"x-access-token:ghp_",
		"AKIAIOSFODNN7EXAMPLE",
		"eyJhbGciOiJSUzI1NiJ9",
		"MIIEowIBAAKCAQEAsecretbody",
		"unclosedbody",
		"-----BEGIN",
		"-----END",
	} {
		if strings.Contains(msg, leak) {
			t.Fatalf("SafeErrorCodeMessage leaked %q in %q", leak, msg)
		}
	}
}

func TestBudgetLimiterConcurrency(t *testing.T) {
	limiter := workflow.NewBudgetLimiter(1, 1, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	repoID := domain.MustNewID()
	relRepo, err := limiter.AcquireRepo(ctx, repoID)
	if err != nil {
		t.Fatalf("AcquireRepo(1): %v", err)
	}
	relScan, err := limiter.AcquireScan(ctx)
	if err != nil {
		t.Fatalf("AcquireScan(1): %v", err)
	}
	relModel, err := limiter.AcquireModel(ctx)
	if err != nil {
		t.Fatalf("AcquireModel(1): %v", err)
	}

	// Second concurrent acquire on scan must block until released.
	shortCtx, shortCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	_, blockErr := limiter.AcquireScan(shortCtx)
	shortCancel()
	if !errors.Is(blockErr, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded when scan budget=1 is saturated, got %v", blockErr)
	}

	relModel()
	relScan()
	relRepo()

	relScan2, err := limiter.AcquireScan(ctx)
	if err != nil {
		t.Fatalf("AcquireScan after release: %v", err)
	}
	relScan2()
}

// --- Test Helpers & Fakes ---

type stubInspector struct {
	mu    sync.Mutex
	fn    func(ctx context.Context, req inspection.Request) (inspection.Report, error)
	calls []inspection.Request
}

func (s *stubInspector) Inspect(ctx context.Context, req inspection.Request) (inspection.Report, error) {
	s.mu.Lock()
	s.calls = append(s.calls, req)
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, req)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]domain.ScanRun, 0, len(inspection.MandatoryScanners))
	for _, sc := range inspection.MandatoryScanners {
		runs = append(runs, domain.ScanRun{
			ID:             domain.MustNewID(),
			ProposalID:     req.ProposalID,
			ArtifactID:     req.ArtifactID,
			Scanner:        string(sc),
			ScannerVersion: "1.0.0",
			Status:         domain.ScanStatusCompleted,
			Coverage: domain.ScanCoverage{
				FilesExamined: 2,
				FilesSkipped:  0,
				BytesExamined: 64,
				Complete:      true,
			},
			StartedAt:   now,
			CompletedAt: &now,
		})
	}
	return inspection.Report{
		ProposalID: req.ProposalID,
		ArtifactID: req.ArtifactID,
		ScanRuns:   runs,
		Findings:   nil,
		Summary: inspection.InspectionSummary{
			MandatoryScannersComplete: true,
			ScanComplete:              true,
			CountsByCategory:          map[string]int{},
			CountsBySeverity:          map[string]int{},
			CountsByScanner:           map[string]int{},
			EvidenceIDs:               []string{},
			FailedScanners:            []string{},
			IncompleteScanners:        []string{},
		},
	}, nil
}

type failingGitReader struct {
	inner     domain.GitReader
	mu        sync.Mutex
	failLeft  int
	failErr   error
	callCount int
}

func (f *failingGitReader) ResolveRef(ctx context.Context, repo domain.Repository, ref string) (string, error) {
	return f.inner.ResolveRef(ctx, repo, ref)
}

func (f *failingGitReader) Checkout(ctx context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error) {
	f.mu.Lock()
	f.callCount++
	shouldFail := f.failLeft != 0
	if f.failLeft > 0 {
		f.failLeft--
	}
	err := f.failErr
	f.mu.Unlock()
	if shouldFail {
		return domain.CheckoutResult{}, err
	}
	return f.inner.Checkout(ctx, repo, commitSHA, opts)
}

type mockGatewayState struct {
	mu           sync.Mutex
	requests     []decisions.GatewayRequest
	statusCode   int
	assessmentFn func(req decisions.GatewayRequest) string
}

func startMockGateway(t *testing.T, state *mockGatewayState) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var gwReq decisions.GatewayRequest
		if err := json.NewDecoder(r.Body).Decode(&gwReq); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		state.mu.Lock()
		state.requests = append(state.requests, gwReq)
		code := state.statusCode
		fn := state.assessmentFn
		state.mu.Unlock()

		if code >= 400 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"gateway outage"}`))
			return
		}
		at := gwReq.AssessmentType
		if fn != nil {
			at = fn(gwReq)
		}
		if at == "" {
			at = "SECURITY_REVIEW"
		}
		risk := "LOW"
		disp := "CLEAR"
		if at == "IP_PROVENANCE" {
			risk = "HIGH"
			disp = "REVIEW"
		}
		body := map[string]any{
			"id":     "chatcmpl-test",
			"object": "chat.completion",
			"model":  "mock-model-v1",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role": "assistant",
						"content": mustJSONString(map[string]any{
							"schema_version":  "1",
							"assessment_type": at,
							"risk":            risk,
							"disposition":     disp,
							"confidence":      0.95,
							"summary":         "mock assessment completed",
							"findings":        []any{},
							"limitations":     []string{},
						}),
					},
					"finish_reason": "stop",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type pgTestFixture struct {
	pg       *harness.PostgresHarness
	store    *persistence.Store
	git      *harness.BareGitHarness
	snaps    *harness.SnapshotHarness
	repo     persistence.RepositoryRow
	bareRepo harness.BareRepo
	owner    persistence.PrincipalRow
	policyID uuid.UUID
}

func setupPGFixture(t *testing.T, classification domain.Classification, allowedRoutes []string) *pgTestFixture {
	t.Helper()
	pg := harness.StartPostgres(t, harness.WithPGAllowDockerSkip(true))
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)

	gh := harness.NewBareGitHarness(t, "")
	bareRepo, err := gh.InitBareRepo("acme", "service", harness.WithInitialFiles(map[string]string{
		"README.md": "# Custodian Test Repo\n",
		"main.go":   "package main\nfunc main() {}\n",
	}))
	if err != nil {
		t.Fatalf("InitBareRepo: %v", err)
	}

	sh := harness.NewSnapshotHarness(t)
	ctx := context.Background()

	ownerRow, err := store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://issuer.test",
		Subject:       "human-owner-1",
		DisplayName:   "Alice Owner",
		VerifiedEmail: "alice@example.com",
		Groups:        []string{"engineering"},
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal: %v", err)
	}

	if len(allowedRoutes) == 0 {
		allowedRoutes = []string{"approved-code-review"}
	}
	repoRow, err := store.CreateRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:      bareRepo.GitHubRepositoryID,
		GitHubInstallationID:    bareRepo.InstallationID,
		FullName:                bareRepo.FullName,
		Classification:          classification,
		Enabled:                 true,
		AllowedModelRoutes:      allowedRoutes,
		MaxConcurrentOperations: 5,
	})
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}

	// Sync policies/defaults/default.yaml so ORG policy bundle is active.
	policyEngine, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	repoRoot := findRepoRoot(t)
	if _, err := workflow.SyncPolicyDir(ctx, store, policyEngine, filepath.Join(repoRoot, "policies", "defaults"), time.Now().UTC()); err != nil {
		t.Fatalf("SyncPolicyDir: %v", err)
	}
	orgBundles, err := store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
	if err != nil || len(orgBundles) == 0 {
		t.Fatalf("ListActivePolicyBundlesByScope: %v (len=%d)", err, len(orgBundles))
	}

	return &pgTestFixture{
		pg:       pg,
		store:    store,
		git:      gh,
		snaps:    sh,
		repo:     repoRow,
		bareRepo: bareRepo,
		owner:    ownerRow,
		policyID: orgBundles[0].ID,
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", dir)
		}
		dir = parent
	}
}

func buildTarGzBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar Write(%s): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func newTestWorkflowRunner(t *testing.T, fx *pgTestFixture, gitReader domain.GitReader, insp inspection.Runner, dec workflow.DecisionAssessor, cfg workflow.Config) (*workflow.Service, *workflow.Runner) {
	t.Helper()
	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "workflow-test",
	})
	if gitReader == nil {
		gitReader = fx.git.LocalReader()
	}
	reconSvc, err := reconstruct.NewService(reconstruct.Config{
		GitReader:     gitReader,
		SnapshotStore: fx.snaps.Store(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("reconstruct.NewService: %v", err)
	}
	if insp == nil {
		insp = &stubInspector{}
	}
	svc, err := workflow.NewService(workflow.ServiceConfig{
		Store:            fx.store,
		SnapshotStore:    fx.snaps.Store(),
		GitReader:        gitReader,
		Reconstructor:    reconSvc,
		InspectionRunner: insp,
		Decisions:        dec,
		Logger:           logger,
		Config:           cfg,
	})
	if err != nil {
		t.Fatalf("workflow.NewService: %v", err)
	}
	runner, err := workflow.NewRunner(workflow.RunnerConfig{
		Service: svc,
		Config:  cfg,
	})
	if err != nil {
		t.Fatalf("workflow.NewRunner: %v", err)
	}
	return svc, runner
}

// --- PG17 Integration Tests ---

func TestWorkflow_WorkspaceIngress_SuccessPolicyDenyAndRetries(t *testing.T) {
	t.Run("success and idempotency", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		svc, runner := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{
			ArtifactRetentionTTL: 5 * time.Minute,
		})

		wsSvc := workspaces.NewService(fx.store, nil, nil)
		created, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID,
			OwnerID:      fx.owner.ID,
			ModelRoute:   "approved-code-review",
			BaseCommit:   fx.bareRepo.HeadSHA,
			TargetRef:    "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}

		n, err := runner.ProcessOnce(ctx)
		if err != nil || n != 1 {
			t.Fatalf("ProcessOnce: n=%d err=%v", n, err)
		}

		ws, err := wsSvc.Get(ctx, created.Workspace.ID)
		if err != nil {
			t.Fatalf("ws.Get: %v", err)
		}
		opRow, err := fx.store.GetOperationByID(ctx, created.Operation.ID)
		if err != nil {
			t.Fatalf("GetOperationByID: %v", err)
		}
		if ws.Status != domain.WorkspaceStatusReady || ws.SourceArtifactID == nil {
			t.Fatalf("expected READY workspace with source_artifact_id, got status=%s art=%v (opStatus=%s lastErr=%q)", ws.Status, ws.SourceArtifactID, opRow.Status, derefStr(opRow.LastError))
		}

		artRow, err := fx.store.GetArtifactByID(ctx, *ws.SourceArtifactID)
		if err != nil {
			t.Fatalf("GetArtifactByID: %v", err)
		}
		if artRow.ExpiresAt == nil {
			t.Fatalf("expected WORKSPACE_SOURCE artifact to have expires_at set")
		}

		// Idempotent re-execution when already READY.
		if opRow.Status != domain.OperationStatusSucceeded {
			t.Fatalf("expected SUCCEEDED op, got %s (%s)", opRow.Status, derefStr(opRow.LastError))
		}
		idemRes, err := svc.ExecuteIngress(ctx, operations.OperationDetails{
			Operation: opRow.ToDomain(),
		})
		if err != nil || !idemRes.Idempotent {
			t.Fatalf("expected idempotent ExecuteIngress, got %+v err=%v", idemRes, err)
		}
	})

	t.Run("ingress policy deny blocks workspace and audits", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		secretInsp := &stubInspector{
			fn: func(ctx context.Context, req inspection.Request) (inspection.Report, error) {
				now := time.Now().UTC().Truncate(time.Microsecond)
				srID := domain.MustNewID()
				return inspection.Report{
					ProposalID: req.ProposalID,
					ArtifactID: req.ArtifactID,
					ScanRuns: []domain.ScanRun{{
						ID:             srID,
						ProposalID:     req.ProposalID,
						ArtifactID:     req.ArtifactID,
						Scanner:        "gitleaks",
						ScannerVersion: "8.0.0",
						Status:         domain.ScanStatusCompleted,
						Coverage:       domain.ScanCoverage{FilesExamined: 1, Complete: true},
						StartedAt:      now,
						CompletedAt:    &now,
					}},
					Findings: []domain.Finding{{
						ID:          domain.MustNewID(),
						ScanRunID:   srID,
						EvidenceID:  "ev-1",
						Scanner:     "gitleaks",
						Category:    "SECRET",
						Severity:    domain.SeverityCritical,
						RuleID:      "aws-access-token",
						Path:        ".env",
						Fingerprint: "fp-1",
						Redacted:    true,
						Message:     "redacted secret",
					}},
					Summary: inspection.InspectionSummary{
						MandatoryScannersComplete: true,
						ScanComplete:              true,
						CriticalSecrets:           1,
						TotalFindings:             1,
						CountsByCategory:          map[string]int{"SECRET": 1},
						CountsBySeverity:          map[string]int{"CRITICAL": 1},
						CountsByScanner:           map[string]int{"gitleaks": 1},
						EvidenceIDs:               []string{"ev-1"},
						FailedScanners:            []string{},
						IncompleteScanners:        []string{},
					},
				}, nil
			},
		}
		_, runner := newTestWorkflowRunner(t, fx, nil, secretInsp, nil, workflow.Config{})
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		created, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID,
			OwnerID:      fx.owner.ID,
			ModelRoute:   "approved-code-review",
			BaseCommit:   fx.bareRepo.HeadSHA,
			TargetRef:    "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}

		if _, err := runner.ProcessOnce(ctx); err != nil {
			t.Fatalf("ProcessOnce: %v", err)
		}

		opRow, _ := fx.store.GetOperationByID(ctx, created.Operation.ID)
		if opRow.Status != domain.OperationStatusFailed {
			t.Fatalf("expected FAILED operation on ingress policy deny, got %s", opRow.Status)
		}
		ws, _ := wsSvc.Get(ctx, created.Workspace.ID)
		if ws.Status != domain.WorkspaceStatusFailed {
			t.Fatalf("expected FAILED workspace on ingress policy deny, got %s", ws.Status)
		}
		audSvc := audit.NewService(fx.store, nil)
		audRes, err := audSvc.List(ctx, audit.ListFilter{
			ResourceType: "workspace",
			ResourceID:   &created.Workspace.ID,
			Limit:        20,
		})
		if err != nil || len(audRes.Events) == 0 {
			t.Fatalf("expected workspace audit events, got len=%d err=%v", len(audRes.Events), err)
		}
	})

	t.Run("transient retry succeeds and permanent outage exhausts max_attempts", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		flakyGit := &failingGitReader{
			inner:    fx.git.LocalReader(),
			failLeft: 1,
			failErr:  domain.Unavailable("GITHUB_UNAVAILABLE", "503 transient"),
		}
		_, runner := newTestWorkflowRunner(t, fx, flakyGit, nil, nil, workflow.Config{})
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		c1, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID,
			OwnerID:      fx.owner.ID,
			ModelRoute:   "approved-code-review",
			BaseCommit:   fx.bareRepo.HeadSHA,
			TargetRef:    "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("Create(c1): %v", err)
		}
		if _, err := runner.ProcessOnce(ctx); err != nil {
			t.Fatalf("ProcessOnce attempt 1: %v", err)
		}
		op1, _ := fx.store.GetOperationByID(ctx, c1.Operation.ID)
		if op1.Status != domain.OperationStatusPending || op1.Attempts != 1 {
			t.Fatalf("expected PENDING retry after attempt 1, got status=%s attempts=%d", op1.Status, op1.Attempts)
		}
		// Fast-forward available_at so attempt 2 runs immediately.
		if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET available_at = now() - interval '1 second' WHERE id = $1`, c1.Operation.ID); err != nil {
			t.Fatalf("fast-forward available_at: %v", err)
		}
		if _, err := runner.ProcessOnce(ctx); err != nil {
			t.Fatalf("ProcessOnce attempt 2: %v", err)
		}
		op1, _ = fx.store.GetOperationByID(ctx, c1.Operation.ID)
		if op1.Status != domain.OperationStatusSucceeded || op1.Attempts != 2 {
			t.Fatalf("expected SUCCEEDED on attempt 2, got status=%s attempts=%d", op1.Status, op1.Attempts)
		}

		// Permanent outage exhausting max_attempts=2 fails workspace too.
		permGit := &failingGitReader{
			inner:    fx.git.LocalReader(),
			failLeft: -1,
			failErr:  domain.Unavailable("GITHUB_UNAVAILABLE", "503 permanent"),
		}
		_, permRunner := newTestWorkflowRunner(t, fx, permGit, nil, nil, workflow.Config{})
		c2, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID,
			OwnerID:      fx.owner.ID,
			ModelRoute:   "approved-code-review",
			BaseCommit:   fx.bareRepo.HeadSHA,
			TargetRef:    "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("Create(c2): %v", err)
		}
		if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET max_attempts = 2 WHERE id = $1`, c2.Operation.ID); err != nil {
			t.Fatalf("set max_attempts=2: %v", err)
		}
		_, _ = permRunner.ProcessOnce(ctx)
		_, _ = fx.pg.Pool().Exec(ctx, `UPDATE operations SET available_at = now() - interval '1 second' WHERE id = $1`, c2.Operation.ID)
		_, _ = permRunner.ProcessOnce(ctx)

		op2, _ := fx.store.GetOperationByID(ctx, c2.Operation.ID)
		if op2.Status != domain.OperationStatusFailed || op2.Attempts != 2 {
			t.Fatalf("expected FAILED after max_attempts=2, got status=%s attempts=%d", op2.Status, op2.Attempts)
		}
		ws2, _ := wsSvc.Get(ctx, c2.Workspace.ID)
		if ws2.Status != domain.WorkspaceStatusFailed {
			t.Fatalf("expected FAILED workspace when operation exhausts max_attempts, got %s", ws2.Status)
		}
	})
}

func TestWorkflow_ProposalReconstructAndEvaluate_FullCoverage(t *testing.T) {
	runIngressAndSubmit := func(ctx context.Context, t *testing.T, fx *pgTestFixture, runner *workflow.Runner, modelRoute string, tarFiles map[string]string) proposals.SubmitResult {
		t.Helper()
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID,
			OwnerID:      fx.owner.ID,
			ModelRoute:   modelRoute,
			BaseCommit:   fx.bareRepo.HeadSHA,
			TargetRef:    "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}
		for i := 0; i < 4; i++ {
			n, pErr := runner.ProcessOnce(ctx)
			if pErr != nil {
				t.Fatalf("ProcessOnce(ingress): %v", pErr)
			}
			if n == 0 {
				break
			}
		}

		tarBytes := buildTarGzBytes(t, tarFiles)
		sha := domain.SHA256Hex(tarBytes)
		key := fmt.Sprintf("uploads/%s/egress.tar.gz", domain.MustNewID().String())
		putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, key, tarBytes)
		if err != nil {
			t.Fatalf("PutBytes: %v", err)
		}
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
		gen := int64(1)
		regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
			ID:                  putArt.ID,
			Kind:                domain.ArtifactKindEgressSnapshot,
			SHA256:              putArt.SHA256,
			StorageKey:          putArt.StorageKey,
			StorageGeneration:   putArt.StorageGeneration,
			SizeBytes:           putArt.SizeBytes,
			Format:              "application/gzip",
			WorkspaceID:         &wsRes.Workspace.ID,
			WorkspaceGeneration: &gen,
			UploadedBy:          &fx.owner.ID,
			ExpiresAt:           &exp,
		})
		if err != nil {
			t.Fatalf("RegisterArtifact(egress): %v", err)
		}

		propSvc := proposals.NewService(fx.store, nil, nil)
		sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
			WorkspaceID:         wsRes.Workspace.ID,
			WorkspaceGeneration: 1,
			SnapshotArtifactID:  regArt.ID,
			SnapshotSHA256:      sha,
			SizeBytes:           int64(len(tarBytes)),
			Title:               "Test Proposal",
			ProvenanceType:      "agent_assisted",
			CaptureMethod:       "frozen_filesystem",
		})
		if err != nil {
			t.Fatalf("proposals.Submit: %v", err)
		}
		return sub
	}

	t.Run("reconstruct + evaluate happy path INTERNAL (SECURITY_REVIEW) and CONFIDENTIAL (IP_PROVENANCE)", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			classification domain.Classification
			wantAssessType string
			wantOblGroup   string
		}{
			{"internal", domain.ClassificationInternal, "SECURITY_REVIEW", ""},
			{"confidential", domain.ClassificationConfidential, "IP_PROVENANCE", "ip-review"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fx := setupPGFixture(t, tc.classification, []string{"approved-code-review"})
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				gwState := &mockGatewayState{}
				gwSrv := startMockGateway(t, gwState)
				gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
				if err != nil {
					t.Fatalf("NewHTTPGatewayClient: %v", err)
				}
				decSvc, err := decisions.NewService(gwClient)
				if err != nil {
					t.Fatalf("decisions.NewService: %v", err)
				}

				_, runner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{
					ArtifactRetentionTTL: 1 * time.Second,
				})

				sub := runIngressAndSubmit(ctx, t, fx, runner, "approved-code-review", map[string]string{
					"README.md": "# Custodian Test Repo\n",
					"main.go":   "package main\nfunc main() { println(1) }\n",
				})

				// Process PROPOSAL_RECONSTRUCT.
				for i := 0; i < 4; i++ {
					n, pErr := runner.ProcessOnce(ctx)
					if pErr != nil {
						t.Fatalf("ProcessOnce(reconstruct): %v", pErr)
					}
					if n == 0 {
						break
					}
				}

				propSvc := proposals.NewService(fx.store, nil, nil)
				afterRecon, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
				if err != nil {
					t.Fatalf("GetDetails(after recon): %v", err)
				}
				if afterRecon.Status != domain.ProposalStatusReconstructed || afterRecon.CanonicalArtifactID == nil || afterRecon.ManifestArtifactID == nil {
					t.Fatalf("expected RECONSTRUCTED proposal with canonical & manifest artifacts, got %+v", afterRecon)
				}
				// Verify canonical artifacts honor ArtifactRetentionTTL when > 0.
				canonArt, _ := fx.store.GetArtifactByID(ctx, *afterRecon.CanonicalArtifactID)
				if canonArt.ExpiresAt == nil {
					t.Fatalf("expected canonical artifact expires_at to be set when ArtifactRetentionTTL > 0")
				}

				// Request evaluation & process PROPOSAL_EVALUATE.
				if _, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
					ProposalID:      afterRecon.ID,
					ExpectedVersion: afterRecon.Version,
				}); err != nil {
					t.Fatalf("RequestEvaluation: %v", err)
				}
				for i := 0; i < 4; i++ {
					n, pErr := runner.ProcessOnce(ctx)
					if pErr != nil {
						t.Fatalf("ProcessOnce(evaluate): %v", pErr)
					}
					if n == 0 {
						break
					}
				}

				afterEval, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
				if err != nil {
					t.Fatalf("GetDetails(after eval): %v", err)
				}
				if afterEval.Status != domain.ProposalStatusPendingApproval {
					t.Fatalf("expected PENDING_APPROVAL, got status=%s effect=%v", afterEval.Status, afterEval.LatestPolicyEffect)
				}

				gwState.mu.Lock()
				if len(gwState.requests) != 1 || gwState.requests[0].AssessmentType != tc.wantAssessType {
					t.Fatalf("expected 1 gateway request with assessment_type=%s, got %+v", tc.wantAssessType, gwState.requests)
				}
				gwState.mu.Unlock()

				if tc.wantOblGroup != "" {
					reqs, err := fx.store.ListApprovalRequirementsByProposal(ctx, afterEval.ID)
					if err != nil || len(reqs) == 0 || reqs[0].ReviewerGroup != tc.wantOblGroup {
						t.Fatalf("expected obligation %q, got %+v (err=%v)", tc.wantOblGroup, reqs, err)
					}
				}
			})
		}
	})

	t.Run("adversarial corrupt snapshot marks proposal FAILED terminally", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		_, runner := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{})
		sub := runIngressAndSubmit(ctx, t, fx, runner, "approved-code-review", map[string]string{
			"README.md": "ok\n",
		})
		// Corrupt the uploaded snapshot in SnapshotStore so ReconstructDetailed fails with DIGEST_MISMATCH (ErrUnprocessable, non-retryable).
		artRow, _ := fx.store.GetArtifactByID(ctx, sub.Proposal.SnapshotArtifactID)
		if err := fx.snaps.CorruptBlob(artRow.StorageKey, []byte("corrupted-not-gzip")); err != nil {
			t.Fatalf("CorruptBlob: %v", err)
		}
		for i := 0; i < 4; i++ {
			n, _ := runner.ProcessOnce(ctx)
			if n == 0 {
				break
			}
		}
		opRow, _ := fx.store.GetOperationByID(ctx, sub.Operation.ID)
		if opRow.Status != domain.OperationStatusFailed {
			t.Fatalf("expected terminal FAILED op on corrupt snapshot, got %s", opRow.Status)
		}
		prop, _ := fx.store.GetProposalByID(ctx, sub.Proposal.ID)
		if prop.Status != domain.ProposalStatusFailed {
			t.Fatalf("expected proposal FAILED on corrupt snapshot, got %s", prop.Status)
		}
	})

	t.Run("unauthorized route, org non-overridable deny, missing mandatory scanner, and gateway outage", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationRestricted, []string{"restricted-only-route"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		gwState := &mockGatewayState{}
		gwSrv := startMockGateway(t, gwState)
		gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
		decSvc, _ := decisions.NewService(gwClient)
		_, runner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})

		// 1. Unauthorized route revoked in DB after workspace creation -> INDETERMINATE -> QUARANTINED with 0 gateway calls.
		sub1 := runIngressAndSubmit(ctx, t, fx, runner, "restricted-only-route", map[string]string{
			"README.md": "ok\n",
		})
		if _, err := fx.pg.Pool().Exec(ctx, `UPDATE repositories SET allowed_model_routes = ARRAY['other-route'] WHERE id = $1`, fx.repo.ID); err != nil {
			t.Fatalf("revoke route: %v", err)
		}
		for i := 0; i < 4; i++ {
			if n, _ := runner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		propSvc := proposals.NewService(fx.store, nil, nil)
		p1, _ := propSvc.GetDetails(ctx, sub1.Proposal.ID)
		_, _ = propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{ProposalID: p1.ID, ExpectedVersion: p1.Version})
		for i := 0; i < 4; i++ {
			if n, _ := runner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		p1After, _ := propSvc.GetDetails(ctx, p1.ID)
		if p1After.Status != domain.ProposalStatusQuarantined {
			t.Fatalf("expected QUARANTINED on unauthorized route, got %s", p1After.Status)
		}
		gwState.mu.Lock()
		if len(gwState.requests) != 0 {
			t.Fatalf("expected 0 gateway calls on unauthorized route, got %d", len(gwState.requests))
		}
		gwState.mu.Unlock()

		// 2. ORG non-overridable DENY beats permissive REPO bundle.
		repoRoot := findRepoRoot(t)
		orgYAML, err := os.ReadFile(filepath.Join(repoRoot, "test", "e2e", "fixtures", "policies", "org_mandatory_deny.yaml"))
		if err != nil {
			t.Fatalf("read org_mandatory_deny.yaml: %v", err)
		}
		repoYAML, err := os.ReadFile(filepath.Join(repoRoot, "test", "e2e", "fixtures", "policies", "repo_permissive_override_attempt.yaml"))
		if err != nil {
			t.Fatalf("read repo_permissive_override_attempt.yaml: %v", err)
		}
		pe, _ := policy.NewEngine()
		orgComp, valErrs := pe.Compile(orgYAML)
		if len(valErrs) > 0 {
			t.Fatalf("Compile org: %+v", valErrs)
		}
		repoComp, valErrs := pe.Compile(repoYAML)
		if len(valErrs) > 0 {
			t.Fatalf("Compile repo: %+v", valErrs)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name: orgComp.Bundle.Metadata.Name, Version: orgComp.Bundle.Metadata.Version,
			Scope: domain.PolicyScopeOrg, Digest: orgComp.Digest, Definition: orgComp.Definition,
			ActivatedAt: &now, CreatedAt: now,
		}); err != nil {
			t.Fatalf("upsert org bundle: %v", err)
		}
		if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name: repoComp.Bundle.Metadata.Name, Version: repoComp.Bundle.Metadata.Version,
			Scope: domain.PolicyScopeRepo, RepositoryID: &fx.repo.ID, Digest: repoComp.Digest, Definition: repoComp.Definition,
			ActivatedAt: &now, CreatedAt: now,
		}); err != nil {
			t.Fatalf("upsert repo bundle: %v", err)
		}
		if _, err := fx.pg.Pool().Exec(ctx, `UPDATE repositories SET allowed_model_routes = ARRAY['restricted-only-route'] WHERE id = $1`, fx.repo.ID); err != nil {
			t.Fatalf("restore route: %v", err)
		}

		// Inspector emits secret on EGRESS only (so ingress passes and egress tests ORG DENY vs REPO ALLOW).
		egressSecretInsp := &stubInspector{
			fn: func(ctx context.Context, req inspection.Request) (inspection.Report, error) {
				srID := domain.MustNewID()
				ts := time.Now().UTC().Truncate(time.Microsecond)
				runs := make([]domain.ScanRun, 0, len(inspection.MandatoryScanners))
				for _, sc := range inspection.MandatoryScanners {
					id := domain.MustNewID()
					if sc == inspection.ScannerGitleaks {
						id = srID
					}
					runs = append(runs, domain.ScanRun{
						ID: id, ProposalID: req.ProposalID, ArtifactID: req.ArtifactID,
						Scanner: string(sc), ScannerVersion: "1.0", Status: domain.ScanStatusCompleted,
						Coverage: domain.ScanCoverage{FilesExamined: 1, Complete: true}, StartedAt: ts, CompletedAt: &ts,
					})
				}
				if req.Stage == inspection.StageIngress {
					return inspection.Report{
						ProposalID: req.ProposalID, ArtifactID: req.ArtifactID, ScanRuns: runs,
						Summary: inspection.InspectionSummary{MandatoryScannersComplete: true, ScanComplete: true, CountsByCategory: map[string]int{}, CountsBySeverity: map[string]int{}, CountsByScanner: map[string]int{}, EvidenceIDs: []string{}, FailedScanners: []string{}, IncompleteScanners: []string{}},
					}, nil
				}
				return inspection.Report{
					ProposalID: req.ProposalID, ArtifactID: req.ArtifactID, ScanRuns: runs,
					Findings: []domain.Finding{{
						ID: domain.MustNewID(), ScanRunID: srID, EvidenceID: "ev-sec", Scanner: "gitleaks",
						Category: "SECRET", Severity: domain.SeverityCritical, RuleID: "aws", Path: ".env",
						Fingerprint: "fp-sec", Redacted: true, Message: "redacted",
					}},
					Summary: inspection.InspectionSummary{
						MandatoryScannersComplete: true, ScanComplete: true, CriticalSecrets: 1, TotalFindings: 1,
						CountsByCategory: map[string]int{"SECRET": 1}, CountsBySeverity: map[string]int{"CRITICAL": 1}, CountsByScanner: map[string]int{"gitleaks": 1},
						EvidenceIDs: []string{"ev-sec"}, FailedScanners: []string{}, IncompleteScanners: []string{},
					},
				}, nil
			},
		}
		_, denyRunner := newTestWorkflowRunner(t, fx, nil, egressSecretInsp, decSvc, workflow.Config{})
		sub2 := runIngressAndSubmit(ctx, t, fx, denyRunner, "restricted-only-route", map[string]string{"README.md": "ok\n"})
		for i := 0; i < 4; i++ {
			if n, _ := denyRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		p2, _ := propSvc.GetDetails(ctx, sub2.Proposal.ID)
		_, _ = propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{ProposalID: p2.ID, ExpectedVersion: p2.Version})
		for i := 0; i < 4; i++ {
			if n, _ := denyRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		p2After, _ := propSvc.GetDetails(ctx, p2.ID)
		if p2After.Status != domain.ProposalStatusDenied || p2After.LatestPolicyEffect == nil || *p2After.LatestPolicyEffect != domain.PolicyEffectDeny {
			t.Fatalf("expected ORG DENY over permissive REPO override, got status=%s effect=%v", p2After.Status, p2After.LatestPolicyEffect)
		}

		// 3. Gateway 503 outage retries and then fails closed to QUARANTINED when max_attempts=1.
		gwState.mu.Lock()
		gwState.statusCode = http.StatusServiceUnavailable
		gwState.mu.Unlock()

		_, cleanRunner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})
		sub3 := runIngressAndSubmit(ctx, t, fx, cleanRunner, "restricted-only-route", map[string]string{"README.md": "ok\n"})
		for i := 0; i < 4; i++ {
			if n, _ := cleanRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		p3, _ := propSvc.GetDetails(ctx, sub3.Proposal.ID)
		evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{ProposalID: p3.ID, ExpectedVersion: p3.Version})
		if err != nil {
			t.Fatalf("RequestEvaluation(p3): %v", err)
		}
		if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET max_attempts = 1 WHERE id = $1`, evalRes.Operation.ID); err != nil {
			t.Fatalf("set max_attempts=1: %v", err)
		}
		for i := 0; i < 4; i++ {
			if n, _ := cleanRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		p3After, _ := propSvc.GetDetails(ctx, p3.ID)
		if p3After.Status != domain.ProposalStatusQuarantined {
			t.Fatalf("expected QUARANTINED fail-closed on gateway 503 at max_attempts=1, got status=%s", p3After.Status)
		}

		// 4. Missing policy-mandatory scanner (trivy) fails closed to QUARANTINED even when gateway returns clean.
		gwState.mu.Lock()
		gwState.statusCode = 0
		gwState.mu.Unlock()
		sub4 := runIngressAndSubmit(ctx, t, fx, cleanRunner, "restricted-only-route", map[string]string{"README.md": "ok\n"})
		for i := 0; i < 4; i++ {
			if n, _ := cleanRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		strictYAML, err := os.ReadFile(filepath.Join(repoRoot, "policies", "examples", "repo_strict_security.yaml"))
		if err != nil {
			t.Fatalf("read repo_strict_security.yaml: %v", err)
		}
		strictComp, valErrs := pe.Compile(strictYAML)
		if len(valErrs) > 0 {
			t.Fatalf("Compile strict: %+v", valErrs)
		}
		if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name: strictComp.Bundle.Metadata.Name, Version: strictComp.Bundle.Metadata.Version,
			Scope: domain.PolicyScopeRepo, RepositoryID: &fx.repo.ID, Digest: strictComp.Digest, Definition: strictComp.Definition,
			ActivatedAt: &now, CreatedAt: now,
		}); err != nil {
			t.Fatalf("upsert strict repo bundle: %v", err)
		}
		// stubInspector only reports MandatoryScanners (no trivy), so trivy missing -> scan_complete=false -> QUARANTINED.
		p4, _ := propSvc.GetDetails(ctx, sub4.Proposal.ID)
		_, _ = propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{ProposalID: p4.ID, ExpectedVersion: p4.Version})
		for i := 0; i < 4; i++ {
			if n, _ := cleanRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		p4After, _ := propSvc.GetDetails(ctx, p4.ID)
		if p4After.Status != domain.ProposalStatusQuarantined {
			t.Fatalf("expected QUARANTINED when policy-mandatory trivy scanner is missing, got status=%s", p4After.Status)
		}
	})
}

func TestWorkflow_NeverClaimsPublish_ReapExpired_Outbox_Retention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	var dispatched atomic.Int64
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &bytes.Buffer{},
		Format:    observability.LogFormatJSON,
		Component: "workflow-test",
	})
	reconSvc, err := reconstruct.NewService(reconstruct.Config{
		GitReader:     fx.git.LocalReader(),
		SnapshotStore: fx.snaps.Store(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("reconstruct.NewService: %v", err)
	}
	wfCfg := workflow.Config{
		LeaseDuration:     15 * time.Second,
		RenewInterval:     5 * time.Second,
		PollInterval:      50 * time.Millisecond,
		ReapInterval:      50 * time.Millisecond,
		RetentionInterval: 50 * time.Millisecond,
	}
	svc, err := workflow.NewService(workflow.ServiceConfig{
		Store:            fx.store,
		SnapshotStore:    fx.snaps.Store(),
		GitReader:        fx.git.LocalReader(),
		Reconstructor:    reconSvc,
		InspectionRunner: &stubInspector{},
		OutboxDispatcher: workflow.OutboxDispatcherFunc(func(context.Context, persistence.OutboxEventRow) error {
			dispatched.Add(1)
			return nil
		}),
		Logger: logger,
		Config: wfCfg,
	})
	if err != nil {
		t.Fatalf("workflow.NewService: %v", err)
	}
	runner, err := workflow.NewRunner(workflow.RunnerConfig{Service: svc, Config: wfCfg})
	if err != nil {
		t.Fatalf("workflow.NewRunner: %v", err)
	}

	// 1. Enqueue a PROPOSAL_PUBLISH operation and confirm worker NEVER claims it.
	pubOpID := domain.MustNewID()
	pubResID := domain.MustNewID()
	if _, err := fx.store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		ID:            pubOpID,
		OperationType: domain.OperationTypeProposalPublish,
		ResourceType:  "proposal",
		ResourceID:    pubResID,
		MaxAttempts:   3,
	}); err != nil {
		t.Fatalf("EnqueueOperation(PROPOSAL_PUBLISH): %v", err)
	}
	for i := 0; i < 5; i++ {
		n, err := runner.ProcessOnce(ctx)
		if err != nil || n != 0 {
			t.Fatalf("expected ProcessOnce to claim 0 PROPOSAL_PUBLISH ops, got n=%d err=%v", n, err)
		}
	}
	pubOp, _ := fx.store.GetOperationByID(ctx, pubOpID)
	if pubOp.Status != domain.OperationStatusPending || pubOp.Attempts != 0 {
		t.Fatalf("PROPOSAL_PUBLISH was mutated by worker: %+v", pubOp)
	}

	// 2. Lease expiry reclaim (TestT4_S08-style: dead worker mid-lease with attempts < max_attempts) + ReapExpired when attempts >= max_attempts.
	wsSvc := workspaces.NewService(fx.store, nil, nil)
	ws1, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID,
		OwnerID:      fx.owner.ID,
		ModelRoute:   "approved-code-review",
		BaseCommit:   fx.bareRepo.HeadSHA,
		TargetRef:    "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("Create(ws1): %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='RUNNING', leased_by='dead-worker', lease_until = now() - interval '5 seconds', attempts=1 WHERE id=$1`, ws1.Operation.ID); err != nil {
		t.Fatalf("inject expired reclaimable lease: %v", err)
	}
	n, err := runner.ProcessOnce(ctx)
	if err != nil || n != 1 {
		t.Fatalf("expected reclaim ProcessOnce=1, got n=%d err=%v", n, err)
	}
	op1, _ := fx.store.GetOperationByID(ctx, ws1.Operation.ID)
	if op1.Status != domain.OperationStatusSucceeded || op1.Attempts != 2 {
		t.Fatalf("expected reclaimed SUCCEEDED attempts=2, got status=%s attempts=%d", op1.Status, op1.Attempts)
	}

	// Exhausted expired lease (attempts == max_attempts) must be reaped and workspace marked FAILED, while expired PROPOSAL_PUBLISH is ignored.
	ws2, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID,
		OwnerID:      fx.owner.ID,
		ModelRoute:   "approved-code-review",
		BaseCommit:   fx.bareRepo.HeadSHA,
		TargetRef:    "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("Create(ws2): %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='RUNNING', leased_by='dead-worker', lease_until = now() - interval '5 seconds', attempts=5, max_attempts=5 WHERE id=$1`, ws2.Operation.ID); err != nil {
		t.Fatalf("inject exhausted expired lease: %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='RUNNING', leased_by='dead-pub', lease_until = now() - interval '5 seconds', attempts=3, max_attempts=3 WHERE id=$1`, pubOpID); err != nil {
		t.Fatalf("inject expired pub lease: %v", err)
	}
	reapedCount, err := runner.ReapExpired(ctx)
	if err != nil || reapedCount != 1 {
		t.Fatalf("expected ReapExpired=1 (ignoring PROPOSAL_PUBLISH), got count=%d err=%v", reapedCount, err)
	}
	gotWS2, _ := wsSvc.Get(ctx, ws2.Workspace.ID)
	if gotWS2.Status != domain.WorkspaceStatusFailed {
		t.Fatalf("expected reaped workspace FAILED, got %s", gotWS2.Status)
	}

	// 3. Outbox delivery.
	delivered, err := runner.DispatchOutboxOnce(ctx)
	if err != nil || delivered == 0 || dispatched.Load() == 0 {
		t.Fatalf("expected DispatchOutboxOnce > 0, got %d (dispatched=%d) err=%v", delivered, dispatched.Load(), err)
	}
	var pendingOutbox int
	if err := fx.pg.Pool().QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE delivered_at IS NULL`).Scan(&pendingOutbox); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if pendingOutbox != 0 {
		t.Fatalf("expected 0 undelivered outbox_events, got %d", pendingOutbox)
	}

	// 4. Artifact retention reaper deletes expired artifacts only, preserving unexpired artifacts & audit chain.
	expData := []byte("expired-blob")
	expArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "retention/expired.tar.gz", expData)
	if err != nil {
		t.Fatalf("PutBytes(expired): %v", err)
	}
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: expArt.ID, Kind: domain.ArtifactKindWorkspaceSource, SHA256: expArt.SHA256,
		StorageKey: expArt.StorageKey, StorageGeneration: expArt.StorageGeneration,
		SizeBytes: expArt.SizeBytes, Format: "application/gzip", ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("RegisterArtifact(expired): %v", err)
	}

	freshData := []byte("fresh-blob")
	freshArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "retention/fresh.tar.gz", freshData)
	if err != nil {
		t.Fatalf("PutBytes(fresh): %v", err)
	}
	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	if _, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: freshArt.ID, Kind: domain.ArtifactKindWorkspaceSource, SHA256: freshArt.SHA256,
		StorageKey: freshArt.StorageKey, StorageGeneration: freshArt.StorageGeneration,
		SizeBytes: freshArt.SizeBytes, Format: "application/gzip", ExpiresAt: &future,
	}); err != nil {
		t.Fatalf("RegisterArtifact(fresh): %v", err)
	}

	reapedArts, err := runner.ReapExpiredArtifacts(ctx)
	if err != nil || reapedArts != 1 {
		t.Fatalf("expected ReapExpiredArtifacts=1, got %d err=%v", reapedArts, err)
	}
	gotExp, _ := fx.store.GetArtifactByID(ctx, expArt.ID)
	if gotExp.DeletedAt == nil {
		t.Fatalf("expected expired artifact deleted_at != nil")
	}
	if err := fx.snaps.Store().Verify(ctx, expArt); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected expired blob deleted from SnapshotStore, got err=%v", err)
	}
	gotFresh, _ := fx.store.GetArtifactByID(ctx, freshArt.ID)
	if gotFresh.DeletedAt != nil {
		t.Fatalf("expected fresh artifact preserved, got deleted_at=%v", gotFresh.DeletedAt)
	}
	if err := fx.snaps.Store().Verify(ctx, freshArt); err != nil {
		t.Fatalf("expected fresh blob intact in SnapshotStore, got %v", err)
	}
}

type failingDeleteSnapshotStore struct {
	inner       domain.SnapshotStore
	deleteCalls atomic.Int64
	deleteErr   error
}

func (f *failingDeleteSnapshotStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	return f.inner.Put(ctx, req, r, size)
}

func (f *failingDeleteSnapshotStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	return f.inner.Open(ctx, artifact)
}

func (f *failingDeleteSnapshotStore) Verify(ctx context.Context, artifact domain.Artifact) error {
	return f.inner.Verify(ctx, artifact)
}

func (f *failingDeleteSnapshotStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	f.deleteCalls.Add(1)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.inner.Delete(ctx, artifact)
}

func TestWorkflow_OrgPolicyNotSuppressedBySameNameVersionRepoBundle_AndWinningOrgID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	gwState := &mockGatewayState{}
	gwSrv := startMockGateway(t, gwState)
	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	decSvc, err := decisions.NewService(gwClient)
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}

	pe, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}

	// Upsert an extra active ORG bundle with a later ActivatedAt that matches 0 rules (placed first in orgRows)
	// to verify winningOrgID tracks the ORG bundle that actually matched (engineering-default).
	unmatchedOrgYAML := []byte(`
apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: org-noop-overlay
  version: "1.0.0"
  scope: ORG
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: org.noop.only_nonexistent_path
    stages: [EGRESS]
    when: change.paths.exists(p, p == "never/matched/path.txt")
    effect: REQUIRE_APPROVAL
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: security-team
        minimum: 1
`)
	unmatchedComp, valErrs := pe.Compile(unmatchedOrgYAML)
	if len(valErrs) > 0 {
		t.Fatalf("Compile unmatchedOrgYAML: %+v", valErrs)
	}
	later := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: unmatchedComp.Bundle.Metadata.Name, Version: unmatchedComp.Bundle.Metadata.Version,
		Scope: domain.PolicyScopeOrg, Digest: unmatchedComp.Digest, Definition: unmatchedComp.Definition,
		ActivatedAt: &later, CreatedAt: later,
	}); err != nil {
		t.Fatalf("upsert unmatched org bundle: %v", err)
	}

	// Upsert an active REPO bundle sharing the EXACT (name, version) "engineering-default@1.0.0"
	// with a permissive ALLOW rule (RG-06 bypass attempt).
	permissiveSameNameYAML := []byte(`
apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: engineering-default
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: repo.allow.all
    stages: [INGRESS, EGRESS]
    when: "true"
    effect: ALLOW
`)
	repoComp, valErrs := pe.Compile(permissiveSameNameYAML)
	if len(valErrs) > 0 {
		t.Fatalf("Compile permissiveSameNameYAML: %+v", valErrs)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	repoBundleRow, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: repoComp.Bundle.Metadata.Name, Version: repoComp.Bundle.Metadata.Version,
		Scope: domain.PolicyScopeRepo, RepositoryID: &fx.repo.ID, Digest: repoComp.Digest, Definition: repoComp.Definition,
		ActivatedAt: &now, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("upsert colliding repo bundle: %v", err)
	}

	// Emit a critical secret on EGRESS only so ingress succeeds and egress exercises ORG DENY vs colliding REPO ALLOW.
	egressSecretInsp := &stubInspector{
		fn: func(ctx context.Context, req inspection.Request) (inspection.Report, error) {
			srID := domain.MustNewID()
			ts := time.Now().UTC().Truncate(time.Microsecond)
			runs := make([]domain.ScanRun, 0, len(inspection.MandatoryScanners))
			for _, sc := range inspection.MandatoryScanners {
				id := domain.MustNewID()
				if sc == inspection.ScannerGitleaks {
					id = srID
				}
				runs = append(runs, domain.ScanRun{
					ID: id, ProposalID: req.ProposalID, ArtifactID: req.ArtifactID,
					Scanner: string(sc), ScannerVersion: "1.0.0", Status: domain.ScanStatusCompleted,
					Coverage: domain.ScanCoverage{FilesExamined: 1, Complete: true}, StartedAt: ts, CompletedAt: &ts,
				})
			}
			if req.Stage == inspection.StageIngress {
				return inspection.Report{
					ProposalID: req.ProposalID, ArtifactID: req.ArtifactID, ScanRuns: runs,
					Summary: inspection.InspectionSummary{MandatoryScannersComplete: true, ScanComplete: true, CountsByCategory: map[string]int{}, CountsBySeverity: map[string]int{}, CountsByScanner: map[string]int{}, EvidenceIDs: []string{}, FailedScanners: []string{}, IncompleteScanners: []string{}},
				}, nil
			}
			return inspection.Report{
				ProposalID: req.ProposalID, ArtifactID: req.ArtifactID, ScanRuns: runs,
				Findings: []domain.Finding{{
					ID: domain.MustNewID(), ScanRunID: srID, EvidenceID: "ev-rg06", Scanner: "gitleaks",
					Category: "SECRET", Severity: domain.SeverityCritical, RuleID: "aws-key", Path: ".env",
					Fingerprint: "fp-rg06", Redacted: true, Message: "redacted secret",
				}},
				Summary: inspection.InspectionSummary{
					MandatoryScannersComplete: true, ScanComplete: true, CriticalSecrets: 1, TotalFindings: 1,
					CountsByCategory: map[string]int{"SECRET": 1}, CountsBySeverity: map[string]int{"CRITICAL": 1}, CountsByScanner: map[string]int{"gitleaks": 1},
					EvidenceIDs: []string{"ev-rg06"}, FailedScanners: []string{}, IncompleteScanners: []string{},
				},
			}, nil
		},
	}

	_, runner := newTestWorkflowRunner(t, fx, nil, egressSecretInsp, decSvc, workflow.Config{})

	wsSvc := workspaces.NewService(fx.store, nil, nil)
	wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID,
		OwnerID:      fx.owner.ID,
		ModelRoute:   "approved-code-review",
		BaseCommit:   fx.bareRepo.HeadSHA,
		TargetRef:    "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create: %v", err)
	}
	for i := 0; i < 4; i++ {
		if n, pErr := runner.ProcessOnce(ctx); pErr != nil || n == 0 {
			if pErr != nil {
				t.Fatalf("ProcessOnce(ingress): %v", pErr)
			}
			break
		}
	}

	tarBytes := buildTarGzBytes(t, map[string]string{"README.md": "ok\n", ".env": "SECRET=redacted\n"})
	putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "uploads/rg06.tar.gz", tarBytes)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	gen := int64(1)
	regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
		StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
		Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact: %v", err)
	}

	propSvc := proposals.NewService(fx.store, nil, nil)
	sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
		SizeBytes: int64(len(tarBytes)), Title: "RG-06 Collision Test",
	})
	if err != nil {
		t.Fatalf("proposals.Submit: %v", err)
	}
	for i := 0; i < 4; i++ {
		if n, _ := runner.ProcessOnce(ctx); n == 0 {
			break
		}
	}
	afterRecon, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	if _, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: afterRecon.ID, ExpectedVersion: afterRecon.Version,
	}); err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}
	for i := 0; i < 4; i++ {
		if n, _ := runner.ProcessOnce(ctx); n == 0 {
			break
		}
	}

	afterEval, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails(after eval): %v", err)
	}
	if afterEval.Status != domain.ProposalStatusDenied || afterEval.LatestPolicyEffect == nil || *afterEval.LatestPolicyEffect != domain.PolicyEffectDeny {
		t.Fatalf("RG-06 bypass: expected DENIED despite colliding REPO bundle engineering-default@1.0.0, got status=%s effect=%v", afterEval.Status, afterEval.LatestPolicyEffect)
	}

	pd, err := fx.store.GetLatestPolicyDecisionForProposal(ctx, afterEval.ID)
	if err != nil {
		t.Fatalf("GetLatestPolicyDecisionForProposal: %v", err)
	}
	if pd.OrgBundleID == nil || *pd.OrgBundleID != fx.policyID {
		t.Fatalf("expected winningOrgID=%s (engineering-default), got %v", fx.policyID, pd.OrgBundleID)
	}
	if pd.RepoBundleID == nil || *pd.RepoBundleID != repoBundleRow.ID {
		t.Fatalf("expected repoBundleID=%s, got %v", repoBundleRow.ID, pd.RepoBundleID)
	}
}

func TestWorkflow_ReapExpired_ScopedAndDefensiveReconciliation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	_, runner := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{})

	wsSvc := workspaces.NewService(fx.store, nil, nil)
	wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
		BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create: %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(ingress): n=%d err=%v", n, err)
	}

	// Create proposal in EVALUATING with an expired PROPOSAL_EVALUATE operation.
	tarBytes := buildTarGzBytes(t, map[string]string{"README.md": "ok\n"})
	putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "uploads/reap-eval.tar.gz", tarBytes)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	gen := int64(1)
	regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
		StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
		Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact: %v", err)
	}
	propSvc := proposals.NewService(fx.store, nil, nil)
	sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
		SizeBytes: int64(len(tarBytes)), Title: "Reap Evaluate Proposal",
	})
	if err != nil {
		t.Fatalf("proposals.Submit: %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(reconstruct): n=%d err=%v", n, err)
	}
	reconProp, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: reconProp.ID, ExpectedVersion: reconProp.Version,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}

	// Also enqueue an expired PROPOSAL_PUBLISH operation.
	pubOpID := domain.MustNewID()
	if _, err := fx.store.EnqueueOperation(ctx, persistence.EnqueueOperationParams{
		ID: pubOpID, OperationType: domain.OperationTypeProposalPublish,
		ResourceType: "proposal", ResourceID: domain.MustNewID(), MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("EnqueueOperation(PROPOSAL_PUBLISH): %v", err)
	}

	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='RUNNING', leased_by='dead-worker', lease_until = now() - interval '5 seconds', attempts=5, max_attempts=5 WHERE id=$1`, evalRes.Operation.ID); err != nil {
		t.Fatalf("expire eval op: %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='RUNNING', leased_by='dead-pub', lease_until = now() - interval '5 seconds', attempts=3, max_attempts=3 WHERE id=$1`, pubOpID); err != nil {
		t.Fatalf("expire pub op: %v", err)
	}

	reapedCount, err := runner.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired: %v", err)
	}
	if reapedCount != 1 {
		t.Fatalf("expected ReapExpired=1 (eval only, never publish), got %d", reapedCount)
	}

	evalOpAfter, _ := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
	if evalOpAfter.Status != domain.OperationStatusFailed {
		t.Fatalf("expected PROPOSAL_EVALUATE FAILED, got %s", evalOpAfter.Status)
	}
	evalPropAfter, _ := propSvc.Get(ctx, sub.Proposal.ID)
	if evalPropAfter.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected evaluated proposal FAILED, got %s", evalPropAfter.Status)
	}
	pubOpAfter, _ := fx.store.GetOperationByID(ctx, pubOpID)
	if pubOpAfter.Status != domain.OperationStatusRunning {
		t.Fatalf("PROPOSAL_PUBLISH MUST remain RUNNING untouched by worker ReapExpired, got %s", pubOpAfter.Status)
	}

	// Defensive cross-daemon reconciliation: simulate operations already marked FAILED (e.g. by publisher's reaper)
	// while workspace is PREPARING and proposals are RECONSTRUCTING / EVALUATING.
	stuckWS, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
		BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("Create(stuckWS): %v", err)
	}
	if _, err := wsSvc.TransitionStatus(ctx, stuckWS.Workspace.ID, domain.WorkspaceStatusPending, domain.WorkspaceStatusPreparing); err != nil {
		t.Fatalf("TransitionStatus(PREPARING): %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='FAILED', lease_until=NULL, leased_by=NULL, last_error='lease expired after max attempts', completed_at=now() WHERE id=$1`, stuckWS.Operation.ID); err != nil {
		t.Fatalf("mark stuckWS op FAILED: %v", err)
	}

	subRecon, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
		SizeBytes: int64(len(tarBytes)), Title: "Stuck Reconstruct Proposal",
	})
	if err != nil {
		t.Fatalf("Submit(subRecon): %v", err)
	}
	if _, err := propSvc.BeginReconstruction(ctx, proposals.BeginReconstructionInput{
		ProposalID: subRecon.Proposal.ID, ExpectedVersion: subRecon.Proposal.Version,
	}); err != nil {
		t.Fatalf("BeginReconstruction: %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='FAILED', lease_until=NULL, leased_by=NULL, last_error='lease expired after max attempts', completed_at=now() WHERE id=$1`, subRecon.Operation.ID); err != nil {
		t.Fatalf("mark subRecon op FAILED: %v", err)
	}

	// Also create an EVALUATING proposal whose PROPOSAL_EVALUATE op is already FAILED.
	subEvalStuck, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
		SizeBytes: int64(len(tarBytes)), Title: "Stuck Evaluate Proposal",
	})
	if err != nil {
		t.Fatalf("Submit(subEvalStuck): %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(reconstruct subEvalStuck): n=%d err=%v", n, err)
	}
	detEvalStuck, err := propSvc.GetDetails(ctx, subEvalStuck.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails(subEvalStuck): %v", err)
	}
	evalStuckRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: detEvalStuck.ID, ExpectedVersion: detEvalStuck.Version,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation(subEvalStuck): %v", err)
	}
	if _, err := fx.pg.Pool().Exec(ctx, `UPDATE operations SET status='FAILED', lease_until=NULL, leased_by=NULL, last_error='lease expired after max attempts', completed_at=now() WHERE id=$1`, evalStuckRes.Operation.ID); err != nil {
		t.Fatalf("mark evalStuck op FAILED: %v", err)
	}

	reconciledCount, err := runner.ReapExpired(ctx)
	if err != nil {
		t.Fatalf("ReapExpired(defensive): %v", err)
	}
	if reconciledCount != 3 {
		t.Fatalf("expected 3 reconciled stuck resources (PREPARING ws + RECONSTRUCTING + EVALUATING proposals), got %d", reconciledCount)
	}
	gotStuckWS, _ := wsSvc.Get(ctx, stuckWS.Workspace.ID)
	if gotStuckWS.Status != domain.WorkspaceStatusFailed {
		t.Fatalf("expected reconciled workspace FAILED, got %s", gotStuckWS.Status)
	}
	gotStuckProp, _ := propSvc.Get(ctx, subRecon.Proposal.ID)
	if gotStuckProp.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected reconciled reconstructing proposal FAILED, got %s", gotStuckProp.Status)
	}
	gotStuckEvalProp, _ := propSvc.Get(ctx, subEvalStuck.Proposal.ID)
	if gotStuckEvalProp.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected reconciled evaluating proposal FAILED, got %s", gotStuckEvalProp.Status)
	}

	// Idempotent second call must find 0.
	againCount, err := runner.ReapExpired(ctx)
	if err != nil || againCount != 0 {
		t.Fatalf("expected idempotent 0 on second ReapExpired, got count=%d err=%v", againCount, err)
	}
}

func TestWorkflow_LeaseFencing_FailBeforeTerminalState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	wsSvc := workspaces.NewService(fx.store, nil, nil)
	wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
		BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create: %v", err)
	}

	// During ExecuteIngress, steal the operation lease in PostgreSQL before returning a non-retryable error.
	stealingGit := &failingGitReader{
		inner: fx.git.LocalReader(),
	}
	var stolen atomic.Bool
	// Wrap via a custom gitReader that executes SQL lease steal on Checkout.
	leaseStealReader := &hookGitReader{
		resolveFn: stealingGit.ResolveRef,
		checkoutFn: func(c context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error) {
			if stolen.CompareAndSwap(false, true) {
				if _, execErr := fx.pg.Pool().Exec(context.Background(),
					`UPDATE operations SET leased_by = 'new-active-worker', lease_until = now() + interval '30 seconds' WHERE id = $1`,
					wsRes.Operation.ID,
				); execErr != nil {
					return domain.CheckoutResult{}, execErr
				}
			}
			// Return non-retryable error (ErrUnprocessable -> isFinal = true).
			return domain.CheckoutResult{}, domain.Unprocessable("CORRUPT_CHECKOUT", "non-retryable failure after lease stolen")
		},
	}

	_, runner := newTestWorkflowRunner(t, fx, leaseStealReader, nil, nil, workflow.Config{
		WorkerID:      "stale-worker",
		LeaseDuration: 15 * time.Second,
		RenewInterval: 1 * time.Minute, // prevent background renew from cancelling attemptCtx before ops.Fail runs
	})

	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce: n=%d err=%v", n, err)
	}

	// Because ops.Fail rejected with ErrConflict/LEASE_LOST, handleTerminalFailure MUST NOT have run!
	wsAfter, err := wsSvc.Get(ctx, wsRes.Workspace.ID)
	if err != nil {
		t.Fatalf("ws.Get: %v", err)
	}
	if wsAfter.Status != domain.WorkspaceStatusPreparing {
		t.Fatalf("lease fencing violation: stale worker mutated workspace status to %s (expected PREPARING)", wsAfter.Status)
	}
	opAfter, _ := fx.store.GetOperationByID(ctx, wsRes.Operation.ID)
	if opAfter.Status != domain.OperationStatusRunning || derefStr(opAfter.LeasedBy) != "new-active-worker" {
		t.Fatalf("expected operation still RUNNING by new-active-worker, got status=%s leased_by=%q", opAfter.Status, derefStr(opAfter.LeasedBy))
	}

	// Also verify proposal lease fencing on PROPOSAL_EVALUATE.
	ws2, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
		BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create(ws2): %v", err)
	}
	_, cleanRunner := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{})
	if n, err := cleanRunner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(ws2 ingress): n=%d err=%v", n, err)
	}
	tarBytes := buildTarGzBytes(t, map[string]string{"README.md": "ok\n"})
	putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "uploads/lease-fence-eval.tar.gz", tarBytes)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	gen := int64(1)
	regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
		StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
		Format: "application/gzip", WorkspaceID: &ws2.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact: %v", err)
	}
	propSvc := proposals.NewService(fx.store, nil, nil)
	sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: ws2.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
		SizeBytes: int64(len(tarBytes)), Title: "Lease Fence Eval",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if n, err := cleanRunner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(reconstruct): n=%d err=%v", n, err)
	}
	det, _ := propSvc.GetDetails(ctx, sub.Proposal.ID)
	evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: det.ID, ExpectedVersion: det.Version,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}
	var evalStolen atomic.Bool
	stealingInsp := &stubInspector{
		fn: func(c context.Context, req inspection.Request) (inspection.Report, error) {
			if evalStolen.CompareAndSwap(false, true) {
				if _, execErr := fx.pg.Pool().Exec(context.Background(),
					`UPDATE operations SET leased_by = 'new-eval-worker', lease_until = now() + interval '30 seconds' WHERE id = $1`,
					evalRes.Operation.ID,
				); execErr != nil {
					return inspection.Report{}, execErr
				}
			}
			return inspection.Report{}, domain.Unprocessable("BAD_EVAL", "non-retryable failure after eval lease stolen")
		},
	}
	gwSrv := startMockGateway(t, &mockGatewayState{})
	gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
	decSvc, _ := decisions.NewService(gwClient)
	_, staleEvalRunner := newTestWorkflowRunner(t, fx, nil, stealingInsp, decSvc, workflow.Config{
		WorkerID:      "stale-eval-worker",
		LeaseDuration: 15 * time.Second,
		RenewInterval: 1 * time.Minute,
	})
	if n, err := staleEvalRunner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(stale eval): n=%d err=%v", n, err)
	}
	propAfter, _ := propSvc.Get(ctx, sub.Proposal.ID)
	if propAfter.Status != domain.ProposalStatusEvaluating {
		t.Fatalf("lease fencing violation: stale worker mutated proposal status to %s (expected EVALUATING)", propAfter.Status)
	}
	evalOpAfter, _ := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
	if evalOpAfter.Status != domain.OperationStatusRunning || derefStr(evalOpAfter.LeasedBy) != "new-eval-worker" {
		t.Fatalf("expected eval op still RUNNING by new-eval-worker, got status=%s leased_by=%q", evalOpAfter.Status, derefStr(evalOpAfter.LeasedBy))
	}
}

type hookGitReader struct {
	resolveFn  func(ctx context.Context, repo domain.Repository, ref string) (string, error)
	checkoutFn func(ctx context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error)
}

func (h *hookGitReader) ResolveRef(ctx context.Context, repo domain.Repository, ref string) (string, error) {
	return h.resolveFn(ctx, repo, ref)
}

func (h *hookGitReader) Checkout(ctx context.Context, repo domain.Repository, commitSHA string, opts domain.CheckoutOptions) (domain.CheckoutResult, error) {
	return h.checkoutFn(ctx, repo, commitSHA, opts)
}

func TestWorkflow_Evaluate_FailClosedManifest_ScanRunRemap_And_NilInspector(t *testing.T) {
	// 1. ExecuteIngress fails closed with INSPECTOR_UNAVAILABLE when s.inspector == nil.
	t.Run("nil inspector fails closed on ingress", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		reconSvc, _ := reconstruct.NewService(reconstruct.Config{
			GitReader: fx.git.LocalReader(), SnapshotStore: fx.snaps.Store(),
		})
		svc, err := workflow.NewService(workflow.ServiceConfig{
			Store:         fx.store,
			SnapshotStore: fx.snaps.Store(),
			GitReader:     fx.git.LocalReader(),
			Reconstructor: reconSvc,
		})
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}
		_, ingErr := svc.ExecuteIngress(ctx, operations.OperationDetails{Operation: wsRes.Operation.Operation})
		var domErr *domain.DomainError
		if !errors.As(ingErr, &domErr) || domErr.Code() != "INSPECTOR_UNAVAILABLE" {
			t.Fatalf("expected INSPECTOR_UNAVAILABLE, got %v", ingErr)
		}
	})

	// Helper to create a reconstructed proposal ready for ExecuteEvaluate.
	setupReconstructedProposal := func(ctx context.Context, t *testing.T, fx *pgTestFixture, runner *workflow.Runner) proposals.ProposalDetails {
		t.Helper()
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}
		for i := 0; i < 4; i++ {
			if n, _ := runner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		tarBytes := buildTarGzBytes(t, map[string]string{"README.md": "ok\n", "infra/prod/main.tf": "resource {}\n"})
		putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, fmt.Sprintf("uploads/%s.tar.gz", domain.MustNewID()), tarBytes)
		if err != nil {
			t.Fatalf("PutBytes: %v", err)
		}
		gen := int64(1)
		regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
			ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
			StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
			Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
		})
		if err != nil {
			t.Fatalf("RegisterArtifact: %v", err)
		}
		propSvc := proposals.NewService(fx.store, nil, nil)
		sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
			WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
			SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
			SizeBytes: int64(len(tarBytes)), Title: "Manifest Fail-Closed Test",
		})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		for i := 0; i < 4; i++ {
			if n, _ := runner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		det, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
		if err != nil {
			t.Fatalf("GetDetails: %v", err)
		}
		return det
	}

	// 2. Corrupted PUBLICATION_MANIFEST JSON fails closed (FAILED) instead of evaluating with empty change.paths.
	t.Run("corrupted manifest JSON fails closed", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		gwSrv := startMockGateway(t, &mockGatewayState{})
		gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
		decSvc, _ := decisions.NewService(gwClient)
		_, runner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})

		det := setupReconstructedProposal(ctx, t, fx, runner)
		manArt, err := fx.store.GetArtifactByID(ctx, *det.ManifestArtifactID)
		if err != nil {
			t.Fatalf("GetArtifactByID(manifest): %v", err)
		}
		corruptJSON := []byte("{corrupted-json")
		if err := fx.snaps.CorruptBlob(manArt.StorageKey, corruptJSON); err != nil {
			t.Fatalf("CorruptBlob: %v", err)
		}
		if _, err := fx.pg.Pool().Exec(ctx,
			`UPDATE artifacts SET sha256 = $1, size_bytes = $2 WHERE id = $3`,
			domain.SHA256Hex(corruptJSON), int64(len(corruptJSON)), manArt.ID,
		); err != nil {
			t.Fatalf("update manifest artifact digest/size: %v", err)
		}

		propSvc := proposals.NewService(fx.store, nil, nil)
		evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
			ProposalID: det.ID, ExpectedVersion: det.Version,
		})
		if err != nil {
			t.Fatalf("RequestEvaluation: %v", err)
		}
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(evaluate): n=%d err=%v", n, err)
		}
		opAfter, _ := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
		if opAfter.Status != domain.OperationStatusFailed || !strings.Contains(derefStr(opAfter.LastError), "INVALID_PUBLICATION_MANIFEST") {
			t.Fatalf("expected FAILED op with INVALID_PUBLICATION_MANIFEST, got status=%s last_error=%q", opAfter.Status, derefStr(opAfter.LastError))
		}
		propAfter, _ := propSvc.Get(ctx, det.ID)
		if propAfter.Status != domain.ProposalStatusFailed {
			t.Fatalf("expected proposal FAILED on corrupt manifest, got %s", propAfter.Status)
		}
	})

	// 3. Deleted PUBLICATION_MANIFEST artifact fails closed (ARTIFACT_DELETED).
	t.Run("deleted manifest artifact fails closed", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		gwSrv := startMockGateway(t, &mockGatewayState{})
		gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
		decSvc, _ := decisions.NewService(gwClient)
		_, runner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})

		det := setupReconstructedProposal(ctx, t, fx, runner)
		if _, err := fx.store.MarkArtifactDeleted(ctx, *det.ManifestArtifactID, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
			t.Fatalf("MarkArtifactDeleted: %v", err)
		}

		propSvc := proposals.NewService(fx.store, nil, nil)
		evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
			ProposalID: det.ID, ExpectedVersion: det.Version,
		})
		if err != nil {
			t.Fatalf("RequestEvaluation: %v", err)
		}
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(evaluate): n=%d err=%v", n, err)
		}
		opAfter, _ := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
		if opAfter.Status != domain.OperationStatusFailed || !strings.Contains(derefStr(opAfter.LastError), "ARTIFACT_DELETED") {
			t.Fatalf("expected FAILED op with ARTIFACT_DELETED, got status=%s last_error=%q", opAfter.Status, derefStr(opAfter.LastError))
		}
		propAfter, _ := propSvc.Get(ctx, det.ID)
		if propAfter.Status != domain.ProposalStatusFailed {
			t.Fatalf("expected proposal FAILED on deleted manifest, got %s", propAfter.Status)
		}
	})

	// 4. Non-UUIDv7 ScanRun.ID is remapped on Finding.ScanRunID during persistInspectionReport.
	t.Run("non-UUIDv7 ScanRun ID remapped on findings", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		gwSrv := startMockGateway(t, &mockGatewayState{})
		gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
		decSvc, _ := decisions.NewService(gwClient)

		v4RunID := uuid.New() // intentionally UUIDv4 (non-UUIDv7)
		remapInsp := &stubInspector{
			fn: func(ctx context.Context, req inspection.Request) (inspection.Report, error) {
				ts := time.Now().UTC().Truncate(time.Microsecond)
				runs := make([]domain.ScanRun, 0, len(inspection.MandatoryScanners))
				for _, sc := range inspection.MandatoryScanners {
					id := domain.MustNewID()
					if sc == inspection.ScannerSemgrep {
						id = v4RunID
					}
					runs = append(runs, domain.ScanRun{
						ID: id, ProposalID: req.ProposalID, ArtifactID: req.ArtifactID,
						Scanner: string(sc), ScannerVersion: "1.0.0", Status: domain.ScanStatusCompleted,
						Coverage: domain.ScanCoverage{FilesExamined: 1, Complete: true}, StartedAt: ts, CompletedAt: &ts,
					})
				}
				if req.Stage == inspection.StageIngress {
					return inspection.Report{
						ProposalID: req.ProposalID, ArtifactID: req.ArtifactID, ScanRuns: runs,
						Summary: inspection.InspectionSummary{MandatoryScannersComplete: true, ScanComplete: true, CountsByCategory: map[string]int{}, CountsBySeverity: map[string]int{}, CountsByScanner: map[string]int{}, EvidenceIDs: []string{}, FailedScanners: []string{}, IncompleteScanners: []string{}},
					}, nil
				}
				return inspection.Report{
					ProposalID: req.ProposalID, ArtifactID: req.ArtifactID, ScanRuns: runs,
					Findings: []domain.Finding{{
						ID: uuid.New(), ScanRunID: v4RunID, EvidenceID: "ev-remap", Scanner: "semgrep",
						Category: "SAST", Severity: domain.SeverityLow, RuleID: "info-rule", Path: "README.md",
						Fingerprint: "fp-remap", Redacted: true, Message: "low info finding",
					}},
					Summary: inspection.InspectionSummary{
						MandatoryScannersComplete: true, ScanComplete: true, TotalFindings: 1,
						CountsByCategory: map[string]int{"SAST": 1}, CountsBySeverity: map[string]int{"LOW": 1}, CountsByScanner: map[string]int{"semgrep": 1},
						EvidenceIDs: []string{"ev-remap"}, FailedScanners: []string{}, IncompleteScanners: []string{},
					},
				}, nil
			},
		}

		_, runner := newTestWorkflowRunner(t, fx, nil, remapInsp, decSvc, workflow.Config{})
		det := setupReconstructedProposal(ctx, t, fx, runner)
		propSvc := proposals.NewService(fx.store, nil, nil)
		if _, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
			ProposalID: det.ID, ExpectedVersion: det.Version,
		}); err != nil {
			t.Fatalf("RequestEvaluation: %v", err)
		}
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(evaluate): n=%d err=%v", n, err)
		}
		afterEval, _ := propSvc.GetDetails(ctx, det.ID)
		if afterEval.Status != domain.ProposalStatusPendingApproval {
			t.Fatalf("expected PENDING_APPROVAL after ScanRun ID remap, got %s", afterEval.Status)
		}
		findingsRes, err := propSvc.ListFindings(ctx, proposals.ListFindingsFilter{ProposalID: det.ID, Limit: 10})
		if err != nil || len(findingsRes.Findings) != 1 {
			t.Fatalf("expected 1 persisted finding, got len=%d err=%v", len(findingsRes.Findings), err)
		}
		if !domain.IsUUIDv7(findingsRes.Findings[0].ScanRunID) || findingsRes.Findings[0].ScanRunID == v4RunID {
			t.Fatalf("expected finding ScanRunID remapped to UUIDv7, got %s", findingsRes.Findings[0].ScanRunID)
		}
	})

	// 5. >16 MiB tail-tampered CANONICAL_DIFF fails terminally on attempt 1 with DIGEST_MISMATCH.
	t.Run("oversized tampered CANONICAL_DIFF fails closed terminally with DIGEST_MISMATCH", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		gwState := &mockGatewayState{}
		gwSrv := startMockGateway(t, gwState)
		gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
		decSvc, _ := decisions.NewService(gwClient)
		_, runner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})

		det := setupReconstructedProposal(ctx, t, fx, runner)
		if det.DiffArtifactID == nil || *det.DiffArtifactID == uuid.Nil {
			t.Fatalf("expected non-nil diff_artifact_id on reconstructed proposal")
		}

		oversized := bytes.Repeat([]byte("diff-line-payload-0123456789abcdef\n"), ((16<<20)+4096)/35+1)
		oversized = oversized[:(16<<20)+4096]
		putDiff, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindCanonicalDiff, fmt.Sprintf("canonical/%s-oversized-tampered.diff", det.ID), oversized)
		if err != nil {
			t.Fatalf("PutBytes(oversized diff): %v", err)
		}
		if _, err := fx.pg.Pool().Exec(ctx,
			`UPDATE artifacts SET storage_key = $1, storage_generation = $2, sha256 = $3, size_bytes = $4 WHERE id = $5`,
			putDiff.StorageKey, putDiff.StorageGeneration, putDiff.SHA256, putDiff.SizeBytes, *det.DiffArtifactID,
		); err != nil {
			t.Fatalf("UPDATE artifacts(oversized tampered diff): %v", err)
		}

		tampered := append([]byte(nil), oversized...)
		copy(tampered[len(tampered)-16:], "TAMPERED_TAIL_XX")
		if err := fx.snaps.CorruptBlob(putDiff.StorageKey, tampered); err != nil {
			t.Fatalf("CorruptBlob(oversized diff): %v", err)
		}

		propSvc := proposals.NewService(fx.store, nil, nil)
		evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
			ProposalID: det.ID, ExpectedVersion: det.Version,
		})
		if err != nil {
			t.Fatalf("RequestEvaluation: %v", err)
		}
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(evaluate): n=%d err=%v", n, err)
		}

		opAfter, err := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
		if err != nil {
			t.Fatalf("GetOperationByID: %v", err)
		}
		if opAfter.Status != domain.OperationStatusFailed {
			t.Fatalf("expected terminal FAILED op on attempt 1, got %s (last_error=%q)", opAfter.Status, derefStr(opAfter.LastError))
		}
		if opAfter.Attempts != 1 {
			t.Fatalf("expected non-retryable terminal failure on attempt 1, got attempts=%d", opAfter.Attempts)
		}
		if !strings.Contains(derefStr(opAfter.LastError), "DIGEST_MISMATCH") {
			t.Fatalf("expected DIGEST_MISMATCH in op last_error, got %q", derefStr(opAfter.LastError))
		}
		propAfter, err := propSvc.Get(ctx, det.ID)
		if err != nil {
			t.Fatalf("prop.Get: %v", err)
		}
		if propAfter.Status != domain.ProposalStatusFailed {
			t.Fatalf("expected proposal FAILED on tampered >16 MiB diff, got %s", propAfter.Status)
		}
		gwState.mu.Lock()
		gwCalls := len(gwState.requests)
		gwState.mu.Unlock()
		if gwCalls != 0 {
			t.Fatalf("expected 0 gateway calls on tampered diff, got %d", gwCalls)
		}
	})

	// 6. >16 MiB valid CANONICAL_DIFF verifies full stream to EOF and succeeds.
	t.Run("oversized valid CANONICAL_DIFF verifies full stream and succeeds", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		gwState := &mockGatewayState{}
		gwSrv := startMockGateway(t, gwState)
		gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
		decSvc, _ := decisions.NewService(gwClient)
		_, runner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})

		det := setupReconstructedProposal(ctx, t, fx, runner)
		if det.DiffArtifactID == nil || *det.DiffArtifactID == uuid.Nil {
			t.Fatalf("expected non-nil diff_artifact_id on reconstructed proposal")
		}

		oversized := bytes.Repeat([]byte("diff-line-payload-0123456789abcdef\n"), ((16<<20)+4096)/35+1)
		oversized = oversized[:(16<<20)+4096]
		putDiff, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindCanonicalDiff, fmt.Sprintf("canonical/%s-oversized-valid.diff", det.ID), oversized)
		if err != nil {
			t.Fatalf("PutBytes(oversized valid diff): %v", err)
		}
		if _, err := fx.pg.Pool().Exec(ctx,
			`UPDATE artifacts SET storage_key = $1, storage_generation = $2, sha256 = $3, size_bytes = $4 WHERE id = $5`,
			putDiff.StorageKey, putDiff.StorageGeneration, putDiff.SHA256, putDiff.SizeBytes, *det.DiffArtifactID,
		); err != nil {
			t.Fatalf("UPDATE artifacts(oversized valid diff): %v", err)
		}

		propSvc := proposals.NewService(fx.store, nil, nil)
		evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
			ProposalID: det.ID, ExpectedVersion: det.Version,
		})
		if err != nil {
			t.Fatalf("RequestEvaluation: %v", err)
		}
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(evaluate): n=%d err=%v", n, err)
		}

		opAfter, err := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
		if err != nil {
			t.Fatalf("GetOperationByID: %v", err)
		}
		if opAfter.Status != domain.OperationStatusSucceeded {
			t.Fatalf("expected SUCCEEDED op on valid >16 MiB diff, got %s (last_error=%q)", opAfter.Status, derefStr(opAfter.LastError))
		}
		propAfter, err := propSvc.Get(ctx, det.ID)
		if err != nil {
			t.Fatalf("prop.Get: %v", err)
		}
		if propAfter.Status != domain.ProposalStatusPendingApproval {
			t.Fatalf("expected proposal PENDING_APPROVAL on valid >16 MiB diff, got %s", propAfter.Status)
		}
		gwState.mu.Lock()
		defer gwState.mu.Unlock()
		if len(gwState.requests) != 1 {
			t.Fatalf("expected 1 gateway call, got %d", len(gwState.requests))
		}
		foundTruncated := false
		for _, m := range gwState.requests[0].Messages {
			if strings.Contains(m.Content, `"diff_truncated":true`) {
				foundTruncated = true
				break
			}
		}
		if !foundTruncated {
			t.Fatalf("expected gateway prompt message to include \"diff_truncated\":true")
		}
	})
}

func TestWorkflow_ReapExpiredArtifacts_TightLoopGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	failStore := &failingDeleteSnapshotStore{
		inner:     fx.snaps.Store(),
		deleteErr: domain.Unavailable("STORAGE_DOWN", "simulated snapshot store outage"),
	}
	reconSvc, err := reconstruct.NewService(reconstruct.Config{
		GitReader:     fx.git.LocalReader(),
		SnapshotStore: fx.snaps.Store(),
	})
	if err != nil {
		t.Fatalf("reconstruct.NewService: %v", err)
	}
	wfCfg := workflow.Config{
		RetentionBatchSize: 2,
	}
	svc, err := workflow.NewService(workflow.ServiceConfig{
		Store:            fx.store,
		SnapshotStore:    failStore,
		GitReader:        fx.git.LocalReader(),
		Reconstructor:    reconSvc,
		InspectionRunner: &stubInspector{},
		Config:           wfCfg,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	runner, err := workflow.NewRunner(workflow.RunnerConfig{Service: svc, Config: wfCfg})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for i := 0; i < 2; i++ {
		art, putErr := fx.snaps.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, fmt.Sprintf("retention/fail-%d.tar.gz", i), []byte("blob"))
		if putErr != nil {
			t.Fatalf("PutBytes(%d): %v", i, putErr)
		}
		if _, regErr := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
			ID: art.ID, Kind: domain.ArtifactKindWorkspaceSource, SHA256: art.SHA256,
			StorageKey: art.StorageKey, StorageGeneration: art.StorageGeneration,
			SizeBytes: art.SizeBytes, Format: "application/gzip", ExpiresAt: &past,
		}); regErr != nil {
			t.Fatalf("RegisterArtifact(%d): %v", i, regErr)
		}
	}

	reaped, err := runner.ReapExpiredArtifacts(ctx)
	if err != nil {
		t.Fatalf("ReapExpiredArtifacts: %v", err)
	}
	if reaped != 0 {
		t.Fatalf("expected 0 reaped on failing SnapshotStore.Delete, got %d", reaped)
	}
	if gotCalls := failStore.deleteCalls.Load(); gotCalls != 2 {
		t.Fatalf("expected exactly 2 Delete calls (1 batch pass, no tight loop), got %d", gotCalls)
	}
}

func mustJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type hookSnapshotStore struct {
	inner domain.SnapshotStore
	putFn func(ctx context.Context, req domain.PutRequest, art domain.Artifact) error
}

func (h *hookSnapshotStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	art, err := h.inner.Put(ctx, req, r, size)
	if err != nil {
		return art, err
	}
	if h.putFn != nil {
		if hookErr := h.putFn(ctx, req, art); hookErr != nil {
			return art, hookErr
		}
	}
	return art, nil
}

func (h *hookSnapshotStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	return h.inner.Open(ctx, artifact)
}

func (h *hookSnapshotStore) Verify(ctx context.Context, artifact domain.Artifact) error {
	return h.inner.Verify(ctx, artifact)
}

func (h *hookSnapshotStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	return h.inner.Delete(ctx, artifact)
}

type hookReconstructor struct {
	inner workflow.Reconstructor
	fn    func(ctx context.Context, repo domain.Repository, baseCommit string, snapshot domain.Artifact, res reconstruct.Result) error
}

func (h *hookReconstructor) ReconstructDetailed(ctx context.Context, repo domain.Repository, baseCommit string, snapshot domain.Artifact) (reconstruct.Result, error) {
	res, err := h.inner.ReconstructDetailed(ctx, repo, baseCommit, snapshot)
	if err != nil {
		return res, err
	}
	if h.fn != nil {
		if hookErr := h.fn(ctx, repo, baseCommit, snapshot, res); hookErr != nil {
			return res, hookErr
		}
	}
	return res, nil
}

type hookDecisionAssessor struct {
	inner workflow.DecisionAssessor
	fn    func(ctx context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error)
}

func (h *hookDecisionAssessor) Assess(ctx context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error) {
	if h.fn != nil {
		return h.fn(ctx, req)
	}
	return h.inner.Assess(ctx, req)
}

func TestWorkflow_LeaseFencing_IngressBlockedAfterLeaseLost(t *testing.T) {
	assertNoBlockedAudit := func(t *testing.T, ctx context.Context, store *persistence.Store, wsID uuid.UUID) {
		t.Helper()
		audSvc := audit.NewService(store, nil)
		audRes, err := audSvc.List(ctx, audit.ListFilter{
			ResourceType: "workspace",
			ResourceID:   &wsID,
			Limit:        20,
		})
		if err != nil {
			t.Fatalf("audit.List: %v", err)
		}
		for _, ev := range audRes.Events {
			if ev.EventType == "workspace.ingress_blocked" || ev.EventType == "workspace.failed" {
				t.Fatalf("lease fencing violation: unexpected %s audit event after lease stolen", ev.EventType)
			}
		}
	}

	t.Run("scanner incomplete after lease stolen leaves workspace PREPARING and zero ingress_blocked audit", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}

		var stolen atomic.Bool
		insp := &stubInspector{
			fn: func(c context.Context, req inspection.Request) (inspection.Report, error) {
				if stolen.CompareAndSwap(false, true) {
					if _, execErr := fx.pg.Pool().Exec(context.Background(),
						`UPDATE operations SET leased_by = 'new-active-worker', lease_until = now() + interval '30 seconds' WHERE id = $1`,
						wsRes.Operation.ID,
					); execErr != nil {
						return inspection.Report{}, execErr
					}
				}
				now := time.Now().UTC().Truncate(time.Microsecond)
				srID := domain.MustNewID()
				return inspection.Report{
					ProposalID: req.ProposalID,
					ArtifactID: req.ArtifactID,
					ScanRuns: []domain.ScanRun{{
						ID: srID, ProposalID: req.ProposalID, ArtifactID: req.ArtifactID,
						Scanner: "gitleaks", ScannerVersion: "8.0.0", Status: domain.ScanStatusFailed,
						Coverage:  domain.ScanCoverage{FilesExamined: 0, FilesSkipped: 1, Complete: false},
						StartedAt: now, CompletedAt: &now,
					}},
					Summary: inspection.InspectionSummary{
						MandatoryScannersComplete: false,
						ScanComplete:              false,
						CountsByCategory:          map[string]int{},
						CountsBySeverity:          map[string]int{},
						CountsByScanner:           map[string]int{},
						EvidenceIDs:               []string{},
						FailedScanners:            []string{"gitleaks"},
						IncompleteScanners:        []string{"gitleaks"},
					},
				}, nil
			},
		}

		_, runner := newTestWorkflowRunner(t, fx, nil, insp, nil, workflow.Config{
			WorkerID:      "stale-worker",
			LeaseDuration: 15 * time.Second,
			RenewInterval: 1 * time.Minute,
		})
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce: n=%d err=%v", n, err)
		}

		wsAfter, err := wsSvc.Get(ctx, wsRes.Workspace.ID)
		if err != nil {
			t.Fatalf("ws.Get: %v", err)
		}
		if wsAfter.Status != domain.WorkspaceStatusPreparing {
			t.Fatalf("lease fencing violation: workspace mutated to %s (expected PREPARING)", wsAfter.Status)
		}
		opAfter, err := fx.store.GetOperationByID(ctx, wsRes.Operation.ID)
		if err != nil {
			t.Fatalf("GetOperationByID: %v", err)
		}
		if opAfter.Status != domain.OperationStatusRunning || derefStr(opAfter.LeasedBy) != "new-active-worker" {
			t.Fatalf("expected op RUNNING by new-active-worker, got status=%s leased_by=%q", opAfter.Status, derefStr(opAfter.LeasedBy))
		}
		assertNoBlockedAudit(t, ctx, fx.store, wsRes.Workspace.ID)
	})

	t.Run("critical secret after lease stolen leaves workspace PREPARING and zero ingress_blocked audit", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}

		var stolen atomic.Bool
		insp := &stubInspector{
			fn: func(c context.Context, req inspection.Request) (inspection.Report, error) {
				if stolen.CompareAndSwap(false, true) {
					if _, execErr := fx.pg.Pool().Exec(context.Background(),
						`UPDATE operations SET leased_by = 'new-active-worker', lease_until = now() + interval '30 seconds' WHERE id = $1`,
						wsRes.Operation.ID,
					); execErr != nil {
						return inspection.Report{}, execErr
					}
				}
				now := time.Now().UTC().Truncate(time.Microsecond)
				srID := domain.MustNewID()
				return inspection.Report{
					ProposalID: req.ProposalID,
					ArtifactID: req.ArtifactID,
					ScanRuns: []domain.ScanRun{{
						ID: srID, ProposalID: req.ProposalID, ArtifactID: req.ArtifactID,
						Scanner: "gitleaks", ScannerVersion: "8.0.0", Status: domain.ScanStatusCompleted,
						Coverage:  domain.ScanCoverage{FilesExamined: 1, Complete: true},
						StartedAt: now, CompletedAt: &now,
					}},
					Findings: []domain.Finding{{
						ID: domain.MustNewID(), ScanRunID: srID, EvidenceID: "ev-secret", Scanner: "gitleaks",
						Category: "SECRET", Severity: domain.SeverityCritical, RuleID: "aws-key",
						Path: ".env", Fingerprint: "fp-secret", Redacted: true, Message: "redacted",
					}},
					Summary: inspection.InspectionSummary{
						MandatoryScannersComplete: true, ScanComplete: true, CriticalSecrets: 1, TotalFindings: 1,
						CountsByCategory: map[string]int{"SECRET": 1}, CountsBySeverity: map[string]int{"CRITICAL": 1},
						CountsByScanner: map[string]int{"gitleaks": 1}, EvidenceIDs: []string{"ev-secret"},
						FailedScanners: []string{}, IncompleteScanners: []string{},
					},
				}, nil
			},
		}

		_, runner := newTestWorkflowRunner(t, fx, nil, insp, nil, workflow.Config{
			WorkerID:      "stale-worker",
			LeaseDuration: 15 * time.Second,
			RenewInterval: 1 * time.Minute,
		})
		if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce: n=%d err=%v", n, err)
		}

		wsAfter, _ := wsSvc.Get(ctx, wsRes.Workspace.ID)
		if wsAfter.Status != domain.WorkspaceStatusPreparing {
			t.Fatalf("lease fencing violation: workspace mutated to %s (expected PREPARING)", wsAfter.Status)
		}
		opAfter, _ := fx.store.GetOperationByID(ctx, wsRes.Operation.ID)
		if opAfter.Status != domain.OperationStatusRunning || derefStr(opAfter.LeasedBy) != "new-active-worker" {
			t.Fatalf("expected op RUNNING by new-active-worker, got status=%s leased_by=%q", opAfter.Status, derefStr(opAfter.LeasedBy))
		}
		assertNoBlockedAudit(t, ctx, fx.store, wsRes.Workspace.ID)
	})

	t.Run("direct ExecuteIngress with stolen lease does not mutate workspace or audit", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}

		opsSvc := operations.NewService(fx.store, nil, nil)
		opType := domain.OperationTypeWorkspaceIngress
		claimed, err := opsSvc.Claim(ctx, operations.ClaimInput{
			WorkerID: "stale-worker", OperationType: &opType, Limit: 1, LeaseDuration: 15 * time.Second,
		})
		if err != nil || len(claimed) != 1 {
			t.Fatalf("ops.Claim: len=%d err=%v", len(claimed), err)
		}

		insp := &stubInspector{
			fn: func(c context.Context, req inspection.Request) (inspection.Report, error) {
				if _, execErr := fx.pg.Pool().Exec(context.Background(),
					`UPDATE operations SET leased_by = 'new-active-worker', lease_until = now() + interval '30 seconds' WHERE id = $1`,
					claimed[0].ID,
				); execErr != nil {
					return inspection.Report{}, execErr
				}
				now := time.Now().UTC().Truncate(time.Microsecond)
				srID := domain.MustNewID()
				return inspection.Report{
					ProposalID: req.ProposalID,
					ArtifactID: req.ArtifactID,
					ScanRuns: []domain.ScanRun{{
						ID: srID, ProposalID: req.ProposalID, ArtifactID: req.ArtifactID,
						Scanner: "gitleaks", ScannerVersion: "8.0.0", Status: domain.ScanStatusFailed,
						Coverage:  domain.ScanCoverage{FilesSkipped: 1, Complete: false},
						StartedAt: now, CompletedAt: &now,
					}},
					Summary: inspection.InspectionSummary{
						MandatoryScannersComplete: false, ScanComplete: false,
						CountsByCategory: map[string]int{}, CountsBySeverity: map[string]int{}, CountsByScanner: map[string]int{},
						EvidenceIDs: []string{}, FailedScanners: []string{"gitleaks"}, IncompleteScanners: []string{"gitleaks"},
					},
				}, nil
			},
		}
		svc, _ := newTestWorkflowRunner(t, fx, nil, insp, nil, workflow.Config{})
		_, ingErr := svc.ExecuteIngress(ctx, claimed[0])
		var domErr *domain.DomainError
		if !errors.As(ingErr, &domErr) || domErr.Code() != "INGRESS_POLICY_DENIED" {
			t.Fatalf("expected INGRESS_POLICY_DENIED, got %v", ingErr)
		}

		wsAfter, _ := wsSvc.Get(ctx, wsRes.Workspace.ID)
		if wsAfter.Status != domain.WorkspaceStatusPreparing {
			t.Fatalf("lease fencing violation on direct ExecuteIngress: ws status=%s (want PREPARING)", wsAfter.Status)
		}
		opAfter, _ := fx.store.GetOperationByID(ctx, claimed[0].ID)
		if opAfter.Status != domain.OperationStatusRunning || derefStr(opAfter.LeasedBy) != "new-active-worker" {
			t.Fatalf("expected op RUNNING by new-active-worker, got status=%s leased_by=%q", opAfter.Status, derefStr(opAfter.LeasedBy))
		}
		assertNoBlockedAudit(t, ctx, fx.store, wsRes.Workspace.ID)
	})
}

func TestWorkflow_LeaseFencing_HappyPath(t *testing.T) {
	reclaimOp := func(ctx context.Context, fx *pgTestFixture, opID uuid.UUID, opType domain.OperationType, newWorker string) (operations.OperationDetails, error) {
		if _, err := fx.pg.Pool().Exec(context.Background(),
			`UPDATE operations SET lease_until = now() - interval '1 second' WHERE id = $1`, opID,
		); err != nil {
			return operations.OperationDetails{}, err
		}
		opsSvc := operations.NewService(fx.store, nil, nil)
		claimed, err := opsSvc.Claim(ctx, operations.ClaimInput{
			WorkerID: newWorker, OperationType: &opType, Limit: 1, LeaseDuration: 30 * time.Second,
		})
		if err != nil {
			return operations.OperationDetails{}, err
		}
		if len(claimed) != 1 || claimed[0].ID != opID {
			return operations.OperationDetails{}, fmt.Errorf("expected to reclaim op %s, got %+v", opID, claimed)
		}
		return claimed[0], nil
	}

	setupReconstructed := func(ctx context.Context, t *testing.T, fx *pgTestFixture, decSvc workflow.DecisionAssessor) proposals.ProposalDetails {
		t.Helper()
		_, cleanRunner := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{})
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}
		for i := 0; i < 4; i++ {
			if n, _ := cleanRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		tarBytes := buildTarGzBytes(t, map[string]string{"README.md": "ok\n", "main.go": "package main\nfunc main() { println(42) }\n"})
		putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, fmt.Sprintf("uploads/%s.tar.gz", domain.MustNewID()), tarBytes)
		if err != nil {
			t.Fatalf("PutBytes: %v", err)
		}
		gen := int64(1)
		regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
			ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
			StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
			Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
		})
		if err != nil {
			t.Fatalf("RegisterArtifact: %v", err)
		}
		propSvc := proposals.NewService(fx.store, nil, nil)
		sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
			WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
			SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
			SizeBytes: int64(len(tarBytes)), Title: "Happy Path Lease Fencing",
		})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		for i := 0; i < 4; i++ {
			if n, _ := cleanRunner.ProcessOnce(ctx); n == 0 {
				break
			}
		}
		det, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
		if err != nil {
			t.Fatalf("GetDetails: %v", err)
		}
		return det
	}

	t.Run("ingress lease stolen before AttachSourceArtifact fails with LEASE_LOST and active worker succeeds", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}

		var (
			reclaimedOnce atomic.Bool
			activeOp      operations.OperationDetails
			stalePutArt   domain.Artifact
		)
		hookStore := &hookSnapshotStore{
			inner: fx.snaps.Store(),
			putFn: func(c context.Context, req domain.PutRequest, art domain.Artifact) error {
				if reclaimedOnce.CompareAndSwap(false, true) {
					stalePutArt = art
					var claimErr error
					activeOp, claimErr = reclaimOp(c, fx, wsRes.Operation.ID, domain.OperationTypeWorkspaceIngress, "active-worker")
					return claimErr
				}
				return nil
			},
		}

		reconSvc, _ := reconstruct.NewService(reconstruct.Config{
			GitReader: fx.git.LocalReader(), SnapshotStore: fx.snaps.Store(),
		})
		staleCfg := workflow.Config{WorkerID: "stale-worker", LeaseDuration: 15 * time.Second, RenewInterval: 1 * time.Minute}
		staleSvc, err := workflow.NewService(workflow.ServiceConfig{
			Store: fx.store, SnapshotStore: hookStore, GitReader: fx.git.LocalReader(),
			Reconstructor: reconSvc, InspectionRunner: &stubInspector{}, Config: staleCfg,
		})
		if err != nil {
			t.Fatalf("NewService(stale): %v", err)
		}
		staleRunner, _ := workflow.NewRunner(workflow.RunnerConfig{Service: staleSvc, Config: staleCfg})
		if n, err := staleRunner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(stale): n=%d err=%v", n, err)
		}

		wsAfterStale, _ := wsSvc.Get(ctx, wsRes.Workspace.ID)
		if wsAfterStale.Status != domain.WorkspaceStatusPreparing || wsAfterStale.SourceArtifactID != nil {
			t.Fatalf("lease fencing violation: stale worker mutated workspace to %s art=%v", wsAfterStale.Status, wsAfterStale.SourceArtifactID)
		}
		if verifyErr := fx.snaps.Store().Verify(ctx, stalePutArt); !errors.Is(verifyErr, domain.ErrNotFound) {
			t.Fatalf("expected stale unattached blob to be cleaned up, Verify err=%v", verifyErr)
		}
		opMid, _ := fx.store.GetOperationByID(ctx, wsRes.Operation.ID)
		if opMid.Status != domain.OperationStatusRunning || derefStr(opMid.LeasedBy) != "active-worker" {
			t.Fatalf("expected op RUNNING by active-worker, got status=%s leased_by=%q", opMid.Status, derefStr(opMid.LeasedBy))
		}

		// Active worker completes cleanly.
		activeSvc, _ := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{WorkerID: "active-worker"})
		res, err := activeSvc.ExecuteIngress(ctx, activeOp)
		if err != nil {
			t.Fatalf("active ExecuteIngress: %v", err)
		}
		opsSvc := operations.NewService(fx.store, nil, nil)
		if _, err := opsSvc.Complete(ctx, activeOp.ID, "active-worker", mustJSONBytes(t, res)); err != nil {
			t.Fatalf("ops.Complete(active): %v", err)
		}
		wsFinal, _ := wsSvc.Get(ctx, wsRes.Workspace.ID)
		if wsFinal.Status != domain.WorkspaceStatusReady || wsFinal.SourceArtifactID == nil {
			t.Fatalf("expected READY workspace from active worker, got status=%s", wsFinal.Status)
		}
	})

	t.Run("reconstruct lease stolen before CompleteReconstruction fails with LEASE_LOST and active worker succeeds", func(t *testing.T) {
		fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		_, cleanRunner := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{})
		wsSvc := workspaces.NewService(fx.store, nil, nil)
		wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
			RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
			BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}
		if n, err := cleanRunner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(ingress): n=%d err=%v", n, err)
		}
		tarBytes := buildTarGzBytes(t, map[string]string{"README.md": "ok\n", "app.go": "package main\n"})
		putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "uploads/recon-lease.tar.gz", tarBytes)
		if err != nil {
			t.Fatalf("PutBytes: %v", err)
		}
		gen := int64(1)
		regArt, _ := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
			ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
			StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
			Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
		})
		propSvc := proposals.NewService(fx.store, nil, nil)
		sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
			WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
			SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
			SizeBytes: int64(len(tarBytes)), Title: "Reconstruct Lease Fence",
		})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}

		baseRecon, _ := reconstruct.NewService(reconstruct.Config{
			GitReader: fx.git.LocalReader(), SnapshotStore: fx.snaps.Store(),
		})
		var (
			reclaimedOnce atomic.Bool
			activeOp      operations.OperationDetails
		)
		hookRecon := &hookReconstructor{
			inner: baseRecon,
			fn: func(c context.Context, _ domain.Repository, _ string, _ domain.Artifact, _ reconstruct.Result) error {
				if reclaimedOnce.CompareAndSwap(false, true) {
					var claimErr error
					activeOp, claimErr = reclaimOp(c, fx, sub.Operation.ID, domain.OperationTypeProposalReconstruct, "active-recon-worker")
					return claimErr
				}
				return nil
			},
		}
		staleCfg := workflow.Config{WorkerID: "stale-recon-worker", LeaseDuration: 15 * time.Second, RenewInterval: 1 * time.Minute}
		staleSvc, _ := workflow.NewService(workflow.ServiceConfig{
			Store: fx.store, SnapshotStore: fx.snaps.Store(), GitReader: fx.git.LocalReader(),
			Reconstructor: hookRecon, InspectionRunner: &stubInspector{}, Config: staleCfg,
		})
		staleRunner, _ := workflow.NewRunner(workflow.RunnerConfig{Service: staleSvc, Config: staleCfg})
		if n, err := staleRunner.ProcessOnce(ctx); err != nil || n != 1 {
			t.Fatalf("ProcessOnce(stale recon): n=%d err=%v", n, err)
		}

		propMid, _ := propSvc.Get(ctx, sub.Proposal.ID)
		if propMid.Status != domain.ProposalStatusReconstructing || propMid.CanonicalArtifactID != nil {
			t.Fatalf("lease fencing violation: stale worker mutated proposal to %s art=%v", propMid.Status, propMid.CanonicalArtifactID)
		}

		// Active worker completes reconstruction cleanly without PROPOSAL_VERSION_CONFLICT or MarkFailed.
		activeSvc, _ := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{WorkerID: "active-recon-worker"})
		res, err := activeSvc.ExecuteReconstruct(ctx, activeOp)
		if err != nil {
			t.Fatalf("active ExecuteReconstruct: %v", err)
		}
		opsSvc := operations.NewService(fx.store, nil, nil)
		if _, err := opsSvc.Complete(ctx, activeOp.ID, "active-recon-worker", mustJSONBytes(t, res)); err != nil {
			t.Fatalf("ops.Complete(active recon): %v", err)
		}
		propFinal, _ := propSvc.Get(ctx, sub.Proposal.ID)
		if propFinal.Status != domain.ProposalStatusReconstructed {
			t.Fatalf("expected RECONSTRUCTED proposal from active worker, got %s", propFinal.Status)
		}
	})

	for _, stage := range []string{"persistInspectionReport", "persistModelAssessment", "ApplyPolicyDecision"} {
		stage := stage
		t.Run("evaluate lease stolen before "+stage+" fails with LEASE_LOST and active worker succeeds", func(t *testing.T) {
			fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			gwSrv := startMockGateway(t, &mockGatewayState{})
			gwClient, _ := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
			decSvc, _ := decisions.NewService(gwClient)

			det := setupReconstructed(ctx, t, fx, decSvc)
			propSvc := proposals.NewService(fx.store, nil, nil)
			evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
				ProposalID: det.ID, ExpectedVersion: det.Version,
			})
			if err != nil {
				t.Fatalf("RequestEvaluation: %v", err)
			}

			var (
				reclaimedOnce atomic.Bool
				activeOp      operations.OperationDetails
			)
			var insp inspection.Runner = &stubInspector{}
			var assessor workflow.DecisionAssessor = decSvc

			if stage == "persistInspectionReport" {
				baseInsp := &stubInspector{}
				insp = &stubInspector{
					fn: func(c context.Context, req inspection.Request) (inspection.Report, error) {
						rep, repErr := baseInsp.Inspect(c, req)
						if repErr != nil {
							return rep, repErr
						}
						if reclaimedOnce.CompareAndSwap(false, true) {
							var claimErr error
							activeOp, claimErr = reclaimOp(c, fx, evalRes.Operation.ID, domain.OperationTypeProposalEvaluate, "active-eval-worker")
							if claimErr != nil {
								return rep, claimErr
							}
						}
						return rep, nil
					},
				}
			} else if stage == "persistModelAssessment" {
				assessor = &hookDecisionAssessor{
					inner: decSvc,
					fn: func(c context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error) {
						ma, maErr := decSvc.Assess(c, req)
						if maErr != nil {
							return ma, maErr
						}
						if reclaimedOnce.CompareAndSwap(false, true) {
							var claimErr error
							activeOp, claimErr = reclaimOp(c, fx, evalRes.Operation.ID, domain.OperationTypeProposalEvaluate, "active-eval-worker")
							if claimErr != nil {
								return ma, claimErr
							}
						}
						return ma, nil
					},
				}
			} else if stage == "ApplyPolicyDecision" {
				assessor = &hookDecisionAssessor{
					inner: decSvc,
					fn: func(c context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error) {
						if reclaimedOnce.CompareAndSwap(false, true) {
							var claimErr error
							activeOp, claimErr = reclaimOp(c, fx, evalRes.Operation.ID, domain.OperationTypeProposalEvaluate, "active-eval-worker")
							if claimErr != nil {
								return domain.ModelAssessment{}, claimErr
							}
						}
						// Return ID == uuid.Nil so persistModelAssessment is skipped and lease fence is hit inside ApplyPolicyDecision.
						return domain.ModelAssessment{
							ProposalID:     req.ProposalID,
							ArtifactID:     req.ArtifactID,
							ModelRoute:     req.ModelRoute,
							ModelVersion:   "mock-v1",
							PromptVersion:  "1",
							AssessmentType: req.AssessmentType,
							Status:         domain.AssessmentStatusComplete,
							Risk:           domain.RiskLevelLow,
							Disposition:    domain.DispositionClear,
						}, nil
					},
				}
			}

			_, staleRunner := newTestWorkflowRunner(t, fx, nil, insp, assessor, workflow.Config{
				WorkerID:      "stale-eval-worker",
				LeaseDuration: 15 * time.Second,
				RenewInterval: 1 * time.Minute,
			})
			if n, err := staleRunner.ProcessOnce(ctx); err != nil || n != 1 {
				t.Fatalf("ProcessOnce(stale eval): n=%d err=%v", n, err)
			}

			propMid, _ := propSvc.Get(ctx, det.ID)
			if propMid.Status != domain.ProposalStatusEvaluating {
				t.Fatalf("lease fencing violation (%s): stale worker mutated proposal to %s", stage, propMid.Status)
			}
			if stage == "persistInspectionReport" {
				runs, _ := fx.store.ListScanRunsByProposal(ctx, det.ID)
				if len(runs) != 0 {
					t.Fatalf("expected 0 scan_runs persisted by stale worker, got %d", len(runs))
				}
			}
			if stage == "persistModelAssessment" {
				assessments, _ := fx.store.ListModelAssessmentsByProposal(ctx, det.ID)
				if len(assessments) != 0 {
					t.Fatalf("expected 0 model_assessments persisted by stale worker, got %d", len(assessments))
				}
			}
			if stage == "ApplyPolicyDecision" {
				decs, _ := fx.store.ListPolicyDecisionsByProposal(ctx, det.ID)
				if len(decs) != 0 {
					t.Fatalf("expected 0 policy_decisions persisted by stale worker, got %d", len(decs))
				}
			}

			// Active worker executes and completes cleanly without PROPOSAL_VERSION_CONFLICT or MarkFailed.
			activeSvc, _ := newTestWorkflowRunner(t, fx, nil, nil, decSvc, workflow.Config{WorkerID: "active-eval-worker"})
			res, err := activeSvc.ExecuteEvaluate(ctx, activeOp)
			if err != nil {
				t.Fatalf("active ExecuteEvaluate (%s): %v", stage, err)
			}
			opsSvc := operations.NewService(fx.store, nil, nil)
			if _, err := opsSvc.Complete(ctx, activeOp.ID, "active-eval-worker", mustJSONBytes(t, res)); err != nil {
				t.Fatalf("ops.Complete(active eval %s): %v", stage, err)
			}
			propFinal, _ := propSvc.Get(ctx, det.ID)
			if propFinal.Status != domain.ProposalStatusPendingApproval {
				t.Fatalf("expected PENDING_APPROVAL from active worker (%s), got %s", stage, propFinal.Status)
			}
		})
	}
}

func TestWorkflow_OutboxDispatcher_FailureRetryAndConflict(t *testing.T) {
	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var (
		mu  sync.Mutex
		now = time.Now().UTC().Truncate(time.Microsecond)
	)
	clockFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	var attemptNum atomic.Int32
	var dispatchFn func(ctx context.Context, ev persistence.OutboxEventRow) error

	wfCfg := workflow.Config{
		WorkerID:            "outbox-worker",
		OutboxLeaseDuration: 15 * time.Second,
		OutboxRetryDelay:    5 * time.Second,
		OutboxBatchSize:     10,
		Clock:               clockFn,
	}
	reconSvc, _ := reconstruct.NewService(reconstruct.Config{
		GitReader: fx.git.LocalReader(), SnapshotStore: fx.snaps.Store(),
	})
	svc, err := workflow.NewService(workflow.ServiceConfig{
		Store:            fx.store,
		SnapshotStore:    fx.snaps.Store(),
		GitReader:        fx.git.LocalReader(),
		Reconstructor:    reconSvc,
		InspectionRunner: &stubInspector{},
		OutboxDispatcher: workflow.OutboxDispatcherFunc(func(c context.Context, ev persistence.OutboxEventRow) error {
			return dispatchFn(c, ev)
		}),
		Config: wfCfg,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	runner, err := workflow.NewRunner(workflow.RunnerConfig{Service: svc, Config: wfCfg})
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	// 1. Secret redaction, exponential backoff (5s -> 10s), available_at gating, and eventual delivery.
	ev1ID := domain.MustNewID()
	if _, err := fx.store.EnqueueOutboxEvent(ctx, persistence.EnqueueOutboxParams{
		ID:          ev1ID,
		EventType:   "proposal.evaluated",
		AggregateID: domain.MustNewID(),
		Payload:     json.RawMessage(`{"ok":true}`),
		AvailableAt: clockFn(),
	}); err != nil {
		t.Fatalf("EnqueueOutboxEvent(ev1): %v", err)
	}

	dispatchFn = func(_ context.Context, _ persistence.OutboxEventRow) error {
		n := attemptNum.Add(1)
		switch n {
		case 1:
			return errors.New("webhook failed https://x-access-token:ghp_secret1234567890@hook.example.com Bearer tok_abc123 password=supersecret")
		case 2:
			return errors.New("second transient outage")
		default:
			return nil
		}
	}

	n, err := runner.DispatchOutboxOnce(ctx)
	if err != nil || n != 0 {
		t.Fatalf("attempt 1 DispatchOutboxOnce: n=%d err=%v", n, err)
	}
	row1, err := fx.store.GetOutboxEventByID(ctx, ev1ID)
	if err != nil {
		t.Fatalf("GetOutboxEventByID(1): %v", err)
	}
	if row1.Attempts != 1 || row1.DeliveredAt != nil || row1.LeasedBy != nil || row1.LeaseUntil != nil {
		t.Fatalf("unexpected row after attempt 1 failure: %+v", row1)
	}
	if row1.LastError == nil {
		t.Fatalf("expected non-nil last_error after dispatch failure")
	}
	for _, secret := range []string{"ghp_secret1234567890", "tok_abc123", "supersecret"} {
		if strings.Contains(*row1.LastError, secret) {
			t.Fatalf("outbox last_error leaked secret %q: %q", secret, *row1.LastError)
		}
	}
	if !strings.Contains(*row1.LastError, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in outbox last_error, got %q", *row1.LastError)
	}
	if !row1.AvailableAt.Equal(clockFn().Add(5 * time.Second)) {
		t.Fatalf("expected attempt 1 available_at=%s, got %s", clockFn().Add(5*time.Second), row1.AvailableAt)
	}

	// Before available_at (+4s < +5s): must NOT claim or dispatch.
	advance(4 * time.Second)
	n, err = runner.DispatchOutboxOnce(ctx)
	if err != nil || n != 0 || attemptNum.Load() != 1 {
		t.Fatalf("expected 0 claims before available_at, got n=%d attempts=%d err=%v", n, attemptNum.Load(), err)
	}

	// Past +5s (+6s total): attempt 2 fails and applies exponential backoff (ComputeBackoff(2, 5s, 5m) = 10s).
	advance(2 * time.Second)
	n, err = runner.DispatchOutboxOnce(ctx)
	if err != nil || n != 0 || attemptNum.Load() != 2 {
		t.Fatalf("attempt 2 DispatchOutboxOnce: n=%d attempts=%d err=%v", n, attemptNum.Load(), err)
	}
	row2, _ := fx.store.GetOutboxEventByID(ctx, ev1ID)
	if row2.Attempts != 2 || !row2.AvailableAt.Equal(clockFn().Add(10*time.Second)) {
		t.Fatalf("expected attempts=2 and 10s backoff available_at=%s, got attempts=%d available_at=%s",
			clockFn().Add(10*time.Second), row2.Attempts, row2.AvailableAt)
	}

	// Past +10s (+11s): attempt 3 delivers cleanly.
	advance(11 * time.Second)
	n, err = runner.DispatchOutboxOnce(ctx)
	if err != nil || n != 1 || attemptNum.Load() != 3 {
		t.Fatalf("attempt 3 DispatchOutboxOnce: n=%d attempts=%d err=%v", n, attemptNum.Load(), err)
	}
	row3, _ := fx.store.GetOutboxEventByID(ctx, ev1ID)
	if row3.DeliveredAt == nil {
		t.Fatalf("expected delivered_at set after successful retry")
	}

	// 2. MarkOutboxDelivered ErrConflict (lease stolen during Dispatch) must NOT increment processed.
	ev2ID := domain.MustNewID()
	if _, err := fx.store.EnqueueOutboxEvent(ctx, persistence.EnqueueOutboxParams{
		ID:          ev2ID,
		EventType:   "proposal.evaluated",
		AggregateID: domain.MustNewID(),
		Payload:     json.RawMessage(`{"ok":true}`),
		AvailableAt: clockFn(),
	}); err != nil {
		t.Fatalf("EnqueueOutboxEvent(ev2): %v", err)
	}
	dispatchFn = func(_ context.Context, ev persistence.OutboxEventRow) error {
		_, execErr := fx.pg.Pool().Exec(context.Background(),
			`UPDATE outbox_events SET leased_by = 'other-outbox-worker', lease_until = now() + interval '30 seconds' WHERE id = $1`,
			ev.ID,
		)
		return execErr
	}
	n, err = runner.DispatchOutboxOnce(ctx)
	if err != nil || n != 0 {
		t.Fatalf("expected processed=0 when MarkOutboxDelivered hits ErrConflict, got n=%d err=%v", n, err)
	}
	rowConflict, _ := fx.store.GetOutboxEventByID(ctx, ev2ID)
	if rowConflict.DeliveredAt != nil {
		t.Fatalf("expected ev2 still undelivered after ErrConflict")
	}

	// Clear ev2 so it won't interfere with shutdown test.
	_, _ = fx.pg.Pool().Exec(ctx, `DELETE FROM outbox_events WHERE id = $1`, ev2ID)

	// 3. Shutdown ctx cancelled during Dispatch must NOT call FailOutbox.
	ev3ID := domain.MustNewID()
	if _, err := fx.store.EnqueueOutboxEvent(ctx, persistence.EnqueueOutboxParams{
		ID:          ev3ID,
		EventType:   "proposal.evaluated",
		AggregateID: domain.MustNewID(),
		Payload:     json.RawMessage(`{"ok":true}`),
		AvailableAt: clockFn(),
	}); err != nil {
		t.Fatalf("EnqueueOutboxEvent(ev3): %v", err)
	}
	subCtx, cancelSub := context.WithCancel(ctx)
	dispatchFn = func(_ context.Context, _ persistence.OutboxEventRow) error {
		cancelSub()
		return context.Canceled
	}
	n, err = runner.DispatchOutboxOnce(subCtx)
	if err != nil || n != 0 {
		t.Fatalf("expected n=0 err=nil on shutdown cancellation during dispatch, got n=%d err=%v", n, err)
	}
	rowShutdown, _ := fx.store.GetOutboxEventByID(ctx, ev3ID)
	if rowShutdown.Attempts != 0 || rowShutdown.LastError != nil {
		t.Fatalf("expected FailOutbox skipped on shutdown cancel (attempts=0, last_error=nil), got attempts=%d last_error=%v",
			rowShutdown.Attempts, rowShutdown.LastError)
	}
}

func mustJSONBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := domain.CanonicalJSONBytes(v)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes: %v", err)
	}
	return b
}

func TestWorkflow_ExecuteEvaluate_ScrubsChangedPathsAndTargetRefForStageBWhilePreservingStageCCELPaths(t *testing.T) {
	const (
		customSecret     = "custodian_custom_tok_xyz987654321"
		patternSecret    = "sk-projkey1234567890"
		patternRefSecret = "sk-testkey1234567890"
		diffAKIASecret   = "AKIAIOSFODNN7EXAMPLE"
	)
	customPath := "keys/" + customSecret + ".env"
	patternPath := "config/" + patternSecret + ".txt"
	targetRef := "refs/heads/fix/" + patternRefSecret + "/" + customSecret

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Register a REPO-scoped PolicyBundle whose CEL rule matches ONLY if Stage C receives
	// the real, un-scrubbed changedPaths and target_ref.
	pe, err := policy.NewEngine()
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	repoBundleYAML := []byte(fmt.Sprintf(`
apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: repo-raw-path-ref-verification
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: repo.raw-paths-and-ref-preserved
    description: Verify Stage C CEL PolicyInput receives raw un-scrubbed paths and target_ref.
    stages: [EGRESS]
    when: >-
      change.paths.exists(p, p == %q) &&
      change.paths.exists(p, p == %q) &&
      change.target_ref == %q
    effect: DENY
    message: RAW_PATHS_AND_REF_VISIBLE_TO_STAGE_C
`, customPath, patternPath, targetRef))
	repoComp, valErrs := pe.Compile(repoBundleYAML)
	if len(valErrs) > 0 {
		t.Fatalf("Compile repoBundleYAML: %+v", valErrs)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := fx.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name:         repoComp.Bundle.Metadata.Name,
		Version:      repoComp.Bundle.Metadata.Version,
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: &fx.repo.ID,
		Digest:       repoComp.Digest,
		Definition:   repoComp.Definition,
		ActivatedAt:  &now,
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest: %v", err)
	}

	// Build real inspection.NewRunner backed by POSIX stub binaries so Stage A genuinely
	// harvests the custom secret on egress while allowing clean ingress.
	stubDir := t.TempDir()
	gitleaksBin := filepath.Join(stubDir, "gitleaks")
	scancodeBin := filepath.Join(stubDir, "scancode")
	semgrepBin := filepath.Join(stubDir, "semgrep")
	trivyBin := filepath.Join(stubDir, "trivy")

	gitleaksScript := fmt.Sprintf(`#!/bin/sh
set -eu
for arg in "$@"; do
  if [ "$arg" = "version" ] || [ "$arg" = "--version" ]; then
    printf 'v8.18.4\n'
    exit 0
  fi
done
SRC_DIR=""
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --source) SRC_DIR="$2"; shift 2 ;;
    --report-path) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/%s" ]; then
  cat <<'EOF' > "$OUT_FILE"
[{"Description":"Custom Token","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":40,"Match":"TOKEN=%s","Secret":"%s","File":"%s","RuleID":"custom-tok","Fingerprint":"fp-custom-1"}]
EOF
else
  printf '[]\n' > "$OUT_FILE"
fi
`, customPath, customSecret, customSecret, customPath)

	scancodeScript := `#!/bin/sh
set -eu
for arg in "$@"; do
  if [ "$arg" = "--version" ]; then
    printf '32.1.0\n'
    exit 0
  fi
done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json-pp) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.1.0","errors":[],"extra_data":{"files_count":1}}],"files":[]}\n' > "$OUT_FILE"
`

	semgrepScript := `#!/bin/sh
set -eu
for arg in "$@"; do
  if [ "$arg" = "--version" ]; then
    printf '1.90.0\n'
    exit 0
  fi
done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"version":"1.90.0","results":[],"errors":[],"paths":{"scanned":["README.md"],"skipped":[]}}\n' > "$OUT_FILE"
`

	trivyScript := `#!/bin/sh
set -eu
for arg in "$@"; do
  if [ "$arg" = "--version" ]; then
    printf 'Version: 0.58.0\n'
    exit 0
  fi
done
OUT_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) OUT_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"SchemaVersion":2,"ArtifactName":".","ArtifactType":"filesystem","Results":[]}\n' > "$OUT_FILE"
`

	for path, body := range map[string]string{
		gitleaksBin: gitleaksScript,
		scancodeBin: scancodeScript,
		semgrepBin:  semgrepScript,
		trivyBin:    trivyScript,
	} {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", path, err)
		}
	}

	realInspector := inspection.NewRunner(inspection.Config{
		GitleaksBin: gitleaksBin,
		ScanCodeBin: scancodeBin,
		SemgrepBin:  semgrepBin,
		TrivyBin:    trivyBin,
	})

	gwState := &mockGatewayState{}
	gwSrv := startMockGateway(t, gwState)
	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gwSrv.URL})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	decSvc, err := decisions.NewService(gwClient)
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}

	var capturedMu sync.Mutex
	var capturedReq *decisions.AssessRequest
	assessor := &hookDecisionAssessor{
		inner: decSvc,
		fn: func(c context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error) {
			reqCopy := req
			reqCopy.ChangedPaths = append([]string(nil), req.ChangedPaths...)
			capturedMu.Lock()
			capturedReq = &reqCopy
			capturedMu.Unlock()
			return decSvc.Assess(c, req)
		},
	}

	_, runner := newTestWorkflowRunner(t, fx, nil, realInspector, assessor, workflow.Config{})

	wsSvc := workspaces.NewService(fx.store, nil, nil)
	wsRes, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID,
		OwnerID:      fx.owner.ID,
		ModelRoute:   "approved-code-review",
		BaseCommit:   fx.bareRepo.HeadSHA,
		TargetRef:    targetRef,
	})
	if err != nil {
		t.Fatalf("workspaces.Create: %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(ingress): n=%d err=%v", n, err)
	}
	if ingOp, err := fx.store.GetOperationByID(ctx, wsRes.Operation.ID); err != nil || ingOp.Status != domain.OperationStatusSucceeded {
		t.Fatalf("ingress op not SUCCEEDED: err=%v status=%s last_error=%q", err, ingOp.Status, derefStr(ingOp.LastError))
	}

	tarBytes := buildTarGzBytes(t, map[string]string{
		"README.md": "# Custodian Test Repo\n",
		"main.go":   "package main\nfunc main() {}\n",
		customPath:  "TOKEN=" + customSecret + "\n",
		patternPath: "AWS_KEY=" + diffAKIASecret + "\nOPENAI_KEY=" + patternSecret + "\nNORMAL_SETTING=keep_me\n",
	})
	putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, fmt.Sprintf("uploads/%s.tar.gz", domain.MustNewID()), tarBytes)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	gen := int64(1)
	regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
		StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
		Format: "application/gzip", WorkspaceID: &wsRes.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact: %v", err)
	}

	propSvc := proposals.NewService(fx.store, nil, nil)
	sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsRes.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(tarBytes),
		SizeBytes: int64(len(tarBytes)), Title: "Stage B Path/Ref Scrub Regression",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(reconstruct): n=%d err=%v", n, err)
	}
	if reconOp, err := fx.store.GetOperationByID(ctx, sub.Operation.ID); err != nil || reconOp.Status != domain.OperationStatusSucceeded {
		t.Fatalf("reconstruct op not SUCCEEDED: err=%v status=%s last_error=%q", err, reconOp.Status, derefStr(reconOp.LastError))
	}
	det, err := propSvc.GetDetails(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("GetDetails: %v", err)
	}
	evalRes, err := propSvc.RequestEvaluation(ctx, proposals.EvaluateInput{
		ProposalID: det.ID, ExpectedVersion: det.Version,
	})
	if err != nil {
		t.Fatalf("RequestEvaluation: %v", err)
	}
	if n, err := runner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(evaluate): n=%d err=%v", n, err)
	}
	opAfter, err := fx.store.GetOperationByID(ctx, evalRes.Operation.ID)
	if err != nil {
		t.Fatalf("GetOperationByID: %v", err)
	}
	if opAfter.Status != domain.OperationStatusSucceeded {
		t.Fatalf("expected SUCCEEDED evaluate op, got %s (last_error=%q)", opAfter.Status, derefStr(opAfter.LastError))
	}

	// 1. Verify Stage B AssessRequest received scrubbed TargetRef, ChangedPaths, and CanonicalDiff.
	capturedMu.Lock()
	gotReq := capturedReq
	capturedMu.Unlock()
	if gotReq == nil {
		t.Fatalf("expected Stage B AssessRequest to be captured")
	}
	if strings.Contains(gotReq.TargetRef, customSecret) || strings.Contains(gotReq.TargetRef, patternSecret) || strings.Contains(gotReq.TargetRef, patternRefSecret) {
		t.Fatalf("Stage B AssessRequest.TargetRef leaked secret: %q", gotReq.TargetRef)
	}
	if !strings.Contains(gotReq.TargetRef, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in Stage B AssessRequest.TargetRef, got %q", gotReq.TargetRef)
	}
	if len(gotReq.ChangedPaths) != 2 {
		t.Fatalf("expected 2 Stage B AssessRequest.ChangedPaths, got %v", gotReq.ChangedPaths)
	}
	for _, p := range gotReq.ChangedPaths {
		if strings.Contains(p, customSecret) || strings.Contains(p, patternSecret) {
			t.Fatalf("Stage B AssessRequest.ChangedPaths leaked secret: %q", p)
		}
		if !strings.Contains(p, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in Stage B AssessRequest.ChangedPaths element, got %q", p)
		}
	}
	if strings.Contains(gotReq.CanonicalDiff, customSecret) || strings.Contains(gotReq.CanonicalDiff, patternSecret) || strings.Contains(gotReq.CanonicalDiff, diffAKIASecret) {
		t.Fatalf("Stage B AssessRequest.CanonicalDiff leaked secret: %q", gotReq.CanonicalDiff)
	}
	if !strings.Contains(gotReq.CanonicalDiff, "NORMAL_SETTING=keep_me") {
		t.Fatalf("expected non-secret diff context preserved, got %q", gotReq.CanonicalDiff)
	}

	// 2. Verify the serialized Stage B GatewayRequest payload sent to the HTTP gateway contains zero secrets.
	gwState.mu.Lock()
	gwReqs := append([]decisions.GatewayRequest(nil), gwState.requests...)
	gwState.mu.Unlock()
	if len(gwReqs) != 1 {
		t.Fatalf("expected 1 Stage B gateway request, got %d", len(gwReqs))
	}
	gwBytes, err := json.Marshal(gwReqs[0])
	if err != nil {
		t.Fatalf("marshal GatewayRequest: %v", err)
	}
	gwWire := string(gwBytes)
	for _, forbidden := range []string{
		customSecret,
		patternSecret,
		patternRefSecret,
		diffAKIASecret,
		base64.StdEncoding.EncodeToString([]byte(customSecret)),
		base64.RawURLEncoding.EncodeToString([]byte(customSecret)),
		base64.StdEncoding.EncodeToString([]byte(patternSecret)),
		base64.RawURLEncoding.EncodeToString([]byte(patternSecret)),
		base64.StdEncoding.EncodeToString([]byte(patternRefSecret)),
		base64.RawURLEncoding.EncodeToString([]byte(patternRefSecret)),
		base64.StdEncoding.EncodeToString([]byte(diffAKIASecret)),
		base64.RawURLEncoding.EncodeToString([]byte(diffAKIASecret)),
	} {
		if strings.Contains(gwWire, forbidden) {
			t.Fatalf("Stage B GatewayRequest wire payload leaked secret/encoded form %q: %s", forbidden, gwWire)
		}
	}
	if len(gwReqs[0].Messages) < 2 {
		t.Fatalf("expected >= 2 gateway messages, got %d", len(gwReqs[0].Messages))
	}
	var env struct {
		TargetRef              string   `json:"target_ref"`
		ChangedPaths           []string `json:"changed_paths"`
		UntrustedCanonicalDiff string   `json:"untrusted_canonical_diff"`
	}
	if err := json.Unmarshal([]byte(gwReqs[0].Messages[1].Content), &env); err != nil {
		t.Fatalf("unmarshal Stage B prompt envelope: %v", err)
	}
	if env.TargetRef != "refs/heads/fix/[REDACTED]/[REDACTED]" {
		t.Fatalf("unexpected Stage B prompt envelope target_ref: %q", env.TargetRef)
	}
	if len(env.ChangedPaths) != 2 || env.ChangedPaths[0] != "config/[REDACTED].txt" || env.ChangedPaths[1] != "keys/[REDACTED].env" {
		t.Fatalf("unexpected Stage B prompt envelope changed_paths: %v", env.ChangedPaths)
	}
	if !strings.Contains(env.UntrustedCanonicalDiff, "NORMAL_SETTING=keep_me") {
		t.Fatalf("expected non-secret diff content in Stage B prompt envelope, got %q", env.UntrustedCanonicalDiff)
	}

	// 3. Verify Stage C CEL PolicyInput preserved the real, un-scrubbed changedPaths and target_ref.
	pdRow, err := fx.store.GetLatestPolicyDecisionForProposal(ctx, det.ID)
	if err != nil {
		t.Fatalf("GetLatestPolicyDecisionForProposal: %v", err)
	}
	pd := pdRow.ToDomain()
	if pd.Effect != domain.PolicyEffectDeny {
		t.Fatalf("expected Stage C DENY, got %s", pd.Effect)
	}
	matchedRawRule := false
	for _, r := range pd.Reasons {
		if r.RuleID == "repo.raw-paths-and-ref-preserved" && r.Message == "RAW_PATHS_AND_REF_VISIBLE_TO_STAGE_C" {
			matchedRawRule = true
			break
		}
	}
	if !matchedRawRule {
		t.Fatalf("expected Stage C CEL rule repo.raw-paths-and-ref-preserved to match un-scrubbed paths and target_ref, got reasons=%+v", pd.Reasons)
	}
}

func TestWorkflow_TerminalFailureTransitionsResourceBeforeOpsFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	fx := setupPGFixture(t, domain.ClassificationInternal, []string{"approved-code-review"})

	// Enforce in PostgreSQL itself that when an operation transitions RUNNING -> FAILED,
	// its underlying workspace or proposal MUST already be in FAILED status.
	if _, err := fx.pg.Pool().Exec(ctx, `
CREATE OR REPLACE FUNCTION assert_resource_failed_before_op_fail()
RETURNS trigger AS $$
DECLARE
    res_status text;
BEGIN
    IF NEW.status = 'FAILED' AND OLD.status = 'RUNNING' THEN
        IF NEW.operation_type = 'WORKSPACE_INGRESS' THEN
            SELECT status INTO res_status FROM workspaces WHERE id = NEW.resource_id;
            IF res_status IS DISTINCT FROM 'FAILED' THEN
                RAISE EXCEPTION 'ordering violation: workspace % status is % when WORKSPACE_INGRESS op % transitions to FAILED', NEW.resource_id, res_status, NEW.id;
            END IF;
        ELSIF NEW.operation_type IN ('PROPOSAL_RECONSTRUCT', 'PROPOSAL_EVALUATE') THEN
            SELECT status INTO res_status FROM proposals WHERE id = NEW.resource_id;
            IF res_status IS DISTINCT FROM 'FAILED' THEN
                RAISE EXCEPTION 'ordering violation: proposal % status is % when % op % transitions to FAILED', NEW.resource_id, res_status, NEW.operation_type, NEW.id;
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_assert_resource_failed_before_op_fail ON operations;
CREATE TRIGGER trg_assert_resource_failed_before_op_fail
    BEFORE UPDATE ON operations
    FOR EACH ROW
    EXECUTE FUNCTION assert_resource_failed_before_op_fail();
`); err != nil {
		t.Fatalf("install ordering trigger: %v", err)
	}

	wsSvc := workspaces.NewService(fx.store, nil, nil)

	// 1. WORKSPACE_INGRESS terminal failure transitions workspace to FAILED before ops.Fail.
	wsBad, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
		BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create(wsBad): %v", err)
	}
	failReader := &failingGitReader{
		inner:    fx.git.LocalReader(),
		failLeft: 1,
		failErr:  domain.Unprocessable("CORRUPT_CHECKOUT", "non-retryable checkout failure"),
	}
	_, failRunner := newTestWorkflowRunner(t, fx, failReader, nil, nil, workflow.Config{})
	if n, err := failRunner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(wsBad): n=%d err=%v", n, err)
	}
	wsBadAfter, err := wsSvc.Get(ctx, wsBad.Workspace.ID)
	if err != nil {
		t.Fatalf("wsSvc.Get(wsBad): %v", err)
	}
	if wsBadAfter.Status != domain.WorkspaceStatusFailed {
		t.Fatalf("expected workspace FAILED, got %s", wsBadAfter.Status)
	}
	wsOpAfter, err := fx.store.GetOperationByID(ctx, wsBad.Operation.ID)
	if err != nil {
		t.Fatalf("GetOperationByID(wsBad): %v", err)
	}
	if wsOpAfter.Status != domain.OperationStatusFailed {
		t.Fatalf("expected WORKSPACE_INGRESS operation FAILED (trigger passes), got %s (last_error=%q)", wsOpAfter.Status, derefStr(wsOpAfter.LastError))
	}

	// 2. PROPOSAL_RECONSTRUCT terminal failure (e.g., invalid archive/bomb) transitions proposal to FAILED before ops.Fail.
	wsGood, err := wsSvc.Create(ctx, workspaces.CreateInput{
		RepositoryID: fx.repo.ID, OwnerID: fx.owner.ID, ModelRoute: "approved-code-review",
		BaseCommit: fx.bareRepo.HeadSHA, TargetRef: "refs/heads/main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create(wsGood): %v", err)
	}
	_, cleanRunner := newTestWorkflowRunner(t, fx, nil, nil, nil, workflow.Config{})
	if n, err := cleanRunner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(wsGood ingress): n=%d err=%v", n, err)
	}

	badTar := []byte("not-a-valid-gzip-archive")
	putArt, err := fx.snaps.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "uploads/invalid-reconstruct.tar.gz", badTar)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	gen := int64(1)
	regArt, err := fx.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		ID: putArt.ID, Kind: domain.ArtifactKindEgressSnapshot, SHA256: putArt.SHA256,
		StorageKey: putArt.StorageKey, StorageGeneration: putArt.StorageGeneration, SizeBytes: putArt.SizeBytes,
		Format: "application/gzip", WorkspaceID: &wsGood.Workspace.ID, WorkspaceGeneration: &gen, UploadedBy: &fx.owner.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact: %v", err)
	}

	propSvc := proposals.NewService(fx.store, nil, nil)
	sub, err := propSvc.Submit(ctx, proposals.SubmitInput{
		WorkspaceID: wsGood.Workspace.ID, WorkspaceGeneration: 1,
		SnapshotArtifactID: regArt.ID, SnapshotSHA256: domain.SHA256Hex(badTar),
		SizeBytes: int64(len(badTar)), Title: "Invalid Archive Proposal",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if n, err := cleanRunner.ProcessOnce(ctx); err != nil || n != 1 {
		t.Fatalf("ProcessOnce(reconstruct fail): n=%d err=%v", n, err)
	}

	propAfter, err := propSvc.Get(ctx, sub.Proposal.ID)
	if err != nil {
		t.Fatalf("propSvc.Get: %v", err)
	}
	if propAfter.Status != domain.ProposalStatusFailed {
		t.Fatalf("expected proposal FAILED, got %s", propAfter.Status)
	}
	reconOpAfter, err := fx.store.GetOperationByID(ctx, sub.Operation.ID)
	if err != nil {
		t.Fatalf("GetOperationByID(reconstruct): %v", err)
	}
	if reconOpAfter.Status != domain.OperationStatusFailed {
		t.Fatalf("expected PROPOSAL_RECONSTRUCT operation FAILED (trigger passes), got %s (last_error=%q)", reconOpAfter.Status, derefStr(reconOpAfter.LastError))
	}
}
