package fixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/publish"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/publication"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workflow"
	"github.com/timreynolds/custodian/internal/workspaces"
)

type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// StackConfig customizes NewFullStack.
type StackConfig struct {
	Classification       domain.Classification
	AllowedModelRoutes   []string
	RepoConcurrencyLimit int
	GlobalScanBudget     int
	GlobalModelBudget    int
	MaxConcurrentOps     int
	ArtifactRetentionTTL time.Duration
	RoutePolicy          *decisions.RoutePolicy
	RepoPolicyYAML       string
}

// StackOption mutates StackConfig.
type StackOption func(*StackConfig)

func WithRepoPolicy(yamlStr string) StackOption {
	return func(s *StackConfig) { s.RepoPolicyYAML = yamlStr }
}

func WithClassification(c domain.Classification) StackOption {
	return func(s *StackConfig) { s.Classification = c }
}

func WithAllowedRoutes(routes ...string) StackOption {
	return func(s *StackConfig) { s.AllowedModelRoutes = append([]string(nil), routes...) }
}

func WithLimits(repoConc, globalScan, globalModel int) StackOption {
	return func(s *StackConfig) {
		s.RepoConcurrencyLimit = repoConc
		s.GlobalScanBudget = globalScan
		s.GlobalModelBudget = globalModel
		if repoConc > 0 {
			s.MaxConcurrentOps = repoConc
		}
	}
}

func WithRetentionTTL(ttl time.Duration) StackOption {
	return func(s *StackConfig) { s.ArtifactRetentionTTL = ttl }
}

func WithRoutePolicy(rp *decisions.RoutePolicy) StackOption {
	return func(s *StackConfig) { s.RoutePolicy = rp }
}

// FullStack bundles real PG17-backed Custodian services, HTTP API, worker, publisher, and offline harnesses.
type FullStack struct {
	T            testing.TB
	PG           *harness.PostgresHarness
	Store        *persistence.Store
	OIDC         *harness.MockOIDC
	Git          *harness.BareGitHarness
	BareRepo     harness.BareRepo
	WriteClient  *write.LocalBareClient
	Snapshots    *harness.SnapshotHarness
	Scanners     *StubScannerController
	Gateway      *MockGateway
	Directory    *identity.Directory
	Repos        *repositories.Service
	Workspaces   *workspaces.Service
	Proposals    *proposals.Service
	Approvals    *approvals.Service
	Operations   *operations.Service
	Audit        *audit.Service
	Artifacts    *artifacts.Service
	PolicyEngine *policy.Engine
	WorkflowSvc  *workflow.Service
	WorkerRunner *workflow.Runner
	PubSvc       *publication.Service
	PubRunner    *publication.Runner
	Router       http.Handler
	Server       *httptest.Server
	Repo         repositories.Record
	Logs         *syncLogBuffer
}

// NewFullStack boots an isolated PG17-backed Custodian stack with zero external cloud dependencies.
func NewFullStack(t testing.TB, opts ...StackOption) *FullStack {
	t.Helper()
	cfg := StackConfig{
		Classification:       domain.ClassificationInternal,
		AllowedModelRoutes:   []string{"approved-code-review"},
		RepoConcurrencyLimit: 5,
		GlobalScanBudget:     10,
		GlobalModelBudget:    10,
		MaxConcurrentOps:     5,
		ArtifactRetentionTTL: 720 * time.Hour,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	pg := harness.StartPostgres(t, harness.WithPGAllowDockerSkip(true))
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(store.Close)

	logBuf := &syncLogBuffer{}
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    logBuf,
		Format:    observability.LogFormatJSON,
		Level:     slog.LevelDebug,
		Component: "custodian-test-stack",
	})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	oidc := harness.StartMockOIDC(t, "custodian-api")
	verifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   oidc.Issuer(),
		JWKSURL:  oidc.JWKSURL(),
		Audience: oidc.Audience(),
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	capSvc, err := auth.NewCapabilityService(auth.CapabilityConfig{
		Secret:     []byte("custodian-tier5-test-capability-secret-32b"),
		DefaultTTL: 5 * time.Minute,
		MaxTTL:     15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewCapabilityService: %v", err)
	}

	dir, err := identity.NewDirectory(store, identity.DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	gitH := harness.NewBareGitHarness(t, "")
	bareRepo, err := gitH.InitBareRepo("acme", "custodian-app", harness.WithInitialFiles(map[string]string{
		"README.md": "# Custodian App\n",
		"main.go":   "package main\n\nfunc main() {}\n",
	}))
	if err != nil {
		t.Fatalf("InitBareRepo: %v", err)
	}
	writeClient := write.NewLocalBareClient(write.WithBareRootDir(gitH.RootDir()), write.WithLogger(logger))
	if err := writeClient.RegisterRepo(bareRepo.GitHubRepositoryID, bareRepo.FullName, bareRepo.BarePath); err != nil {
		t.Fatalf("RegisterRepo: %v", err)
	}

	snaps := harness.NewSnapshotHarness(t)
	scanners := NewStubScanners(t)
	gw := StartMockGateway(t)

	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{BaseURL: gw.Server.URL})
	if err != nil {
		t.Fatalf("NewHTTPGatewayClient: %v", err)
	}
	var decOpts []decisions.ServiceOption
	decOpts = append(decOpts, decisions.WithLogger(logger), decisions.WithMetrics(metrics))
	if cfg.RoutePolicy != nil {
		decOpts = append(decOpts, decisions.WithRoutePolicy(cfg.RoutePolicy))
	}
	decSvc, err := decisions.NewService(gwClient, decOpts...)
	if err != nil {
		t.Fatalf("decisions.NewService: %v", err)
	}

	polEngine, err := policy.NewEngine(policy.WithMetrics(metrics), policy.WithLogger(logger))
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}

	ctx := context.Background()
	repoRoot := FindRepoRoot(t)
	if _, err := workflow.SyncPolicyDir(ctx, store, polEngine, filepath.Join(repoRoot, "policies", "defaults"), time.Now().UTC()); err != nil {
		t.Fatalf("SyncPolicyDir: %v", err)
	}

	reposSvc := repositories.NewService(store, logger)
	wsSvc := workspaces.NewService(store, metrics, logger)
	opsSvc := operations.NewService(store, metrics, logger, operations.Config{DefaultLeaseDuration: 15 * time.Second})
	audSvc := audit.NewService(store, logger)
	artSvc := artifacts.NewService(store, logger)
	propSvc := proposals.NewService(store, metrics, logger)
	appSvc := approvals.NewService(store, metrics, logger)

	repoRec, err := reposSvc.Upsert(ctx, repositories.UpsertInput{
		ID:                      domain.MustNewID(),
		GitHubRepositoryID:      bareRepo.GitHubRepositoryID,
		GitHubInstallationID:    bareRepo.InstallationID,
		FullName:                bareRepo.FullName,
		Classification:          cfg.Classification,
		Enabled:                 true,
		AllowedModelRoutes:      cfg.AllowedModelRoutes,
		MaxConcurrentOperations: cfg.MaxConcurrentOps,
	})
	if err != nil {
		t.Fatalf("reposSvc.Upsert: %v", err)
	}
	if cfg.RepoPolicyYAML != "" {
		compiled, errs := polEngine.Compile([]byte(cfg.RepoPolicyYAML))
		if len(errs) > 0 {
			t.Fatalf("compile RepoPolicyYAML: %+v", errs)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if _, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name:         compiled.Bundle.Metadata.Name,
			Version:      compiled.Bundle.Metadata.Version,
			Scope:        domain.PolicyScopeRepo,
			RepositoryID: &repoRec.ID,
			Digest:       compiled.Digest,
			Definition:   compiled.Definition,
			ActivatedAt:  &now,
			CreatedAt:    now,
		}); err != nil {
			t.Fatalf("UpsertPolicyBundleByDigest RepoPolicyYAML: %v", err)
		}
	}

	reconSvc, err := reconstruct.NewService(reconstruct.Config{
		GitReader:     gitH.LocalReader(),
		SnapshotStore: snaps.Store(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("reconstruct.NewService: %v", err)
	}

	inspRunner := inspection.NewRunner(scanners.Config)
	wfCfg := workflow.Config{
		WorkerID:             "stack-worker-1",
		LeaseDuration:        15 * time.Second,
		ArtifactRetentionTTL: cfg.ArtifactRetentionTTL,
		GlobalScanBudget:     cfg.GlobalScanBudget,
		GlobalModelBudget:    cfg.GlobalModelBudget,
		RepoConcurrencyLimit: cfg.RepoConcurrencyLimit,
	}
	wfSvc, err := workflow.NewService(workflow.ServiceConfig{
		Store:            store,
		SnapshotStore:    snaps.Store(),
		GitReader:        gitH.LocalReader(),
		Reconstructor:    reconSvc,
		InspectionRunner: inspRunner,
		Decisions:        decSvc,
		PolicyEngine:     polEngine,
		Logger:           logger,
		Metrics:          metrics,
		Config:           wfCfg,
	})
	if err != nil {
		t.Fatalf("workflow.NewService: %v", err)
	}
	wfRunner, err := workflow.NewRunner(workflow.RunnerConfig{Service: wfSvc, Config: wfCfg})
	if err != nil {
		t.Fatalf("workflow.NewRunner: %v", err)
	}

	opener, closeOpener, err := publication.NewArtifactOpener(ctx, publication.ArtifactOpenerConfig{
		StoreKind:    "local",
		LocalRootDir: snaps.RootDir(),
		Logger:       logger,
	})
	if err != nil {
		t.Fatalf("NewArtifactOpener: %v", err)
	}
	t.Cleanup(func() { _ = closeOpener() })

	gitPub, err := publish.NewService(publish.Config{
		WriteClient:    writeClient,
		ArtifactOpener: opener,
		CommitterName:  "Custodian",
		CommitterEmail: "custodian@custodian.local",
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("publish.NewService: %v", err)
	}
	pubSvc, err := publication.NewService(store, gitPub, metrics, logger)
	if err != nil {
		t.Fatalf("publication.NewService: %v", err)
	}
	pubRunner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:           opsSvc,
		Service:       pubSvc,
		WorkerID:      "stack-pub-1",
		LeaseDuration: 15 * time.Second,
		Logger:        logger,
		Metrics:       metrics,
	})
	if err != nil {
		t.Fatalf("publication.NewRunner: %v", err)
	}

	router := api.NewRouter(api.Deps{
		Store:                store,
		OIDC:                 verifier,
		Capabilities:         capSvc,
		Directory:            dir,
		Snapshots:            snaps.Store(),
		GitHubRead:           gitH.LocalReader(),
		Repositories:         reposSvc,
		Workspaces:           wsSvc,
		Operations:           opsSvc,
		Audit:                audSvc,
		Artifacts:            artSvc,
		Proposals:            propSvc,
		Approvals:            appSvc,
		PolicyEngine:         polEngine,
		Metrics:              metrics,
		Logger:               logger,
		RepoConcurrencyLimit: cfg.RepoConcurrencyLimit,
		GlobalScanBudget:     cfg.GlobalScanBudget,
		GlobalModelBudget:    cfg.GlobalModelBudget,
		MaxUploadBytes:       16 << 20,
		CapabilityTTL:        5 * time.Minute,
		ArtifactRetentionTTL: cfg.ArtifactRetentionTTL,
		MaxDiffBytes:         4 << 20,
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &FullStack{
		T:            t,
		PG:           pg,
		Store:        store,
		OIDC:         oidc,
		Git:          gitH,
		BareRepo:     bareRepo,
		WriteClient:  writeClient,
		Snapshots:    snaps,
		Scanners:     scanners,
		Gateway:      gw,
		Directory:    dir,
		Repos:        reposSvc,
		Workspaces:   wsSvc,
		Proposals:    propSvc,
		Approvals:    appSvc,
		Operations:   opsSvc,
		Audit:        audSvc,
		Artifacts:    artSvc,
		PolicyEngine: polEngine,
		WorkflowSvc:  wfSvc,
		WorkerRunner: wfRunner,
		PubSvc:       pubSvc,
		PubRunner:    pubRunner,
		Router:       router,
		Server:       srv,
		Repo:         repoRec,
		Logs:         logBuf,
	}
}

func (s *FullStack) MintHuman(sub, email string, groups, roles []string) string {
	s.T.Helper()
	ev := true
	return s.OIDC.MintToken(harness.OIDCTokenClaims{
		Subject:       sub,
		Kind:          "HUMAN",
		Email:         email,
		EmailVerified: &ev,
		DisplayName:   sub,
		Groups:        groups,
		Roles:         roles,
		Scope:         "openid profile email",
	})
}

func (s *FullStack) MintController(sub string) string {
	s.T.Helper()
	return s.OIDC.MintToken(harness.OIDCTokenClaims{
		Subject: sub,
		Kind:    "CONTROLLER",
		Roles:   []string{"controller"},
		Scope:   "workspace:control",
	})
}

func (s *FullStack) MintAuditor(sub string) string {
	s.T.Helper()
	verified := true
	return s.OIDC.MintToken(harness.OIDCTokenClaims{
		Subject:       sub,
		Kind:          "AUDITOR",
		Email:         sub + "@acme.test",
		EmailVerified: &verified,
		Roles:         []string{"auditor"},
		Scope:         "audit:read",
	})
}

func (s *FullStack) DoJSON(method, path, token, idemKey string, body any, extraHeaders map[string]string) (int, []byte) {
	s.T.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.T.Fatalf("json.Marshal: %v", err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.Server.URL+path, r)
	if err != nil {
		s.T.Fatalf("NewRequest(%s %s): %v", method, path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.T.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		s.T.Fatalf("ReadAll: %v", err)
	}
	return resp.StatusCode, raw
}

func (s *FullStack) DrainWorker(ctx context.Context) {
	s.T.Helper()
	for i := 0; i < 16; i++ {
		n, err := s.WorkerRunner.ProcessOnce(ctx)
		if err != nil {
			s.T.Fatalf("WorkerRunner.ProcessOnce: %v", err)
		}
		if n == 0 {
			return
		}
	}
}

func (s *FullStack) DrainPublisher(ctx context.Context) {
	s.T.Helper()
	for i := 0; i < 8; i++ {
		n, err := s.PubRunner.ProcessOnce(ctx)
		if err != nil {
			s.T.Fatalf("PubRunner.ProcessOnce: %v", err)
		}
		if n == 0 {
			return
		}
	}
}

// CreateReadyWorkspaceAndUploadProposal runs ingress, downloads source descriptor, uploads snapshot via capability token,
// submits proposal, runs reconstruction, and returns (wsID, propID, manifestDigest, version).
func (s *FullStack) CreateReadyWorkspaceAndSubmit(
	ctx context.Context,
	humanTok, ctrlTok string,
	entries []TarEntrySpec,
) (wsID, propID, manifestDigest string, propVersion int64) {
	s.T.Helper()
	code, raw := s.DoJSON(http.MethodPost, "/v1/workspaces", humanTok, "ws-"+uuid.NewString(), map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": s.Repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}, nil)
	if code != http.StatusAccepted {
		s.T.Fatalf("POST /v1/workspaces expected 202, got %d: %s", code, string(raw))
	}
	var wsResp struct {
		WorkspaceID string `json:"workspace_id"`
	}
	_ = json.Unmarshal(raw, &wsResp)
	wsID = wsResp.WorkspaceID

	s.DrainWorker(ctx)

	code, descRaw := s.DoJSON(http.MethodGet, "/v1/workspaces/"+wsID+"/source", ctrlTok, "", nil, nil)
	if code != http.StatusOK {
		s.T.Fatalf("GET /source expected 200, got %d: %s", code, string(descRaw))
	}
	var desc struct {
		Generation       int64 `json:"generation"`
		UploadCapability struct {
			Token     string `json:"token"`
			UploadURL string `json:"upload_url"`
		} `json:"upload_capability"`
	}
	_ = json.Unmarshal(descRaw, &desc)

	gz := BuildTarGz(s.T, entries)
	shaHex := domain.SHA256Hex(gz)

	uploadURL := desc.UploadCapability.UploadURL
	if strings.HasPrefix(uploadURL, "http://127.0.0.1:8080") {
		uploadURL = s.Server.URL + strings.TrimPrefix(uploadURL, "http://127.0.0.1:8080")
	} else if strings.HasPrefix(uploadURL, "/") {
		uploadURL = s.Server.URL + uploadURL
	}
	upReq, err := http.NewRequest(http.MethodPut, uploadURL, bytes.NewReader(gz))
	if err != nil {
		s.T.Fatalf("NewRequest PUT upload: %v", err)
	}
	upReq.Header.Set("Authorization", "Bearer "+desc.UploadCapability.Token)
	upReq.Header.Set("Content-Type", "application/gzip")
	upReq.Header.Set("X-Content-SHA256", shaHex)
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		s.T.Fatalf("PUT upload: %v", err)
	}
	upRaw, _ := io.ReadAll(upResp.Body)
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated && upResp.StatusCode != http.StatusOK {
		s.T.Fatalf("PUT upload expected 200/201, got %d: %s", upResp.StatusCode, string(upRaw))
	}
	var upOut struct {
		ArtifactID string `json:"artifact_id"`
		SHA256     string `json:"sha256"`
	}
	_ = json.Unmarshal(upRaw, &upOut)

	code, subRaw := s.DoJSON(http.MethodPost, "/v1/workspaces/"+wsID+"/proposals", ctrlTok, "sub-"+uuid.NewString(), map[string]any{
		"snapshot": map[string]any{
			"artifact_id":          upOut.ArtifactID,
			"sha256":               upOut.SHA256,
			"workspace_generation": desc.Generation,
			"size_bytes":           len(gz),
		},
		"title": "Fixture Proposal",
	}, nil)
	if code != http.StatusAccepted {
		s.T.Fatalf("POST /proposals expected 202, got %d: %s", code, string(subRaw))
	}
	var subOut struct {
		ProposalID string `json:"proposal_id"`
	}
	_ = json.Unmarshal(subRaw, &subOut)
	propID = subOut.ProposalID

	s.DrainWorker(ctx)

	code, propRaw := s.DoJSON(http.MethodGet, "/v1/proposals/"+propID, humanTok, "", nil, nil)
	if code != http.StatusOK {
		s.T.Fatalf("GET /proposals/{id} expected 200, got %d: %s", code, string(propRaw))
	}
	var propOut struct {
		PublicationManifestDigest string `json:"publication_manifest_digest"`
		Version                   int64  `json:"version"`
	}
	_ = json.Unmarshal(propRaw, &propOut)
	return wsID, propID, propOut.PublicationManifestDigest, propOut.Version
}

// VerifyRepoBundleLoaded reads a policy bundle from the repository root.
func VerifyRepoBundleLoaded(t testing.TB, relPath string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(FindRepoRoot(t), relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return b
}
