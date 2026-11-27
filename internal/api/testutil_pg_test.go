package api_test

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

	validator "github.com/pb33f/libopenapi-validator"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workspaces"
)

type fakeRefResolver struct {
	mu       sync.RWMutex
	refs     map[string]string
	err      error
	delay    time.Duration
	panicMsg string
}

func (f *fakeRefResolver) SetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeRefResolver) SetDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
}

func (f *fakeRefResolver) SetPanic(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panicMsg = msg
}

func (f *fakeRefResolver) ResolveRef(ctx context.Context, _ domain.Repository, ref string) (string, error) {
	f.mu.RLock()
	delay := f.delay
	err := f.err
	panicMsg := f.panicMsg
	sha, ok := f.refs[ref]
	f.mu.RUnlock()
	if panicMsg != "" {
		panic(panicMsg)
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err != nil {
		return "", err
	}
	if ok {
		return sha, nil
	}
	return "", domain.NotFound("REF_NOT_FOUND", "git ref not found: "+ref)
}

type apiTestEnv struct {
	t            testing.TB
	pg           *harness.PostgresHarness
	oidc         *harness.MockOIDC
	store        *persistence.Store
	snapshots    *harness.SnapshotHarness
	caps         *auth.CapabilityService
	dir          *identity.Directory
	refResolver  *fakeRefResolver
	repos        *repositories.Service
	workspaces   *workspaces.Service
	operations   *operations.Service
	audit        *audit.Service
	artifacts    *artifacts.Service
	proposals    *proposals.Service
	approvals    *approvals.Service
	policyEngine *policy.Engine
	metrics      *observability.Metrics
	router       http.Handler
	repo         repositories.Record
	policyBundle persistence.PolicyBundleRow
}

func newAPITestEnv(t testing.TB, depsOverride func(*api.Deps)) *apiTestEnv {
	t.Helper()
	ctx := context.Background()

	pg := harness.StartPostgres(t)
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
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
		Secret:     []byte("custodian-m4d-test-capability-secret-32b"),
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

	snapHarness := harness.NewSnapshotHarness(t)
	metrics, err := observability.NewMetrics(observability.MetricsConfig{
		Namespace: "custodian",
	})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	policyEngine, err := policy.NewEngine(policy.WithMetrics(metrics), policy.WithLogger(logger))
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}

	// Load and seed default policy bundle into PG.
	defaultPolicyBytes, err := os.ReadFile(filepath.Join("..", "..", "policies", "defaults", "default.yaml"))
	if err != nil {
		t.Fatalf("read default policy: %v", err)
	}
	parsedBundle, valErrs := policy.ParseBundle(defaultPolicyBytes)
	if len(valErrs) > 0 {
		t.Fatalf("ParseBundle: %+v", valErrs)
	}
	defJSON, bundleDigest, err := policy.CanonicalBundleJSON(parsedBundle)
	if err != nil {
		t.Fatalf("CanonicalBundleJSON: %v", err)
	}
	now := time.Now().UTC()
	scope := parsedBundle.Metadata.Scope
	if scope == "" {
		scope = domain.PolicyScopeOrg
	}
	bundleRow, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		ID:          domain.MustNewID(),
		Name:        parsedBundle.Metadata.Name,
		Version:     parsedBundle.Metadata.Version,
		Scope:       scope,
		Digest:      bundleDigest,
		Definition:  defJSON,
		ActivatedAt: &now,
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest: %v", err)
	}

	reposSvc := repositories.NewService(store, logger)
	wsSvc := workspaces.NewService(store, metrics, logger)
	opsSvc := operations.NewService(store, metrics, logger)
	auditSvc := audit.NewService(store, logger)
	artifactsSvc := artifacts.NewService(store, logger)
	propsSvc := proposals.NewService(store, metrics, logger)
	approvalsSvc := approvals.NewService(store, metrics, logger)

	repoRec, err := reposSvc.Upsert(ctx, repositories.UpsertInput{
		ID:                      domain.MustNewID(),
		GitHubRepositoryID:      1001,
		GitHubInstallationID:    2001,
		FullName:                "acme/custodian-demo",
		Classification:          domain.ClassificationInternal,
		Enabled:                 true,
		AllowedModelRoutes:      []string{"openai/gpt-5", "anthropic/claude-sonnet-4-6"},
		MaxConcurrentOperations: 4,
	})
	if err != nil {
		t.Fatalf("repositories.Upsert: %v", err)
	}

	refResolver := &fakeRefResolver{
		refs: map[string]string{
			"main":       strings.Repeat("a", 40),
			"refs/main":  strings.Repeat("a", 40),
			"feature/ok": strings.Repeat("b", 40),
		},
	}

	deps := api.Deps{
		Store:                store,
		OIDC:                 verifier,
		Capabilities:         capSvc,
		Directory:            dir,
		Snapshots:            snapHarness.Store(),
		GitHubRead:           refResolver,
		Repositories:         reposSvc,
		Workspaces:           wsSvc,
		Operations:           opsSvc,
		Audit:                auditSvc,
		Artifacts:            artifactsSvc,
		Proposals:            propsSvc,
		Approvals:            approvalsSvc,
		PolicyEngine:         policyEngine,
		Metrics:              metrics,
		Logger:               logger,
		BaseURL:              "http://127.0.0.1:8080",
		RepoConcurrencyLimit: 4,
		GlobalScanBudget:     10,
		GlobalModelBudget:    10,
		MaxUploadBytes:       1 << 20,
		CapabilityTTL:        5 * time.Minute,
		ArtifactRetentionTTL: 24 * time.Hour,
		MaxDiffBytes:         1 << 20,
	}
	if depsOverride != nil {
		depsOverride(&deps)
	}

	return &apiTestEnv{
		t:            t,
		pg:           pg,
		oidc:         oidc,
		store:        store,
		snapshots:    snapHarness,
		caps:         capSvc,
		dir:          dir,
		refResolver:  refResolver,
		repos:        reposSvc,
		workspaces:   wsSvc,
		operations:   opsSvc,
		audit:        auditSvc,
		artifacts:    artifactsSvc,
		proposals:    propsSvc,
		approvals:    approvalsSvc,
		policyEngine: policyEngine,
		metrics:      metrics,
		router:       api.NewRouter(deps),
		repo:         repoRec,
		policyBundle: bundleRow,
	}
}

func (e *apiTestEnv) mintHuman(sub, email string, groups []string, roles []string, scopes string) string {
	verified := true
	return e.oidc.MintToken(harness.OIDCTokenClaims{
		Subject:       sub,
		Kind:          "HUMAN",
		Email:         email,
		EmailVerified: &verified,
		DisplayName:   sub,
		Groups:        groups,
		Roles:         roles,
		Scope:         scopes,
	})
}

func (e *apiTestEnv) mintController(sub string) string {
	return e.oidc.MintControllerToken(sub, "controller")
}

func (e *apiTestEnv) mintAuditor(sub string) string {
	verified := true
	return e.oidc.MintToken(harness.OIDCTokenClaims{
		Subject:       sub,
		Kind:          "AUDITOR",
		Email:         sub + "@acme.test",
		EmailVerified: &verified,
		Roles:         []string{"auditor"},
	})
}

func (e *apiTestEnv) mintPolicyAdmin(sub string) string {
	verified := true
	return e.oidc.MintToken(harness.OIDCTokenClaims{
		Subject:       sub,
		Kind:          "POLICY_ADMIN",
		Email:         sub + "@acme.test",
		EmailVerified: &verified,
		Roles:         []string{"policy_admin"},
	})
}

func (e *apiTestEnv) do(method, path, token, idemKey string, body any, extraHeaders map[string]string, v validator.Validator) *httptest.ResponseRecorder {
	e.t.Helper()
	var bodyBytes []byte
	if body != nil {
		switch tv := body.(type) {
		case []byte:
			bodyBytes = tv
		case string:
			bodyBytes = []byte(tv)
		default:
			var err error
			bodyBytes, err = json.Marshal(tv)
			if err != nil {
				e.t.Fatalf("marshal request body: %v", err)
			}
		}
	}

	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, bytes.NewReader(bodyBytes))
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	for k, val := range extraHeaders {
		req.Header.Set(k, val)
	}

	if v != nil {
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		valid, errs := v.ValidateHttpRequestSync(req)
		if !valid {
			e.t.Fatalf("OpenAPI request validation failed for %s %s: %+v", method, path, errs)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)

	if v != nil {
		resp := rec.Result()
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		valid, errs := v.ValidateHttpResponse(req, resp)
		if !valid {
			e.t.Fatalf("OpenAPI response validation failed for %s %s (status=%d, body=%s): %+v", method, path, rec.Code, string(respBody), errs)
		}
	}
	return rec
}

// seedReadyWorkspaceAndProposal creates a READY workspace with a real tarball source artifact,
// an uploaded EGRESS_SNAPSHOT artifact, and a SUBMITTED proposal.
func (e *apiTestEnv) seedWorkspaceAndProposal(ctx context.Context, ownerID uuid.UUID, ownerToken, ctrlToken string) (wsID uuid.UUID, propID uuid.UUID, snapshotID uuid.UUID, snapshotSHA string) {
	e.t.Helper()

	srcBytes := []byte("tarball-source-bytes")
	srcArt, err := e.snapshots.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "workspaces/"+domain.MustNewID().String()+"/source.tar.gz", srcBytes)
	if err != nil {
		e.t.Fatalf("PutBytes source: %v", err)
	}
	srcReg, err := e.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                domain.MustNewID(),
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            srcArt.SHA256,
		SizeBytes:         int64(len(srcBytes)),
		Format:            "tar.gz",
		StorageKey:        srcArt.StorageKey,
		StorageGeneration: srcArt.StorageGeneration,
		UploadedBy:        &ownerID,
	})
	if err != nil {
		e.t.Fatalf("Register source artifact: %v", err)
	}

	wsRes, err := e.workspaces.Create(ctx, workspaces.CreateInput{
		RepositoryID: e.repo.ID,
		OwnerID:      ownerID,
		BaseCommit:   strings.Repeat("a", 40),
		TargetRef:    "main",
	})
	if err != nil {
		e.t.Fatalf("workspaces.Create: %v", err)
	}
	if _, err := e.workspaces.AttachSourceArtifact(ctx, wsRes.Workspace.ID, srcReg.ID, domain.WorkspaceStatusReady); err != nil {
		e.t.Fatalf("AttachSourceArtifact: %v", err)
	}
	if _, err := e.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = NOW(), updated_at = NOW() WHERE id = $1`, wsRes.Operation.ID); err != nil {
		e.t.Fatalf("complete seeded workspace ingress op: %v", err)
	}

	snapBytes := []byte("egress-snapshot-bytes")
	snapArt, err := e.snapshots.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "workspaces/"+wsRes.Workspace.ID.String()+"/gen1/snap.tar.gz", snapBytes)
	if err != nil {
		e.t.Fatalf("PutBytes egress: %v", err)
	}
	ctrlCaller, err := e.dir.ResolveCaller(ctx, mustVerifyToken(e.t, e.oidc, ctrlToken))
	if err != nil {
		e.t.Fatalf("ResolveCaller ctrl: %v", err)
	}
	snapReg, err := e.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                domain.MustNewID(),
		Kind:              domain.ArtifactKindEgressSnapshot,
		SHA256:            snapArt.SHA256,
		SizeBytes:         int64(len(snapBytes)),
		Format:            "tar.gz",
		StorageKey:        snapArt.StorageKey,
		StorageGeneration: snapArt.StorageGeneration,
		UploadedBy:        &ctrlCaller.Principal.ID,
	})
	if err != nil {
		e.t.Fatalf("Register egress artifact: %v", err)
	}

	capturedAt := time.Now().UTC()
	propRes, err := e.proposals.Submit(ctx, proposals.SubmitInput{
		WorkspaceID:         wsRes.Workspace.ID,
		ActorID:             &ctrlCaller.Principal.ID,
		SnapshotArtifactID:  snapReg.ID,
		SnapshotSHA256:      snapReg.SHA256,
		WorkspaceGeneration: 1,
		SizeBytes:           int64(len(snapBytes)),
		CapturedAt:          &capturedAt,
		Title:               "Fix issue #1",
		Description:         "Seeded proposal",
		ProvenanceType:      "human_authored",
		CaptureMethod:       "frozen_filesystem",
	})
	if err != nil {
		e.t.Fatalf("proposals.Submit: %v", err)
	}

	_ = ownerToken
	return wsRes.Workspace.ID, propRes.Proposal.ID, snapReg.ID, snapReg.SHA256
}

func (e *apiTestEnv) seedReconstructed(ctx context.Context, propID, actorID uuid.UUID) (canonicalID uuid.UUID, manifestDigest string, prop domain.Proposal) {
	e.t.Helper()
	var err error
	prop, err = e.proposals.Get(ctx, propID)
	if err != nil {
		e.t.Fatalf("proposals.Get: %v", err)
	}
	prop, err = e.proposals.BeginReconstruction(ctx, proposals.BeginReconstructionInput{
		ProposalID:      propID,
		ExpectedVersion: prop.Version,
		ActorID:         &actorID,
	})
	if err != nil {
		e.t.Fatalf("BeginReconstruction: %v", err)
	}

	canonicalBytes := []byte("canonical-tree-tar")
	canonicalArt, err := e.snapshots.PutBytes(ctx, domain.ArtifactKindCanonicalTree, "reconstruct/"+propID.String()+"/tree.tar.gz", canonicalBytes)
	if err != nil {
		e.t.Fatalf("PutBytes canonical: %v", err)
	}
	canonicalReg, err := e.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                domain.MustNewID(),
		Kind:              domain.ArtifactKindCanonicalTree,
		SHA256:            canonicalArt.SHA256,
		SizeBytes:         int64(len(canonicalBytes)),
		Format:            "tar.gz",
		StorageKey:        canonicalArt.StorageKey,
		StorageGeneration: canonicalArt.StorageGeneration,
		UploadedBy:        &actorID,
	})
	if err != nil {
		e.t.Fatalf("Register canonical: %v", err)
	}

	diffBytes := []byte("diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n")
	diffArt, err := e.snapshots.PutBytes(ctx, domain.ArtifactKindCanonicalDiff, "reconstruct/"+propID.String()+"/diff.patch", diffBytes)
	if err != nil {
		e.t.Fatalf("PutBytes diff: %v", err)
	}
	diffReg, err := e.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                domain.MustNewID(),
		Kind:              domain.ArtifactKindCanonicalDiff,
		SHA256:            diffArt.SHA256,
		SizeBytes:         int64(len(diffBytes)),
		Format:            "patch",
		StorageKey:        diffArt.StorageKey,
		StorageGeneration: diffArt.StorageGeneration,
		UploadedBy:        &actorID,
	})
	if err != nil {
		e.t.Fatalf("Register diff: %v", err)
	}

	fileSHA := domain.SHA256Hex([]byte("new\n"))
	treeDigest := domain.SHA256Hex([]byte("tree-digest"))
	manifestObj := reconstruct.PublicationManifest{
		SchemaVersion:       "1.0",
		BaseCommit:          strings.Repeat("a", 40),
		TreeDigest:          treeDigest,
		CanonicalTreeSHA256: canonicalReg.SHA256,
		DiffDigest:          diffReg.SHA256,
		FileCount:           1,
		TotalBytes:          4,
		Changes: []reconstruct.ChangedFile{
			{
				Path:       "README.md",
				ChangeType: "MODIFIED",
				SizeBytes:  4,
				SHA256:     fileSHA,
			},
		},
	}
	manifestBytes, err := json.Marshal(manifestObj)
	if err != nil {
		e.t.Fatalf("marshal PublicationManifest: %v", err)
	}
	manifestArt, err := e.snapshots.PutBytes(ctx, domain.ArtifactKindPublicationManifest, "reconstruct/"+propID.String()+"/manifest.json", manifestBytes)
	if err != nil {
		e.t.Fatalf("PutBytes manifest: %v", err)
	}
	manifestReg, err := e.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                domain.MustNewID(),
		Kind:              domain.ArtifactKindPublicationManifest,
		SHA256:            manifestArt.SHA256,
		SizeBytes:         int64(len(manifestBytes)),
		Format:            "json",
		StorageKey:        manifestArt.StorageKey,
		StorageGeneration: manifestArt.StorageGeneration,
		UploadedBy:        &actorID,
	})
	if err != nil {
		e.t.Fatalf("Register manifest: %v", err)
	}

	prop, err = e.proposals.CompleteReconstruction(ctx, proposals.CompleteReconstructionInput{
		ProposalID:          propID,
		ExpectedVersion:     prop.Version,
		CanonicalArtifactID: canonicalReg.ID,
		DiffArtifactID:      &diffReg.ID,
		ManifestArtifactID:  manifestReg.ID,
		TreeDigest:          treeDigest,
		DiffDigest:          diffReg.SHA256,
		ManifestDigest:      manifestReg.SHA256,
		ActorID:             &actorID,
	})
	if err != nil {
		e.t.Fatalf("CompleteReconstruction: %v", err)
	}
	if _, err := e.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = NOW(), updated_at = NOW() WHERE resource_id = $1 AND operation_type = 'PROPOSAL_RECONSTRUCT' AND status IN ('PENDING', 'RUNNING')`, propID); err != nil {
		e.t.Fatalf("complete seeded reconstruct op: %v", err)
	}
	return canonicalReg.ID, manifestReg.SHA256, prop
}

func (e *apiTestEnv) seedReconstructedAndEvaluated(ctx context.Context, propID, actorID uuid.UUID, effect domain.PolicyEffect, obligations []domain.Obligation) (manifestDigest string, policyDecisionID uuid.UUID) {
	e.t.Helper()
	canonicalID, manifestDigest, prop := e.seedReconstructed(ctx, propID, actorID)

	// Seed a scan run + finding + model assessment.
	now := time.Now().UTC()
	scanRun, err := e.store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		ID:             domain.MustNewID(),
		ProposalID:     propID,
		ArtifactID:     canonicalID,
		Scanner:        "gitleaks",
		ScannerVersion: "8.18.0",
		Status:         domain.ScanStatusCompleted,
		Coverage: domain.ScanCoverage{
			FilesExamined: 1,
			FilesSkipped:  0,
			BytesExamined: 4,
			Complete:      true,
		},
		StartedAt:   now,
		CompletedAt: &now,
	})
	if err != nil {
		e.t.Fatalf("CreateScanRun: %v", err)
	}
	line := 1
	if _, err := e.store.CreateFinding(ctx, persistence.CreateFindingParams{
		ID:          domain.MustNewID(),
		ScanRunID:   scanRun.ID,
		EvidenceID:  "ev-1",
		Scanner:     "gitleaks",
		Category:    "secret",
		Severity:    domain.SeverityLow,
		RuleID:      "generic-rule",
		Path:        "README.md",
		StartLine:   &line,
		EndLine:     &line,
		Fingerprint: domain.SHA256Hex([]byte("fp-1")),
		EvidenceRef: "README.md:1",
		Baseline:    "new",
		Message:     "benign test finding",
		Redacted:    true,
	}); err != nil {
		e.t.Fatalf("CreateFinding: %v", err)
	}

	if _, err := e.store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		ID:             domain.MustNewID(),
		ProposalID:     propID,
		ArtifactID:     canonicalID,
		ModelRoute:     "openai/gpt-5",
		ModelVersion:   "gpt-5-2026",
		PromptVersion:  "v1",
		AssessmentType: "security_review",
		Status:         domain.AssessmentStatusComplete,
		Risk:           domain.RiskLevelLow,
		Disposition:    domain.DispositionClear,
		Result: domain.AssessmentResult{
			SchemaVersion:  "1.0",
			AssessmentType: "security_review",
			Risk:           domain.RiskLevelLow,
			Disposition:    domain.DispositionClear,
			Confidence:     0.95,
			Summary:        "Clean change",
			Findings: []domain.AssessmentFinding{
				{Category: "quality", EvidenceIDs: []string{"ev-1"}, Reason: "Minor doc edit", RecommendedAction: "NONE"},
			},
			Limitations: []string{},
		},
		EvidenceIDs:  []string{"ev-1"},
		InputDigest:  domain.SHA256Hex([]byte("model-in")),
		OutputDigest: domain.SHA256Hex([]byte("model-out")),
		CreatedAt:    now,
	}); err != nil {
		e.t.Fatalf("CreateModelAssessment: %v", err)
	}

	prop, err = e.proposals.BeginEvaluation(ctx, propID, prop.Version)
	if err != nil {
		e.t.Fatalf("BeginEvaluation: %v", err)
	}

	prop, err = e.proposals.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID:      propID,
		ExpectedVersion: prop.Version,
		PolicyBundleID:  e.policyBundle.ID,
		Stage:           "EGRESS",
		InputDigest:     domain.SHA256Hex([]byte("policy-in")),
		Effect:          effect,
		Reasons: []domain.PolicyReason{
			{RuleID: "rule-1", Effect: effect, Stage: "EGRESS", Message: "evaluated"},
		},
		Obligations: obligations,
		ActorID:     &actorID,
	})
	if err != nil {
		e.t.Fatalf("ApplyPolicyDecision: %v", err)
	}

	latest, err := e.store.GetLatestPolicyDecisionForProposal(ctx, propID)
	if err != nil {
		e.t.Fatalf("GetLatestPolicyDecisionForProposal: %v", err)
	}
	return manifestDigest, latest.ID
}

func mustVerifyToken(t testing.TB, oidc *harness.MockOIDC, raw string) auth.VerifiedClaims {
	t.Helper()
	v, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   oidc.Issuer(),
		JWKSURL:  oidc.JWKSURL(),
		Audience: oidc.Audience(),
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	claims, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify token: %v", err)
	}
	return claims
}
