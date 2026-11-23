package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func TestOperationalHealthReadyMetrics(t *testing.T) {
	env := newAPITestEnv(t, nil)

	rec := env.do(http.MethodGet, "/healthz", "", "", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = env.do(http.MethodGet, "/readyz", "", "", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = env.do(http.MethodGet, "/metrics", "", "", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "custodian_") {
		t.Fatalf("expected prometheus custodian_ metrics, got: %.200s", rec.Body.String())
	}

	// Closing PG pool makes /readyz return 503.
	env.pg.Pool().Close()
	rec = env.do(http.MethodGet, "/readyz", "", "", nil, nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with closed DB expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSourceDescriptorArtifactDownloadAndCapabilityUpload(t *testing.T) {
	ctx := context.Background()
	const maxUpload = int64(256)
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.MaxUploadBytes = maxUpload
	})

	humanA := env.mintHuman("human-a", "alice@acme.test", nil, []string{"developer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-1")
	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	// Seed READY workspace with source artifact.
	rawSource := []byte("source-archive-contents-0123456789")
	srcStored, err := env.snapshots.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "workspaces/src/tree.tar.gz", rawSource)
	if err != nil {
		t.Fatalf("PutBytes source: %v", err)
	}
	srcArt, err := env.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                domain.MustNewID(),
		Kind:              domain.ArtifactKindWorkspaceSource,
		SHA256:            srcStored.SHA256,
		SizeBytes:         int64(len(rawSource)),
		Format:            "tar.gz",
		StorageKey:        srcStored.StorageKey,
		StorageGeneration: srcStored.StorageGeneration,
		UploadedBy:        &humanACaller.Principal.ID,
	})
	if err != nil {
		t.Fatalf("Register source: %v", err)
	}
	wsRes, err := env.workspaces.Create(ctx, workspaces.CreateInput{
		RepositoryID: env.repo.ID,
		OwnerID:      humanACaller.Principal.ID,
		BaseCommit:   strings.Repeat("a", 40),
		TargetRef:    "main",
	})
	if err != nil {
		t.Fatalf("workspaces.Create: %v", err)
	}
	if _, err := env.workspaces.AttachSourceArtifact(ctx, wsRes.Workspace.ID, srcArt.ID, domain.WorkspaceStatusReady); err != nil {
		t.Fatalf("AttachSourceArtifact: %v", err)
	}

	// GET /source by CONTROLLER returns descriptor; by Human returns 403.
	rec := env.do(http.MethodGet, "/v1/workspaces/"+wsRes.Workspace.ID.String()+"/source", humanA, "", nil, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("human GET /source expected 403, got %d", rec.Code)
	}

	rec = env.do(http.MethodGet, "/v1/workspaces/"+wsRes.Workspace.ID.String()+"/source", ctrlToken, "", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("controller GET /source expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var desc api.SourceArtifactDescriptorDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("unmarshal SourceArtifactDescriptorDTO: %v", err)
	}

	// Capability token MUST be rejected on /v1/* endpoints.
	rec = env.do(http.MethodGet, "/v1/workspaces/"+wsRes.Workspace.ID.String(), desc.UploadCapability.Token, "", nil, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("capability token on /v1/workspaces/{id} expected 401, got %d", rec.Code)
	}

	// Download artifact via descriptor URL (strip scheme+host).
	dlPath := strings.TrimPrefix(desc.Download.URL, "http://127.0.0.1:8080")
	rec = env.do(http.MethodGet, dlPath, humanA, "", nil, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("human GET %s expected 403, got %d", dlPath, rec.Code)
	}
	rec = env.do(http.MethodGet, dlPath, ctrlToken, "", nil, nil, nil)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), rawSource) {
		t.Fatalf("controller GET %s expected 200 with exact source bytes, got %d len=%d", dlPath, rec.Code, rec.Body.Len())
	}

	// Upload capability path.
	upPath := strings.TrimPrefix(desc.UploadCapability.UploadURL, "http://127.0.0.1:8080")

	// GET on upload URL MUST return 405 and never leak bytes.
	rec = env.do(http.MethodGet, upPath, desc.UploadCapability.Token, "", nil, nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on upload URL expected 405, got %d", rec.Code)
	}

	// Oversized PUT (> maxUpload) MUST return 413 and store ZERO bytes in SnapshotStore!
	tooBig := bytes.Repeat([]byte("X"), int(maxUpload)+50)
	req := httptest.NewRequest(http.MethodPut, desc.UploadCapability.UploadURL, bytes.NewReader(tooBig))
	req.Header.Set("Authorization", "Bearer "+desc.UploadCapability.Token)
	req.Header.Set("Content-Type", "application/gzip")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
	egressDir := filepath.Join(env.snapshots.RootDir(), string(domain.ArtifactKindEgressSnapshot))
	var foundFiles []string
	if _, statErr := os.Stat(egressDir); statErr == nil {
		_ = filepath.WalkDir(egressDir, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr == nil && !d.IsDir() {
				foundFiles = append(foundFiles, p)
			}
			return nil
		})
	}
	if len(foundFiles) > 0 {
		t.Fatalf("expected ZERO files persisted on oversized upload, found: %v", foundFiles)
	}

	// Valid PUT succeeds with 201 and attributes UploadedBy to controller principal.
	validPayload := []byte("valid-egress-snapshot-tarball-payload")
	req = httptest.NewRequest(http.MethodPut, desc.UploadCapability.UploadURL, bytes.NewReader(validPayload))
	req.Header.Set("Authorization", "Bearer "+desc.UploadCapability.Token)
	req.Header.Set("Content-Type", "application/gzip")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid capability upload expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var upResp api.UploadSnapshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &upResp); err != nil {
		t.Fatalf("unmarshal UploadSnapshotResponse: %v", err)
	}
	if upResp.SHA256 != domain.SHA256Hex(validPayload) || upResp.SizeBytes != int64(len(validPayload)) {
		t.Fatalf("unexpected upload response: %+v", upResp)
	}
	artID, _ := uuid.Parse(upResp.ArtifactID)
	artRec, err := env.artifacts.GetByID(ctx, artID)
	if err != nil {
		t.Fatalf("artifacts.GetByID: %v", err)
	}
	if artRec.Kind != domain.ArtifactKindEgressSnapshot || artRec.UploadedBy == nil || *artRec.UploadedBy != ctrlCaller.Principal.ID {
		t.Fatalf("unexpected artifact provenance: kind=%s uploadedBy=%v want=%s", artRec.Kind, artRec.UploadedBy, ctrlCaller.Principal.ID)
	}
}

func TestWorkspaceErrorsLimitsAndHistoryAuditDenial(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.RepoConcurrencyLimit = 1
	})

	humanNoHist := env.mintHuman("human-nohist", "nohist@acme.test", nil, []string{"developer"}, "openid profile email")
	humanHist := env.mintHuman("human-hist", "hist@acme.test", nil, []string{"developer"}, "openid profile email repo:history")
	auditorToken := env.mintAuditor("auditor-1")

	// Unauthorized include_history: true -> 403 AND audit denial event persisted!
	rec := env.do(http.MethodPost, "/v1/workspaces", humanNoHist, "ws-hist-deny", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"},
		"source_options": map[string]any{
			"include_git_metadata": true,
			"include_history":      true,
		},
	}, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthorized include_history, got %d", rec.Code)
	}

	auditRec := env.do(http.MethodGet, "/v1/audit/events?event_type=workspace.history_denied", auditorToken, "", nil, nil, nil)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit/events expected 200, got %d", auditRec.Code)
	}
	var auditList api.AuditEventsListResponse
	_ = json.Unmarshal(auditRec.Body.Bytes(), &auditList)
	if len(auditList.Events) == 0 {
		t.Fatal("expected workspace.history_denied audit event to be persisted")
	}

	// Disallowed model_route -> 403
	rec = env.do(http.MethodPost, "/v1/workspaces", humanNoHist, "ws-bad-route", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"},
		"agent":      map[string]any{"type": "codex", "session_id": "s1", "model_route": "rogue/unknown-model"},
	}, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed model_route, got %d: %s", rec.Code, rec.Body.String())
	}

	// Nonexistent ref -> 422
	rec = env.do(http.MethodPost, "/v1/workspaces", humanNoHist, "ws-bad-ref", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "does-not-exist"},
	}, nil, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for nonexistent Git ref, got %d: %s", rec.Code, rec.Body.String())
	}

	// GitHub API outage -> 503
	env.refResolver.SetError(domain.Unavailable("GITHUB_UNAVAILABLE", "github api down"))
	rec = env.do(http.MethodPost, "/v1/workspaces", humanNoHist, "ws-gh-outage", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"},
	}, nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on GitHub outage, got %d: %s", rec.Code, rec.Body.String())
	}
	env.refResolver.SetError(nil)

	// Authorized include_history: true succeeds (creates 1 active operation -> fills RepoConcurrencyLimit=1).
	rec = env.do(http.MethodPost, "/v1/workspaces", humanHist, "ws-hist-ok", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"},
		"source_options": map[string]any{
			"include_git_metadata": true,
			"include_history":      true,
		},
	}, nil, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for authorized include_history, got %d: %s", rec.Code, rec.Body.String())
	}

	// Second concurrent workspace creation on same repo hits RepoConcurrencyLimit=1 -> 429 + Retry-After: 1.
	rec = env.do(http.MethodPost, "/v1/workspaces", humanNoHist, "ws-concurrency-429", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"},
	}, nil, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when repo concurrency limit exceeded, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429 response")
	}

	// Disabled repo -> 403.
	disabledRepo, err := env.repos.Upsert(ctx, repositories.UpsertInput{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   9999,
		GitHubInstallationID: 9999,
		FullName:             "acme/disabled",
		Classification:       domain.ClassificationInternal,
		Enabled:              false,
	})
	if err != nil {
		t.Fatalf("Upsert disabled repo: %v", err)
	}
	rec = env.do(http.MethodPost, "/v1/workspaces", humanNoHist, "ws-disabled-repo", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": disabledRepo.GitHubRepositoryID, "ref": "main"},
	}, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled repository, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEvaluateVersionBudgetsApprovalsRBACAndAuditPagination(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.GlobalScanBudget = 1
		d.GlobalModelBudget = 1
	})

	humanA := env.mintHuman("human-a", "alice@acme.test", []string{"eng"}, []string{"developer"}, "openid profile email")
	humanB := env.mintHuman("human-b", "bob@acme.test", []string{"security-reviewers"}, []string{"reviewer"}, "openid profile email")
	humanC := env.mintHuman("human-c", "carol@acme.test", []string{"other"}, []string{"developer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-1")
	auditorToken := env.mintAuditor("auditor-1")
	policyAdminToken := env.mintPolicyAdmin("poladmin-1")

	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	wsID, propID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)

	// HumanC (unrelated) cannot read HumanA's workspace or proposal!
	if rec := env.do(http.MethodGet, "/v1/workspaces/"+wsID.String(), humanC, "", nil, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("unrelated HumanC GET workspace expected 403, got %d", rec.Code)
	}
	if rec := env.do(http.MethodGet, "/v1/proposals/"+propID.String(), humanC, "", nil, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("unrelated HumanC GET proposal expected 403, got %d", rec.Code)
	}
	// PolicyAdmin / Auditor cannot read HumanA's proposal or create workspaces.
	if rec := env.do(http.MethodPost, "/v1/workspaces", auditorToken, "aud-ws", map[string]any{"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"}}, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("auditor POST /workspaces expected 403, got %d", rec.Code)
	}
	// Non-AUDITOR cannot query audit events; non-POLICY_ADMIN cannot validate/evaluate policies.
	if rec := env.do(http.MethodGet, "/v1/audit/events", humanA, "", nil, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("human GET /audit/events expected 403, got %d", rec.Code)
	}
	if rec := env.do(http.MethodPost, "/v1/policies/validate", humanA, "", map[string]any{"bundle_yaml": "x"}, nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("human POST /policies/validate expected 403, got %d", rec.Code)
	}
	_ = policyAdminToken

	// Reconstruct propID so it is eligible for evaluation.
	_, _, evalProp := env.seedReconstructed(ctx, propID, ctrlCaller.Principal.ID)

	// If-Match mismatch -> 409
	rec := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-ifmatch-bad", nil, map[string]string{"If-Match": `"99"`}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("evaluate with stale If-Match expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// Empty body evaluate with matching If-Match succeeds (202).
	rec = env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-empty-ok", nil, map[string]string{"If-Match": `"` + strconv.FormatInt(evalProp.Version, 10) + `"`}, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("evaluate with empty body and If-Match expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	// Second evaluate while active PROPOSAL_EVALUATE operation exists hits GlobalScanBudget=1 -> 429 + Retry-After!
	rec = env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-budget-429", nil, nil, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("evaluate exceeding global scan budget expected 429, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After on budget 429")
	}

	// Seed a second proposal evaluated as DENIED -> self-approval 403, publish 409 with policy_decision_id!
	_, deniedPropID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	manifestDigest, decisionID := env.seedReconstructedAndEvaluated(ctx, deniedPropID, ctrlCaller.Principal.ID, domain.PolicyEffectDeny, nil)

	// Owner self-approval rejected (SoD).
	rec = env.do(http.MethodPost, "/v1/proposals/"+deniedPropID.String()+"/approvals", humanA, "self-approve", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        decisionID.String(),
	}, nil, nil)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusConflict {
		t.Fatalf("owner self-approval expected 403/409, got %d: %s", rec.Code, rec.Body.String())
	}
	// Wrong reviewer group rejected.
	_ = humanB

	// Publish on DENIED proposal MUST return 409 with error.policy_decision_id.
	rec = env.do(http.MethodPost, "/v1/proposals/"+deniedPropID.String()+"/publish", ctrlToken, "pub-denied-policy", map[string]any{
		"publication_manifest_digest": manifestDigest,
	}, nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("publish on DENIED proposal expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp api.ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	if errResp.Error.PolicyDecisionID == nil || *errResp.Error.PolicyDecisionID != decisionID.String() {
		t.Fatalf("expected error.policy_decision_id=%s, got %v", decisionID, errResp.Error.PolicyDecisionID)
	}

	// Audit events cursor pagination: must be strictly ascending chain_seq & disjoint!
	seenIDs := make(map[string]bool)
	var allEventIDs []string
	cursor := ""
	for page := 0; page < 20; page++ {
		path := "/v1/audit/events?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		aRec := env.do(http.MethodGet, path, auditorToken, "", nil, nil, nil)
		if aRec.Code != http.StatusOK {
			t.Fatalf("audit page %d expected 200, got %d: %s", page, aRec.Code, aRec.Body.String())
		}
		var pageResp api.AuditEventsListResponse
		if err := json.Unmarshal(aRec.Body.Bytes(), &pageResp); err != nil {
			t.Fatalf("unmarshal audit page: %v", err)
		}
		for _, ev := range pageResp.Events {
			if seenIDs[ev.ID] {
				t.Fatalf("duplicate audit event ID across cursor pages: %s", ev.ID)
			}
			seenIDs[ev.ID] = true
			allEventIDs = append(allEventIDs, ev.ID)
		}
		if !pageResp.HasMore {
			break
		}
		if pageResp.NextCursor == nil || *pageResp.NextCursor == "" {
			t.Fatal("has_more=true but next_cursor missing")
		}
		cursor = *pageResp.NextCursor
	}
	if len(allEventIDs) < 3 {
		t.Fatalf("expected >= 3 audit events, got %d", len(allEventIDs))
	}
	// Verify DB ascending chain_seq order matches returned API order.
	dbEvents, err := env.store.ListAllAuditEventsOrdered(ctx)
	if err != nil {
		t.Fatalf("ListAllAuditEventsOrdered: %v", err)
	}
	if len(allEventIDs) != len(dbEvents) {
		t.Fatalf("paginated event count %d != DB total %d", len(allEventIDs), len(dbEvents))
	}
	for i := range dbEvents {
		if i > 0 && dbEvents[i].ChainSeq <= dbEvents[i-1].ChainSeq {
			t.Fatalf("expected ascending chain_seq at idx %d: %d <= %d", i, dbEvents[i].ChainSeq, dbEvents[i-1].ChainSeq)
		}
		if allEventIDs[i] != dbEvents[i].ID.String() {
			t.Fatalf("audit order mismatch at idx %d: API %s != DB %s (seq %d)", i, allEventIDs[i], dbEvents[i].ID, dbEvents[i].ChainSeq)
		}
	}
}

func TestIdempotencyAcrossAll5MutatingPOSTs(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, nil)

	humanA := env.mintHuman("human-a", "alice@acme.test", nil, []string{"developer"}, "openid profile email")
	humanB := env.mintHuman("human-b", "bob@acme.test", []string{"security-reviewers"}, []string{"reviewer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-1")

	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	// Missing Idempotency-Key -> 400
	rec := env.do(http.MethodPost, "/v1/workspaces", humanA, "", map[string]any{
		"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"},
	}, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing Idempotency-Key expected 400, got %d", rec.Code)
	}

	// 1. POST /v1/workspaces replay & mismatch
	wsPayload := map[string]any{"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "main"}}
	r1 := env.do(http.MethodPost, "/v1/workspaces", humanA, "idem-ws-1", wsPayload, nil, nil)
	r2 := env.do(http.MethodPost, "/v1/workspaces", humanA, "idem-ws-1", wsPayload, nil, nil)
	if r1.Code != http.StatusAccepted || r2.Code != http.StatusAccepted {
		t.Fatalf("workspace idempotency replay status mismatch: r1=%d r2=%d", r1.Code, r2.Code)
	}
	assertJSONEqual(t, r1.Body.Bytes(), r2.Body.Bytes())
	r3 := env.do(http.MethodPost, "/v1/workspaces", humanA, "idem-ws-1", map[string]any{"repository": map[string]any{"provider": "github", "repository_id": env.repo.GitHubRepositoryID, "ref": "feature/ok"}}, nil, nil)
	if r3.Code != http.StatusConflict {
		t.Fatalf("workspace idempotency payload mismatch expected 409, got %d", r3.Code)
	}

	// Seed ready workspace + snapshot for remaining 4 mutating POSTs.
	wsID, propSeedID, snapID, snapSHA := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)

	// 2. POST /v1/workspaces/{id}/proposals
	ws2Res, _ := env.workspaces.Create(ctx, workspaces.CreateInput{
		RepositoryID: env.repo.ID,
		OwnerID:      humanACaller.Principal.ID, BaseCommit: strings.Repeat("a", 40), TargetRef: "main",
	})
	_, _ = env.workspaces.TransitionStatus(ctx, ws2Res.Workspace.ID, domain.WorkspaceStatusPending, domain.WorkspaceStatusReady)
	_, _ = env.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = NOW(), updated_at = NOW() WHERE id = $1`, ws2Res.Operation.ID)
	subBody := map[string]any{
		"title":      "Idem submit",
		"snapshot":   map[string]any{"artifact_id": snapID.String(), "sha256": snapSHA, "workspace_generation": 1, "size_bytes": 21, "captured_at": time.Now().UTC().Format(time.RFC3339)},
		"provenance": map[string]any{"type": "human_authored", "capture_method": "frozen_filesystem"},
	}
	_ = wsID
	s1 := env.do(http.MethodPost, "/v1/workspaces/"+ws2Res.Workspace.ID.String()+"/proposals", ctrlToken, "idem-sub-1", subBody, nil, nil)
	s2 := env.do(http.MethodPost, "/v1/workspaces/"+ws2Res.Workspace.ID.String()+"/proposals", ctrlToken, "idem-sub-1", subBody, nil, nil)
	s3 := env.do(http.MethodPost, "/v1/workspaces/"+ws2Res.Workspace.ID.String()+"/proposals", ctrlToken, "idem-sub-1", map[string]any{
		"title": "Different", "snapshot": subBody["snapshot"], "provenance": subBody["provenance"],
	}, nil, nil)
	if s1.Code != http.StatusAccepted || s2.Code != http.StatusAccepted || s3.Code != http.StatusConflict {
		t.Fatalf("submit idempotency failed: s1=%d s2=%d s3=%d", s1.Code, s2.Code, s3.Code)
	}
	assertJSONEqual(t, s1.Body.Bytes(), s2.Body.Bytes())
	var subResp api.SubmitProposalResponse
	_ = json.Unmarshal(s1.Body.Bytes(), &subResp)

	// 3. POST /v1/proposals/{id}/evaluate
	subPropUUID, _ := uuid.Parse(subResp.ProposalID)
	_, _, evalProp := env.seedReconstructed(ctx, subPropUUID, ctrlCaller.Principal.ID)
	e1 := env.do(http.MethodPost, "/v1/proposals/"+subResp.ProposalID+"/evaluate", ctrlToken, "idem-eval-1", map[string]any{"expected_version": evalProp.Version}, nil, nil)
	e2 := env.do(http.MethodPost, "/v1/proposals/"+subResp.ProposalID+"/evaluate", ctrlToken, "idem-eval-1", map[string]any{"expected_version": evalProp.Version}, nil, nil)
	e3 := env.do(http.MethodPost, "/v1/proposals/"+subResp.ProposalID+"/evaluate", ctrlToken, "idem-eval-1", map[string]any{"expected_version": evalProp.Version + 1}, nil, nil)
	if e1.Code != http.StatusAccepted || e2.Code != http.StatusAccepted || e3.Code != http.StatusConflict {
		t.Fatalf("evaluate idempotency failed: e1=%d e2=%d e3=%d", e1.Code, e2.Code, e3.Code)
	}
	assertJSONEqual(t, e1.Body.Bytes(), e2.Body.Bytes())

	// 4. POST /v1/proposals/{id}/approvals + 5. POST /v1/proposals/{id}/publish
	manifestDigest, decisionID := env.seedReconstructedAndEvaluated(ctx, propSeedID, ctrlCaller.Principal.ID, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "REQUIRE_APPROVAL", ReviewerGroup: "security-reviewers", Minimum: 1},
	})
	appBody := map[string]any{"decision": "APPROVE", "publication_manifest_digest": manifestDigest, "policy_evaluation_id": decisionID.String()}
	a1 := env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/approvals", humanB, "idem-app-1", appBody, nil, nil)
	a2 := env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/approvals", humanB, "idem-app-1", appBody, nil, nil)
	a3 := env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/approvals", humanB, "idem-app-1", map[string]any{"decision": "REJECT", "publication_manifest_digest": manifestDigest, "policy_evaluation_id": decisionID.String()}, nil, nil)
	if a1.Code != http.StatusCreated || a2.Code != http.StatusCreated || a3.Code != http.StatusConflict {
		t.Fatalf("approval idempotency failed: a1=%d a2=%d a3=%d", a1.Code, a2.Code, a3.Code)
	}
	assertJSONEqual(t, a1.Body.Bytes(), a2.Body.Bytes())

	p1 := env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/publish", ctrlToken, "idem-pub-1", map[string]any{"publication_manifest_digest": manifestDigest}, nil, nil)
	p2 := env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/publish", ctrlToken, "idem-pub-1", map[string]any{"publication_manifest_digest": manifestDigest}, nil, nil)
	p3 := env.do(http.MethodPost, "/v1/proposals/"+propSeedID.String()+"/publish", ctrlToken, "idem-pub-1", map[string]any{"publication_manifest_digest": strings.Repeat("f", 64)}, nil, nil)
	if p1.Code != http.StatusAccepted || p2.Code != http.StatusAccepted || p3.Code != http.StatusConflict {
		t.Fatalf("publish idempotency failed: p1=%d p2=%d p3=%d", p1.Code, p2.Code, p3.Code)
	}
	assertJSONEqual(t, p1.Body.Bytes(), p2.Body.Bytes())
}

func assertJSONEqual(t testing.TB, want, got []byte) {
	t.Helper()
	var wVal, gVal any
	if err := json.Unmarshal(want, &wVal); err != nil {
		t.Fatalf("unmarshal want JSON: %v (%s)", err, string(want))
	}
	if err := json.Unmarshal(got, &gVal); err != nil {
		t.Fatalf("unmarshal got JSON: %v (%s)", err, string(got))
	}
	if !reflect.DeepEqual(wVal, gVal) {
		t.Fatalf("replayed JSON mismatch:\nwant=%s\ngot=%s", string(want), string(got))
	}
}

func TestConcurrentWorkspaceLimitBarrier(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.RepoConcurrencyLimit = 2
	})
	// Align repository max_concurrent_operations=2 as well.
	if _, err := env.repos.Upsert(ctx, repositories.UpsertInput{
		ID:                      env.repo.ID,
		GitHubRepositoryID:      env.repo.GitHubRepositoryID,
		GitHubInstallationID:    env.repo.GitHubInstallationID,
		FullName:                env.repo.FullName,
		Classification:          env.repo.Classification,
		Enabled:                 true,
		AllowedModelRoutes:      env.repo.AllowedModelRoutes,
		MaxConcurrentOperations: 2,
	}); err != nil {
		t.Fatalf("repos.Upsert: %v", err)
	}
	env.refResolver.SetDelay(40 * time.Millisecond)

	humanA := env.mintHuman("human-burst", "burst@acme.test", nil, []string{"developer"}, "openid profile email")
	payload := map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}

	const n = 5
	gate := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-gate
			results[idx] = env.do(http.MethodPost, "/v1/workspaces", humanA, fmt.Sprintf("ws-burst-%d", idx), payload, nil, nil)
		}(i)
	}
	close(gate)
	wg.Wait()

	admitted := 0
	rateLimited := 0
	for i, rec := range results {
		switch rec.Code {
		case http.StatusAccepted:
			admitted++
		case http.StatusTooManyRequests:
			rateLimited++
			if rec.Header().Get("Retry-After") == "" {
				t.Fatalf("burst[%d]: expected Retry-After header on 429 response", i)
			}
		default:
			t.Fatalf("burst[%d]: unexpected status %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	if admitted < 1 || admitted > 2 {
		t.Fatalf("expected 1..2 admitted requests under limit=2, got admitted=%d rateLimited=%d", admitted, rateLimited)
	}
	if rateLimited < 3 {
		t.Fatalf("expected >= 3 rate-limited 429 responses under limit=2, got admitted=%d rateLimited=%d", admitted, rateLimited)
	}

	active, err := env.store.CountActiveOperationsByRepository(ctx, env.repo.ID)
	if err != nil {
		t.Fatalf("CountActiveOperationsByRepository: %v", err)
	}
	if active != int64(admitted) || active > 2 {
		t.Fatalf("expected active operations == %d (<=2), got %d", admitted, active)
	}
}

func TestConcurrentEvaluateGlobalBudgetBarrier(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.GlobalScanBudget = 1
		d.GlobalModelBudget = 1
	})

	humanA := env.mintHuman("human-eval", "eval@acme.test", nil, []string{"developer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-eval")
	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	_, prop1ID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	_, _, prop1 := env.seedReconstructed(ctx, prop1ID, ctrlCaller.Principal.ID)
	_, prop2ID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	_, _, prop2 := env.seedReconstructed(ctx, prop2ID, ctrlCaller.Principal.ID)

	props := []struct {
		id  uuid.UUID
		ver int64
	}{
		{id: prop1.ID, ver: prop1.Version},
		{id: prop2.ID, ver: prop2.Version},
	}

	gate := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, len(props))

	for i, p := range props {
		wg.Add(1)
		go func(idx int, propID uuid.UUID, ver int64) {
			defer wg.Done()
			<-gate
			results[idx] = env.do(
				http.MethodPost,
				"/v1/proposals/"+propID.String()+"/evaluate",
				ctrlToken,
				fmt.Sprintf("eval-burst-%d", idx),
				map[string]any{"expected_version": ver},
				nil,
				nil,
			)
		}(i, p.id, p.ver)
	}
	close(gate)
	wg.Wait()

	admitted := 0
	rateLimited := 0
	for i, rec := range results {
		switch rec.Code {
		case http.StatusAccepted:
			admitted++
		case http.StatusTooManyRequests:
			rateLimited++
			if rec.Header().Get("Retry-After") == "" {
				t.Fatalf("eval[%d]: expected Retry-After header on 429", i)
			}
		default:
			t.Fatalf("eval[%d]: unexpected status %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	if admitted != 1 || rateLimited != 1 {
		t.Fatalf("expected exactly 1 admitted (202) and 1 rejected (429) under GlobalScanBudget=1, got admitted=%d rateLimited=%d", admitted, rateLimited)
	}
}

func TestIdempotencyRetryAfterHandlerErrorAndIfMatchConflict(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.RepoConcurrencyLimit = 1
	})

	humanA := env.mintHuman("human-idem", "idem@acme.test", nil, []string{"developer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-idem")
	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	wsPayload := map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}

	// 1. Immediate retry with same Idempotency-Key after 503 GITHUB_UNAVAILABLE succeeds cleanly (202).
	env.refResolver.SetError(domain.Unavailable("GITHUB_UNAVAILABLE", "github api down"))
	r503 := env.do(http.MethodPost, "/v1/workspaces", humanA, "retry-after-503", wsPayload, nil, nil)
	if r503.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on GitHub outage, got %d: %s", r503.Code, r503.Body.String())
	}
	env.refResolver.SetError(nil)
	rAfter503 := env.do(http.MethodPost, "/v1/workspaces", humanA, "retry-after-503", wsPayload, nil, nil)
	if rAfter503.Code != http.StatusAccepted {
		t.Fatalf("expected 202 on immediate retry after 503, got %d: %s", rAfter503.Code, rAfter503.Body.String())
	}

	// 2. Immediate retry with same Idempotency-Key after 429 REPO_CONCURRENCY_LIMIT_EXCEEDED returns 429 (NEVER 409 IDEMPOTENCY_IN_PROGRESS).
	r429 := env.do(http.MethodPost, "/v1/workspaces", humanA, "retry-after-429", wsPayload, nil, nil)
	if r429.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when repo concurrency limit exceeded, got %d: %s", r429.Code, r429.Body.String())
	}
	rAfter429 := env.do(http.MethodPost, "/v1/workspaces", humanA, "retry-after-429", wsPayload, nil, nil)
	if rAfter429.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 (not 409 IDEMPOTENCY_IN_PROGRESS) on immediate retry after 429, got %d: %s", rAfter429.Code, rAfter429.Body.String())
	}
	var errResp api.ErrorResponse
	_ = json.Unmarshal(rAfter429.Body.Bytes(), &errResp)
	if errResp.Error.Code != "REPO_CONCURRENCY_LIMIT_EXCEEDED" {
		t.Fatalf("expected REPO_CONCURRENCY_LIMIT_EXCEEDED on retry, got %q", errResp.Error.Code)
	}

	// Complete the earlier workspace ingress operation from step 1 before testing step 3 on the same RepoConcurrencyLimit=1 repository.
	var wsCreatedResp api.CreateWorkspaceResponse
	_ = json.Unmarshal(rAfter503.Body.Bytes(), &wsCreatedResp)
	if wsCreatedResp.OperationID != "" {
		opID, _ := uuid.Parse(wsCreatedResp.OperationID)
		_, _ = env.pg.Pool().Exec(ctx, `UPDATE operations SET status = 'SUCCEEDED', completed_at = NOW(), updated_at = NOW() WHERE id = $1`, opID)
	}

	// 3. Reusing Idempotency-Key on POST /v1/proposals/{id}/evaluate with different or missing If-Match returns 409 IDEMPOTENCY_CONFLICT.
	_, propID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	_, _, evalProp := env.seedReconstructed(ctx, propID, ctrlCaller.Principal.ID)
	ifMatchVal := `"` + strconv.FormatInt(evalProp.Version, 10) + `"`

	e1 := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-ifmatch-idem", nil, map[string]string{"If-Match": ifMatchVal}, nil)
	if e1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 on initial evaluate with If-Match, got %d: %s", e1.Code, e1.Body.String())
	}
	eReplay := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-ifmatch-idem", nil, map[string]string{"If-Match": ifMatchVal}, nil)
	if eReplay.Code != http.StatusAccepted {
		t.Fatalf("expected 202 on exact If-Match replay, got %d: %s", eReplay.Code, eReplay.Body.String())
	}
	assertJSONEqual(t, e1.Body.Bytes(), eReplay.Body.Bytes())

	eDiffHeader := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-ifmatch-idem", nil, map[string]string{"If-Match": `"99"`}, nil)
	if eDiffHeader.Code != http.StatusConflict {
		t.Fatalf("expected 409 IDEMPOTENCY_CONFLICT on different If-Match header, got %d: %s", eDiffHeader.Code, eDiffHeader.Body.String())
	}
	var diffErr api.ErrorResponse
	_ = json.Unmarshal(eDiffHeader.Body.Bytes(), &diffErr)
	if diffErr.Error.Code != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("expected IDEMPOTENCY_CONFLICT, got %q", diffErr.Error.Code)
	}

	eNoHeader := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-ifmatch-idem", nil, nil, nil)
	if eNoHeader.Code != http.StatusConflict {
		t.Fatalf("expected 409 IDEMPOTENCY_CONFLICT when If-Match omitted on replay, got %d: %s", eNoHeader.Code, eNoHeader.Body.String())
	}
}

func TestIdempotencyPanicReleasesReservation(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, nil)

	humanA := env.mintHuman("human-panic", "panic@acme.test", nil, []string{"developer"}, "openid profile email")
	wsPayload := map[string]any{
		"repository": map[string]any{
			"provider":      "github",
			"repository_id": env.repo.GitHubRepositoryID,
			"ref":           "main",
		},
	}

	// Force a panic inside runIdempotent handler (via RefResolver.ResolveRef).
	env.refResolver.SetPanic("simulated handler panic inside runIdempotent")
	rPanic := env.do(http.MethodPost, "/v1/workspaces", humanA, "idem-panic-1", wsPayload, nil, nil)
	if rPanic.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError from recoverMiddleware on handler panic, got %d: %s", rPanic.Code, rPanic.Body.String())
	}
	var panicErr api.ErrorResponse
	if err := json.Unmarshal(rPanic.Body.Bytes(), &panicErr); err != nil {
		t.Fatalf("unmarshal 500 panic response: %v", err)
	}
	if panicErr.Error.Code != "INTERNAL_ERROR" {
		t.Fatalf("expected INTERNAL_ERROR on panic, got %q", panicErr.Error.Code)
	}

	// Verify defer release() deleted the IN_PROGRESS row from PostgreSQL.
	var remaining int
	if err := env.pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM idempotency_keys WHERE idempotency_key = $1`, "idem-panic-1").Scan(&remaining); err != nil {
		t.Fatalf("query idempotency_keys: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 idempotency_keys rows after panic cleanup, got %d", remaining)
	}

	// Clear panic and immediately retry with the exact same Idempotency-Key -> must succeed (202), NOT 409 IDEMPOTENCY_IN_PROGRESS.
	env.refResolver.SetPanic("")
	rRetry := env.do(http.MethodPost, "/v1/workspaces", humanA, "idem-panic-1", wsPayload, nil, nil)
	if rRetry.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on immediate retry after panic cleanup (not 409 IDEMPOTENCY_IN_PROGRESS), got %d: %s", rRetry.Code, rRetry.Body.String())
	}
}

func TestUTF8RuneBoundariesPG17(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, nil)

	humanA := env.mintHuman("human-utf8-a", "utf8a@acme.test", nil, []string{"developer"}, "openid profile email")
	humanB := env.mintHuman("human-utf8-b", "utf8b@acme.test", []string{"security-reviewers"}, []string{"reviewer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-utf8")

	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	// Seed a READY workspace and uploaded EGRESS_SNAPSHOT for proposal submission tests.
	seedReadyWS := func() (uuid.UUID, uuid.UUID, string) {
		t.Helper()
		srcBytes := []byte("tarball-source-bytes")
		srcArt, err := env.snapshots.PutBytes(ctx, domain.ArtifactKindWorkspaceSource, "workspaces/"+domain.MustNewID().String()+"/source.tar.gz", srcBytes)
		if err != nil {
			t.Fatalf("PutBytes source: %v", err)
		}
		srcReg, err := env.artifacts.Register(ctx, artifacts.RegisterInput{
			ID:                domain.MustNewID(),
			Kind:              domain.ArtifactKindWorkspaceSource,
			SHA256:            srcArt.SHA256,
			SizeBytes:         int64(len(srcBytes)),
			Format:            "tar.gz",
			StorageKey:        srcArt.StorageKey,
			StorageGeneration: srcArt.StorageGeneration,
			UploadedBy:        &humanACaller.Principal.ID,
		})
		if err != nil {
			t.Fatalf("Register source: %v", err)
		}
		wsRes, err := env.workspaces.Create(ctx, workspaces.CreateInput{
			RepositoryID: env.repo.ID,
			OwnerID:      humanACaller.Principal.ID,
			BaseCommit:   strings.Repeat("a", 40),
			TargetRef:    "main",
		})
		if err != nil {
			t.Fatalf("workspaces.Create: %v", err)
		}
		if _, err := env.workspaces.AttachSourceArtifact(ctx, wsRes.Workspace.ID, srcReg.ID, domain.WorkspaceStatusReady); err != nil {
			t.Fatalf("AttachSourceArtifact: %v", err)
		}
		snapBytes := []byte("egress-snapshot-bytes")
		snapArt, err := env.snapshots.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "workspaces/"+wsRes.Workspace.ID.String()+"/gen1/snap.tar.gz", snapBytes)
		if err != nil {
			t.Fatalf("PutBytes egress: %v", err)
		}
		snapReg, err := env.artifacts.Register(ctx, artifacts.RegisterInput{
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
			t.Fatalf("Register egress: %v", err)
		}
		return wsRes.Workspace.ID, snapReg.ID, snapReg.SHA256
	}

	wsID1, snapID1, snapSHA1 := seedReadyWS()
	snapObj := func(id uuid.UUID, sha string) map[string]any {
		return map[string]any{
			"artifact_id":          id.String(),
			"sha256":               sha,
			"workspace_generation": 1,
			"size_bytes":           21,
			"captured_at":          time.Now().UTC().Format(time.RFC3339),
		}
	}

	// 1. Proposal title: 256*'é' (512 UTF-8 bytes) -> 202; 257*'é' -> 400 INVALID_TITLE.
	exactTitle := strings.Repeat("é", 256)
	rec := env.do(http.MethodPost, "/v1/workspaces/"+wsID1.String()+"/proposals", ctrlToken, "utf8-title-256", map[string]any{
		"title":      exactTitle,
		"snapshot":   snapObj(snapID1, snapSHA1),
		"provenance": map[string]any{"type": "human_authored", "capture_method": "frozen_filesystem"},
	}, nil, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for 256*'é' title, got %d: %s", rec.Code, rec.Body.String())
	}
	var propResp1 api.SubmitProposalResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &propResp1); err != nil {
		t.Fatalf("unmarshal propResp1: %v", err)
	}
	p1ID, _ := uuid.Parse(propResp1.ProposalID)
	p1Row, err := env.proposals.Get(ctx, p1ID)
	if err != nil || p1Row.Title != exactTitle {
		t.Fatalf("expected persisted 256*'é' title, err=%v len=%d", err, len(p1Row.Title))
	}

	recOverTitle := env.do(http.MethodPost, "/v1/workspaces/"+wsID1.String()+"/proposals", ctrlToken, "utf8-title-257", map[string]any{
		"title":      strings.Repeat("é", 257),
		"snapshot":   snapObj(snapID1, snapSHA1),
		"provenance": map[string]any{"type": "human_authored", "capture_method": "frozen_filesystem"},
	}, nil, nil)
	if recOverTitle.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 257*'é' title, got %d: %s", recOverTitle.Code, recOverTitle.Body.String())
	}
	var errTitle api.ErrorResponse
	_ = json.Unmarshal(recOverTitle.Body.Bytes(), &errTitle)
	if errTitle.Error.Code != "INVALID_TITLE" {
		t.Fatalf("expected INVALID_TITLE, got %q", errTitle.Error.Code)
	}

	// 2. Proposal description: 8192*'é' (16384 UTF-8 bytes) -> 202; 8193*'é' -> 400 INVALID_DESCRIPTION.
	wsID2, snapID2, snapSHA2 := seedReadyWS()
	exactDesc := strings.Repeat("é", 8192)
	recDesc := env.do(http.MethodPost, "/v1/workspaces/"+wsID2.String()+"/proposals", ctrlToken, "utf8-desc-8192", map[string]any{
		"title":       "Valid UTF-8 description boundary",
		"description": exactDesc,
		"snapshot":    snapObj(snapID2, snapSHA2),
		"provenance":  map[string]any{"type": "human_authored", "capture_method": "frozen_filesystem"},
	}, nil, nil)
	if recDesc.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for 8192*'é' description, got %d: %s", recDesc.Code, recDesc.Body.String())
	}
	var propResp2 api.SubmitProposalResponse
	if err := json.Unmarshal(recDesc.Body.Bytes(), &propResp2); err != nil {
		t.Fatalf("unmarshal propResp2: %v", err)
	}
	p2ID, _ := uuid.Parse(propResp2.ProposalID)
	p2Row, err := env.proposals.Get(ctx, p2ID)
	if err != nil || p2Row.Description != exactDesc {
		t.Fatalf("expected persisted 8192*'é' description, err=%v len=%d", err, len(p2Row.Description))
	}

	recOverDesc := env.do(http.MethodPost, "/v1/workspaces/"+wsID2.String()+"/proposals", ctrlToken, "utf8-desc-8193", map[string]any{
		"title":       "Over limit description",
		"description": strings.Repeat("é", 8193),
		"snapshot":    snapObj(snapID2, snapSHA2),
		"provenance":  map[string]any{"type": "human_authored", "capture_method": "frozen_filesystem"},
	}, nil, nil)
	if recOverDesc.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 8193*'é' description, got %d: %s", recOverDesc.Code, recOverDesc.Body.String())
	}
	var errDesc api.ErrorResponse
	_ = json.Unmarshal(recOverDesc.Body.Bytes(), &errDesc)
	if errDesc.Error.Code != "INVALID_DESCRIPTION" {
		t.Fatalf("expected INVALID_DESCRIPTION, got %q", errDesc.Error.Code)
	}

	// 3. Approval comment: 4096*'é' (8192 UTF-8 bytes) -> 201; 4097*'é' -> 400 COMMENT_TOO_LONG.
	manifestDigest, decisionID := env.seedReconstructedAndEvaluated(ctx, p2ID, ctrlCaller.Principal.ID, domain.PolicyEffectRequireApproval, []domain.Obligation{
		{Type: "REQUIRE_APPROVAL", ReviewerGroup: "security-reviewers", Minimum: 1},
	})

	recOverComment := env.do(http.MethodPost, "/v1/proposals/"+p2ID.String()+"/approvals", humanB, "utf8-comment-4097", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        decisionID.String(),
		"comment":                     strings.Repeat("é", 4097),
	}, nil, nil)
	if recOverComment.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 4097*'é' comment, got %d: %s", recOverComment.Code, recOverComment.Body.String())
	}
	var errComment api.ErrorResponse
	_ = json.Unmarshal(recOverComment.Body.Bytes(), &errComment)
	if errComment.Error.Code != "COMMENT_TOO_LONG" {
		t.Fatalf("expected COMMENT_TOO_LONG, got %q", errComment.Error.Code)
	}

	exactComment := strings.Repeat("é", 4096)
	recComment := env.do(http.MethodPost, "/v1/proposals/"+p2ID.String()+"/approvals", humanB, "utf8-comment-4096", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        decisionID.String(),
		"comment":                     exactComment,
	}, nil, nil)
	if recComment.Code != http.StatusCreated {
		t.Fatalf("expected 201 for 4096*'é' comment, got %d: %s", recComment.Code, recComment.Body.String())
	}
	var appResp api.ApprovalResponse
	if err := json.Unmarshal(recComment.Body.Bytes(), &appResp); err != nil {
		t.Fatalf("unmarshal ApprovalResponse: %v", err)
	}
	if appResp.ProposalStatus != string(domain.ProposalStatusApproved) {
		t.Fatalf("expected APPROVED proposal status, got %q", appResp.ProposalStatus)
	}
}

func TestGetProposalDiffTruncatedDrainVerifiesIntegrityPG17(t *testing.T) {
	ctx := context.Background()
	const maxDiff = 64
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.MaxDiffBytes = maxDiff
	})

	humanA := env.mintHuman("human-diff-a", "diffa@acme.test", nil, []string{"developer"}, "openid profile email")
	ctrlToken := env.mintController("ctrl-diff")
	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	ctrlCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))

	_, propID, _, _ := env.seedWorkspaceAndProposal(ctx, humanACaller.Principal.ID, humanA, ctrlToken)
	prop, err := env.proposals.Get(ctx, propID)
	if err != nil {
		t.Fatalf("proposals.Get: %v", err)
	}
	prop, err = env.proposals.BeginReconstruction(ctx, proposals.BeginReconstructionInput{
		ProposalID:      propID,
		ExpectedVersion: prop.Version,
		ActorID:         &ctrlCaller.Principal.ID,
	})
	if err != nil {
		t.Fatalf("BeginReconstruction: %v", err)
	}

	canonicalBytes := []byte("canonical-tree-tar")
	canonicalArt, err := env.snapshots.PutBytes(ctx, domain.ArtifactKindCanonicalTree, "reconstruct/"+propID.String()+"/tree.tar.gz", canonicalBytes)
	if err != nil {
		t.Fatalf("PutBytes canonical: %v", err)
	}
	canonicalReg, err := env.artifacts.Register(ctx, artifacts.RegisterInput{
		ID: domain.MustNewID(), Kind: domain.ArtifactKindCanonicalTree, SHA256: canonicalArt.SHA256,
		SizeBytes: int64(len(canonicalBytes)), Format: "tar.gz", StorageKey: canonicalArt.StorageKey,
		StorageGeneration: canonicalArt.StorageGeneration, UploadedBy: &ctrlCaller.Principal.ID,
	})
	if err != nil {
		t.Fatalf("Register canonical: %v", err)
	}

	// Build a valid CANONICAL_DIFF larger than maxDiff (64 bytes).
	diffBytes := []byte("diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old line content\n+new line content with extra tail bytes past 64\n")
	diffArt, err := env.snapshots.PutBytes(ctx, domain.ArtifactKindCanonicalDiff, "reconstruct/"+propID.String()+"/diff.patch", diffBytes)
	if err != nil {
		t.Fatalf("PutBytes diff: %v", err)
	}
	diffReg, err := env.artifacts.Register(ctx, artifacts.RegisterInput{
		ID: domain.MustNewID(), Kind: domain.ArtifactKindCanonicalDiff, SHA256: diffArt.SHA256,
		SizeBytes: int64(len(diffBytes)), Format: "patch", StorageKey: diffArt.StorageKey,
		StorageGeneration: diffArt.StorageGeneration, UploadedBy: &ctrlCaller.Principal.ID,
	})
	if err != nil {
		t.Fatalf("Register diff: %v", err)
	}

	treeDigest := domain.SHA256Hex([]byte("tree-digest"))
	manifestObj := reconstruct.PublicationManifest{
		SchemaVersion: "1.0", BaseCommit: strings.Repeat("a", 40), TreeDigest: treeDigest,
		CanonicalTreeSHA256: canonicalReg.SHA256, DiffDigest: diffReg.SHA256, FileCount: 1, TotalBytes: 4,
		Changes: []reconstruct.ChangedFile{{Path: "README.md", ChangeType: "MODIFIED", SizeBytes: 4, SHA256: domain.SHA256Hex([]byte("new\n"))}},
	}
	manifestBytes, _ := json.Marshal(manifestObj)
	manifestArt, err := env.snapshots.PutBytes(ctx, domain.ArtifactKindPublicationManifest, "reconstruct/"+propID.String()+"/manifest.json", manifestBytes)
	if err != nil {
		t.Fatalf("PutBytes manifest: %v", err)
	}
	manifestReg, err := env.artifacts.Register(ctx, artifacts.RegisterInput{
		ID: domain.MustNewID(), Kind: domain.ArtifactKindPublicationManifest, SHA256: manifestArt.SHA256,
		SizeBytes: int64(len(manifestBytes)), Format: "json", StorageKey: manifestArt.StorageKey,
		StorageGeneration: manifestArt.StorageGeneration, UploadedBy: &ctrlCaller.Principal.ID,
	})
	if err != nil {
		t.Fatalf("Register manifest: %v", err)
	}

	if _, err := env.proposals.CompleteReconstruction(ctx, proposals.CompleteReconstructionInput{
		ProposalID: propID, ExpectedVersion: prop.Version,
		CanonicalArtifactID: canonicalReg.ID, DiffArtifactID: &diffReg.ID, ManifestArtifactID: manifestReg.ID,
		TreeDigest: treeDigest, DiffDigest: diffReg.SHA256, ManifestDigest: manifestReg.SHA256,
		ActorID: &ctrlCaller.Principal.ID,
	}); err != nil {
		t.Fatalf("CompleteReconstruction: %v", err)
	}

	// 1. Valid truncated diff succeeds with 200 OK, truncated=true, and exact 64-byte prefix.
	okRec := env.do(http.MethodGet, "/v1/proposals/"+propID.String()+"/diff", humanA, "", nil, nil, nil)
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid truncated diff, got %d: %s", okRec.Code, okRec.Body.String())
	}
	var diffDTO api.ProposalDiffDTO
	if err := json.Unmarshal(okRec.Body.Bytes(), &diffDTO); err != nil {
		t.Fatalf("unmarshal ProposalDiffDTO: %v", err)
	}
	if !diffDTO.Truncated || len(diffDTO.UnifiedDiff) != maxDiff || diffDTO.UnifiedDiff != string(diffBytes[:maxDiff]) {
		t.Fatalf("unexpected truncated diff DTO: truncated=%v len=%d", diffDTO.Truncated, len(diffDTO.UnifiedDiff))
	}

	// 2. Tamper a byte in the tail BEYOND maxDiff (preserving file length) so verifyingReadCloser detects DIGEST_MISMATCH only during drain!
	tampered := append([]byte(nil), diffBytes...)
	tampered[len(tampered)-2] ^= 0xFF
	diskPath := filepath.Join(env.snapshots.RootDir(), filepath.FromSlash(diffArt.StorageKey))
	if err := os.WriteFile(diskPath, tampered, 0o600); err != nil {
		t.Fatalf("tamper diff on disk: %v", err)
	}

	badRec := env.do(http.MethodGet, "/v1/proposals/"+propID.String()+"/diff", humanA, "", nil, nil, nil)
	if badRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 DIGEST_MISMATCH when tail-tampered truncated diff is drained, got %d: %s", badRec.Code, badRec.Body.String())
	}
	var errResp api.ErrorResponse
	if err := json.Unmarshal(badRec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp.Error.Code != "DIGEST_MISMATCH" {
		t.Fatalf("expected DIGEST_MISMATCH, got %q", errResp.Error.Code)
	}
}

func testAdvisoryLockKey(namespace, id string) int64 {
	sum := sha256.Sum256([]byte(namespace + ":" + id))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func TestAdvisoryLockContentionTimeout503AndRecovery(t *testing.T) {
	ctx := context.Background()
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.DBTimeout = 100 * time.Millisecond
		d.RepoConcurrencyLimit = 5
		d.GlobalScanBudget = 5
	})

	humanToken := env.mintHuman("lock-human", "lock@acme.test", nil, []string{"developer"}, "openid profile email")
	ctrlToken := env.mintController("lock-ctrl")
	humanCaller, err := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanToken))
	if err != nil {
		t.Fatalf("ResolveCaller human: %v", err)
	}
	ctrlCaller, err := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, ctrlToken))
	if err != nil {
		t.Fatalf("ResolveCaller ctrl: %v", err)
	}

	_, propID, _, _ := env.seedWorkspaceAndProposal(ctx, humanCaller.Principal.ID, humanToken, ctrlToken)
	env.seedReconstructed(ctx, propID, ctrlCaller.Principal.ID)

	// Hold the real PostgreSQL advisory locks on a separate pool connection so localSem is free
	// and conn.Exec(lockCtx, "SELECT pg_advisory_lock...") genuinely blocks in PostgreSQL.
	holdExternalLock := func(lockKey int64) func() {
		conn, err := env.pg.Pool().Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire hold conn: %v", err)
		}
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1::bigint)`, lockKey); err != nil {
			conn.Release()
			t.Fatalf("pg_advisory_lock: %v", err)
		}
		return func() {
			_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1::bigint)`, lockKey)
			conn.Release()
		}
	}

	t.Run("POST /v1/workspaces with RepoConcurrencyLimit > 0 times out at DBTimeout with 503 DATABASE_TIMEOUT then recovers", func(t *testing.T) {
		unlock := holdExternalLock(testAdvisoryLockKey("custodian:repo_concurrency", env.repo.ID.String()))
		released := false
		defer func() {
			if !released {
				unlock()
			}
		}()

		start := time.Now()
		rec := env.do(http.MethodPost, "/v1/workspaces", humanToken, "ws-lock-timeout", map[string]any{
			"repository": map[string]any{
				"provider":      "github",
				"repository_id": env.repo.GitHubRepositoryID,
				"ref":           "main",
			},
		}, nil, nil)
		elapsed := time.Since(start)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 during PG advisory lock contention, got %d (%s)", rec.Code, rec.Body.String())
		}
		if elapsed > 1*time.Second {
			t.Fatalf("expected fast DBTimeout (~100ms), took %v", elapsed)
		}
		var errResp api.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("unmarshal error response: %v", err)
		}
		if errResp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected DATABASE_TIMEOUT, got %q", errResp.Error.Code)
		}

		unlock()
		released = true

		okRec := env.do(http.MethodPost, "/v1/workspaces", humanToken, "ws-lock-recovered", map[string]any{
			"repository": map[string]any{
				"provider":      "github",
				"repository_id": env.repo.GitHubRepositoryID,
				"ref":           "main",
			},
		}, nil, nil)
		if okRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 after lock released, got %d (%s)", okRec.Code, okRec.Body.String())
		}
	})

	t.Run("POST /v1/proposals/{id}/evaluate with GlobalScanBudget > 0 times out at DBTimeout with 503 DATABASE_TIMEOUT then recovers", func(t *testing.T) {
		unlock := holdExternalLock(testAdvisoryLockKey("custodian:global_eval_budget", "global"))
		released := false
		defer func() {
			if !released {
				unlock()
			}
		}()

		start := time.Now()
		rec := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-lock-timeout", map[string]any{}, nil, nil)
		elapsed := time.Since(start)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 during PG eval advisory lock contention, got %d (%s)", rec.Code, rec.Body.String())
		}
		if elapsed > 1*time.Second {
			t.Fatalf("expected fast DBTimeout (~100ms), took %v", elapsed)
		}
		var errResp api.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("unmarshal error response: %v", err)
		}
		if errResp.Error.Code != "DATABASE_TIMEOUT" {
			t.Fatalf("expected DATABASE_TIMEOUT, got %q", errResp.Error.Code)
		}

		unlock()
		released = true

		okRec := env.do(http.MethodPost, "/v1/proposals/"+propID.String()+"/evaluate", ctrlToken, "eval-lock-recovered", map[string]any{}, nil, nil)
		if okRec.Code != http.StatusAccepted {
			t.Fatalf("expected 202 after eval lock released, got %d (%s)", okRec.Code, okRec.Body.String())
		}
	})
}
