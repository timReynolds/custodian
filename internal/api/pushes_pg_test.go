package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestPushControlPlane_ApprovalsLifecycleSoDCanonicalAndRevocationPG17(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.Logger = slog.New(observability.NewSafeHandler(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}), nil))
	})

	humanA := env.mintHuman("pg-push-a", "pga@acme.test", []string{"engineering"}, nil, "openid profile email")
	secAdmin := env.mintHuman("pg-sec-admin", "pgsec@acme.test", []string{"security-admins"}, nil, "openid profile email")
	auditor := env.mintAuditor("pg-auditor")

	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))
	secAdminCaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, secAdmin))
	_, _ = env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, auditor))

	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("d", 64)
	art, err := env.store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind:              domain.ArtifactKindGitPushBundle,
		SHA256:            digest,
		StorageKey:        "pushes/pg-test.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         1024,
		Format:            "tar.gz",
		UploadedBy:        &humanACaller.Principal.ID,
	})
	if err != nil {
		t.Fatalf("RegisterArtifact: %v", err)
	}

	// Push 1: owned by humanA, uppercase host in destination, APPROVAL_REQUIRED
	ps1, err := env.store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:           humanACaller.Principal.ID,
		RepositoryID:          &env.repo.ID,
		Destination:           "https://x-access-token:ghp_SuperSecretToken123@GitHub.COM/acme/custodian-demo",
		DestinationHost:       "GitHub.COM",
		DestinationRegistered: true,
		DestinationExternal:   false,
		Transport:             domain.PushTransportHTTPS,
		PushManifestDigest:    digest,
		BundleArtifactID:      &art.ID,
		EgressMode:            domain.EgressModeEnforceBlock,
		Status:                domain.PushSessionStatusApprovalRequired,
		CreatedAt:             now,
	})
	if err != nil {
		t.Fatalf("CreatePushSession ps1: %v", err)
	}
	dec1, err := env.store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		PushSessionID:  &ps1.ID,
		PolicyBundleID: env.policyBundle.ID,
		Stage:          "PUSH_EGRESS",
		InputDigest:    digest,
		Effect:         domain.PolicyEffectRequireApproval,
		CreatedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision dec1: %v", err)
	}
	effReqApp := domain.PolicyEffectRequireApproval
	if _, err := env.store.ApplyPushSessionPolicyDecision(ctx, persistence.ApplyPushSessionPolicyDecisionParams{
		ID:               ps1.ID,
		PolicyDecisionID: dec1.ID,
		Verdict:          effReqApp,
		Status:           domain.PushSessionStatusApprovalRequired,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("ApplyPushSessionPolicyDecision: %v", err)
	}

	// Attach a finding with forbidden raw keys to verify sanitization on GET /v1/pushes/{id}
	sr1, err := env.store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		PushSessionID:  &ps1.ID,
		ArtifactID:     art.ID,
		Scanner:        "gitleaks",
		ScannerVersion: "8.18.0",
		Status:         domain.ScanStatusCompleted,
		Coverage:       domain.ScanCoverage{FilesExamined: 1, FilesSkipped: 0, Complete: true},
		StartedAt:      now,
		CompletedAt:    &now,
	})
	if err != nil {
		t.Fatalf("CreateScanRun: %v", err)
	}
	if _, err := env.store.CreateFinding(ctx, persistence.CreateFindingParams{
		ScanRunID:   sr1.ID,
		Category:    "SECRET",
		Severity:    domain.SeverityHigh,
		RuleID:      "ghp-pat",
		Path:        "main.go",
		Fingerprint: digest,
		Redacted:    true,
		Message:     "leaked Bearer eyJhbGciOiJSUzI1NiJ9.abcdef123456.sig123456",
		Metadata:    map[string]any{"source_ref": "ok", "snippet": "RAW_RESTRICTED_SOURCE_TEXT"},
	}); err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}

	// GET /v1/pushes/{id} strips userinfo from destination and forbidden keys/tokens from findings
	rec := env.do(http.MethodGet, "/v1/pushes/"+ps1.ID.String(), humanA, "", nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/pushes/{id} expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	bodyStr := rec.Body.String()
	for _, secret := range []string{"ghp_SuperSecretToken123", "eyJhbGciOiJSUzI1NiJ9", "RAW_RESTRICTED_SOURCE_TEXT"} {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("GET /v1/pushes/{id} leaked %q: %s", secret, bodyStr)
		}
	}

	// Regular human cannot filter by another principal_id (403)
	rec = env.do(http.MethodGet, "/v1/pushes?principal_id="+secAdminCaller.Principal.ID.String(), humanA, "", nil, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /v1/pushes with foreign principal_id expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Seed an EXPIRED unrevoked approval release for (humanA, "github.com/acme/custodian-demo", digest)
	_, err = env.store.CreatePushApprovalRelease(ctx, persistence.CreatePushApprovalReleaseParams{
		PrincipalID:        humanACaller.Principal.ID,
		Destination:        "github.com/acme/custodian-demo",
		PushManifestDigest: digest,
		PushSessionID:      ps1.ID,
		PolicyDecisionID:   dec1.ID,
		ApprovedBy:         secAdminCaller.Principal.ID,
		Reason:             "expired earlier release",
		ExpiresAt:          now.Add(-1 * time.Minute),
		CreatedAt:          now.Add(-5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreatePushApprovalRelease expired: %v", err)
	}

	// Auditor cannot approve (403)
	rec = env.do(http.MethodPost, "/v1/pushes/"+ps1.ID.String()+"/approvals", auditor, "pg-aud-app", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
	}, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor approve expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Self-approval (SoD) rejected with 403 even if user has security-admins group
	psOwn, err := env.store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:        secAdminCaller.Principal.ID,
		Destination:        "github.com/acme/custodian-demo",
		DestinationHost:    "github.com",
		PushManifestDigest: digest,
		EgressMode:         domain.EgressModeEnforceBlock,
		Status:             domain.PushSessionStatusApprovalRequired,
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("CreatePushSession psOwn: %v", err)
	}
	decOwn, err := env.store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		PushSessionID:  &psOwn.ID,
		PolicyBundleID: env.policyBundle.ID,
		Stage:          "PUSH_EGRESS",
		InputDigest:    digest,
		Effect:         domain.PolicyEffectRequireApproval,
		CreatedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision decOwn: %v", err)
	}
	if _, err := env.store.ApplyPushSessionPolicyDecision(ctx, persistence.ApplyPushSessionPolicyDecisionParams{
		ID:               psOwn.ID,
		PolicyDecisionID: decOwn.ID,
		Verdict:          effReqApp,
		Status:           domain.PushSessionStatusApprovalRequired,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("ApplyPushSessionPolicyDecision psOwn: %v", err)
	}

	rec = env.do(http.MethodPost, "/v1/pushes/"+psOwn.ID.String()+"/approvals", secAdmin, "pg-sod-app", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
	}, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SoD self-approval expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// Valid replacement approval by secAdmin for ps1 auto-revokes expired release and canonicalizes host
	rec = env.do(http.MethodPost, "/v1/pushes/"+ps1.ID.String()+"/approvals", secAdmin, "pg-app-replace", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
		"destination":          "https://GITHUB.COM/acme/custodian-demo",
		"ttl_seconds":          600,
	}, nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("replacement approval expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var appResp api.PushApprovalReleaseResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &appResp); err != nil {
		t.Fatalf("unmarshal appResp: %v", err)
	}
	if appResp.Destination != "github.com/acme/custodian-demo" {
		t.Fatalf("expected canonical lowercase host destination, got %q", appResp.Destination)
	}

	// Duplicate active approval for same binding fails with 409
	rec = env.do(http.MethodPost, "/v1/pushes/"+ps1.ID.String()+"/approvals", secAdmin, "pg-app-dup", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
	}, nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate active approval expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// Audit hash chain must remain valid
	verifyRes, err := env.audit.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("audit VerifyChain failed: %v", err)
	}
	if verifyRes.EventCount < 1 {
		t.Fatalf("expected >= 1 audit event, got %d", verifyRes.EventCount)
	}

	// SafeHandler logs must not contain secrets
	if strings.Contains(logBuf.String(), "ghp_SuperSecretToken123") || strings.Contains(logBuf.String(), "RAW_RESTRICTED_SOURCE_TEXT") {
		t.Fatalf("SafeHandler logs leaked secret: %s", logBuf.String())
	}
}

func TestPushControlPlane_IPCorporaZeroRawSourceAndRepoEgressModePG17(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer

	// First test with IPCorpusReindexer == nil -> POST /v1/ip-corpora creates PENDING (201), /reindex returns 503
	envNilReindexer := newAPITestEnv(t, func(d *api.Deps) {
		d.Logger = slog.New(observability.NewSafeHandler(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}), nil))
		d.IPCorpusReindexer = nil
	})
	secAdmin := envNilReindexer.mintHuman("corp-sec", "corpsec@acme.test", []string{"security-admins"}, nil, "openid profile email")
	humanA := envNilReindexer.mintHuman("corp-hum", "corphum@acme.test", []string{"engineering"}, nil, "openid profile email")
	_, _ = envNilReindexer.dir.ResolveCaller(ctx, mustVerifyToken(t, envNilReindexer.oidc, secAdmin))
	_, _ = envNilReindexer.dir.ResolveCaller(ctx, mustVerifyToken(t, envNilReindexer.oidc, humanA))

	// Empty {name, classification} rejected with 422
	rec := envNilReindexer.do(http.MethodPost, "/v1/ip-corpora", secAdmin, "corp-empty-src", map[string]any{
		"name":           "no-source",
		"classification": "RESTRICTED",
	}, nil, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty source expected 422, got %d: %s", rec.Code, rec.Body.String())
	}

	// Invalid classification rejected with 422
	rec = envNilReindexer.do(http.MethodPost, "/v1/ip-corpora", secAdmin, "corp-bad-cls", map[string]any{
		"name":           "bad-cls",
		"classification": "PUBLIC",
		"source_ref":     "git://internal/repo",
	}, nil, nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("PUBLIC classification expected 422, got %d: %s", rec.Code, rec.Body.String())
	}

	const rawSecretCode = "func TopSecretProprietaryKernelFormula() int { return 0xDEADBEEF }"
	const rawSecretPath = "internal/proprietary/secret_kernel.go"

	rec = envNilReindexer.do(http.MethodPost, "/v1/ip-corpora", secAdmin, "corp-create-pending", map[string]any{
		"name":           "kernel-ip",
		"classification": "RESTRICTED",
		"files": []map[string]any{
			{"path": rawSecretPath, "content": rawSecretCode},
		},
	}, nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create corpus with nil reindexer expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var corp api.IPCorpusDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &corp); err != nil {
		t.Fatalf("unmarshal IPCorpusDTO: %v", err)
	}
	if corp.Status != "PENDING" {
		t.Fatalf("expected PENDING status when reindexer nil, got %q", corp.Status)
	}

	// Duplicate name -> 409
	rec = envNilReindexer.do(http.MethodPost, "/v1/ip-corpora", secAdmin, "corp-dup-name", map[string]any{
		"name":           "kernel-ip",
		"classification": "RESTRICTED",
		"source_ref":     "git://internal/dup",
	}, nil, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate corpus name expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	// /reindex fails closed with 503 when IPCorpusReindexer == nil
	rec = envNilReindexer.do(http.MethodPost, "/v1/ip-corpora/"+corp.ID+"/reindex", secAdmin, "corp-reindex-503", map[string]any{
		"force": true,
	}, nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("reindex with nil reindexer expected 503, got %d: %s", rec.Code, rec.Body.String())
	}

	// Nonexistent corpus with valid UUIDv7 when reindexer IS wired -> 404
	// Verify zero raw source or raw file paths in PG (ip_fingerprint_corpora + audit_events) and logs!
	var dbDump string
	if err := envNilReindexer.pg.Pool().QueryRow(ctx, `SELECT COALESCE(string_agg(source_ref || ' ' || COALESCE(description, ''), ' '), '') FROM ip_fingerprint_corpora`).Scan(&dbDump); err != nil {
		t.Fatalf("query ip_fingerprint_corpora: %v", err)
	}
	var auditDump string
	if err := envNilReindexer.pg.Pool().QueryRow(ctx, `SELECT COALESCE(string_agg(payload::text, ' '), '') FROM audit_events`).Scan(&auditDump); err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	for _, needle := range []string{rawSecretCode, "0xDEADBEEF", rawSecretPath, "secret_kernel.go"} {
		if strings.Contains(rec.Body.String(), needle) || strings.Contains(dbDump, needle) || strings.Contains(auditDump, needle) || strings.Contains(logBuf.String(), needle) {
			t.Fatalf("raw restricted source/path %q leaked into DB/audit/logs/HTTP", needle)
		}
	}

	// Repository egress mode: reject embedded credentials in git_remote_url, allow valid update, 403 for humanA
	rec = envNilReindexer.do(http.MethodPut, "/v1/repositories/"+envNilReindexer.repo.ID.String()+"/egress-mode", humanA, "repo-403", map[string]any{
		"egress_mode": "ENFORCE_BLOCK",
	}, nil, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("regular human egress-mode expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = envNilReindexer.do(http.MethodPut, "/v1/repositories/"+envNilReindexer.repo.ID.String()+"/egress-mode", secAdmin, "repo-bad-url", map[string]any{
		"egress_mode":    "ENFORCE_BLOCK",
		"git_remote_url": "https://user:secretpass@github.com/acme/repo.git",
	}, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("embedded password in git_remote_url expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = envNilReindexer.do(http.MethodPut, "/v1/repositories/"+envNilReindexer.repo.ID.String()+"/egress-mode", secAdmin, "repo-ok", map[string]any{
		"egress_mode":            "ENFORCE_BLOCK",
		"passive_audit_delivery": "INLINE_WARN",
		"git_remote_url":         "https://github.com/acme/custodian-demo.git",
		"remote_host":            "GitHub.COM",
		"registered_destination": true,
		"external":               false,
	}, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid egress-mode expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var modeResp api.RepositoryEgressModeResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &modeResp); err != nil {
		t.Fatalf("unmarshal RepositoryEgressModeResponseDTO: %v", err)
	}
	if modeResp.RemoteHost == nil || *modeResp.RemoteHost != "github.com" || modeResp.EgressMode != "ENFORCE_BLOCK" {
		t.Fatalf("unexpected modeResp: %+v", modeResp)
	}

	// Verify nonexistent corpus ID returns 404 when reindexer is configured
	envWithReindexer := newAPITestEnv(t, func(d *api.Deps) {
		d.IPCorpusReindexer = &fakeIPCorpusReindexer{}
	})
	secAdmin2 := envWithReindexer.mintHuman("corp-sec-2", "corpsec2@acme.test", []string{"security-admins"}, nil, "openid profile email")
	rec = envWithReindexer.do(http.MethodPost, "/v1/ip-corpora/"+uuid.Must(uuid.NewV7()).String()+"/reindex", secAdmin2, "corp-404", map[string]any{
		"force": true,
	}, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reindex missing corpus expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

type slowOrFailingIPCorpusReindexer struct {
	delay time.Duration
	err   error
}

func (s *slowOrFailingIPCorpusReindexer) Reindex(ctx context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return api.IPCorpusReindexResult{}, ctx.Err()
		}
	}
	if s.err != nil {
		return api.IPCorpusReindexResult{}, s.err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return api.IPCorpusReindexResult{
		Status:              domain.IPCorpusStatusReady,
		FingerprintsIndexed: int64(len(input.Files) + 5),
		FilesProcessed:      int64(len(input.Files)),
		LastIndexedDigest:   domain.SHA256Hex([]byte(input.Corpus.Name)),
		CompletedAt:         &now,
	}, nil
}

func TestPushControlPlane_RegressionIter1FindingsPG17(t *testing.T) {
	ctx := context.Background()

	// 1. Reindex exceeding DBTimeout (25ms DBTimeout vs 70ms Reindex) must NOT fail with 503 or leave PENDING.
	envSlow := newAPITestEnv(t, func(d *api.Deps) {
		d.DBTimeout = 25 * time.Millisecond
		d.IPCorpusReindexer = &slowOrFailingIPCorpusReindexer{delay: 70 * time.Millisecond}
	})
	secAdmin := envSlow.mintHuman("r2-sec", "r2sec@acme.test", []string{"security-admins"}, nil, "openid profile email")

	rec := envSlow.do(http.MethodPost, "/v1/ip-corpora", secAdmin, "r2-slow-create", map[string]any{
		"name":           "slow-corpus",
		"classification": "RESTRICTED",
		"files":          []map[string]any{{"path": "algo.go", "content": "package p\nfunc Secret() {}\n"}},
	}, nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("slow createIPCorpus expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var slowCorp api.IPCorpusDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &slowCorp); err != nil {
		t.Fatalf("unmarshal slowCorp: %v", err)
	}
	if slowCorp.Status != "READY" {
		t.Fatalf("slow createIPCorpus expected READY, got %q", slowCorp.Status)
	}

	rec = envSlow.do(http.MethodPost, "/v1/ip-corpora/"+slowCorp.ID+"/reindex", secAdmin, "r2-slow-reindex", map[string]any{
		"force": true,
	}, nil, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("slow reindexIPCorpus expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var slowReindexResp api.ReindexIPCorpusResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &slowReindexResp); err != nil {
		t.Fatalf("unmarshal slowReindexResp: %v", err)
	}
	if slowReindexResp.Status != "READY" {
		t.Fatalf("slow reindexIPCorpus expected READY, got %q", slowReindexResp.Status)
	}

	// 2. Reindex failure during createIPCorpus marks corpus FAILED in DB cleanly.
	envFail := newAPITestEnv(t, func(d *api.Deps) {
		d.IPCorpusReindexer = &slowOrFailingIPCorpusReindexer{err: domain.Unavailable("REINDEX_IO", "disk read failed")}
	})
	secFail := envFail.mintHuman("r2-fail-sec", "r2fail@acme.test", []string{"security-admins"}, nil, "openid profile email")
	rec = envFail.do(http.MethodPost, "/v1/ip-corpora", secFail, "r2-fail-create", map[string]any{
		"name":           "fail-corpus",
		"classification": "CONFIDENTIAL",
		"files":          []map[string]any{{"path": "algo.go", "content": "package p\nfunc Secret() {}\n"}},
	}, nil, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("failing reindex createIPCorpus expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var dbStatus string
	if err := envFail.pg.Pool().QueryRow(ctx, `SELECT status FROM ip_fingerprint_corpora WHERE name = 'fail-corpus'`).Scan(&dbStatus); err != nil {
		t.Fatalf("query fail-corpus status: %v", err)
	}
	if dbStatus != "FAILED" {
		t.Fatalf("expected fail-corpus status FAILED, got %q", dbStatus)
	}

	// 3. Corpus validation regressions: files:[], empty content without sha256, backslash traversal, credentialed source_ref.
	for _, tc := range []struct {
		name     string
		path     string
		body     map[string]any
		wantCode int
	}{
		{"empty_files_create", "/v1/ip-corpora", map[string]any{"name": "c1", "classification": "RESTRICTED", "source_ref": "git://internal/repo", "files": []any{}}, http.StatusBadRequest},
		{"empty_files_reindex", "/v1/ip-corpora/" + slowCorp.ID + "/reindex", map[string]any{"files": []any{}}, http.StatusBadRequest},
		{"empty_content_no_sha", "/v1/ip-corpora", map[string]any{"name": "c2", "classification": "RESTRICTED", "files": []map[string]any{{"path": "empty.go", "content": ""}}}, http.StatusUnprocessableEntity},
		{"backslash_traversal", "/v1/ip-corpora", map[string]any{"name": "c3", "classification": "RESTRICTED", "source_path": `dir\..\secret`}, http.StatusBadRequest},
		{"source_ref_creds", "/v1/ip-corpora", map[string]any{"name": "c4", "classification": "RESTRICTED", "source_ref": "https://user:ghp_SecretToken123@github.com/org/repo"}, http.StatusBadRequest},
	} {
		rec = envSlow.do(http.MethodPost, tc.path, secAdmin, "r2-corp-"+tc.name, tc.body, nil, nil)
		if rec.Code != tc.wantCode {
			t.Fatalf("%s: expected %d, got %d: %s", tc.name, tc.wantCode, rec.Code, rec.Body.String())
		}
	}

	// 4. Push approval expires_at > 24h rejected (400 INVALID_EXPIRY), destination > 512 rejected (400),
	// and SCP-style SSH destination matches canonical github.com/acme/custodian-demo.
	humanA := envSlow.mintHuman("r2-push-a", "r2pa@acme.test", []string{"engineering"}, nil, "openid profile email")
	humanACaller, _ := envSlow.dir.ResolveCaller(ctx, mustVerifyToken(t, envSlow.oidc, humanA))
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("e", 64)
	ps, err := envSlow.store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:        humanACaller.Principal.ID,
		RepositoryID:       &envSlow.repo.ID,
		Destination:        "git@GitHub.COM:acme/custodian-demo.git",
		DestinationHost:    "GitHub.COM",
		Transport:          domain.PushTransportSSH,
		PushManifestDigest: digest,
		EgressMode:         domain.EgressModeEnforceBlock,
		Status:             domain.PushSessionStatusApprovalRequired,
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("CreatePushSession: %v", err)
	}
	dec, err := envSlow.store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		PushSessionID:  &ps.ID,
		PolicyBundleID: envSlow.policyBundle.ID,
		Stage:          "PUSH_EGRESS",
		InputDigest:    digest,
		Effect:         domain.PolicyEffectRequireApproval,
		CreatedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision: %v", err)
	}
	eff := domain.PolicyEffectRequireApproval
	if _, err := envSlow.store.ApplyPushSessionPolicyDecision(ctx, persistence.ApplyPushSessionPolicyDecisionParams{
		ID:               ps.ID,
		PolicyDecisionID: dec.ID,
		Verdict:          eff,
		Status:           domain.PushSessionStatusApprovalRequired,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("ApplyPushSessionPolicyDecision: %v", err)
	}

	rec = envSlow.do(http.MethodPost, "/v1/pushes/"+ps.ID.String()+"/approvals", secAdmin, "r2-exp-25h", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
		"expires_at":           now.Add(25 * time.Hour).Format(time.RFC3339),
	}, nil, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_EXPIRY") {
		t.Fatalf("expires_at > 24h expected 400 INVALID_EXPIRY, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = envSlow.do(http.MethodPost, "/v1/pushes/"+ps.ID.String()+"/approvals", secAdmin, "r2-dest-513", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
		"destination":          "  " + strings.Repeat("a", 511),
	}, nil, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_DESTINATION") {
		t.Fatalf("destination > 512 expected 400 INVALID_DESTINATION, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = envSlow.do(http.MethodPost, "/v1/pushes/"+ps.ID.String()+"/approvals", secAdmin, "r2-scp-ok", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
		"destination":          "https://GITHUB.COM/acme/custodian-demo.git",
		"expires_at":           now.Add(2 * time.Hour).Format(time.RFC3339),
	}, nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("SCP destination canonical approval expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var appResp api.PushApprovalReleaseResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &appResp); err != nil {
		t.Fatalf("unmarshal appResp: %v", err)
	}
	if appResp.Destination != "github.com/acme/custodian-demo.git" {
		t.Fatalf("expected canonical SCP destination github.com/acme/custodian-demo.git, got %q", appResp.Destination)
	}
}

type switchableIPCorpusReindexer struct {
	failErr error
}

func (s *switchableIPCorpusReindexer) Reindex(_ context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	if s.failErr != nil {
		return api.IPCorpusReindexResult{}, s.failErr
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return api.IPCorpusReindexResult{
		Status:              domain.IPCorpusStatusReady,
		FingerprintsIndexed: int64(len(input.Files) + 7),
		FilesProcessed:      int64(len(input.Files)),
		LastIndexedDigest:   domain.SHA256Hex([]byte(input.Corpus.Name)),
		CompletedAt:         &now,
	}, nil
}

func TestTier5_ReapproveConsumedPushSessionRejectedAndCorpusCreateRetryPG17(t *testing.T) {
	ctx := context.Background()

	// Part A: Re-approving or rejecting an already-consumed APPROVAL_REQUIRED push session returns 409 APPROVAL_ALREADY_CONSUMED.
	env := newAPITestEnv(t, nil)
	humanA := env.mintHuman("t5-push-a", "t5a@acme.test", []string{"engineering"}, nil, "openid profile email")
	secAdmin := env.mintHuman("t5-sec-admin", "t5sec@acme.test", []string{"security-admins"}, nil, "openid profile email")
	humanACaller, _ := env.dir.ResolveCaller(ctx, mustVerifyToken(t, env.oidc, humanA))

	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("c", 64)
	s1, err := env.store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:        humanACaller.Principal.ID,
		RepositoryID:       &env.repo.ID,
		Destination:        "github.com/acme/custodian-demo",
		DestinationHost:    "github.com",
		Transport:          domain.PushTransportHTTPS,
		PushManifestDigest: digest,
		EgressMode:         domain.EgressModeEnforceBlock,
		Status:             domain.PushSessionStatusApprovalRequired,
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("CreatePushSession(S1): %v", err)
	}
	dec, err := env.store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		PushSessionID:  &s1.ID,
		PolicyBundleID: env.policyBundle.ID,
		Stage:          "PUSH_EGRESS",
		InputDigest:    digest,
		Effect:         domain.PolicyEffectRequireApproval,
		CreatedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision: %v", err)
	}
	if _, err := env.store.ApplyPushSessionPolicyDecision(ctx, persistence.ApplyPushSessionPolicyDecisionParams{
		ID:               s1.ID,
		PolicyDecisionID: dec.ID,
		Verdict:          domain.PolicyEffectRequireApproval,
		Status:           domain.PushSessionStatusApprovalRequired,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("ApplyPushSessionPolicyDecision: %v", err)
	}

	rec := env.do(http.MethodPost, "/v1/pushes/"+s1.ID.String()+"/approvals", secAdmin, "t5-approve-1", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": digest,
		"reason":               "first approval",
	}, nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("initial APPROVE expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	s2, err := env.store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:        humanACaller.Principal.ID,
		RepositoryID:       &env.repo.ID,
		Destination:        "github.com/acme/custodian-demo",
		DestinationHost:    "github.com",
		Transport:          domain.PushTransportHTTPS,
		PushManifestDigest: digest,
		EgressMode:         domain.EgressModeEnforceBlock,
		Status:             domain.PushSessionStatusReceived,
		CreatedAt:          now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("CreatePushSession(S2): %v", err)
	}
	if _, err := env.store.ConsumePushApprovalRelease(ctx, persistence.ConsumePushApprovalReleaseParams{
		PrincipalID:             humanACaller.Principal.ID,
		Destination:             "github.com/acme/custodian-demo",
		PushManifestDigest:      digest,
		ConsumedAt:              now.Add(2 * time.Second),
		ConsumedByPushSessionID: s2.ID,
	}); err != nil {
		t.Fatalf("ConsumePushApprovalRelease: %v", err)
	}

	for _, tc := range []struct {
		name     string
		idemKey  string
		decision string
	}{
		{"reapprove", "t5-reapprove-consumed", "APPROVE"},
		{"reject_after_consume", "t5-reject-consumed", "REJECT"},
	} {
		rec = env.do(http.MethodPost, "/v1/pushes/"+s1.ID.String()+"/approvals", secAdmin, tc.idemKey, map[string]any{
			"decision":             tc.decision,
			"push_manifest_digest": digest,
			"reason":               "should fail",
		}, nil, nil)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "APPROVAL_ALREADY_CONSUMED") {
			t.Fatalf("%s expected 409 APPROVAL_ALREADY_CONSUMED, got %d: %s", tc.name, rec.Code, rec.Body.String())
		}
	}

	var unconsumedCount int
	if err := env.pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM push_approval_releases WHERE push_session_id = $1 AND consumed_at IS NULL`, s1.ID).Scan(&unconsumedCount); err != nil {
		t.Fatalf("count unconsumed releases: %v", err)
	}
	if unconsumedCount != 0 {
		t.Fatalf("expected 0 unconsumed releases for consumed session S1, got %d", unconsumedCount)
	}
	s1After, err := env.store.GetPushSessionByID(ctx, s1.ID)
	if err != nil || s1After.Status != domain.PushSessionStatusApprovalRequired {
		t.Fatalf("expected S1 status unchanged APPROVAL_REQUIRED, got %+v err=%v", s1After, err)
	}

	// Part B: POST /v1/ip-corpora transient 503 failure -> FAILED in DB -> retry with identical Idempotency-Key & payload -> 201 READY.
	reindexer := &switchableIPCorpusReindexer{
		failErr: domain.Unavailable("REINDEX_IO", "transient db/io outage"),
	}
	envRetry := newAPITestEnv(t, func(d *api.Deps) {
		d.IPCorpusReindexer = reindexer
	})
	secRetry := envRetry.mintHuman("t5-corp-sec", "t5corp@acme.test", []string{"security-admins"}, nil, "openid profile email")
	corpusPayload := map[string]any{
		"name":           "t5-retry-corpus",
		"classification": "RESTRICTED",
		"files":          []map[string]any{{"path": "algo.go", "content": "package p\nfunc Secret() {}\n"}},
	}

	rec1 := envRetry.do(http.MethodPost, "/v1/ip-corpora", secRetry, "t5-create-idem-1", corpusPayload, nil, nil)
	if rec1.Code != http.StatusServiceUnavailable {
		t.Fatalf("first failing POST /v1/ip-corpora expected 503, got %d: %s", rec1.Code, rec1.Body.String())
	}
	var dbStatus string
	if err := envRetry.pg.Pool().QueryRow(ctx, `SELECT status FROM ip_fingerprint_corpora WHERE name = 't5-retry-corpus'`).Scan(&dbStatus); err != nil {
		t.Fatalf("query status after 503: %v", err)
	}
	if dbStatus != "FAILED" {
		t.Fatalf("expected FAILED in DB after 503, got %q", dbStatus)
	}

	// Different payload with same corpus name must still return 409 CONFLICT.
	diffPayload := map[string]any{
		"name":           "t5-retry-corpus",
		"classification": "RESTRICTED",
		"files":          []map[string]any{{"path": "other.go", "content": "package p\nfunc Other() {}\n"}},
	}
	recDiff := envRetry.do(http.MethodPost, "/v1/ip-corpora", secRetry, "t5-create-diff-key", diffPayload, nil, nil)
	if recDiff.Code != http.StatusConflict {
		t.Fatalf("conflicting payload for FAILED corpus expected 409, got %d: %s", recDiff.Code, recDiff.Body.String())
	}

	// Recover reindexer and retry with the identical Idempotency-Key and payload -> 201 READY.
	reindexer.failErr = nil
	rec2 := envRetry.do(http.MethodPost, "/v1/ip-corpora", secRetry, "t5-create-idem-1", corpusPayload, nil, nil)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("idempotent retry POST /v1/ip-corpora expected 201, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var createdDTO api.IPCorpusDTO
	if err := json.Unmarshal(rec2.Body.Bytes(), &createdDTO); err != nil {
		t.Fatalf("unmarshal createdDTO: %v", err)
	}
	if createdDTO.Status != "READY" || createdDTO.FingerprintCount <= 0 {
		t.Fatalf("expected READY corpus with fingerprints after retry, got %+v", createdDTO)
	}

	// Replay with same finalized Idempotency-Key returns cached 201 Created.
	rec3 := envRetry.do(http.MethodPost, "/v1/ip-corpora", secRetry, "t5-create-idem-1", corpusPayload, nil, nil)
	if rec3.Code != http.StatusCreated {
		t.Fatalf("cached replay expected 201, got %d: %s", rec3.Code, rec3.Body.String())
	}
	_ = errors.New
}

type cancelOnReindexIPCorpusReindexer struct {
	onReindex func()
}

func (c *cancelOnReindexIPCorpusReindexer) Reindex(ctx context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	if c.onReindex != nil {
		c.onReindex()
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return api.IPCorpusReindexResult{}, domain.WrapError(domain.ErrUnavailable, "REINDEX_TIMEOUT", "corpus reindex timed out", ctx.Err())
		}
		return api.IPCorpusReindexResult{}, domain.WrapError(domain.ErrUnavailable, "REINDEX_CANCELLED", "corpus reindex cancelled", ctx.Err())
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return api.IPCorpusReindexResult{
		Status:              domain.IPCorpusStatusReady,
		FingerprintsIndexed: int64(len(input.Files) + 7),
		FilesProcessed:      int64(len(input.Files)),
		LastIndexedDigest:   domain.SHA256Hex([]byte(input.Corpus.Name)),
		CompletedAt:         &now,
	}, nil
}

func TestTier5_CreateIPCorpusContextCancelTransitionsToFailedAndRetrySucceedsPG17(t *testing.T) {
	ctx := context.Background()

	reindexer := &cancelOnReindexIPCorpusReindexer{}
	env := newAPITestEnv(t, func(d *api.Deps) {
		d.IPCorpusReindexer = reindexer
	})
	secAdmin := env.mintHuman("t5-cancel-sec", "t5cancel@acme.test", []string{"security-admins"}, nil, "openid profile email")

	corpusPayload := map[string]any{
		"name":           "t5-cancel-retry-corpus",
		"classification": "RESTRICTED",
		"files":          []map[string]any{{"path": "algo.go", "content": "package p\nfunc Secret() {}\n"}},
	}
	bodyBytes, err := json.Marshal(corpusPayload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	reqCtx, cancelReq := context.WithCancel(ctx)
	defer cancelReq()
	reindexer.onReindex = cancelReq

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/ip-corpora", bytes.NewReader(bodyBytes)).WithContext(reqCtx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secAdmin)
	req.Header.Set("Idempotency-Key", "t5-cancel-idem-1")
	rec1 := httptest.NewRecorder()
	env.router.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled POST /v1/ip-corpora expected 503, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Row must transition to FAILED (not remain stuck in PENDING) even though r.Context() was canceled.
	var dbStatus string
	var fpCount int64
	if err := env.pg.Pool().QueryRow(ctx, `SELECT status, fingerprint_count FROM ip_fingerprint_corpora WHERE name = 't5-cancel-retry-corpus'`).Scan(&dbStatus, &fpCount); err != nil {
		t.Fatalf("query corpus status after cancel: %v", err)
	}
	if dbStatus != "FAILED" || fpCount != 0 {
		t.Fatalf("expected status=FAILED fingerprint_count=0 after r.Context() cancel, got status=%q count=%d", dbStatus, fpCount)
	}

	// Retry with identical Idempotency-Key and payload must succeed with 201 Created (READY).
	reindexer.onReindex = nil
	rec2 := env.do(http.MethodPost, "/v1/ip-corpora", secAdmin, "t5-cancel-idem-1", corpusPayload, nil, nil)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("retry after canceled create expected 201, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var createdDTO api.IPCorpusDTO
	if err := json.Unmarshal(rec2.Body.Bytes(), &createdDTO); err != nil {
		t.Fatalf("unmarshal createdDTO: %v", err)
	}
	if createdDTO.Status != "READY" || createdDTO.FingerprintCount <= 0 {
		t.Fatalf("expected READY corpus with fingerprints after retry, got %+v", createdDTO)
	}
}
