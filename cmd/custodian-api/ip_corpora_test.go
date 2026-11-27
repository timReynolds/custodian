package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestIPCorpusReindexerAdapterUnit(t *testing.T) {
	ctx := context.Background()
	memStore := fingerprints.NewMemoryCorpusStore()
	adapter := &ipCorpusReindexerAdapter{
		indexer: fingerprints.NewCorpusIndexer(memStore, memStore),
	}

	corpusID, err := domain.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	corpusRow, err := memStore.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		ID:             corpusID,
		Name:           "unit-ip-corpus",
		Classification: domain.ClassificationRestricted,
		SourceRef:      "inline:sha256:" + strings.Repeat("a", 64),
		Status:         domain.IPCorpusStatusPending,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus: %v", err)
	}

	// 1. Empty input on PENDING corpus must return 422 EMPTY_CORPUS (never 500).
	_, err = adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus: corpusRow.ToDomain(),
		Force:  true,
	})
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) || domErr.HTTPStatus() != http.StatusUnprocessableEntity || domErr.Code() != "EMPTY_CORPUS" {
		t.Fatalf("expected 422 EMPTY_CORPUS on empty PENDING corpus, got %v", err)
	}

	// Reset corpus status back to PENDING for inline Files indexing.
	_, err = memStore.UpdateIPFingerprintCorpusStatus(ctx, persistence.UpdateIPFingerprintCorpusStatusParams{
		ID:     corpusID,
		Status: domain.IPCorpusStatusPending,
	})
	if err != nil {
		t.Fatalf("reset corpus status: %v", err)
	}

	// 2. Both SourcePath and Files specified -> 400 INVALID_CORPUS_SOURCE.
	_, err = adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus:     corpusRow.ToDomain(),
		SourcePath: t.TempDir(),
		Files:      []api.IPCorpusFileInput{{Path: "a.go", Content: "package a\n"}},
	})
	if !errors.As(err, &domErr) || domErr.HTTPStatus() != http.StatusBadRequest {
		t.Fatalf("expected 400 INVALID_CORPUS_SOURCE, got %v", err)
	}

	// 3. Inline Files indexing succeeds and populates L1/L2/L3 fingerprints.
	sampleA := "// Copyright (c) Acme Proprietary Confidential\npackage secret\n\nfunc ProprietaryAlgo(x int) int {\n\tacc := x * 31\n\tfor i := 0; i < 16; i++ {\n\t\tacc ^= (i + x) * 17\n\t}\n\treturn acc\n}\n"
	sumA := sha256.Sum256([]byte(sampleA))
	res, err := adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus: corpusRow.ToDomain(),
		Files: []api.IPCorpusFileInput{
			{
				Path:    "secret/algo.go",
				Content: sampleA,
				SHA256:  hex.EncodeToString(sumA[:]),
			},
			{
				Path:    "secret/helpers.go",
				Content: "// Proprietary and Confidential\npackage secret\nfunc Helper(v int) int { return v + 42 }\n",
			},
		},
		Force: true,
	})
	if err != nil {
		t.Fatalf("Reindex(Files): %v", err)
	}
	if res.Status != domain.IPCorpusStatusReady || res.FingerprintsIndexed <= 0 || res.FilesProcessed != 2 || res.LastIndexedDigest == "" {
		t.Fatalf("unexpected Reindex(Files) result: %+v", res)
	}

	// 4. Crucial E2E idempotency case: READY corpus + {Force: true} + empty Files/SourcePath
	// returns existing READY metadata without marking FAILED or modifying fingerprints.
	readyRow, err := memStore.GetIPFingerprintCorpusByID(ctx, corpusID)
	if err != nil {
		t.Fatalf("GetIPFingerprintCorpusByID: %v", err)
	}
	readyDomain := readyRow.ToDomain()
	idempRes, err := adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus:    readyDomain,
		SourceRef: readyDomain.SourceRef,
		Force:     true,
	})
	if err != nil {
		t.Fatalf("idempotent Reindex on READY corpus failed: %v", err)
	}
	if idempRes.Status != domain.IPCorpusStatusReady ||
		idempRes.FingerprintsIndexed != readyDomain.FingerprintCount ||
		idempRes.LastIndexedDigest != readyDomain.LastIndexedDigest {
		t.Fatalf("unexpected idempotent Reindex result: got %+v, want count=%d digest=%s", idempRes, readyDomain.FingerprintCount, readyDomain.LastIndexedDigest)
	}

	// 5. SourcePath indexing + symlink escape rejection.
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "core.go"), []byte(sampleA), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	srcRes, err := adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus:     readyRow.ToDomain(),
		SourcePath: srcDir,
		Force:      true,
	})
	if err != nil {
		t.Fatalf("Reindex(SourcePath): %v", err)
	}
	if srcRes.Status != domain.IPCorpusStatusReady || srcRes.FingerprintsIndexed <= 0 || srcRes.FilesProcessed != 1 {
		t.Fatalf("unexpected Reindex(SourcePath) result: %+v", srcRes)
	}

	// Missing directory -> 400 INVALID_TARGET_DIR, and READY status preserved.
	_, err = adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus:     readyRow.ToDomain(),
		SourcePath: filepath.Join(srcDir, "does-not-exist"),
		Force:      true,
	})
	if !errors.As(err, &domErr) || domErr.HTTPStatus() != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing SourcePath, got %v", err)
	}
	afterMissing, _ := memStore.GetIPFingerprintCorpusByID(ctx, corpusID)
	if afterMissing.Status != domain.IPCorpusStatusReady {
		t.Fatalf("expected READY status preserved after missing SourcePath, got %s", afterMissing.Status)
	}

	// Symlink inside SourcePath -> 422 INCOMPLETE_CORPUS_WALK, READY status preserved.
	symDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(symDir, "ok.go"), []byte(sampleA), 0o600)
	if err := os.Symlink("/etc/passwd", filepath.Join(symDir, "escape.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	_, err = adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus:     readyRow.ToDomain(),
		SourcePath: symDir,
		Force:      true,
	})
	if !errors.As(err, &domErr) || domErr.HTTPStatus() != http.StatusUnprocessableEntity || domErr.Code() != "INCOMPLETE_CORPUS_WALK" {
		t.Fatalf("expected 422 INCOMPLETE_CORPUS_WALK for symlinked SourcePath, got %v", err)
	}
	afterSym, _ := memStore.GetIPFingerprintCorpusByID(ctx, corpusID)
	if afterSym.Status != domain.IPCorpusStatusReady {
		t.Fatalf("expected READY status preserved after symlink SourcePath, got %s", afterSym.Status)
	}

	// Changed SourceRef with empty Files/SourcePath on READY corpus -> 422 EMPTY_CORPUS, READY status preserved.
	_, err = adapter.Reindex(ctx, api.IPCorpusReindexInput{
		Corpus:    readyRow.ToDomain(),
		SourceRef: "git://internal/changed-ref",
		Force:     true,
	})
	if !errors.As(err, &domErr) || domErr.HTTPStatus() != http.StatusUnprocessableEntity || domErr.Code() != "EMPTY_CORPUS" {
		t.Fatalf("expected 422 EMPTY_CORPUS for changed SourceRef without files, got %v", err)
	}
	afterChangedRef, _ := memStore.GetIPFingerprintCorpusByID(ctx, corpusID)
	if afterChangedRef.Status != domain.IPCorpusStatusReady {
		t.Fatalf("expected READY status preserved after changed SourceRef, got %s", afterChangedRef.Status)
	}

	// Canceled context -> 503 REINDEX_CANCELLED.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = adapter.Reindex(cctx, api.IPCorpusReindexInput{
		Corpus: readyRow.ToDomain(),
		Files:  []api.IPCorpusFileInput{{Path: "a.go", Content: "package a\n"}},
		Force:  true,
	})
	if !errors.As(err, &domErr) || domErr.HTTPStatus() != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on canceled context, got %v", err)
	}
}

func TestIPCorporaCreateAndReindexPG17HTTP(t *testing.T) {
	pg := harness.StartPostgres(t)
	oidc := harness.StartMockOIDC(t, "custodian-api")
	snapDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	listenAddr := ln.Addr().String()
	_ = ln.Close()

	envMap := map[string]string{
		"CUSTODIAN_LISTEN_ADDR":                 listenAddr,
		"CUSTODIAN_BASE_URL":                    "http://" + listenAddr,
		"CUSTODIAN_DATABASE_URL":                pg.DSN(),
		"CUSTODIAN_OIDC_ISSUER":                 oidc.Issuer(),
		"CUSTODIAN_OIDC_JWKS_URL":               oidc.JWKSURL(),
		"CUSTODIAN_OIDC_AUDIENCE":               oidc.Audience(),
		"CUSTODIAN_CAPABILITY_HMAC_SECRET":      "0123456789abcdef0123456789abcdef",
		"CUSTODIAN_GITHUB_READ_APP_ID":          "42",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM": pemStr,
		"CUSTODIAN_GITHUB_API_URL":              "http://127.0.0.1:18080/api/v3/",
		"CUSTODIAN_SNAPSHOT_ROOT":               snapDir,
		"CUSTODIAN_LOG_FORMAT":                  "json",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- run(ctx, nil, func(k string) string { return envMap[k] }, &stdout, &stderr)
	}()
	defer func() {
		cancel()
		select {
		case <-exitCh:
		case <-time.After(10 * time.Second):
		}
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	ready := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + listenAddr + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("custodian-api never became ready: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}

	verified := true
	adminTok := oidc.MintToken(harness.OIDCTokenClaims{
		Subject:       "sec-admin-001",
		Kind:          "HUMAN",
		Email:         "secadmin@example.com",
		EmailVerified: &verified,
		DisplayName:   "Security Admin",
		Roles:         []string{"policy_admin"},
	})

	secretMarker := "UNIQUE_RAW_RESTRICTED_SOURCE_SENTINEL_XYZ123"
	rawSource := fmt.Sprintf("// Copyright (c) 2026 Acme Corp. Proprietary and Confidential.\npackage vault\n\n// %s\nfunc ComputeProprietaryKeySchedule(seed uint64) []uint64 {\n\tout := make([]uint64, 32)\n\tfor i := range out {\n\t\tseed = seed*6364136223846793005 + 1442695040888963407\n\t\tout[i] = seed ^ uint64(i*97)\n\t}\n\treturn out\n}\n", secretMarker)
	sum := sha256.Sum256([]byte(rawSource))

	createBody, _ := json.Marshal(map[string]any{
		"name":           "pg17-restricted-corpus",
		"classification": "RESTRICTED",
		"files": []map[string]any{
			{
				"path":    "vault/schedule.go",
				"content": rawSource,
				"sha256":  hex.EncodeToString(sum[:]),
			},
		},
	})

	createReq, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/ip-corpora", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+adminTok)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Idempotency-Key", "create-corpus-1")
	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("POST /v1/ip-corpora: %v", err)
	}
	createRespBytes, _ := io.ReadAll(createResp.Body)
	_ = createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/ip-corpora status=%d body=%s", createResp.StatusCode, string(createRespBytes))
	}

	var created struct {
		ID                string `json:"id"`
		Status            string `json:"status"`
		FingerprintCount  int64  `json:"fingerprint_count"`
		LastIndexedDigest string `json:"last_indexed_digest"`
	}
	if err := json.Unmarshal(createRespBytes, &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if created.Status != "READY" || created.FingerprintCount <= 0 || created.LastIndexedDigest == "" {
		t.Fatalf("expected READY corpus with fingerprints, got %+v", created)
	}

	// Verify L1, L2, and L3 rows were persisted in PG17.
	pool := pg.Pool()
	var l1, l2, l3 int64
	if err := pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE layer = 'L1_EXACT_CHUNK'),
			COUNT(*) FILTER (WHERE layer = 'L2_WINNOW_KGRAM'),
			COUNT(*) FILTER (WHERE layer = 'L3_HEADER_MARKER')
		FROM ip_fingerprints
		WHERE corpus_id = $1::uuid
	`, created.ID).Scan(&l1, &l2, &l3); err != nil {
		t.Fatalf("query ip_fingerprints layers: %v", err)
	}
	if l1 == 0 || l2 == 0 || l3 == 0 {
		t.Fatalf("expected L1, L2, and L3 fingerprints in PG, got l1=%d l2=%d l3=%d", l1, l2, l3)
	}

	// Reindex with {force: true} and no files -> 202 READY and idempotent count.
	reindexBody, _ := json.Marshal(map[string]any{"force": true})
	reindexReq, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/ip-corpora/"+created.ID+"/reindex", bytes.NewReader(reindexBody))
	reindexReq.Header.Set("Authorization", "Bearer "+adminTok)
	reindexReq.Header.Set("Content-Type", "application/json")
	reindexReq.Header.Set("Idempotency-Key", "reindex-corpus-1")
	reindexResp, err := client.Do(reindexReq)
	if err != nil {
		t.Fatalf("POST /v1/ip-corpora/{id}/reindex: %v", err)
	}
	reindexRespBytes, _ := io.ReadAll(reindexResp.Body)
	_ = reindexResp.Body.Close()
	if reindexResp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /reindex status=%d body=%s", reindexResp.StatusCode, string(reindexRespBytes))
	}

	var reindexed struct {
		Status              string `json:"status"`
		FingerprintsIndexed int64  `json:"fingerprints_indexed"`
		LastIndexedDigest   string `json:"last_indexed_digest"`
	}
	if err := json.Unmarshal(reindexRespBytes, &reindexed); err != nil {
		t.Fatalf("unmarshal reindex response: %v", err)
	}
	if reindexed.Status != "READY" || reindexed.FingerprintsIndexed != created.FingerprintCount {
		t.Fatalf("expected idempotent READY count=%d, got %+v", created.FingerprintCount, reindexed)
	}

	var totalAfter int64
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_fingerprints WHERE corpus_id = $1::uuid`, created.ID).Scan(&totalAfter); err != nil {
		t.Fatalf("count ip_fingerprints after reindex: %v", err)
	}
	if totalAfter != l1+l2+l3 {
		t.Fatalf("expected idempotent total %d, got %d", l1+l2+l3, totalAfter)
	}

	// Verify fingerprints.Engine.Analyze matches the READY corpus on L1 and L2 before and after failed reindexes.
	fpStore, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("persistence.NewStore: %v", err)
	}
	engine := fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:        fpStore,
		RequireStore: true,
	})
	scanDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanDir, "leaked.go"), []byte(rawSource), 0o600); err != nil {
		t.Fatalf("WriteFile(leaked.go): %v", err)
	}
	inv, err := inspection.WalkWorkspace(scanDir)
	if err != nil {
		t.Fatalf("WalkWorkspace: %v", err)
	}
	findingsBefore, _, err := engine.Analyze(ctx, inspection.Request{TargetDir: scanDir}, inv)
	if err != nil {
		t.Fatalf("Engine.Analyze before failed reindex: %v", err)
	}
	hasL1Before, hasL2Before := false, false
	for _, f := range findingsBefore {
		if f.Category == "IP_EXACT" || strings.Contains(strings.ToLower(f.RuleID), "l1") {
			hasL1Before = true
		}
		if f.Category == "IP_WINNOW" || strings.Contains(strings.ToLower(f.RuleID), "l2") {
			hasL2Before = true
		}
	}
	if !hasL1Before || !hasL2Before {
		t.Fatalf("expected L1 and L2 findings before failed reindex, got %+v", findingsBefore)
	}

	// Invalid reindex requests on the READY corpus (non-existent SourcePath, symlink inside SourcePath,
	// symlink root SourcePath, and changed SourceRef with empty Files/SourcePath) must return 400/422
	// WITHOUT flipping ip_fingerprint_corpora.status from READY to FAILED!
	badDir := filepath.Join(t.TempDir(), "non-existent-corpus-dir")
	symRootTarget := t.TempDir()
	_ = os.WriteFile(filepath.Join(symRootTarget, "sample.go"), []byte(rawSource), 0o600)
	symRootLink := filepath.Join(t.TempDir(), "symlinked-root")
	if err := os.Symlink(symRootTarget, symRootLink); err != nil {
		t.Fatalf("Symlink(root): %v", err)
	}
	symInnerDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(symInnerDir, "sample.go"), []byte(rawSource), 0o600)
	if err := os.Symlink(filepath.Join(symRootTarget, "sample.go"), filepath.Join(symInnerDir, "linked.go")); err != nil {
		t.Fatalf("Symlink(inner): %v", err)
	}

	invalidReindexCases := []struct {
		name       string
		payload    map[string]any
		wantStatus int
	}{
		{
			name:       "non_existent_source_path",
			payload:    map[string]any{"source_path": badDir, "force": true},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "symlink_root_source_path",
			payload:    map[string]any{"source_path": symRootLink, "force": true},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "symlink_inner_source_path",
			payload:    map[string]any{"source_path": symInnerDir, "force": true},
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name:       "changed_source_ref_empty_files",
			payload:    map[string]any{"source_ref": "git://internal/new-ref-without-files", "force": true},
			wantStatus: http.StatusUnprocessableEntity,
		},
	}

	for i, tc := range invalidReindexCases {
		b, _ := json.Marshal(tc.payload)
		req, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/ip-corpora/"+created.ID+"/reindex", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+adminTok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", fmt.Sprintf("invalid-ready-reindex-%d", i))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: request failed: %v", tc.name, err)
		}
		respBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.wantStatus {
			t.Fatalf("%s: status=%d want=%d body=%s", tc.name, resp.StatusCode, tc.wantStatus, string(respBytes))
		}

		var dbStatus string
		var dbFPCount int64
		if err := pool.QueryRow(ctx, `SELECT status, fingerprint_count FROM ip_fingerprint_corpora WHERE id = $1::uuid`, created.ID).Scan(&dbStatus, &dbFPCount); err != nil {
			t.Fatalf("%s: query corpus status: %v", tc.name, err)
		}
		if dbStatus != "READY" || dbFPCount != created.FingerprintCount {
			t.Fatalf("%s: expected PG status=READY count=%d preserved, got status=%s count=%d", tc.name, created.FingerprintCount, dbStatus, dbFPCount)
		}
	}

	findingsAfter, _, err := engine.Analyze(ctx, inspection.Request{TargetDir: scanDir}, inv)
	if err != nil {
		t.Fatalf("Engine.Analyze after failed reindexes: %v", err)
	}
	hasL1After, hasL2After := false, false
	for _, f := range findingsAfter {
		if f.Category == "IP_EXACT" || strings.Contains(strings.ToLower(f.RuleID), "l1") {
			hasL1After = true
		}
		if f.Category == "IP_WINNOW" || strings.Contains(strings.ToLower(f.RuleID), "l2") {
			hasL2After = true
		}
	}
	if !hasL1After || !hasL2After || len(findingsAfter) != len(findingsBefore) {
		t.Fatalf("expected L1/L2 Engine.Analyze findings preserved (%d), got %d (%+v)", len(findingsBefore), len(findingsAfter), findingsAfter)
	}

	// PENDING corpus (created with source_ref only) reindexed without files/source_path -> 422 EMPTY_CORPUS (not 500).
	pendingBody, _ := json.Marshal(map[string]any{
		"name":           "pg17-pending-corpus",
		"classification": "CONFIDENTIAL",
		"source_ref":     "git://internal/pending-corpus",
	})
	pReq, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/ip-corpora", bytes.NewReader(pendingBody))
	pReq.Header.Set("Authorization", "Bearer "+adminTok)
	pReq.Header.Set("Content-Type", "application/json")
	pReq.Header.Set("Idempotency-Key", "create-pending-1")
	pResp, err := client.Do(pReq)
	if err != nil {
		t.Fatalf("POST pending corpus: %v", err)
	}
	pBytes, _ := io.ReadAll(pResp.Body)
	_ = pResp.Body.Close()
	if pResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST pending corpus status=%d body=%s", pResp.StatusCode, string(pBytes))
	}
	var pCreated struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(pBytes, &pCreated)
	if pCreated.Status != "PENDING" {
		t.Fatalf("expected PENDING status, got %s", pCreated.Status)
	}

	emptyReindexReq, _ := http.NewRequest(http.MethodPost, "http://"+listenAddr+"/v1/ip-corpora/"+pCreated.ID+"/reindex", bytes.NewReader(reindexBody))
	emptyReindexReq.Header.Set("Authorization", "Bearer "+adminTok)
	emptyReindexReq.Header.Set("Content-Type", "application/json")
	emptyReindexReq.Header.Set("Idempotency-Key", "reindex-pending-1")
	emptyReindexResp, err := client.Do(emptyReindexReq)
	if err != nil {
		t.Fatalf("POST empty reindex: %v", err)
	}
	emptyReindexBytes, _ := io.ReadAll(emptyReindexResp.Body)
	_ = emptyReindexResp.Body.Close()
	if emptyReindexResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on empty PENDING reindex, got %d body=%s", emptyReindexResp.StatusCode, string(emptyReindexBytes))
	}

	// Verify zero raw corpus source strings leaked in DB tables or logs.
	var leakCount int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM ip_fingerprint_corpora WHERE source_ref LIKE '%' || $1 || '%' OR COALESCE(last_error, '') LIKE '%' || $1 || '%') +
			(SELECT COUNT(*) FROM ip_fingerprints WHERE COALESCE(metadata::text, '') LIKE '%' || $1 || '%') +
			(SELECT COUNT(*) FROM audit_events WHERE COALESCE(payload::text, '') LIKE '%' || $1 || '%')
	`, secretMarker).Scan(&leakCount); err != nil {
		t.Fatalf("check raw source leaks: %v", err)
	}
	if leakCount != 0 {
		t.Fatalf("raw corpus source leaked into PG tables (count=%d)", leakCount)
	}
	if strings.Contains(stdout.String()+stderr.String(), secretMarker) {
		t.Fatal("raw corpus source leaked into server logs")
	}
}

type hookedIPCorpusReindexer struct {
	inner     api.IPCorpusReindexer
	beforeRun func()
}

func (h *hookedIPCorpusReindexer) Reindex(ctx context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	if h.beforeRun != nil {
		h.beforeRun()
	}
	return h.inner.Reindex(ctx, input)
}

func TestIPCorporaProdReindexerCancelTransitionsToFailedAndRetrySucceedsPG17(t *testing.T) {
	ctx := context.Background()
	pg := harness.StartPostgres(t)
	oidc := harness.StartMockOIDC(t, "custodian-api")
	pool := pg.Pool()

	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	oidcVerifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   oidc.Issuer(),
		JWKSURL:  oidc.JWKSURL(),
		Audience: oidc.Audience(),
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	dir, err := identity.NewDirectory(store, identity.DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	hook := &hookedIPCorpusReindexer{
		inner: newIPCorpusReindexer(store),
	}
	router := api.NewRouter(api.Deps{
		Store:             store,
		OIDC:              oidcVerifier,
		Directory:         dir,
		Audit:             audit.NewService(store, logger),
		Logger:            logger,
		IPCorpusReindexer: hook,
	})

	verified := true
	adminTok := oidc.MintToken(harness.OIDCTokenClaims{
		Subject:       "prod-cancel-admin",
		Kind:          "HUMAN",
		Email:         "prodcancel@example.com",
		EmailVerified: &verified,
		DisplayName:   "Prod Cancel Admin",
		Roles:         []string{"policy_admin"},
	})

	rawSource := "// Copyright (c) 2026 Acme Corp. Proprietary and Confidential.\npackage vault\n\nfunc ProdCancelAlgo(x uint64) uint64 {\n\tfor i := 0; i < 16; i++ {\n\t\tx = (x * 6364136223846793005) ^ uint64(i*97)\n\t}\n\treturn x\n}\n"
	sum := sha256.Sum256([]byte(rawSource))
	payloadBytes, err := json.Marshal(map[string]any{
		"name":           "pg17-prod-cancel-retry-corpus",
		"classification": "RESTRICTED",
		"files": []map[string]any{
			{
				"path":    "vault/cancel_algo.go",
				"content": rawSource,
				"sha256":  hex.EncodeToString(sum[:]),
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	// 1. Cancel request context right before production newIPCorpusReindexer runs.
	reqCtx1, cancel1 := context.WithCancel(ctx)
	defer cancel1()
	hook.beforeRun = cancel1

	req1 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/ip-corpora", bytes.NewReader(payloadBytes)).WithContext(reqCtx1)
	req1.Header.Set("Authorization", "Bearer "+adminTok)
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Idempotency-Key", "prod-cancel-retry-idem-1")
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusServiceUnavailable || !strings.Contains(rec1.Body.String(), "REINDEX_CANCELLED") {
		t.Fatalf("expected 503 REINDEX_CANCELLED, got status=%d body=%s", rec1.Code, rec1.Body.String())
	}

	var dbStatus string
	var fpCount int64
	if err := pool.QueryRow(ctx, `SELECT status, fingerprint_count FROM ip_fingerprint_corpora WHERE name = 'pg17-prod-cancel-retry-corpus'`).Scan(&dbStatus, &fpCount); err != nil {
		t.Fatalf("query corpus status after cancel: %v", err)
	}
	if dbStatus != "FAILED" || fpCount != 0 {
		t.Fatalf("expected FAILED (not PENDING) with count=0 after cancel, got status=%q count=%d", dbStatus, fpCount)
	}

	// 2. Also verify expired deadline during Reindex transitions FAILED and maps to REINDEX_TIMEOUT.
	dlCtx, dlCancel := context.WithTimeout(ctx, 1*time.Second)
	defer dlCancel()
	hook.beforeRun = func() {
		<-dlCtx.Done()
	}
	req2 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/ip-corpora", bytes.NewReader(payloadBytes)).WithContext(dlCtx)
	req2.Header.Set("Authorization", "Bearer "+adminTok)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", "prod-cancel-retry-idem-1")
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusServiceUnavailable || !strings.Contains(rec2.Body.String(), "REINDEX_TIMEOUT") {
		t.Fatalf("expected 503 REINDEX_TIMEOUT, got status=%d body=%s", rec2.Code, rec2.Body.String())
	}

	if err := pool.QueryRow(ctx, `SELECT status, fingerprint_count FROM ip_fingerprint_corpora WHERE name = 'pg17-prod-cancel-retry-corpus'`).Scan(&dbStatus, &fpCount); err != nil {
		t.Fatalf("query corpus status after timeout: %v", err)
	}
	if dbStatus != "FAILED" || fpCount != 0 {
		t.Fatalf("expected FAILED (not PENDING) with count=0 after timeout, got status=%q count=%d", dbStatus, fpCount)
	}

	// 3. Retry with identical Idempotency-Key and payload succeeds with 201 Created (READY) and real fingerprints.
	hook.beforeRun = nil
	req3 := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/v1/ip-corpora", bytes.NewReader(payloadBytes)).WithContext(ctx)
	req3.Header.Set("Authorization", "Bearer "+adminTok)
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Idempotency-Key", "prod-cancel-retry-idem-1")
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusCreated {
		t.Fatalf("retry after cancel/timeout expected 201, got status=%d body=%s", rec3.Code, rec3.Body.String())
	}
	var created struct {
		ID               string `json:"id"`
		Status           string `json:"status"`
		FingerprintCount int64  `json:"fingerprint_count"`
	}
	if err := json.Unmarshal(rec3.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal retry response: %v", err)
	}
	if created.Status != "READY" || created.FingerprintCount <= 0 {
		t.Fatalf("expected READY with fingerprints after retry, got %+v", created)
	}
	var persistedCount int64
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM ip_fingerprints WHERE corpus_id = $1::uuid`, created.ID).Scan(&persistedCount); err != nil {
		t.Fatalf("count ip_fingerprints: %v", err)
	}
	if persistedCount != created.FingerprintCount {
		t.Fatalf("expected %d persisted fingerprints, got %d", created.FingerprintCount, persistedCount)
	}
}
