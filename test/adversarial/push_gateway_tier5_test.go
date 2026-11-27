package adversarial_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/snapshots"
)

type advSwitchableSnapshotStore struct {
	mu      sync.Mutex
	inner   domain.SnapshotStore
	failErr error
}

func (s *advSwitchableSnapshotStore) setFailErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failErr = err
}

func (s *advSwitchableSnapshotStore) Put(ctx context.Context, req domain.PutRequest, r io.Reader, size int64) (domain.Artifact, error) {
	s.mu.Lock()
	err := s.failErr
	s.mu.Unlock()
	if err != nil {
		return domain.Artifact{}, err
	}
	return s.inner.Put(ctx, req, r, size)
}

func (s *advSwitchableSnapshotStore) Open(ctx context.Context, artifact domain.Artifact) (io.ReadCloser, error) {
	return s.inner.Open(ctx, artifact)
}

func (s *advSwitchableSnapshotStore) Verify(ctx context.Context, artifact domain.Artifact) error {
	return s.inner.Verify(ctx, artifact)
}

func (s *advSwitchableSnapshotStore) Delete(ctx context.Context, artifact domain.Artifact) error {
	return s.inner.Delete(ctx, artifact)
}

type advSwitchableReindexer struct {
	mu      sync.Mutex
	inner   api.IPCorpusReindexer
	failErr error
}

func (r *advSwitchableReindexer) setFailErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failErr = err
}

func (r *advSwitchableReindexer) Reindex(ctx context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	r.mu.Lock()
	err := r.failErr
	r.mu.Unlock()
	if err != nil {
		return api.IPCorpusReindexResult{}, err
	}
	return r.inner.Reindex(ctx, input)
}

// Tier-5 Finding 1 & Finding 2: PASSIVE_AUDIT must never block clean developer pushes on
// corrupt PUSH_EGRESS policy bundles, SnapshotStore outages, or fetchEphemeralBaseline outages,
// while ENFORCE_BLOCK remains strictly fail-closed (0 upstream bytes) and corrupt EGRESS-only
// bundles never block PUSH_EGRESS pushes.
func TestADV_PG_Tier5_PassiveAuditNonBlockingInfraOutages(t *testing.T) {
	var swSnap *advSwitchableSnapshotStore
	s := newPGAdvStack(t, func(o *pgAdvOptions) {
		local, err := snapshots.NewLocalStore(snapshots.LocalConfig{RootDir: t.TempDir()})
		if err != nil {
			t.Fatalf("NewLocalStore: %v", err)
		}
		swSnap = &advSwitchableSnapshotStore{inner: local}
		o.snapshotStore = swSnap
	})
	ctx := context.Background()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	setMode := func(mode, delivery string) {
		t.Helper()
		if _, err := s.pg.Pool().Exec(ctx, `
			UPDATE repositories
			SET egress_mode = $2, passive_audit_delivery = $3
			WHERE id = $1
		`, s.repo.ID, mode, delivery); err != nil {
			t.Fatalf("update repo mode: %v", err)
		}
	}

	work := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "tier5 clean commit", map[string]string{
		"tier5_clean.go": "package main\nfunc Tier5Clean() int { return 42 }\n",
	})

	// 1. Corrupt EGRESS-domain bundle (stages: ["EGRESS"]) must NOT block ENFORCE_BLOCK pushes.
	setMode("ENFORCE_BLOCK", "ASYNC")
	egressCorruptRow, err := s.store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:         "tier5-corrupt-egress-only",
		Version:      "1.0.0",
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: &s.repo.ID,
		Digest:       domain.SHA256Hex([]byte("tier5-corrupt-egress-only")),
		Definition:   json.RawMessage(`{"rules":[{"id":"bad-egress","stages":["EGRESS"],"when":"((("}]}`),
		ActivatedAt:  ptrTime(time.Now().UTC()),
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle(egress corrupt): %v", err)
	}
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-egress-corrupt-ignored"); c != 0 {
		t.Fatalf("expected corrupt EGRESS-only bundle not to block PUSH_EGRESS, exit=%d out:\n%s", c, out)
	}
	sessEgress := s.latestPushSession(t, &s.repo.ID)
	if sessEgress.Status != domain.PushSessionStatusCompleted || !sessEgress.UpstreamForwarded {
		t.Fatalf("expected COMPLETED push despite corrupt EGRESS-only bundle, got %+v", sessEgress)
	}
	_, _ = s.pg.Pool().Exec(ctx, `UPDATE policy_bundles SET activated_at = NULL WHERE id = $1`, egressCorruptRow.ID)

	// 2. Corrupt active REPO PUSH_EGRESS bundle: ENFORCE_BLOCK fails closed (0 bytes); PASSIVE_AUDIT forwards!
	corruptRepoBundle, err := s.store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:         "tier5-corrupt-push-repo",
		Version:      "1.0.0",
		Scope:        domain.PolicyScopeRepo,
		RepositoryID: &s.repo.ID,
		Digest:       domain.SHA256Hex([]byte("tier5-corrupt-push-repo")),
		Definition:   json.RawMessage(`{"rules":[{"id":"bad-push","stages":["PUSH_EGRESS"],"when":"((("}]}`),
		ActivatedAt:  ptrTime(time.Now().UTC()),
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle(push corrupt): %v", err)
	}

	setMode("ENFORCE_BLOCK", "ASYNC")
	baseObj := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-repo-corrupt-enf"); c == 0 {
		t.Fatal("expected corrupt REPO PUSH_EGRESS bundle to fail closed in ENFORCE_BLOCK")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObj, "")
	sessRepoEnf := s.latestPushSession(t, &s.repo.ID)
	if sessRepoEnf.Status != domain.PushSessionStatusFailed || sessRepoEnf.ErrorCode == nil || *sessRepoEnf.ErrorCode != "INVALID_POLICY_BUNDLE" {
		t.Fatalf("expected FAILED/INVALID_POLICY_BUNDLE in ENFORCE_BLOCK, got %+v", sessRepoEnf)
	}

	setMode("PASSIVE_AUDIT", "INLINE_WARN")
	s.upstream.resetCounters()
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-repo-corrupt-pa"); c != 0 || !strings.Contains(out, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT forward on corrupt REPO bundle, exit=%d out:\n%s", c, out)
	}
	if recvCalls, recvBytes, _, _, _, _ := s.upstream.stats(); recvCalls != 1 || recvBytes == 0 {
		t.Fatalf("expected 1 forwarded receive-pack call in PASSIVE_AUDIT, got calls=%d bytes=%d", recvCalls, recvBytes)
	}
	sessRepoPA := s.latestPushSession(t, &s.repo.ID)
	if sessRepoPA.Status != domain.PushSessionStatusObservedWouldBlock || sessRepoPA.Enforced || !sessRepoPA.UpstreamForwarded {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK forwarded session in PASSIVE_AUDIT, got %+v", sessRepoPA)
	}
	_, _ = s.pg.Pool().Exec(ctx, `UPDATE policy_bundles SET activated_at = NULL WHERE id = $1`, corruptRepoBundle.ID)

	// 3. Corrupt active ORG PUSH_EGRESS bundle in PASSIVE_AUDIT -> forwards without blocking!
	corruptOrgBundle, err := s.store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:        "tier5-corrupt-push-org",
		Version:     "1.0.0",
		Scope:       domain.PolicyScopeOrg,
		Digest:      domain.SHA256Hex([]byte("tier5-corrupt-push-org")),
		Definition:  json.RawMessage(`{"rules":[{"id":"bad-org-push","stages":["PUSH_EGRESS"],"when":"((("}]}`),
		ActivatedAt: ptrTime(time.Now().UTC()),
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle(org corrupt): %v", err)
	}
	s.upstream.resetCounters()
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-org-corrupt-pa"); c != 0 || !strings.Contains(out, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT forward on corrupt ORG bundle, exit=%d out:\n%s", c, out)
	}
	sessOrgPA := s.latestPushSession(t, &s.repo.ID)
	if sessOrgPA.Status != domain.PushSessionStatusObservedWouldBlock || !sessOrgPA.UpstreamForwarded {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK on corrupt ORG bundle in PASSIVE_AUDIT, got %+v", sessOrgPA)
	}
	_, _ = s.pg.Pool().Exec(ctx, `UPDATE policy_bundles SET activated_at = NULL WHERE id = $1`, corruptOrgBundle.ID)

	// 4. SnapshotStore outage: ENFORCE_BLOCK fails closed (0 bytes); PASSIVE_AUDIT forwards safely without nil deref!
	swSnap.setFailErr(domain.Unavailable("STORAGE_UNAVAILABLE", "local snapshot storage unavailable"))
	setMode("ENFORCE_BLOCK", "ASYNC")
	baseObjSnap := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-snap-enf"); c == 0 {
		t.Fatal("expected SnapshotStore outage to fail closed in ENFORCE_BLOCK")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjSnap, "")

	setMode("PASSIVE_AUDIT", "INLINE_WARN")
	s.upstream.resetCounters()
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-snap-pa"); c != 0 || !strings.Contains(out, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT forward on SnapshotStore outage, exit=%d out:\n%s", c, out)
	}
	if recvCalls, recvBytes, _, _, _, _ := s.upstream.stats(); recvCalls != 1 || recvBytes == 0 {
		t.Fatalf("expected 1 forwarded receive-pack call on SnapshotStore outage, got calls=%d bytes=%d", recvCalls, recvBytes)
	}
	sessSnapPA := s.latestPushSession(t, &s.repo.ID)
	if sessSnapPA.Status != domain.PushSessionStatusObservedWouldBlock || !sessSnapPA.UpstreamForwarded {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK on SnapshotStore outage in PASSIVE_AUDIT, got %+v", sessSnapPA)
	}
	swSnap.setFailErr(nil)

	// 5. fetchEphemeralBaseline outage (git-upload-pack HTTP 500 during receive-pack baseline fetch)
	// on an incremental push: ENFORCE_BLOCK fails closed (0 bytes); PASSIVE_AUDIT forwards raw pack cleanly!
	s.upstream.setUploadPackOverride(func(ownerRepo string, body []byte) (int, []byte, bool) {
		return http.StatusInternalServerError, []byte("baseline upload-pack outage"), true
	})
	defer s.upstream.setUploadPackOverride(nil)

	setMode("ENFORCE_BLOCK", "ASYNC")
	baseObjBase := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-base-enf"); c == 0 {
		t.Fatal("expected fetchEphemeralBaseline outage to fail closed in ENFORCE_BLOCK")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjBase, "")

	setMode("PASSIVE_AUDIT", "INLINE_WARN")
	s.upstream.resetCounters()
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/t5-base-pa"); c != 0 || !strings.Contains(out, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT forward on baseline fetch outage, exit=%d out:\n%s", c, out)
	}
	if recvCalls, recvBytes, _, _, _, _ := s.upstream.stats(); recvCalls != 1 || recvBytes == 0 {
		t.Fatalf("expected 1 forwarded receive-pack call on baseline fetch outage, got calls=%d bytes=%d", recvCalls, recvBytes)
	}
	if gotSHA := s.upstream.bareRefSHA(t, "acme/service", "refs/heads/t5-base-pa"); gotSHA == "" {
		t.Fatal("expected t5-base-pa ref landed upstream despite baseline fetch outage in PASSIVE_AUDIT")
	}
	sessBasePA := s.latestPushSession(t, &s.repo.ID)
	if sessBasePA.Status != domain.PushSessionStatusObservedWouldBlock || !sessBasePA.UpstreamForwarded {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK on baseline fetch outage in PASSIVE_AUDIT, got %+v", sessBasePA)
	}
	s.assertZeroSecretsInLogs(t)
}

// Tier-5 Finding 3: Cumulative lfsTotalBytes int64 overflow must fail closed to QUARANTINED
// (LFS_SIZE_OVERFLOW) with 0 upstream bytes in ENFORCE_BLOCK, and never trigger PostgreSQL
// CHECK (lfs_total_bytes >= 0) CONSTRAINT_VIOLATION or wrap positive in PASSIVE_AUDIT.
func TestADV_PG_Tier5_LFSTotalBytesOverflowRejected(t *testing.T) {
	s := newPGAdvStack(t)
	ctx := context.Background()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	mkLFSPtr := func(tag string, sz int64) string {
		sum := sha256.Sum256([]byte(tag))
		return fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", hex.EncodeToString(sum[:]), sz)
	}

	// Case A: 2 pointers each size MaxInt64 (would wrap to -2 -> PG CONSTRAINT_VIOLATION).
	work2 := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "lfs overflow 2 ptrs", map[string]string{
		"a.bin": mkLFSPtr("lfs-overflow-a", math.MaxInt64),
		"b.bin": mkLFSPtr("lfs-overflow-b", math.MaxInt64),
	})
	baseObj := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, work2, httpEnv, "push", "origin", "HEAD:refs/heads/t5-lfs-ovf-2"); c == 0 {
		t.Fatal("expected 2x MaxInt64 LFS pointers to fail closed in ENFORCE_BLOCK")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObj, "")
	sess2 := s.latestPushSession(t, &s.repo.ID)
	if sess2.Status != domain.PushSessionStatusQuarantined || sess2.ErrorCode == nil || *sess2.ErrorCode != "LFS_SIZE_OVERFLOW" {
		t.Fatalf("expected QUARANTINED/LFS_SIZE_OVERFLOW for 2x MaxInt64, got %+v", sess2)
	}

	// Case B: 3 pointers (MaxInt64, MaxInt64, 100) (would wrap modulo 2^64 to +98).
	work3 := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "lfs overflow 3 ptrs", map[string]string{
		"a.bin": mkLFSPtr("lfs-overflow-3a", math.MaxInt64),
		"b.bin": mkLFSPtr("lfs-overflow-3b", math.MaxInt64),
		"c.bin": mkLFSPtr("lfs-overflow-3c", 100),
	})
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, work3, httpEnv, "push", "origin", "HEAD:refs/heads/t5-lfs-ovf-3"); c == 0 {
		t.Fatal("expected 3-pointer int64 wraparound to fail closed in ENFORCE_BLOCK")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObj, "")
	sess3 := s.latestPushSession(t, &s.repo.ID)
	if sess3.Status != domain.PushSessionStatusQuarantined || sess3.ErrorCode == nil || *sess3.ErrorCode != "LFS_SIZE_OVERFLOW" || sess3.LFSTotalBytes != 0 {
		t.Fatalf("expected QUARANTINED/LFS_SIZE_OVERFLOW with LFSTotalBytes=0 (never wrapped 98), got %+v", sess3)
	}

	// Case C: PASSIVE_AUDIT must saturate lfs_total_bytes at MaxInt64 without DB CONSTRAINT_VIOLATION and forward cleanly.
	if _, err := s.pg.Pool().Exec(ctx, `UPDATE repositories SET egress_mode = 'PASSIVE_AUDIT', passive_audit_delivery = 'INLINE_WARN' WHERE id = $1`, s.repo.ID); err != nil {
		t.Fatalf("set PASSIVE_AUDIT: %v", err)
	}
	s.upstream.resetCounters()
	if out, c := runAdvGit(t, work3, httpEnv, "push", "origin", "HEAD:refs/heads/t5-lfs-ovf-pa"); c != 0 || !strings.Contains(out, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT push to forward without DB constraint crash, exit=%d out:\n%s", c, out)
	}
	sessPA := s.latestPushSession(t, &s.repo.ID)
	if sessPA.Status != domain.PushSessionStatusObservedWouldBlock || !sessPA.UpstreamForwarded || sessPA.LFSTotalBytes != math.MaxInt64 {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK forwarded with LFSTotalBytes=MaxInt64, got %+v", sessPA)
	}
	s.assertZeroSecretsInLogs(t)
}

// Tier-5 Finding 4 & Finding 5: Annotated tag peeled refs (^{}) in baseline resolution, and
// upstream receive.advertisePushOptions = true with git push -o ... over HTTPS & SSH.
func TestADV_PG_Tier5_AnnotatedTagBaselineAndUpstreamPushOptions(t *testing.T) {
	s := newPGAdvStack(t)
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	// 1. Seed an annotated tag v1.0 on upstream bare repo and verify real incremental push succeeds.
	bareDir := s.upstream.barePath("acme/service")
	tagSeed := filepath.Join(t.TempDir(), "tag-seed")
	mustAdvGit(t, "", nil, "clone", bareDir, tagSeed)
	mustAdvGit(t, tagSeed, nil, "config", "user.name", "Seed")
	mustAdvGit(t, tagSeed, nil, "config", "user.email", "seed@example.com")
	mustAdvGit(t, tagSeed, nil, "tag", "-a", "v1.0", "-m", "annotated v1.0")
	mustAdvGit(t, tagSeed, nil, "push", bareDir, "refs/tags/v1.0")

	workTag := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "push with annotated tag upstream", map[string]string{
		"tag_ok.go": "package main\nfunc TagOK() {}\n",
	})
	if out, c := runAdvGit(t, workTag, httpEnv, "push", "origin", "HEAD:refs/heads/t5-annotated-tag-ok"); c != 0 {
		t.Fatalf("push against upstream with annotated tag failed (%d):\n%s", c, out)
	}
	sessTag := s.latestPushSession(t, &s.repo.ID)
	if sessTag.Status != domain.PushSessionStatusCompleted || !sessTag.UpstreamForwarded {
		t.Fatalf("expected COMPLETED push with annotated tag upstream, got %+v", sessTag)
	}

	// 2. Upstream receive.advertisePushOptions = true: git push -o ci.skip=true must NOT produce
	// QUARANTINED/INVALID_PACK_CHECKSUM over HTTPS or SSH, and raw push-options must fail cleanly.
	mustAdvGit(t, bareDir, nil, "config", "receive.advertisePushOptions", "true")

	// Direct upstream baseline succeeds with -o.
	directWork := filepath.Join(t.TempDir(), "direct-po")
	mustAdvGit(t, "", nil, "clone", bareDir, directWork)
	mustAdvGit(t, directWork, nil, "config", "user.name", "Direct")
	mustAdvGit(t, directWork, nil, "config", "user.email", "direct@example.com")
	_ = os.WriteFile(filepath.Join(directWork, "direct.txt"), []byte("direct\n"), 0o600)
	mustAdvGit(t, directWork, nil, "add", "direct.txt")
	mustAdvGit(t, directWork, nil, "commit", "-m", "direct push option")
	mustAdvGit(t, directWork, nil, "push", "-o", "ci.skip=true", bareDir, "HEAD:refs/heads/t5-direct-po")

	// Gateway HTTPS push with -o ci.skip=true rejects cleanly before receive-pack (no INVALID_PACK_CHECKSUM).
	workPO := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "gateway push options", map[string]string{
		"po.txt": "push-option\n",
	})
	baseSessions := s.pushSessionCount(t)
	s.upstream.resetCounters()
	outHTTP, cHTTP := runAdvGit(t, workPO, httpEnv, "push", "-o", "ci.skip=true", "origin", "HEAD:refs/heads/t5-gw-po-http")
	if cHTTP == 0 {
		t.Fatalf("expected push-options to be cleanly unsupported when stripped, got exit 0:\n%s", outHTTP)
	}
	if strings.Contains(outHTTP, "INVALID_PACK_CHECKSUM") || !strings.Contains(outHTTP, "does not support push options") {
		t.Fatalf("expected clean 'does not support push options' without INVALID_PACK_CHECKSUM, got:\n%s", outHTTP)
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", s.upstream.bareObjectCount(t, "acme/service"), "")
	if got := s.pushSessionCount(t); got != baseSessions {
		t.Fatalf("expected 0 quarantined push_sessions from client-aborted push-options, got %d vs %d", got, baseSessions)
	}

	// Gateway SSH push with -o ci.skip=true also sees push-options stripped cleanly.
	if _, err := exec.LookPath("ssh"); err == nil {
		aliceSSH := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "t5-po-ssh", 5501, "-1m:+1h", nil)
		outSSH, cSSH := runAdvGit(t, workPO, aliceSSH.gitEnv(true), "push", "-o", "ci.skip=true", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/t5-gw-po-ssh")
		if cSSH == 0 {
			t.Fatalf("expected SSH push-options to be cleanly unsupported when stripped, got exit 0:\n%s", outSSH)
		}
		if strings.Contains(outSSH, "INVALID_PACK_CHECKSUM") || !strings.Contains(outSSH, "does not support push options") {
			t.Fatalf("expected clean SSH 'does not support push options' without INVALID_PACK_CHECKSUM, got:\n%s", outSSH)
		}
	}

	// Raw Smart-HTTP client forcing push-options capability + option pkt-lines + valid PACK -> 400 UNSUPPORTED_CAPABILITY (not INVALID_PACK_CHECKSUM).
	headSHA := strings.TrimSpace(mustAdvGit(t, workPO, nil, "rev-parse", "HEAD"))
	rawPack := buildAdvPackFromRevs(t, workPO, []string{headSHA})
	var rawBody bytes.Buffer
	writeAdvPktLine(&rawBody, []byte(fmt.Sprintf("%s %s refs/heads/t5-raw-po\x00report-status side-band-64k push-options\n", quarantine.ZeroOID, headSHA)))
	rawBody.WriteString("0000")
	writeAdvPktLine(&rawBody, []byte("ci.skip=true\n"))
	rawBody.WriteString("0000")
	rawBody.Write(rawPack)

	req, err := http.NewRequest(http.MethodPost, s.gwHTTP.URL+"/acme/service.git/git-receive-pack", &rawBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.aliceJWT)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	resp, err := s.gwHTTP.Client().Do(req)
	if err != nil {
		t.Fatalf("POST raw push-options: %v", err)
	}
	respBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(respBytes), "UNSUPPORTED_CAPABILITY") {
		t.Fatalf("expected 400 UNSUPPORTED_CAPABILITY for raw push-options, got %d: %s", resp.StatusCode, string(respBytes))
	}
	s.assertZeroSecretsInLogs(t)
}

// Tier-5 Findings 6, 7, & 8:
// - Consumed APPROVAL_REQUIRED push session cannot be re-approved or rejected (409 APPROVAL_ALREADY_CONSUMED).
// - READY IP corpus reindex failure (ctx cancel / RunCorpusTx error) preserves READY and active blocking.
// - POST /v1/ip-corpora transient 503 failure + retry with identical Idempotency-Key & payload recovers to 201 READY.
func TestADV_PG_Tier5_ConsumedApprovalReapproveAndCorpusLifecycle(t *testing.T) {
	var swReindexer *advSwitchableReindexer
	s := newPGAdvStack(t, func(o *pgAdvOptions) {
		o.corpusReindexer = func(base api.IPCorpusReindexer) api.IPCorpusReindexer {
			swReindexer = &advSwitchableReindexer{inner: base}
			return swReindexer
		}
	})
	ctx := context.Background()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	// 1. Finding 6: Consumed approval release cannot be re-approved or rejected via POST /v1/pushes/{S1}/approvals.
	confCode := `// Internal Billing Engine
package billing

func ComputeTieredInvoice(units int, rateCents int) int {
	total := units * rateCents
	if units > 500 {
		total = total - (total / 10)
	}
	return total
}
`
	s.indexCorpus(t, "t5-conf-billing", domain.ClassificationConfidential, []fingerprints.CorpusFile{
		{Path: "billing.go", Content: []byte(confCode)},
	})

	workConf := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "confidential billing push", map[string]string{
		"billing_copy.go": confCode,
	})
	if _, c := runAdvGit(t, workConf, httpEnv, "push", "origin", "HEAD:refs/heads/t5-approval-s1"); c == 0 {
		t.Fatal("expected initial CONFIDENTIAL push S1 to require approval")
	}
	s1 := s.latestPushSession(t, &s.repo.ID)
	if s1.Status != domain.PushSessionStatusApprovalRequired || s1.PushManifestDigest == nil {
		t.Fatalf("expected S1 APPROVAL_REQUIRED with PushManifestDigest, got %+v", s1)
	}

	// Bob approves S1 -> R1 (201).
	appCode, appBody := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+s1.ID.String()+"/approvals", s.bobJWT, "t5-approve-s1-r1", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *s1.PushManifestDigest,
		"reason":               "single-use tier5 approval",
	})
	if appCode != http.StatusCreated {
		t.Fatalf("initial APPROVE S1 expected 201, got %d: %s", appCode, string(appBody))
	}

	// Alice retries S2 -> consumes R1 and lands upstream.
	if out, c := runAdvGit(t, workConf, httpEnv, "push", "origin", "HEAD:refs/heads/t5-approval-s1"); c != 0 {
		t.Fatalf("approved retry S2 failed (%d):\n%s", c, out)
	}
	s2 := s.latestPushSession(t, &s.repo.ID)
	if s2.Status != domain.PushSessionStatusCompleted || !s2.UpstreamForwarded {
		t.Fatalf("expected S2 COMPLETED, got %+v", s2)
	}

	// Re-approving OR rejecting S1 with fresh Idempotency-Keys must fail with 409 APPROVAL_ALREADY_CONSUMED.
	for _, tc := range []struct {
		key      string
		decision string
	}{
		{"t5-reapprove-s1-r2", "APPROVE"},
		{"t5-reject-s1-after", "REJECT"},
	} {
		reCode, reBody := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+s1.ID.String()+"/approvals", s.bobJWT, tc.key, map[string]any{
			"decision":             tc.decision,
			"push_manifest_digest": *s1.PushManifestDigest,
			"reason":               "replay attempt",
		})
		if reCode != http.StatusConflict || !strings.Contains(string(reBody), "APPROVAL_ALREADY_CONSUMED") {
			t.Fatalf("%s on consumed S1 expected 409 APPROVAL_ALREADY_CONSUMED, got %d: %s", tc.decision, reCode, string(reBody))
		}
	}
	var unconsumed int
	if err := s.pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM push_approval_releases WHERE push_session_id = $1 AND consumed_at IS NULL`, s1.ID).Scan(&unconsumed); err != nil {
		t.Fatalf("count unconsumed releases: %v", err)
	}
	if unconsumed != 0 {
		t.Fatalf("expected 0 unconsumed releases for S1, got %d", unconsumed)
	}

	// Delete branch upstream and verify replay S3 STILL hits APPROVAL_REQUIRED with 0 upstream bytes.
	mustAdvGit(t, s.upstream.barePath("acme/service"), nil, "update-ref", "-d", "refs/heads/t5-approval-s1")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, workConf, httpEnv, "push", "origin", "HEAD:refs/heads/t5-approval-s1"); c == 0 {
		t.Fatal("expected S3 replay after consumed R1 + blocked R2 to require approval")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", s.upstream.bareObjectCount(t, "acme/service"), "")

	// 2. Finding 8 & Finding 7: POST /v1/ip-corpora transient 503 + identical Idempotency-Key retry -> 201 READY,
	// then failed READY reindex preserves READY and actively blocks RESTRICTED IP pushes.
	restrictedCode := `// Copyright (c) Acme Corp Proprietary Restricted
package coresecret

func ProprietaryCipherRound(v uint64, k uint64) uint64 {
	v ^= k
	v = (v << 13) | (v >> 51)
	return v * 0x9e3779b97f4a7c15
}
`
	createPayload := map[string]any{
		"name":           "t5-restricted-retry-corpus",
		"classification": "RESTRICTED",
		"files": []map[string]any{
			{"path": "cipher.go", "content": restrictedCode},
		},
	}

	swReindexer.setFailErr(domain.Unavailable("REINDEX_IO", "transient db/io outage"))
	c1, b1 := s.doAPIJSON(t, http.MethodPost, "/v1/ip-corpora", s.adminJWT, "t5-corp-create-idem", createPayload)
	if c1 != http.StatusServiceUnavailable {
		t.Fatalf("first failing POST /v1/ip-corpora expected 503, got %d: %s", c1, string(b1))
	}

	swReindexer.setFailErr(nil)
	c2, b2 := s.doAPIJSON(t, http.MethodPost, "/v1/ip-corpora", s.adminJWT, "t5-corp-create-idem", createPayload)
	if c2 != http.StatusCreated {
		t.Fatalf("idempotent retry POST /v1/ip-corpora expected 201, got %d: %s", c2, string(b2))
	}
	var corpDTO api.IPCorpusDTO
	if err := json.Unmarshal(b2, &corpDTO); err != nil {
		t.Fatalf("unmarshal corpus DTO: %v", err)
	}
	if corpDTO.Status != "READY" || corpDTO.FingerprintCount <= 0 {
		t.Fatalf("expected READY corpus with fingerprints after retry, got %+v", corpDTO)
	}

	// Simulate transient reindex failure (503) on the READY corpus -> corpus MUST remain READY and continue blocking!
	swReindexer.setFailErr(domain.Unavailable("REINDEX_CANCELLED", "transient reindex failure"))
	rxCode, rxBody := s.doAPIJSON(t, http.MethodPost, "/v1/ip-corpora/"+corpDTO.ID+"/reindex", s.adminJWT, "t5-ready-reindex-fail", map[string]any{
		"force": true,
		"files": []map[string]any{{"path": "cipher.go", "content": restrictedCode + "\n// v2\n"}},
	})
	if rxCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on failing reindex, got %d: %s", rxCode, string(rxBody))
	}
	swReindexer.setFailErr(nil)

	var postStatus string
	var postCount int64
	if err := s.pg.Pool().QueryRow(ctx, `SELECT status, fingerprint_count FROM ip_fingerprint_corpora WHERE id = $1::uuid`, corpDTO.ID).Scan(&postStatus, &postCount); err != nil {
		t.Fatalf("query corpus after failed reindex: %v", err)
	}
	if postStatus != "READY" || postCount != corpDTO.FingerprintCount {
		t.Fatalf("expected READY and count=%d preserved after failed reindex, got status=%s count=%d", corpDTO.FingerprintCount, postStatus, postCount)
	}

	workRestr := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "restricted leak after failed reindex", map[string]string{
		"leak_cipher.go": restrictedCode,
	})
	baseObjRestr := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, workRestr, httpEnv, "push", "origin", "HEAD:refs/heads/t5-restricted-blocked"); c == 0 {
		t.Fatal("expected RESTRICTED IP push to still be blocked after failed READY reindex")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjRestr, "")
	sessRestr := s.latestPushSession(t, &s.repo.ID)
	if sessRestr.Status != domain.PushSessionStatusBlocked || sessRestr.Verdict == nil || *sessRestr.Verdict != domain.PolicyEffectDeny {
		t.Fatalf("expected BLOCKED/DENY on RESTRICTED IP push, got %+v", sessRestr)
	}
	s.assertZeroSecretsInLogs(t)
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
