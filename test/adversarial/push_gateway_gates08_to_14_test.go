package adversarial_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/test/fixtures"
)

// Gate 8: Digest-bound approval (principal_id, destination, push_manifest_digest) — SoD/RBAC, expiry, tamper, wrong principal/destination, single-use replay, and concurrent -race replay.
func TestADV_PG_Gate08_ApprovalTamperReplayAndExpiryRejected(t *testing.T) {
	s := newPGAdvStack(t)
	ctx := context.Background()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	s.indexCorpus(t, "gate08-confidential", domain.ClassificationConfidential, []fingerprints.CorpusFile{
		{Path: "billing/ledger.go", Content: []byte(confidentialHeaderlessSampleGo)},
	})

	// Seed second repository for wrong-destination check.
	s.registerRepo(t, 1003, "acme/service-other", domain.ClassificationInternal, domain.EgressModeEnforceBlock, true, false)
	s.upstream.seedBareRepo(t, "acme/service-other", map[string]string{"README.md": "other\n"})

	baseObjCount := s.upstream.bareObjectCount(t, "acme/service")
	baseMainSHA := s.upstream.bareRefSHA(t, "acme/service", "refs/heads/main")

	// 1. Alice pushes CONFIDENTIAL code -> REQUIRE_APPROVAL (APPROVAL_REQUIRED, 0 upstream bytes).
	s.upstream.resetCounters()
	workOrig := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "gate08 confidential push", map[string]string{
		"billing_copy.go": confidentialHeaderlessSampleGo,
	})
	outInit, codeInit := runAdvGit(t, workOrig, httpEnv, "push", "origin", "HEAD:refs/heads/feat-app")
	if codeInit == 0 || !strings.Contains(outInit, "REQUIRE_APPROVAL") {
		t.Fatalf("expected REQUIRE_APPROVAL on initial confidential push, code=%d out:\n%s", codeInit, outInit)
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjCount, baseMainSHA)
	sessInit := s.latestPushSession(t, &s.repo.ID)
	if sessInit.Status != domain.PushSessionStatusApprovalRequired || sessInit.PushManifestDigest == nil {
		t.Fatalf("expected APPROVAL_REQUIRED with PushManifestDigest, got %+v", sessInit)
	}

	// 2. SoD & RBAC checks on POST /v1/pushes/{id}/approvals.
	// Alice self-approval -> 403 (APPROVAL_RELEASE_SOD_VIOLATION or PUSH_APPROVER_REQUIRED).
	selfCode, selfRaw := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessInit.ID.String()+"/approvals", s.aliceJWT, "g8-self", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessInit.PushManifestDigest,
	})
	if selfCode != http.StatusForbidden {
		t.Fatalf("expected 403 on self-approval, got %d: %s", selfCode, string(selfRaw))
	}
	// Even when Alice has approver groups, SoD rejects self-approval with APPROVAL_RELEASE_SOD_VIOLATION.
	evTrue := true
	aliceApproverJWT := s.oidc.MintToken(harness.OIDCTokenClaims{
		Subject:       "alice-human-001",
		Kind:          "HUMAN",
		Email:         "alice@example.com",
		EmailVerified: &evTrue,
		DisplayName:   "Alice Developer",
		Groups:        []string{"engineering", "security-admins", "ip-review"},
		Roles:         []string{"developer", "reviewer"},
	})
	sodCode, sodRaw := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessInit.ID.String()+"/approvals", aliceApproverJWT, "g8-sod", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessInit.PushManifestDigest,
	})
	if sodCode != http.StatusForbidden || !strings.Contains(string(sodRaw), "APPROVAL_RELEASE_SOD_VIOLATION") {
		t.Fatalf("expected 403 APPROVAL_RELEASE_SOD_VIOLATION, got %d: %s", sodCode, string(sodRaw))
	}
	// Restore Alice's standard groups in principals table.
	_, _ = s.pg.Pool().Exec(ctx, `UPDATE principals SET groups = ARRAY['engineering'] WHERE id = $1`, s.alice.ID)

	// Auditor approval -> 403 PUSH_APPROVER_REQUIRED.
	audCode, _ := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessInit.ID.String()+"/approvals", s.auditorJWT, "g8-aud", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessInit.PushManifestDigest,
	})
	if audCode != http.StatusForbidden {
		t.Fatalf("expected 403 on auditor approval, got %d", audCode)
	}

	// Bob approves with ttl_seconds: 1 -> 201.
	expCode, expRaw := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessInit.ID.String()+"/approvals", s.bobJWT, "g8-ttl1", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessInit.PushManifestDigest,
		"ttl_seconds":          1,
		"reason":               "short ttl test",
	})
	if expCode != http.StatusCreated {
		t.Fatalf("expected 201 on ttl=1 approval, got %d: %s", expCode, string(expRaw))
	}

	// Subcase A: Expired approval rejected (0 upstream bytes), then fresh approval succeeds (auto-revoking expired).
	time.Sleep(1300 * time.Millisecond)
	s.upstream.resetCounters()
	if out, c := runAdvGit(t, workOrig, httpEnv, "push", "origin", "HEAD:refs/heads/feat-app"); c == 0 || !strings.Contains(out, "REQUIRE_APPROVAL") {
		t.Fatalf("expected expired approval to be rejected (code=%d):\n%s", c, out)
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjCount, baseMainSHA)

	appCode, appRaw := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessInit.ID.String()+"/approvals", s.bobJWT, "g8-ttl600", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessInit.PushManifestDigest,
		"ttl_seconds":          600,
		"reason":               "valid review",
	})
	if appCode != http.StatusCreated {
		t.Fatalf("expected 201 replacing expired approval, got %d: %s", appCode, string(appRaw))
	}
	var relCreated struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(appRaw, &relCreated)
	relUUID := uuid.MustParse(relCreated.ID)

	// Subcase B: Tamper & binding mismatches (0 upstream bytes, approval remains unconsumed).
	// B1: 1-byte change.
	work1Byte := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "gate08 confidential push", map[string]string{
		"billing_copy.go": confidentialHeaderlessSampleGo + "\n",
	})
	if _, c := runAdvGit(t, work1Byte, httpEnv, "push", "origin", "HEAD:refs/heads/feat-app"); c == 0 {
		t.Fatal("expected 1-byte tamper push to fail approval check")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjCount, baseMainSHA)

	// B2: Amended commit (identical tree, different commit OID/message).
	workAmend := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "gate08 confidential push", map[string]string{
		"billing_copy.go": confidentialHeaderlessSampleGo,
	})
	mustAdvGit(t, workAmend, nil, "commit", "--amend", "-m", "amended commit message")
	if _, c := runAdvGit(t, workAmend, httpEnv, "push", "origin", "HEAD:refs/heads/feat-app"); c == 0 {
		t.Fatal("expected amended commit push to fail approval check")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjCount, baseMainSHA)

	// B3: Ref name change (feat-other instead of feat-app).
	if _, c := runAdvGit(t, workOrig, httpEnv, "push", "origin", "HEAD:refs/heads/feat-other"); c == 0 {
		t.Fatal("expected different ref push to fail approval check")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjCount, baseMainSHA)

	// B4: Wrong principal (Bob pushing Alice's exact commit to feat-app).
	if _, c := runAdvGit(t, workOrig, httpEnv, "push", s.gitHTTPURL("acme/service", s.bobJWT), "HEAD:refs/heads/feat-app"); c == 0 {
		t.Fatal("expected wrong principal push to fail approval check")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseObjCount, baseMainSHA)

	// B5: Wrong destination (acme/service-other).
	otherBaseCnt := s.upstream.bareObjectCount(t, "acme/service-other")
	if _, c := runAdvGit(t, workOrig, httpEnv, "push", s.gitHTTPURL("acme/service-other", s.aliceJWT), "HEAD:refs/heads/feat-app"); c == 0 {
		t.Fatal("expected wrong destination push to fail approval check")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service-other", otherBaseCnt, "")

	// Verify approval release is still unconsumed after all 5 mismatch attempts.
	relBefore, err := s.store.GetPushApprovalReleaseByID(ctx, relUUID)
	if err != nil || relBefore.ConsumedAt != nil {
		t.Fatalf("expected approval release to remain unconsumed, got %+v err=%v", relBefore, err)
	}

	// Subcase C: Exact re-push succeeds ONCE and replay after deletion is rejected.
	s.upstream.resetCounters()
	outOK, codeOK := runAdvGit(t, workOrig, httpEnv, "push", "origin", "HEAD:refs/heads/feat-app")
	if codeOK != 0 || !strings.Contains(outOK, "ALLOW") {
		t.Fatalf("expected exact approved re-push to succeed, code=%d out:\n%s", codeOK, outOK)
	}
	sessWin := s.latestPushSession(t, &s.repo.ID)
	if sessWin.Status != domain.PushSessionStatusCompleted || sessWin.ApprovalReleaseID == nil || *sessWin.ApprovalReleaseID != relUUID {
		t.Fatalf("expected COMPLETED with ApprovalReleaseID=%s, got %+v", relUUID, sessWin)
	}
	relAfter, err := s.store.GetPushApprovalReleaseByID(ctx, relUUID)
	if err != nil || relAfter.ConsumedAt == nil {
		t.Fatalf("expected consumed_at set, got %+v err=%v", relAfter, err)
	}
	audWin, _ := s.store.ListAuditEvents(ctx, persistence.ListAuditEventsParams{ResourceID: &sessWin.ID, Limit: 20})
	sawConsumed := false
	for _, ev := range audWin {
		if ev.EventType == "push.approval_consumed" {
			sawConsumed = true
		}
	}
	if !sawConsumed {
		t.Fatalf("expected push.approval_consumed audit event, got %+v", audWin)
	}

	// Delete branch & replay exact same ZeroOID->NewOID push -> rejected with 0 upstream bytes.
	if outDel, cDel := runAdvGit(t, workOrig, httpEnv, "push", "origin", ":refs/heads/feat-app"); cDel != 0 {
		t.Fatalf("branch delete failed: %s", outDel)
	}
	s.upstream.resetCounters()
	if _, cRep := runAdvGit(t, workOrig, httpEnv, "push", "origin", "HEAD:refs/heads/feat-app"); cRep == 0 {
		t.Fatal("expected single-use replay after consumption to be rejected")
	}
	if calls := s.upstream.receiveCallsFor("acme/service"); len(calls) != 0 {
		t.Fatalf("expected 0 upstream receive-pack calls on replay, got %d", len(calls))
	}

	// Subcase D: Concurrent -race replay (4 goroutines pushing exact approved commit simultaneously -> 1 winner).
	workRace := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "gate08 race push", map[string]string{
		"billing_race.go": confidentialHeaderlessSampleGo,
	})
	if _, c := runAdvGit(t, workRace, httpEnv, "push", "origin", "HEAD:refs/heads/feat-race"); c == 0 {
		t.Fatal("expected initial feat-race push to require approval")
	}
	sessRaceInit := s.latestPushSession(t, &s.repo.ID)
	rCode, rRaw := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessRaceInit.ID.String()+"/approvals", s.bobJWT, "g8-race-app", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessRaceInit.PushManifestDigest,
		"ttl_seconds":          600,
	})
	if rCode != http.StatusCreated {
		t.Fatalf("expected 201 race approval, got %d: %s", rCode, string(rRaw))
	}
	var raceRel struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rRaw, &raceRel)

	s.upstream.resetCounters()
	const racers = 4
	results := make([]int, racers)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-gate
			_, code := runAdvGit(t, workRace, httpEnv, "push", "origin", "HEAD:refs/heads/feat-race")
			results[idx] = code
		}(i)
	}
	close(gate)
	wg.Wait()

	wins := 0
	for _, c := range results {
		if c == 0 {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly 1 concurrent approval replay winner, got %d (codes=%v)", wins, results)
	}
	if calls := s.upstream.receiveCallsFor("acme/service"); len(calls) != 1 {
		t.Fatalf("expected exactly 1 upstream receive-pack call across concurrent race, got %d", len(calls))
	}
	relRaceRow, err := s.store.GetPushApprovalReleaseByID(ctx, uuid.MustParse(raceRel.ID))
	if err != nil || relRaceRow.ConsumedByPushSessionID == nil {
		t.Fatalf("expected single winner ConsumedByPushSessionID, got %+v err=%v", relRaceRow, err)
	}
	s.assertZeroSecretsInLogs(t)
}

// Gate 9: Fail-closed outages (ENFORCE_BLOCK) vs PASSIVE_AUDIT (OBSERVED_WOULD_BLOCK/FAILED without blocking pushes).
func TestADV_PG_Gate09_FailClosedOutagesVsPassiveAudit(t *testing.T) {
	s := newPGAdvStack(t, func(o *pgAdvOptions) {
		o.scannerTimeout = 1 * time.Second
		o.modelGatewayTimeout = 1 * time.Second
	})
	ctx := context.Background()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	setMode := func(mode, delivery, cls string) {
		if _, err := s.pg.Pool().Exec(ctx, `UPDATE repositories SET egress_mode = $1, passive_audit_delivery = $2, classification = $3 WHERE id = $4`, mode, delivery, cls, s.repo.ID); err != nil {
			t.Fatalf("update repo mode: %v", err)
		}
	}

	// 1. Scanner crash & timeout: ENFORCE_BLOCK -> QUARANTINED (0 bytes); PASSIVE_AUDIT -> forwards (OBSERVED_WOULD_BLOCK).
	for _, scMode := range []string{"crash", "timeout"} {
		setMode("ENFORCE_BLOCK", "ASYNC", "INTERNAL")
		s.scanners.setSemgrepMode(scMode)
		baseCnt := s.upstream.bareObjectCount(t, "acme/service")
		s.upstream.resetCounters()
		work := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "scanner "+scMode, map[string]string{
			"sc_" + scMode + ".txt": "clean\n",
		})
		if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/g9-sc-enf-"+scMode); c == 0 || !strings.Contains(out, "QUARANTINE") {
			t.Fatalf("expected QUARANTINE on scanner %s in ENFORCE_BLOCK, code=%d out:\n%s", scMode, c, out)
		}
		assertZeroUpstreamReceivePack(t, s, "acme/service", baseCnt, "")
		sessEnf := s.latestPushSession(t, &s.repo.ID)
		if sessEnf.Status != domain.PushSessionStatusQuarantined {
			t.Fatalf("expected QUARANTINED on scanner %s, got %+v", scMode, sessEnf)
		}

		setMode("PASSIVE_AUDIT", "INLINE_WARN", "INTERNAL")
		s.upstream.resetCounters()
		outPA, cPA := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/g9-sc-pa-"+scMode)
		if cPA != 0 || !strings.Contains(outPA, "PASSIVE_AUDIT WARNING") {
			t.Fatalf("expected PASSIVE_AUDIT INLINE_WARN forward on scanner %s, code=%d out:\n%s", scMode, cPA, outPA)
		}
		sessPA := s.latestPushSession(t, &s.repo.ID)
		if sessPA.Status != domain.PushSessionStatusObservedWouldBlock || sessPA.Enforced || !sessPA.UpstreamForwarded {
			t.Fatalf("expected OBSERVED_WOULD_BLOCK on scanner %s in PASSIVE_AUDIT, got %+v", scMode, sessPA)
		}
		s.scanners.setSemgrepMode("clean")
	}

	// 2. Stage B 503 & timeout on RESTRICTED repo: ENFORCE_BLOCK -> QUARANTINED; PASSIVE_AUDIT -> OBSERVED_WOULD_BLOCK.
	for _, sbCase := range []string{"503", "timeout"} {
		if sbCase == "503" {
			s.stageBGW.setHandler(func(req decisions.GatewayRequest) (int, []byte) {
				return http.StatusServiceUnavailable, []byte(`{"error":"503"}`)
			})
		} else {
			s.stageBGW.setHandler(func(req decisions.GatewayRequest) (int, []byte) {
				time.Sleep(2 * time.Second)
				return http.StatusOK, mustAdvStageBResponse("IP_PROVENANCE", "CLEAR", "LOW", nil)
			})
		}
		setMode("ENFORCE_BLOCK", "ASYNC", "RESTRICTED")
		baseCnt := s.upstream.bareObjectCount(t, "acme/service")
		s.upstream.resetCounters()
		workSB := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "stageb "+sbCase, map[string]string{
			"sb_" + sbCase + ".txt": "clean\n",
		})
		if _, c := runAdvGit(t, workSB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-sb-enf-"+sbCase); c == 0 {
			t.Fatalf("expected QUARANTINE on Stage B %s in ENFORCE_BLOCK", sbCase)
		}
		assertZeroUpstreamReceivePack(t, s, "acme/service", baseCnt, "")
		sessSB := s.latestPushSession(t, &s.repo.ID)
		if sessSB.Status != domain.PushSessionStatusQuarantined {
			t.Fatalf("expected QUARANTINED on Stage B %s, got %+v", sbCase, sessSB)
		}

		setMode("PASSIVE_AUDIT", "INLINE_WARN", "RESTRICTED")
		s.upstream.resetCounters()
		outPA, cPA := runAdvGit(t, workSB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-sb-pa-"+sbCase)
		if cPA != 0 || !strings.Contains(outPA, "PASSIVE_AUDIT WARNING") {
			t.Fatalf("expected PASSIVE_AUDIT forward on Stage B %s, code=%d out:\n%s", sbCase, cPA, outPA)
		}
		sessPA := s.latestPushSession(t, &s.repo.ID)
		if sessPA.Status != domain.PushSessionStatusObservedWouldBlock || sessPA.Enforced || !sessPA.UpstreamForwarded {
			t.Fatalf("expected OBSERVED_WOULD_BLOCK on Stage B %s, got %+v", sbCase, sessPA)
		}
	}
	s.stageBGW.setHandler(nil)

	// 3. DB stage persistence failure (model_assessments trigger) + full DB unavailability (closed pool).
	if _, err := s.pg.Pool().Exec(ctx, `
		CREATE OR REPLACE FUNCTION adv_fail_ma_insert() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'simulated model_assessments db failure';
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER trg_adv_fail_ma BEFORE INSERT ON model_assessments
		FOR EACH ROW EXECUTE FUNCTION adv_fail_ma_insert();
	`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	setMode("ENFORCE_BLOCK", "ASYNC", "INTERNAL")
	baseCntDB := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	workDB := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "db stage fail", map[string]string{
		"db_stage.txt": "clean\n",
	})
	if out, c := runAdvGit(t, workDB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-db-enf"); c == 0 || !strings.Contains(out, "QUARANTINE") {
		t.Fatalf("expected QUARANTINE on DB stage persistence failure, code=%d out:\n%s", c, out)
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseCntDB, "")

	setMode("PASSIVE_AUDIT", "INLINE_WARN", "INTERNAL")
	s.upstream.resetCounters()
	if outPA, cPA := runAdvGit(t, workDB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-db-pa"); cPA != 0 || !strings.Contains(outPA, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT forward on DB stage failure, code=%d out:\n%s", cPA, outPA)
	}
	sessDBPA := s.latestPushSession(t, &s.repo.ID)
	if sessDBPA.Status != domain.PushSessionStatusObservedWouldBlock || sessDBPA.Enforced || !sessDBPA.UpstreamForwarded {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK on DB stage failure, got %+v", sessDBPA)
	}
	_, _ = s.pg.Pool().Exec(ctx, `DROP TRIGGER IF EXISTS trg_adv_fail_ma ON model_assessments; DROP FUNCTION IF EXISTS adv_fail_ma_insert();`)

	// Full DB outage via isolated stack with closed PG pool -> 503 fail closed, 0 upstream bytes.
	sClosed := newPGAdvStack(t)
	closedWork := sClosed.cloneAndCommitHTTP(t, "acme/service", sClosed.aliceJWT, "Alice", "alice@example.com", "db down", map[string]string{"x.txt": "x\n"})
	closedBaseCnt := sClosed.upstream.bareObjectCount(t, "acme/service")
	sClosed.upstream.resetCounters()
	sClosed.pg.Pool().Close()
	if _, c := runAdvGit(t, closedWork, []string{"GIT_SSL_CAINFO=" + sClosed.caFile}, "push", "origin", "HEAD:refs/heads/g9-closed"); c == 0 {
		t.Fatal("expected push against closed DB pool to fail closed")
	}
	assertZeroUpstreamReceivePack(t, sClosed, "acme/service", closedBaseCnt, "")

	// 4. Policy bundle load error (INVALID_POLICY_BUNDLE) & runtime CEL error (10 / findings.critical_secrets > 1).
	celErrYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: runtime-cel-divzero
  version: "1.0.0"
  scope: REPO
defaults:
  effect: ALLOW
  onError: DENY
rules:
  - id: push.runtime.divzero
    stages: [PUSH_EGRESS]
    when: "(10 / findings.critical_secrets) > 1"
    effect: ALLOW
`
	compiledCEL, errs := s.policyEngine.Compile([]byte(celErrYAML))
	if len(errs) > 0 {
		t.Fatalf("compile celErrYAML: %+v", errs)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	celBundleRow, err := s.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: compiledCEL.Bundle.Metadata.Name, Version: compiledCEL.Bundle.Metadata.Version,
		Scope: domain.PolicyScopeRepo, RepositoryID: &s.repo.ID, Digest: compiledCEL.Digest,
		Definition: compiledCEL.Definition, ActivatedAt: &now, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest(celErr): %v", err)
	}
	setMode("ENFORCE_BLOCK", "ASYNC", "INTERNAL")
	baseCntCEL := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, workDB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-cel-enf"); c == 0 {
		t.Fatal("expected runtime CEL error in ENFORCE_BLOCK to fail closed")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseCntCEL, "")
	sessCELEnf := s.latestPushSession(t, &s.repo.ID)
	if sessCELEnf.Status != domain.PushSessionStatusBlocked || sessCELEnf.Verdict == nil || *sessCELEnf.Verdict != domain.PolicyEffectDeny {
		t.Fatalf("expected BLOCKED/DENY on runtime CEL error, got %+v", sessCELEnf)
	}

	setMode("PASSIVE_AUDIT", "INLINE_WARN", "INTERNAL")
	s.upstream.resetCounters()
	if outPA, cPA := runAdvGit(t, workDB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-cel-pa"); cPA != 0 || !strings.Contains(outPA, "PASSIVE_AUDIT WARNING") {
		t.Fatalf("expected PASSIVE_AUDIT forward on runtime CEL error, code=%d out:\n%s", cPA, outPA)
	}
	sessCELPA := s.latestPushSession(t, &s.repo.ID)
	if sessCELPA.Status != domain.PushSessionStatusObservedWouldBlock || sessCELPA.Enforced || !sessCELPA.UpstreamForwarded {
		t.Fatalf("expected OBSERVED_WOULD_BLOCK on runtime CEL error in PASSIVE_AUDIT, got %+v", sessCELPA)
	}

	// Corrupt bundle at load time -> FAILED (INVALID_POLICY_BUNDLE), 0 upstream bytes.
	setMode("ENFORCE_BLOCK", "ASYNC", "INTERNAL")
	if _, err := s.pg.Pool().Exec(ctx, `UPDATE policy_bundles SET definition = '{"rules":[{"id":"bad","stages":["PUSH_EGRESS"],"when":"((("}]}'::jsonb WHERE id = $1`, celBundleRow.ID); err != nil {
		t.Fatalf("corrupt bundle: %v", err)
	}
	s.upstream.resetCounters()
	if _, c := runAdvGit(t, workDB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-corrupt-bundle"); c == 0 {
		t.Fatal("expected corrupt active bundle to fail closed")
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseCntCEL, "")
	sessBadBundle := s.latestPushSession(t, &s.repo.ID)
	if sessBadBundle.Status != domain.PushSessionStatusFailed || sessBadBundle.ErrorCode == nil || *sessBadBundle.ErrorCode != "INVALID_POLICY_BUNDLE" {
		t.Fatalf("expected FAILED/INVALID_POLICY_BUNDLE, got %+v", sessBadBundle)
	}
	_, _ = s.pg.Pool().Exec(ctx, `UPDATE policy_bundles SET activated_at = NULL WHERE id = $1`, celBundleRow.ID)

	// 5. Upstream push error (HTTP 500) -> FAILED (UPSTREAM_RECEIVE_PACK_FAILED) in BOTH ENFORCE_BLOCK and PASSIVE_AUDIT.
	s.upstream.setReceivePackOverride(func(ownerRepo string, body []byte) (int, []byte, bool) {
		return http.StatusInternalServerError, []byte("upstream 500 boom"), true
	})
	defer s.upstream.setReceivePackOverride(nil)
	for _, m := range []string{"ENFORCE_BLOCK", "PASSIVE_AUDIT"} {
		setMode(m, "ASYNC", "INTERNAL")
		if _, c := runAdvGit(t, workDB, httpEnv, "push", "origin", "HEAD:refs/heads/g9-up500-"+m); c == 0 {
			t.Fatalf("expected upstream HTTP 500 to fail push in mode %s", m)
		}
		sessUp := s.latestPushSession(t, &s.repo.ID)
		if sessUp.Status != domain.PushSessionStatusFailed || sessUp.ErrorCode == nil || *sessUp.ErrorCode != "UPSTREAM_RECEIVE_PACK_FAILED" {
			t.Fatalf("expected FAILED/UPSTREAM_RECEIVE_PACK_FAILED in %s, got %+v", m, sessUp)
		}
	}
	s.assertZeroSecretsInLogs(t)
}

// Gate 10: SSH user-certificate authentication & principal attribution (negative certs + positive real ssh/ssh-keygen + forged author).
func TestADV_PG_Gate10_SSHCertAuthAndAttribution(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh binary not found")
	}
	s := newPGAdvStack(t)
	ctx := context.Background()

	work := s.initLocalAndCommit(t, "Mallory Spoof", "mallory@evil.test", "ssh auth test", map[string]string{
		"ssh_file.txt": "ssh content\n",
	})

	// 1. Negative auth cases (0 upstream bytes, 0 new push_sessions).
	baseSessions := s.pushSessionCount(t)
	baseCnt := s.upstream.bareObjectCount(t, "acme/service")
	s.upstream.resetCounters()

	// Raw key (no cert).
	rawCred := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "raw", 9001, "-1m:+1h", nil)
	if _, c := runAdvGit(t, work, rawCred.gitEnv(false), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-raw"); c == 0 {
		t.Fatal("expected raw SSH key without cert to fail")
	}

	// Rogue CA cert.
	rogueCred := s.mintSSHCertWithKeygen(t, s.rogueCAPath, []string{"alice-human-001"}, "rogue", 9002, "-1m:+1h", nil)
	if _, c := runAdvGit(t, work, rogueCred.gitEnv(true), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-rogue"); c == 0 {
		t.Fatal("expected rogue CA cert to fail")
	}

	// Expired cert.
	expCred := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "exp", 9003, "-2h:-1h", nil)
	if _, c := runAdvGit(t, work, expCred.gitEnv(true), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-exp"); c == 0 {
		t.Fatal("expected expired cert to fail")
	}

	// Not-yet-valid cert.
	futCred := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "fut", 9004, "+1h:+2h", nil)
	if _, c := runAdvGit(t, work, futCred.gitEnv(true), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-fut"); c == 0 {
		t.Fatal("expected future cert to fail")
	}

	// Wrong principal + ssh user mismatch.
	wrongCred := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"mallory"}, "wrong", 9005, "-1m:+1h", nil)
	if _, c := runAdvGit(t, work, wrongCred.gitEnv(true), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-wrong"); c == 0 {
		t.Fatal("expected wrong principal cert to fail")
	}
	aliceValid := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "adv-alice-key", 9001, "-1m:+1h", nil)
	if _, c := runAdvGit(t, work, aliceValid.gitEnv(true), "push", s.gitSSHURL("bob-human-002", "acme/service"), "HEAD:refs/heads/g10-mismatch"); c == 0 {
		t.Fatal("expected ssh username != cert ValidPrincipals to fail")
	}

	// Unrecognized critical option.
	critCred := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "crit", 9006, "-1m:+1h", []string{"force-command=/bin/sh"})
	if _, c := runAdvGit(t, work, critCred.gitEnv(true), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-crit"); c == 0 {
		t.Fatal("expected unrecognized critical option cert to fail")
	}

	// Unseeded principal -> strict no-auto-provisioning.
	var prinBefore int
	_ = s.pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM principals`).Scan(&prinBefore)
	unseededCred := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"unseeded-cert-user@example.com"}, "unseeded", 9007, "-1m:+1h", nil)
	if _, c := runAdvGit(t, work, unseededCred.gitEnv(true), "push", s.gitSSHURL("git", "acme/service"), "HEAD:refs/heads/g10-unseeded"); c == 0 {
		t.Fatal("expected unseeded SSH principal to fail")
	}
	var prinAfter int
	_ = s.pg.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM principals`).Scan(&prinAfter)
	if prinAfter != prinBefore {
		t.Fatalf("unseeded SSH principal was auto-provisioned! before=%d after=%d", prinBefore, prinAfter)
	}
	assertZeroUpstreamReceivePack(t, s, "acme/service", baseCnt, "")
	if gotSess := s.pushSessionCount(t); gotSess != baseSessions {
		t.Fatalf("expected 0 new push_sessions on failed SSH auth, before=%d after=%d", baseSessions, gotSess)
	}

	// 2. Positive SSH cert clone & push with forged Git Author -> attributed strictly to Alice.
	cloneSSH := filepath.Join(t.TempDir(), "ssh-clone")
	if out, c := runAdvGit(t, "", aliceValid.gitEnv(true), "clone", s.gitSSHURL("git", "acme/service"), cloneSSH); c != 0 {
		t.Fatalf("SSH clone failed: %s", out)
	}
	mustAdvGit(t, cloneSSH, nil, "config", "user.name", "Mallory Spoof")
	mustAdvGit(t, cloneSSH, nil, "config", "user.email", "mallory@evil.test")
	_ = os.WriteFile(filepath.Join(cloneSSH, "ssh_ok.txt"), []byte("valid ssh cert\n"), 0o600)
	mustAdvGit(t, cloneSSH, nil, "add", "ssh_ok.txt")
	mustAdvGit(t, cloneSSH, nil, "commit", "-m", "ssh cert commit")
	if out, c := runAdvGit(t, cloneSSH, aliceValid.gitEnv(true), "push", "origin", "HEAD:refs/heads/ssh-auth"); c != 0 {
		t.Fatalf("SSH push failed: %s", out)
	}
	sessSSH := s.latestPushSession(t, &s.repo.ID)
	if sessSSH.PrincipalID != s.alice.ID || sessSSH.Transport != domain.PushTransportSSH || !sessSSH.UpstreamForwarded {
		t.Fatalf("unexpected SSH push_session: %+v", sessSSH)
	}
	events, _ := s.store.ListAuditEvents(ctx, persistence.ListAuditEventsParams{ResourceID: &sessSSH.ID, Limit: 10})
	var payloadMap map[string]any
	if len(events) == 0 || events[0].ActorID == nil || *events[0].ActorID != s.alice.ID || json.Unmarshal(events[0].Payload, &payloadMap) != nil {
		t.Fatalf("expected audit actor_id=%s and valid JSON payload, got %+v", s.alice.ID, events)
	}
	payloadStr := string(events[0].Payload)
	if strings.Contains(payloadStr, "mallory@evil.test") ||
		payloadMap["auth_method"] != "ssh_cert" ||
		payloadMap["ssh_key_id"] != "adv-alice-key" ||
		payloadMap["ssh_cert_serial"] != float64(9001) ||
		payloadMap["principal_subject"] != "alice-human-001" {
		t.Fatalf("unexpected SSH audit payload: %s", payloadStr)
	}
	s.assertZeroSecretsInLogs(t)
}

// Gate 11: Transparent git clone / git push read-write compatibility across HTTPS & SSH.
func TestADV_PG_Gate11_TransparentReadWriteCompatibility(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh binary not found")
	}
	s := newPGAdvStack(t)
	ctx := context.Background()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}
	aliceSSH := s.mintSSHCertWithKeygen(t, s.caPrivPath, []string{"alice-human-001"}, "g11-key", 1101, "-1m:+1h", nil)

	// Enable PASSIVE_AUDIT for transparent read/write compatibility checks.
	if _, err := s.pg.Pool().Exec(ctx, `UPDATE repositories SET egress_mode = 'PASSIVE_AUDIT' WHERE id = $1`, s.repo.ID); err != nil {
		t.Fatalf("update PASSIVE_AUDIT: %v", err)
	}

	// 1. Full & shallow (--depth=1) clones over HTTPS and SSH.
	s.upstream.addCommitToRepo(t, "acme/service", "history2.txt", "second\n")
	for _, tc := range []struct {
		name string
		env  []string
		url  string
		args []string
	}{
		{"https_full", httpEnv, s.gitHTTPURL("acme/service", s.aliceJWT), []string{"clone"}},
		{"https_shallow", httpEnv, s.gitHTTPURL("acme/service", s.aliceJWT), []string{"clone", "--depth=1"}},
		{"ssh_full", aliceSSH.gitEnv(true), s.gitSSHURL("git", "acme/service"), []string{"clone"}},
		{"ssh_shallow", aliceSSH.gitEnv(true), s.gitSSHURL("git", "acme/service"), []string{"clone", "--depth=1"}},
	} {
		dst := filepath.Join(t.TempDir(), tc.name)
		args := append(append([]string(nil), tc.args...), tc.url, dst)
		if out, c := runAdvGit(t, "", tc.env, args...); c != 0 {
			t.Fatalf("%s failed: %s", tc.name, out)
		}
		if _, err := os.Stat(filepath.Join(dst, "history2.txt")); err != nil {
			t.Fatalf("%s missing seeded file: %v", tc.name, err)
		}
	}

	// 2. Clean push to main, new branch, lightweight & annotated tags, multi-ref, and deletions over HTTPS & SSH.
	work := filepath.Join(t.TempDir(), "rw-https")
	mustAdvGit(t, "", httpEnv, "clone", s.gitHTTPURL("acme/service", s.aliceJWT), work)
	mustAdvGit(t, work, nil, "config", "user.name", "Alice")
	mustAdvGit(t, work, nil, "config", "user.email", "alice@example.com")
	_ = os.WriteFile(filepath.Join(work, "feat.go"), []byte("package main\nfunc F() {}\n"), 0o600)
	mustAdvGit(t, work, nil, "add", "feat.go")
	mustAdvGit(t, work, nil, "commit", "-m", "clean main update")
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/main"); c != 0 {
		t.Fatalf("main push failed: %s", out)
	}
	headMain := strings.TrimSpace(mustAdvGit(t, work, nil, "rev-parse", "HEAD"))
	if got := s.upstream.bareRefSHA(t, "acme/service", "refs/heads/main"); got != headMain {
		t.Fatalf("upstream main=%s, want %s", got, headMain)
	}

	// New branch, lightweight tag, annotated tag, multi-ref push.
	mustAdvGit(t, work, nil, "checkout", "-b", "feat/new-branch")
	_ = os.WriteFile(filepath.Join(work, "br.txt"), []byte("branch\n"), 0o600)
	mustAdvGit(t, work, nil, "add", "br.txt")
	mustAdvGit(t, work, nil, "commit", "-m", "new branch")
	mustAdvGit(t, work, nil, "tag", "v1.0.0-light")
	mustAdvGit(t, work, nil, "tag", "-a", "v1.0.0", "-m", "release 1.0.0")
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", "refs/heads/feat/new-branch", "refs/tags/v1.0.0-light", "refs/tags/v1.0.0"); c != 0 {
		t.Fatalf("multi-ref push failed: %s", out)
	}
	if s.upstream.bareRefSHA(t, "acme/service", "refs/heads/feat/new-branch") == "" ||
		s.upstream.bareRefSHA(t, "acme/service", "refs/tags/v1.0.0-light") == "" ||
		s.upstream.bareRefSHA(t, "acme/service", "refs/tags/v1.0.0") == "" {
		t.Fatal("expected branch and tags created upstream")
	}

	// Branch & tag deletion over HTTPS and SSH.
	if out, c := runAdvGit(t, work, httpEnv, "push", "origin", ":refs/heads/feat/new-branch", ":refs/tags/v1.0.0-light"); c != 0 {
		t.Fatalf("HTTPS deletion failed: %s", out)
	}
	if s.upstream.bareRefSHA(t, "acme/service", "refs/heads/feat/new-branch") != "" ||
		s.upstream.bareRefSHA(t, "acme/service", "refs/tags/v1.0.0-light") != "" {
		t.Fatal("expected deleted refs absent upstream after HTTPS delete")
	}

	// SSH branch push & pure deletion.
	workSSH := filepath.Join(t.TempDir(), "rw-ssh")
	mustAdvGit(t, "", aliceSSH.gitEnv(true), "clone", s.gitSSHURL("git", "acme/service"), workSSH)
	mustAdvGit(t, workSSH, nil, "config", "user.name", "Alice")
	mustAdvGit(t, workSSH, nil, "config", "user.email", "alice@example.com")
	_ = os.WriteFile(filepath.Join(workSSH, "ssh_del.txt"), []byte("del\n"), 0o600)
	mustAdvGit(t, workSSH, nil, "add", "ssh_del.txt")
	mustAdvGit(t, workSSH, nil, "commit", "-m", "ssh branch")
	mustAdvGit(t, workSSH, aliceSSH.gitEnv(true), "push", "origin", "HEAD:refs/heads/feat/ssh-del")
	if out, c := runAdvGit(t, workSSH, aliceSSH.gitEnv(true), "push", "origin", ":refs/heads/feat/ssh-del"); c != 0 {
		t.Fatalf("SSH pure deletion failed: %s", out)
	}
	if s.upstream.bareRefSHA(t, "acme/service", "refs/heads/feat/ssh-del") != "" {
		t.Fatal("expected SSH deleted branch absent upstream")
	}

	// 3. Non-fast-forward: without --force aborts, with --force succeeds, and denyNonFastForwards=true -> FAILED.
	mustAdvGit(t, work, nil, "checkout", "main")
	advUpstreamSHA := s.upstream.addCommitToRepo(t, "acme/service", "upstream_diverge.txt", "upstream\n")
	_ = os.WriteFile(filepath.Join(work, "local_diverge.txt"), []byte("local\n"), 0o600)
	mustAdvGit(t, work, nil, "add", "local_diverge.txt")
	mustAdvGit(t, work, nil, "commit", "-m", "diverged local commit")
	if _, c := runAdvGit(t, work, httpEnv, "push", "origin", "HEAD:refs/heads/main"); c == 0 {
		t.Fatal("expected non-fast-forward without --force to fail")
	}
	if got := s.upstream.bareRefSHA(t, "acme/service", "refs/heads/main"); got != advUpstreamSHA {
		t.Fatalf("expected upstream main unchanged (%s), got %s", advUpstreamSHA, got)
	}
	if out, c := runAdvGit(t, work, httpEnv, "push", "--force", "origin", "HEAD:refs/heads/main"); c != 0 {
		t.Fatalf("expected --force push to succeed when bare repo permits: %s", out)
	}

	// Enable receive.denyNonFastForwards=true on bare repo and diverge again.
	bareDir := s.upstream.barePath("acme/service")
	mustAdvGit(t, bareDir, nil, "config", "receive.denyNonFastForwards", "true")
	lockedSHA := s.upstream.addCommitToRepo(t, "acme/service", "locked.txt", "locked\n")
	_ = os.WriteFile(filepath.Join(work, "force_blocked.txt"), []byte("blocked\n"), 0o600)
	mustAdvGit(t, work, nil, "add", "force_blocked.txt")
	mustAdvGit(t, work, nil, "commit", "-m", "force push denied by upstream")
	if _, c := runAdvGit(t, work, httpEnv, "push", "--force", "origin", "HEAD:refs/heads/main"); c == 0 {
		t.Fatal("expected --force push to fail when receive.denyNonFastForwards=true")
	}
	if got := s.upstream.bareRefSHA(t, "acme/service", "refs/heads/main"); got != lockedSHA {
		t.Fatalf("expected upstream main unchanged (%s), got %s", lockedSHA, got)
	}
	sessNFF := s.latestPushSession(t, &s.repo.ID)
	if sessNFF.Status != domain.PushSessionStatusFailed {
		t.Fatalf("expected FAILED push_session on upstream non-fast-forward rejection, got %+v", sessNFF)
	}
	s.assertZeroSecretsInLogs(t)
}

// Gate 12: Git LFS batch gating, clfs1 capability tokens, real git-lfs + push.has_lfs CEL gating, and missing LFS 404 blocking.
func TestADV_PG_Gate12_GitLFSBatchGatingAndCEL(t *testing.T) {
	s := newPGAdvStack(t)
	ctx := context.Background()
	gwClient := s.gwHTTP.Client()
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	// Seed ENFORCE_PR repo and unregistered repo.
	s.registerRepo(t, 1004, "acme/pr-only", domain.ClassificationInternal, domain.EgressModeEnforcePR, true, false)
	s.upstream.seedBareRepo(t, "acme/pr-only", map[string]string{"README.md": "pr\n"})
	s.upstream.seedBareRepo(t, "external/unreg-lfs", map[string]string{"README.md": "unreg\n"})

	sampleBytes := bytes.Repeat([]byte("L"), 512)
	sum := sha256.Sum256(sampleBytes)
	sampleOID := hex.EncodeToString(sum[:])

	callBatch := func(ownerRepo, op, oid string, size int64) (int, gitgateway.LFSBatchResponse) {
		body, _ := json.Marshal(gitgateway.LFSBatchRequest{
			Operation: op,
			Transfers: []string{"basic"},
			Objects:   []gitgateway.LFSBatchObjectInput{{OID: oid, Size: size}},
		})
		req, _ := http.NewRequest(http.MethodPost, s.gwHTTP.URL+"/"+ownerRepo+".git/info/lfs/objects/batch", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+s.aliceJWT)
		resp, err := gwClient.Do(req)
		if err != nil {
			t.Fatalf("LFS batch %s %s: %v", ownerRepo, op, err)
		}
		defer resp.Body.Close()
		var parsed gitgateway.LFSBatchResponse
		_ = json.NewDecoder(resp.Body).Decode(&parsed)
		return resp.StatusCode, parsed
	}

	// 1. LFS batch gating before upstream: ENFORCE_PR upload -> 403 (0 upstream calls); download -> 200; unregistered upload -> 403.
	s.upstream.resetCounters()
	stPRUp, _ := callBatch("acme/pr-only", "upload", sampleOID, int64(len(sampleBytes)))
	if stPRUp != http.StatusForbidden {
		t.Fatalf("expected 403 on ENFORCE_PR LFS upload batch, got %d", stPRUp)
	}
	s.upstream.putLFSObject("acme/pr-only", sampleOID, sampleBytes)
	stPRDown, _ := callBatch("acme/pr-only", "download", sampleOID, int64(len(sampleBytes)))
	if stPRDown != http.StatusOK {
		t.Fatalf("expected 200 on ENFORCE_PR LFS download batch, got %d", stPRDown)
	}
	stUnregUp, _ := callBatch("external/unreg-lfs", "upload", sampleOID, int64(len(sampleBytes)))
	if stUnregUp != http.StatusForbidden {
		t.Fatalf("expected 403 on unregistered ENFORCE_BLOCK LFS upload batch, got %d", stUnregUp)
	}
	if _, _, _, _, lfsBatch, _ := s.upstream.stats(); lfsBatch != 1 {
		t.Fatalf("expected only 1 upstream LFS batch call (the ENFORCE_PR download), got %d", lfsBatch)
	}

	// 2. clfs1. capability token verification: signature tamper (401), scope mismatch (403), size mismatch (422), OID mismatch (422).
	stOK, batchOK := callBatch("acme/service", "upload", sampleOID, int64(len(sampleBytes)))
	if stOK != http.StatusOK || len(batchOK.Objects) != 1 {
		t.Fatalf("expected 200 LFS batch on registered repo, got %d: %+v", stOK, batchOK)
	}
	upAct := batchOK.Objects[0].Actions["upload"]
	authHdr := upAct.Header["Authorization"]
	if !strings.HasPrefix(upAct.Href, s.gwHTTP.URL) || !strings.HasPrefix(authHdr, "Bearer clfs1.") || strings.Contains(authHdr, s.writeTok) || strings.Contains(authHdr, s.aliceJWT) {
		t.Fatalf("unexpected LFS upload action href=%q header=%v", upAct.Href, upAct.Header)
	}

	doPutLFS := func(href, bearer string, payload []byte) int {
		req, _ := http.NewRequest(http.MethodPut, href, bytes.NewReader(payload))
		req.Header.Set("Authorization", bearer)
		resp, err := gwClient.Do(req)
		if err != nil {
			t.Fatalf("LFS PUT %s: %v", href, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// Tampered signature -> 401.
	tampered := authHdr[:len(authHdr)-2] + "XX"
	if tampered == authHdr {
		tampered = authHdr[:len(authHdr)-2] + "YY"
	}
	if c := doPutLFS(upAct.Href, tampered, sampleBytes); c != http.StatusUnauthorized {
		t.Fatalf("expected 401 on tampered clfs1 signature, got %d", c)
	}
	// Wrong repo scope -> 403.
	if c := doPutLFS(strings.Replace(upAct.Href, "acme/service", "acme/pr-only", 1), authHdr, sampleBytes); c != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong repo scope, got %d", c)
	}
	// Wrong size -> 422.
	if c := doPutLFS(upAct.Href, authHdr, []byte("short")); c != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on LFS size mismatch, got %d", c)
	}
	// Wrong SHA-256 -> 422.
	wrongSHA := bytes.Repeat([]byte("M"), len(sampleBytes))
	if c := doPutLFS(upAct.Href, authHdr, wrongSHA); c != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on LFS SHA-256 mismatch, got %d", c)
	}

	// 3. push.has_lfs CEL gating (> 4096 -> REQUIRE_APPROVAL, <= 4096 -> ALLOW) + real git-lfs if available.
	lfsCELYAML := `apiVersion: custodian.dev/v1
kind: PolicyBundle
metadata:
  name: adv-lfs-cel-gate
  version: "1.0.0"
  scope: REPO
defaults:
  effect: DENY
  onError: DENY
rules:
  - id: push.lfs.oversize_approval
    stages: [PUSH_EGRESS]
    when: push.has_lfs && push.lfs_total_bytes > 4096
    effect: REQUIRE_APPROVAL
    overridable: true
    obligations:
      - type: HUMAN_REVIEW
        reviewer_group: ip-review
        minimum: 1
  - id: push.lfs.allow_bounded
    stages: [PUSH_EGRESS]
    when: push.has_lfs && push.lfs_total_bytes <= 4096 && destination.registered
    effect: ALLOW
`
	compiledLFS, errs := s.policyEngine.Compile([]byte(lfsCELYAML))
	if len(errs) > 0 {
		t.Fatalf("compile lfsCELYAML: %+v", errs)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := s.store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
		Name: compiledLFS.Bundle.Metadata.Name, Version: compiledLFS.Bundle.Metadata.Version,
		Scope: domain.PolicyScopeRepo, RepositoryID: &s.repo.ID, Digest: compiledLFS.Digest,
		Definition: compiledLFS.Definition, ActivatedAt: &now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPolicyBundleByDigest(lfs): %v", err)
	}

	if lfsBin, err := exec.LookPath("git-lfs"); err == nil && lfsBin != "" {
		// Real git-lfs CLI push (2048B -> ALLOW, 8192B -> REQUIRE_APPROVAL with 0 receive-pack calls).
		workLFS := filepath.Join(t.TempDir(), "real-lfs")
		mustAdvGit(t, "", httpEnv, "clone", s.gitHTTPURL("acme/service", s.aliceJWT), workLFS)
		mustAdvGit(t, workLFS, httpEnv, "config", "user.name", "Alice")
		mustAdvGit(t, workLFS, httpEnv, "config", "user.email", "alice@example.com")
		mustAdvGit(t, workLFS, httpEnv, "lfs", "install", "--local")
		mustAdvGit(t, workLFS, httpEnv, "lfs", "track", "*.bin")
		_ = os.WriteFile(filepath.Join(workLFS, "small.bin"), bytes.Repeat([]byte("S"), 2048), 0o600)
		mustAdvGit(t, workLFS, httpEnv, "add", ".gitattributes", "small.bin")
		mustAdvGit(t, workLFS, httpEnv, "commit", "-m", "small lfs asset 2048B")
		s.upstream.resetCounters()
		if out, c := runAdvGitAllowHooks(t, workLFS, httpEnv, "push", "origin", "HEAD:refs/heads/lfs-small"); c != 0 {
			t.Fatalf("real git-lfs 2048B push failed (%d):\n%s", c, out)
		}
		sessSmall := s.latestPushSession(t, &s.repo.ID)
		if !sessSmall.HasLFS || sessSmall.LFSObjectCount != 1 || sessSmall.LFSTotalBytes != 2048 || sessSmall.Status != domain.PushSessionStatusCompleted {
			t.Fatalf("unexpected small git-lfs push_session: %+v", sessSmall)
		}

		_ = os.WriteFile(filepath.Join(workLFS, "big.bin"), bytes.Repeat([]byte("B"), 8192), 0o600)
		mustAdvGit(t, workLFS, httpEnv, "add", "big.bin")
		mustAdvGit(t, workLFS, httpEnv, "commit", "-m", "big lfs asset 8192B")
		s.upstream.resetCounters()
		if out, c := runAdvGitAllowHooks(t, workLFS, httpEnv, "push", "origin", "HEAD:refs/heads/lfs-big"); c == 0 || !strings.Contains(out, "REQUIRE_APPROVAL") {
			t.Fatalf("expected big git-lfs push to REQUIRE_APPROVAL (code=%d):\n%s", c, out)
		}
		if calls := s.upstream.receiveCallsFor("acme/service"); len(calls) != 0 {
			t.Fatalf("expected 0 receive-pack calls on blocked oversize LFS push, got %d", len(calls))
		}
		sessBig := s.latestPushSession(t, &s.repo.ID)
		if sessBig.Status != domain.PushSessionStatusApprovalRequired || !sessBig.HasLFS || sessBig.LFSTotalBytes != 8192 {
			t.Fatalf("unexpected oversize git-lfs push_session: %+v", sessBig)
		}
	}

	// Missing (404) LFS object pointer on ALLOW path -> blocked (LFS_OBJECT_MISSING, 0 receive-pack calls).
	s.upstream.resetCounters()
	workMiss := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "missing lfs", map[string]string{
		"missing.bin": fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 1024\n", strings.Repeat("e", 64)),
	})
	if _, c := runAdvGit(t, workMiss, httpEnv, "push", "origin", "HEAD:refs/heads/lfs-miss"); c == 0 {
		t.Fatal("expected missing 404 LFS object pointer to be blocked")
	}
	if calls := s.upstream.receiveCallsFor("acme/service"); len(calls) != 0 {
		t.Fatalf("expected 0 receive-pack calls on missing LFS object, got %d", len(calls))
	}
	sessMiss := s.latestPushSession(t, &s.repo.ID)
	if sessMiss.Status != domain.PushSessionStatusBlocked || sessMiss.ErrorCode == nil || *sessMiss.ErrorCode != "LFS_OBJECT_MISSING" {
		t.Fatalf("expected BLOCKED/LFS_OBJECT_MISSING, got %+v", sessMiss)
	}
	s.assertZeroSecretsInLogs(t)
}

// Gate 13: Control-plane API, custodian credential-helper & push status CLI, all 9 Prometheus metrics, and zero-secret logs/audit/findings/sideband.
func TestADV_PG_Gate13_ControlPlaneAPICLIMetricsZeroSecretLogs(t *testing.T) {
	s := newPGAdvStack(t)
	ctx := context.Background()
	cliBin := buildAdvCustodianCLI(t)
	httpEnv := []string{"GIT_SSL_CAINFO=" + s.caFile}

	// 1. custodian credential-helper + real git clone & push (without embedding JWT in URL).
	tokFile := filepath.Join(t.TempDir(), "alice.jwt")
	if err := os.WriteFile(tokFile, []byte(s.aliceJWT+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(tok): %v", err)
	}
	credHelper := fmt.Sprintf("!%s credential-helper --api-url=%s --token-file=%s", cliBin, s.apiServer.URL, tokFile)
	workCLI := filepath.Join(t.TempDir(), "cli-work")
	if out, c := runAdvGit(t, "", httpEnv, "-c", "credential.helper="+credHelper, "clone", s.gitHTTPURL("acme/service", ""), workCLI); c != 0 {
		t.Fatalf("git clone via credential-helper failed (%d):\n%s", c, out)
	}
	mustAdvGit(t, workCLI, nil, "config", "user.name", "Alice")
	mustAdvGit(t, workCLI, nil, "config", "user.email", "alice@example.com")
	_ = os.WriteFile(filepath.Join(workCLI, "cli_clean.go"), []byte("package main\nfunc cliOK() {}\n"), 0o600)
	mustAdvGit(t, workCLI, nil, "add", "cli_clean.go")
	mustAdvGit(t, workCLI, nil, "commit", "-m", "clean push via credential-helper")
	if out, c := runAdvGit(t, workCLI, httpEnv, "-c", "credential.helper="+credHelper, "push", "origin", "HEAD:refs/heads/main"); c != 0 {
		t.Fatalf("git push via credential-helper failed (%d):\n%s", c, out)
	}
	sessClean := s.latestPushSession(t, &s.repo.ID)
	if sessClean.PrincipalID != s.alice.ID || sessClean.Status != domain.PushSessionStatusCompleted {
		t.Fatalf("expected Alice COMPLETED push via credential-helper, got %+v", sessClean)
	}

	// credential-helper negative cases: invalid token -> exit 1 & redacted; non-matching --allowed-hosts -> exit 0 & empty stdout.
	badTok := "eyJhbGciOiJSUzI1NiJ9.badtokenpayload.sig12345"
	cmdBad := exec.Command(cliBin, "credential-helper", "--api-url="+s.apiServer.URL, "--token="+badTok, "get")
	cmdBad.Stdin = strings.NewReader("protocol=https\nhost=127.0.0.1\n\n")
	var badOut, badErr bytes.Buffer
	cmdBad.Stdout = &badOut
	cmdBad.Stderr = &badErr
	if err := cmdBad.Run(); err == nil {
		t.Fatal("expected credential-helper with invalid token to exit non-zero")
	}
	if strings.Contains(badErr.String(), badTok) {
		t.Fatalf("credential-helper leaked bad token in stderr: %s", badErr.String())
	}

	cmdHost := exec.Command(cliBin, "credential-helper", "--api-url="+s.apiServer.URL, "--token="+s.aliceJWT, "--allowed-hosts=git.corp.invalid", "get")
	cmdHost.Stdin = strings.NewReader("protocol=https\nhost=127.0.0.1\n\n")
	outHost, errHost := cmdHost.Output()
	if errHost != nil || len(bytes.TrimSpace(outHost)) != 0 {
		t.Fatalf("expected exit 0 + empty stdout on non-matching allowed-hosts, got out=%q err=%v", string(outHost), errHost)
	}

	// 2. PUT /v1/repositories/{id}/egress-mode (admin 200, non-admin 403).
	nonAdminCode, _ := s.doAPIJSON(t, http.MethodPut, "/v1/repositories/"+s.repo.ID.String()+"/egress-mode", s.aliceJWT, "g13-mode-403", map[string]any{
		"egress_mode":            "PASSIVE_AUDIT",
		"passive_audit_delivery": "INLINE_WARN",
	})
	if nonAdminCode != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin egress-mode change, got %d", nonAdminCode)
	}
	modeCode, _ := s.doAPIJSON(t, http.MethodPut, "/v1/repositories/"+s.repo.ID.String()+"/egress-mode", s.adminJWT, "g13-mode-pa", map[string]any{
		"egress_mode":            "PASSIVE_AUDIT",
		"passive_audit_delivery": "INLINE_WARN",
	})
	if modeCode != http.StatusOK {
		t.Fatalf("expected 200 setting PASSIVE_AUDIT, got %d", modeCode)
	}

	// Trigger PASSIVE_AUDIT would-block push (with secret + IP corpus) for metrics & zero-secret checks.
	corpRawSourceSecret := "SECRET_UNIQUE_SOURCE_MARKER_GATE13_XYZ"
	corpusSource := "// Copyright (c) 2026 Acme Proprietary Systems Inc.\npackage secretcorp\n// " + corpRawSourceSecret + "\n" + restrictedCorpusSampleGo
	corpPath := "internal_secret_dir/core_algo_v13.go"
	cCode, cRaw := s.doAPIJSON(t, http.MethodPost, "/v1/ip-corpora", s.adminJWT, "g13-corp-create", map[string]any{
		"name":           "gate13-corpus",
		"classification": "RESTRICTED",
		"files": []map[string]any{
			{"path": corpPath, "content": corpusSource},
		},
	})
	if cCode != http.StatusCreated {
		t.Fatalf("POST /v1/ip-corpora expected 201, got %d: %s", cCode, string(cRaw))
	}
	var corpOut struct {
		ID               string `json:"id"`
		Status           string `json:"status"`
		FingerprintCount int64  `json:"fingerprint_count"`
	}
	_ = json.Unmarshal(cRaw, &corpOut)
	if corpOut.Status != "READY" || corpOut.FingerprintCount == 0 {
		t.Fatalf("expected READY corpus with fingerprints, got %s", string(cRaw))
	}

	// List & Reindex corpus via wired IPCorpusReindexer.
	lCode, lRaw := s.doAPIJSON(t, http.MethodGet, "/v1/ip-corpora", s.auditorJWT, "", nil)
	if lCode != http.StatusOK || !strings.Contains(string(lRaw), corpOut.ID) {
		t.Fatalf("GET /v1/ip-corpora failed (%d): %s", lCode, string(lRaw))
	}
	rCode, rRaw := s.doAPIJSON(t, http.MethodPost, "/v1/ip-corpora/"+corpOut.ID+"/reindex", s.adminJWT, "g13-reindex", map[string]any{
		"force": true,
		"files": []map[string]any{
			{"path": corpPath, "content": corpusSource},
			{"path": "internal_secret_dir/extra.go", "content": confidentialHeaderlessSampleGo},
		},
	})
	if (rCode != http.StatusOK && rCode != http.StatusAccepted) || !strings.Contains(string(rRaw), `"READY"`) {
		t.Fatalf("POST /v1/ip-corpora/{id}/reindex failed (%d): %s", rCode, string(rRaw))
	}

	// Verify zero raw corpus source or raw path leaked in API, ip_fingerprints, or audit_events.
	var fpDump string
	_ = s.pg.Pool().QueryRow(ctx, `SELECT COALESCE(string_agg(COALESCE(metadata::text, ''), ' '), '') FROM ip_fingerprints WHERE corpus_id = $1`, uuid.MustParse(corpOut.ID)).Scan(&fpDump)
	for label, blob := range map[string]string{
		"create_resp":     string(cRaw),
		"list_resp":       string(lRaw),
		"reindex_resp":    string(rRaw),
		"ip_fingerprints": fpDump,
	} {
		if strings.Contains(blob, corpRawSourceSecret) || strings.Contains(blob, corpPath) {
			t.Fatalf("Gate 13 violation: raw corpus source/path leaked in %s", label)
		}
	}

	// Push violating commit with delegated PAT & canary secret in PASSIVE_AUDIT -> records would-block metric + zero secret leaks.
	delegatedPAT := "ghp_adv13_delegated_secret_token_999"
	canarySecret := "AKIAIOSFODNN7EXAMPLE"
	// Allow delegated PAT in upstream server for this push.
	s.upstream.mu.Lock()
	s.upstream.requireWriteTok = ""
	s.upstream.mu.Unlock()
	workPA := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "passive audit canary", map[string]string{
		"leak.env": "KEY=" + canarySecret + "\n",
		"ip.go":    restrictedCorpusSampleGo,
	})
	paOut, paCode := runAdvGit(t, workPA, httpEnv, "-c", "http.extraHeader=X-Custodian-Upstream-Token: "+delegatedPAT, "push", "origin", "HEAD:refs/heads/g13-pa")
	if paCode != 0 {
		t.Fatalf("expected PASSIVE_AUDIT push to forward, code=%d out:\n%s", paCode, paOut)
	}
	sessPA := s.latestPushSession(t, &s.repo.ID)

	// Switch back to ENFORCE_BLOCK and trigger: quarantine rejection (refs/replace/*), approval issuance/consumption, and LFS batch.
	_, _ = s.doAPIJSON(t, http.MethodPut, "/v1/repositories/"+s.repo.ID.String()+"/egress-mode", s.adminJWT, "g13-mode-enf", map[string]any{
		"egress_mode": "ENFORCE_BLOCK",
	})
	mustAdvGit(t, workCLI, nil, "update-ref", "refs/replace/deadbeef", strings.TrimSpace(mustAdvGit(t, workCLI, nil, "rev-parse", "HEAD")))
	_, _ = runAdvGit(t, workCLI, httpEnv, "-c", "credential.helper="+credHelper, "push", "origin", "refs/replace/deadbeef:refs/replace/deadbeef")

	// Confidential corpus -> approval issuance & consumption (to populate approval_releases metric).
	s.indexCorpus(t, "g13-conf", domain.ClassificationConfidential, []fingerprints.CorpusFile{
		{Path: "billing/ledger.go", Content: []byte(confidentialHeaderlessSampleGo)},
	})
	// Deactivate RESTRICTED corpus so CONFIDENTIAL push hits REQUIRE_APPROVAL rather than DENY.
	_, _ = s.pg.Pool().Exec(ctx, `UPDATE ip_fingerprint_corpora SET enabled = FALSE WHERE id = $1`, uuid.MustParse(corpOut.ID))
	workConf := s.cloneAndCommitHTTP(t, "acme/service", s.aliceJWT, "Alice", "alice@example.com", "g13 conf", map[string]string{
		"billing_g13.go": confidentialHeaderlessSampleGo,
	})
	_, _ = runAdvGit(t, workConf, httpEnv, "push", "origin", "HEAD:refs/heads/g13-conf")
	sessNeedApp := s.latestPushSession(t, &s.repo.ID)
	apCode, _ := s.doAPIJSON(t, http.MethodPost, "/v1/pushes/"+sessNeedApp.ID.String()+"/approvals", s.bobJWT, "g13-app", map[string]any{
		"decision":             "APPROVE",
		"push_manifest_digest": *sessNeedApp.PushManifestDigest,
	})
	if apCode != http.StatusCreated {
		t.Fatalf("expected 201 approval, got %d", apCode)
	}
	if out, c := runAdvGit(t, workConf, httpEnv, "push", "origin", "HEAD:refs/heads/g13-conf"); c != 0 {
		t.Fatalf("expected approved re-push to succeed: %s", out)
	}

	// LFS batch request to populate lfs_batch_requests_total.
	lfsBody, _ := json.Marshal(gitgateway.LFSBatchRequest{
		Operation: "upload",
		Transfers: []string{"basic"},
		Objects:   []gitgateway.LFSBatchObjectInput{{OID: strings.Repeat("a", 64), Size: 64}},
	})
	reqLFS, _ := http.NewRequest(http.MethodPost, s.gwHTTP.URL+"/acme/service.git/info/lfs/objects/batch", bytes.NewReader(lfsBody))
	reqLFS.Header.Set("Authorization", "Bearer "+s.aliceJWT)
	respLFS, err := s.gwHTTP.Client().Do(reqLFS)
	if err != nil || respLFS.StatusCode != http.StatusOK {
		t.Fatalf("LFS batch failed: resp=%v err=%v", respLFS, err)
	}
	var lfsParsed gitgateway.LFSBatchResponse
	_ = json.NewDecoder(respLFS.Body).Decode(&lfsParsed)
	_ = respLFS.Body.Close()
	clfsTok := strings.TrimPrefix(lfsParsed.Objects[0].Actions["upload"].Header["Authorization"], "Bearer ")

	// 3. Control-plane GET /v1/pushes, GET /v1/pushes/{id}, and custodian push status CLI.
	crossCode, _ := s.doAPIJSON(t, http.MethodGet, "/v1/pushes?principal_id="+s.bob.ID.String(), s.aliceJWT, "", nil)
	if crossCode != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-principal GET /v1/pushes, got %d", crossCode)
	}
	getCode, getRaw := s.doAPIJSON(t, http.MethodGet, "/v1/pushes/"+sessPA.ID.String(), s.auditorJWT, "", nil)
	if getCode != http.StatusOK {
		t.Fatalf("GET /v1/pushes/{id} failed (%d): %s", getCode, string(getRaw))
	}

	cmdText := exec.Command(cliBin, "--api-url="+s.apiServer.URL, "--token="+s.aliceJWT, "push", "status", sessPA.ID.String(), "--format", "text")
	outText, errText := cmdText.CombinedOutput()
	if errText != nil || !strings.Contains(string(outText), "OBSERVED_WOULD_BLOCK") || !strings.Contains(string(outText), "Manifest Digest:") {
		t.Fatalf("custodian push status text failed: err=%v out:\n%s", errText, string(outText))
	}
	cmdJSON := exec.Command(cliBin, "--api-url="+s.apiServer.URL, "--token="+s.adminJWT, "push", "status", "--repository-id="+s.repo.ID.String(), "--format", "json")
	outJSON, errJSON := cmdJSON.CombinedOutput()
	if errJSON != nil || !strings.Contains(string(outJSON), `"pushes"`) {
		t.Fatalf("custodian push status json failed: err=%v out:\n%s", errJSON, string(outJSON))
	}

	// 4. Scrape GET /metrics on gateway and verify all 9 custodian_push_* metric families exist.
	respMet, err := s.gwHTTP.Client().Get(s.gwHTTP.URL + "/metrics")
	if err != nil || respMet.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics failed: resp=%v err=%v", respMet, err)
	}
	metBytes, _ := io.ReadAll(respMet.Body)
	_ = respMet.Body.Close()
	metStr := string(metBytes)
	for _, metricName := range []string{
		"custodian_push_sessions_total",
		"custodian_push_gateway_duration_seconds",
		"custodian_push_quarantine_rejections_total",
		"custodian_push_ip_fingerprint_matches_total",
		"custodian_push_ip_fingerprint_duration_seconds",
		"custodian_push_passive_audit_would_block_total",
		"custodian_push_approval_releases_total",
		"custodian_push_upstream_bytes_total",
		"custodian_push_lfs_batch_requests_total",
	} {
		if !strings.Contains(metStr, metricName) {
			t.Fatalf("missing Prometheus metric %q in /metrics output", metricName)
		}
	}

	// 5. Zero-secret verification across logs, audit_events, findings, model_assessments, GET /v1/pushes/{id}, and sideband.
	_, audRaw := s.doAPIJSON(t, http.MethodGet, "/v1/audit/events?limit=200", s.auditorJWT, "", nil)
	var findDump string
	_ = s.pg.Pool().QueryRow(ctx, `SELECT COALESCE(string_agg(COALESCE(message,'') || ' ' || COALESCE(metadata::text,''), ' '), '') FROM findings WHERE push_session_id = $1`, sessPA.ID).Scan(&findDump)
	sensitive := []string{canarySecret, delegatedPAT, s.aliceJWT, s.bobJWT, s.adminJWT, s.writeTok, string(s.ghPEM), clfsTok}
	s.assertZeroSecretsInLogs(t, delegatedPAT, clfsTok, canarySecret)
	for label, blob := range map[string]string{
		"audit_events": string(audRaw),
		"findings":     findDump,
		"get_push":     string(getRaw),
		"sideband":     paOut,
	} {
		for _, sec := range sensitive {
			if sec != "" && strings.Contains(blob, sec) {
				t.Fatalf("Gate 13 zero-secret violation: secret leaked in %s!", label)
			}
		}
	}
}

// Gate 14: Publisher isolation (PASSIVE_AUDIT enforced=false / PUSH_EGRESS cannot trigger custodian-publisher) + ZERO_FORBIDDEN_DEPS.
func TestADV_PG_Gate14_PublisherIsolationAndZeroForbiddenDeps(t *testing.T) {
	// 1. Runtime isolation against FullStack PG17.
	st := fixtures.NewFullStack(t)
	ctx := context.Background()

	ownerTok := st.MintHuman("g14-owner", "g14o@acme.test", []string{"eng"}, []string{"developer"})
	reviewerTok := st.MintHuman("g14-rev", "g14r@acme.test", []string{"security-reviewers"}, []string{"reviewer"})
	ctrlTok := st.MintController("g14-ctrl")

	_, propID, manifestDigest, version := st.CreateReadyWorkspaceAndSubmit(ctx, ownerTok, ctrlTok, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# Gate 14\n")},
		{Name: "app.go", Body: []byte("package main\nfunc main() {}\n")},
	})
	propUUID := uuid.MustParse(propID)

	evalCode, _ := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/evaluate", ctrlTok, "g14-eval", map[string]any{
		"expected_version": version,
	}, nil)
	if evalCode != http.StatusAccepted {
		t.Fatalf("Evaluate expected 202, got %d", evalCode)
	}
	st.DrainWorker(ctx)

	propRow, err := st.Store.GetProposalByID(ctx, propUUID)
	if err != nil || propRow.LatestPolicyEvaluationID == nil {
		t.Fatalf("GetProposalByID: prop=%+v err=%v", propRow, err)
	}
	appCode, appRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/approvals", reviewerTok, "g14-approve", map[string]any{
		"decision":                    "APPROVE",
		"publication_manifest_digest": manifestDigest,
		"policy_evaluation_id":        propRow.LatestPolicyEvaluationID.String(),
	}, nil)
	if appCode != http.StatusCreated {
		t.Fatalf("Approve expected 201, got %d: %s", appCode, string(appRaw))
	}

	assertPublishBlocked := func(label, pubIdem, wantErrSubstr string) {
		t.Helper()
		pCode, pRaw := st.DoJSON(http.MethodPost, "/v1/proposals/"+propID+"/publish", ctrlTok, pubIdem, map[string]any{
			"publication_manifest_digest": manifestDigest,
		}, nil)
		switch pCode {
		case http.StatusForbidden, http.StatusConflict:
			if !strings.Contains(string(pRaw), wantErrSubstr) {
				t.Fatalf("%s: expected error containing %q, got %d: %s", label, wantErrSubstr, pCode, string(pRaw))
			}
		case http.StatusAccepted:
			var out struct {
				OperationID string `json:"operation_id"`
			}
			_ = json.Unmarshal(pRaw, &out)
			st.DrainPublisher(ctx)
			op, opErr := st.Operations.GetDetails(ctx, uuid.MustParse(out.OperationID))
			if opErr != nil || op.Status != domain.OperationStatusFailed || !strings.Contains(op.LastError, wantErrSubstr) {
				t.Fatalf("%s: expected FAILED op containing %q, got status=%s err=%q opErr=%v", label, wantErrSubstr, op.Status, op.LastError, opErr)
			}
		default:
			t.Fatalf("%s: unexpected publish status %d: %s", label, pCode, string(pRaw))
		}
		var pubCnt int
		_ = st.PG.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM publications WHERE proposal_id = $1 AND status = 'PUBLISHED'`, propUUID).Scan(&pubCnt)
		if pubCnt != 0 || len(st.WriteClient.PullRequests(st.BareRepo.FullName)) != 0 {
			t.Fatalf("%s: publisher produced publication/PR despite blocked precondition!", label)
		}
	}

	// Case A: Mutate EGRESS policy_decision to enforced = false (simulating PASSIVE_AUDIT unenforced decision).
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE policy_decisions SET enforced = FALSE WHERE id = $1`, *propRow.LatestPolicyEvaluationID); err != nil {
		t.Fatalf("set enforced=false: %v", err)
	}
	assertPublishBlocked("caseA_enforced_false", "g14-pub-a", "UNENFORCED_POLICY_DECISION")

	// Case B1: Restore APPROVED state, point proposal.latest_policy_evaluation_id to a real PASSIVE_AUDIT PUSH_EGRESS decision.
	// Verify BOTH direct PubSvc.RequestPublication (STALE_POLICY_DECISION) AND API POST /publish (409) reject it.
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE proposals SET status = 'APPROVED' WHERE id = $1`, propUUID); err != nil {
		t.Fatalf("restore APPROVED status: %v", err)
	}
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE policy_decisions SET enforced = TRUE WHERE id = $1`, *propRow.LatestPolicyEvaluationID); err != nil {
		t.Fatalf("restore enforced=true: %v", err)
	}
	pushPrincipal, err := st.Store.UpsertPrincipal(ctx, persistence.UpsertPrincipalParams{
		ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, Issuer: st.OIDC.Issuer(),
		Subject: "g14-pusher", DisplayName: "G14 Pusher", VerifiedEmail: "g14p@acme.test", CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertPrincipal: %v", err)
	}
	pushSessID := domain.MustNewID()
	enforcedFalse := false
	if _, err := st.Store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		ID: pushSessID, PrincipalID: pushPrincipal.ID, RepositoryID: &st.Repo.ID,
		Destination: "github.com/" + st.BareRepo.FullName, DestinationHost: "github.com",
		DestinationRegistered: true, DestinationExternal: false, Transport: domain.PushTransportHTTPS,
		RefUpdates: []domain.PushRefUpdate{{RefName: "refs/heads/main", OldOID: strings.Repeat("0", 40), NewOID: strings.Repeat("a", 40)}},
		EgressMode: domain.EgressModePassiveAudit, PassiveAuditDelivery: domain.PassiveAuditDeliveryInlineWarn,
		Enforced: &enforcedFalse, Status: domain.PushSessionStatusObservedWouldBlock, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreatePushSession: %v", err)
	}
	orgBundles, err := st.Store.ListActivePolicyBundlesByScope(ctx, domain.PolicyScopeOrg, nil)
	if err != nil || len(orgBundles) == 0 {
		t.Fatalf("ListActivePolicyBundlesByScope: %v", err)
	}
	pushPD, err := st.Store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		ProposalID: uuid.Nil, PushSessionID: &pushSessID, PolicyBundleID: orgBundles[0].ID,
		Stage: "PUSH_EGRESS", Enforced: &enforcedFalse, InputDigest: strings.Repeat("b", 64),
		Effect: domain.PolicyEffectAllow, CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision(PUSH_EGRESS): %v", err)
	}
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE proposals SET latest_policy_evaluation_id = $1 WHERE id = $2`, pushPD.ID, propUUID); err != nil {
		t.Fatalf("point proposal to PUSH_EGRESS decision: %v", err)
	}
	if _, pubErr := st.PubSvc.RequestPublication(ctx, propUUID, manifestDigest, nil); pubErr == nil || !strings.Contains(pubErr.Error(), "STALE_POLICY_DECISION") {
		t.Fatalf("caseB1 PubSvc.RequestPublication expected STALE_POLICY_DECISION, got %v", pubErr)
	}
	assertPublishBlocked("caseB1_push_egress_decision", "g14-pub-b1", "MISSING_HUMAN_APPROVAL")

	// Case B2: Restore APPROVED state and latest_policy_evaluation_id, set stage='PUSH_EGRESS' on the decision row -> INVALID_POLICY_STAGE.
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE proposals SET status = 'APPROVED', latest_policy_evaluation_id = $1 WHERE id = $2`, *propRow.LatestPolicyEvaluationID, propUUID); err != nil {
		t.Fatalf("restore APPROVED and latest_policy_evaluation_id: %v", err)
	}
	if _, err := st.PG.Pool().Exec(ctx, `UPDATE policy_decisions SET stage = 'PUSH_EGRESS' WHERE id = $1`, *propRow.LatestPolicyEvaluationID); err != nil {
		t.Fatalf("set stage=PUSH_EGRESS: %v", err)
	}
	if _, pubErr := st.PubSvc.RequestPublication(ctx, propUUID, manifestDigest, nil); pubErr == nil || !strings.Contains(pubErr.Error(), "INVALID_POLICY_STAGE") {
		t.Fatalf("caseB2 PubSvc.RequestPublication expected INVALID_POLICY_STAGE, got %v", pubErr)
	}
	assertPublishBlocked("caseB2_push_egress_stage", "g14-pub-b2", "INVALID_POLICY_STAGE")

	// 2. Compile-time ZERO_FORBIDDEN_DEPS verification across publisher packages.
	root := fixtures.FindRepoRoot(t)
	cmdDeps := exec.Command("go", "list", "-deps",
		"github.com/timreynolds/custodian/cmd/custodian-publisher",
		"github.com/timreynolds/custodian/internal/publication",
		"github.com/timreynolds/custodian/internal/git/publish",
	)
	cmdDeps.Dir = root
	outDeps, err := cmdDeps.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, string(outDeps))
	}
	forbidden := []string{
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/workflow",
		"github.com/timreynolds/custodian/internal/gitgateway",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/git/checkout",
		"github.com/timreynolds/custodian/internal/git/reconstruct",
		"github.com/google/cel-go",
		"golang.org/x/crypto/ssh",
	}
	for _, line := range strings.Split(strings.TrimSpace(string(outDeps)), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "github.com/timreynolds/custodian/internal/github" {
			t.Fatalf("forbidden publisher dependency: %s", pkg)
		}
		for _, f := range forbidden {
			if pkg == f || strings.HasPrefix(pkg, f+"/") {
				t.Fatalf("forbidden publisher dependency: %s", pkg)
			}
		}
	}
}
