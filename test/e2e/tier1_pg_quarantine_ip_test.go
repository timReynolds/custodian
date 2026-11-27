package e2e_test

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

func t1pgResolveGoBin(t testing.TB) string {
	t.Helper()
	goBin, err := harness.ResolveGoBin()
	if err != nil {
		t.Fatalf("ResolveGoBin: %v", err)
	}
	return goBin
}

func t1pgSQLQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func t1pgReadQuarantineFixtureBytes(t testing.TB, relParts ...string) []byte {
	t.Helper()
	parts := append([]string{pgFindRepoRoot(t), "test", "e2e", "fixtures", "push_gateway"}, relParts...)
	p := filepath.Join(parts...)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %q: %v", p, err)
	}
	return data
}

func t1pgReadQuarantineFixture(t testing.TB, relParts ...string) string {
	t.Helper()
	return string(t1pgReadQuarantineFixtureBytes(t, relParts...))
}

func t1pgRestrictedCorpusFiles(t testing.TB) map[string]string {
	t.Helper()
	return map[string]string{
		"proprietary_engine.go": t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go"),
		"proprietary_header.py": t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_header.py"),
	}
}

func t1pgConfidentialCorpusFiles(t testing.TB) map[string]string {
	t.Helper()
	return map[string]string{
		"internal_billing_rules.go": t1pgReadQuarantineFixture(t, "corpora", "confidential", "internal_billing_rules.go"),
	}
}

func t1pgRestrictedSensitiveSnippets() []string {
	return []string{
		"TelemetryCalibrator",
		"ComputeAttenuation",
		"SealTelemetryFrame",
		"SpectralConvergenceTol",
		"DefaultDecayCoefficient",
		"acme proprietary spectral calibration diverged",
		"ACME_SETTLEMENT_WEIGHTS",
		"compute_settlement_exposure",
		"ACME_SETTLEMENT_FLOOR",
	}
}

func t1pgWaitLatestPush(t testing.TB, env *harness.Env, cli *harness.APIClient, repoID string, timeout time.Duration) harness.PushSessionResp {
	t.Helper()
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	deadline := time.Now().Add(timeout)
	var latest harness.PushSessionResp
	for time.Now().Before(deadline) {
		resp, raw, err := cli.ListPushes(ctx, harness.PushFilter{
			RepositoryID: repoID,
			Limit:        10,
		})
		if err != nil {
			t.Fatalf("ListPushes(repo=%s): %v", repoID, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		if len(resp.Pushes) > 0 {
			latest = resp.Pushes[0]
			if t1pgIsTerminalPushStatus(env, latest.Status) {
				detail, gRaw, err := cli.GetPush(ctx, latest.ID)
				if err != nil {
					t.Fatalf("GetPush(%s): %v", latest.ID, err)
				}
				gRaw.RequireStatus(t, http.StatusOK)
				return detail
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("push session for repo %s did not reach terminal status within %s (last=%+v)", repoID, timeout, latest)
	return harness.PushSessionResp{}
}

func t1pgWaitPushCount(t testing.TB, env *harness.Env, cli *harness.APIClient, repoID string, minCount int, timeout time.Duration) []harness.PushSessionResp {
	t.Helper()
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	deadline := time.Now().Add(timeout)
	var last []harness.PushSessionResp
	for time.Now().Before(deadline) {
		resp, raw, err := cli.ListPushes(ctx, harness.PushFilter{
			RepositoryID: repoID,
			Limit:        50,
		})
		if err != nil {
			t.Fatalf("ListPushes(repo=%s): %v", repoID, err)
		}
		raw.RequireStatus(t, http.StatusOK)
		last = resp.Pushes
		if len(last) >= minCount {
			allTerminal := true
			for _, p := range last[:minCount] {
				if !t1pgIsTerminalPushStatus(env, p.Status) {
					allTerminal = false
					break
				}
			}
			if allTerminal {
				details := make([]harness.PushSessionResp, len(last))
				for i, s := range last {
					detail, gRaw, gErr := cli.GetPush(ctx, s.ID)
					if gErr != nil {
						t.Fatalf("GetPush(%s): %v", s.ID, gErr)
					}
					gRaw.RequireStatus(t, http.StatusOK)
					details[i] = detail
				}
				return details
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected >= %d terminal push sessions for repo %s within %s, got %d (%+v)", minCount, repoID, timeout, len(last), last)
	return nil
}

func t1pgSeedRepoRow(t testing.TB, env *harness.Env, fullName, classification, mode, delivery string) (harness.SeededRepo, string) {
	t.Helper()
	repo, ok := env.Git().Repo(fullName)
	if !ok {
		t.Fatalf("seeded repo %q missing from BareGitHelper", fullName)
	}
	if classification == "" {
		classification = "INTERNAL"
	}
	repoID := harness.NewTestUUIDv7()
	q := fmt.Sprintf(
		`INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations)
		 VALUES (%s::uuid, %d, %d, %s, %s, true, ARRAY['approved-code-review']::text[], 10);`,
		t1pgSQLQuote(repoID), repo.GitHubRepoID, repo.InstallationID, t1pgSQLQuote(repo.FullName), t1pgSQLQuote(classification),
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("seed repo row %q: %v", fullName, err)
	}
	if mode != "" {
		adminTok := env.MintToken(harness.TokenClaims{
			Kind:    "HUMAN",
			Subject: "t1pg-repo-admin",
			Email:   "t1pg-admin@example.com",
			Groups:  []string{"security-admins", "policy-admins"},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, raw, err := env.Client(adminTok).SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
			EgressMode:           mode,
			PassiveAuditDelivery: delivery,
		})
		if err != nil {
			t.Fatalf("SetRepoEgressMode(%s, %s): %v", repoID, mode, err)
		}
		raw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	}
	return repo, repoID
}

func t1pgIsLowerHexRange(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func t1pgIsHex64(s string) bool {
	return t1pgIsLowerHexRange(s, 64, 64)
}

func t1pgCloneGatewayRepo(t testing.TB, env *harness.Env, repoFullName, token string) string {
	t.Helper()
	workDir, res := pgGitCloneHTTP(t, t1pgGatewayRepoURL(env, repoFullName), token, env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("pgGitCloneHTTP(%s) failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			repoFullName, res.ExitCode, res.Stdout, res.Stderr)
	}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", "Alice Developer")
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", "alice@example.com")
	return workDir
}

func t1pgRunV1PRWorkflow(t testing.TB, env *harness.Env, repo harness.SeededRepo, actors pgActorSet, filePath, content string) harness.PublicationResp {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	humanCli := actors.HumanACli
	ctrlCli := actors.CtrlCli

	wsCreate, wsRaw, err := humanCli.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/" + repo.DefaultBranch,
		},
		Agent: &harness.WorkspaceAgentInfo{
			Type:       "coding-agent",
			SessionID:  "sess-" + harness.NewTestUUIDv7(),
			ModelRoute: "approved-code-review",
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	wsRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated, http.StatusOK)

	wsID := wsCreate.WorkspaceID
	if wsID == "" {
		wsID = wsCreate.ID
	}
	harness.AssertUUIDv7(t, wsID)
	if wsCreate.OperationID != "" {
		op, err := humanCli.WaitForOperation(ctx, wsCreate.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(ws %s): %v", wsID, err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("workspace op failed: %+v", op)
		}
	}

	ws, getRaw, err := humanCli.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace(%s): %v", wsID, err)
	}
	getRaw.RequireStatus(t, http.StatusOK)

	capResp, capRaw, err := ctrlCli.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability(%s): %v", wsID, err)
	}
	capRaw.RequireStatus(t, http.StatusOK)

	entries := []harness.TarEntry{
		{Name: "README.md", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("# acme/service\n")},
		{Name: "main.go", Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: filePath, Typeflag: tar.TypeReg, Mode: 0o644, Body: []byte(content)},
	}
	gzBytes, shaHex := harness.MustBuildTarGz(t, entries)

	upRaw, err := ctrlCli.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, gzBytes)
	if err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)
	var upBody struct {
		ArtifactID string `json:"artifact_id"`
		ID         string `json:"id"`
		SHA256     string `json:"sha256"`
	}
	if err := json.Unmarshal(upRaw.Body, &upBody); err != nil {
		t.Fatalf("decode UploadSnapshot response: %v", err)
	}
	artID := upBody.ArtifactID
	if artID == "" {
		artID = upBody.ID
	}
	if upBody.SHA256 != "" {
		shaHex = upBody.SHA256
	}

	subResp, subRaw, err := ctrlCli.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artID,
			SHA256:              shaHex,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gzBytes)),
		},
		Title:      "v1 PR parity test",
		Provenance: &harness.Provenance{Type: "agent_assisted", CaptureMethod: "frozen_filesystem"},
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusCreated, http.StatusOK)
	propID := subResp.ProposalID
	if propID == "" {
		propID = subResp.ID
	}
	if subResp.OperationID != "" {
		op, err := ctrlCli.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(reconstruct): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("reconstruct op failed: %+v", op)
		}
	}

	prop, pRaw, err := ctrlCli.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal(%s): %v", propID, err)
	}
	pRaw.RequireStatus(t, http.StatusOK)

	evalResp, evalRaw, err := ctrlCli.EvaluateProposal(ctx, propID, harness.EvaluateReq{ExpectedVersion: prop.Version})
	if err != nil {
		t.Fatalf("EvaluateProposal(%s): %v", propID, err)
	}
	evalRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	if evalResp.OperationID != "" {
		op, err := ctrlCli.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(evaluate): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("evaluate op failed: %+v", op)
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		prop, pRaw, err = ctrlCli.GetProposal(ctx, propID)
		if err != nil {
			t.Fatalf("GetProposal(%s): %v", propID, err)
		}
		pRaw.RequireStatus(t, http.StatusOK)
		if prop.Status == "APPROVED" || prop.Status == "PENDING_APPROVAL" {
			break
		}
		if harness.ContainsStatus(env.Contracts().ProposalStatuses.TerminalFailure, prop.Status) {
			t.Fatalf("proposal %s reached unexpected failure status %q", propID, prop.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if prop.Status == "PENDING_APPROVAL" {
		_, aRaw, err := actors.SecAdminCli.ApproveProposal(ctx, propID, harness.ApproveReq{
			Decision:                  "APPROVE",
			PublicationManifestDigest: prop.PublicationManifestDigest,
			PolicyEvaluationID:        prop.LatestPolicyEvaluationID,
			Comment:                   "approve v1 PR workflow",
		})
		if err != nil {
			t.Fatalf("ApproveProposal(%s): %v", propID, err)
		}
		aRaw.RequireAnyStatus(t, http.StatusCreated, http.StatusOK)
	} else if prop.Status != "APPROVED" {
		t.Fatalf("proposal %s status = %q (want APPROVED or PENDING_APPROVAL)", propID, prop.Status)
	}

	pubResp, pubRaw, err := ctrlCli.PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal(%s): %v", propID, err)
	}
	pubRaw.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)
	pubID := pubResp.PublicationID
	if pubID == "" {
		pubID = pubResp.ID
	}
	if pubResp.OperationID != "" {
		op, err := ctrlCli.WaitForOperation(ctx, pubResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(publish): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("publish op failed: %+v", op)
		}
	}

	pubDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(pubDeadline) {
		got, gRaw, err := ctrlCli.GetPublication(ctx, pubID)
		if err != nil {
			t.Fatalf("GetPublication(%s): %v", pubID, err)
		}
		gRaw.RequireStatus(t, http.StatusOK)
		if got.Status == "PUBLISHED" {
			return got
		}
		if harness.ContainsStatus(env.Contracts().PublicationStatuses.TerminalFailure, got.Status) {
			t.Fatalf("publication %s failed: %+v", pubID, got)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("publication %s did not reach PUBLISHED", pubID)
	return harness.PublicationResp{}
}

func t1pgAssertNoRawLeakOnAllSurfaces(
	t testing.TB,
	env *harness.Env,
	adminCli *harness.APIClient,
	audCli *harness.APIClient,
	pushID string,
	corpusID string,
	gitStderr string,
	snippets ...string,
) {
	t.Helper()
	var filtered []string
	for _, s := range snippets {
		if s != "" {
			filtered = append(filtered, s)
		}
	}
	if len(filtered) == 0 {
		return
	}

	// Surface 1: Git stderr / sideband output.
	if gitStderr != "" {
		harness.AssertNoSecretOrEncodedLeak(t, gitStderr, filtered...)
	}

	// Surface 2: Raw HTTP response bodies.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ep := env.Contracts().PushEndpoints
	base := strings.TrimRight(env.Contracts().APIBasePath, "/")
	if base == "" {
		base = "/v1"
	}
	httpPaths := []struct {
		cli  *harness.APIClient
		path string
	}{
		{adminCli, base + ep.PushesPath},
		{adminCli, base + strings.ReplaceAll(ep.PushByIDPath, "{id}", pushID)},
		{adminCli, base + ep.IPCorporaPath},
		{adminCli, base + strings.ReplaceAll(ep.PushByIDPath, "{id}", pushID) + "/findings"},
		{audCli, base + "/audit/events?resource_id=" + pushID + "&limit=100"},
	}
	for _, target := range httpPaths {
		raw, err := target.cli.DoRaw(ctx, http.MethodGet, target.path, nil)
		if err != nil {
			t.Fatalf("GET %s: %v", target.path, err)
		}
		if raw.StatusCode == http.StatusNotFound && strings.HasSuffix(target.path, "/findings") {
			continue
		}
		harness.AssertNoSecretOrEncodedLeak(t, string(raw.Body), filtered...)
	}

	// Surface 3: PostgreSQL tables (ip_fingerprints, ip_fingerprint_corpora, findings, push_sessions, audit_events).
	queries := []string{
		fmt.Sprintf("SELECT id::text, layer, fingerprint_hash, COALESCE(file_path_hash,''), COALESCE(language,''), COALESCE(metadata::text,'') FROM ip_fingerprints WHERE corpus_id = %s::uuid", t1pgSQLQuote(corpusID)),
		fmt.Sprintf("SELECT id::text, name, classification, COALESCE(description,''), COALESCE(source_ref,''), COALESCE(last_error,'') FROM ip_fingerprint_corpora WHERE id = %s::uuid", t1pgSQLQuote(corpusID)),
		fmt.Sprintf("SELECT f.id::text, COALESCE(f.rule_id,''), COALESCE(f.path,''), COALESCE(f.message,''), COALESCE(f.metadata::text,''), COALESCE(f.evidence_ref,'') FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid", t1pgSQLQuote(pushID)),
		fmt.Sprintf("SELECT id::text, COALESCE(destination,''), COALESCE(error_message,'') FROM push_sessions WHERE id = %s::uuid", t1pgSQLQuote(pushID)),
		fmt.Sprintf("SELECT id::text, event_type, payload::text FROM audit_events WHERE resource_id = %s", t1pgSQLQuote(pushID)),
	}
	var dbDump strings.Builder
	for _, q := range queries {
		rows, err := env.DB().QueryRows(q)
		if err != nil {
			t.Fatalf("query surface %q: %v", q, err)
		}
		for _, r := range rows {
			dbDump.WriteString(strings.Join(r, "\t"))
			dbDump.WriteByte('\n')
		}
	}
	harness.AssertNoSecretOrEncodedLeak(t, dbDump.String(), filtered...)

	// Surface 4: Daemon logs (api, worker, publisher, git-gateway).
	pgAssertNoRawCorpusLeak(t, env, filtered...)
}

// --- EF5: Egress Operating Modes (5 tests) ---

func TestT1_PG_EF5_PassiveAuditAsyncForwardsAndRecordsUnenforced(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "")
	actors := pgMintActors(env)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, modeRaw, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "ASYNC",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode: %v", err)
	}
	modeRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)

	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef5-restricted-async", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")
	tipSHA := pgAddCommit(t, workDir, map[string]string{"proprietary_engine.go": restrictedSrc}, nil, "feat: passive audit async test", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT ASYNC push should succeed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	gotHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotHead != tipSHA {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotHead, err, tipSHA)
	}
	if len(env.GitHub().ReceivePackCalls()) == 0 {
		t.Fatalf("expected upstream receive-pack calls > 0 in PASSIVE_AUDIT")
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.EgressMode != "PASSIVE_AUDIT" {
		t.Fatalf("push.EgressMode = %q, want PASSIVE_AUDIT", push.EgressMode)
	}
	if push.PassiveAuditDelivery != "" && push.PassiveAuditDelivery != "ASYNC" {
		t.Fatalf("push.PassiveAuditDelivery = %q, want ASYNC", push.PassiveAuditDelivery)
	}
	if !push.UpstreamForwarded {
		t.Fatalf("expected push.UpstreamForwarded == true in PASSIVE_AUDIT")
	}
	if push.Status != "OBSERVED_WOULD_BLOCK" && push.Status != "COMPLETED" {
		t.Fatalf("unexpected PASSIVE_AUDIT status %q (want OBSERVED_WOULD_BLOCK or COMPLETED)", push.Status)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT enforced, stage FROM policy_decisions WHERE push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query policy_decisions for push %s: rows=%v err=%v", push.ID, rows, err)
	}
	if rows[0][0] != "f" && rows[0][0] != "false" {
		t.Fatalf("expected policy_decisions.enforced = false in PASSIVE_AUDIT, got %q", rows[0][0])
	}
	if rows[0][1] != "PUSH_EGRESS" {
		t.Fatalf("expected policy_decisions.stage = PUSH_EGRESS, got %q", rows[0][1])
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF5_PassiveAuditInlineWarnEmitsSidebandWarningAndForwards(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "")
	actors := pgMintActors(env)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, modeRaw, err := actors.SecAdminCli.SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
		EgressMode:           "PASSIVE_AUDIT",
		PassiveAuditDelivery: "INLINE_WARN",
	})
	if err != nil {
		t.Fatalf("SetRepoEgressMode: %v", err)
	}
	modeRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)

	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef5-restricted-inline", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")
	tipSHA := pgAddCommit(t, workDir, map[string]string{"proprietary_engine.go": restrictedSrc}, nil, "feat: passive audit inline warn test", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT INLINE_WARN push should succeed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	gotHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || gotHead != tipSHA {
		t.Fatalf("upstream main = %q (err=%v), want %q", gotHead, err, tipSHA)
	}
	if n := env.GitHub().ReceivePackBytes(repo.FullName); n <= 0 {
		t.Fatalf("expected ReceivePackBytes > 0 in PASSIVE_AUDIT INLINE_WARN, got %d", n)
	}
	if !strings.Contains(res.Stderr, "remote:") {
		t.Fatalf("expected sideband channel-2 warning ('remote:') in git stderr, got:\n%s", res.Stderr)
	}
	lowerStderr := strings.ToLower(res.Stderr)
	if !strings.Contains(lowerStderr, "warn") && !strings.Contains(lowerStderr, "would") && !strings.Contains(lowerStderr, "policy") && !strings.Contains(lowerStderr, "passive") {
		t.Fatalf("expected inline warning text in sideband stderr, got:\n%s", res.Stderr)
	}
	harness.AssertNoSecretOrEncodedLeak(t, res.Stderr, t1pgRestrictedSensitiveSnippets()...)

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.EgressMode != "PASSIVE_AUDIT" || !push.UpstreamForwarded {
		t.Fatalf("unexpected push record: %+v", push)
	}
	if push.PassiveAuditDelivery != "" && push.PassiveAuditDelivery != "INLINE_WARN" {
		t.Fatalf("expected PassiveAuditDelivery=INLINE_WARN, got %q", push.PassiveAuditDelivery)
	}
	if push.Status != "OBSERVED_WOULD_BLOCK" {
		t.Fatalf("expected Status=OBSERVED_WOULD_BLOCK, got %q", push.Status)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT enforced FROM policy_decisions WHERE push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 || (rows[0][0] != "f" && rows[0][0] != "false") {
		t.Fatalf("expected unenforced policy_decision row, got rows=%v err=%v", rows, err)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF5_EnforceBlockDeniesViolationWithZeroUpstreamBytes(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef5-restricted-block", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	origHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")
	_ = pgAddCommit(t, workDir, map[string]string{"proprietary_engine.go": restrictedSrc}, nil, "feat: enforce block violation", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected ENFORCE_BLOCK push with restricted IP to fail")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	afterHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || afterHead != origHead {
		t.Fatalf("upstream main changed from %q to %q despite ENFORCE_BLOCK", origHead, afterHead)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.EgressMode != "ENFORCE_BLOCK" || push.UpstreamForwarded {
		t.Fatalf("unexpected push fields: egress_mode=%q upstream_forwarded=%v", push.EgressMode, push.UpstreamForwarded)
	}
	if push.Status != "BLOCKED" && push.Status != "DENIED" {
		t.Fatalf("expected BLOCKED or DENIED status, got %q", push.Status)
	}
	if push.PolicyEffect != "DENY" {
		t.Fatalf("expected PolicyEffect=DENY, got %q", push.PolicyEffect)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT enforced FROM policy_decisions WHERE push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 || (rows[0][0] != "t" && rows[0][0] != "true") {
		t.Fatalf("expected enforced=true policy_decision, got rows=%v err=%v", rows, err)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF5_PerRepoEgressModeOverridesOrgDefault(t *testing.T) {
	defaultSpec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "default-repo",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# default-repo\n"},
	}
	overrideSpec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "override-repo",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# override-repo\n"},
	}
	env := pgNewEnv(t,
		harness.WithSeedRepos(defaultSpec, overrideSpec),
		harness.WithGitGateway(
			harness.WithGitGatewayDefaultEgressMode("PASSIVE_AUDIT"),
			harness.WithGitGatewayPassiveDelivery("ASYNC"),
		),
	)
	actors := pgMintActors(env)

	repoDefault, idDefault := t1pgSeedRepoRow(t, env, "acme/default-repo", "INTERNAL", "", "")
	repoOverride, idOverride := t1pgSeedRepoRow(t, env, "acme/override-repo", "INTERNAL", "ENFORCE_BLOCK", "")

	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef5-restricted-override", "RESTRICTED", t1pgRestrictedCorpusFiles(t))
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")

	// Push to acme/default-repo (inherits org default PASSIVE_AUDIT -> succeeds).
	wd1 := t1pgCloneGatewayRepo(t, env, repoDefault.FullName, actors.HumanATok)
	_ = pgAddCommit(t, wd1, map[string]string{"proprietary_engine.go": restrictedSrc}, nil, "feat: push to org default passive repo", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	res1 := pgGitPushHTTP(t, wd1, t1pgGatewayRepoURL(env, repoDefault.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res1.ExitCode != 0 {
		t.Fatalf("expected default-repo (org PASSIVE_AUDIT) push to succeed, got exit %d:\n%s", res1.ExitCode, res1.Stderr)
	}
	p1 := t1pgWaitLatestPush(t, env, actors.HumanACli, idDefault, 20*time.Second)
	if !p1.UpstreamForwarded || p1.EgressMode != "PASSIVE_AUDIT" {
		t.Fatalf("expected default-repo push in PASSIVE_AUDIT with upstream_forwarded=true, got %+v", p1)
	}

	// Push to acme/override-repo (overridden to ENFORCE_BLOCK -> blocked with 0 upstream bytes).
	wd2 := t1pgCloneGatewayRepo(t, env, repoOverride.FullName, actors.HumanATok)
	_ = pgAddCommit(t, wd2, map[string]string{"proprietary_engine.go": restrictedSrc}, nil, "feat: push to overridden enforce repo", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	res2 := pgGitPushHTTP(t, wd2, t1pgGatewayRepoURL(env, repoOverride.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res2.ExitCode == 0 {
		t.Fatalf("expected override-repo (ENFORCE_BLOCK) push to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repoOverride.FullName)
	p2 := t1pgWaitLatestPush(t, env, actors.HumanACli, idOverride, 20*time.Second)
	if p2.EgressMode != "ENFORCE_BLOCK" || p2.UpstreamForwarded {
		t.Fatalf("expected override-repo push in ENFORCE_BLOCK with upstream_forwarded=false, got %+v", p2)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF5_EnforcePRModePreservesV1WorkflowParity(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_PR")
	actors := pgMintActors(env)

	rows, err := env.DB().QueryRows(fmt.Sprintf("SELECT egress_mode FROM repositories WHERE id = %s::uuid", t1pgSQLQuote(repoID)))
	if err != nil || len(rows) == 0 || rows[0][0] != "ENFORCE_PR" {
		t.Fatalf("expected repositories.egress_mode = ENFORCE_PR, got rows=%v err=%v", rows, err)
	}

	// Part A: Full v1.0 PR publication succeeds while gateway is running.
	pub := t1pgRunV1PRWorkflow(t, env, repo, actors, "clean_pr_feature.go", "package main\n\nfunc prFeature() string { return \"ok\" }\n")
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}
	if env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected 1 PR created on MockGitHub, got %d", env.GitHub().PRCount(repo.FullName))
	}

	// Part B: Direct git push to ENFORCE_PR repo main branch must not bypass PR gating.
	origHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil {
		t.Fatalf("ResolveRef: %v", err)
	}
	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, workDir, map[string]string{"direct_bypass.go": "package main\n"}, nil, "feat: attempt direct push in ENFORCE_PR", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected direct git push to ENFORCE_PR repo to be rejected")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	afterHead, err := env.Git().ResolveRef(repo.FullName, "refs/heads/main")
	if err != nil || afterHead != origHead {
		t.Fatalf("main branch mutated from %q to %q during ENFORCE_PR direct push", origHead, afterHead)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

// --- EF6: Publisher Isolation (5 tests) ---

func TestT1_PG_EF6_PublisherZeroForbiddenDeps(t *testing.T) {
	pgRequireGatewayBinary(t)
	root := pgFindRepoRoot(t)
	goBin := t1pgResolveGoBin(t)

	cmd := exec.Command(goBin, "list", "-deps", "./cmd/custodian-publisher", "./internal/publication", "./internal/git/publish")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, string(out))
	}

	forbiddenPrefixes := []string{
		"github.com/timreynolds/custodian/internal/gitgateway",
		"github.com/timreynolds/custodian/internal/inspection",
		"github.com/timreynolds/custodian/internal/decisions",
		"github.com/timreynolds/custodian/internal/policy",
		"github.com/timreynolds/custodian/internal/auth",
		"github.com/timreynolds/custodian/internal/identity",
		"github.com/timreynolds/custodian/internal/snapshots",
		"github.com/timreynolds/custodian/internal/archive",
		"github.com/timreynolds/custodian/internal/git/checkout",
		"github.com/timreynolds/custodian/internal/git/reconstruct",
		"github.com/google/cel-go",
		"golang.org/x/crypto/ssh",
	}
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		if pkg == "github.com/timreynolds/custodian/internal/github" {
			t.Fatalf("publisher dependency isolation violated: imports forbidden package %q", pkg)
		}
		for _, prefix := range forbiddenPrefixes {
			if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
				t.Fatalf("publisher dependency isolation violated: imports forbidden package %q (prefix %q)", pkg, prefix)
			}
		}
	}
}

func TestT1_PG_EF6_PassiveAuditUnenforcedDecisionCannotTriggerPublisher(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "PASSIVE_AUDIT")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef6-restricted-passive", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")
	_ = pgAddCommit(t, workDir, map[string]string{"proprietary_engine.go": restrictedSrc}, nil, "feat: passive audit publisher isolation", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("PASSIVE_AUDIT push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT stage, enforced FROM policy_decisions WHERE push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query policy_decisions: rows=%v err=%v", rows, err)
	}
	if rows[0][0] != "PUSH_EGRESS" || (rows[0][1] != "f" && rows[0][1] != "false") {
		t.Fatalf("expected stage=PUSH_EGRESS and enforced=false, got %+v", rows[0])
	}

	pubRows, err := env.DB().QueryRows("SELECT COUNT(*) FROM publications")
	if err != nil || len(pubRows) == 0 || pubRows[0][0] != "0" {
		t.Fatalf("expected 0 publications from PASSIVE_AUDIT push, got rows=%v err=%v", pubRows, err)
	}
	opRows, err := env.DB().QueryRows("SELECT COUNT(*) FROM operations WHERE operation_type = 'PROPOSAL_PUBLISH'")
	if err != nil || len(opRows) == 0 || opRows[0][0] != "0" {
		t.Fatalf("expected 0 PROPOSAL_PUBLISH operations, got rows=%v err=%v", opRows, err)
	}
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs on MockGitHub, got %d", env.GitHub().PRCount(repo.FullName))
	}
	if strings.Contains(env.Logs("publisher"), push.ID) {
		t.Fatalf("publisher logs unexpectedly referenced push_session %s", push.ID)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF6_PushEgressAllowDecisionCannotTriggerPublisher(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_ = pgAddCommit(t, workDir, map[string]string{"clean_feature.go": cleanSrc}, nil, "feat: clean push allow publisher isolation", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("clean push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.PolicyEffect != "ALLOW" || !push.UpstreamForwarded {
		t.Fatalf("expected ALLOW and upstream_forwarded=true, got %+v", push)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT stage, effect, enforced FROM policy_decisions WHERE push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query policy_decisions: rows=%v err=%v", rows, err)
	}
	if rows[0][0] != "PUSH_EGRESS" || rows[0][1] != "ALLOW" || (rows[0][2] != "t" && rows[0][2] != "true") {
		t.Fatalf("unexpected policy_decision row: %+v", rows[0])
	}

	pubRows, err := env.DB().QueryRows("SELECT COUNT(*) FROM publications")
	if err != nil || len(pubRows) == 0 || pubRows[0][0] != "0" {
		t.Fatalf("expected 0 publications after PUSH_EGRESS ALLOW, got rows=%v err=%v", pubRows, err)
	}
	opRows, err := env.DB().QueryRows("SELECT COUNT(*) FROM operations WHERE operation_type = 'PROPOSAL_PUBLISH'")
	if err != nil || len(opRows) == 0 || opRows[0][0] != "0" {
		t.Fatalf("expected 0 PROPOSAL_PUBLISH operations, got rows=%v err=%v", opRows, err)
	}
	if env.GitHub().PRCount(repo.FullName) != 0 {
		t.Fatalf("expected 0 PRs on MockGitHub, got %d", env.GitHub().PRCount(repo.FullName))
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF6_PublisherContinuesWorkingOnV1EnforcedEgress(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	pub := t1pgRunV1PRWorkflow(t, env, repo, actors, "v1_egress_ok.go", "package main\n\nfunc v1OK() int { return 42 }\n")
	if pub.Status != "PUBLISHED" {
		t.Fatalf("expected PUBLISHED, got %q", pub.Status)
	}
	if env.GitHub().PRCount(repo.FullName) != 1 {
		t.Fatalf("expected 1 PR on MockGitHub, got %d", env.GitHub().PRCount(repo.FullName))
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT stage, effect, enforced FROM policy_decisions WHERE proposal_id = %s::uuid ORDER BY created_at DESC LIMIT 1",
		t1pgSQLQuote(pub.ProposalID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query proposal policy_decision: rows=%v err=%v", rows, err)
	}
	if rows[0][0] != "EGRESS" || rows[0][1] != "ALLOW" || (rows[0][2] != "t" && rows[0][2] != "true") {
		t.Fatalf("unexpected v1 EGRESS policy_decision: %+v", rows[0])
	}

	foundWritePush := false
	for _, p := range env.GitHub().PushAttempts() {
		if p.Repo == repo.FullName && p.Allowed && strings.HasPrefix(p.Token, "ghs_write_") && strings.Contains(p.Ref, "custodian/") {
			foundWritePush = true
			break
		}
	}
	if !foundWritePush {
		t.Fatalf("expected publisher ghs_write_* push attempt for custodian/* branch; got %+v", env.GitHub().PushAttempts())
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF6_PublisherProcessAndCredentialIsolation(t *testing.T) {
	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_ = pgAddCommit(t, workDir, map[string]string{"gateway_clean.go": cleanSrc}, nil, "feat: gateway clean push", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	pushRes := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if pushRes.ExitCode != 0 {
		t.Fatalf("gateway push failed: %s", pushRes.Stderr)
	}

	_ = t1pgRunV1PRWorkflow(t, env, repo, actors, "publisher_clean.go", "package main\n\nfunc pubClean() {}\n")

	pubLogs := env.Logs("publisher")
	for _, forbidden := range []string{"panic:", env.Gateway().URL(), env.GitGatewayHTTPSURL(), "CUSTODIAN_GIT_GATEWAY_", "ip_fingerprint"} {
		if forbidden != "" && strings.Contains(pubLogs, forbidden) {
			t.Fatalf("publisher logs contained forbidden marker %q:\n%s", forbidden, pubLogs)
		}
	}

	secrets := []string{
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
		actors.AliceWritePAT,
		actors.HumanATok,
	}
	secrets = append(secrets, env.SSHCA().Secrets()...)
	harness.AssertNoSecretOrEncodedLeak(t, pubLogs, secrets...)
	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.AliceWritePAT)
}

// --- EF7: Hardened Quarantine & Bounds (5 tests) ---

func TestT1_PG_EF7_CleanPushPassesStrictFsckObjects(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_ = pgAddCommit(t, workDir, map[string]string{"strict_fsck.go": cleanSrc}, nil, "feat: clean push for strict fsck", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("clean push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if !push.UpstreamForwarded || !t1pgIsTerminalPushStatus(env, push.Status) {
		t.Fatalf("unexpected push record: %+v", push)
	}

	fsckRes := pgRunHardenedGit(repo.BarePath, nil, "fsck", "--strict", "--full")
	if fsckRes.ExitCode != 0 {
		t.Fatalf("upstream bare repo git fsck --strict --full failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			fsckRes.ExitCode, fsckRes.Stdout, fsckRes.Stderr)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF7_QuarantineIsolatedFromHostGitConfigHooksAndSmudgeFilters(t *testing.T) {
	poisonHome := t.TempDir()
	poisonXDG := t.TempDir()
	poisonConfig := "[core]\n\thooksPath = /nonexistent-failing-hooks\n\tfsmonitor = /bin/false\n[filter \"evil\"]\n\tsmudge = /bin/false\n\tclean = /bin/false\n"
	if err := os.WriteFile(filepath.Join(poisonHome, ".gitconfig"), []byte(poisonConfig), 0o644); err != nil {
		t.Fatalf("write poison .gitconfig: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(poisonXDG, "git"), 0o755); err != nil {
		t.Fatalf("mkdir poison xdg git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(poisonXDG, "git", "config"), []byte(poisonConfig), 0o644); err != nil {
		t.Fatalf("write poison xdg git config: %v", err)
	}

	env, repo, _ := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(harness.WithGitGatewayExtraEnv(map[string]string{
			"HOME":            poisonHome,
			"XDG_CONFIG_HOME": poisonXDG,
		})),
	)
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	tipSHA := pgAddCommit(t, workDir, map[string]string{
		".gitattributes": "*.txt filter=evil\n",
		"notes.txt":      "clean text\n",
		"clean.go":       cleanSrc,
	}, nil, "feat: test quarantine config/hook/filter isolation", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("gateway quarantine was affected by poisoned HOME/XDG gitconfig or filter=evil (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	tree, err := env.Git().InspectTree(repo.FullName, tipSHA)
	if err != nil {
		t.Fatalf("InspectTree(%s): %v", tipSHA, err)
	}
	if tree["notes.txt"] != "clean text\n" {
		t.Fatalf("notes.txt = %q, want %q", tree["notes.txt"], "clean text\n")
	}
	if tree["clean.go"] != cleanSrc {
		t.Fatalf("clean.go content mismatch")
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF7_PushWithinStreamingBoundsSucceeds(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK",
		harness.WithGitGateway(
			harness.WithGitGatewayMaxPackBytes(2<<20),
			harness.WithGitGatewayMaxObjects(200),
			harness.WithGitGatewayMaxInflatedBytes(1<<20),
			harness.WithGitGatewayMaxRefUpdates(4),
		),
	)
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	files := map[string]string{}
	for i := 1; i <= 6; i++ {
		files[fmt.Sprintf("pkg/mod%d/file%d.go", i, i)] = fmt.Sprintf("package mod%d\n\nfunc Value%d() int { return %d }\n", i, i, i)
	}
	tipSHA := pgAddCommit(t, workDir, files, nil, "feat: bounded multi-file commit", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	pushURL, err := pgInjectHTTPAuth(t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth: %v", err)
	}
	res := pgRunHardenedGit(workDir, map[string]string{
		"GIT_SSL_CAINFO": env.GitGatewayCACertPath(),
	}, "push", pushURL, "HEAD:refs/heads/main", "HEAD:refs/heads/feat/bounded")
	if res.ExitCode != 0 {
		t.Fatalf("bounded push failed (exit %d):\nstdout:\n%s\nstderr:\n%s",
			res.ExitCode, res.Stdout, res.Stderr)
	}

	for _, ref := range []string{"refs/heads/main", "refs/heads/feat/bounded"} {
		got, err := env.Git().ResolveRef(repo.FullName, ref)
		if err != nil || got != tipSHA {
			t.Fatalf("ref %s = %q (err=%v), want %q", ref, got, err, tipSHA)
		}
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if !push.UpstreamForwarded {
		t.Fatalf("expected upstream_forwarded=true")
	}
	if len(push.RefUpdates) != 0 && len(push.RefUpdates) != 2 {
		t.Fatalf("expected 2 ref_updates, got %d (%+v)", len(push.RefUpdates), push.RefUpdates)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF7_ZeroFilesSkippedCompleteScanCoverage(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, workDir, map[string]string{
		"pkg/a/a.go":      "package a\n\nfunc A() int { return 1 }\n",
		"pkg/b/b.go":      "package b\n\nfunc B() int { return 2 }\n",
		"docs/readme.txt": "clean documentation\n",
	}, nil, "feat: add 3 clean nested files for scan coverage", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT scanner, status, COALESCE((coverage->>'files_examined')::int, 0), COALESCE((coverage->>'files_skipped')::int, -1), COALESCE((coverage->>'complete')::boolean, false)
		 FROM scan_runs WHERE push_session_id = %s::uuid ORDER BY scanner`,
		t1pgSQLQuote(push.ID),
	))
	if err != nil {
		t.Fatalf("query scan_runs coverage: %v", err)
	}
	if len(rows) < 4 {
		t.Fatalf("expected >= 4 scan_run rows for push %s, got %d (%+v)", push.ID, len(rows), rows)
	}

	seen := make(map[string]bool)
	for _, r := range rows {
		scanner, status, examined, skipped, complete := r[0], r[1], r[2], r[3], r[4]
		seen[scanner] = true
		if status != "COMPLETED" {
			t.Fatalf("scanner %s status = %q, want COMPLETED", scanner, status)
		}
		if skipped != "0" {
			t.Fatalf("scanner %s files_skipped = %q, want 0", scanner, skipped)
		}
		if complete != "t" && complete != "true" {
			t.Fatalf("scanner %s coverage.complete = %q, want true", scanner, complete)
		}
		if examined == "0" {
			t.Fatalf("scanner %s files_examined = 0, expected >= 3", scanner)
		}
	}
	for _, mandatory := range []string{"gitleaks", "scancode", "semgrep", "custom"} {
		if !seen[mandatory] {
			t.Fatalf("missing mandatory scan_run for scanner %q (seen=%v)", mandatory, seen)
		}
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF7_CleanNonExecutableRegularFilesPassPathValidation(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	files := map[string]string{
		"src/service/handler.go": "package service\n\nfunc Handle() string { return \"ok\" }\n",
		"config/settings.json":   "{\"timeout_ms\": 2500}\n",
		"docs/notes.md":          "# Notes\nClean regular files.\n",
	}
	tipSHA := pgAddCommit(t, workDir, files, nil, "feat: clean nested regular files", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("clean regular files push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.Status == "QUARANTINED" || !push.UpstreamForwarded {
		t.Fatalf("expected non-quarantined forwarded push, got %+v", push)
	}

	tree, err := env.Git().InspectTree(repo.FullName, tipSHA)
	if err != nil {
		t.Fatalf("InspectTree(%s): %v", tipSHA, err)
	}
	for k, want := range files {
		if tree[k] != want {
			t.Fatalf("upstream file %q = %q, want %q", k, tree[k], want)
		}
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

// --- EF8: History Extraction, Bundle & Manifest Digest (5 tests) ---

func TestT1_PG_EF8_MultiCommitRangeOldToNewEnumerated(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	oldOID := repo.HeadSHA

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}
	_ = pgAddCommit(t, workDir, map[string]string{"step1.go": "package main\nfunc s1() {}\n"}, nil, "commit 1", author)
	_ = pgAddCommit(t, workDir, map[string]string{"step2.go": "package main\nfunc s2() {}\n"}, nil, "commit 2", author)
	c3 := pgAddCommit(t, workDir, map[string]string{"step3.go": "package main\nfunc s3() {}\n"}, nil, "commit 3", author)

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("multi-commit push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.CommitCount != 0 && push.CommitCount != 3 {
		t.Fatalf("push.CommitCount = %d, want 3", push.CommitCount)
	}
	if len(push.RefUpdates) > 0 {
		matched := false
		for _, ru := range push.RefUpdates {
			if ru.RefName == "refs/heads/main" && ru.OldOID == oldOID && ru.NewOID == c3 {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("expected ref_update refs/heads/main %s..%s, got %+v", oldOID, c3, push.RefUpdates)
		}
	}

	revCount := pgRunHardenedGit(repo.BarePath, nil, "rev-list", "--count", oldOID+".."+c3)
	if revCount.ExitCode != 0 || strings.TrimSpace(revCount.Stdout) != "3" {
		t.Fatalf("upstream rev-list --count %s..%s = %q (err=%s), want 3", oldOID, c3, strings.TrimSpace(revCount.Stdout), revCount.Stderr)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF8_GitPushBundleArtifactStoredInDBAndSnapshotStore(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_ = pgAddCommit(t, workDir, map[string]string{"bundle_check.go": cleanSrc}, nil, "feat: bundle artifact check", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("push failed (exit %d): %s", res.ExitCode, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	harness.AssertUUIDv7(t, push.BundleArtifactID)

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT id::text, kind, sha256, storage_key, size_bytes FROM artifacts WHERE id = %s::uuid",
		t1pgSQLQuote(push.BundleArtifactID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query artifacts for bundle %s: rows=%v err=%v", push.BundleArtifactID, rows, err)
	}
	if rows[0][1] != "GIT_PUSH_BUNDLE" {
		t.Fatalf("artifact kind = %q, want GIT_PUSH_BUNDLE", rows[0][1])
	}
	sha := rows[0][2]
	if !t1pgIsHex64(sha) {
		t.Fatalf("artifact sha256 = %q, want 64 lower hex", sha)
	}

	obj, err := env.Snapshots().FindBySHA256(sha)
	if err != nil {
		t.Fatalf("Snapshots().FindBySHA256(%s): %v", sha, err)
	}
	rawBytes, err := env.Snapshots().ReadBytes(*obj)
	if err != nil || len(rawBytes) == 0 {
		t.Fatalf("ReadBytes(%s): len=%d err=%v", obj.RelPath, len(rawBytes), err)
	}
	if fmt.Sprintf("%d", obj.SizeBytes) != rows[0][4] {
		t.Fatalf("snapshot size %d != DB artifact size_bytes %s", obj.SizeBytes, rows[0][4])
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF8_PushManifestDigest64HexAndDeterministic(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef8-confidential", "CONFIDENTIAL", t1pgConfidentialCorpusFiles(t))

	billingSrc := t1pgReadQuarantineFixture(t, "corpora", "confidential", "internal_billing_rules.go")
	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, workDir, map[string]string{"billing.go": billingSrc}, nil, "feat: confidential billing rules", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res1 := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res1.ExitCode == 0 {
		t.Fatalf("expected confidential push to require approval")
	}
	pushes1 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)

	res2 := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res2.ExitCode == 0 {
		t.Fatalf("expected identical re-push without approval to still require approval")
	}
	pushes2 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)

	d1 := pushes1[0].PushManifestDigest
	d2 := pushes2[0].PushManifestDigest
	if pushes2[0].ID == pushes1[0].ID {
		t.Fatalf("expected two distinct push_session IDs, both were %s", pushes1[0].ID)
	}
	if !t1pgIsHex64(d1) || !t1pgIsHex64(d2) {
		t.Fatalf("expected 64-hex push_manifest_digest values, got d1=%q d2=%q", d1, d2)
	}
	if d1 != d2 {
		t.Fatalf("expected deterministic push_manifest_digest for identical unamended push: %q != %q", d1, d2)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF8_PushManifestDigestChangesWhenBlobOrCommitChanges(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}

	// Push 1: baseline blob + msg A.
	wd1 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, wd1, map[string]string{"data.txt": "alpha\n"}, nil, "commit A", author)
	if res := pgGitPushHTTP(t, wd1, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/feat-a", env.GitGatewayCACertPath()); res.ExitCode != 0 {
		t.Fatalf("push 1 failed: %s", res.Stderr)
	}
	p1 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)[0]

	// Push 2: 1-byte blob change + same msg A.
	wd2 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, wd2, map[string]string{"data.txt": "alphb\n"}, nil, "commit A", author)
	if res := pgGitPushHTTP(t, wd2, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/feat-b", env.GitGatewayCACertPath()); res.ExitCode != 0 {
		t.Fatalf("push 2 failed: %s", res.Stderr)
	}
	p2 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)[0]

	// Push 3: same blob as push 1 + different commit message B.
	wd3 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, wd3, map[string]string{"data.txt": "alpha\n"}, nil, "commit B", author)
	if res := pgGitPushHTTP(t, wd3, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/feat-c", env.GitGatewayCACertPath()); res.ExitCode != 0 {
		t.Fatalf("push 3 failed: %s", res.Stderr)
	}
	p3 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 3, 20*time.Second)[0]

	if !t1pgIsHex64(p1.PushManifestDigest) || !t1pgIsHex64(p2.PushManifestDigest) || !t1pgIsHex64(p3.PushManifestDigest) {
		t.Fatalf("expected 64-hex digests, got %q / %q / %q", p1.PushManifestDigest, p2.PushManifestDigest, p3.PushManifestDigest)
	}
	if p1.PushManifestDigest == p2.PushManifestDigest {
		t.Fatalf("expected digest to change on 1-byte blob modification, both=%q", p1.PushManifestDigest)
	}
	if p1.PushManifestDigest == p3.PushManifestDigest {
		t.Fatalf("expected digest to change on commit/ref change, both=%q", p1.PushManifestDigest)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

func TestT1_PG_EF8_CommitMessageExtractionInspected(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)

	// Control: clean file + clean commit message -> ALLOW.
	wd1 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_ = pgAddCommit(t, wd1, map[string]string{"clean.go": cleanSrc}, nil, "feat: add clean greeting helper", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	if res := pgGitPushHTTP(t, wd1, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath()); res.ExitCode != 0 {
		t.Fatalf("clean control push failed: %s", res.Stderr)
	}

	// Secret placed ONLY in commit message, file content itself is completely benign.
	const canarySecret = "AKIAIOSFODNN7EXAMPLE"
	env.RegisterSecret(canarySecret)
	wd2 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	_ = pgAddCommit(t, wd2, map[string]string{"benign.txt": "hello\n"}, nil, "chore: debug "+canarySecret+" credential", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, wd2, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected push with AWS key in commit message to be blocked")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pushes := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)
	blocked := pushes[0]
	if blocked.Status != "BLOCKED" && blocked.Status != "DENIED" {
		t.Fatalf("expected BLOCKED or DENIED status, got %q", blocked.Status)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT f.category, f.severity FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid",
		t1pgSQLQuote(blocked.ID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("expected SECRET finding from extracted commit message, rows=%v err=%v", rows, err)
	}
	foundSecret := false
	for _, r := range rows {
		if r[0] == "SECRET" {
			foundSecret = true
			break
		}
	}
	if !foundSecret {
		t.Fatalf("expected SECRET finding category in %+v", rows)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, canarySecret)
}

// --- EF9: Deterministic IP Fingerprinting (L1–L4) & Concealment Detection (6 tests) ---

func TestT1_PG_EF9_L1ExactChunkSHA256MatchAgainstRestrictedCorpus(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef9-l1-restricted", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")
	_ = pgAddCommit(t, workDir, map[string]string{"copied_engine.go": restrictedSrc}, nil, "feat: exact restricted IP copy", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected L1 exact restricted IP match to block push")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.PolicyEffect != "DENY" || (push.Status != "BLOCKED" && push.Status != "DENIED") {
		t.Fatalf("expected DENY / BLOCKED, got effect=%q status=%q", push.PolicyEffect, push.Status)
	}

	srRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT status, COALESCE((coverage->>'files_skipped')::int, -1) FROM scan_runs WHERE push_session_id = %s::uuid AND scanner = 'ip_fingerprint'",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(srRows) == 0 || srRows[0][0] != "COMPLETED" || srRows[0][1] != "0" {
		t.Fatalf("expected completed ip_fingerprint scan_run with 0 files_skipped, got rows=%v err=%v", srRows, err)
	}

	fRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COALESCE(f.scanner,''), f.rule_id, f.category FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid AND (f.scanner = 'ip_fingerprint' OR sr.scanner = 'ip_fingerprint')",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(fRows) == 0 {
		t.Fatalf("expected >= 1 ip_fingerprint finding for L1 match, got rows=%v err=%v", fRows, err)
	}

	pgAssertNoRawCorpusLeak(t, env, t1pgRestrictedSensitiveSnippets()...)
}

func TestT1_PG_EF9_L2WinnowingMatchWithRenamedIdentifiers(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef9-l2-restricted", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	renamedSrc := t1pgReadQuarantineFixture(t, "payloads", "stripped_header_engine.go")
	_ = pgAddCommit(t, workDir, map[string]string{"renamed_processor.go": renamedSrc}, nil, "feat: renamed identifier engine", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected L2 Winnowing + L3 stripped-header match to block push")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.PolicyEffect != "DENY" {
		t.Fatalf("expected PolicyEffect=DENY, got %q", push.PolicyEffect)
	}

	fRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COALESCE(f.rule_id,''), COALESCE(f.metadata::text,'') FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid AND (f.scanner = 'ip_fingerprint' OR sr.scanner = 'ip_fingerprint')",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(fRows) == 0 {
		t.Fatalf("expected ip_fingerprint findings for renamed payload, got rows=%v err=%v", fRows, err)
	}
	foundWinnow := false
	for _, r := range fRows {
		joined := strings.ToLower(r[0] + " " + r[1])
		if strings.Contains(joined, "winnow") || strings.Contains(joined, "l2") {
			foundWinnow = true
			break
		}
	}
	if !foundWinnow {
		t.Fatalf("expected L2 winnowing indicator in ip_fingerprint findings, got %+v", fRows)
	}

	pgAssertNoRawCorpusLeak(t, env, t1pgRestrictedSensitiveSnippets()...)
}

func TestT1_PG_EF9_L3CopyrightMarkerAndStrippedHeaderMatch(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef9-l3-restricted", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	// Case A: Proprietary copyright / confidentiality marker only.
	wd1 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	markerSrc := t1pgReadQuarantineFixture(t, "payloads", "copyright_marker_only.txt")
	_ = pgAddCommit(t, wd1, map[string]string{"NOTICE.txt": markerSrc}, nil, "feat: proprietary marker text", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	res1 := pgGitPushHTTP(t, wd1, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res1.ExitCode == 0 {
		t.Fatalf("expected L3 copyright/confidentiality marker push to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pushes1 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)
	fRows1, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COALESCE(f.rule_id,''), COALESCE(f.metadata::text,'') FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid AND (f.scanner = 'ip_fingerprint' OR sr.scanner = 'ip_fingerprint')",
		t1pgSQLQuote(pushes1[0].ID),
	))
	if err != nil || len(fRows1) == 0 {
		t.Fatalf("expected ip_fingerprint L3 marker finding, rows=%v err=%v", fRows1, err)
	}

	// Case B: Stripped copyright header on matching engine body.
	wd2 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	strippedSrc := t1pgReadQuarantineFixture(t, "payloads", "stripped_header_engine.go")
	_ = pgAddCommit(t, wd2, map[string]string{"stripped.go": strippedSrc}, nil, "feat: stripped header engine", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	env.GitHub().ResetPacketCounters()
	res2 := pgGitPushHTTP(t, wd2, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res2.ExitCode == 0 {
		t.Fatalf("expected L3 stripped header push to be blocked")
	}
	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	pushes2 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)
	if pushes2[0].PolicyEffect != "DENY" {
		t.Fatalf("expected DENY on stripped header push, got %q", pushes2[0].PolicyEffect)
	}

	pgAssertNoRawCorpusLeak(t, env, t1pgRestrictedSensitiveSnippets()...)
}

func TestT1_PG_EF9_L4ConcealmentBase64PayloadDetected(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef9-l4-b64", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	b64Src := t1pgReadQuarantineFixture(t, "payloads", "concealed_base64.txt")
	_ = pgAddCommit(t, workDir, map[string]string{"wrapper.txt": b64Src}, nil, "feat: encoded base64 payload", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected L4 base64 concealed payload to be quarantined/blocked")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.Status != "QUARANTINED" && push.Status != "BLOCKED" && push.Status != "DENIED" {
		t.Fatalf("expected QUARANTINED/BLOCKED/DENIED status, got %q", push.Status)
	}

	fRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COALESCE(f.rule_id,''), COALESCE(f.category,''), COALESCE(f.metadata::text,'') FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(fRows) == 0 {
		t.Fatalf("expected concealment finding in DB, rows=%v err=%v", fRows, err)
	}
	foundConcealment := false
	for _, r := range fRows {
		txt := strings.ToLower(r[0] + " " + r[1] + " " + r[2])
		if strings.Contains(txt, "conceal") || strings.Contains(txt, "base64") || strings.Contains(txt, "smuggl") || strings.Contains(txt, "l4") {
			foundConcealment = true
			break
		}
	}
	if !foundConcealment {
		t.Fatalf("expected concealment/base64 finding metadata, got %+v", fRows)
	}

	pgAssertNoRawCorpusLeak(t, env, t1pgRestrictedSensitiveSnippets()...)
}

func TestT1_PG_EF9_L4NestedArchivePayloadDetected(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef9-l4-archive", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	zipBytes := t1pgReadQuarantineFixtureBytes(t, "payloads", "concealed_nested.zip")
	if err := os.WriteFile(filepath.Join(workDir, "bundle.zip"), zipBytes, 0o644); err != nil {
		t.Fatalf("write concealed_nested.zip: %v", err)
	}
	if addRes := pgRunHardenedGit(workDir, nil, "add", "bundle.zip"); addRes.ExitCode != 0 {
		t.Fatalf("git add bundle.zip: %s", addRes.Stderr)
	}
	if cRes := pgRunHardenedGit(workDir, map[string]string{
		"GIT_AUTHOR_NAME":     "Alice Developer",
		"GIT_AUTHOR_EMAIL":    "alice@example.com",
		"GIT_COMMITTER_NAME":  "Alice Developer",
		"GIT_COMMITTER_EMAIL": "alice@example.com",
	}, "commit", "-m", "feat: add nested archive"); cRes.ExitCode != 0 {
		t.Fatalf("git commit bundle.zip: %s", cRes.Stderr)
	}

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected nested archive payload to be quarantined/blocked")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.Status != "QUARANTINED" && push.Status != "BLOCKED" && push.Status != "DENIED" {
		t.Fatalf("expected QUARANTINED/BLOCKED/DENIED status, got %q", push.Status)
	}

	fRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COALESCE(f.rule_id,''), COALESCE(f.category,''), COALESCE(f.metadata::text,'') FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(fRows) == 0 {
		t.Fatalf("expected nested archive finding in DB, rows=%v err=%v", fRows, err)
	}

	pgAssertNoRawCorpusLeak(t, env, t1pgRestrictedSensitiveSnippets()...)
}

func TestT1_PG_EF9_CleanFeaturePassesAllIPFingerprintLayers(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef9-clean-pass", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	cleanSrc := t1pgReadQuarantineFixture(t, "payloads", "clean_feature.go")
	_ = pgAddCommit(t, workDir, map[string]string{"clean_feature.go": cleanSrc}, nil, "feat: clean feature passes L1-L4", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode != 0 {
		t.Fatalf("clean feature push failed (exit %d):\nstdout:\n%s\nstderr:\n%s", res.ExitCode, res.Stdout, res.Stderr)
	}

	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.PolicyEffect != "ALLOW" || !push.UpstreamForwarded {
		t.Fatalf("expected ALLOW and upstream_forwarded=true, got %+v", push)
	}

	fRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COUNT(*) FROM findings f JOIN scan_runs sr ON sr.id = f.scan_run_id WHERE sr.push_session_id = %s::uuid",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(fRows) == 0 || fRows[0][0] != "0" {
		t.Fatalf("expected 0 findings for clean push, got rows=%v err=%v", fRows, err)
	}
	srRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT status, COALESCE((coverage->>'files_skipped')::int, -1) FROM scan_runs WHERE push_session_id = %s::uuid AND scanner = 'ip_fingerprint'",
		t1pgSQLQuote(push.ID),
	))
	if err != nil || len(srRows) == 0 || srRows[0][0] != "COMPLETED" || srRows[0][1] != "0" {
		t.Fatalf("expected completed ip_fingerprint scan_run with 0 skipped, got rows=%v err=%v", srRows, err)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok)
}

// --- EF10: One-Way IP Corpora & Zero Raw Leak (5 tests) ---

func TestT1_PG_EF10_RegisterRestrictedCorpusViaAPI(t *testing.T) {
	env := pgNewEnv(t)
	actors := pgMintActors(env)

	corpusID := pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef10-restricted-corpus", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listResp, raw, err := actors.SecAdminCli.ListIPCorpora(ctx, harness.IPCorpusFilter{
		Classification: "RESTRICTED",
		Limit:          50,
	})
	if err != nil {
		t.Fatalf("ListIPCorpora: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	var found *harness.IPCorpusResp
	for i := range listResp.Corpora {
		if listResp.Corpora[i].ID == corpusID {
			found = &listResp.Corpora[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("created corpus %s missing from ListIPCorpora: %+v", corpusID, listResp.Corpora)
	}
	if found.Classification != "RESTRICTED" || found.Status != "READY" || found.FingerprintCount <= 0 {
		t.Fatalf("unexpected corpus state: %+v", *found)
	}

	env.AssertNoSecretLeakInLogs(actors.SecAdminTok)
}

func TestT1_PG_EF10_RegisterConfidentialCorpusTriggersReviewNotDeny(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	corpusID := pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef10-confidential-corpus", "CONFIDENTIAL", t1pgConfidentialCorpusFiles(t))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listResp, raw, err := actors.SecAdminCli.ListIPCorpora(ctx, harness.IPCorpusFilter{Classification: "CONFIDENTIAL"})
	if err != nil {
		t.Fatalf("ListIPCorpora: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	var ready bool
	for _, c := range listResp.Corpora {
		if c.ID == corpusID && c.Status == "READY" && c.FingerprintCount > 0 {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatalf("CONFIDENTIAL corpus %s not READY with fingerprints > 0: %+v", corpusID, listResp.Corpora)
	}

	workDir := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	confSrc := t1pgReadQuarantineFixture(t, "corpora", "confidential", "internal_billing_rules.go")
	_ = pgAddCommit(t, workDir, map[string]string{"billing_rules.go": confSrc}, nil, "feat: confidential billing code", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})

	env.GitHub().ResetPacketCounters()
	res := pgGitPushHTTP(t, workDir, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res.ExitCode == 0 {
		t.Fatalf("expected CONFIDENTIAL IP match to require approval rather than pass")
	}

	pgAssertZeroUpstreamReceivePack(t, env, repo.FullName)
	push := t1pgWaitLatestPush(t, env, actors.HumanACli, repoID, 20*time.Second)
	if push.PolicyEffect != "REQUIRE_APPROVAL" {
		t.Fatalf("expected PolicyEffect=REQUIRE_APPROVAL for CONFIDENTIAL corpus match (not DENY), got %q (status=%q)", push.PolicyEffect, push.Status)
	}
	if push.Status != "APPROVAL_REQUIRED" && push.Status != "REQUIRE_APPROVAL" {
		t.Fatalf("expected APPROVAL_REQUIRED status, got %q", push.Status)
	}

	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.SecAdminTok)
}

func TestT1_PG_EF10_ReindexCorpusProducesIdempotentFingerprints(t *testing.T) {
	env := pgNewEnv(t)
	actors := pgMintActors(env)

	corpusID := pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef10-idempotent-reindex", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	countRows1, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COUNT(*) FROM ip_fingerprints WHERE corpus_id = %s::uuid",
		t1pgSQLQuote(corpusID),
	))
	if err != nil || len(countRows1) == 0 || countRows1[0][0] == "0" {
		t.Fatalf("expected > 0 fingerprints after 1st index, got rows=%v err=%v", countRows1, err)
	}
	layerRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT DISTINCT layer FROM ip_fingerprints WHERE corpus_id = %s::uuid",
		t1pgSQLQuote(corpusID),
	))
	if err != nil {
		t.Fatalf("query distinct layers: %v", err)
	}
	layers := make(map[string]bool)
	for _, r := range layerRows {
		layers[r[0]] = true
	}
	for _, wantLayer := range []string{"L1_EXACT_CHUNK", "L2_WINNOW_KGRAM", "L3_HEADER_MARKER"} {
		if !layers[wantLayer] {
			t.Fatalf("expected layer %q in ip_fingerprints, got %v", wantLayer, layers)
		}
	}

	// Second reindex with Force=true must be idempotent.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reResp, rRaw, err := actors.SecAdminCli.ReindexIPCorpus(ctx, corpusID, harness.ReindexIPCorpusReq{Force: true})
	if err != nil {
		t.Fatalf("2nd ReindexIPCorpus: %v", err)
	}
	rRaw.RequireAnyStatus(t, http.StatusOK, http.StatusAccepted)
	if reResp.OperationID != "" {
		op, err := actors.SecAdminCli.WaitForOperation(ctx, reResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(2nd reindex): %v", err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("2nd reindex failed: %+v", op)
		}
	}

	countRows2, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT COUNT(*) FROM ip_fingerprints WHERE corpus_id = %s::uuid",
		t1pgSQLQuote(corpusID),
	))
	if err != nil || len(countRows2) == 0 {
		t.Fatalf("query 2nd count: rows=%v err=%v", countRows2, err)
	}
	if countRows2[0][0] != countRows1[0][0] {
		t.Fatalf("reindex was not idempotent: count1=%s count2=%s", countRows1[0][0], countRows2[0][0])
	}

	env.AssertNoSecretLeakInLogs(actors.SecAdminTok)
}

func TestT1_PG_EF10_IPFingerprintsDBStoresOnlyOneWayHashesZeroRawSource(t *testing.T) {
	env := pgNewEnv(t)
	actors := pgMintActors(env)
	corpusID := pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef10-oneway-hashes", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT id::text, layer, fingerprint_hash, COALESCE(file_path_hash,''), COALESCE(language,''), COALESCE(metadata::text,'') FROM ip_fingerprints WHERE corpus_id = %s::uuid",
		t1pgSQLQuote(corpusID),
	))
	if err != nil || len(rows) == 0 {
		t.Fatalf("query ip_fingerprints: rows=%v err=%v", rows, err)
	}

	var dump strings.Builder
	for _, r := range rows {
		fpHash := r[2]
		pathHash := r[3]
		meta := r[5]
		if !t1pgIsLowerHexRange(fpHash, 16, 64) {
			t.Fatalf("fingerprint_hash %q is not 16-64 lowercase hex", fpHash)
		}
		if pathHash != "" && !t1pgIsHex64(pathHash) {
			t.Fatalf("file_path_hash %q is not 64-hex SHA-256", pathHash)
		}
		lowerMeta := strings.ToLower(meta)
		for _, forbiddenKey := range []string{"raw_source", "raw_code", "source_text", "match_raw"} {
			if strings.Contains(lowerMeta, forbiddenKey) {
				t.Fatalf("ip_fingerprints.metadata contained forbidden raw-source key %q: %s", forbiddenKey, meta)
			}
		}
		dump.WriteString(strings.Join(r, "\t"))
		dump.WriteByte('\n')
	}

	corpRows, err := env.DB().QueryRows(fmt.Sprintf(
		"SELECT id::text, name, classification, COALESCE(description,''), COALESCE(source_ref,''), COALESCE(last_error,'') FROM ip_fingerprint_corpora WHERE id = %s::uuid",
		t1pgSQLQuote(corpusID),
	))
	if err != nil {
		t.Fatalf("query ip_fingerprint_corpora: %v", err)
	}
	for _, r := range corpRows {
		dump.WriteString(strings.Join(r, "\t"))
		dump.WriteByte('\n')
	}

	dumpStr := dump.String()
	if strings.Contains(dumpStr, "proprietary_engine.go") || strings.Contains(dumpStr, "proprietary_header.py") {
		t.Fatalf("raw corpus filenames leaked into ip_fingerprints / ip_fingerprint_corpora DB dump")
	}
	harness.AssertNoSecretOrEncodedLeak(t, dumpStr, t1pgRestrictedSensitiveSnippets()...)
	env.AssertNoSecretLeakInLogs(actors.SecAdminTok)
}

func TestT1_PG_EF10_ZeroRawRestrictedSourceLeakInHTTPFindingsAndLogs(t *testing.T) {
	env, repo, repoID := pgNewEnvWithSeededRepo(t, "ENFORCE_BLOCK")
	actors := pgMintActors(env)
	corpusID := pgSeedCorpusFiles(t, env, actors.SecAdminTok, "ef10-zero-leak-surfaces", "RESTRICTED", t1pgRestrictedCorpusFiles(t))

	audTok := env.MintToken(harness.TokenClaims{
		Kind:    "AUDITOR",
		Subject: "ef10-auditor-001",
		Email:   "ef10-auditor@example.com",
		Groups:  []string{"audit-readers"},
	})
	audCli := env.Client(audTok)

	// Push 1: Raw restricted source.
	wd1 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	restrictedSrc := t1pgReadQuarantineFixture(t, "corpora", "restricted", "proprietary_engine.go")
	_ = pgAddCommit(t, wd1, map[string]string{"exfil_raw.go": restrictedSrc}, nil, "feat: test zero raw leak on block", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	res1 := pgGitPushHTTP(t, wd1, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res1.ExitCode == 0 {
		t.Fatalf("expected restricted push to be blocked")
	}
	p1 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 1, 20*time.Second)[0]
	t1pgAssertNoRawLeakOnAllSurfaces(t, env, actors.SecAdminCli, audCli, p1.ID, corpusID, res1.Stderr, t1pgRestrictedSensitiveSnippets()...)

	// Push 2: Concealed base64 restricted source.
	wd2 := t1pgCloneGatewayRepo(t, env, repo.FullName, actors.HumanATok)
	b64Src := t1pgReadQuarantineFixture(t, "payloads", "concealed_base64.txt")
	_ = pgAddCommit(t, wd2, map[string]string{"exfil_b64.txt": b64Src}, nil, "feat: test zero raw leak on quarantine", harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"})
	res2 := pgGitPushHTTP(t, wd2, t1pgGatewayRepoURL(env, repo.FullName), actors.HumanATok, "HEAD:refs/heads/main", env.GitGatewayCACertPath())
	if res2.ExitCode == 0 {
		t.Fatalf("expected concealed base64 push to be quarantined/blocked")
	}
	p2 := t1pgWaitPushCount(t, env, actors.HumanACli, repoID, 2, 20*time.Second)[0]
	t1pgAssertNoRawLeakOnAllSurfaces(t, env, actors.SecAdminCli, audCli, p2.ID, corpusID, res2.Stderr, t1pgRestrictedSensitiveSnippets()...)

	env.AssertNoSecretLeakInLogs(actors.HumanATok, actors.SecAdminTok, audTok)
}
