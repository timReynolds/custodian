package e2e_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

type pgActorSet struct {
	HumanATok      string
	HumanACli      *harness.APIClient
	HumanBTok      string
	HumanBCli      *harness.APIClient
	SecAdminTok    string
	SecAdminCli    *harness.APIClient
	AuditorTok     string
	AuditorCli     *harness.APIClient
	PolicyAdminTok string
	PolicyAdminCli *harness.APIClient
	CtrlTok        string
	CtrlCli        *harness.APIClient
	AliceWritePAT  string
	BobReadPAT     string
}

type pgGitResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

func pgFindRepoRoot(t testing.TB) string {
	t.Helper()
	if envRoot := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_ROOT")); envRoot != "" {
		return envRoot
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	cur := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			if _, err2 := os.Stat(filepath.Join(cur, "test", "e2e", "run_e2e.sh")); err2 == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	t.Fatalf("unable to locate repository root from %q", wd)
	return ""
}

func pgRequireGatewayBinary(t testing.TB) string {
	t.Helper()
	root := pgFindRepoRoot(t)
	gwName := harness.DefaultContracts().Binaries.GitGateway
	if gwName == "" {
		gwName = harness.PushGatewayBinary
	}
	binDir := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_BIN_DIR"))
	if !harness.HasBinary(root, binDir, gwName) {
		t.Fatalf("custodian-git-gateway binary not built yet (requires M4)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binPath, err := harness.BuildPushGatewayBinary(ctx, "", root, "", binDir, harness.DefaultContracts().Binaries)
	if err != nil {
		t.Fatalf("BuildPushGatewayBinary(%q): %v", gwName, err)
	}
	return binPath
}

func pgPolicyDirWithDefaults(t testing.TB, extraFiles map[string]string) string {
	t.Helper()
	root := pgFindRepoRoot(t)
	dir := t.TempDir()

	defaults := []struct {
		src string
		dst string
	}{
		{
			src: filepath.Join(root, "test", "e2e", "fixtures", "policies", "valid_default.yaml"),
			dst: "valid_default.yaml",
		},
		{
			src: filepath.Join(root, "test", "e2e", "fixtures", "push_gateway", "policies", "push_ip_protection_default.yaml"),
			dst: "push_ip_protection_default.yaml",
		},
	}
	for _, f := range defaults {
		data, err := os.ReadFile(f.src)
		if err != nil {
			t.Fatalf("read default policy fixture %q: %v", f.src, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.dst), data, 0o644); err != nil {
			t.Fatalf("write temp policy %q: %v", f.dst, err)
		}
	}
	for name, content := range extraFiles {
		target := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir policy dir for %q: %v", name, err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatalf("write extra policy %q: %v", name, err)
		}
	}
	return dir
}

func pgNewEnv(t *testing.T, opts ...harness.EnvOption) *harness.Env {
	t.Helper()
	pgRequireGatewayBinary(t)
	merged := []harness.EnvOption{
		harness.WithRepoRoot(pgFindRepoRoot(t)),
		harness.WithPolicyBundleDir(pgPolicyDirWithDefaults(t, nil)),
		harness.WithGitGateway(),
	}
	merged = append(merged, opts...)
	return harness.NewEnv(t, merged...)
}

func pgNewEnvWithSeededRepo(t *testing.T, mode string, opts ...harness.EnvOption) (*harness.Env, harness.SeededRepo, string) {
	t.Helper()
	seedSpec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "service",
		DefaultBranch: "main",
		Files: map[string]string{
			"README.md": "# acme/service\n",
			"main.go":   "package main\n\nfunc main() {}\n",
		},
	}
	allOpts := make([]harness.EnvOption, 0, len(opts)+1)
	allOpts = append(allOpts, harness.WithSeedRepos(seedSpec))
	allOpts = append(allOpts, opts...)

	env := pgNewEnv(t, allOpts...)
	repo, ok := env.Git().Repo("acme/service")
	if !ok {
		t.Fatalf("seeded repo acme/service missing from BareGitHelper")
	}

	repoID := harness.NewTestUUIDv7()
	q := fmt.Sprintf(
		`INSERT INTO repositories (id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations)
		 VALUES ('%s'::uuid, %d, %d, '%s', 'INTERNAL', true, ARRAY['approved-code-review']::text[], 10);`,
		repoID, repo.GitHubRepoID, repo.InstallationID, strings.ReplaceAll(repo.FullName, "'", "''"),
	)
	if _, err := env.DB().ExecSQL(q); err != nil {
		t.Fatalf("seed repository in DB: %v", err)
	}

	if mode != "" {
		adminTok := env.MintToken(harness.TokenClaims{
			Kind:    "HUMAN",
			Subject: "pg-seed-admin",
			Email:   "admin@example.com",
			Groups:  []string{"security-admins", "policy-admins"},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, raw, err := env.Client(adminTok).SetRepoEgressMode(ctx, repoID, harness.SetRepoEgressModeReq{
			EgressMode: mode,
		})
		if err != nil {
			t.Fatalf("SetRepoEgressMode(%s): %v", mode, err)
		}
		raw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	}
	return env, repo, repoID
}

func pgMintActors(env *harness.Env) pgActorSet {
	humanATok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "alice-human-001",
		Name:    "Alice Developer",
		Email:   "alice@example.com",
		Groups:  []string{"engineering"},
	})
	humanBTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "bob-human-002",
		Name:    "Bob Developer",
		Email:   "bob@example.com",
		Groups:  []string{"engineering"},
	})
	secAdminTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "sec-admin-003",
		Name:    "Carol Security",
		Email:   "carol@example.com",
		Groups:  []string{"engineering", "ip-review", "security-admins"},
	})
	auditorTok := env.MintToken(harness.TokenClaims{
		Kind:    "AUDITOR",
		Subject: "auditor-004",
		Name:    "Dave Auditor",
		Email:   "dave@example.com",
		Groups:  []string{"audit-readers"},
	})
	policyAdminTok := env.MintToken(harness.TokenClaims{
		Kind:    "POLICY_ADMIN",
		Subject: "policy-admin-005",
		Name:    "Eve Policy",
		Email:   "eve@example.com",
		Groups:  []string{"policy-admins", "security-admins"},
	})
	ctrlTok := env.MintToken(harness.TokenClaims{
		Kind:    "CONTROLLER",
		Subject: "controller-001",
	})

	const (
		alicePAT = "gho_alice_write_e2e_token"
		bobPAT   = "gho_bob_read_e2e_token"
	)
	env.GitHub().RegisterUserToken(alicePAT, true)
	env.GitHub().RegisterUserToken(bobPAT, false)
	env.RegisterSecret(alicePAT)
	env.RegisterSecret(bobPAT)

	return pgActorSet{
		HumanATok:      humanATok,
		HumanACli:      env.Client(humanATok),
		HumanBTok:      humanBTok,
		HumanBCli:      env.Client(humanBTok),
		SecAdminTok:    secAdminTok,
		SecAdminCli:    env.Client(secAdminTok),
		AuditorTok:     auditorTok,
		AuditorCli:     env.Client(auditorTok),
		PolicyAdminTok: policyAdminTok,
		PolicyAdminCli: env.Client(policyAdminTok),
		CtrlTok:        ctrlTok,
		CtrlCli:        env.Client(ctrlTok),
		AliceWritePAT:  alicePAT,
		BobReadPAT:     bobPAT,
	}
}

func pgRunHardenedGit(dir string, extraEnv map[string]string, args ...string) pgGitResult {
	fullArgs := append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false"}, args...)
	cmd := exec.Command("git", fullArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	envMap := map[string]string{
		"PATH":                os.Getenv("PATH"),
		"HOME":                os.Getenv("HOME"),
		"TMPDIR":              os.Getenv("TMPDIR"),
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_TERMINAL_PROMPT": "0",
	}
	for k, v := range extraEnv {
		envMap[k] = v
	}
	cmdEnv := make([]string, 0, len(envMap))
	for k, v := range envMap {
		cmdEnv = append(cmdEnv, k+"="+v)
	}
	cmd.Env = cmdEnv

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return pgGitResult{
		ExitCode: code,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
}

func pgCreateGitRepoWithFiles(t testing.TB, files map[string]string, msg string, author harness.GitIdentity) string {
	t.Helper()
	workDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir git repo %q: %v", workDir, err)
	}
	if res := pgRunHardenedGit(workDir, nil, "init", "--initial-branch=main"); res.ExitCode != 0 {
		if res2 := pgRunHardenedGit(workDir, nil, "init"); res2.ExitCode != 0 {
			t.Fatalf("git init failed: %s", res2.Stderr)
		}
		_ = pgRunHardenedGit(workDir, nil, "checkout", "-b", "main")
	}
	if author.Name == "" {
		author.Name = "Alice Developer"
	}
	if author.Email == "" {
		author.Email = "alice@example.com"
	}
	if res := pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name); res.ExitCode != 0 {
		t.Fatalf("git config user.name: %s", res.Stderr)
	}
	if res := pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email); res.ExitCode != 0 {
		t.Fatalf("git config user.email: %s", res.Stderr)
	}
	if msg == "" {
		msg = "initial commit"
	}
	_ = pgAddCommit(t, workDir, files, nil, msg, author)
	return workDir
}

func pgAddCommit(t testing.TB, repoDir string, files map[string]string, deleted []string, msg string, author harness.GitIdentity) string {
	t.Helper()
	for _, rel := range deleted {
		_ = os.Remove(filepath.Join(repoDir, rel))
	}
	for rel, content := range files {
		target := filepath.Join(repoDir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir for %q: %v", rel, err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatalf("write file %q: %v", rel, err)
		}
	}
	if res := pgRunHardenedGit(repoDir, nil, "add", "-A"); res.ExitCode != 0 {
		t.Fatalf("git add -A failed: %s", res.Stderr)
	}
	env := map[string]string{}
	if author.Name != "" {
		env["GIT_AUTHOR_NAME"] = author.Name
		env["GIT_COMMITTER_NAME"] = author.Name
	}
	if author.Email != "" {
		env["GIT_AUTHOR_EMAIL"] = author.Email
		env["GIT_COMMITTER_EMAIL"] = author.Email
	}
	if msg == "" {
		msg = "commit"
	}
	if res := pgRunHardenedGit(repoDir, env, "commit", "--allow-empty", "-m", msg); res.ExitCode != 0 {
		t.Fatalf("git commit failed: %s", res.Stderr)
	}
	shaRes := pgRunHardenedGit(repoDir, nil, "rev-parse", "HEAD")
	if shaRes.ExitCode != 0 {
		t.Fatalf("git rev-parse HEAD failed: %s", shaRes.Stderr)
	}
	return strings.TrimSpace(shaRes.Stdout)
}

func pgMakeHistorySmuggleRepo(t testing.TB, cloneURL string, smuggledFiles map[string]string, cleanOverlay map[string]string, caCertPath string) (workDir, smuggledSHA, tipSHA string) {
	t.Helper()
	workDir = filepath.Join(t.TempDir(), "smuggle-repo")
	extraEnv := map[string]string{}
	if caCertPath != "" {
		extraEnv["GIT_SSL_CAINFO"] = caCertPath
	}
	if res := pgRunHardenedGit("", extraEnv, "clone", cloneURL, workDir); res.ExitCode != 0 {
		t.Fatalf("git clone %q failed: %s", cloneURL, res.Stderr)
	}
	author := harness.GitIdentity{Name: "Alice Developer", Email: "alice@example.com"}
	_ = pgRunHardenedGit(workDir, nil, "config", "user.name", author.Name)
	_ = pgRunHardenedGit(workDir, nil, "config", "user.email", author.Email)

	smuggledSHA = pgAddCommit(t, workDir, smuggledFiles, nil, "add restricted payload", author)
	deleted := make([]string, 0, len(smuggledFiles))
	for k := range smuggledFiles {
		deleted = append(deleted, k)
	}
	tipSHA = pgAddCommit(t, workDir, cleanOverlay, deleted, "remove restricted payload before push", author)
	return workDir, smuggledSHA, tipSHA
}

func pgBuildConcealmentPayloads(t testing.TB, secretOrIP []byte) map[string][]byte {
	t.Helper()
	payloads := make(map[string][]byte)

	payloads["concealed_b64.txt"] = []byte("// wrapped\n" + base64.StdEncoding.EncodeToString(secretOrIP) + "\n")
	payloads["concealed_hex.txt"] = []byte(hex.EncodeToString(secretOrIP) + "\n")

	var tgzBuf bytes.Buffer
	gz := gzip.NewWriter(&tgzBuf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "secret.txt",
		Mode: 0o644,
		Size: int64(len(secretOrIP)),
	}); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if _, err := tw.Write(secretOrIP); err != nil {
		t.Fatalf("tar Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	zf, err := zw.Create("inner.tar.gz")
	if err != nil {
		t.Fatalf("zip Create: %v", err)
	}
	if _, err := zf.Write(tgzBuf.Bytes()); err != nil {
		t.Fatalf("zip Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	payloads["nested_archive.zip"] = zipBuf.Bytes()

	// PNG magic bytes followed by raw source/secret (magic-byte mismatch).
	pngMismatch := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, secretOrIP...)
	payloads["disguised.png"] = pngMismatch
	return payloads
}

func pgInjectHTTPAuth(rawURL, token string) (string, error) {
	if token == "" {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword("x-access-token", token)
	return u.String(), nil
}

func pgGitPushHTTP(t testing.TB, repoDir, gatewayRepoURL, token, refspec, caCertPath string) pgGitResult {
	t.Helper()
	pushURL, err := pgInjectHTTPAuth(gatewayRepoURL, token)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth(%q): %v", gatewayRepoURL, err)
	}
	if refspec == "" {
		refspec = "HEAD:refs/heads/main"
	}
	extraEnv := map[string]string{}
	if caCertPath != "" {
		extraEnv["GIT_SSL_CAINFO"] = caCertPath
	}
	return pgRunHardenedGit(repoDir, extraEnv, "push", pushURL, refspec)
}

func pgShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func pgGitPushHTTPCredentialHelper(t testing.TB, env *harness.Env, repoDir, gatewayRepoURL, token, refspec string) pgGitResult {
	t.Helper()
	if refspec == "" {
		refspec = "HEAD:refs/heads/main"
	}
	binName := env.Contracts().Binaries.Custodian
	if binName == "" {
		binName = "custodian"
	}
	custodianBin := env.BinaryPath(binName)
	if custodianBin == "" || custodianBin == binName {
		if binDir := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_BIN_DIR")); binDir != "" {
			candidate := filepath.Join(binDir, binName)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				custodianBin = candidate
			}
		}
	}
	if custodianBin == "" {
		custodianBin = binName
	}
	helperSub := env.Contracts().CLI.CredentialHelperSubcommand
	if len(helperSub) == 0 {
		helperSub = []string{"credential-helper"}
	}
	quotedParts := make([]string, 0, 1+len(helperSub))
	quotedParts = append(quotedParts, pgShellQuote(custodianBin))
	for _, arg := range helperSub {
		quotedParts = append(quotedParts, pgShellQuote(arg))
	}
	helperCmd := "!" + strings.Join(quotedParts, " ")

	extraEnv := map[string]string{
		"CUSTODIAN_API_URL": env.APIBaseURL(),
		"CUSTODIAN_TOKEN":   token,
	}
	if caPath := env.GitGatewayCACertPath(); caPath != "" {
		extraEnv["GIT_SSL_CAINFO"] = caPath
	}
	return pgRunHardenedGit(repoDir, extraEnv, "-c", "credential.helper="+helperCmd, "push", gatewayRepoURL, refspec)
}

func pgGitPushSSH(t testing.TB, repoDir, sshURL string, cred harness.SSHUserCredential, sshAddr, refspec string, sshHelper *harness.SSHCAHelper) pgGitResult {
	t.Helper()
	if refspec == "" {
		refspec = "HEAD:refs/heads/main"
	}
	extraEnv := sshHelper.GitEnv(cred, sshAddr)
	return pgRunHardenedGit(repoDir, extraEnv, "push", sshURL, refspec)
}

func pgGitCloneHTTP(t testing.TB, gatewayRepoURL, token, caCertPath string) (string, pgGitResult) {
	t.Helper()
	cloneURL, err := pgInjectHTTPAuth(gatewayRepoURL, token)
	if err != nil {
		t.Fatalf("pgInjectHTTPAuth(%q): %v", gatewayRepoURL, err)
	}
	dst := filepath.Join(t.TempDir(), "clone-http")
	extraEnv := map[string]string{}
	if caCertPath != "" {
		extraEnv["GIT_SSL_CAINFO"] = caCertPath
	}
	res := pgRunHardenedGit("", extraEnv, "clone", cloneURL, dst)
	return dst, res
}

func pgGitCloneSSH(t testing.TB, sshURL string, cred harness.SSHUserCredential, sshAddr string, sshHelper *harness.SSHCAHelper) (string, pgGitResult) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "clone-ssh")
	extraEnv := sshHelper.GitEnv(cred, sshAddr)
	res := pgRunHardenedGit("", extraEnv, "clone", sshURL, dst)
	return dst, res
}

func pgGitPushRawPack(t testing.TB, gatewayReceivePackURL, token, caCertPath string, rawBody []byte) (int, []byte) {
	t.Helper()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCertPath != "" {
		pemBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			t.Fatalf("read caCertPath %q: %v", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			t.Fatalf("append CA cert from %q failed", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	req, err := http.NewRequest(http.MethodPost, gatewayReceivePackURL, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("build raw receive-pack request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", gatewayReceivePackURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, body
}

func pgAssertZeroUpstreamReceivePack(t testing.TB, env *harness.Env, repoFullName string) {
	t.Helper()
	gh := env.GitHub()
	for _, c := range gh.ReceivePackCalls() {
		if repoFullName == "" || c.Repo == repoFullName {
			t.Fatalf("expected zero upstream POST /git-receive-pack calls for %q, found %+v", repoFullName, c)
		}
	}
	if n := gh.ReceivePackBytes(repoFullName); n != 0 {
		t.Fatalf("expected 0 upstream receive-pack bytes for %q, got %d", repoFullName, n)
	}
	if lfs := gh.LFSUploadBytes(repoFullName); lfs != 0 {
		t.Fatalf("expected 0 upstream LFS upload bytes for %q, got %d", repoFullName, lfs)
	}
	for _, p := range gh.PushAttempts() {
		if repoFullName == "" || p.Repo == repoFullName {
			t.Fatalf("expected zero upstream PushAttempts for %q, found %+v", repoFullName, p)
		}
	}
}

func pgSeedCorpusFiles(t testing.TB, env *harness.Env, adminToken, name, classification string, files map[string]string) string {
	t.Helper()
	inputs := make([]harness.IPCorpusFileInput, 0, len(files))
	for path, content := range files {
		sum := sha256.Sum256([]byte(content))
		inputs = append(inputs, harness.IPCorpusFileInput{
			Path:    path,
			Content: content,
			SHA256:  hex.EncodeToString(sum[:]),
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := env.Client(adminToken)
	corpResp, raw, err := client.CreateIPCorpus(ctx, harness.CreateIPCorpusReq{
		Name:           name,
		Classification: classification,
		Files:          inputs,
	})
	if err != nil {
		t.Fatalf("CreateIPCorpus(%q): %v", name, err)
	}
	raw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated, http.StatusAccepted)
	harness.AssertUUIDv7(t, corpResp.ID)

	reindexResp, rRaw, err := client.ReindexIPCorpus(ctx, corpResp.ID, harness.ReindexIPCorpusReq{Force: true})
	if err != nil {
		t.Fatalf("ReindexIPCorpus(%q): %v", corpResp.ID, err)
	}
	rRaw.RequireAnyStatus(t, http.StatusOK, http.StatusAccepted)
	if reindexResp.OperationID != "" {
		op, err := client.WaitForOperation(ctx, reindexResp.OperationID, 30*time.Second)
		if err != nil {
			t.Fatalf("WaitForOperation(reindex %s): %v", reindexResp.OperationID, err)
		}
		if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, op.Status) {
			t.Fatalf("reindex operation %s ended in status %q (err=%q)", op.ID, op.Status, op.LastError)
		}
	}
	return corpResp.ID
}

func pgAssertNoRawCorpusLeak(t testing.TB, env *harness.Env, snippets ...string) {
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
	harness.AssertNoSecretOrEncodedLeak(t, env.AllLogs(), filtered...)
}
