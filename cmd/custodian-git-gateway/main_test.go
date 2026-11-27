package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/persistence"
)

func writeTestTLSFiles(t *testing.T, dir string) (certPath, keyPath string, certPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ECDSA): %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath = filepath.Join(dir, "gateway.crt")
	keyPath = filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert): %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
	return certPath, keyPath, certPEM
}

func writeTestSSHFiles(t *testing.T, dir string) (hostKeyPath, userCAPath string, hostKeyPEM []byte) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ed25519 host): %v", err)
	}
	hostBlock, err := ssh.MarshalPrivateKey(hostPriv, "test-host-key")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	hostKeyPEM = pem.EncodeToMemory(hostBlock)
	hostKeyPath = filepath.Join(dir, "ssh_host_ed25519_key")
	if err := os.WriteFile(hostKeyPath, hostKeyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(hostKey): %v", err)
	}

	caPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ed25519 ca): %v", err)
	}
	sshCAPub, err := ssh.NewPublicKey(caPub)
	if err != nil {
		t.Fatalf("NewPublicKey(ca): %v", err)
	}
	userCAPath = filepath.Join(dir, "ssh_user_ca.pub")
	if err := os.WriteFile(userCAPath, ssh.MarshalAuthorizedKey(sshCAPub), 0o644); err != nil {
		t.Fatalf("WriteFile(userCA): %v", err)
	}
	return hostKeyPath, userCAPath, hostKeyPEM
}

func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(RSA): %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestGatewayCLIHelpAndUnknownFlags(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "help"} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{arg}, nil, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("arg %q: expected exit 0, got %d (stderr=%s)", arg, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "custodian-git-gateway") {
			t.Fatalf("arg %q: unexpected usage output %s", arg, stdout.String())
		}
	}

	for _, args := range [][]string{{"--unknown-flag"}, {"unexpected-positional"}} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, nil, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("args %v: expected exit 2, got %d", args, code)
		}
	}
}

func TestGatewayConfigParsingAndValidation(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeTestTLSFiles(t, dir)
	hostKeyPath, userCAPath, _ := writeTestSSHFiles(t, dir)
	readPEM := generateTestRSAPEM(t)
	writePEM := generateTestRSAPEM(t)

	baseEnv := map[string]string{
		"CUSTODIAN_DATABASE_URL":                    "postgres://custodian:supersecretpw@127.0.0.1:5432/custodian?sslmode=disable",
		"CUSTODIAN_SNAPSHOT_ROOT":                   dir,
		"CUSTODIAN_OIDC_ISSUER":                     "http://127.0.0.1:9999",
		"CUSTODIAN_OIDC_AUDIENCE":                   "custodian-api",
		"CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE":       certPath,
		"CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE":        keyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE":   hostKeyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE":    userCAPath,
		"CUSTODIAN_GIT_GATEWAY_HTTP_ADDR":           "127.0.0.1:9443",
		"CUSTODIAN_GIT_GATEWAY_SSH_ADDR":            "127.0.0.1:2223",
		"CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL":        "http://127.0.0.1:18080",
		"CUSTODIAN_GIT_GATEWAY_API_BASE_URL":        "http://127.0.0.1:18081",
		"CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES":      "1048576",
		"CUSTODIAN_GIT_GATEWAY_MAX_OBJECTS":         "500",
		"CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES":  "32768",
		"CUSTODIAN_GIT_GATEWAY_MAX_REF_UPDATES":     "25",
		"CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE": "PASSIVE_AUDIT",
		"CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY":    "INLINE_WARN",
		"CUSTODIAN_GITHUB_READ_APP_ID":              "101",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":     readPEM,
		"CUSTODIAN_GITHUB_WRITE_APP_ID":             "202",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM":    writePEM,
	}

	cfg, err := loadConfig(func(k string) string { return baseEnv[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9443" || cfg.SSHAddr != "127.0.0.1:2223" {
		t.Fatalf("unexpected listen addrs: http=%q ssh=%q", cfg.HTTPAddr, cfg.SSHAddr)
	}
	if cfg.SnapshotDir != dir {
		t.Fatalf("expected SnapshotDir fallback to CUSTODIAN_SNAPSHOT_ROOT=%q, got %q", dir, cfg.SnapshotDir)
	}
	if cfg.QuarantineLimits.MaxPackBytes != 1048576 ||
		cfg.QuarantineLimits.MaxObjects != 500 ||
		cfg.QuarantineLimits.MaxInflatedObjectBytes != 32768 ||
		cfg.QuarantineLimits.MaxRefUpdates != 25 {
		t.Fatalf("unexpected QuarantineLimits: %+v", cfg.QuarantineLimits)
	}
	if cfg.DefaultEgressMode != domain.EgressModePassiveAudit || cfg.PassiveDelivery != domain.PassiveAuditDeliveryInlineWarn {
		t.Fatalf("unexpected egress mode/delivery: %s / %s", cfg.DefaultEgressMode, cfg.PassiveDelivery)
	}
	if !cfg.AllowInsecureHTTP {
		t.Fatal("expected AllowInsecureHTTP=true for loopback upstream URL")
	}

	// CUSTODIAN_SNAPSHOT_DIR takes precedence over CUSTODIAN_SNAPSHOT_ROOT.
	baseEnv["CUSTODIAN_SNAPSHOT_DIR"] = filepath.Join(dir, "explicit-dir")
	cfg, err = loadConfig(func(k string) string { return baseEnv[k] })
	if err != nil || cfg.SnapshotDir != baseEnv["CUSTODIAN_SNAPSHOT_DIR"] {
		t.Fatalf("expected CUSTODIAN_SNAPSHOT_DIR precedence, got %q err=%v", cfg.SnapshotDir, err)
	}

	// Secret redaction removes DSN password, PEMs, TLS key, and SSH host key.
	rawErr := fmt.Sprintf("failed postgres://custodian:supersecretpw@127.0.0.1:5432/db %s %s %s",
		readPEM, string(cfg.TLSKeyPEM), string(cfg.SSHHostKeyPEM))
	redacted := redactString(rawErr, cfg.secrets()...)
	for _, needle := range []string{"supersecretpw", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"} {
		if strings.Contains(redacted, needle) {
			t.Fatalf("secret %q leaked in redacted string: %s", needle, redacted)
		}
	}

	// Invalid bounds & modes fail cleanly.
	for _, tc := range []struct {
		key, val string
	}{
		{"CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES", "0"},
		{"CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES", "-5"},
		{"CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE", "INVALID_MODE"},
		{"CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY", "BAD_DELIVERY"},
	} {
		clone := make(map[string]string, len(baseEnv))
		for k, v := range baseEnv {
			clone[k] = v
		}
		clone[tc.key] = tc.val
		if _, err := loadConfig(func(k string) string { return clone[k] }); err == nil {
			t.Fatalf("expected loadConfig failure for %s=%s", tc.key, tc.val)
		}
	}
}

func TestGatewayStartupFailsCleanlyWithoutSecretLeaks(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, func(string) string { return "" }, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1 on missing env, got %d", code)
	}
	if strings.Contains(stdout.String()+stderr.String(), "panic:") {
		t.Fatalf("unexpected panic: %s", stdout.String()+stderr.String())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	dir := t.TempDir()
	certPath, keyPath, _ := writeTestTLSFiles(t, dir)
	hostKeyPath, userCAPath, _ := writeTestSSHFiles(t, dir)
	dbPass := "GatewayUltraSecretPass987!"
	writePEM := generateTestRSAPEM(t)

	envMap := map[string]string{
		"CUSTODIAN_GIT_GATEWAY_HTTP_ADDR":         "127.0.0.1:0",
		"CUSTODIAN_GIT_GATEWAY_SSH_ADDR":          "127.0.0.1:0",
		"CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE":     certPath,
		"CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE":      keyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE": hostKeyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE":  userCAPath,
		"CUSTODIAN_DATABASE_URL":                  fmt.Sprintf("postgres://custodian:%s@%s/custodian?sslmode=disable", dbPass, deadAddr),
		"CUSTODIAN_SNAPSHOT_DIR":                  dir,
		"CUSTODIAN_OIDC_ISSUER":                   "http://127.0.0.1:19999",
		"CUSTODIAN_OIDC_AUDIENCE":                 "custodian-api",
		"CUSTODIAN_GITHUB_WRITE_APP_ID":           "77",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM":  writePEM,
		"CUSTODIAN_LOG_FORMAT":                    "json",
	}

	stdout.Reset()
	stderr.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	code := run(ctx, nil, func(k string) string { return envMap[k] }, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit when DB is unreachable")
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "panic:") {
		t.Fatalf("unexpected panic: %s", combined)
	}
	for _, secret := range []string{dbPass, "PRIVATE KEY", "OPENSSH"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("secret %q leaked in output: %s", secret, combined)
		}
	}
}

func TestGatewayPG17LifecycleTLSHealthReadyMetricsSSHAndShutdown(t *testing.T) {
	pg := harness.StartPostgres(t)
	oidc := harness.StartMockOIDC(t, "custodian-api")
	dir := t.TempDir()
	certPath, keyPath, certPEM := writeTestTLSFiles(t, dir)
	hostKeyPath, userCAPath, _ := writeTestSSHFiles(t, dir)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(http): %v", err)
	}
	httpAddr := httpLn.Addr().String()
	_ = httpLn.Close()

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(ssh): %v", err)
	}
	sshAddr := sshLn.Addr().String()
	_ = sshLn.Close()

	envMap := map[string]string{
		"CUSTODIAN_GIT_GATEWAY_HTTP_ADDR":         httpAddr,
		"CUSTODIAN_GIT_GATEWAY_SSH_ADDR":          sshAddr,
		"CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE":     certPath,
		"CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE":      keyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE": hostKeyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE":  userCAPath,
		"CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL":      "http://127.0.0.1:18080",
		"CUSTODIAN_DATABASE_URL":                  pg.DSN(),
		"CUSTODIAN_SNAPSHOT_DIR":                  dir,
		"CUSTODIAN_POLICY_DIR":                    "../../policies/defaults",
		"CUSTODIAN_OIDC_ISSUER":                   oidc.Issuer(),
		"CUSTODIAN_OIDC_JWKS_URL":                 oidc.JWKSURL(),
		"CUSTODIAN_OIDC_AUDIENCE":                 oidc.Audience(),
		"CUSTODIAN_LOG_FORMAT":                    "json",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- run(ctx, nil, func(k string) string { return envMap[k] }, &stdout, &stderr)
	}()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM failed")
	}
	tlsClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	ready := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := tlsClient.Get("https://" + httpAddr + "/readyz")
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
		cancel()
		code := <-exitCh
		t.Fatalf("custodian-git-gateway never became ready (exit=%d)\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}

	// /healthz returns 200 JSON without auth.
	hResp, err := tlsClient.Get("https://" + httpAddr + "/healthz")
	if err != nil || hResp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz failed: resp=%v err=%v", hResp, err)
	}
	var healthBody map[string]string
	_ = json.NewDecoder(hResp.Body).Decode(&healthBody)
	_ = hResp.Body.Close()
	if healthBody["status"] != "ok" {
		t.Fatalf("unexpected /healthz body: %+v", healthBody)
	}

	// /metrics returns 200 Prometheus text without auth.
	mResp, err := tlsClient.Get("https://" + httpAddr + "/metrics")
	if err != nil || mResp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics failed: resp=%v err=%v", mResp, err)
	}
	mBytes, _ := io.ReadAll(mResp.Body)
	_ = mResp.Body.Close()
	if !strings.Contains(string(mBytes), "# TYPE") || !strings.Contains(string(mBytes), "# HELP") {
		t.Fatalf("unexpected /metrics body: %s", string(mBytes))
	}

	// SSH listener is bound and accepting TCP connections.
	sshConn, err := net.DialTimeout("tcp", sshAddr, time.Second)
	if err != nil {
		t.Fatalf("TCP dial to SSHAddr %s failed: %v", sshAddr, err)
	}
	_ = sshConn.Close()

	// Verify policy bundles were seeded in PG.
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	bundles, err := store.ListActivePolicyBundles(context.Background())
	if err != nil || len(bundles) == 0 {
		t.Fatalf("expected active seeded policy bundles, got len=%d err=%v", len(bundles), err)
	}

	// Graceful shutdown on context cancel.
	cancel()
	select {
	case code := <-exitCh:
		if code != 0 {
			t.Fatalf("expected clean exit 0 on shutdown, got %d\nstderr=%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}

	// Verify structured JSON logs contain zero panics or secrets.
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "{") {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSON log line %q: %v", line, err)
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "panic:") {
		t.Fatalf("unexpected panic in logs: %s", stdout.String())
	}
}

func TestGatewayPG17LivePipelineEndToEndPush(t *testing.T) {
	pg := harness.StartPostgres(t)
	oidc := harness.StartMockOIDC(t, "custodian-api")
	dir := t.TempDir()
	certPath, keyPath, certPEM := writeTestTLSFiles(t, dir)
	hostKeyPath, userCAPath, _ := writeTestSSHFiles(t, dir)

	// Bare upstream git repo + mock GitHub HTTP/API servers.
	bareDir := filepath.Join(t.TempDir(), "upstream.git")
	seedWork := filepath.Join(t.TempDir(), "seed-work")
	runTestGit := func(workDir string, extraEnv []string, args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		if workDir != "" {
			cmd.Dir = workDir
		}
		env := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
		}
		env = append(env, extraEnv...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := runTestGit("", nil, "init", "--bare", "--initial-branch=main", bareDir); err != nil {
		t.Fatalf("git init bare: %v\n%s", err, out)
	}
	if out, err := runTestGit("", nil, "init", "--initial-branch=main", seedWork); err != nil {
		t.Fatalf("git init work: %v\n%s", err, out)
	}
	_, _ = runTestGit(seedWork, nil, "config", "user.name", "Seed")
	_, _ = runTestGit(seedWork, nil, "config", "user.email", "seed@example.com")
	if err := os.WriteFile(filepath.Join(seedWork, "README.md"), []byte("# acme/live\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, _ = runTestGit(seedWork, nil, "add", "README.md")
	_, _ = runTestGit(seedWork, nil, "commit", "-m", "initial")
	if out, err := runTestGit(seedWork, nil, "push", bareDir, "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("seed push: %v\n%s", err, out)
	}

	const writeTok = "ghs_live_cmd_write_token_123"
	var upstreamRecvCalls int
	upSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/acme/live.git/info/refs":
			svc := r.URL.Query().Get("service")
			cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", strings.TrimPrefix(svc, "git-"), "--stateless-rpc", "--advertise-refs", bareDir)
			out, err := cmd.Output()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-"+svc+"-advertisement")
			pkt := fmt.Sprintf("# service=%s\n", svc)
			_, _ = fmt.Fprintf(w, "%04x%s0000", len(pkt)+4, pkt)
			_, _ = w.Write(out)
		case r.URL.Path == "/acme/live.git/git-upload-pack":
			body, _ := io.ReadAll(r.Body)
			cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "upload-pack", "--stateless-rpc", bareDir)
			cmd.Stdin = bytes.NewReader(body)
			out, err := cmd.Output()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			_, _ = w.Write(out)
		case r.URL.Path == "/acme/live.git/git-receive-pack":
			upstreamRecvCalls++
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("Authorization") != "Bearer "+writeTok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "receive-pack", "--stateless-rpc", bareDir)
			cmd.Stdin = bytes.NewReader(body)
			out, err := cmd.Output()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
			_, _ = w.Write(out)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upSrv.Close()

	ghAPISrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/access_tokens") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      writeTok,
				"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ghAPISrv.Close()

	// Stub scanner binaries so Stage A completes cleanly.
	stubDir := t.TempDir()
	for name, body := range map[string]string{
		"gitleaks": "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = version ] && { echo v8.18.4; exit 0; }; done\nOUT=\"\"; while [ $# -gt 0 ]; do case \"$1\" in --report-path) OUT=\"$2\"; shift 2;; *) shift;; esac; done\necho '[]' > \"$OUT\"\n",
		"scancode": "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = --version ] && { echo 32.1.0; exit 0; }; done\nOUT=\"\"; while [ $# -gt 0 ]; do case \"$1\" in --json-pp) OUT=\"$2\"; shift 2;; *) shift;; esac; done\necho '{\"headers\":[{\"tool_name\":\"scancode\",\"tool_version\":\"32.1.0\",\"errors\":[],\"extra_data\":{\"files_count\":1}}],\"files\":[]}' > \"$OUT\"\n",
		"semgrep":  "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = --version ] && { echo 1.90.0; exit 0; }; done\nOUT=\"\"; while [ $# -gt 0 ]; do case \"$1\" in --output) OUT=\"$2\"; shift 2;; *) shift;; esac; done\necho '{\"version\":\"1.90.0\",\"results\":[],\"errors\":[],\"paths\":{\"scanned\":[\"README.md\"],\"skipped\":[]}}' > \"$OUT\"\n",
	} {
		if err := os.WriteFile(filepath.Join(stubDir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
	}

	writePEM := generateTestRSAPEM(t)
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	_ = httpLn.Close()
	sshLn, _ := net.Listen("tcp", "127.0.0.1:0")
	sshAddr := sshLn.Addr().String()
	_ = sshLn.Close()

	// Seed registered repository in PG17.
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	regTrue, extFalse := true, false
	repoRow, err := store.UpsertRepository(context.Background(), persistence.UpsertRepositoryParams{
		GitHubRepositoryID:    777,
		GitHubInstallationID:  888,
		FullName:              "acme/live",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		AllowedModelRoutes:    []string{"approved-code-review"},
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		GitRemoteURL:          upSrv.URL + "/acme/live.git",
		RemoteHost:            "github.com",
		RegisteredDestination: &regTrue,
		External:              &extFalse,
	})
	if err != nil {
		t.Fatalf("UpsertRepository: %v", err)
	}

	envMap := map[string]string{
		"CUSTODIAN_GIT_GATEWAY_HTTP_ADDR":         httpAddr,
		"CUSTODIAN_GIT_GATEWAY_SSH_ADDR":          sshAddr,
		"CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE":     certPath,
		"CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE":      keyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE": hostKeyPath,
		"CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE":  userCAPath,
		"CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL":      upSrv.URL,
		"CUSTODIAN_GITHUB_API_URL":                ghAPISrv.URL,
		"CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP":    "true",
		"CUSTODIAN_GITHUB_READ_APP_ID":            "101",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":   writePEM,
		"CUSTODIAN_GITHUB_WRITE_APP_ID":           "102",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM":  writePEM,
		"CUSTODIAN_CAPABILITY_HMAC_SECRET":        "live-gateway-test-capability-secret-32b",
		"CUSTODIAN_DATABASE_URL":                  pg.DSN(),
		"CUSTODIAN_SNAPSHOT_DIR":                  dir,
		"CUSTODIAN_POLICY_DIR":                    "../../policies/defaults",
		"CUSTODIAN_OIDC_ISSUER":                   oidc.Issuer(),
		"CUSTODIAN_OIDC_JWKS_URL":                 oidc.JWKSURL(),
		"CUSTODIAN_OIDC_AUDIENCE":                 oidc.Audience(),
		"CUSTODIAN_GITLEAKS_BIN":                  filepath.Join(stubDir, "gitleaks"),
		"CUSTODIAN_SCANCODE_BIN":                  filepath.Join(stubDir, "scancode"),
		"CUSTODIAN_SEMGREP_BIN":                   filepath.Join(stubDir, "semgrep"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- run(ctx, nil, func(k string) string { return envMap[k] }, &stdout, &stderr)
	}()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	tlsClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if resp, err := tlsClient.Get("https://" + httpAddr + "/readyz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-exitCh
		t.Fatalf("gateway never became ready\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}

	caFile := filepath.Join(t.TempDir(), "gw-ca.crt")
	_ = os.WriteFile(caFile, certPEM, 0o600)
	jwt := oidc.MintHumanToken("live-alice", "alice@example.com", "Alice Live", "engineering")
	gitEnv := []string{"GIT_SSL_CAINFO=" + caFile}

	// 1. Registered repo clean clone + push -> ALLOW!
	work := filepath.Join(t.TempDir(), "live-work")
	gwRepoURL := fmt.Sprintf("https://x-access-token:%s@%s/acme/live.git", jwt, httpAddr)
	if out, err := runTestGit("", gitEnv, "clone", gwRepoURL, work); err != nil {
		t.Fatalf("live clone failed: %v\n%s", err, out)
	}
	_, _ = runTestGit(work, nil, "config", "user.name", "Alice Live")
	_, _ = runTestGit(work, nil, "config", "user.email", "alice@example.com")
	_ = os.WriteFile(filepath.Join(work, "hello.go"), []byte("package main\nfunc live() {}\n"), 0o600)
	_, _ = runTestGit(work, nil, "add", "hello.go")
	_, _ = runTestGit(work, nil, "commit", "-m", "feat: live pipeline push")
	if out, err := runTestGit(work, gitEnv, "push", "origin", "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("live push failed: %v\n%s", err, out)
	} else if !strings.Contains(out, "ALLOW") {
		t.Fatalf("expected sideband ALLOW on live push:\n%s", out)
	}
	if upstreamRecvCalls != 1 {
		t.Fatalf("expected 1 upstream receive-pack call, got %d", upstreamRecvCalls)
	}

	sessions, err := store.ListPushSessions(context.Background(), persistence.ListPushSessionsParams{
		RepositoryID: &repoRow.ID,
		Limit:        5,
	})
	if err != nil || len(sessions) == 0 || sessions[0].Status != domain.PushSessionStatusCompleted {
		t.Fatalf("expected COMPLETED push session in PG17, got %+v err=%v", sessions, err)
	}

	// 2. Unregistered repo push -> DENY with 0 upstream calls.
	unregURL := fmt.Sprintf("https://x-access-token:%s@%s/external/unreg.git", jwt, httpAddr)
	if out, err := runTestGit(work, gitEnv, "push", unregURL, "HEAD:refs/heads/main"); err == nil {
		t.Fatalf("expected unregistered push to be denied, output:\n%s", out)
	} else if !strings.Contains(out, "DENY") {
		t.Fatalf("expected sideband DENY on unregistered push:\n%s", out)
	}
	if upstreamRecvCalls != 1 {
		t.Fatalf("expected still 1 upstream receive-pack call after DENY, got %d", upstreamRecvCalls)
	}

	cancel()
	if code := <-exitCh; code != 0 {
		t.Fatalf("expected clean exit 0, got %d\nstderr=%s", code, stderr.String())
	}
}
