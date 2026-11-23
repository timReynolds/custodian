package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/persistence"
)

func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func TestHelpAndConfigParsingAndRedaction(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("custodian-api --help expected 0, got %d (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "custodian-api") {
		t.Fatalf("unexpected --help output: %s", stdout.String())
	}

	// Config env aliases: CUSTODIAN_SNAPSHOT_ROOT fallback CUSTODIAN_SNAPSHOT_DIR, CUSTODIAN_ARTIFACT_RETENTION fallback _TTL.
	pemStr := generateTestRSAPEM(t)
	envMap := map[string]string{
		"CUSTODIAN_DATABASE_URL":                "postgres://custodian:supersecretpw@127.0.0.1:5432/custodian?sslmode=disable",
		"CUSTODIAN_OIDC_ISSUER":                 "http://127.0.0.1:9999",
		"CUSTODIAN_OIDC_AUDIENCE":               "custodian-api",
		"CUSTODIAN_CAPABILITY_HMAC_SECRET":      "0123456789abcdef0123456789abcdef",
		"CUSTODIAN_GITHUB_READ_APP_ID":          "1234",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM": pemStr,
		"CUSTODIAN_GITHUB_API_URL":              "http://127.0.0.1:18080/api/v3/",
		"CUSTODIAN_SNAPSHOT_DIR":                "/tmp/snap-dir",
		"CUSTODIAN_ARTIFACT_RETENTION":          "48h",
	}
	cfg, err := loadConfig(func(k string) string { return envMap[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SnapshotDir != "/tmp/snap-dir" {
		t.Fatalf("expected SnapshotDir=/tmp/snap-dir, got %q", cfg.SnapshotDir)
	}
	if cfg.ArtifactRetentionTTL != 48*time.Hour {
		t.Fatalf("expected ArtifactRetentionTTL=48h, got %v", cfg.ArtifactRetentionTTL)
	}
	if !cfg.AllowInsecureHTTP {
		t.Fatal("expected AllowInsecureHTTP=true for loopback GitHub API URL")
	}

	// CUSTODIAN_SNAPSHOT_ROOT takes precedence over CUSTODIAN_SNAPSHOT_DIR.
	envMap["CUSTODIAN_SNAPSHOT_ROOT"] = "/tmp/snap-root"
	// CUSTODIAN_BASE_URL fallback when CUSTODIAN_API_PUBLIC_URL is unset, and override when set.
	envMap["CUSTODIAN_BASE_URL"] = "https://base.custodian.test"
	cfg, err = loadConfig(func(k string) string { return envMap[k] })
	if err != nil || cfg.SnapshotDir != "/tmp/snap-root" {
		t.Fatalf("expected CUSTODIAN_SNAPSHOT_ROOT override, got dir=%q err=%v", cfg.SnapshotDir, err)
	}
	if cfg.BaseURL != "https://base.custodian.test" {
		t.Fatalf("expected BaseURL fallback to CUSTODIAN_BASE_URL, got %q", cfg.BaseURL)
	}
	envMap["CUSTODIAN_API_PUBLIC_URL"] = "https://public.custodian.test"
	cfg, err = loadConfig(func(k string) string { return envMap[k] })
	if err != nil || cfg.BaseURL != "https://public.custodian.test" {
		t.Fatalf("expected CUSTODIAN_API_PUBLIC_URL precedence, got %q err=%v", cfg.BaseURL, err)
	}

	if !isLoopbackHTTP("http://127.0.0.1:8080") || !isLoopbackHTTP("http://localhost:9000") || isLoopbackHTTP("https://127.0.0.1:8080") || isLoopbackHTTP("http://example.com:8080") {
		t.Fatal("isLoopbackHTTP check failed")
	}

	rawErr := fmt.Sprintf("dial tcp failed for postgres://custodian:supersecretpw@127.0.0.1:5432/db password=anothersecret %s", pemStr)
	redacted := redactString(rawErr, cfg.secrets()...)
	for _, secret := range []string{"supersecretpw", "anothersecret", "BEGIN RSA PRIVATE KEY", "0123456789abcdef"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q leaked in redacted output: %s", secret, redacted)
		}
	}
}

func TestStartupFailsCleanlyOnMissingOrUnreachableDB(t *testing.T) {
	// Missing required env vars fails cleanly without panic.
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), nil, func(string) string { return "" }, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit when config is empty")
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "panic:") {
		t.Fatalf("unexpected panic in output: %s", combined)
	}

	// Unreachable PostgreSQL fails cleanly and NEVER leaks DSN password or capability secret.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	pemStr := generateTestRSAPEM(t)
	dbPass := "UltraSecretDBPass999"
	capSecret := "UltraSecretCapHMACKey_32_Bytes!!"
	envMap := map[string]string{
		"CUSTODIAN_LISTEN_ADDR":                 "127.0.0.1:0",
		"CUSTODIAN_DATABASE_URL":                fmt.Sprintf("postgres://custodian:%s@%s/custodian?sslmode=disable", dbPass, deadAddr),
		"CUSTODIAN_OIDC_ISSUER":                 "http://127.0.0.1:19999",
		"CUSTODIAN_OIDC_AUDIENCE":               "custodian-api",
		"CUSTODIAN_CAPABILITY_HMAC_SECRET":      capSecret,
		"CUSTODIAN_GITHUB_READ_APP_ID":          "1",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM": pemStr,
		"CUSTODIAN_SNAPSHOT_ROOT":               t.TempDir(),
		"CUSTODIAN_LOG_FORMAT":                  "json",
	}

	stdout.Reset()
	stderr.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	code = run(ctx, nil, func(k string) string { return envMap[k] }, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit when DB is unreachable")
	}
	out := stdout.String() + stderr.String()
	if strings.Contains(out, "panic:") {
		t.Fatalf("unexpected panic on unreachable DB: %s", out)
	}
	if strings.Contains(out, dbPass) || strings.Contains(out, capSecret) || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("secret leaked on DB startup failure: %s", out)
	}
}

func TestStartupPG17PolicySeedingReadyzAndGracefulShutdown(t *testing.T) {
	pg := harness.StartPostgres(t)
	oidc := harness.StartMockOIDC(t, "custodian-api")
	snapDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)

	// Reserve ephemeral free port for custodian-api listener.
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
		"CUSTODIAN_POLICY_DIR":                  "../../policies/defaults",
		"CUSTODIAN_LOG_FORMAT":                  "json",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)
	go func() {
		exitCh <- run(ctx, nil, func(k string) string { return envMap[k] }, &stdout, &stderr)
	}()

	// Poll /readyz until 200 OK.
	client := &http.Client{Timeout: 2 * time.Second}
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
		cancel()
		code := <-exitCh
		t.Fatalf("custodian-api never became ready (exit=%d)\nstdout=%s\nstderr=%s", code, stdout.String(), stderr.String())
	}

	// Verify /healthz returns 200 JSON.
	hResp, err := client.Get("http://" + listenAddr + "/healthz")
	if err != nil || hResp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz failed: resp=%v err=%v", hResp, err)
	}
	var healthBody map[string]any
	_ = json.NewDecoder(hResp.Body).Decode(&healthBody)
	_ = hResp.Body.Close()

	// Verify policy bundle from CUSTODIAN_POLICY_DIR was seeded and activated in PG.
	store, err := persistence.NewStore(pg.Pool())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	bundles, err := store.ListActivePolicyBundles(context.Background())
	if err != nil {
		t.Fatalf("ListActivePolicyBundles: %v", err)
	}
	if len(bundles) == 0 {
		t.Fatal("expected policy bundle from CUSTODIAN_POLICY_DIR to be seeded & active in PostgreSQL")
	}

	// Trigger graceful shutdown via context cancellation (simulates SIGTERM/SIGINT).
	cancel()
	select {
	case code := <-exitCh:
		if code != 0 {
			t.Fatalf("expected clean exit 0 on shutdown, got %d\nstderr=%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}
}
