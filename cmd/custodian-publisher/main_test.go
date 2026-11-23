package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

func generateTestRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string {
		return m[k]
	}
}

func TestHelpAndUsage_ExitsZeroWithEmptyEnv(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, mapEnv(map[string]string{}), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("args=%v exit=%d, want 0 (stderr=%s)", args, code, stderr.String())
		}
		combined := stdout.String() + stderr.String()
		if strings.TrimSpace(combined) == "" {
			t.Fatalf("args=%v produced empty help output", args)
		}
		if strings.Contains(combined, "panic:") {
			t.Fatalf("args=%v output contains panic: %s", args, combined)
		}
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--unknown-flag"}, mapEnv(map[string]string{}), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit for unknown flag")
	}
	if strings.Contains(stdout.String()+stderr.String(), "panic:") {
		t.Fatalf("unknown flag output must not contain panic")
	}
}

func TestConfigEnvIsolationAndLoopbackAndPEM(t *testing.T) {
	pemStr := generateTestRSAKeyPEM(t)
	escapedPEM := strings.ReplaceAll(strings.TrimSpace(pemStr), "\n", `\n`)
	snapDir := t.TempDir()

	// Must succeed with ONLY DB, snapshot, log, and write GitHub App env vars
	// (no model gateway, scanner bins, read-only GitHub App, OIDC, capability HMAC, or policy dir).
	cfg, err := loadConfig(mapEnv(map[string]string{
		"CUSTODIAN_DATABASE_URL":                 "postgres://u:p@127.0.0.1:5432/custodian?sslmode=disable",
		"CUSTODIAN_SNAPSHOT_STORE":               "local",
		"CUSTODIAN_SNAPSHOT_DIR":                 snapDir,
		"CUSTODIAN_GITHUB_API_URL":               "http://127.0.0.1:18080/api/v3/",
		"CUSTODIAN_GITHUB_WRITE_APP_ID":          "202",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM": escapedPEM,
		"CUSTODIAN_LOG_FORMAT":                   "json",
		"CUSTODIAN_LOG_LEVEL":                    "info",
	}))
	if err != nil {
		t.Fatalf("loadConfig minimal isolated env: %v", err)
	}
	if !cfg.AllowInsecureHTTP {
		t.Fatalf("expected AllowInsecureHTTP=true for loopback http://127.0.0.1")
	}
	if !strings.Contains(string(cfg.WritePrivateKeyPEM), "\n") {
		t.Fatalf("expected escaped \\n in PEM to be normalized to newlines")
	}

	// Verify loopback detection table.
	loopbackCases := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:8080/api/v3/", true},
		{"http://localhost:8080/api/v3/", true},
		{"http://[::1]:8080/api/v3/", true},
		{"https://127.0.0.1:8080/api/v3/", false},
		{"https://api.github.com/", false},
		{"http://api.github.com/", false},
		{"http://evil.example.com/", false},
	}
	for _, tc := range loopbackCases {
		if got := isLoopbackHTTP(tc.url); got != tc.want {
			t.Fatalf("isLoopbackHTTP(%q)=%v, want %v", tc.url, got, tc.want)
		}
	}

	// Verify _FILE fallback + explicit CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP=false override + GCS config.
	keyFile := filepath.Join(t.TempDir(), "write.pem")
	if err := os.WriteFile(keyFile, []byte(pemStr), 0o600); err != nil {
		t.Fatalf("write keyFile: %v", err)
	}
	cfgGCS, err := loadConfig(mapEnv(map[string]string{
		"CUSTODIAN_DATABASE_URL":                  "postgres://u:p@127.0.0.1:5432/custodian",
		"CUSTODIAN_SNAPSHOT_STORE":                "gcs",
		"CUSTODIAN_SNAPSHOT_BUCKET":               "custodian-artifacts",
		"CUSTODIAN_SNAPSHOT_PREFIX":               "prod/v1",
		"CUSTODIAN_GITHUB_API_URL":                "http://localhost:9090/api/v3/",
		"CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP":    "false",
		"CUSTODIAN_GITHUB_WRITE_APP_ID":           "303",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_FILE": keyFile,
	}))
	if err != nil {
		t.Fatalf("loadConfig gcs+_FILE: %v", err)
	}
	if cfgGCS.AllowInsecureHTTP {
		t.Fatalf("expected explicit CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP=false to override loopback")
	}
	if cfgGCS.SnapshotBucket != "custodian-artifacts" || cfgGCS.SnapshotPrefix != "prod/v1" {
		t.Fatalf("unexpected GCS config: %+v", cfgGCS)
	}
}

func TestCleanDBFailure_EmptyAndUnreachableNoPasswordLeak(t *testing.T) {
	pemStr := generateTestRSAKeyPEM(t)
	snapDir := t.TempDir()

	// 1. Empty CUSTODIAN_DATABASE_URL.
	var stdoutEmpty, stderrEmpty bytes.Buffer
	code := run(context.Background(), nil, mapEnv(map[string]string{
		"CUSTODIAN_DATABASE_URL":                 "",
		"CUSTODIAN_SNAPSHOT_STORE":               "local",
		"CUSTODIAN_SNAPSHOT_DIR":                 snapDir,
		"CUSTODIAN_GITHUB_WRITE_APP_ID":          "202",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM": pemStr,
		"CUSTODIAN_LOG_FORMAT":                   "json",
	}), &stdoutEmpty, &stderrEmpty)
	if code == 0 {
		t.Fatalf("expected non-zero exit for empty DSN")
	}
	combinedEmpty := stdoutEmpty.String() + stderrEmpty.String()
	if strings.Contains(combinedEmpty, "panic:") {
		t.Fatalf("empty DSN must not panic: %s", combinedEmpty)
	}

	// 2. Unreachable CUSTODIAN_DATABASE_URL with embedded password: must not leak secret & must emit valid JSON logs.
	secretPass := "superSecretPass123"
	badDSN := "postgres://baduser:" + secretPass + "@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdoutBad, stderrBad bytes.Buffer
	code = run(ctx, nil, mapEnv(map[string]string{
		"CUSTODIAN_DATABASE_URL":                 badDSN,
		"CUSTODIAN_SNAPSHOT_STORE":               "local",
		"CUSTODIAN_SNAPSHOT_DIR":                 snapDir,
		"CUSTODIAN_GITHUB_WRITE_APP_ID":          "202",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM": pemStr,
		"CUSTODIAN_LOG_FORMAT":                   "json",
		"CUSTODIAN_LOG_LEVEL":                    "info",
	}), &stdoutBad, &stderrBad)
	if code == 0 {
		t.Fatalf("expected non-zero exit for unreachable DSN")
	}
	combinedBad := stdoutBad.String() + stderrBad.String()
	if strings.Contains(combinedBad, "panic:") {
		t.Fatalf("unreachable DSN must not panic: %s", combinedBad)
	}
	if strings.Contains(combinedBad, secretPass) || strings.Contains(combinedBad, "baduser:"+secretPass) {
		t.Fatalf("unreachable DSN leaked credentials: %s", combinedBad)
	}
	if strings.Contains(combinedBad, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("logs leaked private key PEM")
	}

	// Every stdout line must be valid JSON and contain ID/digest/safe metadata only.
	jsonLines := 0
	for _, line := range strings.Split(strings.TrimSpace(stdoutBad.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSON log line %q: %v", line, err)
		}
		jsonLines++
		if obj["component"] != "custodian-publisher" {
			t.Fatalf("expected component=custodian-publisher, got %v", obj["component"])
		}
	}
	if jsonLines == 0 {
		t.Fatalf("expected at least 1 JSON log line on stdout")
	}
}

func TestCompiledBinarySmoke_HelpAndUnreachableDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess binary build smoke check under -short")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	binPath := filepath.Join(t.TempDir(), "custodian-publisher")
	buildCmd := exec.Command(goBin, "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, string(out))
	}

	helpCmd := exec.Command(binPath, "--help")
	helpCmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	helpOut, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, string(helpOut))
	}
	if strings.TrimSpace(string(helpOut)) == "" || strings.Contains(string(helpOut), "panic:") {
		t.Fatalf("unexpected --help output: %s", string(helpOut))
	}

	secret := "TopSecretDBPass99"
	pemStr := generateTestRSAKeyPEM(t)
	dbCmd := exec.Command(binPath)
	dbCmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"CUSTODIAN_DATABASE_URL=postgres://cust:" + secret + "@127.0.0.1:1/custodian?sslmode=disable&connect_timeout=1",
		"CUSTODIAN_SNAPSHOT_STORE=local",
		"CUSTODIAN_SNAPSHOT_DIR=" + t.TempDir(),
		"CUSTODIAN_GITHUB_WRITE_APP_ID=202",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM=" + pemStr,
		"CUSTODIAN_LOG_FORMAT=json",
	}
	dbOut, err := dbCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on unreachable DB")
	}
	outStr := string(dbOut)
	if strings.Contains(outStr, "panic:") {
		t.Fatalf("binary panicked on unreachable DB: %s", outStr)
	}
	if strings.Contains(outStr, secret) {
		t.Fatalf("binary leaked DB password: %s", outStr)
	}
}

func TestRedactString(t *testing.T) {
	raw := "failed connecting postgres://user:myPass@10.0.0.1:5432/db password='kvSecret' -----BEGIN RSA PRIVATE KEY-----"
	redacted := redactString(raw, "myPass")
	for _, forbidden := range []string{"myPass", "kvSecret", "BEGIN RSA PRIVATE KEY"} {
		if strings.Contains(redacted, forbidden) {
			t.Fatalf("redactString leaked %q in %q", forbidden, redacted)
		}
	}
	_ = observability.LogFormatJSON
}

func TestConfigAndRedaction_ErrorsJoinAndNonLoopbackGitURL(t *testing.T) {
	joinedSecret := "JoinSecret99!"
	domErr := domain.WrapError(
		domain.ErrUnavailable,
		"DATABASE_UNAVAILABLE",
		"failed connecting to postgres://cust:"+joinedSecret+"@10.0.0.1:5432/db",
		errors.New("underlying cause "+joinedSecret),
	)
	wrapped := errors.Join(errors.New("outer failure "+joinedSecret), domErr)
	code, msg := sanitizeErrorMessage(wrapped, joinedSecret)
	if code != "DATABASE_UNAVAILABLE" {
		t.Fatalf("expected DATABASE_UNAVAILABLE code, got %q", code)
	}
	if strings.Contains(msg, joinedSecret) || strings.Contains(msg, "underlying cause") {
		t.Fatalf("sanitizeErrorMessage leaked secret/cause from errors.Join: %q", msg)
	}

	pemStr := generateTestRSAKeyPEM(t)
	snapDir := t.TempDir()
	baseEnv := func(extra map[string]string) func(string) string {
		m := map[string]string{
			"CUSTODIAN_DATABASE_URL":                 "postgres://u:p@127.0.0.1:5432/custodian?sslmode=disable",
			"CUSTODIAN_SNAPSHOT_STORE":               "local",
			"CUSTODIAN_SNAPSHOT_DIR":                 snapDir,
			"CUSTODIAN_GITHUB_API_URL":               "http://127.0.0.1:18080/api/v3/",
			"CUSTODIAN_GITHUB_WRITE_APP_ID":          "202",
			"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM": pemStr,
		}
		for k, v := range extra {
			m[k] = v
		}
		return mapEnv(m)
	}

	// Non-loopback HTTP GIT URL with loopback API URL must default AllowInsecureHTTP to false.
	cfgNonLoopbackHTTP, err := loadConfig(baseEnv(map[string]string{
		"CUSTODIAN_GITHUB_GIT_URL": "http://git.example.com/",
	}))
	if err != nil {
		t.Fatalf("loadConfig non-loopback git url: %v", err)
	}
	if cfgNonLoopbackHTTP.AllowInsecureHTTP {
		t.Fatalf("expected AllowInsecureHTTP=false when CUSTODIAN_GITHUB_GIT_URL is non-loopback")
	}

	// Non-loopback HTTPS GIT URL with loopback API URL must also default AllowInsecureHTTP to false.
	cfgNonLoopbackHTTPS, err := loadConfig(baseEnv(map[string]string{
		"CUSTODIAN_GITHUB_GIT_URL": "https://github.com/",
	}))
	if err != nil {
		t.Fatalf("loadConfig https git url: %v", err)
	}
	if cfgNonLoopbackHTTPS.AllowInsecureHTTP {
		t.Fatalf("expected AllowInsecureHTTP=false when CUSTODIAN_GITHUB_GIT_URL is https://github.com/")
	}

	// Both API and GIT URLs loopback HTTP -> AllowInsecureHTTP defaults to true.
	cfgBothLoopback, err := loadConfig(baseEnv(map[string]string{
		"CUSTODIAN_GITHUB_GIT_URL": "http://localhost:18081/git",
	}))
	if err != nil {
		t.Fatalf("loadConfig both loopback: %v", err)
	}
	if !cfgBothLoopback.AllowInsecureHTTP {
		t.Fatalf("expected AllowInsecureHTTP=true when both API and GIT URLs are loopback HTTP")
	}
}
