package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/harness"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

func TestCLI_HelpAndInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, func(string) string { return "" }, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("args %v: expected exit 0, got %d (stderr=%s)", args, code, stderr.String())
		}
		if strings.TrimSpace(stdout.String()) == "" {
			t.Fatalf("args %v: expected non-empty usage output", args)
		}
		if strings.Contains(stdout.String()+stderr.String(), "panic:") {
			t.Fatalf("args %v: unexpected panic output", args)
		}
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--unknown-flag"}, func(string) string { return "" }, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown flag: expected exit 2, got %d", code)
	}
}

func TestCLI_MissingAndUnreachableDSN_NoSecretLeak(t *testing.T) {
	tmpDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)

	// 1. Missing CUSTODIAN_DATABASE_URL exits non-zero cleanly without panic.
	var out1, err1 bytes.Buffer
	code1 := run(context.Background(), nil, func(k string) string {
		switch k {
		case "CUSTODIAN_SNAPSHOT_DIR":
			return tmpDir
		case "CUSTODIAN_GITHUB_READ_APP_ID":
			return "123"
		case "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":
			return pemStr
		default:
			return ""
		}
	}, &out1, &err1)
	if code1 == 0 {
		t.Fatalf("expected non-zero exit on missing DSN")
	}
	combined1 := out1.String() + err1.String()
	if strings.Contains(combined1, "panic:") {
		t.Fatalf("unexpected panic on missing DSN: %s", combined1)
	}

	// 2. Unreachable DSN with password must exit non-zero cleanly and never leak password or private key.
	secretPass := "supersecretpass123"
	var out2, err2 bytes.Buffer
	code2 := run(context.Background(), nil, func(k string) string {
		switch k {
		case "CUSTODIAN_DATABASE_URL":
			return "postgres://bad:" + secretPass + "@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
		case "CUSTODIAN_SNAPSHOT_DIR":
			return tmpDir
		case "CUSTODIAN_GITHUB_READ_APP_ID":
			return "123"
		case "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":
			return pemStr
		default:
			return ""
		}
	}, &out2, &err2)
	if code2 == 0 {
		t.Fatalf("expected non-zero exit on unreachable DB")
	}
	combined2 := out2.String() + err2.String()
	if strings.Contains(combined2, "panic:") {
		t.Fatalf("unexpected panic on unreachable DB: %s", combined2)
	}
	if strings.Contains(combined2, secretPass) || strings.Contains(combined2, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("secret leaked in unreachable DB error output: %s", combined2)
	}
}

func TestConfig_NoWriteAppOrAPIEnvRequired_AndLoopbackGitDerivation(t *testing.T) {
	tmpDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)

	cfg, err := loadConfig(func(k string) string {
		switch k {
		case "CUSTODIAN_DATABASE_URL":
			return "postgres://user:pass@127.0.0.1:5432/custodian?sslmode=disable"
		case "CUSTODIAN_SNAPSHOT_DIR":
			return tmpDir
		case "CUSTODIAN_GITHUB_API_URL":
			return "http://127.0.0.1:41234/"
		case "CUSTODIAN_GITHUB_READ_APP_ID":
			return "42"
		case "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":
			return pemStr
		case "CUSTODIAN_GLOBAL_SCAN_BUDGET":
			return "3"
		case "CUSTODIAN_GLOBAL_MODEL_BUDGET":
			return "2"
		case "CUSTODIAN_REPO_CONCURRENCY_LIMIT":
			return "4"
		case "CUSTODIAN_ARTIFACT_RETENTION_TTL":
			return "5m"
		case "CUSTODIAN_RETENTION_INTERVAL":
			return "200ms"
		case "CUSTODIAN_SCANNER_TIMEOUT":
			return "2s"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.GitHubGitBaseURL != "http://127.0.0.1:41234" {
		t.Fatalf("expected derived GitHubGitBaseURL=http://127.0.0.1:41234, got %q", cfg.GitHubGitBaseURL)
	}
	if !cfg.AllowInsecureHTTP {
		t.Fatalf("expected AllowInsecureHTTP=true for loopback HTTP API URL")
	}
	if cfg.LeaseDuration != 15*time.Second || cfg.HeartbeatInterval != 5*time.Second || cfg.ReapInterval != 5*time.Second || cfg.PollInterval != 150*time.Millisecond {
		t.Fatalf("unexpected default timings: %+v", cfg)
	}
	if cfg.GlobalScanBudget != 3 || cfg.GlobalModelBudget != 2 || cfg.RepoConcurrencyLimit != 4 {
		t.Fatalf("unexpected budget caps: %+v", cfg)
	}
	if cfg.Inspection.ScannerTimeout != 2*time.Second {
		t.Fatalf("expected ScannerTimeout=2s, got %s", cfg.Inspection.ScannerTimeout)
	}
}

func TestConfig_GitHubGitBaseURLDerivation(t *testing.T) {
	tmpDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)

	cases := []struct {
		name              string
		apiURL            string
		gitURL            string
		wantAPIBase       string
		wantGitBase       string
		wantAllowInsecure bool
	}{
		{
			name:              "default github api url",
			wantAPIBase:       "https://api.github.com/",
			wantGitBase:       "",
			wantAllowInsecure: false,
		},
		{
			name:              "explicit default github api url without trailing slash",
			apiURL:            "https://api.github.com",
			wantAPIBase:       "https://api.github.com",
			wantGitBase:       "",
			wantAllowInsecure: false,
		},
		{
			name:              "mock github api v3 url with trailing slash",
			apiURL:            "http://127.0.0.1:41234/api/v3/",
			wantAPIBase:       "http://127.0.0.1:41234/api/v3/",
			wantGitBase:       "http://127.0.0.1:41234",
			wantAllowInsecure: true,
		},
		{
			name:              "mock github api v3 url without trailing slash",
			apiURL:            "http://127.0.0.1:41234/api/v3",
			wantAPIBase:       "http://127.0.0.1:41234/api/v3",
			wantGitBase:       "http://127.0.0.1:41234",
			wantAllowInsecure: true,
		},
		{
			name:              "loopback root url without api v3",
			apiURL:            "http://127.0.0.1:41234/",
			wantAPIBase:       "http://127.0.0.1:41234/",
			wantGitBase:       "http://127.0.0.1:41234",
			wantAllowInsecure: true,
		},
		{
			name:              "ghes api v3 url with query and fragment",
			apiURL:            "https://ghes.example.com/api/v3/?x=1#frag",
			wantAPIBase:       "https://ghes.example.com/api/v3/?x=1#frag",
			wantGitBase:       "https://ghes.example.com",
			wantAllowInsecure: false,
		},
		{
			name:              "ghes subpath api v3 url",
			apiURL:            "https://ghes.example.com/subpath/api/v3/",
			wantAPIBase:       "https://ghes.example.com/subpath/api/v3/",
			wantGitBase:       "https://ghes.example.com/subpath",
			wantAllowInsecure: false,
		},
		{
			name:              "explicit git url overrides derivation",
			apiURL:            "http://127.0.0.1:41234/api/v3/",
			gitURL:            "http://127.0.0.1:50000/custom",
			wantAPIBase:       "http://127.0.0.1:41234/api/v3/",
			wantGitBase:       "http://127.0.0.1:50000/custom",
			wantAllowInsecure: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(func(k string) string {
				switch k {
				case "CUSTODIAN_DATABASE_URL":
					return "postgres://user:pass@127.0.0.1:5432/custodian?sslmode=disable"
				case "CUSTODIAN_SNAPSHOT_DIR":
					return tmpDir
				case "CUSTODIAN_GITHUB_API_URL":
					return tc.apiURL
				case "CUSTODIAN_GITHUB_GIT_URL":
					return tc.gitURL
				case "CUSTODIAN_GITHUB_READ_APP_ID":
					return "42"
				case "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":
					return pemStr
				default:
					return ""
				}
			})
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if cfg.GitHubAPIBaseURL != tc.wantAPIBase {
				t.Fatalf("GitHubAPIBaseURL = %q, want %q", cfg.GitHubAPIBaseURL, tc.wantAPIBase)
			}
			if cfg.GitHubGitBaseURL != tc.wantGitBase {
				t.Fatalf("GitHubGitBaseURL = %q, want %q", cfg.GitHubGitBaseURL, tc.wantGitBase)
			}
			if cfg.AllowInsecureHTTP != tc.wantAllowInsecure {
				t.Fatalf("AllowInsecureHTTP = %v, want %v", cfg.AllowInsecureHTTP, tc.wantAllowInsecure)
			}
		})
	}
}

func TestCLI_JSONLogsAndGracefulShutdown_PG17(t *testing.T) {
	pg := harness.StartPostgres(t, harness.WithPGAllowDockerSkip(true))
	snapDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	policyDir := filepath.Clean(filepath.Join(wd, "..", "..", "policies", "defaults"))

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan int, 1)

	go func() {
		done <- run(ctx, nil, func(k string) string {
			switch k {
			case "CUSTODIAN_DATABASE_URL":
				return pg.DSN()
			case "CUSTODIAN_SNAPSHOT_DIR":
				return snapDir
			case "CUSTODIAN_SNAPSHOT_STORE":
				return "local"
			case "CUSTODIAN_POLICY_DIR":
				return policyDir
			case "CUSTODIAN_GITHUB_API_URL":
				return "http://127.0.0.1:19999"
			case "CUSTODIAN_GITHUB_READ_APP_ID":
				return "101"
			case "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":
				return pemStr
			case "CUSTODIAN_LOG_FORMAT":
				return "json"
			case "CUSTODIAN_LOG_LEVEL":
				return "info"
			default:
				return ""
			}
		}, &stdout, &stderr)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "worker started") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("expected exit 0 on graceful shutdown, got %d (stderr=%s)", code, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("worker did not shut down cleanly within 3s")
	}

	jsonLines := 0
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSON log line %q: %v", line, err)
		}
		jsonLines++
	}
	if jsonLines == 0 {
		t.Fatalf("expected structured JSON log lines, got stdout=%q", stdout.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("private key leaked into logs")
	}
}

type fakeGatewayClient struct {
	calls atomic.Int32
}

func (f *fakeGatewayClient) Invoke(_ context.Context, _ decisions.GatewayRequest) (decisions.GatewayResponse, error) {
	f.calls.Add(1)
	return decisions.GatewayResponse{
		RawBody:      []byte(`{"schema_version":"1","assessment_type":"IP_PROVENANCE","risk":"LOW","disposition":"CLEAR","confidence":0.95,"summary":"ok","findings":[],"limitations":[]}`),
		ModelVersion: "v1",
		StatusCode:   200,
	}, nil
}

func TestConfig_RetentionAlignmentAndWorkerRoutePolicy(t *testing.T) {
	tmpDir := t.TempDir()
	pemStr := generateTestRSAPEM(t)
	baseEnv := func(extra map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			switch k {
			case "CUSTODIAN_DATABASE_URL":
				return "postgres://user:pass@127.0.0.1:5432/custodian?sslmode=disable"
			case "CUSTODIAN_SNAPSHOT_DIR":
				return tmpDir
			case "CUSTODIAN_GITHUB_READ_APP_ID":
				return "42"
			case "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM":
				return pemStr
			default:
				return ""
			}
		}
	}

	cfgDefault, err := loadConfig(baseEnv(nil))
	if err != nil {
		t.Fatalf("loadConfig(default): %v", err)
	}
	if cfgDefault.ArtifactRetentionTTL != 720*time.Hour {
		t.Fatalf("default ArtifactRetentionTTL=%v, want 720h", cfgDefault.ArtifactRetentionTTL)
	}

	cfgAlias, err := loadConfig(baseEnv(map[string]string{
		"CUSTODIAN_ARTIFACT_RETENTION":     "48h",
		"CUSTODIAN_ARTIFACT_RETENTION_TTL": "12h",
	}))
	if err != nil {
		t.Fatalf("loadConfig(alias): %v", err)
	}
	if cfgAlias.ArtifactRetentionTTL != 48*time.Hour {
		t.Fatalf("CUSTODIAN_ARTIFACT_RETENTION should take precedence, got %v", cfgAlias.ArtifactRetentionTTL)
	}

	gw := &fakeGatewayClient{}
	decSvc, err := newDecisionsService(gw, cfgDefault, nil, nil, nil)
	if err != nil {
		t.Fatalf("newDecisionsService: %v", err)
	}
	resBlocked, err := decSvc.Assess(context.Background(), decisions.AssessRequest{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		Repository: domain.Repository{
			ID:             domain.MustNewID(),
			FullName:       "acme/secret-repo",
			Classification: domain.ClassificationConfidential,
			Enabled:        true,
		},
		AllowedModelRoutes: []string{"openai/gpt-5", "approved-code-review"},
		ModelRoute:         "openai/gpt-5",
		AssessmentType:     "IP_PROVENANCE",
		ChangedPaths:       []string{"main.go"},
		CanonicalDiff:      "+func x() {}",
	})
	if err != nil {
		t.Fatalf("Assess(openai/gpt-5): %v", err)
	}
	if gw.calls.Load() != 0 || resBlocked.Status != domain.AssessmentStatusIndeterminate {
		t.Fatalf("expected 0 gateway calls and INDETERMINATE for openai/gpt-5 on CONFIDENTIAL, got calls=%d status=%s", gw.calls.Load(), resBlocked.Status)
	}

	resAllowed, err := decSvc.Assess(context.Background(), decisions.AssessRequest{
		ProposalID: domain.MustNewID(),
		ArtifactID: domain.MustNewID(),
		Repository: domain.Repository{
			ID:             domain.MustNewID(),
			FullName:       "acme/secret-repo",
			Classification: domain.ClassificationConfidential,
			Enabled:        true,
		},
		AllowedModelRoutes: []string{"openai/gpt-5", "approved-code-review"},
		ModelRoute:         "approved-code-review",
		AssessmentType:     "IP_PROVENANCE",
		ChangedPaths:       []string{"main.go"},
		CanonicalDiff:      "+func x() {}",
	})
	if err != nil {
		t.Fatalf("Assess(approved-code-review): %v", err)
	}
	if gw.calls.Load() != 1 || resAllowed.Status != domain.AssessmentStatusComplete {
		t.Fatalf("expected 1 gateway call and COMPLETE for approved-code-review, got calls=%d status=%s", gw.calls.Load(), resAllowed.Status)
	}
}
