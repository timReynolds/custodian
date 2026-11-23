package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// RepoSeedSpec configures a repository seeded into BareGitHelper during NewEnv.
type RepoSeedSpec struct {
	Owner          string
	Name           string
	Files          map[string]string
	DefaultBranch  string
	RepoID         int64
	InstallationID int64
}

type envConfig struct {
	repoRoot           string
	binDir             string
	contracts          *Contracts
	skipServices       bool
	skipPostgres       bool
	allowDockerSkip    bool
	postgresDSN        string
	seedRepos          []RepoSeedSpec
	perRepoConcurrency int
	globalScanBudget   int
	globalModelBudget  int
	retentionTTL       time.Duration
	policyBundleDir    string
	envOverrides       map[string]string
}

// EnvOption configures NewEnv.
type EnvOption func(*envConfig)

func WithRepoRoot(root string) EnvOption   { return func(c *envConfig) { c.repoRoot = root } }
func WithBinDir(dir string) EnvOption      { return func(c *envConfig) { c.binDir = dir } }
func WithContract(ct *Contracts) EnvOption { return func(c *envConfig) { c.contracts = ct.Clone() } }
func WithSkipServices() EnvOption          { return func(c *envConfig) { c.skipServices = true } }
func WithSkipPostgres() EnvOption          { return func(c *envConfig) { c.skipPostgres = true } }
func WithAllowDockerSkip(allow bool) EnvOption {
	return func(c *envConfig) { c.allowDockerSkip = allow }
}
func WithPostgresDSN(dsn string) EnvOption       { return func(c *envConfig) { c.postgresDSN = dsn } }
func WithPerRepoConcurrency(n int) EnvOption     { return func(c *envConfig) { c.perRepoConcurrency = n } }
func WithGlobalScanBudget(n int) EnvOption       { return func(c *envConfig) { c.globalScanBudget = n } }
func WithGlobalModelBudget(n int) EnvOption      { return func(c *envConfig) { c.globalModelBudget = n } }
func WithRetentionTTL(d time.Duration) EnvOption { return func(c *envConfig) { c.retentionTTL = d } }
func WithPolicyBundleDir(dir string) EnvOption   { return func(c *envConfig) { c.policyBundleDir = dir } }
func WithSeedRepos(specs ...RepoSeedSpec) EnvOption {
	return func(c *envConfig) { c.seedRepos = append(c.seedRepos, specs...) }
}
func WithEnvOverrides(env map[string]string) EnvOption {
	return func(c *envConfig) {
		if c.envOverrides == nil {
			c.envOverrides = make(map[string]string)
		}
		for k, v := range env {
			c.envOverrides[k] = v
		}
	}
}

// Env orchestrates an isolated opaque-box Custodian E2E environment with ephemeral ports,
// isolated credentials per component, local doubles, and deterministic cleanup.
type Env struct {
	t         testing.TB
	cfg       envConfig
	contracts *Contracts
	workDir   string
	repoRoot  string

	pg        *PGDocker
	git       *BareGitHelper
	github    *MockGitHub
	snapshots *SnapshotStoreHelper
	oidc      *MockOIDC
	gateway   *MockGateway
	scanners  *StubScannerController

	mu         sync.RWMutex
	binaries   map[string]string
	apiAddr    string
	apiBaseURL string
	capSecret  string

	apiProc       *managedProc
	workerProc    *managedProc
	publisherProc *managedProc

	secretMu sync.Mutex
	secrets  []string

	closeOnce sync.Once
}

func detectRepoRoot(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if envRoot := strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_ROOT")); envRoot != "" {
		return envRoot
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	cur := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur
		}
		if _, err := os.Stat(filepath.Join(cur, "test", "e2e", "run_e2e.sh")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return wd
}

func reserveLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr, nil
}

func randomHex(nBytes int) string {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand failure: %v", err))
	}
	return hex.EncodeToString(buf)
}

// NewEnv starts an isolated Custodian E2E environment and registers t.Cleanup(e.Close).
func NewEnv(t *testing.T, opts ...EnvOption) *Env {
	t.Helper()

	cfg := envConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	repoRoot := detectRepoRoot(cfg.repoRoot)
	contracts := cfg.contracts
	if contracts == nil {
		var err error
		contracts, err = LoadContracts(repoRoot)
		if err != nil {
			t.Fatalf("LoadContracts(%q): %v", repoRoot, err)
		}
	}

	workDir := t.TempDir()
	capSecret := randomHex(32)

	e := &Env{
		t:         t,
		cfg:       cfg,
		contracts: contracts,
		workDir:   workDir,
		repoRoot:  repoRoot,
		capSecret: capSecret,
	}
	t.Cleanup(e.Close)

	e.RegisterSecret(capSecret)

	if !cfg.skipPostgres {
		var pgOpts []PGOption
		if cfg.postgresDSN != "" {
			pgOpts = append(pgOpts, WithPGExternalDSN(cfg.postgresDSN))
		}
		if cfg.allowDockerSkip {
			pgOpts = append(pgOpts, WithPGAllowDockerSkip(true))
		}
		e.pg = StartPGDocker(t, pgOpts...)
	}

	e.git = NewBareGitHelper(t, filepath.Join(workDir, "bare-repos"))
	for _, spec := range cfg.seedRepos {
		var seedOpts []RepoSeedOption
		if spec.DefaultBranch != "" {
			seedOpts = append(seedOpts, WithDefaultBranch(spec.DefaultBranch))
		}
		if spec.RepoID > 0 {
			seedOpts = append(seedOpts, WithRepoID(spec.RepoID))
		}
		if spec.InstallationID > 0 {
			seedOpts = append(seedOpts, WithInstallationID(spec.InstallationID))
		}
		if _, err := e.git.InitSeededRepo(spec.Owner, spec.Name, spec.Files, seedOpts...); err != nil {
			t.Fatalf("seed repo %s/%s: %v", spec.Owner, spec.Name, err)
		}
	}

	e.github = StartMockGitHub(t, e.git, 101, 202)
	e.RegisterSecret(e.github.ReadAppPrivateKeyPEM())
	e.RegisterSecret(e.github.WriteAppPrivateKeyPEM())

	e.snapshots = NewSnapshotStoreHelper(t, filepath.Join(workDir, "snapshots"))
	e.oidc = StartMockOIDC(t, "custodian-api")
	e.gateway = NewMockGateway(t, contracts)
	e.scanners = NewStubScannerController(t)

	if !cfg.skipServices {
		e.startManagedServices()
	}

	return e
}

func (e *Env) startManagedServices() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	bins, err := BuildOrLocateBinaries(ctx, "", e.repoRoot, "", e.cfg.binDir, e.contracts.Binaries)
	if err != nil {
		e.t.Fatalf("BuildOrLocateBinaries: %v", err)
	}
	e.mu.Lock()
	e.binaries = bins
	e.mu.Unlock()

	policyDir := e.cfg.policyBundleDir
	if policyDir == "" && e.repoRoot != "" {
		candidate := filepath.Join(e.repoRoot, "policies", "defaults")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			policyDir = candidate
		}
	}

	dsn := ""
	if e.pg != nil {
		dsn = e.pg.DSN()
	}

	// Build strictly credential-isolated process environments (§14).
	baseCommon := map[string]string{
		e.contracts.EnvDatabaseDSN:       dsn,
		e.contracts.EnvSnapshotStoreRoot: e.snapshots.RootDir(),
		e.contracts.EnvSnapshotStoreKind: "local",
		e.contracts.EnvLogFormat:         "json",
		e.contracts.EnvLogLevel:          "info",
	}
	if policyDir != "" {
		baseCommon[e.contracts.EnvPolicyBundleDir] = policyDir
	}
	if e.cfg.perRepoConcurrency > 0 {
		baseCommon[e.contracts.EnvRepoConcurrency] = strconv.Itoa(e.cfg.perRepoConcurrency)
	}
	if e.cfg.globalScanBudget > 0 {
		baseCommon[e.contracts.EnvGlobalScanBudget] = strconv.Itoa(e.cfg.globalScanBudget)
	}
	if e.cfg.globalModelBudget > 0 {
		baseCommon[e.contracts.EnvGlobalModelBudget] = strconv.Itoa(e.cfg.globalModelBudget)
	}
	if e.cfg.retentionTTL > 0 {
		baseCommon[e.contracts.EnvArtifactRetention] = e.cfg.retentionTTL.String()
	}

	mergeEnv := func(roleEnv map[string]string) map[string]string {
		out := make(map[string]string, len(baseCommon)+len(roleEnv)+len(e.cfg.envOverrides))
		for k, v := range baseCommon {
			if k != "" {
				out[k] = v
			}
		}
		for k, v := range roleEnv {
			if k != "" {
				out[k] = v
			}
		}
		for k, v := range e.cfg.envOverrides {
			if k != "" {
				out[k] = v
			}
		}
		return out
	}

	// custodian-api: NO write GitHub App private key.
	apiEnvBase := mergeEnv(map[string]string{
		e.contracts.EnvOIDCIssuer:       e.oidc.Issuer(),
		e.contracts.EnvOIDCJWKSURL:      e.oidc.JWKSURL(),
		e.contracts.EnvOIDCAudience:     e.oidc.Audience(),
		e.contracts.EnvCapabilitySecret: e.capSecret,
		e.contracts.EnvGitHubAPIBaseURL: e.github.BaseAPIURL(),
		e.contracts.EnvGitHubReadAppID:  strconv.FormatInt(e.github.ReadAppID(), 10),
		e.contracts.EnvGitHubReadKeyPEM: e.github.ReadAppPrivateKeyPEM(),
	})

	// Retry up to 3 times on rare ephemeral port bind TOCTOU race.
	var startErr error
	for attempt := 0; attempt < 3; attempt++ {
		addr, err := reserveLoopbackAddr()
		if err != nil {
			e.t.Fatalf("reserve loopback port: %v", err)
		}
		apiEnv := make(map[string]string, len(apiEnvBase)+1)
		for k, v := range apiEnvBase {
			apiEnv[k] = v
		}
		apiEnv[e.contracts.EnvListenAddr] = addr

		proc := newManagedProc("custodian-api", bins[e.contracts.Binaries.API], e.workDir, e.contracts.APIArgs, apiEnv)
		if err := proc.Start(); err != nil {
			startErr = err
			continue
		}
		baseURL := "http://" + addr
		if err := e.waitForAPI(baseURL, 15*time.Second); err != nil {
			_ = proc.Stop(2 * time.Second)
			startErr = fmt.Errorf("%w\nlogs:\n%s", err, proc.Logs())
			continue
		}
		e.apiAddr = addr
		e.apiBaseURL = baseURL
		e.apiProc = proc
		startErr = nil
		break
	}
	if startErr != nil {
		e.t.Fatalf("start custodian-api failed: %v", startErr)
	}

	// custodian-worker: read-only GitHub App + Model Gateway + stub scanners. NO write GitHub App key.
	workerRole := map[string]string{
		e.contracts.EnvGitHubAPIBaseURL: e.github.BaseAPIURL(),
		e.contracts.EnvGitHubReadAppID:  strconv.FormatInt(e.github.ReadAppID(), 10),
		e.contracts.EnvGitHubReadKeyPEM: e.github.ReadAppPrivateKeyPEM(),
		e.contracts.EnvModelGatewayURL:  e.gateway.URL(),
	}
	for k, v := range e.scanners.EnvMap(e.contracts) {
		workerRole[k] = v
	}
	e.workerProc = newManagedProc("custodian-worker", bins[e.contracts.Binaries.Worker], e.workDir, e.contracts.WorkerArgs, mergeEnv(workerRole))
	if err := e.workerProc.Start(); err != nil {
		e.t.Fatalf("start custodian-worker failed: %v", err)
	}

	// custodian-publisher: write-only GitHub App ONLY. NO Model Gateway URL or scanner PATH.
	pubRole := map[string]string{
		e.contracts.EnvGitHubAPIBaseURL:  e.github.BaseAPIURL(),
		e.contracts.EnvGitHubWriteAppID:  strconv.FormatInt(e.github.WriteAppID(), 10),
		e.contracts.EnvGitHubWriteKeyPEM: e.github.WriteAppPrivateKeyPEM(),
	}
	e.publisherProc = newManagedProc("custodian-publisher", bins[e.contracts.Binaries.Publisher], e.workDir, e.contracts.PublisherArgs, mergeEnv(pubRole))
	if err := e.publisherProc.Start(); err != nil {
		e.t.Fatalf("start custodian-publisher failed: %v", err)
	}
}

func (e *Env) waitForAPI(baseURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	probePaths := []string{e.contracts.ReadyPath, e.contracts.HealthPath}
	var lastErr error
	for time.Now().Before(deadline) {
		for _, p := range probePaths {
			if p == "" {
				continue
			}
			resp, err := client.Get(baseURL + p)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					return nil
				}
				lastErr = fmt.Errorf("GET %s returned status %d", p, resp.StatusCode)
			} else {
				lastErr = err
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("API readiness probe timed out")
	}
	return lastErr
}

// --- Core Accessors (SCOPE.md § Interface Contracts) ---

func (e *Env) MintToken(claims TokenClaims) string {
	return e.oidc.MintToken(claims)
}

func (e *Env) Client(token string) *APIClient {
	return NewAPIClient(e.apiBaseURL, token, e.contracts)
}

func (e *Env) RunCLI(bin string, args []string, env map[string]string) CLIResult {
	binPath := bin
	e.mu.RLock()
	p, ok := e.binaries[bin]
	e.mu.RUnlock()
	if ok {
		binPath = p
	} else if !filepath.IsAbs(bin) && (e.repoRoot != "" || e.cfg.binDir != "") {
		e.mu.Lock()
		if p2, ok2 := e.binaries[bin]; ok2 {
			binPath = p2
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			bins, err := BuildOrLocateBinaries(ctx, "", e.repoRoot, "", e.cfg.binDir, e.contracts.Binaries)
			cancel()
			if err == nil {
				e.binaries = bins
				if p3, ok3 := bins[bin]; ok3 {
					binPath = p3
				}
			}
		}
		e.mu.Unlock()
	}

	merged := make(map[string]string)
	for k, v := range e.scanners.EnvMap(e.contracts) {
		merged[k] = v
	}
	if e.apiBaseURL != "" {
		merged["CUSTODIAN_API_URL"] = e.apiBaseURL
	}
	if e.pg != nil {
		merged[e.contracts.EnvDatabaseDSN] = e.pg.DSN()
	}
	for k, v := range env {
		merged[k] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return RunBinary(ctx, binPath, e.workDir, args, merged)
}

func (e *Env) Git() *BareGitHelper              { return e.git }
func (e *Env) GitHub() *MockGitHub              { return e.github }
func (e *Env) Gateway() *MockGateway            { return e.gateway }
func (e *Env) Scanners() *StubScannerController { return e.scanners }
func (e *Env) DB() *PGDocker                    { return e.pg }
func (e *Env) Snapshots() *SnapshotStoreHelper  { return e.snapshots }
func (e *Env) OIDC() *MockOIDC                  { return e.oidc }
func (e *Env) APIBaseURL() string               { return e.apiBaseURL }
func (e *Env) WorkDir() string                  { return e.workDir }
func (e *Env) Contracts() *Contracts            { return e.contracts }

// RegisterSecret adds a synthetic or runtime secret to be checked by AssertNoSecretLeakInLogs.
func (e *Env) RegisterSecret(secret string) {
	if secret == "" {
		return
	}
	e.secretMu.Lock()
	defer e.secretMu.Unlock()
	e.secrets = append(e.secrets, secret)
}

// --- Daemon Lifecycle Controls (RG-10 Crash/Restart) ---

func (e *Env) StopWorker() error {
	if e.workerProc == nil {
		return nil
	}
	return e.workerProc.Stop(5 * time.Second)
}

func (e *Env) KillWorker() error {
	if e.workerProc == nil {
		return nil
	}
	return e.workerProc.Kill()
}

func (e *Env) RestartWorker() error {
	if e.workerProc == nil {
		return errors.New("worker process not initialized")
	}
	return e.workerProc.Restart(5 * time.Second)
}

func (e *Env) StopPublisher() error {
	if e.publisherProc == nil {
		return nil
	}
	return e.publisherProc.Stop(5 * time.Second)
}

func (e *Env) KillPublisher() error {
	if e.publisherProc == nil {
		return nil
	}
	return e.publisherProc.Kill()
}

func (e *Env) RestartPublisher() error {
	if e.publisherProc == nil {
		return errors.New("publisher process not initialized")
	}
	return e.publisherProc.Restart(5 * time.Second)
}

func (e *Env) StopAPI() error {
	if e.apiProc == nil {
		return nil
	}
	return e.apiProc.Stop(5 * time.Second)
}

func (e *Env) RestartAPI() error {
	if e.apiProc == nil {
		return errors.New("api process not initialized")
	}
	if err := e.apiProc.Restart(5 * time.Second); err != nil {
		return err
	}
	return e.waitForAPI(e.apiBaseURL, 15*time.Second)
}

// Logs returns captured stdout/stderr for "api", "worker", or "publisher".
func (e *Env) Logs(component string) string {
	switch strings.ToLower(strings.TrimSpace(component)) {
	case "api", "custodian-api":
		if e.apiProc != nil {
			return e.apiProc.Logs()
		}
	case "worker", "custodian-worker":
		if e.workerProc != nil {
			return e.workerProc.Logs()
		}
	case "publisher", "custodian-publisher":
		if e.publisherProc != nil {
			return e.publisherProc.Logs()
		}
	}
	return ""
}

// AllLogs returns combined logs across all managed Custodian daemons.
func (e *Env) AllLogs() string {
	var b strings.Builder
	for _, comp := range []string{"api", "worker", "publisher"} {
		if l := e.Logs(comp); l != "" {
			b.WriteString("=== ")
			b.WriteString(comp)
			b.WriteString(" ===\n")
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// AssertNoSecretLeakInLogs checks daemon logs against registered secrets, extraSecrets, and common key markers.
func (e *Env) AssertNoSecretLeakInLogs(extraSecrets ...string) {
	e.t.Helper()
	all := e.AllLogs()
	AssertLogIDsAndDigestsOnly(e.t, all)

	e.secretMu.Lock()
	combined := append([]string(nil), e.secrets...)
	e.secretMu.Unlock()
	combined = append(combined, extraSecrets...)

	if len(combined) > 0 {
		AssertNoSecretOrEncodedLeak(e.t, all, combined...)
	}
}

// Close tears down all managed processes, mock servers, and the ephemeral PG container.
func (e *Env) Close() {
	e.closeOnce.Do(func() {
		if e.publisherProc != nil {
			_ = e.publisherProc.Stop(3 * time.Second)
		}
		if e.workerProc != nil {
			_ = e.workerProc.Stop(3 * time.Second)
		}
		if e.apiProc != nil {
			_ = e.apiProc.Stop(3 * time.Second)
		}
		if e.gateway != nil {
			e.gateway.Close()
		}
		if e.github != nil {
			e.github.Close()
		}
		if e.oidc != nil {
			e.oidc.Close()
		}
		if e.snapshots != nil {
			_ = e.snapshots.SimulateOutage(false)
		}
		if e.pg != nil {
			_ = e.pg.Close()
		}
	})
}
