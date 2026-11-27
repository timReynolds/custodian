package harness

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
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

type gitGatewayConfig struct {
	maxPackBytes      int64
	maxObjects        int
	maxInflatedBytes  int64
	maxRefUpdates     int
	defaultEgressMode string
	passiveDelivery   string
	sshUserCAFile     string
	sshHostKeyFile    string
	extraEnv          map[string]string
	skipReadyWait     bool
}

// GitGatewayOption configures the managed custodian-git-gateway subprocess when WithGitGateway is enabled.
type GitGatewayOption func(*gitGatewayConfig)

func WithGitGatewayMaxPackBytes(n int64) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.maxPackBytes = n }
}
func WithGitGatewayMaxObjects(n int) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.maxObjects = n }
}
func WithGitGatewayMaxInflatedBytes(n int64) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.maxInflatedBytes = n }
}
func WithGitGatewayMaxRefUpdates(n int) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.maxRefUpdates = n }
}
func WithGitGatewayDefaultEgressMode(mode string) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.defaultEgressMode = mode }
}
func WithGitGatewayPassiveDelivery(delivery string) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.passiveDelivery = delivery }
}
func WithGitGatewaySSHUserCAPubKey(pubKeyPath string) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.sshUserCAFile = pubKeyPath }
}
func WithGitGatewaySSHHostKey(privKeyPath string) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.sshHostKeyFile = privKeyPath }
}
func WithGitGatewayExtraEnv(env map[string]string) GitGatewayOption {
	return func(c *gitGatewayConfig) {
		if c.extraEnv == nil {
			c.extraEnv = make(map[string]string)
		}
		for k, v := range env {
			c.extraEnv[k] = v
		}
	}
}
func WithGitGatewaySkipReadyWait(skip bool) GitGatewayOption {
	return func(c *gitGatewayConfig) { c.skipReadyWait = skip }
}

// EphemeralTLSBundle contains an ephemeral ECDSA P-256 CA and localhost/127.0.0.1 server certificate bundle.
type EphemeralTLSBundle struct {
	CACertPath     string
	ServerCertPath string
	ServerKeyPath  string
	CertPool       *x509.CertPool
	CACertPEM      string
	CAKeyPEM       string
	ServerCertPEM  string
	ServerKeyPEM   string
}

// GenerateEphemeralGatewayTLS generates a self-signed ECDSA P-256 CA and server certificate valid for
// 127.0.0.1, ::1, and localhost, writing ca.crt, server.crt, and server.key under dir.
func GenerateEphemeralGatewayTLS(dir string) (EphemeralTLSBundle, error) {
	if strings.TrimSpace(dir) == "" {
		return EphemeralTLSBundle{}, errors.New("tls output directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("mkdir tls dir %q: %w", dir, err)
	}

	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("generate CA serial: %w", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "Custodian E2E Ephemeral Gateway CA",
			Organization: []string{"Custodian E2E"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("parse CA cert: %w", err)
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("marshal CA key: %w", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("generate server key: %w", err)
	}
	srvSerial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("generate server serial: %w", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: srvSerial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Custodian E2E"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("create server cert: %w", err)
	}
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("marshal server key: %w", err)
	}
	srvLeafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvChainPEM := append(append([]byte(nil), srvLeafPEM...), caCertPEM...)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})

	caCertPath := filepath.Join(dir, "ca.crt")
	srvCertPath := filepath.Join(dir, "server.crt")
	srvKeyPath := filepath.Join(dir, "server.key")

	if err := os.WriteFile(caCertPath, caCertPEM, 0o644); err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("write %q: %w", caCertPath, err)
	}
	if err := os.WriteFile(srvCertPath, srvChainPEM, 0o644); err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("write %q: %w", srvCertPath, err)
	}
	if err := os.WriteFile(srvKeyPath, srvKeyPEM, 0o600); err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("write %q: %w", srvKeyPath, err)
	}
	if err := os.Chmod(srvKeyPath, 0o600); err != nil {
		return EphemeralTLSBundle{}, fmt.Errorf("chmod 0600 %q: %w", srvKeyPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return EphemeralTLSBundle{}, errors.New("append generated CA cert to CertPool failed")
	}

	return EphemeralTLSBundle{
		CACertPath:     caCertPath,
		ServerCertPath: srvCertPath,
		ServerKeyPath:  srvKeyPath,
		CertPool:       pool,
		CACertPEM:      string(caCertPEM),
		CAKeyPEM:       string(caKeyPEM),
		ServerCertPEM:  string(srvChainPEM),
		ServerKeyPEM:   string(srvKeyPEM),
	}, nil
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
	enableGitGateway   bool
	gitGatewayCfg      gitGatewayConfig
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
func WithGitGateway(opts ...GitGatewayOption) EnvOption {
	return func(c *envConfig) {
		c.enableGitGateway = true
		for _, opt := range opts {
			if opt != nil {
				opt(&c.gitGatewayCfg)
			}
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

	sshCA                *SSHCAHelper
	gitGatewayProc       *managedProc
	gitGatewayHTTPAddr   string
	gitGatewayHTTPSURL   string
	gitGatewaySSHAddr    string
	gitGatewayCACertPath string
	gitGatewayTLSKeyPath string
	gitGatewayCertPool   *x509.CertPool

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
	if cfg.enableGitGateway {
		e.sshCA = NewSSHCAHelper(t, WithSSHRootDir(filepath.Join(workDir, "ssh-ca")), WithSSHSecretRecorder(e.RegisterSecret))
	}

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

	if e.cfg.enableGitGateway {
		e.startGitGateway(ctx, mergeEnv)
	}
}

func (e *Env) startGitGateway(ctx context.Context, mergeEnv func(map[string]string) map[string]string) {
	e.t.Helper()

	gwBin, err := BuildPushGatewayBinary(ctx, "", e.repoRoot, "", e.cfg.binDir, e.contracts.Binaries)
	if err != nil {
		e.t.Fatalf("BuildPushGatewayBinary: %v", err)
	}
	gwBinName := e.contracts.Binaries.GitGateway
	if gwBinName == "" {
		gwBinName = PushGatewayBinary
	}
	e.mu.Lock()
	if e.binaries == nil {
		e.binaries = make(map[string]string)
	}
	e.binaries[gwBinName] = gwBin
	e.mu.Unlock()

	tlsBundle, err := GenerateEphemeralGatewayTLS(filepath.Join(e.workDir, "git-gateway-tls"))
	if err != nil {
		e.t.Fatalf("GenerateEphemeralGatewayTLS: %v", err)
	}
	e.RegisterSecret(tlsBundle.ServerKeyPEM)
	e.RegisterSecret(tlsBundle.CAKeyPEM)
	e.gitGatewayCACertPath = tlsBundle.CACertPath
	e.gitGatewayTLSKeyPath = tlsBundle.ServerKeyPath
	e.gitGatewayCertPool = tlsBundle.CertPool

	sshHelper := e.SSHCA()
	sshHelper.RegisterSecrets(e.RegisterSecret)

	hostKeyFile := e.cfg.gitGatewayCfg.sshHostKeyFile
	if hostKeyFile == "" {
		hostKeyFile = sshHelper.HostKeyPath()
	}
	userCAFile := e.cfg.gitGatewayCfg.sshUserCAFile
	if userCAFile == "" {
		userCAFile = sshHelper.UserCAPubKeyPath()
	}

	gwRole := map[string]string{
		e.contracts.EnvOIDCIssuer:               e.oidc.Issuer(),
		e.contracts.EnvOIDCJWKSURL:              e.oidc.JWKSURL(),
		e.contracts.EnvOIDCAudience:             e.oidc.Audience(),
		e.contracts.EnvModelGatewayURL:          e.gateway.URL(),
		e.contracts.EnvGitHubAPIBaseURL:         e.github.BaseAPIURL(),
		e.contracts.EnvGitHubReadAppID:          strconv.FormatInt(e.github.ReadAppID(), 10),
		e.contracts.EnvGitHubReadKeyPEM:         e.github.ReadAppPrivateKeyPEM(),
		e.contracts.EnvGitHubWriteAppID:         strconv.FormatInt(e.github.WriteAppID(), 10),
		e.contracts.EnvGitHubWriteKeyPEM:        e.github.WriteAppPrivateKeyPEM(),
		e.contracts.EnvCapabilitySecret:         e.capSecret,
		e.contracts.EnvGitGatewayTLSCertFile:    tlsBundle.ServerCertPath,
		e.contracts.EnvGitGatewayTLSKeyFile:     tlsBundle.ServerKeyPath,
		e.contracts.EnvGitGatewaySSHHostKeyFile: hostKeyFile,
		e.contracts.EnvGitGatewaySSHUserCAFile:  userCAFile,
		e.contracts.EnvGitGatewayUpstreamURL:    e.github.URL(),
		e.contracts.EnvGitGatewayAPIBaseURL:     e.apiBaseURL,
	}
	for k, v := range e.scanners.EnvMap(e.contracts) {
		gwRole[k] = v
	}
	if e.cfg.gitGatewayCfg.maxPackBytes > 0 {
		gwRole[e.contracts.EnvGitGatewayMaxPackBytes] = strconv.FormatInt(e.cfg.gitGatewayCfg.maxPackBytes, 10)
	}
	if e.cfg.gitGatewayCfg.maxObjects > 0 {
		gwRole[e.contracts.EnvGitGatewayMaxObjects] = strconv.Itoa(e.cfg.gitGatewayCfg.maxObjects)
	}
	if e.cfg.gitGatewayCfg.maxInflatedBytes > 0 {
		gwRole[e.contracts.EnvGitGatewayMaxInflatedBytes] = strconv.FormatInt(e.cfg.gitGatewayCfg.maxInflatedBytes, 10)
	}
	if e.cfg.gitGatewayCfg.maxRefUpdates > 0 {
		gwRole[e.contracts.EnvGitGatewayMaxRefUpdates] = strconv.Itoa(e.cfg.gitGatewayCfg.maxRefUpdates)
	}
	if e.cfg.gitGatewayCfg.defaultEgressMode != "" {
		gwRole[e.contracts.EnvGitGatewayDefaultEgressMode] = e.cfg.gitGatewayCfg.defaultEgressMode
	}
	if e.cfg.gitGatewayCfg.passiveDelivery != "" {
		gwRole[e.contracts.EnvGitGatewayPassiveDelivery] = e.cfg.gitGatewayCfg.passiveDelivery
	}

	gwEnvBase := mergeEnv(gwRole)
	for k, v := range e.cfg.gitGatewayCfg.extraEnv {
		if k != "" {
			gwEnvBase[k] = v
		}
	}

	var startErr error
	for attempt := 0; attempt < 3; attempt++ {
		httpAddr, err := reserveLoopbackAddr()
		if err != nil {
			e.t.Fatalf("reserve gateway http loopback port: %v", err)
		}
		sshAddr, err := reserveLoopbackAddr()
		if err != nil {
			e.t.Fatalf("reserve gateway ssh loopback port: %v", err)
		}
		gwEnv := make(map[string]string, len(gwEnvBase)+2)
		for k, v := range gwEnvBase {
			gwEnv[k] = v
		}
		gwEnv[e.contracts.EnvGitGatewayHTTPAddr] = httpAddr
		gwEnv[e.contracts.EnvGitGatewaySSHAddr] = sshAddr

		proc := newManagedProc("custodian-git-gateway", gwBin, e.workDir, e.contracts.GitGatewayArgs, gwEnv)
		if err := proc.Start(); err != nil {
			startErr = err
			continue
		}
		httpsURL := "https://" + httpAddr
		if !e.cfg.gitGatewayCfg.skipReadyWait {
			if err := e.waitForGitGateway(httpsURL, sshAddr, tlsBundle.CertPool, 15*time.Second); err != nil {
				_ = proc.Stop(2 * time.Second)
				startErr = fmt.Errorf("%w\nlogs:\n%s", err, proc.Logs())
				continue
			}
		}
		e.gitGatewayHTTPAddr = httpAddr
		e.gitGatewayHTTPSURL = httpsURL
		e.gitGatewaySSHAddr = sshAddr
		e.gitGatewayProc = proc
		startErr = nil
		break
	}
	if startErr != nil {
		e.t.Fatalf("start custodian-git-gateway failed: %v", startErr)
	}
}

func (e *Env) waitForGitGateway(httpsURL, sshAddr string, certPool *x509.CertPool, timeout time.Duration) error {
	client := &http.Client{
		Timeout: time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
	deadline := time.Now().Add(timeout)
	probePaths := []string{e.contracts.ReadyPath, e.contracts.HealthPath}
	var lastErr error
	for time.Now().Before(deadline) {
		httpsOK := false
		for _, p := range probePaths {
			if p == "" {
				continue
			}
			resp, err := client.Get(httpsURL + p)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					httpsOK = true
					break
				}
				lastErr = fmt.Errorf("GET %s returned status %d", p, resp.StatusCode)
			} else {
				lastErr = err
			}
		}
		if httpsOK {
			if sshAddr == "" {
				return nil
			}
			conn, err := net.DialTimeout("tcp", sshAddr, 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return nil
			}
			lastErr = fmt.Errorf("SSH dial %s: %w", sshAddr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("git-gateway readiness probe timed out")
	}
	return lastErr
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

// BinaryPath resolves and returns the executable path for bin (locating from cache, binDir,
// CUSTODIAN_E2E_BIN_DIR, or building from repoRoot), returning bin unchanged if unresolved.
func (e *Env) BinaryPath(bin string) string {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return ""
	}
	e.mu.RLock()
	p, ok := e.binaries[bin]
	e.mu.RUnlock()
	if ok && p != "" {
		return p
	}
	if filepath.IsAbs(bin) || (e.repoRoot == "" && e.cfg.binDir == "" && strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_BIN_DIR")) == "") {
		return bin
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if p2, ok2 := e.binaries[bin]; ok2 && p2 != "" {
		return p2
	}
	if e.cfg.binDir != "" {
		candidate := filepath.Join(e.cfg.binDir, bin)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if e.binaries == nil {
				e.binaries = make(map[string]string)
			}
			e.binaries[bin] = candidate
			return candidate
		}
	}
	gwName := e.contracts.Binaries.GitGateway
	if gwName == "" {
		gwName = PushGatewayBinary
	}
	if bin == gwName || bin == PushGatewayBinary {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Minute)
		gwPath, gwErr := BuildPushGatewayBinary(ctx2, "", e.repoRoot, "", e.cfg.binDir, e.contracts.Binaries)
		cancel2()
		if gwErr == nil {
			if e.binaries == nil {
				e.binaries = make(map[string]string)
			}
			e.binaries[bin] = gwPath
			return gwPath
		}
		return bin
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	bins, err := BuildOrLocateBinaries(ctx, "", e.repoRoot, "", e.cfg.binDir, e.contracts.Binaries)
	cancel()
	if err == nil {
		if e.binaries == nil {
			e.binaries = make(map[string]string, len(bins))
		}
		for k, v := range bins {
			e.binaries[k] = v
		}
		if p3, ok3 := e.binaries[bin]; ok3 && p3 != "" {
			return p3
		}
	}
	return bin
}

func (e *Env) resolveCLIInvocation(bin string, env map[string]string) (string, map[string]string) {
	binPath := e.BinaryPath(bin)
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
	return binPath, merged
}

func (e *Env) RunCLI(bin string, args []string, env map[string]string) CLIResult {
	binPath, merged := e.resolveCLIInvocation(bin, env)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return RunBinary(ctx, binPath, e.workDir, args, merged)
}

func (e *Env) RunCLIWithStdin(bin string, args []string, env map[string]string, stdin string) CLIResult {
	binPath, merged := e.resolveCLIInvocation(bin, env)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var r io.Reader
	if stdin != "" {
		r = strings.NewReader(stdin)
	}
	return RunBinaryWithStdin(ctx, binPath, e.workDir, args, merged, r)
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
func (e *Env) GitGatewayHTTPSURL() string       { return e.gitGatewayHTTPSURL }
func (e *Env) GitGatewayCACertPath() string     { return e.gitGatewayCACertPath }
func (e *Env) GitGatewaySSHAddr() string        { return e.gitGatewaySSHAddr }

func (e *Env) GitGatewayMetricsURL() string {
	if e.gitGatewayHTTPSURL == "" {
		return ""
	}
	metricsPath := e.contracts.MetricsPath
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	if !strings.HasPrefix(metricsPath, "/") {
		metricsPath = "/" + metricsPath
	}
	return strings.TrimRight(e.gitGatewayHTTPSURL, "/") + metricsPath
}

func (e *Env) GitGatewayHTTPClient() *http.Client {
	if e.gitGatewayCertPool == nil {
		return &http.Client{Timeout: 30 * time.Second}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    e.gitGatewayCertPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

func (e *Env) SSHCA() *SSHCAHelper {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sshCA == nil {
		e.sshCA = NewSSHCAHelper(e.t, WithSSHRootDir(filepath.Join(e.workDir, "ssh-ca")), WithSSHSecretRecorder(e.RegisterSecret))
	}
	return e.sshCA
}

// RegisterSecret adds a synthetic or runtime secret to be checked by AssertNoSecretLeakInLogs.
func (e *Env) RegisterSecret(secret string) {
	if secret == "" {
		return
	}
	e.secretMu.Lock()
	defer e.secretMu.Unlock()
	for _, existing := range e.secrets {
		if existing == secret {
			return
		}
	}
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

func (e *Env) StopGitGateway() error {
	if e.gitGatewayProc == nil {
		return nil
	}
	return e.gitGatewayProc.Stop(5 * time.Second)
}

func (e *Env) KillGitGateway() error {
	if e.gitGatewayProc == nil {
		return nil
	}
	return e.gitGatewayProc.Kill()
}

func (e *Env) RestartGitGateway() error {
	if e.gitGatewayProc == nil {
		return errors.New("git-gateway process not initialized")
	}
	if err := e.gitGatewayProc.Restart(5 * time.Second); err != nil {
		return err
	}
	if e.cfg.gitGatewayCfg.skipReadyWait {
		return nil
	}
	return e.waitForGitGateway(e.gitGatewayHTTPSURL, e.gitGatewaySSHAddr, e.gitGatewayCertPool, 15*time.Second)
}

// Logs returns captured stdout/stderr for "api", "worker", "publisher", or "git-gateway".
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
	case "git-gateway", "gateway", "custodian-git-gateway":
		if e.gitGatewayProc != nil {
			return e.gitGatewayProc.Logs()
		}
	}
	return ""
}

// AllLogs returns combined logs across all managed Custodian daemons.
func (e *Env) AllLogs() string {
	var b strings.Builder
	for _, comp := range []string{"api", "worker", "publisher", "git-gateway"} {
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
		if e.gitGatewayProc != nil {
			_ = e.gitGatewayProc.Stop(3 * time.Second)
		}
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
