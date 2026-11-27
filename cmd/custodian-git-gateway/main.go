package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/snapshots"
)

const usageText = `custodian-git-gateway - Custodian Push Gateway (Smart-HTTP, SSH User-CA, Git LFS)

Usage:
  custodian-git-gateway [--help|-h]

Environment Variables:
  CUSTODIAN_GIT_GATEWAY_HTTP_ADDR            TLS HTTPS listen address (default: 127.0.0.1:8443)
  CUSTODIAN_GIT_GATEWAY_SSH_ADDR             SSH User-CA listen address (default: 127.0.0.1:2222)
  CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE        TLS server certificate PEM file (required)
  CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE         TLS server private key PEM file (required)
  CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE    SSH host private key file (required when SSH enabled)
  CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE     OpenSSH User CA public key file (required when SSH enabled)
  CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL         Upstream Git base URL (default: https://github.com)
  CUSTODIAN_GIT_GATEWAY_API_BASE_URL         Optional Custodian API base URL
  CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES       Max receive-pack bytes (default: 67108864)
  CUSTODIAN_GIT_GATEWAY_MAX_OBJECTS          Max objects per push pack (default: 10000)
  CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES   Max inflated object bytes (default: 33554432)
  CUSTODIAN_GIT_GATEWAY_MAX_REF_UPDATES      Max ref updates per push (default: 100)
  CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE  Default egress mode (default: ENFORCE_BLOCK)
  CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY     Passive audit delivery: ASYNC or INLINE_WARN (default: ASYNC)
  CUSTODIAN_DATABASE_URL                     PostgreSQL DSN (required)
  CUSTODIAN_SNAPSHOT_STORE                   Snapshot store kind: local or gcs (default: local)
  CUSTODIAN_SNAPSHOT_DIR                     Local snapshot directory (or CUSTODIAN_SNAPSHOT_ROOT)
  CUSTODIAN_OIDC_ISSUER                      OIDC issuer URL (required)
  CUSTODIAN_OIDC_JWKS_URL                    Optional explicit OIDC JWKS URL
  CUSTODIAN_OIDC_AUDIENCE                    Expected OIDC audience (required)
  CUSTODIAN_POLICY_DIR                       Directory of YAML PolicyBundles to seed on startup
  CUSTODIAN_LOG_FORMAT                       Log format: json or text (default: json)
  CUSTODIAN_LOG_LEVEL                        Log level: debug, info, warn, error (default: info)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if getenv == nil {
		getenv = os.Getenv
	}

	fs := flag.NewFlagSet("custodian-git-gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	helpFlag := false
	fs.BoolVar(&helpFlag, "help", false, "show usage")
	fs.BoolVar(&helpFlag, "h", false, "show usage")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usageText)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: %s\n", redactString(err.Error()))
		_, _ = io.WriteString(stderr, usageText)
		return 2
	}
	if helpFlag {
		_, _ = io.WriteString(stdout, usageText)
		return 0
	}
	if fs.NArg() > 0 {
		if strings.EqualFold(fs.Arg(0), "help") {
			_, _ = io.WriteString(stdout, usageText)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "error: unexpected positional arguments\n")
		return 2
	}

	earlyFormat, _ := parseLogFormat(getenv("CUSTODIAN_LOG_FORMAT"))
	if earlyFormat == "" {
		earlyFormat = observability.LogFormatJSON
	}
	earlyLevel, _ := parseLogLevel(getenv("CUSTODIAN_LOG_LEVEL"))

	cfg, err := loadConfig(getenv)
	if err != nil {
		rawSecrets := collectStartupSecrets(getenv)
		code, msg := sanitizeErrorMessage(err, rawSecrets...)
		earlyLogger := observability.NewLogger(observability.LoggerConfig{
			Writer:    stdout,
			Level:     earlyLevel,
			Format:    earlyFormat,
			Component: "custodian-git-gateway",
		})
		earlyLogger.Error("git-gateway configuration invalid",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway configuration error (%s): %s\n", code, msg)
		return 1
	}

	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    stdout,
		Level:     cfg.LogLevel,
		Format:    cfg.LogFormat,
		Component: "custodian-git-gateway",
	})

	metrics, err := observability.NewMetrics(observability.MetricsConfig{
		Namespace:                "custodian",
		IncludeRuntimeCollectors: true,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing metrics", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway metrics error (%s): %s\n", code, msg)
		return 1
	}

	tracerRuntime, err := observability.NewTracerProvider(ctx, observability.TracerConfig{
		ServiceName:    "custodian-git-gateway",
		ServiceVersion: cfg.Version,
		Environment:    cfg.Environment,
		Mode:           cfg.OTelMode,
		OTLPEndpoint:   cfg.OTelEndpoint,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing tracing", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway tracing error (%s): %s\n", code, msg)
		return 1
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tracerRuntime.Shutdown(flushCtx)
	}()

	tlsCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("tls keypair initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway tls error (%s): %s\n", code, msg)
		return 1
	}

	var sshHostKey ssh.Signer
	var sshUserCA ssh.PublicKey
	if cfg.sshEnabled() {
		sshHostKey, err = ssh.ParsePrivateKey(cfg.SSHHostKeyPEM)
		if err != nil {
			code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
			logger.Error("ssh host key initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-git-gateway ssh host key error (%s): %s\n", code, msg)
			return 1
		}
		sshUserCA, _, _, _, err = ssh.ParseAuthorizedKey(cfg.SSHUserCAPubKey)
		if err != nil {
			code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
			logger.Error("ssh user ca initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-git-gateway ssh user ca error (%s): %s\n", code, msg)
			return 1
		}
	}

	dbCtx, dbCancel := context.WithTimeout(ctx, defaultDBConnectTimeout)
	poolCfg := persistence.DefaultPoolConfig()
	poolCfg.ConnectTimeout = defaultDBConnectTimeout
	pool, err := persistence.NewPool(dbCtx, cfg.DatabaseURL, poolCfg)
	dbCancel()
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database connection failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway database error (%s): %s\n", code, msg)
		return 1
	}
	defer pool.Close()

	migCtx, migCancel := context.WithTimeout(ctx, 30*time.Second)
	err = persistence.MigrateUpPool(migCtx, pool)
	migCancel()
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database migration failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway migration error (%s): %s\n", code, msg)
		return 1
	}

	store, err := persistence.NewStore(pool)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database store initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway store error (%s): %s\n", code, msg)
		return 1
	}
	defer store.Close()

	snapStore, closeSnap, err := initSnapshotStore(ctx, cfg, logger)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("snapshot store initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway snapshot store error (%s): %s\n", code, msg)
		return 1
	}
	defer func() { _ = closeSnap() }()

	auditSvc := audit.NewService(store, logger)

	policyEngine, err := policy.NewEngine(
		policy.WithMetrics(metrics),
		policy.WithLogger(logger),
		policy.WithTracer(tracerRuntime.Tracer("custodian.policy")),
	)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("policy engine initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway policy error (%s): %s\n", code, msg)
		return 1
	}

	if cfg.PolicyDir != "" {
		if _, err := seedPolicyDir(ctx, store, policyEngine, cfg.PolicyDir, logger); err != nil {
			code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
			logger.Error("failed seeding policy directory", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-git-gateway policy seed error (%s): %s\n", code, msg)
			return 1
		}
	}

	oidcVerifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   cfg.OIDCIssuer,
		JWKSURL:  cfg.OIDCJWKSURL,
		Audience: cfg.OIDCAudience,
		Logger:   logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("oidc verifier initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway oidc error (%s): %s\n", code, msg)
		return 1
	}

	dir, err := identity.NewDirectory(store, identity.DefaultDirectoryConfig())
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("identity directory initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway directory error (%s): %s\n", code, msg)
		return 1
	}

	// Wire Stage A fingerprinting and Stage B decisions dependencies into M4b pipeline.
	inspCfg := cfg.Inspection
	inspCfg.IPFingerprinter = fingerprints.NewEngine(fingerprints.EngineConfig{
		Store:        store,
		RequireStore: true,
	})
	inspCfg.Logger = logger
	inspCfg.Metrics = metrics
	inspCfg.Tracer = tracerRuntime

	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{
		BaseURL:          cfg.ModelGatewayURL,
		AssessPath:       decisions.DefaultAssessPath,
		Timeout:          defaultModelGatewayTimeout,
		MaxResponseBytes: decisions.DefaultMaxResponseBytes,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("model gateway client initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway model client error (%s): %s\n", code, msg)
		return 1
	}
	decOpts := []decisions.ServiceOption{
		decisions.WithLogger(logger),
		decisions.WithMetrics(metrics),
		decisions.WithTracer(tracerRuntime.Tracer("custodian.decisions")),
		decisions.WithRoutePolicy(cfg.RoutePolicy),
	}
	decSvc, err := decisions.NewService(gwClient, decOpts...)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("decisions service initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway decisions error (%s): %s\n", code, msg)
		return 1
	}

	authenticator, err := gitgateway.NewAuthenticator(gitgateway.AuthenticatorConfig{
		OIDC:       oidcVerifier,
		Directory:  dir,
		Store:      store,
		SSHHostKey: sshHostKey,
		SSHUserCA:  sshUserCA,
		Logger:     logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("authenticator initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway authenticator error (%s): %s\n", code, msg)
		return 1
	}

	resolver, err := gitgateway.NewTargetResolver(gitgateway.TargetResolverConfig{
		Store:                store,
		UpstreamBaseURL:      cfg.UpstreamURL,
		DefaultEgressMode:    cfg.DefaultEgressMode,
		DefaultAuditDelivery: cfg.PassiveDelivery,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("target resolver initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway resolver error (%s): %s\n", code, msg)
		return 1
	}

	broker, err := gitgateway.NewTokenBroker(gitgateway.TokenBrokerConfig{
		APIBaseURL:         cfg.GitHubAPIBaseURL,
		ReadAppID:          cfg.ReadAppID,
		ReadPrivateKeyPEM:  cfg.ReadPrivateKeyPEM,
		WriteAppID:         cfg.WriteAppID,
		WritePrivateKeyPEM: cfg.WritePrivateKeyPEM,
		Logger:             logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("token broker initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway token broker error (%s): %s\n", code, msg)
		return 1
	}

	upstream, err := gitgateway.NewHTTPUpstreamClient(gitgateway.HTTPUpstreamConfig{
		BaseURL:           cfg.UpstreamURL,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
		Logger:            logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("upstream client initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway upstream client error (%s): %s\n", code, msg)
		return 1
	}

	quarantineUnpacker, err := quarantine.NewQuarantineUnpacker(quarantine.UnpackerConfig{
		GitBinary:     cfg.GitBinary,
		DefaultLimits: cfg.QuarantineLimits,
		SnapshotStore: nil,
		Metrics:       metrics,
		Logger:        logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("quarantine unpacker initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway quarantine error (%s): %s\n", code, msg)
		return 1
	}

	receiveHandler, err := gitgateway.NewPipelineReceivePackHandler(gitgateway.PipelineConfig{
		Store:                store,
		SnapshotStore:        snapStore,
		QuarantineUnpacker:   quarantineUnpacker,
		PolicyEngine:         policyEngine,
		PolicyDir:            cfg.PolicyDir,
		InspectionConfig:     inspCfg,
		DecisionsService:     decSvc,
		TokenBroker:          broker,
		Upstream:             upstream,
		AuditService:         auditSvc,
		GitBinary:            cfg.GitBinary,
		Limits:               cfg.QuarantineLimits,
		ArtifactRetentionTTL: cfg.ArtifactRetentionTTL,
		RepoConcurrencyLimit: cfg.RepoConcurrencyLimit,
		GlobalScanBudget:     cfg.GlobalScanBudget,
		Metrics:              metrics,
		Logger:               logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("pipeline receive-pack handler initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway pipeline error (%s): %s\n", code, msg)
		return 1
	}

	gwSrv, err := gitgateway.NewServer(gitgateway.ServerConfig{
		Store:               store,
		Authenticator:       authenticator,
		TargetResolver:      resolver,
		TokenBroker:         broker,
		Upstream:            upstream,
		ReceivePackHandler:  receiveHandler,
		Limits:              cfg.QuarantineLimits,
		LFSCapabilitySecret: cfg.CapabilitySecret,
		Metrics:             metrics,
		Logger:              logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("git gateway server initialization failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway server error (%s): %s\n", code, msg)
		return 1
	}

	httpLn, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("https listener failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-git-gateway listen error (%s): %s\n", code, msg)
		return 1
	}

	var sshLn net.Listener
	if cfg.sshEnabled() {
		sshLn, err = net.Listen("tcp", cfg.SSHAddr)
		if err != nil {
			_ = httpLn.Close()
			code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
			logger.Error("ssh listener failed", "error_code", code, "reason", msg, "stage", "startup", "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-git-gateway ssh listen error (%s): %s\n", code, msg)
			return 1
		}
	}

	httpSrv := &http.Server{
		Handler:           gwSrv.HTTPHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	logger.Info("custodian-git-gateway started",
		"stage", "startup",
		"status", "ready",
	)

	errCh := make(chan error, 2)
	go func() {
		if serveErr := httpSrv.ServeTLS(httpLn, "", ""); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	expectedExitCount := 1
	if sshLn != nil && gwSrv.SSHServer() != nil {
		expectedExitCount = 2
		go func() {
			if serveErr := gwSrv.SSHServer().Serve(sshLn); serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
				errCh <- serveErr
				return
			}
			errCh <- nil
		}()
	}

	select {
	case serveErr := <-errCh:
		if serveErr != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			_ = httpSrv.Shutdown(shutCtx)
			if gwSrv.SSHServer() != nil {
				_ = gwSrv.SSHServer().Shutdown(shutCtx)
			}
			cancel()
			code, msg := sanitizeErrorMessage(serveErr, cfg.secrets()...)
			logger.Error("git-gateway server exited with error", "error_code", code, "reason", msg, "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-git-gateway serve error (%s): %s\n", code, msg)
			return 1
		}
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if shutErr := httpSrv.Shutdown(shutCtx); shutErr != nil {
			code, msg := sanitizeErrorMessage(shutErr, cfg.secrets()...)
			logger.Warn("https server shutdown error", "error_code", code, "reason", msg, "status", "timeout")
		}
		if gwSrv.SSHServer() != nil {
			if shutErr := gwSrv.SSHServer().Shutdown(shutCtx); shutErr != nil {
				code, msg := sanitizeErrorMessage(shutErr, cfg.secrets()...)
				logger.Warn("ssh server shutdown error", "error_code", code, "reason", msg, "status", "timeout")
			}
		}
		for i := 0; i < expectedExitCount; i++ {
			if serveErr := <-errCh; serveErr != nil {
				code, msg := sanitizeErrorMessage(serveErr, cfg.secrets()...)
				logger.Error("git-gateway server exited with error during shutdown", "error_code", code, "reason", msg, "status", "failed")
				return 1
			}
		}
	}

	logger.Info("custodian-git-gateway stopped", "stage", "shutdown", "status", "stopped")
	return 0
}

func collectStartupSecrets(getenv func(string) string) []string {
	var out []string
	for _, k := range []string{
		"CUSTODIAN_DATABASE_URL",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM",
		"CUSTODIAN_CAPABILITY_HMAC_SECRET",
	} {
		if v := getenv(k); v != "" {
			out = append(out, v)
		}
	}
	for _, fk := range []string{
		"CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE",
		"CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE",
	} {
		if path := strings.TrimSpace(getenv(fk)); path != "" {
			if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
				out = append(out, string(data))
			}
		}
	}
	return out
}

func seedPolicyDir(ctx context.Context, store *persistence.Store, engine *policy.Engine, dir string, logger *slog.Logger) (int, error) {
	bundles, err := engine.LoadDir(dir)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	count := 0
	for _, b := range bundles {
		scope := b.Scope
		if !scope.IsValid() {
			scope = b.Bundle.Metadata.Scope
		}
		if scope == domain.PolicyScopeRepo {
			continue
		}
		if scope == "" {
			scope = domain.PolicyScopeOrg
		}
		row, err := store.UpsertPolicyBundleByDigest(ctx, persistence.CreatePolicyBundleParams{
			Name:        b.Bundle.Metadata.Name,
			Version:     b.Bundle.Metadata.Version,
			Scope:       scope,
			Digest:      b.Digest,
			Definition:  b.Definition,
			ActivatedAt: &now,
			CreatedAt:   now,
		})
		if err != nil {
			return count, err
		}
		count++
		if logger != nil {
			logger.Info("seeded policy bundle",
				"policy_bundle_id", row.ID.String(),
				"digest", row.Digest,
				"version", row.Version,
			)
		}
	}
	return count, nil
}

func initSnapshotStore(ctx context.Context, cfg Config, logger *slog.Logger) (domain.SnapshotStore, func() error, error) {
	switch cfg.SnapshotStore {
	case "local":
		st, err := snapshots.NewLocalStore(snapshots.LocalConfig{
			RootDir: cfg.SnapshotDir,
			Logger:  logger,
		})
		if err != nil {
			return nil, nil, err
		}
		return st, func() error { return nil }, nil
	case "gcs":
		st, err := snapshots.NewGCSStore(ctx, snapshots.GCSConfig{
			Bucket: cfg.SnapshotBucket,
			Prefix: cfg.SnapshotPrefix,
			Logger: logger,
		})
		if err != nil {
			return nil, nil, err
		}
		return st, st.Close, nil
	default:
		return nil, nil, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", fmt.Sprintf("unsupported snapshot store %q", cfg.SnapshotStore))
	}
}
