package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/github"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/snapshots"
	"github.com/timreynolds/custodian/internal/workflow"
)

const usageText = `custodian-worker - Custodian ingress, reconstruction, and evaluation worker

Usage:
  custodian-worker [--help|-h]

Environment Variables:
  CUSTODIAN_DATABASE_URL                 PostgreSQL DSN (required)
  CUSTODIAN_SNAPSHOT_STORE               Snapshot store kind: local or gcs (default: local)
  CUSTODIAN_SNAPSHOT_DIR                 Local snapshot root directory (required when store=local)
  CUSTODIAN_SNAPSHOT_BUCKET              GCS bucket name (required when store=gcs)
  CUSTODIAN_SNAPSHOT_PREFIX              Optional GCS object prefix
  CUSTODIAN_POLICY_DIR                   Policy bundle directory (default: policies/defaults if present)
  CUSTODIAN_GITHUB_API_URL               GitHub API base URL (default: https://api.github.com/)
  CUSTODIAN_GITHUB_GIT_URL               Optional explicit Git base URL
  CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP   Allow plain HTTP Git transport (default: true for loopback API URLs)
  CUSTODIAN_GITHUB_READ_APP_ID           Read-only GitHub App ID (required unless CUSTODIAN_LOCAL_BARE_GIT_DIR is set)
  CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM  Read-only GitHub App RSA private key PEM (required unless _FILE is set)
  CUSTODIAN_GITHUB_READ_PRIVATE_KEY_FILE Path to read-only GitHub App RSA private key PEM (optional)
  CUSTODIAN_LOCAL_BARE_GIT_DIR           Optional local bare git directory for offline development
  CUSTODIAN_MODEL_GATEWAY_URL            Stage B contextual decision model gateway URL
  CUSTODIAN_ROUTE_POLICY_JSON            Optional JSON RoutePolicy constraints for Stage B model routes
  CUSTODIAN_GITLEAKS_BIN                 Path to gitleaks binary (default: gitleaks)
  CUSTODIAN_SCANCODE_BIN                 Path to scancode binary (default: scancode)
  CUSTODIAN_SEMGREP_BIN                  Path to semgrep binary (default: semgrep)
  CUSTODIAN_TRIVY_BIN                    Path to trivy binary (default: trivy)
  CUSTODIAN_SCANNER_TIMEOUT              Stage A scanner execution timeout (default: 60s)
  CUSTODIAN_GLOBAL_SCAN_BUDGET           Global concurrent scan budget (default: 0 = unlimited)
  CUSTODIAN_GLOBAL_MODEL_BUDGET          Global concurrent model assessment budget (default: 0 = unlimited)
  CUSTODIAN_REPO_CONCURRENCY_LIMIT       Per-repository concurrency cap (default: 0 = unlimited)
  CUSTODIAN_ARTIFACT_RETENTION           Retention TTL for transient artifacts (default: 720h)
  CUSTODIAN_ARTIFACT_RETENTION_TTL       Alias for CUSTODIAN_ARTIFACT_RETENTION (default: 720h)
  CUSTODIAN_RETENTION_INTERVAL           Artifact retention reaper interval (default: 1m)
  CUSTODIAN_LOG_FORMAT                   Log format: json or text (default: json)
  CUSTODIAN_LOG_LEVEL                    Log level: debug, info, warn, error (default: info)
  CUSTODIAN_WORKER_ID                    Optional worker lease identifier
  CUSTODIAN_WORKER_POLL_INTERVAL         Operation poll interval (default: 150ms)
  CUSTODIAN_WORKER_LEASE_DURATION        Operation lease duration (default: 15s)
  CUSTODIAN_WORKER_HEARTBEAT_INTERVAL    Lease renewal interval (default: 5s)
  CUSTODIAN_WORKER_REAP_INTERVAL         Expired lease reaper interval (default: 5s)
  CUSTODIAN_WORKER_CONCURRENCY           Batch concurrency (default: 1)
  CUSTODIAN_WORKER_GIT_BIN               Path to git binary (default: git)
  CUSTODIAN_WORKER_SHUTDOWN_TIMEOUT      Graceful shutdown drain timeout (default: 10s)
  CUSTODIAN_OTEL_MODE                    OpenTelemetry mode: noop, stdout, otlp_http (default: noop)
  CUSTODIAN_OTEL_EXPORTER_OTLP_ENDPOINT  OTLP HTTP endpoint when otel_mode=otlp_http
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

	fs := flag.NewFlagSet("custodian-worker", flag.ContinueOnError)
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
		rawDSN := getenv("CUSTODIAN_DATABASE_URL")
		rawPEM := getenv("CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM")
		code, msg := sanitizeErrorMessage(err, rawDSN, rawPEM)
		earlyLogger := observability.NewLogger(observability.LoggerConfig{
			Writer:    stdout,
			Level:     earlyLevel,
			Format:    earlyFormat,
			Component: "custodian-worker",
		})
		earlyLogger.Error("worker configuration invalid",
			"error_code", code,
			"reason", msg,
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker configuration error (%s): %s\n", code, msg)
		return 1
	}

	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    stdout,
		Level:     cfg.LogLevel,
		Format:    cfg.LogFormat,
		Component: "custodian-worker",
	})

	metrics, err := observability.NewMetrics(observability.MetricsConfig{
		Namespace:                "custodian",
		IncludeRuntimeCollectors: true,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing metrics", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-worker metrics error (%s): %s\n", code, msg)
		return 1
	}

	tracer, err := observability.NewTracerProvider(ctx, observability.TracerConfig{
		ServiceName:    "custodian-worker",
		ServiceVersion: cfg.Version,
		Environment:    cfg.Environment,
		Mode:           cfg.OTelMode,
		OTLPEndpoint:   cfg.OTelEndpoint,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing tracing", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-worker tracing error (%s): %s\n", code, msg)
		return 1
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tracer.Shutdown(flushCtx)
	}()

	dbCtx, dbCancel := context.WithTimeout(ctx, defaultDBConnectTimeout)
	poolCfg := persistence.DefaultPoolConfig()
	poolCfg.ConnectTimeout = defaultDBConnectTimeout
	pool, err := persistence.NewPool(dbCtx, cfg.DatabaseURL, poolCfg)
	dbCancel()
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database connection failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker database error (%s): %s\n", code, msg)
		return 1
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		pool.Close()
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database store initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker store error (%s): %s\n", code, msg)
		return 1
	}
	defer store.Close()

	snapshotStore, closeSnapshots, err := initSnapshotStore(ctx, cfg, logger)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("snapshot store initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker storage error (%s): %s\n", code, msg)
		return 1
	}
	defer func() { _ = closeSnapshots() }()

	checkoutRunner := checkout.NewRunner(checkout.RunnerConfig{
		GitBinary: cfg.GitBinary,
		Logger:    logger,
	})

	var gitReader domain.GitReader
	if cfg.ReadAppID > 0 {
		gitReader, err = github.NewReadOnlyClient(github.AppConfig{
			AppID:             cfg.ReadAppID,
			PrivateKeyPEM:     cfg.ReadPrivateKeyPEM,
			APIBaseURL:        cfg.GitHubAPIBaseURL,
			GitBaseURL:        cfg.GitHubGitBaseURL,
			AllowInsecureHTTP: cfg.AllowInsecureHTTP,
			CheckoutRunner:    checkoutRunner,
			Logger:            logger,
		})
	} else {
		gitReader = github.NewLocalBareGitReader(
			github.WithBareRootDir(cfg.LocalBareGitDir),
			github.WithCheckoutRunner(checkoutRunner),
			github.WithGitBinary(cfg.GitBinary),
			github.WithLogger(logger),
		)
	}
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("git reader initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker git reader error (%s): %s\n", code, msg)
		return 1
	}

	reconSvc, err := reconstruct.NewService(reconstruct.Config{
		GitReader:     gitReader,
		SnapshotStore: snapshotStore,
		GitBinary:     cfg.GitBinary,
		Logger:        logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("reconstructor initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker reconstructor error (%s): %s\n", code, msg)
		return 1
	}

	inspCfg := cfg.Inspection
	inspCfg.Logger = logger
	inspCfg.Metrics = metrics
	inspCfg.Tracer = tracer
	inspector := inspection.NewRunner(inspCfg)

	gwClient, err := decisions.NewHTTPGatewayClient(decisions.GatewayConfig{
		BaseURL:          cfg.ModelGatewayURL,
		AssessPath:       decisions.DefaultAssessPath,
		Timeout:          defaultModelGatewayTimeout,
		MaxResponseBytes: decisions.DefaultMaxResponseBytes,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("model gateway client initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker gateway error (%s): %s\n", code, msg)
		return 1
	}

	decSvc, err := newDecisionsService(gwClient, cfg, logger, metrics, tracer)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("decisions service initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker decisions error (%s): %s\n", code, msg)
		return 1
	}

	policyEngine, err := policy.NewEngine(
		policy.WithMetrics(metrics),
		policy.WithLogger(logger),
		policy.WithTracer(tracer.Tracer("custodian-worker")),
	)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("policy engine initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker policy engine error (%s): %s\n", code, msg)
		return 1
	}

	if cfg.PolicyDir != "" {
		syncCtx, syncCancel := context.WithTimeout(ctx, 10*time.Second)
		synced, syncErr := workflow.SyncPolicyDir(syncCtx, store, policyEngine, cfg.PolicyDir, time.Now().UTC())
		syncCancel()
		if syncErr != nil {
			code, msg := sanitizeErrorMessage(syncErr, cfg.secrets()...)
			logger.Error("policy directory sync failed",
				"error_code", code,
				"reason", msg,
				"stage", "startup",
				"status", "failed",
			)
			_, _ = fmt.Fprintf(stderr, "custodian-worker policy sync error (%s): %s\n", code, msg)
			return 1
		}
		logger.Info("policy directory synced",
			"stage", "startup",
			"status", "ready",
			"generation", int64(synced),
		)
	}

	opsSvc := operations.NewService(store, metrics, logger, operations.Config{
		DefaultLeaseDuration: cfg.LeaseDuration,
	})

	wfCfg := workflow.Config{
		WorkerID:             cfg.WorkerID,
		LeaseDuration:        cfg.LeaseDuration,
		RenewInterval:        cfg.HeartbeatInterval,
		PollInterval:         cfg.PollInterval,
		ReapInterval:         cfg.ReapInterval,
		RetentionInterval:    cfg.RetentionInterval,
		ArtifactRetentionTTL: cfg.ArtifactRetentionTTL,
		BatchSize:            cfg.Concurrency,
		GlobalScanBudget:     cfg.GlobalScanBudget,
		GlobalModelBudget:    cfg.GlobalModelBudget,
		RepoConcurrencyLimit: cfg.RepoConcurrencyLimit,
		PolicyDir:            cfg.PolicyDir,
	}

	wfSvc, err := workflow.NewService(workflow.ServiceConfig{
		Store:            store,
		Ops:              opsSvc,
		SnapshotStore:    snapshotStore,
		GitReader:        gitReader,
		Reconstructor:    reconSvc,
		InspectionRunner: inspector,
		Decisions:        decSvc,
		PolicyEngine:     policyEngine,
		Logger:           logger,
		Metrics:          metrics,
		Tracer:           tracer.Tracer("custodian-worker"),
		Config:           wfCfg,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("workflow service initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker workflow error (%s): %s\n", code, msg)
		return 1
	}

	runner, err := workflow.NewRunner(workflow.RunnerConfig{
		Service: wfSvc,
		Config:  wfCfg,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("workflow runner initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker runner error (%s): %s\n", code, msg)
		return 1
	}

	logger.Info("worker started",
		"stage", "startup",
		"status", "ready",
	)

	runDone := make(chan error, 1)
	go func() {
		runDone <- runner.Run(ctx)
	}()

	var runErr error
	select {
	case runErr = <-runDone:
	case <-ctx.Done():
		shutdownTimer := time.NewTimer(cfg.ShutdownTimeout)
		select {
		case runErr = <-runDone:
			shutdownTimer.Stop()
		case <-shutdownTimer.C:
			logger.Warn("worker shutdown drain timed out",
				"stage", "shutdown",
				"status", "timeout",
			)
		}
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		code, msg := sanitizeErrorMessage(runErr, cfg.secrets()...)
		logger.Error("worker exited with error",
			"error_code", code,
			"reason", msg,
			"stage", "shutdown",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-worker runtime error (%s): %s\n", code, msg)
		return 1
	}

	logger.Info("worker stopped",
		"stage", "shutdown",
		"status", "stopped",
	)
	return 0
}

func initSnapshotStore(ctx context.Context, cfg Config, logger *slog.Logger) (domain.SnapshotStore, func() error, error) {
	switch cfg.SnapshotStore {
	case "local":
		st, err := snapshots.NewLocalStore(snapshots.LocalConfig{
			RootDir: cfg.SnapshotDir,
			Logger:  logger,
		})
		if err != nil {
			return nil, func() error { return nil }, err
		}
		return st, func() error { return nil }, nil
	case "gcs":
		st, err := snapshots.NewGCSStore(ctx, snapshots.GCSConfig{
			Bucket: cfg.SnapshotBucket,
			Prefix: cfg.SnapshotPrefix,
			Logger: logger,
		})
		if err != nil {
			return nil, func() error { return nil }, err
		}
		return st, func() error { return nil }, nil
	default:
		return nil, func() error { return nil }, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", fmt.Sprintf("unsupported snapshot store %q", cfg.SnapshotStore))
	}
}

func newDecisionsService(gwClient decisions.GatewayClient, cfg Config, logger *slog.Logger, metrics *observability.Metrics, tracer *observability.TracerRuntime) (*decisions.Service, error) {
	opts := []decisions.ServiceOption{
		decisions.WithLogger(logger),
		decisions.WithMetrics(metrics),
	}
	if tracer != nil {
		opts = append(opts, decisions.WithTracer(tracer.Tracer("custodian-worker")))
	}
	routePolicy := cfg.RoutePolicy
	if routePolicy == nil {
		routePolicy = defaultWorkerRoutePolicy()
	}
	opts = append(opts, decisions.WithRoutePolicy(routePolicy))
	return decisions.NewService(gwClient, opts...)
}
