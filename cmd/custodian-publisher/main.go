package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/publish"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/publication"
)

const usageText = `custodian-publisher - Isolated Custodian publication worker

Usage:
  custodian-publisher [--help|-h]

Environment Variables:
  CUSTODIAN_DATABASE_URL                 PostgreSQL DSN (required)
  CUSTODIAN_GITHUB_WRITE_APP_ID          Write GitHub App ID (required)
  CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM Write GitHub App RSA private key PEM (required unless _FILE is set)
  CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_FILE Path to write GitHub App RSA private key PEM (optional)
  CUSTODIAN_GITHUB_API_URL               GitHub API base URL (default: https://api.github.com/)
  CUSTODIAN_GITHUB_GIT_URL               Optional explicit Git base URL
  CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP   Allow plain HTTP Git transport (default: true for loopback API URLs)
  CUSTODIAN_SNAPSHOT_STORE               Snapshot store kind: local or gcs (default: local)
  CUSTODIAN_SNAPSHOT_DIR                 Local snapshot root directory (required when store=local)
  CUSTODIAN_SNAPSHOT_BUCKET              GCS bucket name (required when store=gcs)
  CUSTODIAN_SNAPSHOT_PREFIX              Optional GCS object prefix
  CUSTODIAN_LOG_FORMAT                   Log format: json or text (default: json)
  CUSTODIAN_LOG_LEVEL                    Log level: debug, info, warn, error (default: info)
  CUSTODIAN_PUBLISHER_WORKER_ID          Optional worker lease identifier
  CUSTODIAN_PUBLISHER_POLL_INTERVAL      Operation poll interval (default: 150ms)
  CUSTODIAN_PUBLISHER_LEASE_DURATION     Operation lease duration (default: 15s)
  CUSTODIAN_PUBLISHER_HEARTBEAT_INTERVAL Lease renewal interval (default: 5s)
  CUSTODIAN_PUBLISHER_REAP_INTERVAL      Expired lease reaper interval (default: 5s)
  CUSTODIAN_PUBLISHER_CONCURRENCY        Batch concurrency (default: 1)
  CUSTODIAN_PUBLISHER_GIT_BIN            Path to git binary (default: git)
  CUSTODIAN_PUBLISHER_COMMITTER_NAME     Git committer name (default: Custodian)
  CUSTODIAN_PUBLISHER_COMMITTER_EMAIL    Git committer email (default: custodian@custodian.local)
  CUSTODIAN_PUBLISHER_SHUTDOWN_TIMEOUT   Graceful shutdown drain timeout (default: 10s)
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

	fs := flag.NewFlagSet("custodian-publisher", flag.ContinueOnError)
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
		rawPEM := getenv("CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM")
		code, msg := sanitizeErrorMessage(err, rawDSN, rawPEM)
		earlyLogger := observability.NewLogger(observability.LoggerConfig{
			Writer:    stdout,
			Level:     earlyLevel,
			Format:    earlyFormat,
			Component: "custodian-publisher",
		})
		earlyLogger.Error("publisher configuration invalid",
			"error_code", code,
			"reason", msg,
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher configuration error (%s): %s\n", code, msg)
		return 1
	}

	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    stdout,
		Level:     cfg.LogLevel,
		Format:    cfg.LogFormat,
		Component: "custodian-publisher",
	})

	metrics, err := observability.NewMetrics(observability.MetricsConfig{
		Namespace:                "custodian",
		IncludeRuntimeCollectors: true,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing metrics", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-publisher metrics error (%s): %s\n", code, msg)
		return 1
	}

	tracer, err := observability.NewTracerProvider(ctx, observability.TracerConfig{
		ServiceName:    "custodian-publisher",
		ServiceVersion: cfg.Version,
		Environment:    cfg.Environment,
		Mode:           cfg.OTelMode,
		OTLPEndpoint:   cfg.OTelEndpoint,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing tracing", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-publisher tracing error (%s): %s\n", code, msg)
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
		_, _ = fmt.Fprintf(stderr, "custodian-publisher database error (%s): %s\n", code, msg)
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
		_, _ = fmt.Fprintf(stderr, "custodian-publisher store error (%s): %s\n", code, msg)
		return 1
	}
	defer store.Close()

	opener, closeOpener, err := publication.NewArtifactOpener(ctx, publication.ArtifactOpenerConfig{
		StoreKind:    cfg.SnapshotStore,
		LocalRootDir: cfg.SnapshotDir,
		GCSBucket:    cfg.SnapshotBucket,
		GCSPrefix:    cfg.SnapshotPrefix,
		Logger:       logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("artifact opener initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher storage error (%s): %s\n", code, msg)
		return 1
	}
	defer func() { _ = closeOpener() }()

	writeClient, err := write.NewWriteClient(write.WriteConfig{
		AppID:             cfg.WriteAppID,
		PrivateKeyPEM:     cfg.WritePrivateKeyPEM,
		APIBaseURL:        cfg.GitHubAPIBaseURL,
		GitBaseURL:        cfg.GitHubGitBaseURL,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
		Logger:            logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("github write client initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher github client error (%s): %s\n", code, msg)
		return 1
	}

	gitPub, err := publish.NewService(publish.Config{
		GitBinary:      cfg.GitBinary,
		WriteClient:    writeClient,
		ArtifactOpener: opener,
		CommitterName:  cfg.CommitterName,
		CommitterEmail: cfg.CommitterEmail,
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("git publisher initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher git publisher error (%s): %s\n", code, msg)
		return 1
	}

	pubSvc, err := publication.NewService(store, gitPub, metrics, logger)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("publication service initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher service error (%s): %s\n", code, msg)
		return 1
	}

	opsSvc := operations.NewService(store, metrics, logger, operations.Config{
		DefaultLeaseDuration: cfg.LeaseDuration,
	})

	runner, err := publication.NewRunner(publication.RunnerConfig{
		Ops:           opsSvc,
		Service:       pubSvc,
		WorkerID:      cfg.WorkerID,
		LeaseDuration: cfg.LeaseDuration,
		RenewInterval: cfg.HeartbeatInterval,
		PollInterval:  cfg.PollInterval,
		ReapInterval:  cfg.ReapInterval,
		BatchSize:     cfg.Concurrency,
		Logger:        logger,
		Metrics:       metrics,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("publication runner initialization failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher runner error (%s): %s\n", code, msg)
		return 1
	}

	logger.Info("publisher started",
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
			logger.Warn("publisher shutdown drain timed out",
				"stage", "shutdown",
				"status", "timeout",
			)
		}
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		code, msg := sanitizeErrorMessage(runErr, cfg.secrets()...)
		logger.Error("publisher exited with error",
			"error_code", code,
			"reason", msg,
			"stage", "shutdown",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-publisher runtime error (%s): %s\n", code, msg)
		return 1
	}

	_ = domain.OperationTypeProposalPublish
	logger.Info("publisher stopped",
		"stage", "shutdown",
		"status", "stopped",
	)
	return 0
}
