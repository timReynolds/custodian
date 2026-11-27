package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/timreynolds/custodian/internal/api"
	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/github"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/inspection/fingerprints"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/snapshots"
	"github.com/timreynolds/custodian/internal/workspaces"
)

const usageText = `custodian-api - Custodian REST API server

Usage:
  custodian-api [--help|-h]

Environment Variables:
  CUSTODIAN_LISTEN_ADDR                 HTTP listen address (default: 127.0.0.1:8080)
  CUSTODIAN_DATABASE_URL                PostgreSQL DSN (required)
  CUSTODIAN_OIDC_ISSUER                 OIDC issuer URL (required)
  CUSTODIAN_OIDC_JWKS_URL               Optional explicit OIDC JWKS URL
  CUSTODIAN_OIDC_AUDIENCE               Expected OIDC audience (required)
  CUSTODIAN_CAPABILITY_HMAC_SECRET      HMAC-SHA256 secret (>= 32 bytes, required)
  CUSTODIAN_GITHUB_READ_APP_ID          Read-only GitHub App ID (required)
  CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM Read-only GitHub App RSA PEM (required unless _FILE)
  CUSTODIAN_GITHUB_API_URL              GitHub API base URL (default: https://api.github.com/)
  CUSTODIAN_SNAPSHOT_STORE              Snapshot store kind: local or gcs (default: local)
  CUSTODIAN_SNAPSHOT_ROOT               Local snapshot root directory (or CUSTODIAN_SNAPSHOT_DIR)
  CUSTODIAN_SNAPSHOT_BUCKET             GCS bucket name when store=gcs
  CUSTODIAN_POLICY_DIR                  Directory of YAML PolicyBundles to seed on startup
  CUSTODIAN_REPO_CONCURRENCY_LIMIT      Default max active operations per repository
  CUSTODIAN_GLOBAL_SCAN_BUDGET          Global concurrent scan budget
  CUSTODIAN_GLOBAL_MODEL_BUDGET         Global concurrent decision model budget
  CUSTODIAN_ARTIFACT_RETENTION          Artifact retention TTL (default: 720h)
  CUSTODIAN_LOG_FORMAT                  Log format: json or text (default: json)
  CUSTODIAN_LOG_LEVEL                   Log level: debug, info, warn, error (default: info)
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

	fs := flag.NewFlagSet("custodian-api", flag.ContinueOnError)
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
		rawCap := getenv("CUSTODIAN_CAPABILITY_HMAC_SECRET")
		code, msg := sanitizeErrorMessage(err, rawDSN, rawPEM, rawCap)
		earlyLogger := observability.NewLogger(observability.LoggerConfig{
			Writer:    stdout,
			Level:     earlyLevel,
			Format:    earlyFormat,
			Component: "custodian-api",
		})
		earlyLogger.Error("api configuration invalid",
			"error_code", code,
			"reason", msg,
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-api configuration error (%s): %s\n", code, msg)
		return 1
	}

	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    stdout,
		Level:     cfg.LogLevel,
		Format:    cfg.LogFormat,
		Component: "custodian-api",
	})

	metrics, err := observability.NewMetrics(observability.MetricsConfig{
		Namespace:                "custodian",
		IncludeRuntimeCollectors: true,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing metrics", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api metrics error (%s): %s\n", code, msg)
		return 1
	}

	tracerRuntime, err := observability.NewTracerProvider(ctx, observability.TracerConfig{
		ServiceName:    "custodian-api",
		ServiceVersion: cfg.Version,
		Environment:    cfg.Environment,
		Mode:           cfg.OTelMode,
		OTLPEndpoint:   cfg.OTelEndpoint,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("failed initializing tracing", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api tracing error (%s): %s\n", code, msg)
		return 1
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tracerRuntime.Shutdown(flushCtx)
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
		_, _ = fmt.Fprintf(stderr, "custodian-api database error (%s): %s\n", code, msg)
		return 1
	}
	defer pool.Close()

	migCtx, migCancel := context.WithTimeout(ctx, 30*time.Second)
	err = persistence.MigrateUpPool(migCtx, pool)
	migCancel()
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database migration failed",
			"error_code", code,
			"reason", msg,
			"stage", "startup",
			"status", "failed",
		)
		_, _ = fmt.Fprintf(stderr, "custodian-api migration error (%s): %s\n", code, msg)
		return 1
	}

	store, err := persistence.NewStore(pool)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("database store initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api store error (%s): %s\n", code, msg)
		return 1
	}

	policyEngine, err := policy.NewEngine(
		policy.WithMetrics(metrics),
		policy.WithLogger(logger),
		policy.WithTracer(tracerRuntime.Tracer("custodian.policy")),
	)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("policy engine initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api policy error (%s): %s\n", code, msg)
		return 1
	}

	if cfg.PolicyDir != "" {
		if err := seedPolicyDir(ctx, store, policyEngine, cfg.PolicyDir, logger); err != nil {
			code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
			logger.Error("failed seeding policy directory", "error_code", code, "reason", msg, "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-api policy seed error (%s): %s\n", code, msg)
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
		logger.Error("oidc verifier initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api oidc error (%s): %s\n", code, msg)
		return 1
	}

	capSvc, err := auth.NewCapabilityService(auth.CapabilityConfig{
		Secret:     cfg.CapabilitySecret,
		DefaultTTL: cfg.CapabilityTTL,
		MaxTTL:     maxDuration(15*time.Minute, cfg.CapabilityTTL),
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("capability service initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api capability error (%s): %s\n", code, msg)
		return 1
	}

	dir, err := identity.NewDirectory(store, identity.DefaultDirectoryConfig())
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("identity directory initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api directory error (%s): %s\n", code, msg)
		return 1
	}

	snapStore, closeSnap, err := initSnapshotStore(ctx, cfg, logger)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("snapshot store initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api snapshot store error (%s): %s\n", code, msg)
		return 1
	}
	defer func() { _ = closeSnap() }()

	ghRead, err := github.NewReadOnlyClient(github.AppConfig{
		AppID:             cfg.ReadAppID,
		PrivateKeyPEM:     cfg.ReadPrivateKeyPEM,
		APIBaseURL:        cfg.GitHubAPIBaseURL,
		GitBaseURL:        cfg.GitHubGitBaseURL,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
		Logger:            logger,
	})
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("github read client initialization failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api github client error (%s): %s\n", code, msg)
		return 1
	}

	reposSvc := repositories.NewService(store, logger)
	wsSvc := workspaces.NewService(store, metrics, logger)
	opsSvc := operations.NewService(store, metrics, logger)
	auditSvc := audit.NewService(store, logger)
	artifactsSvc := artifacts.NewService(store, logger)
	propsSvc := proposals.NewService(store, metrics, logger)
	approvalsSvc := approvals.NewService(store, metrics, logger)

	router := api.NewRouter(api.Deps{
		Store:                store,
		OIDC:                 oidcVerifier,
		Capabilities:         capSvc,
		Directory:            dir,
		Snapshots:            snapStore,
		GitHubRead:           ghRead,
		Repositories:         reposSvc,
		Workspaces:           wsSvc,
		Operations:           opsSvc,
		Audit:                auditSvc,
		Artifacts:            artifactsSvc,
		Proposals:            propsSvc,
		Approvals:            approvalsSvc,
		PolicyEngine:         policyEngine,
		IPCorpusReindexer:    newIPCorpusReindexer(store),
		Metrics:              metrics,
		Tracer:               tracerRuntime.Tracer("custodian.api"),
		Logger:               logger,
		BaseURL:              cfg.BaseURL,
		RepoConcurrencyLimit: cfg.RepoConcurrencyLimit,
		GlobalScanBudget:     cfg.GlobalScanBudget,
		GlobalModelBudget:    cfg.GlobalModelBudget,
		MaxUploadBytes:       cfg.MaxUploadBytes,
		CapabilityTTL:        cfg.CapabilityTTL,
		ArtifactRetentionTTL: cfg.ArtifactRetentionTTL,
	})

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
		logger.Error("http listener failed", "error_code", code, "reason", msg, "status", "failed")
		_, _ = fmt.Fprintf(stderr, "custodian-api listen error (%s): %s\n", code, msg)
		return 1
	}

	srv := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("custodian-api started",
		"stage", "startup",
		"status", "ready",
	)

	serveErrCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrCh <- err
			return
		}
		serveErrCh <- nil
	}()

	select {
	case serveErr := <-serveErrCh:
		if serveErr != nil {
			code, msg := sanitizeErrorMessage(serveErr, cfg.secrets()...)
			logger.Error("http server exited with error", "error_code", code, "reason", msg, "status", "failed")
			_, _ = fmt.Fprintf(stderr, "custodian-api serve error (%s): %s\n", code, msg)
			return 1
		}
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			code, msg := sanitizeErrorMessage(err, cfg.secrets()...)
			logger.Warn("http server shutdown error", "error_code", code, "reason", msg, "status", "timeout")
		}
		if serveErr := <-serveErrCh; serveErr != nil {
			code, msg := sanitizeErrorMessage(serveErr, cfg.secrets()...)
			logger.Error("http server exited with error during shutdown", "error_code", code, "reason", msg, "status", "failed")
			return 1
		}
	}

	logger.Info("custodian-api stopped", "stage", "shutdown", "status", "stopped")
	return 0
}

func seedPolicyDir(ctx context.Context, store *persistence.Store, engine *policy.Engine, dir string, logger *slog.Logger) error {
	bundles, err := engine.LoadDir(dir)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, b := range bundles {
		scope := b.Scope
		if !scope.IsValid() {
			scope = b.Bundle.Metadata.Scope
		}
		if scope == domain.PolicyScopeRepo {
			// Repository-scoped bundles require a repository_id; skip automatic ORG seeding for REPO bundles.
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
			return err
		}
		if logger != nil {
			logger.Info("seeded policy bundle",
				"policy_bundle_id", row.ID.String(),
				"digest", row.Digest,
				"version", row.Version,
			)
		}
	}
	return nil
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

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

type ipCorpusReindexerAdapter struct {
	indexer *fingerprints.CorpusIndexer
}

func newIPCorpusReindexer(store *persistence.Store) api.IPCorpusReindexer {
	if store == nil {
		return nil
	}
	return &ipCorpusReindexerAdapter{
		indexer: fingerprints.NewCorpusIndexer(store, fingerprints.NewPersistenceTxRunner(store)),
	}
}

func (a *ipCorpusReindexerAdapter) Reindex(ctx context.Context, input api.IPCorpusReindexInput) (api.IPCorpusReindexResult, error) {
	if a == nil || a.indexer == nil {
		return api.IPCorpusReindexResult{}, domain.Unavailable("SERVICE_UNAVAILABLE", "IP corpus indexer is not configured")
	}
	if err := ctx.Err(); err != nil {
		return api.IPCorpusReindexResult{}, mapReindexContextError(err)
	}
	dir := strings.TrimSpace(input.SourcePath)
	if dir != "" && len(input.Files) > 0 {
		return api.IPCorpusReindexResult{}, domain.BadRequest("INVALID_CORPUS_SOURCE", "source_path and files cannot both be specified")
	}

	isReady := input.Corpus.Status == domain.IPCorpusStatusReady && input.Corpus.FingerprintCount > 0

	// Idempotent reindex when raw inline files were already indexed on creation (raw source is never stored in PG).
	if dir == "" && len(input.Files) == 0 && isReady {
		if strings.TrimSpace(input.SourceRef) == "" || input.SourceRef == input.Corpus.SourceRef {
			return api.IPCorpusReindexResult{
				Status:              domain.IPCorpusStatusReady,
				FingerprintsIndexed: input.Corpus.FingerprintCount,
				FilesProcessed:      0,
				LastIndexedDigest:   input.Corpus.LastIndexedDigest,
				CompletedAt:         input.Corpus.LastIndexedAt,
			}, nil
		}
		// Do not invoke a.indexer.Index on an already-READY corpus when SourceRef changed without new content,
		// because CorpusIndexer.failCorpus would flip ip_fingerprint_corpora.status from READY to FAILED.
		return api.IPCorpusReindexResult{}, domain.Unprocessable("EMPTY_CORPUS", "corpus contains no files to index")
	}

	files := make([]fingerprints.CorpusFile, 0, len(input.Files))
	for _, f := range input.Files {
		files = append(files, fingerprints.CorpusFile{
			Path:    f.Path,
			Content: []byte(f.Content),
			SHA256:  f.SHA256,
		})
	}

	// Pre-validate source inputs before calling CorpusIndexer.Index on a live READY corpus so
	// client validation errors (400/422) never trigger failCorpus and disable L1/L2 matching.
	if isReady {
		if err := prevalidateReadyCorpusReindex(input.Corpus, dir, files); err != nil {
			return api.IPCorpusReindexResult{}, err
		}
	}

	res, err := a.indexer.Index(ctx, fingerprints.IndexRequest{
		CorpusID: input.Corpus.ID,
		Dir:      dir,
		Files:    files,
		Force:    input.Force,
	})
	if err != nil {
		if mapped := mapReindexContextError(err); mapped != err {
			return api.IPCorpusReindexResult{}, mapped
		}
		return api.IPCorpusReindexResult{}, err
	}

	return api.IPCorpusReindexResult{
		Status:              res.Corpus.Status,
		FingerprintsIndexed: res.FingerprintCount,
		FilesProcessed:      int64(res.FilesIndexed),
		LastIndexedDigest:   res.Corpus.LastIndexedDigest,
		CompletedAt:         res.Corpus.LastIndexedAt,
	}, nil
}

func mapReindexContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.WrapError(domain.ErrUnavailable, "REINDEX_TIMEOUT", "corpus reindex timed out", err)
	}
	if errors.Is(err, context.Canceled) {
		return domain.WrapError(domain.ErrUnavailable, "REINDEX_CANCELLED", "corpus reindex cancelled", err)
	}
	return err
}

func prevalidateReadyCorpusReindex(corpus domain.IPFingerprintCorpus, dir string, files []fingerprints.CorpusFile) error {
	var raw []fingerprints.CorpusFile
	if dir != "" {
		inv, err := inspection.WalkWorkspace(dir)
		if err != nil {
			return err
		}
		if inv.FilesSkipped > 0 || len(inv.SkippedReasons) > 0 {
			return domain.Unprocessable("INCOMPLETE_CORPUS_WALK", "corpus directory contains unreadable, symlinked, or non-regular files")
		}
		raw = make([]fingerprints.CorpusFile, 0, len(inv.Files))
		for _, entry := range inv.Files {
			content, err := os.ReadFile(entry.AbsPath)
			if err != nil {
				return domain.WrapError(domain.ErrUnprocessable, "CORPUS_FILE_READ_FAILED", "failed reading corpus file", err)
			}
			raw = append(raw, fingerprints.CorpusFile{
				Path:    entry.RelPath,
				Content: content,
			})
		}
	} else {
		raw = files
	}

	if len(raw) == 0 {
		return domain.Unprocessable("EMPTY_CORPUS", "corpus contains no files to index")
	}

	winnowK := corpus.WinnowK
	if winnowK <= 0 {
		winnowK = 25
	}
	winnowW := corpus.WinnowW
	if winnowW <= 0 {
		winnowW = 15
	}
	chunkSize := corpus.ChunkSizeBytes
	if chunkSize <= 0 {
		chunkSize = 4096
	}

	seenPaths := make(map[string]struct{}, len(raw))
	hasNonEmptyText := false
	hasExtractable := false
	for _, f := range raw {
		cleanPath, err := normalizeCorpusRelPathForPrevalidate(f.Path)
		if err != nil {
			return err
		}
		if _, dup := seenPaths[cleanPath]; dup {
			return domain.BadRequest("DUPLICATE_CORPUS_PATH", "duplicate file path in corpus")
		}
		seenPaths[cleanPath] = struct{}{}

		if strings.TrimSpace(f.SHA256) != "" {
			expected, err := domain.ParseSHA256Digest(f.SHA256)
			if err != nil {
				return err
			}
			if domain.SHA256Hex(f.Content) != expected {
				return domain.Unprocessable("CORPUS_FILE_DIGEST_MISMATCH", "corpus file content digest mismatch")
			}
		}

		if bytes.IndexByte(f.Content, 0) < 0 && len(bytes.TrimSpace(f.Content)) > 0 {
			hasNonEmptyText = true
		}
		if len(fingerprints.ExtractL1Chunks(cleanPath, f.Content, chunkSize)) > 0 {
			hasExtractable = true
			continue
		}
		if _, winnows := fingerprints.ExtractL2Winnow(cleanPath, f.Content, winnowK, winnowW); len(winnows) > 0 {
			hasExtractable = true
			continue
		}
		hdr := fingerprints.ExtractHeadersAndBody(f.Content)
		if len(hdr.Markers) > 0 || (hdr.HasHeader && hdr.HeaderlessBodyHash != "") {
			hasExtractable = true
		}
	}

	if !hasNonEmptyText {
		return domain.Unprocessable("EMPTY_CORPUS", "corpus contains no non-empty text source files")
	}
	if !hasExtractable {
		return domain.Unprocessable("EMPTY_CORPUS_FINGERPRINTS", "corpus yielded zero extractable fingerprints")
	}
	return nil
}

func normalizeCorpusRelPathForPrevalidate(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsRune(trimmed, '\x00') || strings.ContainsRune(trimmed, '\\') {
		return "", domain.BadRequest("INVALID_CORPUS_PATH", "corpus file path is invalid")
	}
	if strings.HasPrefix(trimmed, "/") || filepath.IsAbs(trimmed) {
		return "", domain.BadRequest("INVALID_CORPUS_PATH", "corpus file path must be relative")
	}
	slash := filepath.ToSlash(filepath.Clean(trimmed))
	slash = strings.TrimPrefix(slash, "./")
	if slash == "" || slash == "." || slash == ".." || strings.HasPrefix(slash, "../") {
		return "", domain.BadRequest("INVALID_CORPUS_PATH", "corpus file path must not traverse outside root")
	}
	return slash, nil
}
