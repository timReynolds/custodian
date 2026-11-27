package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	defaultGitHubAPIURL        = "https://api.github.com/"
	defaultSnapshotStore       = "local"
	defaultLogFormat           = "json"
	defaultLogLevel            = "info"
	defaultPollInterval        = 150 * time.Millisecond
	defaultLeaseDuration       = 15 * time.Second
	defaultHeartbeatInt        = 5 * time.Second
	defaultReapInterval        = 5 * time.Second
	defaultRetentionInterval   = 1 * time.Minute
	defaultArtifactRetention   = 720 * time.Hour
	defaultConcurrency         = 1
	defaultGitBin              = "git"
	defaultShutdownTimeout     = 10 * time.Second
	defaultDBConnectTimeout    = 10 * time.Second
	defaultPolicyFallbackDir   = "policies/defaults"
	defaultModelGatewayTimeout = 30 * time.Second
)

var (
	dsnUserInfoPattern    = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	dsnBareUserPass       = regexp.MustCompile(`\b[^/\s:@]+:[^/\s@]+@`)
	dsnKVPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*=\s*(?:'[^']*'|"[^"]*"|\S+)`)
	pemSecretHeaderRegexp = regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`)
)

// Config holds validated runtime configuration for custodian-worker.
type Config struct {
	DatabaseURL          string
	SnapshotStore        string
	SnapshotDir          string
	SnapshotBucket       string
	SnapshotPrefix       string
	PolicyDir            string
	GitHubAPIBaseURL     string
	GitHubGitBaseURL     string
	AllowInsecureHTTP    bool
	ReadAppID            int64
	ReadPrivateKeyPEM    []byte
	LocalBareGitDir      string
	ModelGatewayURL      string
	RoutePolicy          *decisions.RoutePolicy
	Inspection           inspection.Config
	GlobalScanBudget     int
	GlobalModelBudget    int
	RepoConcurrencyLimit int
	ArtifactRetentionTTL time.Duration
	RetentionInterval    time.Duration
	LogFormat            observability.LogFormat
	LogLevel             slog.Level
	WorkerID             string
	PollInterval         time.Duration
	LeaseDuration        time.Duration
	HeartbeatInterval    time.Duration
	ReapInterval         time.Duration
	Concurrency          int
	GitBinary            string
	ShutdownTimeout      time.Duration
	OTelMode             observability.TraceMode
	OTelEndpoint         string
	Environment          string
	Version              string
}

func (c Config) secrets() []string {
	var out []string
	if c.DatabaseURL != "" {
		out = append(out, c.DatabaseURL)
		if u, err := url.Parse(c.DatabaseURL); err == nil && u.User != nil {
			if pass, ok := u.User.Password(); ok && pass != "" {
				out = append(out, pass, url.QueryEscape(pass))
			}
			if user := u.User.Username(); user != "" {
				if pass, ok := u.User.Password(); ok {
					out = append(out, user+":"+pass)
				}
			}
		}
	}
	if len(c.ReadPrivateKeyPEM) > 0 {
		out = append(out, string(c.ReadPrivateKeyPEM))
	}
	return out
}

func loadConfig(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	logFormat, err := parseLogFormat(getenv("CUSTODIAN_LOG_FORMAT"))
	if err != nil {
		return Config{}, err
	}
	logLevel, err := parseLogLevel(getenv("CUSTODIAN_LOG_LEVEL"))
	if err != nil {
		return Config{}, err
	}

	dsn := strings.TrimSpace(getenv("CUSTODIAN_DATABASE_URL"))
	if dsn == "" {
		return Config{}, domain.BadRequest("MISSING_DATABASE_URL", "CUSTODIAN_DATABASE_URL is required")
	}

	storeKind := strings.ToLower(strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_STORE")))
	if storeKind == "" {
		storeKind = defaultSnapshotStore
	}
	snapshotDir := strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_DIR"))
	snapshotBucket := strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_BUCKET"))
	if snapshotBucket == "" {
		snapshotBucket = strings.TrimSpace(getenv("CUSTODIAN_GCS_BUCKET"))
	}
	snapshotPrefix := strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_PREFIX"))
	if snapshotPrefix == "" {
		snapshotPrefix = strings.TrimSpace(getenv("CUSTODIAN_GCS_PREFIX"))
	}

	switch storeKind {
	case "local":
		if snapshotDir == "" {
			return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "CUSTODIAN_SNAPSHOT_DIR is required when CUSTODIAN_SNAPSHOT_STORE=local")
		}
	case "gcs":
		if snapshotBucket == "" {
			return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "CUSTODIAN_SNAPSHOT_BUCKET is required when CUSTODIAN_SNAPSHOT_STORE=gcs")
		}
	default:
		return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", fmt.Sprintf("unsupported CUSTODIAN_SNAPSHOT_STORE %q", storeKind))
	}

	policyDir := strings.TrimSpace(getenv("CUSTODIAN_POLICY_DIR"))
	if policyDir == "" {
		if info, statErr := os.Stat(defaultPolicyFallbackDir); statErr == nil && info.IsDir() {
			policyDir = defaultPolicyFallbackDir
		}
	}

	apiURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_API_URL"))
	if apiURL == "" {
		apiURL = defaultGitHubAPIURL
	}
	gitURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_GIT_URL"))
	if gitURL == "" {
		gitURL = deriveGitBaseURL(apiURL)
	}

	allowInsecure := isLoopbackHTTP(apiURL) || isLoopbackHTTP(gitURL)
	if rawAllow := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP")); rawAllow != "" {
		parsedBool, bErr := strconv.ParseBool(rawAllow)
		if bErr != nil {
			return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP must be a boolean")
		}
		allowInsecure = parsedBool
	}

	localBareDir := strings.TrimSpace(getenv("CUSTODIAN_LOCAL_BARE_GIT_DIR"))
	rawAppID := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_READ_APP_ID"))
	var appID int64
	var normPEM string

	if rawAppID != "" {
		parsedID, idErr := strconv.ParseInt(rawAppID, 10, 64)
		if idErr != nil || parsedID <= 0 {
			return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_READ_APP_ID must be a positive integer")
		}
		appID = parsedID

		rawPEM := getenv("CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM")
		if strings.TrimSpace(rawPEM) == "" {
			if keyFile := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_READ_PRIVATE_KEY_FILE")); keyFile != "" {
				data, readErr := os.ReadFile(keyFile)
				if readErr != nil {
					return Config{}, domain.WrapError(domain.ErrBadRequest, "INVALID_GITHUB_APP_KEY", "failed reading CUSTODIAN_GITHUB_READ_PRIVATE_KEY_FILE", readErr)
				}
				rawPEM = string(data)
			}
		}
		normPEM = normalizePEM(rawPEM)
		if strings.TrimSpace(normPEM) == "" {
			return Config{}, domain.BadRequest("INVALID_GITHUB_APP_KEY", "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM is required")
		}
	} else if localBareDir == "" {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_READ_APP_ID (or CUSTODIAN_LOCAL_BARE_GIT_DIR) is required")
	}

	inspCfg := inspection.DefaultConfig()
	if v := strings.TrimSpace(getenv(inspection.EnvGitleaksBin)); v != "" {
		inspCfg.GitleaksBin = v
	}
	if v := strings.TrimSpace(getenv(inspection.EnvScanCodeBin)); v != "" {
		inspCfg.ScanCodeBin = v
	}
	if v := strings.TrimSpace(getenv(inspection.EnvSemgrepBin)); v != "" {
		inspCfg.SemgrepBin = v
	}
	if v := strings.TrimSpace(getenv(inspection.EnvTrivyBin)); v != "" {
		inspCfg.TrivyBin = v
	}
	if raw := strings.TrimSpace(getenv(inspection.EnvScannerTimeout)); raw != "" {
		d, dErr := time.ParseDuration(raw)
		if dErr != nil || d <= 0 {
			return Config{}, domain.BadRequest("INVALID_SCANNER_TIMEOUT", "CUSTODIAN_SCANNER_TIMEOUT must be a positive duration")
		}
		inspCfg.ScannerTimeout = d
	}

	globalScanBudget, err := parseOptionalNonNegInt(getenv("CUSTODIAN_GLOBAL_SCAN_BUDGET"), "CUSTODIAN_GLOBAL_SCAN_BUDGET")
	if err != nil {
		return Config{}, err
	}
	globalModelBudget, err := parseOptionalNonNegInt(getenv("CUSTODIAN_GLOBAL_MODEL_BUDGET"), "CUSTODIAN_GLOBAL_MODEL_BUDGET")
	if err != nil {
		return Config{}, err
	}
	repoConcurrencyLimit, err := parseOptionalNonNegInt(getenv("CUSTODIAN_REPO_CONCURRENCY_LIMIT"), "CUSTODIAN_REPO_CONCURRENCY_LIMIT")
	if err != nil {
		return Config{}, err
	}

	rawRetention := strings.TrimSpace(getenv("CUSTODIAN_ARTIFACT_RETENTION"))
	retentionName := "CUSTODIAN_ARTIFACT_RETENTION"
	if rawRetention == "" {
		rawRetention = strings.TrimSpace(getenv("CUSTODIAN_ARTIFACT_RETENTION_TTL"))
		retentionName = "CUSTODIAN_ARTIFACT_RETENTION_TTL"
	}
	retentionTTL, err := parseNonNegDurationEnv(rawRetention, defaultArtifactRetention, retentionName)
	if err != nil {
		return Config{}, err
	}
	routePolicy, err := parseRoutePolicyEnv(getenv("CUSTODIAN_ROUTE_POLICY_JSON"))
	if err != nil {
		return Config{}, err
	}
	retentionInterval, err := parseDurationEnv(getenv("CUSTODIAN_RETENTION_INTERVAL"), defaultRetentionInterval, "CUSTODIAN_RETENTION_INTERVAL")
	if err != nil {
		return Config{}, err
	}

	pollInterval, err := parseDurationEnv(getenv("CUSTODIAN_WORKER_POLL_INTERVAL"), defaultPollInterval, "CUSTODIAN_WORKER_POLL_INTERVAL")
	if err != nil {
		return Config{}, err
	}
	leaseDuration, err := parseDurationEnv(getenv("CUSTODIAN_WORKER_LEASE_DURATION"), defaultLeaseDuration, "CUSTODIAN_WORKER_LEASE_DURATION")
	if err != nil {
		return Config{}, err
	}
	heartbeatInterval, err := parseDurationEnv(getenv("CUSTODIAN_WORKER_HEARTBEAT_INTERVAL"), defaultHeartbeatInt, "CUSTODIAN_WORKER_HEARTBEAT_INTERVAL")
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(getenv("CUSTODIAN_WORKER_HEARTBEAT_INTERVAL")) == "" && leaseDuration >= 3*time.Second {
		heartbeatInterval = leaseDuration / 3
	}
	reapInterval, err := parseDurationEnv(getenv("CUSTODIAN_WORKER_REAP_INTERVAL"), defaultReapInterval, "CUSTODIAN_WORKER_REAP_INTERVAL")
	if err != nil {
		return Config{}, err
	}
	shutdownTimeout, err := parseDurationEnv(getenv("CUSTODIAN_WORKER_SHUTDOWN_TIMEOUT"), defaultShutdownTimeout, "CUSTODIAN_WORKER_SHUTDOWN_TIMEOUT")
	if err != nil {
		return Config{}, err
	}

	concurrency := defaultConcurrency
	if rawConc := strings.TrimSpace(getenv("CUSTODIAN_WORKER_CONCURRENCY")); rawConc != "" {
		c, cErr := strconv.Atoi(rawConc)
		if cErr != nil || c < 1 {
			return Config{}, domain.BadRequest("INVALID_CONFIG", "CUSTODIAN_WORKER_CONCURRENCY must be >= 1")
		}
		concurrency = c
	}

	gitBin := strings.TrimSpace(getenv("CUSTODIAN_WORKER_GIT_BIN"))
	if gitBin == "" {
		gitBin = defaultGitBin
	}

	otelMode := observability.TraceMode(strings.ToLower(strings.TrimSpace(getenv("CUSTODIAN_OTEL_MODE"))))
	if otelMode == "" {
		otelMode = observability.TraceModeNoop
	}
	otelEndpoint := strings.TrimSpace(getenv("CUSTODIAN_OTEL_EXPORTER_OTLP_ENDPOINT"))
	if otelEndpoint == "" {
		otelEndpoint = strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}

	return Config{
		DatabaseURL:          dsn,
		SnapshotStore:        storeKind,
		SnapshotDir:          snapshotDir,
		SnapshotBucket:       snapshotBucket,
		SnapshotPrefix:       snapshotPrefix,
		PolicyDir:            policyDir,
		GitHubAPIBaseURL:     apiURL,
		GitHubGitBaseURL:     gitURL,
		AllowInsecureHTTP:    allowInsecure,
		ReadAppID:            appID,
		ReadPrivateKeyPEM:    []byte(normPEM),
		LocalBareGitDir:      localBareDir,
		ModelGatewayURL:      strings.TrimSpace(getenv("CUSTODIAN_MODEL_GATEWAY_URL")),
		RoutePolicy:          routePolicy,
		Inspection:           inspCfg,
		GlobalScanBudget:     globalScanBudget,
		GlobalModelBudget:    globalModelBudget,
		RepoConcurrencyLimit: repoConcurrencyLimit,
		ArtifactRetentionTTL: retentionTTL,
		RetentionInterval:    retentionInterval,
		LogFormat:            logFormat,
		LogLevel:             logLevel,
		WorkerID:             strings.TrimSpace(getenv("CUSTODIAN_WORKER_ID")),
		PollInterval:         pollInterval,
		LeaseDuration:        leaseDuration,
		HeartbeatInterval:    heartbeatInterval,
		ReapInterval:         reapInterval,
		Concurrency:          concurrency,
		GitBinary:            gitBin,
		ShutdownTimeout:      shutdownTimeout,
		OTelMode:             otelMode,
		OTelEndpoint:         otelEndpoint,
		Environment:          strings.TrimSpace(getenv("CUSTODIAN_ENVIRONMENT")),
		Version:              strings.TrimSpace(getenv("CUSTODIAN_VERSION")),
	}, nil
}

func parseOptionalNonNegInt(raw, name string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(trimmed)
	if err != nil || v < 0 {
		return 0, domain.BadRequest("INVALID_CONFIG", fmt.Sprintf("%s must be a non-negative integer", name))
	}
	return v, nil
}

func parseLogFormat(raw string) (observability.LogFormat, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		v = defaultLogFormat
	}
	switch observability.LogFormat(v) {
	case observability.LogFormatJSON, observability.LogFormatText:
		return observability.LogFormat(v), nil
	default:
		return "", domain.BadRequest("INVALID_LOG_FORMAT", fmt.Sprintf("unsupported CUSTODIAN_LOG_FORMAT %q", raw))
	}
}

func parseLogLevel(raw string) (slog.Level, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		v = defaultLogLevel
	}
	switch v {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, domain.BadRequest("INVALID_LOG_LEVEL", fmt.Sprintf("unsupported CUSTODIAN_LOG_LEVEL %q", raw))
	}
}

func parseDurationEnv(raw string, def time.Duration, name string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return def, nil
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil || d <= 0 {
		return 0, domain.BadRequest("INVALID_DURATION", fmt.Sprintf("%s must be a positive duration", name))
	}
	return d, nil
}

func parseNonNegDurationEnv(raw string, def time.Duration, name string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return def, nil
	}
	d, err := time.ParseDuration(trimmed)
	if err != nil || d < 0 {
		return 0, domain.BadRequest("INVALID_DURATION", fmt.Sprintf("%s must be a non-negative duration", name))
	}
	return d, nil
}

func normalizePEM(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "\n") && strings.Contains(trimmed, `\n`) {
		trimmed = strings.ReplaceAll(trimmed, `\r\n`, "\n")
		trimmed = strings.ReplaceAll(trimmed, `\n`, "\n")
	}
	return trimmed
}

func deriveGitBaseURL(apiURL string) string {
	trimmed := strings.TrimSpace(apiURL)
	u, err := url.Parse(trimmed)
	if err != nil {
		return strings.TrimRight(trimmed, "/")
	}
	if strings.EqualFold(u.Hostname(), "api.github.com") {
		return ""
	}
	cleanPath := strings.TrimRight(u.Path, "/")
	cleanPath = strings.TrimSuffix(cleanPath, "/api/v3")
	u.Path = cleanPath
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func isLoopbackHTTP(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sanitizeErrorMessage(err error, secrets ...string) (code string, msg string) {
	if err == nil {
		return "", ""
	}
	code = "WORKER_ERROR"
	raw := err.Error()
	var de *domain.DomainError
	if asDomainError(err, &de) {
		code = de.Code()
		raw = de.Message
	}
	if raw == "" {
		raw = code
	}
	return code, redactString(raw, secrets...)
}

func asDomainError(err error, target **domain.DomainError) bool {
	for err != nil {
		if de, ok := err.(*domain.DomainError); ok {
			*target = de
			return true
		}
		type unwrapper interface {
			Unwrap() error
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func redactString(raw string, secrets ...string) string {
	out := strings.TrimSpace(raw)
	for _, s := range secrets {
		if s != "" {
			out = strings.ReplaceAll(out, s, "[REDACTED]")
		}
	}
	out = dsnUserInfoPattern.ReplaceAllString(out, "${1}[REDACTED]@")
	out = dsnBareUserPass.ReplaceAllString(out, "[REDACTED]@")
	out = dsnKVPasswordPattern.ReplaceAllString(out, "password=[REDACTED]")
	out = pemSecretHeaderRegexp.ReplaceAllString(out, "[REDACTED]")
	return out
}

func defaultWorkerRoutePolicy() *decisions.RoutePolicy {
	return &decisions.RoutePolicy{
		RouteMaxClassification: map[string]domain.Classification{
			"openai/gpt-5":            domain.ClassificationInternal,
			"openai/gpt-4o":           domain.ClassificationInternal,
			"openai/gpt-4":            domain.ClassificationInternal,
			"anthropic/claude-public": domain.ClassificationInternal,
			"public-cloud":            domain.ClassificationInternal,
			"public-route":            domain.ClassificationInternal,
			"public-cheap-route":      domain.ClassificationInternal,
		},
	}
}

func parseRoutePolicyEnv(raw string) (*decisions.RoutePolicy, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultWorkerRoutePolicy(), nil
	}
	var dto struct {
		ClassificationRoutes      map[string][]string `json:"classification_routes"`
		RequireClassificationRule bool                `json:"require_classification_rule"`
		RouteMaxClassification    map[string]string   `json:"route_max_classification"`
	}
	if err := json.Unmarshal([]byte(trimmed), &dto); err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_ROUTE_POLICY", "CUSTODIAN_ROUTE_POLICY_JSON must be valid JSON", err)
	}
	pol := &decisions.RoutePolicy{
		RequireClassificationRule: dto.RequireClassificationRule,
	}
	if len(dto.ClassificationRoutes) > 0 {
		pol.ClassificationRoutes = make(map[domain.Classification][]string, len(dto.ClassificationRoutes))
		for k, v := range dto.ClassificationRoutes {
			cls := domain.Classification(strings.ToUpper(strings.TrimSpace(k)))
			if !cls.IsValid() {
				return nil, domain.BadRequest("INVALID_ROUTE_POLICY", fmt.Sprintf("invalid classification %q in CUSTODIAN_ROUTE_POLICY_JSON", k))
			}
			pol.ClassificationRoutes[cls] = append([]string(nil), v...)
		}
	}
	if len(dto.RouteMaxClassification) > 0 {
		pol.RouteMaxClassification = make(map[string]domain.Classification, len(dto.RouteMaxClassification))
		for route, rawCls := range dto.RouteMaxClassification {
			cls := domain.Classification(strings.ToUpper(strings.TrimSpace(rawCls)))
			if !cls.IsValid() {
				return nil, domain.BadRequest("INVALID_ROUTE_POLICY", fmt.Sprintf("invalid max classification %q for route %q", rawCls, route))
			}
			pol.RouteMaxClassification[strings.TrimSpace(route)] = cls
		}
	}
	return pol, nil
}
