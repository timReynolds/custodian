package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	defaultListenAddr       = "127.0.0.1:8080"
	defaultSnapshotStore    = "local"
	defaultGitHubAPIURL     = "https://api.github.com/"
	defaultLogFormat        = "json"
	defaultLogLevel         = "info"
	defaultArtifactTTL      = 720 * time.Hour
	defaultCapabilityTTL    = 5 * time.Minute
	defaultMaxUploadBytes   = int64(64 << 20)
	defaultShutdownTimeout  = 10 * time.Second
	defaultDBConnectTimeout = 10 * time.Second
)

var (
	dsnUserInfoPattern    = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	dsnBareUserPass       = regexp.MustCompile(`\b[^/\s:@]+:[^/\s@]+@`)
	dsnKVPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*=\s*(?:'[^']*'|"[^"]*"|\S+)`)
	pemSecretHeaderRegexp = regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`)
)

// Config holds validated runtime configuration for custodian-api.
type Config struct {
	ListenAddr           string
	BaseURL              string
	DatabaseURL          string
	SnapshotStore        string
	SnapshotDir          string
	SnapshotBucket       string
	SnapshotPrefix       string
	OIDCIssuer           string
	OIDCJWKSURL          string
	OIDCAudience         string
	CapabilitySecret     []byte
	GitHubAPIBaseURL     string
	GitHubGitBaseURL     string
	AllowInsecureHTTP    bool
	ReadAppID            int64
	ReadPrivateKeyPEM    []byte
	PolicyDir            string
	RepoConcurrencyLimit int
	GlobalScanBudget     int
	GlobalModelBudget    int
	ArtifactRetentionTTL time.Duration
	CapabilityTTL        time.Duration
	MaxUploadBytes       int64
	LogFormat            observability.LogFormat
	LogLevel             slog.Level
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
	if len(c.CapabilitySecret) > 0 {
		out = append(out, string(c.CapabilitySecret))
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

	listenAddr := strings.TrimSpace(getenv("CUSTODIAN_LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	dsn := strings.TrimSpace(getenv("CUSTODIAN_DATABASE_URL"))
	if dsn == "" {
		return Config{}, domain.BadRequest("MISSING_DATABASE_URL", "CUSTODIAN_DATABASE_URL is required")
	}

	storeKind := strings.ToLower(strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_STORE")))
	if storeKind == "" {
		storeKind = defaultSnapshotStore
	}
	snapshotDir := strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_ROOT"))
	if snapshotDir == "" {
		snapshotDir = strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_DIR"))
	}
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
			return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "CUSTODIAN_SNAPSHOT_ROOT or CUSTODIAN_SNAPSHOT_DIR is required when CUSTODIAN_SNAPSHOT_STORE=local")
		}
	case "gcs":
		if snapshotBucket == "" {
			return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "CUSTODIAN_SNAPSHOT_BUCKET is required when CUSTODIAN_SNAPSHOT_STORE=gcs")
		}
	default:
		return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", fmt.Sprintf("unsupported CUSTODIAN_SNAPSHOT_STORE %q", storeKind))
	}

	oidcIssuer := strings.TrimSpace(getenv("CUSTODIAN_OIDC_ISSUER"))
	if oidcIssuer == "" {
		return Config{}, domain.BadRequest("INVALID_OIDC_CONFIG", "CUSTODIAN_OIDC_ISSUER is required")
	}
	oidcJWKSURL := strings.TrimSpace(getenv("CUSTODIAN_OIDC_JWKS_URL"))
	oidcAudience := strings.TrimSpace(getenv("CUSTODIAN_OIDC_AUDIENCE"))
	if oidcAudience == "" {
		return Config{}, domain.BadRequest("INVALID_OIDC_CONFIG", "CUSTODIAN_OIDC_AUDIENCE is required")
	}

	capSecret := getenv("CUSTODIAN_CAPABILITY_HMAC_SECRET")
	if len(capSecret) < 32 {
		return Config{}, domain.BadRequest("INVALID_CAPABILITY_SECRET", "CUSTODIAN_CAPABILITY_HMAC_SECRET must be at least 32 bytes")
	}

	rawAppID := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_READ_APP_ID"))
	if rawAppID == "" {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_READ_APP_ID is required")
	}
	appID, err := strconv.ParseInt(rawAppID, 10, 64)
	if err != nil || appID <= 0 {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_READ_APP_ID must be a positive integer")
	}

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
	normPEM := normalizePEM(rawPEM)
	if strings.TrimSpace(normPEM) == "" {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_KEY", "CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM is required")
	}

	apiURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_API_URL"))
	if apiURL == "" {
		apiURL = defaultGitHubAPIURL
	}
	gitURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_GIT_URL"))

	allowInsecure := isLoopbackHTTP(apiURL)
	if rawAllow := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP")); rawAllow != "" {
		parsedBool, bErr := strconv.ParseBool(rawAllow)
		if bErr != nil {
			return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP must be a boolean")
		}
		allowInsecure = parsedBool
	}

	repoConcurrency, err := parseNonNegativeIntEnv(getenv("CUSTODIAN_REPO_CONCURRENCY_LIMIT"), 0, "CUSTODIAN_REPO_CONCURRENCY_LIMIT")
	if err != nil {
		return Config{}, err
	}
	globalScanBudget, err := parseNonNegativeIntEnv(getenv("CUSTODIAN_GLOBAL_SCAN_BUDGET"), 0, "CUSTODIAN_GLOBAL_SCAN_BUDGET")
	if err != nil {
		return Config{}, err
	}
	globalModelBudget, err := parseNonNegativeIntEnv(getenv("CUSTODIAN_GLOBAL_MODEL_BUDGET"), 0, "CUSTODIAN_GLOBAL_MODEL_BUDGET")
	if err != nil {
		return Config{}, err
	}

	rawRetention := strings.TrimSpace(getenv("CUSTODIAN_ARTIFACT_RETENTION"))
	retentionName := "CUSTODIAN_ARTIFACT_RETENTION"
	if rawRetention == "" {
		rawRetention = strings.TrimSpace(getenv("CUSTODIAN_ARTIFACT_RETENTION_TTL"))
		retentionName = "CUSTODIAN_ARTIFACT_RETENTION_TTL"
	}
	artifactRetention, err := parseDurationEnv(rawRetention, defaultArtifactTTL, retentionName)
	if err != nil {
		return Config{}, err
	}

	capabilityTTL, err := parseDurationEnv(getenv("CUSTODIAN_CAPABILITY_TTL"), defaultCapabilityTTL, "CUSTODIAN_CAPABILITY_TTL")
	if err != nil {
		return Config{}, err
	}

	maxUploadBytes := defaultMaxUploadBytes
	if rawMax := strings.TrimSpace(getenv("CUSTODIAN_MAX_UPLOAD_BYTES")); rawMax != "" {
		v, pErr := strconv.ParseInt(rawMax, 10, 64)
		if pErr != nil || v < 1 {
			return Config{}, domain.BadRequest("INVALID_CONFIG", "CUSTODIAN_MAX_UPLOAD_BYTES must be a positive integer")
		}
		maxUploadBytes = v
	}

	shutdownTimeout, err := parseDurationEnv(getenv("CUSTODIAN_API_SHUTDOWN_TIMEOUT"), defaultShutdownTimeout, "CUSTODIAN_API_SHUTDOWN_TIMEOUT")
	if err != nil {
		return Config{}, err
	}

	otelMode := observability.TraceMode(strings.ToLower(strings.TrimSpace(getenv("CUSTODIAN_OTEL_MODE"))))
	if otelMode == "" || otelMode == "off" {
		otelMode = observability.TraceModeNoop
	}
	otelEndpoint := strings.TrimSpace(getenv("CUSTODIAN_OTEL_EXPORTER_OTLP_ENDPOINT"))
	if otelEndpoint == "" {
		otelEndpoint = strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}

	baseURL := strings.TrimSpace(getenv("CUSTODIAN_API_PUBLIC_URL"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(getenv("CUSTODIAN_BASE_URL"))
	}

	return Config{
		ListenAddr:           listenAddr,
		BaseURL:              baseURL,
		DatabaseURL:          dsn,
		SnapshotStore:        storeKind,
		SnapshotDir:          snapshotDir,
		SnapshotBucket:       snapshotBucket,
		SnapshotPrefix:       snapshotPrefix,
		OIDCIssuer:           oidcIssuer,
		OIDCJWKSURL:          oidcJWKSURL,
		OIDCAudience:         oidcAudience,
		CapabilitySecret:     []byte(capSecret),
		GitHubAPIBaseURL:     apiURL,
		GitHubGitBaseURL:     gitURL,
		AllowInsecureHTTP:    allowInsecure,
		ReadAppID:            appID,
		ReadPrivateKeyPEM:    []byte(normPEM),
		PolicyDir:            strings.TrimSpace(getenv("CUSTODIAN_POLICY_DIR")),
		RepoConcurrencyLimit: repoConcurrency,
		GlobalScanBudget:     globalScanBudget,
		GlobalModelBudget:    globalModelBudget,
		ArtifactRetentionTTL: artifactRetention,
		CapabilityTTL:        capabilityTTL,
		MaxUploadBytes:       maxUploadBytes,
		LogFormat:            logFormat,
		LogLevel:             logLevel,
		ShutdownTimeout:      shutdownTimeout,
		OTelMode:             otelMode,
		OTelEndpoint:         otelEndpoint,
		Environment:          strings.TrimSpace(getenv("CUSTODIAN_ENVIRONMENT")),
		Version:              strings.TrimSpace(getenv("CUSTODIAN_VERSION")),
	}, nil
}

func parseNonNegativeIntEnv(raw string, def int, name string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return def, nil
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
	code = "API_ERROR"
	raw := err.Error()
	var domErr *domain.DomainError
	if asDomainError(err, &domErr) {
		code = domErr.Code()
		raw = domErr.Message
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
