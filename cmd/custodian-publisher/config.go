package main

import (
	"errors"
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
	defaultGitHubAPIURL     = "https://api.github.com/"
	defaultSnapshotStore    = "local"
	defaultLogFormat        = "json"
	defaultLogLevel         = "info"
	defaultPollInterval     = 150 * time.Millisecond
	defaultLeaseDuration    = 15 * time.Second
	defaultHeartbeatInt     = 5 * time.Second
	defaultReapInterval     = 5 * time.Second
	defaultConcurrency      = 1
	defaultGitBin           = "git"
	defaultCommitterName    = "Custodian"
	defaultCommitterEmail   = "custodian@custodian.local"
	defaultShutdownTimeout  = 10 * time.Second
	defaultDBConnectTimeout = 10 * time.Second
)

var (
	dsnUserInfoPattern    = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	dsnBareUserPass       = regexp.MustCompile(`\b[^/\s:@]+:[^/\s@]+@`)
	dsnKVPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*=\s*(?:'[^']*'|"[^"]*"|\S+)`)
	pemSecretHeaderRegexp = regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`)
)

// Config holds validated runtime configuration for custodian-publisher.
type Config struct {
	DatabaseURL        string
	SnapshotStore      string
	SnapshotDir        string
	SnapshotBucket     string
	SnapshotPrefix     string
	GitHubAPIBaseURL   string
	GitHubGitBaseURL   string
	AllowInsecureHTTP  bool
	WriteAppID         int64
	WritePrivateKeyPEM []byte
	LogFormat          observability.LogFormat
	LogLevel           slog.Level
	WorkerID           string
	PollInterval       time.Duration
	LeaseDuration      time.Duration
	HeartbeatInterval  time.Duration
	ReapInterval       time.Duration
	Concurrency        int
	GitBinary          string
	CommitterName      string
	CommitterEmail     string
	ShutdownTimeout    time.Duration
	OTelMode           observability.TraceMode
	OTelEndpoint       string
	Environment        string
	Version            string
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
	if len(c.WritePrivateKeyPEM) > 0 {
		out = append(out, string(c.WritePrivateKeyPEM))
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

	rawAppID := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_WRITE_APP_ID"))
	if rawAppID == "" {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_WRITE_APP_ID is required")
	}
	appID, err := strconv.ParseInt(rawAppID, 10, 64)
	if err != nil || appID <= 0 {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_WRITE_APP_ID must be a positive integer")
	}

	rawPEM := getenv("CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM")
	if strings.TrimSpace(rawPEM) == "" {
		if keyFile := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_FILE")); keyFile != "" {
			data, readErr := os.ReadFile(keyFile)
			if readErr != nil {
				return Config{}, domain.WrapError(domain.ErrBadRequest, "INVALID_GITHUB_APP_KEY", "failed reading CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_FILE", readErr)
			}
			rawPEM = string(data)
		}
	}
	normPEM := normalizePEM(rawPEM)
	if strings.TrimSpace(normPEM) == "" {
		return Config{}, domain.BadRequest("INVALID_GITHUB_APP_KEY", "CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM is required")
	}

	apiURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_API_URL"))
	if apiURL == "" {
		apiURL = defaultGitHubAPIURL
	}
	gitURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_GIT_URL"))

	allowInsecure := isLoopbackHTTP(apiURL) && (gitURL == "" || isLoopbackHTTP(gitURL))
	if rawAllow := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP")); rawAllow != "" {
		parsedBool, bErr := strconv.ParseBool(rawAllow)
		if bErr != nil {
			return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP must be a boolean")
		}
		allowInsecure = parsedBool
	}

	pollInterval, err := parseDurationEnv(getenv("CUSTODIAN_PUBLISHER_POLL_INTERVAL"), defaultPollInterval, "CUSTODIAN_PUBLISHER_POLL_INTERVAL")
	if err != nil {
		return Config{}, err
	}
	leaseDuration, err := parseDurationEnv(getenv("CUSTODIAN_PUBLISHER_LEASE_DURATION"), defaultLeaseDuration, "CUSTODIAN_PUBLISHER_LEASE_DURATION")
	if err != nil {
		return Config{}, err
	}
	heartbeatInterval, err := parseDurationEnv(getenv("CUSTODIAN_PUBLISHER_HEARTBEAT_INTERVAL"), defaultHeartbeatInt, "CUSTODIAN_PUBLISHER_HEARTBEAT_INTERVAL")
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(getenv("CUSTODIAN_PUBLISHER_HEARTBEAT_INTERVAL")) == "" && leaseDuration >= 3*time.Second {
		heartbeatInterval = leaseDuration / 3
	}
	reapInterval, err := parseDurationEnv(getenv("CUSTODIAN_PUBLISHER_REAP_INTERVAL"), defaultReapInterval, "CUSTODIAN_PUBLISHER_REAP_INTERVAL")
	if err != nil {
		return Config{}, err
	}
	shutdownTimeout, err := parseDurationEnv(getenv("CUSTODIAN_PUBLISHER_SHUTDOWN_TIMEOUT"), defaultShutdownTimeout, "CUSTODIAN_PUBLISHER_SHUTDOWN_TIMEOUT")
	if err != nil {
		return Config{}, err
	}

	concurrency := defaultConcurrency
	if rawConc := strings.TrimSpace(getenv("CUSTODIAN_PUBLISHER_CONCURRENCY")); rawConc != "" {
		c, cErr := strconv.Atoi(rawConc)
		if cErr != nil || c < 1 {
			return Config{}, domain.BadRequest("INVALID_CONFIG", "CUSTODIAN_PUBLISHER_CONCURRENCY must be >= 1")
		}
		concurrency = c
	}

	gitBin := strings.TrimSpace(getenv("CUSTODIAN_PUBLISHER_GIT_BIN"))
	if gitBin == "" {
		gitBin = defaultGitBin
	}
	committerName := strings.TrimSpace(getenv("CUSTODIAN_PUBLISHER_COMMITTER_NAME"))
	if committerName == "" {
		committerName = defaultCommitterName
	}
	committerEmail := strings.TrimSpace(getenv("CUSTODIAN_PUBLISHER_COMMITTER_EMAIL"))
	if committerEmail == "" {
		committerEmail = defaultCommitterEmail
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
		DatabaseURL:        dsn,
		SnapshotStore:      storeKind,
		SnapshotDir:        snapshotDir,
		SnapshotBucket:     snapshotBucket,
		SnapshotPrefix:     snapshotPrefix,
		GitHubAPIBaseURL:   apiURL,
		GitHubGitBaseURL:   gitURL,
		AllowInsecureHTTP:  allowInsecure,
		WriteAppID:         appID,
		WritePrivateKeyPEM: []byte(normPEM),
		LogFormat:          logFormat,
		LogLevel:           logLevel,
		WorkerID:           strings.TrimSpace(getenv("CUSTODIAN_PUBLISHER_WORKER_ID")),
		PollInterval:       pollInterval,
		LeaseDuration:      leaseDuration,
		HeartbeatInterval:  heartbeatInterval,
		ReapInterval:       reapInterval,
		Concurrency:        concurrency,
		GitBinary:          gitBin,
		CommitterName:      committerName,
		CommitterEmail:     committerEmail,
		ShutdownTimeout:    shutdownTimeout,
		OTelMode:           otelMode,
		OTelEndpoint:       otelEndpoint,
		Environment:        strings.TrimSpace(getenv("CUSTODIAN_ENVIRONMENT")),
		Version:            strings.TrimSpace(getenv("CUSTODIAN_VERSION")),
	}, nil
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
	code = "PUBLISHER_ERROR"
	raw := err.Error()
	if domErr, ok := err.(*domain.DomainError); ok {
		code = domErr.Code()
		raw = domErr.Message
	} else {
		// Check wrapped DomainError via errors.As without printing internal Cause.
		var de *domain.DomainError
		if asDomainError(err, &de) {
			code = de.Code()
			raw = de.Message
		}
	}
	if raw == "" {
		raw = code
	}
	return code, redactString(raw, secrets...)
}

func asDomainError(err error, target **domain.DomainError) bool {
	return errors.As(err, target)
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
