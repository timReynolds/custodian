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
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	defaultHTTPAddr            = "127.0.0.1:8443"
	defaultSSHAddr             = "127.0.0.1:2222"
	defaultUpstreamURL         = "https://github.com"
	defaultGitHubAPIURL        = "https://api.github.com/"
	defaultSnapshotStore       = "local"
	defaultPolicyFallbackDir   = "policies/defaults"
	defaultLogFormat           = "json"
	defaultLogLevel            = "info"
	defaultArtifactTTL         = 720 * time.Hour
	defaultShutdownTimeout     = 10 * time.Second
	defaultDBConnectTimeout    = 10 * time.Second
	defaultModelGatewayTimeout = 15 * time.Second
	defaultGitBinary           = "git"
	defaultMaxPackBytes        = int64(64 << 20)
	defaultMaxObjects          = 10_000
	defaultMaxInflatedBytes    = int64(32 << 20)
	defaultMaxRefUpdates       = 100
)

var (
	dsnUserInfoPattern    = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@]+@`)
	dsnBareUserPass       = regexp.MustCompile(`\b[^/\s:@]+:[^/\s@]+@`)
	dsnKVPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*=\s*(?:'[^']*'|"[^"]*"|\S+)`)
	pemSecretHeaderRegexp = regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*-----`)
	sshKeyMaterialRegexp  = regexp.MustCompile(`(?i)\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+[A-Za-z0-9+/=]{16,}`)
)

// Config holds validated runtime configuration for custodian-git-gateway.
type Config struct {
	HTTPAddr             string
	SSHAddr              string
	TLSCertFile          string
	TLSKeyFile           string
	TLSKeyPEM            []byte
	SSHHostKeyFile       string
	SSHHostKeyPEM        []byte
	SSHUserCAFile        string
	SSHUserCAPubKey      []byte
	UpstreamURL          string
	APIBaseURL           string
	DatabaseURL          string
	SnapshotStore        string
	SnapshotDir          string
	SnapshotBucket       string
	SnapshotPrefix       string
	PolicyDir            string
	OIDCIssuer           string
	OIDCJWKSURL          string
	OIDCAudience         string
	CapabilitySecret     []byte
	GitHubAPIBaseURL     string
	GitHubGitBaseURL     string
	AllowInsecureHTTP    bool
	ReadAppID            int64
	ReadPrivateKeyPEM    []byte
	WriteAppID           int64
	WritePrivateKeyPEM   []byte
	ModelGatewayURL      string
	RoutePolicy          *decisions.RoutePolicy
	Inspection           inspection.Config
	QuarantineLimits     quarantine.Limits
	DefaultEgressMode    domain.EgressMode
	PassiveDelivery      domain.PassiveAuditDelivery
	RepoConcurrencyLimit int
	GlobalScanBudget     int
	GlobalModelBudget    int
	ArtifactRetentionTTL time.Duration
	GitBinary            string
	LogFormat            observability.LogFormat
	LogLevel             slog.Level
	ShutdownTimeout      time.Duration
	OTelMode             observability.TraceMode
	OTelEndpoint         string
	Environment          string
	Version              string
}

func (c Config) sshEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(c.SSHAddr))
	return v != "" && v != "off" && v != "disabled"
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
	if len(c.WritePrivateKeyPEM) > 0 {
		out = append(out, string(c.WritePrivateKeyPEM))
	}
	if len(c.CapabilitySecret) > 0 {
		out = append(out, string(c.CapabilitySecret))
	}
	if len(c.TLSKeyPEM) > 0 {
		out = append(out, string(c.TLSKeyPEM))
	}
	if len(c.SSHHostKeyPEM) > 0 {
		out = append(out, string(c.SSHHostKeyPEM))
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

	httpAddr := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_HTTP_ADDR"))
	if httpAddr == "" {
		httpAddr = defaultHTTPAddr
	}
	sshAddr := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_SSH_ADDR"))
	if sshAddr == "" {
		sshAddr = defaultSSHAddr
	}

	tlsCertFile := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE"))
	tlsKeyFile := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE"))
	if tlsCertFile == "" || tlsKeyFile == "" {
		return Config{}, domain.BadRequest("INVALID_TLS_CONFIG", "CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE and CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE are required")
	}
	if _, err := os.Stat(tlsCertFile); err != nil {
		return Config{}, domain.WrapError(domain.ErrBadRequest, "INVALID_TLS_CONFIG", "failed reading CUSTODIAN_GIT_GATEWAY_TLS_CERT_FILE", err)
	}
	tlsKeyPEM, err := os.ReadFile(tlsKeyFile)
	if err != nil {
		return Config{}, domain.WrapError(domain.ErrBadRequest, "INVALID_TLS_CONFIG", "failed reading CUSTODIAN_GIT_GATEWAY_TLS_KEY_FILE", err)
	}

	sshHostKeyFile := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE"))
	sshUserCAFile := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE"))
	var sshHostKeyPEM, sshUserCAPubKey []byte
	sshOff := strings.EqualFold(sshAddr, "off") || strings.EqualFold(sshAddr, "disabled")
	if !sshOff {
		if sshHostKeyFile == "" || sshUserCAFile == "" {
			return Config{}, domain.BadRequest("INVALID_SSH_CONFIG", "CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE and CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE are required when SSH is enabled")
		}
		sshHostKeyPEM, err = os.ReadFile(sshHostKeyFile)
		if err != nil {
			return Config{}, domain.WrapError(domain.ErrBadRequest, "INVALID_SSH_CONFIG", "failed reading CUSTODIAN_GIT_GATEWAY_SSH_HOST_KEY_FILE", err)
		}
		sshUserCAPubKey, err = os.ReadFile(sshUserCAFile)
		if err != nil {
			return Config{}, domain.WrapError(domain.ErrBadRequest, "INVALID_SSH_CONFIG", "failed reading CUSTODIAN_GIT_GATEWAY_SSH_USER_CA_FILE", err)
		}
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
	if snapshotDir == "" {
		snapshotDir = strings.TrimSpace(getenv("CUSTODIAN_SNAPSHOT_ROOT"))
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
			return Config{}, domain.BadRequest("INVALID_SNAPSHOT_CONFIG", "CUSTODIAN_SNAPSHOT_DIR or CUSTODIAN_SNAPSHOT_ROOT is required when CUSTODIAN_SNAPSHOT_STORE=local")
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

	oidcIssuer := strings.TrimSpace(getenv("CUSTODIAN_OIDC_ISSUER"))
	if oidcIssuer == "" {
		return Config{}, domain.BadRequest("INVALID_OIDC_CONFIG", "CUSTODIAN_OIDC_ISSUER is required")
	}
	oidcJWKSURL := strings.TrimSpace(getenv("CUSTODIAN_OIDC_JWKS_URL"))
	oidcAudience := strings.TrimSpace(getenv("CUSTODIAN_OIDC_AUDIENCE"))
	if oidcAudience == "" {
		return Config{}, domain.BadRequest("INVALID_OIDC_CONFIG", "CUSTODIAN_OIDC_AUDIENCE is required")
	}

	var capSecret []byte
	if rawCap := getenv("CUSTODIAN_CAPABILITY_HMAC_SECRET"); rawCap != "" {
		if len(rawCap) < 32 {
			return Config{}, domain.BadRequest("INVALID_CAPABILITY_SECRET", "CUSTODIAN_CAPABILITY_HMAC_SECRET must be at least 32 bytes")
		}
		capSecret = []byte(rawCap)
	}

	apiURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_API_URL"))
	if apiURL == "" {
		apiURL = defaultGitHubAPIURL
	}
	gitURL := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_GIT_URL"))

	upstreamURL := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL"))
	if upstreamURL == "" {
		upstreamURL = gitURL
	}
	if upstreamURL == "" {
		upstreamURL = defaultUpstreamURL
	}
	parsedUp, upErr := url.Parse(upstreamURL)
	if upErr != nil || parsedUp.Host == "" || (!strings.EqualFold(parsedUp.Scheme, "http") && !strings.EqualFold(parsedUp.Scheme, "https")) {
		return Config{}, domain.BadRequest("INVALID_UPSTREAM_URL", "CUSTODIAN_GIT_GATEWAY_UPSTREAM_URL must be a valid http/https URL")
	}

	gatewayAPIBaseURL := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_API_BASE_URL"))
	if gatewayAPIBaseURL != "" {
		u, uErr := url.Parse(gatewayAPIBaseURL)
		if uErr != nil || u.Host == "" || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
			return Config{}, domain.BadRequest("INVALID_API_BASE_URL", "CUSTODIAN_GIT_GATEWAY_API_BASE_URL must be a valid http/https URL")
		}
	}

	allowInsecure := isLoopbackHTTP(apiURL) || isLoopbackHTTP(gitURL) || isLoopbackHTTP(upstreamURL)
	if rawAllow := strings.TrimSpace(getenv("CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP")); rawAllow != "" {
		parsedBool, bErr := strconv.ParseBool(rawAllow)
		if bErr != nil {
			return Config{}, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_ALLOW_INSECURE_HTTP must be a boolean")
		}
		allowInsecure = parsedBool
	}

	readAppID, readKeyPEM, err := loadGitHubAppCreds(
		getenv,
		"CUSTODIAN_GITHUB_READ_APP_ID",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_PEM",
		"CUSTODIAN_GITHUB_READ_PRIVATE_KEY_FILE",
	)
	if err != nil {
		return Config{}, err
	}
	writeAppID, writeKeyPEM, err := loadGitHubAppCreds(
		getenv,
		"CUSTODIAN_GITHUB_WRITE_APP_ID",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_PEM",
		"CUSTODIAN_GITHUB_WRITE_PRIVATE_KEY_FILE",
	)
	if err != nil {
		return Config{}, err
	}

	maxPackBytes, err := parsePositiveInt64Env(getenv("CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES"), defaultMaxPackBytes, "CUSTODIAN_GIT_GATEWAY_MAX_PACK_BYTES")
	if err != nil {
		return Config{}, err
	}
	maxObjects, err := parsePositiveIntEnv(getenv("CUSTODIAN_GIT_GATEWAY_MAX_OBJECTS"), defaultMaxObjects, "CUSTODIAN_GIT_GATEWAY_MAX_OBJECTS")
	if err != nil {
		return Config{}, err
	}
	maxInflatedBytes, err := parsePositiveInt64Env(getenv("CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES"), defaultMaxInflatedBytes, "CUSTODIAN_GIT_GATEWAY_MAX_INFLATED_BYTES")
	if err != nil {
		return Config{}, err
	}
	maxRefUpdates, err := parsePositiveIntEnv(getenv("CUSTODIAN_GIT_GATEWAY_MAX_REF_UPDATES"), defaultMaxRefUpdates, "CUSTODIAN_GIT_GATEWAY_MAX_REF_UPDATES")
	if err != nil {
		return Config{}, err
	}

	defaultEgressMode := domain.EgressMode(strings.ToUpper(strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE"))))
	if defaultEgressMode == "" {
		defaultEgressMode = domain.EgressModeEnforceBlock
	}
	if !defaultEgressMode.IsValid() {
		return Config{}, domain.BadRequest("INVALID_EGRESS_MODE", fmt.Sprintf("unsupported CUSTODIAN_GIT_GATEWAY_DEFAULT_EGRESS_MODE %q", defaultEgressMode))
	}

	passiveDelivery := domain.PassiveAuditDelivery(strings.ToUpper(strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY"))))
	if passiveDelivery == "" {
		passiveDelivery = domain.PassiveAuditDeliveryAsync
	}
	if !passiveDelivery.IsValid() {
		return Config{}, domain.BadRequest("INVALID_PASSIVE_AUDIT_DELIVERY", fmt.Sprintf("unsupported CUSTODIAN_GIT_GATEWAY_PASSIVE_DELIVERY %q", passiveDelivery))
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

	routePolicy, err := parseRoutePolicyEnv(getenv("CUSTODIAN_ROUTE_POLICY_JSON"))
	if err != nil {
		return Config{}, err
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

	rawRetention := strings.TrimSpace(getenv("CUSTODIAN_ARTIFACT_RETENTION_TTL"))
	retentionName := "CUSTODIAN_ARTIFACT_RETENTION_TTL"
	if rawRetention == "" {
		rawRetention = strings.TrimSpace(getenv("CUSTODIAN_ARTIFACT_RETENTION"))
		retentionName = "CUSTODIAN_ARTIFACT_RETENTION"
	}
	artifactRetention, err := parseDurationEnv(rawRetention, defaultArtifactTTL, retentionName)
	if err != nil {
		return Config{}, err
	}

	shutdownTimeout, err := parseDurationEnv(getenv("CUSTODIAN_GIT_GATEWAY_SHUTDOWN_TIMEOUT"), defaultShutdownTimeout, "CUSTODIAN_GIT_GATEWAY_SHUTDOWN_TIMEOUT")
	if err != nil {
		return Config{}, err
	}

	gitBin := strings.TrimSpace(getenv("CUSTODIAN_GIT_GATEWAY_GIT_BIN"))
	if gitBin == "" {
		gitBin = strings.TrimSpace(getenv("CUSTODIAN_GIT_BIN"))
	}
	if gitBin == "" {
		gitBin = defaultGitBinary
	}

	otelMode := observability.TraceMode(strings.ToLower(strings.TrimSpace(getenv("CUSTODIAN_OTEL_MODE"))))
	if otelMode == "" || otelMode == "off" {
		otelMode = observability.TraceModeNoop
	}
	otelEndpoint := strings.TrimSpace(getenv("CUSTODIAN_OTEL_EXPORTER_OTLP_ENDPOINT"))
	if otelEndpoint == "" {
		otelEndpoint = strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}

	return Config{
		HTTPAddr:           httpAddr,
		SSHAddr:            sshAddr,
		TLSCertFile:        tlsCertFile,
		TLSKeyFile:         tlsKeyFile,
		TLSKeyPEM:          tlsKeyPEM,
		SSHHostKeyFile:     sshHostKeyFile,
		SSHHostKeyPEM:      sshHostKeyPEM,
		SSHUserCAFile:      sshUserCAFile,
		SSHUserCAPubKey:    sshUserCAPubKey,
		UpstreamURL:        upstreamURL,
		APIBaseURL:         gatewayAPIBaseURL,
		DatabaseURL:        dsn,
		SnapshotStore:      storeKind,
		SnapshotDir:        snapshotDir,
		SnapshotBucket:     snapshotBucket,
		SnapshotPrefix:     snapshotPrefix,
		PolicyDir:          policyDir,
		OIDCIssuer:         oidcIssuer,
		OIDCJWKSURL:        oidcJWKSURL,
		OIDCAudience:       oidcAudience,
		CapabilitySecret:   capSecret,
		GitHubAPIBaseURL:   apiURL,
		GitHubGitBaseURL:   gitURL,
		AllowInsecureHTTP:  allowInsecure,
		ReadAppID:          readAppID,
		ReadPrivateKeyPEM:  readKeyPEM,
		WriteAppID:         writeAppID,
		WritePrivateKeyPEM: writeKeyPEM,
		ModelGatewayURL:    strings.TrimSpace(getenv("CUSTODIAN_MODEL_GATEWAY_URL")),
		RoutePolicy:        routePolicy,
		Inspection:         inspCfg,
		QuarantineLimits: quarantine.Limits{
			MaxPackBytes:           maxPackBytes,
			MaxRefUpdates:          maxRefUpdates,
			MaxObjects:             maxObjects,
			MaxInflatedObjectBytes: maxInflatedBytes,
		},
		DefaultEgressMode:    defaultEgressMode,
		PassiveDelivery:      passiveDelivery,
		RepoConcurrencyLimit: repoConcurrency,
		GlobalScanBudget:     globalScanBudget,
		GlobalModelBudget:    globalModelBudget,
		ArtifactRetentionTTL: artifactRetention,
		GitBinary:            gitBin,
		LogFormat:            logFormat,
		LogLevel:             logLevel,
		ShutdownTimeout:      shutdownTimeout,
		OTelMode:             otelMode,
		OTelEndpoint:         otelEndpoint,
		Environment:          strings.TrimSpace(getenv("CUSTODIAN_ENVIRONMENT")),
		Version:              strings.TrimSpace(getenv("CUSTODIAN_VERSION")),
	}, nil
}

func loadGitHubAppCreds(getenv func(string) string, idVar, pemVar, fileVar string) (int64, []byte, error) {
	rawID := strings.TrimSpace(getenv(idVar))
	if rawID == "" {
		return 0, nil, nil
	}
	appID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || appID <= 0 {
		return 0, nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", fmt.Sprintf("%s must be a positive integer", idVar))
	}
	rawPEM := getenv(pemVar)
	if strings.TrimSpace(rawPEM) == "" {
		if keyFile := strings.TrimSpace(getenv(fileVar)); keyFile != "" {
			data, readErr := os.ReadFile(keyFile)
			if readErr != nil {
				return 0, nil, domain.WrapError(domain.ErrBadRequest, "INVALID_GITHUB_APP_KEY", fmt.Sprintf("failed reading %s", fileVar), readErr)
			}
			rawPEM = string(data)
		}
	}
	normPEM := normalizePEM(rawPEM)
	if strings.TrimSpace(normPEM) == "" {
		return 0, nil, domain.BadRequest("INVALID_GITHUB_APP_KEY", fmt.Sprintf("%s is required when %s is set", pemVar, idVar))
	}
	return appID, []byte(normPEM), nil
}

func parsePositiveInt64Env(raw string, def int64, name string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return def, nil
	}
	v, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || v <= 0 {
		return 0, domain.BadRequest("INVALID_CONFIG", fmt.Sprintf("%s must be a positive integer", name))
	}
	return v, nil
}

func parsePositiveIntEnv(raw string, def int, name string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return def, nil
	}
	v, err := strconv.Atoi(trimmed)
	if err != nil || v <= 0 {
		return 0, domain.BadRequest("INVALID_CONFIG", fmt.Sprintf("%s must be a positive integer", name))
	}
	return v, nil
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

func defaultGatewayRoutePolicy() *decisions.RoutePolicy {
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
		return defaultGatewayRoutePolicy(), nil
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

func sanitizeErrorMessage(err error, secrets ...string) (code string, msg string) {
	if err == nil {
		return "", ""
	}
	code = "GATEWAY_ERROR"
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
	out = sshKeyMaterialRegexp.ReplaceAllString(out, "[REDACTED]")
	return out
}
