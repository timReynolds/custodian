package inspection

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	EnvGitleaksBin    = "CUSTODIAN_GITLEAKS_BIN"
	EnvScanCodeBin    = "CUSTODIAN_SCANCODE_BIN"
	EnvSemgrepBin     = "CUSTODIAN_SEMGREP_BIN"
	EnvTrivyBin       = "CUSTODIAN_TRIVY_BIN"
	EnvScannerTimeout = "CUSTODIAN_SCANNER_TIMEOUT"

	defaultScannerTimeout      = 60 * time.Second
	defaultVersionProbeTimeout = 10 * time.Second
	defaultMaxOutputBytes      = 16 * 1024 * 1024
	defaultMaxFileInspectBytes = 4 * 1024 * 1024
)

// DefaultProhibitedLicenses lists SPDX license prefixes/identifiers blocked by default policy.
var DefaultProhibitedLicenses = []string{
	"AGPL-",
	"GPL-",
	"SSPL-",
	"BUSL-",
	"WTFPL",
	"CC-BY-NC",
	"CPL-1.0",
	"EPL-1.0",
}

// Config configures Stage A scanner binaries, timeouts, rules, hooks, and observability.
type Config struct {
	GitleaksBin         string
	ScanCodeBin         string
	SemgrepBin          string
	TrivyBin            string
	ScannerTimeout      time.Duration
	VersionProbeTimeout time.Duration
	MaxOutputBytes      int64
	MaxFileInspectBytes int64
	ProhibitedLicenses  []string
	IPFingerprinter     IPFingerprinter
	ExtraScanners       []Scanner
	Logger              *slog.Logger
	Metrics             *observability.Metrics
	Tracer              *observability.TracerRuntime
}

// DefaultConfig returns a Config populated with safe defaults.
func DefaultConfig() Config {
	return Config{
		GitleaksBin:         string(ScannerGitleaks),
		ScanCodeBin:         string(ScannerScanCode),
		SemgrepBin:          string(ScannerSemgrep),
		TrivyBin:            string(ScannerTrivy),
		ScannerTimeout:      defaultScannerTimeout,
		VersionProbeTimeout: defaultVersionProbeTimeout,
		MaxOutputBytes:      defaultMaxOutputBytes,
		MaxFileInspectBytes: defaultMaxFileInspectBytes,
		ProhibitedLicenses:  append([]string(nil), DefaultProhibitedLicenses...),
		IPFingerprinter:     NewDefaultIPFingerprinter(),
	}
}

// LoadConfigFromEnv builds a Config from CUSTODIAN_* scanner environment variables.
func LoadConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()

	if v := strings.TrimSpace(os.Getenv(EnvGitleaksBin)); v != "" {
		cfg.GitleaksBin = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvScanCodeBin)); v != "" {
		cfg.ScanCodeBin = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvSemgrepBin)); v != "" {
		cfg.SemgrepBin = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvTrivyBin)); v != "" {
		cfg.TrivyBin = v
	}
	if raw := strings.TrimSpace(os.Getenv(EnvScannerTimeout)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return Config{}, domain.BadRequest("INVALID_SCANNER_TIMEOUT", "CUSTODIAN_SCANNER_TIMEOUT must be a positive duration")
		}
		cfg.ScannerTimeout = d
	}
	return cfg, nil
}

func (c Config) withDefaults() Config {
	def := DefaultConfig()
	if strings.TrimSpace(c.GitleaksBin) == "" {
		c.GitleaksBin = def.GitleaksBin
	}
	if strings.TrimSpace(c.ScanCodeBin) == "" {
		c.ScanCodeBin = def.ScanCodeBin
	}
	if strings.TrimSpace(c.SemgrepBin) == "" {
		c.SemgrepBin = def.SemgrepBin
	}
	if strings.TrimSpace(c.TrivyBin) == "" {
		c.TrivyBin = def.TrivyBin
	}
	if c.ScannerTimeout <= 0 {
		c.ScannerTimeout = def.ScannerTimeout
	}
	if c.VersionProbeTimeout <= 0 {
		c.VersionProbeTimeout = def.VersionProbeTimeout
	}
	if c.VersionProbeTimeout > c.ScannerTimeout {
		c.VersionProbeTimeout = c.ScannerTimeout
	}
	if c.MaxOutputBytes <= 0 {
		c.MaxOutputBytes = def.MaxOutputBytes
	}
	if c.MaxFileInspectBytes <= 0 {
		c.MaxFileInspectBytes = def.MaxFileInspectBytes
	}
	if len(c.ProhibitedLicenses) == 0 {
		c.ProhibitedLicenses = def.ProhibitedLicenses
	}
	if c.IPFingerprinter == nil {
		c.IPFingerprinter = def.IPFingerprinter
	}
	return c
}
