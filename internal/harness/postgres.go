package harness

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/timreynolds/custodian/internal/persistence"
)

var pgHarnessSeq atomic.Uint64

type postgresConfig struct {
	database        string
	user            string
	password        string
	image           string
	fsync           bool
	externalDSN     string
	allowDockerSkip bool
	skipMigrate     bool
	runInShort      bool
	readyTimeout    time.Duration
}

// PostgresOption configures StartPostgres.
type PostgresOption func(*postgresConfig)

// WithPGDatabase overrides the PostgreSQL database name (default "custodian").
func WithPGDatabase(name string) PostgresOption {
	return func(c *postgresConfig) {
		if name != "" {
			c.database = name
		}
	}
}

// WithPGUser overrides the PostgreSQL username (default "custodian").
func WithPGUser(user string) PostgresOption {
	return func(c *postgresConfig) {
		if user != "" {
			c.user = user
		}
	}
}

// WithPGPassword overrides the PostgreSQL password (default "custodian").
func WithPGPassword(pw string) PostgresOption {
	return func(c *postgresConfig) {
		if pw != "" {
			c.password = pw
		}
	}
}

// WithPGImage overrides the container image (default "postgres:17-alpine").
func WithPGImage(image string) PostgresOption {
	return func(c *postgresConfig) {
		if image != "" {
			c.image = image
		}
	}
}

// WithPGFsync enables or disables fsync/synchronous_commit/full_page_writes (default false for fast tests).
func WithPGFsync(enabled bool) PostgresOption {
	return func(c *postgresConfig) { c.fsync = enabled }
}

// WithPGExternalDSN attaches to an existing PostgreSQL DSN instead of starting Docker.
func WithPGExternalDSN(dsn string) PostgresOption {
	return func(c *postgresConfig) { c.externalDSN = strings.TrimSpace(dsn) }
}

// WithPGAllowDockerSkip skips the test if Docker is unavailable (also honored via CUSTODIAN_TEST_ALLOW_DOCKER_SKIP=1).
func WithPGAllowDockerSkip(allow bool) PostgresOption {
	return func(c *postgresConfig) { c.allowDockerSkip = allow }
}

// WithPGSkipMigrate disables automatic embedded schema migration on startup.
func WithPGSkipMigrate(skip bool) PostgresOption {
	return func(c *postgresConfig) { c.skipMigrate = skip }
}

// WithPGRunInShort forces Docker execution even under `go test -short` (also honored via CUSTODIAN_TEST_FORCE_DOCKER=1).
func WithPGRunInShort(run bool) PostgresOption {
	return func(c *postgresConfig) { c.runInShort = run }
}

// WithPGReadyTimeout sets the readiness wait timeout (default 30s).
func WithPGReadyTimeout(d time.Duration) PostgresOption {
	return func(c *postgresConfig) {
		if d > 0 {
			c.readyTimeout = d
		}
	}
}

// PostgresHarness manages an ephemeral PostgreSQL 17 Docker container (or external DSN)
// bound to an ephemeral loopback port (never 5432), with embedded migrations and cleanup.
type PostgresHarness struct {
	dsn         string
	migrateURL  string
	hostPort    string
	containerID string
	database    string
	user        string
	external    bool
	pool        *pgxpool.Pool

	mu     sync.Mutex
	closed bool
}

// StartPostgres launches an ephemeral postgres:17-alpine container (or attaches to CUSTODIAN_TEST_DSN),
// discovers the dynamically assigned host port (never 5432), waits for pgxpool SELECT 1 readiness,
// runs embedded migrations (unless WithPGSkipMigrate(true)), and registers unconditional cleanup.
func StartPostgres(t testing.TB, opts ...PostgresOption) *PostgresHarness {
	t.Helper()

	cfg := postgresConfig{
		database:     "custodian",
		user:         "custodian",
		password:     "custodian",
		image:        "postgres:17-alpine",
		fsync:        false,
		readyTimeout: 30 * time.Second,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if testing.Short() && !cfg.runInShort && os.Getenv("CUSTODIAN_TEST_FORCE_DOCKER") != "1" {
		t.Skip("skipping PG17 Docker harness under -short (set CUSTODIAN_TEST_FORCE_DOCKER=1 to override)")
	}

	if cfg.externalDSN == "" {
		cfg.externalDSN = strings.TrimSpace(os.Getenv("CUSTODIAN_TEST_DSN"))
	}
	if cfg.externalDSN != "" {
		h := &PostgresHarness{
			dsn:        cfg.externalDSN,
			migrateURL: toPGX5Scheme(cfg.externalDSN),
			database:   cfg.database,
			user:       cfg.user,
			external:   true,
		}
		t.Cleanup(func() {
			_ = h.Close()
		})
		pool, err := persistence.NewPool(context.Background(), h.dsn, persistence.DefaultPoolConfig())
		if err != nil {
			t.Fatalf("connect external postgres DSN: %v", err)
		}
		h.pool = pool
		if !cfg.skipMigrate {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := h.Migrate(ctx); err != nil {
				t.Fatalf("migrate external postgres: %v", err)
			}
		}
		return h
	}

	allowSkip := cfg.allowDockerSkip || os.Getenv("CUSTODIAN_TEST_ALLOW_DOCKER_SKIP") == "1"

	infoCmd := exec.Command("docker", "info")
	var infoOut bytes.Buffer
	infoCmd.Stdout = &infoOut
	infoCmd.Stderr = &infoOut
	if err := infoCmd.Run(); err != nil {
		if allowSkip {
			t.Skipf("skipping StartPostgres: docker daemon unavailable: %v (%s)", err, strings.TrimSpace(infoOut.String()))
		}
		t.Fatalf("docker daemon unavailable for StartPostgres: %v\n%s", err, infoOut.String())
	}

	name := fmt.Sprintf("custodian-m1-pg-%d-%d", os.Getpid(), pgHarnessSeq.Add(1))
	args := []string{
		"run", "-d", "--rm",
		"--name", name,
		"-e", "POSTGRES_USER=" + cfg.user,
		"-e", "POSTGRES_PASSWORD=" + cfg.password,
		"-e", "POSTGRES_DB=" + cfg.database,
		"-p", "127.0.0.1::5432",
		cfg.image,
	}
	if !cfg.fsync {
		args = append(args,
			"-c", "fsync=off",
			"-c", "synchronous_commit=off",
			"-c", "full_page_writes=off",
			"-c", "max_connections=200",
		)
	} else {
		args = append(args, "-c", "max_connections=200")
	}

	runCmd := exec.Command("docker", args...)
	var runOut, runErr bytes.Buffer
	runCmd.Stdout = &runOut
	runCmd.Stderr = &runErr
	if err := runCmd.Run(); err != nil {
		t.Fatalf("docker run %s failed: %v\nstderr: %s", cfg.image, err, runErr.String())
	}
	cid := strings.TrimSpace(runOut.String())
	if cid == "" {
		t.Fatalf("docker run returned empty container ID")
	}

	h := &PostgresHarness{
		containerID: cid,
		database:    cfg.database,
		user:        cfg.user,
	}
	// Register cleanup immediately upon getting container ID.
	t.Cleanup(func() {
		_ = h.Close()
	})

	portCmd := exec.Command("docker", "port", cid, "5432/tcp")
	var portOut, portErr bytes.Buffer
	portCmd.Stdout = &portOut
	portCmd.Stderr = &portErr
	if err := portCmd.Run(); err != nil {
		t.Fatalf("docker port %s 5432/tcp failed: %v\n%s", cid, err, portErr.String())
	}
	portLine := strings.TrimSpace(strings.Split(strings.TrimSpace(portOut.String()), "\n")[0])
	_, portStr, err := net.SplitHostPort(portLine)
	if err != nil {
		t.Fatalf("parse docker port output %q: %v", portLine, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum <= 0 || portNum == 5432 {
		t.Fatalf("invalid ephemeral PostgreSQL host port %q (must be > 0 and != 5432)", portStr)
	}

	h.hostPort = portStr
	dsnURL := &url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(cfg.user, cfg.password),
		Host:     net.JoinHostPort("127.0.0.1", portStr),
		Path:     "/" + cfg.database,
		RawQuery: "sslmode=disable",
	}
	h.dsn = dsnURL.String()
	migrateURL := *dsnURL
	migrateURL.Scheme = "pgx5"
	h.migrateURL = migrateURL.String()

	pool, err := h.waitReadyPool(cfg.readyTimeout)
	if err != nil {
		logsOut, _ := exec.Command("docker", "logs", cid).CombinedOutput()
		t.Fatalf("postgres container %s failed readiness: %v\nlogs:\n%s", cid, err, string(logsOut))
	}
	h.pool = pool

	if !cfg.skipMigrate {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := h.Migrate(ctx); err != nil {
			t.Fatalf("migrate postgres container %s: %v", cid, err)
		}
	}

	return h
}

func (h *PostgresHarness) waitReadyPool(timeout time.Duration) (*pgxpool.Pool, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		inspectCmd := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", h.containerID)
		inspectOut, inspectErr := inspectCmd.CombinedOutput()
		if inspectErr != nil || strings.TrimSpace(string(inspectOut)) != "true" {
			return nil, fmt.Errorf("container %s stopped unexpectedly (%v, %q)", h.containerID, inspectErr, strings.TrimSpace(string(inspectOut)))
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		pool, err := persistence.NewPool(ctx, h.dsn, persistence.DefaultPoolConfig())
		if err == nil {
			var one int
			err = pool.QueryRow(ctx, "SELECT 1").Scan(&one)
			cancel()
			if err == nil && one == 1 {
				return pool, nil
			}
			pool.Close()
		} else {
			cancel()
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out after %s waiting for pgxpool SELECT 1: %w", timeout, lastErr)
}

// DSN returns the postgres:// connection string.
func (h *PostgresHarness) DSN() string {
	return h.dsn
}

// MigrateURL returns the pgx5:// migration URL.
func (h *PostgresHarness) MigrateURL() string {
	return h.migrateURL
}

// HostPort returns the dynamically assigned host port (never 5432).
func (h *PostgresHarness) HostPort() string {
	return h.hostPort
}

// ContainerID returns the Docker container ID (empty for external DSNs).
func (h *PostgresHarness) ContainerID() string {
	return h.containerID
}

// Pool returns the shared *pgxpool.Pool.
func (h *PostgresHarness) Pool() *pgxpool.Pool {
	return h.pool
}

// Migrate runs embedded up-migrations against the pool.
func (h *PostgresHarness) Migrate(ctx context.Context) error {
	if h.pool != nil {
		return persistence.MigrateUpPool(ctx, h.pool)
	}
	return persistence.MigrateUp(ctx, h.dsn)
}

// MigrateDown rolls back embedded migrations against the pool.
func (h *PostgresHarness) MigrateDown(ctx context.Context) error {
	if h.pool != nil {
		return persistence.MigrateDownPool(ctx, h.pool)
	}
	return persistence.MigrateDown(ctx, h.dsn)
}

// Reset truncates all domain tables (preserving schema_migrations) and re-seeds audit_chain_head.
func (h *PostgresHarness) Reset(ctx context.Context) error {
	if h.pool == nil {
		return fmt.Errorf("postgres harness pool is nil")
	}
	rows, err := h.pool.Query(ctx, `
		SELECT tablename
		FROM pg_tables
		WHERE schemaname = 'public'
		  AND tablename <> 'schema_migrations'
		ORDER BY tablename
	`)
	if err != nil {
		return fmt.Errorf("list public tables for reset: %w", err)
	}
	var tables []string
	var hasAuditHead bool
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan table name: %w", err)
		}
		if name == "audit_chain_head" {
			hasAuditHead = true
		}
		tables = append(tables, `"`+strings.ReplaceAll(name, `"`, `""`)+`"`)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate table names: %w", err)
	}
	rows.Close()

	if len(tables) > 0 {
		stmt := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE"
		if _, err := h.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("truncate tables: %w", err)
		}
	}
	if hasAuditHead {
		if _, err := h.pool.Exec(ctx, `
			INSERT INTO audit_chain_head (chain_id, last_event_id, last_event_hash, event_count)
			VALUES ('default', NULL, NULL, 0)
			ON CONFLICT (chain_id) DO NOTHING
		`); err != nil {
			return fmt.Errorf("re-seed audit_chain_head: %w", err)
		}
	}
	return nil
}

// Close closes the shared pool and forcefully removes the ephemeral Docker container.
func (h *PostgresHarness) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	pool := h.pool
	cid := h.containerID
	external := h.external
	h.mu.Unlock()

	if pool != nil {
		pool.Close()
	}

	if external || cid == "" {
		return nil
	}

	rmCmd := exec.Command("docker", "rm", "-f", "-v", cid)
	var out bytes.Buffer
	rmCmd.Stdout = &out
	rmCmd.Stderr = &out
	if err := rmCmd.Run(); err != nil {
		msg := out.String()
		if strings.Contains(msg, "No such container") || strings.Contains(msg, "is already in progress") {
			return nil
		}
		return fmt.Errorf("docker rm -f -v %s: %w (%s)", cid, err, strings.TrimSpace(msg))
	}
	return nil
}

func toPGX5Scheme(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	if u.Scheme == "postgres" || u.Scheme == "postgresql" {
		u.Scheme = "pgx5"
	}
	return u.String()
}
