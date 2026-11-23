package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var pgSeq atomic.Uint64

type pgConfig struct {
	database        string
	fsync           bool
	externalDSN     string
	allowDockerSkip bool
}

// PGOption configures StartPGDocker.
type PGOption func(*pgConfig)

// WithPGDatabase overrides the PostgreSQL database name (default "custodian").
func WithPGDatabase(db string) PGOption {
	return func(c *pgConfig) {
		if db != "" {
			c.database = db
		}
	}
}

// WithPGFsync enables or disables fsync/synchronous_commit in the ephemeral container.
func WithPGFsync(enabled bool) PGOption {
	return func(c *pgConfig) { c.fsync = enabled }
}

// WithPGExternalDSN configures an explicit PostgreSQL DSN instead of starting Docker.
func WithPGExternalDSN(dsn string) PGOption {
	return func(c *pgConfig) { c.externalDSN = dsn }
}

// WithPGAllowDockerSkip allows StartPGDocker to call t.Skipf when Docker is unavailable.
func WithPGAllowDockerSkip(allow bool) PGOption {
	return func(c *pgConfig) { c.allowDockerSkip = allow }
}

// PGDocker manages an ephemeral postgres:17-alpine Docker container bound to 127.0.0.1::<ephemeral>.
type PGDocker struct {
	dsn         string
	hostPort    string
	containerID string
	database    string
	user        string
	external    bool

	mu     sync.Mutex
	closed bool
}

// StartPGDocker launches an ephemeral postgres:17-alpine container (or attaches to CUSTODIAN_TEST_DSN),
// discovers the dynamically assigned host port (never 5432), waits until TCP + psql queries succeed,
// and registers unconditional teardown via t.Cleanup.
func StartPGDocker(t testing.TB, opts ...PGOption) *PGDocker {
	t.Helper()

	cfg := pgConfig{
		database: "custodian",
		fsync:    false,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.externalDSN == "" {
		cfg.externalDSN = strings.TrimSpace(os.Getenv("CUSTODIAN_TEST_DSN"))
	}
	if cfg.externalDSN != "" {
		pg := &PGDocker{
			dsn:      cfg.externalDSN,
			database: cfg.database,
			user:     "custodian",
			external: true,
		}
		return pg
	}

	allowSkip := cfg.allowDockerSkip || os.Getenv("CUSTODIAN_E2E_ALLOW_DOCKER_SKIP") == "1"

	infoCmd := exec.Command("docker", "info")
	var infoOut bytes.Buffer
	infoCmd.Stdout = &infoOut
	infoCmd.Stderr = &infoOut
	if err := infoCmd.Run(); err != nil {
		if allowSkip {
			t.Skipf("skipping PGDocker: docker daemon unavailable: %v (%s)", err, strings.TrimSpace(infoOut.String()))
		}
		t.Fatalf("docker daemon unavailable for StartPGDocker: %v\n%s", err, infoOut.String())
	}

	name := fmt.Sprintf("custodian-e2e-pg-%d-%d", os.Getpid(), pgSeq.Add(1))
	args := []string{
		"run", "-d", "--rm",
		"--name", name,
		"-e", "POSTGRES_USER=custodian",
		"-e", "POSTGRES_PASSWORD=custodian",
		"-e", "POSTGRES_DB=" + cfg.database,
		"-p", "127.0.0.1::5432",
		"postgres:17-alpine",
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
		t.Fatalf("docker run postgres:17-alpine failed: %v\nstderr: %s", err, runErr.String())
	}
	cid := strings.TrimSpace(runOut.String())
	if cid == "" {
		t.Fatalf("docker run returned empty container ID")
	}

	pg := &PGDocker{
		containerID: cid,
		database:    cfg.database,
		user:        "custodian",
	}
	// Register cleanup immediately so failed readiness checks still remove the container.
	t.Cleanup(func() {
		_ = pg.Close()
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

	pg.hostPort = portStr
	pg.dsn = fmt.Sprintf("postgres://custodian:custodian@127.0.0.1:%s/%s?sslmode=disable", portStr, cfg.database)

	if err := pg.waitReady(30 * time.Second); err != nil {
		logsCmd := exec.Command("docker", "logs", cid)
		logsOut, _ := logsCmd.CombinedOutput()
		t.Fatalf("postgres container %s failed readiness: %v\nlogs:\n%s", cid, err, string(logsOut))
	}

	return pg
}

func (p *PGDocker) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		readyCmd := exec.CommandContext(ctx, "docker", "exec", p.containerID,
			"pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", p.user, "-d", p.database)
		err1 := readyCmd.Run()
		cancel()
		if err1 != nil {
			lastErr = fmt.Errorf("pg_isready: %w", err1)
			time.Sleep(150 * time.Millisecond)
			continue
		}

		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		sqlCmd := exec.CommandContext(ctx2, "docker", "exec", p.containerID,
			"psql", "-h", "127.0.0.1", "-U", p.user, "-d", p.database, "-At", "-c", "SELECT 1")
		out2, err2 := sqlCmd.CombinedOutput()
		cancel2()
		if err2 != nil || strings.TrimSpace(string(out2)) != "1" {
			lastErr = fmt.Errorf("psql SELECT 1: %v (%s)", err2, strings.TrimSpace(string(out2)))
			time.Sleep(150 * time.Millisecond)
			continue
		}

		conn, err3 := net.DialTimeout("tcp", "127.0.0.1:"+p.hostPort, time.Second)
		if err3 != nil {
			lastErr = fmt.Errorf("host tcp dial 127.0.0.1:%s: %w", p.hostPort, err3)
			time.Sleep(150 * time.Millisecond)
			continue
		}
		_ = conn.Close()
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("timed out")
	}
	return lastErr
}

// DSN returns the postgres:// connection string pointing at 127.0.0.1:<ephemeralPort>.
func (p *PGDocker) DSN() string { return p.dsn }

// HostPort returns the dynamically assigned host TCP port string.
func (p *PGDocker) HostPort() string { return p.hostPort }

// ContainerID returns the Docker container ID (empty when using external DSN).
func (p *PGDocker) ContainerID() string { return p.containerID }

// ExecSQL executes SQL via docker exec psql (zero third-party pgx dependency).
func (p *PGDocker) ExecSQL(query string) (string, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return "", errors.New("PGDocker is closed")
	}

	var cmd *exec.Cmd
	if p.external {
		psqlBin, err := exec.LookPath("psql")
		if err != nil {
			return "", fmt.Errorf("psql not found for external DSN: %w", err)
		}
		cmd = exec.Command(psqlBin, p.dsn, "-v", "ON_ERROR_STOP=1", "-At", "-F", "\t", "-f", "-")
	} else {
		cmd = exec.Command("docker", "exec", "-i", p.containerID,
			"psql", "-U", p.user, "-d", p.database, "-v", "ON_ERROR_STOP=1", "-At", "-F", "\t", "-f", "-")
	}
	cmd.Stdin = strings.NewReader(query)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ExecSQL failed: %w\nstderr: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// ExecSQLFile reads a local SQL file and executes it against the database.
func (p *PGDocker) ExecSQLFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read SQL file %q: %w", path, err)
	}
	return p.ExecSQL(string(data))
}

// QueryRows executes a query and splits tab-delimited rows and columns.
func (p *PGDocker) QueryRows(query string) ([][]string, error) {
	out, err := p.ExecSQL(query)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(out, "\r\n")
	if trimmed == "" {
		return nil, nil
	}
	lines := strings.Split(trimmed, "\n")
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows, nil
}

// Pause pauses the PostgreSQL container to simulate transient DB outages.
func (p *PGDocker) Pause() error {
	if p.external {
		return errors.New("cannot pause external PostgreSQL instance")
	}
	out, err := exec.Command("docker", "pause", p.containerID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pause %s: %w (%s)", p.containerID, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Unpause resumes a paused PostgreSQL container.
func (p *PGDocker) Unpause() error {
	if p.external {
		return errors.New("cannot unpause external PostgreSQL instance")
	}
	out, err := exec.Command("docker", "unpause", p.containerID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker unpause %s: %w (%s)", p.containerID, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Close removes the ephemeral PostgreSQL container cleanly. Safe to call multiple times.
func (p *PGDocker) Close() error {
	p.mu.Lock()
	if p.closed || p.external || p.containerID == "" {
		p.closed = true
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	cid := p.containerID
	p.mu.Unlock()

	out, err := exec.Command("docker", "rm", "-f", "-v", cid).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such container") {
		return fmt.Errorf("docker rm -f -v %s: %w (%s)", cid, err, strings.TrimSpace(string(out)))
	}
	return nil
}
