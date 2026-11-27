package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PushGatewayBinary is the conditional v1.x Push Gateway daemon binary name.
const PushGatewayBinary = "custodian-git-gateway"

// AllBinaryNames returns the canonical 5 Custodian binary names.
var AllBinaryNames = []string{
	"custodian",
	"custodian-api",
	"custodian-worker",
	"custodian-publisher",
	"custodian-policy",
}

// CLIResult captures the output and exit status of a CLI binary invocation.
type CLIResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	Err      error
}

// ResolveGoBin resolves the Go compiler using:
// 1. $CUSTODIAN_GO_BIN
// 2. exec.LookPath("go")
func ResolveGoBin() (string, error) {
	if envBin := strings.TrimSpace(os.Getenv("CUSTODIAN_GO_BIN")); envBin != "" {
		if info, err := os.Stat(envBin); err == nil && !info.IsDir() {
			return envBin, nil
		}
		return "", fmt.Errorf("CUSTODIAN_GO_BIN=%q is not an executable file", envBin)
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	return "", errors.New("unable to resolve go binary via CUSTODIAN_GO_BIN or PATH")
}

type binaryCacheEntry struct {
	mu    sync.Mutex
	paths map[string]string
}

var (
	buildCacheMu sync.Mutex
	buildCache   = make(map[string]*binaryCacheEntry)
)

func getCacheEntry(key string) *binaryCacheEntry {
	buildCacheMu.Lock()
	defer buildCacheMu.Unlock()
	e, ok := buildCache[key]
	if !ok {
		e = &binaryCacheEntry{}
		buildCache[key] = e
	}
	return e
}

func resolveBinaryList(names BinaryNames) []string {
	out := make([]string, 0, 5)
	for _, pair := range []struct {
		v   string
		def string
	}{
		{names.Custodian, "custodian"},
		{names.API, "custodian-api"},
		{names.Worker, "custodian-worker"},
		{names.Publisher, "custodian-publisher"},
		{names.Policy, "custodian-policy"},
	} {
		if pair.v != "" {
			out = append(out, pair.v)
		} else {
			out = append(out, pair.def)
		}
	}
	return out
}

// BuildOrLocateBinaries locates prebuilt binaries from prebuiltDir / $CUSTODIAN_E2E_BIN_DIR
// or builds ./cmd/<name> once per (repoRoot, outDir) using ResolveGoBin().
func BuildOrLocateBinaries(ctx context.Context, goBin, repoRoot, outDir, prebuiltDir string, names ...BinaryNames) (map[string]string, error) {
	var bn BinaryNames
	if len(names) > 0 {
		bn = names[0]
	}
	binList := resolveBinaryList(bn)

	if prebuiltDir == "" {
		prebuiltDir = strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_BIN_DIR"))
	}
	if prebuiltDir != "" {
		found := make(map[string]string, len(binList))
		allFound := true
		for _, name := range binList {
			p := filepath.Join(prebuiltDir, name)
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				allFound = false
				break
			}
			found[name] = p
		}
		if allFound {
			return found, nil
		}
	}

	if goBin == "" {
		var err error
		goBin, err = ResolveGoBin()
		if err != nil {
			return nil, err
		}
	}
	if repoRoot == "" {
		return nil, errors.New("repoRoot is required when prebuilt binaries are not provided")
	}

	cacheKey := repoRoot + "|" + strings.Join(binList, ",")
	entry := getCacheEntry(cacheKey)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if len(entry.paths) == len(binList) {
		allStillExist := true
		for _, p := range entry.paths {
			if _, err := os.Stat(p); err != nil {
				allStillExist = false
				break
			}
		}
		if allStillExist {
			cp := make(map[string]string, len(entry.paths))
			for k, v := range entry.paths {
				cp[k] = v
			}
			return cp, nil
		}
	}

	if outDir == "" {
		var err error
		outDir, err = os.MkdirTemp("", "custodian-e2e-bins-*")
		if err != nil {
			return nil, fmt.Errorf("create temp binary dir: %w", err)
		}
	} else {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir outDir %q: %w", outDir, err)
		}
	}

	built := make(map[string]string, len(binList))
	for _, name := range binList {
		dst := filepath.Join(outDir, name)
		pkg := "./cmd/" + name
		cmd := exec.CommandContext(ctx, goBin, "build", "-o", dst, pkg)
		cmd.Dir = repoRoot
		var combined bytes.Buffer
		cmd.Stdout = &combined
		cmd.Stderr = &combined
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("build %s (%s): %w\n%s", name, pkg, err, combined.String())
		}
		built[name] = dst
	}

	entry.paths = built
	cp := make(map[string]string, len(built))
	for k, v := range built {
		cp[k] = v
	}
	return cp, nil
}

// HasBinary reports whether binary name is available in prebuiltDir/$CUSTODIAN_E2E_BIN_DIR
// or has buildable Go source under <repoRoot>/cmd/<name>.
func HasBinary(repoRoot, prebuiltDir, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if prebuiltDir == "" {
		prebuiltDir = strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_BIN_DIR"))
	}
	if prebuiltDir != "" {
		if info, err := os.Stat(filepath.Join(prebuiltDir, name)); err == nil && !info.IsDir() {
			return true
		}
	}
	if repoRoot == "" {
		repoRoot = detectRepoRoot("")
	}
	if repoRoot == "" {
		return false
	}
	cmdDir := filepath.Join(repoRoot, "cmd", name)
	info, err := os.Stat(cmdDir)
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(cmdDir)
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".go") {
			return true
		}
	}
	return false
}

// BuildBinary locates a single prebuilt binary from prebuiltDir/$CUSTODIAN_E2E_BIN_DIR
// or builds ./cmd/<name> once per (repoRoot, name).
func BuildBinary(ctx context.Context, goBin, repoRoot, outDir, prebuiltDir, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("binary name is required")
	}
	if prebuiltDir == "" {
		prebuiltDir = strings.TrimSpace(os.Getenv("CUSTODIAN_E2E_BIN_DIR"))
	}
	if prebuiltDir != "" {
		p := filepath.Join(prebuiltDir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}

	if goBin == "" {
		var err error
		goBin, err = ResolveGoBin()
		if err != nil {
			return "", err
		}
	}
	if repoRoot == "" {
		repoRoot = detectRepoRoot("")
	}
	if repoRoot == "" {
		return "", errors.New("repoRoot is required when prebuilt binary is not provided")
	}

	cmdDir := filepath.Join(repoRoot, "cmd", name)
	if info, err := os.Stat(cmdDir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("binary %q source directory %q not found", name, cmdDir)
	}

	cacheKey := "single|" + repoRoot + "|" + name
	entry := getCacheEntry(cacheKey)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if cachedPath, ok := entry.paths[name]; ok && cachedPath != "" {
		if info, err := os.Stat(cachedPath); err == nil && !info.IsDir() {
			return cachedPath, nil
		}
	}

	if outDir == "" {
		var err error
		outDir, err = os.MkdirTemp("", "custodian-e2e-bin-*")
		if err != nil {
			return "", fmt.Errorf("create temp binary dir: %w", err)
		}
	} else if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir outDir %q: %w", outDir, err)
	}

	dst := filepath.Join(outDir, name)
	pkg := "./cmd/" + name
	cmd := exec.CommandContext(ctx, goBin, "build", "-o", dst, pkg)
	cmd.Dir = repoRoot
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build %s (%s): %w\n%s", name, pkg, err, combined.String())
	}
	entry.paths = map[string]string{name: dst}
	return dst, nil
}

// BuildPushGatewayBinary locates or builds custodian-git-gateway (or contracts.Binaries.GitGateway).
func BuildPushGatewayBinary(ctx context.Context, goBin, repoRoot, outDir, prebuiltDir string, names ...BinaryNames) (string, error) {
	target := PushGatewayBinary
	if len(names) > 0 && strings.TrimSpace(names[0].GitGateway) != "" {
		target = strings.TrimSpace(names[0].GitGateway)
	}
	return BuildBinary(ctx, goBin, repoRoot, outDir, prebuiltDir, target)
}

// cleanBaseEnv constructs a sanitized subprocess environment with hardened Git defaults.
func cleanBaseEnv(extra map[string]string) []string {
	merged := map[string]string{
		"PATH":                os.Getenv("PATH"),
		"HOME":                os.Getenv("HOME"),
		"TMPDIR":              os.Getenv("TMPDIR"),
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_TERMINAL_PROMPT": "0",
	}
	for k, v := range extra {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+merged[k])
	}
	return out
}

// RunBinary invokes a CLI binary (custodian, custodian-policy, etc.) capturing exit code, stdout, and stderr.
func RunBinary(ctx context.Context, binPath, workDir string, args []string, env map[string]string) CLIResult {
	return RunBinaryWithStdin(ctx, binPath, workDir, args, env, nil)
}

// RunBinaryWithStdin invokes a CLI binary with optional stdin, capturing exit code, stdout, and stderr.
func RunBinaryWithStdin(ctx context.Context, binPath, workDir string, args []string, env map[string]string, stdin io.Reader) CLIResult {
	start := time.Now()
	cmd := exec.CommandContext(ctx, binPath, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}
	cmd.Env = cleanBaseEnv(env)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return err
			}
		}
		return nil
	}
	cmd.WaitDelay = 200 * time.Millisecond
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return CLIResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
		Err:      err,
	}
}

// safeLogBuffer is a race-free buffer for capturing subprocess stdout/stderr.
type safeLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeLogBuffer) WriteString(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(s)
}

func (b *safeLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// managedProc supervises a daemon subprocess (custodian-api, custodian-worker, custodian-publisher)
// using its own process group (Setpgid: true) so Stop/Kill/Restart never leave orphaned children.
type managedProc struct {
	name    string
	binPath string
	workDir string
	args    []string
	env     map[string]string

	mu      sync.Mutex
	cmd     *exec.Cmd
	doneCh  chan error
	running bool
	logs    safeLogBuffer
}

func newManagedProc(name, binPath, workDir string, args []string, env map[string]string) *managedProc {
	envCopy := make(map[string]string, len(env))
	for k, v := range env {
		envCopy[k] = v
	}
	argsCopy := append([]string(nil), args...)
	return &managedProc{
		name:    name,
		binPath: binPath,
		workDir: workDir,
		args:    argsCopy,
		env:     envCopy,
	}
}

func (p *managedProc) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return nil
	}
	cmd := exec.Command(p.binPath, p.args...)
	if p.workDir != "" {
		cmd.Dir = p.workDir
	}
	cmd.Env = cleanBaseEnv(p.env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = &p.logs
	cmd.Stderr = &p.logs

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s (%s): %w", p.name, p.binPath, err)
	}
	done := make(chan error, 1)
	p.cmd = cmd
	p.doneCh = done
	p.running = true

	go func(c *exec.Cmd, ch chan error) {
		err := c.Wait()
		p.mu.Lock()
		if p.cmd == c {
			p.running = false
		}
		p.mu.Unlock()
		ch <- err
		close(ch)
	}(cmd, done)

	return nil
}

func (p *managedProc) Stop(timeout time.Duration) error {
	p.mu.Lock()
	if !p.running || p.cmd == nil || p.cmd.Process == nil {
		p.mu.Unlock()
		return nil
	}
	pid := p.cmd.Process.Pid
	done := p.doneCh
	p.mu.Unlock()

	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
		return nil
	}
}

// Kill immediately terminates the process group with SIGKILL (simulates crash mid-lease for RG-10).
func (p *managedProc) Kill() error {
	p.mu.Lock()
	if !p.running || p.cmd == nil || p.cmd.Process == nil {
		p.mu.Unlock()
		return nil
	}
	pid := p.cmd.Process.Pid
	done := p.doneCh
	p.mu.Unlock()

	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill %s (-%d): %w", p.name, pid, err)
	}
	<-done
	return nil
}

// Restart stops (if running) and restarts the subprocess, preserving log history with a delimiter.
func (p *managedProc) Restart(stopTimeout time.Duration) error {
	if err := p.Stop(stopTimeout); err != nil {
		return err
	}
	p.logs.WriteString(fmt.Sprintf("\n=== RESTART %s at %s ===\n", p.name, time.Now().UTC().Format(time.RFC3339)))
	return p.Start()
}

func (p *managedProc) Logs() string {
	return p.logs.String()
}
