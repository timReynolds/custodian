package inspection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultMaxStdioBytes = 4 * 1024 * 1024

var errBinaryMissing = errors.New("scanner binary missing or not executable")

type execResult struct {
	ExitCode        int
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	TimedOut        bool
	Canceled        bool
	BinaryMissing   bool
	Err             error
}

type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, b.buf.Len())
	copy(cp, b.buf.Bytes())
	return cp
}

func (b *limitedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// cleanSubprocessEnv builds a strictly allowlisted environment for child scanner processes,
// stripping all broker credentials (CUSTODIAN_*, GITHUB_*, AWS_*, GOOGLE_*, etc.).
func cleanSubprocessEnv(tempHome, tempDir string) []string {
	allowedKeys := map[string]struct{}{
		"PATH":          {},
		"LANG":          {},
		"LC_ALL":        {},
		"SSL_CERT_FILE": {},
		"SSL_CERT_DIR":  {},
	}

	vals := make(map[string]string, len(allowedKeys)+4)
	for _, entry := range os.Environ() {
		k, v, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, allowed := allowedKeys[k]; allowed && v != "" {
			vals[k] = v
		}
	}

	if vals["PATH"] == "" {
		vals["PATH"] = "/usr/local/bin:/usr/bin:/bin"
	}
	if vals["LANG"] == "" {
		vals["LANG"] = "C"
	}
	if vals["LC_ALL"] == "" {
		vals["LC_ALL"] = "C"
	}
	if tempHome != "" {
		vals["HOME"] = tempHome
	}
	if tempDir != "" {
		vals["TMPDIR"] = tempDir
		vals["TMP"] = tempDir
		vals["TEMP"] = tempDir
	}

	out := make([]string, 0, len(vals))
	for k, v := range vals {
		out = append(out, k+"="+v)
	}
	return out
}

func resolveBinary(bin string) (string, error) {
	trimmed := strings.TrimSpace(bin)
	if trimmed == "" {
		return "", fmt.Errorf("%w: empty binary name", errBinaryMissing)
	}
	path, err := exec.LookPath(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errBinaryMissing, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return abs, nil
}

func runCommand(ctx context.Context, bin string, args []string, workDir, tempOutDir string, maxStdioBytes int64) execResult {
	resolved, err := resolveBinary(bin)
	if err != nil {
		return execResult{
			ExitCode:      -1,
			BinaryMissing: true,
			Err:           err,
		}
	}

	if maxStdioBytes <= 0 {
		maxStdioBytes = defaultMaxStdioBytes
	}

	homeDir := filepath.Join(tempOutDir, "home")
	_ = os.MkdirAll(homeDir, 0o700)

	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = workDir
	cmd.Env = cleanSubprocessEnv(homeDir, tempOutDir)
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.WaitDelay = 500 * time.Millisecond
	cmd.Cancel = func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return nil
		}
		// Kill entire process group so child processes (e.g., sleep) terminate immediately.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}

	stdoutBuf := &limitedBuffer{limit: maxStdioBytes}
	stderrBuf := &limitedBuffer{limit: maxStdioBytes}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	if startErr := cmd.Start(); startErr != nil {
		isMissing := errors.Is(startErr, os.ErrNotExist) || errors.Is(startErr, os.ErrPermission)
		return execResult{
			ExitCode:      -1,
			BinaryMissing: isMissing,
			Err:           startErr,
		}
	}

	pgid := cmd.Process.Pid
	waitErr := cmd.Wait()
	if pgid > 0 {
		// Defensive cleanup of any stray descendant in the process group.
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}

	res := execResult{
		Stdout:          stdoutBuf.Bytes(),
		Stderr:          stderrBuf.Bytes(),
		StdoutTruncated: stdoutBuf.Truncated(),
		TimedOut:        errors.Is(ctx.Err(), context.DeadlineExceeded),
		Canceled:        errors.Is(ctx.Err(), context.Canceled),
		Err:             waitErr,
	}

	if waitErr == nil {
		res.ExitCode = 0
		return res
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
	} else {
		res.ExitCode = -1
	}
	return res
}

func probeVersion(ctx context.Context, bin string, versionArgs []string, timeout time.Duration, tempOutDir string, redactor *Redactor) (string, bool, error) {
	if _, err := resolveBinary(bin); err != nil {
		return "unknown", true, err
	}
	if len(versionArgs) == 0 {
		versionArgs = []string{"--version"}
	}
	if timeout <= 0 {
		timeout = defaultVersionProbeTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := runCommand(probeCtx, bin, versionArgs, tempOutDir, tempOutDir, 64*1024)
	if res.BinaryMissing {
		return "unknown", true, res.Err
	}
	if res.Err != nil || res.ExitCode != 0 {
		return "unknown", false, nil
	}
	ver := extractFirstVersionLine(string(res.Stdout))
	if ver == "" {
		ver = extractFirstVersionLine(string(res.Stderr))
	}
	if ver == "" {
		return "unknown", false, nil
	}
	if redactor != nil {
		ver = redactor.ScrubString(ver)
	}
	// Defer final 64-byte display clamp until Inspect aggregates cross-scanner secrets and scrubs ScannerVersion.
	if len(ver) > 512 {
		ver = ver[:512]
	}
	return ver, false, nil
}

func extractFirstVersionLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if maxBytes <= 0 {
		maxBytes = defaultMaxOutputBytes
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("scanner output exceeds %d bytes", maxBytes)
	}
	return data, nil
}
