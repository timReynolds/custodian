package checkout

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

func runTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func setupBareTestRepo(t *testing.T) (bareDir string, commit1 string, commit2 string) {
	t.Helper()
	tmp := t.TempDir()
	bareDir = filepath.Join(tmp, "repo.git")
	workDir := filepath.Join(tmp, "seed")

	cmd := exec.Command("git", "init", "--bare", "--initial-branch=main", bareDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	runTestGit(t, bareDir, "config", "uploadpack.allowReachableSHA1InWant", "true")

	cmdClone := exec.Command("git", "init", "--initial-branch=main", workDir)
	if out, err := cmdClone.CombinedOutput(); err != nil {
		t.Fatalf("git init seed: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, workDir, "add", "README.md")
	runTestGit(t, workDir, "commit", "-m", "commit 1")
	commit1 = runTestGit(t, workDir, "rev-parse", "HEAD")

	// Commit 2 adds a secret-like file and a git symlink entry (mode 120000) to verify core.symlinks=false.
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	blobSHA := runTestGit(t, workDir, "hash-object", "-w", "--stdin")
	_ = blobSHA
	// Create symlink object in git index directly using update-index (works without OS symlink)
	targetBlobCmd := exec.Command("git", "-C", workDir, "hash-object", "-w", "--stdin")
	targetBlobCmd.Stdin = strings.NewReader("/etc/passwd")
	targetBlobOut, err := targetBlobCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hash-object: %v\n%s", err, targetBlobOut)
	}
	linkHash := strings.TrimSpace(string(targetBlobOut))
	runTestGit(t, workDir, "update-index", "--add", "--cacheinfo", "120000,"+linkHash+",evil-link")
	runTestGit(t, workDir, "add", "README.md")
	runTestGit(t, workDir, "commit", "-m", "commit 2")
	commit2 = runTestGit(t, workDir, "rev-parse", "HEAD")

	runTestGit(t, workDir, "push", bareDir, "main")
	return bareDir, commit1, commit2
}

func TestCheckoutValidationAndProtocolGuards(t *testing.T) {
	t.Parallel()
	r := NewRunner(RunnerConfig{})
	validSHA := strings.Repeat("a", 40)

	cases := []struct {
		name string
		req  Request
		want error
	}{
		{"empty_url", Request{RemoteURL: "", CommitSHA: validSHA}, domain.ErrBadRequest},
		{"flag_injection_url", Request{RemoteURL: "--upload-pack=evil", CommitSHA: validSHA}, domain.ErrBadRequest},
		{"flag_injection_sha", Request{RemoteURL: "https://github.com/a/b.git", CommitSHA: "--help"}, domain.ErrBadRequest},
		{"short_sha", Request{RemoteURL: "https://github.com/a/b.git", CommitSHA: "abcd"}, domain.ErrBadRequest},
		{"embedded_creds", Request{RemoteURL: "https://user:ghs_secret@github.com/a/b.git", CommitSHA: validSHA}, domain.ErrBadRequest},
		{"file_disallowed", Request{RemoteURL: "file:///tmp/repo.git", CommitSHA: validSHA, AllowLocalBare: false}, domain.ErrBadRequest},
		{"ext_disallowed", Request{RemoteURL: "ext::sh -c id", CommitSHA: validSHA}, domain.ErrBadRequest},
		{"ssh_disallowed", Request{RemoteURL: "ssh://git@github.com/a/b.git", CommitSHA: validSHA}, domain.ErrBadRequest},
		{"http_disallowed", Request{RemoteURL: "http://example.com/a/b.git", CommitSHA: validSHA, AllowInsecureHTTP: false}, domain.ErrBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Checkout(context.Background(), tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v for %s, got %v", tc.want, tc.name, err)
			}
		})
	}
}

func TestCheckoutShallowHistoryAndGitMetadataSanitization(t *testing.T) {
	bareDir, commit1, commit2 := setupBareTestRepo(t)

	// Poison host environment to verify CleanGitEnv & HardenedGitFlags isolate execution.
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/evil'")
	t.Setenv("GIT_EXTERNAL_DIFF", "false")
	t.Setenv("GIT_SSH_COMMAND", "false")

	r := NewRunner(RunnerConfig{})
	ctx := context.Background()

	// 1. Default shallow checkout of non-tip commit1 without .git metadata
	res1, err := r.Checkout(ctx, Request{
		RemoteURL:          "file://" + bareDir,
		CommitSHA:          commit1,
		IncludeGitMetadata: false,
		IncludeHistory:     false,
		AllowLocalBare:     true,
	})
	if err != nil {
		t.Fatalf("Checkout commit1: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(res1.WorkDir) })

	if res1.CommitSHA != commit1 || res1.HasGitMetadata || res1.IncludesHistory {
		t.Fatalf("unexpected checkout result: %+v", res1)
	}
	if _, err := os.Stat(filepath.Join(res1.WorkDir, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected .git to be removed, got err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(res1.WorkDir, "README.md"))
	if err != nil || string(data) != "v1\n" {
		t.Fatalf("unexpected README content: %q err=%v", data, err)
	}

	// 2. Sanitised .git without history (depth=1) on commit2 (with symlink entry)
	res2, err := r.Checkout(ctx, Request{
		RemoteURL:          "file://" + bareDir,
		CommitSHA:          commit2,
		IncludeGitMetadata: true,
		IncludeHistory:     false,
		AllowLocalBare:     true,
	})
	if err != nil {
		t.Fatalf("Checkout commit2 sanitised: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(res2.WorkDir) })

	// Committed gitlink must be checked out as regular file, NOT an OS symlink!
	linkInfo, err := os.Lstat(filepath.Join(res2.WorkDir, "evil-link"))
	if err != nil {
		t.Fatalf("lstat evil-link: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("evil-link was checked out as a live OS symlink!")
	}

	// Verify unsafe .git paths stripped & config sanitized
	for _, absent := range []string{"hooks", "logs", "FETCH_HEAD", "ORIG_HEAD", "refs/remotes"} {
		if _, err := os.Stat(filepath.Join(res2.WorkDir, ".git", absent)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected .git/%s to be absent, got err=%v", absent, err)
		}
	}
	cfgBytes, err := os.ReadFile(filepath.Join(res2.WorkDir, ".git", "config"))
	if err != nil {
		t.Fatalf("read .git/config: %v", err)
	}
	cfgStr := string(cfgBytes)
	if strings.Contains(cfgStr, "[remote") || strings.Contains(cfgStr, bareDir) || !strings.Contains(cfgStr, "symlinks = false") {
		t.Fatalf("unexpected .git/config contents:\n%s", cfgStr)
	}
	count := runTestGit(t, res2.WorkDir, "rev-list", "--count", "HEAD")
	if count != "1" {
		t.Fatalf("expected shallow commit count 1, got %q", count)
	}

	// 3. Full history checkout (IncludeHistory: true, IncludeGitMetadata: true)
	res3, err := r.Checkout(ctx, Request{
		RemoteURL:          "file://" + bareDir,
		CommitSHA:          commit2,
		IncludeGitMetadata: true,
		IncludeHistory:     true,
		AllowLocalBare:     true,
	})
	if err != nil {
		t.Fatalf("Checkout commit2 full history: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(res3.WorkDir) })

	fullCount := runTestGit(t, res3.WorkDir, "rev-list", "--count", "HEAD")
	if fullCount != "2" {
		t.Fatalf("expected full history count 2, got %q", fullCount)
	}
}

func TestCheckoutAskpassAuthAndZeroSecretLeakage(t *testing.T) {
	t.Parallel()
	secretToken := "ghs_TestSecretToken1234567890"
	var mu sync.Mutex
	var authHeaders []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="custodian-test"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		authHeaders = append(authHeaders, auth)
		mu.Unlock()
		// Return 403 after capturing Basic auth header to exercise error sanitization too.
		http.Error(w, "forbidden with token "+secretToken, http.StatusForbidden)
	}))
	defer srv.Close()

	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "checkout-test",
	})

	r := NewRunner(RunnerConfig{Logger: logger})
	_, err := r.Checkout(context.Background(), Request{
		RemoteURL:         srv.URL + "/org/repo.git",
		CommitSHA:         strings.Repeat("b", 40),
		Token:             secretToken,
		AllowInsecureHTTP: true,
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden on 403, got %v", err)
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("error leaked secret token: %v", err)
	}
	if strings.Contains(logBuf.String(), secretToken) {
		t.Fatalf("logs leaked secret token: %s", logBuf.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(authHeaders) == 0 {
		t.Fatalf("expected GIT_ASKPASS to send Authorization header")
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+secretToken))
	if authHeaders[0] != want {
		t.Fatalf("unexpected Authorization header: got %q want %q", authHeaders[0], want)
	}

	// Verify SanitizeGitOutput directly.
	sanitized := SanitizeGitOutput("fatal: https://x-access-token:ghs_abcd12345678@github.com/a/b.git failed", secretToken)
	if strings.Contains(sanitized, "ghs_abcd12345678") || strings.Contains(sanitized, secretToken) {
		t.Fatalf("SanitizeGitOutput leaked secret: %q", sanitized)
	}
}
