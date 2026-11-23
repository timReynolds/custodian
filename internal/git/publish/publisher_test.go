package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/observability"
)

type tarSpec struct {
	Name     string
	Typeflag byte
	Mode     int64
	Body     []byte
	Linkname string
}

func buildTarGz(t *testing.T, entries []tarSpec) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		tf := e.Typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		mode := e.Mode
		if mode == 0 {
			if tf == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o644
			}
		}
		hdr := &tar.Header{
			Name:     e.Name,
			Typeflag: tf,
			Mode:     mode,
			Size:     int64(len(e.Body)),
			Linkname: e.Linkname,
			ModTime:  time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader(%s): %v", e.Name, err)
		}
		if len(e.Body) > 0 {
			if _, err := tw.Write(e.Body); err != nil {
				t.Fatalf("tar Write(%s): %v", e.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	raw := buf.Bytes()
	return raw, domain.SHA256Hex(raw)
}

func runTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Seed User",
		"GIT_AUTHOR_EMAIL=seed@example.com",
		"GIT_COMMITTER_NAME=Seed User",
		"GIT_COMMITTER_EMAIL=seed@example.com",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func setupSeededBareRepo(t *testing.T) (bareRoot, bareDir, baseCommit string) {
	t.Helper()
	bareRoot = t.TempDir()
	bareDir = filepath.Join(bareRoot, "acme", "service.git")
	if err := os.MkdirAll(filepath.Dir(bareDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "init", "--bare", "--initial-branch=main", bareDir).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	runTestGit(t, bareDir, "config", "http.receivepack", "true")
	runTestGit(t, bareDir, "config", "uploadpack.allowReachableSHA1InWant", "true")

	seed := filepath.Join(t.TempDir(), "seed")
	if out, err := exec.Command("git", "init", "--initial-branch=main", seed).CombinedOutput(); err != nil {
		t.Fatalf("git init seed: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(seed, "README.md"), []byte("hello\n"), 0o644)
	runTestGit(t, seed, "add", "README.md")
	runTestGit(t, seed, "commit", "-m", "initial commit")
	baseCommit = runTestGit(t, seed, "rev-parse", "HEAD")
	runTestGit(t, seed, "push", bareDir, "main")
	return bareRoot, bareDir, baseCommit
}

func generateTestAppKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
}

func parseTrailers(t *testing.T, bareDir, ref string) map[string][]string {
	t.Helper()
	out := runTestGit(t, bareDir, "log", "-1", "--format=%(trailers:unfold,separator=%x1f)", ref)
	res := make(map[string][]string)
	for _, item := range strings.Split(strings.TrimSpace(out), "\x1f") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		k, v, ok := strings.Cut(item, ":")
		if ok {
			res[strings.TrimSpace(k)] = append(res[strings.TrimSpace(k)], strings.TrimSpace(v))
		}
	}
	return res
}

func TestPublishDependencyIsolationBoundary(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		t.Fatalf("failed to locate repo root from %s: %v", wd, err)
	}

	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, "list", "-f", `{{range .Deps}}{{.}}{{"\n"}}{{end}}`, "./internal/git/publish", "./internal/github/write")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}

	forbidden := []string{
		"internal/inspection",
		"internal/decisions",
		"internal/snapshots",
		"internal/archive",
		"internal/auth",
		"internal/identity",
		"internal/policy",
		"internal/git/reconstruct",
		"internal/git/checkout",
		"github.com/google/cel-go",
	}
	for _, line := range strings.Split(string(out), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		for _, bad := range forbidden {
			if strings.Contains(pkg, bad) {
				t.Fatalf("isolation boundary violated: %q matches forbidden %q", pkg, bad)
			}
		}
	}
}

type staticLoader struct {
	req PublishRequest
	err error
}

func (l staticLoader) LoadApprovedPublication(_ context.Context, _ domain.ApprovedPublication) (PublishRequest, error) {
	return l.req, l.err
}

type memOpener struct {
	data []byte
}

func (m memOpener) Open(_ context.Context, _ domain.Artifact) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.data)), nil
}

func TestPublishHappyPath_LocalBareAndDomainPublisher(t *testing.T) {
	t.Parallel()
	bareRoot, bareDir, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))

	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "publish-test",
	})
	metrics, err := observability.NewMetrics(observability.MetricsConfig{})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	tarGz, tarSHA := buildTarGz(t, []tarSpec{
		{Name: "README.md", Mode: 0o644, Body: []byte("updated readme\n")},
		{Name: "bin", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "bin/run.sh", Mode: 0o755, Body: []byte("#!/bin/sh\necho ok\n")},
	})

	propID := domain.MustNewID()
	wsID := domain.MustNewID()
	repo := domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   101,
		GitHubInstallationID: 1,
		FullName:             "acme/service",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
	}
	owner := domain.Principal{
		ID:            domain.MustNewID(),
		Kind:          domain.PrincipalKindHuman,
		DisplayName:   "Alice Developer",
		VerifiedEmail: "alice@example.com",
	}
	manifestDigest := strings.Repeat("c", 64)

	svc, err := NewService(Config{
		WriteClient: bareClient,
		Loader: staticLoader{
			req: PublishRequest{
				ProposalID:                  propID,
				WorkspaceID:                 wsID,
				Repository:                  repo,
				Owner:                       owner,
				BaseCommit:                  baseCommit,
				TargetRef:                   "main",
				Title:                       "Add executable script",
				Description:                 "Adds bin/run.sh safely.",
				AgentAssisted:               true,
				ManifestDigest:              manifestDigest,
				ExpectedCanonicalTreeSHA256: tarSHA,
				CanonicalTreeArtifact:       &domain.Artifact{ID: domain.MustNewID(), Kind: domain.ArtifactKindCanonicalTree, SHA256: tarSHA, SizeBytes: int64(len(tarGz))},
				CommitTime:                  time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC),
			},
		},
		ArtifactOpener: memOpener{data: tarGz},
		Logger:         logger,
		Metrics:        metrics,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	ctx := context.Background()

	// Reject manifest digest mismatch in domain.Publisher.Publish
	if _, err := svc.Publish(ctx, domain.ApprovedPublication{
		ProposalID:     propID,
		ManifestDigest: strings.Repeat("d", 64),
	}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on manifest digest mismatch, got %v", err)
	}

	res, err := svc.Publish(ctx, domain.ApprovedPublication{
		ProposalID:     propID,
		ManifestDigest: manifestDigest,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	wantBranch := "custodian/" + propID.String()
	if res.Branch != wantBranch || res.PRNumber != 1 || res.ProposalID != propID {
		t.Fatalf("unexpected PublicationResult: %+v", res)
	}

	// Verify git commit metadata on bare repo.
	const sep = "\x1e"
	info := runTestGit(t, bareDir, "log", "-1", "--format="+strings.Join([]string{"%H", "%P", "%an", "%ae", "%cn", "%ce", "%s"}, sep), "refs/heads/"+wantBranch)
	parts := strings.Split(info, sep)
	if len(parts) != 7 {
		t.Fatalf("unexpected git log parts: %q", info)
	}
	if parts[0] != res.CommitSHA || parts[1] != baseCommit {
		t.Fatalf("unexpected commit/parent: got (%s, %s), want (%s, %s)", parts[0], parts[1], res.CommitSHA, baseCommit)
	}
	if parts[2] != "Alice Developer" || parts[3] != "alice@example.com" {
		t.Fatalf("unexpected author: %s <%s>", parts[2], parts[3])
	}
	if parts[4] != "Custodian" || parts[5] != "custodian@custodian.local" {
		t.Fatalf("unexpected committer: %s <%s>", parts[4], parts[5])
	}
	if parts[6] != "Add executable script" {
		t.Fatalf("unexpected subject: %q", parts[6])
	}

	// Verify executable file mode preserved as 100755.
	lsTree := runTestGit(t, bareDir, "ls-tree", res.CommitSHA, "bin/run.sh")
	if !strings.HasPrefix(lsTree, "100755 blob ") {
		t.Fatalf("expected mode 100755 for bin/run.sh, got %q", lsTree)
	}

	// Verify trailers.
	trailers := parseTrailers(t, bareDir, "refs/heads/"+wantBranch)
	if len(trailers["Custodian-Proposal"]) != 1 || trailers["Custodian-Proposal"][0] != propID.String() {
		t.Fatalf("unexpected Custodian-Proposal trailer: %+v", trailers)
	}
	if len(trailers["Custodian-Workspace"]) != 1 || trailers["Custodian-Workspace"][0] != wsID.String() {
		t.Fatalf("unexpected Custodian-Workspace trailer: %+v", trailers)
	}
	if len(trailers["Agent-Assisted"]) != 1 || trailers["Agent-Assisted"][0] != "true" {
		t.Fatalf("unexpected Agent-Assisted trailer: %+v", trailers)
	}

	// Verify main branch was not modified.
	mainTip := runTestGit(t, bareDir, "rev-parse", "refs/heads/main")
	if mainTip != baseCommit {
		t.Fatalf("main branch was modified: got %s want %s", mainTip, baseCommit)
	}

	// Verify SafeHandler logs did not leak email or description body.
	logStr := logBuf.String()
	if strings.Contains(logStr, "alice@example.com") || strings.Contains(logStr, "Adds bin/run.sh") {
		t.Fatalf("logs leaked sensitive fields: %s", logStr)
	}
}

func TestPublishHappyPath_MockGitHubSmartHTTP(t *testing.T) {
	t.Parallel()
	_, bareDir, baseCommit := setupSeededBareRepo(t)
	pemBytes := generateTestAppKeyPEM(t)
	writeToken := "ghs_write_smarthttp_token_abc123"

	var mu sync.Mutex
	var receiveTokens []string
	type prRec struct {
		Number int
		Title  string
		Body   string
		Head   string
		Base   string
		State  string
	}
	var prs []prRec
	var forcePR503 bool

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/app/installations/88/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      writeToken,
			"expires_at": time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/service", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             4242,
			"name":           "service",
			"full_name":      "acme/service",
			"private":        true,
			"default_branch": "main",
			"clone_url":      srv.URL + "/acme/service.git",
			"owner":          map[string]any{"login": "acme"},
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/service/pulls", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if forcePR503 {
			http.Error(w, `{"message":"simulated outage"}`, http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			head := r.URL.Query().Get("head")
			base := r.URL.Query().Get("base")
			var out []map[string]any
			for _, pr := range prs {
				if pr.State == "open" &&
					(head == "" || head == "acme:"+pr.Head || head == pr.Head) &&
					(base == "" || base == pr.Base) {
					out = append(out, map[string]any{
						"number":   pr.Number,
						"title":    pr.Title,
						"body":     pr.Body,
						"state":    pr.State,
						"url":      srv.URL + "/api/v3/repos/acme/service/pulls/1",
						"html_url": srv.URL + "/acme/service/pull/1",
						"head":     map[string]any{"ref": pr.Head},
						"base":     map[string]any{"ref": pr.Base},
					})
				}
			}
			if out == nil {
				out = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var body struct {
				Title string `json:"title"`
				Body  string `json:"body"`
				Head  string `json:"head"`
				Base  string `json:"base"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			n := len(prs) + 1
			pr := prRec{Number: n, Title: body.Title, Body: body.Body, Head: body.Head, Base: body.Base, State: "open"}
			prs = append(prs, pr)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number":   pr.Number,
				"title":    pr.Title,
				"body":     pr.Body,
				"state":    pr.State,
				"url":      srv.URL + "/api/v3/repos/acme/service/pulls/1",
				"html_url": srv.URL + "/acme/service/pull/1",
				"head":     map[string]any{"ref": pr.Head},
				"base":     map[string]any{"ref": pr.Base},
			})
		}
	})
	mux.HandleFunc("/api/v3/repos/acme/service/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Title *string `json:"title"`
			Body  *string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		if body.Title != nil {
			prs[0].Title = *body.Title
		}
		if body.Body != nil {
			prs[0].Body = *body.Body
		}
		pr := prs[0]
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"number":   pr.Number,
			"title":    pr.Title,
			"body":     pr.Body,
			"state":    pr.State,
			"url":      srv.URL + "/api/v3/repos/acme/service/pulls/1",
			"html_url": srv.URL + "/acme/service/pull/1",
			"head":     map[string]any{"ref": pr.Head},
			"base":     map[string]any{"ref": pr.Base},
		})
	})

	// Git Smart HTTP endpoints
	mux.HandleFunc("/acme/service.git/info/refs", func(w http.ResponseWriter, r *http.Request) {
		service := r.URL.Query().Get("service")
		if service == "git-receive-pack" {
			_, pass, ok := r.BasicAuth()
			if !ok || pass == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="MockGitHub"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if pass != writeToken {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		cmdName := strings.TrimPrefix(service, "git-")
		out, err := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", "--advertise-refs", bareDir).CombinedOutput()
		if err != nil {
			http.Error(w, string(out), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
		pkt := fmt.Sprintf("# service=%s\n", service)
		hdr := fmt.Sprintf("%04x%s0000", len(pkt)+4, pkt)
		_, _ = io.WriteString(w, hdr)
		_, _ = w.Write(out)
	})
	handleSmartRPC := func(cmdName string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if cmdName == "receive-pack" {
				_, pass, ok := r.BasicAuth()
				if !ok || pass != writeToken {
					w.Header().Set("WWW-Authenticate", `Basic realm="MockGitHub"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				mu.Lock()
				receiveTokens = append(receiveTokens, pass)
				mu.Unlock()
			}
			var body io.Reader = r.Body
			if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
				gz, err := gzip.NewReader(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				defer gz.Close()
				body = gz
			}
			reqBytes, _ := io.ReadAll(body)
			cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", bareDir)
			cmd.Stdin = bytes.NewReader(reqBytes)
			var outBuf bytes.Buffer
			cmd.Stdout = &outBuf
			if err := cmd.Run(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", fmt.Sprintf("application/x-git-%s-result", cmdName))
			_, _ = w.Write(outBuf.Bytes())
		}
	}
	mux.HandleFunc("/acme/service.git/git-upload-pack", handleSmartRPC("upload-pack"))
	mux.HandleFunc("/acme/service.git/git-receive-pack", handleSmartRPC("receive-pack"))

	srv = httptest.NewServer(mux)
	defer srv.Close()

	wc, err := write.NewWriteClient(write.WriteConfig{
		AppID:             202,
		PrivateKeyPEM:     pemBytes,
		APIBaseURL:        srv.URL + "/api/v3/",
		HTTPClient:        srv.Client(),
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewWriteClient: %v", err)
	}
	svc, err := NewService(Config{WriteClient: wc})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	tarGz, tarSHA := buildTarGz(t, []tarSpec{
		{Name: "README.md", Mode: 0o644, Body: []byte("smart http change\n")},
	})
	propID := domain.MustNewID()
	wsID := domain.MustNewID()
	req := PublishRequest{
		ProposalID:                  propID,
		WorkspaceID:                 wsID,
		Repository:                  domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 4242, GitHubInstallationID: 88, FullName: "acme/service", Enabled: true},
		Owner:                       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, VerifiedEmail: "bob@example.com"},
		BaseCommit:                  baseCommit,
		TargetRef:                   "HEAD", // resolves via DefaultBranch
		Title:                       "Human direct change",
		AgentAssisted:               false,
		ManifestDigest:              strings.Repeat("e", 64),
		ExpectedCanonicalTreeSHA256: tarSHA,
		CanonicalTreeTarGz:          tarGz,
	}

	// Simulate RG-08 crash-after-push: push succeeds, PR creation returns 503.
	mu.Lock()
	forcePR503 = true
	mu.Unlock()
	if _, err := svc.PublishRequest(context.Background(), req); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on PR 503, got %v", err)
	}

	// Retry after outage clears: must reuse pushed commit without duplicating commit or PR.
	mu.Lock()
	forcePR503 = false
	mu.Unlock()
	res1, err := svc.PublishRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("PublishRequest retry: %v", err)
	}
	res2, err := svc.PublishRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("PublishRequest replay: %v", err)
	}
	if res1.CommitSHA != res2.CommitSHA || res1.PRNumber != 1 || res2.PRNumber != 1 {
		t.Fatalf("idempotency mismatch: res1=%+v res2=%+v", res1, res2)
	}

	mu.Lock()
	if len(receiveTokens) != 1 || receiveTokens[0] != writeToken {
		t.Fatalf("expected exactly 1 receive-pack push using writeToken, got %v", receiveTokens)
	}
	if len(prs) != 1 {
		t.Fatalf("expected exactly 1 PR, got %d", len(prs))
	}
	mu.Unlock()

	// Verify fallback author name = VerifiedEmail and Agent-Assisted: false
	trailers := parseTrailers(t, bareDir, "refs/heads/custodian/"+propID.String())
	if len(trailers["Agent-Assisted"]) != 1 || trailers["Agent-Assisted"][0] != "false" {
		t.Fatalf("expected Agent-Assisted: false, got %+v", trailers)
	}
	author := runTestGit(t, bareDir, "log", "-1", "--format=%an|%ae", res1.CommitSHA)
	if author != "bob@example.com|bob@example.com" {
		t.Fatalf("expected email fallback author, got %q", author)
	}
}

func TestPublishBranchExclusivity_RG07(t *testing.T) {
	t.Parallel()
	bareRoot, bareDir, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))
	svc, err := NewService(Config{WriteClient: bareClient})
	if err != nil {
		t.Fatal(err)
	}
	tarGz, _ := buildTarGz(t, []tarSpec{{Name: "a.txt", Body: []byte("a\n")}})
	propID := domain.MustNewID()
	baseReq := PublishRequest{
		ProposalID:         propID,
		WorkspaceID:        domain.MustNewID(),
		Repository:         domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
		Owner:              domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
		BaseCommit:         baseCommit,
		TargetRef:          "main",
		Title:              "Branch test",
		CanonicalTreeTarGz: tarGz,
	}

	for _, badBranch := range []string{"main", "refs/heads/main", "custodian/" + domain.MustNewID().String(), "feature/evil"} {
		r := baseReq
		r.BranchOverride = badBranch
		if _, err := svc.PublishRequest(context.Background(), r); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("BranchOverride %q: expected ErrForbidden, got %v", badBranch, err)
		}
	}

	for _, badTarget := range []string{
		"refs/tags/v1.0",
		baseCommit,
		"-main",
		"bad..ref",
		"refs/heads/-evil",
		"refs/heads/",
		"refs/heads/foo.lock/bar",
		"refs/heads/.hidden",
		"foo.lock/bar",
		".hidden",
	} {
		r := baseReq
		r.TargetRef = badTarget
		if _, err := svc.PublishRequest(context.Background(), r); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("TargetRef %q: expected ErrBadRequest, got %v", badTarget, err)
		}
	}

	// Only main should exist in bareDir.
	branches := runTestGit(t, bareDir, "for-each-ref", "--format=%(refname:short)", "refs/heads")
	if branches != "main" {
		t.Fatalf("expected only main branch, got %q", branches)
	}
}

func TestPublishHardenedGitEnvAndMaliciousArchive_ADV05(t *testing.T) {
	bareRoot, bareDir, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))

	// Poison host git environment variables; publisher must ignore/strip them.
	hookMarker := filepath.Join(t.TempDir(), "pwned.marker")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/nonexistent'")
	t.Setenv("GIT_EXTERNAL_DIFF", "touch "+hookMarker)
	t.Setenv("GIT_SSH_COMMAND", "touch "+hookMarker)
	t.Setenv("SSH_ASKPASS", "touch "+hookMarker)

	svc, err := NewService(Config{WriteClient: bareClient})
	if err != nil {
		t.Fatal(err)
	}
	propID := domain.MustNewID()
	baseReq := PublishRequest{
		ProposalID:  propID,
		WorkspaceID: domain.MustNewID(),
		Repository:  domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
		Owner:       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
		BaseCommit:  baseCommit,
		TargetRef:   "main",
		Title:       "ADV-05 test",
	}

	maliciousArchives := []struct {
		name    string
		entries []tarSpec
		wantErr error
	}{
		{"git_hooks", []tarSpec{{Name: ".git/hooks/pre-commit", Mode: 0o755, Body: []byte("#!/bin/sh\necho pwn\n")}}, domain.ErrUnprocessable},
		{"git_config", []tarSpec{{Name: ".git/config", Body: []byte("[core]\n\tfsmonitor = evil\n")}}, domain.ErrUnprocessable},
		{"traversal", []tarSpec{{Name: "../outside.txt", Body: []byte("x")}}, domain.ErrUnprocessable},
		{"windows_drive_raw", []tarSpec{{Name: "C:drive.txt", Body: []byte("x")}}, domain.ErrUnprocessable},
		{"windows_drive_dot_slash", []tarSpec{{Name: "./C:drive.txt", Body: []byte("x")}}, domain.ErrUnprocessable},
		{"windows_drive_double_dot_slash", []tarSpec{{Name: "././C:drive.txt", Body: []byte("x")}}, domain.ErrUnprocessable},
		{"windows_drive_slash", []tarSpec{{Name: "./C:/evil.txt", Body: []byte("x")}}, domain.ErrUnprocessable},
		{"windows_drive_lower", []tarSpec{{Name: "./d:foo.txt", Body: []byte("x")}}, domain.ErrUnprocessable},
		{"symlink", []tarSpec{{Name: "sym", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, domain.ErrUnprocessable},
		{"hardlink", []tarSpec{{Name: "hard", Typeflag: tar.TypeLink, Linkname: "README.md"}}, domain.ErrUnprocessable},
		{"fifo", []tarSpec{{Name: "pipe", Typeflag: tar.TypeFifo}}, domain.ErrUnprocessable},
		{"case_collision", []tarSpec{{Name: "README.md", Body: []byte("a")}, {Name: "readme.md", Body: []byte("b")}}, domain.ErrUnprocessable},
		{"nfc_nfd_collision", []tarSpec{{Name: "caf\u00e9.txt", Body: []byte("a")}, {Name: "cafe\u0301.txt", Body: []byte("b")}}, domain.ErrUnprocessable},
	}

	for _, tc := range maliciousArchives {
		t.Run(tc.name, func(t *testing.T) {
			gz, _ := buildTarGz(t, tc.entries)
			r := baseReq
			r.CanonicalTreeTarGz = gz
			if _, err := svc.PublishRequest(context.Background(), r); !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: expected %v, got %v", tc.name, tc.wantErr, err)
			}
		})
	}

	// ExpectedTreeDigest mismatch & archive SHA mismatch
	goodGz, goodSHA := buildTarGz(t, []tarSpec{{Name: "ok.txt", Body: []byte("ok\n")}})
	badSHA := baseReq
	badSHA.CanonicalTreeTarGz = goodGz
	badSHA.ExpectedCanonicalTreeSHA256 = strings.Repeat("0", 64)
	if _, err := svc.PublishRequest(context.Background(), badSHA); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on canonical tree SHA mismatch, got %v", err)
	}

	badTree := baseReq
	badTree.CanonicalTreeTarGz = goodGz
	badTree.ExpectedCanonicalTreeSHA256 = goodSHA
	badTree.ExpectedTreeDigest = strings.Repeat("1", 40)
	if _, err := svc.PublishRequest(context.Background(), badTree); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict on tree digest mismatch, got %v", err)
	}

	if _, err := os.Stat(hookMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("poisoned git env marker was executed!")
	}
	if len(bareClient.PullRequests("acme/service")) != 0 {
		t.Fatalf("expected 0 PRs after rejected archives")
	}
	_ = bareDir

	// Verify secret token redaction on Smart HTTP 403 error & insecure HTTP rejection.
	secretToken := "ghs_SuperSecretWriteToken123456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden token="+secretToken, http.StatusForbidden)
	}))
	defer srv.Close()

	mockWC := &staticAccessWriteClient{
		access: write.RepositoryAccess{
			RemoteURL:         srv.URL + "/acme/service.git",
			Token:             secretToken,
			AllowInsecureHTTP: true,
		},
	}
	httpSvc, err := NewService(Config{WriteClient: mockWC})
	if err != nil {
		t.Fatal(err)
	}
	reqWithToken := baseReq
	reqWithToken.CanonicalTreeTarGz = goodGz
	_, err = httpSvc.PublishRequest(context.Background(), reqWithToken)
	if err == nil || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("expected error without token leak, got %v", err)
	}

	// Disallowed http:// when AllowInsecureHTTP is false.
	disallowedWC := &staticAccessWriteClient{
		access: write.RepositoryAccess{
			RemoteURL:         "http://example.com/acme/service.git",
			Token:             secretToken,
			AllowInsecureHTTP: false,
		},
	}
	disallowedSvc, _ := NewService(Config{WriteClient: disallowedWC})
	if _, err := disallowedSvc.PublishRequest(context.Background(), reqWithToken); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for disallowed http://, got %v", err)
	}
}

type staticAccessWriteClient struct {
	access write.RepositoryAccess
}

func (s *staticAccessWriteClient) PreparePushAccess(context.Context, domain.Repository) (write.RepositoryAccess, error) {
	return s.access, nil
}
func (s *staticAccessWriteClient) ResolveBranchSHA(context.Context, domain.Repository, string) (string, error) {
	return "", nil
}
func (s *staticAccessWriteClient) CreateOrUpdatePullRequest(context.Context, write.PullRequestParams) (write.PullRequestResult, error) {
	return write.PullRequestResult{}, nil
}

func TestPublishForgedAuthorAndNonHumanRejected_ADV07(t *testing.T) {
	t.Parallel()
	bareRoot, bareDir, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))
	svc, err := NewService(Config{WriteClient: bareClient})
	if err != nil {
		t.Fatal(err)
	}
	tarGz, _ := buildTarGz(t, []tarSpec{{Name: "file.txt", Body: []byte("hi\n")}})

	// 1. AGENT and SERVICE principals must be rejected 403.
	for _, kind := range []domain.PrincipalKind{domain.PrincipalKindAgent, domain.PrincipalKindService} {
		_, err := svc.PublishRequest(context.Background(), PublishRequest{
			ProposalID:         domain.MustNewID(),
			WorkspaceID:        domain.MustNewID(),
			Repository:         domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
			Owner:              domain.Principal{ID: domain.MustNewID(), Kind: kind, DisplayName: "Bot", VerifiedEmail: "bot@example.com"},
			BaseCommit:         baseCommit,
			TargetRef:          "main",
			Title:              "Bot attempt",
			CanonicalTreeTarGz: tarGz,
		})
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("principal kind %s: expected ErrForbidden, got %v", kind, err)
		}
	}

	// 2. HUMAN without VerifiedEmail must be rejected 422.
	_, err = svc.PublishRequest(context.Background(), PublishRequest{
		ProposalID:         domain.MustNewID(),
		WorkspaceID:        domain.MustNewID(),
		Repository:         domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
		Owner:              domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Unverified"},
		BaseCommit:         baseCommit,
		TargetRef:          "main",
		Title:              "Missing email",
		CanonicalTreeTarGz: tarGz,
	})
	if !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("missing email: expected ErrUnprocessable, got %v", err)
	}

	// 3. Forged author & forged trailer lines in Description must not alter commit author or trailers.
	propID := domain.MustNewID()
	wsID := domain.MustNewID()
	forgedID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	res, err := svc.PublishRequest(context.Background(), PublishRequest{
		ProposalID:         propID,
		WorkspaceID:        wsID,
		Repository:         domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
		Owner:              domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice Real", VerifiedEmail: "alice@real.com"},
		BaseCommit:         baseCommit,
		TargetRef:          "main",
		Title:              "Legit PR\nForged-Header: nope",
		Description:        "Some body\n\nCustodian-Proposal: " + forgedID.String() + "\nCustodian-Workspace: " + forgedID.String() + "\nAgent-Assisted: false\nAuthor: CEO <ceo@evil.com>",
		AgentAssisted:      true,
		CanonicalTreeTarGz: tarGz,
	})
	if err != nil {
		t.Fatalf("PublishRequest with forged description: %v", err)
	}

	author := runTestGit(t, bareDir, "log", "-1", "--format=%an|%ae", res.CommitSHA)
	if author != "Alice Real|alice@real.com" {
		t.Fatalf("expected Alice Real <alice@real.com>, got %q", author)
	}
	trailers := parseTrailers(t, bareDir, res.CommitSHA)
	if len(trailers["Custodian-Proposal"]) != 1 || trailers["Custodian-Proposal"][0] != propID.String() {
		t.Fatalf("forged Custodian-Proposal trailer leaked: %+v", trailers)
	}
	if len(trailers["Custodian-Workspace"]) != 1 || trailers["Custodian-Workspace"][0] != wsID.String() {
		t.Fatalf("forged Custodian-Workspace trailer leaked: %+v", trailers)
	}
	if len(trailers["Agent-Assisted"]) != 1 || trailers["Agent-Assisted"][0] != "true" {
		t.Fatalf("forged Agent-Assisted trailer leaked: %+v", trailers)
	}
}

func TestPublishUpstreamForcePushAborted_ADV11(t *testing.T) {
	t.Parallel()
	bareRoot, bareDir, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))
	svc, err := NewService(Config{WriteClient: bareClient})
	if err != nil {
		t.Fatal(err)
	}
	repo := domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true}
	owner := domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"}

	// 1. Fast-forward commit on main: baseCommit is still an ancestor -> MUST succeed.
	ffWork := filepath.Join(t.TempDir(), "ff")
	runTestGit(t, filepath.Dir(ffWork), "clone", bareDir, ffWork)
	_ = os.WriteFile(filepath.Join(ffWork, "other.txt"), []byte("upstream ff\n"), 0o644)
	runTestGit(t, ffWork, "add", "other.txt")
	runTestGit(t, ffWork, "commit", "-m", "upstream ff")
	runTestGit(t, ffWork, "push", "origin", "main")

	tarGz, _ := buildTarGz(t, []tarSpec{{Name: "feature.txt", Body: []byte("feature\n")}})
	ffProp := domain.MustNewID()
	ffRes, err := svc.PublishRequest(context.Background(), PublishRequest{
		ProposalID:         ffProp,
		WorkspaceID:        domain.MustNewID(),
		Repository:         repo,
		Owner:              owner,
		BaseCommit:         baseCommit,
		TargetRef:          "main",
		Title:              "FF compatible",
		CanonicalTreeTarGz: tarGz,
	})
	if err != nil {
		t.Fatalf("expected fast-forward compatible publish to succeed, got %v", err)
	}
	if ffRes.PRNumber != 1 {
		t.Fatalf("expected PR #1, got %+v", ffRes)
	}

	// 2. Orphan force-push on main: baseCommit is NO LONGER an ancestor -> MUST abort with ErrConflict!
	orphanWork := filepath.Join(t.TempDir(), "orphan")
	if out, err := exec.Command("git", "init", "--initial-branch=main", orphanWork).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	_ = os.WriteFile(filepath.Join(orphanWork, "README.md"), []byte("rewritten history\n"), 0o644)
	runTestGit(t, orphanWork, "add", "README.md")
	runTestGit(t, orphanWork, "commit", "-m", "orphan force push")
	runTestGit(t, orphanWork, "push", "--force", bareDir, "main")

	abortedProp := domain.MustNewID()
	_, err = svc.PublishRequest(context.Background(), PublishRequest{
		ProposalID:         abortedProp,
		WorkspaceID:        domain.MustNewID(),
		Repository:         repo,
		Owner:              owner,
		BaseCommit:         baseCommit,
		TargetRef:          "main",
		Title:              "Should abort on force push",
		CanonicalTreeTarGz: tarGz,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected ErrConflict after upstream force-push, got %v", err)
	}

	// Verify zero custodian/<abortedProp> branch and still only 1 PR from step 1.
	branches := runTestGit(t, bareDir, "for-each-ref", "--format=%(refname:short)", "refs/heads")
	if strings.Contains(branches, abortedProp.String()) {
		t.Fatalf("branch custodian/%s must not be created after force-push abort; branches=%q", abortedProp, branches)
	}
	if len(bareClient.PullRequests("acme/service")) != 1 {
		t.Fatalf("expected no PR created on force-push abort, got %d", len(bareClient.PullRequests("acme/service")))
	}
}

func TestPublishCorruptGzipTrailerAndTrailingMember_ADV05(t *testing.T) {
	t.Parallel()
	bareRoot, _, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))
	svc, err := NewService(Config{
		WriteClient: bareClient,
		ArchiveLimits: ArchiveLimits{
			MaxUncompressedBytes: 4096,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	goodGz, _ := buildTarGz(t, []tarSpec{{Name: "hello.txt", Body: []byte("hello world\n")}})
	baseReq := PublishRequest{
		ProposalID:         domain.MustNewID(),
		WorkspaceID:        domain.MustNewID(),
		Repository:         domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
		Owner:              domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
		BaseCommit:         baseCommit,
		TargetRef:          "main",
		Title:              "Corrupt gzip test",
		ManifestDigest:     strings.Repeat("a", 64),
		ExpectedTreeDigest: "",
		// Deliberately leave ExpectedCanonicalTreeSHA256 empty to verify gzip stream validation itself.
	}

	t.Run("corrupted_crc32_trailer_no_expected_sha", func(t *testing.T) {
		corrupt := append([]byte(nil), goodGz...)
		corrupt[len(corrupt)-8] ^= 0xff
		r := baseReq
		r.ProposalID = domain.MustNewID()
		r.CanonicalTreeTarGz = corrupt
		_, err := svc.PublishRequest(context.Background(), r)
		if !errors.Is(err, domain.ErrUnprocessable) || !strings.Contains(err.Error(), "CORRUPT_CANONICAL_TREE") {
			t.Fatalf("expected ErrUnprocessable(CORRUPT_CANONICAL_TREE), got %v", err)
		}
	})

	t.Run("corrupted_isize_trailer_no_expected_sha", func(t *testing.T) {
		corrupt := append([]byte(nil), goodGz...)
		corrupt[len(corrupt)-1] ^= 0xff
		r := baseReq
		r.ProposalID = domain.MustNewID()
		r.CanonicalTreeTarGz = corrupt
		_, err := svc.PublishRequest(context.Background(), r)
		if !errors.Is(err, domain.ErrUnprocessable) || !strings.Contains(err.Error(), "CORRUPT_CANONICAL_TREE") {
			t.Fatalf("expected ErrUnprocessable(CORRUPT_CANONICAL_TREE), got %v", err)
		}
	})

	t.Run("truncated_gzip_trailer_no_expected_sha", func(t *testing.T) {
		truncated := append([]byte(nil), goodGz[:len(goodGz)-4]...)
		r := baseReq
		r.ProposalID = domain.MustNewID()
		r.CanonicalTreeTarGz = truncated
		_, err := svc.PublishRequest(context.Background(), r)
		if !errors.Is(err, domain.ErrUnprocessable) || !strings.Contains(err.Error(), "CORRUPT_CANONICAL_TREE") {
			t.Fatalf("expected ErrUnprocessable(CORRUPT_CANONICAL_TREE), got %v", err)
		}
	})

	t.Run("trailing_oversized_gzip_member_no_expected_sha", func(t *testing.T) {
		var trailing bytes.Buffer
		gw := gzip.NewWriter(&trailing)
		if _, err := gw.Write(bytes.Repeat([]byte("Z"), 8192)); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		combined := append(append([]byte(nil), goodGz...), trailing.Bytes()...)
		r := baseReq
		r.ProposalID = domain.MustNewID()
		r.CanonicalTreeTarGz = combined
		_, err := svc.PublishRequest(context.Background(), r)
		if !errors.Is(err, domain.ErrUnprocessable) || !strings.Contains(err.Error(), "ARCHIVE_LIMIT_EXCEEDED") {
			t.Fatalf("expected ErrUnprocessable(ARCHIVE_LIMIT_EXCEEDED), got %v", err)
		}
	})

	t.Run("trailing_garbage_after_gzip_member_no_expected_sha", func(t *testing.T) {
		combined := append(append([]byte(nil), goodGz...), []byte("not-a-gzip-member")...)
		r := baseReq
		r.ProposalID = domain.MustNewID()
		r.CanonicalTreeTarGz = combined
		_, err := svc.PublishRequest(context.Background(), r)
		if !errors.Is(err, domain.ErrUnprocessable) || !strings.Contains(err.Error(), "CORRUPT_CANONICAL_TREE") {
			t.Fatalf("expected ErrUnprocessable(CORRUPT_CANONICAL_TREE), got %v", err)
		}
	})
}

func TestPublishTargetRefHeadsFlagInjectionRejectedWithoutFetch_RG07(t *testing.T) {
	t.Parallel()
	_, _, baseCommit := setupSeededBareRepo(t)
	tarGz, _ := buildTarGz(t, []tarSpec{{Name: "a.txt", Body: []byte("a\n")}})

	var remoteRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteRequests++
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()

	mockWC := &staticAccessWriteClient{
		access: write.RepositoryAccess{
			RemoteURL:         srv.URL + "/acme/service.git",
			Token:             "ghs_test_token_12345678",
			AllowInsecureHTTP: true,
		},
	}
	svc, err := NewService(Config{WriteClient: mockWC})
	if err != nil {
		t.Fatal(err)
	}

	for _, badRef := range []string{"refs/heads/-evil", "refs/heads/foo.lock/bar", "refs/heads/.hidden"} {
		_, err = svc.PublishRequest(context.Background(), PublishRequest{
			ProposalID:         domain.MustNewID(),
			WorkspaceID:        domain.MustNewID(),
			Repository:         domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
			Owner:              domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
			BaseCommit:         baseCommit,
			TargetRef:          badRef,
			Title:              "Flag injection test",
			CanonicalTreeTarGz: tarGz,
		})
		if !errors.Is(err, domain.ErrBadRequest) || !strings.Contains(err.Error(), "INVALID_REF_NAME") {
			t.Fatalf("%q: expected ErrBadRequest(INVALID_REF_NAME), got %v", badRef, err)
		}
	}
	if remoteRequests != 0 {
		t.Fatalf("expected 0 remote git HTTP requests (no fetch/push), got %d", remoteRequests)
	}
}

func TestClassifyGitError_NetworkBeforeHTTPStatus(t *testing.T) {
	t.Parallel()
	baseErr := errors.New("exit status 128")

	err := classifyGitError(
		context.Background(),
		"fatal: unable to access 'http://127.0.0.1:40412/acme/service.git/': Failed to connect to 127.0.0.1 port 40412 after 0 ms: Connection refused",
		baseErr,
	)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for connection refused on port 40412, got %v", err)
	}

	err = classifyGitError(
		context.Background(),
		"fatal: unable to access 'http://127.0.0.1:40301/acme/service.git/': Could not resolve host: 127.0.0.1",
		baseErr,
	)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable for could not resolve host on port 40301, got %v", err)
	}

	err = classifyGitError(
		context.Background(),
		"remote: Repository not found.\nfatal: unable to access 'https://github.com/acme/missing.git/': The requested URL returned error: 404",
		baseErr,
	)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for actual HTTP 404, got %v", err)
	}
}

func TestRemoteCommitMatches_FetchHeadMismatch(t *testing.T) {
	t.Parallel()
	_, bareDir, baseCommit := setupSeededBareRepo(t)
	propID := domain.MustNewID()
	wsID := domain.MustNewID()
	branchRef := "refs/heads/custodian/" + propID.String()

	// Create a second commit on bareDir's proposal branch so FETCH_HEAD != baseCommit.
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runTestGit(t, filepath.Dir(cloneDir), "clone", bareDir, cloneDir)
	_ = os.WriteFile(filepath.Join(cloneDir, "README.md"), []byte("new content\n"), 0o644)
	runTestGit(t, cloneDir, "add", "README.md")
	runTestGit(t, cloneDir, "commit", "-m", "second commit")
	secondSHA := runTestGit(t, cloneDir, "rev-parse", "HEAD")
	runTestGit(t, cloneDir, "push", "origin", "HEAD:"+branchRef)

	svc := &Service{gitBin: "git", timeout: defaultTimeout}
	homeDir := t.TempDir()
	workDir := t.TempDir()
	env := cleanGitEnv(homeDir, true, false, "", "")
	if _, err := svc.runGit(context.Background(), "", env, true, "", "init", "--initial-branch=main", "--", workDir); err != nil {
		t.Fatal(err)
	}
	// Fetch baseCommit first so baseCommit exists locally in workDir.
	if _, err := svc.runGit(context.Background(), workDir, env, true, "", "fetch", "--no-tags", "--", "file://"+bareDir, "refs/heads/main"); err != nil {
		t.Fatal(err)
	}

	// Pass stale remoteSHA (baseCommit) while branchRef on remote actually points to secondSHA.
	matches, err := svc.remoteCommitMatches(
		context.Background(),
		workDir,
		env,
		true,
		"",
		"file://"+bareDir,
		branchRef,
		baseCommit,
		"",
		"",
		"",
		"",
		"",
		"",
		FormatCommitMessage("Title", "", propID, wsID, false),
	)
	if err != nil {
		t.Fatalf("remoteCommitMatches returned unexpected error: %v (secondSHA=%s)", err, secondSHA)
	}
	if matches {
		t.Fatalf("expected false when FETCH_HEAD (%s) != remoteSHA (%s)", secondSHA, baseCommit)
	}
}

func TestPublishRemoteCommitMatchesTransient503AndBranchRace_RG08(t *testing.T) {
	t.Parallel()
	_, bareDir, baseCommit := setupSeededBareRepo(t)
	pemBytes := generateTestAppKeyPEM(t)
	writeToken := "ghs_write_rg08_503_token_123"

	var mu sync.Mutex
	var receiveCount int
	var uploadPackPostCount int
	var failSecondUploadPack503 bool
	var forcePR503 bool
	var deleteProposalOnSecondInfoRefs bool
	var deleteProposalRef string
	type prRec struct {
		Number int
		Title  string
		Body   string
		Head   string
		Base   string
		State  string
	}
	var prs []prRec
	var infoRefsCount int

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/app/installations/88/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      writeToken,
			"expires_at": time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/service", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             4242,
			"name":           "service",
			"full_name":      "acme/service",
			"private":        true,
			"default_branch": "main",
			"clone_url":      srv.URL + "/acme/service.git",
			"owner":          map[string]any{"login": "acme"},
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/service/pulls", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if forcePR503 {
			http.Error(w, `{"message":"simulated PR outage"}`, http.StatusServiceUnavailable)
			return
		}
		switch r.Method {
		case http.MethodGet:
			var out []map[string]any
			for _, pr := range prs {
				out = append(out, map[string]any{
					"number":   pr.Number,
					"title":    pr.Title,
					"body":     pr.Body,
					"state":    pr.State,
					"url":      srv.URL + "/api/v3/repos/acme/service/pulls/1",
					"html_url": srv.URL + "/acme/service/pull/1",
					"head":     map[string]any{"ref": pr.Head},
					"base":     map[string]any{"ref": pr.Base},
				})
			}
			if out == nil {
				out = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var body struct {
				Title string `json:"title"`
				Body  string `json:"body"`
				Head  string `json:"head"`
				Base  string `json:"base"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			pr := prRec{Number: len(prs) + 1, Title: body.Title, Body: body.Body, Head: body.Head, Base: body.Base, State: "open"}
			prs = append(prs, pr)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number":   pr.Number,
				"title":    pr.Title,
				"body":     pr.Body,
				"state":    pr.State,
				"url":      srv.URL + "/api/v3/repos/acme/service/pulls/1",
				"html_url": srv.URL + "/acme/service/pull/1",
				"head":     map[string]any{"ref": pr.Head},
				"base":     map[string]any{"ref": pr.Base},
			})
		}
	})
	mux.HandleFunc("/acme/service.git/info/refs", func(w http.ResponseWriter, r *http.Request) {
		service := r.URL.Query().Get("service")
		cmdName := strings.TrimPrefix(service, "git-")
		out, err := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", "--advertise-refs", bareDir).CombinedOutput()
		if err != nil {
			http.Error(w, string(out), http.StatusInternalServerError)
			return
		}
		mu.Lock()
		if service == "git-upload-pack" {
			infoRefsCount++
			if deleteProposalOnSecondInfoRefs && infoRefsCount == 2 && deleteProposalRef != "" {
				// Delete the branch right after lsRemoteHead sees it, before remoteCommitMatches fetches it.
				_ = exec.Command("git", "-C", bareDir, "update-ref", "-d", deleteProposalRef).Run()
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
		pkt := fmt.Sprintf("# service=%s\n", service)
		hdr := fmt.Sprintf("%04x%s0000", len(pkt)+4, pkt)
		_, _ = io.WriteString(w, hdr)
		_, _ = w.Write(out)
	})
	handleSmartRPC := func(cmdName string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			if cmdName == "receive-pack" {
				receiveCount++
			}
			if cmdName == "upload-pack" {
				uploadPackPostCount++
				if failSecondUploadPack503 && uploadPackPostCount == 2 {
					mu.Unlock()
					http.Error(w, "simulated remoteCommitMatches 503", http.StatusServiceUnavailable)
					return
				}
			}
			mu.Unlock()
			var body io.Reader = r.Body
			if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
				gz, err := gzip.NewReader(r.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				defer gz.Close()
				body = gz
			}
			reqBytes, _ := io.ReadAll(body)
			cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", bareDir)
			cmd.Stdin = bytes.NewReader(reqBytes)
			var outBuf bytes.Buffer
			cmd.Stdout = &outBuf
			if err := cmd.Run(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", fmt.Sprintf("application/x-git-%s-result", cmdName))
			_, _ = w.Write(outBuf.Bytes())
		}
	}
	mux.HandleFunc("/acme/service.git/git-upload-pack", handleSmartRPC("upload-pack"))
	mux.HandleFunc("/acme/service.git/git-receive-pack", handleSmartRPC("receive-pack"))

	srv = httptest.NewServer(mux)
	defer srv.Close()

	wc, err := write.NewWriteClient(write.WriteConfig{
		AppID:             202,
		PrivateKeyPEM:     pemBytes,
		APIBaseURL:        srv.URL + "/api/v3/",
		HTTPClient:        srv.Client(),
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewWriteClient: %v", err)
	}
	svc, err := NewService(Config{WriteClient: wc})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	tarGz, tarSHA := buildTarGz(t, []tarSpec{{Name: "README.md", Mode: 0o644, Body: []byte("rg08 test\n")}})
	propID := domain.MustNewID()
	req := PublishRequest{
		ProposalID:                  propID,
		WorkspaceID:                 domain.MustNewID(),
		Repository:                  domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 4242, GitHubInstallationID: 88, FullName: "acme/service", Enabled: true},
		Owner:                       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
		BaseCommit:                  baseCommit,
		TargetRef:                   "main",
		Title:                       "RG-08 outage test",
		ExpectedCanonicalTreeSHA256: tarSHA,
		CanonicalTreeTarGz:          tarGz,
		// Zero CommitTime intentionally: a duplicate commit-tree call after >=1s would mint a new SHA.
	}

	// 1. Initial publish pushes the commit, then fails PR creation with 503.
	mu.Lock()
	forcePR503 = true
	mu.Unlock()
	if _, err := svc.PublishRequest(context.Background(), req); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on PR 503, got %v", err)
	}
	branchRef := "refs/heads/custodian/" + propID.String()
	initialBranchSHA := runTestGit(t, bareDir, "rev-parse", branchRef)

	// Wait >1s so any accidental commit-tree call would mint a different commit SHA.
	time.Sleep(1100 * time.Millisecond)

	// 2. Retry encounters 503 during remoteCommitMatches proposal-branch fetch: MUST abort with ErrUnavailable and zero new pushes.
	mu.Lock()
	forcePR503 = false
	uploadPackPostCount = 0
	failSecondUploadPack503 = true
	mu.Unlock()
	if _, err := svc.PublishRequest(context.Background(), req); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable when remoteCommitMatches hits 503, got %v", err)
	}
	mu.Lock()
	if receiveCount != 1 {
		t.Fatalf("expected zero duplicate pushes on remoteCommitMatches 503; receiveCount=%d", receiveCount)
	}
	if len(prs) != 0 {
		t.Fatalf("expected 0 PRs on aborted retry, got %d", len(prs))
	}
	mu.Unlock()
	if gotSHA := runTestGit(t, bareDir, "rev-parse", branchRef); gotSHA != initialBranchSHA {
		t.Fatalf("existing commit %s was overwritten with %s during 503", initialBranchSHA, gotSHA)
	}

	// 3. Retry succeeds cleanly once outage clears, reusing initialBranchSHA with zero additional pushes.
	mu.Lock()
	failSecondUploadPack503 = false
	uploadPackPostCount = 0
	mu.Unlock()
	res, err := svc.PublishRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("recovery retry failed: %v", err)
	}
	if res.CommitSHA != initialBranchSHA || res.PRNumber != 1 {
		t.Fatalf("expected reused CommitSHA=%s PR=1, got %+v", initialBranchSHA, res)
	}
	mu.Lock()
	if receiveCount != 1 || len(prs) != 1 {
		t.Fatalf("expected 1 push and 1 PR total, got pushes=%d prs=%d", receiveCount, len(prs))
	}
	mu.Unlock()

	// 4. Remote branch vanished between ls-remote and remoteCommitMatches fetch -> ErrConflict (PUBLICATION_BRANCH_RACE).
	mu.Lock()
	infoRefsCount = 0
	uploadPackPostCount = 0
	deleteProposalOnSecondInfoRefs = true
	deleteProposalRef = branchRef
	mu.Unlock()
	_, err = svc.PublishRequest(context.Background(), req)
	if !errors.Is(err, domain.ErrConflict) || !strings.Contains(err.Error(), "PUBLICATION_BRANCH_RACE") {
		t.Fatalf("expected ErrConflict(PUBLICATION_BRANCH_RACE), got %v", err)
	}
	mu.Lock()
	if receiveCount != 1 {
		t.Fatalf("expected zero pushes on branch race conflict, got %d", receiveCount)
	}
	mu.Unlock()
}

func TestPublishClassifyGitError_URLPortAndPathCollisions(t *testing.T) {
	t.Parallel()
	baseErr := errors.New("exit status 128")

	// Unit checks on classifyGitError across tricky URL ports/paths.
	unitCases := []struct {
		name   string
		stderr string
		want   error
	}{
		{
			name:   "503_on_port_40412",
			stderr: "fatal: unable to access 'http://127.0.0.1:40412/acme/service.git/': The requested URL returned error: 503",
			want:   domain.ErrUnavailable,
		},
		{
			name:   "503_on_org404_path",
			stderr: "fatal: unable to access 'http://127.0.0.1:63175/org404/service.git/': The requested URL returned error: 503",
			want:   domain.ErrUnavailable,
		},
		{
			name:   "503_on_org401_path",
			stderr: "remote: service unavailable\nfatal: unable to access 'http://127.0.0.1:63177/org401/service.git/': The requested URL returned error: 503",
			want:   domain.ErrUnavailable,
		},
		{
			name:   "404_on_org403_path",
			stderr: "remote: not found\nfatal: repository 'http://127.0.0.1:63180/org403/service.git/' not found",
			want:   domain.ErrNotFound,
		},
		{
			name:   "non_fast_forward_on_org401_and_port_40312",
			stderr: "To http://127.0.0.1:40312/org401/service.git\n ! [rejected]        deadbeef -> refs/heads/custodian/1 (non-fast-forward)",
			want:   domain.ErrConflict,
		},
		{
			name:   "502_on_org403_path",
			stderr: "error: RPC failed; HTTP 502 curl 22 The requested URL returned error: 502\nfatal: unable to access 'http://127.0.0.1:40412/org403/service.git/'",
			want:   domain.ErrUnavailable,
		},
		{
			name:   "401_on_org503_path",
			stderr: "fatal: unable to access 'http://127.0.0.1:50312/org503/service.git/': The requested URL returned error: 401",
			want:   domain.ErrForbidden,
		},
	}
	for _, tc := range unitCases {
		t.Run("unit_"+tc.name, func(t *testing.T) {
			err := classifyGitError(context.Background(), tc.stderr, baseErr)
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s: expected %v, got %v", tc.name, tc.want, err)
			}
		})
	}

	// End-to-end Service.PublishRequest against httptest.Server with /org404/, /org401/, /org403/ and port 40412.
	_, _, baseCommit := setupSeededBareRepo(t)
	tarGz, tarSHA := buildTarGz(t, []tarSpec{{Name: "a.txt", Body: []byte("a\n")}})

	statusHandler := func(status int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "simulated status", status)
		})
	}

	// Try binding 127.0.0.1:40412 specifically when available.
	t.Run("e2e_503_port_40412", func(t *testing.T) {
		ln40412, err := net.Listen("tcp", "127.0.0.1:40412")
		if err != nil {
			t.Skipf("port 40412 busy in environment: %v", err)
		}
		srv40412 := &httptest.Server{
			Listener: ln40412,
			Config:   &http.Server{Handler: statusHandler(http.StatusServiceUnavailable)},
		}
		srv40412.Start()
		defer srv40412.Close()

		wc := &staticAccessWriteClient{
			access: write.RepositoryAccess{
				RemoteURL:         srv40412.URL + "/acme/service.git",
				Token:             "ghs_test_token_40412",
				AllowInsecureHTTP: true,
			},
		}
		svc, _ := NewService(Config{WriteClient: wc})
		_, pubErr := svc.PublishRequest(context.Background(), PublishRequest{
			ProposalID:                  domain.MustNewID(),
			WorkspaceID:                 domain.MustNewID(),
			Repository:                  domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
			Owner:                       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
			BaseCommit:                  baseCommit,
			TargetRef:                   "main",
			Title:                       "503 on 40412",
			ExpectedCanonicalTreeSHA256: tarSHA,
			CanonicalTreeTarGz:          tarGz,
		})
		if domain.HTTPStatusFromError(pubErr) != http.StatusServiceUnavailable || !errors.Is(pubErr, domain.ErrUnavailable) {
			t.Fatalf("503 on :40412: expected 503 ErrUnavailable, got status=%d err=%v", domain.HTTPStatusFromError(pubErr), pubErr)
		}
	})

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.Handle("/org404/service.git/", statusHandler(http.StatusServiceUnavailable))
	mux.Handle("/org401/service.git/", statusHandler(http.StatusServiceUnavailable))
	mux.Handle("/org403/service.git/", statusHandler(http.StatusServiceUnavailable))
	mux.Handle("/org403/missing.git/", statusHandler(http.StatusNotFound))
	srv = httptest.NewServer(mux)
	defer srv.Close()

	e2eCases := []struct {
		name       string
		remotePath string
		wantStatus int
		wantErr    error
	}{
		{"503_org404", "/org404/service.git", http.StatusServiceUnavailable, domain.ErrUnavailable},
		{"503_org401", "/org401/service.git", http.StatusServiceUnavailable, domain.ErrUnavailable},
		{"503_org403", "/org403/service.git", http.StatusServiceUnavailable, domain.ErrUnavailable},
		{"404_org403", "/org403/missing.git", http.StatusConflict, domain.ErrConflict},
	}
	for _, tc := range e2eCases {
		t.Run("e2e_"+tc.name, func(t *testing.T) {
			wc := &staticAccessWriteClient{
				access: write.RepositoryAccess{
					RemoteURL:         srv.URL + tc.remotePath,
					Token:             "ghs_test_token_path",
					AllowInsecureHTTP: true,
				},
			}
			svc, _ := NewService(Config{WriteClient: wc})
			_, pubErr := svc.PublishRequest(context.Background(), PublishRequest{
				ProposalID:                  domain.MustNewID(),
				WorkspaceID:                 domain.MustNewID(),
				Repository:                  domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
				Owner:                       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
				BaseCommit:                  baseCommit,
				TargetRef:                   "main",
				Title:                       tc.name,
				ExpectedCanonicalTreeSHA256: tarSHA,
				CanonicalTreeTarGz:          tarGz,
			})
			if domain.HTTPStatusFromError(pubErr) != tc.wantStatus || !errors.Is(pubErr, tc.wantErr) {
				t.Fatalf("%s: expected status %d (%v), got status %d (%v)", tc.name, tc.wantStatus, tc.wantErr, domain.HTTPStatusFromError(pubErr), pubErr)
			}
		})
	}
}

type cancelAfterNReader struct {
	r         io.Reader
	cancelAt  int64
	readBytes int64
	cancel    context.CancelFunc
	cancelled bool
}

func (c *cancelAfterNReader) Read(p []byte) (int, error) {
	if len(p) > 2048 {
		p = p[:2048]
	}
	n, err := c.r.Read(p)
	c.readBytes += int64(n)
	if !c.cancelled && c.readBytes >= c.cancelAt {
		c.cancelled = true
		c.cancel()
	}
	return n, err
}

func TestPublishExtractCanonicalTree_ContextCancelInCopyN_PreservesUnavailable(t *testing.T) {
	t.Parallel()
	bareRoot, _, baseCommit := setupSeededBareRepo(t)
	bareClient := write.NewLocalBareClient(write.WithBareRootDir(bareRoot))
	svc, err := NewService(Config{WriteClient: bareClient})
	if err != nil {
		t.Fatal(err)
	}

	// Build incompressible 64KB file inside .tar.gz so io.CopyN iterates across multiple reads.
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	largeTarGz, _ := buildTarGz(t, []tarSpec{{Name: "large.bin", Mode: 0o644, Body: payload}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err = svc.PublishRequest(ctx, PublishRequest{
		ProposalID:  domain.MustNewID(),
		WorkspaceID: domain.MustNewID(),
		Repository:  domain.Repository{ID: domain.MustNewID(), GitHubRepositoryID: 1, FullName: "acme/service", Enabled: true},
		Owner:       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@example.com"},
		BaseCommit:  baseCommit,
		TargetRef:   "main",
		Title:       "Cancel mid CopyN test",
		OpenCanonicalTree: func(_ context.Context) (io.ReadCloser, error) {
			return io.NopCloser(&cancelAfterNReader{
				r:        bytes.NewReader(largeTarGz),
				cancelAt: 8192,
				cancel:   cancel,
			}), nil
		},
	})
	if domain.HTTPStatusFromError(err) != http.StatusServiceUnavailable || !errors.Is(err, domain.ErrUnavailable) || !strings.Contains(err.Error(), "ARCHIVE_ABORTED") {
		t.Fatalf("expected 503 ErrUnavailable(ARCHIVE_ABORTED) on cancel during io.CopyN, got status=%d err=%v", domain.HTTPStatusFromError(err), err)
	}

	// Also verify context cancelled right before gzip.NewReader preserves ARCHIVE_ABORTED (503).
	preCancelledCtx, preCancel := context.WithCancel(context.Background())
	if err := extractCanonicalTree(preCancelledCtx, &cancelAfterNReader{
		r:        bytes.NewReader(largeTarGz),
		cancelAt: 1,
		cancel:   preCancel,
	}, 0, "", t.TempDir(), ArchiveLimits{}); domain.HTTPStatusFromError(err) != http.StatusServiceUnavailable || !errors.Is(err, domain.ErrUnavailable) || !strings.Contains(err.Error(), "ARCHIVE_ABORTED") {
		t.Fatalf("expected 503 ErrUnavailable(ARCHIVE_ABORTED) on cancel in gzip.NewReader, got status=%d err=%v", domain.HTTPStatusFromError(err), err)
	}
}

func TestPublishCanonicalTar_WindowsDrivePrefixesRejected(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"C:drive.txt", "./C:drive.txt", "././C:drive.txt", "./C:/evil.txt", "./d:foo.txt"} {
		if _, _, err := normalizeCanonicalTarPath(p, tar.TypeReg, defaultMaxPathBytes, defaultMaxPathDepth); !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("normalizeCanonicalTarPath(%q) expected ErrUnprocessable, got %v", p, err)
		} else {
			var domErr *domain.DomainError
			if !errors.As(err, &domErr) || domErr.Code() != "UNSAFE_ARCHIVE_PATH" {
				t.Fatalf("normalizeCanonicalTarPath(%q) expected UNSAFE_ARCHIVE_PATH, got %v", p, err)
			}
		}
		gz, _ := buildTarGz(t, []tarSpec{{Name: p, Body: []byte("x")}})
		err := extractCanonicalTree(context.Background(), bytes.NewReader(gz), 0, "", t.TempDir(), ArchiveLimits{})
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("extractCanonicalTree(%q) expected ErrUnprocessable, got %v", p, err)
		}
		var domErr *domain.DomainError
		if !errors.As(err, &domErr) || domErr.Code() != "UNSAFE_ARCHIVE_PATH" {
			t.Fatalf("extractCanonicalTree(%q) expected UNSAFE_ARCHIVE_PATH, got %v", p, err)
		}
	}
}
