package harness

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// GitIdentity represents a Git author or committer name and email.
type GitIdentity struct {
	Name  string
	Email string
}

// CommitSpec defines files, deletions, commit message, and author for BareGitHelper commits.
type CommitSpec struct {
	Files     map[string]string
	Deleted   []string
	Message   string
	Author    GitIdentity
	Committer GitIdentity
}

// SeededRepo describes a bare Git repository managed by BareGitHelper.
type SeededRepo struct {
	FullName       string
	Owner          string
	Name           string
	BarePath       string
	DefaultBranch  string
	HeadSHA        string
	GitHubRepoID   int64
	InstallationID int64
}

// CommitInfo contains inspected Git commit headers, parents, body, and trailers.
type CommitInfo struct {
	SHA            string
	TreeSHA        string
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	Subject        string
	Body           string
	Parents        []string
	Trailers       map[string][]string
}

type repoSeedConfig struct {
	defaultBranch  string
	repoID         int64
	installationID int64
}

// RepoSeedOption configures InitSeededRepo.
type RepoSeedOption func(*repoSeedConfig)

// WithDefaultBranch sets the initial branch name (default "main").
func WithDefaultBranch(branch string) RepoSeedOption {
	return func(c *repoSeedConfig) {
		if branch != "" {
			c.defaultBranch = branch
		}
	}
}

// WithRepoID sets the numeric GitHub repository ID for MockGitHub lookups.
func WithRepoID(id int64) RepoSeedOption {
	return func(c *repoSeedConfig) {
		if id > 0 {
			c.repoID = id
		}
	}
}

// WithInstallationID sets the GitHub App installation ID for MockGitHub lookups.
func WithInstallationID(id int64) RepoSeedOption {
	return func(c *repoSeedConfig) {
		if id > 0 {
			c.installationID = id
		}
	}
}

// BareGitHelper manages isolated local bare Git repositories using hardened Git env defaults.
type BareGitHelper struct {
	t       testing.TB
	rootDir string
	seq     atomic.Int64

	mu    sync.RWMutex
	repos map[string]SeededRepo
}

// NewBareGitHelper creates a BareGitHelper rooted at rootDir (or t.TempDir() if empty).
func NewBareGitHelper(t testing.TB, rootDir string) *BareGitHelper {
	t.Helper()
	if rootDir == "" {
		rootDir = filepath.Join(t.TempDir(), "bare-repos")
	}
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("mkdir bare git root %q: %v", rootDir, err)
	}
	return &BareGitHelper{
		t:       t,
		rootDir: rootDir,
		repos:   make(map[string]SeededRepo),
	}
}

func runHardenedGit(dir string, extraEnv map[string]string, args ...string) (string, error) {
	fullArgs := append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false"}, args...)
	cmd := exec.Command("git", fullArgs...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = cleanBaseEnv(extraEnv)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w\nstderr: %s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// InitSeededRepo initializes a bare repo at <rootDir>/<owner>/<name>.git and creates an initial commit.
func (g *BareGitHelper) InitSeededRepo(owner, name string, files map[string]string, opts ...RepoSeedOption) (SeededRepo, error) {
	if owner == "" || name == "" {
		return SeededRepo{}, errors.New("owner and name are required")
	}
	seq := g.seq.Add(1)
	cfg := repoSeedConfig{
		defaultBranch:  "main",
		repoID:         1000 + seq,
		installationID: 5000 + seq,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	fullName := owner + "/" + name
	barePath := filepath.Join(g.rootDir, owner, name+".git")
	if err := os.MkdirAll(filepath.Dir(barePath), 0o755); err != nil {
		return SeededRepo{}, err
	}
	if _, err := runHardenedGit("", nil, "init", "--bare", "--initial-branch="+cfg.defaultBranch, barePath); err != nil {
		// Fallback for older git init without --initial-branch if needed
		if _, err2 := runHardenedGit("", nil, "init", "--bare", barePath); err2 != nil {
			return SeededRepo{}, err
		}
	}
	_, _ = runHardenedGit(barePath, nil, "symbolic-ref", "HEAD", "refs/heads/"+cfg.defaultBranch)
	_, _ = runHardenedGit(barePath, nil, "config", "http.receivepack", "true")
	_, _ = runHardenedGit(barePath, nil, "config", "uploadpack.allowFilter", "true")
	_, _ = runHardenedGit(barePath, nil, "config", "uploadpack.allowReachableSHA1InWant", "true")
	_, _ = runHardenedGit(barePath, nil, "config", "uploadpack.allowAnySHA1InWant", "true")

	repo := SeededRepo{
		FullName:       fullName,
		Owner:          owner,
		Name:           name,
		BarePath:       barePath,
		DefaultBranch:  cfg.defaultBranch,
		GitHubRepoID:   cfg.repoID,
		InstallationID: cfg.installationID,
	}

	g.mu.Lock()
	g.repos[fullName] = repo
	g.mu.Unlock()

	if len(files) == 0 {
		files = map[string]string{"README.md": "# " + fullName + "\n"}
	}
	sha, err := g.CommitToBranch(fullName, cfg.defaultBranch, CommitSpec{
		Files:   files,
		Message: "Initial seeded commit",
		Author:  GitIdentity{Name: "Seed User", Email: "seed@example.com"},
	})
	if err != nil {
		return SeededRepo{}, err
	}
	repo.HeadSHA = sha

	g.mu.Lock()
	g.repos[fullName] = repo
	g.mu.Unlock()

	return repo, nil
}

// Repo looks up a previously initialized SeededRepo by "owner/name".
func (g *BareGitHelper) Repo(fullName string) (SeededRepo, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	r, ok := g.repos[fullName]
	return r, ok
}

func (g *BareGitHelper) repoByID(id int64) (SeededRepo, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, r := range g.repos {
		if r.GitHubRepoID == id {
			return r, true
		}
	}
	return SeededRepo{}, false
}

// CommitToBranch clones/checks out branch in a temp worktree, applies spec, and pushes to the bare repo.
func (g *BareGitHelper) CommitToBranch(fullName, branch string, spec CommitSpec) (string, error) {
	return g.commitBranch(fullName, branch, spec, false)
}

// ForcePushBranch creates an orphan divergent commit (detaching prior base commits) and force-updates branch (ADV-11).
func (g *BareGitHelper) ForcePushBranch(fullName, branch string, spec CommitSpec) (string, error) {
	return g.commitBranch(fullName, branch, spec, true)
}

// SimulateForcePush is an alias for ForcePushBranch.
func (g *BareGitHelper) SimulateForcePush(fullName, branch string, spec CommitSpec) (string, error) {
	return g.ForcePushBranch(fullName, branch, spec)
}

func (g *BareGitHelper) commitBranch(fullName, branch string, spec CommitSpec, orphan bool) (string, error) {
	repo, ok := g.Repo(fullName)
	if !ok {
		return "", fmt.Errorf("unknown bare repo %q", fullName)
	}
	if branch == "" {
		branch = repo.DefaultBranch
	}

	tmpDir, err := os.MkdirTemp("", "custodian-e2e-wt-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	if _, err := runHardenedGit("", nil, "clone", repo.BarePath, tmpDir); err != nil {
		return "", err
	}

	exists, err := g.BranchExists(fullName, branch)
	if err != nil {
		return "", err
	}
	if orphan {
		if _, err := runHardenedGit(tmpDir, nil, "checkout", "--orphan", "custodian-orphan-tmp"); err != nil {
			return "", err
		}
		// Remove inherited tracked index entries if any so orphan commit is cleanly independent if desired,
		// while preserving files written by spec.Files.
	} else if exists {
		if _, err := runHardenedGit(tmpDir, nil, "checkout", branch); err != nil {
			return "", err
		}
	} else {
		if _, err := runHardenedGit(tmpDir, nil, "checkout", "-b", branch); err != nil {
			return "", err
		}
	}

	for _, del := range spec.Deleted {
		target := filepath.Join(tmpDir, filepath.FromSlash(del))
		_ = os.Remove(target)
	}
	for rel, content := range spec.Files {
		target := filepath.Join(tmpDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return "", err
		}
	}

	if _, err := runHardenedGit(tmpDir, nil, "add", "-A"); err != nil {
		return "", err
	}

	author := spec.Author
	if author.Name == "" {
		author.Name = "Developer"
	}
	if author.Email == "" {
		author.Email = "developer@example.com"
	}
	committer := spec.Committer
	if committer.Name == "" {
		committer.Name = author.Name
	}
	if committer.Email == "" {
		committer.Email = author.Email
	}
	msg := spec.Message
	if msg == "" {
		msg = "Update repository"
	}

	gitEnv := map[string]string{
		"GIT_AUTHOR_NAME":     author.Name,
		"GIT_AUTHOR_EMAIL":    author.Email,
		"GIT_COMMITTER_NAME":  committer.Name,
		"GIT_COMMITTER_EMAIL": committer.Email,
	}
	if _, err := runHardenedGit(tmpDir, gitEnv, "commit", "--allow-empty", "-m", msg); err != nil {
		return "", err
	}
	shaOut, err := runHardenedGit(tmpDir, nil, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(shaOut)

	pushArgs := []string{"push"}
	if orphan {
		pushArgs = append(pushArgs, "--force")
	}
	pushArgs = append(pushArgs, "origin", "HEAD:refs/heads/"+branch)
	if _, err := runHardenedGit(tmpDir, nil, pushArgs...); err != nil {
		return "", err
	}

	return sha, nil
}

// ResolveRef resolves a Git ref (e.g. "refs/heads/main" or "main") to a 40-hex commit SHA.
func (g *BareGitHelper) ResolveRef(fullName, ref string) (string, error) {
	repo, ok := g.Repo(fullName)
	if !ok {
		return "", fmt.Errorf("unknown bare repo %q", fullName)
	}
	out, err := runHardenedGit(repo.BarePath, nil, "rev-parse", "--verify", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ListBranches lists branch names (without "refs/heads/" prefix) in the bare repo.
func (g *BareGitHelper) ListBranches(fullName string) ([]string, error) {
	repo, ok := g.Repo(fullName)
	if !ok {
		return nil, fmt.Errorf("unknown bare repo %q", fullName)
	}
	out, err := runHardenedGit(repo.BarePath, nil, "for-each-ref", "--format=%(refname:short)", "refs/heads")
	if err != nil {
		return nil, err
	}
	var branches []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			branches = append(branches, line)
		}
	}
	sort.Strings(branches)
	return branches, nil
}

// BranchExists reports whether refs/heads/<branch> exists in the bare repo.
func (g *BareGitHelper) BranchExists(fullName, branch string) (bool, error) {
	repo, ok := g.Repo(fullName)
	if !ok {
		return false, fmt.Errorf("unknown bare repo %q", fullName)
	}
	ref := branch
	if !strings.HasPrefix(ref, "refs/") {
		ref = "refs/heads/" + branch
	}
	_, err := runHardenedGit(repo.BarePath, nil, "show-ref", "--verify", "--quiet", ref)
	if err == nil {
		return true, nil
	}
	return false, nil
}

// InspectCommit parses commit metadata, parents, message, and Git trailers from refOrSHA.
func (g *BareGitHelper) InspectCommit(fullName, refOrSHA string) (CommitInfo, error) {
	repo, ok := g.Repo(fullName)
	if !ok {
		return CommitInfo{}, fmt.Errorf("unknown bare repo %q", fullName)
	}
	const sep = "\x1e"
	format := strings.Join([]string{"%H", "%T", "%an", "%ae", "%cn", "%ce", "%P", "%s", "%B"}, sep)
	out, err := runHardenedGit(repo.BarePath, nil, "log", "-1", "--format="+format, refOrSHA)
	if err != nil {
		return CommitInfo{}, err
	}
	parts := strings.SplitN(out, sep, 9)
	if len(parts) < 9 {
		return CommitInfo{}, fmt.Errorf("unexpected git log output: %q", out)
	}
	var parents []string
	if p := strings.TrimSpace(parts[6]); p != "" {
		parents = strings.Fields(p)
	}
	rawBody := strings.TrimRight(parts[8], "\r\n")

	trailers := make(map[string][]string)
	trOut, trErr := runHardenedGit(repo.BarePath, nil, "log", "-1", "--format=%(trailers:unfold,separator=%x1f)", refOrSHA)
	if trErr == nil {
		for _, item := range strings.Split(strings.TrimSpace(trOut), "\x1f") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			k, v, has := strings.Cut(item, ":")
			if has {
				key := strings.TrimSpace(k)
				val := strings.TrimSpace(v)
				trailers[key] = append(trailers[key], val)
			}
		}
	}

	return CommitInfo{
		SHA:            strings.TrimSpace(parts[0]),
		TreeSHA:        strings.TrimSpace(parts[1]),
		AuthorName:     parts[2],
		AuthorEmail:    parts[3],
		CommitterName:  parts[4],
		CommitterEmail: parts[5],
		Parents:        parents,
		Subject:        parts[7],
		Body:           rawBody,
		Trailers:       trailers,
	}, nil
}

// InspectTree returns a map of file path -> file content at refOrSHA.
func (g *BareGitHelper) InspectTree(fullName, refOrSHA string) (map[string]string, error) {
	repo, ok := g.Repo(fullName)
	if !ok {
		return nil, fmt.Errorf("unknown bare repo %q", fullName)
	}
	lsOut, err := runHardenedGit(repo.BarePath, nil, "ls-tree", "-r", "-z", "--name-only", refOrSHA)
	if err != nil {
		return nil, err
	}
	files := make(map[string]string)
	for _, p := range strings.Split(lsOut, "\x00") {
		if p == "" {
			continue
		}
		content, err := runHardenedGit(repo.BarePath, nil, "show", refOrSHA+":"+p)
		if err != nil {
			return nil, err
		}
		files[p] = content
	}
	return files, nil
}

type PullRequest struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Head    string `json:"head"`
	Base    string `json:"base"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	URL     string `json:"url"`
}

type pullRequestBranchWire struct {
	Label string `json:"label"`
	Ref   string `json:"ref"`
	SHA   string `json:"sha"`
}

type pullRequestWire struct {
	Number              int                   `json:"number"`
	Title               string                `json:"title"`
	Body                string                `json:"body"`
	Head                pullRequestBranchWire `json:"head"`
	Base                pullRequestBranchWire `json:"base"`
	State               string                `json:"state"`
	HTMLURL             string                `json:"html_url"`
	URL                 string                `json:"url"`
	MaintainerCanModify bool                  `json:"maintainer_can_modify"`
}

func (m *MockGitHub) toPullRequestWire(repo SeededRepo, pr PullRequest, maintainerCanModify bool) pullRequestWire {
	headSHA, _ := m.git.ResolveRef(repo.FullName, "refs/heads/"+pr.Head)
	baseSHA, _ := m.git.ResolveRef(repo.FullName, "refs/heads/"+pr.Base)
	return pullRequestWire{
		Number:  pr.Number,
		Title:   pr.Title,
		Body:    pr.Body,
		State:   pr.State,
		HTMLURL: pr.HTMLURL,
		URL:     pr.URL,
		Head: pullRequestBranchWire{
			Label: repo.Owner + ":" + pr.Head,
			Ref:   pr.Head,
			SHA:   headSHA,
		},
		Base: pullRequestBranchWire{
			Label: repo.Owner + ":" + pr.Base,
			Ref:   pr.Base,
			SHA:   baseSHA,
		},
		MaintainerCanModify: maintainerCanModify,
	}
}

func normalizePRBranch(owner, ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	prefix := owner + ":"
	if strings.HasPrefix(strings.ToLower(ref), strings.ToLower(prefix)) {
		ref = ref[len(prefix):]
	} else if strings.HasPrefix(ref, ":") {
		ref = ref[1:]
	}
	return ref
}

func matchesPRHeadFilter(owner, filter, prHead string) bool {
	prHeadNorm := normalizePRBranch(owner, prHead)
	if strings.Contains(filter, ":") {
		return strings.EqualFold(filter, owner+":"+prHeadNorm)
	}
	return strings.EqualFold(filter, prHeadNorm)
}

// PushAttempt records a Git ref update received over Smart HTTP or REST Git refs API.
type PushAttempt struct {
	Timestamp time.Time
	Repo      string
	Ref       string
	OldSHA    string
	NewSHA    string
	Token     string
	Allowed   bool
	Stage     string
}

// AuthChallenge records a 401 Basic authentication challenge issued by MockGitHub
// (for example on the initial unauthenticated GET /info/refs?service=git-receive-pack handshake).
type AuthChallenge struct {
	Timestamp  time.Time
	Method     string
	Path       string
	Repo       string
	Service    string
	StatusCode int
}

type outageRule struct {
	methodPrefix string
	pathContains string
	statusCode   int
	remaining    int // < 0 means unlimited until cleared
}

// MockGitHub serves GitHub REST API v3 and Git Smart HTTP backed by BareGitHelper on 127.0.0.1:0.
type MockGitHub struct {
	t          testing.TB
	git        *BareGitHelper
	server     *httptest.Server
	readAppID  int64
	writeAppID int64
	readPEM    string
	writePEM   string
	readKey    *rsa.PrivateKey
	writeKey   *rsa.PrivateKey

	mu         sync.Mutex
	tokenSeq   atomic.Int64
	prs        map[string][]PullRequest
	pushes     []PushAttempt
	challenges []AuthChallenge
	outages    []outageRule
}

func generateTestRSAPEM() (string, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})), nil
}

func parseRSAPrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key (PKCS1/PKCS8): %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PKCS8 key is not RSA")
	}
	return rsaKey, nil
}

// SignAppJWT signs a GitHub App RS256 JWT using a PKCS#1 or PKCS#8 RSA private key PEM.
func SignAppJWT(appID int64, pemStr string, now time.Time) (string, error) {
	if appID <= 0 {
		return "", errors.New("appID must be positive")
	}
	key, err := parseRSAPrivateKeyPEM(pemStr)
	if err != nil {
		return "", err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	headerBytes, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: "RS256",
		Typ: "JWT",
	})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}{
		Iss: strconv.FormatInt(appID, 10),
		Iat: now.Add(-60 * time.Second).Unix(),
		Exp: now.Add(9 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// StartMockGitHub starts a local MockGitHub server bound to 127.0.0.1:0.
func StartMockGitHub(t testing.TB, git *BareGitHelper, readAppID, writeAppID int64) *MockGitHub {
	t.Helper()
	if readAppID == 0 {
		readAppID = 101
	}
	if writeAppID == 0 {
		writeAppID = 202
	}
	readPEM, err := generateTestRSAPEM()
	if err != nil {
		t.Fatalf("generate read GitHub App PEM: %v", err)
	}
	writePEM, err := generateTestRSAPEM()
	if err != nil {
		t.Fatalf("generate write GitHub App PEM: %v", err)
	}
	readKey, err := parseRSAPrivateKeyPEM(readPEM)
	if err != nil {
		t.Fatalf("parse read GitHub App PEM: %v", err)
	}
	writeKey, err := parseRSAPrivateKeyPEM(writePEM)
	if err != nil {
		t.Fatalf("parse write GitHub App PEM: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback for MockGitHub: %v", err)
	}

	m := &MockGitHub{
		t:          t,
		git:        git,
		readAppID:  readAppID,
		writeAppID: writeAppID,
		readPEM:    readPEM,
		writePEM:   writePEM,
		readKey:    readKey,
		writeKey:   writeKey,
		prs:        make(map[string][]PullRequest),
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(m.serveHTTP))
	srv.Listener = ln
	srv.Start()
	m.server = srv
	t.Cleanup(m.Close)
	return m
}

func (m *MockGitHub) URL() string                   { return m.server.URL }
func (m *MockGitHub) BaseAPIURL() string            { return m.server.URL + "/api/v3/" }
func (m *MockGitHub) ReadAppID() int64              { return m.readAppID }
func (m *MockGitHub) WriteAppID() int64             { return m.writeAppID }
func (m *MockGitHub) ReadAppPrivateKeyPEM() string  { return m.readPEM }
func (m *MockGitHub) WriteAppPrivateKeyPEM() string { return m.writePEM }
func (m *MockGitHub) CloneURL(fullName string) string {
	return fmt.Sprintf("%s/%s.git", m.server.URL, fullName)
}

func (m *MockGitHub) Close() {
	if m != nil && m.server != nil {
		m.server.Close()
	}
}

// SetOutage injects statusCode responses for matching requests (count <= 0 means persistent until ClearOutages).
func (m *MockGitHub) SetOutage(methodPrefix, pathContains string, statusCode, count int) {
	if statusCode == 0 {
		statusCode = http.StatusServiceUnavailable
	}
	rem := count
	if rem <= 0 {
		rem = -1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outages = append(m.outages, outageRule{
		methodPrefix: strings.ToUpper(methodPrefix),
		pathContains: pathContains,
		statusCode:   statusCode,
		remaining:    rem,
	})
}

// ClearOutages removes all injected GitHub outage rules.
func (m *MockGitHub) ClearOutages() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outages = nil
}

// PullRequests returns a copy of all PRs recorded for owner/repo.
func (m *MockGitHub) PullRequests(fullName string) []PullRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.prs[fullName]
	out := make([]PullRequest, len(src))
	copy(out, src)
	return out
}

// PRCount returns the number of PRs recorded for owner/repo.
func (m *MockGitHub) PRCount(fullName string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.prs[fullName])
}

// PushAttempts returns a copy of recorded push / ref-mutation attempts
// (403 auth rejections, POST /git-receive-pack executions, and REST ref mutations).
// Initial 401 BasicAuth handshake challenges on GET /info/refs?service=git-receive-pack
// are recorded separately in AuthChallenges so valid authenticated pushes (which
// perform Git's standard unauthenticated-then-authenticated GET /info/refs handshake)
// do not record spurious Allowed: false entries in PushAttempts.
func (m *MockGitHub) PushAttempts() []PushAttempt {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PushAttempt, len(m.pushes))
	copy(out, m.pushes)
	return out
}

// AuthChallenges returns a copy of 401 authentication challenges issued by MockGitHub.
func (m *MockGitHub) AuthChallenges() []AuthChallenge {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuthChallenge, len(m.challenges))
	copy(out, m.challenges)
	return out
}

func (m *MockGitHub) checkOutage(method, path string) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < len(m.outages); i++ {
		r := &m.outages[i]
		if r.remaining == 0 {
			continue
		}
		if (r.methodPrefix == "" || strings.HasPrefix(strings.ToUpper(method), r.methodPrefix)) &&
			(r.pathContains == "" || strings.Contains(path, r.pathContains)) {
			status := r.statusCode
			if r.remaining > 0 {
				r.remaining--
			}
			return status, true
		}
	}
	return 0, false
}

func extractGitHubToken(r *http.Request) string {
	if _, pass, ok := r.BasicAuth(); ok && pass != "" {
		return pass
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	for _, prefix := range []string{"Bearer ", "token ", "Token "} {
		if strings.HasPrefix(auth, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		}
	}
	return ""
}

func isReadOnlyToken(tok string) bool {
	return strings.HasPrefix(tok, "ghs_read_")
}

func isWriteToken(tok string) bool {
	return strings.HasPrefix(tok, "ghs_write_")
}

func (m *MockGitHub) recordPush(p PushAttempt) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushes = append(m.pushes, p)
}

func (m *MockGitHub) recordAuthChallenge(c AuthChallenge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.challenges = append(m.challenges, c)
}

func (m *MockGitHub) serveHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if status, hit := m.checkOutage(r.Method, path); hit {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "simulated github outage"})
		return
	}

	// Git Smart HTTP routes: /{owner}/{repo}.git/...
	if strings.Contains(path, ".git/") {
		m.handleSmartHTTP(w, r)
		return
	}

	// Strip optional /api/v3 prefix used by go-github WithEnterpriseURLs.
	apiPath := strings.TrimPrefix(path, "/api/v3")
	if apiPath == "" {
		apiPath = "/"
	}

	// Installation access token minting
	if r.Method == http.MethodPost && strings.HasPrefix(apiPath, "/app/installations/") && strings.HasSuffix(apiPath, "/access_tokens") {
		m.handleInstallationToken(w, r, apiPath)
		return
	}

	// Lookup repository by numeric ID: /repositories/{id}
	if strings.HasPrefix(apiPath, "/repositories/") {
		idStr := strings.TrimPrefix(apiPath, "/repositories/")
		idStr = strings.SplitN(idStr, "/", 2)[0]
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"message":"invalid repo id"}`, http.StatusBadRequest)
			return
		}
		repo, ok := m.git.repoByID(id)
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		m.writeRepoJSON(w, repo)
		return
	}

	// /repos/{owner}/{repo}...
	if strings.HasPrefix(apiPath, "/repos/") {
		rest := strings.TrimPrefix(apiPath, "/repos/")
		segs := strings.SplitN(rest, "/", 3)
		if len(segs) < 2 {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		fullName := segs[0] + "/" + segs[1]
		repo, ok := m.git.Repo(fullName)
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		sub := ""
		if len(segs) == 3 {
			sub = "/" + segs[2]
		}
		m.handleRepoAPI(w, r, repo, sub)
		return
	}

	http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
}

func (m *MockGitHub) verifyAppJWT(authHeader string, now time.Time) (bool, error) {
	trimmed := strings.TrimSpace(authHeader)
	if len(trimmed) < len("bearer ") || !strings.EqualFold(trimmed[:len("bearer ")], "bearer ") {
		return false, errors.New("missing Bearer authorization header")
	}
	token := strings.TrimSpace(trimmed[len("bearer "):])
	if token == "" {
		return false, errors.New("empty Bearer token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false, errors.New("malformed JWT structure")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("decode JWT header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return false, fmt.Errorf("parse JWT header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return false, fmt.Errorf("unsupported JWT alg %q", hdr.Alg)
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "JWT") {
		return false, fmt.Errorf("unsupported JWT typ %q", hdr.Typ)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims struct {
		Iss json.RawMessage `json:"iss"`
		Iat int64           `json:"iat"`
		Exp int64           `json:"exp"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return false, fmt.Errorf("parse JWT claims: %w", err)
	}
	if len(bytes.TrimSpace(claims.Iss)) == 0 {
		return false, errors.New("missing JWT iss claim")
	}

	var issAppID int64
	var issStr string
	if err := json.Unmarshal(claims.Iss, &issStr); err == nil {
		issAppID, err = strconv.ParseInt(strings.TrimSpace(issStr), 10, 64)
		if err != nil {
			return false, fmt.Errorf("invalid JWT iss %q: %w", issStr, err)
		}
	} else {
		var issNum int64
		if err := json.Unmarshal(claims.Iss, &issNum); err != nil {
			return false, fmt.Errorf("invalid JWT iss claim: %w", err)
		}
		issAppID = issNum
	}

	var isWriteApp bool
	var pubKey *rsa.PublicKey
	switch issAppID {
	case m.readAppID:
		isWriteApp = false
		if m.readKey != nil {
			pubKey = &m.readKey.PublicKey
		}
	case m.writeAppID:
		isWriteApp = true
		if m.writeKey != nil {
			pubKey = &m.writeKey.PublicKey
		}
	default:
		return false, fmt.Errorf("unknown GitHub App iss %d", issAppID)
	}
	if pubKey == nil {
		return false, errors.New("mock GitHub App public key not initialized")
	}

	if claims.Iat <= 0 || claims.Exp <= 0 || claims.Exp <= claims.Iat {
		return false, errors.New("invalid JWT iat/exp window")
	}
	if claims.Exp-claims.Iat > 660 {
		return false, errors.New("JWT lifetime exceeds maximum 10m window")
	}
	nowUnix := now.UTC().Unix()
	if nowUnix > claims.Exp+60 {
		return false, errors.New("JWT has expired")
	}
	if claims.Iat > nowUnix+120 {
		return false, errors.New("JWT iat is in the future")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("decode JWT signature: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sum[:], sig); err != nil {
		return false, fmt.Errorf("verify JWT signature: %w", err)
	}

	return isWriteApp, nil
}

func (m *MockGitHub) handleInstallationToken(w http.ResponseWriter, r *http.Request, apiPath string) {
	isWriteApp, authErr := m.verifyAppJWT(r.Header.Get("Authorization"), time.Now().UTC())
	if authErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Bad credentials"})
		return
	}

	trimmed := strings.TrimPrefix(apiPath, "/app/installations/")
	instIDStr := strings.TrimSuffix(trimmed, "/access_tokens")
	instIDStr = strings.TrimSuffix(instIDStr, "/")
	instID, err := strconv.ParseInt(instIDStr, 10, 64)
	if err != nil || instID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "invalid installation id"})
		return
	}
	seq := m.tokenSeq.Add(1)

	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	hasPermissions := false
	requestsWrite := false
	if len(bytes.TrimSpace(body)) > 0 {
		var req struct {
			Permissions map[string]string `json:"permissions"`
		}
		if json.Unmarshal(body, &req) == nil && len(req.Permissions) > 0 {
			hasPermissions = true
			for k, v := range req.Permissions {
				lk := strings.ToLower(strings.TrimSpace(k))
				lv := strings.ToLower(strings.TrimSpace(v))
				if lk == "pull_requests" || (lv != "" && lv != "read") {
					requestsWrite = true
				}
			}
		}
	}
	if !requestsWrite && (bytes.Contains(body, []byte(`"write"`)) || bytes.Contains(body, []byte("pull_requests"))) {
		requestsWrite = true
		hasPermissions = true
	}

	if !isWriteApp && requestsWrite {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by integration"})
		return
	}

	isWrite := isWriteApp && (!hasPermissions || requestsWrite)

	prefix := "ghs_read_"
	perms := map[string]string{"contents": "read", "metadata": "read"}
	if isWrite {
		prefix = "ghs_write_"
		perms = map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}
	}
	tok := fmt.Sprintf("%s%s_%d", prefix, instIDStr, seq)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":       tok,
		"expires_at":  time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
		"permissions": perms,
	})
}

func (m *MockGitHub) writeRepoJSON(w http.ResponseWriter, repo SeededRepo) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":             repo.GitHubRepoID,
		"name":           repo.Name,
		"full_name":      repo.FullName,
		"private":        true,
		"default_branch": repo.DefaultBranch,
		"clone_url":      m.CloneURL(repo.FullName),
		"owner": map[string]any{
			"login": repo.Owner,
		},
	})
}

func (m *MockGitHub) handleRepoAPI(w http.ResponseWriter, r *http.Request, repo SeededRepo, sub string) {
	tok := extractGitHubToken(r)

	switch {
	case sub == "" && r.Method == http.MethodGet:
		m.writeRepoJSON(w, repo)

	case strings.HasPrefix(sub, "/git/ref/") && r.Method == http.MethodGet:
		ref := "refs/" + strings.TrimPrefix(sub, "/git/ref/")
		sha, err := m.git.ResolveRef(repo.FullName, ref)
		if err != nil {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref": ref,
			"object": map[string]any{
				"type": "commit",
				"sha":  sha,
			},
		})

	case strings.HasPrefix(sub, "/git/matching-refs/") && r.Method == http.MethodGet:
		prefix := "refs/" + strings.TrimPrefix(sub, "/git/matching-refs/")
		out, err := runHardenedGit(repo.BarePath, nil, "for-each-ref", "--format=%(refname) %(objectname)", prefix)
		if err != nil {
			http.Error(w, `{"message":"git error"}`, http.StatusInternalServerError)
			return
		}
		refs := []map[string]any{}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				refs = append(refs, map[string]any{
					"ref": fields[0],
					"object": map[string]any{
						"type": "commit",
						"sha":  fields[1],
					},
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(refs)

	case strings.HasPrefix(sub, "/branches/") && r.Method == http.MethodGet:
		branch := strings.TrimPrefix(sub, "/branches/")
		sha, err := m.git.ResolveRef(repo.FullName, "refs/heads/"+branch)
		if err != nil {
			http.Error(w, `{"message":"Branch not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": branch,
			"commit": map[string]any{
				"sha": sha,
			},
		})

	case strings.HasPrefix(sub, "/commits/") && r.Method == http.MethodGet:
		ref := strings.TrimPrefix(sub, "/commits/")
		info, err := m.git.InspectCommit(repo.FullName, ref)
		if err != nil {
			http.Error(w, `{"message":"No commit found for SHA"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha": info.SHA,
			"commit": map[string]any{
				"message": info.Body,
				"author": map[string]any{
					"name":  info.AuthorName,
					"email": info.AuthorEmail,
				},
				"committer": map[string]any{
					"name":  info.CommitterName,
					"email": info.CommitterEmail,
				},
			},
		})

	case (sub == "/git/refs" && r.Method == http.MethodPost) || (strings.HasPrefix(sub, "/git/refs/") && r.Method == http.MethodPatch):
		if tok == "" {
			m.recordAuthChallenge(AuthChallenge{Timestamp: time.Now().UTC(), Method: r.Method, Path: r.URL.Path, Repo: repo.FullName, StatusCode: http.StatusUnauthorized})
			m.recordPush(PushAttempt{Timestamp: time.Now().UTC(), Repo: repo.FullName, Token: tok, Allowed: false, Stage: "rest_ref_401"})
			http.Error(w, `{"message":"Requires authentication"}`, http.StatusUnauthorized)
			return
		}
		if !isWriteToken(tok) {
			m.recordPush(PushAttempt{Timestamp: time.Now().UTC(), Repo: repo.FullName, Token: tok, Allowed: false, Stage: "rest_ref_403"})
			http.Error(w, `{"message":"Resource not accessible by integration (write token required)"}`, http.StatusForbidden)
			return
		}
		var req struct {
			Ref   string `json:"ref"`
			SHA   string `json:"sha"`
			Force *bool  `json:"force"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"message":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.Ref == "" && strings.HasPrefix(sub, "/git/refs/") {
			req.Ref = "refs/" + strings.TrimPrefix(sub, "/git/refs/")
		}
		if req.Ref == "" || !strings.HasPrefix(req.Ref, "refs/") {
			m.recordPush(PushAttempt{
				Timestamp: time.Now().UTC(),
				Repo:      repo.FullName,
				Ref:       req.Ref,
				NewSHA:    req.SHA,
				Token:     tok,
				Allowed:   false,
				Stage:     "rest_ref_invalid_ref",
			})
			http.Error(w, `{"message":"Invalid reference name"}`, http.StatusUnprocessableEntity)
			return
		}
		var curSHA string
		if resolved, err := m.git.ResolveRef(repo.FullName, req.Ref); err == nil {
			curSHA = resolved
		}
		if r.Method == http.MethodPatch && curSHA == "" {
			m.recordPush(PushAttempt{
				Timestamp: time.Now().UTC(),
				Repo:      repo.FullName,
				Ref:       req.Ref,
				NewSHA:    req.SHA,
				Token:     tok,
				Allowed:   false,
				Stage:     "rest_ref_missing",
			})
			http.Error(w, `{"message":"Reference does not exist"}`, http.StatusUnprocessableEntity)
			return
		}
		if r.Method == http.MethodPost && curSHA != "" {
			m.recordPush(PushAttempt{
				Timestamp: time.Now().UTC(),
				Repo:      repo.FullName,
				Ref:       req.Ref,
				OldSHA:    curSHA,
				NewSHA:    req.SHA,
				Token:     tok,
				Allowed:   false,
				Stage:     "rest_ref_exists",
			})
			http.Error(w, `{"message":"Reference already exists"}`, http.StatusUnprocessableEntity)
			return
		}
		req.SHA = strings.ToLower(strings.TrimSpace(req.SHA))
		if !isHexSHA(req.SHA) {
			m.recordPush(PushAttempt{
				Timestamp: time.Now().UTC(),
				Repo:      repo.FullName,
				Ref:       req.Ref,
				OldSHA:    curSHA,
				NewSHA:    req.SHA,
				Token:     tok,
				Allowed:   false,
				Stage:     "rest_ref_invalid_sha",
			})
			http.Error(w, `{"message":"Invalid commit SHA"}`, http.StatusUnprocessableEntity)
			return
		}
		if _, objErr := runHardenedGit(repo.BarePath, nil, "cat-file", "-e", req.SHA+"^{commit}"); objErr != nil {
			m.recordPush(PushAttempt{
				Timestamp: time.Now().UTC(),
				Repo:      repo.FullName,
				Ref:       req.Ref,
				OldSHA:    curSHA,
				NewSHA:    req.SHA,
				Token:     tok,
				Allowed:   false,
				Stage:     "rest_ref_invalid_sha",
			})
			http.Error(w, `{"message":"Invalid commit SHA"}`, http.StatusUnprocessableEntity)
			return
		}
		if r.Method == http.MethodPatch && req.Force != nil && !*req.Force {
			if _, ffErr := runHardenedGit(repo.BarePath, nil, "merge-base", "--is-ancestor", curSHA, req.SHA); ffErr != nil {
				m.recordPush(PushAttempt{
					Timestamp: time.Now().UTC(),
					Repo:      repo.FullName,
					Ref:       req.Ref,
					OldSHA:    curSHA,
					NewSHA:    req.SHA,
					Token:     tok,
					Allowed:   false,
					Stage:     "rest_ref_non_ff",
				})
				http.Error(w, `{"message":"Update is not a fast forward"}`, http.StatusUnprocessableEntity)
				return
			}
		}
		if _, err := runHardenedGit(repo.BarePath, nil, "update-ref", req.Ref, req.SHA); err != nil {
			http.Error(w, fmt.Sprintf(`{"message":%q}`, err.Error()), http.StatusUnprocessableEntity)
			return
		}
		m.recordPush(PushAttempt{Timestamp: time.Now().UTC(), Repo: repo.FullName, Ref: req.Ref, OldSHA: curSHA, NewSHA: req.SHA, Token: tok, Allowed: true, Stage: "rest_ref"})
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref": req.Ref,
			"object": map[string]any{
				"type": "commit",
				"sha":  req.SHA,
			},
		})

	case strings.HasPrefix(sub, "/pulls"):
		numStr := strings.TrimPrefix(sub, "/pulls")
		if numStr == "" && r.Method == http.MethodGet {
			headParam := r.URL.Query().Get("head")
			stateParam := r.URL.Query().Get("state")
			if stateParam == "" {
				stateParam = "open"
			}
			baseParam := r.URL.Query().Get("base")

			m.mu.Lock()
			prs := m.prs[repo.FullName]
			m.mu.Unlock()

			var filtered []pullRequestWire
			for _, pr := range prs {
				stateMatch := (stateParam == "all" || strings.EqualFold(pr.State, stateParam))
				headMatch := (headParam == "" || matchesPRHeadFilter(repo.Owner, headParam, pr.Head))
				baseMatch := (baseParam == "" || strings.TrimPrefix(pr.Base, "refs/heads/") == strings.TrimPrefix(baseParam, "refs/heads/"))
				if stateMatch && headMatch && baseMatch {
					filtered = append(filtered, m.toPullRequestWire(repo, pr, false))
				}
			}
			if filtered == nil {
				filtered = []pullRequestWire{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(filtered)
			return
		}

		if numStr == "" && r.Method == http.MethodPost {
			if tok == "" {
				http.Error(w, `{"message":"Requires authentication"}`, http.StatusUnauthorized)
				return
			}
			if !isWriteToken(tok) {
				http.Error(w, `{"message":"Resource not accessible by integration (write token required)"}`, http.StatusForbidden)
				return
			}
			var req struct {
				Title string `json:"title"`
				Body  string `json:"body"`
				Head  string `json:"head"`
				Base  string `json:"base"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"message":"invalid json"}`, http.StatusBadRequest)
				return
			}
			head := normalizePRBranch(repo.Owner, req.Head)
			base := strings.TrimPrefix(strings.TrimSpace(req.Base), "refs/heads/")
			if head == "" || base == "" {
				http.Error(w, `{"message":"Invalid head or base"}`, http.StatusUnprocessableEntity)
				return
			}
			m.mu.Lock()
			prs := m.prs[repo.FullName]
			for _, pr := range prs {
				if pr.State == "open" && normalizePRBranch(repo.Owner, pr.Head) == head && strings.TrimPrefix(pr.Base, "refs/heads/") == base {
					m.mu.Unlock()
					http.Error(w, fmt.Sprintf(`{"message":"A pull request already exists for %s:%s."}`, repo.Owner, head), http.StatusUnprocessableEntity)
					return
				}
			}
			num := len(prs) + 1
			pr := PullRequest{
				Number:  num,
				Title:   req.Title,
				Body:    req.Body,
				Head:    head,
				Base:    base,
				State:   "open",
				HTMLURL: fmt.Sprintf("%s/%s/pull/%d", m.server.URL, repo.FullName, num),
				URL:     fmt.Sprintf("%s/repos/%s/pulls/%d", m.server.URL, repo.FullName, num),
			}
			m.prs[repo.FullName] = append(m.prs[repo.FullName], pr)
			m.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(m.toPullRequestWire(repo, pr, false))
			return
		}

		if strings.HasPrefix(numStr, "/") {
			num, err := strconv.Atoi(strings.TrimPrefix(numStr, "/"))
			if err != nil {
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
				return
			}
			m.mu.Lock()
			prs := m.prs[repo.FullName]
			var pr *PullRequest
			for i := range prs {
				if prs[i].Number == num {
					pr = &prs[i]
					break
				}
			}
			if pr == nil {
				m.mu.Unlock()
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
				return
			}

			if r.Method == http.MethodGet {
				res := m.toPullRequestWire(repo, *pr, false)
				m.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(res)
				return
			}

			if r.Method == http.MethodPatch {
				if tok == "" {
					m.mu.Unlock()
					http.Error(w, `{"message":"Requires authentication"}`, http.StatusUnauthorized)
					return
				}
				if !isWriteToken(tok) {
					m.mu.Unlock()
					http.Error(w, `{"message":"Resource not accessible by integration (write token required)"}`, http.StatusForbidden)
					return
				}
				var req struct {
					Title               *string `json:"title"`
					Body                *string `json:"body"`
					State               *string `json:"state"`
					Base                *string `json:"base"`
					MaintainerCanModify *bool   `json:"maintainer_can_modify"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					m.mu.Unlock()
					http.Error(w, `{"message":"invalid json"}`, http.StatusBadRequest)
					return
				}
				if req.State != nil {
					state := strings.ToLower(*req.State)
					if state != "open" && state != "closed" {
						m.mu.Unlock()
						http.Error(w, `{"message":"Invalid state"}`, http.StatusUnprocessableEntity)
						return
					}
					pr.State = state
				}
				if req.Base != nil {
					if pr.State == "closed" {
						m.mu.Unlock()
						http.Error(w, `{"message":"Cannot change base branch of closed pull request"}`, http.StatusUnprocessableEntity)
						return
					}
					pr.Base = strings.TrimPrefix(strings.TrimSpace(*req.Base), "refs/heads/")
				}
				if req.Title != nil {
					pr.Title = *req.Title
				}
				if req.Body != nil {
					pr.Body = *req.Body
				}
				maintainerCanModify := false
				if req.MaintainerCanModify != nil {
					maintainerCanModify = *req.MaintainerCanModify
				}
				res := m.toPullRequestWire(repo, *pr, maintainerCanModify)
				m.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(res)
				return
			}
		}

	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

type receivePackCmd struct {
	oldSHA string
	newSHA string
	ref    string
}

func isHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func parseReceivePackCommands(reqBytes []byte) []receivePackCmd {
	var cmds []receivePackCmd
	pos := 0
	for pos < len(reqBytes) {
		if pos+4 > len(reqBytes) {
			break
		}
		n, err := strconv.ParseUint(string(reqBytes[pos:pos+4]), 16, 16)
		if err != nil {
			break
		}
		pktLen := int(n)
		if pktLen == 0 { // 0000 flush-pkt terminates the command section before PACK
			break
		}
		if pktLen < 4 || pos+pktLen > len(reqBytes) {
			break
		}
		pkt := reqBytes[pos+4 : pos+pktLen]
		pos += pktLen

		if nul := bytes.IndexByte(pkt, 0); nul >= 0 {
			pkt = pkt[:nul]
		}
		line := strings.TrimRight(string(pkt), "\r\n")
		fields := strings.Fields(line)
		if len(fields) == 3 && isHexSHA(fields[0]) && isHexSHA(fields[1]) && strings.HasPrefix(fields[2], "refs/") {
			cmds = append(cmds, receivePackCmd{
				oldSHA: strings.ToLower(fields[0]),
				newSHA: strings.ToLower(fields[1]),
				ref:    fields[2],
			})
		}
	}
	return cmds
}

type receivePackOutcome struct {
	unpackFailed       bool
	unpackOK           bool
	sawUnpack          bool
	fatalSideband      bool
	anyRejected        bool
	parsedReportStatus bool
	sawSideband        bool
	sideband2          string
	rejectedRefs       map[string]bool
	acceptedRefs       map[string]bool
}

func parsePktLines(data []byte) ([][]byte, bool) {
	var lines [][]byte
	pos := 0
	for pos < len(data) {
		if pos+4 > len(data) {
			return lines, false
		}
		n, err := strconv.ParseUint(string(data[pos:pos+4]), 16, 16)
		if err != nil {
			return lines, false
		}
		pktLen := int(n)
		if pktLen <= 2 { // 0000 flush, 0001 delim, 0002 response-end
			pos += 4
			continue
		}
		if pktLen < 4 || pos+pktLen > len(data) {
			return lines, false
		}
		lines = append(lines, data[pos+4:pos+pktLen])
		pos += pktLen
	}
	return lines, true
}

func parseReceivePackOutcome(out []byte) receivePackOutcome {
	res := receivePackOutcome{
		rejectedRefs: make(map[string]bool),
		acceptedRefs: make(map[string]bool),
	}
	applyStatusLine := func(raw string) {
		line := strings.TrimRight(raw, "\r\n")
		if line == "" {
			return
		}
		if strings.HasPrefix(line, "unpack ") {
			res.sawUnpack = true
			res.parsedReportStatus = true
			if line == "unpack ok" {
				res.unpackOK = true
			} else {
				res.unpackFailed = true
			}
			return
		}
		if strings.HasPrefix(line, "ng ") {
			res.parsedReportStatus = true
			rest := strings.TrimPrefix(line, "ng ")
			ref := rest
			if sp := strings.IndexByte(rest, ' '); sp >= 0 {
				ref = rest[:sp]
			}
			if ref != "" {
				res.rejectedRefs[ref] = true
			}
			res.anyRejected = true
			return
		}
		if strings.HasPrefix(line, "ok ") {
			res.parsedReportStatus = true
			ref := strings.TrimSpace(strings.TrimPrefix(line, "ok "))
			if ref != "" {
				res.acceptedRefs[ref] = true
			}
		}
	}

	outer, _ := parsePktLines(out)
	if len(outer) > 0 {
		var sideband1 bytes.Buffer
		var sideband2 strings.Builder
		for _, pkt := range outer {
			if len(pkt) == 0 {
				continue
			}
			switch pkt[0] {
			case 1:
				res.sawSideband = true
				sideband1.Write(pkt[1:])
			case 2:
				res.sawSideband = true
				sideband2.Write(pkt[1:])
			case 3:
				res.sawSideband = true
				res.fatalSideband = true
			default:
				applyStatusLine(string(pkt))
			}
		}
		res.sideband2 = sideband2.String()
		if sideband1.Len() > 0 {
			inner, _ := parsePktLines(sideband1.Bytes())
			if len(inner) > 0 {
				for _, pkt := range inner {
					applyStatusLine(string(pkt))
				}
			} else {
				for _, line := range strings.Split(sideband1.String(), "\n") {
					applyStatusLine(line)
				}
			}
		}
		if res.parsedReportStatus || res.fatalSideband || sideband1.Len() > 0 || res.sawSideband {
			return res
		}
	}

	for _, line := range strings.Split(string(out), "\n") {
		applyStatusLine(line)
	}
	return res
}

func (m *MockGitHub) handleSmartHTTP(w http.ResponseWriter, r *http.Request) {
	idx := strings.Index(r.URL.Path, ".git/")
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	fullName := strings.TrimPrefix(r.URL.Path[:idx], "/")
	suffix := r.URL.Path[idx+len(".git"):]
	repo, ok := m.git.Repo(fullName)
	if !ok {
		http.NotFound(w, r)
		return
	}

	tok := extractGitHubToken(r)
	service := r.URL.Query().Get("service")

	switch suffix {
	case "/info/refs":
		if service == "git-receive-pack" {
			if tok == "" {
				m.recordAuthChallenge(AuthChallenge{
					Timestamp:  time.Now().UTC(),
					Method:     r.Method,
					Path:       r.URL.Path,
					Repo:       fullName,
					Service:    service,
					StatusCode: http.StatusUnauthorized,
				})
				w.Header().Set("WWW-Authenticate", `Basic realm="MockGitHub"`)
				http.Error(w, "unauthorized: authentication required to push", http.StatusUnauthorized)
				return
			}
			if !isWriteToken(tok) {
				m.recordPush(PushAttempt{Timestamp: time.Now().UTC(), Repo: fullName, Token: tok, Allowed: false, Stage: "info_refs_403"})
				http.Error(w, "forbidden: write token required to push", http.StatusForbidden)
				return
			}
		}
		if service != "git-upload-pack" && service != "git-receive-pack" {
			http.Error(w, "unsupported service", http.StatusBadRequest)
			return
		}
		cmdName := strings.TrimPrefix(service, "git-")
		out, err := runHardenedGit("", nil, cmdName, "--stateless-rpc", "--advertise-refs", repo.BarePath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
		w.Header().Set("Cache-Control", "no-cache")
		pkt := fmt.Sprintf("# service=%s\n", service)
		hdr := fmt.Sprintf("%04x%s0000", len(pkt)+4, pkt)
		_, _ = io.WriteString(w, hdr)
		_, _ = io.WriteString(w, out)

	case "/git-upload-pack", "/git-receive-pack":
		svc := strings.TrimPrefix(suffix, "/")
		if svc == "git-receive-pack" {
			if tok == "" {
				m.recordAuthChallenge(AuthChallenge{
					Timestamp:  time.Now().UTC(),
					Method:     r.Method,
					Path:       r.URL.Path,
					Repo:       fullName,
					Service:    svc,
					StatusCode: http.StatusUnauthorized,
				})
				m.recordPush(PushAttempt{Timestamp: time.Now().UTC(), Repo: fullName, Token: tok, Allowed: false, Stage: "receive_pack_401"})
				w.Header().Set("WWW-Authenticate", `Basic realm="MockGitHub"`)
				http.Error(w, "unauthorized: authentication required to push", http.StatusUnauthorized)
				return
			}
			if !isWriteToken(tok) {
				m.recordPush(PushAttempt{Timestamp: time.Now().UTC(), Repo: fullName, Token: tok, Allowed: false, Stage: "receive_pack_403"})
				http.Error(w, "forbidden: write token required to push", http.StatusForbidden)
				return
			}
		}
		var bodyReader io.Reader = r.Body
		if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			defer gz.Close()
			bodyReader = gz
		}
		reqBytes, err := io.ReadAll(bodyReader)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		cmdName := strings.TrimPrefix(svc, "git-")
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", repo.BarePath)
		cmd.Env = cleanBaseEnv(nil)
		cmd.Stdin = bytes.NewReader(reqBytes)
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		runErr := cmd.Run()
		if svc == "git-receive-pack" {
			rawOut := outBuf.Bytes()
			outcome := parseReceivePackOutcome(rawOut)
			hasReportStatus := outcome.parsedReportStatus ||
				(!outcome.sawSideband && (bytes.Contains(rawOut, []byte("unpack ")) ||
					bytes.Contains(rawOut, []byte("ok ")) ||
					bytes.Contains(rawOut, []byte("ng "))))
			baseAllowed := runErr == nil && !outcome.unpackFailed && !outcome.fatalSideband
			if outcome.sawUnpack {
				baseAllowed = baseAllowed && outcome.unpackOK
			} else if !outcome.parsedReportStatus && !outcome.sawSideband && bytes.Contains(rawOut, []byte("unpack ")) && !bytes.Contains(rawOut, []byte("unpack ok")) {
				baseAllowed = false
			}
			if !hasReportStatus {
				errLower := strings.ToLower(errBuf.String())
				sb2Lower := strings.ToLower(outcome.sideband2)
				if strings.Contains(errLower, "fatal:") || strings.Contains(errLower, "error:") ||
					strings.Contains(sb2Lower, "fatal:") || strings.Contains(sb2Lower, "error:") {
					baseAllowed = false
				}
			}

			cmds := parseReceivePackCommands(reqBytes)
			if len(cmds) == 0 {
				allowed := baseAllowed && !outcome.anyRejected && (outcome.parsedReportStatus || outcome.sawSideband || !bytes.Contains(rawOut, []byte("ng ")))
				m.recordPush(PushAttempt{
					Timestamp: time.Now().UTC(),
					Repo:      fullName,
					Token:     tok,
					Allowed:   allowed,
					Stage:     "receive_pack",
				})
			}
			for _, cmd := range cmds {
				ref := cmd.ref
				rawRejected := !outcome.parsedReportStatus && !outcome.sawSideband &&
					(bytes.Contains(rawOut, []byte("ng "+ref+" ")) || bytes.Contains(rawOut, []byte("ng "+ref+"\n")))
				allowed := baseAllowed && !outcome.rejectedRefs[ref] && !rawRejected
				m.recordPush(PushAttempt{
					Timestamp: time.Now().UTC(),
					Repo:      fullName,
					OldSHA:    cmd.oldSHA,
					NewSHA:    cmd.newSHA,
					Ref:       ref,
					Token:     tok,
					Allowed:   allowed,
					Stage:     "receive_pack",
				})
			}
		}
		if runErr != nil {
			http.Error(w, fmt.Sprintf("git %s failed: %v\n%s", cmdName, runErr, errBuf.String()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-result", svc))
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(outBuf.Bytes())

	default:
		http.NotFound(w, r)
	}
}
