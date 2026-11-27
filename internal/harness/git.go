package harness

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
	"github.com/timreynolds/custodian/internal/github"
)

// GitIdentity configures author/committer metadata for harness commits and annotated tags.
type GitIdentity struct {
	Name  string
	Email string
}

// BareRepo describes a local bare Git repository managed by BareGitHarness.
type BareRepo struct {
	FullName           string
	Owner              string
	Name               string
	BarePath           string
	DefaultBranch      string
	HeadSHA            string
	GitHubRepositoryID int64
	InstallationID     int64
}

type bareRepoConfig struct {
	defaultBranch  string
	githubRepoID   int64
	installationID int64
	initialFiles   map[string]string
}

// BareRepoOption customizes InitBareRepo.
type BareRepoOption func(*bareRepoConfig)

func WithDefaultBranch(branch string) BareRepoOption {
	return func(c *bareRepoConfig) {
		if strings.TrimSpace(branch) != "" {
			c.defaultBranch = strings.TrimSpace(branch)
		}
	}
}

func WithGitHubRepoID(id int64) BareRepoOption {
	return func(c *bareRepoConfig) {
		c.githubRepoID = id
	}
}

func WithInstallationID(id int64) BareRepoOption {
	return func(c *bareRepoConfig) {
		c.installationID = id
	}
}

func WithInitialFiles(files map[string]string) BareRepoOption {
	return func(c *bareRepoConfig) {
		c.initialFiles = files
	}
}

// BareGitHarness manages offline bare Git repositories and a paired LocalBareGitReader.
type BareGitHarness struct {
	mu      sync.RWMutex
	rootDir string
	repos   map[string]BareRepo
	nextID  int64
	reader  *github.LocalBareGitReader
}

// NewBareGitHarness initializes a BareGitHarness under rootDir (or t.TempDir() if rootDir == "").
func NewBareGitHarness(t testing.TB, rootDir string) *BareGitHarness {
	t.Helper()
	if strings.TrimSpace(rootDir) == "" {
		rootDir = t.TempDir()
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		t.Fatalf("resolve bare git harness root: %v", err)
	}
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		t.Fatalf("create bare git harness root: %v", err)
	}
	return &BareGitHarness{
		rootDir: absRoot,
		repos:   make(map[string]BareRepo),
		nextID:  1000,
		reader:  github.NewLocalBareGitReader(github.WithBareRootDir(absRoot)),
	}
}

func (h *BareGitHarness) RootDir() string {
	return h.rootDir
}

func (h *BareGitHarness) LocalReader() *github.LocalBareGitReader {
	return h.reader
}

func (h *BareGitHarness) BarePath(fullName string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	repo, ok := h.repos[strings.ToLower(strings.TrimSpace(fullName))]
	return repo.BarePath, ok
}

func (h *BareGitHarness) InitBareRepo(owner, name string, opts ...BareRepoOption) (BareRepo, error) {
	owner = strings.TrimSpace(owner)
	name = strings.TrimSpace(name)
	if owner == "" || name == "" {
		return BareRepo{}, fmt.Errorf("owner and name are required")
	}

	h.mu.Lock()
	h.nextID++
	cfg := bareRepoConfig{
		defaultBranch:  "main",
		githubRepoID:   h.nextID,
		installationID: 1,
	}
	h.mu.Unlock()

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	barePath := filepath.Join(h.rootDir, owner, name+".git")
	if err := os.MkdirAll(filepath.Dir(barePath), 0o755); err != nil {
		return BareRepo{}, err
	}
	if _, err := h.runGit("", GitIdentity{}, "init", "--bare", "--initial-branch="+cfg.defaultBranch, barePath); err != nil {
		return BareRepo{}, err
	}
	for _, kv := range [][2]string{
		{"uploadpack.allowReachableSHA1InWant", "true"},
		{"uploadpack.allowFilter", "true"},
		{"http.receivepack", "true"},
	} {
		if _, err := h.runGit(barePath, GitIdentity{}, "config", kv[0], kv[1]); err != nil {
			return BareRepo{}, err
		}
	}

	fullName := owner + "/" + name
	repo := BareRepo{
		FullName:           fullName,
		Owner:              owner,
		Name:               name,
		BarePath:           barePath,
		DefaultBranch:      cfg.defaultBranch,
		GitHubRepositoryID: cfg.githubRepoID,
		InstallationID:     cfg.installationID,
	}

	h.mu.Lock()
	h.repos[strings.ToLower(fullName)] = repo
	h.mu.Unlock()

	if err := h.reader.RegisterRepo(repo.GitHubRepositoryID, fullName, barePath); err != nil {
		return BareRepo{}, err
	}

	if len(cfg.initialFiles) > 0 {
		sha, err := h.CommitFiles(fullName, cfg.defaultBranch, cfg.initialFiles, nil, "initial commit", GitIdentity{
			Name:  "Harness Init",
			Email: "harness@custodian.local",
		})
		if err != nil {
			return BareRepo{}, err
		}
		repo.HeadSHA = sha
		h.mu.Lock()
		h.repos[strings.ToLower(fullName)] = repo
		h.mu.Unlock()
	}

	return repo, nil
}

func (h *BareGitHarness) CommitFile(fullName, branch, relPath, content, message string, author ...GitIdentity) (string, error) {
	id := GitIdentity{Name: "Harness Author", Email: "author@custodian.local"}
	if len(author) > 0 && (author[0].Name != "" || author[0].Email != "") {
		id = author[0]
	}
	return h.CommitFiles(fullName, branch, map[string]string{relPath: content}, nil, message, id)
}

func (h *BareGitHarness) CommitFiles(fullName, branch string, files map[string]string, deleted []string, message string, author GitIdentity) (string, error) {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(branch) == "" {
		branch = repo.DefaultBranch
	}
	if author.Name == "" {
		author.Name = "Harness Author"
	}
	if author.Email == "" {
		author.Email = "author@custodian.local"
	}

	workDir, err := os.MkdirTemp("", "custodian-bareharness-work-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	if _, err := h.runGit("", author, "init", "--initial-branch="+branch, workDir); err != nil {
		return "", err
	}

	// If branch already exists in bare repo, fetch and check it out first.
	if _, err := h.runGit(repo.BarePath, author, "rev-parse", "--verify", "refs/heads/"+branch+"^{commit}"); err == nil {
		if _, err := h.runGit(workDir, author, "fetch", "--no-tags", "file://"+repo.BarePath, "refs/heads/"+branch); err != nil {
			return "", err
		}
		if _, err := h.runGit(workDir, author, "checkout", "-B", branch, "FETCH_HEAD"); err != nil {
			return "", err
		}
	}

	for rel, content := range files {
		clean := filepath.Clean(filepath.FromSlash(rel))
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return "", fmt.Errorf("unsafe relative path %q", rel)
		}
		full := filepath.Join(workDir, clean)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return "", err
		}
	}
	for _, rel := range deleted {
		clean := filepath.Clean(filepath.FromSlash(rel))
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return "", fmt.Errorf("unsafe deleted path %q", rel)
		}
		_ = os.Remove(filepath.Join(workDir, clean))
	}

	if _, err := h.runGit(workDir, author, "add", "-A"); err != nil {
		return "", err
	}
	if _, err := h.runGit(workDir, author, "commit", "--allow-empty", "-m", message); err != nil {
		return "", err
	}
	sha, err := h.runGit(workDir, author, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", err
	}
	sha = strings.ToLower(strings.TrimSpace(sha))

	if _, err := h.runGit(workDir, author, "push", "file://"+repo.BarePath, "HEAD:refs/heads/"+branch); err != nil {
		return "", err
	}

	if branch == repo.DefaultBranch {
		_, _ = h.runGit(repo.BarePath, author, "symbolic-ref", "HEAD", "refs/heads/"+branch)
		h.mu.Lock()
		r := h.repos[strings.ToLower(repo.FullName)]
		r.HeadSHA = sha
		h.repos[strings.ToLower(repo.FullName)] = r
		h.mu.Unlock()
	}
	return sha, nil
}

func (h *BareGitHarness) GetHeadSHA(fullName string) (string, error) {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return "", err
	}
	out, err := h.runGit(repo.BarePath, GitIdentity{}, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(out)), nil
}

func (h *BareGitHarness) GetRefSHA(fullName, ref string) (string, error) {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return "", err
	}
	out, err := h.runGit(repo.BarePath, GitIdentity{}, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(out)), nil
}

func (h *BareGitHarness) CreateBranch(fullName, branch, fromRef string) error {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return err
	}
	sha, err := h.GetRefSHA(fullName, fromRef)
	if err != nil {
		return err
	}
	_, err = h.runGit(repo.BarePath, GitIdentity{}, "update-ref", "refs/heads/"+branch, sha)
	return err
}

func (h *BareGitHarness) CreateTag(fullName, tag, targetSHA string) error {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return err
	}
	sha, err := domain.ParseGitSHA(targetSHA)
	if err != nil {
		return err
	}
	_, err = h.runGit(repo.BarePath, GitIdentity{}, "tag", tag, sha)
	return err
}

func (h *BareGitHarness) CreateAnnotatedTag(fullName, tag, targetSHA, message string, tagger GitIdentity) error {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return err
	}
	sha, err := domain.ParseGitSHA(targetSHA)
	if err != nil {
		return err
	}
	if tagger.Name == "" {
		tagger.Name = "Harness Tagger"
	}
	if tagger.Email == "" {
		tagger.Email = "tagger@custodian.local"
	}
	_, err = h.runGit(repo.BarePath, tagger, "tag", "-a", tag, "-m", message, sha)
	return err
}

// ForcePushBranch creates an orphan divergent commit and force-pushes it to branch.
func (h *BareGitHarness) ForcePushBranch(fullName, branch, relPath, content, message string) (string, error) {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(branch) == "" {
		branch = repo.DefaultBranch
	}

	author := GitIdentity{Name: "Force Push", Email: "force@custodian.local"}
	workDir, err := os.MkdirTemp("", "custodian-bareharness-force-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(workDir)

	if _, err := h.runGit("", author, "init", "--initial-branch="+branch, workDir); err != nil {
		return "", err
	}
	clean := filepath.Clean(filepath.FromSlash(relPath))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("unsafe path %q", relPath)
	}
	full := filepath.Join(workDir, clean)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		return "", err
	}
	if _, err := h.runGit(workDir, author, "add", "-A"); err != nil {
		return "", err
	}
	if _, err := h.runGit(workDir, author, "commit", "-m", message); err != nil {
		return "", err
	}
	sha, err := h.runGit(workDir, author, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", err
	}
	sha = strings.ToLower(strings.TrimSpace(sha))

	if _, err := h.runGit(workDir, author, "push", "--force", "file://"+repo.BarePath, "HEAD:refs/heads/"+branch); err != nil {
		return "", err
	}
	return sha, nil
}

func (h *BareGitHarness) DomainRepo(fullName string, classification domain.Classification) (domain.Repository, error) {
	repo, err := h.getRepo(fullName)
	if err != nil {
		return domain.Repository{}, err
	}
	if !classification.IsValid() {
		classification = domain.ClassificationInternal
	}
	return domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   repo.GitHubRepositoryID,
		GitHubInstallationID: repo.InstallationID,
		FullName:             repo.FullName,
		Classification:       classification,
		Enabled:              true,
	}, nil
}

func (h *BareGitHarness) getRepo(fullName string) (BareRepo, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	repo, ok := h.repos[strings.ToLower(strings.TrimSpace(fullName))]
	if !ok {
		return BareRepo{}, fmt.Errorf("repository %q not found in harness", fullName)
	}
	return repo, nil
}

func (h *BareGitHarness) runGit(repoDir string, id GitIdentity, args ...string) (string, error) {
	homeDir, err := os.MkdirTemp("", "custodian-harness-home-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(homeDir)

	var allArgs []string
	if repoDir != "" {
		allArgs = append(checkout.HardenedGitFlags(true), "-C", repoDir)
		allArgs = append(allArgs, args...)
	} else {
		allArgs = append(checkout.HardenedGitFlags(true), args...)
	}

	env := checkout.CleanGitEnv(homeDir, true, false, "", "")
	if id.Name != "" {
		env = append(env, "GIT_AUTHOR_NAME="+id.Name, "GIT_COMMITTER_NAME="+id.Name)
	}
	if id.Email != "" {
		env = append(env, "GIT_AUTHOR_EMAIL="+id.Email, "GIT_COMMITTER_EMAIL="+id.Email)
	}

	cmd := exec.Command("git", allArgs...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %v: %w (%s)", args, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}
