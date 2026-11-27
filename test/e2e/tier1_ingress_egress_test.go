package e2e_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

// --- F-07: Repo registry, classification, model route & read-only ref-pinning (Tier 1: 5 tests) ---

func TestT1_F07_WorkspaceCreationPinsBranchRefTo40HexSHA(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})

	createResp, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	if !m2IsLowerHexLen(createResp.BaseCommit, 40) {
		t.Fatalf("createResp.BaseCommit %q is not 40 lowercase hex", createResp.BaseCommit)
	}
	if createResp.BaseCommit != repo.HeadSHA {
		t.Fatalf("createResp.BaseCommit = %q (want %q)", createResp.BaseCommit, repo.HeadSHA)
	}
	if ws.BaseCommit != repo.HeadSHA {
		t.Fatalf("ws.BaseCommit = %q (want %q)", ws.BaseCommit, repo.HeadSHA)
	}
	if ws.TargetRef != "refs/heads/main" && ws.TargetRef != "main" {
		t.Fatalf("unexpected ws.TargetRef = %q", ws.TargetRef)
	}
}

func TestT1_F07_ShortBranchNameAndNonDefaultBranchPinCorrectly(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	featSHA, err := env.Git().CommitToBranch(repo.FullName, "feat/m2", harness.CommitSpec{
		Files:   map[string]string{"feat.txt": "feature branch content\n"},
		Message: "Add feat/m2 branch",
	})
	if err != nil {
		t.Fatalf("CommitToBranch(feat/m2): %v", err)
	}

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	_, wsShort := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "feat/m2",
		},
	})
	if wsShort.BaseCommit != featSHA {
		t.Fatalf("short branch ref BaseCommit = %q (want %q)", wsShort.BaseCommit, featSHA)
	}

	_, wsFull := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/feat/m2",
		},
	})
	if wsFull.BaseCommit != featSHA {
		t.Fatalf("full branch ref BaseCommit = %q (want %q)", wsFull.BaseCommit, featSHA)
	}
}

func TestT1_F07_UpstreamCommitsAfterPinDoNotShiftWorkspaceBaseCommit(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	sha1 := repo.HeadSHA
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	wsID := m2ResolveWorkspaceID(ws)

	sha2, err := env.Git().CommitToBranch(repo.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"later.txt": "arrived after workspace pin\n"},
		Message: "Advance main after workspace creation",
	})
	if err != nil {
		t.Fatalf("CommitToBranch: %v", err)
	}
	if sha2 == sha1 {
		t.Fatalf("expected sha2 != sha1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	wsAfter, raw, err := env.Client(humanTok).GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	if wsAfter.BaseCommit != sha1 {
		t.Fatalf("workspace base_commit shifted from %s to %s", sha1, wsAfter.BaseCommit)
	}

	dlBytes, dlRaw, err := env.Client(ctrlTok).DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	dlRaw.RequireStatus(t, http.StatusOK)
	entries, err := harness.ExtractTarGz(dlBytes)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}
	for _, e := range entries {
		if strings.TrimPrefix(e.Name, "./") == "later.txt" {
			t.Fatalf("pinned workspace archive unexpectedly contains post-pin file later.txt")
		}
	}
}

func TestT1_F07_AuthorizedClassificationAndModelRouteSucceed(t *testing.T) {
	spec := harness.RepoSeedSpec{
		Owner:         "sec",
		Name:          "confidential-app",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# confidential\n"},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(spec))
	repo, ok := env.Git().Repo("sec/confidential-app")
	if !ok {
		t.Fatalf("seeded repo sec/confidential-app missing")
	}
	m2SeedRepoDB(t, env, repo, "CONFIDENTIAL", true, []string{"restricted-internal-route"}, 5)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
		Agent: &harness.WorkspaceAgentInfo{
			Type:       "coder",
			SessionID:  "s1",
			ModelRoute: "restricted-internal-route",
		},
	})
	if ws.Agent == nil || ws.Agent.ModelRoute != "restricted-internal-route" {
		t.Fatalf("expected authorized model route preserved on workspace, got %+v", ws.Agent)
	}
}

func TestT1_F07_IngressCheckoutUsesReadOnlyAppWithoutWrites(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})

	m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	if pushes := env.GitHub().PushAttempts(); len(pushes) != 0 {
		t.Fatalf("expected 0 push attempts on ingress, got %+v", pushes)
	}
	env.AssertNoSecretLeakInLogs()
}

// --- F-08: Deterministic ingress archive & SnapshotStore (Tier 1: 5 tests) ---

func TestT1_F08_DefaultIngressDeliversShallowPinnedTreeWithoutGitDir(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
		SourceOptions: &harness.WorkspaceSourceOptions{
			IncludeGitMetadata: false,
			IncludeHistory:     false,
		},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dlBytes, raw, err := env.Client(ctrlTok).DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	entries, err := harness.ExtractTarGz(dlBytes)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}
	foundFiles := make(map[string]string)
	for _, e := range entries {
		norm := strings.TrimPrefix(e.Name, "./")
		if norm == ".git" || strings.HasPrefix(norm, ".git/") {
			t.Fatalf("shallow ingress archive unexpectedly includes .git entry %q", e.Name)
		}
		if e.Typeflag == tar.TypeReg {
			foundFiles[norm] = string(e.Body)
		}
	}
	if foundFiles["README.md"] != "# acme/service\n" {
		t.Fatalf("README.md mismatch in shallow archive: %q", foundFiles["README.md"])
	}
	if !strings.Contains(foundFiles["main.go"], "package main") {
		t.Fatalf("main.go missing or corrupted in shallow archive: %q", foundFiles["main.go"])
	}
	env.Snapshots().AssertArchiveNoSecretLeak(t, dlBytes,
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	)
}

func TestT1_F08_IngressArchiveIsByteDeterministicForSameCommit(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	req := harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
		SourceOptions: &harness.WorkspaceSourceOptions{
			IncludeGitMetadata: false,
			IncludeHistory:     false,
		},
	}
	_, ws1 := m2CreateReadyWorkspace(t, env, humanTok, req)
	_, ws2 := m2CreateReadyWorkspace(t, env, humanTok, req)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	desc1, r1, err := ctrlClient.GetWorkspaceSource(ctx, m2ResolveWorkspaceID(ws1))
	if err != nil {
		t.Fatalf("GetWorkspaceSource(ws1): %v", err)
	}
	r1.RequireStatus(t, http.StatusOK)

	desc2, r2, err := ctrlClient.GetWorkspaceSource(ctx, m2ResolveWorkspaceID(ws2))
	if err != nil {
		t.Fatalf("GetWorkspaceSource(ws2): %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)

	if desc1.Artifact.SHA256 != desc2.Artifact.SHA256 {
		t.Fatalf("ingress archive SHA256 not deterministic: %s != %s", desc1.Artifact.SHA256, desc2.Artifact.SHA256)
	}

	gz1, dr1, err := ctrlClient.DownloadWorkspaceSource(ctx, m2ResolveWorkspaceID(ws1))
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource(ws1): %v", err)
	}
	dr1.RequireStatus(t, http.StatusOK)

	gz2, dr2, err := ctrlClient.DownloadWorkspaceSource(ctx, m2ResolveWorkspaceID(ws2))
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource(ws2): %v", err)
	}
	dr2.RequireStatus(t, http.StatusOK)

	if !bytes.Equal(gz1, gz2) {
		t.Fatalf("ingress archive bytes differ for identical pinned commit (%d vs %d bytes)", len(gz1), len(gz2))
	}
}

func TestT1_F08_SanitisedGitMetadataStripsHooksAndCredentials(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
		SourceOptions: &harness.WorkspaceSourceOptions{
			IncludeGitMetadata: true,
			IncludeHistory:     false,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gz, raw, err := env.Client(ctrlTok).DownloadWorkspaceSource(ctx, m2ResolveWorkspaceID(ws))
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	entries, err := harness.ExtractTarGz(gz)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}
	hasGitHEAD := false
	for _, e := range entries {
		norm := strings.TrimPrefix(e.Name, "./")
		if norm == ".git/HEAD" {
			hasGitHEAD = true
		}
		if norm == ".git/config" {
			lower := strings.ToLower(string(e.Body))
			for _, bad := range []string{"fsmonitor", "sshcommand", "credential", "filter.", "alias.", "x-access-token"} {
				if strings.Contains(lower, bad) {
					t.Fatalf("sanitised .git/config contains forbidden key/token %q", bad)
				}
			}
		}
	}
	if !hasGitHEAD {
		t.Fatalf("expected .git/HEAD in include_git_metadata=true archive")
	}
	env.Snapshots().AssertArchiveGitSanitised(t, gz)
	env.Snapshots().AssertArchiveNoSecretLeak(t, gz,
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	)
}

func TestT1_F08_AuthorizedFullHistoryDeliversSanitisedHistory(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	if _, err := env.Git().CommitToBranch(repo.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"c2.txt": "commit 2\n"},
		Message: "Second commit",
	}); err != nil {
		t.Fatalf("CommitToBranch #2: %v", err)
	}
	if _, err := env.Git().CommitToBranch(repo.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"c3.txt": "commit 3\n"},
		Message: "Third commit",
	}); err != nil {
		t.Fatalf("CommitToBranch #3: %v", err)
	}

	histTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "history-reader-1",
		Email:   "history-reader@example.com",
		Groups:  []string{"engineering", "history-readers"},
		Roles:   []string{"human", "developer", "history_reader"},
		Scope:   "repo:history",
	})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, histTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
		SourceOptions: &harness.WorkspaceSourceOptions{
			IncludeGitMetadata: true,
			IncludeHistory:     true,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gz, raw, err := env.Client(ctrlTok).DownloadWorkspaceSource(ctx, m2ResolveWorkspaceID(ws))
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	env.Snapshots().AssertArchiveGitSanitised(t, gz)
	env.Snapshots().AssertArchiveNoSecretLeak(t, gz,
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
	)

	entries, err := harness.ExtractTarGz(gz)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}
	unpackDir := t.TempDir()
	hasGitObjects := false
	for _, e := range entries {
		norm := filepath.Clean(strings.TrimPrefix(e.Name, "./"))
		if norm == "." || strings.HasPrefix(norm, "..") || filepath.IsAbs(norm) {
			continue
		}
		if strings.HasPrefix(filepath.ToSlash(norm), ".git/objects") {
			hasGitObjects = true
		}
		dst := filepath.Join(unpackDir, norm)
		if e.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				t.Fatalf("mkdir %q: %v", dst, err)
			}
		} else if e.Typeflag == tar.TypeReg {
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				t.Fatalf("mkdir parent %q: %v", dst, err)
			}
			if err := os.WriteFile(dst, e.Body, 0o644); err != nil {
				t.Fatalf("write %q: %v", dst, err)
			}
		}
	}
	if !hasGitObjects {
		t.Fatalf("expected .git/objects in full-history archive")
	}

	cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "rev-list", "--count", "HEAD")
	cmd.Dir = unpackDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git rev-list --count HEAD failed: %v\n%s", err, string(out))
	}
	var count int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count); err != nil || count < 3 {
		t.Fatalf("expected full history >= 3 commits, got %q (err=%v)", strings.TrimSpace(string(out)), err)
	}
}

func TestT1_F08_SnapshotStorePersistsImmutableSourceArtifact(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{
			Provider:     "github",
			RepositoryID: repo.GitHubRepoID,
			Ref:          "refs/heads/main",
		},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	desc, raw, err := ctrlClient.GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	gzBytes, dlRaw, err := ctrlClient.DownloadWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource: %v", err)
	}
	dlRaw.RequireStatus(t, http.StatusOK)

	if got := harness.SHA256Hex(gzBytes); got != desc.Artifact.SHA256 {
		t.Fatalf("downloaded sha256 %s != descriptor %s", got, desc.Artifact.SHA256)
	}
	if int64(len(gzBytes)) != desc.Artifact.SizeBytes {
		t.Fatalf("downloaded size %d != descriptor %d", len(gzBytes), desc.Artifact.SizeBytes)
	}
	obj, err := env.Snapshots().FindBySHA256(desc.Artifact.SHA256)
	if err != nil {
		t.Fatalf("FindBySHA256(%s): %v", desc.Artifact.SHA256, err)
	}
	if obj.SizeBytes != int64(len(gzBytes)) {
		t.Fatalf("stored size %d != downloaded %d", obj.SizeBytes, len(gzBytes))
	}
}

// --- F-09: Upload-only scoped capability & controller provenance (Tier 1: 5 tests) ---

func TestT1_F09_UploadCapabilityIssuedWithExactScopeMetadata(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	capResp, raw, err := env.Client(ctrlTok).RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	if capResp.Token == "" {
		t.Fatalf("expected non-empty capability token")
	}
	if capResp.WorkspaceID != wsID {
		t.Fatalf("cap.WorkspaceID = %q (want %q)", capResp.WorkspaceID, wsID)
	}
	if capResp.Generation != ws.Generation {
		t.Fatalf("cap.Generation = %d (want %d)", capResp.Generation, ws.Generation)
	}
	if capResp.MaxBytes <= 0 {
		t.Fatalf("cap.MaxBytes = %d (want > 0)", capResp.MaxBytes)
	}
	if !capResp.ExpiresAt.After(time.Now()) {
		t.Fatalf("cap.ExpiresAt %s is not in the future", capResp.ExpiresAt)
	}
	if capResp.UploadURL == "" {
		t.Fatalf("expected non-empty cap.UploadURL")
	}
}

func TestT1_F09_ValidUploadCapabilityStoresEgressSnapshot(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, wantSHA := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# uploaded\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	artifactID, gotSHA := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)
	harness.AssertUUIDv7(t, artifactID)
	if gotSHA != wantSHA {
		t.Fatalf("uploaded sha256 = %q (want %q)", gotSHA, wantSHA)
	}
	if _, err := env.Snapshots().FindBySHA256(wantSHA); err != nil {
		t.Fatalf("uploaded snapshot not found in SnapshotStore: %v", err)
	}
}

func TestT1_F09_ControllerWorkloadIdentityRecordedAsCaptureProvenance(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "human-prov-1", Email: "hp1@example.com"})
	ctrlSubject := "spiffe://custodian.local/ns/sandbox/sa/trusted-runtime-controller"
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER", Subject: ctrlSubject})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# provenance\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "ctrl-provenance", &harness.Provenance{
		Type:          "agent_assisted",
		CaptureMethod: "frozen_filesystem",
	})
	if prop.Owner == nil || ws.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("proposal owner (%+v) != human workspace owner (%+v)", prop.Owner, ws.Owner)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(
		`SELECT p.kind, coalesce(p.subject, '')
		 FROM artifacts a
		 JOIN principals p ON p.id = a.uploaded_by
		 WHERE a.id = %s::uuid`,
		m2SQLLiteral(prop.SnapshotArtifactID),
	))
	if err != nil {
		t.Fatalf("query artifacts.uploaded_by: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 uploaded_by principal row for artifact %s, got %d", prop.SnapshotArtifactID, len(rows))
	}
	if rows[0][0] != "SERVICE" {
		t.Fatalf("uploaded_by principal kind = %q (want SERVICE)", rows[0][0])
	}
	if rows[0][1] != ctrlSubject {
		t.Fatalf("uploaded_by principal subject = %q (want %q)", rows[0][1], ctrlSubject)
	}
}

func TestT1_F09_ExactMaxBytesBoundaryUploadSucceeds(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	capResp, capRaw, err := ctrlClient.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{MaxBytes: 8192})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	if capResp.MaxBytes <= 0 {
		t.Fatalf("expected capResp.MaxBytes > 0, got %d", capResp.MaxBytes)
	}

	var gz []byte
	var sha string
	if capResp.MaxBytes <= 64<<20 {
		gz, sha = m2BuildExactSizeTarGz(t, capResp.MaxBytes)
		if int64(len(gz)) != capResp.MaxBytes {
			t.Fatalf("expected exact boundary archive %d bytes, got %d", capResp.MaxBytes, len(gz))
		}
	} else {
		// Server enforced >64 MiB default max_bytes; upload a substantial multi-MB valid archive within memory bounds.
		t.Logf("capResp.MaxBytes=%d exceeds 64MiB in-memory cap; testing substantial >=1MiB valid archive within bound", capResp.MaxBytes)
		gz, sha = m2BuildExactSizeTarGz(t, 4<<20)
		if len(gz) < 1<<20 || int64(len(gz)) > capResp.MaxBytes {
			t.Fatalf("expected substantial archive in [1MiB, %d], got %d", capResp.MaxBytes, len(gz))
		}
	}
	if _, err := harness.ExtractTarGz(gz); err != nil {
		t.Fatalf("boundary archive is not valid tar.gz: %v", err)
	}

	upRaw, err := ctrlClient.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, gz)
	if err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)

	var upBody struct {
		ArtifactID string `json:"artifact_id"`
		ID         string `json:"id"`
	}
	if err := json.Unmarshal(upRaw.Body, &upBody); err != nil {
		t.Fatalf("decode upload body: %v", err)
	}
	artifactID := upBody.ArtifactID
	if artifactID == "" {
		artifactID = upBody.ID
	}
	harness.AssertUUIDv7(t, artifactID)

	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "boundary-upload",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	op, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED, got %q (%s)", op.Status, op.LastError)
	}
}

func TestT1_F09_DistinctWorkspacesReceiveDistinctCapabilities(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws1 := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	_, ws2 := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	ws1ID := m2ResolveWorkspaceID(ws1)
	ws2ID := m2ResolveWorkspaceID(ws2)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	cap1, r1, err := ctrlClient.RequestUploadCapability(ctx, ws1ID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability(ws1): %v", err)
	}
	r1.RequireStatus(t, http.StatusOK)

	cap2, r2, err := ctrlClient.RequestUploadCapability(ctx, ws2ID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability(ws2): %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)

	if cap1.Token == cap2.Token {
		t.Fatalf("distinct workspaces received identical upload capability tokens")
	}
	if cap1.WorkspaceID != ws1ID || cap2.WorkspaceID != ws2ID {
		t.Fatalf("capability workspace mismatch: cap1=%s (want %s), cap2=%s (want %s)", cap1.WorkspaceID, ws1ID, cap2.WorkspaceID, ws2ID)
	}
}

// --- F-10: Strict egress archive parser & limits (Tier 1: 5 tests) ---

func TestT1_F10_ValidNestedDirectoriesAndExecutableFilesAccepted(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "pkg/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "pkg/sub/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "pkg/sub/code.go", Mode: 0o644, Body: []byte("package sub\n\nfunc Answer() int { return 42 }\n")},
		{Name: "scripts/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "scripts/build.sh", Mode: 0o755, Body: []byte("#!/bin/sh\necho build\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "nested-exec", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	seen := make(map[string]string)
	for _, p := range diff.Paths {
		seen[p.Path] = p.ChangeType
	}
	if seen["pkg/sub/code.go"] != "ADDED" || seen["scripts/build.sh"] != "ADDED" {
		t.Fatalf("expected nested files ADDED, got paths=%+v", diff.Paths)
	}
}

func TestT1_F10_DistinctValidUnicodeNFCPortablePathsAccepted(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "docs/caf\u00e9.txt", Body: []byte("menu\n")},
		{Name: "docs/na\u00efve.md", Body: []byte("notes\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "unicode-nfc", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	seen := make(map[string]bool)
	for _, p := range diff.Paths {
		seen[p.Path] = true
	}
	if !seen["docs/caf\u00e9.txt"] || !seen["docs/na\u00efve.md"] {
		t.Fatalf("expected both UTF-8 NFC paths in diff, got %+v", diff.Paths)
	}
}

func TestT1_F10_ZeroByteFileAndFileDeletionHandledCleanly(t *testing.T) {
	spec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "zero-del",
		DefaultBranch: "main",
		Files: map[string]string{
			"README.md":    "# zero-del\n",
			"obsolete.txt": "to be deleted\n",
		},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(spec))
	repo, ok := env.Git().Repo("acme/zero-del")
	if !ok {
		t.Fatalf("seeded repo missing")
	}
	m2SeedRepoDB(t, env, repo, "INTERNAL", true, []string{m2DefaultModelRoute}, 10)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# zero-del\n")},
		{Name: "marker.empty", Body: []byte{}},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "zero-byte-and-delete", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	byPath := make(map[string]harness.ChangedFile)
	for _, p := range diff.Paths {
		byPath[p.Path] = p
	}
	if cf, ok := byPath["marker.empty"]; !ok || cf.ChangeType != "ADDED" || cf.SizeBytes != 0 {
		t.Fatalf("expected marker.empty ADDED size=0, got %+v", cf)
	}
	if cf, ok := byPath["obsolete.txt"]; !ok || cf.ChangeType != "DELETED" {
		t.Fatalf("expected obsolete.txt DELETED, got %+v", cf)
	}
}

func TestT1_F10_GoldenCleanSnapshotMatchesExpectedPatch(t *testing.T) {
	root := m2FindRepoRoot(t)
	goldenDir := filepath.Join(root, "test", "e2e", "fixtures", "golden")
	readmeBytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_tree", "README.md"))
	if err != nil {
		t.Fatalf("read golden README.md: %v", err)
	}
	goldenGZ, err := os.ReadFile(filepath.Join(goldenDir, "clean_snapshot.tar.gz"))
	if err != nil {
		t.Fatalf("read golden clean_snapshot.tar.gz: %v", err)
	}
	goldenSHABytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_snapshot.sha256"))
	if err != nil {
		t.Fatalf("read golden clean_snapshot.sha256: %v", err)
	}
	wantSHA := strings.TrimSpace(string(goldenSHABytes))
	if gotSHA := harness.SHA256Hex(goldenGZ); gotSHA != wantSHA {
		t.Fatalf("golden archive sha256 mismatch: got %s, want %s", gotSHA, wantSHA)
	}
	expectedPatchBytes, err := os.ReadFile(filepath.Join(goldenDir, "expected_diff_hello.patch"))
	if err != nil {
		t.Fatalf("read expected_diff_hello.patch: %v", err)
	}

	spec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "golden-repo",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": string(readmeBytes)},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(spec))
	repo, ok := env.Git().Repo("acme/golden-repo")
	if !ok {
		t.Fatalf("seeded golden repo missing")
	}
	m2SeedRepoDB(t, env, repo, "INTERNAL", true, []string{m2DefaultModelRoute}, 10)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, goldenGZ, "golden-snapshot", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	if len(diff.Paths) != 1 || diff.Paths[0].Path != "pkg/hello/hello.go" || diff.Paths[0].ChangeType != "ADDED" {
		t.Fatalf("expected single ADDED path pkg/hello/hello.go, got %+v", diff.Paths)
	}
	for _, needle := range []string{
		"diff --git a/pkg/hello/hello.go b/pkg/hello/hello.go",
		"+func Greeting(name string) string {",
		`+		return "hello, custodian"`,
	} {
		if !strings.Contains(diff.UnifiedDiff, needle) {
			t.Fatalf("golden UnifiedDiff missing %q:\ngot:\n%s\nwant snippet from:\n%s", needle, diff.UnifiedDiff, string(expectedPatchBytes))
		}
	}
}

func TestT1_F10_DotSlashPrefixedArchiveEntriesNormalizedSafely(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "./README.md", Body: []byte("# acme/service\n")},
		{Name: "./main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "./pkg/norm/a.go", Body: []byte("package norm\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "dot-slash-norm", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	found := false
	for _, p := range diff.Paths {
		if strings.HasPrefix(p.Path, "./") || strings.Contains(p.Path, "..") {
			t.Fatalf("unnormalized path in diff: %q", p.Path)
		}
		if p.Path == "pkg/norm/a.go" && p.ChangeType == "ADDED" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected normalized pkg/norm/a.go ADDED in diff paths: %+v", diff.Paths)
	}
}

// --- F-11: Clean base reconstruction & canonical digests (Tier 1: 5 tests) ---

func TestT1_F11_CleanReconstructionProducesCanonicalDigests(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# modified readme\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "pkg/a.go", Body: []byte("package pkg\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "canonical-digests", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	if !m2IsLowerHexLen(diff.TreeDigest, 40) && !m2IsLowerHexLen(diff.TreeDigest, 64) {
		t.Fatalf("invalid TreeDigest %q (want 40 or 64 lowercase hex)", diff.TreeDigest)
	}
	if !m2IsLowerHexLen(diff.DiffDigest, 64) {
		t.Fatalf("invalid DiffDigest %q", diff.DiffDigest)
	}
	if !m2IsLowerHexLen(diff.PublicationManifestDigest, 64) {
		t.Fatalf("invalid PublicationManifestDigest %q", diff.PublicationManifestDigest)
	}
	if prop.TreeDigest != diff.TreeDigest || prop.DiffDigest != diff.DiffDigest ||
		prop.PublicationManifestDigest != diff.PublicationManifestDigest {
		t.Fatalf("proposal digests (%s, %s, %s) != diff digests (%s, %s, %s)",
			prop.TreeDigest, prop.DiffDigest, prop.PublicationManifestDigest,
			diff.TreeDigest, diff.DiffDigest, diff.PublicationManifestDigest)
	}
	harness.AssertUUIDv7(t, prop.CanonicalArtifactID)
	harness.AssertUUIDv7(t, prop.ManifestArtifactID)
}

func TestT1_F11_CanonicalDigestsInvariantToTarMtimeUIDAndOrder(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	entries := []harness.TarEntry{
		{Name: "README.md", Body: []byte("# invariant\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() { println(\"hi\") }\n")},
		{Name: "pkg/a.go", Body: []byte("package pkg\n")},
	}
	gz1, sha1 := harness.BuildTarGz(entries)
	gz2, sha2 := harness.BuildTarGzWithVaryingMeta(entries, time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC), 1001, 1001, true)
	if sha1 == sha2 {
		t.Fatalf("expected different tar.gz SHA256 for varied metadata/order")
	}

	prop1, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz1, "meta-1", nil)
	prop2, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz2, "meta-2", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff1, r1, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop1))
	if err != nil {
		t.Fatalf("GetProposalDiff(1): %v", err)
	}
	r1.RequireStatus(t, http.StatusOK)

	diff2, r2, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop2))
	if err != nil {
		t.Fatalf("GetProposalDiff(2): %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)

	if diff1.TreeDigest != diff2.TreeDigest {
		t.Fatalf("TreeDigest varied with tar metadata: %s vs %s", diff1.TreeDigest, diff2.TreeDigest)
	}
	if diff1.DiffDigest != diff2.DiffDigest {
		t.Fatalf("DiffDigest varied with tar metadata: %s vs %s", diff1.DiffDigest, diff2.DiffDigest)
	}
	if diff1.PublicationManifestDigest != diff2.PublicationManifestDigest {
		t.Fatalf("PublicationManifestDigest varied with tar metadata: %s vs %s", diff1.PublicationManifestDigest, diff2.PublicationManifestDigest)
	}
	if diff1.UnifiedDiff != diff2.UnifiedDiff {
		t.Fatalf("UnifiedDiff varied with tar metadata")
	}
}

func TestT1_F11_ReconstructsAgainstPinnedBaseCommitNotFloatingHead(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	sha1 := repo.HeadSHA
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	if _, err := env.Git().CommitToBranch(repo.FullName, "main", harness.CommitSpec{
		Files:   map[string]string{"upstream.txt": "upstream only\n"},
		Message: "Upstream commit after workspace pin",
	}); err != nil {
		t.Fatalf("CommitToBranch: %v", err)
	}

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "feature.go", Body: []byte("package main\n\nfunc feat() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "pinned-reconstruct", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	if diff.BaseCommit != sha1 {
		t.Fatalf("diff.BaseCommit = %s (want pinned %s)", diff.BaseCommit, sha1)
	}
	seenFeat := false
	for _, p := range diff.Paths {
		if p.Path == "upstream.txt" {
			t.Fatalf("reconstruct diff leaked post-pin upstream.txt: %+v", p)
		}
		if p.Path == "feature.go" && p.ChangeType == "ADDED" {
			seenFeat = true
		}
	}
	if !seenFeat {
		t.Fatalf("expected feature.go ADDED in diff, got %+v", diff.Paths)
	}
}

func TestT1_F11_CanonicalDiffCategorizesAddedModifiedDeleted(t *testing.T) {
	spec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "diff-cats",
		DefaultBranch: "main",
		Files: map[string]string{
			"README.md":     "v1\n",
			"unchanged.txt": "keep\n",
			"gone.txt":      "bye\n",
		},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(spec))
	repo, ok := env.Git().Repo("acme/diff-cats")
	if !ok {
		t.Fatalf("seeded repo missing")
	}
	m2SeedRepoDB(t, env, repo, "INTERNAL", true, []string{m2DefaultModelRoute}, 10)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("v2\n")},
		{Name: "unchanged.txt", Body: []byte("keep\n")},
		{Name: "new.txt", Body: []byte("hi\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "diff-categories", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	cats := make(map[string]string)
	for _, p := range diff.Paths {
		cats[p.Path] = p.ChangeType
	}
	if cats["README.md"] != "MODIFIED" {
		t.Fatalf("README.md change_type = %q (want MODIFIED)", cats["README.md"])
	}
	if cats["new.txt"] != "ADDED" {
		t.Fatalf("new.txt change_type = %q (want ADDED)", cats["new.txt"])
	}
	if cats["gone.txt"] != "DELETED" {
		t.Fatalf("gone.txt change_type = %q (want DELETED)", cats["gone.txt"])
	}
	if _, exists := cats["unchanged.txt"]; exists {
		t.Fatalf("unchanged.txt unexpectedly present in diff paths: %+v", diff.Paths)
	}
	for _, token := range []string{"-v1", "+v2", "+hi", "-bye"} {
		if !strings.Contains(diff.UnifiedDiff, token) {
			t.Fatalf("UnifiedDiff missing %q:\n%s", token, diff.UnifiedDiff)
		}
	}
}

func TestT1_F11_CanonicalTreeDiffAndManifestPersistedInStore(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# persisted\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "persisted-artifacts", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)

	artifactIDs := []string{prop.CanonicalArtifactID, prop.ManifestArtifactID}
	if diff.DiffArtifactID != "" {
		artifactIDs = append(artifactIDs, diff.DiffArtifactID)
	}
	for _, aid := range artifactIDs {
		harness.AssertUUIDv7(t, aid)
		rows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT sha256 FROM artifacts WHERE id = %s::uuid`, m2SQLLiteral(aid)))
		if err != nil || len(rows) != 1 {
			t.Fatalf("artifact %s missing in DB: rows=%v err=%v", aid, rows, err)
		}
		obj, err := env.Snapshots().FindBySHA256(rows[0][0])
		if err != nil {
			t.Fatalf("artifact %s (sha=%s) missing in SnapshotStore: %v", aid, rows[0][0], err)
		}
		if aid == prop.ManifestArtifactID {
			manifestBytes, err := env.Snapshots().ReadBytes(*obj)
			if err != nil {
				t.Fatalf("ReadBytes(manifest): %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(manifestBytes, &m); err != nil {
				t.Fatalf("manifest artifact is not valid JSON: %v\n%s", err, string(manifestBytes))
			}
			if m["tree_digest"] != diff.TreeDigest || m["diff_digest"] != diff.DiffDigest || m["base_commit"] != diff.BaseCommit {
				t.Fatalf("manifest artifact digest mismatch: %+v vs diff %+v", m, diff)
			}
		}
	}
}

// --- F-12: Proposal lifecycle & optimistic versioning (Tier 1: 5 tests) ---

func TestT1_F12_ProposalLifecycleProgressesCapturedToReconstructed(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# lifecycle\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "lifecycle-progression",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	if subResp.Status != "CAPTURED" && subResp.Status != "RECONSTRUCTING" {
		t.Fatalf("initial SubmitProposal status = %q (want CAPTURED or RECONSTRUCTING)", subResp.Status)
	}
	if subResp.Version < 1 {
		t.Fatalf("initial SubmitProposal version = %d (want >= 1)", subResp.Version)
	}

	propID := m2ResolveProposalID(subResp)
	op, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "SUCCEEDED" {
		t.Fatalf("reconstruct op status = %q (%s)", op.Status, op.LastError)
	}

	prop, propRaw, err := ctrlClient.GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	propRaw.RequireStatus(t, http.StatusOK)
	if prop.Status != "RECONSTRUCTED" {
		t.Fatalf("post-reconstruct status = %q (want RECONSTRUCTED)", prop.Status)
	}
	if prop.Version <= subResp.Version {
		t.Fatalf("expected proposal version to increment after reconstruction: before=%d after=%d", subResp.Version, prop.Version)
	}
}

func TestT1_F12_GetProposalDiffReturnsCanonicalPayloadToOwnerAndController(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# owner and controller diff\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "owner-ctrl-diff", nil)
	propID := m2ResolveProposalID(prop)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dOwner, rOwner, err := env.Client(humanTok).GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("owner GetProposalDiff: %v", err)
	}
	rOwner.RequireStatus(t, http.StatusOK)

	dCtrl, rCtrl, err := env.Client(ctrlTok).GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("controller GetProposalDiff: %v", err)
	}
	rCtrl.RequireStatus(t, http.StatusOK)

	if dOwner.TreeDigest != dCtrl.TreeDigest || dOwner.DiffDigest != dCtrl.DiffDigest ||
		dOwner.PublicationManifestDigest != dCtrl.PublicationManifestDigest || dOwner.UnifiedDiff != dCtrl.UnifiedDiff {
		t.Fatalf("owner vs controller ProposalDiff mismatch: %+v vs %+v", dOwner, dCtrl)
	}
}

func TestT1_F12_IdempotencyKeyReplaysSubmitProposalWithoutDuplicate(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# idempotent\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	idemKey := harness.NewTestUUIDv7()
	req := harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "idempotent-proposal",
	}

	r1, raw1, err := ctrlClient.SubmitProposal(ctx, wsID, req, harness.WithIdempotencyKey(idemKey))
	if err != nil {
		t.Fatalf("SubmitProposal #1: %v", err)
	}
	raw1.RequireStatus(t, http.StatusAccepted)

	r2, raw2, err := ctrlClient.SubmitProposal(ctx, wsID, req, harness.WithIdempotencyKey(idemKey))
	if err != nil {
		t.Fatalf("SubmitProposal #2: %v", err)
	}
	raw2.RequireAnyStatus(t, http.StatusAccepted, http.StatusOK)

	if m2ResolveProposalID(r1) != m2ResolveProposalID(r2) {
		t.Fatalf("idempotent replay returned different proposal IDs: %s vs %s", m2ResolveProposalID(r1), m2ResolveProposalID(r2))
	}
	if r1.OperationID != r2.OperationID {
		t.Fatalf("idempotent replay returned different operation IDs: %s vs %s", r1.OperationID, r2.OperationID)
	}

	rows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT count(*) FROM proposals WHERE workspace_id = %s::uuid`, m2SQLLiteral(wsID)))
	if err != nil || len(rows) != 1 || rows[0][0] != "1" {
		t.Fatalf("expected exactly 1 proposal row for workspace %s, got rows=%v err=%v", wsID, rows, err)
	}
}

func TestT1_F12_MultipleProposalsUnderOneWorkspaceStayIndependent(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz1, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# proposal one\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	gz2, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# proposal two\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})

	prop1, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz1, "prop-1", nil)
	time.Sleep(5 * time.Millisecond)
	prop2, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz2, "prop-2", nil)

	id1 := m2ResolveProposalID(prop1)
	id2 := m2ResolveProposalID(prop2)
	if id1 == id2 {
		t.Fatalf("expected distinct proposal IDs, got %s", id1)
	}
	harness.AssertUUIDv7Monotonic(t, []string{id1, id2})
	if prop1.PublicationManifestDigest == prop2.PublicationManifestDigest {
		t.Fatalf("expected distinct manifest digests for distinct edits, got %s", prop1.PublicationManifestDigest)
	}
}

func TestT1_F12_EvaluateProposalAcceptsMatchingExpectedVersion(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# evaluate version\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "matching-version", nil)
	propID := m2ResolveProposalID(prop)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	evalResp, raw, err := env.Client(ctrlTok).EvaluateProposal(ctx, propID, harness.EvaluateReq{
		ExpectedVersion: prop.Version,
	}, harness.WithHeader("If-Match", fmt.Sprintf("%d", prop.Version)))
	if err != nil {
		t.Fatalf("EvaluateProposal: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	harness.AssertUUIDv7(t, evalResp.OperationID)
	if evalResp.Version < prop.Version {
		t.Fatalf("expected version >= %d, got %d", prop.Version, evalResp.Version)
	}
}
