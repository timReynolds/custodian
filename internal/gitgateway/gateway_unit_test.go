package gitgateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

// --- In-memory test doubles for fast -short unit tests ---

type memPrincipalStore struct {
	mu          sync.Mutex
	byID        map[uuid.UUID]domain.Principal
	byIssSub    map[string]uuid.UUID
	groupsByID  map[uuid.UUID][]string
	upsertCalls int
}

func newMemPrincipalStore() *memPrincipalStore {
	return &memPrincipalStore{
		byID:       make(map[uuid.UUID]domain.Principal),
		byIssSub:   make(map[string]uuid.UUID),
		groupsByID: make(map[uuid.UUID][]string),
	}
}

func (m *memPrincipalStore) groupCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.groupsByID)
}

func (m *memPrincipalStore) seed(p domain.Principal, groups []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[p.ID] = p
	m.byIssSub[p.Issuer+"\x00"+p.Subject] = p.ID
	m.groupsByID[p.ID] = append([]string(nil), groups...)
}

func (m *memPrincipalStore) GetByID(_ context.Context, id uuid.UUID) (domain.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byID[id]
	if !ok {
		return domain.Principal{}, domain.NotFound("NOT_FOUND", "principal not found")
	}
	return p, nil
}

func (m *memPrincipalStore) GetByIssuerSubject(_ context.Context, issuer, subject string) (domain.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byIssSub[issuer+"\x00"+subject]
	if !ok {
		return domain.Principal{}, domain.NotFound("NOT_FOUND", "principal not found")
	}
	return m.byID[id], nil
}

func (m *memPrincipalStore) Upsert(_ context.Context, p domain.Principal) (domain.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byIssSub[p.Issuer+"\x00"+p.Subject]; ok {
		existing := m.byID[id]
		if p.DisplayName != "" {
			existing.DisplayName = p.DisplayName
		}
		if p.VerifiedEmail != "" {
			existing.VerifiedEmail = p.VerifiedEmail
		}
		m.byID[id] = existing
		return existing, nil
	}
	if p.ID == uuid.Nil {
		p.ID, _ = domain.NewID()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	m.byID[p.ID] = p
	m.byIssSub[p.Issuer+"\x00"+p.Subject] = p.ID
	return p, nil
}

func (m *memPrincipalStore) UpsertPrincipal(_ context.Context, arg persistence.UpsertPrincipalParams) (persistence.PrincipalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertCalls++
	id := arg.ID
	if existingID, ok := m.byIssSub[arg.Issuer+"\x00"+arg.Subject]; ok {
		id = existingID
	}
	if id == uuid.Nil {
		id, _ = domain.NewID()
	}
	p := domain.Principal{
		ID:            id,
		Kind:          arg.Kind,
		Issuer:        arg.Issuer,
		Subject:       arg.Subject,
		DisplayName:   arg.DisplayName,
		VerifiedEmail: arg.VerifiedEmail,
		CreatedAt:     arg.CreatedAt,
	}
	m.byID[id] = p
	if arg.Issuer != "" && arg.Subject != "" {
		m.byIssSub[arg.Issuer+"\x00"+arg.Subject] = id
	}
	if len(arg.Groups) > 0 {
		m.groupsByID[id] = append([]string(nil), arg.Groups...)
	}
	return persistence.PrincipalRow{
		ID:     id,
		Kind:   arg.Kind,
		Groups: append([]string(nil), m.groupsByID[id]...),
	}, nil
}

func (m *memPrincipalStore) LookupBySSHPrincipals(_ context.Context, candidates []string) (persistence.PrincipalRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.byID {
		if slices.Contains(candidates, p.Subject) || (p.VerifiedEmail != "" && slices.Contains(candidates, p.VerifiedEmail)) {
			iss := p.Issuer
			sub := p.Subject
			dn := p.DisplayName
			em := p.VerifiedEmail
			return persistence.PrincipalRow{
				ID:            p.ID,
				Kind:          p.Kind,
				Issuer:        &iss,
				Subject:       &sub,
				DisplayName:   &dn,
				VerifiedEmail: &em,
				Groups:        append([]string(nil), m.groupsByID[p.ID]...),
				CreatedAt:     p.CreatedAt,
			}, nil
		}
	}
	return persistence.PrincipalRow{}, domain.Unauthorized("UNKNOWN_SSH_PRINCIPAL", "ssh principal is not registered")
}

type memRepoLookup struct {
	mu       sync.Mutex
	byName   map[string]persistence.RepositoryRow
	byRemote map[string]persistence.RepositoryRow
	err      error
}

func newMemRepoLookup() *memRepoLookup {
	return &memRepoLookup{
		byName:   make(map[string]persistence.RepositoryRow),
		byRemote: make(map[string]persistence.RepositoryRow),
	}
}

func (l *memRepoLookup) add(row persistence.RepositoryRow) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.byName[row.FullName] = row
	if row.GitRemoteURL != nil && *row.GitRemoteURL != "" {
		l.byRemote[*row.GitRemoteURL] = row
	}
}

func (l *memRepoLookup) GetRepositoryByGitRemoteURL(_ context.Context, remoteURL string) (persistence.RepositoryRow, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return persistence.RepositoryRow{}, l.err
	}
	r, ok := l.byRemote[remoteURL]
	if !ok {
		return persistence.RepositoryRow{}, domain.NotFound("NOT_FOUND", "repository not found")
	}
	return r, nil
}

func (l *memRepoLookup) GetRepositoryByFullName(_ context.Context, fullName string) (persistence.RepositoryRow, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return persistence.RepositoryRow{}, l.err
	}
	r, ok := l.byName[fullName]
	if !ok {
		return persistence.RepositoryRow{}, domain.NotFound("NOT_FOUND", "repository not found")
	}
	return r, nil
}

// --- Bare Git + LFS Mock Upstream HTTP Server ---

type mockUpstreamGitServer struct {
	mu               sync.Mutex
	server           *httptest.Server
	repos            map[string]string // owner/repo -> bare git dir
	lfsObjects       map[string]map[string][]byte
	infoRefsCalls    int
	uploadPackCalls  int
	receivePackCalls int
	receivePackBytes int64
	lfsBatchCalls    int
	lfsUploadBytes   int64
	requireWriteTok  string
	seenAuthTokens   []string
	lastReceiveToken string
}

func newMockUpstreamGitServer(t *testing.T, writeTok string) *mockUpstreamGitServer {
	t.Helper()
	m := &mockUpstreamGitServer{
		repos:           make(map[string]string),
		lfsObjects:      make(map[string]map[string][]byte),
		requireWriteTok: writeTok,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockUpstreamGitServer) stats() (recvCalls int, recvBytes int64, lfsBatch int, lfsBytes int64, seenToks []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.receivePackCalls, m.receivePackBytes, m.lfsBatchCalls, m.lfsUploadBytes, append([]string(nil), m.seenAuthTokens...)
}

func (m *mockUpstreamGitServer) seedBareRepo(t *testing.T, fullName string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	bareDir := filepath.Join(root, "bare.git")
	workDir := filepath.Join(root, "work")

	runGit(t, "", "init", "--bare", "--initial-branch=main", bareDir)
	runGit(t, "", "init", "--initial-branch=main", workDir)
	runGit(t, workDir, "config", "user.name", "Upstream Seed")
	runGit(t, workDir, "config", "user.email", "seed@example.com")
	for rel, content := range files {
		full := filepath.Join(workDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	runGit(t, workDir, "add", ".")
	runGit(t, workDir, "commit", "-m", "initial upstream commit")
	runGit(t, workDir, "push", bareDir, "HEAD:refs/heads/main")
	headSHA := strings.TrimSpace(runGit(t, bareDir, "rev-parse", "refs/heads/main"))

	m.mu.Lock()
	m.repos[fullName] = bareDir
	m.mu.Unlock()
	return headSHA
}

func (m *mockUpstreamGitServer) addCommitToRepo(t *testing.T, fullName, relPath, content string) string {
	t.Helper()
	m.mu.Lock()
	bareDir, ok := m.repos[fullName]
	m.mu.Unlock()
	if !ok {
		t.Fatalf("addCommitToRepo: repo %s not seeded", fullName)
	}
	workDir := filepath.Join(t.TempDir(), "work")
	runGit(t, "", "clone", bareDir, workDir)
	runGit(t, workDir, "config", "user.name", "Upstream Advance")
	runGit(t, workDir, "config", "user.email", "advance@example.com")
	if err := os.WriteFile(filepath.Join(workDir, relPath), []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runGit(t, workDir, "add", relPath)
	runGit(t, workDir, "commit", "-m", "advance "+relPath)
	runGit(t, workDir, "push", bareDir, "HEAD:refs/heads/main")
	return strings.TrimSpace(runGit(t, bareDir, "rev-parse", "refs/heads/main"))
}

func (m *mockUpstreamGitServer) serve(w http.ResponseWriter, r *http.Request) {
	idx := strings.Index(r.URL.Path, ".git/")
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	fullName := strings.TrimPrefix(r.URL.Path[:idx], "/")
	suffix := r.URL.Path[idx+len(".git"):]
	m.mu.Lock()
	bareDir, ok := m.repos[fullName]
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	tok := ""
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		tok = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
	}
	if tok != "" {
		m.mu.Lock()
		m.seenAuthTokens = append(m.seenAuthTokens, tok)
		m.mu.Unlock()
	}

	switch {
	case suffix == "/info/refs":
		svc := r.URL.Query().Get("service")
		m.mu.Lock()
		m.infoRefsCalls++
		m.mu.Unlock()
		if svc == "git-receive-pack" && m.requireWriteTok != "" && tok != m.requireWriteTok {
			http.Error(w, "write token required", http.StatusForbidden)
			return
		}
		cmdName := strings.TrimPrefix(svc, "git-")
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", cmdName, "--stateless-rpc", "--advertise-refs", bareDir)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-"+svc+"-advertisement")
		pkt := fmt.Sprintf("# service=%s\n", svc)
		_, _ = fmt.Fprintf(w, "%04x%s0000", len(pkt)+4, pkt)
		_, _ = w.Write(out)

	case suffix == "/git-upload-pack":
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.uploadPackCalls++
		m.mu.Unlock()
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "upload-pack", "--stateless-rpc", bareDir)
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		_, _ = w.Write(out)

	case suffix == "/git-receive-pack":
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.receivePackCalls++
		m.receivePackBytes += int64(len(body))
		m.lastReceiveToken = tok
		m.mu.Unlock()
		if m.requireWriteTok != "" && tok != m.requireWriteTok {
			http.Error(w, "write token required", http.StatusForbidden)
			return
		}
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "receive-pack", "--stateless-rpc", bareDir)
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.Output()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		_, _ = w.Write(out)

	case suffix == "/info/lfs/objects/batch":
		m.mu.Lock()
		m.lfsBatchCalls++
		m.mu.Unlock()
		var req LFSBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.Operation == "upload" && m.requireWriteTok != "" && tok != m.requireWriteTok {
			http.Error(w, "write token required", http.StatusForbidden)
			return
		}
		resp := LFSBatchResponse{Transfer: "basic", Objects: make([]LFSBatchObjectResponse, 0, len(req.Objects))}
		m.mu.Lock()
		objs := m.lfsObjects[fullName]
		for _, o := range req.Objects {
			item := LFSBatchObjectResponse{OID: o.OID, Size: o.Size, Authenticated: true}
			href := fmt.Sprintf("%s/%s.git/info/lfs/objects/%s", m.server.URL, fullName, o.OID)
			hdr := map[string]string{"Authorization": "Bearer " + tok}
			if req.Operation == "upload" {
				item.Actions = map[string]LFSAction{"upload": {Href: href, Header: hdr}}
			} else if _, exists := objs[o.OID]; exists {
				item.Actions = map[string]LFSAction{"download": {Href: href, Header: hdr}}
			} else {
				item.Error = &LFSError{Code: 404, Message: "not found"}
			}
			resp.Objects = append(resp.Objects, item)
		}
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
		_ = json.NewEncoder(w).Encode(resp)

	case strings.HasPrefix(suffix, "/info/lfs/objects/"):
		oid := strings.TrimPrefix(suffix, "/info/lfs/objects/")
		if r.Method == http.MethodPut {
			if m.requireWriteTok != "" && tok != m.requireWriteTok {
				http.Error(w, "write token required", http.StatusForbidden)
				return
			}
			data, _ := io.ReadAll(r.Body)
			m.mu.Lock()
			if m.lfsObjects[fullName] == nil {
				m.lfsObjects[fullName] = make(map[string][]byte)
			}
			m.lfsObjects[fullName][oid] = data
			m.lfsUploadBytes += int64(len(data))
			m.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		m.mu.Lock()
		data, exists := m.lfsObjects[fullName][oid]
		m.mu.Unlock()
		if !exists {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)

	default:
		http.NotFound(w, r)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v (dir=%s) failed: %v\noutput:\n%s", args, dir, err, string(out))
	}
	return string(out)
}

func generateRSAPrivateKeyAndPEM(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(RSA): %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	return priv, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func generateLocalhostTLSCert(t *testing.T) (tls.Certificate, *x509.CertPool, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(ca.crt): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pair, pool, caFile
}

// --- Unit Tests ---

func TestCanonicalizeDestinationParity(t *testing.T) {
	cases := []struct {
		raw, fb  string
		wantDest string
		wantHost string
		wantErr  bool
	}{
		{"https://GitHub.com/Acme/Service.git", "", "github.com/Acme/Service.git", "github.com", false},
		{"https://user:secret@GitHub.com:8443/Acme/Service", "", "github.com:8443/Acme/Service", "github.com:8443", false},
		{"git@GitHub.com:Acme/Service", "", "github.com/Acme/Service", "github.com", false},
		{"git@[::1]:8443/Acme/Service", "", "[::1]:8443/Acme/Service", "[::1]:8443", false},
		{"[::1]:Acme/Service", "", "[::1]/Acme/Service", "[::1]", false},
		{"Acme/Service", "GitHub.com", "github.com/Acme/Service", "github.com", false},
		{"localhost:8443/Acme/Service", "", "localhost:8443/Acme/Service", "localhost:8443", false},
		{"", "github.com", "", "", true},
		{"[::1]:8443", "", "", "", true},
		{"localhost:8443", "", "", "", true},
		{"github.com/Acme\n/Service", "", "", "", true},
	}
	for _, tc := range cases {
		dest, host, err := CanonicalizeDestination(tc.raw, tc.fb)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("CanonicalizeDestination(%q, %q) expected error, got %q", tc.raw, tc.fb, dest)
			}
			continue
		}
		if err != nil || dest != tc.wantDest || host != tc.wantHost {
			t.Fatalf("CanonicalizeDestination(%q, %q) = (%q, %q, %v), want (%q, %q, nil)",
				tc.raw, tc.fb, dest, host, err, tc.wantDest, tc.wantHost)
		}
	}
}

func TestParseSmartHTTPRepoPathAndSSHRepoPathAndLFSOID(t *testing.T) {
	ownerRepo, suffix, err := ParseSmartHTTPRepoPath("/acme/service.git/info/refs", "/acme/service.git/info/refs")
	if err != nil || ownerRepo != "acme/service" || suffix != "/info/refs" {
		t.Fatalf("valid Smart-HTTP path failed: (%q, %q, %v)", ownerRepo, suffix, err)
	}

	for _, bad := range []struct{ raw, dec string }{
		{"/acme/../../etc/passwd.git/info/refs", "/etc/passwd.git/info/refs"},
		{"/%2e%2e/acme/service.git/git-receive-pack", "/../acme/service.git/git-receive-pack"},
		{"/%2E%2E/acme/service.git/info/refs", "/../acme/service.git/info/refs"},
		{"/invalid-no-dot-git/info/refs", "/invalid-no-dot-git/info/refs"},
		{"/acme\\service.git/info/refs", "/acme\\service.git/info/refs"},
		{"/acme/service.git/info/refs\x00", "/acme/service.git/info/refs\x00"},
	} {
		if _, _, err := ParseSmartHTTPRepoPath(bad.raw, bad.dec); err == nil {
			t.Fatalf("expected ParseSmartHTTPRepoPath(%q, %q) to fail", bad.raw, bad.dec)
		}
	}

	for _, okArg := range []string{"'/acme/service.git'", `"/acme/service"`, "acme/service.git", "acme/service"} {
		got, err := ParseSSHRepoPath(okArg)
		if err != nil || got != "acme/service" {
			t.Fatalf("ParseSSHRepoPath(%q) = (%q, %v)", okArg, got, err)
		}
	}
	for _, badArg := range []string{"", "'/acme/../etc/passwd.git'", "'acme/%2e%2e/repo'", "'no-slash.git'", "'acme/repo\\x'"} {
		if got, err := ParseSSHRepoPath(badArg); err == nil {
			t.Fatalf("expected ParseSSHRepoPath(%q) error, got %q", badArg, got)
		}
	}

	validOID := strings.Repeat("a", 64)
	if err := ValidateLFSOID(validOID); err != nil {
		t.Fatalf("ValidateLFSOID(valid) failed: %v", err)
	}
	for _, badOID := range []string{"", ".", "..", "not-hex", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if err := ValidateLFSOID(badOID); err == nil {
			t.Fatalf("expected ValidateLFSOID(%q) error", badOID)
		}
	}
}

func TestTargetResolverUnit(t *testing.T) {
	ctx := context.Background()
	lookup := newMemRepoLookup()
	remote := "http://127.0.0.1:18080/acme/registered.git"
	repoID, _ := domain.NewID()
	lookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    1001,
		GitHubInstallationID:  2002,
		FullName:              "acme/registered",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModePassiveAudit,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryInlineWarn,
		GitRemoteURL:          &remote,
		RemoteHost:            "github.com",
		RegisteredDestination: true,
		External:              false,
	})
	disabledID, _ := domain.NewID()
	lookup.add(persistence.RepositoryRow{
		ID:             disabledID,
		FullName:       "acme/disabled",
		Classification: domain.ClassificationInternal,
		Enabled:        false,
		EgressMode:     domain.EgressModeEnforceBlock,
	})

	resolver, err := NewTargetResolver(TargetResolverConfig{
		Store:                lookup,
		UpstreamBaseURL:      "http://127.0.0.1:18080",
		DefaultEgressMode:    domain.EgressModeEnforceBlock,
		DefaultAuditDelivery: domain.PassiveAuditDeliveryAsync,
	})
	if err != nil {
		t.Fatalf("NewTargetResolver: %v", err)
	}

	// Registered repository resolved via git_remote_url.
	target, err := resolver.Resolve(ctx, "acme/registered", "gateway.local")
	if err != nil {
		t.Fatalf("Resolve(registered): %v", err)
	}
	if !target.Registered || target.External || target.CanonicalDestination != "github.com/acme/registered" ||
		target.EgressMode != domain.EgressModePassiveAudit || target.PassiveAuditDelivery != domain.PassiveAuditDeliveryInlineWarn {
		t.Fatalf("unexpected resolved target: %+v", target)
	}

	// Disabled repository rejected with 403 REPOSITORY_DISABLED.
	_, err = resolver.Resolve(ctx, "acme/disabled", "gateway.local")
	var de *domain.DomainError
	if !errors.As(err, &de) || de.Code() != "REPOSITORY_DISABLED" || de.HTTPStatus() != http.StatusForbidden {
		t.Fatalf("expected 403 REPOSITORY_DISABLED, got %v", err)
	}

	// Unregistered repository falls back to External=true + DefaultEgressMode.
	unreg, err := resolver.Resolve(ctx, "external/personal", "gateway.local")
	if err != nil {
		t.Fatalf("Resolve(unregistered): %v", err)
	}
	if unreg.Registered || !unreg.External || unreg.Repository != nil || unreg.EgressMode != domain.EgressModeEnforceBlock {
		t.Fatalf("unexpected unregistered target: %+v", unreg)
	}
}

func TestTokenBrokerDelegatedAndGitHubAppMintingAndReadWriteIsolation(t *testing.T) {
	ctx := context.Background()
	readPriv, readPEM := generateRSAPrivateKeyAndPEM(t)
	writePriv, writePEM := generateRSAPrivateKeyAndPEM(t)
	_ = readPriv
	_ = writePriv

	var mu sync.Mutex
	var lastEndpoint string
	var lastAuthHeader string
	var mintCalls int
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastEndpoint = r.URL.Path
		lastAuthHeader = r.Header.Get("Authorization")
		mintCalls++
		mu.Unlock()

		switch r.URL.Path {
		case "/repos/acme/fallback/installation":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 888})
		case "/app/installations/555/access_tokens", "/app/installations/888/access_tokens":
			var body struct {
				Permissions map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			tok := "ghs_read_token_1234567890"
			if body.Permissions["contents"] == "write" {
				tok = "ghs_write_token_abcdef123456"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      tok,
				"expires_at": time.Now().UTC().Add(10 * time.Minute),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer apiSrv.Close()

	broker, err := NewTokenBroker(TokenBrokerConfig{
		APIBaseURL:         apiSrv.URL,
		ReadAppID:          101,
		ReadPrivateKeyPEM:  readPEM,
		WriteAppID:         202,
		WritePrivateKeyPEM: writePEM,
		DisableTokenCache:  true,
	})
	if err != nil {
		t.Fatalf("NewTokenBroker: %v", err)
	}

	target := ResolvedTarget{
		OwnerRepo: "acme/service",
		Repository: &domain.Repository{
			GitHubRepositoryID:   42,
			GitHubInstallationID: 555,
			FullName:             "acme/service",
			Enabled:              true,
		},
	}

	// 1. Delegated PAT forwarded & added to ExtraSecrets; OIDC JWT never returned as Token.
	delegatedCaller := AuthenticatedPrincipal{
		AuthMethod:             "oidc",
		OIDCToken:              "eyJ_caller_oidc_jwt_must_never_forward",
		DelegatedUpstreamToken: "ghp_delegated_pat_secret_999",
	}
	res1, err := broker.ResolveUpstreamAuth(ctx, TokenScopeWrite, delegatedCaller, target)
	if err != nil {
		t.Fatalf("ResolveUpstreamAuth(delegated): %v", err)
	}
	if res1.Token != "ghp_delegated_pat_secret_999" || res1.Source != "delegated" {
		t.Fatalf("unexpected delegated auth result: %+v", res1)
	}
	if !slices.Contains(res1.ExtraSecrets, delegatedCaller.OIDCToken) || !slices.Contains(res1.ExtraSecrets, delegatedCaller.DelegatedUpstreamToken) {
		t.Fatalf("ExtraSecrets missing tokens: %+v", res1.ExtraSecrets)
	}
	if mintCalls != 0 {
		t.Fatalf("expected 0 GitHub App mint calls when delegated token present, got %d", mintCalls)
	}

	// 2. Write scope mints ghs_write_* token using write App key & puts it in ExtraSecrets.
	oidcCaller := AuthenticatedPrincipal{
		AuthMethod: "oidc",
		OIDCToken:  "eyJ_caller_oidc_jwt_must_never_forward",
	}
	res2, err := broker.ResolveUpstreamAuth(ctx, TokenScopeWrite, oidcCaller, target)
	if err != nil {
		t.Fatalf("ResolveUpstreamAuth(write): %v", err)
	}
	if res2.Token != "ghs_write_token_abcdef123456" || res2.Source != "github_app_write" {
		t.Fatalf("unexpected write auth result: %+v", res2)
	}
	if !slices.Contains(res2.ExtraSecrets, res2.Token) || !slices.Contains(res2.ExtraSecrets, oidcCaller.OIDCToken) {
		t.Fatalf("ExtraSecrets missing minted write token or OIDC token: %+v", res2.ExtraSecrets)
	}
	if res2.Token == oidcCaller.OIDCToken || lastEndpoint != "/app/installations/555/access_tokens" || !strings.HasPrefix(lastAuthHeader, "Bearer eyJ") {
		t.Fatalf("unexpected GitHub API call state: endpoint=%s auth=%s", lastEndpoint, lastAuthHeader)
	}

	// 3. Fallback installation lookup via /repos/{owner}/{repo}/installation when GitHubInstallationID == 0.
	fallbackTarget := ResolvedTarget{
		OwnerRepo: "acme/fallback",
		Repository: &domain.Repository{
			GitHubRepositoryID:   99,
			GitHubInstallationID: 0,
			FullName:             "acme/fallback",
			Enabled:              true,
		},
	}
	res3, err := broker.ResolveUpstreamAuth(ctx, TokenScopeWrite, oidcCaller, fallbackTarget)
	if err != nil || res3.Token != "ghs_write_token_abcdef123456" {
		t.Fatalf("fallback installation mint failed: res=%+v err=%v", res3, err)
	}

	// 4. Read path NEVER uses WriteAppID/WritePrivateKeyPEM (works with nil write keys).
	readOnlyBroker, err := NewTokenBroker(TokenBrokerConfig{
		APIBaseURL:        apiSrv.URL,
		ReadAppID:         101,
		ReadPrivateKeyPEM: readPEM,
	})
	if err != nil {
		t.Fatalf("NewTokenBroker(read-only): %v", err)
	}
	resRead, err := readOnlyBroker.ResolveUpstreamAuth(ctx, TokenScopeRead, oidcCaller, target)
	if err != nil || resRead.Token != "ghs_read_token_1234567890" || resRead.Source != "github_app_read" {
		t.Fatalf("read path failed: res=%+v err=%v", resRead, err)
	}
	if _, err := readOnlyBroker.ResolveUpstreamAuth(ctx, TokenScopeWrite, oidcCaller, target); err == nil {
		t.Fatal("expected write scope to fail when write App is unconfigured")
	}
}

func TestDefaultFailClosedReceivePackHandler(t *testing.T) {
	h := NewDefaultFailClosedReceivePackHandler()
	var sb bytes.Buffer
	out, err := h.HandleReceivePack(context.Background(), ReceivePackRequest{
		Transport: domain.PushTransportHTTPS,
		RefUpdates: []quarantine.RefUpdate{
			{RefName: "refs/heads/main", OldOID: quarantine.ZeroOID, NewOID: strings.Repeat("1", 40)},
		},
		SidebandWriter: &sb,
	})
	if err != nil {
		t.Fatalf("HandleReceivePack: %v", err)
	}
	if out.Status != domain.PushSessionStatusBlocked ||
		out.Effect != domain.PolicyEffectDeny ||
		out.HTTPStatus != http.StatusServiceUnavailable ||
		out.UpstreamForwarded ||
		out.UpstreamBytesSent != 0 ||
		out.UnpackOK ||
		len(out.RefResults) != 1 || out.RefResults[0].OK {
		t.Fatalf("unexpected fail-closed outcome: %+v", out)
	}
	if !strings.Contains(sb.String(), "ENFORCE_BLOCK") {
		t.Fatalf("expected ENFORCE_BLOCK sideband message, got %q", sb.String())
	}
}

type stubReceivePackHandler struct {
	mu      sync.Mutex
	calls   []ReceivePackRequest
	outcome ReceivePackOutcome
}

func (s *stubReceivePackHandler) HandleReceivePack(_ context.Context, req ReceivePackRequest) (ReceivePackOutcome, error) {
	_, _ = io.ReadAll(req.PackReader)
	if req.SidebandWriter != nil {
		_, _ = io.WriteString(req.SidebandWriter, "Custodian Policy Verdict: "+string(s.outcome.Effect)+"\n")
	}
	s.mu.Lock()
	s.calls = append(s.calls, req)
	s.mu.Unlock()
	out := s.outcome
	if len(out.RefResults) == 0 {
		for _, ru := range req.RefUpdates {
			out.RefResults = append(out.RefResults, RefResult{
				RefName: ru.RefName,
				OK:      out.UnpackOK,
				Message: "policy verdict",
			})
		}
	}
	return out, nil
}

func newGatewayTestHarness(t *testing.T, upstream *mockUpstreamGitServer, handler ReceivePackHandler) (*Server, *memPrincipalStore, *memRepoLookup, *harness.MockOIDC, *observability.Metrics) {
	t.Helper()
	oidc := harness.StartMockOIDC(t, "custodian-api")
	pStore := newMemPrincipalStore()
	rLookup := newMemRepoLookup()

	verifier, err := auth.NewOIDCVerifier(auth.OIDCConfig{
		Issuer:   oidc.Issuer(),
		JWKSURL:  oidc.JWKSURL(),
		Audience: oidc.Audience(),
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}
	dir, err := identity.NewDirectory(pStore, identity.DefaultDirectoryConfig())
	if err != nil {
		t.Fatalf("NewDirectory: %v", err)
	}

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	caPub, _, _ := ed25519.GenerateKey(rand.Reader)
	caSSHPub, _ := ssh.NewPublicKey(caPub)

	authSvc, err := NewAuthenticator(AuthenticatorConfig{
		OIDC:          verifier,
		Directory:     dir,
		GroupUpserter: pStore,
		SSHLookup:     pStore,
		SSHHostKey:    hostSigner,
		SSHUserCA:     caSSHPub,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	resolver, err := NewTargetResolver(TargetResolverConfig{
		Store:                rLookup,
		UpstreamBaseURL:      upstream.server.URL,
		DefaultEgressMode:    domain.EgressModeEnforceBlock,
		DefaultAuditDelivery: domain.PassiveAuditDeliveryAsync,
	})
	if err != nil {
		t.Fatalf("NewTargetResolver: %v", err)
	}

	_, writePEM := generateRSAPrivateKeyAndPEM(t)
	// Mock GitHub App API server returning requireWriteTok.
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      upstream.requireWriteTok,
			"expires_at": time.Now().UTC().Add(10 * time.Minute),
		})
	}))
	t.Cleanup(ghAPI.Close)

	broker, err := NewTokenBroker(TokenBrokerConfig{
		APIBaseURL:         ghAPI.URL,
		WriteAppID:         202,
		WritePrivateKeyPEM: writePEM,
	})
	if err != nil {
		t.Fatalf("NewTokenBroker: %v", err)
	}

	upClient, err := NewHTTPUpstreamClient(HTTPUpstreamConfig{
		BaseURL:           upstream.server.URL,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPUpstreamClient: %v", err)
	}

	metrics, err := observability.NewMetrics(observability.MetricsConfig{Namespace: "custodian"})
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		Authenticator:      authSvc,
		TargetResolver:     resolver,
		TokenBroker:        broker,
		Upstream:           upClient,
		ReceivePackHandler: handler,
		Limits: quarantine.Limits{
			MaxPackBytes:  4096,
			MaxRefUpdates: 10,
		},
		Metrics: metrics,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, pStore, rLookup, oidc, metrics
}

func TestSmartHTTPLsRemoteCloneFetchGzipAndReceivePackRealGit(t *testing.T) {
	writeTok := "ghs_write_upstream_secret_123"
	upstream := newMockUpstreamGitServer(t, writeTok)
	headSHA := upstream.seedBareRepo(t, "acme/service", map[string]string{
		"README.md": "hello custodian\n",
	})

	stubHandler := &stubReceivePackHandler{
		outcome: ReceivePackOutcome{
			Status:            domain.PushSessionStatusBlocked,
			Effect:            domain.PolicyEffectDeny,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			UnpackOK:          false,
			UnpackMessage:     "blocked by policy",
		},
	}
	srv, pStore, rLookup, oidc, _ := newGatewayTestHarness(t, upstream, stubHandler)

	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    42,
		GitHubInstallationID:  77,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RemoteHost:            "github.com",
		RegisteredDestination: true,
	})

	cert, pool, caFile := generateLocalhostTLSCert(t)
	gwTLS := httptest.NewUnstartedServer(srv.HTTPHandler())
	gwTLS.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	gwTLS.StartTLS()
	defer gwTLS.Close()

	jwt := oidc.MintHumanToken("alice-001", "alice@example.com", "Alice", "eng", "platform")
	gwClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	// 1. OIDC Bearer /info/refs?service=git-upload-pack & git-receive-pack both return 200 and required caps.
	for _, svc := range []string{"git-upload-pack", "git-receive-pack"} {
		req, _ := http.NewRequest(http.MethodGet, gwTLS.URL+"/acme/service.git/info/refs?service="+svc, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := gwClient.Do(req)
		if err != nil {
			t.Fatalf("GET info/refs (%s): %v", svc, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(headSHA)) {
			t.Fatalf("info/refs (%s): status=%d body=%q", svc, resp.StatusCode, string(body))
		}
		if svc == "git-receive-pack" && (!bytes.Contains(body, []byte("report-status")) || !bytes.Contains(body, []byte("side-band-64k"))) {
			t.Fatalf("receive-pack advertisement missing capabilities: %q", string(body))
		}
	}

	// Verify OIDC groups persisted in store.
	if pStore.groupCount() == 0 {
		t.Fatal("expected OIDC groups persisted in principal store")
	}

	// 2. Real git ls-remote & git clone & git fetch using Basic x-access-token:<jwt>.
	u := strings.Replace(gwTLS.URL, "https://", "https://x-access-token:"+jwt+"@", 1) + "/acme/service.git"
	lsCmd := exec.Command("git", "-c", "http.sslCAInfo="+caFile, "ls-remote", u)
	lsOut, err := lsCmd.CombinedOutput()
	if err != nil || !strings.Contains(string(lsOut), headSHA) {
		t.Fatalf("git ls-remote failed: %v\nout=%s", err, string(lsOut))
	}

	cloneDir := filepath.Join(t.TempDir(), "clone")
	cloneCmd := exec.Command("git", "-c", "http.sslCAInfo="+caFile, "clone", u, cloneDir)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone failed: %v\nout=%s", err, string(out))
	}

	// Add a new commit upstream and run git fetch through the gateway to verify real want/have/done negotiation.
	newSHA := upstream.addCommitToRepo(t, "acme/service", "upstream_next.txt", "next commit\n")
	fetchCmd := exec.Command("git", "-C", cloneDir, "-c", "http.sslCAInfo="+caFile, "fetch", "origin")
	if out, err := fetchCmd.CombinedOutput(); err != nil {
		t.Fatalf("git fetch failed: %v\nout=%s", err, string(out))
	}
	fetchedSHA := strings.TrimSpace(runGit(t, cloneDir, "rev-parse", "FETCH_HEAD"))
	if fetchedSHA != newSHA {
		t.Fatalf("git fetch FETCH_HEAD=%s, want %s", fetchedSHA, newSHA)
	}

	// Verify X-Custodian-Upstream-Token & X-GitHub-Token delegated tokens are extracted & passed to ReceivePackHandler without leaking OIDC JWT.
	for _, hdrName := range []string{"X-Custodian-Upstream-Token", "X-GitHub-Token"} {
		delegatedVal := "ghp_delegated_" + strings.ReplaceAll(hdrName, "-", "_")
		cmdLine := fmt.Sprintf("%s %s refs/heads/main\x00report-status\n", quarantine.ZeroOID, strings.Repeat("a", 40))
		pkt := append(formatPktLine([]byte(cmdLine)), []byte("0000PACK")...)
		dReq, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", bytes.NewReader(pkt))
		dReq.Header.Set("Authorization", "Bearer "+jwt)
		dReq.Header.Set(hdrName, delegatedVal)
		dResp, dErr := gwClient.Do(dReq)
		if dErr != nil {
			t.Fatalf("delegated POST (%s): %v", hdrName, dErr)
		}
		_ = dResp.Body.Close()
		stubHandler.mu.Lock()
		last := stubHandler.calls[len(stubHandler.calls)-1]
		stubHandler.mu.Unlock()
		if last.UpstreamToken != delegatedVal || !slices.Contains(last.ExtraSecrets, delegatedVal) || !slices.Contains(last.ExtraSecrets, jwt) {
			t.Fatalf("expected delegated token %q and ExtraSecrets in ReceivePackRequest, got tok=%q extra=%v", delegatedVal, last.UpstreamToken, last.ExtraSecrets)
		}
	}

	// 3. Real git push hits ReceivePackHandler, streams sideband-2 verdict, and sends ZERO bytes upstream.
	runGit(t, cloneDir, "config", "user.name", "Alice")
	runGit(t, cloneDir, "config", "user.email", "alice@example.com")
	if err := os.WriteFile(filepath.Join(cloneDir, "change.txt"), []byte("new change\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runGit(t, cloneDir, "add", "change.txt")
	runGit(t, cloneDir, "commit", "-m", "test push")

	pushCmd := exec.Command("git", "-C", cloneDir, "-c", "http.sslCAInfo="+caFile, "push", u, "HEAD:refs/heads/feature")
	pushOut, pushErr := pushCmd.CombinedOutput()
	if pushErr == nil {
		t.Fatalf("expected git push to be rejected by stubHandler, got success:\n%s", string(pushOut))
	}
	if !strings.Contains(string(pushOut), "DENY") {
		t.Fatalf("expected sideband-2 DENY verdict in git push stderr, got:\n%s", string(pushOut))
	}
	if rc, rb, _, _, _ := upstream.stats(); rc != 0 || rb != 0 {
		t.Fatalf("expected 0 upstream receive-pack calls/bytes, got calls=%d bytes=%d", rc, rb)
	}

	// 4. Unregistered repo push still reaches ReceivePackHandler via synthetic /info/refs!
	unregURL := strings.Replace(gwTLS.URL, "https://", "https://x-access-token:"+jwt+"@", 1) + "/unregistered/personal-repo.git"
	unregCmd := exec.Command("git", "-C", cloneDir, "-c", "http.sslCAInfo="+caFile, "push", unregURL, "HEAD:refs/heads/main")
	unregOut, unregErr := unregCmd.CombinedOutput()
	if unregErr == nil || !strings.Contains(string(unregOut), "DENY") {
		t.Fatalf("expected unregistered git push to hit ReceivePackHandler and emit DENY, got err=%v out=%s", unregErr, string(unregOut))
	}

	// 5. Ensure OIDC JWT was NEVER forwarded to upstream MockGitHub.
	_, _, _, _, seenToks := upstream.stats()
	for _, tok := range seenToks {
		if tok == jwt {
			t.Fatal("caller OIDC JWT leaked upstream!")
		}
	}
}

func TestSmartHTTPRejectionsZeroUpstream(t *testing.T) {
	writeTok := "ghs_write_secret"
	upstream := newMockUpstreamGitServer(t, writeTok)
	upstream.seedBareRepo(t, "acme/service", map[string]string{"README.md": "hi\n"})
	upstream.seedBareRepo(t, "acme/disabled", map[string]string{"README.md": "hi\n"})

	// Use default fail-closed handler (503).
	srv, _, rLookup, oidc, _ := newGatewayTestHarness(t, upstream, nil)
	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    1,
		GitHubInstallationID:  1,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RegisteredDestination: true,
	})
	disID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:             disID,
		FullName:       "acme/disabled",
		Classification: domain.ClassificationInternal,
		Enabled:        false,
		EgressMode:     domain.EgressModeEnforceBlock,
	})

	cert, pool, _ := generateLocalhostTLSCert(t)
	gwTLS := httptest.NewUnstartedServer(srv.HTTPHandler())
	gwTLS.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	gwTLS.StartTLS()
	defer gwTLS.Close()

	jwt := oidc.MintHumanToken("alice-001", "alice@example.com", "Alice")
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}

	// 1. Unauthenticated POST /git-receive-pack -> 401 + WWW-Authenticate: Basic.
	resp, err := client.Post(gwTLS.URL+"/acme/service.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader("0000"))
	if err != nil {
		t.Fatalf("unauth POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("expected 401 + Basic challenge, got %d (%s)", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 2. Path traversal -> 400 (NEVER 301).
	for _, rawPath := range []string{
		"/acme/../../etc/passwd.git/info/refs?service=git-receive-pack",
		"/%2e%2e/acme/service.git/git-receive-pack",
		"/invalid-no-dot-git/info/refs?service=git-receive-pack",
	} {
		conn, err := tls.Dial("tcp", strings.TrimPrefix(gwTLS.URL, "https://"), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n", rawPath, jwt)
		rawResp, _ := io.ReadAll(conn)
		_ = conn.Close()
		if !strings.HasPrefix(string(rawResp), "HTTP/1.1 400 ") {
			t.Fatalf("path %q: expected 400, got:\n%s", rawPath, string(rawResp))
		}
	}

	// 3. Invalid HTTP methods -> 405.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/acme/service.git/git-receive-pack"},
		{http.MethodPost, "/acme/service.git/info/refs?service=git-receive-pack"},
	} {
		req, _ := http.NewRequest(tc.method, gwTLS.URL+tc.path, strings.NewReader("0000"))
		req.Header.Set("Authorization", "Bearer "+jwt)
		r, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: expected 405, got %d", tc.method, tc.path, r.StatusCode)
		}
	}

	// 4. Disabled repo -> 403.
	reqDis, _ := http.NewRequest(http.MethodGet, gwTLS.URL+"/acme/disabled.git/info/refs?service=git-upload-pack", nil)
	reqDis.Header.Set("Authorization", "Bearer "+jwt)
	rDis, err := client.Do(reqDis)
	if err != nil {
		t.Fatalf("disabled GET: %v", err)
	}
	_ = rDis.Body.Close()
	if rDis.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled repo, got %d", rDis.StatusCode)
	}

	// 5. Oversized Content-Length (> MaxPackBytes + 2 MiB maxWireBytes) -> 413.
	reqBig, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", strings.NewReader("0000"))
	reqBig.Header.Set("Authorization", "Bearer "+jwt)
	reqBig.ContentLength = 10 << 20
	rBig, err := client.Do(reqBig)
	if err == nil {
		_ = rBig.Body.Close()
		if rBig.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 for oversized Content-Length, got %d", rBig.StatusCode)
		}
	}

	// 6. Malformed pkt-lines (including signed "+000" / "-001") -> 400.
	for _, badBody := range []string{"zzzz0000", "0040short", "0003", "+000", "-001"} {
		reqBad, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", strings.NewReader(badBody))
		reqBad.Header.Set("Authorization", "Bearer "+jwt)
		rBad, err := client.Do(reqBad)
		if err != nil {
			t.Fatalf("malformed %q: %v", badBody, err)
		}
		_ = rBad.Body.Close()
		if rBad.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed %q: expected 400, got %d", badBody, rBad.StatusCode)
		}
	}

	// 7. Gzipped valid pkt-line hits DefaultFailClosedReceivePackHandler -> 503 with 0 upstream bytes.
	cmdLine := fmt.Sprintf("%s %s refs/heads/main\x00report-status side-band-64k\n", quarantine.ZeroOID, strings.Repeat("1", 40))
	pktPayload := append(formatPktLine([]byte(cmdLine)), []byte("0000PACK")...)
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write(pktPayload)
	_ = gz.Close()

	reqGz, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", bytes.NewReader(gzBuf.Bytes()))
	reqGz.Header.Set("Authorization", "Bearer "+jwt)
	reqGz.Header.Set("Content-Encoding", "gzip")
	rGz, err := client.Do(reqGz)
	if err != nil {
		t.Fatalf("gzipped receive-pack: %v", err)
	}
	_ = rGz.Body.Close()
	if rGz.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from DefaultFailClosedReceivePackHandler, got %d", rGz.StatusCode)
	}

	if rc, rb, _, _, _ := upstream.stats(); rc != 0 || rb != 0 {
		t.Fatalf("expected 0 upstream receive-pack calls/bytes across all rejections, got %d / %d", rc, rb)
	}
}

func mintSSHUserCert(t *testing.T, caSigner ssh.Signer, principals []string, keyID string, serial uint64, validAfter, validBefore time.Time) (ssh.Signer, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(ed25519 user): %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}
	return certSigner, pem.EncodeToMemory(privBlock)
}

func TestSSHUserCAAuthRejectionsAndRealGitCloneFetchPush(t *testing.T) {
	writeTok := "ghs_write_ssh_secret"
	upstream := newMockUpstreamGitServer(t, writeTok)
	headSHA := upstream.seedBareRepo(t, "acme/service", map[string]string{"hello.txt": "ssh world\n"})

	oidc := harness.StartMockOIDC(t, "custodian-api")
	pStore := newMemPrincipalStore()
	aliceID, _ := domain.NewID()
	pStore.seed(domain.Principal{
		ID:            aliceID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "alice-human-001",
		DisplayName:   "Alice",
		VerifiedEmail: "alice@example.com",
		CreatedAt:     time.Now().UTC(),
	}, []string{"eng"})

	rLookup := newMemRepoLookup()
	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    42,
		GitHubInstallationID:  77,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RemoteHost:            "github.com",
		RegisteredDestination: true,
	})

	verifier, _ := auth.NewOIDCVerifier(auth.OIDCConfig{Issuer: oidc.Issuer(), JWKSURL: oidc.JWKSURL(), Audience: oidc.Audience()})
	dir, _ := identity.NewDirectory(pStore, identity.DefaultDirectoryConfig())

	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostSSHPub, _ := ssh.NewPublicKey(hostPub)

	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caSSHPub, _ := ssh.NewPublicKey(caPub)

	_, rogueCAPriv, _ := ed25519.GenerateKey(rand.Reader)
	rogueCASigner, _ := ssh.NewSignerFromKey(rogueCAPriv)

	authSvc, err := NewAuthenticator(AuthenticatorConfig{
		OIDC:          verifier,
		Directory:     dir,
		GroupUpserter: pStore,
		SSHLookup:     pStore,
		SSHHostKey:    hostSigner,
		SSHUserCA:     caSSHPub,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	resolver, _ := NewTargetResolver(TargetResolverConfig{Store: rLookup, UpstreamBaseURL: upstream.server.URL})
	_, writePEM := generateRSAPrivateKeyAndPEM(t)
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": writeTok, "expires_at": time.Now().UTC().Add(10 * time.Minute)})
	}))
	defer ghAPI.Close()
	broker, _ := NewTokenBroker(TokenBrokerConfig{APIBaseURL: ghAPI.URL, WriteAppID: 202, WritePrivateKeyPEM: writePEM})
	upClient, _ := NewHTTPUpstreamClient(HTTPUpstreamConfig{BaseURL: upstream.server.URL, AllowInsecureHTTP: true})

	stubHandler := &stubReceivePackHandler{
		outcome: ReceivePackOutcome{
			Status:            domain.PushSessionStatusBlocked,
			Effect:            domain.PolicyEffectDeny,
			UpstreamForwarded: false,
			UpstreamBytesSent: 0,
			UnpackOK:          false,
			UnpackMessage:     "blocked by SSH policy",
		},
	}
	srv, err := NewServer(ServerConfig{
		Authenticator:      authSvc,
		TargetResolver:     resolver,
		TokenBroker:        broker,
		Upstream:           upClient,
		ReceivePackHandler: stubHandler,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	sshAddr := sshLn.Addr().String()
	go func() { _ = srv.SSHServer().Serve(sshLn) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.SSHServer().Shutdown(ctx)
	}()

	now := time.Now()
	validSigner, validKeyPEM := mintSSHUserCert(t, caSigner, []string{"alice-human-001"}, "alice-key-1", 1001, now.Add(-time.Minute), now.Add(time.Hour))
	expiredSigner, _ := mintSSHUserCert(t, caSigner, []string{"alice-human-001"}, "expired", 1002, now.Add(-2*time.Hour), now.Add(-time.Hour))
	rogueSigner, _ := mintSSHUserCert(t, rogueCASigner, []string{"alice-human-001"}, "rogue", 1003, now.Add(-time.Minute), now.Add(time.Hour))
	emptyPrincipalsSigner, _ := mintSSHUserCert(t, caSigner, nil, "empty", 1004, now.Add(-time.Minute), now.Add(time.Hour))
	unknownSigner, _ := mintSSHUserCert(t, caSigner, []string{"unregistered-xyz"}, "unknown", 1005, now.Add(-time.Minute), now.Add(time.Hour))
	bobSigner, _ := mintSSHUserCert(t, caSigner, []string{"bob-human-002"}, "bob", 1006, now.Add(-time.Minute), now.Add(time.Hour))

	// 1. Auth rejections via golang.org/x/crypto/ssh client.
	for _, tc := range []struct {
		name   string
		user   string
		signer ssh.Signer
	}{
		{"expired_cert", "git", expiredSigner},
		{"rogue_ca", "git", rogueSigner},
		{"empty_principals", "git", emptyPrincipalsSigner},
		{"unknown_principal", "git", unknownSigner},
		{"wrong_username", "alice-human-001", bobSigner},
	} {
		cfg := &ssh.ClientConfig{
			User:            tc.user,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(tc.signer)},
			HostKeyCallback: ssh.FixedHostKey(hostSSHPub),
			Timeout:         3 * time.Second,
		}
		if c, err := ssh.Dial("tcp", sshAddr, cfg); err == nil {
			_ = c.Close()
			t.Fatalf("expected SSH auth failure for %s", tc.name)
		}
	}

	// 2. Valid cert succeeds and records SSHKeyID & SSHCertSerial.
	c, err := ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(validSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSSHPub),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("valid SSH dial failed: %v", err)
	}
	_ = c.Close()

	// 3. Real git CLI over SSH (if ssh binary available in PATH).
	if _, lookErr := exec.LookPath("ssh"); lookErr == nil {
		sshDir := t.TempDir()
		keyPath := filepath.Join(sshDir, "id_ed25519")
		certPath := filepath.Join(sshDir, "id_ed25519-cert.pub")
		knownHostsPath := filepath.Join(sshDir, "known_hosts")
		_ = os.WriteFile(keyPath, validKeyPEM, 0o600)
		if certSigner, ok := validSigner.(ssh.Signer); ok {
			_ = os.WriteFile(certPath, ssh.MarshalAuthorizedKey(certSigner.PublicKey()), 0o644)
		}
		host, port, _ := net.SplitHostPort(sshAddr)
		khLine := fmt.Sprintf("[%s]:%s %s", host, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSSHPub))))
		_ = os.WriteFile(knownHostsPath, []byte(khLine+"\n"), 0o600)

		gitSSH := fmt.Sprintf("ssh -i %s -o CertificateFile=%s -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -p %s",
			keyPath, certPath, knownHostsPath, port)

		sshCloneURL := fmt.Sprintf("ssh://git@%s:%s/acme/service.git", host, port)
		lsCmd := exec.Command("git", "ls-remote", sshCloneURL)
		lsCmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH, "GIT_TERMINAL_PROMPT=0")
		if out, err := lsCmd.CombinedOutput(); err != nil || !strings.Contains(string(out), headSHA) {
			t.Fatalf("git ls-remote over SSH failed: %v\n%s", err, string(out))
		}

		cloneDir := filepath.Join(t.TempDir(), "ssh-clone")
		cloneCmd := exec.Command("git", "clone", sshCloneURL, cloneDir)
		cloneCmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH, "GIT_TERMINAL_PROMPT=0")
		if out, err := cloneCmd.CombinedOutput(); err != nil {
			t.Fatalf("git clone over SSH failed: %v\n%s", err, string(out))
		}

		newSSHSHA := upstream.addCommitToRepo(t, "acme/service", "ssh_upstream_next.txt", "ssh next\n")
		fetchCmd := exec.Command("git", "-C", cloneDir, "fetch", "origin")
		fetchCmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH, "GIT_TERMINAL_PROMPT=0")
		if out, err := fetchCmd.CombinedOutput(); err != nil {
			t.Fatalf("git fetch over SSH failed: %v\n%s", err, string(out))
		}
		if got := strings.TrimSpace(runGit(t, cloneDir, "rev-parse", "FETCH_HEAD")); got != newSSHSHA {
			t.Fatalf("SSH git fetch FETCH_HEAD=%s, want %s", got, newSSHSHA)
		}

		// Real git push over SSH reaches ReceivePackHandler with SSHKeyID/SSHCertSerial & sends 0 upstream bytes.
		runGit(t, cloneDir, "config", "user.name", "Alice")
		runGit(t, cloneDir, "config", "user.email", "alice@example.com")
		_ = os.WriteFile(filepath.Join(cloneDir, "ssh_push.txt"), []byte("ssh push\n"), 0o600)
		runGit(t, cloneDir, "add", "ssh_push.txt")
		runGit(t, cloneDir, "commit", "-m", "ssh commit")

		pushCmd := exec.Command("git", "-C", cloneDir, "push", sshCloneURL, "HEAD:refs/heads/ssh-feat")
		pushCmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH, "GIT_TERMINAL_PROMPT=0")
		pushOut, pushErr := pushCmd.CombinedOutput()
		if pushErr == nil || !strings.Contains(string(pushOut), "DENY") {
			t.Fatalf("expected SSH push DENY verdict, got err=%v out=%s", pushErr, string(pushOut))
		}

		stubHandler.mu.Lock()
		nCalls := len(stubHandler.calls)
		var lastCall ReceivePackRequest
		if nCalls > 0 {
			lastCall = stubHandler.calls[nCalls-1]
		}
		stubHandler.mu.Unlock()
		if nCalls == 0 || lastCall.Transport != domain.PushTransportSSH ||
			lastCall.Caller.SSHKeyID != "alice-key-1" || lastCall.Caller.SSHCertSerial != 1001 {
			t.Fatalf("unexpected SSH ReceivePackRequest caller metadata: %+v", lastCall.Caller)
		}
		if rc, _, _, _, _ := upstream.stats(); rc != 0 {
			t.Fatalf("expected 0 upstream receive-pack calls on blocked SSH push, got %d", rc)
		}
	}
}

func TestLFSBatchAndObjectEndpointsAndMetrics(t *testing.T) {
	writeTok := "ghs_write_lfs_secret_token"
	upstream := newMockUpstreamGitServer(t, writeTok)
	upstream.seedBareRepo(t, "acme/service", map[string]string{"README.md": "lfs\n"})

	srv, _, rLookup, oidc, metrics := newGatewayTestHarness(t, upstream, nil)
	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    42,
		GitHubInstallationID:  77,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RegisteredDestination: true,
	})
	disID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:             disID,
		FullName:       "acme/disabled",
		Classification: domain.ClassificationInternal,
		Enabled:        false,
		EgressMode:     domain.EgressModeEnforceBlock,
	})

	cert, pool, _ := generateLocalhostTLSCert(t)
	gwTLS := httptest.NewUnstartedServer(srv.HTTPHandler())
	gwTLS.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	gwTLS.StartTLS()
	defer gwTLS.Close()

	jwt := oidc.MintHumanToken("alice-001", "alice@example.com", "Alice")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	payload := []byte("Custodian LFS binary payload 0123456789")
	sum := sha256.Sum256(payload)
	oid := hex.EncodeToString(sum[:])

	// 1. Invalid OID, unsupported op, oversized size, disabled repo, unregistered upload -> 0 upstream calls.
	badBatches := []struct {
		repo string
		body string
	}{
		{"acme/service", `{"operation":"upload","objects":[{"oid":"bad-oid","size":10}]}`},
		{"acme/service", fmt.Sprintf(`{"operation":"delete","objects":[{"oid":%q,"size":10}]}`, oid)},
		{"acme/service", fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":-1}]}`, oid)},
		{"acme/service", fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":%d}]}`, oid, int64(100)<<30)},
		{"acme/disabled", fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":10}]}`, oid)},
		{"external/unregistered", fmt.Sprintf(`{"operation":"upload","objects":[{"oid":%q,"size":10}]}`, oid)},
	}
	for _, tc := range badBatches {
		req, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/"+tc.repo+".git/info/lfs/objects/batch", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("bad LFS batch (%s): %v", tc.repo, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Fatalf("expected 4xx for %s %s, got %d", tc.repo, tc.body, resp.StatusCode)
		}
	}
	if _, _, lb, lu, _ := upstream.stats(); lb != 0 || lu != 0 {
		t.Fatalf("expected 0 upstream LFS calls on invalid/denied requests, got batch=%d bytes=%d", lb, lu)
	}

	// 2. Valid LFS upload batch -> rewrites href to gateway URL, strips upstream token from headers!
	upBatchBody, _ := json.Marshal(LFSBatchRequest{
		Operation: "upload",
		Transfers: []string{"basic"},
		Objects:   []LFSBatchObjectInput{{OID: oid, Size: int64(len(payload))}},
	})
	reqUp, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/info/lfs/objects/batch", bytes.NewReader(upBatchBody))
	reqUp.Header.Set("Authorization", "Bearer "+jwt)
	respUp, err := client.Do(reqUp)
	if err != nil || respUp.StatusCode != http.StatusOK {
		t.Fatalf("upload batch failed: resp=%v err=%v", respUp, err)
	}
	rawUpResp, _ := io.ReadAll(respUp.Body)
	_ = respUp.Body.Close()
	if strings.Contains(string(rawUpResp), writeTok) {
		t.Fatal("upstream write token leaked in LFS batch response headers!")
	}
	var parsedUp LFSBatchResponse
	if err := json.Unmarshal(rawUpResp, &parsedUp); err != nil {
		t.Fatalf("unmarshal upload batch: %v", err)
	}
	upAction := parsedUp.Objects[0].Actions["upload"]
	if !strings.HasPrefix(upAction.Href, gwTLS.URL+"/acme/service.git/info/lfs/objects/"+oid) {
		t.Fatalf("expected rewritten gateway href, got %q", upAction.Href)
	}

	// PUT mismatched SHA-256 -> 422 before upstream.
	reqBadPut, _ := http.NewRequest(http.MethodPut, upAction.Href, strings.NewReader("wrong bytes"))
	reqBadPut.Header.Set("Authorization", "Bearer "+jwt)
	rBadPut, err := client.Do(reqBadPut)
	if err != nil {
		t.Fatalf("PUT mismatch: %v", err)
	}
	_ = rBadPut.Body.Close()
	if rBadPut.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on PUT SHA-256 mismatch, got %d", rBadPut.StatusCode)
	}

	// Valid PUT upload.
	reqPut, _ := http.NewRequest(http.MethodPut, upAction.Href, bytes.NewReader(payload))
	reqPut.Header.Set("Authorization", "Bearer "+jwt)
	rPut, err := client.Do(reqPut)
	if err != nil || rPut.StatusCode != http.StatusOK {
		t.Fatalf("PUT LFS object failed: resp=%v err=%v", rPut, err)
	}
	_ = rPut.Body.Close()

	// 3. Valid download batch + GET object.
	dlBatchBody, _ := json.Marshal(LFSBatchRequest{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects:   []LFSBatchObjectInput{{OID: oid, Size: int64(len(payload))}},
	})
	reqDlBatch, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/info/lfs/objects/batch", bytes.NewReader(dlBatchBody))
	reqDlBatch.Header.Set("Authorization", "Bearer "+jwt)
	respDlBatch, err := client.Do(reqDlBatch)
	if err != nil || respDlBatch.StatusCode != http.StatusOK {
		t.Fatalf("download batch failed: resp=%v err=%v", respDlBatch, err)
	}
	var parsedDl LFSBatchResponse
	_ = json.NewDecoder(respDlBatch.Body).Decode(&parsedDl)
	_ = respDlBatch.Body.Close()
	dlHref := parsedDl.Objects[0].Actions["download"].Href

	reqGet, _ := http.NewRequest(http.MethodGet, dlHref, nil)
	reqGet.Header.Set("Authorization", "Bearer "+jwt)
	rGet, err := client.Do(reqGet)
	if err != nil || rGet.StatusCode != http.StatusOK {
		t.Fatalf("GET LFS object failed: resp=%v err=%v", rGet, err)
	}
	gotData, _ := io.ReadAll(rGet.Body)
	_ = rGet.Body.Close()
	if !bytes.Equal(gotData, payload) {
		t.Fatalf("downloaded LFS payload mismatch: got %q want %q", string(gotData), string(payload))
	}

	// Verify custodian_push_lfs_batch_requests_total metric incremented.
	mRec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(mRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(mRec.Body.String(), "custodian_push_lfs_batch_requests_total") {
		t.Fatalf("expected custodian_push_lfs_batch_requests_total in /metrics output:\n%s", mRec.Body.String())
	}
}

func TestSSHShallowCloneAndFetchDepthOne(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh binary not found in PATH")
	}

	writeTok := "ghs_write_ssh_shallow"
	upstream := newMockUpstreamGitServer(t, writeTok)
	upstream.seedBareRepo(t, "acme/shallow", map[string]string{"f0.txt": "c0\n"})
	// Seed >= 10 commits total (12 commits) cleanly in one workDir push so deepen/unshallow tests have deep history.
	{
		bareDir := upstream.repos["acme/shallow"]
		workDir := filepath.Join(t.TempDir(), "seed-history")
		runGit(t, "", "clone", bareDir, workDir)
		runGit(t, workDir, "config", "user.name", "Upstream Seed")
		runGit(t, workDir, "config", "user.email", "seed@example.com")
		for i := 1; i <= 11; i++ {
			rel := fmt.Sprintf("f%d.txt", i)
			if err := os.WriteFile(filepath.Join(workDir, rel), []byte(fmt.Sprintf("c%d\n", i)), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			runGit(t, workDir, "add", rel)
			runGit(t, workDir, "commit", "-m", fmt.Sprintf("commit %d", i))
		}
		runGit(t, workDir, "push", bareDir, "HEAD:refs/heads/main")
	}
	headSHA := strings.TrimSpace(runGit(t, upstream.repos["acme/shallow"], "rev-parse", "refs/heads/main"))
	const initialCommits = 12

	oidc := harness.StartMockOIDC(t, "custodian-api")
	pStore := newMemPrincipalStore()
	aliceID, _ := domain.NewID()
	pStore.seed(domain.Principal{
		ID:            aliceID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "alice-shallow-001",
		DisplayName:   "Alice",
		VerifiedEmail: "alice-shallow@example.com",
		CreatedAt:     time.Now().UTC(),
	}, []string{"eng"})

	rLookup := newMemRepoLookup()
	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    43,
		GitHubInstallationID:  78,
		FullName:              "acme/shallow",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RemoteHost:            "github.com",
		RegisteredDestination: true,
	})

	verifier, _ := auth.NewOIDCVerifier(auth.OIDCConfig{Issuer: oidc.Issuer(), JWKSURL: oidc.JWKSURL(), Audience: oidc.Audience()})
	dir, _ := identity.NewDirectory(pStore, identity.DefaultDirectoryConfig())

	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostSSHPub, _ := ssh.NewPublicKey(hostPub)
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caSSHPub, _ := ssh.NewPublicKey(caPub)

	authSvc, err := NewAuthenticator(AuthenticatorConfig{
		OIDC:          verifier,
		Directory:     dir,
		GroupUpserter: pStore,
		SSHLookup:     pStore,
		SSHHostKey:    hostSigner,
		SSHUserCA:     caSSHPub,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	resolver, _ := NewTargetResolver(TargetResolverConfig{Store: rLookup, UpstreamBaseURL: upstream.server.URL})
	_, writePEM := generateRSAPrivateKeyAndPEM(t)
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": writeTok, "expires_at": time.Now().UTC().Add(10 * time.Minute)})
	}))
	defer ghAPI.Close()
	broker, _ := NewTokenBroker(TokenBrokerConfig{APIBaseURL: ghAPI.URL, WriteAppID: 202, WritePrivateKeyPEM: writePEM})
	upClient, _ := NewHTTPUpstreamClient(HTTPUpstreamConfig{BaseURL: upstream.server.URL, AllowInsecureHTTP: true})

	srv, err := NewServer(ServerConfig{
		Authenticator:  authSvc,
		TargetResolver: resolver,
		TokenBroker:    broker,
		Upstream:       upClient,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	sshAddr := sshLn.Addr().String()
	go func() { _ = srv.SSHServer().Serve(sshLn) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.SSHServer().Shutdown(ctx)
	}()

	cert, _, caFile := generateLocalhostTLSCert(t)
	gwTLS := httptest.NewUnstartedServer(srv.HTTPHandler())
	gwTLS.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	gwTLS.StartTLS()
	defer gwTLS.Close()

	now := time.Now()
	validSigner, validKeyPEM := mintSSHUserCert(t, caSigner, []string{"alice-shallow-001"}, "alice-shallow-key", 2001, now.Add(-time.Minute), now.Add(time.Hour))
	sshDir := t.TempDir()
	keyPath := filepath.Join(sshDir, "id_ed25519")
	certPath := filepath.Join(sshDir, "id_ed25519-cert.pub")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	_ = os.WriteFile(keyPath, validKeyPEM, 0o600)
	_ = os.WriteFile(certPath, ssh.MarshalAuthorizedKey(validSigner.PublicKey()), 0o644)
	host, port, _ := net.SplitHostPort(sshAddr)
	khLine := fmt.Sprintf("[%s]:%s %s", host, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSSHPub))))
	_ = os.WriteFile(knownHostsPath, []byte(khLine+"\n"), 0o600)

	gitSSH := fmt.Sprintf("ssh -i %s -o CertificateFile=%s -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -p %s",
		keyPath, certPath, knownHostsPath, port)
	sshURL := fmt.Sprintf("ssh://git@%s:%s/acme/shallow.git", host, port)

	runSSHGit := func(dir string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var fullArgs []string
		if dir != "" {
			fullArgs = append(fullArgs, "-C", dir)
		}
		fullArgs = append(fullArgs, args...)
		cmd := exec.CommandContext(ctx, "git", fullArgs...)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
			"GIT_SSH_COMMAND=" + gitSSH,
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. git clone --depth=1 -> git fetch --depth=5 (WITHOUT new upstream commits) -> count == 5 + git fsck --full.
	cloneA := filepath.Join(t.TempDir(), "clone-depth5")
	if out, err := runSSHGit("", "clone", "--depth=1", sshURL, cloneA); err != nil {
		t.Fatalf("git clone --depth=1 failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(runGit(t, cloneA, "rev-parse", "HEAD")); got != headSHA {
		t.Fatalf("cloneA HEAD=%s want %s", got, headSHA)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneA, "rev-list", "--count", "HEAD")); cnt != "1" {
		t.Fatalf("expected cloneA commit count 1, got %s", cnt)
	}
	if out, err := runSSHGit(cloneA, "fetch", "--depth=5", "origin", "main"); err != nil {
		t.Fatalf("git fetch --depth=5 (no new commits) failed: %v\n%s", err, out)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneA, "rev-list", "--count", "FETCH_HEAD")); cnt != "5" {
		t.Fatalf("expected depth=5 commit count 5, got %s", cnt)
	}
	runGit(t, cloneA, "fsck", "--full")

	// 2. git clone --depth=1 -> git fetch --depth=2 (no new commits) -> git fetch --unshallow (no new commits) -> full count + fsck.
	cloneB := filepath.Join(t.TempDir(), "clone-depth2-unshallow")
	if out, err := runSSHGit("", "clone", "--depth=1", sshURL, cloneB); err != nil {
		t.Fatalf("cloneB failed: %v\n%s", err, out)
	}
	if out, err := runSSHGit(cloneB, "fetch", "--depth=2", "origin", "main"); err != nil {
		t.Fatalf("git fetch --depth=2 (no new commits) failed: %v\n%s", err, out)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneB, "rev-list", "--count", "FETCH_HEAD")); cnt != "2" {
		t.Fatalf("expected depth=2 commit count 2, got %s", cnt)
	}
	runGit(t, cloneB, "fsck", "--full")

	if out, err := runSSHGit(cloneB, "fetch", "--unshallow", "origin", "main"); err != nil {
		t.Fatalf("git fetch --unshallow (no new commits) failed: %v\n%s", err, out)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneB, "rev-list", "--count", "FETCH_HEAD")); cnt != fmt.Sprintf("%d", initialCommits) {
		t.Fatalf("expected unshallow commit count %d, got %s", initialCommits, cnt)
	}
	runGit(t, cloneB, "fsck", "--full")

	// 3. git push from a --depth=1 shallow clone over BOTH SSH and Smart-HTTP:
	//    - up-to-date 0000 no-op push succeeds with exit 0 and 0 upstream bytes
	//    - commit push hits DefaultFailClosedReceivePackHandler (NOT 400/ERR MALFORMED_PKT_LINE) with 0 upstream bytes
	clonePush := filepath.Join(t.TempDir(), "clone-shallow-push")
	if out, err := runSSHGit("", "clone", "--depth=1", sshURL, clonePush); err != nil {
		t.Fatalf("clonePush failed: %v\n%s", err, out)
	}
	if out, err := runSSHGit(clonePush, "push", sshURL, "HEAD:refs/heads/main"); err != nil {
		t.Fatalf("expected SSH 0000 no-op push from shallow clone to succeed, got %v\n%s", err, out)
	}

	jwt := oidc.MintHumanToken("alice-shallow-001", "alice-shallow@example.com", "Alice")
	httpURL := strings.Replace(gwTLS.URL, "https://", "https://x-access-token:"+jwt+"@", 1) + "/acme/shallow.git"
	noopHTTPCmd := exec.Command("git", "-C", clonePush, "-c", "http.sslCAInfo="+caFile, "push", httpURL, "HEAD:refs/heads/main")
	noopHTTPCmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := noopHTTPCmd.CombinedOutput(); err != nil {
		t.Fatalf("expected Smart-HTTP 0000 no-op push from shallow clone to succeed, got %v\n%s", err, string(out))
	}

	runGit(t, clonePush, "config", "user.name", "Alice")
	runGit(t, clonePush, "config", "user.email", "alice-shallow@example.com")
	_ = os.WriteFile(filepath.Join(clonePush, "shallow_local.txt"), []byte("shallow push\n"), 0o600)
	runGit(t, clonePush, "add", "shallow_local.txt")
	runGit(t, clonePush, "commit", "-m", "shallow local commit")

	sshPushOut, sshPushErr := runSSHGit(clonePush, "push", sshURL, "HEAD:refs/heads/shallow-feat")
	if sshPushErr == nil {
		t.Fatalf("expected SSH shallow commit push to hit fail-closed handler, got success:\n%s", sshPushOut)
	}
	if strings.Contains(sshPushOut, "must contain old-oid") || !strings.Contains(sshPushOut, "ENFORCE_BLOCK") {
		t.Fatalf("expected SSH shallow commit push to reach DefaultFailClosedReceivePackHandler (ENFORCE_BLOCK), got:\n%s", sshPushOut)
	}

	httpPushCmd := exec.Command("git", "-C", clonePush, "-c", "http.sslCAInfo="+caFile, "push", httpURL, "HEAD:refs/heads/shallow-feat")
	httpPushCmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	httpPushOut, httpPushErr := httpPushCmd.CombinedOutput()
	if httpPushErr == nil {
		t.Fatalf("expected Smart-HTTP shallow commit push to hit fail-closed handler (503), got success:\n%s", string(httpPushOut))
	}
	if strings.Contains(string(httpPushOut), "MALFORMED_PKT_LINE") || strings.Contains(string(httpPushOut), "400") || !strings.Contains(string(httpPushOut), "503") {
		t.Fatalf("expected Smart-HTTP shallow commit push to reach ReceivePackHandler (503), got:\n%s", string(httpPushOut))
	}
	if rc, rb, _, _, _ := upstream.stats(); rc != 0 || rb != 0 {
		t.Fatalf("expected 0 upstream receive-pack calls/bytes on shallow pushes, got calls=%d bytes=%d", rc, rb)
	}

	// 4. git clone --depth=1 -> new commit pushed upstream -> git fetch --unshallow -> full count + fsck.
	cloneD := filepath.Join(t.TempDir(), "clone-unshallow-new")
	if out, err := runSSHGit("", "clone", "--depth=1", sshURL, cloneD); err != nil {
		t.Fatalf("cloneD failed: %v\n%s", err, out)
	}
	nextSHA := upstream.addCommitToRepo(t, "acme/shallow", "f12.txt", "c12\n")
	if out, err := runSSHGit(cloneD, "fetch", "--unshallow", "origin", "main"); err != nil {
		t.Fatalf("git fetch --unshallow (with new upstream commit) failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(runGit(t, cloneD, "rev-parse", "FETCH_HEAD")); got != nextSHA {
		t.Fatalf("cloneD FETCH_HEAD=%s want %s", got, nextSHA)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneD, "rev-list", "--count", "FETCH_HEAD")); cnt != fmt.Sprintf("%d", initialCommits+1) {
		t.Fatalf("expected unshallow-with-new-commit count %d, got %s", initialCommits+1, cnt)
	}
	runGit(t, cloneD, "fsck", "--full")

	// 5. Incremental shallow fetch (--depth=1 -> advance upstream -> --depth=1 -> --depth=2).
	cloneE := filepath.Join(t.TempDir(), "clone-inc")
	if out, err := runSSHGit("", "clone", "--depth=1", sshURL, cloneE); err != nil {
		t.Fatalf("cloneE failed: %v\n%s", err, out)
	}
	nextSHA2 := upstream.addCommitToRepo(t, "acme/shallow", "f13.txt", "c13\n")
	if out, err := runSSHGit(cloneE, "fetch", "--depth=1", "origin", "main"); err != nil {
		t.Fatalf("git fetch --depth=1 over SSH failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(runGit(t, cloneE, "rev-parse", "FETCH_HEAD")); got != nextSHA2 {
		t.Fatalf("shallow fetch FETCH_HEAD=%s want %s", got, nextSHA2)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneE, "rev-list", "--count", "FETCH_HEAD")); cnt != "1" {
		t.Fatalf("expected shallow fetch --depth=1 commit count 1, got %s", cnt)
	}
	if out, err := runSSHGit(cloneE, "fetch", "--depth=2", "origin", "main"); err != nil {
		t.Fatalf("git fetch --depth=2 over SSH failed: %v\n%s", err, out)
	}
	if cnt := strings.TrimSpace(runGit(t, cloneE, "rev-list", "--count", "FETCH_HEAD")); cnt != "2" {
		t.Fatalf("expected deepened commit count 2, got %s", cnt)
	}
	runGit(t, cloneE, "fsck", "--full")
}

func TestShallowReceivePackParsingAndStripHelpers(t *testing.T) {
	oid1 := strings.Repeat("a", 40)
	oid2 := strings.Repeat("b", 40)
	oid256 := strings.Repeat("c", 64)

	// 1. parseReceivePackCommands accepts shallow <oid> before ref-update + preserves capabilities.
	var wire bytes.Buffer
	wire.Write(formatPktLine([]byte("shallow " + oid1 + "\n")))
	wire.Write(formatPktLine([]byte(quarantine.ZeroOID + " " + oid2 + " refs/heads/feat\x00report-status side-band-64k\n")))
	_ = writeFlushPkt(&wire)
	cmds, caps, err := parseReceivePackCommands(&wire, 10)
	if err != nil {
		t.Fatalf("parseReceivePackCommands(shallow+cmd): %v", err)
	}
	if len(cmds) != 1 || cmds[0].RefName != "refs/heads/feat" || cmds[0].NewOID != oid2 {
		t.Fatalf("unexpected cmds: %+v", cmds)
	}
	if !slices.Contains(caps, "report-status") || !slices.Contains(caps, "side-band-64k") {
		t.Fatalf("capabilities lost after shallow line: %v", caps)
	}

	// 2. SHA-256 shallow OID + 0000 no-op push yields len(cmds)==0 without error.
	var noopWire bytes.Buffer
	noopWire.Write(formatPktLine([]byte("shallow " + oid256 + "\n")))
	_ = writeFlushPkt(&noopWire)
	cmds, caps, err = parseReceivePackCommands(&noopWire, 10)
	if err != nil || len(cmds) != 0 || len(caps) != 0 {
		t.Fatalf("expected empty cmds/caps for shallow no-op, got cmds=%+v caps=%v err=%v", cmds, caps, err)
	}

	// 3. Malformed shallow OID or shallow after ref-update command must fail closed.
	for _, bad := range [][]byte{
		formatPktLine([]byte("shallow not-hex\n")),
		append(formatPktLine([]byte(quarantine.ZeroOID+" "+oid2+" refs/heads/main\x00report-status\n")), formatPktLine([]byte("shallow "+oid1+"\n"))...),
	} {
		if _, _, err := parseReceivePackCommands(bytes.NewReader(append(bad, []byte("0000")...)), 10); err == nil {
			t.Fatalf("expected malformed shallow receive-pack input to fail: %q", string(bad))
		}
	}

	// 4. stripLeadingShallowSection strips leading shallow/unshallow...0000 and empty 0000, but never strips non-shallow responses.
	var withShallow bytes.Buffer
	withShallow.Write(formatPktLine([]byte("shallow " + oid1 + "\n")))
	withShallow.Write(formatPktLine([]byte("unshallow " + oid2 + "\n")))
	_ = writeFlushPkt(&withShallow)
	withShallow.Write(formatPktLine([]byte("NAK\n")))
	if got := stripLeadingShallowSection(withShallow.Bytes()); !bytes.Equal(got, formatPktLine([]byte("NAK\n"))) {
		t.Fatalf("stripLeadingShallowSection(shallow+unshallow): got %q", string(got))
	}

	emptyShallow := append([]byte("0000"), formatPktLine([]byte("NAK\n"))...)
	if got := stripLeadingShallowSection(emptyShallow); !bytes.Equal(got, formatPktLine([]byte("NAK\n"))) {
		t.Fatalf("stripLeadingShallowSection(empty 0000): got %q", string(got))
	}

	plainNAK := formatPktLine([]byte("NAK\n"))
	if got := stripLeadingShallowSection(plainNAK); !bytes.Equal(got, plainNAK) {
		t.Fatalf("stripLeadingShallowSection(plain NAK) modified response: got %q", string(got))
	}

	// 5. SSH upload-pack turn reader rejects turns exceeding sshMaxUploadPackTurnBytes.
	line := formatPktLine([]byte("want " + oid1 + "\n")) // 50 bytes per line
	oversizedTurn := bytes.Repeat(line, (sshMaxUploadPackTurnBytes/len(line))+2)
	if _, _, err := readSSHUploadPackTurn(bytes.NewReader(oversizedTurn), true); err == nil {
		t.Fatal("expected readSSHUploadPackTurn to reject oversized turn")
	}
	if _, _, _, err := readSSHUloadPackNegotiationTurn(bytes.NewReader(oversizedTurn)); err == nil {
		t.Fatal("expected readSSHUloadPackNegotiationTurn to reject oversized turn")
	}
}

type drainingReceivePackHandler struct {
	drainedBytes int64
	readErr      error
}

func (d *drainingReceivePackHandler) HandleReceivePack(_ context.Context, req ReceivePackRequest) (ReceivePackOutcome, error) {
	n, err := io.Copy(io.Discard, req.PackReader)
	d.drainedBytes = n
	d.readErr = err
	if err != nil {
		return ReceivePackOutcome{}, err
	}
	return ReceivePackOutcome{
		Status:     domain.PushSessionStatusAllowed,
		Effect:     domain.PolicyEffectAllow,
		UnpackOK:   true,
		HTTPStatus: http.StatusOK,
	}, nil
}

type errUpstreamClient struct {
	UpstreamClient
	uploadErr error
}

func (e *errUpstreamClient) UploadPack(context.Context, string, string, io.Reader, io.Writer) (int, error) {
	return 0, e.uploadErr
}

func TestSmartHTTPGzipBombsPackBoundsAndErrorSanitization(t *testing.T) {
	writeTok := "ghs_write_bounds_secret"
	upstream := newMockUpstreamGitServer(t, writeTok)
	upstream.seedBareRepo(t, "acme/service", map[string]string{"README.md": "bounds\n"})

	drainingHandler := &drainingReceivePackHandler{}
	srv, _, rLookup, oidc, _ := newGatewayTestHarness(t, upstream, drainingHandler)
	// Override Limits to 64 KiB MaxPackBytes and default 100 MaxRefUpdates.
	srv.limits.MaxPackBytes = 64 << 10
	srv.limits.MaxRefUpdates = 100

	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    42,
		GitHubInstallationID:  77,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RegisteredDestination: true,
	})

	cert, pool, _ := generateLocalhostTLSCert(t)
	gwTLS := httptest.NewUnstartedServer(srv.HTTPHandler())
	gwTLS.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	gwTLS.StartTLS()
	defer gwTLS.Close()

	jwt := oidc.MintHumanToken("alice-001", "alice@example.com", "Alice")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	gzipBytes := func(raw []byte) []byte {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = gw.Write(raw)
		_ = gw.Close()
		return buf.Bytes()
	}

	// 1. 512 KiB gzipped pack rejected when MaxPackBytes = 64 KiB (413 PACK_TOO_LARGE, 0 upstream calls).
	cmdLine := fmt.Sprintf("%s %s refs/heads/main\x00report-status\n", quarantine.ZeroOID, strings.Repeat("1", 40))
	var recv512 bytes.Buffer
	recv512.Write(formatPktLine([]byte(cmdLine)))
	_ = writeFlushPkt(&recv512)
	recv512.Write(bytes.Repeat([]byte("A"), 512<<10))
	gz512 := gzipBytes(recv512.Bytes())

	req512, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", bytes.NewReader(gz512))
	req512.Header.Set("Authorization", "Bearer "+jwt)
	req512.Header.Set("Content-Encoding", "gzip")
	resp512, err := client.Do(req512)
	if err != nil {
		t.Fatalf("512 KiB gzipped receive-pack request failed: %v", err)
	}
	body512, _ := io.ReadAll(resp512.Body)
	_ = resp512.Body.Close()
	if resp512.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body512), "PACK_TOO_LARGE") {
		t.Fatalf("expected 413 PACK_TOO_LARGE for 512 KiB pack (MaxPackBytes=64 KiB), got %d body=%s", resp512.StatusCode, string(body512))
	}
	if !errors.Is(drainingHandler.readErr, errStreamLimitExceeded) {
		t.Fatalf("expected errStreamLimitExceeded in PackReader, got %v", drainingHandler.readErr)
	}

	// 2. Pack right at MaxPackBytes (64 KiB) + pkt-line command header NOT prematurely rejected by Content-Length.
	var exact64 bytes.Buffer
	exact64.Write(formatPktLine([]byte(cmdLine)))
	_ = writeFlushPkt(&exact64)
	exact64.Write(bytes.Repeat([]byte("B"), 64<<10))
	reqExact, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", bytes.NewReader(exact64.Bytes()))
	reqExact.Header.Set("Authorization", "Bearer "+jwt)
	respExact, err := client.Do(reqExact)
	if err != nil {
		t.Fatalf("exact 64 KiB receive-pack failed: %v", err)
	}
	bodyExact, _ := io.ReadAll(respExact.Body)
	_ = respExact.Body.Close()
	if respExact.StatusCode != http.StatusOK || drainingHandler.drainedBytes != 64<<10 {
		t.Fatalf("expected 200 and 65536 pack bytes for MaxPackBytes+header, got status=%d drained=%d body=%s", respExact.StatusCode, drainingHandler.drainedBytes, string(bodyExact))
	}

	// 3. Gzip bomb in pkt-line command area (> 2 MiB) returns 413 PACK_TOO_LARGE (not 400 MALFORMED_PKT_LINE).
	var pktBomb bytes.Buffer
	padRef := "refs/heads/bomb-" + strings.Repeat("a", 60000)
	for i := 0; i < 40; i++ {
		line := fmt.Sprintf("%s %s %s-%02d\n", quarantine.ZeroOID, strings.Repeat("1", 40), padRef, i)
		pktBomb.Write(formatPktLine([]byte(line)))
	}
	gzPktBomb := gzipBytes(pktBomb.Bytes())
	reqPktBomb, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-receive-pack", bytes.NewReader(gzPktBomb))
	reqPktBomb.Header.Set("Authorization", "Bearer "+jwt)
	reqPktBomb.Header.Set("Content-Encoding", "gzip")
	respPktBomb, err := client.Do(reqPktBomb)
	if err != nil {
		t.Fatalf("pkt-line gzip bomb request failed: %v", err)
	}
	bodyPktBomb, _ := io.ReadAll(respPktBomb.Body)
	_ = respPktBomb.Body.Close()
	if respPktBomb.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(bodyPktBomb), "PACK_TOO_LARGE") {
		t.Fatalf("expected 413 PACK_TOO_LARGE for pkt-line gzip bomb, got %d body=%s", respPktBomb.StatusCode, string(bodyPktBomb))
	}

	// 4. 5 MiB gzip bomb on git-upload-pack rejected with 413 and 0 upstream calls.
	upstream.mu.Lock()
	upBefore := upstream.uploadPackCalls
	upstream.mu.Unlock()

	gzUploadBomb := gzipBytes(bytes.Repeat([]byte("0032want "+strings.Repeat("a", 40)+"\n"), 110000)) // ~5.5 MiB uncompressed
	reqUpBomb, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-upload-pack", bytes.NewReader(gzUploadBomb))
	reqUpBomb.Header.Set("Authorization", "Bearer "+jwt)
	reqUpBomb.Header.Set("Content-Encoding", "gzip")
	respUpBomb, err := client.Do(reqUpBomb)
	if err != nil {
		t.Fatalf("upload-pack gzip bomb request failed: %v", err)
	}
	bodyUpBomb, _ := io.ReadAll(respUpBomb.Body)
	_ = respUpBomb.Body.Close()
	if respUpBomb.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on upload-pack 5 MiB gzip bomb, got %d body=%s", respUpBomb.StatusCode, string(bodyUpBomb))
	}
	upstream.mu.Lock()
	upAfter := upstream.uploadPackCalls
	upstream.mu.Unlock()
	if upAfter != upBefore {
		t.Fatalf("expected 0 upstream upload-pack calls on gzip bomb, got delta=%d", upAfter-upBefore)
	}

	// Oversized Content-Length on git-upload-pack -> 413 and 0 upstream calls.
	reqUpCL, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-upload-pack", strings.NewReader("0000"))
	reqUpCL.Header.Set("Authorization", "Bearer "+jwt)
	reqUpCL.ContentLength = 10 << 20
	respUpCL, err := client.Do(reqUpCL)
	if err == nil {
		_ = respUpCL.Body.Close()
		if respUpCL.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 for upload-pack oversized Content-Length, got %d", respUpCL.StatusCode)
		}
	}

	// 5. Non-*domain.DomainError errors in writeGatewayError do NOT expose raw err.Error().
	var logBuf bytes.Buffer
	srv.logger = slog.New(slog.NewTextHandler(&logBuf, nil))
	srv.upstream = &errUpstreamClient{
		UpstreamClient: srv.upstream,
		uploadErr:      errors.New("raw internal tcp dial secret_host:1234 failed"),
	}
	reqRawErr, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/git-upload-pack", strings.NewReader("0000"))
	reqRawErr.Header.Set("Authorization", "Bearer "+jwt)
	respRawErr, err := client.Do(reqRawErr)
	if err != nil {
		t.Fatalf("raw error test request failed: %v", err)
	}
	bodyRawErr, _ := io.ReadAll(respRawErr.Body)
	_ = respRawErr.Body.Close()
	if respRawErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on non-domain error, got %d body=%s", respRawErr.StatusCode, string(bodyRawErr))
	}
	if strings.Contains(string(bodyRawErr), "secret_host") || !strings.Contains(string(bodyRawErr), "internal gateway error") {
		t.Fatalf("expected sanitized internal gateway error without raw err.Error(), got %s", string(bodyRawErr))
	}
	if !strings.Contains(logBuf.String(), "secret_host") {
		t.Fatalf("expected sanitized server-side error log, got %s", logBuf.String())
	}

	if rc, rb, _, _, _ := upstream.stats(); rc != 0 || rb != 0 {
		t.Fatalf("expected 0 upstream receive-pack calls/bytes, got %d / %d", rc, rb)
	}
}

type badOIDUpstream struct {
	UpstreamClient
}

func (b *badOIDUpstream) LFSBatch(context.Context, string, string, LFSBatchRequest) (int, LFSBatchResponse, []byte, error) {
	return http.StatusOK, LFSBatchResponse{
		Transfer: "basic",
		Objects: []LFSBatchObjectResponse{
			{
				OID:  "../../etc/passwd",
				Size: 12,
				Actions: map[string]LFSAction{
					"download": {Href: "https://upstream.example/obj"},
				},
			},
		},
	}, nil, nil
}

func TestLFSBatchRejectsInvalidUpstreamOIDAndTokenBrokerUnregisteredGuard(t *testing.T) {
	upstream := newMockUpstreamGitServer(t, "ghs_tok")
	srv, _, rLookup, oidc, _ := newGatewayTestHarness(t, upstream, nil)
	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    42,
		GitHubInstallationID:  77,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RegisteredDestination: true,
	})
	srv.upstream = &badOIDUpstream{UpstreamClient: srv.upstream}

	cert, pool, _ := generateLocalhostTLSCert(t)
	gwTLS := httptest.NewUnstartedServer(srv.HTTPHandler())
	gwTLS.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	gwTLS.StartTLS()
	defer gwTLS.Close()

	jwt := oidc.MintHumanToken("alice-001", "alice@example.com", "Alice")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}

	validOID := strings.Repeat("a", 64)
	batchBody := fmt.Sprintf(`{"operation":"download","objects":[{"oid":%q,"size":12}]}`, validOID)
	req, _ := http.NewRequest(http.MethodPost, gwTLS.URL+"/acme/service.git/info/lfs/objects/batch", strings.NewReader(batchBody))
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("LFS batch request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "UPSTREAM_LFS_INVALID_OID") {
		t.Fatalf("expected 502 UPSTREAM_LFS_INVALID_OID for invalid upstream OID, got %d body=%s", resp.StatusCode, string(body))
	}

	// TokenBroker must NOT fall back to GET /app/installations list[0].ID when target.Repository == nil.
	_, writePEM := generateRSAPrivateKeyAndPEM(t)
	var globalListCalls int
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations":
			globalListCalls++
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 999}})
		case "/app/installations/999/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      "ghs_global_fallback_should_only_work_for_registered",
				"expires_at": time.Now().UTC().Add(10 * time.Minute),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghAPI.Close()

	broker, err := NewTokenBroker(TokenBrokerConfig{
		APIBaseURL:         ghAPI.URL,
		WriteAppID:         202,
		WritePrivateKeyPEM: writePEM,
		DisableTokenCache:  true,
	})
	if err != nil {
		t.Fatalf("NewTokenBroker: %v", err)
	}

	caller := AuthenticatedPrincipal{AuthMethod: "oidc", OIDCToken: "eyJ_oidc"}
	unregTarget := ResolvedTarget{OwnerRepo: "unregistered/personal", Repository: nil}
	_, err = broker.ResolveUpstreamAuth(context.Background(), TokenScopeWrite, caller, unregTarget)
	var de *domain.DomainError
	if !errors.As(err, &de) || de.Code() != "GITHUB_INSTALLATION_NOT_FOUND" {
		t.Fatalf("expected GITHUB_INSTALLATION_NOT_FOUND for unregistered target, got %v", err)
	}
	if globalListCalls != 0 {
		t.Fatalf("expected 0 GET /app/installations calls for unregistered target, got %d", globalListCalls)
	}

	// Registered repository with GitHubInstallationID == 0 may still fall back when /repos/.../installation 404s.
	regTarget := ResolvedTarget{
		OwnerRepo: "acme/registered-no-inst-id",
		Repository: &domain.Repository{
			GitHubRepositoryID: 123,
			FullName:           "acme/registered-no-inst-id",
			Enabled:            true,
		},
	}
	resReg, err := broker.ResolveUpstreamAuth(context.Background(), TokenScopeWrite, caller, regTarget)
	if err != nil || resReg.Token == "" {
		t.Fatalf("expected registered repository fallback to succeed, got res=%+v err=%v", resReg, err)
	}
	if globalListCalls != 1 {
		t.Fatalf("expected 1 GET /app/installations call for registered target fallback, got %d", globalListCalls)
	}
}

type sshPureDeleteHandler struct {
	mu        sync.Mutex
	calls     int
	lastRefs  []quarantine.RefUpdate
	packBytes int64
}

func (h *sshPureDeleteHandler) HandleReceivePack(_ context.Context, req ReceivePackRequest) (ReceivePackOutcome, error) {
	n, err := io.Copy(io.Discard, req.PackReader)
	if err != nil {
		return ReceivePackOutcome{}, err
	}
	if req.SidebandWriter != nil {
		_, _ = io.WriteString(req.SidebandWriter, "ALLOW: pure deletion verified\n")
	}
	h.mu.Lock()
	h.calls++
	h.lastRefs = append([]quarantine.RefUpdate(nil), req.RefUpdates...)
	h.packBytes = n
	h.mu.Unlock()

	results := make([]RefResult, 0, len(req.RefUpdates))
	for _, ru := range req.RefUpdates {
		results = append(results, RefResult{
			RefName: ru.RefName,
			OK:      true,
		})
	}
	return ReceivePackOutcome{
		Status:     domain.PushSessionStatusCompleted,
		Effect:     domain.PolicyEffectAllow,
		UnpackOK:   true,
		RefResults: results,
		HTTPStatus: http.StatusOK,
	}, nil
}

func TestSSHPureDeletionDoesNotDeadlockOnOpenStdin(t *testing.T) {
	writeTok := "ghs_write_ssh_del_secret"
	upstream := newMockUpstreamGitServer(t, writeTok)
	headSHA := upstream.seedBareRepo(t, "acme/service", map[string]string{"hello.txt": "ssh delete test\n"})
	runGit(t, upstream.repos["acme/service"], "update-ref", "refs/heads/feat/to-delete", headSHA)

	oidc := harness.StartMockOIDC(t, "custodian-api")
	pStore := newMemPrincipalStore()
	aliceID, _ := domain.NewID()
	pStore.seed(domain.Principal{
		ID:            aliceID,
		Kind:          domain.PrincipalKindHuman,
		Issuer:        oidc.Issuer(),
		Subject:       "alice-del-001",
		DisplayName:   "Alice",
		VerifiedEmail: "alice-del@example.com",
		CreatedAt:     time.Now().UTC(),
	}, []string{"eng"})

	rLookup := newMemRepoLookup()
	repoID, _ := domain.NewID()
	rLookup.add(persistence.RepositoryRow{
		ID:                    repoID,
		GitHubRepositoryID:    44,
		GitHubInstallationID:  79,
		FullName:              "acme/service",
		Classification:        domain.ClassificationInternal,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryAsync,
		RemoteHost:            "github.com",
		RegisteredDestination: true,
	})

	verifier, _ := auth.NewOIDCVerifier(auth.OIDCConfig{Issuer: oidc.Issuer(), JWKSURL: oidc.JWKSURL(), Audience: oidc.Audience()})
	dir, _ := identity.NewDirectory(pStore, identity.DefaultDirectoryConfig())

	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	hostSSHPub, _ := ssh.NewPublicKey(hostPub)
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	caSSHPub, _ := ssh.NewPublicKey(caPub)

	authSvc, err := NewAuthenticator(AuthenticatorConfig{
		OIDC:          verifier,
		Directory:     dir,
		GroupUpserter: pStore,
		SSHLookup:     pStore,
		SSHHostKey:    hostSigner,
		SSHUserCA:     caSSHPub,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	resolver, _ := NewTargetResolver(TargetResolverConfig{Store: rLookup, UpstreamBaseURL: upstream.server.URL})
	_, writePEM := generateRSAPrivateKeyAndPEM(t)
	ghAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token": writeTok, "expires_at": time.Now().UTC().Add(10 * time.Minute)})
	}))
	defer ghAPI.Close()
	broker, _ := NewTokenBroker(TokenBrokerConfig{APIBaseURL: ghAPI.URL, WriteAppID: 202, WritePrivateKeyPEM: writePEM})
	upClient, _ := NewHTTPUpstreamClient(HTTPUpstreamConfig{BaseURL: upstream.server.URL, AllowInsecureHTTP: true})

	delHandler := &sshPureDeleteHandler{}
	srv, err := NewServer(ServerConfig{
		Authenticator:      authSvc,
		TargetResolver:     resolver,
		TokenBroker:        broker,
		Upstream:           upClient,
		ReceivePackHandler: delHandler,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	sshAddr := sshLn.Addr().String()
	go func() { _ = srv.SSHServer().Serve(sshLn) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.SSHServer().Shutdown(ctx)
	}()

	now := time.Now()
	validSigner, validKeyPEM := mintSSHUserCert(t, caSigner, []string{"alice-del-001"}, "alice-del-key", 3001, now.Add(-time.Minute), now.Add(time.Hour))

	sshClient, err := ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(validSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostSSHPub),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	defer sshClient.Close()

	// 1. Open-stdin pure deletion: client writes ref deletion + 0000 and keeps stdin open waiting for report-status.
	sess1, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession(1): %v", err)
	}
	stdin1, err := sess1.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe(1): %v", err)
	}
	stdout1, err := sess1.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe(1): %v", err)
	}
	var stderr1 bytes.Buffer
	sess1.Stderr = &stderr1
	if err := sess1.Start("git-receive-pack '/acme/service.git'"); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	// Read ref advertisement until 0000 flush.
	advDone := make(chan error, 1)
	go func() {
		for {
			_, flush, rerr := readPktLine(stdout1)
			if rerr != nil {
				advDone <- rerr
				return
			}
			if flush {
				advDone <- nil
				return
			}
		}
	}()
	select {
	case rerr := <-advDone:
		if rerr != nil {
			t.Fatalf("reading ref advertisement: %v", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading git-receive-pack ref advertisement")
	}

	// Send pure deletion command + 0000 WITHOUT closing stdin1!
	var reqWire bytes.Buffer
	reqWire.Write(formatPktLine([]byte(fmt.Sprintf("%s %s refs/heads/feat/to-delete\x00report-status delete-refs side-band-64k\n", headSHA, quarantine.ZeroOID))))
	_ = writeFlushPkt(&reqWire)
	if _, err := stdin1.Write(reqWire.Bytes()); err != nil {
		t.Fatalf("writing pure deletion command: %v", err)
	}

	// Server must respond promptly with sideband report-status while stdin1 remains open.
	type reportRes struct {
		raw string
		err error
	}
	repCh := make(chan reportRes, 1)
	go func() {
		var sb bytes.Buffer
		for {
			payload, flush, rerr := readPktLine(stdout1)
			if rerr != nil {
				repCh <- reportRes{raw: sb.String(), err: rerr}
				return
			}
			if flush {
				repCh <- reportRes{raw: sb.String(), err: nil}
				return
			}
			sb.Write(payload)
		}
	}()
	select {
	case res := <-repCh:
		if res.err != nil {
			t.Fatalf("reading report-status: %v (stderr=%s)", res.err, stderr1.String())
		}
		if !strings.Contains(res.raw, "unpack ok\n") || !strings.Contains(res.raw, "ok refs/heads/feat/to-delete\n") {
			t.Fatalf("expected report-status unpack ok + ok refs/heads/feat/to-delete, got %q", res.raw)
		}
		if !strings.Contains(res.raw, "ALLOW: pure deletion verified") {
			t.Fatalf("expected sideband-2 verdict message, got %q", res.raw)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSH git-receive-pack deadlocked waiting for stdin EOF on pure branch deletion")
	}

	// Only close stdin1 AFTER report-status has been received, matching git send-pack.
	_ = stdin1.Close()
	waitCh1 := make(chan error, 1)
	go func() { waitCh1 <- sess1.Wait() }()
	select {
	case werr := <-waitCh1:
		if werr != nil {
			t.Fatalf("sess1.Wait failed: %v (stderr=%s)", werr, stderr1.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SSH session 1 exit")
	}

	delHandler.mu.Lock()
	if delHandler.calls != 1 || delHandler.packBytes != 0 || len(delHandler.lastRefs) != 1 ||
		delHandler.lastRefs[0].RefName != "refs/heads/feat/to-delete" || delHandler.lastRefs[0].NewOID != quarantine.ZeroOID {
		delHandler.mu.Unlock()
		t.Fatalf("unexpected handler state after pure deletion: calls=%d packBytes=%d refs=%+v",
			delHandler.calls, delHandler.packBytes, delHandler.lastRefs)
	}
	delHandler.mu.Unlock()

	// 2. Fail-closed if client sends unexpected pack data buffered after pure-deletion 0000.
	sess2, err := sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession(2): %v", err)
	}
	stdin2, err := sess2.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe(2): %v", err)
	}
	stdout2, err := sess2.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe(2): %v", err)
	}
	var stderr2 bytes.Buffer
	sess2.Stderr = &stderr2
	if err := sess2.Start("git-receive-pack '/acme/service.git'"); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	for {
		_, flush, rerr := readPktLine(stdout2)
		if rerr != nil {
			t.Fatalf("reading adv(2): %v", rerr)
		}
		if flush {
			break
		}
	}
	var badWire bytes.Buffer
	badWire.Write(reqWire.Bytes())
	badWire.WriteString("PACK\x00\x00\x00\x02\x00\x00\x00\x00")
	_, _ = stdin2.Write(badWire.Bytes())
	_ = stdin2.Close()
	if werr := sess2.Wait(); werr == nil {
		t.Fatalf("expected SSH pure-deletion with trailing PACK bytes to fail closed")
	}
	if !strings.Contains(stderr2.String(), "unexpected pack data") {
		t.Fatalf("expected unexpected pack data error on stderr, got %q", stderr2.String())
	}
	delHandler.mu.Lock()
	if delHandler.calls != 1 {
		delHandler.mu.Unlock()
		t.Fatalf("expected HandleReceivePack NOT to be called on unexpected trailing pack data, got calls=%d", delHandler.calls)
	}
	delHandler.mu.Unlock()

	// 3. Real git push :refs/heads/feat/to-delete over SSH completes without deadlock.
	if _, lookErr := exec.LookPath("ssh"); lookErr == nil {
		sshDir := t.TempDir()
		keyPath := filepath.Join(sshDir, "id_ed25519")
		certPath := filepath.Join(sshDir, "id_ed25519-cert.pub")
		knownHostsPath := filepath.Join(sshDir, "known_hosts")
		_ = os.WriteFile(keyPath, validKeyPEM, 0o600)
		_ = os.WriteFile(certPath, ssh.MarshalAuthorizedKey(validSigner.PublicKey()), 0o644)
		host, port, _ := net.SplitHostPort(sshAddr)
		khLine := fmt.Sprintf("[%s]:%s %s", host, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSSHPub))))
		_ = os.WriteFile(knownHostsPath, []byte(khLine+"\n"), 0o600)

		gitSSH := fmt.Sprintf("ssh -i %s -o CertificateFile=%s -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -p %s",
			keyPath, certPath, knownHostsPath, port)
		sshURL := fmt.Sprintf("ssh://git@%s:%s/acme/service.git", host, port)

		cloneDir := filepath.Join(t.TempDir(), "ssh-del-clone")
		cloneCtx, cloneCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cloneCancel()
		cloneCmd := exec.CommandContext(cloneCtx, "git", "clone", sshURL, cloneDir)
		cloneCmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH, "GIT_TERMINAL_PROMPT=0")
		if out, err := cloneCmd.CombinedOutput(); err != nil {
			t.Fatalf("git clone over SSH failed: %v\n%s", err, string(out))
		}

		delCtx, delCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer delCancel()
		delCmd := exec.CommandContext(delCtx, "git", "-C", cloneDir, "push", sshURL, ":refs/heads/feat/to-delete")
		delCmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSH, "GIT_TERMINAL_PROMPT=0")
		if out, err := delCmd.CombinedOutput(); err != nil {
			t.Fatalf("real git push :refs/heads/feat/to-delete over SSH failed: %v\n%s", err, string(out))
		}
		delHandler.mu.Lock()
		if delHandler.calls != 2 || delHandler.packBytes != 0 {
			delHandler.mu.Unlock()
			t.Fatalf("expected 2nd handler call with 0 packBytes, got calls=%d packBytes=%d", delHandler.calls, delHandler.packBytes)
		}
		delHandler.mu.Unlock()
	}
}
