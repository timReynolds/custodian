package e2e_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

func m2BuildIncompressibleBytes(t testing.TB, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read(%d): %v", n, err)
	}
	return buf
}

// m2BuildExactSizeTarGz builds a valid .tar.gz archive whose exact compressed byte length equals targetBytes.
func m2BuildExactSizeTarGz(t testing.TB, targetBytes int64) ([]byte, string) {
	t.Helper()
	if targetBytes <= 0 {
		t.Fatalf("m2BuildExactSizeTarGz: targetBytes must be > 0, got %d", targetBytes)
	}

	baseEntries := []harness.TarEntry{
		{Name: "README.md", Body: []byte("# boundary upload\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	}
	mtime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	encodeTar := func(entries []harness.TarEntry) []byte {
		var tarBuf bytes.Buffer
		tw := tar.NewWriter(&tarBuf)
		for _, e := range entries {
			if err := tw.WriteHeader(&tar.Header{
				Name:     e.Name,
				Mode:     0o644,
				Size:     int64(len(e.Body)),
				ModTime:  mtime,
				Typeflag: tar.TypeReg,
			}); err != nil {
				t.Fatalf("WriteHeader(%s): %v", e.Name, err)
			}
			if len(e.Body) > 0 {
				if _, err := tw.Write(e.Body); err != nil {
					t.Fatalf("Write(%s): %v", e.Name, err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("tar Close: %v", err)
		}
		return tarBuf.Bytes()
	}

	compressTar := func(tarBytes []byte, level int, extra []byte) []byte {
		var gzBuf bytes.Buffer
		gw, err := gzip.NewWriterLevel(&gzBuf, level)
		if err != nil {
			t.Fatalf("gzip.NewWriterLevel: %v", err)
		}
		gw.Header = gzip.Header{
			ModTime: time.Unix(0, 0).UTC(),
			OS:      255,
			Extra:   extra,
		}
		if _, err := gw.Write(tarBytes); err != nil {
			t.Fatalf("gzip Write: %v", err)
		}
		if err := gw.Close(); err != nil {
			t.Fatalf("gzip Close: %v", err)
		}
		return gzBuf.Bytes()
	}

	if targetBytes <= 65535 {
		tarBytes := encodeTar(baseEntries)
		gzBase := compressTar(tarBytes, gzip.BestCompression, nil)
		diff := targetBytes - int64(len(gzBase))
		if diff == 0 {
			return gzBase, harness.SHA256Hex(gzBase)
		}
		if diff == 1 || diff == 2 {
			// Shrink base tar to a single minimal entry so diff >= 3 for FEXTRA (2-byte XLEN + >=1 byte Extra).
			tarBytes = encodeTar([]harness.TarEntry{{Name: "README.md", Body: []byte("# b\n")}})
			gzBase = compressTar(tarBytes, gzip.BestCompression, nil)
			diff = targetBytes - int64(len(gzBase))
			if diff == 0 {
				return gzBase, harness.SHA256Hex(gzBase)
			}
		}
		if diff >= 3 && diff <= 65537 {
			extra := bytes.Repeat([]byte{'P'}, int(diff-2))
			gz := compressTar(tarBytes, gzip.BestCompression, extra)
			if int64(len(gz)) != targetBytes {
				t.Fatalf("exact small tar.gz size mismatch: got %d, want %d", len(gz), targetBytes)
			}
			return gz, harness.SHA256Hex(gz)
		}
		t.Fatalf("cannot construct exact %d-byte valid tar.gz (base=%d)", targetBytes, len(gzBase))
	}

	const maxEntryBytes = 16 << 20
	approxTar := targetBytes - (targetBytes/65535)*5 - 8192
	payloadSize := int(approxTar) - 3584
	if payloadSize < 0 {
		payloadSize = 0
	}
	randBuf := m2BuildIncompressibleBytes(t, payloadSize+65536)

	for iter := 0; iter < 12; iter++ {
		if payloadSize > len(randBuf) {
			randBuf = m2BuildIncompressibleBytes(t, payloadSize+16384)
		}
		entries := []harness.TarEntry{
			baseEntries[0],
			baseEntries[1],
		}
		if payloadSize <= maxEntryBytes {
			entries = append(entries, harness.TarEntry{Name: "payload.bin", Body: randBuf[:payloadSize]})
		} else {
			offset := 0
			for part := 0; offset < payloadSize; part++ {
				end := offset + maxEntryBytes
				if end > payloadSize {
					end = payloadSize
				}
				entries = append(entries, harness.TarEntry{
					Name: fmt.Sprintf("payload-%02d.bin", part),
					Body: randBuf[offset:end],
				})
				offset = end
			}
		}
		tarBytes := encodeTar(entries)
		gzBase := compressTar(tarBytes, gzip.NoCompression, nil)
		diff := targetBytes - int64(len(gzBase))
		if diff == 0 {
			return gzBase, harness.SHA256Hex(gzBase)
		}
		if diff >= 3 && diff <= 65537 {
			extra := bytes.Repeat([]byte{'P'}, int(diff-2))
			gz := compressTar(tarBytes, gzip.NoCompression, extra)
			if int64(len(gz)) != targetBytes {
				t.Fatalf("exact large tar.gz size mismatch: got %d, want %d", len(gz), targetBytes)
			}
			return gz, harness.SHA256Hex(gz)
		}
		if diff < 3 {
			payloadSize -= int(-diff) + 1024
			if payloadSize < 0 {
				payloadSize = 0
			}
		} else {
			payloadSize += int(diff) - 4096
		}
	}
	t.Fatalf("failed to converge exact tar.gz size %d", targetBytes)
	return nil, ""
}

type m2StoredGzipReader struct {
	prefix                []byte
	prefixPos             int
	blockHdr              [5]byte
	blockHdrPos           int
	blockHdrLen           int
	blockRemaining        int64
	uncompressedRemaining int64
	trailer               [8]byte
	trailerPos            int
}

func (r *m2StoredGzipReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		if r.prefixPos < len(r.prefix) {
			n := copy(p[written:], r.prefix[r.prefixPos:])
			r.prefixPos += n
			written += n
			continue
		}
		if r.blockHdrPos < r.blockHdrLen {
			n := copy(p[written:], r.blockHdr[r.blockHdrPos:r.blockHdrLen])
			r.blockHdrPos += n
			written += n
			continue
		}
		if r.blockRemaining > 0 {
			rem := int64(len(p) - written)
			if rem > r.blockRemaining {
				rem = r.blockRemaining
			}
			clear(p[written : written+int(rem)])
			r.blockRemaining -= rem
			written += int(rem)
			continue
		}
		if r.uncompressedRemaining > 0 {
			b := int64(65535)
			if b > r.uncompressedRemaining {
				b = r.uncompressedRemaining
			}
			r.uncompressedRemaining -= b
			isFinal := r.uncompressedRemaining == 0
			if isFinal {
				r.blockHdr[0] = 0x01
			} else {
				r.blockHdr[0] = 0x00
			}
			binary.LittleEndian.PutUint16(r.blockHdr[1:3], uint16(b))
			binary.LittleEndian.PutUint16(r.blockHdr[3:5], ^uint16(b))
			r.blockHdrPos = 0
			r.blockHdrLen = 5
			r.blockRemaining = b
			continue
		}
		if r.trailerPos < len(r.trailer) {
			n := copy(p[written:], r.trailer[r.trailerPos:])
			r.trailerPos += n
			written += n
			continue
		}
		break
	}
	if written == 0 {
		return 0, io.EOF
	}
	return written, nil
}

// m2NewStreamingOversizedTarGz returns a streaming reader yielding a valid .tar.gz of exact length targetBytes
// using ~64 KiB of memory regardless of targetBytes.
func m2NewStreamingOversizedTarGz(t testing.TB, targetBytes int64) io.Reader {
	t.Helper()
	if targetBytes < 4096 {
		t.Fatalf("m2NewStreamingOversizedTarGz: targetBytes %d too small", targetBytes)
	}

	storedGzLen := func(tarLen int64) int64 {
		numFull := tarLen / 65535
		rem := tarLen % 65535
		if rem > 0 {
			return 10 + numFull*65540 + (5 + rem) + 8
		}
		return 10 + numFull*65540 + 8
	}

	approxTar := targetBytes - (targetBytes/65540)*5 - 4096
	payloadSize := ((approxTar - 1536) / 512) * 512
	if payloadSize < 0 {
		payloadSize = 0
	}

	var tarLen, extraTotal int64
	converged := false
	for iter := 0; iter < 32; iter++ {
		tarLen = payloadSize + 1536
		extraTotal = targetBytes - storedGzLen(tarLen)
		if extraTotal == 0 || (extraTotal >= 3 && extraTotal <= 65537) {
			converged = true
			break
		}
		if extraTotal < 3 {
			payloadSize -= 512
			if payloadSize < 0 {
				payloadSize = 0
			}
		} else {
			payloadSize += ((extraTotal - 4096) / 512) * 512
			if extraTotal-4096 < 512 {
				payloadSize += 512
			}
		}
	}
	if !converged {
		t.Fatalf("failed to converge streaming tar.gz size %d (last extraTotal=%d)", targetBytes, extraTotal)
	}

	var hdrBuf bytes.Buffer
	tw := tar.NewWriter(&hdrBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "oversized.bin",
		Mode:     0o644,
		Size:     payloadSize,
		ModTime:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	tarHdr := hdrBuf.Bytes() // exactly 512 bytes

	crc := crc32.ChecksumIEEE(tarHdr)
	zeroChunk := make([]byte, 64*1024)
	zerosLeft := payloadSize + 1024
	for zerosLeft > 0 {
		n := int64(len(zeroChunk))
		if n > zerosLeft {
			n = zerosLeft
		}
		crc = crc32.Update(crc, crc32.IEEETable, zeroChunk[:int(n)])
		zerosLeft -= n
	}

	block0Len := int64(65535)
	if block0Len > tarLen {
		block0Len = tarLen
	}
	uncompressedRemaining := tarLen - block0Len
	isFinal0 := uncompressedRemaining == 0

	var prefix bytes.Buffer
	flg := byte(0x00)
	if extraTotal > 0 {
		flg = 0x04 // FEXTRA
	}
	prefix.Write([]byte{0x1f, 0x8b, 0x08, flg, 0, 0, 0, 0, 0x00, 0xff})
	if extraTotal > 0 {
		var xlen [2]byte
		binary.LittleEndian.PutUint16(xlen[:], uint16(extraTotal-2))
		prefix.Write(xlen[:])
		prefix.Write(bytes.Repeat([]byte{'P'}, int(extraTotal-2)))
	}
	var bh [5]byte
	if isFinal0 {
		bh[0] = 0x01
	}
	binary.LittleEndian.PutUint16(bh[1:3], uint16(block0Len))
	binary.LittleEndian.PutUint16(bh[3:5], ^uint16(block0Len))
	prefix.Write(bh[:])
	prefix.Write(tarHdr)

	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[0:4], crc)
	binary.LittleEndian.PutUint32(trailer[4:8], uint32(tarLen))

	return &m2StoredGzipReader{
		prefix:                prefix.Bytes(),
		blockRemaining:        block0Len - int64(len(tarHdr)),
		uncompressedRemaining: uncompressedRemaining,
		trailer:               trailer,
	}
}

// --- F-07: Repo registry, classification, model route & read-only ref-pinning (Tier 2: 5 tests) ---

func TestT2_F07_DisabledOrUnregisteredRepoRejected(t *testing.T) {
	specA := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "disabled-repo",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# disabled\n"},
	}
	specB := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "unregistered-repo",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# unregistered\n"},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(specA, specB))
	repoA, ok := env.Git().Repo("acme/disabled-repo")
	if !ok {
		t.Fatalf("seeded repoA missing")
	}
	repoB, ok := env.Git().Repo("acme/unregistered-repo")
	if !ok {
		t.Fatalf("seeded repoB missing")
	}
	m2SeedRepoDB(t, env, repoA, "INTERNAL", false, []string{m2DefaultModelRoute}, 5)
	// Intentionally omit repoB from PostgreSQL repositories table.

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := env.Client(humanTok)

	_, rawA, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repoA.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(disabled): %v", err)
	}
	rawA.RequireStatus(t, http.StatusForbidden)

	_, rawB, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repoB.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(unregistered): %v", err)
	}
	rawB.RequireAnyStatus(t, http.StatusForbidden, http.StatusNotFound)
}

func TestT2_F07_UnauthorizedModelRouteForRestrictedRepoDenied(t *testing.T) {
	spec := harness.RepoSeedSpec{
		Owner:         "sec",
		Name:          "restricted-repo",
		DefaultBranch: "main",
		Files:         map[string]string{"README.md": "# restricted\n"},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(spec))
	repo, ok := env.Git().Repo("sec/restricted-repo")
	if !ok {
		t.Fatalf("seeded repo missing")
	}
	m2SeedRepoDB(t, env, repo, "RESTRICTED", true, []string{"restricted-internal"}, 5)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, raw, err := env.Client(humanTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		Agent: &harness.WorkspaceAgentInfo{
			Type:       "coding-agent",
			SessionID:  "sess-unauth-route",
			ModelRoute: "public-cloud-llm",
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(unauthorized route): %v", err)
	}
	raw.RequireAnyStatus(t, http.StatusForbidden, http.StatusUnprocessableEntity)

	rows, err := env.DB().QueryRows(`SELECT count(*) FROM workspaces`)
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("expected 0 workspaces created on denied model route, got rows=%v err=%v", rows, err)
	}
}

func TestT2_F07_NonExistentOrEmptyGitRefRejected(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := env.Client(humanTok)

	_, rawMissing, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/nonexistent"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(nonexistent ref): %v", err)
	}
	rawMissing.RequireAnyStatus(t, http.StatusUnprocessableEntity, http.StatusNotFound, http.StatusBadRequest)

	_, rawEmpty, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: ""},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(empty ref): %v", err)
	}
	rawEmpty.RequireStatus(t, http.StatusBadRequest)
}

func TestT2_F07_GitHubOutageDuringRefResolutionReturns503AndRecovers(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	env.GitHub().SetOutage("GET", "/git/ref/", http.StatusServiceUnavailable, 0)
	env.GitHub().SetOutage("GET", "/git/matching-refs/", http.StatusServiceUnavailable, 0)
	env.GitHub().SetOutage("GET", "/branches/", http.StatusServiceUnavailable, 0)
	env.GitHub().SetOutage("GET", "/commits/", http.StatusServiceUnavailable, 0)

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	client := env.Client(humanTok)

	_, rawOutage, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace during GitHub outage: %v", err)
	}
	rawOutage.RequireStatus(t, http.StatusServiceUnavailable)

	env.GitHub().ClearOutages()
	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if ws.BaseCommit != repo.HeadSHA {
		t.Fatalf("recovered workspace base_commit = %q (want %q)", ws.BaseCommit, repo.HeadSHA)
	}
}

func TestT2_F07_UnsupportedProviderAndInvalidRepoIDReturn400(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := env.Client(humanTok)

	_, rawProvider, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "gitlab", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(gitlab): %v", err)
	}
	rawProvider.RequireStatus(t, http.StatusBadRequest)
	if rawProvider.Error == nil || rawProvider.Error.Code == "" {
		t.Fatalf("expected ErrorResponse for unsupported provider: %s", string(rawProvider.Body))
	}

	_, rawZeroID, err := client.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: 0, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(repo_id=0): %v", err)
	}
	rawZeroID.RequireStatus(t, http.StatusBadRequest)
	if rawZeroID.Error == nil || rawZeroID.Error.Code == "" {
		t.Fatalf("expected ErrorResponse for invalid repo ID: %s", string(rawZeroID.Body))
	}
}

// --- F-08: Deterministic ingress archive & SnapshotStore (Tier 2: 5 tests) ---

func TestT2_F08_ZeroGitHubCredentialsObservableInIngressArtifactsOrLogs(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, wsShallow := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository:    harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		SourceOptions: &harness.WorkspaceSourceOptions{IncludeGitMetadata: false, IncludeHistory: false},
	})
	_, wsGit := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository:    harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		SourceOptions: &harness.WorkspaceSourceOptions{IncludeGitMetadata: true, IncludeHistory: false},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	gz1, r1, err := ctrlClient.DownloadWorkspaceSource(ctx, m2ResolveWorkspaceID(wsShallow))
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource(shallow): %v", err)
	}
	r1.RequireStatus(t, http.StatusOK)

	gz2, r2, err := ctrlClient.DownloadWorkspaceSource(ctx, m2ResolveWorkspaceID(wsGit))
	if err != nil {
		t.Fatalf("DownloadWorkspaceSource(git): %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)

	secrets := []string{
		env.GitHub().ReadAppPrivateKeyPEM(),
		env.GitHub().WriteAppPrivateKeyPEM(),
		"x-access-token:",
		"ghs_",
		"ghp_",
	}
	env.Snapshots().AssertArchiveNoSecretLeak(t, gz1, secrets...)
	env.Snapshots().AssertArchiveNoSecretLeak(t, gz2, secrets...)

	objs, err := env.Snapshots().ListObjects()
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	for _, obj := range objs {
		rawBytes, err := env.Snapshots().ReadBytes(obj)
		if err != nil {
			t.Fatalf("ReadBytes(%s): %v", obj.RelPath, err)
		}
		harness.AssertNoSecretOrEncodedLeak(t, string(rawBytes),
			env.GitHub().ReadAppPrivateKeyPEM(),
			env.GitHub().WriteAppPrivateKeyPEM(),
		)
	}
	env.AssertNoSecretLeakInLogs(secrets...)
}

func TestT2_F08_UnauthorizedIncludeHistoryRequestDenied403(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	standardHumanTok := env.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "standard-dev",
		Email:   "standard-dev@example.com",
		Groups:  []string{"engineering"},
		Roles:   []string{"human", "developer"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, raw, err := env.Client(standardHumanTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
		SourceOptions: &harness.WorkspaceSourceOptions{
			IncludeGitMetadata: true,
			IncludeHistory:     true,
		},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace(include_history): %v", err)
	}
	raw.RequireStatus(t, http.StatusForbidden)

	rows, err := env.DB().QueryRows(`SELECT count(*) FROM workspaces`)
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("expected 0 workspaces created on unauthorized include_history, got rows=%v err=%v", rows, err)
	}
}

func TestT2_F08_NonControllerRejectedOnWorkspaceSourceEndpoint(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	tokA := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "owner-src", Email: "ownersrc@example.com"})
	tokB := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "other-src", Email: "othersrc@example.com"})
	agentTok := env.MintToken(harness.TokenClaims{Kind: "AGENT"})

	_, ws := m2CreateReadyWorkspace(t, env, tokA, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, raw401, err := env.Client("").GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("unauth GetWorkspaceSource: %v", err)
	}
	raw401.RequireStatus(t, http.StatusUnauthorized)

	_, rawAgent, err := env.Client(agentTok).GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("agent GetWorkspaceSource: %v", err)
	}
	rawAgent.RequireStatus(t, http.StatusForbidden)

	_, rawOtherHuman, err := env.Client(tokB).GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("other human GetWorkspaceSource: %v", err)
	}
	rawOtherHuman.RequireStatus(t, http.StatusForbidden)
}

func TestT2_F08_WorkspaceSourceBeforeReadyReturns409(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cResp, raw, err := env.Client(humanTok).CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)

	_, srcRaw, err := env.Client(ctrlTok).GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource before READY: %v", err)
	}
	srcRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F08_IngressPolicyDenyBlocksSourceDelivery(t *testing.T) {
	root := m2FindRepoRoot(t)
	secretBytes, err := os.ReadFile(filepath.Join(root, "test", "e2e", "fixtures", "payloads", "synthetic_aws_secret.env"))
	if err != nil {
		t.Fatalf("read synthetic_aws_secret.env: %v", err)
	}
	spec := harness.RepoSeedSpec{
		Owner:         "acme",
		Name:          "secret-ingress",
		DefaultBranch: "main",
		Files: map[string]string{
			"README.md": "# secret repo\n",
			".env":      string(secretBytes),
		},
	}
	env := m2NewEnv(t, harness.WithSeedRepos(spec))
	repo, ok := env.Git().Repo("acme/secret-ingress")
	if !ok {
		t.Fatalf("seeded repo missing")
	}
	m2SeedRepoDB(t, env, repo, "INTERNAL", true, []string{m2DefaultModelRoute}, 5)

	env.Scanners().Set(harness.ScannerGitleaks, harness.ScannerBehavior{
		Mode:        harness.ScannerModeSecretFinding,
		FilePath:    ".env",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
		RuleID:      "aws-access-token",
	})

	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	humanClient := env.Client(humanTok)
	cResp, cRaw, err := humanClient.CreateWorkspace(ctx, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	cRaw.RequireStatus(t, http.StatusAccepted)
	wsID := m2ResolveCreatedWorkspaceID(cResp)

	op, err := humanClient.WaitForOperation(ctx, cResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if op.Status != "FAILED" {
		t.Fatalf("expected FAILED terminal op status on ingress secret deny, got %q (last_error=%q)", op.Status, op.LastError)
	}
	if strings.TrimSpace(op.LastError) == "" {
		t.Fatalf("expected non-empty op.LastError on FAILED ingress operation %s", op.ID)
	}

	ws, wsRaw, err := humanClient.GetWorkspace(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	wsRaw.RequireStatus(t, http.StatusOK)
	if ws.Status != "FAILED" && ws.Status != "CLOSED" {
		t.Fatalf("expected workspace blocked (FAILED/CLOSED) on ingress secret DENY, got %q", ws.Status)
	}

	_, srcRaw, err := env.Client(ctrlTok).GetWorkspaceSource(ctx, wsID)
	if err != nil {
		t.Fatalf("GetWorkspaceSource: %v", err)
	}
	srcRaw.RequireAnyStatus(t, http.StatusConflict, http.StatusForbidden)

	env.Scanners().AssertInvoked(t, harness.ScannerGitleaks)

	audTok := env.MintToken(harness.TokenClaims{Kind: "AUDITOR"})
	audClient := env.Client(audTok)
	wsEvents, audRaw, err := audClient.ListAuditEvents(ctx, harness.AuditFilter{
		ResourceType: "workspace",
		ResourceID:   wsID,
		Limit:        100,
	})
	if err != nil {
		t.Fatalf("ListAuditEvents(workspace=%s): %v", wsID, err)
	}
	audRaw.RequireStatus(t, http.StatusOK)
	if len(wsEvents.Events) == 0 {
		t.Fatalf("expected >= 1 persisted audit_events record for blocked workspace %s", wsID)
	}
	for _, ev := range wsEvents.Events {
		if ev.ResourceType != "workspace" || ev.ResourceID != wsID {
			t.Fatalf("unexpected audit event in workspace filter: %+v", ev)
		}
		harness.AssertUUIDv7(t, ev.ID)
	}
	allAudit := m2SortAuditEventsAscending(m2FetchAllAuditEvents(t, audClient))
	harness.VerifyFullAuditHashChainFromGenesis(t, allAudit)

	env.AssertNoSecretLeakInLogs("AKIAIOSFODNN7EXAMPLE", "custodian_e2e_dummy_secret_value_0123456789abcdef")
}

// --- F-09: Upload-only scoped capability & controller provenance (Tier 2: 5 tests) ---

func TestT2_F09_UploadCapabilityBlockedFromReadingAnyArtifact(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	capResp, capRaw, err := ctrlClient.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# cap read block\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	upRaw, err := ctrlClient.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, gz)
	if err != nil {
		t.Fatalf("UploadSnapshot: %v", err)
	}
	upRaw.RequireAnyStatus(t, http.StatusOK, http.StatusCreated)

	anonClient := env.Client("")
	getUpRaw, err := anonClient.DoRaw(ctx, http.MethodGet, capResp.UploadURL, nil,
		harness.WithoutAuth(),
		harness.WithHeader("Authorization", "Bearer "+capResp.Token),
	)
	if err != nil {
		t.Fatalf("GET uploadURL with capability: %v", err)
	}
	getUpRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed)
	if bytes.Contains(getUpRaw.Body, gz) {
		t.Fatalf("upload capability leaked uploaded artifact bytes on GET")
	}

	getSrcRaw, err := anonClient.DoRaw(ctx, http.MethodGet, "/v1/workspaces/"+wsID+"/source", nil,
		harness.WithoutAuth(),
		harness.WithHeader("Authorization", "Bearer "+capResp.Token),
	)
	if err != nil {
		t.Fatalf("GET /source with capability: %v", err)
	}
	getSrcRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)
}

func TestT2_F09_UploadCapabilityRejectedAcrossWorkspaces(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws1 := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	_, ws2 := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	cap1, r1, err := ctrlClient.RequestUploadCapability(ctx, m2ResolveWorkspaceID(ws1), harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("cap1: %v", err)
	}
	r1.RequireStatus(t, http.StatusOK)

	cap2, r2, err := ctrlClient.RequestUploadCapability(ctx, m2ResolveWorkspaceID(ws2), harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("cap2: %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "README.md", Body: []byte("# cross ws\n")}})
	upRaw, err := ctrlClient.UploadSnapshot(ctx, cap2.UploadURL, cap1.Token, gz)
	if err != nil {
		t.Fatalf("UploadSnapshot cross-workspace: %v", err)
	}
	upRaw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)
}

func TestT2_F09_TamperedMissingAndForgedUploadCapabilityRejected(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	capResp, capRaw, err := ctrlClient.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)

	gz, sha := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "unique-tamper-check.txt", Body: []byte("never stored\n")}})

	// Tamper an interior character of the signature segment (never the final base64url char, which can
	// collide on unused trailing bits in base64.RawURLEncoding).
	tamperedBytes := []byte(capResp.Token)
	if len(tamperedBytes) > 0 {
		idx := len(tamperedBytes) / 2
		if dotIdx := strings.LastIndexByte(capResp.Token, '.'); dotIdx >= 0 && len(capResp.Token)-dotIdx-1 >= 4 {
			idx = dotIdx + 1 + (len(capResp.Token)-dotIdx-1)/2
		} else if len(tamperedBytes) > 2 && idx == len(tamperedBytes)-1 {
			idx = len(tamperedBytes) - 2
		}
		switch tamperedBytes[idx] {
		case 'a':
			tamperedBytes[idx] = 'b'
		case 'A':
			tamperedBytes[idx] = 'B'
		default:
			tamperedBytes[idx] = 'a'
		}
	}
	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "tampered_hmac", token: string(tamperedBytes)},
		{name: "missing_token", token: ""},
		{name: "forged_token", token: "v1.eyJmb3JnZWQiOnRydWV9.ZmFrZXNpZw"},
	} {
		raw, err := ctrlClient.UploadSnapshot(ctx, capResp.UploadURL, tc.token, gz)
		if err != nil {
			t.Fatalf("%s UploadSnapshot: %v", tc.name, err)
		}
		raw.RequireAnyStatus(t, http.StatusUnauthorized, http.StatusForbidden)
	}

	if _, err := env.Snapshots().FindBySHA256(sha); err == nil {
		t.Fatalf("rejected tampered/forged upload unexpectedly persisted snapshot %s", sha)
	}
}

func TestT2_F09_UploadExceedingMaxBytesRejected(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	capResp, capRaw, err := ctrlClient.RequestUploadCapability(ctx, wsID, harness.UploadCapabilityReq{MaxBytes: 1024})
	if err != nil {
		t.Fatalf("RequestUploadCapability: %v", err)
	}
	capRaw.RequireStatus(t, http.StatusOK)
	if capResp.MaxBytes <= 0 {
		t.Fatalf("expected capResp.MaxBytes > 0, got %d", capResp.MaxBytes)
	}

	beforeObjs, err := env.Snapshots().ListObjects()
	if err != nil {
		t.Fatalf("Snapshots().ListObjects before: %v", err)
	}

	targetBytes := capResp.MaxBytes + 1024
	if capResp.MaxBytes <= 64<<20 {
		oversized, oversizedSHA := m2BuildExactSizeTarGz(t, targetBytes)
		if int64(len(oversized)) != targetBytes {
			t.Fatalf("oversized archive len = %d (want %d)", len(oversized), targetBytes)
		}
		if gzr, gerr := gzip.NewReader(bytes.NewReader(oversized)); gerr != nil {
			t.Fatalf("oversized payload is not valid gzip: %v", gerr)
		} else {
			_ = gzr.Close()
		}

		raw, err := ctrlClient.UploadSnapshot(ctx, capResp.UploadURL, capResp.Token, oversized)
		if err != nil {
			t.Fatalf("UploadSnapshot(oversized): %v", err)
		}
		raw.RequireAnyStatus(t, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusForbidden)

		if _, err := env.Snapshots().FindBySHA256(oversizedSHA); err == nil {
			t.Fatalf("oversized payload %s unexpectedly persisted in SnapshotStore", oversizedSHA)
		}
	} else {
		streamReader := m2NewStreamingOversizedTarGz(t, targetBytes)
		hasher := sha256.New()
		teeReader := io.TeeReader(streamReader, hasher)

		targetURL := capResp.UploadURL
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			if !strings.HasPrefix(targetURL, "/") {
				targetURL = "/" + targetURL
			}
			targetURL = strings.TrimRight(env.APIBaseURL(), "/") + targetURL
		}
		method := env.Contracts().UploadCapabilityMethod
		if method == "" {
			method = http.MethodPut
		}
		req, err := http.NewRequestWithContext(ctx, method, targetURL, teeReader)
		if err != nil {
			t.Fatalf("NewRequestWithContext(oversized stream): %v", err)
		}
		req.ContentLength = targetBytes
		req.Header.Set("Content-Type", "application/gzip")
		hdrName := env.Contracts().UploadCapabilityHeader
		if hdrName == "" {
			hdrName = "Authorization"
		}
		hdrVal := capResp.Token
		if env.Contracts().UploadCapabilityBearer && capResp.Token != "" && !strings.HasPrefix(capResp.Token, "Bearer ") {
			hdrVal = "Bearer " + capResp.Token
		}
		if hdrVal != "" {
			req.Header.Set(hdrName, hdrVal)
		}

		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("streaming UploadSnapshot(oversized): %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge &&
			resp.StatusCode != http.StatusUnprocessableEntity &&
			resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unexpected HTTP status %d for oversized streaming tar.gz (want 413, 422, or 403)", resp.StatusCode)
		}

		oversizedSHA := hex.EncodeToString(hasher.Sum(nil))
		if _, err := env.Snapshots().FindBySHA256(oversizedSHA); err == nil {
			t.Fatalf("oversized streamed payload %s unexpectedly persisted in SnapshotStore", oversizedSHA)
		}
	}

	afterObjs, err := env.Snapshots().ListObjects()
	if err != nil {
		t.Fatalf("Snapshots().ListObjects after: %v", err)
	}
	if len(afterObjs) != len(beforeObjs) {
		t.Fatalf("SnapshotStore object count changed after rejected oversized upload: before=%d after=%d", len(beforeObjs), len(afterObjs))
	}
}

func TestT2_F09_NonControllerSpoofingCapturedByRejectedOnProposalSubmit(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	agentTok := env.MintToken(harness.TokenClaims{Kind: "AGENT"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "README.md", Body: []byte("# spoof\n")}})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	req := harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title:       "spoof-captured-by",
		Description: `{"captured_by":"trusted-runtime-controller"}`,
	}
	for _, tc := range []struct {
		name string
		tok  string
	}{
		{name: "human", tok: humanTok},
		{name: "agent", tok: agentTok},
	} {
		_, raw, err := env.Client(tc.tok).SubmitProposal(ctx, wsID, req, harness.WithHeader("X-Captured-By", "trusted-runtime-controller"))
		if err != nil {
			t.Fatalf("%s SubmitProposal: %v", tc.name, err)
		}
		raw.RequireStatus(t, http.StatusForbidden)
	}

	rows, err := env.DB().QueryRows(`SELECT count(*) FROM proposals`)
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("expected 0 proposals created by non-controller, got rows=%v err=%v", rows, err)
	}
}

// --- F-10: Strict egress archive parser & limits (Tier 2: 5 tests) ---

func TestT2_F10_RejectsMalformedCorruptAndTruncatedTarGz(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	for _, mode := range []harness.CorruptArchiveMode{
		harness.CorruptRandomBytes,
		harness.CorruptTarChecksum,
		harness.CorruptTruncatedGzip,
		harness.CorruptTruncatedTarEntry,
	} {
		corrupt := harness.BuildCorruptTarGz(mode)
		m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, corrupt, string(mode))
	}
}

func TestT2_F10_RejectsPathTraversalArchives(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	for _, p := range []string{
		harness.TraversalDotDot,
		harness.TraversalNested,
		harness.TraversalAbsolute,
		harness.TraversalBackslash,
	} {
		gz, _ := harness.BuildPathTraversalArchive(p)
		m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, gz, "traversal-"+p)
	}
}

func TestT2_F10_RejectsSymlinksHardlinksSpecialFilesAndUnsupportedTypes(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	s1, _ := harness.BuildSymlinkArchive("l1", "/etc/passwd")
	s2, _ := harness.BuildSymlinkArchive("l2", "README.md")
	h1, _ := harness.BuildHardlinkArchive("h1", "README.md")
	f1, _ := harness.BuildSpecialFileArchive(tar.TypeFifo, "f1")
	c1, _ := harness.BuildSpecialFileArchive(tar.TypeChar, "c1")
	u1, _ := harness.BuildUnsupportedTypeArchive('?', "u1")

	for _, tc := range []struct {
		label string
		gz    []byte
	}{
		{label: "symlink-abs", gz: s1},
		{label: "symlink-rel", gz: s2},
		{label: "hardlink", gz: h1},
		{label: "fifo", gz: f1},
		{label: "char-dev", gz: c1},
		{label: "unsupported-type", gz: u1},
	} {
		m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, tc.gz, tc.label)
	}
}

func TestT2_F10_RejectsCaseAndUnicodeNFCCollisions(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	caseGZ, _ := harness.BuildCaseCollisionArchive()
	unicodeGZ, _ := harness.BuildUnicodeCollisionArchive()
	dupGZ, _ := harness.BuildTarGz([]harness.TarEntry{
		{Name: "dup.txt", Body: []byte("first\n")},
		{Name: "dup.txt", Body: []byte("second\n")},
	})
	fileDirGZ, _ := harness.BuildTarGz([]harness.TarEntry{
		{Name: "foo", Body: []byte("file\n")},
		{Name: "foo/bar.txt", Body: []byte("nested\n")},
	})

	m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, caseGZ, "case-collision")
	m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, unicodeGZ, "unicode-nfc-collision")
	m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, dupGZ, "duplicate-entry")
	m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, fileDirGZ, "file-dir-collision")
}

func TestT2_F10_RejectsSubmodulesGitlinksAndDecompressionBomb(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	subGZ, _ := harness.BuildSubmoduleArchive()
	bombGZ, _ := harness.BuildGzipBomb(128 << 20)

	m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, subGZ, "submodule-gitlink")
	m2SubmitAndExpectArchiveRejected(t, env, ctrlTok, wsID, ws.Generation, bombGZ, "gzip-bomb-128mb")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hRaw, err := env.Client("").GetHealth(ctx)
	if err != nil {
		t.Fatalf("GetHealth after bomb: %v", err)
	}
	hRaw.RequireStatus(t, http.StatusOK)

	rRaw, err := env.Client("").GetReady(ctx)
	if err != nil {
		t.Fatalf("GetReady after bomb: %v", err)
	}
	rRaw.RequireStatus(t, http.StatusOK)
}

// --- F-11: Clean base reconstruction & canonical digests (Tier 2: 5 tests) ---

func TestT2_F11_SandboxDotGitHooksAndConfigIgnoredOnReconstruct(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	baseEntries := []harness.TarEntry{
		{Name: "README.md", Body: []byte("# clean base\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	}
	cleanGZ, _ := harness.BuildTarGz(baseEntries)
	evilGZ, _ := harness.BuildGitInjectionArchive(baseEntries)

	propClean, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, cleanGZ, "clean-git-ignore", nil)
	propEvil, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, evilGZ, "evil-git-ignore", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diffClean, r1, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(propClean))
	if err != nil {
		t.Fatalf("GetProposalDiff(clean): %v", err)
	}
	r1.RequireStatus(t, http.StatusOK)

	diffEvil, r2, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(propEvil))
	if err != nil {
		t.Fatalf("GetProposalDiff(evil): %v", err)
	}
	r2.RequireStatus(t, http.StatusOK)

	if diffEvil.TreeDigest != diffClean.TreeDigest ||
		diffEvil.DiffDigest != diffClean.DiffDigest ||
		diffEvil.PublicationManifestDigest != diffClean.PublicationManifestDigest {
		t.Fatalf("sandbox .git injection altered canonical digests: clean=(%s,%s,%s) evil=(%s,%s,%s)",
			diffClean.TreeDigest, diffClean.DiffDigest, diffClean.PublicationManifestDigest,
			diffEvil.TreeDigest, diffEvil.DiffDigest, diffEvil.PublicationManifestDigest)
	}
	for _, p := range diffEvil.Paths {
		if p.Path == ".git" || strings.HasPrefix(p.Path, ".git/") {
			t.Fatalf(".git entry %q leaked into reconstructed ProposalDiff.Paths", p.Path)
		}
	}
	env.AssertNoSecretLeakInLogs()
}

func TestT2_F11_ForgedGitAuthorInSandboxConfigIgnored(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "real-owner-gitcfg", Email: "realowner@example.com"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
		{Name: "pkg/f.go", Body: []byte("package pkg\n")},
		{Name: ".git/config", Body: []byte("[user]\n\tname = Forged\n\temail = forged@evil.com\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "forged-git-author", nil)

	if prop.Owner == nil || ws.Owner == nil || prop.Owner.PrincipalID != ws.Owner.PrincipalID {
		t.Fatalf("proposal owner %+v != workspace owner %+v", prop.Owner, ws.Owner)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diff, raw, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(prop))
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	raw.RequireStatus(t, http.StatusOK)
	for _, p := range diff.Paths {
		if strings.HasPrefix(p.Path, ".git") {
			t.Fatalf(".git file %q leaked into ProposalDiff.Paths", p.Path)
		}
	}
}

func TestT2_F11_SnapshotSHA256MismatchRejected422(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "README.md", Body: []byte("# mismatch\n")}})
	artifactID, _ := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)
	subResp, subRaw, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              strings.Repeat("e", 64),
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "sha256-mismatch",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	if subRaw.StatusCode == http.StatusUnprocessableEntity || subRaw.StatusCode == http.StatusConflict || subRaw.StatusCode == http.StatusBadRequest {
		return
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	op, err := ctrlClient.WaitForOperation(ctx, subResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation: %v", err)
	}
	if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalFailure, op.Status) {
		t.Fatalf("expected FAILED operation on SHA256 mismatch, got %q", op.Status)
	}
}

func TestT2_F11_NonExistentSnapshotArtifactIDRejected(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, raw, err := env.Client(ctrlTok).SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          harness.NewTestUUIDv7(),
			SHA256:              strings.Repeat("a", 64),
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           128,
		},
		Title: "missing-artifact",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	raw.RequireAnyStatus(t, http.StatusNotFound, http.StatusUnprocessableEntity, http.StatusBadRequest)
}

func TestT2_F11_SingleByteChangeMutatesAllCanonicalDigests(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gzA, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nconst v = \"v1\"\n")},
	})
	gzB, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# acme/service\n")},
		{Name: "main.go", Body: []byte("package main\n\nconst v = \"v2\"\n")},
	})

	propA, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gzA, "byte-a", nil)
	propB, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gzB, "byte-b", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	diffA, rA, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(propA))
	if err != nil {
		t.Fatalf("GetProposalDiff(A): %v", err)
	}
	rA.RequireStatus(t, http.StatusOK)

	diffB, rB, err := env.Client(humanTok).GetProposalDiff(ctx, m2ResolveProposalID(propB))
	if err != nil {
		t.Fatalf("GetProposalDiff(B): %v", err)
	}
	rB.RequireStatus(t, http.StatusOK)

	if diffA.TreeDigest == diffB.TreeDigest {
		t.Fatalf("TreeDigest did not change on 1-byte diff: %s", diffA.TreeDigest)
	}
	if diffA.DiffDigest == diffB.DiffDigest {
		t.Fatalf("DiffDigest did not change on 1-byte diff: %s", diffA.DiffDigest)
	}
	if diffA.PublicationManifestDigest == diffB.PublicationManifestDigest {
		t.Fatalf("PublicationManifestDigest did not change on 1-byte diff: %s", diffA.PublicationManifestDigest)
	}
}

// --- F-12: Proposal lifecycle & optimistic versioning (Tier 2: 5 tests) ---

func TestT2_F12_StaleExpectedVersionReturns409Conflict(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)

	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# optimistic lock\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "opt-version-1", nil)
	propID := m2ResolveProposalID(prop)
	ver := prop.Version

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	// (a) Mismatched future ExpectedVersion + If-Match -> 409 Conflict.
	futureVer := ver + 10
	_, rawStale1, err := ctrlClient.EvaluateProposal(ctx, propID, harness.EvaluateReq{
		ExpectedVersion: futureVer,
	}, harness.WithHeader("If-Match", fmt.Sprintf("%d", futureVer)))
	if err != nil {
		t.Fatalf("EvaluateProposal(futureVer): %v", err)
	}
	rawStale1.RequireStatus(t, http.StatusConflict)
	if rawStale1.Error == nil || rawStale1.Error.Code == "" {
		t.Fatalf("expected ErrorResponse on 409 conflict: %s", string(rawStale1.Body))
	}

	// (b) Matching version succeeds and advances version, then old ver -> 409 Conflict.
	evalResp, rawOK, err := ctrlClient.EvaluateProposal(ctx, propID, harness.EvaluateReq{
		ExpectedVersion: ver,
	}, harness.WithHeader("If-Match", fmt.Sprintf("%d", ver)))
	if err != nil {
		t.Fatalf("EvaluateProposal(matching): %v", err)
	}
	rawOK.RequireStatus(t, http.StatusAccepted)
	opRes, err := ctrlClient.WaitForOperation(ctx, evalResp.OperationID, 30*time.Second)
	if err != nil {
		t.Fatalf("WaitForOperation(%s): %v", evalResp.OperationID, err)
	}
	if !harness.ContainsStatus(env.Contracts().OperationStatuses.TerminalSuccess, opRes.Status) {
		t.Fatalf("expected EvaluateProposal operation %s to succeed, got status=%q err=%q", evalResp.OperationID, opRes.Status, opRes.LastError)
	}

	_, rawStale2, err := ctrlClient.EvaluateProposal(ctx, propID, harness.EvaluateReq{
		ExpectedVersion: ver,
	}, harness.WithHeader("If-Match", fmt.Sprintf("%d", ver)))
	if err != nil {
		t.Fatalf("EvaluateProposal(now-stale): %v", err)
	}
	rawStale2.RequireStatus(t, http.StatusConflict)

	// (c) Concurrent race on a fresh proposal: at most 1 winner, loser gets 409 Conflict.
	prop2, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, wsID, ws.Generation, gz, "opt-version-race", nil)
	prop2ID := m2ResolveProposalID(prop2)
	ver2 := prop2.Version

	statuses := make([]int, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	startGate := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate
			c := env.Client(ctrlTok)
			_, r, err := c.EvaluateProposal(ctx, prop2ID, harness.EvaluateReq{
				ExpectedVersion: ver2,
			}, harness.WithHeader("If-Match", fmt.Sprintf("%d", ver2)))
			errs[idx] = err
			if r != nil {
				statuses[idx] = r.StatusCode
			}
		}(i)
	}
	close(startGate)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("race goroutine %d err: %v", i, err)
		}
	}
	acceptedCount := 0
	conflictCount := 0
	for _, st := range statuses {
		switch st {
		case http.StatusAccepted:
			acceptedCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Fatalf("unexpected status %d in optimistic version race (want 202 or 409): statuses=%v", st, statuses)
		}
	}
	if acceptedCount != 1 || conflictCount != 1 {
		t.Fatalf("expected exactly one 202 winner and one 409 loser in concurrent optimistic lock race, got statuses=%v", statuses)
	}
}

func TestT2_F12_IdempotencyKeyMissing400AndPayloadConflict409(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "README.md", Body: []byte("# idem conflict\n")}})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	ctrlClient := env.Client(ctrlTok)

	// (a) Missing Idempotency-Key -> 400.
	_, raw400, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "missing-idem",
	}, harness.WithoutIdempotency())
	if err != nil {
		t.Fatalf("SubmitProposal(no idem): %v", err)
	}
	raw400.RequireStatus(t, http.StatusBadRequest)

	// (b) Reuse same Idempotency-Key with different payload -> 409 (or 422).
	idemKey := harness.NewTestUUIDv7()
	_, rawFirst, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "Title A",
	}, harness.WithIdempotencyKey(idemKey))
	if err != nil {
		t.Fatalf("SubmitProposal(A): %v", err)
	}
	rawFirst.RequireStatus(t, http.StatusAccepted)

	_, rawConflict, err := ctrlClient.SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "Title B",
	}, harness.WithIdempotencyKey(idemKey))
	if err != nil {
		t.Fatalf("SubmitProposal(B): %v", err)
	}
	rawConflict.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	rows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT count(*) FROM proposals WHERE workspace_id = %s::uuid`, m2SQLLiteral(wsID)))
	if err != nil || len(rows) != 1 || rows[0][0] != "1" {
		t.Fatalf("expected 1 proposal in DB after idempotency conflict, got rows=%v err=%v", rows, err)
	}
}

func TestT2_F12_WorkspaceGenerationMismatchReturns409(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "README.md", Body: []byte("# gen mismatch\n")}})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, raw, err := env.Client(ctrlTok).SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation + 1,
			SizeBytes:           int64(len(gz)),
		},
		Title: "gen-mismatch",
	})
	if err != nil {
		t.Fatalf("SubmitProposal(gen mismatch): %v", err)
	}
	raw.RequireAnyStatus(t, http.StatusConflict, http.StatusUnprocessableEntity)

	rows, err := env.DB().QueryRows(fmt.Sprintf(`SELECT count(*) FROM proposals WHERE workspace_id = %s::uuid`, m2SQLLiteral(wsID)))
	if err != nil || len(rows) != 1 || rows[0][0] != "0" {
		t.Fatalf("expected 0 proposals on generation mismatch, got rows=%v err=%v", rows, err)
	}
}

func TestT2_F12_GetProposalDiffBeforeReconstructionReturns409(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN"})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	wsID := m2ResolveWorkspaceID(ws)
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{{Name: "README.md", Body: []byte("# pre-reconstruct diff\n")}})
	artifactID, sha := m2UploadSnapshotBytes(t, env, ctrlTok, wsID, gz)

	if err := env.StopWorker(); err != nil {
		t.Fatalf("StopWorker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	subResp, subRaw, err := env.Client(ctrlTok).SubmitProposal(ctx, wsID, harness.SubmitProposalReq{
		Snapshot: harness.SnapshotSubmitRef{
			ArtifactID:          artifactID,
			SHA256:              sha,
			WorkspaceGeneration: ws.Generation,
			SizeBytes:           int64(len(gz)),
		},
		Title: "diff-before-reconstruct",
	})
	if err != nil {
		t.Fatalf("SubmitProposal: %v", err)
	}
	subRaw.RequireStatus(t, http.StatusAccepted)
	propID := m2ResolveProposalID(subResp)

	_, diffRaw, err := env.Client(humanTok).GetProposalDiff(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposalDiff: %v", err)
	}
	diffRaw.RequireStatus(t, http.StatusConflict)
}

func TestT2_F12_InvalidStateTransitionsBlocked409(t *testing.T) {
	env, repo := m2NewEnvWithSeededRepo(t)
	humanTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "owner-state", Email: "ownerstate@example.com"})
	reviewerTok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "reviewer-state", Email: "reviewerstate@example.com", Groups: []string{"engineering", "reviewers"}})
	ctrlTok := env.MintToken(harness.TokenClaims{Kind: "CONTROLLER"})

	_, ws := m2CreateReadyWorkspace(t, env, humanTok, harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: repo.GitHubRepoID, Ref: "refs/heads/main"},
	})
	gz, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "README.md", Body: []byte("# state transitions\n")},
		{Name: "main.go", Body: []byte("package main\n\nfunc main() {}\n")},
	})
	prop, _ := m2UploadAndSubmitProposal(t, env, ctrlTok, m2ResolveWorkspaceID(ws), ws.Generation, gz, "invalid-transitions", nil)
	propID := m2ResolveProposalID(prop)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// (a) Approve directly from RECONSTRUCTED (without policy evaluation) -> 409 Conflict.
	_, appRaw, err := env.Client(reviewerTok).ApproveProposal(ctx, propID, harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: prop.PublicationManifestDigest,
		PolicyEvaluationID:        harness.NewTestUUIDv7(),
	})
	if err != nil {
		t.Fatalf("ApproveProposal: %v", err)
	}
	appRaw.RequireStatus(t, http.StatusConflict)

	// (b) Publish directly from RECONSTRUCTED -> 409 Conflict.
	_, pubRaw, err := env.Client(ctrlTok).PublishProposal(ctx, propID, harness.PublishReq{
		PublicationManifestDigest: prop.PublicationManifestDigest,
	})
	if err != nil {
		t.Fatalf("PublishProposal: %v", err)
	}
	pubRaw.RequireStatus(t, http.StatusConflict)

	propAfter, getRaw, err := env.Client(humanTok).GetProposal(ctx, propID)
	if err != nil {
		t.Fatalf("GetProposal: %v", err)
	}
	getRaw.RequireStatus(t, http.StatusOK)
	if propAfter.Status != "RECONSTRUCTED" {
		t.Fatalf("expected proposal to remain RECONSTRUCTED, got %q", propAfter.Status)
	}
}
