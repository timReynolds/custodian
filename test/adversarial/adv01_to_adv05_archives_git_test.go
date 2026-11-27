package adversarial_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/publish"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/github/write"
	"github.com/timreynolds/custodian/internal/harness"
	"github.com/timreynolds/custodian/test/fixtures"
)

func TestADV01_MaliciousArchivesAndBombs(t *testing.T) {
	ctx := context.Background()

	// 1. Gzip decompression bomb exceeding MaxUncompressedBytes.
	bombBytes := bytes.Repeat([]byte("A"), 256*1024)
	bombGz := fixtures.BuildTarGz(t, []fixtures.TarEntrySpec{
		{Name: "bomb.txt", Body: bombBytes},
	})
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(bombGz), t.TempDir(), archive.EgressOptions{
		MaxUncompressedBytes: 32 * 1024,
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("gzip bomb expected ErrUnprocessable, got %v", err)
	}

	// 2. Entry count bomb (> MaxEntries).
	entries := make([]fixtures.TarEntrySpec, 0, 25)
	for i := 0; i < 25; i++ {
		entries = append(entries, fixtures.TarEntrySpec{Name: "f-" + string(rune('a'+i)) + ".txt", Body: []byte("x")})
	}
	manyGz := fixtures.BuildTarGz(t, entries)
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(manyGz), t.TempDir(), archive.EgressOptions{
		MaxEntries: 10,
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("entry-count bomb expected ErrUnprocessable, got %v", err)
	}

	// 3. Single file exceeding MaxSingleFileBytes.
	bigFileGz := fixtures.BuildTarGz(t, []fixtures.TarEntrySpec{
		{Name: "big.bin", Body: bytes.Repeat([]byte("Z"), 8192)},
	})
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(bigFileGz), t.TempDir(), archive.EgressOptions{
		MaxSingleFileBytes: 1024,
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("oversized single file expected ErrUnprocessable, got %v", err)
	}

	// 4. Trailing concatenated gzip member smuggling.
	concatGz := fixtures.BuildConcatenatedTarGz(t,
		[]fixtures.TarEntrySpec{{Name: "a.txt", Body: []byte("one\n")}},
		[]fixtures.TarEntrySpec{{Name: "b.txt", Body: []byte("two\n")}},
	)
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(concatGz), t.TempDir(), archive.EgressOptions{}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("concatenated gzip member expected ErrUnprocessable, got %v", err)
	}

	// 5. Truncated / corrupt tar.gz stream.
	validGz := fixtures.BuildTarGz(t, []fixtures.TarEntrySpec{{Name: "ok.txt", Body: []byte("hello world\n")}})
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(validGz[:len(validGz)/2]), t.TempDir(), archive.EgressOptions{}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("truncated tar.gz expected ErrUnprocessable, got %v", err)
	}

	// 6. Corrupt USTAR tar header / negative size field.
	var rawTar bytes.Buffer
	var hdr [512]byte
	copy(hdr[0:100], []byte("neg.txt"))
	copy(hdr[100:108], "0000644\x00")
	copy(hdr[108:116], "0000000\x00")
	copy(hdr[116:124], "0000000\x00")
	copy(hdr[124:136], "-0000000001\x00")
	copy(hdr[136:148], "14000000000\x00")
	for i := 148; i < 156; i++ {
		hdr[i] = ' '
	}
	hdr[156] = tar.TypeReg
	copy(hdr[257:263], []byte("ustar\x00"))
	copy(hdr[263:265], []byte("00"))
	var sum uint32
	for _, b := range hdr {
		sum += uint32(b)
	}
	copy(hdr[148:156], []byte(string([]byte{
		byte('0' + (sum>>15)&7),
		byte('0' + (sum>>12)&7),
		byte('0' + (sum>>9)&7),
		byte('0' + (sum>>6)&7),
		byte('0' + (sum>>3)&7),
		byte('0' + sum&7),
		0, ' ',
	})))
	rawTar.Write(hdr[:])
	rawTar.Write(make([]byte, 1024))
	var negBuf bytes.Buffer
	gw := gzip.NewWriter(&negBuf)
	_, _ = gw.Write(rawTar.Bytes())
	_ = gw.Close()
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(negBuf.Bytes()), t.TempDir(), archive.EgressOptions{}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("negative/corrupt tar size expected ErrUnprocessable, got %v", err)
	}
}

func TestADV02_PathTraversalAndUnsafePaths(t *testing.T) {
	ctx := context.Background()
	unsafePaths := []string{
		"../escape.txt",
		"sub/../../escape.txt",
		"/etc/passwd",
		`a\b.txt`,
		"C:drive.txt",
		"./C:drive.txt",
		"././C:drive.txt",
		"./C:/evil.txt",
		"./d:foo.txt",
		"sub/.git/config",
		"foo//bar.txt",
	}
	for _, p := range unsafePaths {
		gz := fixtures.BuildTarGz(t, []fixtures.TarEntrySpec{{Name: p, Body: []byte("bad\n")}})
		_, err := archive.ExtractEgress(ctx, bytes.NewReader(gz), t.TempDir(), archive.EgressOptions{})
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("path %q expected ErrUnprocessable, got %v", p, err)
		}
		var domErr *domain.DomainError
		if !errors.As(err, &domErr) || domErr.Code() != "UNSAFE_ARCHIVE_PATH" {
			t.Fatalf("path %q expected UNSAFE_ARCHIVE_PATH, got %v", p, err)
		}
	}

	// NUL byte delivered via PAX extended header.
	paxBody := []byte("16 path=a\x00b.txt\n")
	var paxTar bytes.Buffer
	var paxHdr [512]byte
	copy(paxHdr[0:100], []byte("paxheader"))
	copy(paxHdr[100:108], "0000644\x00")
	copy(paxHdr[108:116], "0000000\x00")
	copy(paxHdr[116:124], "0000000\x00")
	copy(paxHdr[124:136], []byte("00000000020\x00"))
	copy(paxHdr[136:148], []byte("14000000000\x00"))
	for i := 148; i < 156; i++ {
		paxHdr[i] = ' '
	}
	paxHdr[156] = tar.TypeXHeader
	copy(paxHdr[257:263], []byte("ustar\x00"))
	copy(paxHdr[263:265], []byte("00"))
	var sum uint32
	for _, b := range paxHdr {
		sum += uint32(b)
	}
	copy(paxHdr[148:156], []byte(string([]byte{
		byte('0' + (sum>>15)&7),
		byte('0' + (sum>>12)&7),
		byte('0' + (sum>>9)&7),
		byte('0' + (sum>>6)&7),
		byte('0' + (sum>>3)&7),
		byte('0' + sum&7),
		0, ' ',
	})))
	paxTar.Write(paxHdr[:])
	padded := make([]byte, 512)
	copy(padded, paxBody)
	paxTar.Write(padded)
	tw := tar.NewWriter(&paxTar)
	_ = tw.WriteHeader(&tar.Header{Name: "fallback.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	var paxGz bytes.Buffer
	gw := gzip.NewWriter(&paxGz)
	_, _ = gw.Write(paxTar.Bytes())
	_ = gw.Close()
	if _, err := archive.ExtractEgress(ctx, bytes.NewReader(paxGz.Bytes()), t.TempDir(), archive.EgressOptions{}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("NUL byte PAX path expected ErrUnprocessable, got %v", err)
	}
}

func TestADV03_SymlinksHardlinksSpecialFilesAndGitlinks(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		entry fixtures.TarEntrySpec
	}{
		{name: "symlink", entry: fixtures.TarEntrySpec{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}},
		{name: "hardlink", entry: fixtures.TarEntrySpec{Name: "hard", Typeflag: tar.TypeLink, Linkname: "target.txt"}},
		{name: "fifo", entry: fixtures.TarEntrySpec{Name: "pipe", Typeflag: tar.TypeFifo, Mode: 0o600}},
		{name: "char_device", entry: fixtures.TarEntrySpec{Name: "cdev", Typeflag: tar.TypeChar, Mode: 0o600}},
		{name: "block_device", entry: fixtures.TarEntrySpec{Name: "bdev", Typeflag: tar.TypeBlock, Mode: 0o600}},
		{name: "gitlink_0160000", entry: fixtures.TarEntrySpec{Name: "submod", Typeflag: tar.TypeReg, Mode: 0o160000}},
		{name: "root_gitmodules", entry: fixtures.TarEntrySpec{Name: ".gitmodules", Body: []byte("[submodule \"x\"]\n\tpath = x\n\turl = https://evil.test/x.git\n")}},
		{name: "nested_gitmodules", entry: fixtures.TarEntrySpec{Name: "vendor/.gitmodules", Body: []byte("[submodule \"x\"]\n")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gz := fixtures.BuildTarGz(t, []fixtures.TarEntrySpec{tc.entry})
			if _, err := archive.ExtractEgress(ctx, bytes.NewReader(gz), t.TempDir(), archive.EgressOptions{}); !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("case %s expected ErrUnprocessable, got %v", tc.name, err)
			}
		})
	}
}

func TestADV04_CaseAndUnicodeCollisions(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		entries []fixtures.TarEntrySpec
	}{
		{
			name: "case_collision",
			entries: []fixtures.TarEntrySpec{
				{Name: "README.md", Body: []byte("upper\n")},
				{Name: "readme.md", Body: []byte("lower\n")},
			},
		},
		{
			name: "nfc_nfd_collision",
			entries: []fixtures.TarEntrySpec{
				{Name: "caf\u00e9.txt", Body: []byte("nfc\n")},
				{Name: "cafe\u0301.txt", Body: []byte("nfd\n")},
			},
		},
		{
			name: "file_dir_collision",
			entries: []fixtures.TarEntrySpec{
				{Name: "Dir/file.txt", Body: []byte("inside\n")},
				{Name: "dir", Body: []byte("file-colliding-with-dir\n")},
			},
		},
		{
			name: "duplicate_dir_entry",
			entries: []fixtures.TarEntrySpec{
				{Name: "pkg", Typeflag: tar.TypeDir, Mode: 0o755},
				{Name: "PKG", Typeflag: tar.TypeDir, Mode: 0o755},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gz := fixtures.BuildTarGz(t, tc.entries)
			if _, err := archive.ExtractEgress(ctx, bytes.NewReader(gz), t.TempDir(), archive.EgressOptions{}); !errors.Is(err, domain.ErrUnprocessable) {
				t.Fatalf("case %s expected ErrUnprocessable, got %v", tc.name, err)
			}
		})
	}
}

func TestADV05_GitHooksConfigAndFilterSmuggling(t *testing.T) {
	ctx := context.Background()
	gitH := harness.NewBareGitHarness(t, "")
	bareRepo, err := gitH.InitBareRepo("acme", "smuggle-test", harness.WithInitialFiles(map[string]string{
		"README.md": "# Clean\n",
	}))
	if err != nil {
		t.Fatalf("InitBareRepo: %v", err)
	}
	sh := harness.NewSnapshotHarness(t)
	writeClient := write.NewLocalBareClient(write.WithBareRootDir(gitH.RootDir()))
	if err := writeClient.RegisterRepo(bareRepo.GitHubRepositoryID, bareRepo.FullName, bareRepo.BarePath); err != nil {
		t.Fatalf("RegisterRepo: %v", err)
	}

	markerFile := filepath.Join(t.TempDir(), "pwned.marker")
	evilFilterCmd := "touch " + markerFile
	egressGz := fixtures.BuildTarGz(t, []fixtures.TarEntrySpec{
		{Name: "README.md", Body: []byte("# Updated\n")},
		{Name: ".git/hooks/post-checkout", Mode: 0o755, Body: []byte("#!/bin/sh\n" + evilFilterCmd + "\n")},
		{Name: ".git/config", Body: []byte("[core]\n\tfsmonitor = " + evilFilterCmd + "\n[filter \"evil\"]\n\tclean = " + evilFilterCmd + "\n\tsmudge = " + evilFilterCmd + "\n")},
		{Name: ".gitattributes", Body: []byte("*.txt filter=evil diff=evil\n")},
		{Name: "notes.txt", Body: []byte("innocent text\n")},
	})

	snapArt, err := sh.PutBytes(ctx, domain.ArtifactKindEgressSnapshot, "egress/smuggle.tar.gz", egressGz)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}

	reconSvc, err := reconstruct.NewService(reconstruct.Config{
		GitReader:     gitH.LocalReader(),
		SnapshotStore: sh.Store(),
	})
	if err != nil {
		t.Fatalf("reconstruct.NewService: %v", err)
	}

	repo := domain.Repository{
		ID:                 domain.MustNewID(),
		GitHubRepositoryID: bareRepo.GitHubRepositoryID,
		FullName:           bareRepo.FullName,
		Classification:     domain.ClassificationInternal,
		Enabled:            true,
	}
	reconRes, err := reconSvc.ReconstructDetailed(ctx, repo, bareRepo.HeadSHA, snapArt)
	if err != nil {
		t.Fatalf("ReconstructDetailed: %v", err)
	}

	// Verify sandbox .git/* files are absent from canonical changes.
	for _, ch := range reconRes.Manifest.Changes {
		if strings.HasPrefix(ch.Path, ".git/") {
			t.Fatalf("ADV-05 violation: .git metadata leaked into canonical manifest: %s", ch.Path)
		}
	}

	// Publish reconstructed tree and verify evil filter/fsmonitor/hook command never executed.
	pubSvc, err := publish.NewService(publish.Config{
		WriteClient:    writeClient,
		CommitterName:  "Custodian",
		CommitterEmail: "custodian@custodian.local",
		ArtifactOpener: sh.Store(),
	})
	if err != nil {
		t.Fatalf("publish.NewService: %v", err)
	}

	propID := domain.MustNewID()
	wsID := domain.MustNewID()
	pubRes, err := pubSvc.PublishRequest(ctx, publish.PublishRequest{
		ProposalID:                  propID,
		WorkspaceID:                 wsID,
		Repository:                  repo,
		Owner:                       domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman, DisplayName: "Alice", VerifiedEmail: "alice@acme.test"},
		BaseCommit:                  bareRepo.HeadSHA,
		TargetRef:                   "main",
		Title:                       "Smuggle containment",
		ManifestDigest:              reconRes.Change.ManifestDigest,
		ExpectedTreeDigest:          reconRes.Change.TreeDigest,
		ExpectedCanonicalTreeSHA256: reconRes.Change.Artifact.SHA256,
		CanonicalTreeArtifact:       &reconRes.Change.Artifact,
	})
	if err != nil {
		t.Fatalf("PublishRequest: %v", err)
	}
	if pubRes.Branch != "custodian/"+propID.String() {
		t.Fatalf("unexpected branch %q", pubRes.Branch)
	}
	if _, statErr := os.Stat(markerFile); !os.IsNotExist(statErr) {
		t.Fatalf("ADV-05 CRITICAL VIOLATION: malicious git hook/filter executed and created %s", markerFile)
	}
}
