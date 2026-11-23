package harness

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

// TarEntry describes a single entry for deterministic or adversarial tar.gz construction.
type TarEntry struct {
	Name      string
	Typeflag  byte // 0 auto-selects tar.TypeReg (or tar.TypeDir if trailing '/' and empty Body)
	Body      []byte
	Mode      int64 // default 0o644 for reg, 0o755 for dir
	Linkname  string
	Devmajor  int64
	Devminor  int64
	ModTime   time.Time // overridden in deterministic mode
	Uid       int
	Gid       int
	RawHeader bool // bypass archive/tar.Writer validation using a raw 512-byte USTAR header
}

// CorruptArchiveMode selects the corruption pattern for BuildCorruptTarGz.
type CorruptArchiveMode string

const (
	CorruptRandomBytes       CorruptArchiveMode = "random_bytes"
	CorruptTarChecksum       CorruptArchiveMode = "tar_checksum"
	CorruptTruncatedGzip     CorruptArchiveMode = "truncated_gzip"
	CorruptTruncatedTarEntry CorruptArchiveMode = "truncated_tar_entry"
)

// Traversal presets for BuildPathTraversalArchive.
const (
	TraversalDotDot    = "../../etc/passwd"
	TraversalNested    = "a/b/../../../escape.txt"
	TraversalAbsolute  = "/etc/shadow"
	TraversalBackslash = `a\..\b.txt`
)

var deterministicModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// SHA256Hex returns the 64-char lowercase hex SHA-256 digest of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SHA256Prefixed returns "sha256:" + 64-char lowercase hex SHA-256 digest of b.
func SHA256Prefixed(b []byte) string {
	return "sha256:" + SHA256Hex(b)
}

func normalizeTarEntry(e TarEntry, mtime time.Time, uid, gid int) TarEntry {
	cp := e
	if cp.Typeflag == 0 {
		if strings.HasSuffix(cp.Name, "/") && len(cp.Body) == 0 {
			cp.Typeflag = tar.TypeDir
		} else {
			cp.Typeflag = tar.TypeReg
		}
	}
	if cp.Mode == 0 {
		switch cp.Typeflag {
		case tar.TypeDir:
			cp.Mode = 0o755
		case tar.TypeSymlink:
			cp.Mode = 0o777
		default:
			cp.Mode = 0o644
		}
	}
	cp.ModTime = mtime
	cp.Uid = uid
	cp.Gid = gid
	if cp.Typeflag != tar.TypeReg {
		cp.Body = nil
	}
	return cp
}

// encodeRawUSTARHeader writes a 512-byte POSIX USTAR header block directly, allowing
// adversarial tests to emit unsupported Typeflags or malformed headers that archive/tar rejects.
func encodeRawUSTARHeader(name string, typeflag byte, mode, size int64, linkname string) [512]byte {
	var blk [512]byte
	copy(blk[0:100], []byte(name))
	copy(blk[100:108], fmt.Sprintf("%07o\x00", mode&0o777777))
	copy(blk[108:116], "0000000\x00")
	copy(blk[116:124], "0000000\x00")
	copy(blk[124:136], fmt.Sprintf("%011o\x00", size))
	copy(blk[136:148], fmt.Sprintf("%011o\x00", deterministicModTime.Unix()))
	for i := 148; i < 156; i++ {
		blk[i] = ' '
	}
	blk[156] = typeflag
	copy(blk[157:257], []byte(linkname))
	copy(blk[257:263], []byte("ustar\x00"))
	copy(blk[263:265], []byte("00"))

	var sum uint32
	for _, b := range blk {
		sum += uint32(b)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

func buildTarStream(entries []TarEntry) ([]byte, error) {
	var tarBuf bytes.Buffer
	hasRaw := false
	for _, e := range entries {
		if e.RawHeader {
			hasRaw = true
			break
		}
	}

	if !hasRaw {
		tw := tar.NewWriter(&tarBuf)
		for _, e := range entries {
			hdr := &tar.Header{
				Name:     e.Name,
				Mode:     e.Mode,
				Uid:      e.Uid,
				Gid:      e.Gid,
				Size:     int64(len(e.Body)),
				ModTime:  e.ModTime,
				Typeflag: e.Typeflag,
				Linkname: e.Linkname,
				Devmajor: e.Devmajor,
				Devminor: e.Devminor,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, fmt.Errorf("write tar header %q: %w", e.Name, err)
			}
			if e.Typeflag == tar.TypeReg && len(e.Body) > 0 {
				if _, err := tw.Write(e.Body); err != nil {
					return nil, fmt.Errorf("write tar body %q: %w", e.Name, err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			return nil, fmt.Errorf("close tar writer: %w", err)
		}
		return tarBuf.Bytes(), nil
	}

	// Raw mode: write each entry directly with USTAR blocks so unsupported typeflags succeed.
	for _, e := range entries {
		blk := encodeRawUSTARHeader(e.Name, e.Typeflag, e.Mode, int64(len(e.Body)), e.Linkname)
		tarBuf.Write(blk[:])
		if len(e.Body) > 0 {
			tarBuf.Write(e.Body)
			if rem := len(e.Body) % 512; rem != 0 {
				tarBuf.Write(make([]byte, 512-rem))
			}
		}
	}
	tarBuf.Write(make([]byte, 1024)) // EOF two 512-byte zero blocks
	return tarBuf.Bytes(), nil
}

func gzipDeterministic(tarBytes []byte) ([]byte, error) {
	var gzBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gw.Header = gzip.Header{
		ModTime: time.Unix(0, 0).UTC(),
		OS:      255,
	}
	if _, err := gw.Write(tarBytes); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return gzBuf.Bytes(), nil
}

// BuildTarGzE builds a deterministic tar.gz archive (sorted by Name, normalized ModTime/UID/GID,
// fixed gzip header) and returns (gzBytes, sha256HexLower, err).
func BuildTarGzE(entries []TarEntry) ([]byte, string, error) {
	norm := make([]TarEntry, len(entries))
	for i, e := range entries {
		norm[i] = normalizeTarEntry(e, deterministicModTime, 0, 0)
	}
	slices.SortStableFunc(norm, func(a, b TarEntry) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	tarBytes, err := buildTarStream(norm)
	if err != nil {
		return nil, "", err
	}
	gzBytes, err := gzipDeterministic(tarBytes)
	if err != nil {
		return nil, "", err
	}
	return gzBytes, SHA256Hex(gzBytes), nil
}

// BuildTarGz builds a deterministic tar.gz archive and returns (gzBytes, sha256HexLower).
func BuildTarGz(entries []TarEntry) ([]byte, string) {
	gz, sum, err := BuildTarGzE(entries)
	if err != nil {
		panic(fmt.Sprintf("BuildTarGz failed: %v", err))
	}
	return gz, sum
}

// MustBuildTarGz builds a deterministic tar.gz archive, failing t on error.
func MustBuildTarGz(t testing.TB, entries []TarEntry) ([]byte, string) {
	t.Helper()
	gz, sum, err := BuildTarGzE(entries)
	if err != nil {
		t.Fatalf("MustBuildTarGz failed: %v", err)
	}
	return gz, sum
}

// BuildTarGzWithVaryingMeta builds a valid tar.gz with altered mtime, uid, gid, and optional reverse ordering,
// producing different archive bytes/SHA-256 for the same logical tree (for F-11 canonical digest tests).
func BuildTarGzWithVaryingMeta(entries []TarEntry, mtime time.Time, uid, gid int, reverseOrder bool) ([]byte, string) {
	norm := make([]TarEntry, len(entries))
	for i, e := range entries {
		norm[i] = normalizeTarEntry(e, mtime, uid, gid)
	}
	slices.SortStableFunc(norm, func(a, b TarEntry) int {
		if reverseOrder {
			if a.Name > b.Name {
				return -1
			}
			if a.Name < b.Name {
				return 1
			}
			return 0
		}
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	tarBytes, err := buildTarStream(norm)
	if err != nil {
		panic(fmt.Sprintf("BuildTarGzWithVaryingMeta tar failed: %v", err))
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Header.ModTime = mtime
	if _, err := gw.Write(tarBytes); err != nil {
		panic(fmt.Sprintf("BuildTarGzWithVaryingMeta gzip write failed: %v", err))
	}
	if err := gw.Close(); err != nil {
		panic(fmt.Sprintf("BuildTarGzWithVaryingMeta gzip close failed: %v", err))
	}
	gzBytes := gzBuf.Bytes()
	return gzBytes, SHA256Hex(gzBytes)
}

// ExtractTarGz reads a tar.gz archive into memory (capped at 64 MiB uncompressed) for ingress/sanitisation assertions.
func ExtractTarGz(gzBytes []byte) ([]TarEntry, error) {
	const maxUncompressed = 64 << 20
	gzr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(io.LimitReader(gzr, maxUncompressed+1))
	var out []TarEntry
	var totalRead int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}
		var body []byte
		if hdr.Size > 0 {
			totalRead += hdr.Size
			if totalRead > maxUncompressed {
				return nil, fmt.Errorf("archive exceeds max inspection limit (%d bytes)", maxUncompressed)
			}
			body, err = io.ReadAll(io.LimitReader(tr, maxUncompressed+1))
			if err != nil {
				return nil, fmt.Errorf("tar read body %q: %w", hdr.Name, err)
			}
		}
		out = append(out, TarEntry{
			Name:     hdr.Name,
			Typeflag: hdr.Typeflag,
			Body:     body,
			Mode:     hdr.Mode,
			Linkname: hdr.Linkname,
			Devmajor: hdr.Devmajor,
			Devminor: hdr.Devminor,
			ModTime:  hdr.ModTime,
			Uid:      hdr.Uid,
			Gid:      hdr.Gid,
		})
	}
	return out, nil
}

// BuildGitInjectionArchive appends malicious .git/hooks, .git/config, and .git/HEAD entries to base.
func BuildGitInjectionArchive(base []TarEntry) ([]byte, string) {
	entries := make([]TarEntry, 0, len(base)+3)
	entries = append(entries, base...)
	fakeGitHubToken := "ghp_" + "FAKEADMIN999TESTONLY0000000000000000"
	entries = append(entries,
		TarEntry{
			Name:     ".git/hooks/pre-commit",
			Typeflag: tar.TypeReg,
			Mode:     0o755,
			Body:     []byte("#!/bin/sh\necho PWNED\nexit 1\n"),
		},
		TarEntry{
			Name:     ".git/config",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body: []byte(fmt.Sprintf(
				"[core]\n\tfsmonitor = sh -c id\n\tsshCommand = sh -c id\n[credential]\n\thelper = store\n[remote \"origin\"]\n\turl = https://x-access-token:%s@github.com/org/repo.git\n",
				fakeGitHubToken,
			)),
		},
		TarEntry{
			Name:     ".git/HEAD",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("ref: refs/heads/evil\n"),
		},
	)
	return BuildTarGz(entries)
}

// BuildPathTraversalArchive builds an archive containing a traversal path (e.g. TraversalDotDot).
func BuildPathTraversalArchive(traversalPath string) ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:     traversalPath,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("traversal payload\n"),
		},
	})
}

// BuildSymlinkArchive builds an archive containing a symlink entry.
func BuildSymlinkArchive(linkPath, target string) ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:     linkPath,
			Typeflag: tar.TypeSymlink,
			Linkname: target,
			Mode:     0o777,
		},
	})
}

// BuildHardlinkArchive builds an archive with a regular target file and a hardlink entry.
func BuildHardlinkArchive(linkPath, target string) ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:     target,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("target data\n"),
		},
		{
			Name:     linkPath,
			Typeflag: tar.TypeLink,
			Linkname: target,
			Mode:     0o644,
		},
	})
}

// BuildSpecialFileArchive builds an archive containing a special file (tar.TypeFifo, tar.TypeChar, tar.TypeBlock).
func BuildSpecialFileArchive(kind byte, path string) ([]byte, string) {
	entry := TarEntry{
		Name:     path,
		Typeflag: kind,
		Mode:     0o600,
	}
	switch kind {
	case tar.TypeChar:
		entry.Devmajor = 1
		entry.Devminor = 3
	case tar.TypeBlock:
		entry.Devmajor = 8
		entry.Devminor = 0
	}
	return BuildTarGz([]TarEntry{entry})
}

// BuildSubmoduleArchive builds an archive containing both .gitmodules and a 0o160000 gitlink entry.
func BuildSubmoduleArchive() ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:     ".gitmodules",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("[submodule \"evil\"]\n\tpath = vendor/evil\n\turl = https://github.com/evil/repo\n"),
		},
		{
			Name:     "vendor/evil",
			Typeflag: tar.TypeDir,
			Mode:     0o160000,
		},
	})
}

// BuildUnicodeCollisionArchive builds an archive containing NFC ("café.txt") and NFD ("cafe\u0301.txt") entries.
func BuildUnicodeCollisionArchive() ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:     "caf\u00e9.txt",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("nfc\n"),
		},
		{
			Name:     "cafe\u0301.txt",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("nfd\n"),
		},
	})
}

// BuildCaseCollisionArchive builds an archive containing case-colliding filenames ("Config.yaml" and "config.yaml").
func BuildCaseCollisionArchive() ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:     "Config.yaml",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("upper: true\n"),
		},
		{
			Name:     "config.yaml",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Body:     []byte("lower: true\n"),
		},
	})
}

// BuildUnsupportedTypeArchive builds an archive using a raw USTAR header with an unsupported typeflag byte (e.g. '?').
func BuildUnsupportedTypeArchive(typeflag byte, path string) ([]byte, string) {
	return BuildTarGz([]TarEntry{
		{
			Name:      path,
			Typeflag:  typeflag,
			Mode:      0o644,
			RawHeader: true,
		},
	})
}

// BuildCorruptTarGz builds intentionally malformed/corrupt tar.gz bytes.
func BuildCorruptTarGz(mode CorruptArchiveMode) []byte {
	switch mode {
	case CorruptRandomBytes:
		return []byte("not-a-gzip-stream-\x00\xff\xfe\xfd-corrupt-payload")
	case CorruptTarChecksum:
		blk := encodeRawUSTARHeader("broken.txt", tar.TypeReg, 0o644, 0, "")
		copy(blk[148:156], "0000000\x00") // invalid checksum
		var tarBuf bytes.Buffer
		tarBuf.Write(blk[:])
		tarBuf.Write(make([]byte, 1024))
		gz, err := gzipDeterministic(tarBuf.Bytes())
		if err != nil {
			panic(err)
		}
		return gz
	case CorruptTruncatedGzip:
		valid, _ := BuildTarGz([]TarEntry{
			{Name: "hello.txt", Body: []byte("hello world from custodian e2e test\n")},
		})
		half := len(valid) / 2
		if half < 10 {
			half = len(valid) - 1
		}
		return valid[:half]
	case CorruptTruncatedTarEntry:
		blk := encodeRawUSTARHeader("truncated.bin", tar.TypeReg, 0o644, 4096, "")
		var tarBuf bytes.Buffer
		tarBuf.Write(blk[:])
		tarBuf.Write(bytes.Repeat([]byte("A"), 64)) // claims 4096 bytes, ends after 64
		gz, err := gzipDeterministic(tarBuf.Bytes())
		if err != nil {
			panic(err)
		}
		return gz
	default:
		return []byte("not-a-gzip-stream")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// BuildGzipBomb streams decompressedSize zero bytes into a single tar entry compressed at BestCompression
// without allocating decompressedSize bytes in memory.
func BuildGzipBomb(decompressedSize int64) ([]byte, string) {
	if decompressedSize < 0 {
		decompressedSize = 0
	}
	var gzBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	gw.Header = gzip.Header{
		ModTime: time.Unix(0, 0).UTC(),
		OS:      255,
	}
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "bomb.bin",
		Mode:     0o644,
		Size:     decompressedSize,
		ModTime:  deterministicModTime,
		Typeflag: tar.TypeReg,
	}); err != nil {
		panic(err)
	}
	if _, err := io.Copy(tw, io.LimitReader(zeroReader{}, decompressedSize)); err != nil {
		panic(err)
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := gw.Close(); err != nil {
		panic(err)
	}
	gzBytes := gzBuf.Bytes()
	return gzBytes, SHA256Hex(gzBytes)
}
