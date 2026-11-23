package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/timreynolds/custodian/internal/domain"
)

type rawTarSpec struct {
	name      string
	typeflag  byte
	mode      int64
	body      []byte
	linkname  string
	devmajor  int64
	devminor  int64
	rawHeader bool
	rawSize   int64
}

func buildRawUSTARHeader(name string, typeflag byte, mode, size int64, linkname string, corruptChecksum bool) [512]byte {
	var blk [512]byte
	copy(blk[0:100], []byte(name))
	copy(blk[100:108], fmt.Sprintf("%07o\x00", mode&0o777777))
	copy(blk[108:116], "0000000\x00")
	copy(blk[116:124], "0000000\x00")
	copy(blk[124:136], fmt.Sprintf("%011o\x00", size))
	copy(blk[136:148], fmt.Sprintf("%011o\x00", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()))
	for i := 148; i < 156; i++ {
		blk[i] = ' '
	}
	blk[156] = typeflag
	copy(blk[157:257], []byte(linkname))
	copy(blk[257:263], []byte("ustar\x00"))
	copy(blk[263:265], []byte("00"))

	if corruptChecksum {
		copy(blk[148:156], "0000000\x00")
		return blk
	}
	var sum uint32
	for _, b := range blk {
		sum += uint32(b)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

func buildTestTarGz(t testing.TB, specs []rawTarSpec) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	hasRaw := false
	for _, s := range specs {
		if s.rawHeader {
			hasRaw = true
			break
		}
	}

	if !hasRaw {
		tw := tar.NewWriter(&tarBuf)
		for _, s := range specs {
			tf := s.typeflag
			if tf == 0 && s.rawHeader {
				tf = tar.TypeRegA
			}
			mode := s.mode
			if mode == 0 && tf != tar.TypeRegA {
				if tf == tar.TypeDir {
					mode = 0o755
				} else {
					mode = 0o644
				}
			}
			hdr := &tar.Header{
				Name:     s.name,
				Mode:     mode,
				Size:     int64(len(s.body)),
				ModTime:  EpochTime,
				Typeflag: tf,
				Linkname: s.linkname,
				Devmajor: s.devmajor,
				Devminor: s.devminor,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatalf("WriteHeader(%q): %v", s.name, err)
			}
			if (tf == tar.TypeReg || tf == tar.TypeRegA) && len(s.body) > 0 {
				if _, err := tw.Write(s.body); err != nil {
					t.Fatalf("Write(%q): %v", s.name, err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("tw.Close: %v", err)
		}
	} else {
		for _, s := range specs {
			sz := int64(len(s.body))
			if s.rawSize > 0 {
				sz = s.rawSize
			}
			blk := buildRawUSTARHeader(s.name, s.typeflag, s.mode, sz, s.linkname, false)
			tarBuf.Write(blk[:])
			if len(s.body) > 0 {
				tarBuf.Write(s.body)
				if rem := len(s.body) % 512; rem != 0 {
					tarBuf.Write(make([]byte, 512-rem))
				}
			}
		}
		tarBuf.Write(make([]byte, 1024))
	}

	var gzBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip.NewWriterLevel: %v", err)
	}
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gw.Write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gw.Close: %v", err)
	}
	return gzBuf.Bytes()
}

type zeroStreamReader struct{}

func (zeroStreamReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func buildZeroBombTarGz(t testing.TB, entryName string, decompressedSize int64) []byte {
	t.Helper()
	var gzBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("gzip.NewWriterLevel: %v", err)
	}
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     entryName,
		Mode:     0o644,
		Size:     decompressedSize,
		ModTime:  EpochTime,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := io.Copy(tw, io.LimitReader(zeroStreamReader{}, decompressedSize)); err != nil {
		t.Fatalf("io.Copy bomb: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tw.Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gw.Close: %v", err)
	}
	return gzBuf.Bytes()
}

func assertUnprocessable(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error wrapping domain.ErrUnprocessable, got nil", label)
	}
	if !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("%s: expected errors.Is(err, domain.ErrUnprocessable), got %v", label, err)
	}
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected clean empty dir %s after failed extraction, found %d entries", dir, len(entries))
	}
}

func TestEgress_ValidEdgeCasesAndSafeExtraction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	specs := []rawTarSpec{
		{name: "./", typeflag: tar.TypeDir, mode: 0o755},
		{name: "pkg/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "pkg/sub/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "empty_dir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "./README.md", typeflag: tar.TypeReg, mode: 0o644, body: []byte("# Custodian\n")},
		{name: "scripts/build.sh", typeflag: tar.TypeReg, mode: 0o755, body: []byte("#!/bin/sh\necho ok\n")},
		{name: "marker.empty", typeflag: tar.TypeReg, mode: 0o644, body: nil},
		{name: "docs/caf\u00e9.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("cafe\n")},
		{name: "docs/na\u00efve.md", typeflag: tar.TypeReg, mode: 0o644, body: []byte("naive\n")},
		// Out-of-order child before parent TypeDir (should succeed).
		{name: "late/child.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("child\n")},
		{name: "late/", typeflag: tar.TypeDir, mode: 0o755},
		// V7 TypeRegA entry.
		{name: "legacy.txt", typeflag: tar.TypeRegA, mode: 0o100644, body: []byte("legacy\n"), rawHeader: true},
	}

	gzBytes := buildTestTarGz(t, specs)

	valRes, err := ValidateEgress(ctx, bytes.NewReader(gzBytes), EgressOptions{})
	if err != nil {
		t.Fatalf("ValidateEgress failed: %v", err)
	}
	if valRes.FileCount != 7 {
		t.Fatalf("expected 7 files, got %d (%+v)", valRes.FileCount, valRes.Files)
	}

	destDir := t.TempDir()
	extRes, err := ExtractEgress(ctx, bytes.NewReader(gzBytes), destDir, EgressOptions{})
	if err != nil {
		t.Fatalf("ExtractEgress failed: %v", err)
	}
	if extRes.FileCount != valRes.FileCount || extRes.TotalBytes != valRes.TotalBytes {
		t.Fatalf("ValidateEgress vs ExtractEgress mismatch: %+v vs %+v", valRes, extRes)
	}

	// Verify normalized paths and permissions on disk.
	infoBuild, err := os.Stat(filepath.Join(destDir, "scripts", "build.sh"))
	if err != nil {
		t.Fatalf("stat build.sh: %v", err)
	}
	if infoBuild.Mode().Perm() != 0o755 {
		t.Fatalf("expected 0755 on build.sh, got %o", infoBuild.Mode().Perm())
	}

	infoReadme, err := os.Stat(filepath.Join(destDir, "README.md"))
	if err != nil {
		t.Fatalf("stat README.md: %v", err)
	}
	if infoReadme.Mode().Perm() != 0o644 {
		t.Fatalf("expected 0644 on README.md, got %o", infoReadme.Mode().Perm())
	}

	emptyBytes, err := os.ReadFile(filepath.Join(destDir, "marker.empty"))
	if err != nil || len(emptyBytes) != 0 {
		t.Fatalf("expected 0-byte marker.empty, got len=%d err=%v", len(emptyBytes), err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "empty_dir")); err != nil {
		t.Fatalf("expected empty_dir to exist: %v", err)
	}

	// Verify golden clean_snapshot.tar.gz fixture validates and extracts cleanly.
	goldenPath := filepath.Join("..", "..", "test", "e2e", "fixtures", "golden", "clean_snapshot.tar.gz")
	gf, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("open golden fixture: %v", err)
	}
	defer gf.Close()

	goldenDest := t.TempDir()
	goldenRes, err := ExtractEgress(ctx, gf, goldenDest, EgressOptions{})
	if err != nil {
		t.Fatalf("ExtractEgress(golden): %v", err)
	}
	if goldenRes.FileCount != 2 {
		t.Fatalf("expected 2 files in golden fixture, got %d", goldenRes.FileCount)
	}
}

func TestEgress_ADV01_CorruptTruncatedAndBombArchives(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. Random bytes and empty input.
	for name, payload := range map[string][]byte{
		"empty":        {},
		"random_bytes": []byte("not-a-gzip-stream-\x00\xff\xfe\xfd"),
	} {
		dest := t.TempDir()
		_, err := ExtractEgress(ctx, bytes.NewReader(payload), dest, EgressOptions{})
		assertUnprocessable(t, err, name)
		assertDirEmpty(t, dest)
	}

	// 2. Corrupt tar header checksum.
	{
		blk := buildRawUSTARHeader("broken.txt", tar.TypeReg, 0o644, 0, "", true)
		var tarBuf bytes.Buffer
		tarBuf.Write(blk[:])
		tarBuf.Write(make([]byte, 1024))
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		_, _ = gw.Write(tarBuf.Bytes())
		_ = gw.Close()
		dest := t.TempDir()
		_, err := ExtractEgress(ctx, bytes.NewReader(gzBuf.Bytes()), dest, EgressOptions{})
		assertUnprocessable(t, err, "bad_tar_checksum")
		assertDirEmpty(t, dest)
	}

	// 3. Truncated gzip stream after a valid file (verifies mid-stream cleanup!).
	{
		valid := buildTestTarGz(t, []rawTarSpec{
			{name: "ok.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("hello world from custodian\n")},
		})
		truncated := valid[:len(valid)-6] // chop gzip CRC32/ISIZE trailer
		dest := t.TempDir()
		_, err := ExtractEgress(ctx, bytes.NewReader(truncated), dest, EgressOptions{})
		assertUnprocessable(t, err, "truncated_gzip_trailer")
		assertDirEmpty(t, dest)
	}

	// 4. Truncated tar entry body.
	{
		blk := buildRawUSTARHeader("truncated.bin", tar.TypeReg, 0o644, 4096, "", false)
		var tarBuf bytes.Buffer
		tarBuf.Write(blk[:])
		tarBuf.Write(bytes.Repeat([]byte("A"), 64))
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		_, _ = gw.Write(tarBuf.Bytes())
		_ = gw.Close()
		dest := t.TempDir()
		_, err := ExtractEgress(ctx, bytes.NewReader(gzBuf.Bytes()), dest, EgressOptions{})
		assertUnprocessable(t, err, "truncated_tar_entry")
		assertDirEmpty(t, dest)
	}

	// 5. Trailing garbage and concatenated multistream gzip.
	{
		valid := buildTestTarGz(t, []rawTarSpec{
			{name: "a.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("a\n")},
		})
		withTrailing := append(append([]byte(nil), valid...), []byte("trailing")...)
		_, err := ValidateEgress(ctx, bytes.NewReader(withTrailing), EgressOptions{})
		assertUnprocessable(t, err, "trailing_bytes")

		multiStream := append(append([]byte(nil), valid...), valid...)
		_, err = ValidateEgress(ctx, bytes.NewReader(multiStream), EgressOptions{})
		assertUnprocessable(t, err, "multistream_gzip")
	}

	// 6. Decompression bombs (64 MiB and 128 MiB) under default limits, plus bomb hidden under .git/.
	for _, tc := range []struct {
		name string
		path string
		size int64
	}{
		{name: "bomb_64MiB", path: "bomb.bin", size: 64 << 20},
		{name: "bomb_128MiB", path: "bomb.bin", size: 128 << 20},
		{name: "bomb_inside_git", path: ".git/objects/bomb.bin", size: 64 << 20},
	} {
		bomb := buildZeroBombTarGz(t, tc.path, tc.size)
		dest := t.TempDir()
		_, err := ExtractEgress(ctx, bytes.NewReader(bomb), dest, EgressOptions{})
		assertUnprocessable(t, err, tc.name)
		assertDirEmpty(t, dest)
	}

	// 7. Entry count limit & compressed size limit & exact boundary pass.
	{
		many := make([]rawTarSpec, 15)
		for i := range many {
			many[i] = rawTarSpec{
				name:     fmt.Sprintf("f%02d.txt", i),
				typeflag: tar.TypeReg,
				mode:     0o644,
				body:     []byte("x"),
			}
		}
		manyGz := buildTestTarGz(t, many)
		_, err := ValidateEgress(ctx, bytes.NewReader(manyGz), EgressOptions{MaxEntries: 10})
		assertUnprocessable(t, err, "max_entries_exceeded")

		// Exact compressed boundary succeeds; 1 byte smaller fails.
		exactOpts := EgressOptions{MaxCompressedBytes: int64(len(manyGz))}
		if _, err := ValidateEgress(ctx, bytes.NewReader(manyGz), exactOpts); err != nil {
			t.Fatalf("expected exact MaxCompressedBytes boundary to succeed, got %v", err)
		}
		_, err = ValidateEgress(ctx, bytes.NewReader(manyGz), EgressOptions{MaxCompressedBytes: int64(len(manyGz) - 1)})
		assertUnprocessable(t, err, "max_compressed_bytes_exceeded")
	}
}

func TestEgress_ADV02_PathTraversalAndIllegalNames(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	badPaths := []struct {
		name     string
		path     string
		typeflag byte
	}{
		{name: "dotdot", path: "../../etc/passwd", typeflag: tar.TypeReg},
		{name: "nested_dotdot", path: "a/b/../../../escape.txt", typeflag: tar.TypeReg},
		{name: "dot_slash_dotdot", path: "./../escape.txt", typeflag: tar.TypeReg},
		{name: "abs_path", path: "/etc/shadow", typeflag: tar.TypeReg},
		{name: "backslash", path: `a\..\b.txt`, typeflag: tar.TypeReg},
		{name: "newline", path: "a\nb.txt", typeflag: tar.TypeReg},
		{name: "invalid_utf8", path: "bad_\xff_name.txt", typeflag: tar.TypeReg},
		{name: "empty_segment", path: "a//b.txt", typeflag: tar.TypeReg},
		{name: "interior_dot", path: "a/./b.txt", typeflag: tar.TypeReg},
		{name: "root_dot_as_reg", path: ".", typeflag: tar.TypeReg},
		{name: "trailing_slash_on_reg", path: "foo/", typeflag: tar.TypeReg},
		{name: "empty_name", path: "", typeflag: tar.TypeReg},
		{name: "nested_dotgit", path: "vendor/.git/hooks/pre-commit", typeflag: tar.TypeReg},
		{name: "nested_dotGIT", path: "vendor/.GIT/config", typeflag: tar.TypeReg},
		{name: "windows_drive_raw", path: "C:drive.txt", typeflag: tar.TypeReg},
		{name: "windows_drive_dot_slash", path: "./C:drive.txt", typeflag: tar.TypeReg},
		{name: "windows_drive_double_dot_slash", path: "././C:drive.txt", typeflag: tar.TypeReg},
		{name: "windows_drive_slash", path: "./C:/evil.txt", typeflag: tar.TypeReg},
		{name: "windows_drive_lower", path: "./d:foo.txt", typeflag: tar.TypeReg},
		{name: "windows_drive_dir", path: "./C:/", typeflag: tar.TypeDir},
	}

	for _, tc := range badPaths {
		t.Run(tc.name, func(t *testing.T) {
			gz := buildTestTarGz(t, []rawTarSpec{
				{name: tc.path, typeflag: tc.typeflag, mode: 0o644, body: []byte("x"), rawHeader: true},
			})
			dest := t.TempDir()
			_, err := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
			assertUnprocessable(t, err, tc.name)
			assertDirEmpty(t, dest)
		})
	}

	t.Run("windows_drive_unsafe_archive_path_code", func(t *testing.T) {
		for _, p := range []string{"C:drive.txt", "./C:drive.txt", "././C:drive.txt", "./C:/evil.txt", "./d:foo.txt"} {
			gz := buildTestTarGz(t, []rawTarSpec{
				{name: p, typeflag: tar.TypeReg, mode: 0o644, body: []byte("x"), rawHeader: true},
			})
			dest := t.TempDir()
			_, err := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
			assertUnprocessable(t, err, p)
			var domErr *domain.DomainError
			if !errors.As(err, &domErr) || domErr.Code() != "UNSAFE_ARCHIVE_PATH" {
				t.Fatalf("%q: expected UNSAFE_ARCHIVE_PATH, got %v", p, err)
			}
			assertDirEmpty(t, dest)
		}
	})

	// NUL byte delivered via PAX ('x') header so tar.Reader parses "a\x00b.txt" verbatim,
	// plus direct normalizeEgressTarPath check.
	t.Run("nul_byte_pax", func(t *testing.T) {
		paxRec := "16 path=a\x00b.txt\n"
		gz := buildTestTarGz(t, []rawTarSpec{
			{name: "paxheader", typeflag: tar.TypeXHeader, mode: 0o644, body: []byte(paxRec), rawHeader: true},
			{name: "fallback.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x"), rawHeader: true},
		})
		dest := t.TempDir()
		_, err := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
		assertUnprocessable(t, err, "nul_byte_pax")
		assertDirEmpty(t, dest)

		_, _, normErr := normalizeEgressTarPath("a\x00b.txt", tar.TypeReg, DefaultMaxPathBytes, DefaultMaxPathDepth)
		assertUnprocessable(t, normErr, "normalize_nul_byte")
	})

	// Path depth limit.
	deepPath := strings.Repeat("d/", 65) + "leaf.txt"
	deepGz := buildTestTarGz(t, []rawTarSpec{{name: deepPath, typeflag: tar.TypeReg, mode: 0o644, body: []byte("x")}})
	_, err := ValidateEgress(ctx, bytes.NewReader(deepGz), EgressOptions{})
	assertUnprocessable(t, err, "path_depth_exceeded")
}

func TestEgress_ADV03_ForbiddenTypesAndSubmodules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name  string
		specs []rawTarSpec
	}{
		{
			name:  "symlink_abs",
			specs: []rawTarSpec{{name: "sym", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/etc/passwd"}},
		},
		{
			name:  "symlink_rel",
			specs: []rawTarSpec{{name: "sym", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../secret"}},
		},
		{
			name: "hardlink",
			specs: []rawTarSpec{
				{name: "target.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("hi")},
				{name: "hard.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "target.txt"},
			},
		},
		{
			name:  "fifo",
			specs: []rawTarSpec{{name: "pipe", typeflag: tar.TypeFifo, mode: 0o600}},
		},
		{
			name:  "char_device",
			specs: []rawTarSpec{{name: "null", typeflag: tar.TypeChar, mode: 0o600, devmajor: 1, devminor: 3}},
		},
		{
			name:  "block_device",
			specs: []rawTarSpec{{name: "sda", typeflag: tar.TypeBlock, mode: 0o600, devmajor: 8, devminor: 0}},
		},
		{
			name:  "unsupported_typeflag",
			specs: []rawTarSpec{{name: "weird", typeflag: '?', mode: 0o644, rawHeader: true}},
		},
		{
			name:  "forged_symlink_mode_on_reg",
			specs: []rawTarSpec{{name: "fake", typeflag: tar.TypeReg, mode: 0o120777, body: []byte("/etc/passwd"), rawHeader: true}},
		},
		{
			name:  "gitlink_0160000",
			specs: []rawTarSpec{{name: "vendor/sub", typeflag: tar.TypeDir, mode: 0o160000}},
		},
		{
			name:  "gitmodules_root",
			specs: []rawTarSpec{{name: ".gitmodules", typeflag: tar.TypeReg, mode: 0o644, body: []byte("[submodule \"x\"]\n")}},
		},
		{
			name:  "gitmodules_nested_case",
			specs: []rawTarSpec{{name: "sub/.GitModules", typeflag: tar.TypeReg, mode: 0o644, body: []byte("[submodule \"x\"]\n")}},
		},
		{
			name:  "symlink_inside_dotgit",
			specs: []rawTarSpec{{name: ".git/hooks/pre-commit", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/bin/sh"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gz := buildTestTarGz(t, tc.specs)
			dest := t.TempDir()
			_, err := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
			assertUnprocessable(t, err, tc.name)
			assertDirEmpty(t, dest)
		})
	}
}

func TestEgress_ADV04_Collisions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name  string
		specs []rawTarSpec
	}{
		{
			name: "duplicate_file",
			specs: []rawTarSpec{
				{name: "dup.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("1")},
				{name: "dup.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("2")},
			},
		},
		{
			name: "duplicate_dir",
			specs: []rawTarSpec{
				{name: "pkg/", typeflag: tar.TypeDir, mode: 0o755},
				{name: "pkg/", typeflag: tar.TypeDir, mode: 0o755},
			},
		},
		{
			name: "case_collision_file",
			specs: []rawTarSpec{
				{name: "Config.yaml", typeflag: tar.TypeReg, mode: 0o644, body: []byte("a")},
				{name: "config.yaml", typeflag: tar.TypeReg, mode: 0o644, body: []byte("b")},
			},
		},
		{
			name: "case_collision_dir",
			specs: []rawTarSpec{
				{name: "Pkg/a.go", typeflag: tar.TypeReg, mode: 0o644, body: []byte("a")},
				{name: "pkg/b.go", typeflag: tar.TypeReg, mode: 0o644, body: []byte("b")},
			},
		},
		{
			name: "unicode_nfc_nfd_file",
			specs: []rawTarSpec{
				{name: "caf\u00e9.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("nfc")},
				{name: "cafe\u0301.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("nfd")},
			},
		},
		{
			name: "unicode_case_plus_nfc_nfd",
			specs: []rawTarSpec{
				{name: "CAF\u00c9.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
				{name: "cafe\u0301.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("nfd")},
			},
		},
		{
			name: "unicode_nfc_nfd_dir",
			specs: []rawTarSpec{
				{name: "docs\u0301/a.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("1")},
				{name: "doc\u015b/b.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("2")},
			},
		},
		{
			name: "file_then_dir_child",
			specs: []rawTarSpec{
				{name: "foo", typeflag: tar.TypeReg, mode: 0o644, body: []byte("file")},
				{name: "foo/bar.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("child")},
			},
		},
		{
			name: "dir_child_then_file",
			specs: []rawTarSpec{
				{name: "foo/bar.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("child")},
				{name: "foo", typeflag: tar.TypeReg, mode: 0o644, body: []byte("file")},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gz := buildTestTarGz(t, tc.specs)
			dest := t.TempDir()
			_, err := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
			assertUnprocessable(t, err, tc.name)
			assertDirEmpty(t, dest)
		})
	}
}

func TestEgress_ADV05_TopLevelDotGitIgnoredAndSymlinkEscapeBlocked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	gz := buildTestTarGz(t, []rawTarSpec{
		{name: ".git/", typeflag: tar.TypeDir, mode: 0o755},
		{name: ".git/hooks/pre-commit", typeflag: tar.TypeReg, mode: 0o755, body: []byte("#!/bin/sh\nexit 1\n")},
		{name: ".GIT/config", typeflag: tar.TypeReg, mode: 0o644, body: []byte("[core]\n\tfsmonitor = evil\n")},
		{name: "./.git/HEAD", typeflag: tar.TypeReg, mode: 0o644, body: []byte("ref: refs/heads/evil\n")},
		{name: "app/main.go", typeflag: tar.TypeReg, mode: 0o644, body: []byte("package main\n")},
	})

	dest := t.TempDir()
	res, err := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
	if err != nil {
		t.Fatalf("ExtractEgress failed: %v", err)
	}
	if res.IgnoredGitEntries != 4 {
		t.Fatalf("expected 4 ignored .git entries, got %d", res.IgnoredGitEntries)
	}
	if res.FileCount != 1 || res.Files[0].Path != "app/main.go" {
		t.Fatalf("unexpected extracted files: %+v", res.Files)
	}
	if _, err := os.Lstat(filepath.Join(dest, ".git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected .git not to be extracted, stat err=%v", err)
	}

	// Pre-planted symlink escape in destination directory must be rejected by os.Root guard.
	outside := t.TempDir()
	symDest := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(symDest, "app")); err != nil {
		t.Fatalf("symlink setup: %v", err)
	}
	cleanGz := buildTestTarGz(t, []rawTarSpec{
		{name: "app/escape.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("pwn")},
	})
	_, err = ExtractEgress(ctx, bytes.NewReader(cleanGz), symDest, EgressOptions{})
	assertUnprocessable(t, err, "preplanted_symlink_escape")
	if _, statErr := os.Stat(filepath.Join(outside, "escape.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("file escaped through symlink into outside dir!")
	}
}

func TestEgress_ValidateTarEntrySizeOverflowSafe(t *testing.T) {
	t.Parallel()
	cfg := EgressOptions{
		MaxSingleFileBytes:   math.MaxInt64,
		MaxUncompressedBytes: math.MaxInt64,
	}
	err := validateTarEntrySize(100, cfg, math.MaxInt64-10)
	assertUnprocessable(t, err, "int64_addition_overflow_guard")
}

func assertCollisionUnprocessable(t *testing.T, err error, label string) {
	t.Helper()
	assertUnprocessable(t, err, label)
	var domErr *domain.DomainError
	if !errors.As(err, &domErr) {
		t.Fatalf("%s: expected *domain.DomainError, got %T (%v)", label, err, err)
	}
	if domErr.Code() != "ARCHIVE_PATH_COLLISION" {
		t.Fatalf("%s: expected error code ARCHIVE_PATH_COLLISION, got %q (%v)", label, domErr.Code(), err)
	}
}

func TestEgress_ADV04_UnicodeCanonicalCaselessCollisions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name  string
		specs []rawTarSpec
	}{
		{
			name: "greek_u0390_vs_u03aa_u0301_file",
			specs: []rawTarSpec{
				{name: "\u0390.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("lower")},
				{name: "\u03aa\u0301.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "greek_u03b0_vs_u03ab_u0301_file",
			specs: []rawTarSpec{
				{name: "\u03b0.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("lower")},
				{name: "\u03ab\u0301.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "greek_u1fd3_vs_u0399_u0308_u0301_file",
			specs: []rawTarSpec{
				{name: "\u1fd3.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("oxia")},
				{name: "\u0399\u0308\u0301.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("decomposed")},
			},
		},
		{
			name: "greek_u1fd2_vs_u03aa_u0300_file",
			specs: []rawTarSpec{
				{name: "\u1fd2.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("varia")},
				{name: "\u03aa\u0300.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "greek_u1fd7_vs_u03aa_u0342_file",
			specs: []rawTarSpec{
				{name: "\u1fd7.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("perispomeni")},
				{name: "\u03aa\u0342.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "greek_u1fe2_vs_u03ab_u0300_file",
			specs: []rawTarSpec{
				{name: "\u1fe2.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("varia")},
				{name: "\u03ab\u0300.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "greek_u1fe3_vs_u03ab_u0301_file",
			specs: []rawTarSpec{
				{name: "\u1fe3.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("oxia")},
				{name: "\u03ab\u0301.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "greek_u1fe7_vs_u03ab_u0342_file",
			specs: []rawTarSpec{
				{name: "\u1fe7.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("perispomeni")},
				{name: "\u03ab\u0342.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
			},
		},
		{
			name: "latin_multi_combining_case_file",
			specs: []rawTarSpec{
				{name: "VI\u1ec6T.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
				{name: "vie\u0302\u0323t.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("nfd")},
			},
		},
		{
			name: "reordered_combining_marks_case_file",
			specs: []rawTarSpec{
				{name: "Q\u0323\u0302.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("order1")},
				{name: "q\u0302\u0323.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("order2")},
			},
		},
		{
			name: "cherokee_case_pair_file",
			specs: []rawTarSpec{
				{name: "\u13a0.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("upper")},
				{name: "\uab70.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("lower")},
			},
		},
		{
			name: "greek_u0390_vs_u03aa_u0301_dir",
			specs: []rawTarSpec{
				{name: "\u0390/a.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("a")},
				{name: "\u03aa\u0301/b.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("b")},
			},
		},
		{
			name: "greek_u03b0_vs_u03ab_u0301_explicit_dir",
			specs: []rawTarSpec{
				{name: "\u03b0/", typeflag: tar.TypeDir, mode: 0o755},
				{name: "\u03ab\u0301/b.txt", typeflag: tar.TypeReg, mode: 0o644, body: []byte("b")},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gz := buildTestTarGz(t, tc.specs)

			_, valErr := ValidateEgress(ctx, bytes.NewReader(gz), EgressOptions{})
			assertCollisionUnprocessable(t, valErr, tc.name+"/ValidateEgress")

			dest := t.TempDir()
			_, extErr := ExtractEgress(ctx, bytes.NewReader(gz), dest, EgressOptions{})
			assertCollisionUnprocessable(t, extErr, tc.name+"/ExtractEgress")
			assertDirEmpty(t, dest)
		})
	}
}

func TestEgress_FoldSegmentCanonicalCaselessInvariance(t *testing.T) {
	t.Parallel()
	ct := newCollisionTracker()
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		s := string(r)
		nfd := norm.NFD.String(s)
		nfc := norm.NFC.String(s)
		gotS := ct.foldSegment(s)
		gotNFD := ct.foldSegment(nfd)
		gotNFC := ct.foldSegment(nfc)
		if gotS != gotNFD || gotS != gotNFC {
			t.Fatalf("rune U+%04X (%q): foldSegment not canonically invariant: s=%x nfd=%x nfc=%x", r, s, gotS, gotNFD, gotNFC)
		}
		// Canonical caseless equivalence per Unicode §3.13: foldSegment is idempotent
		// and collapses every unicode.SimpleFold equivalence class.
		if twice := ct.foldSegment(gotS); twice != gotS {
			t.Fatalf("rune U+%04X (%q): foldSegment not idempotent: once=%x twice=%x", r, s, gotS, twice)
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if gotF := ct.foldSegment(string(f)); gotF != gotS {
				t.Fatalf("rune U+%04X vs SimpleFold U+%04X: foldSegment mismatch: %x vs %x", r, f, gotS, gotF)
			}
		}
	}
}
