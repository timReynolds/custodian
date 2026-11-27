package quarantine

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
)

type testRefResolver struct {
	refs         map[string]string
	baselineOIDs []string
}

func (r *testRefResolver) ResolveRef(_ context.Context, refName string) (string, bool, error) {
	if r == nil || r.refs == nil {
		return "", false, nil
	}
	oid, ok := r.refs[refName]
	return oid, ok, nil
}

func (r *testRefResolver) ListBaselineOIDs(_ context.Context) ([]string, error) {
	if r == nil {
		return nil, nil
	}
	return append([]string(nil), r.baselineOIDs...), nil
}

func runTestGit(t *testing.T, dir string, env []string, stdin []byte, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if env != nil {
		cmd.Env = env
	} else {
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test User",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_AUTHOR_DATE=2025-01-01T00:00:00Z",
			"GIT_COMMITTER_NAME=Test User",
			"GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_COMMITTER_DATE=2025-01-01T00:00:00Z",
		)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v failed in %s: %v\nstderr: %s\nstdout: %s", args, dir, err, stderr.String(), stdout.String())
	}
	return stdout.String()
}

func initTestRepo(t *testing.T, bare bool) string {
	t.Helper()
	dir := t.TempDir()
	args := []string{"init", "--initial-branch=main"}
	if bare {
		args = append(args, "--bare")
	}
	args = append(args, dir)
	runTestGit(t, "", nil, nil, args...)
	if !bare {
		runTestGit(t, dir, nil, nil, "config", "user.name", "Test User")
		runTestGit(t, dir, nil, nil, "config", "user.email", "test@example.com")
	}
	return dir
}

func commitFile(t *testing.T, repoDir, relPath, content, msg string) string {
	t.Helper()
	full := filepath.Join(repoDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
	runTestGit(t, repoDir, nil, nil, "add", "--", relPath)
	runTestGit(t, repoDir, nil, nil, "commit", "-m", msg)
	return strings.TrimSpace(runTestGit(t, repoDir, nil, nil, "rev-parse", "HEAD"))
}

func buildPackFromRevs(t *testing.T, repoDir string, revs []string, thin bool) []byte {
	t.Helper()
	var stdin bytes.Buffer
	for _, r := range revs {
		stdin.WriteString(r)
		stdin.WriteByte('\n')
	}
	args := []string{"pack-objects", "--revs", "--stdout", "-q"}
	if thin {
		args = append(args, "--thin")
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	cmd.Stdin = &stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v failed: %v\nstderr: %s", args, err, stderr.String())
	}
	return stdout.Bytes()
}

type rawPackEntry struct {
	objType int
	// rawPayload is uncompressed object data (without git object header) for normal objects,
	// or full delta payload (LEB128 baseSize + targetSize + delta ops) for delta objects.
	rawPayload []byte
	// declaredSizeOverride overrides the pack entry header size if >= 0.
	declaredSizeOverride int64
	// baseOffset for OBJ_OFS_DELTA (negative distance from current entry offset)
	ofsDeltaNeg uint64
	// baseOID for OBJ_REF_DELTA
	refDeltaBase [20]byte
	// zlibStreamOverride replaces the compressed stream if non-nil
	zlibStreamOverride []byte
}

func encodePackEntryHeader(objType int, size uint64) []byte {
	var out []byte
	b := byte((objType & 0x07) << 4)
	b |= byte(size & 0x0f)
	size >>= 4
	if size > 0 {
		b |= 0x80
	}
	out = append(out, b)
	for size > 0 {
		nb := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			nb |= 0x80
		}
		out = append(out, nb)
	}
	return out
}

func encodeOfsDeltaOffset(neg uint64) []byte {
	var rev []byte
	rev = append(rev, byte(neg&0x7f))
	neg >>= 7
	for neg > 0 {
		neg--
		rev = append(rev, byte(0x80|(neg&0x7f)))
		neg >>= 7
	}
	out := make([]byte, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

func encodeLEB128(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

func compressZlib(data []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return buf.Bytes()
}

func buildRawPack(entries []rawPackEntry) []byte {
	var body bytes.Buffer
	body.WriteString("PACK")
	_ = binary.Write(&body, binary.BigEndian, uint32(2))
	_ = binary.Write(&body, binary.BigEndian, uint32(len(entries)))

	for _, e := range entries {
		sz := uint64(len(e.rawPayload))
		if e.declaredSizeOverride >= 0 {
			sz = uint64(e.declaredSizeOverride)
		}
		body.Write(encodePackEntryHeader(e.objType, sz))
		switch e.objType {
		case packObjOfsDelta:
			body.Write(encodeOfsDeltaOffset(e.ofsDeltaNeg))
		case packObjRefDelta:
			body.Write(e.refDeltaBase[:])
		}
		if e.zlibStreamOverride != nil {
			body.Write(e.zlibStreamOverride)
		} else {
			body.Write(compressZlib(e.rawPayload))
		}
	}

	sum := sha1.Sum(body.Bytes())
	body.Write(sum[:])
	return body.Bytes()
}

func hashGitObjectRaw(objType string, payload []byte) [20]byte {
	hdr := fmt.Sprintf("%s %d\x00", objType, len(payload))
	h := sha1.New()
	_, _ = h.Write([]byte(hdr))
	_, _ = h.Write(payload)
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeGitObjectToRepo(t *testing.T, repoDir, objType string, payload []byte) string {
	t.Helper()
	oid := strings.TrimSpace(runTestGit(t, repoDir, nil, payload, "hash-object", "-t", objType, "-w", "--stdin"))
	return oid
}

func buildRawTreePayload(entries []struct {
	mode string
	name string
	oid  [20]byte
}) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.mode)
		buf.WriteByte(' ')
		buf.WriteString(e.name)
		buf.WriteByte(0)
		buf.Write(e.oid[:])
	}
	return buf.Bytes()
}

func assertWorkspaceSafeForInspection(t *testing.T, workspaceDir string) *inspection.Inventory {
	t.Helper()
	err := filepath.WalkDir(workspaceDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Name() == ".git" && p != workspaceDir {
			t.Fatalf("workspace must not contain .git directory: %s", p)
		}
		if d.Type()&os.ModeSymlink != 0 {
			t.Fatalf("workspace must not contain symlinks: %s", p)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		if d.IsDir() {
			if perm != 0o755 {
				t.Fatalf("workspace dir %s perm = %o, want 0755", p, perm)
			}
		} else {
			if !info.Mode().IsRegular() {
				t.Fatalf("workspace entry %s is not regular file: %v", p, info.Mode())
			}
			if perm != 0o644 {
				t.Fatalf("workspace file %s perm = %o, want 0644", p, perm)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%s): %v", workspaceDir, err)
	}

	inv, err := inspection.WalkWorkspace(workspaceDir)
	if err != nil {
		t.Fatalf("inspection.WalkWorkspace(%s): %v", workspaceDir, err)
	}
	if inv.FilesSkipped != 0 {
		t.Fatalf("inspection.WalkWorkspace skipped %d files: %v", inv.FilesSkipped, inv.SkippedReasons)
	}
	return inv
}

func assertDomainErrCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", wantCode)
	}
	code := errorCodeOf(err)
	if code != wantCode {
		t.Fatalf("error code = %q (err=%v), want %q", code, err, wantCode)
	}
}

func mustHex20(t *testing.T, hexStr string) [20]byte {
	t.Helper()
	oid, err := domain.ParseGitSHA(hexStr)
	if err != nil {
		t.Fatalf("ParseGitSHA(%q): %v", hexStr, err)
	}
	var out [20]byte
	for i := 0; i < 20; i++ {
		var b byte
		_, _ = fmt.Sscanf(oid[i*2:i*2+2], "%02x", &b)
		out[i] = b
	}
	return out
}
