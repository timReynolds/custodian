package gitgateway

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/checkout"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
)

const (
	lfsPointerVersionLine  = "version https://git-lfs.github.com/spec/v1"
	maxLFSPointerBlobBytes = 4096
	maxLFSExtValueBytes    = 256
)

var lfsExtKeyPattern = regexp.MustCompile(`^ext-[0-9]+-[a-z0-9.-]+$`)

func extractLFSPointers(ctx context.Context, gitBinary string, res *quarantine.UnpackResult) ([]domain.PushLFSObject, error) {
	if res == nil || len(res.Blobs) == 0 {
		return nil, nil
	}

	var candidateOIDs []string
	for _, b := range res.Blobs {
		if b.SizeBytes > 0 && b.SizeBytes <= maxLFSPointerBlobBytes {
			candidateOIDs = append(candidateOIDs, b.OID)
		}
	}
	if len(candidateOIDs) == 0 {
		return nil, nil
	}

	var blobContents map[string][]byte
	var err error
	if strings.TrimSpace(res.RepoDir) != "" {
		blobContents, err = readSmallBlobsFromGitRepo(ctx, gitBinary, res.RepoDir, candidateOIDs)
		if err != nil {
			return nil, err
		}
	} else if strings.TrimSpace(res.WorkspaceDir) != "" {
		blobContents = readSmallBlobsFromWorkspace(res.WorkspaceDir, res.Blobs)
	}

	seenSizes := make(map[string]int64)
	for _, oid := range candidateOIDs {
		raw, ok := blobContents[oid]
		if !ok {
			continue
		}
		ptr, isPtr, parseErr := parseLFSPointer(raw)
		if parseErr != nil {
			return nil, parseErr
		}
		if !isPtr {
			continue
		}
		if prevSize, exists := seenSizes[ptr.OID]; exists {
			if prevSize != ptr.Size {
				return nil, domain.Unprocessable("INVALID_LFS_POINTER", fmt.Sprintf("conflicting sizes for LFS object %s", ptr.OID))
			}
			continue
		}
		seenSizes[ptr.OID] = ptr.Size
	}

	if len(seenSizes) == 0 {
		return nil, nil
	}

	out := make([]domain.PushLFSObject, 0, len(seenSizes))
	for oid, size := range seenSizes {
		out = append(out, domain.PushLFSObject{
			OID:  oid,
			Size: size,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OID != out[j].OID {
			return out[i].OID < out[j].OID
		}
		return out[i].Size < out[j].Size
	})
	return out, nil
}

func parseLFSPointer(raw []byte) (domain.PushLFSObject, bool, error) {
	ptr, isPtr, _, err := parseLFSPointerDetailed(raw)
	return ptr, isPtr, err
}

func parseLFSPointerDetailed(raw []byte) (domain.PushLFSObject, bool, bool, error) {
	if len(raw) == 0 || len(raw) > maxLFSPointerBlobBytes || bytes.IndexByte(raw, 0) >= 0 {
		return domain.PushLFSObject{}, false, false, nil
	}
	text := string(raw)
	if !strings.HasPrefix(text, lfsPointerVersionLine) {
		return domain.PushLFSObject{}, false, false, nil
	}
	if len(text) > len(lfsPointerVersionLine) {
		next := text[len(lfsPointerVersionLine)]
		if next != '\n' && next != '\r' {
			return domain.PushLFSObject{}, false, false, nil
		}
	}

	if !utf8.ValidString(text) {
		return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer must be valid UTF-8")
	}
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b == '\r' {
			if i+1 >= len(text) || text[i+1] != '\n' {
				return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer contains disallowed carriage return")
			}
			continue
		}
		if b == '\n' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer contains disallowed control characters")
		}
	}

	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var (
		oid      string
		size     int64 = -1
		hasExt   bool
		seenKeys = make(map[string]struct{}, 4)
	)
	for i, line := range lines {
		if line == "" {
			continue
		}
		if i == 0 {
			if line != lfsPointerVersionLine {
				return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "invalid LFS pointer version header")
			}
			seenKeys["version"] = struct{}{}
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok || key == "" || val == "" {
			return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "malformed LFS pointer key-value line")
		}
		if _, dup := seenKeys[key]; dup {
			return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", fmt.Sprintf("duplicate LFS pointer key %q", key))
		}
		seenKeys[key] = struct{}{}
		switch key {
		case "version":
			return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "duplicate LFS pointer version")
		case "oid":
			digest, hasPrefix := strings.CutPrefix(val, "sha256:")
			if !hasPrefix {
				return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer oid must use sha256:")
			}
			if err := ValidateLFSOID(digest); err != nil {
				return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer oid must be 64 lowercase hex characters")
			}
			oid = digest
		case "size":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil || n < 0 {
				return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer size must be a non-negative integer")
			}
			size = n
		default:
			if !isValidLFSExtensionKeyValue(key, val) {
				return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", fmt.Sprintf("invalid LFS pointer extension key/value for %q", key))
			}
			hasExt = true
		}
	}

	if oid == "" || size < 0 {
		return domain.PushLFSObject{}, false, false, domain.Unprocessable("INVALID_LFS_POINTER", "LFS pointer missing required oid or size")
	}
	return domain.PushLFSObject{
		OID:  oid,
		Size: size,
	}, true, hasExt, nil
}

func isValidLFSExtensionKeyValue(key, val string) bool {
	if len(key) == 0 || len(key) > 128 || !lfsExtKeyPattern.MatchString(key) {
		return false
	}
	if len(val) == 0 || len(val) > maxLFSExtValueBytes {
		return false
	}
	for i := 0; i < len(val); i++ {
		b := val[i]
		if b <= 0x20 || b >= 0x7f {
			return false
		}
	}
	return true
}

func readSmallBlobsFromGitRepo(ctx context.Context, gitBinary, repoDir string, oids []string) (map[string][]byte, error) {
	if strings.TrimSpace(gitBinary) == "" {
		gitBinary = "git"
	}
	var stdin bytes.Buffer
	for _, oid := range oids {
		stdin.WriteString(oid)
		stdin.WriteByte('\n')
	}

	args := append([]string(nil), checkout.HardenedGitFlags(false)...)
	args = append(args, "-C", repoDir, "cat-file", "--batch")
	cmd := exec.CommandContext(ctx, gitBinary, args...)
	cmd.Stdin = &stdin

	envHome := filepath.Dir(repoDir)
	cmd.Env = checkout.CleanGitEnv(envHome, false, false, "", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "LFS_BLOB_READ_FAILED", "failed piping git cat-file", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "LFS_BLOB_READ_FAILED", "failed starting git cat-file", err)
	}

	out := make(map[string][]byte, len(oids))
	br := bufio.NewReaderSize(stdout, 32*1024)
	for _, expectedOID := range oids {
		hdr, readErr := br.ReadString('\n')
		if readErr != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, domain.WrapError(domain.ErrInternal, "LFS_BLOB_READ_FAILED", "failed reading git cat-file header", readErr)
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		parts := strings.Split(hdr, " ")
		if len(parts) < 3 || parts[1] != "blob" {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, domain.Unprocessable("LFS_BLOB_READ_FAILED", fmt.Sprintf("unexpected git cat-file header for %s", expectedOID))
		}
		sz, parseErr := strconv.ParseInt(parts[2], 10, 64)
		if parseErr != nil || sz < 0 || sz > maxLFSPointerBlobBytes {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, domain.Unprocessable("LFS_BLOB_READ_FAILED", "invalid blob size from git cat-file")
		}
		buf := make([]byte, sz)
		if _, err := io.ReadFull(br, buf); err != nil {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, domain.WrapError(domain.ErrInternal, "LFS_BLOB_READ_FAILED", "failed reading blob bytes", err)
		}
		nl, err := br.ReadByte()
		if err != nil || nl != '\n' {
			_ = stdout.Close()
			_ = cmd.Wait()
			return nil, domain.WrapError(domain.ErrInternal, "LFS_BLOB_READ_FAILED", "malformed git cat-file record terminator", err)
		}
		out[parts[0]] = buf
	}
	_ = stdout.Close()
	if err := cmd.Wait(); err != nil {
		return nil, domain.WrapError(domain.ErrInternal, "LFS_BLOB_READ_FAILED", "git cat-file failed", err)
	}
	return out, nil
}

func readSmallBlobsFromWorkspace(workspaceDir string, blobs []quarantine.ExtractedBlob) map[string][]byte {
	out := make(map[string][]byte)
	for _, b := range blobs {
		if b.SizeBytes <= 0 || b.SizeBytes > maxLFSPointerBlobBytes {
			continue
		}
		for _, p := range b.Paths {
			matches, _ := filepath.Glob(filepath.Join(workspaceDir, "tip", "*", filepath.FromSlash(p)))
			for _, m := range matches {
				if data, err := os.ReadFile(m); err == nil {
					out[b.OID] = data
					break
				}
			}
			if _, ok := out[b.OID]; ok {
				break
			}
		}
	}
	return out
}

func finalizeAndUploadPushBundle(
	ctx context.Context,
	res *quarantine.UnpackResult,
	lfsObjects []domain.PushLFSObject,
	snapStore domain.SnapshotStore,
) (domain.Artifact, error) {
	if res == nil {
		return domain.Artifact{}, domain.Internal("INVALID_UNPACK_RESULT", "unpack result is required")
	}
	if snapStore == nil {
		return domain.Artifact{}, domain.Unavailable("SNAPSHOT_STORE_UNAVAILABLE", "snapshot store is not configured")
	}

	if len(lfsObjects) > 0 {
		manifest := res.Manifest
		lfsList := make([]quarantine.PushManifestLFSObject, 0, len(lfsObjects))
		for _, obj := range lfsObjects {
			lfsList = append(lfsList, quarantine.PushManifestLFSObject{
				OID:  obj.OID,
				Size: obj.Size,
			})
		}
		manifest.LFSObjects = lfsList
		normManifest, manifestJSON, manifestDigest, err := quarantine.ComputePushManifestDigest(manifest)
		if err != nil {
			return domain.Artifact{}, err
		}
		res.Manifest = normManifest
		res.PushManifestDigest = manifestDigest
		res.LFSObjects = append([]domain.PushLFSObject(nil), lfsObjects...)

		if err := rebuildDeterministicBundleFile(ctx, res, manifestJSON, manifestDigest); err != nil {
			return domain.Artifact{}, err
		}
	}

	bundleID, err := domain.NewID()
	if err != nil {
		return domain.Artifact{}, err
	}
	objectKey := fmt.Sprintf("git-push-bundles/%s/%s/git_push_bundle.tar.gz", res.PushManifestDigest, bundleID.String())

	f, err := os.Open(res.BundlePath)
	if err != nil {
		return domain.Artifact{}, domain.WrapError(domain.ErrInternal, "BUNDLE_STORE_FAILED", "failed opening git push bundle", err)
	}
	defer f.Close()

	art, err := snapStore.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindGitPushBundle,
		ObjectKey:      objectKey,
		ExpectedSHA256: res.BundleSHA256,
		MaxBytes:       res.BundleSizeBytes,
		ContentType:    "application/gzip",
	}, f, res.BundleSizeBytes)
	if err != nil {
		return domain.Artifact{}, err
	}
	if art.ID == uuid.Nil {
		art.ID = bundleID
	}
	res.BundleArtifact = &art
	return art, nil
}

func rebuildDeterministicBundleFile(ctx context.Context, res *quarantine.UnpackResult, manifestJSON []byte, digest string) error {
	quarDir := filepath.Dir(res.BundlePath)
	if quarDir == "" || quarDir == "." {
		var err error
		quarDir, err = os.MkdirTemp("", "custodian-bundle-*")
		if err != nil {
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed creating bundle directory", err)
		}
	}

	var cleanPackPath string
	var cleanPackSize int64
	hasIntroducedObjects := len(res.Commits)+len(res.Trees)+len(res.Blobs)+len(res.Tags) > 0
	if res.NeedsPack() && hasIntroducedObjects {
		pf, err := os.CreateTemp(quarDir, "push-lfs-*.pack")
		if err != nil {
			return domain.WrapError(domain.ErrInternal, "BUNDLE_PACK_FAILED", "failed creating temp clean pack file", err)
		}
		cleanPackPath = pf.Name()
		stats, packErr := quarantine.BuildCleanPack(ctx, res, pf)
		closeErr := pf.Close()
		if packErr != nil {
			_ = os.Remove(cleanPackPath)
			return packErr
		}
		if closeErr != nil {
			_ = os.Remove(cleanPackPath)
			return domain.WrapError(domain.ErrInternal, "BUNDLE_PACK_FAILED", "failed closing clean pack file", closeErr)
		}
		cleanPackSize = stats.BytesWritten
		defer func() { _ = os.Remove(cleanPackPath) }()
	}

	tmpBundle, err := os.CreateTemp(quarDir, "git_push_bundle-*.tar.gz")
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed creating temp git push bundle", err)
	}
	tmpBundlePath := tmpBundle.Name()

	hasher := sha256.New()
	var written int64
	cw := &pipelineCountingWriter{n: &written}
	mw := io.MultiWriter(tmpBundle, hasher, cw)

	gw, err := gzip.NewWriterLevel(mw, gzip.BestCompression)
	if err != nil {
		_ = tmpBundle.Close()
		_ = os.Remove(tmpBundlePath)
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed initializing gzip writer", err)
	}
	gw.Header = gzip.Header{
		ModTime: archive.EpochTime,
		OS:      255,
	}
	tw := tar.NewWriter(gw)

	if cleanPackPath != "" && cleanPackSize > 0 {
		pf, err := os.Open(cleanPackPath)
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = tmpBundle.Close()
			_ = os.Remove(tmpBundlePath)
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed opening clean pack for bundle", err)
		}
		hdr := &tar.Header{
			Name:     "push.pack",
			Mode:     0o644,
			Size:     cleanPackSize,
			ModTime:  archive.EpochTime,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = pf.Close()
			_ = tw.Close()
			_ = gw.Close()
			_ = tmpBundle.Close()
			_ = os.Remove(tmpBundlePath)
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed writing push.pack tar header", err)
		}
		if _, err := io.CopyN(tw, pf, cleanPackSize); err != nil {
			_ = pf.Close()
			_ = tw.Close()
			_ = gw.Close()
			_ = tmpBundle.Close()
			_ = os.Remove(tmpBundlePath)
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed writing push.pack tar payload", err)
		}
		_ = pf.Close()
	}

	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "push_manifest.json", data: manifestJSON},
		{name: "push_manifest.sha256", data: []byte(digest + "\n")},
	} {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Size:     int64(len(entry.data)),
			ModTime:  archive.EpochTime,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = tmpBundle.Close()
			_ = os.Remove(tmpBundlePath)
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed writing manifest tar header", err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = tmpBundle.Close()
			_ = os.Remove(tmpBundlePath)
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed writing manifest tar payload", err)
		}
	}

	if err := tw.Close(); err != nil {
		_ = gw.Close()
		_ = tmpBundle.Close()
		_ = os.Remove(tmpBundlePath)
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed finalizing tar bundle", err)
	}
	if err := gw.Close(); err != nil {
		_ = tmpBundle.Close()
		_ = os.Remove(tmpBundlePath)
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed finalizing gzip bundle", err)
	}
	if err := tmpBundle.Sync(); err != nil {
		_ = tmpBundle.Close()
		_ = os.Remove(tmpBundlePath)
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed syncing bundle", err)
	}
	if err := tmpBundle.Close(); err != nil {
		_ = os.Remove(tmpBundlePath)
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed closing bundle", err)
	}

	finalPath := filepath.Join(quarDir, "git_push_bundle.tar.gz")
	if err := os.Rename(tmpBundlePath, finalPath); err != nil {
		_ = os.Remove(tmpBundlePath)
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed replacing git push bundle", err)
	}

	res.BundlePath = finalPath
	res.BundleSHA256 = hex.EncodeToString(hasher.Sum(nil))
	res.BundleSizeBytes = written
	return nil
}

var errLFSVerifySizeExceeded = errors.New("upstream LFS object exceeds expected pointer size")

type boundedLFSVerifyWriter struct {
	w        io.Writer
	n        *int64
	maxBytes int64
}

func (b *boundedLFSVerifyWriter) Write(p []byte) (int, error) {
	if *b.n+int64(len(p)) > b.maxBytes {
		rem := b.maxBytes - *b.n
		if rem > 0 {
			written, err := b.w.Write(p[:rem])
			*b.n += int64(written)
			if err != nil {
				return written, err
			}
			return written, errLFSVerifySizeExceeded
		}
		return 0, errLFSVerifySizeExceeded
	}
	written, err := b.w.Write(p)
	*b.n += int64(written)
	return written, err
}

type pipelineCountingWriter struct {
	n *int64
}

func (w *pipelineCountingWriter) Write(p []byte) (int, error) {
	*w.n += int64(len(p))
	return len(p), nil
}

func verifyLFSObjectsUpstream(
	ctx context.Context,
	upstream UpstreamClient,
	broker *TokenBroker,
	caller AuthenticatedPrincipal,
	target ResolvedTarget,
	lfsObjects []domain.PushLFSObject,
	allowMissingWhenApproved bool,
	extraSecrets *[]string,
) error {
	if len(lfsObjects) == 0 || target.Repository == nil || upstream == nil {
		return nil
	}

	var readToken string
	if broker != nil {
		authRes, err := broker.ResolveUpstreamAuth(ctx, TokenScopeRead, caller, target)
		if err != nil {
			return err
		}
		readToken = authRes.Token
		if extraSecrets != nil {
			*extraSecrets = collectExtraSecrets(append(*extraSecrets, authRes.ExtraSecrets...)...)
		}
	}

	batchObjs := make([]LFSBatchObjectInput, 0, len(lfsObjects))
	for _, obj := range lfsObjects {
		batchObjs = append(batchObjs, LFSBatchObjectInput{
			OID:  obj.OID,
			Size: obj.Size,
		})
	}
	status, upResp, _, err := upstream.LFSBatch(ctx, target.OwnerRepo, readToken, LFSBatchRequest{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects:   batchObjs,
	})
	if err != nil {
		return domain.WrapError(domain.ErrUnavailable, "LFS_VERIFICATION_FAILED", "upstream LFS download batch request failed", err)
	}
	if status != http.StatusOK {
		return domain.Unprocessable("LFS_VERIFICATION_FAILED", fmt.Sprintf("upstream LFS download batch returned status %d", status))
	}

	byOID := make(map[string]LFSBatchObjectResponse, len(upResp.Objects))
	for _, item := range upResp.Objects {
		byOID[strings.ToLower(strings.TrimSpace(item.OID))] = item
	}

	for _, expected := range lfsObjects {
		item, ok := byOID[expected.OID]
		if !ok {
			return domain.Unprocessable("LFS_OBJECT_MISSING", fmt.Sprintf("LFS object %s missing from upstream batch response", expected.OID))
		}
		if item.Error != nil {
			if allowMissingWhenApproved && item.Error.Code == http.StatusNotFound {
				continue
			}
			return domain.Unprocessable("LFS_OBJECT_MISSING", fmt.Sprintf("LFS object %s is not available upstream (code %d)", expected.OID, item.Error.Code))
		}

		hasher := sha256.New()
		var actualSize int64
		bw := &boundedLFSVerifyWriter{
			w:        hasher,
			n:        &actualSize,
			maxBytes: expected.Size,
		}
		getStatus, _, getErr := upstream.LFSGetObject(ctx, target.OwnerRepo, expected.OID, readToken, bw)
		if getErr != nil {
			if errors.Is(getErr, errLFSVerifySizeExceeded) {
				return domain.Unprocessable("LFS_SIZE_MISMATCH", fmt.Sprintf("LFS object %s size exceeds pointer size %d", expected.OID, expected.Size))
			}
			return domain.WrapError(domain.ErrUnavailable, "LFS_VERIFICATION_FAILED", fmt.Sprintf("failed downloading LFS object %s for verification", expected.OID), getErr)
		}
		if getStatus != http.StatusOK {
			if allowMissingWhenApproved && getStatus == http.StatusNotFound {
				continue
			}
			return domain.Unprocessable("LFS_OBJECT_MISSING", fmt.Sprintf("upstream LFS object %s returned status %d", expected.OID, getStatus))
		}
		if actualSize != expected.Size {
			return domain.Unprocessable("LFS_SIZE_MISMATCH", fmt.Sprintf("LFS object %s size mismatch: pointer=%d upstream=%d", expected.OID, expected.Size, actualSize))
		}
		actualOID := hex.EncodeToString(hasher.Sum(nil))
		if actualOID != expected.OID {
			return domain.Unprocessable("LFS_OID_MISMATCH", fmt.Sprintf("LFS object %s SHA-256 mismatch upstream", expected.OID))
		}
	}
	return nil
}

// prepareLFSInspectionDir creates a temporary copy of workspaceDir where strictly canonical
// Git LFS v1 pointer files (version, oid, size only — zero ext-* extension lines) are suffixed
// with ".lfspointer" so Stage A L4 magic-byte/extension mismatch checks (e.g. .png, .jpg, .pdf,
// .zip, .tar.gz, .wasm, .exe, .ttf, .bin, .dat) do not false-positive on legitimate LFS pointer
// stubs while preserving full scan coverage and leaving all non-pointer or ext-* files untouched.
func prepareLFSInspectionDir(workspaceDir string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "custodian-inspect-lfs-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	err = filepath.WalkDir(workspaceDir, func(srcPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(workspaceDir, srcPath)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dstPath := filepath.Join(tmpDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > 0 && info.Size() <= maxLFSPointerBlobBytes {
			if data, readErr := os.ReadFile(srcPath); readErr == nil {
				if _, isPtr, hasExt, parseErr := parseLFSPointerDetailed(data); parseErr == nil && isPtr && !hasExt {
					dstPath += ".lfspointer"
					return os.WriteFile(dstPath, data, 0o600)
				}
			}
		}
		if linkErr := os.Link(srcPath, dstPath); linkErr == nil {
			return nil
		}
		in, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	return tmpDir, cleanup, nil
}
