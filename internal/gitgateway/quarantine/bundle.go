package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/domain"
)

type countingWriter struct {
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func buildAndStoreBundle(
	ctx context.Context,
	res *UnpackResult,
	manifestJSON []byte,
	digest string,
	store domain.SnapshotStore,
) error {
	var cleanPackPath string
	var cleanPackSize int64

	hasIntroducedObjects := len(res.Commits)+len(res.Trees)+len(res.Blobs)+len(res.Tags) > 0
	if res.NeedsPack() && hasIntroducedObjects {
		cleanPackPath = filepath.Join(res.quarantineRoot, "push.pack")
		pf, err := os.OpenFile(cleanPackPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return domain.WrapError(domain.ErrInternal, "BUNDLE_PACK_FAILED", "failed creating clean pack file for bundle", err)
		}
		stats, packErr := BuildCleanPack(ctx, res, pf)
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
		defer func() {
			_ = os.Remove(cleanPackPath)
		}()
	}

	bundlePath := filepath.Join(res.quarantineRoot, "git_push_bundle.tar.gz")
	bf, err := os.OpenFile(bundlePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed creating git push bundle archive", err)
	}

	hasher := sha256.New()
	cw := &countingWriter{}
	mw := io.MultiWriter(bf, hasher, cw)

	gw, err := gzip.NewWriterLevel(mw, gzip.BestCompression)
	if err != nil {
		_ = bf.Close()
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed initializing gzip writer", err)
	}
	gw.Header = gzip.Header{
		ModTime: archive.EpochTime,
		OS:      255,
	}
	tw := tar.NewWriter(gw)

	// Write deterministic sorted tar entries: push.pack (optional), push_manifest.json, push_manifest.sha256.
	if cleanPackPath != "" && cleanPackSize > 0 {
		pf, err := os.Open(cleanPackPath)
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = bf.Close()
			return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed opening clean pack for bundle", err)
		}
		err = writeTarStreamEntry(tw, "push.pack", pf, cleanPackSize)
		_ = pf.Close()
		if err != nil {
			_ = tw.Close()
			_ = gw.Close()
			_ = bf.Close()
			return err
		}
	}

	if err := writeTarBytesEntry(tw, "push_manifest.json", manifestJSON); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = bf.Close()
		return err
	}
	if err := writeTarBytesEntry(tw, "push_manifest.sha256", []byte(digest+"\n")); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = bf.Close()
		return err
	}

	if err := tw.Close(); err != nil {
		_ = gw.Close()
		_ = bf.Close()
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed finalizing tar bundle", err)
	}
	if err := gw.Close(); err != nil {
		_ = bf.Close()
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed finalizing gzip bundle", err)
	}
	if err := bf.Sync(); err != nil {
		_ = bf.Close()
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed syncing bundle archive", err)
	}
	if err := bf.Close(); err != nil {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", "failed closing bundle archive", err)
	}

	bundleSHA := hex.EncodeToString(hasher.Sum(nil))
	res.BundlePath = bundlePath
	res.BundleSHA256 = bundleSHA
	res.BundleSizeBytes = cw.n

	if store != nil {
		bundleID := domain.MustNewID()
		objectKey := fmt.Sprintf("git-push-bundles/%s/%s/git_push_bundle.tar.gz", digest, bundleID.String())

		rf, err := os.Open(bundlePath)
		if err != nil {
			return domain.WrapError(domain.ErrInternal, "BUNDLE_STORE_FAILED", "failed opening bundle archive for store upload", err)
		}
		defer rf.Close()

		art, err := store.Put(ctx, domain.PutRequest{
			Kind:           domain.ArtifactKindGitPushBundle,
			ObjectKey:      objectKey,
			ExpectedSHA256: bundleSHA,
			MaxBytes:       cw.n,
			ContentType:    "application/gzip",
		}, rf, cw.n)
		if err != nil {
			return err
		}
		if art.ID == uuid.Nil {
			art.ID = bundleID
		}
		res.BundleArtifact = &art
	}
	return nil
}

func writeTarBytesEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Uid:      0,
		Gid:      0,
		Uname:    "",
		Gname:    "",
		Size:     int64(len(data)),
		ModTime:  archive.EpochTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", fmt.Sprintf("failed writing tar header for %s", name), err)
	}
	if _, err := tw.Write(data); err != nil {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", fmt.Sprintf("failed writing tar payload for %s", name), err)
	}
	return nil
}

func writeTarStreamEntry(tw *tar.Writer, name string, r io.Reader, size int64) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0o644,
		Uid:      0,
		Gid:      0,
		Uname:    "",
		Gname:    "",
		Size:     size,
		ModTime:  archive.EpochTime,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", fmt.Sprintf("failed writing tar header for %s", name), err)
	}
	n, err := io.CopyN(tw, r, size)
	if err != nil || n != size {
		return domain.WrapError(domain.ErrInternal, "BUNDLE_CREATE_FAILED", fmt.Sprintf("failed streaming tar payload for %s", name), err)
	}
	return nil
}
