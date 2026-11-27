package snapshots

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/timreynolds/custodian/internal/domain"
)

// ValidateObjectKey validates and normalizes a relative POSIX object key,
// rejecting empty keys, absolute paths, backslashes, NUL bytes, volume prefixes,
// and "." / ".." traversal segments.
func ValidateObjectKey(key string) (string, error) {
	if key == "" {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key must not be empty")
	}
	if strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsRune(key, '\x00') {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key contains illegal path characters")
	}
	if filepath.VolumeName(key) != "" {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key must not contain a volume name")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key contains empty or traversal segments")
		}
	}
	clean := path.Clean(key)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") {
		return "", domain.BadRequest("INVALID_OBJECT_KEY", "object key is unsafe")
	}
	return clean, nil
}

type verifyingReadCloser struct {
	inner        io.ReadCloser
	hasher       hashWriter
	bytesRead    int64
	expectedSHA  string
	expectedSize int64
	verified     bool
	verifyErr    error
}

type hashWriter interface {
	io.Writer
	Sum(b []byte) []byte
}

func newVerifyingReadCloser(inner io.ReadCloser, expectedSHA string, expectedSize int64) *verifyingReadCloser {
	return &verifyingReadCloser{
		inner:        inner,
		hasher:       sha256.New(),
		expectedSHA:  expectedSHA,
		expectedSize: expectedSize,
	}
}

func (v *verifyingReadCloser) Read(p []byte) (int, error) {
	if v.verified && v.verifyErr != nil {
		return 0, v.verifyErr
	}
	n, err := v.inner.Read(p)
	if n > 0 {
		_, _ = v.hasher.Write(p[:n])
		v.bytesRead += int64(n)
	}
	if err == io.EOF {
		if verr := v.verify(); verr != nil {
			return n, verr
		}
		return n, io.EOF
	}
	return n, err
}

func (v *verifyingReadCloser) verify() error {
	if v.verified {
		return v.verifyErr
	}
	v.verified = true
	if v.expectedSize >= 0 && v.bytesRead != v.expectedSize {
		v.verifyErr = domain.Unprocessable("SIZE_MISMATCH", fmt.Sprintf("artifact size mismatch: got %d bytes, expected %d", v.bytesRead, v.expectedSize))
		return v.verifyErr
	}
	if v.expectedSHA != "" {
		actual := hex.EncodeToString(v.hasher.Sum(nil))
		if actual != v.expectedSHA {
			v.verifyErr = domain.Unprocessable("DIGEST_MISMATCH", "artifact SHA-256 digest mismatch")
			return v.verifyErr
		}
	}
	return nil
}

func (v *verifyingReadCloser) Close() error {
	return v.inner.Close()
}
