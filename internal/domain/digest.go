package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
)

// SHA256Hex computes the lowercase 64-character SHA-256 hex digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256Reader streams r to compute its lowercase SHA-256 hex digest and exact byte count.
func SHA256Reader(r io.Reader) (hexDigest string, bytesRead int64, err error) {
	if r == nil {
		return "", 0, BadRequest("INVALID_READER", "reader must not be nil")
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// CanonicalJSONBytes produces deterministic canonical JSON bytes by normalizing through
// encoding/json with UseNumber() (preserving int64 precision), lexicographically sorted
// map keys, and SetEscapeHTML(false).
func CanonicalJSONBytes(v any) ([]byte, error) {
	var raw []byte
	switch val := v.(type) {
	case json.RawMessage:
		raw = []byte(val)
	case []byte:
		raw = val
	default:
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return nil, WrapError(ErrBadRequest, "CANONICAL_JSON_ERROR", "failed to encode JSON value", err)
		}
		raw = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, BadRequest("CANONICAL_JSON_ERROR", "JSON input must not be empty")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var normalized any
	if err := dec.Decode(&normalized); err != nil {
		return nil, WrapError(ErrBadRequest, "CANONICAL_JSON_ERROR", "failed to decode JSON value", err)
	}
	// Ensure no trailing garbage after the single JSON value.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, BadRequest("CANONICAL_JSON_ERROR", "JSON input contains trailing data")
	}

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, WrapError(ErrBadRequest, "CANONICAL_JSON_ERROR", "failed to re-encode canonical JSON", err)
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// CanonicalJSONDigest returns the SHA-256 hex digest of CanonicalJSONBytes(v).
func CanonicalJSONDigest(v any) (string, error) {
	canonical, err := CanonicalJSONBytes(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(canonical), nil
}

// ParseSHA256Digest validates and normalizes a "<64hex>" or "sha256:<64hex>" digest to
// lowercase 64-char hex.
func ParseSHA256Digest(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(trimmed), "sha256:") {
		trimmed = trimmed[len("sha256:"):]
	}
	lower := strings.ToLower(trimmed)
	if !IsValidSHA256Hex(lower) {
		return "", BadRequest("INVALID_DIGEST", "invalid SHA-256 digest format")
	}
	return lower, nil
}

// FormatPrefixedSHA256 returns "sha256:" followed by the lowercase hex digest.
func FormatPrefixedSHA256(hexDigest string) string {
	trimmed := strings.TrimSpace(hexDigest)
	if strings.HasPrefix(strings.ToLower(trimmed), "sha256:") {
		trimmed = trimmed[len("sha256:"):]
	}
	return "sha256:" + strings.ToLower(trimmed)
}

// IsValidSHA256Hex reports whether s is an exact 64-character lowercase hex SHA-256 digest.
func IsValidSHA256Hex(s string) bool {
	return isLowerHexLen(s, 64)
}

// IsValidGitSHA reports whether s is an exact 40-character lowercase hex Git SHA.
func IsValidGitSHA(s string) bool {
	return isLowerHexLen(s, 40)
}

// ParseGitSHA normalizes and validates a 40-character hex Git commit SHA.
func ParseGitSHA(raw string) (string, error) {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if !IsValidGitSHA(lower) {
		return "", BadRequest("INVALID_GIT_SHA", "invalid 40-character Git SHA")
	}
	return lower, nil
}

func isLowerHexLen(s string, expectedLen int) bool {
	if len(s) != expectedLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
