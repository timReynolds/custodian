package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read boom")
}

func TestSHA256Hex(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, tc := range cases {
		if got := SHA256Hex([]byte(tc.in)); got != tc.want {
			t.Fatalf("SHA256Hex(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestSHA256Reader(t *testing.T) {
	data := []byte("custodian-immutable-artifact")
	digest, n, err := SHA256Reader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("SHA256Reader failed: %v", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("bytesRead = %d, want %d", n, len(data))
	}
	if digest != SHA256Hex(data) {
		t.Fatalf("digest mismatch: got %s want %s", digest, SHA256Hex(data))
	}

	if _, _, err := SHA256Reader(nil); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("SHA256Reader(nil) err = %v, want ErrBadRequest", err)
	}
	if _, _, err := SHA256Reader(errReader{}); err == nil {
		t.Fatal("expected reader error, got nil")
	}
}

func TestCanonicalJSONDigest(t *testing.T) {
	m1 := map[string]any{
		"b": 9007199254740993, // > 2^53 float64 precision boundary
		"a": map[string]any{"y": "<tag>&val", "x": []int{3, 1, 2}},
	}
	m2 := json.RawMessage("{\n  \"a\": { \"x\": [3, 1, 2], \"y\": \"<tag>&val\" },\n  \"b\": 9007199254740993\n}")

	b1, err := CanonicalJSONBytes(m1)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes(m1): %v", err)
	}
	b2, err := CanonicalJSONBytes(m2)
	if err != nil {
		t.Fatalf("CanonicalJSONBytes(m2): %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("canonical bytes mismatch:\n%s\nvs\n%s", b1, b2)
	}
	if !strings.Contains(string(b1), "9007199254740993") {
		t.Fatalf("int64 precision lost in canonical JSON: %s", b1)
	}
	if !strings.Contains(string(b1), "<tag>&val") {
		t.Fatalf("HTML chars escaped unexpectedly: %s", b1)
	}

	d1, err := CanonicalJSONDigest(m1)
	if err != nil {
		t.Fatalf("CanonicalJSONDigest(m1): %v", err)
	}
	d2, err := CanonicalJSONDigest(m2)
	if err != nil {
		t.Fatalf("CanonicalJSONDigest(m2): %v", err)
	}
	if d1 != d2 {
		t.Fatalf("digest mismatch: %s vs %s", d1, d2)
	}

	// Trailing JSON values must fail
	if _, err := CanonicalJSONBytes(json.RawMessage(`{"a":1}{"b":2}`)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for trailing JSON, got %v", err)
	}
	if _, err := CanonicalJSONBytes(json.RawMessage(`   `)); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for empty JSON, got %v", err)
	}
}

func TestParseSHA256AndGitSHA(t *testing.T) {
	upper64 := strings.Repeat("AB", 32)
	lower64 := strings.Repeat("ab", 32)

	got, err := ParseSHA256Digest("SHA256:" + upper64)
	if err != nil {
		t.Fatalf("ParseSHA256Digest failed: %v", err)
	}
	if got != lower64 {
		t.Fatalf("got %s, want %s", got, lower64)
	}
	if FormatPrefixedSHA256(upper64) != "sha256:"+lower64 {
		t.Fatalf("FormatPrefixedSHA256 unexpected: %s", FormatPrefixedSHA256(upper64))
	}
	if !IsValidSHA256Hex(lower64) || IsValidSHA256Hex(upper64) {
		t.Fatal("IsValidSHA256Hex case check failed")
	}

	if _, err := ParseSHA256Digest("sha256:xyz"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid sha256, got %v", err)
	}

	upper40 := strings.Repeat("CD", 20)
	lower40 := strings.Repeat("cd", 20)
	gitGot, err := ParseGitSHA(" " + upper40 + " ")
	if err != nil {
		t.Fatalf("ParseGitSHA failed: %v", err)
	}
	if gitGot != lower40 {
		t.Fatalf("got %s, want %s", gitGot, lower40)
	}
	if !IsValidGitSHA(lower40) || IsValidGitSHA(upper40) {
		t.Fatal("IsValidGitSHA case check failed")
	}
	if _, err := ParseGitSHA("short"); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid git sha, got %v", err)
	}
}
