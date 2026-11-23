package harness

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

var uuidV7MinTimestamp = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// AuditEvent models a single hash-chained record from GET /v1/audit/events or DB inspection.
type AuditEvent struct {
	ID           string          `json:"id"`
	EventType    string          `json:"event_type"`
	ActorID      string          `json:"actor_id"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Payload      json.RawMessage `json:"payload"`
	PreviousHash string          `json:"previous_hash"`
	EventHash    string          `json:"event_hash"`
	CreatedAt    time.Time       `json:"created_at"`
}

// NewTestUUIDv7 generates a valid RFC 9562 UUIDv7 string using crypto/rand and current Unix ms.
func NewTestUUIDv7() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failure generating UUIDv7: %v", err))
	}
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ParseUUIDv7 validates that id is a canonical lowercase RFC 9562 UUIDv7 string and returns its embedded timestamp.
func ParseUUIDv7(id string) (time.Time, error) {
	if len(id) != 36 {
		return time.Time{}, fmt.Errorf("uuid %q invalid length %d (want 36)", id, len(id))
	}
	if id != strings.ToLower(id) {
		return time.Time{}, fmt.Errorf("uuid %q must be lowercase canonical", id)
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return time.Time{}, fmt.Errorf("uuid %q invalid hyphen positions", id)
	}
	compact := id[0:8] + id[9:13] + id[14:18] + id[19:23] + id[24:36]
	raw, err := hex.DecodeString(compact)
	if err != nil || len(raw) != 16 {
		return time.Time{}, fmt.Errorf("uuid %q invalid hex: %w", id, err)
	}
	if ver := raw[6] >> 4; ver != 7 {
		return time.Time{}, fmt.Errorf("uuid %q version is %d (want 7)", id, ver)
	}
	if variant := raw[8] & 0xC0; variant != 0x80 {
		return time.Time{}, fmt.Errorf("uuid %q variant bits 0x%02x (want RFC 9562 0x80)", id, variant)
	}
	ms := uint64(raw[0])<<40 |
		uint64(raw[1])<<32 |
		uint64(raw[2])<<24 |
		uint64(raw[3])<<16 |
		uint64(raw[4])<<8 |
		uint64(raw[5])
	ts := time.UnixMilli(int64(ms)).UTC()
	if ts.Before(uuidV7MinTimestamp) || ts.After(time.Now().UTC().Add(5*time.Minute)) {
		return time.Time{}, fmt.Errorf("uuid %q timestamp %s out of plausible range", id, ts.Format(time.RFC3339))
	}
	return ts, nil
}

// ValidateUUIDv7 verifies id is a valid RFC 9562 UUIDv7.
func ValidateUUIDv7(id string) error {
	_, err := ParseUUIDv7(id)
	return err
}

// AssertUUIDv7 fails t if id is not a valid RFC 9562 UUIDv7.
func AssertUUIDv7(t testing.TB, id string) {
	t.Helper()
	if err := ValidateUUIDv7(id); err != nil {
		t.Fatalf("AssertUUIDv7 failed: %v", err)
	}
}

// AssertUUIDv7Monotonic verifies each ID is a valid UUIDv7 and embedded timestamps are non-decreasing.
func AssertUUIDv7Monotonic(t testing.TB, ids []string) {
	t.Helper()
	var prev time.Time
	for i, id := range ids {
		ts, err := ParseUUIDv7(id)
		if err != nil {
			t.Fatalf("ids[%d]: %v", i, err)
		}
		if i > 0 && ts.Before(prev) {
			t.Fatalf("UUIDv7 timestamp decreased at index %d: %s (%s) < %s (%s)",
				i, id, ts.Format(time.RFC3339Nano), ids[i-1], prev.Format(time.RFC3339Nano))
		}
		prev = ts
	}
}

// AssertUUIDv7LexMonotonic verifies each ID is valid UUIDv7 and strictly increases lexicographically.
func AssertUUIDv7LexMonotonic(t testing.TB, ids []string) {
	t.Helper()
	AssertUUIDv7Monotonic(t, ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("UUIDv7 not strictly lexicographically increasing at index %d: %q <= %q", i, ids[i], ids[i-1])
		}
	}
}

func isLowerSHA256Hex(s string) bool {
	if len(s) != 64 {
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

func isGenesisPrevHash(s string) bool {
	return s == "" || s == strings.Repeat("0", 64)
}

// ValidateAuditHashChain verifies hash-chain format, UUIDv7 IDs, non-decreasing timestamps,
// and strict events[i].PreviousHash == events[i-1].EventHash linkage.
func ValidateAuditHashChain(events []AuditEvent) error {
	if len(events) == 0 {
		return errors.New("audit event slice is empty")
	}
	var prevTS time.Time
	for i, ev := range events {
		idTS, err := ParseUUIDv7(ev.ID)
		if err != nil {
			return fmt.Errorf("event[%d] invalid ID: %w", i, err)
		}
		if !isLowerSHA256Hex(ev.EventHash) {
			return fmt.Errorf("event[%d] (%s) invalid event_hash %q: must be 64 lowercase hex chars", i, ev.ID, ev.EventHash)
		}
		if !isGenesisPrevHash(ev.PreviousHash) {
			if !isLowerSHA256Hex(ev.PreviousHash) {
				return fmt.Errorf("event[%d] (%s) invalid previous_hash %q", i, ev.ID, ev.PreviousHash)
			}
			if ev.PreviousHash == ev.EventHash {
				return fmt.Errorf("event[%d] (%s) previous_hash equals event_hash (%s)", i, ev.ID, ev.EventHash)
			}
		}
		effectiveTS := ev.CreatedAt
		if effectiveTS.IsZero() {
			effectiveTS = idTS
		}
		if i > 0 {
			if events[i].PreviousHash != events[i-1].EventHash {
				return fmt.Errorf("hash chain break at event[%d] (%s): previous_hash=%q != prev.event_hash=%q",
					i, ev.ID, events[i].PreviousHash, events[i-1].EventHash)
			}
			if effectiveTS.Before(prevTS) {
				return fmt.Errorf("audit timestamp decreased at event[%d] (%s): %s < %s",
					i, ev.ID, effectiveTS.Format(time.RFC3339Nano), prevTS.Format(time.RFC3339Nano))
			}
		}
		prevTS = effectiveTS
	}
	return nil
}

// ValidateFullAuditHashChainFromGenesis additionally verifies events[0] is a valid genesis link.
func ValidateFullAuditHashChainFromGenesis(events []AuditEvent) error {
	if err := ValidateAuditHashChain(events); err != nil {
		return err
	}
	if !isGenesisPrevHash(events[0].PreviousHash) {
		return fmt.Errorf("event[0] (%s) is not genesis: previous_hash=%q", events[0].ID, events[0].PreviousHash)
	}
	return nil
}

// ValidateAuditHashChainWithDigest verifies chain linkage AND recomputes each event's SHA-256 digest via preimageFn.
func ValidateAuditHashChainWithDigest(events []AuditEvent, preimageFn func(AuditEvent) []byte) error {
	if err := ValidateAuditHashChain(events); err != nil {
		return err
	}
	if preimageFn == nil {
		return errors.New("preimageFn must not be nil")
	}
	for i, ev := range events {
		sum := sha256.Sum256(preimageFn(ev))
		want := hex.EncodeToString(sum[:])
		if ev.EventHash != want {
			return fmt.Errorf("event[%d] (%s) digest mismatch: got %s, want %s", i, ev.ID, ev.EventHash, want)
		}
	}
	return nil
}

// VerifyAuditHashChain fails t if events do not form a valid audit hash chain.
func VerifyAuditHashChain(t testing.TB, events []AuditEvent) {
	t.Helper()
	if err := ValidateAuditHashChain(events); err != nil {
		t.Fatalf("VerifyAuditHashChain failed: %v", err)
	}
}

// VerifyFullAuditHashChainFromGenesis fails t if events do not form a complete genesis-anchored chain.
func VerifyFullAuditHashChainFromGenesis(t testing.TB, events []AuditEvent) {
	t.Helper()
	if err := ValidateFullAuditHashChainFromGenesis(events); err != nil {
		t.Fatalf("VerifyFullAuditHashChainFromGenesis failed: %v", err)
	}
}

// VerifyAuditHashChainWithDigest fails t if chain linkage or canonical SHA-256 digest verification fails.
func VerifyAuditHashChainWithDigest(t testing.TB, events []AuditEvent, preimageFn func(AuditEvent) []byte) {
	t.Helper()
	if err := ValidateAuditHashChainWithDigest(events, preimageFn); err != nil {
		t.Fatalf("VerifyAuditHashChainWithDigest failed: %v", err)
	}
}

func maskSecret(sec string) string {
	if len(sec) <= 6 {
		return "***"
	}
	return sec[:3] + "..." + sec[len(sec)-2:]
}

// FindSecretLeaks checks text for verbatim occurrences of any secret in secrets.
// Empty secrets are returned as an explicit sentinel marker so callers cannot pass empty strings silently.
func FindSecretLeaks(text string, secrets ...string) []string {
	var leaks []string
	for idx, sec := range secrets {
		if sec == "" {
			leaks = append(leaks, fmt.Sprintf("<empty-secret-arg-%d>", idx))
			continue
		}
		if strings.Contains(text, sec) {
			leaks = append(leaks, fmt.Sprintf("verbatim(%s)", maskSecret(sec)))
		}
	}
	return leaks
}

// FindSecretOrEncodedLeaks checks verbatim, base64-std, base64-rawurl, and URL-escaped forms of secrets.
func FindSecretOrEncodedLeaks(text string, secrets ...string) []string {
	leaks := FindSecretLeaks(text, secrets...)
	for _, sec := range secrets {
		if len(sec) < 8 {
			continue
		}
		b64Std := base64.StdEncoding.EncodeToString([]byte(sec))
		if strings.Contains(text, b64Std) {
			leaks = append(leaks, fmt.Sprintf("base64std(%s)", maskSecret(sec)))
		}
		b64URL := base64.RawURLEncoding.EncodeToString([]byte(sec))
		if strings.Contains(text, b64URL) {
			leaks = append(leaks, fmt.Sprintf("base64url(%s)", maskSecret(sec)))
		}
		escaped := url.QueryEscape(sec)
		if escaped != sec && strings.Contains(text, escaped) {
			leaks = append(leaks, fmt.Sprintf("urlescaped(%s)", maskSecret(sec)))
		}
	}
	return leaks
}

// AssertNoSecretLeak fails t if any secret appears in text (or if an empty secret argument was passed).
func AssertNoSecretLeak(t testing.TB, text string, secrets ...string) {
	t.Helper()
	if leaks := FindSecretLeaks(text, secrets...); len(leaks) > 0 {
		t.Fatalf("secret leak detected: %s", strings.Join(leaks, ", "))
	}
}

// AssertNoSecretOrEncodedLeak fails t if any secret or encoded variant appears in text.
func AssertNoSecretOrEncodedLeak(t testing.TB, text string, secrets ...string) {
	t.Helper()
	if leaks := FindSecretOrEncodedLeaks(text, secrets...); len(leaks) > 0 {
		t.Fatalf("secret/encoded leak detected: %s", strings.Join(leaks, ", "))
	}
}

// AssertLogIDsAndDigestsOnly checks structured service logs for common unredacted credential markers.
func AssertLogIDsAndDigestsOnly(t testing.TB, logOutput string) {
	t.Helper()
	markers := []string{
		"BEGIN RSA PRIVATE KEY",
		"BEGIN EC PRIVATE KEY",
		"BEGIN OPENSSH PRIVATE KEY",
		"BEGIN PRIVATE KEY",
		"x-access-token:",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_",
		"ghs_",
	}
	for _, m := range markers {
		if strings.Contains(logOutput, m) {
			t.Fatalf("log output violated ID/digest-only invariant; found credential marker %q", m)
		}
	}
}
