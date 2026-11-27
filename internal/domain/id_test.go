package domain

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNewID_UUIDv7Properties(t *testing.T) {
	seen := make(map[uuid.UUID]struct{}, 1000)
	var prev string
	for i := 0; i < 1000; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID() failed at %d: %v", i, err)
		}
		if id == uuid.Nil {
			t.Fatalf("NewID() returned uuid.Nil")
		}
		if id.Version() != uuid.Version(7) {
			t.Fatalf("expected version 7, got %d", id.Version())
		}
		if id.Variant() != uuid.RFC4122 {
			t.Fatalf("expected RFC4122 variant, got %v", id.Variant())
		}
		if !IsUUIDv7(id) {
			t.Fatalf("IsUUIDv7(%s) = false", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate UUIDv7 generated: %s", id)
		}
		seen[id] = struct{}{}

		s := id.String()
		if prev != "" && s < prev {
			t.Fatalf("UUIDv7 not monotonically non-decreasing: prev=%s curr=%s", prev, s)
		}
		prev = s
	}
}

func TestMustNewID(t *testing.T) {
	id := MustNewID()
	if !IsUUIDv7(id) {
		t.Fatalf("MustNewID() returned non-v7 UUID: %s", id)
	}
}

func TestParseID(t *testing.T) {
	valid := MustNewID()
	parsed, err := ParseID("  " + valid.String() + "\n")
	if err != nil {
		t.Fatalf("ParseID(valid) unexpected error: %v", err)
	}
	if parsed != valid {
		t.Fatalf("ParseID mismatch: got %s want %s", parsed, valid)
	}

	cases := []string{
		"",
		"   ",
		"not-a-uuid",
		uuid.Nil.String(),
	}
	for _, tc := range cases {
		_, err := ParseID(tc)
		if !errors.Is(err, ErrBadRequest) {
			t.Fatalf("ParseID(%q) error = %v, want ErrBadRequest", tc, err)
		}
	}
}

func TestIsUUIDv7(t *testing.T) {
	if IsUUIDv7(uuid.Nil) {
		t.Fatal("IsUUIDv7(uuid.Nil) = true, want false")
	}
	if IsUUIDv7(uuid.New()) {
		t.Fatal("IsUUIDv7(v4) = true, want false")
	}
	if !IsUUIDv7(MustNewID()) {
		t.Fatal("IsUUIDv7(v7) = false, want true")
	}

	// Non-RFC4122 variants with version 7 nibble must be rejected per RFC 9562.
	base := MustNewID()
	for _, tc := range []struct {
		name string
		bits byte
	}{
		{name: "Reserved", bits: 0x00},
		{name: "Microsoft", bits: 0xc0},
		{name: "Future", bits: 0xe0},
	} {
		var nonRFC uuid.UUID
		copy(nonRFC[:], base[:])
		nonRFC[8] = (nonRFC[8] & 0x1f) | tc.bits
		if nonRFC.Version() != uuid.Version(7) {
			t.Fatalf("%s: expected version 7, got %d", tc.name, nonRFC.Version())
		}
		if nonRFC.Variant() == uuid.RFC4122 {
			t.Fatalf("%s: expected non-RFC4122 variant, got %v", tc.name, nonRFC.Variant())
		}
		if IsUUIDv7(nonRFC) {
			t.Fatalf("IsUUIDv7(%s variant %v) = true, want false", tc.name, nonRFC.Variant())
		}
	}
}
