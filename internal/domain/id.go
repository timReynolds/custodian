package domain

import (
	"strings"

	"github.com/google/uuid"
)

// NewID generates a new UUIDv7 identifier.
func NewID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, WrapError(ErrInternal, "ID_GENERATION_FAILED", "failed to generate UUIDv7", err)
	}
	return id, nil
}

// MustNewID generates a new UUIDv7 identifier and panics on failure.
func MustNewID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id
}

// ParseID parses a string UUID and rejects empty, malformed, or nil UUIDs with ErrBadRequest.
func ParseID(raw string) (uuid.UUID, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return uuid.Nil, BadRequest("INVALID_ID", "id must not be empty")
	}
	id, err := uuid.Parse(trimmed)
	if err != nil {
		return uuid.Nil, WrapError(ErrBadRequest, "INVALID_ID", "invalid UUID format", err)
	}
	if id == uuid.Nil {
		return uuid.Nil, BadRequest("INVALID_ID", "id must not be nil UUID")
	}
	return id, nil
}

// IsUUIDv7 reports whether id is a non-nil RFC 9562 UUIDv7.
func IsUUIDv7(id uuid.UUID) bool {
	return id != uuid.Nil && id.Version() == uuid.Version(7) && id.Variant() == uuid.RFC4122
}
