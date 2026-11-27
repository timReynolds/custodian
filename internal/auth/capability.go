package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	capabilityVersionPrefix = "v1"
	capabilityVersionNum    = 1
	capabilityUploadScope   = "snapshot:upload"
	minCapabilitySecretLen  = 32

	defaultCapabilityTTL       = 5 * time.Minute
	defaultCapabilityMaxTTL    = 15 * time.Minute
	defaultCapabilityClockSkew = 10 * time.Second
)

// CapabilityConfig configures CapabilityService.
type CapabilityConfig struct {
	Secret     []byte
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	ClockSkew  time.Duration
	Now        func() time.Time
}

// UploadScope binds verification of an upload capability token to a specific upload operation.
type UploadScope struct {
	WorkspaceID   uuid.UUID
	Generation    int64
	ObjectKey     string
	ContentLength int64
	PrincipalID   *uuid.UUID
	Operation     string
}

type capabilityEnvelope struct {
	Version     int       `json:"ver"`
	Scope       string    `json:"scope"`
	TokenID     uuid.UUID `json:"jti"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	Generation  int64     `json:"generation"`
	ObjectKey   string    `json:"object_key"`
	MaxBytes    int64     `json:"max_bytes"`
	UploadOnly  bool      `json:"upload_only"`
	IssuedTo    uuid.UUID `json:"issued_to"`
	Provenance  string    `json:"provenance,omitempty"`
	IssuedAt    time.Time `json:"iat"`
	ExpiresAt   time.Time `json:"exp"`
}

// CapabilityService issues and verifies short-lived HMAC-SHA256 upload-only snapshot capabilities.
type CapabilityService struct {
	secret     []byte
	defaultTTL time.Duration
	maxTTL     time.Duration
	clockSkew  time.Duration
	now        func() time.Time
}

var _ domain.CapabilitySigner = (*CapabilityService)(nil)

// NewCapabilityService constructs a CapabilityService with strict secret length and TTL validation.
func NewCapabilityService(cfg CapabilityConfig) (*CapabilityService, error) {
	if len(cfg.Secret) < minCapabilitySecretLen {
		return nil, domain.BadRequest("INVALID_CAPABILITY_SECRET", "capability HMAC secret must be at least 32 bytes")
	}
	if cfg.DefaultTTL < 0 || cfg.MaxTTL < 0 || cfg.ClockSkew < 0 {
		return nil, domain.BadRequest("INVALID_CAPABILITY_CONFIG", "capability durations must be non-negative")
	}

	defTTL := cfg.DefaultTTL
	if defTTL == 0 {
		defTTL = defaultCapabilityTTL
	}
	maxTTL := cfg.MaxTTL
	if maxTTL == 0 {
		maxTTL = defaultCapabilityMaxTTL
	}
	if defTTL > maxTTL {
		return nil, domain.BadRequest("INVALID_CAPABILITY_CONFIG", "default capability TTL cannot exceed max TTL")
	}
	skew := cfg.ClockSkew
	if skew == 0 {
		skew = defaultCapabilityClockSkew
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	secretCopy := make([]byte, len(cfg.Secret))
	copy(secretCopy, cfg.Secret)

	return &CapabilityService{
		secret:     secretCopy,
		defaultTTL: defTTL,
		maxTTL:     maxTTL,
		clockSkew:  skew,
		now:        nowFn,
	}, nil
}

// IssueUpload mints a signed upload-only capability token for claims.
func (s *CapabilityService) IssueUpload(ctx context.Context, claims domain.SnapshotCapability) (string, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", domain.WrapError(domain.ErrUnavailable, "CAPABILITY_CONTEXT_CANCELLED", "capability issuance aborted", err)
		}
	}

	now := s.now().UTC()
	if claims.TokenID == uuid.Nil {
		id, err := domain.NewID()
		if err != nil {
			return "", domain.WrapError(domain.ErrInternal, "ID_GENERATION_FAILED", "failed to generate capability ID", err)
		}
		claims.TokenID = id
	}
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = now
	} else {
		claims.IssuedAt = claims.IssuedAt.UTC()
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = claims.IssuedAt.Add(s.defaultTTL)
	} else {
		claims.ExpiresAt = claims.ExpiresAt.UTC()
	}

	if !claims.IssuedAt.Before(claims.ExpiresAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > s.maxTTL {
		return "", domain.BadRequest("INVALID_CAPABILITY_TTL", "capability TTL is invalid or exceeds maximum allowed duration")
	}
	if err := claims.Validate(now); err != nil {
		return "", err
	}

	env := capabilityEnvelope{
		Version:     capabilityVersionNum,
		Scope:       capabilityUploadScope,
		TokenID:     claims.TokenID,
		WorkspaceID: claims.WorkspaceID,
		Generation:  claims.Generation,
		ObjectKey:   claims.ObjectKey,
		MaxBytes:    claims.MaxBytes,
		UploadOnly:  claims.UploadOnly,
		IssuedTo:    claims.IssuedTo,
		Provenance:  strings.TrimSpace(claims.Provenance),
		IssuedAt:    claims.IssuedAt,
		ExpiresAt:   claims.ExpiresAt,
	}

	payloadJSON, err := json.Marshal(env)
	if err != nil {
		return "", domain.WrapError(domain.ErrInternal, "CAPABILITY_ENCODE_FAILED", "failed to encode capability", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := capabilityVersionPrefix + "." + payloadB64
	mac := s.computeMAC(signingInput)
	macB64 := base64.RawURLEncoding.EncodeToString(mac)

	return signingInput + "." + macB64, nil
}

// VerifyUpload verifies signature, format, scope, TTL, and SnapshotCapability invariants.
func (s *CapabilityService) VerifyUpload(ctx context.Context, token string) (domain.SnapshotCapability, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return domain.SnapshotCapability{}, domain.WrapError(domain.ErrUnavailable, "CAPABILITY_CONTEXT_CANCELLED", "capability verification aborted", err)
		}
	}

	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY", "capability token is empty or malformed")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != capabilityVersionPrefix || parts[1] == "" || parts[2] == "" {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY", "capability token format is invalid")
	}

	macBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(macBytes) != sha256.Size {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY_SIGNATURE", "capability signature is malformed")
	}

	signingInput := parts[0] + "." + parts[1]
	expectedMAC := s.computeMAC(signingInput)
	if !hmac.Equal(macBytes, expectedMAC) {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY_SIGNATURE", "capability signature verification failed")
	}

	payloadJSON, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY", "capability payload encoding is invalid")
	}

	var env capabilityEnvelope
	dec := json.NewDecoder(bytes.NewReader(payloadJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY", "capability payload JSON is invalid")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY", "capability payload contains trailing data")
	}

	if env.Version != capabilityVersionNum {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY_VERSION", "unsupported capability version")
	}
	if env.Scope != capabilityUploadScope {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_NOT_UPLOAD_ONLY", "capability scope is not upload-only")
	}

	now := s.now().UTC()
	if env.IssuedAt.IsZero() || env.IssuedAt.After(now.Add(s.clockSkew)) {
		return domain.SnapshotCapability{}, domain.Unauthorized("CAPABILITY_NOT_YET_VALID", "capability issued_at is in the future")
	}
	if !env.IssuedAt.Before(env.ExpiresAt) || env.ExpiresAt.Sub(env.IssuedAt) > s.maxTTL {
		return domain.SnapshotCapability{}, domain.Unauthorized("INVALID_CAPABILITY_TTL", "capability TTL is invalid")
	}

	claims := domain.SnapshotCapability{
		TokenID:     env.TokenID,
		WorkspaceID: env.WorkspaceID,
		Generation:  env.Generation,
		ObjectKey:   env.ObjectKey,
		MaxBytes:    env.MaxBytes,
		UploadOnly:  env.UploadOnly,
		IssuedTo:    env.IssuedTo,
		Provenance:  env.Provenance,
		IssuedAt:    env.IssuedAt.UTC(),
		ExpiresAt:   env.ExpiresAt.UTC(),
	}
	if err := claims.Validate(now); err != nil {
		return domain.SnapshotCapability{}, err
	}
	return claims, nil
}

// VerifyUploadFor verifies the capability token and binds it strictly to the requested upload scope.
func (s *CapabilityService) VerifyUploadFor(ctx context.Context, token string, scope UploadScope) (domain.SnapshotCapability, error) {
	op := strings.ToLower(strings.TrimSpace(scope.Operation))
	if op != "" && op != "upload" {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_OPERATION_DENIED", "capability cannot be used for non-upload operations")
	}

	claims, err := s.VerifyUpload(ctx, token)
	if err != nil {
		return domain.SnapshotCapability{}, err
	}

	if scope.WorkspaceID == uuid.Nil || claims.WorkspaceID != scope.WorkspaceID {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_WORKSPACE_MISMATCH", "capability workspace_id mismatch")
	}
	if claims.Generation != scope.Generation {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_GENERATION_MISMATCH", "capability generation mismatch")
	}
	if scope.ObjectKey == "" || claims.ObjectKey != scope.ObjectKey {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_OBJECT_MISMATCH", "capability object_key mismatch")
	}
	if scope.ContentLength < 0 {
		return domain.SnapshotCapability{}, domain.BadRequest("INVALID_CONTENT_LENGTH", "content length must be non-negative")
	}
	if scope.ContentLength > claims.MaxBytes {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_SIZE_EXCEEDED", "upload size exceeds capability max_bytes")
	}
	if scope.PrincipalID != nil && claims.IssuedTo != *scope.PrincipalID {
		return domain.SnapshotCapability{}, domain.Forbidden("CAPABILITY_PRINCIPAL_MISMATCH", "capability issued_to principal mismatch")
	}

	return claims, nil
}

func (s *CapabilityService) computeMAC(input string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(input))
	return mac.Sum(nil)
}
