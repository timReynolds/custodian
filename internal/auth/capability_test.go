package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

func testSecret() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestNewCapabilityServiceValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewCapabilityService(CapabilityConfig{Secret: []byte("too-short")}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for short secret, got %v", err)
	}
	if _, err := NewCapabilityService(CapabilityConfig{
		Secret:     testSecret(),
		DefaultTTL: 20 * time.Minute,
		MaxTTL:     10 * time.Minute,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest when DefaultTTL > MaxTTL, got %v", err)
	}
}

func TestCapabilityServiceRoundTripAndScopes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	svc, err := NewCapabilityService(CapabilityConfig{
		Secret:     testSecret(),
		DefaultTTL: 5 * time.Minute,
		MaxTTL:     15 * time.Minute,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewCapabilityService: %v", err)
	}

	wsID := domain.MustNewID()
	ctrlID := domain.MustNewID()

	tok, err := svc.IssueUpload(context.Background(), domain.SnapshotCapability{
		WorkspaceID: wsID,
		Generation:  1,
		ObjectKey:   "workspaces/" + wsID.String() + "/egress/gen-1.tar.gz",
		MaxBytes:    1024 * 1024,
		UploadOnly:  true,
		IssuedTo:    ctrlID,
		Provenance:  "controller-runtime-v1",
	})
	if err != nil {
		t.Fatalf("IssueUpload: %v", err)
	}
	if !strings.HasPrefix(tok, "v1.") {
		t.Fatalf("expected v1. prefix, got %q", tok)
	}

	got, err := svc.VerifyUpload(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyUpload: %v", err)
	}
	if got.WorkspaceID != wsID || got.Generation != 1 || got.IssuedTo != ctrlID || !got.UploadOnly {
		t.Fatalf("unexpected claims: %+v", got)
	}

	scope := UploadScope{
		WorkspaceID:   wsID,
		Generation:    1,
		ObjectKey:     got.ObjectKey,
		ContentLength: 4096,
		PrincipalID:   &ctrlID,
		Operation:     "upload",
	}
	if _, err := svc.VerifyUploadFor(context.Background(), tok, scope); err != nil {
		t.Fatalf("VerifyUploadFor: %v", err)
	}
}

func TestCapabilityServiceRejectsTamperingAndMisuse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	curNow := now
	svc, err := NewCapabilityService(CapabilityConfig{
		Secret:     testSecret(),
		DefaultTTL: 5 * time.Minute,
		MaxTTL:     15 * time.Minute,
		Now:        func() time.Time { return curNow },
	})
	if err != nil {
		t.Fatalf("NewCapabilityService: %v", err)
	}

	wsID := domain.MustNewID()
	ctrlID := domain.MustNewID()
	objKey := "workspaces/" + wsID.String() + "/egress/gen-1.tar.gz"

	// Non-upload-only rejected at issue
	if _, err := svc.IssueUpload(context.Background(), domain.SnapshotCapability{
		WorkspaceID: wsID,
		Generation:  1,
		ObjectKey:   objKey,
		MaxBytes:    1024,
		UploadOnly:  false,
		IssuedTo:    ctrlID,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for UploadOnly=false, got %v", err)
	}

	// Unsafe object key rejected at issue
	if _, err := svc.IssueUpload(context.Background(), domain.SnapshotCapability{
		WorkspaceID: wsID,
		Generation:  1,
		ObjectKey:   "../escape.tar.gz",
		MaxBytes:    1024,
		UploadOnly:  true,
		IssuedTo:    ctrlID,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for unsafe object key, got %v", err)
	}

	tok, err := svc.IssueUpload(context.Background(), domain.SnapshotCapability{
		WorkspaceID: wsID,
		Generation:  1,
		ObjectKey:   objKey,
		MaxBytes:    1024,
		UploadOnly:  true,
		IssuedTo:    ctrlID,
	})
	if err != nil {
		t.Fatalf("IssueUpload: %v", err)
	}

	// Tampered payload
	parts := strings.Split(tok, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"ver":1,"scope":"snapshot:upload","max_bytes":999999}`))
	if _, err := svc.VerifyUpload(context.Background(), strings.Join(parts, ".")); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for tampered payload, got %v", err)
	}

	// Tampered MAC
	macParts := strings.Split(tok, ".")
	macParts[2] = "ZZZZ" + macParts[2][4:]
	if _, err := svc.VerifyUpload(context.Background(), strings.Join(macParts, ".")); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for tampered MAC, got %v", err)
	}

	// Truncated / extra segments
	if _, err := svc.VerifyUpload(context.Background(), "v1.abc"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for truncated token, got %v", err)
	}
	if _, err := svc.VerifyUpload(context.Background(), tok+".extra"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for extra segment, got %v", err)
	}

	// Wrong secret
	otherSvc, err := NewCapabilityService(CapabilityConfig{
		Secret: []byte("fedcba9876543210fedcba9876543210"),
		Now:    func() time.Time { return curNow },
	})
	if err != nil {
		t.Fatalf("NewCapabilityService other: %v", err)
	}
	if _, err := otherSvc.VerifyUpload(context.Background(), tok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for wrong secret, got %v", err)
	}

	// Read/download operation rejected with 403
	for _, op := range []string{"read", "download", "delete"} {
		if _, err := svc.VerifyUploadFor(context.Background(), tok, UploadScope{
			WorkspaceID: wsID, Generation: 1, ObjectKey: objKey, ContentLength: 512, Operation: op,
		}); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("expected ErrForbidden for operation %q, got %v", op, err)
		}
	}

	// Signed token with non-upload scope rejected with 403
	readEnv := capabilityEnvelope{
		Version:     1,
		Scope:       "snapshot:read",
		TokenID:     domain.MustNewID(),
		WorkspaceID: wsID,
		Generation:  1,
		ObjectKey:   objKey,
		MaxBytes:    1024,
		UploadOnly:  true,
		IssuedTo:    ctrlID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(time.Minute),
	}
	b, _ := json.Marshal(readEnv)
	in := "v1." + base64.RawURLEncoding.EncodeToString(b)
	readTok := in + "." + base64.RawURLEncoding.EncodeToString(svc.computeMAC(in))
	if _, err := svc.VerifyUpload(context.Background(), readTok); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for snapshot:read scope, got %v", err)
	}

	// Cross-workspace, cross-generation, cross-object, size exceeded, principal mismatch
	otherID := domain.MustNewID()
	if _, err := svc.VerifyUploadFor(context.Background(), tok, UploadScope{
		WorkspaceID: otherID, Generation: 1, ObjectKey: objKey, ContentLength: 10,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for cross-workspace, got %v", err)
	}
	if _, err := svc.VerifyUploadFor(context.Background(), tok, UploadScope{
		WorkspaceID: wsID, Generation: 2, ObjectKey: objKey, ContentLength: 10,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for cross-generation, got %v", err)
	}
	if _, err := svc.VerifyUploadFor(context.Background(), tok, UploadScope{
		WorkspaceID: wsID, Generation: 1, ObjectKey: "other.tar.gz", ContentLength: 10,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for cross-object, got %v", err)
	}
	if _, err := svc.VerifyUploadFor(context.Background(), tok, UploadScope{
		WorkspaceID: wsID, Generation: 1, ObjectKey: objKey, ContentLength: 1025,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for size exceeded, got %v", err)
	}
	if _, err := svc.VerifyUploadFor(context.Background(), tok, UploadScope{
		WorkspaceID: wsID, Generation: 1, ObjectKey: objKey, ContentLength: 10, PrincipalID: &otherID,
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for principal mismatch, got %v", err)
	}

	// Expired capability
	curNow = now.Add(6 * time.Minute)
	if _, err := svc.VerifyUpload(context.Background(), tok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for expired capability, got %v", err)
	}
	_ = uuid.Nil
}
