package domain

import (
	"context"
	"io"

	"github.com/google/uuid"
)

// GitReader resolves refs and performs hardened read-only checkouts.
type GitReader interface {
	ResolveRef(ctx context.Context, repo Repository, ref string) (string, error)
	Checkout(ctx context.Context, repo Repository, commitSHA string, opts CheckoutOptions) (CheckoutResult, error)
}

// SnapshotStore persists and retrieves immutable content-addressed artifacts.
type SnapshotStore interface {
	Put(ctx context.Context, req PutRequest, r io.Reader, size int64) (Artifact, error)
	Open(ctx context.Context, artifact Artifact) (io.ReadCloser, error)
	Verify(ctx context.Context, artifact Artifact) error
	Delete(ctx context.Context, artifact Artifact) error
}

// Reconstructor applies a verified egress snapshot onto a clean base checkout.
type Reconstructor interface {
	Reconstruct(ctx context.Context, repo Repository, baseCommit string, snapshot Artifact) (CanonicalChange, error)
}

// Publisher creates or updates a single PR on custodian/<proposal-id>.
type Publisher interface {
	Publish(ctx context.Context, req ApprovedPublication) (PublicationResult, error)
}

// CapabilitySigner issues and verifies short-lived upload-only snapshot capabilities.
type CapabilitySigner interface {
	IssueUpload(ctx context.Context, claims SnapshotCapability) (string, error)
	VerifyUpload(ctx context.Context, token string) (SnapshotCapability, error)
}

// PrincipalStore resolves and upserts verified identity directory principals.
type PrincipalStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (Principal, error)
	GetByIssuerSubject(ctx context.Context, issuer, subject string) (Principal, error)
	Upsert(ctx context.Context, principal Principal) (Principal, error)
}
