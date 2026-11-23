package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type CanonicalChange struct {
	Artifact         Artifact  `json:"artifact"`
	DiffArtifact     *Artifact `json:"diff_artifact,omitempty"`
	ManifestArtifact *Artifact `json:"manifest_artifact,omitempty"`
	TreeDigest       string    `json:"tree_digest"`
	DiffDigest       string    `json:"diff_digest"`
	ManifestDigest   string    `json:"manifest_digest"`
	Paths            []string  `json:"paths"`
	FileCount        int       `json:"file_count"`
	TotalBytes       int64     `json:"total_bytes"`
}

type ApprovedPublication struct {
	ProposalID     uuid.UUID `json:"proposal_id"`
	ManifestDigest string    `json:"manifest_digest"`
}

type PublicationResult struct {
	ProposalID uuid.UUID `json:"proposal_id"`
	CommitSHA  string    `json:"commit_sha"`
	Branch     string    `json:"branch"`
	PRNumber   int64     `json:"pr_number"`
	PRURL      string    `json:"pr_url"`
}

type SnapshotCapability struct {
	TokenID     uuid.UUID `json:"jti"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	Generation  int64     `json:"generation"`
	ObjectKey   string    `json:"object_key"`
	MaxBytes    int64     `json:"max_bytes"`
	UploadOnly  bool      `json:"upload_only"`
	IssuedTo    uuid.UUID `json:"issued_to"`
	Provenance  string    `json:"provenance,omitempty"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Validate enforces scope, upload-only, object-key safety, size, and expiration invariants.
func (c SnapshotCapability) Validate(now time.Time) error {
	if c.TokenID == uuid.Nil {
		return Unauthorized("INVALID_CAPABILITY", "capability token ID must not be nil")
	}
	if c.WorkspaceID == uuid.Nil {
		return BadRequest("INVALID_CAPABILITY", "workspace_id must not be nil")
	}
	if c.Generation < 0 {
		return BadRequest("INVALID_CAPABILITY", "generation must be non-negative")
	}
	if !isSafeObjectKey(c.ObjectKey) {
		return BadRequest("INVALID_OBJECT_KEY", "capability object_key is unsafe")
	}
	if c.MaxBytes <= 0 {
		return BadRequest("INVALID_CAPABILITY", "max_bytes must be positive")
	}
	if !c.UploadOnly {
		return Forbidden("CAPABILITY_NOT_UPLOAD_ONLY", "snapshot capability must be upload-only")
	}
	if c.IssuedTo == uuid.Nil {
		return Forbidden("INVALID_CAPABILITY_ISSUED_TO", "issued_to principal must not be nil")
	}
	if c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return Unauthorized("EXPIRED_CAPABILITY", "snapshot capability has expired")
	}
	return nil
}

func isSafeObjectKey(key string) bool {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") || strings.ContainsRune(key, '\x00') {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

type CheckoutOptions struct {
	IncludeGitMetadata bool   `json:"include_git_metadata"`
	IncludeHistory     bool   `json:"include_history"`
	WorkDir            string `json:"work_dir,omitempty"`
}

type CheckoutResult struct {
	CommitSHA       string    `json:"commit_sha"`
	WorkDir         string    `json:"work_dir,omitempty"`
	Artifact        *Artifact `json:"artifact,omitempty"`
	HasGitMetadata  bool      `json:"has_git_metadata"`
	IncludesHistory bool      `json:"includes_history"`
}

type PutRequest struct {
	Kind           ArtifactKind `json:"kind"`
	ObjectKey      string       `json:"object_key"`
	ExpectedSHA256 string       `json:"expected_sha256,omitempty"`
	MaxBytes       int64        `json:"max_bytes,omitempty"`
	WorkspaceID    *uuid.UUID   `json:"workspace_id,omitempty"`
	Generation     *int64       `json:"generation,omitempty"`
	ContentType    string       `json:"content_type,omitempty"`
}
