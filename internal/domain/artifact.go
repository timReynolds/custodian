package domain

import (
	"time"

	"github.com/google/uuid"
)

type ArtifactKind string

const (
	ArtifactKindWorkspaceSource     ArtifactKind = "WORKSPACE_SOURCE"
	ArtifactKindSourceManifest      ArtifactKind = "SOURCE_MANIFEST"
	ArtifactKindEgressSnapshot      ArtifactKind = "EGRESS_SNAPSHOT"
	ArtifactKindCanonicalTree       ArtifactKind = "CANONICAL_TREE"
	ArtifactKindCanonicalDiff       ArtifactKind = "CANONICAL_DIFF"
	ArtifactKindPublicationManifest ArtifactKind = "PUBLICATION_MANIFEST"
	ArtifactKindScanEvidence        ArtifactKind = "SCAN_EVIDENCE"
	ArtifactKindModelEvidence       ArtifactKind = "MODEL_EVIDENCE"
)

func (k ArtifactKind) IsValid() bool {
	switch k {
	case ArtifactKindWorkspaceSource,
		ArtifactKindSourceManifest,
		ArtifactKindEgressSnapshot,
		ArtifactKindCanonicalTree,
		ArtifactKindCanonicalDiff,
		ArtifactKindPublicationManifest,
		ArtifactKindScanEvidence,
		ArtifactKindModelEvidence:
		return true
	default:
		return false
	}
}

type Artifact struct {
	ID                uuid.UUID    `json:"id"`
	Kind              ArtifactKind `json:"kind"`
	SHA256            string       `json:"sha256"`
	StorageKey        string       `json:"storage_key"`
	StorageGeneration string       `json:"storage_generation"`
	SizeBytes         int64        `json:"size_bytes"`
	CreatedAt         time.Time    `json:"created_at"`
}

func (a Artifact) PrefixedSHA256() string {
	return FormatPrefixedSHA256(a.SHA256)
}
