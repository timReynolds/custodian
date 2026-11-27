package domain

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type PushTransport string

const (
	PushTransportHTTPS PushTransport = "HTTPS"
	PushTransportSSH   PushTransport = "SSH"
)

func (t PushTransport) IsValid() bool {
	switch t {
	case PushTransportHTTPS, PushTransportSSH:
		return true
	default:
		return false
	}
}

type PushSessionStatus string

const (
	PushSessionStatusReceived           PushSessionStatus = "RECEIVED"
	PushSessionStatusUnpacking          PushSessionStatus = "UNPACKING"
	PushSessionStatusQuarantined        PushSessionStatus = "QUARANTINED"
	PushSessionStatusInspecting         PushSessionStatus = "INSPECTING"
	PushSessionStatusEvaluating         PushSessionStatus = "EVALUATING"
	PushSessionStatusAllowed            PushSessionStatus = "ALLOWED"
	PushSessionStatusBlocked            PushSessionStatus = "BLOCKED"
	PushSessionStatusApprovalRequired   PushSessionStatus = "APPROVAL_REQUIRED"
	PushSessionStatusForwarding         PushSessionStatus = "FORWARDING"
	PushSessionStatusCompleted          PushSessionStatus = "COMPLETED"
	PushSessionStatusObservedWouldBlock PushSessionStatus = "OBSERVED_WOULD_BLOCK"
	PushSessionStatusFailed             PushSessionStatus = "FAILED"
)

func (s PushSessionStatus) IsValid() bool {
	switch s {
	case PushSessionStatusReceived,
		PushSessionStatusUnpacking,
		PushSessionStatusQuarantined,
		PushSessionStatusInspecting,
		PushSessionStatusEvaluating,
		PushSessionStatusAllowed,
		PushSessionStatusBlocked,
		PushSessionStatusApprovalRequired,
		PushSessionStatusForwarding,
		PushSessionStatusCompleted,
		PushSessionStatusObservedWouldBlock,
		PushSessionStatusFailed:
		return true
	default:
		return false
	}
}

func (s PushSessionStatus) IsTerminal() bool {
	switch s {
	case PushSessionStatusQuarantined,
		PushSessionStatusBlocked,
		PushSessionStatusCompleted,
		PushSessionStatusObservedWouldBlock,
		PushSessionStatusFailed:
		return true
	default:
		return false
	}
}

type PushRefUpdate struct {
	RefName string `json:"ref_name"`
	OldOID  string `json:"old_oid"`
	NewOID  string `json:"new_oid"`
}

type PushLFSObject struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

type PushSession struct {
	ID                     uuid.UUID            `json:"id"`
	PrincipalID            uuid.UUID            `json:"principal_id"`
	RepositoryID           *uuid.UUID           `json:"repository_id,omitempty"`
	Destination            string               `json:"destination"`
	DestinationHost        string               `json:"destination_host"`
	DestinationRegistered  bool                 `json:"destination_registered"`
	DestinationExternal    bool                 `json:"destination_external"`
	Transport              PushTransport        `json:"transport"`
	RefUpdates             []PushRefUpdate      `json:"ref_updates,omitempty"`
	HasLFS                 bool                 `json:"has_lfs"`
	LFSObjects             []PushLFSObject      `json:"lfs_objects,omitempty"`
	LFSObjectCount         int64                `json:"lfs_object_count"`
	LFSTotalBytes          int64                `json:"lfs_total_bytes"`
	PushManifestDigest     string               `json:"push_manifest_digest,omitempty"`
	BundleArtifactID       *uuid.UUID           `json:"bundle_artifact_id,omitempty"`
	EgressMode             EgressMode           `json:"egress_mode"`
	PassiveAuditDelivery   PassiveAuditDelivery `json:"passive_audit_delivery,omitempty"`
	Enforced               bool                 `json:"enforced"`
	Status                 PushSessionStatus    `json:"status"`
	Verdict                *PolicyEffect        `json:"verdict,omitempty"`
	LatestPolicyDecisionID *uuid.UUID           `json:"latest_policy_decision_id,omitempty"`
	ApprovalReleaseID      *uuid.UUID           `json:"approval_release_id,omitempty"`
	ErrorCode              string               `json:"error_code,omitempty"`
	ErrorMessage           string               `json:"error_message,omitempty"`
	UpstreamForwarded      bool                 `json:"upstream_forwarded"`
	UpstreamBytesSent      int64                `json:"upstream_bytes_sent"`
	CreatedAt              time.Time            `json:"created_at"`
	UpdatedAt              time.Time            `json:"updated_at"`
	CompletedAt            *time.Time           `json:"completed_at,omitempty"`
}

type PushApprovalRelease struct {
	ID                      uuid.UUID  `json:"id"`
	PrincipalID             uuid.UUID  `json:"principal_id"`
	Destination             string     `json:"destination"`
	DestinationHost         string     `json:"destination_host,omitempty"`
	DestinationRepo         string     `json:"destination_repo,omitempty"`
	PushManifestDigest      string     `json:"push_manifest_digest"`
	PushSessionID           uuid.UUID  `json:"push_session_id"`
	ConsumedByPushSessionID *uuid.UUID `json:"consumed_by_push_session_id,omitempty"`
	PolicyDecisionID        uuid.UUID  `json:"policy_decision_id"`
	ApprovedBy              uuid.UUID  `json:"approved_by"`
	Reason                  string     `json:"reason,omitempty"`
	ExpiresAt               time.Time  `json:"expires_at"`
	ConsumedAt              *time.Time `json:"consumed_at,omitempty"`
	RevokedAt               *time.Time `json:"revoked_at,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
}

// IsUsableFor verifies that the approval release is active, unrevoked, unconsumed, unexpired,
// complies with Separation of Duties (ApprovedBy != PrincipalID), and matches the caller's
// principal, destination host/repository, and normalized SHA-256 push manifest digest.
func (r PushApprovalRelease) IsUsableFor(now time.Time, principalID uuid.UUID, destHost, destRepo, pushManifestDigest string) error {
	if r.RevokedAt != nil {
		return Forbidden("APPROVAL_RELEASE_REVOKED", "push approval release has been revoked")
	}
	if r.ConsumedAt != nil || r.ConsumedByPushSessionID != nil {
		return Forbidden("APPROVAL_RELEASE_CONSUMED", "push approval release has already been consumed")
	}
	if !now.Before(r.ExpiresAt) {
		return Forbidden("APPROVAL_RELEASE_EXPIRED", "push approval release has expired")
	}
	if r.PrincipalID == uuid.Nil || principalID == uuid.Nil || r.PrincipalID != principalID {
		return Forbidden("APPROVAL_RELEASE_PRINCIPAL_MISMATCH", "push approval release principal mismatch")
	}
	if r.ApprovedBy == uuid.Nil || r.ApprovedBy == r.PrincipalID {
		return Forbidden("APPROVAL_RELEASE_SOD_VIOLATION", "push approval release violates separation of duties")
	}

	normHost := strings.TrimSpace(destHost)
	normRepo := strings.TrimSpace(destRepo)
	if normHost == "" || normRepo == "" {
		return BadRequest("INVALID_DESTINATION", "destination host and repository are required")
	}

	if err := r.matchDestination(normHost, normRepo); err != nil {
		return err
	}

	expectedDigest, err := ParseSHA256Digest(pushManifestDigest)
	if err != nil {
		return BadRequest("INVALID_MANIFEST_DIGEST", fmt.Sprintf("invalid push manifest digest: %v", err))
	}
	actualDigest, err := ParseSHA256Digest(r.PushManifestDigest)
	if err != nil {
		return Forbidden("APPROVAL_RELEASE_DIGEST_MISMATCH", "approval release has invalid push manifest digest")
	}
	if !strings.EqualFold(actualDigest, expectedDigest) {
		return Forbidden("APPROVAL_RELEASE_DIGEST_MISMATCH", "push manifest digest does not match approval release")
	}
	return nil
}

func (r PushApprovalRelease) matchDestination(destHost, destRepo string) error {
	hasHost := strings.TrimSpace(r.DestinationHost) != ""
	hasRepo := strings.TrimSpace(r.DestinationRepo) != ""
	if hasHost || hasRepo {
		if !hasHost || !hasRepo {
			return Forbidden("APPROVAL_RELEASE_DESTINATION_MISMATCH", "approval release destination is incomplete")
		}
		if !strings.EqualFold(strings.TrimSpace(r.DestinationHost), destHost) || strings.TrimSpace(r.DestinationRepo) != destRepo {
			return Forbidden("APPROVAL_RELEASE_DESTINATION_MISMATCH", "push destination does not match approval release")
		}
		if strings.TrimSpace(r.Destination) != "" {
			expectedFull := destHost + "/" + destRepo
			if !strings.EqualFold(strings.TrimSpace(r.Destination), expectedFull) && strings.TrimSpace(r.Destination) != destRepo {
				return Forbidden("APPROVAL_RELEASE_DESTINATION_MISMATCH", "push destination does not match approval release")
			}
		}
		return nil
	}

	dest := strings.TrimSpace(r.Destination)
	if dest == "" {
		return Forbidden("APPROVAL_RELEASE_DESTINATION_MISMATCH", "approval release destination is empty")
	}
	host, repo, ok := strings.Cut(dest, "/")
	if !ok || strings.TrimSpace(host) == "" || strings.TrimSpace(repo) == "" {
		return Forbidden("APPROVAL_RELEASE_DESTINATION_MISMATCH", "approval release destination must include host and repository")
	}
	if !strings.EqualFold(strings.TrimSpace(host), destHost) || strings.TrimSpace(repo) != destRepo {
		return Forbidden("APPROVAL_RELEASE_DESTINATION_MISMATCH", "push destination does not match approval release")
	}
	return nil
}

type IPCorpusStatus string

const (
	IPCorpusStatusPending  IPCorpusStatus = "PENDING"
	IPCorpusStatusIndexing IPCorpusStatus = "INDEXING"
	IPCorpusStatusReady    IPCorpusStatus = "READY"
	IPCorpusStatusFailed   IPCorpusStatus = "FAILED"
)

func (s IPCorpusStatus) IsValid() bool {
	switch s {
	case IPCorpusStatusPending, IPCorpusStatusIndexing, IPCorpusStatusReady, IPCorpusStatusFailed:
		return true
	default:
		return false
	}
}

type FingerprintLayer string

const (
	FingerprintLayerL1ExactChunk   FingerprintLayer = "L1_EXACT_CHUNK"
	FingerprintLayerL2WinnowKGram  FingerprintLayer = "L2_WINNOW_KGRAM"
	FingerprintLayerL3HeaderMarker FingerprintLayer = "L3_HEADER_MARKER"
)

func (l FingerprintLayer) IsValid() bool {
	switch l {
	case FingerprintLayerL1ExactChunk, FingerprintLayerL2WinnowKGram, FingerprintLayerL3HeaderMarker:
		return true
	default:
		return false
	}
}

type IPFingerprintCorpus struct {
	ID                uuid.UUID      `json:"id"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	Classification    Classification `json:"classification"`
	RepositoryID      *uuid.UUID     `json:"repository_id,omitempty"`
	SourceRef         string         `json:"source_ref,omitempty"`
	WinnowK           int            `json:"winnow_k"`
	WinnowW           int            `json:"winnow_w"`
	ChunkSizeBytes    int            `json:"chunk_size_bytes"`
	Enabled           bool           `json:"enabled"`
	Status            IPCorpusStatus `json:"status"`
	FingerprintCount  int64          `json:"fingerprint_count"`
	LastIndexedDigest string         `json:"last_indexed_digest,omitempty"`
	LastIndexedAt     *time.Time     `json:"last_indexed_at,omitempty"`
	LastError         string         `json:"last_error,omitempty"`
	CreatedBy         *uuid.UUID     `json:"created_by,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// ValidateClassification restricts IP fingerprint corpora to CONFIDENTIAL or RESTRICTED repositories.
func (c IPFingerprintCorpus) ValidateClassification() error {
	if c.Classification == ClassificationRestricted || c.Classification == ClassificationConfidential {
		return nil
	}
	return Unprocessable("INVALID_CORPUS_CLASSIFICATION", "ip fingerprint corpus classification must be CONFIDENTIAL or RESTRICTED")
}

type IPFingerprint struct {
	ID              uuid.UUID        `json:"id"`
	CorpusID        uuid.UUID        `json:"corpus_id"`
	Layer           FingerprintLayer `json:"layer"`
	FingerprintHash string           `json:"fingerprint_hash"`
	FilePathHash    string           `json:"file_path_hash,omitempty"`
	Language        string           `json:"language,omitempty"`
	ChunkIndex      *int             `json:"chunk_index,omitempty"`
	LineStart       *int             `json:"line_start,omitempty"`
	LineEnd         *int             `json:"line_end,omitempty"`
	TokenCount      *int             `json:"token_count,omitempty"`
	Metadata        map[string]any   `json:"metadata,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
}

var forbiddenIPMetadataKeys = map[string]struct{}{
	"rawsource":  {},
	"rawcode":    {},
	"sourcetext": {},
	"content":    {},
	"snippet":    {},
	"rawsecret":  {},
	"matchraw":   {},
}

func isForbiddenIPMetadataKeyName(name string) bool {
	norm := normalizeMetadataKeyName(name)
	if _, forbidden := forbiddenIPMetadataKeys[norm]; forbidden {
		return true
	}
	return isForbiddenMetadataKeyName(norm)
}

// ValidateIPFingerprintMetadata ensures IP fingerprint metadata never persists raw source code or secret fields.
func ValidateIPFingerprintMetadata(meta map[string]any) error {
	return checkMetadataKeysWith(meta, isForbiddenIPMetadataKeyName, "FORBIDDEN_IP_METADATA", "ip fingerprint metadata contains forbidden raw source or secret key")
}
