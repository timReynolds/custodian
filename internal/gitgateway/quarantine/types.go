package quarantine

import (
	"context"
	"io"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	// ZeroOID is the 40-character all-zero Git SHA-1 OID representing ref creation/deletion.
	ZeroOID = "0000000000000000000000000000000000000000"

	defaultGitBinary             = "git"
	defaultTimeout               = 2 * time.Minute
	defaultMaxPackBytes          = int64(64 << 20)
	defaultMaxRefUpdates         = 100
	defaultMaxObjects            = 10_000
	defaultMaxInflatedObjBytes   = int64(32 << 20)
	defaultMinTotalInflatedBytes = int64(256 << 20)
	defaultMaxDeltaDepth         = 64
	defaultMaxPathBytes          = 4096
	defaultMaxPathDepth          = 64
	defaultMaxTagDepth           = 4
	defaultMaxWorkspaceBytes     = int64(256 << 20)
	defaultMaxDiffBytesPerCommit = int64(3 << 20)
)

// Limits bounds pack ingestion, inflation, delta/tag/path depth, and materialized inspection size.
type Limits struct {
	MaxPackBytes           int64
	MaxRefUpdates          int
	MaxObjects             int
	MaxInflatedObjectBytes int64
	MaxTotalInflatedBytes  int64
	MaxDeltaDepth          int
	MaxPathBytes           int
	MaxPathDepth           int
	MaxTagDepth            int
	MaxWorkspaceBytes      int64
	MaxDiffBytesPerCommit  int64
}

func defaultLimits() Limits {
	return Limits{
		MaxPackBytes:           defaultMaxPackBytes,
		MaxRefUpdates:          defaultMaxRefUpdates,
		MaxObjects:             defaultMaxObjects,
		MaxInflatedObjectBytes: defaultMaxInflatedObjBytes,
		MaxTotalInflatedBytes:  defaultMinTotalInflatedBytes * 2,
		MaxDeltaDepth:          defaultMaxDeltaDepth,
		MaxPathBytes:           defaultMaxPathBytes,
		MaxPathDepth:           defaultMaxPathDepth,
		MaxTagDepth:            defaultMaxTagDepth,
		MaxWorkspaceBytes:      defaultMaxWorkspaceBytes,
		MaxDiffBytesPerCommit:  defaultMaxDiffBytesPerCommit,
	}
}

func (l Limits) validateNonNegative() error {
	if l.MaxPackBytes < 0 ||
		l.MaxRefUpdates < 0 ||
		l.MaxObjects < 0 ||
		l.MaxInflatedObjectBytes < 0 ||
		l.MaxTotalInflatedBytes < 0 ||
		l.MaxDeltaDepth < 0 ||
		l.MaxPathBytes < 0 ||
		l.MaxPathDepth < 0 ||
		l.MaxTagDepth < 0 ||
		l.MaxWorkspaceBytes < 0 ||
		l.MaxDiffBytesPerCommit < 0 {
		return domain.BadRequest("INVALID_LIMITS", "quarantine limits must not be negative")
	}
	return nil
}

func (l Limits) resolve(base Limits) (Limits, error) {
	if err := l.validateNonNegative(); err != nil {
		return Limits{}, err
	}
	out := base
	if l.MaxPackBytes > 0 {
		out.MaxPackBytes = l.MaxPackBytes
	}
	if l.MaxRefUpdates > 0 {
		out.MaxRefUpdates = l.MaxRefUpdates
	}
	if l.MaxObjects > 0 {
		out.MaxObjects = l.MaxObjects
	}
	if l.MaxInflatedObjectBytes > 0 {
		out.MaxInflatedObjectBytes = l.MaxInflatedObjectBytes
	}
	if l.MaxTotalInflatedBytes > 0 {
		out.MaxTotalInflatedBytes = l.MaxTotalInflatedBytes
	} else {
		calc := scaledMaxTotalInflatedBytes(out.MaxInflatedObjectBytes)
		if out.MaxTotalInflatedBytes <= 0 || out.MaxTotalInflatedBytes < calc {
			out.MaxTotalInflatedBytes = calc
		}
	}
	if l.MaxDeltaDepth > 0 {
		out.MaxDeltaDepth = l.MaxDeltaDepth
	}
	if l.MaxPathBytes > 0 {
		out.MaxPathBytes = l.MaxPathBytes
	}
	if l.MaxPathDepth > 0 {
		out.MaxPathDepth = l.MaxPathDepth
	}
	if l.MaxTagDepth > 0 {
		out.MaxTagDepth = l.MaxTagDepth
	}
	if l.MaxWorkspaceBytes > 0 {
		out.MaxWorkspaceBytes = l.MaxWorkspaceBytes
	}
	if l.MaxDiffBytesPerCommit > 0 {
		out.MaxDiffBytesPerCommit = l.MaxDiffBytesPerCommit
	}

	if out.MaxPackBytes <= 0 {
		out.MaxPackBytes = defaultMaxPackBytes
	}
	if out.MaxRefUpdates <= 0 {
		out.MaxRefUpdates = defaultMaxRefUpdates
	}
	if out.MaxObjects <= 0 {
		out.MaxObjects = defaultMaxObjects
	}
	if out.MaxInflatedObjectBytes <= 0 {
		out.MaxInflatedObjectBytes = defaultMaxInflatedObjBytes
	}
	if out.MaxTotalInflatedBytes <= 0 {
		out.MaxTotalInflatedBytes = scaledMaxTotalInflatedBytes(out.MaxInflatedObjectBytes)
	}
	if out.MaxDeltaDepth <= 0 {
		out.MaxDeltaDepth = defaultMaxDeltaDepth
	}
	if out.MaxPathBytes <= 0 {
		out.MaxPathBytes = defaultMaxPathBytes
	}
	if out.MaxPathDepth <= 0 {
		out.MaxPathDepth = defaultMaxPathDepth
	}
	if out.MaxTagDepth <= 0 {
		out.MaxTagDepth = defaultMaxTagDepth
	}
	if out.MaxWorkspaceBytes <= 0 {
		out.MaxWorkspaceBytes = defaultMaxWorkspaceBytes
	}
	if out.MaxDiffBytesPerCommit <= 0 {
		out.MaxDiffBytesPerCommit = defaultMaxDiffBytesPerCommit
	}
	return out, nil
}

func scaledMaxTotalInflatedBytes(maxInflatedObjBytes int64) int64 {
	var calc int64
	if maxInflatedObjBytes > math.MaxInt64/16 {
		calc = math.MaxInt64
	} else {
		calc = maxInflatedObjBytes * 16
	}
	if calc < defaultMinTotalInflatedBytes {
		calc = defaultMinTotalInflatedBytes
	}
	return calc
}

// RefUpdate describes a single Git reference transition supplied by git-receive-pack.
type RefUpdate struct {
	RefName string `json:"ref_name"`
	OldOID  string `json:"old_oid"`
	NewOID  string `json:"new_oid"`
}

// ExistingRefResolver optionally resolves current upstream reference OIDs and baseline roots.
type ExistingRefResolver interface {
	ResolveRef(ctx context.Context, refName string) (oid string, exists bool, err error)
	ListBaselineOIDs(ctx context.Context) ([]string, error)
}

// UnpackerConfig configures QuarantineUnpacker defaults, Git binary, and observability.
type UnpackerConfig struct {
	GitBinary           string
	Timeout             time.Duration
	AllowedRefPrefixes  []string
	DefaultLimits       Limits
	SnapshotStore       domain.SnapshotStore
	AllowTagToNonCommit bool
	Metrics             *observability.Metrics
	Logger              *slog.Logger
}

// UnpackRequest describes an untrusted Git push packfile and its ref updates to quarantine.
type UnpackRequest struct {
	PushSessionID       uuid.UUID
	PackReader          io.Reader
	RefUpdates          []RefUpdate
	LFSObjects          []domain.PushLFSObject
	BaselineRepoDir     string
	ExistingObjectsDir  string
	ExistingRefResolver ExistingRefResolver
	BaselineOIDs        []string
	SnapshotStore       domain.SnapshotStore
	Limits              Limits
}

// ExtractedCommit holds normalized commit metadata and raw message extracted from quarantine.
type ExtractedCommit struct {
	OID            string   `json:"oid"`
	TreeOID        string   `json:"tree_oid"`
	ParentOIDs     []string `json:"parent_oids"`
	AuthorName     string   `json:"author_name,omitempty"`
	AuthorEmail    string   `json:"author_email,omitempty"`
	CommitterName  string   `json:"committer_name,omitempty"`
	CommitterEmail string   `json:"committer_email,omitempty"`
	Message        string   `json:"message"`
}

// ExtractedBlob records an introduced blob OID, size, and associated repo-relative paths.
type ExtractedBlob struct {
	OID       string   `json:"oid"`
	SizeBytes int64    `json:"size_bytes"`
	Paths     []string `json:"paths"`
}

// ExtractedTag records an introduced annotated tag object and its message.
type ExtractedTag struct {
	OID        string `json:"oid"`
	Name       string `json:"name"`
	TargetOID  string `json:"target_oid"`
	TargetType string `json:"target_type"`
	Message    string `json:"message"`
}

// UnpackResult holds the validated quarantine workspace, extracted history, digest, and bundle artifact.
type UnpackResult struct {
	WorkspaceDir       string                 `json:"workspace_dir"`
	RepoDir            string                 `json:"repo_dir"`
	RefUpdates         []RefUpdate            `json:"ref_updates"`
	Commits            []ExtractedCommit      `json:"commits"`
	Trees              []string               `json:"trees"`
	Blobs              []ExtractedBlob        `json:"blobs"`
	Tags               []ExtractedTag         `json:"tags"`
	ChangedPaths       []string               `json:"changed_paths"`
	CommitMessages     []string               `json:"commit_messages"`
	LFSObjects         []domain.PushLFSObject `json:"lfs_objects"`
	PushManifestDigest string                 `json:"push_manifest_digest"`
	Manifest           PushManifest           `json:"manifest"`
	BundleArtifact     *domain.Artifact       `json:"bundle_artifact,omitempty"`
	BundlePath         string                 `json:"bundle_path,omitempty"`
	BundleSHA256       string                 `json:"bundle_sha256,omitempty"`
	BundleSizeBytes    int64                  `json:"bundle_size_bytes"`

	mu             sync.Mutex
	quarantineRoot string
	homeDir        string
	gitBinary      string
	timeout        time.Duration
	excludeOIDs    []string
	closed         bool
}

// NeedsPack reports whether any ref update creates or advances a reference (NewOID != ZeroOID).
func (r *UnpackResult) NeedsPack() bool {
	if r == nil {
		return false
	}
	for _, ru := range r.RefUpdates {
		if ru.NewOID != "" && ru.NewOID != ZeroOID {
			return true
		}
	}
	return false
}

// Close removes all ephemeral quarantine directories and files. It is nil-safe and idempotent.
func (r *UnpackResult) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.quarantineRoot != "" {
		return os.RemoveAll(r.quarantineRoot)
	}
	return nil
}

// QuarantineUnpacker unpacks and validates untrusted Git push packfiles inside an isolated quarantine.
type QuarantineUnpacker struct {
	gitBinary           string
	timeout             time.Duration
	allowedRefPrefixes  []string
	defaultLimits       Limits
	snapshotStore       domain.SnapshotStore
	allowTagToNonCommit bool
	metrics             *observability.Metrics
	logger              *slog.Logger
}
