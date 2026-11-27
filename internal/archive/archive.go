package archive

import (
	"bytes"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	FormatTarGz           = "tar.gz"
	ManifestSchemaVersion = "1"
)

// EpochTime is the fixed UTC epoch timestamp used for deterministic tar and gzip headers.
var EpochTime = time.Unix(0, 0).UTC()

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`x-access-token:[^\s@'"]+`),
	regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{8,}`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`https?://[^/\s:@]+:[^/\s@]+@`),
}

// ManifestFileEntry describes one regular file recorded in SourceManifest.
type ManifestFileEntry struct {
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// SourceManifest captures the canonical, deterministic metadata for an ingress workspace archive.
type SourceManifest struct {
	SchemaVersion      string              `json:"schema_version"`
	WorkspaceID        *uuid.UUID          `json:"workspace_id,omitempty"`
	RepositoryID       *uuid.UUID          `json:"repository_id,omitempty"`
	GitHubRepositoryID int64               `json:"github_repository_id,omitempty"`
	RepositoryFullName string              `json:"repository_full_name,omitempty"`
	CommitSHA          string              `json:"commit_sha"`
	TargetRef          string              `json:"target_ref,omitempty"`
	Format             string              `json:"format"`
	IncludeGitMetadata bool                `json:"include_git_metadata"`
	IncludeHistory     bool                `json:"include_history"`
	FileCount          int                 `json:"file_count"`
	TotalBytes         int64               `json:"total_bytes"`
	ArchiveSHA256      string              `json:"archive_sha256"`
	ArchiveSizeBytes   int64               `json:"archive_size_bytes"`
	Files              []ManifestFileEntry `json:"files"`
}

// ValidateArchiveRelPath normalizes rel to a POSIX relative path and rejects traversal or unsafe chars.
func ValidateArchiveRelPath(rel string) (string, error) {
	if rel == "" {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path must not be empty")
	}
	if strings.ContainsRune(rel, '\x00') || strings.Contains(rel, "\\") {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path contains illegal characters")
	}
	if hasVolumeOrDrivePrefix(rel) {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path must not include a volume name")
	}
	slashed := filepath.ToSlash(rel)
	if strings.HasPrefix(slashed, "/") {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path must be relative")
	}
	if hasVolumeOrDrivePrefix(slashed) {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path must not include a volume name")
	}
	for _, seg := range strings.Split(slashed, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path contains traversal or empty segments")
		}
	}
	clean := path.Clean(slashed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path is unsafe")
	}
	if hasVolumeOrDrivePrefix(clean) {
		return "", domain.Unprocessable("UNSAFE_ARCHIVE_PATH", "archive path must not include a volume name")
	}
	return clean, nil
}

// ScanForCredentials rejects any explicit forbidden secret or known credential marker in data.
func ScanForCredentials(data []byte, extraSecrets []string) error {
	for _, secret := range extraSecrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(data, []byte(secret)) {
			return domain.Forbidden("CREDENTIAL_LEAK_DETECTED", "forbidden credential material detected in artifact metadata")
		}
	}
	for _, pat := range credentialPatterns {
		if pat.Match(data) {
			return domain.Forbidden("CREDENTIAL_LEAK_DETECTED", "credential pattern detected in artifact metadata")
		}
	}
	return nil
}
