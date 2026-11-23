package domain

import (
	"strings"

	"github.com/google/uuid"
)

type Classification string

const (
	ClassificationPublic       Classification = "PUBLIC"
	ClassificationInternal     Classification = "INTERNAL"
	ClassificationConfidential Classification = "CONFIDENTIAL"
	ClassificationRestricted   Classification = "RESTRICTED"
)

func (c Classification) IsValid() bool {
	switch c {
	case ClassificationPublic, ClassificationInternal, ClassificationConfidential, ClassificationRestricted:
		return true
	default:
		return false
	}
}

type Repository struct {
	ID                   uuid.UUID      `json:"id"`
	GitHubRepositoryID   int64          `json:"github_repository_id"`
	GitHubInstallationID int64          `json:"github_installation_id"`
	FullName             string         `json:"full_name"` // "owner/repo"
	Classification       Classification `json:"classification"`
	Enabled              bool           `json:"enabled"`
}

// OwnerRepo splits FullName ("owner/repo") into owner and repository name.
func (r Repository) OwnerRepo() (owner, name string, err error) {
	parts := strings.Split(strings.TrimSpace(r.FullName), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", BadRequest("INVALID_REPOSITORY_NAME", "repository full_name must be owner/repo")
	}
	return parts[0], parts[1], nil
}
