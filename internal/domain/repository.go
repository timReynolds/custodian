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

type EgressMode string

const (
	EgressModePassiveAudit EgressMode = "PASSIVE_AUDIT"
	EgressModeEnforceBlock EgressMode = "ENFORCE_BLOCK"
	EgressModeEnforcePR    EgressMode = "ENFORCE_PR"
)

func (m EgressMode) IsValid() bool {
	switch m {
	case EgressModePassiveAudit, EgressModeEnforceBlock, EgressModeEnforcePR:
		return true
	default:
		return false
	}
}

type PassiveAuditDelivery string

const (
	PassiveAuditDeliveryAsync      PassiveAuditDelivery = "ASYNC"
	PassiveAuditDeliveryInlineWarn PassiveAuditDelivery = "INLINE_WARN"
)

func (d PassiveAuditDelivery) IsValid() bool {
	switch d {
	case PassiveAuditDeliveryAsync, PassiveAuditDeliveryInlineWarn:
		return true
	default:
		return false
	}
}

type Repository struct {
	ID                    uuid.UUID            `json:"id"`
	GitHubRepositoryID    int64                `json:"github_repository_id"`
	GitHubInstallationID  int64                `json:"github_installation_id"`
	FullName              string               `json:"full_name"` // "owner/repo"
	Classification        Classification       `json:"classification"`
	Enabled               bool                 `json:"enabled"`
	EgressMode            EgressMode           `json:"egress_mode,omitempty"`
	PassiveAuditDelivery  PassiveAuditDelivery `json:"passive_audit_delivery,omitempty"`
	GitRemoteURL          string               `json:"git_remote_url,omitempty"`
	RemoteHost            string               `json:"remote_host,omitempty"`
	RegisteredDestination bool                 `json:"registered_destination"`
	External              bool                 `json:"external"`
}

// OwnerRepo splits FullName ("owner/repo") into owner and repository name.
func (r Repository) OwnerRepo() (owner, name string, err error) {
	parts := strings.Split(strings.TrimSpace(r.FullName), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", BadRequest("INVALID_REPOSITORY_NAME", "repository full_name must be owner/repo")
	}
	return parts[0], parts[1], nil
}
