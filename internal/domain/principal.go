package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type PrincipalKind string

const (
	PrincipalKindHuman   PrincipalKind = "HUMAN"
	PrincipalKindAgent   PrincipalKind = "AGENT"
	PrincipalKindService PrincipalKind = "SERVICE"
)

func (k PrincipalKind) IsValid() bool {
	switch k {
	case PrincipalKindHuman, PrincipalKindAgent, PrincipalKindService:
		return true
	default:
		return false
	}
}

type Principal struct {
	ID            uuid.UUID     `json:"id"`
	Kind          PrincipalKind `json:"kind"`
	Issuer        string        `json:"issuer,omitempty"`
	Subject       string        `json:"subject,omitempty"`
	DisplayName   string        `json:"display_name,omitempty"`
	VerifiedEmail string        `json:"verified_email,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

// GitAuthor returns the accountable human Git author identity.
// Only HUMAN principals with a verified email may serve as Git commit authors.
func (p Principal) GitAuthor() (name, email string, err error) {
	if p.Kind != PrincipalKindHuman {
		return "", "", Forbidden("NON_HUMAN_AUTHOR", "only verified human principals can author published commits")
	}
	email = strings.TrimSpace(p.VerifiedEmail)
	if email == "" {
		return "", "", Unprocessable("MISSING_VERIFIED_EMAIL", "human principal lacks a verified email")
	}
	name = strings.TrimSpace(p.DisplayName)
	if name == "" {
		name = email
	}
	return name, email, nil
}
