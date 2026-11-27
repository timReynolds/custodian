package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type PolicyScope string

const (
	PolicyScopeOrg  PolicyScope = "ORG"
	PolicyScopeRepo PolicyScope = "REPO"
)

func (s PolicyScope) IsValid() bool {
	switch s {
	case PolicyScopeOrg, PolicyScopeRepo:
		return true
	default:
		return false
	}
}

type PolicyStage string

const (
	PolicyStageIngress    PolicyStage = "INGRESS"
	PolicyStageEgress     PolicyStage = "EGRESS"
	PolicyStagePushEgress PolicyStage = "PUSH_EGRESS"
)

func (s PolicyStage) IsValid() bool {
	switch s {
	case PolicyStageIngress, PolicyStageEgress, PolicyStagePushEgress:
		return true
	default:
		return false
	}
}

type PolicyEffect string

const (
	PolicyEffectDeny               PolicyEffect = "DENY"
	PolicyEffectQuarantine         PolicyEffect = "QUARANTINE"
	PolicyEffectRequireRemediation PolicyEffect = "REQUIRE_REMEDIATION"
	PolicyEffectRequireApproval    PolicyEffect = "REQUIRE_APPROVAL"
	PolicyEffectAllow              PolicyEffect = "ALLOW"
)

func (e PolicyEffect) IsValid() bool {
	switch e {
	case PolicyEffectDeny,
		PolicyEffectQuarantine,
		PolicyEffectRequireRemediation,
		PolicyEffectRequireApproval,
		PolicyEffectAllow:
		return true
	default:
		return false
	}
}

// Rank orders effects from least restrictive (ALLOW=1) to most restrictive (DENY=5).
// Unknown effects fail closed with the highest restrictiveness rank.
func (e PolicyEffect) Rank() int {
	switch e {
	case PolicyEffectAllow:
		return 1
	case PolicyEffectRequireApproval:
		return 2
	case PolicyEffectRequireRemediation:
		return 3
	case PolicyEffectQuarantine:
		return 4
	case PolicyEffectDeny:
		return 5
	default:
		return 5
	}
}

func (e PolicyEffect) BlocksPublication() bool {
	return e == PolicyEffectDeny || e == PolicyEffectQuarantine || e == PolicyEffectRequireRemediation || !e.IsValid()
}

// MoreRestrictive enforces DENY > QUARANTINE > REQUIRE_REMEDIATION > REQUIRE_APPROVAL > ALLOW,
// failing closed to DENY on any invalid effect.
func (e PolicyEffect) MoreRestrictive(other PolicyEffect) PolicyEffect {
	if !e.IsValid() || !other.IsValid() {
		return PolicyEffectDeny
	}
	if other.Rank() > e.Rank() {
		return other
	}
	return e
}

type Obligation struct {
	Type          string `json:"type"`
	ReviewerGroup string `json:"reviewer_group"`
	Minimum       int    `json:"minimum"`
}

type PolicyReason struct {
	RuleID  string       `json:"rule_id"`
	Effect  PolicyEffect `json:"effect"`
	Stage   string       `json:"stage,omitempty"`
	Message string       `json:"message,omitempty"`
}

type PolicyBundle struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Scope       PolicyScope     `json:"scope"`
	Digest      string          `json:"digest"`
	Definition  json.RawMessage `json:"definition"`
	ActivatedAt *time.Time      `json:"activated_at,omitempty"`
}

type PolicyDecision struct {
	ID             uuid.UUID      `json:"id"`
	ProposalID     uuid.UUID      `json:"proposal_id"`
	PushSessionID  *uuid.UUID     `json:"push_session_id,omitempty"`
	PolicyBundleID uuid.UUID      `json:"policy_bundle_id"`
	Stage          PolicyStage    `json:"stage,omitempty"`
	Enforced       bool           `json:"enforced"`
	InputDigest    string         `json:"input_digest"`
	Effect         PolicyEffect   `json:"effect"`
	Reasons        []PolicyReason `json:"reasons"`
	Obligations    []Obligation   `json:"obligations"`
	CreatedAt      time.Time      `json:"created_at"`
}
