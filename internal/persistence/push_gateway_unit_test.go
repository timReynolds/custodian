package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestValidatePolicyStage_AllowsPushEgress(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", "EGRESS"},
		{"INGRESS", "INGRESS"},
		{"EGRESS", "EGRESS"},
		{"PUSH_EGRESS", "PUSH_EGRESS"},
	} {
		got, err := validatePolicyStage(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("validatePolicyStage(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}
	if _, err := validatePolicyStage("UNKNOWN"); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid stage, got %v", err)
	}
}

func TestRepositoryNormalizationDefaults(t *testing.T) {
	t.Parallel()

	norm, err := validateAndNormalizeRepoArgs(UpsertRepositoryParams{
		GitHubRepositoryID:   1,
		GitHubInstallationID: 2,
		FullName:             "acme/app",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
	})
	if err != nil {
		t.Fatalf("validateAndNormalizeRepoArgs: %v", err)
	}
	if norm.egressMode != domain.EgressModePassiveAudit || norm.setEgressMode {
		t.Fatalf("expected default PASSIVE_AUDIT with setEgressMode=false, got (%s, %v)", norm.egressMode, norm.setEgressMode)
	}
	if norm.delivery != domain.PassiveAuditDeliveryAsync || norm.setDelivery {
		t.Fatalf("expected default ASYNC delivery with setDelivery=false, got (%s, %v)", norm.delivery, norm.setDelivery)
	}
	if !norm.registered || norm.setRegistered {
		t.Fatalf("expected default RegisteredDestination=true with setRegistered=false, got (%v, %v)", norm.registered, norm.setRegistered)
	}
	if norm.external || norm.setExternal {
		t.Fatalf("expected default External=false with setExternal=false, got (%v, %v)", norm.external, norm.setExternal)
	}
	if norm.remoteHost != "github.com" || norm.setRemoteHost {
		t.Fatalf("expected default RemoteHost=github.com with setRemoteHost=false, got (%q, %v)", norm.remoteHost, norm.setRemoteHost)
	}

	regFalse := false
	extTrue := true
	normExplicit, err := validateAndNormalizeRepoArgs(UpsertRepositoryParams{
		GitHubRepositoryID:    1,
		GitHubInstallationID:  2,
		FullName:              "acme/app",
		Classification:        domain.ClassificationRestricted,
		Enabled:               true,
		EgressMode:            domain.EgressModeEnforceBlock,
		PassiveAuditDelivery:  domain.PassiveAuditDeliveryInlineWarn,
		RemoteHost:            "git.internal",
		RegisteredDestination: &regFalse,
		External:              &extTrue,
	})
	if err != nil {
		t.Fatalf("explicit validateAndNormalizeRepoArgs: %v", err)
	}
	if normExplicit.egressMode != domain.EgressModeEnforceBlock || !normExplicit.setEgressMode {
		t.Fatalf("unexpected explicit egress mode: %+v", normExplicit)
	}
	if normExplicit.registered || !normExplicit.setRegistered {
		t.Fatalf("unexpected explicit registered_destination: %+v", normExplicit)
	}
	if !normExplicit.external || !normExplicit.setExternal {
		t.Fatalf("unexpected explicit external: %+v", normExplicit)
	}
}

func TestOwnerXORValidationWithoutDB(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	q := &Queries{}
	id := domain.MustNewID()
	pushID := domain.MustNewID()
	digest := strings.Repeat("a", 64)

	// ScanRun: neither owner nor both owners
	if _, err := q.CreateScanRun(ctx, CreateScanRunParams{ArtifactID: id, Scanner: "gitleaks", ScannerVersion: "1.0"}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CreateScanRun neither owner expected ErrBadRequest, got %v", err)
	}
	if _, err := q.CreateScanRun(ctx, CreateScanRunParams{ProposalID: id, PushSessionID: &pushID, ArtifactID: id, Scanner: "gitleaks", ScannerVersion: "1.0"}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CreateScanRun both owners expected ErrBadRequest, got %v", err)
	}

	// ModelAssessment: neither owner nor both owners
	if _, err := q.CreateModelAssessment(ctx, CreateModelAssessmentParams{
		ArtifactID: id, ModelRoute: "r", ModelVersion: "1", PromptVersion: "1", AssessmentType: "IP_PROVENANCE",
		InputDigest: digest, OutputDigest: digest,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CreateModelAssessment neither owner expected ErrBadRequest, got %v", err)
	}
	if _, err := q.CreateModelAssessment(ctx, CreateModelAssessmentParams{
		ProposalID: id, PushSessionID: &pushID, ArtifactID: id, ModelRoute: "r", ModelVersion: "1", PromptVersion: "1", AssessmentType: "IP_PROVENANCE",
		InputDigest: digest, OutputDigest: digest,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CreateModelAssessment both owners expected ErrBadRequest, got %v", err)
	}

	// PolicyDecision: neither owner nor both owners
	if _, err := q.CreatePolicyDecision(ctx, CreatePolicyDecisionParams{
		PolicyBundleID: id, InputDigest: digest, Effect: domain.PolicyEffectAllow,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CreatePolicyDecision neither owner expected ErrBadRequest, got %v", err)
	}
	if _, err := q.CreatePolicyDecision(ctx, CreatePolicyDecisionParams{
		ProposalID: id, PushSessionID: &pushID, PolicyBundleID: id, InputDigest: digest, Effect: domain.PolicyEffectAllow,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("CreatePolicyDecision both owners expected ErrBadRequest, got %v", err)
	}
}

func TestPushApprovalReleaseAndIPFingerprintValidationWithoutDB(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	q := &Queries{}
	principalID := domain.MustNewID()
	sessionID := domain.MustNewID()
	decisionID := domain.MustNewID()
	now := time.Now().UTC()
	digest := strings.Repeat("a", 64)

	// Self-approval fails SoD before hitting DB.
	_, err := q.CreatePushApprovalRelease(ctx, CreatePushApprovalReleaseParams{
		PrincipalID:        principalID,
		ApprovedBy:         principalID,
		Destination:        "github.com/acme/repo",
		PushManifestDigest: digest,
		PushSessionID:      sessionID,
		PolicyDecisionID:   decisionID,
		ExpiresAt:          now.Add(time.Hour),
		CreatedAt:          now,
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-approval expected ErrForbidden, got %v", err)
	}

	// Expiry <= createdAt fails before hitting DB.
	_, err = q.CreatePushApprovalRelease(ctx, CreatePushApprovalReleaseParams{
		PrincipalID:        principalID,
		ApprovedBy:         domain.MustNewID(),
		Destination:        "github.com/acme/repo",
		PushManifestDigest: digest,
		PushSessionID:      sessionID,
		PolicyDecisionID:   decisionID,
		ExpiresAt:          now,
		CreatedAt:          now,
	})
	if !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("non-future expiry expected ErrBadRequest, got %v", err)
	}

	// IP fingerprint rejects raw source metadata and short/non-hex hashes.
	corpusID := domain.MustNewID()
	if _, err := q.InsertIPFingerprint(ctx, InsertIPFingerprintParams{
		CorpusID:        corpusID,
		Layer:           domain.FingerprintLayerL1ExactChunk,
		FingerprintHash: "deadbeef", // < 16 hex chars
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("short fingerprint hash expected ErrBadRequest, got %v", err)
	}
	if _, err := q.InsertIPFingerprint(ctx, InsertIPFingerprintParams{
		CorpusID:        corpusID,
		Layer:           domain.FingerprintLayerL1ExactChunk,
		FingerprintHash: strings.Repeat("a", 64),
		Metadata:        map[string]any{"raw_source": "func secret() {}"},
	}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("raw_source metadata expected ErrUnprocessable, got %v", err)
	}
	if _, err := q.UpsertIPFingerprintsBatch(ctx, []InsertIPFingerprintParams{{
		CorpusID:        corpusID,
		Layer:           domain.FingerprintLayerL2WinnowKGram,
		FingerprintHash: strings.Repeat("b", 16),
		Metadata:        map[string]any{"nested": map[string]any{"snippet": "leaked"}},
	}}); !errors.Is(err, domain.ErrUnprocessable) {
		t.Fatalf("batch snippet metadata expected ErrUnprocessable, got %v", err)
	}
}

func TestPushRowsToDomainConversions(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Microsecond)
	pushID := domain.MustNewID()
	decID := domain.MustNewID()
	bundleID := domain.MustNewID()

	decRow := PolicyDecisionRow{
		ID:             decID,
		ProposalID:     uuid.Nil,
		PushSessionID:  &pushID,
		PolicyBundleID: bundleID,
		Stage:          "PUSH_EGRESS",
		Enforced:       false,
		InputDigest:    strings.Repeat("c", 64),
		Effect:         domain.PolicyEffectDeny,
		Reasons:        json.RawMessage(`[{"rule_id":"push.destination","effect":"DENY","stage":"PUSH_EGRESS"}]`),
		Obligations:    json.RawMessage(`[]`),
		CreatedAt:      now,
	}
	domDec := decRow.ToDomain()
	if domDec.Stage != domain.PolicyStagePushEgress || domDec.Enforced || domDec.PushSessionID == nil || *domDec.PushSessionID != pushID {
		t.Fatalf("unexpected PolicyDecisionRow.ToDomain: %+v", domDec)
	}
}
