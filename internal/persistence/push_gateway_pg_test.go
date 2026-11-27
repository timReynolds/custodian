package persistence_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/persistence"
)

func TestPushGatewaySchemaAndConstraintsPG17(t *testing.T) {
	dsn, pool := startPG17ForPersistenceTest(t)
	ctx := context.Background()
	if err := persistence.MigrateUp(ctx, dsn); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	store, err := persistence.NewStore(pool)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("a", 64)
	digest2 := strings.Repeat("b", 64)

	principal, err := store.Upsert(ctx, domain.Principal{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "push-user",
		DisplayName:   "Push User",
		VerifiedEmail: "push@example.com",
	})
	if err != nil {
		t.Fatalf("Upsert principal: %v", err)
	}
	reviewer, err := store.Upsert(ctx, domain.Principal{
		Kind:          domain.PrincipalKindHuman,
		Issuer:        "https://oidc.example",
		Subject:       "reviewer-user",
		DisplayName:   "Reviewer User",
		VerifiedEmail: "reviewer@example.com",
	})
	if err != nil {
		t.Fatalf("Upsert reviewer: %v", err)
	}

	// 1. Repository defaults & non-clobbering upsert.
	repo, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   9001,
		GitHubInstallationID: 77,
		FullName:             "acme/secret-core",
		Classification:       domain.ClassificationRestricted,
		Enabled:              true,
	})
	if err != nil {
		t.Fatalf("UpsertRepository initial: %v", err)
	}
	if repo.EgressMode != domain.EgressModePassiveAudit || !repo.RegisteredDestination || repo.External {
		t.Fatalf("unexpected initial repo defaults: %+v", repo)
	}
	repo, err = store.UpdateRepositoryEgressMode(ctx, repo.ID, domain.EgressModeEnforceBlock, domain.PassiveAuditDeliveryInlineWarn)
	if err != nil {
		t.Fatalf("UpdateRepositoryEgressMode: %v", err)
	}
	if repo.EgressMode != domain.EgressModeEnforceBlock {
		t.Fatalf("expected ENFORCE_BLOCK, got %s", repo.EgressMode)
	}
	// Upsert again without EgressMode must NOT reset ENFORCE_BLOCK back to PASSIVE_AUDIT.
	repoUpserted, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   9001,
		GitHubInstallationID: 77,
		FullName:             "acme/secret-core",
		Classification:       domain.ClassificationRestricted,
		Enabled:              true,
	})
	if err != nil {
		t.Fatalf("UpsertRepository preserve: %v", err)
	}
	if repoUpserted.EgressMode != domain.EgressModeEnforceBlock {
		t.Fatalf("UpsertRepository clobbered egress_mode: got %s", repoUpserted.EgressMode)
	}
	// External: *bool must not clobber existing true when omitted (nil), and must update when explicitly false.
	extTrue := true
	repoExtSet, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   9001,
		GitHubInstallationID: 77,
		FullName:             "acme/secret-core",
		Classification:       domain.ClassificationRestricted,
		Enabled:              true,
		External:             &extTrue,
	})
	if err != nil || !repoExtSet.External {
		t.Fatalf("UpsertRepository set External=true failed: (%+v, %v)", repoExtSet, err)
	}
	repoExtPreserved, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   9001,
		GitHubInstallationID: 77,
		FullName:             "acme/secret-core",
		Classification:       domain.ClassificationRestricted,
		Enabled:              true,
	})
	if err != nil || !repoExtPreserved.External {
		t.Fatalf("UpsertRepository(External: nil) clobbered External=true: (%+v, %v)", repoExtPreserved, err)
	}
	extFalse := false
	repoExtCleared, err := store.UpsertRepository(ctx, persistence.UpsertRepositoryParams{
		GitHubRepositoryID:   9001,
		GitHubInstallationID: 77,
		FullName:             "acme/secret-core",
		Classification:       domain.ClassificationRestricted,
		Enabled:              true,
		External:             &extFalse,
	})
	if err != nil || repoExtCleared.External {
		t.Fatalf("UpsertRepository(External: &false) did not clear External: (%+v, %v)", repoExtCleared, err)
	}

	// 2. GIT_PUSH_BUNDLE artifact + push_session + XOR scan_run / model_assessment / policy_decision.
	bundleArt, err := store.RegisterArtifact(ctx, persistence.RegisterArtifactParams{
		Kind:              domain.ArtifactKindGitPushBundle,
		SHA256:            digest,
		StorageKey:        "pushes/bundle.tar.gz",
		StorageGeneration: "1",
		SizeBytes:         2048,
		Format:            "tar.gz",
		UploadedBy:        &principal.ID,
	})
	if err != nil {
		t.Fatalf("CreateArtifact(GIT_PUSH_BUNDLE): %v", err)
	}

	enforcedFalse := false
	ps, err := store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:           principal.ID,
		RepositoryID:          &repo.ID,
		Destination:           "github.com/acme/secret-core",
		DestinationHost:       "github.com",
		DestinationRegistered: true,
		DestinationExternal:   false,
		Transport:             domain.PushTransportSSH,
		HasLFS:                true,
		LFSObjects:            []domain.PushLFSObject{{OID: digest, Size: 512}},
		LFSObjectCount:        1,
		LFSTotalBytes:         512,
		EgressMode:            domain.EgressModeEnforceBlock,
		Status:                domain.PushSessionStatusReceived,
		CreatedAt:             now,
	})
	if err != nil {
		t.Fatalf("CreatePushSession: %v", err)
	}
	if !ps.Enforced || !ps.HasLFS || ps.LFSObjectCount != 1 {
		t.Fatalf("unexpected push session: %+v", ps)
	}

	ps, err = store.UpdatePushSessionUnpack(ctx, persistence.UpdatePushSessionUnpackParams{
		ID:                 ps.ID,
		PushManifestDigest: digest,
		BundleArtifactID:   &bundleArt.ID,
		RefUpdates:         []domain.PushRefUpdate{{RefName: "refs/heads/main", OldOID: strings.Repeat("0", 40), NewOID: strings.Repeat("1", 40)}},
		Status:             domain.PushSessionStatusQuarantined,
		UpdatedAt:          now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("UpdatePushSessionUnpack: %v", err)
	}

	sr, err := store.CreateScanRun(ctx, persistence.CreateScanRunParams{
		PushSessionID:  &ps.ID,
		ArtifactID:     bundleArt.ID,
		Scanner:        "ip_fingerprint",
		ScannerVersion: "1.0.0",
		Status:         domain.ScanStatusCompleted,
		Coverage:       domain.ScanCoverage{FilesExamined: 3, FilesSkipped: 0, Complete: true},
		StartedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreateScanRun for push session: %v", err)
	}
	if sr.PushSessionID == nil || *sr.PushSessionID != ps.ID {
		t.Fatalf("unexpected scan run push_session_id: %+v", sr)
	}

	ma, err := store.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
		PushSessionID:  &ps.ID,
		ArtifactID:     bundleArt.ID,
		ModelRoute:     "not-required",
		ModelVersion:   "not-required",
		PromptVersion:  "not-required",
		AssessmentType: "IP_PROVENANCE",
		Status:         domain.AssessmentStatusNotRequired,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionNotRequired,
		Result: domain.AssessmentResult{
			SchemaVersion:  "1.0",
			AssessmentType: "IP_PROVENANCE",
			Risk:           domain.RiskLevelNone,
			Disposition:    domain.DispositionNotRequired,
			Confidence:     1.0,
			Summary:        "Stage B not triggered",
		},
		InputDigest:  digest,
		OutputDigest: digest,
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("CreateModelAssessment(NOT_REQUIRED): %v", err)
	}
	if ma.Status != domain.AssessmentStatusNotRequired || !ma.ToDomain().AllowsPushEgress() || !ma.ToDomain().BlocksPublication() {
		t.Fatalf("unexpected NOT_REQUIRED assessment behavior: %+v", ma)
	}

	pb, err := store.CreatePolicyBundle(ctx, persistence.CreatePolicyBundleParams{
		Name:       "push-ip-protection",
		Version:    "1.0.0",
		Scope:      domain.PolicyScopeOrg,
		Digest:     digest,
		Definition: json.RawMessage(`{"rules":[]}`),
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("CreatePolicyBundle: %v", err)
	}

	dec, err := store.CreatePolicyDecision(ctx, persistence.CreatePolicyDecisionParams{
		PushSessionID:  &ps.ID,
		PolicyBundleID: pb.ID,
		Stage:          "PUSH_EGRESS",
		Enforced:       &enforcedFalse,
		InputDigest:    digest,
		Effect:         domain.PolicyEffectRequireApproval,
		CreatedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreatePolicyDecision(PUSH_EGRESS): %v", err)
	}
	if dec.Stage != "PUSH_EGRESS" || dec.Enforced {
		t.Fatalf("unexpected policy decision: %+v", dec)
	}

	// 3. PushApprovalRelease: SoD, expiry, single-use consume, replay rejection.
	rel, err := store.CreatePushApprovalRelease(ctx, persistence.CreatePushApprovalReleaseParams{
		PrincipalID:        principal.ID,
		ApprovedBy:         reviewer.ID,
		Destination:        "github.com/acme/secret-core",
		PushManifestDigest: digest,
		PushSessionID:      ps.ID,
		PolicyDecisionID:   dec.ID,
		Reason:             "approved for partner sync",
		ExpiresAt:          now.Add(10 * time.Minute),
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatalf("CreatePushApprovalRelease: %v", err)
	}

	ps2, err := store.CreatePushSession(ctx, persistence.CreatePushSessionParams{
		PrincipalID:        principal.ID,
		RepositoryID:       &repo.ID,
		Destination:        "github.com/acme/secret-core",
		DestinationHost:    "github.com",
		PushManifestDigest: digest,
		EgressMode:         domain.EgressModeEnforceBlock,
		Status:             domain.PushSessionStatusReceived,
		CreatedAt:          now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatalf("CreatePushSession ps2: %v", err)
	}

	// Wrong digest fails NotFound.
	_, err = store.ConsumePushApprovalRelease(ctx, persistence.ConsumePushApprovalReleaseParams{
		PrincipalID:             principal.ID,
		Destination:             "github.com/acme/secret-core",
		PushManifestDigest:      digest2,
		ConsumedAt:              now.Add(3 * time.Second),
		ConsumedByPushSessionID: ps2.ID,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("wrong digest expected ErrNotFound, got %v", err)
	}

	// Expired fails NotFound.
	_, err = store.ConsumePushApprovalRelease(ctx, persistence.ConsumePushApprovalReleaseParams{
		PrincipalID:             principal.ID,
		Destination:             "github.com/acme/secret-core",
		PushManifestDigest:      digest,
		ConsumedAt:              now.Add(15 * time.Minute),
		ConsumedByPushSessionID: ps2.ID,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expired consume expected ErrNotFound, got %v", err)
	}

	// Valid consume succeeds once.
	consumed, err := store.ConsumePushApprovalRelease(ctx, persistence.ConsumePushApprovalReleaseParams{
		PrincipalID:             principal.ID,
		Destination:             "github.com/acme/secret-core",
		PushManifestDigest:      digest,
		ConsumedAt:              now.Add(3 * time.Second),
		ConsumedByPushSessionID: ps2.ID,
	})
	if err != nil || consumed.ID != rel.ID || consumed.ConsumedAt == nil {
		t.Fatalf("valid ConsumePushApprovalRelease failed: (%+v, %v)", consumed, err)
	}

	// Replay fails NotFound.
	_, err = store.ConsumePushApprovalRelease(ctx, persistence.ConsumePushApprovalReleaseParams{
		PrincipalID:             principal.ID,
		Destination:             "github.com/acme/secret-core",
		PushManifestDigest:      digest,
		ConsumedAt:              now.Add(4 * time.Second),
		ConsumedByPushSessionID: ps2.ID,
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("replay consume expected ErrNotFound, got %v", err)
	}

	// 4. IP Fingerprint Corpus & Lookup.
	corpus, err := store.CreateIPFingerprintCorpus(ctx, persistence.CreateIPFingerprintCorpusParams{
		Name:           "core-algo",
		Classification: domain.ClassificationRestricted,
		RepositoryID:   &repo.ID,
		Status:         domain.IPCorpusStatusReady,
		CreatedAt:      now,
	})
	if err != nil {
		t.Fatalf("CreateIPFingerprintCorpus: %v", err)
	}
	inserted, err := store.UpsertIPFingerprintsBatch(ctx, []persistence.InsertIPFingerprintParams{
		{
			CorpusID:        corpus.ID,
			Layer:           domain.FingerprintLayerL1ExactChunk,
			FingerprintHash: digest,
			FilePathHash:    digest2,
			Language:        "go",
			Metadata:        map[string]any{"chunk_bytes": 4096},
		},
	})
	if err != nil || inserted != 1 {
		t.Fatalf("UpsertIPFingerprintsBatch = (%d, %v)", inserted, err)
	}
	matches, err := store.LookupIPFingerprintsByHashes(ctx, domain.FingerprintLayerL1ExactChunk, []string{digest})
	if err != nil || len(matches) != 1 || matches[0].CorpusName != "core-algo" {
		t.Fatalf("LookupIPFingerprintsByHashes = (%+v, %v)", matches, err)
	}

	// 5. Verify MigrateDown -> MigrateUp cleanly handles push rows!
	if err := persistence.MigrateDownPool(ctx, pool); err != nil {
		t.Fatalf("MigrateDownPool with push rows present: %v", err)
	}
	if err := persistence.MigrateUpPool(ctx, pool); err != nil {
		t.Fatalf("MigrateUpPool after down: %v", err)
	}
}
