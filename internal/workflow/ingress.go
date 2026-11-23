package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/policy"
)

// IngressResult records the outcome of a WORKSPACE_INGRESS operation.
type IngressResult struct {
	WorkspaceID      uuid.UUID `json:"workspace_id"`
	SourceArtifactID uuid.UUID `json:"source_artifact_id"`
	SHA256           string    `json:"sha256"`
	SizeBytes        int64     `json:"size_bytes"`
	Status           string    `json:"status"`
	Idempotent       bool      `json:"idempotent,omitempty"`
}

type ingressBlockedError struct {
	workspaceID    uuid.UUID
	effect         domain.PolicyEffect
	bundleDigest   string
	matchedRuleIDs []string
	err            *domain.DomainError
}

func (e *ingressBlockedError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *ingressBlockedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// ExecuteIngress runs the WORKSPACE_INGRESS workflow for the given operation.
func (s *Service) ExecuteIngress(ctx context.Context, op operations.OperationDetails) (IngressResult, error) {
	ctx = s.ensureOperationLeaseContext(ctx, op)
	res, err := s.executeIngress(ctx, op)
	if err != nil {
		var blocked *ingressBlockedError
		if errors.As(err, &blocked) && s.canRecordDirectIngressBlock(ctx, op) {
			_ = s.recordIngressBlocked(ctx, blocked.workspaceID, blocked.effect, blocked.bundleDigest, blocked.matchedRuleIDs)
		}
		return res, err
	}
	return res, nil
}

func (s *Service) canRecordDirectIngressBlock(ctx context.Context, op operations.OperationDetails) bool {
	if s == nil || s.ops == nil || op.ID == uuid.Nil {
		return true
	}
	cur, err := s.ops.GetDetails(ctx, op.ID)
	if err != nil {
		return op.LeasedBy == "" && errors.Is(err, domain.ErrNotFound)
	}
	if op.LeasedBy != "" {
		return cur.Status == domain.OperationStatusRunning &&
			cur.LeasedBy == op.LeasedBy &&
			(op.Attempts == 0 || cur.Attempts == op.Attempts) &&
			(cur.LeaseUntil == nil || cur.LeaseUntil.After(s.now()))
	}
	return cur.Status != domain.OperationStatusRunning || cur.LeasedBy == ""
}

func (s *Service) executeIngress(ctx context.Context, op operations.OperationDetails) (IngressResult, error) {
	ctx = s.ensureOperationLeaseContext(ctx, op)
	if s == nil || s.workspaces == nil || s.repositories == nil || s.artifacts == nil {
		return IngressResult{}, domain.Unavailable("WORKFLOW_UNAVAILABLE", "workflow service dependencies are not configured")
	}
	if s.gitReader == nil {
		return IngressResult{}, domain.Unavailable("GIT_READER_UNAVAILABLE", "git reader is not configured")
	}
	if s.snapshotStore == nil {
		return IngressResult{}, domain.Unavailable("STORAGE_UNAVAILABLE", "snapshot store is not configured")
	}
	if s.inspector == nil {
		return IngressResult{}, domain.Unavailable("INSPECTOR_UNAVAILABLE", "inspection runner is not configured")
	}

	wsDetails, err := s.workspaces.GetDetails(ctx, op.ResourceID)
	if err != nil {
		return IngressResult{}, err
	}
	if wsDetails.Status == domain.WorkspaceStatusReady && wsDetails.SourceArtifactID != nil {
		var sha string
		var size int64
		if art, artErr := s.artifacts.GetByID(ctx, *wsDetails.SourceArtifactID); artErr == nil {
			sha = art.SHA256
			size = art.SizeBytes
		}
		return IngressResult{
			WorkspaceID:      wsDetails.ID,
			SourceArtifactID: *wsDetails.SourceArtifactID,
			SHA256:           sha,
			SizeBytes:        size,
			Status:           string(wsDetails.Status),
			Idempotent:       true,
		}, nil
	}
	if wsDetails.Status.IsTerminal() {
		return IngressResult{}, domain.Conflict("WORKSPACE_TERMINAL", "workspace is already in a terminal status")
	}

	releaseRepo, err := s.budgets.AcquireRepo(ctx, wsDetails.RepositoryID)
	if err != nil {
		return IngressResult{}, err
	}
	defer releaseRepo()

	repoRec, err := s.repositories.Authorize(ctx, wsDetails.RepositoryID, wsDetails.ModelRoute)
	if err != nil {
		return IngressResult{}, err
	}

	if wsDetails.Status == domain.WorkspaceStatusPending {
		if _, err := s.workspaces.TransitionStatus(ctx, wsDetails.ID, domain.WorkspaceStatusPending, domain.WorkspaceStatusPreparing); err != nil {
			if !errors.Is(err, domain.ErrConflict) || isLeaseLostError(err) {
				return IngressResult{}, err
			}
			// Re-read in case another attempt already transitioned to PREPARING or terminal.
			wsDetails, err = s.workspaces.GetDetails(ctx, op.ResourceID)
			if err != nil {
				return IngressResult{}, err
			}
			if wsDetails.Status == domain.WorkspaceStatusReady && wsDetails.SourceArtifactID != nil {
				return IngressResult{
					WorkspaceID:      wsDetails.ID,
					SourceArtifactID: *wsDetails.SourceArtifactID,
					Status:           string(wsDetails.Status),
					Idempotent:       true,
				}, nil
			}
			if wsDetails.Status.IsTerminal() {
				return IngressResult{}, domain.Conflict("WORKSPACE_TERMINAL", "workspace is already in a terminal status")
			}
		}
	}

	chk, err := s.gitReader.Checkout(ctx, repoRec.Repository, wsDetails.BaseCommit, domain.CheckoutOptions{
		IncludeGitMetadata: wsDetails.SourceOptions.IncludeGitMetadata,
		IncludeHistory:     wsDetails.SourceOptions.IncludeHistory,
	})
	if err != nil {
		return IngressResult{}, err
	}
	if chk.WorkDir != "" {
		defer os.RemoveAll(chk.WorkDir)
	}

	// Run ingress Stage A inspection + Stage C INGRESS policy evaluation (in-memory; scan_runs FKs proposals).
	orgBundles, repoBundles, err := s.resolveActivePolicyBundles(ctx, repoRec.ID)
	if err != nil {
		return IngressResult{}, err
	}
	inspCfg := composeInspectionConfigAll(orgBundles, repoBundles)

	releaseScan, err := s.budgets.AcquireScan(ctx)
	if err != nil {
		return IngressResult{}, err
	}
	report, inspectErr := s.inspector.Inspect(ctx, inspection.Request{
		ProposalID:        wsDetails.ID,
		ArtifactID:        wsDetails.ID,
		TargetDir:         chk.WorkDir,
		Classification:    repoRec.Classification,
		Stage:             inspection.StageIngress,
		MandatoryScanners: inspCfg.Mandatory,
	})
	releaseScan()
	if inspectErr != nil {
		return IngressResult{}, inspectErr
	}

	summary := enforceMandatoryScanners(report.Summary, report.ScanRuns, inspCfg.Mandatory)
	ownerRow, ownerErr := s.store.GetPrincipalByID(ctx, wsDetails.OwnerID)
	var owner domain.Principal
	var ownerGroups []string
	if ownerErr == nil {
		owner = ownerRow.ToDomain()
		ownerGroups = ownerRow.Groups
	} else {
		owner = domain.Principal{
			ID:          wsDetails.OwnerID,
			Kind:        domain.PrincipalKindHuman,
			Issuer:      wsDetails.Owner.IdentityProvider,
			DisplayName: wsDetails.Owner.DisplayName,
		}
	}

	pInput := buildIngressPolicyInput(wsDetails, repoRec, owner, ownerGroups, summary)
	outcome, evalErr := s.evaluateComposedBundles(ctx, orgBundles, repoBundles, policy.StageIngress, pInput)
	if evalErr != nil {
		return IngressResult{}, evalErr
	}

	explicitBlock := outcome.result.Effect.BlocksPublication() &&
		(len(outcome.result.MatchedRuleIDs) > 0 || outcome.result.HadError || hasIngressAllowRule(orgBundles, repoBundles))
	hardFail := !summary.ScanComplete || summary.CriticalSecrets > 0 || summary.ProhibitedLicenses > 0

	if explicitBlock || hardFail {
		blockEffect := outcome.result.Effect
		if !blockEffect.BlocksPublication() {
			blockEffect = domain.PolicyEffectDeny
		}
		return IngressResult{}, &ingressBlockedError{
			workspaceID:    wsDetails.ID,
			effect:         blockEffect,
			bundleDigest:   outcome.result.BundleDigest,
			matchedRuleIDs: append([]string(nil), outcome.result.MatchedRuleIDs...),
			err:            domain.Forbidden("INGRESS_POLICY_DENIED", fmt.Sprintf("workspace ingress blocked by policy (%s)", blockEffect)),
		}
	}

	pkgRes, err := s.packager.Package(ctx, archive.IngressPackageRequest{
		SourceDir:          chk.WorkDir,
		WorkspaceID:        &wsDetails.ID,
		RepositoryID:       &repoRec.ID,
		GitHubRepositoryID: repoRec.GitHubRepositoryID,
		RepositoryFullName: repoRec.FullName,
		CommitSHA:          wsDetails.BaseCommit,
		TargetRef:          wsDetails.TargetRef,
		IncludeGitMetadata: wsDetails.SourceOptions.IncludeGitMetadata,
		IncludeHistory:     wsDetails.SourceOptions.IncludeHistory,
		HistoryAuthorised:  wsDetails.SourceOptions.IncludeHistory,
		MaxArchiveBytes:    s.cfg.IngressMaxArchiveBytes,
	})
	if err != nil {
		return IngressResult{}, err
	}

	if err := s.verifyOperationLease(ctx); err != nil {
		return IngressResult{}, err
	}

	attemptID, err := domain.NewID()
	if err != nil {
		return IngressResult{}, err
	}
	objectKey := fmt.Sprintf("workspaces/%s/gen-%d/%s-source.tar.gz", wsDetails.ID.String(), wsDetails.Generation, attemptID.String())
	putArt, err := s.snapshotStore.Put(ctx, domain.PutRequest{
		Kind:           domain.ArtifactKindWorkspaceSource,
		ObjectKey:      objectKey,
		ExpectedSHA256: pkgRes.ArchiveSHA256,
		MaxBytes:       s.cfg.IngressMaxArchiveBytes,
		WorkspaceID:    &wsDetails.ID,
		ContentType:    "application/gzip",
	}, bytes.NewReader(pkgRes.ArchiveBytes), pkgRes.ArchiveSizeBytes)
	if err != nil {
		return IngressResult{}, err
	}

	cleanupBlob := true
	defer func() {
		if cleanupBlob {
			delCtx, cancel := detachTimeout(context.Background(), defaultTxCleanupTimeout)
			_ = s.snapshotStore.Delete(delCtx, putArt)
			cancel()
		}
	}()

	var expiresAt *time.Time
	if s.cfg.ArtifactRetentionTTL > 0 {
		t := s.now().Add(s.cfg.ArtifactRetentionTTL).UTC().Truncate(time.Microsecond)
		expiresAt = &t
	}

	artID := putArt.ID
	if artID == uuid.Nil || !domain.IsUUIDv7(artID) {
		artID, err = domain.NewID()
		if err != nil {
			return IngressResult{}, err
		}
	}

	if err := s.verifyOperationLease(ctx); err != nil {
		return IngressResult{}, err
	}

	regArt, err := s.artifacts.Register(ctx, artifacts.RegisterInput{
		ID:                  artID,
		Kind:                domain.ArtifactKindWorkspaceSource,
		SHA256:              putArt.SHA256,
		StorageKey:          putArt.StorageKey,
		StorageGeneration:   putArt.StorageGeneration,
		SizeBytes:           putArt.SizeBytes,
		Format:              "application/gzip",
		WorkspaceID:         &wsDetails.ID,
		WorkspaceGeneration: &wsDetails.Generation,
		UploadedBy:          &wsDetails.OwnerID,
		ExpiresAt:           expiresAt,
	})
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			existing, lookupErr := s.artifacts.GetByStorageObject(ctx, putArt.StorageKey, putArt.StorageGeneration)
			if lookupErr == nil {
				regArt = existing
				err = nil
			}
		}
		if err != nil {
			return IngressResult{}, err
		}
	}

	updatedWS, err := s.workspaces.AttachSourceArtifact(ctx, wsDetails.ID, regArt.ID, domain.WorkspaceStatusReady)
	if err != nil {
		// Check if another concurrent retry already attached and marked READY.
		if errors.Is(err, domain.ErrConflict) && !isLeaseLostError(err) {
			curWS, getErr := s.workspaces.GetDetails(ctx, wsDetails.ID)
			if getErr == nil && curWS.Status == domain.WorkspaceStatusReady && curWS.SourceArtifactID != nil {
				return IngressResult{
					WorkspaceID:      curWS.ID,
					SourceArtifactID: *curWS.SourceArtifactID,
					SHA256:           regArt.SHA256,
					SizeBytes:        regArt.SizeBytes,
					Status:           string(curWS.Status),
					Idempotent:       true,
				}, nil
			}
		}
		return IngressResult{}, err
	}

	cleanupBlob = false
	if s.logger != nil {
		observability.LoggerWithTrace(ctx, s.logger).InfoContext(ctx, "workspace ingress completed",
			"workspace_id", updatedWS.ID.String(),
			"source_artifact_id", regArt.ID.String(),
			"sha256", regArt.SHA256,
			"size_bytes", regArt.SizeBytes,
			"status", string(updatedWS.Status),
		)
	}

	return IngressResult{
		WorkspaceID:      updatedWS.ID,
		SourceArtifactID: regArt.ID,
		SHA256:           regArt.SHA256,
		SizeBytes:        regArt.SizeBytes,
		Status:           string(updatedWS.Status),
	}, nil
}

func (s *Service) failWorkspaceTerminal(ctx context.Context, workspaceID uuid.UUID, reasonCode string) error {
	if s == nil || s.workspaces == nil || workspaceID == uuid.Nil {
		return nil
	}
	ws, err := s.workspaces.Get(ctx, workspaceID)
	if err != nil {
		return err
	}
	if ws.Status.IsTerminal() {
		return nil
	}
	if ws.Status == domain.WorkspaceStatusPending || ws.Status == domain.WorkspaceStatusPreparing || ws.Status == domain.WorkspaceStatusReady {
		if _, err := s.workspaces.TransitionStatus(ctx, ws.ID, ws.Status, domain.WorkspaceStatusFailed); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				if isLeaseLostError(err) {
					return err
				}
				return nil
			}
			return err
		}
	}
	if s.audit != nil {
		payload, err := domain.CanonicalJSONBytes(map[string]any{
			"workspace_id": workspaceID.String(),
			"status":       string(domain.WorkspaceStatusFailed),
			"reason":       SanitizeErrorString(reasonCode),
		})
		if err == nil {
			_, _ = s.audit.Append(ctx, audit.AppendInput{
				EventType:    "workspace.failed",
				ResourceType: "workspace",
				ResourceID:   workspaceID,
				Payload:      json.RawMessage(payload),
			})
		}
	}
	return nil
}

func (s *Service) recordIngressBlocked(ctx context.Context, workspaceID uuid.UUID, effect domain.PolicyEffect, bundleDigest string, matchedRuleIDs []string) error {
	if s == nil || workspaceID == uuid.Nil {
		return nil
	}
	if s.workspaces != nil {
		ws, err := s.workspaces.Get(ctx, workspaceID)
		if err != nil {
			return err
		}
		if ws.Status.IsTerminal() {
			return nil
		}
		if _, err := s.workspaces.TransitionStatus(ctx, ws.ID, ws.Status, domain.WorkspaceStatusFailed); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				if isLeaseLostError(err) {
					return err
				}
				return nil
			}
			return err
		}
	}
	if s.audit != nil {
		if matchedRuleIDs == nil {
			matchedRuleIDs = []string{}
		}
		payload, err := domain.CanonicalJSONBytes(map[string]any{
			"workspace_id":     workspaceID.String(),
			"stage":            policy.StageIngress,
			"effect":           string(effect),
			"bundle_digest":    bundleDigest,
			"matched_rule_ids": matchedRuleIDs,
			"status":           string(domain.WorkspaceStatusFailed),
		})
		if err == nil {
			_, _ = s.audit.Append(ctx, audit.AppendInput{
				EventType:    "workspace.ingress_blocked",
				ResourceType: "workspace",
				ResourceID:   workspaceID,
				Payload:      json.RawMessage(payload),
			})
		}
	}
	return nil
}
