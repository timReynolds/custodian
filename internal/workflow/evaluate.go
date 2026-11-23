package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/prompts"
)

const maxCanonicalDiffReadBytes = 16 << 20 // 16 MiB safety bound

// EvaluateResult records the outcome of a PROPOSAL_EVALUATE operation.
type EvaluateResult struct {
	ProposalID        uuid.UUID `json:"proposal_id"`
	PolicyDecisionID  uuid.UUID `json:"policy_decision_id,omitempty"`
	PolicyBundleID    uuid.UUID `json:"policy_bundle_id,omitempty"`
	ModelAssessmentID uuid.UUID `json:"model_assessment_id,omitempty"`
	Effect            string    `json:"effect"`
	Status            string    `json:"status"`
	Version           int64     `json:"version"`
}

// ExecuteEvaluate runs Stage A inspection, Stage B decision model evaluation, and
// Stage C CEL policy evaluation for a PROPOSAL_EVALUATE operation.
func (s *Service) ExecuteEvaluate(ctx context.Context, op operations.OperationDetails) (EvaluateResult, error) {
	ctx = s.ensureOperationLeaseContext(ctx, op)
	if s == nil || s.proposals == nil || s.workspaces == nil || s.artifacts == nil {
		return EvaluateResult{}, domain.Unavailable("WORKFLOW_UNAVAILABLE", "workflow service dependencies are not configured")
	}
	if s.snapshotStore == nil {
		return EvaluateResult{}, domain.Unavailable("STORAGE_UNAVAILABLE", "snapshot store is not configured")
	}
	if s.inspector == nil {
		return EvaluateResult{}, domain.Unavailable("INSPECTOR_UNAVAILABLE", "inspection runner is not configured")
	}
	if s.decisions == nil {
		return EvaluateResult{}, domain.Unavailable("DECISIONS_UNAVAILABLE", "decisions service is not configured")
	}

	details, err := s.proposals.GetDetails(ctx, op.ResourceID)
	if err != nil {
		return EvaluateResult{}, err
	}
	if idempRes, ok, idempErr := s.checkIdempotentEvaluate(ctx, op, details); idempErr != nil {
		return EvaluateResult{}, idempErr
	} else if ok {
		return idempRes, nil
	}
	if details.Status.IsTerminal() {
		return EvaluateResult{}, domain.Conflict("PROPOSAL_TERMINAL", "proposal is already in a terminal status")
	}
	if details.CanonicalArtifactID == nil || *details.CanonicalArtifactID == uuid.Nil {
		return EvaluateResult{}, domain.Conflict("MISSING_CANONICAL_ARTIFACT", "proposal is missing canonical_artifact_id")
	}

	releaseRepo, err := s.budgets.AcquireRepo(ctx, details.RepositoryID)
	if err != nil {
		return EvaluateResult{}, err
	}
	defer releaseRepo()

	wsDetails, err := s.workspaces.GetDetails(ctx, details.WorkspaceID)
	if err != nil {
		return EvaluateResult{}, err
	}
	repoRow, err := s.store.GetRepositoryByID(ctx, details.RepositoryID)
	if err != nil {
		return EvaluateResult{}, err
	}
	if !repoRow.Enabled {
		return EvaluateResult{}, domain.Forbidden("REPOSITORY_DISABLED", "repository is disabled")
	}
	ownerRow, err := s.store.GetPrincipalByID(ctx, details.OwnerID)
	if err != nil {
		return EvaluateResult{}, err
	}

	prop, err := s.proposals.BeginEvaluation(ctx, details.ID, details.Version)
	if err != nil {
		return EvaluateResult{}, err
	}
	details.Version = prop.Version
	details.Status = prop.Status

	// Extract CANONICAL_TREE to a temporary directory for Stage A scanners.
	treeArtRec, err := s.artifacts.GetByID(ctx, *details.CanonicalArtifactID)
	if err != nil {
		return EvaluateResult{}, err
	}
	if treeArtRec.DeletedAt != nil {
		return EvaluateResult{}, domain.Conflict("ARTIFACT_DELETED", "canonical tree artifact has been deleted")
	}
	extractDir, err := os.MkdirTemp("", "custodian-eval-*")
	if err != nil {
		return EvaluateResult{}, domain.WrapError(domain.ErrInternal, "TEMP_DIR_FAILED", "failed creating evaluation temp directory", err)
	}
	defer os.RemoveAll(extractDir)

	treeReader, err := s.snapshotStore.Open(ctx, treeArtRec.Artifact)
	if err != nil {
		return EvaluateResult{}, err
	}
	_, extractErr := archive.ExtractEgress(ctx, treeReader, extractDir, archive.EgressOptions{})
	_ = treeReader.Close()
	if extractErr != nil {
		return EvaluateResult{}, extractErr
	}

	// Read CANONICAL_DIFF and PUBLICATION_MANIFEST for Stage B and Stage C context.
	var canonicalDiff string
	if details.DiffArtifactID != nil && *details.DiffArtifactID != uuid.Nil {
		diffArtRec, diffErr := s.artifacts.GetByID(ctx, *details.DiffArtifactID)
		if diffErr != nil {
			return EvaluateResult{}, diffErr
		}
		if diffArtRec.DeletedAt != nil {
			return EvaluateResult{}, domain.Conflict("ARTIFACT_DELETED", "canonical diff artifact has been deleted")
		}
		rc, openErr := s.snapshotStore.Open(ctx, diffArtRec.Artifact)
		if openErr != nil {
			return EvaluateResult{}, openErr
		}
		diffBytes, readErr := io.ReadAll(io.LimitReader(rc, maxCanonicalDiffReadBytes))
		var drainErr error
		if readErr == nil {
			_, drainErr = io.Copy(io.Discard, rc)
		}
		closeErr := rc.Close()
		if err := firstNonNilErr(readErr, drainErr, closeErr); err != nil {
			var domErr *domain.DomainError
			if errors.As(err, &domErr) {
				return EvaluateResult{}, domErr
			}
			return EvaluateResult{}, domain.WrapError(domain.ErrUnavailable, "STORAGE_READ_FAILED", "failed reading canonical diff", err)
		}
		canonicalDiff = string(diffBytes)
	}

	if details.ManifestArtifactID == nil || *details.ManifestArtifactID == uuid.Nil {
		return EvaluateResult{}, domain.Conflict("MISSING_MANIFEST_ARTIFACT", "proposal is missing manifest_artifact_id")
	}
	var manifest reconstruct.PublicationManifest
	var changedPaths []string
	manArtRec, manErr := s.artifacts.GetByID(ctx, *details.ManifestArtifactID)
	if manErr != nil {
		return EvaluateResult{}, manErr
	}
	if manArtRec.DeletedAt != nil {
		return EvaluateResult{}, domain.Conflict("ARTIFACT_DELETED", "publication manifest artifact has been deleted")
	}
	rc, openErr := s.snapshotStore.Open(ctx, manArtRec.Artifact)
	if openErr != nil {
		return EvaluateResult{}, openErr
	}
	manBytes, readErr := io.ReadAll(io.LimitReader(rc, maxCanonicalDiffReadBytes+1))
	closeErr := rc.Close()
	if err := firstNonNilErr(readErr, closeErr); err != nil {
		var domErr *domain.DomainError
		if errors.As(err, &domErr) {
			return EvaluateResult{}, domErr
		}
		return EvaluateResult{}, domain.WrapError(domain.ErrUnavailable, "STORAGE_READ_FAILED", "failed reading publication manifest", err)
	}
	if len(manBytes) > maxCanonicalDiffReadBytes {
		return EvaluateResult{}, domain.Unprocessable("INVALID_PUBLICATION_MANIFEST", "publication manifest exceeds maximum allowed size")
	}
	if err := json.Unmarshal(manBytes, &manifest); err != nil {
		return EvaluateResult{}, domain.WrapError(domain.ErrUnprocessable, "INVALID_PUBLICATION_MANIFEST", "failed decoding publication manifest JSON", err)
	}
	for _, ch := range manifest.Changes {
		if ch.Path != "" {
			changedPaths = append(changedPaths, ch.Path)
		}
	}

	// Resolve active ORG and repo-specific REPO policy bundles before Stage A so
	// mandatory scanner expectations and decision model route defaults are known.
	orgBundles, repoBundles, err := s.resolveActivePolicyBundles(ctx, repoRow.ID)
	if err != nil {
		return EvaluateResult{}, err
	}
	inspCfg := composeInspectionConfigAll(orgBundles, repoBundles)

	// Stage A: Deterministic scanners + persistence of scan_runs & redacted findings.
	if err := s.verifyOperationLease(ctx); err != nil {
		return EvaluateResult{}, err
	}
	releaseScan, err := s.budgets.AcquireScan(ctx)
	if err != nil {
		return EvaluateResult{}, err
	}

	var preScanRunID uuid.UUID
	scanFinalized := false
	if s.store != nil && s.store.Pool() != nil {
		preScanRunID, err = s.startPendingScanRun(ctx, details.ID, *details.CanonicalArtifactID, string(inspection.ScannerGitleaks))
		if err != nil {
			releaseScan()
			return EvaluateResult{}, err
		}
		defer func() {
			if !scanFinalized && preScanRunID != uuid.Nil {
				cleanCtx, cleanCancel := detachTimeout(context.Background(), defaultTxCleanupTimeout)
				defer cleanCancel()
				_, _ = s.store.Pool().Exec(cleanCtx, "DELETE FROM scan_runs WHERE id = $1 AND status IN ('PENDING', 'RUNNING')", preScanRunID)
			}
		}()
	}

	report, inspectErr := s.inspector.Inspect(ctx, inspection.Request{
		ProposalID:        details.ID,
		ArtifactID:        *details.CanonicalArtifactID,
		TargetDir:         extractDir,
		Classification:    repoRow.Classification,
		Stage:             inspection.StageEgress,
		ChangedPaths:      changedPaths,
		MandatoryScanners: inspCfg.Mandatory,
	})
	releaseScan()
	if inspectErr != nil {
		return EvaluateResult{}, inspectErr
	}

	if err := s.persistInspectionReport(ctx, report, preScanRunID); err != nil {
		return EvaluateResult{}, err
	}
	scanFinalized = true

	summary := enforceMandatoryScanners(report.Summary, report.ScanRuns, inspCfg.Mandatory)

	// Stage B: Contextual decision model (always invoked; route authorization & schema/grounding
	// checked inside decisions.Service.Assess).
	modelRoute := resolveEvaluationModelRoute(details.WorkspaceModelRoute, repoRow.AllowedModelRoutes, orgBundles, repoBundles, inspCfg)
	assessmentType := prompts.AssessmentTypeSecurityReview
	if repoRow.Classification == domain.ClassificationConfidential {
		assessmentType = prompts.AssessmentTypeIPProvenance
	}

	if err := s.verifyOperationLease(ctx); err != nil {
		return EvaluateResult{}, err
	}
	releaseModel, err := s.budgets.AcquireModel(ctx)
	if err != nil {
		return EvaluateResult{}, err
	}

	var preAssessmentID uuid.UUID
	assessmentFinalized := false
	if s.store != nil && s.store.Pool() != nil {
		preAssessmentID, err = s.startPendingModelAssessment(ctx, details.ID, *details.CanonicalArtifactID, modelRoute, assessmentType)
		if err != nil {
			releaseModel()
			return EvaluateResult{}, err
		}
		defer func() {
			if !assessmentFinalized && preAssessmentID != uuid.Nil {
				cleanCtx, cleanCancel := detachTimeout(context.Background(), defaultTxCleanupTimeout)
				defer cleanCancel()
				_, _ = s.store.Pool().Exec(cleanCtx, "DELETE FROM model_assessments WHERE id = $1 AND status = 'PENDING'", preAssessmentID)
			}
		}()
	}

	scrubbedDiff := report.ScrubText(canonicalDiff)
	scrubbedTargetRef := report.ScrubText(details.TargetRef)
	scrubbedPaths := make([]string, len(changedPaths))
	for i, p := range changedPaths {
		scrubbedPaths[i] = report.ScrubText(p)
	}
	assessment, assessErr := s.decisions.Assess(ctx, decisions.AssessRequest{
		ProposalID:         details.ID,
		ArtifactID:         *details.CanonicalArtifactID,
		Repository:         repoRow.ToDomain(),
		AllowedModelRoutes: repoRow.AllowedModelRoutes,
		ModelRoute:         modelRoute,
		AssessmentType:     assessmentType,
		BaseCommit:         details.BaseCommit,
		TargetRef:          scrubbedTargetRef,
		ChangedPaths:       scrubbedPaths,
		CanonicalDiff:      scrubbedDiff,
		Findings:           report.Findings,
		ScanRuns:           report.ScanRuns,
	})
	releaseModel()

	if assessErr != nil {
		// Transient gateway outage on an intermediate attempt retries the operation.
		if IsRetryableError(assessErr) && (op.MaxAttempts == 0 || op.Attempts < op.MaxAttempts) {
			return EvaluateResult{}, assessErr
		}
		// Terminal or exhausted gateway error: persist the failed assessment if built so Stage C fails closed.
		if assessment.ID == uuid.Nil {
			return EvaluateResult{}, assessErr
		}
	}

	if assessment.ID != uuid.Nil {
		if err := s.persistModelAssessment(ctx, &assessment, preAssessmentID); err != nil {
			return EvaluateResult{}, err
		}
		assessmentFinalized = true
	}

	// Stage C: CEL policy evaluation over verified persisted facts.
	policyInput := buildEgressPolicyInput(details, wsDetails, repoRow, ownerRow, summary, assessment, manifest, changedPaths)
	outcome, err := s.evaluateComposedBundles(ctx, orgBundles, repoBundles, policy.StageEgress, policyInput)
	if err != nil {
		return EvaluateResult{}, err
	}

	decided, err := s.proposals.ApplyPolicyDecision(ctx, proposals.ApplyPolicyDecisionInput{
		ProposalID:      details.ID,
		ExpectedVersion: prop.Version,
		PolicyBundleID:  outcome.primaryBundleID,
		OrgBundleID:     outcome.orgBundleID,
		RepoBundleID:    outcome.repoBundleID,
		Stage:           policy.StageEgress,
		InputDigest:     outcome.result.InputDigest,
		Effect:          outcome.result.Effect,
		Reasons:         outcome.result.Reasons,
		Obligations:     outcome.result.Obligations,
	})
	if err != nil {
		return EvaluateResult{}, err
	}

	var decisionID uuid.UUID
	updatedDetails, detailsErr := s.proposals.GetDetails(ctx, decided.ID)
	if detailsErr == nil && updatedDetails.LatestPolicyEvaluationID != nil {
		decisionID = *updatedDetails.LatestPolicyEvaluationID
	} else {
		if detailsErr != nil && s.logger != nil {
			code, msg := SafeErrorCodeMessage(detailsErr)
			observability.LoggerWithTrace(ctx, s.logger).WarnContext(ctx, "failed reloading proposal details after policy decision; falling back to latest policy decision",
				"proposal_id", decided.ID.String(),
				"error_code", code,
				"reason", msg,
			)
		}
		if pd, pdErr := s.store.GetLatestPolicyDecisionForProposal(ctx, decided.ID); pdErr == nil {
			decisionID = pd.ID
		} else if s.logger != nil {
			code, msg := SafeErrorCodeMessage(pdErr)
			observability.LoggerWithTrace(ctx, s.logger).WarnContext(ctx, "failed resolving latest policy decision id",
				"proposal_id", decided.ID.String(),
				"error_code", code,
				"reason", msg,
			)
		}
	}

	if s.logger != nil {
		observability.LoggerWithTrace(ctx, s.logger).InfoContext(ctx, "proposal evaluation completed",
			"proposal_id", decided.ID.String(),
			"policy_bundle_id", outcome.primaryBundleID.String(),
			"policy_decision_id", decisionID.String(),
			"model_assessment_id", assessment.ID.String(),
			"effect", string(outcome.result.Effect),
			"status", string(decided.Status),
		)
	}

	return EvaluateResult{
		ProposalID:        decided.ID,
		PolicyDecisionID:  decisionID,
		PolicyBundleID:    outcome.primaryBundleID,
		ModelAssessmentID: assessment.ID,
		Effect:            string(outcome.result.Effect),
		Status:            string(decided.Status),
		Version:           decided.Version,
	}, nil
}

func (s *Service) checkIdempotentEvaluate(ctx context.Context, op operations.OperationDetails, details proposals.ProposalDetails) (EvaluateResult, bool, error) {
	switch details.Status {
	case domain.ProposalStatusFailed:
		return EvaluateResult{}, false, domain.Conflict("PROPOSAL_TERMINAL", "proposal is already in a terminal status")
	case domain.ProposalStatusReconstructed, domain.ProposalStatusEvaluating:
		return EvaluateResult{}, false, nil
	case domain.ProposalStatusApproved,
		domain.ProposalStatusPublishing,
		domain.ProposalStatusPublished,
		domain.ProposalStatusPendingApproval,
		domain.ProposalStatusRemediationRequired,
		domain.ProposalStatusDenied,
		domain.ProposalStatusQuarantined,
		domain.ProposalStatusRejected:
		if details.LatestPolicyEvaluationID == nil || *details.LatestPolicyEvaluationID == uuid.Nil || s.store == nil {
			if details.Status.IsTerminal() {
				return EvaluateResult{}, false, domain.Conflict("PROPOSAL_TERMINAL", "proposal is already in a terminal status")
			}
			if details.Status == domain.ProposalStatusApproved || details.Status == domain.ProposalStatusPublishing {
				return EvaluateResult{}, false, domain.Conflict("INVALID_PROPOSAL_STATE", "proposal is not eligible for evaluation in its current status")
			}
			return EvaluateResult{}, false, nil
		}

		pd, pdErr := s.store.GetLatestPolicyDecisionForProposal(ctx, details.ID)
		if pdErr != nil || pd.ID == uuid.Nil {
			if details.Status.IsTerminal() {
				return EvaluateResult{}, false, domain.Conflict("PROPOSAL_TERMINAL", "proposal is already in a terminal status")
			}
			return EvaluateResult{}, false, nil
		}

		alreadyCommittedForOp := op.Attempts > 1 || (!op.CreatedAt.IsZero() && !pd.CreatedAt.Before(op.CreatedAt))
		if !alreadyCommittedForOp {
			if details.Status == domain.ProposalStatusApproved || details.Status == domain.ProposalStatusPublishing || details.Status == domain.ProposalStatusPublished {
				alreadyCommittedForOp = true
			} else if details.Status.IsTerminal() {
				return EvaluateResult{}, false, domain.Conflict("PROPOSAL_TERMINAL", "proposal is already in a terminal status")
			} else {
				return EvaluateResult{}, false, nil
			}
		}

		var maID uuid.UUID
		if mas, maErr := s.store.ListModelAssessmentsByProposal(ctx, details.ID); maErr == nil && len(mas) > 0 {
			maID = mas[0].ID
		}
		return EvaluateResult{
			ProposalID:        details.ID,
			PolicyDecisionID:  pd.ID,
			PolicyBundleID:    pd.PolicyBundleID,
			ModelAssessmentID: maID,
			Effect:            string(pd.Effect),
			Status:            string(details.Status),
			Version:           details.Version,
		}, true, nil
	default:
		return EvaluateResult{}, false, nil
	}
}

func (s *Service) startPendingScanRun(ctx context.Context, proposalID, artifactID uuid.UUID, scanner string) (uuid.UUID, error) {
	id, err := domain.NewID()
	if err != nil {
		return uuid.Nil, err
	}
	err = s.store.WithTx(ctx, func(tx *persistence.Tx) error {
		if lease, ok := operationLeaseFromContext(ctx); ok {
			if err := verifyOperationLeaseTx(ctx, tx, lease, s.now()); err != nil {
				return err
			}
		}
		_, err := tx.CreateScanRun(ctx, persistence.CreateScanRunParams{
			ID:             id,
			ProposalID:     proposalID,
			ArtifactID:     artifactID,
			Scanner:        scanner,
			ScannerVersion: "pending",
			Status:         domain.ScanStatusRunning,
			StartedAt:      s.now(),
		})
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func (s *Service) startPendingModelAssessment(ctx context.Context, proposalID, artifactID uuid.UUID, modelRoute, assessmentType string) (uuid.UUID, error) {
	id, err := domain.NewID()
	if err != nil {
		return uuid.Nil, err
	}
	route := strings.TrimSpace(modelRoute)
	if route == "" {
		route = "route-pending"
	}
	err = s.store.WithTx(ctx, func(tx *persistence.Tx) error {
		if lease, ok := operationLeaseFromContext(ctx); ok {
			if err := verifyOperationLeaseTx(ctx, tx, lease, s.now()); err != nil {
				return err
			}
		}
		_, err := tx.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
			ID:             id,
			ProposalID:     proposalID,
			ArtifactID:     artifactID,
			ModelRoute:     route,
			ModelVersion:   "pending",
			PromptVersion:  "pending",
			AssessmentType: assessmentType,
			Status:         domain.AssessmentStatusPending,
			InputDigest:    domain.SHA256Hex([]byte("pending:" + id.String())),
			OutputDigest:   domain.SHA256Hex([]byte("pending:" + id.String())),
			CreatedAt:      s.now(),
		})
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func normalizeTerminalScanStatus(st domain.ScanStatus) domain.ScanStatus {
	switch st {
	case domain.ScanStatusCompleted, domain.ScanStatusFailed, domain.ScanStatusTimedOut, domain.ScanStatusIncomplete:
		return st
	default:
		return domain.ScanStatusIncomplete
	}
}

func (s *Service) persistInspectionReport(ctx context.Context, report inspection.Report, preScanRunID uuid.UUID) error {
	return s.store.WithTx(ctx, func(tx *persistence.Tx) error {
		if lease, ok := operationLeaseFromContext(ctx); ok {
			if err := verifyOperationLeaseTx(ctx, tx, lease, s.now()); err != nil {
				return err
			}
		}
		runIDMap := make(map[uuid.UUID]uuid.UUID, len(report.ScanRuns))
		matchedPre := false
		for _, run := range report.ScanRuns {
			origID := run.ID
			version := strings.TrimSpace(run.ScannerVersion)
			if version == "" {
				version = "unknown"
			}
			if !matchedPre && preScanRunID != uuid.Nil && run.Scanner == string(inspection.ScannerGitleaks) {
				matchedPre = true
				if origID != uuid.Nil {
					runIDMap[origID] = preScanRunID
				}
				completedAt := s.now()
				if run.CompletedAt != nil {
					completedAt = *run.CompletedAt
				}
				if _, err := tx.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
					ID:             preScanRunID,
					Status:         normalizeTerminalScanStatus(run.Status),
					ScannerVersion: version,
					Coverage:       run.Coverage,
					CompletedAt:    completedAt,
				}); err != nil {
					return err
				}
				continue
			}

			id := run.ID
			if id == uuid.Nil || !domain.IsUUIDv7(id) {
				var err error
				id, err = domain.NewID()
				if err != nil {
					return err
				}
			}
			if origID != uuid.Nil {
				runIDMap[origID] = id
			}
			if _, err := tx.CreateScanRun(ctx, persistence.CreateScanRunParams{
				ID:             id,
				ProposalID:     run.ProposalID,
				ArtifactID:     run.ArtifactID,
				Scanner:        run.Scanner,
				ScannerVersion: version,
				Status:         run.Status,
				Coverage:       run.Coverage,
				StartedAt:      run.StartedAt,
				CompletedAt:    run.CompletedAt,
			}); err != nil {
				return err
			}
		}
		if !matchedPre && preScanRunID != uuid.Nil {
			fallbackStatus := domain.ScanStatusCompleted
			if !report.Summary.ScanComplete {
				fallbackStatus = domain.ScanStatusIncomplete
			}
			if _, err := tx.CompleteScanRun(ctx, persistence.CompleteScanRunParams{
				ID:          preScanRunID,
				Status:      fallbackStatus,
				Coverage:    domain.ScanCoverage{Complete: report.Summary.ScanComplete},
				CompletedAt: s.now(),
			}); err != nil {
				return err
			}
		}

		for _, f := range report.Findings {
			id := f.ID
			if id == uuid.Nil || !domain.IsUUIDv7(id) {
				var err error
				id, err = domain.NewID()
				if err != nil {
					return err
				}
			}
			scanRunID := f.ScanRunID
			if remapped, ok := runIDMap[scanRunID]; ok {
				scanRunID = remapped
			}
			var startLine, endLine *int
			if f.StartLine > 0 {
				v := f.StartLine
				startLine = &v
			}
			if f.EndLine > 0 {
				v := f.EndLine
				endLine = &v
			}
			var conf *float64
			if f.Confidence > 0 {
				v := f.Confidence
				conf = &v
			}
			if _, err := tx.CreateFinding(ctx, persistence.CreateFindingParams{
				ID:                 id,
				ScanRunID:          scanRunID,
				EvidenceID:         f.EvidenceID,
				Scanner:            f.Scanner,
				Category:           f.Category,
				Severity:           f.Severity,
				RuleID:             f.RuleID,
				Path:               f.Path,
				StartLine:          startLine,
				EndLine:            endLine,
				Fingerprint:        f.Fingerprint,
				EvidenceArtifactID: f.EvidenceArtifactID,
				EvidenceRef:        f.EvidenceRef,
				Baseline:           f.Baseline,
				Confidence:         conf,
				Message:            f.Message,
				Redacted:           f.Redacted,
				Metadata:           f.Metadata,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) persistModelAssessment(ctx context.Context, ma *domain.ModelAssessment, preAssessmentID uuid.UUID) error {
	if preAssessmentID != uuid.Nil {
		err := s.store.WithTx(ctx, func(tx *persistence.Tx) error {
			if lease, ok := operationLeaseFromContext(ctx); ok {
				if err := verifyOperationLeaseTx(ctx, tx, lease, s.now()); err != nil {
					return err
				}
			}
			_, err := tx.UpdateModelAssessmentResult(ctx, persistence.UpdateModelAssessmentResultParams{
				ID:            preAssessmentID,
				Status:        ma.Status,
				Risk:          ma.Risk,
				Disposition:   ma.Disposition,
				Result:        ma.Result,
				EvidenceIDs:   ma.EvidenceIDs,
				OutputDigest:  ma.OutputDigest,
				ModelRoute:    ma.ModelRoute,
				ModelVersion:  ma.ModelVersion,
				PromptVersion: ma.PromptVersion,
				InputDigest:   ma.InputDigest,
			})
			return err
		})
		if err == nil {
			ma.ID = preAssessmentID
		}
		return err
	}

	id := ma.ID
	if id == uuid.Nil || !domain.IsUUIDv7(id) {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return err
		}
		ma.ID = id
	}
	return s.store.WithTx(ctx, func(tx *persistence.Tx) error {
		if lease, ok := operationLeaseFromContext(ctx); ok {
			if err := verifyOperationLeaseTx(ctx, tx, lease, s.now()); err != nil {
				return err
			}
		}
		_, err := tx.CreateModelAssessment(ctx, persistence.CreateModelAssessmentParams{
			ID:             id,
			ProposalID:     ma.ProposalID,
			ArtifactID:     ma.ArtifactID,
			ModelRoute:     ma.ModelRoute,
			ModelVersion:   ma.ModelVersion,
			PromptVersion:  ma.PromptVersion,
			AssessmentType: ma.AssessmentType,
			Status:         ma.Status,
			Risk:           ma.Risk,
			Disposition:    ma.Disposition,
			Result:         ma.Result,
			EvidenceIDs:    ma.EvidenceIDs,
			InputDigest:    ma.InputDigest,
			OutputDigest:   ma.OutputDigest,
			CreatedAt:      ma.CreatedAt,
		})
		return err
	})
}
