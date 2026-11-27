package workflow

import (
	"slices"

	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workspaces"
)

func enforceMandatoryScanners(summary inspection.InspectionSummary, scanRuns []domain.ScanRun, required []string) inspection.InspectionSummary {
	if len(required) == 0 {
		return summary
	}
	byScanner := make(map[string]domain.ScanRun, len(scanRuns))
	for _, run := range scanRuns {
		byScanner[run.Scanner] = run
	}

	out := summary
	out.IncompleteScanners = slices.Clone(summary.IncompleteScanners)
	if out.IncompleteScanners == nil {
		out.IncompleteScanners = []string{}
	}

	for _, name := range required {
		if name == "" {
			continue
		}
		run, ok := byScanner[name]
		if !ok || !run.IsCleanComplete() {
			out.MandatoryScannersComplete = false
			out.ScanComplete = false
			if !slices.Contains(out.IncompleteScanners, name) {
				out.IncompleteScanners = append(out.IncompleteScanners, name)
			}
		}
	}
	return out
}

// SummaryToFindingsInput maps a Stage A InspectionSummary into Stage C CEL FindingsInput.
func SummaryToFindingsInput(s inspection.InspectionSummary) policy.FindingsInput {
	return summaryToFindingsInput(s)
}

func summaryToFindingsInput(s inspection.InspectionSummary) policy.FindingsInput {
	cat := make(map[string]int64, len(s.CountsByCategory))
	for k, v := range s.CountsByCategory {
		cat[k] = int64(v)
	}
	sev := make(map[string]int64, len(s.CountsBySeverity))
	for k, v := range s.CountsBySeverity {
		sev[k] = int64(v)
	}
	sc := make(map[string]int64, len(s.CountsByScanner))
	for k, v := range s.CountsByScanner {
		sc[k] = int64(v)
	}
	evIDs := slices.Clone(s.EvidenceIDs)
	if evIDs == nil {
		evIDs = []string{}
	}
	failed := slices.Clone(s.FailedScanners)
	if failed == nil {
		failed = []string{}
	}
	incomplete := slices.Clone(s.IncompleteScanners)
	if incomplete == nil {
		incomplete = []string{}
	}
	return policy.FindingsInput{
		MandatoryScannersComplete: s.MandatoryScannersComplete,
		ScanComplete:              s.ScanComplete,
		CriticalSecrets:           int64(s.CriticalSecrets),
		ProhibitedLicenses:        int64(s.ProhibitedLicenses),
		HighVulnerabilities:       int64(s.HighVulnerabilities),
		HighSASTFindings:          int64(s.HighSASTFindings),
		TotalFindings:             int64(s.TotalFindings),
		IPExactMatches:            int64(s.IPExactMatches),
		IPWinnowMatches:           int64(s.IPWinnowMatches),
		IPHeaderStripMatches:      int64(s.IPHeaderStripMatches),
		ConcealmentFindings:       int64(s.ConcealmentFindings),
		RestrictedIPMatches:       int64(s.RestrictedIPMatches),
		ConfidentialIPMatches:     int64(s.ConfidentialIPMatches),
		CountsByCategory:          cat,
		CountsBySeverity:          sev,
		CountsByScanner:           sc,
		EvidenceIDs:               evIDs,
		FailedScanners:            failed,
		IncompleteScanners:        incomplete,
	}
}

func buildIngressPolicyInput(
	ws workspaces.WorkspaceDetails,
	repo repositories.Record,
	owner domain.Principal,
	ownerGroups []string,
	summary inspection.InspectionSummary,
) policy.PolicyInput {
	allowedRoutes := slices.Clone(repo.AllowedModelRoutes)
	if allowedRoutes == nil {
		allowedRoutes = []string{}
	}
	groups := slices.Clone(ownerGroups)
	if groups == nil {
		groups = []string{}
	}
	return policy.PolicyInput{
		Stage:    policy.StageIngress,
		Findings: summaryToFindingsInput(summary),
		Change: policy.ChangeInput{
			Paths:      []string{},
			BaseCommit: ws.BaseCommit,
			TargetRef:  ws.TargetRef,
		},
		Repository: policy.RepositoryInput{
			ID:                   repo.ID.String(),
			FullName:             repo.FullName,
			Classification:       string(repo.Classification),
			Enabled:              repo.Enabled,
			AllowedModelRoutes:   allowedRoutes,
			GitHubRepositoryID:   repo.GitHubRepositoryID,
			GitHubInstallationID: repo.GitHubInstallationID,
		},
		Workspace: policy.WorkspaceInput{
			ID:                 ws.ID.String(),
			Generation:         ws.Generation,
			AgentAssisted:      ws.AgentID != nil,
			ModelRoute:         ws.ModelRoute,
			IncludeGitMetadata: ws.SourceOptions.IncludeGitMetadata,
			IncludeHistory:     ws.SourceOptions.IncludeHistory,
			BaseCommit:         ws.BaseCommit,
			TargetRef:          ws.TargetRef,
		},
		Principal: policy.PrincipalInput{
			ID:            owner.ID.String(),
			Kind:          string(owner.Kind),
			Subject:       owner.Subject,
			DisplayName:   owner.DisplayName,
			VerifiedEmail: owner.VerifiedEmail,
			Groups:        groups,
			Roles:         []string{},
		},
	}
}

func buildEgressPolicyInput(
	details proposals.ProposalDetails,
	ws workspaces.WorkspaceDetails,
	repo persistence.RepositoryRow,
	owner persistence.PrincipalRow,
	summary inspection.InspectionSummary,
	assessment domain.ModelAssessment,
	manifest reconstruct.PublicationManifest,
	changedPaths []string,
) policy.PolicyInput {
	fact := decisions.ToPolicyAssessmentFact(assessment)
	allowedRoutes := slices.Clone(repo.AllowedModelRoutes)
	if allowedRoutes == nil {
		allowedRoutes = []string{}
	}
	groups := slices.Clone(owner.Groups)
	if groups == nil {
		groups = []string{}
	}
	paths := slices.Clone(changedPaths)
	if paths == nil {
		paths = []string{}
	}
	domOwner := owner.ToDomain()

	return policy.PolicyInput{
		Stage:    policy.StageEgress,
		Findings: summaryToFindingsInput(summary),
		Assessment: policy.AssessmentInput{
			Status:         fact.Status,
			IPRisk:         fact.IPRisk,
			Risk:           fact.Risk,
			Disposition:    fact.Disposition,
			ModelRoute:     fact.ModelRoute,
			ModelVersion:   fact.ModelVersion,
			PromptVersion:  fact.PromptVersion,
			AssessmentType: fact.AssessmentType,
		},
		Change: policy.ChangeInput{
			Paths:          paths,
			FileCount:      int64(manifest.FileCount),
			TotalBytes:     manifest.TotalBytes,
			TreeDigest:     details.TreeDigest,
			DiffDigest:     details.DiffDigest,
			ManifestDigest: details.ManifestDigest,
			BaseCommit:     details.BaseCommit,
			TargetRef:      details.TargetRef,
		},
		Repository: policy.RepositoryInput{
			ID:                   repo.ID.String(),
			FullName:             repo.FullName,
			Classification:       string(repo.Classification),
			Enabled:              repo.Enabled,
			AllowedModelRoutes:   allowedRoutes,
			GitHubRepositoryID:   repo.GitHubRepositoryID,
			GitHubInstallationID: repo.GitHubInstallationID,
		},
		Workspace: policy.WorkspaceInput{
			ID:                 ws.ID.String(),
			Generation:         ws.Generation,
			AgentAssisted:      ws.AgentID != nil || details.ProvenanceType == "agent_assisted",
			ModelRoute:         ws.ModelRoute,
			IncludeGitMetadata: ws.SourceOptions.IncludeGitMetadata,
			IncludeHistory:     ws.SourceOptions.IncludeHistory,
			BaseCommit:         ws.BaseCommit,
			TargetRef:          ws.TargetRef,
		},
		Proposal: policy.ProposalInput{
			ID:             details.ID.String(),
			Version:        details.Version,
			OwnerID:        details.OwnerID.String(),
			BaseCommit:     details.BaseCommit,
			TargetRef:      details.TargetRef,
			ProvenanceType: details.ProvenanceType,
			CaptureMethod:  details.CaptureMethod,
		},
		Principal: policy.PrincipalInput{
			ID:            domOwner.ID.String(),
			Kind:          string(domOwner.Kind),
			Subject:       domOwner.Subject,
			DisplayName:   domOwner.DisplayName,
			VerifiedEmail: domOwner.VerifiedEmail,
			Groups:        groups,
			Roles:         []string{},
		},
		Provenance: policy.ProvenanceInput{
			Type:          details.ProvenanceType,
			CaptureMethod: details.CaptureMethod,
		},
	}
}
