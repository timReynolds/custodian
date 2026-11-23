package persistence

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// --- policy_bundles ---

type CreatePolicyBundleParams struct {
	ID           uuid.UUID
	Name         string
	Version      string
	Scope        domain.PolicyScope
	RepositoryID *uuid.UUID
	Digest       string
	Definition   json.RawMessage
	ActivatedAt  *time.Time
	CreatedAt    time.Time
}

const createPolicyBundleSQL = `
INSERT INTO policy_bundles (
    id, name, version, scope, repository_id, digest, definition, activated_at, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING id, name, version, scope, repository_id, digest, definition, activated_at, created_at
`

func (q *Queries) CreatePolicyBundle(ctx context.Context, arg CreatePolicyBundleParams) (PolicyBundleRow, error) {
	return q.execPolicyBundleWrite(ctx, createPolicyBundleSQL, arg)
}

const upsertPolicyBundleByDigestSQL = `
INSERT INTO policy_bundles (
    id, name, version, scope, repository_id, digest, definition, activated_at, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
ON CONFLICT (digest) DO UPDATE SET
    name          = EXCLUDED.name,
    version       = EXCLUDED.version,
    scope         = EXCLUDED.scope,
    repository_id = EXCLUDED.repository_id,
    definition    = EXCLUDED.definition,
    activated_at  = COALESCE(EXCLUDED.activated_at, policy_bundles.activated_at)
RETURNING id, name, version, scope, repository_id, digest, definition, activated_at, created_at
`

func (q *Queries) UpsertPolicyBundleByDigest(ctx context.Context, arg CreatePolicyBundleParams) (PolicyBundleRow, error) {
	return q.execPolicyBundleWrite(ctx, upsertPolicyBundleByDigestSQL, arg)
}

func (q *Queries) execPolicyBundleWrite(ctx context.Context, stmt string, arg CreatePolicyBundleParams) (PolicyBundleRow, error) {
	if arg.Name == "" || arg.Version == "" {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "name and version must not be empty")
	}
	if !arg.Scope.IsValid() {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_SCOPE", "invalid policy scope")
	}
	if arg.RepositoryID != nil && *arg.RepositoryID == uuid.Nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_ID", "repository_id must not be nil when provided")
	}
	if arg.Scope == domain.PolicyScopeOrg && arg.RepositoryID != nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "ORG policy bundle must not set repository_id")
	}
	if arg.Scope == domain.PolicyScopeRepo && arg.RepositoryID == nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "repository-scoped policy bundle requires repository_id")
	}
	digest, err := domain.ParseSHA256Digest(arg.Digest)
	if err != nil {
		return PolicyBundleRow{}, err
	}
	trimmedDef := bytes.TrimSpace(arg.Definition)
	if len(trimmedDef) == 0 || bytes.Equal(trimmedDef, []byte("null")) {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "definition must not be empty or null")
	}
	canonicalDef, err := domain.CanonicalJSONBytes(trimmedDef)
	if err != nil {
		return PolicyBundleRow{}, domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_BUNDLE", "definition must be valid JSON", err)
	}
	if bytes.Equal(canonicalDef, []byte("null")) {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "definition must not be null")
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return PolicyBundleRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_ID", "policy_bundle id must be UUIDv7")
	}
	var activatedAt *time.Time
	if arg.ActivatedAt != nil {
		t := arg.ActivatedAt.UTC().Truncate(time.Microsecond)
		activatedAt = &t
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)

	var row PolicyBundleRow
	err = scanPolicyBundleRow(q.db.QueryRow(ctx, stmt,
		id,
		arg.Name,
		arg.Version,
		string(arg.Scope),
		arg.RepositoryID,
		digest,
		json.RawMessage(canonicalDef),
		activatedAt,
		createdAt,
	), &row)
	if err != nil {
		return PolicyBundleRow{}, MapError(err)
	}
	return row, nil
}

const getPolicyBundleByIDSQL = `
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE id = $1
`

func (q *Queries) GetPolicyBundleByID(ctx context.Context, id uuid.UUID) (PolicyBundleRow, error) {
	if id == uuid.Nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_ID", "policy_bundle id must not be nil")
	}
	var row PolicyBundleRow
	err := scanPolicyBundleRow(q.db.QueryRow(ctx, getPolicyBundleByIDSQL, id), &row)
	if err != nil {
		return PolicyBundleRow{}, MapError(err)
	}
	return row, nil
}

const getPolicyBundleByDigestSQL = `
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE digest = $1
`

func (q *Queries) GetPolicyBundleByDigest(ctx context.Context, digest string) (PolicyBundleRow, error) {
	parsed, err := domain.ParseSHA256Digest(digest)
	if err != nil {
		return PolicyBundleRow{}, err
	}
	var row PolicyBundleRow
	err = scanPolicyBundleRow(q.db.QueryRow(ctx, getPolicyBundleByDigestSQL, parsed), &row)
	if err != nil {
		return PolicyBundleRow{}, MapError(err)
	}
	return row, nil
}

const getActivePolicyBundleSQL = `
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE scope = $1::text
  AND activated_at IS NOT NULL
  AND (
      ($2::uuid IS NULL AND repository_id IS NULL)
      OR repository_id = $2::uuid
  )
ORDER BY activated_at DESC, created_at DESC, id DESC
LIMIT 1
`

func (q *Queries) GetActivePolicyBundle(ctx context.Context, scope domain.PolicyScope, repositoryID *uuid.UUID) (PolicyBundleRow, error) {
	if !scope.IsValid() {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_SCOPE", "invalid policy scope")
	}
	if repositoryID != nil && *repositoryID == uuid.Nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_ID", "repository_id must not be nil when provided")
	}
	if scope == domain.PolicyScopeOrg && repositoryID != nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "ORG policy bundle lookup must not set repository_id")
	}
	if scope == domain.PolicyScopeRepo && repositoryID == nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_POLICY_BUNDLE", "repository-scoped policy bundle lookup requires repository_id")
	}
	var row PolicyBundleRow
	err := scanPolicyBundleRow(q.db.QueryRow(ctx, getActivePolicyBundleSQL, string(scope), repositoryID), &row)
	if err != nil {
		return PolicyBundleRow{}, MapError(err)
	}
	return row, nil
}

const activatePolicyBundleSQL = `
UPDATE policy_bundles
SET activated_at = $2
WHERE id = $1
RETURNING id, name, version, scope, repository_id, digest, definition, activated_at, created_at
`

func (q *Queries) ActivatePolicyBundle(ctx context.Context, id uuid.UUID, activatedAt time.Time) (PolicyBundleRow, error) {
	if id == uuid.Nil {
		return PolicyBundleRow{}, domain.BadRequest("INVALID_ID", "policy_bundle id must not be nil")
	}
	ts := normalizeTimestamp(activatedAt)
	var row PolicyBundleRow
	err := scanPolicyBundleRow(q.db.QueryRow(ctx, activatePolicyBundleSQL, id, ts), &row)
	if err != nil {
		return PolicyBundleRow{}, MapError(err)
	}
	return row, nil
}

const listActivePolicyBundlesSQL = `
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE activated_at IS NOT NULL
ORDER BY scope ASC, activated_at DESC, created_at DESC, id DESC
`

func (q *Queries) ListActivePolicyBundles(ctx context.Context) ([]PolicyBundleRow, error) {
	rows, err := q.db.Query(ctx, listActivePolicyBundlesSQL)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]PolicyBundleRow, 0)
	for rows.Next() {
		var row PolicyBundleRow
		if err := scanPolicyBundleRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const listActivePolicyBundlesByScopeSQL = `
SELECT id, name, version, scope, repository_id, digest, definition, activated_at, created_at
FROM policy_bundles
WHERE scope = $1::text
  AND activated_at IS NOT NULL
  AND (
      ($2::uuid IS NULL AND repository_id IS NULL)
      OR repository_id = $2::uuid
  )
ORDER BY activated_at DESC, created_at DESC, id DESC
`

func (q *Queries) ListActivePolicyBundlesByScope(ctx context.Context, scope domain.PolicyScope, repositoryID *uuid.UUID) ([]PolicyBundleRow, error) {
	if !scope.IsValid() {
		return nil, domain.BadRequest("INVALID_POLICY_SCOPE", "invalid policy scope")
	}
	if repositoryID != nil && *repositoryID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "repository_id must not be nil when provided")
	}
	if scope == domain.PolicyScopeOrg && repositoryID != nil {
		return nil, domain.BadRequest("INVALID_POLICY_BUNDLE", "ORG policy bundle lookup must not set repository_id")
	}
	if scope == domain.PolicyScopeRepo && repositoryID == nil {
		return nil, domain.BadRequest("INVALID_POLICY_BUNDLE", "repository-scoped policy bundle lookup requires repository_id")
	}
	rows, err := q.db.Query(ctx, listActivePolicyBundlesByScopeSQL, string(scope), repositoryID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]PolicyBundleRow, 0)
	for rows.Next() {
		var row PolicyBundleRow
		if err := scanPolicyBundleRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

// --- policy_decisions ---

type CreatePolicyDecisionParams struct {
	ID             uuid.UUID
	ProposalID     uuid.UUID
	PolicyBundleID uuid.UUID
	OrgBundleID    *uuid.UUID
	RepoBundleID   *uuid.UUID
	Stage          string
	InputDigest    string
	Effect         domain.PolicyEffect
	Reasons        []domain.PolicyReason
	Obligations    []domain.Obligation
	CreatedAt      time.Time
}

const createPolicyDecisionSQL = `
INSERT INTO policy_decisions (
    id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9, $10, $11
)
RETURNING id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
`

func validatePolicyStage(stage string) (string, error) {
	if stage == "" {
		return "EGRESS", nil
	}
	switch stage {
	case "INGRESS", "EGRESS":
		return stage, nil
	default:
		return "", domain.BadRequest("INVALID_POLICY_STAGE", "stage must be INGRESS or EGRESS")
	}
}

func (q *Queries) CreatePolicyDecision(ctx context.Context, arg CreatePolicyDecisionParams) (PolicyDecisionRow, error) {
	if arg.ProposalID == uuid.Nil || arg.PolicyBundleID == uuid.Nil {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_POLICY_DECISION", "proposal_id and policy_bundle_id are required")
	}
	if arg.OrgBundleID != nil && *arg.OrgBundleID == uuid.Nil {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_ID", "org_bundle_id must not be nil when provided")
	}
	if arg.RepoBundleID != nil && *arg.RepoBundleID == uuid.Nil {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_ID", "repo_bundle_id must not be nil when provided")
	}
	stage, err := validatePolicyStage(arg.Stage)
	if err != nil {
		return PolicyDecisionRow{}, err
	}
	inputDigest, err := domain.ParseSHA256Digest(arg.InputDigest)
	if err != nil {
		return PolicyDecisionRow{}, err
	}
	if !arg.Effect.IsValid() {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_POLICY_EFFECT", "invalid policy effect")
	}

	reasons := arg.Reasons
	if reasons == nil {
		reasons = []domain.PolicyReason{}
	}
	rawReasons, err := json.Marshal(reasons)
	if err != nil {
		return PolicyDecisionRow{}, domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_REASONS", "failed to marshal policy reasons", err)
	}
	canonReasons, err := domain.CanonicalJSONBytes(rawReasons)
	if err != nil {
		return PolicyDecisionRow{}, err
	}

	obligations := arg.Obligations
	if obligations == nil {
		obligations = []domain.Obligation{}
	}
	rawObligations, err := json.Marshal(obligations)
	if err != nil {
		return PolicyDecisionRow{}, domain.WrapError(domain.ErrBadRequest, "INVALID_POLICY_OBLIGATIONS", "failed to marshal policy obligations", err)
	}
	canonObligations, err := domain.CanonicalJSONBytes(rawObligations)
	if err != nil {
		return PolicyDecisionRow{}, err
	}

	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return PolicyDecisionRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_ID", "policy_decision id must be UUIDv7")
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)

	var row PolicyDecisionRow
	err = scanPolicyDecisionRow(q.db.QueryRow(ctx, createPolicyDecisionSQL,
		id,
		arg.ProposalID,
		arg.PolicyBundleID,
		arg.OrgBundleID,
		arg.RepoBundleID,
		stage,
		inputDigest,
		string(arg.Effect),
		json.RawMessage(canonReasons),
		json.RawMessage(canonObligations),
		createdAt,
	), &row)
	if err != nil {
		return PolicyDecisionRow{}, MapError(err)
	}
	return row, nil
}

const getPolicyDecisionByIDSQL = `
SELECT id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
FROM policy_decisions
WHERE id = $1
`

func (q *Queries) GetPolicyDecisionByID(ctx context.Context, id uuid.UUID) (PolicyDecisionRow, error) {
	if id == uuid.Nil {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_ID", "policy_decision id must not be nil")
	}
	var row PolicyDecisionRow
	err := scanPolicyDecisionRow(q.db.QueryRow(ctx, getPolicyDecisionByIDSQL, id), &row)
	if err != nil {
		return PolicyDecisionRow{}, MapError(err)
	}
	return row, nil
}

const listPolicyDecisionsByProposalSQL = `
SELECT id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
FROM policy_decisions
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC
`

func (q *Queries) ListPolicyDecisionsByProposal(ctx context.Context, proposalID uuid.UUID) ([]PolicyDecisionRow, error) {
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listPolicyDecisionsByProposalSQL, proposalID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]PolicyDecisionRow, 0)
	for rows.Next() {
		var row PolicyDecisionRow
		if err := scanPolicyDecisionRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const getLatestPolicyDecisionForProposalSQL = `
SELECT id, proposal_id, policy_bundle_id, org_bundle_id, repo_bundle_id,
    stage, input_digest, effect, reasons, obligations, created_at
FROM policy_decisions
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC
LIMIT 1
`

func (q *Queries) GetLatestPolicyDecisionForProposal(ctx context.Context, proposalID uuid.UUID) (PolicyDecisionRow, error) {
	if proposalID == uuid.Nil {
		return PolicyDecisionRow{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	var row PolicyDecisionRow
	err := scanPolicyDecisionRow(q.db.QueryRow(ctx, getLatestPolicyDecisionForProposalSQL, proposalID), &row)
	if err != nil {
		return PolicyDecisionRow{}, MapError(err)
	}
	return row, nil
}

// --- scan helpers ---

func scanPolicyBundleRow(s rowScanner, row *PolicyBundleRow) error {
	var scope string
	if err := s.Scan(
		&row.ID,
		&row.Name,
		&row.Version,
		&scope,
		&row.RepositoryID,
		&row.Digest,
		&row.Definition,
		&row.ActivatedAt,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Scope = domain.PolicyScope(scope)
	return nil
}

func scanPolicyDecisionRow(s rowScanner, row *PolicyDecisionRow) error {
	var effect string
	if err := s.Scan(
		&row.ID,
		&row.ProposalID,
		&row.PolicyBundleID,
		&row.OrgBundleID,
		&row.RepoBundleID,
		&row.Stage,
		&row.InputDigest,
		&effect,
		&row.Reasons,
		&row.Obligations,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Effect = domain.PolicyEffect(effect)
	return nil
}
