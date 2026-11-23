package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/timreynolds/custodian/internal/domain"
)

// --- scan_runs ---

type CreateScanRunParams struct {
	ID             uuid.UUID
	ProposalID     uuid.UUID
	ArtifactID     uuid.UUID
	Scanner        string
	ScannerVersion string
	Status         domain.ScanStatus
	Coverage       domain.ScanCoverage
	StartedAt      time.Time
	CompletedAt    *time.Time
}

const createScanRunSQL = `
INSERT INTO scan_runs (
    id, proposal_id, artifact_id, scanner, scanner_version,
    status, coverage, started_at, completed_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9
)
RETURNING id, proposal_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
`

func marshalScanCoverage(c domain.ScanCoverage) (json.RawMessage, error) {
	if c.FilesExamined < 0 || c.FilesSkipped < 0 || c.BytesExamined < 0 {
		return nil, domain.BadRequest("INVALID_SCAN_COVERAGE", "scan coverage counts must be non-negative")
	}
	if c.SkippedReasons == nil {
		c.SkippedReasons = []string{}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_SCAN_COVERAGE", "failed to marshal scan coverage", err)
	}
	canonical, err := domain.CanonicalJSONBytes(raw)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func (q *Queries) CreateScanRun(ctx context.Context, arg CreateScanRunParams) (ScanRunRow, error) {
	if arg.ProposalID == uuid.Nil || arg.ArtifactID == uuid.Nil {
		return ScanRunRow{}, domain.BadRequest("INVALID_SCAN_RUN", "proposal_id and artifact_id are required")
	}
	if arg.Scanner == "" || arg.ScannerVersion == "" {
		return ScanRunRow{}, domain.BadRequest("INVALID_SCAN_RUN", "scanner and scanner_version must not be empty")
	}
	status := arg.Status
	if status == "" {
		status = domain.ScanStatusPending
	}
	if !status.IsValid() {
		return ScanRunRow{}, domain.BadRequest("INVALID_SCAN_STATUS", "invalid scan status")
	}
	coverageJSON, err := marshalScanCoverage(arg.Coverage)
	if err != nil {
		return ScanRunRow{}, err
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return ScanRunRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return ScanRunRow{}, domain.BadRequest("INVALID_ID", "scan_run id must be UUIDv7")
	}
	startedAt := normalizeTimestamp(arg.StartedAt)
	var completedAt *time.Time
	if arg.CompletedAt != nil {
		t := arg.CompletedAt.UTC().Truncate(time.Microsecond)
		completedAt = &t
	}

	var row ScanRunRow
	err = scanScanRunRow(q.db.QueryRow(ctx, createScanRunSQL,
		id,
		arg.ProposalID,
		arg.ArtifactID,
		arg.Scanner,
		arg.ScannerVersion,
		string(status),
		coverageJSON,
		startedAt,
		completedAt,
	), &row)
	if err != nil {
		return ScanRunRow{}, MapError(err)
	}
	return row, nil
}

const getScanRunByIDSQL = `
SELECT id, proposal_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
FROM scan_runs
WHERE id = $1
`

func (q *Queries) GetScanRunByID(ctx context.Context, id uuid.UUID) (ScanRunRow, error) {
	if id == uuid.Nil {
		return ScanRunRow{}, domain.BadRequest("INVALID_ID", "scan_run id must not be nil")
	}
	var row ScanRunRow
	err := scanScanRunRow(q.db.QueryRow(ctx, getScanRunByIDSQL, id), &row)
	if err != nil {
		return ScanRunRow{}, MapError(err)
	}
	return row, nil
}

const listScanRunsByProposalSQL = `
SELECT id, proposal_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
FROM scan_runs
WHERE proposal_id = $1
ORDER BY started_at DESC, id DESC
`

func (q *Queries) ListScanRunsByProposal(ctx context.Context, proposalID uuid.UUID) ([]ScanRunRow, error) {
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listScanRunsByProposalSQL, proposalID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ScanRunRow, 0)
	for rows.Next() {
		var row ScanRunRow
		if err := scanScanRunRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type CompleteScanRunParams struct {
	ID             uuid.UUID
	Status         domain.ScanStatus
	ScannerVersion string
	Coverage       domain.ScanCoverage
	CompletedAt    time.Time
}

const completeScanRunSQL = `
UPDATE scan_runs
SET status          = $2,
    coverage        = $3,
    completed_at    = $4,
    scanner_version = COALESCE(NULLIF($5, ''), scanner_version)
WHERE id = $1
  AND status IN ('PENDING', 'RUNNING')
RETURNING id, proposal_id, artifact_id, scanner, scanner_version, status, coverage, started_at, completed_at
`

func isTerminalScanStatus(s domain.ScanStatus) bool {
	switch s {
	case domain.ScanStatusCompleted, domain.ScanStatusFailed, domain.ScanStatusTimedOut, domain.ScanStatusIncomplete:
		return true
	default:
		return false
	}
}

func (q *Queries) CompleteScanRun(ctx context.Context, arg CompleteScanRunParams) (ScanRunRow, error) {
	if arg.ID == uuid.Nil {
		return ScanRunRow{}, domain.BadRequest("INVALID_ID", "scan_run id must not be nil")
	}
	if !isTerminalScanStatus(arg.Status) {
		return ScanRunRow{}, domain.BadRequest("INVALID_SCAN_STATUS", "completion requires terminal scan status")
	}
	coverageJSON, err := marshalScanCoverage(arg.Coverage)
	if err != nil {
		return ScanRunRow{}, err
	}
	completedAt := normalizeTimestamp(arg.CompletedAt)

	var row ScanRunRow
	err = scanScanRunRow(q.db.QueryRow(ctx, completeScanRunSQL,
		arg.ID,
		string(arg.Status),
		coverageJSON,
		completedAt,
		arg.ScannerVersion,
	), &row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var existing ScanRunRow
			lookupErr := scanScanRunRow(q.db.QueryRow(ctx, getScanRunByIDSQL, arg.ID), &existing)
			if lookupErr == nil {
				return ScanRunRow{}, domain.Conflict("SCAN_RUN_STATE_CONFLICT", "scan_run is already completed")
			}
			if !errors.Is(lookupErr, pgx.ErrNoRows) {
				return ScanRunRow{}, MapError(lookupErr)
			}
		}
		return ScanRunRow{}, MapError(err)
	}
	return row, nil
}

// --- findings ---

type CreateFindingParams struct {
	ID                 uuid.UUID
	ScanRunID          uuid.UUID
	EvidenceID         string
	Scanner            string
	Category           string
	Severity           domain.Severity
	RuleID             string
	Path               string
	StartLine          *int
	EndLine            *int
	Fingerprint        string
	EvidenceArtifactID *uuid.UUID
	EvidenceRef        string
	Baseline           string
	Confidence         *float64
	Message            string
	Redacted           bool
	Metadata           map[string]any
}

const createFindingSQL = `
INSERT INTO findings (
    id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13,
    $14, $15, $16, $17, $18
)
RETURNING id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
`

func (q *Queries) CreateFinding(ctx context.Context, arg CreateFindingParams) (FindingRow, error) {
	if arg.ScanRunID == uuid.Nil {
		return FindingRow{}, domain.BadRequest("INVALID_ID", "scan_run_id must not be nil")
	}
	if arg.Category == "" || arg.RuleID == "" || arg.Fingerprint == "" {
		return FindingRow{}, domain.BadRequest("INVALID_FINDING", "category, rule_id, and fingerprint are required")
	}
	if !arg.Severity.IsValid() {
		return FindingRow{}, domain.BadRequest("INVALID_SEVERITY", "invalid finding severity")
	}
	if arg.StartLine != nil && *arg.StartLine < 0 {
		return FindingRow{}, domain.BadRequest("INVALID_LINE", "start_line must be >= 0")
	}
	if arg.EndLine != nil && *arg.EndLine < 0 {
		return FindingRow{}, domain.BadRequest("INVALID_LINE", "end_line must be >= 0")
	}
	if arg.Confidence != nil && (math.IsNaN(*arg.Confidence) || *arg.Confidence < 0.0 || *arg.Confidence > 1.0) {
		return FindingRow{}, domain.BadRequest("INVALID_CONFIDENCE", "confidence must be between 0.0 and 1.0")
	}
	if arg.EvidenceArtifactID != nil && *arg.EvidenceArtifactID == uuid.Nil {
		return FindingRow{}, domain.BadRequest("INVALID_ID", "evidence_artifact_id must not be nil when provided")
	}

	// Enforce domain secret-redaction invariant before hitting PostgreSQL.
	domFinding := domain.Finding{
		ScanRunID:   arg.ScanRunID,
		Category:    arg.Category,
		Severity:    arg.Severity,
		RuleID:      arg.RuleID,
		Fingerprint: arg.Fingerprint,
		Redacted:    arg.Redacted,
		Metadata:    arg.Metadata,
	}
	if err := domFinding.ValidateRedacted(); err != nil {
		return FindingRow{}, err
	}

	metadata := arg.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	rawMeta, err := json.Marshal(metadata)
	if err != nil {
		return FindingRow{}, domain.WrapError(domain.ErrBadRequest, "INVALID_METADATA", "failed to marshal finding metadata", err)
	}
	canonicalMeta, err := domain.CanonicalJSONBytes(rawMeta)
	if err != nil {
		return FindingRow{}, err
	}

	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return FindingRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return FindingRow{}, domain.BadRequest("INVALID_ID", "finding id must be UUIDv7")
	}

	var row FindingRow
	err = scanFindingRow(q.db.QueryRow(ctx, createFindingSQL,
		id,
		arg.ScanRunID,
		nilIfEmpty(arg.EvidenceID),
		nilIfEmpty(arg.Scanner),
		arg.Category,
		string(arg.Severity),
		arg.RuleID,
		nilIfEmpty(arg.Path),
		arg.StartLine,
		arg.EndLine,
		arg.Fingerprint,
		arg.EvidenceArtifactID,
		nilIfEmpty(arg.EvidenceRef),
		nilIfEmpty(arg.Baseline),
		arg.Confidence,
		nilIfEmpty(arg.Message),
		arg.Redacted,
		json.RawMessage(canonicalMeta),
	), &row)
	if err != nil {
		return FindingRow{}, MapError(err)
	}
	return row, nil
}

const getFindingByIDSQL = `
SELECT id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
FROM findings
WHERE id = $1
`

func (q *Queries) GetFindingByID(ctx context.Context, id uuid.UUID) (FindingRow, error) {
	if id == uuid.Nil {
		return FindingRow{}, domain.BadRequest("INVALID_ID", "finding id must not be nil")
	}
	var row FindingRow
	err := scanFindingRow(q.db.QueryRow(ctx, getFindingByIDSQL, id), &row)
	if err != nil {
		return FindingRow{}, MapError(err)
	}
	return row, nil
}

const listFindingsByScanRunSQL = `
SELECT id, scan_run_id, evidence_id, scanner, category, severity, rule_id,
    path, start_line, end_line, fingerprint, evidence_artifact_id, evidence_ref,
    baseline, confidence, message, redacted, metadata
FROM findings
WHERE scan_run_id = $1
ORDER BY id ASC
`

func (q *Queries) ListFindingsByScanRun(ctx context.Context, scanRunID uuid.UUID) ([]FindingRow, error) {
	if scanRunID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "scan_run_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listFindingsByScanRunSQL, scanRunID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]FindingRow, 0)
	for rows.Next() {
		var row FindingRow
		if err := scanFindingRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type ListFindingsByProposalParams struct {
	ProposalID uuid.UUID
	Scanner    *string
	Severity   *domain.Severity
	CursorID   *uuid.UUID
	Limit      int
}

const listFindingsByProposalSQL = `
SELECT f.id, f.scan_run_id, f.evidence_id, f.scanner, f.category, f.severity, f.rule_id,
    f.path, f.start_line, f.end_line, f.fingerprint, f.evidence_artifact_id, f.evidence_ref,
    f.baseline, f.confidence, f.message, f.redacted, f.metadata
FROM findings f
JOIN scan_runs sr ON sr.id = f.scan_run_id
WHERE sr.proposal_id = $1
  AND ($2::text IS NULL OR f.scanner = $2::text)
  AND ($3::text IS NULL OR f.severity = $3::text)
  AND ($4::uuid IS NULL OR f.id > $4::uuid)
ORDER BY f.id ASC
LIMIT $5
`

func (q *Queries) ListFindingsByProposal(ctx context.Context, arg ListFindingsByProposalParams) ([]FindingRow, error) {
	if arg.ProposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	var scannerArg *string
	if arg.Scanner != nil && *arg.Scanner != "" {
		s := *arg.Scanner
		scannerArg = &s
	}
	var severityArg *string
	if arg.Severity != nil {
		if !arg.Severity.IsValid() {
			return nil, domain.BadRequest("INVALID_SEVERITY", "invalid finding severity")
		}
		s := string(*arg.Severity)
		severityArg = &s
	}
	if arg.CursorID != nil && *arg.CursorID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_CURSOR", "cursor_id must not be nil")
	}
	limit := arg.Limit
	if limit <= 0 {
		limit = 100
	} else if limit > 1001 {
		limit = 1001
	}

	rows, err := q.db.Query(ctx, listFindingsByProposalSQL, arg.ProposalID, scannerArg, severityArg, arg.CursorID, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]FindingRow, 0)
	for rows.Next() {
		var row FindingRow
		if err := scanFindingRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

// --- model_assessments ---

type CreateModelAssessmentParams struct {
	ID             uuid.UUID
	ProposalID     uuid.UUID
	ArtifactID     uuid.UUID
	ModelRoute     string
	ModelVersion   string
	PromptVersion  string
	AssessmentType string
	Status         domain.AssessmentStatus
	Risk           domain.RiskLevel
	Disposition    domain.Disposition
	Result         domain.AssessmentResult
	EvidenceIDs    []string
	InputDigest    string
	OutputDigest   string
	CreatedAt      time.Time
}

const createModelAssessmentSQL = `
INSERT INTO model_assessments (
    id, proposal_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $8, $9, $10, $11, $12,
    $13, $14, $15
)
RETURNING id, proposal_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
`

func marshalAssessmentResultAndEvidence(res domain.AssessmentResult, evidenceIDs []string) (json.RawMessage, json.RawMessage, error) {
	if res.Findings == nil {
		res.Findings = []domain.AssessmentFinding{}
	}
	for i := range res.Findings {
		if res.Findings[i].EvidenceIDs == nil {
			res.Findings[i].EvidenceIDs = []string{}
		}
	}
	if res.Limitations == nil {
		res.Limitations = []string{}
	}
	rawRes, err := json.Marshal(res)
	if err != nil {
		return nil, nil, domain.WrapError(domain.ErrBadRequest, "INVALID_ASSESSMENT_RESULT", "failed to marshal assessment result", err)
	}
	canonRes, err := domain.CanonicalJSONBytes(rawRes)
	if err != nil {
		return nil, nil, err
	}

	if evidenceIDs == nil {
		evidenceIDs = []string{}
	}
	rawEv, err := json.Marshal(evidenceIDs)
	if err != nil {
		return nil, nil, domain.WrapError(domain.ErrBadRequest, "INVALID_EVIDENCE_IDS", "failed to marshal evidence_ids", err)
	}
	canonEv, err := domain.CanonicalJSONBytes(rawEv)
	if err != nil {
		return nil, nil, err
	}
	return json.RawMessage(canonRes), json.RawMessage(canonEv), nil
}

func (q *Queries) CreateModelAssessment(ctx context.Context, arg CreateModelAssessmentParams) (ModelAssessmentRow, error) {
	if arg.ProposalID == uuid.Nil || arg.ArtifactID == uuid.Nil {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_MODEL_ASSESSMENT", "proposal_id and artifact_id are required")
	}
	if arg.ModelRoute == "" || arg.ModelVersion == "" || arg.PromptVersion == "" || arg.AssessmentType == "" {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_MODEL_ASSESSMENT", "model_route, model_version, prompt_version, and assessment_type are required")
	}
	status := arg.Status
	if status == "" {
		status = domain.AssessmentStatusPending
	}
	if !status.IsValid() {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_ASSESSMENT_STATUS", "invalid assessment status")
	}
	if arg.Risk != "" && !arg.Risk.IsValid() {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_RISK_LEVEL", "invalid risk level")
	}
	if arg.Disposition != "" && !arg.Disposition.IsValid() {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_DISPOSITION", "invalid disposition")
	}
	inputDigest, err := domain.ParseSHA256Digest(arg.InputDigest)
	if err != nil {
		return ModelAssessmentRow{}, err
	}
	outputDigest, err := domain.ParseSHA256Digest(arg.OutputDigest)
	if err != nil {
		return ModelAssessmentRow{}, err
	}
	resJSON, evJSON, err := marshalAssessmentResultAndEvidence(arg.Result, arg.EvidenceIDs)
	if err != nil {
		return ModelAssessmentRow{}, err
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return ModelAssessmentRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_ID", "model_assessment id must be UUIDv7")
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)

	var row ModelAssessmentRow
	err = scanModelAssessmentRow(q.db.QueryRow(ctx, createModelAssessmentSQL,
		id,
		arg.ProposalID,
		arg.ArtifactID,
		arg.ModelRoute,
		arg.ModelVersion,
		arg.PromptVersion,
		arg.AssessmentType,
		string(status),
		nilIfEmpty(string(arg.Risk)),
		nilIfEmpty(string(arg.Disposition)),
		resJSON,
		evJSON,
		inputDigest,
		outputDigest,
		createdAt,
	), &row)
	if err != nil {
		return ModelAssessmentRow{}, MapError(err)
	}
	return row, nil
}

const getModelAssessmentByIDSQL = `
SELECT id, proposal_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
FROM model_assessments
WHERE id = $1
`

func (q *Queries) GetModelAssessmentByID(ctx context.Context, id uuid.UUID) (ModelAssessmentRow, error) {
	if id == uuid.Nil {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_ID", "model_assessment id must not be nil")
	}
	var row ModelAssessmentRow
	err := scanModelAssessmentRow(q.db.QueryRow(ctx, getModelAssessmentByIDSQL, id), &row)
	if err != nil {
		return ModelAssessmentRow{}, MapError(err)
	}
	return row, nil
}

const listModelAssessmentsByProposalSQL = `
SELECT id, proposal_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
FROM model_assessments
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC
`

func (q *Queries) ListModelAssessmentsByProposal(ctx context.Context, proposalID uuid.UUID) ([]ModelAssessmentRow, error) {
	if proposalID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listModelAssessmentsByProposalSQL, proposalID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]ModelAssessmentRow, 0)
	for rows.Next() {
		var row ModelAssessmentRow
		if err := scanModelAssessmentRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

type UpdateModelAssessmentResultParams struct {
	ID            uuid.UUID
	Status        domain.AssessmentStatus
	Risk          domain.RiskLevel
	Disposition   domain.Disposition
	Result        domain.AssessmentResult
	EvidenceIDs   []string
	OutputDigest  string
	ModelRoute    string
	ModelVersion  string
	PromptVersion string
	InputDigest   string
}

const updateModelAssessmentResultSQL = `
UPDATE model_assessments
SET status         = $2,
    risk           = $3,
    disposition    = $4,
    result         = $5,
    evidence_ids   = $6,
    output_digest  = $7,
    model_route    = COALESCE(NULLIF($8, ''), model_route),
    model_version  = COALESCE(NULLIF($9, ''), model_version),
    prompt_version = COALESCE(NULLIF($10, ''), prompt_version),
    input_digest   = COALESCE(NULLIF($11, ''), input_digest)
WHERE id = $1
  AND status = 'PENDING'
RETURNING id, proposal_id, artifact_id, model_route, model_version, prompt_version,
    assessment_type, status, risk, disposition, result, evidence_ids,
    input_digest, output_digest, created_at
`

func (q *Queries) UpdateModelAssessmentResult(ctx context.Context, arg UpdateModelAssessmentResultParams) (ModelAssessmentRow, error) {
	if arg.ID == uuid.Nil {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_ID", "model_assessment id must not be nil")
	}
	if !arg.Status.IsValid() || arg.Status == domain.AssessmentStatusPending {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_ASSESSMENT_STATUS", "updating model_assessment requires terminal status")
	}
	if arg.Risk != "" && !arg.Risk.IsValid() {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_RISK_LEVEL", "invalid risk level")
	}
	if arg.Disposition != "" && !arg.Disposition.IsValid() {
		return ModelAssessmentRow{}, domain.BadRequest("INVALID_DISPOSITION", "invalid disposition")
	}
	outputDigest, err := domain.ParseSHA256Digest(arg.OutputDigest)
	if err != nil {
		return ModelAssessmentRow{}, err
	}
	inputDigest := ""
	if arg.InputDigest != "" {
		inputDigest, err = domain.ParseSHA256Digest(arg.InputDigest)
		if err != nil {
			return ModelAssessmentRow{}, err
		}
	}
	resJSON, evJSON, err := marshalAssessmentResultAndEvidence(arg.Result, arg.EvidenceIDs)
	if err != nil {
		return ModelAssessmentRow{}, err
	}

	var row ModelAssessmentRow
	err = scanModelAssessmentRow(q.db.QueryRow(ctx, updateModelAssessmentResultSQL,
		arg.ID,
		string(arg.Status),
		nilIfEmpty(string(arg.Risk)),
		nilIfEmpty(string(arg.Disposition)),
		resJSON,
		evJSON,
		outputDigest,
		arg.ModelRoute,
		arg.ModelVersion,
		arg.PromptVersion,
		inputDigest,
	), &row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var existing ModelAssessmentRow
			lookupErr := scanModelAssessmentRow(q.db.QueryRow(ctx, getModelAssessmentByIDSQL, arg.ID), &existing)
			if lookupErr == nil {
				return ModelAssessmentRow{}, domain.Conflict("MODEL_ASSESSMENT_STATE_CONFLICT", "model_assessment is not in PENDING status")
			}
			if !errors.Is(lookupErr, pgx.ErrNoRows) {
				return ModelAssessmentRow{}, MapError(lookupErr)
			}
		}
		return ModelAssessmentRow{}, MapError(err)
	}
	return row, nil
}

const countActiveScanRunsSQL = `
SELECT COUNT(*)::bigint
FROM scan_runs
WHERE status IN ('PENDING', 'RUNNING')
`

func (q *Queries) CountActiveScanRuns(ctx context.Context) (int64, error) {
	var count int64
	if err := q.db.QueryRow(ctx, countActiveScanRunsSQL).Scan(&count); err != nil {
		return 0, MapError(err)
	}
	return count, nil
}

const countActiveModelAssessmentsSQL = `
SELECT COUNT(*)::bigint
FROM model_assessments
WHERE status = 'PENDING'
`

func (q *Queries) CountActiveModelAssessments(ctx context.Context) (int64, error) {
	var count int64
	if err := q.db.QueryRow(ctx, countActiveModelAssessmentsSQL).Scan(&count); err != nil {
		return 0, MapError(err)
	}
	return count, nil
}

// --- scan helpers ---

func scanScanRunRow(s rowScanner, row *ScanRunRow) error {
	var status string
	if err := s.Scan(
		&row.ID,
		&row.ProposalID,
		&row.ArtifactID,
		&row.Scanner,
		&row.ScannerVersion,
		&status,
		&row.Coverage,
		&row.StartedAt,
		&row.CompletedAt,
	); err != nil {
		return err
	}
	row.Status = domain.ScanStatus(status)
	return nil
}

func scanFindingRow(s rowScanner, row *FindingRow) error {
	var severity string
	if err := s.Scan(
		&row.ID,
		&row.ScanRunID,
		&row.EvidenceID,
		&row.Scanner,
		&row.Category,
		&severity,
		&row.RuleID,
		&row.Path,
		&row.StartLine,
		&row.EndLine,
		&row.Fingerprint,
		&row.EvidenceArtifactID,
		&row.EvidenceRef,
		&row.Baseline,
		&row.Confidence,
		&row.Message,
		&row.Redacted,
		&row.Metadata,
	); err != nil {
		return err
	}
	row.Severity = domain.Severity(severity)
	return nil
}

func scanModelAssessmentRow(s rowScanner, row *ModelAssessmentRow) error {
	var status string
	var risk, disposition *string
	if err := s.Scan(
		&row.ID,
		&row.ProposalID,
		&row.ArtifactID,
		&row.ModelRoute,
		&row.ModelVersion,
		&row.PromptVersion,
		&row.AssessmentType,
		&status,
		&risk,
		&disposition,
		&row.Result,
		&row.EvidenceIDs,
		&row.InputDigest,
		&row.OutputDigest,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Status = domain.AssessmentStatus(status)
	if risk != nil {
		r := domain.RiskLevel(*risk)
		row.Risk = &r
	} else {
		row.Risk = nil
	}
	if disposition != nil {
		d := domain.Disposition(*disposition)
		row.Disposition = &d
	} else {
		row.Disposition = nil
	}
	return nil
}
