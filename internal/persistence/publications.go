package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/timreynolds/custodian/internal/domain"
)

// --- publications ---

type CreatePublicationParams struct {
	ID         uuid.UUID
	ProposalID uuid.UUID
	BranchRef  string
	Status     domain.PublicationStatus
	CreatedAt  time.Time
}

const createPublicationSQL = `
INSERT INTO publications (
    id, proposal_id, branch_ref, status, attempt_count, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $5
)
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
`

const tryInsertPublicationSQL = `
INSERT INTO publications (
    id, proposal_id, branch_ref, status, attempt_count, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $5
)
ON CONFLICT (proposal_id) DO NOTHING
`

func validateCreatePublication(arg CreatePublicationParams) (uuid.UUID, string, domain.PublicationStatus, time.Time, error) {
	if arg.ProposalID == uuid.Nil {
		return uuid.Nil, "", "", time.Time{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must not be nil")
	}
	branchRef := arg.BranchRef
	if branchRef == "" {
		branchRef = domain.ExpectedBranchName(arg.ProposalID)
	}
	if err := domain.ValidateBranchRef(arg.ProposalID, branchRef); err != nil {
		return uuid.Nil, "", "", time.Time{}, err
	}
	status := arg.Status
	if status == "" {
		status = domain.PublicationStatusPending
	}
	if !status.IsValid() {
		return uuid.Nil, "", "", time.Time{}, domain.BadRequest("INVALID_PUBLICATION_STATUS", "invalid publication status")
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return uuid.Nil, "", "", time.Time{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return uuid.Nil, "", "", time.Time{}, domain.BadRequest("INVALID_ID", "publication id must be UUIDv7")
	}
	now := normalizeTimestamp(arg.CreatedAt)
	return id, branchRef, status, now, nil
}

func (q *Queries) CreatePublication(ctx context.Context, arg CreatePublicationParams) (PublicationRow, error) {
	id, branchRef, status, now, err := validateCreatePublication(arg)
	if err != nil {
		return PublicationRow{}, err
	}
	var row PublicationRow
	err = scanPublicationRow(q.db.QueryRow(ctx, createPublicationSQL,
		id,
		arg.ProposalID,
		branchRef,
		string(status),
		now,
	), &row)
	if err != nil {
		return PublicationRow{}, MapError(err)
	}
	return row, nil
}

// EnsurePublication idempotently creates or returns the single publication row for a proposal (RG-08).
func (q *Queries) EnsurePublication(ctx context.Context, arg CreatePublicationParams) (PublicationRow, error) {
	id, branchRef, status, now, err := validateCreatePublication(arg)
	if err != nil {
		return PublicationRow{}, err
	}
	if _, err := q.db.Exec(ctx, tryInsertPublicationSQL,
		id,
		arg.ProposalID,
		branchRef,
		string(status),
		now,
	); err != nil {
		return PublicationRow{}, MapError(err)
	}
	return q.GetPublicationByProposalID(ctx, arg.ProposalID)
}

const getPublicationByIDSQL = `
SELECT id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
FROM publications
WHERE id = $1
`

func (q *Queries) GetPublicationByID(ctx context.Context, id uuid.UUID) (PublicationRow, error) {
	if id == uuid.Nil {
		return PublicationRow{}, domain.BadRequest("INVALID_ID", "publication id must not be nil")
	}
	var row PublicationRow
	err := scanPublicationRow(q.db.QueryRow(ctx, getPublicationByIDSQL, id), &row)
	if err != nil {
		return PublicationRow{}, MapError(err)
	}
	return row, nil
}

const getPublicationByProposalIDSQL = `
SELECT id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
FROM publications
WHERE proposal_id = $1
`

func (q *Queries) GetPublicationByProposalID(ctx context.Context, proposalID uuid.UUID) (PublicationRow, error) {
	if proposalID == uuid.Nil {
		return PublicationRow{}, domain.BadRequest("INVALID_ID", "proposal_id must not be nil")
	}
	var row PublicationRow
	err := scanPublicationRow(q.db.QueryRow(ctx, getPublicationByProposalIDSQL, proposalID), &row)
	if err != nil {
		return PublicationRow{}, MapError(err)
	}
	return row, nil
}

const transitionPublicationToPublishingSQL = `
UPDATE publications
SET status        = 'PUBLISHING',
    attempt_count = attempt_count + 1,
    updated_at    = $2
WHERE id = $1
  AND status IN ('PENDING', 'FAILED', 'PUBLISHING')
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
`

func (q *Queries) TransitionPublicationToPublishing(ctx context.Context, id uuid.UUID, now time.Time) (PublicationRow, error) {
	if id == uuid.Nil {
		return PublicationRow{}, domain.BadRequest("INVALID_ID", "publication id must not be nil")
	}
	ts := normalizeTimestamp(now)
	var row PublicationRow
	err := scanPublicationRow(q.db.QueryRow(ctx, transitionPublicationToPublishingSQL, id, ts), &row)
	if err != nil {
		return PublicationRow{}, q.disambiguatePublicationConflict(ctx, id, "publication is already published", err)
	}
	return row, nil
}

type BeginPublicationAttemptParams struct {
	PublicationID  uuid.UUID
	AttemptID      uuid.UUID
	ManifestDigest string
	Now            time.Time
}

// BeginPublicationAttempt transitions the publication to PUBLISHING, increments attempt_count,
// and records the corresponding STARTED publication_attempts row. Callers should run inside WithTx.
func (q *Queries) BeginPublicationAttempt(ctx context.Context, arg BeginPublicationAttemptParams) (PublicationRow, PublicationAttemptRow, error) {
	if arg.PublicationID == uuid.Nil {
		return PublicationRow{}, PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_id must not be nil")
	}
	if arg.AttemptID != uuid.Nil && !domain.IsUUIDv7(arg.AttemptID) {
		return PublicationRow{}, PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_attempt id must be UUIDv7")
	}
	manifestDigest, err := domain.ParseSHA256Digest(arg.ManifestDigest)
	if err != nil {
		return PublicationRow{}, PublicationAttemptRow{}, err
	}
	now := normalizeTimestamp(arg.Now)
	pub, err := q.TransitionPublicationToPublishing(ctx, arg.PublicationID, now)
	if err != nil {
		return PublicationRow{}, PublicationAttemptRow{}, err
	}
	attempt, err := q.CreatePublicationAttempt(ctx, CreatePublicationAttemptParams{
		ID:             arg.AttemptID,
		PublicationID:  pub.ID,
		AttemptNumber:  pub.AttemptCount,
		ManifestDigest: manifestDigest,
		StartedAt:      now,
	})
	if err != nil {
		return PublicationRow{}, PublicationAttemptRow{}, err
	}
	return pub, attempt, nil
}

type MarkPublicationPublishedParams struct {
	ID                uuid.UUID
	CommitSHA         string
	PullRequestNumber *int64
	PullRequestURL    string
	UpdatedAt         time.Time
}

const markPublicationPublishedSQL = `
UPDATE publications
SET status              = 'PUBLISHED',
    commit_sha          = $2,
    pull_request_number = $3,
    pull_request_url    = $4,
    updated_at          = $5
WHERE id = $1
  AND status = 'PUBLISHING'
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
`

func (q *Queries) MarkPublicationPublished(ctx context.Context, arg MarkPublicationPublishedParams) (PublicationRow, error) {
	if arg.ID == uuid.Nil {
		return PublicationRow{}, domain.BadRequest("INVALID_ID", "publication id must not be nil")
	}
	commitSHA, err := domain.ParseGitSHA(arg.CommitSHA)
	if err != nil {
		return PublicationRow{}, err
	}
	if arg.PullRequestNumber != nil && *arg.PullRequestNumber <= 0 {
		return PublicationRow{}, domain.BadRequest("INVALID_PR_NUMBER", "pull_request_number must be positive")
	}
	now := normalizeTimestamp(arg.UpdatedAt)

	var row PublicationRow
	err = scanPublicationRow(q.db.QueryRow(ctx, markPublicationPublishedSQL,
		arg.ID,
		commitSHA,
		arg.PullRequestNumber,
		nilIfEmpty(arg.PullRequestURL),
		now,
	), &row)
	if err != nil {
		return PublicationRow{}, q.disambiguatePublicationConflict(ctx, arg.ID, "publication is not in PUBLISHING status", err)
	}
	return row, nil
}

const markPublicationFailedSQL = `
UPDATE publications
SET status     = 'FAILED',
    updated_at = $2
WHERE id = $1
  AND status IN ('PENDING', 'PUBLISHING')
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
`

func (q *Queries) MarkPublicationFailed(ctx context.Context, id uuid.UUID, updatedAt time.Time) (PublicationRow, error) {
	if id == uuid.Nil {
		return PublicationRow{}, domain.BadRequest("INVALID_ID", "publication id must not be nil")
	}
	now := normalizeTimestamp(updatedAt)
	var row PublicationRow
	err := scanPublicationRow(q.db.QueryRow(ctx, markPublicationFailedSQL, id, now), &row)
	if err != nil {
		return PublicationRow{}, q.disambiguatePublicationConflict(ctx, id, "publication cannot transition to FAILED from current status", err)
	}
	return row, nil
}

func (q *Queries) disambiguatePublicationConflict(ctx context.Context, id uuid.UUID, msg string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		var existing PublicationRow
		lookupErr := scanPublicationRow(q.db.QueryRow(ctx, getPublicationByIDSQL, id), &existing)
		if lookupErr == nil {
			return domain.Conflict("PUBLICATION_STATE_CONFLICT", msg)
		}
		if !errors.Is(lookupErr, pgx.ErrNoRows) {
			return MapError(lookupErr)
		}
	}
	return MapError(err)
}

// --- publication_attempts ---

type CreatePublicationAttemptParams struct {
	ID             uuid.UUID
	PublicationID  uuid.UUID
	AttemptNumber  int
	ManifestDigest string
	StartedAt      time.Time
}

const createPublicationAttemptSQL = `
INSERT INTO publication_attempts (
    id, publication_id, attempt_number, manifest_digest, status, started_at
) VALUES (
    $1, $2, $3, $4, 'STARTED', $5
)
RETURNING id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
`

func (q *Queries) CreatePublicationAttempt(ctx context.Context, arg CreatePublicationAttemptParams) (PublicationAttemptRow, error) {
	if arg.PublicationID == uuid.Nil {
		return PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_id must not be nil")
	}
	if arg.AttemptNumber < 1 {
		return PublicationAttemptRow{}, domain.BadRequest("INVALID_ATTEMPT_NUMBER", "attempt_number must be >= 1")
	}
	manifestDigest, err := domain.ParseSHA256Digest(arg.ManifestDigest)
	if err != nil {
		return PublicationAttemptRow{}, err
	}
	id := arg.ID
	if id == uuid.Nil {
		id, err = domain.NewID()
		if err != nil {
			return PublicationAttemptRow{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_attempt id must be UUIDv7")
	}
	startedAt := normalizeTimestamp(arg.StartedAt)

	var row PublicationAttemptRow
	err = scanPublicationAttemptRow(q.db.QueryRow(ctx, createPublicationAttemptSQL,
		id,
		arg.PublicationID,
		arg.AttemptNumber,
		manifestDigest,
		startedAt,
	), &row)
	if err != nil {
		return PublicationAttemptRow{}, MapError(err)
	}
	return row, nil
}

const getPublicationAttemptByIDSQL = `
SELECT id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
FROM publication_attempts
WHERE id = $1
`

func (q *Queries) GetPublicationAttemptByID(ctx context.Context, id uuid.UUID) (PublicationAttemptRow, error) {
	if id == uuid.Nil {
		return PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_attempt id must not be nil")
	}
	var row PublicationAttemptRow
	err := scanPublicationAttemptRow(q.db.QueryRow(ctx, getPublicationAttemptByIDSQL, id), &row)
	if err != nil {
		return PublicationAttemptRow{}, MapError(err)
	}
	return row, nil
}

const listPublicationAttemptsByPublicationSQL = `
SELECT id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
FROM publication_attempts
WHERE publication_id = $1
ORDER BY attempt_number ASC, id ASC
`

func (q *Queries) ListPublicationAttemptsByPublication(ctx context.Context, publicationID uuid.UUID) ([]PublicationAttemptRow, error) {
	if publicationID == uuid.Nil {
		return nil, domain.BadRequest("INVALID_ID", "publication_id must not be nil")
	}
	rows, err := q.db.Query(ctx, listPublicationAttemptsByPublicationSQL, publicationID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]PublicationAttemptRow, 0)
	for rows.Next() {
		var row PublicationAttemptRow
		if err := scanPublicationAttemptRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const completePublicationAttemptSucceededSQL = `
UPDATE publication_attempts
SET status       = 'SUCCEEDED',
    commit_sha   = $2,
    completed_at = $3
WHERE id = $1
  AND status = 'STARTED'
RETURNING id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
`

func (q *Queries) CompletePublicationAttemptSucceeded(ctx context.Context, id uuid.UUID, commitSHA string, completedAt time.Time) (PublicationAttemptRow, error) {
	if id == uuid.Nil {
		return PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_attempt id must not be nil")
	}
	sha, err := domain.ParseGitSHA(commitSHA)
	if err != nil {
		return PublicationAttemptRow{}, err
	}
	ts := normalizeTimestamp(completedAt)

	var row PublicationAttemptRow
	err = scanPublicationAttemptRow(q.db.QueryRow(ctx, completePublicationAttemptSucceededSQL, id, sha, ts), &row)
	if err != nil {
		return PublicationAttemptRow{}, q.disambiguatePublicationAttemptConflict(ctx, id, err)
	}
	return row, nil
}

const completePublicationAttemptFailedSQL = `
UPDATE publication_attempts
SET status        = 'FAILED',
    error_code    = $2,
    error_message = $3,
    completed_at  = $4
WHERE id = $1
  AND status = 'STARTED'
RETURNING id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
`

func (q *Queries) CompletePublicationAttemptFailed(ctx context.Context, id uuid.UUID, errorCode, errorMessage string, completedAt time.Time) (PublicationAttemptRow, error) {
	if id == uuid.Nil {
		return PublicationAttemptRow{}, domain.BadRequest("INVALID_ID", "publication_attempt id must not be nil")
	}
	ts := normalizeTimestamp(completedAt)

	var row PublicationAttemptRow
	err := scanPublicationAttemptRow(q.db.QueryRow(ctx, completePublicationAttemptFailedSQL,
		id,
		nilIfEmpty(errorCode),
		nilIfEmpty(errorMessage),
		ts,
	), &row)
	if err != nil {
		return PublicationAttemptRow{}, q.disambiguatePublicationAttemptConflict(ctx, id, err)
	}
	return row, nil
}

func (q *Queries) disambiguatePublicationAttemptConflict(ctx context.Context, id uuid.UUID, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		var existing PublicationAttemptRow
		lookupErr := scanPublicationAttemptRow(q.db.QueryRow(ctx, getPublicationAttemptByIDSQL, id), &existing)
		if lookupErr == nil {
			return domain.Conflict("PUBLICATION_ATTEMPT_STATE_CONFLICT", "publication_attempt is not in STARTED status")
		}
		if !errors.Is(lookupErr, pgx.ErrNoRows) {
			return MapError(lookupErr)
		}
	}
	return MapError(err)
}

// --- scan helpers ---

func scanPublicationRow(s rowScanner, row *PublicationRow) error {
	var status string
	if err := s.Scan(
		&row.ID,
		&row.ProposalID,
		&row.BranchRef,
		&row.CommitSHA,
		&row.PullRequestNumber,
		&row.PullRequestURL,
		&status,
		&row.AttemptCount,
		&row.CreatedAt,
		&row.UpdatedAt,
	); err != nil {
		return err
	}
	row.Status = domain.PublicationStatus(status)
	return nil
}

func scanPublicationAttemptRow(s rowScanner, row *PublicationAttemptRow) error {
	return s.Scan(
		&row.ID,
		&row.PublicationID,
		&row.AttemptNumber,
		&row.ManifestDigest,
		&row.Status,
		&row.CommitSHA,
		&row.ErrorCode,
		&row.ErrorMessage,
		&row.StartedAt,
		&row.CompletedAt,
	)
}
