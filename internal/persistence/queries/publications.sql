-- name: CreatePublication :one
INSERT INTO publications (
    id, proposal_id, branch_ref, status, attempt_count, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $5
)
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at;

-- name: TryInsertPublication :execrows
INSERT INTO publications (
    id, proposal_id, branch_ref, status, attempt_count, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, 0, $5, $5
)
ON CONFLICT (proposal_id) DO NOTHING;

-- name: GetPublicationByID :one
SELECT id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
FROM publications
WHERE id = $1;

-- name: GetPublicationByProposalID :one
SELECT id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at
FROM publications
WHERE proposal_id = $1;

-- name: TransitionPublicationToPublishing :one
UPDATE publications
SET status        = 'PUBLISHING',
    attempt_count = attempt_count + 1,
    updated_at    = $2
WHERE id = $1
  AND status IN ('PENDING', 'FAILED', 'PUBLISHING')
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at;

-- name: MarkPublicationPublished :one
UPDATE publications
SET status              = 'PUBLISHED',
    commit_sha          = $2,
    pull_request_number = $3,
    pull_request_url    = $4,
    updated_at          = $5
WHERE id = $1
  AND status = 'PUBLISHING'
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at;

-- name: MarkPublicationFailed :one
UPDATE publications
SET status     = 'FAILED',
    updated_at = $2
WHERE id = $1
  AND status IN ('PENDING', 'PUBLISHING')
RETURNING id, proposal_id, branch_ref, commit_sha, pull_request_number, pull_request_url,
    status, attempt_count, created_at, updated_at;

-- name: CreatePublicationAttempt :one
INSERT INTO publication_attempts (
    id, publication_id, attempt_number, manifest_digest, status, started_at
) VALUES (
    $1, $2, $3, $4, 'STARTED', $5
)
RETURNING id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at;

-- name: GetPublicationAttemptByID :one
SELECT id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
FROM publication_attempts
WHERE id = $1;

-- name: ListPublicationAttemptsByPublication :many
SELECT id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at
FROM publication_attempts
WHERE publication_id = $1
ORDER BY attempt_number ASC, id ASC;

-- name: CompletePublicationAttemptSucceeded :one
UPDATE publication_attempts
SET status       = 'SUCCEEDED',
    commit_sha   = $2,
    completed_at = $3
WHERE id = $1
  AND status = 'STARTED'
RETURNING id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at;

-- name: CompletePublicationAttemptFailed :one
UPDATE publication_attempts
SET status        = 'FAILED',
    error_code    = $2,
    error_message = $3,
    completed_at  = $4
WHERE id = $1
  AND status = 'STARTED'
RETURNING id, publication_id, attempt_number, manifest_digest, status, commit_sha,
    error_code, error_message, started_at, completed_at;
