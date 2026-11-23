-- name: CreateApproval :one
INSERT INTO approvals (
    id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
RETURNING id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at;

-- name: GetApprovalByID :one
SELECT id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
FROM approvals
WHERE id = $1;

-- name: ListApprovalsByProposal :many
SELECT id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
FROM approvals
WHERE proposal_id = $1
ORDER BY created_at DESC, id DESC;

-- name: ListActiveApprovalsForDecision :many
SELECT id, proposal_id, reviewer_id, policy_decision_id, manifest_digest, decision, comment, revoked_at, created_at
FROM approvals
WHERE proposal_id = $1
  AND policy_decision_id = $2
  AND manifest_digest = $3
  AND decision = 'APPROVE'
  AND revoked_at IS NULL
ORDER BY created_at ASC, id ASC;

-- name: HasActiveApprovalByReviewer :one
SELECT EXISTS (
    SELECT 1
    FROM approvals
    WHERE proposal_id = $1
      AND policy_decision_id = $2
      AND reviewer_id = $3
      AND manifest_digest = $4
      AND decision = 'APPROVE'
      AND revoked_at IS NULL
);

-- name: RevokeApprovalsForProposal :execrows
UPDATE approvals
SET revoked_at = $2
WHERE proposal_id = $1
  AND revoked_at IS NULL;

-- name: CreateApprovalRequirement :one
INSERT INTO approval_requirements (
    id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, 0, $7
)
RETURNING id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at;

-- name: GetApprovalRequirementByID :one
SELECT id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
FROM approval_requirements
WHERE id = $1;

-- name: ListApprovalRequirementsByProposal :many
SELECT id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
FROM approval_requirements
WHERE proposal_id = $1
ORDER BY created_at ASC, id ASC;

-- name: ListApprovalRequirementsByPolicyDecision :many
SELECT id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at
FROM approval_requirements
WHERE policy_decision_id = $1
ORDER BY created_at ASC, id ASC;

-- name: IncrementApprovalRequirementSatisfaction :one
UPDATE approval_requirements
SET satisfied_count = satisfied_count + 1,
    satisfied_at    = CASE
        WHEN satisfied_count + 1 >= minimum_approvals AND satisfied_at IS NULL THEN $2
        ELSE satisfied_at
    END
WHERE id = $1
RETURNING id, proposal_id, policy_decision_id, requirement_type, reviewer_group,
    minimum_approvals, satisfied_count, satisfied_at, created_at;

-- name: ResetApprovalRequirementsForPolicyDecision :execrows
UPDATE approval_requirements
SET satisfied_count = 0,
    satisfied_at    = NULL
WHERE policy_decision_id = $1;
