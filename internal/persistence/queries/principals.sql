-- name: GetPrincipalByID :one
SELECT id, kind, issuer, subject, display_name, verified_email, groups, created_at
FROM principals
WHERE id = $1;

-- name: GetPrincipalByIssuerSubject :one
SELECT id, kind, issuer, subject, display_name, verified_email, groups, created_at
FROM principals
WHERE issuer = $1 AND subject = $2;

-- name: UpsertPrincipalByIssuerSubject :one
INSERT INTO principals (
    id, kind, issuer, subject, display_name, verified_email, groups, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (issuer, subject) DO UPDATE SET
    display_name   = COALESCE(NULLIF(EXCLUDED.display_name, ''), principals.display_name),
    verified_email = COALESCE(NULLIF(EXCLUDED.verified_email, ''), principals.verified_email),
    groups         = CASE WHEN cardinality(EXCLUDED.groups) > 0 THEN EXCLUDED.groups ELSE principals.groups END
RETURNING id, kind, issuer, subject, display_name, verified_email, groups, created_at;

-- name: UpsertPrincipalByID :one
INSERT INTO principals (
    id, kind, issuer, subject, display_name, verified_email, groups, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (id) DO UPDATE SET
    issuer         = COALESCE(EXCLUDED.issuer, principals.issuer),
    subject        = COALESCE(EXCLUDED.subject, principals.subject),
    display_name   = COALESCE(NULLIF(EXCLUDED.display_name, ''), principals.display_name),
    verified_email = COALESCE(NULLIF(EXCLUDED.verified_email, ''), principals.verified_email),
    groups         = CASE WHEN cardinality(EXCLUDED.groups) > 0 THEN EXCLUDED.groups ELSE principals.groups END
RETURNING id, kind, issuer, subject, display_name, verified_email, groups, created_at;
