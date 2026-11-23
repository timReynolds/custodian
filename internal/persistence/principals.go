package persistence

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const getPrincipalByIDSQL = `
SELECT id, kind, issuer, subject, display_name, verified_email, groups, created_at
FROM principals
WHERE id = $1
`

func (q *Queries) GetPrincipalByID(ctx context.Context, id uuid.UUID) (PrincipalRow, error) {
	if id == uuid.Nil {
		return PrincipalRow{}, domain.BadRequest("INVALID_ID", "principal id must not be nil")
	}
	var row PrincipalRow
	var kind string
	err := q.db.QueryRow(ctx, getPrincipalByIDSQL, id).Scan(
		&row.ID,
		&kind,
		&row.Issuer,
		&row.Subject,
		&row.DisplayName,
		&row.VerifiedEmail,
		&row.Groups,
		&row.CreatedAt,
	)
	if err != nil {
		return PrincipalRow{}, MapError(err)
	}
	row.Kind = domain.PrincipalKind(kind)
	if row.Groups == nil {
		row.Groups = []string{}
	}
	return row, nil
}

const getPrincipalByIssuerSubjectSQL = `
SELECT id, kind, issuer, subject, display_name, verified_email, groups, created_at
FROM principals
WHERE issuer = $1 AND subject = $2
`

func (q *Queries) GetPrincipalByIssuerSubject(ctx context.Context, issuer, subject string) (PrincipalRow, error) {
	if issuer == "" || subject == "" {
		return PrincipalRow{}, domain.BadRequest("INVALID_PRINCIPAL", "issuer and subject must not be empty")
	}
	var row PrincipalRow
	var kind string
	err := q.db.QueryRow(ctx, getPrincipalByIssuerSubjectSQL, issuer, subject).Scan(
		&row.ID,
		&kind,
		&row.Issuer,
		&row.Subject,
		&row.DisplayName,
		&row.VerifiedEmail,
		&row.Groups,
		&row.CreatedAt,
	)
	if err != nil {
		return PrincipalRow{}, MapError(err)
	}
	row.Kind = domain.PrincipalKind(kind)
	if row.Groups == nil {
		row.Groups = []string{}
	}
	return row, nil
}

const upsertPrincipalByIssuerSubjectSQL = `
INSERT INTO principals (
    id, kind, issuer, subject, display_name, verified_email, groups, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (issuer, subject) DO UPDATE SET
    display_name   = COALESCE(NULLIF(EXCLUDED.display_name, ''), principals.display_name),
    verified_email = COALESCE(NULLIF(EXCLUDED.verified_email, ''), principals.verified_email),
    groups         = CASE WHEN cardinality(EXCLUDED.groups) > 0 THEN EXCLUDED.groups ELSE principals.groups END
RETURNING id, kind, issuer, subject, display_name, verified_email, groups, created_at
`

const upsertPrincipalByIDSQL = `
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
RETURNING id, kind, issuer, subject, display_name, verified_email, groups, created_at
`

type UpsertPrincipalParams struct {
	ID            uuid.UUID
	Kind          domain.PrincipalKind
	Issuer        string
	Subject       string
	DisplayName   string
	VerifiedEmail string
	Groups        []string
	CreatedAt     time.Time
}

func (q *Queries) UpsertPrincipal(ctx context.Context, arg UpsertPrincipalParams) (PrincipalRow, error) {
	if !arg.Kind.IsValid() {
		return PrincipalRow{}, domain.BadRequest("INVALID_PRINCIPAL_KIND", "invalid principal kind")
	}
	if (arg.Issuer == "") != (arg.Subject == "") {
		return PrincipalRow{}, domain.BadRequest("INVALID_PRINCIPAL", "issuer and subject must both be set or both be empty")
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return PrincipalRow{}, err
		}
	}
	createdAt := arg.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		createdAt = createdAt.UTC().Truncate(time.Microsecond)
	}
	groups := arg.Groups
	if groups == nil {
		groups = []string{}
	}

	sqlStmt := upsertPrincipalByIDSQL
	if arg.Issuer != "" && arg.Subject != "" {
		sqlStmt = upsertPrincipalByIssuerSubjectSQL
	}

	var row PrincipalRow
	var kind string
	err := q.db.QueryRow(ctx, sqlStmt,
		id,
		string(arg.Kind),
		nilIfEmpty(arg.Issuer),
		nilIfEmpty(arg.Subject),
		nilIfEmpty(arg.DisplayName),
		nilIfEmpty(arg.VerifiedEmail),
		groups,
		createdAt,
	).Scan(
		&row.ID,
		&kind,
		&row.Issuer,
		&row.Subject,
		&row.DisplayName,
		&row.VerifiedEmail,
		&row.Groups,
		&row.CreatedAt,
	)
	if err != nil {
		return PrincipalRow{}, MapError(err)
	}
	row.Kind = domain.PrincipalKind(kind)
	if row.Groups == nil {
		row.Groups = []string{}
	}
	return row, nil
}
