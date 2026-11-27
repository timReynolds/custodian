package persistence

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const repositoryColumns = `id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at`

const getRepositoryByIDSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE id = $1
`

func (q *Queries) GetRepositoryByID(ctx context.Context, id uuid.UUID) (RepositoryRow, error) {
	if id == uuid.Nil {
		return RepositoryRow{}, domain.BadRequest("INVALID_ID", "repository id must not be nil")
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByIDSQL, id), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const getRepositoryByGitHubIDSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE github_repository_id = $1
`

func (q *Queries) GetRepositoryByGitHubID(ctx context.Context, githubRepoID int64) (RepositoryRow, error) {
	if githubRepoID <= 0 {
		return RepositoryRow{}, domain.BadRequest("INVALID_REPOSITORY_ID", "github_repository_id must be positive")
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByGitHubIDSQL, githubRepoID), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const getRepositoryByFullNameSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE full_name = $1
ORDER BY created_at DESC, id DESC
LIMIT 1
`

func (q *Queries) GetRepositoryByFullName(ctx context.Context, fullName string) (RepositoryRow, error) {
	trimmed := strings.TrimSpace(fullName)
	if _, _, err := (domain.Repository{FullName: trimmed}).OwnerRepo(); err != nil {
		return RepositoryRow{}, err
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByFullNameSQL, trimmed), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const getRepositoryByGitRemoteURLSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
WHERE git_remote_url = $1
ORDER BY created_at DESC, id DESC
LIMIT 1
`

func (q *Queries) GetRepositoryByGitRemoteURL(ctx context.Context, remoteURL string) (RepositoryRow, error) {
	trimmed := strings.TrimSpace(remoteURL)
	if trimmed == "" {
		return RepositoryRow{}, domain.BadRequest("INVALID_REMOTE_URL", "git_remote_url must not be empty")
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, getRepositoryByGitRemoteURLSQL, trimmed), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

const listRepositoriesSQL = `
SELECT id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
FROM repositories
ORDER BY created_at DESC, id DESC
LIMIT $1
`

func (q *Queries) ListRepositories(ctx context.Context, limit int32) ([]RepositoryRow, error) {
	if limit <= 0 {
		limit = 100
	} else if limit > 1000 {
		limit = 1000
	}
	rows, err := q.db.Query(ctx, listRepositoriesSQL, limit)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	out := make([]RepositoryRow, 0)
	for rows.Next() {
		var row RepositoryRow
		if err := scanRepositoryRow(rows, &row); err != nil {
			return nil, MapError(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

const updateRepositoryEgressModeSQL = `
UPDATE repositories
SET egress_mode            = $2,
    passive_audit_delivery = $3
WHERE id = $1
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
`

func (q *Queries) UpdateRepositoryEgressMode(ctx context.Context, id uuid.UUID, egressMode domain.EgressMode, delivery domain.PassiveAuditDelivery) (RepositoryRow, error) {
	if id == uuid.Nil {
		return RepositoryRow{}, domain.BadRequest("INVALID_ID", "repository id must not be nil")
	}
	if !egressMode.IsValid() {
		return RepositoryRow{}, domain.BadRequest("INVALID_EGRESS_MODE", "invalid egress_mode")
	}
	if delivery == "" {
		delivery = domain.PassiveAuditDeliveryAsync
	}
	if !delivery.IsValid() {
		return RepositoryRow{}, domain.BadRequest("INVALID_PASSIVE_AUDIT_DELIVERY", "invalid passive_audit_delivery")
	}
	var row RepositoryRow
	if err := scanRepositoryRow(q.db.QueryRow(ctx, updateRepositoryEgressModeSQL, id, string(egressMode), string(delivery)), &row); err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

type UpsertRepositoryParams struct {
	ID                      uuid.UUID
	GitHubRepositoryID      int64
	GitHubInstallationID    int64
	FullName                string
	Classification          domain.Classification
	Enabled                 bool
	AllowedModelRoutes      []string
	MaxConcurrentOperations int
	EgressMode              domain.EgressMode
	PassiveAuditDelivery    domain.PassiveAuditDelivery
	GitRemoteURL            string
	RemoteHost              string
	RegisteredDestination   *bool
	External                *bool
	CreatedAt               time.Time
}

const createRepositorySQL = `
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations,
    egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15
)
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
`

const upsertRepositorySQL = `
INSERT INTO repositories (
    id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations,
    egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12, $13, $14, $15
)
ON CONFLICT (github_repository_id) DO UPDATE SET
    github_installation_id    = EXCLUDED.github_installation_id,
    full_name                 = EXCLUDED.full_name,
    classification            = EXCLUDED.classification,
    enabled                   = EXCLUDED.enabled,
    allowed_model_routes      = EXCLUDED.allowed_model_routes,
    max_concurrent_operations = EXCLUDED.max_concurrent_operations,
    egress_mode               = CASE WHEN $16::boolean THEN EXCLUDED.egress_mode ELSE repositories.egress_mode END,
    passive_audit_delivery    = CASE WHEN $17::boolean THEN EXCLUDED.passive_audit_delivery ELSE repositories.passive_audit_delivery END,
    git_remote_url            = COALESCE(EXCLUDED.git_remote_url, repositories.git_remote_url),
    remote_host               = CASE WHEN $18::boolean THEN EXCLUDED.remote_host ELSE repositories.remote_host END,
    registered_destination    = CASE WHEN $19::boolean THEN EXCLUDED.registered_destination ELSE repositories.registered_destination END,
    external                  = CASE WHEN $20::boolean THEN EXCLUDED.external ELSE repositories.external END
RETURNING id, github_repository_id, github_installation_id, full_name, classification, enabled, allowed_model_routes, max_concurrent_operations, egress_mode, passive_audit_delivery, git_remote_url, remote_host, registered_destination, external, created_at
`

type normalizedRepoArgs struct {
	id            uuid.UUID
	routes        []string
	maxConc       int
	egressMode    domain.EgressMode
	setEgressMode bool
	delivery      domain.PassiveAuditDelivery
	setDelivery   bool
	gitRemoteURL  *string
	remoteHost    string
	setRemoteHost bool
	registered    bool
	setRegistered bool
	external      bool
	setExternal   bool
	createdAt     time.Time
}

func validateAndNormalizeRepoArgs(arg UpsertRepositoryParams) (normalizedRepoArgs, error) {
	if arg.GitHubRepositoryID <= 0 || arg.GitHubInstallationID <= 0 {
		return normalizedRepoArgs{}, domain.BadRequest("INVALID_REPOSITORY", "github repository and installation IDs must be positive")
	}
	if !arg.Classification.IsValid() {
		return normalizedRepoArgs{}, domain.BadRequest("INVALID_CLASSIFICATION", "invalid repository classification")
	}
	repo := domain.Repository{
		FullName: arg.FullName,
	}
	if _, _, err := repo.OwnerRepo(); err != nil {
		return normalizedRepoArgs{}, err
	}
	id := arg.ID
	if id == uuid.Nil {
		var err error
		id, err = domain.NewID()
		if err != nil {
			return normalizedRepoArgs{}, err
		}
	} else if !domain.IsUUIDv7(id) {
		return normalizedRepoArgs{}, domain.BadRequest("INVALID_ID", "repository id must be UUIDv7")
	}
	routes := arg.AllowedModelRoutes
	if routes == nil {
		routes = []string{}
	}
	maxConc := arg.MaxConcurrentOperations
	if maxConc <= 0 {
		maxConc = 10
	}
	setEgressMode := arg.EgressMode != ""
	egressMode := arg.EgressMode
	if !setEgressMode {
		egressMode = domain.EgressModePassiveAudit
	} else if !egressMode.IsValid() {
		return normalizedRepoArgs{}, domain.BadRequest("INVALID_EGRESS_MODE", "invalid egress_mode")
	}
	setDelivery := arg.PassiveAuditDelivery != ""
	delivery := arg.PassiveAuditDelivery
	if !setDelivery {
		delivery = domain.PassiveAuditDeliveryAsync
	} else if !delivery.IsValid() {
		return normalizedRepoArgs{}, domain.BadRequest("INVALID_PASSIVE_AUDIT_DELIVERY", "invalid passive_audit_delivery")
	}
	trimmedHost := strings.TrimSpace(arg.RemoteHost)
	setRemoteHost := trimmedHost != ""
	if !setRemoteHost {
		trimmedHost = "github.com"
	}
	setRegistered := arg.RegisteredDestination != nil
	registered := true
	if setRegistered {
		registered = *arg.RegisteredDestination
	}
	setExternal := arg.External != nil
	external := false
	if setExternal {
		external = *arg.External
	}
	createdAt := normalizeTimestamp(arg.CreatedAt)
	return normalizedRepoArgs{
		id:            id,
		routes:        routes,
		maxConc:       maxConc,
		egressMode:    egressMode,
		setEgressMode: setEgressMode,
		delivery:      delivery,
		setDelivery:   setDelivery,
		gitRemoteURL:  nilIfEmpty(strings.TrimSpace(arg.GitRemoteURL)),
		remoteHost:    trimmedHost,
		setRemoteHost: setRemoteHost,
		registered:    registered,
		setRegistered: setRegistered,
		external:      external,
		setExternal:   setExternal,
		createdAt:     createdAt,
	}, nil
}

func (q *Queries) CreateRepository(ctx context.Context, arg UpsertRepositoryParams) (RepositoryRow, error) {
	norm, err := validateAndNormalizeRepoArgs(arg)
	if err != nil {
		return RepositoryRow{}, err
	}
	var row RepositoryRow
	err = scanRepositoryRow(q.db.QueryRow(ctx, createRepositorySQL,
		norm.id,
		arg.GitHubRepositoryID,
		arg.GitHubInstallationID,
		arg.FullName,
		string(arg.Classification),
		arg.Enabled,
		norm.routes,
		norm.maxConc,
		string(norm.egressMode),
		string(norm.delivery),
		norm.gitRemoteURL,
		norm.remoteHost,
		norm.registered,
		norm.external,
		norm.createdAt,
	), &row)
	if err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

func (q *Queries) UpsertRepository(ctx context.Context, arg UpsertRepositoryParams) (RepositoryRow, error) {
	norm, err := validateAndNormalizeRepoArgs(arg)
	if err != nil {
		return RepositoryRow{}, err
	}
	var row RepositoryRow
	err = scanRepositoryRow(q.db.QueryRow(ctx, upsertRepositorySQL,
		norm.id,
		arg.GitHubRepositoryID,
		arg.GitHubInstallationID,
		arg.FullName,
		string(arg.Classification),
		arg.Enabled,
		norm.routes,
		norm.maxConc,
		string(norm.egressMode),
		string(norm.delivery),
		norm.gitRemoteURL,
		norm.remoteHost,
		norm.registered,
		norm.external,
		norm.createdAt,
		norm.setEgressMode,
		norm.setDelivery,
		norm.setRemoteHost,
		norm.setRegistered,
		norm.setExternal,
	), &row)
	if err != nil {
		return RepositoryRow{}, MapError(err)
	}
	return row, nil
}

func scanRepositoryRow(s rowScanner, row *RepositoryRow) error {
	var classification, egressMode, delivery string
	if err := s.Scan(
		&row.ID,
		&row.GitHubRepositoryID,
		&row.GitHubInstallationID,
		&row.FullName,
		&classification,
		&row.Enabled,
		&row.AllowedModelRoutes,
		&row.MaxConcurrentOperations,
		&egressMode,
		&delivery,
		&row.GitRemoteURL,
		&row.RemoteHost,
		&row.RegisteredDestination,
		&row.External,
		&row.CreatedAt,
	); err != nil {
		return err
	}
	row.Classification = domain.Classification(classification)
	row.EgressMode = domain.EgressMode(egressMode)
	row.PassiveAuditDelivery = domain.PassiveAuditDelivery(delivery)
	if row.AllowedModelRoutes == nil {
		row.AllowedModelRoutes = []string{}
	}
	return nil
}
