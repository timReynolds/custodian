package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/timreynolds/custodian/internal/domain"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type IdempotencyReserveInput struct {
	PrincipalID    uuid.UUID
	Method         string
	Route          string
	IdempotencyKey string
	RequestHash    string
	LockTTL        time.Duration
	TTL            time.Duration
	Now            time.Time
}

type IdempotencyReservation struct {
	Acquired bool
	Replay   bool
	Record   IdempotencyKeyRow
}

type FinalizeIdempotencyParams struct {
	PrincipalID         uuid.UUID
	Method              string
	Route               string
	IdempotencyKey      string
	ExpectedLockedUntil time.Time
	ResponseStatus      int
	ResponseHeaders     json.RawMessage
	ResponseBody        json.RawMessage
	CompletedAt         time.Time
	ExpiresAt           time.Time
}

const tryInsertIdempotencyKeySQL = `
INSERT INTO idempotency_keys (
    principal_id, method, route, idempotency_key, request_hash, status, locked_until, created_at, expires_at
) VALUES (
    $1, $2, $3, $4, $5, 'IN_PROGRESS', $6, $7, $8
)
ON CONFLICT (principal_id, method, route, idempotency_key) DO NOTHING
`

const getIdempotencyKeyForUpdateSQL = `
SELECT principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
FROM idempotency_keys
WHERE principal_id = $1 AND method = $2 AND route = $3 AND idempotency_key = $4
FOR UPDATE
`

const getIdempotencyKeySQL = `
SELECT principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
FROM idempotency_keys
WHERE principal_id = $1 AND method = $2 AND route = $3 AND idempotency_key = $4
`

const takeoverStaleIdempotencyKeySQL = `
UPDATE idempotency_keys
SET locked_until = $5,
    expires_at   = $6
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND status = 'IN_PROGRESS'
  AND locked_until <= $7
RETURNING principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
`

const resetExpiredIdempotencyKeySQL = `
UPDATE idempotency_keys
SET request_hash     = $5,
    status           = 'IN_PROGRESS',
    response_status  = NULL,
    response_headers = '{}'::jsonb,
    response_body    = NULL,
    locked_until     = $6,
    created_at       = $7,
    completed_at     = NULL,
    expires_at       = $8
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND expires_at <= $7
RETURNING principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
`

const finalizeIdempotencyKeySQL = `
UPDATE idempotency_keys
SET status           = 'COMPLETED',
    response_status  = $5,
    response_headers = $6,
    response_body    = $7,
    completed_at     = $8,
    expires_at       = $9
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND status = 'IN_PROGRESS'
  AND ($10::timestamptz IS NULL OR locked_until = $10::timestamptz)
RETURNING principal_id, method, route, idempotency_key, request_hash, status,
    response_status, response_headers, response_body, locked_until, created_at, completed_at, expires_at
`

const deleteExpiredIdempotencyKeysSQL = `
DELETE FROM idempotency_keys
WHERE expires_at <= $1
`

func validateIdempotencyScope(principalID uuid.UUID, method, route, key string) error {
	if principalID == uuid.Nil {
		return domain.BadRequest("INVALID_PRINCIPAL_ID", "principal_id must not be nil")
	}
	if method == "" || route == "" {
		return domain.BadRequest("INVALID_IDEMPOTENCY_SCOPE", "method and route must not be empty")
	}
	if !idempotencyKeyPattern.MatchString(key) {
		return domain.BadRequest("INVALID_IDEMPOTENCY_KEY", "idempotency key must match ^[A-Za-z0-9._-]{1,128}$")
	}
	return nil
}

func (q *Queries) GetIdempotencyKey(ctx context.Context, principalID uuid.UUID, method, route, key string) (IdempotencyKeyRow, error) {
	if err := validateIdempotencyScope(principalID, method, route, key); err != nil {
		return IdempotencyKeyRow{}, err
	}
	var row IdempotencyKeyRow
	err := scanIdempotencyRow(q.db.QueryRow(ctx, getIdempotencyKeySQL, principalID, method, route, key), &row)
	if err != nil {
		return IdempotencyKeyRow{}, MapError(err)
	}
	return row, nil
}

func (q *Queries) FinalizeIdempotencyKey(ctx context.Context, arg FinalizeIdempotencyParams) (IdempotencyKeyRow, error) {
	if err := validateIdempotencyScope(arg.PrincipalID, arg.Method, arg.Route, arg.IdempotencyKey); err != nil {
		return IdempotencyKeyRow{}, err
	}
	headers := arg.ResponseHeaders
	if len(headers) == 0 {
		headers = json.RawMessage(`{}`)
	}
	completedAt := arg.CompletedAt
	if completedAt.IsZero() {
		completedAt = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		completedAt = completedAt.UTC().Truncate(time.Microsecond)
	}
	expiresAt := arg.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = completedAt.Add(24 * time.Hour)
	} else {
		expiresAt = expiresAt.UTC().Truncate(time.Microsecond)
	}
	var bodyArg any
	if len(arg.ResponseBody) > 0 {
		bodyArg = arg.ResponseBody
	}
	var expectedLockedUntil *time.Time
	if !arg.ExpectedLockedUntil.IsZero() {
		t := arg.ExpectedLockedUntil.UTC().Truncate(time.Microsecond)
		expectedLockedUntil = &t
	}

	var row IdempotencyKeyRow
	err := scanIdempotencyRow(q.db.QueryRow(ctx, finalizeIdempotencyKeySQL,
		arg.PrincipalID,
		arg.Method,
		arg.Route,
		arg.IdempotencyKey,
		arg.ResponseStatus,
		headers,
		bodyArg,
		completedAt,
		expiresAt,
		expectedLockedUntil,
	), &row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var existing IdempotencyKeyRow
			lookupErr := scanIdempotencyRow(q.db.QueryRow(ctx, getIdempotencyKeySQL,
				arg.PrincipalID,
				arg.Method,
				arg.Route,
				arg.IdempotencyKey,
			), &existing)
			if lookupErr == nil {
				return IdempotencyKeyRow{}, domain.Conflict("IDEMPOTENCY_LOCK_LOST", "idempotency key lock is no longer held by caller")
			}
			if !errors.Is(lookupErr, pgx.ErrNoRows) {
				return IdempotencyKeyRow{}, MapError(lookupErr)
			}
		}
		return IdempotencyKeyRow{}, MapError(err)
	}
	return row, nil
}

func (q *Queries) DeleteExpiredIdempotencyKeys(ctx context.Context, asOf time.Time) (int64, error) {
	if asOf.IsZero() {
		asOf = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		asOf = asOf.UTC().Truncate(time.Microsecond)
	}
	tag, err := q.db.Exec(ctx, deleteExpiredIdempotencyKeysSQL, asOf)
	if err != nil {
		return 0, MapError(err)
	}
	return tag.RowsAffected(), nil
}

// ReserveIdempotencyKeyInTx performs atomic idempotency reservation inside an active transaction.
func (q *Queries) ReserveIdempotencyKeyInTx(ctx context.Context, input IdempotencyReserveInput) (IdempotencyReservation, error) {
	if err := validateIdempotencyScope(input.PrincipalID, input.Method, input.Route, input.IdempotencyKey); err != nil {
		return IdempotencyReservation{}, err
	}
	reqHash, err := domain.ParseSHA256Digest(input.RequestHash)
	if err != nil {
		return IdempotencyReservation{}, err
	}
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Microsecond)
	} else {
		now = now.UTC().Truncate(time.Microsecond)
	}
	lockTTL := input.LockTTL
	if lockTTL <= 0 {
		lockTTL = 30 * time.Second
	}
	ttl := input.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	lockedUntil := now.Add(lockTTL)
	expiresAt := now.Add(ttl)

	var existing IdempotencyKeyRow
	foundExisting := false
	for attempt := 0; attempt < 3; attempt++ {
		tag, err := q.db.Exec(ctx, tryInsertIdempotencyKeySQL,
			input.PrincipalID,
			input.Method,
			input.Route,
			input.IdempotencyKey,
			reqHash,
			lockedUntil,
			now,
			expiresAt,
		)
		if err != nil {
			return IdempotencyReservation{}, MapError(err)
		}
		if tag.RowsAffected() == 1 {
			var row IdempotencyKeyRow
			if err := scanIdempotencyRow(q.db.QueryRow(ctx, getIdempotencyKeySQL, input.PrincipalID, input.Method, input.Route, input.IdempotencyKey), &row); err != nil {
				return IdempotencyReservation{}, MapError(err)
			}
			return IdempotencyReservation{
				Acquired: true,
				Replay:   false,
				Record:   row,
			}, nil
		}

		if err := scanIdempotencyRow(q.db.QueryRow(ctx, getIdempotencyKeyForUpdateSQL, input.PrincipalID, input.Method, input.Route, input.IdempotencyKey), &existing); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// Concurrent DeleteExpiredIdempotencyKeys removed the row between insert conflict and FOR UPDATE; retry.
				continue
			}
			return IdempotencyReservation{}, MapError(err)
		}
		foundExisting = true
		break
	}
	if !foundExisting {
		return IdempotencyReservation{}, domain.Conflict("IDEMPOTENCY_CONFLICT", "idempotency key concurrently expired; retry request")
	}

	if !existing.ExpiresAt.After(now) {
		var reset IdempotencyKeyRow
		if err := scanIdempotencyRow(q.db.QueryRow(ctx, resetExpiredIdempotencyKeySQL,
			input.PrincipalID,
			input.Method,
			input.Route,
			input.IdempotencyKey,
			reqHash,
			lockedUntil,
			now,
			expiresAt,
		), &reset); err != nil {
			return IdempotencyReservation{}, MapError(err)
		}
		return IdempotencyReservation{
			Acquired: true,
			Replay:   false,
			Record:   reset,
		}, nil
	}

	if existing.RequestHash != reqHash {
		return IdempotencyReservation{}, domain.Conflict("IDEMPOTENCY_CONFLICT", "idempotency key reused with different request payload")
	}

	if existing.Status == "COMPLETED" {
		return IdempotencyReservation{
			Acquired: false,
			Replay:   true,
			Record:   existing,
		}, nil
	}

	if existing.LockedUntil.After(now) {
		return IdempotencyReservation{}, domain.Conflict("IDEMPOTENCY_IN_PROGRESS", "request with this idempotency key is currently in progress")
	}

	var taken IdempotencyKeyRow
	if err := scanIdempotencyRow(q.db.QueryRow(ctx, takeoverStaleIdempotencyKeySQL,
		input.PrincipalID,
		input.Method,
		input.Route,
		input.IdempotencyKey,
		lockedUntil,
		expiresAt,
		now,
	), &taken); err != nil {
		return IdempotencyReservation{}, MapError(err)
	}
	return IdempotencyReservation{
		Acquired: true,
		Replay:   false,
		Record:   taken,
	}, nil
}

func scanIdempotencyRow(s rowScanner, row *IdempotencyKeyRow) error {
	return s.Scan(
		&row.PrincipalID,
		&row.Method,
		&row.Route,
		&row.IdempotencyKey,
		&row.RequestHash,
		&row.Status,
		&row.ResponseStatus,
		&row.ResponseHeaders,
		&row.ResponseBody,
		&row.LockedUntil,
		&row.CreatedAt,
		&row.CompletedAt,
		&row.ExpiresAt,
	)
}
