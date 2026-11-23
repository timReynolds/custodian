package persistence

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX is the sqlc-compatible database query interface implemented by *pgxpool.Pool, *pgx.Conn, and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Queries provides sqlc-compatible typed query execution against a DBTX.
type Queries struct {
	db DBTX
}

// New constructs a Queries instance backed by db.
func New(db DBTX) *Queries {
	return &Queries{db: db}
}

// WithTx returns a copy of Queries bound to the given pgx.Tx.
func (q *Queries) WithTx(tx pgx.Tx) *Queries {
	return &Queries{db: tx}
}

// DB returns the underlying DBTX.
func (q *Queries) DB() DBTX {
	return q.db
}
