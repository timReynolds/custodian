package migrations

import "embed"

// FS contains embedded PostgreSQL schema migrations.
//
//go:embed *.sql
var FS embed.FS
