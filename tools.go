//go:build tools

// Package custodian retains pre-seeded M1 Go module dependencies in go.mod and go.sum
// so `go mod tidy` remains idempotent prior to M1.2-M1.4 package implementations,
// without adding any runtime dependencies to compiled binaries or violating publisher isolation.
package custodian

import (
	_ "cloud.google.com/go/storage"
	_ "github.com/coreos/go-oidc/v3/oidc"
	_ "github.com/go-chi/chi/v5"
	_ "github.com/go-chi/chi/v5/middleware"
	_ "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/google/cel-go/cel"
	_ "github.com/google/go-github/v75/github"
	_ "github.com/google/uuid"
	_ "github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/pb33f/libopenapi"
	_ "github.com/pb33f/libopenapi-validator"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/collectors"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	_ "go.opentelemetry.io/otel"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	_ "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	_ "go.opentelemetry.io/otel/sdk/resource"
	_ "go.opentelemetry.io/otel/sdk/trace"
	_ "go.opentelemetry.io/otel/sdk/trace/tracetest"
	_ "go.opentelemetry.io/otel/trace"
	_ "gopkg.in/yaml.v3"
)
