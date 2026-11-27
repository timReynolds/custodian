package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

type callerContextKey struct{}

var idempotencyKeyRegexp = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// CallerFromContext returns the authenticated CallerContext attached by RequireOIDC.
func CallerFromContext(ctx context.Context) (identity.CallerContext, bool) {
	if ctx == nil {
		return identity.CallerContext{}, false
	}
	c, ok := ctx.Value(callerContextKey{}).(identity.CallerContext)
	return c, ok
}

func withCallerContext(ctx context.Context, caller identity.CallerContext) context.Context {
	return context.WithValue(ctx, callerContextKey{}, caller)
}

func isRegularHuman(c identity.CallerContext) bool {
	return c.IsHuman() && !c.IsAuditor() && !c.IsPolicyAdmin()
}

func canReadProposal(c identity.CallerContext, ownerID domain.Principal) bool {
	return canReadProposalByOwnerID(c, ownerID.ID)
}

func canReadProposalByOwnerID(c identity.CallerContext, ownerID uuid.UUID) bool {
	if c.IsController() {
		return true
	}
	if c.Principal.ID == ownerID {
		return true
	}
	return c.IsHuman() && !c.IsAuditor() && !c.IsPolicyAdmin() && c.HasRole("reviewer")
}

func isPushAuditor(c identity.CallerContext) bool {
	return c.IsAuditor() || (c.IsHuman() && c.InGroup("audit-readers"))
}

func isPushAdmin(c identity.CallerContext) bool {
	if !c.IsHuman() || isPushAuditor(c) {
		return false
	}
	return c.IsPolicyAdmin() ||
		c.InGroup("security-admins") ||
		c.InGroup("policy-admins") ||
		c.HasRole("security_admin")
}

func isPushApprover(c identity.CallerContext) bool {
	if !c.IsHuman() || isPushAuditor(c) {
		return false
	}
	return c.IsPolicyAdmin() ||
		c.InGroup("security-admins") ||
		c.InGroup("policy-admins") ||
		c.InGroup("ip-review") ||
		c.InGroup("security-reviewers") ||
		c.HasRole("reviewer") ||
		c.HasRole("security_admin")
}

func canReadAllPushes(c identity.CallerContext) bool {
	return c.IsController() || isPushAuditor(c) || isPushAdmin(c) ||
		(c.IsHuman() && (c.InGroup("ip-review") || c.InGroup("security-reviewers") || c.HasRole("reviewer")))
}

func requireOIDCMiddleware(verifier auth.TokenVerifier, dir *identity.Directory, logger *slog.Logger, dbTimeout time.Duration) func(http.Handler) http.Handler {
	if dbTimeout <= 0 {
		dbTimeout = defaultDBTimeout
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if verifier == nil || dir == nil {
				writeError(w, r, logger, domain.Unavailable("AUTH_UNAVAILABLE", "authentication service is not configured"))
				return
			}
			bearer, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
			if err != nil {
				writeError(w, r, logger, err)
				return
			}
			claims, err := verifier.Verify(r.Context(), bearer)
			if err != nil {
				writeError(w, r, logger, err)
				return
			}
			dbCtx, cancel := withDBTimeoutCause(r.Context(), dbTimeout)
			caller, err := dir.ResolveCaller(dbCtx, claims)
			cancel()
			if err != nil {
				writeError(w, r, logger, mapDBTimeoutError(dbCtx, err))
				return
			}
			next.ServeHTTP(w, r.WithContext(withCallerContext(r.Context(), caller)))
		})
	}
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusResponseWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func observabilityMiddleware(metrics *observability.Metrics, tracer trace.Tracer, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := r.Context()
			var span trace.Span
			if tracer != nil {
				ctx, span = tracer.Start(ctx, r.Method+" "+r.URL.Path,
					trace.WithSpanKind(trace.SpanKindServer),
					trace.WithAttributes(
						attribute.String("http.method", r.Method),
					),
				)
				r = r.WithContext(ctx)
			}

			sw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				dur := time.Since(start)
				route := routePattern(r)
				if span != nil {
					span.SetAttributes(
						attribute.String("http.route", route),
						attribute.Int("http.status_code", sw.status),
					)
					if sw.status >= 500 {
						span.SetStatus(codes.Error, http.StatusText(sw.status))
					}
					span.End()
				}
				if metrics != nil {
					metrics.ObserveHTTP(r.Method, route, sw.status, dur)
				}
				if logger != nil {
					l := observability.LoggerWithTrace(r.Context(), logger)
					attrs := []any{
						"method", r.Method,
						"route", route,
						"http_status", sw.status,
						"duration_ms", dur.Milliseconds(),
					}
					if caller, ok := CallerFromContext(r.Context()); ok {
						attrs = append(attrs, "principal_id", caller.Principal.ID.String())
					}
					l.Info("http request completed", attrs...)
				}
			}()

			next.ServeHTTP(sw, r)
		})
	}
}

func recoverMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if logger != nil {
						observability.LoggerWithTrace(r.Context(), logger).Error("recovered http handler panic",
							"error_code", "PANIC_RECOVERED",
							"method", r.Method,
							"route", routePattern(r),
						)
					}
					writeError(w, r, logger, domain.Internal("INTERNAL_ERROR", "an unexpected internal error occurred"))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func routePattern(r *http.Request) string {
	if r == nil {
		return ""
	}
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if pat := rctx.RoutePattern(); pat != "" {
			return pat
		}
	}
	return r.URL.Path
}

func parseIdempotencyKeyHeader(r *http.Request, required bool) (string, error) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		if required {
			return "", domain.BadRequest("MISSING_IDEMPOTENCY_KEY", "Idempotency-Key header is required")
		}
		return "", nil
	}
	if !idempotencyKeyRegexp.MatchString(key) {
		return "", domain.BadRequest("INVALID_IDEMPOTENCY_KEY", "Idempotency-Key must match ^[A-Za-z0-9._-]{1,128}$")
	}
	return key, nil
}

const releaseIdempotencyKeySQL = `
DELETE FROM idempotency_keys
WHERE principal_id = $1
  AND method = $2
  AND route = $3
  AND idempotency_key = $4
  AND status = 'IN_PROGRESS'
  AND locked_until = $5
`

func computeIdempotencyRequestHash(method, path string, rawBody []byte, extraParts ...string) string {
	bodyPart := rawBody
	if len(strings.TrimSpace(string(rawBody))) > 0 {
		if canon, err := domain.CanonicalJSONBytes(rawBody); err == nil {
			bodyPart = canon
		}
	}
	combined := make([]byte, 0, len(method)+len(path)+len(bodyPart)+2)
	combined = append(combined, method...)
	combined = append(combined, '\n')
	combined = append(combined, path...)
	combined = append(combined, '\n')
	combined = append(combined, bodyPart...)
	for _, part := range extraParts {
		combined = append(combined, '\n')
		combined = append(combined, part...)
	}
	return domain.SHA256Hex(combined)
}

func (s *server) releaseIdempotencyReservation(
	ctx context.Context,
	principalID uuid.UUID,
	method string,
	route string,
	idemKey string,
	lockedUntil time.Time,
) {
	if s.deps.Store == nil {
		return
	}
	if pool := s.deps.Store.Pool(); pool != nil {
		if _, err := pool.Exec(ctx, releaseIdempotencyKeySQL,
			principalID,
			method,
			route,
			idemKey,
			lockedUntil.UTC().Truncate(time.Microsecond),
		); err != nil && s.deps.Logger != nil {
			observability.LoggerWithTrace(ctx, s.deps.Logger).Warn("failed releasing idempotency key reservation",
				"idempotency_key", idemKey,
				"error_code", "IDEMPOTENCY_RELEASE_FAILED",
			)
		}
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, _ = s.deps.Store.FinalizeIdempotencyKey(ctx, persistence.FinalizeIdempotencyParams{
		PrincipalID:         principalID,
		Method:              method,
		Route:               route,
		IdempotencyKey:      idemKey,
		ExpectedLockedUntil: lockedUntil,
		ResponseStatus:      http.StatusInternalServerError,
		CompletedAt:         now,
		ExpiresAt:           now.Add(-time.Second),
	})
}

func (s *server) runIdempotent(
	w http.ResponseWriter,
	r *http.Request,
	caller identity.CallerContext,
	idemKey string,
	rawBody []byte,
	fn func() (int, any, error),
	extraHashParts ...string,
) {
	if s.deps.Store == nil {
		writeError(w, r, s.deps.Logger, domain.Unavailable("STORE_UNAVAILABLE", "persistence store is not configured"))
		return
	}
	route := r.URL.Path
	reqHash := computeIdempotencyRequestHash(r.Method, route, rawBody, extraHashParts...)

	resCtx, resCancel := s.withDBTimeout(r.Context())
	res, err := s.deps.Store.ReserveIdempotencyKey(resCtx, persistence.IdempotencyReserveInput{
		PrincipalID:    caller.Principal.ID,
		Method:         r.Method,
		Route:          route,
		IdempotencyKey: idemKey,
		RequestHash:    reqHash,
	})
	resCancel()
	if err != nil {
		writeError(w, r, s.deps.Logger, mapDBTimeoutError(resCtx, err))
		return
	}

	if res.Replay {
		status := http.StatusOK
		if res.Record.ResponseStatus != nil && *res.Record.ResponseStatus > 0 {
			status = *res.Record.ResponseStatus
		}
		var headers map[string]string
		if len(res.Record.ResponseHeaders) > 0 {
			_ = json.Unmarshal(res.Record.ResponseHeaders, &headers)
		}
		writeRawJSON(w, status, headers, res.Record.ResponseBody)
		return
	}

	releasedOrFinalized := false
	release := func() {
		if releasedOrFinalized {
			return
		}
		releasedOrFinalized = true
		releaseCtx, cancel := s.withDBTimeout(context.Background())
		defer cancel()
		s.releaseIdempotencyReservation(releaseCtx, caller.Principal.ID, r.Method, route, idemKey, res.Record.LockedUntil)
	}
	defer release()

	status, payload, fnErr := fn()
	if fnErr != nil {
		release()
		writeError(w, r, s.deps.Logger, fnErr)
		return
	}

	respBytes, err := json.Marshal(payload)
	if err != nil {
		release()
		writeError(w, r, s.deps.Logger, domain.WrapError(domain.ErrInternal, "RESPONSE_ENCODE_FAILED", "failed encoding response", err))
		return
	}

	headersJSON, _ := json.Marshal(map[string]string{
		"Content-Type": "application/json",
	})

	if status >= 200 && status < 300 {
		releasedOrFinalized = true
		now := time.Now().UTC().Truncate(time.Microsecond)
		finCtx, finCancel := s.withDBTimeout(context.WithoutCancel(r.Context()))
		_, finErr := s.deps.Store.FinalizeIdempotencyKey(finCtx, persistence.FinalizeIdempotencyParams{
			PrincipalID:         caller.Principal.ID,
			Method:              r.Method,
			Route:               route,
			IdempotencyKey:      idemKey,
			ExpectedLockedUntil: res.Record.LockedUntil,
			ResponseStatus:      status,
			ResponseHeaders:     json.RawMessage(headersJSON),
			ResponseBody:        json.RawMessage(respBytes),
			CompletedAt:         now,
			ExpiresAt:           now.Add(24 * time.Hour),
		})
		finCancel()
		if finErr != nil && s.deps.Logger != nil {
			observability.LoggerWithTrace(r.Context(), s.deps.Logger).Warn("failed finalizing idempotency key",
				"idempotency_key", idemKey,
				"error_code", "IDEMPOTENCY_FINALIZE_FAILED",
			)
		}
	} else {
		release()
	}

	writeRawJSON(w, status, map[string]string{"Content-Type": "application/json"}, respBytes)
}

func requestBaseURL(r *http.Request, configured string) string {
	if trimmed := strings.TrimRight(strings.TrimSpace(configured), "/"); trimmed != "" {
		return trimmed
	}
	scheme := "http"
	if r != nil {
		if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			scheme = "https"
		}
		if host := strings.TrimSpace(r.Host); host != "" {
			return scheme + "://" + host
		}
	}
	return "http://127.0.0.1:8080"
}
