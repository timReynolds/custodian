package decisions

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/timreynolds/custodian/internal/decisions/schemas"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

// Service orchestrates Stage B contextual decision model assessments.
type Service struct {
	gateway      GatewayClient
	routePolicy  *RoutePolicy
	logger       *slog.Logger
	metrics      *observability.Metrics
	tracer       trace.Tracer
	maxDiffBytes int
	nowFn        func() time.Time
}

// ServiceOption configures optional dependencies on Service.
type ServiceOption func(*Service)

// WithRoutePolicy sets an optional classification-to-route policy.
func WithRoutePolicy(policy *RoutePolicy) ServiceOption {
	return func(s *Service) {
		s.routePolicy = policy
	}
}

// WithLogger sets an ID/digest-only structured logger.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// WithMetrics sets Prometheus metrics recording.
func WithMetrics(metrics *observability.Metrics) ServiceOption {
	return func(s *Service) {
		s.metrics = metrics
	}
}

// WithTracer sets an OpenTelemetry tracer (or nil for noop).
func WithTracer(tracer trace.Tracer) ServiceOption {
	return func(s *Service) {
		if tracer != nil {
			s.tracer = tracer
		}
	}
}

// WithMaxDiffBytes bounds the canonical diff size sent in untrusted user prompts.
func WithMaxDiffBytes(maxBytes int) ServiceOption {
	return func(s *Service) {
		if maxBytes > 0 {
			s.maxDiffBytes = maxBytes
		}
	}
}

// WithClock overrides time.Now for deterministic tests.
func WithClock(nowFn func() time.Time) ServiceOption {
	return func(s *Service) {
		if nowFn != nil {
			s.nowFn = nowFn
		}
	}
}

// NewService constructs a Stage B assessment Service.
func NewService(gateway GatewayClient, opts ...ServiceOption) (*Service, error) {
	if gateway == nil {
		return nil, domain.BadRequest("GATEWAY_REQUIRED", "gateway client must not be nil")
	}
	s := &Service{
		gateway:      gateway,
		tracer:       noop.NewTracerProvider().Tracer("custodian/internal/decisions"),
		maxDiffBytes: DefaultMaxDiffBytes,
		nowFn:        func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s, nil
}

// Assess executes Stage B contextual decision evaluation with pre-gateway route
// binding, server-only prompt construction, strict JSON schema validation, and
// Stage A evidence_ids grounding.
func (s *Service) Assess(ctx context.Context, req AssessRequest) (domain.ModelAssessment, error) {
	if s == nil {
		return domain.ModelAssessment{}, domain.Internal("SERVICE_NIL", "decisions service is nil")
	}
	if !domain.IsUUIDv7(req.ProposalID) {
		return domain.ModelAssessment{}, domain.BadRequest("INVALID_PROPOSAL_ID", "proposal_id must be a valid UUIDv7")
	}
	if !domain.IsUUIDv7(req.ArtifactID) {
		return domain.ModelAssessment{}, domain.BadRequest("INVALID_ARTIFACT_ID", "artifact_id must be a valid UUIDv7")
	}

	start := s.nowFn()

	// Build prompt first so ValidateRedacted(), TemplateFor(), and InputDigest run
	// deterministically before any gateway decision, without executing any HTTP calls.
	built, err := BuildPrompt(req, s.maxDiffBytes)
	if err != nil {
		return domain.ModelAssessment{}, err
	}

	ctx, span := s.tracer.Start(ctx, "decisions.Assess", trace.WithAttributes(
		attribute.String("proposal_id", req.ProposalID.String()),
		attribute.String("artifact_id", req.ArtifactID.String()),
		attribute.String("model_route", strings.TrimSpace(req.ModelRoute)),
		attribute.String("assessment_type", built.AssessmentType),
		attribute.String("classification", string(req.Repository.Classification)),
		attribute.String("input_digest", built.InputDigest),
	))
	defer span.End()

	// Pre-gateway route & classification binding check (0 gateway calls if unauthorized).
	if routeErr := AuthorizeModelRoute(req.Repository, req.AllowedModelRoutes, req.ModelRoute, s.routePolicy); routeErr != nil {
		assessment, buildErr := buildUnauthorizedAssessment(
			req,
			built.AssessmentType,
			built.PromptVersion,
			built.InputDigest,
			routeErr.Error(),
			s.nowFn(),
		)
		if buildErr != nil {
			span.RecordError(buildErr)
			span.SetStatus(codes.Error, "ASSESSMENT_BUILD_ERROR")
			return domain.ModelAssessment{}, buildErr
		}
		s.recordTelemetry(ctx, span, assessment, req.Repository.Classification, 0, start, errorCodeOf(routeErr), "stage b model route unauthorized")
		return assessment, nil
	}

	route := strings.TrimSpace(req.ModelRoute)
	gwResp, gwErr := s.gateway.Invoke(ctx, GatewayRequest{
		ModelRoute:     route,
		Model:          route,
		AssessmentType: built.AssessmentType,
		Temperature:    0,
		Messages: []GatewayMessage{
			{Role: "system", Content: built.SystemPrompt},
			{Role: "user", Content: built.UserPrompt},
		},
	})
	if gwErr != nil {
		modelVer := strings.TrimSpace(gwResp.ModelVersion)
		if modelVer == "" {
			modelVer = route
		}
		errCode := errorCodeOf(gwErr)
		failed, buildErr := s.buildFailedAssessment(
			req,
			built,
			modelVer,
			gwResp.RawBody,
			nil,
			errCode,
			"stage b model gateway invocation failed",
		)
		if buildErr != nil {
			span.RecordError(buildErr)
			span.SetStatus(codes.Error, "ASSESSMENT_BUILD_ERROR")
			return domain.ModelAssessment{}, buildErr
		}
		s.recordTelemetry(ctx, span, failed, req.Repository.Classification, gwResp.CostUSD, start, errCode, "stage b model gateway error")
		return failed, gwErr
	}

	candidateJSON, modelVersion, costUSD, unwrapErr := UnwrapGatewayResponse(gwResp.RawBody, route)
	if strings.TrimSpace(gwResp.ModelVersion) != "" && modelVersion == route {
		modelVersion = strings.TrimSpace(gwResp.ModelVersion)
	}
	if gwResp.CostUSD > 0 && costUSD == 0 {
		costUSD = gwResp.CostUSD
	}
	if unwrapErr != nil {
		errCode := errorCodeOf(unwrapErr)
		failed, buildErr := s.buildFailedAssessment(
			req,
			built,
			modelVersion,
			gwResp.RawBody,
			nil,
			errCode,
			"stage b gateway response envelope invalid",
		)
		if buildErr != nil {
			span.RecordError(buildErr)
			span.SetStatus(codes.Error, "ASSESSMENT_BUILD_ERROR")
			return domain.ModelAssessment{}, buildErr
		}
		s.recordTelemetry(ctx, span, failed, req.Repository.Classification, costUSD, start, errCode, "stage b response unwrap failed")
		return failed, nil
	}

	result, schemaErr := schemas.ValidateAssessmentResult(candidateJSON)
	if schemaErr != nil {
		errCode := errorCodeOf(schemaErr)
		failed, buildErr := s.buildFailedAssessment(
			req,
			built,
			modelVersion,
			gwResp.RawBody,
			candidateJSON,
			errCode,
			"stage b output failed strict JSON schema validation",
		)
		if buildErr != nil {
			span.RecordError(buildErr)
			span.SetStatus(codes.Error, "ASSESSMENT_BUILD_ERROR")
			return domain.ModelAssessment{}, buildErr
		}
		s.recordTelemetry(ctx, span, failed, req.Repository.Classification, costUSD, start, errCode, "stage b schema validation failed")
		return failed, nil
	}

	if result.AssessmentType != built.AssessmentType {
		const errCode = "ASSESSMENT_TYPE_MISMATCH"
		failed, buildErr := s.buildFailedAssessment(
			req,
			built,
			modelVersion,
			gwResp.RawBody,
			candidateJSON,
			errCode,
			"stage b output assessment_type does not match requested assessment_type",
		)
		if buildErr != nil {
			span.RecordError(buildErr)
			span.SetStatus(codes.Error, "ASSESSMENT_BUILD_ERROR")
			return domain.ModelAssessment{}, buildErr
		}
		s.recordTelemetry(ctx, span, failed, req.Repository.Classification, costUSD, start, errCode, "stage b assessment_type mismatch")
		return failed, nil
	}

	groundedIDs, groundErr := ValidateGrounding(result, req.Findings)
	if groundErr != nil {
		errCode := errorCodeOf(groundErr)
		failed, buildErr := s.buildFailedAssessment(
			req,
			built,
			modelVersion,
			gwResp.RawBody,
			candidateJSON,
			errCode,
			"stage b output referenced ungrounded evidence_ids",
		)
		if buildErr != nil {
			span.RecordError(buildErr)
			span.SetStatus(codes.Error, "ASSESSMENT_BUILD_ERROR")
			return domain.ModelAssessment{}, buildErr
		}
		s.recordTelemetry(ctx, span, failed, req.Repository.Classification, costUSD, start, errCode, "stage b grounding validation failed")
		return failed, nil
	}

	status := domain.AssessmentStatusComplete
	if result.Disposition == domain.DispositionIndeterminate {
		status = domain.AssessmentStatusIndeterminate
	}

	outputDigest, err := computeOutputDigest(candidateJSON, gwResp.RawBody, result)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "OUTPUT_DIGEST_ERROR")
		return domain.ModelAssessment{}, err
	}

	id, err := domain.NewID()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "ID_GENERATION_FAILED")
		return domain.ModelAssessment{}, err
	}

	assessment := domain.ModelAssessment{
		ID:             id,
		ProposalID:     req.ProposalID,
		ArtifactID:     req.ArtifactID,
		ModelRoute:     route,
		ModelVersion:   fallbackOrDefaultModelVersion(modelVersion),
		PromptVersion:  built.PromptVersion,
		AssessmentType: result.AssessmentType,
		Status:         status,
		Risk:           result.Risk,
		Disposition:    result.Disposition,
		Result:         result,
		EvidenceIDs:    groundedIDs,
		InputDigest:    built.InputDigest,
		OutputDigest:   outputDigest,
		CreatedAt:      s.nowFn().UTC(),
	}

	s.recordTelemetry(ctx, span, assessment, req.Repository.Classification, costUSD, start, "", "stage b model assessment completed")
	return assessment, nil
}

func (s *Service) buildFailedAssessment(
	req AssessRequest,
	built BuiltPrompt,
	modelVersion string,
	rawBody []byte,
	candidateJSON []byte,
	errCode string,
	summary string,
) (domain.ModelAssessment, error) {
	route := strings.TrimSpace(req.ModelRoute)
	if route == "" {
		route = modelRouteMissingPlaceholder
	}

	result := domain.AssessmentResult{
		SchemaVersion:  "1",
		AssessmentType: built.AssessmentType,
		Risk:           domain.RiskLevelNone,
		Disposition:    domain.DispositionIndeterminate,
		Confidence:     0.0,
		Summary:        summary,
		Findings:       []domain.AssessmentFinding{},
		Limitations:    []string{errCode},
	}

	outputDigest, err := computeOutputDigest(candidateJSON, rawBody, result)
	if err != nil {
		return domain.ModelAssessment{}, err
	}

	id, err := domain.NewID()
	if err != nil {
		return domain.ModelAssessment{}, err
	}

	return domain.ModelAssessment{
		ID:             id,
		ProposalID:     req.ProposalID,
		ArtifactID:     req.ArtifactID,
		ModelRoute:     route,
		ModelVersion:   fallbackOrDefaultModelVersion(modelVersion),
		PromptVersion:  built.PromptVersion,
		AssessmentType: built.AssessmentType,
		Status:         domain.AssessmentStatusFailed,
		Risk:           "",
		Disposition:    "",
		Result:         result,
		EvidenceIDs:    []string{},
		InputDigest:    built.InputDigest,
		OutputDigest:   outputDigest,
		CreatedAt:      s.nowFn().UTC(),
	}, nil
}

func computeOutputDigest(candidateJSON, rawBody []byte, fallbackResult domain.AssessmentResult) (string, error) {
	if len(candidateJSON) > 0 {
		if d, err := domain.CanonicalJSONDigest(candidateJSON); err == nil {
			return d, nil
		}
		return domain.SHA256Hex(candidateJSON), nil
	}
	if len(rawBody) > 0 {
		if d, err := domain.CanonicalJSONDigest(rawBody); err == nil {
			return d, nil
		}
		return domain.SHA256Hex(rawBody), nil
	}
	d, err := domain.CanonicalJSONDigest(fallbackResult)
	if err != nil {
		return "", domain.WrapError(domain.ErrInternal, "OUTPUT_DIGEST_ERROR", "failed to compute fallback output digest", err)
	}
	return d, nil
}

func (s *Service) recordTelemetry(
	ctx context.Context,
	span trace.Span,
	a domain.ModelAssessment,
	classification domain.Classification,
	costUSD float64,
	start time.Time,
	errCode string,
	logMsg string,
) {
	riskLabel := string(a.Risk)
	if riskLabel == "" {
		riskLabel = string(domain.RiskLevelNone)
	}
	s.metrics.RecordModelAssessment(a.AssessmentType, string(a.Status), riskLabel, a.ModelRoute, costUSD)

	span.SetAttributes(
		attribute.String("model_assessment_id", a.ID.String()),
		attribute.String("model_version", a.ModelVersion),
		attribute.String("prompt_version", a.PromptVersion),
		attribute.String("status", string(a.Status)),
		attribute.String("risk", riskLabel),
		attribute.String("disposition", string(a.Disposition)),
		attribute.String("output_digest", a.OutputDigest),
	)
	if errCode != "" {
		span.SetAttributes(attribute.String("err_code", errCode))
	}
	if a.Status == domain.AssessmentStatusFailed {
		span.SetStatus(codes.Error, errCode)
	} else {
		span.SetStatus(codes.Ok, string(a.Status))
	}

	logger := observability.LoggerWithTrace(ctx, s.logger)
	if logger == nil {
		return
	}
	durMs := s.nowFn().Sub(start).Milliseconds()
	if durMs < 0 {
		durMs = 0
	}
	attrs := []any{
		"proposal_id", a.ProposalID.String(),
		"artifact_id", a.ArtifactID.String(),
		"model_assessment_id", a.ID.String(),
		"model_route", a.ModelRoute,
		"model_version", a.ModelVersion,
		"prompt_version", a.PromptVersion,
		"assessment_type", a.AssessmentType,
		"classification", string(classification),
		"status", string(a.Status),
		"risk", riskLabel,
		"disposition", string(a.Disposition),
		"input_digest", a.InputDigest,
		"output_digest", a.OutputDigest,
		"duration_ms", durMs,
	}
	if errCode != "" {
		attrs = append(attrs, "err_code", errCode)
		logger.Warn(logMsg, attrs...)
		return
	}
	logger.Info(logMsg, attrs...)
}

func errorCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		return domErr.Code()
	}
	return "INTERNAL_ERROR"
}
