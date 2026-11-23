package policy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

// EngineOption configures optional observability and safety limits on a policy Engine.
type EngineOption func(*Engine)

// WithCostLimit overrides the default CEL runtime evaluation cost limit (DefaultCostLimit).
func WithCostLimit(limit uint64) EngineOption {
	return func(e *Engine) {
		if limit > 0 {
			e.costLimit = limit
		}
	}
}

// WithMetrics wires optional Prometheus metrics into policy evaluation.
func WithMetrics(m *observability.Metrics) EngineOption {
	return func(e *Engine) {
		e.metrics = m
	}
}

// WithLogger wires an ID/digest-only structured logger into policy evaluation.
func WithLogger(l *slog.Logger) EngineOption {
	return func(e *Engine) {
		e.logger = l
	}
}

// WithTracer wires an OpenTelemetry tracer into policy evaluation.
func WithTracer(t trace.Tracer) EngineOption {
	return func(e *Engine) {
		if t != nil {
			e.tracer = t
		}
	}
}

// Engine compiles, validates, and evaluates Custodian CEL policy bundles.
type Engine struct {
	env       *cel.Env
	costLimit uint64
	metrics   *observability.Metrics
	logger    *slog.Logger
	tracer    trace.Tracer
}

// NewEngine constructs a Stage C CEL policy engine with typed fact declarations and safety bounds.
func NewEngine(opts ...EngineOption) (*Engine, error) {
	env, err := cel.NewEnv(
		ext.NativeTypes(
			ext.ParseStructTags(true),
			reflect.TypeOf(FindingsInput{}),
			reflect.TypeOf(AssessmentInput{}),
			reflect.TypeOf(ChangeInput{}),
			reflect.TypeOf(RepositoryInput{}),
			reflect.TypeOf(WorkspaceInput{}),
			reflect.TypeOf(ProposalInput{}),
			reflect.TypeOf(PrincipalInput{}),
			reflect.TypeOf(ProvenanceInput{}),
		),
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		cel.OptionalTypes(),
		cel.ParserRecursionLimit(32),
		cel.ParserExpressionSizeLimit(8192),
		cel.ExpressionNestingDepthLimit(32),
		cel.ExpressionNodeLimit(512),
		cel.ExtendedValidations(),
		cel.Variable("stage", cel.StringType),
		cel.Variable("findings", cel.ObjectType("policy.FindingsInput")),
		cel.Variable("assessment", cel.ObjectType("policy.AssessmentInput")),
		cel.Variable("change", cel.ObjectType("policy.ChangeInput")),
		cel.Variable("repository", cel.ObjectType("policy.RepositoryInput")),
		cel.Variable("workspace", cel.ObjectType("policy.WorkspaceInput")),
		cel.Variable("proposal", cel.ObjectType("policy.ProposalInput")),
		cel.Variable("principal", cel.ObjectType("policy.PrincipalInput")),
		cel.Variable("provenance", cel.ObjectType("policy.ProvenanceInput")),
		cel.Variable("flags", cel.MapType(cel.StringType, cel.BoolType)),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	e := &Engine{
		env:       env,
		costLimit: DefaultCostLimit,
		tracer:    noop.NewTracerProvider().Tracer("custodian.policy"),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e, nil
}

// Compile parses, validates, and compiles a YAML or JSON PolicyBundle into executable CEL programs.
func (e *Engine) Compile(raw []byte) (*CompiledBundle, []ValidationError) {
	b, errs := ParseBundle(raw)
	if len(errs) > 0 {
		// Still compile any non-empty rules so callers get complete diagnostics.
		_, extraErrs := e.compileRules(b.Rules)
		errs = append(errs, extraErrs...)
		return nil, errs
	}

	compiledRules, compileErrs := e.compileRules(b.Rules)
	if len(compileErrs) > 0 {
		return nil, compileErrs
	}

	def, digest, err := CanonicalBundleJSON(b)
	if err != nil {
		return nil, []ValidationError{{
			Code:    "CANONICALIZATION_ERROR",
			Message: err.Error(),
		}}
	}

	return &CompiledBundle{
		Bundle:     b,
		Scope:      b.Metadata.Scope,
		Digest:     digest,
		Definition: def,
		Rules:      compiledRules,
	}, nil
}

// CompileDomainBundle compiles a persisted domain.PolicyBundle into a ready-to-evaluate bundle.
func (e *Engine) CompileDomainBundle(db domain.PolicyBundle) (*CompiledBundle, []ValidationError) {
	b, errs := ParseDomainBundle(db)
	if len(errs) > 0 {
		_, extraErrs := e.compileRules(b.Rules)
		errs = append(errs, extraErrs...)
		return nil, errs
	}

	compiledRules, compileErrs := e.compileRules(b.Rules)
	if len(compileErrs) > 0 {
		return nil, compileErrs
	}

	def, digest, err := CanonicalBundleJSON(b)
	if err != nil {
		return nil, []ValidationError{{
			Code:    "CANONICALIZATION_ERROR",
			Message: err.Error(),
		}}
	}

	scope := b.Metadata.Scope
	if db.Scope.IsValid() {
		scope = db.Scope
	}

	return &CompiledBundle{
		Bundle:     b,
		Scope:      scope,
		Digest:     digest,
		Definition: def,
		Rules:      compiledRules,
	}, nil
}

// Validate parses and compiles raw bundle YAML/JSON and returns a full ValidationResult
// suitable for CLI `validate` and `POST /v1/policies/validate`.
func (e *Engine) Validate(raw []byte) ValidationResult {
	res, _ := e.validateAndCompile(raw)
	return res
}

// ValidateWithTests validates bundleYAML and, when testCasesYAML is non-empty and the bundle
// compiles cleanly, executes the inline PolicyTestSuite against the compiled bundle.
func (e *Engine) ValidateWithTests(ctx context.Context, bundleYAML []byte, testCasesYAML []byte) (ValidationResult, *TestSuiteReport) {
	res, compiled := e.validateAndCompile(bundleYAML)
	if !res.Valid || compiled == nil || len(bytes.TrimSpace(testCasesYAML)) == 0 {
		return res, nil
	}

	suite, err := ParseTestSuite(testCasesYAML)
	if err != nil {
		res.Valid = false
		res.Errors = append(res.Errors, ValidationError{
			Code:    "INVALID_TEST_SUITE",
			Message: err.Error(),
		})
		return res, nil
	}

	report, err := e.RunTestSuite(ctx, suite, "", compiled)
	if err != nil {
		res.Valid = false
		res.Errors = append(res.Errors, ValidationError{
			Code:    "TEST_SUITE_ERROR",
			Message: err.Error(),
		})
		return res, nil
	}

	if !report.AllPassed() {
		res.Valid = false
		for _, tc := range report.Cases {
			if !tc.Passed {
				res.Errors = append(res.Errors, ValidationError{
					Code:    "POLICY_TEST_FAILED",
					Message: fmt.Sprintf("test case %q failed: %s", tc.Name, tc.FailureReason),
				})
			}
		}
	}
	return res, &report
}

func (e *Engine) validateAndCompile(raw []byte) (ValidationResult, *CompiledBundle) {
	b, structErrs := ParseBundle(raw)
	compiledRules, compileErrs := e.compileRules(b.Rules)

	allErrs := make([]ValidationError, 0, len(structErrs)+len(compileErrs))
	allErrs = append(allErrs, structErrs...)
	allErrs = append(allErrs, compileErrs...)

	digest := domain.SHA256Hex(raw)
	var compiled *CompiledBundle
	if len(allErrs) == 0 {
		def, canonDigest, err := CanonicalBundleJSON(b)
		if err != nil {
			allErrs = append(allErrs, ValidationError{
				Code:    "CANONICALIZATION_ERROR",
				Message: err.Error(),
			})
		} else {
			digest = canonDigest
			compiled = &CompiledBundle{
				Bundle:     b,
				Scope:      b.Metadata.Scope,
				Digest:     canonDigest,
				Definition: def,
				Rules:      compiledRules,
			}
		}
	} else if b.APIVersion != "" || b.Kind != "" || b.Metadata.Name != "" || len(b.Rules) > 0 {
		if _, canonDigest, err := CanonicalBundleJSON(b); err == nil {
			digest = canonDigest
		}
	}

	var scopePtr *domain.PolicyScope
	if b.Metadata.Scope.IsValid() {
		s := b.Metadata.Scope
		scopePtr = &s
	}

	res := ValidationResult{
		Valid:         len(allErrs) == 0,
		Name:          b.Metadata.Name,
		Version:       b.Metadata.Version,
		Scope:         scopePtr,
		Digest:        digest,
		RulesCompiled: len(compiledRules),
		Errors:        allErrs,
	}
	return res, compiled
}

func (e *Engine) compileRules(rules []Rule) ([]CompiledRule, []ValidationError) {
	compiled := make([]CompiledRule, 0, len(rules))
	var errs []ValidationError

	for _, r := range rules {
		if r.When == "" {
			continue
		}
		ast, issues := e.env.Compile(r.When)
		if issues != nil && issues.Err() != nil {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    classifyCompileError(issues.Err()),
				Message: issues.Err().Error(),
			})
			continue
		}

		outType := ast.OutputType()
		if outType == nil || (!outType.IsExactType(cel.BoolType) && outType != cel.BoolType) {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    "CEL_NON_BOOLEAN_RETURN",
				Message: fmt.Sprintf("CEL expression must return bool, got %v", outType),
			})
			continue
		}

		prg, err := e.env.Program(
			ast,
			cel.CostLimit(e.costLimit),
			cel.InterruptCheckFrequency(100),
		)
		if err != nil {
			errs = append(errs, ValidationError{
				RuleID:  r.ID,
				Code:    "CEL_PROGRAM_ERROR",
				Message: fmt.Sprintf("failed to construct CEL program: %v", err),
			})
			continue
		}

		obls := make([]domain.Obligation, 0, len(r.Obligations))
		for _, o := range r.Obligations {
			minVal := 1
			if o.Minimum != nil && *o.Minimum >= 1 {
				minVal = *o.Minimum
			}
			typ := o.Type
			if typ == "" {
				typ = DefaultObligationType
			}
			obls = append(obls, domain.Obligation{
				Type:          typ,
				ReviewerGroup: o.ReviewerGroup,
				Minimum:       minVal,
			})
		}

		compiled = append(compiled, CompiledRule{
			Spec:        r,
			Program:     prg,
			Obligations: obls,
		})
	}

	return compiled, errs
}

func classifyCompileError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "found no matching overload") ||
		strings.Contains(msg, "type") ||
		strings.Contains(msg, "undeclared reference") ||
		strings.Contains(msg, "undefined field") {
		return "CEL_TYPE_ERROR"
	}
	return "CEL_SYNTAX_ERROR"
}
