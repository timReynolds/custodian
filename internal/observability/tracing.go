package observability

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type TraceMode string

const (
	TraceModeNoop     TraceMode = "noop"
	TraceModeInMemory TraceMode = "inmemory"
	TraceModeStdout   TraceMode = "stdout"
	TraceModeOTLPHTTP TraceMode = "otlp_http"
)

type TracerConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	Mode           TraceMode
	OTLPEndpoint   string
	StdoutWriter   io.Writer
	SampleRatio    float64
	SyncExport     bool
	Exporter       sdktrace.SpanExporter
	RegisterGlobal bool
}

type TracerRuntime struct {
	Provider    trace.TracerProvider
	SDKProvider *sdktrace.TracerProvider
	InMemory    *tracetest.InMemoryExporter
	shutdownFn  func(context.Context) error
	closeOnce   sync.Once
	closeErr    error
}

// NewTracerProvider constructs an isolated OpenTelemetry TracerRuntime.
func NewTracerProvider(ctx context.Context, cfg TracerConfig) (*TracerRuntime, error) {
	mode := cfg.Mode
	if mode == "" {
		if cfg.Exporter != nil {
			mode = TraceModeInMemory
		} else {
			mode = TraceModeNoop
		}
	}

	if cfg.Exporter == nil && mode == TraceModeNoop {
		np := noop.NewTracerProvider()
		if cfg.RegisterGlobal {
			otel.SetTracerProvider(np)
		}
		return &TracerRuntime{
			Provider:   np,
			shutdownFn: func(context.Context) error { return nil },
		}, nil
	}

	svc := cfg.ServiceName
	if svc == "" {
		svc = "custodian"
	}
	ver := cfg.ServiceVersion
	if ver == "" {
		ver = "dev"
	}
	attrs := []attribute.KeyValue{
		semconv.ServiceName(svc),
		semconv.ServiceVersion(ver),
	}
	if cfg.Environment != "" {
		attrs = append(attrs, attribute.String("deployment.environment", cfg.Environment))
	}
	// Use schemaless resource to avoid ErrSchemaURLConflict when sdktrace merges resource.Environment().
	res := resource.NewSchemaless(attrs...)

	var (
		exp      sdktrace.SpanExporter
		inMemory *tracetest.InMemoryExporter
		syncMode = cfg.SyncExport
	)

	if cfg.Exporter != nil {
		exp = cfg.Exporter
	} else {
		switch mode {
		case TraceModeInMemory:
			inMemory = tracetest.NewInMemoryExporter()
			exp = inMemory
			syncMode = true
		case TraceModeStdout:
			w := cfg.StdoutWriter
			if w == nil {
				w = os.Stdout
			}
			stdoutExp, err := stdouttrace.New(stdouttrace.WithWriter(w))
			if err != nil {
				return nil, err
			}
			exp = stdoutExp
		case TraceModeOTLPHTTP:
			if cfg.OTLPEndpoint == "" {
				return nil, errors.New("otlp_http trace mode requires non-empty OTLPEndpoint")
			}
			otlpExp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint))
			if err != nil {
				return nil, err
			}
			exp = otlpExp
		default:
			return nil, errors.New("unsupported trace mode: " + string(mode))
		}
	}

	sampler := sdktrace.AlwaysSample()
	if cfg.SampleRatio > 0 && cfg.SampleRatio < 1 {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	}
	if syncMode {
		opts = append(opts, sdktrace.WithSyncer(exp))
	} else {
		opts = append(opts, sdktrace.WithBatcher(exp))
	}

	tp := sdktrace.NewTracerProvider(opts...)
	if cfg.RegisterGlobal {
		otel.SetTracerProvider(tp)
	}

	return &TracerRuntime{
		Provider:    tp,
		SDKProvider: tp,
		InMemory:    inMemory,
		shutdownFn:  tp.Shutdown,
	}, nil
}

func (r *TracerRuntime) Tracer(name string, opts ...trace.TracerOption) trace.Tracer {
	if r == nil || r.Provider == nil {
		return noop.NewTracerProvider().Tracer(name, opts...)
	}
	return r.Provider.Tracer(name, opts...)
}

func (r *TracerRuntime) ForceFlush(ctx context.Context) error {
	if r == nil || r.SDKProvider == nil {
		return nil
	}
	return r.SDKProvider.ForceFlush(ctx)
}

// Shutdown flushes and shuts down the tracer provider idempotently.
func (r *TracerRuntime) Shutdown(ctx context.Context) error {
	if r == nil || r.shutdownFn == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.closeErr = r.shutdownFn(ctx)
	})
	return r.closeErr
}
