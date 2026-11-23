package observability

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNewTracerProvider_Noop(t *testing.T) {
	ctx := context.Background()
	rt, err := NewTracerProvider(ctx, TracerConfig{Mode: TraceModeNoop})
	if err != nil {
		t.Fatalf("NewTracerProvider(noop): %v", err)
	}
	_, span := rt.Tracer("test").Start(ctx, "noop-op")
	span.End()

	if err := rt.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush(noop): %v", err)
	}
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown(noop) 1: %v", err)
	}
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown(noop) 2 (idempotent): %v", err)
	}
}

func TestNewTracerProvider_InMemory(t *testing.T) {
	ctx := context.Background()
	rt, err := NewTracerProvider(ctx, TracerConfig{
		ServiceName:    "custodian-api",
		ServiceVersion: "0.1.0",
		Environment:    "test",
		Mode:           TraceModeInMemory,
	})
	if err != nil {
		t.Fatalf("NewTracerProvider(inmemory): %v", err)
	}
	defer func() { _ = rt.Shutdown(ctx) }()

	_, span := rt.Tracer("custodian.workflow").Start(ctx, "CreateWorkspace")
	if !span.SpanContext().IsValid() {
		t.Fatal("expected valid SpanContext in inmemory mode")
	}
	span.End()

	if err := rt.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
	spans := rt.InMemory.GetSpans()
	if len(spans) != 1 || spans[0].Name != "CreateWorkspace" {
		t.Fatalf("unexpected spans: %+v", spans)
	}

	var foundService bool
	for _, attr := range spans[0].Resource.Attributes() {
		if string(attr.Key) == "service.name" && attr.Value.AsString() == "custodian-api" {
			foundService = true
		}
	}
	if !foundService {
		t.Fatal("service.name resource attribute missing from recorded span")
	}
}

func TestNewTracerProvider_StdoutAndCustomExporter(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	rt, err := NewTracerProvider(ctx, TracerConfig{
		ServiceName:  "custodian-worker",
		Mode:         TraceModeStdout,
		StdoutWriter: &buf,
		SyncExport:   true,
	})
	if err != nil {
		t.Fatalf("NewTracerProvider(stdout): %v", err)
	}
	_, span := rt.Tracer("worker").Start(ctx, "IngressJob")
	span.End()
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown(stdout): %v", err)
	}
	if !strings.Contains(buf.String(), "IngressJob") {
		t.Fatalf("stdout exporter output missing span name: %s", buf.String())
	}

	// Custom exporter override
	customExp := tracetest.NewInMemoryExporter()
	rtCustom, err := NewTracerProvider(ctx, TracerConfig{
		Exporter:   customExp,
		SyncExport: true,
	})
	if err != nil {
		t.Fatalf("NewTracerProvider(custom): %v", err)
	}
	_, sp2 := rtCustom.Tracer("custom").Start(ctx, "CustomSpan")
	sp2.End()
	if err := rtCustom.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush(custom): %v", err)
	}
	if len(customExp.GetSpans()) != 1 {
		t.Fatalf("custom exporter got %d spans, want 1", len(customExp.GetSpans()))
	}
	_ = rtCustom.Shutdown(ctx)
}

func TestNewTracerProvider_OTLPValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := NewTracerProvider(ctx, TracerConfig{Mode: TraceModeOTLPHTTP}); err == nil {
		t.Fatal("expected error when OTLPEndpoint is empty")
	}
	if _, err := NewTracerProvider(ctx, TracerConfig{Mode: TraceMode("invalid")}); err == nil {
		t.Fatal("expected error for unsupported trace mode")
	}
}
