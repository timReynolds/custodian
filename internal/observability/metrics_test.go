package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestMetrics_IsolatedRegistryAndExposition(t *testing.T) {
	m, err := NewMetrics(MetricsConfig{})
	if err != nil {
		t.Fatalf("NewMetrics failed: %v", err)
	}

	m.ObserveWorkflow("ingress", "checkout", "succeeded", 25*time.Millisecond)
	m.IncOperation("WORKSPACE_INGRESS", "SUCCEEDED")
	m.IncActiveOperation("WORKSPACE_INGRESS")
	m.DecActiveOperation("WORKSPACE_INGRESS")
	m.ObserveHTTP("POST", "/v1/workspaces", http.StatusAccepted, 12*time.Millisecond)
	m.IncScannerRun("gitleaks", "COMPLETED")
	m.IncScannerFailure("trivy", "timeout")
	m.RecordModelAssessment("SECURITY_REVIEW", "COMPLETE", "LOW", "internal-v1", 0.012)
	m.IncPolicyDecision("EGRESS", "REQUIRE_APPROVAL")
	m.IncPolicyDenial("EGRESS", "ORG")
	m.IncPublication("PUBLISHED")
	m.IncPublicationRetry()

	// Verify prometheus.DefaultGatherer is untouched.
	defaultMFs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("DefaultGatherer.Gather: %v", err)
	}
	for _, mf := range defaultMFs {
		if strings.HasPrefix(mf.GetName(), "custodian_") {
			t.Fatalf("metric %s leaked into prometheus.DefaultGatherer", mf.GetName())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("metrics handler status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	expectedNames := []string{
		"custodian_workflow_duration_seconds",
		"custodian_operations_total",
		"custodian_active_operations",
		"custodian_http_requests_total",
		"custodian_http_request_duration_seconds",
		"custodian_scanner_runs_total",
		"custodian_scanner_failures_total",
		"custodian_model_assessments_total",
		"custodian_model_cost_usd_total",
		"custodian_policy_decisions_total",
		"custodian_policy_denials_total",
		"custodian_publications_total",
		"custodian_publication_retries_total",
	}
	for _, name := range expectedNames {
		if !strings.Contains(body, name) {
			t.Fatalf("metrics output missing %s", name)
		}
	}
}
