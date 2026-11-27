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
	m.RecordPushSession("HTTPS", "ENFORCE_BLOCK", "ALLOW", "COMPLETED")
	m.ObservePushPhase("SSH", "ENFORCE_BLOCK", "quarantine", 40*time.Millisecond)
	m.IncPushQuarantineRejection("unreferenced_object")
	m.IncPushIPMatch("L1_EXACT_CHUNK", "RESTRICTED")
	m.ObservePushIPFingerprint("RESTRICTED", 15*time.Millisecond)
	m.IncPushPassiveAuditWouldBlock("ASYNC", "DENY")
	m.IncPushApprovalRelease("consumed")
	m.AddPushUpstreamBytes("ENFORCE_BLOCK", "receive_pack", 4096)
	m.IncPushLFSBatch("upload", "ALLOW")

	// Nil receiver must be safe across all push metric helpers.
	var nilMetrics *Metrics
	nilMetrics.RecordPushSession("HTTPS", "PASSIVE_AUDIT", "ALLOW", "COMPLETED")
	nilMetrics.ObservePushPhase("HTTPS", "PASSIVE_AUDIT", "total", time.Millisecond)
	nilMetrics.IncPushQuarantineRejection("test")
	nilMetrics.IncPushIPMatch("L2_WINNOW_KGRAM", "CONFIDENTIAL")
	nilMetrics.ObservePushIPFingerprint("CONFIDENTIAL", time.Millisecond)
	nilMetrics.IncPushPassiveAuditWouldBlock("INLINE_WARN", "QUARANTINE")
	nilMetrics.IncPushApprovalRelease("expired")
	nilMetrics.AddPushUpstreamBytes("PASSIVE_AUDIT", "receive_pack", 100)
	nilMetrics.IncPushLFSBatch("download", "DENY")

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
		"custodian_push_sessions_total",
		"custodian_push_gateway_duration_seconds",
		"custodian_push_quarantine_rejections_total",
		"custodian_push_ip_fingerprint_matches_total",
		"custodian_push_ip_fingerprint_duration_seconds",
		"custodian_push_passive_audit_would_block_total",
		"custodian_push_approval_releases_total",
		"custodian_push_upstream_bytes_total",
		"custodian_push_lfs_batch_requests_total",
	}
	for _, name := range expectedNames {
		if !strings.Contains(body, name) {
			t.Fatalf("metrics output missing %s", name)
		}
	}
}
