package observability

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsConfig struct {
	Namespace                string
	IncludeRuntimeCollectors bool
}

type Metrics struct {
	registry                        *prometheus.Registry
	WorkflowDuration                *prometheus.HistogramVec
	OperationsTotal                 *prometheus.CounterVec
	ActiveOperations                *prometheus.GaugeVec
	HTTPRequestsTotal               *prometheus.CounterVec
	HTTPRequestDuration             *prometheus.HistogramVec
	ScannerRunsTotal                *prometheus.CounterVec
	ScannerFailuresTotal            *prometheus.CounterVec
	ModelAssessmentsTotal           *prometheus.CounterVec
	ModelCostUSDTotal               *prometheus.CounterVec
	PolicyDecisionsTotal            *prometheus.CounterVec
	PolicyDenialsTotal              *prometheus.CounterVec
	PublicationsTotal               *prometheus.CounterVec
	PublicationRetriesTotal         prometheus.Counter
	PushSessionsTotal               *prometheus.CounterVec
	PushGatewayDuration             *prometheus.HistogramVec
	PushQuarantineRejectionsTotal   *prometheus.CounterVec
	PushIPFingerprintMatchesTotal   *prometheus.CounterVec
	PushIPFingerprintDuration       *prometheus.HistogramVec
	PushPassiveAuditWouldBlockTotal *prometheus.CounterVec
	PushApprovalReleasesTotal       *prometheus.CounterVec
	PushUpstreamBytesTotal          *prometheus.CounterVec
	PushLFSBatchRequestsTotal       *prometheus.CounterVec
}

// NewMetrics creates an isolated Prometheus Registry and registers all Custodian metrics.
func NewMetrics(cfg MetricsConfig) (*Metrics, error) {
	ns := cfg.Namespace
	if ns == "" {
		ns = "custodian"
	}

	reg := prometheus.NewRegistry()
	if cfg.IncludeRuntimeCollectors {
		if err := reg.Register(collectors.NewGoCollector()); err != nil {
			return nil, fmt.Errorf("register go collector: %w", err)
		}
		if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
			return nil, fmt.Errorf("register process collector: %w", err)
		}
	}

	m := &Metrics{
		registry: reg,
		WorkflowDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "workflow_duration_seconds",
			Help:      "Duration of Custodian workflow stages in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"workflow", "stage", "status"}),
		OperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "operations_total",
			Help:      "Total asynchronous operations processed by type and status.",
		}, []string{"operation_type", "status"}),
		ActiveOperations: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Name:      "active_operations",
			Help:      "Number of currently leased active operations by type.",
		}, []string{"operation_type"}),
		HTTPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "http_requests_total",
			Help:      "Total HTTP API requests by method, route, and status.",
		}, []string{"method", "route", "status"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP API request latency in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "route"}),
		ScannerRunsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "scanner_runs_total",
			Help:      "Total Stage A scanner executions by scanner and status.",
		}, []string{"scanner", "status"}),
		ScannerFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "scanner_failures_total",
			Help:      "Total Stage A scanner failures by scanner and reason.",
		}, []string{"scanner", "reason"}),
		ModelAssessmentsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "model_assessments_total",
			Help:      "Total Stage B model assessments by type, status, and risk.",
		}, []string{"assessment_type", "status", "risk"}),
		ModelCostUSDTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "model_cost_usd_total",
			Help:      "Cumulative estimated model gateway spend in USD.",
		}, []string{"model_route", "assessment_type"}),
		PolicyDecisionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "policy_decisions_total",
			Help:      "Total Stage C CEL policy decisions by stage and effect.",
		}, []string{"stage", "effect"}),
		PolicyDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "policy_denials_total",
			Help:      "Total policy denials/blocks by stage and scope.",
		}, []string{"stage", "scope"}),
		PublicationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "publications_total",
			Help:      "Total proposal publications by outcome status.",
		}, []string{"status"}),
		PublicationRetriesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "publication_retries_total",
			Help:      "Total publisher retry attempts.",
		}),
		PushSessionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_sessions_total",
			Help:      "Total push gateway sessions by transport, egress mode, policy effect, and final status.",
		}, []string{"transport", "egress_mode", "effect", "status"}),
		PushGatewayDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "push_gateway_duration_seconds",
			Help:      "Push gateway phase duration in seconds.",
			Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 12, 30},
		}, []string{"transport", "egress_mode", "phase"}),
		PushQuarantineRejectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_quarantine_rejections_total",
			Help:      "Total push quarantine rejections by reason.",
		}, []string{"reason"}),
		PushIPFingerprintMatchesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_ip_fingerprint_matches_total",
			Help:      "Total IP fingerprint matches by layer and corpus classification.",
		}, []string{"layer", "classification"}),
		PushIPFingerprintDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Name:      "push_ip_fingerprint_duration_seconds",
			Help:      "IP fingerprinting evaluation latency in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2.5},
		}, []string{"classification"}),
		PushPassiveAuditWouldBlockTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_passive_audit_would_block_total",
			Help:      "Total PASSIVE_AUDIT pushes that would have been blocked under enforcement.",
		}, []string{"delivery", "effect"}),
		PushApprovalReleasesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_approval_releases_total",
			Help:      "Total push approval release lifecycle events by outcome.",
		}, []string{"outcome"}),
		PushUpstreamBytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_upstream_bytes_total",
			Help:      "Total bytes forwarded upstream by egress mode and phase.",
		}, []string{"egress_mode", "phase"}),
		PushLFSBatchRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Name:      "push_lfs_batch_requests_total",
			Help:      "Total Git LFS batch requests evaluated by operation and policy effect.",
		}, []string{"operation", "effect"}),
	}

	allCollectors := []prometheus.Collector{
		m.WorkflowDuration,
		m.OperationsTotal,
		m.ActiveOperations,
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.ScannerRunsTotal,
		m.ScannerFailuresTotal,
		m.ModelAssessmentsTotal,
		m.ModelCostUSDTotal,
		m.PolicyDecisionsTotal,
		m.PolicyDenialsTotal,
		m.PublicationsTotal,
		m.PublicationRetriesTotal,
		m.PushSessionsTotal,
		m.PushGatewayDuration,
		m.PushQuarantineRejectionsTotal,
		m.PushIPFingerprintMatchesTotal,
		m.PushIPFingerprintDuration,
		m.PushPassiveAuditWouldBlockTotal,
		m.PushApprovalReleasesTotal,
		m.PushUpstreamBytesTotal,
		m.PushLFSBatchRequestsTotal,
	}
	for _, c := range allCollectors {
		if err := reg.Register(c); err != nil {
			return nil, fmt.Errorf("register metric: %w", err)
		}
	}

	return m, nil
}

func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

func (m *Metrics) ObserveWorkflow(workflow, stage, status string, dur time.Duration) {
	if m == nil {
		return
	}
	m.WorkflowDuration.WithLabelValues(workflow, stage, status).Observe(dur.Seconds())
}

func (m *Metrics) IncOperation(opType, status string) {
	if m == nil {
		return
	}
	m.OperationsTotal.WithLabelValues(opType, status).Inc()
}

func (m *Metrics) IncActiveOperation(opType string) {
	if m == nil {
		return
	}
	m.ActiveOperations.WithLabelValues(opType).Inc()
}

func (m *Metrics) DecActiveOperation(opType string) {
	if m == nil {
		return
	}
	m.ActiveOperations.WithLabelValues(opType).Dec()
}

func (m *Metrics) ObserveHTTP(method, route string, status int, dur time.Duration) {
	if m == nil {
		return
	}
	m.HTTPRequestsTotal.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, route).Observe(dur.Seconds())
}

func (m *Metrics) IncScannerRun(scanner, status string) {
	if m == nil {
		return
	}
	m.ScannerRunsTotal.WithLabelValues(scanner, status).Inc()
}

func (m *Metrics) IncScannerFailure(scanner, reason string) {
	if m == nil {
		return
	}
	m.ScannerFailuresTotal.WithLabelValues(scanner, reason).Inc()
}

func (m *Metrics) RecordModelAssessment(assessmentType, status, risk, modelRoute string, costUSD float64) {
	if m == nil {
		return
	}
	m.ModelAssessmentsTotal.WithLabelValues(assessmentType, status, risk).Inc()
	if costUSD > 0 {
		m.ModelCostUSDTotal.WithLabelValues(modelRoute, assessmentType).Add(costUSD)
	}
}

func (m *Metrics) IncPolicyDecision(stage, effect string) {
	if m == nil {
		return
	}
	m.PolicyDecisionsTotal.WithLabelValues(stage, effect).Inc()
}

func (m *Metrics) IncPolicyDenial(stage, scope string) {
	if m == nil {
		return
	}
	m.PolicyDenialsTotal.WithLabelValues(stage, scope).Inc()
}

func (m *Metrics) IncPublication(status string) {
	if m == nil {
		return
	}
	m.PublicationsTotal.WithLabelValues(status).Inc()
}

func (m *Metrics) IncPublicationRetry() {
	if m == nil {
		return
	}
	m.PublicationRetriesTotal.Inc()
}

func (m *Metrics) RecordPushSession(transport, egressMode, effect, status string) {
	if m == nil {
		return
	}
	m.PushSessionsTotal.WithLabelValues(transport, egressMode, effect, status).Inc()
}

func (m *Metrics) ObservePushPhase(transport, egressMode, phase string, dur time.Duration) {
	if m == nil {
		return
	}
	m.PushGatewayDuration.WithLabelValues(transport, egressMode, phase).Observe(dur.Seconds())
}

func (m *Metrics) IncPushQuarantineRejection(reason string) {
	if m == nil {
		return
	}
	m.PushQuarantineRejectionsTotal.WithLabelValues(reason).Inc()
}

func (m *Metrics) IncPushIPMatch(layer, classification string) {
	if m == nil {
		return
	}
	m.PushIPFingerprintMatchesTotal.WithLabelValues(layer, classification).Inc()
}

func (m *Metrics) ObservePushIPFingerprint(classification string, dur time.Duration) {
	if m == nil {
		return
	}
	m.PushIPFingerprintDuration.WithLabelValues(classification).Observe(dur.Seconds())
}

func (m *Metrics) IncPushPassiveAuditWouldBlock(delivery, effect string) {
	if m == nil {
		return
	}
	m.PushPassiveAuditWouldBlockTotal.WithLabelValues(delivery, effect).Inc()
}

func (m *Metrics) IncPushApprovalRelease(outcome string) {
	if m == nil {
		return
	}
	m.PushApprovalReleasesTotal.WithLabelValues(outcome).Inc()
}

func (m *Metrics) AddPushUpstreamBytes(egressMode, phase string, n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.PushUpstreamBytesTotal.WithLabelValues(egressMode, phase).Add(float64(n))
}

func (m *Metrics) IncPushLFSBatch(operation, effect string) {
	if m == nil {
		return
	}
	m.PushLFSBatchRequestsTotal.WithLabelValues(operation, effect).Inc()
}
