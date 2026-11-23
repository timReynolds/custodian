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
	registry                *prometheus.Registry
	WorkflowDuration        *prometheus.HistogramVec
	OperationsTotal         *prometheus.CounterVec
	ActiveOperations        *prometheus.GaugeVec
	HTTPRequestsTotal       *prometheus.CounterVec
	HTTPRequestDuration     *prometheus.HistogramVec
	ScannerRunsTotal        *prometheus.CounterVec
	ScannerFailuresTotal    *prometheus.CounterVec
	ModelAssessmentsTotal   *prometheus.CounterVec
	ModelCostUSDTotal       *prometheus.CounterVec
	PolicyDecisionsTotal    *prometheus.CounterVec
	PolicyDenialsTotal      *prometheus.CounterVec
	PublicationsTotal       *prometheus.CounterVec
	PublicationRetriesTotal prometheus.Counter
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
