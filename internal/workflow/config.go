package workflow

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/timreynolds/custodian/internal/archive"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/decisions"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/git/reconstruct"
	"github.com/timreynolds/custodian/internal/inspection"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workspaces"
)

const (
	defaultLeaseDuration        = 15 * time.Second
	defaultRenewInterval        = 5 * time.Second
	defaultPollInterval         = 150 * time.Millisecond
	defaultReapInterval         = 5 * time.Second
	defaultOutboxPollInterval   = 150 * time.Millisecond
	defaultOutboxLeaseDuration  = 15 * time.Second
	defaultOutboxRetryDelay     = 5 * time.Second
	defaultMaxOutboxRetryDelay  = 5 * time.Minute
	defaultOutboxBatchSize      = 25
	defaultRetentionInterval    = 1 * time.Minute
	defaultArtifactRetentionTTL = 24 * time.Hour
	defaultRetentionBatchSize   = 100
	defaultBatchSize            = 1
	defaultIngressMaxBytes      = 256 << 20 // 256 MiB
	defaultTxCleanupTimeout     = 5 * time.Second
)

// Reconstructor executes clean egress base reconstruction and persists canonical artifacts
// to SnapshotStore.
type Reconstructor interface {
	ReconstructDetailed(ctx context.Context, repo domain.Repository, baseCommit string, snapshot domain.Artifact) (reconstruct.Result, error)
}

// DecisionAssessor executes Stage B contextual decision model evaluation.
type DecisionAssessor interface {
	Assess(ctx context.Context, req decisions.AssessRequest) (domain.ModelAssessment, error)
}

// OutboxDispatcher delivers a claimed outbox event to an external/internal sink.
type OutboxDispatcher interface {
	Dispatch(ctx context.Context, ev persistence.OutboxEventRow) error
}

// OutboxDispatcherFunc adapts a function into an OutboxDispatcher.
type OutboxDispatcherFunc func(ctx context.Context, ev persistence.OutboxEventRow) error

// Dispatch invokes f(ctx, ev).
func (f OutboxDispatcherFunc) Dispatch(ctx context.Context, ev persistence.OutboxEventRow) error {
	return f(ctx, ev)
}

// Config holds operational tuning and concurrency/budget limits for workflow processing.
type Config struct {
	WorkerID               string
	LeaseDuration          time.Duration
	RenewInterval          time.Duration
	PollInterval           time.Duration
	ReapInterval           time.Duration
	OutboxPollInterval     time.Duration
	OutboxLeaseDuration    time.Duration
	OutboxRetryDelay       time.Duration
	OutboxBatchSize        int
	RetentionInterval      time.Duration
	ArtifactRetentionTTL   time.Duration
	RetentionBatchSize     int
	BatchSize              int
	GlobalScanBudget       int
	GlobalModelBudget      int
	RepoConcurrencyLimit   int
	PolicyDir              string
	IngressMaxArchiveBytes int64
	Clock                  func() time.Time
}

func (c Config) withDefaults() Config {
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = defaultLeaseDuration
	}
	if c.RenewInterval <= 0 {
		if c.LeaseDuration >= 3*time.Second {
			c.RenewInterval = c.LeaseDuration / 3
		} else {
			c.RenewInterval = defaultRenewInterval
		}
	}
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.ReapInterval <= 0 {
		c.ReapInterval = defaultReapInterval
	}
	if c.OutboxPollInterval <= 0 {
		c.OutboxPollInterval = defaultOutboxPollInterval
	}
	if c.OutboxLeaseDuration <= 0 {
		c.OutboxLeaseDuration = defaultOutboxLeaseDuration
	}
	if c.OutboxRetryDelay <= 0 {
		c.OutboxRetryDelay = defaultOutboxRetryDelay
	}
	if c.OutboxBatchSize <= 0 {
		c.OutboxBatchSize = defaultOutboxBatchSize
	}
	if c.RetentionInterval <= 0 {
		c.RetentionInterval = defaultRetentionInterval
	}
	if c.RetentionBatchSize <= 0 {
		c.RetentionBatchSize = defaultRetentionBatchSize
	}
	if c.BatchSize <= 0 {
		c.BatchSize = defaultBatchSize
	}
	if c.IngressMaxArchiveBytes <= 0 {
		c.IngressMaxArchiveBytes = defaultIngressMaxBytes
	}
	if c.Clock == nil {
		c.Clock = func() time.Time { return time.Now().UTC() }
	}
	if c.WorkerID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "localhost"
		}
		c.WorkerID = fmt.Sprintf("worker-%s-%d-%s", host, os.Getpid(), uuid.NewString()[:8])
	}
	return c
}

// ServiceConfig wires dependencies for workflow.Service and workflow.Runner.
type ServiceConfig struct {
	Store            *persistence.Store
	Ops              *operations.Service
	Workspaces       *workspaces.Service
	Repositories     *repositories.Service
	Proposals        *proposals.Service
	Artifacts        *artifacts.Service
	Audit            *audit.Service
	SnapshotStore    domain.SnapshotStore
	GitReader        domain.GitReader
	Reconstructor    Reconstructor
	InspectionRunner inspection.Runner
	Decisions        DecisionAssessor
	PolicyEngine     *policy.Engine
	OutboxDispatcher OutboxDispatcher
	Logger           *slog.Logger
	Metrics          *observability.Metrics
	Tracer           trace.Tracer
	Config           Config
}

// Service implements WORKSPACE_INGRESS, PROPOSAL_RECONSTRUCT, PROPOSAL_EVALUATE,
// outbox dispatch, expired lease reaping, and artifact retention reaping.
type Service struct {
	store          *persistence.Store
	ops            *operations.Service
	workspaces     *workspaces.Service
	repositories   *repositories.Service
	proposals      *proposals.Service
	artifacts      *artifacts.Service
	audit          *audit.Service
	snapshotStore  domain.SnapshotStore
	gitReader      domain.GitReader
	reconstructor  Reconstructor
	inspector      inspection.Runner
	decisions      DecisionAssessor
	policyEngine   *policy.Engine
	packager       *archive.IngressPackager
	outboxDispatch OutboxDispatcher
	budgets        *BudgetLimiter
	logger         *slog.Logger
	metrics        *observability.Metrics
	tracer         trace.Tracer
	cfg            Config
}

// NewService validates ServiceConfig and constructs a workflow Service.
func NewService(sc ServiceConfig) (*Service, error) {
	if sc.Store == nil {
		return nil, domain.BadRequest("INVALID_WORKFLOW_CONFIG", "persistence store is required")
	}
	cfg := sc.Config.withDefaults()

	nowFn := func() time.Time { return cfg.Clock().UTC().Truncate(time.Microsecond) }

	opsSvc := sc.Ops
	if opsSvc == nil {
		opsSvc = operations.NewService(sc.Store, sc.Metrics, sc.Logger, operations.Config{
			DefaultLeaseDuration: cfg.LeaseDuration,
			Clock:                cfg.Clock,
		})
	}
	wsSvc := sc.Workspaces
	if wsSvc == nil {
		wsSvc = workspaces.NewServiceWithStore(&leaseFencedWorkspaceStore{
			Store: workspaces.NewStoreAdapter(sc.Store),
			store: sc.Store,
			now:   nowFn,
		}, sc.Metrics, sc.Logger)
	}
	repoSvc := sc.Repositories
	if repoSvc == nil {
		repoSvc = repositories.NewService(sc.Store, sc.Logger)
	}
	propSvc := sc.Proposals
	if propSvc == nil {
		propSvc = proposals.NewServiceWithStore(&leaseFencedProposalStore{
			Store: proposals.NewStoreAdapter(sc.Store),
			store: sc.Store,
			now:   nowFn,
		}, sc.Metrics, sc.Logger)
	}
	artSvc := sc.Artifacts
	if artSvc == nil {
		artSvc = artifacts.NewService(sc.Store, sc.Logger)
	}
	audSvc := sc.Audit
	if audSvc == nil {
		audSvc = audit.NewService(sc.Store, sc.Logger)
	}
	polEngine := sc.PolicyEngine
	if polEngine == nil {
		var err error
		polEngine, err = policy.NewEngine(policy.WithMetrics(sc.Metrics), policy.WithLogger(sc.Logger))
		if err != nil {
			return nil, err
		}
	}

	return &Service{
		store:          sc.Store,
		ops:            opsSvc,
		workspaces:     wsSvc,
		repositories:   repoSvc,
		proposals:      propSvc,
		artifacts:      artSvc,
		audit:          audSvc,
		snapshotStore:  sc.SnapshotStore,
		gitReader:      sc.GitReader,
		reconstructor:  sc.Reconstructor,
		inspector:      sc.InspectionRunner,
		decisions:      sc.Decisions,
		policyEngine:   polEngine,
		packager:       archive.NewIngressPackager(sc.Logger),
		outboxDispatch: sc.OutboxDispatcher,
		budgets:        NewBudgetLimiter(cfg.GlobalScanBudget, cfg.GlobalModelBudget, cfg.RepoConcurrencyLimit),
		logger:         sc.Logger,
		metrics:        sc.Metrics,
		tracer:         sc.Tracer,
		cfg:            cfg,
	}, nil
}

func (s *Service) now() time.Time {
	return s.cfg.Clock().UTC().Truncate(time.Microsecond)
}
