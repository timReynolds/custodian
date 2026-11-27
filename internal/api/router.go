package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/timreynolds/custodian/internal/approvals"
	"github.com/timreynolds/custodian/internal/artifacts"
	"github.com/timreynolds/custodian/internal/audit"
	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/operations"
	"github.com/timreynolds/custodian/internal/persistence"
	"github.com/timreynolds/custodian/internal/policy"
	"github.com/timreynolds/custodian/internal/proposals"
	"github.com/timreynolds/custodian/internal/repositories"
	"github.com/timreynolds/custodian/internal/workspaces"
)

const (
	defaultUploadMaxBytes    int64         = 64 << 20 // 64 MiB
	defaultCapabilityTTL     time.Duration = 5 * time.Minute
	defaultArtifactRetention time.Duration = 720 * time.Hour
	defaultMaxDiffBytes      int           = 2 << 20 // 2 MiB
	defaultDBTimeout         time.Duration = 3 * time.Second
)

// RefResolver resolves a repository's Git ref or SHA to a pinned 40-char commit SHA.
type RefResolver interface {
	ResolveRef(ctx context.Context, repo domain.Repository, ref string) (string, error)
}

// IPCorpusFileInput represents a single source file supplied when registering or reindexing an IP corpus.
type IPCorpusFileInput struct {
	Path    string
	Content string
	SHA256  string
}

// IPCorpusReindexInput provides parameters for deterministic IP corpus fingerprinting/reindexing.
type IPCorpusReindexInput struct {
	Corpus     domain.IPFingerprintCorpus
	SourceRef  string
	SourcePath string
	Files      []IPCorpusFileInput
	Force      bool
	ActorID    uuid.UUID
}

// IPCorpusReindexResult summarizes the outcome of a corpus reindex invocation.
type IPCorpusReindexResult struct {
	OperationID         *uuid.UUID
	Status              domain.IPCorpusStatus
	FingerprintsIndexed int64
	FilesProcessed      int64
	LastIndexedDigest   string
	CompletedAt         *time.Time
}

// IPCorpusReindexer performs deterministic one-way IP corpus indexing without storing raw source.
type IPCorpusReindexer interface {
	Reindex(ctx context.Context, input IPCorpusReindexInput) (IPCorpusReindexResult, error)
}

// Deps holds all dependencies wired into the Custodian REST API router.
type Deps struct {
	Store             *persistence.Store
	OIDC              auth.TokenVerifier
	Capabilities      *auth.CapabilityService
	Directory         *identity.Directory
	Snapshots         domain.SnapshotStore
	GitHubRead        RefResolver
	Repositories      *repositories.Service
	Workspaces        *workspaces.Service
	Operations        *operations.Service
	Audit             *audit.Service
	Artifacts         *artifacts.Service
	Proposals         *proposals.Service
	Approvals         *approvals.Service
	PolicyEngine      *policy.Engine
	IPCorpusReindexer IPCorpusReindexer
	Metrics           *observability.Metrics
	Tracer            trace.Tracer
	Logger            *slog.Logger

	BaseURL              string
	RepoConcurrencyLimit int
	GlobalScanBudget     int
	GlobalModelBudget    int
	MaxUploadBytes       int64
	CapabilityTTL        time.Duration
	ArtifactRetentionTTL time.Duration
	MaxDiffBytes         int
	DBTimeout            time.Duration
}

type server struct {
	deps           Deps
	repoLocksMu    sync.Mutex
	repoLocks      map[uuid.UUID]chan struct{}
	evalBudgetLock chan struct{}
	lockPool       advisoryLockPool
}

// NewRouter constructs the chi HTTP handler implementing operational endpoints,
// capability upload endpoints, and all 22 OpenAPI 3.1 /v1 paths (23 operations).
func NewRouter(deps Deps) http.Handler {
	return newServer(deps).routes()
}

func newServer(deps Deps) *server {
	if deps.MaxUploadBytes <= 0 {
		deps.MaxUploadBytes = defaultUploadMaxBytes
	}
	if deps.CapabilityTTL <= 0 {
		deps.CapabilityTTL = defaultCapabilityTTL
	}
	if deps.ArtifactRetentionTTL <= 0 {
		deps.ArtifactRetentionTTL = defaultArtifactRetention
	}
	if deps.MaxDiffBytes <= 0 {
		deps.MaxDiffBytes = defaultMaxDiffBytes
	}
	if deps.DBTimeout <= 0 {
		deps.DBTimeout = defaultDBTimeout
	}

	return &server{
		deps:           deps,
		repoLocks:      make(map[uuid.UUID]chan struct{}),
		evalBudgetLock: make(chan struct{}, 1),
	}
}

func (s *server) routes() http.Handler {
	deps := s.deps

	r := chi.NewRouter()
	r.Use(recoverMiddleware(deps.Logger))
	r.Use(observabilityMiddleware(deps.Metrics, deps.Tracer, deps.Logger))

	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		writeError(w, req, deps.Logger, domain.NotFound("ROUTE_NOT_FOUND", "endpoint not found"))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		writeError(w, req, deps.Logger, &domain.DomainError{
			Status:  http.StatusMethodNotAllowed,
			ErrCode: "METHOD_NOT_ALLOWED",
			Message: "method not allowed",
		})
	})

	// Operational endpoints (unauthenticated).
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/metrics", s.handleMetrics)

	// Capability-authenticated upload endpoint (NEVER accepts OIDC, NEVER allows GET).
	r.Put("/v1/uploads/workspaces/{id}/generations/{generation}/*", s.handleUploadSnapshot)
	r.Get("/v1/uploads/workspaces/{id}/generations/{generation}/*", s.handleUploadMethodNotAllowed)

	// Authenticated /v1 REST API (OIDC bearer tokens ONLY).
	r.Route("/v1", func(v1 chi.Router) {
		v1.Use(requireOIDCMiddleware(deps.OIDC, deps.Directory, deps.Logger, deps.DBTimeout))

		v1.Post("/workspaces", s.handleCreateWorkspace)
		v1.Get("/workspaces/{id}", s.handleGetWorkspace)
		v1.Get("/workspaces/{id}/source", s.handleGetWorkspaceSource)
		v1.Get("/workspaces/{id}/source/artifact", s.handleDownloadWorkspaceSourceArtifact)
		v1.Post("/workspaces/{id}/proposals", s.handleSubmitProposal)

		v1.Get("/proposals/{id}", s.handleGetProposal)
		v1.Get("/proposals/{id}/diff", s.handleGetProposalDiff)
		v1.Get("/proposals/{id}/findings", s.handleListProposalFindings)
		v1.Get("/proposals/{id}/assessments", s.handleListProposalAssessments)
		v1.Post("/proposals/{id}/evaluate", s.handleEvaluateProposal)
		v1.Post("/proposals/{id}/approvals", s.handleCreateApproval)
		v1.Post("/proposals/{id}/publish", s.handlePublishProposal)

		v1.Get("/publications/{id}", s.handleGetPublication)

		v1.Post("/policies/validate", s.handleValidatePolicy)
		v1.Post("/policies/evaluate", s.handleEvaluatePolicy)

		v1.Get("/operations/{id}", s.handleGetOperation)
		v1.Get("/audit/events", s.handleListAuditEvents)

		v1.Get("/pushes", s.handleListPushes)
		v1.Get("/pushes/{id}", s.handleGetPush)
		v1.Post("/pushes/{id}/approvals", s.handleApprovePush)

		v1.Put("/repositories/{id}/egress-mode", s.handleSetRepositoryEgressMode)

		v1.Get("/ip-corpora", s.handleListIPCorpora)
		v1.Post("/ip-corpora", s.handleCreateIPCorpus)
		v1.Post("/ip-corpora/{id}/reindex", s.handleReindexIPCorpus)
	})

	return r
}

var errDBTimeout = errors.New("database operation timeout")

func withDBTimeoutCause(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultDBTimeout
	}
	return context.WithTimeoutCause(parent, timeout, errDBTimeout)
}

func (s *server) withDBTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	return withDBTimeoutCause(parent, s.deps.DBTimeout)
}

func mapDBTimeoutError(dbCtx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var domErr *domain.DomainError
	if errors.As(err, &domErr) {
		if domErr.Code() == "DATABASE_TIMEOUT" && dbCtx != nil && errors.Is(dbCtx.Err(), context.DeadlineExceeded) && !errors.Is(context.Cause(dbCtx), errDBTimeout) {
			if domErr.Cause != nil {
				return domErr.Cause
			}
			return context.DeadlineExceeded
		}
		return err
	}
	if dbCtx != nil && errors.Is(context.Cause(dbCtx), errDBTimeout) && errors.Is(err, context.DeadlineExceeded) {
		return domain.WrapError(domain.ErrUnavailable, "DATABASE_TIMEOUT", "database operation timed out", err)
	}
	return err
}
