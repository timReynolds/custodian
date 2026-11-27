package gitgateway

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

// AuthenticatedPrincipal identifies an authenticated HTTPS OIDC or SSH User-CA caller.
// Sensitive token fields MUST NEVER be logged or forwarded to unauthorized destinations.
type AuthenticatedPrincipal struct {
	Principal              domain.Principal
	Groups                 []string
	AuthMethod             string // "oidc" | "ssh_cert"
	SSHKeyID               string
	SSHCertSerial          uint64
	OIDCToken              string // added to ExtraSecrets; never logged or forwarded upstream
	DelegatedUpstreamToken string // from X-Custodian-Upstream-Token / X-GitHub-Token; never logged
}

// ResolvedTarget describes the canonicalized Git destination, repository metadata,
// and effective egress mode for a request.
type ResolvedTarget struct {
	OwnerRepo            string
	CanonicalDestination string
	Host                 string
	Repository           *domain.Repository // nil when destination is unregistered
	AllowedModelRoutes   []string
	Registered           bool
	External             bool
	EgressMode           domain.EgressMode
	PassiveAuditDelivery domain.PassiveAuditDelivery
}

// RefResult represents the per-ref status returned by ReceivePackHandler for Git report-status.
type RefResult struct {
	RefName string
	OK      bool
	Message string
}

// ReceivePackRequest encapsulates a parsed git-receive-pack push request handed off from
// HTTPS Smart-HTTP or SSH transport to the M4b quarantine/inspection/policy pipeline.
type ReceivePackRequest struct {
	SessionID          uuid.UUID // optional; pipeline generates UUIDv7 if Nil
	Transport          domain.PushTransport
	Caller             AuthenticatedPrincipal
	Target             ResolvedTarget
	RefUpdates         []quarantine.RefUpdate
	ClientCapabilities []string
	PackReader         io.Reader
	SidebandWriter     io.Writer // writes raw progress/verdict lines; transport frames onto channel-2 or stderr
	UpstreamToken      string    // brokered or delegated upstream token (already in ExtraSecrets)
	ExtraSecrets       []string
}

// ReceivePackOutcome describes the terminal result of a HandleReceivePack execution.
type ReceivePackOutcome struct {
	SessionID          uuid.UUID
	Status             domain.PushSessionStatus
	Effect             domain.PolicyEffect
	UpstreamForwarded  bool
	UpstreamBytesSent  int64
	UpstreamStatusLine string
	UnpackOK           bool
	UnpackMessage      string
	RefResults         []RefResult
	PushManifestDigest string
	ErrorCode          string
	ErrorMessage       string
	HTTPStatus         int // optional HTTP status override (e.g. 503 for fail-closed unavailable)
}

// ReceivePackHandler executes push verification, policy evaluation, and conditional upstream forwarding.
type ReceivePackHandler interface {
	HandleReceivePack(ctx context.Context, req ReceivePackRequest) (ReceivePackOutcome, error)
}

// DefaultFailClosedReceivePackHandler is the M4a default stub that fails closed in ENFORCE_BLOCK
// with 503 Service Unavailable and zero upstream bytes sent until M4b wires the full pipeline.
type DefaultFailClosedReceivePackHandler struct{}

// NewDefaultFailClosedReceivePackHandler returns a fail-closed ReceivePackHandler stub.
func NewDefaultFailClosedReceivePackHandler() *DefaultFailClosedReceivePackHandler {
	return &DefaultFailClosedReceivePackHandler{}
}

// HandleReceivePack rejects every push fail-closed without touching upstream.
func (h *DefaultFailClosedReceivePackHandler) HandleReceivePack(_ context.Context, req ReceivePackRequest) (ReceivePackOutcome, error) {
	sessionID := req.SessionID
	if sessionID == uuid.Nil {
		if id, err := domain.NewID(); err == nil {
			sessionID = id
		}
	}
	if req.SidebandWriter != nil {
		_, _ = io.WriteString(req.SidebandWriter, "ENFORCE_BLOCK: push inspection pipeline is unavailable; blocking push (0 bytes sent upstream)\n")
	}
	results := make([]RefResult, 0, len(req.RefUpdates))
	for _, ru := range req.RefUpdates {
		results = append(results, RefResult{
			RefName: ru.RefName,
			OK:      false,
			Message: "push pipeline unavailable",
		})
	}
	return ReceivePackOutcome{
		SessionID:         sessionID,
		Status:            domain.PushSessionStatusBlocked,
		Effect:            domain.PolicyEffectDeny,
		UpstreamForwarded: false,
		UpstreamBytesSent: 0,
		UnpackOK:          false,
		UnpackMessage:     "push pipeline unavailable",
		RefResults:        results,
		ErrorCode:         "PUSH_PIPELINE_UNAVAILABLE",
		ErrorMessage:      "push inspection pipeline is not configured; fail-closed in ENFORCE_BLOCK",
		HTTPStatus:        http.StatusServiceUnavailable,
	}, nil
}

// LFSBatchRequest represents a Git LFS Batch API request payload.
type LFSBatchRequest struct {
	Operation string                `json:"operation"`
	Transfers []string              `json:"transfers,omitempty"`
	Objects   []LFSBatchObjectInput `json:"objects"`
}

// LFSBatchObjectInput identifies an object in a Git LFS Batch request.
type LFSBatchObjectInput struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// LFSAction describes a single download/upload transfer action in an LFS Batch response.
type LFSAction struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresIn int               `json:"expires_in,omitempty"`
}

// LFSError describes a per-object error in an LFS Batch response.
type LFSError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// LFSBatchObjectResponse represents a single object entry in an LFS Batch response.
type LFSBatchObjectResponse struct {
	OID           string               `json:"oid"`
	Size          int64                `json:"size"`
	Authenticated bool                 `json:"authenticated,omitempty"`
	Actions       map[string]LFSAction `json:"actions,omitempty"`
	Error         *LFSError            `json:"error,omitempty"`
}

// LFSBatchResponse represents the Git LFS Batch API JSON response.
type LFSBatchResponse struct {
	Transfer string                   `json:"transfer"`
	Objects  []LFSBatchObjectResponse `json:"objects"`
}

// UpstreamClient abstracts upstream Git Smart-HTTP and Git LFS transport operations.
type UpstreamClient interface {
	InfoRefs(ctx context.Context, ownerRepo, service, token string) (status int, contentType string, body []byte, refs map[string]string, err error)
	UploadPack(ctx context.Context, ownerRepo, token string, reqBody io.Reader, dst io.Writer) (status int, err error)
	ReceivePack(ctx context.Context, ownerRepo, token string, pktLineAndPack io.Reader) (status int, respBody []byte, bytesSent int64, err error)
	LFSBatch(ctx context.Context, ownerRepo, token string, req LFSBatchRequest) (status int, resp LFSBatchResponse, rawBody []byte, err error)
	LFSGetObject(ctx context.Context, ownerRepo, oid, token string, dst io.Writer) (status int, contentLength int64, err error)
	LFSPutObject(ctx context.Context, ownerRepo, oid, token string, body io.Reader, size int64) (status int, err error)
}

// ServerConfig configures the unified HTTP Smart-HTTP/LFS handler and SSH Git server.
type ServerConfig struct {
	Store               *persistence.Store
	Authenticator       *Authenticator
	TargetResolver      *TargetResolver
	TokenBroker         *TokenBroker
	Upstream            UpstreamClient
	ReceivePackHandler  ReceivePackHandler
	Limits              quarantine.Limits
	MaxLFSObjectBytes   int64
	GatewayPublicURL    string
	LFSCapabilitySecret []byte
	Metrics             *observability.Metrics
	Logger              *slog.Logger
}
