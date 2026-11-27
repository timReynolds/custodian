package decisions

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

// AssessRequest contains all server-assembled inputs for a Stage B model assessment.
type AssessRequest struct {
	ProposalID         uuid.UUID
	ArtifactID         uuid.UUID
	Repository         domain.Repository
	AllowedModelRoutes []string
	ModelRoute         string
	AssessmentType     string
	BaseCommit         string
	TargetRef          string
	ChangedPaths       []string
	CanonicalDiff      string
	Findings           []domain.Finding
	ScanRuns           []domain.ScanRun
}

// RoutePolicy constrains which model routes may be used for repository classifications.
type RoutePolicy struct {
	// ClassificationRoutes restricts allowed routes per repository classification when present.
	ClassificationRoutes map[domain.Classification][]string
	// RequireClassificationRule requires ClassificationRoutes to contain an explicit entry
	// for the repository's classification.
	RequireClassificationRule bool
	// RouteMaxClassification restricts a route to repositories at or below the configured classification.
	RouteMaxClassification map[string]domain.Classification
}

// GatewayConfig configures the HTTP Stage B model gateway client.
type GatewayConfig struct {
	BaseURL          string
	AssessPath       string
	APIKey           string
	Timeout          time.Duration
	MaxResponseBytes int64
	HTTPClient       *http.Client
}

// GatewayMessage represents a single OpenAI-compatible chat message.
type GatewayMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// GatewayRequest is the wire payload sent to the external model gateway.
type GatewayRequest struct {
	ModelRoute     string           `json:"model_route"`
	Model          string           `json:"model"`
	AssessmentType string           `json:"assessment_type"`
	Temperature    float64          `json:"temperature"`
	Messages       []GatewayMessage `json:"messages"`
}

// GatewayResponse carries the raw HTTP response and optional usage/model metadata from the gateway.
type GatewayResponse struct {
	RawBody      []byte
	ModelVersion string
	CostUSD      float64
	StatusCode   int
}

// GatewayClient invokes a Stage B model gateway over a transport boundary.
type GatewayClient interface {
	Invoke(ctx context.Context, req GatewayRequest) (GatewayResponse, error)
}
