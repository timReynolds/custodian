package decisions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	EnvModelGatewayURL      = "CUSTODIAN_MODEL_GATEWAY_URL"
	DefaultAssessPath       = "/v1/assess"
	DefaultGatewayTimeout   = 30 * time.Second
	DefaultMaxResponseBytes = 4 << 20 // 4 MiB
)

// GatewayConfigFromEnv builds a GatewayConfig from environment variables with safe defaults.
func GatewayConfigFromEnv() GatewayConfig {
	return GatewayConfig{
		BaseURL:          strings.TrimSpace(os.Getenv(EnvModelGatewayURL)),
		AssessPath:       DefaultAssessPath,
		Timeout:          DefaultGatewayTimeout,
		MaxResponseBytes: DefaultMaxResponseBytes,
	}
}

// HTTPGatewayClient communicates with an external HTTP Stage B model gateway.
type HTTPGatewayClient struct {
	endpoint         string
	apiKey           string
	maxResponseBytes int64
	httpClient       *http.Client
	configErr        error
}

// NewHTTPGatewayClient constructs a validated HTTP gateway client.
func NewHTTPGatewayClient(cfg GatewayConfig) (*HTTPGatewayClient, error) {
	assessPath := strings.TrimSpace(cfg.AssessPath)
	if assessPath == "" {
		assessPath = DefaultAssessPath
	}
	if !strings.HasPrefix(assessPath, "/") {
		assessPath = "/" + assessPath
	}

	maxResp := cfg.MaxResponseBytes
	if maxResp <= 0 {
		maxResp = DefaultMaxResponseBytes
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultGatewayTimeout
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return &HTTPGatewayClient{
			apiKey:           cfg.APIKey,
			maxResponseBytes: maxResp,
			httpClient:       client,
			configErr:        domain.Unavailable("GATEWAY_NOT_CONFIGURED", "model gateway URL is not configured"),
		}, nil
	}

	endpoint, err := resolveAssessURL(base, assessPath)
	if err != nil {
		return nil, err
	}

	return &HTTPGatewayClient{
		endpoint:         endpoint,
		apiKey:           cfg.APIKey,
		maxResponseBytes: maxResp,
		httpClient:       client,
	}, nil
}

func resolveAssessURL(baseURL, assessPath string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", domain.WrapError(domain.ErrBadRequest, "INVALID_GATEWAY_URL", "invalid model gateway URL", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Host) == "" {
		return "", domain.BadRequest("INVALID_GATEWAY_URL", "model gateway URL must be an http(s) URL with host")
	}

	// Treat an empty path as a gateway root and append assessPath; preserve
	// explicit non-empty endpoint paths without double-appending.
	trimmedPath := strings.TrimRight(u.Path, "/")
	if trimmedPath == "" {
		u.Path = assessPath
	} else {
		u.Path = trimmedPath
	}
	return u.String(), nil
}

// Endpoint returns the resolved HTTP endpoint URL used for assessment requests.
func (c *HTTPGatewayClient) Endpoint() string {
	return c.endpoint
}

// Invoke sends a Stage B assessment request to the configured gateway endpoint.
func (c *HTTPGatewayClient) Invoke(ctx context.Context, req GatewayRequest) (GatewayResponse, error) {
	if c == nil {
		return GatewayResponse{}, domain.Unavailable("GATEWAY_NOT_CONFIGURED", "gateway client is nil")
	}
	if c.configErr != nil {
		return GatewayResponse{}, c.configErr
	}
	if strings.TrimSpace(c.endpoint) == "" {
		return GatewayResponse{}, domain.Unavailable("GATEWAY_NOT_CONFIGURED", "model gateway endpoint is empty")
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return GatewayResponse{}, domain.WrapError(domain.ErrInternal, "GATEWAY_REQUEST_ENCODE_FAILED", "failed to encode gateway request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return GatewayResponse{}, domain.WrapError(domain.ErrBadRequest, "GATEWAY_REQUEST_BUILD_FAILED", "failed to construct gateway HTTP request", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if route := strings.TrimSpace(req.ModelRoute); route != "" {
		httpReq.Header.Set("X-Model-Route", route)
	}
	if strings.TrimSpace(c.apiKey) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.apiKey))
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if isTimeoutError(ctx, err) {
			return GatewayResponse{}, domain.WrapError(domain.ErrUnavailable, "GATEWAY_TIMEOUT", "model gateway request timed out", err)
		}
		return GatewayResponse{}, domain.WrapError(domain.ErrUnavailable, "GATEWAY_UNAVAILABLE", "model gateway request failed", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, c.maxResponseBytes+1)
	rawBody, readErr := io.ReadAll(limited)
	if readErr != nil {
		if isTimeoutError(ctx, readErr) {
			return GatewayResponse{}, domain.WrapError(domain.ErrUnavailable, "GATEWAY_TIMEOUT", "reading model gateway response timed out", readErr)
		}
		return GatewayResponse{}, domain.WrapError(domain.ErrUnavailable, "GATEWAY_READ_FAILED", "failed reading model gateway response", readErr)
	}
	if int64(len(rawBody)) > c.maxResponseBytes {
		return GatewayResponse{}, domain.BadRequest("GATEWAY_RESPONSE_TOO_LARGE", "model gateway response exceeded maximum size limit")
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return GatewayResponse{RawBody: rawBody, StatusCode: resp.StatusCode},
			domain.RateLimited("GATEWAY_RATE_LIMITED", "model gateway rate limited request")
	}
	if resp.StatusCode >= 500 {
		return GatewayResponse{RawBody: rawBody, StatusCode: resp.StatusCode},
			domain.Unavailable("GATEWAY_UNAVAILABLE", fmt.Sprintf("model gateway returned HTTP %d", resp.StatusCode))
	}
	if resp.StatusCode >= 400 {
		return GatewayResponse{RawBody: rawBody, StatusCode: resp.StatusCode},
			domain.BadRequest("GATEWAY_BAD_REQUEST", fmt.Sprintf("model gateway rejected request with HTTP %d", resp.StatusCode))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return GatewayResponse{RawBody: rawBody, StatusCode: resp.StatusCode},
			domain.Unavailable("GATEWAY_UNEXPECTED_STATUS", fmt.Sprintf("model gateway returned unexpected HTTP %d", resp.StatusCode))
	}

	return GatewayResponse{
		RawBody:    rawBody,
		StatusCode: resp.StatusCode,
	}, nil
}

func isTimeoutError(ctx context.Context, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// UnwrapGatewayResponse decodes either an OpenAI chat.completion envelope
// (choices[0].message.content + model + optional usage) or a raw Stage B
// AssessmentResult JSON payload.
func UnwrapGatewayResponse(rawBody []byte, fallbackModelVersion string) (candidateJSON []byte, modelVersion string, costUSD float64, err error) {
	trimmed := bytes.TrimSpace(rawBody)
	if len(trimmed) == 0 {
		return nil, fallbackOrDefaultModelVersion(fallbackModelVersion), 0, domain.Unprocessable(
			"EMPTY_GATEWAY_RESPONSE",
			"model gateway returned an empty response body",
		)
	}

	var top map[string]any
	if unmarshalErr := json.Unmarshal(trimmed, &top); unmarshalErr != nil {
		return nil, fallbackOrDefaultModelVersion(fallbackModelVersion), 0, domain.WrapError(
			domain.ErrUnprocessable,
			"MALFORMED_GATEWAY_JSON",
			"model gateway response is not valid JSON",
			unmarshalErr,
		)
	}

	modelVersion = extractModelVersion(top, fallbackModelVersion)
	costUSD = extractUsageCostUSD(top)

	if choicesRaw, hasChoices := top["choices"]; hasChoices {
		choices, ok := choicesRaw.([]any)
		if !ok || len(choices) == 0 {
			return nil, modelVersion, costUSD, domain.Unprocessable(
				"INVALID_GATEWAY_ENVELOPE",
				"chat completion envelope missing non-empty choices array",
			)
		}
		first, ok := choices[0].(map[string]any)
		if !ok {
			return nil, modelVersion, costUSD, domain.Unprocessable(
				"INVALID_GATEWAY_ENVELOPE",
				"chat completion envelope choices[0] is not an object",
			)
		}
		msg, ok := first["message"].(map[string]any)
		if !ok {
			return nil, modelVersion, costUSD, domain.Unprocessable(
				"INVALID_GATEWAY_ENVELOPE",
				"chat completion envelope missing message object",
			)
		}
		content, ok := msg["content"].(string)
		if !ok || strings.TrimSpace(content) == "" {
			return nil, modelVersion, costUSD, domain.Unprocessable(
				"INVALID_GATEWAY_ENVELOPE",
				"chat completion envelope missing non-empty message.content",
			)
		}
		return []byte(content), modelVersion, costUSD, nil
	}

	return trimmed, modelVersion, costUSD, nil
}

func extractModelVersion(top map[string]any, fallback string) string {
	for _, key := range []string{"model_version", "model"} {
		if s, ok := top[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return fallbackOrDefaultModelVersion(fallback)
}

func extractUsageCostUSD(top map[string]any) float64 {
	usage, ok := top["usage"].(map[string]any)
	if !ok {
		return 0
	}
	if v, ok := usage["cost_usd"].(float64); ok && v > 0 {
		return v
	}
	return 0
}

func fallbackOrDefaultModelVersion(fallback string) string {
	if s := strings.TrimSpace(fallback); s != "" {
		return s
	}
	return "gateway-unknown"
}
