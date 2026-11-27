package decisions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

func TestResolveAssessURL_NoDoubleAppend(t *testing.T) {
	t.Parallel()

	cases := []struct {
		base string
		want string
	}{
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/v1/assess"},
		{"http://127.0.0.1:8080/", "http://127.0.0.1:8080/v1/assess"},
		{"http://127.0.0.1:8080/v1/assess", "http://127.0.0.1:8080/v1/assess"},
		{"http://127.0.0.1:8080/v1/assess/", "http://127.0.0.1:8080/v1/assess"},
		{"https://gw.internal/v1/chat/completions", "https://gw.internal/v1/chat/completions"},
	}

	for _, tc := range cases {
		got, err := resolveAssessURL(tc.base, DefaultAssessPath)
		if err != nil {
			t.Fatalf("resolveAssessURL(%q) error: %v", tc.base, err)
		}
		if got != tc.want {
			t.Fatalf("resolveAssessURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

func TestHTTPGatewayClient_InvokeAndErrorMapping(t *testing.T) {
	t.Parallel()

	t.Run("sends X-Model-Route, Bearer auth, and OpenAI messages", func(t *testing.T) {
		t.Parallel()

		var gotPath, gotRoute, gotAuth string
		var gotBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotRoute = r.Header.Get("X-Model-Route")
			gotAuth = r.Header.Get("Authorization")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &gotBody)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.94,"summary":"ok","findings":[],"limitations":[]}`))
		}))
		defer srv.Close()

		client, err := NewHTTPGatewayClient(GatewayConfig{
			BaseURL: srv.URL,
			APIKey:  "secret-gw-key",
			Timeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Invoke(context.Background(), GatewayRequest{
			ModelRoute:     "approved-code-review",
			Model:          "approved-code-review",
			AssessmentType: "SECURITY_REVIEW",
			Messages: []GatewayMessage{
				{Role: "system", Content: "static"},
				{Role: "user", Content: "{}"},
			},
		})
		if err != nil {
			t.Fatalf("Invoke error: %v", err)
		}
		if gotPath != "/v1/assess" {
			t.Fatalf("got path %q, want /v1/assess", gotPath)
		}
		if gotRoute != "approved-code-review" {
			t.Fatalf("got X-Model-Route %q", gotRoute)
		}
		if gotAuth != "Bearer secret-gw-key" {
			t.Fatalf("got Authorization %q", gotAuth)
		}
		if gotBody["model_route"] != "approved-code-review" {
			t.Fatalf("expected model_route in body, got %+v", gotBody)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("maps 503 to ErrUnavailable", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
		}))
		defer srv.Close()

		client, _ := NewHTTPGatewayClient(GatewayConfig{BaseURL: srv.URL})
		_, err := client.Invoke(context.Background(), GatewayRequest{ModelRoute: "r"})
		if !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("expected ErrUnavailable, got %v", err)
		}
	})

	t.Run("maps 429 to ErrRateLimited", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()

		client, _ := NewHTTPGatewayClient(GatewayConfig{BaseURL: srv.URL})
		_, err := client.Invoke(context.Background(), GatewayRequest{ModelRoute: "r"})
		if !errors.Is(err, domain.ErrRateLimited) {
			t.Fatalf("expected ErrRateLimited, got %v", err)
		}
	})

	t.Run("maps 400 to ErrBadRequest", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()

		client, _ := NewHTTPGatewayClient(GatewayConfig{BaseURL: srv.URL})
		_, err := client.Invoke(context.Background(), GatewayRequest{ModelRoute: "r"})
		if !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest, got %v", err)
		}
	})

	t.Run("maps timeout to ErrUnavailable", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(150 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		client, _ := NewHTTPGatewayClient(GatewayConfig{
			BaseURL: srv.URL,
			Timeout: 30 * time.Millisecond,
		})
		_, err := client.Invoke(context.Background(), GatewayRequest{ModelRoute: "r"})
		if !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("expected ErrUnavailable on timeout, got %v", err)
		}
	})

	t.Run("enforces MaxResponseBytes", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("a", 512)))
		}))
		defer srv.Close()

		client, _ := NewHTTPGatewayClient(GatewayConfig{
			BaseURL:          srv.URL,
			MaxResponseBytes: 128,
		})
		_, err := client.Invoke(context.Background(), GatewayRequest{ModelRoute: "r"})
		if !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest for oversized response, got %v", err)
		}
	})
}

func TestUnwrapGatewayResponse(t *testing.T) {
	t.Parallel()

	t.Run("OpenAI chat.completion envelope", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`{
			"id": "chatcmpl-1",
			"object": "chat.completion",
			"model": "gpt-review-2026",
			"usage": {"cost_usd": 0.0125},
			"choices": [
				{
					"index": 0,
					"message": {
						"role": "assistant",
						"content": "{\"schema_version\":\"1\",\"assessment_type\":\"SECURITY_REVIEW\",\"risk\":\"LOW\",\"disposition\":\"CLEAR\",\"confidence\":0.94,\"summary\":\"ok\",\"findings\":[],\"limitations\":[]}"
					},
					"finish_reason": "stop"
				}
			]
		}`)
		cand, modelVer, cost, err := UnwrapGatewayResponse(raw, "fallback-route")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if modelVer != "gpt-review-2026" {
			t.Fatalf("got modelVer=%q, want gpt-review-2026", modelVer)
		}
		if cost != 0.0125 {
			t.Fatalf("got cost=%v, want 0.0125", cost)
		}
		if !strings.Contains(string(cand), `"disposition":"CLEAR"`) {
			t.Fatalf("unexpected candidateJSON: %s", cand)
		}
	})

	t.Run("raw JSON payload with fallback model version", func(t *testing.T) {
		t.Parallel()
		raw := []byte(`{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW","disposition":"CLEAR","confidence":0.9,"summary":"ok","findings":[],"limitations":[]}`)
		cand, modelVer, _, err := UnwrapGatewayResponse(raw, "approved-code-review")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if modelVer != "approved-code-review" {
			t.Fatalf("got modelVer=%q, want approved-code-review", modelVer)
		}
		if string(cand) != string(raw) {
			t.Fatalf("expected raw payload passthrough")
		}
	})

	t.Run("invalid envelope rejected", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := UnwrapGatewayResponse([]byte(`{"choices":[]}`), "route")
		if !errors.Is(err, domain.ErrUnprocessable) {
			t.Fatalf("expected ErrUnprocessable, got %v", err)
		}
	})
}

func TestGatewayConfigFromEnv(t *testing.T) {
	t.Setenv(EnvModelGatewayURL, "http://127.0.0.1:9999")
	cfg := GatewayConfigFromEnv()
	if cfg.BaseURL != "http://127.0.0.1:9999" {
		t.Fatalf("got BaseURL=%q", cfg.BaseURL)
	}
	if cfg.AssessPath != DefaultAssessPath || cfg.Timeout != DefaultGatewayTimeout || cfg.MaxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}
