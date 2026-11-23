package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// StageBFinding matches Implementation Spec §7 Stage B JSON schema.
type StageBFinding struct {
	Category          string   `json:"category"`
	EvidenceIDs       []string `json:"evidence_ids"`
	Reason            string   `json:"reason"`
	RecommendedAction string   `json:"recommended_action"`
}

// StageBAssessmentPayload matches Implementation Spec §7 Stage B structured JSON output.
type StageBAssessmentPayload struct {
	SchemaVersion  string          `json:"schema_version"`
	AssessmentType string          `json:"assessment_type"`
	Risk           string          `json:"risk"`
	Disposition    string          `json:"disposition"`
	Confidence     float64         `json:"confidence"`
	Summary        string          `json:"summary"`
	Findings       []StageBFinding `json:"findings"`
	Limitations    []string        `json:"limitations"`
}

// GatewayMessage models an OpenAI-style prompt message recorded by MockGateway.
type GatewayMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// RecordedGatewayRequest records an incoming Stage B model gateway HTTP request.
type RecordedGatewayRequest struct {
	Timestamp     time.Time
	Method        string
	Path          string
	RawQuery      string
	Headers       http.Header
	Authorization string
	Route         string
	RawBody       []byte
	ParsedBody    map[string]any
	Messages      []GatewayMessage
	EvidenceIDs   []string
}

// GatewayMode selects deterministic MockGateway response behavior.
type GatewayMode string

const (
	GatewayModeClean              GatewayMode = "clean"
	GatewayModeHighRiskReview     GatewayMode = "high_risk_review"
	GatewayModeBlock              GatewayMode = "block"
	GatewayModeIndeterminate      GatewayMode = "indeterminate"
	GatewayModeMalformedJSON      GatewayMode = "malformed_json"
	GatewayModeUnknownDisposition GatewayMode = "unknown_disposition"
	GatewayModeInvalidEvidenceIDs GatewayMode = "invalid_evidence_ids"
	GatewayModeMissingFields      GatewayMode = "missing_fields"
	GatewayModeOutage503          GatewayMode = "outage_503"
	GatewayModeTimeout            GatewayMode = "timeout"
)

// GatewayResponseFormat selects raw JSON vs OpenAI chat completion envelope.
type GatewayResponseFormat string

const (
	GatewayFormatAuto       GatewayResponseFormat = "auto"
	GatewayFormatRawJSON    GatewayResponseFormat = "raw_json"
	GatewayFormatOpenAIChat GatewayResponseFormat = "openai_chat"
)

// GatewayProgram configures a single or default MockGateway response.
type GatewayProgram struct {
	Mode           GatewayMode
	Format         GatewayResponseFormat
	AssessmentType string
	Summary        string
	Confidence     float64
	EvidenceIDs    []string
	Delay          time.Duration
	CustomStatus   int
	CustomBody     []byte
	DynamicFn      func(req RecordedGatewayRequest) (int, []byte)
}

// MockGateway is an ephemeral loopback HTTP double for Custodian's Stage B model gateway.
type MockGateway struct {
	t         testing.TB
	server    *httptest.Server
	contracts *Contracts

	mu            sync.Mutex
	defaultProg   GatewayProgram
	queue         []GatewayProgram
	routeProgs    map[string]GatewayProgram
	requests      []RecordedGatewayRequest
	defaultFormat GatewayResponseFormat
}

// NewMockGateway starts MockGateway on 127.0.0.1:0 and registers t.Cleanup(gw.Close).
func NewMockGateway(t testing.TB, contracts *Contracts) *MockGateway {
	t.Helper()
	if contracts == nil {
		contracts = DefaultContracts()
	}
	fmtMode := GatewayFormatAuto
	switch strings.ToLower(strings.TrimSpace(contracts.GatewayResponseFormat)) {
	case "raw_json":
		fmtMode = GatewayFormatRawJSON
	case "openai_chat":
		fmtMode = GatewayFormatOpenAIChat
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback for MockGateway: %v", err)
	}

	gw := &MockGateway{
		t:             t,
		contracts:     contracts,
		defaultProg:   GatewayProgram{Mode: GatewayModeClean, Confidence: 0.94},
		routeProgs:    make(map[string]GatewayProgram),
		defaultFormat: fmtMode,
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(gw.handleHTTP))
	srv.Listener = ln
	srv.Start()
	gw.server = srv
	t.Cleanup(gw.Close)
	return gw
}

func (g *MockGateway) URL() string { return g.server.URL }

func (g *MockGateway) Close() {
	if g != nil && g.server != nil {
		g.server.Close()
	}
}

func (g *MockGateway) SetDefault(prog GatewayProgram) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.defaultProg = prog
}

func (g *MockGateway) SetMode(mode GatewayMode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.defaultProg = GatewayProgram{Mode: mode, Confidence: 0.92}
}

func (g *MockGateway) Enqueue(progs ...GatewayProgram) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.queue = append(g.queue, progs...)
}

func (g *MockGateway) SetRouteProgram(route string, prog GatewayProgram) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routeProgs[route] = prog
}

func (g *MockGateway) ClearRoutePrograms() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.routeProgs = make(map[string]GatewayProgram)
}

func (g *MockGateway) ResetRequests() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = nil
}

func (g *MockGateway) Requests() []RecordedGatewayRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]RecordedGatewayRequest, len(g.requests))
	for i, req := range g.requests {
		cp := req
		cp.RawBody = append([]byte(nil), req.RawBody...)
		cp.Messages = append([]GatewayMessage(nil), req.Messages...)
		cp.EvidenceIDs = append([]string(nil), req.EvidenceIDs...)
		cp.Headers = req.Headers.Clone()
		out[i] = cp
	}
	return out
}

func (g *MockGateway) LastRequest() (RecordedGatewayRequest, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.requests) == 0 {
		return RecordedGatewayRequest{}, false
	}
	req := g.requests[len(g.requests)-1]
	req.RawBody = append([]byte(nil), req.RawBody...)
	req.Messages = append([]GatewayMessage(nil), req.Messages...)
	req.EvidenceIDs = append([]string(nil), req.EvidenceIDs...)
	req.Headers = req.Headers.Clone()
	return req, true
}

func (g *MockGateway) WaitForRequests(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		count := len(g.requests)
		g.mu.Unlock()
		if count >= n {
			return true
		}
		time.Sleep(15 * time.Millisecond)
	}
	return false
}

var findingIDRe = regexp.MustCompile(`finding_[A-Za-z0-9_-]+`)

func extractEvidenceIDs(rawBody []byte, parsed map[string]any) []string {
	seen := make(map[string]struct{})
	var ids []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if evID, ok := x["evidence_id"].(string); ok {
				add(evID)
			}
			if arr, ok := x["evidence_ids"].([]any); ok {
				for _, elem := range arr {
					if s, ok := elem.(string); ok {
						add(s)
					}
				}
			}
			if findings, ok := x["findings"].([]any); ok {
				for _, f := range findings {
					if fm, ok := f.(map[string]any); ok {
						if fid, ok := fm["id"].(string); ok {
							add(fid)
						}
						if eid, ok := fm["evidence_id"].(string); ok {
							add(eid)
						}
						if eids, ok := fm["evidence_ids"].([]any); ok {
							for _, elem := range eids {
								if s, ok := elem.(string); ok {
									add(s)
								}
							}
						}
					}
				}
			}
			for _, val := range x {
				walk(val)
			}
		case []any:
			for _, elem := range x {
				walk(elem)
			}
		case string:
			trimmed := strings.TrimSpace(x)
			if len(trimmed) >= 2 && (trimmed[0] == '{' || trimmed[0] == '[') {
				var nested any
				if json.Unmarshal([]byte(trimmed), &nested) == nil {
					walk(nested)
				}
			}
		}
	}
	if parsed != nil {
		walk(parsed)
	}

	bodyStr := string(rawBody)
	for _, m := range findingIDRe.FindAllString(bodyStr, -1) {
		add(m)
	}
	return ids
}

func extractMessages(parsed map[string]any) []GatewayMessage {
	if parsed == nil {
		return nil
	}
	var out []GatewayMessage
	if rawMsgs, ok := parsed["messages"].([]any); ok {
		for _, item := range rawMsgs {
			if m, ok := item.(map[string]any); ok {
				role, _ := m["role"].(string)
				content, _ := m["content"].(string)
				out = append(out, GatewayMessage{Role: role, Content: content})
			}
		}
	}
	if sys, ok := parsed["system_prompt"].(string); ok && sys != "" {
		out = append(out, GatewayMessage{Role: "system", Content: sys})
	}
	if usr, ok := parsed["user_prompt"].(string); ok && usr != "" {
		out = append(out, GatewayMessage{Role: "user", Content: usr})
	}
	return out
}

func extractRoute(r *http.Request, parsed map[string]any) string {
	if hdr := strings.TrimSpace(r.Header.Get("X-Model-Route")); hdr != "" {
		return hdr
	}
	if parsed != nil {
		for _, key := range []string{"model_route", "route", "model"} {
			if v, ok := parsed[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func (g *MockGateway) selectProgram(route string) (GatewayProgram, GatewayResponseFormat) {
	g.mu.Lock()
	defer g.mu.Unlock()

	fmtMode := g.defaultFormat
	if len(g.queue) > 0 {
		prog := g.queue[0]
		g.queue = g.queue[1:]
		if prog.Format != "" {
			fmtMode = prog.Format
		}
		return prog, fmtMode
	}
	if route != "" {
		if prog, ok := g.routeProgs[route]; ok {
			if prog.Format != "" {
				fmtMode = prog.Format
			}
			return prog, fmtMode
		}
	}
	prog := g.defaultProg
	if prog.Format != "" {
		fmtMode = prog.Format
	}
	return prog, fmtMode
}

func (g *MockGateway) handleHTTP(w http.ResponseWriter, r *http.Request) {
	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	var parsed map[string]any
	if len(bytes.TrimSpace(rawBody)) > 0 {
		_ = json.Unmarshal(rawBody, &parsed)
	}
	route := extractRoute(r, parsed)
	rec := RecordedGatewayRequest{
		Timestamp:     time.Now().UTC(),
		Method:        r.Method,
		Path:          r.URL.Path,
		RawQuery:      r.URL.RawQuery,
		Headers:       r.Header.Clone(),
		Authorization: r.Header.Get("Authorization"),
		Route:         route,
		RawBody:       rawBody,
		ParsedBody:    parsed,
		Messages:      extractMessages(parsed),
		EvidenceIDs:   extractEvidenceIDs(rawBody, parsed),
	}

	g.mu.Lock()
	g.requests = append(g.requests, rec)
	g.mu.Unlock()

	prog, fmtMode := g.selectProgram(route)
	if prog.DynamicFn != nil {
		status, body := prog.DynamicFn(rec)
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	if prog.Delay > 0 && prog.Mode != GatewayModeTimeout {
		select {
		case <-time.After(prog.Delay):
		case <-r.Context().Done():
			return
		}
	}

	if prog.CustomStatus != 0 || prog.CustomBody != nil {
		status := prog.CustomStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(prog.CustomBody)
		return
	}

	switch prog.Mode {
	case GatewayModeOutage503:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"model gateway unavailable"}`))
		return
	case GatewayModeTimeout:
		delay := prog.Delay
		if delay <= 0 {
			delay = 5 * time.Second
		}
		select {
		case <-time.After(delay):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte(`{"error":"model gateway timeout"}`))
		case <-r.Context().Done():
		}
		return
	case GatewayModeMalformedJSON:
		g.writeContent(w, r.URL.Path, fmtMode, []byte(`{"schema_version":"1","assessment_type":"SECURITY_REVIEW","risk":"LOW",`))
		return
	case GatewayModeMissingFields:
		g.writeContent(w, r.URL.Path, fmtMode, []byte(`{}`))
		return
	}

	payload := g.buildPayload(prog, rec.EvidenceIDs)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	g.writeContent(w, r.URL.Path, fmtMode, jsonBytes)
}

func (g *MockGateway) writeContent(w http.ResponseWriter, path string, fmtMode GatewayResponseFormat, content []byte) {
	useOpenAI := fmtMode == GatewayFormatOpenAIChat ||
		(fmtMode == GatewayFormatAuto && strings.HasSuffix(path, "/chat/completions"))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if !useOpenAI {
		_, _ = w.Write(content)
		return
	}

	envelope := map[string]any{
		"id":     "chatcmpl-custodian-e2e",
		"object": "chat.completion",
		"model":  "approved-code-review",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": string(content),
				},
				"finish_reason": "stop",
			},
		},
	}
	_ = json.NewEncoder(w).Encode(envelope)
}

func (g *MockGateway) buildPayload(prog GatewayProgram, callerEvidenceIDs []string) StageBAssessmentPayload {
	assessmentType := prog.AssessmentType
	if assessmentType == "" {
		assessmentType = "SECURITY_REVIEW"
	}
	conf := prog.Confidence
	if conf == 0 {
		conf = 0.90
	}

	evidenceIDs := append([]string(nil), prog.EvidenceIDs...)
	if len(evidenceIDs) == 0 {
		evidenceIDs = append([]string(nil), callerEvidenceIDs...)
	}

	p := StageBAssessmentPayload{
		SchemaVersion:  "1",
		AssessmentType: assessmentType,
		Confidence:     conf,
		Findings:       []StageBFinding{},
		Limitations:    []string{},
	}

	switch prog.Mode {
	case "", GatewayModeClean:
		cleanDisp := "CLEAR"
		if g.contracts != nil && strings.TrimSpace(g.contracts.GatewayCleanDisposition) != "" {
			cleanDisp = g.contracts.GatewayCleanDisposition
		}
		p.Risk = "LOW"
		p.Disposition = cleanDisp
		p.Summary = nonEmpty(prog.Summary, "No policy-relevant risks identified in submitted change")
		if len(evidenceIDs) > 0 {
			p.Findings = []StageBFinding{
				{
					Category:          "CONTEXTUAL_REVIEW",
					EvidenceIDs:       evidenceIDs,
					Reason:            "Reviewed Stage A evidence and confirmed benign usage",
					RecommendedAction: "NONE",
				},
			}
		}

	case GatewayModeHighRiskReview:
		p.Risk = "HIGH"
		p.Disposition = "REVIEW"
		p.Summary = nonEmpty(prog.Summary, "Potential reuse of restricted implementation")
		p.Limitations = []string{"Source ownership cannot be established from similarity alone"}
		if len(evidenceIDs) > 0 {
			p.Findings = []StageBFinding{
				{
					Category:          "SOURCE_SIMILARITY",
					EvidenceIDs:       evidenceIDs,
					Reason:            "Non-trivial structural similarity",
					RecommendedAction: "IP_REVIEW",
				},
			}
		}

	case GatewayModeBlock:
		p.Risk = "CRITICAL"
		p.Disposition = "BLOCK"
		p.Summary = nonEmpty(prog.Summary, "Critical security or IP violation detected")
		if len(evidenceIDs) > 0 {
			p.Findings = []StageBFinding{
				{
					Category:          "SECURITY_VIOLATION",
					EvidenceIDs:       evidenceIDs,
					Reason:            "Verified high-severity Stage A finding",
					RecommendedAction: "BLOCK",
				},
			}
		}

	case GatewayModeIndeterminate:
		p.Risk = "NONE"
		p.Disposition = "INDETERMINATE"
		p.Confidence = 0.0
		p.Summary = nonEmpty(prog.Summary, "Assessment indeterminate")
		p.Limitations = []string{"Insufficient authorised context to complete assessment"}

	case GatewayModeUnknownDisposition:
		p.Risk = "LOW"
		p.Disposition = "SHIP_IT_YOLO"
		p.Summary = nonEmpty(prog.Summary, "Invalid disposition test")

	case GatewayModeInvalidEvidenceIDs:
		p.Risk = "HIGH"
		p.Disposition = "REVIEW"
		p.Summary = nonEmpty(prog.Summary, "Ungrounded evidence test")
		p.Findings = []StageBFinding{
			{
				Category:          "SOURCE_SIMILARITY",
				EvidenceIDs:       []string{"nonexistent_evidence_999", "01900000-0000-7000-8000-999999999999"},
				Reason:            "Fabricated evidence reference",
				RecommendedAction: "IP_REVIEW",
			},
		}
	}

	return p
}

func nonEmpty(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fallback
}

// AssertNoSecretInPrompts fails t if any secret appears in any recorded gateway prompt body.
func (g *MockGateway) AssertNoSecretInPrompts(t testing.TB, secrets ...string) {
	t.Helper()
	for i, req := range g.Requests() {
		if leaks := FindSecretOrEncodedLeaks(string(req.RawBody), secrets...); len(leaks) > 0 {
			t.Fatalf("gateway request[%d] leaked secret: %s", i, strings.Join(leaks, ", "))
		}
	}
}

// AssertNoRouteCalled fails t if any recorded request targeted unauthorizedRoute.
func (g *MockGateway) AssertNoRouteCalled(t testing.TB, unauthorizedRoute string) {
	t.Helper()
	for i, req := range g.Requests() {
		if strings.EqualFold(req.Route, unauthorizedRoute) {
			t.Fatalf("unauthorized model route %q was called at request[%d]", unauthorizedRoute, i)
		}
	}
}

// CheckPromptUntrustedFraming verifies untrustedMarker does not appear inside system instructions
// (or system role messages) while appearing inside user/untrusted data content (or RawBody if Messages is empty).
func (g *MockGateway) CheckPromptUntrustedFraming(untrustedMarker string, systemForbidden bool) error {
	reqs := g.Requests()
	if len(reqs) == 0 {
		return errors.New("no gateway requests recorded")
	}
	last := reqs[len(reqs)-1]
	if len(last.Messages) == 0 {
		if !strings.Contains(string(last.RawBody), untrustedMarker) {
			// Also check parsed body fields
			found := false
			for _, v := range last.ParsedBody {
				if s, ok := v.(string); ok && strings.Contains(s, untrustedMarker) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("expected untrusted marker %q in prompt payload or parsed body", untrustedMarker)
			}
		}
		return nil
	}
	foundUser := false
	for _, msg := range last.Messages {
		if strings.EqualFold(msg.Role, "system") && systemForbidden && strings.Contains(msg.Content, untrustedMarker) {
			return fmt.Errorf("untrusted marker %q leaked into system prompt role", untrustedMarker)
		}
		if !strings.EqualFold(msg.Role, "system") && strings.Contains(msg.Content, untrustedMarker) {
			foundUser = true
		}
	}
	if !foundUser {
		return fmt.Errorf("expected untrusted marker %q in non-system prompt message", untrustedMarker)
	}
	return nil
}

// AssertPromptUntrustedFraming fails t if untrustedMarker appears inside system instructions
// (when systemForbidden) or is missing from user/untrusted data content.
func (g *MockGateway) AssertPromptUntrustedFraming(t testing.TB, untrustedMarker string, systemForbidden bool) {
	t.Helper()
	if err := g.CheckPromptUntrustedFraming(untrustedMarker, systemForbidden); err != nil {
		t.Fatal(err)
	}
}
