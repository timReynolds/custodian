package harness

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const defaultOIDCKID = "custodian-e2e-k1"

// TokenClaims describes an OIDC or workload identity JWT to mint via MockOIDC.
type TokenClaims struct {
	Kind              string // HUMAN, AUDITOR, POLICY_ADMIN, SERVICE, CONTROLLER, AGENT
	Issuer            string // defaults to MockOIDC.Issuer()
	Subject           string
	Audience          []string // defaults to []string{MockOIDC.Audience()}
	Email             string
	EmailVerified     *bool // defaults to true for HUMAN/AUDITOR/POLICY_ADMIN
	Name              string
	PreferredUsername string
	Groups            []string
	Roles             []string
	Scope             string
	ExpiresAt         time.Time // defaults to now + 1h
	NotBefore         time.Time
	IssuedAt          time.Time
	KeyID             string
	SignWithWrongKey  bool // signs with unpublished rogue RSA-2048 key
	TamperSignature   bool // flips final byte of valid signature
	Extra             map[string]any
}

// MockOIDC is a pure-stdlib RS256 OIDC discovery + JWKS server bound to 127.0.0.1:0.
type MockOIDC struct {
	server     *httptest.Server
	audience   string
	primaryKey *rsa.PrivateKey
	rogueKey   *rsa.PrivateKey
	kid        string

	mu     sync.RWMutex
	outage bool
}

// StartMockOIDC starts a pure-stdlib RS256 OIDC + JWKS server bound to 127.0.0.1:0.
func StartMockOIDC(t testing.TB, audience string) *MockOIDC {
	t.Helper()
	if audience == "" {
		audience = "custodian-api"
	}

	primary, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate primary RSA key: %v", err)
	}
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rogue RSA key: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback for MockOIDC: %v", err)
	}

	m := &MockOIDC{
		audience:   audience,
		primaryKey: primary,
		rogueKey:   rogue,
		kid:        defaultOIDCKID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks.json", m.handleJWKS)
	mux.HandleFunc("/.well-known/jwks.json", m.handleJWKS)

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	m.server = srv

	t.Cleanup(m.Close)
	return m
}

// NewMockOIDC starts a MockOIDC server with default audience "custodian-api".
func NewMockOIDC(t testing.TB) *MockOIDC {
	return StartMockOIDC(t, "custodian-api")
}

// Issuer returns the OIDC issuer base URL (http://127.0.0.1:<port>).
func (o *MockOIDC) Issuer() string {
	return o.server.URL
}

// JWKSURL returns the full JWKS endpoint URL.
func (o *MockOIDC) JWKSURL() string {
	return o.server.URL + "/jwks.json"
}

// Audience returns the default audience configured for this MockOIDC server.
func (o *MockOIDC) Audience() string {
	return o.audience
}

// SetOutage toggles HTTP 503 outage simulation on OIDC discovery and JWKS endpoints.
func (o *MockOIDC) SetOutage(down bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outage = down
}

// Close shuts down the mock OIDC server.
func (o *MockOIDC) Close() {
	if o != nil && o.server != nil {
		o.server.Close()
	}
}

func (o *MockOIDC) isDown() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.outage
}

func (o *MockOIDC) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if o.isDown() {
		http.Error(w, `{"error":"oidc unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                o.Issuer(),
		"jwks_uri":                              o.JWKSURL(),
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"id_token"},
	})
}

func (o *MockOIDC) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if o.isDown() {
		http.Error(w, `{"error":"jwks unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	pub := &o.primaryKey.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": o.kid,
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	})
}

// MintToken creates and RS256-signs a JWT using TokenClaims.
func (o *MockOIDC) MintToken(claims TokenClaims) string {
	now := time.Now().UTC()
	iss := claims.Issuer
	if iss == "" {
		iss = o.Issuer()
	}
	aud := claims.Audience
	if len(aud) == 0 {
		aud = []string{o.audience}
	}
	kid := claims.KeyID
	if kid == "" {
		kid = o.kid
	}
	iat := claims.IssuedAt
	if iat.IsZero() {
		iat = now
	}
	nbf := claims.NotBefore
	if nbf.IsZero() {
		nbf = iat.Add(-1 * time.Minute)
	}
	exp := claims.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(1 * time.Hour)
	}

	kind := claims.Kind
	if kind == "" {
		kind = "HUMAN"
	}

	sub := claims.Subject
	email := claims.Email
	name := claims.Name
	groups := append([]string(nil), claims.Groups...)
	roles := append([]string(nil), claims.Roles...)
	emailVerified := claims.EmailVerified

	switch kind {
	case "HUMAN":
		if sub == "" {
			sub = "human-dev-1"
		}
		if email == "" {
			email = "developer@example.com"
		}
		if name == "" {
			name = "Developer"
		}
		if len(groups) == 0 {
			groups = []string{"engineering"}
		}
		if len(roles) == 0 {
			roles = []string{"human", "developer"}
		}
		if emailVerified == nil {
			tr := true
			emailVerified = &tr
		}
	case "AUDITOR":
		if sub == "" {
			sub = "auditor-1"
		}
		if email == "" {
			email = "auditor@example.com"
		}
		if name == "" {
			name = "Security Auditor"
		}
		if len(groups) == 0 {
			groups = []string{"auditors"}
		}
		if len(roles) == 0 {
			roles = []string{"auditor"}
		}
		if emailVerified == nil {
			tr := true
			emailVerified = &tr
		}
	case "POLICY_ADMIN":
		if sub == "" {
			sub = "policy-admin-1"
		}
		if email == "" {
			email = "policy-admin@example.com"
		}
		if name == "" {
			name = "Policy Admin"
		}
		if len(groups) == 0 {
			groups = []string{"policy-admins"}
		}
		if len(roles) == 0 {
			roles = []string{"policy_admin"}
		}
		if emailVerified == nil {
			tr := true
			emailVerified = &tr
		}
	case "SERVICE", "CONTROLLER":
		if sub == "" {
			sub = "spiffe://custodian.local/ns/sandbox/sa/trusted-runtime-controller"
		}
		if name == "" {
			name = "trusted-runtime-controller"
		}
		if len(roles) == 0 {
			roles = []string{"service", "controller"}
		}
	case "AGENT":
		if sub == "" {
			sub = "agent-coder-1"
		}
		if name == "" {
			name = "Coding Agent"
		}
		if len(roles) == 0 {
			roles = []string{"agent"}
		}
	}

	payload := map[string]any{
		"iss":  iss,
		"sub":  sub,
		"aud":  aud,
		"iat":  iat.Unix(),
		"nbf":  nbf.Unix(),
		"exp":  exp.Unix(),
		"kind": kind,
	}
	if len(aud) == 1 {
		payload["aud"] = aud[0]
	}
	if email != "" {
		payload["email"] = email
	}
	if emailVerified != nil {
		payload["email_verified"] = *emailVerified
	}
	if name != "" {
		payload["name"] = name
		payload["display_name"] = name
	}
	if claims.PreferredUsername != "" {
		payload["preferred_username"] = claims.PreferredUsername
	}
	if len(groups) > 0 {
		payload["groups"] = groups
	}
	if len(roles) > 0 {
		payload["roles"] = roles
	}
	if claims.Scope != "" {
		payload["scope"] = claims.Scope
	}
	for k, v := range claims.Extra {
		payload[k] = v
	}

	hdrBytes, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	})
	if err != nil {
		panic(fmt.Sprintf("marshal JWT header: %v", err))
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("marshal JWT payload: %v", err))
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes)

	key := o.primaryKey
	if claims.SignWithWrongKey {
		key = o.rogueKey
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(fmt.Sprintf("sign JWT: %v", err))
	}
	if claims.TamperSignature && len(sig) > 0 {
		sig[len(sig)-1] ^= 0xff
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}
