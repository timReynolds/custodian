package harness

import (
	"crypto"
	"crypto/hmac"
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
	"strings"
	"sync"
	"testing"
	"time"
)

// OIDCTokenClaims configures tokens minted by MockOIDC for positive and adversarial tests.
type OIDCTokenClaims struct {
	Issuer            string
	Subject           string
	Audience          []string
	Kind              string
	Email             string
	EmailVerified     *bool
	DisplayName       string
	PreferredUsername string
	Groups            []string
	Roles             []string
	Scope             string
	AuthorizedParty   string
	IssuedAt          time.Time
	NotBefore         *time.Time
	ExpiresAt         time.Time

	// Adversarial test toggles
	SignWithWrongKey bool
	TamperSignature  bool
	TamperPayload    bool
	Algorithm        string
	OmitSubject      bool
}

// MockOIDC is a thread-safe offline RS256 OIDC discovery and JWKS httptest server.
type MockOIDC struct {
	mu          sync.RWMutex
	audience    string
	server      *httptest.Server
	keys        map[string]*rsa.PrivateKey
	activeKID   string
	keySeq      int
	rogueKey    *rsa.PrivateKey
	outage      bool
	retainOldOn bool
}

// NewMockOIDCServer starts a standalone MockOIDC server bound to 127.0.0.1:0.
func NewMockOIDCServer(audience string) (*MockOIDC, error) {
	if strings.TrimSpace(audience) == "" {
		audience = "custodian-api"
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rogue rsa key: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen mock oidc: %w", err)
	}

	m := &MockOIDC{
		audience:    audience,
		keys:        map[string]*rsa.PrivateKey{"key-1": priv},
		activeKID:   "key-1",
		keySeq:      1,
		rogueKey:    rogue,
		retainOldOn: true,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks.json", m.handleJWKS)
	mux.HandleFunc("/.well-known/jwks.json", m.handleJWKS)

	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	m.server = srv
	return m, nil
}

// StartMockOIDC starts a MockOIDC server and registers t.Cleanup(m.Close).
func StartMockOIDC(t testing.TB, audience string) *MockOIDC {
	t.Helper()
	m, err := NewMockOIDCServer(audience)
	if err != nil {
		t.Fatalf("StartMockOIDC: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

func (m *MockOIDC) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

func (m *MockOIDC) Issuer() string {
	return m.server.URL
}

func (m *MockOIDC) JWKSURL() string {
	return m.server.URL + "/jwks.json"
}

func (m *MockOIDC) Audience() string {
	return m.audience
}

func (m *MockOIDC) HTTPClient() *http.Client {
	return m.server.Client()
}

func (m *MockOIDC) SetOutage(down bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outage = down
}

// RotateKey generates a new active RS256 signing key and returns its kid.
func (m *MockOIDC) RotateKey() string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("mock oidc rotate key: %v", err))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keySeq++
	kid := fmt.Sprintf("key-%d", m.keySeq)
	if !m.retainOldOn {
		m.keys = map[string]*rsa.PrivateKey{}
	}
	m.keys[kid] = priv
	m.activeKID = kid
	return kid
}

func (m *MockOIDC) MintHumanToken(sub, email, name string, groups ...string) string {
	verified := true
	return m.MintToken(OIDCTokenClaims{
		Subject:       sub,
		Kind:          "HUMAN",
		Email:         email,
		EmailVerified: &verified,
		DisplayName:   name,
		Groups:        groups,
	})
}

func (m *MockOIDC) MintControllerToken(sub string, roles ...string) string {
	return m.MintToken(OIDCTokenClaims{
		Subject: sub,
		Kind:    "CONTROLLER",
		Roles:   roles,
	})
}

func (m *MockOIDC) MintAgentToken(sub string, roles ...string) string {
	return m.MintToken(OIDCTokenClaims{
		Subject: sub,
		Kind:    "AGENT",
		Roles:   roles,
	})
}

func (m *MockOIDC) MintToken(c OIDCTokenClaims) string {
	m.mu.RLock()
	kid := m.activeKID
	priv := m.keys[kid]
	rogue := m.rogueKey
	defaultIss := m.server.URL
	defaultAud := m.audience
	m.mu.RUnlock()

	now := time.Now().UTC()
	iss := c.Issuer
	if iss == "" {
		iss = defaultIss
	}
	aud := c.Audience
	if len(aud) == 0 {
		aud = []string{defaultAud}
	}
	iat := c.IssuedAt
	if iat.IsZero() {
		iat = now
	}
	exp := c.ExpiresAt
	if exp.IsZero() {
		exp = iat.Add(10 * time.Minute)
	}
	alg := c.Algorithm
	if alg == "" {
		alg = "RS256"
	}

	payload := map[string]any{
		"iss": iss,
		"aud": aud,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
	}
	if !c.OmitSubject {
		sub := c.Subject
		if sub == "" {
			sub = "subject-default"
		}
		payload["sub"] = sub
	}
	if c.NotBefore != nil {
		payload["nbf"] = c.NotBefore.UTC().Unix()
	}
	if c.Kind != "" {
		payload["kind"] = c.Kind
	}
	if c.Email != "" {
		payload["email"] = c.Email
	}
	if c.EmailVerified != nil {
		payload["email_verified"] = *c.EmailVerified
	} else if c.Email != "" {
		payload["email_verified"] = true
	}
	if c.DisplayName != "" {
		payload["display_name"] = c.DisplayName
		payload["name"] = c.DisplayName
	}
	if c.PreferredUsername != "" {
		payload["preferred_username"] = c.PreferredUsername
	}
	if len(c.Groups) > 0 {
		payload["groups"] = c.Groups
	}
	if len(c.Roles) > 0 {
		payload["roles"] = c.Roles
	}
	if c.Scope != "" {
		payload["scope"] = c.Scope
	}
	if c.AuthorizedParty != "" {
		payload["azp"] = c.AuthorizedParty
	}

	header := map[string]any{
		"alg": alg,
		"typ": "JWT",
		"kid": kid,
	}

	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)

	hEnc := base64.RawURLEncoding.EncodeToString(hBytes)
	pEnc := base64.RawURLEncoding.EncodeToString(pBytes)
	signingInput := hEnc + "." + pEnc

	var sigEnc string
	switch alg {
	case "none":
		sigEnc = ""
	case "HS256":
		mac := hmac.New(sha256.New, []byte("mock-oidc-hs256-downgrade-key"))
		_, _ = mac.Write([]byte(signingInput))
		sigEnc = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	default:
		key := priv
		if c.SignWithWrongKey {
			key = rogue
		}
		sum := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			panic(fmt.Sprintf("mock oidc sign jwt: %v", err))
		}
		sigEnc = base64.RawURLEncoding.EncodeToString(sig)
	}

	if c.TamperPayload {
		payload["sub"] = "tampered-admin"
		tpBytes, _ := json.Marshal(payload)
		pEnc = base64.RawURLEncoding.EncodeToString(tpBytes)
	}
	if c.TamperSignature && len(sigEnc) > 4 {
		flip := "A"
		if sigEnc[0] == 'A' {
			flip = "B"
		}
		sigEnc = flip + sigEnc[1:]
	}

	return hEnc + "." + pEnc + "." + sigEnc
}

func (m *MockOIDC) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	down := m.outage
	m.mu.RUnlock()
	if down {
		http.Error(w, "oidc discovery unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                m.server.URL,
		"jwks_uri":                              m.server.URL + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"id_token"},
	})
}

func (m *MockOIDC) handleJWKS(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	down := m.outage
	keysCopy := make(map[string]*rsa.PrivateKey, len(m.keys))
	for k, v := range m.keys {
		keysCopy[k] = v
	}
	m.mu.RUnlock()
	if down {
		http.Error(w, "jwks unavailable", http.StatusServiceUnavailable)
		return
	}

	jwks := make([]map[string]any, 0, len(keysCopy))
	for kid, priv := range keysCopy {
		eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		jwks = append(jwks, map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": jwks})
}
