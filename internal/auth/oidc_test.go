package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

type testOIDCServer struct {
	mu      sync.RWMutex
	server  *httptest.Server
	keys    map[string]*rsa.PrivateKey
	active  string
	outage  bool
	rogue   *rsa.PrivateKey
	issuer  string
	jwksURL string
}

func newTestOIDCServer(t *testing.T) *testOIDCServer {
	t.Helper()
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rogue, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rogue rsa key: %v", err)
	}
	s := &testOIDCServer{
		keys:   map[string]*rsa.PrivateKey{"key-1": k1},
		active: "key-1",
		rogue:  rogue,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	s.server = httptest.NewServer(mux)
	s.issuer = s.server.URL
	s.jwksURL = s.server.URL + "/jwks.json"
	t.Cleanup(s.server.Close)
	return s
}

func (s *testOIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	down := s.outage
	issuer := s.issuer
	jwks := s.jwksURL
	s.mu.RUnlock()
	if down {
		http.Error(w, "oidc down", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              jwks,
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"id_token"},
	})
}

func (s *testOIDCServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	down := s.outage
	keysCopy := make(map[string]*rsa.PrivateKey, len(s.keys))
	for k, v := range s.keys {
		keysCopy[k] = v
	}
	s.mu.RUnlock()
	if down {
		http.Error(w, "jwks down", http.StatusServiceUnavailable)
		return
	}
	var jwks []map[string]any
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

func (s *testOIDCServer) setOutage(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outage = down
}

func (s *testOIDCServer) rotateKey(t *testing.T, newKID string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[newKID] = k
	s.active = newKID
}

func (s *testOIDCServer) signJWT(t *testing.T, header map[string]any, claims map[string]any, useRogue bool) string {
	t.Helper()
	s.mu.RLock()
	kid := s.active
	priv := s.keys[kid]
	rogue := s.rogue
	s.mu.RUnlock()

	if _, ok := header["kid"]; !ok {
		header["kid"] = kid
	}
	hJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hJSON) + "." + base64.RawURLEncoding.EncodeToString(cJSON)

	alg, _ := header["alg"].(string)
	switch alg {
	case "none":
		return signingInput + "."
	case "HS256":
		m := hmac.New(sha256.New, []byte("super-secret-symmetric-key"))
		_, _ = m.Write([]byte(signingInput))
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	default:
		key := priv
		if useRogue {
			key = rogue
		}
		sum := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatalf("sign rs256: %v", err)
		}
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
}

func TestNewOIDCVerifierValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewOIDCVerifier(OIDCConfig{Audience: "custodian"}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for empty issuer, got %v", err)
	}
	if _, err := NewOIDCVerifier(OIDCConfig{Issuer: "https://issuer.example"}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for empty audience, got %v", err)
	}
	if _, err := NewOIDCVerifier(OIDCConfig{
		Issuer:               "https://issuer.example",
		Audience:             "custodian",
		SupportedSigningAlgs: []string{"HS256"},
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for symmetric HS256 alg, got %v", err)
	}
	if _, err := NewOIDCVerifier(OIDCConfig{
		Issuer:               "https://issuer.example",
		Audience:             "custodian",
		SupportedSigningAlgs: []string{"none"},
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for alg=none, got %v", err)
	}
	if _, err := NewOIDCVerifier(OIDCConfig{
		Issuer:    "https://issuer.example",
		Audience:  "custodian",
		ClockSkew: -time.Second,
	}); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for negative clock skew, got %v", err)
	}
}

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()
	if _, err := ExtractBearerToken(""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for empty header, got %v", err)
	}
	if _, err := ExtractBearerToken("Basic abc"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for Basic scheme, got %v", err)
	}
	if _, err := ExtractBearerToken("Bearer a b"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for token with space, got %v", err)
	}
	for _, bad := range []string{
		"Bearer \nheader.payload.sig",
		"Bearer \r\nheader.payload.sig",
		"Bearer \theader.payload.sig",
		"Bearer \vheader.payload.sig",
		"Bearer \fheader.payload.sig",
		"Bearer \u00a0header.payload.sig",
		"Bearer \u0085header.payload.sig",
		"\nBearer header.payload.sig",
		"Bearer header.payload.sig\n",
		"Bearer header.payload.sig\v",
		"Bearer header.payload.sig\u00a0",
		"Bearer header.payload.sig\x00",
	} {
		if _, err := ExtractBearerToken(bad); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized for malformed header %q, got %v", bad, err)
		}
	}
	tok, err := ExtractBearerToken("Bearer header.payload.sig")
	if err != nil || tok != "header.payload.sig" {
		t.Fatalf("unexpected result: tok=%q err=%v", tok, err)
	}
}

func TestOIDCVerifierValidRolesAndModes(t *testing.T) {
	t.Parallel()
	srv := newTestOIDCServer(t)
	now := time.Now().UTC().Truncate(time.Second)

	for _, mode := range []string{"discovery", "explicit_jwks"} {
		t.Run(mode, func(t *testing.T) {
			cfg := OIDCConfig{
				Issuer:           srv.issuer,
				AllowedAudiences: []string{"custodian-api", "custodian-cli"},
				HTTPClient:       srv.server.Client(),
				ClockSkew:        30 * time.Second,
				Now:              func() time.Time { return now },
			}
			if mode == "explicit_jwks" {
				cfg.JWKSURL = srv.jwksURL
			}
			v, err := NewOIDCVerifier(cfg)
			if err != nil {
				t.Fatalf("NewOIDCVerifier: %v", err)
			}

			cases := []struct {
				name      string
				claims    map[string]any
				wantKind  domain.PrincipalKind
				wantToken TokenKind
				wantEmail string
			}{
				{
					name: "human",
					claims: map[string]any{
						"iss": srv.issuer, "sub": "user-1", "aud": "custodian-api",
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
						"kind": "HUMAN", "email": "alice@example.com", "email_verified": true,
						"name": "Alice", "groups": []string{"eng"},
					},
					wantKind:  domain.PrincipalKindHuman,
					wantToken: TokenKindHuman,
					wantEmail: "alice@example.com",
				},
				{
					name: "auditor",
					claims: map[string]any{
						"iss": srv.issuer, "sub": "aud-1", "aud": []string{"custodian-cli"},
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
						"kind": "AUDITOR", "email": "auditor@example.com", "email_verified": "true",
					},
					wantKind:  domain.PrincipalKindHuman,
					wantToken: TokenKindAuditor,
					wantEmail: "auditor@example.com",
				},
				{
					name: "policy_admin",
					claims: map[string]any{
						"iss": srv.issuer, "sub": "pol-1", "aud": "custodian-api",
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
						"kind": "POLICY_ADMIN", "email": "policy@example.com", "email_verified": true,
					},
					wantKind:  domain.PrincipalKindHuman,
					wantToken: TokenKindPolicyAdmin,
					wantEmail: "policy@example.com",
				},
				{
					name: "controller",
					claims: map[string]any{
						"iss": srv.issuer, "sub": "spiffe://custodian/controller/1", "aud": "custodian-api",
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
						"kind": "CONTROLLER",
					},
					wantKind:  domain.PrincipalKindService,
					wantToken: TokenKindController,
				},
				{
					name: "agent",
					claims: map[string]any{
						"iss": srv.issuer, "sub": "agent-pi-1", "aud": "custodian-api",
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
						"kind": "AGENT", "roles": []string{"coder"},
					},
					wantKind:  domain.PrincipalKindAgent,
					wantToken: TokenKindAgent,
				},
				{
					name: "unverified_email_stripped",
					claims: map[string]any{
						"iss": srv.issuer, "sub": "user-unv", "aud": "custodian-api",
						"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
						"kind": "HUMAN", "email": "spoof@example.com", "email_verified": false,
					},
					wantKind:  domain.PrincipalKindHuman,
					wantToken: TokenKindHuman,
					wantEmail: "",
				},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					jwt := srv.signJWT(t, map[string]any{"alg": "RS256", "typ": "JWT"}, tc.claims, false)
					got, err := v.Verify(context.Background(), "Bearer "+jwt)
					if err != nil {
						t.Fatalf("Verify failed: %v", err)
					}
					if got.Kind != tc.wantKind || got.TokenKind != tc.wantToken {
						t.Fatalf("kind mismatch: got (%s,%s) want (%s,%s)", got.Kind, got.TokenKind, tc.wantKind, tc.wantToken)
					}
					if got.Email != tc.wantEmail {
						t.Fatalf("email mismatch: got %q want %q", got.Email, tc.wantEmail)
					}
				})
			}
		})
	}
}

func TestOIDCVerifierRejectsAdversarialTokensAndLogsSafely(t *testing.T) {
	t.Parallel()
	srv := newTestOIDCServer(t)
	now := time.Now().UTC().Truncate(time.Second)

	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Format:    observability.LogFormatJSON,
		Component: "auth-test",
	})

	v, err := NewOIDCVerifier(OIDCConfig{
		Issuer:     srv.issuer,
		Audience:   "custodian-api",
		HTTPClient: srv.server.Client(),
		ClockSkew:  30 * time.Second,
		Now:        func() time.Time { return now },
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}

	baseClaims := func() map[string]any {
		return map[string]any{
			"iss":            srv.issuer,
			"sub":            "user-1",
			"aud":            "custodian-api",
			"iat":            now.Unix(),
			"exp":            now.Add(5 * time.Minute).Unix(),
			"kind":           "HUMAN",
			"email":          "secret-user@example.com",
			"email_verified": true,
		}
	}

	// Future nbf within ClockSkew (now + 10s) must succeed.
	withinSkew := baseClaims()
	withinSkew["nbf"] = now.Add(10 * time.Second).Unix()
	okTok := srv.signJWT(t, map[string]any{"alg": "RS256", "typ": "JWT"}, withinSkew, false)
	if _, err := v.Verify(context.Background(), okTok); err != nil {
		t.Fatalf("expected token within 30s clock skew to pass, got %v", err)
	}

	// Future nbf beyond 30s ClockSkew (now + 2m) — must override go-oidc's 5m leeway!
	beyondSkew := baseClaims()
	beyondSkew["nbf"] = now.Add(2 * time.Minute).Unix()
	nbfTok := srv.signJWT(t, map[string]any{"alg": "RS256", "typ": "JWT"}, beyondSkew, false)
	if _, err := v.Verify(context.Background(), nbfTok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for nbf=now+2m (overriding 5m leeway), got %v", err)
	}

	// Huge float64 nbf (1e30 / -1e30) must be rejected instead of overflowing int64.
	for _, extremeNBF := range []float64{1e30, -1e30, 1e20} {
		overflowNBF := baseClaims()
		overflowNBF["nbf"] = extremeNBF
		overflowTok := srv.signJWT(t, map[string]any{"alg": "RS256", "typ": "JWT"}, overflowNBF, false)
		if _, err := v.Verify(context.Background(), overflowTok); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized for overflow nbf=%g, got %v", extremeNBF, err)
		}
	}

	// Control whitespace in Verify bearer header must be rejected.
	validBearerJWT := srv.signJWT(t, map[string]any{"alg": "RS256", "typ": "JWT"}, baseClaims(), false)
	for _, badHeader := range []string{
		"Bearer \n" + validBearerJWT,
		"Bearer \r\n" + validBearerJWT,
		"Bearer \t" + validBearerJWT,
		"Bearer \v" + validBearerJWT,
		"Bearer \f" + validBearerJWT,
		"Bearer \u00a0" + validBearerJWT,
		"Bearer \u0085" + validBearerJWT,
		"\nBearer " + validBearerJWT,
		"\v" + validBearerJWT,
		validBearerJWT + "\u00a0",
	} {
		if _, err := v.Verify(context.Background(), badHeader); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized for control whitespace in header %q, got %v", badHeader, err)
		}
	}

	// Expired token
	expired := baseClaims()
	expired["exp"] = now.Add(-1 * time.Minute).Unix()
	if _, err := v.Verify(context.Background(), srv.signJWT(t, map[string]any{"alg": "RS256"}, expired, false)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for expired token, got %v", err)
	}

	// Wrong issuer
	wrongIss := baseClaims()
	wrongIss["iss"] = "https://evil.example"
	if _, err := v.Verify(context.Background(), srv.signJWT(t, map[string]any{"alg": "RS256"}, wrongIss, false)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for wrong issuer, got %v", err)
	}

	// Wrong audience
	wrongAud := baseClaims()
	wrongAud["aud"] = "other-service"
	if _, err := v.Verify(context.Background(), srv.signJWT(t, map[string]any{"alg": "RS256"}, wrongAud, false)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for wrong audience, got %v", err)
	}

	// Empty subject
	emptySub := baseClaims()
	emptySub["sub"] = "   "
	if _, err := v.Verify(context.Background(), srv.signJWT(t, map[string]any{"alg": "RS256"}, emptySub, false)); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for empty subject, got %v", err)
	}

	// Rogue key signature
	rogueTok := srv.signJWT(t, map[string]any{"alg": "RS256"}, baseClaims(), true)
	if _, err := v.Verify(context.Background(), rogueTok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for rogue key, got %v", err)
	}

	// Tampered payload
	validTok := srv.signJWT(t, map[string]any{"alg": "RS256"}, baseClaims(), false)
	parts := strings.Split(validTok, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + srv.issuer + `","sub":"admin","aud":"custodian-api"}`))
	if _, err := v.Verify(context.Background(), strings.Join(parts, ".")); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for tampered payload, got %v", err)
	}

	// Tampered signature
	sigParts := strings.Split(validTok, ".")
	sigParts[2] = "AAAA" + sigParts[2][4:]
	if _, err := v.Verify(context.Background(), strings.Join(sigParts, ".")); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for tampered signature, got %v", err)
	}

	// alg=none & alg=HS256 downgrade
	noneTok := srv.signJWT(t, map[string]any{"alg": "none"}, baseClaims(), false)
	if _, err := v.Verify(context.Background(), noneTok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for alg=none, got %v", err)
	}
	hsTok := srv.signJWT(t, map[string]any{"alg": "HS256"}, baseClaims(), false)
	if _, err := v.Verify(context.Background(), hsTok); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for alg=HS256, got %v", err)
	}

	// Unsupported caller kind -> 403 Forbidden
	badKind := baseClaims()
	badKind["kind"] = "ROOT_SUPERUSER"
	if _, err := v.Verify(context.Background(), srv.signJWT(t, map[string]any{"alg": "RS256"}, badKind, false)); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for unsupported caller kind, got %v", err)
	}

	// Ensure logs never leak email or JWT fragments.
	logs := logBuf.String()
	if strings.Contains(logs, "secret-user@example.com") || strings.Contains(logs, "eyJ") {
		t.Fatalf("logs leaked sensitive data: %s", logs)
	}
}

func TestOIDCVerifierOutageRecoveryAndKeyRotation(t *testing.T) {
	t.Parallel()
	srv := newTestOIDCServer(t)
	now := time.Now().UTC().Truncate(time.Second)

	// Start in outage during initial discovery.
	srv.setOutage(true)
	v, err := NewOIDCVerifier(OIDCConfig{
		Issuer:     srv.issuer,
		Audience:   "custodian-api",
		HTTPClient: srv.server.Client(),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier: %v", err)
	}

	tok := srv.signJWT(t, map[string]any{"alg": "RS256"}, map[string]any{
		"iss": srv.issuer, "sub": "user-1", "aud": "custodian-api",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"kind": "HUMAN", "email": "alice@example.com", "email_verified": true,
	}, false)

	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable during discovery outage, got %v", err)
	}

	// Recover from outage -> lazy discovery succeeds.
	srv.setOutage(false)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected recovery after outage cleared, got %v", err)
	}

	// Rotate key and verify token signed by new key.
	srv.rotateKey(t, "key-2")
	tok2 := srv.signJWT(t, map[string]any{"alg": "RS256"}, map[string]any{
		"iss": srv.issuer, "sub": "user-2", "aud": "custodian-api",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"kind": "HUMAN", "email": "bob@example.com", "email_verified": true,
	}, false)

	// Trigger JWKS outage for unknown kid -> 503.
	srv.setOutage(true)
	if _, err := v.Verify(context.Background(), tok2); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable when JWKS returns 503 for rotated key, got %v", err)
	}
	srv.setOutage(false)

	got, err := v.Verify(context.Background(), tok2)
	if err != nil {
		t.Fatalf("expected rotated key verification to succeed, got %v", err)
	}
	if got.Subject != "user-2" {
		t.Fatalf("unexpected subject: %q", got.Subject)
	}
}
