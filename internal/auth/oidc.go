package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/timreynolds/custodian/internal/domain"
)

// TokenKind captures the normalized caller kind claim extracted from a verified OIDC/workload token.
type TokenKind string

const (
	TokenKindHuman       TokenKind = "HUMAN"
	TokenKindAuditor     TokenKind = "AUDITOR"
	TokenKindPolicyAdmin TokenKind = "POLICY_ADMIN"
	TokenKindService     TokenKind = "SERVICE"
	TokenKindController  TokenKind = "CONTROLLER"
	TokenKindAgent       TokenKind = "AGENT"
)

const defaultClockSkew = 30 * time.Second

var allowedAsymmetricAlgs = map[string]struct{}{
	oidc.RS256: {},
	oidc.RS384: {},
	oidc.RS512: {},
	oidc.ES256: {},
	oidc.ES384: {},
	oidc.ES512: {},
	oidc.PS256: {},
	oidc.PS384: {},
	oidc.PS512: {},
	"EdDSA":    {},
}

// VerifiedClaims holds validated identity and authorization claims from a bearer token.
type VerifiedClaims struct {
	Issuer            string
	Subject           string
	Audience          []string
	Kind              domain.PrincipalKind
	TokenKind         TokenKind
	Email             string
	EmailVerified     bool
	DisplayName       string
	PreferredUsername string
	Groups            []string
	Roles             []string
	Scopes            []string
	AuthorizedParty   string
	IssuedAt          time.Time
	NotBefore         *time.Time
	ExpiresAt         time.Time
}

// TokenVerifier validates incoming bearer tokens into VerifiedClaims.
type TokenVerifier interface {
	Verify(ctx context.Context, bearerToken string) (VerifiedClaims, error)
}

// OIDCConfig configures OIDCVerifier.
type OIDCConfig struct {
	Issuer               string
	JWKSURL              string
	Audience             string
	AllowedAudiences     []string
	SupportedSigningAlgs []string
	HTTPClient           *http.Client
	ClockSkew            time.Duration
	Now                  func() time.Time
	Logger               *slog.Logger
}

// OIDCVerifier verifies OIDC and workload identity JWTs using asymmetric JWKS keys.
type OIDCVerifier struct {
	issuer           string
	jwksURL          string
	allowedAudiences []string
	signingAlgs      []string
	httpClient       *http.Client
	clockSkew        time.Duration
	now              func() time.Time
	logger           *slog.Logger

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewOIDCVerifier constructs a hardened OIDCVerifier.
func NewOIDCVerifier(cfg OIDCConfig) (*OIDCVerifier, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, domain.BadRequest("INVALID_OIDC_CONFIG", "oidc issuer is required")
	}

	audSet := make(map[string]struct{})
	var audiences []string
	addAud := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return
		}
		if _, exists := audSet[trimmed]; !exists {
			audSet[trimmed] = struct{}{}
			audiences = append(audiences, trimmed)
		}
	}
	addAud(cfg.Audience)
	for _, a := range cfg.AllowedAudiences {
		addAud(a)
	}
	if len(audiences) == 0 {
		return nil, domain.BadRequest("INVALID_OIDC_CONFIG", "at least one allowed audience is required")
	}

	algs := cfg.SupportedSigningAlgs
	if len(algs) == 0 {
		algs = []string{oidc.RS256}
	} else {
		cleaned := make([]string, 0, len(algs))
		for _, alg := range algs {
			a := strings.TrimSpace(alg)
			if _, ok := allowedAsymmetricAlgs[a]; !ok {
				return nil, domain.BadRequest("INVALID_SIGNING_ALG", "unsupported or symmetric OIDC signing algorithm")
			}
			if !slices.Contains(cleaned, a) {
				cleaned = append(cleaned, a)
			}
		}
		algs = cleaned
	}

	if cfg.ClockSkew < 0 {
		return nil, domain.BadRequest("INVALID_OIDC_CONFIG", "clock skew must be non-negative")
	}
	skew := cfg.ClockSkew
	if skew == 0 {
		skew = defaultClockSkew
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}

	return &OIDCVerifier{
		issuer:           issuer,
		jwksURL:          strings.TrimSpace(cfg.JWKSURL),
		allowedAudiences: audiences,
		signingAlgs:      algs,
		httpClient:       hc,
		clockSkew:        skew,
		now:              nowFn,
		logger:           cfg.Logger,
	}, nil
}

func hasDisallowedBearerRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || (unicode.IsSpace(r) && r != ' ') {
			return true
		}
	}
	return false
}

// ExtractBearerToken parses an HTTP Authorization header into a raw bearer token.
func ExtractBearerToken(authHeader string) (string, error) {
	if hasDisallowedBearerRune(authHeader) {
		return "", domain.Unauthorized("INVALID_BEARER_TOKEN", "bearer token contains control characters")
	}
	trimmed := strings.TrimSpace(authHeader)
	if trimmed == "" {
		return "", domain.Unauthorized("MISSING_BEARER_TOKEN", "authorization bearer token is required")
	}
	parts := strings.SplitN(trimmed, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", domain.Unauthorized("INVALID_AUTHORIZATION_SCHEME", "authorization header must use Bearer scheme")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", domain.Unauthorized("INVALID_BEARER_TOKEN", "bearer token is malformed")
	}
	return token, nil
}

// Verify validates a raw JWT (or "Bearer <jwt>" header value) and returns VerifiedClaims.
func (v *OIDCVerifier) Verify(ctx context.Context, bearerToken string) (VerifiedClaims, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return VerifiedClaims{}, domain.WrapError(domain.ErrUnavailable, "OIDC_CONTEXT_CANCELLED", "token verification aborted", err)
	}
	if hasDisallowedBearerRune(bearerToken) {
		return VerifiedClaims{}, domain.Unauthorized("INVALID_BEARER_TOKEN", "bearer token contains control characters")
	}

	raw := strings.TrimSpace(bearerToken)
	if len(raw) >= 7 && strings.EqualFold(raw[:7], "Bearer ") {
		var err error
		raw, err = ExtractBearerToken(raw)
		if err != nil {
			return VerifiedClaims{}, err
		}
	} else if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return VerifiedClaims{}, domain.Unauthorized("MISSING_BEARER_TOKEN", "bearer token is required")
	}

	verifier, err := v.ensureVerifier(ctx)
	if err != nil {
		v.logFailure("OIDC_UNAVAILABLE", "provider_init_failed")
		return VerifiedClaims{}, err
	}

	verifyCtx := oidc.ClientContext(ctx, v.httpClient)
	idToken, err := verifier.Verify(verifyCtx, raw)
	if err != nil {
		mapped := mapVerifyError(err)
		var domErr *domain.DomainError
		if errors.As(mapped, &domErr) {
			v.logFailure(domErr.Code(), "verify_failed")
		}
		return VerifiedClaims{}, mapped
	}

	now := v.now().UTC()
	if idToken.Issuer != v.issuer {
		v.logFailure("INVALID_ISSUER", "issuer_mismatch")
		return VerifiedClaims{}, domain.Unauthorized("INVALID_ISSUER", "token issuer does not match expected issuer")
	}
	subject := strings.TrimSpace(idToken.Subject)
	if subject == "" {
		v.logFailure("MISSING_SUBJECT", "empty_subject")
		return VerifiedClaims{}, domain.Unauthorized("MISSING_SUBJECT", "token subject must not be empty")
	}
	if idToken.Expiry.IsZero() || !now.Before(idToken.Expiry) {
		v.logFailure("TOKEN_EXPIRED", "expired")
		return VerifiedClaims{}, domain.Unauthorized("TOKEN_EXPIRED", "bearer token has expired")
	}
	if !audienceMatches(idToken.Audience, v.allowedAudiences) {
		v.logFailure("INVALID_AUDIENCE", "audience_mismatch")
		return VerifiedClaims{}, domain.Unauthorized("INVALID_AUDIENCE", "token audience is not allowed")
	}

	var custom rawOIDCClaims
	if err := idToken.Claims(&custom); err != nil {
		v.logFailure("INVALID_CLAIMS", "claims_decode_failed")
		return VerifiedClaims{}, domain.WrapError(domain.ErrUnauthorized, "INVALID_CLAIMS", "failed to decode token claims", err)
	}

	var notBeforePtr *time.Time
	if custom.NBF != nil {
		nbfTime, err := parseNumericDate(*custom.NBF)
		if err != nil {
			v.logFailure("INVALID_CLAIMS", "invalid_nbf")
			return VerifiedClaims{}, domain.Unauthorized("INVALID_CLAIMS", "invalid nbf claim")
		}
		if now.Add(v.clockSkew).Before(nbfTime) {
			v.logFailure("TOKEN_NOT_YET_VALID", "nbf_in_future")
			return VerifiedClaims{}, domain.Unauthorized("TOKEN_NOT_YET_VALID", "bearer token is not yet valid")
		}
		notBeforePtr = &nbfTime
	}

	emailVerified := bool(custom.EmailVerified)
	verifiedEmail := ""
	if emailVerified {
		verifiedEmail = strings.TrimSpace(custom.Email)
	}

	roles := normalizeStringSlice(custom.Roles)
	groups := normalizeStringSlice(custom.Groups)
	scopes := normalizeScopes(custom.Scope)

	principalKind, tokenKind, roles, err := classifyCaller(custom.Kind, subject, verifiedEmail, emailVerified, roles)
	if err != nil {
		v.logFailure("UNCLASSIFIED_CALLER", "kind_rejected")
		return VerifiedClaims{}, err
	}

	displayName := strings.TrimSpace(custom.DisplayName)
	if displayName == "" {
		displayName = strings.TrimSpace(custom.Name)
	}
	if displayName == "" {
		displayName = strings.TrimSpace(custom.PreferredUsername)
	}

	return VerifiedClaims{
		Issuer:            idToken.Issuer,
		Subject:           subject,
		Audience:          append([]string(nil), idToken.Audience...),
		Kind:              principalKind,
		TokenKind:         tokenKind,
		Email:             verifiedEmail,
		EmailVerified:     emailVerified,
		DisplayName:       displayName,
		PreferredUsername: strings.TrimSpace(custom.PreferredUsername),
		Groups:            groups,
		Roles:             roles,
		Scopes:            scopes,
		AuthorizedParty:   strings.TrimSpace(custom.AZP),
		IssuedAt:          idToken.IssuedAt.UTC(),
		NotBefore:         notBeforePtr,
		ExpiresAt:         idToken.Expiry.UTC(),
	}, nil
}

func (v *OIDCVerifier) ensureVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}

	cfg := &oidc.Config{
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: append([]string(nil), v.signingAlgs...),
		Now:                  v.now,
	}

	var provider *oidc.Provider
	var err error
	if v.jwksURL != "" {
		// RemoteKeySet caches the provider context for background key refreshes, so keep
		// the custom http.Client bound to a non-cancelling background context.
		jwksCtx := oidc.ClientContext(context.Background(), v.httpClient)
		pc := &oidc.ProviderConfig{
			IssuerURL:  v.issuer,
			JWKSURL:    v.jwksURL,
			Algorithms: append([]string(nil), v.signingAlgs...),
		}
		provider = pc.NewProvider(jwksCtx)
	} else {
		discCtx := oidc.ClientContext(ctx, v.httpClient)
		provider, err = oidc.NewProvider(discCtx, v.issuer)
		if err != nil {
			return nil, domain.WrapError(domain.ErrUnavailable, "OIDC_UNAVAILABLE", "oidc discovery unavailable", err)
		}
	}

	v.verifier = provider.Verifier(cfg)
	return v.verifier, nil
}

func (v *OIDCVerifier) logFailure(code, reason string) {
	if v.logger == nil {
		return
	}
	v.logger.Warn("oidc verification failed", "error_code", code, "reason", reason)
}

func mapVerifyError(err error) error {
	var expiredErr *oidc.TokenExpiredError
	if errors.As(err, &expiredErr) {
		return domain.WrapError(domain.ErrUnauthorized, "TOKEN_EXPIRED", "bearer token has expired", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return domain.WrapError(domain.ErrUnavailable, "OIDC_UNAVAILABLE", "oidc key set unavailable", err)
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "fetching keys") ||
		strings.Contains(msg, "get keys failed") ||
		strings.Contains(msg, "oidc: get keys") {
		return domain.WrapError(domain.ErrUnavailable, "OIDC_UNAVAILABLE", "oidc key set unavailable", err)
	}
	return domain.WrapError(domain.ErrUnauthorized, "INVALID_TOKEN", "bearer token verification failed", err)
}

func audienceMatches(tokenAud, allowed []string) bool {
	for _, a := range tokenAud {
		if slices.Contains(allowed, a) {
			return true
		}
	}
	return false
}

func classifyCaller(rawKind, subject, verifiedEmail string, emailVerified bool, roles []string) (domain.PrincipalKind, TokenKind, []string, error) {
	norm := strings.ToUpper(strings.TrimSpace(rawKind))
	outRoles := append([]string(nil), roles...)
	addRole := func(r string) {
		if !slices.Contains(outRoles, r) {
			outRoles = append(outRoles, r)
		}
	}

	switch norm {
	case string(TokenKindHuman):
		return domain.PrincipalKindHuman, TokenKindHuman, outRoles, nil
	case string(TokenKindAuditor):
		addRole("auditor")
		return domain.PrincipalKindHuman, TokenKindAuditor, outRoles, nil
	case string(TokenKindPolicyAdmin):
		addRole("policy_admin")
		return domain.PrincipalKindHuman, TokenKindPolicyAdmin, outRoles, nil
	case string(TokenKindService):
		return domain.PrincipalKindService, TokenKindService, outRoles, nil
	case string(TokenKindController):
		addRole("controller")
		return domain.PrincipalKindService, TokenKindController, outRoles, nil
	case string(TokenKindAgent):
		return domain.PrincipalKindAgent, TokenKindAgent, outRoles, nil
	case "":
		if strings.HasPrefix(subject, "spiffe://") || (hasAnyRole(outRoles, "service", "controller") && verifiedEmail == "") {
			tk := TokenKindService
			if hasAnyRole(outRoles, "controller") {
				tk = TokenKindController
			}
			return domain.PrincipalKindService, tk, outRoles, nil
		}
		if hasAnyRole(outRoles, "agent") && verifiedEmail == "" {
			return domain.PrincipalKindAgent, TokenKindAgent, outRoles, nil
		}
		if verifiedEmail != "" && emailVerified {
			return domain.PrincipalKindHuman, TokenKindHuman, outRoles, nil
		}
		return "", "", nil, domain.Forbidden("UNCLASSIFIED_CALLER", "token lacks recognised caller kind")
	default:
		return "", "", nil, domain.Forbidden("UNSUPPORTED_CALLER_KIND", "unsupported caller kind")
	}
}

func hasAnyRole(roles []string, targets ...string) bool {
	for _, r := range roles {
		for _, t := range targets {
			if strings.EqualFold(r, t) {
				return true
			}
		}
	}
	return false
}

func normalizeStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !slices.Contains(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeScopes(scope string) []string {
	fields := strings.Fields(strings.TrimSpace(scope))
	if len(fields) == 0 {
		return nil
	}
	return normalizeStringSlice(fields)
}

const (
	minNumericDateSec = -62135596800 // 0001-01-01T00:00:00Z
	maxNumericDateSec = 253402300799 // 9999-12-31T23:59:59Z
)

func parseNumericDate(n json.Number) (time.Time, error) {
	if i, err := n.Int64(); err == nil {
		if i < minNumericDateSec || i > maxNumericDateSec {
			return time.Time{}, errors.New("numeric date out of range")
		}
		return time.Unix(i, 0).UTC(), nil
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < float64(minNumericDateSec) || f > float64(maxNumericDateSec) {
		return time.Time{}, errors.New("numeric date out of range")
	}
	sec := int64(f)
	nsec := int64((f - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec).UTC(), nil
}

type rawOIDCClaims struct {
	Kind              string       `json:"kind"`
	Email             string       `json:"email"`
	EmailVerified     flexibleBool `json:"email_verified"`
	Name              string       `json:"name"`
	DisplayName       string       `json:"display_name"`
	PreferredUsername string       `json:"preferred_username"`
	Groups            []string     `json:"groups"`
	Roles             []string     `json:"roles"`
	Scope             string       `json:"scope"`
	AZP               string       `json:"azp"`
	NBF               *json.Number `json:"nbf"`
}

type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(data []byte) error {
	var rawBool bool
	if err := json.Unmarshal(data, &rawBool); err == nil {
		*b = flexibleBool(rawBool)
		return nil
	}
	var rawStr string
	if err := json.Unmarshal(data, &rawStr); err == nil {
		switch strings.ToLower(strings.TrimSpace(rawStr)) {
		case "true":
			*b = true
			return nil
		case "false", "":
			*b = false
			return nil
		}
	}
	return errors.New("invalid boolean claim")
}
