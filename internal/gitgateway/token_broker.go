package gitgateway

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/github"
)

const (
	defaultBrokerGitHubAPI = "https://api.github.com/"
	tokenRefreshSkew       = 1 * time.Minute
	maxGitHubAPIRespBytes  = 1 << 20
)

// TokenScope distinguishes read-only vs write upstream operations.
type TokenScope string

const (
	TokenScopeRead  TokenScope = "read"
	TokenScopeWrite TokenScope = "write"
)

// TokenBrokerConfig configures delegated PAT forwarding and GitHub App installation token minting.
type TokenBrokerConfig struct {
	APIBaseURL         string
	ReadAppID          int64
	ReadPrivateKeyPEM  []byte
	WriteAppID         int64
	WritePrivateKeyPEM []byte
	HTTPClient         *http.Client
	Now                func() time.Time
	DisableTokenCache  bool
	Logger             *slog.Logger
}

// ResolvedUpstreamAuth contains the upstream token and all sensitive secrets for redaction.
type ResolvedUpstreamAuth struct {
	Token        string
	Source       string   // "delegated" | "github_app_write" | "github_app_read" | "none"
	ExtraSecrets []string // all sensitive tokens for inspection.NewRedactor
}

type brokerCacheKey struct {
	scope          TokenScope
	installationID int64
	repoID         int64
	ownerRepo      string
}

type cachedBrokerToken struct {
	token     string
	expiresAt time.Time
}

// TokenBroker resolves upstream Git credentials without ever forwarding caller OIDC JWTs
// and without ever using write App keys for read paths.
type TokenBroker struct {
	apiBaseURL   *url.URL
	readAppID    int64
	readKey      *rsa.PrivateKey
	writeAppID   int64
	writeKey     *rsa.PrivateKey
	httpClient   *http.Client
	now          func() time.Time
	disableCache bool
	logger       *slog.Logger

	mu    sync.Mutex
	cache map[brokerCacheKey]cachedBrokerToken
}

// NewTokenBroker creates a TokenBroker validating configured RSA keys.
func NewTokenBroker(cfg TokenBrokerConfig) (*TokenBroker, error) {
	rawAPI := strings.TrimSpace(cfg.APIBaseURL)
	if rawAPI == "" {
		rawAPI = defaultBrokerGitHubAPI
	}
	if !strings.HasSuffix(rawAPI, "/") {
		rawAPI += "/"
	}
	apiURL, err := url.Parse(rawAPI)
	if err != nil || apiURL.Scheme == "" || apiURL.Host == "" {
		return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "invalid GitHub API base URL")
	}

	var readKey *rsa.PrivateKey
	if cfg.ReadAppID > 0 || len(cfg.ReadPrivateKeyPEM) > 0 {
		if cfg.ReadAppID <= 0 {
			return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_READ_APP_ID must be positive")
		}
		readKey, err = github.ParseRSAPrivateKeyPEM(cfg.ReadPrivateKeyPEM)
		if err != nil {
			return nil, err
		}
	}

	var writeKey *rsa.PrivateKey
	if cfg.WriteAppID > 0 || len(cfg.WritePrivateKeyPEM) > 0 {
		if cfg.WriteAppID <= 0 {
			return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "CUSTODIAN_GITHUB_WRITE_APP_ID must be positive")
		}
		writeKey, err = github.ParseRSAPrivateKeyPEM(cfg.WritePrivateKeyPEM)
		if err != nil {
			return nil, err
		}
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &TokenBroker{
		apiBaseURL:   apiURL,
		readAppID:    cfg.ReadAppID,
		readKey:      readKey,
		writeAppID:   cfg.WriteAppID,
		writeKey:     writeKey,
		httpClient:   hc,
		now:          nowFn,
		disableCache: cfg.DisableTokenCache,
		logger:       cfg.Logger,
		cache:        make(map[brokerCacheKey]cachedBrokerToken),
	}, nil
}

// ResolveUpstreamAuth resolves an upstream credential for scope, caller, and target.
// Caller OIDC JWTs are NEVER returned as Token, and read scopes NEVER access write App keys.
func (b *TokenBroker) ResolveUpstreamAuth(ctx context.Context, scope TokenScope, caller AuthenticatedPrincipal, target ResolvedTarget) (ResolvedUpstreamAuth, error) {
	extra := collectExtraSecrets(caller.OIDCToken, caller.DelegatedUpstreamToken)

	if caller.DelegatedUpstreamToken != "" {
		return ResolvedUpstreamAuth{
			Token:        caller.DelegatedUpstreamToken,
			Source:       "delegated",
			ExtraSecrets: extra,
		}, nil
	}

	if scope == TokenScopeRead {
		if b == nil || b.readAppID <= 0 || b.readKey == nil || target.Repository == nil {
			return ResolvedUpstreamAuth{
				Token:        "",
				Source:       "none",
				ExtraSecrets: extra,
			}, nil
		}
		tok, err := b.mintInstallationToken(ctx, TokenScopeRead, b.readAppID, b.readKey, target)
		if err != nil {
			return ResolvedUpstreamAuth{ExtraSecrets: extra}, err
		}
		extra = collectExtraSecrets(append(extra, tok)...)
		return ResolvedUpstreamAuth{
			Token:        tok,
			Source:       "github_app_read",
			ExtraSecrets: extra,
		}, nil
	}

	if scope != TokenScopeWrite {
		return ResolvedUpstreamAuth{ExtraSecrets: extra}, domain.BadRequest("INVALID_TOKEN_SCOPE", fmt.Sprintf("unsupported token scope %q", scope))
	}

	if b == nil || b.writeAppID <= 0 || b.writeKey == nil {
		return ResolvedUpstreamAuth{ExtraSecrets: extra}, domain.Unavailable("GITHUB_WRITE_APP_UNCONFIGURED", "GitHub write App credentials are not configured")
	}

	tok, err := b.mintInstallationToken(ctx, TokenScopeWrite, b.writeAppID, b.writeKey, target)
	if err != nil {
		return ResolvedUpstreamAuth{ExtraSecrets: extra}, err
	}
	extra = collectExtraSecrets(append(extra, tok)...)
	return ResolvedUpstreamAuth{
		Token:        tok,
		Source:       "github_app_write",
		ExtraSecrets: extra,
	}, nil
}

func (b *TokenBroker) mintInstallationToken(ctx context.Context, scope TokenScope, appID int64, key *rsa.PrivateKey, target ResolvedTarget) (string, error) {
	var instID, repoID int64
	if target.Repository != nil {
		instID = target.Repository.GitHubInstallationID
		repoID = target.Repository.GitHubRepositoryID
	}

	now := b.now().UTC()
	appJWT, err := github.MintAppJWT(appID, key, now)
	if err != nil {
		return "", err
	}

	if instID <= 0 {
		resolvedID, err := b.resolveInstallationID(ctx, appJWT, target)
		if err != nil {
			return "", err
		}
		instID = resolvedID
	}

	cacheKey := brokerCacheKey{
		scope:          scope,
		installationID: instID,
		repoID:         repoID,
		ownerRepo:      target.OwnerRepo,
	}
	if !b.disableCache {
		b.mu.Lock()
		if cached, ok := b.cache[cacheKey]; ok && now.Add(tokenRefreshSkew).Before(cached.expiresAt) {
			b.mu.Unlock()
			return cached.token, nil
		}
		b.mu.Unlock()
	}

	perms := map[string]string{
		"contents": "read",
		"metadata": "read",
	}
	if scope == TokenScopeWrite {
		perms["contents"] = "write"
		perms["pull_requests"] = "write"
	}
	payload := map[string]any{
		"permissions": perms,
	}
	if repoID > 0 {
		payload["repository_ids"] = []int64{repoID}
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := b.apiURL("app/installations/" + strconv.FormatInt(instID, 10) + "/access_tokens")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return "", domain.WrapError(domain.ErrUnavailable, "GITHUB_TOKEN_EXCHANGE_FAILED", "upstream GitHub installation token exchange failed", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubAPIRespBytes))
	if err != nil {
		return "", domain.WrapError(domain.ErrUnavailable, "GITHUB_TOKEN_EXCHANGE_FAILED", "failed reading GitHub installation token response", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", domain.Forbidden("GITHUB_INSTALLATION_FORBIDDEN", fmt.Sprintf("GitHub installation token rejected with status %d", resp.StatusCode))
		}
		return "", domain.Unavailable("GITHUB_TOKEN_EXCHANGE_FAILED", fmt.Sprintf("GitHub installation token exchange returned status %d", resp.StatusCode))
	}

	var parsed struct {
		Token     string     `json:"token"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", domain.WrapError(domain.ErrUnavailable, "GITHUB_TOKEN_EXCHANGE_FAILED", "invalid JSON in GitHub installation token response", err)
	}
	tok := strings.TrimSpace(parsed.Token)
	if tok == "" {
		return "", domain.Unavailable("GITHUB_EMPTY_TOKEN", "GitHub returned an empty installation token")
	}

	exp := now.Add(10 * time.Minute)
	if parsed.ExpiresAt != nil && !parsed.ExpiresAt.IsZero() {
		exp = parsed.ExpiresAt.UTC()
	}
	if !b.disableCache {
		b.mu.Lock()
		b.cache[cacheKey] = cachedBrokerToken{token: tok, expiresAt: exp}
		b.mu.Unlock()
	}
	if b.logger != nil {
		b.logger.Debug("minted upstream github installation token",
			"github_installation_id", instID,
			"github_repository_id", repoID,
			"status", "ok",
		)
	}
	return tok, nil
}

func (b *TokenBroker) resolveInstallationID(ctx context.Context, appJWT string, target ResolvedTarget) (int64, error) {
	if target.OwnerRepo != "" {
		owner, repo, err := (domain.Repository{FullName: target.OwnerRepo}).OwnerRepo()
		if err == nil {
			repoInstURL := b.apiURL("repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/installation")
			if id, ok, err := b.fetchInstallationID(ctx, appJWT, repoInstURL); err == nil && ok {
				return id, nil
			}
		}
	}

	// Never fall back to an arbitrary global installation (GET /app/installations list[0]) for
	// unregistered repositories (target.Repository == nil).
	if target.Repository == nil {
		return 0, domain.Unavailable("GITHUB_INSTALLATION_NOT_FOUND", "no GitHub App installation ID available for unregistered target repository")
	}

	listURL := b.apiURL("app/installations")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return 0, domain.WrapError(domain.ErrUnavailable, "GITHUB_INSTALLATION_LOOKUP_FAILED", "failed looking up GitHub App installations", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxGitHubAPIRespBytes))
	if resp.StatusCode == http.StatusOK {
		var list []struct {
			ID int64 `json:"id"`
		}
		if json.Unmarshal(body, &list) == nil && len(list) > 0 && list[0].ID > 0 {
			return list[0].ID, nil
		}
	}
	return 0, domain.Unavailable("GITHUB_INSTALLATION_NOT_FOUND", "no GitHub App installation ID available for target repository")
}

func (b *TokenBroker) fetchInstallationID(ctx context.Context, appJWT, endpoint string) (int64, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxGitHubAPIRespBytes))
	var parsed struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.ID <= 0 {
		return 0, false, nil
	}
	return parsed.ID, true, nil
}

func (b *TokenBroker) apiURL(rel string) string {
	ref, err := url.Parse(strings.TrimLeft(rel, "/"))
	if err != nil {
		return strings.TrimRight(b.apiBaseURL.String(), "/") + "/" + strings.TrimLeft(rel, "/")
	}
	return b.apiBaseURL.ResolveReference(ref).String()
}

func collectExtraSecrets(vals ...string) []string {
	seen := make(map[string]struct{}, len(vals))
	var out []string
	for _, v := range vals {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
