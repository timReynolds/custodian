package write

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	gogithub "github.com/google/go-github/v75/github"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

const (
	defaultGitHubAPIBase = "https://api.github.com/"
	defaultGitHubGitBase = "https://github.com"
	tokenRefreshSkew     = 1 * time.Minute
)

// WriteConfig configures the write GitHub App client used by the isolated publisher.
type WriteConfig struct {
	AppID             int64
	PrivateKeyPEM     []byte
	APIBaseURL        string
	GitBaseURL        string
	HTTPClient        *http.Client
	Now               func() time.Time
	AllowInsecureHTTP bool
	DisableTokenCache bool
	Logger            *slog.Logger
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

type tokenCacheKey struct {
	installationID int64
	repoID         int64
	repoName       string
}

type writeTokenSource struct {
	appID        int64
	privateKey   *rsa.PrivateKey
	apiBaseURL   *url.URL
	httpClient   *http.Client
	now          func() time.Time
	disableCache bool
	logger       *slog.Logger

	mu    sync.Mutex
	cache map[tokenCacheKey]cachedToken
}

// ParseRSAPrivateKeyPEM parses a PKCS#1 or PKCS#8 RSA private key PEM block.
func ParseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, domain.BadRequest("INVALID_GITHUB_APP_KEY", "failed to decode GitHub App private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, domain.WrapError(domain.ErrBadRequest, "INVALID_GITHUB_APP_KEY", "failed to parse GitHub App RSA private key", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, domain.BadRequest("INVALID_GITHUB_APP_KEY", "GitHub App private key must be RSA")
	}
	return rsaKey, nil
}

// MintAppJWT mints a short-lived RS256 GitHub App JWT using Go standard library crypto.
func MintAppJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	if appID <= 0 || key == nil {
		return "", domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "valid app_id and RSA key are required")
	}
	utcNow := now.UTC()
	headerBytes, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: "RS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}{
		Iss: strconv.FormatInt(appID, 10),
		Iat: utcNow.Add(-60 * time.Second).Unix(),
		Exp: utcNow.Add(9 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign app jwt: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func newWriteTokenSource(cfg WriteConfig) (*writeTokenSource, error) {
	if cfg.AppID <= 0 {
		return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "github app_id must be positive")
	}
	key, err := ParseRSAPrivateKeyPEM(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	rawAPI := strings.TrimSpace(cfg.APIBaseURL)
	if rawAPI == "" {
		rawAPI = defaultGitHubAPIBase
	}
	if !strings.HasSuffix(rawAPI, "/") {
		rawAPI += "/"
	}
	apiURL, err := url.Parse(rawAPI)
	if err != nil || apiURL.Scheme == "" || apiURL.Host == "" || apiURL.User != nil {
		return nil, domain.BadRequest("INVALID_GITHUB_APP_CONFIG", "invalid GitHub API base URL")
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &writeTokenSource{
		appID:        cfg.AppID,
		privateKey:   key,
		apiBaseURL:   apiURL,
		httpClient:   hc,
		now:          nowFn,
		disableCache: cfg.DisableTokenCache,
		logger:       cfg.Logger,
		cache:        make(map[tokenCacheKey]cachedToken),
	}, nil
}

func (s *writeTokenSource) newBaseClient() *gogithub.Client {
	client := gogithub.NewClient(s.httpClient)
	baseCopy := *s.apiBaseURL
	client.BaseURL = &baseCopy
	return client
}

func (s *writeTokenSource) installationToken(ctx context.Context, installationID, repoID int64, repoName string) (string, error) {
	if installationID <= 0 {
		return "", domain.BadRequest("INVALID_INSTALLATION_ID", "github_installation_id must be positive")
	}
	key := tokenCacheKey{
		installationID: installationID,
		repoID:         repoID,
		repoName:       repoName,
	}

	now := s.now().UTC()
	if !s.disableCache {
		s.mu.Lock()
		if cached, ok := s.cache[key]; ok && now.Add(tokenRefreshSkew).Before(cached.expiresAt) {
			s.mu.Unlock()
			return cached.token, nil
		}
		s.mu.Unlock()
	}

	jwt, err := MintAppJWT(s.appID, s.privateKey, now)
	if err != nil {
		return "", err
	}

	opts := &gogithub.InstallationTokenOptions{
		Permissions: &gogithub.InstallationPermissions{
			Contents:     gogithub.Ptr("write"),
			PullRequests: gogithub.Ptr("write"),
			Metadata:     gogithub.Ptr("read"),
		},
	}
	if repoID > 0 {
		opts.RepositoryIDs = []int64{repoID}
	} else if repoName != "" {
		opts.Repositories = []string{repoName}
	}

	appClient := s.newBaseClient().WithAuthToken(jwt)
	tokResp, resp, err := appClient.Apps.CreateInstallationToken(ctx, installationID, opts)
	if err != nil {
		return "", mapGitHubError(err, resp, "failed to create write GitHub installation token")
	}
	token := strings.TrimSpace(tokResp.GetToken())
	if token == "" {
		return "", domain.Unavailable("GITHUB_EMPTY_TOKEN", "GitHub returned an empty installation token")
	}

	exp := now.Add(10 * time.Minute)
	if tokResp.ExpiresAt != nil && !tokResp.GetExpiresAt().IsZero() {
		exp = tokResp.GetExpiresAt().Time.UTC()
	}

	if !s.disableCache {
		s.mu.Lock()
		s.cache[key] = cachedToken{token: token, expiresAt: exp}
		s.mu.Unlock()
	}
	if s.logger != nil {
		observability.LoggerWithTrace(ctx, s.logger).Debug("minted write github installation token",
			"github_installation_id", installationID,
			"github_repository_id", repoID,
			"status", "ok",
		)
	}
	return token, nil
}
