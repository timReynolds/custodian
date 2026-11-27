package write

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/observability"
)

func generateTestKeyPEM(t *testing.T, pkcs8 bool) (*rsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	var block *pem.Block
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	} else {
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	}
	return priv, pem.EncodeToMemory(block)
}

func TestWriteAppJWTAndKeyParsing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

	for _, pkcs8 := range []bool{false, true} {
		priv, pemBytes := generateTestKeyPEM(t, pkcs8)
		parsed, err := ParseRSAPrivateKeyPEM(pemBytes)
		if err != nil {
			t.Fatalf("ParseRSAPrivateKeyPEM(pkcs8=%v): %v", pkcs8, err)
		}
		jwt, err := MintAppJWT(202, parsed, now)
		if err != nil {
			t.Fatalf("MintAppJWT: %v", err)
		}
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT parts, got %d", len(parts))
		}
		signingInput := parts[0] + "." + parts[1]
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode sig: %v", err)
		}
		sum := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Fatalf("RS256 signature verify failed: %v", err)
		}

		claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Iss string `json:"iss"`
			Iat int64  `json:"iat"`
			Exp int64  `json:"exp"`
		}
		if err := json.Unmarshal(claimsJSON, &claims); err != nil {
			t.Fatalf("unmarshal claims: %v", err)
		}
		if claims.Iss != "202" || claims.Exp-claims.Iat != 600 {
			t.Fatalf("unexpected JWT claims: %+v", claims)
		}
	}

	if _, err := ParseRSAPrivateKeyPEM([]byte("not-a-pem")); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for invalid PEM, got %v", err)
	}
}

func TestWriteClientTokenScopingCloneURLAndRefResolution(t *testing.T) {
	t.Parallel()
	_, pemBytes := generateTestKeyPEM(t, false)
	writeToken := "ghs_write_secret_token_987654321"
	mainSHA := strings.Repeat("a", 40)

	var mu sync.Mutex
	var tokenMintCount int
	var seenPermissions map[string]string
	var seenRepoIDs []int64

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/app/installations/55/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer eyJ") {
			http.Error(w, "missing app jwt", http.StatusUnauthorized)
			return
		}
		var body struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		tokenMintCount++
		seenPermissions = body.Permissions
		seenRepoIDs = body.RepositoryIDs
		mu.Unlock()

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":       writeToken,
			"expires_at":  time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339),
			"permissions": body.Permissions,
		})
	})

	requireWriteAuth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+writeToken {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux.HandleFunc("/api/v3/repos/acme/app", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":             4242,
			"name":           "app",
			"full_name":      "acme/app",
			"private":        true,
			"default_branch": "main",
			"clone_url":      srv.URL + "/acme/app.git",
			"owner":          map[string]any{"login": "acme"},
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/app/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if !requireWriteAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":    "refs/heads/main",
			"object": map[string]any{"type": "commit", "sha": mainSHA},
		})
	})
	mux.HandleFunc("/api/v3/repos/acme/app/git/ref/heads/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "Not Found"})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	var logBuf bytes.Buffer
	logger := observability.NewLogger(observability.LoggerConfig{
		Writer:    &logBuf,
		Level:     nil,
		Format:    observability.LogFormatJSON,
		Component: "write-client-test",
	})

	client, err := NewWriteClient(WriteConfig{
		AppID:             202,
		PrivateKeyPEM:     pemBytes,
		APIBaseURL:        srv.URL + "/api/v3/",
		HTTPClient:        srv.Client(),
		AllowInsecureHTTP: true,
		Logger:            logger,
	})
	if err != nil {
		t.Fatalf("NewWriteClient: %v", err)
	}

	repo := domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   4242,
		GitHubInstallationID: 55,
		FullName:             "acme/app",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
	}
	ctx := context.Background()

	access, err := client.PreparePushAccess(ctx, repo)
	if err != nil {
		t.Fatalf("PreparePushAccess: %v", err)
	}
	if access.RemoteURL != srv.URL+"/acme/app.git" {
		t.Fatalf("expected clone_url %q, got %q", srv.URL+"/acme/app.git", access.RemoteURL)
	}
	if access.DefaultBranch != "main" {
		t.Fatalf("expected default_branch main, got %q", access.DefaultBranch)
	}
	if access.Token != writeToken || !access.AllowInsecureHTTP || access.AllowLocalBare {
		t.Fatalf("unexpected RepositoryAccess: %+v", access)
	}

	mu.Lock()
	if len(seenRepoIDs) != 1 || seenRepoIDs[0] != 4242 {
		t.Fatalf("expected repo_id 4242 scoping, got %v", seenRepoIDs)
	}
	if seenPermissions["contents"] != "write" || seenPermissions["pull_requests"] != "write" || seenPermissions["metadata"] != "read" || len(seenPermissions) != 3 {
		t.Fatalf("unexpected write permissions: %v", seenPermissions)
	}
	mu.Unlock()

	// ResolveBranchSHA should reuse cached installation token.
	sha, err := client.ResolveBranchSHA(ctx, repo, "refs/heads/main")
	if err != nil || sha != mainSHA {
		t.Fatalf("ResolveBranchSHA: got %q err=%v", sha, err)
	}
	mu.Lock()
	if tokenMintCount != 1 {
		t.Fatalf("expected cached token (mint count 1), got %d", tokenMintCount)
	}
	mu.Unlock()

	if _, err := client.ResolveBranchSHA(ctx, repo, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing branch, got %v", err)
	}
	if _, err := client.ResolveBranchSHA(ctx, repo, "refs/tags/v1.0"); !errors.Is(err, domain.ErrBadRequest) {
		t.Fatalf("expected ErrBadRequest for tag ref in ResolveBranchSHA, got %v", err)
	}
	if strings.Contains(logBuf.String(), writeToken) {
		t.Fatalf("logger leaked write token: %s", logBuf.String())
	}
}

func TestWriteClientRejectsInvalidBranchRefsWithoutNetwork(t *testing.T) {
	t.Parallel()
	_, pemBytes := generateTestKeyPEM(t, false)

	var networkCalls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		networkCalls++
		mu.Unlock()
		http.Error(w, "unexpected network call", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := NewWriteClient(WriteConfig{
		AppID:             202,
		PrivateKeyPEM:     pemBytes,
		APIBaseURL:        srv.URL + "/api/v3/",
		HTTPClient:        srv.Client(),
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewWriteClient: %v", err)
	}

	repo := domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   4242,
		GitHubInstallationID: 55,
		FullName:             "acme/app",
		Enabled:              true,
	}
	ctx := context.Background()

	badBranches := []string{
		"refs/heads/-evil",
		"refs/heads/.hidden",
		"refs/heads/foo.lock/bar",
		"foo.lock/bar",
		".hidden",
		"-evil",
	}
	for _, branch := range badBranches {
		if _, err := client.ResolveBranchSHA(ctx, repo, branch); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("ResolveBranchSHA(%q): expected ErrBadRequest, got %v", branch, err)
		}
		if _, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
			Repository: repo,
			HeadBranch: "custodian/prop-1",
			BaseBranch: branch,
			Title:      "Test",
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("CreateOrUpdatePullRequest(BaseBranch=%q): expected ErrBadRequest, got %v", branch, err)
		}
		if _, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
			Repository: repo,
			HeadBranch: branch,
			BaseBranch: "main",
			Title:      "Test",
		}); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("CreateOrUpdatePullRequest(HeadBranch=%q): expected ErrBadRequest, got %v", branch, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if networkCalls != 0 {
		t.Fatalf("expected 0 HTTP calls for invalid branch refs, got %d", networkCalls)
	}
}

func TestWriteClientCreateOrUpdatePullRequestIdempotencyAndRace(t *testing.T) {
	t.Parallel()
	_, pemBytes := generateTestKeyPEM(t, true)
	writeToken := "ghs_write_pr_token_123456"

	var mu sync.Mutex
	type prState struct {
		Number int
		Title  string
		Body   string
		Head   string
		Base   string
		State  string
	}
	var prs []prState
	var forceNextCreateRace bool

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/app/installations/77/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      writeToken,
			"expires_at": time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/v3/repos/acme/app/pulls", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			head := r.URL.Query().Get("head")
			base := r.URL.Query().Get("base")
			state := r.URL.Query().Get("state")
			mu.Lock()
			var out []map[string]any
			for _, pr := range prs {
				if (state == "" || pr.State == state) &&
					(head == "" || head == "acme:"+pr.Head || head == pr.Head) &&
					(base == "" || base == pr.Base) {
					out = append(out, map[string]any{
						"number":   pr.Number,
						"title":    pr.Title,
						"body":     pr.Body,
						"state":    pr.State,
						"url":      srv.URL + "/api/v3/repos/acme/app/pulls/1",
						"html_url": srv.URL + "/acme/app/pull/1",
						"head":     map[string]any{"ref": pr.Head, "label": "acme:" + pr.Head},
						"base":     map[string]any{"ref": pr.Base, "label": "acme:" + pr.Base},
					})
				}
			}
			// Simulate concurrent worker creating the PR between List and Create.
			if forceNextCreateRace && len(out) == 0 {
				prs = append(prs, prState{
					Number: 1,
					Title:  "Raced PR",
					Body:   "Created concurrently",
					Head:   "custodian/prop-1",
					Base:   "main",
					State:  "open",
				})
			}
			mu.Unlock()
			if out == nil {
				out = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			var req struct {
				Title string `json:"title"`
				Body  string `json:"body"`
				Head  string `json:"head"`
				Base  string `json:"base"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			for _, pr := range prs {
				if pr.State == "open" && pr.Head == req.Head && pr.Base == req.Base {
					mu.Unlock()
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(map[string]any{"message": "A pull request already exists for acme:" + req.Head})
					return
				}
			}
			n := len(prs) + 1
			pr := prState{
				Number: n,
				Title:  req.Title,
				Body:   req.Body,
				Head:   req.Head,
				Base:   req.Base,
				State:  "open",
			}
			prs = append(prs, pr)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number":   pr.Number,
				"title":    pr.Title,
				"body":     pr.Body,
				"state":    pr.State,
				"url":      srv.URL + "/api/v3/repos/acme/app/pulls/1",
				"html_url": srv.URL + "/acme/app/pull/1",
				"head":     map[string]any{"ref": pr.Head},
				"base":     map[string]any{"ref": pr.Base},
			})
		}
	})

	mux.HandleFunc("/api/v3/repos/acme/app/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Title *string `json:"title"`
			Body  *string `json:"body"`
			Base  *string `json:"base"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		if req.Title != nil {
			prs[0].Title = *req.Title
		}
		if req.Body != nil {
			prs[0].Body = *req.Body
		}
		if req.Base != nil {
			prs[0].Base = *req.Base
		}
		pr := prs[0]
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"number":   pr.Number,
			"title":    pr.Title,
			"body":     pr.Body,
			"state":    pr.State,
			"url":      srv.URL + "/api/v3/repos/acme/app/pulls/1",
			"html_url": srv.URL + "/acme/app/pull/1",
			"head":     map[string]any{"ref": pr.Head},
			"base":     map[string]any{"ref": pr.Base},
		})
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewWriteClient(WriteConfig{
		AppID:             202,
		PrivateKeyPEM:     pemBytes,
		APIBaseURL:        srv.URL + "/api/v3/",
		GitBaseURL:        srv.URL,
		HTTPClient:        srv.Client(),
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewWriteClient: %v", err)
	}

	repo := domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   900,
		GitHubInstallationID: 77,
		FullName:             "acme/app",
		Enabled:              true,
	}
	ctx := context.Background()

	// 1. Create PR
	res1, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "Initial title",
		Body:       "Initial body",
	})
	if err != nil {
		t.Fatalf("Create PR: %v", err)
	}
	if res1.Number != 1 || res1.Updated {
		t.Fatalf("unexpected create result: %+v", res1)
	}

	// 2. Identical replay reuses existing PR without duplicating
	res2, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "refs/heads/custodian/prop-1",
		BaseBranch: "refs/heads/main",
		Title:      "Initial title",
		Body:       "Initial body",
	})
	if err != nil {
		t.Fatalf("Replay PR: %v", err)
	}
	if res2.Number != 1 || res2.Updated {
		t.Fatalf("expected reused PR #1 without update, got %+v", res2)
	}

	// 3. Updated title/body patches existing PR #1
	res3, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "Updated title",
		Body:       "Updated body",
	})
	if err != nil {
		t.Fatalf("Update PR: %v", err)
	}
	if res3.Number != 1 || !res3.Updated || res3.Title != "Updated title" {
		t.Fatalf("expected updated PR #1, got %+v", res3)
	}

	// 4. Concurrent 422 race recovery
	mu.Lock()
	prs = nil
	forceNextCreateRace = true
	mu.Unlock()
	resRace, err := client.CreateOrUpdatePullRequest(ctx, PullRequestParams{
		Repository: repo,
		HeadBranch: "custodian/prop-1",
		BaseBranch: "main",
		Title:      "Winner title",
		Body:       "Winner body",
	})
	if err != nil {
		t.Fatalf("422 race recovery failed: %v", err)
	}
	if resRace.Number != 1 || !resRace.Updated || resRace.Title != "Winner title" {
		t.Fatalf("unexpected race recovery result: %+v", resRace)
	}
	mu.Lock()
	if len(prs) != 1 {
		t.Fatalf("expected exactly 1 PR after race, got %d", len(prs))
	}
	mu.Unlock()
}

func TestWriteClientErrorMappingAndDisabledRepo(t *testing.T) {
	t.Parallel()
	_, pemBytes := generateTestKeyPEM(t, false)

	cases := []struct {
		status int
		header map[string]string
		want   error
	}{
		{http.StatusUnauthorized, nil, domain.ErrForbidden},
		{http.StatusForbidden, nil, domain.ErrForbidden},
		{http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, domain.ErrRateLimited},
		{http.StatusTooManyRequests, nil, domain.ErrRateLimited},
		{http.StatusUnprocessableEntity, nil, domain.ErrUnprocessable},
		{http.StatusServiceUnavailable, nil, domain.ErrUnavailable},
	}

	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range tc.header {
				w.Header().Set(k, v)
			}
			w.WriteHeader(tc.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "simulated error"})
		}))
		client, err := NewWriteClient(WriteConfig{
			AppID:             202,
			PrivateKeyPEM:     pemBytes,
			APIBaseURL:        srv.URL + "/api/v3/",
			HTTPClient:        srv.Client(),
			DisableTokenCache: true,
		})
		if err != nil {
			srv.Close()
			t.Fatalf("NewWriteClient: %v", err)
		}
		repo := domain.Repository{
			ID:                   domain.MustNewID(),
			GitHubRepositoryID:   1,
			GitHubInstallationID: 1,
			FullName:             "acme/app",
			Enabled:              true,
		}
		_, err = client.PreparePushAccess(context.Background(), repo)
		srv.Close()
		if !errors.Is(err, tc.want) {
			t.Fatalf("status %d: expected %v, got %v", tc.status, tc.want, err)
		}
	}

	// Disabled repo returns ErrForbidden without hitting network.
	client, err := NewWriteClient(WriteConfig{
		AppID:         202,
		PrivateKeyPEM: pemBytes,
	})
	if err != nil {
		t.Fatalf("NewWriteClient: %v", err)
	}
	disabled := domain.Repository{FullName: "acme/app", Enabled: false}
	if _, err := client.PreparePushAccess(context.Background(), disabled); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo, got %v", err)
	}
	if _, err := client.CreateOrUpdatePullRequest(context.Background(), PullRequestParams{
		Repository: disabled,
		HeadBranch: "custodian/p1",
		BaseBranch: "main",
		Title:      "t",
	}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo PR, got %v", err)
	}
}
