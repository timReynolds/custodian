package github

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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
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

func TestMintAppJWTAndKeyParsing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

	for _, pkcs8 := range []bool{false, true} {
		priv, pemBytes := generateTestKeyPEM(t, pkcs8)
		parsed, err := ParseRSAPrivateKeyPEM(pemBytes)
		if err != nil {
			t.Fatalf("ParseRSAPrivateKeyPEM(pkcs8=%v): %v", pkcs8, err)
		}
		jwt, err := MintAppJWT(12345, parsed, now)
		if err != nil {
			t.Fatalf("MintAppJWT: %v", err)
		}
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT parts, got %d", len(parts))
		}

		// Verify RS256 signature with public key
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
		if claims.Iss != "12345" || claims.Exp-claims.Iat != 600 {
			t.Fatalf("unexpected JWT claims: %+v", claims)
		}
	}
}

func TestReadOnlyClientResolveRefAndTokenScoping(t *testing.T) {
	t.Parallel()
	_, pemBytes := generateTestKeyPEM(t, false)
	mainSHA := strings.Repeat("1", 40)
	lightTagSHA := strings.Repeat("2", 40)
	annotTagObjSHA := strings.Repeat("3", 40)
	annotTargetSHA := strings.Repeat("4", 40)
	explicitSHA := strings.Repeat("5", 40)
	installToken := "ghs_readonly_install_token_secret_12345"

	var seenInstallReq struct {
		Auth        string
		RepoIDs     []int64
		Permissions map[string]string
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/99/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		seenInstallReq.Auth = r.Header.Get("Authorization")
		var body struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seenInstallReq.RepoIDs = body.RepositoryIDs
		seenInstallReq.Permissions = body.Permissions

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      installToken,
			"expires_at": time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
		})
	})

	requireInstallAuth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+installToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux.HandleFunc("/repos/acme/app/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":    "refs/heads/main",
			"object": map[string]any{"type": "commit", "sha": mainSHA},
		})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/heads/v1.0", func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "Not Found"})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/tags/v1.0", func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":    "refs/tags/v1.0",
			"object": map[string]any{"type": "commit", "sha": lightTagSHA},
		})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/tags/v2.0", func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ref":    "refs/tags/v2.0",
			"object": map[string]any{"type": "tag", "sha": annotTagObjSHA},
		})
	})
	mux.HandleFunc("/repos/acme/app/git/tags/"+annotTagObjSHA, func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sha":    annotTagObjSHA,
			"object": map[string]any{"type": "commit", "sha": annotTargetSHA},
		})
	})
	mux.HandleFunc("/repos/acme/app/commits/HEAD", func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		_, _ = w.Write([]byte(mainSHA))
	})
	mux.HandleFunc("/repos/acme/app/commits/"+explicitSHA, func(w http.ResponseWriter, r *http.Request) {
		if !requireInstallAuth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": explicitSHA})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/heads/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "Not Found"})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/tags/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "Not Found"})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/heads/ratelimited", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1900000000")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"message": "API rate limit exceeded"})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewReadOnlyClient(AppConfig{
		AppID:         777,
		PrivateKeyPEM: pemBytes,
		APIBaseURL:    srv.URL + "/",
		HTTPClient:    srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewReadOnlyClient: %v", err)
	}

	repo := domain.Repository{
		ID:                   domain.MustNewID(),
		GitHubRepositoryID:   4242,
		GitHubInstallationID: 99,
		FullName:             "acme/app",
		Classification:       domain.ClassificationInternal,
		Enabled:              true,
	}
	ctx := context.Background()

	// Branch resolution
	sha, err := client.ResolveRef(ctx, repo, "main")
	if err != nil || sha != mainSHA {
		t.Fatalf("ResolveRef(main): got %q err=%v", sha, err)
	}
	// Verify read-only permissions and repo scoping
	if !strings.HasPrefix(seenInstallReq.Auth, "Bearer eyJ") {
		t.Fatalf("expected App JWT bearer header, got %q", seenInstallReq.Auth)
	}
	if len(seenInstallReq.RepoIDs) != 1 || seenInstallReq.RepoIDs[0] != 4242 {
		t.Fatalf("expected repo_id 4242 scoping, got %v", seenInstallReq.RepoIDs)
	}
	if seenInstallReq.Permissions["contents"] != "read" || seenInstallReq.Permissions["metadata"] != "read" || len(seenInstallReq.Permissions) != 2 {
		t.Fatalf("expected strictly read-only permissions, got %v", seenInstallReq.Permissions)
	}

	// Qualified branch, lightweight tag, annotated tag, HEAD, explicit SHA
	if got, err := client.ResolveRef(ctx, repo, "refs/heads/main"); err != nil || got != mainSHA {
		t.Fatalf("refs/heads/main: %q %v", got, err)
	}
	if got, err := client.ResolveRef(ctx, repo, "v1.0"); err != nil || got != lightTagSHA {
		t.Fatalf("lightweight tag v1.0: %q %v", got, err)
	}
	if got, err := client.ResolveRef(ctx, repo, "refs/tags/v2.0"); err != nil || got != annotTargetSHA {
		t.Fatalf("annotated tag v2.0: %q %v", got, err)
	}
	if got, err := client.ResolveRef(ctx, repo, "HEAD"); err != nil || got != mainSHA {
		t.Fatalf("HEAD: %q %v", got, err)
	}
	if got, err := client.ResolveRef(ctx, repo, strings.ToUpper(explicitSHA)); err != nil || got != explicitSHA {
		t.Fatalf("explicit SHA: %q %v", got, err)
	}

	// Negative cases: missing ref -> 404, rate limit -> 429, disabled -> 403, invalid ref / PR ref -> 400
	if _, err := client.ResolveRef(ctx, repo, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing ref, got %v", err)
	}
	if _, err := client.ResolveRef(ctx, repo, "refs/heads/ratelimited"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	disabledRepo := repo
	disabledRepo.Enabled = false
	if _, err := client.ResolveRef(ctx, disabledRepo, "main"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for disabled repo, got %v", err)
	}
	for _, badRef := range []string{"-main", "../secret", "refs/pull/1/head", "main..dev", "bad ref"} {
		if _, err := client.ResolveRef(ctx, repo, badRef); !errors.Is(err, domain.ErrBadRequest) {
			t.Fatalf("expected ErrBadRequest for %q, got %v", badRef, err)
		}
	}
}
