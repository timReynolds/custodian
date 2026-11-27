package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/auth"
	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/identity"
)

func TestPushRolePredicates(t *testing.T) {
	secAdmin := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{Groups: []string{"engineering", "ip-review", "security-admins"}},
	}
	policyAdmin := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindPolicyAdmin, Roles: []string{"policy_admin"}},
	}
	ipReviewer := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{Groups: []string{"ip-review"}},
	}
	auditorByKind := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindAuditor, Roles: []string{"auditor"}},
	}
	auditorByGroup := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{Groups: []string{"audit-readers"}},
	}
	regularHuman := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{Groups: []string{"engineering"}},
	}
	controller := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindService},
		Claims:    auth.VerifiedClaims{TokenKind: auth.TokenKindController, Roles: []string{"controller"}},
	}

	if !isPushAdmin(secAdmin) || !isPushApprover(secAdmin) || !canReadAllPushes(secAdmin) {
		t.Fatalf("secAdmin should have admin, approver, and read-all access")
	}
	if !isPushAdmin(policyAdmin) || !isPushApprover(policyAdmin) || !canReadAllPushes(policyAdmin) {
		t.Fatalf("policyAdmin should have admin, approver, and read-all access")
	}
	if isPushAdmin(ipReviewer) || !isPushApprover(ipReviewer) || !canReadAllPushes(ipReviewer) {
		t.Fatalf("ipReviewer should be approver + reader, not admin")
	}
	for _, aud := range []identity.CallerContext{auditorByKind, auditorByGroup} {
		if !isPushAuditor(aud) || isPushAdmin(aud) || isPushApprover(aud) || !canReadAllPushes(aud) {
			t.Fatalf("auditor should only read, never mutate: %+v", aud)
		}
	}
	if isPushAdmin(regularHuman) || isPushApprover(regularHuman) || canReadAllPushes(regularHuman) || isPushAuditor(regularHuman) {
		t.Fatalf("regularHuman must not have privileged push predicates")
	}
	if isPushAdmin(controller) || isPushApprover(controller) || !canReadAllPushes(controller) {
		t.Fatalf("controller should read all pushes, never act as human admin/approver")
	}
}

func TestSanitizeDestinationAndFinding(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://x-access-token:ghp_secret123@github.com/acme/repo.git", "https://github.com/acme/repo.git"},
		{"ssh://user:pass@git.internal/org/repo", "ssh://git.internal/org/repo"},
		{"x-access-token:secret@github.com/acme/repo", "github.com/acme/repo"},
		{"github.com/acme/repo", "github.com/acme/repo"},
	}
	for _, tc := range cases {
		if got := sanitizeDestinationForAPI(tc.in); got != tc.want {
			t.Fatalf("sanitizeDestinationForAPI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	canon, host, err := canonicalizeDestination("https://GitHub.COM/Acme/Repo.git", "")
	if err != nil {
		t.Fatalf("canonicalizeDestination URL: %v", err)
	}
	if canon != "github.com/Acme/Repo.git" || host != "github.com" {
		t.Fatalf("unexpected canonical destination: %q, host=%q", canon, host)
	}

	f := domain.Finding{
		ID:          domain.MustNewID(),
		ScanRunID:   domain.MustNewID(),
		Category:    "SECRET",
		Severity:    domain.SeverityCritical,
		RuleID:      "ghp-pat",
		Fingerprint: strings.Repeat("a", 64),
		Message:     "Found Bearer eyJhbGciOiJSUzI1NiJ9.payload123.sig123456 in config",
		Redacted:    false,
		Metadata: map[string]any{
			"raw_secret":       "ghp_supersecret123456",
			"rawSource":        "CONFIDENTIAL_ALGO()",
			"snippet":          "secret line",
			"token_count":      42,
			"source_ref":       "inline:sha256:abc",
			"redacted_preview": "ghp_***",
			"nested": map[string]any{
				"privateKey": "-----BEGIN RSA PRIVATE KEY-----",
				"safe_note":  "line 12",
			},
		},
	}
	dto := sanitizeFindingForAPI(f)
	if !dto.Redacted {
		t.Fatal("expected SECRET finding to have Redacted=true")
	}
	if dto.Message == nil || strings.Contains(*dto.Message, "eyJhbGciOiJSUzI1NiJ9") {
		t.Fatalf("finding message leaked JWT: %v", dto.Message)
	}
	for _, forbidden := range []string{"raw_secret", "rawSource", "snippet"} {
		if _, exists := dto.Metadata[forbidden]; exists {
			t.Fatalf("forbidden metadata key %q was not stripped: %+v", forbidden, dto.Metadata)
		}
	}
	for _, safe := range []string{"token_count", "source_ref", "redacted_preview"} {
		if _, exists := dto.Metadata[safe]; !exists {
			t.Fatalf("safe metadata key %q was stripped unexpectedly", safe)
		}
	}
	nested, ok := dto.Metadata["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map in metadata")
	}
	if _, exists := nested["privateKey"]; exists {
		t.Fatalf("nested privateKey was not stripped: %+v", nested)
	}
}

func TestHandleReindexIPCorpus_FailsClosed503WhenReindexerNil(t *testing.T) {
	srv := newServer(Deps{
		IPCorpusReindexer: nil,
		Store:             nil,
	})
	admin := identity.CallerContext{
		Principal: domain.Principal{ID: domain.MustNewID(), Kind: domain.PrincipalKindHuman},
		Claims:    auth.VerifiedClaims{Groups: []string{"security-admins"}},
	}
	id := uuid.Must(uuid.NewV7()).String()
	req := httptest.NewRequest(http.MethodPost, "/v1/ip-corpora/"+id+"/reindex", strings.NewReader(`{"force":true}`))
	req.Header.Set("Idempotency-Key", "idem-reindex-nil")
	req = req.WithContext(withCallerContext(context.Background(), admin))

	rec := httptest.NewRecorder()
	srv.handleReindexIPCorpus(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 SERVICE_UNAVAILABLE when IPCorpusReindexer is nil, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSanitizeFindingForAPI_TypedCollectionsRawJSONAndPEM(t *testing.T) {
	type customMetaStruct struct {
		ContentSnippet string `json:"content_snippet"`
		SafeNote       string `json:"safe_note"`
	}
	jwtTok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	pemBlock := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----"

	f := domain.Finding{
		ID:          domain.MustNewID(),
		ScanRunID:   domain.MustNewID(),
		Category:    "IP_LEAK",
		Severity:    domain.SeverityHigh,
		RuleID:      "ip-winnow",
		Fingerprint: strings.Repeat("b", 64),
		Message:     "Found key:\n" + pemBlock,
		Metadata: map[string]any{
			"content_snippet": "func SecretA() {}",
			"content-snippet": "func SecretB() {}",
			"contentSnippet":  "func SecretC() {}",
			"code_snippet":    "func SecretD() {}",
			"matched_text":    "func SecretE() {}",
			"source_snippet":  "func SecretF() {}",
			"match_text":      "func SecretG() {}",
			"raw_line":        "ghp_SecretLine123456",
			"ssh_key":         "ssh-ed25519 AAAA",
			"api_key":         "ak_123456",
			"client_secret":   "cs_123456",
			"bearer_token":    jwtTok,
			"typed_str_slice": []string{"ghp_TopSecretPATValue1234567890", "safe-tag"},
			"typed_str_map": map[string]string{
				"raw_secret": "SuperSecretPass99",
				"safe_key":   "Bearer " + jwtTok,
			},
			"typed_map_slice": []map[string]any{
				{
					"content_snippet": "func ProprietaryAlgorithm() int { return 999999 }",
					"safe_path":       "pkg/public.go",
					"token_val":       "ghs_SecretToken12345",
				},
			},
			"typed_struct": &customMetaStruct{
				ContentSnippet: "func StructSecret() {}",
				SafeNote:       "with ghp_StructPATSecret12345",
			},
			"job_token":             "tok_job_secret",
			"deploy_token":          "tok_deploy_secret",
			"api_token":             "tok_api_secret",
			"auth_token":            "tok_auth_secret",
			"refresh_token":         "tok_refresh_secret",
			"id_token":              "tok_id_secret",
			"session_token":         "tok_session_secret",
			"personal_access_token": "tok_pat_secret",
			"passwd":                "tok_passwd_secret",
			"secret_key":            "tok_secret_key_val",
			"access_key":            "tok_access_key_val",
			"x-amz-security-token":  "tok_amz_sec_val",
			"x-amz-credential":      "tok_amz_cred_val",
			"x-amz-signature":       "tok_amz_sig_val",
			"code":                  "E_SAFE_CODE",
			"key":                   "safe-key-id",
			"signature":             "sig-ok",
			"pass":                  true,
			"auth":                  "oidc",
			"layer":                 "L2",
			"corpus_classification": "RESTRICTED",
			"token_count":           12,
			"source_ref":            "inline:sha256:def",
			"redacted_preview":      "ghp_***",
			"raw_json_msg":          json.RawMessage(`{"content_snippet":"func RawJSONSecret() {}","job_token":"tok_raw_job","deploy_token":"tok_raw_deploy","api_token":"tok_raw_api","auth_token":"tok_raw_auth","refresh_token":"tok_raw_refresh","id_token":"tok_raw_id","session_token":"tok_raw_session","personal_access_token":"tok_raw_pat","passwd":"tok_raw_passwd","secret_key":"tok_raw_secret_key","access_key":"tok_raw_access_key","x-amz-security-token":"tok_raw_amz_sec","x-amz-credential":"tok_raw_amz_cred","x-amz-signature":"tok_raw_amz_sig","safe":"ok","code":"E_JSON_CODE","tok":"ghp_RawJSONSecret12345"}`),
		},
	}

	dto := sanitizeFindingForAPI(f)
	outBytes, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("json.Marshal sanitized FindingDTO: %v", err)
	}
	out := string(outBytes)

	leaks := []string{
		"SecretA", "SecretB", "SecretC", "SecretD", "SecretE", "SecretF", "SecretG",
		"ghp_SecretLine123456", "ssh-ed25519 AAAA", "ak_123456", "cs_123456",
		jwtTok, "ghp_TopSecretPATValue1234567890", "SuperSecretPass99",
		"ProprietaryAlgorithm", "ghs_SecretToken12345", "StructSecret",
		"ghp_StructPATSecret12345", "RawJSONSecret", "ghp_RawJSONSecret12345",
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=", "END OPENSSH PRIVATE KEY",
		"tok_job_secret", "tok_deploy_secret", "tok_api_secret", "tok_auth_secret",
		"tok_refresh_secret", "tok_id_secret", "tok_session_secret", "tok_pat_secret",
		"tok_passwd_secret", "tok_secret_key_val", "tok_access_key_val",
		"tok_amz_sec_val", "tok_amz_cred_val", "tok_amz_sig_val",
		"tok_raw_job", "tok_raw_deploy", "tok_raw_api", "tok_raw_auth",
		"tok_raw_refresh", "tok_raw_id", "tok_raw_session", "tok_raw_pat",
		"tok_raw_passwd", "tok_raw_secret_key", "tok_raw_access_key",
		"tok_raw_amz_sec", "tok_raw_amz_cred", "tok_raw_amz_sig",
	}
	for _, needle := range leaks {
		if strings.Contains(out, needle) {
			t.Fatalf("sanitized finding JSON leaked %q: %s", needle, out)
		}
	}
	for _, keep := range []string{
		"safe-tag", "pkg/public.go", `"safe":"ok"`,
		`"code":"E_SAFE_CODE"`, `"key":"safe-key-id"`, `"signature":"sig-ok"`,
		`"pass":true`, `"auth":"oidc"`, `"layer":"L2"`,
		`"corpus_classification":"RESTRICTED"`, `"token_count":12`,
		`"source_ref":"inline:sha256:def"`, `"redacted_preview":"ghp_***"`,
		`"code":"E_JSON_CODE"`,
	} {
		if !strings.Contains(out, keep) {
			t.Fatalf("sanitized finding JSON unexpectedly dropped %q: %s", keep, out)
		}
	}
}

func TestSanitizeDestinationAndCanonicalizeRegression(t *testing.T) {
	if got := sanitizeDestinationForAPI("https://x-access-token:ghp_Secret123456@github.com/org/repo.git?token=ghp_QuerySecret999&ref=main#ghp_FragSecret123"); strings.Contains(got, "ghp_") || strings.Contains(got, "x-access-token") || !strings.Contains(got, "ref=main") {
		t.Fatalf("sanitizeDestinationForAPI query/fragment leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://gitlab.example.com/org/repo.git?private_token=plainsecret&ref=main"); got != "https://gitlab.example.com/org/repo.git?ref=main" {
		t.Fatalf("sanitizeDestinationForAPI private_token leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://myPlainToken@github.com/org/repo.git%ZZ"); got != "https://github.com/org/repo.git%ZZ" {
		t.Fatalf("sanitizeDestinationForAPI malformed %%ZZ http userinfo leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://myPlainToken@github.com/org/repo.git%ZZ?private_token=plainsecret&ref=main"); got != "https://github.com/org/repo.git%ZZ?ref=main" {
		t.Fatalf("sanitizeDestinationForAPI malformed %%ZZ userinfo+query leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://github.com/org/repo.git%ZZ?private_token=plainsecret&job_token=jobsec&ref=main#ghp_FragSecret123"); got != "https://github.com/org/repo.git%ZZ?ref=main#[REDACTED]" {
		t.Fatalf("sanitizeDestinationForAPI malformed %%ZZ query+fragment leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://github.com/org/repo.git%ZZ?ref=main&private%ZZ_token=plainsecret"); got != "https://github.com/org/repo.git%ZZ?ref=main" {
		t.Fatalf("sanitizeDestinationForAPI malformed %%ZZ key leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://github.com/org/repo.git?ref=main;private_token=plainsecret"); got != "https://github.com/org/repo.git?ref=main" {
		t.Fatalf("sanitizeDestinationForAPI semicolon query leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://github.com/org/repo.git?private_token=plainsecret%ZZ&ref=main"); got != "https://github.com/org/repo.git?ref=main" {
		t.Fatalf("sanitizeDestinationForAPI %%ZZ query value leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("file:///opt/corpora/repo?private_token=plainsecret"); got != "file:///opt/corpora/repo" {
		t.Fatalf("sanitizeDestinationForAPI file:/// query leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("https://github.com?email=alice@example.com%ZZ"); got != "https://github.com?email=alice@example.com%ZZ" {
		t.Fatalf("sanitizeDestinationForAPI unexpected query @ strip: %q", got)
	}
	if got := sanitizeDestinationForAPI("ssh://git@github.com/org/repo.git%ZZ"); got != "ssh://git@github.com/org/repo.git%ZZ" {
		t.Fatalf("sanitizeDestinationForAPI ssh%%ZZ unexpected strip: %q", got)
	}
	if got := sanitizeDestinationForAPI("ssh://git@github.com/org/repo.git%ZZ?private_token=plainsecret&ref=main"); got != "ssh://git@github.com/org/repo.git%ZZ?ref=main" {
		t.Fatalf("sanitizeDestinationForAPI ssh%%ZZ query leak: %q", got)
	}
	if got := sanitizeDestinationForAPI("x-access-token:ghp_Secret12345@github.com:org/repo.git"); got != "github.com:org/repo.git" {
		t.Fatalf("sanitizeDestinationForAPI SCP creds: got %q", got)
	}

	cases := []struct {
		raw      string
		fallback string
		wantDest string
		wantHost string
	}{
		{"git@GitHub.COM:Org/Repo.git", "", "github.com/Org/Repo.git", "github.com"},
		{"user@GitHub.COM:Org/Repo.git", "", "github.com/Org/Repo.git", "github.com"},
		{"Org/Repo", "GitHub.COM", "github.com/Org/Repo", "github.com"},
		{"localhost:8080/Org/Repo.git", "", "localhost:8080/Org/Repo.git", "localhost:8080"},
		{"[::1]:8443/Org/Repo.git", "", "[::1]:8443/Org/Repo.git", "[::1]:8443"},
		{"[::1]/Org/Repo.git", "", "[::1]/Org/Repo.git", "[::1]"},
		{"[::1]:Org/Repo.git", "", "[::1]/Org/Repo.git", "[::1]"},
		{"[::1]:/Org/Repo.git", "", "[::1]/Org/Repo.git", "[::1]"},
		{"git@[2001:DB8::1]:8443/Org/Repo.git", "", "[2001:db8::1]:8443/Org/Repo.git", "[2001:db8::1]:8443"},
		{"https://GitHub.COM///Org/Repo.git", "", "github.com/Org/Repo.git", "github.com"},
		{"git@GitHub.COM:///Org/Repo.git", "", "github.com/Org/Repo.git", "github.com"},
		{"[::1]:8443///Org/Repo.git", "", "[::1]:8443/Org/Repo.git", "[::1]:8443"},
		{"github.com///Org/Repo.git", "", "github.com/Org/Repo.git", "github.com"},
	}
	for _, tc := range cases {
		gotDest, gotHost, err := canonicalizeDestination(tc.raw, tc.fallback)
		if err != nil {
			t.Fatalf("canonicalizeDestination(%q, %q) err: %v", tc.raw, tc.fallback, err)
		}
		if gotDest != tc.wantDest || gotHost != tc.wantHost {
			t.Fatalf("canonicalizeDestination(%q, %q) = (%q, %q), want (%q, %q)", tc.raw, tc.fallback, gotDest, gotHost, tc.wantDest, tc.wantHost)
		}
	}

	invalidDests := []string{
		"https://GitHub.COM///",
		"[::1]",
		"[2001:db8::1]",
		"[::1]:8443",
		"[2001:db8::1]:8443",
		"git@[::1]",
		"git@[::1]:8443",
		"[::1]/",
		"[::1]///",
		"[::1]:",
		"[::1]:/",
		"[::1]:8443/",
		"[::1",
		"[",
		"[bad",
		"[]",
		"[]/Org/Repo",
		"[::1]extra/Org/Repo",
		"[[::1]/Org/Repo",
		"localhost:8443",
	}
	for _, bad := range invalidDests {
		for _, fb := range []string{"", "github.com"} {
			if gotDest, gotHost, err := canonicalizeDestination(bad, fb); err == nil {
				t.Fatalf("canonicalizeDestination(%q, %q) expected error, got (%q, %q)", bad, fb, gotDest, gotHost)
			}
		}
	}
}

func TestValidateGitRemoteURLAndCorpusValidationRegression(t *testing.T) {
	badRemotes := []string{
		"  " + strings.Repeat("a", 511),
		"https://ghp_SecretToken123@github.com/org/repo.git",
		"http://token@github.com/org/repo.git",
		"https://user:pass@github.com/org/repo.git",
		"ssh://user:pass@github.com/org/repo.git",
		"ssh://x-access-token@github.com/org/repo.git",
		"x-access-token:ghp_Secret12345@github.com:org/repo.git",
		"user:secret@github.com:org/repo.git",
		"x-access-token:ghp_Secret12345@github.com/org/repo.git",
		"oauth2@github.com:org/repo.git",
	}
	for _, r := range badRemotes {
		if got, err := validateGitRemoteURL(r); err == nil {
			t.Fatalf("validateGitRemoteURL(%q) unexpectedly succeeded with %q", r, got)
		}
	}
	goodRemotes := []string{
		"https://github.com/org/repo.git",
		"ssh://git@github.com/org/repo.git",
		"git@github.com:org/repo.git",
	}
	for _, r := range goodRemotes {
		if _, err := validateGitRemoteURL(r); err != nil {
			t.Fatalf("validateGitRemoteURL(%q) failed unexpectedly: %v", r, err)
		}
	}

	if _, err := validateRemoteHost(" " + strings.Repeat("a", 255)); err == nil {
		t.Fatal("expected untrimmed remote_host > 255 to fail")
	}

	for _, badPath := range []string{`..\secret`, `dir\..\secret`, "../secret", "  " + strings.Repeat("a", 1023)} {
		if got, err := validateCorpusSourceString(badPath, "INVALID_CORPUS_SOURCE", "source_path", 1024); err == nil {
			t.Fatalf("validateCorpusSourceString(%q) unexpectedly succeeded with %q", badPath, got)
		}
	}

	emptyStr := ""
	wsStr := "   \n\t"
	if _, err := validateAndConvertCorpusFiles([]IPCorpusFileInputDTO{{Path: "empty.go", Content: &emptyStr}}); err == nil {
		t.Fatal("expected empty content without sha256 to fail")
	}
	if _, err := validateAndConvertCorpusFiles([]IPCorpusFileInputDTO{{Path: "ws.go", Content: &wsStr}}); err == nil {
		t.Fatal("expected whitespace content without sha256 to fail")
	}
	sha := strings.Repeat("a", 64)
	if _, err := validateAndConvertCorpusFiles([]IPCorpusFileInputDTO{{Path: "empty.go", Content: &emptyStr, SHA256: &sha}}); err != nil {
		t.Fatalf("expected empty content WITH valid sha256 to pass, got %v", err)
	}

	for _, badRef := range []string{
		"https://user:ghp_SecretToken123@github.com/org/repo",
		"https://ghp_SecretToken123@github.com/org/repo",
		"x-access-token:ghp_SecretToken123@github.com/org/repo",
		"https://github.com/org/repo?token=ghp_SecretToken123",
		"https://gitlab.example.com/org/repo.git?private_token=plainsecret",
		"https://myPlainToken@github.com/org/repo.git%ZZ",
		"https://myPlainToken@github.com/org/repo.git%ZZ?private_token=plainsecret&ref=main",
		"https://github.com/org/repo.git%ZZ?private_token=plainsecret&ref=main",
		"https://github.com/org/repo.git?private_token=plainsecret%ZZ&ref=main",
		"https://github.com/org/repo.git?foo=1;job_token=secret123",
		"github.com/org/repo?private_token=plainsecret",
		"ssh://git@github.com/org/repo.git%ZZ",
	} {
		if err := validateCorpusSourceRefNoCreds(badRef); err == nil {
			t.Fatalf("validateCorpusSourceRefNoCreds(%q) expected error", badRef)
		}
		safe := computeSafeCorpusSourceRef(badRef, "", nil)
		if !strings.HasPrefix(safe, "ref:sha256:") || strings.Contains(safe, "ghp_SecretToken123") || strings.Contains(safe, "user:") || strings.Contains(safe, "plainsecret") || strings.Contains(safe, "myPlainToken") || strings.Contains(safe, "secret123") {
			t.Fatalf("computeSafeCorpusSourceRef(%q) leaked or failed to hash: %q", badRef, safe)
		}
	}
	for _, goodRef := range []string{
		"github.com/org/repo",
		"git@github.com:org/repo.git",
		"file:///opt/corpora/restricted",
		"git://internal/repo",
		"/opt/corpora/restricted",
	} {
		if err := validateCorpusSourceRefNoCreds(goodRef); err != nil {
			t.Fatalf("validateCorpusSourceRefNoCreds(%q) failed unexpectedly: %v", goodRef, err)
		}
		if safe := computeSafeCorpusSourceRef(goodRef, "", nil); safe != goodRef {
			t.Fatalf("computeSafeCorpusSourceRef(%q) = %q, want verbatim", goodRef, safe)
		}
	}
	for _, badQueryRemote := range []string{
		"https://gitlab.example.com/org/repo.git?private_token=plainsecret",
		"https://github.com/org/repo.git?private_token=plainsecret%ZZ",
		"https://github.com/org/repo.git?foo=1;job_token=secret123",
	} {
		if got, err := validateGitRemoteURL(badQueryRemote); err == nil {
			t.Fatalf("validateGitRemoteURL(%q) unexpectedly succeeded with %q", badQueryRemote, got)
		}
	}
}

func TestSanitizeFindingForAPI_PlainCyclesEmptySlicesAndDAGs(t *testing.T) {
	type myBytes []byte
	type myUint8 uint8
	type wrapper struct {
		M map[string]any `json:"m"`
		S []any          `json:"s"`
	}

	selfMap := map[string]any{"note": "ok", "tok": "ghp_SelfMapSecret12345"}
	selfMap["self"] = selfMap

	mutA := map[string]any{"name": "a"}
	mutB := map[string]any{"name": "b", "a": mutA}
	mutA["b"] = mutB

	selfSlice := make([]any, 2)
	selfSlice[0] = "ok"
	selfSlice[1] = selfSlice

	subSlice := make([]any, 2)
	subSlice[0] = subSlice[:1]
	subSlice[1] = "ghp_SubSliceSecret12345"

	mixedMap := map[string]any{"ok": "mixed"}
	mixedSlice := []any{mixedMap, &mixedMap}
	mixedWrap := wrapper{M: mixedMap, S: mixedSlice}
	mixedMap["slice"] = mixedSlice
	mixedMap["wrap"] = &mixedWrap
	mixedMap["pslice"] = &mixedSlice

	sharedMap := map[string]any{"note": "ok", "secret": "drop-me"}
	sharedSlice := []any{"ok", "ghp_SecretToken12345"}

	var nilAnySlice []any
	emptySliceA := []any{}
	emptySliceB := []any{}
	emptyMap := map[string]any{}

	var fixedByteArr [40]byte
	copy(fixedByteArr[:], "ghp_FixedByteSecret123456789012345678901")
	var fixedUint8Arr [40]myUint8
	for i, ch := range []byte("ghp_FixedByteSecret123456789012345678901") {
		fixedUint8Arr[i] = myUint8(ch)
	}
	fixedUint8ArrPtr := fixedUint8Arr
	fIDForTest := domain.MustNewID()

	f := domain.Finding{
		ID:          fIDForTest,
		ScanRunID:   domain.MustNewID(),
		Category:    "SECRET",
		Severity:    domain.SeverityHigh,
		RuleID:      "cycle-test",
		Fingerprint: strings.Repeat("c", 64),
		Metadata: map[string]any{
			"self_map":           selfMap,
			"mutual_a":           mutA,
			"self_slice":         selfSlice,
			"sub_slice":          subSlice,
			"mixed":              mixedMap,
			"dag_map_1":          sharedMap,
			"dag_map_2":          sharedMap,
			"dag_slice_1":        sharedSlice,
			"dag_slice_2":        sharedSlice,
			"nil_slice":          nilAnySlice,
			"empty_slice_a":      emptySliceA,
			"empty_slice_b":      emptySliceB,
			"empty_map":          emptyMap,
			"named_bytes":        myBytes("prefix ghp_NamedByteSecret12345 suffix"),
			"fixed_byte_arr":     fixedByteArr,
			"fixed_uint8_arr":    fixedUint8Arr,
			"fixed_uint8_arr_pt": &fixedUint8ArrPtr,
			"str_array":          [2]string{"ghp_StrArrSecret12345", "safe"},
			"int_array":          [3]int{1, 2, 3},
			"uuid_val":           fIDForTest,
		},
	}

	dto := sanitizeFindingForAPI(f)
	outBytes, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("json.Marshal cyclic/DAG FindingDTO: %v", err)
	}
	out := string(outBytes)

	for _, leak := range []string{
		"ghp_SelfMapSecret12345",
		"ghp_SubSliceSecret12345",
		"ghp_SecretToken12345",
		"ghp_NamedByteSecret12345",
		"ghp_FixedByteSecret123456789012345678901",
		"ghp_StrArrSecret12345",
		"drop-me",
		"[112,114,101", // raw byte array for "pre..."
		"[103,104,112", // raw byte array for "ghp..."
	} {
		if strings.Contains(out, leak) {
			t.Fatalf("sanitized finding JSON leaked %q: %s", leak, out)
		}
	}

	if dto.Metadata["nil_slice"] != nil {
		t.Fatalf("nil_slice expected nil, got %#v", dto.Metadata["nil_slice"])
	}
	if !strings.Contains(out, `"nil_slice":null`) {
		t.Fatalf("expected nil_slice serialized as null, got: %s", out)
	}
	if !strings.Contains(out, `"int_array":[1,2,3]`) {
		t.Fatalf("expected int_array preserved as [1,2,3], got: %s", out)
	}
	if !strings.Contains(out, `"str_array":["[REDACTED]","safe"]`) {
		t.Fatalf("expected str_array scrubbed to [\"[REDACTED]\",\"safe\"], got: %s", out)
	}
	if gotUUID, ok := dto.Metadata["uuid_val"].(string); !ok || gotUUID != f.ID.String() {
		t.Fatalf("uuid_val expected %q, got %#v", f.ID.String(), dto.Metadata["uuid_val"])
	}
	for _, k := range []string{"fixed_byte_arr", "fixed_uint8_arr", "fixed_uint8_arr_pt"} {
		if s, ok := dto.Metadata[k].(string); !ok || s != "[REDACTED]" {
			t.Fatalf("%s expected \"[REDACTED]\", got %#v", k, dto.Metadata[k])
		}
	}

	// Empty slices preserved without false cycle collision.
	if sA, ok := dto.Metadata["empty_slice_a"].([]any); !ok || len(sA) != 0 {
		t.Fatalf("empty_slice_a expected non-nil empty []any, got %#v", dto.Metadata["empty_slice_a"])
	}
	if sB, ok := dto.Metadata["empty_slice_b"].([]any); !ok || len(sB) != 0 {
		t.Fatalf("empty_slice_b expected non-nil empty []any, got %#v", dto.Metadata["empty_slice_b"])
	}

	// DAG branches both retained.
	for _, k := range []string{"dag_map_1", "dag_map_2"} {
		m, ok := dto.Metadata[k].(map[string]any)
		if !ok || m["note"] != "ok" {
			t.Fatalf("%s expected retained map with note=ok, got %#v", k, dto.Metadata[k])
		}
		if _, hasSecret := m["secret"]; hasSecret {
			t.Fatalf("%s leaked forbidden secret key", k)
		}
	}
	for _, k := range []string{"dag_slice_1", "dag_slice_2"} {
		s, ok := dto.Metadata[k].([]any)
		if !ok || len(s) != 2 || s[0] != "ok" || s[1] != "[REDACTED]" {
			t.Fatalf("%s expected [\"ok\", \"[REDACTED]\"], got %#v", k, dto.Metadata[k])
		}
	}

	if gotBytes, ok := dto.Metadata["named_bytes"].(string); !ok || gotBytes != "prefix [REDACTED] suffix" {
		t.Fatalf("named_bytes expected %q, got %#v", "prefix [REDACTED] suffix", dto.Metadata["named_bytes"])
	}
}
