package harness_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/timreynolds/custodian/test/e2e/harness"
)

func decodeJWTParts(t *testing.T, tok string) (hdr map[string]any, claims map[string]any, signingInput string, sig []byte) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT parts %d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode JWT signature: %v", err)
	}
	return hdr, claims, parts[0] + "." + parts[1], sig
}

func TestHarness_OIDCAndJWT(t *testing.T) {
	oidc := harness.StartMockOIDC(t, "custodian-api")

	// 1. Discovery document
	discResp, err := http.Get(oidc.Issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer discResp.Body.Close()
	if discResp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d, want 200", discResp.StatusCode)
	}
	var disc map[string]any
	if err := json.NewDecoder(discResp.Body).Decode(&disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if disc["issuer"] != oidc.Issuer() {
		t.Fatalf("discovery issuer=%v, want %s", disc["issuer"], oidc.Issuer())
	}
	if disc["jwks_uri"] != oidc.JWKSURL() {
		t.Fatalf("discovery jwks_uri=%v, want %s", disc["jwks_uri"], oidc.JWKSURL())
	}

	// 2. JWKS endpoint -> decode RSA public key
	jwksResp, err := http.Get(oidc.JWKSURL())
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status=%d, want 200", jwksResp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected JWKS keys: %+v", jwks.Keys)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	if err != nil {
		t.Fatalf("decode JWK n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	if err != nil {
		t.Fatalf("decode JWK e: %v", err)
	}
	eInt := int(new(big.Int).SetBytes(eBytes).Int64())
	pubKey := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: eInt}

	// 3. Valid HUMAN token verified with real RSA PKCS1v15
	tok := oidc.MintToken(harness.TokenClaims{
		Kind:    "HUMAN",
		Subject: "user-alice",
		Email:   "alice@example.com",
		Name:    "Alice Dev",
		Groups:  []string{"engineering", "ip-review"},
	})
	hdr, claims, signingInput, sig := decodeJWTParts(t, tok)
	if hdr["kid"] != jwks.Keys[0].Kid {
		t.Fatalf("kid mismatch: got %v, want %s", hdr["kid"], jwks.Keys[0].Kid)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("RSA signature verification failed on valid token: %v", err)
	}
	if claims["sub"] != "user-alice" || claims["iss"] != oidc.Issuer() || claims["aud"] != "custodian-api" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) <= time.Now().Unix() {
		t.Fatalf("expected future exp claim, got %v", claims["exp"])
	}

	// 4. Negative: expired token
	expTok := oidc.MintToken(harness.TokenClaims{
		Kind:      "HUMAN",
		ExpiresAt: time.Now().Add(-10 * time.Minute),
	})
	_, expClaims, _, _ := decodeJWTParts(t, expTok)
	if int64(expClaims["exp"].(float64)) >= time.Now().Unix() {
		t.Fatalf("expected expired token exp in past, got %v", expClaims["exp"])
	}

	// 5. Negative: wrong issuer & audience
	wrongIssAudTok := oidc.MintToken(harness.TokenClaims{
		Issuer:   "https://evil.example.com",
		Audience: []string{"wrong-audience"},
	})
	_, wrongClaims, _, _ := decodeJWTParts(t, wrongIssAudTok)
	if wrongClaims["iss"] == oidc.Issuer() || wrongClaims["aud"] == oidc.Audience() {
		t.Fatalf("expected mismatched iss/aud claims")
	}

	// 6. Negative: rogue key signature fails verification
	rogueTok := oidc.MintToken(harness.TokenClaims{SignWithWrongKey: true})
	_, _, rogueInput, rogueSig := decodeJWTParts(t, rogueTok)
	rogueDigest := sha256.Sum256([]byte(rogueInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, rogueDigest[:], rogueSig); err == nil {
		t.Fatalf("expected RSA verification failure for rogue-key token")
	}

	// 7. Negative: tampered signature fails verification
	tamperedTok := oidc.MintToken(harness.TokenClaims{TamperSignature: true})
	_, _, tampInput, tampSig := decodeJWTParts(t, tamperedTok)
	tampDigest := sha256.Sum256([]byte(tampInput))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, tampDigest[:], tampSig); err == nil {
		t.Fatalf("expected RSA verification failure for tampered token")
	}

	// 8. Outage toggle
	oidc.SetOutage(true)
	outResp, err := http.Get(oidc.JWKSURL())
	if err != nil {
		t.Fatalf("GET jwks during outage: %v", err)
	}
	outResp.Body.Close()
	if outResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 during OIDC outage, got %d", outResp.StatusCode)
	}
	oidc.SetOutage(false)
}

func readAllTarHeaders(t *testing.T, gzBytes []byte) []*tar.Header {
	t.Helper()
	gzr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	var hdrs []*tar.Header
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		hdrs = append(hdrs, h)
	}
	return hdrs
}

func TestHarness_ArchiveDeterminismAndAdversarial(t *testing.T) {
	// 1. Determinism across slice ordering & caller metadata
	entriesA := []harness.TarEntry{
		{Name: "b.txt", Body: []byte("bravo\n"), Mode: 0o644, ModTime: time.Now(), Uid: 501, Gid: 20},
		{Name: "a.txt", Body: []byte("alpha\n"), Mode: 0o644, ModTime: time.Unix(12345, 0), Uid: 999, Gid: 999},
	}
	entriesB := []harness.TarEntry{
		{Name: "a.txt", Body: []byte("alpha\n"), Mode: 0o644},
		{Name: "b.txt", Body: []byte("bravo\n"), Mode: 0o644},
	}
	gzA, sumA := harness.MustBuildTarGz(t, entriesA)
	gzB, sumB := harness.MustBuildTarGz(t, entriesB)
	if sumA != sumB || !bytes.Equal(gzA, gzB) {
		t.Fatalf("BuildTarGz was not deterministic: sumA=%s sumB=%s", sumA, sumB)
	}

	// Varying metadata produces different tar/sha256 for F-11 comparison tests
	_, sumVar := harness.BuildTarGzWithVaryingMeta(entriesB, time.Date(2025, 5, 5, 1, 2, 3, 0, time.UTC), 1000, 1000, true)
	if sumVar == sumA {
		t.Fatalf("expected BuildTarGzWithVaryingMeta to produce distinct archive SHA256")
	}

	// 2. Golden fixture exact verification
	goldenDir := filepath.Join("..", "fixtures", "golden")
	readmeBytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_tree", "README.md"))
	if err != nil {
		t.Fatalf("read golden README.md: %v", err)
	}
	helloBytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_tree", "pkg", "hello", "hello.go"))
	if err != nil {
		t.Fatalf("read golden hello.go: %v", err)
	}
	builtGolden, builtSum := harness.BuildTarGz([]harness.TarEntry{
		{Name: "README.md", Body: readmeBytes, Mode: 0o644},
		{Name: "pkg/hello/hello.go", Body: helloBytes, Mode: 0o644},
	})
	diskGolden, err := os.ReadFile(filepath.Join(goldenDir, "clean_snapshot.tar.gz"))
	if err != nil {
		t.Fatalf("read clean_snapshot.tar.gz: %v", err)
	}
	diskSumBytes, err := os.ReadFile(filepath.Join(goldenDir, "clean_snapshot.sha256"))
	if err != nil {
		t.Fatalf("read clean_snapshot.sha256: %v", err)
	}
	diskSum := strings.TrimSpace(string(diskSumBytes))
	if !bytes.Equal(builtGolden, diskGolden) || builtSum != diskSum {
		t.Fatalf("golden fixture mismatch: builtSum=%s diskSum=%s", builtSum, diskSum)
	}

	// 3. Adversarial headers
	travGZ, _ := harness.BuildPathTraversalArchive(harness.TraversalDotDot)
	if hdrs := readAllTarHeaders(t, travGZ); len(hdrs) != 1 || hdrs[0].Name != harness.TraversalDotDot {
		t.Fatalf("expected raw traversal path %q, got %+v", harness.TraversalDotDot, hdrs)
	}

	symGZ, _ := harness.BuildSymlinkArchive("escape", "/etc/passwd")
	if hdrs := readAllTarHeaders(t, symGZ); len(hdrs) != 1 || hdrs[0].Typeflag != tar.TypeSymlink || hdrs[0].Linkname != "/etc/passwd" {
		t.Fatalf("unexpected symlink headers: %+v", hdrs)
	}

	hardGZ, _ := harness.BuildHardlinkArchive("hard", "target.txt")
	if hdrs := readAllTarHeaders(t, hardGZ); len(hdrs) != 2 || hdrs[0].Typeflag != tar.TypeLink {
		t.Fatalf("unexpected hardlink headers: %+v", hdrs)
	}

	fifoGZ, _ := harness.BuildSpecialFileArchive(tar.TypeFifo, "pipe")
	if hdrs := readAllTarHeaders(t, fifoGZ); len(hdrs) != 1 || hdrs[0].Typeflag != tar.TypeFifo {
		t.Fatalf("unexpected fifo headers: %+v", hdrs)
	}

	subGZ, _ := harness.BuildSubmoduleArchive()
	subHdrs := readAllTarHeaders(t, subGZ)
	if len(subHdrs) != 2 || subHdrs[1].Mode != 0o160000 {
		t.Fatalf("unexpected submodule headers: %+v", subHdrs)
	}

	uniGZ, _ := harness.BuildUnicodeCollisionArchive()
	uniHdrs := readAllTarHeaders(t, uniGZ)
	if len(uniHdrs) != 2 {
		t.Fatalf("expected 2 unicode collision entries, got %d", len(uniHdrs))
	}

	caseGZ, _ := harness.BuildCaseCollisionArchive()
	caseHdrs := readAllTarHeaders(t, caseGZ)
	if len(caseHdrs) != 2 {
		t.Fatalf("expected 2 case collision entries, got %d", len(caseHdrs))
	}

	gitGZ, _ := harness.BuildGitInjectionArchive(entriesB)
	gitEntries, err := harness.ExtractTarGz(gitGZ)
	if err != nil {
		t.Fatalf("ExtractTarGz git injection: %v", err)
	}
	foundHook := false
	for _, e := range gitEntries {
		if e.Name == ".git/hooks/pre-commit" && e.Mode == 0o755 {
			foundHook = true
		}
	}
	if !foundHook {
		t.Fatalf("expected .git/hooks/pre-commit in BuildGitInjectionArchive")
	}

	unsupGZ, _ := harness.BuildUnsupportedTypeArchive('?', "weird.bin")
	gzrUnsup, err := gzip.NewReader(bytes.NewReader(unsupGZ))
	if err != nil {
		t.Fatalf("gzip open unsupported type archive: %v", err)
	}
	trUnsup := tar.NewReader(gzrUnsup)
	hdrUnsup, err := trUnsup.Next()
	_ = gzrUnsup.Close()
	if err != nil || hdrUnsup.Typeflag != '?' {
		t.Fatalf("expected raw unsupported typeflag '?', got hdr=%+v err=%v", hdrUnsup, err)
	}

	// 4. Corrupt archives
	for _, mode := range []harness.CorruptArchiveMode{
		harness.CorruptRandomBytes,
		harness.CorruptTarChecksum,
		harness.CorruptTruncatedGzip,
		harness.CorruptTruncatedTarEntry,
	} {
		corrupt := harness.BuildCorruptTarGz(mode)
		if _, err := harness.ExtractTarGz(corrupt); err == nil {
			t.Fatalf("expected ExtractTarGz error for corrupt mode %s", mode)
		}
	}

	// 5. Gzip bomb
	bombGZ, _ := harness.BuildGzipBomb(2 * 1024 * 1024)
	if len(bombGZ) >= 32*1024 {
		t.Fatalf("expected compressed gzip bomb < 32 KiB, got %d bytes", len(bombGZ))
	}
	gzrBomb, err := gzip.NewReader(bytes.NewReader(bombGZ))
	if err != nil {
		t.Fatalf("open gzip bomb: %v", err)
	}
	defer gzrBomb.Close()
	trBomb := tar.NewReader(gzrBomb)
	if _, err := trBomb.Next(); err != nil {
		t.Fatalf("read bomb tar header: %v", err)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(trBomb, (1<<20)+1))
	if err != nil {
		t.Fatalf("read bomb payload: %v", err)
	}
	if n <= 1<<20 {
		t.Fatalf("expected bomb payload > 1 MiB, got %d", n)
	}
}

func TestHarness_UUIDv7(t *testing.T) {
	validIDs := []string{
		"01933e5a-1234-7abc-8def-0123456789ab",
		"01933e5a-1234-7000-b000-000000000000",
		harness.NewTestUUIDv7(),
	}
	for _, id := range validIDs {
		harness.AssertUUIDv7(t, id)
		if err := harness.ValidateUUIDv7(id); err != nil {
			t.Fatalf("ValidateUUIDv7(%q) unexpected error: %v", id, err)
		}
	}
	harness.AssertUUIDv7Monotonic(t, []string{
		"01933e5a-1234-7abc-8def-0123456789ab",
		harness.NewTestUUIDv7(),
	})

	invalidIDs := []string{
		"550e8400-e29b-41d4-a716-446655440000", // UUIDv4
		"01933e5a-1234-7abc-0def-0123456789ab", // bad variant 0
		"01933e5a-1234-7abc-cdef-0123456789ab", // bad variant c
		"not-a-uuid",
		"01933e5a-1234-7abc-8def-0123456789zz",
		"01933E5A-1234-7ABC-8DEF-0123456789AB", // uppercase rejected
	}
	for _, id := range invalidIDs {
		if err := harness.ValidateUUIDv7(id); err == nil {
			t.Fatalf("ValidateUUIDv7(%q) succeeded, expected error", id)
		}
	}
}

func TestHarness_AuditHashChain(t *testing.T) {
	preimage := func(ev harness.AuditEvent) []byte {
		return []byte(ev.ID + "|" + ev.EventType + "|" + ev.PreviousHash)
	}
	hashOf := func(ev harness.AuditEvent) string {
		return harness.SHA256Hex(preimage(ev))
	}

	t0 := time.Now().UTC().Add(-2 * time.Second)
	e0 := harness.AuditEvent{
		ID:           "01933e5a-1000-7000-8000-000000000001",
		EventType:    "workspace.created",
		PreviousHash: "",
		CreatedAt:    t0,
	}
	e0.EventHash = hashOf(e0)

	e1 := harness.AuditEvent{
		ID:           "01933e5a-2000-7000-8000-000000000002",
		EventType:    "proposal.submitted",
		PreviousHash: e0.EventHash,
		CreatedAt:    t0.Add(time.Second),
	}
	e1.EventHash = hashOf(e1)

	e2 := harness.AuditEvent{
		ID:           "01933e5a-3000-7000-8000-000000000003",
		EventType:    "proposal.published",
		PreviousHash: e1.EventHash,
		CreatedAt:    t0.Add(2 * time.Second),
	}
	e2.EventHash = hashOf(e2)

	events := []harness.AuditEvent{e0, e1, e2}
	harness.VerifyAuditHashChain(t, events)
	harness.VerifyFullAuditHashChainFromGenesis(t, events)
	harness.VerifyAuditHashChainWithDigest(t, events, preimage)

	// Negative 1: broken PreviousHash on e2
	broken := []harness.AuditEvent{e0, e1, e2}
	broken[2].PreviousHash = strings.Repeat("a", 64)
	if err := harness.ValidateAuditHashChain(broken); err == nil {
		t.Fatalf("expected ValidateAuditHashChain failure for broken previous_hash")
	}

	// Negative 2: malformed EventHash on e1
	badHex := []harness.AuditEvent{e0, e1, e2}
	badHex[1].EventHash = "not-sha256"
	if err := harness.ValidateAuditHashChain(badHex); err == nil {
		t.Fatalf("expected ValidateAuditHashChain failure for malformed event_hash")
	}

	// Negative 3: reordered events [e0, e2, e1]
	if err := harness.ValidateAuditHashChain([]harness.AuditEvent{e0, e2, e1}); err == nil {
		t.Fatalf("expected ValidateAuditHashChain failure for reordered events")
	}

	// Negative 4: empty event hash
	emptyHash := []harness.AuditEvent{e0}
	emptyHash[0].EventHash = ""
	if err := harness.ValidateAuditHashChain(emptyHash); err == nil {
		t.Fatalf("expected ValidateAuditHashChain failure for empty event_hash")
	}
}

type spyTB struct {
	testing.TB
	failed bool
	msg    string
}

func (s *spyTB) Helper() {}
func (s *spyTB) Fatal(args ...any) {
	s.failed = true
	s.msg = strings.TrimSpace(strings.Join([]string{func() string {
		var b strings.Builder
		for i, a := range args {
			if i > 0 {
				b.WriteByte(' ')
			}
			if err, ok := a.(error); ok {
				b.WriteString(err.Error())
			} else if str, ok := a.(string); ok {
				b.WriteString(str)
			}
		}
		return b.String()
	}()}, ""))
	runtime.Goexit()
}
func (s *spyTB) Fatalf(format string, args ...any) {
	s.failed = true
	s.msg = format
	runtime.Goexit()
}

func assertFramingFails(t *testing.T, gw *harness.MockGateway, marker string, systemForbidden bool, desc string) {
	t.Helper()
	if err := gw.CheckPromptUntrustedFraming(marker, systemForbidden); err == nil {
		t.Fatalf("%s: expected CheckPromptUntrustedFraming error, got nil", desc)
	}
	spy := &spyTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		gw.AssertPromptUntrustedFraming(spy, marker, systemForbidden)
	}()
	<-done
	if !spy.failed {
		t.Fatalf("%s: expected AssertPromptUntrustedFraming to fail TB", desc)
	}
}

func TestHarness_MockGateway(t *testing.T) {
	gw := harness.NewMockGateway(t, nil)

	// 1. Clean mode with zero evidence_ids emits findings: [] and CLEAR disposition
	reqBody := `{"model_route":"approved-code-review","messages":[{"role":"system","content":"You are a reviewer"},{"role":"user","content":"untrusted code"}]}`
	resp, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST gateway: %v", err)
	}
	var payload harness.StageBAssessmentPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		resp.Body.Close()
		t.Fatalf("decode gateway response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || payload.Disposition != "CLEAR" || len(payload.Findings) != 0 {
		t.Fatalf("unexpected clean payload: status=%d payload=%+v", resp.StatusCode, payload)
	}
	gw.AssertNoSecretInPrompts(t, "AKIAIOSFODNN7EXAMPLE")
	gw.AssertNoRouteCalled(t, "unrestricted-public-llm")
	gw.AssertPromptUntrustedFraming(t, "untrusted code", true)

	// 1b. Proposal/workspace/artifact UUIDv7s in Clean mode must NOT be echoed as evidence_ids
	reqWithMetaUUID := `{"proposal_id":"01933e5a-1234-7abc-8def-0123456789ab","workspace_id":"01933e5a-1234-7abc-8def-0123456789ac","findings":[]}`
	respMeta, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(reqWithMetaUUID))
	if err != nil {
		t.Fatalf("POST gateway meta UUID: %v", err)
	}
	var pMeta harness.StageBAssessmentPayload
	if err := json.NewDecoder(respMeta.Body).Decode(&pMeta); err != nil {
		respMeta.Body.Close()
		t.Fatalf("decode meta UUID response: %v", err)
	}
	respMeta.Body.Close()
	if len(pMeta.Findings) != 0 {
		t.Fatalf("expected findings: [] when only proposal_id/workspace_id UUIDv7s are present, got %+v", pMeta.Findings)
	}

	// 1c. AssertPromptUntrustedFraming catches missing marker when Messages is empty
	respEmptyMsgs, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(`{"diff":"clean diff without marker"}`))
	if err != nil {
		t.Fatalf("POST empty messages: %v", err)
	}
	respEmptyMsgs.Body.Close()
	assertFramingFails(t, gw, "MISSING_MARKER", true, "empty messages missing marker")

	// 1d. AssertPromptUntrustedFraming catches marker outside Messages
	respOutside, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(`{"extra":"MARKER_OUTSIDE_MESSAGES","messages":[{"role":"system","content":"sys"},{"role":"user","content":"ordinary diff"}]}`))
	if err != nil {
		t.Fatalf("POST marker outside messages: %v", err)
	}
	respOutside.Body.Close()
	assertFramingFails(t, gw, "MARKER_OUTSIDE_MESSAGES", true, "marker outside messages[]")

	// 2. HighRiskReview auto-echoes caller evidence_ids (and ignores proposal_id UUIDv7)
	gw.SetMode(harness.GatewayModeHighRiskReview)
	reqEv := `{"proposal_id":"01933e5a-0000-7000-8000-000000000001","model_route":"approved-code-review","evidence_ids":["finding_101","01933e5a-1234-7abc-8def-0123456789ab"]}`
	resp2, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(reqEv))
	if err != nil {
		t.Fatalf("POST gateway high risk: %v", err)
	}
	var p2 harness.StageBAssessmentPayload
	_ = json.NewDecoder(resp2.Body).Decode(&p2)
	resp2.Body.Close()
	if p2.Risk != "HIGH" || p2.Disposition != "REVIEW" || len(p2.Findings) != 1 || len(p2.Findings[0].EvidenceIDs) != 2 {
		t.Fatalf("expected 2 echoed evidence_ids (without proposal_id), got %+v", p2)
	}

	// 3. INDETERMINATE mode
	gw.SetMode(harness.GatewayModeIndeterminate)
	resp3, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST indeterminate: %v", err)
	}
	var p3 harness.StageBAssessmentPayload
	_ = json.NewDecoder(resp3.Body).Decode(&p3)
	resp3.Body.Close()
	if p3.Disposition != "INDETERMINATE" || p3.Risk != "NONE" {
		t.Fatalf("expected INDETERMINATE disposition with NONE risk, got %+v", p3)
	}

	// 4. Malformed JSON mode
	gw.SetMode(harness.GatewayModeMalformedJSON)
	resp4, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST malformed: %v", err)
	}
	raw4, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	var tmp map[string]any
	if json.Unmarshal(raw4, &tmp) == nil {
		t.Fatalf("expected malformed JSON, got valid: %s", string(raw4))
	}

	// 5. Outage 503 followed by queued 200 recovery
	gw.Enqueue(
		harness.GatewayProgram{Mode: harness.GatewayModeOutage503},
		harness.GatewayProgram{Mode: harness.GatewayModeClean},
	)
	resp5, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST outage: %v", err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp5.StatusCode)
	}
	resp6, err := http.Post(gw.URL()+"/v1/assess", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST recovery: %v", err)
	}
	resp6.Body.Close()
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 recovery, got %d", resp6.StatusCode)
	}
}

func TestHarness_StubScannerController(t *testing.T) {
	sc := harness.NewStubScannerController(t)
	tmpOut := t.TempDir()
	env := sc.EnvVars(os.Environ(), harness.DefaultContracts())
	t.Setenv("PATH", sc.BinDir()+string(os.PathListSeparator)+os.Getenv("PATH"))

	runScanner := func(name harness.ScannerName, args ...string) (int, string, string) {
		cmd := exec.Command(string(name), args...)
		cmd.Env = env
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("exec %s: %v", name, err)
			}
		}
		return code, outBuf.String(), errBuf.String()
	}

	// 1. Clean mode across all 4 binaries
	for _, s := range []harness.ScannerName{harness.ScannerGitleaks, harness.ScannerScanCode, harness.ScannerSemgrep, harness.ScannerTrivy} {
		code, verOut, _ := runScanner(s, "--version")
		if code != 0 || strings.TrimSpace(verOut) == "" {
			t.Fatalf("%s --version failed: code=%d out=%q", s, code, verOut)
		}
	}
	outGL := filepath.Join(tmpOut, "gitleaks-clean.json")
	if code, _, _ := runScanner(harness.ScannerGitleaks, "detect", "--source", tmpOut, "--report-path", outGL); code != 0 {
		t.Fatalf("gitleaks clean exit=%d", code)
	}
	bGL, _ := os.ReadFile(outGL)
	if strings.TrimSpace(string(bGL)) != "[]" {
		t.Fatalf("expected empty gitleaks array, got %s", string(bGL))
	}

	// 2. Findings mode across all 4 binaries
	sc.Set(harness.ScannerGitleaks, harness.ScannerBehavior{Mode: harness.ScannerModeSecretFinding, SecretValue: "AKIAIOSFODNN7EXAMPLE"})
	sc.Set(harness.ScannerScanCode, harness.ScannerBehavior{Mode: harness.ScannerModeProhibitedLicense, LicenseSPDX: "AGPL-3.0-only"})
	sc.Set(harness.ScannerSemgrep, harness.ScannerBehavior{Mode: harness.ScannerModeSASTFinding})
	sc.Set(harness.ScannerTrivy, harness.ScannerBehavior{Mode: harness.ScannerModeVulnFinding})

	outGLHit := filepath.Join(tmpOut, "gitleaks-hit.json")
	if code, _, _ := runScanner(harness.ScannerGitleaks, "detect", "--source", tmpOut, "--report-path", outGLHit, "--exit-code", "0"); code != 0 {
		t.Fatalf("gitleaks with --exit-code 0 should return 0, got %d", code)
	}
	glHit, _ := os.ReadFile(outGLHit)
	if !strings.Contains(string(glHit), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("expected secret in gitleaks stub report: %s", string(glHit))
	}

	outSC := filepath.Join(tmpOut, "scancode-hit.json")
	if code, _, _ := runScanner(harness.ScannerScanCode, "--license", "--json-pp", outSC, tmpOut); code != 0 {
		t.Fatalf("scancode finding exit=%d", code)
	}
	scHit, _ := os.ReadFile(outSC)
	if !strings.Contains(string(scHit), "AGPL-3.0-only") {
		t.Fatalf("expected AGPL-3.0-only in scancode report: %s", string(scHit))
	}

	outSG := filepath.Join(tmpOut, "semgrep-hit.json")
	if code, _, _ := runScanner(harness.ScannerSemgrep, "scan", "--json", "--output", outSG, tmpOut); code != 0 {
		t.Fatalf("semgrep finding exit=%d", code)
	}
	sgHit, _ := os.ReadFile(outSG)
	if !strings.Contains(string(sgHit), "go.lang.security.audit.unsafe-exec") {
		t.Fatalf("expected rule in semgrep report: %s", string(sgHit))
	}

	// 2b. Semgrep boolean --json with a regular file prints JSON to stdout and does NOT overwrite target file
	sampleGoPath := filepath.Join(tmpOut, "temp_file.go")
	const sampleGoSrc = "package sample\n\nfunc Hello() string { return \"world\" }\n"
	if err := os.WriteFile(sampleGoPath, []byte(sampleGoSrc), 0o644); err != nil {
		t.Fatalf("write sample.go: %v", err)
	}
	codeSGStdout, outSGStdout, errSGStdout := runScanner(harness.ScannerSemgrep, "scan", "--json", sampleGoPath)
	if codeSGStdout != 0 {
		t.Fatalf("semgrep scan --json <file> exit=%d stderr=%s", codeSGStdout, errSGStdout)
	}
	afterSample, err := os.ReadFile(sampleGoPath)
	if err != nil || string(afterSample) != sampleGoSrc {
		t.Fatalf("semgrep --json clobbered target file! got=%q want=%q err=%v", string(afterSample), sampleGoSrc, err)
	}
	var sgStdoutJSON map[string]any
	if err := json.Unmarshal([]byte(outSGStdout), &sgStdoutJSON); err != nil {
		t.Fatalf("expected valid JSON on semgrep stdout, got %q err=%v", outSGStdout, err)
	}

	outTV := filepath.Join(tmpOut, "trivy-hit.json")
	if code, _, _ := runScanner(harness.ScannerTrivy, "fs", "--format", "json", "--output", outTV, tmpOut); code != 0 {
		t.Fatalf("trivy finding exit=%d", code)
	}
	tvHit, _ := os.ReadFile(outTV)
	if !strings.Contains(string(tvHit), "CVE-2026-0001") {
		t.Fatalf("expected CVE in trivy report: %s", string(tvHit))
	}

	// 3. FilesSkipped > 0 mode (RG-05)
	sc.Set(harness.ScannerSemgrep, harness.ScannerBehavior{Mode: harness.ScannerModeFilesSkipped, SkippedPaths: []string{"huge.min.js"}})
	outSGSkip := filepath.Join(tmpOut, "semgrep-skip.json")
	if code, _, _ := runScanner(harness.ScannerSemgrep, "scan", "--json", "--output", outSGSkip, tmpOut); code != 0 {
		t.Fatalf("semgrep skipped exit=%d", code)
	}
	sgSkip, _ := os.ReadFile(outSGSkip)
	if !strings.Contains(string(sgSkip), "huge.min.js") {
		t.Fatalf("expected skipped path huge.min.js in semgrep report: %s", string(sgSkip))
	}

	// 4. Crash mode (non-zero exit + diagnostic stderr)
	sc.Set(harness.ScannerTrivy, harness.ScannerBehavior{Mode: harness.ScannerModeCrash, ExitCode: 2, StderrMsg: "trivy db corrupted"})
	codeCrash, _, errCrash := runScanner(harness.ScannerTrivy, "fs", "--format", "json", tmpOut)
	if codeCrash < 2 || !strings.Contains(errCrash, "trivy db corrupted") {
		t.Fatalf("expected crash exit>=2 and stderr, got code=%d err=%q", codeCrash, errCrash)
	}

	for _, s := range []harness.ScannerName{harness.ScannerGitleaks, harness.ScannerScanCode, harness.ScannerSemgrep, harness.ScannerTrivy} {
		sc.AssertInvoked(t, s)
	}
}

func TestHarness_BareGitAndMockGitHub(t *testing.T) {
	git := harness.NewBareGitHelper(t, "")
	repo, err := git.InitSeededRepo("acme", "service", map[string]string{
		"README.md": "# acme/service\n",
	})
	if err != nil {
		t.Fatalf("InitSeededRepo: %v", err)
	}
	if len(repo.HeadSHA) != 40 {
		t.Fatalf("expected 40-hex HeadSHA, got %q", repo.HeadSHA)
	}

	propSHA, err := git.CommitToBranch("acme/service", "custodian/prop-001", harness.CommitSpec{
		Files: map[string]string{"main.go": "package main\n"},
		Author: harness.GitIdentity{
			Name:  "Alice Developer",
			Email: "alice@example.com",
		},
		Committer: harness.GitIdentity{
			Name:  "Custodian",
			Email: "custodian@example.com",
		},
		Message: "Add main.go\n\nCustodian-Proposal: prop-001\nCustodian-Workspace: ws-001\nAgent-Assisted: true",
	})
	if err != nil {
		t.Fatalf("CommitToBranch: %v", err)
	}
	info, err := git.InspectCommit("acme/service", propSHA)
	if err != nil {
		t.Fatalf("InspectCommit: %v", err)
	}
	if info.AuthorEmail != "alice@example.com" || info.CommitterName != "Custodian" {
		t.Fatalf("unexpected commit attribution: %+v", info)
	}
	if len(info.Parents) != 1 || info.Parents[0] != repo.HeadSHA {
		t.Fatalf("unexpected commit parents: %+v (want [%s])", info.Parents, repo.HeadSHA)
	}
	if got := info.Trailers["Custodian-Proposal"]; len(got) != 1 || got[0] != "prop-001" {
		t.Fatalf("missing Custodian-Proposal trailer: %+v", info.Trailers)
	}
	if got := info.Trailers["Agent-Assisted"]; len(got) != 1 || got[0] != "true" {
		t.Fatalf("missing Agent-Assisted trailer: %+v", info.Trailers)
	}

	// MockGitHub REST + read/write token separation + Smart HTTP
	gh := harness.StartMockGitHub(t, git, 101, 202)

	mintToken := func(appID int64, pemStr string, instID int64) string {
		jwtTok, err := harness.SignAppJWT(appID, pemStr, time.Now().UTC())
		if err != nil {
			t.Fatalf("SignAppJWT(%d): %v", appID, err)
		}
		req, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"app/installations/"+strconv.FormatInt(instID, 10)+"/access_tokens", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+jwtTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("mint GitHub token: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("mint GitHub token status=%d body=%s", resp.StatusCode, string(body))
		}
		var out struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out.Token
	}

	readTok := mintToken(gh.ReadAppID(), gh.ReadAppPrivateKeyPEM(), repo.InstallationID)
	writeTok := mintToken(gh.WriteAppID(), gh.WriteAppPrivateKeyPEM(), repo.InstallationID)
	if !strings.HasPrefix(readTok, "ghs_read_") || !strings.HasPrefix(writeTok, "ghs_write_") {
		t.Fatalf("unexpected minted tokens: read=%q write=%q", readTok, writeTok)
	}

	// Read App ID (101) requesting write/pull_requests permissions is rejected with 403
	readJWT, err := harness.SignAppJWT(gh.ReadAppID(), gh.ReadAppPrivateKeyPEM(), time.Now().UTC())
	if err != nil {
		t.Fatalf("SignAppJWT(read): %v", err)
	}
	escReq, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"app/installations/"+strconv.FormatInt(repo.InstallationID, 10)+"/access_tokens", strings.NewReader(`{"permissions":{"contents":"write","pull_requests":"write"}}`))
	escReq.Header.Set("Authorization", "Bearer "+readJWT)
	escResp, err := http.DefaultClient.Do(escReq)
	if err != nil {
		t.Fatalf("POST readApp write escalation: %v", err)
	}
	escResp.Body.Close()
	if escResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when readAppID requests write permissions, got %d", escResp.StatusCode)
	}

	// Unauthenticated POST /pulls is rejected with 401
	prBody := `{"title":"Prop 1","head":"custodian/prop-001","base":"main"}`
	unauthPRReq, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"repos/acme/service/pulls", strings.NewReader(prBody))
	unauthPRResp, err := http.DefaultClient.Do(unauthPRReq)
	if err != nil {
		t.Fatalf("POST pulls (unauth): %v", err)
	}
	unauthPRResp.Body.Close()
	if unauthPRResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST /pulls, got %d", unauthPRResp.StatusCode)
	}

	// Read token GET ref succeeds
	refReq, _ := http.NewRequest(http.MethodGet, gh.BaseAPIURL()+"repos/acme/service/git/ref/heads/main", nil)
	refReq.Header.Set("Authorization", "Bearer "+readTok)
	refResp, err := http.DefaultClient.Do(refReq)
	if err != nil {
		t.Fatalf("GET git ref: %v", err)
	}
	refResp.Body.Close()
	if refResp.StatusCode != http.StatusOK {
		t.Fatalf("GET git ref status=%d, want 200", refResp.StatusCode)
	}

	// Read token POST /pulls rejected with 403
	badPRReq, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"repos/acme/service/pulls", strings.NewReader(prBody))
	badPRReq.Header.Set("Authorization", "Bearer "+readTok)
	badPRResp, err := http.DefaultClient.Do(badPRReq)
	if err != nil {
		t.Fatalf("POST pulls (read token): %v", err)
	}
	badPRResp.Body.Close()
	if badPRResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only token creating PR, got %d", badPRResp.StatusCode)
	}

	// Write token POST /pulls succeeds and tracks PRCount == 1
	goodPRReq, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"repos/acme/service/pulls", strings.NewReader(prBody))
	goodPRReq.Header.Set("Authorization", "Bearer "+writeTok)
	goodPRResp, err := http.DefaultClient.Do(goodPRReq)
	if err != nil {
		t.Fatalf("POST pulls (write token): %v", err)
	}
	goodPRResp.Body.Close()
	if goodPRResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for write token creating PR, got %d", goodPRResp.StatusCode)
	}
	if gh.PRCount("acme/service") != 1 {
		t.Fatalf("expected PRCount=1, got %d", gh.PRCount("acme/service"))
	}

	// Smart HTTP git clone + push enforcement
	wtDir := t.TempDir()
	runGit := func(dir string, args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=/dev/null"}, args...)...)
		if dir != "" {
			cmd.Dir = dir
		}
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
			"GIT_AUTHOR_NAME=Alice",
			"GIT_AUTHOR_EMAIL=alice@example.com",
			"GIT_COMMITTER_NAME=Custodian",
			"GIT_COMMITTER_EMAIL=custodian@example.com",
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	readURL := strings.Replace(gh.CloneURL("acme/service"), "http://", "http://x-access-token:"+readTok+"@", 1)
	writeURL := strings.Replace(gh.CloneURL("acme/service"), "http://", "http://x-access-token:"+writeTok+"@", 1)
	unauthURL := gh.CloneURL("acme/service")

	if out, err := runGit("", "clone", readURL, wtDir); err != nil {
		t.Fatalf("Smart HTTP git clone with read token failed: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtDir, "feature.txt"), []byte("hello smart http\n"), 0o644); err != nil {
		t.Fatalf("write feature.txt: %v", err)
	}
	if out, err := runGit(wtDir, "add", "feature.txt"); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	if out, err := runGit(wtDir, "commit", "-m", "Add feature.txt"); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	beforeReadPushes := len(gh.PushAttempts())
	if out, err := runGit(wtDir, "push", readURL, "HEAD:refs/heads/custodian/read-rejected"); err == nil {
		t.Fatalf("expected Smart HTTP git push with read token to fail, succeeded: %s", out)
	}
	readPushes := gh.PushAttempts()[beforeReadPushes:]
	if len(readPushes) == 0 || readPushes[len(readPushes)-1].Allowed {
		t.Fatalf("expected Allowed=false PushAttempt for read-token push, got %+v", readPushes)
	}

	beforeUnauthChallenges := len(gh.AuthChallenges())
	beforeUnauthPushes := len(gh.PushAttempts())
	if out, err := runGit(wtDir, "push", unauthURL, "HEAD:refs/heads/custodian/unauth-rejected"); err == nil {
		t.Fatalf("expected Smart HTTP unauthenticated git push to fail, succeeded: %s", out)
	}
	unauthChallenges := gh.AuthChallenges()[beforeUnauthChallenges:]
	if len(unauthChallenges) == 0 || unauthChallenges[0].StatusCode != http.StatusUnauthorized || unauthChallenges[0].Service != "git-receive-pack" || unauthChallenges[0].Repo != "acme/service" {
		t.Fatalf("expected 401 git-receive-pack AuthChallenge for unauthenticated push, got %+v", unauthChallenges)
	}
	if len(gh.PushAttempts()) != beforeUnauthPushes {
		t.Fatalf("expected unauthenticated GET /info/refs 401 not to pollute PushAttempts, got %+v", gh.PushAttempts()[beforeUnauthPushes:])
	}

	beforeWritePushes := len(gh.PushAttempts())
	if out, err := runGit(wtDir, "push", writeURL, "HEAD:refs/heads/custodian/write-ok"); err != nil {
		t.Fatalf("expected Smart HTTP git push with write token to succeed: %v\n%s", err, out)
	}
	exists, err := git.BranchExists("acme/service", "custodian/write-ok")
	if err != nil || !exists {
		t.Fatalf("expected branch custodian/write-ok in bare repo (exists=%v err=%v)", exists, err)
	}
	writePushes := gh.PushAttempts()[beforeWritePushes:]
	sawAllowedWrite := false
	for _, pa := range writePushes {
		if !pa.Allowed {
			t.Fatalf("expected zero Allowed=false PushAttempts during valid write-token push, got %+v", writePushes)
		}
		if pa.Ref == "refs/heads/custodian/write-ok" && pa.Allowed && pa.Token == writeTok {
			sawAllowedWrite = true
		}
	}
	if !sawAllowedWrite {
		t.Fatalf("expected allowed PushAttempt recorded for refs/heads/custodian/write-ok, got %+v", writePushes)
	}

	// Outage 503 + recovery
	gh.SetOutage("GET", "/repos/acme/service", http.StatusServiceUnavailable, 1)
	outResp, err := http.Get(gh.BaseAPIURL() + "repos/acme/service")
	if err != nil {
		t.Fatalf("GET repo outage: %v", err)
	}
	outResp.Body.Close()
	if outResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 outage, got %d", outResp.StatusCode)
	}
	recResp, err := http.Get(gh.BaseAPIURL() + "repos/acme/service")
	if err != nil {
		t.Fatalf("GET repo recovery: %v", err)
	}
	recResp.Body.Close()
	if recResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after 1-shot outage, got %d", recResp.StatusCode)
	}

	// Force-push detaches original HeadSHA
	newMainSHA, err := git.ForcePushBranch("acme/service", "main", harness.CommitSpec{
		Files:   map[string]string{"README.md": "# rewritten\n"},
		Message: "Force pushed main",
	})
	if err != nil {
		t.Fatalf("ForcePushBranch: %v", err)
	}
	if newMainSHA == repo.HeadSHA {
		t.Fatalf("expected force push to rewrite main SHA")
	}
	resolvedMain, err := git.ResolveRef("acme/service", "refs/heads/main")
	if err != nil || resolvedMain != newMainSHA {
		t.Fatalf("ResolveRef after force push=%q err=%v, want %q", resolvedMain, err, newMainSHA)
	}

	// Server-rejected non-fast-forward push (receive.denyNonFastForwards=true + git push --force)
	// must record Allowed=false even though git receive-pack --stateless-rpc exits 0.
	if out, err := runGit(repo.BarePath, "config", "receive.denyNonFastForwards", "true"); err != nil {
		t.Fatalf("git config receive.denyNonFastForwards: %v\n%s", err, out)
	}
	if out, err := runGit(wtDir, "checkout", "--orphan", "orphan-nonff"); err != nil {
		t.Fatalf("git checkout --orphan: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtDir, "orphan.txt"), []byte("divergent\n"), 0o644); err != nil {
		t.Fatalf("write orphan.txt: %v", err)
	}
	if out, err := runGit(wtDir, "add", "orphan.txt"); err != nil {
		t.Fatalf("git add orphan.txt: %v\n%s", err, out)
	}
	if out, err := runGit(wtDir, "commit", "-m", "Orphan divergent commit"); err != nil {
		t.Fatalf("git commit orphan: %v\n%s", err, out)
	}
	beforeNonFF := len(gh.PushAttempts())
	if out, err := runGit(wtDir, "push", "--force", writeURL, "HEAD:refs/heads/main"); err == nil {
		t.Fatalf("expected server-rejected non-fast-forward git push --force to fail, succeeded: %s", out)
	}
	nonFFPushes := gh.PushAttempts()[beforeNonFF:]
	sawRejectedMain := false
	for _, pa := range nonFFPushes {
		if pa.Allowed {
			t.Fatalf("expected zero Allowed=true PushAttempts for server-rejected non-FF push, got %+v", nonFFPushes)
		}
		if pa.Ref == "refs/heads/main" && !pa.Allowed && pa.Token == writeTok && pa.Stage == "receive_pack" {
			sawRejectedMain = true
		}
	}
	if !sawRejectedMain {
		t.Fatalf("expected Allowed=false PushAttempt for rejected refs/heads/main push, got %+v", nonFFPushes)
	}
	afterRejectedMain, err := git.ResolveRef("acme/service", "refs/heads/main")
	if err != nil || afterRejectedMain != newMainSHA {
		t.Fatalf("expected refs/heads/main to remain at %q after rejected push, got %q (err=%v)", newMainSHA, afterRejectedMain, err)
	}

	// Multi-ref push (2 refs: 1st accepted, 2nd rejected non-FF) must preserve exact ref names
	// (no trailing 0000PACK) and record per-ref Allowed flags accurately.
	if _, err := git.CommitToBranch("acme/service", "feat-a", harness.CommitSpec{
		Files:   map[string]string{"feat-a.txt": "seed a\n"},
		Message: "Seed feat-a",
	}); err != nil {
		t.Fatalf("CommitToBranch feat-a: %v", err)
	}
	origFeatB, err := git.CommitToBranch("acme/service", "feat-b", harness.CommitSpec{
		Files:   map[string]string{"feat-b.txt": "seed b\n"},
		Message: "Seed feat-b",
	})
	if err != nil {
		t.Fatalf("CommitToBranch feat-b: %v", err)
	}

	wtMulti := t.TempDir()
	if out, err := runGit("", "clone", writeURL, wtMulti); err != nil {
		t.Fatalf("clone for multi-ref test failed: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "checkout", "-b", "feat-a", "origin/feat-a"); err != nil {
		t.Fatalf("checkout feat-a: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtMulti, "feat-a-2.txt"), []byte("advance a\n"), 0o644); err != nil {
		t.Fatalf("write feat-a-2.txt: %v", err)
	}
	if out, err := runGit(wtMulti, "add", "feat-a-2.txt"); err != nil {
		t.Fatalf("git add feat-a-2.txt: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "commit", "-m", "Advance feat-a"); err != nil {
		t.Fatalf("git commit feat-a: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "checkout", "--orphan", "bad-feat-b"); err != nil {
		t.Fatalf("checkout --orphan bad-feat-b: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtMulti, "bad-b.txt"), []byte("divergent b\n"), 0o644); err != nil {
		t.Fatalf("write bad-b.txt: %v", err)
	}
	if out, err := runGit(wtMulti, "add", "bad-b.txt"); err != nil {
		t.Fatalf("git add bad-b.txt: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "commit", "-m", "Divergent feat-b"); err != nil {
		t.Fatalf("git commit bad-feat-b: %v\n%s", err, out)
	}

	beforeTwoRef := len(gh.PushAttempts())
	if out, err := runGit(wtMulti, "push", "--force", writeURL, "feat-a:refs/heads/feat-a", "bad-feat-b:refs/heads/feat-b"); err == nil {
		t.Fatalf("expected 2-ref push with non-FF 2nd ref to fail, succeeded: %s", out)
	}
	twoRefPushes := gh.PushAttempts()[beforeTwoRef:]
	if len(twoRefPushes) != 2 {
		t.Fatalf("expected 2 PushAttempts for 2-ref push, got %d: %+v", len(twoRefPushes), twoRefPushes)
	}
	if twoRefPushes[0].Ref != "refs/heads/feat-a" || !twoRefPushes[0].Allowed || twoRefPushes[0].Stage != "receive_pack" {
		t.Fatalf("unexpected 1st PushAttempt in 2-ref push: %+v", twoRefPushes[0])
	}
	if twoRefPushes[1].Ref != "refs/heads/feat-b" || twoRefPushes[1].Allowed || twoRefPushes[1].Stage != "receive_pack" {
		t.Fatalf("unexpected 2nd PushAttempt in 2-ref push: %+v", twoRefPushes[1])
	}
	if gotFeatB, err := git.ResolveRef("acme/service", "refs/heads/feat-b"); err != nil || gotFeatB != origFeatB {
		t.Fatalf("expected refs/heads/feat-b unchanged at %q, got %q (err=%v)", origFeatB, gotFeatB, err)
	}

	// Multi-ref push (3 refs: accepted + rejected non-FF + accepted) must record all 3 exact refs
	// with accurate per-ref Allowed flags (true, false, true).
	if _, err := git.CommitToBranch("acme/service", "feat-1", harness.CommitSpec{
		Files:   map[string]string{"feat-1.txt": "seed 1\n"},
		Message: "Seed feat-1",
	}); err != nil {
		t.Fatalf("CommitToBranch feat-1: %v", err)
	}
	origFeat2, err := git.CommitToBranch("acme/service", "feat-2", harness.CommitSpec{
		Files:   map[string]string{"feat-2.txt": "seed 2\n"},
		Message: "Seed feat-2",
	})
	if err != nil {
		t.Fatalf("CommitToBranch feat-2: %v", err)
	}
	if _, err := git.CommitToBranch("acme/service", "feat-3", harness.CommitSpec{
		Files:   map[string]string{"feat-3.txt": "seed 3\n"},
		Message: "Seed feat-3",
	}); err != nil {
		t.Fatalf("CommitToBranch feat-3: %v", err)
	}
	if out, err := runGit(wtMulti, "fetch", "origin"); err != nil {
		t.Fatalf("git fetch origin: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "checkout", "-b", "feat-1", "origin/feat-1"); err != nil {
		t.Fatalf("checkout feat-1: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtMulti, "feat-1-2.txt"), []byte("advance 1\n"), 0o644); err != nil {
		t.Fatalf("write feat-1-2.txt: %v", err)
	}
	if out, err := runGit(wtMulti, "add", "feat-1-2.txt"); err != nil {
		t.Fatalf("git add feat-1-2.txt: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "commit", "-m", "Advance feat-1"); err != nil {
		t.Fatalf("git commit feat-1: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "checkout", "--orphan", "bad-feat-2"); err != nil {
		t.Fatalf("checkout --orphan bad-feat-2: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtMulti, "bad-2.txt"), []byte("divergent 2\n"), 0o644); err != nil {
		t.Fatalf("write bad-2.txt: %v", err)
	}
	if out, err := runGit(wtMulti, "add", "bad-2.txt"); err != nil {
		t.Fatalf("git add bad-2.txt: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "commit", "-m", "Divergent feat-2"); err != nil {
		t.Fatalf("git commit bad-feat-2: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "checkout", "-b", "feat-3", "origin/feat-3"); err != nil {
		t.Fatalf("checkout feat-3: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wtMulti, "feat-3-2.txt"), []byte("advance 3\n"), 0o644); err != nil {
		t.Fatalf("write feat-3-2.txt: %v", err)
	}
	if out, err := runGit(wtMulti, "add", "feat-3-2.txt"); err != nil {
		t.Fatalf("git add feat-3-2.txt: %v\n%s", err, out)
	}
	if out, err := runGit(wtMulti, "commit", "-m", "Advance feat-3"); err != nil {
		t.Fatalf("git commit feat-3: %v\n%s", err, out)
	}

	beforeThreeRef := len(gh.PushAttempts())
	if out, err := runGit(wtMulti, "push", "--force", writeURL,
		"feat-1:refs/heads/feat-1",
		"bad-feat-2:refs/heads/feat-2",
		"feat-3:refs/heads/feat-3",
	); err == nil {
		t.Fatalf("expected 3-ref push with non-FF 2nd ref to fail, succeeded: %s", out)
	}
	threeRefPushes := gh.PushAttempts()[beforeThreeRef:]
	if len(threeRefPushes) != 3 {
		t.Fatalf("expected 3 PushAttempts for 3-ref push, got %d: %+v", len(threeRefPushes), threeRefPushes)
	}
	if threeRefPushes[0].Ref != "refs/heads/feat-1" || !threeRefPushes[0].Allowed || threeRefPushes[0].Stage != "receive_pack" {
		t.Fatalf("unexpected 1st PushAttempt in 3-ref push: %+v", threeRefPushes[0])
	}
	if threeRefPushes[1].Ref != "refs/heads/feat-2" || threeRefPushes[1].Allowed || threeRefPushes[1].Stage != "receive_pack" {
		t.Fatalf("unexpected 2nd PushAttempt in 3-ref push: %+v", threeRefPushes[1])
	}
	if threeRefPushes[2].Ref != "refs/heads/feat-3" || !threeRefPushes[2].Allowed || threeRefPushes[2].Stage != "receive_pack" {
		t.Fatalf("unexpected 3rd PushAttempt in 3-ref push: %+v", threeRefPushes[2])
	}
	if gotFeat2, err := git.ResolveRef("acme/service", "refs/heads/feat-2"); err != nil || gotFeat2 != origFeat2 {
		t.Fatalf("expected refs/heads/feat-2 unchanged at %q, got %q (err=%v)", origFeat2, gotFeat2, err)
	}

	// Raw POST /git-receive-pack without report-status and with a corrupt packfile must record Allowed=false.
	noCapsCmd := strings.Repeat("0", 40) + " " + newMainSHA + " refs/heads/corrupt-nocaps\n"
	noCapsPayload := fmt.Sprintf("%04x%s0000PACK\x00\x00\x00\x02\x00\x00\x00\x01corrupt_truncated_bytes", len(noCapsCmd)+4, noCapsCmd)
	noCapsReq, _ := http.NewRequest(http.MethodPost, gh.CloneURL("acme/service")+"/git-receive-pack", strings.NewReader(noCapsPayload))
	noCapsReq.SetBasicAuth("x-access-token", writeTok)
	noCapsReq.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	beforeNoCaps := len(gh.PushAttempts())
	noCapsResp, err := http.DefaultClient.Do(noCapsReq)
	if err != nil {
		t.Fatalf("POST raw no-caps receive-pack: %v", err)
	}
	noCapsResp.Body.Close()
	if noCapsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from raw receive-pack, got %d", noCapsResp.StatusCode)
	}
	noCapsPushes := gh.PushAttempts()[beforeNoCaps:]
	if len(noCapsPushes) != 1 || noCapsPushes[0].Ref != "refs/heads/corrupt-nocaps" || noCapsPushes[0].Allowed {
		t.Fatalf("expected Allowed=false PushAttempt for corrupt no-caps push, got %+v", noCapsPushes)
	}
	if corruptExists, err := git.BranchExists("acme/service", "corrupt-nocaps"); err != nil || corruptExists {
		t.Fatalf("expected corrupt-nocaps branch not to exist (exists=%v err=%v)", corruptExists, err)
	}

	// REST GET /git/matching-refs/ empty must return [] (not null).
	matchReq, _ := http.NewRequest(http.MethodGet, gh.BaseAPIURL()+"repos/acme/service/git/matching-refs/heads/nonexistent-prefix", nil)
	matchReq.Header.Set("Authorization", "Bearer "+readTok)
	matchResp, err := http.DefaultClient.Do(matchReq)
	if err != nil {
		t.Fatalf("GET matching-refs: %v", err)
	}
	matchBody, _ := io.ReadAll(matchResp.Body)
	matchResp.Body.Close()
	if matchResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from matching-refs, got %d", matchResp.StatusCode)
	}
	if strings.TrimSpace(string(matchBody)) != "[]" {
		t.Fatalf("expected [] for empty matching-refs, got %q", string(matchBody))
	}

	// REST PATCH /git/refs/* with "force": false must reject non-fast-forward updates with 422,
	// while allowing fast-forward updates and force: true updates.
	orphanSHA, err := git.ForcePushBranch("acme/service", "orphan-src", harness.CommitSpec{
		Files:   map[string]string{"orphan-src.txt": "orphan\n"},
		Message: "Orphan commit for REST PATCH test",
	})
	if err != nil {
		t.Fatalf("ForcePushBranch orphan-src: %v", err)
	}
	beforePatchNonFF := len(gh.PushAttempts())
	patchNonFFReq, _ := http.NewRequest(http.MethodPatch, gh.BaseAPIURL()+"repos/acme/service/git/refs/heads/feat-2",
		strings.NewReader(fmt.Sprintf(`{"sha":%q,"force":false}`, orphanSHA)))
	patchNonFFReq.Header.Set("Authorization", "Bearer "+writeTok)
	patchNonFFResp, err := http.DefaultClient.Do(patchNonFFReq)
	if err != nil {
		t.Fatalf("PATCH git/refs (force=false non-FF): %v", err)
	}
	patchNonFFResp.Body.Close()
	if patchNonFFResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for non-FF PATCH with force=false, got %d", patchNonFFResp.StatusCode)
	}
	if gotFeat2, err := git.ResolveRef("acme/service", "refs/heads/feat-2"); err != nil || gotFeat2 != origFeat2 {
		t.Fatalf("expected refs/heads/feat-2 unchanged at %q after rejected PATCH, got %q (err=%v)", origFeat2, gotFeat2, err)
	}
	patchNonFFPushes := gh.PushAttempts()[beforePatchNonFF:]
	if len(patchNonFFPushes) != 1 || patchNonFFPushes[0].Ref != "refs/heads/feat-2" || patchNonFFPushes[0].Allowed {
		t.Fatalf("expected Allowed=false PushAttempt for rejected non-FF PATCH, got %+v", patchNonFFPushes)
	}

	// Fast-forward PATCH with force: false succeeds with 200.
	ffChildSHA, err := git.CommitToBranch("acme/service", "feat-2", harness.CommitSpec{
		Files:   map[string]string{"feat-2-ff.txt": "ff\n"},
		Message: "FF child of feat-2",
	})
	if err != nil {
		t.Fatalf("CommitToBranch feat-2 ff child: %v", err)
	}
	// Reset feat-2 back to origFeat2 first so ffChildSHA is a strict descendant, then PATCH force:false to ffChildSHA.
	patchResetReq, _ := http.NewRequest(http.MethodPatch, gh.BaseAPIURL()+"repos/acme/service/git/refs/heads/feat-2",
		strings.NewReader(fmt.Sprintf(`{"sha":%q,"force":true}`, origFeat2)))
	patchResetReq.Header.Set("Authorization", "Bearer "+writeTok)
	patchResetResp, err := http.DefaultClient.Do(patchResetReq)
	if err != nil {
		t.Fatalf("PATCH reset feat-2: %v", err)
	}
	patchResetResp.Body.Close()
	if patchResetResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for PATCH force=true reset, got %d", patchResetResp.StatusCode)
	}
	patchFFReq, _ := http.NewRequest(http.MethodPatch, gh.BaseAPIURL()+"repos/acme/service/git/refs/heads/feat-2",
		strings.NewReader(fmt.Sprintf(`{"sha":%q,"force":false}`, ffChildSHA)))
	patchFFReq.Header.Set("Authorization", "Bearer "+writeTok)
	patchFFResp, err := http.DefaultClient.Do(patchFFReq)
	if err != nil {
		t.Fatalf("PATCH git/refs (force=false FF): %v", err)
	}
	patchFFResp.Body.Close()
	if patchFFResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for FF PATCH with force=false, got %d", patchFFResp.StatusCode)
	}
	if gotFeat2, err := git.ResolveRef("acme/service", "refs/heads/feat-2"); err != nil || gotFeat2 != ffChildSHA {
		t.Fatalf("expected refs/heads/feat-2 updated to %q, got %q (err=%v)", ffChildSHA, gotFeat2, err)
	}

	// Raw POST /git-receive-pack with side-band-64k (and WITHOUT report-status):
	// (a) non-FF rejection, (b) corrupt packfile, (c) valid push.
	orphanHEADOut, err := runGit(wtDir, "rev-parse", "orphan-nonff")
	if err != nil {
		t.Fatalf("rev-parse orphan-nonff: %v\n%s", err, orphanHEADOut)
	}
	orphanHEAD := strings.TrimSpace(orphanHEADOut)
	buildPack := func(dir, revSpec string) []byte {
		cmd := exec.Command("git", "-c", "core.hooksPath=/dev/null", "pack-objects", "--revs", "--stdout")
		cmd.Dir = dir
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_TERMINAL_PROMPT=0",
		}
		cmd.Stdin = strings.NewReader(revSpec)
		var out, errBuf bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("git pack-objects failed: %v\n%s", err, errBuf.String())
		}
		return out.Bytes()
	}
	sendRawReceivePack := func(cmdLine string, pack []byte) (int, []byte) {
		var body bytes.Buffer
		fmt.Fprintf(&body, "%04x%s0000", len(cmdLine)+4, cmdLine)
		body.Write(pack)
		req, _ := http.NewRequest(http.MethodPost, gh.CloneURL("acme/service")+"/git-receive-pack", &body)
		req.SetBasicAuth("x-access-token", writeTok)
		req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST raw receive-pack: %v", err)
		}
		defer resp.Body.Close()
		respBytes, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, respBytes
	}
	orphanPack := buildPack(wtDir, orphanHEAD+"\n")

	// (a) side-band-64k without report-status: non-FF rejection -> Allowed=false, ref unchanged.
	beforeSBNonFF := len(gh.PushAttempts())
	sbNonFFStatus, sbNonFFBody := sendRawReceivePack(
		fmt.Sprintf("%s %s refs/heads/main\x00side-band-64k\n", newMainSHA, orphanHEAD),
		orphanPack,
	)
	if sbNonFFStatus != http.StatusOK {
		t.Fatalf("expected 200 for side-band-64k non-FF push, got %d", sbNonFFStatus)
	}
	if !bytes.Contains(sbNonFFBody, []byte{2}) || !strings.Contains(strings.ToLower(string(sbNonFFBody)), "error:") {
		t.Fatalf("expected sideband-2 error message in response, got %q", string(sbNonFFBody))
	}
	sbNonFFPushes := gh.PushAttempts()[beforeSBNonFF:]
	if len(sbNonFFPushes) != 1 || sbNonFFPushes[0].Ref != "refs/heads/main" || sbNonFFPushes[0].Allowed || sbNonFFPushes[0].Stage != "receive_pack" {
		t.Fatalf("expected Allowed=false PushAttempt for side-band-64k non-FF push, got %+v", sbNonFFPushes)
	}
	if gotMain, err := git.ResolveRef("acme/service", "refs/heads/main"); err != nil || gotMain != newMainSHA {
		t.Fatalf("expected refs/heads/main unchanged at %q after sideband non-FF rejection, got %q (err=%v)", newMainSHA, gotMain, err)
	}

	// (b) side-band-64k without report-status: corrupt packfile -> Allowed=false, branch not created.
	beforeSBCorrupt := len(gh.PushAttempts())
	sbCorruptStatus, sbCorruptBody := sendRawReceivePack(
		fmt.Sprintf("%s %s refs/heads/corrupt-sb\x00side-band-64k\n", strings.Repeat("0", 40), newMainSHA),
		[]byte("PACK\x00\x00\x00\x02\x00\x00\x00\x01corrupt_truncated_bytes"),
	)
	if sbCorruptStatus != http.StatusOK {
		t.Fatalf("expected 200 for side-band-64k corrupt pack push, got %d", sbCorruptStatus)
	}
	if !bytes.Contains(sbCorruptBody, []byte{2}) || !strings.Contains(strings.ToLower(string(sbCorruptBody)), "fatal:") {
		t.Fatalf("expected sideband-2 fatal message in response, got %q", string(sbCorruptBody))
	}
	sbCorruptPushes := gh.PushAttempts()[beforeSBCorrupt:]
	if len(sbCorruptPushes) != 1 || sbCorruptPushes[0].Ref != "refs/heads/corrupt-sb" || sbCorruptPushes[0].Allowed || sbCorruptPushes[0].Stage != "receive_pack" {
		t.Fatalf("expected Allowed=false PushAttempt for side-band-64k corrupt pack push, got %+v", sbCorruptPushes)
	}
	if corruptSBExists, err := git.BranchExists("acme/service", "corrupt-sb"); err != nil || corruptSBExists {
		t.Fatalf("expected corrupt-sb branch not to exist (exists=%v err=%v)", corruptSBExists, err)
	}

	// (c) side-band-64k without report-status: valid push -> Allowed=true, branch created.
	beforeSBValid := len(gh.PushAttempts())
	sbValidStatus, _ := sendRawReceivePack(
		fmt.Sprintf("%s %s refs/heads/valid-sb\x00side-band-64k\n", strings.Repeat("0", 40), orphanHEAD),
		orphanPack,
	)
	if sbValidStatus != http.StatusOK {
		t.Fatalf("expected 200 for side-band-64k valid push, got %d", sbValidStatus)
	}
	sbValidPushes := gh.PushAttempts()[beforeSBValid:]
	if len(sbValidPushes) != 1 || sbValidPushes[0].Ref != "refs/heads/valid-sb" || !sbValidPushes[0].Allowed || sbValidPushes[0].Stage != "receive_pack" {
		t.Fatalf("expected Allowed=true PushAttempt for side-band-64k valid push, got %+v", sbValidPushes)
	}
	if gotValidSB, err := git.ResolveRef("acme/service", "refs/heads/valid-sb"); err != nil || gotValidSB != orphanHEAD {
		t.Fatalf("expected refs/heads/valid-sb at %q, got %q (err=%v)", orphanHEAD, gotValidSB, err)
	}

	// REST PATCH /git/refs/heads/does-not-exist with "force": false -> 422, branch NOT created, Allowed=false.
	beforePatchMissing := len(gh.PushAttempts())
	patchMissingReq, _ := http.NewRequest(http.MethodPatch, gh.BaseAPIURL()+"repos/acme/service/git/refs/heads/does-not-exist",
		strings.NewReader(fmt.Sprintf(`{"sha":%q,"force":false}`, newMainSHA)))
	patchMissingReq.Header.Set("Authorization", "Bearer "+writeTok)
	patchMissingResp, err := http.DefaultClient.Do(patchMissingReq)
	if err != nil {
		t.Fatalf("PATCH nonexistent ref: %v", err)
	}
	patchMissingResp.Body.Close()
	if patchMissingResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for PATCH on nonexistent ref, got %d", patchMissingResp.StatusCode)
	}
	if missingExists, err := git.BranchExists("acme/service", "does-not-exist"); err != nil || missingExists {
		t.Fatalf("expected does-not-exist branch NOT created (exists=%v err=%v)", missingExists, err)
	}
	patchMissingPushes := gh.PushAttempts()[beforePatchMissing:]
	if len(patchMissingPushes) != 1 || patchMissingPushes[0].Ref != "refs/heads/does-not-exist" || patchMissingPushes[0].Allowed || patchMissingPushes[0].Stage != "rest_ref_missing" {
		t.Fatalf("expected Allowed=false rest_ref_missing PushAttempt, got %+v", patchMissingPushes)
	}

	// REST PATCH with invalid SHA -> 422, ref unchanged.
	beforePatchBadSHA := len(gh.PushAttempts())
	patchBadSHAReq, _ := http.NewRequest(http.MethodPatch, gh.BaseAPIURL()+"repos/acme/service/git/refs/heads/feat-2",
		strings.NewReader(`{"sha":"not-a-valid-sha","force":false}`))
	patchBadSHAReq.Header.Set("Authorization", "Bearer "+writeTok)
	patchBadSHAResp, err := http.DefaultClient.Do(patchBadSHAReq)
	if err != nil {
		t.Fatalf("PATCH invalid SHA: %v", err)
	}
	patchBadSHAResp.Body.Close()
	if patchBadSHAResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for PATCH with invalid SHA, got %d", patchBadSHAResp.StatusCode)
	}
	patchBadSHAPushes := gh.PushAttempts()[beforePatchBadSHA:]
	if len(patchBadSHAPushes) != 1 || patchBadSHAPushes[0].Ref != "refs/heads/feat-2" || patchBadSHAPushes[0].Allowed || patchBadSHAPushes[0].Stage != "rest_ref_invalid_sha" {
		t.Fatalf("expected Allowed=false rest_ref_invalid_sha PushAttempt, got %+v", patchBadSHAPushes)
	}
	// Also test well-formed 40-hex SHA for a nonexistent commit with force:true -> 422, ref unchanged.
	beforePatchGhostSHA := len(gh.PushAttempts())
	patchGhostSHAReq, _ := http.NewRequest(http.MethodPatch, gh.BaseAPIURL()+"repos/acme/service/git/refs/heads/feat-2",
		strings.NewReader(fmt.Sprintf(`{"sha":%q,"force":true}`, strings.Repeat("a", 40))))
	patchGhostSHAReq.Header.Set("Authorization", "Bearer "+writeTok)
	patchGhostSHAResp, err := http.DefaultClient.Do(patchGhostSHAReq)
	if err != nil {
		t.Fatalf("PATCH nonexistent commit SHA: %v", err)
	}
	patchGhostSHAResp.Body.Close()
	if patchGhostSHAResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for PATCH with nonexistent commit SHA, got %d", patchGhostSHAResp.StatusCode)
	}
	patchGhostSHAPushes := gh.PushAttempts()[beforePatchGhostSHA:]
	if len(patchGhostSHAPushes) != 1 || patchGhostSHAPushes[0].Ref != "refs/heads/feat-2" || patchGhostSHAPushes[0].Allowed || patchGhostSHAPushes[0].Stage != "rest_ref_invalid_sha" {
		t.Fatalf("expected Allowed=false rest_ref_invalid_sha PushAttempt for ghost SHA, got %+v", patchGhostSHAPushes)
	}
	if gotFeat2, err := git.ResolveRef("acme/service", "refs/heads/feat-2"); err != nil || gotFeat2 != ffChildSHA {
		t.Fatalf("expected refs/heads/feat-2 unchanged at %q after invalid SHA PATCHes, got %q (err=%v)", ffChildSHA, gotFeat2, err)
	}

	// REST POST /git/refs for an already-existing ref -> 422, ref unchanged.
	beforePostExists := len(gh.PushAttempts())
	postExistsReq, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"repos/acme/service/git/refs",
		strings.NewReader(fmt.Sprintf(`{"ref":"refs/heads/feat-2","sha":%q}`, newMainSHA)))
	postExistsReq.Header.Set("Authorization", "Bearer "+writeTok)
	postExistsResp, err := http.DefaultClient.Do(postExistsReq)
	if err != nil {
		t.Fatalf("POST existing ref: %v", err)
	}
	postExistsResp.Body.Close()
	if postExistsResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for POST /git/refs on existing ref, got %d", postExistsResp.StatusCode)
	}
	if gotFeat2, err := git.ResolveRef("acme/service", "refs/heads/feat-2"); err != nil || gotFeat2 != ffChildSHA {
		t.Fatalf("expected refs/heads/feat-2 unchanged at %q after POST on existing ref, got %q (err=%v)", ffChildSHA, gotFeat2, err)
	}
	postExistsPushes := gh.PushAttempts()[beforePostExists:]
	if len(postExistsPushes) != 1 || postExistsPushes[0].Ref != "refs/heads/feat-2" || postExistsPushes[0].Allowed || postExistsPushes[0].Stage != "rest_ref_exists" {
		t.Fatalf("expected Allowed=false rest_ref_exists PushAttempt, got %+v", postExistsPushes)
	}

	// REST POST /git/refs for a new ref -> 201, ref created.
	beforePostNew := len(gh.PushAttempts())
	postNewReq, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"repos/acme/service/git/refs",
		strings.NewReader(fmt.Sprintf(`{"ref":"refs/heads/created-via-post","sha":%q}`, newMainSHA)))
	postNewReq.Header.Set("Authorization", "Bearer "+writeTok)
	postNewResp, err := http.DefaultClient.Do(postNewReq)
	if err != nil {
		t.Fatalf("POST new ref: %v", err)
	}
	postNewResp.Body.Close()
	if postNewResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for POST /git/refs on new ref, got %d", postNewResp.StatusCode)
	}
	if gotCreated, err := git.ResolveRef("acme/service", "refs/heads/created-via-post"); err != nil || gotCreated != newMainSHA {
		t.Fatalf("expected refs/heads/created-via-post at %q, got %q (err=%v)", newMainSHA, gotCreated, err)
	}
	postNewPushes := gh.PushAttempts()[beforePostNew:]
	if len(postNewPushes) != 1 || postNewPushes[0].Ref != "refs/heads/created-via-post" || !postNewPushes[0].Allowed || postNewPushes[0].Stage != "rest_ref" {
		t.Fatalf("expected Allowed=true rest_ref PushAttempt for POST new ref, got %+v", postNewPushes)
	}

	t.Run("AppJWTVerification", func(t *testing.T) {
		postAccessToken := func(instID int64, authHeader, body string) (int, string) {
			u := fmt.Sprintf("%sapp/installations/%d/access_tokens", gh.BaseAPIURL(), instID)
			req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if authHeader != "" {
				req.Header.Set("Authorization", authHeader)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do(%s): %v", u, err)
			}
			defer resp.Body.Close()
			var out struct {
				Token string `json:"token"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			return resp.StatusCode, out.Token
		}

		mintRawJWT := func(hdrMap, claimsMap map[string]any, key *rsa.PrivateKey) string {
			hb, _ := json.Marshal(hdrMap)
			cb, _ := json.Marshal(claimsMap)
			si := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
			if key == nil {
				return si + "." + base64.RawURLEncoding.EncodeToString([]byte("invalid-sig"))
			}
			sum := sha256.Sum256([]byte(si))
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
			if err != nil {
				t.Fatalf("SignPKCS1v15: %v", err)
			}
			return si + "." + base64.RawURLEncoding.EncodeToString(sig)
		}

		// 1. WriteApp JWT on repo.InstallationID (5001) with write perms -> 201 ghs_write_5001_*
		writeJWT, err := harness.SignAppJWT(gh.WriteAppID(), gh.WriteAppPrivateKeyPEM(), time.Now().UTC())
		if err != nil {
			t.Fatalf("SignAppJWT(write): %v", err)
		}
		code, tok := postAccessToken(repo.InstallationID, "Bearer "+writeJWT, `{"permissions":{"contents":"write","pull_requests":"write"}}`)
		if code != http.StatusCreated || !strings.HasPrefix(tok, fmt.Sprintf("ghs_write_%d_", repo.InstallationID)) {
			t.Fatalf("writeApp write request: got code=%d tok=%q", code, tok)
		}

		// 2. WriteApp JWT explicitly requesting read-only perms -> 201 ghs_read_5001_*
		code, tok = postAccessToken(repo.InstallationID, "Bearer "+writeJWT, `{"permissions":{"contents":"read"}}`)
		if code != http.StatusCreated || !strings.HasPrefix(tok, fmt.Sprintf("ghs_read_%d_", repo.InstallationID)) {
			t.Fatalf("writeApp read-only request: got code=%d tok=%q", code, tok)
		}

		// 3. ReadApp JWT requesting read perms -> 201 ghs_read_5001_*
		readJWT, err := harness.SignAppJWT(gh.ReadAppID(), gh.ReadAppPrivateKeyPEM(), time.Now().UTC())
		if err != nil {
			t.Fatalf("SignAppJWT(read): %v", err)
		}
		code, tok = postAccessToken(repo.InstallationID, "Bearer "+readJWT, `{"permissions":{"contents":"read"}}`)
		if code != http.StatusCreated || !strings.HasPrefix(tok, fmt.Sprintf("ghs_read_%d_", repo.InstallationID)) {
			t.Fatalf("readApp read request: got code=%d tok=%q", code, tok)
		}

		// 4. ReadApp JWT requesting write perms -> 403
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+readJWT, `{"permissions":{"contents":"write"}}`)
		if code != http.StatusForbidden {
			t.Fatalf("readApp write escalation: got %d, want 403", code)
		}

		// 5. Missing Authorization header -> 401
		code, _ = postAccessToken(repo.InstallationID, "", `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("missing auth: got %d, want 401", code)
		}

		// 6. Wrong RSA key signing writeAppID iss -> 401
		wrongKeyJWT, err := harness.SignAppJWT(gh.WriteAppID(), gh.ReadAppPrivateKeyPEM(), time.Now().UTC())
		if err != nil {
			t.Fatalf("SignAppJWT(wrong key): %v", err)
		}
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+wrongKeyJWT, `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("wrong key signature: got %d, want 401", code)
		}

		// 7. Tampered signature -> 401
		parts := strings.Split(writeJWT, ".")
		tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("tampered"))
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+tampered, `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("tampered signature: got %d, want 401", code)
		}

		// 8. Expired JWT -> 401
		expiredJWT, err := harness.SignAppJWT(gh.WriteAppID(), gh.WriteAppPrivateKeyPEM(), time.Now().UTC().Add(-15*time.Minute))
		if err != nil {
			t.Fatalf("SignAppJWT(expired): %v", err)
		}
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+expiredJWT, `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("expired JWT: got %d, want 401", code)
		}

		// 9. Unknown iss -> 401
		unknownIssJWT, err := harness.SignAppJWT(999, gh.WriteAppPrivateKeyPEM(), time.Now().UTC())
		if err != nil {
			t.Fatalf("SignAppJWT(unknown iss): %v", err)
		}
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+unknownIssJWT, `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("unknown iss: got %d, want 401", code)
		}

		// 10. Non-RS256 alg -> 401
		now := time.Now().UTC()
		hsJWT := mintRawJWT(
			map[string]any{"alg": "HS256", "typ": "JWT"},
			map[string]any{"iss": strconv.FormatInt(gh.WriteAppID(), 10), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()},
			nil,
		)
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+hsJWT, `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("non-RS256 alg: got %d, want 401", code)
		}

		// 11. Excessive TTL (>10m) -> 401 (even if signed with arbitrary key / format)
		excessTTLJWT := mintRawJWT(
			map[string]any{"alg": "RS256", "typ": "JWT"},
			map[string]any{"iss": strconv.FormatInt(gh.WriteAppID(), 10), "iat": now.Unix(), "exp": now.Add(30 * time.Minute).Unix()},
			nil,
		)
		code, _ = postAccessToken(repo.InstallationID, "Bearer "+excessTTLJWT, `{}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("excessive TTL: got %d, want 401", code)
		}

		// 12. Invalid instID <= 0 -> 400
		for _, badInst := range []int64{0, -1} {
			code, _ = postAccessToken(badInst, "Bearer "+writeJWT, `{}`)
			if code != http.StatusBadRequest {
				t.Fatalf("instID=%d: got %d, want 400", badInst, code)
			}
		}

		// 13. PKCS#8 RSA PEM format compatibility check for SignAppJWT
		pkcs8Key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(pkcs8Key)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))
		pkcs8JWT, err := harness.SignAppJWT(202, pkcs8PEM, now)
		if err != nil {
			t.Fatalf("SignAppJWT with PKCS#8 PEM failed: %v", err)
		}
		_, claims, si, sig := decodeJWTParts(t, pkcs8JWT)
		if claims["iss"] != "202" {
			t.Fatalf("PKCS#8 JWT iss=%v, want 202", claims["iss"])
		}
		sum := sha256.Sum256([]byte(si))
		if err := rsa.VerifyPKCS1v15(&pkcs8Key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
			t.Fatalf("PKCS#8 JWT signature verification failed: %v", err)
		}
	})
}

func TestHarness_SnapshotStoreHelper(t *testing.T) {
	store := harness.NewSnapshotStoreHelper(t, "")
	cleanGZ, cleanSum := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: "hello.go", Body: []byte("package hello\n")},
	})

	obj, err := store.WriteObject("workspaces/ws-1/source.tar.gz", cleanGZ)
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}
	if obj.SHA256 != cleanSum {
		t.Fatalf("StoredObject SHA256=%s, want %s", obj.SHA256, cleanSum)
	}
	found, err := store.FindBySHA256("sha256:" + cleanSum)
	if err != nil || found.RelPath != obj.RelPath {
		t.Fatalf("FindBySHA256: found=%+v err=%v", found, err)
	}
	readBack, err := store.ReadBytes(*found)
	if err != nil || !bytes.Equal(readBack, cleanGZ) {
		t.Fatalf("ReadBytes mismatch: err=%v", err)
	}
	store.AssertArchiveNoSecretLeak(t, readBack, "AKIAIOSFODNN7EXAMPLE")

	// Negative secret leak detection (body and linkname)
	dirtyGZ, _ := harness.MustBuildTarGz(t, []harness.TarEntry{
		{Name: ".env", Body: []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")},
	})
	if err := store.CheckArchiveNoSecretLeak(dirtyGZ, "AKIAIOSFODNN7EXAMPLE"); err == nil {
		t.Fatalf("expected secret leak error for archive containing AKIAIOSFODNN7EXAMPLE")
	}
	dirtyLinkGZ, _ := harness.BuildSymlinkArchive("escape", "/tmp/secret-link/AKIAIOSFODNN7EXAMPLE")
	if err := store.CheckArchiveNoSecretLeak(dirtyLinkGZ, "AKIAIOSFODNN7EXAMPLE"); err == nil {
		t.Fatalf("expected secret leak error for archive symlink Linkname containing AKIAIOSFODNN7EXAMPLE")
	}

	// Outage simulation & recovery
	if err := store.SimulateOutage(true); err != nil {
		t.Fatalf("SimulateOutage(true): %v", err)
	}
	if _, err := store.ListObjects(); err == nil {
		t.Fatalf("expected error from ListObjects during simulated outage")
	}
	if err := store.SimulateOutage(false); err != nil {
		t.Fatalf("SimulateOutage(false): %v", err)
	}
	cnt, err := store.ObjectCount()
	if err != nil || cnt != 1 {
		t.Fatalf("expected ObjectCount=1 after recovery, got %d err=%v", cnt, err)
	}
}

func TestHarness_PGDocker(t *testing.T) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker daemon unavailable: %v", err)
	}

	pg := harness.StartPGDocker(t)
	cid := pg.ContainerID()
	if cid == "" {
		if os.Getenv("CUSTODIAN_TEST_DSN") != "" {
			t.Skip("using external CUSTODIAN_TEST_DSN; skipping container lifecycle checks")
		}
		t.Fatalf("expected non-empty container ID")
	}
	portNum, err := strconv.Atoi(pg.HostPort())
	if err != nil || portNum <= 0 || portNum == 5432 {
		t.Fatalf("invalid ephemeral PG port %q (must be > 0 and != 5432)", pg.HostPort())
	}

	out, err := pg.ExecSQL("SELECT 1;")
	if err != nil || strings.TrimSpace(out) != "1" {
		t.Fatalf("ExecSQL SELECT 1 failed: out=%q err=%v", out, err)
	}

	if _, err := pg.ExecSQL("CREATE TABLE harness_probe (id INT PRIMARY KEY, name TEXT); INSERT INTO harness_probe VALUES (42, 'custodian');"); err != nil {
		t.Fatalf("DDL/INSERT failed: %v", err)
	}
	rows, err := pg.QueryRows("SELECT id, name FROM harness_probe ORDER BY id;")
	if err != nil || len(rows) != 1 || rows[0][0] != "42" || rows[0][1] != "custodian" {
		t.Fatalf("QueryRows unexpected: rows=%+v err=%v", rows, err)
	}

	if err := pg.Close(); err != nil {
		t.Fatalf("pg.Close(): %v", err)
	}
	// Poll briefly because docker --rm container removal can be asynchronous for a few ms.
	deadline := time.Now().Add(5 * time.Second)
	for {
		psOut, err := exec.Command("docker", "ps", "-aq", "--filter", "id="+cid).CombinedOutput()
		if err == nil && strings.TrimSpace(string(psOut)) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected container %s to be removed after Close(), still found: %s", cid, string(psOut))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestHarness_EnvAndAPIClient(t *testing.T) {
	env := harness.NewEnv(t, harness.WithSkipServices(), harness.WithSkipPostgres())
	tok := env.MintToken(harness.TokenClaims{Kind: "HUMAN", Subject: "dev-1"})
	if tok == "" {
		t.Fatalf("expected minted token")
	}
	env.AssertNoSecretLeakInLogs()

	// Exercise APIClient against a local httptest server verifying Idempotency-Key, OpenAPI DTOs, ErrorResponse, & non-fatal 4xx
	var sawAuth, sawIdem, sawDLHeader string
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawIdem = r.Header.Get("Idempotency-Key")
		if r.URL.Path == "/v1/workspaces" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"workspace_id":"01933e5a-1234-7abc-8def-0123456789ab","status":"PENDING"}`))
			return
		}
		if r.URL.Path == "/v1/workspaces/ws-1/source" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"workspace_id":"01933e5a-1234-7abc-8def-0123456789ab","generation":1,"base_commit":"0123456789abcdef0123456789abcdef01234567","artifact":{"artifact_id":"01933e5a-1234-7abc-8def-0123456789ac","kind":"WORKSPACE_SOURCE","sha256":"` + strings.Repeat("a", 64) + `","size_bytes":5,"format":"tar.gz","storage_key":"ws/1","storage_generation":"1"},"download":{"method":"GET","url":"` + srvURL + `/dl/src.tar.gz","headers":{"X-DL":"cap-ok"},"expires_at":"2026-12-01T00:00:00Z"},"source_options":{"include_git_metadata":false,"include_history":false},"upload_capability":{"token":"cap_tok_1","workspace_id":"01933e5a-1234-7abc-8def-0123456789ab","generation":1,"max_bytes":1024,"expires_at":"2026-12-01T00:00:00Z","upload_url":"` + srvURL + `/upload/1"}}`))
			return
		}
		if r.URL.Path == "/dl/src.tar.gz" && r.Method == http.MethodGet {
			sawDLHeader = r.Header.Get("X-DL")
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write([]byte("TARGZ"))
			return
		}
		if r.URL.Path == "/v1/proposals/bad-json/diff" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{not-valid-json`))
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"CONFLICT","message":"stale version"}}`))
	}))
	srvURL = srv.URL
	defer srv.Close()

	client := harness.NewAPIClient(srv.URL, tok, harness.DefaultContracts())
	wsResp, raw, err := client.CreateWorkspace(context.Background(), harness.CreateWorkspaceReq{
		Repository: harness.WorkspaceRepoRef{Provider: "github", RepositoryID: 98765, Ref: "main"},
	})
	if err != nil {
		t.Fatalf("CreateWorkspace transport error: %v", err)
	}
	raw.RequireStatus(t, http.StatusAccepted)
	if wsResp.WorkspaceID == "" || sawAuth != "Bearer "+tok {
		t.Fatalf("unexpected workspace response or auth header: resp=%+v auth=%q", wsResp, sawAuth)
	}
	harness.AssertUUIDv7(t, sawIdem)

	// OpenAPI nested SourceArtifactDescriptor download + upload_capability
	dlBytes, dlRaw, err := client.DownloadWorkspaceSource(context.Background(), "ws-1")
	if err != nil || string(dlBytes) != "TARGZ" || sawDLHeader != "cap-ok" {
		t.Fatalf("DownloadWorkspaceSource failed: bytes=%q dlHeader=%q raw=%v err=%v", string(dlBytes), sawDLHeader, dlRaw, err)
	}
	capResp, _, err := client.RequestUploadCapability(context.Background(), "ws-1", harness.UploadCapabilityReq{})
	if err != nil || capResp.Token != "cap_tok_1" {
		t.Fatalf("RequestUploadCapability via /source failed: cap=%+v err=%v", capResp, err)
	}

	// 2xx invalid JSON returns decode error from doJSON
	if _, _, err := client.GetProposalDiff(context.Background(), "bad-json"); err == nil {
		t.Fatalf("expected json unmarshal error for 200 invalid JSON diff response")
	}

	// 409 response does not return a Go error and decodes nested OpenAPI ErrorResponse
	_, errRaw, err := client.ApproveProposal(context.Background(), "01933e5a-1234-7abc-8def-0123456789ab", harness.ApproveReq{
		Decision:                  "APPROVE",
		PublicationManifestDigest: strings.Repeat("b", 64),
		PolicyEvaluationID:        "01933e5a-1234-7abc-8def-0123456789ad",
	})
	if err != nil {
		t.Fatalf("expected nil transport error on 409, got %v", err)
	}
	errRaw.RequireStatus(t, http.StatusConflict)
	if errRaw.Error == nil || errRaw.Error.Code != "CONFLICT" {
		t.Fatalf("expected decoded OpenAPI APIError on 409, got %+v", errRaw.Error)
	}

	// Whitespace-padded nonexistent CUSTODIAN_E2E_CONTRACTS must fail loudly
	t.Setenv("CUSTODIAN_E2E_CONTRACTS", " /tmp/does-not-exist-custodian-e2e-99999.json ")
	if _, err := harness.LoadContracts(""); err == nil {
		t.Fatalf("expected LoadContracts to fail on whitespace-padded missing CUSTODIAN_E2E_CONTRACTS")
	}
}

func TestHarness_ConcurrentRunCLI(t *testing.T) {
	binDir := t.TempDir()
	for _, name := range harness.AllBinaryNames {
		cliPath := filepath.Join(binDir, name)
		if err := os.WriteFile(cliPath, []byte("#!/bin/sh\nprintf 'ok:%s\\n' \"$*\"\n"), 0o755); err != nil {
			t.Fatalf("write stub %s cli: %v", name, err)
		}
	}
	env := harness.NewEnv(t, harness.WithSkipServices(), harness.WithSkipPostgres(), harness.WithBinDir(binDir))

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res := env.RunCLI("custodian", []string{"--probe", strconv.Itoa(idx)}, nil)
			if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "ok:--probe "+strconv.Itoa(idx) {
				errs <- "unexpected RunCLI result: code=" + strconv.Itoa(res.ExitCode) + " out=" + res.Stdout + " err=" + res.Stderr
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
}

func TestHarness_MockGitHubPRs(t *testing.T) {
	git := harness.NewBareGitHelper(t, "")
	_, _ = git.InitSeededRepo("acme", "service", nil)
	gh := harness.StartMockGitHub(t, git, 101, 202)
	writeTok := "ghs_write_token"

	// 1. POST /pulls duplicate
	reqBody := `{"title":"Prop 1","head":"custodian/prop-001","base":"main"}`
	resp, err := http.Post(gh.BaseAPIURL()+"repos/acme/service/pulls", "application/json", strings.NewReader(reqBody))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauth, got %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, gh.BaseAPIURL()+"repos/acme/service/pulls", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "token "+writeTok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 created, got %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 duplicate, got %v status=%v", err, resp.StatusCode)
	}
	resp.Body.Close()

	if gh.PRCount("acme/service") != 1 {
		t.Fatalf("expected 1 PR, got %d", gh.PRCount("acme/service"))
	}
}
