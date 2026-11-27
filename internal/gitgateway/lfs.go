package gitgateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	maxLFSBatchBodyBytes     = 4 << 20
	defaultMaxLFSObjectBytes = int64(5) << 30 // 5 GiB (< 100 GiB)
	lfsCapabilityTokenPrefix = "clfs1."
	defaultLFSCapabilityTTL  = 5 * time.Minute
	maxLFSCapabilitySkew     = 30 * time.Second
	maxLFSDelegatedEntries   = 4096
)

type lfsDelegatedEntry struct {
	token     string
	expiresAt time.Time
	seq       uint64
}

type lfsCapabilityClaims struct {
	V           int       `json:"v"`
	Op          string    `json:"op"`
	Repo        string    `json:"repo"`
	OID         string    `json:"oid"`
	Size        int64     `json:"size"`
	PrincipalID uuid.UUID `json:"pid"`
	Nonce       string    `json:"nonce,omitempty"`
	IssuedAt    int64     `json:"iat"`
	ExpiresAt   int64     `json:"exp"`
}

func (s *Server) handleLFSBatch(w http.ResponseWriter, r *http.Request, ownerRepo string) {
	caller, ok := s.authenticateHTTP(w, r)
	if !ok {
		return
	}

	target, err := s.resolver.Resolve(r.Context(), ownerRepo, r.Host)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxLFSBatchBodyBytes+1))
	if err != nil {
		s.writeGatewayError(w, domain.BadRequest("INVALID_LFS_REQUEST", "failed reading LFS batch body"), http.StatusBadRequest)
		return
	}
	if int64(len(bodyBytes)) > maxLFSBatchBodyBytes {
		s.writeGatewayError(w, domain.BadRequest("LFS_BATCH_TOO_LARGE", "LFS batch request exceeds 4 MiB limit"), http.StatusRequestEntityTooLarge)
		return
	}

	var req LFSBatchRequest
	dec := json.NewDecoder(strings.NewReader(string(bodyBytes)))
	if err := dec.Decode(&req); err != nil {
		s.writeGatewayError(w, domain.BadRequest("INVALID_LFS_JSON", "LFS batch request must be valid JSON"), http.StatusBadRequest)
		return
	}

	if req.Operation != "upload" && req.Operation != "download" {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		s.writeGatewayError(w, domain.Unprocessable("UNSUPPORTED_LFS_OPERATION", "LFS operation must be upload or download"), http.StatusUnprocessableEntity)
		return
	}
	if len(req.Transfers) > 0 && !slices.Contains(req.Transfers, "basic") {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		s.writeGatewayError(w, domain.Unprocessable("UNSUPPORTED_LFS_TRANSFER", "only basic LFS transfer adapter is supported"), http.StatusUnprocessableEntity)
		return
	}

	for _, obj := range req.Objects {
		if err := ValidateLFSOID(obj.OID); err != nil {
			s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
			s.writeGatewayError(w, err, http.StatusBadRequest)
			return
		}
		if obj.Size < 0 || obj.Size > s.maxLFSObjectBytes {
			s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
			s.writeGatewayError(w, domain.Unprocessable("INVALID_LFS_SIZE", "LFS object size out of allowed bounds"), http.StatusUnprocessableEntity)
			return
		}
	}

	// Gate ENFORCE_PR uploads and unregistered/external ENFORCE_BLOCK uploads before touching upstream.
	if req.Operation == "upload" && target.EgressMode == domain.EgressModeEnforcePR {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		s.writeGatewayError(w, domain.Forbidden("LFS_UPLOAD_DENIED", "LFS upload blocked when ENFORCE_PR mode is active"), http.StatusForbidden)
		return
	}
	if req.Operation == "upload" && target.EgressMode == domain.EgressModeEnforceBlock && (!target.Registered || target.External) {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		s.writeGatewayError(w, domain.Forbidden("LFS_UPLOAD_DENIED", "LFS upload blocked for unregistered or external destination"), http.StatusForbidden)
		return
	}

	scope := TokenScopeRead
	if req.Operation == "upload" {
		scope = TokenScopeWrite
	}
	authRes, err := s.broker.ResolveUpstreamAuth(r.Context(), scope, caller, target)
	if err != nil {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		s.writeDomainOrGatewayError(w, err)
		return
	}

	status, upResp, _, err := s.upstream.LFSBatch(r.Context(), target.OwnerRepo, authRes.Token, req)
	if err != nil {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		s.writeDomainOrGatewayError(w, err)
		return
	}
	if status != http.StatusOK {
		s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
		writeUpstreamStatusError(w, status, "upstream LFS batch rejected")
		return
	}

	gwBase := s.effectiveGatewayBaseURL(r)
	for i := range upResp.Objects {
		obj := &upResp.Objects[i]
		if len(obj.Actions) == 0 {
			continue
		}
		if err := ValidateLFSOID(obj.OID); err != nil {
			s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
			s.writeGatewayError(w, domain.Unavailable("UPSTREAM_LFS_INVALID_OID", "upstream LFS batch returned invalid object OID"), http.StatusBadGateway)
			return
		}
		rewritten := make(map[string]LFSAction, len(obj.Actions))
		for actionName, act := range obj.Actions {
			act.Header = stripUpstreamLFSHeaders(act.Header)
			if actionName == "download" || actionName == "upload" {
				act.Href = gwBase + "/" + target.OwnerRepo + ".git/info/lfs/objects/" + obj.OID
				capTok, capErr := s.mintLFSCapabilityToken(actionName, target.OwnerRepo, obj.OID, obj.Size, caller.Principal.ID, act.ExpiresIn, caller.DelegatedUpstreamToken)
				if capErr != nil {
					s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectDeny))
					s.writeDomainOrGatewayError(w, capErr)
					return
				}
				if act.Header == nil {
					act.Header = make(map[string]string, 1)
				}
				act.Header["Authorization"] = "Bearer " + capTok
			}
			rewritten[actionName] = act
		}
		obj.Actions = rewritten
	}
	if upResp.Transfer == "" {
		upResp.Transfer = "basic"
	}

	s.metrics.IncPushLFSBatch(req.Operation, string(domain.PolicyEffectAllow))
	w.Header().Set("Content-Type", "application/vnd.git-lfs+json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(upResp)
}

func (s *Server) handleLFSObject(w http.ResponseWriter, r *http.Request, ownerRepo, oid string) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "GET or PUT required for LFS object"), http.StatusMethodNotAllowed)
		return
	}

	if err := ValidateLFSOID(oid); err != nil {
		s.writeGatewayError(w, err, http.StatusBadRequest)
		return
	}

	expectedOp := "download"
	if r.Method == http.MethodPut {
		expectedOp = "upload"
	}

	var (
		caller       AuthenticatedPrincipal
		capClaims    *lfsCapabilityClaims
		hasCapClaims bool
	)
	if capTok, isCap := extractLFSCapabilityBearer(r); isCap {
		claims, capErr := s.verifyLFSCapabilityToken(capTok, expectedOp, ownerRepo, oid)
		if capErr != nil {
			status := http.StatusUnauthorized
			var de *domain.DomainError
			if errors.As(capErr, &de) {
				status = de.HTTPStatus()
			}
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", s.auth.WWWAuthenticateHeader())
			}
			s.writeGatewayError(w, capErr, status)
			return
		}
		resolvedCaller, resErr := s.resolveLFSCapabilityPrincipal(r, claims)
		if resErr != nil {
			status := http.StatusUnauthorized
			var de *domain.DomainError
			if errors.As(resErr, &de) {
				status = de.HTTPStatus()
			}
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", s.auth.WWWAuthenticateHeader())
			}
			s.writeGatewayError(w, resErr, status)
			return
		}
		caller = resolvedCaller
		capClaims = &claims
		hasCapClaims = true
	} else {
		var ok bool
		caller, ok = s.authenticateHTTP(w, r)
		if !ok {
			return
		}
	}

	target, err := s.resolver.Resolve(r.Context(), ownerRepo, r.Host)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	if r.Method == http.MethodGet {
		// Read path MUST NEVER use write App keys.
		authRes, err := s.broker.ResolveUpstreamAuth(r.Context(), TokenScopeRead, caller, target)
		if err != nil {
			s.writeDomainOrGatewayError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		status, written, err := s.upstream.LFSGetObject(r.Context(), target.OwnerRepo, oid, authRes.Token, w)
		if err != nil {
			if written == 0 {
				s.writeDomainOrGatewayError(w, err)
			}
			return
		}
		if status != http.StatusOK && status != 0 {
			writeUpstreamStatusError(w, status, "upstream LFS object GET failed")
			return
		}
		return
	}

	// PUT upload object
	if target.EgressMode == domain.EgressModeEnforcePR {
		s.writeGatewayError(w, domain.Forbidden("LFS_UPLOAD_DENIED", "LFS object upload blocked when ENFORCE_PR mode is active"), http.StatusForbidden)
		return
	}
	if target.EgressMode == domain.EgressModeEnforceBlock && (!target.Registered || target.External) {
		s.writeGatewayError(w, domain.Forbidden("LFS_UPLOAD_DENIED", "LFS object upload blocked for unregistered or external destination"), http.StatusForbidden)
		return
	}
	if r.ContentLength > s.maxLFSObjectBytes {
		s.writeGatewayError(w, domain.BadRequest("LFS_OBJECT_TOO_LARGE", "LFS object exceeds maximum size"), http.StatusRequestEntityTooLarge)
		return
	}
	if hasCapClaims && r.ContentLength >= 0 && r.ContentLength != capClaims.Size {
		s.writeGatewayError(w, domain.Unprocessable("LFS_SIZE_MISMATCH", "uploaded LFS object size does not match capability token size"), http.StatusUnprocessableEntity)
		return
	}

	tmpFile, err := os.CreateTemp("", "custodian-lfs-put-*")
	if err != nil {
		s.writeGatewayError(w, domain.Unavailable("LFS_TEMP_ERROR", "failed buffering LFS object"), http.StatusServiceUnavailable)
		return
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	limited := &boundedFailReader{
		r:   r.Body,
		rem: s.maxLFSObjectBytes,
	}
	written, err := io.Copy(io.MultiWriter(tmpFile, hasher), limited)
	if err != nil {
		if errors.Is(err, errStreamLimitExceeded) {
			s.writeGatewayError(w, domain.BadRequest("LFS_OBJECT_TOO_LARGE", "LFS object exceeds maximum size"), http.StatusRequestEntityTooLarge)
			return
		}
		s.writeGatewayError(w, domain.BadRequest("LFS_UPLOAD_READ_FAILED", "failed reading LFS object body"), http.StatusBadRequest)
		return
	}
	if hasCapClaims && written != capClaims.Size {
		s.writeGatewayError(w, domain.Unprocessable("LFS_SIZE_MISMATCH", "uploaded LFS object size does not match capability token size"), http.StatusUnprocessableEntity)
		return
	}

	actualOID := hex.EncodeToString(hasher.Sum(nil))
	if actualOID != oid {
		s.writeGatewayError(w, domain.Unprocessable("LFS_OID_MISMATCH", "uploaded LFS object SHA-256 does not match oid"), http.StatusUnprocessableEntity)
		return
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		s.writeGatewayError(w, domain.Unavailable("LFS_TEMP_ERROR", "failed rewinding LFS object"), http.StatusServiceUnavailable)
		return
	}

	authRes, err := s.broker.ResolveUpstreamAuth(r.Context(), TokenScopeWrite, caller, target)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	status, err := s.upstream.LFSPutObject(r.Context(), target.OwnerRepo, oid, authRes.Token, tmpFile, written)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}
	if status != http.StatusOK && status != http.StatusCreated {
		writeUpstreamStatusError(w, status, "upstream LFS object PUT failed")
		return
	}
	s.metrics.AddPushUpstreamBytes(string(target.EgressMode), "lfs_put", written)
	w.WriteHeader(status)
}

func extractLFSCapabilityBearer(r *http.Request) (string, bool) {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if hdr == "" {
		return "", false
	}
	if len(hdr) < 7 || !strings.EqualFold(hdr[:7], "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(hdr[7:])
	if !strings.HasPrefix(tok, lfsCapabilityTokenPrefix) {
		return "", false
	}
	return tok, true
}

func (s *Server) mintLFSCapabilityToken(op, ownerRepo, oid string, size int64, principalID uuid.UUID, expiresInSeconds int, delegatedToken string) (string, error) {
	if len(s.lfsCapSecret) < 32 {
		return "", domain.Unavailable("LFS_CAPABILITY_UNAVAILABLE", "LFS capability secret is not configured")
	}
	now := time.Now().UTC()
	ttl := defaultLFSCapabilityTTL
	if expiresInSeconds > 0 && time.Duration(expiresInSeconds)*time.Second < ttl {
		ttl = time.Duration(expiresInSeconds) * time.Second
	}
	exp := now.Add(ttl)

	var nonce string
	if delegatedToken != "" {
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return "", domain.WrapError(domain.ErrInternal, "LFS_CAPABILITY_ERROR", "failed generating capability nonce", err)
		}
		nonce = hex.EncodeToString(rnd[:])
		s.storeDelegatedLFSNonce(nonce, delegatedToken, exp)
	}

	claims := lfsCapabilityClaims{
		V:           1,
		Op:          op,
		Repo:        ownerRepo,
		OID:         oid,
		Size:        size,
		PrincipalID: principalID,
		Nonce:       nonce,
		IssuedAt:    now.Unix(),
		ExpiresAt:   exp.Unix(),
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", domain.WrapError(domain.ErrInternal, "LFS_CAPABILITY_ERROR", "failed encoding LFS capability claims", err)
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := lfsCapabilityTokenPrefix + b64Payload
	mac := hmac.New(sha256.New, s.lfsCapSecret)
	_, _ = mac.Write([]byte(signingInput))
	b64MAC := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + b64MAC, nil
}

func (s *Server) verifyLFSCapabilityToken(rawToken, expectedOp, expectedRepo, expectedOID string) (lfsCapabilityClaims, error) {
	if len(s.lfsCapSecret) < 32 {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "LFS capability verification unavailable")
	}
	rest, ok := strings.CutPrefix(rawToken, lfsCapabilityTokenPrefix)
	if !ok {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "invalid LFS capability token prefix")
	}
	b64Payload, b64MAC, ok := strings.Cut(rest, ".")
	if !ok || b64Payload == "" || b64MAC == "" || strings.Contains(b64MAC, ".") {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "malformed LFS capability token")
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(b64MAC)
	if err != nil {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "malformed LFS capability signature")
	}

	signingInput := lfsCapabilityTokenPrefix + b64Payload
	mac := hmac.New(sha256.New, s.lfsCapSecret)
	_, _ = mac.Write([]byte(signingInput))
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "invalid LFS capability token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(b64Payload)
	if err != nil {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "malformed LFS capability payload")
	}
	var claims lfsCapabilityClaims
	dec := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "invalid LFS capability payload")
	}
	if claims.V != 1 || claims.PrincipalID == uuid.Nil || claims.Size < 0 {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "invalid LFS capability claims")
	}

	nowUnix := time.Now().UTC().Unix()
	if claims.IssuedAt > nowUnix+int64(maxLFSCapabilitySkew.Seconds()) {
		return lfsCapabilityClaims{}, domain.Unauthorized("INVALID_LFS_CAPABILITY", "LFS capability token issued in the future")
	}
	if nowUnix > claims.ExpiresAt {
		return lfsCapabilityClaims{}, domain.Unauthorized("LFS_CAPABILITY_EXPIRED", "LFS capability token has expired")
	}
	if claims.Op != expectedOp || claims.Repo != expectedRepo || claims.OID != expectedOID {
		return lfsCapabilityClaims{}, domain.Forbidden("LFS_CAPABILITY_SCOPE_MISMATCH", "LFS capability token does not match operation, repository, or oid")
	}
	return claims, nil
}

func (s *Server) resolveLFSCapabilityPrincipal(r *http.Request, claims lfsCapabilityClaims) (AuthenticatedPrincipal, error) {
	var principal domain.Principal
	var groups []string
	if s.store != nil {
		row, err := s.store.GetPrincipalByID(r.Context(), claims.PrincipalID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return AuthenticatedPrincipal{}, domain.Unauthorized("UNKNOWN_PRINCIPAL", "LFS capability principal does not exist")
			}
			return AuthenticatedPrincipal{}, err
		}
		principal = row.ToDomain()
		groups = append([]string(nil), row.Groups...)
	} else {
		principal = domain.Principal{
			ID:   claims.PrincipalID,
			Kind: domain.PrincipalKindHuman,
		}
	}

	delegated := ""
	if claims.Nonce != "" {
		delegated = s.lookupDelegatedLFSNonce(claims.Nonce, time.Now().UTC())
	}
	if delegated == "" {
		d, err := extractDelegatedUpstreamToken(r)
		if err != nil {
			return AuthenticatedPrincipal{}, err
		}
		delegated = d
	}

	return AuthenticatedPrincipal{
		Principal:              principal,
		Groups:                 groups,
		AuthMethod:             "lfs_capability",
		DelegatedUpstreamToken: delegated,
	}, nil
}

func (s *Server) storeDelegatedLFSNonce(nonce, token string, exp time.Time) {
	if nonce == "" || token == "" {
		return
	}
	now := time.Now().UTC()
	s.lfsDelegatedMu.Lock()
	defer s.lfsDelegatedMu.Unlock()
	if s.lfsDelegated == nil {
		s.lfsDelegated = make(map[string]lfsDelegatedEntry)
	}
	for k, v := range s.lfsDelegated {
		if !now.Before(v.expiresAt) {
			delete(s.lfsDelegated, k)
		}
	}
	if _, exists := s.lfsDelegated[nonce]; !exists {
		for len(s.lfsDelegated) >= maxLFSDelegatedEntries {
			var oldestKey string
			var oldestSeq uint64
			first := true
			for k, v := range s.lfsDelegated {
				if first || v.seq < oldestSeq {
					oldestKey = k
					oldestSeq = v.seq
					first = false
				}
			}
			if oldestKey == "" {
				break
			}
			delete(s.lfsDelegated, oldestKey)
		}
	}
	s.lfsDelegatedSeq++
	s.lfsDelegated[nonce] = lfsDelegatedEntry{
		token:     token,
		expiresAt: exp,
		seq:       s.lfsDelegatedSeq,
	}
}

func (s *Server) lookupDelegatedLFSNonce(nonce string, now time.Time) string {
	if nonce == "" {
		return ""
	}
	s.lfsDelegatedMu.Lock()
	defer s.lfsDelegatedMu.Unlock()
	entry, ok := s.lfsDelegated[nonce]
	if !ok {
		return ""
	}
	if !now.Before(entry.expiresAt) {
		delete(s.lfsDelegated, nonce)
		return ""
	}
	return entry.token
}

func (s *Server) effectiveGatewayBaseURL(r *http.Request) string {
	if s.gatewayPublicURL != "" {
		return s.gatewayPublicURL
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	return "https://" + host
}

func stripUpstreamLFSHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	cleaned := make(map[string]string, len(headers))
	for k, v := range headers {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "authorization", "proxy-authorization", "x-custodian-upstream-token", "x-github-token":
			continue
		default:
			cleaned[k] = v
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}
