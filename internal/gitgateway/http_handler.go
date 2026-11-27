package gitgateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"unicode"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
	"github.com/timreynolds/custodian/internal/observability"
	"github.com/timreynolds/custodian/internal/persistence"
)

const (
	defaultMaxPackBytes       = int64(64 << 20)
	defaultMaxRefUpdates      = 100
	maxPktLineCommandAreaSize = int64(2 << 20)
	maxUploadPackRequestBytes = int64(4 << 20)
	maxSidebandBufferBytes    = 1 << 20
)

// Server serves HTTPS Smart-HTTP, Git LFS, operational endpoints (/healthz, /readyz, /metrics),
// and builds the companion SSH Git server.
type Server struct {
	store             *persistence.Store
	auth              *Authenticator
	resolver          *TargetResolver
	broker            *TokenBroker
	upstream          UpstreamClient
	receiveHandler    ReceivePackHandler
	limits            quarantine.Limits
	maxLFSObjectBytes int64
	gatewayPublicURL  string
	lfsCapSecret      []byte
	lfsDelegatedMu    sync.Mutex
	lfsDelegated      map[string]lfsDelegatedEntry
	lfsDelegatedSeq   uint64
	metrics           *observability.Metrics
	logger            *slog.Logger
	sshServer         *SSHServer
}

// NewServer constructs a gitgateway Server with fail-closed defaults.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Authenticator == nil {
		return nil, domain.BadRequest("INVALID_GATEWAY_CONFIG", "Authenticator is required")
	}
	if cfg.TargetResolver == nil {
		return nil, domain.BadRequest("INVALID_GATEWAY_CONFIG", "TargetResolver is required")
	}
	if cfg.TokenBroker == nil {
		return nil, domain.BadRequest("INVALID_GATEWAY_CONFIG", "TokenBroker is required")
	}
	if cfg.Upstream == nil {
		return nil, domain.BadRequest("INVALID_GATEWAY_CONFIG", "UpstreamClient is required")
	}

	var lfsCapSecret []byte
	switch len(cfg.LFSCapabilitySecret) {
	case 0:
		lfsCapSecret = make([]byte, 32)
		if _, err := rand.Read(lfsCapSecret); err != nil {
			return nil, domain.WrapError(domain.ErrInternal, "INVALID_GATEWAY_CONFIG", "failed generating ephemeral LFS capability secret", err)
		}
	default:
		if len(cfg.LFSCapabilitySecret) < 32 {
			return nil, domain.BadRequest("INVALID_GATEWAY_CONFIG", "LFSCapabilitySecret must be at least 32 bytes")
		}
		lfsCapSecret = append([]byte(nil), cfg.LFSCapabilitySecret...)
	}

	limits := cfg.Limits
	if limits.MaxPackBytes <= 0 {
		limits.MaxPackBytes = defaultMaxPackBytes
	}
	if limits.MaxRefUpdates <= 0 {
		limits.MaxRefUpdates = defaultMaxRefUpdates
	}
	maxLFS := cfg.MaxLFSObjectBytes
	if maxLFS <= 0 {
		maxLFS = defaultMaxLFSObjectBytes
	}

	handler := cfg.ReceivePackHandler
	if handler == nil {
		handler = NewDefaultFailClosedReceivePackHandler()
	}

	s := &Server{
		store:             cfg.Store,
		auth:              cfg.Authenticator,
		resolver:          cfg.TargetResolver,
		broker:            cfg.TokenBroker,
		upstream:          cfg.Upstream,
		receiveHandler:    handler,
		limits:            limits,
		maxLFSObjectBytes: maxLFS,
		gatewayPublicURL:  strings.TrimRight(strings.TrimSpace(cfg.GatewayPublicURL), "/"),
		lfsCapSecret:      lfsCapSecret,
		lfsDelegated:      make(map[string]lfsDelegatedEntry),
		metrics:           cfg.Metrics,
		logger:            cfg.Logger,
	}

	if cfg.Authenticator.sshHostKey != nil && cfg.Authenticator.sshUserCA != nil {
		sshSrv, err := newSSHServer(s)
		if err != nil {
			return nil, err
		}
		s.sshServer = sshSrv
	}

	return s, nil
}

// SSHServer returns the configured SSH Git server (nil if SSH keys were not provided).
func (s *Server) SSHServer() *SSHServer {
	if s == nil {
		return nil
	}
	return s.sshServer
}

// HTTPHandler returns the HTTP handler serving /healthz, /readyz, /metrics, Smart-HTTP, and LFS.
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	rawPath := r.URL.EscapedPath()
	if r.RequestURI != "" {
		rawPath = r.RequestURI
		if qIdx := strings.IndexByte(rawPath, '?'); qIdx >= 0 {
			rawPath = rawPath[:qIdx]
		}
	}

	// Operational endpoints on the TLS gateway listener (unauthenticated for health probes & Prometheus).
	switch rawPath {
	case "/healthz":
		if r.Method != http.MethodGet {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "method not allowed"), http.StatusMethodNotAllowed)
			return
		}
		writeGatewayJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case "/readyz":
		if r.Method != http.MethodGet {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "method not allowed"), http.StatusMethodNotAllowed)
			return
		}
		if s.store == nil {
			s.writeGatewayError(w, domain.Unavailable("DATABASE_UNAVAILABLE", "persistence store is not configured"), http.StatusServiceUnavailable)
			return
		}
		if err := s.store.Ping(r.Context()); err != nil {
			s.writeGatewayError(w, domain.Unavailable("DATABASE_UNAVAILABLE", "database is not ready"), http.StatusServiceUnavailable)
			return
		}
		writeGatewayJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	case "/metrics":
		if r.Method != http.MethodGet {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "method not allowed"), http.StatusMethodNotAllowed)
			return
		}
		if s.metrics == nil {
			s.writeGatewayError(w, domain.Unavailable("METRICS_UNAVAILABLE", "metrics registry is not configured"), http.StatusServiceUnavailable)
			return
		}
		s.metrics.Handler().ServeHTTP(w, r)
		return
	}

	ownerRepo, suffix, err := ParseSmartHTTPRepoPath(rawPath, r.URL.Path)
	if err != nil {
		s.writeGatewayError(w, err, http.StatusBadRequest)
		return
	}

	switch {
	case suffix == "/info/refs":
		if r.Method != http.MethodGet {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "GET required for /info/refs"), http.StatusMethodNotAllowed)
			return
		}
		s.handleInfoRefs(w, r, ownerRepo)
	case suffix == "/git-upload-pack":
		if r.Method != http.MethodPost {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "POST required for /git-upload-pack"), http.StatusMethodNotAllowed)
			return
		}
		s.handleUploadPack(w, r, ownerRepo)
	case suffix == "/git-receive-pack":
		if r.Method != http.MethodPost {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "POST required for /git-receive-pack"), http.StatusMethodNotAllowed)
			return
		}
		s.handleReceivePack(w, r, ownerRepo)
	case suffix == "/info/lfs/objects/batch":
		if r.Method != http.MethodPost {
			s.writeGatewayError(w, domain.BadRequest("METHOD_NOT_ALLOWED", "POST required for LFS batch"), http.StatusMethodNotAllowed)
			return
		}
		s.handleLFSBatch(w, r, ownerRepo)
	case strings.HasPrefix(suffix, "/info/lfs/objects/"):
		oid := strings.TrimPrefix(suffix, "/info/lfs/objects/")
		s.handleLFSObject(w, r, ownerRepo, oid)
	default:
		s.writeGatewayError(w, domain.NotFound("NOT_FOUND", "unknown git gateway endpoint"), http.StatusNotFound)
	}
}

func (s *Server) authenticateHTTP(w http.ResponseWriter, r *http.Request) (AuthenticatedPrincipal, bool) {
	caller, err := s.auth.AuthenticateHTTPRequest(r.Context(), r)
	if err != nil {
		status := http.StatusUnauthorized
		var de *domain.DomainError
		if errors.As(err, &de) {
			status = de.HTTPStatus()
		}
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", s.auth.WWWAuthenticateHeader())
		}
		s.writeGatewayError(w, err, status)
		return AuthenticatedPrincipal{}, false
	}
	return caller, true
}

func (s *Server) handleInfoRefs(w http.ResponseWriter, r *http.Request, ownerRepo string) {
	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" && service != "git-receive-pack" {
		s.writeGatewayError(w, domain.BadRequest("UNSUPPORTED_SERVICE", "service must be git-upload-pack or git-receive-pack"), http.StatusBadRequest)
		return
	}

	caller, ok := s.authenticateHTTP(w, r)
	if !ok {
		return
	}

	target, err := s.resolver.Resolve(r.Context(), ownerRepo, r.Host)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	if service == "git-upload-pack" {
		authRes, err := s.broker.ResolveUpstreamAuth(r.Context(), TokenScopeRead, caller, target)
		if err != nil {
			s.writeDomainOrGatewayError(w, err)
			return
		}
		status, contentType, body, _, err := s.upstream.InfoRefs(r.Context(), target.OwnerRepo, "git-upload-pack", authRes.Token)
		if err != nil {
			s.writeDomainOrGatewayError(w, err)
			return
		}
		if status != http.StatusOK {
			writeUpstreamStatusError(w, status, "upstream info/refs failed")
			return
		}
		if contentType == "" {
			contentType = "application/x-git-upload-pack-advertisement"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// git-receive-pack advertisement
	body, status, err := s.resolveReceivePackAdvertisement(r.Context(), caller, target)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}
	if status != http.StatusOK {
		writeUpstreamStatusError(w, status, "upstream git-receive-pack info/refs rejected")
		return
	}

	w.Header().Set("Content-Type", "application/x-git-receive-pack-advertisement")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) resolveReceivePackAdvertisement(ctx context.Context, caller AuthenticatedPrincipal, target ResolvedTarget) ([]byte, int, error) {
	if target.Repository != nil {
		authRes, err := s.broker.ResolveUpstreamAuth(ctx, TokenScopeWrite, caller, target)
		if err != nil {
			return nil, 0, err
		}
		status, _, body, _, err := s.upstream.InfoRefs(ctx, target.OwnerRepo, "git-receive-pack", authRes.Token)
		if err != nil {
			return nil, 0, err
		}
		if status != http.StatusOK {
			return nil, status, nil
		}
		return ensureReceivePackAdvertisementCaps(body), http.StatusOK, nil
	}

	// Unregistered destination: query read-safe git-upload-pack refs first (never write App keys),
	// re-frame as git-receive-pack advertisement, or synthesize an empty-repo advertisement on 404
	// so real git push reaches POST /git-receive-pack for policy evaluation and audit recording.
	readAuth, err := s.broker.ResolveUpstreamAuth(ctx, TokenScopeRead, caller, target)
	if err != nil {
		return nil, 0, err
	}
	status, _, body, _, err := s.upstream.InfoRefs(ctx, target.OwnerRepo, "git-upload-pack", readAuth.Token)
	if err != nil {
		return synthesizeEmptyReceivePackAdvertisement(), http.StatusOK, nil
	}
	if status == http.StatusOK {
		return rewriteUploadPackToReceivePackAdvertisement(body), http.StatusOK, nil
	}
	return synthesizeEmptyReceivePackAdvertisement(), http.StatusOK, nil
}

func (s *Server) handleUploadPack(w http.ResponseWriter, r *http.Request, ownerRepo string) {
	caller, ok := s.authenticateHTTP(w, r)
	if !ok {
		return
	}
	target, err := s.resolver.Resolve(r.Context(), ownerRepo, r.Host)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}
	// Read path MUST NEVER use write App keys.
	authRes, err := s.broker.ResolveUpstreamAuth(r.Context(), TokenScopeRead, caller, target)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	maxUploadBytes := s.limits.MaxPackBytes + maxPktLineCommandAreaSize
	if maxUploadBytes > maxUploadPackRequestBytes {
		maxUploadBytes = maxUploadPackRequestBytes
	}
	if r.ContentLength > maxUploadBytes {
		s.writeGatewayError(w, domain.BadRequest("UPLOAD_PACK_TOO_LARGE", "upload-pack Content-Length exceeds maximum allowed bytes"), http.StatusRequestEntityTooLarge)
		return
	}

	limitedBody := &boundedFailReader{
		r:   r.Body,
		rem: maxUploadBytes,
	}
	var reqStream io.Reader = limitedBody
	isGzip := false
	if ce := strings.TrimSpace(r.Header.Get("Content-Encoding")); ce != "" {
		if !strings.EqualFold(ce, "gzip") {
			s.writeGatewayError(w, domain.BadRequest("UNSUPPORTED_ENCODING", "unsupported Content-Encoding"), http.StatusUnsupportedMediaType)
			return
		}
		isGzip = true
		gz, err := gzip.NewReader(limitedBody)
		if err != nil {
			s.writeGatewayError(w, domain.BadRequest("INVALID_GZIP", "invalid gzip upload-pack request"), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		reqStream = &boundedFailReader{
			r:   gz,
			rem: maxUploadBytes,
		}
	}

	var reqBuf bytes.Buffer
	if _, err := io.Copy(&reqBuf, reqStream); err != nil {
		if errors.Is(err, errStreamLimitExceeded) {
			s.writeGatewayError(w, domain.BadRequest("UPLOAD_PACK_TOO_LARGE", "upload-pack stream exceeds maximum allowed bytes"), http.StatusRequestEntityTooLarge)
			return
		}
		if isGzip {
			s.writeGatewayError(w, domain.BadRequest("INVALID_GZIP", "invalid gzip upload-pack request"), http.StatusBadRequest)
			return
		}
		s.writeGatewayError(w, domain.BadRequest("INVALID_UPLOAD_PACK_REQUEST", "failed reading upload-pack request"), http.StatusBadRequest)
		return
	}

	var respBuf bytes.Buffer
	status, err := s.upstream.UploadPack(r.Context(), target.OwnerRepo, authRes.Token, &reqBuf, &respBuf)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}
	if status != http.StatusOK {
		writeUpstreamStatusError(w, status, "upstream git-upload-pack failed")
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBuf.Bytes())
}

func (s *Server) handleReceivePack(w http.ResponseWriter, r *http.Request, ownerRepo string) {
	caller, ok := s.authenticateHTTP(w, r)
	if !ok {
		return
	}
	target, err := s.resolver.Resolve(r.Context(), ownerRepo, r.Host)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	maxWireBytes := s.limits.MaxPackBytes + maxPktLineCommandAreaSize
	if r.ContentLength > maxWireBytes {
		s.writeGatewayError(w, domain.BadRequest("PACK_TOO_LARGE", "receive-pack Content-Length exceeds maximum allowed bytes"), http.StatusRequestEntityTooLarge)
		return
	}

	limitedBody := &boundedFailReader{
		r:   r.Body,
		rem: maxWireBytes,
	}
	var stream io.Reader = limitedBody
	if ce := strings.TrimSpace(r.Header.Get("Content-Encoding")); ce != "" {
		if !strings.EqualFold(ce, "gzip") {
			s.writeGatewayError(w, domain.BadRequest("UNSUPPORTED_ENCODING", "unsupported Content-Encoding"), http.StatusUnsupportedMediaType)
			return
		}
		gz, err := gzip.NewReader(limitedBody)
		if err != nil {
			s.writeGatewayError(w, domain.BadRequest("INVALID_GZIP", "invalid gzip receive-pack request"), http.StatusBadRequest)
			return
		}
		defer gz.Close()
		stream = &boundedFailReader{
			r:   gz,
			rem: maxWireBytes,
		}
	}

	cmdStream := &boundedFailReader{
		r:   stream,
		rem: maxPktLineCommandAreaSize,
	}
	cmds, caps, err := parseReceivePackCommands(cmdStream, s.limits.MaxRefUpdates)
	if err != nil {
		if errors.Is(err, errStreamLimitExceeded) {
			s.writeGatewayError(w, domain.BadRequest("PACK_TOO_LARGE", "receive-pack stream exceeds maximum allowed bytes"), http.StatusRequestEntityTooLarge)
			return
		}
		s.writeDomainOrGatewayError(w, err)
		return
	}

	useSideband := slices.Contains(caps, "side-band-64k") || slices.Contains(caps, "side-band")

	if len(cmds) == 0 {
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildReceivePackReportStatus(true, "", nil, useSideband, nil))
		return
	}

	upstreamToken, extraSecrets, err := s.resolveWriteAuthForReceivePack(r.Context(), caller, target)
	if err != nil {
		s.writeDomainOrGatewayError(w, err)
		return
	}

	var sidebandBuf bytes.Buffer
	sbWriter := &boundedSidebandBuffer{buf: &sidebandBuf, max: maxSidebandBufferBytes}

	packReader := &boundedFailReader{
		r:   stream,
		rem: s.limits.MaxPackBytes,
	}
	outcome, err := s.receiveHandler.HandleReceivePack(r.Context(), ReceivePackRequest{
		Transport:          domain.PushTransportHTTPS,
		Caller:             caller,
		Target:             target,
		RefUpdates:         cmds,
		ClientCapabilities: caps,
		PackReader:         packReader,
		SidebandWriter:     sbWriter,
		UpstreamToken:      upstreamToken,
		ExtraSecrets:       extraSecrets,
	})
	if err != nil {
		if errors.Is(err, errStreamLimitExceeded) {
			s.writeGatewayError(w, domain.BadRequest("PACK_TOO_LARGE", "receive-pack stream exceeds maximum allowed bytes"), http.StatusRequestEntityTooLarge)
			return
		}
		s.writeDomainOrGatewayError(w, err)
		return
	}

	if outcome.HTTPStatus >= 400 {
		code := outcome.ErrorCode
		if code == "" {
			code = "RECEIVE_PACK_REJECTED"
		}
		msg := outcome.ErrorMessage
		if msg == "" {
			msg = "push rejected"
		}
		s.writeGatewayError(w, domain.Unavailable(code, msg), outcome.HTTPStatus)
		return
	}

	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buildReceivePackReportStatus(outcome.UnpackOK, outcome.UnpackMessage, outcome.RefResults, useSideband, sidebandBuf.Bytes()))
}

func (s *Server) resolveWriteAuthForReceivePack(ctx context.Context, caller AuthenticatedPrincipal, target ResolvedTarget) (string, []string, error) {
	authRes, err := s.broker.ResolveUpstreamAuth(ctx, TokenScopeWrite, caller, target)
	if err != nil {
		// Unregistered destinations without DB installation IDs should still reach ReceivePackHandler
		// so push_sessions are recorded and Stage C policy DENY runs cleanly with 0 upstream bytes.
		if target.Repository == nil && errors.Is(err, domain.ErrUnavailable) {
			return "", authRes.ExtraSecrets, nil
		}
		return "", authRes.ExtraSecrets, err
	}
	return authRes.Token, authRes.ExtraSecrets, nil
}

// --- Shared framing & parsing helpers ---

var errStreamLimitExceeded = errors.New("stream byte limit exceeded")

type boundedFailReader struct {
	r   io.Reader
	rem int64
}

func (b *boundedFailReader) Read(p []byte) (int, error) {
	if b.rem <= 0 {
		var probe [1]byte
		n, err := b.r.Read(probe[:])
		if n > 0 {
			return 0, errStreamLimitExceeded
		}
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.rem {
		p = p[:b.rem]
	}
	n, err := b.r.Read(p)
	b.rem -= int64(n)
	return n, err
}

type boundedSidebandBuffer struct {
	buf *bytes.Buffer
	max int
}

func (b *boundedSidebandBuffer) Write(p []byte) (int, error) {
	if b.buf == nil || b.buf.Len() >= b.max {
		return len(p), nil
	}
	avail := b.max - b.buf.Len()
	if len(p) > avail {
		_, _ = b.buf.Write(p[:avail])
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func parseReceivePackCommands(r io.Reader, maxRefUpdates int) ([]quarantine.RefUpdate, []string, error) {
	var cmds []quarantine.RefUpdate
	var caps []string

	for {
		payload, flush, err := readPktLine(r)
		if err != nil {
			if errors.Is(err, errStreamLimitExceeded) {
				return nil, nil, err
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "unexpected EOF while reading git-receive-pack ref updates")
			}
			return nil, nil, err
		}
		if flush {
			break
		}
		if len(payload) == 0 {
			return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "empty pkt-line command in git-receive-pack")
		}

		// Shallow pushes emit "shallow <oid>\n" pkt-lines before ref-update commands (or before 0000 on no-op push).
		if len(cmds) == 0 && bytes.IndexByte(payload, 0) < 0 {
			rawLine := strings.TrimRight(string(payload), "\r\n")
			if oid, ok := strings.CutPrefix(rawLine, "shallow "); ok {
				if !isValidGitHexOID(oid) {
					return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "git-receive-pack shallow line contains invalid OID")
				}
				continue
			}
		}

		cmdPart := payload
		if nulIdx := bytes.IndexByte(payload, 0); nulIdx >= 0 {
			if len(cmds) > 0 {
				return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "unexpected NUL capabilities after first ref-update command")
			}
			cmdPart = payload[:nulIdx]
			capRaw := strings.TrimSpace(string(payload[nulIdx+1:]))
			if capRaw != "" {
				caps = strings.Fields(capRaw)
			}
		}

		line := strings.TrimRight(string(cmdPart), "\r\n")
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "git-receive-pack command must contain old-oid new-oid refname")
		}
		oldOID, newOID, refName := parts[0], parts[1], parts[2]
		if !is40HexLower(oldOID) || !is40HexLower(newOID) {
			return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "git-receive-pack command contains invalid SHA-1 OID")
		}
		if refName == "" || hasDisallowedRefRunes(refName) {
			return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "git-receive-pack command contains invalid ref name")
		}
		cmds = append(cmds, quarantine.RefUpdate{
			OldOID:  oldOID,
			NewOID:  newOID,
			RefName: refName,
		})
		if maxRefUpdates > 0 && len(cmds) > maxRefUpdates {
			return nil, nil, domain.BadRequest("TOO_MANY_REF_UPDATES", fmt.Sprintf("ref update count exceeds limit (%d)", maxRefUpdates))
		}
	}

	if len(cmds) > 0 && slices.Contains(caps, "push-options") {
		// Consume the flush-terminated push-options pkt-line section so option lines never
		// leak into PackReader, and reject unsupported push-options cleanly.
		for {
			_, optFlush, optErr := readPktLine(r)
			if optErr != nil {
				if errors.Is(optErr, errStreamLimitExceeded) {
					return nil, nil, optErr
				}
				return nil, nil, domain.BadRequest("MALFORMED_PKT_LINE", "malformed push-options section in git-receive-pack")
			}
			if optFlush {
				break
			}
		}
		return nil, nil, domain.BadRequest("UNSUPPORTED_CAPABILITY", "push-options capability is not supported")
	}

	return cmds, caps, nil
}

func is64HexLower(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidGitHexOID(s string) bool {
	return is40HexLower(s) || is64HexLower(s)
}

func hasDisallowedRefRunes(ref string) bool {
	if strings.Contains(ref, "..") || strings.Contains(ref, "\\") {
		return true
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func buildReceivePackReportStatus(unpackOK bool, unpackMsg string, refResults []RefResult, sideband bool, sideband2Lines []byte) []byte {
	var reportBuf bytes.Buffer
	if unpackOK {
		_ = writePktLine(&reportBuf, []byte("unpack ok\n"))
	} else {
		msg := strings.TrimSpace(strings.ReplaceAll(unpackMsg, "\n", " "))
		if msg == "" {
			msg = "error"
		}
		_ = writePktLine(&reportBuf, []byte("unpack "+msg+"\n"))
	}
	for _, rr := range refResults {
		if rr.RefName == "" {
			continue
		}
		if rr.OK {
			_ = writePktLine(&reportBuf, []byte("ok "+rr.RefName+"\n"))
		} else {
			msg := strings.TrimSpace(strings.ReplaceAll(rr.Message, "\n", " "))
			if msg == "" {
				msg = "rejected"
			}
			_ = writePktLine(&reportBuf, []byte("ng "+rr.RefName+" "+msg+"\n"))
		}
	}
	_ = writeFlushPkt(&reportBuf)

	if !sideband {
		return reportBuf.Bytes()
	}

	var out bytes.Buffer
	if len(sideband2Lines) > 0 {
		for _, line := range bytes.Split(bytes.TrimRight(sideband2Lines, "\n"), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			pkt := make([]byte, 0, 1+len(line)+1)
			pkt = append(pkt, 0x02)
			pkt = append(pkt, line...)
			pkt = append(pkt, '\n')
			_ = writePktLine(&out, pkt)
		}
	}
	reportBytes := reportBuf.Bytes()
	const maxBandChunk = 65000
	for len(reportBytes) > 0 {
		n := len(reportBytes)
		if n > maxBandChunk {
			n = maxBandChunk
		}
		pkt := make([]byte, 0, 1+n)
		pkt = append(pkt, 0x01)
		pkt = append(pkt, reportBytes[:n]...)
		_ = writePktLine(&out, pkt)
		reportBytes = reportBytes[n:]
	}
	_ = writeFlushPkt(&out)
	return out.Bytes()
}

func synthesizeEmptyReceivePackAdvertisement() []byte {
	var out bytes.Buffer
	_ = writePktLine(&out, []byte("# service=git-receive-pack\n"))
	_ = writeFlushPkt(&out)
	_ = writePktLine(&out, []byte(quarantine.ZeroOID+" capabilities^{}\x00report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta agent=custodian-git-gateway/1.0\n"))
	_ = writeFlushPkt(&out)
	return out.Bytes()
}

func rewriteUploadPackToReceivePackAdvertisement(uploadRefsBody []byte) []byte {
	stripped := stripSmartHTTPServicePrefix(uploadRefsBody, "git-upload-pack")
	rd := bytes.NewReader(stripped)
	var out bytes.Buffer
	_ = writePktLine(&out, []byte("# service=git-receive-pack\n"))
	_ = writeFlushPkt(&out)

	const recvCaps = "report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta agent=custodian-git-gateway/1.0"
	wroteLine := false
	first := true
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil || flush {
			break
		}
		mainPart := payload
		if nulIdx := bytes.IndexByte(payload, 0); nulIdx >= 0 {
			mainPart = payload[:nulIdx]
		}
		line := strings.TrimRight(string(mainPart), "\r\n")
		if first {
			_ = writePktLine(&out, []byte(line+"\x00"+recvCaps+"\n"))
			first = false
		} else {
			_ = writePktLine(&out, []byte(line+"\n"))
		}
		wroteLine = true
	}
	if !wroteLine {
		_ = writePktLine(&out, []byte(quarantine.ZeroOID+" capabilities^{}\x00"+recvCaps+"\n"))
	}
	_ = writeFlushPkt(&out)
	return out.Bytes()
}

func ensureReceivePackAdvertisementCaps(rawBody []byte) []byte {
	rd := bytes.NewReader(rawBody)
	var out bytes.Buffer
	modified := false
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil {
			return rawBody
		}
		if flush {
			_ = writeFlushPkt(&out)
			if rd.Len() == 0 {
				break
			}
			continue
		}
		if !modified && !bytes.HasPrefix(payload, []byte("# service=")) {
			modified = true
			if nulIdx := bytes.IndexByte(payload, 0); nulIdx >= 0 {
				before := payload[:nulIdx]
				capsStr := strings.TrimRight(string(payload[nulIdx+1:]), "\r\n")
				capsRaw := strings.Fields(capsStr)
				caps := make([]string, 0, len(capsRaw)+2)
				for _, c := range capsRaw {
					if c == "push-options" {
						continue
					}
					caps = append(caps, c)
				}
				if !slices.Contains(caps, "report-status") {
					caps = append(caps, "report-status")
				}
				if !slices.Contains(caps, "side-band-64k") {
					caps = append(caps, "side-band-64k")
				}
				newPayload := append([]byte(nil), before...)
				newPayload = append(newPayload, 0)
				newPayload = append(newPayload, strings.Join(caps, " ")...)
				newPayload = append(newPayload, '\n')
				_ = writePktLine(&out, newPayload)
				continue
			}
		}
		_ = writePktLine(&out, payload)
	}
	return out.Bytes()
}

func stripSmartHTTPServicePrefix(rawBody []byte, expectedService string) []byte {
	rd := bytes.NewReader(rawBody)
	payload, flush, err := readPktLine(rd)
	if err == nil && !flush && bytes.HasPrefix(payload, []byte("# service="+expectedService)) {
		_, flush2, err2 := readPktLine(rd)
		if err2 == nil && flush2 {
			rest, _ := io.ReadAll(rd)
			return rest
		}
	}
	return rawBody
}

func (s *Server) writeDomainOrGatewayError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var de *domain.DomainError
	if errors.As(err, &de) {
		status = de.HTTPStatus()
	}
	s.writeGatewayError(w, err, status)
}

func writeUpstreamStatusError(w http.ResponseWriter, status int, msg string) {
	code := fmt.Sprintf("UPSTREAM_HTTP_%d", status)
	writeGatewayJSON(w, status, map[string]string{
		"error_code": code,
		"message":    msg,
	})
}

func (s *Server) writeGatewayError(w http.ResponseWriter, err error, status int) {
	code := "GATEWAY_ERROR"
	msg := "internal gateway error"
	var de *domain.DomainError
	if errors.As(err, &de) {
		code = de.Code()
		msg = de.Message
	} else if err != nil {
		if s != nil && s.logger != nil {
			s.logger.Warn("gitgateway error", "status", status, "error", sanitizeGatewayErrorString(err.Error()))
		}
	}
	if status < 400 {
		status = http.StatusInternalServerError
	}
	writeGatewayJSON(w, status, map[string]string{
		"error_code": code,
		"message":    msg,
	})
}

func sanitizeGatewayErrorString(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(raw))
	if len(cleaned) > 512 {
		return cleaned[:512]
	}
	return cleaned
}

func writeGatewayJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
