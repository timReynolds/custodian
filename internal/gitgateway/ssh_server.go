package gitgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/timreynolds/custodian/internal/domain"
	"github.com/timreynolds/custodian/internal/gitgateway/quarantine"
)

const (
	sshMaxExecPayloadBytes    = 4096
	sshMaxEnvPayloadBytes     = 4096
	sshMaxUploadPackTurnBytes = 16 << 20
)

// SSHServer serves Git over SSH using OpenSSH User-CA certificate authentication.
type SSHServer struct {
	srv      *Server
	sshCfg   *ssh.ServerConfig
	registry *SSHSessionRegistry

	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

func newSSHServer(s *Server) (*SSHServer, error) {
	sshCfg, reg, err := s.auth.BuildSSHServerConfig()
	if err != nil {
		return nil, err
	}
	return &SSHServer{
		srv:      s,
		sshCfg:   sshCfg,
		registry: reg,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Serve accepts SSH connections on ln until ln is closed or Shutdown is called.
func (ss *SSHServer) Serve(ln net.Listener) error {
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return net.ErrClosed
	}
	ss.ln = ln
	ss.mu.Unlock()

	for {
		tcpConn, err := ln.Accept()
		if err != nil {
			ss.mu.Lock()
			closed := ss.closed
			ss.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return net.ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return err
		}

		ss.mu.Lock()
		if ss.closed {
			ss.mu.Unlock()
			_ = tcpConn.Close()
			return net.ErrClosed
		}
		ss.conns[tcpConn] = struct{}{}
		ss.wg.Add(1)
		ss.mu.Unlock()

		go func(c net.Conn) {
			defer ss.wg.Done()
			defer func() {
				ss.mu.Lock()
				delete(ss.conns, c)
				ss.mu.Unlock()
				_ = c.Close()
			}()
			ss.handleTCPConn(c)
		}(tcpConn)
	}
}

// Shutdown closes the listener and waits for active SSH connections to drain until ctx expires.
func (ss *SSHServer) Shutdown(ctx context.Context) error {
	if ss == nil {
		return nil
	}
	ss.mu.Lock()
	ss.closed = true
	ln := ss.ln
	if ln != nil {
		_ = ln.Close()
	}
	ss.mu.Unlock()

	done := make(chan struct{})
	go func() {
		ss.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		ss.mu.Lock()
		for c := range ss.conns {
			_ = c.Close()
		}
		ss.mu.Unlock()
		<-done
		return ctx.Err()
	}
}

func (ss *SSHServer) handleTCPConn(tcpConn net.Conn) {
	sconn, chans, reqs, err := ssh.NewServerConn(tcpConn, ss.sshCfg)
	if err != nil {
		return
	}
	defer func() {
		ss.registry.Delete(sconn.SessionID())
		_ = sconn.Close()
	}()

	caller, ok := ss.registry.Get(sconn.SessionID())
	if !ok {
		return
	}

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		ss.wg.Add(1)
		go func(channel ssh.Channel, requests <-chan *ssh.Request) {
			defer ss.wg.Done()
			ss.handleSessionChannel(sconn, caller, channel, requests)
		}(ch, chReqs)
	}
}

func (ss *SSHServer) handleSessionChannel(_ *ssh.ServerConn, caller AuthenticatedPrincipal, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	execStarted := false
	for req := range reqs {
		switch req.Type {
		case "env":
			if len(req.Payload) <= sshMaxEnvPayloadBytes {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			} else if req.WantReply {
				_ = req.Reply(false, nil)
			}
		case "exec":
			if execStarted || len(req.Payload) < 4 || len(req.Payload) > sshMaxExecPayloadBytes {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			cmdLen := int(binary.BigEndian.Uint32(req.Payload[:4]))
			if cmdLen < 0 || 4+cmdLen > len(req.Payload) {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			execCmd := string(req.Payload[4 : 4+cmdLen])
			execStarted = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			exitCode := ss.executeGitCommand(caller, ch, execCmd)
			_ = sendSSHExitStatus(ch, exitCode)
			_ = ch.CloseWrite()
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func sendSSHExitStatus(ch ssh.Channel, code uint32) error {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], code)
	_, err := ch.SendRequest("exit-status", false, payload[:])
	return err
}

func (ss *SSHServer) executeGitCommand(caller AuthenticatedPrincipal, ch ssh.Channel, rawCmd string) uint32 {
	trimmed := strings.TrimSpace(rawCmd)
	var gitService, repoArg string
	switch {
	case strings.HasPrefix(trimmed, "git-upload-pack "):
		gitService = "git-upload-pack"
		repoArg = strings.TrimSpace(strings.TrimPrefix(trimmed, "git-upload-pack "))
	case strings.HasPrefix(trimmed, "git-receive-pack "):
		gitService = "git-receive-pack"
		repoArg = strings.TrimSpace(strings.TrimPrefix(trimmed, "git-receive-pack "))
	default:
		_, _ = io.WriteString(ch.Stderr(), "ERR unsupported SSH command\n")
		return 1
	}

	ownerRepo, err := ParseSSHRepoPath(repoArg)
	if err != nil {
		_, _ = io.WriteString(ch.Stderr(), "ERR invalid repository path\n")
		return 1
	}

	ctx := context.Background()
	target, err := ss.srv.resolver.Resolve(ctx, ownerRepo, "")
	if err != nil {
		_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
		return 1
	}

	if gitService == "git-upload-pack" {
		return ss.handleSSHUploadPack(ctx, caller, target, ch)
	}
	return ss.handleSSHReceivePack(ctx, caller, target, ch)
}

func (ss *SSHServer) handleSSHUploadPack(ctx context.Context, caller AuthenticatedPrincipal, target ResolvedTarget, ch ssh.Channel) uint32 {
	// Read path MUST NEVER use write App keys.
	readAuth, err := ss.srv.broker.ResolveUpstreamAuth(ctx, TokenScopeRead, caller, target)
	if err != nil {
		_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
		return 1
	}

	status, _, advBody, _, err := ss.srv.upstream.InfoRefs(ctx, target.OwnerRepo, "git-upload-pack", readAuth.Token)
	if err != nil || status != http.StatusOK {
		_, _ = io.WriteString(ch.Stderr(), "ERR repository not found or unreadable\n")
		return 1
	}

	// Over SSH, Git v1 expects raw ref advertisement without the Smart-HTTP "# service=..." prefix.
	v1Refs := stripSmartHTTPServicePrefix(advBody, "git-upload-pack")
	if _, err := ch.Write(v1Refs); err != nil {
		return 1
	}

	// Bridge stateful SSH Git v1 negotiation turns to stateless-RPC HTTP /git-upload-pack
	// without blocking for EOF while client waits for ACK/NAK/packfile.
	wantsBuf, sawFlush, err := readSSHUploadPackTurn(ch, true)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
		}
		return 1
	}
	if len(wantsBuf) == 0 {
		// Client closed or sent immediate 0000 flush (already up-to-date).
		return 0
	}
	if !sawFlush {
		// Wants plus done already included in single turn.
		st, err := ss.srv.upstream.UploadPack(ctx, target.OwnerRepo, readAuth.Token, bytes.NewReader(wantsBuf), ch)
		if err != nil || st != http.StatusOK {
			_, _ = io.WriteString(ch.Stderr(), "ERR upstream git-upload-pack failed\n")
			return 1
		}
		return 0
	}

	// Shallow negotiation (git clone/fetch --depth, --shallow-since, --shallow-exclude):
	// Client sends want... + [shallow <old_oid>...] + deepen* + 0000 and blocks waiting for
	// server's shallow.../0000 reply before sending have/done. Exchange the shallow turn
	// immediately, keep the original wantsBuf intact for stateless-RPC Turn 1+ calls, and
	// strip the re-emitted leading shallow-update section from Turn 1+ responses.
	isShallow := hasShallowDirective(wantsBuf)
	if isShallow {
		var shallowResp bytes.Buffer
		st, err := ss.srv.upstream.UploadPack(ctx, target.OwnerRepo, readAuth.Token, bytes.NewReader(wantsBuf), &shallowResp)
		if err != nil || st != http.StatusOK {
			_, _ = io.WriteString(ch.Stderr(), "ERR upstream git-upload-pack failed\n")
			return 1
		}
		if _, err := ch.Write(shallowResp.Bytes()); err != nil {
			return 1
		}
	}

	var priorHaves bytes.Buffer
	for {
		turnBuf, isDone, sawTurnFlush, err := readSSHUloadPackNegotiationTurn(ch)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
			return 1
		}
		if len(turnBuf) == 0 && !isDone && !sawTurnFlush {
			return 0
		}

		var rpcReq bytes.Buffer
		rpcReq.Write(wantsBuf)
		rpcReq.Write(priorHaves.Bytes())
		rpcReq.Write(turnBuf)

		var respBuf bytes.Buffer
		st, err := ss.srv.upstream.UploadPack(ctx, target.OwnerRepo, readAuth.Token, &rpcReq, &respBuf)
		if err != nil || st != http.StatusOK {
			_, _ = io.WriteString(ch.Stderr(), "ERR upstream git-upload-pack failed\n")
			return 1
		}
		outBytes := respBuf.Bytes()
		if isShallow {
			outBytes = stripLeadingShallowSection(outBytes)
		}
		if _, err := ch.Write(outBytes); err != nil {
			return 1
		}
		if isDone {
			return 0
		}
		appendPktLinesWithoutFlush(&priorHaves, turnBuf, int(maxPktLineCommandAreaSize))
	}
}

func hasShallowDirective(wantsBuf []byte) bool {
	rd := bytes.NewReader(wantsBuf)
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil || flush {
			return false
		}
		line := strings.TrimRight(string(payload), "\r\n")
		if strings.HasPrefix(line, "deepen ") ||
			strings.HasPrefix(line, "deepen-since ") ||
			strings.HasPrefix(line, "deepen-not ") {
			return true
		}
	}
}

func stripLeadingShallowSection(resp []byte) []byte {
	rd := bytes.NewReader(resp)
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil {
			return resp
		}
		if flush {
			consumed := len(resp) - rd.Len()
			return resp[consumed:]
		}
		line := strings.TrimRight(string(payload), "\r\n")
		if oid, ok := strings.CutPrefix(line, "shallow "); ok && isValidGitHexOID(oid) {
			continue
		}
		if oid, ok := strings.CutPrefix(line, "unshallow "); ok && isValidGitHexOID(oid) {
			continue
		}
		return resp
	}
}

func appendPktLinesWithoutFlush(dst *bytes.Buffer, turnBuf []byte, maxBytes int) {
	if dst == nil {
		return
	}
	rd := bytes.NewReader(turnBuf)
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil {
			return
		}
		if flush || len(payload) == 0 {
			continue
		}
		line := strings.TrimRight(string(payload), "\r\n")
		if line == "done" {
			continue
		}
		pkt := formatPktLine(payload)
		if maxBytes > 0 && dst.Len()+len(pkt) > maxBytes {
			return
		}
		_, _ = dst.Write(pkt)
	}
}

func readSSHUploadPackTurn(r io.Reader, stopAtFlush bool) (buf []byte, sawFlush bool, err error) {
	var out bytes.Buffer
	for {
		payload, flush, err := readPktLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) && out.Len() == 0 {
				return nil, false, nil
			}
			return nil, false, err
		}
		if flush {
			if out.Len()+4 > sshMaxUploadPackTurnBytes {
				return nil, false, domain.BadRequest("UPLOAD_PACK_TOO_LARGE", "upload-pack turn exceeds maximum allowed bytes")
			}
			_ = writeFlushPkt(&out)
			if stopAtFlush {
				return out.Bytes(), true, nil
			}
			continue
		}
		if out.Len()+4+len(payload) > sshMaxUploadPackTurnBytes {
			return nil, false, domain.BadRequest("UPLOAD_PACK_TOO_LARGE", "upload-pack turn exceeds maximum allowed bytes")
		}
		_ = writePktLine(&out, payload)
		if bytes.Equal(bytes.TrimRight(payload, "\r\n"), []byte("done")) {
			return out.Bytes(), false, nil
		}
	}
}

func readSSHUloadPackNegotiationTurn(r io.Reader) (buf []byte, isDone bool, sawFlush bool, err error) {
	var out bytes.Buffer
	for {
		payload, flush, err := readPktLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) && out.Len() == 0 {
				return nil, false, false, io.EOF
			}
			return nil, false, false, err
		}
		if flush {
			if out.Len()+4 > sshMaxUploadPackTurnBytes {
				return nil, false, false, domain.BadRequest("UPLOAD_PACK_TOO_LARGE", "upload-pack turn exceeds maximum allowed bytes")
			}
			_ = writeFlushPkt(&out)
			return out.Bytes(), false, true, nil
		}
		if out.Len()+4+len(payload) > sshMaxUploadPackTurnBytes {
			return nil, false, false, domain.BadRequest("UPLOAD_PACK_TOO_LARGE", "upload-pack turn exceeds maximum allowed bytes")
		}
		_ = writePktLine(&out, payload)
		if bytes.Equal(bytes.TrimRight(payload, "\r\n"), []byte("done")) {
			return out.Bytes(), true, false, nil
		}
	}
}

func (ss *SSHServer) handleSSHReceivePack(ctx context.Context, caller AuthenticatedPrincipal, target ResolvedTarget, ch ssh.Channel) uint32 {
	advBody, status, err := ss.srv.resolveReceivePackAdvertisement(ctx, caller, target)
	if err != nil || status != http.StatusOK {
		msg := "upstream git-receive-pack unavailable"
		if err != nil {
			msg = safeSSHError(err)
		}
		_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", msg)
		return 1
	}

	v1Refs := stripSmartHTTPServicePrefix(advBody, "git-receive-pack")
	if _, err := ch.Write(v1Refs); err != nil {
		return 1
	}

	br := bufio.NewReaderSize(ch, 4096)
	cmdStream := &boundedFailReader{
		r:   br,
		rem: maxPktLineCommandAreaSize,
	}
	cmds, caps, err := parseReceivePackCommands(cmdStream, ss.srv.limits.MaxRefUpdates)
	if err != nil {
		if errors.Is(err, errStreamLimitExceeded) {
			_, _ = io.WriteString(ch.Stderr(), "ERR receive-pack command stream exceeds maximum allowed bytes\n")
			return 1
		}
		_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
		return 1
	}
	if len(cmds) == 0 {
		// Immediate 0000 (client had nothing to push).
		return 0
	}

	hasNonZeroNewOID := false
	for _, ru := range cmds {
		if ru.NewOID != "" && ru.NewOID != quarantine.ZeroOID {
			hasNonZeroNewOID = true
			break
		}
	}
	if !hasNonZeroNewOID && br.Buffered() > 0 {
		_, _ = io.WriteString(ch.Stderr(), "ERR unexpected pack data for pure-deletion push\n")
		return 1
	}

	useSideband := slices.Contains(caps, "side-band-64k") || slices.Contains(caps, "side-band")

	upstreamToken, extraSecrets, err := ss.srv.resolveWriteAuthForReceivePack(ctx, caller, target)
	if err != nil {
		_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
		return 1
	}

	var sbWriter io.Writer
	if useSideband {
		sbWriter = &sshSideband2Writer{ch: ch}
	} else {
		sbWriter = ch.Stderr()
	}

	// Per Git pack-protocol, pure ref deletions (all NewOID == ZeroOID) send no packfile
	// and keep the SSH stdin channel open waiting for report-status before sending EOF.
	var packReader io.Reader
	if hasNonZeroNewOID {
		packReader = &boundedFailReader{
			r:   br,
			rem: ss.srv.limits.MaxPackBytes,
		}
	} else {
		packReader = bytes.NewReader(nil)
	}

	outcome, err := ss.srv.receiveHandler.HandleReceivePack(ctx, ReceivePackRequest{
		Transport:          domain.PushTransportSSH,
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
		_, _ = fmt.Fprintf(ch.Stderr(), "ERR %s\n", safeSSHError(err))
		return 1
	}

	report := buildReceivePackReportStatus(outcome.UnpackOK, outcome.UnpackMessage, outcome.RefResults, useSideband, nil)
	_, _ = ch.Write(report)

	if outcome.HTTPStatus >= 400 || !outcome.UnpackOK {
		return 1
	}
	for _, rr := range outcome.RefResults {
		if !rr.OK {
			return 1
		}
	}
	return 0
}

type sshSideband2Writer struct {
	mu sync.Mutex
	ch ssh.Channel
}

func (w *sshSideband2Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	pkt := make([]byte, 0, 1+len(p))
	pkt = append(pkt, 0x02)
	pkt = append(pkt, p...)
	if err := writePktLine(w.ch, pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func safeSSHError(err error) string {
	var de *domain.DomainError
	if errors.As(err, &de) {
		return de.Message
	}
	if err == nil {
		return "error"
	}
	return "request failed"
}
