package gitgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/timreynolds/custodian/internal/domain"
)

const (
	maxUpstreamInfoRefsBytes   = 16 << 20
	maxUpstreamReceivePackResp = 4 << 20
	maxUpstreamLFSBatchResp    = 4 << 20
	maxPktLinePayloadBytes     = 65520
)

// HTTPUpstreamConfig configures HTTPUpstreamClient.
type HTTPUpstreamConfig struct {
	BaseURL           string
	HTTPClient        *http.Client
	AllowInsecureHTTP bool
	Logger            *slog.Logger
}

// HTTPUpstreamClient implements UpstreamClient over Git Smart-HTTP and Git LFS HTTP.
type HTTPUpstreamClient struct {
	baseURL    *url.URL
	httpClient *http.Client
	logger     *slog.Logger
}

// NewHTTPUpstreamClient constructs an UpstreamClient targeting BaseURL.
func NewHTTPUpstreamClient(cfg HTTPUpstreamConfig) (*HTTPUpstreamClient, error) {
	rawBase := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if rawBase == "" {
		rawBase = "https://github.com"
	}
	u, err := url.Parse(rawBase)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, domain.BadRequest("INVALID_UPSTREAM_URL", "upstream URL must include scheme and host")
	}
	if !strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http") {
		return nil, domain.BadRequest("INVALID_UPSTREAM_URL", "upstream URL scheme must be http or https")
	}
	if strings.EqualFold(u.Scheme, "http") && !cfg.AllowInsecureHTTP && !isLoopbackHost(u.Hostname()) {
		return nil, domain.BadRequest("INSECURE_UPSTREAM_URL", "plaintext HTTP upstream requires AllowInsecureHTTP or loopback host")
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   15 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				ResponseHeaderTimeout: 60 * time.Second,
			},
		}
	}

	return &HTTPUpstreamClient{
		baseURL:    u,
		httpClient: hc,
		logger:     cfg.Logger,
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *HTTPUpstreamClient) repoEndpoint(ownerRepo, suffix string) string {
	base := strings.TrimRight(c.baseURL.String(), "/")
	return base + "/" + strings.TrimLeft(ownerRepo, "/") + ".git" + suffix
}

func setUpstreamAuthHeader(req *http.Request, token string) {
	if tok := strings.TrimSpace(token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

// InfoRefs fetches Smart-HTTP /info/refs?service=<service> and parses advertised refs.
func (c *HTTPUpstreamClient) InfoRefs(ctx context.Context, ownerRepo, service, token string) (int, string, []byte, map[string]string, error) {
	endpoint := c.repoEndpoint(ownerRepo, "/info/refs?service="+url.QueryEscape(service))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, "", nil, nil, err
	}
	setUpstreamAuthHeader(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", nil, nil, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_INFO_REFS_FAILED", "upstream info/refs request failed", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamInfoRefsBytes+1))
	if err != nil {
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil, nil, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_INFO_REFS_READ_FAILED", "failed reading upstream info/refs response", err)
	}
	if int64(len(body)) > maxUpstreamInfoRefsBytes {
		return http.StatusBadGateway, "", nil, nil, domain.Unavailable("UPSTREAM_RESPONSE_TOO_LARGE", "upstream info/refs response exceeded limit")
	}

	refs := make(map[string]string)
	if resp.StatusCode == http.StatusOK {
		refs = parseAdvertisedRefs(body)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), body, refs, nil
}

// UploadPack proxies a stateless-RPC git-upload-pack POST to upstream and streams response to dst.
func (c *HTTPUpstreamClient) UploadPack(ctx context.Context, ownerRepo, token string, reqBody io.Reader, dst io.Writer) (int, error) {
	endpoint := c.repoEndpoint(ownerRepo, "/git-upload-pack")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	setUpstreamAuthHeader(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_UPLOAD_PACK_FAILED", "upstream git-upload-pack request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK && dst != nil {
		if _, err := io.Copy(dst, resp.Body); err != nil {
			return resp.StatusCode, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_UPLOAD_PACK_STREAM_FAILED", "failed streaming upstream git-upload-pack response", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	}
	return resp.StatusCode, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

// ReceivePack forwards a git-receive-pack payload upstream and returns status, response body, and exact bytes sent.
func (c *HTTPUpstreamClient) ReceivePack(ctx context.Context, ownerRepo, token string, pktLineAndPack io.Reader) (int, []byte, int64, error) {
	endpoint := c.repoEndpoint(ownerRepo, "/git-receive-pack")
	cr := &countingReader{r: pktLineAndPack}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, cr)
	if err != nil {
		return 0, nil, cr.n, err
	}
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	req.Header.Set("Accept", "application/x-git-receive-pack-result")
	setUpstreamAuthHeader(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, cr.n, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_RECEIVE_PACK_FAILED", "upstream git-receive-pack request failed", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamReceivePackResp))
	if err != nil {
		return resp.StatusCode, nil, cr.n, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_RECEIVE_PACK_READ_FAILED", "failed reading upstream git-receive-pack response", err)
	}
	return resp.StatusCode, respBody, cr.n, nil
}

// LFSBatch forwards a Git LFS Batch API request to upstream.
func (c *HTTPUpstreamClient) LFSBatch(ctx context.Context, ownerRepo, token string, reqPayload LFSBatchRequest) (int, LFSBatchResponse, []byte, error) {
	endpoint := c.repoEndpoint(ownerRepo, "/info/lfs/objects/batch")
	payloadBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return 0, LFSBatchResponse{}, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return 0, LFSBatchResponse{}, nil, err
	}
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	setUpstreamAuthHeader(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, LFSBatchResponse{}, nil, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_LFS_BATCH_FAILED", "upstream LFS batch request failed", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamLFSBatchResp))
	if err != nil {
		return resp.StatusCode, LFSBatchResponse{}, nil, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_LFS_BATCH_READ_FAILED", "failed reading upstream LFS batch response", err)
	}
	var parsed LFSBatchResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			return http.StatusBadGateway, LFSBatchResponse{}, rawBody, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_LFS_BATCH_INVALID_JSON", "upstream LFS batch response invalid JSON", err)
		}
	}
	return resp.StatusCode, parsed, rawBody, nil
}

// LFSGetObject streams an LFS object from upstream into dst.
func (c *HTTPUpstreamClient) LFSGetObject(ctx context.Context, ownerRepo, oid, token string, dst io.Writer) (int, int64, error) {
	endpoint := c.repoEndpoint(ownerRepo, "/info/lfs/objects/"+url.PathEscape(oid))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, 0, err
	}
	setUpstreamAuthHeader(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, 0, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_LFS_GET_FAILED", "upstream LFS object GET failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || dst == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, 0, nil
	}
	n, err := io.Copy(dst, resp.Body)
	if err != nil {
		return resp.StatusCode, n, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_LFS_GET_STREAM_FAILED", "failed streaming upstream LFS object", err)
	}
	return resp.StatusCode, n, nil
}

// LFSPutObject uploads a verified LFS object stream to upstream.
func (c *HTTPUpstreamClient) LFSPutObject(ctx context.Context, ownerRepo, oid, token string, body io.Reader, size int64) (int, error) {
	endpoint := c.repoEndpoint(ownerRepo, "/info/lfs/objects/"+url.PathEscape(oid))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if size >= 0 {
		req.ContentLength = size
	}
	setUpstreamAuthHeader(req, token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, domain.WrapError(domain.ErrUnavailable, "UPSTREAM_LFS_PUT_FAILED", "upstream LFS object PUT failed", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

// --- Pkt-line wire protocol helpers ---

func readPktLine(r io.Reader) (payload []byte, isFlush bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	for _, b := range hdr {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return nil, false, domain.BadRequest("MALFORMED_PKT_LINE", "invalid pkt-line hex length prefix")
		}
	}
	n, err := strconv.ParseInt(string(hdr[:]), 16, 32)
	if err != nil {
		return nil, false, domain.BadRequest("MALFORMED_PKT_LINE", "invalid pkt-line hex length prefix")
	}
	if n == 0 {
		return nil, true, nil
	}
	if n < 4 || n > maxPktLinePayloadBytes {
		return nil, false, domain.BadRequest("MALFORMED_PKT_LINE", fmt.Sprintf("invalid pkt-line length %d", n))
	}
	if n == 4 {
		return nil, false, nil
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, errStreamLimitExceeded) {
			return nil, false, err
		}
		return nil, false, domain.BadRequest("MALFORMED_PKT_LINE", "truncated pkt-line payload")
	}
	return buf, false, nil
}

func formatPktLine(data []byte) []byte {
	hdr := fmt.Sprintf("%04x", len(data)+4)
	out := make([]byte, 0, 4+len(data))
	out = append(out, hdr...)
	out = append(out, data...)
	return out
}

func writePktLine(w io.Writer, data []byte) error {
	_, err := w.Write(formatPktLine(data))
	return err
}

func writeFlushPkt(w io.Writer) error {
	_, err := io.WriteString(w, "0000")
	return err
}

func parseAdvertisedRefs(body []byte) map[string]string {
	refs := make(map[string]string)
	rd := bytes.NewReader(body)
	for {
		payload, flush, err := readPktLine(rd)
		if err != nil {
			break
		}
		if flush || len(payload) == 0 {
			continue
		}
		if bytes.HasPrefix(payload, []byte("# service=")) {
			continue
		}
		mainPart := payload
		if nulIdx := bytes.IndexByte(payload, 0); nulIdx >= 0 {
			mainPart = payload[:nulIdx]
		}
		line := strings.TrimRight(string(mainPart), "\r\n")
		oid, refName, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if refName == "capabilities^{}" || strings.HasSuffix(refName, "^{}") {
			continue
		}
		if is40HexLower(oid) && refName != "" {
			refs[refName] = oid
		}
	}
	return refs
}

func is40HexLower(s string) bool {
	if len(s) != 40 {
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
