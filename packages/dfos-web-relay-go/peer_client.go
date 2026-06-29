package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPeerWriteDisabled is wrapped into the error returned by SubmitOperations
// when a peer rejects a gossip push with HTTP 501 — it advertises
// capabilities.write == false (a pull-only / lite node). Callers use errors.Is
// to distinguish this permanent capability signal from a transient push failure
// and stop gossiping to the peer rather than retrying it every cycle.
var ErrPeerWriteDisabled = errors.New("peer is write-disabled (pull-only)")

// ErrBlobNotFound is returned by GetBlob when a peer responds 404 — the peer is
// reachable but does not (yet) hold that blob. The materializer uses errors.Is
// to distinguish this from a transport/5xx failure: a 404 means "try another
// source," NOT "this peer is down," so it must not trip the source circuit breaker.
var ErrBlobNotFound = errors.New("peer does not have this blob")

// HttpPeerClient implements PeerClient using HTTP requests.
type HttpPeerClient struct {
	client *http.Client
}

// NewHttpPeerClient creates an HTTP-based PeerClient with a default timeout.
func NewHttpPeerClient() *HttpPeerClient {
	return &HttpPeerClient{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *HttpPeerClient) fetchJSON(rawURL string, out any) error {
	resp, err := c.client.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("peer returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *HttpPeerClient) GetIdentityLog(peerURL, did string, after string, limit int) (*PeerLogPage, error) {
	u, err := url.Parse(peerURL + proofBasePath + "/identities/" + url.PathEscape(did) + "/log")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	u.RawQuery = q.Encode()

	var page PeerLogPage
	if err := c.fetchJSON(u.String(), &page); err != nil {
		return nil, err
	}
	return &page, nil
}

func (c *HttpPeerClient) GetContentLog(peerURL, contentID string, after string, limit int) (*PeerLogPage, error) {
	u, err := url.Parse(peerURL + proofBasePath + "/content/" + url.PathEscape(contentID) + "/log")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	u.RawQuery = q.Encode()

	var page PeerLogPage
	if err := c.fetchJSON(u.String(), &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// GetBlob fetches raw document bytes from peerURL's content plane. The blob
// route lives at the relay ROOT (not under proofBasePath) — it belongs to the
// document gateway's own 0.x clock, not the frozen proof plane. Returns the
// verbatim octet-stream body, capped at maxRequestBodyBytes (the same ceiling
// the server enforces on PUT) so a hostile/buggy peer can't exhaust memory.
func (c *HttpPeerClient) GetBlob(peerURL, contentID, ref string) ([]byte, error) {
	rawURL := strings.TrimRight(peerURL, "/") + "/content/" + url.PathEscape(contentID) + "/blob/" + url.PathEscape(ref)
	resp, err := c.client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, ErrBlobNotFound
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("peer returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRequestBodyBytes {
		return nil, fmt.Errorf("peer blob exceeds %d bytes", maxRequestBodyBytes)
	}
	return data, nil
}

func (c *HttpPeerClient) GetOperationLog(peerURL string, after string, limit int) (*PeerLogPage, error) {
	u, err := url.Parse(peerURL + proofBasePath + "/log")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	u.RawQuery = q.Encode()

	var page PeerLogPage
	if err := c.fetchJSON(u.String(), &page); err != nil {
		return nil, err
	}
	return &page, nil
}

func (c *HttpPeerClient) SubmitOperations(peerURL string, operations []string) error {
	body, err := json.Marshal(map[string]any{"operations": operations})
	if err != nil {
		return err
	}
	resp, err := c.client.Post(peerURL+proofBasePath+"/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a bounded amount of the body so the error is actionable without
		// risking an unbounded read from a misbehaving peer.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		// A 501 means the peer is pull-only (writes disabled). Wrap the sentinel
		// so the caller can stop gossiping to it instead of retrying forever.
		if resp.StatusCode == http.StatusNotImplemented {
			return fmt.Errorf("peer %s rejected gossip: %d %s: %w", peerURL, resp.StatusCode, string(snippet), ErrPeerWriteDisabled)
		}
		return fmt.Errorf("peer %s rejected gossip: %d %s", peerURL, resp.StatusCode, string(snippet))
	}
	return nil
}
