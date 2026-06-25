package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ErrPeerWriteDisabled is wrapped into the error returned by SubmitOperations
// when a peer rejects a gossip push with HTTP 501 — it advertises
// capabilities.write == false (a pull-only / lite node). Callers use errors.Is
// to distinguish this permanent capability signal from a transient push failure
// and stop gossiping to the peer rather than retrying it every cycle.
var ErrPeerWriteDisabled = errors.New("peer is write-disabled (pull-only)")

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
