package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

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
	u, err := url.Parse(peerURL + "/identities/" + url.PathEscape(did) + "/log")
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
	u, err := url.Parse(peerURL + "/content/" + url.PathEscape(contentID) + "/log")
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
	u, err := url.Parse(peerURL + "/log")
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
	resp, err := c.client.Post(peerURL+"/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
