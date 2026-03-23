package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for a DFOS web relay.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// New creates a new relay client.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// RelayInfo is the response from /.well-known/dfos-relay.
type RelayInfo struct {
	DID      string `json:"did"`
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
}

// IngestionResult is a single result from POST /operations.
type IngestionResult struct {
	CID     string `json:"cid"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	Kind    string `json:"kind,omitempty"`
	ChainID string `json:"chainId,omitempty"`
}

// GetRelayInfo fetches relay metadata.
func (c *Client) GetRelayInfo() (*RelayInfo, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/.well-known/dfos-relay")
	if err != nil {
		return nil, fmt.Errorf("connect to relay: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("relay returned %d", resp.StatusCode)
	}
	var info RelayInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SubmitOperations submits JWS operations to the relay.
func (c *Client) SubmitOperations(operations []string) ([]IngestionResult, error) {
	body, _ := json.Marshal(map[string]any{"operations": operations})
	resp, err := c.HTTPClient.Post(c.BaseURL+"/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Results []IngestionResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Results, nil
}

// GetIdentity fetches an identity chain from the relay.
func (c *Client) GetIdentity(did string) (map[string]any, error) {
	return c.getJSON("/identities/" + did)
}

// GetContent fetches a content chain from the relay.
func (c *Client) GetContent(contentID string) (map[string]any, error) {
	return c.getJSON("/content/" + contentID)
}

// GetBeacon fetches the latest beacon for a DID.
func (c *Client) GetBeacon(did string) (map[string]any, error) {
	return c.getJSON("/beacons/" + did)
}

// GetOperation fetches an operation by CID.
func (c *Client) GetOperation(cid string) (map[string]any, error) {
	return c.getJSON("/operations/" + cid)
}

// GetCountersignatures fetches countersignatures for a CID.
func (c *Client) GetCountersignatures(cid string) (map[string]any, error) {
	return c.getJSON("/countersignatures/" + cid)
}

// UploadBlob uploads a content blob.
func (c *Client) UploadBlob(contentID string, documentCID string, data []byte, authToken string) error {
	req, err := http.NewRequest("PUT", c.BaseURL+"/content/"+contentID+"/blob", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("X-Document-CID", documentCID)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (%d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// DownloadBlob downloads a content blob.
func (c *Client) DownloadBlob(contentID string, authToken string, credential string) ([]byte, string, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/content/"+contentID+"/blob", nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	if credential != "" {
		req.Header.Set("X-Credential", credential)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("download failed (%d): %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	docCID := resp.Header.Get("X-Document-CID")
	return data, docCID, nil
}

// DoRaw performs a raw HTTP request and returns status, headers, body.
func (c *Client) DoRaw(method, path string, body []byte, headers map[string]string) (int, http.Header, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, respBody, nil
}

func (c *Client) getJSON(path string) (map[string]any, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("not found")
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
