package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// proofBasePath namespaces the frozen proof-plane routes (protocol v1). Document
// gateway routes (blob*) and .well-known stay at root on their own clock. MUST
// match the relay (proofBasePath in routes.go / PROOF_BASE_PATH in relay.ts).
const proofBasePath = "/proof/v1"

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
	DID          string            `json:"did"`
	Protocol     string            `json:"protocol"`
	Version      string            `json:"version"`
	Capabilities RelayCapabilities `json:"capabilities"`
	Profile      string            `json:"profile,omitempty"`

	// Convenience accessors populated after unmarshal.
	Proof   bool `json:"-"`
	Content bool `json:"-"`
	Write   bool `json:"-"`
}

// RelayCapabilities are the nested capability flags from the well-known response.
type RelayCapabilities struct {
	Proof bool `json:"proof"`
	// Write is false on a LITE pull-only node — POST /operations is rejected.
	// Pointer so an older relay that omits the key reads as write-enabled
	// (nil), not write-disabled (see GetRelayInfo).
	Write     *bool `json:"write"`
	Content   bool  `json:"content"`
	Log       bool  `json:"log"`
	Documents bool  `json:"documents"`
}

// IdentityResponse is the response from GET /proof/v1/identities/:did.
type IdentityResponse struct {
	DID     string        `json:"did"`
	HeadCID string        `json:"headCID"`
	State   IdentityState `json:"state"`
}

// IdentityState is the nested state within an identity response.
type IdentityState struct {
	DID            string        `json:"did"`
	IsDeleted      bool          `json:"isDeleted"`
	AuthKeys       []IdentityKey `json:"authKeys"`
	ControllerKeys []IdentityKey `json:"controllerKeys"`
	AssertKeys     []IdentityKey `json:"assertKeys"`
}

// IdentityKey is a key in an identity state response.
type IdentityKey struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// GetIdentityState fetches a typed identity response from the relay.
func (c *Client) GetIdentityState(did string) (*IdentityResponse, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + proofBasePath + "/identities/" + url.PathEscape(did))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("identity not found: %s", did)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var result IdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IngestionResult is a single result from POST /proof/v1/operations.
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
	info.Proof = info.Capabilities.Proof
	info.Content = info.Capabilities.Content
	info.Write = info.Capabilities.Write == nil || *info.Capabilities.Write
	return &info, nil
}

// SubmitOperations submits JWS operations to the relay. Automatically chunks
// into batches of 100 to respect the relay's per-request limit.
func (c *Client) SubmitOperations(operations []string) ([]IngestionResult, error) {
	const maxBatch = 100
	if len(operations) <= maxBatch {
		return c.submitBatch(operations)
	}

	var all []IngestionResult
	for i := 0; i < len(operations); i += maxBatch {
		end := i + maxBatch
		if end > len(operations) {
			end = len(operations)
		}
		results, err := c.submitBatch(operations[i:end])
		if err != nil {
			return all, fmt.Errorf("batch %d-%d: %w", i, end, err)
		}
		all = append(all, results...)
	}
	return all, nil
}

func (c *Client) submitBatch(operations []string) ([]IngestionResult, error) {
	body, _ := json.Marshal(map[string]any{"operations": operations})
	resp, err := c.HTTPClient.Post(c.BaseURL+proofBasePath+"/operations", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("relay returned %d: %s", resp.StatusCode, string(body))
	}

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
	return c.getJSON(proofBasePath + "/identities/" + url.PathEscape(did))
}

// LogEntry is a single entry from a relay /log endpoint.
type LogEntry struct {
	CID      string `json:"cid"`
	JWSToken string `json:"jwsToken"`
}

// logPage is one page of a paginated /log response.
type logPage struct {
	Entries []LogEntry `json:"entries"`
	Cursor  *string    `json:"cursor"`
}

// GetIdentityLog pulls the full operation chain for a DID, following cursors,
// and returns the ordered JWS tokens ready to Ingest. The /identities/{did}
// response carries resolved state, NOT the op log, so fetch must use this.
func (c *Client) GetIdentityLog(did string) ([]string, error) {
	return c.getLog(proofBasePath + "/identities/" + url.PathEscape(did) + "/log")
}

// GetContentLog pulls the full operation chain for a content ID, following
// cursors, and returns the ordered JWS tokens ready to Ingest.
func (c *Client) GetContentLog(contentID string) ([]string, error) {
	return c.getLog(proofBasePath + "/content/" + url.PathEscape(contentID) + "/log")
}

// getLog walks a paginated /log endpoint via the `after` cursor and returns
// every JWS token. Mirrors the relay's own peer-sync pull (peer_client.go /
// relay.go SyncFromPeers): accumulate entries, stop when cursor is null.
func (c *Client) getLog(path string) ([]string, error) {
	var tokens []string
	after := ""
	for {
		u := c.BaseURL + path
		if after != "" {
			u += "?after=" + url.QueryEscape(after)
		}
		resp, err := c.HTTPClient.Get(u)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 404 {
			resp.Body.Close()
			return nil, fmt.Errorf("not found: %s", path)
		}
		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		var page logPage
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
		for _, e := range page.Entries {
			tokens = append(tokens, e.JWSToken)
		}
		// cursor==nil terminates; a non-nil cursor with no entries would loop
		// forever against a misbehaving peer, so stop making progress there too.
		if page.Cursor == nil || len(page.Entries) == 0 {
			break
		}
		after = *page.Cursor
	}
	return tokens, nil
}

// GetContent fetches a content chain from the relay.
func (c *Client) GetContent(contentID string) (map[string]any, error) {
	return c.getJSON(proofBasePath + "/content/" + url.PathEscape(contentID))
}

// GetOperation fetches an operation by CID.
func (c *Client) GetOperation(cid string) (map[string]any, error) {
	return c.getJSON(proofBasePath + "/operations/" + url.PathEscape(cid))
}

// GetCountersignatures fetches countersignatures for an operation CID.
func (c *Client) GetCountersignatures(cid string) (map[string]any, error) {
	return c.getJSON(proofBasePath + "/countersignatures/" + url.PathEscape(cid))
}

// UploadBlob uploads a content blob, keyed by the operation CID that
// introduced the documentCID. The caller must be either the chain creator
// or the signer of the referenced operation.
func (c *Client) UploadBlob(contentID string, operationCID string, data []byte, authToken string) error {
	req, err := http.NewRequest("PUT", c.BaseURL+"/content/"+url.PathEscape(contentID)+"/blob/"+url.PathEscape(operationCID), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+authToken)

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

// DownloadBlob downloads a content blob. If ref is non-empty, downloads blob at
// that specific operation CID (historical version) instead of chain head.
func (c *Client) DownloadBlob(contentID string, authToken string, credential string, ref ...string) ([]byte, string, error) {
	path := "/content/" + url.PathEscape(contentID) + "/blob"
	if len(ref) > 0 && ref[0] != "" {
		path += "/" + url.PathEscape(ref[0])
	}
	req, err := http.NewRequest("GET", c.BaseURL+path, nil)
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
		return nil, fmt.Errorf("not found: %s", path)
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
