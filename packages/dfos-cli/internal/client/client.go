package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// proofBasePath namespaces the frozen proof-plane routes (protocol v1). Document
// gateway routes (blob*) and .well-known stay at root on their own clock. MUST
// match the relay (proofBasePath in routes.go / PROOF_BASE_PATH in relay.ts).
const proofBasePath = "/proof/v1"

// Signer is the key material this client signs identity proofs with.
//
// ONE PROOF PER REQUEST. An identity proof binds one (method, host, path,
// bodyHash, iat), so there is no mint-once token to cache and re-present — the
// client signs each authenticated request as it makes it. See specs/API-AUTH.md.
type Signer struct {
	// Kid is the signing key's full DID URL. Its DID portion IS the principal:
	// the identity proof names no other party.
	Kid string
	// PrivateKey is the ed25519 private key for Kid.
	PrivateKey ed25519.PrivateKey
}

// Client is an HTTP client for a DFOS web relay.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	// Signer is optional key material for the routes that need an identity
	// proof. Nil means this client speaks anonymously — which every public read
	// accepts, and which is also the default admission mode for ingestion.
	//
	// It is a field rather than a constructor argument because resolving a key
	// can hit the OS keychain: a command that only reads public routes must
	// never pay that cost, so each call site attaches a signer at the point it
	// already holds the key material.
	Signer *Signer
}

// New creates a new relay client.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// normalizeAuthority is the `host` member API-AUTH binds: the lowercase
// authority with the port OMITTED when it is the scheme's default (https:443,
// http:80) and carried otherwise.
//
// The default-port drop is not cosmetic. The TS twin derives its host from
// WHATWG `URL.host`, which already drops :443 and :80, and a relay compares a
// proof's `host` byte for byte against its own configured authority. A Go signer
// that kept the explicit default port would therefore sign a host no normally
// configured relay matches — a 401 the two stacks disagree about, from a URL
// spelling the operator is entitled to use.
func normalizeAuthority(scheme, hostport string) string {
	host := strings.ToLower(hostport)
	switch strings.ToLower(scheme) {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// authority is the peer's host[:port] — what the relay checks a proof's `host`
// member against.
func (c *Client) authority() (string, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("peer URL %q has no authority to bind a proof to", c.BaseURL)
	}
	return normalizeAuthority(u.Scheme, u.Host), nil
}

// originForm returns the origin-form request target this client will put on the
// request line for path — the byte string a proof's `path` member binds. Derived
// from the same parsed URL the request uses, so no normalization can fork the
// signed bytes from the sent ones.
func (c *Client) originForm(path string) (string, error) {
	u, err := url.Parse(c.BaseURL + path)
	if err != nil {
		return "", fmt.Errorf("build request target for %q: %w", path, err)
	}
	return u.RequestURI(), nil
}

// newJTI returns a fresh per-request uniqueness member: 128 bits from crypto/rand.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// AuthorizationFor builds the "DFOS <jws>" Authorization value binding one
// request to signer's bare identity. path is the request path (query included)
// as it will be sent; body is the request body octets, nil for a bodyless call.
//
// jti attaches the per-request uniqueness member. Write-shaped surfaces —
// operation submission and blob upload — REQUIRE it; read-shaped surfaces ignore
// it, so attaching one is never wrong, only sometimes unnecessary.
func (c *Client) AuthorizationFor(signer *Signer, method, path string, body []byte, jti bool) (string, error) {
	target, err := c.originForm(path)
	if err != nil {
		return "", err
	}
	return c.identityProof(signer, method, target, body, jti)
}

// identityProof signs one request. target is already origin-form.
func (c *Client) identityProof(signer *Signer, method, target string, body []byte, jti bool) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("no signing key for an authenticated request")
	}
	host, err := c.authority()
	if err != nil {
		return "", err
	}
	opts := protocol.IdentityProofOptions{Body: body}
	if jti {
		id, err := newJTI()
		if err != nil {
			return "", err
		}
		opts.ExtraMembers = protocol.ProofExtraMembers{"jti": id}
	}
	proof, err := protocol.BuildIdentityProof(method, host, target, signer.Kid, signer.PrivateKey, opts)
	if err != nil {
		return "", fmt.Errorf("sign identity proof: %w", err)
	}
	return "DFOS " + proof, nil
}

// authorize attaches an identity proof to an already-built request. The proof
// binds req's own method, target, and body — never a template or a normalized
// form of them.
func (c *Client) authorize(req *http.Request, signer *Signer, body []byte, jti bool) error {
	value, err := c.identityProof(signer, req.Method, req.URL.RequestURI(), body, jti)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", value)
	return nil
}

// RelayInfo is the response from /.well-known/dfos-relay.
type RelayInfo struct {
	DID          string            `json:"did"`
	Protocol     string            `json:"protocol"`
	Version      string            `json:"version"`
	Capabilities RelayCapabilities `json:"capabilities"`
	Profile      string            `json:"profile,omitempty"`
	// Ingestion is the advertised admission mode for POST /operations:
	// "open", "proof-required", or "closed". Empty on a relay too old to
	// advertise it. The advertisement is a hint — the policy decision at
	// submission time is the authority.
	Ingestion string `json:"ingestion,omitempty"`

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

// submitBatch posts one batch, ANONYMOUS FIRST.
//
// Ingestion admission is a relay-local policy, and the default is open — so the
// common submission carries no proof and costs no signature and no well-known
// probe. A relay that wants an identity says so with a 403 at the admission
// ladder (either "proof-required" or a policy weighing the principal), and that
// refusal is answerable: if this client holds a signer, it retries the batch
// ONCE carrying a proof. A second refusal is the caller's answer.
func (c *Client) submitBatch(operations []string) ([]IngestionResult, error) {
	body, _ := json.Marshal(map[string]any{"operations": operations})
	results, status, err := c.postOperations(body, nil)
	if err == nil || status != http.StatusForbidden || c.Signer == nil {
		return results, err
	}
	results, _, retryErr := c.postOperations(body, c.Signer)
	if retryErr != nil {
		return nil, retryErr
	}
	return results, nil
}

// postOperations makes one POST /operations call, optionally signed. The
// returned status is the relay's, so the caller can tell an admission refusal
// from any other failure.
func (c *Client) postOperations(body []byte, signer *Signer) ([]IngestionResult, int, error) {
	path := proofBasePath + "/operations"
	req, err := http.NewRequest("POST", c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if signer != nil {
		// Ingestion is write-shaped: the proof MUST carry jti.
		if err := c.authorize(req, signer, body, true); err != nil {
			return nil, 0, err
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("relay returned %d: %s", resp.StatusCode, string(errBody))
	}

	var result struct {
		Results []IngestionResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, err
	}
	return result.Results, resp.StatusCode, nil
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
	Next    *string    `json:"next"`
	Cursor  *string    `json:"cursor"` // deprecated fallback for older relays
}

// Resume prefers the shared `next` field and falls back to the deprecated
// `cursor` alias emitted by older relays.
func (p logPage) Resume() *string {
	if p.Next != nil {
		return p.Next
	}
	return p.Cursor
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
// relay.go SyncFromPeers): accumulate entries, stop when next is null.
func (c *Client) getLog(path string) ([]string, error) {
	var tokens []string
	after := ""
	restarted := false
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
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, notFoundError(path, body)
		}
		if resp.StatusCode == http.StatusBadRequest && after != "" && !restarted {
			resp.Body.Close()
			// Per-chain cursors are relay-local and may become invalid after a
			// relay wipe. Restart this walk once, discarding the partial prefix;
			// a second rejection is surfaced below.
			tokens = nil
			after = ""
			restarted = true
			continue
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
		// next==nil terminates; a non-nil resume value with no entries would loop
		// forever against a misbehaving peer, so stop making progress there too.
		resume := page.Resume()
		if resume == nil || len(page.Entries) == 0 {
			break
		}
		after = *resume
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
	const maxPages = 10000

	countersignatures := []any{}
	after := ""
	path := proofBasePath + "/countersignatures/" + url.PathEscape(cid)
	for page := 0; page < maxPages; page++ {
		pagePath := path
		if after != "" {
			pagePath += "?after=" + url.QueryEscape(after)
		}
		resp, err := c.getJSON(pagePath)
		if err != nil {
			return nil, err
		}
		if pageCountersignatures, ok := resp["countersignatures"].([]any); ok {
			countersignatures = append(countersignatures, pageCountersignatures...)
		}
		next, ok := resp["next"].(string)
		if !ok || next == "" {
			return map[string]any{"countersignatures": countersignatures}, nil
		}
		after = next
	}
	return nil, fmt.Errorf("countersignatures pagination exceeded %d pages", maxPages)
}

// UploadBlob uploads a content blob, keyed by the operation CID that
// introduced the documentCID. The caller must be either the chain creator
// or the signer of the referenced operation, and must set c.Signer: blob upload
// is write-shaped, so it needs an identity proof carrying jti.
func (c *Client) UploadBlob(contentID string, operationCID string, data []byte) error {
	req, err := http.NewRequest("PUT", c.BaseURL+"/content/"+url.PathEscape(contentID)+"/blob/"+url.PathEscape(operationCID), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if err := c.authorize(req, c.Signer, data, true); err != nil {
		return err
	}

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
//
// A publicly granted blob reads anonymously; anything else needs an identity
// proof, so c.Signer is attached when set. The read is read-shaped — no jti,
// the freshness window alone. An accompanying credential rides X-Credential:
// the proof is the AuthN half, the credential the authorization half.
func (c *Client) DownloadBlob(contentID string, credential string, ref ...string) ([]byte, string, error) {
	path := "/content/" + url.PathEscape(contentID) + "/blob"
	if len(ref) > 0 && ref[0] != "" {
		path += "/" + url.PathEscape(ref[0])
	}
	req, err := http.NewRequest("GET", c.BaseURL+path, nil)
	if err != nil {
		return nil, "", err
	}
	if c.Signer != nil {
		if err := c.authorize(req, c.Signer, nil, false); err != nil {
			return nil, "", err
		}
	}
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
		body, _ := io.ReadAll(resp.Body)
		return nil, notFoundError(path, body)
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

// notFoundError distinguishes a routed record miss from a relay that does not
// serve the route at all. Both remain ordinary errors beginning with the legacy
// "not found: <path>" prefix for caller compatibility.
func notFoundError(path string, body []byte) error {
	var envelope struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Error != "" {
		return fmt.Errorf("not found: %s — relay says: %s", path, envelope.Error)
	}
	return fmt.Errorf("not found: %s — no error envelope in the response; this relay may not serve this route at all (older version or capability off)", path)
}
