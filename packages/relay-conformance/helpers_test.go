package conformance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// relayURL returns the target relay URL from RELAY_URL env var, or skips the test.
func relayURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("RELAY_URL")
	if url == "" {
		t.Skip("RELAY_URL not set — skipping conformance test")
	}
	return url
}

// keypair holds a fresh ed25519 keypair and its derived identifiers.
type keypair struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
	mk    dfos.MultikeyPublicKey
}

func newKeypair() keypair {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := dfos.GenerateKeyID()
	mk := dfos.NewMultikeyPublicKey(keyID, pub)
	return keypair{priv: priv, pub: pub, keyID: keyID, mk: mk}
}

// identity holds a created identity with its signing keys.
type identity struct {
	did        string
	genCID     string
	headCID    string
	controller keypair
	auth       keypair
}

// createIdentity creates a fresh identity on the relay.
func createIdentity(t *testing.T, base string) identity {
	t.Helper()
	ctrl := newKeypair()
	auth := newKeypair()

	token, did, opCID, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID,
		ctrl.priv,
	)
	if err != nil {
		t.Fatalf("SignIdentityCreate: %v", err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create identity: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	return identity{
		did:        did,
		genCID:     opCID,
		headCID:    opCID,
		controller: ctrl,
		auth:       auth,
	}
}

// contentChain holds a created content chain.
type contentChain struct {
	contentID   string
	genCID      string
	headCID     string
	documentCID string
	document    map[string]any
}

// createContent creates a content chain for an identity.
func createContent(t *testing.T, base string, id identity) contentChain {
	t.Helper()
	doc := map[string]any{"type": "post", "title": "hello world", "body": "test content"}
	docCID, _, err := dfos.DocumentCID(doc)
	if err != nil {
		t.Fatalf("DocumentCID: %v", err)
	}

	kid := id.did + "#" + id.auth.keyID
	token, contentID, opCID, err := dfos.SignContentCreate(id.did, docCID, kid, "", id.auth.priv)
	if err != nil {
		t.Fatalf("SignContentCreate: %v", err)
	}

	res := postOperations(t, base, []string{token})
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create content: status %d, body: %s", res.StatusCode, body)
	}
	res.Body.Close()

	return contentChain{
		contentID:   contentID,
		genCID:      opCID,
		headCID:     opCID,
		documentCID: docCID,
		document:    doc,
	}
}

// authToken creates an auth token for the identity targeting the relay.
func authToken(t *testing.T, base string, id identity) string {
	t.Helper()
	relayDID := getRelayDID(t, base)
	kid := id.did + "#" + id.auth.keyID
	token, err := dfos.CreateAuthToken(id.did, relayDID, kid, 5*time.Minute, id.auth.priv)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	return token
}

// authTokenWithKey creates an auth token using a specific key.
func authTokenWithKey(t *testing.T, base string, id identity, kp keypair) string {
	t.Helper()
	relayDID := getRelayDID(t, base)
	kid := id.did + "#" + kp.keyID
	token, err := dfos.CreateAuthToken(id.did, relayDID, kid, 5*time.Minute, kp.priv)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	return token
}

// getRelayDID fetches the relay DID from /.well-known/dfos-relay.
func getRelayDID(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/dfos-relay")
	if err != nil {
		t.Fatalf("GET /.well-known/dfos-relay: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		DID string `json:"did"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode relay metadata: %v", err)
	}
	return body.DID
}

// postOperations POSTs operations to the relay.
func postOperations(t *testing.T, base string, operations []string) *http.Response {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"operations": operations})
	resp, err := http.Post(base+"/operations", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /operations: %v", err)
	}
	return resp
}

// getJSON performs a GET and decodes JSON.
func getJSON(t *testing.T, url string, v any) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	if v != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err := json.Unmarshal(body, v); err != nil {
			t.Fatalf("decode %s: %v (body: %s)", url, err, string(body))
		}
		// replace body so caller can still check status
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp
}

// putBlob uploads a blob.
func putBlob(t *testing.T, base, contentID, operationCID, authTok string, data []byte) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob/%s", base, contentID, operationCID)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	req.Header.Set("authorization", "Bearer "+authTok)
	req.Header.Set("content-type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT blob: %v", err)
	}
	return resp
}

// getBlob downloads a blob. Optional ref is a path segment (operation CID).
func getBlob(t *testing.T, base, contentID, authTok string, ref ...string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob", base, contentID)
	if len(ref) > 0 && ref[0] != "" {
		url += "/" + ref[0]
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("authorization", "Bearer "+authTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET blob: %v", err)
	}
	return resp
}

// getBlobWithCred downloads a blob with an auth token and a read credential.
func getBlobWithCred(t *testing.T, base, contentID, authTok, credential string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob", base, contentID)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("authorization", "Bearer "+authTok)
	req.Header.Set("x-credential", credential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET blob with cred: %v", err)
	}
	return resp
}

// readBody reads and returns the response body.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}
