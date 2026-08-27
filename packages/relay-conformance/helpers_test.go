package conformance

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
	"os"
	"strings"
	"testing"

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

// ---------------------------------------------------------------------------
// identity proofs
// ---------------------------------------------------------------------------

// relayAuthority is the host an identity proof must bind for requests to base.
//
// It is the relay's OWN configured authority, not anything read off a request,
// so a relay reached through a proxy or a tunnel is served by a host string the
// test cannot derive from the URL it dials. RELAY_AUTHORITY names that host
// explicitly; the default — the URL's own authority — is right for a relay
// dialed directly, which is every harness in this package.
func relayAuthority(t *testing.T, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		t.Fatalf("relay URL %q has no authority to bind a proof to", base)
	}
	if v := os.Getenv("RELAY_AUTHORITY"); v != "" {
		// Normalized against the dialed URL's scheme: RELAY_AUTHORITY names the
		// same relay, so its default port is the same one the relay drops.
		return normalizeAuthority(u.Scheme, v)
	}
	return normalizeAuthority(u.Scheme, u.Host)
}

// normalizeAuthority is the `host` member API-AUTH binds: the lowercase
// authority with the port OMITTED when it is the scheme's default (https:443,
// http:80) and carried otherwise.
//
// The default-port drop is not cosmetic. A relay compares a proof's `host` byte
// for byte against its own configured authority, and the TS stack derives that
// host from WHATWG `URL.host`, which already drops :443 and :80. A suite that
// kept the explicit default port would sign a host no normally configured relay
// matches, and report a conformance failure that is the harness's.
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

// proofSigner is the key material a request signs its identity proof with.
//
// THERE IS NO TOKEN TO MINT ONCE. An identity proof binds one (method, host,
// path, bodyHash, iat), so every authenticated request signs its own — these
// helpers carry the key, not a reusable artifact.
type proofSigner struct {
	kid  string
	priv ed25519.PrivateKey
}

// signerFor returns the signer for an identity's current auth key.
func signerFor(id identity) *proofSigner {
	return signerForKey(id, id.auth)
}

// signerForKey returns a signer for a specific key of an identity — including
// one that has been rotated out, which is how the rotation tests prove a
// non-current key stops authenticating.
func signerForKey(id identity, kp keypair) *proofSigner {
	return &proofSigner{kid: id.did + "#" + kp.keyID, priv: kp.priv}
}

// newJTI returns a fresh per-request uniqueness member.
func newJTI(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate jti: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// buildProof signs one identity proof for an exact request. target is the
// origin-form request target — path plus query, byte for byte as it will be
// sent. jti is attached when non-empty; write-shaped surfaces require it.
func buildProof(t *testing.T, base string, s *proofSigner, method, target string, body []byte, jti string) string {
	t.Helper()
	opts := dfos.IdentityProofOptions{Body: body}
	if jti != "" {
		opts.ExtraMembers = dfos.ProofExtraMembers{"jti": jti}
	}
	proof, err := dfos.BuildIdentityProof(method, relayAuthority(t, base), target, s.kid, s.priv, opts)
	if err != nil {
		t.Fatalf("BuildIdentityProof(%s %s): %v", method, target, err)
	}
	return proof
}

// signRequest attaches an identity proof to req, binding req's own method,
// target, and body. A nil signer leaves the request anonymous.
func signRequest(t *testing.T, base string, req *http.Request, s *proofSigner, body []byte, jti string) {
	t.Helper()
	if s == nil {
		return
	}
	req.Header.Set("authorization", "DFOS "+buildProof(t, base, s, req.Method, req.URL.RequestURI(), body, jti))
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
	token, contentID, opCID, err := dfos.SignContentCreate(id.did, docCID, kid, id.auth.priv)
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
	resp, err := http.Post(base+"/proof/v1/operations", "application/json", bytes.NewReader(payload))
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

// putBlob uploads a blob. Blob upload is WRITE-SHAPED, so its proof carries a
// fresh jti; a nil signer sends the request anonymous.
func putBlob(t *testing.T, base, contentID, operationCID string, s *proofSigner, data []byte) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob/%s", base, contentID, operationCID)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	signRequest(t, base, req, s, data, newJTI(t))
	req.Header.Set("content-type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT blob: %v", err)
	}
	return resp
}

// putBlobWithProof uploads a blob under an ALREADY-BUILT proof, so a test can
// present the same proof twice and watch the replay cache refuse the second.
func putBlobWithProof(t *testing.T, base, contentID, operationCID, proof string, data []byte) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob/%s", base, contentID, operationCID)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	if proof != "" {
		req.Header.Set("authorization", "DFOS "+proof)
	}
	req.Header.Set("content-type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT blob: %v", err)
	}
	return resp
}

// getBlob downloads a blob. Optional ref is a path segment (operation CID). A
// blob read is READ-SHAPED — the freshness window alone, no jti.
func getBlob(t *testing.T, base, contentID string, s *proofSigner, ref ...string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob", base, contentID)
	if len(ref) > 0 && ref[0] != "" {
		url += "/" + ref[0]
	}
	req, _ := http.NewRequest("GET", url, nil)
	signRequest(t, base, req, s, nil, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET blob: %v", err)
	}
	return resp
}

// getBlobWithCred downloads a blob under an identity proof plus a read
// credential — the AuthN half and the authorization half, not two competing
// claims.
func getBlobWithCred(t *testing.T, base, contentID string, s *proofSigner, credential string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("%s/content/%s/blob", base, contentID)
	req, _ := http.NewRequest("GET", url, nil)
	signRequest(t, base, req, s, nil, "")
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
