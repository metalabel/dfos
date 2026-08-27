package conformance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

type relayIdentityKey struct {
	ID                 string `json:"id"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type relayIdentityState struct {
	State struct {
		IsDeleted      bool               `json:"isDeleted"`
		AuthKeys       []relayIdentityKey `json:"authKeys"`
		AssertKeys     []relayIdentityKey `json:"assertKeys"`
		ControllerKeys []relayIdentityKey `json:"controllerKeys"`
	} `json:"state"`
}

func relayCurrentKeyResolver(base string, authOnly bool) dfos.KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		hash := strings.Index(kid, "#")
		if hash < 1 || hash == len(kid)-1 {
			return nil, fmt.Errorf("kid must be a DID URL")
		}
		did, keyID := kid[:hash], kid[hash+1:]
		resp, err := http.Get(base + "/proof/v1/identities/" + did)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("identity resolution status %d: %s", resp.StatusCode, body)
		}
		var resolved relayIdentityState
		if err := json.NewDecoder(resp.Body).Decode(&resolved); err != nil {
			return nil, err
		}
		if resolved.State.IsDeleted {
			return nil, fmt.Errorf("identity is deleted")
		}
		keys := append([]relayIdentityKey(nil), resolved.State.AuthKeys...)
		if !authOnly {
			keys = append(keys, resolved.State.AssertKeys...)
			keys = append(keys, resolved.State.ControllerKeys...)
		}
		for _, key := range keys {
			if key.ID != keyID {
				continue
			}
			decoded, err := dfos.DecodeMultikey(key.PublicKeyMultibase)
			if err != nil {
				return nil, err
			}
			return ed25519.PublicKey(decoded), nil
		}
		return nil, fmt.Errorf("key is not present in current identity state")
	}
}

func signSiwdResponse(t *testing.T, typ, kid string, payload []byte, privateKey ed25519.PrivateKey) string {
	t.Helper()
	headerJSON, err := json.Marshal(dfos.JWSHeader{Alg: "EdDSA", Typ: typ, Kid: kid})
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	body := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := header + "." + body
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertSiwdErrorResponse(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	body := assertSigningStatus(t, resp, want)
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded) != 1 {
		t.Fatalf("status %d must use uniform error body, got %s", want, body)
	}
	var message string
	if err := json.Unmarshal(decoded["error"], &message); err != nil || message == "" {
		t.Fatalf("status %d must carry a non-empty string error, got %s", want, body)
	}
}

func verifySiwdMailboxArtifact(t *testing.T, base, token string, expected dfos.SiwdChallenge, acceptanceWindow time.Duration) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("SIWD artifact is not a compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode SIWD header: %v", err)
	}
	var rawHeader map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &rawHeader); err != nil {
		t.Fatalf("decode SIWD header JSON: %v", err)
	}
	var alg, typ, kid string
	if err := json.Unmarshal(rawHeader["alg"], &alg); err != nil || alg != "EdDSA" {
		t.Fatalf("SIWD alg gate: got %q", alg)
	}
	if err := json.Unmarshal(rawHeader["typ"], &typ); err != nil || typ != dfos.SiwdJWSTyp {
		t.Fatalf("SIWD typ gate: got %q", typ)
	}
	if _, present := rawHeader["crit"]; present {
		t.Fatal("SIWD header carries forbidden crit")
	}
	if _, present := rawHeader["jwk"]; present {
		t.Fatal("SIWD header carries forbidden jwk")
	}
	if _, present := rawHeader["x5c"]; present {
		t.Fatal("SIWD header carries forbidden x5c")
	}
	if err := json.Unmarshal(rawHeader["kid"], &kid); err != nil || kid == "" {
		t.Fatal("SIWD header is missing kid")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode SIWD payload: %v", err)
	}
	challenge, err := dfos.ParseSiwdChallenge(payloadBytes)
	if err != nil {
		t.Fatalf("strict SIWD payload parse: %v", err)
	}
	if challenge.Domain != expected.Domain || challenge.Nonce != expected.Nonce || challenge.Timestamp != expected.Timestamp {
		t.Fatalf("SIWD challenge mismatch: got %+v want %+v", challenge, expected)
	}
	hash := strings.Index(kid, "#")
	if hash < 1 {
		t.Fatal("SIWD kid is not a DID URL")
	}
	signerDID := kid[:hash]
	if expected.DID != nil && (*expected.DID != signerDID || challenge.DID == nil || *challenge.DID != signerDID) {
		t.Fatalf("SIWD DID binding mismatch: kid=%s challenge=%+v", kid, challenge)
	}

	publicKey, err := relayCurrentKeyResolver(base, true)(kid)
	if err != nil {
		t.Fatalf("resolve current SIWD auth key: %v", err)
	}
	if _, _, err := dfos.VerifyJWS(token, publicKey); err != nil {
		t.Fatalf("SIWD profile/signature verification: %v", err)
	}
	issuedAt, err := dfos.ParseProtocolTimestamp(challenge.Timestamp)
	if err != nil {
		t.Fatalf("parse SIWD timestamp: %v", err)
	}
	now := time.Now().UTC()
	if now.Sub(issuedAt) > acceptanceWindow {
		t.Fatalf("SIWD artifact is stale: issued=%s now=%s window=%s", issuedAt, now, acceptanceWindow)
	}
	if issuedAt.Sub(now) > time.Minute {
		t.Fatalf("SIWD artifact is future-dated: issued=%s now=%s", issuedAt, now)
	}
}

func TestSiwdMailboxProfile(t *testing.T) {
	base := signingBase(t)
	subject := createIdentity(t, base)
	requester := createIdentity(t, base)
	acceptanceWindow := 5 * time.Minute
	createdAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := createdAt.Add(acceptanceWindow)
	statement := "Sign in through the DFOS mailbox"
	challenge := dfos.SiwdChallenge{
		Domain:    "siwd-conformance.test",
		Nonce:     "siwd-mailbox-conformance-nonce",
		Timestamp: createdAt.Format("2006-01-02T15:04:05.000Z"),
		Statement: &statement,
		DID:       &subject.did,
	}

	request, cid, err := dfos.BuildSiwdSignRequest(
		requester.did, subject.did, challenge, expiresAt, acceptanceWindow,
		requester.auth.keyID, requester.auth.priv, dfos.SignRequestOptions{CreatedAt: createdAt},
	)
	if err != nil {
		t.Fatalf("BuildSiwdSignRequest: %v", err)
	}
	credential, err := dfos.CreateCredential(
		subject.did, requester.did, subject.did+"#"+subject.auth.keyID,
		"mailbox:"+subject.did[len("did:dfos:"):], "deposit", 10*time.Minute, subject.auth.priv,
	)
	if err != nil {
		t.Fatalf("issue mailbox deposit credential: %v", err)
	}
	deposit := map[string]string{"request": request, "credential": credential}
	assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", deposit), http.StatusCreated)

	pollRequest, _ := http.NewRequest(http.MethodGet, base+"/signing/v0/requests", nil)
	signRequest(t, base, pollRequest, signerFor(subject), nil, "")
	pollResponse, err := http.DefaultClient.Do(pollRequest)
	if err != nil {
		t.Fatal(err)
	}
	var pending struct {
		Requests []struct {
			CID     string `json:"cid"`
			Request string `json:"request"`
		} `json:"requests"`
	}
	pollBody := assertSigningStatus(t, pollResponse, http.StatusOK)
	if err := json.Unmarshal(pollBody, &pending); err != nil || len(pending.Requests) != 1 {
		t.Fatalf("unexpected SIWD mailbox poll: %s", pollBody)
	}
	if pending.Requests[0].CID != cid || pending.Requests[0].Request != request {
		t.Fatalf("SIWD mailbox returned a different request: %s", pollBody)
	}

	validated, err := dfos.ValidateSiwdSignRequest(
		pending.Requests[0].Request, subject.did, acceptanceWindow,
		relayCurrentKeyResolver(base, false), time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("ValidateSiwdSignRequest: %v", err)
	}
	wantPayload, _ := dfos.SiwdSigningInput(challenge)
	if !bytes.Equal(validated.PayloadBytes, wantPayload) {
		t.Fatal("validated SIWD request did not preserve the original challenge octets")
	}

	responseURL := base + "/signing/v0/requests/" + cid + "/response"
	wrongTyp := signSiwdResponse(
		t, "did:dfos:credential", subject.did+"#"+subject.auth.keyID,
		validated.PayloadBytes, subject.auth.priv,
	)
	assertSiwdErrorResponse(
		t,
		signingPost(t, responseURL, map[string]string{"response": wrongTyp}),
		http.StatusBadRequest,
	)

	artifact := signSiwdResponse(
		t, dfos.SiwdJWSTyp, subject.did+"#"+subject.auth.keyID,
		validated.PayloadBytes, subject.auth.priv,
	)
	assertSigningStatus(
		t,
		signingPost(t, responseURL, map[string]string{"response": artifact}),
		http.StatusCreated,
	)
	var fetched struct {
		Status   string `json:"status"`
		Response string `json:"response"`
	}
	fetch := getJSON(t, responseURL, &fetched)
	if fetch.StatusCode != http.StatusOK || fetched.Status != "responded" || fetched.Response != artifact {
		t.Fatalf("unexpected SIWD response fetch: status=%d body=%+v", fetch.StatusCode, fetched)
	}
	verifySiwdMailboxArtifact(t, base, fetched.Response, challenge, acceptanceWindow)
}
