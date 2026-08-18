package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func signingBase(t *testing.T) string {
	t.Helper()
	base := relayURL(t)
	var meta struct {
		Capabilities struct {
			Signing bool `json:"signing"`
		} `json:"capabilities"`
	}
	resp := getJSON(t, base+"/.well-known/dfos-relay", &meta)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /.well-known/dfos-relay: status %d", resp.StatusCode)
	}
	if !meta.Capabilities.Signing {
		t.Skip("relay does not advertise capabilities.signing: true — skipping signing conformance")
	}
	return base
}

type signingFixture struct {
	requester  identity
	subject    identity
	request    string
	cid        string
	expiresAt  string
	response   string
	credential string
}

func signingPost(t *testing.T, url string, body any, auth string) *http.Response {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if auth != "" {
		req.Header.Set("authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func signingFixtureFor(t *testing.T, base, role string) signingFixture {
	t.Helper()
	requester := createIdentity(t, base)
	subject := createIdentity(t, base)
	claim, _, err := dfos.SignCreditClaim(subject.did, "cv7n8vkvr64cctf3294h9k4eanhff8z", role, subject.auth.keyID, subject.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.Split([]byte(claim), []byte("."))
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(5 * time.Minute).UTC()
	request, cid, err := dfos.BuildSignRequest(
		requester.did, subject.did, "did:dfos:credit-claim", payload, expires,
		requester.auth.keyID, requester.auth.priv, dfos.SignRequestOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := dfos.CreateCredential(
		subject.did, requester.did, subject.did+"#"+subject.auth.keyID,
		"mailbox:"+subject.did[len("did:dfos:"):], "deposit", 10*time.Minute, subject.auth.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signingFixture{requester, subject, request, cid, expires.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05.000Z"), claim, credential}
}

func assertSigningStatus(t *testing.T, resp *http.Response, want int) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("status %d, want %d (body: %s)", resp.StatusCode, want, body)
	}
	return body
}

func TestSigningHappyPath(t *testing.T) {
	base := signingBase(t)
	f := signingFixtureFor(t, base, "signing-conformance")
	deposit := map[string]any{"request": f.request, "credential": f.credential}
	createdBody := assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", deposit, ""), http.StatusCreated)
	var created struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(createdBody, &created); err != nil || created.ExpiresAt != f.expiresAt {
		t.Fatalf("deposit expiresAt: got %q, want %q (body: %s)", created.ExpiresAt, f.expiresAt, createdBody)
	}
	assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", deposit, ""), http.StatusOK)

	token := authToken(t, base, f.subject)
	req, _ := http.NewRequest(http.MethodGet, base+"/signing/v0/requests", nil)
	req.Header.Set("authorization", "Bearer "+token)
	poll, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var pending struct {
		Requests []struct {
			CID string `json:"cid"`
		} `json:"requests"`
		Next *string `json:"next"`
	}
	body := assertSigningStatus(t, poll, http.StatusOK)
	if err := json.Unmarshal(body, &pending); err != nil || len(pending.Requests) != 1 || pending.Requests[0].CID != f.cid || pending.Next != nil {
		t.Fatalf("unexpected mailbox poll: %s", body)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil || string(envelope["next"]) != "null" || envelope["cursor"] != nil {
		t.Fatalf("unexpected mailbox pagination envelope: %s", body)
	}

	respond := map[string]string{"response": f.response}
	responseURL := base + "/signing/v0/requests/" + f.cid + "/response"
	assertSigningStatus(t, signingPost(t, responseURL, respond, ""), http.StatusCreated)
	assertSigningStatus(t, signingPost(t, responseURL, respond, ""), http.StatusOK)
	var fetched map[string]any
	fetch := getJSON(t, responseURL, &fetched)
	if fetch.StatusCode != http.StatusOK || fetched["status"] != "responded" || fetched["response"] != f.response {
		t.Fatalf("unexpected response fetch: status=%d body=%v", fetch.StatusCode, fetched)
	}
}

func TestSigningDepositRejections(t *testing.T) {
	base := signingBase(t)
	f := signingFixtureFor(t, base, "signing-rejections")
	third := createIdentity(t, base)
	resource := "mailbox:" + f.subject.did[len("did:dfos:"):]
	tests := []struct {
		name       string
		credential string
		status     int
	}{
		{"root-not-subject", mustCredential(t, third, f.requester.did, resource, "deposit"), http.StatusForbidden},
		{"aud-mismatch", mustCredential(t, f.subject, third.did, resource, "deposit"), http.StatusForbidden},
		{"mailbox-wildcard", mustCredential(t, f.subject, f.requester.did, "mailbox:*", "deposit"), http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", map[string]string{"request": f.request, "credential": tc.credential}, ""), tc.status)
		})
	}

	unknown := createIdentityOffline(t)
	claim, _, _ := dfos.SignCreditClaim(unknown.did, "cv7n8vkvr64cctf3294h9k4eanhff8z", "unknown", unknown.auth.keyID, unknown.auth.priv)
	payload, _ := base64.RawURLEncoding.DecodeString(string(bytes.Split([]byte(claim), []byte("."))[1]))
	request, _, _ := dfos.BuildSignRequest(f.requester.did, unknown.did, "did:dfos:credit-claim", payload, time.Now().Add(time.Minute), f.requester.auth.keyID, f.requester.auth.priv, dfos.SignRequestOptions{})
	credential := mustCredential(t, unknown.identity, f.requester.did, "mailbox:"+unknown.did[len("did:dfos:"):], "deposit")
	assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", map[string]any{"request": request, "credential": credential, "chain": []string{unknown.genesisToken}}, ""), http.StatusNotFound)

	expired, _, _ := dfos.BuildSignRequest(f.requester.did, f.subject.did, "did:dfos:credit-claim", payload, time.Now().Add(-time.Second), f.requester.auth.keyID, f.requester.auth.priv, dfos.SignRequestOptions{CreatedAt: time.Now().Add(-time.Minute)})
	assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", map[string]string{"request": expired, "credential": f.credential}, ""), http.StatusBadRequest)
}

func TestSigningPollAuthAndDecline(t *testing.T) {
	base := signingBase(t)
	f := signingFixtureFor(t, base, "signing-decline")
	assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests", map[string]string{"request": f.request, "credential": f.credential}, ""), http.StatusCreated)
	resp, err := http.Get(base + "/signing/v0/requests")
	if err != nil {
		t.Fatal(err)
	}
	assertSigningStatus(t, resp, http.StatusUnauthorized)
	declineURL := base + "/signing/v0/requests/" + f.cid + "/decline"
	assertSigningStatus(t, signingPost(t, declineURL, nil, ""), http.StatusNoContent)
	var status map[string]any
	get := getJSON(t, base+"/signing/v0/requests/"+f.cid+"/response", &status)
	if get.StatusCode != http.StatusOK || status["status"] != "declined" {
		t.Fatalf("unexpected declined status: %v", status)
	}
	assertSigningStatus(t, signingPost(t, base+"/signing/v0/requests/"+f.cid+"/response", map[string]string{"response": f.response}, ""), http.StatusCreated)
}

func mustCredential(t *testing.T, issuer identity, aud, resource, action string) string {
	t.Helper()
	token, err := dfos.CreateCredential(issuer.did, aud, issuer.did+"#"+issuer.auth.keyID, resource, action, 10*time.Minute, issuer.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type offlineIdentity struct {
	identity
	genesisToken string
}

func createIdentityOffline(t *testing.T) offlineIdentity {
	t.Helper()
	ctrl := newKeypair()
	auth := newKeypair()
	token, did, cid, err := dfos.SignIdentityCreate([]dfos.MultikeyPublicKey{ctrl.mk}, []dfos.MultikeyPublicKey{auth.mk}, nil, ctrl.keyID, ctrl.priv)
	if err != nil {
		t.Fatal(err)
	}
	return offlineIdentity{identity: identity{did: did, genCID: cid, headCID: cid, controller: ctrl, auth: auth}, genesisToken: token}
}
