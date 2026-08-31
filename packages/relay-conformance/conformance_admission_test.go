package conformance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const noncurrentAdmissionError = "signing key is not in the identity's current state"

type admissionResult struct {
	CID               string `json:"cid"`
	Status            string `json:"status"`
	Error             string `json:"error"`
	DependencyMissing bool   `json:"dependencyMissing"`
}

func postAdmissionOperation(t *testing.T, base, token string) admissionResult {
	t.Helper()
	res := postOperations(t, base, []string{token})
	body := readBody(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("operation admission: status %d body %s", res.StatusCode, body)
	}
	var decoded struct {
		Results []admissionResult `json:"results"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode admission result: %v (body: %s)", err, body)
	}
	if len(decoded.Results) != 1 {
		t.Fatalf("expected one admission result, got %d", len(decoded.Results))
	}
	return decoded.Results[0]
}

// rotateAdmissionIdentity rotates a genesis-head identity onto a fresh key and
// returns the key that took over.
//
// A WHOLE rotation — the new key replaces the genesis key in all three roles —
// because a genesis declares one key in all three, so anything narrower would
// leave the old key current in the roles it did not touch and the "rotated-out"
// half of every assertion below would be false.
//
// It CARRIES a possession envelope, because introducing a key is exactly the
// transition possession gates: without one the incoming key would be void, and
// every operation this helper's callers sign with it would be refused for the
// wrong reason.
func rotateAdmissionIdentity(t *testing.T, base string, id identity) keypair {
	t.Helper()
	// Identity timestamps must strictly increase.
	time.Sleep(2 * time.Millisecond)
	current := newKeypair()
	token, headCID := signIdentityUpdateWithProofs(t, id.headCID,
		[]dfos.MultikeyPublicKey{current.mk},
		[]dfos.MultikeyPublicKey{current.mk},
		[]dfos.MultikeyPublicKey{current.mk},
		[]string{keyProof(t, current.priv, id.did, id.headCID)},
		id.did+"#"+id.controller.keyID,
		id.controller.priv,
	)
	result := postAdmissionOperation(t, base, token)
	if result.Status != "new" {
		t.Fatalf("rotate identity: %s (%s)", result.Status, result.Error)
	}
	_ = headCID
	return current
}

func assertNoncurrentAdmissionRejected(t *testing.T, result admissionResult) {
	t.Helper()
	if result.Status != "rejected" {
		t.Fatalf("expected permanent rejection, got %s", result.Status)
	}
	if !strings.Contains(result.Error, noncurrentAdmissionError) {
		t.Fatalf("error %q does not name %q", result.Error, noncurrentAdmissionError)
	}
	if result.DependencyMissing {
		t.Fatal("rotated-out key rejection must not be dependencyMissing")
	}
}

func TestFreshRotatedKeyAdmissionRejected(t *testing.T) {
	base := relayURL(t)

	t.Run("artifact", func(t *testing.T) {
		id := createIdentity(t, base)
		current := rotateAdmissionIdentity(t, base, id)
		oldToken, _, err := dfos.SignArtifact(id.did,
			map[string]any{"$schema": "conformance/admission/v1", "key": "old"},
			id.did+"#"+id.auth.keyID, id.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertNoncurrentAdmissionRejected(t, postAdmissionOperation(t, base, oldToken))

		currentToken, _, err := dfos.SignArtifact(id.did,
			map[string]any{"$schema": "conformance/admission/v1", "key": "current"},
			id.did+"#"+current.keyID, current.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := postAdmissionOperation(t, base, currentToken); result.Status != "new" {
			t.Fatalf("current-key artifact: %s (%s)", result.Status, result.Error)
		}
	})

	t.Run("countersignature", func(t *testing.T) {
		author := createIdentity(t, base)
		witness := createIdentity(t, base)
		current := rotateAdmissionIdentity(t, base, witness)
		oldToken, _, err := dfos.SignCountersignWithRelation(witness.did, author.genCID, "old",
			witness.did+"#"+witness.auth.keyID, witness.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertNoncurrentAdmissionRejected(t, postAdmissionOperation(t, base, oldToken))

		currentToken, _, err := dfos.SignCountersignWithRelation(witness.did, author.genCID, "current",
			witness.did+"#"+current.keyID, current.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := postAdmissionOperation(t, base, currentToken); result.Status != "new" {
			t.Fatalf("current-key countersignature: %s (%s)", result.Status, result.Error)
		}
	})

	t.Run("content operation", func(t *testing.T) {
		id := createIdentity(t, base)
		current := rotateAdmissionIdentity(t, base, id)
		oldDoc, _, err := dfos.DocumentCID(map[string]any{"type": "post", "key": "old"})
		if err != nil {
			t.Fatal(err)
		}
		oldToken, _, _, err := dfos.SignContentCreate(id.did, oldDoc,
			id.did+"#"+id.auth.keyID, id.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertNoncurrentAdmissionRejected(t, postAdmissionOperation(t, base, oldToken))

		currentDoc, _, err := dfos.DocumentCID(map[string]any{"type": "post", "key": "current"})
		if err != nil {
			t.Fatal(err)
		}
		currentToken, _, _, err := dfos.SignContentCreate(id.did, currentDoc,
			id.did+"#"+current.keyID, current.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := postAdmissionOperation(t, base, currentToken); result.Status != "new" {
			t.Fatalf("current-key content operation: %s (%s)", result.Status, result.Error)
		}
	})
}

func TestCommittedHistorySurvivesRotation(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	content := createContent(t, base, id)
	rotateAdmissionIdentity(t, base, id)

	var chain struct {
		HeadCID string `json:"headCID"`
	}
	chainResponse := getJSON(t, base+"/proof/v1/content/"+content.contentID, &chain)
	if chainResponse.StatusCode != 200 {
		t.Fatalf("committed content no longer served after rotation: status %d", chainResponse.StatusCode)
	}
	if chain.HeadCID != content.genCID {
		t.Fatalf("committed head changed after rotation: got %s want %s", chain.HeadCID, content.genCID)
	}

	operationResponse := getJSON(t, base+"/proof/v1/operations/"+content.genCID, nil)
	if operationResponse.StatusCode != 200 {
		operationResponse.Body.Close()
		t.Fatalf("committed operation no longer served after rotation: status %d", operationResponse.StatusCode)
	}
	operationResponse.Body.Close()
}
