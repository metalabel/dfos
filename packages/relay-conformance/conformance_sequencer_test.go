// Sequencer conformance tests — cross-batch dependency resolution.
//
// These test the convergence contract: a relay MUST eventually process
// any structurally valid operation whose causal dependencies have been
// processed. Operations submitted before their dependencies should be
// resolved when the dependencies arrive in a later batch.
package conformance

import (
	"encoding/json"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestCrossBatchContentBeforeIdentity submits a content create operation
// before the creator's identity exists, then submits the identity in a
// second batch. The content chain should be resolvable after the second batch.
func TestCrossBatchContentBeforeIdentity(t *testing.T) {
	base := relayURL(t)

	// create identity and content tokens but don't submit yet
	id := createIdentityTokens(t)
	cc := createContentTokens(t, id)

	// batch 1: content op (identity doesn't exist yet) — should be stored but rejected
	res1 := postOperations(t, base, []string{cc.token})
	body1 := readBody(t, res1)
	var result1 struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body1, &result1)
	if len(result1.Results) == 0 {
		t.Fatal("expected a result for content op")
	}
	// status should be "rejected" (dependency missing) — that's fine, it's stored in raw
	if result1.Results[0].Status == "new" {
		t.Fatal("content op should not succeed before identity exists")
	}

	// batch 2: submit identity — sequencer should resolve the pending content op
	res2 := postOperations(t, base, []string{id.token})
	body2 := readBody(t, res2)
	var result2 struct {
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	json.Unmarshal(body2, &result2)
	if len(result2.Results) == 0 || result2.Results[0].Status == "rejected" {
		errMsg := ""
		if len(result2.Results) > 0 {
			errMsg = result2.Results[0].Error
		}
		t.Fatalf("identity should be accepted: %s", errMsg)
	}

	// content chain should now exist (sequencer resolved it)
	resp := getJSON(t, base+"/content/"+cc.contentID, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("content chain should exist after identity arrived: status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestCrossBatchExtensionBeforeGenesis submits a content extension before
// its genesis operation, then submits the genesis. The full chain should
// exist after the second batch.
func TestCrossBatchExtensionBeforeGenesis(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)

	// create genesis and extension tokens
	cc := createContentTokens(t, idTokens{
		did:   id.did,
		token: "",
		auth:  id.auth,
	})

	// create an extension off the genesis
	doc2 := map[string]any{"type": "post", "title": "extension before genesis"}
	docCID2, _, _ := dfos.DocumentCID(doc2)
	kid := id.did + "#" + id.auth.keyID
	extToken, _, _ := dfos.SignContentUpdate(id.did, cc.genCID, docCID2, kid, "", id.auth.priv)

	// batch 1: extension only (genesis doesn't exist yet)
	res1 := postOperations(t, base, []string{extToken})
	body1 := readBody(t, res1)
	var result1 struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body1, &result1)
	if len(result1.Results) > 0 && result1.Results[0].Status == "new" {
		t.Fatal("extension should not succeed before genesis exists")
	}

	// batch 2: genesis
	postOperations(t, base, []string{cc.token}).Body.Close()

	// chain should have 2 ops (genesis + extension resolved by sequencer)
	var chain struct {
		HeadCID string `json:"headCID"`
	}
	resp := getJSON(t, base+"/content/"+cc.contentID, &chain)
	if resp.StatusCode != 200 {
		t.Fatalf("content chain should exist after genesis arrived: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// verify the log has 2 entries
	var log struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
	}
	getJSON(t, base+"/content/"+cc.contentID+"/log", &log)
	if len(log.Entries) != 2 {
		t.Fatalf("expected 2 log entries (genesis + extension), got %d", len(log.Entries))
	}
}

// TestCrossBatchForkBeforeAncestor submits a fork operation before the
// branch it forks from has been synced, then submits the ancestor. Both
// branches should be in the chain log.
func TestCrossBatchForkBeforeAncestor(t *testing.T) {
	base := relayURL(t)
	id := createIdentity(t, base)
	cc := createContent(t, base, id)

	kid := id.did + "#" + id.auth.keyID

	// create update A (extends genesis)
	docA := map[string]any{"type": "post", "title": "branch A"}
	docCIDA, _, _ := dfos.DocumentCID(docA)
	tokenA, cidA, _ := dfos.SignContentUpdate(id.did, cc.genCID, docCIDA, kid, "", id.auth.priv)

	// create update B (also extends genesis — fork)
	time.Sleep(10 * time.Millisecond)
	docB := map[string]any{"type": "post", "title": "branch B"}
	docCIDB, _, _ := dfos.DocumentCID(docB)
	tokenB, _, _ := dfos.SignContentUpdate(id.did, cc.genCID, docCIDB, kid, "", id.auth.priv)

	// create update C that extends A (deeper branch)
	time.Sleep(10 * time.Millisecond)
	docC := map[string]any{"type": "post", "title": "extends branch A"}
	docCIDC, _, _ := dfos.DocumentCID(docC)
	tokenC, _, _ := dfos.SignContentUpdate(id.did, cidA, docCIDC, kid, "", id.auth.priv)

	// batch 1: submit C first (depends on A which hasn't been submitted)
	res1 := postOperations(t, base, []string{tokenC})
	body1 := readBody(t, res1)
	var result1 struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	json.Unmarshal(body1, &result1)

	// batch 2: submit A and B together
	postOperations(t, base, []string{tokenA, tokenB}).Body.Close()

	// chain should have 4 ops: genesis, A, B (fork), C (resolved by sequencer)
	var log struct {
		Entries []struct {
			CID string `json:"cid"`
		} `json:"entries"`
	}
	getJSON(t, base+"/content/"+cc.contentID+"/log", &log)
	if len(log.Entries) != 4 {
		t.Fatalf("expected 4 log entries (genesis + A + B fork + C sequenced), got %d", len(log.Entries))
	}
}

// --- helpers ---

type idTokens struct {
	did   string
	token string
	auth  keypair
}

type contentTokens struct {
	token     string
	contentID string
	genCID    string
}

func createIdentityTokens(t *testing.T) idTokens {
	t.Helper()
	ctrl := newKeypair()
	auth := newKeypair()
	token, did, _, err := dfos.SignIdentityCreate(
		[]dfos.MultikeyPublicKey{ctrl.mk},
		[]dfos.MultikeyPublicKey{auth.mk},
		[]dfos.MultikeyPublicKey{},
		ctrl.keyID, ctrl.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	return idTokens{did: did, token: token, auth: auth}
}

func createContentTokens(t *testing.T, id idTokens) contentTokens {
	t.Helper()
	doc := map[string]any{"type": "post", "title": "sequencer test content"}
	docCID, _, _ := dfos.DocumentCID(doc)
	kid := id.did + "#" + id.auth.keyID
	token, contentID, genCID, err := dfos.SignContentCreate(id.did, docCID, kid, "", id.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	return contentTokens{token: token, contentID: contentID, genCID: genCID}
}
