package relay

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestReadThroughAdmitsAnOpRevokedAfterIt pins read-through on the historical
// side of the admission split. A peer's log is committed history: a delegated
// update whose credential was revoked later must land, exactly as the scheduled
// peer sweep and the TS twin's read-through admit it. Under current admission
// the update is a PERMANENT rejection, which deletes the raw op — the walk never
// repeats and the relay serves a truncated chain from then on.
func TestReadThroughAdmitsAnOpRevokedAfterIt(t *testing.T) {
	now := time.Now()

	// the peer holds the whole chain: genesis, then the delegated update.
	peer := seedAsOfChain(t, -30*time.Minute)
	update, updateCID := signBackdatedDelegatedUpdate(t, peer.delegate, peer.genesisOpCID,
		newDocCID(t, "delegated"), peer.credential, now.Add(-25*time.Minute))
	if res := IngestOperations([]string{update}, peer.store); res[0].Status != "new" {
		t.Fatalf("seed peer update: %s (%s)", res[0].Status, res[0].Error)
	}

	// the local relay holds the identities and a revocation dated AFTER the
	// update, and no content chain at all.
	local := NewMemoryStore()
	IngestOperations([]string{peer.creator.token, peer.delegate.token}, local)
	revocation, _ := peer.signRevocationAt(t, now.Add(-20*time.Minute))
	if res := IngestOperations([]string{revocation}, local); res[0].Status != "new" {
		t.Fatalf("seed local revocation: %s (%s)", res[0].Status, res[0].Error)
	}

	relay, err := NewRelay(RelayOptions{
		Store:      local,
		PeerClient: newMockPeerClient(peer.store, 0),
		Peers:      []PeerConfig{{URL: "http://peer-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(relay.Handler())
	defer srv.Close()

	var body map[string]any
	resp := getJSON(t, srv.URL+"/proof/v1/content/"+peer.contentID, &body)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	chain, err := local.GetContentChain(peer.contentID)
	if err != nil || chain == nil {
		t.Fatalf("GetContentChain: %v (chain %v)", err, chain)
	}
	if len(chain.Log) != 2 {
		t.Fatalf("read-through dropped the delegated update: log has %d ops, want 2", len(chain.Log))
	}
	if chain.State.HeadCID != updateCID {
		t.Fatalf("head is %s, want the delegated update %s", chain.State.HeadCID, updateCID)
	}
}
