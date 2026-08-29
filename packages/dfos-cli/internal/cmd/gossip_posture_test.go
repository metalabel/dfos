package cmd

// The local-only posture: a one-shot `dfos` command writes to the local relay
// and puts nothing on a peer.
//
// The bug these cover shipped in v0.40.0. Ingesting an operation runs the
// sequencer; the sequencer gossips newly sequenced ops to every peer whose
// `gossip` switch is not explicitly false; an absent switch means on. So
// `identity create` with no --peer pushed the new operation to every registered
// peer — about a quarter of the time, because the pushes are goroutines racing
// process exit, and invisibly, because the command reports publishedTo:null and
// never learns what its own relay did on the way out.
//
// Every test here counts the peer's /proof/v1/operations hits. "Did not gossip"
// and "gossiped and the peer said nothing" are the same output otherwise — the
// same reason the sync gate tests count log pulls.

import (
	"strings"
	"testing"
	"time"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
)

// gossipSettle is how long a test waits for the fire-and-forget push goroutines
// before reading the counter. A leak is nondeterministic in production because
// the process exits first; in-process there is nothing to race, so this only has
// to outlast a loopback round trip.
const gossipSettle = 300 * time.Millisecond

// reopenAsCommand drops whatever relay the harness opened and lets getRelay()
// open the next one. That is the production path — config.toml is loaded first
// and the relay is opened lazily afterwards — so the peer set and the OPTIONS
// under test are the ones a real invocation runs on, not a test's own.
func reopenAsCommand(t *testing.T) *localrelay.LocalRelay {
	t.Helper()
	if localRelayInstance != nil {
		localRelayInstance.Close()
		localRelayInstance = nil
	}
	lr, err := getRelay()
	if err != nil {
		t.Fatalf("open the local relay the way a command does: %v", err)
	}
	t.Cleanup(func() {
		if localRelayInstance == lr {
			localRelayInstance = nil
		}
		lr.Close()
	})
	return lr
}

// TestOneShotCommandsDoNotGossip is B8. The peer is registered the ordinary way
// — `peer add` with no switches, which writes no `gossip` key at all — so this
// is precisely the configuration the per-peer default left leaking.
//
// The commands run in a loop because one push landing is enough to be a leak and
// the old behavior did not land every time.
func TestOneShotCommandsDoNotGossip(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	peer := newFakePeer(t)
	// No Gossip field: absent means on, which is the whole point.
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: pinnedDID}
	reopenAsCommand(t)

	createVault(t, "personal")

	const rounds = 6
	for i := 0; i < rounds; i++ {
		// identity create — the reported case.
		did := createIdentity(t, "alice"+strings.Repeat("x", i), storeA)
		if did == "" {
			t.Fatalf("round %d: identity create produced no DID", i)
		}
		// identity update — a second mutating shape through the same Ingest.
		rotateAuth(t)
		// content create — the document plane's mutating command.
		var created struct {
			ContentID   string `json:"contentId"`
			PublishedTo string `json:"publishedTo"`
		}
		runJSON(t, newContentCreateCmd(),
			[]string{writeTempDoc(t, `{"$schema":"https://schemas.dfos.com/post/v1","body":"local"}`)}, &created)
		if created.ContentID == "" {
			t.Fatalf("round %d: content create produced no content id", i)
		}
		if created.PublishedTo != "" {
			t.Fatalf("round %d: a local create reports publishing to %q", i, created.PublishedTo)
		}
	}

	time.Sleep(gossipSettle)
	if n := peer.opsHits.Load(); n != 0 {
		t.Fatalf("local commands pushed %d operation batch(es) to a peer nobody named", n)
	}
	// And the peer was not otherwise contacted behind the operator's back: no
	// bulk pull either, since nothing asked for one.
	if n := peer.logHits.Load(); n != 0 {
		t.Errorf("local commands pulled the peer's log %d time(s)", n)
	}
}

// TestGossipStaysOffEvenWithTheSwitchOn: the posture is not a default a peer can
// override. `gossip = true` in config.toml is honored by `serve` and ignored by
// every one-shot command — a local write is local whatever the peer entry says.
func TestGossipStaysOffEvenWithTheSwitchOn(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	peer := newFakePeer(t)
	on := true
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: pinnedDID, Gossip: &on}
	reopenAsCommand(t)

	createVault(t, "personal")
	createIdentity(t, "alice", storeA)
	rotateAuth(t)

	time.Sleep(gossipSettle)
	if n := peer.opsHits.Load(); n != 0 {
		t.Fatalf("gossip = true made a one-shot command push %d batch(es); publishing is the explicit path", n)
	}
}

// TestServeStillGossipsWhenConfigured is the control, and the half that keeps
// this a posture rather than a removal. `serve` is the mesh participant: opened
// with Gossip on, each peer's own switch decides, and a peer left ungated still
// receives what the sequencer produces.
//
// Without this, "no peer was pushed to" would pass on a relay that had simply
// lost the ability to gossip at all.
func TestServeStillGossipsWhenConfigured(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: pinnedDID}

	createVault(t, "personal")
	log := chainLog(t, lr, createIdentity(t, "alice", storeA))

	// Reopen the way `dfos serve` does — same config peers, gossip on — and give
	// it an operation to sequence.
	serveRelay := reopenAsServe(t)
	mustIngest(t, serveRelay, log)

	if !waitFor(func() bool { return peer.opsHits.Load() > 0 }) {
		t.Fatal("serve gossiped nothing to an ungated peer — the mesh direction is gone, not gated")
	}
}

// TestServeHonorsAGatedPeer: `gossip = false` still means what it said. serve
// reads the switch; it does not push to a peer the config took out.
func TestServeHonorsAGatedPeer(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	off := false
	gated, open := newFakePeer(t), newFakePeer(t)
	cfg.Relays["gated"] = config.RelayConfig{URL: gated.server.URL, DID: pinnedDID, Gossip: &off}
	cfg.Relays["open"] = config.RelayConfig{URL: open.server.URL, DID: pinnedDID}

	createVault(t, "personal")
	log := chainLog(t, lr, createIdentity(t, "alice", storeA))

	serveRelay := reopenAsServe(t)
	mustIngest(t, serveRelay, log)

	if !waitFor(func() bool { return open.opsHits.Load() > 0 }) {
		t.Fatal("the ungated peer received nothing")
	}
	if n := gated.opsHits.Load(); n != 0 {
		t.Errorf("a gossip = false peer received %d batch(es)", n)
	}
}

// chainLog reads an identity's operation log out of a relay.
func chainLog(t *testing.T, lr *localrelay.LocalRelay, did string) []string {
	t.Helper()
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("chain for %s: %v", did, err)
	}
	return chain.Log
}

// mustIngest feeds operations to a relay and fails on a rejection — a rejected
// op is never gossiped, so a silent one would make the control pass for the
// wrong reason.
func mustIngest(t *testing.T, lr *localrelay.LocalRelay, log []string) {
	t.Helper()
	for _, res := range lr.Relay.Ingest(log) {
		if res.Status == "rejected" {
			t.Fatalf("the serve relay rejected %s: %s", res.CID, res.Error)
		}
	}
}

// reopenAsServe opens the local relay with the options `dfos serve` passes: the
// same config peers, with gossip on so each peer's own switch decides.
func reopenAsServe(t *testing.T) *localrelay.LocalRelay {
	t.Helper()
	if localRelayInstance != nil {
		localRelayInstance.Close()
		localRelayInstance = nil
	}
	lr, err := localrelay.Open(cfg, &localrelay.Options{
		DBPath: t.TempDir() + "/serve.db",
		Logger: quietRelayLogger(),
		Gossip: true,
	})
	if err != nil {
		t.Fatalf("open the local relay the way serve does: %v", err)
	}
	localRelayInstance = lr
	t.Cleanup(func() {
		if localRelayInstance == lr {
			localRelayInstance = nil
		}
		lr.Close()
	})
	return lr
}

// waitFor polls until cond holds or the settle window elapses.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}
