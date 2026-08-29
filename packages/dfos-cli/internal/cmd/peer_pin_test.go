package cmd

// The peer DID pin: what a peer NAME means.
//
// Before this, `did` in a `[relays.*]` entry was written once and read by
// nothing — `getPeerDID` had no callers, and a peer whose live well-known
// served a different DID than the pinned one answered `identity fetch`
// repeatedly with no warning. A pin nothing checks is a comment.

import (
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

const (
	pinnedDID = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
	otherDID  = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"
)

// assertMismatch checks an error is the pin refusal: it names the peer, both
// DIDs, and the one command that resolves it.
func assertMismatch(t *testing.T, err error, peer, pinned, live string) {
	t.Helper()
	if err == nil {
		t.Fatal("a moved pin must refuse, got no error")
	}
	for _, want := range []string{peer, pinned, live, "peer repin " + peer} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name %q:\n%v", want, err)
		}
	}
}

// TestPeerPinRefusesAFetchThroughAMovedPin is the live report: the pinned DID
// predates the peer's re-derive, and every fetch through it succeeded silently.
func TestPeerPinRefusesAFetchThroughAMovedPin(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t) // serves pinnedDID
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: otherDID}

	_, _, err := getPeerClient("prod")
	assertMismatch(t, err, "prod", otherDID, pinnedDID)

	// requirePeer is the other funnel (login, recover, relay call) and answers
	// the same way.
	relayFlag = "prod"
	defer func() { relayFlag = "" }()
	_, _, err = requirePeer("")
	assertMismatch(t, err, "prod", otherDID, pinnedDID)
}

// TestPeerPinRefusesASync: bulk sync pulls by URL rather than through a client,
// so it checks the pin itself — and fails the run rather than skipping the peer.
func TestPeerPinRefusesASync(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	applyPeers(t, map[string]config.RelayConfig{"prod": {URL: peer.server.URL, DID: otherDID}})

	_, err := runSync(t, "")
	assertMismatch(t, err, "prod", otherDID, pinnedDID)
	if peer.logHits.Load() != 0 {
		t.Error("a refused sync must not have pulled anything")
	}

	peerPinChecks = map[string]error{}
	_, err = runSync(t, "prod")
	assertMismatch(t, err, "prod", otherDID, pinnedDID)
}

// TestPeerPinMatchingPassesThrough: the pin is not a tax on the normal case.
func TestPeerPinMatchingPassesThrough(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	applyPeers(t, map[string]config.RelayConfig{"prod": {URL: peer.server.URL, DID: pinnedDID}})

	if _, _, err := getPeerClient("prod"); err != nil {
		t.Fatalf("a matching pin must not refuse: %v", err)
	}
	if _, err := runSync(t, ""); err != nil {
		t.Fatalf("a matching pin must not refuse a sync: %v", err)
	}
	if peer.logHits.Load() == 0 {
		t.Error("the peer must still be polled")
	}
}

// TestPeerPinIsMemoizedPerProcess: one well-known round-trip per peer per
// invocation, however many clients the command builds.
func TestPeerPinIsMemoizedPerProcess(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: pinnedDID}

	for range 3 {
		if _, _, err := getPeerClient("prod"); err != nil {
			t.Fatalf("getPeerClient: %v", err)
		}
	}
	if got := peer.infoHits.Load(); got != 1 {
		t.Fatalf("well-known fetched %d times, want 1", got)
	}
}

// TestPeerPinAbsentMeansUnpinned: an entry with no `did` is unpinned by choice.
// Nothing verifies it, and — the half that makes it a choice — nothing writes a
// pin behind the operator's back, so an unpinned entry cannot start failing at
// a moment nobody picked.
func TestPeerPinAbsentMeansUnpinned(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL}

	if _, _, err := getPeerClient("prod"); err != nil {
		t.Fatalf("an unpinned peer must not refuse: %v", err)
	}
	if got := peer.infoHits.Load(); got != 0 {
		t.Errorf("an unpinned peer costs no well-known fetch, got %d", got)
	}
	if r := cfg.Relays["prod"]; r.DID != "" {
		t.Errorf("first contact must not write a pin, got %q", r.DID)
	}
}

// TestPeerPinUnreachableIsNotAMismatch: an offline peer is a reachability
// problem, reported by the operation the caller was running — not a pin error.
func TestPeerPinUnreachableIsNotAMismatch(t *testing.T) {
	setupSync(t)
	cfg.Relays["dead"] = config.RelayConfig{URL: "http://127.0.0.1:1", DID: pinnedDID}

	if _, _, err := getPeerClient("dead"); err != nil {
		t.Fatalf("an unreachable peer must not read as a moved pin: %v", err)
	}
}

// TestPeerRepinMovesThePin is the affordance: one command, naming both DIDs.
func TestPeerRepinMovesThePin(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: otherDID}

	if _, _, err := getPeerClient("prod"); err == nil {
		t.Fatal("precondition: the moved pin must refuse first")
	}

	var got struct {
		DID      string `json:"did"`
		Previous string `json:"previous"`
		Changed  bool   `json:"changed"`
	}
	runJSON(t, newPeerRepinCmd(), []string{"prod"}, &got)
	if got.DID != pinnedDID || got.Previous != otherDID || !got.Changed {
		t.Fatalf("repin result = %+v", got)
	}
	if r := cfg.Relays["prod"]; r.DID != pinnedDID {
		t.Fatalf("config pin = %q, want %q", r.DID, pinnedDID)
	}
	// And the refusal lifts in the same process: repin clears the memo.
	if _, _, err := getPeerClient("prod"); err != nil {
		t.Fatalf("after repin the peer must be usable: %v", err)
	}
}

// TestPeerRepinPinsAnUnpinnedEntry covers the hand-written `[relays.x]` with
// only a url: repin is how it acquires a pin, deliberately.
func TestPeerRepinPinsAnUnpinnedEntry(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL}

	var got struct {
		DID      string `json:"did"`
		Previous string `json:"previous"`
		Changed  bool   `json:"changed"`
	}
	runJSON(t, newPeerRepinCmd(), []string{"prod"}, &got)
	if got.DID != pinnedDID || got.Previous != "" || !got.Changed {
		t.Fatalf("repin result = %+v", got)
	}
}

// TestPeerAddRefusesToMoveAPin: re-registering the same URL is a refresh, and a
// refresh must not be a silent way to accept a different relay identity.
func TestPeerAddRefusesToMoveAPin(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: otherDID}

	err := newPeerAddCmd().RunE(newPeerAddCmd(), []string{"prod", peer.server.URL})
	assertMismatch(t, err, "prod", otherDID, pinnedDID)
	if r := cfg.Relays["prod"]; r.DID != otherDID {
		t.Errorf("a refused add must leave the pin alone, got %q", r.DID)
	}
}

// TestPeerAddRepointsToANewURL: a changed URL is a new registration, not a
// moved pin — there is no claim that the old identity should be at the new
// address.
func TestPeerAddRepointsToANewURL(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: "https://old.example", DID: otherDID}

	runJSON(t, newPeerAddCmd(), []string{"prod", peer.server.URL}, nil)
	if r := cfg.Relays["prod"]; r.DID != pinnedDID || r.URL != peer.server.URL {
		t.Fatalf("re-pointed entry = %+v", r)
	}
}

// TestPeerInfoReportsAMismatchWithoutRefusing: inspection answers the question,
// action refuses. A `peer info` that errored on the mismatch would be a
// diagnostic that hides the diagnosis.
func TestPeerInfoReportsAMismatchWithoutRefusing(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: otherDID}

	var got struct {
		DID string `json:"did"`
		Pin struct {
			Pinned   string `json:"pinned"`
			Matches  bool   `json:"matches"`
			Mismatch bool   `json:"mismatch"`
		} `json:"pin"`
	}
	runJSON(t, newPeerInfoCmd(), []string{"prod"}, &got)
	if got.DID != pinnedDID || got.Pin.Pinned != otherDID || got.Pin.Matches || !got.Pin.Mismatch {
		t.Fatalf("peer info = %+v", got)
	}
	// And it must not quietly repair the pin it just reported on.
	if r := cfg.Relays["prod"]; r.DID != otherDID {
		t.Fatalf("peer info moved the pin to %q", r.DID)
	}
}
