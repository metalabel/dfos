package cmd

// The peer DID pin: what a peer NAME means.
//
// Before this, `did` in a `[relays.*]` entry was written once and read by
// nothing — `getPeerDID` had no callers, and a peer whose live well-known
// served a different DID than the pinned one answered `identity fetch`
// repeatedly with no warning. A pin nothing checks is a comment.

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

const (
	pinnedDID = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"
	otherDID  = "did:dfos:cv7n8vkvr64cctf3294h9k4eanhff8z"
)

// captureStderr runs fn with stderr redirected and returns what it wrote. The
// TOFU announcement goes to stderr so a --json stdout stays one document, which
// means stderr is where the assertion has to look.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out)
}

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

// TestPeerPinTOFUOnFirstContact: an entry with no pin is trusted on first use
// and pinned then. The write is announced, because a trust decision this machine
// makes on the operator's behalf is one they are entitled to watch happen.
func TestPeerPinTOFUOnFirstContact(t *testing.T) {
	setupSync(t)
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL}

	stderr := captureStderr(t, func() {
		if _, _, err := getPeerClient("prod"); err != nil {
			t.Fatalf("first contact must not refuse: %v", err)
		}
	})
	if r := cfg.Relays["prod"]; r.DID != pinnedDID {
		t.Fatalf("first contact must pin, got %q", r.DID)
	}
	for _, want := range []string{"prod", pinnedDID, "first contact", "peer repin prod"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the TOFU write must announce %q, got:\n%s", want, stderr)
		}
	}

	// And it holds from then on: the same URL answering as someone else refuses.
	peerPinChecks = map[string]error{}
	peer.did = otherDID
	_, _, err := getPeerClient("prod")
	assertMismatch(t, err, "prod", pinnedDID, otherDID)
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

// TestPeerPinNotWrittenWhenUnreachable: TOFU pins whoever answered, so a peer
// that never answered pins nothing.
func TestPeerPinNotWrittenWhenUnreachable(t *testing.T) {
	setupSync(t)
	cfg.Relays["dead"] = config.RelayConfig{URL: "http://127.0.0.1:1"}

	if _, _, err := getPeerClient("dead"); err != nil {
		t.Fatalf("an unreachable peer must not refuse: %v", err)
	}
	if r := cfg.Relays["dead"]; r.DID != "" {
		t.Fatalf("nothing may be pinned from a contact that did not happen, got %q", r.DID)
	}
}

// TestUnreachablePeerErrorNamesThePeer: Go's transport error leads with
// `Get "<url>": dial tcp …`, which puts quoting and a verb ahead of the one fact
// the operator needs — which of THEIR peers is down.
func TestUnreachablePeerErrorNamesThePeer(t *testing.T) {
	setupSync(t)
	cfg.Relays["dead"] = config.RelayConfig{URL: "http://127.0.0.1:1"}

	c, _, err := getPeerClient("dead")
	if err != nil {
		t.Fatalf("getPeerClient: %v", err)
	}
	if _, err = c.GetRelayInfo(); err == nil {
		t.Fatal("a dead peer must fail")
	}
	msg := err.Error()
	if !strings.HasPrefix(msg, "fetch relay well-known: peer 'dead' (http://127.0.0.1:1) unreachable:") {
		t.Errorf("error must lead with the operation, the peer, and its URL: %q", msg)
	}
	if strings.Contains(msg, `Get "http`) {
		t.Errorf("the url.Error preamble must be stripped: %q", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("the dial detail must survive as the trailing cause: %q", msg)
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

	// The report goes out in full AND the command exits non-zero, so the JSON is
	// unmarshaled here rather than through the helper, which skips that on error.
	var got peerInfoJSON
	stdout, _, err := runCapturingJSON(t, newPeerInfoCmd(), []string{"prod"}, nil)
	if jsonErr := json.Unmarshal([]byte(stdout), &got); jsonErr != nil {
		t.Fatalf("peer info emitted no JSON document: %v\n%s", jsonErr, stdout)
	}
	if got.DID != pinnedDID || got.Pin.Pinned != otherDID || got.Pin.Matches || !got.Pin.Mismatch {
		t.Fatalf("peer info = %+v (raw %s)", got, stdout)
	}
	// It reports in full — and still exits non-zero, so a script that inspects
	// before acting can branch on the same condition every acting command
	// refuses on.
	var exit *ExitCodeError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("a mismatch must exit non-zero, got %v", err)
	}
	// And it must not quietly repair the pin it just reported on.
	if r := cfg.Relays["prod"]; r.DID != otherDID {
		t.Fatalf("peer info moved the pin to %q", r.DID)
	}
}

type peerInfoJSON struct {
	DID        string `json:"did"`
	Content    bool   `json:"content"`
	Proof      bool   `json:"proof"`
	Log        bool   `json:"log"`
	Sync       bool   `json:"sync"`
	Advertises struct {
		Content bool `json:"content"`
		Proof   bool `json:"proof"`
		Log     bool `json:"log"`
	} `json:"advertises"`
	Pin struct {
		Pinned   string `json:"pinned"`
		Matches  bool   `json:"matches"`
		Mismatch bool   `json:"mismatch"`
	} `json:"pin"`
}

// TestPeerInfoLeavesThePolicyFlagsAlone is the one-command silent bypass: with
// the plane flags gating bulk sync, a `peer info` that wrote back the advertised
// values would turn a posture off and on again unprompted. The flags are the
// operator's answer to "what do I use this peer for"; what the peer advertises
// is shown beside them, never over them.
func TestPeerInfoLeavesThePolicyFlagsAlone(t *testing.T) {
	setupSync(t)
	off := false
	peer := newFakePeer(t) // advertises content, proof, log all true
	cfg.Relays["prod"] = config.RelayConfig{
		URL: peer.server.URL, DID: pinnedDID,
		Content: &off, Proof: &off, Sync: &off,
	}

	var got peerInfoJSON
	runJSON(t, newPeerInfoCmd(), []string{"prod"}, &got)

	r := cfg.Relays["prod"]
	if r.Content == nil || *r.Content || r.Proof == nil || *r.Proof {
		t.Fatalf("peer info rewrote the operator's plane flags: %+v", r)
	}
	if r.Sync == nil || *r.Sync {
		t.Fatalf("peer info rewrote the sync switch: %v", r.Sync)
	}
	if r.Log != nil {
		t.Errorf("peer info wrote a log flag the operator never set: %v", *r.Log)
	}

	// Both facts, distinctly: what is configured and what is advertised.
	if got.Content || got.Proof || got.Sync {
		t.Errorf("configured posture must report the operator's values: %+v", got)
	}
	if !got.Advertises.Content || !got.Advertises.Proof || !got.Advertises.Log {
		t.Errorf("the peer's advertisement must be reported too: %+v", got.Advertises)
	}
}

// TestPeerAddPreservesThePolicyFlagsOnReRegistration: same rule for the other
// refresh path. A re-add of the same URL is a refresh, not a posture reset.
func TestPeerAddPreservesThePolicyFlagsOnReRegistration(t *testing.T) {
	setupSync(t)
	off := false
	peer := newFakePeer(t)
	cfg.Relays["prod"] = config.RelayConfig{URL: peer.server.URL, DID: pinnedDID, Proof: &off}

	runJSON(t, newPeerAddCmd(), []string{"prod", peer.server.URL}, nil)
	if r := cfg.Relays["prod"]; r.Proof == nil || *r.Proof {
		t.Fatalf("re-registration rewrote the operator's proof flag: %v", r.Proof)
	}
}
