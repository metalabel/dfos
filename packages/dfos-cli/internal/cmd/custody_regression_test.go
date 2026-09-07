package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func TestCustodyExistingKeyAdoptionSurvivesPrune(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	pub := plantKey(t, store, "temporary")
	account := keyAccount(pub)
	if err := store.RenameKey("temporary", account); err != nil {
		t.Fatal(err)
	}
	result := &proveResult{}
	fileAdoptedKey(&presentationAnswer{DID: didWithNoChainHere, KeyID: protocol.DeriveKeyID(pub)}, &ceremony{DID: didWithNoChainHere}, &candidateKey{Account: account, PublicKey: pub}, result)
	if result.FilingError != "" {
		t.Fatal(result.FilingError)
	}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if e := entryFor(t, ledger, account); e.Status != statusDeclared || e.Prunable || e.DID != didWithNoChainHere {
		t.Fatalf("adoption lost: %+v", e)
	}
	runPrune(t, true)
	if !store.HasKey(account) {
		t.Fatal("pruned adopted key")
	}
}

func TestCustodyCandidateCorpusScanRefusesRemoval(t *testing.T) {
	store, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	chain, err := localRelayInstance.Relay.GetIdentity(did)
	if err != nil {
		t.Fatal(err)
	}
	pub := chain.State.ControllerKeys[0].PublicKeyMultibase
	if err := store.RenameKey(keyAccount(pub), candidateAccountPrefix+pub); err != nil {
		t.Fatal(err)
	}
	cfg.Identities = map[string]config.IdentityConfig{}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if e := entryFor(t, ledger, candidateAccountPrefix+pub); e.Status != statusDeclared || e.DID != did {
		t.Fatalf("candidate not placed: %+v", e)
	}
	removeRefusal(t, pub)
}

func TestCustodySyncPromotesFetchedCandidate(t *testing.T) {
	store, _, source := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	chain, err := source.Relay.GetIdentity(did)
	if err != nil {
		t.Fatal(err)
	}
	pub := chain.State.ControllerKeys[0].PublicKeyMultibase
	if err := store.RenameKey(keyAccount(pub), candidateAccountPrefix+pub); err != nil {
		t.Fatal(err)
	}
	custodyHTTP(t, source.Relay.Handler())
	cfg.Identities = map[string]config.IdentityConfig{}
	cfg.Relays["source"] = config.RelayConfig{URL: "http://custody.test"}
	// The explicit sync opens a fresh database at the config directory.
	localRelayInstance = nil
	syncHarnessRelay = source
	t.Cleanup(func() { syncHarnessRelay = nil })
	if _, err := runSync(t, "source"); err != nil {
		t.Fatal(err)
	}
	if !store.HasKey(keyAccount(pub)) || store.HasKey(candidateAccountPrefix+pub) {
		t.Fatal("sync did not promote candidate")
	}
	receipt, err := readKeyAdoption(pub)
	if err != nil || receipt == nil || receipt.DID != did {
		t.Fatalf("receipt: %+v, %v", receipt, err)
	}
	localRelayInstance = nil
	lr, err := getRelay()
	if err != nil {
		t.Fatal(err)
	}
	defer lr.Close()
	removeRefusal(t, pub)
}

func TestCustodyVoidCandidateIsNotPromoted(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	pub := plantKey(t, store, "temporary")
	account := candidateAccountPrefix + pub
	if err := store.RenameKey("temporary", account); err != nil {
		t.Fatal(err)
	}
	state := protocol.IdentityState{VoidKeys: []protocol.VoidKeyMembership{{Key: protocol.MultikeyPublicKey{ID: protocol.DeriveKeyID(pub), PublicKeyMultibase: pub}, Role: "auth"}}}
	if err := promoteCandidateKeys(didWithNoChainHere, state); err != nil {
		t.Fatal(err)
	}
	receipt, err := readKeyAdoption(pub)
	if err != nil || receipt != nil || !store.HasKey(account) || store.HasKey(keyAccount(pub)) {
		t.Fatalf("void key promoted: %+v, %v", receipt, err)
	}
}

func TestCustodyReceiptDoesNotOverrideChainAttribution(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil {
		t.Fatal(err)
	}
	key := chain.State.ControllerKeys[0]
	if err := recordKeyAdoption(key.PublicKeyMultibase, didWithNoChainHere, "key_3333333333333333333333333333333"); err != nil {
		t.Fatal(err)
	}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if e := entryFor(t, ledger, keyAccount(key.PublicKeyMultibase)); e.DID != did || e.KeyID != key.ID {
		t.Fatalf("receipt overrode chain: %+v", e)
	}
}

func TestCustodyPinnedPeerCannotOmitDID(t *testing.T) {
	setupSync(t)
	custodyHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	cfg.Relays["prod"] = config.RelayConfig{URL: "http://custody.test", DID: pinnedDID}
	assertMismatch(t, verifyPeerPin("prod"), "prod", pinnedDID, "")
	assertMismatch(t, verifyPeerPin("prod"), "prod", pinnedDID, "")
}

func TestCustodyServePinPreservesConcurrentConfigChange(t *testing.T) {
	setupSync(t)
	contacted := make(chan struct{})
	resume := make(chan struct{})
	custodyHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(contacted)
		<-resume
		json.NewEncoder(w).Encode(map[string]string{"did": pinnedDID})
	}))
	cfg.Relays["prod"] = config.RelayConfig{URL: "http://custody.test"}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	saved := make(chan error, 1)
	go func() {
		<-contacted
		latest, err := config.Load()
		if err == nil {
			latest.Identities["concurrent"] = config.IdentityConfig{DID: otherDID}
			err = config.Save(latest)
		}
		saved <- err
		close(resume)
	}()
	if err := verifyConfiguredPeerPins(); err != nil {
		t.Fatal(err)
	}
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
	latest, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if latest.Identities["concurrent"].DID != otherDID || latest.Relays["prod"].DID != pinnedDID {
		t.Fatalf("lost config change: %+v", latest)
	}
}

// Run HTTP handlers in memory; these regressions need no listening sockets.
type custodyTransport struct{ handler http.Handler }

func (c custodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
func custodyHTTP(t *testing.T, handler http.Handler) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = custodyTransport{handler: handler}
	t.Cleanup(func() { http.DefaultTransport = previous })
}
