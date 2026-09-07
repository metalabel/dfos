package cmd

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func TestCustodyTailAdoptionSurvivesWithoutVaultOrChain(t *testing.T) {
	store, _, _ := setupDevices(t)
	keys = store
	pub := plantKey(t, store, "temporary")
	account := candidateAccountPrefix + pub
	if err := store.RenameKey("temporary", account); err != nil {
		t.Fatal(err)
	}
	if got, held := heldKeyAccount(didWithNoChainHere, "key_3333333333333333333333333333333", pub); !held || got != account {
		t.Fatalf("candidate not held: %s", got)
	}
	keyID := "key_3333333333333333333333333333333"
	result := &proveResult{}
	fileAdoptedKey(&presentationAnswer{DID: didWithNoChainHere, KeyID: keyID}, &ceremony{DID: didWithNoChainHere}, &candidateKey{Account: account, PublicKey: pub}, result)
	if result.FilingError != "" {
		t.Fatal(result.FilingError)
	}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatal(err)
	}
	e := entryFor(t, ledger, keyAccount(pub))
	if e.Prunable || e.DID != didWithNoChainHere {
		t.Fatalf("adopted key lost: %+v", e)
	}
	if err := os.WriteFile(keyAdoptionPath(pub), nil, 0600); err != nil {
		t.Fatal(err)
	}
	ledger, err = buildKeyLedger()
	if err != nil {
		t.Fatal(err)
	}
	if e := entryFor(t, ledger, keyAccount(pub)); e.Prunable || e.Status != statusUnreadable {
		t.Fatalf("corrupt receipt ignored: %+v", e)
	}
}

func TestCustodyTailFetchPromotesCandidate(t *testing.T) {
	store, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	log := heldLog(t, did)
	verified, err := protocol.VerifyIdentityChain(log)
	if err != nil {
		t.Fatal(err)
	}
	pub := verified.State.ControllerKeys[0].PublicKeyMultibase
	if err := store.RenameKey(keyAccount(pub), candidateAccountPrefix+pub); err != nil {
		t.Fatal(err)
	}
	newMachineRelay(t)
	oracle := newFakeOracle(t)
	oracle.logsByDID[did] = log
	oracle.registerAsPeer(t, "oracle")
	cmd := newIdentityFetchCmd()
	mustSetFlag(t, cmd, "peer", "oracle")
	if _, _, err := runCapturing(t, cmd, []string{did}); err != nil {
		t.Fatal(err)
	}
	if !store.HasKey(keyAccount(pub)) || store.HasKey(candidateAccountPrefix+pub) {
		t.Fatal("fetch did not promote candidate")
	}
}

func TestCustodyTailVaultUnavailable(t *testing.T) {
	store, _, _ := setupDevices(t)
	createVault(t, "personal")
	did := createIdentity(t, "alice", store)
	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	pub := chain.State.ControllerKeys[0].PublicKeyMultibase
	path := filepath.Join(config.ConfigDir(), "vaults", "broken.toml")
	if err := os.WriteFile(path, []byte("["), 0600); err != nil {
		t.Fatal(err)
	}
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatal(err)
	}
	e := entryFor(t, ledger, keyAccount(pub))
	if ledger.Limit == "" || e.VaultsUnavailable == "" {
		t.Fatalf("missing vault uncertainty: %+v", e)
	}
	out := captureStdout(t, func() { printKeyFacts(e) })
	if strings.Contains(out, "only copy") || !strings.Contains(out, "unknown") {
		t.Fatal(out)
	}
}

func TestCustodyTailRotationRecordsBeforePeerFailure(t *testing.T) {
	store, _, lr := setupDevices(t)
	createVault(t, "personal")
	did := createIdentity(t, "alice", store)
	asFlag = "alice"
	cfg.Relays["dead"] = config.RelayConfig{URL: deadURL(t)}
	cmd := newIdentityUpdateCmd()
	for _, role := range []string{"controller", "auth", "assert"} {
		mustSetFlag(t, cmd, "rotate-"+role, "true")
	}
	mustSetFlag(t, cmd, "peer", "dead")
	if _, _, err := runCapturing(t, cmd, nil); err == nil {
		t.Fatal("expected peer failure")
	}
	chain, err := lr.Relay.GetIdentity(did)
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := resolveRotationVault(chain, "", false)
	if err != nil || name != "personal" {
		t.Fatalf("rotation lost provenance: %s %v", name, err)
	}
}

func TestCustodyTailRemoteDIDBinding(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	oracle := newFakeOracle(t)
	oracle.logsByDID[didWithNoChainHere] = heldLog(t, did)
	oracle.registerAsPeer(t, "oracle")
	if _, _, err := loadChainFacts(lr, client.New(oracle.server.URL), didWithNoChainHere, true); err == nil {
		t.Fatal("recovery accepted another DID")
	}
	result, err := statusJSON(t, didWithNoChainHere, "oracle")
	if err == nil || result.Remote != nil {
		t.Fatalf("status accepted another DID: %+v", result)
	}
}

func TestCustodyTailMnemonicAndLoopbacks(t *testing.T) {
	setupDevices(t)
	if err := confirmReveal(strings.NewReader("personal\n"), "personal"); err == nil {
		t.Fatal("noninteractive reveal allowed")
	}
	for _, phrase := range []string{testMnemonic, testMnemonic + " " + testMnemonic} {
		cmd := newVaultImportCmd()
		err := cmd.Args(cmd, []string{phrase})
		if err == nil {
			t.Fatal("phrase accepted as name")
		}
		encoded, _ := json.Marshal(map[string]string{"error": err.Error()})
		if strings.Contains(string(encoded), "abandon") {
			t.Fatal("phrase leaked into JSON error")
		}
		_, _, err = runCapturing(t, cmd, []string{phrase})
		if err == nil || strings.Contains(err.Error(), "abandon") {
			t.Fatal("name validation leaked phrase")
		}
	}
	for _, host := range []string{"localhost", "127.0.0.1", "[::1]"} {
		u, _ := url.Parse("http://" + host + ":8080")
		if !loopbackHosts[u.Hostname()] {
			t.Fatalf("loopback rejected: %s", host)
		}
	}
}

func TestCustodyTailCredentialWarning(t *testing.T) {
	setupCredsTest(t)
	writeCredentialRecord(t, testLoginSubject, "", testCredentialToken(t, 1234))
	if err := os.WriteFile(filepath.Join(credentialStoreDir(), "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	out, warning, err := runCapturing(t, newCredsListCmd(), nil)
	if err != nil || !strings.Contains(warning, "broken.json") || !strings.Contains(out, testLoginSubject) {
		t.Fatalf("out=%s warning=%s err=%v", out, warning, err)
	}
}

func TestCustodyTailRejectsNonPublicDomains(t *testing.T) {
	for _, domain := range []string{"127.0.0.1", "169.254.169.254", "192.168.1.10", "::1", "foo.123", "foo.local", "foo.internal", "foo.localhost", "foo.home.arpa"} {
		if _, err := validateDomain(domain); err == nil {
			t.Errorf("accepted %s", domain)
		}
	}
}

func TestCustodyTailAddKeyCarriesServices(t *testing.T) {
	store, _, lr := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	asFlag = "alice"
	update := newIdentityUpdateCmd()
	mustSetFlag(t, update, "service", "id=origin,type=DfosOrigin,domain=example.com")
	if _, _, err := runCapturing(t, update, nil); err != nil {
		t.Fatal(err)
	}
	before, err := lr.Relay.GetIdentity(did)
	if err != nil {
		t.Fatal(err)
	}
	var dev struct {
		ID                 string `json:"id"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}
	runJSON(t, newIdentityDevicePubkeyCmd(), nil, &dev)
	add := newIdentityAddKeyCmd()
	mustSetFlag(t, add, "auth-key", "true")
	mustSetFlag(t, add, "id", dev.ID)
	mustSetFlag(t, add, "pubkey", dev.PublicKeyMultibase)
	if _, _, err := runCapturing(t, add, nil); err != nil {
		t.Fatal(err)
	}
	after, err := lr.Relay.GetIdentity(did)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(before.State.Services)
	b, _ := json.Marshal(after.State.Services)
	if len(before.State.Services) == 0 || string(a) != string(b) {
		t.Fatalf("services changed: %s -> %s", a, b)
	}
}

func TestCustodyTailPromotionAndFilingFailure(t *testing.T) {
	store, _, _ := setupDevices(t)
	did := createStandaloneIdentity(t, "alice", store)
	verified, err := protocol.VerifyIdentityChain(heldLog(t, did))
	if err != nil {
		t.Fatal(err)
	}
	pub := verified.State.ControllerKeys[0].PublicKeyMultibase
	account := candidateAccountPrefix + pub
	if err := store.RenameKey(keyAccount(pub), account); err != nil {
		t.Fatal(err)
	}
	if err := promoteCandidateKeys(did, verified.State); err != nil {
		t.Fatal(err)
	}
	if !store.HasKey(keyAccount(pub)) || store.HasKey(account) {
		t.Fatal("candidate not promoted")
	}
	if err := os.WriteFile(keyAdoptionPath(pub), nil, 0600); err != nil {
		t.Fatal(err)
	}
	result := &proveResult{}
	fileAdoptedKey(&presentationAnswer{DID: did, KeyID: verified.State.ControllerKeys[0].ID}, &ceremony{DID: did}, &candidateKey{Account: account, PublicKey: pub}, result)
	if result.FilingError == "" {
		t.Fatal("filing failure was silent")
	}
}
