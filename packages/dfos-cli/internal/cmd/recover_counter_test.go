package cmd

// The counter half of `dfos recover`: what the run LEARNED about which indices
// this vault has spent, and whether the vault's counter clears all of it.
//
// The bug these cover shipped in v0.40.0 and is the worst kind this repo has:
// silent Ed25519 private key reuse across two unrelated DIDs.
//
// The shape. Rotations move an identity's current auth key to a fresh index each
// time, and unpublished operations leave the oracle's index blind to the ones in
// between. The scan's gap limit then ends the walk before the current key's
// index. The chain fetch still names that public key — `identity show` was
// correct the whole time — and the seed still derives it, but nothing fed that
// back: the counter converged past the SCANNED indices only, over the message
// "the next mint from this vault cannot reuse a recovered index". The next
// rotate-auth then took an index a burn identity had already spent.
//
// So these tests assert three things together, because any one alone would pass
// over the bug: the beyond-scan key is INSTALLED, the counter clears it, and the
// report SAYS the scan stopped short.

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// rotateAuth runs `dfos identity update --rotate-auth` once, moving the current
// auth key to the vault's next index.
func rotateAuth(t *testing.T) {
	t.Helper()
	cmd := newIdentityUpdateCmd()
	mustSetFlag(t, cmd, "rotate-auth", "true")
	runJSON(t, cmd, nil, &struct{}{})
}

// keyAtIndex finds the recovered key the report filed under a derivation index.
func keyAtIndex(t *testing.T, r recoverResult, index uint32) recoveredKey {
	t.Helper()
	for _, k := range r.Keys {
		if k.Index == index {
			return k
		}
	}
	t.Fatalf("no recovered key at index %d: %+v", index, r.Keys)
	return recoveredKey{}
}

// rotatedPastTheScan builds the repro: an identity whose current auth key sits
// at index 5 after four rotations, against an oracle whose INDEX knows only the
// genesis pair while its proof plane serves the whole chain. It returns the
// mnemonic and the DID, with device B active and the vault imported as
// "restored" — the fresh machine holding nothing but the phrase.
func rotatedPastTheScan(t *testing.T) (mnemonic, did string, oracle *fakeOracle, storeB *keystore.MemoryStore) {
	t.Helper()
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle = newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic = createVault(t, "personal")
	did = createIdentity(t, "alice", storeA) // controller at 0, auth at 1
	for i := 0; i < 4; i++ {
		rotateAuth(t) // 2, 3, 4, then 5 — the current auth key
	}

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil || chain == nil {
		t.Fatalf("chain for %s: %v", did, err)
	}
	oracle.logsByDID[did] = chain.Log

	// The index answers for the genesis pair and nothing the rotations declared.
	// A relay whose index lags its own proof plane looks like this, and so does a
	// corpus whose rotation operations were never published.
	oracle.declare(derivedPublicKey(t, mnemonic, 0), did, false, "")
	oracle.declare(derivedPublicKey(t, mnemonic, 1), did, false, "")

	storeB, _, _ = setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")
	return mnemonic, did, oracle, storeB
}

// TestRecoverLearnsTheCurrentKeyBeyondTheScanDepth is B7's core. With a gap
// limit of two the walk stops after index 3, and the current auth key at index 5
// is out of its reach — yet the chain declares it and the seed derives it.
func TestRecoverLearnsTheCurrentKeyBeyondTheScanDepth(t *testing.T) {
	mnemonic, did, _, storeB := rotatedPastTheScan(t)

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "2",
	}), nil, &res)

	// The walk itself really did stop short — without this the rest proves nothing.
	if res.IndicesScanned != 4 {
		t.Fatalf("scanned %d indices at depth 2, want 4 (0–3)", res.IndicesScanned)
	}

	// Every index the seed spent is recovered, including the two the walk reached
	// but the oracle stayed silent about (2, 3) and the two past it (4, 5).
	if got := usedIndices(res); !equalIndices(got, []uint32{0, 1, 2, 3, 4, 5}) {
		t.Fatalf("used indices = %v, want 0–5: the chain declares all six", got)
	}

	// The current auth key is the one the old code left out of the keystore
	// entirely: the chain proves it, the seed derives it, and there is no reason
	// for a recovered identity's CURRENT key to be missing.
	current := keyAtIndex(t, res, 5)
	if current.Outcome != "recovered" {
		t.Errorf("the current auth key at index 5 = %q (%s), want recovered", current.Outcome, current.Reason)
	}
	if !storeB.HasKey(current.Account) {
		t.Errorf("the current auth key was not installed under %s", current.Account)
	}
	if len(current.Roles) != 1 || current.Roles[0] != "auth" || current.Superseded {
		t.Errorf("index 5 = %+v, want role auth and not superseded", current)
	}
	if current.DID != did {
		t.Errorf("index 5 filed under %q, want %s", current.DID, did)
	}
	if !current.BeyondScan {
		t.Error("index 5 is not marked as past the scan")
	}
	// Index 3 was derived by the walk; the oracle simply had no row for it. That
	// is the oracle's shortfall, not the scan depth's.
	if keyAtIndex(t, res, 3).BeyondScan {
		t.Error("index 3 is marked past the scan, but the walk reached it")
	}

	// The counter is the correctness half. Anything below 6 hands out an index
	// the seed has already spent.
	if res.HighestUsedIndex != 5 {
		t.Errorf("highest used index = %d, want 5", res.HighestUsedIndex)
	}
	meta, _ := getVaults().Load("restored")
	if meta.NextIndex != 6 {
		t.Fatalf("counter = %d after recovering through index 5, want 6", meta.NextIndex)
	}
	if res.CounterAfter != 6 {
		t.Errorf("the report claims counter %d, want 6", res.CounterAfter)
	}
	_ = mnemonic
}

// TestRecoverReportsTheScanStoppedShort is the loud half. Converging the counter
// silently would still leave an operator believing a clean "recovered" — and the
// same shortfall can hide an identity whose every key sits past the gap, whose
// indices this run therefore never learned.
func TestRecoverReportsTheScanStoppedShort(t *testing.T) {
	rotatedPastTheScan(t)

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "2",
	}), nil, &res)

	// The machine-readable fact, so a scripted caller never has to read prose.
	if res.ScanComplete {
		t.Error("scanComplete is true on a scan a chain proved stopped short")
	}
	if !equalIndices(res.BeyondScanIndices, []uint32{4, 5}) {
		t.Errorf("beyondScanIndices = %v, want [4 5]", res.BeyondScanIndices)
	}
	if res.RecommendedScanDepth != 6 {
		t.Errorf("recommendedScanDepth = %d, want 6 (enough to reach index 5)", res.RecommendedScanDepth)
	}
}

// TestRecoverScanShortfallBannerIsLoud is the same fact in as many words. It
// needs its own fresh machine: once a run has reconciled the vault, the manifest
// names every index and the next scan legitimately reaches all of them — there
// is nothing left to fall short of, which is the fix working.
func TestRecoverScanShortfallBannerIsLoud(t *testing.T) {
	rotatedPastTheScan(t)

	stdout, _, err := runCapturing(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "2",
	}), nil)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	for _, want := range []string{
		"SCAN DEPTH TOO SHALLOW",
		"beyond scan depth",
		"--scan-depth 6",
		"already spent",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report does not say %q:\n%s", want, stdout)
		}
	}
	// The counter line must not make the safety claim it cannot support.
	if strings.Contains(stdout, "cannot reuse") {
		t.Errorf("the counter line claims reuse is impossible after a short scan:\n%s", stdout)
	}
	if !strings.Contains(stdout, "remain unknown") {
		t.Errorf("the counter line does not scope its claim:\n%s", stdout)
	}
}

// TestRecoverDryRunDoesNotClaimAScanItCouldNotCheck: --dry-run pulls no chain,
// so on a fresh machine it reads none — and a chain it never read is one whose
// declared keys it never matched against a derivation.
//
// A dry run is exactly where an operator looks before deciding to trust a vault,
// so a clean scanComplete on the strength of having looked at nothing is the
// same silence-read-as-an-answer the rest of this command refuses.
func TestRecoverDryRunDoesNotClaimAScanItCouldNotCheck(t *testing.T) {
	rotatedPastTheScan(t)

	before, _ := getVaults().Load("restored")
	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "2", "dry-run": "true",
	}), nil, &res)

	if !res.DryRun {
		t.Error("the dry run does not record itself as one")
	}
	if res.ScanComplete {
		t.Error("a dry run that read no chain claims a complete scan")
	}
	// Unproven, not proven: no chain was read, so nothing showed an index past
	// the walk. The two kinds of incompleteness are distinguishable in --json.
	if len(res.BeyondScanIndices) != 0 {
		t.Errorf("beyondScanIndices = %v, want none — no chain was read to prove one", res.BeyondScanIndices)
	}

	after, _ := getVaults().Load("restored")
	if after.NextIndex != before.NextIndex || len(after.Minted) != len(before.Minted) {
		t.Errorf("the dry run moved the vault: counter %d → %d", before.NextIndex, after.NextIndex)
	}
}

// TestRecoverThenMintDoesNotReuseAKey is the invariant, end to end and in the
// terms the bug broke it in: after recovery, the next key this vault mints must
// not be one an existing DID is already signing with.
//
// Under the bug the counter converged to 4 here and the next rotate-auth took
// index 4 — an index the identity's own chain had already declared.
func TestRecoverThenMintDoesNotReuseAKey(t *testing.T) {
	mnemonic, _, _, storeB := rotatedPastTheScan(t)

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "2",
	}), nil, &res)

	// Every public key the recovered corpus is already using.
	spent := map[string]uint32{}
	for _, k := range res.Keys {
		spent[k.PublicKey] = k.Index
	}
	if len(spent) != 6 {
		t.Fatalf("recovered %d distinct keys, want 6", len(spent))
	}

	// Mint from the restored vault. Its next key must be new material.
	newDID := createIdentity(t, "second", storeB)
	if newDID == "" {
		t.Fatal("minting from the restored vault produced no identity")
	}
	meta, _ := getVaults().Load("restored")
	for _, r := range meta.Minted {
		if r.DID != newDID {
			continue
		}
		if idx, reused := spent[r.PublicKey]; reused {
			t.Fatalf("the new identity's key at index %d reuses index %d — two DIDs, one private key", r.Index, idx)
		}
		if r.Index < 6 {
			t.Errorf("the new identity took index %d, below the recovered high-water mark of 5", r.Index)
		}
	}
	_ = mnemonic
}

// TestRecoverReportsACompleteScanAsComplete is the control. Scanned deep enough,
// nothing is past the walk, the banner stays away, and the counter line makes
// the claim it is entitled to.
func TestRecoverReportsACompleteScanAsComplete(t *testing.T) {
	rotatedPastTheScan(t)

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "10",
	}), nil, &res)

	if !res.ScanComplete {
		t.Errorf("a scan deep enough to reach every declared index reports incomplete: %+v", res)
	}
	if len(res.BeyondScanIndices) != 0 {
		t.Errorf("beyondScanIndices = %v, want none", res.BeyondScanIndices)
	}
	if res.RecommendedScanDepth != 0 {
		t.Errorf("recommendedScanDepth = %d, want 0 on a complete scan", res.RecommendedScanDepth)
	}
	// The counter lands in the same place either way — that is the point.
	if meta, _ := getVaults().Load("restored"); meta.NextIndex != 6 {
		t.Errorf("counter = %d, want 6", meta.NextIndex)
	}

	stdout, _, err := runCapturing(t, newRecover(t, map[string]string{
		"vault": "restored", "peer": "oracle", "scan-depth": "10",
	}), nil)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if strings.Contains(stdout, "SCAN DEPTH TOO SHALLOW") {
		t.Errorf("a complete scan printed the shortfall banner:\n%s", stdout)
	}
	// The gap-limit lever is named whether or not the scan fell short — it is the
	// standing limitation of a gap-limited walk, not an incident report.
	if !strings.Contains(stdout, "--scan-depth N") {
		t.Errorf("the footer does not name the lever that moves the gap limit:\n%s", stdout)
	}
}

// TestProbeBeyondScanLeavesAForeignKeyAlone: a key a chain declares that this
// seed cannot derive was minted somewhere else — another vault, another device's
// own key added to the identity. It spends no index here, so it must produce no
// hit, move no counter, and above all raise no shortfall: a multi-device
// identity holds such a key as a matter of course, and a banner that fired on
// every one of them would be noise the operator learns to skip past.
//
// It also pins the walk's exit: an unexplainable key must not send it to the
// ceiling looking for one, and finding everything it CAN explain must stop it.
func TestProbeBeyondScanLeavesAForeignKeyAlone(t *testing.T) {
	seed, err := vault.MnemonicSeed(testMnemonic)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	derived := func(i uint32) string {
		_, pub, err := vault.DeriveKey(seed, i)
		if err != nil {
			t.Fatalf("derive %d: %v", i, err)
		}
		return protocol.EncodeMultikey(pub)
	}

	// A foreign key with no relationship to this seed.
	foreignPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate a foreign key: %v", err)
	}
	foreign := protocol.EncodeMultikey(foreignPub)

	chains := map[string]*chainFacts{
		"did:dfos:alice": {keyIDByPublic: map[string]string{
			derived(0): "key-0",
			derived(7): "key-7", // past a scan that stopped at 4
			foreign:    "key-laptop",
		}},
	}
	// The scan matched index 0 and stopped after deriving 0–3.
	scanned := []scanHit{{index: 0, publicKey: derived(0)}}

	found := probeBeyondScan(seed, chains, scanned, 4, recoverOptions{})

	if len(found) != 1 {
		t.Fatalf("probe found %d hits, want 1 (index 7 alone): %+v", len(found), found)
	}
	if found[0].index != 7 || !found[0].beyondScan {
		t.Errorf("hit = %+v, want index 7 marked past the scan", found[0])
	}
	if len(found[0].chainDIDs) != 1 || found[0].chainDIDs[0] != "did:dfos:alice" {
		t.Errorf("hit names %v, want the chain that declared it", found[0].chainDIDs)
	}
	if found[0].private == nil {
		t.Error("the hit carries no private key, so nothing could be installed")
	}
	for _, h := range found {
		if h.publicKey == foreign {
			t.Error("a key this seed cannot derive was attributed to an index")
		}
	}
}

// TestProbeBeyondScanSkipsManifestOnly: manifest-only asks no relay and already
// banners itself as covering only what the vault's own records name. It does not
// get a second, quieter walk under a different name.
func TestProbeBeyondScanSkipsManifestOnly(t *testing.T) {
	seed, err := vault.MnemonicSeed(testMnemonic)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, pub, err := vault.DeriveKey(seed, 3)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	chains := map[string]*chainFacts{
		"did:dfos:alice": {keyIDByPublic: map[string]string{protocol.EncodeMultikey(pub): "key-3"}},
	}
	if found := probeBeyondScan(seed, chains, nil, 0, recoverOptions{manifestOnly: true}); found != nil {
		t.Errorf("manifest-only probed anyway: %+v", found)
	}
	// The control: the same inputs without the flag do find it.
	if found := probeBeyondScan(seed, chains, nil, 0, recoverOptions{}); len(found) != 1 {
		t.Fatalf("the scanning probe found %d hits, want 1", len(found))
	}
}
