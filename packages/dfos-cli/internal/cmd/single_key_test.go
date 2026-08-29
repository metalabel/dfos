package cmd

// Single-key genesis, content-addressed key ids, and content-addressed keystore
// accounts — the three halves of one change, tested where they meet.
//
// Like the rest of this package's tests these drive RunE against the globals
// setupDevices wires, so they MUST NOT run with t.Parallel().

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/keystore"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// rolesOf reads a chain's roles for one key id, in controller→auth→assert order.
func rolesOf(chain *relay.StoredIdentityChain, keyID string) string {
	var roles []string
	for _, r := range []struct {
		set  []protocol.MultikeyPublicKey
		name string
	}{
		{chain.State.ControllerKeys, "controller"},
		{chain.State.AuthKeys, "auth"},
		{chain.State.AssertKeys, "assert"},
	} {
		for _, k := range r.set {
			if k.ID == keyID {
				roles = append(roles, r.name)
			}
		}
	}
	return strings.Join(roles, ",")
}

// TestRotationMatrixAgainstASingleKeyIdentity walks every rotation flag against
// the shape `identity create` now mints, because the interesting answers all
// live in what the OLD key keeps.
//
// An update is a full-state replacement per role. Rotating one role therefore
// replaces that role's set and carries the other two forward untouched — which
// means the key a rotation displaced is, in every partial case here, still the
// identity's controller or its assert key. That is the mechanically correct
// result, and the report has to say it rather than call the key rotated out.
func TestRotationMatrixAgainstASingleKeyIdentity(t *testing.T) {
	cases := []struct {
		name          string
		flags         []string
		newRoles      string // roles the freshly minted key lands in
		retainedRoles string // roles the displaced genesis key keeps
	}{
		{"auth", []string{"rotate-auth"}, "auth", "controller,assert"},
		{"controller", []string{"rotate-controller"}, "controller", "auth,assert"},
		{"assert", []string{"rotate-assert"}, "assert", "controller,auth"},
		{"controller+auth", []string{"rotate-controller", "rotate-auth"}, "controller,auth", "assert"},
		{"all three", []string{"rotate-controller", "rotate-auth", "rotate-assert"}, "controller,auth,assert", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storeA, _, lr := setupDevices(t)
			keys = storeA
			createVault(t, "personal")
			did := createIdentity(t, "alice", storeA)

			before, _ := lr.Relay.GetIdentity(did)
			genesisKey := before.State.ControllerKeys[0]

			rotate := newIdentityUpdateCmd()
			for _, f := range tc.flags {
				mustSetFlag(t, rotate, f, "true")
			}
			var res struct {
				RotatedKeys []string `json:"rotatedKeys"`
				RetiredKeys []struct {
					KeyID string   `json:"keyId"`
					Roles []string `json:"stillDeclaredIn"`
				} `json:"retiredKeys"`
				Vault struct {
					Indices []uint32 `json:"indices"`
				} `json:"vault"`
			}
			runJSON(t, rotate, nil, &res)

			// One reservation, one index, one key — whatever the flag count.
			if len(res.Vault.Indices) != 1 || res.Vault.Indices[0] != 1 {
				t.Fatalf("rotation indices = %v, want exactly [1]", res.Vault.Indices)
			}
			if len(res.RotatedKeys) != len(tc.flags) {
				t.Fatalf("rotatedKeys = %v, want one entry per rotated role", res.RotatedKeys)
			}

			after, _ := lr.Relay.GetIdentity(did)
			newKey := protocol.MultikeyPublicKey{}
			for _, k := range distinctChainKeys(after) {
				if k.ID != genesisKey.ID {
					newKey = k
				}
			}
			if newKey.ID == "" {
				t.Fatal("no new key in the chain after a rotation")
			}
			if got := rolesOf(after, newKey.ID); got != tc.newRoles {
				t.Errorf("new key roles = %q, want %q", got, tc.newRoles)
			}
			if got := rolesOf(after, genesisKey.ID); got != tc.retainedRoles {
				t.Errorf("displaced key roles = %q, want %q", got, tc.retainedRoles)
			}

			// The report says what the displaced key still is — the copy that
			// must not lie. Exactly one key lost a role: the genesis one.
			if len(res.RetiredKeys) != 1 || res.RetiredKeys[0].KeyID != genesisKey.ID {
				t.Fatalf("retiredKeys = %+v, want just the genesis key", res.RetiredKeys)
			}
			if got := strings.Join(res.RetiredKeys[0].Roles, ","); got != tc.retainedRoles {
				t.Errorf("the report says the displaced key still holds %q, chain says %q", got, tc.retainedRoles)
			}

			// The identity can still act: whichever role it needs, some held key
			// covers it, and every key is filed under its own content address.
			for _, role := range []struct {
				set  []protocol.MultikeyPublicKey
				name string
			}{
				{after.State.ControllerKeys, "controller"},
				{after.State.AuthKeys, "auth"},
				{after.State.AssertKeys, "assert"},
			} {
				held, err := selectHeldKey(did, role.set, role.name)
				if err != nil {
					t.Fatalf("no held %s key after rotating %v: %v", role.name, tc.flags, err)
				}
				if held.Account != keyAccount(held.PublicKey) {
					t.Errorf("%s key is filed under %q, want its content address", role.name, held.Account)
				}
			}
		})
	}
}

// TestKeyIDsAreDerivedFromTheKey checks the property the derivation exists for:
// every key id this CLI publishes is computable from the public key alone, by
// anything holding that key, with nothing exchanged.
func TestKeyIDsAreDerivedFromTheKey(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	runJSON(t, rotate, nil, &struct{}{})

	chain, _ := lr.Relay.GetIdentity(did)
	for _, k := range distinctChainKeys(chain) {
		if want := protocol.DeriveKeyID(k.PublicKeyMultibase); k.ID != want {
			t.Errorf("key %s is published as %q, want the derived %q", k.PublicKeyMultibase, k.ID, want)
		}
	}
}

// TestTheSameSeedWrittenTwiceIsOneKeystoreEntry is the F4 property, expressed
// where it now holds by construction: an address computed from the key itself
// cannot be two addresses for one key. The old `<did>#<keyId>` account made the
// same private bytes look like two independent keys the moment two identities
// declared them; content addressing makes that arithmetically impossible.
func TestTheSameSeedWrittenTwiceIsOneKeystoreEntry(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	chain, _ := localRelayInstance.Relay.GetIdentity(did)
	key := chain.State.ControllerKeys[0]
	account := keyAccount(key.PublicKeyMultibase)

	priv, err := storeA.GetPrivateKey(account)
	if err != nil {
		t.Fatalf("read the genesis key: %v", err)
	}

	before, err := storeA.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}

	// The same seed arriving again — a recovery, a re-import, a second identity
	// that turned out to declare the same key — computes the address from the
	// key, so it lands on the one the key already has.
	pub := priv.Public().(ed25519.PublicKey)
	if keyAccount(protocol.EncodeMultikey(pub)) != account {
		t.Fatal("the same key computed two different addresses")
	}
	if _, err := storeA.PutKey(keyAccount(protocol.EncodeMultikey(pub)), priv); err != nil {
		t.Fatalf("re-put: %v", err)
	}

	after, err := storeA.Entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("re-writing the same key added an entry: %d → %d", len(before), len(after))
	}

	// And under the OLD addressing it would have been two entries, because the
	// name came from the relationship rather than from the key.
	if legacyKeyAccount(did, key.ID) == legacyKeyAccount("did:dfos:someoneelse", key.ID) {
		t.Fatal("the legacy account did not depend on the DID")
	}
}

// TestAContentAddressedKeyNothingDeclaresIsAnOrphan: dropping the `pending:`
// dance must not cost prune its reach. A create that dies between the mint and
// the signed operation leaves a content-addressed key no chain names, and the
// ledger has to reach the same verdict the `pending:` prefix used to hand it.
func TestAContentAddressedKeyNothingDeclaresIsAnOrphan(t *testing.T) {
	storeA, _, _ := setupDevices(t)
	keys = storeA
	// An identity that IS declared, so the fold has something to keep as well.
	createStandaloneIdentity(t, "alice", storeA)

	leftover := keyAccount(plantContentAddressedKey(t, storeA))

	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	entry := entryFor(t, ledger, leftover)
	if entry.Status != statusOrphan || !entry.Prunable {
		t.Fatalf("an undeclared content-addressed key came out %q (prunable=%v)", entry.Status, entry.Prunable)
	}
	if entry.PublicKey == "" {
		t.Fatal("a content-addressed account IS its public key; the ledger lost it")
	}

	if res := runPrune(t, true); res.Removed != 1 {
		t.Fatalf("prune removed %d, want the one orphan", res.Removed)
	}
	if storeA.HasKey(leftover) {
		t.Fatal("prune left the orphan behind")
	}
}

// plantContentAddressedKey writes one fresh key under its content address and
// returns its public multikey.
func plantContentAddressedKey(t *testing.T, store *keystore.MemoryStore) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	mb := protocol.EncodeMultikey(pub)
	if _, err := store.PutKey(keyAccount(mb), priv); err != nil {
		t.Fatalf("plant: %v", err)
	}
	return mb
}

// TestALegacyDIDScopedAccountStillSignsAndStillLists is the read-compat case: a
// key an earlier version filed under `<did>#<keyId>` keeps working — it is
// found, it signs, and the ledger places it — without being rewritten.
func TestALegacyDIDScopedAccountStillSignsAndStillLists(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	did := createStandaloneIdentity(t, "alice", storeA)

	chain, _ := lr.Relay.GetIdentity(did)
	key := chain.State.ControllerKeys[0]

	// Move the key back to the shape the previous version wrote.
	if err := storeA.RenameKey(keyAccount(key.PublicKeyMultibase), legacyKeyAccount(did, key.ID)); err != nil {
		t.Fatalf("stage a legacy account: %v", err)
	}
	if storeA.HasKey(keyAccount(key.PublicKeyMultibase)) {
		t.Fatal("test premise wrong: the content address still holds the key")
	}

	// Found, with the legacy account reported as the account.
	held, err := selectHeldKey(did, chain.State.ControllerKeys, "controller")
	if err != nil {
		t.Fatalf("a legacy-addressed key was not found: %v", err)
	}
	if held.Account != legacyKeyAccount(did, key.ID) {
		t.Fatalf("resolved to %q, want the legacy account", held.Account)
	}
	if !holdsDeclaredKey(did, key) || countKeysInChain(chain) != 1 {
		t.Fatal("a legacy-addressed key does not count as held")
	}

	// Placed by the ledger, and never an orphan.
	ledger, err := buildKeyLedger()
	if err != nil {
		t.Fatalf("buildKeyLedger: %v", err)
	}
	entry := entryFor(t, ledger, legacyKeyAccount(did, key.ID))
	if entry.Status != statusDeclared {
		t.Fatalf("a legacy-addressed declared key came out %q", entry.Status)
	}
	if entry.Prunable {
		t.Fatal("a legacy-addressed declared key was marked prunable")
	}
	if res := runPrune(t, true); res.Removed != 0 {
		t.Fatalf("prune removed %d legacy-addressed keys", res.Removed)
	}

	// And it still signs: a rotation is signed by a controller key this device
	// holds, which is exactly the key sitting under the legacy account.
	identityFlag = "alice"
	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	runJSON(t, rotate, nil, &struct{}{})

	after, _ := lr.Relay.GetIdentity(did)
	if len(after.Log) != 2 {
		t.Fatalf("the rotation did not land: %d operations", len(after.Log))
	}
	// The legacy account is left where it is. Nothing rewrites a key that works.
	if !storeA.HasKey(legacyKeyAccount(did, key.ID)) {
		t.Fatal("the legacy account was removed by an unrelated operation")
	}
}

// TestRecoverConvergesOnAMixedVault: one identity's key held under the legacy
// account, another's under the content address, both derived from one seed.
// Recovery must report BOTH as already-present and write neither again — a
// recovery that cannot recognize a key it already holds writes a duplicate.
func TestRecoverConvergesOnAMixedVault(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	first := createIdentity(t, "alice", storeA) // index 0
	second := createIdentity(t, "bob", storeA)  // index 1
	for _, did := range []string{first, second} {
		chain, _ := lr.Relay.GetIdentity(did)
		oracle.logsByDID[did] = chain.Log
		for _, k := range chain.State.ControllerKeys {
			oracle.declare(k.PublicKeyMultibase, did, false, "")
		}
	}

	// Age alice's key back to the previous addressing; bob's stays current.
	aliceChain, _ := lr.Relay.GetIdentity(first)
	aliceKey := aliceChain.State.ControllerKeys[0]
	if err := storeA.RenameKey(keyAccount(aliceKey.PublicKeyMultibase), legacyKeyAccount(first, aliceKey.ID)); err != nil {
		t.Fatalf("stage a legacy account: %v", err)
	}

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "personal", "peer": "oracle"}), nil, &res)

	if len(res.Keys) != 2 {
		t.Fatalf("recovered %d keys, want 2 (one per identity): %+v", len(res.Keys), res.Keys)
	}
	for _, k := range res.Keys {
		if k.Outcome != "already-present" {
			t.Errorf("index %d = %q (%s), want already-present under either addressing", k.Index, k.Outcome, k.Reason)
		}
	}
	// Alice's key is reported at the account it is really under, and no second
	// copy was written to the content address.
	for _, k := range res.Keys {
		if k.DID != first {
			continue
		}
		if k.Account != legacyKeyAccount(first, aliceKey.ID) {
			t.Errorf("alice's key reported as %q, want its legacy account", k.Account)
		}
	}
	if storeA.HasKey(keyAccount(aliceKey.PublicKeyMultibase)) {
		t.Error("recovery wrote a second copy of a key it already held")
	}
	_ = mnemonic
}

// TestSingleKeyRoundTripCreateRotateRecoverSign is the whole arc in one test:
// create (one key), rotate its auth role, lose the machine, adopt the phrase on
// a fresh one, recover — and sign again with what came back.
func TestSingleKeyRoundTripCreateRotateRecoverSign(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	oracle := newFakeOracle(t)
	oracle.registerAsPeer(t, "oracle")

	mnemonic := createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	// whoami sees a signing key, and names the index it came from.
	var who whoamiResult
	runJSON(t, newWhoamiCmd(), nil, &who)
	if !who.SigningKey.Available || who.SigningKey.Vault == nil || who.SigningKey.Vault.Index != 0 {
		t.Fatalf("whoami after create: %+v", who.SigningKey)
	}

	rotate := newIdentityUpdateCmd()
	mustSetFlag(t, rotate, "rotate-auth", "true")
	runJSON(t, rotate, nil, &struct{}{})

	chain, _ := lr.Relay.GetIdentity(did)
	oracle.logsByDID[did] = chain.Log
	for _, k := range distinctChainKeys(chain) {
		oracle.declare(k.PublicKeyMultibase, did, false, "alice")
	}

	// A bare machine: new config directory, new keystore, nothing but the phrase.
	storeB, _, _ := setupDevices(t)
	keys = storeB
	importVault(t, "restored", mnemonic)
	oracle.registerAsPeer(t, "oracle")

	var res recoverResult
	runJSON(t, newRecover(t, map[string]string{"vault": "restored", "peer": "oracle"}), nil, &res)
	if len(res.Keys) != 2 {
		t.Fatalf("recovered %d keys, want 2 (genesis and the rotated-in auth key): %+v", len(res.Keys), res.Keys)
	}
	for _, k := range res.Keys {
		if k.Outcome != "recovered" {
			t.Fatalf("index %d = %q (%s)", k.Index, k.Outcome, k.Reason)
		}
	}

	// Signing works again — the actual test of a recovery.
	recovered, _ := localRelayInstance.Relay.GetIdentity(did)
	if recovered == nil {
		t.Fatal("the chain was not pulled into the fresh machine's relay")
	}
	if n := countKeysInChain(recovered); n != 2 {
		t.Fatalf("the fresh machine holds %d of the chain's keys, want 2", n)
	}
	identityFlag = res.Identities[0].Name
	cc := newContentCreateCmd()
	mustSetFlag(t, cc, "no-schema-warn", "true")
	var content struct {
		ContentID string `json:"contentId"`
	}
	runJSON(t, cc, []string{writeTempDoc(t, `{"hello":"after recovery"}`)}, &content)
	if content.ContentID == "" {
		t.Fatal("the recovered identity could not publish")
	}
}

// blindStore's fallback path names candidate accounts from other local stores.
// With content addressing those names come from the chains and the vault
// records, so a key held under either shape is still reachable on a backend that
// cannot list itself.
func TestABlindBackendFindsBothAddressings(t *testing.T) {
	storeA, _, lr := setupDevices(t)
	keys = storeA
	createVault(t, "personal")
	did := createIdentity(t, "alice", storeA)

	chain, _ := lr.Relay.GetIdentity(did)
	key := chain.State.ControllerKeys[0]

	for _, account := range []string{
		keyAccount(key.PublicKeyMultibase),
		legacyKeyAccount(did, key.ID),
	} {
		// Put the one key under exactly this account and no other.
		staged := keystore.NewMemoryStore()
		priv, err := storeA.GetPrivateKey(keyAccount(key.PublicKeyMultibase))
		if err != nil {
			priv, err = storeA.GetPrivateKey(legacyKeyAccount(did, key.ID))
		}
		if err != nil {
			t.Fatalf("read the genesis key: %v", err)
		}
		if _, err := staged.PutKey(account, priv); err != nil {
			t.Fatalf("stage %s: %v", account, err)
		}
		keys = &blindStore{MemoryStore: staged}

		ledger, err := buildKeyLedger()
		if err != nil {
			t.Fatalf("buildKeyLedger for %s: %v", account, err)
		}
		entry := entryFor(t, ledger, account)
		if entry.Status != statusDeclared {
			t.Errorf("%s came out %q on a blind backend, want declared", account, entry.Status)
		}
	}
}
