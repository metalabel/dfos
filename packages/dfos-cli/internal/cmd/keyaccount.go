package cmd

// Where a private key lives in the keystore.
//
// A key is addressed by its CONTENT — `key:<publicKeyMultibase>` — and by
// nothing else. The public key is the one name a key carries that every machine
// computes identically, so two devices that hold the same seed file it under the
// same address, and a phrase reimported twice writes the same bytes to the same
// place instead of two entries that look like two keys.
//
// The scheme it replaces addressed a key by the identity that declared it,
// `<did>#<key_id>`. That name is not a property of the key: it is a property of a
// relationship, it does not exist until a chain does, and one key declared by two
// identities was two entries with no way to see they were the same key. Those
// accounts are still READ — an upgrade must never lose a key — and are never
// written again. See heldKeyAccount for the read order, which is the same
// read-old-shape/write-new-shape contract internal/keystore's file names use.
//
// Three account namespaces are deliberately untouched:
//
//   - `candidate:<publicKeyMultibase>` (keys_prove.go) was already content
//     addressed; it is the same idea under a different prefix, kept because the
//     ledger reports candidates as their own status.
//   - `pending:<key_id>` (identity.go) marks a key minted for a genesis that has
//     not landed. It is transient by construction and renamed to the content
//     address the moment the DID exists.
//   - `login-client__<key_id>` (login.go) is this installation's SIWD client key.
//     Its handle is recorded in login-client.json, a file this CLI owns, so the
//     account is already reconstructible without a chain.

import (
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// keyAccountPrefix namespaces a content-addressed key account. The prefix is
// carried rather than implied so the account is legible next to the other
// namespaces in the same keystore and can never be mistaken for a bare DID URL.
const keyAccountPrefix = "key:"

// keyAccount is the address a key is WRITTEN under: its public key.
func keyAccount(publicKeyMultibase string) string {
	return keyAccountPrefix + publicKeyMultibase
}

// publicKeyFromAccount inverts keyAccount. ok is false for any other account
// shape — nothing guesses.
func publicKeyFromAccount(account string) (publicKeyMultibase string, ok bool) {
	if len(account) <= len(keyAccountPrefix) || account[:len(keyAccountPrefix)] != keyAccountPrefix {
		return "", false
	}
	return account[len(keyAccountPrefix):], true
}

// legacyKeyAccount is the pre-content-addressing account for a key: the DID URL
// that names it. Read, never written.
func legacyKeyAccount(did, keyID string) string {
	return did + "#" + keyID
}

// heldKey is one key this device holds, resolved: the kid a signature carries,
// the account the seed is stored under, and the public key that addresses it.
// The kid and the account are different strings on purpose — one is a wire
// identifier scoped to an identity, the other is a local address scoped to
// nothing.
type heldKey struct {
	KID       string
	Account   string
	PublicKey string
}

// heldKeyAccount answers where a declared key's seed actually is on this
// machine: the content address if it is there, otherwise the legacy DID-scoped
// account, otherwise nowhere.
//
// The order is not arbitrary. A key written by this version is at the content
// address; a key written by an earlier one is at the legacy account; a key
// touched by both is at both, and the content address is the one that stays
// correct when the same key turns up under a second identity.
func heldKeyAccount(did, keyID, publicKeyMultibase string) (account string, held bool) {
	if publicKeyMultibase != "" {
		if a := keyAccount(publicKeyMultibase); keys.HasKey(a) {
			return a, true
		}
	}
	if did != "" && keyID != "" {
		if a := legacyKeyAccount(did, keyID); keys.HasKey(a) {
			return a, true
		}
	}
	return "", false
}

// holdsDeclaredKey reports whether this device holds the private half of a key
// an identity declares, under either addressing.
func holdsDeclaredKey(did string, k protocol.MultikeyPublicKey) bool {
	_, held := heldKeyAccount(did, k.ID, k.PublicKeyMultibase)
	return held
}

// chainKeyRole is one key an identity declares, the roles it is declared in, and
// whether this device holds its private half.
type chainKeyRole struct {
	Key   protocol.MultikeyPublicKey
	Roles []string
	Held  bool
	// Void is true when every role this chain names the key in is void — declared
	// and never proved, so the key resolves nowhere.
	Void bool
}

// chainKeyRoles folds a chain's three role sets into one row per key, in
// controller→auth→assert order of first appearance. This is the shape every
// display wants: a key is a thing, and its roles are an attribute of it.
//
// VOID MEMBERSHIPS ARE ROWS TOO, marked `<role> (void)`. The role arrays are
// EFFECTIVE state — the memberships a possession proof admitted — so folding only
// those would make `identity keys` silently omit a key the chain visibly
// declares, and a controller who introduced a key without a proof would have a
// chain that verifies, a key that resolves nowhere, and no display anywhere
// saying why. Void is surfaced loudly or it is not surfaced at all.
func chainKeyRoles(chain *relay.StoredIdentityChain) []chainKeyRole {
	index := map[string]int{}
	var out []chainKeyRole
	place := func(k protocol.MultikeyPublicKey) int {
		i, seen := index[k.ID]
		if !seen {
			index[k.ID] = len(out)
			out = append(out, chainKeyRole{Key: k, Held: holdsDeclaredKey(chain.DID, k)})
			i = len(out) - 1
		}
		return i
	}
	add := func(set []protocol.MultikeyPublicKey, role string) {
		for _, k := range set {
			i := place(k)
			out[i].Roles = append(out[i].Roles, role)
		}
	}
	add(chain.State.ControllerKeys, "controller")
	add(chain.State.AuthKeys, "auth")
	add(chain.State.AssertKeys, "assert")
	// A key with an effective role somewhere is not void, however many of its
	// other memberships are — Void marks a key that resolves NOWHERE, which is the
	// state worth a warning.
	for _, void := range chain.State.VoidKeys {
		i := place(void.Key)
		if len(out[i].Roles) == 0 {
			out[i].Void = true
		}
		out[i].Roles = append(out[i].Roles, string(void.Role)+" (void)")
	}
	return out
}

// keyAccountsFor names every account a declared key could be filed under, newest
// shape first. It is for readers that fold over what a chain declares and have to
// meet a key wherever it is, without probing the backend once per shape.
func keyAccountsFor(did, keyID, publicKeyMultibase string) []string {
	var out []string
	if publicKeyMultibase != "" {
		out = append(out, keyAccount(publicKeyMultibase))
	}
	if did != "" && keyID != "" {
		out = append(out, legacyKeyAccount(did, keyID))
	}
	return out
}
