// Command genfixture writes a DETERMINISTIC parity fixture used by the
// dual-relay parity harness (WP-7).
//
// The fixture is a single JSON file containing:
//   - the relay's pinned identity (DID + profile artifact JWS) — both relays
//     boot from this via createRelay({identity}) / NewRelay({Identity}), which
//     SKIP the JIT bootstrap so neither relay ingests a RANDOM identity into the
//     global log. (A random relay identity is the #1 parity flake: its genesis
//     leaks into /log entry #1 and /.well-known, diverging the gate trivially.)
//   - bootstrapOps: the relay's own genesis + profile tokens, replayed as
//     ordinary ops so the relay DID's log entries are byte-identical on both
//     twins.
//   - ops: a fixed, dependency-ordered set of user identity/content/artifact/
//     credential ops.
//
// Every token is built BY HAND (payload map + DagCborCID + CreateJWS) with
// SEEDED ed25519 keys and PINNED createdAt timestamps. The protocol library's
// Sign* helpers stamp a wall-clock createdAt and reseed from crypto/rand, so
// they cannot produce byte-identical tokens run-to-run or twin-to-twin —
// hand-building is the only way to pin every byte.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Fixture is the on-disk shape shared by the TS serve script, the Go serve
// binary, and the parity test.
type Fixture struct {
	RelayDID        string   `json:"relayDid"`
	RelayProfileJWS string   `json:"relayProfileJws"`
	RelayContentID  string   `json:"relayContentId"` // unused placeholder for symmetry
	BootstrapOps    []string `json:"bootstrapOps"`   // relay genesis + profile, replayed
	Ops             []string `json:"ops"`            // fixed user op set
	// QueryDIDs / QueryContentIDs let the test hit per-chain log routes.
	QueryDID       string `json:"queryDid"`
	QueryContentID string `json:"queryContentId"`
}

// seededKey returns a deterministic ed25519 keypair from a single seed byte.
func seededKey(seed byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, priv.Public().(ed25519.PublicKey)
}

const pinnedTime = "2025-01-01T00:00:00.000Z"

// pinnedTimeAt returns a fixed timestamp offset by `min` minutes from the base —
// used for chained content ops, which require strictly increasing createdAt.
func pinnedTimeAt(min int) string {
	// base 2025-01-01T00:00:00, add `min` minutes. Hand-formatted to stay
	// byte-stable and avoid any timezone/locale drift.
	return fmt.Sprintf("2025-01-01T00:%02d:00.000Z", min)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// signJWS builds a JWS with a CID-bearing header. The CID is derived from the
// payload via DagCborCID.
func signJWS(typ, kid string, payload map[string]any, priv ed25519.PrivateKey) (token, cid string) {
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		panic(err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: typ, Kid: kid, CID: cidStr}
	tok, err := dfos.CreateJWS(header, payload, priv)
	if err != nil {
		panic(err)
	}
	return tok, cidStr
}

// identityCreate builds a genesis identity-op (1 key for all roles) and derives
// the DID. The genesis kid is the BARE key ID.
func identityCreate(priv ed25519.PrivateKey, pub ed25519.PublicKey, keyID string) (token, did, opCID string) {
	mk := dfos.NewMultikeyPublicKey(keyID, pub)
	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       []dfos.MultikeyPublicKey{mk},
		"assertKeys":     []dfos.MultikeyPublicKey{mk},
		"controllerKeys": []dfos.MultikeyPublicKey{mk},
		"createdAt":      pinnedTime,
	}
	_, cidBytes, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		panic(err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: keyID, CID: cidStr}
	token = must(dfos.CreateJWS(header, payload, priv))
	did = dfos.DeriveDID(cidBytes)
	return token, did, cidStr
}

func profileArtifact(did, keyID string, priv ed25519.PrivateKey) (token, cid string) {
	kid := did + "#" + keyID
	payload := map[string]any{
		"version": 1,
		"type":    "artifact",
		"did":     did,
		"content": map[string]any{
			"$schema": "https://schemas.dfos.com/profile/v1",
			"name":    "DFOS Relay",
		},
		"createdAt": pinnedTime,
	}
	return signJWS("did:dfos:artifact", kid, payload, priv)
}

func contentCreate(did, docCID, kid, createdAt string, priv ed25519.PrivateKey) (token, contentID, opCID string) {
	payload := map[string]any{
		"version":         1,
		"type":            "create",
		"did":             did,
		"documentCID":     docCID,
		"baseDocumentCID": nil,
		"createdAt":       createdAt,
	}
	_, cidBytes, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		panic(err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}
	token = must(dfos.CreateJWS(header, payload, priv))
	contentID = dfos.DeriveContentID(cidBytes)
	return token, contentID, cidStr
}

func contentUpdate(did, prevCID, docCID, kid, createdAt string, priv ed25519.PrivateKey) (token, opCID string) {
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"did":                  did,
		"previousOperationCID": prevCID,
		"documentCID":          docCID,
		"baseDocumentCID":      nil,
		"createdAt":            createdAt,
	}
	return signJWS("did:dfos:content-op", kid, payload, priv)
}

func publicCredential(issuerDID, kid string, priv ed25519.PrivateKey) (token, cid string) {
	payload := map[string]any{
		"version": 1,
		"type":    "DFOSCredential",
		"iss":     issuerDID,
		"aud":     "*",
		"att":     []any{map[string]any{"resource": "chain:*", "action": "read"}},
		"prf":     []any{},
		"exp":     int64(4102444800), // 2100-01-01, far future, fixed
		"iat":     int64(1735689600), // 2025-01-01, fixed
	}
	return signJWS("did:dfos:credential", kid, payload, priv)
}

func docCID(doc map[string]any) string {
	cid, _, err := dfos.DocumentCID(doc)
	if err != nil {
		panic(err)
	}
	return cid
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: genfixture <output-path>")
		os.Exit(1)
	}
	out := os.Args[1]

	// --- relay identity (pinned, seed 1) ---
	relayPriv, relayPub := seededKey(1)
	relayKeyID := "key_relay00000000000000000000000"
	relayGenesis, relayDID, _ := identityCreate(relayPriv, relayPub, relayKeyID)
	relayProfile, _ := profileArtifact(relayDID, relayKeyID, relayPriv)

	// --- user A (seed 2) ---
	aPriv, aPub := seededKey(2)
	aKeyID := "key_userA00000000000000000000000"
	aGenesis, aDID, _ := identityCreate(aPriv, aPub, aKeyID)
	aKid := aDID + "#" + aKeyID

	// --- user B (seed 3) ---
	bPriv, bPub := seededKey(3)
	bKeyID := "key_userB00000000000000000000000"
	bGenesis, bDID, _ := identityCreate(bPriv, bPub, bKeyID)
	_ = bDID

	// --- content chain owned by A: create + update (strictly increasing createdAt) ---
	doc1 := docCID(map[string]any{"type": "post", "title": "first", "body": "hello"})
	cCreate, contentID, cCreateCID := contentCreate(aDID, doc1, aKid, pinnedTimeAt(1), aPriv)
	doc2 := docCID(map[string]any{"type": "post", "title": "second", "body": "world"})
	cUpdate, _ := contentUpdate(aDID, cCreateCID, doc2, aKid, pinnedTimeAt(2), aPriv)

	// --- artifact by A ---
	artPayload := map[string]any{
		"version":   1,
		"type":      "artifact",
		"did":       aDID,
		"content":   map[string]any{"$schema": "test/v1", "title": "a fixed artifact"},
		"createdAt": pinnedTime,
	}
	artifact, _ := signJWS("did:dfos:artifact", aKid, artPayload, aPriv)

	// --- public credential (aud:*) by A ---
	cred, _ := publicCredential(aDID, aKid, aPriv)

	fixture := Fixture{
		RelayDID:        relayDID,
		RelayProfileJWS: relayProfile,
		BootstrapOps:    []string{relayGenesis, relayProfile},
		// Dependency order: identities first (A, B), then A's content + artifact +
		// credential. The sequencer converges regardless of order, but a fixed
		// dependency order keeps the drained log deterministic and avoids relying
		// on retry timing for the byte-parity gate.
		Ops: []string{
			aGenesis,
			bGenesis,
			cCreate,
			cUpdate,
			artifact,
			cred,
		},
		QueryDID:       aDID,
		QueryContentID: contentID,
	}

	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote parity fixture to %s (relayDid=%s, %d ops)\n", out, relayDID, len(fixture.Ops))
}
