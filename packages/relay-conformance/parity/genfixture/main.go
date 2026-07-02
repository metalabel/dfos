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
	// QueryServiceDID resolves to an identity carrying a DfosRelay + ContentAnchor
	// services set; QueryDeletedDID resolves to a deactivated (create+delete)
	// identity. Both drive the universal-resolver parity cases.
	QueryServiceDID string `json:"queryServiceDid"`
	QueryDeletedDID string `json:"queryDeletedDid"`
	// QueryRevokedCredentialCID is the CID of a credential issued AND revoked by
	// QueryRevocationIssuerDID (user B). Both drive the revocation-status parity
	// cases (/revocations/v1).
	QueryRevokedCredentialCID string `json:"queryRevokedCredentialCid"`
	QueryRevocationIssuerDID  string `json:"queryRevocationIssuerDid"`
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

// identityCreateWithServices is identityCreate plus a services set on the genesis
// payload (added BEFORE CID derivation so the DID commits to it). Exercises the
// resolver's service[] projection (DfosRelay + ContentAnchor).
func identityCreateWithServices(priv ed25519.PrivateKey, pub ed25519.PublicKey, keyID string, services []any) (token, did, opCID string) {
	mk := dfos.NewMultikeyPublicKey(keyID, pub)
	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       []dfos.MultikeyPublicKey{mk},
		"assertKeys":     []dfos.MultikeyPublicKey{mk},
		"controllerKeys": []dfos.MultikeyPublicKey{mk},
		"services":       services,
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

// identityDelete builds a delete op (permanent deactivation) chaining onto a
// genesis. The signer uses a DID-URL kid over a current controller key. createdAt
// is strictly after the genesis so the delete sequences deterministically.
func identityDelete(did, prevCID, keyID, createdAt string, priv ed25519.PrivateKey) (token, opCID string) {
	kid := did + "#" + keyID
	payload := map[string]any{
		"version":              1,
		"type":                 "delete",
		"previousOperationCID": prevCID,
		"createdAt":            createdAt,
	}
	return signJWS("did:dfos:identity-op", kid, payload, priv)
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

// revocation builds a pinned-createdAt revocation of a credential CID, signed by
// the issuer (issuer-only rule). Payload shape matches SignRevocation, which
// stamps wall-clock createdAt and so cannot be byte-pinned.
func revocation(issuerDID, credentialCID, kid, createdAt string, priv ed25519.PrivateKey) (token, cid string) {
	payload := map[string]any{
		"version":       1,
		"type":          "revocation",
		"did":           issuerDID,
		"credentialCID": credentialCID,
		"createdAt":     createdAt,
	}
	return signJWS("did:dfos:revocation", kid, payload, priv)
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
	bKid := bDID + "#" + bKeyID

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

	// --- credential by B, revoked by B (revocation-status parity cases) ---
	// A separate issuer so A's standing public credential is untouched; the
	// revocation removes B's from the public set on BOTH twins identically.
	bCred, bCredCID := publicCredential(bDID, bKid, bPriv)
	bRevocation, _ := revocation(bDID, bCredCID, bKid, pinnedTimeAt(3), bPriv)

	// --- user C (seed 4): genesis WITH a services set (DfosRelay + ContentAnchor) ---
	// The ContentAnchor points at A's 31-char content chain id, which satisfies the
	// contentId anchor shape validated at ingest.
	cPriv, cPub := seededKey(4)
	cKeyID := "key_userC00000000000000000000000"
	cServices := []any{
		map[string]any{"id": "svc_relay", "type": "DfosRelay", "endpoint": "https://relay.example"},
		map[string]any{"id": "svc_anchor", "type": "ContentAnchor", "label": "pinned", "anchor": contentID},
	}
	cGenesis, cDID, _ := identityCreateWithServices(cPriv, cPub, cKeyID, cServices)

	// --- user D (seed 5): genesis then delete (deactivated identity) ---
	dPriv, dPub := seededKey(5)
	dKeyID := "key_userD00000000000000000000000"
	dGenesis, dDID, dCreateCID := identityCreate(dPriv, dPub, dKeyID)
	dDelete, _ := identityDelete(dDID, dCreateCID, dKeyID, pinnedTimeAt(1), dPriv)

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
			bCred,
			bRevocation,
			cGenesis,
			dGenesis,
			dDelete,
		},
		QueryDID:                  aDID,
		QueryContentID:            contentID,
		QueryServiceDID:           cDID,
		QueryDeletedDID:           dDID,
		QueryRevokedCredentialCID: bCredCID,
		QueryRevocationIssuerDID:  bDID,
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
