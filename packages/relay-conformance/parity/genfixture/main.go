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

type FixtureBlob struct {
	ContentID    string          `json:"contentId"`
	OperationCID string          `json:"operationCid"`
	Body         json.RawMessage `json:"body"`
}

// Fixture is the on-disk shape shared by the TS serve script, the Go serve
// binary, and the parity test.
type Fixture struct {
	RelayDID        string        `json:"relayDid"`
	RelayProfileJWS string        `json:"relayProfileJws"`
	RelayContentID  string        `json:"relayContentId"` // unused placeholder for symmetry
	BootstrapOps    []string      `json:"bootstrapOps"`   // relay genesis + profile, replayed
	Ops             []string      `json:"ops"`            // fixed user op set
	Blobs           []FixtureBlob `json:"blobs"`          // held document bytes uploaded to both twins
	QueryAuthKeyID  string        `json:"queryAuthKeyId"`
	// QueryDIDs / QueryContentIDs let the test hit per-chain log routes.
	QueryDID         string `json:"queryDid"`
	QueryContentID   string `json:"queryContentId"`
	QueryDocumentCID string `json:"queryDocumentCid"`
	// QueryServiceDID resolves to an identity carrying a DfosRelay + ContentAnchor
	// + DfosAuthorizationServer services set; QueryDeletedDID resolves to a deactivated (create+delete)
	// identity. Both drive the universal-resolver parity cases.
	QueryServiceDID  string `json:"queryServiceDid"`
	QueryDeletedDID  string `json:"queryDeletedDid"`
	QueryProfileDID  string `json:"queryProfileDid"`
	QueryProfileName string `json:"queryProfileName"`
	// QueryRevokedCredentialCID is the CID of a credential issued AND revoked by
	// QueryRevocationIssuerDID (user B). Both drive the revocation-status parity
	// cases (/revocations/v1).
	QueryRevokedCredentialCID string `json:"queryRevokedCredentialCid"`
	QueryRevocationIssuerDID  string `json:"queryRevocationIssuerDid"`
	// QueryCountersignedCID is the CID of an op (A's content-create) that carries
	// one countersignature (witnessed by user B). Drives the countersignatures
	// route parity cases (/proof/v1/countersignatures).
	QueryCountersignedCID string `json:"queryCountersignedCid"`

	// --- signerKey= parity (/index/v0/operations) ---
	//
	// The multibase public keys are the strings the chains DECLARED, byte for
	// byte — the same alphabet /index/v0/identities?key= matches, which is the
	// reading both reference relays ship. A parity case that re-encoded them
	// would not be testing what a client can actually paste between the two
	// filters.
	//
	// QueryAuthKeyMultibase is A's key: it signs A's own genesis (with a BARE
	// kid — the DID does not exist until the op is encoded), A's content
	// create+update, A's profile content-create, A's artifact, and A's
	// credential. QueryWitnessKeyMultibase is B's: B's genesis, B's credential,
	// B's revocation, and the countersignature over A's content-create.
	QueryAuthKeyMultibase    string `json:"queryAuthKeyMultibase"`
	QueryWitnessKeyMultibase string `json:"queryWitnessKeyMultibase"`
	// QueryAuthGenesisCID / QueryWitnessCountersignCID name two rows by CID so a
	// parity assertion can prove the filter returned the GENESIS row (the
	// bare-kid shape a `#`-splitting resolver silently drops) and the
	// countersign row (which must index the WITNESS's key, never the
	// countersigned op author's).
	QueryAuthGenesisCID        string `json:"queryAuthGenesisCid"`
	QueryWitnessCountersignCID string `json:"queryWitnessCountersignCid"`
	// The rotation chain (user E): one identity, two keys. E1 signs the genesis
	// and the update that rotates itself out; E2 — declared BY that update —
	// signs the artifact that follows. `signerKey=` must partition those two row
	// sets, which is the discriminating shape for a KEY-addressed filter: a
	// DID-addressed one could not tell them apart. E1 also proves the ingest-time
	// freeze — a key a later update rotated out still matches the rows it signed.
	QueryRotationDID            string `json:"queryRotationDid"`
	QueryRotatedOutKeyMultibase string `json:"queryRotatedOutKeyMultibase"`
	QueryRotationKeyMultibase   string `json:"queryRotationKeyMultibase"`
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

// identityUpdate builds an update op that REPLACES the entire key set, signed
// by a controller key of the state BEFORE the update (a DID-URL kid). That is
// what rotates a key out: the op's own signer is the key the op removes, so the
// update row itself is indexed under the ROTATED-OUT key.
func identityUpdate(did, prevCID, signingKeyID, createdAt string, next dfos.MultikeyPublicKey, priv ed25519.PrivateKey) (token, opCID string) {
	kid := did + "#" + signingKeyID
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"previousOperationCID": prevCID,
		"authKeys":             []dfos.MultikeyPublicKey{next},
		"assertKeys":           []dfos.MultikeyPublicKey{next},
		"controllerKeys":       []dfos.MultikeyPublicKey{next},
		"createdAt":            createdAt,
	}
	return signJWS("did:dfos:identity-op", kid, payload, priv)
}

// artifactOp builds a pinned-createdAt artifact under an explicit DID-URL kid,
// so a fixture can name WHICH key of an identity signed it.
func artifactOp(did, kid, title, createdAt string, priv ed25519.PrivateKey) (token, cid string) {
	payload := map[string]any{
		"version":   1,
		"type":      "artifact",
		"did":       did,
		"content":   map[string]any{"$schema": "test/v1", "title": title},
		"createdAt": createdAt,
	}
	return signJWS("did:dfos:artifact", kid, payload, priv)
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

// countersign builds a pinned-createdAt standalone countersignature by a witness
// over a target op/artifact CID. Payload shape matches SignCountersign, which
// stamps wall-clock createdAt and so cannot be byte-pinned.
func countersign(witnessDID, targetCID, kid, createdAt string, priv ed25519.PrivateKey) (token, cid string) {
	payload := map[string]any{
		"version":   1,
		"type":      "countersign",
		"did":       witnessDID,
		"targetCID": targetCID,
		"createdAt": createdAt,
	}
	return signJWS("did:dfos:countersign", kid, payload, priv)
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
	aGenesis, aDID, aGenesisCID := identityCreate(aPriv, aPub, aKeyID)
	aKid := aDID + "#" + aKeyID

	// --- user B (seed 3) ---
	bPriv, bPub := seededKey(3)
	bKeyID := "key_userB00000000000000000000000"
	bGenesis, bDID, _ := identityCreate(bPriv, bPub, bKeyID)
	bKid := bDID + "#" + bKeyID

	// --- content chain owned by A: create + update (strictly increasing createdAt) ---
	doc1 := docCID(map[string]any{"type": "post", "title": "first", "body": "hello"})
	cCreate, contentID, cCreateCID := contentCreate(aDID, doc1, aKid, pinnedTimeAt(1), aPriv)
	contentDoc := map[string]any{
		"$schema": "https://schemas.dfos.com/post/v1",
		"title":   "second",
		"body":    "world",
		"credits": []any{
			map[string]any{"did": aDID, "role": "writing"},
			map[string]any{"did": bDID, "role": "editing", "claim": "opaque", "name": "never projected"},
		},
	}
	doc2 := docCID(contentDoc)
	cUpdate, cUpdateCID := contentUpdate(aDID, cCreateCID, doc2, aKid, pinnedTimeAt(2), aPriv)
	contentBody := must(json.Marshal(contentDoc))

	// --- artifact by A ---
	artPayload := map[string]any{
		"version":   1,
		"type":      "artifact",
		"did":       aDID,
		"content":   map[string]any{"$schema": "test/v1", "title": "a fixed artifact"},
		"createdAt": pinnedTime,
	}
	artifact, _ := signJWS("did:dfos:artifact", aKid, artPayload, aPriv)

	// --- public profile content owned by A ---
	// User C anchors this chain as its profile below. The blob is included in the
	// fixture and uploaded identically to both twins so nameContains and
	// hasPublicProfile parity exercise positive rows, not empty-result symmetry.
	const profileName = "Parity Profile"
	profileDoc := map[string]any{
		"$schema": "https://schemas.dfos.com/profile/v1",
		"name":    profileName,
	}
	profileDocCID := docCID(profileDoc)
	profileCreate, profileContentID, profileOperationCID := contentCreate(aDID, profileDocCID, aKid, pinnedTimeAt(3), aPriv)
	profileBody := must(json.Marshal(profileDoc))

	// --- public credential (aud:*) by A ---
	cred, _ := publicCredential(aDID, aKid, aPriv)

	// --- credential by B, revoked by B (revocation-status parity cases) ---
	// A separate issuer so A's standing public credential is untouched; the
	// revocation removes B's from the public set on BOTH twins identically.
	bCred, bCredCID := publicCredential(bDID, bKid, bPriv)
	bRevocation, _ := revocation(bDID, bCredCID, bKid, pinnedTimeAt(3), bPriv)

	// --- countersignature by B over A's content-create CID (countersign parity) ---
	// A witnesses nothing of its own; B (an already-ingested identity) attests to
	// A's content-create op, so /proof/v1/countersignatures/{cCreateCID} returns
	// exactly one countersignature on both twins.
	bCountersign, bCountersignCID := countersign(bDID, cCreateCID, bKid, pinnedTimeAt(4), bPriv)

	// --- user C (seed 4): genesis WITH a services set (DfosRelay + ContentAnchor
	// + DfosAuthorizationServer) ---
	// The ContentAnchor points at A's public profile chain, which satisfies the
	// contentId anchor shape validated at ingest and yields a named profile row.
	// The DfosAuthorizationServer entry is the open-namespace authorize origin
	// SIWD adds; it is here so the resolver parity case actually exercises the
	// endpoint→serviceEndpoint arm on BOTH twins rather than only in unit tests.
	cPriv, cPub := seededKey(4)
	cKeyID := "key_userC00000000000000000000000"
	cServices := []any{
		map[string]any{"id": "svc_relay", "type": "DfosRelay", "endpoint": "https://relay.example"},
		map[string]any{"id": "svc_anchor", "type": "ContentAnchor", "label": "profile", "anchor": profileContentID},
		map[string]any{"id": "svc_authz", "type": "DfosAuthorizationServer", "endpoint": "https://app.example"},
	}
	cGenesis, cDID, _ := identityCreateWithServices(cPriv, cPub, cKeyID, cServices)

	// --- user D (seed 5): genesis then delete (deactivated identity) ---
	dPriv, dPub := seededKey(5)
	dKeyID := "key_userD00000000000000000000000"
	dGenesis, dDID, dCreateCID := identityCreate(dPriv, dPub, dKeyID)
	dDelete, _ := identityDelete(dDID, dCreateCID, dKeyID, pinnedTimeAt(1), dPriv)

	// --- user E (seeds 6/7): ONE identity, TWO keys — the rotation chain ---
	//
	// E1 signs the genesis (bare kid) and the update that rotates ITSELF out;
	// E2, declared by that update, signs the artifact that follows. So
	// `signerKey=E1` must return {genesis, update} and `signerKey=E2` exactly
	// {artifact} — a partition no DID-addressed signer filter could produce, and
	// the ingest-time-freeze property (a rotated-out key still matches the rows
	// it signed) in the same corpus.
	//
	// Ordering is safe in one batch: both twins apply identity ops before
	// artifacts and genesis before extensions, so E2 is current state by the time
	// its artifact is verified.
	ePriv, ePub := seededKey(6)
	eNextPriv, eNextPub := seededKey(7)
	eKeyID := "key_userE00000000000000000000000"
	eNextKeyID := "key_userE20000000000000000000000"
	eGenesis, eDID, eGenesisCID := identityCreate(ePriv, ePub, eKeyID)
	eNextMK := dfos.NewMultikeyPublicKey(eNextKeyID, eNextPub)
	eUpdate, _ := identityUpdate(eDID, eGenesisCID, eKeyID, pinnedTimeAt(1), eNextMK, ePriv)
	eArtifact, _ := artifactOp(eDID, eDID+"#"+eNextKeyID, "signed after the rotation", pinnedTimeAt(2), eNextPriv)

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
			profileCreate,
			artifact,
			cred,
			bCred,
			bRevocation,
			bCountersign,
			cGenesis,
			dGenesis,
			dDelete,
			eGenesis,
			eUpdate,
			eArtifact,
		},
		Blobs: []FixtureBlob{
			{ContentID: contentID, OperationCID: cUpdateCID, Body: contentBody},
			{ContentID: profileContentID, OperationCID: profileOperationCID, Body: profileBody},
		},
		QueryAuthKeyID:            aKeyID,
		QueryDID:                  aDID,
		QueryContentID:            contentID,
		QueryDocumentCID:          doc2,
		QueryServiceDID:           cDID,
		QueryDeletedDID:           dDID,
		QueryProfileDID:           cDID,
		QueryProfileName:          profileName,
		QueryRevokedCredentialCID: bCredCID,
		QueryRevocationIssuerDID:  bDID,
		QueryCountersignedCID:     cCreateCID,

		QueryAuthKeyMultibase:      dfos.NewMultikeyPublicKey(aKeyID, aPub).PublicKeyMultibase,
		QueryWitnessKeyMultibase:   dfos.NewMultikeyPublicKey(bKeyID, bPub).PublicKeyMultibase,
		QueryAuthGenesisCID:        aGenesisCID,
		QueryWitnessCountersignCID: bCountersignCID,

		QueryRotationDID:            eDID,
		QueryRotatedOutKeyMultibase: dfos.NewMultikeyPublicKey(eKeyID, ePub).PublicKeyMultibase,
		QueryRotationKeyMultibase:   eNextMK.PublicKeyMultibase,
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
