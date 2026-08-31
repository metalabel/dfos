package dfos

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// MultikeyPublicKey represents a public key in Multikey format.
type MultikeyPublicKey struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// DeclaredKeyState is the key arrays exactly as the chain's operations DECLARE
// them, before any question of possession. Structural state: what the controller
// wrote.
type DeclaredKeyState struct {
	AuthKeys       []MultikeyPublicKey `json:"authKeys"`
	AssertKeys     []MultikeyPublicKey `json:"assertKeys"`
	ControllerKeys []MultikeyPublicKey `json:"controllerKeys"`
}

// IsZero reports whether no declared state was ever recorded. A caller may hand a
// hand-built IdentityState to VerifyIdentityExtension; an absent declared state is
// read as "the effective arrays are also the declared arrays", which is exactly
// true for any chain with no void memberships and is the only reading available
// for a state that never recorded the difference.
func (s DeclaredKeyState) IsZero() bool {
	return len(s.AuthKeys) == 0 && len(s.AssertKeys) == 0 && len(s.ControllerKeys) == 0
}

// VoidKeyMembership is ONE DECLARED-BUT-UNPROVED KEY-ROLE MEMBERSHIP. The chain
// says this key holds this role; no possession proof ever admitted it, so
// consumers do not see it.
//
// VOID IS NOT INVALID. The operation that declared it is valid, the chain is
// valid, and the membership is simply absent from effective state. Enumerating
// these loudly is the point: a controller who introduced a key without a proof has
// a chain that verifies and a key that does not resolve, and the only way they
// learn that is if tooling can see the list.
type VoidKeyMembership struct {
	// Key is the key as declared.
	Key MultikeyPublicKey `json:"key"`
	// Role is the role it was declared into but is not effective for.
	Role KeyRole `json:"role"`
	// OperationCID is the CID of the operation whose declaration is unproved.
	OperationCID string `json:"operationCID"`
}

// IdentityState represents the verified state of an identity chain.
//
// AuthKeys/AssertKeys/ControllerKeys are EFFECTIVE state — the memberships a
// possession proof actually admitted — because effective state is what every
// consumer wants: a void key must never resolve, never index, and never enter a
// has-ever surface.
//
// Declared and VoidKeys carry the structural half alongside it, so the surfaces
// that genuinely need "what does the chain SAY" can ask. There is exactly one such
// surface in the protocol: SIGNER VALIDITY, which stays declared-state-based on
// purpose (see verify.go).
type IdentityState struct {
	DID            string              `json:"did"`
	IsDeleted      bool                `json:"isDeleted"`
	AuthKeys       []MultikeyPublicKey `json:"authKeys"`
	AssertKeys     []MultikeyPublicKey `json:"assertKeys"`
	ControllerKeys []MultikeyPublicKey `json:"controllerKeys"`
	Services       []ServiceEntry      `json:"services"`
	// Declared is what the chain declares, void memberships included.
	Declared DeclaredKeyState `json:"declared"`
	// VoidKeys are the declared memberships no proof admitted. Empty on a
	// fully-proved chain.
	//
	// ALWAYS SERIALIZED, deliberately not omitempty. The TypeScript twin emits
	// `voidKeys: []` on a fully-proved chain, and both relays serve this struct
	// verbatim on the same identity route — an omitempty here would make the two
	// relays answer the same identity with different JSON, which is precisely
	// what the parity suite exists to catch. Every construction path assigns a
	// non-nil slice, so this encodes as `[]` and never as `null`.
	VoidKeys []VoidKeyMembership `json:"voidKeys"`
	// ProvedKeys is HAS-EVER-PROVED: the union of every effective key state this
	// chain has held, across its whole history. Monotonic — a key that was proved
	// into a role and later removed stays here forever, because the fact it names
	// is that the holder once demonstrated possession, and that does not become
	// untrue.
	//
	// TWO SURFACES NEED EXACTLY THIS, and both are wrong without it:
	//
	//   - THE key= REVERSE INDEX, which is the one-key-one-DID oracle. A holder
	//     asks it before signing a key proof, and refuses when some chain already
	//     proved the key — because proving one key into two chains publishes an
	//     irreversible public link between them. A DECLARATION publishes no such
	//     link: anyone can write anyone's public key into their own chain, so
	//     indexing declarations would let a stranger burn a key they do not hold,
	//     by writing it into a chain and making every future ceremony refuse it.
	//   - HISTORICAL KEY RESOLUTION, which verifies long-lived artifacts across
	//     rotations. A credential signed by a key that was proved and later
	//     rotated out must still verify; one signed by a key no chain ever proved
	//     must not.
	//
	// Computed during the walk, where the fold already runs, so consumers stop
	// re-deriving it from the raw log under a declared-state rule that quietly
	// disagrees with this one.
	ProvedKeys DeclaredKeyState `json:"provedKeys"`
}

// NewMultikeyPublicKey creates a MultikeyPublicKey from an ed25519 public key.
func NewMultikeyPublicKey(keyID string, pubKey ed25519.PublicKey) MultikeyPublicKey {
	return MultikeyPublicKey{
		ID:                 keyID,
		Type:               "Multikey",
		PublicKeyMultibase: EncodeMultikey(pubKey),
	}
}

// SignIdentityCreate signs an identity genesis (create) operation.
// Returns the JWS token and derived DID.
func SignIdentityCreate(controllerKeys, authKeys, assertKeys []MultikeyPublicKey, signerKeyID string, privateKey ed25519.PrivateKey) (jwsToken string, did string, operationCID string, err error) {
	return SignIdentityCreateWithServices(controllerKeys, authKeys, assertKeys, nil, signerKeyID, privateKey)
}

// SignIdentityCreateWithServices is SignIdentityCreate plus a discovery-vocabulary
// services set. A nil/empty services slice is omitted from the payload entirely,
// so it encodes identically to a service-less genesis (CID-neutral).
//
// THE SINGLE-KEY GENESIS RULE IS ENFORCED HERE TOO. Genesis declares exactly one
// key, in all three roles, and its own signature is that key's possession proof —
// so any other shape is a chain no verifier will accept. Refusing it on the
// producer side is the same discipline SignKeyProof applies to an empty typ: a
// signer must not mint an artifact its own verifier rejects.
func SignIdentityCreateWithServices(controllerKeys, authKeys, assertKeys []MultikeyPublicKey, services []ServiceEntry, signerKeyID string, privateKey ed25519.PrivateKey) (jwsToken string, did string, operationCID string, err error) {
	now := protocolTimestamp()

	if err := assertSingleKeyGenesis(authKeys, assertKeys, controllerKeys); err != nil {
		return "", "", "", err
	}

	payload := map[string]any{
		"version":        1,
		"type":           "create",
		"authKeys":       authKeys,
		"assertKeys":     assertKeys,
		"controllerKeys": controllerKeys,
		"createdAt":      now.Format("2006-01-02T15:04:05.000Z"),
	}
	if len(services) > 0 {
		payload["services"] = services
	}

	_, cidBytes, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: signerKeyID, // bare key ID for genesis
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", "", err
	}

	did = DeriveDID(cidBytes)
	return jwsToken, did, cidStr, nil
}

// THE WRITER DOOR.
//
// A key's appearance in an identity chain is accompanied by that key's own
// signature over the appearance. Genesis is the one exception and proves itself —
// one key in all three roles, signing the operation that declares it. Every OTHER
// introduction carries an embedded envelope, and a membership no envelope covers
// is VOID: excluded from effective state, never indexed, resolving nowhere.
//
// Voiding is a READER's verdict, and it is deliberately lenient — a relay
// sequences an unproved introduction rather than rejecting it, because two relays
// disagreeing about whether an operation exists is the one divergence a gossip
// layer cannot heal. The WRITER is where strictness belongs instead: a chain that
// verifies and a key that does not work is a trap, and the party best placed to
// refuse it is the one about to author it. So these signers refuse what the walk
// would merely void.
//
// THE GATE RUNS THE READER'S OWN CODE. It calls foldEffectiveKeyState — the same
// fold the chain walk uses — rather than reimplementing coverage. A second
// implementation of the byte contract is exactly the twin that drifts, and a
// writer door disagreeing with the reader it guards would be worse than no door.

// assertIntroductionsProved is the gate both update signers run before they sign.
//
// It answers two questions with one mechanism. Running the fold with NO envelopes
// yields a void entry per (key, role) the operation INTRODUCES, which is the
// introduction set itself; running it again with the envelopes yields whatever
// they failed to cover. Nothing here re-derives what an introduction is.
func assertIntroductionsProved(prior IdentityState, previousCID string,
	controllerKeys, authKeys, assertKeys []MultikeyPublicKey, keyProofs []string) error {
	if prior.DID == "" {
		return fmt.Errorf("invalid identity update: prior state must name the chain being extended")
	}
	if len(keyProofs) > MaxKeyProofs {
		return fmt.Errorf("invalid identity update: keyProofs exceeds max count: %d > %d",
			len(keyProofs), MaxKeyProofs)
	}

	fold := keyProofFold{
		did:      prior.DID,
		declared: DeclaredKeyState{AuthKeys: authKeys, AssertKeys: assertKeys, ControllerKeys: controllerKeys},
		priorEffective: DeclaredKeyState{
			AuthKeys:       prior.AuthKeys,
			AssertKeys:     prior.AssertKeys,
			ControllerKeys: prior.ControllerKeys,
		},
		previousOperationCID: previousCID,
	}

	// Introductions, from the reader's own arithmetic: with no envelopes, every
	// introduced membership comes back void.
	_, introduced := foldEffectiveKeyState(fold)
	if len(introduced) == 0 {
		// An operation that introduces nothing has nothing for an envelope to
		// cover, so carrying one is a caller who has misunderstood what they are
		// signing. Refusing beats silently emitting a member the walk will ignore,
		// and beats changing the operation's CID for no reason.
		if len(keyProofs) > 0 {
			return fmt.Errorf("invalid identity update: %d key proof(s) carried by an operation that introduces no key",
				len(keyProofs))
		}
		return nil
	}

	fold.keyProofs = keyProofs
	_, uncovered := foldEffectiveKeyState(fold)
	if len(uncovered) > 0 {
		return fmt.Errorf("invalid identity update: %s", unprovedIntroductions(uncovered))
	}
	return nil
}

// unprovedIntroductions renders every uncovered (key, role) pair at once. A
// caller fixing them one refusal per run is a caller re-signing an operation
// several times to discover a list this function already has.
func unprovedIntroductions(void []VoidKeyMembership) string {
	pairs := make([]string, 0, len(void))
	for _, membership := range void {
		pairs = append(pairs, fmt.Sprintf("%s in %s", membership.Key.ID, membership.Role))
	}
	return fmt.Sprintf("%d key-role introduction(s) carry no possession proof (%s) — "+
		"a key enters a chain with its own signature over the introduction, and a membership no proof "+
		"covers is void: it never resolves and never indexes",
		len(void), strings.Join(pairs, ", "))
}

// SignIdentityUpdate signs an identity update operation (key rotation).
// The signer must use a current controller key. kid must be a DID URL
// (e.g., "did:dfos:xxx#key_yyy").
//
// prior is the verified state this update extends; keyProofs carries one envelope
// per key the operation introduces. See THE WRITER DOOR above.
func SignIdentityUpdate(prior IdentityState, previousCID string, controllerKeys, authKeys, assertKeys []MultikeyPublicKey, keyProofs []string, kid string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	return SignIdentityUpdateWithServices(prior, previousCID, controllerKeys, authKeys, assertKeys, nil, keyProofs, kid, privateKey)
}

// SignIdentityUpdateWithServices is SignIdentityUpdate plus a discovery-vocabulary
// services set. An update REPLACES the entire services state; a nil/empty slice is
// omitted from the payload (clears services, CID-neutral vs a service-less update).
func SignIdentityUpdateWithServices(prior IdentityState, previousCID string, controllerKeys, authKeys, assertKeys []MultikeyPublicKey, services []ServiceEntry, keyProofs []string, kid string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

	if authKeys == nil {
		authKeys = []MultikeyPublicKey{}
	}
	if assertKeys == nil {
		assertKeys = []MultikeyPublicKey{}
	}
	if controllerKeys == nil {
		controllerKeys = []MultikeyPublicKey{}
	}

	if err := assertIntroductionsProved(prior, previousCID, controllerKeys, authKeys, assertKeys, keyProofs); err != nil {
		return "", "", err
	}

	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"previousOperationCID": previousCID,
		"authKeys":             authKeys,
		"assertKeys":           assertKeys,
		"controllerKeys":       controllerKeys,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
	}
	if len(services) > 0 {
		payload["services"] = services
	}
	// OMITTED WHEN EMPTY, and that is a CID rule rather than a tidiness one: an
	// update that introduces nothing must encode identically to one signed before
	// the member existed.
	if len(keyProofs) > 0 {
		payload["keyProofs"] = keyProofs
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}

// SignIdentityDelete signs an identity delete operation (deactivation).
// The signer must use a current controller key.
func SignIdentityDelete(previousCID, kid string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":              1,
		"type":                 "delete",
		"previousOperationCID": previousCID,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}

// SignIdentityRestore signs an identity restore operation. It is valid only as
// the immediate successor of delete and must use a deleted-state controller key.
func SignIdentityRestore(previousCID, kid string, privateKey ed25519.PrivateKey) (jwsToken string, operationCID string, err error) {
	now := protocolTimestamp()

	payload := map[string]any{
		"version":              1,
		"type":                 "restore",
		"previousOperationCID": previousCID,
		"createdAt":            now.Format("2006-01-02T15:04:05.000Z"),
	}

	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		return "", "", err
	}

	header := JWSHeader{
		Alg: "EdDSA",
		Typ: "did:dfos:identity-op",
		Kid: kid,
		CID: cidStr,
	}

	jwsToken, err = CreateJWS(header, payload, privateKey)
	if err != nil {
		return "", "", err
	}

	return jwsToken, cidStr, nil
}
