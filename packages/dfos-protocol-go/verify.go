package dfos

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

// maxOperationSize is the max dag-cbor-encoded size (bytes) of a single identity
// or content operation payload — the one aggregate validity bound on operation
// size, measured over the exact bytes the CID commits to. Generously set (64 KiB)
// so it never binds a legitimate proof-layer operation while bounding decode/
// verify cost. VALIDITY-determining: MUST match the TS reference
// (MAX_OPERATION_SIZE in chain/schemas.ts). Credentials are NOT subject to this
// cap — their size is bounded by the delegation-depth and att/prf limits, and a
// max-depth chain legitimately exceeds it.
const maxOperationSize = 65536

// maxKeysPerRole bounds the number of keys in any single role array (authKeys,
// assertKeys, controllerKeys) on an identity operation. A CARDINALITY cap (DoS
// pre-allocation guard) — a generous ceiling on key fan-out; the op-size cap is
// the real byte arbiter. Enforced identically in the TS reference
// (MAX_KEYS_PER_ROLE in chain/schemas.ts).
const maxKeysPerRole = 256

// operationSizeForCap returns the dag-cbor-encoded byte length of an operation
// payload for the purpose of the op-size cap, EXCLUDING any embedded
// `authorization` credential. The op-size cap bounds the operation's own
// payload; an `authorization` credential is a separately-bounded object
// (maxCredentialSize), so counting it against the op cap would conflate two
// independent limits and reject a legitimate deep-delegation write — whose
// credential legitimately approaches its own (larger) cap. fullEncoded is the
// already-derived encoding of the complete payload (the common no-authorization
// case avoids a second encode). MUST match the TS reference (content-chain.ts).
func operationSizeForCap(payload map[string]any, fullEncoded []byte) (int, error) {
	auth, hasAuth := payload["authorization"].(string)
	if !hasAuth {
		return len(fullEncoded), nil
	}
	// the excluded authorization credential is independently bounded here, so
	// excluding it cannot smuggle unbounded bytes past both limits — total
	// operation bytes stay ≤ maxOperationSize + maxCredentialSize.
	if len(auth) > maxCredentialSize {
		return 0, fmt.Errorf("authorization credential exceeds max size: %d > %d", len(auth), maxCredentialSize)
	}
	rest := make(map[string]any, len(payload))
	for k, v := range payload {
		if k != "authorization" {
			rest[k] = v
		}
	}
	encoded, err := DagCborEncode(rest)
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

// KeyResolver resolves a kid (DID URL: "did:dfos:xxx#key_yyy") to an Ed25519 public key.
//
// A RESOLVER ERROR IS A TYPED FACT AND MUST REACH THE CALLER INTACT. Only the
// resolver knows WHY a key did not resolve — "the identity chain has not synced
// to this store yet" and "this kid is malformed" are the same `error` value at
// this seam, and only the resolver's own sentinel separates them. Every verify
// entrypoint in this package therefore re-wraps a resolver failure with %w and
// never %v or %s, so a caller can classify it with errors.Is.
//
// The rule exists because the alternative was tried and was a vulnerability: the
// relay used to classify "is this a missing dependency?" by substring-matching
// the error TEXT, and much of that text is attacker-influenced (a kid, a typ, a
// credential audience are all submitter-chosen and appear verbatim in messages
// here). A submitter could spell a permanent rejection so it read as retryable
// and the relay would keep and re-verify the operation forever. Preserving the
// chain is what lets the classification be a fact rather than a spelling.
// TestResolverErrorSurvivesEveryVerifyEntrypoint pins it.
type KeyResolver func(kid string) (ed25519.PublicKey, error)

// RevocationChecker reports whether a credential (by issuer DID + credential
// CID) has been revoked. Threaded onto the content WRITE path so revoked
// credentials — leaf AND parents — no longer authorize writes.
//
// asOfUnix selects WHICH question is being asked, and the two are different
// decisions: acceptance is a freshness decision; verification of committed
// history is a validity decision.
//
//   - asOfUnix <= 0 (timeless) — "is this credential revoked as far as you know
//     right now?". The freshness question, used by acceptance gates: relay
//     ingest (do not admit a NEW operation authorized by a credential we
//     already know to be revoked) and live read-path authorization. 0 is the
//     in-band sentinel, so "as of epoch 0" is not expressible; the whole
//     non-positive range is timeless in the TS twin too, which keeps the two
//     from answering that degenerate input oppositely (an operation dated at or
//     before 1970 gets the stricter answer in both).
//   - asOfUnix > 0 (as-of) — "was this credential already revoked at asOfUnix?".
//     The validity question. Report true only if a revocation exists AND its
//     signed createdAt is <= asOfUnix. Used when verifying operations already
//     committed to a chain, where asOfUnix is the operation's own createdAt. A
//     revocation signed AFTER an operation does not invalidate it — see
//     CREDENTIALS.md "Revocation Scope".
//
// An implementation that ignores asOfUnix degrades to the timeless answer, which
// is always the stricter (safe) direction. MUST stay in sync with the TS twin
// (dfos-credential.ts RevocationChecker).
type RevocationChecker func(issuerDID, credentialCID string, asOfUnix int64) (bool, error)

// IdentityDeletedChecker reports whether an identity (by DID) has been deleted.
// Threaded onto the content WRITE path so credentials issued by a deleted
// issuer/parent identity no longer authorize writes. The protocol package is
// store-agnostic, so the relay supplies this closure at the call boundary.
type IdentityDeletedChecker func(did string) (bool, error)

// contentVerifyOpts holds optional WRITE-path hardening callbacks threaded from
// the relay boundary. All are nil-safe — when a callback is nil the
// corresponding check is skipped (the protocol layer stays store-agnostic).
type contentVerifyOpts struct {
	isRevoked            RevocationChecker
	isDeleted            IdentityDeletedChecker
	credentialResolveKey KeyResolver
}

// ContentVerifyOption configures optional content-chain WRITE-path checks.
type ContentVerifyOption func(*contentVerifyOpts)

// WithRevocationChecker threads a leaf+parent revocation check onto the content
// write path.
func WithRevocationChecker(fn RevocationChecker) ContentVerifyOption {
	return func(o *contentVerifyOpts) { o.isRevoked = fn }
}

// WithIdentityDeletedChecker threads an issuer/parent isDeleted gate onto the
// content write path.
func WithIdentityDeletedChecker(fn IdentityDeletedChecker) ContentVerifyOption {
	return func(o *contentVerifyOpts) { o.isDeleted = fn }
}

// WithCredentialKeyResolver separates credential-history verification from
// operation-signature admission. When omitted, credentials use the operation
// resolver for backward compatibility.
func WithCredentialKeyResolver(fn KeyResolver) ContentVerifyOption {
	return func(o *contentVerifyOpts) { o.credentialResolveKey = fn }
}

// protocolTimeFormat is declared in timestamp.go

// contentIDLength is the expected length of a DFOS content ID.
const contentIDLength = 31

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

// VerifiedIdentityResult is the result of identity chain verification.
type VerifiedIdentityResult struct {
	State         IdentityState
	HeadCID       string
	LastCreatedAt string
}

// VerifiedContentResult is the result of content chain verification.
type VerifiedContentResult struct {
	State         ContentState
	LastCreatedAt string
}

// VerifiedArtifactResult is the result of artifact verification.
type VerifiedArtifactResult struct {
	ArtifactCID string
	DID         string
	Content     map[string]any
	CreatedAt   string
}

// VerifiedCountersignResult is the result of countersignature verification.
type VerifiedCountersignResult struct {
	CountersignCID string
	WitnessDID     string
	TargetCID      string
	// Relation is the open-namespace relation tag, empty when absent.
	Relation string
}

// -----------------------------------------------------------------------------
// Payload extraction helpers
// -----------------------------------------------------------------------------

func validateCreatedAt(createdAt string) error {
	if createdAt == "" {
		return fmt.Errorf("missing createdAt")
	}
	if _, err := time.Parse(protocolTimeFormat, createdAt); err != nil {
		return fmt.Errorf("invalid createdAt format")
	}
	return nil
}

func payloadString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func payloadStringPtr(m map[string]any, key string) *string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func payloadMultikeyArray(m map[string]any, key string) ([]MultikeyPublicKey, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an array", key)
	}
	if len(arr) > maxKeysPerRole {
		return nil, fmt.Errorf("%s exceeds max keys per role: %d > %d", key, len(arr), maxKeysPerRole)
	}
	result := make([]MultikeyPublicKey, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] is not an object", key, i)
		}
		id, _ := obj["id"].(string)
		typ, _ := obj["type"].(string)
		pkm, _ := obj["publicKeyMultibase"].(string)
		if typ != "Multikey" {
			return nil, fmt.Errorf("%s[%d]: invalid multikey", key, i)
		}
		result[i] = MultikeyPublicKey{ID: id, Type: typ, PublicKeyMultibase: pkm}
	}
	return result, nil
}

// -----------------------------------------------------------------------------
// The possession fold
// -----------------------------------------------------------------------------

// TWO KEY STATES, AND WHY. A chain carries what its controller DECLARED and,
// separately, what possession actually PROVED. The two differ because a
// controller can write any key into any role — declaring a key is a claim about
// someone else's private material, and a claim is not a demonstration.
//
//   - DECLARED state is structural: the full-state key arrays exactly as the
//     operations spell them.
//   - EFFECTIVE state is declared state minus every key-role membership no
//     possession proof admitted.
//
// THE BIMODAL PROOF RULE, WITH NO THIRD CASE. Genesis declares exactly ONE key,
// in all three roles, and SIGNS ITSELF with it — that signature is the proof, and
// it covers all three roles. Every OTHER key-role membership in the chain's life
// is proved by an embedded KEY-PROOF envelope and by nothing else. There is no
// grandfathering, no operator attestation, and no "the controller vouched for it".
//
// AN UNPROVED INTRODUCTION VOIDS A MEMBERSHIP, NOT AN OPERATION. The operation is
// valid, the chain is valid, the CID stands and relays sequence it. The key is
// simply not in effective state for that role, and shows up on VoidKeys so tooling
// can say so out loud. Voiding rather than rejecting is what keeps possession
// proofs off the ingest path: a relay that rejected unproved introductions would
// be a relay whose accept/reject verdict depends on evidence another relay might
// weigh differently, and two relays disagreeing about whether an operation exists
// is the one divergence a gossip layer cannot heal.
//
// SIGNER VALIDITY STAYS DECLARED-STATE-BASED, and this is load-bearing for the
// same reason. An operation's signer must be a controller key of the immediately
// prior DECLARED state. Gating signature admission on proof status would make
// chain VALIDITY — not just resolution — depend on the possession fold, and put
// the divergence back.
//
// Byte-twin of dfos-protocol/src/chain/identity-chain.ts.

// MaxKeyProofs bounds the keyProofs array on an identity update. A CARDINALITY
// cap (DoS pre-allocation guard). MUST match the TS reference (MAX_KEY_PROOFS in
// chain/schemas.ts), where it is a schema bound — so an operation carrying more is
// INVALID, not merely unproved.
const MaxKeyProofs = 256

// declaredRoleKeys returns the array a role's membership lives in.
func declaredRoleKeys(state DeclaredKeyState, role KeyRole) []MultikeyPublicKey {
	switch role {
	case "auth":
		return state.AuthKeys
	case "assert":
		return state.AssertKeys
	case "controller":
		return state.ControllerKeys
	}
	return nil
}

func appendRoleKey(state *DeclaredKeyState, role KeyRole, key MultikeyPublicKey) {
	switch role {
	case "auth":
		state.AuthKeys = append(state.AuthKeys, key)
	case "assert":
		state.AssertKeys = append(state.AssertKeys, key)
	case "controller":
		state.ControllerKeys = append(state.ControllerKeys, key)
	}
}

func emptyKeyState() DeclaredKeyState {
	return DeclaredKeyState{
		AuthKeys:       []MultikeyPublicKey{},
		AssertKeys:     []MultikeyPublicKey{},
		ControllerKeys: []MultikeyPublicKey{},
	}
}

// fullyProvedKeyState copies a key state where every declared membership is also
// effective — the genesis case, where the operation's own signature is the proof.
func fullyProvedKeyState(state DeclaredKeyState) DeclaredKeyState {
	return DeclaredKeyState{
		AuthKeys:       append([]MultikeyPublicKey{}, state.AuthKeys...),
		AssertKeys:     append([]MultikeyPublicKey{}, state.AssertKeys...),
		ControllerKeys: append([]MultikeyPublicKey{}, state.ControllerKeys...),
	}
}

// unionProvedKeyState folds one effective key state into a running
// HAS-EVER-PROVED union. Monotonic and first-wins: a key id already in the union
// keeps the entry it went in with, which is the same entry regardless, because
// key-material consistency is enforced chain-wide.
func unionProvedKeyState(into, next DeclaredKeyState) DeclaredKeyState {
	merged := emptyKeyState()
	for _, role := range KeyRoles {
		seen := map[string]bool{}
		for _, source := range [][]MultikeyPublicKey{
			declaredRoleKeys(into, role), declaredRoleKeys(next, role),
		} {
			for _, key := range source {
				if seen[key.ID] {
					continue
				}
				seen[key.ID] = true
				appendRoleKey(&merged, role, key)
			}
		}
	}
	return merged
}

// keyProofFold is the input to one operation's possession fold.
type keyProofFold struct {
	did string
	// declared is the operation's own full-state key arrays.
	declared DeclaredKeyState
	// priorEffective is effective state as of the operation immediately before.
	priorEffective DeclaredKeyState
	// previousOperationCID is what an envelope must name.
	previousOperationCID string
	// operationCID is stamped onto any void membership this operation leaves.
	operationCID string
	// keyProofs are the envelopes this operation carries.
	keyProofs []string
}

// foldEffectiveKeyState computes the key-role memberships an operation's key
// proofs admit.
//
// AN INTRODUCTION IS A TRANSITION, NOT A PRESENCE. An operation introduces key K
// to role R exactly when K is in the operation's R array and K was NOT in the
// PRIOR EFFECTIVE R state. Two consequences follow, and both are the point:
//
//   - An ordinary update that replays keys already effective introduces nothing
//     and needs no envelope. Full-state carriage moves key ARRAYS forward, never
//     the evidence that admitted them, so proofs never accumulate in a chain.
//   - Re-adding a removed key, or promoting an effective key into a role it did
//     not hold, IS a fresh introduction and needs a FRESH envelope. An old
//     envelope names an old prevCID and is dead against the current head, which is
//     precisely how standing consent is foreclosed: there is no envelope a
//     controller can bank against a future operation.
//
// Note that the prior state consulted is the EFFECTIVE one. A membership that went
// void at operation N is therefore introduced AGAIN at N+1, where a
// correctly-headed envelope can still rescue it — void is a state a chain can
// climb out of, not a mark.
func foldEffectiveKeyState(in keyProofFold) (DeclaredKeyState, []VoidKeyMembership) {
	carried := func(role KeyRole, key MultikeyPublicKey) bool {
		for _, prior := range declaredRoleKeys(in.priorEffective, role) {
			if prior.ID == key.ID {
				return true
			}
		}
		return false
	}

	// The introductions, indexed by key MATERIAL. Material rather than key id
	// because an envelope binds a Multikey: two ids naming the same material are
	// the same key, and one envelope proves both.
	type introduction struct {
		key   MultikeyPublicKey
		roles map[KeyRole]bool
	}
	introduced := map[string]*introduction{}
	for _, role := range KeyRoles {
		for _, key := range declaredRoleKeys(in.declared, role) {
			if carried(role, key) {
				continue
			}
			entry, ok := introduced[key.PublicKeyMultibase]
			if !ok {
				entry = &introduction{key: key, roles: map[KeyRole]bool{}}
				introduced[key.PublicKeyMultibase] = entry
			}
			entry.roles[role] = true
		}
	}

	// Route each envelope to the candidate it NAMES and gate it there. The routing
	// hint is unverified (see UnsafeKeyProofSubject); the gate immediately
	// re-checks it against the candidate's declared Multikey, so a forged hint only
	// reaches a candidate it then fails against.
	proved := map[string]map[KeyRole]bool{}
	for _, jws := range in.keyProofs {
		subject, ok := UnsafeKeyProofSubject(jws)
		if !ok {
			continue
		}
		candidate, ok := introduced[subject]
		if !ok {
			continue
		}
		for _, role := range KeyRoles {
			if !candidate.roles[role] {
				continue
			}
			if _, err := VerifyChainKeyProof(jws, ChainKeyProofExpectations{
				Typ:                KeyAddJWSTyp,
				DID:                in.did,
				PrevCID:            in.previousOperationCID,
				PublicKeyMultibase: candidate.key.PublicKeyMultibase,
				Role:               role,
			}); err != nil {
				// Not proof of THIS membership. Never fatal: an envelope that fails
				// here is evidence that did not apply, not an invalid chain.
				continue
			}
			covered, ok := proved[subject]
			if !ok {
				covered = map[KeyRole]bool{}
				proved[subject] = covered
			}
			covered[role] = true
		}
	}

	effective := emptyKeyState()
	voidKeys := []VoidKeyMembership{}
	for _, role := range KeyRoles {
		for _, key := range declaredRoleKeys(in.declared, role) {
			if carried(role, key) || proved[key.PublicKeyMultibase][role] {
				appendRoleKey(&effective, role, key)
			} else {
				voidKeys = append(voidKeys, VoidKeyMembership{
					Key: key, Role: role, OperationCID: in.operationCID,
				})
			}
		}
	}
	return effective, voidKeys
}

// assertSingleKeyGenesis applies THE SINGLE-KEY GENESIS RULE, structural. A
// genesis operation declares exactly ONE key: one entry in each of the three
// arrays, and the same key in all three.
//
// This is a REJECT, not a void, and it is the only key rule in the chain that is.
// Genesis is the one operation whose keys are proved by the operation's own
// signature, and one signature demonstrates possession of exactly one key — so a
// genesis declaring a second key would be declaring a membership that the bimodal
// rule has no way to prove and no later operation can rescue, since nothing
// precedes genesis to be a prevCID. Rather than mint a chain that is born with a
// permanently void membership, the shape is refused outright. A second key joins
// the ordinary way: an update, carrying an envelope.
func assertSingleKeyGenesis(authKeys, assertKeys, controllerKeys []MultikeyPublicKey) error {
	if len(authKeys) != 1 || len(assertKeys) != 1 || len(controllerKeys) != 1 {
		return fmt.Errorf("create must declare exactly one key in each of auth, assert and controller")
	}
	same := func(a, b MultikeyPublicKey) bool {
		return a.ID == b.ID && a.Type == b.Type && a.PublicKeyMultibase == b.PublicKeyMultibase
	}
	if !same(authKeys[0], assertKeys[0]) || !same(authKeys[0], controllerKeys[0]) {
		return fmt.Errorf("create must declare the SAME key in auth, assert and controller")
	}
	return nil
}

// parseKeyProofs applies THE CARRIAGE GATE and reads the envelopes off an
// operation. keyProofs is valid on update and nowhere else — a create, delete or
// restore carrying one is an INVALID operation.
//
// A rejection rather than a MUST-ignore, unlike every other unknown member on
// these loose payloads, because a proof on one of those three operations is not an
// unknown extension a later version might define: it is a claim in a position
// where the bimodal rule already has an answer. On create the answer is the genesis
// signature; on delete and restore there is nothing to introduce. Ignoring it would
// let an operation carry evidence that reads as consequential and is not.
func parseKeyProofs(payload map[string]any, opType string) ([]string, error) {
	raw, present := payload["keyProofs"]
	if !present {
		return nil, nil
	}
	if opType != "update" {
		return nil, fmt.Errorf("keyProofs is valid on update only, not on %s", opType)
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("keyProofs must be an array of strings")
	}
	if len(arr) > MaxKeyProofs {
		return nil, fmt.Errorf("keyProofs exceeds max count: %d > %d", len(arr), MaxKeyProofs)
	}
	proofs := make([]string, len(arr))
	for i, item := range arr {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("keyProofs[%d] is not a string", i)
		}
		proofs[i] = value
	}
	return proofs, nil
}

// -----------------------------------------------------------------------------
// Identity chain verification
// -----------------------------------------------------------------------------

// VerifyIdentityChain verifies a log of JWS identity operations and derives
// the identity state. The chain is self-sovereign — keys are resolved from
// the chain itself, no external resolver needed.
//
// Walks the chain from genesis, verifying signatures and chain integrity, and
// folds the possession proofs alongside. The returned state's key arrays are
// EFFECTIVE state, with the declared arrays and the void memberships beside them.
func VerifyIdentityChain(log []string) (*VerifiedIdentityResult, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("log must have at least one operation")
	}

	var (
		did           string
		isDeleted     bool
		previousCID   string
		lastCreatedAt string
		// declared is what the chain SAYS — the arbiter of signer validity.
		declared = emptyKeyState()
		// effective is what possession PROVED — what consumers get.
		effective = emptyKeyState()
		// provedKeys is every membership possession has EVER proved. Monotonic.
		provedKeys = emptyKeyState()
		voidKeys   = []VoidKeyMembership{}
		services   []ServiceEntry
		seenKeys   = make(map[string]MultikeyPublicKey)
	)

	for idx, jwsToken := range log {
		header, payload, err := DecodeJWSUnsafe(jwsToken)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to decode JWS", idx)
		}

		opType := payloadString(payload, "type")
		createdAt := payloadString(payload, "createdAt")

		// validate basics
		if v, ok := payload["version"].(int64); !ok || v != 1 {
			return nil, fmt.Errorf("log[%d]: invalid or missing version", idx)
		}
		if opType != "create" && opType != "update" && opType != "delete" && opType != "restore" {
			return nil, fmt.Errorf("log[%d]: invalid operation type", idx)
		}
		if err := validateCreatedAt(createdAt); err != nil {
			return nil, fmt.Errorf("log[%d]: %w", idx, err)
		}
		if header.Typ != "did:dfos:identity-op" {
			return nil, fmt.Errorf("log[%d]: invalid typ: %s", idx, header.Typ)
		}

		// A deleted identity admits exactly restore. Since nothing else may
		// follow delete, isDeleted proves the immediate parent was delete.
		if isDeleted && opType != "restore" {
			return nil, fmt.Errorf("log[%d]: cannot modify a deleted identity", idx)
		}
		if !isDeleted && opType == "restore" {
			return nil, fmt.Errorf("log[%d]: restore must immediately follow delete", idx)
		}

		// type sequence
		if idx == 0 && opType != "create" {
			return nil, fmt.Errorf("log[%d]: first operation must be create", idx)
		}
		if idx > 0 && opType == "create" {
			return nil, fmt.Errorf("log[%d]: create can only be the first operation", idx)
		}

		// key proofs ride on update and nowhere else
		keyProofs, err := parseKeyProofs(payload, opType)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: %w", idx, err)
		}

		// parse keys for create/update
		var opAuthKeys, opAssertKeys, opControllerKeys []MultikeyPublicKey
		if opType == "create" || opType == "update" {
			opControllerKeys, err = payloadMultikeyArray(payload, "controllerKeys")
			if err != nil {
				return nil, fmt.Errorf("log[%d]: %w", idx, err)
			}
			if opType == "update" && len(opControllerKeys) == 0 {
				return nil, fmt.Errorf("log[%d]: update must have at least one controller key", idx)
			}
			opAuthKeys, err = payloadMultikeyArray(payload, "authKeys")
			if err != nil {
				return nil, fmt.Errorf("log[%d]: %w", idx, err)
			}
			opAssertKeys, err = payloadMultikeyArray(payload, "assertKeys")
			if err != nil {
				return nil, fmt.Errorf("log[%d]: %w", idx, err)
			}
		}
		opDeclared := DeclaredKeyState{
			AuthKeys:       opAuthKeys,
			AssertKeys:     opAssertKeys,
			ControllerKeys: opControllerKeys,
		}

		// parse services (discovery vocabulary) for create/update — full-state
		var opServices []ServiceEntry
		if opType == "create" || opType == "update" {
			opServices, err = parseServices(payload)
			if err != nil {
				return nil, fmt.Errorf("log[%d]: %w", idx, err)
			}
		}

		// initialize key state from genesis
		if opType == "create" {
			if err := assertSingleKeyGenesis(opAuthKeys, opAssertKeys, opControllerKeys); err != nil {
				return nil, fmt.Errorf("log[%d]: %w", idx, err)
			}
			// Genesis declares one key and signs itself with it, so declared and
			// effective are the same set and there is nothing to void. Declared state
			// is assigned HERE, before the signature check below, because genesis is
			// the one operation whose signer is resolved against its own declaration.
			declared = opDeclared
			effective = fullyProvedKeyState(declared)
			provedKeys = fullyProvedKeyState(declared)
			services = opServices
		}

		// chain integrity for non-genesis
		if opType != "create" {
			prevCID := payloadString(payload, "previousOperationCID")
			if prevCID != previousCID {
				return nil, fmt.Errorf("log[%d]: previousCID is incorrect", idx)
			}
			if lastCreatedAt == "" {
				return nil, fmt.Errorf("log[%d]: lastCreatedAt is not set", idx)
			}
			if createdAt <= lastCreatedAt {
				return nil, fmt.Errorf("log[%d]: createdAt must be after last op", idx)
			}
		}

		// key consistency — same key ID must always map to same material.
		// DECLARED, not effective: key-material consistency is a property of what
		// the chain wrote, and a void key still may not change its material later.
		if opType == "create" || opType == "update" {
			allKeys := make([]MultikeyPublicKey, 0)
			allKeys = append(allKeys, declared.AuthKeys...)
			allKeys = append(allKeys, declared.AssertKeys...)
			allKeys = append(allKeys, declared.ControllerKeys...)
			allKeys = append(allKeys, opAuthKeys...)
			allKeys = append(allKeys, opAssertKeys...)
			allKeys = append(allKeys, opControllerKeys...)

			for _, k := range allKeys {
				existing, found := seenKeys[k.ID]
				if !found {
					seenKeys[k.ID] = k
				} else if existing.PublicKeyMultibase != k.PublicKeyMultibase || existing.Type != k.Type {
					return nil, fmt.Errorf("log[%d]: key %s type or public key inconsistency", idx, k.ID)
				}
			}

			// no duplicate key IDs within a usage section
			for _, keys := range [][]MultikeyPublicKey{opAuthKeys, opAssertKeys, opControllerKeys} {
				seen := make(map[string]bool)
				for _, k := range keys {
					if seen[k.ID] {
						return nil, fmt.Errorf("log[%d]: cannot repeat key ids in same usage", idx)
					}
					seen[k.ID] = true
				}
			}
		}

		// derive operation CID from payload
		cborBytes, cidBytes, operationCID, err := DagCborCID(payload)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to derive CID: %w", idx, err)
		}
		if len(cborBytes) > maxOperationSize {
			return nil, fmt.Errorf("log[%d]: operation exceeds max size: %d > %d", idx, len(cborBytes), maxOperationSize)
		}

		// verify cid header
		if header.CID == "" {
			return nil, fmt.Errorf("log[%d]: missing cid in protected header", idx)
		}
		if header.CID != operationCID {
			return nil, fmt.Errorf("log[%d]: cid mismatch in protected header", idx)
		}

		// resolve signing key from kid
		kid := header.Kid
		var signingKeyID string
		if strings.Contains(kid, "#") {
			hashIdx := strings.Index(kid, "#")
			signingKeyID = kid[hashIdx+1:]
			if idx == 0 {
				return nil, fmt.Errorf("log[%d]: genesis op kid must be bare key ID, got DID URL", idx)
			}
		} else {
			signingKeyID = kid
			if idx > 0 {
				return nil, fmt.Errorf("log[%d]: non-genesis op kid must be DID URL, got bare key ID", idx)
			}
		}

		// Find the controller key referenced by kid — in DECLARED state, on purpose.
		// Proof status does not gate signature admission: chain validity must not
		// depend on the possession fold, or two relays weighing evidence differently
		// would disagree about whether an operation exists.
		var signingKey *MultikeyPublicKey
		for i := range declared.ControllerKeys {
			if declared.ControllerKeys[i].ID == signingKeyID {
				signingKey = &declared.ControllerKeys[i]
				break
			}
		}
		if signingKey == nil {
			return nil, fmt.Errorf("log[%d]: kid references unknown key: %s", idx, signingKeyID)
		}

		// verify JWS signature
		keyBytes, err := DecodeMultikey(signingKey.PublicKeyMultibase)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to decode key: %w", idx, err)
		}
		if _, _, err := VerifyJWS(jwsToken, keyBytes); err != nil {
			return nil, fmt.Errorf("log[%d]: invalid signature", idx)
		}

		// derive DID from genesis CID
		if did == "" {
			did = DeriveDID(cidBytes)
		}

		// verify DID in kid for non-genesis
		if idx > 0 && strings.Contains(kid, "#") {
			didFromKid := kid[:strings.Index(kid, "#")]
			if didFromKid != did {
				return nil, fmt.Errorf("log[%d]: kid DID does not match identity DID", idx)
			}
		}

		// advance state
		previousCID = operationCID
		lastCreatedAt = createdAt

		switch opType {
		case "update":
			// The possession fold runs against the state that held BEFORE this
			// operation, then declared state advances. Order matters: an
			// introduction is a transition out of the PRIOR effective state.
			foldedEffective, foldedVoid := foldEffectiveKeyState(keyProofFold{
				did:                  did,
				declared:             opDeclared,
				priorEffective:       effective,
				previousOperationCID: payloadString(payload, "previousOperationCID"),
				operationCID:         operationCID,
				keyProofs:            keyProofs,
			})
			declared = opDeclared
			effective = foldedEffective
			provedKeys = unionProvedKeyState(provedKeys, foldedEffective)
			voidKeys = foldedVoid
			services = opServices
		case "delete":
			isDeleted = true
		case "restore":
			isDeleted = false
		}
	}

	if did == "" {
		return nil, fmt.Errorf("did is not set")
	}

	return &VerifiedIdentityResult{
		State: IdentityState{
			DID:       did,
			IsDeleted: isDeleted,
			// EFFECTIVE state is what a consumer gets. A void key never resolves.
			AuthKeys:       effective.AuthKeys,
			AssertKeys:     effective.AssertKeys,
			ControllerKeys: effective.ControllerKeys,
			Services:       normalizeServices(services),
			Declared:       declared,
			VoidKeys:       voidKeys,
			ProvedKeys:     provedKeys,
		},
		HeadCID:       previousCID,
		LastCreatedAt: lastCreatedAt,
	}, nil
}

// VerifyIdentityExtension verifies a single new operation against
// already-verified identity state. O(1) — one signature verification,
// one state transition.
//
// THE POSSESSION FOLD RUNS HERE TOO, and it needs both halves of the trusted
// state: the EFFECTIVE arrays (to know what an introduction is a transition out
// of) and the DECLARED arrays (to admit the signer). currentState.Declared
// carries the second. When it is absent — a hand-built state, or one produced
// before this member existed — the effective arrays stand in for it, which is
// exactly correct for any chain with no void memberships and is the only reading
// available for a state that never recorded the difference.
func VerifyIdentityExtension(currentState IdentityState, headCID, lastCreatedAt, newOp string) (*VerifiedIdentityResult, error) {
	priorEffective := DeclaredKeyState{
		AuthKeys:       currentState.AuthKeys,
		AssertKeys:     currentState.AssertKeys,
		ControllerKeys: currentState.ControllerKeys,
	}
	priorDeclared := currentState.Declared
	if priorDeclared.IsZero() {
		priorDeclared = priorEffective
	}
	// Absent has-ever-proved history reads as "what is effective now was proved" —
	// true for any chain that never voided a membership, and the only reading
	// available for a state that did not record the difference.
	priorProved := currentState.ProvedKeys
	if priorProved.IsZero() {
		priorProved = priorEffective
	}

	header, payload, err := DecodeJWSUnsafe(newOp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWS")
	}

	opType := payloadString(payload, "type")
	createdAt := payloadString(payload, "createdAt")

	if v, ok := payload["version"].(int64); !ok || v != 1 {
		return nil, fmt.Errorf("invalid or missing version")
	}
	if header.Typ != "did:dfos:identity-op" {
		return nil, fmt.Errorf("invalid typ: %s", header.Typ)
	}
	if opType == "create" {
		return nil, fmt.Errorf("extension cannot be a create operation")
	}
	if opType != "update" && opType != "delete" && opType != "restore" {
		return nil, fmt.Errorf("invalid operation type")
	}

	// key proofs ride on update and nowhere else
	keyProofs, err := parseKeyProofs(payload, opType)
	if err != nil {
		return nil, err
	}

	if currentState.IsDeleted && opType != "restore" {
		return nil, fmt.Errorf("cannot extend a deleted identity")
	}
	if !currentState.IsDeleted && opType == "restore" {
		return nil, fmt.Errorf("restore must immediately follow delete")
	}
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, err
	}

	// chain integrity
	prevCID := payloadString(payload, "previousOperationCID")
	if prevCID != headCID {
		return nil, fmt.Errorf("previousCID is incorrect")
	}
	if createdAt <= lastCreatedAt {
		return nil, fmt.Errorf("createdAt must be after last op")
	}

	// derive CID
	cborBytes, _, operationCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive CID: %w", err)
	}
	if len(cborBytes) > maxOperationSize {
		return nil, fmt.Errorf("operation exceeds max size: %d > %d", len(cborBytes), maxOperationSize)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in protected header")
	}
	if header.CID != operationCID {
		return nil, fmt.Errorf("cid mismatch in protected header")
	}

	// resolve kid — must be DID URL for non-genesis
	kid := header.Kid
	if !strings.Contains(kid, "#") {
		return nil, fmt.Errorf("non-genesis op kid must be DID URL, got bare key ID")
	}
	hashIdx := strings.Index(kid, "#")
	signingKeyID := kid[hashIdx+1:]
	kidDid := kid[:hashIdx]
	if kidDid != currentState.DID {
		return nil, fmt.Errorf("kid DID does not match identity DID")
	}

	// DECLARED state admits the signer — proof status must not gate signature
	// admission, or chain validity would depend on the possession fold.
	var signingKey *MultikeyPublicKey
	for i := range priorDeclared.ControllerKeys {
		if priorDeclared.ControllerKeys[i].ID == signingKeyID {
			signingKey = &priorDeclared.ControllerKeys[i]
			break
		}
	}
	if signingKey == nil {
		return nil, fmt.Errorf("kid references unknown key: %s", signingKeyID)
	}

	// verify signature
	keyBytes, err := DecodeMultikey(signingKey.PublicKeyMultibase)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	if _, _, err := VerifyJWS(newOp, keyBytes); err != nil {
		return nil, fmt.Errorf("invalid signature")
	}

	// key duplicate check for update
	if opType == "update" {
		opControllerKeys, err := payloadMultikeyArray(payload, "controllerKeys")
		if err != nil {
			return nil, err
		}
		if len(opControllerKeys) == 0 {
			return nil, fmt.Errorf("update must have at least one controller key")
		}
		opAuthKeys, err := payloadMultikeyArray(payload, "authKeys")
		if err != nil {
			return nil, err
		}
		opAssertKeys, err := payloadMultikeyArray(payload, "assertKeys")
		if err != nil {
			return nil, err
		}
		for _, keys := range [][]MultikeyPublicKey{opAuthKeys, opAssertKeys, opControllerKeys} {
			seen := make(map[string]bool)
			for _, k := range keys {
				if seen[k.ID] {
					return nil, fmt.Errorf("cannot repeat key ids in same usage")
				}
				seen[k.ID] = true
			}
		}

		// update REPLACES the full services state
		opServices, err := parseServices(payload)
		if err != nil {
			return nil, err
		}

		opDeclared := DeclaredKeyState{
			AuthKeys:       opAuthKeys,
			AssertKeys:     opAssertKeys,
			ControllerKeys: opControllerKeys,
		}
		foldedEffective, foldedVoid := foldEffectiveKeyState(keyProofFold{
			did:                  currentState.DID,
			declared:             opDeclared,
			priorEffective:       priorEffective,
			previousOperationCID: prevCID,
			operationCID:         operationCID,
			keyProofs:            keyProofs,
		})

		return &VerifiedIdentityResult{
			State: IdentityState{
				DID:            currentState.DID,
				IsDeleted:      false,
				AuthKeys:       foldedEffective.AuthKeys,
				AssertKeys:     foldedEffective.AssertKeys,
				ControllerKeys: foldedEffective.ControllerKeys,
				Services:       normalizeServices(opServices),
				Declared:       opDeclared,
				VoidKeys:       foldedVoid,
				ProvedKeys:     unionProvedKeyState(priorProved, foldedEffective),
			},
			HeadCID:       operationCID,
			LastCreatedAt: createdAt,
		}, nil
	}

	// delete and restore introduce nothing, so both key states — and the void
	// list — travel forward untouched.
	voidKeys := currentState.VoidKeys
	if voidKeys == nil {
		voidKeys = []VoidKeyMembership{}
	}
	return &VerifiedIdentityResult{
		State: IdentityState{
			DID:            currentState.DID,
			IsDeleted:      opType == "delete",
			AuthKeys:       currentState.AuthKeys,
			AssertKeys:     currentState.AssertKeys,
			ControllerKeys: currentState.ControllerKeys,
			Services:       normalizeServices(currentState.Services),
			Declared:       priorDeclared,
			VoidKeys:       voidKeys,
			ProvedKeys:     priorProved,
		},
		HeadCID:       operationCID,
		LastCreatedAt: createdAt,
	}, nil
}

// -----------------------------------------------------------------------------
// Content authorization verification (internal)
// -----------------------------------------------------------------------------

// verifyContentAuthorization verifies that a delegated content operation has a
// valid DFOS credential authorizing the signer to write to this content chain.
// Walks the delegation chain to confirm it roots at the creator DID.
//
// WRITE-path hardening (mirrors the relay READ path / the TS twin):
//   - issuer-isDeleted gate (via opts.isDeleted)
//   - aud:"*" wildcard accepted (subject="" + explicit aud check)
//   - action/resource matched via matchesResource (comma-split + scan-ALL att
//     entries), not the first-entry break in verifyCredentialCore
//   - explicit LEAF revocation check (verifyDelegationChain covers PARENTS only)
func verifyContentAuthorization(authorization, opDID, creatorDID, contentID, createdAt string, resolveKey KeyResolver, opts contentVerifyOpts) error {
	vcHeader, vcPayload, vcErr := DecodeJWSUnsafe(authorization)
	if vcErr != nil {
		return fmt.Errorf("failed to decode authorization credential")
	}
	vcKid := vcHeader.Kid
	if vcKid == "" || !strings.Contains(vcKid, "#") {
		return fmt.Errorf("authorization credential kid must be a DID URL")
	}

	// issuer-isDeleted gate — a credential from a deleted issuer authorizes
	// nothing (mirrors read-path auth.go:137-140 / TS verifyDFOSCredential).
	issuerDID := vcKid[:strings.Index(vcKid, "#")]
	if opts.isDeleted != nil {
		deleted, err := opts.isDeleted(issuerDID)
		if err != nil {
			return fmt.Errorf("issuer delete-check failed: %w", err)
		}
		if deleted {
			return fmt.Errorf("credential issuer identity is deleted")
		}
	}

	credentialResolveKey := opts.credentialResolveKey
	if credentialResolveKey == nil {
		credentialResolveKey = resolveKey
	}
	creatorPubKey, err := credentialResolveKey(vcKid)
	if err != nil {
		// %w, never %v: the resolver's error is the ONLY carrier of "this
		// identity is not here yet" and a caller (the relay ingest classifier)
		// branches on it with errors.Is. Flattening it to text would force that
		// caller back onto substring matching of a message an attacker can
		// influence.
		return fmt.Errorf("cannot resolve creator key for authorization verification: %w", err)
	}

	opTime, parseErr := time.Parse(protocolTimeFormat, createdAt)
	if parseErr != nil {
		return fmt.Errorf("invalid createdAt format: %w", parseErr)
	}
	opTimeUnix := opTime.Unix()

	// subject="" so the wildcard aud:"*" credential is accepted; the explicit
	// aud check below replicates the TS rule (aud=="*" || aud==opDID). Do NOT
	// loosen verifyCredentialCore's subject check directly — it is shared with
	// other callers.
	vc, err := VerifyCredentialAt(authorization, creatorPubKey, "", "", opTimeUnix)
	if err != nil {
		return err
	}

	if vc.Aud != "*" && vc.Aud != opDID {
		return fmt.Errorf("credential audience %s does not match operation signer %s", vc.Aud, opDID)
	}

	// explicit LEAF-revocation check on the write path. verifyDelegationChain
	// covers PARENTS only — without this a revoked leaf still authorizes writes.
	//
	// asOf = opTimeUnix, the operation's own createdAt and the SAME deterministic
	// basis already used for expiry above. A revocation signed after this
	// operation leaves it valid on every future verification of the chain; only a
	// revocation that predates it invalidates it. MUST stay in sync with the TS
	// twin (content-chain.ts verifyOperationAuthorization).
	if opts.isRevoked != nil {
		revoked, err := opts.isRevoked(vc.Iss, vc.CID, opTimeUnix)
		if err != nil {
			return fmt.Errorf("revocation check failed: %w", err)
		}
		if revoked {
			return fmt.Errorf("credential is revoked")
		}
	}

	// resource + action coverage — scan ALL att entries with comma-split actions
	// (matchesResource), not verifyCredentialCore's first-recognized-entry break.
	childAtt := ParseAtt(vcPayload)
	if !matchesResource(childAtt, "chain:"+contentID, "write") {
		return fmt.Errorf("credential does not cover write access to chain:%s", contentID)
	}

	// walk the delegation chain — verify it roots at the creator DID, threading
	// the revocation + isDeleted checks onto every parent hop.
	childPrf, err := ParsePrf(vcPayload)
	if err != nil {
		return fmt.Errorf("credential prf invalid: %v", err)
	}
	if err := verifyDelegationChain(authorization, vc, childAtt, childPrf, credentialResolveKey, creatorDID, opts.isRevoked, opts.isDeleted, opTimeUnix, 0); err != nil {
		return err
	}

	return nil
}

// matchesResource reports whether an att array covers a requested
// resource+action. Mirrors the relay READ path (auth.go matchesResource) and
// the TS protocol matchesResource: comma-split actions, scan ALL entries,
// chain:* wildcard. Lives in the protocol package so the write path no longer
// depends on verifyCredentialCore's first-entry convenience fields.
func matchesResource(att []AttEntry, resource, action string) bool {
	reqType, reqID, ok := ParseResource(resource)
	if !ok {
		return false
	}
	reqActions := ParseActions(action)

	for _, entry := range att {
		entryType, entryID, ok := ParseResource(entry.Resource)
		if !ok {
			continue
		}
		entryActions := ParseActions(entry.Action)

		actionsCovered := true
		for a := range reqActions {
			if !entryActions[a] {
				actionsCovered = false
				break
			}
		}
		if !actionsCovered {
			continue
		}

		// chain:* covers any chain: request
		if entryType == "chain" && entryID == "*" && reqType == "chain" {
			return true
		}
		// exact resource match
		if entryType == reqType && entryID == reqID {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Content chain verification
// -----------------------------------------------------------------------------

// VerifyContentChain verifies a content chain's structural integrity,
// signatures, and authorization. The caller provides a KeyResolver to look up
// public keys from kid values.
//
// When enforceAuthorization is true, non-creator signers must include a valid
// DFOS credential with action "write" in the operation's authorization field.
func VerifyContentChain(log []string, resolveKey KeyResolver, enforceAuthorization bool, options ...ContentVerifyOption) (*VerifiedContentResult, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("log must have at least one operation")
	}

	var opts contentVerifyOpts
	for _, o := range options {
		o(&opts)
	}

	var (
		contentID     string
		genesisCID    string
		headCID       string
		isDeleted     bool
		currentDocCID *string
		previousCID   string
		lastCreatedAt string
		creatorDID    string
		length        int
	)

	for idx, jwsToken := range log {
		header, payload, err := DecodeJWSUnsafe(jwsToken)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to decode JWS", idx)
		}

		opType := payloadString(payload, "type")
		createdAt := payloadString(payload, "createdAt")
		opDID := payloadString(payload, "did")

		// validate basics
		if v, ok := payload["version"].(int64); !ok || v != 1 {
			return nil, fmt.Errorf("log[%d]: invalid or missing version", idx)
		}
		if opType != "create" && opType != "update" && opType != "delete" {
			return nil, fmt.Errorf("log[%d]: invalid operation type", idx)
		}
		if err := validateCreatedAt(createdAt); err != nil {
			return nil, fmt.Errorf("log[%d]: %w", idx, err)
		}
		if header.Typ != "did:dfos:content-op" {
			return nil, fmt.Errorf("log[%d]: invalid typ: %s", idx, header.Typ)
		}

		// terminal state
		if isDeleted {
			return nil, fmt.Errorf("log[%d]: cannot extend a deleted chain", idx)
		}

		// type sequence
		if idx == 0 && opType != "create" {
			return nil, fmt.Errorf("log[%d]: first operation must be create", idx)
		}
		if idx > 0 && opType == "create" {
			return nil, fmt.Errorf("log[%d]: create can only be the first operation", idx)
		}

		// chain integrity for non-genesis
		if opType == "update" || opType == "delete" {
			prevCID := payloadString(payload, "previousOperationCID")
			if prevCID != previousCID {
				return nil, fmt.Errorf("log[%d]: previousOperationCID is incorrect", idx)
			}
			if lastCreatedAt == "" {
				return nil, fmt.Errorf("log[%d]: lastCreatedAt is not set", idx)
			}
			if createdAt <= lastCreatedAt {
				return nil, fmt.Errorf("log[%d]: createdAt must be after last op", idx)
			}
		}

		// verify kid DID matches payload did
		kid := header.Kid
		hashIdx := strings.Index(kid, "#")
		if hashIdx < 0 {
			return nil, fmt.Errorf("log[%d]: kid must be a DID URL", idx)
		}
		kidDid := kid[:hashIdx]
		if kidDid != opDID {
			return nil, fmt.Errorf("log[%d]: kid DID does not match operation did", idx)
		}

		// verify signature via key resolver
		publicKey, err := resolveKey(kid)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to resolve key: %w", idx, err)
		}
		if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
			return nil, fmt.Errorf("log[%d]: invalid signature", idx)
		}

		// authorization check
		if idx == 0 {
			creatorDID = opDID
		} else if opDID != creatorDID && enforceAuthorization {
			authorization := payloadString(payload, "authorization")
			if authorization == "" {
				return nil, fmt.Errorf("log[%d]: signer %s is not the chain creator — authorization credential required", idx, opDID)
			}

			if err := verifyContentAuthorization(authorization, opDID, creatorDID, contentID, createdAt, resolveKey, opts); err != nil {
				return nil, fmt.Errorf("log[%d]: authorization verification failed: %w", idx, err)
			}
		}

		// derive operation CID
		cborBytes, cidBytes, operationCID, err := DagCborCID(payload)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to derive CID: %w", idx, err)
		}
		opSize, err := operationSizeForCap(payload, cborBytes)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to size operation: %w", idx, err)
		}
		if opSize > maxOperationSize {
			return nil, fmt.Errorf("log[%d]: operation exceeds max size: %d > %d", idx, opSize, maxOperationSize)
		}
		if header.CID == "" {
			return nil, fmt.Errorf("log[%d]: missing cid in protected header", idx)
		}
		if header.CID != operationCID {
			return nil, fmt.Errorf("log[%d]: cid mismatch in protected header", idx)
		}

		// update state
		if idx == 0 {
			genesisCID = operationCID
			contentID = DeriveContentID(cidBytes)
		}
		headCID = operationCID
		previousCID = operationCID
		lastCreatedAt = createdAt
		length++

		switch opType {
		case "create":
			docCIDStr := payloadString(payload, "documentCID")
			if docCIDStr == "" {
				return nil, fmt.Errorf("log[%d]: create must have a documentCID", idx)
			}
			currentDocCID = &docCIDStr
		case "update":
			if _, hasDocCID := payload["documentCID"]; !hasDocCID {
				return nil, fmt.Errorf("log[%d]: update must include documentCID field", idx)
			}
			docCID := payloadStringPtr(payload, "documentCID")
			currentDocCID = docCID
		case "delete":
			isDeleted = true
			currentDocCID = nil
		}
	}

	return &VerifiedContentResult{
		State: ContentState{
			ContentID:          contentID,
			GenesisCID:         genesisCID,
			HeadCID:            headCID,
			IsDeleted:          isDeleted,
			CurrentDocumentCID: currentDocCID,
			Length:             length,
			CreatorDID:         creatorDID,
		},
		LastCreatedAt: lastCreatedAt,
	}, nil
}

// VerifyContentExtension verifies a single new content operation against
// already-verified chain state. O(1) — one signature verification, one
// key resolution, one state transition.
func VerifyContentExtension(currentState ContentState, lastCreatedAt, newOp string, resolveKey KeyResolver, enforceAuthorization bool, options ...ContentVerifyOption) (*VerifiedContentResult, error) {
	if currentState.IsDeleted {
		return nil, fmt.Errorf("cannot extend a deleted chain")
	}

	var opts contentVerifyOpts
	for _, o := range options {
		o(&opts)
	}

	header, payload, err := DecodeJWSUnsafe(newOp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWS")
	}

	opType := payloadString(payload, "type")
	createdAt := payloadString(payload, "createdAt")
	opDID := payloadString(payload, "did")

	if v, ok := payload["version"].(int64); !ok || v != 1 {
		return nil, fmt.Errorf("invalid or missing version")
	}
	if header.Typ != "did:dfos:content-op" {
		return nil, fmt.Errorf("invalid typ: %s", header.Typ)
	}
	if opType == "create" {
		return nil, fmt.Errorf("extension cannot be a create operation")
	}
	if opType != "update" && opType != "delete" {
		return nil, fmt.Errorf("invalid operation type")
	}
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, err
	}

	// chain integrity
	prevCID := payloadString(payload, "previousOperationCID")
	if prevCID != currentState.HeadCID {
		return nil, fmt.Errorf("previousOperationCID is incorrect")
	}
	if createdAt <= lastCreatedAt {
		return nil, fmt.Errorf("createdAt must be after last op")
	}

	// verify kid DID matches payload did
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("kid must be a DID URL")
	}
	kidDid := kid[:hashIdx]
	if kidDid != opDID {
		return nil, fmt.Errorf("kid DID does not match operation did")
	}

	// verify signature
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key: %w", err)
	}
	if _, _, err := VerifyJWS(newOp, publicKey); err != nil {
		return nil, fmt.Errorf("invalid signature")
	}

	// authorization check
	if opDID != currentState.CreatorDID && enforceAuthorization {
		authorization := payloadString(payload, "authorization")
		if authorization == "" {
			return nil, fmt.Errorf("signer %s is not the chain creator — authorization credential required", opDID)
		}

		if err := verifyContentAuthorization(authorization, opDID, currentState.CreatorDID, currentState.ContentID, createdAt, resolveKey, opts); err != nil {
			return nil, fmt.Errorf("authorization verification failed: %w", err)
		}
	}

	// derive CID
	cborBytes, _, operationCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive CID: %w", err)
	}
	opSize, err := operationSizeForCap(payload, cborBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to size operation: %w", err)
	}
	if opSize > maxOperationSize {
		return nil, fmt.Errorf("operation exceeds max size: %d > %d", opSize, maxOperationSize)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in protected header")
	}
	if header.CID != operationCID {
		return nil, fmt.Errorf("cid mismatch in protected header")
	}

	// compute new state
	newState := ContentState{
		ContentID:  currentState.ContentID,
		GenesisCID: currentState.GenesisCID,
		HeadCID:    operationCID,
		IsDeleted:  opType == "delete",
		Length:     currentState.Length + 1,
		CreatorDID: currentState.CreatorDID,
	}
	if opType == "update" {
		if _, hasDocCID := payload["documentCID"]; !hasDocCID {
			return nil, fmt.Errorf("update must include documentCID field")
		}
		newState.CurrentDocumentCID = payloadStringPtr(payload, "documentCID")
	}

	return &VerifiedContentResult{
		State:         newState,
		LastCreatedAt: createdAt,
	}, nil
}

// -----------------------------------------------------------------------------
// Artifact verification
// -----------------------------------------------------------------------------

const maxArtifactPayloadSize = 16384

// VerifyArtifact verifies an artifact JWS — signature, CID, payload schema,
// size limit.
func VerifyArtifact(jwsToken string, resolveKey KeyResolver) (*VerifiedArtifactResult, error) {
	header, payload, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode artifact JWS")
	}

	// validate payload
	if v, ok := payload["version"].(int64); !ok || v != 1 {
		return nil, fmt.Errorf("invalid artifact payload: invalid or missing version")
	}
	if payloadString(payload, "type") != "artifact" {
		return nil, fmt.Errorf("invalid artifact payload: wrong type")
	}
	artifactDID := payloadString(payload, "did")
	if artifactDID == "" {
		return nil, fmt.Errorf("invalid artifact payload: missing did")
	}
	createdAt := payloadString(payload, "createdAt")
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, fmt.Errorf("invalid artifact payload: %w", err)
	}
	contentRaw, ok := payload["content"]
	if !ok {
		return nil, fmt.Errorf("invalid artifact payload: missing content")
	}
	content, ok := contentRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid artifact payload: content is not an object")
	}
	if _, ok := content["$schema"].(string); !ok {
		return nil, fmt.Errorf("invalid artifact payload: content must have $schema")
	}

	// verify typ
	if header.Typ != "did:dfos:artifact" {
		return nil, fmt.Errorf("invalid artifact typ: %s", header.Typ)
	}

	// verify kid DID matches payload did
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("artifact kid must be a DID URL")
	}
	kidDid := kid[:hashIdx]
	if kidDid != artifactDID {
		return nil, fmt.Errorf("artifact kid DID does not match payload did")
	}

	// verify signature
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve artifact key: %w", err)
	}
	if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
		return nil, fmt.Errorf("invalid artifact signature")
	}

	// verify CID — use raw decoded payload to preserve all content keys
	cborBytes, _, artifactCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive artifact CID: %w", err)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in artifact header")
	}
	if header.CID != artifactCID {
		return nil, fmt.Errorf("artifact cid mismatch")
	}

	// enforce size limit
	if len(cborBytes) > maxArtifactPayloadSize {
		return nil, fmt.Errorf("artifact payload exceeds max size: %d > %d", len(cborBytes), maxArtifactPayloadSize)
	}

	return &VerifiedArtifactResult{
		ArtifactCID: artifactCID,
		DID:         artifactDID,
		Content:     content,
		CreatedAt:   createdAt,
	}, nil
}

// -----------------------------------------------------------------------------
// Countersignature verification
// -----------------------------------------------------------------------------

// VerifyCountersignature verifies a countersignature JWS — stateless
// verification of signature, CID, and payload schema. Does NOT check whether
// the target exists or whether the witness differs from the target author —
// those are relay-level semantic checks.
func VerifyCountersignature(jwsToken string, resolveKey KeyResolver) (*VerifiedCountersignResult, error) {
	header, payload, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode countersignature JWS")
	}

	// verify typ
	if header.Typ != "did:dfos:countersign" {
		return nil, fmt.Errorf("invalid countersignature typ: %s", header.Typ)
	}

	// validate payload
	if v, ok := payload["version"].(int64); !ok || v != 1 {
		return nil, fmt.Errorf("invalid countersignature payload: invalid or missing version")
	}
	if payloadString(payload, "type") != "countersign" {
		return nil, fmt.Errorf("invalid countersignature payload: wrong type")
	}
	witnessDID := payloadString(payload, "did")
	if witnessDID == "" {
		return nil, fmt.Errorf("invalid countersignature payload: missing did")
	}
	targetCID := payloadString(payload, "targetCID")
	if targetCID == "" {
		return nil, fmt.Errorf("invalid countersignature payload: missing targetCID")
	}
	// optional open-namespace relation tag — present → must be a 1..N string
	relation := ""
	if rv, ok := payload["relation"]; ok {
		rs, ok := rv.(string)
		if !ok || len(rs) < 1 || len(rs) > maxRelation {
			return nil, fmt.Errorf("invalid countersignature payload: relation must be a non-empty string (1..%d chars)", maxRelation)
		}
		relation = rs
	}

	// verify kid DID matches payload did
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("countersignature kid must be a DID URL")
	}
	kidDid := kid[:hashIdx]
	if kidDid != witnessDID {
		return nil, fmt.Errorf("countersignature kid DID does not match payload did")
	}

	// verify signature
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve countersignature key: %w", err)
	}
	if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
		return nil, fmt.Errorf("invalid countersignature signature")
	}

	// verify CID — use raw decoded payload
	_, _, countersignCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive countersignature CID: %w", err)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in countersignature header")
	}
	if header.CID != countersignCID {
		return nil, fmt.Errorf("countersignature cid mismatch")
	}

	return &VerifiedCountersignResult{
		CountersignCID: countersignCID,
		WitnessDID:     witnessDID,
		TargetCID:      targetCID,
		Relation:       relation,
	}, nil
}
