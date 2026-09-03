package relay

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ---------------------------------------------------------------------------
// temporal guard
// ---------------------------------------------------------------------------

// ErrDependencyMissing marks a verification failure as a MISSING DEPENDENCY:
// the identity chain or key the operation references is not in this store yet,
// so the operation may verify once sync or gossip delivers it. The sequencer
// keeps such an op pending; every other rejection is permanent and DELETES the
// raw op (MarkOpRejected), which is unrecoverable.
//
// CLASSIFICATION IS A TYPED FACT, NEVER A SPELLING. Only a resolver knows that
// a lookup missed — "this identity is not here" and "this kid is malformed" are
// the same error type at that seam — so the resolvers below wrap this sentinel
// and every classifier reads it with errors.Is.
//
// The previous mechanism was a list of substrings matched against the error
// TEXT, and that text quotes submitter-controlled input verbatim: a kid reaches
// dfos.ValidateDID's "malformed did:dfos identifier: %q", a credential's
// audience reaches "credential audience %s does not match operation signer %s",
// a typ reaches "invalid typ: %s". Spelling any of the listed phrases inside
// one of those fields made a PERMANENT rejection classify as retryable, so the
// relay kept the op and re-verified it on every sequencer cycle — and varying
// one byte to mint a fresh CID grew the raw-op store without bound. A submitter
// chose the relay's control flow by choosing a string.
//
// The two twins MUST classify identically, and now do so structurally rather
// than by keeping two string lists in sync: the TS twin's marker is
// isDependencyMissing/markDependencyMissing in @metalabel/dfos-protocol, wrapped
// at the same resolver miss sites (ingest.ts).
var ErrDependencyMissing = errors.New("dependency missing")

// dependencyMissingError carries ErrDependencyMissing WITHOUT altering the
// human-readable message.
//
// The message has to stay byte-identical to the TS twin's: the conformance
// parity suite compares the two relays' /proof/v1/operations response bodies
// verbatim, and the TS marker is a property hung on the error object, which
// touches no text at all. A `fmt.Errorf("%w: ...", ErrDependencyMissing, ...)`
// would prefix every miss with "dependency missing: " on the Go side only and
// split the twins on the exact surface the classification was meant to unify.
type dependencyMissingError struct{ msg string }

func (e dependencyMissingError) Error() string { return e.msg }

// Unwrap is what makes errors.Is find the sentinel, including through the %w
// wraps the protocol library applies on the way back up.
func (e dependencyMissingError) Unwrap() error { return ErrDependencyMissing }

// dependencyMissingf builds a miss with a formatted message.
func dependencyMissingf(format string, a ...any) error {
	return dependencyMissingError{msg: fmt.Sprintf(format, a...)}
}

const noncurrentSigningKeyError = "signing key is not in the identity's current state"
const identityConflictingExtensionError = "identity chains are linear: conflicting extension refused"

type admissionMode int

const (
	currentAdmission admissionMode = iota
	historicalAdmission
)

// maxFutureTimestamp is the maximum allowed clock skew for operation timestamps (24 hours).
const maxFutureTimestamp = 24 * time.Hour

// isFutureTimestamp returns true if createdAt is more than 24 hours in the future.
func isFutureTimestamp(createdAt string) bool {
	t, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return false // invalid dates rejected by protocol verification
	}
	return t.After(time.Now().Add(maxFutureTimestamp))
}

// ---------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------

type classifiedOp struct {
	jwsToken      string
	kind          string // identity-op, content-op, countersign, artifact, unknown
	referencedDID string // DID referenced in the operation
	signerDID     string // for content ops: payload.did
	priority      int    // sort bucket: identity=0, artifact=1, content=2, countersign=3
	operationCID  string // from JWS header
	previousCID   string // previousOperationCID if present
	originalIndex int    // submission order
}

func classify(jwsToken string) classifiedOp {
	unknown := classifiedOp{
		jwsToken: jwsToken,
		kind:     "unknown",
		priority: 99,
	}

	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return unknown
	}

	kid := header.Kid
	if kid == "" {
		return unknown
	}

	kidDID := ""
	if idx := strings.Index(kid, "#"); idx >= 0 {
		kidDID = kid[:idx]
	}

	operationCID := header.CID
	previousCID := ""
	if s, ok := payload["previousOperationCID"].(string); ok {
		previousCID = s
	}
	base := classifiedOp{
		jwsToken:     jwsToken,
		operationCID: operationCID,
		previousCID:  previousCID,
	}

	switch header.Typ {
	case "did:dfos:identity-op":
		base.kind = "identity-op"
		base.referencedDID = kidDID
		base.priority = 0
		return base

	case "did:dfos:content-op":
		base.kind = "content-op"
		base.priority = 2
		if did, ok := payload["did"].(string); ok {
			base.signerDID = did
		}
		return base

	case "did:dfos:countersign":
		base.kind = "countersign"
		base.priority = 3
		base.previousCID = "" // countersigns have no chaining
		if did, ok := payload["did"].(string); ok {
			base.referencedDID = did
		}
		return base

	case "did:dfos:artifact":
		base.kind = "artifact"
		base.priority = 1     // resolves against identity keys, like revocations/credentials
		base.previousCID = "" // artifacts have no chaining
		if did, ok := payload["did"].(string); ok {
			base.referencedDID = did
		}
		return base

	case "did:dfos:revocation":
		base.kind = "revocation"
		base.priority = 1 // needs identity keys to verify
		base.previousCID = ""
		if did, ok := payload["did"].(string); ok {
			base.referencedDID = did
		}
		return base

	case "did:dfos:credential":
		base.kind = "credential"
		base.priority = 1
		base.previousCID = ""
		// only ingest public credentials (aud: "*"), silently ignore private ones
		if aud, ok := payload["aud"].(string); ok && aud != "*" {
			return unknown
		}
		base.referencedDID = kidDID
		return base
	}

	return unknown
}

// ---------------------------------------------------------------------------
// key resolution
// ---------------------------------------------------------------------------

// THE THREE KEY STATES, AND WHICH SURFACE TAKES WHICH.
//
// dfos.IdentityState now carries three readings of an identity's keys, and every
// surface in this package must pick one deliberately:
//
//   - EFFECTIVE (State.AuthKeys / AssertKeys / ControllerKeys) — "what is true
//     NOW". The memberships a possession proof admitted, at the head. Live auth,
//     current-state admission, and the DID document's verification methods.
//   - HAS-EVER-PROVED (State.ProvedKeys) — "what was EVER true". The monotonic
//     union of every effective state the chain has held: a key proved in and
//     later rotated out stays forever, a key only ever declared never enters.
//     Historical key resolution and the `key=` / `signerKey=` reverse indexes.
//   - DECLARED (State.Declared) — "what the chain SAYS", void memberships
//     included. Exactly one surface needs it, SIGNER ADMISSION, and that surface
//     lives in the protocol library's chain walk, not here. Nothing in this
//     package reads it.

// effectiveKeyState flattens the head EFFECTIVE arrays into a key state, so the
// current-state and has-ever-proved lookups can share one search.
func effectiveKeyState(state dfos.IdentityState) dfos.DeclaredKeyState {
	return dfos.DeclaredKeyState{
		AuthKeys:       state.AuthKeys,
		AssertKeys:     state.AssertKeys,
		ControllerKeys: state.ControllerKeys,
	}
}

// provedKeyState is an identity's HAS-EVER-PROVED key state.
//
// An absent has-ever-proved history reads as "what is effective now was proved"
// — the same reading dfos.VerifyIdentityExtension applies, exactly true for any
// chain that never voided a membership, and the only reading available for a
// state persisted before the member existed. A relay holding such rows resolves
// and indexes a narrower set than the chain walk would (rotated-out keys are
// lost until the row is rewritten), which is the safe direction: it under-claims
// rather than admitting a key nothing proved.
func provedKeyState(state dfos.IdentityState) dfos.DeclaredKeyState {
	if state.ProvedKeys.IsZero() {
		return effectiveKeyState(state)
	}
	return state.ProvedKeys
}

// keysInKeyState flattens a key state's three roles into one list. Duplicates
// across roles are kept: every caller here is either searching by key ID or
// writing into an idempotent index.
func keysInKeyState(state dfos.DeclaredKeyState) []dfos.MultikeyPublicKey {
	keys := make([]dfos.MultikeyPublicKey, 0, len(state.AuthKeys)+len(state.AssertKeys)+len(state.ControllerKeys))
	keys = append(keys, state.AuthKeys...)
	keys = append(keys, state.AssertKeys...)
	keys = append(keys, state.ControllerKeys...)
	return keys
}

// findKeyInKeyState searches all three roles of a key state for a key ID.
func findKeyInKeyState(state dfos.DeclaredKeyState, keyID string) (dfos.MultikeyPublicKey, bool) {
	for _, k := range keysInKeyState(state) {
		if k.ID == keyID {
			return k, true
		}
	}
	return dfos.MultikeyPublicKey{}, false
}

// CreateKeyResolver returns a KeyResolver that resolves every key an identity
// chain has EVER PROVED — rotated-out keys included. Used for protocol
// verification during ingestion, where a long-lived artifact signed by a key
// that has since rotated away must still verify.
//
// HAS-EVER-PROVED, NOT HAS-EVER-DECLARED. A declared-but-unproved membership is
// VOID: no possession proof ever admitted it, so nothing it signed was ever
// authorized, and resolving it would let a chain that merely LISTS a stranger's
// key speak with it. The chain walk already folds this union onto
// State.ProvedKeys, so there is no log re-scan here — a hand-rolled scan would
// have to restate the possession rule and would quietly disagree with the walk
// that produced the effective arrays beside it.
//
// No fast/slow split remains either: has-ever-proved is a superset of effective,
// so one search over ProvedKeys answers both.
//
// WHICH FAILURES ARE DEPENDENCY MISSES. Exactly two: the identity chain is not
// in this store, and the identity is here but has never proved that key id.
// Both may be answered differently once sync delivers more of the graph, so
// both wrap ErrDependencyMissing. The malformed-kid and malformed-DID failures
// do NOT: no amount of syncing makes a kid that is not a DID URL into one, so
// they stay permanent and the op is durably rejected.
func CreateKeyResolver(store Store) dfos.KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		hashIdx := strings.Index(kid, "#")
		if hashIdx < 0 {
			return nil, fmt.Errorf("kid must be a DID URL: %s", kid)
		}
		did := kid[:hashIdx]
		keyID := kid[hashIdx+1:]

		if err := dfos.ValidateDID(did); err != nil {
			return nil, err
		}

		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return nil, dependencyMissingf("unknown identity: %s", did)
		}

		if k, ok := findKeyInKeyState(provedKeyState(identity.State), keyID); ok {
			return dfos.DecodeMultikey(k.PublicKeyMultibase)
		}

		return nil, dependencyMissingf("unknown key %s on identity %s", keyID, did)
	}
}

// CreateCurrentKeyResolver returns a KeyResolver that only resolves
// current-state keys. Used for live auth and first admission — rotated-out keys
// are rejected but remain resolvable for committed history.
//
// EFFECTIVE state, which is what the head arrays now mean: a declared-but-void
// key is absent from them, so it never authenticates. No change was needed here
// beyond saying so — the possession fold made the arrays correct for this
// surface for free.
//
// Only the unknown-identity failure is a dependency miss here. A DELETED
// identity and a key that is merely no longer current are both verdicts this
// store is already entitled to reach, and re-asking later cannot change them.
func CreateCurrentKeyResolver(store Store) dfos.KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		hashIdx := strings.Index(kid, "#")
		if hashIdx < 0 {
			return nil, fmt.Errorf("kid must be a DID URL: %s", kid)
		}
		did := kid[:hashIdx]
		keyID := kid[hashIdx+1:]

		if err := dfos.ValidateDID(did); err != nil {
			return nil, err
		}

		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return nil, dependencyMissingf("unknown identity: %s", did)
		}
		if identity.State.IsDeleted {
			return nil, fmt.Errorf("signing identity is deleted")
		}

		if k, ok := findKeyInKeyState(effectiveKeyState(identity.State), keyID); ok {
			return dfos.DecodeMultikey(k.PublicKeyMultibase)
		}

		return nil, fmt.Errorf("%s", noncurrentSigningKeyError)
	}
}

func admissionKeyResolver(store Store, mode admissionMode) dfos.KeyResolver {
	if mode == historicalAdmission {
		return CreateKeyResolver(store)
	}
	return CreateCurrentKeyResolver(store)
}

// ---------------------------------------------------------------------------
// individual verifiers
// ---------------------------------------------------------------------------

func ingestIdentityOp(jwsToken string, store Store, logEnabled bool) IngestionResult {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return IngestionResult{Status: "rejected", Error: "failed to decode JWS"}
	}

	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: "failed to compute CID"}
	}

	// temporal guard: reject operations with timestamps too far in the future
	if createdAt, ok := payload["createdAt"].(string); ok && isFutureTimestamp(createdAt) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "createdAt is too far in the future"}
	}

	// idempotent: already stored
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "operation already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "identity-op", ChainID: existing.ChainID}
	}

	opType, _ := payload["type"].(string)
	isGenesis := opType == "create"

	if isGenesis {
		result, err := dfos.VerifyIdentityChain([]string{jwsToken})
		if err != nil {
			return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
		}
		createdAt, _ := payload["createdAt"].(string)
		chain := StoredIdentityChain{
			DID:           result.State.DID,
			Log:           []string{jwsToken},
			HeadCID:       cid,
			LastCreatedAt: createdAt,
			State:         result.State,
		}
		if perr := persistError(cid, store.PutIdentityChain(chain)); perr != nil {
			return *perr
		}
		if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: result.State.DID})); perr != nil {
			return *perr
		}
		if logEnabled {
			if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "identity-op", ChainID: result.State.DID})); perr != nil {
				return *perr
			}
		}
		return IngestionResult{CID: cid, Status: "new", Kind: "identity-op", ChainID: result.State.DID}
	}

	// extension — find existing chain via kid DID
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return IngestionResult{CID: cid, Status: "rejected", Error: "non-genesis kid must be a DID URL"}
	}
	did := kid[:hashIdx]

	chain, _ := store.GetIdentityChain(did)
	if chain == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown identity: %s", did), DependencyMissing: true}
	}

	// extract previousOperationCID from payload
	previousCID, _ := payload["previousOperationCID"].(string)

	if previousCID == chain.HeadCID {
		// linear extension (fast path)
		extResult, err := dfos.VerifyIdentityExtension(chain.State, chain.HeadCID, chain.LastCreatedAt, jwsToken)
		if err != nil {
			return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
		}
		updated := StoredIdentityChain{
			DID:           chain.DID,
			Log:           append(append([]string{}, chain.Log...), jwsToken),
			HeadCID:       extResult.HeadCID,
			LastCreatedAt: extResult.LastCreatedAt,
			State:         extResult.State,
		}
		if perr := persistError(cid, store.PutIdentityChain(updated)); perr != nil {
			return *perr
		}
		if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: did})); perr != nil {
			return *perr
		}
		if logEnabled {
			if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "identity-op", ChainID: did})); perr != nil {
				return *perr
			}
		}
		return IngestionResult{CID: cid, Status: "new", Kind: "identity-op", ChainID: did}
	}

	// Unknown parents are retryable dependencies. A known non-head parent
	// already has a committed child and is a permanent conflict.
	if previousCID == "" || !chainLogContainsCID(chain.Log, previousCID) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in identity chain", DependencyMissing: true}
	}
	return IngestionResult{CID: cid, Status: "rejected", Error: identityConflictingExtensionError}
}

func ingestContentOp(jwsToken string, store Store, logEnabled bool, mode admissionMode) IngestionResult {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return IngestionResult{Status: "rejected", Error: "failed to decode JWS"}
	}

	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: "failed to compute CID"}
	}

	// temporal guard: reject operations with timestamps too far in the future
	if createdAt, ok := payload["createdAt"].(string); ok && isFutureTimestamp(createdAt) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "createdAt is too far in the future"}
	}

	// idempotent
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "operation already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "content-op", ChainID: existing.ChainID}
	}

	// reject content ops from deleted identities. A failed lookup is NOT
	// "not deleted" — the gate fails closed and the op stays pending.
	signerDID, _ := payload["did"].(string)
	if signerDID != "" {
		signerIdentity, err := store.GetIdentityChain(signerDID)
		if serr := storeReadError(cid, err); serr != nil {
			return *serr
		}
		if signerIdentity != nil && signerIdentity.State.IsDeleted {
			return IngestionResult{CID: cid, Status: "rejected", Error: "signer identity is deleted"}
		}
	}

	resolveKey := admissionKeyResolver(store, mode)
	resolveCredentialKey := CreateKeyResolver(store)
	// WRITE-path hardening callbacks (mirror the relay READ path / the TS twin):
	// revoked credentials and deleted issuers/parents no longer authorize writes.
	//
	// ACCEPTANCE IS A FRESHNESS DECISION. The protocol verifier offers an as-of
	// basis (the op's own createdAt) because verifying committed history is a
	// validity decision — but admitting a NEW operation is not that question. This
	// closure therefore DELIBERATELY IGNORES asOfUnix (passing 0 = timeless) and
	// answers from the relay's current knowledge: a relay must never accept a new
	// op authorized by a credential it already knows to be revoked, no matter how
	// the op is dated. (Answering "revoked as of now" instead would be subtly
	// weaker — it would admit an op under a revocation whose own createdAt is in
	// the future. Current knowledge is strictly stronger and byte-identical to the
	// pre-as-of behavior, so ingest verdicts do not change.) Mirrors the TS twin
	// (ingest.ts).
	isRevoked := dfos.WithRevocationChecker(func(issuerDID, credentialCID string, _ int64) (bool, error) {
		return store.IsCredentialRevoked(issuerDID, credentialCID, 0)
	})
	isDeleted := dfos.WithIdentityDeletedChecker(func(did string) (bool, error) {
		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return false, err
		}
		return identity != nil && identity.State.IsDeleted, nil
	})
	opType, _ := payload["type"].(string)
	isGenesis := opType == "create"

	if isGenesis {
		result, err := dfos.VerifyContentChain([]string{jwsToken}, resolveKey, true, isRevoked, isDeleted, dfos.WithCredentialKeyResolver(resolveCredentialKey))
		if err != nil {
			return IngestionResult{CID: cid, Status: "rejected", Error: err.Error(), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
		}
		createdAt, _ := payload["createdAt"].(string)
		chain := StoredContentChain{
			ContentID:     result.State.ContentID,
			GenesisCID:    result.State.GenesisCID,
			Log:           []string{jwsToken},
			LastCreatedAt: createdAt,
			State:         result.State,
		}
		if perr := persistError(cid, store.PutContentChain(chain)); perr != nil {
			return *perr
		}
		if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: result.State.ContentID})); perr != nil {
			return *perr
		}
		if logEnabled {
			if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "content-op", ChainID: result.State.ContentID})); perr != nil {
				return *perr
			}
		}
		return IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: result.State.ContentID}
	}

	// extension — find chain via previousOperationCID
	previousCID, ok := payload["previousOperationCID"].(string)
	if !ok || previousCID == "" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "missing previousOperationCID"}
	}

	prevOp, _ := store.GetOperation(previousCID)
	if prevOp == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown previous operation: %s", previousCID), DependencyMissing: true}
	}
	if prevOp.ChainType != "content" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "previousOperationCID is not a content operation"}
	}

	chain, _ := store.GetContentChain(prevOp.ChainID)
	if chain == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("content chain not found: %s", prevOp.ChainID), DependencyMissing: true}
	}

	// reject if creator's identity is deleted (fails closed on a store error)
	creatorIdentity, cerr := store.GetIdentityChain(chain.State.CreatorDID)
	if serr := storeReadError(cid, cerr); serr != nil {
		return *serr
	}
	if creatorIdentity != nil && creatorIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "content creator identity is deleted"}
	}

	if chain.State.HeadCID == previousCID {
		// linear extension (fast path)
		extResult, err := dfos.VerifyContentExtension(chain.State, chain.LastCreatedAt, jwsToken, resolveKey, true, isRevoked, isDeleted, dfos.WithCredentialKeyResolver(resolveCredentialKey))
		if err != nil {
			return IngestionResult{CID: cid, Status: "rejected", Error: err.Error(), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
		}
		updated := StoredContentChain{
			ContentID:     chain.ContentID,
			GenesisCID:    chain.GenesisCID,
			Log:           append(append([]string{}, chain.Log...), jwsToken),
			LastCreatedAt: extResult.LastCreatedAt,
			State:         extResult.State,
		}
		if perr := persistError(cid, store.PutContentChain(updated)); perr != nil {
			return *perr
		}
		if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: chain.ContentID})); perr != nil {
			return *perr
		}
		if logEnabled {
			if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "content-op", ChainID: chain.ContentID})); perr != nil {
				return *perr
			}
		}
		return IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: chain.ContentID}
	}

	// fork path — check if previousCID exists in chain ops
	if !chainLogContainsCID(chain.Log, previousCID) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in content chain", DependencyMissing: true}
	}

	forkState, err := store.GetContentStateAtCID(chain.ContentID, previousCID)
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: ForkPointStateErrorPrefix + fmt.Sprintf("%v", err), DependencyMissing: true}
	}
	if forkState == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in content chain", DependencyMissing: true}
	}

	extResult, err := dfos.VerifyContentExtension(forkState.State, forkState.LastCreatedAt, jwsToken, resolveKey, true, isRevoked, isDeleted, dfos.WithCredentialKeyResolver(resolveCredentialKey))
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: err.Error(), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
	}

	updatedLog := append(append([]string{}, chain.Log...), jwsToken)
	head := selectDeterministicHead(updatedLog)

	headState := chain.State
	headLastCreatedAt := chain.LastCreatedAt

	if head.cid == cid {
		headState = extResult.State
		headLastCreatedAt = extResult.LastCreatedAt
	}

	updated := StoredContentChain{
		ContentID:     chain.ContentID,
		GenesisCID:    chain.GenesisCID,
		Log:           updatedLog,
		LastCreatedAt: headLastCreatedAt,
		State:         headState,
	}
	if perr := persistError(cid, store.PutContentChain(updated)); perr != nil {
		return *perr
	}
	if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: chain.ContentID})); perr != nil {
		return *perr
	}
	if logEnabled {
		if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "content-op", ChainID: chain.ContentID})); perr != nil {
			return *perr
		}
	}
	return IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: chain.ContentID}
}

func ingestCountersign(jwsToken string, store Store, logEnabled bool, mode admissionMode) IngestionResult {
	resolveKey := admissionKeyResolver(store, mode)

	result, err := dfos.VerifyCountersignature(jwsToken, resolveKey)
	if err != nil {
		return IngestionResult{CID: computeOpCID(jwsToken), Status: "rejected", Error: err.Error(), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
	}

	cid := result.CountersignCID
	witnessDID := result.WitnessDID
	targetCID := result.TargetCID

	// idempotent
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "countersign already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "countersign", ChainID: targetCID}
	}

	// target must exist (may arrive later via sync/gossip — retryable)
	targetOp, _ := store.GetOperation(targetCID)
	if targetOp == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown target operation: %s", targetCID), DependencyMissing: true}
	}

	// witness must differ from target author
	var targetAuthorDID string
	if targetOp.ChainType == "identity" {
		targetAuthorDID = targetOp.ChainID
	} else {
		_, targetPayload, err := dfos.DecodeJWSUnsafe(targetOp.JWSToken)
		if err == nil && targetPayload != nil {
			if d, ok := targetPayload["did"].(string); ok {
				targetAuthorDID = d
			}
		}
	}

	if targetAuthorDID != "" && witnessDID == targetAuthorDID {
		return IngestionResult{CID: cid, Status: "rejected", Error: "witness DID must differ from target author DID"}
	}

	// reject countersigns from deleted witnesses (fails closed on a store error)
	witnessIdentity, werr := store.GetIdentityChain(witnessDID)
	if serr := storeReadError(cid, werr); serr != nil {
		return *serr
	}
	if witnessIdentity != nil && witnessIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "witness identity is deleted"}
	}

	// dedup: one countersign per witness per target
	existingCountersigns, _ := store.GetCountersignatures(targetCID)
	for _, csJws := range existingCountersigns {
		_, csPayload, err := dfos.DecodeJWSUnsafe(csJws)
		if err != nil {
			continue
		}
		if d, ok := csPayload["did"].(string); ok && d == witnessDID {
			return IngestionResult{CID: cid, Status: "duplicate", Kind: "countersign", ChainID: targetCID}
		}
	}

	if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "countersign", ChainID: targetCID})); perr != nil {
		return *perr
	}
	if perr := persistError(cid, store.AddCountersignature(targetCID, jwsToken)); perr != nil {
		return *perr
	}
	if logEnabled {
		if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "countersign", ChainID: targetCID})); perr != nil {
			return *perr
		}
	}
	return IngestionResult{CID: cid, Status: "new", Kind: "countersign", ChainID: targetCID}
}

func ingestArtifact(jwsToken string, store Store, logEnabled bool, mode admissionMode) IngestionResult {
	resolveKey := admissionKeyResolver(store, mode)

	result, err := dfos.VerifyArtifact(jwsToken, resolveKey)
	if err != nil {
		return IngestionResult{CID: computeOpCID(jwsToken), Status: "rejected", Error: err.Error(), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
	}

	cid := result.ArtifactCID
	did := result.DID

	// idempotent
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "artifact already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "artifact", ChainID: did}
	}

	// reject artifacts from deleted identities (fails closed on a store error)
	identity, ierr := store.GetIdentityChain(did)
	if serr := storeReadError(cid, ierr); serr != nil {
		return *serr
	}
	if identity != nil && identity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "identity is deleted"}
	}

	if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "artifact", ChainID: did})); perr != nil {
		return *perr
	}
	if logEnabled {
		if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "artifact", ChainID: did})); perr != nil {
			return *perr
		}
	}
	return IngestionResult{CID: cid, Status: "new", Kind: "artifact", ChainID: did}
}

func ingestRevocation(jwsToken string, store Store, logEnabled bool) IngestionResult {
	resolveKey := CreateKeyResolver(store)

	result, err := dfos.VerifyRevocation(jwsToken, resolveKey)
	if err != nil {
		return IngestionResult{CID: computeOpCID(jwsToken), Status: "rejected", Error: err.Error(), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
	}

	cid := result.RevocationCID
	did := result.DID

	// idempotent
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "operation already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "revocation", ChainID: did}
	}

	// reject if identity is deleted (fails closed on a store error)
	identity, ierr := store.GetIdentityChain(did)
	if serr := storeReadError(cid, ierr); serr != nil {
		return *serr
	}
	if identity != nil && identity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "identity is deleted"}
	}

	revokedCredential, err := store.GetPublicCredentialByCID(result.CredentialCID)
	if perr := persistError(cid, err); perr != nil {
		return *perr
	}
	var revokedGrant *RevokedGrant
	if revokedCredential != nil {
		wildcard, contentIDs := contentIdsFromCredential(*revokedCredential)
		revokedGrant = &RevokedGrant{Wildcard: wildcard, ContentIDs: contentIDs}
	}

	// store revocation — carrying the VERIFIED createdAt, which is the as-of
	// boundary every later validity check compares against
	if perr := persistError(cid, store.AddRevocation(StoredRevocation{
		CID:           cid,
		IssuerDID:     did,
		CredentialCID: result.CredentialCID,
		JWSToken:      jwsToken,
		CreatedAt:     result.CreatedAt,
	})); perr != nil {
		return *perr
	}

	// revoke any standing public credential
	if perr := persistError(cid, store.RemovePublicCredential(result.CredentialCID)); perr != nil {
		return *perr
	}

	if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "revocation", ChainID: did})); perr != nil {
		return *perr
	}
	if logEnabled {
		if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "revocation", ChainID: did})); perr != nil {
			return *perr
		}
	}
	return IngestionResult{CID: cid, Status: "new", Kind: "revocation", ChainID: did, RevokedGrant: revokedGrant}
}

func ingestPublicCredential(jwsToken string, store Store, logEnabled bool) IngestionResult {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return IngestionResult{Status: "rejected", Error: "failed to decode JWS"}
	}

	// header.CID is the JWS-header-claimed CID. It keys the OPERATION store /
	// idempotency lookups below (GetOperation/PutOperation) and is surfaced to API
	// callers as IngestionResult.CID — but it does NOT key the raw op: raw_ops is
	// keyed by the recomputed storage CID (computeOpCID(token) = DagCborCID(payload)),
	// independent of header.CID. The drain loops therefore key MarkOp{Rejected,
	// Sequenced} on that storage CID, and gate on it (NOT on this res.CID), so a
	// rejection carrying an empty header.CID still drains its stored raw row rather
	// than stranding it 'pending'. (Pre-#117 this comment claimed header.CID keyed
	// the raw op — it never did in the Go relay; that mismatch caused the wedge.)
	cid := header.CID

	// verify it's a credential
	if header.Typ != "did:dfos:credential" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "invalid typ for credential"}
	}

	// must be public (aud: "*")
	aud, _ := payload["aud"].(string)
	if aud != "*" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "only public credentials (aud: *) are ingested"}
	}

	// bound prf to a single parent (spec MUST-rejects prf>1; defense-in-depth so
	// standalone ingest matches construction/decode — TS bounds this in the zod
	// schema). Count the RAW array length here for a direct, decode-independent
	// bound; ParsePrf (which hard-rejects empty/non-string elements) runs later in
	// the delegation walk.
	if prfRaw, ok := payload["prf"].([]any); ok && len(prfRaw) > 1 {
		return IngestionResult{CID: cid, Status: "rejected", Error: "multi-parent credentials are not supported (prf must have at most one entry)"}
	}

	// parse issuer from kid
	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return IngestionResult{CID: cid, Status: "rejected", Error: "kid must be a DID URL"}
	}
	kidDID := kid[:strings.Index(kid, "#")]

	if cid == "" {
		return IngestionResult{Status: "rejected", Error: "missing cid in credential header"}
	}

	// idempotent
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "operation already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "credential", ChainID: kidDID}
	}

	// reject credentials from a deleted issuer (matches TS verifyDFOSCredential,
	// which resolves the issuer identity and rejects when isDeleted). Fails
	// closed on a store error.
	issuerIdentity, ierr := store.GetIdentityChain(kidDID)
	if serr := storeReadError(cid, ierr); serr != nil {
		return *serr
	}
	if issuerIdentity != nil && issuerIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "issuer identity is deleted"}
	}

	// check if already revoked — timeless (asOf 0): admitting a standing credential
	// is an acceptance decision, so it asks what the relay knows right now. A
	// revocation lookup that FAILS is not "not revoked": the gate fails closed.
	revoked, rerr := store.IsCredentialRevoked(kidDID, cid, 0)
	if serr := storeReadError(cid, rerr); serr != nil {
		return *serr
	}
	if revoked {
		return IngestionResult{CID: cid, Status: "rejected", Error: "credential has been revoked"}
	}

	// resolve key and verify credential. An unresolved key means the issuer
	// identity has not synced yet — retryable.
	resolveKey := CreateKeyResolver(store)
	publicKey, err := resolveKey(kid)
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("failed to resolve key: %v", err), DependencyMissing: errors.Is(err, ErrDependencyMissing)}
	}

	credential, err := dfos.VerifyCredential(jwsToken, publicKey, "", "")
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
	}

	// build att pairs
	attRaw, _ := payload["att"].([]any)
	var att []AttenuationPair
	for _, a := range attRaw {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		resource, _ := am["resource"].(string)
		action, _ := am["action"].(string)
		att = append(att, AttenuationPair{Resource: resource, Action: action})
	}
	ingestedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	if perr := persistError(cid, store.AddPublicCredential(StoredPublicCredential{
		CID:        cid,
		IssuerDID:  credential.Iss,
		Att:        att,
		Exp:        credential.Exp,
		JWSToken:   jwsToken,
		CreatedAt:  credentialCreatedAt(credential.Iat),
		IngestedAt: ingestedAt,
	})); perr != nil {
		return *perr
	}

	if perr := persistError(cid, store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "credential", ChainID: kidDID, IngestedAt: ingestedAt})); perr != nil {
		return *perr
	}
	if logEnabled {
		if perr := persistError(cid, appendOperationToLog(store, LogEntry{CID: cid, JWSToken: jwsToken, Kind: "credential", ChainID: kidDID})); perr != nil {
			return *perr
		}
	}
	return IngestionResult{CID: cid, Status: "new", Kind: "credential", ChainID: kidDID}
}

// ---------------------------------------------------------------------------
// fork helpers
// ---------------------------------------------------------------------------

// chainLogContainsCID checks if a chain log contains an operation with the given CID.
func chainLogContainsCID(log []string, targetCID string) bool {
	for _, jws := range log {
		header, _, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		if header.CID == targetCID {
			return true
		}
	}
	return false
}

type tipInfo struct {
	cid       string
	createdAt string
}

// selectDeterministicHead finds all tips (ops with no children) and selects the
// deterministic head: highest createdAt, lexicographic highest CID tiebreak.
func selectDeterministicHead(log []string) tipInfo {
	type opInfo struct {
		cid         string
		previousCID string
		createdAt   string
	}
	var ops []opInfo
	hasChild := make(map[string]bool)

	for _, jws := range log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		opCID := header.CID
		prevCID, _ := payload["previousOperationCID"].(string)
		createdAt, _ := payload["createdAt"].(string)
		ops = append(ops, opInfo{cid: opCID, previousCID: prevCID, createdAt: createdAt})
		if prevCID != "" {
			hasChild[prevCID] = true
		}
	}

	var tips []tipInfo
	for _, op := range ops {
		if !hasChild[op.cid] {
			tips = append(tips, tipInfo{cid: op.cid, createdAt: op.createdAt})
		}
	}

	if len(tips) == 0 {
		return tipInfo{}
	}

	// sort: highest createdAt first, then lexicographic highest CID
	sort.Slice(tips, func(i, j int) bool {
		if tips[i].createdAt != tips[j].createdAt {
			return tips[i].createdAt > tips[j].createdAt
		}
		return tips[i].cid > tips[j].cid
	})

	return tips[0]
}

// ---------------------------------------------------------------------------
// topological sort
// ---------------------------------------------------------------------------

func dependencySort(ops []classifiedOp) []classifiedOp {
	buckets := make(map[int][]classifiedOp)
	for _, op := range ops {
		buckets[op.priority] = append(buckets[op.priority], op)
	}

	priorities := make([]int, 0, len(buckets))
	for p := range buckets {
		priorities = append(priorities, p)
	}
	sort.Ints(priorities)

	var result []classifiedOp
	for _, p := range priorities {
		bucket := buckets[p]
		if (p == 0 || p == 2) && len(bucket) > 1 {
			result = append(result, topologicalSortBucket(bucket)...)
		} else {
			result = append(result, bucket...)
		}
	}

	return result
}

func topologicalSortBucket(ops []classifiedOp) []classifiedOp {
	if len(ops) <= 1 {
		return ops
	}

	// build set of operationCIDs in this batch
	cidToIdx := make(map[string]int)
	for i, op := range ops {
		if op.operationCID != "" {
			cidToIdx[op.operationCID] = i
		}
	}

	// in-degree: 1 if depends on another op in batch, 0 otherwise
	inDegree := make([]int, len(ops))
	dependents := make(map[string][]int) // operationCID → indices that depend on it

	for i, op := range ops {
		if op.previousCID != "" {
			if _, inBatch := cidToIdx[op.previousCID]; inBatch {
				inDegree[i] = 1
				dependents[op.previousCID] = append(dependents[op.previousCID], i)
			}
		}
	}

	// process zero in-degree first
	queue := make([]int, 0)
	for i, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, i)
		}
	}

	sorted := make([]classifiedOp, 0, len(ops))
	placed := make([]bool, len(ops))

	for len(queue) > 0 {
		idx := queue[0]
		queue = queue[1:]
		sorted = append(sorted, ops[idx])
		placed[idx] = true

		if ops[idx].operationCID != "" {
			for _, depIdx := range dependents[ops[idx].operationCID] {
				inDegree[depIdx]--
				if inDegree[depIdx] == 0 {
					queue = append(queue, depIdx)
				}
			}
		}
	}

	// append unplaceable ops at the end
	for i, op := range ops {
		if !placed[i] {
			sorted = append(sorted, op)
		}
	}

	return sorted
}

// ---------------------------------------------------------------------------
// main pipeline
// ---------------------------------------------------------------------------

type ingestConfig struct {
	logEnabled    bool
	admissionMode admissionMode
}

// IngestOption configures ingestion behavior.
type IngestOption func(*ingestConfig)

// WithLogDisabled disables writing to the global operation log during ingestion.
func WithLogDisabled() IngestOption {
	return func(c *ingestConfig) { c.logEnabled = false }
}

// WithHistoricalAdmission verifies artifacts, countersignatures, and content
// operations as committed peer history. Direct submissions must use the default
// current-state admission mode.
func WithHistoricalAdmission() IngestOption {
	return func(c *ingestConfig) { c.admissionMode = historicalAdmission }
}

// IngestOperations classifies, dependency-sorts, and processes a batch of JWS
// tokens. Returns results in the original submission order.
func IngestOperations(tokens []string, store Store, opts ...IngestOption) []IngestionResult {
	cfg := ingestConfig{logEnabled: true, admissionMode: currentAdmission}
	for _, o := range opts {
		o(&cfg)
	}

	classified := make([]classifiedOp, len(tokens))
	for i, token := range tokens {
		classified[i] = classify(token)
		classified[i].originalIndex = i
	}

	sorted := dependencySort(classified)

	type indexedResult struct {
		index  int
		result IngestionResult
	}
	results := make([]indexedResult, 0, len(sorted))

	// Collect the /index/v0 materialized-projection dirtiness across the whole
	// batch and flush it ONCE below. This is the single choke point for every
	// apply path (local POST, the sequencer fixed-point loop, and peer sync all
	// funnel through IngestOperations). Per-op collection keeps the fan-out
	// triggers (a chain:* grant, a revocation, an identity deletion) from each
	// running a full sweep; the batch flush runs at most one. Non-authoritative
	// and self-isolating: it never throws back into ingestion.
	dirty := newIndexDirtySet()

	for _, op := range sorted {
		var result IngestionResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					result = IngestionResult{CID: computeOpCID(op.jwsToken), Status: "rejected", Error: fmt.Sprintf("unexpected error: %v", r)}
				}
			}()
			switch op.kind {
			case "identity-op":
				result = ingestIdentityOp(op.jwsToken, store, cfg.logEnabled)
			case "content-op":
				result = ingestContentOp(op.jwsToken, store, cfg.logEnabled, cfg.admissionMode)
			case "countersign":
				result = ingestCountersign(op.jwsToken, store, cfg.logEnabled, cfg.admissionMode)
			case "artifact":
				result = ingestArtifact(op.jwsToken, store, cfg.logEnabled, cfg.admissionMode)
			case "revocation":
				result = ingestRevocation(op.jwsToken, store, cfg.logEnabled)
			case "credential":
				result = ingestPublicCredential(op.jwsToken, store, cfg.logEnabled)
			default:
				result = IngestionResult{CID: computeOpCID(op.jwsToken), Status: "rejected", Error: "unrecognized operation type"}
			}
		}()
		// Maintain the /index/v0 materialized projection synchronously, in
		// dependency order, right after the op is applied to the store. This is
		// the single choke point for every apply path (local POST, the sequencer
		// fixed-point loop, and peer sync all funnel through IngestOperations).
		// Non-authoritative and self-isolating: it never throws back into ingestion.
		collectIndexDirtyAfterOp(result, op.jwsToken, store, dirty)
		results = append(results, indexedResult{index: op.originalIndex, result: result})
	}

	// retry ops that failed due to missing dependencies — their dependencies
	// may have been satisfied by earlier ops in the same batch
	//
	// A half-applied op is excluded even though it is retryable: its dependencies
	// were never the problem, and re-running it now is actively harmful. Whatever
	// the failed attempt DID write makes the idempotency check at the top of the
	// ingest path answer "duplicate", which would overwrite the persistence
	// failure with a success verdict — hiding the fact that the op is half
	// applied from the batch owner, whose rollback is the only thing that can
	// undo it. The retry that matters is the next pass, after the batch is
	// discarded and the op is whole again.
	for retry := 0; retry < 3; retry++ {
		var pending []indexedResult
		for i, ir := range results {
			if ir.result.Status == "rejected" && !isPermanentRejection(ir.result) && !ir.result.PersistFailed {
				pending = append(pending, results[i])
			}
		}
		if len(pending) == 0 {
			break
		}

		progressed := false
		for _, p := range pending {
			var result IngestionResult
			switch classified[p.index].kind {
			case "identity-op":
				result = ingestIdentityOp(tokens[p.index], store, cfg.logEnabled)
			case "content-op":
				result = ingestContentOp(tokens[p.index], store, cfg.logEnabled, cfg.admissionMode)
			default:
				continue
			}
			if result.Status != "rejected" || isPermanentRejection(result) {
				// An op that failed dependency-missing in the main pass and now
				// succeeds on retry must still maintain the projection — the main
				// pass ran maintenance on its "rejected" result (a no-op). Mirror
				// the choke-point call here so a retried identity/content row lands.
				collectIndexDirtyAfterOp(result, tokens[p.index], store, dirty)
				// find and update the result
				for i, ir := range results {
					if ir.index == p.index {
						results[i].result = result
						break
					}
				}
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}

	// Flush the batch's collected projection dirtiness once, against the final
	// post-batch store state.
	flushIndexMaintenance(dirty, store)

	// return in original submission order
	sort.Slice(results, func(i, j int) bool {
		return results[i].index < results[j].index
	})

	out := make([]IngestionResult, len(results))
	for i, r := range results {
		out[i] = r.result
	}
	return out
}
