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
// rejection classification
// ---------------------------------------------------------------------------

// ErrDependencyMissing marks a verification failure as a MISSING DEPENDENCY:
// the identity chain or key the operation references is not in this store yet,
// so the operation may verify once sync or gossip delivers it. The sequencer
// keeps such an op pending; a PERMANENT rejection DELETES the raw op
// (MarkOpRejected), which is unrecoverable.
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

// ErrStoreFault marks a failure as THE STORE'S, NOT THE OPERATION'S: a read or a
// write did not complete, so nothing was decided about the operation and — since
// Commit is atomic — nothing was persisted.
//
// It is a separate sentinel from ErrDependencyMissing because the two are
// different facts about the world, even though both are retryable. A missing
// dependency is a verdict the relay reached against what it holds; a store fault
// is the relay failing to reach a verdict at all. Conflating them worked until a
// resolver returned a raw store error that carried NEITHER marker: the rejection
// classified as permanent, and a momentary "database is locked" during signature
// verification durably DELETED a valid operation.
//
// The sentinel survives the %w wrapping the protocol library applies on the way
// back up, which a bare error value from the store does not.
var ErrStoreFault = errors.New("store fault")

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

// storeFaultError carries ErrStoreFault the same way, and for the same reason.
type storeFaultError struct{ msg string }

func (e storeFaultError) Error() string { return e.msg }

func (e storeFaultError) Unwrap() error { return ErrStoreFault }

// storeFault wraps a failed store call so the fault survives every %w wrap
// between here and the classifier.
func storeFault(err error) error {
	return storeFaultError{msg: storeReadErrorPrefix + err.Error()}
}

// rejected builds a rejection from a verification error, classified structurally:
// a store fault and a missing dependency are both retryable, and the sequencer
// tells them apart by StoreFault.
func rejected(cid string, err error) IngestionResult {
	return IngestionResult{
		CID:               cid,
		Status:            "rejected",
		Error:             err.Error(),
		DependencyMissing: errors.Is(err, ErrDependencyMissing) || errors.Is(err, ErrStoreFault),
		StoreFault:        errors.Is(err, ErrStoreFault),
	}
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
// idempotency
// ---------------------------------------------------------------------------

// heldOperation answers the "have I already got this?" question every ingest
// path asks before it verifies, and it FAILS CLOSED.
//
// It returns a rejection result when the answer could not be obtained, when the
// CID is held under a different signature, or when it is held under the same one
// (a duplicate). A nil result means "not held, carry on".
//
// The fail-closed part is the whole point. Two of these gates used to be
// literally `existing, _ := store.GetOperation(cid)`, dropping the error — so one
// transient reader fault on a resubmitted genesis made `existing` nil, re-ran the
// genesis branch, and rewrote an N-operation chain as a 1-operation chain,
// reviving rotated-out keys and undoing a delete. Unrecoverable, because the
// later operations were still in the operations table while the chain row was
// gone, and every replay path hit the same duplicate short-circuit.
func heldOperation(store RelayReadStore, cid, jwsToken, kind, duplicateChainID string) *IngestionResult {
	existing, err := store.GetOperation(cid)
	if err != nil {
		result := rejected(cid, storeFault(err))
		return &result
	}
	if existing == nil {
		return nil
	}
	if existing.JWSToken != jwsToken {
		return &IngestionResult{CID: cid, Status: "rejected", Error: "operation already exists with a different signature"}
	}
	chainID := duplicateChainID
	if chainID == "" {
		chainID = existing.ChainID
	}
	return &IngestionResult{CID: cid, Status: "duplicate", Kind: kind, ChainID: chainID}
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
// dfos.IdentityState carries three readings of an identity's keys, and every
// surface in this package must pick one deliberately:
//
//   - EFFECTIVE (State.AuthKeys / AssertKeys / ControllerKeys) — "what is true
//     at this basis". At the head that is "what is true NOW": live auth,
//     current-state admission, and the DID document's verification methods. At
//     an earlier basis it is the prefix that basis names, which is what
//     ResolveIdentityAsOf computes and what every verification with a committed
//     basis resolves against (PROTOCOL, Time basis).
//   - HAS-EVER-PROVED (State.ProvedKeys) — "what was EVER true". The monotonic
//     union of every effective state the chain has held: a key proved in and
//     later rotated out stays forever, a key only ever declared never enters.
//     Two surfaces take it: credit claims, which run no temporal check at all,
//     and the `key=` / `signerKey=` reverse indexes.
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

// CreateKeyResolver returns a KeyResolver over every key an identity chain has
// EVER PROVED, rotated-out keys included.
//
// HAS-EVER-PROVED IS THE CREDIT-CLAIM CARVE-OUT: a credit claim runs no temporal
// check at all, so it resolves the claimant's key against every key that chain
// has held (PROTOCOL, Time basis). This resolver is the has-ever-proved reading
// the package offers a caller that needs it, the credit-claim path included.
// Every surface inside the relay has a basis and takes CreateAsOfKeyResolver,
// and the `key=` reverse index reads ProvedKeys directly, through
// index_projection.go.
//
// HAS-EVER-PROVED, NOT HAS-EVER-DECLARED. A declared-but-unproved membership is
// VOID: no possession proof ever admitted it, so nothing it signed was ever
// authorized, and resolving it would let a chain that merely LISTS a stranger's
// key speak with it. The chain walk already folds this union onto
// State.ProvedKeys, so there is no log re-scan here.
//
// THREE FAILURE CLASSES, AND THE STORE IS ITS OWN. A missing chain and an
// unknown key id may be answered differently once sync delivers more of the
// graph, so both wrap ErrDependencyMissing. A store error decided nothing at all
// and wraps ErrStoreFault — without that marker a momentary "database is locked"
// during signature verification classified as permanent and DELETED a valid
// operation. The malformed-kid and malformed-DID failures wrap neither: no amount
// of syncing makes a kid that is not a DID URL into one, so they stay permanent.
func CreateKeyResolver(store RelayReadStore) dfos.KeyResolver {
	return func(kid string, _ string) (ed25519.PublicKey, error) {
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
			return nil, storeFault(err)
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

// ResolveIdentityAsOf returns an identity's verified state AS OF basis, from
// this store's copy of its chain (PROTOCOL, Time basis), and whether that answer
// is DETERMINATE for the basis.
//
// TWO BRANCHES, ONE ANSWER. When the stored chain's last operation is dated at
// or before the basis, head state IS the state as of the basis for the log this
// store holds, and no walk runs. Otherwise the log is re-verified with the
// basis, which folds the prefix the basis names. Both branches return the same
// key set for the same basis. An empty basis is ephemeral and takes head state.
//
// ONLY THE RE-WALK BRANCH IS DETERMINATE, and the second return says which one
// answered. A stored operation dated after the basis proves this store holds
// every operation the basis names: the chain is linear and its createdAt
// strictly increases, so anything still to arrive is dated after the stored
// head. A chain that ends at or before the basis proves nothing of the sort,
// because the next operation to arrive can still be dated at or before the basis
// and add a key. A key missing from an indeterminate answer is a dependency miss
// rather than a verdict.
//
// DELETION READS HEAD STATE, never the as-of state: a deleted issuer's
// credentials are invalid retroactively, so the deletion a later operation
// recorded reaches back past the basis (CREDENTIALS, Deleted issuers).
//
// A nil chain with a nil error means this store does not hold it.
func ResolveIdentityAsOf(store RelayReadStore, did string, basis string) (state *dfos.IdentityState, determinate bool, err error) {
	identity, err := store.GetIdentityChain(did)
	if err != nil {
		return nil, false, storeFault(err)
	}
	if identity == nil {
		return nil, false, nil
	}
	if basis == "" || identity.LastCreatedAt <= basis {
		head := identity.State
		return &head, false, nil
	}
	result, err := dfos.VerifyIdentityChainAsOf(identity.Log, basis)
	if err != nil {
		return nil, false, err
	}
	asOf := result.State
	asOf.IsDeleted = identity.State.IsDeleted
	return &asOf, true, nil
}

// CreateAsOfKeyResolver returns a KeyResolver that resolves a kid in the
// identity's EFFECTIVE state as of the basis it is handed — the state that held
// when the artifact was signed. An empty basis is ephemeral and takes head
// state.
//
// A key absent from that state is a VERDICT only when the answer is determinate:
// the stored chain runs past the basis, so no operation the basis names can
// still arrive. Otherwise the miss is retryable, because sync may still deliver
// the operation that adds the key, and a verdict DELETES the raw op. An unknown
// chain stays retryable for the same reason, and a store error is a store fault,
// because it decided nothing. The message is one string either way, so the
// classification never shows up on the wire.
func CreateAsOfKeyResolver(store RelayReadStore) dfos.KeyResolver {
	return func(kid string, basis string) (ed25519.PublicKey, error) {
		hashIdx := strings.Index(kid, "#")
		if hashIdx < 0 {
			return nil, fmt.Errorf("kid must be a DID URL: %s", kid)
		}
		did := kid[:hashIdx]
		keyID := kid[hashIdx+1:]

		if err := dfos.ValidateDID(did); err != nil {
			return nil, err
		}

		state, determinate, err := ResolveIdentityAsOf(store, did, basis)
		if err != nil {
			return nil, err
		}
		if state == nil {
			return nil, dependencyMissingf("unknown identity: %s", did)
		}

		if k, ok := findKeyInKeyState(effectiveKeyState(*state), keyID); ok {
			return dfos.DecodeMultikey(k.PublicKeyMultibase)
		}

		if determinate {
			return nil, fmt.Errorf("unknown key %s on identity %s", keyID, did)
		}
		return nil, dependencyMissingf("unknown key %s on identity %s", keyID, did)
	}
}

// CreateCurrentKeyResolver returns a KeyResolver that only resolves
// current-state keys. Used for live auth and first admission — the freshness
// question the relay asks of a NEW operation (RELAY, "Ingest asks freshness").
// The basis is accepted and ignored: this resolver answers about head state by
// construction.
//
// EFFECTIVE state, which is what the head arrays mean: a declared-but-void key
// is absent from them, so it never authenticates.
//
// Only the unknown-identity failure is a dependency miss here, and only a store
// error is a store fault. A DELETED identity and a key that is merely no longer
// current are both verdicts this store is already entitled to reach, and
// re-asking later cannot change them.
func CreateCurrentKeyResolver(store RelayReadStore) dfos.KeyResolver {
	return func(kid string, _ string) (ed25519.PublicKey, error) {
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
			return nil, storeFault(err)
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

// admissionKeyResolver is the signer resolver for one admission mode.
//
// First admission of a NEW operation asks freshness, so the signer must be
// effective at the head. Replay and peer ingest of committed history ask the
// basis, so the signer must have been effective at the operation's own
// createdAt (RELAY, "Ingest asks freshness; re-verification asks the basis").
func admissionKeyResolver(store RelayReadStore, mode admissionMode) dfos.KeyResolver {
	if mode == historicalAdmission {
		return CreateAsOfKeyResolver(store)
	}
	return CreateCurrentKeyResolver(store)
}

// ---------------------------------------------------------------------------
// the commit
// ---------------------------------------------------------------------------

// commitOperation hands one accepted operation to the store as a single unit and
// turns the two answers into results.
//
// A store error here is a STORE FAULT, never a verdict: Commit persisted nothing,
// the raw op stays pending, and a later pass re-ingests it. That is the whole
// reason the write contract is one atomic call — a run of independent put calls
// could leave the operation half-held, and the half that DID land makes every
// retry short-circuit as a duplicate, so the half that failed is never made up.
func commitOperation(store RelayWriteStore, result IngestionResult, commit OperationCommit) IngestionResult {
	outcome, err := store.Commit(CommitBatch{Operation: &commit})
	if err != nil {
		return IngestionResult{
			CID:               result.CID,
			Status:            "rejected",
			Error:             persistErrorPrefix + err.Error(),
			DependencyMissing: true,
			StoreFault:        true,
		}
	}
	if outcome == CommitDuplicate {
		// Another submission of the same operation won the race. Nothing was
		// written by this one, and the operation is held either way.
		return IngestionResult{CID: result.CID, Status: "duplicate", Kind: result.Kind, ChainID: result.ChainID}
	}
	return result
}

// logEntryFor builds the global-log append for an accepted operation, or nil when
// the relay runs with the log disabled.
func logEntryFor(enabled bool, cid, jwsToken, kind, chainID string) *LogEntry {
	if !enabled {
		return nil
	}
	return &LogEntry{CID: cid, JWSToken: jwsToken, Kind: kind, ChainID: chainID}
}

// ---------------------------------------------------------------------------
// individual verifiers
// ---------------------------------------------------------------------------

func ingestIdentityOp(jwsToken string, store RelayWriteStore, logEnabled bool) IngestionResult {
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

	if held := heldOperation(store, cid, jwsToken, "identity-op", ""); held != nil {
		return *held
	}

	opType, _ := payload["type"].(string)
	isGenesis := opType == "create"

	if isGenesis {
		result, err := dfos.VerifyIdentityChain([]string{jwsToken})
		if err != nil {
			return rejected(cid, err)
		}
		// A genesis never REPLACES a chain. The chain row is written whole, so
		// admitting a genesis for a DID that already has history would rewrite an
		// N-operation chain as a 1-operation one — reviving rotated-out keys and
		// undoing a delete — and nothing legitimate does that.
		existing, cerr := store.GetIdentityChain(result.State.DID)
		if cerr != nil {
			return rejected(cid, storeFault(cerr))
		}
		if existing != nil && existing.HeadCID != cid {
			return IngestionResult{CID: cid, Status: "rejected", Error: "identity chain already exists"}
		}
		createdAt, _ := payload["createdAt"].(string)
		chain := StoredIdentityChain{
			DID:           result.State.DID,
			Log:           []string{jwsToken},
			HeadCID:       cid,
			LastCreatedAt: createdAt,
			State:         result.State,
		}
		return commitOperation(store,
			IngestionResult{CID: cid, Status: "new", Kind: "identity-op", ChainID: result.State.DID},
			OperationCommit{
				Operation:     StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: result.State.DID},
				IdentityChain: &chain,
				LogEntry:      logEntryFor(logEnabled, cid, jwsToken, "identity-op", result.State.DID),
			})
	}

	// extension — find existing chain via kid DID
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return IngestionResult{CID: cid, Status: "rejected", Error: "non-genesis kid must be a DID URL"}
	}
	did := kid[:hashIdx]

	chain, cerr := store.GetIdentityChain(did)
	if cerr != nil {
		return rejected(cid, storeFault(cerr))
	}
	if chain == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown identity: %s", did), DependencyMissing: true}
	}

	// extract previousOperationCID from payload
	previousCID, _ := payload["previousOperationCID"].(string)

	if previousCID == chain.HeadCID {
		// linear extension (fast path)
		extResult, err := dfos.VerifyIdentityExtension(chain.State, chain.HeadCID, chain.LastCreatedAt, jwsToken)
		if err != nil {
			return rejected(cid, err)
		}
		updated := StoredIdentityChain{
			DID:           chain.DID,
			Log:           append(append([]string{}, chain.Log...), jwsToken),
			HeadCID:       extResult.HeadCID,
			LastCreatedAt: extResult.LastCreatedAt,
			State:         extResult.State,
		}
		return commitOperation(store,
			IngestionResult{CID: cid, Status: "new", Kind: "identity-op", ChainID: did},
			OperationCommit{
				Operation:     StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: did},
				IdentityChain: &updated,
				LogEntry:      logEntryFor(logEnabled, cid, jwsToken, "identity-op", did),
			})
	}

	// Unknown parents are retryable dependencies. A known non-head parent
	// already has a committed child and is a permanent conflict.
	if previousCID == "" || !chainLogContainsCID(chain.Log, previousCID) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in identity chain", DependencyMissing: true}
	}
	return IngestionResult{CID: cid, Status: "rejected", Error: identityConflictingExtensionError}
}

func ingestContentOp(jwsToken string, store RelayWriteStore, logEnabled bool, mode admissionMode) IngestionResult {
	_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil {
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

	if held := heldOperation(store, cid, jwsToken, "content-op", ""); held != nil {
		return *held
	}

	// reject content ops from deleted identities. A failed lookup is NOT
	// "not deleted" — the gate fails closed and the op stays pending.
	signerDID, _ := payload["did"].(string)
	if signerDID != "" {
		signerIdentity, err := store.GetIdentityChain(signerDID)
		if err != nil {
			return rejected(cid, storeFault(err))
		}
		if signerIdentity != nil && signerIdentity.State.IsDeleted {
			return IngestionResult{CID: cid, Status: "rejected", Error: "signer identity is deleted"}
		}
	}

	resolveKey := admissionKeyResolver(store, mode)
	// A credential carried inline in a content operation is committed with it, so
	// its issuer resolves as of the operation's own createdAt in BOTH admission
	// modes. The protocol verifier passes that basis; this resolver answers at it.
	resolveCredentialKey := CreateAsOfKeyResolver(store)
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
	//
	// Both closures mark a store failure as a STORE FAULT rather than letting the
	// raw error through: an unmarked error classifies as a permanent rejection,
	// and a permanent rejection deletes the raw op.
	isRevoked := dfos.WithRevocationChecker(func(issuerDID, credentialCID string, _ int64) (bool, error) {
		revoked, err := store.IsCredentialRevoked(issuerDID, credentialCID, 0)
		if err != nil {
			return false, storeFault(err)
		}
		return revoked, nil
	})
	isDeleted := dfos.WithIdentityDeletedChecker(func(did string) (bool, error) {
		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return false, storeFault(err)
		}
		return identity != nil && identity.State.IsDeleted, nil
	})
	opType, _ := payload["type"].(string)
	isGenesis := opType == "create"

	if isGenesis {
		result, err := dfos.VerifyContentChain([]string{jwsToken}, resolveKey, true, isRevoked, isDeleted, dfos.WithCredentialKeyResolver(resolveCredentialKey))
		if err != nil {
			return rejected(cid, err)
		}
		// Same rule as an identity genesis: a chain row is written whole, so a
		// genesis never replaces existing history.
		existing, cerr := store.GetContentChain(result.State.ContentID)
		if cerr != nil {
			return rejected(cid, storeFault(cerr))
		}
		if existing != nil && existing.GenesisCID != cid {
			return IngestionResult{CID: cid, Status: "rejected", Error: "content chain already exists"}
		}
		createdAt, _ := payload["createdAt"].(string)
		chain := StoredContentChain{
			ContentID:     result.State.ContentID,
			GenesisCID:    result.State.GenesisCID,
			Log:           []string{jwsToken},
			LastCreatedAt: createdAt,
			State:         result.State,
		}
		return commitOperation(store,
			IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: result.State.ContentID},
			OperationCommit{
				Operation:    StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: result.State.ContentID},
				ContentChain: &chain,
				LogEntry:     logEntryFor(logEnabled, cid, jwsToken, "content-op", result.State.ContentID),
			})
	}

	// extension — find chain via previousOperationCID
	previousCID, ok := payload["previousOperationCID"].(string)
	if !ok || previousCID == "" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "missing previousOperationCID"}
	}

	prevOp, perr := store.GetOperation(previousCID)
	if perr != nil {
		return rejected(cid, storeFault(perr))
	}
	if prevOp == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown previous operation: %s", previousCID), DependencyMissing: true}
	}
	if prevOp.ChainType != "content" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "previousOperationCID is not a content operation"}
	}

	chain, cerr := store.GetContentChain(prevOp.ChainID)
	if cerr != nil {
		return rejected(cid, storeFault(cerr))
	}
	if chain == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("content chain not found: %s", prevOp.ChainID), DependencyMissing: true}
	}

	// reject if creator's identity is deleted (fails closed on a store error)
	creatorIdentity, ierr := store.GetIdentityChain(chain.State.CreatorDID)
	if ierr != nil {
		return rejected(cid, storeFault(ierr))
	}
	if creatorIdentity != nil && creatorIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "content creator identity is deleted"}
	}

	if chain.State.HeadCID == previousCID {
		// linear extension (fast path)
		extResult, err := dfos.VerifyContentExtension(chain.State, chain.LastCreatedAt, jwsToken, resolveKey, true, isRevoked, isDeleted, dfos.WithCredentialKeyResolver(resolveCredentialKey))
		if err != nil {
			return rejected(cid, err)
		}
		updated := StoredContentChain{
			ContentID:     chain.ContentID,
			GenesisCID:    chain.GenesisCID,
			Log:           append(append([]string{}, chain.Log...), jwsToken),
			LastCreatedAt: extResult.LastCreatedAt,
			State:         extResult.State,
		}
		return commitOperation(store,
			IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: chain.ContentID},
			OperationCommit{
				Operation:    StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: chain.ContentID},
				ContentChain: &updated,
				LogEntry:     logEntryFor(logEnabled, cid, jwsToken, "content-op", chain.ContentID),
			})
	}

	// fork path — check if previousCID exists in chain ops
	if !chainLogContainsCID(chain.Log, previousCID) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in content chain", DependencyMissing: true}
	}

	forkState, err := store.GetContentStateAtCID(chain.ContentID, previousCID)
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: ForkPointStateErrorPrefix + fmt.Sprintf("%v", err), DependencyMissing: true, StoreFault: true}
	}
	if forkState == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in content chain", DependencyMissing: true}
	}

	extResult, err := dfos.VerifyContentExtension(forkState.State, forkState.LastCreatedAt, jwsToken, resolveKey, true, isRevoked, isDeleted, dfos.WithCredentialKeyResolver(resolveCredentialKey))
	if err != nil {
		return rejected(cid, err)
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
	return commitOperation(store,
		IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: chain.ContentID},
		OperationCommit{
			Operation:    StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: chain.ContentID},
			ContentChain: &updated,
			LogEntry:     logEntryFor(logEnabled, cid, jwsToken, "content-op", chain.ContentID),
		})
}

func ingestCountersign(jwsToken string, store RelayWriteStore, logEnabled bool, mode admissionMode) IngestionResult {
	resolveKey := admissionKeyResolver(store, mode)

	result, err := dfos.VerifyCountersignature(jwsToken, resolveKey)
	if err != nil {
		return rejected(computeOpCID(jwsToken), err)
	}

	cid := result.CountersignCID
	witnessDID := result.WitnessDID
	targetCID := result.TargetCID

	if held := heldOperation(store, cid, jwsToken, "countersign", targetCID); held != nil {
		if held.Status == "rejected" && held.Error == "operation already exists with a different signature" {
			return IngestionResult{CID: cid, Status: "rejected", Error: "countersign already exists with a different signature"}
		}
		return *held
	}

	// target must exist (may arrive later via sync/gossip — retryable)
	targetOp, terr := store.GetOperation(targetCID)
	if terr != nil {
		return rejected(cid, storeFault(terr))
	}
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
	if werr != nil {
		return rejected(cid, storeFault(werr))
	}
	if witnessIdentity != nil && witnessIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "witness identity is deleted"}
	}

	// dedup: one countersign per witness per target
	existingCountersigns, cerr := store.GetCountersignatures(targetCID)
	if cerr != nil {
		return rejected(cid, storeFault(cerr))
	}
	for _, csJws := range existingCountersigns {
		_, csPayload, err := dfos.DecodeJWSUnsafe(csJws)
		if err != nil {
			continue
		}
		if d, ok := csPayload["did"].(string); ok && d == witnessDID {
			return IngestionResult{CID: cid, Status: "duplicate", Kind: "countersign", ChainID: targetCID}
		}
	}

	return commitOperation(store,
		IngestionResult{CID: cid, Status: "new", Kind: "countersign", ChainID: targetCID},
		OperationCommit{
			Operation:        StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "countersign", ChainID: targetCID},
			Countersignature: &CountersignatureCommit{TargetCID: targetCID, JWSToken: jwsToken},
			LogEntry:         logEntryFor(logEnabled, cid, jwsToken, "countersign", targetCID),
		})
}

func ingestArtifact(jwsToken string, store RelayWriteStore, logEnabled bool, mode admissionMode) IngestionResult {
	resolveKey := admissionKeyResolver(store, mode)

	result, err := dfos.VerifyArtifact(jwsToken, resolveKey)
	if err != nil {
		return rejected(computeOpCID(jwsToken), err)
	}

	cid := result.ArtifactCID
	did := result.DID

	if held := heldOperation(store, cid, jwsToken, "artifact", did); held != nil {
		if held.Status == "rejected" && held.Error == "operation already exists with a different signature" {
			return IngestionResult{CID: cid, Status: "rejected", Error: "artifact already exists with a different signature"}
		}
		return *held
	}

	// reject artifacts from deleted identities (fails closed on a store error)
	identity, ierr := store.GetIdentityChain(did)
	if ierr != nil {
		return rejected(cid, storeFault(ierr))
	}
	if identity != nil && identity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "identity is deleted"}
	}

	return commitOperation(store,
		IngestionResult{CID: cid, Status: "new", Kind: "artifact", ChainID: did},
		OperationCommit{
			Operation: StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "artifact", ChainID: did},
			LogEntry:  logEntryFor(logEnabled, cid, jwsToken, "artifact", did),
		})
}

func ingestRevocation(jwsToken string, store RelayWriteStore, logEnabled bool) IngestionResult {
	// A revocation is a committed statement: its signer resolves as of its own
	// createdAt, which the protocol verifier passes.
	resolveKey := CreateAsOfKeyResolver(store)

	result, err := dfos.VerifyRevocation(jwsToken, resolveKey)
	if err != nil {
		return rejected(computeOpCID(jwsToken), err)
	}

	cid := result.RevocationCID
	did := result.DID

	if held := heldOperation(store, cid, jwsToken, "revocation", did); held != nil {
		return *held
	}

	// reject if identity is deleted (fails closed on a store error)
	identity, ierr := store.GetIdentityChain(did)
	if ierr != nil {
		return rejected(cid, storeFault(ierr))
	}
	if identity != nil && identity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "identity is deleted"}
	}

	// Issuer scope, not CID scope. Revocation is issuer-only, so a held
	// credential someone ELSE issued is not the credential this revocation
	// reaches: it is neither reported as a revoked grant nor evicted below. See
	// PublicCredentialRemoval — the store enforces the same pairing on the way
	// down, so a foreign revocation cannot drop a grant it did not issue.
	revokedCredential, err := store.GetPublicCredentialByCID(result.CredentialCID)
	if err != nil {
		return rejected(cid, storeFault(err))
	}
	var revokedGrant *RevokedGrant
	if revokedCredential != nil && revokedCredential.IssuerDID == did {
		wildcard, contentIDs := contentIdsFromCredential(*revokedCredential)
		revokedGrant = &RevokedGrant{Wildcard: wildcard, ContentIDs: contentIDs}
	}

	accepted := IngestionResult{CID: cid, Status: "new", Kind: "revocation", ChainID: did, RevokedGrant: revokedGrant}
	return commitOperation(store, accepted, OperationCommit{
		Operation: StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "revocation", ChainID: did},
		// The stored revocation carries the VERIFIED createdAt, which is the as-of
		// boundary every later validity check compares against.
		Revocation: &StoredRevocation{
			CID:           cid,
			IssuerDID:     did,
			CredentialCID: result.CredentialCID,
			JWSToken:      jwsToken,
			CreatedAt:     result.CreatedAt,
		},
		RemovePublicCredential: &PublicCredentialRemoval{IssuerDID: did, CredentialCID: result.CredentialCID},
		LogEntry:               logEntryFor(logEnabled, cid, jwsToken, "revocation", did),
	})
}

func ingestPublicCredential(jwsToken string, store RelayWriteStore, logEnabled bool) IngestionResult {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return IngestionResult{Status: "rejected", Error: "failed to decode JWS"}
	}

	// header.CID is the JWS-header-claimed CID. It keys the OPERATION store /
	// idempotency lookups below and is surfaced to API callers as
	// IngestionResult.CID — but it does NOT key the raw op: raw_ops is keyed by the
	// recomputed storage CID (computeOpCID(token) = DagCborCID(payload)),
	// independent of header.CID. The drain loops therefore key MarkOp{Rejected,
	// Sequenced} on that storage CID, and gate on it (NOT on this res.CID), so a
	// rejection carrying an empty header.CID still drains its stored raw row rather
	// than stranding it 'pending'.
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

	if held := heldOperation(store, cid, jwsToken, "credential", kidDID); held != nil {
		return *held
	}

	// reject credentials from a deleted issuer (matches TS verifyDFOSCredential,
	// which resolves the issuer identity and rejects when isDeleted). Fails
	// closed on a store error.
	issuerIdentity, ierr := store.GetIdentityChain(kidDID)
	if ierr != nil {
		return rejected(cid, storeFault(ierr))
	}
	if issuerIdentity != nil && issuerIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "issuer identity is deleted"}
	}

	// check if already revoked — timeless (asOf 0): admitting a standing credential
	// is an acceptance decision, so it asks what the relay knows right now. A
	// revocation lookup that FAILS is not "not revoked": the gate fails closed.
	revoked, rerr := store.IsCredentialRevoked(kidDID, cid, 0)
	if rerr != nil {
		return rejected(cid, storeFault(rerr))
	}
	if revoked {
		return IngestionResult{CID: cid, Status: "rejected", Error: "credential has been revoked"}
	}

	// A standalone public credential is an ephemeral presentation, so its basis
	// is now: the signing key must be effective at the head, and exp runs against
	// the wall clock. A key the issuer has rotated out grants nothing new. An
	// unresolved identity means the issuer has not synced yet — retryable.
	resolveKey := CreateAsOfKeyResolver(store)
	publicKey, err := resolveKey(kid, "")
	if err != nil {
		return rejected(cid, fmt.Errorf("failed to resolve key: %w", err))
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

	return commitOperation(store,
		IngestionResult{CID: cid, Status: "new", Kind: "credential", ChainID: kidDID},
		OperationCommit{
			Operation: StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "credential", ChainID: kidDID, IngestedAt: ingestedAt},
			PublicCredential: &StoredPublicCredential{
				CID:        cid,
				IssuerDID:  credential.Iss,
				Att:        att,
				Exp:        credential.Exp,
				JWSToken:   jwsToken,
				CreatedAt:  credentialCreatedAt(credential.Iat),
				IngestedAt: ingestedAt,
			},
			LogEntry: logEntryFor(logEnabled, cid, jwsToken, "credential", kidDID),
		})
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
//
// NO INDEX WORK HAPPENS HERE. Maintaining the /index/v0 projection used to be a
// choke point inside this loop, which put a full-corpus sweep inside the ingest
// mutex behind an anonymous POST. The projection now reads the operation log on
// its own schedule (index_projection.go); this function's only job is to admit
// operations and commit them.
func IngestOperations(tokens []string, store RelayWriteStore, opts ...IngestOption) []IngestionResult {
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

	apply := func(op classifiedOp, token string) (result IngestionResult) {
		defer func() {
			if r := recover(); r != nil {
				result = IngestionResult{CID: computeOpCID(token), Status: "rejected", Error: fmt.Sprintf("unexpected error: %v", r)}
			}
		}()
		switch op.kind {
		case "identity-op":
			return ingestIdentityOp(token, store, cfg.logEnabled)
		case "content-op":
			return ingestContentOp(token, store, cfg.logEnabled, cfg.admissionMode)
		case "countersign":
			return ingestCountersign(token, store, cfg.logEnabled, cfg.admissionMode)
		case "artifact":
			return ingestArtifact(token, store, cfg.logEnabled, cfg.admissionMode)
		case "revocation":
			return ingestRevocation(token, store, cfg.logEnabled)
		case "credential":
			return ingestPublicCredential(token, store, cfg.logEnabled)
		default:
			return IngestionResult{CID: computeOpCID(token), Status: "rejected", Error: "unrecognized operation type"}
		}
	}

	for _, op := range sorted {
		results = append(results, indexedResult{index: op.originalIndex, result: apply(op, op.jwsToken)})
	}

	// Retry ops that failed on a missing dependency — their dependencies may have
	// been satisfied by later ops in the same batch.
	//
	// A STORE FAULT IS NOT RETRIED HERE. It is retryable, but not within this
	// batch: the store is unwell, so a second attempt against it costs the same
	// verification work to reach the same answer. The retry that matters is the
	// next sequencer pass, with the raw op still pending.
	for retry := 0; retry < 3; retry++ {
		var pending []indexedResult
		for i, ir := range results {
			if ir.result.Status == "rejected" && ir.result.DependencyMissing && !ir.result.StoreFault {
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
			if result.Status != "rejected" || isPermanentRejection(result) || result.StoreFault {
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
