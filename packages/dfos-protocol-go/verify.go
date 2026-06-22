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
type KeyResolver func(kid string) (ed25519.PublicKey, error)

// RevocationChecker reports whether a credential (by issuer DID + credential
// CID) has been revoked. Threaded onto the content WRITE path so revoked
// credentials — leaf AND parents — no longer authorize writes.
type RevocationChecker func(issuerDID, credentialCID string) (bool, error)

// IdentityDeletedChecker reports whether an identity (by DID) has been deleted.
// Threaded onto the content WRITE path so credentials issued by a deleted
// issuer/parent identity no longer authorize writes. The protocol package is
// store-agnostic, so the relay supplies this closure at the call boundary.
type IdentityDeletedChecker func(did string) (bool, error)

// contentVerifyOpts holds optional WRITE-path hardening callbacks threaded from
// the relay boundary. All are nil-safe — when a callback is nil the
// corresponding check is skipped (the protocol layer stays store-agnostic).
type contentVerifyOpts struct {
	isRevoked RevocationChecker
	isDeleted IdentityDeletedChecker
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
// Identity chain verification
// -----------------------------------------------------------------------------

// VerifyIdentityChain verifies a log of JWS identity operations and derives
// the identity state. The chain is self-sovereign — keys are resolved from
// the chain itself, no external resolver needed.
func VerifyIdentityChain(log []string) (*VerifiedIdentityResult, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("log must have at least one operation")
	}

	var (
		did            string
		isDeleted      bool
		previousCID    string
		lastCreatedAt  string
		authKeys       []MultikeyPublicKey
		assertKeys     []MultikeyPublicKey
		controllerKeys []MultikeyPublicKey
		services       []ServiceEntry
		seenKeys       = make(map[string]MultikeyPublicKey)
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
		if opType != "create" && opType != "update" && opType != "delete" {
			return nil, fmt.Errorf("log[%d]: invalid operation type", idx)
		}
		if err := validateCreatedAt(createdAt); err != nil {
			return nil, fmt.Errorf("log[%d]: %w", idx, err)
		}
		if header.Typ != "did:dfos:identity-op" {
			return nil, fmt.Errorf("log[%d]: invalid typ: %s", idx, header.Typ)
		}

		// terminal state
		if isDeleted {
			return nil, fmt.Errorf("log[%d]: cannot modify a deleted identity", idx)
		}

		// type sequence
		if idx == 0 && opType != "create" {
			return nil, fmt.Errorf("log[%d]: first operation must be create", idx)
		}
		if idx > 0 && opType == "create" {
			return nil, fmt.Errorf("log[%d]: create can only be the first operation", idx)
		}

		// parse keys for create/update
		var opAuthKeys, opAssertKeys, opControllerKeys []MultikeyPublicKey
		if opType == "create" || opType == "update" {
			opControllerKeys, err = payloadMultikeyArray(payload, "controllerKeys")
			if err != nil {
				return nil, fmt.Errorf("log[%d]: %w", idx, err)
			}
			if len(opControllerKeys) == 0 {
				return nil, fmt.Errorf("log[%d]: %s must have at least one controller key", idx, opType)
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
			authKeys = opAuthKeys
			assertKeys = opAssertKeys
			controllerKeys = opControllerKeys
			services = opServices
		}

		// chain integrity for non-genesis
		if opType == "update" || opType == "delete" {
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

		// key consistency — same key ID must always map to same material
		if opType == "create" || opType == "update" {
			allKeys := make([]MultikeyPublicKey, 0)
			allKeys = append(allKeys, authKeys...)
			allKeys = append(allKeys, assertKeys...)
			allKeys = append(allKeys, controllerKeys...)
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

		// find controller key
		var signingKey *MultikeyPublicKey
		for i := range controllerKeys {
			if controllerKeys[i].ID == signingKeyID {
				signingKey = &controllerKeys[i]
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
			authKeys = opAuthKeys
			assertKeys = opAssertKeys
			controllerKeys = opControllerKeys
			services = opServices
		case "delete":
			isDeleted = true
		}
	}

	if did == "" {
		return nil, fmt.Errorf("did is not set")
	}

	return &VerifiedIdentityResult{
		State: IdentityState{
			DID:            did,
			IsDeleted:      isDeleted,
			AuthKeys:       authKeys,
			AssertKeys:     assertKeys,
			ControllerKeys: controllerKeys,
			Services:       normalizeServices(services),
		},
		HeadCID:       previousCID,
		LastCreatedAt: lastCreatedAt,
	}, nil
}

// VerifyIdentityExtension verifies a single new operation against
// already-verified identity state. O(1) — one signature verification,
// one state transition.
func VerifyIdentityExtension(currentState IdentityState, headCID, lastCreatedAt, newOp string) (*VerifiedIdentityResult, error) {
	if currentState.IsDeleted {
		return nil, fmt.Errorf("cannot extend a deleted identity")
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
	if opType != "update" && opType != "delete" {
		return nil, fmt.Errorf("invalid operation type")
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

	// find controller key
	var signingKey *MultikeyPublicKey
	for i := range currentState.ControllerKeys {
		if currentState.ControllerKeys[i].ID == signingKeyID {
			signingKey = &currentState.ControllerKeys[i]
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

		return &VerifiedIdentityResult{
			State: IdentityState{
				DID:            currentState.DID,
				IsDeleted:      false,
				AuthKeys:       opAuthKeys,
				AssertKeys:     opAssertKeys,
				ControllerKeys: opControllerKeys,
				Services:       normalizeServices(opServices),
			},
			HeadCID:       operationCID,
			LastCreatedAt: createdAt,
		}, nil
	}

	// delete — carry the last services state
	return &VerifiedIdentityResult{
		State: IdentityState{
			DID:            currentState.DID,
			IsDeleted:      true,
			AuthKeys:       currentState.AuthKeys,
			AssertKeys:     currentState.AssertKeys,
			ControllerKeys: currentState.ControllerKeys,
			Services:       normalizeServices(currentState.Services),
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

	creatorPubKey, err := resolveKey(vcKid)
	if err != nil {
		return fmt.Errorf("cannot resolve creator key for authorization verification")
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
	if opts.isRevoked != nil {
		revoked, err := opts.isRevoked(vc.Iss, vc.CID)
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
	if err := verifyDelegationChain(authorization, vc, childAtt, childPrf, resolveKey, creatorDID, opts.isRevoked, opts.isDeleted, 0); err != nil {
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
				return nil, fmt.Errorf("log[%d]: authorization verification failed: %s", idx, err)
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
			return nil, fmt.Errorf("authorization verification failed: %s", err)
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
