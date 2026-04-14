package dfos

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

// KeyResolver resolves a kid (DID URL: "did:dfos:xxx#key_yyy") to an Ed25519 public key.
type KeyResolver func(kid string) (ed25519.PublicKey, error)

// protocolTimeFormat is declared in timestamp.go

// contentIDLength is the expected length of a DFOS content ID.
const contentIDLength = 22

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

// VerifiedBeaconResult is the result of beacon verification.
type VerifiedBeaconResult struct {
	BeaconCID         string
	DID               string
	ManifestContentId string
	CreatedAt         string
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

		// initialize key state from genesis
		if opType == "create" {
			authKeys = opAuthKeys
			assertKeys = opAssertKeys
			controllerKeys = opControllerKeys
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
		_, cidBytes, operationCID, err := DagCborCID(payload)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to derive CID: %w", idx, err)
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
	_, _, operationCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive CID: %w", err)
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

		return &VerifiedIdentityResult{
			State: IdentityState{
				DID:            currentState.DID,
				IsDeleted:      false,
				AuthKeys:       opAuthKeys,
				AssertKeys:     opAssertKeys,
				ControllerKeys: opControllerKeys,
			},
			HeadCID:       operationCID,
			LastCreatedAt: createdAt,
		}, nil
	}

	// delete
	return &VerifiedIdentityResult{
		State: IdentityState{
			DID:            currentState.DID,
			IsDeleted:      true,
			AuthKeys:       currentState.AuthKeys,
			AssertKeys:     currentState.AssertKeys,
			ControllerKeys: currentState.ControllerKeys,
		},
		HeadCID:       operationCID,
		LastCreatedAt: createdAt,
	}, nil
}

// -----------------------------------------------------------------------------
// Content chain verification
// -----------------------------------------------------------------------------

// VerifyContentChain verifies a content chain's structural integrity,
// signatures, and authorization. The caller provides a KeyResolver to look up
// public keys from kid values.
//
// When enforceAuthorization is true, non-creator signers must include a valid
// DFOSContentWrite DFOS credential in the operation's authorization field.
func VerifyContentChain(log []string, resolveKey KeyResolver, enforceAuthorization bool) (*VerifiedContentResult, error) {
	if len(log) == 0 {
		return nil, fmt.Errorf("log must have at least one operation")
	}

	var (
		contentID      string
		genesisCID     string
		headCID        string
		isDeleted      bool
		currentDocCID  *string
		previousCID    string
		lastCreatedAt  string
		creatorDID     string
		length         int
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

			vcHeader, _, vcErr := DecodeJWSUnsafe(authorization)
			if vcErr != nil {
				return nil, fmt.Errorf("log[%d]: failed to decode authorization credential", idx)
			}
			vcKid := vcHeader.Kid
			if vcKid == "" || !strings.Contains(vcKid, "#") {
				return nil, fmt.Errorf("log[%d]: authorization credential kid must be a DID URL", idx)
			}

			creatorPubKey, err := resolveKey(vcKid)
			if err != nil {
				return nil, fmt.Errorf("log[%d]: cannot resolve creator key for authorization verification", idx)
			}

			opTime, parseErr := time.Parse(protocolTimeFormat, createdAt)
			if parseErr != nil {
				return nil, fmt.Errorf("log[%d]: invalid createdAt format: %w", idx, parseErr)
			}
			opTimeUnix := opTime.Unix()

			vc, err := VerifyCredentialAt(authorization, creatorPubKey, opDID, "DFOSContentWrite", opTimeUnix)
			if err != nil {
				return nil, fmt.Errorf("log[%d]: authorization verification failed: %s", idx, err)
			}
			if vc.Iss != creatorDID {
				return nil, fmt.Errorf("log[%d]: authorization verification failed: credential issuer is not the chain creator", idx)
			}
			if vc.ContentID != "" && vc.ContentID != contentID {
				return nil, fmt.Errorf("log[%d]: authorization verification failed: credential contentId %s does not match chain %s", idx, vc.ContentID, contentID)
			}
		}

		// derive operation CID
		_, cidBytes, operationCID, err := DagCborCID(payload)
		if err != nil {
			return nil, fmt.Errorf("log[%d]: failed to derive CID: %w", idx, err)
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
func VerifyContentExtension(currentState ContentState, lastCreatedAt, newOp string, resolveKey KeyResolver, enforceAuthorization bool) (*VerifiedContentResult, error) {
	if currentState.IsDeleted {
		return nil, fmt.Errorf("cannot extend a deleted chain")
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

		vcHeader, _, vcErr := DecodeJWSUnsafe(authorization)
		if vcErr != nil {
			return nil, fmt.Errorf("failed to decode authorization credential")
		}
		vcKid := vcHeader.Kid
		if vcKid == "" || !strings.Contains(vcKid, "#") {
			return nil, fmt.Errorf("authorization credential kid must be a DID URL")
		}

		creatorPubKey, err := resolveKey(vcKid)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve creator key for authorization verification")
		}

		opTime, parseErr := time.Parse(protocolTimeFormat, createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid createdAt format: %w", parseErr)
		}
		opTimeUnix := opTime.Unix()

		vc, err := VerifyCredentialAt(authorization, creatorPubKey, opDID, "DFOSContentWrite", opTimeUnix)
		if err != nil {
			return nil, fmt.Errorf("authorization verification failed: %s", err)
		}
		if vc.Iss != currentState.CreatorDID {
			return nil, fmt.Errorf("authorization verification failed: credential issuer is not the chain creator")
		}
		if vc.ContentID != "" && vc.ContentID != currentState.ContentID {
			return nil, fmt.Errorf("authorization verification failed: credential contentId %s does not match chain %s", vc.ContentID, currentState.ContentID)
		}
	}

	// derive CID
	_, _, operationCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive CID: %w", err)
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
// Beacon verification
// -----------------------------------------------------------------------------

const maxBeaconFuture = 5 * time.Minute

// VerifyBeacon verifies a beacon JWS — signature, CID, payload schema,
// clock skew.
func VerifyBeacon(jwsToken string, resolveKey KeyResolver) (*VerifiedBeaconResult, error) {
	return VerifyBeaconAt(jwsToken, resolveKey, time.Now())
}

// VerifyBeaconAt is like VerifyBeacon but accepts a custom current time for testing.
func VerifyBeaconAt(jwsToken string, resolveKey KeyResolver, now time.Time) (*VerifiedBeaconResult, error) {
	header, payload, err := DecodeJWSUnsafe(jwsToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode beacon JWS")
	}

	// validate payload
	if payloadString(payload, "type") != "beacon" {
		return nil, fmt.Errorf("invalid beacon payload: wrong type")
	}
	beaconDID := payloadString(payload, "did")
	if beaconDID == "" {
		return nil, fmt.Errorf("invalid beacon payload: missing did")
	}
	manifestContentId := payloadString(payload, "manifestContentId")
	if len(manifestContentId) != contentIDLength {
		return nil, fmt.Errorf("invalid beacon payload: manifestContentId must be a 22-character content ID")
	}
	createdAt := payloadString(payload, "createdAt")
	if err := validateCreatedAt(createdAt); err != nil {
		return nil, fmt.Errorf("invalid beacon payload: %w", err)
	}

	// verify typ
	if header.Typ != "did:dfos:beacon" {
		return nil, fmt.Errorf("invalid beacon typ: %s", header.Typ)
	}

	// verify kid DID matches payload did
	kid := header.Kid
	hashIdx := strings.Index(kid, "#")
	if hashIdx < 0 {
		return nil, fmt.Errorf("beacon kid must be a DID URL")
	}
	kidDid := kid[:hashIdx]
	if kidDid != beaconDID {
		return nil, fmt.Errorf("beacon kid DID does not match payload did")
	}

	// verify signature
	publicKey, err := resolveKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve beacon key: %w", err)
	}
	if _, _, err := VerifyJWS(jwsToken, publicKey); err != nil {
		return nil, fmt.Errorf("invalid beacon signature")
	}

	// verify CID
	_, _, beaconCID, err := DagCborCID(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to derive beacon CID: %w", err)
	}
	if header.CID == "" {
		return nil, fmt.Errorf("missing cid in beacon header")
	}
	if header.CID != beaconCID {
		return nil, fmt.Errorf("beacon cid mismatch")
	}

	// clock skew check
	beaconTime, err := time.Parse(protocolTimeFormat, createdAt)
	if err != nil {
		return nil, fmt.Errorf("invalid beacon createdAt: %w", err)
	}
	if beaconTime.After(now.Add(maxBeaconFuture)) {
		return nil, fmt.Errorf("beacon createdAt is too far in the future")
	}

	return &VerifiedBeaconResult{
		BeaconCID:         beaconCID,
		DID:               beaconDID,
		ManifestContentId: manifestContentId,
		CreatedAt:         createdAt,
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
	}, nil
}
