package relay

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ---------------------------------------------------------------------------
// classification
// ---------------------------------------------------------------------------

type classifiedOp struct {
	jwsToken      string
	kind          string // identity-op, content-op, beacon, countersign, artifact, unknown
	referencedDID string // DID referenced in the operation
	signerDID     string // for content ops: payload.did
	priority      int    // sort bucket: identity=0, beacon/artifact=1, content=2, countersign=3
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

	case "did:dfos:beacon":
		base.kind = "beacon"
		base.priority = 1
		base.previousCID = "" // beacons have no chaining
		if did, ok := payload["did"].(string); ok {
			base.referencedDID = did
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
		base.priority = 1 // same as beacons
		base.previousCID = "" // artifacts have no chaining
		if did, ok := payload["did"].(string); ok {
			base.referencedDID = did
		}
		return base
	}

	return unknown
}

// ---------------------------------------------------------------------------
// key resolution
// ---------------------------------------------------------------------------

// CreateKeyResolver returns a KeyResolver that searches all keys ever in an
// identity chain log — including rotated-out keys. Used for protocol
// verification during ingestion.
func CreateKeyResolver(store Store) dfos.KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		hashIdx := strings.Index(kid, "#")
		if hashIdx < 0 {
			return nil, fmt.Errorf("kid must be a DID URL: %s", kid)
		}
		did := kid[:hashIdx]
		keyID := kid[hashIdx+1:]

		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return nil, fmt.Errorf("unknown identity: %s", did)
		}

		// fast path: check current state
		allKeys := make([]dfos.MultikeyPublicKey, 0, len(identity.State.AuthKeys)+len(identity.State.AssertKeys)+len(identity.State.ControllerKeys))
		allKeys = append(allKeys, identity.State.AuthKeys...)
		allKeys = append(allKeys, identity.State.AssertKeys...)
		allKeys = append(allKeys, identity.State.ControllerKeys...)
		for _, k := range allKeys {
			if k.ID == keyID {
				return dfos.DecodeMultikey(k.PublicKeyMultibase)
			}
		}

		// slow path: search historical keys from the identity chain log
		for _, token := range identity.Log {
			_, payload, err := dfos.DecodeJWSUnsafe(token)
			if err != nil {
				continue
			}
			opType, _ := payload["type"].(string)
			if opType != "create" && opType != "update" {
				continue
			}
			for _, arrayName := range []string{"authKeys", "assertKeys", "controllerKeys"} {
				keys, ok := payload[arrayName].([]any)
				if !ok {
					continue
				}
				for _, k := range keys {
					km, ok := k.(map[string]any)
					if !ok {
						continue
					}
					id, _ := km["id"].(string)
					if id != keyID {
						continue
					}
					multibase, _ := km["publicKeyMultibase"].(string)
					if multibase == "" {
						continue
					}
					return dfos.DecodeMultikey(multibase)
				}
			}
		}

		return nil, fmt.Errorf("unknown key %s on identity %s", keyID, did)
	}
}

// CreateCurrentKeyResolver returns a KeyResolver that only resolves
// current-state keys. Used for live auth — rotated-out keys are rejected.
func CreateCurrentKeyResolver(store Store) dfos.KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		hashIdx := strings.Index(kid, "#")
		if hashIdx < 0 {
			return nil, fmt.Errorf("kid must be a DID URL: %s", kid)
		}
		did := kid[:hashIdx]
		keyID := kid[hashIdx+1:]

		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return nil, err
		}
		if identity == nil {
			return nil, fmt.Errorf("unknown identity: %s", did)
		}

		allKeys := make([]dfos.MultikeyPublicKey, 0, len(identity.State.AuthKeys)+len(identity.State.AssertKeys)+len(identity.State.ControllerKeys))
		allKeys = append(allKeys, identity.State.AuthKeys...)
		allKeys = append(allKeys, identity.State.AssertKeys...)
		allKeys = append(allKeys, identity.State.ControllerKeys...)
		for _, k := range allKeys {
			if k.ID == keyID {
				return dfos.DecodeMultikey(k.PublicKeyMultibase)
			}
		}

		return nil, fmt.Errorf("unknown key %s on identity %s", keyID, did)
	}
}

// ---------------------------------------------------------------------------
// individual verifiers
// ---------------------------------------------------------------------------

func ingestIdentityOp(jwsToken string, store Store) IngestionResult {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return IngestionResult{Status: "rejected", Error: "failed to decode JWS"}
	}

	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: "failed to compute CID"}
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
		store.PutIdentityChain(chain)
		store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: result.State.DID})
		store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "identity-op", ChainID: result.State.DID})
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
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown identity: %s", did)}
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
		store.PutIdentityChain(updated)
		store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: did})
		store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "identity-op", ChainID: did})
		return IngestionResult{CID: cid, Status: "new", Kind: "identity-op", ChainID: did}
	}

	// fork path — check if previousCID exists in chain ops
	if previousCID == "" || !chainLogContainsCID(chain.Log, previousCID) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in identity chain"}
	}

	forkState, err := store.GetIdentityStateAtCID(did, previousCID)
	if err != nil || forkState == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: "failed to compute state at fork point"}
	}

	extResult, err := dfos.VerifyIdentityExtension(forkState.State, previousCID, forkState.LastCreatedAt, jwsToken)
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
	}

	updatedLog := append(append([]string{}, chain.Log...), jwsToken)
	head := selectDeterministicHead(updatedLog)

	headState := chain.State
	headLastCreatedAt := chain.LastCreatedAt
	headCID := chain.HeadCID

	if head.cid == cid {
		headState = extResult.State
		headLastCreatedAt = extResult.LastCreatedAt
		headCID = cid
	} else {
		headCID = head.cid
		headLastCreatedAt = head.createdAt
	}

	updated := StoredIdentityChain{
		DID:           chain.DID,
		Log:           updatedLog,
		HeadCID:       headCID,
		LastCreatedAt: headLastCreatedAt,
		State:         headState,
	}
	store.PutIdentityChain(updated)
	store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "identity", ChainID: did})
	store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "identity-op", ChainID: did})
	return IngestionResult{CID: cid, Status: "new", Kind: "identity-op", ChainID: did}
}

func ingestContentOp(jwsToken string, store Store) IngestionResult {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return IngestionResult{Status: "rejected", Error: "failed to decode JWS"}
	}

	_, _, cid, err := dfos.DagCborCID(payload)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: "failed to compute CID"}
	}

	// idempotent
	existing, _ := store.GetOperation(cid)
	if existing != nil {
		if existing.JWSToken != jwsToken {
			return IngestionResult{CID: cid, Status: "rejected", Error: "operation already exists with a different signature"}
		}
		return IngestionResult{CID: cid, Status: "duplicate", Kind: "content-op", ChainID: existing.ChainID}
	}

	// reject content ops from deleted identities
	signerDID, _ := payload["did"].(string)
	if signerDID != "" {
		signerIdentity, _ := store.GetIdentityChain(signerDID)
		if signerIdentity != nil && signerIdentity.State.IsDeleted {
			return IngestionResult{CID: cid, Status: "rejected", Error: "signer identity is deleted"}
		}
	}

	resolveKey := CreateKeyResolver(store)
	opType, _ := payload["type"].(string)
	isGenesis := opType == "create"

	if isGenesis {
		result, err := dfos.VerifyContentChain([]string{jwsToken}, resolveKey, true)
		if err != nil {
			return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
		}
		createdAt, _ := payload["createdAt"].(string)
		chain := StoredContentChain{
			ContentID:     result.State.ContentID,
			GenesisCID:    result.State.GenesisCID,
			Log:           []string{jwsToken},
			LastCreatedAt: createdAt,
			State:         result.State,
		}
		store.PutContentChain(chain)
		store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: result.State.ContentID})
		store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "content-op", ChainID: result.State.ContentID})
		return IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: result.State.ContentID}
	}

	// extension — find chain via previousOperationCID
	previousCID, ok := payload["previousOperationCID"].(string)
	if !ok || previousCID == "" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "missing previousOperationCID"}
	}

	prevOp, _ := store.GetOperation(previousCID)
	if prevOp == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown previous operation: %s", previousCID)}
	}
	if prevOp.ChainType != "content" {
		return IngestionResult{CID: cid, Status: "rejected", Error: "previousOperationCID is not a content operation"}
	}

	chain, _ := store.GetContentChain(prevOp.ChainID)
	if chain == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("content chain not found: %s", prevOp.ChainID)}
	}

	// reject if creator's identity is deleted
	creatorIdentity, _ := store.GetIdentityChain(chain.State.CreatorDID)
	if creatorIdentity != nil && creatorIdentity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "content creator identity is deleted"}
	}

	if chain.State.HeadCID == previousCID {
		// linear extension (fast path)
		extResult, err := dfos.VerifyContentExtension(chain.State, chain.LastCreatedAt, jwsToken, resolveKey, true)
		if err != nil {
			return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
		}
		updated := StoredContentChain{
			ContentID:     chain.ContentID,
			GenesisCID:    chain.GenesisCID,
			Log:           append(append([]string{}, chain.Log...), jwsToken),
			LastCreatedAt: extResult.LastCreatedAt,
			State:         extResult.State,
		}
		store.PutContentChain(updated)
		store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: chain.ContentID})
		store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "content-op", ChainID: chain.ContentID})
		return IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: chain.ContentID}
	}

	// fork path — check if previousCID exists in chain ops
	if !chainLogContainsCID(chain.Log, previousCID) {
		return IngestionResult{CID: cid, Status: "rejected", Error: "unknown previous operation in content chain"}
	}

	forkState, err := store.GetContentStateAtCID(chain.ContentID, previousCID)
	if err != nil || forkState == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: "failed to compute state at fork point"}
	}

	extResult, err := dfos.VerifyContentExtension(forkState.State, forkState.LastCreatedAt, jwsToken, resolveKey, true)
	if err != nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: err.Error()}
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
	store.PutContentChain(updated)
	store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "content", ChainID: chain.ContentID})
	store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "content-op", ChainID: chain.ContentID})
	return IngestionResult{CID: cid, Status: "new", Kind: "content-op", ChainID: chain.ContentID}
}

func ingestBeacon(jwsToken string, store Store) IngestionResult {
	resolveKey := CreateKeyResolver(store)

	result, err := dfos.VerifyBeacon(jwsToken, resolveKey)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: err.Error()}
	}

	did := result.DID
	cid := result.BeaconCID

	// reject beacons from deleted identities
	identity, _ := store.GetIdentityChain(did)
	if identity != nil && identity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "identity is deleted"}
	}

	// replace-on-newer: only store if this beacon is more recent
	existing, _ := store.GetBeacon(did)
	if existing != nil {
		existingTime, _ := time.Parse(time.RFC3339Nano, existing.Payload.CreatedAt)
		newTime, _ := time.Parse(time.RFC3339Nano, result.CreatedAt)
		if !newTime.After(existingTime) {
			return IngestionResult{CID: cid, Status: "duplicate", Kind: "beacon", ChainID: did}
		}
	}

	beacon := StoredBeacon{
		DID:       did,
		JWSToken:  jwsToken,
		BeaconCID: cid,
		Payload: BeaconPayload{
			Version:    1,
			Type:       "beacon",
			DID:        did,
			MerkleRoot: result.MerkleRoot,
			CreatedAt:  result.CreatedAt,
		},
	}
	store.PutBeacon(beacon)
	store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "beacon", ChainID: did})
	store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "beacon", ChainID: did})
	return IngestionResult{CID: cid, Status: "new", Kind: "beacon", ChainID: did}
}

func ingestCountersign(jwsToken string, store Store) IngestionResult {
	resolveKey := CreateKeyResolver(store)

	result, err := dfos.VerifyCountersignature(jwsToken, resolveKey)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: err.Error()}
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

	// target must exist
	targetOp, _ := store.GetOperation(targetCID)
	if targetOp == nil {
		return IngestionResult{CID: cid, Status: "rejected", Error: fmt.Sprintf("unknown target operation: %s", targetCID)}
	}

	// witness must differ from target author
	var targetAuthorDID string
	if targetOp.ChainType == "identity" {
		targetAuthorDID = targetOp.ChainID
	} else {
		targetDecoded, _, err := dfos.DecodeJWSUnsafe(targetOp.JWSToken)
		if err == nil && targetDecoded != nil {
			// extract did from payload
			_, targetPayload, _ := dfos.DecodeJWSUnsafe(targetOp.JWSToken)
			if d, ok := targetPayload["did"].(string); ok {
				targetAuthorDID = d
			}
		}
	}

	if targetAuthorDID != "" && witnessDID == targetAuthorDID {
		return IngestionResult{CID: cid, Status: "rejected", Error: "witness DID must differ from target author DID"}
	}

	// reject countersigns from deleted witnesses
	witnessIdentity, _ := store.GetIdentityChain(witnessDID)
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

	store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "countersign", ChainID: targetCID})
	store.AddCountersignature(targetCID, jwsToken)
	store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "countersign", ChainID: targetCID})
	return IngestionResult{CID: cid, Status: "new", Kind: "countersign", ChainID: targetCID}
}

func ingestArtifact(jwsToken string, store Store) IngestionResult {
	resolveKey := CreateKeyResolver(store)

	result, err := dfos.VerifyArtifact(jwsToken, resolveKey)
	if err != nil {
		return IngestionResult{Status: "rejected", Error: err.Error()}
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

	// reject artifacts from deleted identities
	identity, _ := store.GetIdentityChain(did)
	if identity != nil && identity.State.IsDeleted {
		return IngestionResult{CID: cid, Status: "rejected", Error: "identity is deleted"}
	}

	store.PutOperation(StoredOperation{CID: cid, JWSToken: jwsToken, ChainType: "artifact", ChainID: did})
	store.AppendToLog(LogEntry{CID: cid, JWSToken: jwsToken, Kind: "artifact", ChainID: did})
	return IngestionResult{CID: cid, Status: "new", Kind: "artifact", ChainID: did}
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

// IngestOperations classifies, dependency-sorts, and processes a batch of JWS
// tokens. Returns results in the original submission order.
func IngestOperations(tokens []string, store Store) []IngestionResult {
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

	for _, op := range sorted {
		var result IngestionResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					result = IngestionResult{Status: "rejected", Error: fmt.Sprintf("unexpected error: %v", r)}
				}
			}()
			switch op.kind {
			case "identity-op":
				result = ingestIdentityOp(op.jwsToken, store)
			case "content-op":
				result = ingestContentOp(op.jwsToken, store)
			case "beacon":
				result = ingestBeacon(op.jwsToken, store)
			case "countersign":
				result = ingestCountersign(op.jwsToken, store)
			case "artifact":
				result = ingestArtifact(op.jwsToken, store)
			default:
				result = IngestionResult{Status: "rejected", Error: "unrecognized operation type"}
			}
		}()
		results = append(results, indexedResult{index: op.originalIndex, result: result})
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
