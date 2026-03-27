package relay

import (
	"strings"
	"sync"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// MemoryStore is an in-memory Store implementation for development and testing.
type MemoryStore struct {
	mu               sync.RWMutex
	operations       map[string]StoredOperation
	identityChains   map[string]StoredIdentityChain
	contentChains    map[string]StoredContentChain
	beacons          map[string]StoredBeacon
	blobs            map[string][]byte
	countersignatures map[string][]string
	operationLog     []LogEntry
	peerCursors      map[string]string
}

// NewMemoryStore creates a new empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		operations:       make(map[string]StoredOperation),
		identityChains:   make(map[string]StoredIdentityChain),
		contentChains:    make(map[string]StoredContentChain),
		beacons:          make(map[string]StoredBeacon),
		blobs:            make(map[string][]byte),
		countersignatures: make(map[string][]string),
		peerCursors:      make(map[string]string),
	}
}

func blobKeyStr(key BlobKey) string {
	return key.CreatorDID + "::" + key.DocumentCID
}

func (s *MemoryStore) GetOperation(cid string) (*StoredOperation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	op, ok := s.operations[cid]
	if !ok {
		return nil, nil
	}
	return &op, nil
}

func (s *MemoryStore) PutOperation(op StoredOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operations[op.CID] = op
	return nil
}

func (s *MemoryStore) GetIdentityChain(did string) (*StoredIdentityChain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chain, ok := s.identityChains[did]
	if !ok {
		return nil, nil
	}
	return &chain, nil
}

func (s *MemoryStore) PutIdentityChain(chain StoredIdentityChain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identityChains[chain.DID] = chain
	return nil
}

func (s *MemoryStore) GetContentChain(contentID string) (*StoredContentChain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chain, ok := s.contentChains[contentID]
	if !ok {
		return nil, nil
	}
	return &chain, nil
}

func (s *MemoryStore) PutContentChain(chain StoredContentChain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contentChains[chain.ContentID] = chain
	return nil
}

func (s *MemoryStore) GetBeacon(did string) (*StoredBeacon, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	beacon, ok := s.beacons[did]
	if !ok {
		return nil, nil
	}
	return &beacon, nil
}

func (s *MemoryStore) PutBeacon(beacon StoredBeacon) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beacons[beacon.DID] = beacon
	return nil
}

func (s *MemoryStore) GetBlob(key BlobKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blobs[blobKeyStr(key)]
	if !ok {
		return nil, nil
	}
	return data, nil
}

func (s *MemoryStore) PutBlob(key BlobKey, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[blobKeyStr(key)] = data
	return nil
}

func (s *MemoryStore) GetCountersignatures(operationCID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cs := s.countersignatures[operationCID]
	if cs == nil {
		return []string{}, nil
	}
	return cs, nil
}

func (s *MemoryStore) AddCountersignature(operationCID string, jwsToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing := s.countersignatures[operationCID]

	// dedup by witness DID (kid DID prefix)
	header, _, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err == nil && header != nil {
		kid := header.Kid
		witnessDID := kid
		if idx := strings.Index(kid, "#"); idx >= 0 {
			witnessDID = kid[:idx]
		}
		for _, cs := range existing {
			h, _, err := dfos.DecodeJWSUnsafe(cs)
			if err != nil || h == nil {
				continue
			}
			existingDID := h.Kid
			if idx := strings.Index(h.Kid, "#"); idx >= 0 {
				existingDID = h.Kid[:idx]
			}
			if existingDID == witnessDID {
				return nil // same witness, dedup
			}
		}
	}

	s.countersignatures[operationCID] = append(existing, jwsToken)
	return nil
}

func (s *MemoryStore) AppendToLog(entry LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operationLog = append(s.operationLog, entry)
	return nil
}

func (s *MemoryStore) ReadLog(after string, limit int) ([]LogEntry, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	startIdx := 0
	if after != "" {
		found := false
		for i, e := range s.operationLog {
			if e.CID == after {
				startIdx = i + 1
				found = true
				break
			}
		}
		if !found {
			startIdx = len(s.operationLog) // cursor not found → empty
		}
	}

	end := startIdx + limit
	if end > len(s.operationLog) {
		end = len(s.operationLog)
	}

	entries := s.operationLog[startIdx:end]
	result := make([]LogEntry, len(entries))
	copy(result, entries)

	var cursor string
	if len(result) == limit {
		cursor = result[len(result)-1].CID
	}

	return result, cursor, nil
}

func (s *MemoryStore) GetIdentityStateAtCID(did, cid string) (*IdentityStateAtCID, error) {
	s.mu.RLock()
	chain, ok := s.identityChains[did]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	// build CID → {jws, previousCID} map
	type opInfo struct {
		jws         string
		previousCID string
	}
	opsByCID := make(map[string]opInfo)
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		opCID := header.CID
		prevCID, _ := payload["previousOperationCID"].(string)
		opsByCID[opCID] = opInfo{jws: jws, previousCID: prevCID}
	}

	if _, ok := opsByCID[cid]; !ok {
		return nil, nil
	}

	// walk backward from target CID to genesis
	var path []string
	currentCID := cid
	for currentCID != "" {
		op, ok := opsByCID[currentCID]
		if !ok {
			return nil, nil
		}
		path = append([]string{op.jws}, path...)
		currentCID = op.previousCID
	}

	result, err := dfos.VerifyIdentityChain(path)
	if err != nil {
		return nil, err
	}

	// extract createdAt of the target CID
	targetOp := opsByCID[cid]
	_, targetPayload, _ := dfos.DecodeJWSUnsafe(targetOp.jws)
	lastCreatedAt, _ := targetPayload["createdAt"].(string)

	return &IdentityStateAtCID{State: result.State, LastCreatedAt: lastCreatedAt}, nil
}

func (s *MemoryStore) GetContentStateAtCID(contentID, cid string) (*ContentStateAtCID, error) {
	s.mu.RLock()
	chain, ok := s.contentChains[contentID]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	type opInfo struct {
		jws         string
		previousCID string
	}
	opsByCID := make(map[string]opInfo)
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		opCID := header.CID
		prevCID, _ := payload["previousOperationCID"].(string)
		opsByCID[opCID] = opInfo{jws: jws, previousCID: prevCID}
	}

	if _, ok := opsByCID[cid]; !ok {
		return nil, nil
	}

	var path []string
	currentCID := cid
	for currentCID != "" {
		op, ok := opsByCID[currentCID]
		if !ok {
			return nil, nil
		}
		path = append([]string{op.jws}, path...)
		currentCID = op.previousCID
	}

	resolveKey := CreateKeyResolver(s)
	result, err := dfos.VerifyContentChain(path, resolveKey, true)
	if err != nil {
		return nil, err
	}

	targetOp := opsByCID[cid]
	_, targetPayload, _ := dfos.DecodeJWSUnsafe(targetOp.jws)
	lastCreatedAt, _ := targetPayload["createdAt"].(string)

	return &ContentStateAtCID{State: result.State, LastCreatedAt: lastCreatedAt}, nil
}

func (s *MemoryStore) GetPeerCursor(peerURL string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerCursors[peerURL], nil
}

func (s *MemoryStore) SetPeerCursor(peerURL string, cursor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerCursors[peerURL] = cursor
	return nil
}
