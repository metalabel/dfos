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
