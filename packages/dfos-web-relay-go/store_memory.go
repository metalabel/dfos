package relay

import (
	"sort"
	"strings"
	"sync"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// MemoryStore is an in-memory Store implementation for development and testing.
type MemoryStore struct {
	mu                sync.RWMutex
	operations        map[string]StoredOperation
	identityChains    map[string]StoredIdentityChain
	contentChains     map[string]StoredContentChain
	blobs             map[string][]byte
	countersignatures map[string][]string
	operationLog      []LogEntry
	peerCursors       map[string]string
	rawOps            map[string]rawOpEntry             // cid → entry
	revocations       map[string]StoredRevocation       // key: "issuerDID::credentialCID"
	publicCredentials map[string]StoredPublicCredential // key: credential CID
	// --- index (v0) materialized projection rows ---
	indexIdentityRows    map[string]indexIdentityRow            // keyed by DID
	indexContentRows     map[string]indexContentRow             // keyed by contentId
	indexCountersignRows map[string]storedIndexCountersignature // keyed by cid (carry witness_did)
}

type rawOpEntry struct {
	jwsToken string
	status   string // "pending", "sequenced", "rejected"
}

// NewMemoryStore creates a new empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		operations:        make(map[string]StoredOperation),
		identityChains:    make(map[string]StoredIdentityChain),
		contentChains:     make(map[string]StoredContentChain),
		blobs:             make(map[string][]byte),
		countersignatures: make(map[string][]string),
		peerCursors:       make(map[string]string),
		rawOps:            make(map[string]rawOpEntry),
		revocations:       make(map[string]StoredRevocation),
		publicCredentials: make(map[string]StoredPublicCredential),

		indexIdentityRows:    make(map[string]indexIdentityRow),
		indexContentRows:     make(map[string]indexContentRow),
		indexCountersignRows: make(map[string]storedIndexCountersignature),
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

func (s *MemoryStore) ListIdentityChains() ([]StoredIdentityChain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chains := make([]StoredIdentityChain, 0, len(s.identityChains))
	for _, chain := range s.identityChains {
		chains = append(chains, chain)
	}
	return chains, nil
}

func (s *MemoryStore) ListContentChains() ([]StoredContentChain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chains := make([]StoredContentChain, 0, len(s.contentChains))
	for _, chain := range s.contentChains {
		chains = append(chains, chain)
	}
	return chains, nil
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

func (s *MemoryStore) DeleteBlob(key BlobKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, blobKeyStr(key)) // idempotent: deleting a missing key is a no-op
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

// ListCountersignatures enumerates every stored countersignature (all
// witnesses), sorted by CID. Used ONLY by the index-projection rebuild path.
func (s *MemoryStore) ListCountersignatures() ([]StoredCountersignature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []StoredCountersignature{}
	for targetCID, tokens := range s.countersignatures {
		for _, token := range tokens {
			row := countersignatureFromToken(targetCID, token)
			if row == nil {
				continue
			}
			rows = append(rows, *row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CID < rows[j].CID })
	return rows, nil
}

// ---------------------------------------------------------------------------
// index (v0) materialized projection
// ---------------------------------------------------------------------------

// pageIndexRows sorts rows ascending by keyOf, gates strictly greater than after
// (keyset semantics — deterministic and resumable even when the cursor row was
// mutated or filtered out between pages), and caps at limit. Bytewise string
// order over ASCII DIDs/CIDs == the SQL BINARY-collation twin.
func pageIndexRows[T any](rows []T, keyOf func(T) string, after string, limit int) []T {
	sort.Slice(rows, func(i, j int) bool { return keyOf(rows[i]) < keyOf(rows[j]) })
	out := []T{}
	for _, row := range rows {
		if after != "" && keyOf(row) <= after {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *MemoryStore) QueryIndexIdentities(q IndexIdentityQuery) ([]indexIdentityRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]indexIdentityRow, 0, len(s.indexIdentityRows))
	for _, row := range s.indexIdentityRows {
		if q.HasPublicProfile != nil {
			isPublic := row.Profile != nil && row.Profile.PublicRead
			if isPublic != *q.HasPublicProfile {
				continue
			}
		}
		rows = append(rows, row)
	}
	return pageIndexRows(rows, func(row indexIdentityRow) string { return row.DID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexContent(q IndexContentQuery) ([]indexContentRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]indexContentRow, 0, len(s.indexContentRows))
	for _, row := range s.indexContentRows {
		if q.Creator != "" && row.CreatorDID != q.Creator {
			continue
		}
		if q.DocSchema != nil && (row.DocSchema == nil || *row.DocSchema != *q.DocSchema) {
			continue
		}
		if q.DocumentCID != nil && (row.CurrentDocumentCID == nil || *row.CurrentDocumentCID != *q.DocumentCID) {
			continue
		}
		if q.PublicRead != nil && row.PublicRead != *q.PublicRead {
			continue
		}
		rows = append(rows, row)
	}
	return pageIndexRows(rows, func(row indexContentRow) string { return row.ContentID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]indexCountersignatureRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []indexCountersignatureRow{}
	for _, row := range s.indexCountersignRows {
		if row.WitnessDID != q.Witness {
			continue
		}
		// Strip the witness_did column — the wire row never carries it (the witness
		// is echoed at the response top level).
		rows = append(rows, indexCountersignatureRow{
			CID:       row.CID,
			TargetCID: row.TargetCID,
			Relation:  row.Relation,
			JWSToken:  row.JWSToken,
		})
	}
	return pageIndexRows(rows, func(row indexCountersignatureRow) string { return row.CID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexCredentials(q IndexCredentialQuery) ([]indexCredentialRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []indexCredentialRow{}
	for _, cred := range s.publicCredentials {
		if q.Issuer != "" && cred.IssuerDID != q.Issuer {
			continue
		}
		if q.Resource != nil {
			found := false
			for _, att := range cred.Att {
				if att.Resource == *q.Resource {
					found = true
					break
				}
				if strings.HasPrefix(*q.Resource, "chain:") && att.Resource == "chain:*" {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		rows = append(rows, indexCredentialRow{
			CID:       cred.CID,
			IssuerDID: cred.IssuerDID,
			Att:       cred.Att,
			Exp:       cred.Exp,
			JWSToken:  cred.JWSToken,
		})
	}
	return pageIndexRows(rows, func(row indexCredentialRow) string { return row.CID }, q.After, q.Limit), nil
}

func (s *MemoryStore) PutIndexIdentityRow(row indexIdentityRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indexIdentityRows[row.DID] = row
	return nil
}

func (s *MemoryStore) PutIndexContentRow(row indexContentRow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indexContentRows[row.ContentID] = row
	return nil
}

func (s *MemoryStore) PutIndexCountersignatureRow(row storedIndexCountersignature) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indexCountersignRows[row.CID] = row
	return nil
}

func (s *MemoryStore) GetIndexIdentityDIDsByProfileAnchor(contentID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dids := []string{}
	for _, row := range s.indexIdentityRows {
		if row.Profile != nil && row.Profile.Anchor == contentID {
			dids = append(dids, row.DID)
		}
	}
	return dids, nil
}

func (s *MemoryStore) GetIndexContentIDsByDocumentCID(documentCID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	contentIds := []string{}
	for _, row := range s.indexContentRows {
		if row.CurrentDocumentCID != nil && *row.CurrentDocumentCID == documentCID {
			contentIds = append(contentIds, row.ContentID)
		}
	}
	return contentIds, nil
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

	// Return a resume cursor whenever the page has entries (not only when full), so
	// a caught-up puller advances past the final partial page instead of re-fetching
	// the tail every cycle. Mirrors SQLiteStore.ReadLog.
	var cursor string
	if len(result) > 0 {
		cursor = result[len(result)-1].CID
	}

	return result, cursor, nil
}

func (s *MemoryStore) RelayStats() (*RelayStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	opCount := len(s.operationLog)
	counts := newKindCounts()
	for _, e := range s.operationLog {
		if b := kindBucket(e.Kind); b != "" {
			counts[b]++
		}
	}

	var headCID *string
	var oldestOpAt *string
	if opCount > 0 {
		head := s.operationLog[opCount-1].CID
		headCID = &head

		_, payload, err := dfos.DecodeJWSUnsafe(s.operationLog[0].JWSToken)
		if err == nil {
			if createdAt, ok := payload["createdAt"].(string); ok {
				oldestOpAt = &createdAt
			}
		}
	}

	return &RelayStats{
		OpCount:      opCount,
		CountsByKind: counts,
		OldestOpAt:   oldestOpAt,
		HeadCID:      headCID,
	}, nil
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

func (s *MemoryStore) PutRawOp(cid string, jwsToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rawOps[cid]; !exists {
		s.rawOps[cid] = rawOpEntry{jwsToken: jwsToken, status: "pending"}
	}
	return nil
}

func (s *MemoryStore) GetUnsequencedOps(limit int) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, entry := range s.rawOps {
		if entry.status == "pending" {
			out = append(out, entry.jwsToken)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *MemoryStore) MarkOpsSequenced(cids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cid := range cids {
		if entry, ok := s.rawOps[cid]; ok {
			entry.status = "sequenced"
			s.rawOps[cid] = entry
		}
	}
	return nil
}

func (s *MemoryStore) MarkOpRejected(cid string, reason string) error {
	// Permanently drop the raw op — see SQLiteStore.MarkOpRejected. Rejected ops
	// have no recovery value and keeping them is an unbounded-growth vector.
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rawOps, cid)
	return nil
}

func (s *MemoryStore) CountUnsequenced() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, entry := range s.rawOps {
		if entry.status == "pending" {
			count++
		}
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// revocations
// ---------------------------------------------------------------------------

func (s *MemoryStore) GetRevocations(issuerDID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var cids []string
	for _, rev := range s.revocations {
		if rev.IssuerDID == issuerDID {
			cids = append(cids, rev.CredentialCID)
		}
	}
	if cids == nil {
		return []string{}, nil
	}
	return cids, nil
}

func (s *MemoryStore) AddRevocation(revocation StoredRevocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := revocation.IssuerDID + "::" + revocation.CredentialCID
	s.revocations[key] = revocation
	return nil
}

func (s *MemoryStore) IsCredentialRevoked(issuerDID string, credentialCID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := issuerDID + "::" + credentialCID
	_, ok := s.revocations[key]
	return ok, nil
}

func (s *MemoryStore) GetRevocationForCredential(credentialCID string) (*StoredRevocation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// deterministic across stores/twins: smallest issuerDID wins on a
	// (theoretical) multi-issuer collision
	var found *StoredRevocation
	for _, rev := range s.revocations {
		if rev.CredentialCID != credentialCID {
			continue
		}
		if found == nil || rev.IssuerDID < found.IssuerDID {
			r := rev
			found = &r
		}
	}
	return found, nil
}

func (s *MemoryStore) GetRevocationsByIssuer(issuerDID string) ([]StoredRevocation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type revocationWithCreatedAt struct {
		revocation StoredRevocation
		createdAt  string
	}
	revs := []revocationWithCreatedAt{}
	for _, rev := range s.revocations {
		if rev.IssuerDID != issuerDID {
			continue
		}
		createdAt := ""
		if _, payload, err := dfos.DecodeJWSUnsafe(rev.JWSToken); err == nil {
			if value, ok := payload["createdAt"].(string); ok {
				createdAt = value
			}
		}
		revs = append(revs, revocationWithCreatedAt{revocation: rev, createdAt: createdAt})
	}
	sort.Slice(revs, func(i, j int) bool {
		if revs[i].createdAt != revs[j].createdAt {
			return revs[i].createdAt < revs[j].createdAt
		}
		return revs[i].revocation.CredentialCID < revs[j].revocation.CredentialCID
	})
	result := make([]StoredRevocation, 0, len(revs))
	for _, rev := range revs {
		result = append(result, rev.revocation)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// public credentials (standing authorization)
// ---------------------------------------------------------------------------

func (s *MemoryStore) GetPublicCredentials(resource string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var tokens []string
	for _, cred := range s.publicCredentials {
		for _, att := range cred.Att {
			if att.Resource == resource {
				tokens = append(tokens, cred.JWSToken)
				break
			}
			// chain:* credentials match any chain: resource
			if strings.HasPrefix(resource, "chain:") && att.Resource == "chain:*" {
				tokens = append(tokens, cred.JWSToken)
				break
			}
		}
	}
	if tokens == nil {
		return []string{}, nil
	}
	return tokens, nil
}

func (s *MemoryStore) AddPublicCredential(credential StoredPublicCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicCredentials[credential.CID] = credential
	return nil
}

func (s *MemoryStore) RemovePublicCredential(credentialCID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.publicCredentials, credentialCID)
	return nil
}

func (s *MemoryStore) ResetPeerCursors() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerCursors = make(map[string]string)
	return nil
}

func (s *MemoryStore) ResetSequencer() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for cid, entry := range s.rawOps {
		if entry.status != "rejected" {
			entry.status = "pending"
			s.rawOps[cid] = entry
		}
	}
	return nil
}
