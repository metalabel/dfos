package relay

import (
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

type signingCursor struct {
	SubjectDID  string
	DepositedAt string
	CID         string
}

func encodeSigningCursor(cursor signingCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursor.SubjectDID + "|" + cursor.DepositedAt + "|" + cursor.CID))
}

func decodeSigningCursor(encoded string) (signingCursor, bool) {
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(bytes) != encoded {
		return signingCursor{}, false
	}
	decoded := string(bytes)
	if strings.Count(decoded, "|") != 2 {
		return signingCursor{}, false
	}
	parts := strings.SplitN(decoded, "|", 3)
	depositedAt, err := time.Parse(signingTimeFormat, parts[1])
	if err != nil || parts[0] == "" || depositedAt.UTC().Format(signingTimeFormat) != parts[1] || parts[2] == "" {
		return signingCursor{}, false
	}
	return signingCursor{SubjectDID: parts[0], DepositedAt: parts[1], CID: parts[2]}, true
}

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
	signRequests      map[string]StoredSignRequest      // key: request CID
	// --- index (v0) materialized projection rows ---
	indexIdentityRows    map[string]IndexIdentityRow            // keyed by DID
	indexContentRows     map[string]IndexContentRow             // keyed by contentId
	indexCreditRows      map[string][]IndexCreditRow            // grouped by contentId
	indexContentSigners  map[string]map[string]struct{}         // contentId → signer DID set
	indexIdentityKeys    map[string]map[string]struct{}         // DID → has-ever-proved public key set
	indexCountersignRows map[string]StoredIndexCountersignature // keyed by cid (carry witness_did)
	indexOperationRows   map[string]IndexOperationRow           // keyed by operation cid
	// operation cid → the multibase public key its signature verified against at
	// ingest. Held beside the row rather than on it because the row IS the wire
	// shape /index/v0/operations serves, and signerKey is a filter, never a field.
	// A CID absent here never resolved, and matches no signerKey= value.
	indexOperationSignerKeys map[string]string
	indexArtifactRows        map[string]IndexArtifactRow // keyed by artifact cid
	// indexCursor is the projection worker's persisted position (log cursor +
	// any outstanding resumable sweep). Ephemeral like the rest of this store.
	indexCursor IndexCursor
}

type rawOpEntry struct {
	jwsToken string
	origin   OpOrigin
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
		signRequests:      make(map[string]StoredSignRequest),

		indexIdentityRows:        make(map[string]IndexIdentityRow),
		indexContentRows:         make(map[string]IndexContentRow),
		indexCreditRows:          make(map[string][]IndexCreditRow),
		indexContentSigners:      make(map[string]map[string]struct{}),
		indexIdentityKeys:        make(map[string]map[string]struct{}),
		indexCountersignRows:     make(map[string]StoredIndexCountersignature),
		indexOperationRows:       make(map[string]IndexOperationRow),
		indexOperationSignerKeys: make(map[string]string),
		indexArtifactRows:        make(map[string]IndexArtifactRow),
	}
}

func (s *MemoryStore) GetSignRequest(cid string, now time.Time) (*StoredSignRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredSignRequestsLocked(now)
	request, ok := s.signRequests[cid]
	if !ok {
		return nil, nil
	}
	request.PayloadBytes = append([]byte(nil), request.PayloadBytes...)
	return &request, nil
}

func (s *MemoryStore) pruneExpiredSignRequestsLocked(now time.Time) {
	for cid, request := range s.signRequests {
		expires, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
		if err != nil || !now.Before(expires) {
			delete(s.signRequests, cid)
		}
	}
}

func (s *MemoryStore) PruneExpiredSignRequests(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredSignRequestsLocked(now)
	return nil
}

func (s *MemoryStore) PutSignRequest(request StoredSignRequest, now time.Time) (SigningPutResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredSignRequestsLocked(now)
	if existing, ok := s.signRequests[request.CID]; ok {
		if existing.Request == request.Request {
			return SigningIdentical, nil
		}
		return SigningConflict, nil
	}
	pending := 0
	for _, existing := range s.signRequests {
		if existing.SubjectDID == request.SubjectDID && existing.Response == "" {
			pending++
		}
	}
	if pending >= MaxPendingSignRequestsPerMailbox {
		return SigningAtCapacity, nil
	}
	request.PayloadBytes = append([]byte(nil), request.PayloadBytes...)
	s.signRequests[request.CID] = request
	return SigningCreated, nil
}

func (s *MemoryStore) ListPendingSignRequests(subjectDID, after string, limit int, now time.Time) ([]StoredSignRequest, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredSignRequestsLocked(now)
	rows := make([]StoredSignRequest, 0)
	for _, request := range s.signRequests {
		if request.SubjectDID != subjectDID || request.Response != "" {
			continue
		}
		request.PayloadBytes = append([]byte(nil), request.PayloadBytes...)
		rows = append(rows, request)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DepositedAt != rows[j].DepositedAt {
			return rows[i].DepositedAt < rows[j].DepositedAt
		}
		return rows[i].CID < rows[j].CID
	})
	start := 0
	if after != "" {
		cursor, ok := decodeSigningCursor(after)
		if !ok || cursor.SubjectDID != subjectDID {
			return nil, "", ErrInvalidSigningCursor
		}
		for start < len(rows) && (rows[start].DepositedAt < cursor.DepositedAt ||
			(rows[start].DepositedAt == cursor.DepositedAt && rows[start].CID <= cursor.CID)) {
			start++
		}
	}
	end := start + limit
	if end > len(rows) {
		end = len(rows)
	}
	page := rows[start:end]
	cursor := ""
	if len(page) == limit && len(page) > 0 {
		last := page[len(page)-1]
		cursor = encodeSigningCursor(signingCursor{SubjectDID: subjectDID, DepositedAt: last.DepositedAt, CID: last.CID})
	}
	return page, cursor, nil
}

func (s *MemoryStore) PutSignResponse(cid, response string, now time.Time) (SigningPutResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredSignRequestsLocked(now)
	request, ok := s.signRequests[cid]
	if !ok {
		return SigningNotFound, nil
	}
	if request.Response != "" {
		if request.Response == response {
			return SigningIdentical, nil
		}
		return SigningConflict, nil
	}
	request.Response = response
	s.signRequests[cid] = request
	return SigningCreated, nil
}

func (s *MemoryStore) DeclineSignRequest(cid string, now time.Time) (SigningPutResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredSignRequestsLocked(now)
	request, ok := s.signRequests[cid]
	if !ok {
		return SigningNotFound, nil
	}
	if request.Response != "" {
		return SigningConflict, nil
	}
	request.Declined = true
	s.signRequests[cid] = request
	return SigningCreated, nil
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

func (s *MemoryStore) putOperationLocked(op StoredOperation) error {
	if op.IngestedAt == "" {
		op.IngestedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
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

func (s *MemoryStore) putIdentityChainLocked(chain StoredIdentityChain) error {
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

func (s *MemoryStore) putContentChainLocked(chain StoredContentChain) error {
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

func (s *MemoryStore) GetBlob(key BlobKey) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blobs[blobKeyStr(key)]
	if !ok {
		return nil, nil
	}
	return data, nil
}

func (s *MemoryStore) putBlobLocked(key BlobKey, data []byte) error {
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

func (s *MemoryStore) addCountersignatureLocked(operationCID string, jwsToken string) error {
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

func pageOrderedIndexRows[T any](rows []T, keyOf func(T) string, timestampOf func(T) string, after *IndexOrderedCursor, limit int) []T {
	sort.Slice(rows, func(i, j int) bool {
		its := timestampOf(rows[i])
		jts := timestampOf(rows[j])
		if its != jts {
			return its > jts
		}
		return keyOf(rows[i]) < keyOf(rows[j])
	})
	out := []T{}
	for _, row := range rows {
		ts := timestampOf(row)
		key := keyOf(row)
		if after != nil && !(ts < after.Timestamp || (ts == after.Timestamp && key > after.Key)) {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *MemoryStore) QueryIndexIdentities(q IndexIdentityQuery) ([]IndexIdentityRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]IndexIdentityRow, 0, len(s.indexIdentityRows))
	for _, row := range s.indexIdentityRows {
		if q.DID != "" && row.DID != q.DID {
			continue
		}
		if q.Key != "" {
			// Has-ever-declared: the set is accumulated per accepted op, so a key a
			// later update rotated out still matches.
			if _, ok := s.indexIdentityKeys[row.DID][q.Key]; !ok {
				continue
			}
		}
		if q.HasPublicProfile != nil {
			isPublic := row.Profile != nil && row.Profile.PublicRead
			if isPublic != *q.HasPublicProfile {
				continue
			}
		}
		if q.NameContains != "" {
			// Match only rows whose name is servable (public) — closes the oracle on
			// any non-public name a pre-gate builder may have persisted.
			if row.Profile == nil || !row.Profile.PublicRead || row.Profile.Name == nil || !strings.Contains(strings.ToLower(*row.Profile.Name), strings.ToLower(q.NameContains)) {
				continue
			}
		}
		rows = append(rows, row)
	}
	if q.Order != "" {
		return pageOrderedIndexRows(rows, func(row IndexIdentityRow) string { return row.DID }, func(row IndexIdentityRow) string {
			if q.Order == "genesisAt.desc" {
				return row.GenesisAt
			}
			return row.HeadAt
		}, q.OrderedAfter, q.Limit), nil
	}
	return pageIndexRows(rows, func(row IndexIdentityRow) string { return row.DID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexContent(q IndexContentQuery) ([]IndexContentRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := make([]IndexContentRow, 0, len(s.indexContentRows))
	for _, row := range s.indexContentRows {
		if q.ContentID != nil && row.ContentID != *q.ContentID {
			continue
		}
		if q.Creator != "" && row.CreatorDID != q.Creator {
			continue
		}
		if q.Signer != "" {
			signers := s.indexContentSigners[row.ContentID]
			if signers == nil {
				continue
			}
			if _, ok := signers[q.Signer]; !ok {
				continue
			}
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
		if q.IsDeleted != nil && row.IsDeleted != *q.IsDeleted {
			continue
		}
		if q.TitleContains != "" {
			if !row.PublicRead || row.Title == nil || !strings.Contains(strings.ToLower(*row.Title), strings.ToLower(q.TitleContains)) {
				continue
			}
		}
		rows = append(rows, row)
	}
	if q.Order != "" {
		return pageOrderedIndexRows(rows, func(row IndexContentRow) string { return row.ContentID }, func(row IndexContentRow) string {
			if q.Order == "genesisAt.desc" {
				return row.GenesisAt
			}
			return row.HeadAt
		}, q.OrderedAfter, q.Limit), nil
	}
	return pageIndexRows(rows, func(row IndexContentRow) string { return row.ContentID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexCredits(q IndexCreditQuery) ([]IndexCreditRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []IndexCreditRow{}
	for _, contentRows := range s.indexCreditRows {
		for _, row := range contentRows {
			if q.DID != nil && row.DID != *q.DID {
				continue
			}
			if q.ContentID != nil && row.ContentID != *q.ContentID {
				continue
			}
			if q.Role != nil && (row.Role == nil || *row.Role != *q.Role) {
				continue
			}
			if q.After != nil && (row.ContentID < q.After.ContentID ||
				(row.ContentID == q.After.ContentID && row.Position <= q.After.Position)) {
				continue
			}
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ContentID != rows[j].ContentID {
			return rows[i].ContentID < rows[j].ContentID
		}
		return rows[i].Position < rows[j].Position
	})
	if len(rows) > q.Limit {
		rows = rows[:q.Limit]
	}
	return rows, nil
}

func (s *MemoryStore) QueryIndexArtifacts(q IndexArtifactQuery) ([]IndexArtifactRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []IndexArtifactRow{}
	for _, row := range s.indexArtifactRows {
		if q.CID != nil && row.CID != *q.CID {
			continue
		}
		if q.Signer != "" && row.SignerDID != q.Signer {
			continue
		}
		if q.DocSchema != nil && (row.DocSchema == nil || *row.DocSchema != *q.DocSchema) {
			continue
		}
		rows = append(rows, row)
	}
	if q.Order != "" {
		return pageOrderedIndexRows(rows, func(row IndexArtifactRow) string { return row.CID }, func(row IndexArtifactRow) string {
			if q.Order == "createdAt.desc" {
				return row.CreatedAt
			}
			return row.IngestedAt
		}, q.OrderedAfter, q.Limit), nil
	}
	return pageIndexRows(rows, func(row IndexArtifactRow) string { return row.CID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]IndexCountersignatureRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []IndexCountersignatureRow{}
	for _, row := range s.indexCountersignRows {
		if row.WitnessDID != q.Witness {
			continue
		}
		if q.Relation != nil && (row.Relation == nil || *row.Relation != *q.Relation) {
			continue
		}
		// Strip the witness_did column — the wire row never carries it (the witness
		// is echoed at the response top level).
		rows = append(rows, IndexCountersignatureRow{
			CID:        row.CID,
			TargetCID:  row.TargetCID,
			Relation:   row.Relation,
			JWSToken:   row.JWSToken,
			CreatedAt:  row.CreatedAt,
			IngestedAt: row.IngestedAt,
		})
	}
	if q.Order != "" {
		return pageOrderedIndexRows(rows, func(row IndexCountersignatureRow) string { return row.CID }, func(row IndexCountersignatureRow) string {
			if q.Order == "createdAt.desc" {
				return row.CreatedAt
			}
			return row.IngestedAt
		}, q.OrderedAfter, q.Limit), nil
	}
	return pageIndexRows(rows, func(row IndexCountersignatureRow) string { return row.CID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexCredentials(q IndexCredentialQuery) ([]IndexCredentialRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []IndexCredentialRow{}
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
		if q.Action != nil {
			found := false
			for _, att := range cred.Att {
				if att.Action == *q.Action {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		rows = append(rows, IndexCredentialRow{
			CID:        cred.CID,
			IssuerDID:  cred.IssuerDID,
			Aud:        "*",
			Att:        cred.Att,
			Exp:        cred.Exp,
			JWSToken:   cred.JWSToken,
			CreatedAt:  cred.CreatedAt,
			IngestedAt: cred.IngestedAt,
		})
	}
	if q.Order != "" {
		return pageOrderedIndexRows(rows, func(row IndexCredentialRow) string { return row.CID }, func(row IndexCredentialRow) string {
			if q.Order == "createdAt.desc" {
				return row.CreatedAt
			}
			return row.IngestedAt
		}, q.OrderedAfter, q.Limit), nil
	}
	return pageIndexRows(rows, func(row IndexCredentialRow) string { return row.CID }, q.After, q.Limit), nil
}

func (s *MemoryStore) QueryIndexOperations(q IndexOperationQuery) ([]IndexOperationRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := []IndexOperationRow{}
	for _, row := range s.indexOperationRows {
		if q.Kind != "" && row.Kind != q.Kind {
			continue
		}
		if q.ChainID != nil && row.ChainID != *q.ChainID {
			continue
		}
		if q.SignerKey != "" {
			// Opaque byte match against the key ingest resolved. A row whose signer
			// key never resolved has no entry here and so matches nothing, which is
			// the SQLite twin's `signer_key = ?` against NULL.
			if s.indexOperationSignerKeys[row.CID] != q.SignerKey {
				continue
			}
		}
		rows = append(rows, row)
	}
	return pageOrderedIndexRows(rows, func(row IndexOperationRow) string { return row.CID }, func(row IndexOperationRow) string {
		if q.Order == "createdAt.desc" {
			return row.CreatedAt
		}
		return row.IngestedAt
	}, q.OrderedAfter, q.Limit), nil
}

func (s *MemoryStore) putIndexIdentityRowLocked(row IndexIdentityRow) error {
	s.indexIdentityRows[row.DID] = row
	return nil
}

func (s *MemoryStore) putIndexContentRowLocked(row IndexContentRow) error {
	s.indexContentRows[row.ContentID] = row
	return nil
}

func (s *MemoryStore) putIndexCreditRowsLocked(contentID string, rows []IndexCreditRow) error {
	replacement := make([]IndexCreditRow, len(rows))
	copy(replacement, rows)
	for i := range replacement {
		replacement[i].ContentID = contentID
	}
	s.indexCreditRows[contentID] = replacement
	return nil
}

func (s *MemoryStore) putIndexArtifactRowLocked(row IndexArtifactRow) error {
	s.indexArtifactRows[row.CID] = row
	return nil
}

func (s *MemoryStore) putIndexContentSignerLocked(contentID string, did string) error {
	signers := s.indexContentSigners[contentID]
	if signers == nil {
		signers = map[string]struct{}{}
		s.indexContentSigners[contentID] = signers
	}
	signers[did] = struct{}{}
	return nil
}

// PutIndexIdentityKey adds one proved public key to a DID's has-ever-proved set.
// keyID is not retained: nothing queries by it, and the durable store's
// (public_key, did, key_id) row only uses it to keep one row per membership.
func (s *MemoryStore) putIndexIdentityKeyLocked(did string, publicKey string) error {
	keys := s.indexIdentityKeys[did]
	if keys == nil {
		keys = map[string]struct{}{}
		s.indexIdentityKeys[did] = keys
	}
	keys[publicKey] = struct{}{}
	return nil
}

func (s *MemoryStore) putIndexCountersignatureRowLocked(row StoredIndexCountersignature) error {
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

func (s *MemoryStore) appendToLogLocked(entry LogEntry) error {
	// One op, one log row — the SQLite twin enforces it with a unique index on
	// cid, and indexOperationRows (written only here) is this store's record of
	// which CIDs the log already carries. Silently ignoring the repeat matches
	// the twin's INSERT OR IGNORE.
	if _, exists := s.indexOperationRows[entry.CID]; exists {
		return nil
	}
	s.operationLog = append(s.operationLog, entry)
	// One op, one receipt stamp: PutOperation stamped this op moments ago in the
	// same ingest, so source ingestedAt from the stored operation's receipt stamp
	// rather than re-reading the wall clock — otherwise /index/v0/operations and
	// the projection rows that source from the operation (artifacts,
	// countersignatures) can disagree by a millisecond about the same op. Wall
	// clock only as a last-resort fallback for a log entry with no stored op.
	ingestedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if op, ok := s.operations[entry.CID]; ok && op.IngestedAt != "" {
		ingestedAt = op.IngestedAt
	}
	entry.IngestedAt = ingestedAt
	s.operationLog[len(s.operationLog)-1] = entry
	s.indexOperationRows[entry.CID] = IndexOperationRow{
		CID: entry.CID, Kind: entry.Kind, ChainID: entry.ChainID, CreatedAt: operationCreatedAt(entry.JWSToken),
		IngestedAt: ingestedAt,
	}
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
			// Relay-local cursor this log never issued → the route answers 400,
			// never a silently empty page.
			return nil, "", ErrUnknownLogCursor
		}
	}

	end := startIdx + limit
	if end > len(s.operationLog) {
		end = len(s.operationLog)
	}

	entries := s.operationLog[startIdx:end]
	result := make([]LogEntry, len(entries))
	copy(result, entries)

	// `next` only on a FULL page — a partial page means caught up (the shared
	// list envelope's contract). The puller retains its last persisted cursor on
	// null and re-fetches the final partial page next cycle (cheap dedup), so
	// nothing strands. Mirrors SQLiteStore.ReadLog and the TS twin.
	var next string
	if len(result) == limit {
		next = result[len(result)-1].CID
	}

	return result, next, nil
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

	// Replay of committed history is a VALIDITY decision, so it runs at each
	// operation's own createdAt: signers resolve in the state that held then, and
	// a credential revoked after an op was signed leaves that op — and therefore
	// the fork state derived from it — valid. Without the basis this replay would
	// start failing the moment any credential in the chain's history was revoked,
	// which would make a legitimate fork extension unverifiable. Mirrors the TS
	// twin (store.ts getContentStateAtCID).
	// Identity deletion, unlike revocation, IS retroactive and does not run
	// against the basis (CREDENTIALS.md "Deleted issuers"), so the deleted-issuer
	// gate is threaded unconditionally. The TS twin gets this for free — its
	// verifyDFOSCredential rejects a deleted issuer via resolveIdentity — while Go
	// takes it as an explicit option, so omitting it here would let a deleted
	// issuer's credentials keep authorizing committed history on Go only.
	resolveKey := CreateAsOfKeyResolver(s)
	isRevoked := dfos.WithRevocationChecker(func(issuerDID, credentialCID string, asOfUnix int64) (bool, error) {
		return s.IsCredentialRevoked(issuerDID, credentialCID, asOfUnix)
	})
	isDeleted := dfos.WithIdentityDeletedChecker(func(did string) (bool, error) {
		identity, err := s.GetIdentityChain(did)
		if err != nil {
			return false, err
		}
		return identity != nil && identity.State.IsDeleted, nil
	})
	result, err := dfos.VerifyContentChain(path, resolveKey, true, isRevoked, isDeleted)
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

func (s *MemoryStore) PutRawOp(cid string, jwsToken string, origins ...OpOrigin) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	origin := OpOriginDirect
	if len(origins) > 0 && origins[0] == OpOriginPeer {
		origin = OpOriginPeer
	}
	if _, exists := s.rawOps[cid]; exists {
		return false, nil
	}
	s.rawOps[cid] = rawOpEntry{jwsToken: jwsToken, origin: origin, status: "pending"}
	return true, nil
}

func (s *MemoryStore) GetUnsequencedOps(limit int) ([]PendingOp, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []PendingOp
	for _, entry := range s.rawOps {
		if entry.status == "pending" {
			out = append(out, PendingOp{JWSToken: entry.jwsToken, Origin: entry.origin})
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

func (s *MemoryStore) addRevocationLocked(revocation StoredRevocation) error {
	key := revocation.IssuerDID + "::" + revocation.CredentialCID
	// earliest boundary wins — see revocationSupersedes. The survivor is kept
	// WHOLE (artifact + boundary together), so the revocation this store serves
	// from /revocations/v1 is always the one that actually sets the boundary.
	if existing, ok := s.revocations[key]; ok && !revocationSupersedes(revocation, existing) {
		return nil
	}
	s.revocations[key] = revocation
	return nil
}

func (s *MemoryStore) IsCredentialRevoked(issuerDID string, credentialCID string, asOfUnix int64) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := issuerDID + "::" + credentialCID
	rev, ok := s.revocations[key]
	if !ok {
		return false, nil
	}
	// asOfUnix <= 0 is the timeless (freshness) question — see the Store contract.
	if asOfUnix <= 0 {
		return true, nil
	}
	revokedAt, ok := revocationCreatedAtUnix(storedRevocationCreatedAt(rev.CreatedAt, rev.JWSToken))
	return !ok || revokedAt <= asOfUnix, nil
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
	revs := []StoredRevocation{}
	for _, rev := range s.revocations {
		if rev.IssuerDID != issuerDID {
			continue
		}
		revs = append(revs, rev)
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i].CredentialCID < revs[j].CredentialCID })
	return revs, nil
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

func (s *MemoryStore) GetPublicCredentialByCID(cid string) (*StoredPublicCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	credential, ok := s.publicCredentials[cid]
	if !ok {
		return nil, nil
	}
	return &credential, nil
}

func (s *MemoryStore) addPublicCredentialLocked(credential StoredPublicCredential) error {
	s.publicCredentials[credential.CID] = credential
	return nil
}

// removePublicCredentialLocked drops a held grant only when the revoking issuer
// is the credential's OWN issuer. Unscoped removal let any identity sign a
// revocation naming someone else's credential CID and un-publish content it had
// no authority over.
func (s *MemoryStore) removePublicCredentialLocked(removal PublicCredentialRemoval) error {
	held, ok := s.publicCredentials[removal.CredentialCID]
	if !ok || held.IssuerDID != removal.IssuerDID {
		return nil
	}
	delete(s.publicCredentials, removal.CredentialCID)
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

// ---------------------------------------------------------------------------
// write contract
// ---------------------------------------------------------------------------

// Commit persists one accepted operation, or one document blob, as a unit.
//
// Everything happens under the store's single lock, and every write below is a
// map assignment that cannot fail, so "all of it or none of it" holds by
// construction here. A durable store buys the same property with a transaction
// (see SQLiteStore.Commit).
func (s *MemoryStore) Commit(batch CommitBatch) (CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if batch.Blob != nil {
		// Blob bytes are content-addressed, so a rewrite is a no-op and the
		// answer is always "new".
		return CommitNew, s.putBlobLocked(batch.Blob.Key, batch.Blob.Bytes)
	}
	op := batch.Operation
	if op == nil {
		return "", errors.New("commit batch carries neither an operation nor a blob")
	}
	// The race backstop. Ingestion already read for this CID before verifying —
	// it has to, to tell "same op" from "same CID, different signature" — so
	// reaching here with the CID held means a concurrent submission won.
	if _, held := s.operations[op.Operation.CID]; held {
		return CommitDuplicate, nil
	}

	if err := s.putOperationLocked(op.Operation); err != nil {
		return "", err
	}
	if op.IdentityChain != nil {
		if err := s.putIdentityChainLocked(*op.IdentityChain); err != nil {
			return "", err
		}
	}
	if op.ContentChain != nil {
		if err := s.putContentChainLocked(*op.ContentChain); err != nil {
			return "", err
		}
	}
	if op.Countersignature != nil {
		if err := s.addCountersignatureLocked(op.Countersignature.TargetCID, op.Countersignature.JWSToken); err != nil {
			return "", err
		}
	}
	if op.Revocation != nil {
		if err := s.addRevocationLocked(*op.Revocation); err != nil {
			return "", err
		}
	}
	if op.RemovePublicCredential != nil {
		if err := s.removePublicCredentialLocked(*op.RemovePublicCredential); err != nil {
			return "", err
		}
	}
	if op.PublicCredential != nil {
		if err := s.addPublicCredentialLocked(*op.PublicCredential); err != nil {
			return "", err
		}
	}
	if op.LogEntry != nil {
		if err := s.appendToLogLocked(*op.LogEntry); err != nil {
			return "", err
		}
	}
	return CommitNew, nil
}

// ---------------------------------------------------------------------------
// index projection — write side
// ---------------------------------------------------------------------------

func (s *MemoryStore) ApplyIndexRows(rows IndexRowBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range rows.Identities {
		if err := s.putIndexIdentityRowLocked(row); err != nil {
			return err
		}
	}
	for _, row := range rows.Content {
		if err := s.putIndexContentRowLocked(row); err != nil {
			return err
		}
	}
	for _, set := range rows.Credits {
		if err := s.putIndexCreditRowsLocked(set.ContentID, set.Rows); err != nil {
			return err
		}
	}
	for _, row := range rows.Artifacts {
		if err := s.putIndexArtifactRowLocked(row); err != nil {
			return err
		}
	}
	for _, row := range rows.Countersignatures {
		if err := s.putIndexCountersignatureRowLocked(row); err != nil {
			return err
		}
	}
	for _, row := range rows.IdentityKeys {
		if err := s.putIndexIdentityKeyLocked(row.DID, row.PublicKey); err != nil {
			return err
		}
	}
	for _, row := range rows.ContentSigners {
		if err := s.putIndexContentSignerLocked(row.ContentID, row.DID); err != nil {
			return err
		}
	}
	for _, key := range rows.OperationSignerKeys {
		// An unresolved key is never stamped — see IndexOperationSignerKey.
		if key.PublicKey != "" {
			s.indexOperationSignerKeys[key.CID] = key.PublicKey
		}
	}
	return nil
}

func (s *MemoryStore) GetIndexCursor() (IndexCursor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cursor := s.indexCursor
	if cursor.Sweep != nil {
		sweep := *cursor.Sweep
		cursor.Sweep = &sweep
	}
	return cursor, nil
}

func (s *MemoryStore) SetIndexCursor(cursor IndexCursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cursor.Sweep != nil {
		sweep := *cursor.Sweep
		cursor.Sweep = &sweep
	}
	s.indexCursor = cursor
	return nil
}

// RewriteIdentityChainState replaces one row's materialized state with a fresh
// walk of the log it already holds. See MigratableStore.
func (s *MemoryStore) RewriteIdentityChainState(chain StoredIdentityChain) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putIdentityChainLocked(chain)
}
