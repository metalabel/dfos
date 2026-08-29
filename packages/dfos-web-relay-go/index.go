package relay

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const (
	indexBasePath = "/index/v0"
	profileSchema = "https://schemas.dfos.com/profile/v1"
	postSchema    = "https://schemas.dfos.com/post/v1"

	// IndexProjectionVersion is the schema version of the materialized /index/v0
	// projection. A durable store stamps this in index_meta after a rebuild; when
	// the stored value differs from this const on boot (a fresh DB stamps 0), the
	// relay rebuilds all projection rows from the authoritative chain/countersign
	// tables before serving. Bump this whenever the projection row shape or a
	// row-value computation changes.
	//
	// v3: gate the extracted display-name fields (profile name, content title) on
	// the row's publicRead — a non-public document never projects its extracted
	// field onto the anonymous index surface — so upgraded relays rebuild any rows
	// a pre-gate builder persisted with a non-public name/title.
	//
	// v4: persist countersignature created/ingested clocks for ordered queries.
	// v5: add standalone artifact projection rows.
	// v6: add public-head credit projection rows.
	//
	// v7: add the identity has-ever-declared key reverse index behind `key=`.
	// The rows are history, not head state, so an upgraded relay can only
	// backfill them by replaying every identity op log — which is exactly what
	// the rebuild does.
	//
	// v8: retain each operation-log row's resolved signer key behind `signerKey=`.
	// Ingest resolves the signing key to verify the operation and now persists the
	// multibase it resolved to; rows a pre-v8 relay wrote carry no key, so the
	// rebuild re-resolves them from the stored JWS against the identity chains.
	// Unlike every other bump this one does not clear and re-derive a projection
	// table — the operation log is authoritative — it fills the new column in
	// place on the rows that lack it.
	IndexProjectionVersion = 8
)

var (
	contentIDRe                   = regexp.MustCompile(`^[2346789acdefhknrtvz]{31}$`)
	indexOrderedCursorTimestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`)
)

type indexProfile struct {
	Anchor     string  `json:"anchor"`
	PublicRead bool    `json:"publicRead"`
	DocSchema  *string `json:"docSchema"`
	Name       *string `json:"name"`
}

type indexIdentityRow struct {
	DID       string        `json:"did"`
	HeadCID   string        `json:"headCID"`
	OpCount   int           `json:"opCount"`
	GenesisAt string        `json:"genesisAt"`
	HeadAt    string        `json:"headAt"`
	IsDeleted bool          `json:"isDeleted"`
	Profile   *indexProfile `json:"profile"`
}

type indexIdentityPage struct {
	Identities []indexIdentityRow `json:"identities"`
	Next       *string            `json:"next"`
}

type indexContentRow struct {
	ContentID          string  `json:"contentId"`
	GenesisCID         string  `json:"genesisCID"`
	HeadCID            string  `json:"headCID"`
	CreatorDID         string  `json:"creatorDID"`
	IsDeleted          bool    `json:"isDeleted"`
	OpCount            int     `json:"opCount"`
	GenesisAt          string  `json:"genesisAt"`
	HeadAt             string  `json:"headAt"`
	CurrentDocumentCID *string `json:"currentDocumentCID"`
	PublicRead         bool    `json:"publicRead"`
	DocSchema          *string `json:"docSchema"`
	Title              *string `json:"title"`
}

type indexContentPage struct {
	Content []indexContentRow `json:"content"`
	Next    *string           `json:"next"`
}

type indexCreditRow struct {
	ContentID string  `json:"contentId"`
	DID       string  `json:"did"`
	Role      *string `json:"role"`
	Position  int     `json:"position"`
	HasClaim  bool    `json:"hasClaim"`
}

type indexCreditPage struct {
	Credits []indexCreditRow `json:"credits"`
	Next    *string          `json:"next"`
}

type indexCreditCursor struct {
	ContentID string
	Position  int
}

type indexCountersignatureRow struct {
	CID        string  `json:"cid"`
	TargetCID  string  `json:"targetCID"`
	Relation   *string `json:"relation"`
	JWSToken   string  `json:"jwsToken"`
	CreatedAt  string  `json:"-"`
	IngestedAt string  `json:"-"`
}

type indexCountersignaturePage struct {
	Witness           string                     `json:"witness"`
	Countersignatures []indexCountersignatureRow `json:"countersignatures"`
	Next              *string                    `json:"next"`
}

type indexCredentialRow struct {
	CID       string            `json:"cid"`
	IssuerDID string            `json:"issuerDID"`
	Aud       string            `json:"aud"`
	Att       []AttenuationPair `json:"att"`
	Exp       int64             `json:"exp"`
	JWSToken  string            `json:"jwsToken"`
}

type indexOperationRow struct {
	CID        string `json:"cid"`
	Kind       string `json:"kind"`
	ChainID    string `json:"chainId"`
	CreatedAt  string `json:"createdAt"`
	IngestedAt string `json:"ingestedAt"`
}

type indexOperationPage struct {
	Operations []indexOperationRow `json:"operations"`
	Next       *string             `json:"next"`
}

type indexArtifactRow struct {
	CID        string  `json:"cid"`
	SignerDID  string  `json:"signerDID"`
	CreatedAt  string  `json:"createdAt"`
	IngestedAt string  `json:"ingestedAt"`
	DocSchema  *string `json:"docSchema"`
}

type indexArtifactPage struct {
	Artifacts []indexArtifactRow `json:"artifacts"`
	Next      *string            `json:"next"`
}

type indexCredentialPage struct {
	Credentials []indexCredentialRow `json:"credentials"`
	Next        *string              `json:"next"`
}

type indexOrderedCursor struct {
	Timestamp string
	Key       string
}

func (r *Relay) handleIndexIdentities(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	query := req.URL.Query()
	hasPublicProfile, validBoolean := parseBooleanQuery(query, "hasPublicProfile")
	if !validBoolean {
		writeError(w, 400, "invalid boolean")
		return
	}
	did := query.Get("did")
	if _, present := firstQueryValue(query, "did"); present && !isValidDfosDid(did) {
		writeError(w, 400, "invalid DID")
		return
	}
	// `key` is matched as an opaque string against the multibase public keys the
	// chain's accepted operations declared — no format validation, so a NON-EMPTY
	// string no operation ever declared is a 200 with an empty page, never a 400.
	// Read with Get, not firstQueryValue: an empty `key=` is no filter, the same
	// posture `signerKey=` on /index/v0/operations holds, rather than the
	// present-but-empty filters that presence-detect elsewhere in this family.
	key := query.Get("key")
	nameContains := query.Get("nameContains")
	order, validOrder := parseIndexOrder(req.URL.Query().Get("order"))
	if !validOrder {
		writeError(w, 400, "invalid order")
		return
	}
	var orderedAfter *indexOrderedCursor
	if order != "" && req.URL.Query().Get("after") != "" {
		cursor, ok := decodeIndexOrderedCursor(req.URL.Query().Get("after"))
		if !ok {
			writeError(w, 400, "invalid cursor")
			return
		}
		orderedAfter = cursor
	}
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexIdentities(IndexIdentityQuery{
		DID:              did,
		Key:              key,
		HasPublicProfile: hasPublicProfile,
		NameContains:     nameContains,
		After:            req.URL.Query().Get("after"),
		OrderedAfter:     orderedAfter,
		Order:            order,
		Limit:            limit,
	})
	if storeErr(w, err) {
		return
	}
	for i := range rows {
		rows[i] = redactNonPublicIdentityRow(rows[i])
	}
	writeJSON(w, 200, indexIdentityPage{Identities: rows, Next: nextIndexCursor(len(rows), limit, order, func() (string, string) {
		row := rows[len(rows)-1]
		if order == "genesisAt.desc" {
			return row.GenesisAt, row.DID
		}
		return row.HeadAt, row.DID
	})})
}

func (r *Relay) handleIndexContent(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	query := req.URL.Query()
	creator := query.Get("creator")
	if creator != "" && !isValidDfosDid(creator) {
		writeError(w, 400, "invalid DID")
		return
	}
	signer := query.Get("signer")
	if signer != "" && !isValidDfosDid(signer) {
		writeError(w, 400, "invalid DID")
		return
	}
	var docSchema *string
	if value, ok := firstQueryValue(query, "docSchema"); ok {
		docSchema = &value
	}
	var documentCID *string
	if value, ok := firstQueryValue(query, "documentCID"); ok {
		documentCID = &value
	}
	publicRead, validBoolean := parseBooleanQuery(query, "publicRead")
	if !validBoolean {
		writeError(w, 400, "invalid boolean")
		return
	}
	titleContains, titleContainsPresent := firstQueryValue(query, "titleContains")
	if titleContainsPresent && publicRead != nil && !*publicRead {
		writeError(w, 400, "invalid filter combination")
		return
	}
	if titleContainsPresent {
		value := true
		publicRead = &value
	}
	isDeleted, validBoolean := parseBooleanQuery(query, "isDeleted")
	if !validBoolean {
		writeError(w, 400, "invalid boolean")
		return
	}
	var contentID *string
	if value, ok := firstQueryValue(query, "contentId"); ok {
		contentID = &value
	}
	order, validOrder := parseIndexOrder(query.Get("order"))
	if !validOrder {
		writeError(w, 400, "invalid order")
		return
	}
	var orderedAfter *indexOrderedCursor
	if order != "" && query.Get("after") != "" {
		cursor, ok := decodeIndexOrderedCursor(query.Get("after"))
		if !ok {
			writeError(w, 400, "invalid cursor")
			return
		}
		orderedAfter = cursor
	}
	limit := parseLimit(req, 100, 1000)

	rows, err := r.readStore.QueryIndexContent(IndexContentQuery{
		ContentID:     contentID,
		Creator:       creator,
		Signer:        signer,
		DocSchema:     docSchema,
		DocumentCID:   documentCID,
		PublicRead:    publicRead,
		IsDeleted:     isDeleted,
		TitleContains: titleContains,
		After:         query.Get("after"),
		OrderedAfter:  orderedAfter,
		Order:         order,
		Limit:         limit,
	})
	if storeErr(w, err) {
		return
	}
	for i := range rows {
		rows[i] = redactNonPublicContentRow(rows[i])
	}
	writeJSON(w, 200, indexContentPage{Content: rows, Next: nextIndexCursor(len(rows), limit, order, func() (string, string) {
		row := rows[len(rows)-1]
		if order == "genesisAt.desc" {
			return row.GenesisAt, row.ContentID
		}
		return row.HeadAt, row.ContentID
	})})
}

func (r *Relay) handleIndexCredits(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	query := req.URL.Query()
	var did *string
	if value, present := firstQueryValue(query, "did"); present {
		if !isValidDfosDid(value) {
			writeError(w, 400, "invalid DID")
			return
		}
		did = &value
	}
	var contentID *string
	if value, present := firstQueryValue(query, "contentId"); present {
		contentID = &value
	}
	var role *string
	if value, present := firstQueryValue(query, "role"); present {
		role = &value
	}
	var after *indexCreditCursor
	if raw := query.Get("after"); raw != "" {
		cursor, ok := decodeIndexCreditCursor(raw)
		if !ok {
			writeError(w, 400, "invalid cursor")
			return
		}
		after = cursor
	}
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexCredits(IndexCreditQuery{
		DID: did, ContentID: contentID, Role: role, After: after, Limit: limit,
	})
	if storeErr(w, err) {
		return
	}
	var next *string
	if len(rows) == limit && len(rows) > 0 {
		last := rows[len(rows)-1]
		cursor := encodeIndexCreditCursor(last.ContentID, last.Position)
		next = &cursor
	}
	writeJSON(w, 200, indexCreditPage{Credits: rows, Next: next})
}

func (r *Relay) handleIndexArtifacts(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}
	query := req.URL.Query()
	signer := query.Get("signer")
	if _, present := firstQueryValue(query, "signer"); present && !isValidDfosDid(signer) {
		writeError(w, 400, "invalid DID")
		return
	}
	var cid *string
	if value, ok := firstQueryValue(query, "cid"); ok {
		cid = &value
	}
	var docSchema *string
	if value, ok := firstQueryValue(query, "docSchema"); ok {
		docSchema = &value
	}
	order, validOrder := parseIndexRecencyOrder(query.Get("order"), "")
	if !validOrder {
		writeError(w, 400, "invalid order")
		return
	}
	var orderedAfter *indexOrderedCursor
	if order != "" && query.Get("after") != "" {
		cursor, ok := decodeIndexOrderedCursor(query.Get("after"))
		if !ok {
			writeError(w, 400, "invalid cursor")
			return
		}
		orderedAfter = cursor
	}
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexArtifacts(IndexArtifactQuery{
		CID: cid, Signer: signer, DocSchema: docSchema, After: query.Get("after"),
		OrderedAfter: orderedAfter, Order: order, Limit: limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexArtifactPage{Artifacts: rows, Next: nextIndexCursor(len(rows), limit, order, func() (string, string) {
		row := rows[len(rows)-1]
		if order == "createdAt.desc" {
			return row.CreatedAt, row.CID
		}
		return row.IngestedAt, row.CID
	})})
}

func (r *Relay) handleIndexCountersignatures(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	query := req.URL.Query()
	witness := query.Get("witness")
	if witness == "" || !isValidDfosDid(witness) {
		writeError(w, 400, "invalid DID")
		return
	}

	var relation *string
	if value, ok := firstQueryValue(query, "relation"); ok {
		relation = &value
	}
	order, validOrder := parseIndexRecencyOrder(query.Get("order"), "")
	if !validOrder {
		writeError(w, 400, "invalid order")
		return
	}
	var orderedAfter *indexOrderedCursor
	if order != "" && query.Get("after") != "" {
		cursor, ok := decodeIndexOrderedCursor(query.Get("after"))
		if !ok {
			writeError(w, 400, "invalid cursor")
			return
		}
		orderedAfter = cursor
	}
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexCountersignatures(IndexCountersignatureQuery{
		Witness:      witness,
		Relation:     relation,
		After:        query.Get("after"),
		OrderedAfter: orderedAfter,
		Order:        order,
		Limit:        limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexCountersignaturePage{Witness: witness, Countersignatures: rows, Next: nextIndexCursor(len(rows), limit, order, func() (string, string) {
		row := rows[len(rows)-1]
		if order == "createdAt.desc" {
			return row.CreatedAt, row.CID
		}
		return row.IngestedAt, row.CID
	})})
}

func (r *Relay) handleIndexCredentials(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	query := req.URL.Query()
	issuer := query.Get("issuer")
	if issuer != "" && !isValidDfosDid(issuer) {
		writeError(w, 400, "invalid DID")
		return
	}

	var resource *string
	if value, ok := firstQueryValue(query, "resource"); ok {
		resource = &value
	}
	var action *string
	if value, ok := firstQueryValue(query, "action"); ok {
		action = &value
	}
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexCredentials(IndexCredentialQuery{
		Issuer:   issuer,
		Resource: resource,
		Action:   action,
		After:    query.Get("after"),
		Limit:    limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexCredentialPage{Credentials: rows, Next: nextCursor(len(rows), limit, func() string { return rows[len(rows)-1].CID })})
}

func (r *Relay) handleIndexOperations(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	query := req.URL.Query()
	kind := query.Get("kind")
	if _, present := firstQueryValue(query, "kind"); present && !isIndexOperationKind(kind) {
		writeError(w, 400, "invalid kind")
		return
	}
	var chainID *string
	if value, ok := firstQueryValue(query, "chainId"); ok {
		chainID = &value
	}
	// `signerKey` is matched as an opaque string against the multibase public key
	// this row's signature verified against at ingest — no format validation, so a
	// string no accepted operation was signed with is a 200 with an empty page,
	// never a 400. Read with Get, not firstQueryValue: an empty `signerKey=` is no
	// filter, the identities `key=` posture the spec names — which `key=` itself
	// holds on the empty value too — rather than the present-but-empty filter
	// `chainId=` above applies.
	signerKey := query.Get("signerKey")
	order, validOrder := parseIndexRecencyOrder(query.Get("order"), "ingestedAt.desc")
	if !validOrder {
		writeError(w, 400, "invalid order")
		return
	}
	var orderedAfter *indexOrderedCursor
	if query.Get("after") != "" {
		cursor, ok := decodeIndexOrderedCursor(query.Get("after"))
		if !ok {
			writeError(w, 400, "invalid cursor")
			return
		}
		orderedAfter = cursor
	}
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexOperations(IndexOperationQuery{
		Kind:         kind,
		ChainID:      chainID,
		SignerKey:    signerKey,
		OrderedAfter: orderedAfter,
		Order:        order,
		Limit:        limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexOperationPage{Operations: rows, Next: nextIndexCursor(len(rows), limit, order, func() (string, string) {
		row := rows[len(rows)-1]
		if order == "createdAt.desc" {
			return row.CreatedAt, row.CID
		}
		return row.IngestedAt, row.CID
	})})
}

// nextCursor returns the keyset continuation cursor: the last row's key when the
// page filled to limit (there may be more), else null. Mirrors the TS route rule
// next = rows.length === limit ? key(last) : null.
func nextCursor(rowCount, limit int, lastKey func() string) *string {
	if rowCount == limit && rowCount > 0 {
		key := lastKey()
		return &key
	}
	return nil
}

func nextIndexCursor(rowCount, limit int, order string, last func() (string, string)) *string {
	if rowCount != limit || rowCount == 0 {
		return nil
	}
	timestamp, key := last()
	if order != "" {
		cursor := encodeIndexOrderedCursor(timestamp, key)
		return &cursor
	}
	return &key
}

// ---------------------------------------------------------------------------
// row builders — the single source of row-value truth, run at maintenance time
// (index_maintenance.go) and by the projection rebuild. Store-scoped so they can
// run against either the ingestion store (within-batch, uncommitted-visible) or
// the HTTP read store. Byte-identical to the TS twins in index-routes.ts.
// ---------------------------------------------------------------------------

func identityIndexRow(chain StoredIdentityChain, store Store) indexIdentityRow {
	return indexIdentityRow{
		DID:       chain.DID,
		HeadCID:   chain.HeadCID,
		OpCount:   len(chain.Log),
		GenesisAt: createdAtOf(chain.Log),
		HeadAt:    chain.LastCreatedAt,
		IsDeleted: chain.State.IsDeleted,
		Profile:   profileProjection(chain, store),
	}
}

func contentIndexRow(chain StoredContentChain, store Store) indexContentRow {
	doc, docSchema, publicRead := contentProjectionSources(chain, store)
	// Confidentiality is enforced at the application layer by whoever serves: a
	// non-public document MUST NOT project its extracted display-name field onto
	// the anonymous index surface. Compute publicRead first and gate title on it.
	var title *string
	if publicRead && docSchema != nil && *docSchema == postSchema && doc != nil {
		if value, ok := doc["title"].(string); ok && value != "" {
			title = &value
		}
	}
	return indexContentRow{
		ContentID:          chain.ContentID,
		GenesisCID:         chain.GenesisCID,
		HeadCID:            chain.State.HeadCID,
		CreatorDID:         chain.State.CreatorDID,
		IsDeleted:          chain.State.IsDeleted,
		OpCount:            len(chain.Log),
		GenesisAt:          createdAtOf(chain.Log),
		HeadAt:             chain.LastCreatedAt,
		CurrentDocumentCID: chain.State.CurrentDocumentCID,
		PublicRead:         publicRead,
		DocSchema:          docSchema,
		Title:              title,
	}
}

// creditIndexRows builds one content chain's complete public-head credit set.
func creditIndexRows(chain StoredContentChain, store Store) []indexCreditRow {
	doc, docSchema, publicRead := contentProjectionSources(chain, store)
	if chain.State.IsDeleted || !publicRead || docSchema == nil || *docSchema != postSchema || doc == nil {
		return []indexCreditRow{}
	}
	credits, ok := doc["credits"].([]any)
	if !ok {
		return []indexCreditRow{}
	}
	rows := []indexCreditRow{}
	for position, raw := range credits {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		did, ok := entry["did"].(string)
		if !ok {
			continue
		}
		var role *string
		if value, ok := entry["role"].(string); ok {
			role = &value
		}
		_, hasClaim := entry["claim"].(string)
		rows = append(rows, indexCreditRow{
			ContentID: chain.ContentID, DID: did, Role: role, Position: position, HasClaim: hasClaim,
		})
	}
	return rows
}

// redactNonPublicIdentityRow strips the extracted display-name field from a
// non-public identity row before serialization — defense in depth against a row
// persisted by a pre-gate builder (the current builder already withholds it).
// Clones the profile so it never mutates a shared in-memory projection row.
func redactNonPublicIdentityRow(row indexIdentityRow) indexIdentityRow {
	if row.Profile != nil && !row.Profile.PublicRead && row.Profile.Name != nil {
		clone := *row.Profile
		clone.Name = nil
		row.Profile = &clone
	}
	return row
}

// redactNonPublicContentRow strips the extracted title from a non-public content
// row before serialization — the content-side twin of the identity redaction.
func redactNonPublicContentRow(row indexContentRow) indexContentRow {
	if !row.PublicRead {
		row.Title = nil
	}
	return row
}

// countersignatureIndexRow projects a stored countersignature to its wire row.
func countersignatureIndexRow(row StoredCountersignature) indexCountersignatureRow {
	return indexCountersignatureRow{
		CID:       row.CID,
		TargetCID: row.TargetCID,
		Relation:  row.Relation,
		JWSToken:  row.JWSToken,
	}
}

func artifactIndexRow(cid, jwsToken, ingestedAt string) *indexArtifactRow {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil || payload == nil {
		return nil
	}
	signerDID := header.Kid
	if index := strings.Index(signerDID, "#"); index >= 0 {
		signerDID = signerDID[:index]
	}
	createdAt, _ := payload["createdAt"].(string)
	if signerDID == "" || createdAt == "" {
		return nil
	}
	var docSchema *string
	if content, ok := payload["content"].(map[string]any); ok {
		if value, ok := content["$schema"].(string); ok {
			docSchema = &value
		}
	}
	return &indexArtifactRow{CID: cid, SignerDID: signerDID, CreatedAt: createdAt, IngestedAt: ingestedAt, DocSchema: docSchema}
}

func profileProjection(chain StoredIdentityChain, store Store) *indexProfile {
	candidates := make([]dfos.ServiceEntry, 0)
	for _, service := range chain.State.Services {
		if service["type"] != "ContentAnchor" {
			continue
		}
		label, ok := service["label"].(string)
		if !ok || strings.ToLower(label) != "profile" {
			continue
		}
		anchor, ok := service["anchor"].(string)
		if !ok || !contentIDRe.MatchString(anchor) {
			continue
		}
		candidates = append(candidates, service)
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, _ := candidates[i]["id"].(string)
		b, _ := candidates[j]["id"].(string)
		return a < b
	})
	if len(candidates) == 0 {
		return nil
	}
	anchor, _ := candidates[0]["anchor"].(string)
	if anchor == "" {
		return nil
	}

	var doc map[string]any
	var docSchema *string
	if content, _ := store.GetContentChain(anchor); content != nil {
		doc, docSchema = headDocumentProjection(*content, store)
	}

	// Confidentiality is enforced at the application layer by whoever serves: a
	// non-public profile document MUST NOT project its extracted name onto the
	// anonymous index surface. Compute publicRead first and gate name on it.
	publicRead := hasPublicStandingAuth(anchor, "read", store)
	var name *string
	if publicRead && docSchema != nil && *docSchema == profileSchema && doc != nil {
		if value, ok := doc["name"].(string); ok && value != "" {
			name = &value
		}
	}
	return &indexProfile{
		Anchor:     anchor,
		PublicRead: publicRead,
		DocSchema:  docSchema,
		Name:       name,
	}
}

func headDocumentProjection(chain StoredContentChain, store Store) (map[string]any, *string) {
	documentCID := chain.State.CurrentDocumentCID
	if documentCID == nil {
		return nil, nil
	}
	blob, err := store.GetBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: *documentCID})
	if err != nil || blob == nil {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		return nil, nil
	}
	doc, ok := decoded.(map[string]any)
	if !ok {
		return nil, nil
	}
	schemaValue, ok := doc["$schema"].(string)
	if !ok {
		return doc, nil
	}
	return doc, &schemaValue
}

func contentProjectionSources(chain StoredContentChain, store Store) (map[string]any, *string, bool) {
	doc, docSchema := headDocumentProjection(chain, store)
	return doc, docSchema, hasPublicStandingAuth(chain.ContentID, "read", store)
}

func parseBooleanQuery(query map[string][]string, key string) (*bool, bool) {
	raw, present := firstQueryValue(query, key)
	if !present {
		return nil, true
	}
	switch raw {
	case "true":
		value := true
		return &value, true
	case "false":
		value := false
		return &value, true
	default:
		return nil, false
	}
}

func parseIndexOrder(raw string) (string, bool) {
	switch raw {
	case "":
		return "", true
	case "genesisAt.desc", "headAt.desc":
		return raw, true
	default:
		return "", false
	}
}

func parseIndexRecencyOrder(raw, defaultOrder string) (string, bool) {
	switch raw {
	case "":
		return defaultOrder, true
	case "createdAt.desc", "ingestedAt.desc":
		return raw, true
	default:
		return "", false
	}
}

func isIndexOperationKind(kind string) bool {
	switch kind {
	case "identity-op", "content-op", "artifact", "countersign", "revocation", "credential":
		return true
	default:
		return false
	}
}

func encodeIndexOrderedCursor(timestamp, key string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(timestamp + "~" + key))
}

func decodeIndexOrderedCursor(raw string) (*indexOrderedCursor, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, false
	}
	parts := strings.Split(string(decoded), "~")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, false
	}
	if !indexOrderedCursorTimestampRe.MatchString(parts[0]) {
		return nil, false
	}
	return &indexOrderedCursor{Timestamp: parts[0], Key: parts[1]}, true
}

func encodeIndexCreditCursor(contentID string, position int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(contentID + "~" + strconv.Itoa(position)))
}

func decodeIndexCreditCursor(raw string) (*indexCreditCursor, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	// canonicality round-trip: reject non-canonical encodings (padding,
	// whitespace) so both twins agree on exactly which cursors are valid
	if base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, false
	}
	parts := strings.Split(string(decoded), "~")
	if len(parts) != 2 || !contentIDRe.MatchString(parts[0]) || parts[1] == "" {
		return nil, false
	}
	position, err := strconv.Atoi(parts[1])
	if err != nil || position < 0 || strconv.Itoa(position) != parts[1] {
		return nil, false
	}
	return &indexCreditCursor{ContentID: parts[0], Position: position}, true
}

func createdAtOf(log []string) string {
	if len(log) == 0 {
		return ""
	}
	_, payload, err := dfos.DecodeJWSUnsafe(log[0])
	if err != nil {
		return ""
	}
	if value, ok := payload["createdAt"].(string); ok {
		return value
	}
	return ""
}

// operationCreatedAt normalizes the operation's author clock to the index wire
// timestamp. Protocol operations carry createdAt; credentials carry numeric iat.
func operationCreatedAt(jwsToken string) string {
	_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || payload == nil {
		return ""
	}
	if value, ok := payload["createdAt"].(string); ok {
		return value
	}
	if value, ok := payload["iat"].(float64); ok {
		return time.Unix(int64(value), 0).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if value, ok := payload["iat"].(int64); ok {
		return time.Unix(value, 0).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return ""
}

func firstQueryValue(query map[string][]string, key string) (string, bool) {
	values, ok := query[key]
	if !ok {
		return "", false
	}
	if len(values) == 0 {
		return "", true
	}
	return values[0], true
}

func countersignatureFromToken(targetCID, jwsToken string) *StoredCountersignature {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return nil
	}
	witnessDID, _ := payload["did"].(string)
	if witnessDID == "" {
		return nil
	}
	cid := header.CID
	if cid == "" {
		return nil
	}
	if payloadTarget, ok := payload["targetCID"].(string); ok {
		targetCID = payloadTarget
	}
	var relation *string
	if value, ok := payload["relation"].(string); ok {
		relation = &value
	}
	createdAt, _ := payload["createdAt"].(string)
	return &StoredCountersignature{
		CID:        cid,
		TargetCID:  targetCID,
		WitnessDID: witnessDID,
		Relation:   relation,
		JWSToken:   jwsToken,
		CreatedAt:  createdAt,
	}
}
