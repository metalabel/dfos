package relay

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const (
	indexBasePath = "/index/v0"
	profileSchema = "https://schemas.dfos.com/profile/v1"

	// IndexProjectionVersion is the schema version of the materialized /index/v0
	// projection. A durable store stamps this in index_meta after a rebuild; when
	// the stored value differs from this const on boot (a fresh DB stamps 0), the
	// relay rebuilds all projection rows from the authoritative chain/countersign
	// tables before serving. Bump this whenever the projection row shape or a
	// row-value computation changes.
	IndexProjectionVersion = 1
)

var contentIDRe = regexp.MustCompile(`^[2346789acdefhknrtvz]{31}$`)

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
}

type indexContentPage struct {
	Content []indexContentRow `json:"content"`
	Next    *string           `json:"next"`
}

type indexCountersignatureRow struct {
	CID       string  `json:"cid"`
	TargetCID string  `json:"targetCID"`
	Relation  *string `json:"relation"`
	JWSToken  string  `json:"jwsToken"`
}

type indexCountersignaturePage struct {
	Witness           string                     `json:"witness"`
	Countersignatures []indexCountersignatureRow `json:"countersignatures"`
	Next              *string                    `json:"next"`
}

func (r *Relay) handleIndexIdentities(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	hasPublicProfile := parseBooleanQuery(req.URL.Query().Get("hasPublicProfile"))
	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexIdentities(IndexIdentityQuery{
		HasPublicProfile: hasPublicProfile,
		After:            req.URL.Query().Get("after"),
		Limit:            limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexIdentityPage{Identities: rows, Next: nextCursor(len(rows), limit, func() string { return rows[len(rows)-1].DID })})
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
	var docSchema *string
	if value, ok := firstQueryValue(query, "docSchema"); ok {
		docSchema = &value
	}
	var documentCID *string
	if value, ok := firstQueryValue(query, "documentCID"); ok {
		documentCID = &value
	}
	publicRead := parseBooleanQuery(query.Get("publicRead"))
	limit := parseLimit(req, 100, 1000)

	rows, err := r.readStore.QueryIndexContent(IndexContentQuery{
		Creator:     creator,
		DocSchema:   docSchema,
		DocumentCID: documentCID,
		PublicRead:  publicRead,
		After:       query.Get("after"),
		Limit:       limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexContentPage{Content: rows, Next: nextCursor(len(rows), limit, func() string { return rows[len(rows)-1].ContentID })})
}

func (r *Relay) handleIndexCountersignatures(w http.ResponseWriter, req *http.Request) {
	if !r.indexEnabled {
		writeError(w, 501, "index not available")
		return
	}

	witness := req.URL.Query().Get("witness")
	if witness == "" || !isValidDfosDid(witness) {
		writeError(w, 400, "invalid DID")
		return
	}

	limit := parseLimit(req, 100, 1000)
	rows, err := r.readStore.QueryIndexCountersignatures(IndexCountersignatureQuery{
		Witness: witness,
		After:   req.URL.Query().Get("after"),
		Limit:   limit,
	})
	if storeErr(w, err) {
		return
	}
	writeJSON(w, 200, indexCountersignaturePage{Witness: witness, Countersignatures: rows, Next: nextCursor(len(rows), limit, func() string { return rows[len(rows)-1].CID })})
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
	_, docSchema := headDocumentProjection(chain, store)
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
		PublicRead:         hasPublicStandingAuth(chain.ContentID, "read", store),
		DocSchema:          docSchema,
	}
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

	var name *string
	if docSchema != nil && *docSchema == profileSchema && doc != nil {
		if value, ok := doc["name"].(string); ok && value != "" {
			name = &value
		}
	}
	return &indexProfile{
		Anchor:     anchor,
		PublicRead: hasPublicStandingAuth(anchor, "read", store),
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

func parseBooleanQuery(raw string) *bool {
	switch raw {
	case "true":
		value := true
		return &value
	case "false":
		value := false
		return &value
	default:
		return nil
	}
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
	return &StoredCountersignature{
		CID:        cid,
		TargetCID:  targetCID,
		WitnessDID: witnessDID,
		Relation:   relation,
		JWSToken:   jwsToken,
	}
}
