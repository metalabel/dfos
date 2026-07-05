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

	chains, err := r.readStore.ListIdentityChains()
	if storeErr(w, err) {
		return
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].DID < chains[j].DID })

	hasPublicProfile := parseBooleanQuery(req.URL.Query().Get("hasPublicProfile"))
	rows := make([]indexIdentityRow, 0, len(chains))
	for _, chain := range chains {
		row := r.identityIndexRow(chain)
		if hasPublicProfile != nil && (row.Profile != nil && row.Profile.PublicRead) != *hasPublicProfile {
			continue
		}
		rows = append(rows, row)
	}

	page, next := pageByKey(rows, func(row indexIdentityRow) string { return row.DID }, req.URL.Query().Get("after"), parseLimit(req, 100, 1000))
	writeJSON(w, 200, indexIdentityPage{Identities: page, Next: next})
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
	docSchema, hasDocSchema := firstQueryValue(query, "docSchema")
	publicRead := parseBooleanQuery(query.Get("publicRead"))

	chains, err := r.readStore.ListContentChains()
	if storeErr(w, err) {
		return
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].ContentID < chains[j].ContentID })

	rows := make([]indexContentRow, 0, len(chains))
	for _, chain := range chains {
		row := r.contentIndexRow(chain)
		if creator != "" && row.CreatorDID != creator {
			continue
		}
		if hasDocSchema && (row.DocSchema == nil || *row.DocSchema != docSchema) {
			continue
		}
		if publicRead != nil && row.PublicRead != *publicRead {
			continue
		}
		rows = append(rows, row)
	}

	page, next := pageByKey(rows, func(row indexContentRow) string { return row.ContentID }, query.Get("after"), parseLimit(req, 100, 1000))
	writeJSON(w, 200, indexContentPage{Content: page, Next: next})
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

	stored, err := r.readStore.GetCountersignaturesByWitness(witness)
	if storeErr(w, err) {
		return
	}
	rows := make([]indexCountersignatureRow, 0, len(stored))
	for _, row := range stored {
		rows = append(rows, indexCountersignatureRow{
			CID:       row.CID,
			TargetCID: row.TargetCID,
			Relation:  row.Relation,
			JWSToken:  row.JWSToken,
		})
	}

	page, next := pageByKey(rows, func(row indexCountersignatureRow) string { return row.CID }, req.URL.Query().Get("after"), parseLimit(req, 100, 1000))
	writeJSON(w, 200, indexCountersignaturePage{Witness: witness, Countersignatures: page, Next: next})
}

func (r *Relay) identityIndexRow(chain StoredIdentityChain) indexIdentityRow {
	return indexIdentityRow{
		DID:       chain.DID,
		HeadCID:   chain.HeadCID,
		OpCount:   len(chain.Log),
		GenesisAt: createdAtOf(chain.Log),
		HeadAt:    chain.LastCreatedAt,
		IsDeleted: chain.State.IsDeleted,
		Profile:   r.profileProjection(chain),
	}
}

func (r *Relay) contentIndexRow(chain StoredContentChain) indexContentRow {
	_, docSchema := r.headDocumentProjection(chain)
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
		PublicRead:         r.hasPublicStandingAuth(chain.ContentID, "read"),
		DocSchema:          docSchema,
	}
}

func (r *Relay) profileProjection(chain StoredIdentityChain) *indexProfile {
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
	if content, _ := r.readStore.GetContentChain(anchor); content != nil {
		doc, docSchema = r.headDocumentProjection(*content)
	}

	var name *string
	if docSchema != nil && *docSchema == profileSchema && doc != nil {
		if value, ok := doc["name"].(string); ok && value != "" {
			name = &value
		}
	}
	return &indexProfile{
		Anchor:     anchor,
		PublicRead: r.hasPublicStandingAuth(anchor, "read"),
		DocSchema:  docSchema,
		Name:       name,
	}
}

func (r *Relay) headDocumentProjection(chain StoredContentChain) (map[string]any, *string) {
	documentCID := chain.State.CurrentDocumentCID
	if documentCID == nil {
		return nil, nil
	}
	blob, err := r.readStore.GetBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: *documentCID})
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

func pageByKey[T any](rows []T, keyOf func(T) string, after string, limit int) ([]T, *string) {
	startIdx := 0
	if after != "" {
		startIdx = len(rows)
		for i, row := range rows {
			if keyOf(row) == after {
				startIdx = i + 1
				break
			}
		}
	}
	end := startIdx + limit
	if end > len(rows) {
		end = len(rows)
	}
	page := rows[startIdx:end]
	if len(page) == limit {
		next := keyOf(page[len(page)-1])
		return page, &next
	}
	return page, nil
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
