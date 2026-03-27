package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

func newRouter(r *Relay) http.Handler {
	mux := http.NewServeMux()

	// well-known
	mux.HandleFunc("GET /.well-known/dfos-relay", r.handleWellKnown)

	// proof plane — public
	mux.HandleFunc("POST /operations", r.handlePostOperations)
	mux.HandleFunc("GET /operations/{cid}/countersignatures", r.handleOperationCountersignatures)
	mux.HandleFunc("GET /operations/{cid}", r.handleGetOperation)
	mux.HandleFunc("GET /identities/{did}/log", r.handleIdentityLog)
	mux.HandleFunc("GET /identities/{did...}", r.handleGetIdentity)
	mux.HandleFunc("GET /content/{contentId}/log", r.handleContentLog)
	mux.HandleFunc("GET /content/{contentId}/blob/{ref}", r.handleGetBlob)
	mux.HandleFunc("GET /content/{contentId}/blob", r.handleGetBlobHead)
	mux.HandleFunc("PUT /content/{contentId}/blob/{operationCID}", r.handlePutBlob)
	mux.HandleFunc("GET /content/{contentId}", r.handleGetContent)
	mux.HandleFunc("GET /countersignatures/{cid}", r.handleGetCountersignatures)
	mux.HandleFunc("GET /beacons/{did...}", r.handleGetBeacon)
	mux.HandleFunc("GET /log", r.handleGetLog)

	return mux
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// storeErr returns true if err is non-nil (writing a 500 response).
func storeErr(w http.ResponseWriter, err error) bool {
	if err != nil {
		writeError(w, 500, "internal error")
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// well-known
// ---------------------------------------------------------------------------

func (r *Relay) handleWellKnown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"did":      r.did,
		"protocol": "dfos-web-relay",
		"version":  "0.1.0",
		"proof":    true,
		"content":  r.contentEnabled,
		"log":      r.logEnabled,
		"profile":  r.profileArtifactJWS,
	})
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

func (r *Relay) handlePostOperations(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Operations []string `json:"operations"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON body"})
		return
	}
	if len(body.Operations) == 0 || len(body.Operations) > 100 {
		writeJSON(w, 400, map[string]any{
			"error":   "invalid request",
			"details": []map[string]string{{"message": "operations must contain 1-100 items"}},
		})
		return
	}

	results := r.Ingest(body.Operations)
	writeJSON(w, 200, map[string]any{"results": results})
}

func (r *Relay) handleGetOperation(w http.ResponseWriter, req *http.Request) {
	cid := req.PathValue("cid")
	op, err := r.store.GetOperation(cid)
	if storeErr(w, err) {
		return
	}
	if op == nil {
		writeError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, op)
}

// ---------------------------------------------------------------------------
// identities
// ---------------------------------------------------------------------------

func (r *Relay) handleGetIdentity(w http.ResponseWriter, req *http.Request) {
	did := req.PathValue("did")
	chain, err := r.store.GetIdentityChain(did)
	if storeErr(w, err) {
		return
	}

	// read-through: try peers on local miss
	if chain == nil && r.peerClient != nil {
		for _, peer := range r.peers {
			if peer.ReadThrough != nil && !*peer.ReadThrough {
				continue
			}
			page, err := r.peerClient.GetIdentityLog(peer.URL, did, "", 1000)
			if err != nil || page == nil || len(page.Entries) == 0 {
				continue
			}
			tokens := make([]string, len(page.Entries))
			for i, e := range page.Entries {
				tokens[i] = e.JWSToken
			}
			r.Ingest(tokens)
			chain, _ = r.store.GetIdentityChain(did)
			if chain != nil {
				break
			}
		}
	}

	if chain == nil {
		writeError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"did":     chain.DID,
		"headCID": chain.HeadCID,
		"state":   chain.State,
	})
}

func (r *Relay) handleIdentityLog(w http.ResponseWriter, req *http.Request) {
	did := req.PathValue("did")
	chain, err := r.store.GetIdentityChain(did)
	if storeErr(w, err) {
		return
	}
	if chain == nil {
		writeError(w, 404, "not found")
		return
	}

	after := req.URL.Query().Get("after")
	limit := parseLimit(req, 100, 1000)

	// build entries from chain log
	type logEntry struct {
		CID      string `json:"cid"`
		JWSToken string `json:"jwsToken"`
	}
	entries := make([]logEntry, 0, len(chain.Log))
	for _, jws := range chain.Log {
		header, _, _ := dfos.DecodeJWSUnsafe(jws)
		cid := ""
		if header != nil {
			cid = header.CID
		}
		entries = append(entries, logEntry{CID: cid, JWSToken: jws})
	}

	// apply cursor pagination
	startIdx := 0
	if after != "" {
		found := false
		for i, e := range entries {
			if e.CID == after {
				startIdx = i + 1
				found = true
				break
			}
		}
		if !found {
			startIdx = len(entries)
		}
	}

	end := startIdx + limit
	if end > len(entries) {
		end = len(entries)
	}
	page := entries[startIdx:end]

	var cursor *string
	if len(page) == limit {
		c := page[len(page)-1].CID
		cursor = &c
	}

	writeJSON(w, 200, map[string]any{
		"entries": page,
		"cursor":  cursor,
	})
}

// ---------------------------------------------------------------------------
// content
// ---------------------------------------------------------------------------

func (r *Relay) handleGetContent(w http.ResponseWriter, req *http.Request) {
	contentID := req.PathValue("contentId")
	chain, err := r.store.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}

	// read-through: try peers on local miss
	if chain == nil && r.peerClient != nil {
		for _, peer := range r.peers {
			if peer.ReadThrough != nil && !*peer.ReadThrough {
				continue
			}
			page, err := r.peerClient.GetContentLog(peer.URL, contentID, "", 1000)
			if err != nil || page == nil || len(page.Entries) == 0 {
				continue
			}
			tokens := make([]string, len(page.Entries))
			for i, e := range page.Entries {
				tokens[i] = e.JWSToken
			}
			r.Ingest(tokens)
			chain, _ = r.store.GetContentChain(contentID)
			if chain != nil {
				break
			}
		}
	}

	if chain == nil {
		writeError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"contentId":  chain.ContentID,
		"genesisCID": chain.GenesisCID,
		"headCID":    chain.State.HeadCID,
		"state":      chain.State,
	})
}

func (r *Relay) handleContentLog(w http.ResponseWriter, req *http.Request) {
	contentID := req.PathValue("contentId")
	chain, err := r.store.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}
	if chain == nil {
		writeError(w, 404, "not found")
		return
	}

	after := req.URL.Query().Get("after")
	limit := parseLimit(req, 100, 1000)

	type logEntry struct {
		CID      string `json:"cid"`
		JWSToken string `json:"jwsToken"`
	}
	entries := make([]logEntry, 0, len(chain.Log))
	for _, jws := range chain.Log {
		header, _, _ := dfos.DecodeJWSUnsafe(jws)
		cid := ""
		if header != nil {
			cid = header.CID
		}
		entries = append(entries, logEntry{CID: cid, JWSToken: jws})
	}

	startIdx := 0
	if after != "" {
		found := false
		for i, e := range entries {
			if e.CID == after {
				startIdx = i + 1
				found = true
				break
			}
		}
		if !found {
			startIdx = len(entries)
		}
	}

	end := startIdx + limit
	if end > len(entries) {
		end = len(entries)
	}
	page := entries[startIdx:end]

	var cursor *string
	if len(page) == limit {
		c := page[len(page)-1].CID
		cursor = &c
	}

	writeJSON(w, 200, map[string]any{
		"entries": page,
		"cursor":  cursor,
	})
}

// ---------------------------------------------------------------------------
// countersignatures
// ---------------------------------------------------------------------------

func (r *Relay) handleGetCountersignatures(w http.ResponseWriter, req *http.Request) {
	cid := req.PathValue("cid")

	op, err := r.store.GetOperation(cid)
	if storeErr(w, err) {
		return
	}
	if op == nil {
		cs, csErr := r.store.GetCountersignatures(cid)
		if storeErr(w, csErr) {
			return
		}
		if len(cs) == 0 {
			writeError(w, 404, "not found")
			return
		}
		writeJSON(w, 200, map[string]any{
			"cid":              cid,
			"countersignatures": cs,
		})
		return
	}

	cs, csErr := r.store.GetCountersignatures(cid)
	if storeErr(w, csErr) {
		return
	}
	writeJSON(w, 200, map[string]any{
		"operationCID":     cid,
		"countersignatures": cs,
	})
}

func (r *Relay) handleOperationCountersignatures(w http.ResponseWriter, req *http.Request) {
	cid := req.PathValue("cid")

	op, err := r.store.GetOperation(cid)
	if storeErr(w, err) {
		return
	}
	if op == nil {
		writeError(w, 404, "not found")
		return
	}

	cs, csErr := r.store.GetCountersignatures(cid)
	if storeErr(w, csErr) {
		return
	}
	writeJSON(w, 200, map[string]any{
		"operationCID":     cid,
		"countersignatures": cs,
	})
}

// ---------------------------------------------------------------------------
// beacons
// ---------------------------------------------------------------------------

func (r *Relay) handleGetBeacon(w http.ResponseWriter, req *http.Request) {
	did := req.PathValue("did")
	beacon, err := r.store.GetBeacon(did)
	if storeErr(w, err) {
		return
	}
	if beacon == nil {
		writeError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"did":       beacon.DID,
		"jwsToken":  beacon.JWSToken,
		"beaconCID": beacon.BeaconCID,
		"payload":   beacon.Payload,
	})
}

// ---------------------------------------------------------------------------
// global log
// ---------------------------------------------------------------------------

func (r *Relay) handleGetLog(w http.ResponseWriter, req *http.Request) {
	if !r.logEnabled {
		writeError(w, 501, "global log not available")
		return
	}
	after := req.URL.Query().Get("after")
	limit := parseLimit(req, 100, 1000)

	entries, cursor, err := r.store.ReadLog(after, limit)
	if storeErr(w, err) {
		return
	}
	if entries == nil {
		entries = []LogEntry{}
	}

	var cursorPtr *string
	if cursor != "" {
		cursorPtr = &cursor
	}

	writeJSON(w, 200, map[string]any{
		"entries": entries,
		"cursor":  cursorPtr,
	})
}

// ---------------------------------------------------------------------------
// blob upload/download (content plane)
// ---------------------------------------------------------------------------

func (r *Relay) handlePutBlob(w http.ResponseWriter, req *http.Request) {
	if !r.contentEnabled {
		writeError(w, 501, "content plane not available")
		return
	}

	contentID := req.PathValue("contentId")
	operationCID := req.PathValue("operationCID")

	// authenticate
	auth := AuthenticateRequest(req.Header.Get("Authorization"), r.did, r.store)
	if auth == nil {
		writeError(w, 401, "authentication required")
		return
	}

	// verify chain exists
	chain, err := r.store.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}
	if chain == nil {
		writeError(w, 404, "content chain not found")
		return
	}

	// find the referenced operation in the chain
	var documentCID string
	var operationSignerDID string
	for _, token := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(token)
		if err != nil || header == nil || header.CID != operationCID {
			continue
		}
		if d, ok := payload["documentCID"].(string); ok {
			documentCID = d
		}
		if d, ok := payload["did"].(string); ok {
			operationSignerDID = d
		}
		break
	}

	if documentCID == "" {
		writeError(w, 404, "operation not found in chain or has no documentCID")
		return
	}

	// authorize: caller must be chain creator or the operation signer
	if auth.Iss != chain.State.CreatorDID && auth.Iss != operationSignerDID {
		writeError(w, 403, "not authorized — must be chain creator or operation signer")
		return
	}

	// read blob bytes (capped at 16 MB) and verify they match documentCID
	const maxBlobSize = 16 << 20 // 16 MB
	req.Body = http.MaxBytesReader(w, req.Body, maxBlobSize)
	bytes, err := io.ReadAll(req.Body)
	if err != nil {
		writeError(w, 400, "failed to read body")
		return
	}

	var parsed any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		writeError(w, 400, "blob bytes do not match documentCID")
		return
	}
	_, _, computedCID, err := dfos.DagCborCID(parsed)
	if err != nil || computedCID != documentCID {
		writeError(w, 400, "blob bytes do not match documentCID")
		return
	}

	r.store.PutBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: documentCID}, bytes)

	writeJSON(w, 200, map[string]any{
		"status":       "stored",
		"contentId":    contentID,
		"documentCID":  documentCID,
		"operationCID": operationCID,
	})
}

func (r *Relay) handleGetBlobHead(w http.ResponseWriter, req *http.Request) {
	if !r.contentEnabled {
		writeError(w, 501, "content plane not available")
		return
	}
	r.readBlob(w, req, req.PathValue("contentId"), "head")
}

func (r *Relay) handleGetBlob(w http.ResponseWriter, req *http.Request) {
	if !r.contentEnabled {
		writeError(w, 501, "content plane not available")
		return
	}
	r.readBlob(w, req, req.PathValue("contentId"), req.PathValue("ref"))
}

func (r *Relay) readBlob(w http.ResponseWriter, req *http.Request, contentID, ref string) {
	// authenticate
	auth := AuthenticateRequest(req.Header.Get("Authorization"), r.did, r.store)
	if auth == nil {
		writeError(w, 401, "authentication required")
		return
	}

	chain, err := r.store.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}
	if chain == nil {
		writeError(w, 404, "content chain not found")
		return
	}

	// verify read credential unless caller is creator
	if auth.Iss != chain.State.CreatorDID {
		credHeader := req.Header.Get("X-Credential")
		if credErr := r.verifyReadCredential(auth, chain, contentID, credHeader); credErr != "" {
			writeError(w, 403, credErr)
			return
		}
	}

	// resolve documentCID for the requested ref
	var documentCID string
	operationFound := ref == "head"

	if ref == "head" {
		if chain.State.CurrentDocumentCID != nil {
			documentCID = *chain.State.CurrentDocumentCID
		}
	} else {
		for _, token := range chain.Log {
			header, payload, err := dfos.DecodeJWSUnsafe(token)
			if err != nil || header == nil || header.CID != ref {
				continue
			}
			operationFound = true
			if d, ok := payload["documentCID"].(string); ok {
				documentCID = d
			}
			break
		}
	}

	if !operationFound {
		writeError(w, 404, "operation not found in chain")
		return
	}
	if documentCID == "" {
		writeError(w, 404, "no document at this ref")
		return
	}

	blob, _ := r.store.GetBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: documentCID})
	if blob == nil {
		writeError(w, 404, "blob not found")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Document-Cid", documentCID)
	w.WriteHeader(200)
	w.Write(blob)
}

func (r *Relay) verifyReadCredential(auth *dfos.VerifiedAuthToken, chain *StoredContentChain, contentID, credHeader string) string {
	if credHeader == "" {
		return "DFOSContentRead credential required"
	}

	resolveKey := CreateCurrentKeyResolver(r.store)

	header, _, err := dfos.DecodeJWSUnsafe(credHeader)
	if err != nil || header == nil {
		return "invalid credential format"
	}
	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return "credential kid must be a DID URL"
	}

	vcIssuerDID := kid[:strings.Index(kid, "#")]
	if vcIssuerDID != chain.State.CreatorDID {
		return "credential must be issued by the chain creator"
	}

	// reject credentials from deleted issuers
	issuerIdentity, _ := r.store.GetIdentityChain(vcIssuerDID)
	if issuerIdentity != nil && issuerIdentity.State.IsDeleted {
		return "credential issuer identity is deleted"
	}

	creatorKey, err := resolveKey(kid)
	if err != nil {
		return fmt.Sprintf("failed to resolve credential key: %v", err)
	}

	credential, err := dfos.VerifyCredential(credHeader, creatorKey, auth.Iss, "DFOSContentRead")
	if err != nil {
		return err.Error()
	}

	if credential.Iss != chain.State.CreatorDID {
		return "credential issuer is not the chain creator"
	}

	if credential.ContentID != "" && credential.ContentID != contentID {
		return "credential contentId does not match"
	}

	return "" // no error
}

// ---------------------------------------------------------------------------
// utils
// ---------------------------------------------------------------------------

func parseLimit(req *http.Request, defaultLimit, maxLimit int) int {
	limitStr := req.URL.Query().Get("limit")
	if limitStr == "" {
		return defaultLimit
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}
