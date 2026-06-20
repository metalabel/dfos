package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// maxRequestBodyBytes caps the size of request bodies that buffer the whole
// payload in memory (POST /operations, PUT blob). Defined once and shared by
// both routes. The .max(100) item check and the documentCID match fire only
// AFTER a full decode/read, so without this cap the bytes are unbounded — an
// unauthenticated client could OOM the relay with one huge POST.
const maxRequestBodyBytes = 16 << 20 // 16 MB

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
	mux.HandleFunc("GET /content/{contentId}/documents", r.handleGetDocuments)
	mux.HandleFunc("GET /content/{contentId}/log", r.handleContentLog)
	mux.HandleFunc("GET /content/{contentId}/blob/{ref}", r.handleGetBlob)
	mux.HandleFunc("GET /content/{contentId}/blob", r.handleGetBlobHead)
	mux.HandleFunc("PUT /content/{contentId}/blob/{operationCID}", r.handlePutBlob)
	mux.HandleFunc("GET /content/{contentId}", r.handleGetContent)
	mux.HandleFunc("GET /countersignatures/{cid}", r.handleGetCountersignatures)
	mux.HandleFunc("GET /log", r.handleGetLog)

	return mux
}

// withCORS wraps a handler with a permissive CORS policy so browser clients can
// read the public proof plane cross-origin. The policy is kept byte-for-byte in
// sync with the TS relay: Allow-Origin *, Allow-Methods GET, POST, PUT, OPTIONS,
// Allow-Headers Content-Type, Authorization, and 204 on preflight.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if req.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, req)
	})
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
		"version":  Version,
		"capabilities": map[string]any{
			"proof":     true,
			"content":   r.contentEnabled,
			"log":       r.logEnabled,
			"documents": r.contentEnabled,
		},
		"profile": r.profileArtifactJWS,
	})
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

func (r *Relay) handlePostOperations(w http.ResponseWriter, req *http.Request) {
	// DoS cap: bound the body before decoding. A MaxBytesError surfaces as a
	// decode error and flows through the existing 400 path.
	req.Body = http.MaxBytesReader(w, req.Body, maxRequestBodyBytes)
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
	op, err := r.readStore.GetOperation(cid)
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
	chain, err := r.readStore.GetIdentityChain(did)
	if storeErr(w, err) {
		return
	}

	// read-through: try peers on local miss (paginate through full log)
	if chain == nil && r.peerClient != nil {
		for _, peer := range r.peers {
			if peer.ReadThrough != nil && !*peer.ReadThrough {
				continue
			}
			after := ""
			for {
				page, err := r.peerClient.GetIdentityLog(peer.URL, did, after, 1000)
				if err != nil || page == nil || len(page.Entries) == 0 {
					break
				}
				tokens := make([]string, len(page.Entries))
				for i, e := range page.Entries {
					tokens[i] = e.JWSToken
				}
				r.Ingest(tokens)
				if page.Cursor == nil {
					break
				}
				after = *page.Cursor
			}
			chain, _ = r.readStore.GetIdentityChain(did)
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
	chain, err := r.readStore.GetIdentityChain(did)
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
	chain, err := r.readStore.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}

	// read-through: try peers on local miss (paginate through full log)
	if chain == nil && r.peerClient != nil {
		for _, peer := range r.peers {
			if peer.ReadThrough != nil && !*peer.ReadThrough {
				continue
			}
			after := ""
			for {
				page, err := r.peerClient.GetContentLog(peer.URL, contentID, after, 1000)
				if err != nil || page == nil || len(page.Entries) == 0 {
					break
				}
				tokens := make([]string, len(page.Entries))
				for i, e := range page.Entries {
					tokens[i] = e.JWSToken
				}
				r.Ingest(tokens)
				if page.Cursor == nil {
					break
				}
				after = *page.Cursor
			}
			chain, _ = r.readStore.GetContentChain(contentID)
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
	chain, err := r.readStore.GetContentChain(contentID)
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

	op, err := r.readStore.GetOperation(cid)
	if storeErr(w, err) {
		return
	}
	if op == nil {
		cs, csErr := r.readStore.GetCountersignatures(cid)
		if storeErr(w, csErr) {
			return
		}
		if len(cs) == 0 {
			writeError(w, 404, "not found")
			return
		}
		writeJSON(w, 200, map[string]any{
			"cid":               cid,
			"countersignatures": cs,
		})
		return
	}

	cs, csErr := r.readStore.GetCountersignatures(cid)
	if storeErr(w, csErr) {
		return
	}
	writeJSON(w, 200, map[string]any{
		"operationCID":      cid,
		"countersignatures": cs,
	})
}

func (r *Relay) handleOperationCountersignatures(w http.ResponseWriter, req *http.Request) {
	cid := req.PathValue("cid")

	op, err := r.readStore.GetOperation(cid)
	if storeErr(w, err) {
		return
	}
	if op == nil {
		writeError(w, 404, "not found")
		return
	}

	cs, csErr := r.readStore.GetCountersignatures(cid)
	if storeErr(w, csErr) {
		return
	}
	writeJSON(w, 200, map[string]any{
		"operationCID":      cid,
		"countersignatures": cs,
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

	entries, cursor, err := r.readStore.ReadLog(after, limit)
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

	// authenticate — use readStore so the auth read never races on the
	// ingestion store's active write transaction (tx aliasing).
	auth := AuthenticateRequest(req.Header.Get("Authorization"), r.did, r.readStore, r.maxAuthTokenTTL)
	if auth == nil {
		writeError(w, 401, "authentication required")
		return
	}

	// verify chain exists
	chain, err := r.readStore.GetContentChain(contentID)
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

	// read blob bytes (capped at 16 MB, shared with POST /operations) and verify
	// they match documentCID
	req.Body = http.MaxBytesReader(w, req.Body, maxRequestBodyBytes)
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

	// Hold ingestMu for the write: the ingestion store's writerDB() aliases the
	// active batch transaction, which ingest/sequencer mutate under ingestMu.
	// Writing here without the lock races on s.tx. Propagate the error instead
	// of discarding it and returning an unconditional 200.
	r.ingestMu.Lock()
	putErr := r.store.PutBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: documentCID}, bytes)
	r.ingestMu.Unlock()
	if storeErr(w, putErr) {
		return
	}

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

// authorizeRead checks if the request is authorized to read the given content.
// Returns true if authorized. Writes 401/403 error response and returns false if not.
// Allows unauthenticated access when a valid public standing credential exists.
func (r *Relay) authorizeRead(w http.ResponseWriter, req *http.Request, contentID string, creatorDID string) bool {
	if r.hasPublicStandingAuth(contentID, "read") {
		return true
	}
	auth := AuthenticateRequest(req.Header.Get("Authorization"), r.did, r.readStore, r.maxAuthTokenTTL)
	if auth == nil {
		writeError(w, 401, "authentication required")
		return false
	}
	credHeader := req.Header.Get("X-Credential")
	if errMsg := r.verifyContentAccess(auth.Iss, creatorDID, "chain:"+contentID, "read", credHeader); errMsg != "" {
		writeError(w, 403, errMsg)
		return false
	}
	return true
}

func (r *Relay) readBlob(w http.ResponseWriter, req *http.Request, contentID, ref string) {
	chain, err := r.readStore.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}
	if chain == nil {
		writeError(w, 404, "content chain not found")
		return
	}

	if !r.authorizeRead(w, req, contentID, chain.State.CreatorDID) {
		return
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

	blob, _ := r.readStore.GetBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: documentCID})
	if blob == nil {
		writeError(w, 404, "blob not found")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Document-Cid", documentCID)
	w.WriteHeader(200)
	w.Write(blob)
}

// ---------------------------------------------------------------------------
// documents
// ---------------------------------------------------------------------------

func (r *Relay) handleGetDocuments(w http.ResponseWriter, req *http.Request) {
	if !r.contentEnabled {
		writeError(w, 501, "content plane not available")
		return
	}
	contentID := req.PathValue("contentId")

	// verify chain exists
	chain, err := r.readStore.GetContentChain(contentID)
	if storeErr(w, err) {
		return
	}
	if chain == nil {
		writeError(w, 404, "not found")
		return
	}

	if !r.authorizeRead(w, req, contentID, chain.State.CreatorDID) {
		return
	}

	after := req.URL.Query().Get("after")
	limit := parseLimit(req, 100, 1000)

	docs, cursor, err := r.readStore.GetDocuments(contentID, after, limit)
	if storeErr(w, err) {
		return
	}

	var cursorPtr *string
	if cursor != "" {
		cursorPtr = &cursor
	}

	writeJSON(w, 200, map[string]any{
		"contentId":  contentID,
		"documents":  docs,
		"nextCursor": cursorPtr,
	})
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
