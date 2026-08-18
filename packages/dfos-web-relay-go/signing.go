package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

const (
	maxSigningDepositBody  = 524288
	maxSigningResponse     = 8192
	maxSigningResponseBody = maxSigningResponse + 512
	maxSigningDeclineBody  = 512
)

type bundledSigningIdentity struct {
	state dfos.IdentityState
	log   []string
}

func (r *Relay) signingMailboxStore() SigningStore {
	return r.readStore.(SigningStore)
}

func verifySigningBundle(tokens []string) (map[string]bundledSigningIdentity, error) {
	grouped := make(map[string][]string)
	for _, token := range tokens {
		header, payload, err := dfos.DecodeJWSUnsafe(token)
		if err != nil || header == nil {
			return nil, fmt.Errorf("invalid identity operation in bundle")
		}
		var did string
		if typ, _ := payload["type"].(string); typ == "create" {
			result, err := dfos.VerifyIdentityChain([]string{token})
			if err != nil {
				return nil, err
			}
			did = result.State.DID
		} else {
			hash := strings.Index(header.Kid, "#")
			if hash < 0 {
				return nil, fmt.Errorf("invalid identity operation kid in bundle")
			}
			did = header.Kid[:hash]
		}
		grouped[did] = append(grouped[did], token)
	}

	verified := make(map[string]bundledSigningIdentity)
	for did, log := range grouped {
		result, err := dfos.VerifyIdentityChain(log)
		if err != nil {
			return nil, err
		}
		if result.State.DID != did {
			return nil, fmt.Errorf("identity bundle DID mismatch")
		}
		verified[did] = bundledSigningIdentity{state: result.State, log: log}
	}
	return verified, nil
}

func keyFromState(state dfos.IdentityState, keyID string) (ed25519.PublicKey, error) {
	keys := make([]dfos.MultikeyPublicKey, 0, len(state.AuthKeys)+len(state.AssertKeys)+len(state.ControllerKeys))
	keys = append(keys, state.AuthKeys...)
	keys = append(keys, state.AssertKeys...)
	keys = append(keys, state.ControllerKeys...)
	for _, key := range keys {
		if key.ID == keyID {
			return dfos.DecodeMultikey(key.PublicKeyMultibase)
		}
	}
	return nil, fmt.Errorf("unknown key %s", keyID)
}

func signingBundleKey(identity bundledSigningIdentity, kid string, historical bool) (ed25519.PublicKey, error) {
	hash := strings.Index(kid, "#")
	if hash < 0 || kid[:hash] != identity.state.DID {
		return nil, fmt.Errorf("invalid kid")
	}
	keyID := kid[hash+1:]
	if key, err := keyFromState(identity.state, keyID); err == nil {
		return key, nil
	}
	if historical {
		for _, token := range identity.log {
			_, payload, err := dfos.DecodeJWSUnsafe(token)
			if err != nil {
				continue
			}
			for _, role := range []string{"authKeys", "assertKeys", "controllerKeys"} {
				entries, _ := payload[role].([]any)
				for _, raw := range entries {
					entry, _ := raw.(map[string]any)
					if id, _ := entry["id"].(string); id == keyID {
						multibase, _ := entry["publicKeyMultibase"].(string)
						return dfos.DecodeMultikey(multibase)
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("unknown key %s", keyID)
}

func signingResolvers(store Store, bundle map[string]bundledSigningIdentity) (dfos.KeyResolver, dfos.KeyResolver) {
	localCurrent := CreateCurrentKeyResolver(store)
	localHistorical := CreateKeyResolver(store)
	current := func(kid string) (ed25519.PublicKey, error) {
		hash := strings.Index(kid, "#")
		if hash < 0 {
			return nil, fmt.Errorf("invalid kid")
		}
		if local, _ := store.GetIdentityChain(kid[:hash]); local != nil {
			if local.State.IsDeleted {
				return nil, fmt.Errorf("identity deleted")
			}
			return localCurrent(kid)
		}
		identity, ok := bundle[kid[:hash]]
		if !ok || identity.state.IsDeleted {
			return nil, fmt.Errorf("identity unavailable")
		}
		return signingBundleKey(identity, kid, false)
	}
	historical := func(kid string) (ed25519.PublicKey, error) {
		hash := strings.Index(kid, "#")
		if hash < 0 {
			return nil, fmt.Errorf("invalid kid")
		}
		if local, _ := store.GetIdentityChain(kid[:hash]); local != nil {
			return localHistorical(kid)
		}
		identity, ok := bundle[kid[:hash]]
		if !ok || identity.state.IsDeleted {
			return nil, fmt.Errorf("identity unavailable")
		}
		return signingBundleKey(identity, kid, true)
	}
	return current, historical
}

func mailboxDepositCovered(att []dfos.AttEntry, subject string) bool {
	resource := "mailbox:" + strings.TrimPrefix(subject, "did:dfos:")
	exact := make([]dfos.AttEntry, 0, len(att))
	for _, entry := range att {
		if entry.Resource == resource {
			exact = append(exact, entry)
		}
	}
	return matchesResource(exact, resource, "deposit")
}

func (r *Relay) verifySigningCredential(token string, request *dfos.VerifiedSignRequest, resolveKey dfos.KeyResolver, bundle map[string]bundledSigningIdentity) error {
	header, payload, err := dfos.DecodeJWSUnsafe(token)
	if err != nil || header == nil || !strings.Contains(header.Kid, "#") {
		return fmt.Errorf("invalid credential")
	}
	issuer := header.Kid[:strings.Index(header.Kid, "#")]
	if local, _ := r.readStore.GetIdentityChain(issuer); local != nil && local.State.IsDeleted {
		return fmt.Errorf("issuer deleted")
	}
	if identity, ok := bundle[issuer]; ok && identity.state.IsDeleted {
		return fmt.Errorf("issuer deleted")
	}
	key, err := resolveKey(header.Kid)
	if err != nil {
		return err
	}
	verified, err := dfos.VerifyCredential(token, key, "", "")
	if err != nil {
		return err
	}
	revoked, err := r.readStore.IsCredentialRevoked(verified.Iss, verified.CID, 0)
	if err != nil || revoked {
		return fmt.Errorf("credential revoked")
	}
	att := dfos.ParseAtt(payload)
	prf, err := dfos.ParsePrf(payload)
	if err != nil {
		return err
	}
	isRevoked := func(issuerDID, credentialCID string, _ int64) (bool, error) {
		return r.readStore.IsCredentialRevoked(issuerDID, credentialCID, 0)
	}
	isDeleted := func(did string) (bool, error) {
		if local, err := r.readStore.GetIdentityChain(did); err != nil {
			return false, err
		} else if local != nil {
			return local.State.IsDeleted, nil
		}
		identity, ok := bundle[did]
		return ok && identity.state.IsDeleted, nil
	}
	if err := dfos.VerifyDelegationChain(token, verified, att, prf, resolveKey, request.Subject, isRevoked, isDeleted, 0); err != nil {
		return err
	}
	if verified.Aud != "*" && verified.Aud != request.DID {
		return fmt.Errorf("credential audience mismatch")
	}
	if !mailboxDepositCovered(att, request.Subject) {
		return fmt.Errorf("credential does not cover mailbox deposit")
	}
	return nil
}

func (r *Relay) handleSigningDeposit(w http.ResponseWriter, req *http.Request) {
	if !r.signingEnabled {
		writeError(w, http.StatusNotImplemented, "signing mailbox not available")
		return
	}
	if req.ContentLength > maxSigningDepositBody {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, maxSigningDepositBody)
	var body struct {
		Request    string   `json:"request"`
		Credential string   `json:"credential"`
		Chain      []string `json:"chain"`
	}
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&body); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
		}
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || body.Request == "" || body.Credential == "" {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	bundle, err := verifySigningBundle(body.Chain)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identity chain bundle")
		return
	}
	current, historical := signingResolvers(r.readStore, bundle)
	verified, err := dfos.VerifySignRequest(body.Request, current, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid sign request")
		return
	}
	subject, err := r.readStore.GetIdentityChain(verified.Subject)
	if storeErr(w, err) {
		return
	}
	if subject == nil || subject.State.IsDeleted {
		writeError(w, http.StatusNotFound, "subject identity not found")
		return
	}
	if err := r.verifySigningCredential(body.Credential, verified, historical, bundle); err != nil {
		writeError(w, http.StatusForbidden, "deposit credential rejected")
		return
	}
	now := time.Now().UTC()
	result, err := r.signingMailboxStore().PutSignRequest(StoredSignRequest{
		CID: verified.RequestCID, Request: body.Request, RequesterDID: verified.DID,
		SubjectDID: verified.Subject, PayloadTyp: verified.PayloadTyp,
		PayloadBytes: append([]byte(nil), verified.PayloadBytes...), ExpiresAt: verified.ExpiresAt,
		DepositedAt: now.Format(signingTimeFormat), Declined: false,
	}, now)
	if storeErr(w, err) {
		return
	}
	if result == SigningConflict {
		writeError(w, http.StatusConflict, "request CID conflict")
		return
	}
	if result == SigningAtCapacity {
		writeError(w, http.StatusTooManyRequests, "signing mailbox pending limit reached")
		return
	}
	status := http.StatusCreated
	if result == SigningIdentical {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]string{"cid": verified.RequestCID, "expiresAt": verified.ExpiresAt})
}

func (r *Relay) handleSigningPoll(w http.ResponseWriter, req *http.Request) {
	if !r.signingEnabled {
		writeError(w, http.StatusNotImplemented, "signing mailbox not available")
		return
	}
	auth := AuthenticateRequest(req.Header.Get("Authorization"), r.did, r.readStore, r.maxAuthTokenTTL)
	if auth == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	after := req.URL.Query().Get("after")
	limit := parseLimit(req, 100, 1000)
	requests, nextCursor, err := r.signingMailboxStore().ListPendingSignRequests(auth.Iss, after, limit, time.Now())
	if errors.Is(err, ErrInvalidSigningCursor) {
		writeError(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	if storeErr(w, err) {
		return
	}
	type item struct {
		CID         string `json:"cid"`
		Request     string `json:"request"`
		DepositedAt string `json:"depositedAt"`
		Declined    bool   `json:"declined"`
	}
	items := make([]item, len(requests))
	for i, request := range requests {
		items[i] = item{request.CID, request.Request, request.DepositedAt, request.Declined}
	}
	var next any
	if nextCursor != "" {
		next = nextCursor
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": items, "next": next})
}

func decodeCanonicalSigningResponse(token string) (*dfos.JWSHeader, []byte, error) {
	if len(token) > maxSigningResponse {
		return nil, nil, fmt.Errorf("response too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWS")
	}
	decoded := make([][]byte, len(parts))
	for i, part := range parts {
		segment, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(segment) != part {
			return nil, nil, fmt.Errorf("non-canonical JWS segment")
		}
		decoded[i] = segment
	}
	var header dfos.JWSHeader
	if err := json.Unmarshal(decoded[0], &header); err != nil {
		return nil, nil, err
	}
	if header.Typ == "" || header.Kid == "" {
		return nil, nil, fmt.Errorf("invalid response header")
	}
	return &header, decoded[1], nil
}

func (r *Relay) verifySigningResponse(token string, request *StoredSignRequest) error {
	header, payload, err := decodeCanonicalSigningResponse(token)
	if err != nil {
		return err
	}
	if header.Typ != request.PayloadTyp {
		return fmt.Errorf("response typ mismatch")
	}
	hash := strings.Index(header.Kid, "#")
	if hash < 0 || header.Kid[:hash] != request.SubjectDID {
		return fmt.Errorf("response subject mismatch")
	}
	if !bytes.Equal(payload, request.PayloadBytes) {
		return fmt.Errorf("response payload mismatch")
	}
	key, err := CreateKeyResolver(r.readStore)(header.Kid)
	if err != nil {
		return err
	}
	_, _, err = dfos.VerifyJWS(token, key)
	return err
}

func (r *Relay) handleSigningRespond(w http.ResponseWriter, req *http.Request) {
	if !r.signingEnabled {
		writeError(w, http.StatusNotImplemented, "signing mailbox not available")
		return
	}
	now := time.Now()
	request, err := r.signingMailboxStore().GetSignRequest(req.PathValue("cid"), now)
	if storeErr(w, err) {
		return
	}
	if request == nil {
		writeError(w, http.StatusNotFound, "sign request not found")
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, maxSigningResponseBody)
	var body struct {
		Response string `json:"response"`
	}
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&body); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid response")
		}
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid response")
		}
		return
	}
	if body.Response == "" {
		writeError(w, http.StatusBadRequest, "invalid response")
		return
	}
	if err := r.verifySigningResponse(body.Response, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid response")
		return
	}
	result, err := r.signingMailboxStore().PutSignResponse(request.CID, body.Response, time.Now())
	if storeErr(w, err) {
		return
	}
	if result == SigningNotFound {
		writeError(w, http.StatusNotFound, "sign request not found")
		return
	}
	if result == SigningConflict {
		writeError(w, http.StatusConflict, "response already exists")
		return
	}
	status := http.StatusCreated
	if result == SigningIdentical {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]string{"status": "stored"})
}

func (r *Relay) handleSigningGetResponse(w http.ResponseWriter, req *http.Request) {
	if !r.signingEnabled {
		writeError(w, http.StatusNotImplemented, "signing mailbox not available")
		return
	}
	request, err := r.signingMailboxStore().GetSignRequest(req.PathValue("cid"), time.Now())
	if storeErr(w, err) {
		return
	}
	if request == nil {
		writeError(w, http.StatusNotFound, "sign request not found")
		return
	}
	if request.Response != "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "responded", "response": request.Response})
		return
	}
	if request.Declined {
		writeJSON(w, http.StatusOK, map[string]string{"status": "declined"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
}

func (r *Relay) handleSigningDecline(w http.ResponseWriter, req *http.Request) {
	if !r.signingEnabled {
		writeError(w, http.StatusNotImplemented, "signing mailbox not available")
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, maxSigningDeclineBody)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid request body")
		}
		return
	}
	if len(bytes.TrimSpace(body)) != 0 {
		writeError(w, http.StatusBadRequest, "request body must be empty")
		return
	}
	result, err := r.signingMailboxStore().DeclineSignRequest(req.PathValue("cid"), time.Now())
	if storeErr(w, err) {
		return
	}
	if result == SigningNotFound {
		writeError(w, http.StatusNotFound, "sign request not found")
		return
	}
	if result == SigningConflict {
		writeError(w, http.StatusConflict, "response already exists")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
