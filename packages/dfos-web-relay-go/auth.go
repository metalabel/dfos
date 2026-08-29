package relay

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// IDENTITY-PROOF AUTHENTICATION (AuthN) and DFOS credential verification (AuthZ)
// for relay requests.
//
// THE RELAY OWNS NO AUTHENTICATION GRAMMAR. Every authenticated request consumes
// the API-AUTH envelope family — "Authorization: DFOS <did:dfos:identity-proof
// JWS>" — verified by the reference helpers in dfos-protocol-go. The DID-signed
// JWT auth token this file used to carry is GONE: a bearer JWT with a
// self-chosen lifetime was a replayable credential for any request to any route,
// where an identity proof binds ONE method, host, path, and body inside a window
// the RELAY owns.
//
// Byte twin of packages/dfos-web-relay/src/auth.ts. See specs/WEB-RELAY.md
// "Authentication" and specs/API-AUTH.md "The Identity Proof".

const (
	// DefaultProofWindowSeconds is the acceptance window W — how old an identity
	// proof may be. "The freshness window is the relay's to own."
	DefaultProofWindowSeconds int64 = 60
	// DefaultProofSkewSeconds is the clock-skew allowance S.
	DefaultProofSkewSeconds int64 = 60
	// MaxJtiBytes caps the jti member.
	//
	// A replay cache keyed on a caller-chosen string is a caller-controlled memory
	// allocation, so the key needs a bound. 256 bytes is generous for any UUID,
	// ULID, or random token and is enforced IDENTICALLY by the TS twin — a jti one
	// relay accepts and the other refuses would fork the admission decision.
	MaxJtiBytes = 256
)

// ---------------------------------------------------------------------------
// current-state key resolution
// ---------------------------------------------------------------------------

// CreateCurrentStateProofResolver resolves an identity proof's kid to a CURRENT
// key of the presenter, from THIS relay's local store.
//
// CURRENT-STATE ONLY, deliberately (WEB-RELAY.md, Key Resolution): after a key
// rotation the old key immediately stops authenticating, which is how a
// presenter whose key is compromised revokes that key's ability to speak in its
// name. A deleted identity has no live-authentication standing at all.
//
// The verdict split is load-bearing. A non-canonical DID, a deleted identity,
// and a key absent from current state are all things this resolver CHECKED, so
// they wrap dfos.ErrProofPresenterInvalid and surface as 401. An unknown chain
// or a failed store read are things it could NOT check, so they stay bare and
// surface as 503 — the server's condition, never a judgment on the caller.
func CreateCurrentStateProofResolver(store Store) dfos.KeyResolver {
	return func(kid string) (ed25519.PublicKey, error) {
		hash := strings.Index(kid, "#")
		if hash < 0 {
			return nil, fmt.Errorf("%w: kid must be a DID URL", dfos.ErrProofPresenterInvalid)
		}
		did := kid[:hash]
		// Refused BEFORE the store read: a flood of garbage kids costs a regex,
		// never a lookup per request.
		if !isValidDfosDid(did) {
			return nil, fmt.Errorf("%w: kid does not name a canonical did:dfos",
				dfos.ErrProofPresenterInvalid)
		}
		identity, err := store.GetIdentityChain(did)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity chain: %w", err)
		}
		if identity == nil {
			return nil, fmt.Errorf("unknown identity: %s", did)
		}
		if identity.State.IsDeleted {
			return nil, fmt.Errorf("%w: presenter identity is deleted", dfos.ErrProofPresenterInvalid)
		}
		// Any CURRENT key role may sign a proof (API-AUTH.md, "Key resolution is
		// current-state") — auth, assert, or controller. keyFromState searches
		// exactly those three sets of the CURRENT state.
		publicKey, err := keyFromState(identity.State, kid[hash+1:])
		if err != nil {
			return nil, fmt.Errorf("%w: signing key is not a current key of the presenter",
				dfos.ErrProofPresenterInvalid)
		}
		return publicKey, nil
	}
}

// ---------------------------------------------------------------------------
// jti replay cache
// ---------------------------------------------------------------------------

// JtiCache is the replay cache a relay consumes — REQUIRED on every
// write-shaped proof (WEB-RELAY.md, Authentication).
//
// WHY A WRITE-SHAPED SURFACE CANNOT BORROW ITS REPLAY POSTURE FROM DOWNSTREAM
// IDEMPOTENCY: the admission ladder runs POLICY before full verification, so the
// relay grants admission-layer effects (quota spend, reputation attribution)
// before it knows whether the payload is a harmless duplicate. Ingestion being
// idempotent does not make a replayed submission free.
//
// The primitive is ATOMIC INSERT-IF-ABSENT (accept iff newly inserted), not the
// check-and-delete a server-minted nonce would use — the verifier never held the
// client-chosen jti beforehand. Entries expire after the freshness window
// (W + S): past that the proof itself is stale, so the entry protects nothing.
//
// It is an INTERFACE because the default implementation is per-process: a
// multi-process deployment injects one whose insert-if-absent is atomic across
// the fleet (RelayOptions.JtiCache). Twin of the TS JtiReplayCache interface.
type JtiCache interface {
	// InsertIfAbsent records (presenterDID, jti) if absent. It returns true when
	// newly inserted (the proof is fresh) and false when the pair was already seen
	// within its lifetime (a replay).
	InsertIfAbsent(presenterDID, jti string, now time.Time, ttl time.Duration) bool
}

// JtiReplayCache is the default JtiCache — in-memory and per-process.
type JtiReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewJtiReplayCache() *JtiReplayCache {
	return &JtiReplayCache{seen: make(map[string]time.Time)}
}

// InsertIfAbsent implements JtiCache.
func (c *JtiReplayCache) InsertIfAbsent(presenterDID, jti string, now time.Time, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Prune before the lookup, so an expired entry never reports a replay. The
	// map is small by construction (one window's worth of write-shaped proofs).
	for key, expiresAt := range c.seen {
		if !expiresAt.After(now) {
			delete(c.seen, key)
		}
	}
	// Newline-joined: a DID cannot contain one, so no (did, jti) pair can be
	// spelled two ways or collide with another pair's concatenation.
	key := presenterDID + "\n" + jti
	if expiresAt, exists := c.seen[key]; exists && expiresAt.After(now) {
		return false
	}
	c.seen[key] = now.Add(ttl)
	return true
}

// ---------------------------------------------------------------------------
// identity-proof authentication
// ---------------------------------------------------------------------------

// AuthenticatedPrincipal is a verified identity proof, as the routes consume it.
type AuthenticatedPrincipal struct {
	// DID is THE PRINCIPAL — the proof's kid DID. Who the request is from.
	DID string
	// Kid is the full DID URL, key fragment included.
	Kid string
	// Iat is the proof's issued-at, unix seconds.
	Iat int64
}

// authOutcome is what a route needs to decide: a principal, anonymity, or a
// refusal with its status and message.
type authOutcome struct {
	// Principal is nil for an anonymous request (no Authorization header).
	Principal *AuthenticatedPrincipal
	// Status is 0 when the request is authenticated or legitimately anonymous.
	Status int
	Error  string
}

// authenticateIdentityProof authenticates one request against the API-AUTH
// identity proof.
//
// It returns an anonymous outcome when NO Authorization header is present —
// anonymity is a valid admission mode on ingestion, and the caller decides
// whether its route permits it. A header that is present but not this family (a
// stale Bearer JWT, say) is a 401: the relay owns no other authentication
// grammar, and silently treating it as anonymous would hide a client that thinks
// it is authenticated from a relay that disagrees.
//
// requireJti marks a WRITE-SHAPED surface (ingestion, blob upload). Read-shaped
// surfaces (blob reads, the mailbox poll) rely on the freshness window alone,
// per API-AUTH's accepted within-window replay bound.
func (r *Relay) authenticateIdentityProof(req *http.Request, body []byte, requireJti bool) authOutcome {
	header := req.Header.Get("Authorization")
	if strings.TrimSpace(header) == "" {
		return authOutcome{}
	}
	token := dfos.ParseDFOSAuthorization(header)
	if token == "" {
		return authOutcome{Status: http.StatusUnauthorized, Error: "authentication required"}
	}
	if r.authority == "" {
		// A 503, never a 401 or a fallback: the host binding is the deployment's to
		// supply, and a relay that cannot supply it cannot authenticate ANYTHING.
		// Answering 401 would blame the caller for the operator's omission, and
		// reading the authority off the request would remove the binding entirely.
		return authOutcome{Status: http.StatusServiceUnavailable,
			Error: "relay authority is not configured; authenticated routes are unavailable"}
	}

	window, skew := r.proofWindowSeconds, r.proofSkewSeconds
	// THE VERIFIER'S HASH CAP IS THIS DEPLOYMENT'S TRANSPORT CAP, ALWAYS.
	//
	// MaxBodyBytes bounds the body the envelope verifier is willing to SHA-256,
	// and an over-cap body is an INVALID PROOF — which every caller below turns
	// into a bare `401 authentication required`. Leaving it nil takes the
	// library's MaxBodyBytesDefault (1 MiB) while the routes that reach here
	// buffer up to maxRequestBodyBytes (16 MiB), so every authenticated write
	// between those two numbers died at a 401 that said nothing about size —
	// silently, deterministically, at exactly 1 MiB + 1.
	//
	// The two numbers are one number. body is ALREADY bounded before it arrives:
	// each route caps its own read with http.MaxBytesReader, so the cap is a
	// belt-and-braces bound on an in-hand buffer, never the thing that lets an
	// unbounded body through. Routes with a TIGHTER read cap (the signing
	// deposit/response bodies) stay bounded by their own reader; what must never
	// happen again is a verifier refusing bytes a route already accepted.
	verified, err := dfos.VerifyIdentityProof(token, dfos.IdentityProofExpectations{
		Method:        req.Method,
		Host:          r.authority,
		Path:          originFormTarget(req),
		Body:          body,
		WindowSeconds: dfos.Int64Ptr(window),
		SkewSeconds:   dfos.Int64Ptr(skew),
		MaxBodyBytes:  dfos.Int64Ptr(maxRequestBodyBytes),
	}, CreateCurrentStateProofResolver(r.readStore), time.Now())
	if err != nil {
		if errors.Is(err, dfos.ErrIdentityProofInvalid) {
			return authOutcome{Status: http.StatusUnauthorized, Error: "authentication required"}
		}
		// unverifiable and config both answer 503: neither is a judgment about the
		// caller, and a config verdict is the operator's condition to fix.
		return authOutcome{Status: http.StatusServiceUnavailable, Error: "authentication unavailable"}
	}

	if requireJti {
		// jti is an UNKNOWN member to the envelope verifier (MUST-ignore-unknown),
		// read here, AFTER verification, off the decoded payload the signature
		// already covers. The canonical member set stays closed.
		jti, ok := verified.RawPayload["jti"].(string)
		if !ok || jti == "" || len(jti) > MaxJtiBytes {
			return authOutcome{Status: http.StatusUnauthorized, Error: "authentication required"}
		}
		ttl := time.Duration(window+skew) * time.Second
		if !r.jtiCache.InsertIfAbsent(verified.PresenterDID, jti, time.Now(), ttl) {
			return authOutcome{Status: http.StatusUnauthorized, Error: "authentication required"}
		}
	}

	return authOutcome{Principal: &AuthenticatedPrincipal{
		DID: verified.PresenterDID,
		Kid: verified.Kid,
		Iat: verified.Payload.Iat,
	}}
}

// originFormTarget returns the ORIGIN-FORM request target — path plus query
// string, byte for byte, as the request line carried it.
//
// This is what an identity proof's `path` binds, and it is deliberately NOT a
// route template and NOT a normalization: no percent-decoding, no query
// reordering, no trailing-slash equivalence. req.RequestURI is the raw target
// the server read off the wire and is preferred for exactly that reason;
// URL.RequestURI() is the fallback for a request built in-process (httptest's
// NewRequest leaves RequestURI empty).
func originFormTarget(req *http.Request) string {
	// Only an ORIGIN-FORM RequestURI is usable: it is the raw target the server
	// read off the wire, which is exactly what the signer bound. Anything else
	// (absolute-form, as a proxy or an in-process test request may carry) is
	// re-derived from the parsed URL, which yields the same origin-form string.
	if strings.HasPrefix(req.RequestURI, "/") {
		return req.RequestURI
	}
	return req.URL.RequestURI()
}

// ---------------------------------------------------------------------------
// public standing auth
// ---------------------------------------------------------------------------

// hasPublicStandingAuth checks if a valid public standing credential exists
// for the given content. Verifies expiry and revocation.
//
// Store-scoped (mirrors the TS twin hasPublicStandingAuth(contentId, action,
// store)): the HTTP read path passes r.readStore (never races on the ingestion
// tx); ingest-time index maintenance passes the ingestion store so the recompute
// sees the same within-batch uncommitted writes the op just made.
func hasPublicStandingAuth(contentID string, action string, store Store) bool {
	resource := "chain:" + contentID
	publicCreds, _ := store.GetPublicCredentials(resource)
	resolveKey := CreateKeyResolver(store)

	chain, _ := store.GetContentChain(contentID)
	if chain == nil {
		return false
	}

	for _, credJws := range publicCreds {
		if err := verifyCredentialForAccess(credJws, resolveKey, resource, action, chain.State.CreatorDID, "", store, true); err == nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// content access verification
// ---------------------------------------------------------------------------

// verifyContentAccess checks whether a requester has access to a resource.
// Returns "" if access is granted, or an error message string if denied.
//
// Checks in order:
// 1. Creator always has access
// 2. Stored public credentials (standing authorization)
// 3. Per-request credential (X-Credential header)
//
// allowPublicGrant governs whether public (aud "*") grants count. A standing
// public grant asserts the publicness of a chain's CURRENT head only, so a
// request for a non-head document passes false: access then requires the creator
// or a credential scoped to the requester's audience — never a public grant,
// whether stored (step 2) or presented (step 3).
func (r *Relay) verifyContentAccess(requesterDID string, creatorDID string, requestedResource string, action string, credentialJWS string, allowPublicGrant bool) string {
	// 1. creator always has access
	if requesterDID != "" && requesterDID == creatorDID {
		return ""
	}

	// readStore: key resolution runs on the HTTP read path, never races on tx.
	store := r.readStore
	resolveKey := CreateKeyResolver(store)

	// 2. check stored public credentials — standing public (aud "*") grants,
	// skipped for a non-head request.
	if allowPublicGrant {
		publicCreds, _ := store.GetPublicCredentials(requestedResource)
		for _, credJws := range publicCreds {
			if err := verifyCredentialForAccess(credJws, resolveKey, requestedResource, action, creatorDID, "", store, true); err == nil {
				return ""
			}
		}
	}

	// 3. check per-request credential
	if credentialJWS != "" {
		if err := verifyCredentialForAccess(credentialJWS, resolveKey, requestedResource, action, creatorDID, requesterDID, store, allowPublicGrant); err != nil {
			return err.Error()
		}
		return ""
	}

	return "read credential required"
}

// verifyCredentialForAccess verifies a single credential for resource access.
// It verifies the signature, checks revocation, checks resource+action match,
// and verifies the delegation chain.
//
// For public credentials (aud="*"), requesterDID can be empty.
// For per-request credentials, requesterDID is checked against aud.
// allowPublicGrant=false rejects public (aud="*") credentials outright — a
// non-head read may not be granted by a public grant presented as a bearer.
func verifyCredentialForAccess(credJws string, resolveKey dfos.KeyResolver, requestedResource string, action string, creatorDID string, requesterDID string, store Store, allowPublicGrant bool) error {
	// decode to get kid and raw payload
	header, payload, err := dfos.DecodeJWSUnsafe(credJws)
	if err != nil || header == nil {
		return fmt.Errorf("invalid credential format")
	}

	kid := header.Kid
	if kid == "" || !strings.Contains(kid, "#") {
		return fmt.Errorf("credential kid must be a DID URL")
	}

	issuerDID := kid[:strings.Index(kid, "#")]

	// check issuer identity is not deleted. A store failure is NOT "not deleted":
	// an authorization gate that cannot be evaluated denies (mirrors
	// verifySigningCredential in signing.go, which propagates the same call).
	issuerIdentity, err := store.GetIdentityChain(issuerDID)
	if err != nil {
		return fmt.Errorf("failed to check credential issuer identity: %v", err)
	}
	if issuerIdentity != nil && issuerIdentity.State.IsDeleted {
		return fmt.Errorf("credential issuer identity is deleted")
	}

	// resolve signing key and verify credential signature + structure
	publicKey, err := resolveKey(kid)
	if err != nil {
		return fmt.Errorf("failed to resolve credential key: %v", err)
	}

	// VerifyCredential checks signature, CID integrity, temporal validity, kid
	// We pass empty string for subject to skip audience check (we do it manually)
	// and empty string for expectedType to accept any action type
	verified, err := dfos.VerifyCredential(credJws, publicKey, "", "")
	if err != nil {
		return err
	}

	// check leaf revocation — timeless (asOf 0), the live read-path question.
	// A lookup that FAILS is not an answer of "not revoked": deny.
	revoked, err := store.IsCredentialRevoked(verified.Iss, verified.CID, 0)
	if err != nil {
		return fmt.Errorf("failed to check credential revocation: %v", err)
	}
	if revoked {
		return fmt.Errorf("credential is revoked")
	}

	// parse att from raw payload for resource matching and delegation
	att := dfos.ParseAtt(payload)

	// check resource + action match
	if !matchesResource(att, requestedResource, action) {
		return fmt.Errorf("credential does not cover requested resource")
	}

	// audience check. A public (aud "*") credential is a bearer capability —
	// rejected outright when public grants are disallowed (non-head reads). A
	// scoped credential must name the requester as its audience.
	aud, _ := payload["aud"].(string)
	if aud == "*" {
		if !allowPublicGrant {
			return fmt.Errorf("public credential does not grant access to this resource")
		}
	} else if requesterDID == "" || aud != requesterDID {
		return fmt.Errorf("credential audience does not match requester")
	}

	// verify delegation chain — shared with the write path via the protocol
	// library's linear (single-parent) walk. The relay no longer maintains its
	// own copy: the previous copy unioned the att of ALL parents and recursed
	// only through parents[0], which let a self-issued secondary parent contribute
	// scope never rooted at the creator (a multi-parent authority-escalation the
	// library walk and the TS stack reject). Closures bind the read-store
	// revocation + issuer-deletion checks; leaf revocation/deletion is checked
	// above (the walk covers parents only).
	prf, err := dfos.ParsePrf(payload)
	if err != nil {
		return fmt.Errorf("credential prf invalid: %v", err)
	}
	// asOf = 0 (timeless) at every hop: a read is a live, ephemeral decision that
	// never enters the replicated log, so it asks the FRESHNESS question — "is this
	// credential revoked as far as we know right now?" — exactly as before. The
	// as-of basis belongs to verification of committed history, not to read-path
	// authorization.
	//
	// Both closures PROPAGATE store errors rather than answering "not revoked" /
	// "not deleted" — VerifyDelegationChain turns a callback error into a chain
	// verification failure, so a gate the relay could not evaluate denies the
	// read instead of silently authorizing it. Same shape as signing.go.
	isRevoked := func(issuerDID, credentialCID string, _ int64) (bool, error) {
		return store.IsCredentialRevoked(issuerDID, credentialCID, 0)
	}
	isDeleted := func(did string) (bool, error) {
		idc, err := store.GetIdentityChain(did)
		if err != nil {
			return false, err
		}
		return idc != nil && idc.State.IsDeleted, nil
	}
	if err := dfos.VerifyDelegationChain(credJws, verified, att, prf, resolveKey, creatorDID, isRevoked, isDeleted, 0); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------
// resource matching
// ---------------------------------------------------------------------------

// matchesResource checks if an att array covers a requested resource+action.
func matchesResource(att []dfos.AttEntry, resource string, action string) bool {
	reqType, reqID, ok := dfos.ParseResource(resource)
	if !ok {
		return false
	}
	reqActions := dfos.ParseActions(action)

	for _, entry := range att {
		entryType, entryID, ok := dfos.ParseResource(entry.Resource)
		if !ok {
			continue
		}
		entryActions := dfos.ParseActions(entry.Action)

		// check action coverage — all requested actions must be in entry actions
		actionsCovered := true
		for a := range reqActions {
			if !entryActions[a] {
				actionsCovered = false
				break
			}
		}
		if !actionsCovered {
			continue
		}

		// chain:* covers any chain: request
		if entryType == "chain" && entryID == "*" && reqType == "chain" {
			return true
		}

		// exact resource match
		if entryType == reqType && entryID == reqID {
			return true
		}

	}

	return false
}
