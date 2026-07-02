package relay

// REVOCATION STATUS (Go twin)
//
// Pure, read-only projection of the relay's revocation set — the same
// (issuerDID, credentialCID) index credential enforcement already consults —
// into the `/revocations/v1` route family. Revocations remain ordinary
// proof-plane ops (kind "revocation", ingested via POST /proof/v1/operations,
// gossiped); this is an additive read surface at the relay ROOT on its own
// version clock, exactly like the universal resolver at /1.0/identifiers/{did}.
// Byte twin of the TS reference in packages/dfos-web-relay/src/revocations.ts —
// keep the two in lockstep.
//
// Key principle: every positive answer carries the revocation JWS itself, so a
// zero-trust caller re-verifies (signature, CID integrity, kid-DID == payload
// did, issuer-only rule) instead of trusting the relay's boolean. The boolean
// is a convenience; the JWS is the proof.
//
// Absence semantics are HONEST: `revoked: false` means "this relay has not
// ingested a revocation for this CID" — it is NOT proof of non-revocation. A
// relay can only attest to what it has seen (and can withhold); querying a
// quorum of relays is the client-side mitigation.
//
// RAW-BYTE NOTE: responses are emitted via structs in TS field-declaration
// order, so raw curl output byte-matches the TS twin (same trick as
// did_document.go).

import (
	"net/http"
	"regexp"
)

// revocationsBasePath namespaces the revocation-status routes on their own 0.x
// clock (NOT the frozen /proof/v1 proof plane). Additive relay
// reference-implementation surface; MUST stay in byte-sync with the TS relay
// (REVOCATIONS_BASE_PATH in revocations.ts).
const revocationsBasePath = "/revocations/v1"

// credentialCidRe mirrors revocations.ts CREDENTIAL_CID_RE: a credential CID is
// a CIDv1 dag-cbor + sha256 identifier — the fixed `bafyrei` head + 52 base32
// chars (same shape the protocol pins for artifact anchors). Any other length
// or charset is not a credential CID this index could ever hold — the routes
// reject it with 400 instead of answering a well-formed-looking `revoked: false`.
var credentialCidRe = regexp.MustCompile(`^bafyrei[a-z2-7]{52}$`)

func isValidCredentialCid(cid string) bool { return credentialCidRe.MatchString(cid) }

// -----------------------------------------------------------------------------
// response shapes (fields in TS insertion order)
// -----------------------------------------------------------------------------

// credentialRevocationStatus is the single-credential answer. Revocation is
// omitted (not null) on the known-nothing answer, matching the TS twin's
// conditional spread.
type credentialRevocationStatus struct {
	CredentialCID string `json:"credentialCID"`
	Revoked       bool   `json:"revoked"`
	Revocation    string `json:"revocation,omitempty"`
}

type issuerRevocationEntry struct {
	CredentialCID string `json:"credentialCID"`
	Revocation    string `json:"revocation"`
}

// issuerRevocationList is the per-issuer listing. Revocations is non-nil so an
// empty set renders `[]`, never null.
type issuerRevocationList struct {
	DID         string                  `json:"did"`
	Revocations []issuerRevocationEntry `json:"revocations"`
}

// -----------------------------------------------------------------------------
// handlers
// -----------------------------------------------------------------------------

// handleRevocationStatus serves GET /revocations/v1/credential/{credentialCID}.
// Byte twin of the TS route in relay.ts: 400 on a malformed CID param, 200 with
// the self-proving revocation JWS when revoked, 200 revoked:false otherwise.
func (r *Relay) handleRevocationStatus(w http.ResponseWriter, req *http.Request) {
	credentialCID := req.PathValue("credentialCID")

	// reject anything that is not a credential-shaped CID — a malformed param
	// gets a 400, never a well-formed-looking `revoked: false`
	if !isValidCredentialCid(credentialCID) {
		writeError(w, 400, "invalid credential CID")
		return
	}

	rev, err := r.readStore.GetRevocationForCredential(credentialCID)
	if storeErr(w, err) {
		return
	}
	if rev == nil {
		writeJSON(w, 200, credentialRevocationStatus{CredentialCID: credentialCID, Revoked: false})
		return
	}
	writeJSON(w, 200, credentialRevocationStatus{
		CredentialCID: credentialCID,
		Revoked:       true,
		Revocation:    rev.JWSToken,
	})
}

// handleIssuerRevocations serves GET /revocations/v1/issuer/{did}. Byte twin of
// the TS route: 400 on a non-canonical did:dfos, 200 with the full (possibly
// empty) revocation list sorted by credentialCID otherwise.
func (r *Relay) handleIssuerRevocations(w http.ResponseWriter, req *http.Request) {
	did := req.PathValue("did")

	// must be the exact canonical 31-char did:dfos form
	if !isValidDfosDid(did) {
		writeError(w, 400, "invalid DID")
		return
	}

	revs, err := r.readStore.GetRevocationsByIssuer(did)
	if storeErr(w, err) {
		return
	}

	entries := make([]issuerRevocationEntry, 0, len(revs))
	for _, rev := range revs {
		entries = append(entries, issuerRevocationEntry{
			CredentialCID: rev.CredentialCID,
			Revocation:    rev.JWSToken,
		})
	}
	writeJSON(w, 200, issuerRevocationList{DID: did, Revocations: entries})
}
