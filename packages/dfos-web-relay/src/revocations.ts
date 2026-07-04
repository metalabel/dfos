/*

  REVOCATION STATUS PROJECTION

  Pure, read-only projection of the relay's revocation set — the
  (issuerDID, credentialCID) index it already maintains for its own credential
  enforcement — into the frozen `/revocations/v1` route family. Revocations
  remain ordinary proof-plane ops (kind "revocation", ingested via
  POST /proof/v1/operations, gossiped); this is a frozen v1 contract at the
  relay ROOT on its own version clock, alongside but not under the frozen
  proof plane, exactly like the universal resolver at /1.0/identifiers/:did.

  Key principle: every positive answer carries the revocation JWS itself, so a
  zero-trust caller re-verifies (signature, CID integrity, kid-DID == payload
  did, issuer-only rule) instead of trusting the relay's boolean. The boolean
  is a convenience; the JWS is the proof.

  Absence semantics are HONEST: `revoked: false` means "this relay has not
  ingested a revocation for this CID" — it is NOT proof of non-revocation. A
  relay can only attest to what it has seen (and can withhold); querying a
  quorum of relays is the client-side mitigation.

*/

import type { StoredRevocation } from './types';

// -----------------------------------------------------------------------------
// route family base path
// -----------------------------------------------------------------------------

/**
 * Namespaces the revocation-status routes on their own frozen v1 clock (NOT
 * the /proof/v1 proof plane). Root-mounted v1 contract; MUST stay in byte-sync
 * with the Go relay (revocationsBasePath in revocations.go).
 */
export const REVOCATIONS_BASE_PATH = '/revocations/v1';

// -----------------------------------------------------------------------------
// credential CID validation
// -----------------------------------------------------------------------------

/**
 * A credential CID is a CIDv1 dag-cbor + sha256 identifier: the fixed
 * `bafyrei` head + 52 base32 chars (same shape the protocol pins for artifact
 * anchors — ARTIFACT_CID_ANCHOR_RE in @metalabel/dfos-protocol/chain). Any
 * other length or charset is not a credential CID this index could ever hold —
 * the routes reject it with 400 instead of answering a well-formed-looking
 * `revoked: false`.
 */
const CREDENTIAL_CID_RE = /^bafyrei[a-z2-7]{52}$/;

export const isValidCredentialCid = (cid: string): boolean => CREDENTIAL_CID_RE.test(cid);

// -----------------------------------------------------------------------------
// response shapes (field order is normative — the Go twin mirrors it)
// -----------------------------------------------------------------------------

export interface CredentialRevocationStatus {
  credentialCID: string;
  revoked: boolean;
  /** The full revocation JWS token — present iff revoked. Self-proving. */
  revocation?: string;
}

export interface IssuerRevocationEntry {
  credentialCID: string;
  /** The full revocation JWS token — self-proving */
  revocation: string;
}

export interface IssuerRevocationList {
  did: string;
  revocations: IssuerRevocationEntry[];
  next: string | null;
}

/**
 * Shape a credential revocation-status response. `revocation` is omitted (not
 * null) on the known-nothing answer, matching the Go twin's omitempty.
 */
export const credentialRevocationStatus = (
  credentialCID: string,
  revocation: StoredRevocation | undefined,
): CredentialRevocationStatus => {
  if (!revocation) return { credentialCID, revoked: false };
  return { credentialCID, revoked: true, revocation: revocation.jwsToken };
};

/** Shape an issuer revocation-list response. Empty set renders `[]`, never null. */
export const issuerRevocationList = (
  did: string,
  revocations: StoredRevocation[],
  next: string | null,
): IssuerRevocationList => ({
  did,
  revocations: revocations.map((rev) => ({
    credentialCID: rev.credentialCID,
    revocation: rev.jwsToken,
  })),
  next,
});
