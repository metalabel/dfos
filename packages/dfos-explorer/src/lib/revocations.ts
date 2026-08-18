/*

  REVOCATIONS — fold local revocation ops onto the credentials they invalidate

  A revocation is a standalone signed proof-plane op (typ: did:dfos:revocation)
  whose payload names the `credentialCID` its issuer permanently invalidates
  (see op-annotations.ts / protocol RevocationPayload). Revocations are synced
  into the local index like any other op, so a credential's active/revoked status
  can be folded LOCALLY — no relay round-trip — by matching revocation ops to
  credential CIDs. This is house doctrine: truth from the math you already hold.

  Relay-asserted until you open the credential; the credential detail view
  re-verifies any revocation proof (signature, CID, issuer binding). This fold
  is the discovery-index answer, not the proof.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { ExplorerOp } from './db';

/**
 * Index revocation ops by the credential CID they revoke → the revoking op's own
 * CID (so a revoked row can link to the revocation). First revocation wins on a
 * duplicate — revocation is permanent and one proof is enough.
 */
export const revokedByCredential = (revocationOps: ExplorerOp[]): Map<string, string> => {
  const byCredential = new Map<string, string>();
  for (const op of revocationOps) {
    const decoded = decodeJwsUnsafe(op.jwsToken);
    if (!decoded) continue;
    const credentialCID = decoded.payload['credentialCID'];
    if (typeof credentialCID !== 'string' || !credentialCID) continue;
    if (!byCredential.has(credentialCID)) byCredential.set(credentialCID, op.cid);
  }
  return byCredential;
};

// -----------------------------------------------------------------------------
// the relay lane — /revocations/v1, the route family that answers exactly this
//
// Folding the revocation set out of a full local scan works only after a deep
// sync and costs a whole-partition read. The relay serves the same projection
// directly: by ISSUER (every revocation a DID has signed) and by CREDENTIAL (one
// status). Both are bounded queries, always fresh, and need no sync — so the
// views ask the relay first and keep the local fold as the offline fallback.
//
// Every positive answer carries the self-proving revocation JWS. This map is a
// DISPLAY hint (which chip to show, which op to link); the credential view
// re-verifies the proof, and `revoked: false` is honest absence, never proof of
// non-revocation.
// -----------------------------------------------------------------------------

/** Pages of an issuer feed to walk before giving up — a revocation set that
 *  large is not a display concern (the issuer view is not a revocation browser). */
const MAX_ISSUER_PAGES = 20;

/** Credentials whose status is queried one-by-one — the grants a page renders. */
const MAX_STATUS_QUERIES = 50;

const REVOCATIONS = '/revocations/v1';

const getJson = async (url: string): Promise<unknown | null> => {
  try {
    const res = await fetch(url, { mode: 'cors', signal: AbortSignal.timeout(10000) });
    return res.ok ? ((await res.json()) as unknown) : null;
  } catch {
    return null;
  }
};

/** revocation JWS → the revoking op's own CID (its JWS header cid), '' if undecodable. */
const revocationOpCid = (jws: string): string => {
  const decoded = decodeJwsUnsafe(jws);
  return typeof decoded?.header.cid === 'string' ? decoded.header.cid : '';
};

/**
 * credentialCID → revoking op CID for every revocation the relay attributes to
 * this ISSUER. `null` when no relay served the feed (route absent on an older
 * relay, or all unreachable) — the caller falls back to the local fold rather
 * than rendering a false "nothing revoked", the same honest-absence rule the
 * index lanes follow.
 */
export const fetchIssuerRevocations = async (
  did: string,
  relays: string[],
): Promise<Map<string, string> | null> => {
  for (const relay of relays) {
    const out = new Map<string, string>();
    let after = '';
    let ok = false;
    for (let page = 0; page < MAX_ISSUER_PAGES; page++) {
      const url = `${relay}${REVOCATIONS}/issuer/${encodeURIComponent(did)}${
        after ? `?after=${encodeURIComponent(after)}` : ''
      }`;
      const body = (await getJson(url)) as {
        revocations?: { credentialCID?: unknown; revocation?: unknown }[];
        next?: unknown;
      } | null;
      if (!body || !Array.isArray(body.revocations)) break;
      ok = true;
      for (const entry of body.revocations) {
        if (typeof entry.credentialCID !== 'string' || typeof entry.revocation !== 'string') {
          continue;
        }
        if (!out.has(entry.credentialCID)) {
          out.set(entry.credentialCID, revocationOpCid(entry.revocation));
        }
      }
      if (typeof body.next !== 'string' || !body.next) return out;
      after = body.next;
    }
    if (ok) return out;
  }
  return null;
};

/**
 * credentialCID → revoking op CID for a KNOWN, BOUNDED set of credentials — one
 * status query each across the relay set, capped at {@link MAX_STATUS_QUERIES}.
 * Unrevoked and unanswerable credentials are simply absent from the map (the
 * "active" chip is the honest render of both).
 */
export const fetchCredentialRevocations = async (
  credentialCIDs: string[],
  relays: string[],
): Promise<Map<string, string>> => {
  const out = new Map<string, string>();
  const wanted = [...new Set(credentialCIDs)].slice(0, MAX_STATUS_QUERIES);
  await Promise.all(
    wanted.map(async (cid) => {
      for (const relay of relays) {
        const body = (await getJson(
          `${relay}${REVOCATIONS}/credential/${encodeURIComponent(cid)}`,
        )) as { revoked?: unknown; revocation?: unknown } | null;
        if (!body) continue;
        if (body.revoked === true && typeof body.revocation === 'string') {
          out.set(cid, revocationOpCid(body.revocation));
        }
        return; // this relay answered — honest absence, no need to poll the rest
      }
    }),
  );
  return out;
};
