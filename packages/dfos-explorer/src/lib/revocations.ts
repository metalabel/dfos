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
// THE THREE STATES — absence is never authoritative
//
// Folding the revocation set out of a full local scan works only after a deep
// sync and costs a whole-partition read. The relay serves the same projection
// directly: by ISSUER (every revocation a DID has signed) and by CREDENTIAL (one
// status). Both are bounded, always fresh, and need no sync.
//
// But `revoked: false` from one relay means ONLY "this relay has not ingested a
// revocation for this CID" — the route's own contract says so, and dfos-client's
// checker encodes it by consulting EVERY relay before it answers false. A single
// relay can withhold. So a credential has THREE display states, not two:
//
//   revoked   a positive proof was seen — by any relay, or by the local fold
//   active    the whole relay set was consulted and none holds one
//   unknown   no relay answered for it, or it was never asked about
//
// Collapsing `unknown` into `active` is the one failure this module exists to
// prevent: a revoked credential must NEVER render green because the network was
// unreachable, the route was absent, or a query cap skipped it. Positives union
// across every source; only a completed sweep of the relay set can license green.
//
// This is a DISPLAY verdict — which chip, which op to link. The credential view
// re-verifies the proof itself.
// -----------------------------------------------------------------------------

/** Per-credential display verdict. See the block comment above. */
export type RevocationStatus = 'revoked' | 'active' | 'unknown';

export interface RevocationView {
  /** credentialCID → revoking op CID. A positive proof was seen for each. */
  revoked: Map<string, string>;
  /**
   * A source actually completed a sweep that can license "active" for the
   * credentials it covered. FALSE means nothing authoritative answered, so every
   * unrevoked credential is UNKNOWN rather than active. The local fold never sets
   * this: an un-synced (or partly-synced) local index proves nothing about what
   * it does not hold.
   */
  established: boolean;
  /** Credentials the sweep could NOT cover — unreachable for that CID, or past a
   *  query cap. These stay unknown even when `established` is true. */
  unknown: Set<string>;
}

export const emptyRevocations = (): RevocationView => ({
  revoked: new Map(),
  established: false,
  unknown: new Set(),
});

/** One credential's verdict. Pure, unit-tested — the whole honesty rule in one
 *  expression: a positive wins; green requires an established sweep that covered
 *  this CID; everything else is unknown. */
export const revocationStatus = (view: RevocationView, credentialCID: string): RevocationStatus => {
  if (view.revoked.has(credentialCID)) return 'revoked';
  if (view.established && !view.unknown.has(credentialCID)) return 'active';
  return 'unknown';
};

/** Union two sources. A positive from EITHER wins (and clears any unknown for
 *  it); "established" is likewise a union — one completed sweep is enough — while
 *  an unknown from either side survives, the conservative direction. Pure. */
export const mergeRevocations = (a: RevocationView, b: RevocationView): RevocationView => {
  const revoked = new Map([...a.revoked, ...b.revoked]);
  const unknown = new Set<string>();
  for (const cid of [...a.unknown, ...b.unknown]) if (!revoked.has(cid)) unknown.add(cid);
  return { revoked, established: a.established || b.established, unknown };
};

/** The local fold as a view: it contributes POSITIVES ONLY. It never establishes
 *  absence — a local index holds what a past sync pulled, which is no evidence
 *  about a revocation it never saw. */
export const localRevocations = (revocationOps: ExplorerOp[]): RevocationView => ({
  revoked: revokedByCredential(revocationOps),
  established: false,
  unknown: new Set(),
});

/** Pages of an issuer feed to walk before giving up — a revocation set that
 *  large is not a display concern (the issuer view is not a revocation browser). */
const MAX_ISSUER_PAGES = 20;

/** Credentials whose status is queried one-by-one. Anything past this is marked
 *  UNKNOWN, never silently active — see the block comment above. */
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

/** Walk one relay's issuer feed. `null` when that relay never served it. */
const issuerFeedFrom = async (relay: string, did: string): Promise<Map<string, string> | null> => {
  const out = new Map<string, string>();
  let after = '';
  let served = false;
  for (let page = 0; page < MAX_ISSUER_PAGES; page++) {
    const url = `${relay}${REVOCATIONS}/issuer/${encodeURIComponent(did)}${
      after ? `?after=${encodeURIComponent(after)}` : ''
    }`;
    const body = (await getJson(url)) as {
      revocations?: { credentialCID?: unknown; revocation?: unknown }[];
      next?: unknown;
    } | null;
    if (!body || !Array.isArray(body.revocations)) break;
    served = true;
    for (const entry of body.revocations) {
      if (typeof entry.credentialCID !== 'string' || typeof entry.revocation !== 'string') continue;
      if (!out.has(entry.credentialCID)) {
        out.set(entry.credentialCID, revocationOpCid(entry.revocation));
      }
    }
    if (typeof body.next !== 'string' || !body.next) break;
    after = body.next;
  }
  return served ? out : null;
};

/**
 * Every revocation the relay set attributes to this ISSUER, UNIONED across all
 * relays — one relay serving an empty feed is not evidence that another isn't
 * holding the revocation, so the sweep never stops at the first answer. It
 * `established`es absence only when at least one relay actually served the feed;
 * with none reachable the caller's credentials render unknown, not active.
 */
export const fetchIssuerRevocations = async (
  did: string,
  relays: string[],
): Promise<RevocationView> => {
  const feeds = await Promise.all(relays.map((relay) => issuerFeedFrom(relay, did)));
  const revoked = new Map<string, string>();
  let established = false;
  for (const feed of feeds) {
    if (!feed) continue;
    established = true;
    for (const [cid, op] of feed) if (!revoked.has(cid)) revoked.set(cid, op);
  }
  return { revoked, established, unknown: new Set() };
};

/** One credential's status across the WHOLE relay set: a positive from any relay
 *  wins immediately; otherwise every relay is consulted before absence counts.
 *  `null` when no relay answered at all — that credential is unknown. */
const credentialStatusFrom = async (
  credentialCID: string,
  relays: string[],
): Promise<{ revokedByOp: string } | 'unrevoked' | null> => {
  let answered = false;
  for (const relay of relays) {
    const body = (await getJson(
      `${relay}${REVOCATIONS}/credential/${encodeURIComponent(credentialCID)}`,
    )) as { revoked?: unknown; revocation?: unknown } | null;
    if (!body) continue; // unreachable / route absent — this relay is silent, ask the next
    answered = true;
    if (body.revoked === true && typeof body.revocation === 'string') {
      return { revokedByOp: revocationOpCid(body.revocation) };
    }
  }
  return answered ? 'unrevoked' : null;
};

/**
 * Status for a KNOWN, BOUNDED set of credentials. Each is swept across the full
 * relay set (see {@link credentialStatusFrom}). A credential no relay answered
 * for — and every credential past {@link MAX_STATUS_QUERIES} — comes back
 * UNKNOWN, so an unreachable network or a capped query can never paint a revoked
 * credential green.
 */
export const fetchCredentialRevocations = async (
  credentialCIDs: string[],
  relays: string[],
): Promise<RevocationView> => {
  const distinct = [...new Set(credentialCIDs)];
  const wanted = distinct.slice(0, MAX_STATUS_QUERIES);
  const revoked = new Map<string, string>();
  // anything the cap excluded was never asked about — unknown by construction
  const unknown = new Set<string>(distinct.slice(MAX_STATUS_QUERIES));
  await Promise.all(
    wanted.map(async (cid) => {
      const verdict = await credentialStatusFrom(cid, relays);
      if (verdict === null) unknown.add(cid);
      else if (verdict !== 'unrevoked') revoked.set(cid, verdict.revokedByOp);
    }),
  );
  return { revoked, established: true, unknown };
};
