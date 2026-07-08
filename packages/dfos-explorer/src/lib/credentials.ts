/*

  CREDENTIALS — relate synced grant ops to a content chain

  Credentials chain under their ISSUER DID, not the content they grant over, so
  there's no chain-endpoint that lists "the grants on this chain". The relay only
  consults them internally to gate blob reads. What we DO have is the global log:
  every public-read grant is a `credential` op in it, synced into the local
  index. So we find related grants by scanning those ops and matching the
  attenuation resource `chain:<contentId>`.

  These are relay-asserted until opened — the credential detail view is what
  verifies the signature and that the delegation roots at the chain's creator.

*/

import type { IndexCredentialRow } from '@metalabel/dfos-client';
import { decodeDFOSCredentialUnsafe } from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { ExplorerOp } from './db';

export interface GrantSummary {
  /** credential op CID — links to the credential detail view for full verify */
  cid: string;
  /** audience: '*' for a public standing grant, else a specific DID */
  aud: string;
  /** actions this grant confers over the chain (e.g. ['read']) */
  actions: string[];
  /** expiry, unix seconds (undefined when the token omits exp) */
  exp?: number | undefined;
  /** aud === '*' — the standing public-read grant that makes bytes anon-servable */
  isPublic: boolean;
  /** true when this grant reaches the chain via a `chain:*` wildcard (any-chain,
   *  rooted at the ISSUER's authority — NOT proven to root at THIS chain's creator
   *  until folded) rather than naming the chain exactly. Only set on index-derived
   *  grants; the local-scan path matches exact `chain:<id>` only. */
  wildcard?: boolean;
}

/**
 * The grants (from local-index credential ops) whose attenuation names this
 * content chain as a resource. Deduped by CID, public grants first.
 */
export const grantsForChain = (ops: ExplorerOp[], contentId: string): GrantSummary[] => {
  if (!contentId) return [];
  const want = `chain:${contentId}`;
  const byCid = new Map<string, GrantSummary>();
  for (const op of ops) {
    if (byCid.has(op.cid)) continue;
    const decoded = decodeJwsUnsafe(op.jwsToken);
    if (!decoded) continue;
    const payload = decoded.payload as Record<string, unknown>;
    const att = Array.isArray(payload['att'])
      ? (payload['att'] as { resource?: unknown; action?: unknown }[])
      : [];
    const actions = att
      .filter((a) => a.resource === want && typeof a.action === 'string')
      .map((a) => a.action as string);
    if (actions.length === 0) continue;
    const aud = typeof payload['aud'] === 'string' ? payload['aud'] : '';
    byCid.set(op.cid, {
      cid: op.cid,
      aud,
      actions,
      exp: typeof payload['exp'] === 'number' ? payload['exp'] : undefined,
      isPublic: aud === '*',
    });
  }
  return [...byCid.values()].sort((a, b) => Number(b.isPublic) - Number(a.isPublic));
};

/** A compact, decode-only view of an op payload's embedded `authorization`
 *  credential — the DFOS credential a NON-creator signer carries to prove
 *  delegated write/delete authority (PROTOCOL.md). Unverified (the credential
 *  page folds the real proof); this is just the readable summary the op view
 *  shows in place of an unbounded raw-JWS dump. */
export interface AuthorizationSummary {
  iss: string;
  aud: string;
  att: { resource: string; action: string }[];
  iat: number;
  exp: number;
}

/** Decode an embedded `authorization` JWS into its summary, or null when it is
 *  not a well-formed DFOS credential. Pure — no network, no verification. */
export const summarizeAuthorization = (token: string): AuthorizationSummary | null => {
  const decoded = decodeDFOSCredentialUnsafe(token);
  if (!decoded) return null;
  const p = decoded.payload;
  return {
    iss: p.iss,
    aud: p.aud,
    att: p.att.map((a) => ({ resource: a.resource, action: a.action })),
    iat: p.iat,
    exp: p.exp,
  };
};

/** Re-derive a credential's CID from its own payload bytes (dag-cbor → CID), the
 *  same self-addressing credential.tsx uses so the op view can link to the
 *  credential page by its content hash — not a relay-supplied header value.
 *  Returns null when the token can't be decoded or encoded (the caller renders a
 *  visible failure rather than sticking on "deriving…"). */
export const deriveCredentialCid = async (token: string): Promise<string | null> => {
  const decoded = decodeDFOSCredentialUnsafe(token);
  if (!decoded) return null;
  try {
    return (await dagCborCanonicalEncode(decoded.payload)).cid.toString();
  } catch {
    return null;
  }
};

/**
 * Grants for a chain built from the relay's `/index/v0/credentials?resource=chain:<id>`
 * projection — the always-fresh, no-sync-required path. The index returns a SUPERSET
 * of candidates: creds naming this chain exactly UNION any `chain:*` wildcard cred (a
 * wildcard MAY authorize this chain, but only once folded to prove it roots at the
 * chain's creator). Each candidate is AMBER (relay-asserted); opening the credential
 * folds its signature + root authority. Wildcard candidates are flagged so the UI can
 * distinguish "this chain" from "any-chain (chain:*)". Deduped by CID, public first.
 */
export const grantsFromIndex = (rows: IndexCredentialRow[], contentId: string): GrantSummary[] => {
  if (!contentId) return [];
  const want = `chain:${contentId}`;
  const byCid = new Map<string, GrantSummary>();
  for (const row of rows) {
    if (byCid.has(row.cid)) continue;
    const exact = row.att.filter((a) => a.resource === want).map((a) => a.action);
    const wild = row.att.filter((a) => a.resource === 'chain:*').map((a) => a.action);
    const actions = exact.length > 0 ? exact : wild;
    if (actions.length === 0) continue;
    // The index stores only public creds (aud '*'); decode the self-proving token to
    // read aud rather than trusting the row shape.
    const decoded = decodeJwsUnsafe(row.jwsToken);
    const payload = (decoded?.payload ?? {}) as Record<string, unknown>;
    const aud = typeof payload['aud'] === 'string' ? payload['aud'] : '*';
    byCid.set(row.cid, {
      cid: row.cid,
      aud,
      actions,
      exp: typeof row.exp === 'number' ? row.exp : undefined,
      isPublic: aud === '*',
      wildcard: exact.length === 0,
    });
  }
  return [...byCid.values()].sort((a, b) => Number(b.isPublic) - Number(a.isPublic));
};
