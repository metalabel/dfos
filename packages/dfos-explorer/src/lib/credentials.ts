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

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
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
