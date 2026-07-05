/*

  PUBLIC GRANTS — which content chains have a STANDING public-read grant

  A relay serves an anonymous /content/:id/blob ONLY when a standing public
  credential exists: aud '*', action covering read, resource `chain:<id>` (or
  the `chain:*` wildcard), unexpired, unrevoked, delegation rooting at the
  chain's creator — hasPublicStandingAuth in dfos-web-relay/src/auth.ts. Every
  credential AND revocation op is already synced into the local index, so that
  eligibility folds locally: Phase 2 need not ask a relay thousands of times to
  be told 401 for chains whose log already shows no standing grant.

  This fold is a FETCH PREFILTER, not a trust claim. It errs open: signatures
  and delegation chains are NOT verified here, so a bogus grant just costs one
  fetch that 401s into the same gated outcome. It never errs closed for the
  reference policy — no aud-'*' read grant in the log means an anonymous fetch
  is denied by construction. Publicness itself is still only recorded after
  served bytes re-hash to the committed doc CID (sync-projections.ts).

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { ExplorerOp } from './db';
import { revokedByCredential } from './revocations';

export interface PublicGrantSet {
  /** an active public `chain:*` grant exists — every chain is fetch-eligible. */
  all: boolean;
  /** contentIds named by an active public read grant. */
  chains: Set<string>;
}

/** matchesResource semantics (dfos-credential.ts): actions are a comma set. */
const grantsRead = (action: unknown): boolean =>
  typeof action === 'string' &&
  action
    .split(',')
    .map((a) => a.trim())
    .includes('read');

/**
 * Fold the standing public-read grant set from local credential + revocation
 * ops. `nowSec` (unix seconds) drops expired grants.
 */
export const publicGrantSet = (
  credentialOps: ExplorerOp[],
  revocationOps: ExplorerOp[],
  nowSec: number,
): PublicGrantSet => {
  const revoked = revokedByCredential(revocationOps);
  const out: PublicGrantSet = { all: false, chains: new Set() };

  for (const op of credentialOps) {
    if (revoked.has(op.cid)) continue;
    const decoded = decodeJwsUnsafe(op.jwsToken);
    if (!decoded) continue;
    const payload = decoded.payload as Record<string, unknown>;
    if (payload['aud'] !== '*') continue;
    const exp = payload['exp'];
    if (typeof exp === 'number' && exp <= nowSec) continue;

    const att = Array.isArray(payload['att'])
      ? (payload['att'] as { resource?: unknown; action?: unknown }[])
      : [];
    for (const entry of att) {
      if (!grantsRead(entry.action)) continue;
      if (typeof entry.resource !== 'string' || !entry.resource.startsWith('chain:')) continue;
      const id = entry.resource.slice('chain:'.length);
      if (id === '*') out.all = true;
      else if (id) out.chains.add(id);
    }
  }
  return out;
};

/** Whether an anonymous blob fetch for this chain can possibly succeed. */
export const isFetchEligible = (grants: PublicGrantSet, contentId: string): boolean =>
  grants.all || grants.chains.has(contentId);
