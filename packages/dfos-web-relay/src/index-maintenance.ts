/*

  INDEX (v0) — MATERIALIZED PROJECTION MAINTENANCE

  "op applied → recompute affected rows". The ingestion pipeline calls
  maintainIndexAfterOp synchronously after each accepted operation; the blob
  route calls maintainIndexAfterBlob after a document lands. Recompute reads
  CURRENT store state through the shared row builders (index-routes.ts) — the
  single source of row-value truth — and upserts via the store's putIndex*Row
  members. Because a row is a pure function of (chain state, held blobs,
  standing credentials), every recompute converges to the same row regardless
  of when it runs; incremental maintenance and a full rebuild are
  interchangeable.

  The projection is a NON-AUTHORITATIVE hint plane. Maintenance therefore never
  fails an authoritative write: every entry point swallows its own errors so a
  projection hiccup can never reject an ingested op or a stored blob.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { contentIndexRow, identityIndexRow } from './index-routes';
import type { IngestionResult, RelayStore } from './types';

/**
 * Upper bound for the maintenance-time enumerate-all fallback used by the two
 * fan-out triggers (a `chain:*` grant, and any revocation). Both can flip
 * publicRead across many rows without naming a single content, so we recompute
 * the bounded affected superset. Kept well above any realistic in-memory
 * corpus; the SQL twins do the equivalent as an indexed `WHERE public_read`
 * (revocation) or a full projection scan (`chain:*`).
 */
const ENUMERATE_ALL_LIMIT = Number.MAX_SAFE_INTEGER;

/** Recompute one identity projection row from current store state. */
export const recomputeIdentityRow = async (did: string, store: RelayStore): Promise<void> => {
  const chain = await store.getIdentityChain(did);
  if (!chain) return;
  await store.putIndexIdentityRow(await identityIndexRow(chain, store));
};

/**
 * Recompute one content projection row from current store state, then cascade
 * to every identity row anchored on it (profile.anchor == contentId) — an
 * identity's profile projection embeds the anchored content's publicRead, doc
 * schema, and name, so a content change is also an identity change.
 */
export const recomputeContentRow = async (contentId: string, store: RelayStore): Promise<void> => {
  const chain = await store.getContentChain(contentId);
  if (!chain) return;
  await store.putIndexContentRow(await contentIndexRow(chain, store));
  const anchoredDIDs = await store.getIndexIdentityDIDsByProfileAnchor(contentId);
  for (const did of anchoredDIDs) await recomputeIdentityRow(did, store);
};

/** Recompute every content row (+ anchored identities). Fan-out fallback. */
const recomputeAllContentRows = async (store: RelayStore): Promise<void> => {
  const rows = await store.queryIndexContent({ limit: ENUMERATE_ALL_LIMIT });
  for (const row of rows) await recomputeContentRow(row.contentId, store);
};

/** Recompute every currently-public-read content row (+ anchored identities). */
const recomputePublicReadContentRows = async (store: RelayStore): Promise<void> => {
  const rows = await store.queryIndexContent({ publicRead: true, limit: ENUMERATE_ALL_LIMIT });
  for (const row of rows) await recomputeContentRow(row.contentId, store);
};

/**
 * Content ids named by a public credential's attenuations (`chain:<contentId>`
 * resources). Returns { wildcard: true } when it grants `chain:*`, which covers
 * every chain and therefore fans out to all content rows.
 */
const contentIdsFromCredential = (
  jwsToken: string,
): { wildcard: boolean; contentIds: string[] } => {
  const decoded = decodeJwsUnsafe(jwsToken);
  const att = (decoded?.payload as Record<string, unknown> | undefined)?.['att'];
  const contentIds: string[] = [];
  let wildcard = false;
  if (Array.isArray(att)) {
    for (const entry of att) {
      const resource = (entry as Record<string, unknown> | null)?.['resource'];
      if (resource === 'chain:*') wildcard = true;
      else if (typeof resource === 'string' && resource.startsWith('chain:')) {
        contentIds.push(resource.slice('chain:'.length));
      }
    }
  }
  return { wildcard, contentIds };
};

/**
 * Maintain the index projection after ONE accepted operation. Called from the
 * single ingest choke point (ingestOperations) in dependency order, right after
 * each op is applied to the store. Only `status === 'new'` mutates state; a
 * duplicate is already reflected, a rejection changed nothing.
 *
 * Mapping (identical across all implementations):
 *  - identity-op / artifact for chain D → recompute identity row D
 *  - content-op for chain C            → recompute content row C (+ anchored identities)
 *  - credential grant                  → recompute the att-named content rows,
 *                                        or all content rows on a `chain:*` grant
 *  - revocation                        → recompute all currently-public-read
 *                                        content rows (a revocation only ever
 *                                        turns publicRead true→false, so this is
 *                                        the complete affected superset)
 *  - countersign                       → upsert the accepted countersign row
 *                                        (dedup returns 'duplicate', so a
 *                                        status:'new' countersign IS the accepted
 *                                        one — never a shadowed raw op)
 */
export const maintainIndexAfterOp = async (
  result: IngestionResult,
  jwsToken: string,
  store: RelayStore,
): Promise<void> => {
  if (result.status !== 'new' || !result.kind) return;
  try {
    switch (result.kind) {
      case 'identity-op':
      case 'artifact':
        if (result.chainId) await recomputeIdentityRow(result.chainId, store);
        break;
      case 'content-op':
        if (result.chainId) await recomputeContentRow(result.chainId, store);
        break;
      case 'credential': {
        const { wildcard, contentIds } = contentIdsFromCredential(jwsToken);
        if (wildcard) await recomputeAllContentRows(store);
        else for (const contentId of contentIds) await recomputeContentRow(contentId, store);
        break;
      }
      case 'revocation':
        await recomputePublicReadContentRows(store);
        break;
      case 'countersign': {
        if (!result.chainId) break;
        const decoded = decodeJwsUnsafe(jwsToken);
        const payload = decoded?.payload as Record<string, unknown> | undefined;
        const cid = typeof decoded?.header.cid === 'string' ? decoded.header.cid : result.cid;
        const relation = typeof payload?.['relation'] === 'string' ? payload['relation'] : null;
        const witnessDID = typeof payload?.['did'] === 'string' ? payload['did'] : '';
        await store.putIndexCountersignatureRow({
          cid,
          targetCID: result.chainId,
          relation,
          jwsToken,
          witnessDID,
        });
        break;
      }
    }
  } catch {
    // projection is a non-authoritative hint — never fail the write for it
  }
};

/**
 * Maintain the index projection after a document blob lands. A blob arriving
 * (often late, out of band from the op that referenced it) can turn a content
 * row's docSchema/name/profile projection from unknown to known, so recompute
 * every content row that projects this documentCID, cascading to their anchored
 * identities.
 */
export const maintainIndexAfterBlob = async (
  documentCID: string,
  store: RelayStore,
): Promise<void> => {
  try {
    const contentIds = await store.getIndexContentIdsByDocumentCID(documentCID);
    for (const contentId of contentIds) await recomputeContentRow(contentId, store);
  } catch {
    // projection is a non-authoritative hint — never fail the blob write for it
  }
};
