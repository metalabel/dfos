/*

  INDEX (v0) — MATERIALIZED PROJECTION MAINTENANCE

  "op applied → recompute affected rows". The ingestion pipeline records the
  affected rows for each accepted op into a per-batch IndexDirtySet
  (collectIndexDirtyAfterOp), then flushes ONCE at the end of the batch
  (flushIndexMaintenance); the blob route calls maintainIndexAfterBlob after a
  document lands. Recompute reads CURRENT store state through the shared row
  builders (index-routes.ts) — the single source of row-value truth — and
  upserts via the store's putIndex*Row members. Because a row is a pure function
  of (chain state, held blobs, standing credentials), every recompute converges
  to the same row regardless of when it runs; incremental maintenance and a full
  rebuild are interchangeable.

  Why batch-coalesce rather than recompute per op: two triggers fan out over a
  bounded-but-large superset — a `chain:*` grant touches every content row, and
  a revocation (or an identity deletion, which removes a credential issuer /
  delegation hop) touches every currently-public-read content row. Running that
  per op means a sync batch delivering N such ops does N back-to-back full
  sweeps. Collecting dirtiness across the batch and flushing once collapses that
  to a single sweep, while the post-batch store state the flush reads is the same
  final state each per-op recompute would have converged to — so the projection
  is byte-identical, just computed once.

  The projection is a NON-AUTHORITATIVE hint plane. Maintenance therefore never
  fails an authoritative write: every entry point swallows its own errors so a
  projection hiccup can never reject an ingested op or a stored blob.

  A materialized row is a snapshot of standing authority AT LAST TOUCH. One input
  to `publicRead` — a standing credential's `exp` — is wall-clock-relative, so a
  row can outlive the grant that made it public until the next op happens to
  dirty that content (or a full rebuild reruns the builder). This is acceptable
  for a non-authoritative hint plane: authoritative reads always re-verify via
  hasPublicStandingAuth at request time; the index only advertises a browse hint.
  See specs/WEB-RELAY.md §Index.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { contentIndexRow, identityIndexRow, type IndexCountersignatureRow } from './index-routes';
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

/**
 * The rows one batch of accepted ops dirtied, collected across the batch and
 * flushed once. `allContent`/`allPublicContent` are the two fan-out supersets
 * (a `chain:*` grant → all content; a revocation or identity deletion → all
 * currently-public-read content); when set they subsume the per-id sets, so a
 * batch of N such ops flushes a single sweep instead of N.
 */
export interface IndexDirtySet {
  identityDIDs: Set<string>;
  contentIds: Set<string>;
  countersigns: (IndexCountersignatureRow & { witnessDID: string })[];
  allContent: boolean;
  allPublicContent: boolean;
}

/** A fresh, empty dirty set for one ingest batch. */
export const createIndexDirtySet = (): IndexDirtySet => ({
  identityDIDs: new Set(),
  contentIds: new Set(),
  countersigns: [],
  allContent: false,
  allPublicContent: false,
});

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
 * Collect the rows ONE accepted operation dirties into the batch's dirty set.
 * Called from the single ingest choke point (ingestOperations) in dependency
 * order, right after each op is applied to the store. Only `status === 'new'`
 * mutates state; a duplicate is already reflected, a rejection changed nothing.
 * Nothing is recomputed here — the batch flushes once via flushIndexMaintenance.
 *
 * Mapping (identical across all implementations):
 *  - identity-op / artifact for chain D → dirty identity row D; if the op left
 *                                         the identity DELETED, also mark all
 *                                         currently-public-read content dirty —
 *                                         a deleted identity is no longer a valid
 *                                         credential issuer / delegation hop, so
 *                                         any content whose public-read authority
 *                                         routes through D flips true→false
 *                                         (deletion is terminal, so public-read
 *                                         content is the complete affected superset)
 *  - content-op for chain C            → dirty content row C (+ anchored identities)
 *  - credential grant                  → dirty the att-named content rows, or all
 *                                        content rows on a `chain:*` grant
 *  - revocation                        → dirty all currently-public-read content
 *                                        rows (a revocation only ever turns
 *                                        publicRead true→false)
 *  - countersign                       → queue the accepted countersign row upsert
 *                                        (dedup returns 'duplicate', so a
 *                                        status:'new' countersign IS the accepted
 *                                        one — never a shadowed raw op)
 */
export const collectIndexDirtyAfterOp = async (
  result: IngestionResult,
  jwsToken: string,
  store: RelayStore,
  dirty: IndexDirtySet,
): Promise<void> => {
  if (result.status !== 'new' || !result.kind) return;
  try {
    switch (result.kind) {
      case 'identity-op':
      case 'artifact':
        if (result.chainId) {
          dirty.identityDIDs.add(result.chainId);
          const chain = await store.getIdentityChain(result.chainId);
          if (chain?.state.isDeleted) dirty.allPublicContent = true;
        }
        break;
      case 'content-op':
        if (result.chainId) dirty.contentIds.add(result.chainId);
        break;
      case 'credential': {
        const { wildcard, contentIds } = contentIdsFromCredential(jwsToken);
        if (wildcard) dirty.allContent = true;
        else for (const contentId of contentIds) dirty.contentIds.add(contentId);
        break;
      }
      case 'revocation':
        dirty.allPublicContent = true;
        break;
      case 'countersign': {
        if (!result.chainId) break;
        const decoded = decodeJwsUnsafe(jwsToken);
        const payload = decoded?.payload as Record<string, unknown> | undefined;
        const cid = typeof decoded?.header.cid === 'string' ? decoded.header.cid : result.cid;
        const relation = typeof payload?.['relation'] === 'string' ? payload['relation'] : null;
        const witnessDID = typeof payload?.['did'] === 'string' ? payload['did'] : '';
        dirty.countersigns.push({ cid, targetCID: result.chainId, relation, jwsToken, witnessDID });
        break;
      }
    }
  } catch {
    // projection is a non-authoritative hint — never fail the write for it
  }
};

/**
 * Flush the batch's collected dirtiness ONCE, after every op has been applied to
 * the store. All recompute reads the final post-batch store state, so a single
 * pass converges to the same rows N per-op recomputes would have. `allContent`
 * subsumes everything else; otherwise the public-read sweep and the per-id
 * content rows are unioned (a per-id content may be brand-new and thus not yet
 * enumerable by the sweep, so both run), then the identity rows (op'd identities
 * that may anchor no recomputed content), then the queued countersign upserts.
 */
export const flushIndexMaintenance = async (
  dirty: IndexDirtySet,
  store: RelayStore,
): Promise<void> => {
  try {
    if (dirty.allContent) {
      await recomputeAllContentRows(store);
    } else {
      if (dirty.allPublicContent) await recomputePublicReadContentRows(store);
      for (const contentId of dirty.contentIds) await recomputeContentRow(contentId, store);
    }
    for (const did of dirty.identityDIDs) await recomputeIdentityRow(did, store);
    for (const row of dirty.countersigns) await store.putIndexCountersignatureRow(row);
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
