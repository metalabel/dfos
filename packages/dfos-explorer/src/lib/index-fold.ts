/*

  INDEX CHAIN FOLD — resolve every op's document, fold the LWW-Map in the tab

  The canonical fold is branch-INCLUSIVE: every op in the chain log
  participates, not just the selected-head branch — concurrent forks converge
  to the same map in any arrival order. Each op's committed document is
  fetched by ref from the content plane and integrity-checked (re-encoded
  canonically, re-hashed, compared to the CID the op committed) before its
  deltas enter the fold. Unreadable documents are a COVERAGE gap and are
  reported, never silently skipped.

*/

import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { foldIndexV1, INDEX_V1_SCHEMA, type IndexEntry } from '@metalabel/dfos-protocol/fold';
import type { OpRow } from './op-rows';

export { INDEX_V1_SCHEMA };
export type { IndexEntry };

export interface FoldedIndex {
  /** the resolved LWW-Map */
  entries: Map<string, IndexEntry>;
  /** per-op documents that participated (op cid → parsed doc), for history */
  docs: { opCid: string; createdAt: string; deltas: unknown[] }[];
  /** ops whose committed document could not be fetched or failed integrity */
  gaps: { opCid: string; reason: string }[];
  /** ops that committed no document (delete/clear) */
  nulls: number;
}

export const isIndexDocument = (doc: unknown): boolean =>
  typeof doc === 'object' &&
  doc !== null &&
  !Array.isArray(doc) &&
  (doc as Record<string, unknown>)['$schema'] === INDEX_V1_SCHEMA;

/**
 * Fetch every op's committed document by ref and fold. `rows` must be the
 * VERIFIED chain log (any order — the fold linearizes internally).
 */
export const foldIndexChain = async (options: {
  contentId: string;
  rows: OpRow[];
  relays: string[];
  fetchImpl?: typeof fetch;
}): Promise<FoldedIndex> => {
  const { contentId, rows, relays } = options;
  const fetchImpl = options.fetchImpl ?? fetch;

  const gaps: FoldedIndex['gaps'] = [];
  const docs: FoldedIndex['docs'] = [];
  let nulls = 0;

  const ops = await Promise.all(
    rows.map(async (row) => {
      const decoded = decodeJwsUnsafe(row.jwsToken);
      const committedCid = decoded?.payload['documentCID'];
      if (committedCid === null || committedCid === undefined) {
        nulls += 1;
        return { cid: row.cid, createdAt: row.createdAt, document: null };
      }
      if (typeof committedCid !== 'string') {
        gaps.push({ opCid: row.cid, reason: 'malformed documentCID' });
        return { cid: row.cid, createdAt: row.createdAt, document: null };
      }
      for (const relay of relays) {
        try {
          const res = await fetchImpl(
            `${relay}/content/${encodeURIComponent(contentId)}/blob/${encodeURIComponent(row.cid)}`,
            { mode: 'cors', signal: AbortSignal.timeout(15000) },
          );
          if (!res.ok) continue;
          const bytes = new Uint8Array(await res.arrayBuffer());
          const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
          const encoded = await dagCborCanonicalEncode(parsed as Record<string, unknown>);
          if (encoded.cid.toString() !== committedCid) {
            gaps.push({
              opCid: row.cid,
              reason: 'served bytes do not re-hash to the committed CID',
            });
            return { cid: row.cid, createdAt: row.createdAt, document: null };
          }
          if (isIndexDocument(parsed)) {
            const deltas = (parsed as Record<string, unknown>)['deltas'];
            docs.push({
              opCid: row.cid,
              createdAt: row.createdAt,
              deltas: Array.isArray(deltas) ? deltas : [],
            });
          }
          return { cid: row.cid, createdAt: row.createdAt, document: parsed };
        } catch {
          continue;
        }
      }
      gaps.push({ opCid: row.cid, reason: 'document not readable from any relay' });
      return { cid: row.cid, createdAt: row.createdAt, document: null };
    }),
  );

  const entries = foldIndexV1(ops);
  docs.sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0));
  return { entries, docs, gaps, nulls };
};
