/*

  OPERATION-LOG FEED — a paged browser over the relay's global log

  `GET /proof/v1/log` is the raw floor: every accepted operation, in the relay's
  own APPEND ORDER, paged by a forward-only keyset cursor (store.readLog resolves
  `after` positionally and hands back the last entry's cid as `next`).

  THE ORDER IS THE HONEST CONSTRAINT ON THAT ROUTE. It serves no reverse order and
  no offset, so there is no way to ask it for the most RECENT operations —
  reaching the tail means draining the whole log (71k+ ops on the public relay:
  tens of megabytes of JWS). Three honest sources exist, and this feed uses each
  where it is true:

    - the INDEX operation feed (`/index/v0/operations?order=…`), a recency feed
      over the same operations, served straight off the relay's projection. It is
      the only source that answers "what just happened on the network" on a COLD
      tab, with no sync and no walk. Rows are relay-asserted metadata, amber.
    - the RELAY log, walked forward from genesis. Live, no sync, complete from the
      start — and oldest-first, which it says plainly.
    - the LOCAL index, once a deep sync has folded the log into the tab. That IS
      genuinely newest-first, because the local store indexes ops by createdAt.

  What this feed will NOT do is relabel a recency-ordered CHAIN feed
  (`/index/v0/content?order=headAt.desc`) as an operation feed: chains are not
  operations, and a row labeled "operation" that is really a chain rollup is the
  kind of quiet lie the rest of this explorer exists to avoid. `/index/v0/operations`
  is not that — it enumerates operations as operations, which is why it qualifies
  where the chain feed never did.

  Rows are relay-asserted log entries either way (sync.ts records the log without
  verifying it; verification happens at fold time). The chain-forming kinds carry
  the usual attributed→verified badge; every row links to its op, where the
  signature is actually checked.

*/

import type { LogOp } from '@metalabel/dfos-client';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { getClient } from './client';
import { isOpKind, type ExplorerOp, type OpKind } from './db';
import { getDb } from './db-instance';
import { PAGE, useIndexPageStack, type IndexPage } from './index-light';
import {
  fetchOperationsPage,
  fetchSignerKeyOperationsPage,
  type IndexOperationRow,
  type IndexRecency,
} from './index-raw';

/** One operation row, ready to render. */
export interface LogRow {
  cid: string;
  kind: OpKind;
  /** the chain this op belongs to — a DID, a contentId, or a target CID. */
  chainId: string;
  /** payload.type ('create' | 'update' | 'delete' | …), '' when undecodable. */
  type: string;
  createdAt: string;
}

/**
 * Decode global-log entries into display rows. `kind`/`chainId` are relay-asserted
 * routing hints (see LogOp) — an unknown kind falls back to 'artifact', the
 * standalone-op bucket, exactly as the sync engine classifies it. Pure, unit-tested.
 */
export const toLogRows = (entries: LogOp[]): LogRow[] =>
  entries.map((entry) => {
    const decoded = decodeJwsUnsafe(entry.jwsToken);
    const type = typeof decoded?.payload['type'] === 'string' ? decoded.payload['type'] : '';
    const createdAt =
      typeof decoded?.payload['createdAt'] === 'string' ? decoded.payload['createdAt'] : '';
    return {
      cid: entry.cid,
      kind: isOpKind(entry.kind) ? entry.kind : 'artifact',
      chainId: typeof entry.chainId === 'string' ? entry.chainId : '',
      type,
      createdAt,
    };
  });

/** Local index ops → the same row shape (they already carry decoded metadata). */
export const localOpRows = (ops: ExplorerOp[]): LogRow[] =>
  ops.map((op) => ({
    cid: op.cid,
    kind: op.kind,
    chainId: op.chainId,
    type: op.type,
    createdAt: op.createdAt,
  }));

/**
 * Index operation rows → the same display shape. The index projects browsing
 * METADATA only, so there is no `type` to show (the payload's create/update/delete
 * verb lives in the JWS, which this route deliberately does not carry) — the cell
 * renders empty rather than guessing. An unknown `kind` falls back to 'artifact',
 * the standalone-op bucket, exactly as the global log's rows do. Pure, unit-tested.
 */
export const indexOpRows = (rows: IndexOperationRow[]): LogRow[] =>
  rows.map((row) => ({
    cid: row.cid,
    kind: isOpKind(row.kind) ? row.kind : 'artifact',
    chainId: row.chainId,
    type: '',
    createdAt: row.createdAt,
  }));

/** Which source the operation feed is reading — see the header note. */
export type LogSource = 'index' | 'relay' | 'local';

/**
 * Which source the operation feed should read, given what is actually available.
 * The live index leads whenever it can — it is the only source that is BOTH fresh
 * and recency-ordered, and (as on every other browse surface) a live index is
 * fresher than a past sync. A relay that does not serve `/index/v0/operations`
 * declines everywhere, which the caller latches as `indexFailed`; from then on the
 * feed uses the local corpus if a deep sync has run, else the forward walk. An
 * explicit `src` choice wins wherever it is viable, so a reader can always pin the
 * source they want and link it. Pure, unit-tested.
 */
export const logSource = (
  indexed: boolean | null,
  indexFailed: boolean,
  logSynced: boolean,
  src: string,
): LogSource => {
  const indexOk = indexed === true && !indexFailed;
  if (src === 'relay') return 'relay';
  if (src === 'local') return logSynced ? 'local' : 'relay';
  if (src === 'index') return indexOk ? 'index' : logSynced ? 'local' : 'relay';
  if (indexOk) return 'index';
  return logSynced ? 'local' : 'relay';
};

/**
 * Page the relay's INDEX operation feed, newest first. This is the cold-start
 * recency source: no sync, no walk from genesis, one round trip. `cursor` is the
 * opaque ordered token the relay issued, carried in the URL so a page can be
 * linked. Throws (→ the pager's error) when no relay serves the route, which is
 * how a pre-`/operations` relay is detected — there is nothing to probe.
 */
export const useIndexLog = (
  enabled: boolean,
  order: IndexRecency,
  cursor: string,
  onCursor: (cursor: string) => void,
): IndexPage<LogRow> =>
  useIndexPageStack(enabled, `index-log:${order}`, cursor, onCursor, async (after) => {
    const page = await fetchOperationsPage({ order, ...(after ? { after } : {}), limit: PAGE });
    return { items: indexOpRows(page.items), next: page.next };
  });

/**
 * Page the operations one PUBLIC KEY signed — `/index/v0/operations?signerKey=`.
 *
 * The rows are the same shape the recency feed renders, because they are the same
 * rows under a filter: the relay narrows the operations index to those whose
 * verified signature resolved to this key at ingest. That is a PROOF-TIER axis
 * over every op kind — an identity-chain update, a content-chain op, a
 * countersignature, a credential — so it answers the question a key page is for,
 * which the identity index's has-ever-declared lookup cannot.
 *
 * Ordered `createdAt.desc`, not the route's `ingestedAt.desc` default: the table's
 * one timestamp column is the op's own author-claimed clock, and a column that
 * disagrees with the ordering it is sorted by reads as broken. Both orderings are
 * served on this route.
 *
 * `enabled` carries TWO gates: a relay index must exist, and `relays` must be
 * non-empty — the subset whose own probe said they honour `signerKey=`
 * (`useIndexSignerKeyFilterRelays` in ./index-light). A relay predating the filter
 * ignores it and answers with the unfiltered operations feed, so the query is sent
 * ONLY to vetted relays, never to the configured set: the failover takes the first
 * 2xx from whoever answers, and an unvetted answer here is the whole log presented
 * as this key's signings. The relay set is part of the resetKey too — a query
 * bound to different relays is a different query.
 */
export const useSignerKeyLog = (
  enabled: boolean,
  signerKey: string,
  relays: string[],
  cursor: string,
  onCursor: (cursor: string) => void,
): IndexPage<LogRow> =>
  useIndexPageStack(
    enabled,
    `signer-key-log:${signerKey}:${relays.join(',')}`,
    cursor,
    onCursor,
    async (after) => {
      const page = await fetchSignerKeyOperationsPage({
        order: 'createdAt.desc',
        signerKey,
        relays,
        ...(after ? { after } : {}),
        limit: PAGE,
      });
      return { items: indexOpRows(page.items), next: page.next };
    },
  );

/**
 * Page the RELAY's global log forward from genesis. `cursor` is the position the
 * URL states — it restores a deep link and keeps following the hash thereafter.
 * A cursor the relay never issued (a rebuilt log, or a link minted against a
 * different relay) rejects, which surfaces as the pager's honest error + retry —
 * `⇤ first` re-enters from the top.
 */
export const useRelayLog = (
  enabled: boolean,
  cursor: string,
  onCursor: (cursor: string) => void,
): IndexPage<LogRow> =>
  useIndexPageStack(enabled, 'relay-log', cursor, onCursor, async (after) => {
    const page = await getClient().globalLog(after, { limit: PAGE });
    if (page === 'invalid-cursor') throw new Error('the relay rejected this log cursor');
    if (!page.provenance.answeredBy) throw new Error('no relay served the operation log');
    return { items: toLogRows(page.entries), next: page.next };
  });

/**
 * Page the LOCAL index newest-first. Enabled only once a deep sync has folded
 * ops into the tab — that is the one place a "most recent operations" ordering
 * genuinely exists. The cursor is the local `${createdAt}|${cid}` key, which is
 * meaningful only to THIS tab's corpus, so it is deliberately not deep-linked.
 */
export const useLocalLog = (enabled: boolean): IndexPage<LogRow> =>
  useIndexPageStack(enabled, 'local-log', '', undefined, async (after) => {
    const db = await getDb();
    const page = await db.opsPage({ before: after ?? '', limit: PAGE });
    return { items: localOpRows(page.rows), next: page.next };
  });
