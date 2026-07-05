/*

  LOCAL INDEX — the side panel

  Sync the full operation log from every configured relay into IndexedDB, then
  browse the derived chain rollups offline. The counts and rows here are
  relay-asserted routing metadata; verification happens on the detail pages.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Panel } from '../components/ui';
import type { ChainRollup, ExplorerOp, OpKind } from '../lib/db';
import { estimateStorageBytes } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtBytes, fmtCount, short } from '../lib/format';
import {
  AUTO_SYNC_OPTIONS,
  getAutoSyncMinutes,
  setAutoSyncMinutes,
  subscribeSettings,
} from '../lib/settings';
import {
  markDbChanged,
  nextAutoSyncAt,
  startSync,
  stopSync,
  useSyncState,
} from '../lib/sync-store';

type Filter = 'all' | 'identity-op' | 'content-op' | 'credential';
type Sort = 'recent' | 'ops';

const FILTERS: { key: Filter; label: string }[] = [
  { key: 'all', label: 'all' },
  { key: 'identity-op', label: 'identity' },
  { key: 'content-op', label: 'content' },
  { key: 'credential', label: 'credential' },
];

const SORTS: { key: Sort; label: string }[] = [
  { key: 'recent', label: 'recent' },
  { key: 'ops', label: 'most ops' },
];

// The sidebar is a bounded ACTIVITY panel, not the whole corpus — rendering all
// ~20k rollups as DOM rows was a real perf bug (pages measured in thousands of
// px). Cap what we paint and route "browse all" into the dedicated index pages.
const SIDEBAR_LIMIT = 50;

/** The dedicated index page + total for a filter, for the "browse all N →" link. */
const browseAllTarget = (
  filter: Filter,
  counts: { chains: number; byKind: Partial<Record<OpKind, number>> },
): { href: string; total: number } | null => {
  switch (filter) {
    case 'identity-op':
      return { href: '#/identities', total: counts.byKind['identity-op'] ?? 0 };
    case 'content-op':
      return { href: '#/documents', total: counts.byKind['content-op'] ?? 0 };
    default:
      return null; // 'all' and 'credential' have no single dedicated index page
  }
};

/** "next auto-sync" hint from a due ms-epoch: "~4m", "soon", "now". */
const autoSyncHint = (dueAt: number): string => {
  if (!dueAt) return '';
  const secs = Math.round((dueAt - Date.now()) / 1000);
  if (secs <= 0) return 'now';
  if (secs < 60) return 'soon';
  return `~${Math.round(secs / 60)}m`;
};

const routeForChain = (row: ChainRollup): string => {
  switch (row.kind) {
    case 'content-op':
      return `#/content/${row.chainId}`;
    case 'identity-op':
    case 'credential': // credential ops chain under their issuer DID
      return `#/did/${row.chainId}`;
    case 'countersign': // chainId is the target op CID
      return `#/op/${row.chainId}`;
    default:
      return `#/op/${row.headCid}`;
  }
};

export const LocalIndex = () => {
  const [counts, setCounts] = useState<{
    ops: number;
    chains: number;
    byKind: Partial<Record<OpKind, number>>;
  }>({ ops: 0, chains: 0, byKind: {} });
  const [rows, setRows] = useState<ChainRollup[]>([]);
  // credentials chain under their issuer DID (colliding with the identity
  // chain), so they don't surface as their own rollup — list them from the ops
  // store instead when the credential filter is active
  const [credRows, setCredRows] = useState<ExplorerOp[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [sort, setSort] = useState<Sort>('recent');
  const [storageBytes, setStorageBytes] = useState<number | null>(null);
  const sync = useSyncState();
  const syncing = sync.phase === 'syncing';
  // either phase streams dbEpoch bumps per page/chain — throttle refreshes for both
  const busy = syncing || sync.phase === 'resolving';
  const [wiped, setWiped] = useState('');
  const [autoMin, setAutoMin] = useState(getAutoSyncMinutes());
  const lastPaint = useRef(0);

  useEffect(() => subscribeSettings(() => setAutoMin(getAutoSyncMinutes())), []);

  const refresh = async (): Promise<void> => {
    const db = await getDb();
    setCounts(await db.counts());
    if (filter === 'credential') {
      setCredRows(await db.opsOfKind('credential', SIDEBAR_LIMIT));
      setRows([]);
    } else {
      const res = await db.chainsQuery({
        sort,
        kind: filter === 'all' ? undefined : filter,
        limit: SIDEBAR_LIMIT,
      });
      setRows(res.rows);
      setCredRows([]);
    }
    setStorageBytes(await estimateStorageBytes());
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, sort]);

  // live-refresh the rows as the global sync makes progress (throttled), and a
  // final refresh whenever a run settles
  useEffect(() => {
    if (busy) {
      const now = performance.now();
      if (now - lastPaint.current > 500) {
        lastPaint.current = now;
        void refresh();
      }
    } else {
      void refresh();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sync.dbEpoch, sync.phase]);

  // any sync (even one kicked from the home hero) supersedes the wiped notice
  useEffect(() => {
    if (syncing && wiped) setWiped('');
  }, [syncing, wiped]);

  const doSync = (): void => {
    if (wiped) setWiped('');
    void startSync('manual');
  };

  const doWipe = async (): Promise<void> => {
    const db = await getDb();
    await db.wipe();
    setWiped('wiped');
    markDbChanged();
    void refresh();
  };

  const status = wiped || sync.status;
  const browseAll = filter === 'credential' ? null : browseAllTarget(filter, counts);

  const summary = useMemo(() => {
    const k = counts.byKind;
    const parts: string[] = [];
    if (k['identity-op']) parts.push(`${fmtCount(k['identity-op'])} id`);
    if (k['content-op']) parts.push(`${fmtCount(k['content-op'])} content`);
    if (k['credential']) parts.push(`${fmtCount(k['credential'])} grants`);
    return parts.join(' · ');
  }, [counts]);

  return (
    <Panel title="local index" right={<span class="lbl">{fmtCount(counts.chains)} chains</span>}>
      <div class="bar">
        {syncing ? (
          <button onClick={() => stopSync()} title="abort the running sync">
            stop
          </button>
        ) : (
          <button onClick={doSync}>sync full log</button>
        )}
        <button onClick={() => void doWipe()} disabled={syncing} title="clear IndexedDB">
          wipe
        </button>
      </div>
      {syncing ? <div class="syncbar" /> : null}
      <div class="lbl" style={{ margin: '7px 0' }}>
        {status ||
          (counts.ops ? `${fmtCount(counts.ops)} ops · ${summary}` : 'no local data — hit sync')}
        {counts.ops && storageBytes ? (
          <span class="idb-size"> · {fmtBytes(storageBytes)} on disk</span>
        ) : null}
      </div>
      <div class="autosync">
        <span class="lbl">auto-sync</span>
        <div class="filters">
          {AUTO_SYNC_OPTIONS.map((m) => (
            <button
              key={m}
              class={autoMin === m ? 'on' : ''}
              onClick={() => setAutoSyncMinutes(m)}
              title={m === 0 ? 'auto-sync off' : `re-sync in the background every ${m} minutes`}
            >
              {m === 0 ? 'off' : `${m}m`}
            </button>
          ))}
        </div>
      </div>
      {autoMin > 0 && !syncing ? (
        <div class="lbl autosync-next">next auto-sync {autoSyncHint(nextAutoSyncAt())}</div>
      ) : null}
      <div class="filters" style={{ marginBottom: 4 }}>
        {FILTERS.map((f) => (
          <button key={f.key} class={filter === f.key ? 'on' : ''} onClick={() => setFilter(f.key)}>
            {f.label}
          </button>
        ))}
      </div>
      <div class="filters" style={{ marginBottom: 8 }}>
        {SORTS.map((s) => (
          <button key={s.key} class={sort === s.key ? 'on' : ''} onClick={() => setSort(s.key)}>
            {s.label}
          </button>
        ))}
      </div>
      <div class="index-rows">
        {filter === 'credential' ? (
          credRows.length === 0 ? (
            <span class="muted">{counts.byKind['credential'] ? '…' : 'no grants — hit sync'}</span>
          ) : (
            <table>
              <tbody>
                {credRows.map((op) => {
                  const aud = decodeJwsUnsafe(op.jwsToken)?.payload['aud'];
                  return (
                    <tr key={op.cid} onClick={() => (location.hash = `#/cred/${op.cid}`)}>
                      <td>
                        <span class="kind credential">grant</span>
                      </td>
                      <td>{short(op.cid, 13, 5)}</td>
                      <td class="n">{aud === '*' ? 'public' : aud ? 'scoped' : ''}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )
        ) : rows.length === 0 ? (
          <span class="muted">{counts.chains ? 'no chains of this kind' : 'idle'}</span>
        ) : (
          <table>
            <tbody>
              {rows.map((row) => (
                <tr key={row.chainId} onClick={() => (location.hash = routeForChain(row))}>
                  <td>
                    <span class={`kind ${row.kind}`}>{row.kind.replace('-op', '')}</span>
                  </td>
                  <td>{row.name ? <b>{row.name}</b> : short(row.chainId, 13, 5)}</td>
                  <td class="n">{fmtCount(row.opCount)} ops</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {browseAll && browseAll.total > rows.length ? (
          <div class="lbl" style={{ marginTop: 6 }}>
            <a href={browseAll.href}>browse all {fmtCount(browseAll.total)} →</a>
          </div>
        ) : null}
      </div>
    </Panel>
  );
};
