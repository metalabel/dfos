/*

  LOCAL INDEX — the side panel

  Sync the full operation log from every configured relay into IndexedDB, then
  browse the derived chain rollups offline. The counts and rows here are
  relay-asserted routing metadata; verification happens on the detail pages.

*/

import { useEffect, useMemo, useState } from 'preact/hooks';
import { Panel } from '../components/ui';
import { getClient } from '../lib/client';
import type { ChainRollup, OpKind } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtCount, short } from '../lib/format';
import { getRelays, subscribeRelays } from '../lib/relays';
import { syncAll } from '../lib/sync';

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
  const [filter, setFilter] = useState<Filter>('all');
  const [sort, setSort] = useState<Sort>('recent');
  const [syncing, setSyncing] = useState(false);
  const [status, setStatus] = useState('');
  const [relays, setRelays] = useState(getRelays());

  useEffect(() => subscribeRelays(() => setRelays(getRelays())), []);

  const refresh = async (): Promise<void> => {
    const db = await getDb();
    setCounts(await db.counts());
    setRows(
      await db.chainsQuery({
        sort,
        kind: filter === 'all' ? undefined : filter,
        limit: 300,
      }),
    );
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, sort]);

  const doSync = async (): Promise<void> => {
    if (syncing) return;
    setSyncing(true);
    setStatus('starting…');
    try {
      const db = await getDb();
      let lastPaint = 0;
      const result = await syncAll({
        db,
        client: getClient(),
        relays,
        onProgress: (p) => {
          setStatus(
            `${short(p.relay.replace(/^https?:\/\//, ''), 18, 0)} · ${fmtCount(p.count)} ops · ${fmtCount(p.chains)} chains`,
          );
          const now = performance.now();
          if (now - lastPaint > 500) {
            lastPaint = now;
            void refresh();
          }
        },
      });
      setStatus(
        result.errors.length
          ? `done, ${result.errors.length} relay error(s): ${result.errors.map((e) => e.error).join('; ')}`
          : `done · +${fmtCount(result.added)} new ops`,
      );
    } catch (e) {
      setStatus(`sync failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSyncing(false);
      void refresh();
    }
  };

  const doWipe = async (): Promise<void> => {
    const db = await getDb();
    await db.wipe();
    setStatus('wiped');
    void refresh();
  };

  const summary = useMemo(() => {
    const k = counts.byKind;
    const parts: string[] = [];
    if (k['identity-op']) parts.push(`${fmtCount(k['identity-op'])} id`);
    if (k['content-op']) parts.push(`${fmtCount(k['content-op'])} content`);
    if (k['credential']) parts.push(`${fmtCount(k['credential'])} cred`);
    return parts.join(' · ');
  }, [counts]);

  return (
    <Panel title="local index" right={<span class="lbl">{fmtCount(counts.chains)} chains</span>}>
      <div class="bar">
        <button onClick={() => void doSync()} disabled={syncing}>
          {syncing ? 'syncing…' : 'sync full log'}
        </button>
        <button onClick={() => void doWipe()} disabled={syncing} title="clear IndexedDB">
          wipe
        </button>
      </div>
      <div class="lbl" style={{ margin: '7px 0' }}>
        {status ||
          (counts.ops ? `${fmtCount(counts.ops)} ops · ${summary}` : 'no local data — hit sync')}
      </div>
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
        {rows.length === 0 ? (
          <span class="muted">{counts.chains ? 'no chains of this kind' : 'idle'}</span>
        ) : (
          <table>
            <tbody>
              {rows.map((row) => (
                <tr key={row.chainId} onClick={() => (location.hash = routeForChain(row))}>
                  <td>
                    <span class={`kind ${row.kind}`}>{row.kind.replace('-op', '')}</span>
                  </td>
                  <td>{short(row.chainId, 13, 5)}</td>
                  <td class="n">{row.opCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
};
