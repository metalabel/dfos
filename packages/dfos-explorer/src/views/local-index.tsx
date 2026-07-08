/*

  LOCAL INDEX — the side panel

  Sync the full operation log from every configured relay into IndexedDB, so the
  detail pages can fold chains offline. This panel is the sync INSTRUMENT — its
  controls, progress, and footprint. Browsing the synced corpus lives on the
  dedicated index pages (documents / identities), not here.

*/

import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Panel } from '../components/ui';
import type { OpKind } from '../lib/db';
import { estimateStorageBytes } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtBytes, fmtCount } from '../lib/format';
import {
  AUTO_SYNC_OPTIONS,
  getAutoSyncMinutes,
  setAutoSyncMinutes,
  subscribeSettings,
} from '../lib/settings';
import { markDbChanged, nextAutoSyncAt, startSync, stopSync, useSyncState } from '../lib/sync-store';

/** "next auto-sync" hint from a due ms-epoch: "~4m", "soon", "now". */
const autoSyncHint = (dueAt: number): string => {
  if (!dueAt) return '';
  const secs = Math.round((dueAt - Date.now()) / 1000);
  if (secs <= 0) return 'now';
  if (secs < 60) return 'soon';
  return `~${Math.round(secs / 60)}m`;
};

export const LocalIndex = () => {
  const [counts, setCounts] = useState<{
    ops: number;
    chains: number;
    byKind: Partial<Record<OpKind, number>>;
  }>({ ops: 0, chains: 0, byKind: {} });
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
    setStorageBytes(await estimateStorageBytes());
  };

  // live-refresh the counts as the global sync makes progress (throttled), and a
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
    </Panel>
  );
};
