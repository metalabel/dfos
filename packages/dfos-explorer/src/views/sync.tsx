/*

  LOCAL SYNC — the local index's own page

  This was a 340px sidebar riding along beside home and the browse pages, which
  cost every content view a third of its width to show a control panel nobody
  reads twice. It is a page now: the sync instrument, an honest account of what
  the tab is holding, a divergence spot-check, and the reset.

  Browsing the synced corpus still lives on the index pages (documents /
  identities). This page is about the STORE, not what's in it.

*/

import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Panel, Term } from '../components/ui';
import type { OpKind } from '../lib/db';
import { estimateStorageBytes } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { checkDivergence, type DivergenceReport } from '../lib/divergence';
import { fmtBytes, fmtCount } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { getRelays } from '../lib/relays';
import {
  AUTO_SYNC_OPTIONS,
  getAutoSyncMinutes,
  setAutoSyncMinutes,
  subscribeSettings,
} from '../lib/settings';
import {
  nextAutoSyncAt,
  resetLocalIndex,
  startSync,
  stopSync,
  useSyncState,
} from '../lib/sync-store';

interface Counts {
  ops: number;
  chains: number;
  byKind: Partial<Record<OpKind, number>>;
  storageBytes: number | null;
}

const EMPTY: Counts = { ops: 0, chains: 0, byKind: {}, storageBytes: null };

/** "next auto-sync" hint from a due ms-epoch: "~4m", "soon", "now". */
const autoSyncHint = (dueAt: number): string => {
  if (!dueAt) return '';
  const secs = Math.round((dueAt - Date.now()) / 1000);
  if (secs <= 0) return 'now';
  if (secs < 60) return 'soon';
  return `~${Math.round(secs / 60)}m`;
};

/**
 * Live counts off the local index. Refreshes on every dbEpoch bump (sync pages,
 * JIT writes, a reset) but throttled while a run is streaming them.
 */
const useLocalCounts = (): Counts => {
  const [counts, setCounts] = useState<Counts>(EMPTY);
  const sync = useSyncState();
  const busy = sync.phase === 'syncing' || sync.phase === 'resolving';
  const lastPaint = useRef(0);

  useEffect(() => {
    const refresh = async (): Promise<void> => {
      // a local-index open failure (another tab blocking an upgrade) leaves the
      // counts at their zero floor rather than throwing an unhandled rejection —
      // the page reads "0 chains", an honest empty state, not a stuck spinner.
      const db = await getDb().catch(() => null);
      if (!db) return;
      const [c, storageBytes] = await Promise.all([db.counts(), estimateStorageBytes()]);
      setCounts({ ...c, storageBytes });
    };
    if (busy) {
      const now = performance.now();
      if (now - lastPaint.current > 500) {
        lastPaint.current = now;
        void refresh();
      }
    } else {
      void refresh();
    }
  }, [sync.dbEpoch, sync.phase, busy]);

  return counts;
};

// -----------------------------------------------------------------------------
// the instrument — pull the log, stop it, set the cadence
// -----------------------------------------------------------------------------

const Instrument = (props: { counts: Counts }) => {
  const { counts } = props;
  const sync = useSyncState();
  const syncing = sync.phase === 'syncing';
  const resolving = sync.phase === 'resolving';
  const [autoMin, setAutoMin] = useState(getAutoSyncMinutes());

  useEffect(() => subscribeSettings(() => setAutoMin(getAutoSyncMinutes())), []);

  const summary = useMemo(() => {
    const k = counts.byKind;
    const parts: string[] = [];
    if (k['identity-op']) parts.push(`${fmtCount(k['identity-op'])} identity chains`);
    if (k['content-op']) parts.push(`${fmtCount(k['content-op'])} content chains`);
    if (k['credential']) parts.push(`${fmtCount(k['credential'])} credentials`);
    return parts.join(' · ');
  }, [counts]);

  return (
    <Panel
      title="local sync"
      right={
        <span class="lbl">
          {fmtCount(counts.chains)} chains
          {counts.storageBytes ? (
            <span class="idb-size"> · {fmtBytes(counts.storageBytes)} on disk</span>
          ) : null}
        </span>
      }
      orient={
        <>
          Your browser keeps its own copy of every operation it has pulled from the relay logs — a{' '}
          <Term word="local index" def={GLOSSARY['localIndex'] ?? ''} /> in IndexedDB that survives
          reloads. Chains fold from it <b>offline</b>, and the figures on home stop being the
          relay's claim and start being counted in your tab. It lives here and nowhere else.
        </>
      }
    >
      <div class="bar">
        {syncing || resolving ? (
          <button onClick={() => stopSync()} title="abort the running sync">
            stop
          </button>
        ) : (
          <button class={counts.ops ? '' : 'primary'} onClick={() => void startSync('manual')}>
            {counts.ops ? 're-sync' : 'sync the full log'}
          </button>
        )}
      </div>

      {syncing || resolving ? <div class="syncbar" /> : null}

      <div class="lbl" style={{ margin: '7px 0' }}>
        {sync.status ||
          (counts.ops
            ? `${fmtCount(counts.ops)} operations · ${summary}`
            : 'no local data — hit sync')}
      </div>
      {sync.error ? <div class="err">{sync.error}</div> : null}

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
      {autoMin > 0 && !syncing && !resolving ? (
        <div class="lbl autosync-next">next auto-sync {autoSyncHint(nextAutoSyncAt())}</div>
      ) : null}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// divergence — does what we hold still exist upstream?
// -----------------------------------------------------------------------------

const VERDICT_ACCENT = {
  aligned: 'ok',
  diverged: 'bad',
  unknown: 'warn',
  empty: undefined,
} as const;

const Divergence = (props: {
  counts: Counts;
  report: DivergenceReport | null;
  onReport: (r: DivergenceReport | null) => void;
}) => {
  const populated = props.counts.chains > 0;
  const sync = useSyncState();
  const busy = sync.phase === 'syncing' || sync.phase === 'resolving';
  const [checking, setChecking] = useState(false);
  const ran = useRef(false);
  const { onReport, report } = props;

  const run = async (): Promise<void> => {
    setChecking(true);
    try {
      const db = await getDb().catch(() => null);
      if (!db) return;
      onReport(await checkDivergence({ db, relays: getRelays() }));
    } finally {
      setChecking(false);
    }
  };

  // check once on arrival when there is something to check — you came to this
  // page because something looked wrong, so don't make the answer a second click
  useEffect(() => {
    if (ran.current || !populated || busy) return;
    ran.current = true;
    void run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [populated, busy]);

  const verdict = report?.verdict;

  return (
    <Panel
      title="divergence"
      accent={verdict ? VERDICT_ACCENT[verdict] : undefined}
      right={
        <span class="lbl">
          {verdict === 'diverged'
            ? 'local data no longer matches the relays'
            : verdict === 'aligned'
              ? 'sample resolves upstream'
              : verdict === 'unknown'
                ? 'inconclusive'
                : 'spot-check'}
        </span>
      }
      orient={
        <>
          The local index never retracts an operation. A relay that <b>drops</b> one — a corpus
          rebuild, a re-mint under new CIDs — leaves this tab holding history no relay carries any
          more, and the local figures quietly stop describing the network. This spot-checks a spread
          of the operations you hold against the relays you configured.
        </>
      }
    >
      <div class="bar">
        <button onClick={() => void run()} disabled={checking || !populated}>
          {checking ? 'checking…' : 'check now'}
        </button>
      </div>

      <div class="ck-note" style={{ marginTop: 8 }}>
        {!populated ? (
          <>Nothing synced yet — there is nothing to compare.</>
        ) : checking && !report ? (
          <>Fetching a sample of your operations back from the relays…</>
        ) : verdict === 'diverged' ? (
          <>
            <b class="err">Local data diverges from the relay — reset recommended.</b>{' '}
            {fmtCount(report?.absent ?? 0)} of {fmtCount(report?.sampled ?? 0)} sampled operations
            no longer exist on any relay you have configured. What you are looking at is a history
            the network has dropped; counts, ages, and browse rows drawn from it describe a corpus
            that is gone. Clearing the local data below and re-syncing is the fix.
          </>
        ) : verdict === 'aligned' ? (
          <>
            Every one of the {fmtCount(report?.sampled ?? 0)} sampled operations still resolves on a
            configured relay. That is a spot-check over a spread of your chains, not a proof of
            completeness — nothing here ever proves completeness.
          </>
        ) : verdict === 'unknown' ? (
          <>
            Inconclusive: {fmtCount(report?.unknown ?? 0)} of {fmtCount(report?.sampled ?? 0)}{' '}
            operations could not be settled either way — a relay that timed out, refused, or errored
            says nothing about whether an operation exists. No sampled operation was definitively
            missing. Retry when the relays answer.
          </>
        ) : (
          <>Not checked yet.</>
        )}
      </div>
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// reset — the destructive control, behind a confirm barrier
// -----------------------------------------------------------------------------

const Reset = (props: { counts: Counts; onCleared: () => void }) => {
  const sync = useSyncState();
  const busy = sync.phase === 'syncing' || sync.phase === 'resolving';
  const [armed, setArmed] = useState(false);
  const [working, setWorking] = useState(false);
  const populated = props.counts.ops > 0;

  const wipe = async (resync: boolean): Promise<void> => {
    setWorking(true);
    try {
      const cleared = await resetLocalIndex().catch(() => false);
      setArmed(false);
      if (!cleared) return;
      // the standing divergence verdict was about data that no longer exists
      props.onCleared();
      if (resync) void startSync('manual');
    } finally {
      setWorking(false);
    }
  };

  return (
    <Panel
      title="reset local data"
      right={
        <span class="lbl">
          {populated ? `${fmtCount(props.counts.ops)} operations stored` : 'nothing stored'}
        </span>
      }
    >
      <div class="ck-note">
        Clears this browser's copy of the operation log — every operation, every chain rollup, the
        per-relay sync cursors, the resolved public projections, and the saved fold verdicts — and
        starts the sync over from the relays you have configured. <b>Local only:</b> nothing is
        deleted, retracted, or submitted anywhere on any relay, and no operation is destroyed — the
        relays still hold whatever they hold, and the next sync pulls it back. What you lose is
        time: a full re-sync has to page the whole log again.
      </div>

      <div class="bar" style={{ marginTop: 8 }}>
        {busy ? (
          <>
            <button disabled>reset local data</button>
            <span class="lbl">stop the running sync first</span>
          </>
        ) : armed ? (
          <>
            <span class="err">clear {fmtCount(props.counts.ops)} stored operations?</span>
            <button onClick={() => void wipe(true)} disabled={working}>
              {working ? 'clearing…' : 'yes — clear and re-sync'}
            </button>
            <button onClick={() => void wipe(false)} disabled={working}>
              clear only
            </button>
            <button onClick={() => setArmed(false)} disabled={working}>
              cancel
            </button>
          </>
        ) : (
          <>
            <button onClick={() => setArmed(true)} disabled={!populated}>
              reset local data
            </button>
            {populated ? null : <span class="lbl">nothing to clear</span>}
          </>
        )}
      </div>
    </Panel>
  );
};

// -----------------------------------------------------------------------------

export const LocalSync = () => {
  const counts = useLocalCounts();
  // the verdict lives here so the reset can retire it — a "diverged" banner left
  // standing over a freshly-cleared store is the same stale-data bug one level up
  const [report, setReport] = useState<DivergenceReport | null>(null);
  return (
    <>
      <Instrument counts={counts} />
      <Divergence counts={counts} report={report} onReport={setReport} />
      <Reset counts={counts} onCleared={() => setReport(null)} />
    </>
  );
};
