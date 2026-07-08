/*

  HOME — the network observatory

  Not a landing page: a live instrument. Two sources, one honest palette:
  RELAY-ASSERTED figures (the relay's /.well-known claim) are the amber
  headline; VERIFIED-LOCALLY figures (folded in your tab) are green. The gap
  between them IS the thesis — speed from the relay, truth from the math. As
  you browse, rows verify locally and the verified-ops figure climbs toward the
  relay's assertion; a deep sync closes it entirely (and audits for omissions).

  Everything reads from the LOCAL db + the relay hint. No new verification
  inputs here — the figures reflect what's already been folded.

*/

import type { IndexContentRow, IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { Panel, Term } from '../components/ui';
import type { ChainRollup, OpKind } from '../lib/db';
import { estimateStorageBytes, OP_KINDS } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtAge, fmtBytes, fmtCount, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  indexListState,
  useIndexCapable,
  useIndexContent,
  useIndexIdentities,
  useIndexIter2,
  type IndexLoad,
} from '../lib/index-light';
import { fetchRelayHint, type RelayHint } from '../lib/relay-hint';
import { startSync, stopSync, useSyncState } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';

const SAMPLES: { label: string; q: string }[] = [
  { label: 'identity', q: 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e' },
  { label: 'public content', q: 'dn2nc79k7z6ekzfhd43he4v8tr6h236' },
  { label: 'issuer (has credential)', q: 'did:dfos:tz49rzd68z98dfvre622nv2ta3a28vt' },
];

// the six primitive buckets, in a stable render order for the by-kind bar
const KIND_LABEL: Record<OpKind, string> = {
  'identity-op': 'identity',
  'content-op': 'content',
  credential: 'credential',
  artifact: 'artifact',
  countersign: 'countersign',
  revocation: 'revocation',
};

const KIND_COLOR: Record<OpKind, string> = {
  'identity-op': 'var(--ok)',
  'content-op': 'var(--link)',
  credential: 'var(--cred)',
  artifact: 'var(--dim)',
  countersign: 'var(--ink)',
  revocation: 'var(--bad)',
};

// relays key countsByKind by PRIMITIVE ('identity'), the local index by op-kind
// ('identity-op') — map so the asserted subline lines up with the local figure.
const HINT_KEY: Partial<Record<OpKind, string>> = {
  'identity-op': 'identity',
  'content-op': 'content',
  credential: 'credential',
  artifact: 'artifact',
  countersign: 'countersign',
  revocation: 'revocation',
};

interface Counts {
  ops: number;
  chains: number;
  byKind: Partial<Record<OpKind, number>>;
}

interface Observatory {
  counts: Counts;
  oldestOpAt: string;
  publicDocs: number;
  recent: ChainRollup[];
  identities: { chainId: string; name: string; avatarRef?: string }[];
  storageBytes: number | null;
}

const chainRoute = (row: ChainRollup): string =>
  row.kind === 'content-op' ? `#/content/${row.chainId}` : `#/did/${row.chainId}`;

// -----------------------------------------------------------------------------
// one stat cell. Trust palette: amber = RELAY-ASSERTED (the network's claim, a
// hint), green = VERIFIED LOCALLY (folded in your tab). The headline numeral is
// the relay-asserted figure in amber; a green subline shows how much of it your
// tab has verified. When the whole figure is verified locally the numeral goes
// green. `verifiedText` overrides the subline for figures that are inherently
// local (e.g. public docs resolved in-tab).
// -----------------------------------------------------------------------------

const Stat = (props: {
  label: string;
  asserted: number | null;
  assertedText?: string | undefined;
  verified?: number | null | undefined;
  verifiedText?: string | undefined;
  fullyVerified?: boolean | undefined;
  // amber/dim subline override for a figure with no relay assertion to verify
  // against (e.g. a local-only count that needs a deep sync to compute).
  noteText?: string | undefined;
}) => {
  const known = props.assertedText != null || props.asserted != null;
  const main = props.assertedText ?? (props.asserted != null ? fmtCount(props.asserted) : '—');
  const verified = props.verified ?? 0;
  const green = props.verifiedText != null || props.fullyVerified === true || verified > 0;
  const sub =
    props.verifiedText ??
    (props.fullyVerified === true
      ? 'verified locally'
      : verified > 0
        ? `${fmtCount(verified)} verified`
        : (props.noteText ?? (known ? 'relay-asserted' : 'no relay hint')));
  // the NUMERAL goes green only when the whole figure is verified locally
  // (a deep audit, or an inherently-local resolved figure); a partial verified
  // delta greens only the SUBLINE, leaving the relay-asserted headline amber.
  const numGreen = props.fullyVerified === true || props.verifiedText != null;
  return (
    <div class="stat">
      <div class={`stat-num ${numGreen ? 'ok' : 'asserted'}`}>{main}</div>
      <div class="stat-unit">{props.label}</div>
      <div class={`stat-sub ${green ? 'ok' : 'asserted'}`}>{sub}</div>
    </div>
  );
};

// -----------------------------------------------------------------------------
// NETWORK — stat band + by-kind proportional bar
// -----------------------------------------------------------------------------

const NetworkPanel = (props: { obs: Observatory | null; hint: RelayHint }) => {
  const sync = useSyncState();
  const resolving = sync.phase === 'resolving';
  const syncing = sync.phase === 'syncing';
  const { obs, hint } = props;
  const counts = obs?.counts ?? { ops: 0, chains: 0, byKind: {} };
  const hk = hint.countsByKind ?? {};
  const asserted = (k: OpKind): number | null => {
    const key = HINT_KEY[k];
    return key ? (hk[key] ?? null) : null;
  };

  // the one unit-safe local-vs-network comparison: OPERATIONS folded in your tab
  // (JIT folds as you browse + any deep sync) vs the ops the relay asserts. This
  // is the honest "how much of the network have I verified" figure; it grows as
  // you browse and completes on a deep sync. Per-kind identity/content figures
  // are CHAIN counts locally but OP counts in the hint, so they carry no verified
  // delta — they stay relay-asserted headline figures.
  const localOps = counts.ops;
  const assertedOps = hint.opCount ?? 0;
  const fullyVerified = assertedOps > 0 && localOps >= assertedOps;

  const assertedOldest = hint.oldestOpAt ? fmtAge(hint.oldestOpAt) : undefined;
  const localOldest = obs?.oldestOpAt ? fmtAge(obs.oldestOpAt) : undefined;
  const publicDocs = obs?.publicDocs ?? null;

  // by-kind: relay-asserted proportions — the network's shape, always available.
  const kindCounts: [OpKind, number][] = OP_KINDS.map((k) => [k, asserted(k) ?? 0]);
  const total = kindCounts.reduce((n, [, c]) => n + c, 0);

  const right = fullyVerified
    ? 'fully verified locally'
    : localOps > 0
      ? `relay-asserted · ${fmtCount(localOps)} ops verified locally`
      : 'relay-asserted';

  return (
    <Panel
      title="network"
      accent={fullyVerified ? 'ok' : 'warn'}
      right={<span class="lbl">{right}</span>}
    >
      {/* Headline numerals are the relay's assertion (amber = hint); a green
          subline shows what your tab has folded (verified locally). Only
          operations carries a numeric verified delta — it is the one figure
          where local and relay share a unit (ops vs ops). */}
      <div class="statband">
        <Stat
          label="operations"
          asserted={assertedOps}
          verified={localOps}
          fullyVerified={fullyVerified}
        />
        <Stat label="identities" asserted={asserted('identity-op')} fullyVerified={fullyVerified} />
        <Stat
          label="content chains"
          asserted={asserted('content-op')}
          fullyVerified={fullyVerified}
        />
        <Stat label="credentials" asserted={asserted('credential')} fullyVerified={fullyVerified} />
        <Stat
          label="public docs"
          asserted={null}
          assertedText={
            resolving
              ? 'resolving'
              : publicDocs != null && publicDocs > 0
                ? fmtCount(publicDocs)
                : '—'
          }
          verifiedText={
            publicDocs != null && publicDocs > 0 && !resolving ? 'verified locally' : undefined
          }
          noteText={
            resolving
              ? 'resolving'
              : publicDocs && publicDocs > 0
                ? undefined
                : 'local · deep-sync to count'
          }
        />
        <Stat
          label="oldest op"
          asserted={null}
          assertedText={
            (fullyVerified && localOldest ? localOldest : assertedOldest) ?? localOldest ?? '—'
          }
          verifiedText={fullyVerified && localOldest ? 'verified locally' : undefined}
        />
      </div>

      {total > 0 ? (
        <div style={{ marginTop: 12 }}>
          <div class="lbl" style={{ marginBottom: 6 }}>
            by kind · relay-asserted
          </div>
          <div class="kindbar">
            {kindCounts.map(([k, c]) =>
              c > 0 ? (
                <div
                  key={k}
                  class="kindbar-seg"
                  style={{ flex: `${c} 0 auto`, background: KIND_COLOR[k] }}
                  title={`${KIND_LABEL[k]}: ${fmtCount(c)}`}
                />
              ) : null,
            )}
          </div>
          <div class="kindbar-legend">
            {kindCounts.map(([k, c]) => (
              <span key={k} class="kindbar-key">
                <span class="kindbar-dot" style={{ background: KIND_COLOR[k] }} />
                {KIND_LABEL[k]} <b>{fmtCount(c)}</b>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <div class="hero-actions" style={{ marginTop: 12 }}>
        {syncing ? (
          <button onClick={() => stopSync()}>stop</button>
        ) : (
          <button class={fullyVerified ? '' : 'primary'} onClick={() => void startSync('manual')}>
            {fullyVerified ? 're-audit full log' : 'deep-sync · verify the full log'}
          </button>
        )}
        <span class="muted">
          {fullyVerified
            ? 'Every figure above is counted from the math in your tab. A deep sync re-audits the full log for completeness — it can detect a relay index’s omissions.'
            : 'Headline figures are relay-asserted hints; rows you browse verify locally as you view them. Deep-sync folds the entire operation log into your tab — every figure then counted from math, not taken on faith, and relay omissions become detectable.'}
        </span>
      </div>
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// RECENT ACTIVITY — public content chains by most-recent head time
//   index-capable path: content `order=headAt.desc` — genuinely recency-ordered
//   (the relay serves the sort), each row an attributed hint that greens as it
//   scrolls into view and its chain folds. This is the network's pulse AND the
//   recent-public-documents feed: the title projection surfaces on each row.
//   local (non-indexed) path: latest local chains by last op, as before.
// -----------------------------------------------------------------------------

// how many recent rows home shows and verifies live
const RECENT_N = 60;

/** One recent-content row: the projected title (attributed) + when, with a live
 *  verify badge that flips to verified as the row enters view and its chain folds
 *  in the tab. opCount/deletion reconcile to the fold (the fold wins). */
const RecentContentRow = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <span class="kind content-op">content</span>
      </td>
      <td>
        {row.title ? (
          <span class="attr">{row.title}</span>
        ) : (
          <span class="cid">{short(row.contentId, 14, 5)}</span>
        )}{' '}
        <VerifyBadge kind="content" chainId={row.contentId} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td class="n">{fmtAge(row.headAt)}</td>
    </tr>
  );
};

const RecentPanel = (props: {
  obs: Observatory | null;
  indexed: boolean | null;
  content: IndexLoad<IndexContentRow>;
}) => {
  // index-capable → the live recent-public-documents feed, content ordered by
  // author-claimed head time (recency), every row verifying in real time. Where
  // no relay advertises the index, fall back to the local recent-activity view.
  if (props.indexed === true) {
    const rows = props.content.rows.slice(0, RECENT_N);
    const state = indexListState(props.content.loading, props.content.error, rows.length);
    return (
      <Panel
        title="recent activity"
        accent="warn"
        right={
          <span class="lbl">
            public documents · newest active · from relay index · verifying live
          </span>
        }
      >
        {state === 'rows' ? (
          <div class="index-rows">
            <table>
              <tbody>
                {rows.map((row) => (
                  <RecentContentRow key={row.contentId} row={row} />
                ))}
              </tbody>
            </table>
          </div>
        ) : state === 'error' ? (
          <span class="muted">couldn’t reach the relay index.</span>
        ) : state === 'loading' ? (
          <span class="muted">loading recent public documents…</span>
        ) : (
          <span class="muted">no public documents in the relay index</span>
        )}
      </Panel>
    );
  }

  const rows = props.obs?.recent ?? [];
  const populated = (props.obs?.counts.chains ?? 0) > 0;
  return (
    <Panel
      title="recent activity"
      accent={populated ? 'ok' : undefined}
      right={<span class="lbl">latest chains · from local index</span>}
    >
      {rows.length === 0 ? (
        <span class="muted">{populated ? 'no chains yet' : 'sync the log to see activity'}</span>
      ) : (
        <div class="index-rows">
          <table>
            <tbody>
              {rows.map((row) => (
                <tr key={row.chainId} onClick={() => (location.hash = chainRoute(row))}>
                  <td>
                    <span class={`kind ${row.kind}`}>{row.kind.replace('-op', '')}</span>
                  </td>
                  <td>{row.name ? <b>{row.name}</b> : short(row.chainId, 14, 5)}</td>
                  <td class="n">{fmtCount(row.opCount)} ops</td>
                  <td class="n">{fmtAge(row.lastCreatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// RECENTLY ARRIVED IDENTITIES — identities `order=genesisAt.desc`, the newest
// chains first (the relay serves the sort). Each row an attributed name that
// greens as its chain folds. Local fallback: the synced identity strip.
// -----------------------------------------------------------------------------

const ARRIVED_N = 60;

/** One recently-arrived identity row: attributed name + when it arrived
 *  (genesisAt), with a live verify badge that greens as its chain folds. */
const ArrivedIdentityRow = (props: { row: IndexIdentityRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('identity', row.did, row.opCount);
  const rec = useVerifyStatus('identity', row.did);
  const name = row.profile?.name ?? '';
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/did/${row.did}`)}>
      <td>
        <span class="kind identity-op">identity</span>
      </td>
      <td>
        {name ? <span class="attr">{name}</span> : <span class="cid">{short(row.did, 14, 5)}</span>}{' '}
        <VerifyBadge kind="identity" chainId={row.did} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td class="n">{fmtAge(row.genesisAt)}</td>
    </tr>
  );
};

const ArrivedIdentitiesPanel = (props: {
  obs: Observatory | null;
  indexed: boolean | null;
  ids: IndexLoad<IndexIdentityRow>;
}) => {
  // hook stays above the indexed branch — `indexed` resolves null→true/false
  // after mount, and a conditional hook would change the hook order mid-life
  const sync = useSyncState();
  if (props.indexed === true) {
    const rows = props.ids.rows.slice(0, ARRIVED_N);
    const state = indexListState(props.ids.loading, props.ids.error, rows.length);
    return (
      <Panel
        title="recently arrived identities"
        accent="warn"
        right={<span class="lbl">newest first · from relay index · verifying live</span>}
      >
        {state === 'rows' ? (
          <div class="index-rows">
            <table>
              <tbody>
                {rows.map((row) => (
                  <ArrivedIdentityRow key={row.did} row={row} />
                ))}
              </tbody>
            </table>
          </div>
        ) : state === 'error' ? (
          <span class="muted">couldn’t reach the relay index.</span>
        ) : state === 'loading' ? (
          <span class="muted">loading recently-arrived identities…</span>
        ) : (
          <span class="muted">no identities in the relay index</span>
        )}
        <div class="lbl" style={{ marginTop: 9 }}>
          <a href="#/identities">browse all identities →</a>
        </div>
      </Panel>
    );
  }

  // local fallback: the synced identity strip (attributed chips), as before.
  const busy = sync.phase === 'resolving' || sync.phase === 'syncing';
  const ids = props.obs?.identities ?? [];
  const populated = (props.obs?.counts.chains ?? 0) > 0;
  return (
    <Panel
      title="public identities"
      accent={ids.length > 0 ? 'warn' : undefined}
      right={<span class="lbl">attributed · from local index</span>}
    >
      {ids.length === 0 ? (
        <span class="muted">
          {!populated
            ? 'sync the log to surface identities'
            : busy
              ? 'resolving projections…'
              : 'no attributed public profiles yet'}
        </span>
      ) : (
        <>
          <div class="idstrip">
            {ids.map((id) => (
              <a key={id.chainId} class="idchip" href={`#/did/${id.chainId}`} title={id.name}>
                <span class="av">{(id.name || '·').slice(0, 1).toUpperCase()}</span>
                <span class="nm">{id.name}</span>
              </a>
            ))}
          </div>
          <div class="lbl" style={{ marginTop: 9 }}>
            <a href="#/identities">browse all identities →</a>
          </div>
        </>
      )}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// RECENTLY ACTIVE IDENTITIES — DERIVED, not curated: the distinct creator DIDs
// of the recent-content feed, in first-seen (most-recent-activity) order. No
// random sampling — who actually moved the chain most recently. Names come from
// the recently-arrived identity rows when known, else the DID stands in.
// Index-only (it derives from the index content feed); silent otherwise.
// -----------------------------------------------------------------------------

const ACTIVE_N = 12;

const ActiveIdentitiesPanel = (props: {
  indexed: boolean | null;
  content: IndexLoad<IndexContentRow>;
  arrived: IndexIdentityRow[];
}) => {
  if (props.indexed !== true) return null;
  // did → attributed name, from whatever recently-arrived rows we've loaded
  const nameByDid = new Map<string, string>();
  for (const r of props.arrived) {
    const n = r.profile?.name;
    if (typeof n === 'string' && n.length > 0) nameByDid.set(r.did, n);
  }
  // distinct creators in recent-activity order (first appearance wins)
  const seen = new Set<string>();
  const actors: { did: string; name: string }[] = [];
  for (const row of props.content.rows) {
    if (seen.has(row.creatorDID)) continue;
    seen.add(row.creatorDID);
    actors.push({ did: row.creatorDID, name: nameByDid.get(row.creatorDID) ?? '' });
    if (actors.length >= ACTIVE_N) break;
  }
  const state = indexListState(props.content.loading, props.content.error, actors.length);
  return (
    <Panel
      title="recently active identities"
      accent={actors.length > 0 ? 'warn' : undefined}
      right={<span class="lbl">derived from recent activity · attributed</span>}
    >
      {state === 'rows' ? (
        <div class="idstrip">
          {actors.map((a) => (
            <a key={a.did} class="idchip" href={`#/did/${a.did}`} title={a.name || a.did}>
              <span class="av">
                {(a.name || a.did.replace('did:dfos:', '') || '·').slice(0, 1).toUpperCase()}
              </span>
              <span class="nm">{a.name || short(a.did, 12, 4)}</span>
            </a>
          ))}
        </div>
      ) : state === 'error' ? (
        <span class="muted">couldn’t reach the relay index.</span>
      ) : state === 'loading' ? (
        <span class="muted">deriving active identities from recent activity…</span>
      ) : (
        <span class="muted">no recent public activity to derive from</span>
      )}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// sync instrument — compact; the sidebar carries the full controls on wide
// screens, but the drawer is hidden on mobile so home keeps its own.
// -----------------------------------------------------------------------------

const ago = (ms: number): string => {
  if (!ms) return '';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
};

const SyncInstrument = (props: { obs: Observatory | null }) => {
  const sync = useSyncState();
  const syncing = sync.phase === 'syncing';
  const resolving = sync.phase === 'resolving';
  const populated = (props.obs?.counts.chains ?? 0) > 0;
  const bytes = props.obs?.storageBytes ?? null;

  return (
    <Panel
      title="sync"
      right={
        populated ? (
          <span class="lbl">
            {fmtCount(props.obs?.counts.chains ?? 0)} chains
            {bytes ? ` · ${fmtBytes(bytes)}` : ''}
            {sync.lastSyncAt ? ` · ${ago(sync.lastSyncAt)}` : ''}
          </span>
        ) : null
      }
    >
      {syncing || resolving ? (
        <div class="hero">
          <div class="hero-row">
            <span class="spin">◍</span>
            <b>{resolving ? 'resolving public projections' : 'syncing the global log'}</b>
            <span class="muted">{sync.status}</span>
          </div>
          <div class="syncbar" />
          <div class="hero-actions">
            <button onClick={() => stopSync()}>stop</button>
            <span class="muted">
              Runs in the background — navigate freely, it keeps going. Completeness is outside the
              proof; this pulls what these relays hold.
            </span>
          </div>
        </div>
      ) : (
        <div class="hero-actions">
          <button class={populated ? '' : 'primary'} onClick={() => void startSync('manual')}>
            {populated ? 're-sync' : 'sync full log'}
          </button>
          <span class="muted">
            {populated
              ? 'Pulls new ops since your last sync and re-resolves drifted projections.'
              : 'Pull the full operation log into a local store — chains then fold offline.'}
          </span>
          {sync.error ? <div class="err">{sync.error}</div> : null}
        </div>
      )}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// home
// -----------------------------------------------------------------------------

export const Home = (props: { onSample: (q: string) => void }) => {
  const sync = useSyncState();
  const [obs, setObs] = useState<Observatory | null>(null);
  const [hint, setHint] = useState<RelayHint>({});
  const indexed = useIndexCapable();
  // the recency panels (recent activity, recently arrived, derived active) are
  // ENTIRELY about `order=` — meaningless on a relay that ignores it (it would
  // serve LEXICAL rows under a recency label). Gate them on iteration-2 support:
  // `orderedIndexed` is true only when the relay is index-capable AND honours
  // order, null while either is still resolving (hold, don't flash), else false —
  // and false routes each panel to its existing LOCAL-fallback rendering.
  const iter2 = useIndexIter2();
  const orderedIndexed: boolean | null =
    indexed === null || iter2 === null ? null : indexed && iter2;
  // recent public documents by head time (recency) — feeds the recent-activity
  // panel AND the derived recently-active identities; recently-arrived identities
  // by genesis time. Both index-only AND order-only; local paths fall back to the
  // synced corpus (which IS genuinely recency-ordered, by last local op).
  const recentContent = useIndexContent(orderedIndexed === true, true, { order: 'headAt.desc' });
  // recently-arrived is a plain identity enumeration — NOT public-profile-only;
  // name-less arrivals still render (truncated DID), the honest "newest arrivals".
  const arrivedIds = useIndexIdentities(orderedIndexed === true, false, {
    order: 'genesisAt.desc',
  });

  useEffect(() => {
    let dead = false;
    void (async () => {
      const db = await getDb();
      const [counts, oldestOpAt, docs, recentRes, idRes, storageBytes] = await Promise.all([
        db.counts(),
        db.oldestOpAt(),
        db.browseDocuments({ limit: 1 }),
        db.chainsQuery({ sort: 'recent', limit: 15 }),
        db.browseIdentities({ limit: 12 }),
        estimateStorageBytes(),
      ]);
      if (dead) return;
      setObs({
        counts,
        oldestOpAt,
        publicDocs: docs.publicCount,
        recent: recentRes.rows,
        identities: idRes.rows.map((r) => ({
          chainId: r.chainId,
          name: r.name ?? '',
          ...(r.avatarRef ? { avatarRef: r.avatarRef } : {}),
        })),
        storageBytes,
      });
    })();
    return () => {
      dead = true;
    };
  }, [sync.dbEpoch, sync.phase]);

  useEffect(() => {
    let dead = false;
    void fetchRelayHint().then((h) => {
      if (!dead) setHint(h);
    });
    return () => {
      dead = true;
    };
  }, []);

  return (
    <>
      <div class="samples" style={{ marginBottom: 14 }}>
        <span class="lbl">try</span>
        {SAMPLES.map((s) => (
          <span key={s.q} class="chip" onClick={() => props.onSample(s.q)}>
            {s.label}
          </span>
        ))}
        <span class="muted" style={{ marginLeft: 'auto' }}>
          new here? read the <a href="#/glossary">glossary</a>
        </span>
      </div>

      <NetworkPanel obs={obs} hint={hint} />
      <RecentPanel obs={obs} indexed={orderedIndexed} content={recentContent} />
      <ArrivedIdentitiesPanel obs={obs} indexed={orderedIndexed} ids={arrivedIds} />
      <ActiveIdentitiesPanel
        indexed={orderedIndexed}
        content={recentContent}
        arrived={arrivedIds.rows}
      />
      <SyncInstrument obs={obs} />

      <Panel title="what this is">
        <div class="kv about">
          <div class="k">no backend</div>
          <div class="v muted">
            A static page. Relays are swappable parameters, like RPC endpoints — never authorities.
          </div>
          <div class="k">verify-in-tab</div>
          <div class="v muted">
            Signatures, CIDs, and chain linkage recompute locally via{' '}
            <code>@metalabel/dfos-client</code> — the relay's claims render first, then flip to
            verified (or <b>MISMATCH</b>, loudly).
          </div>
          <div class="k">no canonical state</div>
          <div class="v muted">
            Completeness is outside the proof — you see what these relays hold. Full definitions in
            the <Term word="glossary" def={GLOSSARY['verifiedLocal'] ?? ''} />.
          </div>
        </div>
      </Panel>
    </>
  );
};
