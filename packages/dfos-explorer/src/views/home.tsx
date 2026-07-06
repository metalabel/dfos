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

import type { IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { Panel, Term } from '../components/ui';
import type { ChainRollup, OpKind } from '../lib/db';
import { estimateStorageBytes, OP_KINDS } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtAge, fmtBytes, fmtCount, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { indexListState, useIndexCapable, useIndexIdentities } from '../lib/index-light';
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
// RECENT ACTIVITY / INDEX HEAD
//   local (non-indexed) path: latest chains by last op — genuinely recency-ordered.
//   index-capable path: the HEAD of the relay index — the /index/v0 identities
//   endpoint pages by DID ascending (lexicographic), NOT recency, so this panel
//   is titled "head of relay index", never "recent", and each row verifies live.
// -----------------------------------------------------------------------------

// how many head-of-index rows home shows and verifies live
const HEAD_N = 100;

/** One head-of-index identity row on home: attributed name + a live verify badge
 *  that flips to verified as the row enters view and its chain folds in the tab.
 *  opCount reconciles to the fold (the fold wins over the relay hint). */
const IndexHeadRow = (props: { row: IndexIdentityRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('identity', row.did, row.opCount);
  const rec = useVerifyStatus('identity', row.did);
  const name = row.profile?.name ?? '';
  const opCount = rec.facts?.opCount ?? row.opCount;
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/did/${row.did}`)}>
      <td>
        <span class="kind identity-op">identity</span>
      </td>
      <td>
        {name ? <b>{name}</b> : short(row.did, 14, 5)}{' '}
        <VerifyBadge kind="identity" chainId={row.did} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td class="n">{fmtCount(opCount)} ops</td>
    </tr>
  );
};

const RecentPanel = (props: {
  obs: Observatory | null;
  indexed: boolean | null;
  indexRows: IndexIdentityRow[];
  indexLoading: boolean;
  indexError: boolean;
}) => {
  // index-capable → show the HEAD of the live relay index (DID-ordered, NOT
  // recency), every row verifying in real time (attributed → verified) right on
  // the landing page. Otherwise fall back to the local recent-activity view.
  if (props.indexed === true) {
    const head = props.indexRows.slice(0, HEAD_N);
    const state = indexListState(props.indexLoading, props.indexError, head.length);
    return (
      <Panel
        title="identities · head of relay index"
        accent="warn"
        right={
          <span class="lbl">head {fmtCount(head.length)} · from relay index · verifying live</span>
        }
      >
        {state === 'rows' ? (
          <div class="index-rows">
            <table>
              <tbody>
                {head.map((row) => (
                  <IndexHeadRow key={row.did} row={row} />
                ))}
              </tbody>
            </table>
          </div>
        ) : state === 'error' ? (
          <span class="muted">couldn’t reach the relay index.</span>
        ) : state === 'loading' ? (
          <span class="muted">loading the head of the relay index…</span>
        ) : (
          <span class="muted">no public identities in the relay index</span>
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
// PUBLIC IDENTITIES — attributed profile chips
// -----------------------------------------------------------------------------

const IdentitiesPanel = (props: {
  obs: Observatory | null;
  indexed: boolean | null;
  indexRows: IndexIdentityRow[];
  indexLoading: boolean;
  indexError: boolean;
}) => {
  const sync = useSyncState();
  const busy = sync.phase === 'resolving' || sync.phase === 'syncing';
  const localIds = props.obs?.identities ?? [];
  const populated = (props.obs?.counts.chains ?? 0) > 0;
  // index-capable relay → surface attributed identities straight from the live
  // relay index (a hint, framed as such), so home is alive before/without any
  // sync. Where no relay advertises the index, fall back to the local synced set.
  const indexed = props.indexed === true;
  const indexIds = props.indexRows
    .filter((r) => typeof r.profile?.name === 'string' && r.profile.name.length > 0)
    .slice(0, 12)
    .map((r) => ({ chainId: r.did, name: r.profile?.name ?? '' }));
  const ids = indexed ? indexIds : localIds;
  // distinguish index error / still-loading / settled-empty so an unreachable or
  // loading index never shows a false "nobody is public"
  const idxState = indexListState(props.indexLoading, props.indexError, indexIds.length);
  return (
    <Panel
      title="public identities"
      accent={ids.length > 0 ? 'warn' : undefined}
      right={<span class="lbl">attributed · from {indexed ? 'relay index' : 'local index'}</span>}
    >
      {ids.length === 0 ? (
        <span class="muted">
          {/* only claim "none" once resolution has settled — while Phase 2 runs
              an empty strip means "not resolved yet", not "nobody is public" */}
          {indexed
            ? idxState === 'error'
              ? 'couldn’t reach the relay index.'
              : idxState === 'loading'
                ? 'loading identities from the relay index…'
                : 'no public identities in the relay index'
            : !populated
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
  // one live index-identities fetch, shared by the head panel and the id strip
  const indexed = useIndexCapable();
  const idIndex = useIndexIdentities(indexed === true, true);

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
      <RecentPanel
        obs={obs}
        indexed={indexed}
        indexRows={idIndex.rows}
        indexLoading={idIndex.loading}
        indexError={idIndex.error}
      />
      <IdentitiesPanel
        obs={obs}
        indexed={indexed}
        indexRows={idIndex.rows}
        indexLoading={idIndex.loading}
        indexError={idIndex.error}
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
