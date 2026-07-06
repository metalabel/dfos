/*

  HOME — the network observatory

  Not a landing page: a live instrument. The local index (relay-asserted
  routing metadata, honestly counted) is the "verified index"; where a relay
  advertises more in its /.well-known, the delta is shown as amber "asserted"
  — that gap IS the thesis (speed from the relay, truth from the math). Before
  any sync the page still reads: relay-asserted figures render in amber with a
  sync CTA, so it is alive from the first paint.

  Everything reads from the LOCAL db + the optional relay hint. No new network
  fetches; nothing here is a verification input.

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
// one stat cell — local verified figure, with a dim "relay asserts N" subline
// where a relay advertises more. Pre-sync (no local corpus) the asserted figure
// takes the numeral in amber.
// -----------------------------------------------------------------------------

const Stat = (props: {
  label: string;
  local: number | null;
  localText?: string | undefined;
  asserted?: number | undefined;
  assertedText?: string | undefined;
  populated: boolean;
}) => {
  const hasLocal = props.localText != null || props.local != null;
  if (props.populated && hasLocal) {
    const main = props.localText ?? fmtCount(props.local ?? 0);
    const showAsserted =
      props.assertedText != null || (props.asserted != null && props.asserted > (props.local ?? 0));
    const sub = props.assertedText ?? `relay asserts ${fmtCount(props.asserted ?? 0)}`;
    return (
      <div class="stat">
        <div class="stat-num">{main}</div>
        <div class="stat-unit">{props.label}</div>
        {showAsserted ? <div class="stat-sub">{sub}</div> : null}
      </div>
    );
  }
  // pre-sync (or a stat with no local value): relay-asserted, amber, honest.
  const amain = props.assertedText ?? (props.asserted != null ? fmtCount(props.asserted) : '—');
  const known = props.assertedText != null || props.asserted != null;
  return (
    <div class="stat">
      <div class="stat-num asserted">{amain}</div>
      <div class="stat-unit">{props.label}</div>
      <div class="stat-sub asserted">{known ? 'asserted' : 'no relay hint'}</div>
    </div>
  );
};

// -----------------------------------------------------------------------------
// NETWORK — stat band + by-kind proportional bar
// -----------------------------------------------------------------------------

const NetworkPanel = (props: { obs: Observatory | null; hint: RelayHint }) => {
  const sync = useSyncState();
  const resolving = sync.phase === 'resolving';
  const { obs, hint } = props;
  const counts = obs?.counts ?? { ops: 0, chains: 0, byKind: {} };
  const populated = counts.chains > 0 || counts.ops > 0;
  const hk = hint.countsByKind ?? {};
  const asserted = (k: OpKind): number | undefined => {
    const key = HINT_KEY[k];
    return key ? hk[key] : undefined;
  };

  const localOldest = obs?.oldestOpAt ? fmtAge(obs.oldestOpAt) : '';
  const assertedOldest = hint.oldestOpAt ? fmtAge(hint.oldestOpAt) : undefined;

  // by-kind segments from the local corpus (or the relay hint pre-sync)
  const kindCounts: [OpKind, number][] = OP_KINDS.map((k) => [
    k,
    (populated ? (counts.byKind[k] ?? 0) : (asserted(k) ?? 0)) as number,
  ]);
  const total = kindCounts.reduce((n, [, c]) => n + c, 0);

  return (
    <Panel
      title="network"
      accent={populated ? 'ok' : 'warn'}
      right={
        <span class="lbl">
          {populated ? 'local verified index' : 'relay-asserted — nothing synced'}
        </span>
      }
    >
      {/* The "relay asserts N" comparison subline renders ONLY on operations —
          the one figure where local and relay counts share a unit (ops vs ops).
          countsByKind advertises per-kind OP counts while the local identities /
          content figures are CHAIN counts, so a subline there would imply a
          verification delta that is really a unit artifact. Pre-sync the amber
          asserted numerals still render for every stat (no local claim to
          compare against — they're the only data, framed 'asserted'). */}
      <div class="statband">
        <Stat
          label="operations"
          local={populated ? counts.ops : null}
          asserted={hint.opCount}
          populated={populated}
        />
        <Stat
          label="identities"
          local={populated ? (counts.byKind['identity-op'] ?? 0) : null}
          asserted={populated ? undefined : asserted('identity-op')}
          populated={populated}
        />
        <Stat
          label="content chains"
          local={populated ? (counts.byKind['content-op'] ?? 0) : null}
          asserted={populated ? undefined : asserted('content-op')}
          populated={populated}
        />
        <Stat
          label="credentials"
          local={populated ? (counts.byKind['credential'] ?? 0) : null}
          asserted={populated ? undefined : asserted('credential')}
          populated={populated}
        />
        <Stat
          label="public docs"
          local={populated ? (obs?.publicDocs ?? 0) : null}
          localText={populated && resolving ? '…' : undefined}
          assertedText={populated && resolving ? 'resolving' : undefined}
          populated={populated}
        />
        <Stat
          label="oldest op"
          local={populated ? 0 : null}
          localText={populated ? localOldest || '—' : undefined}
          assertedText={populated ? undefined : assertedOldest}
          populated={populated}
        />
      </div>

      {total > 0 ? (
        <div style={{ marginTop: 12 }}>
          <div class="lbl" style={{ marginBottom: 6 }}>
            by kind {populated ? '' : '· relay-asserted'}
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

      {!populated ? (
        <div class="hero-actions" style={{ marginTop: 12 }}>
          {sync.phase === 'syncing' ? (
            <button onClick={() => stopSync()}>stop</button>
          ) : (
            <button class="primary" onClick={() => void startSync('manual')}>
              sync full log
            </button>
          )}
          <span class="muted">
            Pull the operation log from your relays into a local IndexedDB store — then every figure
            above is counted from the math in your tab, not taken on faith.
          </span>
        </div>
      ) : null}
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
