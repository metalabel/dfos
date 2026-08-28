/*

  HOME — the network, then what's happening on it

  The stat band is still here and still honest — RELAY-ASSERTED figures amber,
  VERIFIED-LOCALLY figures green, the gap between them the whole thesis — but it
  has been compacted to one strip and is no longer the headline. What leads is
  what an explorer is for: things you can open.

    operations   a real browser over the operation log, leading with the relay
                 index's recency feed so a COLD tab shows what just happened —
                 see lib/log-feed.ts for the three sources and when each is true
    posts        the public post feed off the relay's content index

  Both page 25 at a time off a keyset cursor, and both carry their position in
  the hash so a view can be linked.

*/

import type { IndexContentRow } from '@metalabel/dfos-client';
import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { ContentChip } from '../components/content-chip';
import { DidChip } from '../components/did-chip';
import { DocName, useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { HomeIntro } from '../components/intro';
import { OpLink, Pager, Panel, Term } from '../components/ui';
import { useIndexRowLabel } from '../lib/content-labels';
import type { OpKind } from '../lib/db';
import { estimateStorageBytes, OP_KINDS } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtAge, fmtBytes, fmtCount, schemaLabel, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { useIndexCapable, useIndexContent, useIndexIter2 } from '../lib/index-light';
import {
  logSource,
  useIndexLog,
  useLocalLog,
  useRelayLog,
  type LogRow,
  type LogSource,
} from '../lib/log-feed';
import { fetchRelayHint, type RelayHint } from '../lib/relay-hint';
import { getRelays } from '../lib/relays';
import { getPublicOnly, setPublicOnly } from '../lib/settings';
import { startSync, stopSync, useSyncState } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';
import { useHashParam } from '../router';

/** The lead content feed's type. Everything else lives under #/documents. */
const POST_SCHEMA = 'https://schemas.dfos.com/post/v1';

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
// ('identity-op') — map so the asserted figure lines up with the local one.
const HINT_KEY: Partial<Record<OpKind, string>> = {
  'identity-op': 'identity',
  'content-op': 'content',
  credential: 'credential',
  artifact: 'artifact',
  countersign: 'countersign',
  revocation: 'revocation',
};

interface Observatory {
  /** ops in the local index — INCLUDING ops landed by JIT folds while browsing,
   *  so this counts what the tab holds, not what it has synced. */
  ops: number;
  chains: number;
  oldestOpAt: string;
  storageBytes: number | null;
  /**
   * A LOG SYNC has actually run against some configured relay — sync.ts records a
   * cursor row per relay when a run completes (it records one even for an empty
   * log, precisely so "has ever synced this relay" reads true). This, NOT the op
   * count, gates the newest-first feed: opening a single detail page JIT-indexes
   * that chain's ops, and a two-op corpus from browsing is not "your synced log".
   */
  logSynced: boolean;
}

// -----------------------------------------------------------------------------
// NETWORK — one compact strip. Trust palette unchanged: amber = RELAY-ASSERTED
// (the network's claim, a hint), green = VERIFIED LOCALLY (folded in your tab).
// Only OPERATIONS carries a numeric verified delta — it is the one figure where
// local and relay share a unit (ops vs ops); the per-kind figures are CHAIN
// counts locally but OP counts in the hint, so they stay relay-asserted.
// -----------------------------------------------------------------------------

const StatCell = (props: { label: string; value: string; green: boolean }) => (
  <span class="ss">
    <b class={`ss-num ${props.green ? 'ok' : 'asserted'}`}>{props.value}</b>
    <span class="ss-unit">{props.label}</span>
  </span>
);

const NetworkPanel = (props: { obs: Observatory | null; hint: RelayHint }) => {
  const { obs, hint } = props;
  const hk = hint.countsByKind ?? {};
  const asserted = (k: OpKind): number | null => {
    const key = HINT_KEY[k];
    return key ? (hk[key] ?? null) : null;
  };
  const num = (n: number | null): string => (n != null ? fmtCount(n) : '—');

  const localOps = obs?.ops ?? 0;
  const assertedOps = hint.opCount ?? 0;
  const fullyVerified = assertedOps > 0 && localOps >= assertedOps;
  const oldest = fullyVerified && obs?.oldestOpAt ? obs.oldestOpAt : hint.oldestOpAt;

  // by-kind: relay-asserted proportions — the network's shape, always available.
  const kindCounts: [OpKind, number][] = OP_KINDS.map((k) => [k, asserted(k) ?? 0]);
  const total = kindCounts.reduce((n, [, c]) => n + c, 0);

  return (
    <Panel
      title="network"
      accent={fullyVerified ? 'ok' : 'warn'}
      right={
        <span class="lbl">
          {fullyVerified
            ? 'fully verified locally'
            : localOps > 0
              ? `relay-asserted · ${fmtCount(localOps)} ops verified locally`
              : 'relay-asserted'}
        </span>
      }
    >
      <div class="statstrip">
        {/* the verified delta lives in the panel's right label, not inline — one
            statement of it, and the strip stays one line. */}
        <StatCell label="operations" value={num(hint.opCount ?? null)} green={fullyVerified} />
        <StatCell label="identities" value={num(asserted('identity-op'))} green={fullyVerified} />
        <StatCell
          label="content chains"
          value={num(asserted('content-op'))}
          green={fullyVerified}
        />
        <StatCell label="credentials" value={num(asserted('credential'))} green={fullyVerified} />
        <StatCell label="oldest op" value={oldest ? fmtAge(oldest) : '—'} green={fullyVerified} />
      </div>

      {total > 0 ? (
        <>
          <div class="kindbar sm">
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
        </>
      ) : null}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// OPERATIONS — the op browser (no such surface existed before)
// -----------------------------------------------------------------------------

/** A chain identifier rendered by what it actually is: an identity resolves to
 *  its public profile name, a content chain links to its chain, a bare CID to
 *  its op. Non-chain primitives (credential / countersign / revocation) ride a
 *  shared chainId, which is why this is a switch and not a single link. */
const ChainCell = (props: { chainId: string }) => {
  const { chainId } = props;
  if (!chainId) return <span class="muted">—</span>;
  if (chainId.startsWith('did:dfos:')) return <DidChip did={chainId} />;
  if (chainId.startsWith('baf')) return <OpLink cid={chainId} />;
  return <ContentChip id={chainId} />;
};

/** The shared cells of an operation row; the two wrappers below differ only in
 *  whether the chain is one the verify-queue can fold. */
const OpCells = (props: { row: LogRow; badge?: ComponentChildren }) => {
  const { row } = props;
  return (
    <>
      <td>
        <span class={`kind ${row.kind}`}>{row.kind.replace('-op', '')}</span>
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <ChainCell chainId={row.chainId} /> {props.badge}
      </td>
      <td>{row.type ? <span class="k-role">{row.type}</span> : null}</td>
      <td class="n">{fmtAge(row.createdAt)}</td>
      <td class="cid">{short(row.cid, 10, 6)}</td>
    </>
  );
};

/** identity-op / content-op: the chain folds, so the row greens as it is seen. */
const OpChainRow = (props: { row: LogRow; kind: 'identity' | 'content' }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>(props.kind, row.chainId);
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/op/${row.cid}`)}>
      <OpCells row={row} badge={<VerifyBadge kind={props.kind} chainId={row.chainId} />} />
    </tr>
  );
};

/** artifact / credential / countersign / revocation: standalone ops with no
 *  chain history to fold — the op page itself is where they verify. */
const OpPlainRow = (props: { row: LogRow }) => (
  <tr onClick={() => (location.hash = `#/op/${props.row.cid}`)}>
    <OpCells row={props.row} />
  </tr>
);

const OperationsPanel = (props: {
  obs: Observatory | null;
  assertedOps: number;
  indexed: boolean | null;
}) => {
  // ONE CURSOR PARAM PER SOURCE. The three feeds speak different cursor
  // vocabularies — an opaque ordered token, a log CID, a local `createdAt|cid`
  // key — and a single shared param hands one source's position to another the
  // moment the source changes, including the AUTOMATIC change below, where the
  // reader never touched a control and would just land on an invalid-cursor
  // error. `ops` stays the forward log walk's (deep links minted before the index
  // feed existed still resolve); the index feed carries its own.
  const [cursor, setCursor] = useHashParam('ops');
  const [indexCursor, setIndexCursor] = useHashParam('iops');
  const [srcParam, setSrcParam] = useHashParam('src');
  // `/index/v0/operations` is NEWER than the `capabilities.index` flag, so its
  // absence can only be discovered by asking. ONLY the durable verdict latches —
  // every relay answering 404/501, i.e. the route is genuinely not served. A
  // transient failure (unreachable, 5xx, a rejected cursor) leaves the index
  // selected and retryable in place: latching on one of those would let a single
  // bad page hide a working feed for the rest of the session. The durable latch
  // also can't oscillate, since it never clears.
  const [indexFailed, setIndexFailed] = useState(false);

  // The gate on the LOCAL source is the sync CURSOR, not the op count. Opening any
  // detail page JIT-indexes that chain's ops, so a count-based gate flips this
  // panel to "your synced log" over a handful of ops picked up by browsing — a
  // label that is simply false about where the rows came from.
  const synced = props.obs?.logSynced === true;
  // hold until BOTH the local store and the index capability have settled, so the
  // panel never flashes the genesis walk and then jumps to the recency feed
  const ready = props.obs !== null && props.indexed !== null;
  const source: LogSource = logSource(props.indexed, indexFailed, synced, srcParam);
  const indexOk = props.indexed === true && !indexFailed;
  // a sync pages FORWARD from the start of the log, so a run that was stopped (or
  // is still going) holds the log's oldest ops — "newest first" over it is newest
  // of what you HOLD, which is not the newest on the network. Say which it is.
  const localOps = props.obs?.ops ?? 0;
  const partial = props.assertedOps > 0 && localOps < props.assertedOps;

  const index = useIndexLog(
    ready && source === 'index',
    'ingestedAt.desc',
    indexCursor,
    setIndexCursor,
  );
  const relay = useRelayLog(ready && source === 'relay', cursor, setCursor);
  const local = useLocalLog(ready && source === 'local');
  const feed = source === 'index' ? index : source === 'local' ? local : relay;

  useEffect(() => {
    if (index.routeAbsent) setIndexFailed(true);
  }, [index.routeAbsent]);

  const pick = (src: string): void => setSrcParam(src);

  return (
    <Panel
      title="operations"
      accent="warn"
      right={
        <span class="lbl">
          {source === 'index'
            ? 'newest first · live from the relay index'
            : source === 'local'
              ? partial
                ? 'newest first · from the part of the log you have synced'
                : 'newest first · from your synced log'
              : 'append order · live from the relay log'}
        </span>
      }
    >
      <div class="ck-note" style={{ marginBottom: 8 }}>
        {source === 'index' ? (
          <>
            The most recent operations the relay has accepted, straight off its{' '}
            <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> — no sync, no walk from
            genesis. Rows are <b>attributed</b> relay metadata (the index carries no JWS); open one
            to verify its signature, or watch a chain row green as your tab folds it. The ordering
            is this relay’s own <b>arrival</b> order, which is browse chronology, not a network
            clock — and completeness is never proven, so a <b>deep sync</b> stays the audit stance.
          </>
        ) : source === 'local' ? (
          <>
            Every operation you have synced, newest first. Rows are the relay's own log entries —
            browsing metadata, not proof; open one to verify its signature, or watch a chain row
            green as your tab folds it.
            {partial ? (
              <>
                {' '}
                Your sync holds <b>{fmtCount(localOps)}</b> of the relay's asserted{' '}
                {fmtCount(props.assertedOps)} operations, and a sync pages <b>forward</b> from the
                start of the log — so this is the newest of what <i>you</i> hold, not the newest on
                the network. Finish the sync to close that gap.
              </>
            ) : null}
          </>
        ) : (
          <>
            Every operation the relay has accepted, in its own append order. The log route is
            <b> forward-only</b> — it serves no reverse order and no offset — so this walks from the
            first operation the relay holds.{' '}
            {indexOk ? (
              <>
                The relay’s <code>/index/v0/operations</code> feed answers the same question
                newest-first.
              </>
            ) : (
              <>
                <b>Deep-sync the full log</b> and this panel flips to newest-first, counted from
                your own store.
              </>
            )}
          </>
        )}
      </div>

      {indexOk || synced ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          {indexOk ? (
            <button class={source === 'index' ? 'on' : ''} onClick={() => pick('')}>
              newest on the network
            </button>
          ) : null}
          {synced ? (
            <button
              class={source === 'local' ? 'on' : ''}
              onClick={() => pick(indexOk ? 'local' : '')}
            >
              newest you’ve synced
            </button>
          ) : null}
          <button class={source === 'relay' ? 'on' : ''} onClick={() => pick('relay')}>
            from the beginning
          </button>
        </div>
      ) : null}

      {feed.error ? (
        <div class="ck-note">
          couldn’t read the operation log.{' '}
          <button onClick={feed.retry} disabled={feed.loading}>
            {feed.loading ? 'retrying…' : 'retry'}
          </button>
          {feed.offFirst ? <button onClick={feed.first}> start over</button> : null}
        </div>
      ) : feed.rows.length === 0 ? (
        <span class="muted">
          {feed.loading ? 'reading the operation log…' : 'the operation log is empty'}
        </span>
      ) : (
        <div class="index-rows">
          <table>
            <thead>
              <tr>
                <th>kind</th>
                <th>chain</th>
                <th>op</th>
                <th>when</th>
                <th>operation CID</th>
              </tr>
            </thead>
            <tbody>
              {feed.rows.map((row) =>
                row.kind === 'identity-op' ? (
                  <OpChainRow key={row.cid} row={row} kind="identity" />
                ) : row.kind === 'content-op' ? (
                  <OpChainRow key={row.cid} row={row} kind="content" />
                ) : (
                  <OpPlainRow key={row.cid} row={row} />
                ),
              )}
            </tbody>
          </table>
        </div>
      )}

      <Pager
        count={feed.rows.length}
        noun="operations"
        loading={feed.loading}
        hasNext={feed.hasNext}
        hasPrev={feed.hasPrev}
        offFirst={feed.offFirst}
        onFirst={feed.first}
        onPrev={feed.prev}
        onNext={feed.next}
      />
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// POSTS — the public post feed off the relay's content index
// -----------------------------------------------------------------------------

/** One post in the public feed: the chain's label + type + creator + when. Same
 *  row vocabulary and same three label beats as the document browser — a post
 *  reached from the feed reads identically to one reached by browsing. */
const PostRow = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const { label, tier } = useIndexRowLabel(row, rec.status !== 'attributed');
  const gated = !(row.docSchema && row.publicRead);
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <DocName label={label} tier={tier} /> <VerifyBadge kind="content" chainId={row.contentId} />
        {gated ? <span class="err"> gated</span> : null}
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td>
        {row.docSchema ? (
          <span class="k-role">{schemaLabel(row.docSchema)}</span>
        ) : (
          <span class="muted">untyped</span>
        )}
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <DidChip did={row.creatorDID} />
      </td>
      <td class="n">{fmtAge(row.headAt)}</td>
    </tr>
  );
};

const PostsPanel = (props: { indexed: boolean | null; ordered: boolean | null }) => {
  const [cursor, setCursor] = useHashParam('posts');
  const [pubParam, setPubParam] = useHashParam('pub');
  // the hash param wins for THIS view (so a link carries what it shows); absent,
  // the persisted preference decides.
  const publicOnly = pubParam ? pubParam !== '0' : getPublicOnly();
  // an ordered feed is meaningless on a relay that ignores `order=` — it would
  // serve LEXICAL rows under a recency label. Hold (null) until the probe settles.
  const ordered = props.ordered === true;
  const index = useIndexContent(props.indexed === true && props.ordered !== null, publicOnly, {
    docSchema: POST_SCHEMA,
    ...(ordered ? { order: 'headAt.desc' as const } : {}),
    cursor,
    onCursor: setCursor,
  });

  const toggle = (): void => {
    const next = !publicOnly;
    setPublicOnly(next);
    setPubParam(next ? '1' : '0');
  };

  if (props.indexed === false) {
    return (
      <Panel title="posts" right={<span class="lbl">needs a relay index</span>}>
        <span class="muted">
          no configured relay serves an index — posts enumerate from <code>/index/v0/content</code>.
          Add an index-capable relay on the <a href="#/relays">relays</a> page.
        </span>
      </Panel>
    );
  }

  return (
    <Panel
      title="posts"
      accent="warn"
      right={
        <span class="lbl">
          post/v1 · {ordered ? 'most recently updated' : 'relay order'} · from relay index
        </span>
      }
    >
      <div class="filters" style={{ marginBottom: 8 }}>
        <button class={publicOnly ? 'on' : ''} onClick={toggle}>
          public only
        </button>
        <span class="lbl">
          {publicOnly
            ? 'gated chains hidden'
            : 'including gated chains — their titles are never rendered'}
        </span>
      </div>
      {!ordered && props.ordered !== null ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          this relay doesn’t honour <code>order=</code>, so these are in the index’s lexical order,
          not by recency — the explorer won’t relabel one as the other.
        </div>
      ) : null}

      {index.error ? (
        <div class="ck-note">
          couldn’t reach the relay index for posts.{' '}
          <button onClick={index.retry} disabled={index.loading}>
            {index.loading ? 'retrying…' : 'retry'}
          </button>
        </div>
      ) : index.rows.length === 0 ? (
        <span class="muted">
          {index.loading ? 'loading posts…' : 'the relay index holds no posts on this page'}
        </span>
      ) : (
        <div class="index-rows">
          <table>
            <thead>
              <tr>
                <th>title</th>
                <th>type</th>
                <th>author</th>
                <th>updated</th>
              </tr>
            </thead>
            <tbody>
              {index.rows.map((row) => (
                <PostRow key={row.contentId} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Pager
        count={index.rows.length}
        noun="posts"
        loading={index.loading}
        hasNext={index.hasNext}
        hasPrev={index.hasPrev}
        offFirst={index.offFirst}
        onFirst={index.first}
        onPrev={index.prev}
        onNext={index.next}
      />
      <div class="lbl" style={{ marginTop: 8 }}>
        <a href="#/documents">browse every public document →</a>
      </div>
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
  const populated = (props.obs?.chains ?? 0) > 0;
  const bytes = props.obs?.storageBytes ?? null;

  return (
    <Panel
      title="sync"
      right={
        populated ? (
          <span class="lbl">
            {fmtCount(props.obs?.chains ?? 0)} chains
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
            {populated ? 're-sync' : 'deep-sync · verify the full log'}
          </button>
          <span class="muted">
            {populated
              ? 'Pulls new ops since your last sync and re-resolves drifted projections.'
              : 'Pull the full operation log into a local store — chains then fold offline, the figures above are counted from math instead of taken on faith, and relay omissions become detectable.'}
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

export const Home = () => {
  const sync = useSyncState();
  const [obs, setObs] = useState<Observatory | null>(null);
  const [hint, setHint] = useState<RelayHint>({});
  const indexed = useIndexCapable();
  const iter2 = useIndexIter2();
  // ordered = the relay is index-capable AND honours `order=`; null while either
  // is still resolving (hold, don't flash a recency label over lexical rows).
  const ordered: boolean | null = indexed === null || iter2 === null ? null : indexed && iter2;

  useEffect(() => {
    let dead = false;
    void (async () => {
      // a local-index open failure (e.g. another tab blocking an upgrade) leaves
      // obs null — the panels already render their empty state, so home degrades
      // honestly instead of an unhandled rejection.
      const db = await getDb().catch(() => null);
      if (dead || !db) return;
      const [counts, oldestOpAt, storageBytes, cursors] = await Promise.all([
        db.counts(),
        db.oldestOpAt(),
        estimateStorageBytes(),
        Promise.all(getRelays().map((relay) => db.getCursor(relay))),
      ]);
      if (dead) return;
      setObs({
        ops: counts.ops,
        chains: counts.chains,
        oldestOpAt,
        storageBytes,
        logSynced: cursors.some((c) => c !== undefined),
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
      <HomeIntro />
      <NetworkPanel obs={obs} hint={hint} />
      <OperationsPanel obs={obs} assertedOps={hint.opCount ?? 0} indexed={indexed} />
      <PostsPanel indexed={indexed} ordered={ordered} />
      <SyncInstrument obs={obs} />

      {/* The PERSISTENT canonical statement — the intro banner above is a
          dismissable cold-visitor greeting, this is what stays. So it carries
          the whole story on its own, and it says the honest thing about the two
          serverless routes rather than the flat "no backend" it used to claim. */}
      <Panel title="what this is">
        <div class="kv about">
          <div class="k">static page</div>
          <div class="v muted">
            The app is a static bundle with no database and no account. Relays are swappable
            parameters, like RPC endpoints — never authorities.
          </div>
          <div class="k">verify-in-tab</div>
          <div class="v muted">
            Signatures, CIDs, and chain linkage recompute locally via{' '}
            <code>@metalabel/dfos-client</code> — the relay's claims render first, then flip to
            verified (or <b>MISMATCH</b>, loudly). Completeness stays outside the proof: you see
            what these relays hold. Definitions in the{' '}
            <Term word="glossary" def={GLOSSARY['verifiedLocal'] ?? ''} />.
          </div>
          <div class="k">the two routes</div>
          <div class="v muted">
            Checking a domain binding needs a DNS lookup and a fetch of someone else's
            <code> /.well-known</code>, and a browser can do neither. Two small routes under{' '}
            <code>packages/dfos-explorer/api</code> perform those lookups and report what they saw;
            they store nothing and decide nothing — the verdict is still computed here.
          </div>
        </div>
      </Panel>
    </>
  );
};
