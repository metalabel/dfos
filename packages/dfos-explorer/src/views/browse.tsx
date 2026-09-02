/*

  BROWSE — public identities / documents

  Both enumerate LIVE from the relay's /index/v0 whenever a relay advertises the
  index capability — always, even after a deep sync (the live index is fresher
  than a past sync). Each row is an ATTRIBUTED relay hint, promoted to VERIFIED
  as it scrolls into view and its chain folds (the fold wins). Where no relay
  advertises the index, these fall back to the LOCAL synced index. Each is a
  different primitive:

    identities — who. Attributed public profiles, substring-searchable by name.
    documents  — what content. Public content chains, typed by their doc $schema.

  The browse surface is a 1:1 MIRROR OF THE RELAY'S INDEX CAPABILITY SURFACE, so
  what it can do is legible: what the index projects, you can browse; what it
  doesn't, you can't. Artifacts joined that surface when `/index/v0/artifacts`
  shipped and now browse in views/artifacts.tsx — on relays that serve the route,
  which is not every relay, so that page detects and says so rather than
  pretending. They live in their own view because an artifact has no chain to
  fold, and therefore no attributed→verified promotion in place.

  Pages are 20 rows off the relay's keyset cursor, with the position carried in
  the hash so a browse view can be linked. Enumeration is never a completeness
  claim ("completeness is outside the proof"); a deep sync is the exhaustive
  AUDIT stance that alone detects a relay's omissions.

*/

import type { IndexContentRow, IndexIdentityRow, IndexOrder } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { DidChip } from '../components/did-chip';
import {
  DocName,
  IdentityName,
  IndexLightNote,
  useVerifyOnVisible,
  VerifyBadge,
} from '../components/index-light';
import { Badge, ClientPager, Pager, Panel, Pill, Term } from '../components/ui';
import { useIndexRowLabel } from '../lib/content-labels';
import type { ChainRollup, DocumentsBrowse, IdentitiesBrowse } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { deriveDocLabel } from '../lib/doc-label';
import { fmtAge, fmtCount, schemaLabel, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  indexBrowseMode,
  useIndexCapable,
  useIndexContent,
  useIndexIdentities,
  useIndexIter2,
  type IndexPage,
} from '../lib/index-light';
import { useClientPager } from '../lib/paging';
import { fetchRelayHint } from '../lib/relay-hint';
import { startProjections, startSync, stopSync, useSyncState } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';
import { useHashParam } from '../router';

const BROWSE_LIMIT = 300;

/** Debounce a rapidly-changing value (e.g. a search box) so it only settles after
 *  `ms` of quiet — used to fold keystrokes into one server-side index query. */
const useDebounced = <T,>(value: T, ms: number): T => {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return settled;
};

// stable references so useAvailable's effect runs once, not every render
const ID_KEYS = ['identity', 'identity-op'];
const DOC_KEYS = ['content', 'content-op'];

/**
 * Relay-advertised count for a browse kind (max across relays), or undefined when
 * no relay advertises it. Takes fallback keys because a relay may key
 * countsByKind by primitive ('identity') or op-kind ('identity-op').
 */
const useAvailable = (keys: string[]): number | undefined => {
  const [n, setN] = useState<number | undefined>(undefined);
  useEffect(() => {
    let dead = false;
    void fetchRelayHint().then((h) => {
      if (dead) return;
      for (const k of keys) {
        const v = h.countsByKind?.[k];
        if (typeof v === 'number') {
          setN(v);
          return;
        }
      }
    });
    return () => {
      dead = true;
    };
  }, [keys]);
  return n;
};

/** Relay-asserted "~N available — sync to browse" hint; silent when absent. */
const AvailableHint = (props: { available: number | undefined; localCount: number }) => {
  const { available } = props;
  if (available === undefined || available <= props.localCount) return null;
  return (
    <div class="ck-note" style={{ marginBottom: 8 }}>
      ~{fmtCount(available)} advertised across your relays (relay-asserted) —{' '}
      <b>sync the full log</b> to browse them locally. Completeness is never proven; this is a hint,
      not a promise.
    </div>
  );
};

/** Shared "you have no local data yet" call-to-action. */
const SyncPrompt = (props: { syncing: boolean }) => (
  <div class="ck-note">
    {props.syncing ? (
      'syncing the global log — rows appear as chains land…'
    ) : (
      <>
        Nothing synced yet. <button onClick={() => void startSync('manual')}>sync full log</button>{' '}
        to pull the operation log and resolve public projections.
      </>
    )}
  </div>
);

// -----------------------------------------------------------------------------
// index browse — live attributed rows straight off a relay's /index/v0, each
// promoted to verified as it scrolls into view (see lib/index-light.ts). Active
// whenever a relay advertises the index capability (useIndexCapable), ALWAYS —
// the live index is the enumeration source even after a deep sync. Where no relay
// advertises it, the surfaces below fall back to the local synced index.
// -----------------------------------------------------------------------------

/** The relay index couldn't be reached and there's no local corpus to fall back
 *  on — an honest error with a retry, never a false "the index returned nothing". */
const IndexUnavailable = (props: { noun: string; loading: boolean; onRetry: () => void }) => (
  <div class="ck-note">
    couldn’t reach the relay index for {props.noun}.{' '}
    <button onClick={props.onRetry} disabled={props.loading}>
      {props.loading ? 'retrying…' : 'retry'}
    </button>
  </div>
);

/** The relay index errored but a synced local corpus exists — show the local
 *  table and say so, rather than a blank or a false-empty. */
const FellBackNote = () => (
  <div class="ck-note" style={{ marginBottom: 8 }}>
    relay index unavailable — showing your synced local index.
  </div>
);

/**
 * One identity index row: name + a live verify badge; opCount and deletion
 * reconcile to the fold once it lands (the fold wins over the hint).
 *
 * THE NAME RUNS THE SAME THREE BEATS AS THE CHIPS, through the shared
 * {@link IdentityName}: the relay's projected public name amber, replaced in
 * place by the name re-derived from the identity's own signed profile bytes as
 * the row scrolls into view — and a projection the fold contradicts (no public
 * profile after all) is retired rather than left standing.
 */
const IndexIdentityRowView = (props: { row: IndexIdentityRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('identity', row.did, row.opCount);
  const rec = useVerifyStatus('identity', row.did);
  const opCount = rec.facts?.opCount ?? row.opCount;
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/did/${row.did}`)}>
      <td>
        <IdentityName row={row} seen={rec.status !== 'attributed'} />{' '}
        <VerifyBadge kind="identity" chainId={row.did} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td class="cid">{short(row.did, 16, 6)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

const IndexIdentitiesLight = (props: {
  page: IndexPage<IndexIdentityRow>;
  query: string;
  /** whether the listing behind this page is narrowed to public profiles — the
   *  empty state must not say "no PUBLIC identities" about a query that asked
   *  for all of them. Defaults to the narrowed reading, which is every caller
   *  that does not pass it. */
  publicOnly?: boolean;
}) => {
  const { page } = props;
  const publicOnly = props.publicOnly !== false;
  const needle = props.query.trim();
  // rows are ALREADY filtered SERVER-SIDE (the relay's `nameContains` runs before
  // pagination) — render them straight, no client-side needle pass.
  return (
    <>
      <IndexLightNote />
      {page.loading && page.rows.length === 0 ? (
        <span class="muted">
          {needle
            ? `searching the relay index for “${needle}”…`
            : 'loading identities from the relay index…'}
        </span>
      ) : page.rows.length === 0 ? (
        <span class="muted">
          {needle
            ? `no ${publicOnly ? 'public ' : ''}identities in the relay index match “${needle}”.`
            : `the relay index returned no ${publicOnly ? 'public ' : ''}identities.`}
        </span>
      ) : (
        <table>
          <thead>
            <tr>
              <th>name</th>
              <th>identity (DID)</th>
              <th>ops</th>
            </tr>
          </thead>
          <tbody>
            {page.rows.map((row) => (
              <IndexIdentityRowView key={row.did} row={row} />
            ))}
          </tbody>
        </table>
      )}
      {needle ? (
        <div class="ck-note" style={{ marginTop: 8 }}>
          A relay-asserted case-insensitive substring over projected profile names (<b>amber</b>,
          verified as each row folds). Completeness is never proven; a deep-sync of the full log
          audits for names the relay withheld.
        </div>
      ) : null}
      <Pager
        count={page.rows.length}
        noun="identities"
        loading={page.loading}
        hasNext={page.hasNext}
        hasPrev={page.hasPrev}
        offFirst={page.offFirst}
        onFirst={page.first}
        onPrev={page.prev}
        onNext={page.next}
      />
    </>
  );
};

/** One content index row: the chain's label + type ($schema, held-bytes only) +
 *  creator + when, with a live verify badge. The label runs the three beats every
 *  surface that names a chain runs (`useIndexRowLabel`): the relay's projected
 *  title amber, replaced by a label derived from bytes this tab re-hashed to the
 *  committed CID. The badge tracks a DIFFERENT question on its own track — the
 *  chain's structural facts (signatures, op count, deletion) — so a row can be
 *  green on its chain while its name is still amber, and vice versa. */
const IndexContentRowView = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const opCount = rec.facts?.opCount ?? row.opCount;
  const gated = !(row.docSchema && row.publicRead);
  const { label, tier } = useIndexRowLabel(row, rec.status !== 'attributed');
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <DocName label={label} tier={tier} /> <VerifyBadge kind="content" chainId={row.contentId} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td>
        {row.docSchema ? (
          <span class="k-role">{schemaLabel(row.docSchema)}</span>
        ) : (
          <span class="muted">untyped</span>
        )}
        {gated ? <span class="err"> gated</span> : null}
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <DidChip did={row.creatorDID} />
      </td>
      <td class="n">{fmtAge(row.headAt)}</td>
      <td class="cid">{short(row.contentId, 16, 6)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

const IndexDocumentsLight = (props: { page: IndexPage<IndexContentRow> }) => {
  const { page } = props;
  return (
    <>
      <IndexLightNote />
      {page.loading && page.rows.length === 0 ? (
        <span class="muted">loading content chains from the relay index…</span>
      ) : page.rows.length === 0 ? (
        <span class="muted">the relay index returned no public content chains.</span>
      ) : (
        <table>
          <thead>
            <tr>
              <th>name / title</th>
              <th>type</th>
              <th>creator</th>
              <th>updated</th>
              <th>content chain</th>
              <th>ops</th>
            </tr>
          </thead>
          <tbody>
            {page.rows.map((row) => (
              <IndexContentRowView key={row.contentId} row={row} />
            ))}
          </tbody>
        </table>
      )}
      <Pager
        count={page.rows.length}
        noun="documents"
        loading={page.loading}
        hasNext={page.hasNext}
        hasPrev={page.hasPrev}
        offFirst={page.offFirst}
        onFirst={page.first}
        onPrev={page.prev}
        onNext={page.next}
      />
    </>
  );
};

// -----------------------------------------------------------------------------
// identities
// -----------------------------------------------------------------------------

export const BrowseIdentities = () => {
  const sync = useSyncState();
  const indexed = useIndexCapable();
  const [query, setQuery] = useHashParam('q');
  const [cursor, setCursor] = useHashParam('after');
  const [includeGated, setIncludeGated] = useState(false);
  // THE INDEX-PATH SIBLING of `includeGated`, and a separate piece of state
  // because it drives a different query against a different source. Default OFF:
  // the population it reveals is chains that publish no public profile, which is
  // most often a bare chain with nothing to read, so it is opt-in the same way
  // the local path's control is.
  //
  // IT RIDES THE HASH, alongside the cursor, and it must. A keyset cursor is
  // minted against one query and means nothing to another, and `useIndexPageStack`
  // deliberately keeps a restored cursor on a deep-linked first mount rather than
  // resetting it. So a link into page 3 of a widened listing, with the toggle
  // living only in component state, would restore the cursor into the NARROWER
  // query — a page of rows from neither enumeration. Carrying both in the URL is
  // what makes the link mean what it showed.
  //
  // What it CANNOT reach: sealed (`isDeleted`) identities. A relay may exclude
  // those from the DISCOVERY shapes of /index/v0/identities — a relay that has
  // sealed thousands of chains would otherwise make its live identities
  // un-enumerable — while still returning them from the resolution shapes
  // (`did=`, `key=`). Dropping `hasPublicProfile` widens the profile predicate
  // and nothing else; a sealed chain is reached by its DID or its key, or from
  // the proof plane.
  const [npParam, setNpParam] = useHashParam('np');
  const includeNoProfile = npParam === '1';
  const [result, setResult] = useState<IdentitiesBrowse | null>(null);
  const available = useAvailable(ID_KEYS);
  // the LOCAL fallback listing is materialized whole (up to BROWSE_LIMIT rows)
  // rather than walked off a relay cursor, so it pages here in the tab — the same
  // twenty-row control the index path gets from its keyset pager.
  const localPage = useClientPager(result?.rows ?? []);
  // debounce the search box into the relay's server-side `nameContains` filter so
  // a keystroke doesn't re-page the index on every character; the relay filters
  // over the projected profile name (amber) before paginating.
  const nameContains = useDebounced(query.trim(), 250);
  // THE TOGGLE ONLY WIDENS AN UNFILTERED ENUMERATION. A relay never projects a
  // non-public profile's name, so those rows carry no name for `nameContains` to
  // match and a name search cannot reach them however this is set. The title, the
  // orient copy and the empty state all read THIS rather than the raw toggle, so
  // none of them promises rows the active query cannot return — and the note
  // below says why when the two disagree.
  const showingNonPublic = includeNoProfile && !nameContains;
  const index = useIndexIdentities(indexed === true, !includeNoProfile, {
    nameContains,
    cursor,
    onCursor: setCursor,
  });

  useEffect(() => {
    let dead = false;
    void getDb()
      .then((db) => db.browseIdentities({ query, includeGated, limit: BROWSE_LIMIT }))
      .then((r) => {
        if (!dead) setResult(r);
      })
      // a local-index open failure (another tab blocking an upgrade) clears to
      // the empty state — SyncPrompt, not a stuck spinner — rather than throwing.
      .catch(() => {
        if (!dead) setResult(null);
      });
    return () => {
      dead = true;
    };
  }, [query, includeGated, sync.dbEpoch, sync.phase]);

  const total = (result?.publicCount ?? 0) + (result?.gatedCount ?? 0);
  const syncing = sync.phase === 'syncing';
  const mode = indexBrowseMode(indexed, index.error, total > 0);

  return (
    <Panel
      title={
        <>
          {mode === 'index' && showingNonPublic ? 'identities' : 'public identities'}{' '}
          {mode === 'index' ? (
            <Pill state="warn">{fmtCount(index.rows.length)}</Pill>
          ) : result ? (
            <Pill state="ok">{fmtCount(result.publicCount)}</Pill>
          ) : null}
        </>
      }
      right={<span class="lbl">who · from {mode === 'index' ? 'relay index' : 'local index'}</span>}
      orient={
        mode === 'index' ? (
          <>
            {showingNonPublic
              ? 'Every identity chain the relay enumerates, whether or not it publishes a readable profile,'
              : 'Identities with a publicly-readable profile,'}{' '}
            straight off the relay's <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> —
            every row is an <b>attributed</b> relay hint, promoted to <b>verified</b> as your tab
            folds its chain. Search runs server-side over projected names (a relay-asserted
            substring, amber).
          </>
        ) : (
          <>
            Identities with a publicly-readable profile,{' '}
            <Term word="attributed" def={GLOSSARY['attributed'] ?? ''} /> to the DID that signed the
            profile chain's genesis op. Search is a substring over names in your{' '}
            <Term word="local index" def={GLOSSARY['localIndex'] ?? ''} /> —{' '}
            <b>attributed, not verified</b>; open a row to fold the rigorous proof.
          </>
        )
      }
    >
      {indexed !== true ? <AvailableHint available={available} localCount={total} /> : null}
      <div class="bar" style={{ marginBottom: 8 }}>
        <input
          placeholder="search names…"
          style={{ flex: 1 }}
          value={query}
          onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
        />
      </div>
      {indexed !== true && result && result.gatedCount > 0 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={includeGated ? 'on' : ''} onClick={() => setIncludeGated((v) => !v)}>
            {includeGated ? 'hide' : 'show'} {fmtCount(result.gatedCount)} without a public profile
          </button>
        </div>
      ) : null}
      {mode === 'index' ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button
            class={includeNoProfile ? 'on' : ''}
            onClick={() => setNpParam(includeNoProfile ? '' : '1')}
          >
            include identities without a public profile
          </button>
          <span class="lbl">
            {showingNonPublic
              ? 'every enumerated chain — a row with no readable name says so'
              : 'showing only chains with a readable profile'}
          </span>
        </div>
      ) : null}
      {mode === 'index' && includeNoProfile && nameContains ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          a name search cannot reach these: the relay never projects a non-public profile's name, so
          there is no name for the filter to match. Clear the search to enumerate them.
        </div>
      ) : null}

      {mode === 'index' ? (
        <IndexIdentitiesLight page={index} query={query} publicOnly={!showingNonPublic} />
      ) : mode === 'index-unavailable' ? (
        <IndexUnavailable noun="identities" loading={index.loading} onRetry={index.retry} />
      ) : !result || total === 0 ? (
        indexed === null ? (
          <span class="muted">checking relay capabilities…</span>
        ) : (
          <SyncPrompt syncing={syncing} />
        )
      ) : result.rows.length === 0 ? (
        <span class="muted">no identities match “{query}”.</span>
      ) : (
        <>
          {mode === 'index-fell-back' ? <FellBackNote /> : null}
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>identity (DID)</th>
                <th>ops</th>
              </tr>
            </thead>
            <tbody>
              {localPage.rows.map((row) => (
                <tr key={row.chainId} onClick={() => (location.hash = `#/did/${row.chainId}`)}>
                  <td>
                    {row.name ? (
                      <>
                        <b>{row.name}</b> <Badge state="warn">attributed</Badge>
                      </>
                    ) : (
                      <span class="muted">— no public profile</span>
                    )}
                  </td>
                  <td class="cid">{short(row.chainId, 16, 6)}</td>
                  <td class="n">{row.opCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <ClientPager page={localPage} noun="identities" />
          {result.matched > result.rows.length ? (
            <div class="ck-note" style={{ marginTop: 8 }}>
              showing {fmtCount(result.rows.length)} of {fmtCount(result.matched)} — narrow the
              search to see more.
            </div>
          ) : null}
        </>
      )}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// documents
// -----------------------------------------------------------------------------

export const BrowseDocuments = () => {
  const sync = useSyncState();
  const indexed = useIndexCapable();
  // does the serving relay honour `order=`? An older relay IGNORES it and returns
  // LEXICAL rows — so we hide the recency options and never send `order=` there.
  const iter2 = useIndexIter2();
  const ordered = iter2 === true;
  const [includeGated, setIncludeGated] = useState(false);
  const [schema, setSchema] = useHashParam('schema');
  const [cursor, setCursor] = useHashParam('after');
  // enumeration order for the index path: newest (genesisAt.desc) is the default
  // — a browse-by-recency feed is what a reader wants, not the relay's lexical
  // contentId order (which is meaningless to a human). "recently active"
  // (headAt.desc) is the other offered ordering; the lexical default is no longer
  // surfaced. Only sent to a relay that honours `order=` (iteration-2, gated below).
  const [orderParam, setOrderParam] = useHashParam('order');
  const order: IndexOrder = orderParam === 'headAt.desc' ? 'headAt.desc' : 'genesisAt.desc';
  // never send `order=` to a relay that ignores it (would mislabel lexical rows
  // as recency-ordered); the toggle is hidden there, but guard the query too.
  const effectiveOrder = ordered ? order : null;
  const [result, setResult] = useState<DocumentsBrowse | null>(null);
  const available = useAvailable(DOC_KEYS);
  // same as the identities lane: the local listing arrives whole, so it pages in
  // the tab rather than off a cursor.
  const localPage = useClientPager(result?.rows ?? []);
  const index = useIndexContent(indexed === true, true, {
    ...(schema ? { docSchema: schema } : {}),
    ...(effectiveOrder ? { order: effectiveOrder } : {}),
    cursor,
    onCursor: setCursor,
  });

  // monotonic set of $schemas seen across loaded rows — so the facet bar stays
  // stable even after a filter narrows the live rows down to one schema
  const [schemas, setSchemas] = useState<string[]>([]);
  useEffect(() => {
    setSchemas((prev) => {
      const set = new Set(prev);
      for (const r of index.rows) if (r.docSchema) set.add(r.docSchema);
      return set.size === prev.length ? prev : [...set];
    });
  }, [index.rows]);

  useEffect(() => {
    let dead = false;
    void getDb()
      .then((db) => db.browseDocuments({ includeGated, limit: BROWSE_LIMIT }))
      .then((r) => {
        if (!dead) setResult(r);
      })
      // local-index open failure → empty state (SyncPrompt), never a hung spinner.
      .catch(() => {
        if (!dead) setResult(null);
      });
    return () => {
      dead = true;
    };
  }, [includeGated, sync.dbEpoch, sync.phase]);

  const syncing = sync.phase === 'syncing';
  const resolving = sync.phase === 'resolving';
  const hasLocal = !!result && result.publicCount + result.gatedCount + result.unresolvedCount > 0;
  const mode = indexBrowseMode(indexed, index.error, hasLocal);

  return (
    <Panel
      title={
        <>
          public documents{' '}
          {mode === 'index' ? (
            <Pill state="warn">{fmtCount(index.rows.length)}</Pill>
          ) : result ? (
            <Pill state="ok">{fmtCount(result.publicCount)}</Pill>
          ) : null}
        </>
      }
      right={
        <span class="lbl">what · from {mode === 'index' ? 'relay index' : 'local index'}</span>
      }
      orient={
        mode === 'index' ? (
          <>
            Public content chains straight off the relay's{' '}
            <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> — <code>$schema</code> and
            public-read are <b>attributed</b> relay projections over the bytes it holds, promoted to{' '}
            <b>verified</b> as your tab folds each chain.
          </>
        ) : (
          <>
            Content chains whose document bytes were served to an anonymous fetch and{' '}
            <Term word="re-hashed" def={GLOSSARY['publicProjection'] ?? ''} /> to the on-chain
            committed CID — typed by the document's <code>$schema</code>.
          </>
        )
      }
    >
      {indexed !== true ? (
        <AvailableHint
          available={available}
          localCount={
            (result?.publicCount ?? 0) + (result?.gatedCount ?? 0) + (result?.unresolvedCount ?? 0)
          }
        />
      ) : null}

      {indexed !== true && result && result.unresolvedCount > 0 ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          {fmtCount(result.unresolvedCount)} content chain(s) not yet resolved.{' '}
          {resolving ? (
            <>
              resolving… <button onClick={() => stopSync()}>stop</button>
            </>
          ) : (
            <button onClick={() => void startProjections()}>resolve public projections</button>
          )}
        </div>
      ) : null}

      {indexed !== true && result && result.gatedCount > 0 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={includeGated ? 'on' : ''} onClick={() => setIncludeGated((v) => !v)}>
            {includeGated ? 'hide' : 'show'} {fmtCount(result.gatedCount)} gated / private
          </button>
        </div>
      ) : null}

      {/* enumeration order — the relay serves lexical (contentId) by default, or a
          recency ordering via `order=`. Hidden entirely on a relay that doesn't
          honour `order=` (pre-iteration-2 UX): offering recency there would just
          relabel lexical rows. */}
      {mode === 'index' && ordered ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <span class="lbl" style={{ marginRight: 2 }}>
            order
          </span>
          <button class={order === 'genesisAt.desc' ? 'on' : ''} onClick={() => setOrderParam('')}>
            newest
          </button>
          <button
            class={order === 'headAt.desc' ? 'on' : ''}
            onClick={() => setOrderParam('headAt.desc')}
          >
            recently active
          </button>
        </div>
      ) : null}
      {mode === 'index' && ordered && order === 'headAt.desc' ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          <code>headAt.desc</code> sorts by author-claimed head time — a recency feed. It is
          eventually-fresh: a chain updated mid-scroll moves to the top of a fresher enumeration, so
          refresh from the top; completeness stays the job of the lexical order or a deep-sync.
        </div>
      ) : null}

      {/* $schema facet — only once the corpus shows more than one type (a single-
          schema corpus needs no filter). Chips gate exactly like the toggle above. */}
      {mode === 'index' && schemas.length > 1 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={schema === '' ? 'on' : ''} onClick={() => setSchema('')}>
            all types
          </button>
          {schemas.map((s) => (
            <button key={s} class={schema === s ? 'on' : ''} onClick={() => setSchema(s)}>
              {schemaLabel(s)}
            </button>
          ))}
        </div>
      ) : null}
      {mode === 'index' && schema !== '' ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          filtering by <code>$schema</code> server-side — options are the schemas seen so far;
          select one to page all of that type.
        </div>
      ) : null}

      {mode === 'index' ? (
        <IndexDocumentsLight page={index} />
      ) : mode === 'index-unavailable' ? (
        <IndexUnavailable noun="documents" loading={index.loading} onRetry={index.retry} />
      ) : !hasLocal ? (
        indexed === null ? (
          <span class="muted">checking relay capabilities…</span>
        ) : (
          <SyncPrompt syncing={syncing} />
        )
      ) : result && result.rows.length === 0 ? (
        <span class="muted">
          no public documents resolved yet
          {result.unresolvedCount > 0 ? ' — run "resolve public projections" above.' : '.'}
        </span>
      ) : (
        <>
          {mode === 'index-fell-back' ? <FellBackNote /> : null}
          <table>
            <thead>
              <tr>
                <th>name / title</th>
                <th>type</th>
                <th>content chain</th>
                <th>ops</th>
              </tr>
            </thead>
            <tbody>
              {localPage.rows.map((row: ChainRollup) => {
                const gated = !(row.docSchema && row.publicRead);
                // local projections carry the same material the relay index does:
                // a post/v1 title/snippet on the rollup, a profile name via names-join.
                const label = deriveDocLabel({
                  title: row.title ?? result.names[row.chainId],
                  snippet: row.snippet,
                  docSchema: row.docSchema,
                  contentId: row.chainId,
                });
                return (
                  <tr
                    key={row.chainId}
                    onClick={() => (location.hash = `#/content/${row.chainId}`)}
                  >
                    <td>
                      {label.kind === 'id' ? (
                        <span class="muted">—</span>
                      ) : (
                        <>
                          <DocName label={label} /> <Badge state="warn">attributed</Badge>
                        </>
                      )}
                    </td>
                    <td>
                      {row.docSchema ? (
                        <span class="k-role">{schemaLabel(row.docSchema)}</span>
                      ) : (
                        <span class="muted">untyped</span>
                      )}
                      {/* access chip only when the "show gated" toggle reveals a gated row —
                          public is the default and would just be visual noise */}
                      {gated ? <span class="err"> gated</span> : null}
                    </td>
                    <td class="cid">{short(row.chainId, 16, 6)}</td>
                    <td class="n">{row.opCount}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <ClientPager page={localPage} noun="documents" />
          {result && result.matched > result.rows.length ? (
            <div class="ck-note" style={{ marginTop: 8 }}>
              showing {fmtCount(result.rows.length)} of {fmtCount(result.matched)}.
            </div>
          ) : null}
        </>
      )}
    </Panel>
  );
};
