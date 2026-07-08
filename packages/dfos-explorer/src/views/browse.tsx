/*

  BROWSE — public identities / documents / artifacts

  Identities and documents enumerate LIVE from the relay's /index/v0 whenever a
  relay advertises the index capability — always, even after a deep sync (the live
  index is fresher than a past sync). Each row is an ATTRIBUTED relay hint,
  promoted to VERIFIED as it scrolls into view and its chain folds (the fold
  wins). Where no relay advertises the index, these fall back to the LOCAL synced
  index. Artifacts have no index projection (their type is inline in the JWS), so
  they always browse from the local log. Each is a different primitive:

    identities — who. Attributed public profiles, substring-searchable by name.
    documents  — what content. Public content chains, typed by their doc $schema.
    artifacts  — signed claims. Standalone statements, type read from the JWS.

  Enumeration is never a completeness claim ("completeness is outside the proof");
  a deep sync is the exhaustive AUDIT stance that alone detects a relay's
  omissions. Public-only by default, with an honest count of what's hidden and a
  toggle (decision D).

*/

import type { IndexContentRow, IndexIdentityRow, IndexOrder } from '@metalabel/dfos-client';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { IndexLightNote, useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { Badge, DidLink, Panel, Pill, Term } from '../components/ui';
import type { ChainRollup, DocumentsBrowse, ExplorerOp, IdentitiesBrowse } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtAge, fmtCount, schemaLabel, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  indexBrowseMode,
  useIndexCapable,
  useIndexContent,
  useIndexIdentities,
} from '../lib/index-light';
import { fetchRelayHint } from '../lib/relay-hint';
import { startProjections, startSync, stopSync, useSyncState } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';

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
const ART_KEYS = ['artifact'];

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

/** Pull the next index page on demand — enumeration pages instead of a silent
 *  whole-corpus cap; the relay's `next` cursor drives it. */
const LoadMore = (props: {
  hasMore: boolean;
  loading: boolean;
  onMore: () => void;
  noun: string;
}) =>
  props.hasMore ? (
    <div class="ck-note" style={{ marginTop: 8 }}>
      <button onClick={props.onMore} disabled={props.loading}>
        {props.loading ? 'loading…' : `load more ${props.noun}`}
      </button>
    </div>
  ) : null;

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

/** One identity index row: name (attributed) + a live verify badge; opCount and
 *  deletion reconcile to the fold once it lands (the fold wins over the hint). */
const IndexIdentityRowView = (props: { row: IndexIdentityRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('identity', row.did, row.opCount);
  const rec = useVerifyStatus('identity', row.did);
  const name = row.profile?.name ?? '';
  const opCount = rec.facts?.opCount ?? row.opCount;
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/did/${row.did}`)}>
      <td>
        {name ? <span class="attr">{name}</span> : <span class="muted">— no public profile</span>}{' '}
        <VerifyBadge kind="identity" chainId={row.did} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td class="cid">{short(row.did, 16, 6)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

const IndexIdentitiesLight = (props: {
  rows: IndexIdentityRow[];
  loading: boolean;
  hasMore: boolean;
  loadMore: () => void;
  query: string;
}) => {
  const { rows, loading } = props;
  const needle = props.query.trim();
  // rows are ALREADY filtered SERVER-SIDE (the relay's `nameContains` runs before
  // pagination) — render them straight, no client-side needle pass. Load-more
  // appends the next page of matches; PAGE + user-driven load-more bound growth.
  return (
    <>
      <IndexLightNote />
      {loading && rows.length === 0 ? (
        <span class="muted">
          {needle
            ? `searching the relay index for “${needle}”…`
            : 'loading identities from the relay index…'}
        </span>
      ) : rows.length === 0 ? (
        <span class="muted">
          {needle
            ? `no public identities in the relay index match “${needle}”.`
            : 'the relay index returned no public identities.'}
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
            {rows.map((row) => (
              <IndexIdentityRowView key={row.did} row={row} />
            ))}
          </tbody>
        </table>
      )}
      {needle ? (
        <div class="ck-note" style={{ marginTop: 8 }}>
          <b>{fmtCount(rows.length)}</b> match(es) — a relay-asserted case-insensitive substring
          over projected profile names (<b>amber</b>, verified as each row folds). Completeness is
          never proven; a deep-sync of the full log audits for names the relay withheld.
        </div>
      ) : null}
      <LoadMore
        hasMore={props.hasMore}
        loading={loading}
        onMore={props.loadMore}
        noun="identities"
      />
    </>
  );
};

/** One content index row: the projected title (attributed) + type ($schema,
 *  held-bytes only) + creator + when, with a live verify badge. The title, like an
 *  identity's name, is a relay projection over held head bytes — shown amber; the
 *  badge greens as the tab folds the chain (which re-checks its structural facts). */
const IndexContentRowView = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const opCount = rec.facts?.opCount ?? row.opCount;
  const gated = !(row.docSchema && row.publicRead);
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        {row.title ? <span class="attr">{row.title}</span> : <span class="muted">—</span>}{' '}
        <VerifyBadge kind="content" chainId={row.contentId} />
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
        <DidLink did={row.creatorDID} />
      </td>
      <td class="n">{fmtAge(row.headAt)}</td>
      <td class="cid">{short(row.contentId, 16, 6)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

const IndexDocumentsLight = (props: {
  rows: IndexContentRow[];
  loading: boolean;
  hasMore: boolean;
  loadMore: () => void;
}) => {
  const { rows, loading } = props;
  // render ALL loaded index rows — load-more appends past any fixed cap (FIX)
  const shown = rows;
  return (
    <>
      <IndexLightNote />
      {loading && rows.length === 0 ? (
        <span class="muted">loading content chains from the relay index…</span>
      ) : shown.length === 0 ? (
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
            {shown.map((row) => (
              <IndexContentRowView key={row.contentId} row={row} />
            ))}
          </tbody>
        </table>
      )}
      <LoadMore
        hasMore={props.hasMore}
        loading={loading}
        onMore={props.loadMore}
        noun="documents"
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
  const [query, setQuery] = useState('');
  const [includeGated, setIncludeGated] = useState(false);
  const [result, setResult] = useState<IdentitiesBrowse | null>(null);
  const available = useAvailable(ID_KEYS);
  // debounce the search box into the relay's server-side `nameContains` filter so
  // a keystroke doesn't re-page the index on every character; the relay filters
  // over the projected profile name (amber) before paginating.
  const nameContains = useDebounced(query.trim(), 250);
  const index = useIndexIdentities(indexed === true, true, { nameContains });

  useEffect(() => {
    let dead = false;
    void getDb()
      .then((db) => db.browseIdentities({ query, includeGated, limit: BROWSE_LIMIT }))
      .then((r) => {
        if (!dead) setResult(r);
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
          public identities{' '}
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
            Identities with a publicly-readable profile, straight off the relay's{' '}
            <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> — every row is an{' '}
            <b>attributed</b> relay hint, promoted to <b>verified</b> as your tab folds its chain.
            Search runs server-side over projected names (a relay-asserted substring, amber).
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
        <IndexIdentitiesLight
          rows={index.rows}
          loading={index.loading}
          hasMore={index.hasMore}
          loadMore={index.loadMore}
          query={query}
        />
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
              {result.rows.map((row) => (
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
  const [includeGated, setIncludeGated] = useState(false);
  const [schema, setSchema] = useState<string | null>(null);
  // enumeration order for the index path: null = the relay's lexical default
  // (contentId ascending — the pre-order behavior), or a recency ordering the
  // relay serves via `order=`. Picking post/v1 + "recently active" composes the
  // application-level "recent public posts" feed entirely client-side.
  const [order, setOrder] = useState<IndexOrder | null>(null);
  const [result, setResult] = useState<DocumentsBrowse | null>(null);
  const available = useAvailable(DOC_KEYS);
  const index = useIndexContent(indexed === true, true, {
    ...(schema ? { docSchema: schema } : {}),
    ...(order ? { order } : {}),
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
            committed CID — typed by the document's <code>$schema</code>. The view is type-agnostic;
            today every public doc is a <code>profile/v1</code>.
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
          recency ordering via `order=`. "recently active" (headAt.desc) over the
          post/v1 facet is the client-composed "recent public posts" feed. */}
      {mode === 'index' ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <span class="lbl" style={{ marginRight: 2 }}>
            order
          </span>
          <button class={order === null ? 'on' : ''} onClick={() => setOrder(null)}>
            lexical
          </button>
          <button
            class={order === 'genesisAt.desc' ? 'on' : ''}
            onClick={() => setOrder('genesisAt.desc')}
          >
            newest
          </button>
          <button
            class={order === 'headAt.desc' ? 'on' : ''}
            onClick={() => setOrder('headAt.desc')}
          >
            recently active
          </button>
        </div>
      ) : null}
      {mode === 'index' && order === 'headAt.desc' ? (
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
          <button class={schema === null ? 'on' : ''} onClick={() => setSchema(null)}>
            all types
          </button>
          {schemas.map((s) => (
            <button key={s} class={schema === s ? 'on' : ''} onClick={() => setSchema(s)}>
              {schemaLabel(s)}
            </button>
          ))}
        </div>
      ) : null}
      {mode === 'index' && schema !== null ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          filtering by <code>$schema</code> server-side — options are the schemas seen so far;
          select one to page all of that type.
        </div>
      ) : null}

      {mode === 'index' ? (
        <IndexDocumentsLight
          rows={index.rows}
          loading={index.loading}
          hasMore={index.hasMore}
          loadMore={index.loadMore}
        />
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
              {result?.rows.map((row) => {
                const title = result.names[row.chainId];
                const gated = !(row.docSchema && row.publicRead);
                return (
                  <tr
                    key={row.chainId}
                    onClick={() => (location.hash = `#/content/${row.chainId}`)}
                  >
                    <td>
                      {title ? (
                        <>
                          <b>{title}</b> <Badge state="warn">attributed</Badge>
                        </>
                      ) : (
                        <span class="muted">—</span>
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

// -----------------------------------------------------------------------------
// artifacts
// -----------------------------------------------------------------------------

/** The embedded content document of an artifact, read straight from its JWS. */
const artifactContent = (op: ExplorerOp): Record<string, unknown> | null => {
  const decoded = decodeJwsUnsafe(op.jwsToken);
  const content = decoded?.payload['content'];
  return typeof content === 'object' && content !== null
    ? (content as Record<string, unknown>)
    : null;
};

/** Artifact "type" = the $schema of its embedded content, read from the JWS. */
const artifactType = (op: ExplorerOp): string => {
  const schema = artifactContent(op)?.['$schema'];
  return typeof schema === 'string' ? schemaLabel(schema) : 'artifact';
};

/** Human title of an artifact from its embedded content (name → title), if any.
 *  No projection needed — the document lives inline in the JWS. */
const artifactTitle = (op: ExplorerOp): string => {
  const content = artifactContent(op);
  const name = content?.['name'] ?? content?.['title'];
  return typeof name === 'string' ? name.trim() : '';
};

export const BrowseArtifacts = () => {
  const sync = useSyncState();
  const [rows, setRows] = useState<ExplorerOp[] | null>(null);
  // the rows list is capped at BROWSE_LIMIT; the TRUE synced count drives the
  // relay-hint comparison so it doesn't nag "sync more" once the cap is hit
  const [total, setTotal] = useState(0);
  const available = useAvailable(ART_KEYS);

  useEffect(() => {
    let dead = false;
    void getDb()
      .then(async (db) => ({
        rows: await db.opsOfKind('artifact', BROWSE_LIMIT),
        counts: await db.counts(),
      }))
      .then(({ rows: r, counts }) => {
        if (dead) return;
        setRows(r);
        setTotal(counts.byKind['artifact'] ?? 0);
      });
    return () => {
      dead = true;
    };
  }, [sync.dbEpoch, sync.phase]);

  const syncing = sync.phase === 'syncing';

  return (
    <Panel
      title={<>public artifacts {rows ? <Pill state="ok">{fmtCount(rows.length)}</Pill> : null}</>}
      right={<span class="lbl">signed claims · from local index</span>}
      orient={
        <>
          Standalone signed <Term word="artifacts" def={GLOSSARY['artifact'] ?? ''} /> — immutable
          statements addressed by their own CID, with no predecessor or successor. Type is read
          straight from the embedded document's <code>$schema</code> in the JWS — no projection
          needed. Open one to verify its self-CID and any countersignatures.
        </>
      }
    >
      <AvailableHint available={available} localCount={total} />
      {!rows || rows.length === 0 ? (
        <SyncPrompt syncing={syncing} />
      ) : (
        <table>
          <thead>
            <tr>
              <th>name / title</th>
              <th>type</th>
              <th>artifact CID</th>
              <th>signer</th>
              <th>when</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((op) => {
              const title = artifactTitle(op);
              return (
                <tr key={op.cid} onClick={() => (location.hash = `#/op/${op.cid}`)}>
                  <td>{title ? <b>{title}</b> : <span class="muted">—</span>}</td>
                  <td>
                    <span class="k-role">{artifactType(op)}</span>
                  </td>
                  <td class="cid">{short(op.cid, 14, 8)}</td>
                  <td class="cid">
                    {op.kid ? short(op.kid, 14, 4) : <span class="muted">—</span>}
                  </td>
                  <td class="muted">{op.createdAt ? op.createdAt.slice(0, 10) : ''}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Panel>
  );
};
