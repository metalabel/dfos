/*

  BROWSE — public identities / documents / artifacts

  Three sections over the LOCAL index (never a query-for-list against a relay —
  enumeration is intrinsically sync-local in a "completeness is outside the proof"
  trust model). Each is a different primitive:

    identities — who. Attributed public profiles, substring-searchable by name.
    documents  — what content. Public content chains, typed by their doc $schema.
    artifacts  — signed claims. Standalone statements, type read from the JWS.

  Identities and documents need Phase-2 projections (name / type materialized from
  the content-plane blob); artifacts carry their type in the op itself, so they
  browse straight from the log with no resolution step. Public-only by default,
  with an honest count of what's hidden and a toggle (decision D).

*/

import type { IndexContentRow, IndexIdentityRow } from '@metalabel/dfos-client';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { IndexLightNote, useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { Badge, Panel, Pill, Term } from '../components/ui';
import type { ChainRollup, DocumentsBrowse, ExplorerOp, IdentitiesBrowse } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtCount, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { useIndexContent, useIndexIdentities, useLightMode } from '../lib/index-light';
import { fetchRelayHint } from '../lib/relay-hint';
import { startProjections, startSync, stopSync, useSyncState } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';

const BROWSE_LIMIT = 300;

// stable references so useAvailable's effect runs once, not every render
const ID_KEYS = ['identity', 'identity-op'];
const DOC_KEYS = ['content', 'content-op'];
const ART_KEYS = ['artifact'];

/** Short, human label for a doc/artifact $schema URL (…/profile/v1 → profile/v1). */
const schemaLabel = (schema: string | undefined): string => {
  if (!schema) return 'untyped';
  const m = /schemas\.dfos\.com\/(.+)$/.exec(schema);
  return m?.[1] ?? schema;
};

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
// index light — instant attributed rows straight off a relay's /index/v0, each
// promoted to verified as it scrolls into view (see lib/index-light.ts). Gated
// by useLightMode: active while a relay advertises the capability AND no full
// log sync has ever run against the configured relays (per-relay cursor state —
// NOT corpus emptiness, which the verify queue's own JIT folds would destroy).
// After a real sync, every surface below resumes its pre-index local behavior.
// -----------------------------------------------------------------------------

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
        {name ? <b>{name}</b> : <span class="muted">— no public profile</span>}{' '}
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
  query: string;
}) => {
  const { rows, loading } = props;
  const needle = props.query.trim().toLowerCase();
  const filtered = needle
    ? rows.filter((r) => (r.profile?.name ?? '').toLowerCase().includes(needle))
    : rows;
  const shown = filtered.slice(0, BROWSE_LIMIT);
  return (
    <>
      <IndexLightNote />
      {loading && rows.length === 0 ? (
        <span class="muted">loading identities from the relay index…</span>
      ) : shown.length === 0 ? (
        <span class="muted">
          {needle
            ? `no loaded identities match “${props.query}”.`
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
            {shown.map((row) => (
              <IndexIdentityRowView key={row.did} row={row} />
            ))}
          </tbody>
        </table>
      )}
      {needle ? (
        <div class="ck-note" style={{ marginTop: 8 }}>
          searching {fmtCount(rows.length)} loaded index rows — the relay has no name search; sync
          the full log to search the whole corpus.
        </div>
      ) : null}
    </>
  );
};

/** One content index row: type ($schema, held-bytes only) + a live verify badge. */
const IndexContentRowView = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const opCount = rec.facts?.opCount ?? row.opCount;
  const gated = !(row.docSchema && row.publicRead);
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <span class="muted">—</span> <VerifyBadge kind="content" chainId={row.contentId} />
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
      <td class="cid">{short(row.contentId, 16, 6)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

const IndexDocumentsLight = (props: { rows: IndexContentRow[]; loading: boolean }) => {
  const { rows, loading } = props;
  const shown = rows.slice(0, BROWSE_LIMIT);
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
    </>
  );
};

// -----------------------------------------------------------------------------
// identities
// -----------------------------------------------------------------------------

export const BrowseIdentities = () => {
  const sync = useSyncState();
  const light = useLightMode();
  const [query, setQuery] = useState('');
  const [includeGated, setIncludeGated] = useState(false);
  const [result, setResult] = useState<IdentitiesBrowse | null>(null);
  const available = useAvailable(ID_KEYS);
  const index = useIndexIdentities(light === true, true);

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

  return (
    <Panel
      title={
        <>
          public identities{' '}
          {light === true ? (
            <Pill state="warn">{fmtCount(index.rows.length)}</Pill>
          ) : result ? (
            <Pill state="ok">{fmtCount(result.publicCount)}</Pill>
          ) : null}
        </>
      }
      right={<span class="lbl">who · from {light === true ? 'relay index' : 'local index'}</span>}
      orient={
        light === true ? (
          <>
            Identities with a publicly-readable profile, straight off the relay's{' '}
            <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> — every row is an{' '}
            <b>attributed</b> relay hint, promoted to <b>verified</b> as your tab folds its chain.
            Search filters the loaded rows only.
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
      {light !== true ? <AvailableHint available={available} localCount={total} /> : null}
      <div class="bar" style={{ marginBottom: 8 }}>
        <input
          placeholder="search names…"
          style={{ flex: 1 }}
          value={query}
          onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
        />
      </div>
      {light !== true && result && result.gatedCount > 0 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={includeGated ? 'on' : ''} onClick={() => setIncludeGated((v) => !v)}>
            {includeGated ? 'hide' : 'show'} {fmtCount(result.gatedCount)} without a public profile
          </button>
        </div>
      ) : null}

      {light === true ? (
        <IndexIdentitiesLight rows={index.rows} loading={index.loading} query={query} />
      ) : !result || total === 0 ? (
        light === null ? (
          <span class="muted">checking relay capabilities…</span>
        ) : (
          <SyncPrompt syncing={syncing} />
        )
      ) : result.rows.length === 0 ? (
        <span class="muted">no identities match “{query}”.</span>
      ) : (
        <>
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
  const light = useLightMode();
  const [includeGated, setIncludeGated] = useState(false);
  const [result, setResult] = useState<DocumentsBrowse | null>(null);
  const available = useAvailable(DOC_KEYS);
  const index = useIndexContent(light === true, true);

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

  return (
    <Panel
      title={
        <>
          public documents{' '}
          {light === true ? (
            <Pill state="warn">{fmtCount(index.rows.length)}</Pill>
          ) : result ? (
            <Pill state="ok">{fmtCount(result.publicCount)}</Pill>
          ) : null}
        </>
      }
      right={<span class="lbl">what · from {light === true ? 'relay index' : 'local index'}</span>}
      orient={
        light === true ? (
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
      {light !== true ? (
        <AvailableHint
          available={available}
          localCount={
            (result?.publicCount ?? 0) + (result?.gatedCount ?? 0) + (result?.unresolvedCount ?? 0)
          }
        />
      ) : null}

      {light !== true && result && result.unresolvedCount > 0 ? (
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

      {light !== true && result && result.gatedCount > 0 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={includeGated ? 'on' : ''} onClick={() => setIncludeGated((v) => !v)}>
            {includeGated ? 'hide' : 'show'} {fmtCount(result.gatedCount)} gated / private
          </button>
        </div>
      ) : null}

      {light === true ? (
        <IndexDocumentsLight rows={index.rows} loading={index.loading} />
      ) : !hasLocal ? (
        light === null ? (
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
