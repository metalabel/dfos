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

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { Panel, Pill, Term } from '../components/ui';
import type { ChainRollup, DocumentsBrowse, ExplorerOp, IdentitiesBrowse } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtCount, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { fetchRelayHint } from '../lib/relay-hint';
import { startProjections, startSync, stopSync, useSyncState } from '../lib/sync-store';

const BROWSE_LIMIT = 300;

/** Short, human label for a doc/artifact $schema URL (…/profile/v1 → profile/v1). */
const schemaLabel = (schema: string | undefined): string => {
  if (!schema) return 'untyped';
  const m = /schemas\.dfos\.com\/(.+)$/.exec(schema);
  return m?.[1] ?? schema;
};

/** Relay-asserted "~N available — sync to browse" hint; silent when absent. */
const AvailableHint = (props: { available: number | undefined; localCount: number }) => {
  const { available } = props;
  if (available === undefined || available <= props.localCount) return null;
  return (
    <div class="ck-note" style={{ marginBottom: 8 }}>
      ~{fmtCount(available)} advertised across your relays (relay-asserted) — <b>sync the full log</b>{' '}
      to browse them locally. Completeness is never proven; this is a hint, not a promise.
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
// identities
// -----------------------------------------------------------------------------

export const BrowseIdentities = () => {
  const sync = useSyncState();
  const [query, setQuery] = useState('');
  const [includeGated, setIncludeGated] = useState(false);
  const [result, setResult] = useState<IdentitiesBrowse | null>(null);
  const [available, setAvailable] = useState<number | undefined>(undefined);

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

  useEffect(() => {
    let dead = false;
    void fetchRelayHint().then((h) => {
      if (!dead) setAvailable(h.countsByKind?.['identity'] ?? h.countsByKind?.['identity-op']);
    });
    return () => {
      dead = true;
    };
  }, []);

  const total = (result?.publicCount ?? 0) + (result?.gatedCount ?? 0);
  const syncing = sync.phase === 'syncing';

  return (
    <Panel
      title={
        <>
          public identities{' '}
          {result ? <Pill state="ok">{fmtCount(result.publicCount)}</Pill> : null}
        </>
      }
      right={<span class="lbl">who · from local index</span>}
      orient={
        <>
          Identities with a publicly-readable profile, <Term word="attributed" def={GLOSSARY['attributed'] ?? ''} />{' '}
          to the DID that signed the profile chain's genesis op. Search is a substring over names in
          your <Term word="local index" def={GLOSSARY['localIndex'] ?? ''} /> — <b>attributed, not
          verified</b>; open a row to fold the rigorous proof.
        </>
      }
    >
      <AvailableHint available={available} localCount={total} />
      <div class="bar" style={{ marginBottom: 8 }}>
        <input
          placeholder="search names…"
          style={{ flex: 1 }}
          value={query}
          onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
        />
      </div>
      {result && result.gatedCount > 0 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={includeGated ? 'on' : ''} onClick={() => setIncludeGated((v) => !v)}>
            {includeGated ? 'hide' : 'show'} {fmtCount(result.gatedCount)} without a public profile
          </button>
        </div>
      ) : null}

      {!result || total === 0 ? (
        <SyncPrompt syncing={syncing} />
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
                        <b>{row.name}</b> <span class="lbl">attributed</span>
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
              showing {fmtCount(result.rows.length)} of {fmtCount(result.matched)} — narrow the search
              to see more.
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
  const [includeGated, setIncludeGated] = useState(false);
  const [result, setResult] = useState<DocumentsBrowse | null>(null);
  const [available, setAvailable] = useState<number | undefined>(undefined);

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

  useEffect(() => {
    let dead = false;
    void fetchRelayHint().then((h) => {
      if (!dead) setAvailable(h.countsByKind?.['content'] ?? h.countsByKind?.['content-op']);
    });
    return () => {
      dead = true;
    };
  }, []);

  const syncing = sync.phase === 'syncing';
  const resolving = sync.phase === 'resolving';
  const hasLocal = !!result && (result.publicCount + result.gatedCount + result.unresolvedCount) > 0;

  return (
    <Panel
      title={
        <>
          public documents{' '}
          {result ? <Pill state="ok">{fmtCount(result.publicCount)}</Pill> : null}
        </>
      }
      right={<span class="lbl">what · from local index</span>}
      orient={
        <>
          Content chains whose document bytes were served to an anonymous fetch and{' '}
          <Term word="re-hashed" def={GLOSSARY['publicProjection'] ?? ''} /> to the on-chain committed
          CID — typed by the document's <code>$schema</code>. The view is type-agnostic; today every
          public doc is a <code>profile/v1</code>.
        </>
      }
    >
      <AvailableHint
        available={available}
        localCount={(result?.publicCount ?? 0) + (result?.gatedCount ?? 0)}
      />

      {result && result.unresolvedCount > 0 ? (
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

      {result && result.gatedCount > 0 ? (
        <div class="filters" style={{ marginBottom: 8 }}>
          <button class={includeGated ? 'on' : ''} onClick={() => setIncludeGated((v) => !v)}>
            {includeGated ? 'hide' : 'show'} {fmtCount(result.gatedCount)} gated / private
          </button>
        </div>
      ) : null}

      {!hasLocal ? (
        <SyncPrompt syncing={syncing} />
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
                <th>type</th>
                <th>content chain</th>
                <th>access</th>
                <th>ops</th>
              </tr>
            </thead>
            <tbody>
              {result?.rows.map((row) => (
                <tr key={row.chainId} onClick={() => (location.hash = `#/content/${row.chainId}`)}>
                  <td>
                    {row.docSchema ? (
                      <span class="k-role">{schemaLabel(row.docSchema)}</span>
                    ) : (
                      <span class="muted">untyped</span>
                    )}
                  </td>
                  <td class="cid">{short(row.chainId, 16, 6)}</td>
                  <td>
                    {row.docSchema && row.publicRead ? (
                      <span class="ck ok">✓ public</span>
                    ) : (
                      <span class="err">gated</span>
                    )}
                  </td>
                  <td class="n">{row.opCount}</td>
                </tr>
              ))}
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

/** Artifact "type" = the $schema of its embedded content, read from the JWS. */
const artifactType = (op: ExplorerOp): string => {
  const decoded = decodeJwsUnsafe(op.jwsToken);
  const content = decoded?.payload['content'];
  if (typeof content === 'object' && content !== null) {
    const schema = (content as Record<string, unknown>)['$schema'];
    if (typeof schema === 'string') return schemaLabel(schema);
  }
  return 'artifact';
};

export const BrowseArtifacts = () => {
  const sync = useSyncState();
  const [rows, setRows] = useState<ExplorerOp[] | null>(null);
  const [available, setAvailable] = useState<number | undefined>(undefined);

  useEffect(() => {
    let dead = false;
    void getDb()
      .then((db) => db.opsOfKind('artifact', BROWSE_LIMIT))
      .then((r) => {
        if (!dead) setRows(r);
      });
    return () => {
      dead = true;
    };
  }, [sync.dbEpoch, sync.phase]);

  useEffect(() => {
    let dead = false;
    void fetchRelayHint().then((h) => {
      if (!dead) setAvailable(h.countsByKind?.['artifact']);
    });
    return () => {
      dead = true;
    };
  }, []);

  const syncing = sync.phase === 'syncing';

  return (
    <Panel
      title={
        <>
          public artifacts {rows ? <Pill state="ok">{fmtCount(rows.length)}</Pill> : null}
        </>
      }
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
      <AvailableHint available={available} localCount={rows?.length ?? 0} />
      {!rows || rows.length === 0 ? (
        <SyncPrompt syncing={syncing} />
      ) : (
        <table>
          <thead>
            <tr>
              <th>type</th>
              <th>artifact CID</th>
              <th>signer</th>
              <th>when</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((op) => (
              <tr key={op.cid} onClick={() => (location.hash = `#/op/${op.cid}`)}>
                <td>
                  <span class="k-role">{artifactType(op)}</span>
                </td>
                <td class="cid">{short(op.cid, 14, 8)}</td>
                <td class="cid">{op.kid ? short(op.kid, 14, 4) : <span class="muted">—</span>}</td>
                <td class="muted">{op.createdAt ? op.createdAt.slice(0, 10) : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
};
