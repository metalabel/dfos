/*

  BROWSE — artifacts

  An artifact is a standalone signed document: no chain, no history, nothing to
  fold. That is exactly why it used to be unbrowsable here — the browse surface
  mirrors the relay's index capability surface, and until `/index/v0/artifacts`
  existed the only way to enumerate artifacts was to replay the whole operation
  log. Rather than ship a page that quietly meant something different from its
  neighbours ("the artifacts you happen to have synced"), there was no page.

  The route closes that gap, so the page exists on the same terms as identities
  and documents: LIVE rows off the relay index, one keyset page at a time, every
  row an ATTRIBUTED relay hint. What differs is the promotion: a chain row greens
  as your tab folds its history, and an artifact has no history — the whole proof
  is the one JWS. So there is no in-place badge to earn; opening a row is the
  verification, and the row says so instead of implying a tier it cannot reach.

  Enumeration is never a completeness claim. A deep sync remains the audit stance
  that alone detects what a relay withheld.

*/

import { DidChip } from '../components/did-chip';
import { Pager, Panel, Pill, Term } from '../components/ui';
import { fmtAge, fmtCount, schemaLabel } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { indexListStateFor, useIndexCapable } from '../lib/index-light';
import { useIndexArtifacts, type IndexArtifactRow, type IndexRecency } from '../lib/index-raw';
import { useHashParam } from '../router';

/** One artifact row: signer, declared type, when it was signed. The row carries
 *  no payload (the index projects none), so the CID is the handle and the op page
 *  is where the JWS is fetched and re-verified. */
const ArtifactRowView = (props: { row: IndexArtifactRow }) => {
  const { row } = props;
  return (
    <tr onClick={() => (location.hash = `#/op/${row.cid}`)}>
      <td class="cid">{row.cid}</td>
      <td>
        {row.docSchema ? (
          <span class="k-role">{schemaLabel(row.docSchema)}</span>
        ) : (
          <span class="muted">untyped</span>
        )}
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <DidChip did={row.signerDID} />
      </td>
      <td class="n">{fmtAge(row.createdAt)}</td>
    </tr>
  );
};

export const BrowseArtifacts = () => {
  const indexed = useIndexCapable();
  const [cursor, setCursor] = useHashParam('after');
  const [orderParam, setOrderParam] = useHashParam('order');
  // newest-signed leads — an author-claimed `createdAt` ordering, the same trust
  // posture as the chain feeds. `ingestedAt.desc` is this relay's own arrival
  // order (browse chronology, relay-local by definition), offered as the second
  // option because the two genuinely answer different questions.
  const order: IndexRecency =
    orderParam === 'ingestedAt.desc' ? 'ingestedAt.desc' : 'createdAt.desc';
  const page = useIndexArtifacts(indexed === true, { order, cursor, onCursor: setCursor });
  // the list stays disabled until the capability probe settles, and a disabled
  // pager holds `loading: false` — so the raw state would read `empty` and claim
  // the relay returned no artifacts before anything had been asked. Pending is
  // loading.
  const state = indexListStateFor(indexed, page.loading, page.error, page.rows.length);

  const pick = (value: string): void => {
    setOrderParam(value);
    setCursor('');
  };

  if (indexed === false) {
    return (
      <Panel title="artifacts" right={<span class="lbl">needs a relay index</span>}>
        <span class="muted">
          no configured relay serves an index — artifacts enumerate from{' '}
          <code>/index/v0/artifacts</code>. Add an index-capable relay on the{' '}
          <a href="#/relays">relays</a> page.
        </span>
      </Panel>
    );
  }

  return (
    <Panel
      title={
        <>
          artifacts{' '}
          {state === 'rows' ? <Pill state="warn">{fmtCount(page.rows.length)}</Pill> : null}
        </>
      }
      accent="warn"
      right={<span class="lbl">standalone signatures · from relay index</span>}
      orient={
        <>
          An <Term word="artifact" def={GLOSSARY['artifact'] ?? ''} /> — a signed document with no
          chain and no history. Rows are <b>attributed</b> relay hints; the entire proof is the one
          JWS, so <b>open a row</b> to fetch and re-verify it rather than waiting for a badge to
          green in place.
        </>
      }
    >
      <div class="filters" style={{ marginBottom: 8 }}>
        <span class="lbl" style={{ marginRight: 2 }}>
          order
        </span>
        <button class={order === 'createdAt.desc' ? 'on' : ''} onClick={() => pick('')}>
          newest signed
        </button>
        <button
          class={order === 'ingestedAt.desc' ? 'on' : ''}
          onClick={() => pick('ingestedAt.desc')}
        >
          newest here
        </button>
      </div>
      {order === 'ingestedAt.desc' ? (
        <div class="ck-note" style={{ marginBottom: 8 }}>
          <code>ingestedAt</code> is when <i>this relay</i> accepted the artifact — browse
          chronology, local by definition, and not comparable across relays. <code>createdAt</code>{' '}
          is the timestamp the signer claimed.
        </div>
      ) : null}

      {state === 'error' ? (
        <div class="ck-note">
          {page.routeAbsent ? (
            <>
              every configured relay answered <b>no such route</b> — their index predates{' '}
              <code>/index/v0/artifacts</code>, so there is nothing here to enumerate yet. Retrying
              won’t change that; add a relay whose index serves the route on the{' '}
              <a href="#/relays">relays</a> page.
            </>
          ) : (
            <>couldn’t reach the relay index for artifacts just now. </>
          )}
          {page.routeAbsent ? null : (
            <>
              <button onClick={page.retry} disabled={page.loading}>
                {page.loading ? 'retrying…' : 'retry'}
              </button>
              {/* same trap the credits pager has: a stale or hand-edited `?after=`
                  is rejected by the relay, and retry re-sends it unchanged. */}
              {page.offFirst ? <button onClick={page.first}> start over</button> : null}
            </>
          )}
        </div>
      ) : state === 'loading' ? (
        <span class="muted">
          {indexed === null
            ? 'checking relay capabilities…'
            : 'loading artifacts from the relay index…'}
        </span>
      ) : state === 'empty' ? (
        <span class="muted">the relay index returned no artifacts.</span>
      ) : (
        <div class="index-rows">
          <table>
            <thead>
              <tr>
                <th>artifact CID</th>
                <th>type</th>
                <th>signer</th>
                <th>signed</th>
              </tr>
            </thead>
            <tbody>
              {page.rows.map((row) => (
                <ArtifactRowView key={row.cid} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Pager
        count={page.rows.length}
        noun="artifacts"
        loading={page.loading}
        hasNext={page.hasNext}
        hasPrev={page.hasPrev}
        offFirst={page.offFirst}
        onFirst={page.first}
        onPrev={page.prev}
        onNext={page.next}
      />
    </Panel>
  );
};
