/*

  SEARCH — one box, grouped results, no invented capabilities

  The relay index serves exactly two searches, both case-insensitive substrings
  over the display-name registry's projections, both applied SERVER-SIDE before
  pagination: `nameContains` over public profile names (the identities group) and
  `titleContains` over public content titles (the content group). Those are the
  index's stated search ceiling, and this page goes no further.

  `titleContains` is NEWER than the `capabilities.index` flag, and a relay that
  predates it does not error — it IGNORES the parameter and returns an ordinary
  unfiltered page of content chains. Rendering that as "chains whose title
  matches" would make every row a fabricated hit, which is the exact dishonesty
  this page has always refused (as would filtering a page of already-loaded rows
  client-side and calling it search — no amount of UI polish makes an unbounded
  corpus searchable from one page of it). So the group is gated on a probe, and
  where the relay does not honour the filter it says so and offers the direct
  resolve instead, exactly as it did before the filter existed.

*/

import type { IndexContentRow, IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useRef, useState } from 'preact/hooks';
import { DidChip } from '../components/did-chip';
import {
  DocName,
  IndexLightNote,
  useVerifyOnVisible,
  VerifyBadge,
} from '../components/index-light';
import { Pager, Panel, Term } from '../components/ui';
import { useIndexRowLabel } from '../lib/doc-label';
import { fmtAge, fmtCount, schemaLabel, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  useIndexCapable,
  useIndexContent,
  useIndexIdentities,
  useIndexTitleSearch,
} from '../lib/index-light';
import { dispatchInput, routeFor } from '../lib/resolve-input';
import { useVerifyStatus } from '../lib/verify-queue';
import { useHashParam } from '../router';

/** Debounce a rapidly-changing value so it settles into one server-side query. */
const useDebounced = <T,>(value: T, ms: number): T => {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return settled;
};

const IdentityHit = (props: { row: IndexIdentityRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('identity', row.did, row.opCount);
  // Honest degradation: only surface a projected name the relay marks public. An
  // unupgraded relay may still send a non-public name; never render it.
  const name = row.profile?.publicRead ? (row.profile.name ?? '') : '';
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/did/${row.did}`)}>
      <td>
        {name ? <span class="attr">{name}</span> : <span class="muted">— no public profile</span>}{' '}
        <VerifyBadge kind="identity" chainId={row.did} />
      </td>
      <td class="cid">{short(row.did, 16, 6)}</td>
      <td class="n">{row.opCount}</td>
    </tr>
  );
};

/** One content hit: the projected title (attributed), its type, creator, and a
 *  live verify badge — the same row vocabulary the document browser uses, so a
 *  title reached by search reads identically to one reached by browsing. */
const ContentHit = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const label = useIndexRowLabel(row, rec.status === 'attributed');
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <DocName label={label} /> <VerifyBadge kind="content" chainId={row.contentId} />
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

export const Search = () => {
  const indexed = useIndexCapable();
  // does the serving relay honour `titleContains=`? null while the probe is in
  // flight — the content group holds rather than running a query it could not
  // stand behind. See the header note.
  const titleSearch = useIndexTitleSearch();
  const [q, setQ] = useHashParam('q');
  const [cursor, setCursor] = useHashParam('after');
  // the two groups page independently, so they carry separate positions
  const [docCursor, setDocCursor] = useHashParam('dafter');
  const [draft, setDraft] = useState(q);
  const needle = useDebounced(draft.trim(), 250);
  // the last value THIS view wrote into `q`, so its own write echoing back through
  // the hash is not mistaken for someone else changing the search
  const written = useRef(q);

  // the settled box drives the hash, so the URL always names what is on screen
  useEffect(() => {
    if (needle === written.current) return;
    written.current = needle;
    setQ(needle);
    // setQ is a stable hash writer
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [needle]);

  // `q` moved and it wasn't us — the global search bar submitted a new query while
  // this view was already mounted (same route, so no remount). Adopt it: without
  // this the box and the results keep showing the OLD search, and worse, the
  // debounce above writes that stale value straight back over the new one, so the
  // URL silently reverts to a search the user has already left.
  useEffect(() => {
    if (q === written.current) return;
    written.current = q;
    setDraft(q);
  }, [q]);

  const index = useIndexIdentities(indexed === true && needle.length > 0, true, {
    nameContains: needle,
    cursor,
    onCursor: setCursor,
  });

  // public-only by construction: the relay restricts a `titleContains` query to
  // publicRead rows server-side, and never projects a non-public chain's title.
  const docs = useIndexContent(
    indexed === true && titleSearch === true && needle.length > 0,
    true,
    { titleContains: needle, cursor: docCursor, onCursor: setDocCursor },
  );

  const direct = dispatchInput(needle);

  return (
    <>
      <Panel
        title="search"
        right={<span class="lbl">{needle ? `“${needle}”` : 'nothing entered'}</span>}
        orient={
          <>
            The relay index searches <b>public profile names</b> and <b>public content titles</b> —
            substrings over what things call themselves, and nothing else. Identifiers resolve
            directly. All of it is shown below for whatever you typed.
          </>
        }
      >
        <div class="bar">
          <input
            placeholder="a name or title, or a did:dfos:… / contentId / operation CID"
            style={{ flex: 1 }}
            value={draft}
            autocomplete="off"
            spellcheck={false}
            onInput={(e) => setDraft((e.target as HTMLInputElement).value)}
          />
        </div>
      </Panel>

      {direct ? (
        <Panel title="direct resolve" accent="ok" right={<span class="lbl">an identifier</span>}>
          <div class="ck-note">
            that’s a{' '}
            {direct.kind === 'identity'
              ? 'DID'
              : direct.kind === 'content'
                ? 'content chain id'
                : 'CID'}{' '}
            — <a href={routeFor(direct)}>open it</a> and the explorer will fetch and verify it.
          </div>
        </Panel>
      ) : null}

      <Panel
        title={
          <>
            identities{' '}
            {needle && !index.loading ? (
              <span class="lbl">{fmtCount(index.rows.length)} on this page</span>
            ) : null}
          </>
        }
        accent={index.rows.length > 0 ? 'warn' : undefined}
        right={<span class="lbl">server-side name search · from relay index</span>}
      >
        {indexed === null ? (
          <span class="muted">checking relay capabilities…</span>
        ) : indexed === false ? (
          <span class="muted">
            no configured relay serves an index, so there is no name search. Add an index-capable
            relay on the <a href="#/relays">relays</a> page.
          </span>
        ) : !needle ? (
          <span class="muted">type a name above.</span>
        ) : index.error ? (
          <div class="ck-note">
            couldn’t reach the relay index.{' '}
            <button onClick={index.retry} disabled={index.loading}>
              {index.loading ? 'retrying…' : 'retry'}
            </button>
          </div>
        ) : index.rows.length === 0 ? (
          <span class="muted">
            {index.loading
              ? `searching the relay index for “${needle}”…`
              : `no public identities in the relay index match “${needle}”.`}
          </span>
        ) : (
          <>
            <IndexLightNote />
            <div class="index-rows">
              <table>
                <thead>
                  <tr>
                    <th>name</th>
                    <th>identity (DID)</th>
                    <th>ops</th>
                  </tr>
                </thead>
                <tbody>
                  {index.rows.map((row) => (
                    <IdentityHit key={row.did} row={row} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pager
              count={index.rows.length}
              noun="matches"
              loading={index.loading}
              hasNext={index.hasNext}
              hasPrev={index.hasPrev}
              offFirst={index.offFirst}
              onFirst={index.first}
              onPrev={index.prev}
              onNext={index.next}
            />
          </>
        )}
      </Panel>

      <Panel
        title={
          <>
            content{' '}
            {needle && titleSearch === true && !docs.loading ? (
              <span class="lbl">{fmtCount(docs.rows.length)} on this page</span>
            ) : null}
          </>
        }
        accent={docs.rows.length > 0 ? 'warn' : undefined}
        right={
          <span class="lbl">
            {titleSearch === true
              ? 'server-side title search · from relay index'
              : 'no index title search'}
          </span>
        }
      >
        {indexed === null || titleSearch === null ? (
          <span class="muted">checking relay capabilities…</span>
        ) : indexed === false || titleSearch === false ? (
          <div class="ck-note">
            The relay’s <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> projects a
            document’s title, but these relays serve <b>no query over it</b> — so there is nothing
            here to search, and this page will not fake one by filtering a page of already-loaded
            rows. To reach a document: paste its <b>contentId</b> (31 characters) or an operation{' '}
            <b>CID</b> (<code>baf…</code>) above, or{' '}
            <a href="#/documents">browse public documents</a>.
          </div>
        ) : !needle ? (
          <span class="muted">type a title above.</span>
        ) : docs.error ? (
          <div class="ck-note">
            couldn’t reach the relay index.{' '}
            <button onClick={docs.retry} disabled={docs.loading}>
              {docs.loading ? 'retrying…' : 'retry'}
            </button>
          </div>
        ) : docs.rows.length === 0 ? (
          <span class="muted">
            {docs.loading
              ? `searching the relay index for “${needle}”…`
              : `no public content in the relay index has a title matching “${needle}”.`}
          </span>
        ) : (
          <>
            <div class="ck-note" style={{ marginBottom: 8 }}>
              A relay-asserted case-insensitive substring over projected titles (<b>amber</b>,
              verified as each row folds). The query is <b>public-only by construction</b> — a
              non-public chain never projects a title, so one can never be reached this way.
              Completeness is never proven.
            </div>
            <div class="index-rows">
              <table>
                <thead>
                  <tr>
                    <th>name / title</th>
                    <th>type</th>
                    <th>creator</th>
                    <th>updated</th>
                  </tr>
                </thead>
                <tbody>
                  {docs.rows.map((row) => (
                    <ContentHit key={row.contentId} row={row} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pager
              count={docs.rows.length}
              noun="matches"
              loading={docs.loading}
              hasNext={docs.hasNext}
              hasPrev={docs.hasPrev}
              offFirst={docs.offFirst}
              onFirst={docs.first}
              onPrev={docs.prev}
              onNext={docs.next}
            />
          </>
        )}
      </Panel>
    </>
  );
};
