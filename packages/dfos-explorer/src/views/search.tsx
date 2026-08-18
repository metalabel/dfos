/*

  SEARCH — one box, grouped results, no invented capabilities

  The relay index offers exactly one search: a case-insensitive substring over
  PROJECTED PUBLIC PROFILE NAMES (`nameContains`, applied server-side before
  pagination). That is the identities group, and it is real.

  There is NO title search over content — the index projects a post's title but
  offers no query on it. So the content group does not exist as a search: it
  offers the direct resolve, which is the honest capability, and says so. The
  alternative — filtering whichever rows happened to be loaded and calling the
  result "search" — would be the exact dishonesty the rest of this explorer
  refuses, and no amount of UI polish makes an unbounded corpus searchable from
  one page of it.

*/

import type { IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useRef, useState } from 'preact/hooks';
import { IndexLightNote, useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { Pager, Panel, Term } from '../components/ui';
import { fmtCount, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { useIndexCapable, useIndexIdentities } from '../lib/index-light';
import { dispatchInput, routeFor } from '../lib/resolve-input';
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

export const Search = () => {
  const indexed = useIndexCapable();
  const [q, setQ] = useHashParam('q');
  const [cursor, setCursor] = useHashParam('after');
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

  const direct = dispatchInput(needle);

  return (
    <>
      <Panel
        title="search"
        right={<span class="lbl">{needle ? `“${needle}”` : 'nothing entered'}</span>}
        orient={
          <>
            The relay index searches <b>public profile names</b> and nothing else. Identifiers
            resolve directly. Both are shown below for whatever you typed.
          </>
        }
      >
        <div class="bar">
          <input
            placeholder="a name, or a did:dfos:… / contentId / operation CID"
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

      <Panel title="content" right={<span class="lbl">no index search exists</span>}>
        <div class="ck-note">
          The relay’s <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> projects a document’s
          title but serves <b>no query over it</b> — so there is nothing here to search, and this
          page will not fake one by filtering a page of already-loaded rows. To reach a document:
          paste its <b>contentId</b> (31 characters) or an operation <b>CID</b> (<code>baf…</code>)
          above, or <a href="#/documents">browse public documents</a>.
        </div>
      </Panel>
    </>
  );
};
