/*

  KEY VIEW — a public key as an addressable thing, and what it has ever controlled

  Every other detail page starts from a chain. This one starts from a KEY, which
  owns no chain and signs no page of its own: the only thing that can be said
  about it is which identities have declared it, and only a relay index can
  answer that. So the page is a reverse lookup —
  `/index/v0/identities?key=<multibase>` — over the has-ever-declared index
  (WEB-RELAY.md, Identities). Its consumers are audit ("what has this key ever
  controlled") and key-loss recovery, where the matches that matter most are
  exactly the ones a current-state filter would hide.

  TWO HONESTY PROBLEMS, both handled here rather than papered over.

  1. THE ROWS ARE A HINT AND THEY ARE ALSO STALE BY DESIGN. "Ever declared" is
     read by a human as "controls", and those are different claims. So each row
     carries the key's CURRENT standing, folded from that identity's own chain in
     this tab (lib/key-standing.ts) — current / rotated out / identity deleted /
     could not check. The rows render before any fold lands; the labels arrive
     after. `could not check` is its own state and is never rounded to `rotated`.

  2. A RELAY PREDATING THE FILTER IGNORES IT and answers with the UNFILTERED
     identity list. Rendering that page would make this the one surface in the
     explorer that fabricates claims about key custody. So the page runs the
     sentinel probe in lib/index-light.ts first (`useIndexKeyFilter`) and, where
     the filter is not honoured, says so and asks nothing.

*/

import type { IndexIdentityRow } from '@metalabel/dfos-client';
import { IdentityName } from '../components/index-light';
import { Pager, Panel, Pill, Term, TruncId } from '../components/ui';
import { fmtAge, fmtCount, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { indexListStateFor, useIndexCapable, useIndexKeyFilter } from '../lib/index-light';
import { useIndexIdentitiesByKey } from '../lib/index-raw';
import { useKeyStanding, type KeyStanding } from '../lib/key-standing';
import { useHashParam } from '../router';

/** The standing label, said plainly. The chip word stays the precise one — a
 *  reader scanning the column is scanning for `rotated out`, not for a sentence —
 *  and the plain rendering sits one hover away, the same split the verdict pills
 *  make everywhere else. */
const STANDING_DEFS = {
  current: 'This identity’s head state still declares this key, in the classes named beside it.',
  rotated:
    'This identity’s chain verifies here and its head no longer declares this key — a later update rotated it out. The index entry stays, because the declaration happened.',
  deleted:
    'This identity’s chain verifies here and the identity is deactivated. Whatever the key’s place in the head state, the chain it belonged to is deleted.',
  unchecked:
    'No relay you have configured served this identity’s chain, so its current state was not read. Could not check — this is our failure to observe, not a statement that the key was rotated out.',
} as const;

/** One row's standing chip. `null` is the fold still in flight, which is neither
 *  an answer nor an absence and says so. */
const StandingChip = (props: { standing: KeyStanding | null }) => {
  const { standing } = props;
  if (standing === null) {
    return (
      <span class="badge warn" title="folding this identity’s chain in your tab…">
        <span class="spin">◍</span> checking
      </span>
    );
  }
  switch (standing.kind) {
    case 'current':
      return (
        <>
          <span class="badge ok" title={STANDING_DEFS.current}>
            current
          </span>{' '}
          {standing.classes.map((c) => (
            <span key={c} class="k-role">
              {c}
            </span>
          ))}
        </>
      );
    case 'rotated':
      return (
        <span class="badge neutral" title={STANDING_DEFS.rotated}>
          rotated out
        </span>
      );
    case 'deleted':
      return (
        <span class="badge bad" title={STANDING_DEFS.deleted}>
          identity deleted
        </span>
      );
    case 'unchecked':
      return (
        <span class="badge warn" title={`${STANDING_DEFS.unchecked} — ${standing.reason}`}>
          could not check
        </span>
      );
  }
};

/**
 * One matched identity. The row is the index's claim that this identity once
 * declared the key; the standing cell is this tab's answer about what its chain
 * says now. The name runs its usual attributed→verified beats, started once the
 * fold this page already needed has landed — the same chain answers both.
 */
const KeyMatchRow = (props: { row: IndexIdentityRow; multibase: string }) => {
  const { row } = props;
  const standing = useKeyStanding(row.did, props.multibase);
  return (
    <tr onClick={() => (location.hash = `#/did/${row.did}`)}>
      <td>
        <IdentityName row={row} seen={standing !== null} />
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <StandingChip standing={standing} />
      </td>
      <td class="cid">{short(row.did, 16, 6)}</td>
      <td class="n">{fmtAge(row.headAt)}</td>
      <td class="n">{row.opCount}</td>
    </tr>
  );
};

export const Key = (props: { multibase: string }) => {
  const indexed = useIndexCapable();
  // does the serving relay honour `key=`? An older relay IGNORES it and returns
  // the UNFILTERED identity list — every row of which would be a fabricated match.
  const keyFilter = useIndexKeyFilter();
  const [cursor, setCursor] = useHashParam('after');
  const enabled = indexed === true && keyFilter === true;
  const page = useIndexIdentitiesByKey(enabled, props.multibase, { cursor, onCursor: setCursor });
  // a disabled pager holds `loading: false`, so the raw state would settle on
  // `empty` and announce that no identity declared this key before anything had
  // been asked. Either gate answering NO returns its own panel below, so what
  // reaches the list is settled-and-enabled or still pending — and pending is
  // LOADING.
  const state = indexListStateFor(enabled || null, page.loading, page.error, page.rows.length);

  const header = (
    <Panel
      title="public key"
      right={<span class="lbl">multibase · Ed25519 Multikey</span>}
      orient={
        <>
          A key, as the thing itself. An identity declares keys by{' '}
          <Term word="role" def={GLOSSARY['keyRoles'] ?? ''} /> and rotates them over time, so the
          same key can appear on more than one chain and can outlive its place on any of them. This
          page asks the relay index which identities have ever declared it, and folds each of those
          chains here to say where it stands now.
        </>
      }
    >
      <div class="kv">
        <div class="k">
          publicKeyMultibase <span class="lbl">click to copy</span>
        </div>
        <div class="v">
          <TruncId value={props.multibase} head={48} tail={0} />
        </div>
      </div>
    </Panel>
  );

  if (indexed === false) {
    return (
      <>
        {header}
        <Panel title="identities" right={<span class="lbl">needs a relay index</span>}>
          <span class="muted">
            no configured relay serves an index — a key reverse lookup runs against{' '}
            <code>/index/v0/identities?key=</code>, and there is no other way to ask it. Add an
            index-capable relay on the <a href="#/relays">relays</a> page.
          </span>
        </Panel>
      </>
    );
  }

  if (keyFilter === false) {
    return (
      <>
        {header}
        <Panel title="identities" accent="warn" right={<span class="lbl">route unsupported</span>}>
          <span class="muted">
            this relay does not support key lookup — it answered a key no chain can have declared
            with a full page of identities, which means it ignores the <code>key=</code> filter
            rather than applying it. Showing that page here would present every identity on the
            relay as one that declared this key.
          </span>
          <div class="ck-note" style={{ marginTop: 10 }}>
            The filter is served by <code>web-relay</code> 0.39.0 and later. Add a relay whose index
            honours it on the <a href="#/relays">relays</a> page.
          </div>
        </Panel>
      </>
    );
  }

  return (
    <>
      {header}
      <Panel
        title={
          <>
            identities that declared this key{' '}
            {state === 'rows' ? <Pill state="warn">{fmtCount(page.rows.length)}</Pill> : null}
          </>
        }
        accent="warn"
        right={<span class="lbl">has ever declared · from relay index</span>}
        orient={
          <>
            Every identity whose accepted operations ever declared this key — genesis or update,
            whether or not a later update rotated it out. Rotation and deletion never remove an
            entry, which is what makes the list useful for audit and key-loss recovery. Rows are{' '}
            <b>attributed</b> relay hints: the{' '}
            <Term word="index is a hint" def={GLOSSARY['indexLight'] ?? ''} />, the chain is the
            authority, so each row's <b>standing</b> is folded from that identity's own chain in
            your tab.
          </>
        }
      >
        {state === 'error' ? (
          <div class="ck-note">
            {page.routeAbsent ? (
              <>
                every configured relay answered <b>no such route</b> for the identity index. Nothing
                was learned about this key — this is not a statement that no identity declared it.
              </>
            ) : (
              <>
                couldn’t reach the relay index just now — so this says nothing about whether any
                identity declared this key.{' '}
                <button onClick={page.retry} disabled={page.loading}>
                  {page.loading ? 'retrying…' : 'retry'}
                </button>
                {/* a stale or hand-edited `?after=` is rejected by the relay, and
                    retry re-sends it unchanged */}
                {page.offFirst ? <button onClick={page.first}> start over</button> : null}
              </>
            )}
          </div>
        ) : state === 'loading' ? (
          <span class="muted">
            {indexed === null
              ? 'checking relay capabilities…'
              : keyFilter === null
                ? 'checking whether this relay supports key lookup…'
                : 'asking the relay index which identities declared this key…'}
          </span>
        ) : state === 'empty' ? (
          <span class="muted">
            no identity in this relay's index has ever declared this key. An index can withhold
            rows, so this is what this relay surfaces — never a proof that none exists.
          </span>
        ) : (
          <div class="index-rows">
            <table>
              <thead>
                <tr>
                  <th>identity</th>
                  <th>standing</th>
                  <th>identity (DID)</th>
                  <th>updated</th>
                  <th>ops</th>
                </tr>
              </thead>
              <tbody>
                {page.rows.map((row) => (
                  <KeyMatchRow key={row.did} row={row} multibase={props.multibase} />
                ))}
              </tbody>
            </table>
          </div>
        )}

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
      </Panel>
    </>
  );
};
