/*

  KEY VIEW — a public key as an addressable thing, and what it has ever controlled

  Every other detail page starts from a chain. This one starts from a KEY, which
  owns no chain and signs no page of its own, so everything on it is a relay-index
  reverse lookup. There are TWO, on two different axes, and the page keeps them
  apart because they answer different questions:

    DECLARED  `/index/v0/identities?key=`      — which identities have ever named
                                                 this key in their state. A claim
                                                 in a document.
    SIGNED    `/index/v0/operations?signerKey=` — which operations this key put a
                                                 signature on, across every chain
                                                 and every kind. A fact the relay
                                                 verified at ingest.

  Neither contains the other. A key signs on content chains no identity document
  of its own mentions, and an identity can declare a key that never signs
  anything. The page's consumers are audit ("what has this key ever controlled")
  and key-loss recovery, where the matches that matter most are exactly the ones a
  current-state filter would hide.

  THREE HONESTY PROBLEMS, all handled here rather than papered over.

  1. THE DECLARED ROWS ARE A HINT AND THEY ARE ALSO STALE BY DESIGN. "Ever
     declared" is read by a human as "controls", and those are different claims.
     So each row carries the key's CURRENT standing, folded from that identity's
     own chain in this tab (lib/key-standing.ts) — current / rotated out /
     identity deleted / could not check. The rows render before any fold lands;
     the labels arrive after. `could not check` is its own state and is never
     rounded to `rotated`.

  2. A RELAY PREDATING EITHER FILTER IGNORES IT and answers with the UNFILTERED
     list — every identity on the relay, or every operation on it. Rendering
     either would make this the one surface in the explorer that fabricates claims
     about key custody. Both filters are specified as opaque matches that never
     400, so both are body-probed with a sentinel key (lib/index-light.ts,
     `useIndexKeyFilterRelays` / `useIndexSignerKeyFilterRelays`).

     THE PROBE'S ANSWER IS A SET OF RELAYS, NOT A YES. Index queries fail over
     relay by relay and take the first 2xx from whoever answers, so "some relay
     supports it" is not a safe gate: probe A as supported, have A be down, and
     the query lands on old relay B and fabricates the whole page. So each lane
     asks ONLY the relays that passed their own probe, and an empty set is the
     unsupported state — the lane says so and asks nothing. The two sets are
     INDEPENDENT (a relay can serve one filter and not the other), so each lane
     carries its own.

  3. THE OP COUNT IS NOT THE IDENTITY'S OP COUNT. An index identity row's
     `opCount` counts that identity's whole chain, by any of its keys; on a key
     page a column headed `ops` reads as this key's signings and is off by
     everything the key signed elsewhere. So that column says `chain ops`, and the
     key-scoped figure lives on the signed lane, where `signerKey=` produces it —
     as what the enumeration loaded, since a keyset cursor serves no total
     (lib/key-ops.ts).

*/

import type { IndexIdentityRow } from '@metalabel/dfos-client';
import { ChainCell, IdentityName } from '../components/index-light';
import { OpLink, Pager, Panel, Pill, Term, TruncId } from '../components/ui';
import { fmtAge, fmtCount, fmtStamp, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  bodyFilterSupported,
  indexListStateFor,
  useIndexCapable,
  useIndexKeyFilterRelays,
  useIndexSignerKeyFilterRelays,
} from '../lib/index-light';
import { useIndexIdentitiesByKey } from '../lib/index-raw';
import { signerOpCount, signerOpCountLabel } from '../lib/key-ops';
import { useKeyStanding, type KeyStanding } from '../lib/key-standing';
import { useSignerKeyLog, type LogRow } from '../lib/log-feed';
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

/** The `chain ops` column, said plainly. The column exists because it is a real
 *  fact about the matched identity; the definition exists because on THIS page a
 *  bare "ops" would be read as this key's signings. */
const CHAIN_OPS_DEF =
  'Operations on this identity’s whole chain, by any of its keys — the figure the relay index carries for the identity, not a count of what this key signed. What this key signed is the lane below, which asks a different route.';

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
      {/* the identity's WHOLE chain, by any of its keys — never this key's
          signings, which is the signed lane's figure (see the header note) */}
      <td class="n" title={CHAIN_OPS_DEF}>
        {row.opCount}
      </td>
    </tr>
  );
};

/**
 * DECLARED — the has-ever-declared reverse lookup, and each match's standing.
 *
 * Carries its own two gates (an index at all, and `key=` honoured) rather than
 * short-circuiting the page: the signed lane runs on a different route with a
 * different filter, and a relay can serve one and not the other.
 */
const DeclaredPanel = (props: { multibase: string; indexed: boolean | null }) => {
  const { indexed } = props;
  // WHICH relays honour `key=`? An older relay IGNORES it and returns the
  // UNFILTERED identity list — every row of which would be a fabricated match —
  // so the lookup is sent only to the relays whose own probe cleared them, never
  // to the configured set (which the failover would happily fall back onto).
  const keyRelays = useIndexKeyFilterRelays();
  const keyFilter = bodyFilterSupported(keyRelays);
  const [cursor, setCursor] = useHashParam('after');
  const enabled = indexed === true && keyFilter === true;
  const page = useIndexIdentitiesByKey(enabled, props.multibase, keyRelays ?? [], {
    cursor,
    onCursor: setCursor,
  });
  // a disabled pager holds `loading: false`, so the raw state would settle on
  // `empty` and announce that no identity declared this key before anything had
  // been asked. Either gate answering NO returns its own panel below, so what
  // reaches the list is settled-and-enabled or still pending — and pending is
  // LOADING.
  const state = indexListStateFor(enabled || null, page.loading, page.error, page.rows.length);

  if (indexed === false) {
    return (
      <Panel title="identities" right={<span class="lbl">needs a relay index</span>}>
        <span class="muted">
          no configured relay serves an index — a key reverse lookup runs against{' '}
          <code>/index/v0/identities?key=</code>, and there is no other way to ask it. Add an
          index-capable relay on the <a href="#/relays">relays</a> page.
        </span>
      </Panel>
    );
  }

  if (keyFilter === false) {
    return (
      <Panel title="identities" accent="warn" right={<span class="lbl">route unsupported</span>}>
        <span class="muted">
          no configured relay supports key lookup. Each one either answered a key no chain can have
          declared with a full page of identities — which means it ignores the <code>key=</code>{' '}
          filter rather than applying it — or could not be reached to check. Asking one of them
          anyway would present every identity it holds as one that declared this key.
        </span>
        <div class="ck-note" style={{ marginTop: 10 }}>
          The filter is served by <code>web-relay</code> 0.39.0 and later. Add a relay whose index
          honours it on the <a href="#/relays">relays</a> page.
        </div>
      </Panel>
    );
  }

  return (
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
          whether or not a later update rotated it out. Rotation and deletion never remove an entry,
          which is what makes the list useful for audit and key-loss recovery. Rows are{' '}
          <b>attributed</b> relay hints: the{' '}
          <Term word="index is a hint" def={GLOSSARY['indexLight'] ?? ''} />, the chain is the
          authority, so each row's <b>standing</b> is folded from that identity's own chain in your
          tab.
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
              ? 'checking which relays support key lookup…'
              : 'asking the relay index which identities declared this key…'}
        </span>
      ) : state === 'empty' ? (
        <span class="muted">
          no identity in this relay's index has ever declared this key. An index can withhold rows,
          so this is what this relay surfaces — never a proof that none exists.
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
                <th title={CHAIN_OPS_DEF}>chain ops</th>
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
  );
};

/**
 * One signed operation. Four columns and no verdict badge: an index operation row
 * carries no JWS, so nothing on this line has been checked here — the op page is
 * where its signature is folded, which is where the row goes when clicked.
 */
const SignedOpRow = (props: { row: LogRow }) => {
  const { row } = props;
  return (
    <tr onClick={() => (location.hash = `#/op/${row.cid}`)}>
      <td>
        <span class={`kind ${row.kind}`}>{row.kind.replace('-op', '')}</span>
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <ChainCell chainId={row.chainId} />
      </td>
      <td onClick={(e) => e.stopPropagation()}>
        <OpLink cid={row.cid} />
      </td>
      <td class="muted" title={row.createdAt}>
        {fmtStamp(row.createdAt)}
      </td>
    </tr>
  );
};

/**
 * SIGNED — the operations this key put a signature on, one query on the actor
 * axis (`signerKey=`) rather than a fan-out over the identities that declared it.
 * The chain column carries whatever ownership annotation a chainId can honestly
 * give — an identity resolves to its public profile name, a content chain to its
 * title — so a key serving several identities reads as several named chains
 * without a per-row owner join this route does not answer.
 *
 * The panel's count is the fold in lib/key-ops.ts, and it is the page's answer to
 * "how many operations has this key signed": a number only where a relay that
 * honours the filter served a page for this key, in the loaded-and-paged form
 * wherever the keyset enumeration is not known to be exhausted.
 */
const SignedPanel = (props: { multibase: string; indexed: boolean | null }) => {
  const { indexed } = props;
  // the same trap as `key=`, on the other route: a relay predating `signerKey=`
  // ignores it and answers with the UNFILTERED operations feed. Same answer —
  // ask only the relays that passed their own probe. The two sets are computed
  // independently because a relay can serve one filter and not the other.
  const signerRelays = useIndexSignerKeyFilterRelays();
  const supported = bodyFilterSupported(signerRelays);
  // its own cursor param — the two lanes page independently, and one lane's
  // opaque cursor means nothing to the other's route
  const [cursor, setCursor] = useHashParam('sops');
  const enabled = indexed === true && supported === true;
  const page = useSignerKeyLog(enabled, props.multibase, signerRelays ?? [], cursor, setCursor);
  const state = indexListStateFor(enabled || null, page.loading, page.error, page.rows.length);
  const count = signerOpCount({
    indexed,
    supported,
    loading: page.loading,
    error: page.error,
    loaded: page.rows.length,
    hasNext: page.hasNext,
    offFirst: page.offFirst,
  });

  const title = (
    <>
      operations signed by this key{' '}
      <Pill
        state={
          count.kind === 'counted' ? 'warn' : count.kind === 'checking' ? 'pending' : 'neutral'
        }
        word="operations signed by this key"
        def={GLOSSARY['signerKey'] ?? ''}
      >
        {signerOpCountLabel(count)}
      </Pill>
    </>
  );

  if (indexed === false) {
    return (
      <Panel title={title} right={<span class="lbl">needs a relay index</span>}>
        <span class="muted">
          no configured relay serves an index — a signer lookup runs against{' '}
          <code>/index/v0/operations?signerKey=</code>, and there is no other way to ask it. Add an
          index-capable relay on the <a href="#/relays">relays</a> page.
        </span>
      </Panel>
    );
  }

  if (supported === false) {
    return (
      <Panel title={title} accent="warn" right={<span class="lbl">route unsupported</span>}>
        <span class="muted">
          no configured relay supports signer lookup. Each one either answered a key nothing can
          have signed with a full page of operations — which means it ignores the{' '}
          <code>signerKey=</code> filter rather than applying it — or could not be reached to check.
          Asking one of them anyway would present every operation it holds as one this key signed.
        </span>
        <div class="ck-note" style={{ marginTop: 10 }}>
          So this key’s signings cannot be counted here, and the{' '}
          <b title={CHAIN_OPS_DEF}>chain ops</b> column above is not a stand-in — it counts each
          matched identity’s whole chain, by any of its keys. Add a relay whose operations index
          honours <code>signerKey=</code> on the <a href="#/relays">relays</a> page.
        </div>
      </Panel>
    );
  }

  return (
    <Panel
      title={title}
      accent="warn"
      right={<span class="lbl">newest signed first · from relay index</span>}
      orient={
        <>
          Every operation this relay holds whose signature it verified against this key at ingest —{' '}
          <Term word="signed by this key" def={GLOSSARY['signerKey'] ?? ''} />, across every chain
          and every kind, including chains owned by no identity that declared it. Rows are browsing
          metadata and carry no signature: open one to fold its proof. The count is what this
          enumeration has loaded — a keyset cursor serves no total, so it is never a claim about how
          many exist.
        </>
      }
    >
      {state === 'error' ? (
        <div class="ck-note">
          {page.routeAbsent ? (
            <>
              every configured relay answered <b>no such route</b> for the operations index. Nothing
              was learned about what this key signed — this is not a statement that it signed
              nothing.
            </>
          ) : (
            <>
              couldn’t reach the relay index just now — so this says nothing about what this key has
              signed.{' '}
              <button onClick={page.retry} disabled={page.loading}>
                {page.loading ? 'retrying…' : 'retry'}
              </button>
              {page.offFirst ? <button onClick={page.first}> start over</button> : null}
            </>
          )}
        </div>
      ) : state === 'loading' ? (
        <span class="muted">
          {indexed === null
            ? 'checking relay capabilities…'
            : supported === null
              ? 'checking which relays support signer lookup…'
              : 'asking the relay index what this key has signed…'}
        </span>
      ) : state === 'empty' ? (
        <span class="muted">
          no operation in this relay's index carries a signature this key verified. An index can
          withhold rows, so this is what this relay surfaces — never a proof that none exists.
        </span>
      ) : (
        <div class="index-rows">
          <table>
            <thead>
              <tr>
                <th>kind</th>
                <th>chain</th>
                <th>operation</th>
                <th>signed</th>
              </tr>
            </thead>
            <tbody>
              {page.rows.map((row) => (
                <SignedOpRow key={row.cid} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Pager
        count={page.rows.length}
        noun="operations"
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

export const Key = (props: { multibase: string }) => {
  const indexed = useIndexCapable();
  return (
    <>
      <Panel
        title="public key"
        right={<span class="lbl">multibase · Ed25519 Multikey</span>}
        orient={
          <>
            A key, as the thing itself: the{' '}
            <Term word="public key, not a key id" def={GLOSSARY['keyIdentity'] ?? ''} /> — a{' '}
            <code>key_1</code> names a slot on one identity document and travels nowhere. An
            identity declares keys by <Term word="role" def={GLOSSARY['keyRoles'] ?? ''} /> and
            rotates them over time, so the same key can appear on more than one chain and can
            outlive its place on any of them. This page asks the relay index which identities have
            ever declared it — folding each of those chains here to say where it stands now — and
            then what it has actually <Term word="signed" def={GLOSSARY['signerKey'] ?? ''} />,
            which is a different list.
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
      <DeclaredPanel multibase={props.multibase} indexed={indexed} />
      <SignedPanel multibase={props.multibase} indexed={indexed} />
    </>
  );
};
