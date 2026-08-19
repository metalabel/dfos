/*

  CREDITS — document attribution, in two tiers

  The document signer asserts every entry by committing to these bytes. An
  optional credit-claim JWS adds the claimant's matching assertion. Verification
  is local and binds the claim to this exact content chain, DID, and role.

  The whole verdict — including the full three-component bind and the
  invalid/unverifiable split — comes from the protocol library's
  `verifyCreditEntry`. This panel does no verification reasoning of its own: it
  renders a state. Earlier drafts re-implemented the bind here and matched error
  MESSAGES to tell "could not check" from "checked and failed", which reads the
  wrong verdict the moment that prose is reworded.

  TWO TIERS, ONE PANEL. The verified tier above needs the served bytes re-hashed
  to the committed document CID on a verified chain — three round trips and a fold
  — and until then a content page showed nothing at all. The relay's credit
  projection (`/index/v0/credits?contentId=`) answers "who does this public
  document say made it" in one request, so it renders first, AMBER, and is
  replaced in place the moment the verified tier lands. Same panel, same row
  vocabulary, upgraded — the profile-name pattern applied to attribution.

  What the amber tier may and may not say is exactly bounded. The relay is
  deliberately not credit-claim aware: a row restates the entry's DID, role, and
  display position, and `hasClaim` is BYTE-PRESENCE of a claim token. It is never
  a verdict. So the amber tier never renders "claimed" — that word belongs to the
  fold, which checks the signature and the three-component bind. It says a
  self-claim is PRESENT, and marks that amber like every other relay projection.

*/

import { verifyCreditEntry } from '@metalabel/dfos-protocol/chain';
import type { CreditEntryState, VerifiedCreditEntry } from '@metalabel/dfos-protocol/chain';
import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from '../lib/client';
import { GLOSSARY } from '../lib/glossary';
import type { IndexPage } from '../lib/index-light';
import { useIndexCredits, type IndexCreditRow } from '../lib/index-raw';
import { Check, Checks, type CheckState } from './checks';
import { DidChip } from './did-chip';
import { Badge, DidLink, Pager, Panel, Term } from './ui';

/** `pending` is a render-only state — the library never returns it */
type DisplayState = CreditEntryState | 'pending';

interface CreditResult {
  state: DisplayState;
  note: string;
}

/** What the panel needs for DISPLAY; verification reads the raw entry itself */
interface CreditDisplay {
  did: string | undefined;
  name: string | undefined;
  role: string | undefined;
  claimPresent: boolean;
}

const readDisplay = (value: unknown): CreditDisplay => {
  const entry =
    typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  return {
    did: typeof entry['did'] === 'string' ? entry['did'] : undefined,
    name: typeof entry['name'] === 'string' ? entry['name'] : undefined,
    role: typeof entry['role'] === 'string' ? entry['role'] : undefined,
    claimPresent: entry['claim'] !== undefined,
  };
};

const initialResult = (display: CreditDisplay): CreditResult =>
  display.claimPresent
    ? { state: 'pending', note: 'checking claimant identity, signature, CID, and exact bind…' }
    : {
        state: 'unclaimed',
        note: 'credited · unclaimed — document signer asserts this credit; claimant has not signed it',
      };

/** Prefix the library's diagnosis with how to read the verdict */
const describe = (verified: VerifiedCreditEntry): CreditResult => {
  const prefix: Record<CreditEntryState, string> = {
    claimed: 'claimed — ',
    unclaimed: 'credited · unclaimed — ',
    invalid: 'checked and failed — ',
    unverifiable: 'could not check — ',
  };
  return { state: verified.state, note: `${prefix[verified.state]}${verified.note}` };
};

const checkState = (state: DisplayState): CheckState => {
  if (state === 'claimed') return 'ok';
  if (state === 'invalid') return 'bad';
  if (state === 'unverifiable') return 'warn';
  return 'pend';
};

const stateBadge = (state: DisplayState) => {
  if (state === 'pending') return <Badge state="neutral">checking</Badge>;
  if (state === 'claimed') return <Badge state="ok">claimed</Badge>;
  if (state === 'invalid') return <Badge state="bad">invalid</Badge>;
  if (state === 'unverifiable') return <Badge state="warn">unverifiable</Badge>;
  return <Badge state="neutral">unclaimed</Badge>;
};

/** The shared shell, so the amber tier and the verified tier are visibly the same
 *  panel in two states rather than two panels that happen to both say "credits". */
const CreditsPanel = (props: { verified: boolean; children: ComponentChildren }) => (
  <Panel
    title="credits"
    accent={props.verified ? undefined : 'warn'}
    right={
      <span class="lbl">
        {props.verified
          ? 'claimant assertions re-verified locally'
          : 'relay-asserted · from relay index'}
      </span>
    }
    orient={
      <>
        A <Term word="credit claim" def={GLOSSARY['creditClaim'] ?? ''} /> binds the claimant's
        signature to this chain, credited DID, and byte-exact role.{' '}
        <b>Attribution, not authorization.</b>
        {props.verified ? null : (
          <>
            {' '}
            These rows are the relay's projection of the current public head document — it restates
            who the document credits, and whether an entry carries a claim token, but{' '}
            <b>never whether that token verifies</b>. The verified fold replaces them once this tab
            has the bytes.
          </>
        )}
      </>
    }
  >
    {props.children}
  </Panel>
);

// -----------------------------------------------------------------------------
// the VERIFIED tier — the fold over bytes this tab re-hashed itself
// -----------------------------------------------------------------------------

const VerifiedCredits = (props: { contentId: string; entries: readonly unknown[] }) => {
  const displays = props.entries.map(readDisplay);
  const [results, setResults] = useState<CreditResult[]>(() => displays.map(initialResult));

  useEffect(() => {
    let dead = false;
    setResults(displays.map(initialResult));

    props.entries.forEach((entry, index) => {
      if (!readDisplay(entry).claimPresent) return;
      void verifyCreditEntry(entry as Record<string, unknown>, {
        resolveIdentity: getClient().callbacks().resolveIdentity,
        contentId: props.contentId,
      })
        .then((verified) => (dead ? null : describe(verified)))
        .catch((error: unknown) => {
          if (dead) return null;
          // the helper only throws for a missing contentId (a bug here, not a
          // verdict about the entry), so this is honest ignorance, not a failure
          const detail = error instanceof Error ? error.message : String(error);
          return {
            state: 'unverifiable' as const,
            note: `could not check — ${detail}`,
          };
        })
        .then((result) => {
          if (dead || !result) return;
          setResults((current) => current.map((item, i) => (i === index ? result : item)));
        });
    });

    return () => {
      dead = true;
    };
  }, [props.contentId, props.entries]);

  return (
    <CreditsPanel verified>
      <Checks>
        {displays.map((display, index) => {
          const result = results[index] ?? initialResult(display);
          return (
            <Check key={index} state={checkState(result.state)} note={result.note}>
              {display.name ? <b>{display.name}</b> : <span class="muted">unnamed credit</span>}
              {' · '}
              {display.did ? <DidLink did={display.did} /> : <span class="err">missing DID</span>}
              {' · '}
              {display.role !== undefined ? (
                <span class="k-role">{display.role || 'empty role'}</span>
              ) : (
                <span class="muted">no role</span>
              )}{' '}
              {stateBadge(result.state)}
            </Check>
          );
        })}
      </Checks>
    </CreditsPanel>
  );
};

// -----------------------------------------------------------------------------
// the AMBER tier — the relay's projection of the same list, one request
// -----------------------------------------------------------------------------

/** One projected credit. `position` 0 is the primary author (the entry array's
 *  order is the document's display order), and a claim is reported as PRESENT —
 *  never as valid, which the relay does not and must not know. */
const IndexCreditRowView = (props: { row: IndexCreditRow }) => {
  const { row } = props;
  return (
    <Check
      state="pend"
      note={
        row.hasClaim
          ? 'the head document carries a self-claim token for this entry — byte-presence, not a verdict; the fold below checks its signature and bind'
          : 'the document signer asserts this credit; no claim token accompanies it'
      }
    >
      <DidChip did={row.did} />
      {' · '}
      {row.role !== null ? (
        <span class="k-role">{row.role || 'empty role'}</span>
      ) : (
        <span class="muted">no role</span>
      )}
      {row.position === 0 ? <span class="lbl"> primary</span> : null}{' '}
      {row.hasClaim ? (
        <Badge state="warn">self-claimed</Badge>
      ) : (
        <Badge state="neutral">unclaimed</Badge>
      )}
    </Check>
  );
};

const IndexCredits = (props: { page: IndexPage<IndexCreditRow> }) => {
  const { page } = props;
  return (
    <CreditsPanel verified={false}>
      <Checks>
        {page.rows.map((row) => (
          <IndexCreditRowView key={`${row.did}:${row.position}`} row={row} />
        ))}
      </Checks>
      {page.hasNext || page.offFirst ? (
        <Pager
          count={page.rows.length}
          noun="credits"
          loading={page.loading}
          hasNext={page.hasNext}
          hasPrev={page.hasPrev}
          offFirst={page.offFirst}
          onFirst={page.first}
          onPrev={page.prev}
          onNext={page.next}
        />
      ) : null}
    </CreditsPanel>
  );
};

// -----------------------------------------------------------------------------

/**
 * The credits panel in whichever tier is actually available. `entries` is the
 * document's own `credits[]`, present only once the served bytes re-hashed to the
 * committed document CID on a verified chain (see the gate in views/content.tsx);
 * when it is null the relay's projection stands in, amber.
 *
 * Renders NOTHING when neither tier has anything: an uncredited document, a relay
 * whose index predates the credits family, or a chain that is not publicly
 * readable (which by design has zero credit rows — attribution is never more
 * public than the content it attributes). Credits are enrichment, so their
 * absence is silent rather than an error panel.
 */
export const Credits = (props: {
  contentId: string;
  entries: readonly unknown[] | null;
  indexed: boolean | null;
}) => {
  // the amber prelude runs only while the verified tier is unavailable — once the
  // fold has the bytes there is nothing a projection can add
  const page = useIndexCredits(props.indexed === true && props.entries === null, {
    contentId: props.contentId,
  });

  if (props.entries !== null) {
    return <VerifiedCredits contentId={props.contentId} entries={props.entries} />;
  }
  if (page.rows.length === 0) return null;
  return <IndexCredits page={page} />;
};
