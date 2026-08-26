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

/** Which of a credit row's two identity fields leads the row. */
export type CreditLead = 'name' | 'did' | 'none';

/**
 * The lead slot for one verified credit row. A document credit's `name` is
 * OPTIONAL and frequently absent — the DID is the entry's actual identity, and
 * it resolves to a public profile name through the same chip every other surface
 * uses. So a nameless entry leads with its DID rather than announcing "unnamed
 * credit" across a row that names someone perfectly well, alongside their role.
 *
 * The muted placeholder is reserved for the one entry that really has nothing to
 * lead with: neither field present. Whitespace is not a name (nor a DID) —
 * a blank <b> would read as a rendering bug rather than an absent field.
 *
 * The amber tier already leads with the chip; this is the verified tier catching
 * up to its own row vocabulary. Pure, unit-tested.
 */
export const creditLead = (name: string | undefined, did: string | undefined): CreditLead =>
  name?.trim() ? 'name' : did?.trim() ? 'did' : 'none';

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
          const lead = creditLead(display.name, display.did);
          return (
            <Check key={index} state={checkState(result.state)} note={result.note}>
              {/* one identity slot, never two: when the DID leads, the chip IS
                  the identity — a DidLink beside it would print the same
                  identifier twice on one row (see {@link creditLead}) */}
              {lead === 'name' ? (
                <>
                  <b>{display.name}</b>
                  {' · '}
                  {display.did ? (
                    <DidLink did={display.did} />
                  ) : (
                    <span class="err">missing DID</span>
                  )}
                </>
              ) : lead === 'did' && display.did ? (
                <DidChip did={display.did} />
              ) : (
                <>
                  <span class="muted">unnamed credit</span>
                  {' · '}
                  <span class="err">missing DID</span>
                </>
              )}
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

/**
 * One projected credit. `position` 0 is the primary author (the entry array's
 * order is the document's display order).
 *
 * THE BADGE REPORTS PRESENCE, NOT A VERDICT, and its wording has to carry that on
 * its own — a reader sees the badge, not this comment. `hasClaim` is byte-presence
 * of a claim token, which is equally true of a token whose signature fails, whose
 * bind names a different role, or that was replayed from another chain: all three
 * resolve INVALID under the fold. So the amber tier borrows none of the four
 * verification words — not "claimed", and not "unclaimed" either, since both are
 * verdicts the relay is in no position to reach. It says what is attached.
 */
const IndexCreditRowView = (props: { row: IndexCreditRow }) => {
  const { row } = props;
  return (
    <Check
      state="pend"
      note={
        row.hasClaim
          ? 'the head document carries a claim token for this entry — byte-presence only; whether it verifies, and binds to this chain, DID, and role, is the fold’s answer'
          : 'the document signer asserts this credit; the relay projects no claim token alongside it'
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
        <Badge state="warn">claim attached</Badge>
      ) : (
        <Badge state="neutral">no claim</Badge>
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
 * The document's own `credits[]`, read from bytes the caller has already
 * re-hashed to the committed document CID. TOTAL, and deliberately so: a
 * document with no credits — the field absent, an empty array, or a decoded
 * shape that cannot carry one — yields an EMPTY LIST, which is a verified fact
 * ("this document credits nobody") and emphatically not the same as having no
 * answer yet. Collapsing those two into one null is what let a relay projection
 * outlive its own contradiction; see {@link creditsTier}. Pure, unit-tested.
 */
export const documentCredits = (parsed: unknown): readonly unknown[] => {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return [];
  const credits = (parsed as Record<string, unknown>)['credits'];
  return Array.isArray(credits) ? credits : [];
};

/** Which tier the credits panel should render. */
export type CreditsTier = 'verified' | 'index' | 'none';

/**
 * The tier rule, and the whole trust ordering in one place: THE FOLD ALWAYS WINS.
 *
 * `entries` is null only while the fold has no answer — the bytes are not fetched,
 * or not yet re-hashed to the committed CID on a verified chain. In exactly that
 * window the relay's projection may stand in. Once `entries` is a list the fold
 * has spoken, and an EMPTY list is a verdict, not a gap: this document credits
 * nobody. It must retire the projection rather than leave it standing, or a stale
 * relay — or a hostile one — keeps rendering credits on a chain whose verified
 * current document has none, which is precisely the assertion the fold exists to
 * overrule. Pure, unit-tested.
 */
export const creditsTier = (
  entries: readonly unknown[] | null,
  indexRowCount: number,
): CreditsTier => {
  if (entries !== null) return entries.length > 0 ? 'verified' : 'none';
  return indexRowCount > 0 ? 'index' : 'none';
};

/**
 * The credits panel in whichever tier is actually available — see
 * {@link creditsTier} for the ordering. `entries` is the document's own
 * `credits[]` once the served bytes re-hashed to the committed document CID on a
 * verified chain (see the gate in views/content.tsx), and null until then.
 *
 * Renders NOTHING when no tier has anything: a document the fold proves credits
 * nobody, a relay whose index predates the credits family, or a chain that is not
 * publicly readable (which by design has zero credit rows — attribution is never
 * more public than the content it attributes). Credits are enrichment, so their
 * absence is silent rather than an error panel.
 */
export const Credits = (props: {
  contentId: string;
  entries: readonly unknown[] | null;
  indexed: boolean | null;
}) => {
  // the amber prelude runs only while the fold has no answer — once it does,
  // there is nothing a projection can add and it must not keep fetching
  const page = useIndexCredits(props.indexed === true && props.entries === null, {
    contentId: props.contentId,
  });
  const tier = creditsTier(props.entries, page.rows.length);

  if (tier === 'verified') {
    return <VerifiedCredits contentId={props.contentId} entries={props.entries ?? []} />;
  }
  if (tier === 'index') return <IndexCredits page={page} />;
  return null;
};
