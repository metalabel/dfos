/*

  CREDITS — document attribution, re-verified from the claimant's side

  The document signer asserts every entry by committing to these bytes. An
  optional credit-claim JWS adds the claimant's matching assertion. Verification
  is local and binds the claim to this exact content chain, DID, and role.

  The whole verdict — including the full three-component bind and the
  invalid/unverifiable split — comes from the protocol library's
  `verifyCreditEntry`. This panel does no verification reasoning of its own: it
  renders a state. Earlier drafts re-implemented the bind here and matched error
  MESSAGES to tell "could not check" from "checked and failed", which reads the
  wrong verdict the moment that prose is reworded.

  Only mounted when the served document bytes have been re-hashed to the committed
  document CID on a verified chain — see the gate in views/content.tsx.

*/

import { verifyCreditEntry } from '@metalabel/dfos-protocol/chain';
import type { CreditEntryState, VerifiedCreditEntry } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from '../lib/client';
import { GLOSSARY } from '../lib/glossary';
import { Check, Checks, type CheckState } from './checks';
import { Badge, DidLink, Panel, Term } from './ui';

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

export const Credits = (props: { contentId: string; entries: readonly unknown[] }) => {
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
    <Panel
      title="credits"
      right={<span class="lbl">claimant assertions re-verified locally</span>}
      orient={
        <>
          A <Term word="credit claim" def={GLOSSARY['creditClaim'] ?? ''} /> binds the claimant's
          signature to this chain, credited DID, and byte-exact role.{' '}
          <b>Attribution, not authorization.</b>
        </>
      }
    >
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
    </Panel>
  );
};
