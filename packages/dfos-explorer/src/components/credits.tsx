/*

  CREDITS — document attribution, re-verified from the claimant's side

  The document signer asserts every entry by committing to these bytes. An
  optional credit-claim JWS adds the claimant's matching assertion. Verification
  is local and binds the claim to this exact content chain, DID, and role.

*/

import { verifyCreditClaim } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from '../lib/client';
import { GLOSSARY } from '../lib/glossary';
import { Check, Checks, type CheckState } from './checks';
import { Badge, DidLink, Panel, Term } from './ui';

type CreditState = 'pending' | 'claimed' | 'unclaimed' | 'invalid' | 'unverifiable';

interface CreditResult {
  state: CreditState;
  note: string;
}

interface CreditEntry {
  claim: string | undefined;
  claimPresent: boolean;
  did: string | undefined;
  name: string | undefined;
  role: string | undefined;
}

const readEntry = (value: unknown): CreditEntry => {
  const entry =
    typeof value === 'object' && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  return {
    claim: typeof entry['claim'] === 'string' ? entry['claim'] : undefined,
    claimPresent: Object.prototype.hasOwnProperty.call(entry, 'claim'),
    did: typeof entry['did'] === 'string' ? entry['did'] : undefined,
    name: typeof entry['name'] === 'string' ? entry['name'] : undefined,
    role: typeof entry['role'] === 'string' ? entry['role'] : undefined,
  };
};

const initialResult = (entry: CreditEntry): CreditResult =>
  entry.claimPresent
    ? { state: 'pending', note: 'checking claimant identity, signature, CID, and exact bind…' }
    : {
        state: 'unclaimed',
        note: 'credited · unclaimed — document signer asserts this credit; claimant has not signed it',
      };

const verifyEntry = async (entry: CreditEntry, contentId: string): Promise<CreditResult> => {
  if (!entry.claimPresent) return initialResult(entry);
  if (!entry.claim) {
    return { state: 'invalid', note: 'checked and failed — claim field is not a JWS string' };
  }
  if (!entry.did) {
    return { state: 'invalid', note: 'checked and failed — credited DID is missing' };
  }
  if (entry.role === undefined) {
    return {
      state: 'invalid',
      note: 'checked and failed — a claim-bearing entry must include a role',
    };
  }

  try {
    const verified = await verifyCreditClaim(entry.claim, {
      resolveIdentity: getClient().callbacks().resolveIdentity,
      expectedContentId: contentId,
    });
    if (verified.did !== entry.did) {
      return {
        state: 'invalid',
        note: 'checked and failed — signed claimant DID does not exactly match the credited DID',
      };
    }
    if (verified.role !== entry.role) {
      return {
        state: 'invalid',
        note: 'checked and failed — signed role does not exactly match the credited role',
      };
    }
    return {
      state: 'claimed',
      note: 'signature and exact contentId/DID/role bind verified locally',
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/^claimant identity not found(?::|$)/.test(message)) {
      return {
        state: 'unverifiable',
        note:
          'could not check — claimant identity was not found on the configured relays; ' +
          'the claim is unproven, not denied',
      };
    }
    return { state: 'invalid', note: `checked and failed — ${message}` };
  }
};

const checkState = (state: CreditState): CheckState => {
  if (state === 'claimed') return 'ok';
  if (state === 'invalid') return 'bad';
  if (state === 'unverifiable') return 'warn';
  return 'pend';
};

const stateBadge = (state: CreditState) => {
  if (state === 'pending') return <Badge state="neutral">checking</Badge>;
  if (state === 'claimed') return <Badge state="ok">claimed</Badge>;
  if (state === 'invalid') return <Badge state="bad">invalid</Badge>;
  if (state === 'unverifiable') return <Badge state="warn">unverifiable</Badge>;
  return <Badge state="neutral">unclaimed</Badge>;
};

export const Credits = (props: { contentId: string; entries: readonly unknown[] }) => {
  const entries = props.entries.map(readEntry);
  const [results, setResults] = useState<CreditResult[]>(() => entries.map(initialResult));

  useEffect(() => {
    let dead = false;
    setResults(entries.map(initialResult));

    entries.forEach((entry, index) => {
      if (!entry.claimPresent) return;
      void verifyEntry(entry, props.contentId).then((result) => {
        if (dead) return;
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
        {entries.map((entry, index) => {
          const result = results[index] ?? initialResult(entry);
          return (
            <Check key={index} state={checkState(result.state)} note={result.note}>
              {entry.name ? <b>{entry.name}</b> : <span class="muted">unnamed credit</span>}
              {' · '}
              {entry.did ? <DidLink did={entry.did} /> : <span class="err">missing DID</span>}
              {' · '}
              {entry.role !== undefined ? (
                <span class="k-role">{entry.role || 'empty role'}</span>
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
