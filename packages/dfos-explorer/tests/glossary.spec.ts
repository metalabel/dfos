/**
 * Glossary integrity — the plain-language layer's contract.
 *
 * The verdict pills on the identity and domain views read their PLAIN rendering
 * out of the glossary by key. A renamed or dropped key does not fail a type
 * check (the lookup is `GLOSSARY[key] ?? ''`), it silently renders a pill with an
 * empty definition — a verdict with no plain layer at all, which is exactly the
 * regression this file exists to catch.
 */

import { describe, expect, it } from 'vitest';
import { GLOSSARY, GLOSSARY_TERMS } from '../src/lib/glossary';

/** Every key a view looks up for the verdict vocabulary. */
const VERDICT_KEYS = [
  'bindingBound',
  'bindingStale',
  'bindingBroken',
  'bindingVantage',
  'bindingNotCheckable',
  'appDescription',
  'domainAttestation',
  'relayDiverged',
  'noCarriage',
  'logAheadBehindDiverged',
] as const;

describe('GLOSSARY — shape', () => {
  it('has no duplicate keys', () => {
    const keys = GLOSSARY_TERMS.map((t) => t.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('every entry carries a term and a non-empty definition', () => {
    for (const t of GLOSSARY_TERMS) {
      expect(t.term, t.key).not.toBe('');
      expect(t.def.length, t.key).toBeGreaterThan(20);
    }
  });
});

describe('GLOSSARY — the verdict vocabulary the pills depend on', () => {
  it('defines every key the verdict pills look up', () => {
    for (const key of VERDICT_KEYS) {
      expect(GLOSSARY[key], key).toBeTruthy();
    }
  });

  // The spine of the honest-state discipline, in plain words. `stale` must read
  // as SILENCE and never as an accusation, and `broken` must stay scoped to the
  // domain claim — the identity and its history are untouched.
  it('renders stale as silence, explicitly not as contradiction', () => {
    const def = GLOSSARY['bindingStale'] ?? '';
    expect(def.toLowerCase()).toContain('silent');
    expect(def.toLowerCase()).toContain('silence is not contradiction');
  });

  it('renders broken as scoped to the domain claim alone', () => {
    const def = GLOSSARY['bindingBroken'] ?? '';
    expect(def.toLowerCase()).toContain('contradicts');
    expect(def.toLowerCase()).toContain('untouched');
  });

  // The explorer is stateless: it has never seen a binding before this page load,
  // so no plain rendering may imply a remembered observation.
  it('never invents a confirmation history', () => {
    for (const key of VERDICT_KEYS) {
      expect(GLOSSARY[key] ?? '', key).not.toMatch(/last (confirmed|checked|seen)/i);
    }
  });

  // The two well-known systems are constantly confused for each other, so each
  // definition names the sibling it is NOT.
  it('keeps the two well-known systems distinguished from each other', () => {
    expect(GLOSSARY['appDescription'] ?? '').toContain('domain attestation');
    expect(GLOSSARY['domainAttestation'] ?? '').toContain('app description');
  });

  it('covers the whole relay-log taxonomy in one entry', () => {
    const def = (GLOSSARY['logAheadBehindDiverged'] ?? '').toLowerCase();
    for (const word of ['ahead', 'behind', 'diverged']) expect(def, word).toContain(word);
  });
});
