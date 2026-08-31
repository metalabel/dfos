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

/**
 * Keys the inline `Term` help links by name, outside the verdict vocabulary. Same
 * failure mode as the pills: a renamed key type-checks and renders a dotted word
 * with an EMPTY definition, which is worse than not offering the link at all.
 */
const HELP_KEYS = [
  'cid',
  'indexLight',
  'keyIdentity',
  'keyProved',
  'keyRoles',
  'localDivergence',
  'localIndex',
  'publicProjection',
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

describe('GLOSSARY — the inline help vocabulary', () => {
  it('defines every key a Term links by name', () => {
    for (const key of HELP_KEYS) {
      expect(GLOSSARY[key], key).toBeTruthy();
    }
  });

  // "diverged" names two different findings in this app, and reading one as the
  // other is the whole risk: a STALE CACHE in your tab is not a signed
  // contradiction between two servers. The local entry has to say which it is not.
  it('separates a stale local index from a signed relay-log divergence', () => {
    const def = (GLOSSARY['localDivergence'] ?? '').toLowerCase();
    expect(def).toContain('distinct from');
    expect(def).toContain('local sync');
  });

  // Absence must be DEFINITIVE (lib/divergence.ts): only an answered "not found"
  // from every configured relay is evidence, and a failure to look never reads as
  // clean. The plain rendering must not soften that into "we checked, it's fine".
  it('keeps an unsettled divergence probe inconclusive rather than clean', () => {
    const def = (GLOSSARY['localDivergence'] ?? '').toLowerCase();
    expect(def).toContain('not found');
    expect(def).toContain('inconclusive');
    expect(def).not.toMatch(/proves? (completeness|the corpus)/);
  });
});
