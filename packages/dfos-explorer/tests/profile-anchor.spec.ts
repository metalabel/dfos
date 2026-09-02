/*

  ANCHORED-PROFILE RESOLUTION — the three classifiers behind the header's states

  The header used to render `null` for every way of failing to reach an anchored
  profile. These are the pure deciders that replaced that silence, and each one
  exists to keep two facts from being reported as one:

    not held   vs  could not ask
    the relay contradicts ITSELF  vs  two relays disagree with each other
    an empty body                 vs  a failed integrity check

*/

import { describe, expect, it } from 'vitest';
import { bytesFailureKind, chainFailureKind, integrityVerdict } from '../src/views/identity';

const claim = (status: number, gated = false) => ({ relay: 'https://r.example', status, gated });
const blob = (status: number, gated = false) => ({ relay: 'https://r.example', status, gated });

describe('chainFailureKind — a proof-plane failure is three different facts', () => {
  it('an answered 404 is absence', () => {
    expect(chainFailureKind(claim(404))).toBe('chain-absent');
  });

  it('401/403 is gated, whatever the status number says', () => {
    expect(chainFailureKind(claim(401, true))).toBe('chain-gated');
    expect(chainFailureKind(claim(403, true))).toBe('chain-gated');
  });

  it('a timeout or a 5xx is a question that never got answered, NOT absence', () => {
    // the distinction the whole state exists for: "not held here" is a claim
    // about the corpus and must never be made on the strength of a failed fetch
    expect(chainFailureKind(claim(0))).toBe('chain-unreachable');
    expect(chainFailureKind(claim(500))).toBe('chain-unreachable');
    expect(chainFailureKind(claim(502))).toBe('chain-unreachable');
  });
});

describe('bytesFailureKind — the same split on the content plane', () => {
  it('404 is absence and 401/403 is gated', () => {
    expect(bytesFailureKind(blob(404))).toBe('bytes-absent');
    expect(bytesFailureKind(blob(401, true))).toBe('bytes-gated');
    expect(bytesFailureKind(blob(403, true))).toBe('bytes-gated');
  });

  it('an EMPTY 200 body is absence — zero bytes cannot have mismatched anything', () => {
    expect(bytesFailureKind(blob(200))).toBe('bytes-absent');
  });

  it('unreachable and 5xx stay their own answer', () => {
    expect(bytesFailureKind(blob(0))).toBe('bytes-unreachable');
    expect(bytesFailureKind(blob(503))).toBe('bytes-unreachable');
  });
});

describe('integrityVerdict — self-contradiction is red, skew is not', () => {
  it('everything agreeing is ok', () => {
    expect(integrityVerdict('cidA', 'cidA', 'cidA')).toBe('ok');
  });

  it('RED only when the serving relay contradicts its OWN document CID header', () => {
    expect(integrityVerdict('cidB', 'cidA', 'cidA')).toBe('mismatch');
    // and it stays red even when the chain lookup happens to agree with the bytes
    expect(integrityVerdict('cidB', 'cidA', 'cidB')).toBe('mismatch');
  });

  it('bytes matching their own relay but not the chain lookup are SKEW, not a mismatch', () => {
    // two relays at different points in the chain is benign and common; painting
    // it red would teach a reader to ignore the one alarm that matters
    expect(integrityVerdict('cidA', 'cidA', 'cidB')).toBe('skew');
  });

  it('a relay that sent no document-CID header cannot be shown to contradict itself', () => {
    expect(integrityVerdict('cidA', undefined, 'cidB')).toBe('skew');
    expect(integrityVerdict('cidA', undefined, 'cidA')).toBe('ok');
  });

  it('undecodable bytes fail the check, and are red only against a relay header', () => {
    expect(integrityVerdict(null, 'cidA', 'cidA')).toBe('mismatch');
    expect(integrityVerdict(null, undefined, 'cidA')).toBe('skew');
  });

  it('a chain committing no document is a two-plane disagreement, so skew', () => {
    expect(integrityVerdict('cidA', 'cidA', null)).toBe('skew');
  });
});
