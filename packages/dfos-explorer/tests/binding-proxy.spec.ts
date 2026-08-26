import { describe, expect, it } from 'vitest';
import { parseDidBody, parseTxtRecords } from '../api/binding';

// The binding route's judgement lives in these two pure parsers: what a TXT name
// is saying, and what a /.well-known/dfos-did body is saying. Everything else in
// the route is transport around them. The line they must hold is the spec's:
// SILENCE (nothing published, nothing readable) is never CONTRADICTION.

const DID = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
const OTHER = 'did:dfos:2346789acdefhknrtvz2346789acdef';

describe('parseTxtRecords', () => {
  it('reads a single well-formed did= record', () => {
    expect(parseTxtRecords([[`did=${DID}`]])).toEqual({ status: 'ok', did: DID });
  });

  // a TXT record over 255 bytes arrives as several chunks; the record is the
  // JOIN of its chunks, never the chunks read separately
  it('joins the chunks of one record before reading it', () => {
    expect(parseTxtRecords([['did=', DID.slice(0, 10), DID.slice(10)]])).toEqual({
      status: 'ok',
      did: DID,
    });
  });

  it('ignores records that do not begin did=', () => {
    expect(
      parseTxtRecords([['v=spf1 -all'], [`did=${DID}`], ['google-site-verification=x']]),
    ).toEqual({ status: 'ok', did: DID });
  });

  it('is silent when the name carries no did= record at all', () => {
    expect(parseTxtRecords([]).status).toBe('none');
    expect(parseTxtRecords([['v=spf1 -all']]).status).toBe('none');
  });

  // the spec is explicit: more than one did= record is a contradiction and a
  // verifier MUST NOT pick one
  it('reports multiple did= records as a contradiction', () => {
    const out = parseTxtRecords([[`did=${DID}`], [`did=${OTHER}`]]);
    expect(out).toEqual({ status: 'contradiction', reason: 'multiple did= records' });
  });

  // "they happen to agree" is a tiebreak by another name — still a contradiction
  it('contradicts on duplicates even when the values match', () => {
    expect(parseTxtRecords([[`did=${DID}`], [`did=${DID}`]]).status).toBe('contradiction');
  });

  // a single record that is not a DID says NOTHING — it is not a second answer
  it('treats one malformed did= record as silence, not contradiction', () => {
    for (const bad of [
      'did=',
      'did=not-a-did',
      'did=did:dfos:tooshort',
      `did=did:dfos:${'b'.repeat(31)}`, // right length, outside the id alphabet
      `did=${DID} `, // trailing space — TXT values are exact
      `did=${DID}extra`,
      `DID=${DID}`, // wrong case: not a did= record at all
    ]) {
      const out = parseTxtRecords([[bad]]);
      expect(out.status, bad).toBe('none');
    }
  });
});

describe('parseDidBody', () => {
  it('accepts exactly one DID', () => {
    expect(parseDidBody(DID)).toEqual({ status: 'ok', did: DID });
  });

  it('trims ASCII whitespace around it', () => {
    expect(parseDidBody(`\n  ${DID}\t\r\n`)).toEqual({ status: 'ok', did: DID });
  });

  // present but not an attestation: `malformed` rather than `none`, because the
  // document EXISTS — which is what blocks the app-description fallback
  it('reports a non-DID body as malformed, never as absence', () => {
    for (const body of [
      '',
      '   ',
      '<!doctype html><title>404</title>',
      'did:dfos:tooshort',
      `${DID} ${DID}`,
      `did=${DID}`,
      `{"did":"${DID}"}`,
      'did:web:example.com',
    ]) {
      const out = parseDidBody(body);
      expect(out.status, JSON.stringify(body)).toBe('malformed');
    }
  });

  it('rejects a body carrying more than the DID even on one line', () => {
    expect(parseDidBody(`${DID}\nnot a did`).status).toBe('malformed');
  });
});
